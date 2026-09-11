"""
pipeline.py — PhishIt unified email analysis pipeline.

Public entry point: process_email(eml_path) -> dict

Parses one .eml file and runs it through every teammate's module in
sequence (Header Forensics -> NLP Content Analysis -> IP Geolocation ->
Domain Intelligence -> Correlation), combining their real outputs into
one unified dictionary. The processed email's indicators are appended to
data/emails_processed.csv (the correlation module's history file), and
the unified result is written to output/<email_id>.json as well as
returned.

No module failure is allowed to crash the pipeline: every step is called
through a guarded wrapper that records status="ok"/"error" and an `error`
message inside that section of the result, so the caller (CLI, dashboard,
or a batch loop) always gets back one complete, consistently-shaped
dictionary for the file it asked about.
"""

import csv
import email
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from email import policy
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

# Each teammate's module uses flat, same-directory imports (e.g.
# `from domain_age import check_domain_age`), so their own folder has to
# be on sys.path for those internal imports to resolve.
_MODULE_DIRS = [
    REPO_ROOT / "PhishIt-02_03",
    REPO_ROOT / "PhishIt-04" / "domain_intelligence",
    REPO_ROOT / "PhishIt05",
    REPO_ROOT / "src",
]
for _dir in _MODULE_DIRS:
    if str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))

DATA_DIR = REPO_ROOT / "data"
OUTPUT_DIR = REPO_ROOT / "output"
CSV_PATH = DATA_DIR / "emails_processed.csv"
CSV_COLUMNS = ["email_id", "sender", "domain", "ip", "url", "reply_to", "timestamp"]

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+")


class PipelineInputError(Exception):
    """Raised when the .eml file itself can't be read or parsed. Distinct
    from a module failing — this means we never got a usable email at all."""


# ============================================================
# 1. Reading and parsing the .eml file
# ============================================================

def _read_eml(eml_path: str) -> str:
    try:
        with open(eml_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise PipelineInputError(f"File not found: {eml_path}")
    except IsADirectoryError:
        raise PipelineInputError(f"Expected a file but found a directory: {eml_path}")
    except PermissionError:
        raise PipelineInputError(f"Permission denied while reading: {eml_path}")
    except UnicodeDecodeError:
        raise PipelineInputError(
            f"Could not read '{eml_path}' as UTF-8 text. It may be saved in a "
            "different encoding (e.g. Latin-1 or Windows-1252, common with Outlook exports)."
        )
    except OSError as e:
        raise PipelineInputError(f"Could not read file '{eml_path}': {e}")


def _parse_eml(raw_email: str):
    try:
        return email.message_from_string(raw_email, policy=policy.default)
    except email.errors.MessageError as e:
        raise PipelineInputError(f"Could not parse email content: {e}")


def _extract_body(msg) -> str:
    """Best-effort plain-text body extraction, tolerant of missing/odd encodings."""
    try:
        if msg.is_multipart():
            parts = []
            for part in msg.walk():
                if part.get_content_type() == "text/plain" and not part.is_multipart():
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            parts.append(payload.decode(charset, errors="replace"))
            return "\n".join(parts)
        try:
            return msg.get_content()
        except Exception:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                return payload.decode(charset, errors="replace")
            return str(msg.get_payload() or "")
    except Exception:
        return ""


# ============================================================
# 2. Module wrappers — each one guarded so a module failure
#    (missing dependency, missing config, network error, etc.)
#    becomes a status="error" section, never a crash.
# ============================================================

def _run_header_forensics(raw_email: str) -> dict:
    from header_forensics import analyze_headers  # stdlib-only, always importable

    result = analyze_headers(raw_email)
    result["status"] = "error" if result.get("parse_error") else "ok"
    result["error"] = result.get("parse_error")
    return result


def _empty_nlp(status: str, error: str) -> dict:
    return {
        "phishing_score": None,
        "verdict": "UNKNOWN",
        "triggers": None,
        "status": status,
        "error": error,
    }


def _run_nlp(subject: str, body: str) -> dict:
    try:
        from predict import predict
    except Exception as e:
        return _empty_nlp("error", f"NLP Content Analysis module unavailable: {type(e).__name__}: {e}")

    try:
        result = predict(subject, body)
    except Exception as e:
        return _empty_nlp("error", f"NLP prediction failed: {type(e).__name__}: {e}")

    result["status"] = "ok"
    result["error"] = None
    return result


def _empty_origin(ip, status: str, error: str) -> dict:
    return {"ip": ip, "geo": None, "status": status, "error": error}


def _empty_ip_reputation(ip, status: str, error: str) -> dict:
    return {
        "ip": ip,
        "abusive": None,
        "abuse_score": None,
        "is_tor": None,
        "usage_type": None,
        "spamhaus_listed": None,
        "spamhaus_codes": [],
        "verdict": "UNKNOWN",
        "status": status,
        "error": error,
    }


def _run_ip_geolocation(ip: str):
    """Returns (origin_dict, ip_reputation_dict)."""
    if not ip:
        return (
            _empty_origin(None, "skipped", "No originating IP found in headers"),
            _empty_ip_reputation(None, "skipped", "No originating IP found in headers"),
        )

    try:
        from geolocation_modded import geolocate_ip
    except Exception as e:
        msg = f"IP Geolocation module unavailable: {type(e).__name__}: {e}"
        return _empty_origin(ip, "error", msg), _empty_ip_reputation(ip, "error", msg)

    try:
        geo_data, flag_data = geolocate_ip(ip)
    except Exception as e:
        msg = f"IP Geolocation lookup failed: {type(e).__name__}: {e}"
        return _empty_origin(ip, "error", msg), _empty_ip_reputation(ip, "error", msg)

    origin = {"ip": ip, "geo": geo_data, "status": "ok" if geo_data else "error",
              "error": None if geo_data else "Geolocation lookup returned no data (network error or invalid IP)"}

    if flag_data:
        ip_reputation = dict(flag_data)
        ip_reputation["status"] = "ok"
        ip_reputation["error"] = None
    else:
        ip_reputation = _empty_ip_reputation(
            ip, "error", "IP threat flagging returned no data (geolocation step failed before threat checks ran)"
        )

    return origin, ip_reputation


def _empty_domain(domain, status: str, error: str) -> dict:
    return {
        "name": domain,
        "age_days": None,
        "is_new": None,
        "has_mx": False,
        "mx_provider": None,
        "lookalike_of": None,
        "suspicious_tld": False,
        "verdict": "suspicious" if status == "error" else "unknown",
        "reasons": [error] if error else [],
        "status": status,
        "error": error,
    }


def _run_domain_intelligence(domain: str) -> dict:
    if not domain:
        return _empty_domain(None, "skipped", "No sender domain available (From header missing)")

    try:
        from analyze_domain import analyze_domain
    except Exception as e:
        return _empty_domain(domain, "error", f"Domain Intelligence module unavailable: {type(e).__name__}: {e}")

    try:
        result = analyze_domain(domain)
    except Exception as e:
        # analyze_domain() is documented to never raise, but guard anyway —
        # a module-level contract violation shouldn't be able to crash the pipeline.
        return _empty_domain(domain, "error", f"analyze_domain() raised unexpectedly: {type(e).__name__}: {e}")

    result["status"] = "ok"
    result["error"] = None
    return result


def _empty_campaign(email_id, status: str, error: str) -> dict:
    return {
        "email_id": email_id,
        "in_campaign": False,
        "campaign": None,
        "related_emails": [],
        "total_emails_processed": None,
        "graph_html_path": None,
        "graph_error": None,
        "status": status,
        "error": error,
    }


def _build_correlation_graph(G, campaigns, email_id: str):
    """Renders the real PyVis network graph (same G/campaigns correlation.py
    produces) to a self-contained HTML file (CDN-hosted JS/CSS, no local
    lib/ folder needed) so it can be embedded by a dashboard. Returns
    (path_or_None, error_or_None) - never raises."""
    try:
        from correlation import build_visualization
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        out_path = OUTPUT_DIR / f"{email_id}_graph.html"
        build_visualization(G, campaigns, output_html=str(out_path), cdn_resources="remote")
        return str(out_path), None
    except Exception as e:
        return None, f"Graph generation failed: {type(e).__name__}: {e}"


def _run_correlation(email_id: str) -> dict:
    try:
        from correlation import correlate
    except Exception as e:
        return _empty_campaign(
            email_id, "error", f"Correlation module unavailable: {type(e).__name__}: {e}"
        )

    try:
        result, graph = correlate(str(CSV_PATH))
    except Exception as e:
        return _empty_campaign(email_id, "error", f"Correlation run failed: {type(e).__name__}: {e}")

    related_emails = [
        r for r in result.get("relationships", [])
        if email_id in (r.get("email_1"), r.get("email_2"))
    ]
    campaign = next(
        (c for c in result.get("campaigns", []) if email_id in c.get("emails", [])), None
    )

    graph_html_path, graph_error = _build_correlation_graph(graph, result.get("campaigns", []), email_id)

    return {
        "email_id": email_id,
        "in_campaign": campaign is not None,
        "campaign": campaign,
        "related_emails": related_emails,
        "total_emails_processed": result.get("email_count"),
        "graph_html_path": graph_html_path,
        "graph_error": graph_error,
        "status": "ok",
        "error": None,
    }


# ============================================================
# 3. CSV history (correlation input)
# ============================================================

def _append_csv_row(row: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    file_exists = CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


# ============================================================
# 4. Overall score / verdict / red_flags
#
# NOTE: no module in the repo currently produces a single combined score —
# each one returns its own independent verdict. This weighting is a
# starting-point heuristic (not derived from labeled data) that the team
# should review and recalibrate together.
# ============================================================

def _combine(header, nlp, domain, ip_reputation, campaign):
    red_flags = list(header.get("flags", []))
    score = 0.0

    for protocol in ("spf", "dkim", "dmarc"):
        if header.get(protocol) != "pass":
            score += 5  # up to 15
    if header.get("from_missing"):
        score += 20
    if header.get("from_reply_to_mismatch"):
        score += 15

    if nlp.get("status") == "ok" and nlp.get("phishing_score") is not None:
        score += nlp["phishing_score"] * 40
        if nlp.get("verdict") == "PHISHING":
            red_flags.append(f"NLP content model flags this as phishing (score {nlp['phishing_score']})")

    if domain.get("status") == "ok" and domain.get("verdict") == "suspicious":
        score += 20
        red_flags.append(f"Sender domain '{domain.get('name')}' flagged suspicious by Domain Intelligence")

    if ip_reputation.get("status") == "ok":
        verdict = ip_reputation.get("verdict")
        if verdict == "FLAGGED":
            score += 25
            red_flags.append(f"Originating IP flagged (abuse score {ip_reputation.get('abuse_score')}/100)")
        elif verdict == "SUSPICIOUS":
            score += 12
            red_flags.append(f"Originating IP suspicious (abuse score {ip_reputation.get('abuse_score')}/100)")
        if ip_reputation.get("is_tor"):
            red_flags.append("Originating IP is a TOR exit node")
        if ip_reputation.get("spamhaus_listed"):
            red_flags.append("Originating IP is on the Spamhaus blocklist")

    if campaign.get("status") == "ok" and campaign.get("in_campaign"):
        score += 10
        confidence = (campaign.get("campaign") or {}).get("attribution_confidence")
        red_flags.append(f"Email correlates with a known campaign (attribution confidence: {confidence})")

    score = min(round(score, 1), 100)
    if score >= 65:
        risk_level, verdict = "HIGH", "PHISHING"
    elif score >= 35:
        risk_level, verdict = "MEDIUM", "SUSPICIOUS"
    else:
        risk_level, verdict = "LOW", "LEGIT"

    return score, risk_level, verdict, red_flags


# ============================================================
# 5. Main entry point
# ============================================================

def process_email(eml_path: str) -> dict:
    """
    Parse one .eml file, run it through every PhishIt module, append its
    indicators to the correlation history CSV, write the unified result to
    output/<email_id>.json, and return that same dictionary.

    Raises PipelineInputError if eml_path can't be read/parsed at all.
    Never raises for a downstream module failure — those show up as
    status="error" inside the relevant section of the returned dict.
    """
    raw_email = _read_eml(eml_path)
    msg = _parse_eml(raw_email)

    email_id = f"{Path(eml_path).stem}-{uuid.uuid4().hex[:8]}"
    subject = str(msg["Subject"]) if msg["Subject"] is not None else ""
    body = _extract_body(msg)

    header = _run_header_forensics(raw_email)
    nlp = _run_nlp(subject, body)
    origin, ip_reputation = _run_ip_geolocation(header.get("originating_ip"))
    domain = _run_domain_intelligence(header.get("from_domain"))

    sender_addr = parseaddr(header.get("from") or "")[1]
    url_match = URL_REGEX.search(body)
    url = url_match.group(0) if url_match else ""

    date_header = msg["Date"]
    try:
        timestamp = parsedate_to_datetime(str(date_header)).isoformat() if date_header else None
    except Exception:
        timestamp = None
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    _append_csv_row({
        "email_id": email_id,
        "sender": sender_addr or "",
        "domain": header.get("from_domain") or "",
        "ip": header.get("originating_ip") or "",
        "url": url or "",
        "reply_to": header.get("reply_to") or "",
        "timestamp": timestamp,
    })

    campaign = _run_correlation(email_id)

    score, risk_level, verdict, red_flags = _combine(header, nlp, domain, ip_reputation, campaign)

    unified = {
        "email_id": email_id,
        "source_file": str(eml_path),
        "verdict": verdict,
        "score": score,
        "risk_level": risk_level,
        "red_flags": red_flags,
        "origin": origin,
        "header": header,
        "nlp": nlp,
        "domain": domain,
        "ip_reputation": ip_reputation,
        "campaign": campaign,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / f"{email_id}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(unified, f, indent=2, default=str)
    unified["_output_path"] = str(out_path)

    return unified
