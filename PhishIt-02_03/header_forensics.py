import email
import email.errors
import re
import sys
from email import policy

SAMPLE_EMAIL = """From: "SBI Bank" <noreply@sbi.com>
Reply-To: scammer@randomsite.ru
Return-Path: bounce@suspicioussite.com
Message-ID: <abc123@suspicioussite.com>
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=suspicioussite.com;
    dkim=fail header.d=sbi.com;
    dmarc=fail action=none header.from=sbi.com
Received: from suspicioussite.com (192.168.1.100)
        by mx.google.com; Mon, 9 Sep 2024 10:00:00 +0000
Received: from unknownrelay.net (10.0.0.1)
        by suspicioussite.com; Mon, 9 Sep 2024 09:58:00 +0000

This is a fake phishing email body.
"""


def analyze_headers(raw_email: str) -> dict:
    """
    Main entry point / integration contract for the Header Forensics module.

    Input:  the raw text of a .eml file (a string)
    Output: a dictionary -
        {
            "from": str or None,               # raw From header, or None if missing
            "from_missing": bool,              # True if the From header is absent
            "reply_to": str or None,
            "return_path": str or None,
            "message_id": str or None,
            "from_domain": str or None,        # domain parsed out of From
            "reply_to_domain": str or None,     # domain parsed out of Reply-To
            "from_reply_to_mismatch": bool,
            "spf": "pass" | "fail" | ... | "not found",
            "dkim": same as spf,
            "dmarc": same as spf,
            "originating_ip": str or None,      # first hop IP in the Received chain
            "hop_count": int,
            "flags": [str, ...],                # plain-English red flags
            "risk_level": "HIGH" or "LOW",
            "parse_error": str or None,         # set only if raw_email could not be parsed
        }

    Always returns a complete dictionary in this exact shape - never raises.
    If the raw text can't be parsed as an email at all, every field falls
    back to a safe default and "parse_error" explains why, same policy as
    the rest of the PhishIt pipeline modules (never take down the caller).
    """
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
    except email.errors.MessageError as e:
        return {
            "from": None,
            "from_missing": True,
            "reply_to": None,
            "return_path": None,
            "message_id": None,
            "from_domain": None,
            "reply_to_domain": None,
            "from_reply_to_mismatch": False,
            "spf": "not found",
            "dkim": "not found",
            "dmarc": "not found",
            "originating_ip": None,
            "hop_count": 0,
            "received_hops": [],
            "flags": [f"Could not parse email headers: {e}"],
            "risk_level": "HIGH",
            "parse_error": str(e),
        }

    flags = []

    # --- Basic fields ---
    raw_from = msg["From"]
    reply_to = str(msg["Reply-To"]) if msg["Reply-To"] is not None else None
    return_path = str(msg["Return-Path"]) if msg["Return-Path"] is not None else None
    message_id = str(msg["Message-ID"]) if msg["Message-ID"] is not None else None
    auth_results = str(msg["Authentication-Results"]) if msg["Authentication-Results"] is not None else ""

    if raw_from is None:
        from_addr = None
        from_missing = True
        flags.append("Missing From header")
    else:
        from_addr = str(raw_from)
        from_missing = False

    from_domain = from_addr.split("@")[-1].replace(">", "").strip() if from_addr else None

    # --- Mismatch check: From vs Reply-To ---
    reply_to_domain = None
    from_reply_to_mismatch = False
    if from_addr is not None and reply_to:
        reply_to_domain = reply_to.split("@")[-1].replace(">", "").strip()
        if from_domain != reply_to_domain:
            from_reply_to_mismatch = True
            flags.append("From/Reply-To domain mismatch")

    # --- SPF / DKIM / DMARC ---
    auth = {}
    for protocol in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{protocol}=(\w+)", auth_results)
        result = match.group(1) if match else "not found"
        auth[protocol] = result
        if result != "pass":
            flags.append(f"{protocol.upper()} {result}")

    # --- Received chain / originating IP ---
    received_headers = msg.get_all("Received")
    originating_ip = None
    hop_count = 0
    received_hops = []
    if received_headers:
        hop_count = len(received_headers)
        ip_pattern = re.compile(r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)")
        for i, hop in enumerate(reversed(received_headers)):
            ip_match = ip_pattern.search(hop)
            ip = ip_match.group(1) if ip_match else None
            received_hops.append(ip)
            if i == 0:
                originating_ip = ip

    risk_level = "HIGH" if flags else "LOW"

    return {
        "from": from_addr,
        "from_missing": from_missing,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "from_reply_to_mismatch": from_reply_to_mismatch,
        "spf": auth["spf"],
        "dkim": auth["dkim"],
        "dmarc": auth["dmarc"],
        "originating_ip": originating_ip,
        "hop_count": hop_count,
        "received_hops": received_hops,
        "flags": flags,
        "risk_level": risk_level,
        "parse_error": None,
    }


def _print_report(result: dict) -> None:
    print("===== HEADER FORENSICS REPORT =====\n")

    if result["parse_error"]:
        print(f"[ERROR] {result['parse_error']}")
        return

    if result["from_missing"]:
        print("From:        [MISSING] — no From header present in this email")
    else:
        print(f"From:        {result['from']}")
    print(f"Reply-To:    {result['reply_to']}")
    print(f"Return-Path: {result['return_path']}")
    print(f"Message-ID:  {result['message_id']}")

    if result["from_missing"]:
        print("[FLAG] Cannot verify From/Reply-To match — From header is missing")
    elif result["reply_to"]:
        if result["from_reply_to_mismatch"]:
            print(f"[FLAG] From domain:     {result['from_domain']}")
            print(f"[FLAG] Reply-To domain: {result['reply_to_domain']}")
            print("[!] MISMATCH DETECTED — reply will go to a different domain than sender")
        else:
            print("[OK] From and Reply-To domains match")
    else:
        print("[OK] No Reply-To set (normal for automated emails)")

    print("\n--- Authentication Results ---")
    for protocol in ["spf", "dkim", "dmarc"]:
        value = result[protocol]
        status = "[OK]" if value == "pass" else "[FLAG]"
        print(f"{status} {protocol.upper()}: {value}")

    print("\n--- Received Chain ---")
    if result["hop_count"]:
        print(f"Total hops: {result['hop_count']}")
        for i, ip in enumerate(result["received_hops"]):
            print(f"  Hop {i + 1}: {ip if ip else 'IP not found'}")
        print(f"\nOriginating IP (first hop): {result['originating_ip']}")

    print("\n===== THREAT SUMMARY =====")
    if result["flags"]:
        print(f"Risk Level: {result['risk_level']} — {len(result['flags'])} issue(s) found\n")
        for f in result["flags"]:
            print(f"  [!] {f}")
    else:
        print(f"Risk Level: {result['risk_level']} — No issues detected")


if __name__ == "__main__":
    print("Arguments:", sys.argv)
    print("File being read:", sys.argv[1] if len(sys.argv) > 1 else "NO FILE — using sample data")

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_email = f.read()
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
            sys.exit(1)
        except IsADirectoryError:
            print(f"Error: Expected a file but found a directory: {file_path}")
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied while reading: {file_path}")
            sys.exit(1)
        except UnicodeDecodeError:
            print(
                f"Error: Could not read '{file_path}' as UTF-8 text. "
                "The file may be saved in a different encoding "
                "(e.g. Latin-1 or Windows-1252, common with Outlook exports)."
            )
            sys.exit(1)
        except OSError as e:
            print(f"Error: Could not read file '{file_path}': {e}")
            sys.exit(1)
    else:
        raw_email = SAMPLE_EMAIL

    report = analyze_headers(raw_email)
    if report["parse_error"]:
        print(f"Error: Could not parse the email. Details: {report['parse_error']}")
        sys.exit(1)

    _print_report(report)
