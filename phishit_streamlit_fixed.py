"""
PHISHIT — AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform
Streamlit conversion of the original React/JSX app.

ARCHITECTURE NOTE:
The dashboard does NOT analyze the email itself.
It writes the raw .eml content to a temp file, runs it through the real
pipeline.py (process_email), adapts that result into this dashboard's
display shape (see adapt_pipeline_result), then renders it.

SCORING/CALCULATIONS ARE NOT FINAL — team will finalize exact
penalty values and combination logic (see pipeline.py::_combine) after
all modules are integrated.
"""

import streamlit as st
import time
import math
import os
import sys
import tempfile
import uuid
import streamlit.components.v1 as components
from datetime import datetime, timezone
from pathlib import Path

# ─── PAGE CONFIG ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="PhishIt — Email Threat Detection",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── REAL BACKEND ──────────────────────────────────────────────────────────────
# Wired to the actual pipeline.py (Header Forensics -> NLP -> IP Geolocation ->
# Domain Intelligence -> Correlation). No mock data below this point.

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipeline import process_email, PipelineInputError  # noqa: E402


def _pct(value):
    """0-1 float -> 0-100 int, tolerant of None (module unavailable)."""
    if value is None:
        return 0
    return round(value * 100)


def _auth_word(value):
    return "PASS" if value == "pass" else "FAIL"


def adapt_pipeline_result(unified: dict) -> dict:
    """Map pipeline.process_email()'s real unified dict into the flat shape
    this dashboard's rendering code was built against, so the UI below needs
    no further changes to consume real data instead of the old mock."""
    header = unified["header"]
    nlp = unified["nlp"]
    domain = unified["domain"]
    ip_rep = unified["ip_reputation"]
    origin = unified["origin"]
    campaign = unified["campaign"]

    geo = origin.get("geo") or {}
    is_tor_or_proxy = bool(ip_rep.get("is_tor")) or ip_rep.get("usage_type") in (
        "VPN", "Anonymous Proxy", "Public Proxy",
    )

    # predict.py reports aggregate counts/flags, not literal matched phrases —
    # synthesize readable indicators from what's actually available instead of
    # inventing quoted phrases the model never returned.
    suspicious_phrases = []
    if nlp.get("status") == "ok":
        triggers = nlp.get("triggers") or {}
        if triggers.get("urgency_words_found"):
            suspicious_phrases.append(f"{triggers['urgency_words_found']} urgency word(s)")
        if triggers.get("generic_greeting"):
            suspicious_phrases.append("generic greeting")
        if triggers.get("urls_found"):
            suspicious_phrases.append(f"{triggers['urls_found']} link(s) in body")
        if not suspicious_phrases:
            suspicious_phrases.append("no strong content signals")
    else:
        suspicious_phrases.append(f"NLP module unavailable ({nlp.get('error') or 'unknown error'})")

    related_ids = set()
    for r in campaign.get("related_emails", []):
        for e in (r.get("email_1"), r.get("email_2")):
            if e and e != campaign.get("email_id"):
                related_ids.add(e)

    risk_tier = unified["risk_level"]
    risk_word = {"HIGH": "High Risk", "MEDIUM": "Medium Risk", "LOW": "Low Risk"}.get(risk_tier, risk_tier)

    return {
        "verdict": unified["verdict"],
        "score": round(unified["score"]),
        "risk_level": risk_word,
        "risk_tier": risk_tier,  # raw HIGH/MEDIUM/LOW, used only for styling
        "red_flags": unified["red_flags"] or ["No red flags identified"],
        "origin": {
            "country": geo.get("country") or "Unknown",
            "city": geo.get("city") or "Unknown",
            "is_vpn": is_tor_or_proxy,
        },
        "header": {
            "spf": _auth_word(header.get("spf")),
            "dkim": _auth_word(header.get("dkim")),
            "dmarc": _auth_word(header.get("dmarc")),
            "sender_ip": header.get("originating_ip") or "Unknown",
        },
        "nlp": {
            "phishing_score": _pct(nlp.get("phishing_score")),
            "suspicious_phrases": suspicious_phrases,
        },
        "domain": {
            "name": domain.get("name") or "Unknown",
            "age_days": domain.get("age_days") if domain.get("age_days") is not None else "N/A",
            "has_mx": bool(domain.get("has_mx")),
            "mx_provider": domain.get("mx_provider"),
            "lookalike_of": domain.get("lookalike_of"),
            "suspicious_tld": bool(domain.get("suspicious_tld")),
            "verdict": domain.get("verdict") or "unknown",
        },
        "ip_reputation": {
            "abuse_confidence_score": ip_rep.get("abuse_score") or 0,
            "is_proxy": is_tor_or_proxy,
        },
        "campaign": {
            "linked_emails": len(related_ids),
            "graph_file": campaign.get("graph_html_path") or "Not generated for this run",
        },
    }


def run_real_pipeline(raw_email: str) -> dict:
    """Writes the pasted/uploaded raw email to a temp .eml file and runs it
    through the real PhishIt pipeline (pipeline.process_email). Returns the
    raw, unadapted unified dict."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".eml", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(raw_email)
        tmp_path = tmp.name

    try:
        return process_email(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def validate_result(result: dict) -> bool:
    required = ["verdict", "score", "risk_level", "red_flags",
                 "origin", "header", "nlp", "domain", "ip_reputation", "campaign"]
    return all(k in result for k in required)

# ─── GLOBAL CSS ────────────────────────────────────────────────────────────────
def inject_css():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap');

    :root {
        --purple-900: #3B235F;
        --purple-800: #4C2A78;
        --purple-700: #5B4278;
        --purple-600: #7C3AED;
        --purple-500: #8B5CF6;
        --purple-400: #A855F7;
        --purple-300: #C4B5FD;
        --lavender-100: #EDE9FE;
        --lavender-50: #F3E8FF;
        --lavender-25: #F7F2FF;
        --white: #FFFFFF;
    }

    /* Global overrides */
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif !important;
        background: #faf8ff !important;
    }
    .stApp {
        background: linear-gradient(135deg, #faf8ff 0%, #f3e8ff 50%, #ede9fe 100%) !important;
        min-height: 100vh;
    }

    /* Hide default streamlit elements */
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 0 !important; max-width: 1200px !important; }

    /* ── NAV ── */
    .phishit-nav {
        background: rgba(255,255,255,0.85);
        backdrop-filter: blur(16px);
        border-bottom: 1px solid #EDE9FE;
        padding: 0 24px;
        position: sticky; top: 0; z-index: 100;
        display: flex; align-items: center; justify-content: space-between;
        height: 64px; margin-bottom: 0;
    }
    .nav-logo {
        display: flex; align-items: center; gap: 10px;
        font-size: 22px; font-weight: 900; color: #7C3AED;
        letter-spacing: -0.5px;
    }
    .nav-logo-icon {
        width: 32px; height: 32px;
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        border-radius: 8px;
        display: inline-flex; align-items: center; justify-content: center;
        color: white; font-size: 16px; font-weight: 900;
    }
    .nav-badge {
        font-size: 10px; font-weight: 700; color: #7C3AED;
        background: #EDE9FE; border: 1px solid #C4B5FD;
        padding: 2px 8px; border-radius: 20px; letter-spacing: 0.5px;
    }

    /* ── HERO ── */
    .hero-section {
        padding: 60px 24px 40px; text-align: center;
    }
    .hero-eyebrow {
        display: inline-flex; align-items: center; gap: 8px;
        font-size: 12px; font-weight: 600; color: #7C3AED;
        background: #EDE9FE; border: 1px solid #C4B5FD;
        padding: 6px 14px; border-radius: 20px; margin-bottom: 28px;
        letter-spacing: 0.4px;
    }
    .hero-dot {
        width: 6px; height: 6px; border-radius: 50%;
        background: #8B5CF6; display: inline-block;
        animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
    .hero-title {
        font-size: clamp(32px, 5vw, 64px); font-weight: 900;
        color: #3B235F; line-height: 1.05; letter-spacing: -2px;
        margin-bottom: 20px;
    }
    .hero-title span { color: #8B5CF6; }
    .hero-sub {
        font-size: 18px; color: #5B4278; max-width: 560px;
        margin: 0 auto 32px; line-height: 1.6; font-weight: 400;
    }
    .module-pills {
        display: flex; flex-wrap: wrap; justify-content: center;
        gap: 10px; margin-bottom: 40px;
    }
    .module-pill {
        font-size: 12px; font-weight: 600; color: #5B4278;
        background: white; border: 1.5px solid #C4B5FD;
        padding: 6px 14px; border-radius: 20px;
        box-shadow: 0 2px 8px rgba(124,58,237,0.08);
    }

    /* ── CARDS ── */
    .phishit-card {
        background: white; border: 1.5px solid #EDE9FE;
        border-radius: 20px; padding: 28px;
        box-shadow: 0 4px 24px rgba(124,58,237,0.08);
        margin-bottom: 20px;
    }
    .phishit-card-purple {
        background: linear-gradient(135deg, #F7F2FF, #F3E8FF);
        border-color: #C4B5FD;
    }
    .card-title {
        font-size: 13px; font-weight: 700; color: #7C3AED;
        text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 20px;
    }

    /* ── VERDICT BANNER ── */
    .verdict-banner {
        background: linear-gradient(135deg, #3B235F 0%, #7C3AED 100%);
        border-radius: 24px; padding: 48px; text-align: center;
        margin-bottom: 28px; position: relative; overflow: hidden;
        box-shadow: 0 8px 40px rgba(124,58,237,0.35);
    }
    .verdict-label {
        font-size: 12px; font-weight: 700; color: #C4B5FD;
        letter-spacing: 2px; text-transform: uppercase; margin-bottom: 16px;
    }
    .verdict-word {
        font-size: clamp(48px, 8vw, 80px); font-weight: 900;
        color: white; letter-spacing: -2px; line-height: 1; margin-bottom: 28px;
    }
    .verdict-metrics {
        display: flex; justify-content: center; gap: 60px;
    }
    .verdict-metric-label {
        font-size: 11px; font-weight: 600; color: #C4B5FD;
        letter-spacing: 1px; text-transform: uppercase; margin-bottom: 8px;
    }
    .verdict-metric-value {
        font-size: 32px; font-weight: 900; color: white; letter-spacing: -1px;
    }
    .verdict-metric-sub { font-size: 13px; color: #C4B5FD; margin-top: 4px; }
    .verdict-divider {
        width: 1px; background: rgba(255,255,255,0.15); height: 60px; align-self: center;
    }

    /* ── RED FLAGS ── */
    .red-flag-item {
        display: flex; align-items: flex-start; gap: 12px;
        background: #F7F2FF; border: 1.5px solid #C4B5FD;
        border-radius: 12px; padding: 14px 16px; margin-bottom: 12px;
    }
    .red-flag-icon {
        width: 28px; height: 28px; border-radius: 8px;
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        display: inline-flex; align-items: center; justify-content: center;
        flex-shrink: 0; color: white; font-size: 14px;
    }
    .red-flag-text { font-size: 14px; font-weight: 600; color: #4C2A78; padding-top: 3px; }

    /* ── AUTH GRID ── */
    .auth-item {
        border-radius: 12px; padding: 16px; text-align: center;
    }
    .auth-item-pass { background: #F3E8FF; border: 1.5px solid #C4B5FD; }
    .auth-item-fail { background: #F7F2FF; border: 1.5px solid #A855F7; }
    .auth-item-name {
        font-size: 11px; font-weight: 700; color: #7C3AED;
        letter-spacing: 0.6px; text-transform: uppercase;
    }
    .auth-status-pass { font-size: 20px; font-weight: 900; color: #7C3AED; margin: 6px 0 4px; }
    .auth-status-fail { font-size: 20px; font-weight: 900; color: #4C2A78; margin: 6px 0 4px; }
    .auth-item-desc { font-size: 11px; color: #5B4278; line-height: 1.4; }

    /* ── EVIDENCE ROWS ── */
    .evidence-row {
        border-bottom: 1px solid #EDE9FE; padding: 14px 0;
    }
    .evidence-row-label {
        font-size: 12px; font-weight: 700; color: #7C3AED;
        text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;
    }
    .evidence-row-value { font-size: 14px; color: #4C2A78; line-height: 1.5; }
    .evidence-row-sub { font-size: 12px; color: #5B4278; margin-top: 2px; line-height: 1.4; }

    /* ── CHIPS ── */
    .chip {
        font-family: 'JetBrains Mono', monospace;
        font-size: 12px; font-weight: 500; color: #5B4278;
        background: #EDE9FE; border: 1.5px solid #C4B5FD;
        padding: 5px 12px; border-radius: 20px; display: inline-block;
        margin: 4px;
    }

    /* ── METRIC BOX ── */
    .metric-box {
        background: #F7F2FF; border: 1.5px solid #C4B5FD;
        border-radius: 14px; padding: 16px; text-align: center;
    }
    .metric-box-value { font-size: 28px; font-weight: 900; color: #5B4278; }
    .metric-box-label {
        font-size: 11px; font-weight: 600; color: #7C3AED;
        text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px;
    }
    .metric-box-sub { font-size: 11px; color: #5B4278; margin-top: 6px; line-height: 1.4; }

    /* ── STATUS BADGE ── */
    .status-badge-warn {
        display: inline-flex; align-items: center; gap: 6px;
        font-size: 12px; font-weight: 700; color: #5B4278;
        background: #EDE9FE; border: 1.5px solid #C4B5FD;
        padding: 4px 12px; border-radius: 20px;
    }
    .status-badge-danger {
        display: inline-flex; align-items: center; gap: 6px;
        font-size: 12px; font-weight: 700; color: #4C2A78;
        background: #F3E8FF; border: 1.5px solid #A855F7;
        padding: 4px 12px; border-radius: 20px;
    }

    /* ── MAP PLACEHOLDER ── */
    .map-placeholder {
        background: linear-gradient(135deg, #F3E8FF, #EDE9FE);
        border: 2px solid #C4B5FD; border-radius: 16px;
        min-height: 200px;
        display: flex; flex-direction: column;
        align-items: center; justify-content: center; gap: 12px;
        position: relative; overflow: hidden; margin-top: 16px;
        padding: 32px 24px;
    }
    .map-grid {
        position: absolute; inset: 0;
        background-image:
            linear-gradient(rgba(139,92,246,0.08) 1px, transparent 1px),
            linear-gradient(90deg, rgba(139,92,246,0.08) 1px, transparent 1px);
        background-size: 28px 28px;
    }
    .map-pin-outer {
        position: relative; z-index: 1;
        width: 56px; height: 56px; border-radius: 50%;
        background: rgba(139,92,246,0.15); border: 2px solid #A855F7;
        display: flex; align-items: center; justify-content: center;
        animation: ping 2s ease-in-out infinite;
    }
    @keyframes ping {
        0%,100% { box-shadow: 0 0 0 0 rgba(139,92,246,0.4); }
        50% { box-shadow: 0 0 0 16px rgba(139,92,246,0); }
    }
    .map-pin-inner {
        width: 24px; height: 24px; border-radius: 50%;
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        display: flex; align-items: center; justify-content: center;
        color: white; font-size: 12px;
    }
    .map-location { font-size: 16px; font-weight: 800; color: #4C2A78; }
    .map-disclaimer {
        font-size: 11px; color: #5B4278; max-width: 380px;
        text-align: center; line-height: 1.5; position: relative; z-index: 1;
        background: rgba(255,255,255,0.7); padding: 8px 14px; border-radius: 8px;
        border: 1px solid #C4B5FD;
    }

    /* ── CAMPAIGN GRAPH ── */
    .campaign-graph {
        background: linear-gradient(135deg, #F7F2FF, #F3E8FF);
        border: 2px solid #C4B5FD; border-radius: 16px;
        padding: 32px; margin-top: 16px; min-height: 180px;
        display: flex; align-items: center; justify-content: center;
    }
    .graph-nodes { display: flex; flex-direction: column; align-items: center; gap: 0; }
    .graph-row { display: flex; align-items: center; gap: 24px; }
    .graph-node {
        padding: 8px 16px; border-radius: 10px; text-align: center;
        font-size: 12px; font-weight: 700; border: 2px solid #A855F7;
        background: white; color: #4C2A78;
        box-shadow: 0 2px 8px rgba(124,58,237,0.1);
        display: inline-block;
    }
    .graph-node-domain {
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        color: white; border-color: transparent;
        box-shadow: 0 4px 16px rgba(124,58,237,0.3);
        padding: 8px 16px; border-radius: 10px; text-align: center;
        font-size: 12px; font-weight: 700; display: inline-block;
    }
    .graph-node-current {
        background: linear-gradient(135deg, #EDE9FE, #F3E8FF);
        border: 2px solid #7C3AED; color: #4C2A78;
        box-shadow: 0 0 0 3px rgba(139,92,246,0.2);
        padding: 8px 16px; border-radius: 10px; text-align: center;
        font-size: 12px; font-weight: 700; display: inline-block;
    }

    /* ── CUSTODY GRID ── */
    .custody-item {
        background: #F7F2FF; border: 1.5px solid #C4B5FD;
        border-radius: 12px; padding: 12px 14px;
    }
    .custody-label {
        font-size: 10px; font-weight: 700; color: #7C3AED;
        text-transform: uppercase; letter-spacing: 0.5px;
    }
    .custody-value {
        font-size: 13px; font-weight: 600; color: #4C2A78;
        margin-top: 4px; word-break: break-all;
        font-family: 'JetBrains Mono', monospace;
    }

    /* ── PRINCIPLES ── */
    .principle-item {
        background: #F7F2FF; border: 1.5px solid #C4B5FD;
        border-radius: 12px; padding: 14px;
    }
    .principle-icon { font-size: 20px; margin-bottom: 8px; }
    .principle-title { font-size: 12px; font-weight: 700; color: #5B4278; }
    .principle-desc { font-size: 11px; color: #7C3AED; margin-top: 4px; line-height: 1.4; }

    /* ── DEMO BANNER ── */
    .demo-banner {
        background: #EDE9FE; border: 2px dashed #A855F7;
        border-radius: 12px; padding: 12px 18px; margin-bottom: 24px;
        font-size: 13px; color: #5B4278; font-weight: 500;
        display: flex; align-items: center; gap: 10px;
    }

    /* ── PIPELINE ── */
    .pipeline-overlay {
        background: rgba(247,242,255,0.98);
        border-radius: 20px; padding: 48px;
        text-align: center; margin: 40px 0;
        border: 2px solid #C4B5FD;
    }
    .pipeline-title {
        font-size: 22px; font-weight: 800; color: #4C2A78;
        margin-bottom: 8px; letter-spacing: -0.5px;
    }
    .pipeline-sub { font-size: 14px; color: #7C3AED; margin-bottom: 32px; font-weight: 500; }
    .pipeline-track { display: flex; flex-direction: column; align-items: center; gap: 0; }
    .pipeline-input-node {
        width: 220px; padding: 12px 20px; border-radius: 14px;
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        color: white; text-align: center;
        font-weight: 700; font-size: 14px;
        box-shadow: 0 4px 20px rgba(124,58,237,0.35);
        margin: 0 auto 0;
    }
    .pipeline-node {
        width: 220px; padding: 14px 20px; border-radius: 14px;
        border: 2px solid #C4B5FD; background: white;
        text-align: center; margin: 0 auto;
        box-shadow: 0 2px 12px rgba(124,58,237,0.08);
    }
    .pipeline-node-active {
        border-color: #8B5CF6;
        background: linear-gradient(135deg, #EDE9FE, #F3E8FF);
        box-shadow: 0 0 0 4px rgba(139,92,246,0.15), 0 4px 20px rgba(124,58,237,0.2);
        transform: scale(1.04);
        width: 220px; padding: 14px 20px; border-radius: 14px;
        text-align: center; margin: 0 auto;
    }
    .pipeline-node-done {
        border-color: #A855F7; background: #F7F2FF;
        width: 220px; padding: 14px 20px; border-radius: 14px;
        text-align: center; margin: 0 auto;
    }
    .pipeline-node-label {
        font-size: 11px; font-weight: 700; color: #7C3AED;
        text-transform: uppercase; letter-spacing: 0.6px;
    }
    .pipeline-node-name { font-size: 14px; font-weight: 700; color: #4C2A78; margin-top: 2px; }
    .pipeline-connector {
        width: 2px; height: 24px; margin: 0 auto;
        background: linear-gradient(to bottom, #C4B5FD, #8B5CF6);
    }
    .pipeline-connector-lit { background: #8B5CF6; width: 2px; height: 24px; margin: 0 auto; }
    .pipeline-result-node {
        width: 220px; padding: 14px 20px; border-radius: 14px;
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        color: white; text-align: center; font-weight: 700; font-size: 14px;
        box-shadow: 0 4px 20px rgba(124,58,237,0.35);
        opacity: 0.35; margin: 0 auto;
    }
    .pipeline-result-node-lit {
        opacity: 1;
        width: 220px; padding: 14px 20px; border-radius: 14px;
        background: linear-gradient(135deg, #7C3AED, #A855F7);
        color: white; text-align: center; font-weight: 700; font-size: 14px;
        box-shadow: 0 4px 20px rgba(124,58,237,0.35);
        transform: scale(1.04); margin: 0 auto;
    }

    /* ── BUTTONS ── */
    .stButton > button {
        font-family: 'Inter', sans-serif !important;
        font-weight: 700 !important; border-radius: 12px !important;
        transition: all 0.2s !important;
    }

    /* ── TEXTAREA ── */
    .stTextArea textarea {
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 13px !important; color: #3B235F !important;
        border: 2px solid #C4B5FD !important; border-radius: 16px !important;
        padding: 20px !important; line-height: 1.7 !important;
        background: white !important;
    }
    .stTextArea textarea:focus {
        border-color: #8B5CF6 !important;
        box-shadow: 0 0 0 4px rgba(139,92,246,0.12) !important;
    }

    /* ── FOOTER ── */
    .phishit-footer {
        text-align: center; padding: 40px 24px;
        border-top: 1px solid #EDE9FE; margin-top: 40px;
    }

    .mono { font-family: 'JetBrains Mono', monospace; font-size: 13px; }
    </style>
    """, unsafe_allow_html=True)

# ─── SESSION STATE ──────────────────────────────────────────────────────────────
def init_state():
    if "phase" not in st.session_state:
        st.session_state.phase = "input"
    if "raw_eml" not in st.session_state:
        st.session_state.raw_eml = ""
    if "result" not in st.session_state:
        st.session_state.result = None
    if "report_ts" not in st.session_state:
        st.session_state.report_ts = None
    if "evidence_id" not in st.session_state:
        st.session_state.evidence_id = None
    if "error" not in st.session_state:
        st.session_state.error = ""
    if "raw_result" not in st.session_state:
        st.session_state.raw_result = None

# ─── SCORE RING SVG ─────────────────────────────────────────────────────────────
RISK_COLORS = {
    "HIGH":   ("#FF4444", "#FF0000"),
    "MEDIUM": ("#F59E0B", "#D97706"),
    "LOW":    ("#22C55E", "#16A34A"),
}

def score_ring_svg(score: int, size: int = 120, risk_tier: str = "HIGH") -> str:
    r = (size - 12) / 2
    circ = 2 * math.pi * r
    frac = score / 100
    dash = frac * circ
    cx = cy = size / 2
    color_start, color_end = RISK_COLORS.get(risk_tier, RISK_COLORS["HIGH"])
    return f"""
    <svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="rgba(255,255,255,0.2)" stroke-width="10"/>
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none"
        stroke="url(#scoreGrad{size})" stroke-width="10"
        stroke-dasharray="{dash:.2f} {circ - dash:.2f}"
        stroke-linecap="round"
        transform="rotate(-90 {cx} {cy})"/>
      <defs>
        <linearGradient id="scoreGrad{size}" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="{color_start}"/>
          <stop offset="100%" stop-color="{color_end}"/>
        </linearGradient>
      </defs>
      <text x="{cx}" y="{cy - 4}" text-anchor="middle" fill="#FFFFFF"
        font-size="26" font-weight="900" font-family="Inter">{score}</text>
      <text x="{cx}" y="{cy + 16}" text-anchor="middle" fill="rgba(255,255,255,0.8)"
        font-size="11" font-weight="600" font-family="Inter">/100</text>
    </svg>
    """

# ─── PIPELINE ANIMATION ─────────────────────────────────────────────────────────
# Order matches the real pipeline.py execution order.
MODULES = [
    {"id": "m1", "label": "Module 1", "name": "Header Forensics"},
    {"id": "m2", "label": "Module 2", "name": "NLP Analysis"},
    {"id": "m3", "label": "Module 3", "name": "Geo / IP Origin"},
    {"id": "m4", "label": "Module 4", "name": "Domain Intelligence"},
    {"id": "m5", "label": "Module 5", "name": "Identity Correlation"},
]

def render_pipeline():
    placeholder = st.empty()
    timings = [0.6, 1.2, 1.9, 2.6, 3.3, 3.8]

    for step_idx, delay in enumerate(timings):
        if step_idx == 0:
            start = time.time()
        else:
            elapsed = time.time() - start
            wait = delay - elapsed
            if wait > 0:
                time.sleep(wait)

        step = step_idx  # -1 offset not needed in python version

        nodes_html = ""
        for i, m in enumerate(MODULES):
            if step > i:
                connector_class = "pipeline-connector-lit"
                node_class = "pipeline-node-done"
                prefix = "✓ "
            elif step == i:
                connector_class = "pipeline-connector-lit"
                node_class = "pipeline-node-active"
                prefix = "⟳ "
            else:
                connector_class = "pipeline-connector"
                node_class = "pipeline-node"
                prefix = ""

            nodes_html += (
                '<div class="' + connector_class + '"></div>'
                '<div class="' + node_class + '">'
                '<div class="pipeline-node-label">' + m['label'] + '</div>'
                '<div class="pipeline-node-name">' + prefix + m['name'] + '</div>'
                '</div>'
            )

        final_class = "pipeline-result-node-lit" if step >= 5 else "pipeline-result-node"
        connector_final = "pipeline-connector-lit" if step >= 5 else "pipeline-connector"

        html = (
            '<div class="pipeline-overlay">'
            '<p class="pipeline-title">Analysing email</p>'
            '<p class="pipeline-sub">Routing through five intelligence modules…</p>'
            '<div class="pipeline-track">'
            '<div class="pipeline-input-node">📧 Raw .eml</div>'
            + nodes_html +
            '<div class="' + connector_final + '"></div>'
            '<div class="' + final_class + '">✶ Final Assessment</div>'
            '</div>'
            '</div>'
        )
        placeholder.markdown(html, unsafe_allow_html=True)

    placeholder.empty()

# ─── GENERATE TXT REPORT ────────────────────────────────────────────────────────
def generate_txt_report(result: dict, ts: str) -> str:
    lines = [
        "=" * 60,
        "PHISHIT — FORENSIC INTELLIGENCE REPORT",
        "=" * 60,
        "",
        "CASE INFORMATION",
        "-" * 40,
        f"Timestamp:       {ts}",
        f"Verdict:         {result['verdict']}",
        f"Threat Score:    {result['score']}/100",
        f"Risk Level:      {result['risk_level']}",
        "",
        "EMAIL AUTHENTICATION",
        "-" * 40,
        f"SPF:             {result['header']['spf']}",
        f"DKIM:            {result['header']['dkim']}",
        f"DMARC:           {result['header']['dmarc']}",
        f"Sender IP:       {result['header']['sender_ip']}",
        "",
        "NLP / CONTENT ANALYSIS",
        "-" * 40,
        f"Phishing score:  {result['nlp']['phishing_score']}/100",
        f"Suspicious phrases: {', '.join(result['nlp']['suspicious_phrases'])}",
        "",
        "DOMAIN INTELLIGENCE",
        "-" * 40,
        f"Domain:          {result['domain']['name']}",
        f"Domain age:      {result['domain']['age_days']} days",
        f"MX record:       {result['domain']['mx_provider'] or 'Found' if result['domain']['has_mx'] else 'Not found'}",
        f"Lookalike of:    {result['domain']['lookalike_of'] or 'None detected'}",
        f"Domain verdict:  {result['domain']['verdict']}",
        "",
        "IP INTELLIGENCE",
        "-" * 40,
        f"Abuse confidence: {result['ip_reputation']['abuse_confidence_score']}/100",
        f"VPN/Proxy:       {'Detected' if result['ip_reputation']['is_proxy'] else 'Not detected'}",
        "",
        "APPROXIMATE ORIGIN (IP-BASED)",
        "-" * 40,
        f"Country:         {result['origin']['country']}",
        f"City:            {result['origin']['city']}",
        f"VPN/Proxy:       {'Detected' if result['origin']['is_vpn'] else 'Not detected'}",
        "",
        "DISCLAIMER: This location represents an approximate network origin",
        "associated with the analyzed IP. It does not identify an individual",
        "or prove their physical location.",
        "",
        "CAMPAIGN CORRELATION",
        "-" * 40,
        f"Potentially related emails: {result['campaign']['linked_emails']}",
        "",
        "RED FLAGS",
        "-" * 40,
        *[f"⚠ {f}" for f in result["red_flags"]],
        "",
        "=" * 60,
        "IMPORTANT: This report is generated from AI-assisted analysis.",
        "All findings are indicators, not definitive proof.",
        "Designed with privacy-aware evidence handling principles.",
        "=" * 60,
    ]
    return "\n".join(lines)

# ─── RENDER NAV ─────────────────────────────────────────────────────────────────
def render_nav():
    phase = st.session_state.phase
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("""
        <div style="display:flex;align-items:center;gap:10px;padding:16px 0 8px;">
            <div class="nav-logo-icon">⚡</div>
            <span style="font-size:22px;font-weight:900;color:#7C3AED;letter-spacing:-0.5px;">PhishIt</span>
            <span class="nav-badge">LIVE ANALYSIS</span>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        if phase == "results":
            if st.button("＋ New Email", key="nav_new", type="secondary"):
                st.session_state.phase = "input"
                st.session_state.raw_eml = ""
                st.session_state.result = None
                st.session_state.raw_result = None
                st.session_state.report_ts = None
                st.session_state.evidence_id = None
                st.session_state.error = ""
                st.rerun()

# ─── RENDER HERO ─────────────────────────────────────────────────────────────────
def render_hero():
    st.markdown("""
    <div class="hero-section">
        <div class="hero-eyebrow">
            <span class="hero-dot"></span>
            Smart India Hackathon · PhishIt
        </div>
        <h1 class="hero-title">
            Email Threat Detection<br>
            <span>&amp; Forensic Intelligence</span>
        </h1>
        <p class="hero-sub">
            Five specialized AI modules investigate every dimension of a suspicious email —
            from language patterns to network origin — and converge on a unified forensic assessment.
        </p>
        <div class="module-pills">
            <span class="module-pill">NLP / Fraud Detection</span>
            <span class="module-pill">Header Forensics</span>
            <span class="module-pill">Geo / IP Origin</span>
            <span class="module-pill">Domain Intelligence</span>
            <span class="module-pill">Identity Correlation</span>
            <span class="module-pill">Forensic Reporting</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

# ─── RENDER INPUT PHASE ──────────────────────────────────────────────────────────
def render_input():
    placeholder_text = (
        "Received: from mail.suspicious-domain.com ([102.89.x.x])\n"
        "        by mx.example.com with ESMTP\n"
        "        id abc123; Wed, 5 Jun 2024 10:22:17 +0000\n"
        "From: \"PayPal Security\" <security@paypa1-secure.com>\n"
        "To: victim@example.com\n"
        "Subject: URGENT: Verify your account immediately\n"
        "Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n\n"
        "Dear Customer,\n"
        "Your account will be suspended. Act now to verify your account.\n"
        "Click here: http://paypa1-secure.com/verify\n\n"
        "PayPal Team"
    )

    _, col, _ = st.columns([1, 3, 1])
    with col:
        st.markdown('<div class="phishit-card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Raw Email Input</div>', unsafe_allow_html=True)

        # ── Upload .eml file ──
        st.markdown('<label style="font-size:13px;font-weight:600;color:#7C3AED;margin-bottom:4px;display:block;">📎 Upload .eml file</label>', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            label="upload_eml",
            type=["eml"],
            label_visibility="collapsed",
            key="eml_uploader",
        )
        if uploaded_file is not None:
            try:
                file_content = uploaded_file.read().decode("utf-8", errors="replace")
                if file_content.strip():
                    st.session_state.raw_eml = file_content
                    st.success(f"✓ Loaded: {uploaded_file.name}")
            except Exception as e:
                st.error(f"Could not read file: {e}")

        st.markdown('<div style="text-align:center;font-size:12px;color:#9CA3AF;margin:8px 0;">— or paste below —</div>', unsafe_allow_html=True)

        st.markdown('<label style="font-size:15px;font-weight:600;color:#4C2A78;">Paste complete raw .eml content</label>', unsafe_allow_html=True)
        st.markdown('<p style="font-size:13px;color:#5B4278;margin-bottom:12px;line-height:1.5;">Include all headers: Received, From, To, Subject, Authentication-Results, and the full message body. PhishIt does not analyze the email here — it routes it to the five-module pipeline.</p>', unsafe_allow_html=True)

        raw_eml = st.text_area(
            label="eml_input",
            value=st.session_state.raw_eml,
            height=240,
            placeholder=placeholder_text,
            label_visibility="collapsed",
            key="eml_textarea",
        )
        st.session_state.raw_eml = raw_eml

        if st.session_state.error:
            st.markdown(f"""
            <div class="demo-banner" style="border-color:#A855F7;margin-top:8px;">
                <span>⚠</span> {st.session_state.error}
            </div>
            """, unsafe_allow_html=True)

        col_a, col_b = st.columns([1, 1])
        with col_a:
            if st.button("Clear", key="clear_btn", use_container_width=True):
                st.session_state.raw_eml = ""
                st.session_state.error = ""
                st.rerun()
        with col_b:
            if st.button("⚡ Analyse Email", key="analyse_btn", type="primary", use_container_width=True):
                if not st.session_state.raw_eml.strip():
                    st.session_state.error = "Please paste or upload a raw .eml email before starting the analysis."
                    st.rerun()
                else:
                    st.session_state.error = ""
                    st.session_state.phase = "pipeline"
                    st.rerun()

        st.markdown('</div>', unsafe_allow_html=True)

        # Architecture note
        st.markdown("""
        <div style="margin-top:20px;padding:16px 20px;background:#F7F2FF;border:1.5px solid #C4B5FD;border-radius:12px;">
            <p style="font-size:12px;color:#5B4278;line-height:1.6;margin:0;">
                <strong style="color:#7C3AED;">Architecture:</strong> PhishIt does not analyze the email in the browser.
                The raw .eml is dispatched to the real five-module pipeline (Header Forensics, NLP, Geo/IP, Domain Intelligence, Identity Correlation).
                The dashboard only visualizes the standardized result object.
                Running <strong>live</strong> against real WHOIS/DNS lookups, a real trained NLP model, and real IP threat-intel APIs.
            </p>
        </div>
        """, unsafe_allow_html=True)

# ─── RENDER PIPELINE PHASE ───────────────────────────────────────────────────────
def render_pipeline_phase():
    _, col, _ = st.columns([1, 2, 1])
    with col:
        render_pipeline()

    # After the animation, run the REAL pipeline (live WHOIS/DNS/IP-threat
    # lookups can take a few extra seconds beyond the animation itself).
    with st.spinner("Finishing analysis…"):
        try:
            raw_result = run_real_pipeline(st.session_state.raw_eml)
        except PipelineInputError as e:
            st.session_state.error = f"Could not analyze this email: {e}"
            st.session_state.phase = "input"
            st.rerun()
            return
        except Exception as e:
            st.session_state.error = f"Unexpected error while analyzing this email: {type(e).__name__}: {e}"
            st.session_state.phase = "input"
            st.rerun()
            return

    result = adapt_pipeline_result(raw_result)
    if not validate_result(result):
        st.session_state.error = "The analysis service returned an incomplete result."
        st.session_state.phase = "input"
        st.rerun()
    else:
        st.session_state.raw_result = raw_result
        st.session_state.result = result
        st.session_state.report_ts = datetime.now(timezone.utc).isoformat()
        st.session_state.evidence_id = f"PHI-{uuid.uuid4().hex[:8].upper()}"
        st.session_state.phase = "results"
        st.rerun()

# ─── RENDER RESULTS PHASE ────────────────────────────────────────────────────────
def render_results():
    result = st.session_state.result
    raw_result = st.session_state.raw_result
    report_ts = st.session_state.report_ts
    evidence_id = st.session_state.evidence_id

    # Live module-status banner — surfaces any module that degraded (missing
    # API key, network error, etc.) instead of silently hiding it.
    degraded = []
    for name, key in [
        ("Header Forensics", "header"), ("NLP Analysis", "nlp"),
        ("IP Geolocation", "origin"), ("IP Reputation", "ip_reputation"),
        ("Domain Intelligence", "domain"), ("Correlation", "campaign"),
    ]:
        section = (raw_result or {}).get(key, {})
        if section.get("status") in ("error", "skipped"):
            degraded.append(f"{name}: {section.get('error') or section.get('status')}")

    if degraded:
        items = "".join(f"<div>• {d}</div>" for d in degraded)
        st.markdown(f"""
        <div class="demo-banner">
            <span>⚠</span>
            <span><strong>Live analysis — {len(degraded)} module(s) returned partial data:</strong>
            <div style="margin-top:6px;font-size:12px;">{items}</div>
            The overall score below only reflects the modules that succeeded.</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="demo-banner">
            <span>✓</span>
            <span><strong>Live analysis.</strong> All 5 pipeline modules (Header Forensics, NLP, IP Geolocation,
            Domain Intelligence, Correlation) returned complete data for this email.</span>
        </div>
        """, unsafe_allow_html=True)

    # ── VERDICT BANNER ──
    risk_tier = result.get("risk_tier", "HIGH")
    risk_color = RISK_COLORS.get(risk_tier, RISK_COLORS["HIGH"])[0]
    score_svg = score_ring_svg(result["score"], size=100, risk_tier=risk_tier)
    st.markdown(f"""
    <div class="verdict-banner">
        <div class="verdict-label">Threat Assessment</div>
        <div class="verdict-word">{result['verdict']}</div>
        <div class="verdict-metrics">
            <div>
                <div class="verdict-metric-label">Threat Score</div>
                <div style="display:flex;justify-content:center;">{score_svg}</div>
            </div>
            <div class="verdict-divider"></div>
            <div>
                <div class="verdict-metric-label">Risk Level</div>
                <div class="verdict-metric-value" style="font-size:24px;padding-top:8px;color:{risk_color};font-weight:900;">{result['risk_level']}</div>
                <div class="verdict-metric-sub">Based on combined module output</div>
            </div>
            <div class="verdict-divider"></div>
            <div>
                <div class="verdict-metric-label">Red Flags</div>
                <div class="verdict-metric-value">{len(result['red_flags'])}</div>
                <div class="verdict-metric-sub">Indicators identified</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── GRID ROW 1: Red Flags + Email Authentication ──
    col1, col2 = st.columns(2)

    with col1:
        flags_html = "".join([
            '<div class="red-flag-item"><div class="red-flag-icon">⚠</div><div class="red-flag-text">' + f + '</div></div>'
            for f in result["red_flags"]
        ])
        rf_card_html = (
            '<div class="phishit-card">'
            '<div class="card-title">Red Flags</div>'
            + flags_html +
            '<p style="font-size:11px;color:#7C3AED;margin-top:14px;line-height:1.5;">'
            'Red flags are indicators returned by the backend analysis modules. '
            'Each represents a suspicious signal requiring further investigation.'
            '</p>'
            '</div>'
        )
        st.markdown(rf_card_html, unsafe_allow_html=True)

    with col2:
        auth_items = [
            {"key": "spf",  "name": "SPF",  "full": "Sender Policy Framework",
             "pass_desc": "Sending server is authorized.",
             "fail_desc": "Sending server is not authorized to send for this domain."},
            {"key": "dkim", "name": "DKIM", "full": "DomainKeys Identified Mail",
             "pass_desc": "Digital signature validated.",
             "fail_desc": "Digital signature could not be validated."},
            {"key": "dmarc","name": "DMARC","full": "Message Authentication Policy",
             "pass_desc": "Domain policy satisfied.",
             "fail_desc": "Domain authentication policy not satisfied."},
        ]
        auth_cols_parts = []
        for item in auth_items:
            val = result["header"][item["key"]]
            is_pass = val == "PASS"
            item_cls = "auth-item-pass" if is_pass else "auth-item-fail"
            status_cls = "auth-status-pass" if is_pass else "auth-status-fail"
            desc = item["pass_desc"] if is_pass else item["fail_desc"]
            part = (
                '<div class="auth-item ' + item_cls + '" style="flex:1;min-width:0;">'
                '<div class="auth-item-name">' + item["name"] + '</div>'
                '<div class="' + status_cls + '">' + val + '</div>'
                '<div class="auth-item-desc">' + item["full"] + '</div>'
                '<div class="auth-item-desc" style="margin-top:4px;">' + desc + '</div>'
                '</div>'
            )
            auth_cols_parts.append(part)
        auth_cols_html = "".join(auth_cols_parts)

        sender_ip = result['header']['sender_ip']
        auth_card_html = (
            '<div class="phishit-card">'
            '<div class="card-title">Email Authentication</div>'
            '<div style="display:flex;gap:12px;">' + auth_cols_html + '</div>'
            '<div class="evidence-row" style="margin-top:16px;">'
            '<div class="evidence-row-label">Sender IP</div>'
            '<div class="evidence-row-value mono">' + sender_ip + '</div>'
            '<div class="evidence-row-sub">IP address identified in the email header chain. Origin is investigated by the Geo/IP module.</div>'
            '</div>'
            '</div>'
        )
        st.markdown(auth_card_html, unsafe_allow_html=True)

    # ── GRID ROW 2: Message Content + Domain Intelligence ──
    col3, col4 = st.columns(2)

    with col3:
        phrases_html = "".join(['<span class="chip">' + p + '</span>' for p in result["nlp"]["suspicious_phrases"]])
        nlp_score = str(result['nlp']['phishing_score'])
        if result['nlp']['phishing_score'] >= 50:
            content_desc = "The message contains language patterns commonly associated with phishing attempts — see the specific indicators detected below."
        else:
            content_desc = "The message content does not show strong phishing-style language patterns based on the indicators detected below."
        nlp_card_html = (
            '<div class="phishit-card">'
            '<div class="card-title">Message Content Analysis</div>'
            '<div class="evidence-row" style="padding-top:0;">'
            '<div class="evidence-row-label">NLP Phishing Score</div>'
            '<div style="display:flex;align-items:center;gap:16px;">'
            '<div style="font-size:36px;font-weight:900;color:#5B4278;">' + nlp_score + '</div>'
            '<div>'
            '<div style="font-size:12px;color:#7C3AED;">out of 100</div>'
            '<div style="font-size:12px;color:#5B4278;margin-top:2px;">Returned by NLP module</div>'
            '</div>'
            '</div>'
            '</div>'
            '<div class="evidence-row">'
            '<div class="evidence-row-label">Phishing-style language</div>'
            '<div class="evidence-row-value">' + content_desc + '</div>'
            '</div>'
            '<div>'
            '<div class="evidence-row-label" style="margin-bottom:4px;">Suspicious phrases detected</div>'
            '<div style="margin-top:6px;">' + phrases_html + '</div>'
            '<p style="font-size:11px;color:#7C3AED;margin-top:10px;line-height:1.5;">'
            'These phrases were flagged by the NLP module as indicators. Presence of these phrases is a signal, not proof of malicious intent.'
            '</p>'
            '</div>'
            '</div>'
        )
        st.markdown(nlp_card_html, unsafe_allow_html=True)

    with col4:
        mx_val = result['domain']['mx_provider'] or "Found" if result['domain']['has_mx'] else "None"
        mx_desc = (
            "Mail server confirmed via live DNS lookup. Legitimate mail senders typically have MX records."
            if result['domain']['has_mx']
            else "No MX record was observed. Legitimate mail senders typically have MX records."
        )
        lookalike_html = ""
        if result["domain"]["lookalike_of"]:
            d_name = result['domain']['name']
            d_like = result['domain']['lookalike_of']
            lookalike_html = (
                '<div class="evidence-row">'
                '<div class="evidence-row-label">Potential lookalike detected</div>'
                '<div class="evidence-row-value">'
                '<span class="mono" style="font-weight:700;">' + d_name + '</span>'
                '<span style="color:#7C3AED;margin:0 8px;">may resemble</span>'
                '<span class="mono" style="font-weight:700;">' + d_like + '</span>'
                '</div>'
                '<div class="evidence-row-sub">'
                'Character substitution detected (e.g. "1" replacing "l"). This is a potential impersonation indicator, not definitive proof.'
                '</div>'
                '</div>'
            )
        domain_name = result['domain']['name']
        age_days = str(result['domain']['age_days'])
        domain_verdict = result['domain']['verdict']
        domain_badge_cls = "status-badge-warn" if domain_verdict == "safe" else "status-badge-danger"
        domain_card_html = (
            '<div class="phishit-card">'
            '<div class="card-title">Domain Intelligence</div>'
            '<div class="evidence-row" style="padding-top:0;">'
            '<div class="evidence-row-label">Domain</div>'
            '<div class="evidence-row-value mono" style="font-size:15px;font-weight:700;color:#4C2A78;">' + domain_name + '</div>'
            '</div>'
            '<div style="display:flex;gap:12px;margin-bottom:14px;">'
            '<div class="metric-box" style="flex:1;">'
            '<div class="metric-box-value">' + age_days + '</div>'
            '<div class="metric-box-label">Domain Age</div>'
            '<div class="metric-box-sub">Days since registration. Very new domains warrant additional scrutiny.</div>'
            '</div>'
            '<div class="metric-box" style="flex:1;">'
            '<div class="metric-box-value">' + mx_val + '</div>'
            '<div class="metric-box-label">MX Record</div>'
            '<div class="metric-box-sub">' + mx_desc + '</div>'
            '</div>'
            '</div>'
            + lookalike_html +
            '<div class="evidence-row">'
            '<div class="evidence-row-label">Domain assessment</div>'
            '<span class="' + domain_badge_cls + '">' + domain_verdict + '</span>'
            '</div>'
            '</div>'
        )
        st.markdown(domain_card_html, unsafe_allow_html=True)

    # ── GRID ROW 3: IP Reputation + Origin Intelligence ──
    col5, col6 = st.columns(2)

    with col5:
        proxy_val = "✓" if result["ip_reputation"]["is_proxy"] else "✗"
        proxy_desc = (
            "A VPN or proxy was detected. This may mask the true origin. VPN use alone does not indicate malicious intent."
            if result["ip_reputation"]["is_proxy"]
            else "No VPN or proxy detected for this IP."
        )
        abuse_score = str(result['ip_reputation']['abuse_confidence_score'])
        ip_card_html = (
            '<div class="phishit-card">'
            '<div class="card-title">IP Reputation</div>'
            '<div style="display:flex;gap:12px;">'
            '<div class="metric-box" style="flex:1;">'
            '<div class="metric-box-value">' + abuse_score + '</div>'
            '<div class="metric-box-label">Abuse Confidence</div>'
            '<div class="metric-box-sub">Score from abuse/reputation database (0–100). Higher values indicate more reports of malicious activity.</div>'
            '</div>'
            '<div class="metric-box" style="flex:1;">'
            '<div class="metric-box-value">' + proxy_val + '</div>'
            '<div class="metric-box-label">VPN / Proxy</div>'
            '<div class="metric-box-sub">' + proxy_desc + '</div>'
            '</div>'
            '</div>'
            '<p style="font-size:11px;color:#7C3AED;margin-top:14px;line-height:1.5;">'
            'IP reputation data is sourced from threat intelligence databases. A high abuse confidence score indicates prior reports of suspicious activity — it is one signal among many.'
            '</p>'
            '</div>'
        )
        st.markdown(ip_card_html, unsafe_allow_html=True)

    with col6:
        origin_rows = [
            ("Country", result["origin"]["country"]),
            ("City", result["origin"]["city"]),
            ("Sender IP", result["header"]["sender_ip"]),
            ("VPN / Proxy", "Detected" if result["origin"]["is_vpn"] else "Not detected"),
        ]
        rows_html = "".join([
            f'<div style="padding:10px 0;border-bottom:1px solid #EDE9FE;">'
            f'<div class="evidence-row-label">{label}</div>'
            f'<div class="evidence-row-value" style="font-weight:600;">{value}</div>'
            f'</div>'
            for label, value in origin_rows
        ])
        oi_city = result['origin']['city']
        oi_country = result['origin']['country']
        origin_card_html = (
            '<div class="phishit-card" style="margin-bottom:0;border-bottom-left-radius:0;border-bottom-right-radius:0;border-bottom:none;">'
            '<div class="card-title">Origin Intelligence</div>'
            + rows_html +
            '</div>'
        )
        st.markdown(origin_card_html, unsafe_allow_html=True)

        geo = (raw_result.get("origin") or {}).get("geo") or {}
        lat, lon = geo.get("lat"), geo.get("lon")
        if lat is not None and lon is not None:
            delta = 0.25
            bbox = f"{lon - delta},{lat - delta},{lon + delta},{lat + delta}"
            map_url = (
                f"https://www.openstreetmap.org/export/embed.html?"
                f"bbox={bbox}&layer=mapnik&marker={lat}%2C{lon}"
            )
            st.markdown(
                '<div style="border:1.5px solid #EDE9FE;border-top:none;border-radius:0 0 20px 20px;'
                'overflow:hidden;background:white;">',
                unsafe_allow_html=True,
            )
            components.iframe(map_url, height=260, scrolling=False)
            vpn_note = " (this IP shows signs of a VPN/proxy, so the plotted location may be an anonymization endpoint, not the true sender)" if result["origin"]["is_vpn"] else ""
            st.markdown(
                '<div style="padding:12px 28px 20px;font-size:11px;color:#5B4278;line-height:1.5;">'
                'Real map, centered on the coordinates ip-api.com returned for sender IP '
                '<span class="mono">' + result['header']['sender_ip'] + '</span> — '
                'approximately <strong>' + oi_city + ', ' + oi_country + '</strong>' + vpn_note + '. '
                "This is a network origin (ISP/hosting/VPN endpoint), not a person's physical location."
                '</div></div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                '<div class="map-placeholder" style="border-radius:0 0 20px 20px;margin-top:0;border-top:none;">'
                '<div class="map-grid"></div>'
                '<div class="map-pin-outer"><div class="map-pin-inner">📍</div></div>'
                '<div style="position:relative;z-index:1;text-align:center;">'
                '<div class="map-location">' + oi_city + ', ' + oi_country + '</div>'
                '<div style="font-size:11px;color:#7C3AED;margin-top:2px;">No coordinates available</div>'
                '</div>'
                '<div class="map-disclaimer">'
                'The IP Geolocation module did not return coordinates for this IP (lookup failed or unavailable), '
                'so no map can be plotted for this result.'
                '</div>'
                '</div>',
                unsafe_allow_html=True,
            )

    # ── CAMPAIGN CORRELATION (full width) ──
    cc_linked = str(result['campaign']['linked_emails'])
    raw_campaign = raw_result.get("campaign") or {}
    real_campaign = raw_campaign.get("campaign")  # the cluster dict, or None if not in one
    shared_indicators = (real_campaign or {}).get("shared_indicators") or []
    graph_html_path = raw_campaign.get("graph_html_path")
    graph_error = raw_campaign.get("graph_error")

    indicators_html = "".join(
        '<span class="chip">' + s + '</span>' for s in shared_indicators
    ) or '<span style="font-size:12px;color:#5B4278;">No shared infrastructure with any other processed email — this looks isolated.</span>'

    campaign_summary_html = (
        '<div class="phishit-card" style="margin-bottom:0;border-bottom-left-radius:0;border-bottom-right-radius:0;">'
        '<div class="card-title">Campaign Correlation</div>'
        '<div style="display:flex;align-items:flex-start;gap:32px;flex-wrap:wrap;">'
        '<div>'
        '<div class="metric-box" style="min-width:160px;text-align:center;">'
        '<div class="metric-box-value">' + cc_linked + '</div>'
        '<div class="metric-box-label">Potentially Related Emails</div>'
        '<div class="metric-box-sub">Detected via shared infrastructure indicators</div>'
        '</div>'
        '</div>'
        '<div style="flex:1;min-width:260px;">'
        '<p style="font-size:13px;color:#4C2A78;margin-bottom:12px;line-height:1.6;">'
        'The correlation module identified <strong>' + cc_linked + ' potentially related messages</strong> sharing infrastructure '
        'and domain indicators with this email, out of <strong>' + str(raw_campaign.get("total_emails_processed", 0)) + '</strong> emails processed so far. '
        'These messages may be part of the same campaign, but shared indicators alone do not confirm a single threat actor.'
        '</p>'
        '<div style="margin-top:6px;">' + indicators_html + '</div>'
        '<p style="font-size:12px;color:#5B4278;line-height:1.5;margin-top:12px;">'
        'Correlation basis: shared sender IP, domain infrastructure, and header patterns. Use language such as “potentially correlated” and “requires investigation” — not “same attacker.”'
        '</p>'
        '</div>'
        '</div>'
        '</div>'
    )
    st.markdown(campaign_summary_html, unsafe_allow_html=True)

    graph_html = None
    if graph_html_path:
        try:
            with open(graph_html_path, "r", encoding="utf-8") as f:
                graph_html = f.read()
        except OSError as e:
            graph_error = graph_error or f"Could not read generated graph file: {e}"

    graph_wrapper_style = (
        'border:1.5px solid #EDE9FE;border-top:none;border-radius:0 0 20px 20px;'
        'overflow:hidden;background:white;padding:8px;'
    )
    if graph_html:
        st.markdown(f'<div style="{graph_wrapper_style}">', unsafe_allow_html=True)
        components.html(graph_html, height=560, scrolling=True)
        st.markdown(
            '<div style="padding:4px 20px 16px;font-size:11px;color:#7C3AED;">'
            'Real NetworkX/PyVis graph built from data/emails_processed.csv — every node and edge above is '
            'real correlation data, not a mockup. Drag nodes, scroll to zoom, hover for details.'
            '</div></div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div style="{graph_wrapper_style}padding:20px;font-size:12px;color:#5B4278;">'
            '⚠ Interactive graph unavailable for this run'
            + (f': {graph_error}' if graph_error else '.')
            + '</div></div>',
            unsafe_allow_html=True,
        )

    # ── FORENSIC REPORT (full width) ──
    ts_display = report_ts[:19].replace("T", " ") + " UTC" if report_ts else "—"
    custody_items = [
        ("Evidence ID", evidence_id or "—"),
        ("Timestamp", ts_display),
        ("Input Type", "Raw .eml (text)"),
        ("Processing", "Live pipeline (5 modules)"),
        ("Result Status", "Complete"),
        ("SHA-256", "— (requires integration)"),
    ]
    custody_html = "".join([
        f'<div class="custody-item"><div class="custody-label">{label}</div><div class="custody-value">{value}</div></div>'
        for label, value in custody_items
    ])

    principles = [
        ("🔒", "Evidence Integrity", "Analysis results are not modified after generation."),
        ("🕐", "Timestamping", "Every analysis is time-stamped at generation."),
        ("🔍", "Auditability", "Each finding is traceable to a specific module."),
        ("🛡️", "Privacy-Aware", "Designed with privacy-aware evidence handling. Raw emails are not stored unnecessarily."),
    ]
    principles_html = "".join([
        f'<div class="principle-item"><div class="principle-icon">{icon}</div>'
        f'<div class="principle-title">{title}</div>'
        f'<div class="principle-desc">{desc}</div></div>'
        for icon, title, desc in principles
    ])

    forensic_card_html = (
        '<div class="phishit-card">'
        '<div class="card-title">Forensic Report &amp; Evidence Integrity</div>'
        '<div class="demo-banner" style="margin-bottom:20px;">'
        '<span>📋</span>'
        'The report reproduces the analysis result as received from the pipeline. It does not perform new analysis.'
        '</div>'
        '<p style="font-size:13px;font-weight:600;color:#4C2A78;margin-bottom:12px;">Evidence Integrity</p>'
        '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px;">'
        + custody_html +
        '</div>'
        '<p style="font-size:13px;font-weight:600;color:#4C2A78;margin-bottom:12px;">Evidence Handling Principles</p>'
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:16px;">'
        + principles_html +
        '</div>'
        '<p style="font-size:11px;color:#5B4278;margin:16px 0 20px;line-height:1.5;">'
        'Designed with privacy-aware evidence handling principles. This platform does not claim regulatory compliance unless it has been independently verified.'
        '</p>'
        '</div>'
    )
    st.markdown(forensic_card_html, unsafe_allow_html=True)

    # Download buttons
    col_dl1, col_dl2, col_dl3 = st.columns([1, 1, 1])
    ts = report_ts or datetime.now(timezone.utc).isoformat()

    with col_dl2:
        txt_report = generate_txt_report(result, ts)
        st.download_button(
            label="📄 Download TXT Report",
            data=txt_report,
            file_name=f"phishit-report-{ts[:10]}.txt",
            mime="text/plain",
            use_container_width=True,
        )

    # Analyse another email button
    st.markdown("<div style='text-align:center;margin-top:32px;'>", unsafe_allow_html=True)
    _, btn_col, _ = st.columns([2, 1, 2])
    with btn_col:
        if st.button("＋ Analyse Another Email", type="primary", use_container_width=True, key="new_analysis"):
            st.session_state.phase = "input"
            st.session_state.raw_eml = ""
            st.session_state.result = None
            st.session_state.report_ts = None
            st.session_state.evidence_id = None
            st.session_state.error = ""
            st.rerun()
    st.markdown("</div>", unsafe_allow_html=True)

# ─── FOOTER ──────────────────────────────────────────────────────────────────────
def render_footer():
    st.markdown("""
    <div class="phishit-footer">
        <div style="font-size:13px;color:#7C3AED;font-weight:600;margin-bottom:6px;">
            ⚡ PhishIt — Smart India Hackathon
        </div>
        <div style="font-size:12px;color:#5B4278;line-height:1.6;max-width:560px;margin:0 auto;">
            Raw Email → Five Specialized Intelligence Modules → Unified Threat Assessment →
            Evidence → Geolocation → Campaign Correlation → Forensic Report.
            All findings are investigative indicators. Nothing herein constitutes definitive proof of malicious intent.
        </div>
    </div>
    """, unsafe_allow_html=True)

# ─── MAIN ────────────────────────────────────────────────────────────────────────
def main():
    inject_css()
    init_state()
    render_nav()
    render_hero()

    phase = st.session_state.phase

    if phase == "input":
        render_input()
    elif phase == "pipeline":
        render_pipeline_phase()
    elif phase == "results":
        render_results()

    render_footer()

if __name__ == "__main__":
    main()
