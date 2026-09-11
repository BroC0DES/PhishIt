import argparse
import json
from urllib.parse import urlparse
 
import pandas as pd
import networkx as nx
from pyvis.network import Network
 
from ip_intelligence import get_ip_info  # Role 3's module
 
 
# ============================================================
# Helpers
# ============================================================
 
def clean(value):
    """Normalize a field: strip whitespace, lowercase, treat blanks/NaN as None.
    Returns None instead of '' or 'nan' so we never accidentally link
    two unrelated emails through a shared *missing* value."""
    if pd.isna(value):
        return None
    value = str(value).strip().lower()
    if value == "" or value == "nan":
        return None
    return value
 
 
_ip_cache = {}
 
 
def safe_ip_info(ip):
    """Cached, fault-tolerant wrapper around get_ip_info."""
    if ip in _ip_cache:
        return _ip_cache[ip]
    try:
        info = get_ip_info(ip)
    except Exception as e:
        info = {"country": "unknown", "city": "unknown", "isp": "unknown", "error": str(e)}
    _ip_cache[ip] = info
    return info
 
 
# ============================================================
# 1. Load email data
# ============================================================
 
def load_emails(csv_path):
    emails = pd.read_csv(csv_path)
    required_cols = ["email_id", "sender", "domain", "ip", "url", "reply_to", "timestamp"]
    missing = [c for c in required_cols if c not in emails.columns]
    if missing:
        raise ValueError(f"email.csv is missing required columns: {missing}")
    return emails
 
 
# ============================================================
# 2. Build the correlation graph
# ============================================================
 
def build_graph(emails: pd.DataFrame) -> nx.Graph:
    G = nx.Graph()
 
    for _, email in emails.iterrows():
        email_id = clean(email["email_id"])
        sender = clean(email["sender"])
        domain = clean(email["domain"])
        ip = clean(email["ip"])
        url = clean(email["url"])
        reply_to = clean(email["reply_to"])
 
        if email_id is None:
            continue  # can't do anything without an email id
 
        G.add_node(email_id, type="email")
 
        # Only add a node + edge for fields that actually have a value.
        # This is the fix for the NaN-node bug: an empty reply_to/url
        # no longer becomes a shared node linking unrelated emails.
        for value, node_type in [
            (sender, "sender"),
            (domain, "domain"),
            (ip, "ip"),
            (url, "url"),
            (reply_to, "reply_to"),
        ]:
            if value is not None:
                G.add_node(value, type=node_type)
                G.add_edge(email_id, value)
 
    return G
 
 
# ============================================================
# 3. Pairwise correlation scoring
# ============================================================
 
def calculate_score(email1, email2):
    score = 0
    reasons = []
 
    ip1, ip2 = clean(email1["ip"]), clean(email2["ip"])
    domain1, domain2 = clean(email1["domain"]), clean(email2["domain"])
    sender1, sender2 = clean(email1["sender"]), clean(email2["sender"])
    url1, url2 = clean(email1["url"]), clean(email2["url"])
    reply1, reply2 = clean(email1["reply_to"]), clean(email2["reply_to"])
 
    if ip1 and ip1 == ip2:
        score += 30
        reasons.append("Same IP")
 
    if domain1 and domain1 == domain2:
        score += 25
        reasons.append("Same Domain")
 
    if sender1 and sender1 == sender2:
        score += 10
        reasons.append("Same Sender")
 
    if url1 and url1 == url2:
        score += 25
        reasons.append("Same URL")
    elif url1 and url2:
        netloc1 = urlparse(url1).netloc
        netloc2 = urlparse(url2).netloc
        if netloc1 and netloc1 == netloc2:
            score += 15
            reasons.append("Same URL Domain")
 
    if reply1 and reply1 == reply2:
        score += 15
        reasons.append("Same Reply-To")
 
    try:
        time1 = pd.to_datetime(email1["timestamp"])
        time2 = pd.to_datetime(email2["timestamp"])
        if abs((time1 - time2).total_seconds()) <= 86400:
            score += 10
            reasons.append("Sent Within 24 Hours")
    except Exception:
        pass  # bad/missing timestamp shouldn't crash scoring
 
    return score, reasons
 
 
def find_relationships(emails: pd.DataFrame, threshold=50):
    """Returns a list of dicts describing each correlated email pair."""
    relationships = []
    max_possible_score = 130  # 30+25+10+25+15+10, kept in one place for consistency
 
    for i in range(len(emails)):
        for j in range(i + 1, len(emails)):
            email1 = emails.iloc[i]
            email2 = emails.iloc[j]
            score, reasons = calculate_score(email1, email2)
 
            if score >= threshold:
                percentage = min(score, max_possible_score) / max_possible_score * 100
                if percentage >= 80:
                    confidence = "HIGH"
                elif percentage >= 60:
                    confidence = "MEDIUM"
                else:
                    confidence = "LOW"
 
                relationships.append({
                    "email_1": email1["email_id"],
                    "email_2": email2["email_id"],
                    "correlation_percent": round(percentage, 1),
                    "confidence": confidence,
                    "reasons": reasons,
                })
 
    return relationships
 
 
# ============================================================
# 4. Campaign detection + attribution scoring
# ============================================================
 
def analyze_campaigns(G: nx.Graph):
    """Returns a list of campaign dicts (structured, ready for the API/dashboard)."""
    clusters = list(nx.connected_components(G))
    campaigns = []
 
    for i, cluster in enumerate(clusters, 1):
        campaign_id = f"C{i:03}"
 
        campaign_emails = [n for n in cluster if G.nodes[n].get("type") == "email"]
        campaign_domains = [n for n in cluster if G.nodes[n].get("type") == "domain"]
        campaign_ips = [n for n in cluster if G.nodes[n].get("type") == "ip"]
        campaign_urls = [n for n in cluster if G.nodes[n].get("type") == "url"]
        campaign_reply_to = [n for n in cluster if G.nodes[n].get("type") == "reply_to"]
 
        # Skip trivial "campaigns" that are really just a single isolated email
        # with no shared infrastructure at all - not useful to report.
        if len(campaign_emails) < 2 and not (campaign_domains or campaign_ips):
            continue
 
        shared_indicators = []
        if len(campaign_ips) == 1:
            shared_indicators.append(f"Shared IP: {campaign_ips[0]}")
        if len(campaign_domains) == 1:
            shared_indicators.append(f"Shared Domain: {campaign_domains[0]}")
        if len(campaign_reply_to) == 1:
            shared_indicators.append(f"Shared Reply-To: {campaign_reply_to[0]}")
 
        # IP intelligence for every IP in the campaign (not just when there's exactly one) —
        # multi-IP campaigns (e.g. rotating hosting infra) are common and shouldn't be skipped.
        ip_intel = {ip: safe_ip_info(ip) for ip in campaign_ips}
 
        # --- Attribution scoring ---
        # Fixed to reward *tight* infrastructure reuse (few distinct IPs/domains
        # across many emails) rather than only rewarding exactly-one-IP campaigns.
        attribution_score = 0
        if campaign_ips:
            attribution_score += 40 if len(campaign_ips) == 1 else max(0, 40 - 5 * (len(campaign_ips) - 1))
        if campaign_domains:
            attribution_score += 30 if len(campaign_domains) == 1 else max(0, 30 - 5 * (len(campaign_domains) - 1))
        if len(campaign_reply_to) == 1:
            attribution_score += 20
        if len(campaign_emails) >= 3:
            attribution_score += 10
        attribution_score = min(attribution_score, 100)
 
        if attribution_score >= 80:
            attribution_confidence = "HIGH"
        elif attribution_score >= 50:
            attribution_confidence = "MEDIUM"
        else:
            attribution_confidence = "LOW"
 
        campaigns.append({
            "campaign_id": campaign_id,
            "emails": campaign_emails,
            "domains": campaign_domains,
            "ips": campaign_ips,
            "urls": campaign_urls,
            "reply_to": campaign_reply_to,
            "shared_indicators": shared_indicators,
            "ip_intelligence": ip_intel,
            "attribution_score": attribution_score,
            "attribution_confidence": attribution_confidence,
        })
 
    return campaigns
 
 
# ============================================================
# 5. Public entry point for Role 6 / API integration
# ============================================================
 
def correlate(csv_path, threshold=50):
    """Main callable. Returns a dict ready to be JSON-serialized for the API."""
    emails = load_emails(csv_path)
    G = build_graph(emails)
    relationships = find_relationships(emails, threshold=threshold)
    campaigns = analyze_campaigns(G)
 
    return {
        "email_count": len(emails),
        "relationships": relationships,
        "campaigns": campaigns,
    }, G
 
 
# ============================================================
# 6. Pyvis visualization
# ============================================================
 
CAMPAIGN_PALETTE = [
    "#4CAF50", "#2196F3", "#FF9800", "#E91E63", "#9C27B0",
    "#00BCD4", "#8BC34A", "#FFC107", "#795548", "#607D8B",
]
 
NODE_STYLE = {
    "email": {"shape": "dot", "size": 30},
    "sender": {"shape": "diamond", "size": 20},
    "domain": {"shape": "square", "size": 25},
    "ip": {"shape": "triangle", "size": 25},
    "url": {"shape": "star", "size": 25},
    "reply_to": {"shape": "hexagon", "size": 20},
}
 
 
def build_visualization(G: nx.Graph, campaigns, output_html="campaign_graph.html"):
    net = Network(height="750px", width="100%", bgcolor="#ffffff", font_color="black")
 
    node_campaign = {}
    for c in campaigns:
        for node in c["emails"] + c["domains"] + c["ips"] + c["urls"] + c["reply_to"]:
            node_campaign[node] = c["campaign_id"]
 
    for node, data in G.nodes(data=True):
        node_type = data.get("type", "unknown")
        campaign = node_campaign.get(node, "Unassigned")
        idx = int(campaign[1:]) - 1 if campaign.startswith("C") else -1
        color = CAMPAIGN_PALETTE[idx % len(CAMPAIGN_PALETTE)] if idx >= 0 else "#757575"
        style = NODE_STYLE.get(node_type, {"shape": "dot", "size": 15})
 
        net.add_node(
            node,
            label=str(node),
            title=f"{node_type.title()}: {node}<br>Campaign: {campaign}",
            color=color,
            shape=style["shape"],
            size=style["size"],
        )
 
    for source, target in G.edges():
        net.add_edge(source, target)
 
    net.set_options("""
    var options = {
      "physics": {"enabled": true, "stabilization": {"iterations": 200}},
      "interaction": {"hover": true, "navigationButtons": true, "keyboard": true},
      "edges": {"smooth": {"enabled": true, "type": "dynamic"}}
    }
    """)
 
    net.write_html(output_html)
    return output_html
 
 
# ============================================================
# 7. CLI entry point
# ============================================================
 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email identity correlation & attribution engine")
    parser.add_argument("--csv", default="email.csv", help="Path to email.csv")
    parser.add_argument("--threshold", type=int, default=50, help="Min score to flag a pairwise relationship")
    parser.add_argument("--out", default="campaigns.json", help="Path to write structured JSON output")
    parser.add_argument("--html", default="campaign_graph.html", help="Path to write the pyvis graph")
    args = parser.parse_args()
 
    result, G = correlate(args.csv, threshold=args.threshold)
 
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2, default=str)
 
    build_visualization(G, result["campaigns"], output_html=args.html)
 
    print(f"Analyzed {result['email_count']} emails")
    print(f"Found {len(result['relationships'])} correlated pairs")
    print(f"Detected {len(result['campaigns'])} campaign(s)")
    print(f"Structured output -> {args.out}")
    print(f"Interactive graph -> {args.html}")
 