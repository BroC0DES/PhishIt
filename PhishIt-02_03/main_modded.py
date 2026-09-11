import email
import re
import sys
from email import policy
from geolocation_modded import geolocate_ip

# --- Read email ---
if len(sys.argv) > 1:
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        raw_email = f.read()
else:
    raw_email = """From: "SBI Bank" <noreply@sbi.com>
Reply-To: scammer@randomsite.ru
Return-Path: bounce@suspicioussite.com
Message-ID: <abc123@suspicioussite.com>
Authentication-Results: mx.google.com;
    spf=fail smtp.mailfrom=suspicioussite.com;
    dkim=fail header.d=sbi.com;
    dmarc=fail action=none header.from=sbi.com
 Received: from unknownrelay.net (10.0.0.1)
        by suspicioussite.com; Mon, 9 Sep 2024 09:58:00 +0000
Received: from suspicioussite.com (185.220.101.45)
        by mx.google.com; Mon, 9 Sep 2024 10:00:00 +0000


This is a fake phishing email body.
"""

msg = email.message_from_string(raw_email, policy=policy.default)
flags = []

print("===== HEADER FORENSICS REPORT =====\n")

from_addr    = str(msg['From'])
reply_to     = str(msg['Reply-To'])
return_path  = str(msg['Return-Path'])
message_id   = str(msg['Message-ID'])
auth_results = str(msg['Authentication-Results'])

print(f"From:        {from_addr}")
print(f"Reply-To:    {reply_to}")
print(f"Return-Path: {return_path}")
print(f"Message-ID:  {message_id}")

# --- Mismatch check ---
print("\n--- Mismatch Analysis ---")
if reply_to and reply_to != 'None':
    from_domain    = from_addr.split('@')[-1].replace('>', '').strip()
    replyto_domain = reply_to.split('@')[-1].replace('>', '').strip()
    if from_domain != replyto_domain:
        flags.append("From/Reply-To domain mismatch")
        print(f"[FLAG] From domain:     {from_domain}")
        print(f"[FLAG] Reply-To domain: {replyto_domain}")
        print("[!] MISMATCH DETECTED — reply will go to a different domain than sender")
    else:
        print("[OK] From and Reply-To domains match")
else:
    print("[OK] No Reply-To set (normal for automated emails)")

# --- SPF / DKIM / DMARC ---
print("\n--- Authentication Results ---")
for protocol in ['spf', 'dkim', 'dmarc']:
    match = re.search(rf'{protocol}=(\w+)', auth_results)
    result = match.group(1) if match else 'not found'
    status = "[OK]" if result == 'pass' else "[FLAG]"
    if result != 'pass':
        flags.append(f"{protocol.upper()} {result}")
    print(f"{status} {protocol.upper()}: {result}")

# --- Received chain ---
print("\n--- Received Chain ---")
received_headers = msg.get_all('Received')
originating_ip = None
if received_headers:
    print(f"Total hops: {len(received_headers)}")
    ip_pattern = re.compile(r'\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)')
    for i, hop in enumerate(reversed(received_headers)):
        ip_match = ip_pattern.search(hop)
        ip = ip_match.group(1) if ip_match else "IP not found"
        print(f"  Hop {i+1}: {ip}")
        if originating_ip is None and ip != "IP not found":
            originating_ip = ip
    print(f"\nOriginating IP: {originating_ip}")

# --- Geolocation + IP threat flagging ---
geo_data, flag_data = geolocate_ip(originating_ip)

# --- Fold IP threat verdict into flags ---
if flag_data:
    if flag_data["is_tor"]:
        flags.append("Originating IP is a TOR exit node")
    if flag_data["spamhaus_listed"]:
        flags.append(f"Originating IP on Spamhaus blocklist ({', '.join(flag_data['spamhaus_codes'])})")
    if flag_data["abuse_score"] >= 25:
        flags.append(f"Originating IP abuse score: {flag_data['abuse_score']}/100")
    if flag_data["usage_type"] in ("VPN", "Tor", "Anonymous Proxy", "Public Proxy"):
        flags.append(f"Originating IP usage type: {flag_data['usage_type']}")

# --- Threat Summary ---
print("\n===== THREAT SUMMARY =====")
if flags:
    print(f"Risk Level: HIGH — {len(flags)} issue(s) found\n")
    for f in flags:
        print(f"  [!] {f}")
else:
    print("Risk Level: LOW — No issues detected")
