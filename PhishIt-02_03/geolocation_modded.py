import os
import requests
import dns.resolver

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

# Spamhaus ZEN return codes -> human-readable label
SPAMHAUS_CODES = {
    "127.0.0.2":  "SBL",
    "127.0.0.3":  "SBL-CSS",
    "127.0.0.4":  "XBL",
    "127.0.0.9":  "SBL-DROP",
    "127.0.0.10": "PBL-ISP",
    "127.0.0.11": "PBL-SPAMHAUS",
}

# Spamhaus ZEN also returns a small set of "error" codes that are NOT
# blocklist hits — they mean the query itself couldn't be answered (most
# commonly: it came through a public/shared DNS resolver, or got
# rate-limited), not that the IP is listed. Treating these as a listing
# produces false positives on ANY IP queried from an affected network,
# including known-clean ones — so they're filtered out before deciding
# whether an IP is "Spamhaus listed".
SPAMHAUS_ERROR_CODES = {"127.255.255.252", "127.255.255.254", "127.255.255.255"}


def _check_abuseipdb(ip):
    """Query AbuseIPDB for abuse score, TOR flag, and usage type.
    Always returns a dict or None — never a tuple."""
    if not ABUSEIPDB_KEY:
        print("[!] ABUSEIPDB_KEY not set — skipping AbuseIPDB check")
        return None

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5,
        )
        d = response.json().get("data", {})
        return {
            "abuse_score": d.get("abuseConfidenceScore", 0),
            "is_tor":      d.get("isTor", False),
            "usage_type":  d.get("usageType", "Unknown"),
            "is_public":   d.get("isPublic", True),
        }
    except Exception as e:
        print(f"[!] AbuseIPDB check failed: {e}")
        return None  # None, not None, None


def _check_spamhaus(ip):
    """DNS-based Spamhaus ZEN lookup. Returns list of matched code labels.
    Spamhaus's own query-error codes (see SPAMHAUS_ERROR_CODES) are filtered
    out here so they're never mistaken for a real blocklist listing."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.zen.spamhaus.org"
        answers = dns.resolver.resolve(query, "A")
        raw_codes = [str(r) for r in answers]

        error_hits = [c for c in raw_codes if c in SPAMHAUS_ERROR_CODES]
        if error_hits:
            print(
                f"[!] Spamhaus query error for {ip}: {error_hits} — likely a "
                "public/rate-limited DNS resolver, not a real listing; ignoring"
            )

        real_codes = [c for c in raw_codes if c not in SPAMHAUS_ERROR_CODES]
        return [SPAMHAUS_CODES.get(c, c) for c in real_codes]
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as e:
        print(f"[!] Spamhaus check failed: {e}")
        return []


def flag_ip(ip):
    """Check an IP against AbuseIPDB and Spamhaus. Returns a unified verdict dict."""
    abuse = _check_abuseipdb(ip)
    spam  = _check_spamhaus(ip)

    # Safely extract fields — abuse may be None if API call failed
    abuse_score  = abuse["abuse_score"] if abuse else 0
    is_tor       = abuse["is_tor"]      if abuse else False
    usage_type   = abuse["usage_type"]  if abuse else "Unknown"
    spamhaus_hit = len(spam) > 0

    if is_tor or abuse_score >= 80 or spamhaus_hit:
        verdict = "FLAGGED"
    elif abuse_score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "ip":              ip,
        "abusive":         abuse_score >= 25,
        "abuse_score":     abuse_score,
        "is_tor":          is_tor,
        "usage_type":      usage_type,
        "spamhaus_listed": spamhaus_hit,
        "spamhaus_codes":  spam,
        "verdict":         verdict,
    }


def geolocate_ip(ip):
    print("\n===== GEOLOCATION REPORT =====\n")

    if not ip or ip == "IP not found":
        print("[!] No valid IP to geolocate.")
        return None, None

    geo_data  = None
    flag_data = None

    # --- Geolocation ---
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()

        if data['status'] == 'success':
            print(f"IP:          {data['query']}")
            print(f"Country:     {data['country']}")
            print(f"Region:      {data['regionName']}")
            print(f"City:        {data['city']}")
            print(f"ISP:         {data['isp']}")
            print(f"Org:         {data['org']}")
            print(f"Timezone:    {data['timezone']}")
            print(f"Coordinates: {data['lat']}, {data['lon']}")
            geo_data = data
        else:
            print(f"[!] Could not geolocate IP: {data.get('message', 'unknown error')}")

    except Exception as e:
        print(f"[!] Geolocation failed: {e}")
        return None, None  # ← exit early if no internet, skip threat flagging too

    # --- Threat Flagging ---
    print("\n--- IP Threat Analysis ---")
    try:
        flag_data = flag_ip(ip)
        print(f"AbuseIPDB Score:  {flag_data['abuse_score']}/100")
        print(f"TOR Exit Node:    {'YES [!]' if flag_data['is_tor'] else 'No'}")
        print(f"Usage Type:       {flag_data['usage_type']}")
        print(f"Spamhaus Listed:  {'YES [!] — ' + ', '.join(flag_data['spamhaus_codes']) if flag_data['spamhaus_listed'] else 'No'}")
        print(f"Verdict:          {flag_data['verdict']}")
    except Exception as e:
        print(f"[!] Threat flagging failed: {e}")

    return geo_data, flag_data  # always a tuple