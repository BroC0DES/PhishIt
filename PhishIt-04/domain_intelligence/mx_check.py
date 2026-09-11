"""
mx_check.py
Part of the PhishIt "Domain Intelligence" module.

Purpose:
    Check a domain's MX (Mail Exchange) records - the DNS entries that
    say which mail servers are allowed to receive email for that domain.
    A missing, broken, or oddly-configured MX setup is a signal that a
    domain may not be a real, legitimate mail sender (or that an email
    claiming to be "from" that domain could be spoofed).

All lookups below are REAL, LIVE DNS queries via dnspython - no
hardcoded/sample DNS data anywhere in this file. See the bottom of
this file for real test domains, and test_mx_logic_offline.py for a
separate, clearly-labeled offline test of the pure classification logic.
"""

import ipaddress

import dns.resolver  # dnspython library: sends real DNS queries over the network


# Known mail providers and a substring we can look for in their MX hostnames.
# This is a simple heuristic, not a complete list - see NOTES_mx_check.txt
# for limitations.
KNOWN_PROVIDERS = {
    "Google Workspace / Gmail": ["google.com", "googlemail.com"],
    "Microsoft 365 / Outlook": ["outlook.com", "protection.outlook.com"],
    "Zoho Mail": ["zoho.com", "zohomail.com"],
    "Yahoo": ["yahoodns.net"],
    "Proofpoint": ["pphosted.com"],
    "Mimecast": ["mimecast.com"],
    "Amazon SES / WorkMail": ["amazonaws.com", "awsapps.com"],
}


def _looks_like_ip_address(hostname):
    """
    MX records are supposed to point to a HOSTNAME (e.g. mail.example.com),
    never a raw IP address - that's against the email standard (RFC 5321)
    and is a common sign of a broken or malicious mail setup.
    This just tries to parse the string as an IP; if it succeeds, it's an IP.
    """
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def identify_provider(mx_hosts):
    """
    Pure logic: given a list of MX hostnames, guess which mail provider
    is being used, by checking for well-known hostname patterns.

    No network call here - just string matching - so this can be tested
    instantly and offline.
    """
    if not mx_hosts:
        return "none"

    lowered_hosts = [h.lower() for h in mx_hosts]
    for provider_name, keywords in KNOWN_PROVIDERS.items():
        for host in lowered_hosts:
            if any(keyword in host for keyword in keywords):
                return provider_name

    return "other / self-hosted"  # not in our known list - could be legit, just not recognised


def flag_suspicious_mx(mx_hosts):
    """
    Pure logic: given a list of MX hostnames that DOES have at least one
    entry, decide if anything about it looks suspicious.

    Right now this checks for one clear red flag: an MX record pointing
    directly at an IP address instead of a hostname. More checks (e.g.
    newly-registered mail server domains) can be added here later.
    """
    for host in mx_hosts:
        if _looks_like_ip_address(host):
            return True, f"MX record points to a raw IP address ({host}) instead of a hostname - invalid by email standards and a common red flag"

    return False, "MX records look normally configured"


def classify_mx(mx_hosts):
    """
    Pure logic: turn the raw list of MX hostnames (or None / empty list)
    into a final verdict dictionary. Kept separate from the network call
    (fetch_mx_hosts below) so it can be unit-tested without internet access.

    mx_hosts meaning, as passed in from fetch_mx_hosts():
        None        -> the DNS lookup itself failed / domain doesn't exist
        []          -> the lookup succeeded, but there are genuinely no MX records
        [.., ..]    -> the lookup succeeded and found one or more mail servers
    """
    if mx_hosts is None:
        # We could not get a real answer at all - never guess, just say so
        return {
            "has_mx": None,
            "provider": "unknown",
            "is_suspicious": None,
            "reason": "DNS lookup failed or domain does not exist",
            "status": "unknown",
        }

    if len(mx_hosts) == 0:
        # Domain is real (DNS responded) but has no mail servers configured
        return {
            "has_mx": False,
            "provider": "none",
            "is_suspicious": True,
            "reason": "Domain has no MX records - it cannot receive email, which is unusual for a domain claiming to send legitimate mail",
            "status": "suspicious",
        }

    if mx_hosts == ["."]:
        # RFC 7505 "Null MX": the domain owner has explicitly published a
        # record that means "this domain sends and receives NO email at
        # all". This is a deliberate, correctly-configured choice (common
        # on web-only domains) - not a red flag by itself. But it is a
        # useful fact: if an email ever claims to be FROM this domain,
        # that claim directly contradicts what the domain's own DNS says.
        return {
            "has_mx": False,
            "provider": "none (explicit Null MX - RFC 7505)",
            "is_suspicious": False,
            "reason": "Domain has published a 'Null MX' record - its owner has formally declared it does not send or receive email. Legitimate on its own, but any email claiming to be FROM this domain should be treated as highly suspicious.",
            "status": "no_mail_by_design",
        }

    provider = identify_provider(mx_hosts)
    is_suspicious, reason = flag_suspicious_mx(mx_hosts)
    return {
        "has_mx": True,
        "provider": provider,
        "is_suspicious": is_suspicious,
        "reason": reason,
        "status": "suspicious" if is_suspicious else "ok",
    }


def fetch_mx_hosts(domain):
    """
    Sends a REAL, LIVE DNS query for this domain's MX records, using
    dnspython. This is the only place in the file that touches the network.

    Returns:
        list of hostnames (strings), sorted by mail priority - on success
        []   - if the domain exists but genuinely has no MX records
        None - if the lookup could not be completed at all (domain doesn't
               exist, DNS server timeout/unreachable, or any other error)
               so the caller can report "unknown" instead of guessing.
    """
    try:
        answers = dns.resolver.resolve(domain, "MX")  # the actual live DNS query
        # Each answer has .preference (lower number = higher priority mail
        # server) and .exchange (the mail server's hostname).
        sorted_answers = sorted(answers, key=lambda record: record.preference)
        hosts = []
        for record in sorted_answers:
            exchange = str(record.exchange)
            if exchange == ".":
                # A single "." means a "Null MX" (RFC 7505) - keep it as-is,
                # classify_mx() below gives it special, non-suspicious handling
                hosts.append(".")
            else:
                # rstrip(".") removes the trailing dot DNS hostnames technically end with
                hosts.append(exchange.rstrip("."))
        return hosts
    except dns.resolver.NoAnswer:
        # The domain exists, but has no MX record - a real, meaningful answer
        return []
    except Exception:
        # Catches: NXDOMAIN (domain doesn't exist), timeouts, no nameservers
        # responded, or any other DNS/network failure - never crash the caller
        return None


def check_mx_records(domain):
    """
    Main entry point for this feature.

    Input:  a domain name string, e.g. "example.com"
    Output: a dictionary with the mail-server verdict for that domain

    Always returns a result - never raises an exception.
    """
    mx_hosts = fetch_mx_hosts(domain)
    result = classify_mx(mx_hosts)
    result["domain"] = domain
    result["mx_hosts"] = mx_hosts if mx_hosts is not None else []
    return result


if __name__ == "__main__":
    # Every case below is a REAL, LIVE DNS query - no hardcoded MX data.

    # --- Case 1: a domain with normal, valid MX records ---
    # Expect: has_mx True, provider recognised, status "ok"
    print("Case 1: Domain with valid MX records (google.com)")
    print(check_mx_records("google.com"))

    # --- Case 2: a real domain with a "Null MX" record ---
    # example.com is the IANA-reserved example domain. Live lookup shows
    # it actually publishes an RFC 7505 "Null MX" - an explicit, on-the-
    # record declaration that it sends/receives no email at all.
    # Expect: has_mx False, status "no_mail_by_design", is_suspicious False
    print("\nCase 2: Real domain with an explicit Null MX record (example.com)")
    print(check_mx_records("example.com"))

    # --- Case 3: a domain that does not exist at all ---
    # Expect: status "unknown" (we genuinely can't tell anything about it)
    print("\nCase 3: Domain that does not exist (DNS lookup fails)")
    print(check_mx_records("this-domain-should-not-exist-98765.com"))

    # NOTE: a live example of an IP-literal / malicious MX record is
    # intentionally not hardcoded here (we won't point this project at a
    # real malicious domain, and such setups don't stay online reliably
    # for demos anyway). See test_mx_logic_offline.py for a clearly
    # labeled, offline proof that the suspicious-MX detection logic works.
