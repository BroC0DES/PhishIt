"""
domain_age.py
Part of the PhishIt "Domain Intelligence" module.

Purpose:
    Check how old a domain is. Attackers commonly register a brand-new
    domain, use it for a phishing scam for a few days, then abandon it.
    So a domain younger than 30 days is treated as a red flag.

Primary data source is WHOIS (see get_domain_creation_date below). But
WHOIS registration dates are increasingly hidden behind GDPR/ICANN
privacy-redaction policies, so this file ALSO has a fallback: if WHOIS
fails or has no creation date, get_wayback_estimate() asks the Internet
Archive's free Wayback Machine API for this domain's EARLIEST known
snapshot date, which proves the domain already existed by then - a
lower-bound age estimate. See NOTES_domain_age.txt sections 8-9 for the
full reasoning, and check_domain_age() below for how the two are combined.
"""

import json
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

import whois  # python-whois library: looks up domain registration (WHOIS) records


def classify_age(creation_date, new_threshold_days=30):
    """
    Pure logic: given a creation date, work out the domain's age in days
    and whether it counts as "new" (suspicious).

    This is kept SEPARATE from the network call (get_domain_creation_date
    below) on purpose, so we can test the age-calculation logic instantly,
    with a made-up date, and without needing internet access or depending
    on a real domain staying "new" forever.
    """
    if creation_date is None:
        # No creation date available at all -> we can't judge age
        return {"age_days": None, "is_new": None, "status": "unknown"}

    # WHOIS sometimes returns a list of dates (e.g. original + re-registration
    # records). If so, just take the first one - that's the original date.
    if isinstance(creation_date, list):
        creation_date = creation_date[0]

    # Some WHOIS servers return "timezone-aware" dates (the date knows which
    # timezone it's in) and some return "naive" dates (no timezone attached).
    # To subtract two dates safely, both sides must match - so we strip the
    # timezone info here and just do a plain, naive comparison.
    if creation_date.tzinfo is not None:
        creation_date = creation_date.replace(tzinfo=None)

    now = datetime.now()  # current local date/time, naive, to match the line above
    age_days = (now - creation_date).days  # difference in whole days

    is_new = age_days < new_threshold_days

    return {
        "age_days": age_days,
        "is_new": is_new,
        "status": "new (suspicious)" if is_new else "established",
    }


def get_domain_creation_date(domain):
    """
    Talks to WHOIS servers (via python-whois) to fetch a domain's
    registration record, and pulls out just the creation date.

    Returns None if anything goes wrong (domain doesn't exist, WHOIS
    server didn't respond, record has no creation date, etc.) instead
    of crashing - so the rest of the pipeline can keep running even if
    one domain lookup fails.
    """
    try:
        record = whois.whois(domain)  # ask WHOIS for everything it knows about this domain
        return record.creation_date  # may be None, a datetime, or a list of datetimes
    except Exception:
        # Catches: domain not found, WHOIS server timeout/refusal, bad response, etc.
        return None


def get_wayback_estimate(domain):
    """
    FALLBACK, used only when WHOIS fails (see check_domain_age below).

    Talks to the Internet Archive's free Wayback Machine "CDX" API to
    find the EARLIEST snapshot ever taken of this domain. If the
    Wayback Machine crawled and archived a copy of the site on, say,
    2015-03-01, that PROVES the domain already existed by that date -
    so "earliest snapshot date" is a LOWER-BOUND estimate of the
    domain's true registration date (the real date could be the same
    or earlier; it can never be later than the earliest snapshot).

    This is the ONLY function in this file that talks to the Wayback
    Machine, kept deliberately separate from get_domain_creation_date()
    (the WHOIS call) - it is called ONLY as a fallback, never as part
    of the primary WHOIS lookup logic.

    Same reliability rules as the WHOIS call: 5-second timeout, catches
    every error, and returns None (never raises) if anything goes
    wrong - unreachable API, malformed response, or the domain genuinely
    having no archived snapshots at all.
    """
    try:
        # The "availability API" (not the CDX full-text search API) is
        # used here on purpose: it's a single, lightweight lookup built
        # exactly for "what's the archived snapshot closest to date X",
        # instead of searching/returning the domain's entire capture
        # history. Asking for the snapshot closest to a very early
        # target timestamp (1980, before the web existed) means the
        # "closest" match it can return IS the earliest snapshot on
        # record - and this stays fast even for huge, heavily-archived
        # domains, where the raw CDX search API can be slow enough to
        # blow past our 5-second budget.
        query = urllib.parse.urlencode({"url": domain, "timestamp": "19800101"})
        request = urllib.request.Request(
            f"https://archive.org/wayback/available?{query}",
            headers={"User-Agent": "PhishIt-DomainIntelligence/1.0"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))

        # No snapshot on record at all -> archived_snapshots is {} (empty)
        timestamp = data.get("archived_snapshots", {}).get("closest", {}).get("timestamp")
        if not timestamp:
            return None

        return datetime.strptime(timestamp, "%Y%m%d%H%M%S")  # e.g. "20150301120000"
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, AttributeError, json.JSONDecodeError):
        # Catches: network unreachable, 5s timeout, HTTP errors (incl.
        # 429 rate-limiting - urllib.error.HTTPError is a URLError
        # subclass), malformed/unexpected JSON shape, bad timestamp
        # format - never crash the caller, just report "no estimate".
        return None
    except Exception:
        # Belt-and-braces: any other unexpected failure still falls
        # back to "unknown" rather than raising
        return None


def check_domain_age(domain, new_threshold_days=30):
    """
    Main entry point for this feature.

    Input:  a domain name string, e.g. "example.com"
    Output: a dictionary describing its age and whether it looks "new"

    Tries WHOIS FIRST (get_domain_creation_date) - it's the authoritative,
    exact source when it's available. ONLY if WHOIS genuinely fails or
    has no creation date (increasingly common with GDPR/ICANN privacy
    redaction) does this fall back to get_wayback_estimate() for a
    lower-bound age estimate instead.

    The result always says which source was actually used, via the
    "source" field ("whois" or "wayback_estimate"), so downstream code
    (and the dashboard) can tell an exact WHOIS date apart from an
    estimate - never presenting an estimate as if it were exact fact.

    Always returns a result - never raises an exception - so it's safe
    to call on any domain, including ones with broken/missing WHOIS data
    AND no Wayback history at all (falls through to "unknown").
    """
    creation_date = get_domain_creation_date(domain)
    source = "whois"

    if creation_date is None:
        # Primary WHOIS lookup failed or had no creation date - fall
        # back to the Wayback Machine estimate instead of giving up.
        creation_date = get_wayback_estimate(domain)
        source = "wayback_estimate" if creation_date is not None else "unknown"

    result = classify_age(creation_date, new_threshold_days)
    result["domain"] = domain  # tag the result with which domain it's about
    result["source"] = source  # "whois" / "wayback_estimate" / "unknown"

    if source == "wayback_estimate":
        # Spelled out explicitly for honesty: this is NOT a WHOIS date.
        # It's a LOWER BOUND, so it can under-estimate age (a domain
        # could be much older than its earliest Wayback snapshot, e.g.
        # if it existed for a while before the crawler ever found it) -
        # it never over-estimates age. That means an is_new=True result
        # from this source is LESS certain than one from real WHOIS data
        # (the domain might actually be older, just not yet crawled),
        # while an is_new=False / "established" result from this source
        # is just as trustworthy as WHOIS (the domain has PROVABLY
        # existed at least that long).
        result["note"] = (
            "age_days/is_new here are a LOWER-BOUND ESTIMATE from the domain's "
            "earliest Wayback Machine snapshot, not exact WHOIS registration data "
            "(WHOIS lookup failed or was privacy-redacted). The domain could be "
            "OLDER than this estimate, never younger."
        )

    return result


if __name__ == "__main__":
    # Every case below goes through check_domain_age() -> get_domain_creation_date()
    # -> whois.whois(domain), i.e. a REAL network call to live WHOIS servers -
    # and, if that fails, on to the REAL Wayback Machine fallback too.
    # There is no hardcoded/sample data anywhere in this file.

    # --- Case 1: an old, well-established brand domain ---
    # Expect: status "established", is_new False, source "whois"
    print("Case 1: Old, well-established brand domain (google.com)")
    print(check_domain_age("google.com"))

    # --- Case 2: a domain with no WHOIS data AND no Wayback history ---
    # Using a domain that almost certainly doesn't exist, so BOTH the
    # live WHOIS lookup and the live Wayback fallback fail, and we fall
    # back to "unknown" instead of crashing or inventing a fake result.
    # Expect: status "unknown", age_days None, source "unknown"
    print("\nCase 2: Domain with no WHOIS data (does not exist)")
    print(check_domain_age("this-domain-should-not-exist-98765.com"))

    # NOTE: a live "brand-new domain" case is intentionally not hardcoded
    # here, because a real domain won't stay under 30 days old forever.
    # See prove_live_lookup.py to test check_domain_age() on ANY domain
    # you supply yourself, test_age_logic_offline.py for a separate,
    # clearly-labeled OFFLINE test of the pure date-math (no network call),
    # and test_wayback_fallback.py for a proof that the WHOIS-fails ->
    # Wayback-estimate fallback path itself works correctly.
