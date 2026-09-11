"""
analyze_domain.py
Part of the PhishIt "Domain Intelligence" module.

Purpose:
    This is the COMBINER. It calls the three independent checks already
    built in this module -

        domain_age.py     -> check_domain_age()   (WHOIS, network)
        mx_check.py        -> check_mx_records()    (DNS, network)
        lookalike_check.py -> check_lookalike()      (pure string logic)

    - and merges their three separate dictionaries into ONE dictionary
    with a single overall verdict. This merged dictionary is the
    INTEGRATION CONTRACT for the rest of PhishIt: Person 5 (campaign
    clustering) and Person 6 (dashboard) both build against the exact
    field names returned by analyze_domain(). See NOTES_analyze_domain.txt
    for the full field-by-field spec.
"""

from domain_age import check_domain_age
from mx_check import check_mx_records
from lookalike_check import check_lookalike


def analyze_domain(domain):
    """
    Main entry point / integration contract for the Domain Intelligence
    module. Runs all three underlying checks on `domain` and combines
    them into one dictionary (exact shape below).

    Input:  a domain name string, e.g. "paypa1-secure-login.tk"
    Output: a dictionary -
        {
            "name": domain,
            "age_days": int or None,      # from domain_age.py
            "is_new": True/False/None,    # from domain_age.py
            "has_mx": True/False,         # from mx_check.py
            "mx_provider": str or None,   # raw MX hostname, from mx_check.py
            "lookalike_of": str or None,  # brand name, from lookalike_check.py
            "suspicious_tld": True/False, # from lookalike_check.py
            "verdict": "safe" or "suspicious",
            "reasons": [str, ...],
        }

    Always returns a complete dictionary in this exact shape - NEVER
    raises an exception, and NEVER silently omits a field. If a check
    fails or is unknown, that field becomes None (or the safest
    boolean default) instead of blowing up the whole pipeline.
    """
    try:
        # ------------------------------------------------------------
        # STEP 1: Run the three independent checks.
        #
        # Each of check_domain_age() / check_mx_records() / check_lookalike()
        # already guarantees it never raises - they catch their own
        # network/parsing errors internally and return an "unknown"-style
        # dict instead. We still wrap each call individually as a second
        # line of defense, in case a future change to one of those files
        # ever breaks that guarantee - one broken check should never take
        # down the other two.
        # ------------------------------------------------------------
        try:
            age_result = check_domain_age(domain)
        except Exception:
            age_result = {"age_days": None, "is_new": None}

        try:
            mx_result = check_mx_records(domain)
        except Exception:
            mx_result = {"has_mx": None, "mx_hosts": [], "reason": "MX check failed unexpectedly"}

        try:
            lookalike_result = check_lookalike(domain)
        except Exception:
            lookalike_result = {
                "lookalike_of": None,
                "suspicious_tld": None,
                "is_long": None,
                "reasons": ["Lookalike check failed unexpectedly"],
            }

        # ------------------------------------------------------------
        # STEP 2: Pull out just the fields the shared contract needs,
        # normalizing each one to the exact type the contract promises
        # (see the docstring above) - so callers never have to handle
        # a surprise type, only a surprise VALUE (like None).
        # ------------------------------------------------------------
        age_days = age_result.get("age_days")
        is_new = age_result.get("is_new")  # True / False / None - passed through as-is

        # has_mx: mx_check.py can return True, False, OR None (DNS lookup
        # itself failed - e.g. domain doesn't exist, DNS server unreachable).
        # This contract's has_mx field is strictly True/False (no None), so
        # an unknown MX status is folded into False. This is a deliberate,
        # CONSERVATIVE choice: "we could not confirm this domain can
        # receive mail" is treated the same as "it can't" for the verdict -
        # better to over-flag an unreachable/broken domain than silently
        # skip the MX signal for it. The unknown-vs-confirmed-missing
        # distinction is NOT lost, though - it's called out in `reasons`.
        raw_has_mx = mx_result.get("has_mx")
        has_mx = raw_has_mx if raw_has_mx is not None else False

        # mx_provider: deliberately the RAW MX hostname (e.g.
        # "aspmx.l.google.com"), not mx_check.py's human-readable provider
        # category (e.g. "Google Workspace / Gmail"). Campaign clustering
        # needs the literal server string - attackers reusing the same
        # mail infrastructure across many lookalike domains show up as
        # matching mx_provider values, which a friendly category name
        # would blur together. Highest-priority (first-sorted) host is
        # used. A Null MX ([".";] - RFC 7505, "this domain sends no mail")
        # has no real server to report, so it maps to None, same as an
        # empty MX list.
        mx_hosts = mx_result.get("mx_hosts") or []
        if mx_hosts and mx_hosts != ["."]:
            mx_provider = mx_hosts[0]
        else:
            mx_provider = None

        lookalike_of = lookalike_result.get("lookalike_of")

        # suspicious_tld / is_long: lookalike_check.py can return None for
        # both (only on invalid input, e.g. domain=None). The contract's
        # suspicious_tld field is strictly True/False, so None -> False.
        # is_long has no dedicated field in the shared contract (the team
        # agreed on a fixed dict shape) - but it still feeds the verdict
        # (see STEP 3) and always shows up in `reasons` when it fires, so
        # no information is lost, just not given its own top-level key.
        suspicious_tld = bool(lookalike_result.get("suspicious_tld"))
        is_long = bool(lookalike_result.get("is_long"))

        # ------------------------------------------------------------
        # STEP 3: Verdict logic.
        #
        # "suspicious" if ANY of the following are true, "safe" otherwise:
        #   - the domain is newly registered (is_new)
        #   - the domain has no confirmed MX / mail server (not has_mx)
        #   - the domain text resembles a known brand (lookalike_of is set)
        #   - the domain's TLD or overall length looks risky
        #     (suspicious_tld OR is_long)
        #
        # This is a simple, transparent OR of independent red flags, on
        # purpose: each of the three underlying checks was built and
        # tested as a standalone, meaningful signal in its own right (see
        # each check's own NOTES file). ANY single one firing is already
        # a real reason for a human (or a downstream model) to take a
        # closer look - we are not trying to build a single confidence
        # score here, just a fast triage flag. A false positive here
        # costs a closer look; a false negative costs a missed phishing
        # domain, so the logic is intentionally biased toward flagging.
        # ------------------------------------------------------------
        is_suspicious = bool(is_new) or (not has_mx) or (lookalike_of is not None) or suspicious_tld or is_long
        verdict = "suspicious" if is_suspicious else "safe"

        # ------------------------------------------------------------
        # STEP 4: Combine plain-English reasons from all three checks
        # into one list, so a human (or the dashboard) can see WHY the
        # verdict came out the way it did, not just the final label.
        # We include an explanatory line even for checks that came back
        # clean, for a full audit trail - not just the flagged ones.
        # ------------------------------------------------------------
        reasons = []

        # age_result["source"] tells us whether age_days/is_new came from
        # exact WHOIS data or a Wayback Machine lower-bound estimate (see
        # NOTES_domain_age.txt sections 8-9) - surfaced here in plain
        # English too, not just as a raw field, so the dashboard's reasons
        # list never implies an estimate is verified WHOIS fact.
        age_source = age_result.get("source")
        age_via = " (estimated from Wayback Machine, not WHOIS)" if age_source == "wayback_estimate" else ""

        if age_result.get("status") == "unknown":
            reasons.append("Domain age could not be determined (WHOIS lookup failed and no Wayback Machine history was found).")
        elif is_new:
            reasons.append(
                f"Domain is newly registered ({age_days} days old{age_via}) - domains under 30 days old "
                f"are commonly used for short-lived phishing campaigns."
            )
        else:
            reasons.append(f"Domain is well-established ({age_days} days old{age_via}) - not a newly registered domain.")

        if age_source == "wayback_estimate":
            reasons.append(age_result.get("note", "Domain age is a Wayback Machine estimate, not exact WHOIS data."))

        reasons.append(mx_result.get("reason", "MX check could not be completed."))
        if raw_has_mx is None:
            reasons.append(
                "MX status could not be confirmed via DNS (lookup failed or domain does not exist) - "
                "conservatively treated as 'no confirmed mail server' for the verdict above."
            )

        reasons.extend(lookalike_result.get("reasons") or [])

        return {
            "name": domain,
            "age_days": age_days,
            "is_new": is_new,
            "has_mx": has_mx,
            "mx_provider": mx_provider,
            "lookalike_of": lookalike_of,
            "suspicious_tld": suspicious_tld,
            "verdict": verdict,
            "reasons": reasons,
        }

    except Exception:
        # Last line of defense: no matter what unexpected thing goes
        # wrong above, ALWAYS return a complete, correctly-shaped
        # dictionary - never let analyze_domain() raise and take down
        # whatever pipeline is calling it. Conservatively verdict this
        # as "suspicious" since we could not actually verify anything.
        return {
            "name": domain,
            "age_days": None,
            "is_new": None,
            "has_mx": False,
            "mx_provider": None,
            "lookalike_of": None,
            "suspicious_tld": False,
            "verdict": "suspicious",
            "reasons": ["Unexpected error while analyzing domain - treated as suspicious as a precaution."],
        }


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # SMOKE TEST - runs analyze_domain() on real domains, over the real
    # network (WHOIS + DNS), so you can visually confirm the combined
    # output looks right end-to-end. Run with:
    #     .venv\\Scripts\\python.exe domain_intelligence\\analyze_domain.py
    #
    # NOTE on domain choice, same policy as domain_age.py / mx_check.py:
    # we do NOT hardcode a link to a real, currently-live PhishTank
    # phishing domain here. Those domains get taken down unpredictably
    # (this demo would silently start failing/changing), and this
    # project deliberately avoids pointing at live malicious
    # infrastructure. Instead, Case 3 below uses a SYNTHETIC domain
    # string built the same way a real phishing/typosquat domain is
    # (brand lookalike + risky TLD) - it doesn't need to exist to prove
    # the lookalike_check.py part of the pipeline works; the WHOIS/DNS
    # checks on it will just gracefully come back "unknown"/"no MX",
    # which is realistic for a throwaway attacker domain anyway.
    # ------------------------------------------------------------------

    print("Case 1: Well-known, long-established, safe domain (google.com)")
    print(analyze_domain("google.com"))

    print("\nCase 2: Domain that doesn't exist - proves graceful 'unknown' handling, no crash")
    print(analyze_domain("this-domain-should-not-exist-98765.com"))

    print("\nCase 3: Synthetic phishing-style domain (typosquat + risky TLD) - not a live/real domain")
    print(analyze_domain("paypa1-secure-login.tk"))

    print("\nCase 4: Real domain with a Null MX record (example.com) - a legitimate edge case")
    print(analyze_domain("example.com"))
    print(
        "Note on Case 4: example.com publishes an explicit RFC 7505 'Null MX' record "
        "(see NOTES_mx_check.txt) - it has has_mx False and gets verdict 'suspicious' "
        "under this module's conservative rule, even though a Null MX is a legitimate, "
        "on-purpose configuration. This is a known, documented limitation - see "
        "NOTES_analyze_domain.txt section on limitations."
    )
