"""
test_wayback_fallback.py

Proves the WHOIS-fails -> Wayback-estimate FALLBACK path in
domain_age.py actually works.

We monkeypatch get_domain_creation_date() to always return None
(simulating what a real GDPR-redacted / privacy-protected WHOIS record
looks like to our code) rather than pick one specific real domain that
currently has WHOIS privacy protection on - because that setting can
change for any given domain at any time, which would make a hardcoded
example silently stop proving anything later. This is the exact same
technique domain_age.py's own file already uses to test the "new
domain" case (see NOTES_domain_age.txt Test 2), for the same reason.

Cases 1-3 are fully OFFLINE and deterministic (network calls are
mocked) - they prove the WIRING and the DATE-MATH/LABELING logic are
correct, without depending on a third-party API being reachable right
now. Case 4 is a best-effort LIVE call to the real Wayback Machine, to
additionally demonstrate the real network path end-to-end - but a
third-party API can legitimately be slow, rate-limited, or briefly
down, so Case 4 accepts EITHER a real estimate OR a graceful "unknown"
as a pass, and only fails if the code crashes or mislabels its source.
"""

from datetime import datetime, timedelta
from unittest.mock import patch

import domain_age
from domain_age import check_domain_age, get_wayback_estimate

print("=" * 70)
print("CASE 1 (offline/mocked): WHOIS fails, Wayback returns a real date")
print("=" * 70)
simulated_snapshot_date = datetime.now() - timedelta(days=1500)  # ~4 years old
with patch.object(domain_age, "get_domain_creation_date", return_value=None), \
     patch.object(domain_age, "get_wayback_estimate", return_value=simulated_snapshot_date):
    result = check_domain_age("example-privacy-protected-domain.com")

print(result)
assert result["source"] == "wayback_estimate", f"expected wayback_estimate, got {result['source']}"
assert result["age_days"] == 1500
assert result["is_new"] is False
assert "note" in result, "wayback-sourced results must carry an honesty note"
assert "LOWER-BOUND ESTIMATE" in result["note"]
print("PASSED - fallback fires when WHOIS fails, result correctly marked.\n")


print("=" * 70)
print("CASE 2 (offline/mocked): WHOIS *and* Wayback both fail -> 'unknown'")
print("=" * 70)
with patch.object(domain_age, "get_domain_creation_date", return_value=None), \
     patch.object(domain_age, "get_wayback_estimate", return_value=None):
    result = check_domain_age("example-totally-unreachable-domain.com")

print(result)
assert result["source"] == "unknown"
assert result["age_days"] is None
assert result["is_new"] is None
assert result["status"] == "unknown"
assert "note" not in result  # no estimate was actually made, so no estimate note
print("PASSED - no crash, honest 'unknown' result when everything fails.\n")


print("=" * 70)
print("CASE 3 (offline/mocked): WHOIS succeeds -> Wayback must NOT be called")
print("=" * 70)
with patch.object(domain_age, "get_wayback_estimate") as mock_wayback:
    result = check_domain_age("google.com")

print(result)
assert result["source"] == "whois"
assert "note" not in result
mock_wayback.assert_not_called()
print("PASSED - fallback is only used when WHOIS genuinely fails.\n")


print("=" * 70)
print("CASE 4 (live, best-effort): real call to the Wayback Machine API")
print("=" * 70)
print("wikipedia.org has been archived continuously since ~2001, so if the")
print("live API is reachable right now, this should return a real, old date.")
live_estimate = get_wayback_estimate("wikipedia.org")
print("get_wayback_estimate('wikipedia.org') ->", live_estimate)

if live_estimate is not None:
    age_days = (datetime.now() - live_estimate).days
    assert age_days > 30, "wikipedia.org's earliest snapshot should clearly be over 30 days old"
    print(f"PASSED (live) - got a real snapshot date, ~{age_days} days old.\n")
else:
    print(
        "Live Wayback call returned None (network hiccup, timeout, or "
        "rate-limited by the third-party API right now) - this IS the "
        "graceful-degradation path working as designed, not a failure of "
        "our code. Cases 1-3 above already prove the fallback logic "
        "itself is correct without depending on this live call.\n"
    )

print("All test_wayback_fallback.py checks passed.")
