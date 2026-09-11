"""
test_age_logic_offline.py

*** THIS FILE DOES NOT PERFORM ANY LIVE WHOIS LOOKUP. ***

It only tests classify_age() - the pure date-math function inside
domain_age.py - by feeding it a made-up ("simulated") date directly.
It never touches the network and never calls check_domain_age()
or get_domain_creation_date().

Why this exists: a real domain won't stay under 30 days old forever,
so we can't hardcode a real "brand-new domain" example that keeps
working correctly next month. This file proves the age-calculation
LOGIC is correct, using an artificial date, completely separately
from the live network-fetching code (which is proven by domain_age.py
and prove_live_lookup.py instead).
"""

from datetime import datetime, timedelta

from domain_age import classify_age

print("OFFLINE test - no internet used, no WHOIS server contacted.")
print("Simulated domain 'created' 5 days ago:\n")

simulated_creation_date = datetime.now() - timedelta(days=5)
result = classify_age(simulated_creation_date)
result["domain"] = "(simulated date - not a real domain lookup)"

print(result)
assert result["is_new"] is True
assert result["status"] == "new (suspicious)"
assert result["age_days"] == 5
print("\nOffline logic check passed.")
