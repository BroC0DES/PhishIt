"""
test_mx_logic_offline.py

*** THIS FILE DOES NOT PERFORM ANY LIVE DNS LOOKUP. ***

It only tests classify_age()-style pure logic from mx_check.py -
specifically identify_provider() and flag_suspicious_mx() - by feeding
them made-up MX hostname lists directly. It never touches the network
and never calls check_mx_records() or fetch_mx_hosts().

Why this exists: we deliberately do NOT point this project at a real
domain with a broken/malicious MX setup (such setups don't stay online
reliably for demos, and pointing a "phishing detection" project at a
real live malicious domain is not something we want to do). This file
proves the suspicious-MX detection LOGIC is correct using a fabricated
example, completely separately from the live network-fetching code
(which is proven by mx_check.py and real domains instead).
"""

from mx_check import flag_suspicious_mx, identify_provider

print("OFFLINE test - no internet used, no DNS server contacted.\n")

# Simulated MX hostnames - NOT the result of any real lookup.
fake_mx_hosts = ["192.0.2.55"]  # 192.0.2.0/24 is reserved for documentation/examples (RFC 5737)

is_suspicious, reason = flag_suspicious_mx(fake_mx_hosts)
provider = identify_provider(fake_mx_hosts)

print(f"Simulated MX hosts: {fake_mx_hosts}")
print(f"is_suspicious: {is_suspicious}")
print(f"reason: {reason}")
print(f"provider guess: {provider}")

assert is_suspicious is True
assert "IP address" in reason
print("\nOffline logic check passed.")
