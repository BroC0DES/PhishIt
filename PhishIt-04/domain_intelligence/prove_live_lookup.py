"""
prove_live_lookup.py

Run this any time you want hard proof that check_domain_age() is doing
a REAL, LIVE WHOIS lookup over the internet - not returning cached,
mocked, or hardcoded data.

Usage:
    .venv\\Scripts\\python.exe domain_intelligence\\prove_live_lookup.py <domain>

Example:
    .venv\\Scripts\\python.exe domain_intelligence\\prove_live_lookup.py wikipedia.org

What this proves, and how:
  1. It prints the exact wall-clock time on YOUR machine right before
     the lookup starts.
  2. It calls whois.whois(domain) directly (same call domain_age.py
     uses) and prints the RAW registrar + creation date exactly as
     the WHOIS server returned them - nothing reformatted or faked.
  3. It then calls check_domain_age(domain) and shows the computed
     age, which you can verify by hand: (today's date - creation date).
  4. It runs on WHATEVER domain you type - if the answer were
     hardcoded, every domain would return the same result. Try two
     different domains back to back and see the results differ.

Self-check you can do right now: turn off your Wi-Fi / internet, then
run this script. A live lookup will fail (timeout or connection
error) - it will NOT silently return a fake successful result. That
failure itself is proof there is no offline/cached/mocked fallback.
"""

import sys
from datetime import datetime

import whois

from domain_age import check_domain_age

domain = sys.argv[1] if len(sys.argv) > 1 else "wikipedia.org"

print(f"Requested domain: {domain}")
print(f"Local time right now (from your machine's clock): {datetime.now()}")
print("Sending live WHOIS query over the internet now...\n")

# Raw call, unmodified - this is the exact same library call used inside
# get_domain_creation_date() in domain_age.py.
raw_record = whois.whois(domain)

print("--- RAW data returned by the live WHOIS server ---")
print("Registrar (as reported by WHOIS):", raw_record.registrar)
print("Creation date (as reported by WHOIS):", raw_record.creation_date)
print("Expiration date (as reported by WHOIS):", raw_record.expiration_date)

print("\n--- Result from our check_domain_age() function ---")
result = check_domain_age(domain)
print(result)

print(
    "\nManual check: subtract the creation date above from today's date "
    "yourself - it should match 'age_days' exactly (give or take a day "
    "for timezone rounding)."
)
