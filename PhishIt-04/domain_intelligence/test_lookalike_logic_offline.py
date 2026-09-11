"""
test_lookalike_logic_offline.py

*** THIS FILE DOES NOT PERFORM ANY NETWORK CALL. ***
(Nothing in lookalike_check.py does either - it's pure string logic.)

It tests the individual pure-logic building blocks in lookalike_check.py -
levenshtein_distance(), find_lookalike_brand(), check_suspicious_tld(),
and check_domain_length() - directly, with fabricated example domains,
the same way test_age_logic_offline.py and test_mx_logic_offline.py test
their modules' pure logic separately from any live lookup.
"""

from lookalike_check import (
    check_domain_length,
    check_lookalike,
    check_suspicious_tld,
    find_lookalike_brand,
    levenshtein_distance,
)

print("OFFLINE test - no internet used, no network call of any kind.\n")

# --- 1. levenshtein_distance() itself ---
assert levenshtein_distance("paypal", "paypal") == 0
assert levenshtein_distance("paypal", "paypa1") == 1  # one substitution
assert levenshtein_distance("google", "gooogle") == 1  # one insertion
assert levenshtein_distance("", "abc") == 3
print("levenshtein_distance() basic cases passed.")

# --- 2. find_lookalike_brand(): character-swap typosquat ---
match = find_lookalike_brand("paypa1.com")
print(f"\nfind_lookalike_brand('paypa1.com') -> {match}")
assert match is not None
assert match[0] == "paypal"
assert match[1] == 1

# --- 3. find_lookalike_brand(): combosquat (brand name + extra words) ---
match = find_lookalike_brand("secure-paypal-login.tk")
print(f"find_lookalike_brand('secure-paypal-login.tk') -> {match}")
assert match is not None
assert match[0] == "paypal"
assert match[1] == 0  # exact brand word, just surrounded by other words

# --- 4. find_lookalike_brand(): the brand's own real domain -> no flag ---
match = find_lookalike_brand("paypal.com")
print(f"find_lookalike_brand('paypal.com') -> {match}")
assert match is None

# --- 5. find_lookalike_brand(): unrelated domain -> no flag ---
match = find_lookalike_brand("wikipedia.org")
print(f"find_lookalike_brand('wikipedia.org') -> {match}")
assert match is None

# --- 6. check_suspicious_tld() ---
is_suspicious, tld = check_suspicious_tld("something.tk")
print(f"\ncheck_suspicious_tld('something.tk') -> ({is_suspicious}, '{tld}')")
assert is_suspicious is True
assert tld == "tk"

is_suspicious, tld = check_suspicious_tld("something.com")
assert is_suspicious is False
assert tld == "com"

# --- 7. check_domain_length() ---
short_domain = "paypal.com"
long_domain = "this-is-a-very-long-domain-name-with-no-brand-at-all.com"
assert check_domain_length(short_domain) is False
assert check_domain_length(long_domain) is True
print(f"check_domain_length('{long_domain}') -> True (len={len(long_domain)})")

# --- 8. check_lookalike(): full combined result, fabricated worst-case domain ---
result = check_lookalike("secure-paypal-login-verify-account.tk")
print(f"\ncheck_lookalike('secure-paypal-login-verify-account.tk') -> {result}")
assert result["lookalike_of"] == "paypal"
assert result["suspicious_tld"] is True
assert result["status"] == "suspicious"
assert len(result["reasons"]) >= 2  # lookalike + suspicious TLD reasons both present

# --- 9. check_lookalike(): clean domain -> status "ok", one explanatory reason ---
result = check_lookalike("wikipedia.org")
print(f"\ncheck_lookalike('wikipedia.org') -> {result}")
assert result["lookalike_of"] is None
assert result["suspicious_tld"] is False
assert result["is_long"] is False
assert result["status"] == "ok"
assert result["reasons"] == ["No lookalike, suspicious-TLD, or excessive-length red flags detected"]

# --- 10. check_lookalike(): bad input -> graceful "unknown", never crashes ---
result = check_lookalike("")
print(f"\ncheck_lookalike('') -> {result}")
assert result["status"] == "unknown"

result = check_lookalike(None)
print(f"check_lookalike(None) -> {result}")
assert result["status"] == "unknown"

print("\nAll offline logic checks passed.")
