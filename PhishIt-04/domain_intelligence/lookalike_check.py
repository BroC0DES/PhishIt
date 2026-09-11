"""
lookalike_check.py
Part of the PhishIt "Domain Intelligence" module.

Purpose:
    Two related but separate checks on a domain NAME itself (no network
    calls needed for either one - everything here is pure string logic):

    1. Lookalike / typosquat detection - does this domain's name closely
       resemble a well-known brand (paypal, google, amazon, ...) without
       actually BEING that brand's real domain? e.g. "paypa1.com" or
       "secure-paypal-login.tk" instead of "paypal.com".

    2. High-risk pattern heuristics - does the domain use a TLD (the
       ".com" / ".ru" / ".tk" part) that's disproportionately associated
       with spam/abuse, or is the domain name unusually long (a common
       trick to bury a trusted brand name inside a long, junk string)?

Unlike domain_age.py and mx_check.py, this file makes NO network calls
at all - it only looks at the domain STRING itself. That means every
function here is directly, instantly testable with no internet
connection and no "unknown" fallback for network failure - the only
fallback case is genuinely bad input (None, empty string, etc.).
"""

import re


# Well-known brands that are common phishing/typosquat targets.
# Lowercase, no spaces/punctuation - matched against normalized domain text.
KNOWN_BRANDS = [
    "paypal",
    "google",
    "amazon",
    "microsoft",
    "sbi",
    "hdfc",
    "icici",
    "netflix",
    "apple",
]

# TLDs (top-level domains - the part after the last dot, e.g. "com", "ru")
# that are disproportionately associated with spam/phishing/abuse, based
# on widely-cited industry abuse reports. NOT proof of malice by itself -
# plenty of legitimate sites use these - just one signal among several.
SUSPICIOUS_TLDS = {"ru", "cn", "tk", "top"}

# Domains longer than this many characters are flagged as unusually long.
MAX_NORMAL_LENGTH = 30


def levenshtein_distance(word_a: str, word_b: str) -> int:
    """
    Pure logic, no network call.

    Computes the Levenshtein ("edit") distance between two strings: the
    minimum number of single-character edits (insertions, deletions, or
    substitutions) needed to turn word_a into word_b.

    Example: levenshtein_distance("paypal", "paypa1") == 1
             (just one substitution: "l" -> "1")

    Classic dynamic-programming implementation: build a grid where
    grid[i][j] = edit distance between the first i characters of word_a
    and the first j characters of word_b, filling it in one row at a
    time using only the previous row (keeps memory usage small).
    """
    if word_a == word_b:
        return 0
    if len(word_a) == 0:
        return len(word_b)
    if len(word_b) == 0:
        return len(word_a)

    previous_row = list(range(len(word_b) + 1))  # distances if word_a were ""
    for i, char_a in enumerate(word_a, start=1):
        current_row = [i]  # distance from "" to first i chars of word_a
        for j, char_b in enumerate(word_b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (0 if char_a == char_b else 1)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row

    return previous_row[-1]


def _split_label_and_tld(domain: str):
    """
    Pure logic. Splits a lowercase domain string into:
        label - everything before the last dot (e.g. "paypal-secure-login")
        tld   - everything after the last dot (e.g. "com")

    A leading "www." is stripped first, since it's not part of the
    meaningful brand/label text. Domains with no dot at all (malformed
    input) are treated as having an empty tld.
    """
    domain = domain.strip().lower()
    if domain.startswith("www."):
        domain = domain[len("www."):]

    if "." not in domain:
        return domain, ""

    label, tld = domain.rsplit(".", 1)
    return label, tld


def _tokenize_label(label: str):
    """
    Pure logic. Breaks a domain label into word-like chunks by splitting
    on anything that isn't a letter or digit (dots, hyphens, underscores).

    e.g. "paypal-secure-login" -> ["paypal", "secure", "login"]
         "paypa1"              -> ["paypa1"]   (single chunk, no separators)

    This lets us catch BOTH classic character-swap typosquats (one chunk,
    slightly misspelled brand name) AND "combosquat" domains that glue
    the real brand name next to unrelated words (multiple chunks, one of
    which matches a brand almost exactly).
    """
    tokens = re.split(r"[^a-z0-9]+", label)
    return [token for token in tokens if token]  # drop empty strings from split


def _distance_threshold(brand: str) -> int:
    """
    Pure logic. How many character edits are "close enough" to count as
    a likely typosquat of this brand, scaled to the brand's length.

    Short brand names (e.g. "sbi", "hdfc") get a tighter threshold of 1,
    because allowing 2 edits on a 3-4 letter word would match almost
    anything and flood us with false positives. Longer brand names get
    a threshold of 2, since a couple of character changes still leaves
    most of the name recognisable (e.g. "micr0s0ft" vs "microsoft").
    This is a simple, tunable starting point - not a proven optimum.
    """
    return 1 if len(brand) <= 4 else 2


def find_lookalike_brand(domain: str, brands=None, min_token_length: int = 3):
    """
    Pure logic, no network call.

    Given a domain, checks whether its name closely resembles any brand
    in `brands` (defaults to KNOWN_BRANDS above), using Levenshtein
    distance. Returns (brand_name, edit_distance) for the closest match
    within threshold, or None if nothing resembles a known brand.

    Two things this deliberately does NOT flag as a lookalike:
      - The brand's own real domain (e.g. "paypal.com" itself) - an
        exact match on a single-word label is the brand, not an
        impersonation of it.
      - Very short leftover fragments (shorter than min_token_length)
        that could coincidentally match a short brand like "sbi".
    """
    if brands is None:
        brands = KNOWN_BRANDS

    label, _tld = _split_label_and_tld(domain)
    tokens = _tokenize_label(label)
    if not tokens:
        return None

    best_match = None  # will hold (brand, distance) with the smallest distance found

    for brand in brands:
        if len(tokens) == 1:
            # Single-word domain label, e.g. "paypa1.com" -> ["paypa1"]
            token = tokens[0]
            if token == brand:
                continue  # this IS the brand's own domain, not a lookalike
            if len(token) < min_token_length:
                continue
            distance = levenshtein_distance(token, brand)
        else:
            # Multi-word label, e.g. "paypal-secure-login.com". Compare
            # each word separately - a domain shouldn't get away with
            # hiding a near-exact brand name just by bolting extra
            # words onto it.
            candidate_tokens = [t for t in tokens if len(t) >= min_token_length]
            if not candidate_tokens:
                continue
            distance = min(levenshtein_distance(t, brand) for t in candidate_tokens)

        if distance <= _distance_threshold(brand):
            if best_match is None or distance < best_match[1]:
                best_match = (brand, distance)

    return best_match


def check_suspicious_tld(domain: str, suspicious_tlds=None):
    """
    Pure logic, no network call.

    Returns (is_suspicious, tld) - whether the domain's TLD is in our
    watch list of TLDs disproportionately associated with spam/abuse.
    """
    if suspicious_tlds is None:
        suspicious_tlds = SUSPICIOUS_TLDS

    _label, tld = _split_label_and_tld(domain)
    return tld in suspicious_tlds, tld


def check_domain_length(domain: str, max_length: int = MAX_NORMAL_LENGTH) -> bool:
    """
    Pure logic, no network call.

    Returns True if the domain string is longer than max_length
    characters (default 30) - a simple, common trick for burying a
    trusted keyword or brand name inside a long, junk-filled string.
    """
    return len(domain) > max_length


def check_lookalike(domain: str, brands=None, suspicious_tlds=None, max_length: int = MAX_NORMAL_LENGTH) -> dict:
    """
    Main entry point for this feature.

    Input:  a domain name string, e.g. "paypa1-secure-login.tk"
    Output: a dictionary combining all three checks above, plus a plain-
            English `reasons` list explaining exactly what was flagged
            and why.

    Always returns a result - never raises an exception - so it's safe
    to call on any input, including malformed or unexpected values.
    There's no network call to fail here, so the only failure mode is
    bad input, which is handled explicitly (not caught blindly).
    """
    try:
        if not domain or not isinstance(domain, str):
            return {
                "domain": domain,
                "lookalike_of": None,
                "lookalike_distance": None,
                "suspicious_tld": None,
                "is_long": None,
                "status": "unknown",
                "reasons": ["Invalid or empty domain input - cannot analyze"],
            }

        domain_clean = domain.strip().lower()

        lookalike_match = find_lookalike_brand(domain_clean, brands=brands)
        lookalike_of = lookalike_match[0] if lookalike_match else None
        lookalike_distance = lookalike_match[1] if lookalike_match else None

        is_suspicious_tld, tld = check_suspicious_tld(domain_clean, suspicious_tlds=suspicious_tlds)
        is_long = check_domain_length(domain_clean, max_length=max_length)

        reasons = []
        if lookalike_of:
            reasons.append(
                f"Domain closely resembles the brand '{lookalike_of}' "
                f"(edit distance {lookalike_distance}) - possible typosquat/lookalike domain"
            )
        if is_suspicious_tld:
            reasons.append(
                f"Domain uses a TLD ('.{tld}') that is disproportionately "
                f"associated with spam/phishing/abuse"
            )
        if is_long:
            reasons.append(
                f"Domain name is unusually long ({len(domain_clean)} characters, "
                f"over the {max_length}-character threshold) - often used to bury "
                f"a brand name or trusted keyword inside a long string"
            )
        if not reasons:
            reasons.append("No lookalike, suspicious-TLD, or excessive-length red flags detected")

        status = "suspicious" if (lookalike_of or is_suspicious_tld or is_long) else "ok"

        return {
            "domain": domain_clean,
            "lookalike_of": lookalike_of,
            "lookalike_distance": lookalike_distance,
            "suspicious_tld": is_suspicious_tld,
            "is_long": is_long,
            "status": status,
            "reasons": reasons,
        }
    except Exception:
        # Belt-and-braces: this module has no network calls to fail, but
        # never crash the caller no matter what unexpected input arrives.
        return {
            "domain": domain,
            "lookalike_of": None,
            "lookalike_distance": None,
            "suspicious_tld": None,
            "is_long": None,
            "status": "unknown",
            "reasons": ["Unexpected error while analyzing domain - treated as unknown"],
        }


if __name__ == "__main__":
    # Every case below is pure string logic - no network call, no
    # internet connection needed, and every result is fully reproducible.

    print("Case 1: Character-swap typosquat (paypa1.com, '1' instead of 'l')")
    print(check_lookalike("paypa1.com"))

    print("\nCase 2: Combosquat - real brand name plus extra words, risky TLD (secure-paypal-login.tk)")
    print(check_lookalike("secure-paypal-login.tk"))

    print("\nCase 3: The brand's own real domain - should NOT be flagged (paypal.com)")
    print(check_lookalike("paypal.com"))

    print("\nCase 4: Unusually long domain name, no brand resemblance")
    print(check_lookalike("this-is-a-very-long-domain-name-with-no-brand.com"))

    print("\nCase 5: Clean, unrelated, normal domain (wikipedia.org)")
    print(check_lookalike("wikipedia.org"))
