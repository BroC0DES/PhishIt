# PhishIt — Domain Intelligence Module
### Master Project Summary (study this to explain and defend the whole module)

Files this document pulls together: `domain_age.py`, `mx_check.py`,
`lookalike_check.py`, `analyze_domain.py`, and `NOTES_domain_age.txt`,
`NOTES_mx_check.txt`, `NOTES_lookalike.txt`, `NOTES_analyze_domain.txt`.

---

## 1. What This Module Does

When PhishIt receives an email, one of the most useful questions it can
ask is: **"Is the sender's domain (the part after the @ in an email
address, or the website a link points to) trustworthy, or does it look
like throwaway infrastructure an attacker just spun up?"** The Domain
Intelligence module answers that question automatically, for free, and
in a fraction of a second, by checking three independent, real-world
signals about a domain — **how old it is**, **whether it's properly set
up to receive mail**, and **whether its name is trying to impersonate a
trusted brand** — and combining them into one simple, explainable
verdict: `"safe"` or `"suspicious"`, plus a plain-English list of exactly
why. It never needs AI or a live internet blocklist to do this — it's
all public information (domain registration records, DNS records, and
the domain's own spelling) that a human investigator would check by
hand, just automated.

---

## 2. Every Python Library Used, and Exactly Why

### Third-party libraries (listed in `requirements.txt`, installed with `pip`)

| Library | What it does, in one sentence | Used in |
|---|---|---|
| **`python-whois`** (imported as `whois`) | Sends a WHOIS lookup — a public "who registered this domain and when" query — to the right registration authority for any domain, and hands back the answer as a Python object. | `domain_age.py`, function `get_domain_creation_date()` — this is the ONLY place it's called. |
| **`dnspython`** (imported as `dns.resolver`) | Sends real DNS (Domain Name System — the internet's phone book) queries and reads back the answers, in this case specifically MX (Mail Exchange) records. | `mx_check.py`, function `fetch_mx_hosts()` — this is the ONLY place it's called. |
| **`python-dateutil`** | A general-purpose date-parsing helper library. | Not imported directly by our own code — it's installed automatically because `python-whois` uses it *internally* to make sense of the many different date formats different WHOIS servers around the world return. |
| **`six`** | A small compatibility library that lets old code written for Python 2 also run on Python 3. | Also not imported directly by us — it's a dependency that one of the other libraries above needs internally. Listed in `requirements.txt` only because `pip` pulled it in automatically. |

**Honest note for judges:** `python-dateutil` and `six` are in
`requirements.txt` because our two direct dependencies (`python-whois`,
possibly `dnspython`) need them to work — we don't call them ourselves.
Knowing the difference between "a library I call directly" and "a
library that got installed because something I use needs it" is exactly
the kind of detail worth being able to explain confidently.

### Python's own built-in standard library (no install needed, comes free with Python)

| Module | What it does, in one sentence | Used in |
|---|---|---|
| **`datetime`** | Represents dates/times and lets you do date math (like "how many days between these two dates"). | `domain_age.py` — computing domain age. |
| **`re`** (regular expressions) | Pattern-matches and splits text using rules, e.g. "split this string wherever there's a hyphen or dot." | `lookalike_check.py` — breaking a domain into word-like chunks. |
| **`ipaddress`** | Checks whether a piece of text is a valid IP address (e.g. `192.0.2.55`) as opposed to a normal hostname. | `mx_check.py` — detecting an MX record that (wrongly) points at a raw IP instead of a proper mail server name. |
| **`urllib.request` / `urllib.parse` / `urllib.error`** | Makes HTTP(S) web requests (like a very lightweight version of what a browser does) and builds properly-encoded URLs. | `domain_age.py` — calling the free Wayback Machine API. |
| **`json`** | Reads and writes JSON (JavaScript Object Notation) — the plain-text format almost every web API replies in. | `domain_age.py` — parsing the Wayback Machine's response. |

---

## 3. Every Check, Explained Simply

### 3a. Domain Age (WHOIS) — *"How long has this domain existed?"*

**What it checks:** the date the domain was first registered.

**How it works:** every domain has to be registered through a company
called a **registrar** (like GoDaddy or Namecheap), and that
registration is recorded in a public system called **WHOIS**. Our code
asks WHOIS for a domain's record and pulls out just the creation date,
then subtracts that from today's date to get the domain's age in days.

**Why a new domain is suspicious:** registering a domain costs very
little and takes minutes. Scammers register a fresh domain, run a scam
for a short time before it gets reported and blacklisted, then abandon
it and register a new one. A legitimate business, on the other hand,
almost never needs to switch domains — its domain is usually years or
decades old. So a very young domain age is a strong, cheap red flag.

**What the 30-day threshold means:** we call a domain "new" (and
therefore suspicious) if it's under 30 days old. This is a simple,
adjustable starting number, not a scientifically proven cutoff — a real
system would tune it using real phishing data over time. It's one clue
combined with others, never proof by itself (a brand-new domain could
just be a legitimate new startup).

### 3b. The Wayback Machine Fallback — *"What if WHOIS won't tell us?"*

**Why it's needed:** since a privacy law called **GDPR** (a European
Union law that protects personal data) came into force, and the
worldwide domain-registration rules (**ICANN** policies) that followed
it, most registrars now hide personal registrant details from public
WHOIS by default — and on many registrars, that also hides the creation
date, not just the owner's name. So more and more real domains
(including plenty of genuinely suspicious ones) now return *nothing*
from WHOIS. Without a fallback, that would mean giving up entirely on
our #1 signal for a large and growing share of domains.

**How it works:** we ask the **Wayback Machine** (the Internet Archive's
free website archive at web.archive.org, which has been taking snapshots
of public websites since 1996) one question: *"what's the EARLIEST
snapshot you have of this domain?"* If it has one from, say, 2015, that's
solid proof the domain already existed by 2015 — no privacy setting can
hide that, because it's something the Archive independently observed,
not something the registrar told us.

**Why it's marked as an "estimate," not exact data:** the domain could
have been registered well *before* its earliest Wayback snapshot (maybe
it sat unused for a while, or the crawler simply hadn't found it yet).
So this estimate is a **lower bound**: the domain is *at least* this
old, but could genuinely be older. It can never make a domain look
*older* than it really is, only potentially *younger*. Because of this,
our code tags every result with a `"source"` field (`"whois"` or
`"wayback_estimate"`) and, when the estimate is used, adds a `"note"`
spelling this caveat out in plain English — so nobody downstream ever
mistakes an estimate for a verified fact.

### 3c. MX Record Check — *"Is this domain even set up to receive mail?"*

**What an MX record is:** DNS (the system that maps human-readable
names like `google.com` to the technical information computers need)
stores different types of records for different purposes. An **MX
(Mail Exchange) record** is the one that says "if you want to deliver
email to this domain, send it to THIS mail server." Without one, a
domain literally cannot receive email.

**What "no MX" means:** a domain that claims to send email but has no
MX records at all can't receive replies — a real business would notice
and fix that immediately. Its absence on a domain actively sending mail
is a red flag.

**What "MX pointing to a raw IP" means:** MX records are supposed to
point to a proper hostname (like `mail.example.com`), never a raw IP
address (like `192.0.2.55`) — that's actually against the official
email rules. A raw IP MX record suggests a quickly, sloppily
thrown-together setup — exactly what an attacker spinning up
infrastructure fast might produce.

**The RFC 7505 "Null MX" edge case, in simple terms:** an **RFC** is an
official published internet standard (RFC = "Request for Comments," the
naming convention for these standards documents). RFC 7505 defines a
special MX record that's just a single dot (`.`) instead of a hostname.
This is a domain owner formally, deliberately declaring: *"this domain
sends and receives NO email, on purpose."* It's common on web-only
domains (e.g. a company's marketing site that has no email of its own)
and is considered *good practice*, not a red flag by itself — but it IS
useful context: if an email ever claims to be *from* such a domain,
that directly contradicts what the domain's own DNS says, which is
highly suspicious.

### 3d. Lookalike / Typosquat Detection — *"Does the domain's spelling try to trick you?"*

**How the similarity comparison works:** we use something called
**Levenshtein distance** (also called "edit distance") — the minimum
number of single-character changes (insert one letter, delete one
letter, or swap one letter for another) needed to turn one word into
another. The smaller the number, the more similar two words look. We
compare the domain's text against a list of well-known brand names
(PayPal, Google, Amazon, etc.) and flag it if it's only 1–2 edits away.

**Worked example:** `"paypal"` → `"paypa1"` (swapping the letter "l" for
the digit "1") is exactly **1 edit**. So `paypa1.com` gets flagged as
resembling "paypal" with an edit distance of 1 — a classic
character-swap typosquat. We also catch the other common trick,
**combosquatting** — keeping the brand name spelled correctly but
gluing extra words onto it, like `secure-paypal-login.tk` — by breaking
the domain into word-chunks (split on hyphens/dots) and checking each
chunk separately, so `paypal` inside that string is still caught even
though it's not the whole domain.

One important detail: the brand's own real domain (`paypal.com` itself)
is deliberately *not* flagged — an exact single-word match to a brand
is treated as that brand's own legitimate site, not an impersonation of
itself.

### 3e. TLD / Length Heuristics — *"Does the overall shape of the domain look risky?"*

**Suspicious TLDs:** a **TLD (Top-Level Domain)** is the part after the
last dot in a domain — `.com`, `.org`, `.ru`, `.tk`, etc. Independent
security research (like Spamhaus' abuse reports) has repeatedly found
that a small number of TLDs (we watch `.ru`, `.cn`, `.tk`, `.top`)
account for a hugely disproportionate share of spam and phishing sites —
mainly because they're free or extremely cheap to register with little
identity checking, making them attractive for disposable attack
infrastructure. This is a *statistical* pattern, not proof — plenty of
legitimate sites use these TLDs too.

**Unusually long domains:** a common trick is to bury a trusted brand
name or keyword deep inside a long string of extra words, so that on a
small screen (like a phone), the visible/truncated part of the URL
looks trustworthy while the actual suspicious content is pushed
off-screen. We flag any domain over 30 characters as unusually long —
most normal brand domains (`paypal.com`, `google.com`) are well under
that.

---

## 4. Key Terms Glossary

| Term | Simple definition |
|---|---|
| **WHOIS** | A public "phone book" for domain names — looking up who registered a domain and when. |
| **Registrar** | The company (like GoDaddy) that sells and manages domain name registrations. |
| **DNS (Domain Name System)** | The internet's system for mapping human-readable names (`google.com`) to technical information computers need (like which server to talk to). |
| **MX record** | A specific type of DNS record that says which mail server handles email for a domain. |
| **Null MX (RFC 7505)** | A special MX record (just a dot, `.`) that formally means "this domain sends/receives no email at all," on purpose. |
| **TLD (Top-Level Domain)** | The part of a domain after the last dot — `.com`, `.org`, `.ru`, etc. |
| **Hostname** | A proper, readable server name, like `mail.example.com` (as opposed to a raw IP address). |
| **IP address** | The numeric address of a computer on the internet, e.g. `192.0.2.55`. |
| **Typosquatting** | Registering a domain that's almost identical to a real brand's domain, hoping a victim won't notice the tiny difference (e.g. `paypa1.com`). |
| **Combosquatting** | Keeping a brand name spelled correctly but gluing extra words onto it (e.g. `secure-paypal-login.tk`). |
| **Levenshtein / edit distance** | The minimum number of single-character changes needed to turn one word into another — used here to measure how "close" a domain is to a real brand name. |
| **RFC (Request for Comments)** | An officially published internet technical standard document. |
| **GDPR** | A European Union privacy law that requires personal data (including WHOIS registrant info, in practice) to be protected/hidden by default. |
| **ICANN** | The organization that sets the global rules domain registrars must follow, including WHOIS privacy rules. |
| **Wayback Machine** | The Internet Archive's free service that stores snapshots of what websites looked like on past dates. |
| **API (Application Programming Interface)** | A defined way for one program to ask another program (often over the internet) for data or to do something. |
| **JSON** | A common plain-text format for structured data, used by most web APIs to send their responses. |
| **Lower-bound estimate** | A number that's guaranteed to be *no higher* than the true value, but could be lower than the truth (e.g. "the domain is *at least* this old"). |
| **Timeout** | A safety limit on how long to wait for a slow or unresponsive server before giving up, instead of waiting forever. |
| **Exception / exception handling** | When code hits an error, Python "raises an exception." "Handling" it (with `try`/`except`) means catching that error and deciding what to do instead of letting the whole program crash. |
| **Network call** | Any operation that has to talk to another computer over the internet (like a WHOIS lookup or a DNS query) — as opposed to "pure logic" that only uses data already on hand. |
| **Dictionary (in Python)** | A data structure that stores labeled values, like `{"age_days": 12, "is_new": True}` — a mini form with named fields. |
| **Boolean** | A value that's either `True` or `False`. |
| **Verdict** | The final, single "safe" or "suspicious" conclusion this module reaches after combining all its checks. |
| **False positive** | Flagging something as suspicious when it's actually fine (e.g. `example.com`'s legitimate Null MX getting flagged). |
| **False negative** | Missing something that actually was suspicious. |

---

## 5. The Final Output Format

`analyze_domain(domain)` is the one function the rest of the team
should call. It **always** returns a dictionary in exactly this shape —
it never raises an error and never leaves a field out:

```python
{
    "name": domain,                # the domain that was checked, e.g. "paypa1-secure-login.tk"

    "age_days": 1500,              # (int, or None if unknown) how many days old the domain is
    "is_new": False,               # (True/False/None) True if registered under 30 days ago

    "has_mx": True,                # (True/False) whether the domain has a working mail server set up
    "mx_provider": "aspmx.l.google.com",  # (string, or None) the RAW mail server hostname —
                                    #    NOT a friendly label — used for spotting shared attacker infrastructure

    "lookalike_of": "paypal",      # (string, or None) which known brand this domain's text resembles, if any

    "suspicious_tld": True,        # (True/False) whether the domain's TLD (.ru/.cn/.tk/.top) is on the risky list

    "verdict": "suspicious",       # (string) the final answer: "safe" or "suspicious"

    "reasons": [                   # (list of strings) plain-English explanation for every check,
        "Domain is newly registered (12 days old) - ...",   #   flagged AND clean, so nothing is hidden
        "MX records look normally configured",
        "Domain closely resembles the brand 'paypal' (edit distance 1) - ...",
    ],
}
```

**Note on `"suspicious_tld"` vs the verdict rule:** the team-agreed
dictionary shape only has a `suspicious_tld` field (no separate
"is_long" field). But the actual verdict rule also checks domain
*length*, not just TLD — that check still runs internally and always
shows up as a line in `reasons` when it fires, it just doesn't get its
own top-level key, to keep the agreed shape fixed and simple.

---

## 6. How This Connects to the Rest of the Team's Project

This module doesn't work in isolation — its output is designed as a
building block for teammates:

- **Overall trust score:** `verdict` (`"safe"`/`"suspicious"`) and
  `reasons` are meant to feed into PhishIt's bigger picture — combined
  with whatever the email *content* analysis finds — to produce one
  overall trust score for an email, rather than this module trying to
  be the whole answer on its own.
- **Campaign clustering (mx_provider):** `mx_provider` deliberately
  gives the *raw* mail server hostname (like `aspmx.l.google.com`)
  instead of just a friendly category name. This matters because
  attackers often reuse the exact same mail infrastructure across many
  different lookalike domains in the same campaign. A teammate working
  on clustering phishing campaigns together can group domains by
  matching `mx_provider` values to spot "these 15 different lookalike
  domains are all actually run by the same attacker," which a vague
  category label like "Google Workspace" would blur together and hide.
- **Dashboard:** `verdict` is the headline flag to show a user, and
  `reasons` is the supporting, plain-English explanation list underneath
  it — designed so a non-technical person can immediately see *why* a
  domain was flagged, not just that it was.

---

## 7. Design Decisions Worth Mentioning to Judges

These are the choices that show real engineering thought, not just
"does it technically work":

1. **Never crashes, no matter what.** Every function that touches the
   network (WHOIS, DNS, Wayback) is wrapped in error handling that
   catches every failure and returns a graceful "unknown" result
   instead of raising an exception. `analyze_domain()` itself has a
   final, whole-function safety net on top of that. A batch job could
   run this over thousands of domains, including broken/nonexistent
   ones, without a single crash.
2. **Pure logic is split from network calls, on purpose, for
   testability.** Every check follows the same pattern: a "fetch"
   function that's the *only* place doing the actual network call, and
   a separate "classify" function that's pure math/logic with zero
   network dependency. This means the decision-making logic (e.g. "is
   5 days new?") can be tested instantly with a made-up date, with no
   internet connection required, and without depending on a real
   domain staying newly-registered forever.
3. **The Null MX edge case is handled correctly, not just brute-forced.**
   Early testing against `example.com` initially reported a wrong
   result (`has_mx: True` with a blank hostname) until this was
   investigated and traced to a real, official DNS feature (RFC 7505)
   — showing the difference between coding around a bug and actually
   understanding what's happening.
4. **The Wayback fallback is honest about being an estimate.** Rather
   than silently guessing a date and presenting it as fact when WHOIS
   is privacy-redacted, every fallback result is explicitly tagged
   `"source": "wayback_estimate"` with a `"note"` explaining it's a
   lower bound, not exact data. Most quick phishing-detection projects
   either ignore privacy-redacted WHOIS entirely or (worse) silently
   treat missing data as certain — this module does neither.
5. **Typosquat detection uses a real string-similarity algorithm, not
   just a fixed list.** Using Levenshtein distance instead of an exact
   string match means it catches typosquats it's never seen before
   (like a brand-new `micr0s0ft.com` variant), not just a hardcoded
   blocklist of known bad domains.
6. **The combined verdict is a simple, transparent, security-biased
   OR.** Rather than a hidden weighted score, `verdict` fires
   "suspicious" if *any* single independent signal fires. This is a
   deliberate choice: a false positive here just costs someone a few
   extra seconds double-checking a domain, while a false negative could
   mean a missed phishing domain — so the logic is intentionally biased
   toward catching more, and it stays fully explainable via `reasons`.

---

## 8. Limitations (be honest about these)

- **Domain age alone proves nothing by itself.** A brand-new domain
  could be a legitimate new startup, not a phishing site. This is meant
  to be *one signal among several*, not a standalone verdict.
- **This module cannot detect a domain that's old and legitimate but has
  since been compromised or hijacked by an attacker.** An old, trusted
  domain with a great WHOIS history and normal mail setup that gets
  hacked and used to host a phishing page would still come back
  `"safe"` from every check here — this module only looks at the
  domain's *registration and infrastructure history*, not what's
  actually being hosted on it right now.
- **The Wayback estimate can under-estimate age.** Because it's a lower
  bound, a domain could genuinely be much older than its earliest
  snapshot suggests (if the Wayback crawler just hadn't found it yet),
  which could make an old, legitimate domain look falsely "new" in the
  worst case.
- **The Null MX edge case is a known false positive.** A domain that
  has formally and correctly declared "I don't send/receive email"
  (RFC 7505) still counts as `has_mx: False` and pushes the verdict
  toward "suspicious" under the current conservative rule, even though
  nothing is actually wrong with that domain (see `example.com` in the
  smoke tests).
- **The known-brands list and suspicious-TLD list are both short and
  static** (9 brands, 4 TLDs) — hand-picked for this project, not a
  large, continuously-updated real-world dataset. A real deployment
  would need a much bigger and regularly-refreshed list.
- **Every network-dependent check can temporarily show "unknown" due to
  a network hiccup, not a real problem with the domain** — a slow DNS
  server or a rate-limited third-party API can look, briefly, just like
  a genuinely broken domain. The module correctly reports "unknown"
  rather than guessing, but that does mean "unknown" isn't always proof
  of anything suspicious either.
- **This module only looks at the domain itself** — it does not analyze
  email body content, attachments, links' visible vs. actual
  destination, or sender behavior over time. It's designed to be one
  input feeding a bigger trust score, not the whole detection system.
