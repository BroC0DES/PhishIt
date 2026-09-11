"""Quick smoke test for the Domain Intelligence module.

Run this to confirm whois and dnspython are working:
    python domain_intelligence/main.py <domain>
"""

import sys

import dns.resolver
import whois


def get_whois_info(domain: str) -> None:
    print(f"\n--- WHOIS info for {domain} ---")
    info = whois.whois(domain)
    print("Registrar:", info.registrar)
    print("Creation date:", info.creation_date)
    print("Expiration date:", info.expiration_date)


def get_dns_records(domain: str, record_type: str = "A") -> None:
    print(f"\n--- {record_type} records for {domain} ---")
    answers = dns.resolver.resolve(domain, record_type)
    for answer in answers:
        print(answer.to_text())


if __name__ == "__main__":
    target_domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    get_whois_info(target_domain)
    get_dns_records(target_domain)
