import argparse
import json
import sys

from osint_tool.dns_lookup import get_dns_records
from osint_tool.header_analyzer import analyze_headers
from osint_tool.subdomain_finder import find_subdomains
from osint_tool.whois_lookup import get_whois_info


def build_report(domain: str) -> dict:
    return {
        "domain": domain,
        "whois": get_whois_info(domain),
        "dns": get_dns_records(domain),
        "subdomains": find_subdomains(domain),
        "security_headers": analyze_headers(f"https://{domain}"),
    }


def print_text_report(report: dict) -> None:
    print(f"=== OSINT Report: {report['domain']} ===\n")

    whois_info = report["whois"]
    print("[WHOIS]")
    print(f"  Registrar:   {whois_info['registrar']}")
    print(f"  Created:     {whois_info['creation_date']}")
    print(f"  Expires:     {whois_info['expiration_date']}\n")

    print("[DNS Records]")
    for rtype, values in report["dns"].items():
        print(f"  {rtype}: {', '.join(values) if values else '(none)'}")
    print()

    print("[Subdomains]")
    if report["subdomains"]:
        for sub in report["subdomains"]:
            print(f"  - {sub}")
    else:
        print("  (none found)")
    print()

    print("[Security Headers]")
    for header, present in report["security_headers"].items():
        print(f"  {header}: {'present' if present else 'MISSING'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="osint-tool",
        description="Coleta informações públicas e passivas sobre um domínio.",
    )
    parser.add_argument("domain", help="Domínio alvo (ex: exemplo.com)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Imprime o relatório em formato JSON em vez de texto.",
    )
    args = parser.parse_args(argv)

    report = build_report(args.domain)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_text_report(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
