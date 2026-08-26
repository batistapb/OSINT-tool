import argparse
import json
import os
import sys

from osint_tool.dns_lookup import get_dns_records
from osint_tool.header_analyzer import analyze_headers
from osint_tool.shodan_lookup import get_shodan_info
from osint_tool.subdomain_finder import find_subdomains
from osint_tool.whois_lookup import get_whois_info


def build_report(domain: str, shodan_api_key: str | None = None) -> dict:
    dns_records = get_dns_records(domain)

    report = {
        "domain": domain,
        "whois": get_whois_info(domain),
        "dns": dns_records,
        "subdomains": find_subdomains(domain),
        "security_headers": analyze_headers(f"https://{domain}"),
    }

    if shodan_api_key and dns_records.get("A"):
        report["shodan"] = get_shodan_info(dns_records["A"][0], shodan_api_key)

    return report


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

    if "shodan" in report:
        print("\n[Shodan]")
        shodan_info = report["shodan"]
        print(f"  IP:        {shodan_info['ip']}")
        print(f"  Org:       {shodan_info['org']}")
        print(f"  OS:        {shodan_info['os']}")
        print(f"  Ports:     {', '.join(str(p) for p in shodan_info['ports'])}")
        print(f"  Hostnames: {', '.join(shodan_info['hostnames'])}")


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
    parser.add_argument(
        "--shodan-key",
        default=os.environ.get("SHODAN_API_KEY"),
        help=(
            "API key do Shodan para enriquecer o relatório com dados de "
            "infraestrutura do primeiro IP encontrado. Também pode ser "
            "definida via variável de ambiente SHODAN_API_KEY."
        ),
    )
    args = parser.parse_args(argv)

    report = build_report(args.domain, shodan_api_key=args.shodan_key)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_text_report(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
