import sys

import requests

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
REQUEST_TIMEOUT = 30


def find_subdomains(domain: str) -> list[str]:
    url = CRT_SH_URL.format(domain=domain)
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        entries = response.json()
    except requests.exceptions.RequestException as exc:
        print(f"[!] crt.sh lookup failed for {domain}: {exc}", file=sys.stderr)
        return []

    subdomains = set()
    for entry in entries:
        subdomains.update(entry["name_value"].split("\n"))

    return sorted(subdomains)
