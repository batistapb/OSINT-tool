import requests

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def find_subdomains(domain: str) -> list[str]:
    url = CRT_SH_URL.format(domain=domain)
    response = requests.get(url, timeout=10)
    response.raise_for_status()
    entries = response.json()

    subdomains = set()
    for entry in entries:
        subdomains.update(entry["name_value"].split("\n"))

    return sorted(subdomains)
