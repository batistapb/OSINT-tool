import requests

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"


def get_shodan_info(ip: str, api_key: str) -> dict:
    response = requests.get(
        SHODAN_HOST_URL.format(ip=ip), params={"key": api_key}, timeout=10
    )
    response.raise_for_status()
    data = response.json()
    return {
        "ip": data.get("ip_str"),
        "org": data.get("org"),
        "os": data.get("os"),
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
    }
