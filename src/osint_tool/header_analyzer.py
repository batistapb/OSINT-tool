import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


def analyze_headers(url: str) -> dict:
    response = requests.get(url, timeout=10)
    return {header: (header in response.headers) for header in SECURITY_HEADERS}
