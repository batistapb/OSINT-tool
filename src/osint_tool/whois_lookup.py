import whois


def get_whois_info(domain: str) -> dict:
    data = whois.whois(domain)
    return {
        "registrar": data.registrar,
        "creation_date": str(data.creation_date),
        "expiration_date": str(data.expiration_date),
    }
