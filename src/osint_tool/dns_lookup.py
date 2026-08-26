import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS"]


def get_dns_records(domain: str) -> dict:
    records = {}
    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            records[rtype] = []
    return records
