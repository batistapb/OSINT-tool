import html

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<title>OSINT Report: {domain}</title>
<style>
  body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; }}
  section {{ margin-bottom: 1.5rem; }}
  h2 {{ color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 0.25rem; }}
  ul {{ list-style: none; padding-left: 0; }}
  .missing {{ color: #f85149; }}
  .present {{ color: #3fb950; }}
</style>
</head>
<body>
<h1>OSINT Report: {domain}</h1>
{sections}
</body>
</html>
"""


def _whois_section(whois_info: dict) -> str:
    return (
        "<section><h2>WHOIS</h2><ul>"
        f"<li>Registrar: {html.escape(str(whois_info['registrar']))}</li>"
        f"<li>Created: {html.escape(str(whois_info['creation_date']))}</li>"
        f"<li>Expires: {html.escape(str(whois_info['expiration_date']))}</li>"
        "</ul></section>"
    )


def _dns_section(dns_records: dict) -> str:
    items = "".join(
        f"<li>{html.escape(rtype)}: {html.escape(', '.join(values) or '(none)')}</li>"
        for rtype, values in dns_records.items()
    )
    return f"<section><h2>DNS Records</h2><ul>{items}</ul></section>"


def _subdomains_section(subdomains: list[str]) -> str:
    items = "".join(f"<li>{html.escape(sub)}</li>" for sub in subdomains)
    return f"<section><h2>Subdomains</h2><ul>{items or '<li>(none found)</li>'}</ul></section>"


def _headers_section(security_headers: dict) -> str:
    items = "".join(
        f'<li class="{"present" if present else "missing"}">'
        f'{html.escape(header)}: {"present" if present else "MISSING"}</li>'
        for header, present in security_headers.items()
    )
    return f"<section><h2>Security Headers</h2><ul>{items}</ul></section>"


def _shodan_section(shodan_info: dict) -> str:
    ports = ", ".join(str(p) for p in shodan_info["ports"])
    hostnames = ", ".join(shodan_info["hostnames"])
    return (
        "<section><h2>Shodan</h2><ul>"
        f"<li>IP: {html.escape(str(shodan_info['ip']))}</li>"
        f"<li>Org: {html.escape(str(shodan_info['org']))}</li>"
        f"<li>OS: {html.escape(str(shodan_info['os']))}</li>"
        f"<li>Ports: {html.escape(ports)}</li>"
        f"<li>Hostnames: {html.escape(hostnames)}</li>"
        "</ul></section>"
    )


def render_html_report(report: dict) -> str:
    sections = [
        _whois_section(report["whois"]),
        _dns_section(report["dns"]),
        _subdomains_section(report["subdomains"]),
        _headers_section(report["security_headers"]),
    ]
    if "shodan" in report:
        sections.append(_shodan_section(report["shodan"]))

    return REPORT_TEMPLATE.format(
        domain=html.escape(report["domain"]), sections="\n".join(sections)
    )
