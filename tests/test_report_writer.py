from osint_tool.report_writer import render_html_report


def _base_report() -> dict:
    return {
        "domain": "exemplo.com",
        "whois": {
            "registrar": "Example Registrar",
            "creation_date": "2000-01-01",
            "expiration_date": "2030-01-01",
        },
        "dns": {"A": ["93.184.216.34"], "MX": []},
        "subdomains": ["www.exemplo.com"],
        "security_headers": {
            "Content-Security-Policy": True,
            "Strict-Transport-Security": False,
        },
    }


def test_render_html_report_includes_core_sections():
    html_report = render_html_report(_base_report())

    assert "<title>OSINT Report: exemplo.com</title>" in html_report
    assert "Example Registrar" in html_report
    assert "www.exemplo.com" in html_report
    assert "MISSING" in html_report
    assert "Shodan" not in html_report


def test_render_html_report_includes_shodan_when_present():
    report = _base_report()
    report["shodan"] = {
        "ip": "93.184.216.34",
        "org": "Example Org",
        "os": "Linux",
        "ports": [80, 443],
        "hostnames": ["exemplo.com"],
    }

    html_report = render_html_report(report)

    assert "<h2>Shodan</h2>" in html_report
    assert "Example Org" in html_report


def test_render_html_report_escapes_untrusted_values():
    report = _base_report()
    report["subdomains"] = ["<script>alert(1)</script>.exemplo.com"]

    html_report = render_html_report(report)

    assert "<script>alert(1)</script>" not in html_report
    assert "&lt;script&gt;" in html_report
