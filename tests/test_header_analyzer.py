from unittest.mock import Mock, patch

from osint_tool.header_analyzer import analyze_headers


def test_analyze_headers_detects_missing_hsts():
    fake_response = Mock()
    fake_response.headers = {"Content-Security-Policy": "default-src 'self'"}

    with patch("osint_tool.header_analyzer.requests.get", return_value=fake_response):
        result = analyze_headers("https://exemplo.com")

    assert result["Content-Security-Policy"] is True
    assert result["Strict-Transport-Security"] is False


def test_analyze_headers_detects_all_present():
    fake_response = Mock()
    fake_response.headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }

    with patch("osint_tool.header_analyzer.requests.get", return_value=fake_response):
        result = analyze_headers("https://exemplo.com")

    assert all(result.values())
