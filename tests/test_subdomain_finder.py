from unittest.mock import Mock, patch

from osint_tool.subdomain_finder import find_subdomains


def test_find_subdomains_parses_crtsh_response():
    fake_json = [
        {"name_value": "api.exemplo.com"},
        {"name_value": "www.exemplo.com\napi.exemplo.com"},
    ]
    fake_response = Mock()
    fake_response.json.return_value = fake_json
    fake_response.raise_for_status = Mock()

    with patch("osint_tool.subdomain_finder.requests.get", return_value=fake_response):
        result = find_subdomains("exemplo.com")

    assert result == ["api.exemplo.com", "www.exemplo.com"]


def test_find_subdomains_returns_empty_list_when_no_entries():
    fake_response = Mock()
    fake_response.json.return_value = []
    fake_response.raise_for_status = Mock()

    with patch("osint_tool.subdomain_finder.requests.get", return_value=fake_response):
        result = find_subdomains("exemplo.com")

    assert result == []
