from unittest.mock import Mock, patch

from osint_tool.shodan_lookup import get_shodan_info


def test_get_shodan_info_parses_response():
    fake_json = {
        "ip_str": "93.184.216.34",
        "org": "Example Org",
        "os": "Linux",
        "ports": [80, 443],
        "hostnames": ["exemplo.com"],
    }
    fake_response = Mock()
    fake_response.json.return_value = fake_json
    fake_response.raise_for_status = Mock()

    with patch(
        "osint_tool.shodan_lookup.requests.get", return_value=fake_response
    ) as mock_get:
        result = get_shodan_info("93.184.216.34", "fake-key")

    mock_get.assert_called_once_with(
        "https://api.shodan.io/shodan/host/93.184.216.34",
        params={"key": "fake-key"},
        timeout=10,
    )
    assert result["ip"] == "93.184.216.34"
    assert result["ports"] == [80, 443]


def test_get_shodan_info_defaults_missing_fields():
    fake_response = Mock()
    fake_response.json.return_value = {"ip_str": "93.184.216.34"}
    fake_response.raise_for_status = Mock()

    with patch("osint_tool.shodan_lookup.requests.get", return_value=fake_response):
        result = get_shodan_info("93.184.216.34", "fake-key")

    assert result["ports"] == []
    assert result["hostnames"] == []
