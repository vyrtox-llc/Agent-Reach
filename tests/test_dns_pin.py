"""DNS-pin helper rejects rebinding hosts and connects to the pinned IP."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from agent_reach.utils import url as url_security


def _addrinfo(*ips: str, port: int = 443):
    results = []
    for ip in ips:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
        results.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
    return results


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "192.0.2.1",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "::ffff:169.254.169.254",
    ],
)
def test_pin_hostname_rejects_non_global_answers(monkeypatch, ip):
    monkeypatch.setattr(
        url_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: _addrinfo(ip),
    )
    with pytest.raises(ValueError, match="public HTTP"):
        url_security.pin_hostname("evil.example", 443)


def test_pin_hostname_rejects_mixed_public_and_private(monkeypatch):
    monkeypatch.setattr(
        url_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: _addrinfo("8.8.8.8", "10.0.0.1"),
    )
    with pytest.raises(ValueError, match="public HTTP"):
        url_security.pin_hostname("dual.example", 443)


def test_pin_hostname_allows_global_ipv4(monkeypatch):
    monkeypatch.setattr(
        url_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: _addrinfo("8.8.8.8"),
    )
    assert url_security.pin_hostname("dns.google", 443) == ["8.8.8.8"]


def test_pin_hostname_allows_global_ipv6(monkeypatch):
    monkeypatch.setattr(
        url_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: _addrinfo("2001:4860:4860::8888"),
    )
    assert url_security.pin_hostname("dns.google", 443) == ["2001:4860:4860::8888"]


def test_pin_hostname_skips_dns_for_global_literals(monkeypatch):
    monkeypatch.setattr(
        url_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("literal IPs must not be DNS-resolved")
        ),
    )
    assert url_security.pin_hostname("8.8.8.8", 443) == ["8.8.8.8"]


def test_pin_public_http_url_normalizes_then_pins(monkeypatch):
    monkeypatch.setattr(
        url_security.socket,
        "getaddrinfo",
        lambda *args, **kwargs: _addrinfo("93.184.216.34"),
    )
    normalized, host, port, ips = url_security.pin_public_http_url(
        "example.com/path"
    )
    assert normalized == "https://example.com/path"
    assert host == "example.com"
    assert port == 443
    assert ips == ["93.184.216.34"]


def test_fetch_pinned_bytes_connects_to_ip_not_hostname(monkeypatch):
    monkeypatch.setattr(
        url_security,
        "pin_public_http_url",
        lambda _url: (
            "https://example.com/article",
            "example.com",
            443,
            ["93.184.216.34"],
        ),
    )
    seen = []

    def fake_create_connection(address, timeout=None):
        seen.append((address, timeout))
        raise OSError("stop after pin")

    monkeypatch.setattr(url_security.socket, "create_connection", fake_create_connection)

    with pytest.raises(OSError, match="stop after pin"):
        url_security.fetch_pinned_bytes(
            "https://example.com/article",
            timeout=7,
            max_bytes=1024,
        )

    assert seen == [(("93.184.216.34", 443), 7)]


def test_fetch_pinned_bytes_does_not_call_urlopen(monkeypatch):
    monkeypatch.setattr(
        url_security,
        "pin_public_http_url",
        lambda _url: (
            "https://example.com/",
            "example.com",
            443,
            ["1.1.1.1"],
        ),
    )
    monkeypatch.setattr(
        url_security.socket,
        "create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("offline")),
    )
    with patch.object(url_security.urllib.request, "urlopen") as urlopen:
        with pytest.raises(OSError, match="offline"):
            url_security.fetch_pinned_bytes(
                "https://example.com/",
                timeout=1,
                max_bytes=16,
            )
    urlopen.assert_not_called()


def test_curl_resolve_argument_brackets_ipv6():
    assert (
        url_security.curl_resolve_argument("v2ex.com", 443, "2001:db8::1")
        == "v2ex.com:443:[2001:db8::1]"
    )
    assert (
        url_security.curl_resolve_argument("v2ex.com", 443, "1.2.3.4")
        == "v2ex.com:443:1.2.3.4"
    )
