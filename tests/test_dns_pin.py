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


def _clear_proxy_env(monkeypatch):
    for name in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "SOCKS_PROXY",
        "socks_proxy",
        "NO_PROXY",
        "no_proxy",
    ):
        monkeypatch.delenv(name, raising=False)


def test_fetch_pinned_bytes_connects_to_ip_not_hostname(monkeypatch):
    _clear_proxy_env(monkeypatch)
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
    _clear_proxy_env(monkeypatch)
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


def test_fetch_pinned_bytes_uses_https_proxy_connect_to_pin_ip(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://user:s3cret@127.0.0.1:7890")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
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
    seen_tcp = []
    connect_requests = []

    class FakeSock:
        def __init__(self):
            self._sent = b""
            self._phase = 0

        def sendall(self, data):
            self._sent += data
            connect_requests.append(data.decode("latin-1", "replace"))

        def recv(self, _n):
            if self._phase == 0:
                self._phase = 1
                return b"HTTP/1.1 200 Connection Established\r\n\r\n"
            return b""

        def close(self):
            return None

    def fake_create_connection(address, timeout=None):
        seen_tcp.append((address, timeout))
        return FakeSock()

    monkeypatch.setattr(url_security.socket, "create_connection", fake_create_connection)

    def boom_wrap_socket(self, sock, server_hostname=None):
        assert server_hostname == "example.com"
        raise OSError("stop after CONNECT")

    monkeypatch.setattr(url_security.ssl.SSLContext, "wrap_socket", boom_wrap_socket)

    with pytest.raises(OSError, match="stop after CONNECT"):
        url_security.fetch_pinned_bytes(
            "https://example.com/article",
            timeout=7,
            max_bytes=1024,
        )

    assert seen_tcp == [(("127.0.0.1", 7890), 7)]
    assert any("CONNECT 93.184.216.34:443" in req for req in connect_requests)
    assert all("s3cret" not in req for req in connect_requests)
    # Basic auth is base64 of user:s3cret — ensure raw password never appears.
    assert all("user:s3cret" not in req for req in connect_requests)


def test_fetch_pinned_bytes_respects_no_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
    monkeypatch.setenv("NO_PROXY", "example.com")
    monkeypatch.setattr(
        url_security,
        "pin_public_http_url",
        lambda _url: (
            "https://example.com/",
            "example.com",
            443,
            ["93.184.216.34"],
        ),
    )
    seen = []

    def fake_create_connection(address, timeout=None):
        seen.append(address)
        raise OSError("direct path")

    monkeypatch.setattr(url_security.socket, "create_connection", fake_create_connection)

    with pytest.raises(OSError, match="direct path"):
        url_security.fetch_pinned_bytes(
            "https://example.com/",
            timeout=3,
            max_bytes=64,
        )

    assert seen == [("93.184.216.34", 443)]


def test_fetch_pinned_bytes_uses_socks5_connect_to_pin_ip(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "socks5://127.0.0.1:1080")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(
        url_security,
        "pin_public_http_url",
        lambda _url: (
            "https://example.com/",
            "example.com",
            443,
            ["93.184.216.34"],
        ),
    )
    seen_tcp = []
    sent = []

    class FakeSock:
        def __init__(self):
            # greeting + CONNECT success (ATYP IPv4 + bind 0.0.0.0:0)
            self._inbox = bytearray(
                b"\x05\x00" + b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            )

        def sendall(self, data):
            sent.append(data)

        def recv(self, n):
            if not self._inbox:
                return b""
            out = bytes(self._inbox[:n])
            del self._inbox[:n]
            return out

        def close(self):
            return None

    def fake_create_connection(address, timeout=None):
        seen_tcp.append((address, timeout))
        return FakeSock()

    monkeypatch.setattr(url_security.socket, "create_connection", fake_create_connection)

    def boom_wrap_socket(self, sock, server_hostname=None):
        assert server_hostname == "example.com"
        raise OSError("stop after SOCKS5")

    monkeypatch.setattr(url_security.ssl.SSLContext, "wrap_socket", boom_wrap_socket)

    with pytest.raises(OSError, match="stop after SOCKS5"):
        url_security.fetch_pinned_bytes(
            "https://example.com/",
            timeout=5,
            max_bytes=64,
        )

    assert seen_tcp == [(("127.0.0.1", 1080), 5)]
    assert any(
        chunk.startswith(b"\x05\x01\x00\x01") and b"\x5d\xb8\xd8\x22" in chunk
        for chunk in sent
    )


def test_fetch_pinned_bytes_http_connect_failure_mentions_pinned_ip(monkeypatch):
    _clear_proxy_env(monkeypatch)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
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

    class FakeSock:
        def sendall(self, data):
            return None

        def recv(self, _n):
            return b"HTTP/1.1 403 Forbidden\r\n\r\n"

        def close(self):
            return None

    monkeypatch.setattr(
        url_security.socket,
        "create_connection",
        lambda *a, **k: FakeSock(),
    )
    with pytest.raises(OSError, match="pinned IP|CONNECT to raw"):
        url_security.fetch_pinned_bytes(
            "https://example.com/",
            timeout=1,
            max_bytes=16,
        )


def test_fetch_pinned_bytes_rejects_socks4_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "socks4://127.0.0.1:1080")
    monkeypatch.delenv("NO_PROXY", raising=False)
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
    with pytest.raises(OSError, match="SOCKS5"):
        url_security.fetch_pinned_bytes(
            "https://example.com/",
            timeout=1,
            max_bytes=16,
        )


def test_fetch_pinned_bytes_falls_back_to_all_proxy_socks_on_http_connect_fail(
    monkeypatch,
):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
    monkeypatch.setenv("ALL_PROXY", "socks5://127.0.0.1:7891")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(
        url_security,
        "pin_public_http_url",
        lambda _url: (
            "https://example.com/",
            "example.com",
            443,
            ["93.184.216.34"],
        ),
    )
    seen_tcp = []

    class HttpRefuseSock:
        def sendall(self, data):
            return None

        def recv(self, _n):
            return b"HTTP/1.1 403 Forbidden\r\n\r\n"

        def close(self):
            return None

    class SocksOkSock:
        def __init__(self):
            self._inbox = bytearray(
                b"\x05\x00" + b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            )

        def sendall(self, data):
            return None

        def recv(self, n):
            if not self._inbox:
                return b""
            out = bytes(self._inbox[:n])
            del self._inbox[:n]
            return out

        def close(self):
            return None

    def fake_create_connection(address, timeout=None):
        seen_tcp.append(address)
        if address == ("127.0.0.1", 7890):
            return HttpRefuseSock()
        if address == ("127.0.0.1", 7891):
            return SocksOkSock()
        raise OSError(f"unexpected {address}")

    monkeypatch.setattr(url_security.socket, "create_connection", fake_create_connection)

    def boom_wrap_socket(self, sock, server_hostname=None):
        assert server_hostname == "example.com"
        raise OSError("stop after SOCKS fallback")

    monkeypatch.setattr(url_security.ssl.SSLContext, "wrap_socket", boom_wrap_socket)

    with pytest.raises(OSError, match="stop after SOCKS fallback"):
        url_security.fetch_pinned_bytes(
            "https://example.com/",
            timeout=3,
            max_bytes=32,
        )

    assert seen_tcp == [("127.0.0.1", 7890), ("127.0.0.1", 7891)]


def test_curl_resolve_argument_brackets_ipv6():
    assert (
        url_security.curl_resolve_argument("v2ex.com", 443, "2001:db8::1")
        == "v2ex.com:443:[2001:db8::1]"
    )
    assert (
        url_security.curl_resolve_argument("v2ex.com", 443, "1.2.3.4")
        == "v2ex.com:443:1.2.3.4"
    )
