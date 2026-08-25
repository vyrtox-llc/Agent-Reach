"""Security helpers for untrusted URLs."""

from __future__ import annotations

import ipaddress
import socket
import http.client
import http.cookiejar
import ssl
import urllib.request
from urllib.parse import urljoin, urlsplit

_BLOCKED_PUBLIC_FETCH_HOSTS = {
    "home.arpa",
    "instance-data",
    "internal",
    "ip6-localhost",
    "ip6-loopback",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "metadata.google.internal",
}
_BLOCKED_PUBLIC_FETCH_SUFFIXES = (
    ".home.arpa",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
)


def _literal_ip_address(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse canonical and legacy IPv4 literal spellings without DNS."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def normalize_public_http_url(url: str) -> str:
    """Normalize a URL or reject targets that are not clearly public HTTP(S)."""
    candidate = str(url or "").strip()
    if (
        not candidate
        or "\\" in candidate
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in candidate
        )
    ):
        raise ValueError("only public HTTP(S) URLs are allowed")
    if "://" not in candidate:
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        # Accessing the port rejects malformed or out-of-range authorities.
        _ = parsed.port
    except (TypeError, ValueError):
        raise ValueError("only public HTTP(S) URLs are allowed") from None

    literal_address = _literal_ip_address(host)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or "%" in host
        or host in _BLOCKED_PUBLIC_FETCH_HOSTS
        or host.endswith(_BLOCKED_PUBLIC_FETCH_SUFFIXES)
        or ("." not in host and literal_address is None)
        or (literal_address is not None and not literal_address.is_global)
    ):
        raise ValueError("only public HTTP(S) URLs are allowed")

    return parsed.geturl()


_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _is_globally_routable(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return whether *addr* is safe to connect to from a public-fetch helper."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if (
        not addr.is_global
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_private
    ):
        return False
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK:
        return False
    return True


def pin_hostname(host: str, port: int) -> list[str]:
    """Resolve *host* and return pinned IPs, or reject non-global answers.

    Literal IP hosts are not DNS-resolved. Every A/AAAA from ``getaddrinfo``
    must be globally routable; mixed public+private answers fail closed.
    """
    normalized_host = str(host or "").lower().rstrip(".")
    if not normalized_host:
        raise ValueError("only public HTTP(S) URLs are allowed")

    literal = _literal_ip_address(normalized_host)
    if literal is not None:
        if not _is_globally_routable(literal):
            raise ValueError("only public HTTP(S) URLs are allowed")
        return [str(literal)]

    try:
        infos = socket.getaddrinfo(normalized_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("only public HTTP(S) URLs are allowed") from exc

    ips: list[str] = []
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        if "%" in ip_str:
            ip_str = ip_str.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise ValueError("only public HTTP(S) URLs are allowed") from exc
        if not _is_globally_routable(addr):
            raise ValueError("only public HTTP(S) URLs are allowed")
        canonical = str(addr)
        if canonical not in ips:
            ips.append(canonical)
    if not ips:
        raise ValueError("only public HTTP(S) URLs are allowed")
    return ips


def pin_public_http_url(url: str) -> tuple[str, str, int, list[str]]:
    """Normalize *url* and pin its host to globally routable addresses."""
    normalized = normalize_public_http_url(url)
    parsed = urlsplit(normalized)
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return normalized, host, port, pin_hostname(host, port)


def curl_resolve_argument(host: str, port: int, ip: str) -> str:
    """Return a ``curl --resolve`` value that pins *host*:*port* to *ip*."""
    formatted = ip
    if ":" in ip and not ip.startswith("["):
        formatted = f"[{ip}]"
    return f"{host}:{port}:{formatted}"


class _CookieResponse:
    """Minimal urllib-shaped response for ``CookieJar.extract_cookies``."""

    def __init__(self, response: http.client.HTTPResponse, url: str) -> None:
        self._headers = response.headers
        self._url = url

    def info(self):
        return self._headers

    def geturl(self) -> str:
        return self._url


def _host_header(host: str, port: int, scheme: str) -> str:
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return host
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _build_request(
    url: str,
    headers: dict[str, str] | None,
    cookie_jar: http.cookiejar.CookieJar | None,
) -> tuple[urllib.request.Request, dict[str, str]]:
    request = urllib.request.Request(url, headers=dict(headers or {}))
    if cookie_jar is not None:
        cookie_jar.add_cookie_header(request)
    return request, dict(request.header_items())


def _http_get_once(
    scheme: str,
    normalized: str,
    host: str,
    port: int,
    pin_ip: str,
    headers: dict[str, str],
    timeout: float,
    max_bytes: int,
    cookie_jar: http.cookiejar.CookieJar | None,
    request: urllib.request.Request,
) -> tuple[int, bytes, str | None]:
    parsed = urlsplit(normalized)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    sock = socket.create_connection((pin_ip, port), timeout=timeout)
    conn: http.client.HTTPConnection | None = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            ssock = context.wrap_socket(sock, server_hostname=host)
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
            conn.sock = ssock
        else:
            conn = http.client.HTTPConnection(pin_ip, port, timeout=timeout)
            conn.sock = sock
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        body = response.read(max_bytes + 1)
        location = response.getheader("Location")
        if cookie_jar is not None:
            cookie_jar.extract_cookies(_CookieResponse(response, normalized), request)
        return response.status, body, location
    finally:
        if conn is not None:
            conn.close()
        else:
            sock.close()


def fetch_pinned_bytes(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 30,
    max_bytes: int,
    cookie_jar: http.cookiejar.CookieJar | None = None,
) -> bytes:
    """GET *url* by connecting to a DNS-pinned global-unicast IP.

    TLS uses the original hostname for SNI and certificate checks. Redirects
    are re-normalized and re-pinned. urllib is not used for the TCP/TLS hop
    because it would resolve the hostname again.
    """
    current = url
    for _ in range(_MAX_REDIRECTS + 1):
        normalized, host, port, ips = pin_public_http_url(current)
        parsed = urlsplit(normalized)
        scheme = parsed.scheme.lower()
        request, send_headers = _build_request(normalized, headers, cookie_jar)
        send_headers["Host"] = _host_header(host, port, scheme)

        last_error: OSError | None = None
        status = 0
        body = b""
        location: str | None = None
        connected = False
        for pin_ip in ips:
            try:
                status, body, location = _http_get_once(
                    scheme,
                    normalized,
                    host,
                    port,
                    pin_ip,
                    send_headers,
                    timeout,
                    max_bytes,
                    cookie_jar,
                    request,
                )
            except OSError as exc:
                last_error = exc
                continue
            connected = True
            break
        if not connected:
            raise last_error or OSError("pinned fetch failed")
        if status in _REDIRECT_STATUSES and location:
            current = urljoin(normalized, location)
            continue
        if status >= 400:
            raise OSError(f"HTTP {status}")
        if len(body) > max_bytes:
            raise ValueError(f"response exceeds {max_bytes} byte limit")
        return body
    raise ValueError("too many redirects")


def domain_matches(host: str, *domains: str) -> bool:
    """Match a hostname/cookie domain exactly or as a real subdomain."""
    normalized_host = str(host or "").lower().lstrip(".").rstrip(".")
    if not normalized_host:
        return False
    for domain in domains:
        allowed = domain.lower().lstrip(".").rstrip(".")
        if normalized_host == allowed or normalized_host.endswith("." + allowed):
            return True
    return False


def host_matches(url: str, *domains: str) -> bool:
    """Return whether *url* has an exact allowed host or a real subdomain.

    Only HTTP(S) URLs without userinfo are accepted. Using ``hostname`` rather
    than substring matching prevents lookalikes such as ``x.com.evil.test`` and
    userinfo disguises such as ``x.com@evil.test``.
    """
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        # ``hostname`` is permissive: malformed or out-of-range ports only
        # raise when ``port`` is accessed. Force that validation here so
        # hostile authorities fail closed.
        _ = parsed.port
    except (TypeError, ValueError):
        return False

    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if not host or parsed.username is not None or parsed.password is not None:
        return False

    return domain_matches(host, *domains)
