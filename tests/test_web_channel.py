# -*- coding: utf-8 -*-
"""Dedicated tests for the ``web`` channel.

``web`` is the tier-0 catch-all: ``can_handle`` must accept *anything* so it
can back-stop every other channel, ``check`` must report ready without touching
the network (it is the zero-overhead fallback), and ``read`` must normalise the
URL before handing it to Jina Reader. Follow-up to #331 / #360 / #361,
completing dedicated coverage for the channels that still lacked it.
"""

from unittest.mock import patch

import pytest

from agent_reach.channels.web import _MAX_RESPONSE_BYTES, _UA, WebChannel


# --- can_handle: universal fallback contract ---

def test_can_handle_accepts_any_url():
    channel = WebChannel()
    for sample in [
        "https://example.com",
        "http://example.com/path?q=1",
        "example.com",
        "ftp://files.example.com/readme.txt",
        "not a url at all",
        "",
    ]:
        assert channel.can_handle(sample) is True, sample


# --- check: ready without any network probe (零开销兜底) ---

def test_check_is_ok_and_touches_no_network():
    channel = WebChannel()
    with patch("agent_reach.utils.url.fetch_pinned_bytes") as mock_fetch:
        status, message = channel.check()
    assert status == "ok"
    assert channel.active_backend == "Jina Reader"
    assert "Jina Reader" in message
    # The fallback channel must stay zero-overhead: no probing on check().
    mock_fetch.assert_not_called()


# --- read: URL normalisation + Jina Reader request shape ---

def test_read_prepends_https_for_schemeless_url():
    channel = WebChannel()
    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=b"# Example\nfull text\n",
    ) as mock_fetch:
        out = channel.read("example.com/article")
    assert mock_fetch.call_args.args[0] == (
        "https://r.jina.ai/https://example.com/article"
    )
    assert out == "# Example\nfull text\n"


def test_read_preserves_existing_http_scheme():
    channel = WebChannel()
    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=b"# Example\nfull text\n",
    ) as mock_fetch:
        channel.read("http://example.com")
    # http:// must be kept as-is, not coerced to https:// nor double-prefixed.
    assert mock_fetch.call_args.args[0] == "https://r.jina.ai/http://example.com"


def test_read_preserves_existing_https_scheme():
    channel = WebChannel()
    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=b"# Example\nfull text\n",
    ) as mock_fetch:
        channel.read("https://example.com/deep/path")
    assert mock_fetch.call_args.args[0] == (
        "https://r.jina.ai/https://example.com/deep/path"
    )


def test_read_sends_expected_headers_and_timeout():
    channel = WebChannel()
    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=b"# Example\nfull text\n",
    ) as mock_fetch:
        channel.read("https://example.com")
    assert mock_fetch.call_args.kwargs["headers"] == {
        "User-Agent": _UA,
        "Accept": "text/plain",
    }
    assert mock_fetch.call_args.kwargs["timeout"] == 30
    assert mock_fetch.call_args.kwargs["max_bytes"] == _MAX_RESPONSE_BYTES


def test_read_decodes_utf8_body():
    channel = WebChannel()
    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value="café ☕\n".encode("utf-8"),
    ):
        out = channel.read("https://example.com")
    assert out == "café ☕\n"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/file",
        "http://localhost/admin",
        "http://intranet/admin",
        "http://home.arpa/admin",
        "http://metadata.google.internal/latest/meta-data",
        "http://127.0.0.1/private",
        "http://127.1/private",
        "http://169.254.169.254/latest/meta-data",
        "http://192.168.1/private",
        "http://0/private",
        "http://2130706433/private",
        "http://0x7f000001/private",
        "http://0177.0.0.1/private",
        "http://2852039166/latest/meta-data",
        "http://0xA9FEA9FE/latest/meta-data",
        "http://[::1]/private",
        "http://[::ffff:127.0.0.1]/private",
        "http://localhost./admin",
        "http://127.0.0.1\\example.com/private",
        "https://user:password@example.com/private",
    ],
)
def test_read_rejects_non_public_urls_before_network(url):
    channel = WebChannel()

    with patch("agent_reach.utils.url.fetch_pinned_bytes") as mock_fetch:
        with pytest.raises(ValueError, match="public HTTP"):
            channel.read(url)

    mock_fetch.assert_not_called()


@pytest.mark.parametrize("url", ["https://8.8.8.8/page", "http://010.010.010.010/page"])
def test_read_allows_public_literal_addresses(url):
    channel = WebChannel()
    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=b"# Example\nfull text\n",
    ) as mock_fetch:
        channel.read(url)
    mock_fetch.assert_called_once()


def test_read_accepts_response_at_exact_size_limit():
    channel = WebChannel()
    body = b"x" * _MAX_RESPONSE_BYTES

    with patch("agent_reach.utils.url.fetch_pinned_bytes", return_value=body):
        out = channel.read("https://example.com/exact")

    assert len(out.encode("utf-8")) == _MAX_RESPONSE_BYTES


def test_read_rejects_oversized_reader_response():
    channel = WebChannel()

    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        side_effect=ValueError(
            f"response exceeds {_MAX_RESPONSE_BYTES} byte limit"
        ),
    ):
        with pytest.raises(ValueError, match="response exceeds"):
            channel.read("https://example.com/large")


@pytest.mark.parametrize(
    "body",
    [
        (
            "Title: Just a moment...\n\n"
            "URL Source: https://imginn.com/instagram/\n\n"
            "Warning: This page maybe requiring CAPTCHA\n\n"
            "Markdown Content:\n\n"
            "## Performing security verification\n"
        ),
        (
            "Title: Attention Required! | Cloudflare\n\n"
            "Sorry, you have been blocked.\n\nRay ID: 1234567890abcdef\n"
        ),
    ],
)
def test_read_rejects_high_confidence_antibot_pages(body):
    channel = WebChannel()

    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=body.encode("utf-8"),
    ) as mock_fetch:
        with pytest.raises(RuntimeError, match="反爬验证页"):
            channel.read("https://example.com/protected")

    mock_fetch.assert_called_once()


@pytest.mark.parametrize(
    "body",
    [
        "# A guide to security verification\n",
        "# DDoS protection explained\n",
        "# Checking your browser automation\n",
        "# Please turn JavaScript on for progressive enhancement\n",
        "# A history of cf-browser-verify\n",
        "Title: Just a moment...\n\nA short-story review.\n",
    ],
)
def test_read_does_not_reject_single_generic_antibot_terms(body):
    channel = WebChannel()

    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=body.encode("utf-8"),
    ):
        assert channel.read("https://example.com/article") == body


def test_antibot_detection_has_a_fixed_scan_window():
    channel = WebChannel()
    body = (
        "x" * 4096
        + "Warning: requiring CAPTCHA\n"
        + "Title: Just a moment...\n"
        + "## Performing security verification\n"
    )

    with patch(
        "agent_reach.utils.url.fetch_pinned_bytes",
        return_value=body.encode("utf-8"),
    ):
        assert channel.read("https://example.com/long-article") == body
