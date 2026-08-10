"""Fetcher tests via httpx.MockTransport (no network)."""

import httpx
import pytest

from techdetect.fetcher import BODY_CAP_BYTES, FetchResult, fetch_homepage


def client_for(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


async def test_redirect_chain_cookies_and_final_host():
    def handler(request):
        if request.url.host == "redir.test":
            return httpx.Response(
                301,
                headers={
                    "location": "https://www.redir.test/",
                    "set-cookie": "intercom-session-x=abc123; Path=/; HttpOnly",
                },
            )
        return httpx.Response(
            200,
            headers={"set-cookie": "final=1"},
            html="<html></html>",
        )

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "redir.test")
    assert result.status == 200
    assert result.final_host == "www.redir.test"
    assert ("intercom-session-x", "abc123") in result.cookies  # set on the redirect hop
    assert ("final", "1") in result.cookies
    assert result.page_trusted


async def test_ladder_advances_on_transport_failure_only():
    attempts = []

    def handler(request):
        attempts.append(str(request.url))
        if request.url.scheme == "https":
            raise httpx.ConnectError("refused")
        return httpx.Response(200, html="<html>ok</html>")

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "ladder.test")
    assert result.status == 200
    assert attempts == [
        "https://ladder.test/",
        "https://www.ladder.test/",
        "http://ladder.test/",
    ]


async def test_valid_http_response_ends_ladder_even_on_500():
    attempts = []

    def handler(request):
        attempts.append(str(request.url))
        return httpx.Response(500, text="internal error")

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "err.test")
    assert len(attempts) == 1  # never advanced past a valid response
    assert result.status == 500
    assert not result.blocked
    assert not result.page_trusted  # but the body is not the homepage


async def test_all_candidates_fail_yields_structured_error():
    def handler(request):
        raise httpx.ConnectTimeout("timed out")

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "down.test")
    assert not result.responded
    assert "ConnectTimeout" in result.error
    assert result.headers == [] and result.cookies == []


async def test_soft_block_status_keeps_headers_and_cookies():
    def handler(request):
        return httpx.Response(
            403,
            headers={"cf-ray": "8f2abc-EWR", "set-cookie": "__cf_bm=tok123"},
            text="<html>Forbidden</html>",
        )

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "blocked.test")
    assert result.blocked and result.block_reason == "HTTP 403"
    assert not result.page_trusted
    assert ("cf-ray", "8f2abc-EWR") in result.headers
    assert ("__cf_bm", "tok123") in result.cookies


async def test_http_200_challenge_page_is_blocked():
    def handler(request):
        return httpx.Response(
            200, html="<html><title>Just a moment...</title><body>checking</body></html>"
        )

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "challenge.test")
    assert result.blocked
    assert "challenge page" in result.block_reason
    assert not result.page_trusted


async def test_503_challenge_vs_plain_503():
    def handler(request):
        if request.url.host == "cfdown.test":
            return httpx.Response(503, text="<html>cf-chl challenge-platform</html>")
        return httpx.Response(503, text="<html>scheduled maintenance</html>")

    async with client_for(handler) as client:
        challenged = await fetch_homepage(client, "cfdown.test")
        maintenance = await fetch_homepage(client, "down.test")
    assert challenged.blocked and challenged.block_reason == "HTTP 503 challenge"
    assert not maintenance.blocked
    assert not maintenance.page_trusted


async def test_body_is_capped():
    def handler(request):
        return httpx.Response(200, content=b"a" * (BODY_CAP_BYTES + 100_000))

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "big.test")
    assert len(result.body) <= BODY_CAP_BYTES


async def test_charset_decoding_with_fallback():
    def handler(request):
        return httpx.Response(
            200,
            content="café".encode("latin-1"),
            headers={"content-type": "text/html; charset=iso-8859-1"},
        )

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "charset.test")
    assert "café" in result.body


@pytest.mark.parametrize(
    ("status", "blocked", "trusted"),
    [
        (200, False, True),
        (204, False, True),  # trusted even though the body is empty
        (299, False, True),
        (301, False, False),  # a final 3xx carries no page representation
        (302, False, False),
        (304, False, False),
        (403, False, False),
        (404, False, False),
        (500, False, False),
        (200, True, False),  # 200 challenge page classified as blocked
    ],
)
def test_page_trusted_only_for_unblocked_2xx(status, blocked, trusted):
    assert FetchResult(domain="d", status=status, blocked=blocked).page_trusted is trusted


def test_page_not_trusted_without_a_response():
    assert not FetchResult(domain="d").page_trusted


async def test_final_3xx_response_is_not_trusted_end_to_end():
    """A terminal redirect (no Location to follow) must not feed page channels."""

    def handler(request):
        return httpx.Response(302, html='<html><link href="/wp-content/x.css"></html>')

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "redirloop.test")
    assert result.status == 302
    assert not result.blocked
    assert not result.page_trusted
    assert result.body  # body was still read, it is simply not trusted


async def test_204_no_content_is_trusted_end_to_end():
    def handler(request):
        return httpx.Response(204)

    async with client_for(handler) as client:
        result = await fetch_homepage(client, "empty.test")
    assert result.status == 204
    assert result.page_trusted
    assert result.body == ""
