"""Homepage fetching: candidate ladder, body cap, cookie chain walk, soft-block detection.

The ladder advances only on transport failures (DNS, connect, TLS, timeout).
Any valid HTTP response — including 4xx/5xx — ends the ladder: that response IS
the domain's answer and its headers/cookies are evidence. Whether the *body*
may be trusted as the site's own homepage is a separate question answered by
``FetchResult.page_trusted``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

# Bounds memory and matching work on unexpectedly large responses. Sized with
# headroom over real homepages: the largest of the assignment's test domains
# serves ~1.5 MB, and a cap it can reach would silently drop page signals.
BODY_CAP_BYTES = 4_000_000
DEFAULT_TIMEOUT = 8.0
CONNECT_TIMEOUT = 5.0
# Challenge markers are only searched in this prefix of a 2xx body: real
# challenge pages are tiny, and a long legitimate page that merely mentions a
# vendor name must not be classified as blocked.
CHALLENGE_SCAN_PREFIX = 10_000

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

BLOCK_STATUSES = {401, 403, 429}
CHALLENGE_BODY_MARKERS = (
    "just a moment",
    "attention required",
    "checking your browser",
    "cf-chl",
    "_cf_chl_opt",
    "challenge-platform",
    "px-captcha",
    "_pxhd",
    "datadome",
)
CHALLENGE_HEADER_NAMES = ("cf-mitigated",)


@dataclass
class FetchResult:
    domain: str
    status: int | None = None
    final_url: str | None = None
    final_host: str | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    cookies: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    blocked: bool = False
    block_reason: str | None = None
    error: str | None = None
    truncated: bool = False  # body hit BODY_CAP_BYTES; signals past the cap were not read

    @property
    def responded(self) -> bool:
        return self.status is not None

    @property
    def page_trusted(self) -> bool:
        """True when the body can be treated as the site's own homepage.

        Only successful 2xx responses qualify. A final 3xx (an unfollowed or
        terminal redirect, or a 304) carries no representation of the page, so
        its body must never feed the HTML, script or meta channels.
        """
        return self.responded and 200 <= self.status < 300 and not self.blocked


def make_client(timeout: float = DEFAULT_TIMEOUT, **kwargs) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=10,
        timeout=httpx.Timeout(timeout, connect=CONNECT_TIMEOUT),
        headers=BROWSER_HEADERS,
        **kwargs,
    )


def candidate_urls(host: str) -> list[str]:
    return [
        f"https://{host}/",
        f"https://www.{host}/",
        f"http://{host}/",
        f"http://www.{host}/",
    ]


def _decode(raw: bytes, response: httpx.Response) -> str:
    encoding = response.charset_encoding or "utf-8"
    try:
        return raw.decode(encoding, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _collect_cookies(response: httpx.Response) -> list[tuple[str, str]]:
    """Set-Cookie (name, value) pairs from every hop of the redirect chain."""
    pairs: list[tuple[str, str]] = []
    for hop in [*response.history, response]:
        for header_value in hop.headers.get_list("set-cookie"):
            name, _, value = header_value.split(";", 1)[0].partition("=")
            if name.strip():
                pairs.append((name.strip(), value.strip()))
    return pairs


def _classify_block(status: int, headers: httpx.Headers, body_lower: str) -> str | None:
    if status in BLOCK_STATUSES:
        return f"HTTP {status}"
    challenge_header = any(name in headers for name in CHALLENGE_HEADER_NAMES)
    if status == 503:
        if challenge_header or any(m in body_lower for m in CHALLENGE_BODY_MARKERS):
            return "HTTP 503 challenge"
        return None
    if status < 400:
        prefix = body_lower[:CHALLENGE_SCAN_PREFIX]
        if challenge_header or any(m in prefix for m in CHALLENGE_BODY_MARKERS):
            return f"challenge page (HTTP {status})"
    return None


async def _attempt(client: httpx.AsyncClient, host: str, url: str) -> FetchResult:
    async with client.stream("GET", url) as response:
        raw = bytearray()
        async for chunk in response.aiter_bytes():
            raw.extend(chunk)
            # Read one byte past the cap so a body of exactly BODY_CAP_BYTES is
            # not misreported as truncated.
            if len(raw) > BODY_CAP_BYTES:
                break
    truncated = len(raw) > BODY_CAP_BYTES
    body = _decode(bytes(raw[:BODY_CAP_BYTES]), response)
    block_reason = _classify_block(response.status_code, response.headers, body.lower())
    return FetchResult(
        domain=host,
        status=response.status_code,
        final_url=str(response.url),
        final_host=urlsplit(str(response.url)).hostname,
        headers=list(response.headers.multi_items()),
        cookies=_collect_cookies(response),
        body=body,
        blocked=block_reason is not None,
        block_reason=block_reason,
        truncated=truncated,
    )


async def fetch_homepage(client: httpx.AsyncClient, host: str) -> FetchResult:
    """Fetch the homepage for a normalized host, walking the candidate ladder."""
    last_error: str | None = None
    for url in candidate_urls(host):
        try:
            return await _attempt(client, host, url)
        except httpx.HTTPError as exc:
            last_error = f"{url}: {exc.__class__.__name__}: {exc}"
            logger.debug("fetch attempt failed — %s", last_error)
    return FetchResult(domain=host, error=last_error or "no fetch attempt made")
