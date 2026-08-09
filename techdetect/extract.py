"""HTML signal extraction and the SignalSet container."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser

# <script> types whose bodies are executable JavaScript ("" = no/empty type attribute).
EXECUTABLE_SCRIPT_TYPES = {"", "text/javascript", "application/javascript", "module"}


@dataclass
class SignalSet:
    """All signals collected for one domain, grouped by channel.

    ``script_srcs`` and ``inline_scripts`` are kept separate: the Wappalyzer
    ``scriptSrc`` key matches only the former, ``scripts`` only the latter, and
    the assignment-compatibility ``script`` key matches both.
    """

    headers: list[tuple[str, str]] = field(default_factory=list)
    cookies: list[tuple[str, str]] = field(default_factory=list)
    script_srcs: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    html: str = ""
    metas: dict[str, list[str]] = field(default_factory=dict)
    dns: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class PageSignals:
    """Signals extracted from one HTML document."""

    script_srcs: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    metas: dict[str, list[str]] = field(default_factory=dict)


class _PageParser(HTMLParser):
    """Collects script src values, executable inline script bodies and meta tags.

    Inline bodies are collected only for scripts without a ``src`` whose ``type``
    is executable JavaScript — data blobs such as ``application/json``
    (e.g. Next.js ``__NEXT_DATA__``) or ``application/ld+json`` are excluded so
    that page text mentioning a vendor URL can never look like script usage.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.page = PageSignals()
        self._collecting_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            attr = {k.lower(): (v or "") for k, v in attrs}
            src = attr.get("src", "").strip()
            if src:
                self.page.script_srcs.append(src)
            script_type = attr.get("type", "").strip().lower()
            self._collecting_script = not src and script_type in EXECUTABLE_SCRIPT_TYPES
            self._script_chunks = []
        elif tag == "meta":
            attr = {k.lower(): (v or "") for k, v in attrs}
            name = (attr.get("name") or attr.get("property") or "").strip().lower()
            if name and "content" in attr:
                self.page.metas.setdefault(name, []).append(attr["content"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            if self._collecting_script:
                body = "".join(self._script_chunks).strip()
                if body:
                    self.page.inline_scripts.append(body)
            self._collecting_script = False
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._collecting_script:
            self._script_chunks.append(data)


def extract_page_signals(html_text: str) -> PageSignals:
    """Parse an HTML document into PageSignals; malformed input never raises."""
    parser = _PageParser()
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:  # html.parser can choke on pathological markup
        pass
    return parser.page
