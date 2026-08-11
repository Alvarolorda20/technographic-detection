"""Wappalyzer-format fingerprint loading and signal matching.

Compatibility scope: this module is format-compatible with the open-source
Wappalyzer technology schema and needs zero technology-specific code changes
for the channels it supports (headers, cookies, scriptSrc, scripts, script,
html, meta, dns MX/TXT/CNAME, and js when explicitly enabled). Patterns in
unsupported channels (dom, xhr, ...) are skipped safely and counted so callers
can report them.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path

from techdetect.extract import SignalSet

logger = logging.getLogger(__name__)

DEFAULT_CONFIDENCE = 100
CONFIDENCE_CAP = 100
SNIPPET_WIDTH = 60

LIST_CHANNELS = {"scriptSrc", "scripts", "script", "html"}
SUPPORTED_DNS_TYPES = {"MX", "TXT", "CNAME"}
# Wappalyzer keys that are descriptive metadata, not matchable patterns.
METADATA_KEYS = {
    "cats",
    "website",
    "description",
    "icon",
    "cpe",
    "saas",
    "oss",
    "pricing",
    "implies",
    "requires",
    "requiresCategory",
    "excludes",
}

# Shipped as package data, so an installed wheel works without the repo checkout.
DEFAULT_FINGERPRINTS_PATH = resources.files("techdetect") / "data" / "fingerprints.json"


class FingerprintError(ValueError):
    """A fingerprint file cannot be loaded or fails strict validation."""


class _SkipPattern(Exception):
    """Internal: a single pattern was skipped during lenient loading."""


@dataclass(frozen=True)
class Rule:
    """One compiled pattern bound to the channel it may match against."""

    technology: str
    channel: str
    raw_pattern: str
    confidence: int
    value_regex: re.Pattern[str] | None  # None = presence-only
    name_regex: re.Pattern[str] | None = None  # headers/cookies dict key
    meta_name: str | None = None
    dns_type: str | None = None
    js_path: str | None = None  # global property path, as written in the fingerprint
    js_needle: str | None = None  # longest path segment; pre-filter for the js matcher


@dataclass(frozen=True)
class MatchEvidence:
    """Why a technology was detected. ``matched_signal`` is sanitized/truncated."""

    technology: str
    channel: str
    pattern: str
    matched_signal: str
    confidence: int


def _parse_pattern(raw: str) -> tuple[str, int]:
    r"""Split a Wappalyzer pattern into (regex source, confidence).

    Tags after ``\;`` are parsed: ``confidence:N`` is honored (default 100),
    ``version:...`` is recognized and intentionally discarded.
    """
    parts = raw.split("\\;")
    confidence = DEFAULT_CONFIDENCE
    for tag in parts[1:]:
        if tag.startswith("confidence:"):
            try:
                confidence = int(tag.split(":", 1)[1])
            except ValueError:
                pass
    return parts[0], confidence


def _as_list(value: object) -> list:
    return value if isinstance(value, list) else [value]


def _pattern_count(value: object) -> int:
    if isinstance(value, dict):
        return sum(len(_as_list(v)) for v in value.values())
    return len(_as_list(value))


def _snippet(text: str, match: re.Match[str] | None = None, width: int = SNIPPET_WIDTH) -> str:
    """Sanitized evidence: a short, whitespace-collapsed window around the match.

    Never exposes complete cookie values, header values, HTML documents or
    script bodies.
    """
    start = 0 if match is None else max(0, match.start() - width // 2)
    window = " ".join(text[start : start + width].split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if start + width < len(text) else ""
    return f"{prefix}{window}{suffix}"


class FingerprintSet:
    """Compiled rules plus bookkeeping about anything that was skipped."""

    def __init__(self, rules: list[Rule], skipped: Counter[str]) -> None:
        self.rules = rules
        self.skipped = skipped

    @property
    def pattern_count(self) -> int:
        return len(self.rules)

    @property
    def technology_count(self) -> int:
        return len({rule.technology for rule in self.rules})

    def skipped_summary(self) -> str:
        if not self.skipped:
            return ""
        parts = [f"{channel}: {count}" for channel, count in sorted(self.skipped.items())]
        return f"skipped {sum(self.skipped.values())} unsupported pattern(s) — " + ", ".join(parts)

    def match(
        self, signals: SignalSet, min_confidence: int = DEFAULT_CONFIDENCE
    ) -> tuple[list[str], list[MatchEvidence]]:
        """Return (sorted detected technologies, evidence records).

        Confidence accumulates across distinct matched rules — each rule counts
        at most once — capped at 100; a technology is emitted only when its
        total reaches ``min_confidence``.
        """
        totals: Counter[str] = Counter()
        evidence: list[MatchEvidence] = []
        for rule in self.rules:
            found = _apply_rule(rule, signals)
            if found is not None:
                evidence.append(found)
                totals[rule.technology] += rule.confidence
        detected = sorted(
            tech for tech, total in totals.items() if min(total, CONFIDENCE_CAP) >= min_confidence
        )
        return detected, evidence


def _evidence(rule: Rule, matched_signal: str) -> MatchEvidence:
    return MatchEvidence(
        technology=rule.technology,
        channel=rule.channel,
        pattern=rule.raw_pattern,
        matched_signal=matched_signal,
        confidence=rule.confidence,
    )


def _match_named_pairs(
    rule: Rule, pairs: list[tuple[str, str]], *, full_name_match: bool, label_sep: str
) -> MatchEvidence | None:
    """Shared matcher for headers (fullmatch on name) and cookies (search on name)."""
    assert rule.name_regex is not None
    for name, value in pairs:
        name_hit = (
            rule.name_regex.fullmatch(name) if full_name_match else rule.name_regex.search(name)
        )
        if not name_hit:
            continue
        if rule.value_regex is None:
            return _evidence(rule, f"{name}{label_sep}{_snippet(value)}")
        value_match = rule.value_regex.search(value)
        if value_match:
            return _evidence(rule, f"{name}{label_sep}{_snippet(value, value_match)}")
    return None


# Escaped opening script tags right before a match mean the surrounding text is
# HTML serialized as data (a docs code sample, a JSON payload) — not a script
# reference. Raw "<script" is NOT guarded: document.write loaders are real usage.
_ESCAPED_SCRIPT_TAG_MARKERS = ("\\u003cscript", "&lt;script", "\\x3cscript", "%3cscript")
_GUARD_WINDOW = 64


def _inside_serialized_html(text: str, match_start: int) -> bool:
    window = text[max(0, match_start - _GUARD_WINDOW) : match_start].lower()
    return any(marker in window for marker in _ESCAPED_SCRIPT_TAG_MARKERS)


# Roots accepted as "the global object" for the js channel. `top` and `parent`
# are deliberately excluded: a cross-frame read is not evidence that this page
# provisions the technology, and `parent` is a common local variable name.
JS_GLOBAL_OBJECTS = ("window", "globalThis", "self")
_JS_ROOT = r"(?<![\w$])(?:" + "|".join(JS_GLOBAL_OBJECTS) + r")"
_JS_DOT = r"\s*\??\.\s*"  # `.x`, ` . x`, a line break, and optional chaining `?.x`
_JS_END = r"(?![\w$])"  # `window.Foo` must not match `window.Foobar`


def _js_access_regex(segments: list[str]) -> re.Pattern[str]:
    """Match an explicit read of ``segments`` through the global object.

    The first segment is reachable as ``.name`` or ``["name"]``; the rest only
    as ``.name`` — bracket access on inner segments is not supported (a
    documented limitation). Segments are escaped individually because real keys
    contain regex metacharacters (jQuery's ``$.fn.jquery``).
    """
    first, *rest = (re.escape(segment) for segment in segments)
    bracket = rf"\s*\[\s*(['\"]){first}\1\s*\]"
    tail = "".join(_JS_DOT + segment for segment in rest)
    return re.compile(rf"{_JS_ROOT}(?:{_JS_DOT}{first}|{bracket}){tail}{_JS_END}")


def _match_texts(
    rule: Rule, texts: list[str], label: str = "", guard_serialized_html: bool = False
) -> MatchEvidence | None:
    for text in texts:
        if rule.value_regex is None:
            return _evidence(rule, f"{label}{_snippet(text)}")
        for found in rule.value_regex.finditer(text):
            if guard_serialized_html and _inside_serialized_html(text, found.start()):
                continue
            return _evidence(rule, f"{label}{_snippet(text, found)}")
    return None


def _apply_rule(rule: Rule, signals: SignalSet) -> MatchEvidence | None:
    if rule.channel == "headers":
        return _match_named_pairs(rule, signals.headers, full_name_match=True, label_sep=": ")
    if rule.channel == "cookies":
        return _match_named_pairs(rule, signals.cookies, full_name_match=False, label_sep="=")
    if rule.channel == "scriptSrc":
        return _match_texts(rule, signals.script_srcs)
    if rule.channel == "scripts":
        return _match_texts(
            rule, signals.inline_scripts, label="inline: ", guard_serialized_html=True
        )
    if rule.channel == "script":
        return _match_texts(rule, signals.script_srcs) or _match_texts(
            rule, signals.inline_scripts, label="inline: ", guard_serialized_html=True
        )
    if rule.channel == "html":
        return _match_texts(rule, [signals.html] if signals.html else [])
    if rule.channel == "meta":
        assert rule.meta_name is not None
        return _match_texts(
            rule, signals.metas.get(rule.meta_name, []), label=f"meta[{rule.meta_name}]: "
        )
    if rule.channel == "dns":
        assert rule.dns_type is not None
        return _match_texts(rule, signals.dns.get(rule.dns_type, []), label=f"{rule.dns_type} ")
    if rule.channel == "js":
        # No JavaScript is executed, so the strongest available static proxy for
        # "this global exists at runtime" is an explicit read of it through the
        # global object, not the bare name appearing somewhere in the source.
        # Still weaker evidence than every other channel — a feature check reads
        # exactly like real usage — hence opt-in only.
        #
        # The needle pre-filter is behaviour-preserving (every segment appears
        # verbatim in any match, and this channel is case-sensitive) and is
        # needed for speed: the alternated root defeats CPython's literal-prefix
        # scan. Measured on the full database (5,639 js rules) against the
        # heaviest test domain (1.3 MB of inline script): 4.7s with it, 194s
        # without.
        assert rule.js_needle is not None
        texts = [text for text in signals.inline_scripts if rule.js_needle in text]
        return _match_texts(rule, texts, label="js: ", guard_serialized_html=True)
    raise AssertionError(f"unreachable channel {rule.channel!r}")


def load_fingerprints(
    path: str | Path | Traversable, strict: bool = False, enable_js: bool = False
) -> FingerprintSet:
    """Load a Wappalyzer-format fingerprint JSON file.

    ``path`` may be a filesystem path or an ``importlib.resources`` traversable
    (how the bundled set is shipped), so an installed wheel needs no checkout.

    ``strict=True`` (used for the bundled set) fails on ANY skipped or invalid
    pattern; the lenient default (external files such as the full Wappalyzer
    database) skips incompatible patterns with warnings and per-channel counts.

    ``enable_js=True`` compiles the ``js`` channel as a conservative static
    approximation (see ``_js_access_regex``). It is off by default because even
    an explicit read of a global does not establish that the global exists at
    runtime — a feature check is indistinguishable from real use.
    """
    source = Path(path) if isinstance(path, str) else path
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FingerprintError(f"cannot load fingerprints from {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise FingerprintError(f"{path}: expected a JSON object mapping technology -> fingerprint")

    rules: list[Rule] = []
    skipped: Counter[str] = Counter()

    def skip(reason: str, count: int, detail: str) -> None:
        if strict:
            raise FingerprintError(f"strict fingerprint validation failed — {detail}")
        logger.warning("skipping %d pattern(s) [%s]: %s", count, reason, detail)
        skipped[reason] += count

    def compile_regex(tech: str, channel: str, source: str, raw: str) -> re.Pattern[str]:
        try:
            return re.compile(source, re.IGNORECASE)
        except re.error as exc:
            skip(f"{channel}:invalid-regex", 1, f"{tech}: {raw!r} ({exc})")
            raise _SkipPattern from exc

    def value_rule(tech: str, channel: str, raw: object, **extra: object) -> Rule:
        source, confidence = _parse_pattern(str(raw))
        regex = compile_regex(tech, channel, source, str(raw)) if source else None
        return Rule(
            technology=tech,
            channel=channel,
            raw_pattern=str(raw),
            confidence=confidence,
            value_regex=regex,
            **extra,  # type: ignore[arg-type]
        )

    def add(build) -> None:
        """Append one rule; a skipped pattern never affects its siblings."""
        try:
            rules.append(build())
        except _SkipPattern:
            pass

    def js_rule(tech: str, global_path: str, val_raw: object) -> Rule:
        """A ``js`` entry: the key is a global property path, compiled into an
        access pattern; the value only carries version/confidence tags (never a
        pattern for the path).

        Two spellings occur in the real database and are normalized here: a
        leading dot (``.__NEXT_DATA__.gsp``) and an explicitly written root
        (``window.AudioEye.version``, which would otherwise compile into
        ``window.window.…`` and never match).

        No ``IGNORECASE``: property access in JavaScript is case-sensitive and
        the fingerprint key *is* the identifier, so folding case would both
        overmatch and silently break the pre-filter in ``_apply_rule``.
        """
        path = str(global_path).strip()
        segments = [segment.strip() for segment in path.strip(".").split(".")]
        if segments and segments[0] in JS_GLOBAL_OBJECTS:
            segments = segments[1:]  # the root is implicit in every compiled pattern
        if not segments or not all(segments):
            skip("js:malformed", 1, f"{tech}: unusable js global path {path!r}")
            raise _SkipPattern
        _, confidence = _parse_pattern(str(val_raw))
        return Rule(
            technology=tech,
            channel="js",
            raw_pattern=f"js:{path}",
            confidence=confidence,
            value_regex=_js_access_regex(segments),
            js_path=path,
            js_needle=max(segments, key=len),
        )

    def header_cookie_rule(tech: str, key: str, name_raw: str, val_raw: object) -> Rule:
        name_regex = compile_regex(tech, key, name_raw, name_raw)
        base = value_rule(tech, key, val_raw)
        return Rule(
            technology=base.technology,
            channel=key,
            raw_pattern=f"{name_raw} -> {val_raw}",
            confidence=base.confidence,
            value_regex=base.value_regex,
            name_regex=name_regex,
        )

    for tech, spec in data.items():
        if not isinstance(spec, dict):
            skip("malformed-technology", 1, f"{tech}: fingerprint is not an object")
            continue
        for key, value in spec.items():
            if key in LIST_CHANNELS:
                for raw in _as_list(value):
                    add(lambda t=tech, k=key, r=raw: value_rule(t, k, r))
            elif key in ("headers", "cookies"):
                if not isinstance(value, dict):
                    skip(f"{key}:malformed", _pattern_count(value), f"{tech}: {key} not a dict")
                    continue
                for name_raw, val_raw in value.items():
                    add(lambda t=tech, k=key, n=name_raw, v=val_raw: header_cookie_rule(t, k, n, v))
            elif key == "meta":
                if not isinstance(value, dict):
                    skip("meta:malformed", _pattern_count(value), f"{tech}: meta not a dict")
                    continue
                for meta_name, patterns in value.items():
                    for raw in _as_list(patterns):
                        add(
                            lambda t=tech, r=raw, n=meta_name: value_rule(
                                t, "meta", r, meta_name=n.strip().lower()
                            )
                        )
            elif key == "js":
                if not enable_js:
                    skip("js", _pattern_count(value), f"{tech}: js channel disabled")
                    continue
                if not isinstance(value, dict):
                    skip("js:malformed", _pattern_count(value), f"{tech}: js not a dict")
                    continue
                for global_path, raw in value.items():
                    add(lambda t=tech, g=global_path, r=raw: js_rule(t, g, r))
            elif key == "dns":
                if not isinstance(value, dict):
                    skip("dns:malformed", _pattern_count(value), f"{tech}: dns not a dict")
                    continue
                for record_type, patterns in value.items():
                    rtype = record_type.strip().upper()
                    if rtype not in SUPPORTED_DNS_TYPES:
                        skip(
                            f"dns:{rtype}",
                            len(_as_list(patterns)),
                            f"{tech}: unsupported DNS record type {record_type!r}",
                        )
                        continue
                    for raw in _as_list(patterns):
                        add(lambda t=tech, r=raw, rt=rtype: value_rule(t, "dns", r, dns_type=rt))
            elif key in METADATA_KEYS:
                continue
            else:
                # Unsupported pattern channel (js, dom, xhr, url, text, css, ...).
                skip(key, _pattern_count(value), f"{tech}: unsupported channel {key!r}")

    logger.debug(
        "loaded %d rules for %d technologies from %s",
        len(rules),
        len({r.technology for r in rules}),
        path,
    )
    return FingerprintSet(rules, skipped)
