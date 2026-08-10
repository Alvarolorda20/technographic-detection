"""Fingerprint loader and matcher tests.

`tests/fixtures/technologies_real_excerpt.json` is a verbatim excerpt of the
open-source webappanalyzer technology database (MIT-licensed Wappalyzer fork),
vendored so the loader is validated against genuine fingerprint data — real
`cats`/`implies`/`js`/`dom` keys, version and confidence tags, and a genuine
`scripts` entry — not only custom JSON shaped like it.
"""

import json
from pathlib import Path

import pytest

from techdetect.engine import DEFAULT_FINGERPRINTS_PATH, FingerprintError, load_fingerprints
from techdetect.extract import SignalSet

BUNDLED = DEFAULT_FINGERPRINTS_PATH  # shipped as package data, not a repo-root file
REAL_EXCERPT = Path(__file__).resolve().parent / "fixtures" / "technologies_real_excerpt.json"


def load_from(tmp_path, data, strict=False):
    path = tmp_path / "fingerprints.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return load_fingerprints(path, strict=strict)


def test_bundled_set_is_strictly_valid():
    fps = load_fingerprints(BUNDLED, strict=True)
    assert fps.pattern_count == 24
    assert fps.technology_count == 16
    assert not fps.skipped


def test_bundled_set_loads_as_package_data():
    """The default set resolves through importlib.resources, so an installed
    wheel works without the repository checkout."""
    assert DEFAULT_FINGERPRINTS_PATH.is_file()
    assert json.loads(DEFAULT_FINGERPRINTS_PATH.read_text(encoding="utf-8"))


def test_load_accepts_a_plain_string_path(tmp_path):
    path = tmp_path / "fp.json"
    path.write_text(json.dumps({"T": {"html": "foo"}}), encoding="utf-8")
    assert load_fingerprints(str(path)).pattern_count == 1


def test_confidence_and_version_tags_parsed(tmp_path):
    fps = load_from(tmp_path, {"T": {"html": "foo\\;confidence:50\\;version:\\1"}})
    (rule,) = fps.rules
    assert rule.confidence == 50
    assert rule.value_regex.pattern == "foo"


def test_invalid_regex_skipped_leniently_but_fatal_in_strict(tmp_path):
    data = {"T": {"scriptSrc": ["good", "bad("]}}
    fps = load_from(tmp_path, data)
    assert fps.pattern_count == 1  # sibling pattern survives
    assert fps.skipped["scriptSrc:invalid-regex"] == 1
    with pytest.raises(FingerprintError):
        load_from(tmp_path, data, strict=True)


def test_header_names_use_fullmatch(tmp_path):
    fps = load_from(tmp_path, {"CF": {"headers": {"cf-ray": ""}}})
    hit, _ = fps.match(SignalSet(headers=[("cf-ray", "8f2-EWR")]))
    assert hit == ["CF"]
    miss, _ = fps.match(SignalSet(headers=[("cf-ray-id", "8f2")]))
    assert miss == []


def test_header_name_regex_family(tmp_path):
    fps = load_from(tmp_path, {"Stripe": {"headers": {"X-Stripe-.*": ""}}})
    hit, evidence = fps.match(SignalSet(headers=[("x-stripe-should-retry", "false")]))
    assert hit == ["Stripe"]
    assert evidence[0].channel == "headers"


def test_cookie_names_use_search(tmp_path):
    fps = load_from(tmp_path, {"Intercom": {"cookies": {"^intercom-": ""}}})
    hit, _ = fps.match(SignalSet(cookies=[("intercom-id-abc123", "v")]))
    assert hit == ["Intercom"]
    miss, _ = fps.match(SignalSet(cookies=[("xintercom-id", "v")]))
    assert miss == []


def test_script_key_routing(tmp_path):
    data = {
        "SrcOnly": {"scriptSrc": "cdn\\.example\\.com"},
        "InlineOnly": {"scripts": "gtag\\("},
        "Both": {"script": "example"},
    }
    fps = load_from(tmp_path, data)
    srcs = SignalSet(script_srcs=["https://cdn.example.com/a.js"])
    inline = SignalSet(inline_scripts=["gtag('config', 'G-1')"])
    assert fps.match(srcs)[0] == ["Both", "SrcOnly"]
    assert fps.match(inline)[0] == ["InlineOnly"]
    assert fps.match(SignalSet(inline_scripts=["var x = 'example'"]))[0] == ["Both"]


def test_confidence_accumulates_across_distinct_rules(tmp_path):
    data = {"T": {"html": ["alpha\\;confidence:50", "beta\\;confidence:50"]}}
    fps = load_from(tmp_path, data)
    assert fps.match(SignalSet(html="only alpha here"))[0] == []
    assert fps.match(SignalSet(html="alpha and beta"))[0] == ["T"]


def test_one_rule_matching_many_signals_counts_once(tmp_path):
    data = {"T": {"scriptSrc": "widget\\.example\\;confidence:50"}}
    fps = load_from(tmp_path, data)
    signals = SignalSet(script_srcs=["widget.example/a.js", "widget.example/b.js"])
    detected, evidence = fps.match(signals)
    assert detected == []  # 50 < 100 even though two signals match the rule
    assert len(evidence) == 1


def test_min_confidence_threshold_is_configurable(tmp_path):
    fps = load_from(tmp_path, {"T": {"html": "alpha\\;confidence:50"}})
    signals = SignalSet(html="alpha")
    assert fps.match(signals, min_confidence=100)[0] == []
    assert fps.match(signals, min_confidence=50)[0] == ["T"]


def test_presence_only_pattern_matches_any_value(tmp_path):
    fps = load_from(tmp_path, {"Shopify": {"headers": {"X-ShopId": ""}}})
    assert fps.match(SignalSet(headers=[("x-shopid", "12345")]))[0] == ["Shopify"]


def test_string_and_list_pattern_forms_are_equivalent(tmp_path):
    as_string = load_from(tmp_path, {"T": {"html": "foo"}})
    as_list = load_from(tmp_path, {"T": {"html": ["foo"]}})
    assert as_string.pattern_count == as_list.pattern_count == 1


def test_metadata_keys_are_ignored_without_skip_counts(tmp_path):
    data = {"T": {"cats": [1], "implies": "Other", "website": "https://x", "html": "foo"}}
    fps = load_from(tmp_path, data)
    assert fps.pattern_count == 1
    assert not fps.skipped


def test_dns_channel_and_unsupported_record_types(tmp_path):
    data = {"T": {"dns": {"MX": "google\\.com", "SOA": "\\.cloudflare\\.com"}}}
    fps = load_from(tmp_path, data)
    assert fps.pattern_count == 1
    assert fps.skipped["dns:SOA"] == 1
    hit, _ = fps.match(SignalSet(dns={"MX": ["aspmx.l.google.com."]}))
    assert hit == ["T"]


def test_evidence_is_sanitized_and_truncated(tmp_path):
    fps = load_from(tmp_path, {"WP": {"html": "/wp-content/"}})
    page = "x" * 5000 + '<link href="/wp-content/themes/a.css">' + "y" * 5000
    detected, evidence = fps.match(SignalSet(html=page))
    assert detected == ["WP"]
    record = evidence[0]
    assert "/wp-content/" in record.matched_signal
    assert len(record.matched_signal) < 200  # never the whole document


def test_inline_match_inside_escaped_html_is_not_usage(tmp_path):
    """A docs code sample serialized into an executable script (e.g. a Next.js
    RSC payload with an escaped <script> tag) is a mention, not usage."""
    fps = load_from(tmp_path, {"Sentry": {"script": "browser\\.sentry-cdn\\.com"}})
    docs_blob = (
        'const install = [{"md": "```html\\n\\u003cscript src=\\"'
        'https://browser.sentry-cdn.com/7/bundle.min.js\\">\\u003c/script>\\n```"}];'
    )
    assert fps.match(SignalSet(inline_scripts=[docs_blob]))[0] == []

    escaped_entity = 'render("&lt;script src=https://browser.sentry-cdn.com/7/b.js&gt;")'
    assert fps.match(SignalSet(inline_scripts=[escaped_entity]))[0] == []


def test_inline_dynamic_loader_still_counts_as_usage(tmp_path):
    fps = load_from(tmp_path, {"Sentry": {"script": "browser\\.sentry-cdn\\.com"}})
    loader = "loadScript('https://browser.sentry-cdn.com/7/bundle.min.js');"
    assert fps.match(SignalSet(inline_scripts=[loader]))[0] == ["Sentry"]
    # document.write with a RAW tag is a classic genuine loader pattern.
    writer = "document.write('<script src=\"https://browser.sentry-cdn.com/7/b.js\">');"
    assert fps.match(SignalSet(inline_scripts=[writer]))[0] == ["Sentry"]
    # A later genuine reference is found even when an earlier one is escaped data.
    both = (
        'help("\\u003cscript src=\\"https://browser.sentry-cdn.com/x\\"");'
        " loadScript('https://browser.sentry-cdn.com/7/bundle.min.js');"
    )
    assert fps.match(SignalSet(inline_scripts=[both]))[0] == ["Sentry"]


def test_js_channel_is_skipped_unless_enabled(tmp_path):
    data = {"Intercom": {"js": {"Intercom.booted": ""}}}
    fps = load_from(tmp_path, data)
    assert fps.pattern_count == 0
    assert fps.skipped["js"] == 1


def test_js_channel_matches_global_path_in_inline_scripts(tmp_path):
    path = tmp_path / "fp.json"
    path.write_text(json.dumps({"Intercom": {"js": {"Intercom.booted": ""}}}), encoding="utf-8")
    fps = load_fingerprints(path, enable_js=True)
    (rule,) = fps.rules
    assert rule.channel == "js" and rule.js_path == "Intercom.booted"

    hit, evidence = fps.match(SignalSet(inline_scripts=["window.Intercom.booted = true;"]))
    assert hit == ["Intercom"]
    assert evidence[0].channel == "js"
    # The path is literal, not a regex: the '.' must not match any character.
    assert fps.match(SignalSet(inline_scripts=["IntercomXbooted"]))[0] == []
    # Page prose is not source: only executable inline scripts feed this channel.
    assert fps.match(SignalSet(html="Intercom.booted"))[0] == []


def test_js_channel_honors_confidence_tags_and_skips_serialized_html(tmp_path):
    path = tmp_path / "fp.json"
    path.write_text(
        json.dumps({"T": {"js": {"Foo.bar": "\\;confidence:50\\;version:\\1"}}}), encoding="utf-8"
    )
    fps = load_fingerprints(path, enable_js=True)
    assert fps.rules[0].confidence == 50
    docs = 'const s = "\\u003cscript>Foo.bar\\u003c/script>";'
    assert fps.match(SignalSet(inline_scripts=[docs]), min_confidence=50)[0] == []
    assert fps.match(SignalSet(inline_scripts=["Foo.bar()"]), min_confidence=50)[0] == ["T"]


def test_real_wappalyzer_excerpt_compiles_js_when_enabled():
    """The genuine database's js entries load unchanged once enabled — the
    channel is off by policy, not because the format is unsupported."""
    off = load_fingerprints(REAL_EXCERPT)
    on = load_fingerprints(REAL_EXCERPT, enable_js=True)
    assert on.pattern_count == off.pattern_count + off.skipped["js"]
    assert not on.skipped["js"]
    assert any(rule.channel == "js" for rule in on.rules)


def test_real_wappalyzer_excerpt_loads_and_reports_skips():
    fps = load_fingerprints(REAL_EXCERPT)  # lenient, like any external DB
    assert fps.pattern_count > 20
    # Genuine `scripts` (inline JS) rules made it in.
    assert any(rule.channel == "scripts" for rule in fps.rules)
    # Version/confidence tags parsed off genuine patterns.
    assert any(rule.confidence == 50 for rule in fps.rules)
    assert any("version:" in rule.raw_pattern for rule in fps.rules)
    # Unsupported channels were skipped and counted, not fatal.
    assert fps.skipped["js"] > 0
    assert fps.skipped["dom"] > 0
    assert fps.skipped["dns:NS"] == 1 and fps.skipped["dns:SOA"] == 1
    assert "skipped" in fps.skipped_summary()


def test_real_excerpt_detects_from_matching_signals():
    fps = load_fingerprints(REAL_EXCERPT)
    signals = SignalSet(
        script_srcs=["https://code.jquery.com/jquery-3.7.1.min.js"],
        metas={"generator": ["WordPress 6.4"]},
    )
    detected, _ = fps.match(signals)
    assert "jQuery" in detected
    assert "WordPress" in detected
