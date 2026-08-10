"""HTML signal extraction tests, including the assignment's core accuracy case:
a page that merely *mentions* vendor URLs must produce no script signals."""

from pathlib import Path

from techdetect.engine import DEFAULT_FINGERPRINTS_PATH, load_fingerprints
from techdetect.extract import SignalSet, extract_page_signals

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_script_src_collection():
    page = extract_page_signals(
        '<script src="https://cdn.example.com/a.js"></script>'
        "<script src='/local/b.js' defer></script>"
    )
    assert page.script_srcs == ["https://cdn.example.com/a.js", "/local/b.js"]


def test_inline_scripts_executable_types_only():
    html = """
    <script>var a = 1;</script>
    <script type="text/javascript">var b = 2;</script>
    <script type="module">import x from 'y';</script>
    <script type="application/json">{"mention": "js.stripe.com/v3"}</script>
    <script type="application/ld+json">{"mention": "gtag("}</script>
    <script type="text/template"><div>gtag(</div></script>
    """
    page = extract_page_signals(html)
    assert page.inline_scripts == ["var a = 1;", "var b = 2;", "import x from 'y';"]


def test_script_with_src_does_not_collect_body():
    page = extract_page_signals('<script src="/a.js">var ignored = true;</script>')
    assert page.script_srcs == ["/a.js"]
    assert page.inline_scripts == []


def test_meta_name_and_property_lowercased():
    html = """
    <meta name="Generator" content="WordPress 6.4">
    <meta property="og:site_name" content="Example">
    <meta name="empty-content" content="">
    <meta name="no-content-attr">
    """
    page = extract_page_signals(html)
    assert page.metas == {
        "generator": ["WordPress 6.4"],
        "og:site_name": ["Example"],
        "empty-content": [""],
    }


def test_malformed_html_never_raises():
    for garbage in [
        '<script src="/a.js"',
        "<<<>><script><meta name=x",
        "<script>unterminated",
        "\x00\x01<html><script src=",
    ]:
        extract_page_signals(garbage)  # must not raise


def test_adversarial_page_yields_no_script_src_signals():
    page = extract_page_signals(read_fixture("adversarial.html"))
    assert page.script_srcs == []
    # Only the RSC-style executable payload survives extraction; the JSON and
    # ld+json data blobs are excluded. Matching-time guards handle the rest.
    assert len(page.inline_scripts) == 1
    assert "__docs_f" in page.inline_scripts[0]


def test_adversarial_page_detects_nothing_with_bundled_fingerprints():
    """The assignment's core challenge: mentions in prose, <pre> blocks and
    JSON data blobs must not be treated as evidence of use."""
    html = read_fixture("adversarial.html")
    page = extract_page_signals(html)
    signals = SignalSet(
        script_srcs=page.script_srcs,
        inline_scripts=page.inline_scripts,
        html=html,
        metas=page.metas,
    )
    fps = load_fingerprints(DEFAULT_FINGERPRINTS_PATH, strict=True)
    detected, evidence = fps.match(signals)
    assert detected == []
    assert evidence == []


def test_genuine_stripe_page_is_detected():
    html = read_fixture("stripe_genuine.html")
    page = extract_page_signals(html)
    signals = SignalSet(
        script_srcs=page.script_srcs,
        inline_scripts=page.inline_scripts,
        html=html,
        metas=page.metas,
    )
    fps = load_fingerprints(DEFAULT_FINGERPRINTS_PATH, strict=True)
    detected, _ = fps.match(signals)
    assert "Stripe" in detected
    assert "Google Analytics 4" in detected  # inline gtag( via the `script` alias


def test_wordpress_page_detected_via_raw_html_channel():
    html = read_fixture("wordpress.html")
    page = extract_page_signals(html)
    signals = SignalSet(html=html, metas=page.metas)
    fps = load_fingerprints(DEFAULT_FINGERPRINTS_PATH, strict=True)
    detected, _ = fps.match(signals)
    assert detected == ["WordPress"]
