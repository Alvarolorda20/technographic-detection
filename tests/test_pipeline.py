"""Offline end-to-end pipeline and CLI tests (MockTransport + fake resolver)."""

import json
from pathlib import Path

import dns.resolver
import httpx
import pytest
from conftest import FakeResolver, cname, mx, txt

from techdetect import cli, scanner
from techdetect.dns_records import DnsClient
from techdetect.engine import DEFAULT_FINGERPRINTS_PATH, load_fingerprints
from techdetect.scanner import normalize_domain, read_domains, scan_all

FIXTURES = Path(__file__).resolve().parent / "fixtures"
WORDPRESS_HTML = (FIXTURES / "wordpress.html").read_text(encoding="utf-8")


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host in ("wp.test", "www.wp.test"):
        return httpx.Response(200, html=WORDPRESS_HTML)
    if host in ("blocked.test", "www.blocked.test"):
        # Soft block whose body mentions /wp-content/: must NOT count as evidence.
        return httpx.Response(
            403,
            headers={"cf-ray": "8abc-EWR"},
            html='<html><link href="/wp-content/x.css">Forbidden</html>',
        )
    if host in ("jsapp.test", "www.jsapp.test"):
        return httpx.Response(200, html="<html><script>window.Intercom.booted;</script></html>")
    if host == "moved.test":
        return httpx.Response(301, headers={"location": "https://app.moved.test/"})
    if host == "app.moved.test":
        return httpx.Response(200, html="<html>ok</html>")
    raise httpx.ConnectError("refused")


def make_test_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


@pytest.fixture
def fingerprints():
    return load_fingerprints(DEFAULT_FINGERPRINTS_PATH, strict=True)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("example.com", "example.com"),
        ("  HTTPS://WWW.Example.COM/path?q=1  ", "example.com"),
        ("www.example.com.", "example.com"),
        ("example.com:8443", "example.com"),
        ("# comment", None),
        ("   ", None),
    ],
)
def test_normalize_domain(line, expected):
    assert normalize_domain(line) == expected


def test_read_domains_dedupes_preserving_order():
    lines = ["b.com", "# note", "a.com", "https://www.b.com/", "", "a.com"]
    assert read_domains(lines) == ["b.com", "a.com"]


async def test_scan_all_end_to_end(fingerprints):
    resolver = FakeResolver(
        {
            ("wp.test", "MX"): [mx("aspmx.l.google.com.")],
            ("blocked.test", "TXT"): [txt(b"v=spf1 include:sendgrid.net ~all")],
        }
    )
    async with make_test_client() as client:
        reports = await scan_all(
            ["wp.test", "blocked.test", "down.test"],
            fingerprints,
            client=client,
            resolver=resolver,
        )

    assert [r.domain for r in reports] == ["wp.test", "blocked.test", "down.test"]

    wp, blocked, down = reports
    assert wp.technologies == ["Google Workspace", "WordPress"]

    # Blocked domain: header + DNS evidence kept, page-derived evidence dropped.
    assert blocked.blocked and blocked.status == 403
    assert "Cloudflare" in blocked.technologies
    assert "SendGrid" in blocked.technologies
    assert "WordPress" not in blocked.technologies

    assert down.technologies == []
    assert down.error and "ConnectError" in down.error


async def test_redirect_to_new_host_triggers_extra_cname_lookup(fingerprints):
    resolver = FakeResolver({("app.moved.test", "CNAME"): [cname("x.salesforce.com.")]})
    async with make_test_client() as client:
        (report,) = await scan_all(["moved.test"], fingerprints, client=client, resolver=resolver)
    assert ("app.moved.test", "CNAME") in {(host, rtype) for host, rtype, _ in resolver.queries}
    assert report.technologies == ["Salesforce"]


async def test_dns_failure_marks_the_report_incomplete(fingerprints):
    """A domain whose MX lookup never answered is not a clean negative: the
    report must say so, because Google Workspace is neither found nor excluded."""
    resolver = FakeResolver({("wp.test", "MX"): dns.resolver.LifetimeTimeout()})
    async with make_test_client() as client:
        (report,) = await scan_all(["wp.test"], fingerprints, client=client, resolver=resolver)
    assert report.technologies == ["WordPress"]  # page evidence is unaffected
    assert "Google Workspace" not in report.technologies
    assert not report.complete
    assert report.dns_failures == ["MX wp.test: LifetimeTimeout"]


async def test_clean_scan_reports_complete(fingerprints):
    resolver = FakeResolver({("wp.test", "MX"): [mx("aspmx.l.google.com.")]})
    async with make_test_client() as client:
        (report,) = await scan_all(["wp.test"], fingerprints, client=client, resolver=resolver)
    assert report.complete and report.dns_failures == [] and not report.truncated


@pytest.fixture
def offline_cli(monkeypatch):
    """Route the CLI's network edges through the offline fakes."""
    fake_resolver = FakeResolver({("wp.test", "MX"): [mx("aspmx.l.google.com.")]})

    monkeypatch.setattr(scanner, "make_client", lambda timeout=8.0: make_test_client())
    monkeypatch.setattr(
        scanner,
        "DnsClient",
        lambda resolver=None, **kwargs: DnsClient(resolver=fake_resolver, attempts=1),
    )
    return fake_resolver


def test_cli_end_to_end(tmp_path, offline_cli):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text(
        "wp.test\n# a comment\nblocked.test\ndown.test\nWP.TEST\n", encoding="utf-8"
    )
    out = tmp_path / "output.json"
    evidence_path = tmp_path / "evidence.json"

    code = cli.main([str(domains_file), "-o", str(out), "--evidence", str(evidence_path), "-q"])
    assert code == 0

    results = json.loads(out.read_text(encoding="utf-8"))
    assert list(results) == ["wp.test", "blocked.test", "down.test"]  # input order, deduped
    assert all(isinstance(v, list) for v in results.values())
    assert results["wp.test"] == ["Google Workspace", "WordPress"]
    assert results["down.test"] == []

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert set(evidence) == set(results)
    record = evidence["wp.test"][0]
    assert set(record) == {"technology", "channel", "pattern", "matched_signal", "confidence"}
    assert all(len(r["matched_signal"]) < 200 for recs in evidence.values() for r in recs)


def test_cli_stdout_stays_clean_json(capsys, tmp_path, offline_cli):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("wp.test\n", encoding="utf-8")
    assert cli.main([str(domains_file)]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed == {"wp.test": ["Google Workspace", "WordPress"]}


def test_cli_unwritable_output_is_fatal(tmp_path, offline_cli):
    """An unwritable results path is a fatal error, not a traceback."""
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("wp.test\n", encoding="utf-8")
    out = tmp_path / "missing" / "output.json"  # parent directory does not exist
    assert cli.main([str(domains_file), "-o", str(out), "-q"]) == 1


def test_cli_unwritable_evidence_is_fatal(tmp_path, offline_cli):
    """Evidence failing to write is fatal too, but the results already landed."""
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("wp.test\n", encoding="utf-8")
    out = tmp_path / "output.json"
    evidence_path = tmp_path / "missing" / "evidence.json"
    code = cli.main([str(domains_file), "-o", str(out), "--evidence", str(evidence_path), "-q"])
    assert code == 1
    assert out.exists()


def test_cli_js_channel_is_opt_in_end_to_end(tmp_path, offline_cli):
    """Same page, same fingerprints: the js channel only fires when asked for."""
    fingerprints_file = tmp_path / "fp.json"
    fingerprints_file.write_text(
        json.dumps({"Intercom": {"js": {"Intercom.booted": ""}}}), encoding="utf-8"
    )
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("jsapp.test\n", encoding="utf-8")
    out = tmp_path / "output.json"
    base = [str(domains_file), "-o", str(out), "--fingerprints", str(fingerprints_file), "-q"]

    assert cli.main(base) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == {"jsapp.test": []}

    assert cli.main([*base, "--enable-js-channel"]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == {"jsapp.test": ["Intercom"]}


def test_cli_missing_domains_file_is_fatal(tmp_path):
    assert cli.main([str(tmp_path / "nope.txt")]) == 1


def test_cli_empty_domains_file_is_fatal(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# only comments\n", encoding="utf-8")
    assert cli.main([str(empty)]) == 1


@pytest.mark.parametrize(
    "bad_args",
    [
        ["--concurrency", "0"],
        ["--concurrency", "-1"],
        ["--concurrency", "abc"],
        ["--timeout", "0"],
        ["--timeout", "-1"],
        ["--timeout", "abc"],
        ["--min-confidence", "-1"],
        ["--min-confidence", "101"],
        ["--min-confidence", "abc"],
    ],
)
def test_cli_rejects_invalid_numeric_arguments(tmp_path, capsys, bad_args):
    """Invalid values fail as argparse usage errors (exit 2), never as an
    internal exception or a Semaphore(0) deadlock."""
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        cli.main([str(domains_file), *bad_args])
    assert exc.value.code == 2
    assert bad_args[0] in capsys.readouterr().err


@pytest.mark.parametrize("value", ["nan", "NaN", "inf", "-inf", "1e309", "Infinity"])
def test_cli_rejects_non_finite_timeouts(tmp_path, capsys, monkeypatch, value):
    """float() parses these, but none is a usable timeout; they must fail at
    parse time and never reach the scanner."""
    scanned = False

    async def fail_if_called(*args, **kwargs):
        nonlocal scanned
        scanned = True
        return []

    monkeypatch.setattr(cli, "scan_all", fail_if_called)
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        cli.main([str(domains_file), "--timeout", value])
    assert exc.value.code == 2
    assert "--timeout" in capsys.readouterr().err
    assert not scanned


@pytest.mark.parametrize("value", ["0", "100"])
def test_cli_accepts_min_confidence_boundaries(tmp_path, offline_cli, value):
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("wp.test\n", encoding="utf-8")
    out = tmp_path / "output.json"
    assert cli.main([str(domains_file), "-o", str(out), "--min-confidence", value, "-q"]) == 0
    assert "WordPress" in json.loads(out.read_text(encoding="utf-8"))["wp.test"]


def test_cli_unparseable_fingerprints_is_fatal(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")
    assert cli.main([str(domains_file), "--fingerprints", str(bad)]) == 1
