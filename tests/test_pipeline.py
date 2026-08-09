"""Offline end-to-end pipeline and CLI tests (MockTransport + fake resolver)."""

import json
from pathlib import Path

import httpx
import pytest
from conftest import FakeResolver, cname, mx, txt

from techdetect import cli, scanner
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
    assert ("app.moved.test", "CNAME", 3.0) in resolver.queries
    assert report.technologies == ["Salesforce"]


@pytest.fixture
def offline_cli(monkeypatch):
    """Route the CLI's network edges through the offline fakes."""
    fake_resolver = FakeResolver({("wp.test", "MX"): [mx("aspmx.l.google.com.")]})

    async def fake_collect_dns(host, resolver=None, cname_hosts=(), lifetime=3.0):
        from techdetect.dns_records import collect_dns

        return await collect_dns(host, resolver=fake_resolver, cname_hosts=cname_hosts)

    async def fake_collect_cname(host, resolver=None, lifetime=3.0):
        return []

    monkeypatch.setattr(scanner, "make_client", lambda timeout=8.0: make_test_client())
    monkeypatch.setattr(scanner, "collect_dns", fake_collect_dns)
    monkeypatch.setattr(scanner, "collect_cname", fake_collect_cname)
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


def test_cli_missing_domains_file_is_fatal(tmp_path):
    assert cli.main([str(tmp_path / "nope.txt")]) == 1


def test_cli_empty_domains_file_is_fatal(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# only comments\n", encoding="utf-8")
    assert cli.main([str(empty)]) == 1


def test_cli_unparseable_fingerprints_is_fatal(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("example.com\n", encoding="utf-8")
    assert cli.main([str(domains_file), "--fingerprints", str(bad)]) == 1
