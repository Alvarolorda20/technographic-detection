"""Scan orchestration: input normalization, concurrency, per-domain signal assembly."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field

import httpx

from techdetect.dns_records import DnsClient, DnsRecords
from techdetect.engine import DEFAULT_CONFIDENCE, FingerprintSet, MatchEvidence
from techdetect.extract import SignalSet, extract_page_signals
from techdetect.fetcher import BODY_CAP_BYTES, FetchResult, fetch_homepage, make_client

logger = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 10
# Hard cap over the whole ladder, so it also defuses a body that trickles in.
DOMAIN_DEADLINE = 20.0
# Concurrent with the fetch, not additive; covers one query's lifetime x attempts.
DNS_DEADLINE = 15.0
# One extra CNAME lookup on the redirected host, so one query's retries is enough.
EXTRA_CNAME_DEADLINE = 8.0


def normalize_domain(line: str) -> str | None:
    """``' https://WWW.Example.com/path '`` -> ``'example.com'``; None for blanks/comments."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    text = text.lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].rstrip(".")
    if text.startswith("www."):
        text = text[4:]
    return text or None


def read_domains(lines: Iterable[str]) -> list[str]:
    """Normalize and de-duplicate, preserving first-seen order."""
    return list(dict.fromkeys(host for line in lines if (host := normalize_domain(line))))


@dataclass
class DomainReport:
    domain: str
    technologies: list[str] = field(default_factory=list)
    evidence: list[MatchEvidence] = field(default_factory=list)
    status: int | None = None
    blocked: bool = False
    block_reason: str | None = None
    error: str | None = None
    elapsed: float = 0.0
    # Partial-measurement flags: the scan produced an answer, but not from all
    # the evidence it meant to read. Both make a missing technology ambiguous,
    # so neither may stay silent.
    dns_failures: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def complete(self) -> bool:
        """True when every channel this domain has was read in full."""
        return not self.dns_failures and not self.truncated


async def _fetch_bounded(client: httpx.AsyncClient, host: str) -> FetchResult:
    try:
        async with asyncio.timeout(DOMAIN_DEADLINE):
            return await fetch_homepage(client, host)
    except TimeoutError:
        return FetchResult(domain=host, error=f"fetch exceeded {DOMAIN_DEADLINE:.0f}s deadline")


async def _dns_bounded(host: str, dns_client: DnsClient) -> DnsRecords:
    try:
        async with asyncio.timeout(DNS_DEADLINE):
            return await dns_client.collect(host, cname_hosts=(f"www.{host}",))
    except TimeoutError:
        return DnsRecords(failures=[f"all records {host}: collection exceeded {DNS_DEADLINE:.0f}s"])


async def scan_domain(
    client: httpx.AsyncClient,
    host: str,
    fingerprints: FingerprintSet,
    dns_client: DnsClient | None = None,
    min_confidence: int = DEFAULT_CONFIDENCE,
) -> DomainReport:
    """Scan one domain. Never raises: any unexpected error becomes report.error."""
    started = time.perf_counter()
    dns_client = dns_client or DnsClient()
    try:
        fetch_result, dns_records = await asyncio.gather(
            _fetch_bounded(client, host), _dns_bounded(host, dns_client)
        )

        signals = SignalSet(dns=dns_records.records)
        if fetch_result.responded:
            # Headers, cookies and DNS are trustworthy even on blocked/error
            # responses; page-derived channels only when the body is the
            # site's own homepage.
            signals.headers = fetch_result.headers
            signals.cookies = fetch_result.cookies
            if fetch_result.page_trusted:
                page = extract_page_signals(fetch_result.body)
                signals.script_srcs = page.script_srcs
                signals.inline_scripts = page.inline_scripts
                signals.metas = page.metas
                signals.html = fetch_result.body

        final_host = fetch_result.final_host
        if final_host and final_host not in (host, f"www.{host}"):
            try:
                async with asyncio.timeout(EXTRA_CNAME_DEADLINE):
                    extra = await dns_client.collect_cname(final_host)
            except TimeoutError:
                extra = DnsRecords(failures=[f"CNAME {final_host}: exceeded deadline"])
            merged = signals.dns.get("CNAME", []) + extra.records["CNAME"]
            signals.dns["CNAME"] = list(dict.fromkeys(merged))
            dns_records.failures.extend(extra.failures)

        technologies, evidence = fingerprints.match(signals, min_confidence=min_confidence)
        for record in evidence:
            logger.debug(
                "%s: %s via %s (%r matched %r)",
                host,
                record.technology,
                record.channel,
                record.pattern,
                record.matched_signal,
            )
        return DomainReport(
            domain=host,
            technologies=technologies,
            evidence=evidence,
            status=fetch_result.status,
            blocked=fetch_result.blocked,
            block_reason=fetch_result.block_reason,
            error=fetch_result.error,
            elapsed=time.perf_counter() - started,
            dns_failures=dns_records.failures,
            truncated=fetch_result.truncated,
        )
    except Exception as exc:  # the never-crash contract: isolate per-domain bugs
        logger.error("%s: unexpected error: %s: %s", host, exc.__class__.__name__, exc)
        return DomainReport(
            domain=host,
            error=f"{exc.__class__.__name__}: {exc}",
            elapsed=time.perf_counter() - started,
        )


async def scan_all(
    domains: list[str],
    fingerprints: FingerprintSet,
    concurrency: int = DEFAULT_CONCURRENCY,
    timeout: float = 8.0,
    min_confidence: int = DEFAULT_CONFIDENCE,
    client: httpx.AsyncClient | None = None,
    resolver=None,
) -> list[DomainReport]:
    """Scan all domains concurrently; results keep input order.

    One ``DnsClient`` is built here and shared by every domain, so its cache and
    its concurrency limit apply to the scan as a whole rather than per domain.
    """
    semaphore = asyncio.Semaphore(concurrency)
    dns_client = DnsClient(resolver=resolver)
    own_client = client is None
    if client is None:
        client = make_client(timeout)

    async def run(host: str) -> DomainReport:
        async with semaphore:
            report = await scan_domain(
                client, host, fingerprints, dns_client=dns_client, min_confidence=min_confidence
            )
        state = f"HTTP {report.status}" if report.status else "no response"
        if report.blocked:
            state += f", soft block: {report.block_reason} — page channels skipped"
        logger.info(
            "%s: %d technologie(s) [%s, %.1fs]",
            host,
            len(report.technologies),
            state,
            report.elapsed,
        )
        # A partial read can only hide a technology, never invent one, so it is
        # a warning rather than an error — but it must be visible by default.
        if report.dns_failures:
            logger.warning(
                "%s: %d DNS lookup(s) produced no answer (%s) — a missing DNS-based "
                "technology is unconfirmed here, not absent",
                host,
                len(report.dns_failures),
                "; ".join(report.dns_failures),
            )
        if report.truncated:
            logger.warning(
                "%s: response body hit the %d byte cap — page signals past the cap were not read",
                host,
                BODY_CAP_BYTES,
            )
        return report

    try:
        return list(await asyncio.gather(*(run(host) for host in domains)))
    finally:
        if own_client:
            await client.aclose()
