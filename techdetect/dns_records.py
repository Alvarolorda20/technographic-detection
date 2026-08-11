"""DNS record collection (MX, TXT, CNAME) via dnspython's async resolver.

MX and TXT are queried on the normalized input host. CNAME is additionally
queried on any extra hosts the caller passes (www variant, final redirected
host) because a CNAME rarely exists at the host that serves MX/TXT.

Reliability matters here as much as correctness: a lookup that times out and a
name that genuinely has no such record are *different* answers, and collapsing
both to an empty list turns a failed measurement into a silent false negative.
``DnsClient`` therefore separates the two — ``NXDOMAIN``/``NoAnswer`` settle the
question, anything else is a failure that is retried and, if it still fails,
reported in ``DnsRecords.failures``.

One ``DnsClient`` is shared by a whole scan so its resolver cache is reused
across domains, and its semaphore bounds how many queries are in flight: 20
domains x 4 lookups fired at once overruns the local resolver and produces
exactly the timeouts described above.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)

RECORD_TYPES = ("MX", "TXT", "CNAME")
# Per query, and a second attempt clears the lost UDP packet this retries.
DEFAULT_LIFETIME = 5.0
DEFAULT_ATTEMPTS = 2
DEFAULT_MAX_CONCURRENT = 12

# These settle the question: the resolver was reached and there is no such
# record. Everything else (timeout, SERVFAIL, no reachable nameserver) is a
# failed measurement worth retrying.
DEFINITIVE_ANSWERS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)


@dataclass
class DnsRecords:
    """Records for one host, plus any lookup that never produced an answer."""

    records: dict[str, list[str]] = field(default_factory=lambda: {t: [] for t in RECORD_TYPES})
    failures: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True when every lookup produced an answer (possibly an empty one)."""
        return not self.failures


def _rdata_text(rtype: str, rdata: object) -> str:
    if rtype == "MX":
        return str(rdata.exchange).lower()
    if rtype == "TXT":
        # TXT rdata arrives as byte chunks split at 255 bytes; join before use
        # so a pattern can never be broken across a chunk boundary.
        return b"".join(rdata.strings).decode("utf-8", "replace").lower()
    if rtype == "CNAME":
        return str(rdata.target).lower()
    return str(rdata).lower()


def _make_resolver() -> dns.asyncresolver.Resolver:
    """A resolver with a cache, so repeated lookups within a scan are cheap."""
    resolver = dns.asyncresolver.Resolver()
    resolver.cache = dns.resolver.Cache()
    return resolver


class DnsClient:
    """Shared resolver, cache and concurrency limit for one scan."""

    def __init__(
        self,
        resolver=None,
        lifetime: float = DEFAULT_LIFETIME,
        attempts: int = DEFAULT_ATTEMPTS,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    ) -> None:
        self.resolver = resolver if resolver is not None else _make_resolver()
        self.lifetime = lifetime
        self.attempts = max(1, attempts)
        self._semaphore = asyncio.Semaphore(max_concurrent) if max_concurrent > 0 else None

    async def _resolve(self, host: str, rtype: str):
        if self._semaphore is None:
            return await self.resolver.resolve(host, rtype, lifetime=self.lifetime)
        async with self._semaphore:
            return await self.resolver.resolve(host, rtype, lifetime=self.lifetime)

    async def query(self, host: str, rtype: str) -> tuple[list[str], str | None]:
        """Return (values, failure). A definitive "no record" is ([], None)."""
        failure = "no attempt made"
        for attempt in range(1, self.attempts + 1):
            try:
                answer = await self._resolve(host, rtype)
            except DEFINITIVE_ANSWERS as exc:
                logger.debug("DNS %s %s -> %s (no record)", rtype, host, exc.__class__.__name__)
                return [], None
            except dns.exception.DNSException as exc:
                failure = exc.__class__.__name__
                logger.debug(
                    "DNS %s %s -> %s (attempt %d/%d)", rtype, host, failure, attempt, self.attempts
                )
            else:
                return [_rdata_text(rtype, rdata) for rdata in answer], None
        return [], f"{rtype} {host}: {failure}"

    async def collect(self, host: str, cname_hosts: tuple[str, ...] = ()) -> DnsRecords:
        """MX and TXT on ``host``, CNAME on ``host`` plus every extra host."""
        cname_targets = list(dict.fromkeys((host, *cname_hosts)))
        plan = [("MX", host), ("TXT", host)] + [("CNAME", target) for target in cname_targets]
        answers = await asyncio.gather(*(self.query(q_host, rtype) for rtype, q_host in plan))

        collected = DnsRecords()
        for (rtype, _), (values, failure) in zip(plan, answers, strict=True):
            collected.records[rtype].extend(values)
            if failure:
                collected.failures.append(failure)
        return collected

    async def collect_cname(self, host: str) -> DnsRecords:
        """One extra CNAME lookup (used for the final redirected host)."""
        values, failure = await self.query(host, "CNAME")
        collected = DnsRecords()
        collected.records["CNAME"].extend(values)
        if failure:
            collected.failures.append(failure)
        return collected
