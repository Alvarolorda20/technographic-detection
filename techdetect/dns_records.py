"""DNS record collection (MX, TXT, CNAME) via dnspython's async resolver.

MX and TXT are queried on the normalized input host. CNAME is additionally
queried on any extra hosts the caller passes (www variant, final redirected
host) because a CNAME rarely exists at the host that serves MX/TXT.
All queries run concurrently with a short per-query lifetime; every DNS
failure (NXDOMAIN, NoAnswer, timeout, SERVFAIL, ...) yields an empty list.
"""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception

logger = logging.getLogger(__name__)

DEFAULT_LIFETIME = 3.0


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


async def _query(resolver, host: str, rtype: str, lifetime: float) -> list[str]:
    try:
        answer = await resolver.resolve(host, rtype, lifetime=lifetime)
    except dns.exception.DNSException as exc:
        logger.debug("DNS %s %s -> %s", rtype, host, exc.__class__.__name__)
        return []
    return [_rdata_text(rtype, rdata) for rdata in answer]


async def collect_dns(
    host: str,
    resolver=None,
    cname_hosts: tuple[str, ...] = (),
    lifetime: float = DEFAULT_LIFETIME,
) -> dict[str, list[str]]:
    """Return {"MX": [...], "TXT": [...], "CNAME": [...]} for the host."""
    resolver = resolver or dns.asyncresolver.Resolver()
    cname_targets = list(dict.fromkeys((host, *cname_hosts)))
    plan = [("MX", host), ("TXT", host)] + [("CNAME", target) for target in cname_targets]
    answers = await asyncio.gather(
        *(_query(resolver, query_host, rtype, lifetime) for rtype, query_host in plan)
    )
    records: dict[str, list[str]] = {"MX": [], "TXT": [], "CNAME": []}
    for (rtype, _), values in zip(plan, answers, strict=True):
        records[rtype].extend(values)
    return records


async def collect_cname(host: str, resolver=None, lifetime: float = DEFAULT_LIFETIME) -> list[str]:
    """One extra CNAME lookup (used for the final redirected host)."""
    resolver = resolver or dns.asyncresolver.Resolver()
    return await _query(resolver, host, "CNAME", lifetime)
