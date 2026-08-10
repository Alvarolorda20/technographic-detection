"""DNS collection tests with an injected fake resolver (no network)."""

import dns.resolver
import pytest
from conftest import FakeResolver, cname, mx, txt

from techdetect.dns_records import DnsClient


async def test_txt_chunks_are_joined_before_matching():
    resolver = FakeResolver(
        {("sendgrid.com", "TXT"): [txt(b"v=spf1 include:send", b"grid.net ~all")]}
    )
    result = await DnsClient(resolver=resolver).collect("sendgrid.com")
    assert result.records["TXT"] == ["v=spf1 include:sendgrid.net ~all"]


async def test_absent_records_are_a_complete_measurement():
    """NXDOMAIN and NoAnswer mean "no such record" — an answer, not a failure."""
    resolver = FakeResolver(
        {
            ("example.com", "MX"): dns.resolver.NoAnswer(),
            ("example.com", "TXT"): dns.resolver.NXDOMAIN(),
        }
    )
    result = await DnsClient(resolver=resolver).collect("example.com")
    assert result.records == {"MX": [], "TXT": [], "CNAME": []}
    assert result.complete and result.failures == []


async def test_timeouts_are_reported_not_silently_empty():
    """A timed-out lookup must be distinguishable from an absent record: the
    difference is a false negative versus a measurement."""
    resolver = FakeResolver({("example.com", "MX"): dns.resolver.LifetimeTimeout()})
    result = await DnsClient(resolver=resolver, attempts=1).collect("example.com")
    assert result.records["MX"] == []
    assert not result.complete
    assert result.failures == ["MX example.com: LifetimeTimeout"]


async def test_transient_failures_are_retried():
    class FlakyResolver(FakeResolver):
        """Times out once, then answers — the pattern seen under load."""

        async def resolve(self, host, rtype, lifetime=None):
            self.queries.append((host, rtype, lifetime))
            if rtype == "MX" and len([q for q in self.queries if q[1] == "MX"]) == 1:
                raise dns.resolver.LifetimeTimeout()
            return self.table.get((host, rtype), [])

    resolver = FlakyResolver({("example.com", "MX"): [mx("aspmx.l.google.com.")]})
    result = await DnsClient(resolver=resolver, attempts=2).collect("example.com")
    assert result.records["MX"] == ["aspmx.l.google.com."]
    assert result.complete


async def test_definitive_answers_are_not_retried():
    resolver = FakeResolver({("example.com", "MX"): dns.resolver.NXDOMAIN()})
    await DnsClient(resolver=resolver, attempts=3).collect("example.com")
    assert len([q for q in resolver.queries if q[1] == "MX"]) == 1


async def test_cname_queried_on_extra_hosts_and_merged():
    resolver = FakeResolver(
        {
            ("example.com", "MX"): [mx("ASPMX.L.GOOGLE.COM.")],
            ("www.example.com", "CNAME"): [cname("sites.salesforce.com.")],
        }
    )
    client = DnsClient(resolver=resolver)
    result = await client.collect("example.com", cname_hosts=("www.example.com",))
    assert result.records["MX"] == ["aspmx.l.google.com."]  # lowercased
    assert result.records["CNAME"] == ["sites.salesforce.com."]
    cname_queries = {host for host, rtype, _ in resolver.queries if rtype == "CNAME"}
    assert cname_queries == {"example.com", "www.example.com"}


async def test_duplicate_cname_hosts_queried_once():
    resolver = FakeResolver({})
    await DnsClient(resolver=resolver, attempts=1).collect(
        "example.com", cname_hosts=("example.com",)
    )
    cname_queries = [q for q in resolver.queries if q[1] == "CNAME"]
    assert len(cname_queries) == 1


async def test_lifetime_is_passed_to_every_query():
    resolver = FakeResolver({})
    await DnsClient(resolver=resolver, lifetime=4.0).collect("example.com")
    assert resolver.queries and all(lifetime == 4.0 for _, _, lifetime in resolver.queries)


async def test_concurrency_limit_bounds_queries_in_flight():
    """Firing every lookup at once is what overran the resolver in the first
    place; the limit is part of the contract, not an implementation detail."""
    in_flight = 0
    peak = 0

    class CountingResolver(FakeResolver):
        async def resolve(self, host, rtype, lifetime=None):
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            try:
                return await super().resolve(host, rtype, lifetime=lifetime)
            finally:
                in_flight -= 1

    resolver = CountingResolver({})
    client = DnsClient(resolver=resolver, attempts=1, max_concurrent=2)
    await client.collect("example.com", cname_hosts=("www.example.com", "app.example.com"))
    assert peak <= 2


async def test_collect_cname_single_lookup():
    resolver = FakeResolver({("app.example.com", "CNAME"): [cname("x.cloudfront.net.")]})
    result = await DnsClient(resolver=resolver).collect_cname("app.example.com")
    assert result.records["CNAME"] == ["x.cloudfront.net."]


async def test_unexpected_non_dns_error_propagates():
    class Boom(FakeResolver):
        async def resolve(self, host, rtype, lifetime=None):
            raise RuntimeError("bug, not a DNS failure")

    with pytest.raises(RuntimeError):
        await DnsClient(resolver=Boom({})).collect("example.com")
