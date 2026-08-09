"""DNS collection tests with an injected fake resolver (no network)."""

import dns.resolver
import pytest
from conftest import FakeResolver, cname, mx, txt

from techdetect.dns_records import collect_cname, collect_dns


async def test_txt_chunks_are_joined_before_matching():
    resolver = FakeResolver(
        {("sendgrid.com", "TXT"): [txt(b"v=spf1 include:send", b"grid.net ~all")]}
    )
    records = await collect_dns("sendgrid.com", resolver=resolver)
    assert records["TXT"] == ["v=spf1 include:sendgrid.net ~all"]


async def test_all_failures_yield_empty_lists():
    resolver = FakeResolver(
        {
            ("example.com", "MX"): dns.resolver.NoAnswer(),
            ("example.com", "TXT"): dns.resolver.NXDOMAIN(),
            ("example.com", "CNAME"): dns.resolver.LifetimeTimeout(),
        }
    )
    records = await collect_dns("example.com", resolver=resolver)
    assert records == {"MX": [], "TXT": [], "CNAME": []}


async def test_cname_queried_on_extra_hosts_and_merged():
    resolver = FakeResolver(
        {
            ("example.com", "MX"): [mx("ASPMX.L.GOOGLE.COM.")],
            ("www.example.com", "CNAME"): [cname("sites.salesforce.com.")],
        }
    )
    records = await collect_dns("example.com", resolver=resolver, cname_hosts=("www.example.com",))
    assert records["MX"] == ["aspmx.l.google.com."]  # lowercased
    assert records["CNAME"] == ["sites.salesforce.com."]
    cname_queries = {host for host, rtype, _ in resolver.queries if rtype == "CNAME"}
    assert cname_queries == {"example.com", "www.example.com"}


async def test_duplicate_cname_hosts_queried_once():
    resolver = FakeResolver({})
    await collect_dns("example.com", resolver=resolver, cname_hosts=("example.com",))
    cname_queries = [q for q in resolver.queries if q[1] == "CNAME"]
    assert len(cname_queries) == 1


async def test_short_lifetime_is_passed_to_every_query():
    resolver = FakeResolver({})
    await collect_dns("example.com", resolver=resolver, lifetime=3.0)
    assert resolver.queries and all(lifetime == 3.0 for _, _, lifetime in resolver.queries)


async def test_collect_cname_single_lookup():
    resolver = FakeResolver({("app.example.com", "CNAME"): [cname("x.cloudfront.net.")]})
    assert await collect_cname("app.example.com", resolver=resolver) == ["x.cloudfront.net."]


async def test_unexpected_non_dns_error_propagates():
    class Boom(FakeResolver):
        async def resolve(self, host, rtype, lifetime=None):
            raise RuntimeError("bug, not a DNS failure")

    resolver = Boom({})
    with pytest.raises(RuntimeError):
        await collect_dns("example.com", resolver=resolver)
