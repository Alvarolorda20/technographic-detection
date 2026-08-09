"""Shared offline test fakes."""

from types import SimpleNamespace

import dns.resolver


class FakeResolver:
    """Records queries; answers from a {(host, rtype): rdatas | exception} table."""

    def __init__(self, table):
        self.table = table
        self.queries = []

    async def resolve(self, host, rtype, lifetime=None):
        self.queries.append((host, rtype, lifetime))
        result = self.table.get((host, rtype), dns.resolver.NXDOMAIN())
        if isinstance(result, Exception):
            raise result
        return result


def mx(exchange):
    return SimpleNamespace(exchange=exchange)


def txt(*chunks):
    return SimpleNamespace(strings=tuple(chunks))


def cname(target):
    return SimpleNamespace(target=target)
