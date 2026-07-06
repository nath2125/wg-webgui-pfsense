"""Next-free-IP allocation from the configured pool.

The set of "used" IPs is computed fresh at allocation time from two sources so we
never hand out a colliding address:
  1. active (non-revoked) rows in our own registry, and
  2. the peers currently configured on pfSense (guards against manual edits or a
     crash that left an orphaned peer).
"""
from __future__ import annotations

import ipaddress

from .config import Settings


class PoolExhaustedError(RuntimeError):
    pass


def iter_pool(settings: Settings):
    start = int(settings.pool_start)
    end = int(settings.pool_end)
    reserved = settings.reserved_ips
    for value in range(start, end + 1):
        addr = ipaddress.ip_address(value)
        if str(addr) in reserved:
            continue
        yield addr


def allocate_ip(settings: Settings, used: set[str]) -> str:
    """Return the lowest free host address in the pool, or raise if none left."""
    for addr in iter_pool(settings):
        if str(addr) not in used:
            return str(addr)
    raise PoolExhaustedError(
        f"No free addresses left in pool {settings.ip_pool_cidr} "
        f"({settings.pool_start}-{settings.pool_end})"
    )


def is_in_pool(settings: Settings, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return int(settings.pool_start) <= int(addr) <= int(settings.pool_end)
