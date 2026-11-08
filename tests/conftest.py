from __future__ import annotations

import random

import pytest

from subnetplan.netmath import Net, make
from subnetplan.store import Store


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def random_net(rng: random.Random, version: int = 4, min_prefix: int = 24, max_prefix: int = 30, base: int = 0) -> Net:
    """A random aligned block inside a small window, so that collisions are common."""
    width = 32 if version == 4 else 128
    prefix = rng.randint(min_prefix, max_prefix)
    slots = 1 << (prefix - min_prefix)
    start = base + rng.randrange(slots) * (1 << (width - prefix))
    return make(version, start, prefix)


def bitmap(nets: list[Net], lo: int, hi: int) -> set[int]:
    """Every address covered, as a set of integers: the brute-force reference."""
    out: set[int] = set()
    for n in nets:
        out.update(range(max(lo, int(n.network_address)), min(hi, int(n.broadcast_address)) + 1))
    return out
