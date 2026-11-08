from __future__ import annotations

import ipaddress
import itertools
import random

import pytest

from conftest import bitmap, random_net
from subnetplan import netmath
from subnetplan.netmath import PlanError, Pool, Request, parse_net

N = netmath.parse_net


# ---- parsing and small facts ------------------------------------------------------------------


@pytest.mark.parametrize(
    "text", ["10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32", "0.0.0.0/0", "::/0", "192.0.2.7/32", " 10.0.0.0/24 "]
)
def test_parse_valid(text: str) -> None:
    assert str(parse_net(text)) == str(ipaddress.ip_network(text.strip()))


@pytest.mark.parametrize(
    "text",
    ["", "   ", "10.0.0.0", "10.0.0.0/33", "10.0.0.0/-1", "256.0.0.0/8", "10.0.0/24", "garbage", "2001:db8::/129",
     "fe80::1%eth0/64", "\u0661\u0660.0.0.0/8", "10.0.0.0/24\n10.0.1.0/24", "1" * 70 + "/8", "10.0.0.0/8 extra"],
)  # fmt: skip
def test_parse_invalid(text: str) -> None:
    with pytest.raises(PlanError):
        parse_net(text)


def test_parse_non_string() -> None:
    with pytest.raises(PlanError):
        parse_net(None)  # type: ignore[arg-type]


def test_host_bits_are_named_and_can_be_masked() -> None:
    with pytest.raises(PlanError, match=r"host bits set; the network is 10\.0\.0\.0/24"):
        parse_net("10.0.0.5/24")
    assert str(parse_net("10.0.0.5/24", strict=False)) == "10.0.0.0/24"
    assert str(parse_net("2001:db8::1/64", strict=False)) == "2001:db8::/64"


def test_usable_hosts() -> None:
    cases = {"10.0.0.0/24": 254, "10.0.0.0/30": 2, "10.0.0.0/31": 2, "10.0.0.1/32": 1, "10.0.0.0/8": 2**24 - 2,
             "2001:db8::/64": 2**64, "2001:db8::/127": 2, "2001:db8::1/128": 1}  # fmt: skip
    for text, usable in cases.items():
        assert netmath.usable_hosts(N(text)) == usable, text


def test_prefix_for_hosts_table() -> None:
    f = netmath.prefix_for_hosts
    assert [f(h, 4) for h in (1, 2, 3, 6, 7, 14, 15, 254, 255, 510, 511)] == [
        30,
        30,
        29,
        29,
        28,
        28,
        27,
        24,
        23,
        23,
        22,
    ]
    assert f(100, 4, growth_percent=20) == 25  # 120 needed
    assert f(100, 4, growth_percent=0) == 25 and f(127, 4) == 24 and f(126, 4) == 25
    assert f(5000, 6) == 64 and f(2, 4, p2p=True) == 31 and f(2, 6, p2p=True) == 127
    assert f(2, 4, growth_percent=500, p2p=True) == 31  # a link has two ends, whatever the growth


def test_prefix_for_hosts_is_tight() -> None:
    """For every host count, the prefix holds the hosts and one more bit would not."""
    for hosts in range(1, 3000):
        p = netmath.prefix_for_hosts(hosts, 4)
        assert (1 << (32 - p)) - 2 >= hosts
        if p > 0 and p < 30:
            assert (1 << (32 - p - 1)) - 2 < hosts


@pytest.mark.parametrize(
    "hosts, version, kwargs",
    [(0, 4, {}), (-3, 4, {}), (True, 4, {}), (1.5, 4, {}), (2**33, 4, {}), (3, 4, {"p2p": True}), (5, 4, {"growth_percent": -1}), (5, 4, {"growth_percent": 5000})],
)  # fmt: skip
def test_prefix_for_hosts_errors(hosts: object, version: int, kwargs: dict[str, object]) -> None:
    with pytest.raises(PlanError):
        netmath.prefix_for_hosts(hosts, version, **kwargs)  # type: ignore[arg-type]


def test_split() -> None:
    assert [str(n) for n in netmath.split_equal(N("192.0.2.0/24"), 4)] == [
        "192.0.2.0/26",
        "192.0.2.64/26",
        "192.0.2.128/26",
        "192.0.2.192/26",
    ]
    assert netmath.split_equal(N("192.0.2.0/24"), 1) == [N("192.0.2.0/24")]
    assert len(netmath.split_prefix(N("2001:db8::/48"), 64)) == 65536
    for bad in (0, 3, 6, -2, True):
        with pytest.raises(PlanError):
            netmath.split_equal(N("192.0.2.0/24"), bad)
    with pytest.raises(PlanError, match="cannot split"):
        netmath.split_prefix(N("192.0.2.0/24"), 23)
    with pytest.raises(PlanError, match="cannot split"):
        netmath.split_prefix(N("192.0.2.0/24"), 33)
    with pytest.raises(PlanError, match="more than"):
        netmath.split_prefix(N("2001:db8::/32"), 64)
    with pytest.raises(PlanError):
        netmath.split_equal(N("192.0.2.0/31"), 4)


# ---- ranges, summaries, free space: against brute force and the standard library ---------------


def test_range_to_cidrs_matches_the_standard_library() -> None:
    rng = random.Random(1)
    for version, width in ((4, 32), (6, 128)):
        for _ in range(1500):
            a = rng.randrange(1 << width)
            b = min((1 << width) - 1, a + rng.choice([0, 1, 2, 3, 7, 255, 1000, 1 << 20, rng.randrange(1 << width)]))
            ours = netmath.range_to_cidrs(a, b, version)
            ref = list(ipaddress.summarize_address_range(ipaddress.ip_address(a) if version == 6 else ipaddress.IPv4Address(a),
                                                          ipaddress.ip_address(b) if version == 6 else ipaddress.IPv4Address(b)))  # fmt: skip
            assert ours == ref
    assert netmath.range_to_cidrs(5, 4, 4) == []
    assert netmath.range_to_cidrs(0, (1 << 32) - 1, 4) == [N("0.0.0.0/0")]


def test_summarize_is_exact_and_minimal() -> None:
    rng = random.Random(2)
    for _ in range(400):
        nets = [random_net(rng, 4, 24, 30, base=0x0A000000) for _ in range(rng.randint(0, 25))]
        out = netmath.summarize(nets)
        assert bitmap(out, 0, 1 << 32) == bitmap(nets, 0, 1 << 32)
        assert out == list(ipaddress.collapse_addresses(nets))  # the same minimal set the library finds
        assert netmath.summarize(out) == out  # idempotent
        assert all(a.broadcast_address < b.network_address for a, b in itertools.pairwise(out))


def test_summarize_mixed_families_and_adjacent_blocks() -> None:
    out = netmath.summarize(
        [N("10.0.0.0/25"), N("10.0.0.128/25"), N("10.0.1.0/24"), N("2001:db8::/33"), N("2001:db8:8000::/33")]
    )
    assert out == [N("10.0.0.0/23"), N("2001:db8::/32")]
    assert netmath.summarize([]) == []


def test_free_blocks_is_the_complement() -> None:
    rng = random.Random(3)
    parent = N("10.1.0.0/24")
    lo, hi = int(parent.network_address), int(parent.broadcast_address)
    for _ in range(500):
        used = [random_net(rng, 4, 24, 30, base=lo) for _ in range(rng.randint(0, 12))]
        free = netmath.free_blocks(parent, used)
        assert bitmap(free, lo, hi + 1) == set(range(lo, hi + 1)) - bitmap(used, lo, hi + 1)
        assert free == netmath.summarize(free)  # minimal, disjoint
        assert all(f.subnet_of(parent) for f in free)


def test_free_blocks_edges() -> None:
    parent = N("192.0.2.0/24")
    assert netmath.free_blocks(parent, []) == [parent]
    assert netmath.free_blocks(parent, [parent]) == []
    assert netmath.free_blocks(parent, [N("192.0.0.0/16")]) == []  # a bigger block takes it all
    assert netmath.free_blocks(parent, [N("198.51.100.0/24")]) == [parent]  # elsewhere: no effect
    assert netmath.free_blocks(parent, [N("192.0.2.0/25"), N("192.0.2.64/26")]) == [N("192.0.2.128/25")]
    with pytest.raises(PlanError, match="IPv6"):
        netmath.free_blocks(parent, [N("2001:db8::/32")])
    v6 = N("2001:db8::/48")
    assert netmath.free_blocks(v6, [N("2001:db8::/49")]) == [N("2001:db8:0:8000::/49")]


# ---- the allocator ----------------------------------------------------------------------------


def test_pool_takes_the_smallest_block_that_fits_at_the_lowest_address() -> None:
    pool = Pool(N("10.0.0.0/24"), used=[N("10.0.0.0/26"), N("10.0.0.128/27")])
    # free: 10.0.0.64/26, 10.0.0.160/27, 10.0.0.192/26
    assert pool.alloc(27) == N("10.0.0.160/27")  # the /27 hole, not a slice of a /26
    assert pool.alloc(27) == N("10.0.0.64/27")  # next: lowest of the /26s
    assert pool.alloc(26) == N("10.0.0.192/26")
    assert pool.alloc(27) == N("10.0.0.96/27")
    assert pool.alloc(27) is None and pool.free_list() == []


def test_pool_release_merges_buddies() -> None:
    parent = N("10.0.0.0/24")
    pool = Pool(parent)
    blocks = [pool.alloc(28) for _ in range(16)]
    assert pool.free_list() == []
    for b in reversed(blocks):
        assert b is not None
        pool.release(b)
    assert pool.free_list() == [parent]


def test_pool_invariants_under_churn() -> None:
    rng = random.Random(4)
    parent = N("10.0.0.0/22")
    lo, hi = int(parent.network_address), int(parent.broadcast_address)
    pool, held = Pool(parent), []
    for step in range(3000):
        if held and rng.random() < 0.45:
            pool.release(held.pop(rng.randrange(len(held))))
        else:
            got = pool.alloc(rng.randint(22, 30))
            if got is not None:
                held.append(got)
        if step % 100 == 0:
            free = pool.free_list()
            assert bitmap(held, lo, hi + 1).isdisjoint(bitmap(free, lo, hi + 1))
            assert len(bitmap(held, lo, hi + 1)) + len(bitmap(free, lo, hi + 1)) == parent.num_addresses
            assert pool.free_addresses() == len(bitmap(free, lo, hi + 1))
            assert sum(h.num_addresses for h in held) == len(bitmap(held, lo, hi + 1))  # held blocks never overlap
    for h in held:
        pool.release(h)
    assert pool.free_list() == [parent]


def test_pool_refusals() -> None:
    pool = Pool(N("10.0.0.0/24"))
    assert pool.alloc(23) is None and pool.alloc(33) is None
    got = pool.alloc(25)
    assert got is not None
    pool.release(got)
    with pytest.raises(PlanError, match="already free"):
        pool.release(got)
    with pytest.raises(PlanError, match="not inside"):
        pool.release(N("10.0.1.0/25"))
    with pytest.raises(PlanError, match="not inside"):
        pool.release(N("2001:db8::/64"))
    p6 = Pool(N("2001:db8::/48"))
    first = p6.alloc(64)
    assert first == N("2001:db8::/64") and p6.alloc(64) == N("2001:db8:0:1::/64")


# ---- VLSM -------------------------------------------------------------------------------------


def test_vlsm_worked_example() -> None:
    plan = netmath.vlsm(
        N("10.0.0.0/22"), [Request("a", 500), Request("b", 100), Request("c", 2, True), Request("d", 60)]
    )
    assert [(x.name, str(x.net)) for x in plan.allocations] == [
        ("a", "10.0.0.0/23"), ("b", "10.0.2.0/25"), ("d", "10.0.2.128/26"), ("c", "10.0.2.192/31")]  # fmt: skip
    assert plan.unplaced == [] and plan.addresses_allocated == 512 + 128 + 64 + 2
    assert plan.utilization == pytest.approx(706 / 1024)
    assert plan.efficiency == pytest.approx((500 + 100 + 60 + 2) / (510 + 126 + 62 + 2))
    assert netmath.summarize(plan.free) == plan.free
    assert sum(f.num_addresses for f in plan.free) == 1024 - 706


def test_vlsm_fits_exactly_when_the_sizes_add_up() -> None:
    """Power-of-two blocks, largest first: it fits if and only if the total is no more than the space."""
    rng = random.Random(5)
    parent = N("10.0.0.0/20")
    for _ in range(600):
        reqs = [
            Request(f"n{i}", rng.choice([1, 2, 5, 12, 30, 60, 120, 250, 500, 1000])) for i in range(rng.randint(1, 30))
        ]
        plan = netmath.vlsm(parent, reqs)
        wanted = sum(1 << (32 - netmath.prefix_for_hosts(r.hosts, 4)) for r in reqs)
        assert (not plan.unplaced) == (wanted <= parent.num_addresses)
        nets = [a.net for a in plan.allocations]
        assert all(n.subnet_of(parent) for n in nets)
        assert len(bitmap(nets, 0, 1 << 32)) == sum(n.num_addresses for n in nets)  # disjoint
        assert all(a.net.num_addresses - 2 >= a.hosts for a in plan.allocations)


def test_vlsm_respects_used_blocks_growth_and_names() -> None:
    plan = netmath.vlsm(N("10.0.0.0/24"), [Request("x", 100)], used=[N("10.0.0.0/25")])
    assert plan.allocations[0].net == N("10.0.0.128/25")
    plan = netmath.vlsm(N("10.0.0.0/24"), [Request("x", 100)], growth_percent=30)  # 130 needed
    assert plan.allocations[0].net == N("10.0.0.0/24")
    with pytest.raises(PlanError, match="same name"):
        netmath.vlsm(N("10.0.0.0/24"), [Request("x", 1), Request("x", 2)])
    plan = netmath.vlsm(N("10.0.0.0/30"), [Request("big", 100), Request("zero", 0)])
    assert {n for n, _ in plan.unplaced} == {"big", "zero"}
    assert netmath.vlsm(N("10.0.0.0/24"), []).free == [N("10.0.0.0/24")]


def test_vlsm_ipv6_and_ordering_is_stable() -> None:
    plan = netmath.vlsm(N("2001:db8::/48"), [Request("b", 10), Request("a", 10), Request("link", 2, True)])
    assert [(x.name, str(x.net)) for x in plan.allocations] == [
        ("a", "2001:db8::/64"), ("b", "2001:db8:0:1::/64"), ("link", "2001:db8:0:2::/127")]  # fmt: skip
    again = netmath.vlsm(N("2001:db8::/48"), [Request("link", 2, True), Request("a", 10), Request("b", 10)])
    assert [str(x.net) for x in again.allocations] == [str(x.net) for x in plan.allocations]


def test_vlsm_request_limit() -> None:
    with pytest.raises(PlanError, match="100000"):
        netmath.vlsm(N("10.0.0.0/8"), [Request(f"n{i}", 1) for i in range(100_001)])


# ---- conflicts --------------------------------------------------------------------------------


def reference_conflicts(items: list[tuple[str, netmath.Net]]) -> set[tuple[str, str, str]]:
    """O(n^2): for each item, the first equal one is its original, else the smallest strict container."""
    out = set()
    ordered = sorted(items, key=lambda t: (t[1].version, int(t[1].network_address), t[1].prefixlen, t[0]))
    for i, (label, net) in enumerate(ordered):
        equal_before = [(lb, n) for lb, n in ordered[:i] if n == net]
        if equal_before:
            out.add(("duplicate", label, equal_before[0][0]))
            continue
        containers = [(lb, n) for lb, n in ordered if n.version == net.version and n != net and net.subnet_of(n)]
        if containers:
            out.add(("nested", label, max(containers, key=lambda t: t[1].prefixlen)[0]))
    return out


def test_find_conflicts_matches_the_quadratic_reference() -> None:
    rng = random.Random(6)
    for _ in range(300):
        items = [(f"i{k}", random_net(rng, rng.choice([4, 4, 6]), 24, 30, base=0)) for k in range(rng.randint(0, 40))]
        got = {(c.kind, c.inner, c.outer) for c in netmath.find_conflicts(items)}
        assert got == reference_conflicts(items)


def test_find_conflicts_examples() -> None:
    items = [("a", N("10.0.0.0/16")), ("b", N("10.0.1.0/24")), ("c", N("10.0.1.0/24")), ("d", N("10.0.1.0/24")),
             ("e", N("10.0.9.0/24")), ("f", N("10.0.1.128/25"))]  # fmt: skip
    got = sorted((c.kind, c.inner, c.outer) for c in netmath.find_conflicts(items))
    assert got == [
        ("duplicate", "c", "b"),
        ("duplicate", "d", "b"),
        ("nested", "b", "a"),
        ("nested", "e", "a"),
        ("nested", "f", "b"),
    ]
    assert netmath.find_conflicts([]) == []
    assert netmath.find_conflicts([("x", N("10.0.0.0/8")), ("y", N("2001:db8::/32"))]) == []
