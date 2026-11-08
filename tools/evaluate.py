"""Measure subnetplan and write docs/report.json.

Three questions, each answered with numbers produced here and nowhere else:

1. Is the arithmetic right?  Random cases checked against brute force and the standard library.
2. Does the allocator waste space?  A churn benchmark: buddy best-fit (what subnetplan does) against
   first-fit and next-fit on the same request stream.
3. Is it fast enough?  Conflict detection and VLSM at scale, and the quadratic reference for scale.

    python tools/evaluate.py            # full run, a few minutes
    python tools/evaluate.py --quick    # smaller, for CI

Everything random is seeded: the correctness and fragmentation sections give the same numbers on every
machine. Timings depend on the machine and are recorded with it.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from conftest import bitmap, random_net  # noqa: E402
from subnetplan import __version__, netmath  # noqa: E402
from subnetplan.netmath import Pool, Request, make  # noqa: E402

# ---- 1. correctness ---------------------------------------------------------------------------


def section_correctness(scale: int) -> dict[str, object]:
    rng = random.Random(2024)
    out: dict[str, dict[str, int]] = {}

    def record(name: str, cases: int, mismatches: int) -> None:
        out[name] = {"cases": cases, "mismatches": mismatches}

    # range_to_cidrs against ipaddress.summarize_address_range
    bad = 0
    n = 4000 * scale
    for i in range(n):
        v, width = (4, 32) if i % 2 else (6, 128)
        a = rng.randrange(1 << width)
        b = min((1 << width) - 1, a + rng.choice([0, 1, 7, 255, 4096, 1 << 20, rng.randrange(1 << width)]))
        conv = ipaddress.IPv4Address if v == 4 else ipaddress.IPv6Address
        bad += netmath.range_to_cidrs(a, b, v) != list(ipaddress.summarize_address_range(conv(a), conv(b)))
    record("range_to_cidrs vs ipaddress.summarize_address_range", n, bad)

    # summarize against collapse_addresses, and exact coverage
    bad, n = 0, 1000 * scale
    for _ in range(n):
        nets = [random_net(rng, 4, 24, 30, 0x0A000000) for _ in range(rng.randint(0, 30))]
        got = netmath.summarize(nets)
        bad += got != list(ipaddress.collapse_addresses(nets)) or bitmap(got, 0, 1 << 32) != bitmap(nets, 0, 1 << 32)
    record("summarize vs ipaddress.collapse_addresses and exact coverage", n, bad)

    # free_blocks against an address bitmap
    parent = netmath.parse_net("10.1.0.0/24")
    lo, hi = int(parent.network_address), int(parent.broadcast_address)
    bad, n = 0, 1000 * scale
    for _ in range(n):
        used = [random_net(rng, 4, 24, 30, lo) for _ in range(rng.randint(0, 14))]
        free = netmath.free_blocks(parent, used)
        want = set(range(lo, hi + 1)) - bitmap(used, lo, hi + 1)
        bad += bitmap(free, lo, hi + 1) != want or free != netmath.summarize(free)
    record("free_blocks vs address bitmap (and minimal)", n, bad)

    # Pool: after random churn, held and free partition the parent, and a full release restores it
    bad, n = 0, 100 * scale
    pool_parent = netmath.parse_net("10.0.0.0/22")
    plo, phi = int(pool_parent.network_address), int(pool_parent.broadcast_address)
    for _ in range(n):
        pool, held = Pool(pool_parent), []
        for _ in range(300):
            if held and rng.random() < 0.45:
                pool.release(held.pop(rng.randrange(len(held))))
            else:
                got = pool.alloc(rng.randint(22, 30))
                if got is not None:
                    held.append(got)
        free = pool.free_list()
        h, f = bitmap(held, plo, phi + 1), bitmap(free, plo, phi + 1)
        bad += not (h.isdisjoint(f) and len(h) + len(f) == pool_parent.num_addresses)
        for x in held:
            pool.release(x)
        bad += pool.free_list() != [pool_parent]
    record("Pool alloc/release: held + free partition the parent; full release restores it", n, bad)

    # VLSM: places everything exactly when the power-of-two sizes add up to no more than the space
    bad, n = 0, 400 * scale
    vparent = netmath.parse_net("10.0.0.0/20")
    for _ in range(n):
        reqs = [
            Request(f"n{i}", rng.choice([1, 2, 5, 12, 30, 60, 120, 250, 500, 1000])) for i in range(rng.randint(1, 30))
        ]
        plan = netmath.vlsm(vparent, reqs)
        need = sum(1 << (32 - netmath.prefix_for_hosts(r.hosts, 4)) for r in reqs)
        nets = [a.net for a in plan.allocations]
        disjoint = len(bitmap(nets, 0, 1 << 32)) == sum(x.num_addresses for x in nets)
        bad += (not plan.unplaced) != (need <= vparent.num_addresses) or not disjoint
    record("VLSM places all requests iff the sizes fit; allocations are disjoint", n, bad)

    # find_conflicts against the O(n^2) definition
    bad, n = 0, 400 * scale
    for _ in range(n):
        items = [(f"i{k}", random_net(rng, rng.choice([4, 6]), 24, 30, 0)) for k in range(rng.randint(0, 40))]
        got = {(c.kind, c.inner, c.outer) for c in netmath.find_conflicts(items)}
        bad += got != reference_conflicts(items)
    record("find_conflicts vs quadratic reference", n, bad)

    total = sum(v["cases"] for v in out.values())
    return {"checks": out, "total_cases": total, "total_mismatches": sum(v["mismatches"] for v in out.values())}


def reference_conflicts(items: list[tuple[str, netmath.Net]]) -> set[tuple[str, str, str]]:
    out = set()
    ordered = sorted(items, key=lambda t: (t[1].version, int(t[1].network_address), t[1].prefixlen, t[0]))
    for i, (label, net) in enumerate(ordered):
        same = [lb for lb, n in ordered[:i] if n == net]
        if same:
            out.add(("duplicate", label, same[0]))
            continue
        above = [(lb, n) for lb, n in ordered if n.version == net.version and n != net and net.subnet_of(n)]
        if above:
            out.add(("nested", label, max(above, key=lambda t: t[1].prefixlen)[0]))
    return out


# ---- 2. fragmentation -------------------------------------------------------------------------

CELL = 30  # the smallest block is a /30; the benchmark works in cells of that size
VLSM_PARENT = netmath.parse_net("10.0.0.0/8")
POOL = netmath.parse_net("10.0.0.0/20")  # 1024 cells
CELLS = POOL.num_addresses >> 2
SIZES = [24, 25, 26, 27, 28, 29, 30]
WEIGHTS = [1, 2, 4, 6, 8, 8, 6]  # many small subnets, few large ones: the usual shape of a network


class FlatAllocator:
    """First-fit or next-fit over a cell bitmap: any aligned free run will do, wherever it is."""

    def __init__(self, mode: str) -> None:
        self.mode, self.cells, self.cursor = mode, bytearray(CELLS), 0

    def alloc(self, prefix: int) -> int | None:
        n = 1 << (CELL - prefix)
        starts = range(0, CELLS, n)
        if self.mode == "next-fit":
            k = self.cursor // n
            starts = [*range(k * n, CELLS, n), *range(0, k * n, n)]  # type: ignore[assignment]
        for s in starts:
            if not self.cells.count(1, s, s + n):
                self.cells[s : s + n] = b"\x01" * n
                self.cursor = (s + n) % CELLS
                return s
        return None

    def release(self, start: int, prefix: int) -> None:
        n = 1 << (CELL - prefix)
        self.cells[start : start + n] = bytes(n)


class BuddyAllocator:
    def __init__(self) -> None:
        self.pool = Pool(POOL)

    def alloc(self, prefix: int) -> netmath.Net | None:
        return self.pool.alloc(prefix)

    def release(self, net: netmath.Net, prefix: int) -> None:
        self.pool.release(net)


def churn(strategy: str, target: float, ops: int, seed: int) -> dict[str, float]:
    """Keep the pool near `target` occupancy for `ops` requests and count the avoidable refusals.

    A refusal is *avoidable* when the pool held enough free addresses in total, but not in one aligned
    block: that is fragmentation, as opposed to the pool simply being full.
    """
    rng = random.Random(seed)
    alloc: FlatAllocator | BuddyAllocator = (
        BuddyAllocator() if strategy == "buddy best-fit" else FlatAllocator(strategy)
    )
    held: list[tuple[object, int]] = []
    used_cells = 0
    asked = avoidable = refused = 0
    for _ in range(ops):
        occupancy = used_cells / CELLS
        if held and (occupancy > target or (occupancy > target - 0.1 and rng.random() < 0.5)):
            i = rng.randrange(len(held))
            where, prefix = held.pop(i)
            alloc.release(where, prefix)  # type: ignore[arg-type]
            used_cells -= 1 << (CELL - prefix)
            continue
        prefix = rng.choices(SIZES, WEIGHTS)[0]
        n = 1 << (CELL - prefix)
        asked += 1
        got = alloc.alloc(prefix)
        if got is None:
            refused += 1
            avoidable += used_cells + n <= CELLS
        else:
            held.append((got, prefix))
            used_cells += n
    return {"requests": asked, "refused": refused, "avoidable": avoidable}


def section_fragmentation(scale: int) -> dict[str, object]:
    ops, seeds = 6000, 5 * scale
    results: dict[str, dict[str, dict[str, object]]] = {}
    for target in (0.6, 0.75, 0.9):
        per_seed: dict[str, list[dict[str, float]]] = {}
        for strategy in ("buddy best-fit", "first-fit", "next-fit"):
            per_seed[strategy] = [churn(strategy, target, ops, seed) for seed in range(seeds)]
        cell: dict[str, dict[str, object]] = {}
        for strategy, runs in per_seed.items():
            asked = sum(r["requests"] for r in runs)
            pct = [100 * r["avoidable"] / r["requests"] for r in runs]
            cell[strategy] = {
                "requests": asked,
                "avoidable_refusals": sum(r["avoidable"] for r in runs),
                "avoidable_pct": round(100 * sum(r["avoidable"] for r in runs) / asked, 2),
                "per_run_pct_mean": round(statistics.mean(pct), 2),
                "per_run_pct_stdev": round(statistics.stdev(pct), 2),
            }
        buddy, first = per_seed["buddy best-fit"], per_seed["first-fit"]
        cell["buddy best-fit"]["runs_with_fewer_refusals_than_first_fit"] = sum(
            b["avoidable"] < f["avoidable"] for b, f in zip(buddy, first, strict=True)
        )
        cell["buddy best-fit"]["runs_with_equal_refusals_to_first_fit"] = sum(
            b["avoidable"] == f["avoidable"] for b, f in zip(buddy, first, strict=True)
        )
        results[f"{int(target * 100)}%"] = cell
    return {
        "pool": str(POOL),
        "sizes": [f"/{p}" for p in SIZES],
        "weights": WEIGHTS,
        "ops_per_run": ops,
        "runs_per_cell": seeds,
        "results": results,
    }


# ---- 3. performance ---------------------------------------------------------------------------


def timed(fn, repeats: int = 3) -> float:  # type: ignore[no-untyped-def]
    best = []
    for _ in range(repeats):
        t = time.perf_counter()
        fn()
        best.append(time.perf_counter() - t)
    return statistics.median(best)


def section_performance(quick: bool) -> dict[str, object]:
    rng = random.Random(7)
    out: dict[str, object] = {}

    sweep, quad = [], []
    for n in (1_000, 10_000, 100_000) if quick else (1_000, 10_000, 100_000, 500_000):
        # n distinct /24..., spread so that duplicates and nesting both occur
        items = [(f"p{i}", make(4, (rng.randrange(1 << 22)) << 10, rng.choice([22, 24, 24, 26]))) for i in range(n)]
        sweep.append({"n": n, "seconds": round(timed(lambda items=items: netmath.find_conflicts(items)), 4)})
    for n in (500, 1_000, 2_000, 4_000):
        items = [(f"p{i}", make(4, (rng.randrange(1 << 22)) << 10, rng.choice([22, 24, 24, 26]))) for i in range(n)]
        quad.append({"n": n, "seconds": round(timed(lambda items=items: reference_conflicts(items), 1), 4)})
    out["find_conflicts_sweep"] = sweep
    out["find_conflicts_quadratic_reference"] = quad

    vl = []
    for n in (100, 1_000, 10_000) if quick else (100, 1_000, 10_000, 50_000):
        reqs = [Request(f"n{i}", rng.choice([2, 10, 30, 60, 120])) for i in range(n)]
        plan = netmath.vlsm(VLSM_PARENT, reqs)
        vl.append(
            {
                "requests": n,
                "placed": len(plan.allocations),
                "seconds": round(timed(lambda reqs=reqs: netmath.vlsm(VLSM_PARENT, reqs)), 4),
            }
        )
    out["vlsm"] = vl

    pool_ops = 50_000 if quick else 200_000
    pool = Pool(netmath.parse_net("10.0.0.0/8"))

    def churn_pool() -> None:
        held: list[netmath.Net] = []
        r = random.Random(1)
        for _ in range(pool_ops):
            if held and r.random() < 0.5:
                pool.release(held.pop(r.randrange(len(held))))
            else:
                got = pool.alloc(r.randint(16, 30))
                if got is not None:
                    held.append(got)
        for h in held:
            pool.release(h)

    s = timed(churn_pool, 1)
    out["pool_churn"] = {"operations": pool_ops, "seconds": round(s, 3), "ops_per_second": int(pool_ops / s)}
    return out


# ---- main -------------------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "docs" / "report.json"))
    args = ap.parse_args()
    scale = 1 if args.quick else 3

    report: dict[str, object] = {
        "version": __version__,
        "python": platform.python_version(),
        "machine": f"{platform.system()} {platform.machine()}",
        "quick": args.quick,
    }
    for name, fn in (("correctness", lambda: section_correctness(scale)), ("fragmentation", lambda: section_fragmentation(scale)),
                     ("performance", lambda: section_performance(args.quick))):  # fmt: skip
        t = time.perf_counter()
        report[name] = fn()
        print(f"{name}: {time.perf_counter() - t:.1f}s", file=sys.stderr)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    c = report["correctness"]
    assert isinstance(c, dict)
    print(f"correctness: {c['total_cases']} cases, {c['total_mismatches']} mismatches")
    return 1 if c["total_mismatches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
