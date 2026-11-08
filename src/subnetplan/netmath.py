"""Pure subnet arithmetic. Everything works on integers and ipaddress networks, IPv4 and IPv6 alike.

The allocator is a buddy system: free space is kept as aligned power-of-two blocks, a request takes
the smallest block that fits (lowest address among equals) and splits it, and a release merges a
block with its buddy again. tools/evaluate.py measures it against first-fit and next-fit.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

Net = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_TEXT = 64
MAX_SPLIT = 1 << 20  # refuse to list more than about a million subnets


class PlanError(ValueError):
    """A request that cannot be satisfied or an input that is not valid. The message is for people."""


def bits(version: int) -> int:
    return 32 if version == 4 else 128


def parse_net(text: str, *, strict: bool = True) -> Net:
    """Parse a CIDR. strict=True rejects host bits ("10.0.0.5/24"); strict=False masks them."""
    if not isinstance(text, str) or not text.strip():
        raise PlanError("empty network")
    text = text.strip()
    if len(text) > MAX_TEXT or not text.isascii() or "%" in text:
        raise PlanError(f"not a network: {text[:40]!r}")
    if "/" not in text:
        raise PlanError(f"{text!r} has no prefix length (write 192.0.2.0/24, or 192.0.2.7/32 for one host)")
    try:
        return ipaddress.ip_network(text, strict=strict)
    except ValueError as exc:
        message = str(exc)
        if "host bits" in message:
            net = ipaddress.ip_network(text, strict=False)
            raise PlanError(f"{text} has host bits set; the network is {net}") from exc
        raise PlanError(f"not a network: {text!r}") from exc


def start_of(net: Net) -> int:
    return int(net.network_address)


def end_of(net: Net) -> int:
    return int(net.broadcast_address)


def make(version: int, start: int, prefix: int) -> Net:
    if version == 4:
        return ipaddress.IPv4Network((start, prefix))
    return ipaddress.IPv6Network((start, prefix))


def usable_hosts(net: Net) -> int:
    """Addresses a host can take. IPv4: minus network and broadcast, except /31 (RFC 3021) and /32."""
    size = net.num_addresses
    if net.version == 4:
        if net.prefixlen >= 31:
            return size
        return size - 2
    return size  # IPv6 has no broadcast; the subnet-router anycast address is left to the caller


def prefix_for_hosts(hosts: int, version: int, *, growth_percent: float = 0.0, p2p: bool = False) -> int:
    """Longest prefix whose subnet holds `hosts` (plus growth). LANs get at least a /30 (IPv4) or a /64 (IPv6)."""
    if isinstance(hosts, bool) or not isinstance(hosts, int) or hosts < 1:
        raise PlanError("hosts must be a whole number of at least 1")
    if not 0 <= growth_percent <= 1000:
        raise PlanError("growth must be between 0 and 1000 percent")
    if p2p:  # a link has two ends, whatever the growth
        if hosts > 2:
            raise PlanError("a point-to-point link has two ends")
        return 31 if version == 4 else 127
    needed = math.ceil(hosts * (1 + growth_percent / 100))
    top = 30 if version == 4 else 64
    for prefix in range(top, -1, -1):
        size = 1 << (bits(version) - prefix)
        usable = size - 2 if version == 4 else size
        if usable >= needed:
            return prefix
    raise PlanError(f"{needed} hosts do not fit in any IPv{version} network")


# ---- splitting and ranges --------------------------------------------------------------------


def split_equal(net: Net, parts: int) -> list[Net]:
    """Divide into `parts` equal subnets (parts must be a power of two)."""
    if isinstance(parts, bool) or not isinstance(parts, int) or parts < 1 or parts & (parts - 1):
        raise PlanError("the number of parts must be a power of two (1, 2, 4, 8, ...)")
    extra = parts.bit_length() - 1
    return split_prefix(net, net.prefixlen + extra)


def split_prefix(net: Net, new_prefix: int) -> list[Net]:
    if not net.prefixlen <= new_prefix <= net.max_prefixlen:
        raise PlanError(
            f"cannot split {net} into /{new_prefix} (it must be between /{net.prefixlen} and /{net.max_prefixlen})"
        )
    if new_prefix - net.prefixlen > 20:
        raise PlanError(f"splitting {net} into /{new_prefix} would give more than {MAX_SPLIT} subnets")
    return list(net.subnets(new_prefix=new_prefix))


def range_to_cidrs(first: int, last: int, version: int) -> list[Net]:
    """The fewest CIDR blocks covering exactly first..last (inclusive)."""
    if first > last:
        return []
    width = bits(version)
    out: list[Net] = []
    while first <= last:
        align = (first & -first).bit_length() - 1 if first else width
        fit = (last - first + 1).bit_length() - 1
        size_bits = min(align, fit)
        out.append(make(version, first, width - size_bits))
        first += 1 << size_bits
    return out


def merge_intervals(items: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for a, b in sorted(items):
        if merged and a <= merged[-1][1] + 1:
            if b > merged[-1][1]:
                merged[-1] = (merged[-1][0], b)
        else:
            merged.append((a, b))
    return merged


def summarize(nets: Iterable[Net]) -> list[Net]:
    """The smallest list of CIDR blocks covering exactly the union of the given networks."""
    by_version: dict[int, list[tuple[int, int]]] = {4: [], 6: []}
    for n in nets:
        by_version[n.version].append((start_of(n), end_of(n)))
    out: list[Net] = []
    for version in (4, 6):
        for a, b in merge_intervals(by_version[version]):
            out.extend(range_to_cidrs(a, b, version))
    return out


def free_blocks(parent: Net, used: Iterable[Net]) -> list[Net]:
    """What is left of `parent` once the `used` networks are taken out, as the fewest CIDR blocks."""
    lo, hi = start_of(parent), end_of(parent)
    taken = []
    for u in used:
        if u.version != parent.version:
            raise PlanError(f"{u} is IPv{u.version}, the parent {parent} is IPv{parent.version}")
        a, b = max(lo, start_of(u)), min(hi, end_of(u))
        if a <= b:
            taken.append((a, b))
    gaps: list[Net] = []
    cursor = lo
    for a, b in merge_intervals(taken):
        gaps.extend(range_to_cidrs(cursor, a - 1, parent.version))
        cursor = b + 1
    gaps.extend(range_to_cidrs(cursor, hi, parent.version))
    return gaps


# ---- the allocator ---------------------------------------------------------------------------


class Pool:
    """Buddy allocator over one parent network."""

    def __init__(self, parent: Net, used: Iterable[Net] = ()) -> None:
        self.parent = parent
        self.version = parent.version
        self._free: dict[int, set[int]] = {p: set() for p in range(parent.prefixlen, parent.max_prefixlen + 1)}
        for block in free_blocks(parent, used):
            self._free[block.prefixlen].add(start_of(block))

    def alloc(self, prefix: int) -> Net | None:
        """Take the smallest free block that fits a /prefix (lowest address among equals), or None."""
        if not self.parent.prefixlen <= prefix <= self.parent.max_prefixlen:
            return None
        for q in range(prefix, self.parent.prefixlen - 1, -1):
            if self._free[q]:
                start = min(self._free[q])
                self._free[q].remove(start)
                width = bits(self.version)
                while q < prefix:  # split, keeping the lower half
                    q += 1
                    self._free[q].add(start + (1 << (width - q)))
                return make(self.version, start, prefix)
        return None

    def release(self, net: Net) -> None:
        """Give a block back and merge it with its buddy as far as possible."""
        if net.version != self.version or not (
            start_of(self.parent) <= start_of(net) and end_of(net) <= end_of(self.parent)
        ):
            raise PlanError(f"{net} is not inside {self.parent}")
        start, q, width = start_of(net), net.prefixlen, bits(self.version)
        if any(self._overlaps_free(start, q)):
            raise PlanError(f"{net} is already free (or partly free)")
        while q > self.parent.prefixlen:
            buddy = start ^ (1 << (width - q))
            if buddy in self._free[q]:
                self._free[q].remove(buddy)
                start = min(start, buddy)
                q -= 1
            else:
                break
        self._free[q].add(start)

    def _overlaps_free(self, start: int, prefix: int) -> Iterator[bool]:
        width = bits(self.version)
        end = start + (1 << (width - prefix)) - 1
        for q, starts in self._free.items():
            size = 1 << (width - q)
            for s in starts:
                if s <= end and start <= s + size - 1:
                    yield True

    def free_list(self) -> list[Net]:
        out = [make(self.version, s, q) for q, starts in self._free.items() for s in starts]
        return sorted(out, key=lambda n: (start_of(n), n.prefixlen))

    def free_addresses(self) -> int:
        width = bits(self.version)
        return sum(len(starts) << (width - q) for q, starts in self._free.items())


# ---- VLSM planning ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Request:
    name: str
    hosts: int
    p2p: bool = False


@dataclass
class Allocation:
    name: str
    net: Net
    hosts: int
    usable: int


@dataclass
class Plan:
    parent: Net
    allocations: list[Allocation] = field(default_factory=list)
    unplaced: list[tuple[str, str]] = field(default_factory=list)
    free: list[Net] = field(default_factory=list)

    @property
    def addresses_allocated(self) -> int:
        return sum(a.net.num_addresses for a in self.allocations)

    @property
    def utilization(self) -> float:
        """Share of the parent's addresses that were handed out."""
        return self.addresses_allocated / self.parent.num_addresses

    @property
    def efficiency(self) -> float:
        """Hosts asked for, over usable addresses handed out: how little each subnet wastes."""
        usable = sum(a.usable for a in self.allocations)
        return sum(a.hosts for a in self.allocations) / usable if usable else 1.0


def vlsm(
    parent: Net,
    requests: list[Request],
    *,
    growth_percent: float = 0.0,
    used: Iterable[Net] = (),
) -> Plan:
    """Place each request in the parent, largest first. `used` are blocks that are already taken.

    With power-of-two blocks, largest-first at the lowest free address is optimal: a set of requests
    fits exactly when the sizes sum to no more than the free space.
    """
    if len(requests) > 100_000:
        raise PlanError("more than 100000 requests")
    names = [r.name for r in requests]
    if len(set(names)) != len(names):
        raise PlanError("two requests have the same name")
    pool = Pool(parent, used)
    sized: list[tuple[int, str, Request]] = []
    plan = Plan(parent)
    for r in requests:
        try:
            sized.append(
                (
                    prefix_for_hosts(
                        r.hosts,
                        parent.version,
                        growth_percent=growth_percent,
                        p2p=r.p2p,
                    ),
                    r.name,
                    r,
                )
            )
        except PlanError as exc:
            plan.unplaced.append((r.name, str(exc)))
    for prefix, _, r in sorted(sized, key=lambda t: (t[0], t[1])):
        net = pool.alloc(prefix)
        if net is None:
            plan.unplaced.append((r.name, f"no free /{prefix} left in {parent}"))
        else:
            plan.allocations.append(Allocation(r.name, net, r.hosts, usable_hosts(net)))
    plan.allocations.sort(key=lambda a: start_of(a.net))
    plan.free = pool.free_list()
    return plan


# ---- conflicts -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Conflict:
    kind: str  # "duplicate" (an error) or "nested" (usually intended)
    inner: str
    outer: str
    inner_net: Net
    outer_net: Net


def find_conflicts(items: list[tuple[str, Net]]) -> list[Conflict]:
    """Duplicates and nesting among labelled networks, in O(n log n).

    Each network is reported against the closest network that contains it (or that it duplicates
    first). CIDR blocks never partly overlap, so these two relations are all there is.
    """
    out: list[Conflict] = []
    for version in (4, 6):
        group = [(label, n) for label, n in items if n.version == version]
        group.sort(key=lambda t: (start_of(t[1]), t[1].prefixlen, t[0]))
        stack: list[tuple[str, Net]] = []
        for label, net in group:
            while stack and end_of(stack[-1][1]) < start_of(net):
                stack.pop()
            if stack:
                top_label, top = stack[-1]
                if top == net:
                    out.append(Conflict("duplicate", label, top_label, net, top))
                    continue
                out.append(Conflict("nested", label, top_label, net, top))
            stack.append((label, net))
    return out
