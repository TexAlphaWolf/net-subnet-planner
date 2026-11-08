"""A small IPAM on SQLite: prefixes in a hierarchy, addresses inside them, one file, no server."""

from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from subnetplan import netmath
from subnetplan.netmath import Net, PlanError, Request

STATUSES = ("container", "active", "reserved", "deprecated")
KINDS = ("host", "gateway", "reserved")
SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS prefixes (
    id INTEGER PRIMARY KEY,
    vrf TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version IN (4, 6)),
    first BLOB NOT NULL,
    last BLOB NOT NULL,
    prefixlen INTEGER NOT NULL,
    name TEXT NOT NULL,
    vlan INTEGER CHECK (vlan IS NULL OR vlan BETWEEN 1 AND 4094),
    status TEXT NOT NULL CHECK (status IN ('container', 'active', 'reserved', 'deprecated')),
    created TEXT NOT NULL,
    UNIQUE (vrf, version, first, prefixlen)
);
CREATE INDEX IF NOT EXISTS prefixes_range ON prefixes (vrf, version, first, last);
CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY,
    prefix_id INTEGER NOT NULL REFERENCES prefixes (id) ON DELETE CASCADE,
    ip BLOB NOT NULL,
    hostname TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('host', 'gateway', 'reserved')),
    note TEXT NOT NULL,
    UNIQUE (prefix_id, ip)
);
"""

MAX_NAME = 120


def blob(value: int, version: int) -> bytes:
    """Big-endian, fixed width: byte order is numeric order, so SQL can compare addresses."""
    return value.to_bytes(4 if version == 4 else 16, "big")


def unblob(data: bytes) -> int:
    return int.from_bytes(data, "big")


@dataclass(frozen=True)
class Prefix:
    id: int
    vrf: str
    net: Net
    name: str
    vlan: int | None
    status: str


@dataclass(frozen=True)
class Address:
    id: int
    prefix_id: int
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    hostname: str
    kind: str
    note: str


def clean(text: str, what: str) -> str:
    if not isinstance(text, str):
        raise PlanError(f"{what} must be text")
    text = text.strip()
    if len(text) > MAX_NAME or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise PlanError(f"{what} is too long or contains control characters")
    return text


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self.db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        try:
            self.db.executescript(SCHEMA)
            row = self.db.execute("SELECT value FROM meta WHERE key = 'schema'").fetchone()
            if row is None:
                self.db.execute("INSERT INTO meta VALUES ('schema', ?)", (str(SCHEMA_VERSION),))
            elif int(row["value"]) != SCHEMA_VERSION:
                raise PlanError(f"{path} has schema {row['value']}, this version reads {SCHEMA_VERSION}")
        except (sqlite3.DatabaseError, PlanError, ValueError) as exc:
            self.db.close()  # do not leak the handle (or keep a file locked on Windows) when we refuse it
            if isinstance(exc, PlanError):
                raise
            raise PlanError(f"{path} is not a usable subnetplan database: {exc}") from exc

    def close(self) -> None:
        self.db.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        self.db.execute("COMMIT")

    # ---- prefixes ------------------------------------------------------------------------

    def _prefix(self, row: sqlite3.Row) -> Prefix:
        v = row["version"]
        net = netmath.make(v, unblob(row["first"]), row["prefixlen"])
        return Prefix(row["id"], row["vrf"], net, row["name"], row["vlan"], row["status"])

    def get(self, prefix_id: int) -> Prefix:
        row = self.db.execute("SELECT * FROM prefixes WHERE id = ?", (prefix_id,)).fetchone()
        if row is None:
            raise PlanError(f"no prefix with id {prefix_id}")
        return self._prefix(row)

    def find(self, net: Net, vrf: str = "default") -> Prefix | None:
        row = self.db.execute(
            "SELECT * FROM prefixes WHERE vrf = ? AND version = ? AND first = ? AND prefixlen = ?",
            (vrf, net.version, blob(netmath.start_of(net), net.version), net.prefixlen),
        ).fetchone()
        return self._prefix(row) if row else None

    def add_prefix(
        self,
        net: Net,
        *,
        name: str = "",
        vlan: int | None = None,
        vrf: str = "default",
        status: str = "active",
    ) -> Prefix:
        name, vrf = clean(name, "name"), clean(vrf, "vrf") or "default"
        if status not in STATUSES:
            raise PlanError(f"status must be one of {', '.join(STATUSES)}")
        if vlan is not None and not (isinstance(vlan, int) and 1 <= vlan <= 4094):
            raise PlanError("vlan must be between 1 and 4094")
        if self.find(net, vrf):
            raise PlanError(f"{net} already exists in vrf {vrf}")
        cur = self.db.execute(
            "INSERT INTO prefixes (vrf, version, first, last, prefixlen, name, vlan, status, created) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                vrf,
                net.version,
                blob(netmath.start_of(net), net.version),
                blob(netmath.end_of(net), net.version),
                net.prefixlen,
                name,
                vlan,
                status,
                datetime.now(UTC).isoformat(timespec="seconds"),
            ),
        )
        return self.get(int(cur.lastrowid or 0))

    def parent_of(self, p: Prefix) -> Prefix | None:
        """The smallest other prefix in the same vrf that contains this one."""
        row = self.db.execute(
            "SELECT * FROM prefixes WHERE vrf = ? AND version = ? AND first <= ? AND last >= ? AND id != ?"
            " ORDER BY prefixlen DESC LIMIT 1",
            (
                p.vrf,
                p.net.version,
                blob(netmath.start_of(p.net), p.net.version),
                blob(netmath.end_of(p.net), p.net.version),
                p.id,
            ),
        ).fetchone()
        # a prefix with the same range but a shorter length cannot exist; containment is strict here
        if row and row["prefixlen"] >= p.net.prefixlen:
            return None
        return self._prefix(row) if row else None

    def descendants(self, p: Prefix) -> list[Prefix]:
        rows = self.db.execute(
            "SELECT * FROM prefixes WHERE vrf = ? AND version = ? AND first >= ? AND last <= ? AND id != ?"
            " ORDER BY first, prefixlen",
            (
                p.vrf,
                p.net.version,
                blob(netmath.start_of(p.net), p.net.version),
                blob(netmath.end_of(p.net), p.net.version),
                p.id,
            ),
        ).fetchall()
        return [self._prefix(r) for r in rows if r["prefixlen"] > p.net.prefixlen]

    def children(self, p: Prefix) -> list[Prefix]:
        """Direct children: descendants that are not inside another descendant."""
        out: list[Prefix] = []
        for d in self.descendants(p):
            if (
                out
                and netmath.end_of(d.net) <= netmath.end_of(out[-1].net)
                and netmath.start_of(d.net) >= netmath.start_of(out[-1].net)
            ):
                continue
            out.append(d)
        return out

    def all(self, vrf: str | None = None) -> list[Prefix]:
        sql = "SELECT * FROM prefixes" + (" WHERE vrf = ?" if vrf else "") + " ORDER BY vrf, version, first, prefixlen"
        return [self._prefix(r) for r in self.db.execute(sql, (vrf,) if vrf else ()).fetchall()]

    def free(self, p: Prefix) -> list[Net]:
        return netmath.free_blocks(p.net, [d.net for d in self.descendants(p)])

    def allocate(
        self,
        parent_id: int,
        *,
        name: str,
        hosts: int | None = None,
        prefixlen: int | None = None,
        growth_percent: float = 0.0,
        vlan: int | None = None,
        status: str = "active",
        p2p: bool = False,
    ) -> Prefix:
        """Carve a new subnet out of a parent: best-fit, lowest address."""
        if (hosts is None) == (prefixlen is None):
            raise PlanError("give either hosts or prefixlen")
        with self.transaction():
            parent = self.get(parent_id)
            self._leaf_check(parent)
            size = (
                prefixlen
                if prefixlen is not None
                else netmath.prefix_for_hosts(
                    int(hosts or 0),
                    parent.net.version,
                    growth_percent=growth_percent,
                    p2p=p2p,
                )
            )
            pool = netmath.Pool(parent.net, [d.net for d in self.descendants(parent)])
            net = pool.alloc(size)
            if net is None:
                raise PlanError(f"no free /{size} left in {parent.net}")
            return self.add_prefix(net, name=name, vlan=vlan, vrf=parent.vrf, status=status)

    def allocate_plan(
        self,
        parent_id: int,
        requests: list[Request],
        *,
        growth_percent: float = 0.0,
        status: str = "active",
    ) -> netmath.Plan:
        """Plan a whole set of requests and save them, all or nothing."""
        with self.transaction():
            parent = self.get(parent_id)
            self._leaf_check(parent)
            plan = netmath.vlsm(
                parent.net,
                requests,
                growth_percent=growth_percent,
                used=[d.net for d in self.descendants(parent)],
            )
            if plan.unplaced:
                raise PlanError("; ".join(f"{n}: {why}" for n, why in plan.unplaced))
            for a in plan.allocations:
                self.add_prefix(a.net, name=a.name, vrf=parent.vrf, status=status)
            return plan

    def _leaf_check(self, parent: Prefix) -> None:
        if parent.status in ("reserved", "deprecated"):
            raise PlanError(f"{parent.net} is {parent.status}; nothing can be allocated from it")
        n = self.db.execute("SELECT COUNT(*) FROM addresses WHERE prefix_id = ?", (parent.id,)).fetchone()[0]
        if n:
            raise PlanError(f"{parent.net} holds {n} address(es); allocate subnets from a container, not from a LAN")

    def delete_prefix(self, prefix_id: int, *, force: bool = False) -> int:
        """Delete a prefix. Refuses if it has sub-prefixes or addresses unless force; returns rows removed."""
        with self.transaction():
            p = self.get(prefix_id)
            kids = self.descendants(p)
            n_addr = self.db.execute("SELECT COUNT(*) FROM addresses WHERE prefix_id = ?", (prefix_id,)).fetchone()[0]
            if (kids or n_addr) and not force:
                raise PlanError(
                    f"{p.net} has {len(kids)} sub-prefix(es) and {n_addr} address(es); use force to delete them too"
                )
            ids = [prefix_id, *[k.id for k in kids]]
            self.db.executemany("DELETE FROM prefixes WHERE id = ?", [(i,) for i in ids])
            return len(ids)

    # ---- addresses -----------------------------------------------------------------------

    def _address(self, row: sqlite3.Row, version: int) -> Address:
        ip = ipaddress.ip_address(unblob(row["ip"])) if version == 6 else ipaddress.IPv4Address(unblob(row["ip"]))
        return Address(row["id"], row["prefix_id"], ip, row["hostname"], row["kind"], row["note"])

    def addresses(self, prefix_id: int) -> list[Address]:
        p = self.get(prefix_id)
        rows = self.db.execute("SELECT * FROM addresses WHERE prefix_id = ? ORDER BY ip", (prefix_id,)).fetchall()
        return [self._address(r, p.net.version) for r in rows]

    def add_address(
        self,
        prefix_id: int,
        *,
        hostname: str = "",
        ip: str | None = None,
        kind: str = "host",
        note: str = "",
    ) -> Address:
        """Record an address in a LAN prefix: the one asked for, or the lowest free usable one."""
        if kind not in KINDS:
            raise PlanError(f"kind must be one of {', '.join(KINDS)}")
        hostname, note = clean(hostname, "hostname"), clean(note, "note")
        with self.transaction():
            p = self.get(prefix_id)
            if p.status in ("container",) or self.descendants(p):
                raise PlanError(f"{p.net} has sub-prefixes; put addresses in a leaf prefix")
            if p.status in ("reserved", "deprecated"):
                raise PlanError(f"{p.net} is {p.status}")
            taken = {
                unblob(a["ip"])
                for a in self.db.execute(
                    "SELECT a.ip FROM addresses a JOIN prefixes q ON q.id = a.prefix_id"
                    " WHERE q.vrf = ? AND q.version = ? AND a.ip >= ? AND a.ip <= ?",
                    (
                        p.vrf,
                        p.net.version,
                        blob(netmath.start_of(p.net), p.net.version),
                        blob(netmath.end_of(p.net), p.net.version),
                    ),
                ).fetchall()
            }
            lo, hi = self._usable_range(p.net)
            if ip is None:
                value = next(
                    (v for v in range(lo, min(hi, lo + len(taken) + 1) + 1) if v not in taken),
                    None,
                )
                if value is None:
                    raise PlanError(f"{p.net} is full")
            else:
                try:
                    addr = ipaddress.ip_address(ip.strip())
                except ValueError as exc:
                    raise PlanError(f"not an IP address: {ip[:40]!r}") from exc
                if addr.version != p.net.version or addr not in p.net:
                    raise PlanError(f"{addr} is not in {p.net}")
                value = int(addr)
                if not lo <= value <= hi:
                    raise PlanError(f"{addr} is the network or broadcast address of {p.net}")
                if value in taken:
                    raise PlanError(f"{addr} is already recorded")
            cur = self.db.execute(
                "INSERT INTO addresses (prefix_id, ip, hostname, kind, note) VALUES (?,?,?,?,?)",
                (prefix_id, blob(value, p.net.version), hostname, kind, note),
            )
            row = self.db.execute("SELECT * FROM addresses WHERE id = ?", (cur.lastrowid,)).fetchone()
            return self._address(row, p.net.version)

    @staticmethod
    def _usable_range(net: Net) -> tuple[int, int]:
        lo, hi = netmath.start_of(net), netmath.end_of(net)
        if net.version == 4 and net.prefixlen <= 30:
            return lo + 1, hi - 1
        return lo, hi

    def release_address(self, prefix_id: int, ip: str) -> None:
        p = self.get(prefix_id)
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError as exc:
            raise PlanError(f"not an IP address: {ip[:40]!r}") from exc
        cur = self.db.execute(
            "DELETE FROM addresses WHERE prefix_id = ? AND ip = ?",
            (prefix_id, blob(int(addr), p.net.version)),
        )
        if cur.rowcount == 0:
            raise PlanError(f"{addr} is not recorded in {p.net}")

    # ---- reporting -----------------------------------------------------------------------

    def utilization(self, p: Prefix) -> dict[str, Any]:
        """For a container: share of addresses given to sub-prefixes. For a LAN: share of usable addresses recorded."""
        kids = self.children(p)
        total = p.net.num_addresses
        if kids:
            used = sum(k.net.num_addresses for k in kids)
            return {
                "kind": "allocated",
                "used": used,
                "total": total,
                "ratio": used / total,
            }
        n = self.db.execute("SELECT COUNT(*) FROM addresses WHERE prefix_id = ?", (p.id,)).fetchone()[0]
        usable = netmath.usable_hosts(p.net)
        return {
            "kind": "addresses",
            "used": n,
            "total": usable,
            "ratio": n / usable if usable else 0.0,
        }

    def audit(self) -> list[str]:
        """Things that should not be true. Empty when the database is consistent."""
        issues: list[str] = []
        for p in self.all():
            for a in self.addresses(p.id):
                if a.ip not in p.net:
                    issues.append(f"{a.ip} is recorded in {p.net} but is outside it")
                lo, hi = self._usable_range(p.net)
                if not lo <= int(a.ip) <= hi:
                    issues.append(f"{a.ip} is the network or broadcast address of {p.net}")
            if self.descendants(p) and self.addresses(p.id):
                issues.append(f"{p.net} has both sub-prefixes and addresses")
        for vrf in {p.vrf for p in self.all()}:
            group = [(f"{p.net}#{p.id}", p.net) for p in self.all(vrf)]
            for c in netmath.find_conflicts(group):
                if c.kind == "duplicate":
                    issues.append(f"{c.inner_net} appears twice in vrf {vrf}")
        return issues
