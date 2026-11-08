"""Command line. Exit codes: 0 fine, 1 the input has a problem the tool found (check), 2 error or unsatisfiable request."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any

from subnetplan import __version__, netmath
from subnetplan.netmath import Net, PlanError, Request
from subnetplan.store import Prefix, Store

OK, PROBLEM, ERROR = 0, 1, 2
MAX_FILE = 5_000_000
DEFAULT_DB = "ipam.db"


def read_lines(path: str) -> list[str]:
    p = Path(path)
    try:
        if p.stat().st_size > MAX_FILE:
            raise PlanError(f"{path} is larger than {MAX_FILE} bytes")
        return p.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise PlanError(f"cannot read {path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise PlanError(f"{path} is not UTF-8 text") from exc


def parse_requests(items: list[str], file: str | None, p2p: set[str]) -> list[Request]:
    out: list[Request] = []
    raw = list(items)
    if file:
        for row in csv.reader(line for line in read_lines(file) if line.strip() and not line.lstrip().startswith("#")):
            if len(row) < 2:
                raise PlanError(f"{file}: expected 'name,hosts' per line")
            if row[0].strip().lower() == "name" and not row[1].strip().isdigit():
                continue  # header
            raw.append(f"{row[0].strip()}={row[1].strip()}")
    for item in raw:
        name, sep, hosts = item.partition("=")
        if not sep or not name.strip() or not hosts.strip().isdigit():
            raise PlanError(f"{item!r}: write name=hosts, for example office=120")
        out.append(Request(name.strip(), int(hosts), name.strip() in p2p))
    return out


def table(rows: list[list[str]], header: list[str]) -> str:
    widths = [max(len(str(r[i])) for r in [header, *rows]) for i in range(len(header))]
    lines = ["  ".join(str(c).ljust(w) for c, w in zip(header, widths, strict=True)).rstrip()]
    lines += ["  ".join(str(c).ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in rows]
    return "\n".join(lines)


def info(net: Net) -> dict[str, Any]:
    first, last = net.network_address, net.broadcast_address
    d: dict[str, Any] = {
        "network": str(net),
        "version": net.version,
        "prefixlen": net.prefixlen,
        "addresses": net.num_addresses,
        "usable_hosts": netmath.usable_hosts(net),
        "first": str(first),
        "last": str(last),
    }
    if net.version == 4:
        d["netmask"] = str(net.netmask)
        d["wildcard"] = str(net.hostmask)
        if net.prefixlen <= 30:
            d["first_usable"], d["last_usable"] = str(first + 1), str(last - 1)
    d["private"] = net.is_private
    return d


def cmd_info(a: argparse.Namespace) -> int:
    d = info(netmath.parse_net(a.network, strict=False))
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        for k, v in d.items():
            print(f"{k:13} {v}")
    return OK


def cmd_split(a: argparse.Namespace) -> int:
    net = netmath.parse_net(a.network)
    subnets = netmath.split_equal(net, a.parts) if a.parts else netmath.split_prefix(net, a.prefix)
    if a.json:
        print(json.dumps([str(s) for s in subnets]))
    else:
        print("\n".join(str(s) for s in subnets))
    return OK


def plan_to_dict(plan: netmath.Plan) -> dict[str, Any]:
    return {
        "parent": str(plan.parent),
        "allocations": [
            {
                "name": x.name,
                "network": str(x.net),
                "hosts_requested": x.hosts,
                "usable": x.usable,
            }
            for x in plan.allocations
        ],
        "unplaced": [{"name": n, "reason": why} for n, why in plan.unplaced],
        "free": [str(f) for f in plan.free],
        "utilization": round(plan.utilization, 4),
        "efficiency": round(plan.efficiency, 4),
    }


def print_plan(plan: netmath.Plan) -> None:
    rows = [[x.name, str(x.net), str(x.hosts), str(x.usable)] for x in plan.allocations]
    print(table(rows, ["name", "network", "asked", "usable"]))
    for name, why in plan.unplaced:
        print(f"NOT PLACED  {name}: {why}")
    print(
        f"\n{plan.addresses_allocated} of {plan.parent.num_addresses} addresses allocated ({plan.utilization:.1%}); "
        f"hosts asked for are {plan.efficiency:.1%} of the usable addresses handed out"
    )
    if plan.free:
        print("free: " + ", ".join(str(f) for f in plan.free))


def cmd_plan(a: argparse.Namespace) -> int:
    parent = netmath.parse_net(a.network)
    requests = parse_requests(a.need, a.file, set(a.p2p))
    if not requests:
        raise PlanError("give at least one --need name=hosts (or --file)")
    used = [netmath.parse_net(u) for u in a.used]
    plan = netmath.vlsm(parent, requests, growth_percent=a.growth, used=used)
    if a.json:
        print(json.dumps(plan_to_dict(plan), indent=2))
    else:
        print_plan(plan)
    return ERROR if plan.unplaced else OK


def cmd_summarize(a: argparse.Namespace) -> int:
    nets = [netmath.parse_net(n, strict=False) for n in a.networks]
    out = netmath.summarize(nets)
    print(json.dumps([str(n) for n in out]) if a.json else "\n".join(str(n) for n in out))
    return OK


def cmd_free(a: argparse.Namespace) -> int:
    free = netmath.free_blocks(netmath.parse_net(a.network), [netmath.parse_net(u) for u in a.used])
    print(json.dumps([str(n) for n in free]) if a.json else "\n".join(str(n) for n in free))
    return OK


def cmd_check(a: argparse.Namespace) -> int:
    """Check a list of prefixes (one per line: 'cidr' or 'cidr,name'): bad syntax, host bits, duplicates, nesting."""
    problems: list[str] = []
    notes: list[str] = []
    items: list[tuple[str, Net]] = []
    for number, line in enumerate(read_lines(a.file), 1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        cidr, _, name = text.partition(",")
        label = f"line {number}" + (f" ({name.strip()})" if name.strip() else "")
        try:
            items.append((label, netmath.parse_net(cidr)))
        except PlanError as exc:
            problems.append(f"{label}: {exc}")
    for c in netmath.find_conflicts(items):
        if c.kind == "duplicate":
            problems.append(f"{c.inner}: {c.inner_net} duplicates {c.outer}")
        else:
            notes.append(f"{c.inner}: {c.inner_net} is inside {c.outer} ({c.outer_net})")
    result = {
        "prefixes": len(items),
        "problems": problems,
        "nested": notes,
        "ok": not problems,
    }
    if a.json:
        print(json.dumps(result, indent=2))
    else:
        for p in problems:
            print(f"PROBLEM  {p}")
        for note in notes:
            print(f"nested   {note}")
        print(f"{len(items)} prefixes read; {len(problems)} problem(s), {len(notes)} nested")
    return PROBLEM if problems else OK


# ---- ipam ------------------------------------------------------------------------------------


def show_tree(store: Store, vrf: str | None) -> None:
    prefixes = store.all(vrf)
    rows = []
    depth: dict[int, int] = {}
    for p in prefixes:
        parent = store.parent_of(p)
        d = depth.get(parent.id, -1) + 1 if parent else 0
        depth[p.id] = d
        u = store.utilization(p)
        rows.append(
            [
                str(p.id),
                "  " * d + str(p.net),
                p.vrf,
                p.name,
                p.status,
                str(p.vlan or ""),
                f"{u['used']}/{u['total']} {u['kind']}",
            ]
        )
    print(table(rows, ["id", "prefix", "vrf", "name", "status", "vlan", "use"]) if rows else "(empty)")


def resolve(store: Store, ref: str, vrf: str) -> Prefix:
    if ref.isdigit():
        return store.get(int(ref))
    p = store.find(netmath.parse_net(ref), vrf)
    if p is None:
        raise PlanError(f"{ref} is not in the database (vrf {vrf})")
    return p


def cmd_ipam(a: argparse.Namespace) -> int:
    store = Store(a.db)
    try:
        op = a.ipam_cmd
        if op == "add":
            p = store.add_prefix(
                netmath.parse_net(a.network),
                name=a.name,
                vlan=a.vlan,
                vrf=a.vrf,
                status=a.status,
            )
            print(f"added {p.net} (id {p.id})")
        elif op == "ls":
            show_tree(store, a.vrf)
        elif op == "alloc":
            parent = resolve(store, a.parent, a.vrf)
            if a.need:
                requests = parse_requests(a.need, None, set())
                plan = store.allocate_plan(parent.id, requests, growth_percent=a.growth)
                print_plan(plan)
            else:
                p = store.allocate(
                    parent.id,
                    name=a.name,
                    hosts=a.hosts,
                    prefixlen=a.prefixlen,
                    growth_percent=a.growth,
                    vlan=a.vlan,
                )
                print(f"allocated {p.net} (id {p.id}) from {parent.net}")
        elif op == "free":
            for n in store.free(resolve(store, a.prefix, a.vrf)):
                print(n)
        elif op == "rm":
            removed = store.delete_prefix(resolve(store, a.prefix, a.vrf).id, force=a.force)
            print(f"deleted {removed} prefix(es)")
        elif op == "addr":
            p = resolve(store, a.prefix, a.vrf)
            x = store.add_address(p.id, hostname=a.hostname, ip=a.ip, kind=a.kind, note=a.note)
            print(f"{x.ip}  {x.kind}  {x.hostname}")
        elif op == "release":
            store.release_address(resolve(store, a.prefix, a.vrf).id, a.ip)
            print(f"released {a.ip}")
        elif op == "addrs":
            p = resolve(store, a.prefix, a.vrf)
            print(
                table(
                    [[str(x.ip), x.kind, x.hostname, x.note] for x in store.addresses(p.id)],
                    ["ip", "kind", "hostname", "note"],
                )
            )
        elif op == "audit":
            issues = store.audit()
            for i in issues:
                print(f"PROBLEM  {i}")
            print(f"{len(issues)} problem(s)")
            return PROBLEM if issues else OK
        return OK
    finally:
        store.close()


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cmd_serve(a: argparse.Namespace) -> int:
    try:
        import uvicorn

        from subnetplan.api import create_app
    except ImportError as exc:
        raise PlanError("the web interface needs: pip install 'subnetplan[web]'") from exc
    app = create_app(a.db)
    if not is_loopback(a.host):
        print(
            f"warning: {a.host} is not a loopback address and there is no authentication; "
            "anyone who can reach this port can change the database",
            file=sys.stderr,
        )
    print(
        f"serving http://{a.host}:{a.port}  (database {a.db}; no authentication, keep it on localhost or behind a proxy)"
    )
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
    return OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subnetplan",
        description="Subnet arithmetic, VLSM planning and a small IPAM.",
    )
    p.add_argument("--version", action="version", version=f"subnetplan {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("info", help="facts about a network")
    s.add_argument("network")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_info)

    s = sub.add_parser("split", help="divide a network")
    s.add_argument("network")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--parts", type=int, help="equal subnets (a power of two)")
    g.add_argument("--prefix", type=int, help="subnets of this prefix length")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_split)

    s = sub.add_parser("plan", help="VLSM: fit named host counts into a network, largest first")
    s.add_argument("network")
    s.add_argument("--need", action="append", default=[], metavar="NAME=HOSTS")
    s.add_argument("--file", help="CSV with name,hosts per line")
    s.add_argument("--growth", type=float, default=0.0, help="spare room, in percent")
    s.add_argument(
        "--p2p",
        action="append",
        default=[],
        metavar="NAME",
        help="this request is a point-to-point link (/31 or /127)",
    )
    s.add_argument(
        "--used",
        action="append",
        default=[],
        metavar="NET",
        help="a block that is already taken",
    )
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_plan)

    s = sub.add_parser("summarize", help="the fewest CIDR blocks that cover exactly the given networks")
    s.add_argument("networks", nargs="+")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_summarize)

    s = sub.add_parser("free", help="what is left of a network after removing some blocks")
    s.add_argument("network")
    s.add_argument("--used", action="append", default=[], metavar="NET")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_free)

    s = sub.add_parser(
        "check",
        help="check a file of prefixes for syntax, host bits, duplicates and nesting",
    )
    s.add_argument("file")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("ipam", help="the database")
    s.add_argument("--db", default=DEFAULT_DB)
    s.add_argument("--vrf", default="default")
    isub = s.add_subparsers(dest="ipam_cmd", required=True)
    x = isub.add_parser("add")
    x.add_argument("network")
    x.add_argument("--name", default="")
    x.add_argument("--vlan", type=int)
    x.add_argument(
        "--status",
        default="active",
        choices=["container", "active", "reserved", "deprecated"],
    )
    isub.add_parser("ls")
    x = isub.add_parser("alloc", help="carve subnets out of a prefix")
    x.add_argument("parent", help="id or CIDR")
    x.add_argument("--name", default="")
    x.add_argument("--hosts", type=int)
    x.add_argument("--prefixlen", type=int)
    x.add_argument("--growth", type=float, default=0.0)
    x.add_argument("--vlan", type=int)
    x.add_argument(
        "--need",
        action="append",
        default=[],
        metavar="NAME=HOSTS",
        help="several at once (VLSM), all or nothing",
    )
    x = isub.add_parser("free")
    x.add_argument("prefix")
    x = isub.add_parser("rm")
    x.add_argument("prefix")
    x.add_argument("--force", action="store_true")
    x = isub.add_parser("addr", help="record an address (the lowest free one unless --ip)")
    x.add_argument("prefix")
    x.add_argument("--hostname", default="")
    x.add_argument("--ip")
    x.add_argument("--kind", default="host", choices=["host", "gateway", "reserved"])
    x.add_argument("--note", default="")
    x = isub.add_parser("addrs")
    x.add_argument("prefix")
    x = isub.add_parser("release")
    x.add_argument("prefix")
    x.add_argument("ip")
    isub.add_parser("audit", help="look for inconsistencies")
    s.set_defaults(fn=cmd_ipam)

    s = sub.add_parser("serve", help="web interface and API (pip install 'subnetplan[web]')")
    s.add_argument("--db", default=DEFAULT_DB)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args))
    except PlanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return ERROR
