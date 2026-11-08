from __future__ import annotations

import random
import sqlite3
from pathlib import Path

import pytest

from conftest import bitmap
from subnetplan.netmath import PlanError, Request, parse_net
from subnetplan.store import Store

N = parse_net


def test_add_and_find(store: Store) -> None:
    p = store.add_prefix(N("10.0.0.0/16"), name="  corp ", status="container")
    assert p.name == "corp" and p.vrf == "default" and p.vlan is None
    assert store.find(N("10.0.0.0/16")) == p and store.find(N("10.0.0.0/16"), "other") is None
    with pytest.raises(PlanError, match="already exists"):
        store.add_prefix(N("10.0.0.0/16"))
    other = store.add_prefix(N("10.0.0.0/16"), vrf="other")  # same block in another VRF is fine
    assert other.id != p.id
    with pytest.raises(PlanError, match="no prefix"):
        store.get(999)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"vlan": 0},
        {"vlan": 4095},
        {"vlan": "10"},
        {"status": "bogus"},
        {"name": "x" * 500},
        {"name": "a\x00b"},
        {"vrf": "a\nb"},
    ],
)
def test_add_prefix_validation(store: Store, kwargs: dict[str, object]) -> None:
    with pytest.raises(PlanError):
        store.add_prefix(N("10.0.0.0/24"), **kwargs)  # type: ignore[arg-type]


def test_tree_queries(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/16"), status="container")
    mid = store.add_prefix(N("10.0.0.0/20"), status="container")
    leaf = store.add_prefix(N("10.0.1.0/24"))
    far = store.add_prefix(N("10.0.64.0/24"))
    v6 = store.add_prefix(N("2001:db8::/32"), status="container")
    assert store.parent_of(leaf) == mid and store.parent_of(mid) == root and store.parent_of(root) is None
    assert {p.id for p in store.descendants(root)} == {mid.id, leaf.id, far.id}
    assert [p.id for p in store.children(root)] == [mid.id, far.id]  # leaf hangs off mid
    assert store.descendants(v6) == [] and store.parent_of(v6) is None  # families never mix
    assert store.parent_of(store.add_prefix(N("10.0.1.0/24"), vrf="b")) is None  # nor do VRFs
    assert [p.id for p in store.all("default")] == [root.id, mid.id, leaf.id, far.id, v6.id]


def test_tree_matches_brute_force() -> None:
    rng = random.Random(7)
    s = Store(":memory:")
    from conftest import random_net

    seen = set()
    for _ in range(120):
        n = random_net(rng, 4, 20, 28, base=0x0A000000)
        if n in seen:
            continue
        seen.add(n)
        s.add_prefix(n)
    for p in s.all():
        kids = {d.net for d in s.descendants(p)}
        assert kids == {o for o in seen if o != p.net and o.subnet_of(p.net)}
        parents = [o for o in seen if o != p.net and p.net.subnet_of(o)]
        want = max(parents, key=lambda o: o.prefixlen) if parents else None
        got = s.parent_of(p)
        assert (got.net if got else None) == want
    s.close()


def test_allocate_best_fit(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/24"), status="container")
    a = store.allocate(root.id, name="a", hosts=100)
    b = store.allocate(root.id, name="b", prefixlen=26, vlan=20)
    c = store.allocate(root.id, name="c", hosts=2, p2p=True)
    assert (str(a.net), str(b.net), str(c.net)) == ("10.0.0.0/25", "10.0.0.128/26", "10.0.0.192/31")
    assert b.vlan == 20 and c.vrf == root.vrf
    store.delete_prefix(a.id)
    assert str(store.allocate(root.id, name="again", hosts=50).net) == "10.0.0.0/26"  # the freed hole is reused
    assert sum(f.num_addresses for f in store.free(root)) == 256 - 64 - 64 - 2
    with pytest.raises(PlanError, match="no free /23"):
        store.allocate(root.id, name="x", prefixlen=23)
    with pytest.raises(PlanError, match="either"):
        store.allocate(root.id, name="x")
    with pytest.raises(PlanError, match="either"):
        store.allocate(root.id, name="x", hosts=3, prefixlen=28)


def test_allocate_refuses_wrong_parents(store: Store) -> None:
    lan = store.add_prefix(N("10.0.0.0/24"))
    store.add_address(lan.id, hostname="h")
    with pytest.raises(PlanError, match="holds 1 address"):
        store.allocate(lan.id, name="x", prefixlen=26)
    res = store.add_prefix(N("10.1.0.0/24"), status="reserved")
    with pytest.raises(PlanError, match="reserved"):
        store.allocate(res.id, name="x", prefixlen=26)


def test_allocate_plan_is_all_or_nothing(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/24"), status="container")
    with pytest.raises(PlanError, match="big"):
        store.allocate_plan(root.id, [Request("ok", 50), Request("big", 400)])
    assert store.children(root) == []  # nothing was saved
    plan = store.allocate_plan(root.id, [Request("lan", 100), Request("wan", 2, True)])
    assert [str(a.net) for a in plan.allocations] == ["10.0.0.0/25", "10.0.0.128/31"]
    assert [p.name for p in store.children(root)] == ["lan", "wan"]
    with pytest.raises(PlanError, match="same name"):
        store.allocate_plan(root.id, [Request("lan", 100), Request("lan", 100)])


def test_failed_transaction_rolls_back(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/24"), status="container")
    with pytest.raises(RuntimeError), store.transaction():
        store.add_prefix(N("10.0.0.0/25"))
        raise RuntimeError("boom")
    assert store.children(root) == []


def test_delete_prefix(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/16"), status="container")
    mid = store.add_prefix(N("10.0.0.0/24"))
    store.add_address(mid.id, hostname="h")
    with pytest.raises(PlanError, match="use force"):
        store.delete_prefix(root.id)
    with pytest.raises(PlanError, match="use force"):
        store.delete_prefix(mid.id)
    assert store.delete_prefix(root.id, force=True) == 2
    assert store.all() == [] and store.db.execute("SELECT COUNT(*) FROM addresses").fetchone()[0] == 0
    with pytest.raises(PlanError):
        store.delete_prefix(root.id)


def test_addresses(store: Store) -> None:
    lan = store.add_prefix(N("192.0.2.0/29"))
    gw = store.add_address(lan.id, hostname="gw", kind="gateway")
    h = store.add_address(lan.id, hostname="web", note=" primary ")
    assert (str(gw.ip), str(h.ip), h.note) == ("192.0.2.1", "192.0.2.2", "primary")
    pinned = store.add_address(lan.id, hostname="db", ip="192.0.2.6")
    assert str(pinned.ip) == "192.0.2.6"
    assert [str(a.ip) for a in store.addresses(lan.id)] == ["192.0.2.1", "192.0.2.2", "192.0.2.6"]
    for ip, msg in [("192.0.2.0", "network or broadcast"), ("192.0.2.7", "network or broadcast"), ("192.0.2.2", "already recorded"),
                    ("192.0.3.2", "not in"), ("nonsense", "not an IP"), ("2001:db8::1", "not in")]:  # fmt: skip
        with pytest.raises(PlanError, match=msg):
            store.add_address(lan.id, ip=ip)
    with pytest.raises(PlanError, match="kind"):
        store.add_address(lan.id, kind="bogus")
    for _ in range(3):
        store.add_address(lan.id)
    with pytest.raises(PlanError, match="full"):
        store.add_address(lan.id)
    store.release_address(lan.id, "192.0.2.2")
    assert str(store.add_address(lan.id).ip) == "192.0.2.2"  # lowest free again
    with pytest.raises(PlanError, match="not recorded"):
        store.release_address(lan.id, "10.9.9.9")
    with pytest.raises(PlanError, match="not an IP"):
        store.release_address(lan.id, "x")


def test_address_edge_prefixes(store: Store) -> None:
    p31 = store.add_prefix(N("192.0.2.0/31"))
    assert [str(store.add_address(p31.id).ip) for _ in range(2)] == ["192.0.2.0", "192.0.2.1"]  # RFC 3021: both usable
    p32 = store.add_prefix(N("192.0.2.9/32"))
    assert str(store.add_address(p32.id).ip) == "192.0.2.9"
    p6 = store.add_prefix(N("2001:db8::/126"))
    assert [str(store.add_address(p6.id).ip) for _ in range(4)] == [
        "2001:db8::",
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
    ]
    with pytest.raises(PlanError, match="full"):
        store.add_address(p6.id)
    big = store.add_prefix(N("2001:db8:1::/64"))
    top = "2001:db8:1:0:ffff:ffff:ffff:ffff"
    assert str(store.add_address(big.id, ip=top).ip) == top


def test_addresses_only_in_leaf_prefixes(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/24"))
    store.add_prefix(N("10.0.0.0/25"))
    with pytest.raises(PlanError, match="sub-prefixes"):
        store.add_address(root.id)
    res = store.add_prefix(N("10.1.0.0/24"), status="deprecated")
    with pytest.raises(PlanError, match="deprecated"):
        store.add_address(res.id)


def test_utilization(store: Store) -> None:
    root = store.add_prefix(N("10.0.0.0/24"), status="container")
    a = store.allocate(root.id, name="a", prefixlen=26)
    assert store.utilization(root) == {"kind": "allocated", "used": 64, "total": 256, "ratio": 0.25}
    for _ in range(31):
        store.add_address(a.id)
    u = store.utilization(a)
    assert (u["kind"], u["used"], u["total"]) == ("addresses", 31, 62) and u["ratio"] == 0.5


def test_audit(store: Store, tmp_path: Path) -> None:
    root = store.add_prefix(N("10.0.0.0/24"), status="container")
    lan = store.allocate(root.id, name="lan", prefixlen=26)
    store.add_address(lan.id, hostname="h")
    assert store.audit() == []
    # corrupt the database behind the API's back; the audit must notice each kind of damage
    store.db.execute("UPDATE addresses SET ip = ?", (bytes([10, 0, 0, 0]),))  # the network address
    assert any("network or broadcast" in i for i in store.audit())
    store.db.execute("UPDATE addresses SET ip = ?", (bytes([172, 16, 0, 5]),))
    assert any("outside it" in i for i in store.audit())
    store.db.execute("DELETE FROM addresses")
    store.db.execute(
        "INSERT INTO addresses (prefix_id, ip, hostname, kind, note) VALUES (?, ?, '', 'host', '')",
        (root.id, bytes([10, 0, 0, 9])),
    )
    assert any("both sub-prefixes and addresses" in i for i in store.audit())


def test_persistence_and_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "ipam.db"
    with_data = Store(path)
    p = with_data.add_prefix(N("10.0.0.0/24"), name="x")
    with_data.add_address(p.id, hostname="h", ip="10.0.0.10")
    with_data.close()
    again = Store(path)
    assert again.get(p.id).name == "x" and str(again.addresses(p.id)[0].ip) == "10.0.0.10"
    again.close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE meta SET value = '99' WHERE key = 'schema'")
    raw.commit()
    raw.close()
    with pytest.raises(PlanError, match="schema"):
        Store(path)


def test_blob_order_is_numeric_order(store: Store) -> None:
    """Fixed-width big-endian blobs: SQLite's byte-wise ORDER BY equals numeric order, also across 255/256."""
    lan = store.add_prefix(N("10.0.0.0/23"))
    for ip in ("10.0.1.0", "10.0.0.255", "10.0.0.2", "10.0.1.254"):
        store.add_address(lan.id, ip=ip)
    got = [int(a.ip) for a in store.addresses(lan.id)]
    assert got == sorted(got)
    covered = bitmap([N("10.0.0.0/23")], 0, 1 << 32)
    assert all(g in covered for g in got)


def test_a_file_that_is_not_a_database_is_refused_cleanly(tmp_path: Path) -> None:
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(PlanError, match="not a usable"):
        Store(junk)
    junk.unlink()  # the handle was closed, so the file can go (matters on Windows)
