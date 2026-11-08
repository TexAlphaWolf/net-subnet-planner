from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx2")

from fastapi.testclient import TestClient

from subnetplan.api import create_app


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    with TestClient(create_app(str(tmp_path / "api.db"))) as c:
        yield c


def make(client: TestClient, cidr: str, **extra: object) -> dict:
    r = client.post("/api/prefixes", json={"cidr": cidr, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_security_headers_on_every_kind_of_response(client: TestClient) -> None:
    for r in (client.get("/"), client.get("/api/prefixes"), client.get("/static/app.js"), client.get("/nope")):
        h = r.headers
        csp = h["content-security-policy"]
        assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp and "base-uri 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert h["x-content-type-options"] == "nosniff" and h["referrer-policy"] == "no-referrer"
        assert h["cache-control"] == "no-store"


def test_pages_and_static_allow_list(client: TestClient) -> None:
    index = client.get("/")
    assert (
        index.status_code == 200 and index.headers["content-type"].startswith("text/html") and "<script" in index.text
    )
    assert client.get("/static/app.js").headers["content-type"].split(";")[0] in {
        "text/javascript",
        "application/javascript",
    }
    assert client.get("/static/style.css").status_code == 200
    for bad in ("index.html", "../api.py", "..%2fapi.py", "nope.js", "%2e%2e/%2e%2e/etc/passwd", "app.js/../../x"):
        assert client.get(f"/static/{bad}").status_code == 404, bad
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code in (200, 404)


def test_prefix_lifecycle(client: TestClient) -> None:
    root = make(client, "10.0.0.0/22", name="site", status="container")
    assert root["parent_id"] is None and root["utilization"]["used"] == 0
    r = client.post(f"/api/prefixes/{root['id']}/allocate", json={"name": "office", "hosts": 200, "vlan": 10})
    assert r.status_code == 201 and r.json()["cidr"] == "10.0.0.0/24" and r.json()["parent_id"] == root["id"]
    r = client.post(f"/api/prefixes/{root['id']}/allocate", json={"name": "dmz", "prefixlen": 27})
    assert r.json()["cidr"] == "10.0.1.0/27"
    assert client.get(f"/api/prefixes/{root['id']}/free").json()[0] == "10.0.1.32/27"
    assert client.get("/api/prefixes").json()[0]["utilization"] == {
        "kind": "allocated",
        "used": 288,
        "total": 1024,
        "ratio": 0.28125,
    }
    listed = client.get("/api/prefixes").json()
    assert [p["cidr"] for p in listed] == ["10.0.0.0/22", "10.0.0.0/24", "10.0.1.0/27"]
    assert client.get("/api/prefixes", params={"vrf": "nothing"}).json() == []
    assert client.delete(f"/api/prefixes/{root['id']}").status_code == 422  # has children
    assert client.delete(f"/api/prefixes/{root['id']}", params={"force": "true"}).json() == {"deleted": 3}
    assert client.delete(f"/api/prefixes/{root['id']}").status_code == 404


def test_validation_and_errors(client: TestClient) -> None:
    cases = [
        ({"cidr": "10.0.0.0/33"}, 422), ({"cidr": "10.0.0.5/24"}, 422), ({"cidr": "x" * 100}, 422), ({}, 422),
        ({"cidr": "10.0.0.0/24", "vlan": 0}, 422), ({"cidr": "10.0.0.0/24", "vlan": 5000}, 422),
        ({"cidr": "10.0.0.0/24", "status": "weird"}, 422), ({"cidr": "10.0.0.0/24", "name": "n" * 500}, 422),
        ({"cidr": "10.0.0.0/24", "name": "bad\x00name"}, 422), ({"cidr": 5}, 422),
    ]  # fmt: skip
    for body, code in cases:
        r = client.post("/api/prefixes", json=body)
        assert r.status_code == code, (body, r.text)
    assert (
        client.post("/api/prefixes", content=b"not json", headers={"content-type": "application/json"}).status_code
        == 422
    )
    make(client, "10.0.0.0/24")
    assert client.post("/api/prefixes", json={"cidr": "10.0.0.0/24"}).status_code == 422  # duplicate
    pid = client.get("/api/prefixes").json()[0]["id"]
    for body in ({}, {"name": "x"}, {"name": "x", "hosts": 5, "prefixlen": 28}, {"hosts": 0}, {"hosts": 5, "growth": -1},
                 {"prefixlen": 200}, {"hosts": 2**70}):  # fmt: skip
        assert client.post(f"/api/prefixes/{pid}/allocate", json=body).status_code == 422, body
    assert client.post("/api/prefixes/999/allocate", json={"hosts": 5}).status_code == 404
    assert client.get("/api/prefixes/999/free").status_code == 404
    assert client.get("/api/prefixes/abc/free").status_code == 422


def test_error_bodies_carry_no_internals(client: TestClient) -> None:
    r = client.post("/api/prefixes", json={"cidr": "bogus"})
    assert (
        r.status_code == 422 and "Traceback" not in r.text and "/home/" not in r.text and "site-packages" not in r.text
    )


def test_plan_preview_and_apply(client: TestClient) -> None:
    body = {
        "network": "10.0.0.0/24",
        "requests": [{"name": "lan", "hosts": 100}, {"name": "wan", "hosts": 2, "p2p": True}],
        "growth": 10,
    }
    r = client.post("/api/plan", json=body)
    assert r.status_code == 200
    plan = r.json()
    assert [(a["name"], a["network"]) for a in plan["allocations"]] == [
        ("lan", "10.0.0.0/25"),
        ("wan", "10.0.0.128/31"),
    ]
    assert client.get("/api/prefixes").json() == []  # a preview saves nothing
    assert client.post("/api/plan", json={**body, "network": None}).status_code == 422
    assert client.post("/api/plan", json={**body, "network": "junk"}).status_code == 422
    assert (
        client.post("/api/plan", json={**body, "used": ["10.0.0.0/25"]}).json()["allocations"][0]["network"]
        == "10.0.0.128/25"
    )
    assert client.post("/api/plan", json={"network": "10.0.0.0/30", "requests": [{"name": "big", "hosts": 99}]}).json()[
        "unplaced"
    ]

    root = make(client, "10.0.0.0/24", status="container")
    r = client.post(f"/api/prefixes/{root['id']}/plan", json=body)
    assert r.status_code == 201 and len(r.json()["allocations"]) == 2
    assert [p["name"] for p in client.get("/api/prefixes").json()][1:] == ["lan", "wan"]
    r = client.post(f"/api/prefixes/{root['id']}/plan", json={"requests": [{"name": "huge", "hosts": 5000}]})
    assert r.status_code == 422 and "huge" in r.text
    assert len(client.get("/api/prefixes").json()) == 3  # all or nothing
    assert (
        client.post(
            "/api/plan", json={"network": "10.0.0.0/8", "requests": [{"name": "a", "hosts": 1}] * 1001}
        ).status_code
        == 422
    )


def test_addresses(client: TestClient) -> None:
    lan = make(client, "192.0.2.0/29")
    base = f"/api/prefixes/{lan['id']}/addresses"
    assert client.post(base, json={"hostname": "gw", "kind": "gateway"}).json()["ip"] == "192.0.2.1"
    assert client.post(base, json={"hostname": "web", "ip": "192.0.2.5"}).json()["ip"] == "192.0.2.5"
    assert [a["ip"] for a in client.get(base).json()] == ["192.0.2.1", "192.0.2.5"]
    for body in (
        {"ip": "192.0.2.0"},
        {"ip": "192.0.2.7"},
        {"ip": "192.0.2.5"},
        {"ip": "10.0.0.1"},
        {"ip": "zzz"},
        {"kind": "bogus"},
        {"note": "n" * 500},
    ):
        assert client.post(base, json=body).status_code == 422, body
    assert client.get(f"/api/prefixes/{lan['id']}").status_code in (404, 405)
    assert client.delete(f"{base}/192.0.2.5").json() == {"released": "192.0.2.5"}
    assert client.delete(f"{base}/192.0.2.5").status_code == 404
    assert client.delete(f"{base}/not-an-ip").status_code == 422
    assert client.get("/api/prefixes").json()[0]["utilization"]["used"] == 1


def test_audit_endpoint(client: TestClient) -> None:
    make(client, "10.0.0.0/24")
    assert client.get("/api/audit").json() == []


def test_vrfs_via_api(client: TestClient) -> None:
    make(client, "10.0.0.0/24", vrf="red")
    make(client, "10.0.0.0/24", vrf="blue")
    assert [p["vrf"] for p in client.get("/api/prefixes", params={"vrf": "red"}).json()] == ["red"]
    assert len(client.get("/api/prefixes").json()) == 2


def test_concurrent_requests_do_not_corrupt_the_database(client: TestClient) -> None:
    from concurrent.futures import ThreadPoolExecutor

    root = make(client, "10.0.0.0/16", status="container")

    def one(i: int) -> int:
        return client.post(f"/api/prefixes/{root['id']}/allocate", json={"name": f"n{i}", "prefixlen": 24}).status_code

    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(one, range(40)))
    assert codes.count(201) == 40
    cidrs = [p["cidr"] for p in client.get("/api/prefixes").json()][1:]
    assert len(set(cidrs)) == 40 and client.get("/api/audit").json() == []
