"""HTTP API and web interface (pip install 'subnetplan[web]'). No authentication: bind to localhost or put a proxy in front."""

from __future__ import annotations

import threading
from collections.abc import Callable
from importlib import resources
from typing import Any, TypeVar

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from subnetplan import __version__, netmath
from subnetplan.netmath import PlanError
from subnetplan.store import Prefix, Store

T = TypeVar("T")
ASSETS = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
}
CSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


class PrefixIn(BaseModel):
    cidr: str = Field(max_length=64)
    name: str = Field(default="", max_length=120)
    vlan: int | None = Field(default=None, ge=1, le=4094)
    vrf: str = Field(default="default", max_length=120)
    status: str = Field(default="active", max_length=20)


class AllocateIn(BaseModel):
    name: str = Field(default="", max_length=120)
    hosts: int | None = Field(default=None, ge=1, le=2**64)
    prefixlen: int | None = Field(default=None, ge=0, le=128)
    growth: float = Field(default=0.0, ge=0, le=1000)
    vlan: int | None = Field(default=None, ge=1, le=4094)


class RequestIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    hosts: int = Field(ge=1, le=2**64)
    p2p: bool = False


class PlanIn(BaseModel):
    network: str | None = Field(default=None, max_length=64)
    requests: list[RequestIn] = Field(max_length=1000)
    growth: float = Field(default=0.0, ge=0, le=1000)
    used: list[str] = Field(default_factory=list, max_length=1000)


class AddressIn(BaseModel):
    hostname: str = Field(default="", max_length=120)
    ip: str | None = Field(default=None, max_length=64)
    kind: str = Field(default="host", max_length=20)
    note: str = Field(default="", max_length=120)


def create_app(db_path: str) -> FastAPI:
    store = Store(db_path)
    lock = threading.Lock()  # one SQLite connection: serialise its use
    app = FastAPI(title="subnetplan", version=__version__, docs_url=None, redoc_url=None)

    def guarded(fn: Callable[[], T]) -> T:
        with lock:
            try:
                return fn()
            except PlanError as exc:
                text = str(exc)
                code = 404 if text.startswith("no prefix with id") or "is not recorded" in text else 422
                raise HTTPException(code, text) from exc

    def prefix_json(p: Prefix) -> dict[str, Any]:
        parent = store.parent_of(p)
        return {
            "id": p.id,
            "cidr": str(p.net),
            "version": p.net.version,
            "vrf": p.vrf,
            "name": p.name,
            "vlan": p.vlan,
            "status": p.status,
            "parent_id": parent.id if parent else None,
            "utilization": store.utilization(p),
        }

    @app.middleware("http")
    async def headers(request: Request, call_next: Callable[[Request], Any]) -> Response:
        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(PlanError)
    async def plan_error(_: Request, exc: PlanError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=422)

    @app.get("/api/prefixes")
    def list_prefixes(vrf: str | None = None) -> list[dict[str, Any]]:
        return guarded(lambda: [prefix_json(p) for p in store.all(vrf)])

    @app.post("/api/prefixes", status_code=201)
    def add_prefix(body: PrefixIn) -> dict[str, Any]:
        return guarded(
            lambda: prefix_json(
                store.add_prefix(
                    netmath.parse_net(body.cidr), name=body.name, vlan=body.vlan, vrf=body.vrf, status=body.status
                )
            )
        )

    @app.delete("/api/prefixes/{prefix_id}")
    def delete_prefix(prefix_id: int, force: bool = False) -> dict[str, int]:
        return guarded(lambda: {"deleted": store.delete_prefix(prefix_id, force=force)})

    @app.get("/api/prefixes/{prefix_id}/free")
    def free(prefix_id: int) -> list[str]:
        return guarded(lambda: [str(n) for n in store.free(store.get(prefix_id))])

    @app.post("/api/prefixes/{prefix_id}/allocate", status_code=201)
    def allocate(prefix_id: int, body: AllocateIn) -> dict[str, Any]:
        return guarded(
            lambda: prefix_json(
                store.allocate(
                    prefix_id,
                    name=body.name,
                    hosts=body.hosts,
                    prefixlen=body.prefixlen,
                    growth_percent=body.growth,
                    vlan=body.vlan,
                )
            )
        )

    @app.post("/api/prefixes/{prefix_id}/plan", status_code=201)
    def apply_plan(prefix_id: int, body: PlanIn) -> dict[str, Any]:
        reqs = [netmath.Request(r.name, r.hosts, r.p2p) for r in body.requests]
        plan = guarded(lambda: store.allocate_plan(prefix_id, reqs, growth_percent=body.growth))
        return plan_json(plan)

    @app.post("/api/plan")
    def preview(body: PlanIn) -> dict[str, Any]:
        if not body.network:
            raise HTTPException(422, "network is required")

        def run() -> dict[str, Any]:
            reqs = [netmath.Request(r.name, r.hosts, r.p2p) for r in body.requests]
            used = [netmath.parse_net(u) for u in body.used]
            return plan_json(
                netmath.vlsm(netmath.parse_net(body.network or ""), reqs, growth_percent=body.growth, used=used)
            )

        return guarded(run)

    @app.get("/api/prefixes/{prefix_id}/addresses")
    def addresses(prefix_id: int) -> list[dict[str, Any]]:
        return guarded(
            lambda: [
                {"ip": str(a.ip), "hostname": a.hostname, "kind": a.kind, "note": a.note}
                for a in store.addresses(prefix_id)
            ]
        )

    @app.post("/api/prefixes/{prefix_id}/addresses", status_code=201)
    def add_address(prefix_id: int, body: AddressIn) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            a = store.add_address(prefix_id, hostname=body.hostname, ip=body.ip, kind=body.kind, note=body.note)
            return {"ip": str(a.ip), "hostname": a.hostname, "kind": a.kind, "note": a.note}

        return guarded(run)

    @app.delete("/api/prefixes/{prefix_id}/addresses/{ip}")
    def release(prefix_id: int, ip: str) -> dict[str, str]:
        guarded(lambda: store.release_address(prefix_id, ip))
        return {"released": ip}

    @app.get("/api/audit")
    def audit() -> list[str]:
        return guarded(store.audit)

    def asset(name: str) -> Response:
        data = resources.files("subnetplan").joinpath("web", name).read_bytes()
        return Response(data, media_type=ASSETS[name])

    @app.get("/", include_in_schema=False)
    def index() -> Response:
        return asset("index.html")

    @app.get("/static/{name}", include_in_schema=False)
    def static(name: str) -> Response:
        if name not in ASSETS or name == "index.html":
            raise HTTPException(404, "not found")
        return asset(name)

    return app


def plan_json(plan: netmath.Plan) -> dict[str, Any]:
    return {
        "parent": str(plan.parent),
        "allocations": [
            {"name": x.name, "network": str(x.net), "hosts": x.hosts, "usable": x.usable} for x in plan.allocations
        ],
        "unplaced": [{"name": n, "reason": why} for n, why in plan.unplaced],
        "free": [str(f) for f in plan.free],
        "utilization": plan.utilization,
        "efficiency": plan.efficiency,
    }
