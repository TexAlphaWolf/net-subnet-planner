"""Render docs/demo.png from the real web app: a real server, a real database, a real browser.

pip install -e ".[web,dev]" && playwright install chromium
python tools/screenshot.py
"""

from __future__ import annotations

import socket
import tempfile
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright

from subnetplan.api import create_app
from subnetplan.netmath import Request
from subnetplan.store import Store

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.png"


def seed(db: str) -> None:
    s = Store(db)
    from subnetplan.netmath import parse_net as n

    site = s.add_prefix(n("10.20.0.0/16"), name="Headquarters", status="container")
    s.add_prefix(n("2001:db8:20::/48"), name="HQ IPv6", status="container")
    campus = s.allocate(site.id, name="Campus", prefixlen=20, status="container")
    s.allocate_plan(
        campus.id,
        [
            Request("Offices", 400),
            Request("Wi-Fi staff", 250),
            Request("Wi-Fi guests", 120),
            Request("Printers", 30),
            Request("Cameras", 60),
        ],
        growth_percent=20,
    )
    for p in s.children(campus):
        if p.name == "Printers":
            s.add_address(p.id, hostname="gw-printers", kind="gateway")
            for host in ("print-01", "print-02", "plotter"):
                s.add_address(p.id, hostname=host)
    s.allocate(site.id, name="Servers", hosts=120, growth_percent=25, vlan=30)
    s.allocate(site.id, name="DMZ", hosts=28)
    s.allocate(site.id, name="WAN link", hosts=2, p2p=True)
    s.close()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "demo.db")
        seed(db)
        port = free_port()
        server = uvicorn.Server(uvicorn.Config(create_app(db), host="127.0.0.1", port=port, log_level="error"))
        threading.Thread(target=server.run, daemon=True).start()
        while not server.started:
            time.sleep(0.05)
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1180, "height": 900}, device_scale_factor=2)
            errors: list[str] = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto(f"http://127.0.0.1:{port}/")
            page.wait_for_selector("#tree tbody tr")
            page.select_option("#parent", index=0)  # 10.20.0.0/16, the first prefix
            page.fill("textarea[name=requests]", "Lab = 90\nVoice = 45\nIoT = 200")
            page.click("button[value=preview]")
            page.wait_for_selector("#result table")
            page.locator("#tree tbody tr", has_text="Printers").get_by_text("addresses").first.click()
            page.wait_for_selector("#addr-table tbody tr")
            page.screenshot(path=str(OUT), full_page=True)
            browser.close()
        server.should_exit = True
        if errors:
            raise SystemExit("the page logged errors: " + "; ".join(errors))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
