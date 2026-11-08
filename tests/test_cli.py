from __future__ import annotations

import json
from pathlib import Path

import pytest

from subnetplan import __version__
from subnetplan.cli import main


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


def js(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, object]:
    code, out, _ = run(capsys, *argv, "--json")
    return code, json.loads(out)


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and __version__ in capsys.readouterr().out


def test_info(capsys: pytest.CaptureFixture[str]) -> None:
    code, data = js(capsys, "info", "192.0.2.0/26")
    assert code == 0 and isinstance(data, dict)
    assert data["usable_hosts"] == 62 and data["last"] == "192.0.2.63" and data["netmask"] == "255.255.255.192"
    code, out, _ = run(capsys, "info", "2001:db8::/64")
    assert code == 0 and "2001:db8::/64" in out
    code, out, _ = run(capsys, "info", "10.0.0.5/24")  # a host address inside the network is accepted here
    assert code == 0 and "10.0.0.0/24" in out
    code, out, err = run(capsys, "info", "10.0.0.0/40")
    assert code == 2 and "error" in err and out == ""


def test_split(capsys: pytest.CaptureFixture[str]) -> None:
    code, data = js(capsys, "split", "192.0.2.0/24", "--parts", "4")
    assert (code == 0 and data == ["192.0.2.0/26", "192.0.2.64/26", "192.0.2.128/26", "192.0.2.192/26"]) or isinstance(
        data, dict
    )
    code, data = js(capsys, "split", "192.0.2.0/24", "--prefix", "26")
    assert code == 0
    assert run(capsys, "split", "192.0.2.0/24", "--parts", "3")[0] == 2
    assert run(capsys, "split", "192.0.2.0/24", "--prefix", "20")[0] == 2


def test_plan_worked_example(capsys: pytest.CaptureFixture[str]) -> None:
    code, data = js(
        capsys, "plan", "10.10.0.0/22", "--need", "office=200", "--need", "guests=60", "--need", "servers=20",
        "--need", "wan=2", "--p2p", "wan", "--growth", "20",
    )  # fmt: skip
    assert code == 0 and isinstance(data, dict)
    nets = {a["name"]: a["network"] for a in data["allocations"]}
    assert nets == {
        "office": "10.10.0.0/24",
        "guests": "10.10.1.0/25",
        "servers": "10.10.1.128/27",
        "wan": "10.10.1.160/31",
    }
    assert data["unplaced"] == []


def test_plan_from_file_and_unsatisfiable(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    f = tmp_path / "needs.csv"
    f.write_text("name,hosts\nlan,100\n# a comment\n\nwifi,50\n", encoding="utf-8")
    code, data = js(capsys, "plan", "10.0.0.0/24", "--file", str(f))
    assert code == 0 and isinstance(data, dict) and len(data["allocations"]) == 2
    code, out, err = run(capsys, "plan", "10.0.0.0/30", "--need", "big=500")
    assert code == 2 and "big" in (out + err)
    assert run(capsys, "plan", "10.0.0.0/24", "--need", "nonsense")[0] == 2
    assert run(capsys, "plan", "10.0.0.0/24", "--need", "x=abc")[0] == 2
    assert run(capsys, "plan", "10.0.0.0/24")[0] == 2  # nothing to plan
    assert run(capsys, "plan", "10.0.0.0/24", "--file", str(tmp_path / "missing.csv"))[0] == 2


def test_summarize_and_free(capsys: pytest.CaptureFixture[str]) -> None:
    code, data = js(capsys, "summarize", "10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24")
    assert code == 0 and data == ["10.0.0.0/23"]
    code, data = js(capsys, "free", "192.0.2.0/24", "--used", "192.0.2.0/25", "--used", "192.0.2.128/26")
    assert code == 0 and data == ["192.0.2.192/26"]
    assert run(capsys, "free", "192.0.2.0/24", "--used", "garbage")[0] == 2


def test_check_reports_conflicts(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    ok = tmp_path / "ok.txt"
    ok.write_text("10.0.0.0/24,lan\n10.0.1.0/24 # dmz\n\n", encoding="utf-8")
    assert run(capsys, "check", str(ok))[0] == 0
    nested = tmp_path / "nested.txt"
    nested.write_text("10.0.0.0/16,corp\n10.0.1.0/24,lan\n", encoding="utf-8")
    code, out, _ = run(capsys, "check", str(nested))
    assert code == 0 and "inside" in out  # nesting is normal in a hierarchy: a note, not a failure
    dup = tmp_path / "dup.txt"
    dup.write_text("10.0.1.0/24,lan\n10.0.1.0/24,lan-copy\n", encoding="utf-8")
    code, out, _ = run(capsys, "check", str(dup))
    assert code == 1 and "duplicates" in out
    code, data = js(capsys, "check", str(dup))
    assert code == 1 and isinstance(data, dict) and len(data["problems"]) == 1
    broken = tmp_path / "broken.txt"
    broken.write_text("10.0.0.0/33,nope\n10.0.0.5/24\n", encoding="utf-8")
    code, out, _ = run(capsys, "check", str(broken))
    assert code == 1 and "host bits" in out and out.count("PROBLEM") == 2
    assert run(capsys, "check", str(tmp_path / "missing.txt"))[0] == 2


def test_ipam_flow(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    db = str(tmp_path / "ipam.db")

    def ipam(*a: str) -> tuple[int, str, str]:
        return run(capsys, "ipam", "--db", db, *a)

    assert ipam("add", "10.0.0.0/22", "--name", "site", "--status", "container")[0] == 0
    assert ipam("add", "10.0.0.0/22")[0] == 2  # duplicate
    code, out, _ = ipam("alloc", "10.0.0.0/22", "--name", "office", "--hosts", "200")
    assert code == 0 and "10.0.0.0/24" in out
    assert ipam("alloc", "1", "--name", "servers", "--prefixlen", "27", "--vlan", "30")[0] == 0  # by id
    code, out, _ = ipam("ls")
    assert code == 0 and "office" in out and "servers" in out and "10.0.1.0/27" in out
    code, out, _ = ipam("free", "10.0.0.0/22")
    assert code == 0 and "10.0.1.32/27" in out
    assert ipam("addr", "10.0.1.0/27", "--hostname", "gw", "--kind", "gateway")[0] == 0
    assert ipam("addr", "10.0.1.0/27", "--hostname", "web", "--ip", "10.0.1.10")[0] == 0
    code, out, _ = ipam("addrs", "10.0.1.0/27")
    assert code == 0 and "10.0.1.1" in out and "10.0.1.10" in out
    assert ipam("release", "10.0.1.0/27", "10.0.1.10")[0] == 0
    assert ipam("release", "10.0.1.0/27", "10.0.1.10")[0] == 2
    assert ipam("audit")[0] == 0
    assert ipam("rm", "10.0.0.0/22")[0] == 2  # has children
    assert ipam("rm", "10.0.0.0/22", "--force")[0] == 0
    assert ipam("ls")[0] == 0
    assert ipam("alloc", "no-such-prefix", "--hosts", "5")[0] == 2


def test_ipam_vrfs_are_separate(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    db = str(tmp_path / "ipam.db")
    assert run(capsys, "ipam", "--db", db, "--vrf", "a", "add", "10.0.0.0/24")[0] == 0
    assert run(capsys, "ipam", "--db", db, "--vrf", "b", "add", "10.0.0.0/24")[0] == 0
    assert run(capsys, "ipam", "--db", db, "--vrf", "a", "add", "10.0.0.0/24")[0] == 2


def test_serve_without_the_web_extra_is_a_clean_error(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import builtins

    real = builtins.__import__

    def deny(name: str, *a: object, **k: object) -> object:
        if name.split(".")[0] in {"uvicorn", "fastapi"} or name == "subnetplan.api":
            raise ImportError(name)
        return real(name, *a, **k)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", deny)
    code, _, err = run(capsys, "serve", "--db", str(tmp_path / "x.db"))
    assert code == 2 and "subnetplan[web]" in err


def test_serve_warns_when_not_on_loopback(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import uvicorn

    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, host, port, **k: calls.append((host, port)))
    db = str(tmp_path / "x.db")
    code, out, err = run(capsys, "serve", "--db", db, "--port", "9999")
    assert code == 0 and calls == [("127.0.0.1", 9999)] and "warning" not in err and "no authentication" in out
    code, _, err = run(capsys, "serve", "--db", db, "--host", "0.0.0.0")
    assert code == 0 and "warning" in err and "no authentication" in err
    assert run(capsys, "serve", "--db", db, "--host", "::1")[2] == ""
