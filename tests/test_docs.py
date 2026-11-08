"""The numbers quoted in the docs must be the ones in docs/report.json."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = json.loads((ROOT / "docs" / "report.json").read_text(encoding="utf-8"))
TEXT = "\n".join((ROOT / p).read_text(encoding="utf-8") for p in ("README.md", "docs/evaluation.md"))


def test_report_is_a_full_run_with_no_mismatches() -> None:
    assert REPORT["quick"] is False
    assert REPORT["correctness"]["total_mismatches"] == 0
    assert (
        f"{REPORT['correctness']['total_cases']} " in TEXT or f"**{REPORT['correctness']['total_cases']} cases" in TEXT
    )


def test_fragmentation_table() -> None:
    res = REPORT["fragmentation"]["results"]
    for occ in ("60%", "75%", "90%"):
        for strategy in ("buddy best-fit", "first-fit", "next-fit"):
            assert f"{res[occ][strategy]['avoidable_pct']:.2f} %" in TEXT, (occ, strategy)
    b90 = res["90%"]["buddy best-fit"]
    assert (
        f"{b90['runs_with_fewer_refusals_than_first_fit']} of the {REPORT['fragmentation']['runs_per_cell']} runs"
        in TEXT
    )


def test_speed_numbers() -> None:
    perf = REPORT["performance"]
    sweep = {r["n"]: r["seconds"] for r in perf["find_conflicts_sweep"]}
    assert f"{sweep[500000]:.2f} s" in TEXT and f"{sweep[100000]:.2f} s" in TEXT
    quad = {r["n"]: r["seconds"] for r in perf["find_conflicts_quadratic_reference"]}
    assert f"{quad[4000]:.2f} s" in TEXT
    assert f"{perf['vlsm'][-1]['seconds']:.2f} s" in TEXT
    assert str(perf["pool_churn"]["ops_per_second"]) in TEXT


def test_every_check_is_listed() -> None:
    for name, check in REPORT["correctness"]["checks"].items():
        assert str(check["cases"]) in TEXT, name
