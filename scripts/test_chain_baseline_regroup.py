"""Tests for the H-03 chain scaffold-resumption collision fix.

Covers `_validate_chain_baseline_not_regrouped` and
`_generate_chain_baseline_regroup_retry_hint` (plamen_validators.py).

The driver writes a MECHANICAL_BASELINE scaffold before Chain Agent 1 runs.
If the agent obeys the generic RESUMPTION PROTOCOL it can skip PHASE 1 grouping,
leaving the scaffold in place — post-inventory depth findings (DA-*) then never
get mapped and are dropped from the report. The mechanical gate must FAIL on the
two observable signatures of that no-op and PASS a healthy grouped run.

GENERIC ONLY: neutral IDs (INV-*/DA-*/GRP-* shapes), no protocol/finding names.

Run: pytest scripts/test_chain_baseline_regroup.py -v
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _pv():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    return importlib.import_module("plamen_validators")


def _cp():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    return importlib.import_module("chain_prep")


# ───────────────────────────── fixtures ─────────────────────────────


def _write_inventory(sp: Path, ids: list[str]) -> None:
    lines = ["# Findings Inventory", ""]
    for fid in ids:
        lines.append(f"### Finding [{fid}]: {fid} title")
        lines.append("**Severity**: Medium")
        lines.append(f"**Location**: src/Foo.sol:L{10 + len(lines)}")
        lines.append("**Root Cause**: example root cause text")
        lines.append("")
    (sp / "findings_inventory.md").write_text("\n".join(lines), encoding="utf-8")


def _write_depth(sp: Path, name: str, ids: list[str]) -> None:
    lines = [f"# Depth Agent {name}", ""]
    for fid in ids:
        lines.append(f"### Finding [{fid}]: {fid} depth title")
        lines.append("**Verdict**: CONFIRMED")
        lines.append("**Severity**: Medium")
        lines.append(f"**Location**: src/Bar.sol:L{20 + len(lines)}")
        lines.append("")
    (sp / f"depth_{name}_findings.md").write_text("\n".join(lines), encoding="utf-8")


def _write_grouped(sp: Path, rows: list[tuple[str, str]], stamped: bool) -> None:
    """rows: list of (constituent_id, hypothesis_id)."""
    head_status = "**Status**: MECHANICAL_BASELINE\n\n" if stamped else ""
    hyp = (
        "# Hypotheses\n\n"
        + head_status
        + "| Hypothesis ID | Severity | Title | Constituent Findings | Location | Notes |\n"
        + "|---------------|----------|-------|----------------------|----------|-------|\n"
    )
    by_hyp: dict[str, list[str]] = {}
    for cid, hid in rows:
        by_hyp.setdefault(hid, []).append(cid)
    for hid, cids in by_hyp.items():
        hyp += f"| {hid} | Medium | grouped | {', '.join(cids)} | UNKNOWN | grouped |\n"
    (sp / "hypotheses.md").write_text(hyp, encoding="utf-8")

    fm = (
        "# Finding Mapping\n\n"
        + head_status
        + "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        + "|------------|---------------|----------------|-------|\n"
    )
    for cid, hid in rows:
        fm += f"| {cid} | {hid} | GROUPED | grouped |\n"
    (sp / "finding_mapping.md").write_text(fm, encoding="utf-8")


# ───────────────────────────── tests ─────────────────────────────


def test_drop_reproduction_stamp_and_unmapped(tmp_path: Path) -> None:
    """The genuine no-op: scaffold un-overwritten + DA-3 unmapped."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2", "INV-3"])
    pv._write_chain_passthrough_outputs(tmp_path, "test")  # stamped scaffold
    _write_depth(tmp_path, "x", ["DA-3"])

    issues = pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")
    assert issues, "expected violations on un-overwritten scaffold"
    joined = " | ".join(issues)
    assert "MECHANICAL_BASELINE" in joined, "stamp issue missing"
    assert "DA-3" in joined, "unmapped depth-ID issue missing"


def test_drop_reproduction_depth_id_only(tmp_path: Path) -> None:
    """Stamp removed (partial overwrite) but DA-3 still unmapped — CHECK 2 alone."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2", "INV-3"])
    _write_grouped(
        tmp_path,
        [("INV-1", "GRP-1"), ("INV-2", "GRP-1"), ("INV-3", "GRP-2")],
        stamped=False,
    )
    _write_depth(tmp_path, "x", ["DA-3"])

    issues = pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")
    assert len(issues) == 1, f"expected exactly one issue, got {issues}"
    assert "DA-3" in issues[0]
    assert "MECHANICAL_BASELINE" not in issues[0]


def test_healthy_grouped_run_no_fire(tmp_path: Path) -> None:
    """Recall-safety anchor: a real grouped run produces zero issues."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2", "INV-3"])
    _write_grouped(
        tmp_path,
        [
            ("INV-1", "GRP-1"),
            ("INV-2", "GRP-1"),
            ("INV-3", "GRP-2"),
            ("DA-3", "GRP-2"),
        ],
        stamped=False,
    )
    _write_depth(tmp_path, "x", ["DA-3"])

    issues = pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")
    assert issues == [], f"healthy grouped run should not fire: {issues}"


def test_light_mode_skip(tmp_path: Path) -> None:
    """Gate only runs in core/thorough; light mode never blocks."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2", "INV-3"])
    pv._write_chain_passthrough_outputs(tmp_path, "test")  # stamped scaffold
    _write_depth(tmp_path, "x", ["DA-3"])

    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "light") == []


def test_chain_summary_cross_ref_not_declared(tmp_path: Path) -> None:
    """CHECK 2 sources IDs ONLY from `### Finding [ID]:` depth headings.

    A REF-9 mentioned in chain_summaries_compact.md prose but not declared in
    any depth_*_findings.md must not be treated as a dropped depth finding.
    """
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2"])
    _write_grouped(
        tmp_path,
        [("INV-1", "GRP-1"), ("INV-2", "GRP-1"), ("DA-7", "GRP-2")],
        stamped=False,
    )
    _write_depth(tmp_path, "x", ["DA-7"])  # only genuinely-declared depth ID
    (tmp_path / "chain_summaries_compact.md").write_text(
        "# Chain Summaries\n\nSome prose referencing REF-9 as a refuted item.\n",
        encoding="utf-8",
    )

    issues = pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")
    assert issues == [], f"cross-ref-only ID must not fire: {issues}"


def test_retry_hint_generation(tmp_path: Path) -> None:
    pv = _pv()
    issues = [
        "hypotheses.md still carries MECHANICAL_BASELINE stamp",
        "depth finding DA-3 declared in depth_x_findings.md is absent",
    ]
    hint = pv._generate_chain_baseline_regroup_retry_hint(issues)
    assert "ATTEMPT 2 RETRY" in hint
    assert "DA-3" in hint
    assert "OVERWRITE" in hint
    assert pv._generate_chain_baseline_regroup_retry_hint([]) == ""


# ─── M1/M2 (recall-build-plan §5.3): INVARIANT + AXISGAP as STEP-0a-LC enablers ───


def test_invariant_candidate_is_low_confidence_enabler(tmp_path: Path) -> None:
    """An M1 INVARIANT candidate (promoted with Verdict NEEDS_VERIFICATION) is a
    STEP-0a-LC low-confidence chain enabler — via the unverified verdict route,
    and also via an ENUMGAP source-id tag when present."""
    cp = _cp()
    assert cp._is_unverified_enabler(
        {"verdict": "NEEDS_VERIFICATION", "source_ids": ["INVARIANT"]}
    )
    assert cp._is_unverified_enabler(
        {"verdict": "", "source_ids": ["INVARIANT", "ENUMGAP"]}
    )


def test_axisgap_candidate_is_low_confidence_enabler(tmp_path: Path) -> None:
    """An M2 AXISGAP candidate (promoted with Verdict NEEDS_VERIFICATION) is a
    STEP-0a-LC low-confidence chain enabler."""
    cp = _cp()
    assert cp._is_unverified_enabler(
        {"verdict": "NEEDS_VERIFICATION", "source_ids": ["AXISGAP"]}
    )


def test_confirmed_finding_not_low_confidence_enabler(tmp_path: Path) -> None:
    """Recall-safety anchor: a CONFIRMED finding with no unverified marker is NOT
    misclassified as a low-confidence enabler (it belongs to the dangerous-state
    baseline instead)."""
    cp = _cp()
    assert not cp._is_unverified_enabler(
        {"verdict": "CONFIRMED", "source_ids": ["INV-3"]}
    )


# ──────────────────── FIX 1: inline auto-map tests ────────────────────


def _write_depth_verdict(sp: Path, name: str, items: list[tuple[str, str, str]]) -> None:
    """items: list of (finding_id, verdict, severity)."""
    lines = [f"# Depth Agent {name}", ""]
    for fid, verdict, sev in items:
        lines.append(f"### Finding [{fid}]: {fid} depth title for {fid}")
        lines.append(f"**Verdict**: {verdict}")
        lines.append(f"**Severity**: {sev}")
        lines.append(f"**Location**: src/Bar.sol:L{20 + len(lines)}")
        lines.append("")
    (sp / f"depth_{name}_findings.md").write_text("\n".join(lines), encoding="utf-8")


def test_automap_full_skip_self_heal(tmp_path: Path) -> None:
    """Full-skip case: stamped scaffold + CONFIRMED DA-3 -> auto-map maps DA-3,
    strips the MECHANICAL_BASELINE stamp, and a gate re-run returns []."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2", "INV-3"])
    pv._write_chain_passthrough_outputs(tmp_path, "test")  # stamped scaffold
    _write_depth_verdict(tmp_path, "x", [("DA-3", "CONFIRMED", "High")])

    # Gate fires before repair.
    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")

    mapped = pv._auto_map_unmapped_depth_findings(tmp_path)
    assert "DA-3" in mapped

    fm = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    hyp = (tmp_path / "hypotheses.md").read_text(encoding="utf-8")
    assert "DA-3" in fm and "DA-3" in hyp
    assert pv._MECHANICAL_BASELINE_STAMP not in fm
    assert pv._MECHANICAL_BASELINE_STAMP not in hyp

    # Re-run gate after repair: clean.
    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough") == []


def test_automap_partial_grouping_append(tmp_path: Path) -> None:
    """Partial-grouping case: unstamped grouped mapping missing DA-3 ->
    auto-map appends DA-3, gate re-run returns []."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2"])
    _write_grouped(
        tmp_path,
        [("INV-1", "GRP-1"), ("INV-2", "GRP-2")],
        stamped=False,
    )
    _write_depth_verdict(tmp_path, "x", [("DA-3", "CONFIRMED", "Medium")])

    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")

    mapped = pv._auto_map_unmapped_depth_findings(tmp_path)
    assert mapped == ["DA-3"]

    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough") == []


def test_automap_producer_refuted_finding_is_still_retained(tmp_path: Path) -> None:
    """Producer REFUTED prose has no central negative-closure authority."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2"])
    _write_grouped(
        tmp_path,
        [("INV-1", "GRP-1"), ("INV-2", "GRP-2")],
        stamped=False,
    )
    _write_depth_verdict(tmp_path, "x", [("DA-9", "REFUTED", "Medium")])

    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough")

    mapped = pv._auto_map_unmapped_depth_findings(tmp_path)
    assert mapped == ["DA-9"]
    fm = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert "DA-9" in fm
    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough") == []


def test_automap_mixed_verdicts(tmp_path: Path) -> None:
    """All producer verdicts are retained pending central disposition."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1"])
    _write_grouped(tmp_path, [("INV-1", "GRP-1")], stamped=False)
    _write_depth_verdict(
        tmp_path,
        "x",
        [
            ("DA-1", "CONFIRMED", "High"),
            ("DA-2", "PARTIAL", "Medium"),
            ("DA-3", "CONTESTED", "Low"),
            ("DA-4", "REFUTED", "Medium"),
        ],
    )
    mapped = set(pv._auto_map_unmapped_depth_findings(tmp_path))
    assert mapped == {"DA-1", "DA-2", "DA-3", "DA-4"}
    fm = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert "DA-4" in fm
    # Gate clean only after every producer verdict is preserved.
    assert pv._validate_chain_baseline_not_regrouped(tmp_path, "thorough") == []


def test_automap_title_severity_preserved(tmp_path: Path) -> None:
    """Recall-safety: title and severity are preserved verbatim from the depth
    block in the appended rows."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1"])
    _write_grouped(tmp_path, [("INV-1", "GRP-1")], stamped=False)
    _write_depth_verdict(tmp_path, "x", [("DA-7", "CONFIRMED", "Critical")])

    pv._auto_map_unmapped_depth_findings(tmp_path)
    hyp = (tmp_path / "hypotheses.md").read_text(encoding="utf-8")
    da7_row = [ln for ln in hyp.splitlines() if "DA-7" in ln]
    assert da7_row, "DA-7 hypothesis row missing"
    row = da7_row[0]
    assert "Critical" in row, f"severity not preserved: {row}"
    assert "depth title for DA-7" in row, f"title not preserved: {row}"


def test_automap_idempotent(tmp_path: Path) -> None:
    """Running auto-map twice does not duplicate rows."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1"])
    _write_grouped(tmp_path, [("INV-1", "GRP-1")], stamped=False)
    _write_depth_verdict(tmp_path, "x", [("DA-5", "CONFIRMED", "Medium")])

    first = pv._auto_map_unmapped_depth_findings(tmp_path)
    assert first == ["DA-5"]
    second = pv._auto_map_unmapped_depth_findings(tmp_path)
    assert second == [], "second run must be a no-op"

    fm = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert fm.count("| DA-5 |") == 1, "DA-5 mapping row duplicated"


def test_automap_healthy_noop(tmp_path: Path) -> None:
    """Healthy fully-mapped run: auto-map is a no-op and adds no rows."""
    pv = _pv()
    _write_inventory(tmp_path, ["INV-1", "INV-2"])
    _write_grouped(
        tmp_path,
        [("INV-1", "GRP-1"), ("INV-2", "GRP-2"), ("DA-3", "GRP-2")],
        stamped=False,
    )
    _write_depth_verdict(tmp_path, "x", [("DA-3", "CONFIRMED", "Medium")])

    fm_before = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    mapped = pv._auto_map_unmapped_depth_findings(tmp_path)
    assert mapped == []
    fm_after = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    assert fm_before == fm_after, "healthy run must not mutate finding_mapping.md"
