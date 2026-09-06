"""Tests for PLAN B — chain self-restatement collapse (duplication class).

Covers:
  * `_validate_chain_self_restatement` (plamen_validators.py) — flags chains
    that merely RESTATE a single constituent at a higher tier, while
    PRESERVING a genuine compound chain (recall-safety).
  * `_parse_chain_constituents` / extended `_parse_hypothesis_constituents`
    (plamen_parsers.py) — chain ID -> [Finding A, Finding B], excluding
    justified compound chains.
  * `_dedup_queue_by_hypothesis` chain carve-out — collapses an unjustified
    chain row with its constituent at the constituent severity.

GENERIC ONLY: neutral IDs (H-08/M-07 shapes), no protocol/finding names.

Run: pytest scripts/test_chain_self_restatement.py -v
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _mods():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    pv = importlib.import_module("plamen_validators")
    pp = importlib.import_module("plamen_parsers")
    return pv, pp


# ───────────────────────────── fixtures ─────────────────────────────


def _write_inventory(sp: Path, findings: list[dict]) -> None:
    """findings: list of {id, severity, location, root_cause, title?}."""
    lines = ["# Findings Inventory", ""]
    for f in findings:
        lines.append(f"### Finding [{f['id']}]: {f.get('title', f['id'] + ' title')}")
        lines.append(f"**Severity**: {f['severity']}")
        lines.append(f"**Location**: {f['location']}")
        lines.append(f"**Root Cause**: {f['root_cause']}")
        lines.append("")
    (sp / "findings_inventory.md").write_text("\n".join(lines), encoding="utf-8")


def _chain_section(
    chain_id: str,
    a_id: str,
    b_id: str | None,
    *,
    justified: bool,
    combined_impact: str = "NONE",
    severity: str = "High",
) -> str:
    """Render one chain hypothesis section in phase4c-chain-prompt.md format."""
    blocks = [
        f"## Chain Hypothesis {chain_id}",
        "### Blocked Finding (A)",
        f"- **ID**: {a_id}, **Title**: blocked attack",
        "- **Original Verdict**: PARTIAL, **Missing Precondition**: state X, **Type**: STATE",
    ]
    if b_id is not None:
        blocks += [
            "### Enabler Finding (B)",
            f"- **ID**: {b_id}, **Title**: enabler finding",
            "- **Original Verdict**: CONFIRMED, **Postcondition Created**: state X, **Type**: STATE",
        ]
    j = "YES" if justified else "NO"
    ids = a_id if b_id is None else f"{a_id},{b_id}"
    blocks += [
        "### Severity Reassessment",
        f"Chain Severity: {severity}",
        f"Constituents: {ids} | Severity-Upgrade-Justified: {j} | Combined-Impact: {combined_impact}",
        "",
    ]
    return "\n".join(blocks)


def _write_chain(sp: Path, *sections: str) -> None:
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n" + "\n".join(sections), encoding="utf-8"
    )


# ──────────────────── STEP 2: validator (under-merge) ────────────────────


def test_single_constituent_chain_flagged(tmp_path):
    """(a) 1-constituent chain with no Combined-Impact -> flagged."""
    pv, _ = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium",
         "location": "A.sol:L10 foo()", "root_cause": "missing bound check in foo"},
    ])
    # B omitted entirely -> only one constituent resolves.
    _write_chain(tmp_path, _chain_section("CH-01", "M-07", None, justified=False))
    issues = pv._validate_chain_self_restatement(tmp_path, "core")
    assert any("CH-01" in i for i in issues), issues


def test_two_same_function_high_jaccard_flagged(tmp_path):
    """(b) 2 constituents, same file+function, Jaccard>=0.5, no justification."""
    pv, _ = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium", "location": "A.sol:L10 foo()",
         "root_cause": "missing bound check overflow in foo accounting"},
        {"id": "M-09", "severity": "Medium", "location": "A.sol:L12 foo()",
         "root_cause": "missing bound check overflow in foo accounting path"},
    ])
    _write_chain(tmp_path, _chain_section("CH-02", "M-07", "M-09", justified=False))
    issues = pv._validate_chain_self_restatement(tmp_path, "core")
    assert any("CH-02" in i for i in issues), issues


def test_genuine_compound_chain_preserved(tmp_path):
    """RECALL-SAFETY: justified chain with concrete Combined-Impact -> NOT flagged."""
    pv, _ = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium", "location": "A.sol:L10 foo()",
         "root_cause": "missing bound check in foo"},
        {"id": "M-23", "severity": "Medium", "location": "B.sol:L80 settle()",
         "root_cause": "stale price snapshot in settle"},
    ])
    _write_chain(tmp_path, _chain_section(
        "CH-03", "M-07", "M-23", justified=True,
        combined_impact="attacker drains 100% of pool by chaining foo into settle",
        severity="High",
    ))
    issues = pv._validate_chain_self_restatement(tmp_path, "core")
    assert not any("CH-03" in i for i in issues), issues


def test_distinct_functions_no_justification_not_flagged_as_restatement(tmp_path):
    """2 constituents in DIFFERENT functions, no justification: not a same-bug
    restatement (handled by STEP 4 carve-out, not the (b) same-func gate)."""
    pv, _ = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium", "location": "A.sol:L10 foo()",
         "root_cause": "missing bound check in foo"},
        {"id": "M-23", "severity": "Medium", "location": "B.sol:L80 settle()",
         "root_cause": "stale price snapshot in settle"},
    ])
    _write_chain(tmp_path, _chain_section("CH-04", "M-07", "M-23", justified=False))
    issues = pv._validate_chain_self_restatement(tmp_path, "core")
    # Different file+function -> the (b) same-bug signature does not fire.
    assert not any("CH-04" in i for i in issues), issues


def test_light_mode_skips(tmp_path):
    pv, _ = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium",
         "location": "A.sol:L10 foo()", "root_cause": "missing bound check in foo"},
    ])
    _write_chain(tmp_path, _chain_section("CH-01", "M-07", None, justified=False))
    assert pv._validate_chain_self_restatement(tmp_path, "light") == []


def test_missing_chain_file_no_raise(tmp_path):
    pv, _ = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium",
         "location": "A.sol:L10 foo()", "root_cause": "x"},
    ])
    assert pv._validate_chain_self_restatement(tmp_path, "core") == []


def test_retry_hint_generated(tmp_path):
    pv, _ = _mods()
    hint = pv._generate_chain_self_restatement_retry_hint(["CH-01 restates M-07"])
    assert "SELF-RESTATEMENT" in hint
    assert "CH-01" in hint
    assert pv._generate_chain_self_restatement_retry_hint([]) == ""


# ──────────────── STEP 3: parser ingests chain constituents ────────────────


def test_parse_chain_constituents_unjustified(tmp_path):
    _, pp = _mods()
    _write_chain(tmp_path, _chain_section("CH-01", "M-07", "M-09", justified=False))
    links = pp._parse_chain_constituents(tmp_path)
    assert links.get("CH-01") == ["M-07", "M-09"], links


def test_parse_chain_constituents_excludes_justified(tmp_path):
    """Genuine compound chain is NOT linked (kept separate)."""
    _, pp = _mods()
    _write_chain(tmp_path, _chain_section(
        "CH-03", "M-07", "M-23", justified=True,
        combined_impact="drains pool", severity="High",
    ))
    links = pp._parse_chain_constituents(tmp_path)
    assert "CH-03" not in links, links


def test_parse_chain_constituents_single(tmp_path):
    _, pp = _mods()
    _write_chain(tmp_path, _chain_section("CH-05", "M-07", None, justified=False))
    links = pp._parse_chain_constituents(tmp_path)
    assert links.get("CH-05") == ["M-07"], links


def test_justified_chain_with_all_standalone_constituents_is_linked(tmp_path):
    """Precision fix #2: a chain self-marked Severity-Upgrade-Justified=YES whose
    constituents ALL also appear standalone is a double-count -> it must be LINKED
    for collapse despite the YES flag (a CH-* row beside its standalone parts)."""
    _, pp = _mods()
    # chain High, constituents also High -> NO elevation -> pure double-count.
    _write_chain(tmp_path, _chain_section(
        "CH-03", "M-07", "M-23", justified=True,
        combined_impact="drains pool", severity="High",
    ))
    sev = {"M-07": "High", "M-23": "High"}
    links = pp._parse_chain_constituents(tmp_path, standalone_severities=sev)
    assert links.get("CH-03") == ["M-07", "M-23"], links
    # legacy call (no standalone set) still excludes it (backward-compatible)
    assert "CH-03" not in pp._parse_chain_constituents(tmp_path)


def test_justified_chain_with_partial_standalone_stays_separate(tmp_path):
    """If only SOME constituents stand alone, the chain is NOT a pure
    double-count -> keep it separate (a genuine compound is preserved)."""
    _, pp = _mods()
    _write_chain(tmp_path, _chain_section(
        "CH-04", "M-07", "M-23", justified=True,
        combined_impact="novel sustained drain", severity="High",
    ))
    # only M-07 stands alone (M-23 absent) -> override does NOT fire
    links = pp._parse_chain_constituents(
        tmp_path, standalone_severities={"M-07": "High"})
    assert "CH-04" not in links, links


def test_justified_chain_that_elevates_severity_stays_separate(tmp_path):
    """A GENUINE elevation (chain High > Medium constituents) is preserved even
    when all constituents stand alone — the research-confirmed exception."""
    _, pp = _mods()
    _write_chain(tmp_path, _chain_section(
        "CH-05", "M-07", "M-23", justified=True,
        combined_impact="novel critical drain", severity="High",
    ))
    sev = {"M-07": "Medium", "M-23": "Medium"}  # chain High > Medium -> elevates
    links = pp._parse_chain_constituents(tmp_path, standalone_severities=sev)
    assert "CH-05" not in links, links


def test_hypothesis_constituents_includes_chains(tmp_path):
    """Raw chain links are available only to the grouping gate/repair path.

    Ordinary consumers fail closed to independent work until the typed
    grouping authority accepts an equivalence relation.
    """
    _, pp = _mods()
    _write_chain(tmp_path, _chain_section("CH-01", "M-07", "M-09", justified=False))
    mapping = pp._parse_hypothesis_constituents(tmp_path)
    assert "CH-01" not in mapping, mapping

    raw_mapping = pp._parse_hypothesis_constituents(
        tmp_path, apply_chain_grouping_authority=False
    )
    assert raw_mapping.get("CH-01") == ["M-07", "M-09"], raw_mapping


# ──────────── STEP 3: dedup-queue collapse inherits constituent sev ────────────


def _write_queue(sp: Path, rows: list[dict]) -> None:
    lines = [
        "# Verification Queue",
        "",
        "| Queue # | Finding ID | Severity | Location | Title |",
        "|---------|-----------|----------|----------|-------|",
    ]
    for i, r in enumerate(rows, 1):
        lines.append(
            f"| {i} | {r['finding id']} | {r['severity']} | "
            f"{r.get('location','')} | {r.get('title','')} |"
        )
    (sp / "verification_queue.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_dedup_chain_without_independent_equivalence_stays_separate(tmp_path):
    """A chain proposal cannot collapse constituents or alter severity until
    an independently bound typed equivalence decision authorizes that action.
    """
    _, pp = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium", "location": "A.sol:L10 foo()",
         "root_cause": "missing bound check overflow in foo accounting"},
        {"id": "M-09", "severity": "Medium", "location": "A.sol:L12 foo()",
         "root_cause": "missing bound check overflow in foo accounting path"},
    ])
    _write_chain(tmp_path, _chain_section(
        "CH-01", "M-07", "M-09", justified=False, severity="High"))
    _write_queue(tmp_path, [
        {"finding id": "M-07", "severity": "Medium", "location": "A.sol:L10"},
        {"finding id": "M-09", "severity": "Medium", "location": "A.sol:L12"},
        {"finding id": "CH-01", "severity": "High", "location": "A.sol:L10"},
    ])
    removed = pp._dedup_queue_by_hypothesis(tmp_path)
    assert removed == 0, "unapproved chain grouping must not collapse work"
    rows = pp.parse_verification_queue_rows(tmp_path)
    by_id = {
        (r.get("finding id") or "").upper(): r
        for r in rows
    }
    assert set(by_id) == {"M-07", "M-09", "CH-01"}, rows
    assert by_id["M-07"].get("severity", "").lower() == "medium", rows
    assert by_id["M-09"].get("severity", "").lower() == "medium", rows
    assert by_id["CH-01"].get("severity", "").lower() == "high", rows


def test_dedup_justified_chain_stays_separate(tmp_path):
    """RECALL-SAFETY: a justified compound chain is not collapsed into its
    constituent (stays its own queue row)."""
    _, pp = _mods()
    _write_inventory(tmp_path, [
        {"id": "M-07", "severity": "Medium", "location": "A.sol:L10 foo()",
         "root_cause": "missing bound check in foo"},
        {"id": "M-23", "severity": "Medium", "location": "B.sol:L80 settle()",
         "root_cause": "stale price snapshot in settle"},
    ])
    _write_chain(tmp_path, _chain_section(
        "CH-03", "M-07", "M-23", justified=True,
        combined_impact="drains entire pool", severity="High"))
    _write_queue(tmp_path, [
        {"finding id": "M-07", "severity": "Medium", "location": "A.sol:L10"},
        {"finding id": "M-23", "severity": "Medium", "location": "B.sol:L80"},
        {"finding id": "CH-03", "severity": "High", "location": "A.sol:L10"},
    ])
    pp._dedup_queue_by_hypothesis(tmp_path)
    rows = pp.parse_verification_queue_rows(tmp_path)
    ids = {(r.get("finding id") or "").upper() for r in rows}
    # CH-03 must survive as a distinct (High) row — not merged away.
    assert "CH-03" in ids, rows
    ch = [r for r in rows if (r.get("finding id") or "").upper() == "CH-03"]
    assert ch[0].get("severity", "").lower() == "high", ch


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
