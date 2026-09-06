"""TASK D — CHAIN-RESTATEMENT triage false-positive (root fix).

`_validate_report_index_triage_safety` previously WARNED that Medium+ excluded
chains lacked an allowed non-body reason even when those chains were
CHAIN-RESTATEMENT (NO-upgrade, absorbed into their body constituents) — a
legitimate consolidation per report-template rules.

Root fix: accept CHAIN-RESTATEMENT / CHAIN-DOWNGRADE (absorbed-into-body,
Severity-Upgrade-Justified: NO) as an allowed non-body reason, equivalent to
CONSOLIDATED.

Negative control (recall-safety): a chain with Severity-Upgrade-Justified: YES
(a real combined-impact compound finding) excluded WITHOUT a body home is a
genuinely dropped compound finding and MUST STILL be flagged.

GENERIC ONLY: neutral IDs (CH-0N / M-0N shapes), no protocol/finding names.

Run: pytest scripts/test_triage_chain_restatement.py -v
"""
from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path


def _pv():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
    return importlib.import_module("plamen_validators")


# ───────────────────────────── fixtures ─────────────────────────────


def _chain_section(
    chain_id: str,
    a_id: str,
    b_id: str,
    *,
    justified: bool,
    combined_impact: str = "NONE",
    severity: str = "High",
) -> str:
    j = "YES" if justified else "NO"
    return "\n".join([
        f"## Chain Hypothesis {chain_id}",
        "### Blocked Finding (A)",
        f"- **ID**: {a_id}, **Title**: blocked attack",
        "### Enabler Finding (B)",
        f"- **ID**: {b_id}, **Title**: enabler finding",
        "### Severity Reassessment",
        f"Chain Severity: {severity}",
        f"Constituents: {a_id},{b_id} | Severity-Upgrade-Justified: {j} "
        f"| Combined-Impact: {combined_impact}",
        "",
    ])


def _write_chain(sp: Path, *sections: str) -> None:
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n" + "\n".join(sections), encoding="utf-8"
    )


def _write_report_index(sp: Path, excluded_rows: list[tuple[str, str, str, str]]) -> None:
    """excluded_rows: list of (internal_id, severity, title, exclusion_reason)."""
    lines = [
        "# Report Index",
        "",
        "## Master Finding Index",
        "",
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |",
        "|-----------|-------|----------|----------|--------------|-----------|--------------------|",
        "| M-01 | a body finding | Medium | A.sol:L10 | VERIFIED | - | INV-001 |",
        "",
        "## Excluded Findings",
        "",
        "| Internal ID | Severity | Title | Exclusion Reason |",
        "|-------------|----------|-------|------------------|",
    ]
    for iid, sev, title, reason in excluded_rows:
        lines.append(f"| {iid} | {sev} | {title} | {reason} |")
    lines.append("")
    (sp / "report_index.md").write_text("\n".join(lines), encoding="utf-8")


# ──────────────── (1) FP-now-resolved: NO-upgrade restatement ────────────────


def test_chain_restatement_no_upgrade_is_clean(tmp_path):
    """NO-upgrade chain absorbed into a body constituent and recorded as
    CHAIN-RESTATEMENT must NOT be flagged (a live false positive class)."""
    pv = _pv()
    _write_chain(
        tmp_path,
        _chain_section("CH-01", "M-07", "M-08", justified=False,
                       combined_impact="NONE"),
    )
    _write_report_index(tmp_path, [
        ("CH-01", "Medium", "chain absorbed into M-07",
         "CHAIN-RESTATEMENT - absorbed into M-07, Severity-Upgrade-Justified: NO"),
    ])
    issues = pv._validate_report_index_triage_safety(tmp_path)
    assert issues, "raw CHAIN-RESTATEMENT must cite an applied alias authority"


def test_chain_restatement_prose_absorbed_is_clean(tmp_path):
    """Human-phrased restatement (`chain absorbed into <body finding>`) for a
    NO-upgrade chain is also allowed."""
    pv = _pv()
    _write_chain(
        tmp_path,
        _chain_section("CH-02", "H-03", "H-04", justified=False),
    )
    _write_report_index(tmp_path, [
        ("CH-02", "High", "restated chain",
         "chain CH-02 absorbed into H-03 (no combined impact)"),
    ])
    issues = pv._validate_report_index_triage_safety(tmp_path)
    assert issues, "prose chain absorption is not an applied alias receipt"


def test_chain_downgrade_trust_adj_is_clean(tmp_path):
    """CHAIN-DOWNGRADE (Trust Adj. token for an absorbed NO-upgrade chain) is
    an allowed non-body reason."""
    pv = _pv()
    _write_chain(
        tmp_path,
        _chain_section("CH-03", "M-09", "M-10", justified=False),
    )
    _write_report_index(tmp_path, [
        ("CH-03", "Medium", "downgraded chain", "CHAIN-DOWNGRADE(Medium)"),
    ])
    issues = pv._validate_report_index_triage_safety(tmp_path)
    assert issues, "CHAIN-DOWNGRADE prose cannot authorize non-body treatment"


# ──────────── (2) NEGATIVE CONTROL: YES-upgrade orphan still flagged ────────────


def test_justified_upgrade_orphan_chain_still_flagged(tmp_path):
    """A YES-upgrade compound chain (concrete Combined-Impact) excluded WITHOUT
    a body home is a genuinely dropped compound finding. Even if the row is
    mislabeled CHAIN-RESTATEMENT, the cited chain is a justified upgrade in
    chain_hypotheses.md → the exemption MUST NOT apply → STILL flagged."""
    pv = _pv()
    _write_chain(
        tmp_path,
        _chain_section("CH-04", "M-11", "M-12", justified=True,
                       combined_impact="attacker drains the full pool in one tx"),
    )
    _write_report_index(tmp_path, [
        ("CH-04", "High", "real compound finding",
         "CHAIN-RESTATEMENT - absorbed into M-11"),
    ])
    issues = pv._validate_report_index_triage_safety(tmp_path)
    assert issues, "justified-upgrade orphan chain must STILL be flagged"
    assert any("CH-04" in i for i in issues), issues


def test_unlabeled_medium_plus_drop_still_flagged(tmp_path):
    """Plain unsafe drop with no allowed reason and no chain-restatement claim
    is still flagged (gate is not a blanket rubber stamp)."""
    pv = _pv()
    _write_report_index(tmp_path, [
        ("M-05", "Medium", "dropped medium", "not client worthy"),
    ])
    issues = pv._validate_report_index_triage_safety(tmp_path)
    assert issues, "plain unsafe Medium drop must still be flagged"
    assert any("M-05" in i for i in issues), issues


# ──────────── helper-level unit checks (canonical-semantics parity) ────────────


def test_chain_justified_upgrade_ids_classification(tmp_path):
    pv = _pv()
    _write_chain(
        tmp_path,
        _chain_section("CH-01", "M-07", "M-08", justified=False),
        _chain_section("CH-02", "M-09", "M-10", justified=True,
                       combined_impact="combined drain"),
    )
    justified = pv._chain_justified_upgrade_ids(tmp_path)
    assert justified == {"CH-02"}, justified


def test_reason_is_chain_restatement_tokens():
    pv = _pv()
    assert pv._reason_is_chain_restatement("CHAIN-RESTATEMENT - absorbed into M-07")
    assert pv._reason_is_chain_restatement("CHAIN_RESTATEMENT")
    assert pv._reason_is_chain_restatement("CHAIN-DOWNGRADE(Medium)")
    assert pv._reason_is_chain_restatement("chain CH-02 absorbed into H-03")
    # Non-chain absorption prose is NOT a chain restatement (handled elsewhere).
    assert not pv._reason_is_chain_restatement("absorbed into M-03")
    assert not pv._reason_is_chain_restatement("not client worthy")
    assert not pv._reason_is_chain_restatement("")
