"""Phase 6d report_dedup_agent: the LLM proposer feeds cross-tier / no-location
MERGES and QO reclassifications into the Python report_dedup executor, which
applies them through the UNCHANGED zero-loss embed + data-loss gate.

These tests cover the data path the agent adds — they do not spawn an LLM. They
assert: (1) the decisions parser is robust + conservative, (2) an agent MERGE
without exact source-identity authority remains proposal-only, (3) an
agent-flagged cosmetic Low/Info is
retabulated to Quality Observations, and (4) missing/garbage proposals degrade
to a mechanical-only pass (never a halt, never a drop).
"""
import importlib
import json
from pathlib import Path

import plamen_mechanical as M


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------
def _write_decisions(scratchpad: Path, body: str):
    (scratchpad / "report_dedup_agent_decisions.md").write_text(
        body, encoding="utf-8"
    )


def test_parser_extracts_merges_and_qo(tmp_path: Path):
    _write_decisions(tmp_path, """# Report Consolidation Decisions

## MERGE Decisions
| Survivor | Absorbed | Same Root Cause | Reason |
|----------|----------|-----------------|--------|
| M-04 | H-03 | YES | devFundPct=100% zeroes issuance — same fix |
| L-15 | I-02 | YES | same expireLockKey orphan path |

## Quality Observation Reclassifications
| Report ID | Class | Reason |
|-----------|-------|--------|
| I-07 | redundant_code | dead duplicate check |

## Reviewed — Kept Separate
| Report ID(s) | Reason |
|--------------|--------|
| M-08, M-12 | different root cause |
""")
    merges, qo = M._parse_report_dedup_agent_decisions(tmp_path)
    assert ("M-04", "H-03") in merges
    assert ("L-15", "I-02") in merges
    assert qo == {"I-07"}


def test_parser_rejects_self_merge_and_non_yes(tmp_path: Path):
    _write_decisions(tmp_path, """# x
## MERGE Decisions
| Survivor | Absorbed | Same Root Cause | Reason |
|----------|----------|-----------------|--------|
| M-01 | M-01 | YES | self merge — must drop |
| H-01 | M-02 | NO | not affirmed — must drop |
| H-01 | M-03 | YES | valid |
""")
    merges, _ = M._parse_report_dedup_agent_decisions(tmp_path)
    assert merges == [("H-01", "M-03")]


def test_parser_dedupes_contradictory_absorbed(tmp_path: Path):
    # An absorbed ID may map to only one survivor; a survivor cannot also be an
    # absorbed elsewhere (no transitive contradiction reaches the merge loop).
    _write_decisions(tmp_path, """# x
## MERGE Decisions
| Survivor | Absorbed | Same Root Cause | Reason |
|----------|----------|-----------------|--------|
| M-01 | L-05 | YES | first wins |
| M-02 | L-05 | YES | duplicate absorbed — dropped |
| L-05 | I-09 | YES | L-05 already absorbed — dropped |
""")
    merges, _ = M._parse_report_dedup_agent_decisions(tmp_path)
    assert merges == [("M-01", "L-05")]


def test_parser_is_column_agnostic_and_multi_absorb(tmp_path: Path):
    # Regression: the agent emits a RICHER table than "Survivor | Absorbed"
    # ("Survivor ID | Survivor Title | Absorbed IDs | Same Root Cause | ...").
    # The parser must read IDs by position-in-row (first=survivor, rest=absorbed),
    # NOT by fixed column index (the old bug read the Title column as the
    # absorbed ID and dropped EVERY agent merge), handle multi-absorb, and
    # loose-match the QO header ("...Reclassification Decisions").
    _write_decisions(tmp_path, """# Report Consolidation Decisions

## MERGE Decisions
| Survivor ID | Survivor Title | Absorbed IDs | Same Root Cause | Same Fix | Notes |
|-------------|----------------|--------------|-----------------|----------|-------|
| H-07 | approval/pull amount diverge | H-08 | YES | YES | fee sub-case |
| L-08 | over-approve gateway | L-17, I-01 | YES | YES | multi-absorb |

## Quality Observation Reclassification Decisions
| Finding ID | Current Severity | Cosmetic Class | Reclassify? | Justification |
|-----------|------------------|----------------|-------------|---------------|
| I-09 | Info | naming | YES | cosmetic |
""")
    merges, qo = M._parse_report_dedup_agent_decisions(tmp_path)
    assert ("H-07", "H-08") in merges                       # title column skipped
    assert ("L-08", "L-17") in merges and ("L-08", "I-01") in merges  # multi-absorb
    assert qo == {"I-09"}                                   # loose QO header matched


def test_parser_missing_file_is_empty(tmp_path: Path):
    merges, qo = M._parse_report_dedup_agent_decisions(tmp_path)
    assert merges == [] and qo == set()


def test_parser_empty_tables_is_empty(tmp_path: Path):
    _write_decisions(tmp_path, """# Report Consolidation Decisions
## MERGE Decisions
| Survivor | Absorbed | Same Root Cause | Reason |
|----------|----------|-----------------|--------|

## Quality Observation Reclassifications
| Report ID | Class | Reason |
|-----------|-------|--------|
""")
    merges, qo = M._parse_report_dedup_agent_decisions(tmp_path)
    assert merges == [] and qo == set()


# --------------------------------------------------------------------------
# End-to-end executor: agent MERGE the mechanical pass would NOT pair
# --------------------------------------------------------------------------
_REPORT = """# Security Audit Report

## Summary

| Severity | Count |
|----------|-------|
| High | 1 |
| Medium | 1 |
| Informational | 1 |

## High Findings

### [H-03] devFundPct=100% destroys all round issuance [UNVERIFIED]

**Severity**: High
**Location**: (location data unavailable - verification file not produced)

**Description**:
A 100% development fund percentage zeroes all validator, app, and SV rewards.

**Impact**:
- All round issuance is destroyed when devFundPct reaches 100%.

## Medium Findings

### [M-04] Development Fund Percentage of 100% Zeroes All Rewards [VERIFIED]

**Severity**: Medium
**Location**: `Issuance.daml:L50, L105-129`

**Description**:
Setting devFundPct to 100% leaves zero issuance for validators/apps/SVs.

**Impact**:
- Validators, apps, and SV participants receive zero rewards.

**Recommendation**:
Bound devFundPct strictly below 100%.

## Informational Findings

### [I-07] lockHolderFee dead duplicate check in validTransferConfig

**Severity**: Informational
**Location**: `AmuletConfig.daml:L158`

**Description**:
A duplicated `lockHolderFee` comparison is dead code with no effect.
"""


def _run(tmp_path: Path, decisions: str | None):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (tmp_path / "AUDIT_REPORT.md").write_text(_REPORT, encoding="utf-8")
    if decisions is not None:
        (sp / "report_dedup_agent_decisions.md").write_text(
            decisions, encoding="utf-8"
        )
    ok = M._dedup_report_python(sp, str(tmp_path))
    assert ok is True
    final = (tmp_path / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    pre = (sp / "AUDIT_REPORT.pre-dedup.md").read_text(encoding="utf-8")
    return sp, final, pre


def test_agent_merge_remains_proposal_without_exact_alias_authority(tmp_path: Path):
    decisions = """# Report Consolidation Decisions
## MERGE Decisions
| Survivor | Absorbed | Same Root Cause | Reason |
|----------|----------|-----------------|--------|
| M-04 | H-03 | YES | same devFundPct=100% root cause across tiers |

## Quality Observation Reclassifications
| Report ID | Class | Reason |
|-----------|-------|--------|
"""
    sp, final, pre = _run(tmp_path, decisions)
    # Pre-dedup snapshot preserves the ORIGINAL untouched report (two versions).
    assert "### [H-03]" in pre
    # H-03 is no longer a standalone parseable section (merged into M-04)...
    assert "\n### [H-03]" in final
    # ...but its distinct content is preserved under the survivor (zero-loss).
    assert "Consolidated from H-03" not in final
    assert "H-03" in final
    assert "M-04" in final
    # Data-loss gate passed → mapping records the merge.
    mapping = (sp / "report_dedup_mapping.md").read_text(encoding="utf-8")
    assert "KEEP_SEPARATE" in mapping and "H-03" in mapping
    receipt = json.loads(
        (sp / "report_dedup_applied_alias_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["applied_aliases"] == []


def test_agent_qo_reclassification(tmp_path: Path):
    decisions = """# Report Consolidation Decisions
## MERGE Decisions
| Survivor | Absorbed | Same Root Cause | Reason |
|----------|----------|-----------------|--------|

## Quality Observation Reclassifications
| Report ID | Class | Reason |
|-----------|-------|--------|
| I-07 | redundant_code | dead duplicate check, no security impact |
"""
    sp, final, _pre = _run(tmp_path, decisions)
    assert "## Quality Observations" in final
    # I-07 leaves its full `### ` section and appears as a QO table row.
    assert "\n### [I-07]" not in final
    assert "I-07" in final  # retabulated, never dropped


def test_no_decisions_file_degrades_to_mechanical(tmp_path: Path):
    # Missing proposal file: behaves exactly like the pre-existing mechanical
    # pass (no agent merges); never raises, never drops, returns True.
    sp, final, pre = _run(tmp_path, None)
    # No mechanical signal pairs H-03/M-04 (no shared location/source-id), so
    # the report is unchanged — proving the agent is what unlocks that merge.
    assert "### [H-03]" in final
    assert final == pre  # identity no-op


def test_garbage_decisions_file_is_safe(tmp_path: Path):
    sp, final, _pre = _run(tmp_path, "this is not a valid decisions file at all")
    # Unparseable → no agent merges → mechanical-only identity; no crash.
    assert "### [H-03]" in final


if __name__ == "__main__":
    import pytest
    import sys

    sys.exit(pytest.main([__file__, "-q"]))
