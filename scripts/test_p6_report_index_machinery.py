"""Tests for v2.0.9 P6 — driver-mechanical report_index machinery.

Covers:
  P6.1  build_report_index_candidates_json — deterministic candidates from
        verification_queue + verdict_manifest + judge_decisions.
  P6.2  validate_report_index_actions_json — schema gate for LLM's actions JSON.
  P6.3  render_report_index_markdown — driver-rendered MD from JSONs.

Ships opt-in via config["use_driver_report_index_renderer"]; the existing
LLM-as-renderer path remains the default for one validation cycle.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from report_index_machinery import (  # noqa: E402
    ACTIONS_SCHEMA_VERSION,
    ALLOWED_ACTIONS,
    CANDIDATES_SCHEMA_VERSION,
    build_report_index_candidates_json,
    read_report_index_candidates_json,
    render_report_index_markdown,
    should_use_driver_renderer,
    validate_report_index_actions_json,
)


def _seed_minimal_scratchpad(tmp_path: Path) -> None:
    """Seed a scratchpad with a small queue + judge decisions + verdict
    manifest to exercise the producer end-to-end.
    """
    queue_md = """# Verification Queue

| Q | Finding ID | Expected | Severity | Title | Description | Preferred Tag | Location | Source IDs | PoC Class |
|---|------------|----------|----------|-------|-------------|---------------|----------|------------|-----------|
| 1 | HH-01 | verify_HH-01.md | High | A real high | desc | [POC-PASS] | x.sol:1 | INV-001 | structural |
| 2 | HH-02 | verify_HH-02.md | High | Phantom POC | desc | [CODE-TRACE] | x.sol:2 | INV-002 | structural |
| 3 | HM-01 | verify_HM-01.md | Medium | A real medium | desc | [CODE-TRACE] | x.sol:3 | INV-003 | structural |
"""
    (tmp_path / "verification_queue.md").write_text(queue_md, encoding="utf-8")

    # Skeptic proposal: HH-02 is UNRESOLVED (visible, no tier authority).
    judge_decisions = {
        "schema_version": "plamen.judge_decisions.v1",
        "source_markdown": "skeptic_judge_decisions.md",
        "generated_at": "2026-05-21T10:00:00",
        "row_count": 1,
        "decisions": [
            {"finding_id": "HH-02", "original_severity": "High",
             "final_severity": "Medium", "decision": "UNRESOLVED",
             "rationale": "skeptic disagrees"},
        ],
        "source_mtime_ns": 1, "source_sha256": "x", "source_size": 1,
    }
    (tmp_path / "judge_decisions.json").write_text(
        json.dumps(judge_decisions, indent=2), encoding="utf-8",
    )

    # Verdict manifest: HH-02 prose claimed [POC-PASS] but mechanical NO_TEST_FILE
    verdict_payload = {
        "schema_version": "plamen.verdict_manifest.v1",
        "mechanical_source": "mechanical_verify_manifest.md",
        "row_count": 3,
        "verdicts": [
            {"finding_id": "HH-01", "verify_file": "verify_HH-01.md",
             "mechanical_status": "PASS", "verifier_prose_tag": "[POC-PASS]",
             "integrity_state": "CONSISTENT", "effective_tag": "[POC-PASS]"},
            {"finding_id": "HH-02", "verify_file": "verify_HH-02.md",
             "mechanical_status": "NO_TEST_FILE",
             "verifier_prose_tag": "[POC-PASS]",
             "integrity_state": "INFLATED_PROSE",
             "effective_tag": "[CODE-TRACE] [INTEGRITY-DOWNGRADE]"},
            {"finding_id": "HM-01", "verify_file": "verify_HM-01.md",
             "mechanical_status": "NO_TEST_FILE",
             "verifier_prose_tag": "[CODE-TRACE]",
             "integrity_state": "CONSISTENT", "effective_tag": "[CODE-TRACE]"},
        ],
    }
    (tmp_path / "verdict_manifest.json").write_text(
        json.dumps(verdict_payload, indent=2), encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# P6.1 — candidates producer
# ---------------------------------------------------------------------------


def test_p61_candidates_payload_round_trip(tmp_path):
    """Producer writes a valid candidates.json with schema_version."""
    _seed_minimal_scratchpad(tmp_path)
    payload = build_report_index_candidates_json(tmp_path)
    assert payload["schema_version"] == CANDIDATES_SCHEMA_VERSION
    assert payload["row_count"] == 3
    rows = read_report_index_candidates_json(tmp_path)
    assert len(rows) == 3


def test_p61_candidates_preserve_tier_for_unresolved_proposal(tmp_path):
    """HH-02 remains High until separate typed adjudication authorizes change."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    rows = {r["canonical_id"]: r for r in read_report_index_candidates_json(tmp_path)}
    assert rows["HH-02"]["upstream_severity"] == "High"
    assert rows["HH-02"]["effective_severity_after_judge"] == "High"
    assert rows["HH-02"]["judge_decision"] == "UNRESOLVED"


def test_p61_unbound_manifest_cannot_assert_inflation_state(tmp_path):
    """Malformed/unbound mechanics degrade visibly without trusted diagnosis."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    rows = {r["canonical_id"]: r for r in read_report_index_candidates_json(tmp_path)}
    assert rows["HH-02"]["integrity_state"] == "MECHANICAL_UNAVAILABLE"
    assert rows["HH-02"]["mechanical_authority_state"] == "UNBOUND"
    assert "[MECHANICAL-UNAVAILABLE]" in rows["HH-02"]["effective_tag"]


def test_p61_bound_successor_preserves_genuine_pass_state(tmp_path):
    from test_mechanical_successor_consumer_p0_ag1 import _bound_fixture

    _bound_fixture(tmp_path, mechanical_status="PASS")
    payload = build_report_index_candidates_json(tmp_path)
    row = payload["candidates"][0]

    assert row["mechanical_authority_state"] == "BOUND"
    assert row["integrity_state"] == "CONSISTENT"
    assert row["effective_tag"] == "[POC-PASS]"


def test_p61_candidates_deterministic_report_id_assignment(tmp_path):
    """Report IDs are deterministically assigned per tier (C-01, H-01, M-01, ...)."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    rows = read_report_index_candidates_json(tmp_path)
    # Both High rows retain their tier; the Medium row starts M numbering.
    by_canonical = {r["canonical_id"]: r["default_report_id"] for r in rows}
    assert by_canonical["HH-01"] == "H-01"
    assert by_canonical["HH-02"] == "H-02"
    assert by_canonical["HM-01"] == "M-01"


def test_p61_candidates_allowed_actions_are_full_set(tmp_path):
    """Every candidate carries the full ALLOWED_ACTIONS list."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    rows = read_report_index_candidates_json(tmp_path)
    for r in rows:
        assert set(r["allowed_actions"]) == set(ALLOWED_ACTIONS)


# ---------------------------------------------------------------------------
# P6.2 — actions JSON schema gate
# ---------------------------------------------------------------------------


def _write_actions(tmp_path: Path, actions: list[dict]) -> None:
    payload = {
        "schema_version": ACTIONS_SCHEMA_VERSION,
        "actions": actions,
    }
    (tmp_path / "report_index_actions.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8",
    )


def test_p62_clean_actions_pass_validation(tmp_path):
    """Well-formed actions for every candidate → passed=True, no issues."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE"},
        {"canonical_id": "HH-02", "action": "APPENDIX_ONLY"},
        {"canonical_id": "HM-01", "action": "REPORTABLE"},
    ])
    passed, issues = validate_report_index_actions_json(tmp_path)
    assert passed, f"Should pass, got: {issues}"
    assert issues == []


def test_p62_missing_action_for_candidate_fails(tmp_path):
    """A candidate without an action is flagged."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE"},
        # Missing HH-02 and HM-01
    ])
    passed, issues = validate_report_index_actions_json(tmp_path)
    assert not passed
    assert any("missing an action" in i for i in issues)


def test_p62_invalid_action_token_fails(tmp_path):
    """Action outside ALLOWED_ACTIONS is rejected."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "FROBNICATE"},
        {"canonical_id": "HH-02", "action": "REPORTABLE"},
        {"canonical_id": "HM-01", "action": "REPORTABLE"},
    ])
    passed, issues = validate_report_index_actions_json(tmp_path)
    assert not passed
    assert any("FROBNICATE" in i for i in issues)


def test_p62_merge_into_must_reference_real_candidate(tmp_path):
    """MERGE_INTO without a valid merge_into target fails."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE"},
        {"canonical_id": "HH-02", "action": "MERGE_INTO", "merge_into": "DOES-NOT-EXIST"},
        {"canonical_id": "HM-01", "action": "REPORTABLE"},
    ])
    passed, issues = validate_report_index_actions_json(tmp_path)
    assert not passed
    assert any("merge_into" in i.lower() for i in issues)


def test_p62_duplicate_action_fails(tmp_path):
    """Two actions for the same canonical_id → fails."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE"},
        {"canonical_id": "HH-01", "action": "APPENDIX_ONLY"},
        {"canonical_id": "HH-02", "action": "REPORTABLE"},
        {"canonical_id": "HM-01", "action": "REPORTABLE"},
    ])
    passed, issues = validate_report_index_actions_json(tmp_path)
    assert not passed
    assert any("duplicate" in i.lower() for i in issues)


# ---------------------------------------------------------------------------
# P6.3 — driver renderer
# ---------------------------------------------------------------------------


def test_p63_driver_renders_report_index_md(tmp_path):
    """Renderer produces a valid report_index.md from candidates + actions."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE", "reason": ""},
        {"canonical_id": "HH-02", "action": "APPENDIX_ONLY", "reason": "inflated POC-PASS"},
        {"canonical_id": "HM-01", "action": "REPORTABLE", "reason": ""},
    ])
    ok = render_report_index_markdown(tmp_path)
    assert ok
    md = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    assert "Master Finding Index" in md
    assert "H-01" in md   # HH-01 → H-01
    assert "M-01" in md   # HM-01 remains the first Medium
    # HH-02 was APPENDIX_ONLY → in Excluded, not in body
    master = md.split("## Proposed Non-Body Actions", 1)[0]
    assert "HH-02" in master
    assert "Proposed Non-Body Actions (Non-authoritative)" in md
    cov = (tmp_path / "report_coverage.md").read_text(encoding="utf-8")
    assert "Report Coverage" in cov
    # All 3 candidates appear in coverage
    for cid in ("HH-01", "HH-02", "HM-01"):
        assert cid in cov


def test_p63_driver_renders_deterministically_byte_compare(tmp_path):
    """Two runs with identical inputs produce identical output (minus
    the timestamp line). Driver is the renderer — no LLM nondeterminism.
    """
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE", "reason": ""},
        {"canonical_id": "HH-02", "action": "APPENDIX_ONLY", "reason": "x"},
        {"canonical_id": "HM-01", "action": "REPORTABLE", "reason": ""},
    ])
    render_report_index_markdown(tmp_path)
    md1 = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    render_report_index_markdown(tmp_path)
    md2 = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    # Strip the timestamp line (`_Generated by driver renderer at ...`)
    def _strip_ts(text: str) -> str:
        return "\n".join(
            l for l in text.splitlines()
            if not l.startswith("_Generated by driver")
        )
    assert _strip_ts(md1) == _strip_ts(md2)


def test_p63_driver_handles_merge_into(tmp_path):
    """MERGE_INTO produces a Consolidation Map entry, not a body row."""
    _seed_minimal_scratchpad(tmp_path)
    build_report_index_candidates_json(tmp_path)
    _write_actions(tmp_path, [
        {"canonical_id": "HH-01", "action": "REPORTABLE", "reason": ""},
        {"canonical_id": "HH-02", "action": "MERGE_INTO",
         "merge_into": "HH-01", "reason": "same root cause"},
        {"canonical_id": "HM-01", "action": "REPORTABLE", "reason": ""},
    ])
    render_report_index_markdown(tmp_path)
    md = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    assert "Proposed Consolidation Map (Non-authoritative)" in md
    assert "HH-02" in md
    assert "HH-01" in md
    master = md.split("## Proposed Consolidation Map", 1)[0]
    assert "HH-02" in master


# ---------------------------------------------------------------------------
# Opt-in flag
# ---------------------------------------------------------------------------


def test_should_use_driver_renderer_default_off():
    """The driver renderer is OFF by default — preserves the existing LLM
    path until validated in a fresh-audit cycle."""
    assert should_use_driver_renderer({}) is False


def test_should_use_driver_renderer_explicit_on():
    """Toggle via config key."""
    assert should_use_driver_renderer(
        {"use_driver_report_index_renderer": True}
    ) is True
