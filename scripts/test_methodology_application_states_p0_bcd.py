"""P0-B/C/D typed application-state and queue contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import methodology_application_states as S


SHA = "a" * 64


def _row(**changes):
    base = {
        "phase": "breadth",
        "worker_id": "B1",
        "producer_invocation_id": "producer-call-1",
        "output": "analysis_oracle.md",
        "output_sha256": "b" * 64,
        "prompt_sha256": "c" * 64,
        "dispatch_contract_sha256": "d" * 64,
        "skill": "ORACLE_ANALYSIS",
        "methodology_path": "C:/plamen/oracle/SKILL.md",
        "methodology_sha256": SHA,
        "step": "2.1",
        "executed": "yes",
        "evidence": "src/Oracle.sol:L9",
        "result": "traced the concrete branch and emitted a candidate",
        "delivery_integrity": "CURRENT",
        "trace_state": "VALID",
        "evidence_basis": "IN_SCOPE_SOURCE",
    }
    base.update(changes)
    return base


def test_missing_and_invalid_application_enter_repair_exactly_once():
    missing = S.classify_application_row(
        _row(trace_state="MISSING", executed="", evidence="", result="")
    )
    invalid = S.classify_application_row(
        _row(
            step="2.2", trace_state="INVALID", result="executed",
            evidence_basis="NONE",
        )
    )
    queues = S.build_application_queues([missing, invalid, missing], phase="breadth")

    assert missing["application_completeness"] == "MISSING"
    assert invalid["application_completeness"] == "INVALID"
    assert queues.repair["row_count"] == 2
    assert len({row["obligation_id"] for row in queues.repair["rows"]}) == 2
    assert queues.skeptic["row_count"] == 0


def test_applied_positive_is_candidate_and_not_skeptic_or_repair():
    state = S.classify_application_row(_row())
    queues = S.build_application_queues([state], phase="breadth")

    assert state["delivery_integrity"] == "CURRENT"
    assert state["application_completeness"] == "APPLIED"
    assert state["semantic_outcome"] == "CANDIDATE"
    assert state["evidence_basis"] == "IN_SCOPE_SOURCE"
    assert state["skeptic_required"] is False
    assert queues.repair["rows"] == []
    assert queues.skeptic["rows"] == []


def test_applied_negative_is_skeptic_work_not_methodology_rerun():
    state = S.classify_application_row(
        _row(result="SAFE: cited guard rejects the transition")
    )
    queues = S.build_application_queues([state], phase="breadth")

    assert state["application_completeness"] == "APPLIED"
    assert state["semantic_outcome"] == "NEGATIVE"
    assert state["skeptic_required"] is True
    assert queues.repair["row_count"] == 0
    assert queues.skeptic["row_count"] == 1


def test_na_subclause_in_detailed_application_is_not_missing_or_not_applicable():
    state = S.classify_application_row(
        _row(result="N/A for callback branch; traced the direct branch at the cited locus")
    )

    assert state["application_completeness"] == "APPLIED"
    assert state["semantic_outcome"] == "CANDIDATE"
    assert state["skeptic_required"] is False


def test_generic_self_attestation_is_invalid_unknown_and_repairable():
    state = S.classify_application_row(
        _row(result="executed", evidence_basis="NONE")
    )

    assert state["application_completeness"] == "INVALID"
    assert state["semantic_outcome"] == "INCONCLUSIVE"
    assert state["skeptic_required"] is False


def test_unsupported_external_clear_cannot_become_closed_negative():
    state = S.classify_application_row(
        _row(
            evidence="factory behavior is out of scope",
            result="SAFE: assume deployer guarantees one-time initialization",
            evidence_basis="EXTERNAL_UNRESEARCHED",
        )
    )

    assert state["application_completeness"] == "APPLIED"
    assert state["semantic_outcome"] == "NEGATIVE"
    assert state["negative_closure_eligible"] is False
    assert state["skeptic_required"] is True
    assert state["skeptic_reason"] == "UNSUPPORTED_NEGATIVE_CLEAR"


def test_supported_negative_bases_remain_pending_independent_skeptic():
    for basis in (
        "IN_SCOPE_SOURCE",
        "IN_SCOPE_EXECUTION",
        "PRIMARY_EXTERNAL_CITED",
    ):
        state = S.classify_application_row(
            _row(result="NO_FINDING: exact premise is refuted", evidence_basis=basis)
        )
        assert state["negative_closure_eligible"] is True
        assert state["skeptic_required"] is True


def test_queue_rows_bind_methodology_and_source_content_and_write_idempotently(
    tmp_path: Path,
):
    state = S.classify_application_row(
        _row(result="SAFE: cited guard rejects the transition")
    )
    first = S.write_application_queues(tmp_path, [state], phase="breadth")
    paths = [
        tmp_path / "methodology_repair_queue_breadth.json",
        tmp_path / "methodology_skeptic_queue_breadth.json",
    ]
    before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
    second = S.write_application_queues(tmp_path, [state], phase="breadth")

    assert first == second
    assert before == [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
    row = second.skeptic["rows"][0]
    assert row["methodology_path"].endswith("SKILL.md")
    assert row["methodology_sha256"] == SHA
    assert row["step"] == "2.1"
    assert row["output_sha256"] == "b" * 64
    assert row["original_result"] == "SAFE: cited guard rejects the transition"
    assert row["original_evidence"] == "src/Oracle.sol:L9"


def test_legacy_v1_migration_is_deterministic_and_conservative():
    legacy = {
        "schema_version": 1,
        "phase": "breadth",
        "rows": [
            {
                **_row(),
                "disposition": "ATTESTED",
                "skeptic_required": False,
                "reason": "legacy attestation",
            },
            {
                **_row(step="2.2", result="SAFE: old negative"),
                "disposition": "GAP",
                "skeptic_required": True,
                "reason": "legacy negative",
            },
        ],
    }

    first = S.migrate_application_receipt(legacy)
    second = S.migrate_application_receipt(json.loads(json.dumps(legacy)))

    assert first == second
    assert first["schema_version"] == "plamen.skill_application_receipt.v2"
    by_step = {row["step"]: row for row in first["rows"]}
    assert by_step["2.1"]["application_completeness"] == "APPLIED"
    assert by_step["2.1"]["semantic_outcome"] == "INCONCLUSIVE"
    assert by_step["2.2"]["application_completeness"] == "APPLIED"
    assert by_step["2.2"]["semantic_outcome"] == "NEGATIVE"
    assert by_step["2.2"]["evidence_basis"] == "NONE"
    assert first["migration_notes"]


def test_legacy_markdown_fallback_is_exact_section_and_header_scoped():
    unrelated = (
        "# Investigation Questions\n\n"
        "| Worker | Output | Skill | Step | Reason |\n|---|---|---|---|---|\n"
        "| B1 | out.md | ORACLE | Q3 | investigate |\n"
    )
    valid = (
        "# Skill Execution Gaps - breadth\n\n"
        "| Worker | Output | Skill | Step | Methodology Path | SHA-256 | Reason |\n"
        "|---|---|---|---|---|---|---|\n"
        f"| B1 | out.md | ORACLE | 2 | C:/skill/SKILL.md | {SHA} | missing trace row |\n"
    )

    assert S.parse_legacy_gap_projection(unrelated) == []
    rows = S.parse_legacy_gap_projection(valid)
    assert len(rows) == 1
    assert rows[0]["step"] == "2"
    assert rows[0]["methodology_sha256"] == SHA
