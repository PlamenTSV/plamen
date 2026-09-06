"""P0-U: unsupported report-index downgrades are restored, not memorialized.

The report writer is a projection consumer.  A lower tier with no independent,
evidence-bound adjustment authority cannot become true merely because the
driver stamps a provenance token beside it.  The repair is deliberately
pre-tier-writer: report IDs and coverage references are repaired before body
manifests and the final report are derived.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_validators as V
from plamen_validators import (
    _repair_report_index_severity_provenance,
    _validate_report_index_inputs,
)
from test_l1_report_index_haltless_parity import (
    _write_coverage,
    _write_queue,
    _write_report_index,
    _write_verify,
)
from severity_decision_ledger import (
    bind_severity_adjudication,
    write_severity_decision_ledger,
)
from test_severity_adjudication_work_p0_ag3 import (
    RUN_ID,
    _decision,
    _prepare,
    _receipt_first_payload,
    _write_state,
)


def _fixture(root: Path) -> None:
    _write_queue(root, [("INV-001", "Medium")])
    _write_verify(root, "INV-001", "Medium")
    _write_report_index(root, [("L-01", "Low", "-", "INV-001")])
    _write_coverage(root, [("INV-001", "PROMOTED", "L-01")])


def test_unsupported_downgrade_restores_tier_report_id_and_coverage(
    tmp_path: Path,
) -> None:
    _fixture(tmp_path)
    assert _validate_report_index_inputs(tmp_path)

    repairs = _repair_report_index_severity_provenance(tmp_path)

    index = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    coverage = (tmp_path / "report_coverage.md").read_text(encoding="utf-8")
    assert "| M-01 |" in index
    assert "| Medium |" in index
    assert "| L-01 |" not in index
    assert "M-01" in coverage and "L-01" not in coverage
    assert not _validate_report_index_inputs(tmp_path)
    assert repairs == [
        {
            "report_id": "M-01",
            "previous_report_id": "L-01",
            "internal": "INV-001",
            "llm_severity": "Low",
            "upstream_severity": "Medium",
            "action": "applied severity restoration to upstream authority",
        }
    ]
    ledger = json.loads(
        (tmp_path / "_severity_override_ledger.json").read_text(encoding="utf-8")
    )
    row = ledger["overrides"][0]
    assert row["report_id"] == "M-01"
    assert row["previous_report_id"] == "L-01"
    assert row["reason"] == "unsupported-downgrade-restored"


def test_restore_allocates_collision_free_report_id_and_is_idempotent(
    tmp_path: Path,
) -> None:
    _write_queue(
        tmp_path,
        [("INV-001", "Medium"), ("INV-002", "Medium")],
    )
    _write_verify(tmp_path, "INV-001", "Medium")
    _write_verify(tmp_path, "INV-002", "Medium")
    _write_report_index(
        tmp_path,
        [
            ("M-01", "Medium", "-", "INV-001"),
            ("L-01", "Low", "-", "INV-002"),
        ],
    )
    _write_coverage(
        tmp_path,
        [
            ("INV-001", "PROMOTED", "M-01"),
            ("INV-002", "PROMOTED", "L-01"),
        ],
    )

    first = _repair_report_index_severity_provenance(tmp_path)
    frozen = {
        path.name: path.read_bytes()
        for path in (
            tmp_path / "report_index.md",
            tmp_path / "report_coverage.md",
            tmp_path / "_severity_override_ledger.json",
            tmp_path / "severity_overrides.md",
        )
    }
    second = _repair_report_index_severity_provenance(tmp_path)

    assert first[0]["report_id"] == "M-02"
    assert second == []
    assert frozen == {path.name: path.read_bytes() for path in (
        tmp_path / "report_index.md",
        tmp_path / "report_coverage.md",
        tmp_path / "_severity_override_ledger.json",
        tmp_path / "severity_overrides.md",
    )}


def test_partial_projection_failure_recovers_from_armed_ledger_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture(tmp_path)
    real_atomic = V._atomic_report_projection_text
    failed = False

    def fail_index_once(path: Path, text: str) -> None:
        nonlocal failed
        if Path(path).name == "report_index.md" and not failed:
            failed = True
            raise OSError("fixture index publish failure")
        real_atomic(path, text)

    monkeypatch.setattr(V, "_atomic_report_projection_text", fail_index_once)
    first = _repair_report_index_severity_provenance(tmp_path)
    assert first[0]["report_id"] == "*"
    assert "fixture index publish failure" in first[0]["action"]
    assert "| L-01 |" in (tmp_path / "report_index.md").read_text(encoding="utf-8")
    assert "M-01" in (tmp_path / "report_coverage.md").read_text(encoding="utf-8")
    assert (tmp_path / "_severity_override_ledger.json").is_file()

    monkeypatch.setattr(V, "_atomic_report_projection_text", real_atomic)
    second = _repair_report_index_severity_provenance(tmp_path)
    assert second and second[0]["report_id"] == "M-01"
    assert not _validate_report_index_inputs(tmp_path)
    assert "L-01" not in (tmp_path / "report_coverage.md").read_text(
        encoding="utf-8"
    )


def test_authority_write_failure_mutates_no_report_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture(tmp_path)
    before = {
        name: (tmp_path / name).read_bytes()
        for name in ("report_index.md", "report_coverage.md")
    }

    def fail_authority(*_args: object, **_kwargs: object) -> None:
        raise OSError("fixture authority arm failure")

    monkeypatch.setattr(V, "_write_severity_override_ledger", fail_authority)
    result = _repair_report_index_severity_provenance(tmp_path)

    assert result[0]["report_id"] == "*"
    assert "fixture authority arm failure" in result[0]["action"]
    assert before == {
        name: (tmp_path / name).read_bytes()
        for name in ("report_index.md", "report_coverage.md")
    }
    assert not (tmp_path / "_severity_override_ledger.json").exists()


def test_legacy_reason_prose_cannot_authorize_a_lower_tier_without_typed_cutover(
    tmp_path: Path,
) -> None:
    _write_queue(tmp_path, [("INV-001", "Medium")])
    _write_verify(tmp_path, "INV-001", "Medium")
    _write_report_index(
        tmp_path,
        [("L-01", "Low", "POC-FAIL evidence-bound cap", "INV-001")],
    )
    repairs = _repair_report_index_severity_provenance(tmp_path)

    assert repairs and repairs[0]["report_id"] == "M-01"
    restored = (tmp_path / "report_index.md").read_text(encoding="utf-8")
    assert "| M-01 |" in restored and "| Medium |" in restored
    assert (tmp_path / "_severity_override_ledger.json").exists()


def test_explicit_cutover_accepts_exact_report_authoritative_resolved_tier(
    tmp_path: Path,
) -> None:
    candidate_id = "INV-001"
    source_decision = _decision(candidate_id, proposed="Medium")
    _write_state(tmp_path, [source_decision])
    plan = _prepare(tmp_path)
    receipt = _receipt_first_payload(
        tmp_path,
        decision=source_decision,
        plan=plan,
        candidate_id=candidate_id,
    )
    proposal = json.loads(
        (
            tmp_path
            / f"verify_{candidate_id}.severity_adjudication_proposal.json"
        ).read_text(encoding="utf-8")
    )
    resolved = bind_severity_adjudication(
        proposal,
        decision=source_decision,
        adjudicator_launch_receipt=receipt["launch_receipt"],
    )
    assert resolved["status"] == "RESOLVED"
    assert resolved["final_severity"] == "Medium"
    write_severity_decision_ledger(
        tmp_path / "severity_decision_ledger.shadow.json",
        RUN_ID,
        [resolved],
    )
    (tmp_path / "config.json").write_text(
        json.dumps({
            "severity_authority_cutover": True,
            "severity_authority_run_id": RUN_ID,
            "severity_authority_source_receipts": {
                candidate_id: resolved["source_receipt_digest"],
            },
        }) + "\n",
        encoding="utf-8",
    )
    _write_queue(tmp_path, [(candidate_id, "High")])
    _write_verify(tmp_path, candidate_id, "High")
    _write_report_index(
        tmp_path,
        [(
            "M-01",
            "Medium",
            "independent typed severity adjudication",
            candidate_id,
        )],
    )
    frozen = (tmp_path / "report_index.md").read_bytes()

    assert not _validate_report_index_inputs(tmp_path)
    assert _repair_report_index_severity_provenance(tmp_path) == []
    assert (tmp_path / "report_index.md").read_bytes() == frozen
    assert not (tmp_path / "_severity_override_ledger.json").exists()
