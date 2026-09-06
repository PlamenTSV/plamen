"""P0-AC: final-report consolidation requires applied alias authority.

The report-dedup model and every similarity detector are proposal producers.
Only the typed, transaction-bound report alias receipt may remove a standalone
report section.  These fixtures are protocol-neutral by construction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_mechanical as M
import plamen_validators as V
import report_dedup_authority as A


REPORT = """# Security Audit Report

## High Findings

### [H-01] Primary boundary failure [VERIFIED]

**Severity**: High
**Location**: `src/module.rs:L10-L20`
**Description**: The transition accepts an invalid boundary state.
**Impact**:
- Value accounting can become inconsistent.
**Recommendation**: Reject the invalid state before committing.

## Medium Findings

### [M-02] Secondary boundary description [VERIFIED]

**Severity**: Medium
**Location**: `src/module.rs:L10-L20`
**Description**: The same transition reaches an invalid boundary state.
**Impact**:
- The later accounting read can observe the invalid state.
**Recommendation**: Reject the invalid state before committing.
"""


def _index(left: str = "INV-001", right: str = "INV-001") -> str:
    return (
        "# Report Index\n\n## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|---|---|---|---|---|---|---|\n"
        f"| H-01 | Primary | High | src/module.rs:L10-L20 | VERIFIED | - | {left} |\n"
        f"| M-02 | Secondary | Medium | src/module.rs:L10-L20 | VERIFIED | - | {right} |\n"
    )


def _decisions() -> str:
    return (
        "# Report Consolidation Decisions\n\n"
        "## MERGE Decisions\n"
        "| Survivor | Absorbed | Same Root Cause | Reason |\n"
        "|---|---|---|---|\n"
        "| H-01 | M-02 | YES | same mechanism and remediation |\n"
    )


def _setup(tmp_path: Path, *, left: str = "INV-001", right: str = "INV-001") -> tuple[Path, Path]:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (project / "AUDIT_REPORT.md").write_text(REPORT, encoding="utf-8")
    (scratch / "report_index.md").write_text(_index(left, right), encoding="utf-8")
    (scratch / "report_dedup_agent_decisions.md").write_text(
        _decisions(), encoding="utf-8"
    )
    return scratch, project


def _receipt(scratch: Path) -> dict:
    raw = (scratch / A.RECEIPT_NAME).read_bytes()
    payload = json.loads(raw)
    assert raw == A.canonical_receipt_bytes(payload)
    return payload


def test_markdown_and_same_fix_are_proposals_only_without_exact_identity(
    tmp_path: Path,
) -> None:
    scratch, project = _setup(tmp_path, left="INV-001", right="INV-002")

    assert M._dedup_report_python(scratch, str(project), run_id="run-distinct")

    delivered = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "### [H-01]" in delivered
    assert "### [M-02]" in delivered
    receipt = _receipt(scratch)
    assert receipt["applied_aliases"] == []
    pair = next(row for row in receipt["decisions"] if row["absorbed"] == "M-02")
    assert pair["status"] == "REJECTED"
    assert pair["reason"] == "SOURCE_IDENTITY_NOT_EQUIVALENT"


def test_exact_source_identity_gets_typed_applied_receipt_and_live_survivor(
    tmp_path: Path,
) -> None:
    scratch, project = _setup(tmp_path)

    assert M._dedup_report_python(scratch, str(project), run_id="run-equivalent")

    delivered = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "### [H-01]" in delivered
    assert "### [M-02]" not in delivered
    receipt = _receipt(scratch)
    assert receipt["applied_aliases"] == [
        {"absorbed": "M-02", "survivor": "H-01"}
    ]
    assert receipt["postconditions"] == {
        "all_candidates_disposed": True,
        "all_survivors_live": True,
        "applied_equals_standalone_identity_delta": True,
        "candidate_loss": [],
        "cycles": [],
    }
    A.validate_receipt(
        receipt,
        pre_report=REPORT,
        post_report=delivered,
        exact_inputs=receipt["exact_inputs"],
        source_ids_by_report_id={"H-01": {"INV-001"}, "M-02": {"INV-001"}},
        semantic_aliases={},
    )
    projection = A.decision_projection_for_closure_broker(
        receipt,
        pre_report=REPORT,
        post_report=delivered,
        exact_inputs=receipt["exact_inputs"],
        source_ids_by_report_id={"H-01": {"INV-001"}, "M-02": {"INV-001"}},
        semantic_aliases={},
    )
    assert projection == {
        "schema_version": A.BROKER_PROJECTION_SCHEMA,
        "provider": "report_dedup_applied_alias_authority",
        "source_receipt_sha256": receipt["receipt_sha256"],
        "decisions": [
            {
                "authority_kind": "APPLIED_LOSSLESS_EQUIVALENCE",
                "subject_id": "M-02",
                "survivor_id": "H-01",
                "decision": "AUTHORIZED_ALIAS",
            }
        ],
    }


def test_receipt_tamper_stale_input_cycle_and_dead_survivor_are_rejected(
    tmp_path: Path,
) -> None:
    scratch, project = _setup(tmp_path)
    assert M._dedup_report_python(scratch, str(project), run_id="run-guards")
    delivered = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    receipt = _receipt(scratch)

    tampered = json.loads(json.dumps(receipt))
    tampered["applied_aliases"][0]["survivor"] = "H-99"
    with pytest.raises(A.ReportDedupAuthorityError):
        A.validate_receipt(
            tampered,
            pre_report=REPORT,
            post_report=delivered,
            exact_inputs=receipt["exact_inputs"],
        )

    stale_inputs = json.loads(json.dumps(receipt["exact_inputs"]))
    stale_inputs[0]["present"] = not stale_inputs[0]["present"]
    with pytest.raises(A.ReportDedupAuthorityError, match="exact input"):
        A.validate_receipt(
            receipt,
            pre_report=REPORT,
            post_report=delivered,
            exact_inputs=stale_inputs,
        )

    cycle_pre = REPORT + (
        "\n## Low Findings\n\n### [L-03] Third projection [VERIFIED]\n\n"
        "**Severity**: Low\n**Description**: Third projection.\n"
    )
    with pytest.raises(A.ReportDedupAuthorityError, match="cycle"):
        A.build_receipt(
            pre_report=cycle_pre,
            post_report="# Security Audit Report\n",
            exact_inputs=receipt["exact_inputs"],
            candidates=[
                {"keep": "H-01", "absorb": "M-02", "signals": ["proposal"]},
                {"keep": "M-02", "absorb": "L-03", "signals": ["proposal"]},
                {"keep": "L-03", "absorb": "H-01", "signals": ["proposal"]},
            ],
            decisions=[
                {"keep": "H-01", "absorb": "M-02", "decision": "MERGE", "reason": "x"},
                {"keep": "M-02", "absorb": "L-03", "decision": "MERGE", "reason": "x"},
                {"keep": "L-03", "absorb": "H-01", "decision": "MERGE", "reason": "x"},
            ],
            source_ids_by_report_id={
                "H-01": {"INV-001"},
                "M-02": {"INV-001"},
                "L-03": {"INV-001"},
            },
            retained_projection_ids=set(),
        )

    with pytest.raises(A.ReportDedupAuthorityError, match="live survivor"):
        A.build_receipt(
            pre_report=REPORT,
            post_report=delivered.replace("### [H-01]", "### [H-99]"),
            exact_inputs=receipt["exact_inputs"],
            candidates=[{"keep": "H-01", "absorb": "M-02", "signals": ["proposal"]}],
            decisions=[{"keep": "H-01", "absorb": "M-02", "decision": "MERGE", "reason": "x"}],
            source_ids_by_report_id={"H-01": {"INV-001"}, "M-02": {"INV-001"}},
            retained_projection_ids=set(),
        )


def test_report_alias_receipt_is_durable_before_crash_and_resume_is_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch, project = _setup(tmp_path)
    real_apply = M._apply_report_mutation_transaction

    def crash_apply(**kwargs):
        def crash(name: str) -> None:
            if name == "REPORT_REPLACED":
                raise RuntimeError("crash-after-report-replace")

        return real_apply(**kwargs, fault_hook=crash)

    monkeypatch.setattr(M, "_apply_report_mutation_transaction", crash_apply)
    with pytest.raises(RuntimeError, match="crash-after-report-replace"):
        M._dedup_report_python(scratch, str(project), run_id="run-resume")
    assert (scratch / A.RECEIPT_NAME).is_file()
    # Durable sidecars are recovery material, not applied authority until the
    # transaction reaches COMMITTED.
    assert V._report_dedup_status_aliases(scratch) == ({}, set())

    monkeypatch.setattr(M, "_apply_report_mutation_transaction", real_apply)
    assert M._dedup_report_python(scratch, str(project), run_id="run-resume")
    delivered = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "### [M-02]" not in delivered
    receipt = _receipt(scratch)
    assert receipt["applied_aliases"] == [
        {"absorbed": "M-02", "survivor": "H-01"}
    ]


def test_driver_live_call_passes_run_identity_to_transactional_dedup() -> None:
    source = Path(M.__file__).with_name("plamen_driver.py").read_text(encoding="utf-8")
    assert "_dedup_report_python(" in source
    assert "run_id=run_id" in source


def test_downstream_alias_consumer_replays_receipt_not_markdown(tmp_path: Path) -> None:
    scratch, project = _setup(tmp_path)
    assert M._dedup_report_python(scratch, str(project), run_id="run-consumer")
    aliases, qo_ids = V._report_dedup_status_aliases(scratch)
    assert aliases == {"M-02": "H-01"}
    assert qo_ids == set()

    # Mapping prose has no authority in either direction.
    (scratch / "report_dedup_mapping.md").write_text(
        "| H-99 | M-98 | MERGE | model | prose only |\n", encoding="utf-8"
    )
    aliases, _ = V._report_dedup_status_aliases(scratch)
    assert aliases == {"M-02": "H-01"}

    # The receipt must not be allowed to select its own smaller input
    # denominator.  Re-hashing a structurally valid but empty input list is not
    # replay of the report-index/source/semantic authorities.
    receipt_path = scratch / A.RECEIPT_NAME
    original_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    stripped = json.loads(json.dumps(original_payload))
    stripped["exact_inputs"] = []
    unsigned = dict(stripped)
    unsigned.pop("receipt_sha256", None)
    stripped["receipt_sha256"] = A._digest(unsigned)
    receipt_path.write_bytes(A.canonical_receipt_bytes(stripped))
    assert V._report_dedup_status_aliases(scratch) == ({}, set())
    receipt_path.write_bytes(A.canonical_receipt_bytes(original_payload))

    # The typed receipt fails closed when tampered.
    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["applied_aliases"][0]["survivor"] = "H-99"
    receipt_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    assert V._report_dedup_status_aliases(scratch) == ({}, set())


def test_receipt_replay_couples_decision_pair_and_live_source_authority(
    tmp_path: Path,
) -> None:
    scratch, project = _setup(tmp_path)
    third = (
        "\n## Low Findings\n\n### [L-03] Independent observation [VERIFIED]\n\n"
        "**Severity**: Low\n**Location**: `src/other.rs:L2`\n"
        "**Description**: An independent observation remains live.\n"
        "**Impact**: A bounded non-critical behavior.\n"
    )
    (project / "AUDIT_REPORT.md").write_text(REPORT + third, encoding="utf-8")
    assert M._dedup_report_python(scratch, str(project), run_id="run-field-coupling")
    delivered = (project / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    receipt = _receipt(scratch)

    forged = json.loads(json.dumps(receipt))
    applied = next(row for row in forged["decisions"] if row["status"] == "APPLIED")
    applied["survivor"] = "L-03"
    applied["survivor_source_ids"] = ["INV-001"]
    applied["absorbed_source_ids"] = ["INV-001"]
    forged["applied_aliases"] = [{"absorbed": "M-02", "survivor": "L-03"}]
    unsigned = dict(forged)
    unsigned.pop("receipt_sha256", None)
    forged["receipt_sha256"] = A._digest(unsigned)

    with pytest.raises(A.ReportDedupAuthorityError):
        A.validate_receipt(
            forged,
            pre_report=REPORT + third,
            post_report=delivered,
            exact_inputs=receipt["exact_inputs"],
            source_ids_by_report_id={
                "H-01": {"INV-001"},
                "M-02": {"INV-001"},
                "L-03": {"INV-003"},
            },
            semantic_aliases={},
        )


def test_h2_and_h3_chmli_findings_share_one_standalone_parser() -> None:
    text = (
        "## [C-01] Critical\nbody\n"
        "### [H-02] High\nbody\n"
        "## [M-03] Medium\nbody\n"
        "### [L-04] Low\nbody\n"
        "### [I-05] Info\nbody\n"
    )
    assert A.standalone_report_ids(text) == {
        "C-01", "H-02", "M-03", "L-04", "I-05"
    }


def test_retained_qo_identity_requires_an_actual_quality_observation_row() -> None:
    pre = (
        "# Report\n\n## Informational Findings\n\n"
        "### [I-03] Cosmetic observation\n\n"
        "**Severity**: Informational\n**Description**: Cosmetic.\n"
    )
    exact_inputs = [
        {"path": path, "present": False}
        for path in sorted(A.REQUIRED_EXACT_INPUT_PATHS)
    ]
    with pytest.raises(A.ReportDedupAuthorityError, match="Quality Observation"):
        A.build_receipt(
            pre_report=pre,
            post_report="# Report\n",
            exact_inputs=exact_inputs,
            candidates=[],
            decisions=[],
            source_ids_by_report_id={},
            retained_projection_ids={"I-03"},
            semantic_aliases={},
        )


def test_candidate_denominator_loss_is_rejected() -> None:
    with pytest.raises(A.ReportDedupAuthorityError, match="candidate loss"):
        A.build_receipt(
            pre_report=REPORT,
            post_report=REPORT,
            exact_inputs=[],
            candidates=[
                {"keep": "H-01", "absorb": "M-02", "signals": ["one"]},
                {"keep": "H-01", "absorb": "L-03", "signals": ["two"]},
            ],
            decisions=[
                {
                    "keep": "H-01",
                    "absorb": "M-02",
                    "decision": "KEEP_SEPARATE",
                    "reason": "distinct",
                }
            ],
            source_ids_by_report_id={},
            retained_projection_ids=set(),
        )


def test_stale_input_after_arm_refuses_resume_without_report_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch, project = _setup(tmp_path)
    real_apply = M._apply_report_mutation_transaction

    def crash_apply(**kwargs):
        def crash(name: str) -> None:
            if name == "ARMED_DURABLE":
                raise RuntimeError("crash-after-arm")

        return real_apply(**kwargs, fault_hook=crash)

    monkeypatch.setattr(M, "_apply_report_mutation_transaction", crash_apply)
    with pytest.raises(RuntimeError, match="crash-after-arm"):
        M._dedup_report_python(scratch, str(project), run_id="run-stale")
    assert (project / "AUDIT_REPORT.md").read_text(encoding="utf-8") == REPORT

    with (scratch / "report_index.md").open("a", encoding="utf-8") as handle:
        handle.write("\n<!-- changed after ARM -->\n")
    monkeypatch.setattr(M, "_apply_report_mutation_transaction", real_apply)
    assert not M._dedup_report_python(scratch, str(project), run_id="run-stale")
    assert (project / "AUDIT_REPORT.md").read_text(encoding="utf-8") == REPORT


def test_data_loss_veto_cannot_stamp_stale_qo_projection_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch, project = _setup(tmp_path)
    qo_report = REPORT + (
        "\n## Informational Findings\n\n"
        "### [I-03] Redundant local assignment\n\n"
        "**Severity**: Informational\n"
        "**Location**: `src/module.rs:L30`\n"
        "**Description**: A local variable is assigned twice before use.\n"
        "**Impact**: No security impact.\n"
        "**Recommendation**: Remove the redundant assignment.\n"
    )
    (project / "AUDIT_REPORT.md").write_text(qo_report, encoding="utf-8")
    (scratch / "report_dedup_agent_decisions.md").write_text(
        _decisions()
        + "\n## Quality Observation Reclassifications\n"
        "| Report ID | Class | Reason |\n|---|---|---|\n"
        "| I-03 | redundant code | no security impact |\n",
        encoding="utf-8",
    )
    calls = 0

    def gate(_before: str, _after: str, *, impact_only: bool = False):
        nonlocal calls
        calls += 1
        return [] if calls == 1 else ["forced-final-veto"]

    monkeypatch.setattr(M, "_dedup_data_loss_gate", gate)
    assert M._dedup_report_python(scratch, str(project), run_id="run-qo-veto")
    assert (project / "AUDIT_REPORT.md").read_text(encoding="utf-8") == qo_report
    receipt = _receipt(scratch)
    assert receipt["applied_aliases"] == []
    assert receipt["post_report"]["retained_projection_ids"] == []
