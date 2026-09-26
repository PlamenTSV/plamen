from __future__ import annotations

import json
from pathlib import Path

import pytest

import audit_completion_receipt as C
import e2e_acceptance_verifier as V
import test_e2e_acceptance_verifier as F


def _expanded_two_shard_plan(tier: str = "critical_high") -> list[str]:
    phases: list[str] = []
    for phase in C.SC_THOROUGH_PHASES:
        if phase == f"report_body_writer_{tier}":
            phases.extend(
                [f"report_body_writer_{tier}_a", f"report_body_writer_{tier}_b"]
            )
        elif phase == f"report_{tier}":
            phases.extend([f"report_{tier}_a", f"report_{tier}_b"])
        else:
            phases.append(phase)
    return phases


def _resign_terminal(paths: dict[str, Path], terminal: dict) -> None:
    terminal.pop("receipt_sha256", None)
    terminal["receipt_sha256"] = F._sha(F._canonical(terminal))
    F._write_json(paths["scratchpad"] / C.RECEIPT_NAME, terminal)


def _strict_projection_kwargs() -> dict:
    candidate = {
        "candidate_id": "F-1",
        "source_record_digest": "1" * 64,
    }
    disposition = {
        "candidate_id": "F-1",
        "disposition": "CONFIRMED",
    }
    return {
        "run_id": F.RUN_ID,
        "candidate_rows": [candidate],
        "candidate_authority": {
            "base_queue_binding": {"artifact": "verification_queue.work_items.json"},
            "delta_binding": None,
            "union_record_count": 1,
            "union_record_set_digest": "0" * 64,
            "source_bindings": [
                {
                    "artifact": "verification_queue.work_items.json",
                    "sha256": "1" * 64,
                }
            ],
        },
        "provenance_ids": ["F-1", "D-1"],
        "verifier_dispositions": [disposition],
        "report_bundle": {
            "expected_report_ids": ["H-1"],
            "records": [
                {
                    "report_id": "H-1",
                    "candidate_ids": ["F-1"],
                    "evidence_sources": [
                        {"artifact": "verify_F-1.md", "sha256": "2" * 64}
                    ],
                }
            ],
            "bundle_digest": "3" * 64,
        },
        "report_bundle_sha256": "4" * 64,
        "report_quality": {
            "receipt_digest": "5" * 64,
            "delivery_state": "SEMANTICALLY_COMPLETE",
            "structurally_delivered": True,
            "semantically_complete": True,
            "missing_semantic_fields": {},
            "evidence_limitations": {},
            "hidden_quality_debt_report_ids": [],
            "unauthorized_proof_grade_report_ids": [],
            "expected_report_ids": ["H-1"],
            "delivered_report_ids": ["H-1"],
        },
        "report_quality_sha256": "6" * 64,
        "report_disposition": {
            "rows": [
                {
                    "candidate_id": "F-1",
                    "identity_accounted": True,
                    "visible_debt": False,
                }
            ],
            "receipt_sha256": "7" * 64,
        },
        "report_disposition_sha256": "8" * 64,
        "artifact_ledger_sha256": "9" * 64,
        "artifact_ledger_digest": "a" * 64,
        "artifact_ledger_work_units": {
            "report_floor/terminal": {
                "run_id": F.RUN_ID,
                "semantic_status": "ACTIVE",
                "execution_state": "OUTPUT_COMMITTED",
                "contract_digest": "b" * 64,
                "launch_digest": "c" * 64,
            }
        },
        "artifact_ledger_binding_count": 1,
    }


def test_realized_plan_accepts_matching_two_shard_families() -> None:
    phases = _expanded_two_shard_plan()
    assert C.validate_realized_phase_plan(phases) == tuple(phases)
    assert len(phases) == len(C.SC_THOROUGH_PHASES) + 2
    assert C.phase_names_sha256(phases) != C.phase_names_sha256()


@pytest.mark.parametrize(
    "mutation",
    ("missing_confirmation", "sparse_suffix", "writer_confirmation_mismatch"),
)
def test_realized_plan_rejects_lossy_or_nondeterministic_shards(
    mutation: str,
) -> None:
    phases = _expanded_two_shard_plan()
    if mutation == "missing_confirmation":
        phases.remove("report_critical_high_b")
    elif mutation == "sparse_suffix":
        index = phases.index("report_body_writer_critical_high_b")
        phases[index] = "report_body_writer_critical_high_c"
        index = phases.index("report_critical_high_b")
        phases[index] = "report_critical_high_c"
    else:
        index = phases.index("report_critical_high_b")
        phases[index] = "report_critical_high_c"
    with pytest.raises(C.CompletionReceiptError, match="report shard"):
        C.validate_realized_phase_plan(phases)


def test_strict_e2e_accepts_exact_realized_multi_shard_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = F._fixture(tmp_path, monkeypatch)
    checkpoint = json.loads(paths["checkpoint"].read_text())
    phases = _expanded_two_shard_plan()
    old_commits = checkpoint["phase_commits"]
    commits: dict[str, dict] = {}
    for phase in phases:
        base = phase
        if phase.startswith("report_body_writer_critical_high_"):
            base = "report_body_writer_critical_high"
        elif phase in {"report_critical_high_a", "report_critical_high_b"}:
            base = "report_critical_high"
        row = dict(old_commits[base])
        row["phase_name"] = phase
        commits[phase] = row
    checkpoint["config"]["_active_phase_names"] = phases
    checkpoint["completed"] = phases
    checkpoint["phase_commits"] = commits
    F._write_json(paths["checkpoint"], checkpoint)

    receipt_path = paths["scratchpad"] / C.RECEIPT_NAME
    terminal = json.loads(receipt_path.read_text())
    terminal["phase_count"] = len(phases)
    terminal["realized_phase_plan_sha256"] = C.phase_names_sha256(phases)
    terminal["checkpoint_sha256"] = F._sha(paths["checkpoint"].read_bytes())
    _resign_terminal(paths, terminal)

    assert F._verify(paths).accepted is True


def test_coherently_resigned_closure_tamper_fails_independent_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = F._fixture(tmp_path, monkeypatch)
    receipt_path = paths["scratchpad"] / C.RECEIPT_NAME
    terminal = json.loads(receipt_path.read_text())
    closure = terminal["terminal_closure"]
    closure["artifact_ledger_binding_count"] += 1
    closure["closure_digest"] = ""
    closure["closure_digest"] = F._sha(F._canonical(closure))
    _resign_terminal(paths, terminal)

    verdict = F._verify(paths)
    assert verdict.accepted is False
    assert "TERMINAL_CLOSURE_INVALID" in F._codes(verdict)


def test_missing_terminal_closure_is_non_accepting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = F._fixture(tmp_path, monkeypatch)
    receipt_path = paths["scratchpad"] / C.RECEIPT_NAME
    terminal = json.loads(receipt_path.read_text())
    terminal.pop("terminal_closure")
    _resign_terminal(paths, terminal)
    verdict = F._verify(paths)
    assert verdict.accepted is False
    assert "TERMINAL_CLOSURE_INVALID" in F._codes(verdict)


def test_degraded_or_missing_semantic_quality_cannot_build_clean_closure() -> None:
    kwargs = _strict_projection_kwargs()
    quality = dict(kwargs["report_quality"])
    quality.update(
        {
            "delivery_state": "DEGRADED_DELIVERY",
            "semantically_complete": False,
            "missing_semantic_fields": {"H-1": ["impact"]},
        }
    )
    kwargs["report_quality"] = quality
    with pytest.raises(C.CompletionReceiptError, match="semantically complete"):
        C.build_terminal_closure_projection(**kwargs)


def test_missing_candidate_disposition_cannot_build_clean_closure() -> None:
    kwargs = _strict_projection_kwargs()
    kwargs["report_disposition"] = {
        "rows": [],
        "receipt_sha256": "7" * 64,
    }
    with pytest.raises(C.CompletionReceiptError, match="exactly close all candidates"):
        C.build_terminal_closure_projection(**kwargs)


def test_report_evidence_unknown_candidate_cannot_build_clean_closure() -> None:
    kwargs = _strict_projection_kwargs()
    bundle = dict(kwargs["report_bundle"])
    bundle["records"] = [dict(bundle["records"][0])]
    bundle["records"][0]["candidate_ids"] = ["F-UNKNOWN"]
    kwargs["report_bundle"] = bundle
    with pytest.raises(C.CompletionReceiptError, match="candidate provenance"):
        C.build_terminal_closure_projection(**kwargs)


def test_nonterminal_artifact_work_unit_cannot_build_clean_closure() -> None:
    kwargs = _strict_projection_kwargs()
    kwargs["artifact_ledger_work_units"] = {
        "report_floor/terminal": {
            "run_id": F.RUN_ID,
            "semantic_status": "INPUTS_BOUND",
            "execution_state": "INPUTS_BOUND_PREEXECUTION",
            "contract_digest": "b" * 64,
            "launch_digest": "c" * 64,
        }
    }
    with pytest.raises(C.CompletionReceiptError, match="nonterminal work unit"):
        C.build_terminal_closure_projection(**kwargs)
