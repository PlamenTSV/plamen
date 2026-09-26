"""Real late recall-floor successor fault, replay, and caller regressions."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

import artifact_ledger as AL
import plamen_driver as D
from plamen_types import Checkpoint, L1_PHASES, SC_PHASES
from test_depth_additive_successor_transaction import _seed_canonical


SUCCESSOR_KEY = "sc/thorough/evm/claude/inventory/late_recall_floor"


class InjectedBoundary(RuntimeError):
    pass


def _run(
    scratch: Path,
    config: dict,
    *,
    boundary: str = "",
) -> dict:
    def inject(name: str) -> None:
        if name == boundary:
            raise InjectedBoundary(name)

    return dict(D._run_late_recall_floor_successor(
        scratchpad=scratch,
        config=config,
        consumer_phase="sc_verify_queue",
        failpoint=inject if boundary else None,
    ))


@pytest.mark.parametrize(
    "boundary",
    (
        "capture:after_replace:inventory_floor_source_manifest.json",
        "after_capture",
        "after_plan",
        "after_arm",
        "after_output_1",
        "after_output_2",
        "after_output_3",
        "after_output_4",
        "before_commit",
        "after_commit",
    ),
)
def test_late_floor_fault_matrix_resumes_without_proposal_reevaluation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    _project, scratch, config = _seed_canonical(tmp_path)
    real_evaluate = D._late_floor_evaluate_proposal
    evaluations = 0

    def counted(**kwargs: object):
        nonlocal evaluations
        evaluations += 1
        return real_evaluate(**kwargs)

    monkeypatch.setattr(D, "_late_floor_evaluate_proposal", counted)
    with pytest.raises(InjectedBoundary, match=boundary):
        _run(scratch, config, boundary=boundary)
    assert evaluations == 1

    resumed = _run(scratch, config)
    assert resumed["safe_to_consume"] is True
    assert evaluations == 1

    manifest = json.loads(
        (scratch / D._LATE_FLOOR_MANIFEST).read_text(encoding="utf-8")
    )
    for name in D._LATE_FLOOR_CANONICAL:
        expected = base64.b64decode(
            manifest["canonical_postimages"][name]["content_b64"],
            validate=True,
        )
        assert (scratch / name).read_bytes() == expected
    unit = AL.read_artifact_ledger(scratch)["work_units"][SUCCESSOR_KEY]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE", "OUTPUT_COMMITTED",
    )
    assert unit["commit_authority"]["actor"] == "DRIVER"


@pytest.mark.parametrize("target_state", ("applied", "unapplied"))
def test_late_floor_resume_rejects_foreign_third_state_then_recovers_exactly(
    tmp_path: Path,
    target_state: str,
) -> None:
    _project, scratch, config = _seed_canonical(tmp_path)
    with pytest.raises(InjectedBoundary):
        _run(scratch, config, boundary="after_output_1")
    manifest = json.loads(
        (scratch / D._LATE_FLOOR_MANIFEST).read_text(encoding="utf-8")
    )
    name = (
        D._LATE_FLOOR_CANONICAL[0]
        if target_state == "applied" else D._LATE_FLOOR_CANONICAL[1]
    )
    row = (
        manifest["canonical_postimages"][name]
        if target_state == "applied"
        else manifest["canonical_preimages"][name]
    )
    expected = base64.b64decode(row["content_b64"], validate=True)
    (scratch / name).write_bytes(b"FOREIGN-THIRD-STATE\n")

    with pytest.raises(AL.ArtifactLedgerError):
        _run(scratch, config)
    (scratch / name).write_bytes(expected)
    assert _run(scratch, config)["safe_to_consume"] is True


def test_late_floor_capture_is_nonrecursive_and_binds_every_derived_byte(
    tmp_path: Path,
) -> None:
    _project, scratch, config = _seed_canonical(tmp_path)
    predecessor = (scratch / "findings_inventory.md").read_bytes()
    (scratch / "unrelated.bin").write_bytes(b"not-admitted")
    nested = scratch / "private-tree"
    nested.mkdir()
    (nested / "analysis_hidden.md").write_bytes(b"hidden")

    result = _run(scratch, config)
    assert result["safe_to_consume"] is True
    assert (scratch / "findings_inventory.md").read_bytes() == predecessor
    manifest = json.loads(
        (scratch / D._LATE_FLOOR_MANIFEST).read_text(encoding="utf-8")
    )
    names = {row["path"] for row in manifest["files"]}
    assert "unrelated.bin" not in names
    assert not any("private-tree" in name for name in names)
    for collection in ("files", "stage_derived_artifacts"):
        for row in manifest[collection]:
            raw = base64.b64decode(row["content_b64"], validate=True)
            assert len(raw) == row["size"]
            assert hashlib.sha256(raw).hexdigest() == row["sha256"]


def test_late_floor_source_mutation_before_capture_commit_is_not_blessed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratch, config = _seed_canonical(tmp_path)
    source = scratch / "analysis_a.md"
    real_evaluate = D._late_floor_evaluate_proposal

    def mutate(**kwargs: object):
        result = real_evaluate(**kwargs)
        source.write_bytes(source.read_bytes() + b"\nFOREIGN\n")
        return result

    monkeypatch.setattr(D, "_late_floor_evaluate_proposal", mutate)
    result = _run(scratch, config)
    assert result["safe_to_consume"] is False
    assert result["status"] == "INPUT_DEBT"
    assert not (scratch / D._LATE_FLOOR_MANIFEST).exists()
    unit = AL.read_artifact_ledger(scratch)["work_units"].get(SUCCESSOR_KEY)
    assert unit is None or unit.get("semantic_status") != "ACTIVE"


def test_sc_and_l1_live_callers_refuse_an_uncommitted_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    scratch.mkdir()
    project.mkdir()
    calls: list[str] = []

    def refused(**kwargs: object) -> dict:
        calls.append(str(kwargs["consumer_phase"]))
        return {
            "status": "INPUT_DEBT",
            "safe_to_consume": False,
            "issues": ["fixture floor refused"],
        }

    monkeypatch.setattr(D, "_run_late_recall_floor_successor", refused)
    monkeypatch.setattr(D, "_inventory_has_usable_findings", lambda *_a, **_k: False)
    monkeypatch.setattr(D, "_inventory_has_any_finding", lambda *_a, **_k: False)
    monkeypatch.setattr(D, "_append_phase_io_debt", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "_commit_incomplete_phase_attempt", lambda *_a, **_k: None)
    checkpoint = Checkpoint(run_id="run-floor-callers")

    sc_phase = next(row for row in SC_PHASES if row.name == "sc_verify_queue")
    sc_result = D._run_live_verify_queue_phase_boundary(
        phase=sc_phase,
        checkpoint=checkpoint,
        scratchpad=scratch,
        config={
            "pipeline": "sc", "mode": "thorough", "language": "evm",
            "cli_backend": "claude", "project_root": str(project),
            "_run_id": checkpoint.run_id,
        },
        phases=list(SC_PHASES),
        trust_preverify_issues=(),
    )
    assert sc_result["safe_to_continue"] is False
    assert "sc_verify_queue" in calls

    l1_phase = next(row for row in L1_PHASES if row.name == "semantic_dedup")
    del l1_phase  # only its canonical phase name is relevant to this boundary
    l1_issues = D._prepare_l1_semantic_dedup_inventory(
        scratchpad=scratch,
        config={
            "pipeline": "l1", "mode": "thorough", "language": "cosmos",
            "cli_backend": "claude", "project_root": str(project),
            "_run_id": checkpoint.run_id,
        },
        checkpoint=checkpoint,
    )
    assert "fixture floor refused" in l1_issues
    assert "semantic_dedup" in calls
