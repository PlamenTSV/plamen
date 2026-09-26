from pathlib import Path
import hashlib
import json
import pytest

from execution_scope_runtime_witness import (
    ExecutionScopeWitnessError, capture_execution_scope_runtime_witness,
)
from execution_scope_runtime import materialize_execution_scope_assessments
from test_execution_scope_runtime_p1_e import _bound_execution


def _materialized_execution(scratch: Path, project: Path):
    result = _bound_execution(scratch, project)
    outcome = materialize_execution_scope_assessments(
        scratch, build_root=project,
    )
    assert outcome["status"] == "CLEAN"
    return result


def test_witness_captures_full_runtime_roster(tmp_path: Path):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _materialized_execution(scratch, project)
    witness = capture_execution_scope_runtime_witness(
        scratch, "H-71", project_root=project, build_root=project,
    )
    assert "scratchpad:_v2_checkpoint.json" not in witness.read_set
    assert witness.semantic_witnesses[
        "scratchpad:_v2_checkpoint.json#runtime"
    ]["project_root"] == str(project.resolve())
    assert "scratchpad:mechanical_verify_manifest.json" in witness.read_set
    assert "scratchpad:verify_H-71.execution_scope_runtime_source.json" in witness.read_set
    assert "scratchpad:verify_H-71.execution_scope_assessment.json" in witness.read_set
    assert "project:foundry.toml" in witness.read_set
    assert "project:Cargo.toml" in witness.absent_identities
    assert set(witness.implementation_identities) == {
        "execution_scope_runtime", "evidence_capabilities", "mechanical_successor_receipts",
    }


def test_witness_rejects_alternate_oracle_candidate(tmp_path: Path):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _materialized_execution(scratch, project)
    # A distinct build root makes the same relative oracle ambiguous.
    build = tmp_path / "build"
    build.mkdir()
    (build / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (build / "test").mkdir()
    (build / "test" / "Candidate.t.sol").write_text("different\n", encoding="utf-8")
    # This setup is stale relative to the already-materialized runtime source,
    # so exact replay still rejects it; ambiguity itself is reportable when it
    # was present at materialization time (covered below).
    with pytest.raises(ExecutionScopeWitnessError):
        capture_execution_scope_runtime_witness(
            scratch, "H-71", project_root=project, build_root=build,
        )


def test_materialized_invalid_receipt_and_missing_oracle_debt_is_witnessed(
    tmp_path: Path,
):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _result, oracle = _bound_execution(scratch, project)
    oracle.unlink()
    receipt = scratch / "verify_H-71.mechanical_successor.receipt.json"
    receipt.write_bytes(b"{invalid receipt\n")
    outcome = materialize_execution_scope_assessments(
        scratch, build_root=project,
    )
    assert outcome["status"] == "DEGRADED"
    witness = capture_execution_scope_runtime_witness(
        scratch, "H-71", project_root=project, build_root=project,
    )
    assert witness.assessment["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    assert witness.read_set["scratchpad:verify_H-71.mechanical_successor.receipt.json"] == b"{invalid receipt\n"
    assert "project:test/Candidate.t.sol" in witness.absent_identities


def test_materialized_ambiguous_oracle_debt_captures_both_candidates(tmp_path: Path):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _bound_execution(scratch, project)
    build = tmp_path / "build"
    (build / "test").mkdir(parents=True)
    (build / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    (build / "test" / "Candidate.t.sol").write_text(
        "distinct candidate\n", encoding="utf-8",
    )
    outcome = materialize_execution_scope_assessments(
        scratch, build_root=build,
    )
    assert outcome["status"] == "DEGRADED"
    witness = capture_execution_scope_runtime_witness(
        scratch, "H-71", project_root=project, build_root=build,
    )
    assert witness.assessment["candidate_state"] == "VISIBLE_EVIDENCE_DEBT"
    build_domain = next(
        identity.split(":", 1)[0]
        for identity in witness.read_set
        if identity.endswith(":test/Candidate.t.sol")
        and not identity.startswith("project:")
    )
    assert f"{build_domain}:test/Candidate.t.sol" in witness.read_set
    assert "project:test/Candidate.t.sol" in witness.read_set


def test_witness_detects_transitive_drift(tmp_path: Path, monkeypatch):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _materialized_execution(scratch, project)
    import execution_scope_runtime_witness as module
    original = module.runtime.load_execution_scope_assessment
    calls = 0
    def mutate_after_first(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            (project / "foundry.toml").write_text("[profile.changed]\n", encoding="utf-8")
        return result
    monkeypatch.setattr(module.runtime, "load_execution_scope_assessment", mutate_after_first)
    with pytest.raises(ExecutionScopeWitnessError):
        capture_execution_scope_runtime_witness(
            scratch, "H-71", project_root=project, build_root=project,
        )


def test_checkpoint_phase_progression_preserves_runtime_projection(tmp_path: Path):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _materialized_execution(scratch, project)
    first = capture_execution_scope_runtime_witness(
        scratch, "H-71", project_root=project, build_root=project,
    )
    checkpoint_path = scratch / "_v2_checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    checkpoint["phase_commits"] = {"later_phase": {"status": "COMPLETED"}}
    checkpoint_path.write_text(json.dumps(checkpoint) + "\n", encoding="utf-8")
    second = capture_execution_scope_runtime_witness(
        scratch, "H-71", project_root=project, build_root=project,
    )
    assert second == first


@pytest.mark.parametrize("selector", ["snapshot", "project_root"])
def test_checkpoint_runtime_selector_drift_is_rejected(tmp_path: Path, selector: str):
    scratch = tmp_path / "scratch"
    project = tmp_path / "project"
    _materialized_execution(scratch, project)
    checkpoint_path = scratch / "_v2_checkpoint.json"
    checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    if selector == "snapshot":
        snapshot = checkpoint["audit_snapshot"]
        snapshot["components"]["source_scope"]["digest"] = "9" * 64
        unsigned = {key: value for key, value in snapshot.items()
                    if key != "snapshot_digest"}
        raw = json.dumps(
            unsigned, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        snapshot["snapshot_digest"] = hashlib.sha256(raw).hexdigest()
    else:
        other = tmp_path / "other-project"
        other.mkdir()
        checkpoint["config"]["project_root"] = str(other)
    checkpoint_path.write_text(json.dumps(checkpoint) + "\n", encoding="utf-8")
    with pytest.raises(ExecutionScopeWitnessError):
        capture_execution_scope_runtime_witness(
            scratch, "H-71", project_root=project, build_root=project,
        )
