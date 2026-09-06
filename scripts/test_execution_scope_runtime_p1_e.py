"""P1-E live runtime authority and conservative-consumer contracts.

These fixtures exercise only generic candidate identities.  Mechanical
execution is not semantic proof: the runtime must bind the exact immutable
execution chain and still withhold harm/refutation authority until a separate,
independently authored structured scope record proves that stronger claim.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path

import pytest

import mechanical_verify as MV
import plamen_validators as V
from mechanical_successor_receipts import apply_mechanical_successor
from queue_work_items import (
    OutputOwnership,
    QueueWorkPlan,
    QueueWorkShard,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
)
from execution_scope_runtime import (
    load_execution_scope_assessment,
    materialize_execution_scope_assessments,
)
from evidence_capabilities import (
    EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA,
    issue_executed_poc_scope_assessment,
)


RUN_ID = "11111111-1111-4111-8111-111111111111"
DRIVER_ID = "sha256:" + "d" * 64


def _sha(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _proposal(candidate_id: str) -> bytes:
    value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": candidate_id,
        "constituent_ids": [candidate_id],
        "impact": {
            "class": "High", "harmed_asset": "protected state",
            "harmed_capability": "integrity", "premise_id": "PREM-I",
            "premise_kind": "INTERNAL", "evidence_ids": ["EVID-I"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium", "actor": "unprivileged participant",
            "preconditions": ["reachable state"], "premise_id": "PREM-L",
            "premise_kind": "INTERNAL", "evidence_ids": ["EVID-L"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [], "proposed_severity": "High", "adjustment": None,
        "constituent_premise_outcomes": {
            candidate_id: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    return _canonical(value)


def _audit_snapshot() -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema": "plamen.audit_snapshot.v1",
        "components": {
            "source_scope": {"digest": "1" * 64},
            "audit_config": {"digest": "2" * 64},
            "methodology": {"digest": "3" * 64},
            "toolchain": {"digest": "4" * 64},
        },
    }
    return {**unsigned, "snapshot_digest": _sha(_canonical(unsigned))}


def _bound_execution(
    scratchpad: Path,
    project_root: Path,
    *,
    candidate_id: str = "H-71",
    status: str = "PASS",
) -> tuple[dict[str, object], Path]:
    scratchpad.mkdir(parents=True, exist_ok=True)
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
    test_dir = project_root / "test"
    test_dir.mkdir(exist_ok=True)
    test_path = test_dir / "Candidate.t.sol"
    test_path.write_text(
        "contract CandidateTest { function test_candidate() public {} }\n",
        encoding="utf-8",
    )
    checkpoint = {
        "run_id": RUN_ID,
        "audit_snapshot": _audit_snapshot(),
        "config": {"project_root": str(project_root)},
    }
    (scratchpad / "_v2_checkpoint.json").write_text(
        json.dumps(checkpoint, sort_keys=True), encoding="utf-8"
    )

    original = (
        f"# Verification: {candidate_id}\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        f"**Evidence Tag**: {'[POC-FAIL]' if status == 'FAIL' else '[FUZZ-PASS]'}\n\n"
        "### Execution Result\n"
        f"- Evidence Tag: {'[POC-FAIL]' if status == 'FAIL' else '[FUZZ-PASS]'}\n"
    ).encode("utf-8")
    verify = scratchpad / f"verify_{candidate_id}.md"
    verify.write_bytes(original)
    proposal = _proposal(candidate_id)
    (scratchpad / f"verify_{candidate_id}.severity_proposal.json").write_bytes(proposal)
    owner = OutputOwnership(
        work_item_id=candidate_id,
        work_item_digest="a" * 64,
        expected_output_file=verify.name,
        expected_output_identity=f"scratchpad:{verify.name}",
    )
    shard = QueueWorkShard(
        shard_id="verify_shard_a",
        ordered_work_item_ids=(candidate_id,),
        shard_record_digest="e" * 64,
        projection_digest="f" * 64,
        output_ownership=(owner,),
    )
    plan = QueueWorkPlan(
        planner_version="p1e.fixture.v1",
        parent_record_set_digest="9" * 64,
        ordered_work_item_ids=(candidate_id,),
        shards=(shard,),
    )
    (scratchpad / "verification_queue.work_plan.json").write_bytes(
        (plan.to_json() + "\n").encode("utf-8")
    )
    identity = VerifierOutputIdentity(
        work_item_id=candidate_id,
        queue_record_digest="a" * 64,
        work_plan_digest=plan.digest,
        shard_id="verify_shard_a",
        expected_output_file=verify.name,
        expected_output_identity=f"scratchpad:{verify.name}",
    )
    (scratchpad / f"verify_{candidate_id}.identity.json").write_bytes(
        _canonical(identity.to_dict())
    )
    receipt = VerifierOutputReceipt.bind(
        identity, original, severity_proposal=proposal,
        launch_digest="c" * 64, verifier_backend="claude",
    )
    (scratchpad / f"verify_{candidate_id}.receipt.json").write_text(
        receipt.to_json(), encoding="utf-8"
    )

    result = MV.ExecResult(
        verify_file=verify.name,
        finding_id=candidate_id,
        language="evm",
        test_file_resolved="test/Candidate.t.sol",
        test_function="test_candidate",
        test_command_used="forge test --match-test test_candidate -vv",
        status=status,
        duration_s=1.0,
        stdout_tail=("[PASS] 1 passed" if status == "PASS" else "[FAIL] 1 failed"),
        recommended_tag=MV._recommended_tag(status),
        race_mode=False,
    )
    manifest = scratchpad / "mechanical_verify_manifest.json"
    manifest.write_text(
        json.dumps({
            "generated_at": "2026-07-18T12:00:00",
            "counts": {status: 1},
            "results": [asdict(result)],
        }, indent=2),
        encoding="utf-8",
    )
    MV._write_verdict_manifest([result], scratchpad)
    outcome = apply_mechanical_successor(
        verify, asdict(result), manifest,
        run_identity=RUN_ID, driver_identity=DRIVER_ID,
    )
    authoritative = MV._authoritative_successor_result(manifest, asdict(result))
    MV._write_exact_execution_evidence(
        scratchpad,
        executed_result=asdict(result),
        authoritative_result=authoritative,
        manifest_path=manifest,
        successor_receipt_path=outcome.receipt_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    MV._write_successor_authority_summary(
        scratchpad, run_identity=RUN_ID, driver_identity=DRIVER_ID,
        committed=1, rejections=[],
    )
    return asdict(result), test_path


def _rich_record(
    scratchpad: Path,
    candidate_id: str,
    *,
    negative: bool = False,
) -> dict[str, object]:
    source = json.loads(
        (scratchpad / f"verify_{candidate_id}.execution_scope_runtime_source.json")
        .read_text(encoding="utf-8")
    )
    return {
        "schema_version": EXECUTED_POC_SCOPE_EVIDENCE_SCHEMA,
        "candidate_id": candidate_id,
        "evidence_id": f"P1E-RICH-{candidate_id}",
        "source_snapshot_sha256": source["source_snapshot_sha256"],
        "build_sha256": source["build_binding_sha256"],
        "command_sha256": source["command_sha256"],
        "oracle_sha256": source["oracle_sha256"],
        "output_sha256": source["output_sha256"],
        "runner_receipt_sha256": source["execution_evidence_sha256"],
        "launch_receipt_sha256": source["successor_receipt_sha256"],
        "execution_status": "COMPLETED",
        "execution_result": "NOT_ESTABLISHED" if negative else "ESTABLISHED",
        "exit_code": 1 if negative else 0,
        "oracle_provenance": "MODEL_GENERATED_ORACLE",
        "oracle_derivation": "IN_SCOPE_CLAIM_BOUND",
        "oracle_author_identity": "verification-worker",
        "oracle_author_invocation_id": "verification-worker-run-1",
        "oracle_review_status": "INDEPENDENTLY_VALIDATED",
        "oracle_reviewer_identity": "independent-scope-reviewer",
        "oracle_reviewer_invocation_id": "independent-scope-reviewer-run-1",
        "reachability": "IN_SCOPE_REACHABLE",
        "environment_fidelity": "FULL_IN_SCOPE",
        "proof_scope": "HARM" if not negative else "REACHABILITY",
        "negative_exhaustiveness": "EXHAUSTIVE_IN_SCOPE" if negative else "NOT_APPLICABLE",
        "required_precondition_ids": ["PRE-1"],
        "represented_precondition_ids": ["PRE-1"],
        "external_evidence_receipts": [],
        "external_premises": [],
        "premise_ids": ["PREM-1"],
        "constituent_ids": [candidate_id],
        "source_author_identity": "verification-worker",
        "source_author_invocation_id": "verification-worker-run-1",
        "issuer_identity": "scope-registrar",
        "issuer_invocation_id": "scope-registrar-run-1",
    }


def _explicit_scope_rewind(scratchpad: Path, candidate_id: str) -> None:
    """Test-only simulation of the explicit re-verification boundary."""

    for suffix in (
        ".execution_scope_runtime_source.json",
        ".execution_scope_assessment.json",
    ):
        path = scratchpad / f"verify_{candidate_id}{suffix}"
        if path.exists():
            path.unlink()
    debt = scratchpad / "execution_scope_runtime_debt.json"
    if debt.exists():
        debt.unlink()


def test_mechanical_pass_is_authenticated_execution_not_harm_proof(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    result = materialize_execution_scope_assessments(scratch, build_root=project)
    loaded = load_execution_scope_assessment(scratch, "H-71")

    assert result["status"] == "CLEAN"
    assert loaded["status"] == "VALID_LIMITED"
    assessment = loaded["assessment"]
    assert assessment["execution_authenticity"] == "AUTHENTICATED"
    assert assessment["positive_capabilities"] == ["EXECUTION"]
    assert assessment["harm_evidence_eligible"] is False
    assert assessment["negative_disposition_eligible"] is False


def test_exact_independent_harm_scope_can_upgrade_only_same_execution(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71")
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    loaded = load_execution_scope_assessment(scratch, "H-71")
    assert loaded["status"] == "VALID_RICH"
    assert loaded["assessment"]["harm_evidence_eligible"] is True
    assert V._effective_tag_is_proof_grade(
        "[FUZZ-PASS]",
        execution_scope_assessment=loaded["assessment"],
    ) is True


def test_full_status_projection_uses_rich_harm_scope_not_pass_tag(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71")
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    (scratch / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| H-71 | High | Candidate | src/Module.sol:10 | unit |\n",
        encoding="utf-8",
    )
    assert V._expected_report_index_statuses(scratch)["H-71"] == "VERIFIED"


def test_exact_exhaustive_negative_can_authorize_only_declared_scope(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project, status="FAIL")
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71", negative=True)
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    loaded = load_execution_scope_assessment(scratch, "H-71")
    assert loaded["status"] == "VALID_RICH"
    assert loaded["assessment"]["negative_disposition_eligible"] is True
    assert loaded["assessment"]["maximum_negative_scope"] == "REACHABILITY"


def test_standalone_demotion_requires_live_exhaustive_negative_authority(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project, status="FAIL")
    (scratch / "verification_queue.md").write_text(
        "| Finding ID | Severity | Title | Location | PoC Class |\n"
        "|---|---|---|---|---|\n"
        "| H-71 | High | Candidate | src/Module.sol:10 | unit |\n",
        encoding="utf-8",
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    assert V._apply_poc_fail_demotions(scratch, "thorough") == []
    assert (scratch / "execution_scope_reverification.json").is_file()

    record = _rich_record(scratch, "H-71", negative=True)
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(scratch, build_root=project)
    demotions = V._apply_poc_fail_demotions(scratch, "thorough")
    assert [row["finding_id"] for row in demotions] == ["H-71"]
    assert not (scratch / "execution_scope_reverification.json").exists()


@pytest.mark.parametrize(
    "mutation",
    ("manifest", "successor", "execution_evidence", "verify", "oracle"),
)
def test_tamper_or_source_drift_revokes_scope_authority(
    tmp_path: Path, mutation: str,
):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _row, oracle = _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    if mutation == "manifest":
        path = scratch / "mechanical_verify_manifest.json"
    elif mutation == "successor":
        path = scratch / "verify_H-71.mechanical_successor.receipt.json"
    elif mutation == "execution_evidence":
        path = next((scratch / "mechanical_execution_evidence").glob("*.json"))
    elif mutation == "verify":
        path = scratch / "verify_H-71.md"
    else:
        path = oracle
    path.write_bytes(path.read_bytes() + b"\n")
    loaded = load_execution_scope_assessment(scratch, "H-71")
    assert loaded["status"] == "INVALID"
    assert loaded["assessment"] is None


def test_case_collision_is_invalid_and_cannot_select_an_assessment(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    canonical = scratch / "verify_H-71.execution_scope_assessment.json"
    transit = scratch / "assessment.case-transit"
    alias = scratch / "VERIFY_H-71.execution_scope_assessment.json"
    canonical.rename(transit)
    transit.rename(alias)
    assert load_execution_scope_assessment(scratch, "H-71")["status"] == "INVALID"


def test_materialization_is_byte_idempotent(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    before = {
        path.name: path.read_bytes()
        for path in scratch.glob("verify_H-71.execution_scope_*.json")
    }
    materialize_execution_scope_assessments(scratch, build_root=project)
    after = {
        path.name: path.read_bytes()
        for path in scratch.glob("verify_H-71.execution_scope_*.json")
    }
    assert after == before


def test_resume_cannot_launder_post_execution_oracle_drift(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _row, oracle = _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    source = scratch / "verify_H-71.execution_scope_runtime_source.json"
    assessment = scratch / "verify_H-71.execution_scope_assessment.json"
    frozen = (source.read_bytes(), assessment.read_bytes())
    oracle.write_text("changed after execution\n", encoding="utf-8")

    replay = materialize_execution_scope_assessments(scratch, build_root=project)
    assert replay["status"] == "DEGRADED"
    assert (source.read_bytes(), assessment.read_bytes()) == frozen
    assert load_execution_scope_assessment(scratch, "H-71")["status"] == "INVALID"


def test_resume_repairs_only_missing_derived_half_when_authority_is_exact(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    assessment = scratch / "verify_H-71.execution_scope_assessment.json"
    expected = assessment.read_bytes()
    assessment.unlink()
    replay = materialize_execution_scope_assessments(scratch, build_root=project)
    assert replay["status"] == "CLEAN"
    assert assessment.read_bytes() == expected


@pytest.mark.parametrize(
    "status", ("TIMEOUT", "NO_TEST_FILE", "TOOLCHAIN_UNAVAILABLE")
)
def test_nonexecution_statuses_never_mint_negative_or_harm_scope(
    tmp_path: Path, status: str,
):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project, status=status)
    materialize_execution_scope_assessments(scratch, build_root=project)
    loaded = load_execution_scope_assessment(scratch, "H-71")
    assert loaded["status"] in {"EVIDENCE_DEBT", "VALID_LIMITED"}
    assessment = loaded["assessment"]
    assert assessment["harm_evidence_eligible"] is False
    assert assessment["negative_disposition_eligible"] is False


def test_rich_record_digest_mismatch_falls_back_to_limited_execution(tmp_path: Path):
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71")
    record["command_sha256"] = "f" * 64
    _explicit_scope_rewind(scratch, "H-71")
    (scratch / "verify_H-71.execution_scope_evidence.json").write_text(
        json.dumps(record), encoding="utf-8"
    )
    result = materialize_execution_scope_assessments(scratch, build_root=project)
    loaded = load_execution_scope_assessment(scratch, "H-71")
    assert result["status"] == "DEGRADED"
    assert loaded["status"] == "VALID_LIMITED"
    assert loaded["assessment"]["harm_evidence_eligible"] is False
    assert "RICH_SCOPE_SOURCE_INVALID" in result["issues"][0]


def test_pure_provider_cannot_float_as_runtime_authority(tmp_path: Path):
    # A self-consistent provider assessment with no runtime binding is useful
    # in unit tests, but the live consumer must reject it as unauthenticated.
    project = tmp_path / "project"
    scratch = tmp_path / "scratch"
    _bound_execution(scratch, project)
    materialize_execution_scope_assessments(scratch, build_root=project)
    record = _rich_record(scratch, "H-71")
    assessment = issue_executed_poc_scope_assessment(record)
    (scratch / "verify_H-71.execution_scope_assessment.json").write_text(
        json.dumps(assessment), encoding="utf-8"
    )
    assert load_execution_scope_assessment(scratch, "H-71")["status"] == "INVALID"
