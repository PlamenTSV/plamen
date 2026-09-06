"""P0 fixtures for post-work MethodCard application authority.

These tests deliberately stop before PhaseIO or driver cutover.  They exercise
the pure reconciliation boundary that those callers will eventually consume.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path

import pytest

import test_method_card_runtime_authority_r2 as runtime_fixtures
from method_card_application_authority import (
    APPLICATION_AUTHORITY_SCHEMA,
    MethodCardRuntimeReplayWitness,
    MethodCardApplicationAuthorityError,
    WorkerExecutionReplayWitness,
    canonical_method_card_application_authority_bytes,
    compile_independent_application_review_receipt,
    compile_producer_application_receipt,
    compile_worker_attempt_identity,
    reconcile_method_card_application,
    validate_method_card_application_authority,
)
from method_card_runtime_authority import (
    compile_method_card_runtime_authority,
    compile_method_card_runtime_input_binding,
    render_selected_method_fragment,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from program_facts_types import canonical_json_bytes
import worker_transaction as worker_tx


SOURCE_PATH = "src/Module.sol"
OUTPUT_PATH = "analysis_authority.md"
SOURCE_BYTES = b"contract Module { function f() external {} }\n"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()  # type: ignore[arg-type]


def _span(path: str, data: bytes, start: int = 1, end: int = 1) -> dict:
    lines = data.splitlines(keepends=True)
    selected = b"".join(lines[start - 1:end])
    return {
        "path": path,
        "line_start": start,
        "line_end": end,
        "sha256": hashlib.sha256(selected).hexdigest(),
    }


def _phaseio(unit: str, output_path: str) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "codex", "breadth", unit
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        phase="breadth",
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output_path,
                owner_key=key,
                artifact_class="REQUIRED",
                writer="MODEL",
                write_mode="CREATE",
            ),
        ),
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="codex",
        model="fixture-model",
        timeout_s=30,
        exec_mode="native",
    )
    return contract, launch


def _plan_for_phaseio(
    base: dict,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    *,
    output_path: str,
) -> dict:
    unit = contract.work_unit_id
    denominator = worker_tx.compile_phase_work_roster_denominator(
        run_id=base["run_id"],
        phase=contract.phase,
        generation=base["generation"],
        required_work_unit_ids=(unit,),
    )
    assignment = copy.deepcopy(base["assignment"])
    assignment["assignment_id"] = f"{unit}-output"
    assignment["members"][0]["staged_relative_path"] = output_path
    assignment["members"][0]["canonical_identity"] = f"scratchpad:{output_path}"
    return worker_tx.compile_worker_plan(
        run_id=base["run_id"],
        phase=contract.phase,
        work_unit_id=unit,
        generation=base["generation"],
        phase_roster_denominator_digest=denominator["roster_denominator_digest"],
        phase_io_contract_digest=contract.digest,
        phase_io_launch_digest=launch.digest,
        phase_io_input_set_digest=base["phase_io_input_set_digest"],
        prompt_template_sha256=base["prompt_template_sha256"],
        methodology_digests=base["methodology_digests"],
        source_snapshot_digest=base["source_snapshot_digest"],
        provider=base["provider"],
        assignment=assignment,
        write_scope={"mode": "ATTEMPT_ONLY", "roots": ["output"]},
        child_denominator=base["child_denominator"],
        completion_policy=base["completion_policy"],
        retry_policy=base["retry_policy"],
        terminal_debt_policy=base["terminal_debt_policy"],
    )


def _write_signed(
    path: Path,
    unsigned: dict,
    digest_field: str,
    *,
    newline_digest: bool = False,
) -> dict:
    digest_input = canonical_json_bytes(unsigned) + (b"\n" if newline_digest else b"")
    value = {**unsigned, digest_field: hashlib.sha256(digest_input).hexdigest()}
    path.parent.mkdir(parents=True, exist_ok=True)
    from program_facts_types import canonical_file_bytes

    path.write_bytes(canonical_file_bytes(value))
    return value


def _execution_witness(
    scratchpad: Path,
    *,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    plan: dict,
    snapshot: dict,
    output_bytes: bytes,
    attempt_id: str,
) -> WorkerExecutionReplayWitness:
    output = contract.outputs[0]
    output_path = scratchpad / output.path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output_bytes)
    prefix = Path(".method_card_execution") / contract.work_unit_id / attempt_id
    provider_path = scratchpad / prefix / "provider.json"
    provider = _write_signed(
        provider_path,
        {"schema": "fixture.provider.v1", "output_source_mode": "WORKER_FILE_OUTPUTS"},
        "completion_sha256",
        newline_digest=True,
    )
    attempt_path = scratchpad / prefix / "attempt.json"
    attempt = _write_signed(
        attempt_path,
        {
            "schema": "fixture.attempt.v1",
            "run_id": plan["run_id"],
            "phase": plan["phase"],
            "work_unit_id": plan["work_unit_id"],
            "generation": plan["generation"],
            "work_plan_digest": plan["work_plan_digest"],
            "attempt_id": attempt_id,
            "provider_completion_relative_path": prefix.joinpath("provider.json").as_posix(),
            "provider_completion_digest": provider["completion_sha256"],
            "canonical_projection_state": "PENDING_PHASE_IO",
        },
        "completion_digest",
    )
    raw_sha = hashlib.sha256(output_bytes).hexdigest()
    incorporation_path = scratchpad / prefix / "incorporation.json"
    incorporation = _write_signed(
        incorporation_path,
        {
            "schema": "plamen.worker_phaseio_incorporation.v1",
            "run_id": plan["run_id"],
            "phase": plan["phase"],
            "work_unit_id": plan["work_unit_id"],
            "generation": plan["generation"],
            "work_plan_digest": plan["work_plan_digest"],
            "attempt_id": attempt_id,
            "provider_completion_digest": provider["completion_sha256"],
            "contract_digest": contract.digest,
            "launch_digest": launch.digest,
            "projection_state": "COMPLETE",
            "projected_members": [
                {
                    "canonical_identity": output.identity,
                    "sha256": raw_sha,
                    "size": len(output_bytes),
                }
            ],
        },
        "incorporation_digest",
    )
    unsigned_authority = {
        "schema": "plamen.worker_execution_authority.v1",
        "run_id": plan["run_id"],
        "phase": plan["phase"],
        "work_unit_id": plan["work_unit_id"],
        "generation": plan["generation"],
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "attempt_completion_relative_path": prefix.joinpath("attempt.json").as_posix(),
        "attempt_completion_digest": attempt["completion_digest"],
        "provider_completion_relative_path": prefix.joinpath("provider.json").as_posix(),
        "provider_completion_digest": provider["completion_sha256"],
        "incorporation_relative_path": prefix.joinpath("incorporation.json").as_posix(),
        "incorporation_digest": incorporation["incorporation_digest"],
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
    }
    authority = {
        **unsigned_authority,
        "authority_digest": _digest(unsigned_authority),
    }
    return WorkerExecutionReplayWitness(
        scratchpad=scratchpad,
        authority=authority,
        phase_io_contract=contract,
        phase_io_launch=launch,
        run_id=plan["run_id"],
        work_plan=plan,
        audit_snapshot=snapshot,
    )


def _fixture(tmp_path: Path):
    fixture = runtime_fixtures.runtime_fixture.__wrapped__(tmp_path)
    producer_contract, producer_launch = _phaseio(
        "breadth-method-card-001", OUTPUT_PATH
    )
    producer_plan = _plan_for_phaseio(
        fixture.plan,
        producer_contract,
        producer_launch,
        output_path=OUTPUT_PATH,
    )
    fixture = replace(fixture, plan=producer_plan)
    authority = runtime_fixtures._compile(fixture)
    runtime_witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=fixture.snapshot,
        work_plan=fixture.plan,
        denominator_source=fixture.denominator_source,
        expected_denominator_producer=fixture.denominator_producer,
        expected_graph_binding=fixture.graph_binding,
        expected_catalog=fixture.catalog,
    )
    reviewer_contract, reviewer_launch = _phaseio(
        "breadth-method-card-review-001", "method_card_review.md"
    )
    reviewer_plan = _plan_for_phaseio(
        fixture.plan,
        reviewer_contract,
        reviewer_launch,
        output_path="method_card_review.md",
    )
    scratchpad = fixture.root / "scratchpad"
    producer_execution = _execution_witness(
        scratchpad,
        contract=producer_contract,
        launch=producer_launch,
        plan=fixture.plan,
        snapshot=fixture.snapshot,
        output_bytes=_output(authority),
        attempt_id="producer-attempt-1",
    )
    reviewer_execution = _execution_witness(
        scratchpad,
        contract=reviewer_contract,
        launch=reviewer_launch,
        plan=reviewer_plan,
        snapshot=fixture.snapshot,
        output_bytes=b"reviewer execution output\n",
        attempt_id="reviewer-attempt-1",
    )
    return fixture, authority, runtime_witness, producer_execution, reviewer_execution


def _output(authority: dict, *, with_candidates: bool = False) -> bytes:
    lines = ["# MethodCard worker output", ""]
    if with_candidates:
        for index, method in enumerate(
            authority["method_binding"]["selected_methods"], start=1
        ):
            lines.append(
                f"## Finding [MCAPP-{index}]: {method['method_id']} candidate"
            )
    lines.append("Applied the selected methods to the exact denominator.")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _attempt(
    fixture,
    authority: dict,
    runtime_witness: MethodCardRuntimeReplayWitness,
    producer_execution: WorkerExecutionReplayWitness,
    output: bytes,
) -> dict:
    return compile_worker_attempt_identity(
        validated_runtime_authority=authority,
        runtime_replay_witness=runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=producer_execution,
        output_path=OUTPUT_PATH,
        output_bytes=output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
    )


def _claims(
    authority: dict,
    *,
    candidates: bool = False,
    status: str = "CLAIMED_APPLIED",
) -> list[dict]:
    denominator = authority["denominators"]
    evidence = [_span(SOURCE_PATH, SOURCE_BYTES)]
    rows: list[dict] = []
    for index, method in enumerate(
        authority["method_binding"]["selected_methods"], start=1
    ):
        method_steps = [
            row
            for row in denominator["steps"]
            if row["method_id"] == method["method_id"]
            and row["method_version"] == method["method_version"]
        ]
        if status == "CLAIMED_NOT_APPLICABLE":
            outcome = "NOT_APPLICABLE"
            reason = "NO_TARGET_MATCH"
            assumptions: list[str] = []
        elif status == "CLAIMED_UNRESOLVED":
            outcome = "UNRESOLVED"
            reason = None
            assumptions = ["dynamic dispatch target remains unresolved"]
        else:
            outcome = "CANDIDATE_PROPOSED" if candidates else "NO_CANDIDATE"
            reason = None
            assumptions = []
        rows.append(
            {
                "method_id": method["method_id"],
                "method_version": method["method_version"],
                "producer_claim_state": "CLAIMED",
                "status": status,
                "targets_examined": list(denominator["targets"]),
                "relations_examined": list(denominator["relations"]),
                "steps_completed": method_steps,
                "evidence": evidence,
                "outcome": {
                    "kind": outcome,
                    "candidate_ids": [f"MCAPP-{index}"] if candidates else [],
                    "detail": "producer-authored application claim",
                },
                "unresolved_assumptions": assumptions,
                "not_applicable_reason": reason,
            }
        )
    return rows


def _reviews(producer: dict, *, disposition: str = "CONFIRMED_APPLICATION") -> list[dict]:
    return [
        {
            "method_id": claim["method_id"],
            "method_version": claim["method_version"],
            "disposition": disposition,
            "evidence": [_span(SOURCE_PATH, SOURCE_BYTES)],
            "reason": "independently replayed the exact method application",
        }
        for claim in producer["claims"]
    ]


@dataclass(frozen=True)
class CompleteBundle:
    fixture: object
    authority: dict
    runtime_witness: MethodCardRuntimeReplayWitness
    producer_execution: WorkerExecutionReplayWitness
    reviewer_execution: WorkerExecutionReplayWitness
    output: bytes
    attempt: dict
    producer: dict
    review: dict


def _complete_bundle(tmp_path: Path, *, candidates: bool = False) -> CompleteBundle:
    (
        fixture,
        authority,
        runtime_witness,
        producer_execution,
        reviewer_execution,
    ) = _fixture(tmp_path)
    output = _output(authority, with_candidates=candidates)
    if candidates:
        producer_execution = _execution_witness(
            producer_execution.scratchpad,
            contract=producer_execution.phase_io_contract,
            launch=producer_execution.phase_io_launch,
            plan=fixture.plan,
            snapshot=fixture.snapshot,
            output_bytes=output,
            attempt_id="producer-attempt-candidates",
        )
    attempt = _attempt(
        fixture, authority, runtime_witness, producer_execution, output
    )
    producer = compile_producer_application_receipt(
        validated_runtime_authority=authority,
        runtime_replay_witness=runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=producer_execution,
        worker_attempt=attempt,
        output_bytes=output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        claims=_claims(authority, candidates=candidates),
    )
    review = compile_independent_application_review_receipt(
        validated_runtime_authority=authority,
        runtime_replay_witness=runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=producer_execution,
        reviewer_execution_witness=reviewer_execution,
        worker_attempt=attempt,
        output_bytes=output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        producer_receipt=producer,
        reviews=_reviews(producer),
    )
    return CompleteBundle(
        fixture=fixture,
        authority=authority,
        runtime_witness=runtime_witness,
        producer_execution=producer_execution,
        reviewer_execution=reviewer_execution,
        output=output,
        attempt=attempt,
        producer=producer,
        review=review,
    )


def _reconcile(bundle):
    return reconcile_method_card_application(
        validated_runtime_authority=bundle.authority,
        runtime_replay_witness=bundle.runtime_witness,
        implementation_root=bundle.fixture.root,
        producer_execution_witness=bundle.producer_execution,
        reviewer_execution_witness=bundle.reviewer_execution,
        worker_attempt=bundle.attempt,
        output_bytes=bundle.output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        producer_receipt=bundle.producer,
        application_review_receipt=bundle.review,
    )


def test_complete_authority_keeps_producer_claimed_and_grants_no_proof_or_drop(
    tmp_path: Path,
):
    bundle = _complete_bundle(tmp_path)
    result = _reconcile(bundle)

    assert result["schema"] == APPLICATION_AUTHORITY_SCHEMA
    assert result["status"] == "COMPLETE"
    assert result["application_complete"] is True
    assert result["debt"] == []
    assert all(row["producer_claim_state"] == "CLAIMED" for row in result["method_states"])
    assert all(
        row["application_disposition"] == "INDEPENDENTLY_CONFIRMED"
        for row in result["method_states"]
    )
    assert result["authority_limits"] == {
        "application_completion_authority": False,
        "drop_authority": False,
        "evidence_proof_authority": False,
        "finding_authority": False,
        "negative_authority": False,
        "report_authority": False,
        "semantic_authority": False,
        "severity_authority": False,
    }

    raw = canonical_method_card_application_authority_bytes(result)
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    validated = validate_method_card_application_authority(
        raw,
        validated_runtime_authority=bundle.authority,
        runtime_replay_witness=bundle.runtime_witness,
        implementation_root=bundle.fixture.root,
        producer_execution_witness=bundle.producer_execution,
        reviewer_execution_witness=bundle.reviewer_execution,
        worker_attempt=bundle.attempt,
        output_bytes=bundle.output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        producer_receipt=bundle.producer,
        application_review_receipt=bundle.review,
    )
    assert validated == result


@pytest.mark.parametrize("field", ["targets_examined", "relations_examined"])
def test_private_subset_or_empty_relation_coverage_fails_closed(
    tmp_path: Path, field: str,
):
    fixture, authority, runtime_witness, producer_execution, _reviewer = _fixture(tmp_path)
    output = _output(authority)
    attempt = _attempt(fixture, authority, runtime_witness, producer_execution, output)
    claims = _claims(authority)
    claims[0][field] = []

    with pytest.raises(MethodCardApplicationAuthorityError, match="exact denominator"):
        compile_producer_application_receipt(
            validated_runtime_authority=authority,
            runtime_replay_witness=runtime_witness,
            implementation_root=fixture.root,
            producer_execution_witness=producer_execution,
            worker_attempt=attempt,
            output_bytes=output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            claims=claims,
        )


def test_candidate_claim_requires_identity_bound_into_exact_output(tmp_path: Path):
    fixture, authority, runtime_witness, producer_execution, _reviewer = _fixture(tmp_path)
    output = _output(authority)
    attempt = _attempt(fixture, authority, runtime_witness, producer_execution, output)
    claims = _claims(authority, candidates=True)

    with pytest.raises(MethodCardApplicationAuthorityError, match="candidate identity"):
        compile_producer_application_receipt(
            validated_runtime_authority=authority,
            runtime_replay_witness=runtime_witness,
            implementation_root=fixture.root,
            producer_execution_witness=producer_execution,
            worker_attempt=attempt,
            output_bytes=output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            claims=claims,
        )

    output_with_ids = _output(authority, with_candidates=True)
    producer_with_ids = _execution_witness(
        producer_execution.scratchpad,
        contract=producer_execution.phase_io_contract,
        launch=producer_execution.phase_io_launch,
        plan=fixture.plan,
        snapshot=fixture.snapshot,
        output_bytes=output_with_ids,
        attempt_id="producer-attempt-candidate-success",
    )
    attempt_with_ids = _attempt(
        fixture, authority, runtime_witness, producer_with_ids, output_with_ids
    )
    receipt = compile_producer_application_receipt(
        validated_runtime_authority=authority,
        runtime_replay_witness=runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=producer_with_ids,
        worker_attempt=attempt_with_ids,
        output_bytes=output_with_ids,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        claims=claims,
    )
    assert all(row["outcome"]["candidate_ids"] for row in receipt["claims"])


def test_self_review_is_rejected_even_with_a_resigned_receipt(tmp_path: Path):
    fixture, authority, runtime_witness, producer_execution, _reviewer = _fixture(tmp_path)
    output = _output(authority)
    attempt = _attempt(fixture, authority, runtime_witness, producer_execution, output)
    producer = compile_producer_application_receipt(
        validated_runtime_authority=authority,
        runtime_replay_witness=runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=producer_execution,
        worker_attempt=attempt,
        output_bytes=output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        claims=_claims(authority),
    )

    with pytest.raises(MethodCardApplicationAuthorityError, match="independent"):
        compile_independent_application_review_receipt(
            validated_runtime_authority=authority,
            runtime_replay_witness=runtime_witness,
            implementation_root=fixture.root,
            producer_execution_witness=producer_execution,
            reviewer_execution_witness=producer_execution,
            worker_attempt=attempt,
            output_bytes=output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            producer_receipt=producer,
            reviews=_reviews(producer),
        )


def test_second_attempt_in_producer_work_unit_is_not_an_independent_review(
    tmp_path: Path,
):
    bundle = _complete_bundle(tmp_path)
    same_unit_reviewer = _execution_witness(
        bundle.producer_execution.scratchpad,
        contract=bundle.producer_execution.phase_io_contract,
        launch=bundle.producer_execution.phase_io_launch,
        plan=bundle.producer_execution.work_plan,
        snapshot=bundle.fixture.snapshot,
        output_bytes=bundle.output,
        attempt_id="producer-unit-second-attempt",
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="independent"):
        compile_independent_application_review_receipt(
            validated_runtime_authority=bundle.authority,
            runtime_replay_witness=bundle.runtime_witness,
            implementation_root=bundle.fixture.root,
            producer_execution_witness=bundle.producer_execution,
            reviewer_execution_witness=same_unit_reviewer,
            worker_attempt=bundle.attempt,
            output_bytes=bundle.output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            producer_receipt=bundle.producer,
            reviews=_reviews(bundle.producer),
        )


@pytest.mark.parametrize(
    ("mutation", "pattern"),
    [
        ("attempt", "attempt"),
        ("review_execution", "independent"),
        ("output", "output"),
        ("source", "source"),
    ],
)
def test_stale_cross_attempt_cross_backend_or_byte_drift_fails(
    tmp_path: Path, mutation: str, pattern: str,
):
    bundle = _complete_bundle(tmp_path)
    if mutation == "attempt":
        attempt = copy.deepcopy(bundle.attempt)
        attempt["attempt_id"] = "attacker-resigned-attempt"
        unsigned = dict(attempt)
        unsigned.pop("attempt_digest")
        attempt["attempt_digest"] = _digest(unsigned)
        bundle = replace(bundle, attempt=attempt)
    elif mutation == "review_execution":
        bundle = replace(bundle, reviewer_execution=bundle.producer_execution)
    elif mutation == "output":
        bundle = replace(bundle, output=bundle.output + b"tampered\n")
    else:
        with pytest.raises(MethodCardApplicationAuthorityError, match=pattern):
            reconcile_method_card_application(
                validated_runtime_authority=bundle.authority,
                runtime_replay_witness=bundle.runtime_witness,
                implementation_root=bundle.fixture.root,
                producer_execution_witness=bundle.producer_execution,
                reviewer_execution_witness=bundle.reviewer_execution,
                worker_attempt=bundle.attempt,
                output_bytes=bundle.output,
                source_files={SOURCE_PATH: SOURCE_BYTES + b"// drift\n"},
                producer_receipt=bundle.producer,
                application_review_receipt=bundle.review,
            )
        return

    with pytest.raises(MethodCardApplicationAuthorityError, match=pattern):
        _reconcile(bundle)


def test_evidence_range_hash_tamper_fails_before_reconciliation(tmp_path: Path):
    fixture, authority, runtime_witness, producer_execution, _reviewer = _fixture(tmp_path)
    output = _output(authority)
    attempt = _attempt(fixture, authority, runtime_witness, producer_execution, output)
    claims = _claims(authority)
    claims[0]["evidence"][0]["sha256"] = "0" * 64

    with pytest.raises(MethodCardApplicationAuthorityError, match="evidence.*digest"):
        compile_producer_application_receipt(
            validated_runtime_authority=authority,
            runtime_replay_witness=runtime_witness,
            implementation_root=fixture.root,
            producer_execution_witness=producer_execution,
            worker_attempt=attempt,
            output_bytes=output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            claims=claims,
        )


def test_unresolved_independent_review_is_durable_typed_debt(tmp_path: Path):
    bundle = _complete_bundle(tmp_path)
    review = compile_independent_application_review_receipt(
        validated_runtime_authority=bundle.authority,
        runtime_replay_witness=bundle.runtime_witness,
        implementation_root=bundle.fixture.root,
        producer_execution_witness=bundle.producer_execution,
        reviewer_execution_witness=bundle.reviewer_execution,
        worker_attempt=bundle.attempt,
        output_bytes=bundle.output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        producer_receipt=bundle.producer,
        reviews=_reviews(bundle.producer, disposition="UNRESOLVED_APPLICATION"),
    )
    bundle = replace(bundle, review=review)
    result = _reconcile(bundle)

    assert result["status"] == "DEBT"
    assert result["application_complete"] is False
    assert len(result["debt"]) == len(bundle.producer["claims"])
    assert {row["code"] for row in result["debt"]} == {
        "INDEPENDENT_APPLICATION_REVIEW_UNRESOLVED"
    }


def _zero_denominator_authority(
    fixture,
    producer_execution: WorkerExecutionReplayWitness,
) -> tuple[dict, MethodCardRuntimeReplayWitness, dict]:
    coverage = {
        "coverage_kind": "EXACT",
        "unknown_remainder": False,
        "limitation_reason": None,
    }
    graph_schema = "fixture.program-graph.v1"
    unsigned_source = {
        "schema": "plamen.method-card-denominator-source.v1",
        "producer": runtime_fixtures._producer(),
        "audit_snapshot_digest": fixture.snapshot["snapshot_digest"],
        "source_scope_digest": fixture.snapshot["components"]["source_scope"]["digest"],
        "graph_schema": graph_schema,
        "graph_digest": runtime_fixtures._graph_digest(
            graph_schema=graph_schema,
            coverage=coverage,
            nodes=[],
            relations=[],
        ),
        "coverage": coverage,
        "nodes": [],
        "relations": [],
    }
    source = {**unsigned_source, "source_digest": _digest(unsigned_source)}
    graph = {
        "graph_schema": graph_schema,
        "graph_digest": source["graph_digest"],
    }
    fragment = render_selected_method_fragment(fixture.catalog, fixture.selections)
    runtime_input = compile_method_card_runtime_input_binding(
        implementation_root=fixture.root,
        audit_snapshot=fixture.snapshot,
        selected_methods=fixture.selections,
        denominator_source=source,
        expected_denominator_producer=fixture.denominator_producer,
        expected_graph_binding=graph,
        target_denominator=(),
        relation_denominator=(),
        step_denominator=fixture.steps,
        expected_catalog=fixture.catalog,
    )
    base_plan = runtime_fixtures._work_plan(
        fixture.snapshot,
        (
            fixture.catalog.digest,
            hashlib.sha256(fragment).hexdigest(),
            runtime_input["runtime_input_binding_digest"],
            fixture.snapshot["components"]["methodology"]["digest"],
        ),
        prompt_digest=runtime_fixtures._sha("zero-denominator-prompt"),
    )
    plan = _plan_for_phaseio(
        base_plan,
        producer_execution.phase_io_contract,
        producer_execution.phase_io_launch,
        output_path=OUTPUT_PATH,
    )
    authority = compile_method_card_runtime_authority(
        implementation_root=fixture.root,
        audit_snapshot=fixture.snapshot,
        work_plan=plan,
        selected_methods=fixture.selections,
        denominator_source=source,
        expected_denominator_producer=fixture.denominator_producer,
        expected_graph_binding=graph,
        target_denominator=(),
        relation_denominator=(),
        step_denominator=fixture.steps,
        expected_catalog=fixture.catalog,
    )
    witness = MethodCardRuntimeReplayWitness(
        audit_snapshot=fixture.snapshot,
        work_plan=plan,
        denominator_source=source,
        expected_denominator_producer=fixture.denominator_producer,
        expected_graph_binding=graph,
        expected_catalog=fixture.catalog,
    )
    return authority, witness, plan


def test_not_applicable_requires_authoritative_zero_denominator_and_card_policy(
    tmp_path: Path,
):
    (
        fixture,
        nonzero,
        runtime_witness,
        producer_execution,
        reviewer_execution,
    ) = _fixture(tmp_path)
    output = _output(nonzero)
    attempt = _attempt(
        fixture, nonzero, runtime_witness, producer_execution, output
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="zero denominator"):
        compile_producer_application_receipt(
            validated_runtime_authority=nonzero,
            runtime_replay_witness=runtime_witness,
            implementation_root=fixture.root,
            producer_execution_witness=producer_execution,
            worker_attempt=attempt,
            output_bytes=output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            claims=_claims(nonzero, status="CLAIMED_NOT_APPLICABLE"),
        )

    zero, zero_runtime_witness, zero_plan = _zero_denominator_authority(
        fixture, producer_execution
    )
    zero_output = _output(zero)
    zero_producer_execution = _execution_witness(
        producer_execution.scratchpad,
        contract=producer_execution.phase_io_contract,
        launch=producer_execution.phase_io_launch,
        plan=zero_plan,
        snapshot=fixture.snapshot,
        output_bytes=zero_output,
        attempt_id="producer-zero-attempt",
    )
    zero_attempt = _attempt(
        fixture,
        zero,
        zero_runtime_witness,
        zero_producer_execution,
        zero_output,
    )
    producer = compile_producer_application_receipt(
        validated_runtime_authority=zero,
        runtime_replay_witness=zero_runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=zero_producer_execution,
        worker_attempt=zero_attempt,
        output_bytes=zero_output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        claims=_claims(zero, status="CLAIMED_NOT_APPLICABLE"),
    )
    review = compile_independent_application_review_receipt(
        validated_runtime_authority=zero,
        runtime_replay_witness=zero_runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=zero_producer_execution,
        reviewer_execution_witness=reviewer_execution,
        worker_attempt=zero_attempt,
        output_bytes=zero_output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        producer_receipt=producer,
        reviews=_reviews(producer),
    )
    result = reconcile_method_card_application(
        validated_runtime_authority=zero,
        runtime_replay_witness=zero_runtime_witness,
        implementation_root=fixture.root,
        producer_execution_witness=zero_producer_execution,
        reviewer_execution_witness=reviewer_execution,
        worker_attempt=zero_attempt,
        output_bytes=zero_output,
        source_files={SOURCE_PATH: SOURCE_BYTES},
        producer_receipt=producer,
        application_review_receipt=review,
    )
    assert result["status"] == "COMPLETE"
    assert {row["producer_status"] for row in result["method_states"]} == {
        "CLAIMED_NOT_APPLICABLE"
    }


def test_recomputed_application_authority_tamper_cannot_validate(tmp_path: Path):
    bundle = _complete_bundle(tmp_path)
    result = _reconcile(bundle)
    tampered = copy.deepcopy(result)
    tampered["authority_limits"]["severity_authority"] = True
    unsigned = dict(tampered)
    unsigned.pop("authority_digest")
    tampered["authority_digest"] = _digest(unsigned)

    with pytest.raises(MethodCardApplicationAuthorityError, match="authority limits"):
        validate_method_card_application_authority(
            tampered,
            validated_runtime_authority=bundle.authority,
            runtime_replay_witness=bundle.runtime_witness,
            implementation_root=bundle.fixture.root,
            producer_execution_witness=bundle.producer_execution,
            reviewer_execution_witness=bundle.reviewer_execution,
            worker_attempt=bundle.attempt,
            output_bytes=bundle.output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            producer_receipt=bundle.producer,
            application_review_receipt=bundle.review,
        )


def test_attacker_resigned_runtime_mapping_cannot_replace_full_current_replay(
    tmp_path: Path,
):
    bundle = _complete_bundle(tmp_path)
    forged = copy.deepcopy(bundle.authority)
    forged["work_plan_binding"]["phase_io_input_set_digest"] = "f" * 64
    unsigned = dict(forged)
    unsigned.pop("authority_digest")
    forged["authority_digest"] = _digest(unsigned)

    with pytest.raises(MethodCardApplicationAuthorityError, match="does not replay"):
        compile_worker_attempt_identity(
            validated_runtime_authority=forged,
            runtime_replay_witness=bundle.runtime_witness,
            implementation_root=bundle.fixture.root,
            producer_execution_witness=bundle.producer_execution,
            output_path=OUTPUT_PATH,
            output_bytes=bundle.output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
        )


def test_producer_execution_requires_current_receipt_chain_and_exact_snapshot_manifest(
    tmp_path: Path,
):
    bundle = _complete_bundle(tmp_path)
    forged_authority = copy.deepcopy(bundle.producer_execution.authority)
    forged_authority["attempt_id"] = "forged-attempt"
    unsigned = dict(forged_authority)
    unsigned.pop("authority_digest")
    forged_authority["authority_digest"] = _digest(unsigned)
    forged_execution = replace(
        bundle.producer_execution,
        authority=forged_authority,
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="execution does not replay"):
        compile_worker_attempt_identity(
            validated_runtime_authority=bundle.authority,
            runtime_replay_witness=bundle.runtime_witness,
            implementation_root=bundle.fixture.root,
            producer_execution_witness=forged_execution,
            output_path=OUTPUT_PATH,
            output_bytes=bundle.output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
        )

    stale_snapshot = copy.deepcopy(bundle.fixture.snapshot)
    stale_snapshot["components"]["source_scope"]["digest"] = "0" * 64
    stale_execution = replace(
        bundle.producer_execution,
        audit_snapshot=stale_snapshot,
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="exact current source snapshot"):
        compile_worker_attempt_identity(
            validated_runtime_authority=bundle.authority,
            runtime_replay_witness=bundle.runtime_witness,
            implementation_root=bundle.fixture.root,
            producer_execution_witness=stale_execution,
            output_path=OUTPUT_PATH,
            output_bytes=bundle.output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
        )


def test_claims_must_equal_complete_parsed_candidate_set(tmp_path: Path):
    (
        fixture,
        authority,
        runtime_witness,
        producer_execution,
        _reviewer,
    ) = _fixture(tmp_path)
    output = _output(authority, with_candidates=True) + (
        b"\n### Finding [UNCLAIMED-1]: omitted by producer receipt\nbody\n"
    )
    producer_execution = _execution_witness(
        producer_execution.scratchpad,
        contract=producer_execution.phase_io_contract,
        launch=producer_execution.phase_io_launch,
        plan=fixture.plan,
        snapshot=fixture.snapshot,
        output_bytes=output,
        attempt_id="producer-extra-candidate",
    )
    attempt = _attempt(
        fixture, authority, runtime_witness, producer_execution, output
    )
    with pytest.raises(MethodCardApplicationAuthorityError, match="exact parsed candidate set"):
        compile_producer_application_receipt(
            validated_runtime_authority=authority,
            runtime_replay_witness=runtime_witness,
            implementation_root=fixture.root,
            producer_execution_witness=producer_execution,
            worker_attempt=attempt,
            output_bytes=output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            claims=_claims(authority, candidates=True),
        )


@pytest.mark.parametrize("status", ["COMPLETE", "DEBT"])
def test_resigned_empty_method_state_authority_is_not_canonical(
    tmp_path: Path,
    status: str,
):
    result = _reconcile(_complete_bundle(tmp_path))
    forged = copy.deepcopy(result)
    forged["status"] = status
    forged["application_complete"] = status == "COMPLETE"
    forged["method_states"] = []
    forged["debt"] = []
    unsigned = dict(forged)
    unsigned.pop("authority_digest")
    forged["authority_digest"] = _digest(unsigned)

    with pytest.raises(MethodCardApplicationAuthorityError, match="nonempty"):
        canonical_method_card_application_authority_bytes(forged)


def test_resigned_lower_bound_authority_cannot_delete_required_debt(
    tmp_path: Path,
):
    result = _reconcile(_complete_bundle(tmp_path))
    forged = copy.deepcopy(result)
    forged["denominator"]["coverage_kind"] = "LOWER_BOUND"
    forged["denominator"]["unknown_remainder"] = True
    forged["denominator"]["limitation_reason"] = "fixture remainder"
    forged["status"] = "DEBT"
    forged["application_complete"] = False
    forged["debt"] = []
    unsigned = dict(forged)
    unsigned.pop("authority_digest")
    forged["authority_digest"] = _digest(unsigned)

    with pytest.raises(MethodCardApplicationAuthorityError, match="lower-bound.*debt"):
        canonical_method_card_application_authority_bytes(forged)


def test_full_validation_replays_current_methodology_while_canonicalization_is_structural(
    tmp_path: Path,
):
    bundle = _complete_bundle(tmp_path)
    result = _reconcile(bundle)
    assert canonical_method_card_application_authority_bytes(result)
    catalog = bundle.fixture.root / "methodology" / "method-cards-v1.yaml"
    catalog.write_bytes(catalog.read_bytes() + b"\n")

    with pytest.raises(MethodCardApplicationAuthorityError, match="does not replay"):
        validate_method_card_application_authority(
            result,
            validated_runtime_authority=bundle.authority,
            runtime_replay_witness=bundle.runtime_witness,
            implementation_root=bundle.fixture.root,
            producer_execution_witness=bundle.producer_execution,
            reviewer_execution_witness=bundle.reviewer_execution,
            worker_attempt=bundle.attempt,
            output_bytes=bundle.output,
            source_files={SOURCE_PATH: SOURCE_BYTES},
            producer_receipt=bundle.producer,
            application_review_receipt=bundle.review,
        )
