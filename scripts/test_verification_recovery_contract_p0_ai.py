"""P0-AI recovery verifiers compile from the same live method registry."""
from __future__ import annotations

import copy
import ast
import json
from pathlib import Path

import pytest

from verification_recovery_contract import (
    RecoveryContractError,
    build_verification_recovery_contract,
    validate_verification_recovery_contract,
    write_or_validate_verification_recovery_contract,
)
import plamen_driver as DRIVER
from artifact_ledger import read_artifact_ledger
from test_claude_mcp_generation_authority import (
    authenticated_mcp_selection_fixture,
)


ROOT = Path(__file__).resolve().parent.parent


def _authenticated_runtime_selection() -> dict[str, object]:
    return authenticated_mcp_selection_fixture()


@pytest.fixture(autouse=True)
def _admitted_claude_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Model production admission for direct recovery compiler unit tests."""

    monkeypatch.setattr(
        DRIVER,
        "_DIRECT_CLAUDE_MCP_SELECTION",
        _authenticated_runtime_selection(),
    )


def _severity_proposal(work_id: str) -> dict[str, object]:
    return {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": work_id,
        "constituent_ids": [work_id],
        "impact": {
            "class": "High", "harmed_asset": "protected asset",
            "harmed_capability": "asset integrity", "premise_id": "PREM-I",
            "premise_kind": "INTERNAL", "evidence_ids": ["EVID-I"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "likelihood": {
            "class": "Medium", "actor": "unprivileged actor",
            "preconditions": ["reachable state"], "premise_id": "PREM-L",
            "premise_kind": "INTERNAL", "evidence_ids": ["EVID-L"],
            "proof_scope": "IN_SCOPE_EXECUTION",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            work_id: {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }


def _emit_recovery_outputs(spec, *, prompt_path: Path, scratchpad: Path) -> None:
    contract = json.loads((prompt_path.parent / "contract.json").read_text(encoding="utf-8"))
    dispatch = contract["method_dispatch"]
    for dispatch_row in dispatch["rows"]:
        work_id = dispatch_row["work_item_id"]
        (scratchpad / f"verify_{work_id}.md").write_text(
            "# Independent verification\n\n"
            "**Severity**: High\n**Impact**: High\n**Likelihood**: Medium\n"
            "**Evidence Tag**: [CODE-TRACE]\n**Verdict**: CONTESTED\n\n"
            "The independent verifier traced the exact assigned transition and "
            "retained the proposal pending the ordinary downstream gates.\n",
            encoding="utf-8",
        )
        operators = []
        for operator_id in dispatch_row["operator_ids"]:
            blocked = (
                operator_id == "context-closure"
                and dispatch_row["context_state"] == "CONTEXT_UNRESOLVED"
            )
            operators.append({
                "operator_id": operator_id,
                "status": "BLOCKED" if blocked else "APPLIED",
                "evidence": [] if blocked else [{
                    "source": "src/generic.ext:1",
                    "detail": "Fixture applied the compiler-selected operator.",
                }],
                "predicate": None,
                "debt_code": "CONTEXT_UNRESOLVED" if blocked else None,
                "blocker_evidence": ["No context graph edge in fixture."] if blocked else [],
            })
        application = {
            "schema_version": "plamen.verification_operator_application.v1",
            "work_item_id": work_id,
            "method_dispatch_id": dispatch["dispatch_id"],
            "selected_module_hashes": dispatch_row["module_hashes"],
            "context_packet_digest": dispatch_row["context_packet_digest"],
            "context_status": dispatch_row["context_state"],
            "context_expansion": [],
            "operators": operators,
            "new_observations": [],
        }
        (scratchpad / f"verify_{work_id}.severity_proposal.json").write_text(
            json.dumps(_severity_proposal(work_id)), encoding="utf-8"
        )
        (scratchpad / f"verify_{work_id}.operator_application.json").write_text(
            json.dumps(application), encoding="utf-8"
        )


def _row(work_id: str = "H-01") -> dict[str, object]:
    return {
        "finding id": work_id,
        "severity": "High",
        "title": "Queued transition requires independent recovery",
        "bug class": "state-accounting",
        "poc class": "unit",
        "location_records": [{
            "artifact": "src/Vault.sol",
            "start_line": 10,
            "end_line": 20,
            "symbol": "settle",
            "note": None,
        }],
        "primary artifact": "depth_state_findings.md",
    }


def _semantic_row(work_id: str = "H-01", *, evidence: str = "trace-a") -> dict[str, object]:
    row = _row(work_id)
    row.update({
        "location": "src/Vault.sol:10-20:settle",
        "mechanism": "The assigned state transition violates its exact postcondition.",
        "harm": "The protected state property can be violated.",
        "evidence": evidence,
        "source_candidate_digest": "a" * 64,
        "source_work_item_id": "INV-041",
        "source_identity": "depth-state:INV-041",
        "finding_lifecycle_obligation_id": "FLO-041",
        "producer_identity": "depth-state-producer",
        "required_discriminator_identity": "late-independent-verifier",
        "independent_discriminator_required": True,
    })
    return row


def test_mandatory_reopen_recovery_preserves_exact_harm_packet(
    tmp_path: Path,
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    row = _semantic_row("MRVW-EXACT")

    contract = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="MANDATORY_REOPEN",
        rows=[row],
        scratchpad=scratch,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=ROOT,
    )

    assert contract["rows"][0]["harm"] == row["harm"]
    assert row["harm"] in contract["manifest_markdown"]
    assert contract["manifest_path"] in contract["prompt_markdown"]


@pytest.mark.parametrize(
    "pipeline,ecosystem,backend",
    [
        ("sc", "evm", "claude"),
        ("sc", "soroban", "codex"),
        ("l1", "go", "claude"),
        ("l1", "mixed", "codex"),
    ],
)
def test_recovery_contract_uses_live_compiler_for_every_backend_and_pipeline(
    tmp_path: Path, pipeline: str, ecosystem: str, backend: str
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    (project / "src").mkdir(parents=True)
    scratch.mkdir()
    (project / "src" / "Vault.sol").write_text(
        "function settle() external {}\n", encoding="utf-8"
    )
    (scratch / "caller_map.md").write_text(
        "settle <- finalize src/Router.sol\n", encoding="utf-8"
    )

    contract = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="POST_VERIFY_SIDE_OBSERVATION",
        rows=[_row()],
        scratchpad=scratch,
        project_root=project,
        pipeline=pipeline,
        ecosystem=ecosystem,
        backend=backend,
        repo_root=ROOT,
    )

    assert contract["pipeline"] == pipeline
    assert contract["ecosystem"] == ecosystem
    assert contract["backend"] == backend
    assert contract["method_dispatch"]["dispatch_id"] in contract["prompt_markdown"]
    assert contract["method_dispatch"]["backend"] == backend
    assert "operator_application.json" in contract["prompt_markdown"]
    assert "Impact:" in contract["prompt_markdown"]
    assert "Likelihood:" in contract["prompt_markdown"]
    assert "Independent Severity:" in contract["prompt_markdown"]
    assert "legacy ecosystem verification prompts" in contract["prompt_markdown"]
    assert "phase5-verification-sc.md" not in contract["prompt_markdown"]
    assert "phase5-verification-l1.md" not in contract["prompt_markdown"]
    assert contract["expected_operator_receipts"] == [
        "verify_H-01.operator_receipt.json"
    ]


def test_recovery_contract_is_bounded_and_does_not_mutate_primary_queue(
    tmp_path: Path,
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    primary = scratch / "verification_queue.md"
    primary.write_bytes(b"primary queue bytes\n")
    before = primary.read_bytes()
    rows = [_row(f"H-{index + 1:02d}") for index in range(4)]

    contract = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="RESUME_QUEUE_DROPOUT",
        rows=rows,
        scratchpad=scratch,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=ROOT,
        max_rows=4,
    )
    assert contract["row_count"] == 4
    assert primary.read_bytes() == before
    with pytest.raises(RecoveryContractError, match="bounded"):
        build_verification_recovery_contract(
            run_id="run-1",
            recovery_kind="RESUME_QUEUE_DROPOUT",
            rows=[*rows, _row("H-05")],
            scratchpad=scratch,
            project_root=project,
            pipeline="sc",
            ecosystem="evm",
            backend="claude",
            repo_root=ROOT,
            max_rows=4,
        )


def test_recovery_contract_write_is_idempotent_and_context_change_invalidates(
    tmp_path: Path,
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    context = scratch / "caller_map.md"
    context.write_text("settle <- finalize src/Router.sol\n", encoding="utf-8")
    first = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="LATE_OPERATOR_CANDIDATE",
        rows=[_row()],
        scratchpad=scratch,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=ROOT,
    )
    target = scratch / "recovery" / "contract.json"
    assert write_or_validate_verification_recovery_contract(target, first)
    before = target.stat().st_mtime_ns
    assert not write_or_validate_verification_recovery_contract(target, first)
    assert target.stat().st_mtime_ns == before

    context.write_text("settle <- another src/Other.sol\n", encoding="utf-8")
    changed = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="LATE_OPERATOR_CANDIDATE",
        rows=[_row()],
        scratchpad=scratch,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=ROOT,
    )
    assert changed["contract_digest"] != first["contract_digest"]
    with pytest.raises(RecoveryContractError, match="differs"):
        write_or_validate_verification_recovery_contract(target, changed)


def test_contract_tamper_and_windows_path_roundtrip_fail_closed(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    contract = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="POST_VERIFY_SIDE_OBSERVATION",
        rows=[_row()],
        scratchpad=scratch,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="codex",
        repo_root=ROOT,
    )
    assert "\\" not in contract["manifest_path"]
    assert contract["manifest_path"].startswith("_verification_recovery/")
    replay = json.loads(json.dumps(contract))
    assert validate_verification_recovery_contract(replay) == contract
    tampered = copy.deepcopy(contract)
    tampered["prompt_markdown"] += "\nchanged"
    with pytest.raises(RecoveryContractError, match="prompt|digest"):
        validate_verification_recovery_contract(tampered)


def test_recovery_identity_binds_the_exact_semantic_claim(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)

    first = build_verification_recovery_contract(
        run_id="run-1", recovery_kind="LATE_OPERATOR_CANDIDATE",
        rows=[_semantic_row(evidence="trace-a")], scratchpad=scratch,
        project_root=project, pipeline="sc", ecosystem="evm",
        backend="claude", repo_root=ROOT,
    )
    second = build_verification_recovery_contract(
        run_id="run-1", recovery_kind="LATE_OPERATOR_CANDIDATE",
        rows=[_semantic_row(evidence="trace-b")], scratchpad=scratch,
        project_root=project, pipeline="sc", ecosystem="evm",
        backend="claude", repo_root=ROOT,
    )

    assert first["contract_digest"] != second["contract_digest"]
    assert first["recovery_id"] != second["recovery_id"]
    exact = first["rows"][0]
    assert exact["mechanism"].startswith("The assigned state transition")
    assert exact["evidence"] == "trace-a"
    assert exact["source_candidate_digest"] == "a" * 64
    assert exact["source_work_item_id"] == "INV-041"
    assert exact["source_identity"] == "depth-state:INV-041"
    assert exact["finding_lifecycle_obligation_id"] == "FLO-041"
    assert exact["producer_identity"] != exact["required_discriminator_identity"]
    assert exact["independent_discriminator_required"] is True
    assert exact["location_records"] == [{
        "artifact": "src/Vault.sol",
        "start_line": 10,
        "end_line": 20,
        "symbol": "settle",
        "note": None,
    }]


@pytest.mark.parametrize(
    "pipeline,ecosystem,backend,mode",
    [
        ("sc", "evm", "claude", "core"),
        ("sc", "soroban", "codex", "thorough"),
        ("l1", "rust", "claude", "core"),
        ("l1", "go", "codex", "thorough"),
    ],
)
def test_live_recovery_is_compiler_bound_receipted_and_resume_exact(
    tmp_path: Path,
    monkeypatch,
    pipeline: str,
    ecosystem: str,
    backend: str,
    mode: str,
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    primary = scratch / "verification_queue_work_plan.json"
    primary.write_bytes(b"immutable primary plan\n")
    launches = []

    def execute(spec, *, prompt_path, scratchpad, **_kwargs):
        assert spec.foreground_only is True
        assert spec.background_children_allowed is False
        assert spec.child_join_policy == "REQUIRE_JOIN_BEFORE_RECEIPT"
        assert spec.process_group_policy == "ISOLATED_PROCESS_GROUP"
        assert spec.orphan_policy == "TERMINATE_TREE_AND_RETAIN_DEBT"
        launches.append(spec.digest)
        _emit_recovery_outputs(spec, prompt_path=prompt_path, scratchpad=scratchpad)
        return 0

    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", execute)
    config = {
        "scratchpad": str(scratch), "project_root": str(project),
        "pipeline": pipeline, "language": ecosystem, "cli_backend": backend,
        "mode": mode, "_run_id": "run-1",
        "_verification_recovery_kind": "GENERIC_RECOVERY",
    }
    assert DRIVER._run_verify_recovery_shard(config, [("H-01", _row())]) == []
    assert len(launches) == 1
    directory = next((scratch / "_verification_recovery").glob("VREC-*"))
    receipt = json.loads((directory / "execution_receipt.json").read_text(encoding="utf-8"))
    assert receipt["status"] == "COMPLETED"
    assert receipt["terminal_negative_authority"] is False
    assert (directory / "phase_io_model_contract.json").is_file()
    assert (directory / "phase_io_prelaunch_contract.json").is_file()
    assert (directory / "phase_io_control_contract.json").is_file()
    assert (scratch / "verify_H-01.operator_receipt.json").is_file()
    assert primary.read_bytes() == b"immutable primary plan\n"
    ledger = read_artifact_ledger(scratch)
    recovery_keys = [
        key for key in ledger["work_units"]
        if "/verify_recovery/method_" in key
    ]
    assert len(recovery_keys) == 3
    prelaunch_key = next(
        key for key in recovery_keys if "/method_context." in key
    )
    model_key = next(key for key in recovery_keys if "/method_model." in key)
    control_key = next(key for key in recovery_keys if "/method_receipt." in key)
    assert ledger["work_units"][prelaunch_key]["semantic_status"] == "ACTIVE"
    assert ledger["work_units"][model_key]["semantic_status"] == "ACTIVE"
    assert ledger["work_units"][control_key]["semantic_status"] == "ACTIVE"
    assert set(ledger["work_units"][prelaunch_key]["artifacts"]) == set(
        ledger["work_units"][model_key]["input_bindings"]
    )
    assert {
        row["producer_work_unit_key"]
        for row in ledger["work_units"][model_key]["input_bindings"].values()
    } == {prelaunch_key}
    assert set(ledger["work_units"][model_key]["artifacts"]) == {
        "scratchpad:verify_H-01.md",
        "scratchpad:verify_H-01.severity_proposal.json",
        "scratchpad:verify_H-01.operator_application.json",
    }
    assert "scratchpad:verify_H-01.operator_receipt.json" in (
        ledger["work_units"][control_key]["artifacts"]
    )
    assert DRIVER._run_verify_recovery_shard(config, [("H-01", _row())]) == []
    assert len(launches) == 1

    (scratch / "verify_H-01.md").write_text("tampered", encoding="utf-8")
    assert DRIVER._run_verify_recovery_shard(config, [("H-01", _row())]) == ["H-01"]
    assert len(launches) == 1


def test_recovery_phase_io_arms_every_boundary_before_canonical_outputs(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    observations: list[str] = []
    real_arm = DRIVER._arm_deterministic_driver_work_unit
    real_record_artifacts = DRIVER.record_work_unit_artifacts

    def arm(*, contract, **kwargs):
        if (
            contract.phase == "verify_recovery"
            and "/method_context." in contract.key
        ):
            assert all(
                not (scratch / output.path).exists()
                for output in contract.outputs
            )
            observations.append("prelaunch-armed-before-bytes")
        return real_arm(contract=contract, **kwargs)

    def record_artifacts(
        scratchpad, project_root, contract, launch, *, actor, **kwargs
    ):
        if (
            contract.phase == "verify_recovery"
            and "/method_model." in contract.key
        ):
            assert not (
                scratch / "verify_H-01.operator_receipt.json"
            ).exists()
            directory = next(
                (scratch / "_verification_recovery").glob("VREC-*")
            )
            assert not (directory / "execution_receipt.json").exists()
            observations.append("model-committed-before-driver-receipts")
        return real_record_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            actor=actor,
            **kwargs,
        )

    def execute(spec, *, prompt_path, scratchpad, **_kwargs):
        ledger = read_artifact_ledger(scratch)
        recovery = {
            key: value
            for key, value in ledger["work_units"].items()
            if "/verify_recovery/method_" in key
        }
        model = next(
            value
            for key, value in recovery.items()
            if "/method_model." in key
        )
        control = next(
            value
            for key, value in recovery.items()
            if "/method_receipt." in key
        )
        assert model["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert control["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert all(
            not (scratch / name).exists()
            for name in spec.expected_output_files
        )
        observations.append("model-and-control-armed-before-launch")
        _emit_recovery_outputs(
            spec, prompt_path=prompt_path, scratchpad=scratchpad
        )
        return 0

    monkeypatch.setattr(
        DRIVER, "_arm_deterministic_driver_work_unit", arm
    )
    monkeypatch.setattr(DRIVER, "record_work_unit_artifacts", record_artifacts)
    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", execute)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
        "_run_id": "run-1",
        "_verification_recovery_kind": "GENERIC_RECOVERY",
    }

    assert DRIVER._run_verify_recovery_shard(
        config, [("H-01", _semantic_row())]
    ) == []
    assert observations == [
        "prelaunch-armed-before-bytes",
        "model-and-control-armed-before-launch",
        "model-committed-before-driver-receipts",
    ]


def test_phase_io_validator_never_adopts_unowned_prelaunch_bytes(
    tmp_path: Path,
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    contract = build_verification_recovery_contract(
        run_id="run-1",
        recovery_kind="GENERIC_RECOVERY",
        rows=[_semantic_row()],
        scratchpad=scratch,
        project_root=project,
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=ROOT,
    )
    directory = (
        scratch / Path(contract["manifest_path"]).parent
    )
    contract_path = directory / "contract.json"
    manifest_path = scratch / contract["manifest_path"]
    context_path = scratch / contract["context_path"]
    dispatch_path = scratch / contract["method_dispatch_path"]
    prompt_path = scratch / contract["prompt_path"]
    launch_path = directory / "launch_spec.json"
    execution_path = directory / "execution_receipt.json"
    launch_spec = DRIVER._verify_recovery_launch_spec(
        contract,
        config={
            "scratchpad": str(scratch),
            "project_root": str(project),
            "pipeline": "sc",
            "language": "evm",
            "cli_backend": "claude",
            "mode": "core",
        },
    )
    prelaunch, model, control = (
        DRIVER._write_verifier_method_phase_io_contracts(
            directory=directory,
            scratchpad=scratch,
            config={
                "pipeline": "sc",
                "language": "evm",
                "cli_backend": "claude",
                "mode": "core",
            },
            phase_name="verify_recovery",
            work_unit_id=str(contract["recovery_id"]).lower(),
            model_outputs=tuple(contract["expected_model_outputs"]),
            operator_receipts=tuple(
                contract["expected_operator_receipts"]
            ),
            immutable_launch_inputs=(
                contract_path,
                manifest_path,
                context_path,
                dispatch_path,
                prompt_path,
                launch_path,
            ),
            driver_outputs=(
                contract_path,
                manifest_path,
                context_path,
                dispatch_path,
                prompt_path,
                launch_path,
                execution_path,
            ),
        )
    )
    directory.mkdir(parents=True)
    contract_path.write_text("unowned\n", encoding="utf-8")

    issues = DRIVER._record_verifier_method_phase_io_authority(
        prelaunch_contract=prelaunch,
        model_contract=model,
        control_contract=control,
        launch_spec=launch_spec,
        scratchpad=scratch,
        project_root=project,
        run_id="run-1",
        include_outputs=False,
        allow_initialize=True,
    )

    assert issues
    ledger = read_artifact_ledger(scratch)
    assert prelaunch.key not in ledger["work_units"]
    assert model.key not in ledger["work_units"]
    assert control.key not in ledger["work_units"]


def test_mixed_recovery_shard_never_resolves_without_exact_operator_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)

    def execute(spec, *, prompt_path, scratchpad, **_kwargs):
        _emit_recovery_outputs(spec, prompt_path=prompt_path, scratchpad=scratchpad)
        (scratchpad / "verify_H-02.operator_application.json").unlink()
        return 0

    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", execute)
    config = {
        "scratchpad": str(scratch), "project_root": str(project),
        "pipeline": "sc", "language": "evm", "cli_backend": "claude",
        "mode": "core", "_run_id": "run-1",
        "_verification_recovery_kind": "GENERIC_RECOVERY",
    }
    rows = [("H-01", _semantic_row("H-01")), ("H-02", _semantic_row("H-02"))]
    assert DRIVER._run_verify_recovery_shard(config, rows) == ["H-02"]
    assert (scratch / "verify_H-01.operator_receipt.json").is_file()
    assert not (scratch / "verify_H-02.operator_receipt.json").exists()

    directory = next((scratch / "_verification_recovery").glob("VREC-*"))
    receipt_path = directory / "execution_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert set(receipt["output_sha256"]) == {
        "verify_H-01.md", "verify_H-01.severity_proposal.json",
        "verify_H-01.operator_application.json", "verify_H-02.md",
        "verify_H-02.severity_proposal.json",
    }
    assert set(receipt["operator_receipt_sha256"]) == {
        "verify_H-01.operator_receipt.json"
    }

    # A self-consistent receipt digest cannot bless a resolved row after its
    # exact operator receipt was removed from the execution denominator.
    receipt["operator_receipt_sha256"].clear()
    receipt["receipt_digest"] = DRIVER._verify_recovery_execution_receipt_digest(receipt)
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    assert DRIVER._run_verify_recovery_shard(config, rows) == ["H-01", "H-02"]


def test_operator_denominator_requires_current_recovery_execution_receipt(
    tmp_path: Path, monkeypatch
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)

    def execute(spec, *, prompt_path, scratchpad, **_kwargs):
        _emit_recovery_outputs(spec, prompt_path=prompt_path, scratchpad=scratchpad)
        return 0

    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", execute)
    config = {
        "scratchpad": str(scratch), "project_root": str(project),
        "pipeline": "sc", "language": "evm", "cli_backend": "claude",
        "mode": "core", "_run_id": "run-1",
        "_verification_recovery_kind": "GENERIC_RECOVERY",
    }
    assert DRIVER._run_verify_recovery_shard(
        config, [("H-01", _semantic_row())]
    ) == []
    assert DRIVER._initial_verifier_operator_receipt_denominator(scratch) == [
        scratch / "verify_H-01.operator_receipt.json"
    ]

    directory = next((scratch / "_verification_recovery").glob("VREC-*"))
    execution_path = directory / "execution_receipt.json"
    execution = json.loads(execution_path.read_text(encoding="utf-8"))
    execution["operator_receipt_sha256"].clear()
    execution["receipt_digest"] = DRIVER._verify_recovery_execution_receipt_digest(
        execution
    )
    execution_path.write_text(json.dumps(execution), encoding="utf-8")

    assert DRIVER._initial_verifier_operator_receipt_denominator(scratch) == []
    authority = json.loads(
        (scratch / "verification_operator_denominator_authority.json")
        .read_text(encoding="utf-8")
    )
    assert any(
        debt["debt_code"] == "RECOVERY_EXECUTION_RECEIPT_MISSING_OR_UNBOUND"
        for debt in authority["debts"]
    )


def test_every_recovery_callsite_reaches_compiler_or_retired_fail_closed() -> None:
    source = Path(DRIVER.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    definitions = {
        node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)
    }
    legacy = definitions["_run_verify_recovery_shard_legacy_retired"]
    assert isinstance(legacy.body[1], ast.Raise) or isinstance(legacy.body[0], ast.Raise)
    live = definitions["_run_verify_recovery_shard"]
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_run_verify_recovery_unit"
        for node in ast.walk(live)
    )
    callers = []
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id == "_run_verify_recovery_shard":
            owner = node
            while owner is not None and not isinstance(
                owner, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                owner = parents.get(owner)
            callers.append(owner.name if owner is not None else "<module>")
        assert node.func.id != "_run_verify_recovery_shard_legacy_retired"
    # Every current semantic/reopen/BB lane shares the compiler-backed
    # implementation.  Pin identities instead of a brittle cardinality so an
    # added call site cannot hide behind an unrelated removed call site.
    assert set(callers) == {
        "_repair_late_verification_backfill",
        "_run_mandatory_report_reverification",
        "_run_bb_policy_terminal_boundary",
        "_consume_verifier_operator_receipts",
        "_run_p0o_scope_recovery",
        "_route_post_verify_late_candidates",
        "main",
    }
