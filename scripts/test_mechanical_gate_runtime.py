from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys

import pytest

from mechanical_gate_execution_receipts import (
    GateArtifactEvidence,
    GateCountReceipt,
    ImmutableGateExecutionLedger,
    PhaseIOCommitLink,
)
from mechanical_gate_inventory import (
    activation_inventory_digest,
    build_activation_inventory,
    compute_decision_code_digest,
    compute_legacy_module_code_digest,
    compute_source_tree_digest,
)
from mechanical_gate_registry import (
    LEGACY_MODULE_CODE_DIGEST_ALGORITHM,
    validate_mechanical_gate_registry,
)
from mechanical_gate_runtime import (
    GateEvaluation,
    GateInvocation,
    GateRuntimeAuthority,
    GateRuntimeError,
    GateTransactionStateMachine,
    RuntimeApplicability,
    evaluate_registered_gate,
)
from test_mechanical_gate_activation_parity import SOURCE
from test_mechanical_gate_registry_schema import valid_registry_payload


def _fixture_source() -> str:
    return SOURCE.replace(
        "def _fixture_guard_impl(context):\n"
        "    return bool(context and len(context) >= _THRESHOLD)",
        "def _fixture_guard_impl(context):\n"
        "    return _FIXTURE_EVALUATION",
    ).replace(
        "_THRESHOLD = 3",
        "_THRESHOLD = 3\n_FIXTURE_EVALUATION = None",
    ).replace(
        "def run_fixture_guard(context):",
        "def run_fixture_guard(context, authority, applicability, ledger=None):",
    ).replace(
        "        evaluator=_fixture_guard_impl,\n"
        "    )",
        "        evaluator=_fixture_guard_impl,\n"
        "        authority=authority,\n"
        "        applicability=applicability,\n"
        "        ledger=ledger,\n"
        "    )",
    ).replace(
        'return run_fixture_guard("fixture")',
        "return run_fixture_guard(None, None, None)",
    )


def _authority(
    root: Path,
    *,
    from_paths: bool = False,
) -> tuple[GateRuntimeAuthority, Path]:
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    module_path = scripts / "gate_fixture.py"
    module_path.write_text(_fixture_source(), encoding="utf-8")
    payload = valid_registry_payload()
    tree_digest = compute_source_tree_digest(
        root,
        production_roots=("scripts",),
        production_excludes=("scripts/test_*.py", "scripts/conftest.py"),
    )
    payload["migration"]["source_tree_digest"] = tree_digest
    payload["activation_inventory"]["source_tree_digest"] = tree_digest
    provisional = validate_mechanical_gate_registry(payload)
    payload["gate_records"][0]["activations"][0]["code_digest"] = (
        compute_decision_code_digest(
            root, provisional.gate_records[0].activations[0]
        )
    )
    registry = validate_mechanical_gate_registry(payload)
    inventory = build_activation_inventory(root, registry)
    payload["activation_inventory"]["manifest_sha256"] = (
        activation_inventory_digest(inventory)
    )
    payload["activation_inventory"]["generator_digest"] = inventory[
        "generator_digest"
    ]
    payload["activation_inventory"]["generator_version"] = inventory[
        "generator_version"
    ]
    registry = validate_mechanical_gate_registry(payload)
    inventory = build_activation_inventory(root, registry)
    if from_paths:
        # Canonical v2 paths admit only the real Stage-1 migration state.
        # Runtime unit fixtures remain object-only until Stage 2 grants an
        # independently reviewed transition.
        module_path.write_text(
            _fixture_source().replace(
                "evaluate_registered_gate",
                "legacy_evaluate_registered_gate",
            ),
            encoding="utf-8",
        )
        tree_digest = compute_source_tree_digest(
            root,
            production_roots=("scripts",),
            production_excludes=(
                "scripts/test_*.py",
                "scripts/conftest.py",
            ),
        )
        payload["migration"]["source_tree_digest"] = tree_digest
        payload["activation_inventory"]["source_tree_digest"] = tree_digest
        payload["migration"]["baseline_review_status"] = "UNREVIEWED"
        payload["gate_records"][0]["overlap_and_consolidation"][
            "consolidation_status"
        ] = "NOT ASSESSED"
        activation = payload["gate_records"][0]["activations"][0]
        activation["runtime_state"] = "LEGACY_NOT_MIGRATED"
        activation["code_digest_algorithm"] = (
            LEGACY_MODULE_CODE_DIGEST_ALGORITHM
        )
        activation["code_digest"] = "a" * 64
        payload["gate_records"][0]["input_contracts"] = []
        payload["gate_records"][0]["output_contracts"] = []
        provisional = validate_mechanical_gate_registry(payload)
        activation["code_digest"] = compute_legacy_module_code_digest(
            root,
            provisional.gate_records[0].activations[0],
            production_roots=("scripts",),
            production_excludes=(
                "scripts/test_*.py",
                "scripts/conftest.py",
            ),
        )
        registry = validate_mechanical_gate_registry(payload)
        inventory = build_activation_inventory(root, registry)
        payload["activation_inventory"]["manifest_sha256"] = (
            activation_inventory_digest(inventory)
        )
        registry = validate_mechanical_gate_registry(payload)
        inventory = build_activation_inventory(root, registry)
        rules = root / "rules"
        rules.mkdir()
        shutil.copyfile(
            Path(__file__).resolve().parents[1]
            / "rules"
            / "mechanical-gate-registry.schema.v2.json",
            rules / "mechanical-gate-registry.schema.v2.json",
        )
        (rules / "mechanical-gate-registry.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (
            rules / "mechanical-gate-activation-baseline.v1.json"
        ).write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return (
            GateRuntimeAuthority.from_paths(installed_root=root),
            module_path,
        )
    return (
        GateRuntimeAuthority.from_objects(
            source_root=root,
            registry=registry,
            inventory=inventory,
        ),
        module_path,
    )


def _load_fixture(path: Path):
    spec = importlib.util.spec_from_file_location("gate_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module._FIXTURE_EVALUATION = GateEvaluation(
        decision="FIRED",
        counts=GateCountReceipt(
            raw_subjects=1,
            unique_subjects=1,
            eligible_subjects=1,
            evaluated_subjects=1,
            fired_subjects=1,
            clear_subjects=0,
            unknown_subjects=0,
            overflow_subjects=0,
            emitted_candidates=1,
        ),
        output_evidence_digests=("d" * 64,),
    )
    return module


def _applicability(**overrides: str) -> RuntimeApplicability:
    values = {
        "pipeline": "SC",
        "mode": "THOROUGH",
        "ecosystem": "EVM",
        "backend": "CLAUDE",
        "phase": "RECON",
    }
    values.update(overrides)
    return RuntimeApplicability(**values)


def _input_artifact() -> GateArtifactEvidence:
    return GateArtifactEvidence(
        artifact_identity=(
            "scratchpad:_mechanical_gates/inputs/fixture.json"
        ),
        schema_version="fixture.input.v1",
        sha256="e" * 64,
        size=17,
    )


def test_exact_registered_wrapper_can_evaluate_but_legacy_is_debt(
    tmp_path: Path,
) -> None:
    authority, path = _authority(tmp_path)
    module = _load_fixture(path)
    receipt = module.run_fixture_guard(
        GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        authority,
        _applicability(),
    )
    assert receipt.decision == "FIRED"
    assert receipt.state == "DEBT"
    assert receipt.authority_effect == "SHADOW_ONLY"
    assert "LEGACY_UNGOVERNED" in receipt.debt_codes


def test_canonical_path_loader_binds_registry_manifest_and_tree(
    tmp_path: Path,
) -> None:
    authority, _path = _authority(tmp_path, from_paths=True)
    assert authority.registry_digest
    assert authority.inventory_digest
    assert (
        authority.source_tree_digest
        == authority.registry.migration["source_tree_digest"]
    )


def test_wrong_caller_cannot_reuse_registered_ids_or_execute_evaluator(
    tmp_path: Path,
) -> None:
    authority, _path = _authority(tmp_path)
    called = False

    def evaluator(_context: object) -> GateEvaluation:
        nonlocal called
        called = True
        raise AssertionError("unregistered caller executed evaluator")

    receipt = evaluate_registered_gate(
        "fixture.integrity_guard",
        activation_id="fixture.integrity_guard.recon",
        context=GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        evaluator=evaluator,
        authority=authority,
        applicability=_applicability(),
    )
    assert called is False
    assert receipt.state == "DEBT"
    assert receipt.decision == "UNKNOWN"
    assert receipt.debt_codes[0].endswith("_MISMATCH")


def test_selector_mismatch_is_not_applicable_and_never_evaluates(
    tmp_path: Path,
) -> None:
    authority, path = _authority(tmp_path)
    module = _load_fixture(path)
    receipt = module.run_fixture_guard(
        GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        authority,
        _applicability(ecosystem="SOLANA"),
    )
    assert receipt.state == "NOT_APPLICABLE"
    assert receipt.decision == "NOT_APPLICABLE"


def test_unknown_activation_is_shadow_debt_not_runtime(
    tmp_path: Path,
) -> None:
    authority, _path = _authority(tmp_path)
    receipt = evaluate_registered_gate(
        "fixture.integrity_guard",
        activation_id="fixture.integrity_guard.unknown",
        context=GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        evaluator=lambda _context: pytest.fail("evaluator must not run"),
        authority=authority,
        applicability=_applicability(),
    )
    assert receipt.state == "DEBT"
    assert receipt.authority_effect == "SHADOW_ONLY"
    assert "UNKNOWN_ACTIVATION" in receipt.debt_codes


def test_absent_input_evidence_cannot_be_reported_clear(
    tmp_path: Path,
) -> None:
    authority, path = _authority(tmp_path)
    module = _load_fixture(path)
    receipt = module.run_fixture_guard(
        GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=(),
            subject_denominator=1,
        ),
        authority,
        _applicability(),
    )
    assert receipt.decision == "UNKNOWN"
    assert receipt.authority_effect == "RETAIN_UPSTREAM_AND_FLAG"
    assert "INPUT_EVIDENCE_ABSENT" in receipt.debt_codes


def test_source_tree_drift_after_authority_arm_blocks_evaluator(
    tmp_path: Path,
) -> None:
    authority, path = _authority(tmp_path)
    module = _load_fixture(path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "_THRESHOLD = 3", "_THRESHOLD = 4"
        ),
        encoding="utf-8",
    )
    receipt = module.run_fixture_guard(
        GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        authority,
        _applicability(),
    )
    assert receipt.decision == "UNKNOWN"
    assert "SOURCE_TREE_DRIFT" in receipt.debt_codes


def test_runtime_ledger_resume_returns_exact_receipt_without_reevaluation(
    tmp_path: Path,
) -> None:
    authority, path = _authority(tmp_path)
    module = _load_fixture(path)
    ledger = ImmutableGateExecutionLedger(tmp_path / "execution-ledger")
    invocation = GateInvocation(
        run_id="fixture-run",
        input_evidence_digests=("e" * 64,),
        subject_denominator=1,
        input_artifacts=(_input_artifact(),),
    )
    first = module.run_fixture_guard(
        invocation,
        authority,
        _applicability(),
        ledger,
    )
    module._FIXTURE_EVALUATION = pytest.fail
    second = module.run_fixture_guard(
        invocation,
        authority,
        _applicability(),
        ledger,
    )
    assert second == first
    assert len(list((tmp_path / "execution-ledger").glob("*.json"))) == 1


def test_overflow_requires_exact_debt_and_durable_backlog_evidence(
    tmp_path: Path,
) -> None:
    authority, path = _authority(tmp_path)
    module = _load_fixture(path)
    module._FIXTURE_EVALUATION = GateEvaluation(
        decision="FIRED",
        counts=GateCountReceipt(
            raw_subjects=2,
            unique_subjects=2,
            eligible_subjects=2,
            evaluated_subjects=1,
            fired_subjects=1,
            clear_subjects=0,
            unknown_subjects=0,
            overflow_subjects=1,
            emitted_candidates=1,
        ),
        output_evidence_digests=("d" * 64,),
        debt_codes=("BUDGET_OVERFLOW",),
    )
    receipt = module.run_fixture_guard(
        GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=2,
            input_artifacts=(_input_artifact(),),
        ),
        authority,
        _applicability(),
    )
    assert "BUDGET_OVERFLOW" in receipt.debt_codes
    assert "OVERFLOW_BACKLOG_ABSENT" in receipt.debt_codes
    assert receipt.counts.overflow_subjects == 1


def test_public_dataclass_constructor_does_not_mint_authority(
    tmp_path: Path,
) -> None:
    authority, _path = _authority(tmp_path)
    forged = GateRuntimeAuthority(
        source_root=authority.source_root,
        registry=authority.registry,
        inventory=authority.inventory,
        registry_digest=authority.registry_digest,
        inventory_digest=authority.inventory_digest,
        source_tree_digest=authority.source_tree_digest,
    )
    with pytest.raises(GateRuntimeError):
        evaluate_registered_gate(
            "fixture.integrity_guard",
            activation_id="fixture.integrity_guard.recon",
            context=GateInvocation(
                run_id="fixture-run",
                input_evidence_digests=("e" * 64,),
                subject_denominator=1,
                input_artifacts=(_input_artifact(),),
            ),
            evaluator=lambda _context: pytest.fail("must not execute"),
            authority=forged,
            applicability=_applicability(),
        )


class _Transaction:
    def __init__(self, issues: tuple[str, ...] = ()) -> None:
        self.events: list[str] = []
        self.issues = issues

    def arm(self, **_kwargs: object) -> None:
        self.events.append("ARM")

    def stage(self, _evaluation: GateEvaluation) -> None:
        self.events.append("STAGE")

    def revalidate(self) -> tuple[str, ...]:
        self.events.append("REVALIDATE")
        return self.issues

    def checked_commit(self) -> PhaseIOCommitLink:
        self.events.append("COMMIT")
        return _phaseio_link("ACTIVE", ())

    def quarantine(
        self, reason_codes: tuple[str, ...]
    ) -> PhaseIOCommitLink:
        self.events.append("QUARANTINE")
        return _phaseio_link("QUARANTINED", reason_codes)


def _phaseio_link(
    state: str, reason_codes: tuple[str, ...]
) -> PhaseIOCommitLink:
    return PhaseIOCommitLink(
        work_unit_key="sc/thorough/evm/claude/recon/fixture.guard",
        contract_digest="a" * 64,
        launch_digest="b" * 64,
        input_set_digest="c" * 64,
        output_identities=(
            "scratchpad:_mechanical_gates/receipts/fixture.json",
        ),
        commit_state=state,
        commit_receipt_digest="d" * 64,
        reason_codes=reason_codes,
    )


def _evaluation() -> GateEvaluation:
    return GateEvaluation(
        decision="FIRED",
        counts=GateCountReceipt(
            raw_subjects=1,
            unique_subjects=1,
            eligible_subjects=1,
            evaluated_subjects=1,
            fired_subjects=1,
            clear_subjects=0,
            unknown_subjects=0,
            overflow_subjects=0,
            emitted_candidates=1,
        ),
        output_evidence_digests=("d" * 64,),
    )


def test_phaseio_state_machine_order_and_quarantine_are_exact(
    tmp_path: Path,
) -> None:
    authority, _path = _authority(tmp_path)
    gate = authority.registry.gate_records[0]
    activation = gate.activations[0]
    transaction = _Transaction(("INPUT_MUTATION",))
    machine = GateTransactionStateMachine(transaction)
    with pytest.raises(GateRuntimeError):
        machine.stage(_evaluation())
    machine.arm(
        gate=gate,
        activation=activation,
        invocation=GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        applicability=_applicability(),
    )
    machine.evaluated()
    machine.stage(_evaluation())
    assert machine.revalidate() == ("INPUT_MUTATION",)
    link = machine.finish(reason_codes=("INPUT_MUTATION",))
    assert link.commit_state == "QUARANTINED"
    assert transaction.events == [
        "ARM",
        "STAGE",
        "REVALIDATE",
        "QUARANTINE",
    ]
    assert machine.state == "RECEIPTED"


def test_phaseio_state_machine_can_quarantine_partial_failure(
    tmp_path: Path,
) -> None:
    authority, _path = _authority(tmp_path)
    gate = authority.registry.gate_records[0]
    activation = gate.activations[0]
    transaction = _Transaction()
    machine = GateTransactionStateMachine(transaction)
    machine.arm(
        gate=gate,
        activation=activation,
        invocation=GateInvocation(
            run_id="fixture-run",
            input_evidence_digests=("e" * 64,),
            subject_denominator=1,
            input_artifacts=(_input_artifact(),),
        ),
        applicability=_applicability(),
    )
    machine.evaluated()
    link = machine.fail(("EVALUATOR_FAILURE",))
    assert link.commit_state == "QUARANTINED"
    assert transaction.events == ["ARM", "QUARANTINE"]
    assert machine.state == "RECEIPTED"
