"""V2 RED denominator for Cut-4 dependency/canonical recon application.

The fixture drives only public PhaseIO, ArtifactLedger, deterministic renderer,
and recon-application seams.  Transaction behavior is never assigned to the
legacy private merge renderer.  Crash injection uses publisher-emitted names,
and exact retry must point at an actually committed ArtifactLedger generation
while executing zero semantic writers.

The required vertical slices are dependency obligations/baseline/terminal/
reconcile, canonical source-capture/merge, supplementary disposition, and the
instantiate+breadth consumer boundary.  A public publisher existing on disk is
not application evidence: each slice must expose executed route receipts and
committed producer/consumer bindings.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import dependency_obligations as DO  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)


RUN_ID = "cut4-recon-v2"

WORKER_SHARDS = (
    "recon_build_static.md",
    "recon_design_context.md",
    "recon_inventory_surface.md",
    "recon_templates_patterns.md",
)

CANONICAL_RECON = (
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
)

CANONICAL_POSTIMAGE = (*CANONICAL_RECON, "recon_signal_transform_receipt.json")

DEPENDENCY_CAPTURE_INPUTS = (
    "audit_snapshot.json",
    "recon_dependency_source_closure.json",
    "recon_dependency_manifest_closure.json",
    "recon_dependency_config_authority.json",
    "recon_dependency_namespace_manifest.json",
)

DEPENDENCY_OUTPUTS = (
    "external_dependency_obligations.json",
    "external_dependency_research.md",
    "report_semantic_dependency_research.md",
    "recon_external_dependency_research.md",
    "recon_dependency_reconcile_source_manifest.json",
)

SUPPLEMENTARY_SIBLINGS = (
    "attack_surface.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
)

# This is the recon portion of the stable driver-smoke mismatch observed by
# the independent reviewer.  skill_selection_catalog.json is intentionally an
# adjacent owner and is not part of the Cut-4 recon claim.
STABLE_SMOKE_RECON_MISMATCH_ROSTER = (
    "attack_surface.md",
    "contract_inventory.md",
    "design_context.md",
    "detected_patterns.md",
    "function_list.md",
    "recon_summary.md",
    "state_variables.md",
    "template_recommendations.md",
)

PUBLIC_SURFACE = (
    "run_dependency",
    "run_canonical_merge",
    "run_supplementary_disposition",
    "canonical_recon_postimage",
    "validate_recon_consumer",
    "recover_recon_publications",
)

TERMINAL_STATES = frozenset({
    "APPLIED",
    "TYPED_ZERO",
    "MODEL_OUTPUT",
    "DRIVER_FALLBACK",
    "EXPLICIT_ABSENCE",
    "DEBT",
    "REJECTED",
    "QUARANTINED",
    "REUSED_COMMITTED_GENERATION",
})


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _application() -> Any:
    try:
        module = importlib.import_module("recon_phaseio_application")
    except ModuleNotFoundError:
        pytest.fail(
            "Cut-4 public closed publisher is absent: expected the bounded "
            "recon_phaseio_application module",
            pytrace=False,
        )
    missing = [name for name in PUBLIC_SURFACE if not callable(getattr(module, name, None))]
    assert not missing, "Cut-4 dependency/canonical public surface is incomplete: " + ", ".join(missing)
    return module


def _resolve(
    work_unit_id: str,
    *,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
    writer: str = "DRIVER",
):
    return resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work_unit_id,
        exact_inputs=inputs,
        exact_outputs=outputs,
        exact_writer=writer,
    )


def _paths(contract: object) -> set[str]:
    return {output.identity.split(":", 1)[1] for output in contract.outputs}


def _obligations(*, count: int = 3, truncated: bool = False) -> dict[str, Any]:
    rows = [
        {
            "obligation_id": f"DEP-{index:012d}",
            "dependency": f"fixture-{index}",
            "source_location": f"Protocol.sol:L{index + 1}",
            "research_question": f"What behavior is guaranteed for fixture-{index}?",
        }
        for index in range(count)
    ]
    return {
        "schema": DO.SCHEMA,
        "provider": "fixture",
        "obligations": rows,
        "observed_count": count + (2 if truncated else 0),
        "retained_count": count,
        "truncated": truncated,
        "overflow_ids": (["DEP-OVERFLOW-1", "DEP-OVERFLOW-2"] if truncated else []),
    }


def _workspace(tmp_path: Path) -> tuple[Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir(parents=True)
    scratchpad.mkdir(parents=True)
    (project / "Protocol.sol").write_text(
        'pragma solidity ^0.8.20;\nimport "@vendor/pkg/External.sol";\n'
        "contract Fixture {}\n",
        encoding="utf-8",
    )
    authorities = {
        "audit_snapshot.json": {"generation": "snapshot-g1"},
        "recon_dependency_source_closure.json": {"generation": "source-g1"},
        "recon_dependency_manifest_closure.json": {"generation": "manifests-g1"},
        "recon_dependency_config_authority.json": {
            "generation": "config-g1",
            "limit": 64,
            "overflow_policy": "RETAIN_TYPED_DEBT",
        },
        "recon_dependency_namespace_manifest.json": {
            "generation": "namespace-g1",
            "outputs": list(DEPENDENCY_OUTPUTS),
        },
        "recon_prepass_finalize.json": {"generation": "prepass-g1"},
    }
    for name, payload in authorities.items():
        (scratchpad / name).write_bytes(_canonical(payload))
    for name in WORKER_SHARDS:
        (scratchpad / name).write_text(
            f"# {name}\n\nMODEL shard generation g1\n" + ("w" * 200) + "\n",
            encoding="utf-8",
        )
    for name in CANONICAL_RECON:
        (scratchpad / name).write_text(
            f"# {name}\n\nprepass generation g1\n" + ("p" * 200) + "\n",
            encoding="utf-8",
        )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "run_id": RUN_ID,
        "_run_id": RUN_ID,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }
    return project, scratchpad, config


def _snapshot(root: Path, names: tuple[str, ...]) -> dict[str, str | None]:
    return {
        name: (_sha((root / name).read_bytes()) if (root / name).is_file() else None)
        for name in names
    }


def _assert_one_terminal(unit: Mapping[str, Any], expected: set[str] | None = None) -> str:
    authority = unit.get("terminal_authority")
    assert isinstance(authority, Mapping)
    assert authority.get("selected_count") == 1
    states = authority.get("states")
    assert isinstance(states, list) and len(states) == 1
    state = str(states[0])
    assert state in TERMINAL_STATES
    if expected is not None:
        assert state in expected
    return state


def _assert_committed(
    scratchpad: Path,
    result: Mapping[str, Any],
    *,
    inputs: set[str] | None = None,
    outputs: set[str] | None = None,
    terminals: set[str] | None = None,
) -> Mapping[str, Any]:
    key = str(result.get("work_unit_key") or "")
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger.get("work_units", {}).get(key)
    assert isinstance(unit, Mapping), f"missing committed child {key}"
    assert unit.get("work_unit_key") == key
    assert unit.get("run_id") == RUN_ID
    assert unit.get("semantic_status") == "ACTIVE"
    assert unit.get("execution_state") == "OUTPUT_COMMITTED"
    assert unit.get("contract_digest") == result.get("contract_digest")
    assert unit.get("launch_digest") == result.get("launch_digest")
    assert unit.get("publication_generation") == result.get("generation_id")
    assert isinstance(unit.get("contract_manifest"), Mapping)
    assert isinstance(unit.get("launch_manifest"), Mapping)
    assert isinstance(unit.get("input_set_digest"), str) and len(unit["input_set_digest"]) == 64
    assert isinstance(unit.get("output_prestate_digest"), str) and len(unit["output_prestate_digest"]) == 64
    if inputs is not None:
        assert set(unit.get("input_bindings", {})) == {f"scratchpad:{name}" for name in inputs}
    if outputs is not None:
        identities = {f"scratchpad:{name}" for name in outputs}
        assert set(unit.get("output_prestates", {})) == identities
        assert set(unit.get("artifacts", {})) == identities
        commit = unit.get("commit_authority")
        assert isinstance(commit, Mapping)
        assert commit.get("state") == "ACTIVE"
        assert commit.get("run_id") == RUN_ID
        assert commit.get("work_unit_key") == key
        assert commit.get("contract_digest") == unit.get("contract_digest")
        assert commit.get("launch_digest") == unit.get("launch_digest")
        assert set(commit.get("expected_output_records", {})) == identities
        for identity in identities:
            binding = ledger.get("artifact_bindings", {}).get(identity)
            assert isinstance(binding, Mapping)
            assert binding.get("owner_key") == key
            assert binding.get("run_id") == RUN_ID
            assert binding.get("status") == "ACTIVE"
    _assert_one_terminal(unit, terminals)
    return unit


def _fixture_contract(
    work: str,
    output: str | tuple[str, ...],
    *,
    inputs: tuple[str, ...] = (),
    requirements: tuple[InputAuthorityRequirement, ...] = (),
) -> tuple[PhaseIOContract, LaunchSpec]:
    key = canonical_work_unit_key("sc", "thorough", "evm", "claude", "recon", work)
    outputs = (output,) if isinstance(output, str) else output
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version="fixture.registered-control.v1",
                minimum_gate="EXACT_BYTES",
            )
            for relative in outputs
        ),
        immutable_inputs=inputs,
        input_authority_requirements=requirements,
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="deterministic",
        timeout_s=30,
        exec_mode="python",
    )
    return contract, launch


def test_positive_control_typed_zero_is_data_not_missing_producer(tmp_path: Path) -> None:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    contract, launch = _fixture_contract(
        "control.dependency_typed_zero",
        "external_dependency_obligations.json",
    )
    AL.record_work_unit_inputs(scratchpad, project, contract, launch, run_id=RUN_ID)
    payload = DO.enumerate_dependency_obligations(
        project,
        {"pipeline": "sc", "language": "evm"},
    )
    assert payload["obligations"] == []
    assert payload["observed_count"] == 0
    assert payload["retained_count"] == 0
    assert payload["truncated"] is False
    (scratchpad / "external_dependency_obligations.json").write_bytes(_canonical(payload))
    unit = AL.record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


@pytest.mark.parametrize("worker_text", ("", "malformed MODEL output without a table"))
def test_positive_control_failed_or_malformed_model_retains_every_row(
    tmp_path: Path,
    worker_text: str,
) -> None:
    project = tmp_path / "project"
    scratchpad = tmp_path / "scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    contract, launch = _fixture_contract(
        "control.dependency_model_retention",
        (
            "external_dependency_research.md",
            "report_semantic_dependency_research.md",
        ),
    )
    AL.record_work_unit_inputs(scratchpad, project, contract, launch, run_id=RUN_ID)
    payload = _obligations(count=3)
    result = DO.reconcile_dependency_research_ledger(
        scratchpad,
        payload,
        worker_text=worker_text,
    )
    text = (scratchpad / "external_dependency_research.md").read_text(encoding="utf-8")
    assert result["researched"] == 0
    assert result["unresolved"] == 3
    assert all(row["obligation_id"] in text for row in payload["obligations"])
    ok, issues = DO.validate_dependency_ledger_parity(payload, text)
    assert ok, issues
    unit = AL.record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_positive_control_exact_current_consumer_binding_rejects_tamper(tmp_path: Path) -> None:
    scratchpad = tmp_path / "scratchpad"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    producer, producer_launch = _fixture_contract("control.producer", "producer.json")
    AL.record_work_unit_inputs(scratchpad, project, producer, producer_launch, run_id=RUN_ID)
    (scratchpad / "producer.json").write_bytes(_canonical({"state": "TYPED_ZERO"}))
    produced = AL.record_work_unit_artifacts(
        scratchpad,
        project,
        producer,
        producer_launch,
        run_id=RUN_ID,
    )
    assert produced["semantic_status"] == "ACTIVE"
    requirement = InputAuthorityRequirement(
        identity="scratchpad:producer.json",
        expected_producer_work_unit_key=producer.key,
        expected_writer="DRIVER",
        require_same_run=True,
        expected_contract_digest=producer.digest,
        expected_launch_digest=producer_launch.digest,
        require_exact_contract=True,
        require_exact_launch=True,
    )
    consumer, consumer_launch = _fixture_contract(
        "control.consumer",
        "consumer.json",
        inputs=("scratchpad:producer.json",),
        requirements=(requirement,),
    )
    bound = AL.record_work_unit_inputs(
        scratchpad,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    )
    assert bound["semantic_status"] == "INPUTS_BOUND"
    assert bound["input_bindings"]["scratchpad:producer.json"]["status"] == "ACTIVE"
    (scratchpad / "producer.json").write_bytes(_canonical({"state": "tampered"}))
    issues = AL.validate_work_unit_inputs(
        scratchpad,
        project,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    )
    assert any("changed" in issue.casefold() or "mismatch" in issue.casefold() for issue in issues)


@pytest.mark.parametrize(
    ("work", "inputs", "outputs", "writer"),
    (
        ("dependency_obligations.nonzero", DEPENDENCY_CAPTURE_INPUTS, ("external_dependency_obligations.json",), "DRIVER"),
        ("dependency_obligations.typed_zero", DEPENDENCY_CAPTURE_INPUTS, ("external_dependency_obligations.json",), "DRIVER"),
        ("dependency_obligations.malformed", DEPENDENCY_CAPTURE_INPUTS, ("external_dependency_obligations.json",), "DRIVER"),
        ("dependency_obligations.truncated", DEPENDENCY_CAPTURE_INPUTS, ("external_dependency_obligations.json",), "DRIVER"),
        ("dependency_obligations.overflow", DEPENDENCY_CAPTURE_INPUTS, ("external_dependency_obligations.json",), "DRIVER"),
        (
            "dependency_baseline",
            ("external_dependency_obligations.json", "recon_dependency_namespace_manifest.json"),
            ("external_dependency_research.md", "report_semantic_dependency_research.md"),
            "DRIVER",
        ),
        (
            "dependency_research.model",
            (
                "external_dependency_obligations.json",
                "external_dependency_research.md",
                "report_semantic_dependency_research.md",
                *WORKER_SHARDS,
            ),
            ("recon_external_dependency_research.md",),
            "MODEL",
        ),
        (
            "dependency_research.explicit_absence.zero_obligations",
            ("external_dependency_obligations.json", "external_dependency_research.md"),
            ("recon_external_dependency_research.md",),
            "DRIVER",
        ),
        (
            "dependency_research.explicit_absence.not_run",
            ("external_dependency_obligations.json", "external_dependency_research.md"),
            ("recon_external_dependency_research.md",),
            "DRIVER",
        ),
        (
            "dependency_research.debt.model_failure",
            ("external_dependency_obligations.json", "external_dependency_research.md"),
            ("recon_external_dependency_research.md",),
            "DRIVER",
        ),
        (
            "dependency_research.debt.malformed_model_output",
            ("external_dependency_obligations.json", "external_dependency_research.md"),
            ("recon_external_dependency_research.md",),
            "DRIVER",
        ),
        (
            "dependency_reconcile.source_capture",
            (
                "external_dependency_obligations.json",
                "external_dependency_research.md",
                "report_semantic_dependency_research.md",
                "recon_external_dependency_research.md",
            ),
            ("recon_dependency_reconcile_source_manifest.json",),
            "DRIVER",
        ),
        (
            "dependency_reconcile",
            ("recon_dependency_reconcile_source_manifest.json",),
            ("external_dependency_research.md", "report_semantic_dependency_research.md"),
            "DRIVER",
        ),
    ),
)
def test_dependency_vertical_slice_contracts_are_registered(
    work: str,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
    writer: str,
) -> None:
    contract = _resolve(work, inputs=inputs, outputs=outputs, writer=writer)
    assert _paths(contract) == set(outputs)
    assert set(contract.immutable_inputs) == {f"scratchpad:{name}" for name in inputs}
    assert {output.writer for output in contract.outputs} == {writer}
    assert contract.model_invoked is (writer == "MODEL")


@pytest.mark.parametrize(
    ("obligation_case", "payload", "expected_terminal"),
    (
        ("empty", _obligations(count=0), "TYPED_ZERO"),
        ("nonempty", _obligations(count=3), "APPLIED"),
        ("malformed", {"schema": DO.SCHEMA, "obligations": "not-a-list"}, "DEBT"),
        ("truncated", _obligations(count=3, truncated=True), "DEBT"),
        ("overflow", {**_obligations(count=3, truncated=True), "retained_count": 999}, "DEBT"),
    ),
)
def test_dependency_obligation_matrix_is_typed_and_committed(
    tmp_path: Path,
    obligation_case: str,
    payload: Mapping[str, Any],
    expected_terminal: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_dependency(
        config,
        route="validation_fallback",
        obligation_payload=deepcopy(payload),
        model_outcome={"state": "NOT_RUN", "bytes": b""},
    )
    obligation = result["children"]["dependency_obligations"]
    assert obligation["terminal_state"] == expected_terminal
    _assert_committed(scratchpad, obligation, terminals={expected_terminal})
    if obligation_case == "empty":
        assert obligation["row_count"] == 0
        assert obligation["output_present"] is True


@pytest.mark.parametrize("drift", ("source", "config", "namespace", "dependency_manifest"))
def test_dependency_capture_drift_rejects_or_creates_successor(tmp_path: Path, drift: str) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_dependency(
        config,
        route="pty",
        obligation_payload=_obligations(count=2),
        model_outcome={"state": "NOT_RUN", "bytes": b""},
        mutate_after_arm=drift,
    )
    assert result["terminal_state"] in {"DEBT", "REJECTED", "APPLIED"}
    if result["terminal_state"] == "APPLIED":
        assert result.get("successor_of")
        assert result.get("generation_id") != result.get("armed_generation_id")


@pytest.mark.parametrize("route", ("pty", "headless", "validation_fallback"))
def test_dependency_live_routes_use_same_registered_chain(tmp_path: Path, route: str) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path / route)
    result = app.run_dependency(
        config,
        route=route,
        obligation_payload=_obligations(count=2),
        model_outcome={"state": "NOT_RUN", "bytes": b""},
    )
    assert result["route"] == route
    assert result["applied"] is True
    assert result["chain"] == [
        "dependency_obligations",
        "dependency_baseline",
        "dependency_research.explicit_absence.not_run",
        "dependency_reconcile.source_capture",
        "dependency_reconcile",
    ]
    assert len(result["terminal_children"]) == len(result["chain"])
    assert all(row["selected_count"] == 1 for row in result["terminal_children"])
    for child in result["children"].values():
        _assert_committed(scratchpad, child)


@pytest.mark.parametrize(
    ("model_state", "expected_terminal"),
    (
        ("MODEL_OUTPUT", "MODEL_OUTPUT"),
        ("ZERO_OBLIGATIONS", "EXPLICIT_ABSENCE"),
        ("NOT_RUN", "EXPLICIT_ABSENCE"),
        ("FAILED", "DEBT"),
        ("MALFORMED", "DEBT"),
    ),
)
def test_model_terminal_is_exclusive_and_debt_is_not_explicit_absence(
    tmp_path: Path,
    model_state: str,
    expected_terminal: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    payload = _obligations(count=(0 if model_state == "ZERO_OBLIGATIONS" else 3))
    model_bytes = (
        b"| Obligation ID | Status | Evidence |\n"
        b"|---|---|---|\n"
        if model_state == "MODEL_OUTPUT"
        else b"malformed"
    )
    result = app.run_dependency(
        config,
        route="headless",
        obligation_payload=payload,
        model_outcome={"state": model_state, "bytes": model_bytes},
    )
    terminal = result["model_terminal"]
    assert terminal["terminal_state"] == expected_terminal
    assert terminal["selected_count"] == 1
    assert set(terminal["candidate_states"]) == {
        "MODEL_OUTPUT",
        "EXPLICIT_ABSENCE",
        "DEBT",
    }
    if model_state in {"FAILED", "MALFORMED"}:
        assert terminal["terminal_state"] != "EXPLICIT_ABSENCE"
        assert result["reconcile"]["unresolved_ids"] == [
            row["obligation_id"] for row in payload["obligations"]
        ]
        assert result["reconcile"]["row_count"] == len(payload["obligations"])


@pytest.mark.parametrize("wrong_generation", ("obligation", "baseline", "model"))
def test_reconcile_rejects_wrong_predecessor_generation(
    tmp_path: Path,
    wrong_generation: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_dependency(
        config,
        route="validation_fallback",
        obligation_payload=_obligations(count=2),
        model_outcome={"state": "FAILED", "bytes": b""},
        wrong_reconcile_generation=wrong_generation,
    )
    reconcile = result["children"]["dependency_reconcile"]
    assert reconcile["terminal_state"] in {"DEBT", "REJECTED", "QUARANTINED"}
    assert reconcile.get("semantic_writer_count", 0) == 0


@pytest.mark.parametrize("desired_poststate", ("CREATED", "DELETED"))
def test_limitation_file_creation_and_deletion_are_declared_poststates(
    tmp_path: Path,
    desired_poststate: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_dependency(
        config,
        route="validation_fallback",
        obligation_payload=_obligations(count=(2 if desired_poststate == "CREATED" else 0)),
        model_outcome={"state": "FAILED", "bytes": b""},
    )
    reconcile = result["children"]["dependency_reconcile"]
    poststates = reconcile["declared_output_poststates"]
    assert poststates["report_semantic_dependency_research.md"] == desired_poststate


@pytest.mark.parametrize(
    "failpoint",
    (
        "AFTER_ARM:dependency_baseline",
        "AFTER_STAGE:external_dependency_research.md",
        "AFTER_STAGE:report_semantic_dependency_research.md",
        "BEFORE_PUBLISH:dependency_baseline",
        "AFTER_PUBLISH:external_dependency_research.md",
        "AFTER_PUBLISH:report_semantic_dependency_research.md",
        "BEFORE_COMMIT:dependency_baseline",
        "AFTER_COMMIT:dependency_baseline",
    ),
)
def test_dependency_baseline_named_failpoints_resume_exactly(
    tmp_path: Path,
    failpoint: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    fired = False

    class InjectedCrash(RuntimeError):
        pass

    def crash(label: str) -> None:
        nonlocal fired
        if label == failpoint and not fired:
            fired = True
            raise InjectedCrash(label)

    with pytest.raises(InjectedCrash):
        app.run_dependency(
            config,
            route="pty",
            obligation_payload=_obligations(count=2),
            model_outcome={"state": "NOT_RUN", "bytes": b""},
            failpoint=crash,
        )
    assert fired
    journal = AL.read_artifact_ledger(scratchpad).get("recon_publication_journal", {})
    assert journal.get("state") in {"STAGED", "ROLL_FORWARD", "QUARANTINED", "COMMITTED"}
    recovered = app.recover_recon_publications(config, route="pty")
    assert recovered["terminal_state"] in {"APPLIED", "QUARANTINED", "DEBT"}


def test_public_canonical_renderer_is_pure_and_byte_deterministic(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, _config = _workspace(tmp_path)
    inputs = {
        name: (scratchpad / name).read_bytes()
        for name in (*WORKER_SHARDS, *CANONICAL_RECON)
    }
    original = deepcopy(inputs)
    before_tree = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file())
    first = app.canonical_recon_postimage(inputs)
    second = app.canonical_recon_postimage(inputs)
    after_tree = sorted(path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*") if path.is_file())
    assert inputs == original
    assert first == second
    assert set(first) == set(CANONICAL_POSTIMAGE)
    assert all(isinstance(value, bytes) for value in first.values())
    assert before_tree == after_tree
    assert not (scratchpad / AL.LEDGER_NAME).exists()


def test_canonical_contract_captures_all_worker_and_prepass_generations() -> None:
    inputs = (*WORKER_SHARDS, *CANONICAL_RECON, "recon_prepass_finalize.json")
    capture = _resolve(
        "canonical_merge.source_capture",
        inputs=inputs,
        outputs=("recon_canonical_merge_source_manifest.json",),
    )
    assert set(capture.immutable_inputs) == {f"scratchpad:{name}" for name in inputs}
    contract = _resolve(
        "canonical_merge",
        inputs=("recon_canonical_merge_source_manifest.json",),
        outputs=CANONICAL_POSTIMAGE,
    )
    assert _paths(contract) == set(CANONICAL_POSTIMAGE)
    receipt = contract.output("scratchpad:recon_signal_transform_receipt.json")
    assert receipt.writer == "DRIVER"
    assert receipt.schema_version == "plamen.recon_signal_transform_set.v1"


@pytest.mark.parametrize(
    "drift",
    (
        "worker_add",
        "worker_remove",
        "worker_change",
        "prepass_change",
        "mixed_worker_generation",
        "mixed_prepass_generation",
        "run_id",
        "parent",
        "work_unit",
        "attempt",
        "contract",
        "launch",
    ),
)
def test_canonical_source_or_identity_drift_never_rebinds_generation(
    tmp_path: Path,
    drift: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    before = _snapshot(scratchpad, CANONICAL_POSTIMAGE)
    result = app.run_canonical_merge(config, route="pty", inject_drift=drift)
    assert result["terminal_state"] in {"DEBT", "REJECTED", "QUARANTINED", "APPLIED"}
    if result["terminal_state"] == "APPLIED":
        assert result.get("successor_of")
        assert result["generation_id"] != result["armed_generation_id"]
    else:
        assert _snapshot(scratchpad, CANONICAL_POSTIMAGE) == before
        assert result.get("semantic_writer_count", 0) == 0


@pytest.mark.parametrize("receipt_defect", ("missing", "malformed", "tampered_digest"))
def test_transform_receipt_is_validated_as_a_real_output(
    tmp_path: Path,
    receipt_defect: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    result = app.run_canonical_merge(
        config,
        route="headless",
        receipt_defect=receipt_defect,
    )
    assert result["terminal_state"] in {"DEBT", "QUARANTINED", "REJECTED"}
    assert result.get("semantic_writer_count", 0) == 0
    assert "receipt" in " ".join(result.get("reason_codes", ())).casefold()


@pytest.mark.parametrize(
    ("boundary", "output_name"),
    tuple(
        (boundary, output_name)
        for boundary in ("AFTER_STAGE", "AFTER_PUBLISH")
        for output_name in CANONICAL_POSTIMAGE
    ),
)
def test_each_canonical_output_has_a_named_publish_failpoint_and_exact_recovery(
    tmp_path: Path,
    boundary: str,
    output_name: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    raw_before = _snapshot(scratchpad, CANONICAL_POSTIMAGE)
    failpoint = f"{boundary}:{output_name}"
    fired = False

    class InjectedCrash(RuntimeError):
        pass

    def crash(label: str) -> None:
        nonlocal fired
        if label == failpoint and not fired:
            fired = True
            raise InjectedCrash(label)

    with pytest.raises(InjectedCrash):
        app.run_canonical_merge(config, route="headless", failpoint=crash)
    assert fired
    journal = AL.read_artifact_ledger(scratchpad).get("recon_publication_journal", {})
    assert journal.get("state") in {"ROLL_FORWARD", "QUARANTINED", "COMMITTED"}
    recovered = app.recover_recon_publications(config, route="headless")
    assert recovered["terminal_state"] in {"APPLIED", "QUARANTINED", "DEBT"}
    raw_after = _snapshot(scratchpad, CANONICAL_POSTIMAGE)
    changed = {name for name in CANONICAL_POSTIMAGE if raw_before[name] != raw_after[name]}
    assert changed in (set(), set(CANONICAL_POSTIMAGE))


@pytest.mark.parametrize(
    "failpoint",
    (
        "AFTER_SOURCE_CAPTURE:canonical_merge",
        "AFTER_NAMESPACE_SEAL:canonical_merge",
        "AFTER_ARM:canonical_merge",
        "BEFORE_PUBLISH:canonical_merge",
        "BEFORE_COMMIT:canonical_merge",
        "AFTER_COMMIT:canonical_merge",
    ),
)
def test_canonical_capture_arm_and_commit_failpoints_are_public_and_recoverable(
    tmp_path: Path,
    failpoint: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    fired = False

    class InjectedCrash(RuntimeError):
        pass

    def crash(label: str) -> None:
        nonlocal fired
        if label == failpoint and not fired:
            fired = True
            raise InjectedCrash(label)

    with pytest.raises(InjectedCrash):
        app.run_canonical_merge(config, route="startup_resume", failpoint=crash)
    assert fired
    journal = AL.read_artifact_ledger(scratchpad).get("recon_publication_journal", {})
    assert journal.get("state") in {
        "SOURCE_CAPTURED",
        "NAMESPACE_SEALED",
        "ARMED",
        "STAGED",
        "ROLL_FORWARD",
        "QUARANTINED",
        "COMMITTED",
    }
    recovered = app.recover_recon_publications(config, route="startup_resume")
    assert recovered["terminal_state"] in {"APPLIED", "QUARANTINED", "DEBT"}


def test_raw_model_shards_are_immutable_and_missing_evidence_is_not_invented(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    missing = scratchpad / "recon_templates_patterns.md"
    missing.unlink()
    before = _snapshot(scratchpad, WORKER_SHARDS)
    result = app.run_canonical_merge(config, route="startup_resume")
    after = _snapshot(scratchpad, WORKER_SHARDS)
    assert after == before
    assert after["recon_templates_patterns.md"] is None
    assert result["terminal_state"] in {"DEBT", "REJECTED", "QUARANTINED"}
    assert "recon_templates_patterns.md" in result["explicit_missing_evidence"]
    assert result.get("invented_model_outputs", []) == []


def test_exact_canonical_retry_reuses_committed_generation_without_renderer(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    first = app.run_canonical_merge(config, route="pty")
    assert first["terminal_state"] == "APPLIED"
    _assert_committed(
        scratchpad,
        first,
        outputs=set(CANONICAL_POSTIMAGE),
        terminals={"APPLIED"},
    )
    before = _snapshot(scratchpad, CANONICAL_POSTIMAGE)
    calls = 0

    def forbidden_renderer(_inputs: Mapping[str, bytes]) -> Mapping[str, bytes]:
        nonlocal calls
        calls += 1
        raise AssertionError("committed canonical generation was rendered again")

    second = app.run_canonical_merge(
        config,
        route="pty",
        renderer=forbidden_renderer,
    )
    assert calls == 0
    assert second["terminal_state"] == "REUSED_COMMITTED_GENERATION"
    assert second["generation_id"] == first["generation_id"]
    assert second["semantic_writer_count"] == 0
    assert _snapshot(scratchpad, CANONICAL_POSTIMAGE) == before
    _assert_committed(scratchpad, second)


@pytest.mark.parametrize("route", ("pty", "headless", "startup_resume", "validation_fallback"))
def test_canonical_live_routes_execute_the_public_publisher(tmp_path: Path, route: str) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path / route)
    result = app.run_canonical_merge(config, route=route)
    assert result["route"] == route
    assert result["publisher"] == "recon_phaseio_application.publish_recon_plan"
    assert result["applied"] is True
    _assert_committed(scratchpad, result, outputs=set(CANONICAL_POSTIMAGE))


@pytest.mark.parametrize(
    ("states", "expected"),
    (
        (("MODEL_OUTPUT", "DRIVER_FALLBACK", "EXPLICIT_ABSENCE", "DEBT"), (1, 1, 1, 1)),
        (("MODEL_OUTPUT", "MODEL_OUTPUT", "MODEL_OUTPUT", "MODEL_OUTPUT"), (4, 0, 0, 0)),
        (("DRIVER_FALLBACK", "DRIVER_FALLBACK", "DRIVER_FALLBACK", "DRIVER_FALLBACK"), (0, 4, 0, 0)),
        (("EXPLICIT_ABSENCE", "EXPLICIT_ABSENCE", "EXPLICIT_ABSENCE", "EXPLICIT_ABSENCE"), (0, 0, 4, 0)),
        (("DEBT", "DEBT", "DEBT", "DEBT"), (0, 0, 0, 4)),
    ),
)
def test_supplementary_disposition_has_one_exclusive_row_per_sibling(
    tmp_path: Path,
    states: tuple[str, ...],
    expected: tuple[int, int, int, int],
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    sibling_outcomes = dict(zip(SUPPLEMENTARY_SIBLINGS, states, strict=True))
    result = app.run_supplementary_disposition(
        config,
        sibling_outcomes=sibling_outcomes,
        canonical_generation="canonical-g1",
    )
    rows = result["rows"]
    assert set(rows) == set(SUPPLEMENTARY_SIBLINGS)
    assert all(row["selected_count"] == 1 for row in rows.values())
    counts = tuple(sum(row["state"] == state for row in rows.values()) for state in (
        "MODEL_OUTPUT", "DRIVER_FALLBACK", "EXPLICIT_ABSENCE", "DEBT"
    ))
    assert counts == expected
    assert result["row_count"] == 4
    assert result["terminal_state"] == "APPLIED"
    _assert_committed(scratchpad, result, terminals={"APPLIED"})


@pytest.mark.parametrize("sibling", SUPPLEMENTARY_SIBLINGS)
def test_each_supplementary_fallback_has_named_crash_recovery(
    tmp_path: Path,
    sibling: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    failpoint = f"AFTER_PUBLISH:{sibling}"
    fired = False

    class InjectedCrash(RuntimeError):
        pass

    def crash(label: str) -> None:
        nonlocal fired
        if label == failpoint and not fired:
            fired = True
            raise InjectedCrash(label)

    with pytest.raises(InjectedCrash):
        app.run_supplementary_disposition(
            config,
            sibling_outcomes={name: "DRIVER_FALLBACK" for name in SUPPLEMENTARY_SIBLINGS},
            canonical_generation="canonical-g1",
            failpoint=crash,
        )
    assert fired
    journal = AL.read_artifact_ledger(scratchpad).get("recon_publication_journal", {})
    assert journal.get("state") in {"ROLL_FORWARD", "QUARANTINED", "COMMITTED"}
    recovered = app.recover_recon_publications(config, route="validation_fallback")
    assert recovered["terminal_state"] in {"APPLIED", "QUARANTINED", "DEBT"}


@pytest.mark.parametrize("sibling", SUPPLEMENTARY_SIBLINGS)
def test_each_supplementary_fallback_has_named_stage_failpoint(
    tmp_path: Path,
    sibling: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    failpoint = f"AFTER_STAGE:{sibling}"
    fired = False

    class InjectedCrash(RuntimeError):
        pass

    def crash(label: str) -> None:
        nonlocal fired
        if label == failpoint and not fired:
            fired = True
            raise InjectedCrash(label)

    with pytest.raises(InjectedCrash):
        app.run_supplementary_disposition(
            config,
            sibling_outcomes={name: "DRIVER_FALLBACK" for name in SUPPLEMENTARY_SIBLINGS},
            canonical_generation="canonical-g1",
            failpoint=crash,
        )
    assert fired
    journal = AL.read_artifact_ledger(scratchpad).get("recon_publication_journal", {})
    assert journal.get("state") in {"STAGED", "QUARANTINED"}


@pytest.mark.parametrize("defect", ("prior_fallback_as_model", "changed_canonical_generation"))
def test_supplementary_disposition_rejects_misattribution_and_stale_canonical(
    tmp_path: Path,
    defect: str,
) -> None:
    app = _application()
    _project, _scratchpad, config = _workspace(tmp_path)
    result = app.run_supplementary_disposition(
        config,
        sibling_outcomes={name: "MODEL_OUTPUT" for name in SUPPLEMENTARY_SIBLINGS},
        canonical_generation="canonical-g1",
        inject_defect=defect,
    )
    assert result["terminal_state"] in {"DEBT", "REJECTED", "QUARANTINED"}
    assert result.get("semantic_writer_count", 0) == 0


@pytest.mark.parametrize("consumer", ("instantiate", "breadth"))
def test_consumers_bind_current_recon_generation_and_stable_smoke_roster(
    tmp_path: Path,
    consumer: str,
) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path / consumer)
    canonical = app.run_canonical_merge(config, route="pty")
    disposition = app.run_supplementary_disposition(
        config,
        sibling_outcomes={name: "MODEL_OUTPUT" for name in SUPPLEMENTARY_SIBLINGS},
        canonical_generation=canonical["generation_id"],
    )
    result = app.validate_recon_consumer(
        config,
        consumer=consumer,
        canonical_generation=canonical["generation_id"],
        disposition_generation=disposition["generation_id"],
    )
    assert result["status"] == "BOUND_CURRENT"
    assert set(result["recon_inputs"]) == set(STABLE_SMOKE_RECON_MISMATCH_ROSTER)
    assert "skill_selection_catalog.json" not in result["recon_inputs"]
    assert result["skill_selection_owner"] != "recon"
    assert result["canonical_generation"] == canonical["generation_id"]
    assert result["disposition_generation"] == disposition["generation_id"]
    consumer_unit = AL.read_artifact_ledger(scratchpad)["work_units"][result["work_unit_key"]]
    for name in STABLE_SMOKE_RECON_MISMATCH_ROSTER:
        binding = consumer_unit["input_bindings"][f"scratchpad:{name}"]
        assert binding["status"] == "ACTIVE"
        assert binding["producer_run_id"] == RUN_ID
        assert len(binding["producer_contract_digest"]) == 64
        assert len(binding["producer_launch_digest"]) == 64


def test_consumer_rejects_tamper_uncommitted_and_foreign_generation(tmp_path: Path) -> None:
    app = _application()
    _project, scratchpad, config = _workspace(tmp_path)
    canonical = app.run_canonical_merge(config, route="headless")
    disposition = app.run_supplementary_disposition(
        config,
        sibling_outcomes={name: "MODEL_OUTPUT" for name in SUPPLEMENTARY_SIBLINGS},
        canonical_generation=canonical["generation_id"],
    )
    for defect in ("tampered_bytes", "uncommitted_producer", "foreign_generation"):
        result = app.validate_recon_consumer(
            config,
            consumer="instantiate",
            canonical_generation=canonical["generation_id"],
            disposition_generation=disposition["generation_id"],
            inject_defect=defect,
        )
        assert result["status"] == "PRODUCER_AUTHORITY_MISMATCH"
        assert result["may_launch"] is False
    assert "skill_selection_catalog.json" not in STABLE_SMOKE_RECON_MISMATCH_ROSTER
    assert not any("skill_selection" in name for name in STABLE_SMOKE_RECON_MISMATCH_ROSTER)


def test_vertical_slice_order_cannot_claim_dormant_publisher_application() -> None:
    app = _application()
    inventory = app.recon_route_application("inventory")
    assert inventory["schema"] == "plamen.recon-route-application.v1"
    assert inventory["vertical_slice_order"] == [
        "prepass",
        "dependency_chain",
        "canonical_merge",
        "supplementary_disposition",
        "consumer_binding",
    ]
    for row in inventory["slices"]:
        assert set(row) >= {
            "contract_registered",
            "publisher_executed",
            "live_routes_executed",
            "ledger_replayed",
            "immediate_consumer_bound",
            "application_state",
        }
        prerequisites = (
            row["contract_registered"],
            row["publisher_executed"],
            row["live_routes_executed"],
            row["ledger_replayed"],
            row["immediate_consumer_bound"],
        )
        assert (row["application_state"] == "APPLIED") is all(prerequisites)
        if row.get("publisher_present") and not row["publisher_executed"]:
            assert row["application_state"] != "APPLIED"
