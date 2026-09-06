from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

from audit_snapshot import build_audit_snapshot
from artifact_ledger import (
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from program_facts_evm_provider import EVM_CAPABILITY_IDS
from program_facts_evm_tool_authority import (
    load_installed_evm_tool_authority,
)
from program_facts_methodology_authority import (
    capture_installed_program_facts_methodology_authority,
)
from program_facts_provider_api import (
    CapabilityRequest,
    PlatformIdentity,
    ProviderContext,
    ToolchainIdentity,
)
from program_facts_provider_registry import (
    load_program_facts_provider_registry,
)
from program_facts_source_manifest import (
    build_program_facts_source_manifest,
    capture_program_facts_audit_snapshot_authority,
    replay_program_facts_source_manifest,
)
from program_facts_types import (
    ProgramFactsBundle,
    canonical_file_bytes,
    canonical_json_bytes,
)
import program_facts_bake as BAKE
import program_facts_loader as LOADER
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract


RUN_ID = "12345678-1234-4234-8234-123456789abc"
SIDECARES = (
    "mechanical_program_facts.v1.json",
    "mechanical_program_facts_receipt.v1.json",
    "mechanical_program_facts_debt.v1.json",
)
CHECKPOINT_CAPTURE = "_program_facts_inputs/checkpoint_capture.v1.json"


def _variant(foundry_raw: bytes) -> dict[str, object]:
    semantic = {
        "ecosystem": "evm",
        "build_system": "foundry",
        "build_root_id": "root-0",
        "manifest_digests": [
            {
                "path": "foundry.toml",
                "sha256": hashlib.sha256(foundry_raw).hexdigest(),
            }
        ],
        "dependency_closure_digest": hashlib.sha256(b"").hexdigest(),
        "compiler_identity_digest": "8" * 64,
        "profile": "default",
        "features": [],
        "tags": [],
        "remappings": [],
        "defines": [],
        "target_triples": [],
        "generated_source_policy": "BOUND_INCLUDED",
    }
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    return {
        "build_variant_id": f"PFB-{digest[:24]}",
        **semantic,
        "variant_digest": digest,
    }


def _production_inputs(tmp_path: Path) -> dict[str, object]:
    project = tmp_path / "evm-project"
    source = project / "src" / "Main.sol"
    source.parent.mkdir(parents=True)
    source.write_bytes(
        b"// SPDX-License-Identifier: MIT\n"
        b"pragma solidity ^0.8.20;\n"
        b"contract Main { uint256 public value; }\n"
    )
    foundry_raw = b"[profile.default]\nsrc = \"src\"\n"
    (project / "foundry.toml").write_bytes(foundry_raw)
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "solidity",
        "cli_backend": "claude",
        "scope_notes": "Program Facts Stage-2 production fixture",
    }
    installed_root = Path(__file__).resolve().parents[1]
    snapshot = build_audit_snapshot(config, installed_root)
    snapshot_authority = capture_program_facts_audit_snapshot_authority(
        snapshot,
        config=config,
    )
    captured = build_program_facts_source_manifest(
        config,
        snapshot,
        compiled_source_paths=["src/Main.sol"],
    )
    source_authority = replay_program_facts_source_manifest(
        captured.canonical_bytes,
        expected_snapshot_digest=snapshot["snapshot_digest"],
        expected_source_scope_digest=snapshot["components"][
            "source_scope"
        ]["digest"],
        source_bytes_by_id=captured.source_bytes_by_id,
        excluded_source_bytes_by_identity=(
            captured.excluded_source_bytes_by_identity
        ),
        capture_capability=captured.capture_capability,
    )
    checkpoint_bytes = canonical_file_bytes(
        {"audit_snapshot": snapshot, "run_id": RUN_ID}
    )
    methodology = capture_installed_program_facts_methodology_authority(
        checkpoint_bytes
    )
    registry = load_program_facts_provider_registry(
        installed_authority=methodology
    )
    source_manifest = json.loads(
        canonical_json_bytes(source_authority.record["source_manifest"])
    )
    variant = _variant(foundry_raw)
    context = ProviderContext(
        audit_run_id=RUN_ID,
        methodology_authority_digest=(
            registry.methodology_capture_digest
        ),
        snapshot_digest=snapshot["snapshot_digest"],
        source_scope_digest=snapshot["components"]["source_scope"]["digest"],
        source_manifest_digest=source_authority.manifest_digest,
        source_authority_digest=source_authority.authority_digest,
        ecosystem="evm",
        languages=("solidity",),
        build_variant_ids=(variant["build_variant_id"],),
        capability_requests=tuple(
            CapabilityRequest(
                capability_id,
                "MAY" if capability_id.endswith("dependencies.v1") else "EXACT",
            )
            for capability_id in EVM_CAPABILITY_IDS
        ),
        toolchains=(ToolchainIdentity("solc", "0.8.28", "8" * 64),),
        platform=PlatformIdentity("windows", "amd64"),
        environment=(),
        working_directory_root_id="root-0",
    )
    return {
        "project": project,
        "scratchpad": scratchpad,
        "config": config,
        "snapshot_authority": snapshot_authority,
        "source_authority": source_authority,
        "source_manifest": source_manifest,
        "source_bytes_by_id": captured.source_bytes_by_id,
        "registry": registry,
        "context": context,
        "build_variants": (variant,),
        "audit_snapshot": {
            "snapshot_digest": snapshot["snapshot_digest"],
            "source_scope_digest": snapshot["components"][
                "source_scope"
            ]["digest"],
            "audit_config_digest": snapshot["components"][
                "audit_config"
            ]["digest"],
            "methodology_digest": snapshot["components"][
                "methodology"
            ]["digest"],
            "toolchain_digest": snapshot["components"]["toolchain"]["digest"],
        },
        "phase_io": {
            "contract_digest": "1" * 64,
            "launch_digest": "2" * 64,
            "input_set_digest": "3" * 64,
            "work_unit_key": (
                "sc/thorough/evm/claude/recon/program_facts_bake"
            ),
            "ledger_binding_state": "PRECOMMIT",
            "ledger_record_digest": "",
        },
        "checkpoint_bytes": checkpoint_bytes,
    }


def test_disabled_evm_bake_stages_exact_production_valid_sidecars(
    tmp_path: Path,
) -> None:
    fixture = _production_inputs(tmp_path)
    plan = BAKE.plan_program_facts_bake(
        context=fixture["context"],
        source_manifest=fixture["source_manifest"],
        source_bytes_by_id=fixture["source_bytes_by_id"],
        build_variants=fixture["build_variants"],
        audit_snapshot=fixture["audit_snapshot"],
        phase_io=fixture["phase_io"],
        source_manifest_authority=fixture["source_authority"],
        audit_snapshot_authority=fixture["snapshot_authority"],
        provider_registry=fixture["registry"],
        tool_authority=load_installed_evm_tool_authority(),
        source_project_root=fixture["project"],
        source_config=fixture["config"],
    )
    result = BAKE.execute_program_facts_bake(plan)

    assert isinstance(result.bundle, ProgramFactsBundle)
    assert result.production_authority_established is True
    assert result.consumer_activation is False
    assert tuple(result.sidecars) == SIDECARES
    assert result.bundle.receipt.value["status"] == "UNAVAILABLE"
    assert result.bundle.receipt.value["provider_runs"] == ()
    assert result.bundle.receipt.value["worker_transaction_refs"] == ()
    assert {
        row["reason"] for row in result.bundle.debt.value["debts"]
    } == {"PROVIDER_UNAVAILABLE"}


def test_bake_and_loader_have_no_process_publication_or_consumer_lane() -> None:
    source = inspect.getsource(BAKE) + inspect.getsource(LOADER)
    forbidden = (
        "import subprocess",
        "from subprocess",
        "subprocess.",
        "Popen(",
        "os.system(",
        "record_work_unit_artifacts",
        "execute_worker_transaction(",
        "write_bytes(",
        "enumeration_gate",
        "chain_prep",
        "program_facts_slicing",
        "program_facts_obligations",
    )
    assert not any(token in source for token in forbidden)
    assert 'publication_authority: str = "STAGED_ONLY"' in source
    assert "consumer_activation: bool = False" in source


def test_staged_result_rejects_sidecar_substitution(tmp_path: Path) -> None:
    fixture = _production_inputs(tmp_path)
    result = BAKE.execute_program_facts_bake(
        BAKE.plan_program_facts_bake(
            context=fixture["context"],
            source_manifest=fixture["source_manifest"],
            source_bytes_by_id=fixture["source_bytes_by_id"],
            build_variants=fixture["build_variants"],
            audit_snapshot=fixture["audit_snapshot"],
            phase_io=fixture["phase_io"],
            source_manifest_authority=fixture["source_authority"],
            audit_snapshot_authority=fixture["snapshot_authority"],
            provider_registry=fixture["registry"],
            tool_authority=load_installed_evm_tool_authority(),
            source_project_root=fixture["project"],
            source_config=fixture["config"],
        )
    )
    tampered = dict(result.sidecars)
    tampered["mechanical_program_facts_debt.v1.json"] += b" "
    decision = BAKE.validate_program_facts_resume(
        sidecars=tampered,
        expected_reuse_key=result.reuse_key,
        context=fixture["context"],
        source_bytes_by_id=fixture["source_bytes_by_id"],
        source_manifest_authority=fixture["source_authority"],
        audit_snapshot_authority=fixture["snapshot_authority"],
        provider_registry=fixture["registry"],
        source_project_root=fixture["project"],
        source_config=fixture["config"],
    )

    assert decision.reusable is False
    assert decision.state == "INVALID"
    assert decision.blocks_reuse is True


def _output_records(
    scratchpad: Path,
    contract,
) -> dict[str, dict[str, object]]:
    return {
        output.identity: {
            "sha256": hashlib.sha256(
                (scratchpad / output.path).read_bytes()
            ).hexdigest(),
            "size": (scratchpad / output.path).stat().st_size,
        }
        for output in contract.outputs
    }


def _launch(contract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )


def test_loader_requires_exact_three_files_and_live_phaseio_commit(
    tmp_path: Path,
) -> None:
    fixture = _production_inputs(tmp_path)
    result = BAKE.execute_program_facts_bake(
        BAKE.plan_program_facts_bake(
            context=fixture["context"],
            source_manifest=fixture["source_manifest"],
            source_bytes_by_id=fixture["source_bytes_by_id"],
            build_variants=fixture["build_variants"],
            audit_snapshot=fixture["audit_snapshot"],
            phase_io=fixture["phase_io"],
            source_manifest_authority=fixture["source_authority"],
            audit_snapshot_authority=fixture["snapshot_authority"],
            provider_registry=fixture["registry"],
            tool_authority=load_installed_evm_tool_authority(),
            source_project_root=fixture["project"],
            source_config=fixture["config"],
        )
    )
    scratchpad = fixture["scratchpad"]
    project = fixture["project"]
    checkpoint_contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="program_facts_checkpoint_capture",
        exact_inputs=(),
        exact_outputs=(CHECKPOINT_CAPTURE,),
        exact_writer="DRIVER",
    )
    checkpoint_launch = _launch(checkpoint_contract)
    record_work_unit_inputs(
        scratchpad,
        project,
        checkpoint_contract,
        checkpoint_launch,
        run_id=RUN_ID,
    )
    checkpoint_path = scratchpad / CHECKPOINT_CAPTURE
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.write_bytes(
        fixture["checkpoint_bytes"]
    )
    record_work_unit_artifacts(
        scratchpad,
        project,
        checkpoint_contract,
        checkpoint_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        expected_output_records=_output_records(
            scratchpad,
            checkpoint_contract,
        ),
    )
    methodology_outputs = tuple(
        fixture["registry"].phase_io_input_bytes
    )
    methodology_contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="program_facts_methodology_capture",
        exact_inputs=(CHECKPOINT_CAPTURE,),
        exact_outputs=methodology_outputs,
    )
    methodology_launch = _launch(methodology_contract)
    record_work_unit_inputs(
        scratchpad,
        project,
        methodology_contract,
        methodology_launch,
        run_id=RUN_ID,
    )
    for identity, raw in fixture["registry"].phase_io_input_bytes.items():
        target = scratchpad / identity.removeprefix(
            "_program_facts_methodology/"
        )
        # PhaseIO identities already include the scratchpad-relative prefix.
        target = scratchpad / identity
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        project,
        methodology_contract,
        methodology_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        expected_output_records=_output_records(
            scratchpad, methodology_contract
        ),
    )
    bake_inputs = (
        CHECKPOINT_CAPTURE,
        *methodology_outputs,
    )
    bake_contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id="program_facts_bake",
        exact_inputs=bake_inputs,
        exact_outputs=SIDECARES,
    )
    bake_launch = _launch(bake_contract)
    record_work_unit_inputs(
        scratchpad,
        project,
        bake_contract,
        bake_launch,
        run_id=RUN_ID,
    )
    for identity, raw in result.sidecars.items():
        (scratchpad / identity).write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        project,
        bake_contract,
        bake_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        expected_output_records=_output_records(scratchpad, bake_contract),
    )

    loaded = LOADER.load_bound_program_facts(
        scratchpad=scratchpad,
        project_root=project,
        contract=bake_contract,
        launch=bake_launch,
        run_id=RUN_ID,
        context=fixture["context"],
        source_bytes_by_id=fixture["source_bytes_by_id"],
        source_manifest_authority=fixture["source_authority"],
        audit_snapshot_authority=fixture["snapshot_authority"],
        provider_registry=fixture["registry"],
        source_project_root=project,
        source_config=fixture["config"],
    )
    assert loaded.state == "UNSUPPORTED"
    assert loaded.valid is True
    assert loaded.reusable is True
    assert loaded.consumer_activation is False

    (scratchpad / "mechanical_program_facts_debt.v1.json").write_bytes(
        result.sidecars["mechanical_program_facts_debt.v1.json"] + b" "
    )
    rejected = LOADER.load_bound_program_facts(
        scratchpad=scratchpad,
        project_root=project,
        contract=bake_contract,
        launch=bake_launch,
        run_id=RUN_ID,
        context=fixture["context"],
        source_bytes_by_id=fixture["source_bytes_by_id"],
        source_manifest_authority=fixture["source_authority"],
        audit_snapshot_authority=fixture["snapshot_authority"],
        provider_registry=fixture["registry"],
        source_project_root=project,
        source_config=fixture["config"],
    )
    assert rejected.state == "INVALID"
    assert rejected.valid is False
    assert rejected.blocks_reuse is True
