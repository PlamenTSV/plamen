from __future__ import annotations

import hashlib
import inspect
from pathlib import Path
import sys

import pytest

import program_facts_evm_wtx as EWTX
from program_facts_evm_provider import (
    EVM_CAPABILITY_IDS,
    plan_evm_slither,
)
from program_facts_evm_tool_authority import (
    load_installed_evm_tool_authority,
)
from program_facts_provider_api import (
    CapabilityRequest,
    ObservedProviderIdentity,
    PlatformIdentity,
    ProviderContext,
    ProviderResources,
    ToolchainIdentity,
)
from program_facts_provider_registry import (
    STRUCTURAL_TEST_ONLY,
    load_program_facts_provider_registry_bytes,
)
from worker_execution_receipts import environment_allowlist_sha256


def _bindings() -> EWTX.EvmWtxPhaseBindings:
    return EWTX.EvmWtxPhaseBindings(
        run_id="stage2-evm-fixture",
        phase="recon",
        work_unit_id="program_facts_evm_provider",
        generation=1,
        phase_roster_denominator_digest="1" * 64,
        phase_io_contract_digest="2" * 64,
        phase_io_launch_digest="3" * 64,
        phase_io_input_set_digest="4" * 64,
    )


def _interpreter() -> EWTX.InterpreterObservation:
    path = Path(sys.executable).resolve()
    return EWTX.InterpreterObservation(
        resolved_executable=path,
        executable_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        version=sys.version.split()[0],
    )


def _plan():
    registry_path = (
        Path(__file__).resolve().parents[1]
        / "rules"
        / "program-facts-provider-registry.v1.json"
    )
    registry = load_program_facts_provider_registry_bytes(
        registry_path.read_bytes(),
        authority_mode=STRUCTURAL_TEST_ONLY,
    )
    row = registry.providers[0]
    context = ProviderContext(
        audit_run_id="stage2-evm-fixture",
        methodology_authority_digest="7" * 64,
        snapshot_digest="0" * 64,
        source_scope_digest="1" * 64,
        source_manifest_digest="2" * 64,
        source_authority_digest="3" * 64,
        ecosystem="evm",
        languages=("solidity",),
        build_variant_ids=("variant-0",),
        capability_requests=tuple(
            CapabilityRequest(
                capability_id,
                "MAY" if capability_id.endswith("dependencies.v1") else "EXACT",
            )
            for capability_id in EVM_CAPABILITY_IDS
        ),
        toolchains=(ToolchainIdentity("solc", "0.8.28", "4" * 64),),
        platform=PlatformIdentity("windows", "amd64"),
        environment=(),
        working_directory_root_id="root-0",
    )
    tool = row["tool_identity"]
    distribution = row["distribution"]
    install = row["install_policy"]
    provenance = row["installation_provenance"]
    raw_binding = row["raw_binding"]
    observed = ObservedProviderIdentity(
        registry_digest=registry.registry_digest,
        provider_schema_version=row["provider_schema_version"],
        adapter_module=row["adapter"]["module"],
        adapter_symbol=row["adapter"]["symbol"],
        parser_callable=raw_binding["parser_callable"],
        parser_source_digest=raw_binding["parser_source_digest"],
        raw_schema_digest=raw_binding["raw_schema_digest"],
        tool_kind=tool["kind"],
        tool_name=tool["name"],
        command=tool["command"],
        module=tool["module"],
        executable_sha256=tool["executable_sha256"],
        module_sha256=tool["module_sha256"],
        distribution_kind=distribution["kind"],
        distribution_name=distribution["name"],
        distribution_version=distribution["version"],
        distribution_checksum=distribution["checksum"],
        distribution_module_source_digest=distribution[
            "module_source_digest"
        ],
        version_output=(
            "plamen-evm-slither-helper 1.0.0 "
            "(slither-analyzer 0.11.5; disabled_pending_semantic_review)"
        ),
        license_classification=row["license_classification"],
        platform=context.platform,
        installation_mode=install["mode"],
        installation_lock_identity=install["lock_identity"],
        installation_lock_digest=install["lock_digest"],
    )
    argv = tuple(row["invocation_policy"]["argv_template"])
    decision = plan_evm_slither(
        registry=registry,
        provider_run_id="evm.slither.typed.run-0",
        context=context,
        observed_identity=observed,
        argv=argv,
        resources=ProviderResources(
            time_seconds=600,
            memory_bytes=1073741824,
            input_bytes=1048576,
            output_bytes=1048576,
        ),
        allowed_license_classifications=("AGPL-3.0-only",),
        source_manifest_authority=None,
        observed_configuration_inputs=row["invocation_policy"][
            "configuration_inputs"
        ],
    )
    assert decision.structurally_valid is True
    assert decision.ready is False
    assert decision.plan is not None
    return registry, context, observed, decision.plan


def test_installed_disabled_tool_yields_debt_without_compiling_work() -> None:
    _registry, _context, _observed, provider_plan = _plan()
    decision = EWTX.plan_evm_worker_transaction(
        provider_plan=provider_plan,
        tool_authority=load_installed_evm_tool_authority(),
        interpreter=_interpreter(),
        phase_bindings=_bindings(),
    )

    assert decision.ready is False
    assert decision.work_plan is None
    assert decision.reason == "PROVIDER_UNAVAILABLE"
    assert decision.blocks_reuse is True
    assert decision.terminal_negative_authority is False


def test_structural_wtx_plan_binds_logical_and_actual_argv() -> None:
    _registry, _context, _observed, provider_plan = _plan()
    authority = load_installed_evm_tool_authority()
    compiled = EWTX.compile_evm_worker_transaction_structural_test_only(
        authority_mode="STRUCTURAL_TEST_ONLY",
        provider_plan=provider_plan,
        tool_authority=authority,
        interpreter=_interpreter(),
        phase_bindings=_bindings(),
    )

    helper = Path(__file__).resolve().parent / "program_facts_evm_helper.py"
    expected_actual = (
        str(_interpreter().resolved_executable),
        "-I",
        str(helper),
        "--stdin-json",
    )
    assert compiled.production_authority_established is False
    assert compiled.logical_argv == tuple(provider_plan.argv)
    assert compiled.actual_argv == expected_actual
    assert compiled.command_binding["logical_argv_sha256"] != (
        compiled.command_binding["actual_argv_sha256"]
    )
    assert compiled.work_plan["provider"]["backend"] == "native"
    assert compiled.work_plan["provider"]["transport"] == "native"
    assert compiled.work_plan["provider"]["argv_template"] == list(
        expected_actual
    )
    assert compiled.work_plan["provider"][
        "environment_allowlist_digest"
    ] == environment_allowlist_sha256(())


def test_structural_plan_cannot_execute_or_mint_receipt() -> None:
    _registry, _context, _observed, provider_plan = _plan()
    compiled = EWTX.compile_evm_worker_transaction_structural_test_only(
        authority_mode="STRUCTURAL_TEST_ONLY",
        provider_plan=provider_plan,
        tool_authority=load_installed_evm_tool_authority(),
        interpreter=_interpreter(),
        phase_bindings=_bindings(),
    )

    with pytest.raises(EWTX.ProgramFactsEvmWtxError, match="production"):
        EWTX.execute_evm_worker_transaction(
            compiled,
            scratchpad=Path.cwd(),
            cwd=Path.cwd(),
            input_relative_paths={
                "manifest": "manifest.json",
                "intent": "intent.json",
                "context": "context.json",
                "prompt": "prompt.json",
                "tool_policy": "tool_policy.json",
            },
            parser_digest=lambda _path, raw: hashlib.sha256(raw).hexdigest(),
        )
    with pytest.raises(EWTX.ProgramFactsEvmWtxError, match="production"):
        EWTX.reconcile_evm_worker_execution(
            compiled,
            object(),
            scratchpad=Path.cwd(),
            parser_digest=lambda _path, raw: hashlib.sha256(raw).hexdigest(),
        )


def test_evm_wtx_module_has_no_direct_process_or_publication_lane() -> None:
    source = inspect.getsource(EWTX)
    forbidden = (
        "import subprocess",
        "from subprocess",
        "Popen(",
        "subprocess.",
        "os.system(",
        "import slither",
        "from slither",
        "record_work_unit_artifacts",
        "write_bytes(",
    )
    assert not any(token in source for token in forbidden)
    assert "execute_worker_transaction(" in source
    assert "NativeCommandAdapter(" in source
