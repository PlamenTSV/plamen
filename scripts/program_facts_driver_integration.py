"""Driver-owned Program Facts Stage-2 integration.

This module is the only production bridge between the audit driver and the
emit-only Program Facts substrate.  It captures one immutable snapshot/run
identity, publishes installed methodology inputs, composes the EVM
``PROVIDER_UNAVAILABLE`` bundle, and commits every output through PhaseIO and
the ArtifactLedger.  It never launches a model, activates a consumer, or
interprets absence as negative authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform as host_platform
import re
from typing import Any, Callable, Mapping, Sequence

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from audit_snapshot import build_audit_snapshot
from phase_io_contracts import (
    LaunchSpec,
    PhaseIOContract,
    resolve_phase_io_contract,
)
from program_facts_bake import (
    PROGRAM_FACTS_SIDECAR_PATHS,
    ProgramFactsBakeResult,
    ensure_program_facts_bake,
)
from program_facts_evm_provider import EVM_CAPABILITY_IDS, EVM_PROVIDER_ID
from program_facts_evm_tool_authority import (
    load_installed_evm_tool_authority,
)
from program_facts_loader import load_bound_program_facts
from program_facts_methodology_authority import (
    PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
    capture_installed_program_facts_methodology_authority,
)
from program_facts_provider_api import (
    CapabilityRequest,
    PlatformIdentity,
    ProviderContext,
    ToolchainIdentity,
)
from program_facts_provider_registry import (
    LoadedProgramFactsProviderRegistry,
    load_program_facts_provider_registry,
)
from program_facts_source_manifest import (
    build_program_facts_source_manifest,
    capture_program_facts_audit_snapshot_authority,
    replay_program_facts_source_manifest,
)
from program_facts_types import (
    canonical_file_bytes,
    canonical_json_bytes,
    strict_json_loads,
)
import rooted_path_io


PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH = (
    "_program_facts_inputs/checkpoint_capture.v1.json"
)
_CHECKPOINT_CAPTURE_UNIT = "program_facts_checkpoint_capture"
_METHODOLOGY_CAPTURE_UNIT = "program_facts_methodology_capture"
_BAKE_UNIT = "program_facts_bake"
_LAUNCH_TIMEOUT_SECONDS = 30
_UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.ASCII,
)
_FaultInjector = Callable[[str], None]
_SNAPSHOT_PRIVATE_CONFIG_KEYS = frozenset(
    {
        "_backend_runtime_contract",
        "_docs_materialized_bundle",
        "_resolved_build_context_files",
        "_resolved_build_context_roots",
        "_resolved_build_root",
        "_resolved_build_source_files",
        "_resolved_compiled_dependency_roots",
        "_snapshot_build_input_limitations",
    }
)


class ProgramFactsDriverIntegrationError(RuntimeError):
    """The Stage-2 driver bridge could not establish truthful authority."""


def _fail(message: str, exc: BaseException | None = None) -> None:
    if exc is None:
        raise ProgramFactsDriverIntegrationError(message)
    raise ProgramFactsDriverIntegrationError(message) from exc


@dataclass(frozen=True)
class ProgramFactsDriverOutcome:
    state: str
    valid: bool
    reused: bool
    consumer_activation: bool = False
    reason_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        if self.consumer_activation:
            _fail("Program Facts Stage-2 cannot activate consumers")


def _dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    mode = str(config.get("mode") or "core").strip().lower()
    language = str(config.get("language") or "").strip().lower()
    ecosystem = {
        "solidity": "evm",
        "ethereum": "evm",
    }.get(language, language)
    backend = str(config.get("cli_backend") or "claude").strip().lower()
    return pipeline, mode, ecosystem, backend


def _snapshot_visible_config(
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Retain exactly the config fields read by the frozen snapshot policy."""

    return {
        str(key): value
        for key, value in config.items()
        if (
            not str(key).startswith("_")
            or str(key) in _SNAPSHOT_PRIVATE_CONFIG_KEYS
        )
    }


def _resolve(
    *,
    config: Mapping[str, Any],
    work_unit_id: str,
    exact_inputs: Sequence[str],
    exact_outputs: Sequence[str],
) -> tuple[PhaseIOContract, LaunchSpec]:
    pipeline, mode, ecosystem, backend = _dimensions(config)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id=work_unit_id,
        exact_inputs=tuple(exact_inputs),
        exact_outputs=tuple(exact_outputs),
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_LAUNCH_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=(),
    )
    return contract, launch


def _output_records(
    scratchpad: Path,
    contract: PhaseIOContract,
) -> dict[str, dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    for output in contract.outputs:
        if output.root != "scratchpad":
            _fail("Program Facts integration only publishes scratchpad outputs")
        try:
            raw = rooted_path_io.read_bytes(
                scratchpad / output.path,
                label=f"Program Facts output {output.path}",
                require_single_link=False,
            )
        except (OSError, rooted_path_io.RootedPathIOError) as exc:
            _fail(f"Program Facts output is unreadable: {output.path}", exc)
        records[output.identity] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
    return records


def _exact_live_bytes(path: Path, expected: bytes) -> bool:
    if not rooted_path_io.lexists(path):
        return False
    try:
        raw = rooted_path_io.read_bytes(
            path,
            label="Program Facts exact live output",
            require_single_link=True,
        )
    except FileNotFoundError:
        return False
    except (OSError, rooted_path_io.RootedPathIOError) as exc:
        _fail(f"unsafe Program Facts output prestate: {path}", exc)
    return raw == expected


def _atomic_materialize(path: Path, raw: bytes) -> None:
    """Durably publish exact bytes while preserving an exact live inode."""

    if type(raw) is not bytes or not raw:
        _fail("Program Facts publication bytes must be exact and nonempty")
    if _exact_live_bytes(path, raw):
        return
    rooted_path_io.ensure_directory(
        path.parent,
        parents=True,
        label="Program Facts publication parent",
    )
    descriptor, temporary = rooted_path_io.exclusive_temp_file(
        path.parent,
        prefix=".program-facts.",
        suffix=".publishing.tmp",
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        rooted_path_io.durable_replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if rooted_path_io.lexists(temporary):
            rooted_path_io.unlink(temporary)


def _stored_unit(
    scratchpad: Path,
    contract: PhaseIOContract,
) -> Mapping[str, Any] | None:
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger.get("work_units", {}).get(contract.key)
    return unit if isinstance(unit, Mapping) else None


def _arm_or_replay(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
) -> bool:
    """Return true only for an already committed exact work unit."""

    unit = _stored_unit(scratchpad, contract)
    if unit is None:
        try:
            unit = record_work_unit_inputs(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
            )
        except ArtifactLedgerError as exc:
            _fail(f"{contract.key}: PhaseIO input arm failed", exc)
    if (
        unit.get("run_id") != run_id
        or unit.get("contract_digest") != contract.digest
        or unit.get("launch_digest") != launch.digest
    ):
        _fail(f"{contract.key}: stored PhaseIO authority drift")
    artifacts = unit.get("artifacts")
    if (
        unit.get("semantic_status") == "ACTIVE"
        and isinstance(artifacts, Mapping)
        and artifacts
    ):
        issues = validate_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
        if issues:
            _fail(
                f"{contract.key}: committed PhaseIO replay failed: "
                + "; ".join(issues)
            )
        return True
    if (
        unit.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
        or unit.get("semantic_status") != "INPUTS_BOUND"
        or not isinstance(artifacts, Mapping)
        or artifacts
    ):
        _fail(
            f"{contract.key}: PhaseIO unit is neither a clean arm nor "
            "an active commit"
        )
    issues = validate_work_unit_inputs(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
    )
    if issues:
        _fail(
            f"{contract.key}: PhaseIO input replay failed: "
            + "; ".join(issues)
        )
    return False


def _publish_phaseio_outputs(
    *,
    scratchpad: Path,
    project_root: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    run_id: str,
    outputs: Mapping[str, bytes],
    fault_injector: _FaultInjector | None,
) -> bool:
    """Publish an exact driver denominator; return true on committed reuse."""

    expected_paths = tuple(output.path for output in contract.outputs)
    if tuple(outputs) != expected_paths:
        _fail(f"{contract.key}: publication denominator/order drift")
    committed = _arm_or_replay(
        scratchpad=scratchpad,
        project_root=project_root,
        contract=contract,
        launch=launch,
        run_id=run_id,
    )
    if committed:
        for identity, raw in outputs.items():
            if not _exact_live_bytes(scratchpad / identity, raw):
                _fail(f"{contract.key}: committed output byte drift: {identity}")
        return True
    for ordinal, (identity, raw) in enumerate(outputs.items(), start=1):
        _atomic_materialize(scratchpad / identity, raw)
        if fault_injector is not None:
            fault_injector(
                f"{contract.work_unit_id}:published:{ordinal}"
            )
    try:
        unit = record_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=_output_records(
                scratchpad, contract
            ),
        )
    except ArtifactLedgerError as exc:
        _fail(f"{contract.key}: PhaseIO output commit failed", exc)
    if unit.get("semantic_status") != "ACTIVE":
        reasons = unit.get("commit_authority", {}).get("reason_codes", ())
        _fail(
            f"{contract.key}: PhaseIO output commit was quarantined: "
            + ", ".join(str(reason) for reason in reasons)
        )
    issues = validate_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    if issues:
        _fail(
            f"{contract.key}: committed output replay failed: "
            + "; ".join(issues)
        )
    return False


def _checkpoint_capture_bytes(
    *,
    run_id: str,
    audit_snapshot: Mapping[str, Any],
) -> bytes:
    if _UUID4_RE.fullmatch(run_id) is None:
        _fail("Program Facts run_id must be a canonical UUIDv4")
    try:
        raw = canonical_file_bytes(
            {
                "audit_snapshot": dict(audit_snapshot),
                "run_id": run_id,
            }
        )
        value = strict_json_loads(
            raw,
            require_final_lf=True,
            require_canonical=True,
        )
    except Exception as exc:
        _fail("Program Facts immutable checkpoint capture is invalid", exc)
    if not isinstance(value, Mapping) or set(value) != {
        "audit_snapshot",
        "run_id",
    }:
        _fail("Program Facts checkpoint capture schema drift")
    return raw


def _portable_platform() -> PlatformIdentity:
    if os.name == "nt":
        os_name = "windows"
    elif os.sys.platform.startswith("linux"):
        os_name = "linux"
    elif os.sys.platform == "darwin":
        os_name = "macos"
    else:
        _fail("Program Facts Stage-2 host OS is unsupported")
    machine = host_platform.machine().strip().lower()
    if machine in {"amd64", "x86_64"}:
        architecture = "amd64"
    elif machine in {"arm64", "aarch64"}:
        architecture = "arm64"
    else:
        _fail("Program Facts Stage-2 host architecture is unsupported")
    return PlatformIdentity(os_name, architecture)


def _unavailable_build_variant() -> tuple[dict[str, Any], ToolchainIdentity]:
    compiler_digest = hashlib.sha256(
        b"PLAMEN_PROGRAM_FACTS_EVM_COMPILER_UNAVAILABLE_V1"
    ).hexdigest()
    semantic: dict[str, Any] = {
        "ecosystem": "evm",
        "build_system": "unresolved",
        "build_root_id": "root-0",
        "manifest_digests": [],
        "dependency_closure_digest": hashlib.sha256(b"").hexdigest(),
        "compiler_identity_digest": compiler_digest,
        "profile": "",
        "features": [],
        "tags": [],
        "remappings": [],
        "defines": [],
        "target_triples": [],
        "generated_source_policy": "BOUND_EXCLUDED",
    }
    digest = hashlib.sha256(canonical_json_bytes(semantic)).hexdigest()
    variant = {
        "build_variant_id": f"PFB-{digest[:24]}",
        **semantic,
        "variant_digest": digest,
    }
    return variant, ToolchainIdentity(
        "solc",
        "0.0.0",
        compiler_digest,
    )


def _capabilities(
    registry: LoadedProgramFactsProviderRegistry,
) -> tuple[CapabilityRequest, ...]:
    provider = next(
        (
            row
            for row in registry.providers
            if row.get("provider_id") == EVM_PROVIDER_ID
        ),
        None,
    )
    if not isinstance(provider, Mapping):
        _fail("installed Program Facts EVM provider is absent")
    maximum_by_id = {
        str(row["capability_id"]): str(row["maximum_precision"])
        for row in provider.get("capabilities", ())
        if isinstance(row, Mapping)
    }
    if tuple(sorted(maximum_by_id)) != EVM_CAPABILITY_IDS:
        _fail("installed Program Facts EVM capability denominator drift")
    return tuple(
        CapabilityRequest(identity, maximum_by_id[identity])
        for identity in EVM_CAPABILITY_IDS
    )


def _audit_snapshot_projection(
    audit_snapshot: Mapping[str, Any],
) -> dict[str, str]:
    try:
        components = audit_snapshot["components"]
        return {
            "snapshot_digest": str(audit_snapshot["snapshot_digest"]),
            "source_scope_digest": str(
                components["source_scope"]["digest"]
            ),
            "audit_config_digest": str(
                components["audit_config"]["digest"]
            ),
            "methodology_digest": str(
                components["methodology"]["digest"]
            ),
            "toolchain_digest": str(
                components["toolchain"]["digest"]
            ),
        }
    except (KeyError, TypeError) as exc:
        _fail("Program Facts audit snapshot projection is malformed", exc)


def _bake_phase_io_projection(
    *,
    scratchpad: Path,
    contract: PhaseIOContract,
    launch: LaunchSpec,
) -> dict[str, str]:
    unit = _stored_unit(scratchpad, contract)
    if not isinstance(unit, Mapping):
        _fail("Program Facts bake PhaseIO arm is absent")
    input_set_digest = str(unit.get("input_set_digest") or "")
    if re.fullmatch(r"[0-9a-f]{64}", input_set_digest) is None:
        _fail("Program Facts bake input-set digest is malformed")
    return {
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "input_set_digest": input_set_digest,
        "work_unit_key": contract.key,
        "ledger_binding_state": "PRECOMMIT",
        "ledger_record_digest": "",
    }


def ensure_program_facts_stage2_emit_only(
    *,
    config: Mapping[str, Any],
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    audit_snapshot: Mapping[str, Any],
    fault_injector: _FaultInjector | None = None,
) -> ProgramFactsDriverOutcome:
    """Ensure the exact EVM emit-only bundle before legacy recon starts."""

    pipeline, _mode, ecosystem, _backend = _dimensions(config)
    if ecosystem != "evm" or pipeline != "sc":
        return ProgramFactsDriverOutcome(
            state="NOOP_UNSUPPORTED_ECOSYSTEM",
            valid=True,
            reused=False,
        )
    root = Path(scratchpad)
    project = Path(project_root)
    source_config = _snapshot_visible_config(config)
    try:
        # Freeze target/source authority before any integration publication.
        # Runtime-private driver fields are excluded by the same visibility
        # boundary as the canonical audit snapshot, while build-resolution
        # fields consumed by that snapshot remain exact inputs.
        snapshot_authority = (
            capture_program_facts_audit_snapshot_authority(
                audit_snapshot,
                config=source_config,
            )
        )
        captured_source = build_program_facts_source_manifest(
            source_config,
            audit_snapshot,
            compiled_source_paths=None,
        )
        source_authority = replay_program_facts_source_manifest(
            captured_source.canonical_bytes,
            expected_snapshot_digest=str(
                audit_snapshot["snapshot_digest"]
            ),
            expected_source_scope_digest=str(
                audit_snapshot["components"]["source_scope"]["digest"]
            ),
            source_bytes_by_id=captured_source.source_bytes_by_id,
            excluded_source_bytes_by_identity=(
                captured_source.excluded_source_bytes_by_identity
            ),
            capture_capability=captured_source.capture_capability,
        )
        source_manifest = strict_json_loads(
            canonical_file_bytes(
                source_authority.record["source_manifest"]
            ),
            require_final_lf=True,
            require_canonical=True,
        )
    except Exception as exc:
        try:
            current = build_audit_snapshot(
                source_config,
                Path(__file__).resolve().parents[1],
            )
            prior_components = audit_snapshot.get("components", {})
            current_components = current.get("components", {})
            drift = tuple(
                name
                for name in (
                    "source_scope",
                    "audit_config",
                    "methodology",
                    "toolchain",
                )
                if (
                    not isinstance(prior_components, Mapping)
                    or not isinstance(current_components, Mapping)
                    or prior_components.get(name) != current_components.get(name)
                )
            )
        except Exception:
            drift = ("UNRESOLVED",)
        cause = f"{type(exc).__name__}: {exc}".strip()
        _fail(
            "Program Facts source snapshot capture failed; live drift: "
            + (",".join(drift) or "NONE")
            + "; cause: "
            + cause,
            exc,
        )
    if not isinstance(source_manifest, Mapping):
        _fail("Program Facts source manifest root is malformed")

    capture_raw = _checkpoint_capture_bytes(
        run_id=run_id,
        audit_snapshot=audit_snapshot,
    )

    checkpoint_contract, checkpoint_launch = _resolve(
        config=config,
        work_unit_id=_CHECKPOINT_CAPTURE_UNIT,
        exact_inputs=(),
        exact_outputs=(PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,),
    )
    _publish_phaseio_outputs(
        scratchpad=root,
        project_root=project,
        contract=checkpoint_contract,
        launch=checkpoint_launch,
        run_id=run_id,
        outputs={PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH: capture_raw},
        fault_injector=fault_injector,
    )

    try:
        methodology_authority = (
            capture_installed_program_facts_methodology_authority(
                capture_raw
            )
        )
        registry = load_program_facts_provider_registry(
            installed_authority=methodology_authority
        )
    except Exception as exc:
        _fail("installed Program Facts methodology capture failed", exc)
    methodology_outputs = registry.phase_io_input_bytes
    methodology_contract, methodology_launch = _resolve(
        config=config,
        work_unit_id=_METHODOLOGY_CAPTURE_UNIT,
        exact_inputs=(PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,),
        exact_outputs=PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
    )
    _publish_phaseio_outputs(
        scratchpad=root,
        project_root=project,
        contract=methodology_contract,
        launch=methodology_launch,
        run_id=run_id,
        outputs=methodology_outputs,
        fault_injector=fault_injector,
    )

    variant, compiler = _unavailable_build_variant()
    context = ProviderContext(
        audit_run_id=run_id,
        methodology_authority_digest=(
            registry.methodology_capture_digest
        ),
        snapshot_digest=str(audit_snapshot["snapshot_digest"]),
        source_scope_digest=str(
            audit_snapshot["components"]["source_scope"]["digest"]
        ),
        source_manifest_digest=source_authority.manifest_digest,
        source_authority_digest=source_authority.authority_digest,
        ecosystem="evm",
        languages=("solidity",),
        build_variant_ids=(str(variant["build_variant_id"]),),
        capability_requests=_capabilities(registry),
        toolchains=(compiler,),
        platform=_portable_platform(),
        environment=(),
        working_directory_root_id="root-0",
    )
    bake_inputs = (
        PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH,
        *PROGRAM_FACTS_METHODOLOGY_INPUT_PATHS,
    )
    bake_contract, bake_launch = _resolve(
        config=config,
        work_unit_id=_BAKE_UNIT,
        exact_inputs=bake_inputs,
        exact_outputs=PROGRAM_FACTS_SIDECAR_PATHS,
    )
    bake_was_committed = _arm_or_replay(
        scratchpad=root,
        project_root=project,
        contract=bake_contract,
        launch=bake_launch,
        run_id=run_id,
    )
    phase_io = _bake_phase_io_projection(
        scratchpad=root,
        contract=bake_contract,
        launch=bake_launch,
    )
    plan_inputs = {
        "context": context,
        "source_manifest": source_manifest,
        "source_bytes_by_id": captured_source.source_bytes_by_id,
        "build_variants": (variant,),
        "audit_snapshot": _audit_snapshot_projection(audit_snapshot),
        "phase_io": phase_io,
        "source_manifest_authority": source_authority,
        "audit_snapshot_authority": snapshot_authority,
        "provider_registry": registry,
        "tool_authority": load_installed_evm_tool_authority(),
        "source_project_root": project,
        "source_config": source_config,
    }
    existing_sidecars: dict[str, bytes] | None = None
    expected_reuse_key: str | None = None
    if bake_was_committed:
        try:
            existing_sidecars = {
                identity: rooted_path_io.read_bytes(
                    root / identity,
                    label=f"Program Facts committed {identity}",
                    require_single_link=False,
                )
                for identity in PROGRAM_FACTS_SIDECAR_PATHS
            }
            receipt = strict_json_loads(
                existing_sidecars[
                    "mechanical_program_facts_receipt.v1.json"
                ],
                require_final_lf=True,
                require_canonical=True,
            )
            expected_reuse_key = str(receipt["reuse_key"])
        except Exception as exc:
            _fail("committed Program Facts resume bytes are invalid", exc)
    try:
        baked = ensure_program_facts_bake(
            existing_sidecars=existing_sidecars,
            expected_reuse_key=expected_reuse_key,
            **plan_inputs,
        )
    except Exception as exc:
        _fail("Program Facts emit-only bake failed", exc)
    if not isinstance(baked, ProgramFactsBakeResult):
        if not baked.reusable or baked.bundle is None:
            _fail("Program Facts committed resume decision rejected")
        staged_sidecars = existing_sidecars
    else:
        staged_sidecars = dict(baked.sidecars)
    if staged_sidecars is None:
        _fail("Program Facts staged sidecars are absent")

    _publish_phaseio_outputs(
        scratchpad=root,
        project_root=project,
        contract=bake_contract,
        launch=bake_launch,
        run_id=run_id,
        outputs=staged_sidecars,
        fault_injector=fault_injector,
    )
    loaded = load_bound_program_facts(
        scratchpad=root,
        project_root=project,
        contract=bake_contract,
        launch=bake_launch,
        run_id=run_id,
        context=context,
        source_bytes_by_id=captured_source.source_bytes_by_id,
        source_manifest_authority=source_authority,
        audit_snapshot_authority=snapshot_authority,
        provider_registry=registry,
        source_project_root=project,
        source_config=source_config,
    )
    if not loaded.valid or not loaded.reusable or loaded.bundle is None:
        _fail(
            "Program Facts committed loader replay failed: "
            + ", ".join(loaded.reason_codes)
        )
    return ProgramFactsDriverOutcome(
        state=loaded.state,
        valid=True,
        reused=bake_was_committed,
        consumer_activation=False,
    )


__all__ = [
    "PROGRAM_FACTS_CHECKPOINT_CAPTURE_PATH",
    "ProgramFactsDriverIntegrationError",
    "ProgramFactsDriverOutcome",
    "ensure_program_facts_stage2_emit_only",
]
