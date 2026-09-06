"""Current-run PhaseIO projection of verification methodology authority.

The live verify-queue transaction consumes two compact JSON projections.  This
provider is their sole producer: it validates the repository-owned policy with
the repository-owned compiler, records every consulted byte, arms the exact
outputs before writing them, and makes reachability problems visible debt.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Mapping, Sequence

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


SCHEMA_VERSION = "plamen.live_verify_queue_methodology_projection.v1"
RECEIPT_SCHEMA = (
    "plamen.live_verify_queue_methodology_projection_receipt.v1"
)
REACHABILITY_PROJECTION_SCHEMA = (
    "plamen.live_methodology_reachability_projection.v1"
)
REGISTRY_SOURCE = (
    "verification_policy/verification_method_registry.v1.json"
)
REACHABILITY_SOURCE = (
    "verification_policy/methodology_reachability.v1.json"
)
REGISTRY_OUTPUT = "methodology_registry.json"
REACHABILITY_OUTPUT = "methodology_reachability_manifest.json"
RECEIPT_OUTPUT = "live_verify_queue_methodology_projection.receipt.json"
_OUTPUTS = (REGISTRY_OUTPUT, REACHABILITY_OUTPUT, RECEIPT_OUTPUT)
_ENGINE_FILES = (
    "scripts/live_verify_queue_methodology_projection.py",
    "scripts/verification_method_compiler.py",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_MAX_CONTROL_FILE_BYTES = 16 * 1024 * 1024


class LiveVerifyQueueMethodologyProjectionError(RuntimeError):
    """Methodology projection cannot obtain current-run exact authority."""


def _canonical_bytes(value: Any) -> bytes:
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


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _stable_digest(value: Any) -> str:
    return _sha(_canonical_bytes(value))


def _implementation_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _safe_relative(value: Any, *, field: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    relative = PurePosixPath(text)
    if (
        not text
        or relative.is_absolute()
        or re.match(r"^[A-Za-z]:", text)
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != text
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            f"{field} is not a safe canonical relative path: {value!r}"
        )
    return text


def _regular_path(root: Path, relative: str) -> Path:
    safe = _safe_relative(relative, field="methodology input")
    base = root.resolve()
    path = base.joinpath(*PurePosixPath(safe).parts)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(base)
    except (OSError, ValueError) as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            f"methodology input is absent or escapes implementation root: {safe}"
        ) from exc
    cursor = base
    for part in PurePosixPath(safe).parts:
        cursor = cursor / part
        if cursor.is_symlink() or (
            hasattr(cursor, "is_junction") and cursor.is_junction()
        ):
            raise LiveVerifyQueueMethodologyProjectionError(
                f"methodology input uses a symlink or junction: {safe}"
            )
    if not resolved.is_file():
        raise LiveVerifyQueueMethodologyProjectionError(
            f"methodology input is not a regular file: {safe}"
        )
    return resolved


def _stable_read(root: Path, relative: str) -> bytes:
    path = _regular_path(root, relative)
    try:
        before = path.stat()
        if before.st_size > _MAX_CONTROL_FILE_BYTES:
            raise LiveVerifyQueueMethodologyProjectionError(
                f"methodology control input is oversized: {relative}"
            )
        raw = path.read_bytes()
        after = path.stat()
    except OSError as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            f"methodology input cannot be read: {relative}"
        ) from exc
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or after.st_size != len(raw)
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            f"methodology source changed during stable read: {relative}"
        )
    return raw


def _json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            f"{label} is not strict JSON: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise LiveVerifyQueueMethodologyProjectionError(
            f"{label} must contain a JSON object"
        )
    return value


def _runtime_binding(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> dict[str, str]:
    root = Path(scratchpad).resolve()
    project = Path(project_root).resolve()
    try:
        root.relative_to(project)
    except ValueError as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology projection scratchpad must be inside project_root"
        ) from exc
    if not root.is_dir() or not project.is_dir():
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology projection project or scratchpad is absent"
        )
    configured_root = str(config.get("scratchpad") or "").strip()
    configured_project = str(config.get("project_root") or "").strip()
    if (
        configured_root
        and Path(configured_root).resolve() != root
    ) or (
        configured_project
        and Path(configured_project).resolve() != project
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology projection runtime root authority mismatch"
        )

    pipeline = str(config.get("pipeline") or "").strip().lower()
    mode = str(config.get("mode") or "").strip().lower()
    ecosystem = str(
        config.get("ecosystem") or config.get("language") or ""
    ).strip().lower()
    backend = str(
        config.get("backend") or config.get("cli_backend") or ""
    ).strip().lower()
    phase_name = str(config.get("phase_name") or "").strip().lower()
    expected_phase = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    run = str(run_id or "").strip()
    configured_run = str(config.get("_run_id") or "").strip()
    snapshot = config.get("_audit_snapshot") or config.get("audit_snapshot")
    snapshot_digest = (
        str(snapshot.get("snapshot_digest") or "").strip().lower()
        if isinstance(snapshot, Mapping)
        else ""
    )
    if (
        pipeline not in {"sc", "l1"}
        or not mode
        or not ecosystem
        or backend not in {"claude", "codex"}
        or phase_name != expected_phase
        or not run
        or (configured_run and configured_run != run)
        or not _HEX64.fullmatch(snapshot_digest)
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology projection run/snapshot/backend runtime authority "
            "is invalid or mismatched"
        )
    return {
        "audit_snapshot_digest": snapshot_digest,
        "backend": backend,
        "ecosystem": ecosystem,
        "mode": mode,
        "phase_name": phase_name,
        "pipeline": pipeline,
        "run_id": run,
    }


def _authority_row(
    implementation_root: Path,
    relative: str,
) -> dict[str, Any]:
    raw = _stable_read(implementation_root, relative)
    return {
        "identity": "implementation:" + relative,
        "sha256": _sha(raw),
        "size": len(raw),
    }


def _evaluation_paths(manifest: Mapping[str, Any]) -> tuple[str, ...]:
    scan_paths = manifest.get("scan_paths")
    entries = manifest.get("entries")
    if (
        not isinstance(scan_paths, list)
        or not isinstance(entries, list)
        or any(not isinstance(row, Mapping) for row in entries)
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology reachability manifest input denominator is malformed"
        )
    paths = {
        _safe_relative(value, field="reachability scan path")
        for value in scan_paths
    }
    for entry in entries:
        for field in ("consumer_path", "test_path"):
            value = entry.get(field)
            if isinstance(value, str) and value:
                paths.add(_safe_relative(
                    value, field=f"reachability {field}"
                ))
    paths.difference_update({REGISTRY_SOURCE, REACHABILITY_SOURCE})
    return tuple(sorted(paths))


def _load_compiler(implementation_root: Path):
    path = _regular_path(
        implementation_root, "scripts/verification_method_compiler.py"
    )
    raw = _stable_read(
        implementation_root, "scripts/verification_method_compiler.py"
    )
    module_name = "_plamen_bound_verification_method_compiler_" + _sha(raw)
    cached = sys.modules.get(module_name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology compiler cannot be loaded"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(module_name, None)
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology compiler engine failed to load"
        ) from exc
    return module


def _phaseio(
    binding: Mapping[str, str],
) -> tuple[PhaseIOContract, LaunchSpec]:
    owner = canonical_work_unit_key(
        binding["pipeline"],
        binding["mode"],
        binding["ecosystem"],
        binding["backend"],
        binding["phase_name"],
        "methodology_projection",
    )
    contract = PhaseIOContract(
        pipeline=binding["pipeline"],
        mode=binding["mode"],
        ecosystem=binding["ecosystem"],
        backend=binding["backend"],
        phase=binding["phase_name"],
        work_unit_id="methodology_projection",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=relative,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    RECEIPT_SCHEMA
                    if relative == RECEIPT_OUTPUT
                    else REACHABILITY_PROJECTION_SCHEMA
                    if relative == REACHABILITY_OUTPUT
                    else "plamen.verification_method_registry.v1"
                ),
                minimum_gate="CURRENT_RUN_PHASEIO_EXACT_BYTES",
                consumers=(
                    binding["phase_name"] + "/t0.live_upstream_authority",
                    binding["phase_name"] + "/t7.live_frozen_context_and_shard_plan",
                ),
            )
            for relative in _OUTPUTS
        ),
        immutable_inputs=(),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=binding["pipeline"],
        mode=binding["mode"],
        ecosystem=binding["ecosystem"],
        backend=binding["backend"],
        model="driver-methodology-projection-v1",
        timeout_s=300,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _expected_projection(
    implementation_root: Path,
    binding: Mapping[str, str],
) -> tuple[dict[str, bytes], dict[str, Any]]:
    registry_raw = _stable_read(implementation_root, REGISTRY_SOURCE)
    reachability_raw = _stable_read(
        implementation_root, REACHABILITY_SOURCE
    )
    registry = _json_object(
        registry_raw, label="verification method registry"
    )
    manifest = _json_object(
        reachability_raw, label="methodology reachability manifest"
    )
    source_rows = [
        {
            "identity": "implementation:" + REGISTRY_SOURCE,
            "sha256": _sha(registry_raw),
            "size": len(registry_raw),
        },
        {
            "identity": "implementation:" + REACHABILITY_SOURCE,
            "sha256": _sha(reachability_raw),
            "size": len(reachability_raw),
        },
    ]
    evaluation_rows = [
        _authority_row(implementation_root, relative)
        for relative in _evaluation_paths(manifest)
    ]
    engine_rows = [
        _authority_row(implementation_root, relative)
        for relative in _ENGINE_FILES
    ]
    compiler = _load_compiler(implementation_root)
    try:
        loaded_registry = compiler.load_verification_method_registry(
            implementation_root
        )
        evaluation = compiler.validate_methodology_reachability(
            implementation_root
        )
    except Exception as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology policy evaluation failed"
        ) from exc
    if loaded_registry != registry or not isinstance(evaluation, dict):
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology compiler/source projection mismatch"
        )
    issues = evaluation.get("issues")
    if not isinstance(issues, list):
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology reachability evaluation omitted issue debt"
        )
    state = (
        "COMMITTED_CLEAN"
        if not issues and evaluation.get("ok") is True
        else "COMMITTED_WITH_VISIBLE_DEBT"
    )
    methodology_rows = [*source_rows, *evaluation_rows]
    methodology_digest = _stable_digest(methodology_rows)
    reachability_unsigned = {
        "schema_version": REACHABILITY_PROJECTION_SCHEMA,
        "source_schema_version": str(
            manifest.get("schema_version") or ""
        ),
        "state": state,
        "safe_to_consume": True,
        "proof_authority": "NONE",
        "runtime_binding": dict(binding),
        "methodology_input_digest": methodology_digest,
        "evaluation": evaluation,
        "issue_count": len(issues),
    }
    reachability = {
        **reachability_unsigned,
        "projection_digest": _stable_digest(reachability_unsigned),
    }
    registry_output = _canonical_bytes(registry)
    reachability_output = _canonical_bytes(reachability)
    output_rows = [
        {
            "identity": "scratchpad:" + REGISTRY_OUTPUT,
            "sha256": _sha(registry_output),
            "size": len(registry_output),
        },
        {
            "identity": "scratchpad:" + REACHABILITY_OUTPUT,
            "sha256": _sha(reachability_output),
            "size": len(reachability_output),
        },
    ]
    engine = {
        "provider_id": "live_verify_queue_methodology_projection",
        "files": engine_rows,
        "digest": _stable_digest(engine_rows),
    }
    receipt_unsigned = {
        "schema_version": RECEIPT_SCHEMA,
        "state": state,
        "safe_to_consume": True,
        "proof_authority": "NONE",
        "runtime_binding": dict(binding),
        "source_authority": source_rows,
        "source_set_digest": _stable_digest(source_rows),
        "evaluation_input_authority": evaluation_rows,
        "evaluation_input_digest": _stable_digest(evaluation_rows),
        "methodology_input_digest": methodology_digest,
        "engine_authority": engine,
        "output_authority": output_rows,
        "reachability_issue_count": len(issues),
        "reachability_issue_codes": sorted({
            str(row.get("code") or "UNCLASSIFIED")
            for row in issues
            if isinstance(row, Mapping)
        }),
    }
    receipt = {
        **receipt_unsigned,
        "receipt_digest": _stable_digest(receipt_unsigned),
    }
    return {
        REGISTRY_OUTPUT: registry_output,
        REACHABILITY_OUTPUT: reachability_output,
        RECEIPT_OUTPUT: _canonical_bytes(receipt),
    }, receipt


def _existing_unit(
    scratchpad: Path,
    contract: PhaseIOContract,
) -> Mapping[str, Any] | None:
    try:
        ledger = read_artifact_ledger(scratchpad)
    except ArtifactLedgerError as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            f"methodology PhaseIO ledger is invalid: {exc}"
        ) from exc
    unit = ledger.get("work_units", {}).get(contract.key)
    return unit if isinstance(unit, Mapping) else None


def _assert_expected_outputs(
    scratchpad: Path,
    expected: Mapping[str, bytes],
    *,
    allow_missing: bool,
) -> None:
    for relative, raw in expected.items():
        path = scratchpad / relative
        if not path.exists():
            if allow_missing:
                continue
            raise LiveVerifyQueueMethodologyProjectionError(
                f"methodology output drift: missing {relative}"
            )
        if not path.is_file() or path.is_symlink():
            raise LiveVerifyQueueMethodologyProjectionError(
                f"methodology output authority is invalid: {relative}"
            )
        if path.read_bytes() != raw:
            raise LiveVerifyQueueMethodologyProjectionError(
                f"methodology output or receipt changed: {relative}"
            )


def _exclusive_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            f"foreign pre-existing methodology projection: {path.name}"
        ) from exc


def _result(
    binding: Mapping[str, str],
    contract: PhaseIOContract,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "state": receipt["state"],
        "safe_to_consume": True,
        "status_json_is_authority": False,
        "output_paths": [REGISTRY_OUTPUT, REACHABILITY_OUTPUT],
        "receipt_path": RECEIPT_OUTPUT,
        "receipt_digest": receipt["receipt_digest"],
        "phase_io_owner_key": contract.key,
        "runtime_binding": dict(binding),
    }


def prepare_live_verify_queue_methodology_projection(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> dict[str, Any]:
    """Create or exactly replay current-run methodology projections."""

    root = Path(scratchpad).resolve()
    project = Path(project_root).resolve()
    binding = _runtime_binding(
        scratchpad=root,
        project_root=project,
        config=config,
        run_id=run_id,
    )
    implementation = _implementation_root().resolve()
    expected, receipt = _expected_projection(implementation, binding)
    contract, launch = _phaseio(binding)
    existing_receipt_path = root / RECEIPT_OUTPUT
    if existing_receipt_path.is_file() and not existing_receipt_path.is_symlink():
        existing_receipt = _json_object(
            existing_receipt_path.read_bytes(),
            label="existing methodology projection receipt",
        )
        if existing_receipt.get("runtime_binding") != dict(binding):
            raise LiveVerifyQueueMethodologyProjectionError(
                "methodology runtime authority drift: run/snapshot/backend "
                "binding changed"
            )
    prior = _existing_unit(root, contract)

    if prior is not None and str(prior.get("run_id") or "") != run_id:
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology PhaseIO run authority conflict"
        )
    if prior is not None and str(
        prior.get("execution_state") or ""
    ) == "OUTPUT_COMMITTED":
        _assert_expected_outputs(root, expected, allow_missing=False)
        issues = [
            *validate_work_unit_inputs(
                root, project, contract, launch, run_id=run_id
            ),
            *validate_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=run_id,
                actor="DRIVER",
            ),
        ]
        if issues:
            raise LiveVerifyQueueMethodologyProjectionError(
                "methodology output PhaseIO authority drift: "
                + "; ".join(issues)
            )
        return _result(binding, contract, receipt)

    try:
        armed = record_work_unit_inputs(
            root, project, contract, launch, run_id=run_id
        )
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise LiveVerifyQueueMethodologyProjectionError(
            f"methodology PhaseIO pre-arm failed: {exc}"
        ) from exc
    if (
        armed.get("run_id") != run_id
        or armed.get("semantic_status") != "INPUTS_BOUND"
        or armed.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            "foreign or pre-existing methodology projection lacks clean "
            "current-run PhaseIO authority"
        )

    # A crash after pre-arm may leave an exact prefix of the three CREATE
    # outputs.  The current-run prestate receipt proves those paths were absent;
    # exact bytes are therefore safely resumable, while any mismatch is debt.
    _assert_expected_outputs(root, expected, allow_missing=True)
    created: list[Path] = []
    try:
        for relative in _OUTPUTS:
            path = root / relative
            if path.exists():
                continue
            _exclusive_write(path, expected[relative])
            created.append(path)
        committed = record_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
    except Exception:
        # Remove only bytes created by this invocation.  Exact remnants from a
        # prior process crash remain recoverable through the pre-arm receipt.
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    if (
        committed.get("execution_state") != "OUTPUT_COMMITTED"
        or committed.get("semantic_status") != "ACTIVE"
    ):
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology PhaseIO output commit was not authoritative"
        )
    issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    if issues:
        raise LiveVerifyQueueMethodologyProjectionError(
            "methodology output postimage authority invalid: "
            + "; ".join(issues)
        )
    return _result(binding, contract, receipt)


__all__ = [
    "LiveVerifyQueueMethodologyProjectionError",
    "prepare_live_verify_queue_methodology_projection",
]
