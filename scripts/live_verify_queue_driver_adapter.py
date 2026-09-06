"""Driver-owned preparation and execution of the live verify-queue cutover.

The T0--T9 transaction intentionally accepts only already-resolved authority.
This module is the single narrow adapter from mutable driver state to that
declarative transaction.  Callers cannot inject an upstream denominator,
runtime digest, context selection, plan, or semantic executor.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

from artifact_ledger import read_artifact_ledger
import live_verify_queue_methodology_projection as _methodology_projection
import live_verify_queue_prearm_inputs as _prearm
import p0af_v2_queue_adapter as _p0af
from preverify_frozen_projection import (
    prepare_preverify_frozen_projection,
)
from preverify_chain_pair_projection import (
    prepare_preverify_chain_pair_projection,
)
from plamen_types import (
    L1_VERIFY_SHARD_MANIFESTS,
    SC_VERIFY_SHARD_MANIFESTS,
)
from production_source_scope import is_production_source_path
from verify_queue_transaction import (
    execute_live_verify_queue_transaction,
    live_verify_queue_base_upstream_roster,
    live_verify_queue_required_upstream_roster,
    resolve_live_verify_queue_transaction_plan,
    validate_live_verify_queue_publication,
)


SCHEMA_VERSION = "plamen.live_verify_queue_driver_cutover.v1"
PLAN_FAILPOINT = "after_live_adapter_plan_resolved"
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SOURCE_SUFFIXES = frozenset({
    ".sol", ".vy", ".rs", ".move", ".go", ".proto", ".daml",
})
_PROJECT_SKIP_DIRECTORIES = frozenset({
    ".git",
    ".scratchpad",
    ".plamen",
    ".pytest_cache",
    "__pycache__",
    "artifacts",
    "build",
    "cache",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
})
_GRAPH_ARTIFACT_NAMES = (
    "caller_map.md",
    "callee_map.md",
    "callees_map.md",
    "state_access_map.md",
    "storage_access_map.md",
    "authority_graph.json",
    "reference_graph.json",
    "typed_cpg.json",
    "typed_cpg_manifest.json",
)
_GRAPH_GLOBS = ("call_graph*.md",)
_METHODOLOGY_DIRECTORIES = (
    "agents",
    "prompts",
    "rules",
    "skills",
    "verification_policy",
)
_MAX_CONTEXT_FILES = 20_000
_MAX_CONTEXT_BYTES = 1024 * 1024 * 1024


class LiveVerifyQueueDriverAdapterError(RuntimeError):
    """Raised when the live queue cannot be armed from current-run authority."""


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


def _normal(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_relative(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    pure = PurePosixPath(text)
    if (
        not text
        or pure.is_absolute()
        or text.startswith("/")
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise LiveVerifyQueueDriverAdapterError(
            f"unsafe live adapter relative path: {value!r}"
        )
    return pure.as_posix()


def _resolved_dimensions(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
) -> dict[str, str]:
    pipeline = _normal(config.get("pipeline"))
    if pipeline not in {"sc", "l1"}:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter pipeline must be sc or l1"
        )
    mode = _normal(config.get("mode"))
    ecosystem = _normal(
        config.get("ecosystem") or config.get("language")
    )
    backend = _normal(
        config.get("backend") or config.get("cli_backend") or "claude"
    )
    phase_name = "sc_verify_queue" if pipeline == "sc" else "verify_queue"
    configured_phase = _normal(config.get("phase_name"))
    if configured_phase and configured_phase != phase_name:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter phase/runtime tuple is inconsistent"
        )
    run = str(run_id or "").strip()
    if (
        not mode
        or not ecosystem
        or backend not in {"claude", "codex"}
        or not run
    ):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter mode/ecosystem/backend/run tuple is invalid"
        )

    root = Path(scratchpad).resolve()
    project = Path(project_root).resolve()
    if not root.is_dir() or not project.is_dir():
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter project or scratchpad directory is absent"
        )
    try:
        root.relative_to(project)
    except ValueError as exc:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter scratchpad must be inside project_root"
        ) from exc
    configured_project = str(config.get("project_root") or "").strip()
    if configured_project and Path(configured_project).resolve() != project:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter project_root differs from runtime config"
        )
    configured_scratch = str(config.get("scratchpad") or "").strip()
    if configured_scratch and Path(configured_scratch).resolve() != root:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter scratchpad differs from runtime config"
        )

    snapshot = config.get("_audit_snapshot") or config.get("audit_snapshot")
    if not isinstance(snapshot, Mapping):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter audit snapshot authority is absent"
        )
    snapshot_digest = _normal(snapshot.get("snapshot_digest"))
    if not _HEX64.fullmatch(snapshot_digest):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter audit snapshot digest is invalid"
        )
    return {
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
        "run_id": run,
        "audit_snapshot_digest": snapshot_digest,
        "project_root": str(project),
        "scratchpad": str(root),
    }


def _adapter_config(
    config: Mapping[str, Any],
    dimensions: Mapping[str, str],
) -> dict[str, Any]:
    result = dict(config)
    result.update({
        "pipeline": dimensions["pipeline"],
        "mode": dimensions["mode"],
        "language": dimensions["ecosystem"],
        "ecosystem": dimensions["ecosystem"],
        "cli_backend": dimensions["backend"],
        "backend": dimensions["backend"],
        "phase_name": dimensions["phase_name"],
        "project_root": dimensions["project_root"],
        "scratchpad": dimensions["scratchpad"],
        "_run_id": dimensions["run_id"],
    })
    return result


def _iter_regular_files(
    root: Path,
    *,
    include: Callable[[Path, str], bool],
) -> Iterable[tuple[str, Path]]:
    if not root.is_dir():
        return
    for directory, names, files in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        retained: list[str] = []
        for name in sorted(names):
            child = directory_path / name
            if (
                name in {"__pycache__", ".git", ".pytest_cache"}
                or child.is_symlink()
                or (
                    hasattr(child, "is_junction")
                    and child.is_junction()
                )
            ):
                continue
            retained.append(name)
        names[:] = retained
        for name in sorted(files):
            path = directory_path / name
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if include(path, relative):
                yield relative, path


def _digest_rows(
    entries: Iterable[tuple[str, Path]],
    *,
    identity_prefix: str,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for relative, path in sorted(entries, key=lambda row: row[0]):
        raw = path.read_bytes()
        rows.append({
            "identity": identity_prefix + relative,
            "sha256": _sha(raw),
            "size": len(raw),
        })
    if not rows:
        raise LiveVerifyQueueDriverAdapterError(
            f"live adapter {identity_prefix.rstrip(':')} denominator is empty"
        )
    return {"rows": rows, "digest": _stable_digest(rows)}


def _trusted_code_evidence(implementation_root: Path) -> dict[str, Any]:
    scripts = implementation_root / "scripts"
    return _digest_rows(
        _iter_regular_files(
            scripts,
            include=lambda path, relative: (
                path.suffix.lower() == ".py"
                and not path.name.startswith("test_")
            ),
        ),
        identity_prefix="implementation:scripts/",
    )


def _methodology_evidence(implementation_root: Path) -> dict[str, Any]:
    entries: list[tuple[str, Path]] = []
    for directory in _METHODOLOGY_DIRECTORIES:
        base = implementation_root / directory
        entries.extend(
            (f"{directory}/{relative}", path)
            for relative, path in _iter_regular_files(
                base, include=lambda _path, _relative: True
            )
        )
    return _digest_rows(
        entries,
        identity_prefix="implementation:",
    )


def _producer_ledger_evidence(
    *,
    scratchpad: Path,
    roster: Sequence[str],
    presence: Mapping[str, Any],
) -> dict[str, Any]:
    ledger = read_artifact_ledger(scratchpad)
    bindings = ledger.get("artifact_bindings")
    work_units = ledger.get("work_units")
    if not isinstance(bindings, Mapping) or not isinstance(work_units, Mapping):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter producer ledger is malformed"
        )
    authority = presence.get("authority")
    entries = authority.get("entries") if isinstance(authority, Mapping) else None
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter presence authority entries are absent"
        )
    presence_rows = {
        str(row.get("identity") or ""): row
        for row in entries
        if isinstance(row, Mapping)
    }
    expected = {"scratchpad:" + _safe_relative(path) for path in roster}
    if set(presence_rows) != expected:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter producer/presence roster denominator drift"
        )

    rows: list[dict[str, Any]] = []
    for identity in sorted(expected):
        presence_row = presence_rows[identity]
        state = str(presence_row.get("state") or "")
        if state in {
            "ABSENT",
            "PRESENT_UNAUTHORIZED_QUARANTINED",
        }:
            marker = _canonical_bytes({
                "identity": identity,
                "state": state,
                "issues": list(presence_row.get("issues") or ()),
                "presence_authority_digest": authority.get(
                    "authority_digest"
                ),
            })
            rows.append({
                "identity": identity,
                "state": state,
                "sha256": _sha(marker),
                "size": 0,
                "producer_binding_digest": None,
            })
            continue
        if state not in {"PRESENT", "PRESENT_AUTHORIZED"}:
            raise LiveVerifyQueueDriverAdapterError(
                f"live adapter presence state is invalid for {identity}"
            )
        relative = identity.split(":", 1)[1]
        path = scratchpad / relative
        if not path.is_file() or path.is_symlink():
            raise LiveVerifyQueueDriverAdapterError(
                f"live adapter present producer artifact is unavailable: {relative}"
            )
        raw = path.read_bytes()
        binding = bindings.get(identity)
        if not isinstance(binding, Mapping):
            raise LiveVerifyQueueDriverAdapterError(
                f"live adapter producer binding is absent: {identity}"
            )
        producer_key = str(binding.get("owner_key") or "")
        producer = work_units.get(producer_key)
        if not producer_key or not isinstance(producer, Mapping):
            raise LiveVerifyQueueDriverAdapterError(
                f"live adapter producer work unit is absent: {identity}"
            )
        binding_view = {
            key: binding.get(key)
            for key in (
                "identity",
                "owner_key",
                "writer",
                "run_id",
                "contract_digest",
                "launch_digest",
                "sha256",
                "size",
                "status",
                "schema_version",
                "artifact_class",
                "write_mode",
            )
        }
        rows.append({
            "identity": identity,
            "state": state,
            "sha256": _sha(raw),
            "size": len(raw),
            "producer_work_unit_key": producer_key,
            "producer_binding_digest": _stable_digest(binding_view),
            "producer_run_id": str(binding.get("run_id") or ""),
            "producer_contract_digest": str(
                binding.get("contract_digest") or ""
            ),
            "producer_launch_digest": str(
                binding.get("launch_digest") or ""
            ),
            "producer_execution_state": str(
                producer.get("execution_state") or ""
            ),
        })
    return {"rows": rows, "digest": _stable_digest(rows)}


def _runtime_authority_and_evidence(
    *,
    scratchpad: Path,
    dimensions: Mapping[str, str],
    roster: Sequence[str],
    presence: Mapping[str, Any],
) -> tuple[dict[str, str], dict[str, Any]]:
    implementation_root = Path(__file__).resolve().parent.parent
    code = _trusted_code_evidence(implementation_root)
    producer = _producer_ledger_evidence(
        scratchpad=scratchpad,
        roster=roster,
        presence=presence,
    )
    methodology = _methodology_evidence(implementation_root)
    audit = {
        "source": "config._audit_snapshot.snapshot_digest",
        "digest": dimensions["audit_snapshot_digest"],
    }
    authority = {
        "audit_snapshot_digest": dimensions["audit_snapshot_digest"],
        "trusted_queue_code_digest": code["digest"],
        "producer_ledger_digest": producer["digest"],
        "methodology_digest": methodology["digest"],
        "pipeline": dimensions["pipeline"],
        "mode": dimensions["mode"],
        "ecosystem": dimensions["ecosystem"],
        "backend": dimensions["backend"],
        "run_id": dimensions["run_id"],
    }
    evidence = {
        "audit_snapshot": audit,
        "trusted_queue_code": code,
        "producer_ledger": producer,
        "methodology": methodology,
    }
    return authority, evidence


def _project_file_candidates(project_root: Path) -> tuple[Path, ...]:
    candidates: list[Path] = []
    for directory, names, files in os.walk(project_root, followlinks=False):
        directory_path = Path(directory)
        retained: list[str] = []
        for name in sorted(names):
            child = directory_path / name
            if (
                name in _PROJECT_SKIP_DIRECTORIES
                or name.startswith(".scratchpad-")
                or name.startswith(".plamen-")
                or child.is_symlink()
                or (
                    hasattr(child, "is_junction")
                    and child.is_junction()
                )
            ):
                continue
            retained.append(name)
        names[:] = retained
        for name in sorted(files):
            path = directory_path / name
            if not path.is_file() or path.is_symlink():
                continue
            candidates.append(path)
            if len(candidates) > _MAX_CONTEXT_FILES:
                raise LiveVerifyQueueDriverAdapterError(
                    "live adapter project context exceeds the bounded file limit"
                )
    return tuple(candidates)


def _inventory_source_paths(
    project_root: Path,
    *,
    inventory_path: Path,
    records_path: Path,
) -> set[Path]:
    text_parts: list[str] = []
    if inventory_path.is_file():
        text_parts.append(
            inventory_path.read_text(encoding="utf-8", errors="replace")
        )
    if records_path.is_file():
        text_parts.append(
            records_path.read_text(encoding="utf-8", errors="replace")
        )
    text = "\n".join(text_parts).replace("\\", "/")
    result: set[Path] = set()
    for match in re.finditer(
        r"(?<![A-Za-z0-9_.-])"
        r"([A-Za-z0-9_@+.,()' -]+(?:/[A-Za-z0-9_@+.,()' -]+)+"
        r"\.(?:sol|vy|rs|move|go|proto|daml))"
        r"(?::(?:L)?\d+(?:-(?:L)?\d+)?)?",
        text,
        flags=re.IGNORECASE,
    ):
        token = match.group(1).strip()
        try:
            relative = _safe_relative(token)
        except LiveVerifyQueueDriverAdapterError:
            continue
        path = project_root.joinpath(*PurePosixPath(relative).parts)
        try:
            path.resolve().relative_to(project_root.resolve())
        except ValueError:
            continue
        if path.is_file() and not path.is_symlink():
            result.add(path)
    return result


def _inventory_scratchpad_artifacts(
    scratchpad: Path,
    *,
    inventory_path: Path,
) -> set[str]:
    if not inventory_path.is_file():
        return set()
    text = inventory_path.read_text(encoding="utf-8", errors="replace")
    result: set[str] = set()
    for match in re.finditer(
        r"(?im)^\s*\*{0,2}(?:Primary|Source)\s+Artifact\*{0,2}"
        r"\s*:\s*`?([^`\r\n]+)",
        text,
    ):
        value = match.group(1).strip()
        try:
            relative = _safe_relative(value)
        except LiveVerifyQueueDriverAdapterError:
            continue
        if (scratchpad / relative).is_file():
            result.add(relative)
    return result


def _frozen_context_sources(
    scratchpad: Path,
    frozen_projection: Mapping[str, Any],
) -> tuple[Path, Path, tuple[str, ...]]:
    """Resolve only receipt-bound physical aliases for context derivation."""

    if (
        not isinstance(frozen_projection, Mapping)
        or frozen_projection.get("schema_version")
        != "plamen.preverify_frozen_projection.v1"
        or frozen_projection.get("state") != "OUTPUT_COMMITTED"
    ):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter frozen context projection is not committed"
        )
    mapping = frozen_projection.get("logical_to_physical")
    required = frozen_projection.get("required_paths")
    if not isinstance(mapping, Mapping) or not isinstance(required, list):
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter frozen context projection is malformed"
        )
    required_set = {
        _safe_relative(value) for value in required
    }
    resolved: dict[str, Path] = {}
    for logical in ("findings_inventory.md", "finding_records.json"):
        relative = _safe_relative(mapping.get(logical))
        if relative not in required_set:
            raise LiveVerifyQueueDriverAdapterError(
                f"frozen context alias is outside required paths: {logical}"
            )
        path = scratchpad.joinpath(*PurePosixPath(relative).parts)
        if not path.is_file() or path.is_symlink():
            raise LiveVerifyQueueDriverAdapterError(
                f"frozen context alias is not a regular file: {relative}"
            )
        resolved[logical] = path
    receipt = _safe_relative(frozen_projection.get("receipt_path"))
    if receipt not in required_set:
        raise LiveVerifyQueueDriverAdapterError(
            "frozen context receipt is outside required paths"
        )
    return (
        resolved["findings_inventory.md"],
        resolved["finding_records.json"],
        tuple(sorted(required_set)),
    )


def _context_capture(
    *,
    scratchpad: Path,
    project_root: Path,
    frozen_projection: Mapping[str, Any],
) -> dict[str, Any]:
    registry = "methodology_registry.json"
    reachability = "methodology_reachability_manifest.json"
    for required in (registry, reachability):
        path = scratchpad / required
        if not path.is_file() or path.is_symlink():
            raise LiveVerifyQueueDriverAdapterError(
                f"live adapter required methodology context is absent: {required}"
            )

    inventory_path, records_path, frozen_inputs = (
        _frozen_context_sources(scratchpad, frozen_projection)
    )
    graph_artifacts = tuple(
        name
        for name in _GRAPH_ARTIFACT_NAMES
        if (scratchpad / name).is_file()
        and not (scratchpad / name).is_symlink()
    )
    scratch_artifacts = _inventory_scratchpad_artifacts(
        scratchpad,
        inventory_path=inventory_path,
    )
    project_files = _project_file_candidates(project_root)
    primary_paths = _inventory_source_paths(
        project_root,
        inventory_path=inventory_path,
        records_path=records_path,
    )
    recognized = {
        path
        for path in project_files
        if path.suffix.lower() in _SOURCE_SUFFIXES
        and is_production_source_path(path, project_root)
    }
    if primary_paths:
        primary_directories = {path.parent for path in primary_paths}
        primary_paths.update(
            path for path in recognized if path.parent in primary_directories
        )
    elif recognized:
        primary_paths = set(recognized)
    else:
        # Unknown/custom ecosystems still receive an honest bounded context
        # rather than a false-clean empty denominator.
        primary_paths = set(project_files)

    ordered_project: list[str] = []
    total_bytes = 0
    for path in sorted(
        primary_paths,
        key=lambda value: value.relative_to(project_root).as_posix(),
    ):
        size = path.stat().st_size
        total_bytes += size
        if total_bytes > _MAX_CONTEXT_BYTES:
            raise LiveVerifyQueueDriverAdapterError(
                "live adapter project context exceeds the bounded byte limit"
            )
        ordered_project.append(
            "project::" + path.relative_to(project_root).as_posix()
        )
    if not ordered_project:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter project context denominator is empty"
        )

    exact_inputs = tuple(sorted({
        *graph_artifacts,
        *scratch_artifacts,
        *frozen_inputs,
        registry,
        reachability,
        *ordered_project,
    }))
    sibling_directories = tuple(sorted({
        "project::" + str(
            PurePosixPath(value[len("project::"):]).parent
        )
        for value in ordered_project
        if str(PurePosixPath(value[len("project::"):]).parent) != "."
    }))
    return {
        "exact_inputs": exact_inputs,
        "graph_artifacts": graph_artifacts,
        "graph_globs": _GRAPH_GLOBS,
        "primary_artifacts": tuple(ordered_project),
        "project_sibling_directories": sibling_directories,
        "methodology_registry": registry,
        "methodology_reachability": reachability,
    }


def _validate_presence(
    *,
    scratchpad: Path,
    project_root: Path,
    dimensions: Mapping[str, str],
    presence: Mapping[str, Any],
) -> None:
    issues = _prearm.validate_prearm_presence_authority(
        scratchpad=scratchpad,
        project_root=project_root,
        pipeline=dimensions["pipeline"],
        mode=dimensions["mode"],
        ecosystem=dimensions["ecosystem"],
        backend=dimensions["backend"],
        phase_name=dimensions["phase_name"],
        run_id=dimensions["run_id"],
        authority_identity=(
            "scratchpad:" + _prearm.PRESENCE_AUTHORITY_FILE
        ),
        authority=presence.get("authority"),
    )
    if issues:
        raise LiveVerifyQueueDriverAdapterError(
            "live adapter prearm presence authority invalid: "
            + "; ".join(issues)
        )


def _replay_execution_projection(
    dimensions: Mapping[str, str],
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "plamen.live_verify_queue_execution.v1",
        "pipeline": dimensions["pipeline"],
        "mode": dimensions["mode"],
        "ecosystem": dimensions["ecosystem"],
        "backend": dimensions["backend"],
        "phase_name": dimensions["phase_name"],
        "run_id": dimensions["run_id"],
        "plan_digest": plan["plan_digest"],
        "state": "OUTPUT_COMMITTED",
        "safe_to_consume": True,
        "replayed": True,
    }


def run_live_verify_queue_driver_cutover(
    *,
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    run_id: str,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Prepare, execute, and validate the live queue transaction exactly once."""

    root = Path(scratchpad).resolve()
    project = Path(project_root).resolve()
    try:
        dimensions = _resolved_dimensions(
            scratchpad=root,
            project_root=project,
            config=config,
            run_id=run_id,
        )
        normalized_config = _adapter_config(config, dimensions)
        methodology_projection = (
            _methodology_projection
            .prepare_live_verify_queue_methodology_projection(
                scratchpad=root,
                project_root=project,
                config=normalized_config,
                run_id=dimensions["run_id"],
            )
        )
        chain_pair_projection = (
            prepare_preverify_chain_pair_projection(
                scratchpad=root,
                project_root=project,
                pipeline=dimensions["pipeline"],
                mode=dimensions["mode"],
                ecosystem=dimensions["ecosystem"],
                backend=dimensions["backend"],
                phase_name=dimensions["phase_name"],
                run_id=dimensions["run_id"],
            )
            if dimensions["pipeline"] == "sc"
            else None
        )
        frozen_projection = prepare_preverify_frozen_projection(
            scratchpad=root,
            project_root=project,
            pipeline=dimensions["pipeline"],
            mode=dimensions["mode"],
            ecosystem=dimensions["ecosystem"],
            backend=dimensions["backend"],
            phase_name=dimensions["phase_name"],
            run_id=dimensions["run_id"],
            chain_pair_projection=chain_pair_projection,
        )
        static_roster = live_verify_queue_base_upstream_roster(
            dimensions["pipeline"]
        )
        dynamic = _prearm.prepare_sc_prearm_dynamic_inputs(
            scratchpad=root,
            project_root=project,
            config=normalized_config,
            run_id=dimensions["run_id"],
        )
        effective_roster = tuple(sorted({
            *static_roster,
            *(
                str(path)
                for path in dynamic.get("t0_additional_inputs", ())
            ),
            *(
                str(path)
                for path in dynamic.get("dynamic_source_paths", ())
            ),
            *(
                str(path)
                for path in frozen_projection.get("required_paths", ())
            ),
            *(
                str(path)
                for path in (
                    chain_pair_projection or {}
                ).get("required_paths", ())
                if (
                    chain_pair_projection or {}
                ).get("state") == "OUTPUT_COMMITTED"
            ),
            str(methodology_projection["receipt_path"]),
        }))
        required_roster = {
            *live_verify_queue_required_upstream_roster(
                dimensions["pipeline"]
            ),
            *(
                str(path)
                for path in dynamic.get("t0_additional_inputs", ())
            ),
            *(
                str(path)
                for path in dynamic.get("dynamic_source_paths", ())
            ),
            *(
                str(path)
                for path in frozen_projection.get("required_paths", ())
            ),
            *(
                str(path)
                for path in (
                    chain_pair_projection or {}
                ).get("required_paths", ())
                if (
                    chain_pair_projection or {}
                ).get("state") == "OUTPUT_COMMITTED"
            ),
        }
        if (
            dimensions["pipeline"] == "sc"
            and dynamic.get("state") == "RESOLVED"
        ):
            required_roster.add(_p0af.CANDIDATE_FILE)
        presence = _prearm.prepare_prearm_presence_authority(
            scratchpad=root,
            project_root=project,
            config=normalized_config,
            run_id=dimensions["run_id"],
            roster=effective_roster,
            required_roster=tuple(sorted(required_roster)),
        )
        _validate_presence(
            scratchpad=root,
            project_root=project,
            dimensions=dimensions,
            presence=presence,
        )
        authority, evidence = _runtime_authority_and_evidence(
            scratchpad=root,
            dimensions=dimensions,
            roster=effective_roster,
            presence=presence,
        )
        context = _context_capture(
            scratchpad=root,
            project_root=project,
            frozen_projection=frozen_projection,
        )
        shard_source = (
            SC_VERIFY_SHARD_MANIFESTS
            if dimensions["pipeline"] == "sc"
            else L1_VERIFY_SHARD_MANIFESTS
        )
        shard_manifests = tuple(sorted(shard_source.values()))
        plan = resolve_live_verify_queue_transaction_plan(
            pipeline=dimensions["pipeline"],
            mode=dimensions["mode"],
            ecosystem=dimensions["ecosystem"],
            backend=dimensions["backend"],
            phase_name=dimensions["phase_name"],
            run_id=dimensions["run_id"],
            upstream_inputs=tuple(sorted({
                *effective_roster,
                _prearm.PRESENCE_AUTHORITY_FILE,
            })),
            runtime_authority=authority,
            shard_manifests=shard_manifests,
            context_capture=context,
            preverify_frozen_projection=frozen_projection,
            preverify_chain_pair_projection=chain_pair_projection,
            prearm_resolution=(
                dynamic if dimensions["pipeline"] == "sc" else None
            ),
            prearm_presence=presence,
        )
        if failpoint is not None:
            failpoint(PLAN_FAILPOINT)

        current_dimensions = _resolved_dimensions(
            scratchpad=root,
            project_root=project,
            config=config,
            run_id=run_id,
        )
        if current_dimensions != dimensions:
            raise LiveVerifyQueueDriverAdapterError(
                "live adapter runtime/snapshot/backend tuple drifted after plan"
            )
        _validate_presence(
            scratchpad=root,
            project_root=project,
            dimensions=dimensions,
            presence=presence,
        )
        current_authority, current_evidence = (
            _runtime_authority_and_evidence(
                scratchpad=root,
                dimensions=dimensions,
                roster=effective_roster,
                presence=presence,
            )
        )
        if current_authority != authority or current_evidence != evidence:
            raise LiveVerifyQueueDriverAdapterError(
                "live adapter runtime authority drifted after plan resolution"
            )
        if _context_capture(
            scratchpad=root,
            project_root=project,
            frozen_projection=frozen_projection,
        ) != context:
            raise LiveVerifyQueueDriverAdapterError(
                "live adapter context denominator drifted after plan resolution"
            )

        prior_validation = validate_live_verify_queue_publication(
            scratchpad=root,
            project_root=project,
            plan=plan,
            run_id=dimensions["run_id"],
        )
        if prior_validation.get("safe_to_consume") is True:
            execution = _replay_execution_projection(dimensions, plan)
            resume_state = "REPLAYED_COMMIT"
        else:
            execution = execute_live_verify_queue_transaction(
                scratchpad=root,
                project_root=project,
                plan=plan,
                run_id=dimensions["run_id"],
                failpoint=failpoint,
            )
            resume_state = "FRESH_COMMIT"
        validation = validate_live_verify_queue_publication(
            scratchpad=root,
            project_root=project,
            plan=plan,
            run_id=dimensions["run_id"],
        )
        validation = {
            **validation,
            "plan_digest": plan["plan_digest"],
        }
        safe = (
            execution.get("state") == "OUTPUT_COMMITTED"
            and execution.get("safe_to_consume") is True
            and validation.get("safe_to_consume") is True
        )
        if not safe:
            raise LiveVerifyQueueDriverAdapterError(
                "live adapter publication validation refused downstream use: "
                + "; ".join(map(str, validation.get("issues") or ()))
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "state": "OUTPUT_COMMITTED",
            "safe_to_consume": True,
            "pipeline": dimensions["pipeline"],
            "mode": dimensions["mode"],
            "ecosystem": dimensions["ecosystem"],
            "backend": dimensions["backend"],
            "phase_name": dimensions["phase_name"],
            "run_id": dimensions["run_id"],
            "runtime_authority": authority,
            "runtime_authority_evidence": evidence,
            "static_upstream_roster": list(static_roster),
            "effective_upstream_roster": list(effective_roster),
            "methodology_projection": methodology_projection,
            "preverify_frozen_projection": frozen_projection,
            "preverify_chain_pair_projection": chain_pair_projection,
            "dynamic_prearm": dynamic,
            "prearm_presence": presence,
            "context_capture": context,
            "plan": plan,
            "execution": execution,
            "publication_validation": validation,
            "resume_state": resume_state,
        }
    except LiveVerifyQueueDriverAdapterError:
        raise
    except Exception as exc:
        raise LiveVerifyQueueDriverAdapterError(
            "live verify-queue driver adapter failed before safe publication: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


__all__ = [
    "LiveVerifyQueueDriverAdapterError",
    "run_live_verify_queue_driver_cutover",
]
