"""Read-only, transaction-scoped witness for P1-E runtime replay."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import evidence_capabilities
import execution_scope_runtime as runtime
import mechanical_successor_receipts
import rooted_path_io as rooted_io


MAX_INPUT_BYTES = 32 * 1024 * 1024


class ExecutionScopeWitnessError(ValueError):
    pass


@dataclass(frozen=True)
class ExecutionScopeRuntimeWitness:
    candidate_id: str
    assessment: Mapping[str, Any]
    read_set: Mapping[str, bytes]
    absent_identities: tuple[str, ...]
    namespace_members: Mapping[str, tuple[str, ...]]
    implementation_identities: Mapping[str, str]
    semantic_witnesses: Mapping[str, Mapping[str, Any]]


def _capture(path: Path, *, root: Path, identity: str) -> bytes:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ExecutionScopeWitnessError(f"witness escapes declared root: {identity}") from exc
    return rooted_io.read_bytes(
        path, label=f"execution-scope witness {identity}",
        require_single_link=True, max_bytes=MAX_INPUT_BYTES,
    )


def _implementation_digest(module: Any) -> str:
    path = Path(str(module.__file__))
    parent = rooted_io.checked_directory(
        path.parent, label=f"implementation root {module.__name__}"
    )
    return hashlib.sha256(rooted_io.read_bytes(
        path, label=f"implementation {module.__name__}",
        require_single_link=True, max_bytes=MAX_INPUT_BYTES,
    )).hexdigest()


def _domain(path: Path, *, scratchpad: Path, project: Path, build: Path,
            build_domain: str) -> str:
    resolved = path.resolve(strict=True)
    choices: list[tuple[str, Path]] = [("scratchpad", scratchpad), ("project", project)]
    if build != project:
        choices.append((build_domain, build))
    matches = [
        (name, resolved.relative_to(root).as_posix())
        for name, root in choices if resolved == root or root in resolved.parents
    ]
    if not matches:
        raise ExecutionScopeWitnessError(f"runtime input is outside declared roots: {path}")
    name, relative = sorted(matches, key=lambda row: len(row[1]))[0]
    return f"{name}:{relative}"


def _source(root: Path, candidate: str) -> Mapping[str, Any]:
    value, _raw = runtime._strict_object(
        root / f"verify_{candidate}{runtime.RUNTIME_SOURCE_SUFFIX}",
        "execution-scope runtime source",
    )
    return runtime._validate_runtime_source(value)


def _checkpoint_projection(root: Path) -> tuple[dict[str, str], bytes]:
    checkpoint, raw = runtime._strict_object(
        root / "_v2_checkpoint.json", "checkpoint"
    )
    snapshot, issues = runtime._snapshot_digest(root)
    project = runtime._project_root_from_checkpoint(root)
    if issues or snapshot is None or project is None:
        raise ExecutionScopeWitnessError("checkpoint runtime projection is invalid")
    # Only these fields are consumed by runtime replay. Phase progression and
    # unrelated checkpoint control state are deliberately not durable inputs.
    return {
        "source_snapshot_sha256": snapshot,
        "project_root": str(project),
    }, raw


def capture_execution_scope_runtime_witness(
    scratchpad: Path, candidate_id: str, *, project_root: Path, build_root: Path,
    build_domain: str | None = None,
) -> ExecutionScopeRuntimeWitness:
    root = rooted_io.checked_directory(scratchpad, label="execution-scope scratchpad")
    project = rooted_io.checked_directory(project_root, label="execution-scope project")
    build = rooted_io.checked_directory(build_root, label="execution-scope build root")
    build_domain = build_domain or f"build.{hashlib.sha256(candidate_id.encode('utf-8')).hexdigest()[:24]}"
    if re.fullmatch(r"build\.[a-z0-9]{24}", build_domain) is None:
        raise ExecutionScopeWitnessError("invalid candidate-qualified build domain")
    first = runtime.load_execution_scope_assessment(root, candidate_id)
    if first.get("assessment") is None:
        raise ExecutionScopeWitnessError("execution-scope replay is not valid")
    source = _source(root, candidate_id)
    checkpoint_projection, checkpoint_raw = _checkpoint_projection(root)
    if checkpoint_projection["project_root"] != str(project):
        raise ExecutionScopeWitnessError("checkpoint project root differs")
    if source.get("source_snapshot_sha256") != checkpoint_projection["source_snapshot_sha256"]:
        raise ExecutionScopeWitnessError("checkpoint snapshot differs from runtime source")
    if Path(str(source["build_root"])).resolve(strict=True) != build:
        raise ExecutionScopeWitnessError("runtime source build root differs")

    read_set: dict[str, bytes] = {}
    absent: set[str] = set()
    scratch_names = {
        "mechanical_verify_manifest.json",
        f"verify_{candidate_id}.md",
        f"verify_{candidate_id}{runtime.RUNTIME_SOURCE_SUFFIX}",
        f"verify_{candidate_id}{runtime.ASSESSMENT_SUFFIX}",
    }
    for field in ("successor_receipt_file", "execution_evidence_file", "semantic_source_file"):
        value = source.get(field)
        if value is not None:
            if not isinstance(value, str) or not value:
                raise ExecutionScopeWitnessError(f"invalid runtime source path: {field}")
            scratch_names.add(value)
    for inspected_name in (
        f"verify_{candidate_id}.mechanical_successor.receipt.json",
        f"verify_{candidate_id}{runtime.RICH_SOURCE_SUFFIX}",
    ):
        if inspected_name in scratch_names:
            continue
        if rooted_io.lexists(root / inspected_name):
            scratch_names.add(inspected_name)
        else:
            absent.add(f"scratchpad:{inspected_name}")

    for name in sorted(scratch_names):
        path = root / name
        identity = f"scratchpad:{name}"
        read_set[identity] = _capture(path, root=root, identity=identity)

    # The execution-evidence selector scans the complete JSON namespace;
    # capture every member so an extra candidate match cannot evade the witness.
    evidence_dir = root / "mechanical_execution_evidence"
    if rooted_io.lexists(evidence_dir):
        evidence_dir = rooted_io.checked_directory(
            evidence_dir, label="mechanical execution-evidence namespace",
        )
        evidence_members = tuple(path.name for path in sorted(evidence_dir.glob("*.json")))
    else:
        evidence_members = ()
        absent.add("scratchpad:mechanical_execution_evidence")
    if len({name.casefold() for name in evidence_members}) != len(evidence_members):
        raise ExecutionScopeWitnessError("execution-evidence namespace case collision")
    for path in (evidence_dir / name for name in evidence_members):
        identity = f"scratchpad:mechanical_execution_evidence/{path.name}"
        read_set[identity] = _capture(path, root=root, identity=identity)

    for name in runtime._BUILD_BINDING_FILES:
        path = build / name
        identity = ("project:" if build == project else f"{build_domain}:") + name
        if rooted_io.lexists(path):
            read_set[identity] = _capture(path, root=build, identity=identity)
        else:
            absent.add(identity)

    oracle = source.get("oracle_file")
    oracle_path = Path(oracle) if isinstance(oracle, str) and oracle else None
    # _resolve_oracle reads every resolvable candidate before deciding whether
    # cardinality is one. Capture present candidates even when the durable
    # outcome is ambiguity debt; absence is evidence only when lexically absent.
    reference = source.get("test_file_reference")
    oracle_candidates: list[tuple[str, Path, Path]] = []
    if isinstance(reference, str) and reference.strip():
        raw_reference = Path(reference)
        if raw_reference.is_absolute():
            try:
                identity = _domain(
                    raw_reference, scratchpad=root, project=project, build=build,
                    build_domain=build_domain,
                )
            except (ExecutionScopeWitnessError, OSError):
                if rooted_io.lexists(raw_reference):
                    raise
            else:
                domain = identity.split(":", 1)[0]
                base = root if domain == "scratchpad" else project if domain == "project" else build
                oracle_candidates.append((identity, base, raw_reference))
        else:
            for domain_name, domain_root in ((build_domain, build), ("project", project)):
                oracle_candidates.append((
                    f"{domain_name}:{raw_reference.as_posix()}",
                    domain_root, domain_root / raw_reference,
                ))
    for identity, domain_root, candidate in oracle_candidates:
        if rooted_io.lexists(candidate):
            read_set[identity] = _capture(
                candidate, root=domain_root, identity=identity,
            )
        else:
            absent.add(identity)
    if oracle_path is not None and not any(
        candidate.resolve(strict=False) == oracle_path.resolve(strict=True)
        for _identity, _root, candidate in oracle_candidates
    ):
        oracle_identity = _domain(
            oracle_path, scratchpad=root, project=project, build=build,
            build_domain=build_domain,
        )
        oracle_root = project if oracle_identity.startswith("project:") else build
        read_set[oracle_identity] = _capture(
            oracle_path, root=oracle_root, identity=oracle_identity,
        )

    implementations = {
        module.__name__: _implementation_digest(module)
        for module in (runtime, evidence_capabilities, mechanical_successor_receipts)
    }
    second = runtime.load_execution_scope_assessment(root, candidate_id)
    final_checkpoint_projection, final_checkpoint_raw = _checkpoint_projection(root)
    if (second != first or _source(root, candidate_id) != source
            or final_checkpoint_projection != checkpoint_projection
            or final_checkpoint_raw != checkpoint_raw):
        raise ExecutionScopeWitnessError("runtime replay changed during witness capture")
    for identity, raw in read_set.items():
        domain, relative = identity.split(":", 1)
        base = root if domain == "scratchpad" else project if domain == "project" else build
        if _capture(base / relative, root=base, identity=identity) != raw:
            raise ExecutionScopeWitnessError(f"runtime witness input drifted: {identity}")
    for identity in absent:
        domain, relative = identity.split(":", 1)
        base = root if domain == "scratchpad" else project if domain == "project" else build
        if rooted_io.lexists(base / relative):
            raise ExecutionScopeWitnessError(f"runtime witness absence drifted: {identity}")
    if tuple(path.name for path in sorted(evidence_dir.glob("*.json"))) != evidence_members:
        raise ExecutionScopeWitnessError("execution-evidence namespace drifted")
    return ExecutionScopeRuntimeWitness(
        candidate_id=candidate_id,
        assessment=MappingProxyType(dict(first["assessment"])),
        read_set=MappingProxyType(dict(sorted(read_set.items()))),
        absent_identities=tuple(sorted(absent)),
        namespace_members=MappingProxyType({
            "scratchpad:mechanical_execution_evidence": evidence_members,
        }),
        implementation_identities=MappingProxyType(implementations),
        semantic_witnesses=MappingProxyType({
            "scratchpad:_v2_checkpoint.json#runtime": MappingProxyType(
                checkpoint_projection
            ),
        }),
    )


__all__ = ["ExecutionScopeRuntimeWitness", "ExecutionScopeWitnessError", "capture_execution_scope_runtime_witness"]
