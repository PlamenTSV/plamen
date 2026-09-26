"""Frozen aggregate witness for read-only report-evidence runtime replay."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

import report_evidence_authority as evidence
import rooted_path_io as rooted_io
from execution_scope_runtime_witness import capture_execution_scope_runtime_witness


SCHEMA = "plamen.report-evidence-runtime-authority.v1"
MAX_BYTES = 32 * 1024 * 1024


class ReportEvidenceRuntimeWitnessError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _implementation_digest(module: Any) -> str:
    path = Path(str(module.__file__))
    parent = rooted_io.checked_directory(
        path.parent, label=f"implementation root {module.__name__}"
    )
    raw = rooted_io.read_bytes(
        path, label=f"implementation {module.__name__}",
        require_single_link=True, max_bytes=MAX_BYTES,
    )
    if path.resolve(strict=True).parent != parent:
        raise ReportEvidenceRuntimeWitnessError("implementation path escaped root")
    return hashlib.sha256(raw).hexdigest()


def _directory_identity(path: Path) -> list[int]:
    stat = os.stat(path, follow_symlinks=False)
    # Directory contents are intentionally mutable across transaction arm and
    # publication. Bind the directory object and ownership, not mutation clocks.
    return [stat.st_dev, stat.st_ino, stat.st_mode, stat.st_uid, stat.st_gid]


def _record(path: Path, *, root: Path, identity: str) -> tuple[dict[str, Any], bytes]:
    checked_root = rooted_io.checked_directory(root, label=f"witness root {identity}")
    try:
        path.relative_to(checked_root)
        resolved = path.resolve(strict=True)
        resolved.relative_to(checked_root)
    except (OSError, ValueError) as exc:
        raise ReportEvidenceRuntimeWitnessError(
            f"report runtime witness escapes its root: {identity}"
        ) from exc
    raw = rooted_io.read_bytes(path, label=f"report runtime witness {identity}",
                               require_single_link=True, max_bytes=MAX_BYTES)
    stat = os.stat(path, follow_symlinks=False)
    return ({"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
             "physical_identity": [stat.st_dev, stat.st_ino, stat.st_mode,
                                   stat.st_uid, stat.st_gid, stat.st_nlink,
                                   stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]}, raw)


def capture_report_evidence_runtime_authority(
    root: Path, *, project_root: Path,
) -> Mapping[str, Any]:
    scratch = rooted_io.checked_directory(root, label="report runtime scratchpad")
    project = rooted_io.checked_directory(project_root, label="report runtime project")
    initial_scratch_identity = _directory_identity(scratch)
    initial_project_identity = _directory_identity(project)
    # The caller has already authenticated the bundle and its producers. This
    # full replay is the admission boundary before following runtime-source
    # paths; the witness below only freezes that admitted runtime's freshness.
    first = evidence.validate_report_evidence_runtime(scratch)
    bundle = first["bundle"]
    # Nonempty records indirectly add report_records.json through every
    # evidence-source denominator. A canonical empty bundle has no record
    # rows, so retain this direct runtime input explicitly in both cases.
    names = {
        "report_records.json",
        "report_evidence_records.json",
        "report_evidence_projection.md",
    }
    source_manifest_dir = rooted_io.checked_directory(
        scratch / "body_manifests", label="body-manifest namespace"
    )
    typed_manifest_dir = rooted_io.checked_directory(
        scratch / "report_evidence_manifests",
        label="typed report-manifest namespace",
    )
    source_manifest_members = tuple(sorted(
        path.name for path in source_manifest_dir.glob("report_*.json")
    ))
    typed_manifest_members = tuple(sorted(
        path.name for path in typed_manifest_dir.glob("*.json")
    ))
    if (len({name.casefold() for name in source_manifest_members})
            != len(source_manifest_members)
            or len({name.casefold() for name in typed_manifest_members})
            != len(typed_manifest_members)):
        raise ReportEvidenceRuntimeWitnessError("report manifest namespace collision")
    names.update(f"body_manifests/{name}" for name in source_manifest_members)
    names.update(f"report_evidence_manifests/{name}" for name in typed_manifest_members)
    for row in bundle["records"]:
        names.update(source["artifact"] for source in row["evidence_sources"])

    raw_set: dict[str, bytes] = {}
    records: dict[str, Any] = {}
    for name in sorted(names):
        identity = f"scratchpad:{name}"
        records[identity], raw_set[identity] = _record(
            scratch / name, root=scratch, identity=identity,
        )

    candidate_ids: set[str] = set()
    absent: set[str] = set()
    namespaces: dict[str, tuple[str, ...]] = {
        "scratchpad:body_manifests/report_*.json": source_manifest_members,
        "scratchpad:report_evidence_manifests/*.json": typed_manifest_members,
    }
    implementations: dict[str, str] = {
        "report_evidence_authority": _implementation_digest(evidence)
    }
    semantic_witnesses: dict[str, Any] = {}
    build_roots: dict[str, Path] = {}
    build_candidates: dict[str, str] = {}
    initial_build_identities: dict[str, list[int]] = {}
    for row in bundle["records"]:
        source_names = {source["artifact"] for source in row["evidence_sources"]}
        for candidate in row["candidate_ids"]:
            if (f"verify_{candidate}.execution_scope_assessment.json" not in source_names):
                continue
            candidate_ids.add(candidate)
            execution_runtime = __import__("execution_scope_runtime")
            source, _source_raw = execution_runtime._strict_object(
                scratch / f"verify_{candidate}.execution_scope_runtime_source.json",
                "execution-scope runtime source",
            )
            source = execution_runtime._validate_runtime_source(source)
            build = Path(str(source.get("build_root") or "")).resolve(strict=True)
            build_domain = "build." + hashlib.sha256(
                candidate.encode("utf-8")
            ).hexdigest()[:24]
            prior_root = build_roots.get(build_domain)
            if prior_root is not None and prior_root != build:
                raise ReportEvidenceRuntimeWitnessError("build-domain collision")
            build_roots[build_domain] = build
            build_candidates[build_domain] = candidate
            initial_build_identities.setdefault(
                build_domain, _directory_identity(build)
            )
            witness = capture_execution_scope_runtime_witness(
                scratch, candidate, project_root=project, build_root=build,
                build_domain=build_domain,
            )
            for identity, raw in witness.read_set.items():
                if identity in raw_set and raw_set[identity] != raw:
                    raise ReportEvidenceRuntimeWitnessError("runtime witness byte conflict")
                raw_set[identity] = raw
                domain, relative = identity.split(":", 1)
                base = (scratch if domain == "scratchpad" else project
                        if domain == "project" else build_roots.get(domain))
                if base is None:
                    raise ReportEvidenceRuntimeWitnessError("unbound build witness domain")
                records[identity], observed = _record(base / relative, root=base,
                                                       identity=identity)
                if observed != raw:
                    raise ReportEvidenceRuntimeWitnessError("runtime witness drift")
            absent.update(witness.absent_identities)
            for key, members in witness.namespace_members.items():
                prior = namespaces.get(key)
                if prior is not None and prior != members:
                    raise ReportEvidenceRuntimeWitnessError("namespace witness conflict")
                namespaces[key] = members
            implementations.update(witness.implementation_identities)
            for key, value in witness.semantic_witnesses.items():
                prior = semantic_witnesses.get(key)
                projected = dict(value)
                if prior is not None and prior != projected:
                    raise ReportEvidenceRuntimeWitnessError("semantic witness conflict")
                semantic_witnesses[key] = projected

    second = evidence.validate_report_evidence_runtime(scratch)
    if second != first:
        raise ReportEvidenceRuntimeWitnessError("report runtime changed during capture")
    for identity, raw in raw_set.items():
        domain, relative = identity.split(":", 1)
        base = (scratch if domain == "scratchpad" else project
                if domain == "project" else build_roots.get(domain))
        if base is None:
            raise ReportEvidenceRuntimeWitnessError("unbound build witness domain")
        meta, observed = _record(base / relative, root=base, identity=identity)
        if observed != raw or meta != records[identity]:
            raise ReportEvidenceRuntimeWitnessError(f"report runtime input drifted: {identity}")
    for identity in absent:
        domain, relative = identity.split(":", 1)
        base = (scratch if domain == "scratchpad" else project
                if domain == "project" else build_roots.get(domain))
        if base is None:
            raise ReportEvidenceRuntimeWitnessError("unbound build absence domain")
        if rooted_io.lexists(base / relative):
            raise ReportEvidenceRuntimeWitnessError(
                f"report runtime absence drifted: {identity}"
            )
    current_namespaces = {
        "scratchpad:body_manifests/report_*.json": tuple(sorted(
            path.name for path in source_manifest_dir.glob("report_*.json")
        )),
        "scratchpad:report_evidence_manifests/*.json": tuple(sorted(
            path.name for path in typed_manifest_dir.glob("*.json")
        )),
        "scratchpad:mechanical_execution_evidence": tuple(sorted(
            path.name for path in (scratch / "mechanical_execution_evidence").glob("*.json")
        )),
    }
    for key, expected_members in namespaces.items():
        if current_namespaces.get(key) != expected_members:
            raise ReportEvidenceRuntimeWitnessError(
                f"report runtime namespace drifted: {key}"
            )
    current_implementations = {
        name: _implementation_digest(__import__(name))
        for name in implementations
    }
    if current_implementations != implementations:
        raise ReportEvidenceRuntimeWitnessError("runtime implementation changed")
    if (_directory_identity(scratch) != initial_scratch_identity
            or _directory_identity(project) != initial_project_identity
            or any(
                _directory_identity(build_roots[domain]) != physical
                for domain, physical in initial_build_identities.items()
            )):
        raise ReportEvidenceRuntimeWitnessError("runtime root identity changed")
    unsigned = {
        "schema": SCHEMA, "candidate_ids": sorted(candidate_ids),
        "root_identities": {
            "scratchpad": {
                "resolved_path": str(scratch),
                "physical_identity": initial_scratch_identity,
            },
            "project": {
                "resolved_path": str(project),
                "physical_identity": initial_project_identity,
            },
            "builds": {
                domain: {
                    "candidate_id": build_candidates[domain],
                    "resolved_path": str(build_roots[domain]),
                    "physical_identity": initial_build_identities[domain],
                }
                for domain in sorted(build_roots)
            },
        },
        "read_set": dict(sorted(records.items())),
        "absent_identities": sorted(absent),
        "namespace_members": {key: list(value) for key, value in sorted(namespaces.items())},
        "implementation_identities": dict(sorted(implementations.items())),
        "semantic_witnesses": dict(sorted(semantic_witnesses.items())),
        "runtime": first,
    }
    return {**unsigned, "authority_digest": hashlib.sha256(_canonical(unsigned)).hexdigest()}


def validate_report_evidence_runtime_authority(
    root: Path, *, project_root: Path, expected: Mapping[str, Any],
) -> Mapping[str, Any]:
    actual = capture_report_evidence_runtime_authority(
        root, project_root=project_root,
    )
    if dict(expected) != dict(actual):
        raise ReportEvidenceRuntimeWitnessError("report runtime authority changed")
    return actual


__all__ = ["ReportEvidenceRuntimeWitnessError", "capture_report_evidence_runtime_authority", "validate_report_evidence_runtime_authority"]
