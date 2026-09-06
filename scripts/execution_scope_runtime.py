"""Candidate-bound P1-E execution-scope runtime.

The mechanical verifier proves that one command ran and binds its immutable
successor.  That fact is intentionally narrower than proof of protocol harm
or a candidate-wide refutation.  This module materializes that narrow fact as
an authenticated ``EXECUTION`` capability and accepts richer semantic scope
only when an exact independently-authorized P1-E source record reconciles to
the same manifest, successor, command, oracle, output, source snapshot, and
candidate identity.

All outputs are deterministic derived sidecars.  Invalid or absent authority
retains the candidate and emits visible evidence debt; it never grants a
proof label, severity cap, exclusion, or deletion.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from evidence_capabilities import (
    EvidenceCapabilityError,
    assess_executed_poc_scope,
    issue_executed_poc_scope_assessment,
    validate_evidence_receipt,
    validate_executed_poc_scope_assessment,
)
from mechanical_successor_receipts import (
    MechanicalSuccessorError,
    MechanicalSuccessorReceipt,
    prepare_mechanical_successor,
)


RUNTIME_SOURCE_SCHEMA = "plamen.execution_scope_runtime_source.v1"
RUNTIME_DEBT_SCHEMA = "plamen.execution_scope_runtime_debt.v1"
ASSESSMENT_SUFFIX = ".execution_scope_assessment.json"
RUNTIME_SOURCE_SUFFIX = ".execution_scope_runtime_source.json"
RICH_SOURCE_SUFFIX = ".execution_scope_evidence.json"
RUNTIME_DEBT_FILE = "execution_scope_runtime_debt.json"
_MAX_JSON_BYTES = 32 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,255}$", re.ASCII)
_EXECUTED_STATUSES = frozenset({"PASS", "FAIL"})
_BUILD_BINDING_FILES = (
    "foundry.toml", "remappings.txt", "Cargo.toml", "Cargo.lock",
    "Move.toml", "go.mod", "go.sum", "daml.yaml",
)
_SOURCE_FIELDS = (
    "schema_version",
    "candidate_id",
    "verify_file",
    "verify_sha256",
    "source_snapshot_sha256",
    "build_root",
    "build_binding_sha256",
    "mechanical_manifest_file",
    "mechanical_manifest_sha256",
    "mechanical_result_sha256",
    "successor_receipt_file",
    "successor_receipt_sha256",
    "successor_receipt_digest",
    "execution_evidence_file",
    "execution_evidence_sha256",
    "execution_evidence_record_digest",
    "test_file_reference",
    "oracle_file",
    "oracle_sha256",
    "command_sha256",
    "output_sha256",
    "execution_status",
    "execution_result",
    "semantic_source_file",
    "semantic_source_sha256",
    "assessment_kind",
    "issues",
    "issuer_identity",
    "record_digest",
)


class ExecutionScopeRuntimeError(ValueError):
    """Runtime scope authority is absent, ambiguous, stale, or malformed."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExecutionScopeRuntimeError(f"non-canonical JSON value: {exc}") from exc


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return _digest_bytes(_canonical_bytes(value))


def _strict_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ExecutionScopeRuntimeError(f"{label} unavailable: {exc}") from exc
    if len(raw) > _MAX_JSON_BYTES:
        raise ExecutionScopeRuntimeError(f"{label} exceeds byte budget")

    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ExecutionScopeRuntimeError(
                    f"{label} contains duplicate JSON key {key!r}"
                )
            out[key] = value
        return out

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ExecutionScopeRuntimeError(
                    f"{label} contains non-finite number {token}"
                )
            ),
        )
    except ExecutionScopeRuntimeError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ExecutionScopeRuntimeError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ExecutionScopeRuntimeError(f"{label} must be an object")
    return value, raw


def _safe_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SAFE_ID.fullmatch(value) is None:
        raise ExecutionScopeRuntimeError(f"{label} is not a safe identity")
    return value


def _hex_or_none(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ExecutionScopeRuntimeError(f"{label} must be a SHA-256 digest or null")
    return value


def _canonical_entry(path: Path, label: str, *, may_be_absent: bool = False) -> None:
    try:
        matches = sorted(
            entry.name
            for entry in path.parent.iterdir()
            if entry.name.casefold() == path.name.casefold()
        )
    except OSError as exc:
        raise ExecutionScopeRuntimeError(
            f"cannot establish canonical {label} ownership: {exc}"
        ) from exc
    if may_be_absent and not matches:
        return
    if matches != [path.name]:
        raise ExecutionScopeRuntimeError(
            f"{label} has ambiguous/non-canonical case ownership: {matches!r}"
        )


def _atomic_derived_write(path: Path, payload: Mapping[str, Any]) -> None:
    _canonical_entry(path, path.name, may_be_absent=True)
    raw = _canonical_bytes(payload) + b"\n"
    if path.is_file() and path.read_bytes() == raw:
        return
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temp.open("wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def _assessment_path(root: Path, candidate_id: str) -> Path:
    return root / f"verify_{candidate_id}{ASSESSMENT_SUFFIX}"


def _runtime_source_path(root: Path, candidate_id: str) -> Path:
    return root / f"verify_{candidate_id}{RUNTIME_SOURCE_SUFFIX}"


def _rich_source_path(root: Path, candidate_id: str) -> Path:
    return root / f"verify_{candidate_id}{RICH_SOURCE_SUFFIX}"


def _snapshot_digest(root: Path) -> tuple[str | None, list[str]]:
    path = root / "_v2_checkpoint.json"
    if not path.is_file():
        return None, ["SOURCE_SNAPSHOT_AUTHORITY_MISSING"]
    try:
        checkpoint, _ = _strict_object(path, "checkpoint")
        snapshot = checkpoint.get("audit_snapshot")
        if not isinstance(snapshot, dict):
            raise ExecutionScopeRuntimeError("checkpoint audit_snapshot is missing")
        declared = snapshot.get("snapshot_digest")
        if not isinstance(declared, str) or _HEX64.fullmatch(declared) is None:
            raise ExecutionScopeRuntimeError("audit snapshot digest is invalid")
        unsigned = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
        if _digest(unsigned) != declared:
            raise ExecutionScopeRuntimeError("audit snapshot digest mismatch")
        return declared, []
    except ExecutionScopeRuntimeError as exc:
        return None, [f"SOURCE_SNAPSHOT_AUTHORITY_INVALID:{exc}"]


def _project_root_from_checkpoint(root: Path) -> Path | None:
    path = root / "_v2_checkpoint.json"
    if not path.is_file():
        return None
    try:
        checkpoint, _ = _strict_object(path, "checkpoint")
    except ExecutionScopeRuntimeError:
        return None
    config = checkpoint.get("config")
    if not isinstance(config, Mapping):
        return None
    raw = config.get("project_root")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        resolved = Path(raw).resolve()
    except OSError:
        return None
    return resolved if resolved.is_dir() else None


def _build_binding(build_root: Path) -> tuple[str | None, list[str]]:
    try:
        resolved = Path(build_root).resolve(strict=True)
    except OSError as exc:
        return None, [f"BUILD_ROOT_UNAVAILABLE:{exc}"]
    if not resolved.is_dir():
        return None, ["BUILD_ROOT_UNAVAILABLE:not a directory"]
    rows: list[dict[str, str]] = []
    for name in _BUILD_BINDING_FILES:
        path = resolved / name
        if path.is_file():
            try:
                rows.append({"file": name, "sha256": _digest_bytes(path.read_bytes())})
            except OSError as exc:
                return None, [f"BUILD_BINDING_UNREADABLE:{name}:{exc}"]
    if not rows:
        return None, ["BUILD_BINDING_MANIFEST_MISSING"]
    return _digest({"build_root": str(resolved), "manifests": rows}), []


def _manifest_row(root: Path, candidate_id: str) -> tuple[dict[str, Any], bytes]:
    path = root / "mechanical_verify_manifest.json"
    _canonical_entry(path, "mechanical manifest")
    manifest, raw = _strict_object(path, "mechanical manifest")
    if set(manifest) != {"generated_at", "counts", "results"}:
        raise ExecutionScopeRuntimeError("mechanical manifest schema mismatch")
    rows = manifest.get("results")
    if not isinstance(rows, list):
        raise ExecutionScopeRuntimeError("mechanical manifest results are invalid")
    identities: set[str] = set()
    counts: dict[str, int] = {}
    matches: list[dict[str, Any]] = []
    for index, item in enumerate(rows):
        if not isinstance(item, dict):
            raise ExecutionScopeRuntimeError(f"mechanical row {index} is invalid")
        fid = item.get("finding_id")
        verify_file = item.get("verify_file")
        status = item.get("status")
        if (
            not isinstance(fid, str) or not fid or fid != fid.strip()
            or verify_file != f"verify_{fid}.md"
            or not isinstance(status, str) or not status
        ):
            raise ExecutionScopeRuntimeError(f"mechanical row {index} identity is invalid")
        key = fid.casefold()
        if key in identities:
            raise ExecutionScopeRuntimeError(
                "mechanical manifest has duplicate/case-colliding identity"
            )
        identities.add(key)
        counts[status] = counts.get(status, 0) + 1
        if fid == candidate_id:
            matches.append(dict(item))
        elif key == candidate_id.casefold():
            raise ExecutionScopeRuntimeError("candidate identity has non-canonical case")
    if manifest.get("counts") != counts:
        raise ExecutionScopeRuntimeError("mechanical manifest counts mismatch")
    if len(matches) != 1:
        raise ExecutionScopeRuntimeError(
            "mechanical manifest lacks exactly one exact candidate row"
        )
    return matches[0], raw


def _validate_successor(
    root: Path, candidate_id: str, result: Mapping[str, Any]
) -> tuple[MechanicalSuccessorReceipt, bytes]:
    path = root / f"verify_{candidate_id}.mechanical_successor.receipt.json"
    _canonical_entry(path, "mechanical successor receipt")
    try:
        raw = path.read_bytes()
        receipt = MechanicalSuccessorReceipt.from_json(
            raw.decode("utf-8", errors="strict")
        )
        if raw != receipt.to_json().encode("utf-8"):
            raise ExecutionScopeRuntimeError("successor receipt bytes are non-canonical")
        prepared = prepare_mechanical_successor(
            root / f"verify_{candidate_id}.md",
            result,
            root / "mechanical_verify_manifest.json",
            run_identity=receipt.run_identity,
            driver_identity=receipt.driver_identity,
        )
        if prepared.receipt != receipt or prepared.receipt_bytes != raw:
            raise ExecutionScopeRuntimeError("successor receipt authority mismatch")
        if prepared.verify_path.read_bytes() != prepared.transformed_bytes:
            raise ExecutionScopeRuntimeError("current verify bytes are not the successor")
    except (OSError, UnicodeError, MechanicalSuccessorError) as exc:
        raise ExecutionScopeRuntimeError(f"successor authority invalid: {exc}") from exc
    return receipt, raw


def _stable_result(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "duration_s"}


def _execution_evidence(
    root: Path,
    candidate_id: str,
    manifest_raw: bytes,
    successor_raw: bytes,
    result: Mapping[str, Any],
) -> tuple[dict[str, Any], Path, bytes]:
    directory = root / "mechanical_execution_evidence"
    try:
        paths = sorted(directory.glob("*.json"))
    except OSError as exc:
        raise ExecutionScopeRuntimeError(f"execution evidence unavailable: {exc}") from exc
    matches: list[tuple[dict[str, Any], Path, bytes]] = []
    expected_fields = {
        "schema_version", "run_identity", "driver_identity", "executor_identity",
        "successor_identity", "executed_result", "authoritative_result_sha256",
        "mechanical_manifest_file", "mechanical_manifest_sha256",
        "successor_receipt_file", "successor_receipt_sha256", "record_digest",
    }
    for path in paths:
        try:
            _canonical_entry(path, "execution evidence")
            value, raw = _strict_object(path, "execution evidence")
        except ExecutionScopeRuntimeError:
            continue
        row = value.get("executed_result")
        if not isinstance(row, Mapping) or row.get("finding_id") != candidate_id:
            continue
        if set(value) != expected_fields:
            raise ExecutionScopeRuntimeError("execution evidence schema mismatch")
        if value.get("schema_version") != "plamen.mechanical_execution_evidence.v1":
            raise ExecutionScopeRuntimeError("execution evidence version mismatch")
        declared = value.get("record_digest")
        unsigned = {key: item for key, item in value.items() if key != "record_digest"}
        if not isinstance(declared, str) or declared != _digest(unsigned):
            raise ExecutionScopeRuntimeError("execution evidence digest mismatch")
        if path.name != f"{declared}.json":
            raise ExecutionScopeRuntimeError("execution evidence filename mismatch")
        if (
            value.get("mechanical_manifest_file") != "mechanical_verify_manifest.json"
            or value.get("mechanical_manifest_sha256") != _digest_bytes(manifest_raw)
            or value.get("successor_receipt_file")
            != f"verify_{candidate_id}.mechanical_successor.receipt.json"
            or value.get("successor_receipt_sha256") != _digest_bytes(successor_raw)
            or value.get("authoritative_result_sha256") != _digest(result)
            or _stable_result(row) != _stable_result(result)
        ):
            raise ExecutionScopeRuntimeError("execution evidence binding mismatch")
        matches.append((value, path, raw))
    if len(matches) != 1:
        raise ExecutionScopeRuntimeError(
            "exact execution evidence cardinality is not one"
        )
    return matches[0]


def _resolve_oracle(
    reference: Any, build_root: Path, project_root: Path | None
) -> tuple[Path | None, str | None, list[str]]:
    if not isinstance(reference, str) or not reference.strip():
        return None, None, ["ORACLE_SOURCE_REFERENCE_MISSING"]
    raw = Path(reference)
    candidates = [raw] if raw.is_absolute() else [build_root / raw]
    if project_root is not None and not raw.is_absolute():
        candidates.append(project_root / raw)
    unique: dict[str, Path] = {}
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        unique[str(resolved).casefold()] = resolved
    files = [path for path in unique.values() if path.is_file()]
    if len(files) != 1:
        return None, None, ["ORACLE_SOURCE_CARDINALITY_NOT_ONE"]
    path = files[0]
    try:
        return path, _digest_bytes(path.read_bytes()), []
    except OSError as exc:
        return None, None, [f"ORACLE_SOURCE_UNREADABLE:{exc}"]


def _runtime_identity() -> str:
    return "sha256:" + _digest_bytes(Path(__file__).read_bytes())


def _rich_assessment(
    path: Path,
    candidate_id: str,
    source: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str], str | None]:
    if not path.exists():
        return None, [], None
    try:
        _canonical_entry(path, "rich execution-scope source")
        record, raw = _strict_object(path, "rich execution-scope source")
        if record.get("candidate_id") != candidate_id:
            raise ExecutionScopeRuntimeError("rich source candidate identity mismatch")
        exact = {
            "source_snapshot_sha256": source["source_snapshot_sha256"],
            "build_sha256": source["build_binding_sha256"],
            "command_sha256": source["command_sha256"],
            "oracle_sha256": source["oracle_sha256"],
            "output_sha256": source["output_sha256"],
            "runner_receipt_sha256": source["execution_evidence_sha256"],
            "launch_receipt_sha256": source["successor_receipt_sha256"],
        }
        for field, expected in exact.items():
            if expected is None or record.get(field) != expected:
                raise ExecutionScopeRuntimeError(
                    f"rich source {field} does not bind exact runtime evidence"
                )
        expected_result = source["execution_result"]
        if record.get("execution_status") != "COMPLETED":
            raise ExecutionScopeRuntimeError("rich source execution is not completed")
        if record.get("execution_result") != expected_result:
            raise ExecutionScopeRuntimeError("rich source result polarity mismatch")
        exit_code = record.get("exit_code")
        if (
            isinstance(exit_code, bool) or not isinstance(exit_code, int)
            or (expected_result == "ESTABLISHED" and exit_code != 0)
            or (expected_result == "NOT_ESTABLISHED" and exit_code == 0)
        ):
            raise ExecutionScopeRuntimeError("rich source exit/result binding is invalid")
        assessment = issue_executed_poc_scope_assessment(record)
        if assessment["candidate_id"] != candidate_id:
            raise ExecutionScopeRuntimeError("rich assessment candidate mismatch")
        return assessment, [], _digest_bytes(raw)
    except (
        ExecutionScopeRuntimeError,
        EvidenceCapabilityError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        try:
            observed_sha = _digest_bytes(path.read_bytes()) if path.is_file() else None
        except OSError:
            observed_sha = None
        return None, [f"RICH_SCOPE_SOURCE_INVALID:{exc}"], observed_sha


def _baseline_assessment(
    candidate_id: str,
    source: Mapping[str, Any],
    *,
    authenticated: bool,
) -> dict[str, Any]:
    source_digest = str(source["record_digest"])
    evidence_id = "MECH-EXEC-" + source_digest[:24].upper()
    if not authenticated:
        value = assess_executed_poc_scope(
            candidate_id,
            {"evidence_id": evidence_id, "runtime_source_sha256": source_digest},
        )
        # Preserve the exact runtime cause rather than collapsing every failure
        # into one generic metadata token.
        unsigned = dict(value)
        unsigned["source_record_sha256"] = source_digest
        unsigned["debts"] = sorted(
            set(value["debts"]) | set(source.get("issues") or [])
        )
        unsigned.pop("assessment_digest", None)
        unsigned["assessment_digest"] = _digest(unsigned)
        return validate_executed_poc_scope_assessment(unsigned)

    receipt = validate_evidence_receipt(
        {
            "evidence_id": evidence_id,
            "content_sha256": source_digest,
            "premise_ids": [f"P1E-EXECUTION-{candidate_id}"],
            "constituent_ids": [candidate_id],
            "proof_scope": "IN_SCOPE_EXECUTION",
            "capabilities": ["EXECUTION"],
            "issuer_identity": str(source["issuer_identity"]),
            "issuer_invocation_id": str(source.get("successor_receipt_digest") or source_digest),
        }
    )
    unsigned = {
        "schema_version": "plamen.executed_poc_scope_assessment.v1",
        "candidate_id": candidate_id,
        "evidence_id": evidence_id,
        "source_record_sha256": source_digest,
        "execution_authenticity": "AUTHENTICATED",
        "execution_result": source["execution_result"],
        "oracle_provenance": "UNKNOWN",
        "oracle_authority": "UNBOUND",
        "reachability": "UNKNOWN",
        "environment_fidelity": "UNKNOWN",
        "precondition_coverage": "UNKNOWN",
        "proof_scope": "UNPROVEN",
        "external_premise_state": "UNKNOWN",
        "negative_exhaustiveness": "UNKNOWN",
        "positive_capabilities": ["EXECUTION"],
        "maximum_negative_scope": "NONE",
        "harm_evidence_eligible": False,
        "negative_disposition_eligible": False,
        "candidate_state": "ADJUDICATION_REQUIRED",
        "debts": sorted(
            set(source.get("issues") or [])
            | {"SEMANTIC_SCOPE_UNASSESSED", "NEGATIVE_SCOPE_NOT_TERMINAL"}
        ),
        "evidence_receipt": receipt,
    }
    unsigned["assessment_digest"] = _digest(unsigned)
    return validate_executed_poc_scope_assessment(unsigned)


def _build_runtime_source(
    root: Path,
    candidate_id: str,
    *,
    build_root: Path | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate_id = _safe_id(candidate_id, "candidate_id")
    issues: list[str] = []
    result, manifest_raw = _manifest_row(root, candidate_id)
    verify_path = root / f"verify_{candidate_id}.md"
    _canonical_entry(verify_path, "verify artifact")
    try:
        verify_raw = verify_path.read_bytes()
    except OSError as exc:
        raise ExecutionScopeRuntimeError(f"verify artifact unavailable: {exc}") from exc

    snapshot, snapshot_issues = _snapshot_digest(root)
    issues.extend(snapshot_issues)
    root_path = Path(build_root) if build_root is not None else _project_root_from_checkpoint(root)
    if root_path is None:
        root_path = root.parent
        issues.append("BUILD_ROOT_AUTHORITY_MISSING")
    try:
        root_path = root_path.resolve()
    except OSError:
        root_path = Path(root_path)
    build_digest, build_issues = _build_binding(root_path)
    issues.extend(build_issues)

    receipt: MechanicalSuccessorReceipt | None = None
    successor_raw: bytes | None = None
    evidence: dict[str, Any] | None = None
    evidence_path: Path | None = None
    evidence_raw: bytes | None = None
    try:
        receipt, successor_raw = _validate_successor(root, candidate_id, result)
        evidence, evidence_path, evidence_raw = _execution_evidence(
            root, candidate_id, manifest_raw, successor_raw, result
        )
    except ExecutionScopeRuntimeError as exc:
        issues.append(f"MECHANICAL_AUTHORITY_INVALID:{exc}")

    reference = result.get("test_file_resolved")
    project_root = _project_root_from_checkpoint(root)
    oracle_path, oracle_digest, oracle_issues = _resolve_oracle(
        reference, root_path, project_root
    )
    issues.extend(oracle_issues)
    command = result.get("test_command_used")
    if not isinstance(command, str) or not command.strip():
        command_digest = None
        issues.append("EXECUTION_COMMAND_UNBOUND")
    else:
        command_digest = _digest_bytes(command.encode("utf-8"))
    output = result.get("stdout_tail")
    if not isinstance(output, str) or not output.strip():
        output_digest = None
        issues.append("EXECUTION_OUTPUT_UNBOUND")
    else:
        output_digest = _digest_bytes(output.encode("utf-8"))
    status = str(result.get("status") or "")
    execution_result = (
        "ESTABLISHED" if status == "PASS"
        else "NOT_ESTABLISHED" if status == "FAIL"
        else "EXECUTION_ERROR"
    )
    if status not in _EXECUTED_STATUSES:
        issues.append(f"MECHANICAL_EXECUTION_NOT_COMPLETED:{status or 'UNKNOWN'}")

    rich_path = _rich_source_path(root, candidate_id)
    semantic_file = rich_path.name if rich_path.exists() else None
    try:
        semantic_sha = _digest_bytes(rich_path.read_bytes()) if rich_path.is_file() else None
    except OSError as exc:
        semantic_sha = None
        issues.append(f"RICH_SCOPE_SOURCE_UNREADABLE:{exc}")
    unsigned = {
        "schema_version": RUNTIME_SOURCE_SCHEMA,
        "candidate_id": candidate_id,
        "verify_file": verify_path.name,
        "verify_sha256": _digest_bytes(verify_raw),
        "source_snapshot_sha256": snapshot,
        "build_root": str(root_path),
        "build_binding_sha256": build_digest,
        "mechanical_manifest_file": "mechanical_verify_manifest.json",
        "mechanical_manifest_sha256": _digest_bytes(manifest_raw),
        "mechanical_result_sha256": _digest(result),
        "successor_receipt_file": (
            f"verify_{candidate_id}.mechanical_successor.receipt.json"
            if receipt is not None else None
        ),
        "successor_receipt_sha256": (
            _digest_bytes(successor_raw) if successor_raw is not None else None
        ),
        "successor_receipt_digest": receipt.receipt_digest if receipt is not None else None,
        "execution_evidence_file": (
            f"mechanical_execution_evidence/{evidence_path.name}"
            if evidence_path is not None else None
        ),
        "execution_evidence_sha256": (
            _digest_bytes(evidence_raw) if evidence_raw is not None else None
        ),
        "execution_evidence_record_digest": (
            evidence.get("record_digest") if evidence is not None else None
        ),
        "test_file_reference": reference if isinstance(reference, str) else None,
        "oracle_file": str(oracle_path) if oracle_path is not None else None,
        "oracle_sha256": oracle_digest,
        "command_sha256": command_digest,
        "output_sha256": output_digest,
        "execution_status": status,
        "execution_result": execution_result,
        "semantic_source_file": semantic_file,
        "semantic_source_sha256": semantic_sha,
        "assessment_kind": "BASELINE",
        "issues": sorted(dict.fromkeys(issues)),
        "issuer_identity": _runtime_identity(),
    }
    rich, rich_issues, observed_rich_sha = _rich_assessment(
        rich_path, candidate_id, {**unsigned, "record_digest": "0" * 64}
    )
    if semantic_sha != observed_rich_sha:
        rich = None
        rich_issues.append("RICH_SCOPE_SOURCE_INVALID:source changed while reading")
    unsigned["issues"] = sorted(dict.fromkeys(unsigned["issues"] + rich_issues))
    if rich is not None:
        unsigned["assessment_kind"] = "RICH"
    unsigned["record_digest"] = _digest(unsigned)
    source = dict(unsigned)
    blocking = [
        issue for issue in issues
        if not issue.startswith("RICH_SCOPE_SOURCE_INVALID")
    ]
    authenticated = status in _EXECUTED_STATUSES and not blocking
    assessment = rich if rich is not None else _baseline_assessment(
        candidate_id, source, authenticated=authenticated
    )
    return source, assessment


def _validate_runtime_source(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(_SOURCE_FIELDS):
        raise ExecutionScopeRuntimeError("runtime source schema fields mismatch")
    out = dict(value)
    if out.get("schema_version") != RUNTIME_SOURCE_SCHEMA:
        raise ExecutionScopeRuntimeError("runtime source version mismatch")
    _safe_id(out.get("candidate_id"), "runtime candidate_id")
    for field in (
        "verify_sha256", "mechanical_manifest_sha256", "mechanical_result_sha256",
        "build_binding_sha256", "source_snapshot_sha256", "successor_receipt_sha256",
        "successor_receipt_digest", "execution_evidence_sha256",
        "execution_evidence_record_digest", "oracle_sha256", "command_sha256",
        "output_sha256", "semantic_source_sha256",
    ):
        _hex_or_none(out.get(field), field)
    if not isinstance(out.get("issues"), list) or any(
        not isinstance(item, str) or not item for item in out["issues"]
    ):
        raise ExecutionScopeRuntimeError("runtime source issues are invalid")
    if out["issues"] != sorted(set(out["issues"])):
        raise ExecutionScopeRuntimeError("runtime source issues are non-canonical")
    if out.get("assessment_kind") not in {"BASELINE", "RICH"}:
        raise ExecutionScopeRuntimeError("runtime assessment kind is invalid")
    declared = out.get("record_digest")
    if not isinstance(declared, str) or declared != _digest(
        {key: item for key, item in out.items() if key != "record_digest"}
    ):
        raise ExecutionScopeRuntimeError("runtime source record_digest mismatch")
    return out


def _write_debt(root: Path, rows: list[dict[str, Any]]) -> None:
    path = root / RUNTIME_DEBT_FILE
    if not rows:
        if path.exists():
            try:
                path.unlink()
            except OSError:
                pass
        return
    unsigned = {
        "schema_version": RUNTIME_DEBT_SCHEMA,
        "authority": "NONE",
        "candidate_count": len(rows),
        "candidates": sorted(rows, key=lambda row: row["candidate_id"].casefold()),
    }
    _atomic_derived_write(path, {**unsigned, "receipt_digest": _digest(unsigned)})


def materialize_execution_scope_assessments(
    scratchpad: Path,
    *,
    build_root: Path | None = None,
) -> dict[str, Any]:
    """Materialize exact candidate-bound assessments for all manifest rows.

    This is haltless per candidate.  A malformed row or missing authority is
    returned and persisted as debt; valid rows continue independently.
    """

    root = Path(scratchpad)
    manifest = root / "mechanical_verify_manifest.json"
    if not manifest.is_file():
        return {"status": "ABSENT", "materialized": 0, "issues": []}
    try:
        value, _ = _strict_object(manifest, "mechanical manifest")
        raw_rows = value.get("results")
        if not isinstance(raw_rows, list):
            raise ExecutionScopeRuntimeError("mechanical manifest results are invalid")
        candidates = []
        seen: set[str] = set()
        for row in raw_rows:
            if not isinstance(row, Mapping) or not isinstance(row.get("finding_id"), str):
                raise ExecutionScopeRuntimeError("mechanical manifest row identity is invalid")
            candidate = row["finding_id"]
            key = candidate.casefold()
            if key in seen:
                raise ExecutionScopeRuntimeError(
                    "mechanical manifest has duplicate/case-colliding candidate"
                )
            seen.add(key)
            candidates.append(candidate)
    except ExecutionScopeRuntimeError as exc:
        issue = f"MANIFEST_AUTHORITY_INVALID:{exc}"
        _write_debt(root, [{"candidate_id": "MANIFEST", "issues": [issue]}])
        return {"status": "DEGRADED", "materialized": 0, "issues": [issue]}

    issues: list[str] = []
    debts: list[dict[str, Any]] = []
    materialized = 0
    for candidate in candidates:
        try:
            source, assessment = _build_runtime_source(
                root, candidate, build_root=build_root
            )
            source_path = _runtime_source_path(root, candidate)
            assessment_path = _assessment_path(root, candidate)
            # Derived authority is immutable once established.  Re-running the
            # phase may repair one missing half only when the surviving half
            # exactly equals the current deterministic projection.  It may not
            # refresh both files after source/oracle/manifest drift, because
            # doing so would launder post-execution bytes into apparent
            # execution-time authority.
            source_exists = source_path.exists()
            assessment_exists = assessment_path.exists()
            if source_exists:
                _canonical_entry(source_path, "execution-scope runtime source")
                persisted_source, _ = _strict_object(
                    source_path, "execution-scope runtime source"
                )
                _validate_runtime_source(persisted_source)
                if persisted_source != source:
                    raise ExecutionScopeRuntimeError(
                        "established runtime source disagrees with current authority; "
                        "explicit rewind/reverification required"
                    )
            if assessment_exists:
                _canonical_entry(assessment_path, "execution-scope assessment")
                persisted_assessment, _ = _strict_object(
                    assessment_path, "execution-scope assessment"
                )
                persisted_assessment = validate_executed_poc_scope_assessment(
                    persisted_assessment
                )
                if persisted_assessment != assessment:
                    raise ExecutionScopeRuntimeError(
                        "established assessment disagrees with current authority; "
                        "explicit rewind/reverification required"
                    )
            if not source_exists:
                _atomic_derived_write(source_path, source)
            if not assessment_exists:
                _atomic_derived_write(assessment_path, assessment)
            materialized += 1
            if source["issues"]:
                candidate_issues = [
                    f"{candidate}:{item}" for item in source["issues"]
                ]
                issues.extend(candidate_issues)
                debts.append({"candidate_id": candidate, "issues": source["issues"]})
        except Exception as exc:
            issue = f"{candidate}:RUNTIME_SCOPE_MATERIALIZATION_FAILED:{type(exc).__name__}:{exc}"
            issues.append(issue)
            debts.append({"candidate_id": candidate, "issues": [issue]})
    _write_debt(root, debts)
    return {
        "status": "DEGRADED" if issues else "CLEAN",
        "materialized": materialized,
        "issues": sorted(dict.fromkeys(issues)),
    }


def load_execution_scope_assessment(
    scratchpad: Path, candidate_id: str
) -> dict[str, Any]:
    """Load only an assessment reproducible from current exact authorities."""

    root = Path(scratchpad)
    try:
        candidate = _safe_id(candidate_id, "candidate_id")
    except ExecutionScopeRuntimeError as exc:
        return {"status": "INVALID", "assessment": None, "issues": [str(exc)]}
    assessment_path = _assessment_path(root, candidate)
    source_path = _runtime_source_path(root, candidate)
    if not assessment_path.exists() and not source_path.exists():
        return {
            "status": "MISSING", "assessment": None,
            "issues": ["MISSING_TYPED_EXECUTION_EVIDENCE"],
        }
    try:
        _canonical_entry(assessment_path, "execution-scope assessment")
        _canonical_entry(source_path, "execution-scope runtime source")
        source_raw, _ = _strict_object(source_path, "execution-scope runtime source")
        source = _validate_runtime_source(source_raw)
        if source["candidate_id"] != candidate:
            raise ExecutionScopeRuntimeError("runtime source candidate mismatch")
        try:
            expected_source, expected_assessment = _build_runtime_source(
                root,
                candidate,
                build_root=Path(str(source["build_root"])),
            )
        except Exception as exc:
            raise ExecutionScopeRuntimeError(
                f"current runtime authority does not validate: {exc}"
            ) from exc
        if expected_source != source:
            raise ExecutionScopeRuntimeError(
                "runtime source is stale or current authority drifted"
            )
        assessment_raw, _ = _strict_object(
            assessment_path, "execution-scope assessment"
        )
        assessment = validate_executed_poc_scope_assessment(assessment_raw)
        if assessment != expected_assessment:
            raise ExecutionScopeRuntimeError(
                "assessment is not the deterministic projection of runtime authority"
            )
        if assessment["candidate_id"] != candidate:
            raise ExecutionScopeRuntimeError("assessment candidate mismatch")
        if assessment["candidate_state"] == "VISIBLE_EVIDENCE_DEBT":
            status = "EVIDENCE_DEBT"
        elif source["assessment_kind"] == "RICH":
            status = "VALID_RICH"
        else:
            status = "VALID_LIMITED"
        return {"status": status, "assessment": assessment, "issues": source["issues"]}
    except (ExecutionScopeRuntimeError, EvidenceCapabilityError, OSError, ValueError) as exc:
        return {
            "status": "INVALID", "assessment": None,
            "issues": [f"INVALID_TYPED_EXECUTION_EVIDENCE:{exc}"],
        }


__all__ = [
    "ASSESSMENT_SUFFIX",
    "RICH_SOURCE_SUFFIX",
    "RUNTIME_DEBT_FILE",
    "RUNTIME_SOURCE_SCHEMA",
    "RUNTIME_SOURCE_SUFFIX",
    "ExecutionScopeRuntimeError",
    "load_execution_scope_assessment",
    "materialize_execution_scope_assessments",
]
