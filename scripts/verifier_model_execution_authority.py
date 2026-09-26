"""Shared replay of the MODEL authority bound by verifier unit gate v2.

This module deliberately validates only provider-worker launch/completion
authority.  It does not create or qualify proof-of-concept execution evidence
and therefore cannot promote a finding to proof-grade VERIFIED status.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping

from artifact_ledger import ArtifactLedgerError, read_artifact_ledger
from phase_io_contracts import LaunchSpec, PhaseIOContract, canonical_work_unit_key
from provider_semantic_completion import (
    provider_transport_completion_is_admitted,
)
from mechanical_successor_receipts import (
    MechanicalSuccessorReceipt,
    _validate_manifest,
)
from queue_work_items import VerifierOutputReceipt
from worker_transaction import (
    WorkerTransactionError,
    _artifact_state,
    _read_digest_bound_json,
    _safe_relative_file,
    validate_worker_execution_authority,
)


GATE_SCHEMA_V2 = "plamen.verifier_unit_gate_receipt.v2"
_BASE_GATE_FIELDS = frozenset({
    "schema_version", "state", "work_unit_id", "work_unit_resume_digest",
    "roster_digest", "launch_spec_digest", "method_dispatch_id",
    "method_dispatch_sha256", "ordered_work_item_ids",
    "operator_receipt_digests", "model_execution_authority_digest",
    "output_sha256",
})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class VerifierModelExecutionAuthorityError(ValueError):
    """A verifier gate is not bound to one replayable MODEL execution."""


@dataclass(frozen=True, slots=True)
class _OutputProjection:
    identity: str


@dataclass(frozen=True, slots=True)
class _ContractProjection:
    phase: str
    work_unit_id: str
    digest: str
    outputs: tuple[_OutputProjection, ...]


@dataclass(frozen=True, slots=True)
class _LaunchProjection:
    digest: str


def _successor_original_state(
    root: Path,
    *,
    identity: str,
    expected_sha256: str,
    expected_size: int,
) -> bool:
    """Replay one governed append-only verifier-output successor."""

    prefix = "scratchpad:verify_"
    suffix = ".md"
    if not identity.startswith(prefix) or not identity.endswith(suffix):
        return False
    finding_id = identity[len(prefix):-len(suffix)]
    if not finding_id or "/" in finding_id or "\\" in finding_id:
        return False
    verify_path = _safe_relative_file(
        root, f"verify_{finding_id}.md", "mechanical successor output"
    )
    successor_path = _safe_relative_file(
        root,
        f"verify_{finding_id}.mechanical_successor.receipt.json",
        "mechanical successor receipt",
    )
    successor = MechanicalSuccessorReceipt.from_json(
        successor_path.read_text(encoding="utf-8", errors="strict")
    )
    current = verify_path.read_bytes()
    original = current[:successor.original_output_size_bytes]
    receipt_path = _safe_relative_file(
        root,
        successor.original_verifier_receipt_file,
        "original verifier receipt",
    )
    receipt_raw = receipt_path.read_bytes()
    verifier_receipt = VerifierOutputReceipt.from_json(
        receipt_raw.decode("utf-8", errors="strict")
    )
    manifest_path = _safe_relative_file(
        root,
        successor.mechanical_manifest_file,
        "mechanical manifest",
    )
    manifest_raw = manifest_path.read_bytes()
    manifest_value = json.loads(manifest_raw.decode("utf-8", errors="strict"))
    result_rows = (
        manifest_value.get("results")
        if isinstance(manifest_value, dict)
        else None
    )
    matches = (
        [
            row
            for row in result_rows
            if isinstance(row, dict)
            and row.get("finding_id") == finding_id
            and row.get("verify_file") == verify_path.name
            and _digest(row) == successor.mechanical_result_sha256
        ]
        if isinstance(result_rows, list)
        else []
    )
    if len(matches) != 1:
        return False
    _validate_manifest(manifest_path, matches[0])
    return (
        successor.finding_id == finding_id
        and successor.verify_file == verify_path.name
        and successor.original_output_sha256 == expected_sha256
        and successor.original_output_size_bytes == expected_size
        and len(current) == successor.transformed_output_size_bytes
        and hashlib.sha256(current).hexdigest()
        == successor.transformed_output_sha256
        and len(original) == expected_size
        and hashlib.sha256(original).hexdigest() == expected_sha256
        and len(receipt_raw) == successor.original_verifier_receipt_size_bytes
        and hashlib.sha256(receipt_raw).hexdigest()
        == successor.original_verifier_receipt_sha256
        and verifier_receipt.digest
        == successor.original_verifier_receipt_digest
        and verifier_receipt.output_sha256 == expected_sha256
        and verifier_receipt.output_size_bytes == expected_size
        and len(manifest_raw) == successor.mechanical_manifest_size_bytes
        and hashlib.sha256(manifest_raw).hexdigest()
        == successor.mechanical_manifest_sha256
    )


def _replay_execution_allowing_successors(
    *,
    root: Path,
    execution: Mapping[str, Any],
    contract: _ContractProjection,
    launch: _LaunchProjection,
    run_id: str,
) -> Mapping[str, Any]:
    """Replay standard authority, narrowly admitting governed successors."""

    try:
        return validate_worker_execution_authority(
            scratchpad=root,
            authority=execution,
            contract=contract,
            launch=launch,
            run_id=run_id,
        )
    except WorkerTransactionError as exc:
        if str(exc) != "incorporated canonical bytes changed":
            raise

    # The standard replay authenticated the entire chain and denominator
    # before its terminal current-byte comparison failed.  Re-read the bound
    # incorporation and require every changed row to be one exact successor.
    incorporation_path = _safe_relative_file(
        root,
        str(execution.get("incorporation_relative_path") or ""),
        "worker incorporation",
    )
    incorporation, incorporation_digest = _read_digest_bound_json(
        incorporation_path,
        digest_field="incorporation_digest",
        label="worker incorporation",
    )
    if incorporation_digest != execution.get("incorporation_digest"):
        raise WorkerTransactionError("incorporation authority mismatch")
    projected = incorporation.get("projected_members")
    if not isinstance(projected, list):
        raise WorkerTransactionError("incorporation output denominator mismatch")
    for row in projected:
        if not isinstance(row, dict):
            raise WorkerTransactionError("incorporation member is malformed")
        identity = row.get("canonical_identity")
        expected_sha = row.get("sha256")
        expected_size = row.get("size")
        if (
            not isinstance(identity, str)
            or not identity.startswith("scratchpad:")
            or _SHA256_RE.fullmatch(str(expected_sha or "")) is None
            or isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            raise WorkerTransactionError("incorporation member is malformed")
        destination = _safe_relative_file(
            root,
            identity.removeprefix("scratchpad:"),
            "canonical projection destination",
        )
        state = _artifact_state(destination)
        if (
            state["status"] == "ACTIVE"
            and state["sha256"] == expected_sha
            and state["size"] == expected_size
        ):
            continue
        if not _successor_original_state(
            root,
            identity=identity,
            expected_sha256=str(expected_sha),
            expected_size=expected_size,
        ):
            raise WorkerTransactionError("incorporated canonical bytes changed")
    return execution


def validated_verifier_model_execution_read_set(
    root: Path,
    *,
    owner_key: str,
    unit: Mapping[str, Any],
) -> tuple[str, ...]:
    """Return the exact transaction files needed to replay one MODEL unit.

    The returned paths are useful only as an input-staging read set.  This
    function first replays the existing execution authority against the live
    root; it neither constructs nor substitutes execution authority.
    """

    execution = unit.get("execution_authority")
    manifest = unit.get("contract_manifest")
    launch_manifest = unit.get("launch_manifest")
    key_parts = owner_key.split("/")
    if (
        unit.get("semantic_status") != "ACTIVE"
        or unit.get("execution_state") != "OUTPUT_COMMITTED"
        or unit.get("model_invoked") is not True
        or not isinstance(execution, Mapping)
        or not isinstance(manifest, Mapping)
        or not isinstance(launch_manifest, Mapping)
        or len(key_parts) != 6
        or manifest.get("key") != owner_key
        or canonical_work_unit_key(*key_parts) != owner_key
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL staging authority is malformed"
        )
    phase, work_unit_id = key_parts[4:]
    run_id = unit.get("run_id")
    contract_digest = unit.get("contract_digest")
    launch_digest = unit.get("launch_digest")
    outputs = manifest.get("outputs")
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(contract_digest, str)
        or not contract_digest
        or not isinstance(launch_digest, str)
        or not launch_digest
        or not isinstance(outputs, list)
        or not outputs
        or launch_manifest.get("work_unit_key") != owner_key
        or execution.get("run_id") != run_id
        or execution.get("phase") != phase
        or execution.get("work_unit_id") != work_unit_id
        or execution.get("contract_digest") != contract_digest
        or execution.get("launch_digest") != launch_digest
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL staging contract is malformed"
        )
    identities: list[str] = []
    for row in outputs:
        identity = row.get("identity") if isinstance(row, Mapping) else None
        if not isinstance(identity, str) or not identity:
            raise VerifierModelExecutionAuthorityError(
                "verifier MODEL staging output denominator is malformed"
            )
        identities.append(identity)
    if len(identities) != len(set(identities)):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL staging output denominator is duplicated"
        )
    contract = _ContractProjection(
        phase=phase,
        work_unit_id=work_unit_id,
        digest=contract_digest,
        outputs=tuple(_OutputProjection(identity) for identity in identities),
    )
    launch = _LaunchProjection(digest=launch_digest)
    try:
        _replay_execution_allowing_successors(
            root=Path(root),
            execution=execution,
            contract=contract,
            launch=launch,
            run_id=run_id,
        )
    except (WorkerTransactionError, OSError) as exc:
        raise VerifierModelExecutionAuthorityError(
            f"verifier MODEL staging execution does not replay: {exc}"
        ) from exc
    names = (
        "attempt_completion_relative_path",
        "provider_completion_relative_path",
        "incorporation_relative_path",
    )
    paths = tuple(str(execution.get(name) or "") for name in names)
    # Replay above resolves these as safe regular files.  Retain exactly the
    # canonical spellings authenticated by the authority record.
    if (
        any(not path or PurePosixPath(path).as_posix() != path for path in paths)
        or len({path.casefold() for path in paths}) != len(paths)
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL staging path is non-canonical"
        )
    return paths


def verifier_model_output_matches_bound_original(
    root: Path,
    *,
    identity: str,
    expected_sha256: str,
    expected_size: int,
) -> bool:
    """Recognize only a governed successor of one bound verifier output."""

    return _successor_original_state(
        Path(root),
        identity=identity,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
    )


def _digest(value: Any) -> str:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise VerifierModelExecutionAuthorityError(
            f"MODEL authority is not canonical JSON: {exc}"
        ) from exc
    return hashlib.sha256(raw).hexdigest()


def replay_verifier_gate_model_execution_authority(
    scratchpad: Path,
    gate: Mapping[str, Any],
    *,
    selected_output_identity: str,
    expected_run_id: str | None = None,
    expected_owner_suffix: str | None = None,
) -> str:
    """Return the exact replayed worker-authority digest selected by ``gate``.

    The selected canonical MODEL output locates its sole ledger owner.  The
    complete output denominator, immutable execution/incorporation chain, and
    gate digest reference are then replayed.  An optional bug-bounty receipt
    field is the only permitted gate extension.
    """

    if not isinstance(gate, Mapping):
        raise VerifierModelExecutionAuthorityError(
            "verifier unit gate is not a mapping"
        )
    fields = set(gate)
    if fields not in (
        set(_BASE_GATE_FIELDS),
        {*_BASE_GATE_FIELDS, "bb_policy_receipt_digest"},
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier unit gate fields are not exact v2"
        )
    if gate.get("schema_version") != GATE_SCHEMA_V2:
        if gate.get("schema_version") == "plamen.verifier_unit_gate_receipt.v1":
            raise VerifierModelExecutionAuthorityError(
                "legacy verifier unit gate lacks MODEL execution authority"
            )
        raise VerifierModelExecutionAuthorityError(
            "verifier unit gate schema is unsupported"
        )
    gate_digest = str(gate.get("model_execution_authority_digest") or "")
    if _SHA256_RE.fullmatch(gate_digest) is None:
        raise VerifierModelExecutionAuthorityError(
            "verifier unit gate MODEL authority digest is malformed"
        )
    root = Path(scratchpad).resolve(strict=True)
    ledger = read_artifact_ledger(root)
    binding = ledger.get("artifact_bindings", {}).get(
        selected_output_identity
    )
    if not isinstance(binding, Mapping):
        raise VerifierModelExecutionAuthorityError(
            "selected verifier output has no MODEL owner"
        )
    owner_key = str(binding.get("owner_key") or "")
    if (
        binding.get("status") != "ACTIVE"
        or binding.get("writer") != "MODEL"
        or not owner_key
        or (
            expected_run_id is not None
            and binding.get("run_id") != expected_run_id
        )
        or (
            expected_owner_suffix is not None
            and not owner_key.endswith(expected_owner_suffix)
        )
    ):
        raise VerifierModelExecutionAuthorityError(
            "selected verifier MODEL binding is foreign or stale"
        )
    unit = ledger.get("work_units", {}).get(owner_key)
    if not isinstance(unit, Mapping):
        raise VerifierModelExecutionAuthorityError(
            "selected verifier MODEL work unit is absent"
        )
    execution = unit.get("execution_authority")
    execution_unsigned = (
        {
            key: value for key, value in execution.items()
            if key != "authority_digest"
        }
        if isinstance(execution, Mapping)
        else {}
    )
    commit = unit.get("commit_authority")
    if (
        unit.get("semantic_status") != "ACTIVE"
        or unit.get("run_id") != binding.get("run_id")
        or (
            expected_run_id is not None
            and unit.get("run_id") != expected_run_id
        )
        or unit.get("execution_state") != "OUTPUT_COMMITTED"
        or unit.get("model_invoked") is not True
        or not isinstance(execution, Mapping)
        or execution.get("schema") != "plamen.worker_execution_authority.v1"
        or execution.get("authority_digest") != _digest(execution_unsigned)
        or execution.get("authority_digest") != gate_digest
        or not isinstance(commit, Mapping)
        or commit.get("execution_authority") != dict(execution)
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL execution authority is absent or stale"
        )
    manifest = unit.get("contract_manifest")
    launch_manifest = unit.get("launch_manifest")
    outputs = manifest.get("outputs") if isinstance(manifest, Mapping) else None
    if not isinstance(outputs, list) or not outputs:
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL output denominator is malformed"
        )
    output_identities: list[str] = []
    for row in outputs:
        identity = row.get("identity") if isinstance(row, Mapping) else None
        if not isinstance(identity, str) or not identity:
            raise VerifierModelExecutionAuthorityError(
                "verifier MODEL output identity is malformed"
            )
        output_identities.append(identity)
    if (
        len(output_identities) != len(set(output_identities))
        or selected_output_identity not in output_identities
    ):
        raise VerifierModelExecutionAuthorityError(
            "selected output is outside the MODEL denominator"
        )
    artifacts = unit.get("artifacts")
    for identity in output_identities:
        artifact = artifacts.get(identity) if isinstance(artifacts, Mapping) else None
        live = ledger.get("artifact_bindings", {}).get(identity)
        if (
            not isinstance(artifact, Mapping)
            or not isinstance(live, Mapping)
            or artifact.get("status") != "ACTIVE"
            or live.get("status") != "ACTIVE"
            or artifact.get("owner_key") != owner_key
            or live.get("owner_key") != owner_key
            or artifact.get("sha256") != live.get("sha256")
            or artifact.get("size") != live.get("size")
        ):
            raise VerifierModelExecutionAuthorityError(
                "verifier MODEL output ownership is inconsistent"
            )
    # PhaseIOContract serializes its dimensions in the canonical key, not as
    # separate phase/work_unit_id fields. Validate that key before projecting
    # the dimensions needed by the execution-chain replay.
    key_parts = owner_key.split("/")
    if (
        len(key_parts) != 6
        or manifest.get("key") != owner_key
        or canonical_work_unit_key(*key_parts) != owner_key
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL contract key is malformed"
        )
    phase, work_unit_id = key_parts[4:]
    contract_digest = str(unit.get("contract_digest") or "")
    launch_digest = str(unit.get("launch_digest") or "")
    if (
        not phase
        or not work_unit_id
        or not isinstance(launch_manifest, Mapping)
        or launch_manifest.get("work_unit_key") != owner_key
        or execution.get("contract_digest") != contract_digest
        or execution.get("launch_digest") != launch_digest
    ):
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL contract or launch authority is malformed"
        )
    contract = _ContractProjection(
        phase=phase,
        work_unit_id=work_unit_id,
        digest=contract_digest,
        outputs=tuple(_OutputProjection(identity) for identity in output_identities),
    )
    launch = _LaunchProjection(digest=launch_digest)
    try:
        replayed = _replay_execution_allowing_successors(
            root=root,
            execution=execution,
            contract=contract,
            launch=launch,
            run_id=str(unit.get("run_id") or ""),
        )
    except Exception as exc:
        raise VerifierModelExecutionAuthorityError(
            f"verifier MODEL execution chain does not replay: {exc}"
        ) from exc
    if replayed.get("authority_digest") != gate_digest:
        raise VerifierModelExecutionAuthorityError(
            "verifier gate differs from replayed MODEL authority"
        )
    final_ledger = read_artifact_ledger(root)
    final_binding = final_ledger.get("artifact_bindings", {}).get(
        selected_output_identity
    )
    final_unit = final_ledger.get("work_units", {}).get(owner_key)
    if final_binding != binding or final_unit != unit:
        raise VerifierModelExecutionAuthorityError(
            "verifier MODEL ledger changed during authority replay"
        )
    return gate_digest


POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA = (
    "plamen.posix_v2_compat_execution_receipt.v1"
)
POSIX_V2_COMPAT_LOG_SEPARATOR = b"\n[plamen-compat-stderr]\n"


def _canonical_receipt_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _reject_duplicate_pairs(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_regular(path: Path, *, maximum: int = 1_048_576) -> bytes:
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or int(before.st_nlink) != 1
        or int(before.st_size) <= 0
        or int(before.st_size) > int(maximum)
    ):
        raise ValueError("file is absent, aliased, empty, or oversized")
    raw = path.read_bytes()
    after = path.lstat()
    if (
        (
            int(before.st_dev), int(before.st_ino), int(before.st_size),
            int(before.st_mtime_ns),
        )
        != (
            int(after.st_dev), int(after.st_ino), int(after.st_size),
            int(after.st_mtime_ns),
        )
        or len(raw) != int(before.st_size)
    ):
        raise ValueError("file changed while reading")
    return raw


def replay_posix_v2_compat_dynamic_verifier_receipt(
    *,
    scratchpad: Path,
    config: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    label: str,
    attempt: int,
    prompt_sha256: str,
    session_authority: object,
    expected_session_binding_sha256: str | None = None,
) -> tuple[dict[str, Any] | None, Path | None, list[str]]:
    """Replay one exact successful compat execution receipt and live session."""

    root = Path(scratchpad).resolve()
    issues: list[str] = []
    try:
        from posix_v2_compat_runtime import require_posix_v2_compat_session

        session = require_posix_v2_compat_session(
            session_authority
        )
        session_binding = dict(session.binding)
    except Exception as exc:
        return None, None, [
            "compat verifier session authority unavailable: "
            f"{type(exc).__name__}: {exc}"
        ]
    expected_session_binding = str(
        session_binding.get("session_binding_sha256") or ""
    )
    expected_backend = str(contract.backend)
    if (
        expected_backend not in {"claude", "codex"}
        or launch.backend != expected_backend
        or session_binding.get("run_id")
        != str(config.get("_run_id") or "test-unbound")
        or session_binding.get("backend") != expected_backend
        or session_binding.get("project_root")
        != os.fspath(Path(str(config["project_root"])).resolve())
        or session_binding.get("scratchpad") != os.fspath(root)
        or re.fullmatch(r"[0-9a-f]{64}", expected_session_binding) is None
    ):
        return None, None, ["compat verifier session binding is foreign"]
    receipt_session_binding = (
        expected_session_binding
        if expected_session_binding_sha256 is None
        else str(expected_session_binding_sha256)
    )
    if re.fullmatch(r"[0-9a-f]{64}", receipt_session_binding) is None:
        return None, None, [
            "compat verifier historical session binding is malformed"
        ]

    receipt_root = root / ".posix_v2_compat_receipts"
    try:
        observed_root = receipt_root.lstat()
        if (
            stat.S_ISLNK(observed_root.st_mode)
            or not stat.S_ISDIR(observed_root.st_mode)
        ):
            raise ValueError("receipt root is not a real directory")
        candidates = sorted(receipt_root.glob(
            f"{contract.phase}.{label}.attempt{int(attempt)}.*.json"
        ))
    except (OSError, ValueError) as exc:
        return None, None, [f"compat verifier receipt lookup failed: {exc}"]
    if len(candidates) != 1:
        return None, None, [
            "compat verifier requires exactly one execution receipt for the "
            "current attempt"
        ]
    receipt_path = candidates[0]
    try:
        receipt_raw = _read_regular(receipt_path)
        receipt = json.loads(
            receipt_raw.decode("ascii", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return None, receipt_path, [f"compat verifier receipt is invalid: {exc}"]
    if not isinstance(receipt, dict):
        return None, receipt_path, [
            "compat verifier receipt is not a JSON object"
        ]
    unsigned = dict(receipt)
    claimed = str(unsigned.pop("receipt_sha256", ""))
    if hashlib.sha256(
        _canonical_receipt_bytes(unsigned)
    ).hexdigest() != claimed:
        issues.append("compat verifier receipt self-hash mismatch")
    try:
        from posix_v2_compat_runtime import (
            replay_posix_v2_compat_execution_receipt,
        )

        replayed_receipt = replay_posix_v2_compat_execution_receipt(
            receipt,
            expected_backend=expected_backend,
            require_completed=True,
        )
    except Exception as exc:
        issues.append(
            "compat verifier provider receipt does not replay: "
            f"{type(exc).__name__}: {exc}"
        )
    else:
        if dict(replayed_receipt) != receipt:
            issues.append("compat verifier provider receipt projection changed")
    invocation_id = str(receipt.get("invocation_id") or "")
    if (
        re.fullmatch(r"[0-9a-f]{32}", invocation_id) is None
        or receipt_path.name != (
            f"{contract.phase}.{label}.attempt{int(attempt)}."
            f"{invocation_id}.json"
        )
    ):
        issues.append("compat verifier invocation identity mismatch")

    try:
        ledger = read_artifact_ledger(root)
    except ArtifactLedgerError as exc:
        return None, receipt_path, [f"compat verifier ledger unavailable: {exc}"]
    unit = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(unit, Mapping):
        return None, receipt_path, ["compat verifier work unit is absent"]
    isolation = receipt.get("isolation")
    if (
        receipt.get("schema") != POSIX_V2_COMPAT_EXECUTION_RECEIPT_SCHEMA
        or receipt.get("mode") != "V2_COMPATIBILITY_REDUCED_ISOLATION"
        or receipt.get("status") != "COMPLETED"
        or receipt.get("failure_code") is not None
        or receipt.get("run_id")
        != str(config.get("_run_id") or "test-unbound")
        or receipt.get("phase") != contract.phase
        or receipt.get("label") != label
        or receipt.get("attempt") != int(attempt)
        or receipt.get("session_binding_sha256")
        != receipt_session_binding
        or receipt.get("backend") != expected_backend
        or receipt.get("requested_model") != launch.model
        or receipt.get("model_binding") != "EXPLICIT_CLI_ARGUMENT"
        or (
            (receipt.get("model_observation"), receipt.get("observed_model"))
            not in {("NOT_OBSERVED", None), ("MATCH", launch.model)}
        )
        or not provider_transport_completion_is_admitted(receipt)
        or receipt.get("compatibility_return_value") != 0
        or receipt.get("timed_out") is not False
        or receipt.get("overflowed_stream") is not None
        or receipt.get("phase_io_contract_digest") != contract.digest
        or receipt.get("phase_io_launch_digest") != launch.digest
        or receipt.get("phase_io_input_set_digest")
        != unit.get("input_set_digest")
        or receipt.get("phase_io_output_prestate_digest")
        != unit.get("output_prestate_digest")
        or receipt.get("methodology_prompt_sha256") != prompt_sha256
        or receipt.get("prompt_sha256") != prompt_sha256
        or receipt.get("provider_event_profile") is not None
        or not isinstance(isolation, Mapping)
        or isolation.get("native_broker_authority") is not False
        or isolation.get("wer_authority") is not False
        or isolation.get("dangerous_bypass_requested") is not False
    ):
        issues.append(
            "compat verifier run/session/model/PhaseIO binding mismatch"
        )

    input_bindings = unit.get("input_bindings")
    input_routes = receipt.get("phase_io_input_routes")
    expected_inputs = sorted({
        *contract.immutable_inputs,
        *contract.bounded_lookup_inputs,
    })
    if not isinstance(input_bindings, Mapping) or not isinstance(
        input_routes, list
    ):
        issues.append("compat verifier input authority is malformed")
    else:
        routes_by_identity = {
            row.get("identity"): row
            for row in input_routes
            if isinstance(row, Mapping)
        }
        if (
            len(input_routes) != len(expected_inputs)
            or set(routes_by_identity) != set(expected_inputs)
        ):
            issues.append("compat verifier input-route denominator mismatch")
        else:
            for identity in expected_inputs:
                binding = input_bindings.get(identity)
                route = routes_by_identity[identity]
                root_name, relative = identity.split(":", 1)
                physical_root = (
                    root
                    if root_name == "scratchpad"
                    else Path(str(config["project_root"])).resolve()
                )
                expected_path = (physical_root / relative).resolve(
                    strict=False
                )
                if (
                    not isinstance(binding, Mapping)
                    or route.get("path") != os.fspath(expected_path)
                    or route.get("binding_status") != binding.get("status")
                    or route.get("sha256") != binding.get("sha256")
                    or route.get("size") != binding.get("size")
                ):
                    issues.append(
                        f"compat verifier input route drift: {identity}"
                    )
    try:
        input_routes_digest = hashlib.sha256(
            _canonical_receipt_bytes(
                {"routes": input_routes}
            )
        ).hexdigest()
    except (TypeError, UnicodeError, ValueError):
        input_routes_digest = ""
    if receipt.get("phase_io_input_routes_digest") != input_routes_digest:
        issues.append("compat verifier input-route hash mismatch")

    prestates = unit.get("output_prestates")
    output_routes = receipt.get("phase_io_output_routes")
    evidence = receipt.get("completed_output_evidence")
    expected_outputs = {spec.identity: spec for spec in contract.outputs}
    route_by_identity = {
        row.get("identity"): row
        for row in output_routes
        if isinstance(row, Mapping)
    } if isinstance(output_routes, list) else {}
    evidence_by_path = {
        row.get("path"): row
        for row in evidence
        if isinstance(row, Mapping)
    } if isinstance(evidence, list) else {}
    if (
        not isinstance(prestates, Mapping)
        or not isinstance(output_routes, list)
        or len(output_routes) != len(expected_outputs)
        or set(route_by_identity) != set(expected_outputs)
        or not isinstance(evidence, list)
        or len(evidence) != len(expected_outputs)
    ):
        issues.append("compat verifier output denominator mismatch")
    else:
        for identity, output_spec in expected_outputs.items():
            root_name, relative = identity.split(":", 1)
            if root_name != "scratchpad":
                issues.append(
                    f"compat verifier output root is unsupported: {identity}"
                )
                continue
            canonical = (root / relative).resolve(strict=False)
            route = route_by_identity[identity]
            if expected_backend == "codex":
                staged = (
                    root / ".posix_v2_compat_private" / invocation_id
                    / "staged-output" / relative
                ).resolve(strict=False)
            else:
                staged = Path(str(route.get("path") or "")).resolve(
                    strict=False
                )
                try:
                    staged.relative_to(root / ".worker_transactions")
                except ValueError:
                    issues.append(
                        f"compat verifier Claude staging root escaped: {identity}"
                    )
            prestate = prestates.get(identity)
            try:
                raw = _read_regular(
                    canonical, maximum=32 * 1024 * 1024
                )
            except (OSError, ValueError) as exc:
                raw = b""
                issues.append(
                    f"compat verifier output unavailable: {identity}: {exc}"
                )
            member = evidence_by_path.get(os.fspath(canonical))
            if (
                not isinstance(prestate, Mapping)
                or route.get("path") != os.fspath(staged)
                or route.get("canonical_path") != os.fspath(canonical)
                or route.get("write_mode") != output_spec.write_mode
                or route.get("prestate_status") != prestate.get("status")
                or route.get("prestate_existed")
                != bool(prestate.get("existed"))
                or route.get("prestate_sha256") != prestate.get("sha256")
                or route.get("prestate_size") != prestate.get("size")
                or not isinstance(member, Mapping)
                or member.get("sha256") != hashlib.sha256(raw).hexdigest()
                or member.get("size") != len(raw)
            ):
                issues.append(
                    f"compat verifier output binding drift: {identity}"
                )
    if expected_backend == "claude":
        provider = receipt.get("provider_execution")
        plan = provider.get("provider_plan") if isinstance(
            provider, Mapping
        ) else None
        try:
            planned_routes_sha256 = hashlib.sha256(
                json.dumps(
                    output_routes,
                    ensure_ascii=True,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
            ).hexdigest()
        except (TypeError, UnicodeError, ValueError):
            planned_routes_sha256 = ""
        if (
            not isinstance(plan, Mapping)
            or plan.get("output_routes_sha256") != planned_routes_sha256
        ):
            issues.append("compat verifier Claude output plan mismatch")
    try:
        output_routes_digest = hashlib.sha256(
            _canonical_receipt_bytes(
                {"routes": output_routes}
            )
        ).hexdigest()
    except (TypeError, UnicodeError, ValueError):
        output_routes_digest = ""
    if receipt.get("phase_io_output_routes_digest") != output_routes_digest:
        issues.append("compat verifier output-route hash mismatch")

    worker_log = root / f"_stdio_{label}.attempt{int(attempt)}.log"
    try:
        before = worker_log.lstat()
        if (
            stat.S_ISLNK(before.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or int(before.st_nlink) != 1
            or int(before.st_size) > 32 * 1024 * 1024
        ):
            raise ValueError("worker log is aliased or oversized")
        log_raw = worker_log.read_bytes()
        after = worker_log.lstat()
        if (
            (
                int(before.st_dev), int(before.st_ino), int(before.st_size),
                int(before.st_mtime_ns),
            )
            != (
                int(after.st_dev), int(after.st_ino), int(after.st_size),
                int(after.st_mtime_ns),
            )
            or len(log_raw) != int(before.st_size)
        ):
            raise ValueError("worker log changed during replay")
    except (OSError, ValueError) as exc:
        issues.append(f"compat verifier worker log unavailable: {exc}")
    else:
        stdout_size = receipt.get("stdout_size")
        stderr_size = receipt.get("stderr_size")
        separator = (
            POSIX_V2_COMPAT_LOG_SEPARATOR
            if isinstance(stderr_size, int) and stderr_size
            else b""
        )
        valid_success_log = (
            type(stdout_size) is int
            and type(stderr_size) is int
            and stdout_size >= 0
            and stderr_size >= 0
            and len(log_raw) == stdout_size + len(separator) + stderr_size
            and (
                not separator
                or log_raw[stdout_size:stdout_size + len(separator)]
                == separator
            )
            and hashlib.sha256(log_raw[:stdout_size]).hexdigest()
            == receipt.get("stdout_sha256")
            and hashlib.sha256(
                log_raw[stdout_size + len(separator):]
            ).hexdigest() == receipt.get("stderr_sha256")
        )
        if not valid_success_log:
            issues.append("compat verifier worker-log binding mismatch")
    return receipt, receipt_path, list(dict.fromkeys(issues))
