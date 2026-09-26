"""POSIX compatibility execution authority for severity adjudication workers."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import threading
from typing import Any, Callable, Mapping

from artifact_ledger import (
    read_artifact_ledger,
    validate_work_unit_artifacts,
)
from phase_io_contracts import LaunchSpec, PhaseIOContract, resolve_phase_io_contract
from posix_compat_model_incorporation import (
    commit_validated_posix_compat_model_execution,
)
from rooted_path_io import (
    RootedPathIOError,
    checked_directory,
    durable_write_once_bytes,
    lexists,
    read_bytes,
    safe_descendant,
)
from worker_transaction import validate_worker_execution_authority
from portable_path_contract import assert_lexically_bounded_relative_path


COMPAT_WORKER_RUN_SCHEMA = (
    "plamen.severity_adjudication_worker_run.posix_compat.v1"
)
COMPAT_PLAN_SCHEMA = "plamen.posix_v2_compat_severity_plan.v1"
COMPAT_PROVIDER_SCHEMA = (
    "plamen.posix_v2_compat_severity_provider_completion.v1"
)
COMPAT_ATTEMPT_SCHEMA = "plamen.posix_v2_compat_severity_attempt.v1"
COMPAT_TRANSACTION_NAMESPACE = "posix_v2_compat_severity"
COMPAT_TRANSPORT = "posix-v2-compat"
COMPAT_BACKENDS = frozenset({"claude", "codex"})

_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_REGISTRY_LOCK = threading.RLock()
_REGISTERED_SESSIONS: dict[tuple[str, str], tuple[object, dict[str, Any]]] = {}


class SeverityCompatAuthorityError(RuntimeError):
    """A compatibility run is absent, foreign, or not replayable."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SeverityCompatAuthorityError(
                f"duplicate compatibility authority key {key!r}"
            )
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise SeverityCompatAuthorityError(
        f"non-finite compatibility JSON constant {token!r}"
    )


def _read_regular(path: Path, *, maximum: int = 32 * 1024 * 1024) -> bytes:
    try:
        raw = read_bytes(
            path,
            label=f"severity compatibility artifact {path.name}",
            require_single_link=True,
            max_bytes=maximum,
        )
    except (OSError, RootedPathIOError) as exc:
        raise SeverityCompatAuthorityError(f"{path.name} is unreadable") from exc
    if not raw:
        raise SeverityCompatAuthorityError(f"{path.name} is empty")
    return raw


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path)
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SeverityCompatAuthorityError(f"{path.name} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise SeverityCompatAuthorityError(f"{path.name} is not a JSON object")
    return value, raw


def _safe_relative(root: Path, raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or PurePosixPath(raw).as_posix() != raw:
        raise SeverityCompatAuthorityError(f"{label} path is not canonical")
    try:
        assert_lexically_bounded_relative_path(raw, label=f"{label} path")
    except ValueError as exc:
        raise SeverityCompatAuthorityError(
            f"{label} path is not canonical"
        ) from exc
    relative = PurePosixPath(raw)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise SeverityCompatAuthorityError(f"{label} path escapes the scratchpad")
    try:
        return safe_descendant(
            root, raw, allow_missing=False,
            label=f"severity compatibility {label}",
        )
    except (OSError, RootedPathIOError) as exc:
        raise SeverityCompatAuthorityError(f"{label} path is unsafe") from exc


def _session_binding(session_authority: object) -> dict[str, Any]:
    try:
        from posix_v2_compat_runtime import require_posix_v2_compat_session

        session = require_posix_v2_compat_session(session_authority)
        binding = dict(session.binding)
    except Exception as exc:
        raise SeverityCompatAuthorityError(
            f"compatibility session authority is unavailable: {exc}"
        ) from exc
    digest = str(binding.get("session_binding_sha256") or "")
    unsigned = {key: value for key, value in binding.items() if key != "session_binding_sha256"}
    if _HEX64.fullmatch(digest) is None or _digest(unsigned) != digest:
        raise SeverityCompatAuthorityError(
            "compatibility session binding is malformed"
        )
    return binding


def register_severity_compat_session(
    session_authority: object,
    *,
    run_id: str,
    scratchpad: Path,
    project_root: Path,
) -> None:
    """Retain one already-issued opaque session for downstream exact replay."""

    root = checked_directory(scratchpad, label="severity compatibility scratchpad")
    project = checked_directory(project_root, label="severity compatibility project")
    run = str(run_id)
    binding = _session_binding(session_authority)
    if (
        not run or run != run.strip()
        or binding.get("run_id") != run
        or binding.get("backend") not in COMPAT_BACKENDS
        or binding.get("scratchpad") != os.fspath(root)
        or binding.get("project_root") != os.fspath(project)
    ):
        raise SeverityCompatAuthorityError(
            "compatibility session registration is foreign"
        )
    key = (os.fspath(root), run)
    with _REGISTRY_LOCK:
        current = _REGISTERED_SESSIONS.get(key)
        if current is not None and current[0] is not session_authority:
            raise SeverityCompatAuthorityError(
                "compatibility session registration collision"
            )
        _REGISTERED_SESSIONS[key] = (session_authority, binding)


def _registered_session(
    root: Path, *, run_id: str, project_root: Path,
) -> tuple[object, dict[str, Any]]:
    checked_root = checked_directory(root, label="severity compatibility scratchpad")
    checked_project = checked_directory(
        project_root, label="severity compatibility project"
    )
    key = (os.fspath(checked_root), run_id)
    with _REGISTRY_LOCK:
        registered = _REGISTERED_SESSIONS.get(key)
    if registered is None:
        raise SeverityCompatAuthorityError(
            "registered compatibility session authority is absent"
        )
    authority, recorded = registered
    current = _session_binding(authority)
    if (
        current != recorded
        or current.get("scratchpad") != key[0]
        or current.get("project_root")
        != os.fspath(checked_project)
        or current.get("run_id") != run_id
        or current.get("backend") not in COMPAT_BACKENDS
    ):
        raise SeverityCompatAuthorityError(
            "registered compatibility session authority changed"
        )
    return authority, current


def _prepared(root: Path, shard_id: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    from severity_adjudication_work import (
        MANIFEST_NAME, WORK_PLAN_NAME, validate_prepared_work,
    )

    plan, plan_raw = _read_json(root / WORK_PLAN_NAME)
    manifest, manifest_raw = _read_json(root / MANIFEST_NAME)
    matches = [
        row for row in plan.get("shards") or []
        if isinstance(row, Mapping) and row.get("shard_id") == shard_id
    ]
    if len(matches) != 1:
        raise SeverityCompatAuthorityError("compatibility shard is not unique")
    shard = dict(matches[0])
    intent_name = shard.get("launch_intent_file")
    if not isinstance(intent_name, str) or Path(intent_name).name != intent_name:
        raise SeverityCompatAuthorityError("compatibility launch intent is unsafe")
    intent, intent_raw = _read_json(root / intent_name)
    issues = validate_prepared_work(root)
    if issues:
        raise SeverityCompatAuthorityError(
            "prepared adjudication work is invalid: " + "; ".join(issues)
        )
    if (
        _read_regular(root / WORK_PLAN_NAME) != plan_raw
        or _read_regular(root / MANIFEST_NAME) != manifest_raw
        or _read_regular(root / intent_name) != intent_raw
    ):
        raise SeverityCompatAuthorityError(
            "prepared adjudication work changed during replay"
        )
    if (
        plan.get("transport") != COMPAT_TRANSPORT
        or plan.get("backend") not in COMPAT_BACKENDS
        or intent.get("transport") != COMPAT_TRANSPORT
        or intent.get("effective_backend") != plan.get("backend")
        or intent.get("shard_id") != shard_id
        or intent.get("plan_digest") != plan.get("plan_digest")
        or intent.get("manifest_digest") != manifest.get("manifest_digest")
    ):
        raise SeverityCompatAuthorityError(
            "compatibility prepared-work transport binding is invalid"
        )
    return plan, manifest, shard


def severity_compat_contract_launch(
    scratchpad: Path,
    *,
    shard_id: str,
    pipeline: str,
    mode: str,
    ecosystem: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    """Derive the exact standard MODEL contract for one compatibility shard."""

    root = checked_directory(scratchpad, label="severity compatibility scratchpad")
    plan, _manifest, shard = _prepared(root, shard_id)
    inputs = (
        "severity_adjudication_work_plan.json",
        "severity_adjudication_work_manifest.json",
        str(shard["launch_intent_file"]),
        str(shard["context_file"]),
        str(shard["prompt_file"]),
        str(shard["tool_policy_file"]),
    )
    outputs = tuple(
        str(value) for _candidate, value in sorted(
            (shard.get("expected_outputs") or {}).items()
        )
    )
    contract = resolve_phase_io_contract(
        pipeline=pipeline, mode=mode, ecosystem=ecosystem,
        backend=str(plan["backend"]),
        phase="severity_adjudication_shadow",
        work_unit_id=f"worker.{shard_id}",
        exact_inputs=inputs, exact_outputs=outputs,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model=str(plan["effective_model"]),
        timeout_s=int(plan["timeout_seconds_per_worker"]),
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    return contract, launch


def severity_compat_label(contract: PhaseIOContract) -> str:
    prefix = "worker."
    if (
        contract.phase != "severity_adjudication_shadow"
        or not contract.work_unit_id.startswith(prefix)
    ):
        raise SeverityCompatAuthorityError(
            "compatibility label requires a severity worker contract"
        )
    return "severity_worker_" + contract.work_unit_id.removeprefix(prefix)


def _output_rows(root: Path, shard: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    from severity_adjudication_work import severity_adjudication_output_digest

    incorporation: list[dict[str, Any]] = []
    receipt_rows: dict[str, dict[str, Any]] = {}
    for candidate, raw_name in sorted((shard.get("expected_outputs") or {}).items()):
        name = str(raw_name)
        if Path(name).name != name:
            raise SeverityCompatAuthorityError("compatibility output name is unsafe")
        raw = _read_regular(root / name)
        proposal_digest = severity_adjudication_output_digest(root / name, raw)
        sha256 = hashlib.sha256(raw).hexdigest()
        incorporation.append({
            "canonical_identity": f"scratchpad:{name}",
            "sha256": sha256,
            "size": len(raw),
        })
        receipt_rows[str(candidate)] = {
            "file": name,
            "sha256": sha256,
            "size_bytes": len(raw),
            "proposal_digest": proposal_digest,
        }
    return incorporation, receipt_rows


def _write_once(path: Path, raw: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    durable_write_once_bytes(path, raw)


def _publish_exact(
    path: Path,
    raw: bytes,
    atomic_write: Callable[[Path, bytes], None],
) -> None:
    try:
        existing = _read_regular(path)
    except SeverityCompatAuthorityError:
        if lexists(path):
            raise
        atomic_write(path, raw)
        return
    if existing != raw:
        raise SeverityCompatAuthorityError(
            f"compatibility authority collision: {path.name}"
        )


def _publish_committed_worker_run(
    *,
    root: Path,
    project: Path,
    plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    shard: Mapping[str, Any],
    contract: PhaseIOContract,
    launch: LaunchSpec,
    expected_label: str,
    expected_attempt: int,
    expected_prompt_sha256: str,
    atomic_write: Callable[[Path, bytes], None],
) -> dict[str, Any]:
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    execution = unit.get("execution_authority") if isinstance(unit, Mapping) else None
    if not (
        isinstance(unit, Mapping)
        and unit.get("semantic_status") == "ACTIVE"
        and unit.get("execution_state") == "OUTPUT_COMMITTED"
        and unit.get("model_invoked") is True
        and isinstance(execution, Mapping)
    ):
        raise SeverityCompatAuthorityError(
            "compatibility MODEL execution authority is absent"
        )
    normalized = validate_worker_execution_authority(
        scratchpad=root, authority=execution, contract=contract,
        launch=launch, run_id=str(plan["run_id"]),
    )
    attempt_path = _safe_relative(
        root, normalized["attempt_completion_relative_path"],
        "attempt completion",
    )
    transaction_plan, _transaction_plan_raw = _read_json(
        attempt_path.parent / "plan.json"
    )
    label = transaction_plan.get("label")
    attempt = transaction_plan.get("outer_attempt")
    prompt_sha256 = transaction_plan.get("prompt_sha256")
    session_sha = transaction_plan.get("session_binding_sha256")
    if (
        label != expected_label
        or attempt != expected_attempt
        or prompt_sha256 != expected_prompt_sha256
        or _HEX64.fullmatch(str(session_sha or "")) is None
    ):
        raise SeverityCompatAuthorityError(
            "committed compatibility attempt differs from requested recovery"
        )
    session_authority, _current_session = _registered_session(
        root, run_id=str(plan["run_id"]), project_root=project,
    )
    from verifier_model_execution_authority import (
        replay_posix_v2_compat_dynamic_verifier_receipt,
    )

    compat, compat_path, compat_issues = (
        replay_posix_v2_compat_dynamic_verifier_receipt(
            scratchpad=root,
            config={"_run_id": plan["run_id"], "project_root": os.fspath(project)},
            contract=contract, launch=launch, label=str(label),
            attempt=int(attempt), prompt_sha256=str(prompt_sha256),
            session_authority=session_authority,
            expected_session_binding_sha256=str(session_sha),
        )
    )
    if compat_issues or compat is None or compat_path is None:
        raise SeverityCompatAuthorityError(
            "committed compatibility receipt is invalid: "
            + "; ".join(compat_issues or ["receipt absent"])
        )
    _incorporation_outputs, receipt_outputs = _output_rows(root, shard)
    intent, _intent_raw = _read_json(root / str(shard["launch_intent_file"]))
    compat_raw = _read_regular(compat_path)
    unsigned = {
        "schema_version": COMPAT_WORKER_RUN_SCHEMA,
        "authority_kind": "POSIX_V2_COMPAT_MODEL_PHASE_IO",
        "run_id": plan["run_id"], "shard_id": shard["shard_id"],
        "plan_digest": plan["plan_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "intent_file": shard["launch_intent_file"],
        "intent_digest": intent["intent_digest"],
        "worker_identity": intent["worker_identity"],
        "invocation_id": intent["invocation_id"],
        "backend": plan["backend"], "effective_model": plan["effective_model"],
        "assessor_principals": intent["assessor_principals"],
        "phase_io_owner_key": contract.key,
        "phase_io_contract_digest": contract.digest,
        "phase_io_launch_digest": launch.digest,
        "model_execution_authority_digest": normalized["authority_digest"],
        "compatibility_label": label, "compatibility_attempt": attempt,
        "prompt_sha256": prompt_sha256,
        "compatibility_receipt_relative_path": compat_path.relative_to(root).as_posix(),
        "compatibility_receipt_file_sha256": hashlib.sha256(compat_raw).hexdigest(),
        "compatibility_receipt_sha256": compat["receipt_sha256"],
        "session_binding_sha256": session_sha,
        "completion_status": "COMPLETED", "outputs": receipt_outputs,
    }
    worker_run = {**unsigned, "receipt_digest": _digest(unsigned)}
    suffix = str(shard["launch_intent_file"]).removeprefix(
        "severity_adjudication_launch_intent."
    ).removesuffix(".json")
    worker_path = root / f"severity_adjudication_worker_run.{suffix}.json"
    validated = validate_severity_compat_worker_run(
        root, next(iter(receipt_outputs)), worker_run
    )
    _publish_exact(worker_path, _canonical(worker_run) + b"\n", atomic_write)
    return validated


def commit_severity_compat_worker_run(
    scratchpad: Path,
    *,
    project_root: Path,
    shard_id: str,
    pipeline: str,
    mode: str,
    ecosystem: str,
    label: str,
    attempt: int,
    prompt_sha256: str,
    session_authority: object,
    atomic_write: Callable[[Path, bytes], None] = _write_once,
) -> dict[str, Any]:
    """Commit a real compat receipt through standard MODEL PhaseIO authority."""

    root = checked_directory(scratchpad, label="severity compatibility scratchpad")
    project = checked_directory(project_root, label="severity compatibility project")
    plan, manifest, shard = _prepared(root, shard_id)
    contract, launch = severity_compat_contract_launch(
        root, shard_id=shard_id, pipeline=pipeline, mode=mode,
        ecosystem=ecosystem,
    )
    if label != severity_compat_label(contract):
        raise SeverityCompatAuthorityError("compatibility worker label is foreign")
    if type(attempt) is not int or attempt < 1:
        raise SeverityCompatAuthorityError("compatibility attempt is invalid")
    prompt_raw = _read_regular(root / str(shard["prompt_file"]))
    if (
        _HEX64.fullmatch(str(prompt_sha256)) is None
        or hashlib.sha256(prompt_raw).hexdigest() != prompt_sha256
    ):
        raise SeverityCompatAuthorityError("compatibility prompt binding drifted")
    register_severity_compat_session(
        session_authority, run_id=str(plan["run_id"]),
        scratchpad=root, project_root=project,
    )
    prior_unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if (
        isinstance(prior_unit, Mapping)
        and prior_unit.get("semantic_status") == "ACTIVE"
        and prior_unit.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        return _publish_committed_worker_run(
            root=root, project=project, plan=plan, manifest=manifest,
            shard=shard, contract=contract, launch=launch,
            expected_label=label, expected_attempt=attempt,
            expected_prompt_sha256=prompt_sha256,
            atomic_write=atomic_write,
        )
    session_binding = _session_binding(session_authority)
    output_rows, receipt_outputs = _output_rows(root, shard)
    intent, _intent_raw = _read_json(root / str(shard["launch_intent_file"]))
    from verifier_model_execution_authority import (
        replay_posix_v2_compat_dynamic_verifier_receipt,
    )

    receipt, receipt_path, receipt_issues = (
        replay_posix_v2_compat_dynamic_verifier_receipt(
            scratchpad=root,
            config={"_run_id": plan["run_id"], "project_root": os.fspath(project)},
            contract=contract, launch=launch, label=label, attempt=attempt,
            prompt_sha256=prompt_sha256, session_authority=session_authority,
        )
    )
    if receipt_issues or receipt is None or receipt_path is None:
        raise SeverityCompatAuthorityError(
            "compatibility execution receipt is invalid: "
            + "; ".join(receipt_issues or ["receipt absent"])
        )
    issues = commit_validated_posix_compat_model_execution(
        scratchpad=root, project_root=project, run_id=str(plan["run_id"]),
        contract=contract, launch=launch, label=label, attempt=attempt,
        prompt_sha256=prompt_sha256, receipt=receipt,
        receipt_path=receipt_path, session_authority=session_authority,
        atomic_write=atomic_write, outputs=output_rows,
        plan_schema=COMPAT_PLAN_SCHEMA, provider_schema=COMPAT_PROVIDER_SCHEMA,
        attempt_schema=COMPAT_ATTEMPT_SCHEMA,
        transaction_namespace=COMPAT_TRANSACTION_NAMESPACE,
        plan_bindings={
            "session_binding": session_binding,
            "session_binding_sha256": session_binding["session_binding_sha256"],
            "severity_manifest_digest": manifest["manifest_digest"],
            "severity_plan_digest": plan["plan_digest"],
            "severity_intent_digest": intent["intent_digest"],
            "severity_shard_id": shard_id,
        },
        provider_bindings={
            "session_binding_sha256": session_binding["session_binding_sha256"],
            "severity_plan_digest": plan["plan_digest"],
            "severity_intent_digest": intent["intent_digest"],
        },
    )
    if issues:
        raise SeverityCompatAuthorityError(
            "compatibility MODEL incorporation failed: " + "; ".join(issues)
        )
    return _publish_committed_worker_run(
        root=root, project=project, plan=plan, manifest=manifest,
        shard=shard, contract=contract, launch=launch,
        expected_label=label, expected_attempt=attempt,
        expected_prompt_sha256=prompt_sha256,
        atomic_write=atomic_write,
    )


_WORKER_FIELDS = {
    "schema_version", "authority_kind", "run_id", "shard_id", "plan_digest",
    "manifest_digest", "intent_file", "intent_digest", "worker_identity",
    "invocation_id", "backend", "effective_model", "assessor_principals",
    "phase_io_owner_key", "phase_io_contract_digest", "phase_io_launch_digest",
    "model_execution_authority_digest", "compatibility_label",
    "compatibility_attempt", "prompt_sha256",
    "compatibility_receipt_relative_path",
    "compatibility_receipt_file_sha256", "compatibility_receipt_sha256",
    "session_binding_sha256", "completion_status", "outputs", "receipt_digest",
}
_PLAN_FIELDS = {
    "schema", "run_id", "phase", "work_unit_id", "generation",
    "contract_digest", "launch_digest", "input_set_digest",
    "output_prestate_digest", "outer_attempt", "label", "model",
    "transport", "timeout_seconds", "prompt_sha256",
    "compatibility_receipt_relative_path",
    "compatibility_receipt_file_sha256", "compatibility_receipt_sha256",
    "outputs", "session_binding", "session_binding_sha256",
    "severity_manifest_digest", "severity_plan_digest",
    "severity_intent_digest", "severity_shard_id", "work_plan_digest",
}
_PROVIDER_FIELDS = {
    "schema", "run_id", "phase", "work_unit_id", "generation",
    "work_plan_digest", "attempt_id", "outer_attempt", "label", "model",
    "contract_digest", "launch_digest", "input_set_digest",
    "output_prestate_digest", "compatibility_receipt_relative_path",
    "compatibility_receipt_file_sha256", "compatibility_receipt_sha256",
    "output_source_mode", "outputs", "session_binding_sha256",
    "severity_plan_digest", "severity_intent_digest", "completion_sha256",
}
_SESSION_FIELDS = {
    "schema", "mode", "run_id", "backend", "project_root",
    "project_root_identity_sha256", "scratchpad",
    "scratchpad_identity_sha256", "native_broker_authority", "wer_authority",
    "creator_pid", "interpreter_nonce_sha256", "session_binding_sha256",
}


def validate_severity_compat_worker_run(
    scratchpad: Path,
    candidate_id: str,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay the standard MODEL and nested POSIX receipt authority."""

    root = checked_directory(scratchpad, label="severity compatibility scratchpad")
    value = dict(receipt)
    if (
        set(value) != _WORKER_FIELDS
        or value.get("schema_version") != COMPAT_WORKER_RUN_SCHEMA
        or value.get("authority_kind") != "POSIX_V2_COMPAT_MODEL_PHASE_IO"
        or value.get("receipt_digest") != _digest({
            key: item for key, item in value.items() if key != "receipt_digest"
        })
    ):
        raise SeverityCompatAuthorityError(
            "compatibility worker-run schema or digest is invalid"
        )
    shard_id = str(value.get("shard_id") or "")
    plan, manifest, shard = _prepared(root, shard_id)
    candidates = shard.get("candidate_ids") or []
    if candidate_id not in candidates:
        raise SeverityCompatAuthorityError(
            "candidate has no compatibility shard owner"
        )
    owner = str(value.get("phase_io_owner_key") or "")
    dimensions = owner.split("/")
    if (
        len(dimensions) != 6
        or dimensions[3] != plan.get("backend")
        or dimensions[4] != "severity_adjudication_shadow"
        or dimensions[5] != f"worker.{shard_id}"
    ):
        raise SeverityCompatAuthorityError(
            "compatibility MODEL owner key is invalid"
        )
    contract, launch = severity_compat_contract_launch(
        root, shard_id=shard_id, pipeline=dimensions[0], mode=dimensions[1],
        ecosystem=dimensions[2],
    )
    project = checked_directory(
        str(plan["source_root"]), label="severity compatibility project"
    )
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    execution = unit.get("execution_authority") if isinstance(unit, Mapping) else None
    incorporation_outputs, receipt_outputs = _output_rows(root, shard)
    intent, _intent_raw = _read_json(root / str(shard["launch_intent_file"]))
    common_valid = (
        value.get("run_id") == plan.get("run_id")
        and value.get("plan_digest") == plan.get("plan_digest")
        and value.get("manifest_digest") == manifest.get("manifest_digest")
        and value.get("intent_file") == shard.get("launch_intent_file")
        and value.get("intent_digest") == intent.get("intent_digest")
        and value.get("worker_identity") == intent.get("worker_identity")
        and value.get("invocation_id") == intent.get("invocation_id")
        and value.get("backend") == plan.get("backend")
        and value.get("effective_model") == plan.get("effective_model")
        and value.get("assessor_principals") == intent.get("assessor_principals")
        and value.get("phase_io_owner_key") == contract.key
        and value.get("phase_io_contract_digest") == contract.digest
        and value.get("phase_io_launch_digest") == launch.digest
        and value.get("completion_status") == "COMPLETED"
        and value.get("outputs") == receipt_outputs
        and isinstance(execution, Mapping)
    )
    if not common_valid:
        raise SeverityCompatAuthorityError(
            "compatibility worker-run prepared/PhaseIO binding mismatch"
        )
    artifact_issues = validate_work_unit_artifacts(
        root, project, contract, launch, run_id=str(plan["run_id"]), actor="MODEL",
    )
    if artifact_issues:
        raise SeverityCompatAuthorityError(
            "compatibility MODEL artifacts are invalid: " + "; ".join(artifact_issues)
        )
    normalized = validate_worker_execution_authority(
        scratchpad=root, authority=execution, contract=contract,
        launch=launch, run_id=str(plan["run_id"]),
    )
    if value.get("model_execution_authority_digest") != normalized.get("authority_digest"):
        raise SeverityCompatAuthorityError(
            "compatibility MODEL execution digest mismatch"
        )
    attempt_path = _safe_relative(
        root, normalized["attempt_completion_relative_path"], "attempt completion"
    )
    transaction_plan, _transaction_plan_raw = _read_json(attempt_path.parent / "plan.json")
    provider_path = _safe_relative(
        root, normalized["provider_completion_relative_path"],
        "provider completion",
    )
    provider, _provider_raw = _read_json(provider_path)
    historical_session = transaction_plan.get("session_binding")
    session_sha = str(transaction_plan.get("session_binding_sha256") or "")
    if not isinstance(historical_session, Mapping):
        raise SeverityCompatAuthorityError("historical session binding is absent")
    historical_unsigned = {
        key: item for key, item in historical_session.items()
        if key != "session_binding_sha256"
    }
    session_authority, current_session = _registered_session(
        root, run_id=str(plan["run_id"]), project_root=project,
    )
    stable = {
        "schema", "mode", "run_id", "backend", "project_root",
        "project_root_identity_sha256", "scratchpad",
        "scratchpad_identity_sha256", "native_broker_authority", "wer_authority",
    }
    if (
        set(historical_session) != _SESSION_FIELDS
        or historical_session.get("session_binding_sha256") != session_sha
        or _digest(historical_unsigned) != session_sha
        or any(historical_session.get(key) != current_session.get(key) for key in stable)
    ):
        raise SeverityCompatAuthorityError(
            "historical compatibility session is foreign"
        )
    label = str(value.get("compatibility_label") or "")
    attempt = value.get("compatibility_attempt")
    prompt_sha256 = str(value.get("prompt_sha256") or "")
    if (
        label != severity_compat_label(contract)
        or type(attempt) is not int or attempt < 1
        or _HEX64.fullmatch(prompt_sha256) is None
        or set(transaction_plan) != _PLAN_FIELDS
        or transaction_plan.get("schema") != COMPAT_PLAN_SCHEMA
        or transaction_plan.get("run_id") != plan.get("run_id")
        or transaction_plan.get("phase") != contract.phase
        or transaction_plan.get("work_unit_id") != contract.work_unit_id
        or transaction_plan.get("generation") != normalized.get("generation")
        or transaction_plan.get("contract_digest") != contract.digest
        or transaction_plan.get("launch_digest") != launch.digest
        or transaction_plan.get("input_set_digest") != unit.get("input_set_digest")
        or transaction_plan.get("output_prestate_digest")
        != unit.get("output_prestate_digest")
        or transaction_plan.get("session_binding") != historical_session
        or transaction_plan.get("session_binding_sha256") != session_sha
        or transaction_plan.get("severity_manifest_digest") != manifest.get("manifest_digest")
        or transaction_plan.get("severity_plan_digest") != plan.get("plan_digest")
        or transaction_plan.get("severity_intent_digest") != intent.get("intent_digest")
        or transaction_plan.get("severity_shard_id") != shard_id
        or transaction_plan.get("outer_attempt") != attempt
        or transaction_plan.get("label") != label
        or transaction_plan.get("model") != launch.model
        or transaction_plan.get("transport") != launch.exec_mode
        or transaction_plan.get("timeout_seconds") != launch.timeout_s
        or transaction_plan.get("prompt_sha256") != prompt_sha256
        or transaction_plan.get("compatibility_receipt_relative_path")
        != value.get("compatibility_receipt_relative_path")
        or transaction_plan.get("compatibility_receipt_file_sha256")
        != value.get("compatibility_receipt_file_sha256")
        or transaction_plan.get("compatibility_receipt_sha256")
        != value.get("compatibility_receipt_sha256")
        or transaction_plan.get("outputs") != incorporation_outputs
        or transaction_plan.get("work_plan_digest") != normalized.get("work_plan_digest")
        or transaction_plan.get("work_plan_digest") != _digest({
            key: item for key, item in transaction_plan.items()
            if key != "work_plan_digest"
        })
    ):
        raise SeverityCompatAuthorityError(
            "compatibility transaction plan binding mismatch"
        )
    provider_unsigned = {
        key: item for key, item in provider.items() if key != "completion_sha256"
    }
    if (
        set(provider) != _PROVIDER_FIELDS
        or provider.get("schema") != COMPAT_PROVIDER_SCHEMA
        or provider.get("run_id") != plan.get("run_id")
        or provider.get("phase") != contract.phase
        or provider.get("work_unit_id") != contract.work_unit_id
        or provider.get("generation") != normalized.get("generation")
        or provider.get("work_plan_digest") != normalized.get("work_plan_digest")
        or provider.get("attempt_id") != normalized.get("attempt_id")
        or provider.get("outer_attempt") != attempt
        or provider.get("label") != label
        or provider.get("model") != launch.model
        or provider.get("contract_digest") != contract.digest
        or provider.get("launch_digest") != launch.digest
        or provider.get("input_set_digest") != unit.get("input_set_digest")
        or provider.get("output_prestate_digest")
        != unit.get("output_prestate_digest")
        or provider.get("compatibility_receipt_relative_path")
        != value.get("compatibility_receipt_relative_path")
        or provider.get("compatibility_receipt_file_sha256")
        != value.get("compatibility_receipt_file_sha256")
        or provider.get("compatibility_receipt_sha256")
        != value.get("compatibility_receipt_sha256")
        or provider.get("output_source_mode") != "WORKER_FILE_OUTPUTS"
        or provider.get("outputs") != incorporation_outputs
        or provider.get("session_binding_sha256") != session_sha
        or provider.get("severity_plan_digest") != plan.get("plan_digest")
        or provider.get("severity_intent_digest") != intent.get("intent_digest")
        or provider.get("completion_sha256")
        != normalized.get("provider_completion_digest")
        or provider.get("completion_sha256")
        != hashlib.sha256(_canonical(provider_unsigned) + b"\n").hexdigest()
    ):
        raise SeverityCompatAuthorityError(
            "compatibility provider completion binding mismatch"
        )
    from verifier_model_execution_authority import (
        replay_posix_v2_compat_dynamic_verifier_receipt,
    )

    compat, compat_path, compat_issues = replay_posix_v2_compat_dynamic_verifier_receipt(
        scratchpad=root,
        config={"_run_id": plan["run_id"], "project_root": os.fspath(project)},
        contract=contract, launch=launch, label=label, attempt=attempt,
        prompt_sha256=prompt_sha256, session_authority=session_authority,
        expected_session_binding_sha256=session_sha,
    )
    if compat_issues or compat is None or compat_path is None:
        raise SeverityCompatAuthorityError(
            "nested compatibility receipt is invalid: "
            + "; ".join(compat_issues or ["receipt absent"])
        )
    staged_context = compat.get("staged_output_context")
    boundary_digest = (
        staged_context.get("boundary_before_sha256")
        if isinstance(staged_context, Mapping) else None
    )
    if (
        not isinstance(boundary_digest, str)
        or _HEX64.fullmatch(boundary_digest) is None
    ):
        raise SeverityCompatAuthorityError(
            "nested compatibility staged boundary is malformed"
        )
    try:
        from severity_compat_runtime import (
            build_severity_compat_staged_gate_binding,
        )

        expected_context, expected_validator, expected_inputs = (
            build_severity_compat_staged_gate_binding(
                plan, shard, boundary_digest, contract=contract,
                input_bindings=unit["input_bindings"],
            )
        )
    except Exception as exc:
        raise SeverityCompatAuthorityError(
            f"nested compatibility staged gate cannot be replayed: {exc}"
        ) from exc
    if (
        staged_context != expected_context
        or compat.get("staged_output_validator_binding") != expected_validator
        or compat.get("staged_output_input_bindings") != expected_inputs
        or compat.get("staged_output_rejection_reasons") != []
    ):
        raise SeverityCompatAuthorityError(
            "nested compatibility staged gate binding mismatch"
        )
    compat_raw = _read_regular(compat_path)
    if (
        value.get("compatibility_receipt_relative_path")
        != compat_path.relative_to(root).as_posix()
        or value.get("compatibility_receipt_file_sha256")
        != hashlib.sha256(compat_raw).hexdigest()
        or value.get("compatibility_receipt_sha256") != compat.get("receipt_sha256")
        or value.get("session_binding_sha256") != session_sha
    ):
        raise SeverityCompatAuthorityError(
            "compatibility worker-run nested receipt binding mismatch"
        )
    return value


__all__ = [
    "COMPAT_ATTEMPT_SCHEMA", "COMPAT_PLAN_SCHEMA", "COMPAT_PROVIDER_SCHEMA",
    "COMPAT_TRANSACTION_NAMESPACE", "COMPAT_TRANSPORT", "COMPAT_WORKER_RUN_SCHEMA",
    "SeverityCompatAuthorityError", "commit_severity_compat_worker_run",
    "register_severity_compat_session", "severity_compat_contract_launch",
    "severity_compat_label", "validate_severity_compat_worker_run",
]
