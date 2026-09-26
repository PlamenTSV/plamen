"""Standard PhaseIO incorporation for a validated POSIX compat MODEL run."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    validate_work_unit_artifacts,
)
from phase_io_contracts import (
    ConditionalOutputReceipt,
    LaunchSpec,
    PhaseIOContract,
)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _write_once(
    path: Path, value: Mapping[str, Any],
    atomic_write: Callable[[Path, bytes], None],
) -> None:
    raw = _canonical(value) + b"\n"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != raw:
            raise ArtifactLedgerError(
                f"compat MODEL authority collision: {path.name}"
            )
        return
    atomic_write(path, raw)


def commit_validated_posix_compat_model_execution(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    contract: PhaseIOContract,
    launch: LaunchSpec,
    label: str,
    attempt: int,
    prompt_sha256: str,
    receipt: Mapping[str, Any],
    receipt_path: Path,
    session_authority: object,
    atomic_write: Callable[[Path, bytes], None],
    outputs: Sequence[Mapping[str, Any]],
    plan_schema: str,
    provider_schema: str,
    attempt_schema: str = "plamen.posix_v2_compat_model_attempt.v1",
    transaction_namespace: str = "posix_v2_compat_model",
    plan_bindings: Mapping[str, Any] | None = None,
    provider_bindings: Mapping[str, Any] | None = None,
) -> list[str]:
    """Revalidate a live receipt and project standard MODEL authority."""

    root = Path(scratchpad).resolve()
    from posix_v2_compat_runtime import require_posix_v2_compat_session

    session = require_posix_v2_compat_session(session_authority)
    binding = dict(session.binding)
    backend = str(contract.backend)
    if (
        backend not in {"codex", "claude"}
        or launch.backend != backend
        or binding.get("run_id") != run_id
        or binding.get("scratchpad") != os.fspath(root)
        or binding.get("project_root")
        != os.fspath(Path(project_root).resolve())
        or binding.get("backend") != backend
        or receipt.get("backend") != backend
        or receipt.get("session_binding_sha256")
        != binding.get("session_binding_sha256")
    ):
        return ["compat MODEL live session binding is foreign"]
    from verifier_model_execution_authority import (
        replay_posix_v2_compat_dynamic_verifier_receipt,
    )

    replayed, replayed_path, issues = replay_posix_v2_compat_dynamic_verifier_receipt(
        scratchpad=root,
        config={"_run_id": run_id, "project_root": os.fspath(project_root)},
        contract=contract, launch=launch, label=label, attempt=attempt,
        prompt_sha256=prompt_sha256, session_authority=session_authority,
    )
    if issues:
        return list(issues)
    if replayed != dict(receipt) or replayed_path != Path(receipt_path):
        return ["compat MODEL receipt changed before incorporation"]
    receipt_file = Path(receipt_path)
    receipt_raw = receipt_file.read_bytes()
    unit = read_artifact_ledger(root).get("work_units", {}).get(contract.key)
    if not isinstance(unit, Mapping):
        return ["compat MODEL INPUTS_BOUND authority disappeared"]
    invocation_id = str(receipt.get("invocation_id") or "")
    attempt_id = f"compat-attempt-{int(attempt):04d}-{invocation_id[:16]}"
    transaction = (
        root / ".worker_transactions" / transaction_namespace
        / contract.work_unit_id / attempt_id
    )
    receipt_relative = receipt_file.relative_to(root).as_posix()
    generation = hashlib.sha256(
        f"{contract.digest}:{launch.digest}".encode("ascii")
    ).hexdigest()
    normalized_outputs = sorted(
        (dict(row) for row in outputs),
        key=lambda row: str(row.get("canonical_identity") or ""),
    )
    output_identities = tuple(
        str(row.get("canonical_identity") or "")
        for row in normalized_outputs
    )
    expected_output_identities = tuple(sorted(
        spec.identity for spec in contract.outputs
    ))
    if (
        len(output_identities) != len(set(output_identities))
        or tuple(sorted(output_identities)) != expected_output_identities
    ):
        return [
            "compat MODEL outputs differ from the registered exact output "
            "denominator"
        ]
    plan: dict[str, Any] = {
        "schema": plan_schema,
        "run_id": run_id,
        "phase": contract.phase,
        "work_unit_id": contract.work_unit_id,
        "generation": generation,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "input_set_digest": receipt["phase_io_input_set_digest"],
        "output_prestate_digest": receipt["phase_io_output_prestate_digest"],
        "outer_attempt": int(attempt),
        "label": label,
        "model": launch.model,
        "transport": launch.exec_mode,
        "timeout_seconds": launch.timeout_s,
        "prompt_sha256": receipt["prompt_sha256"],
        "compatibility_receipt_relative_path": receipt_relative,
        "compatibility_receipt_file_sha256": hashlib.sha256(
            receipt_raw
        ).hexdigest(),
        "compatibility_receipt_sha256": receipt["receipt_sha256"],
        "outputs": normalized_outputs,
    }
    if set(plan) & set(plan_bindings or {}):
        return ["compat MODEL plan extension overrides required bindings"]
    plan.update(plan_bindings or {})
    plan["work_plan_digest"] = _digest(plan)
    _write_once(transaction / "plan.json", plan, atomic_write)

    provider_path = transaction / "provider_completion.json"
    provider: dict[str, Any] = {
        "schema": provider_schema,
        "run_id": run_id,
        "phase": contract.phase,
        "work_unit_id": contract.work_unit_id,
        "generation": generation,
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "outer_attempt": int(attempt),
        "label": label,
        "model": launch.model,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "input_set_digest": plan["input_set_digest"],
        "output_prestate_digest": plan["output_prestate_digest"],
        "compatibility_receipt_relative_path": receipt_relative,
        "compatibility_receipt_file_sha256": plan[
            "compatibility_receipt_file_sha256"
        ],
        "compatibility_receipt_sha256": receipt["receipt_sha256"],
        "output_source_mode": "WORKER_FILE_OUTPUTS",
        "outputs": normalized_outputs,
    }
    if set(provider) & set(provider_bindings or {}):
        return ["compat MODEL provider extension overrides required bindings"]
    provider.update(provider_bindings or {})
    provider["completion_sha256"] = hashlib.sha256(
        _canonical(provider) + b"\n"
    ).hexdigest()
    _write_once(provider_path, provider, atomic_write)

    provider_relative = provider_path.relative_to(root).as_posix()
    completion_path = transaction / "completion.json"
    completion: dict[str, Any] = {
        "schema": attempt_schema,
        "run_id": run_id, "phase": contract.phase,
        "work_unit_id": contract.work_unit_id, "generation": generation,
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "provider_completion_relative_path": provider_relative,
        "provider_completion_digest": provider["completion_sha256"],
        "canonical_projection_state": "PENDING_PHASE_IO",
    }
    completion["completion_digest"] = _digest(completion)
    _write_once(completion_path, completion, atomic_write)

    incorporation_path = transaction / "incorporation.json"
    incorporation: dict[str, Any] = {
        "schema": "plamen.worker_phaseio_incorporation.v1",
        "run_id": run_id, "phase": contract.phase,
        "work_unit_id": contract.work_unit_id, "generation": generation,
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "provider_completion_digest": provider["completion_sha256"],
        "contract_digest": contract.digest, "launch_digest": launch.digest,
        "input_set_digest": plan["input_set_digest"],
        "projection_state": "COMPLETE",
        "projected_members": normalized_outputs,
    }
    incorporation["incorporation_digest"] = _digest(incorporation)
    _write_once(incorporation_path, incorporation, atomic_write)

    authority: dict[str, Any] = {
        "schema": "plamen.worker_execution_authority.v1",
        "run_id": run_id, "phase": contract.phase,
        "work_unit_id": contract.work_unit_id, "generation": generation,
        "work_plan_digest": plan["work_plan_digest"],
        "attempt_id": attempt_id,
        "attempt_completion_relative_path": completion_path.relative_to(root).as_posix(),
        "attempt_completion_digest": completion["completion_digest"],
        "provider_completion_relative_path": provider_relative,
        "provider_completion_digest": provider["completion_sha256"],
        "incorporation_relative_path": incorporation_path.relative_to(root).as_posix(),
        "incorporation_digest": incorporation["incorporation_digest"],
        "contract_digest": contract.digest, "launch_digest": launch.digest,
    }
    authority["authority_digest"] = _digest(authority)
    conditional_receipts = {
        spec.identity: ConditionalOutputReceipt(
            work_unit_key=contract.key,
            contract_digest=contract.digest,
            artifact_identity=spec.identity,
            condition_id=spec.condition_id,
            state="PRODUCED",
            expected_denominator=1,
            produced_identities=(spec.identity,),
        )
        for spec in contract.outputs
        if spec.artifact_class == "CONDITIONAL"
    }
    try:
        record_work_unit_artifacts(
            root, Path(project_root), contract, launch, run_id=run_id,
            actor="MODEL", execution_authority=authority,
            conditional_receipts=conditional_receipts,
        )
        return list(dict.fromkeys(validate_work_unit_artifacts(
            root, Path(project_root), contract, launch, run_id=run_id,
            actor="MODEL",
        )))
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        return [f"compat MODEL commit failed: {exc}"]
