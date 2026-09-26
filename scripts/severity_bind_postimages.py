"""Pure postimage derivation for one severity-adjudication bind.

This module computes bytes only.  It does not publish files or claim PhaseIO
or successor authority; the transaction owner must bind the returned preimages
and postimages before writing them.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Any, Mapping

from severity_adjudication_work import validate_completed_worker_run_for_candidate
from severity_decision_ledger import (
    LAUNCH_RECEIPT_SCHEMA,
    bind_severity_adjudication,
    build_severity_decision_ledger,
    parse_severity_adjudication_proposal,
    severity_adjudicator_input_digest,
)
import severity_runtime as runtime
import rooted_path_io as rio
from plamen_parsers import _read_typed_queue_work_items


class SeverityBindPostimageError(ValueError):
    """The proposed bind cannot be derived from the current exact state."""


@dataclass(frozen=True)
class SeverityBindPostimages:
    candidate_id: str
    run_id: str
    mode: str
    worker_run_digest: str
    transaction_input_bytes: Mapping[str, bytes]
    authority_read_set: Mapping[str, bytes]
    output_bytes: Mapping[str, bytes]


_MAX_BYTES = 32 * 1024 * 1024
_CANDIDATE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", re.ASCII)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SeverityBindPostimageError(
                f"duplicate severity bind JSON key {key!r}"
            )
        result[key] = value
    return result


def _constant(token: str) -> None:
    raise SeverityBindPostimageError(
        f"non-finite severity bind JSON constant {token!r}"
    )


def _strict(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs, parse_constant=_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SeverityBindPostimageError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise SeverityBindPostimageError(f"{label} is not an object")
    return value


def _compact(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(value), ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _ledger_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(
        dict(value), indent=2, ensure_ascii=False,
        allow_nan=False, sort_keys=True,
    ) + "\n").encode("utf-8")


def _read(path: Path) -> bytes:
    try:
        return rio.read_bytes(
            path, label=f"severity bind input {path.name}",
            max_bytes=_MAX_BYTES, require_single_link=True,
        )
    except (OSError, rio.RootedPathIOError) as exc:
        raise SeverityBindPostimageError(
            f"severity bind input {path.name} is unreadable"
        ) from exc


def _relative(root: Path, value: Any, label: str) -> tuple[str, Path]:
    if (
        not isinstance(value, str) or not value
        or "\\" in value or ":" in value or "\x00" in value
    ):
        raise SeverityBindPostimageError(f"{label} path is invalid")
    relative = PurePosixPath(value)
    if (
        relative.as_posix() != value or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise SeverityBindPostimageError(f"{label} path is not canonical")
    path = root.joinpath(*relative.parts)
    try:
        if not path.resolve(strict=False).is_relative_to(root.resolve(strict=True)):
            raise SeverityBindPostimageError(f"{label} path escapes scratchpad")
    except OSError as exc:
        raise SeverityBindPostimageError(f"{label} path is unsafe") from exc
    return value, path


def _capture(root: Path, names: Mapping[str, Path]) -> dict[str, bytes]:
    return {name: _read(path) for name, path in names.items()}


def _worker_authority_paths(
    root: Path, worker: Mapping[str, Any], shard: Mapping[str, Any],
) -> dict[str, Path]:
    names = {
        "severity_adjudication_work_plan.json": root / "severity_adjudication_work_plan.json",
        "severity_adjudication_work_manifest.json": root / "severity_adjudication_work_manifest.json",
    }
    for field in ("launch_intent_file", "context_file", "prompt_file", "tool_policy_file"):
        relative, path = _relative(root, shard.get(field), f"severity {field}")
        names[relative] = path
    worker_name = Path(str(shard["launch_intent_file"])).name.removeprefix(
        "severity_adjudication_launch_intent."
    ).removesuffix(".json")
    worker_name = f"severity_adjudication_worker_run.{worker_name}.json"
    names[worker_name] = root / worker_name
    if worker.get("schema_version") == "plamen.severity_adjudication_worker_run.posix_compat.v1":
        relative, path = _relative(
            root, worker.get("compatibility_receipt_relative_path"),
            "compatibility receipt",
        )
        names[relative] = path
        ledger = _strict(_read(root / "_artifact_state.json"), "artifact ledger")
        unit = (ledger.get("work_units") or {}).get(worker.get("phase_io_owner_key"))
        execution = unit.get("execution_authority") if isinstance(unit, Mapping) else None
        if not isinstance(execution, Mapping):
            raise SeverityBindPostimageError("worker execution authority is absent")
        attempt_parent: Path | None = None
        for field in (
            "attempt_completion_relative_path", "provider_completion_relative_path",
            "incorporation_relative_path",
        ):
            relative, path = _relative(root, execution.get(field), field)
            names[relative] = path
            if field == "attempt_completion_relative_path":
                attempt_parent = path.parent
        if attempt_parent is None:
            raise SeverityBindPostimageError("worker attempt path is absent")
        plan_relative = attempt_parent.relative_to(root).as_posix() + "/plan.json"
        names[plan_relative] = attempt_parent / "plan.json"
    else:
        for field in (
            "provider_arm_file", "provider_completion_file", "provider_publish_file",
        ):
            relative, path = _relative(root, worker.get(field), field)
            names[relative] = path
    return names


def _revalidate_epoch(
    root: Path, *, candidate: str, worker: Mapping[str, Any],
    decisions: Mapping[str, Mapping[str, Any]], paths: Mapping[str, Path],
    expected: Mapping[str, bytes], receipt_path: Path,
    receipt_raw: bytes | None,
) -> None:
    if validate_completed_worker_run_for_candidate(root, candidate) != worker:
        raise SeverityBindPostimageError("worker authority changed")
    runtime._validate_original_verifier_sources(root, decisions)
    if _capture(root, paths) != dict(expected):
        raise SeverityBindPostimageError("severity authority read set changed")
    present = rio.lexists(receipt_path)
    if receipt_raw is None:
        if present:
            raise SeverityBindPostimageError(
                "severity receipt roster changed during derivation"
            )
    elif not present or _read(receipt_path) != receipt_raw:
        raise SeverityBindPostimageError(
            "severity receipt changed during derivation"
        )


def _verifier_authority_paths(
    root: Path, decisions: Mapping[str, Mapping[str, Any]],
) -> dict[str, Path]:
    queue = root / "verification_queue.md"
    if not rio.lexists(queue):
        return {}
    names = {
        "verification_queue.md": queue,
        "verification_queue.work_items.json": root / "verification_queue.work_items.json",
        "verification_queue.work_plan.json": root / "verification_queue.work_plan.json",
    }
    items = {
        item.work_item_id: item
        for item in _read_typed_queue_work_items(queue)
    }
    if set(decisions) - set(items):
        raise SeverityBindPostimageError(
            "shadow decisions are absent from verifier queue authority"
        )
    for candidate, item in items.items():
        if candidate not in decisions:
            continue
        for name in (
            item.expected_output_file,
            f"verify_{candidate}.severity_proposal.json",
            f"verify_{candidate}.receipt.json",
        ):
            relative, path = _relative(root, name, "verifier authority")
            names[relative] = path
    return names


def _authority_arguments(worker: Mapping[str, Any]) -> dict[str, str]:
    return {
        "backend": str(worker.get("backend") or ""),
        "launch_digest": str(worker.get("receipt_digest") or ""),
        "run_id": str(worker.get("run_id") or ""),
        "worker_identity": str(worker.get("worker_identity") or ""),
        "invocation_id": str(worker.get("invocation_id") or ""),
    }


def _same_replay(
    decision: Mapping[str, Any], launch: Mapping[str, Any],
) -> bool:
    history = decision.get("adjudication_history")
    if not isinstance(history, list) or not history:
        return False
    last = history[-1]
    if not isinstance(last, Mapping):
        raise SeverityBindPostimageError(
            "severity adjudication history event is malformed"
        )
    prior = (last.get("adjudicator_authority_binding") or {}).get("receipt")
    if not isinstance(prior, Mapping):
        return False
    fields = (
        "schema_version", "role", "run_id", "candidate_id",
        "constituent_ids", "worker_identity", "invocation_id", "backend",
        "launch_manifest_sha256", "output_sha256",
    )
    return all(prior.get(field) == launch.get(field) for field in fields)


def derive_shadow_adjudication_postimages(
    scratchpad: Path,
    candidate_id: str,
    *,
    backend: str,
    launch_digest: str,
    run_id: str,
    worker_identity: str,
    invocation_id: str,
) -> SeverityBindPostimages:
    """Return the exact three postimages without changing the filesystem."""

    root = Path(scratchpad)
    candidate = candidate_id if type(candidate_id) is str else ""
    if not candidate or not _CANDIDATE.fullmatch(candidate):
        raise SeverityBindPostimageError("severity candidate identity is invalid")
    try:
        worker = validate_completed_worker_run_for_candidate(root, candidate)
        expected = _authority_arguments(worker)
        supplied = {
            "backend": backend, "launch_digest": launch_digest,
            "run_id": run_id, "worker_identity": worker_identity,
            "invocation_id": invocation_id,
        }
        if supplied != expected:
            raise SeverityBindPostimageError(
                "caller adjudication authority differs from worker receipt"
            )
        plan_raw = _read(root / "severity_adjudication_work_plan.json")
        plan = _strict(plan_raw, "severity work plan")
        matches = [
            row for row in plan.get("shards") or []
            if isinstance(row, Mapping) and candidate in (row.get("candidate_ids") or [])
        ]
        if len(matches) != 1:
            raise SeverityBindPostimageError("candidate has no unique worker shard")
        shard = matches[0]
        ledger_name = runtime.SHADOW_LEDGER_NAME
        ledger_raw = _read(root / ledger_name)
        parsed_ledger = _strict(ledger_raw, "shadow ledger")
        rows = parsed_ledger.get("decisions") if isinstance(parsed_ledger, Mapping) else None
        if not isinstance(rows, list):
            raise SeverityBindPostimageError("shadow ledger decision roster is malformed")
        decision_paths: dict[str, Path] = {}
        for row in rows:
            row_id = row.get("candidate_id") if isinstance(row, Mapping) else None
            if not isinstance(row_id, str) or not _CANDIDATE.fullmatch(row_id):
                raise SeverityBindPostimageError("shadow decision identity is invalid")
            name = f"verify_{row_id}.severity_decision.json"
            decision_paths[name] = runtime._canonical_file(root, name)
        decision_bytes = _capture(root, decision_paths)
        parsed_decisions: dict[str, dict[str, Any]] = {}
        for name, raw in decision_bytes.items():
            parsed = _strict(raw, name)
            parsed_id = parsed.get("candidate_id")
            if not isinstance(parsed_id, str) or parsed_id in parsed_decisions:
                raise SeverityBindPostimageError(
                    "captured severity decision identity is invalid or duplicate"
                )
            parsed_decisions[parsed_id] = parsed
        ledger, decisions = runtime._load_shadow_state(root, run_id=run_id)
        if ledger != parsed_ledger or decisions != parsed_decisions:
            raise SeverityBindPostimageError("shadow state changed during capture")
        runtime._validate_original_verifier_sources(root, decisions)
        decision = decisions[candidate]
        proposal_name = f"verify_{candidate}.severity_adjudication_proposal.json"
        proposal_path = runtime._canonical_file(root, proposal_name)
        proposal_raw = _read(proposal_path)
        proposal = parse_severity_adjudication_proposal(proposal_raw)
        launch = {
            "schema_version": LAUNCH_RECEIPT_SCHEMA,
            "role": "ADJUDICATOR",
            "run_id": run_id,
            "candidate_id": candidate,
            "constituent_ids": list(decision.get("constituent_ids") or []),
            "worker_identity": worker_identity,
            "invocation_id": invocation_id,
            "backend": backend,
            "launch_manifest_sha256": launch_digest,
            "input_sha256": severity_adjudicator_input_digest(decision),
            "output_sha256": runtime._digest(proposal),
        }
        decision_name = f"verify_{candidate}.severity_decision.json"
        receipt_name = f"verify_{candidate}.severity_adjudication_receipt.json"
        transaction_inputs = {
            decision_name: decision_bytes[decision_name],
            proposal_name: proposal_raw,
            ledger_name: ledger_raw,
        }
        authority_paths = _worker_authority_paths(root, worker, shard)
        authority_paths.update(_verifier_authority_paths(root, decisions))
        authority_rows = _capture(root, authority_paths)
        # The original verifier-source validator covers the full sibling
        # decision denominator; preserve those exact sidecars separately from
        # the three mutable transaction inputs.
        authority_rows.update(decision_bytes)
        receipt_path = root / receipt_name
        receipt_at_capture: bytes | None = None

        if _same_replay(decision, launch):
            # This rejects a missing or semantically equivalent replacement
            # receipt and replays the full current worker binding.
            receipt = runtime._validate_adjudication_receipt(root, decision)
            if receipt is None:
                raise SeverityBindPostimageError(
                    "exact severity replay receipt is absent"
                )
            receipt_raw = _read(receipt_path)
            receipt_at_capture = receipt_raw
            transaction_inputs[receipt_name] = receipt_raw
            outputs = {
                decision_name: transaction_inputs[decision_name],
                receipt_name: receipt_raw,
                ledger_name: transaction_inputs[ledger_name],
            }
            _revalidate_epoch(
                root, candidate=candidate, worker=worker, decisions=decisions,
                paths={**decision_paths, **authority_paths, ledger_name: root / ledger_name, proposal_name: proposal_path},
                expected={**decision_bytes, **authority_rows, ledger_name: ledger_raw, proposal_name: proposal_raw},
                receipt_path=receipt_path, receipt_raw=receipt_at_capture,
            )
            return SeverityBindPostimages(
                candidate, run_id, "EXACT_REPLAY", str(worker["receipt_digest"]),
                MappingProxyType(transaction_inputs),
                MappingProxyType(authority_rows), MappingProxyType(outputs),
            )

        updated = bind_severity_adjudication(
            proposal, decision=decision, adjudicator_launch_receipt=launch,
        )
        receipt = runtime._adjudication_receipt_payload(
            decision=updated, proposal_path=proposal_path,
            proposal_bytes=proposal_raw, launch_receipt=launch,
        )
        next_decisions = dict(decisions)
        next_decisions[candidate] = updated
        next_ledger = build_severity_decision_ledger(
            run_id, next_decisions.values()
        )
        outputs = {
            decision_name: _compact(updated),
            receipt_name: _compact(receipt),
            ledger_name: _ledger_bytes(next_ledger),
        }
        mode = "NEW_BIND"
        if rio.lexists(receipt_path):
            receipt_raw = _read(receipt_path)
            receipt_at_capture = receipt_raw
            transaction_inputs[receipt_name] = receipt_raw
            if receipt_raw != outputs[receipt_name]:
                raise SeverityBindPostimageError(
                    "existing severity receipt conflicts with derived bind"
                )
            mode = "RECEIPT_PENDING"
        _revalidate_epoch(
            root, candidate=candidate, worker=worker, decisions=decisions,
            paths={**decision_paths, **authority_paths, ledger_name: root / ledger_name, proposal_name: proposal_path},
            expected={**decision_bytes, **authority_rows, ledger_name: ledger_raw, proposal_name: proposal_raw},
            receipt_path=receipt_path, receipt_raw=receipt_at_capture,
        )
        return SeverityBindPostimages(
            candidate, run_id, mode, str(worker["receipt_digest"]),
            MappingProxyType(transaction_inputs),
            MappingProxyType(authority_rows), MappingProxyType(outputs),
        )
    except SeverityBindPostimageError:
        raise
    except (KeyError, OSError, TypeError, ValueError) as exc:
        raise SeverityBindPostimageError(
            f"severity bind postimage derivation failed: {exc}"
        ) from exc


__all__ = [
    "SeverityBindPostimageError", "SeverityBindPostimages",
    "derive_shadow_adjudication_postimages",
]
