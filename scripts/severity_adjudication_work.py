"""Driver-neutral work planning for independent severity adjudication.

This module owns no severity decision.  It turns the existing typed shadow
ledger into bounded, digest-bound worker packets and reconciles their durable
artifacts.  The caller remains responsible for launching workers and invoking
``severity_runtime.bind_shadow_adjudication_for_candidate`` for rows reported
as ``OUTPUT_READY``.

The work plan is deliberately persistent.  On resume, audit/methodology/
backend/transport drift is rejected before any work artifact is replaced, while
normal adjudication outputs are allowed to advance underneath the immutable
plan and are classified by :func:`reconcile_adjudication_work`.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any, Callable, Collection, Iterable, Mapping, Sequence

from severity_decision_ledger import (
    LAUNCH_RECEIPT_SCHEMA,
    bind_severity_adjudication,
    compile_severity_adjudication_prompt_contract,
    load_severity_decision_ledger,
    parse_severity_adjudication_proposal,
    severity_adjudicator_input_digest,
)
from plamen_parsers import read_skeptic_challenges_json_sidecar
from worker_execution_receipts import (
    BoundInput,
    CompletedExecution,
    ExecutionBindings,
    ExpectedOutput,
    PrincipalInvocation,
    WorkerExecutionError,
    environment_allowlist_sha256,
    run_observed_worker,
    validate_completed_execution,
)


MANIFEST_NAME = "severity_adjudication_work_manifest.json"
WORK_PLAN_NAME = "severity_adjudication_work_plan.json"
RECONCILIATION_NAME = "severity_adjudication_work_reconciliation.json"
SOURCE_LEDGER_NAME = "severity_decision_ledger.shadow.json"

MANIFEST_SCHEMA = "plamen.severity_adjudication_work_manifest.v1"
WORK_PLAN_SCHEMA = "plamen.severity_adjudication_work_plan.v4"
CONTEXT_SCHEMA = "plamen.severity_adjudication_context.v1"
TOOL_POLICY_SCHEMA = "plamen.severity_adjudication_tool_policy.v1"
LAUNCH_INTENT_SCHEMA = "plamen.severity_adjudication_launch_intent.v4"
RECONCILIATION_SCHEMA = "plamen.severity_adjudication_reconciliation.v1"
WORKER_RUN_SCHEMA = "plamen.severity_adjudication_worker_run.v2"

DEFAULT_MAX_ITEMS = 4
DEFAULT_MAX_WEIGHT = 8
DEFAULT_MAX_CONTEXT_BYTES = 65_536

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,95}$")
_OWNED_BASENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,191}$")


class AdjudicationWorkError(RuntimeError):
    """A prepared work boundary is corrupt, stale, or unsafe to launch."""


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdjudicationWorkError(
                f"duplicate adjudication-work JSON key {key!r}"
            )
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdjudicationWorkError(
        f"non-finite adjudication-work JSON constant {value!r}"
    )


def _strict_json_bytes(value: bytes | str) -> Any:
    try:
        text = value.decode("utf-8", errors="strict") if isinstance(value, bytes) else value
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AdjudicationWorkError(
            f"adjudication-work JSON is unreadable: {exc}"
        ) from exc


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
    ).encode("utf-8")


def _atomic_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_bytes() == content:
            return
    except OSError:
        pass
    fd, temporary_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_bytes(path, _canonical_json_bytes(value))


def _write_derived_exact_or_missing(path: Path, content: bytes) -> None:
    """Repair a missing deterministic artifact without blessing replacement bytes."""

    try:
        existing = path.read_bytes()
    except FileNotFoundError:
        _atomic_bytes(path, content)
        return
    except OSError as exc:
        raise AdjudicationWorkError(
            f"derived adjudication artifact {path.name} is unreadable"
        ) from exc
    if existing != content:
        raise AdjudicationWorkError(
            f"derived adjudication artifact {path.name} already exists with "
            "different bytes"
        )


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = _strict_json_bytes(path.read_bytes())
    except OSError as exc:
        raise AdjudicationWorkError(f"missing adjudication artifact {path.name}") from exc
    if not isinstance(value, dict):
        raise AdjudicationWorkError(f"{path.name} must contain one JSON object")
    return value


def _owned_child(root: Path, raw_name: Any, field: str) -> Path:
    """Resolve one exact scratchpad basename without ever escaping ``root``."""

    name = _require_text(raw_name, field)
    if not _OWNED_BASENAME_RE.fullmatch(name) or Path(name).name != name:
        raise AdjudicationWorkError(f"{field} must be a canonical owned basename")
    path = root / name
    try:
        if path.resolve(strict=False).parent != root.resolve(strict=False):
            raise AdjudicationWorkError(f"{field} escapes the scratchpad")
    except OSError as exc:
        raise AdjudicationWorkError(f"{field} cannot be resolved safely") from exc
    return path


def _require_hex64(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not _HEX64_RE.fullmatch(value)
    ):
        raise AdjudicationWorkError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_text(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value
        or any(
            ord(char) < 32
            or ord(char) == 127
            or char in {"\u2028", "\u2029"}
            for char in value
        )
    ):
        raise AdjudicationWorkError(f"{field} must be non-empty control-free text")
    return value


def _require_int(
    value: Any,
    field: str,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < minimum or (
        maximum is not None and value > maximum
    ):
        bounds = f"between {minimum} and {maximum}" if maximum is not None else f"at least {minimum}"
        raise AdjudicationWorkError(f"{field} must be an integer {bounds}")
    return value


def _require_text_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise AdjudicationWorkError(f"{field} must be an array")
    result = [_require_text(item, f"{field} item") for item in value]
    if not result or len(result) != len({item.casefold() for item in result}):
        raise AdjudicationWorkError(
            f"{field} must be non-empty and case-insensitively unique"
        )
    return sorted(result)


def _require_working_directory(value: Any) -> str:
    if isinstance(value, Path):
        value = str(value)
    if not isinstance(value, str):
        raise AdjudicationWorkError("working_directory must be a path string")
    raw = _require_text(value, "working_directory")
    try:
        path = Path(raw).resolve(strict=True)
    except OSError as exc:
        raise AdjudicationWorkError("working_directory is not resolvable") from exc
    if not path.is_dir():
        raise AdjudicationWorkError("working_directory must be an existing directory")
    return str(path)


def _signed(
    value: Mapping[str, Any], *, digest_field: str
) -> dict[str, Any]:
    unsigned = dict(value)
    return {**unsigned, digest_field: _digest(unsigned)}


def _verify_signed(
    value: Mapping[str, Any], *, digest_field: str, label: str
) -> None:
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    if value.get(digest_field) != _digest(unsigned):
        raise AdjudicationWorkError(f"{label} digest mismatch")


def _methodology_binding(
    methodology_files: Mapping[str, Path] | Iterable[tuple[str, Path]],
) -> tuple[list[dict[str, Any]], str]:
    items = (
        methodology_files.items()
        if isinstance(methodology_files, Mapping)
        else list(methodology_files)
    )
    rows: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw_name, raw_path in items:
        name = _require_text(raw_name, "methodology logical name")
        name_key = name.casefold()
        if name_key in names:
            raise AdjudicationWorkError("methodology logical names must be unique")
        names.add(name_key)
        path = Path(raw_path)
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise AdjudicationWorkError(
                f"methodology input {name!r} is unreadable"
            ) from exc
        try:
            content_text = content.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise AdjudicationWorkError(
                f"methodology input {name!r} must be UTF-8 text"
            ) from exc
        if not content_text.strip():
            raise AdjudicationWorkError(
                f"methodology input {name!r} is empty"
            )
        rows.append(
            {
                "logical_name": name,
                "content_encoding": "utf-8",
                "content_utf8": content_text,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content),
            }
        )
    rows.sort(key=lambda row: row["logical_name"])
    if not rows:
        raise AdjudicationWorkError(
            "at least one severity adjudication methodology input is required"
        )
    return rows, _digest(rows)


def _load_source_ledger(
    scratchpad: Path, *, run_id: str
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    ledger_path = scratchpad / SOURCE_LEDGER_NAME
    raw = _read_json(ledger_path)
    raw_rows = raw.get("decisions")
    if not isinstance(raw_rows, list):
        raise AdjudicationWorkError("severity source ledger has no decision list")
    source_digests: dict[str, str] = {}
    raw_candidate_keys: set[str] = set()
    for row in raw_rows:
        if not isinstance(row, Mapping):
            continue
        candidate_id = str(row.get("candidate_id") or "")
        candidate_key = candidate_id.casefold()
        if candidate_key in raw_candidate_keys:
            raise AdjudicationWorkError(
                "severity source ledger contains duplicate candidate identities"
            )
        raw_candidate_keys.add(candidate_key)
        source_digests[candidate_id] = str(row.get("source_receipt_digest") or "")
    try:
        ledger = load_severity_decision_ledger(
            ledger_path,
            expected_run_id=run_id,
            expected_source_receipt_digests=source_digests,
        )
    except Exception as exc:
        raise AdjudicationWorkError(f"severity source ledger is invalid: {exc}") from exc
    decisions: dict[str, dict[str, Any]] = {}
    decision_keys: set[str] = set()
    for row in ledger["decisions"]:
        candidate_id = str(row["candidate_id"])
        if not _SAFE_ID_RE.fullmatch(candidate_id):
            raise AdjudicationWorkError(
                f"candidate ID {candidate_id!r} is unsafe for artifact ownership"
            )
        candidate_key = candidate_id.casefold()
        if candidate_key in decision_keys:
            raise AdjudicationWorkError(
                "severity source ledger contains duplicate candidate identities"
            )
        decision_keys.add(candidate_key)
        decision_path = scratchpad / f"verify_{candidate_id}.severity_decision.json"
        persisted = _read_json(decision_path)
        if persisted != row:
            raise AdjudicationWorkError(
                f"{candidate_id} source ledger/decision sidecar mismatch"
            )
        decisions[candidate_id] = dict(row)
    return ledger, decisions


def _load_current_work_source_state(
    scratchpad: Path,
    *,
    run_id: str,
    manifest_items: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Load current authority while tolerating only visible commit windows.

    The aggregate ledger may lag a decision-first crash.  Such a mismatch is
    inspectable debt only when the planned candidate has its own proposal or
    receipt artifact; an unaccompanied sibling mutation is invalid source
    drift and cannot authorize unrelated work.
    """

    ledger_path = scratchpad / SOURCE_LEDGER_NAME
    raw = _read_json(ledger_path)
    raw_rows = raw.get("decisions")
    if not isinstance(raw_rows, list):
        raise AdjudicationWorkError("severity source ledger has no decision list")
    source_digests: dict[str, str] = {}
    seen: set[str] = set()
    for row in raw_rows:
        if not isinstance(row, Mapping):
            raise AdjudicationWorkError("severity source ledger row is malformed")
        candidate_id = str(row.get("candidate_id") or "")
        key = candidate_id.casefold()
        if key in seen:
            raise AdjudicationWorkError(
                "severity source ledger contains duplicate candidate identities"
            )
        seen.add(key)
        source_digests[candidate_id] = str(
            row.get("source_receipt_digest") or ""
        )
    try:
        ledger = load_severity_decision_ledger(
            ledger_path,
            expected_run_id=run_id,
            expected_source_receipt_digests=source_digests,
        )
    except Exception as exc:
        raise AdjudicationWorkError(f"severity source ledger is invalid: {exc}") from exc

    expected_sidecars = {
        f"verify_{row['candidate_id']}.severity_decision.json"
        for row in ledger["decisions"]
    }
    actual_sidecars = {
        path.name
        for path in scratchpad.glob("verify_*.severity_decision.json")
        if path.is_file()
    }
    if len(actual_sidecars) != len(
        {name.casefold() for name in actual_sidecars}
    ) or {name.casefold() for name in actual_sidecars} != {
        name.casefold() for name in expected_sidecars
    }:
        raise AdjudicationWorkError(
            "severity decision sidecar set differs from aggregate ledger"
        )
    if actual_sidecars != expected_sidecars:
        raise AdjudicationWorkError(
            "severity decision sidecar casing is non-canonical"
        )

    current: dict[str, dict[str, Any]] = {}
    for row in ledger["decisions"]:
        candidate_id = str(row["candidate_id"])
        decision_path = scratchpad / f"verify_{candidate_id}.severity_decision.json"
        persisted = _read_json(decision_path)
        if persisted != row:
            item = manifest_items.get(candidate_id)
            proposal_exists = bool(
                item
                and (scratchpad / str(item["expected_output_file"])).exists()
            )
            receipt_exists = (
                scratchpad
                / f"verify_{candidate_id}.severity_adjudication_receipt.json"
            ).exists()
            if item is None or not (proposal_exists or receipt_exists):
                raise AdjudicationWorkError(
                    f"{candidate_id} source ledger/decision sibling drift is unowned"
                )
            try:
                severity_adjudicator_input_digest(persisted)
            except Exception as exc:
                raise AdjudicationWorkError(
                    f"{candidate_id} transaction decision is invalid: {exc}"
                ) from exc
            current[candidate_id] = persisted
        else:
            current[candidate_id] = dict(row)
    return ledger, current


def _direction(upstream: Any, proposed: Any) -> str:
    tiers = ("Critical", "High", "Medium", "Low", "Informational")
    try:
        left = tiers.index(str(upstream))
        right = tiers.index(str(proposed))
    except ValueError:
        return "UNKNOWN"
    return "UP" if right < left else "DOWN" if right > left else "SAME"


def _skeptic_challenge_state(
    scratchpad: Path,
) -> tuple[str | None, dict[str, dict[str, Any]]]:
    """Load the exact proposal-only skeptic context, if present.

    The parser revalidates the receipt digest and all source/manifest hashes.
    This context can force independent adjudication but can never itself
    resolve severity or disposition.
    """

    payload = read_skeptic_challenges_json_sidecar(scratchpad)
    if not payload:
        return None, {}
    digest = str(payload.get("receipt_digest") or "")
    if not _HEX64_RE.fullmatch(digest):
        raise AdjudicationWorkError("skeptic challenge receipt digest is invalid")
    by_id: dict[str, dict[str, Any]] = {}
    for row in payload.get("challenges") or []:
        if not isinstance(row, Mapping):
            raise AdjudicationWorkError("skeptic challenge row is malformed")
        candidate_id = _require_text(
            row.get("finding_id"), "skeptic challenge finding_id"
        )
        if not _SAFE_ID_RE.fullmatch(candidate_id):
            raise AdjudicationWorkError(
                f"skeptic challenge ID {candidate_id!r} is unsafe"
            )
        key = candidate_id.casefold()
        if key in {value.casefold() for value in by_id}:
            raise AdjudicationWorkError(
                "skeptic challenge receipt contains duplicate identities"
            )
        by_id[candidate_id] = dict(row)
    return digest, by_id


def _item_weight(decision: Mapping[str, Any]) -> int:
    constituents = list(decision.get("constituent_ids") or [])
    return 1 + min(3, max(0, len(constituents) - 1))


def _work_item_from_decision(
    candidate_id: str,
    decision: Mapping[str, Any],
    *,
    skeptic_challenge: Mapping[str, Any] | None = None,
    skeptic_challenge_receipt_digest: str | None = None,
) -> dict[str, Any]:
    """Derive the complete immutable work-item row from one source decision.

    Keeping this derivation in one function prevents a re-signed manifest from
    changing routing fields while leaving the embedded decision untouched.
    """

    candidate = _require_text(candidate_id, "work-item candidate_id")
    if decision.get("candidate_id") != candidate:
        raise AdjudicationWorkError(
            f"{candidate} embedded source decision identity mismatch"
        )
    assessment = decision.get("assessment") or {}
    assessor_identity = _require_text(
        assessment.get("assessor_identity"),
        f"{candidate} assessor identity",
    )
    assessor_invocation = _require_text(
        assessment.get("assessor_invocation_id"),
        f"{candidate} assessor invocation",
    )
    try:
        input_digest = severity_adjudicator_input_digest(decision)
    except Exception as exc:
        raise AdjudicationWorkError(
            f"{candidate} adjudicator input cannot be bound: {exc}"
        ) from exc
    item = {
        "candidate_id": candidate,
        "constituent_ids": list(decision.get("constituent_ids") or []),
        "source_status": str(decision.get("status") or ""),
        "upstream_severity": decision.get("upstream_severity"),
        "proposed_severity": decision.get("proposed_severity"),
        "retention_severity": decision.get("retention_severity"),
        "direction": _direction(
            decision.get("upstream_severity"),
            decision.get("proposed_severity"),
        ),
        "weight": _item_weight(decision),
        "assessor_identity": assessor_identity,
        "assessor_invocation_id": assessor_invocation,
        "source_decision_digest": decision["decision_digest"],
        "adjudicator_input_sha256": input_digest,
        "expected_output_file": (
            f"verify_{candidate}.severity_adjudication_proposal.json"
        ),
        "decision": dict(decision),
    }
    if skeptic_challenge is not None:
        challenge = dict(skeptic_challenge)
        if challenge.get("finding_id") != candidate:
            raise AdjudicationWorkError(
                f"{candidate} skeptic challenge identity mismatch"
            )
        receipt_digest = _require_hex64(
            skeptic_challenge_receipt_digest,
            "skeptic challenge receipt digest",
        )
        # A challenge forces a separately authored decision even when the
        # verifier's own severity proposal happened to self-resolve.
        item["source_status"] = "CHALLENGE_REQUIRED"
        item["skeptic_challenge"] = challenge
        item["skeptic_challenge_receipt_digest"] = receipt_digest
    return item


def build_adjudication_manifest(
    scratchpad: Path,
    *,
    run_id: str,
    audit_snapshot_digest: str,
    audit_config_digest: str,
    methodology_entries: list[dict[str, Any]],
    methodology_digest: str,
) -> dict[str, Any]:
    """Build the immutable exact denominator from the typed source ledger."""

    root = Path(scratchpad)
    run = _require_text(run_id, "run_id")
    audit = _require_hex64(audit_snapshot_digest, "audit_snapshot_digest")
    config = _require_hex64(audit_config_digest, "audit_config_digest")
    method_digest = _require_hex64(methodology_digest, "methodology_digest")
    ledger, decisions = _load_source_ledger(root, run_id=run)
    skeptic_receipt_digest, skeptic_challenges = _skeptic_challenge_state(root)
    decision_by_key = {known.casefold(): known for known in decisions}
    challenge_by_key = {
        candidate_id.casefold(): row
        for candidate_id, row in skeptic_challenges.items()
    }
    unknown_skeptic_ids = {
        candidate_id.casefold(): candidate_id
        for candidate_id in skeptic_challenges
        if candidate_id.casefold() not in decision_by_key
    }
    if unknown_skeptic_ids:
        raise AdjudicationWorkError(
            "skeptic challenge denominator contains identities absent from "
            "the severity source ledger: "
            + ", ".join(sorted(unknown_skeptic_ids.values()))
        )
    if len(decisions) != len({candidate_id.casefold() for candidate_id in decisions}):
        raise AdjudicationWorkError(
            "adjudication denominator contains duplicate candidate identities"
        )
    work_items: list[dict[str, Any]] = []
    for candidate_id in sorted(decisions):
        decision = decisions[candidate_id]
        challenge = challenge_by_key.get(candidate_id.casefold())
        if challenge is not None and challenge.get("finding_id") != candidate_id:
            raise AdjudicationWorkError(
                f"{candidate_id} skeptic challenge identity casing mismatch"
            )
        if decision.get("status") == "RESOLVED" and challenge is None:
            continue
        work_items.append(_work_item_from_decision(
            candidate_id,
            decision,
            skeptic_challenge=challenge,
            skeptic_challenge_receipt_digest=(
                skeptic_receipt_digest if challenge is not None else None
            ),
        ))
    unsigned = {
        "schema_version": MANIFEST_SCHEMA,
        "run_id": run,
        "audit_snapshot_digest": audit,
        "audit_config_digest": config,
        "methodology_entries": methodology_entries,
        "methodology_digest": method_digest,
        "source_ledger_file": SOURCE_LEDGER_NAME,
        "source_ledger_digest": ledger["ledger_digest"],
        "source_decision_digests": {
            str(row["candidate_id"]): str(row["decision_digest"])
            for row in ledger["decisions"]
        },
        "skeptic_challenge_receipt_digest": skeptic_receipt_digest,
        "skeptic_challenge_ids": sorted(skeptic_challenges),
        "denominator_count": len(work_items),
        "denominator_ids": [row["candidate_id"] for row in work_items],
        "work_items": work_items,
    }
    manifest = _signed(unsigned, digest_field="manifest_digest")
    _atomic_json(root / MANIFEST_NAME, manifest)
    return manifest


def _context_payload(
    *,
    manifest: Mapping[str, Any],
    plan_digest: str,
    shard_id: str,
    items: list[Mapping[str, Any]],
) -> dict[str, Any]:
    adjudication_contract = compile_severity_adjudication_prompt_contract()
    return {
        "schema_version": CONTEXT_SCHEMA,
        "run_id": manifest["run_id"],
        "shard_id": shard_id,
        "plan_digest": plan_digest,
        "manifest_digest": manifest["manifest_digest"],
        "source_ledger_digest": manifest["source_ledger_digest"],
        "skeptic_challenge_receipt_digest": manifest.get(
            "skeptic_challenge_receipt_digest"
        ),
        "audit_snapshot_digest": manifest["audit_snapshot_digest"],
        "audit_config_digest": manifest["audit_config_digest"],
        "methodology_entries": manifest["methodology_entries"],
        "methodology_digest": manifest["methodology_digest"],
        "adjudication_contract": adjudication_contract,
        "adjudication_contract_digest": _digest(adjudication_contract),
        "item_count": len(items),
        "items": list(items),
    }


def _context_size(
    manifest: Mapping[str, Any], shard_id: str, items: list[Mapping[str, Any]]
) -> int:
    # A real plan digest has the same byte width as this placeholder.
    return len(
        _canonical_json_bytes(
            _context_payload(
                manifest=manifest,
                plan_digest="0" * 64,
                shard_id=shard_id,
                items=items,
            )
        )
    )


def _prompt_text(
    *,
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
    context_digest: str,
    launch_intent_name: str,
) -> str:
    outputs = "\n".join(
        f"- `{candidate}` -> "
        f"`{shard['staging_output_scope']}/{shard['staged_outputs'][candidate]}`"
        for candidate in shard["candidate_ids"]
    )
    return f"""# Independent Severity Adjudication Work

You are an independent severity adjudicator. You did not author the verifier's
assessment. Re-evaluate both upward and downward challenges using only the
typed premise/evidence context supplied below. You may not delete a candidate,
rewrite source artifacts, certify your own execution, or perform later phases.

PLAMEN_SEVERITY_WORK_PLAN_SHA256: {plan['plan_digest']}
PLAMEN_SEVERITY_MANIFEST_SHA256: {plan['manifest_digest']}
PLAMEN_SEVERITY_CONTEXT_FILE: {shard['context_file']}
PLAMEN_SEVERITY_CONTEXT_SHA256: {context_digest}
PLAMEN_SEVERITY_LAUNCH_INTENT_FILE: {launch_intent_name}
PLAMEN_SEVERITY_TOOL_POLICY_FILE: {shard['tool_policy_file']}

Read exactly `{shard['context_file']}`. Each item may contain a hash-bound
`skeptic_challenge`; treat it as a proposal to test, never as a decision. Apply every bound
`methodology_entries[].content_utf8` rule to every listed candidate; a digest
without application is not completion. For each candidate, write exactly
one content-only `plamen.severity_adjudication_proposal.v1` JSON object to its
assigned output file. Do not add driver identity, backend, launch, receipt, or
digest claims; the driver binds those independently after your process exits.

Expected outputs:
{outputs}

Use one of the adjudication decisions accepted by the typed severity schema.
Every resolved conclusion must name resolved premise IDs, evidence IDs, proof scope,
resolved impact/likelihood axes, and a concrete rationale. If evidence cannot
resolve the change, use the bound UNRESOLVED contract with null severity,
axes, and proof scope plus empty premise/evidence/resolution collections;
never assume a best-case external premise. Write no files other than the
expected outputs.
"""


def _shard_spec(
    manifest: Mapping[str, Any],
    index: int,
    items: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build one shard and account for its complete worker input."""

    shard_id = f"severity-adjudication-{index:04d}"
    suffix = f"{index:04d}"
    outputs = {
        row["candidate_id"]: row.get(
            "expected_output_file",
            f"verify_{row['candidate_id']}.severity_adjudication_proposal.json",
        )
        for row in items
    }
    staged_outputs = {
        candidate_id: Path(output).name
        for candidate_id, output in outputs.items()
    }
    provisional = {
        "shard_id": shard_id,
        "candidate_ids": [row["candidate_id"] for row in items],
        "item_count": len(items),
        "total_weight": sum(int(row["weight"]) for row in items),
        "context_file": f"severity_adjudication_context.{suffix}.json",
        "prompt_file": f"severity_adjudication_prompt.{suffix}.md",
        "launch_intent_file": (
            f"severity_adjudication_launch_intent.{suffix}.json"
        ),
        "tool_policy_file": (
            f"severity_adjudication_tool_policy.{suffix}.json"
        ),
        "staging_output_scope": (
            f"severity_adjudication_worker_outputs/{suffix}"
        ),
        "staged_outputs": staged_outputs,
        "expected_outputs": outputs,
    }
    context_payload_size = _context_size(manifest, shard_id, items)
    prompt_size = len(
        _prompt_text(
            plan={
                "plan_digest": "0" * 64,
                "manifest_digest": manifest["manifest_digest"],
            },
            shard=provisional,
            context_digest="0" * 64,
            launch_intent_name=provisional["launch_intent_file"],
        ).encode("utf-8")
    )
    worker_input_size = context_payload_size + prompt_size
    return {
        **provisional,
        "context_payload_size_bytes": context_payload_size,
        "prompt_size_bytes": prompt_size,
        "worker_input_size_bytes": worker_input_size,
        # Historical field retained as the declared aggregate ceiling basis.
        "context_size_bytes": worker_input_size,
    }


def _partition_manifest(
    manifest: Mapping[str, Any],
    *,
    max_items: int,
    max_weight: int,
    max_bytes: int,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    launchable: list[Mapping[str, Any]] = []
    debt: list[dict[str, str]] = []
    for item in manifest["work_items"]:
        status = item["source_status"]
        if status == "CHALLENGE_REQUIRED":
            launchable.append(item)
        elif status == "INCOMPLETE":
            debt.append(
                {
                    "candidate_id": item["candidate_id"],
                    "state": "ASSESSOR_REPAIR_REQUIRED",
                    "reason": "source severity assessment is incomplete",
                }
            )
        elif status == "UNRESOLVED_SEVERITY":
            debt.append(
                {
                    "candidate_id": item["candidate_id"],
                    "state": "COMPLETED_UNRESOLVED",
                    "reason": "prior independent adjudication remains unresolved",
                }
            )
        else:
            debt.append(
                {
                    "candidate_id": item["candidate_id"],
                    "state": "UNSUPPORTED_SOURCE_STATE",
                    "reason": f"unsupported source severity state {status or '(empty)'}",
                }
            )

    grouped: list[list[Mapping[str, Any]]] = []
    current: list[Mapping[str, Any]] = []
    for item in launchable:
        prospective = current + [item]
        prospective_weight = sum(int(row["weight"]) for row in prospective)
        prospective_size = _shard_spec(
            manifest, len(grouped) + 1, prospective
        )["worker_input_size_bytes"]
        fits = (
            len(prospective) <= max_items
            and prospective_weight <= max_weight
            and prospective_size <= max_bytes
        )
        if fits:
            current = prospective
            continue
        if current:
            grouped.append(current)
            current = []
        item_size = _shard_spec(
            manifest, len(grouped) + 1, [item]
        )["worker_input_size_bytes"]
        if (
            int(item["weight"]) > max_weight
            or item_size > max_bytes
        ):
            reason = (
                "single adjudication context exceeds configured byte cap"
                if item_size > max_bytes
                else "single adjudication item exceeds configured weight cap"
            )
            debt.append(
                {
                    "candidate_id": item["candidate_id"],
                    "state": "UNSCHEDULABLE_INPUT_CAP",
                    "reason": reason,
                }
            )
        else:
            current = [item]
    if current:
        grouped.append(current)

    shards: list[dict[str, Any]] = []
    for index, items in enumerate(grouped, start=1):
        shards.append(_shard_spec(manifest, index, items))
    debt.sort(key=lambda row: row["candidate_id"])
    return shards, debt


def _launch_intent_payload(
    *,
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
    selected: list[Mapping[str, Any]],
    context_bytes: bytes,
    prompt_bytes: bytes,
    tool_policy_bytes: bytes,
) -> dict[str, Any]:
    assessor_identities = sorted(
        {str(row["assessor_identity"]) for row in selected}
    )
    assessor_invocations = sorted(
        {str(row["assessor_invocation_id"]) for row in selected}
    )
    assessor_principals = [
        {"identity": identity, "invocation_id": invocation}
        for identity, invocation in sorted(
            {
                (
                    str(row["assessor_identity"]),
                    str(row["assessor_invocation_id"]),
                )
                for row in selected
            }
        )
    ]
    unsigned = {
        "schema_version": LAUNCH_INTENT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": plan["run_id"],
        "shard_id": shard["shard_id"],
        "worker_identity": shard["worker_identity"],
        "invocation_id": shard["invocation_id"],
        "assessor_identities": assessor_identities,
        "assessor_invocation_ids": assessor_invocations,
        "assessor_principals": assessor_principals,
        "backend": plan["backend"],
        "effective_backend": plan["backend"],
        "transport": plan["transport"],
        "effective_model": plan["effective_model"],
        "working_directory": plan["working_directory"],
        "source_root": plan["source_root"],
        "tool_policy": list(plan["tool_policy"]),
        "environment_allowlist_digest": plan[
            "environment_allowlist_digest"
        ],
        "timeout_seconds_per_worker": plan["timeout_seconds_per_worker"],
        "environment_allowlist_sha256": plan[
            "environment_allowlist_digest"
        ],
        "audit_snapshot_digest": plan["audit_snapshot_digest"],
        "audit_config_digest": plan["audit_config_digest"],
        "methodology_digest": plan["methodology_digest"],
        "source_ledger_digest": plan["source_ledger_digest"],
        "manifest_digest": plan["manifest_digest"],
        "plan_digest": plan["plan_digest"],
        "context_file": shard["context_file"],
        "context_sha256": hashlib.sha256(context_bytes).hexdigest(),
        "context_size_bytes": len(context_bytes),
        "prompt_file": shard["prompt_file"],
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "prompt_size_bytes": len(prompt_bytes),
        "tool_policy_file": shard["tool_policy_file"],
        "tool_policy_sha256": hashlib.sha256(tool_policy_bytes).hexdigest(),
        "tool_policy_size_bytes": len(tool_policy_bytes),
        "candidate_ids": list(shard["candidate_ids"]),
        "staging_output_scope": shard["staging_output_scope"],
        "staged_outputs": dict(shard["staged_outputs"]),
        "expected_outputs": dict(shard["expected_outputs"]),
        "output_binding_digest": _digest(
            {
                "staging_output_scope": shard["staging_output_scope"],
                "staged_outputs": shard["staged_outputs"],
                "expected_outputs": shard["expected_outputs"],
            }
        ),
    }
    return _signed(unsigned, digest_field="intent_digest")


def _tool_policy_payload(
    *, plan: Mapping[str, Any], shard: Mapping[str, Any]
) -> dict[str, Any]:
    unsigned = {
        "schema_version": TOOL_POLICY_SCHEMA,
        "run_id": plan["run_id"],
        "shard_id": shard["shard_id"],
        "plan_digest": plan["plan_digest"],
        "worker_identity": shard["worker_identity"],
        "invocation_id": shard["invocation_id"],
        "policy": list(plan["tool_policy"]),
    }
    return _signed(unsigned, digest_field="tool_policy_digest")


def _write_shard_artifacts(
    root: Path,
    *,
    manifest: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> None:
    items = {row["candidate_id"]: row for row in manifest["work_items"]}
    for shard in plan["shards"]:
        context_path = _owned_child(
            root, shard.get("context_file"), "shard context_file"
        )
        prompt_path = _owned_child(
            root, shard.get("prompt_file"), "shard prompt_file"
        )
        intent_path = _owned_child(
            root, shard.get("launch_intent_file"),
            "shard launch_intent_file",
        )
        tool_policy_path = _owned_child(
            root,
            shard.get("tool_policy_file"),
            "shard tool_policy_file",
        )
        selected = [items[candidate_id] for candidate_id in shard["candidate_ids"]]
        context = _context_payload(
            manifest=manifest,
            plan_digest=plan["plan_digest"],
            shard_id=shard["shard_id"],
            items=selected,
        )
        context_bytes = _canonical_json_bytes(context)
        if len(context_bytes) != shard["context_payload_size_bytes"]:
            raise AdjudicationWorkError("planned adjudication context size drifted")
        context_digest = hashlib.sha256(context_bytes).hexdigest()
        _write_derived_exact_or_missing(context_path, context_bytes)

        launch_name = shard["launch_intent_file"]
        prompt = _prompt_text(
            plan=plan,
            shard=shard,
            context_digest=context_digest,
            launch_intent_name=launch_name,
        )
        prompt_bytes = prompt.encode("utf-8")
        if (
            len(prompt_bytes) != shard["prompt_size_bytes"]
            or len(context_bytes) + len(prompt_bytes)
            != shard["worker_input_size_bytes"]
            or shard["context_size_bytes"] != shard["worker_input_size_bytes"]
        ):
            raise AdjudicationWorkError("planned worker-input size drifted")
        prompt_digest = hashlib.sha256(prompt_bytes).hexdigest()
        _write_derived_exact_or_missing(prompt_path, prompt_bytes)

        tool_policy = _tool_policy_payload(plan=plan, shard=shard)
        tool_policy_bytes = _canonical_json_bytes(tool_policy)
        _write_derived_exact_or_missing(tool_policy_path, tool_policy_bytes)

        intent = _launch_intent_payload(
            plan=plan,
            shard=shard,
            selected=selected,
            context_bytes=context_bytes,
            prompt_bytes=prompt_bytes,
            tool_policy_bytes=tool_policy_bytes,
        )
        _write_derived_exact_or_missing(
            intent_path, _canonical_json_bytes(intent)
        )


def _new_work_plan(
    root: Path,
    *,
    manifest: Mapping[str, Any],
    backend: str,
    transport: str,
    effective_model: str,
    working_directory: str,
    source_root: str,
    tool_policy: list[str],
    environment_allowlist_digest: str,
    adjudicator_identity: str,
    invocation_prefix: str,
    timeout_seconds: int,
    max_items: int,
    max_weight: int,
    max_bytes: int,
) -> dict[str, Any]:
    shards, debt = _partition_manifest(
        manifest,
        max_items=max_items,
        max_weight=max_weight,
        max_bytes=max_bytes,
    )
    assessor_identities = {
        str(row["assessor_identity"]).casefold()
        for row in manifest["work_items"]
    }
    assessor_invocations = {
        str(row["assessor_invocation_id"]).casefold()
        for row in manifest["work_items"]
    }
    adjudicator_key = adjudicator_identity.casefold()
    invocation_prefix_key = invocation_prefix.casefold()
    for index, shard in enumerate(shards, start=1):
        worker_identity = f"{adjudicator_identity}:{index:04d}"
        invocation_id = f"{invocation_prefix}:{index:04d}"
        if (
            adjudicator_key in assessor_identities
            or worker_identity.casefold() in assessor_identities
            or invocation_prefix_key in assessor_invocations
            or invocation_id.casefold() in assessor_invocations
        ):
            raise AdjudicationWorkError(
                "assessor and adjudicator authority must remain distinct"
            )
        shard["worker_identity"] = worker_identity
        shard["invocation_id"] = invocation_id
    if (
        adjudicator_key in assessor_identities
        or invocation_prefix_key in assessor_invocations
    ):
        raise AdjudicationWorkError(
            "assessor and adjudicator authority must remain distinct"
        )

    unsigned = {
        "schema_version": WORK_PLAN_SCHEMA,
        "run_id": manifest["run_id"],
        "audit_snapshot_digest": manifest["audit_snapshot_digest"],
        "audit_config_digest": manifest["audit_config_digest"],
        "methodology_digest": manifest["methodology_digest"],
        "source_ledger_digest": manifest["source_ledger_digest"],
        "manifest_file": MANIFEST_NAME,
        "manifest_digest": manifest["manifest_digest"],
        "backend": backend,
        "transport": transport,
        "effective_model": effective_model,
        "working_directory": working_directory,
        "source_root": source_root,
        "tool_policy": list(tool_policy),
        "environment_allowlist_digest": environment_allowlist_digest,
        "adjudicator_identity": adjudicator_identity,
        "invocation_prefix": invocation_prefix,
        "timeout_seconds_per_worker": timeout_seconds,
        "max_items_per_worker": max_items,
        "max_weight_per_worker": max_weight,
        "max_context_bytes_per_worker": max_bytes,
        "denominator_count": manifest["denominator_count"],
        "denominator_ids": list(manifest["denominator_ids"]),
        "shards": shards,
        "debt_items": debt,
        "launch_count": len(shards),
        "zero_row_no_launch": not manifest["denominator_ids"],
    }
    plan = _signed(unsigned, digest_field="plan_digest")
    _atomic_json(root / WORK_PLAN_NAME, plan)
    _write_shard_artifacts(root, manifest=manifest, plan=plan)
    return plan


def prepare_adjudication_work(
    scratchpad: Path,
    *,
    run_id: str,
    audit_snapshot_digest: str,
    audit_config_digest: str,
    methodology_files: Mapping[str, Path] | Iterable[tuple[str, Path]],
    backend: str,
    transport: str,
    effective_model: str,
    working_directory: str | Path,
    source_root: str | Path | None = None,
    tool_policy: Iterable[str],
    environment_allowlist_digest: str,
    adjudicator_identity: str,
    invocation_prefix: str,
    timeout_seconds_per_worker: int = 30,
    max_items_per_worker: int = DEFAULT_MAX_ITEMS,
    max_weight_per_worker: int = DEFAULT_MAX_WEIGHT,
    max_context_bytes_per_worker: int = DEFAULT_MAX_CONTEXT_BYTES,
) -> dict[str, Any]:
    """Create or resume an immutable, bounded adjudication work transaction."""

    root = Path(scratchpad)
    root.mkdir(parents=True, exist_ok=True)
    run = _require_text(run_id, "run_id")
    audit = _require_hex64(audit_snapshot_digest, "audit_snapshot_digest")
    config = _require_hex64(audit_config_digest, "audit_config_digest")
    backend_name = _require_text(backend, "backend")
    transport_name = _require_text(transport, "transport")
    model_name = _require_text(effective_model, "effective_model")
    workdir = _require_working_directory(working_directory)
    source = _require_working_directory(
        Path(source_root) if source_root is not None else root.parent
    )
    tools = _require_text_list(tool_policy, "tool_policy")
    environment_digest = _require_hex64(
        environment_allowlist_digest, "environment_allowlist_digest"
    )
    adjudicator = _require_text(adjudicator_identity, "adjudicator identity")
    prefix = _require_text(invocation_prefix, "invocation prefix")
    worker_timeout = _require_int(
        timeout_seconds_per_worker,
        "timeout_seconds_per_worker",
        minimum=1,
    )
    max_items = _require_int(
        max_items_per_worker,
        "max_items_per_worker",
        minimum=1,
        maximum=4,
    )
    max_weight = _require_int(
        max_weight_per_worker,
        "max_weight_per_worker",
    )
    max_bytes = _require_int(
        max_context_bytes_per_worker,
        "max_context_bytes_per_worker",
    )
    methodology_entries, methodology_digest = _methodology_binding(methodology_files)

    plan_path = root / WORK_PLAN_NAME
    if plan_path.exists():
        plan = _read_json(plan_path)
        _verify_signed(plan, digest_field="plan_digest", label="work plan")
        expected = {
            "run_id": run,
            "audit_snapshot_digest": audit,
            "audit_config_digest": config,
            "methodology_digest": methodology_digest,
            "backend": backend_name,
            "transport": transport_name,
            "effective_model": model_name,
            "working_directory": workdir,
            "source_root": source,
            "tool_policy": tools,
            "environment_allowlist_digest": environment_digest,
            "adjudicator_identity": adjudicator,
            "invocation_prefix": prefix,
            "timeout_seconds_per_worker": worker_timeout,
            "max_items_per_worker": max_items,
            "max_weight_per_worker": max_weight,
            "max_context_bytes_per_worker": max_bytes,
        }
        mismatched = [key for key, value in expected.items() if plan.get(key) != value]
        if mismatched:
            raise AdjudicationWorkError(
                "resume binding mismatch: " + ", ".join(sorted(mismatched))
            )
        manifest = _read_json(root / MANIFEST_NAME)
        _verify_signed(
            manifest, digest_field="manifest_digest", label="work manifest"
        )
        if plan.get("manifest_digest") != manifest.get("manifest_digest"):
            raise AdjudicationWorkError("resume work plan/manifest binding mismatch")
        # The plan is the durable transaction boundary.  A crash can leave
        # deterministic context/prompt/intent artifacts missing after that
        # commit; recreate only missing bytes and reject any replacement.
        _write_shard_artifacts(root, manifest=manifest, plan=plan)
        issues = validate_prepared_work(root)
        if issues:
            raise AdjudicationWorkError(
                "prepared adjudication work is invalid: " + "; ".join(issues)
            )
        return plan

    manifest = build_adjudication_manifest(
        root,
        run_id=run,
        audit_snapshot_digest=audit,
        audit_config_digest=config,
        methodology_entries=methodology_entries,
        methodology_digest=methodology_digest,
    )
    plan = _new_work_plan(
        root,
        manifest=manifest,
        backend=backend_name,
        transport=transport_name,
        effective_model=model_name,
        working_directory=workdir,
        source_root=source,
        tool_policy=tools,
        environment_allowlist_digest=environment_digest,
        adjudicator_identity=adjudicator,
        invocation_prefix=prefix,
        timeout_seconds=worker_timeout,
        max_items=max_items,
        max_weight=max_weight,
        max_bytes=max_bytes,
    )
    issues = validate_prepared_work(root)
    if issues:
        raise AdjudicationWorkError(
            "new adjudication work failed self-validation: " + "; ".join(issues)
        )
    return plan


def _glob_names(root: Path, pattern: str) -> set[str]:
    return {path.name for path in root.glob(pattern) if path.is_file()}


def _validate_prepared_work(root: Path) -> None:
    manifest = _read_json(root / MANIFEST_NAME)
    plan = _read_json(root / WORK_PLAN_NAME)
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise AdjudicationWorkError("work manifest schema mismatch")
    if plan.get("schema_version") != WORK_PLAN_SCHEMA:
        raise AdjudicationWorkError("work plan schema mismatch")
    _verify_signed(manifest, digest_field="manifest_digest", label="work manifest")
    _verify_signed(plan, digest_field="plan_digest", label="work plan")
    if plan.get("manifest_digest") != manifest.get("manifest_digest"):
        raise AdjudicationWorkError("work plan/manifest binding mismatch")
    _require_text(plan.get("backend"), "work plan backend")
    _require_text(plan.get("transport"), "work plan transport")
    _require_text(plan.get("effective_model"), "work plan effective_model")
    if plan.get("working_directory") != _require_working_directory(
        plan.get("working_directory")
    ):
        raise AdjudicationWorkError(
            "work plan working_directory is not canonical"
        )
    if plan.get("source_root") != _require_working_directory(
        plan.get("source_root")
    ):
        raise AdjudicationWorkError("work plan source_root is not canonical")
    if plan.get("tool_policy") != _require_text_list(
        plan.get("tool_policy"), "work plan tool_policy"
    ):
        raise AdjudicationWorkError("work plan tool_policy is not canonical")
    _require_hex64(
        plan.get("environment_allowlist_digest"),
        "work plan environment_allowlist_digest",
    )
    _require_int(
        plan.get("timeout_seconds_per_worker"),
        "work plan timeout_seconds_per_worker",
        minimum=1,
    )
    for key in (
        "run_id",
        "audit_snapshot_digest",
        "audit_config_digest",
        "methodology_digest",
        "source_ledger_digest",
    ):
        if plan.get(key) != manifest.get(key):
            raise AdjudicationWorkError(f"work plan/manifest {key} mismatch")
    methodology_entries = manifest.get("methodology_entries")
    if not isinstance(methodology_entries, list) or not methodology_entries:
        raise AdjudicationWorkError("work manifest methodology bundle is empty")
    methodology_names: set[str] = set()
    for entry in methodology_entries:
        if not isinstance(entry, Mapping):
            raise AdjudicationWorkError("work methodology entry is malformed")
        name = str(entry.get("logical_name") or "")
        name_key = name.casefold()
        content = entry.get("content_utf8")
        if (
            not name
            or name_key in methodology_names
            or entry.get("content_encoding") != "utf-8"
            or not isinstance(content, str)
            or not content.strip()
        ):
            raise AdjudicationWorkError("work methodology entry identity is invalid")
        methodology_names.add(name_key)
        content_bytes = content.encode("utf-8")
        if (
            entry.get("size_bytes") != len(content_bytes)
            or entry.get("sha256") != hashlib.sha256(content_bytes).hexdigest()
        ):
            raise AdjudicationWorkError("work methodology content binding mismatch")
    if manifest.get("methodology_digest") != _digest(methodology_entries):
        raise AdjudicationWorkError("work methodology aggregate digest mismatch")
    if plan.get("denominator_ids") != manifest.get("denominator_ids"):
        raise AdjudicationWorkError("work plan denominator differs from manifest")
    denominator = list(plan.get("denominator_ids") or [])
    if (
        plan.get("denominator_count") != len(denominator)
        or manifest.get("denominator_count") != len(denominator)
    ):
        raise AdjudicationWorkError("work denominator count mismatch")
    if len(denominator) != len({str(item).casefold() for item in denominator}):
        raise AdjudicationWorkError("work denominator contains duplicate identities")
    raw_manifest_items = manifest.get("work_items") or []
    skeptic_receipt_digest, skeptic_challenges = _skeptic_challenge_state(root)
    if (
        manifest.get("skeptic_challenge_receipt_digest")
        != skeptic_receipt_digest
        or manifest.get("skeptic_challenge_ids")
        != sorted(skeptic_challenges)
    ):
        raise AdjudicationWorkError(
            "work manifest skeptic challenge binding mismatch"
        )
    manifest_candidate_ids = [row["candidate_id"] for row in raw_manifest_items]
    if len(manifest_candidate_ids) != len(
        {str(item).casefold() for item in manifest_candidate_ids}
    ):
        raise AdjudicationWorkError(
            "work manifest contains duplicate candidate identities"
        )
    manifest_items = {row["candidate_id"]: row for row in raw_manifest_items}
    if set(manifest_items) != set(denominator):
        raise AdjudicationWorkError("manifest work-item set differs from denominator")
    for candidate_id, row in manifest_items.items():
        decision = row.get("decision")
        if not isinstance(decision, Mapping):
            raise AdjudicationWorkError(
                f"work manifest source row {candidate_id} has no decision"
            )
        challenge = skeptic_challenges.get(candidate_id)
        if row != _work_item_from_decision(
            candidate_id,
            decision,
            skeptic_challenge=challenge,
            skeptic_challenge_receipt_digest=(
                skeptic_receipt_digest if challenge is not None else None
            ),
        ):
            raise AdjudicationWorkError(
                f"work manifest source row {candidate_id} was not exactly derived"
            )
    expected_shards, expected_debt = _partition_manifest(
        manifest,
        max_items=_require_int(
            plan.get("max_items_per_worker"),
            "work plan max_items_per_worker",
            minimum=1,
            maximum=4,
        ),
        max_weight=_require_int(
            plan.get("max_weight_per_worker"),
            "work plan max_weight_per_worker",
        ),
        max_bytes=_require_int(
            plan.get("max_context_bytes_per_worker"),
            "work plan max_context_bytes_per_worker",
        ),
    )
    plan_adjudicator = _require_text(
        plan.get("adjudicator_identity"), "work plan adjudicator_identity"
    )
    plan_invocation_prefix = _require_text(
        plan.get("invocation_prefix"), "work plan invocation_prefix"
    )
    for index, shard in enumerate(expected_shards, start=1):
        shard["worker_identity"] = f"{plan_adjudicator}:{index:04d}"
        shard["invocation_id"] = f"{plan_invocation_prefix}:{index:04d}"
    if (
        plan.get("shards") != expected_shards
        or plan.get("debt_items") != expected_debt
        or plan.get("launch_count") != len(expected_shards)
    ):
        raise AdjudicationWorkError(
            "work plan partition is not the deterministic manifest derivation"
        )
    baseline_digests = manifest.get("source_decision_digests")
    if not isinstance(baseline_digests, Mapping):
        raise AdjudicationWorkError("work manifest source baseline is missing")
    baseline_ids = [str(candidate_id) for candidate_id in baseline_digests]
    if len(baseline_ids) != len(
        {candidate_id.casefold() for candidate_id in baseline_ids}
    ) or any(
        not _SAFE_ID_RE.fullmatch(candidate_id)
        or not isinstance(baseline_digests[candidate_id], str)
        or not _HEX64_RE.fullmatch(baseline_digests[candidate_id])
        for candidate_id in baseline_ids
    ):
        raise AdjudicationWorkError("work manifest source baseline is invalid")
    _current_ledger, current_decisions = _load_current_work_source_state(
        root,
        run_id=str(plan["run_id"]),
        manifest_items=manifest_items,
    )
    if {
        candidate_id.casefold() for candidate_id in current_decisions
    } != {candidate_id.casefold() for candidate_id in baseline_ids}:
        raise AdjudicationWorkError("current source ledger identity set drifted")
    denominator_keys = {str(candidate_id).casefold() for candidate_id in denominator}
    baseline_lookup = {
        str(candidate_id).casefold(): (str(candidate_id), digest)
        for candidate_id, digest in baseline_digests.items()
    }
    for candidate_id, current_decision in current_decisions.items():
        baseline_id, baseline_digest = baseline_lookup[candidate_id.casefold()]
        if candidate_id != baseline_id:
            raise AdjudicationWorkError(
                "current source ledger identity casing drifted"
            )
        unchanged = current_decision.get("decision_digest") == baseline_digest
        if unchanged:
            should_be_in_denominator = (
                current_decision.get("status") != "RESOLVED"
                or candidate_id in skeptic_challenges
            )
            is_in_denominator = candidate_id.casefold() in denominator_keys
            if should_be_in_denominator != is_in_denominator:
                direction = "omitted unresolved" if should_be_in_denominator else "included resolved"
                raise AdjudicationWorkError(
                    f"work manifest {direction} source row {candidate_id}"
                )
        if unchanged and candidate_id in manifest_items:
            challenge = skeptic_challenges.get(candidate_id)
            if manifest_items[candidate_id] != _work_item_from_decision(
                candidate_id,
                current_decision,
                skeptic_challenge=challenge,
                skeptic_challenge_receipt_digest=(
                    skeptic_receipt_digest if challenge is not None else None
                ),
            ):
                raise AdjudicationWorkError(
                    f"work manifest source row {candidate_id} was not exactly derived"
                )

    assigned: list[str] = []
    expected_contexts: set[str] = set()
    expected_prompts: set[str] = set()
    expected_intents: set[str] = set()
    expected_tool_policies: set[str] = set()
    expected_outputs: set[str] = set()
    intent_by_candidate: dict[str, Mapping[str, Any]] = {}
    shard_ids: set[str] = set()
    worker_identities: set[str] = set()
    invocation_ids: set[str] = set()
    global_assessor_identities = {
        str(row["assessor_identity"]).casefold() for row in raw_manifest_items
    }
    global_assessor_invocations = {
        str(row["assessor_invocation_id"]).casefold() for row in raw_manifest_items
    }
    if (
        str(plan.get("adjudicator_identity") or "").casefold()
        in global_assessor_identities
        or str(plan.get("invocation_prefix") or "").casefold()
        in global_assessor_invocations
    ):
        raise AdjudicationWorkError("assessor/adjudicator authority collision")
    for shard in plan.get("shards") or []:
        shard_id = str(shard.get("shard_id") or "")
        worker_identity = str(shard.get("worker_identity") or "")
        invocation_id = str(shard.get("invocation_id") or "")
        shard_key = shard_id.casefold()
        worker_key = worker_identity.casefold()
        invocation_key = invocation_id.casefold()
        if (
            not shard_id
            or shard_key in shard_ids
            or not worker_identity
            or worker_key in worker_identities
            or not invocation_id
            or invocation_key in invocation_ids
            or worker_key in global_assessor_identities
            or invocation_key in global_assessor_invocations
        ):
            raise AdjudicationWorkError("shard authority identity is missing or reused")
        shard_ids.add(shard_key)
        worker_identities.add(worker_key)
        invocation_ids.add(invocation_key)
        candidate_ids = list(shard.get("candidate_ids") or [])
        assigned.extend(candidate_ids)
        if shard.get("item_count") != len(candidate_ids) or len(candidate_ids) > 4:
            raise AdjudicationWorkError("shard item-count ceiling mismatch")
        if len(candidate_ids) > int(plan["max_items_per_worker"]):
            raise AdjudicationWorkError("shard exceeds configured item cap")
        weight = sum(int(manifest_items[item]["weight"]) for item in candidate_ids)
        if shard.get("total_weight") != weight or weight > int(
            plan["max_weight_per_worker"]
        ):
            raise AdjudicationWorkError("shard exceeds configured weight cap")
        context_name = str(shard.get("context_file") or "")
        prompt_name = str(shard.get("prompt_file") or "")
        intent_name = str(shard.get("launch_intent_file") or "")
        tool_policy_name = str(shard.get("tool_policy_file") or "")
        expected_contexts.add(context_name)
        expected_prompts.add(prompt_name)
        expected_intents.add(intent_name)
        expected_tool_policies.add(tool_policy_name)
        context_bytes = (root / context_name).read_bytes()
        if shard.get("context_payload_size_bytes") != len(context_bytes):
            raise AdjudicationWorkError("context byte count mismatch")
        context = _strict_json_bytes(context_bytes)
        if not isinstance(context, Mapping) or context.get("schema_version") != CONTEXT_SCHEMA:
            raise AdjudicationWorkError("context schema mismatch")
        for key, expected in (
            ("run_id", plan["run_id"]),
            ("shard_id", shard_id),
            ("plan_digest", plan["plan_digest"]),
            ("manifest_digest", manifest["manifest_digest"]),
            ("source_ledger_digest", plan["source_ledger_digest"]),
            (
                "skeptic_challenge_receipt_digest",
                manifest.get("skeptic_challenge_receipt_digest"),
            ),
            ("audit_snapshot_digest", plan["audit_snapshot_digest"]),
            ("audit_config_digest", plan["audit_config_digest"]),
            ("methodology_digest", plan["methodology_digest"]),
            ("methodology_entries", methodology_entries),
            (
                "adjudication_contract",
                compile_severity_adjudication_prompt_contract(),
            ),
            (
                "adjudication_contract_digest",
                _digest(compile_severity_adjudication_prompt_contract()),
            ),
            ("item_count", len(candidate_ids)),
        ):
            if context.get(key) != expected:
                raise AdjudicationWorkError(f"context {key} binding mismatch")
        if [row.get("candidate_id") for row in context.get("items") or []] != candidate_ids:
            raise AdjudicationWorkError("context item order/set mismatch")
        for row in context.get("items") or []:
            candidate_id = row.get("candidate_id")
            if row != manifest_items.get(candidate_id):
                raise AdjudicationWorkError("context source decision mismatch")
        expected_context = _canonical_json_bytes(
            _context_payload(
                manifest=manifest,
                plan_digest=plan["plan_digest"],
                shard_id=shard_id,
                items=[manifest_items[item] for item in candidate_ids],
            )
        )
        if context_bytes != expected_context:
            raise AdjudicationWorkError("derived context bytes differ from plan")

        prompt_bytes = (root / prompt_name).read_bytes()
        expected_prompt = _prompt_text(
            plan=plan,
            shard=shard,
            context_digest=hashlib.sha256(context_bytes).hexdigest(),
            launch_intent_name=intent_name,
        ).encode("utf-8")
        if prompt_bytes != expected_prompt:
            raise AdjudicationWorkError("derived prompt bytes differ from plan")
        worker_input_size = len(context_bytes) + len(prompt_bytes)
        if (
            shard.get("prompt_size_bytes") != len(prompt_bytes)
            or shard.get("worker_input_size_bytes") != worker_input_size
            or shard.get("context_size_bytes") != worker_input_size
            or worker_input_size > int(plan["max_context_bytes_per_worker"])
        ):
            raise AdjudicationWorkError("worker input exceeds configured byte cap")
        tool_policy_bytes = (root / tool_policy_name).read_bytes()
        tool_policy = _strict_json_bytes(tool_policy_bytes)
        expected_tool_policy = _tool_policy_payload(plan=plan, shard=shard)
        if (
            not isinstance(tool_policy, Mapping)
            or tool_policy != expected_tool_policy
            or tool_policy.get("schema_version") != TOOL_POLICY_SCHEMA
        ):
            raise AdjudicationWorkError("derived tool policy differs from plan")
        intent = _read_json(root / intent_name)
        if intent.get("schema_version") != LAUNCH_INTENT_SCHEMA:
            raise AdjudicationWorkError("launch intent schema mismatch")
        _verify_signed(intent, digest_field="intent_digest", label="launch intent")
        expected_assessors = sorted(
            {str(manifest_items[item]["assessor_identity"]) for item in candidate_ids}
        )
        expected_assessor_invocations = sorted(
            {
                str(manifest_items[item]["assessor_invocation_id"])
                for item in candidate_ids
            }
        )
        expected_intent = _launch_intent_payload(
            plan=plan,
            shard=shard,
            selected=[manifest_items[item] for item in candidate_ids],
            context_bytes=context_bytes,
            prompt_bytes=prompt_bytes,
            tool_policy_bytes=tool_policy_bytes,
        )
        if intent != expected_intent:
            raise AdjudicationWorkError(
                "launch intent differs from driver-derived exact bytes"
            )
        if (
            intent.get("role") != "ADJUDICATOR"
            or intent.get("plan_digest") != plan["plan_digest"]
            or intent.get("manifest_digest") != manifest["manifest_digest"]
            or intent.get("context_file") != context_name
            or intent.get("context_sha256")
            != hashlib.sha256(context_bytes).hexdigest()
            or intent.get("context_size_bytes") != len(context_bytes)
            or intent.get("prompt_file") != prompt_name
            or intent.get("prompt_sha256") != hashlib.sha256(prompt_bytes).hexdigest()
            or intent.get("prompt_size_bytes") != len(prompt_bytes)
            or intent.get("shard_id") != shard_id
            or intent.get("worker_identity") != worker_identity
            or intent.get("invocation_id") != invocation_id
            or intent.get("assessor_identities") != expected_assessors
            or intent.get("assessor_invocation_ids")
            != expected_assessor_invocations
            or intent.get("assessor_principals")
            != [
                {"identity": identity, "invocation_id": invocation}
                for identity, invocation in sorted(
                    {
                        (
                            str(manifest_items[item]["assessor_identity"]),
                            str(
                                manifest_items[item]["assessor_invocation_id"]
                            ),
                        )
                        for item in candidate_ids
                    }
                )
            ]
            or intent.get("effective_backend") != plan.get("backend")
            or intent.get("environment_allowlist_sha256")
            != plan.get("environment_allowlist_digest")
            or intent.get("timeout_seconds_per_worker")
            != plan.get("timeout_seconds_per_worker")
            or intent.get("tool_policy_file") != tool_policy_name
            or intent.get("tool_policy_sha256")
            != hashlib.sha256(tool_policy_bytes).hexdigest()
            or intent.get("tool_policy_size_bytes") != len(tool_policy_bytes)
            or intent.get("candidate_ids") != candidate_ids
            or intent.get("staging_output_scope")
            != shard.get("staging_output_scope")
            or intent.get("staged_outputs") != shard.get("staged_outputs")
            or intent.get("expected_outputs") != shard.get("expected_outputs")
            or intent.get("output_binding_digest")
            != _digest(
                {
                    "staging_output_scope": shard.get(
                        "staging_output_scope"
                    ),
                    "staged_outputs": shard.get("staged_outputs"),
                    "expected_outputs": shard.get("expected_outputs"),
                }
            )
        ):
            raise AdjudicationWorkError("launch intent binding mismatch")
        for key in (
            "run_id",
            "backend",
            "transport",
            "effective_model",
            "working_directory",
            "source_root",
            "tool_policy",
            "environment_allowlist_digest",
            "timeout_seconds_per_worker",
            "audit_snapshot_digest",
            "audit_config_digest",
            "methodology_digest",
            "source_ledger_digest",
        ):
            if intent.get(key) != plan.get(key):
                raise AdjudicationWorkError(f"launch intent {key} binding mismatch")
        if (
            str(intent.get("worker_identity") or "").casefold()
            in {
                str(value).casefold()
                for value in (intent.get("assessor_identities") or [])
            }
            or str(intent.get("invocation_id") or "").casefold()
            in {
                str(value).casefold()
                for value in (intent.get("assessor_invocation_ids") or [])
            }
        ):
            raise AdjudicationWorkError("assessor/adjudicator identity collision")
        prompt_text = prompt_bytes.decode("utf-8", errors="strict")
        for marker in (
            plan["plan_digest"],
            manifest["manifest_digest"],
            hashlib.sha256(context_bytes).hexdigest(),
            intent_name,
            tool_policy_name,
        ):
            if marker not in prompt_text:
                raise AdjudicationWorkError("prompt binding marker is missing")
        shard_outputs = shard.get("expected_outputs") or {}
        staged_outputs = shard.get("staged_outputs") or {}
        staging_scope = str(shard.get("staging_output_scope") or "")
        if not isinstance(shard_outputs, Mapping) or set(shard_outputs) != set(
            candidate_ids
        ):
            raise AdjudicationWorkError("expected output set differs from shard")
        if (
            not isinstance(staged_outputs, Mapping)
            or set(staged_outputs) != set(candidate_ids)
            or not staging_scope
            or Path(staging_scope).is_absolute()
            or any(
                part in {"", ".", ".."}
                for part in Path(staging_scope).parts
            )
        ):
            raise AdjudicationWorkError("staged output scope differs from shard")
        for candidate_id, output in shard_outputs.items():
            if output != manifest_items[candidate_id]["expected_output_file"]:
                raise AdjudicationWorkError("expected output ownership mismatch")
            staged = staged_outputs.get(candidate_id)
            if staged != Path(output).name or Path(str(staged)).name != staged:
                raise AdjudicationWorkError(
                    "staged output ownership mismatch"
                )
            if output in expected_outputs:
                raise AdjudicationWorkError("expected output is assigned more than once")
            expected_outputs.add(output)
            intent_by_candidate[candidate_id] = intent

    baseline_by_key = {
        candidate_id.casefold(): (candidate_id, digest)
        for candidate_id, digest in baseline_digests.items()
    }
    for current_id, current_decision in current_decisions.items():
        baseline_id, baseline_digest = baseline_by_key[current_id.casefold()]
        if current_id != baseline_id:
            raise AdjudicationWorkError("current source ledger identity casing drifted")
        if current_decision.get("decision_digest") == baseline_digest:
            continue
        item = manifest_items.get(current_id)
        intent = intent_by_candidate.get(current_id)
        if item is None or intent is None:
            raise AdjudicationWorkError(
                f"source decision {current_id} drifted outside adjudication ownership"
            )
        proposal_path = root / item["expected_output_file"]
        receipt_path = root / (
            f"verify_{current_id}.severity_adjudication_receipt.json"
        )
        # A decision-first crash is classified as explicit debt by reconcile;
        # it never authorizes a different candidate.  Any unaccompanied sibling
        # mutation is source-ledger drift and invalidates the work boundary.
        if not receipt_path.exists():
            if proposal_path.exists():
                continue
            raise AdjudicationWorkError(
                f"source decision {current_id} drifted without transaction artifacts"
            )
        # Exact proposal/receipt/transition parity is progression state and is
        # classified by reconcile below.  Prepared-work validation only proves
        # that the changed row is inside its assigned transaction boundary.

    debt_ids = [row.get("candidate_id") for row in plan.get("debt_items") or []]
    combined = assigned + debt_ids
    if len(combined) != len({str(item).casefold() for item in combined}):
        raise AdjudicationWorkError("work plan partition contains overlap")
    if set(combined) != set(denominator):
        raise AdjudicationWorkError("work plan partition does not equal denominator")
    if plan.get("launch_count") != len(plan.get("shards") or []):
        raise AdjudicationWorkError("launch count mismatch")
    if plan.get("zero_row_no_launch") is not (not denominator):
        raise AdjudicationWorkError("zero-row no-launch marker mismatch")
    if not denominator and (plan.get("shards") or plan.get("launch_count")):
        raise AdjudicationWorkError("zero-row plan attempted to launch work")
    if _glob_names(root, "severity_adjudication_context.*.json") != expected_contexts:
        raise AdjudicationWorkError("active context artifact set mismatch")
    if _glob_names(root, "severity_adjudication_prompt.*.md") != expected_prompts:
        raise AdjudicationWorkError("active prompt artifact set mismatch")
    if _glob_names(root, "severity_adjudication_launch_intent.*.json") != expected_intents:
        raise AdjudicationWorkError("active launch-intent artifact set mismatch")
    if (
        _glob_names(root, "severity_adjudication_tool_policy.*.json")
        != expected_tool_policies
    ):
        raise AdjudicationWorkError("active tool-policy artifact set mismatch")
    actual_outputs = _glob_names(
        root, "verify_*.severity_adjudication_proposal.json"
    )
    expected_by_key = {name.casefold(): name for name in expected_outputs}
    actual_keys: set[str] = set()
    for name in actual_outputs:
        key = name.casefold()
        if key in actual_keys:
            raise AdjudicationWorkError(
                "adjudication output ownership has a case collision"
            )
        actual_keys.add(key)
        if key not in expected_by_key:
            raise AdjudicationWorkError(
                f"unassigned adjudication output {name} is ownership debt"
            )
    expected_adjudication_receipts = {
        f"verify_{candidate_id}.severity_adjudication_receipt.json"
        for candidate_id in intent_by_candidate
    }
    actual_adjudication_receipts = _glob_names(
        root, "verify_*.severity_adjudication_receipt.json"
    )
    expected_receipt_by_key = {
        name.casefold(): name for name in expected_adjudication_receipts
    }
    for name in actual_adjudication_receipts:
        expected_name = expected_receipt_by_key.get(name.casefold())
        if expected_name is None:
            raise AdjudicationWorkError(
                f"unassigned adjudication receipt {name} is ownership debt"
            )
        if name != expected_name:
            raise AdjudicationWorkError(
                f"adjudication receipt {name} has non-canonical casing"
            )
    expected_worker_runs = {
        _worker_run_name(shard) for shard in (plan.get("shards") or [])
    }
    actual_worker_runs = _glob_names(
        root, "severity_adjudication_worker_run.*.json"
    )
    expected_run_by_key = {
        name.casefold(): name for name in expected_worker_runs
    }
    for name in actual_worker_runs:
        expected_name = expected_run_by_key.get(name.casefold())
        if expected_name is None:
            raise AdjudicationWorkError(
                f"unassigned worker-run receipt {name} is ownership debt"
            )
        if name != expected_name:
            raise AdjudicationWorkError(
                f"worker-run receipt {name} has non-canonical casing"
            )


def validate_prepared_work(scratchpad: Path) -> list[str]:
    """Return exact structural/binding defects without mutating work state."""

    try:
        _validate_prepared_work(Path(scratchpad))
    except Exception as exc:
        return [f"{type(exc).__name__}: {exc}"]
    return []


def _worker_run_name(shard: Mapping[str, Any]) -> str:
    intent_name = _require_text(
        shard.get("launch_intent_file"), "worker launch-intent filename"
    )
    match = re.fullmatch(
        r"severity_adjudication_launch_intent\.(\d{4})\.json",
        intent_name,
    )
    if not match:
        raise AdjudicationWorkError(
            "worker launch-intent filename is not canonical"
        )
    return f"severity_adjudication_worker_run.{match.group(1)}.json"


def _worker_output_rows(
    root: Path,
    *,
    shard: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    actual_names = _glob_names(
        root, "verify_*.severity_adjudication_proposal.json"
    )
    rows: dict[str, dict[str, Any]] = {}
    for candidate_id, raw_name in (shard.get("expected_outputs") or {}).items():
        output_path = _owned_child(
            root, raw_name, f"{candidate_id} worker output filename"
        )
        if output_path.name not in actual_names:
            raise AdjudicationWorkError(
                f"{candidate_id} completed worker output is missing or mis-cased"
            )
        raw = output_path.read_bytes()
        proposal = parse_severity_adjudication_proposal(raw)
        rows[str(candidate_id)] = {
            "file": output_path.name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "proposal_digest": _digest(proposal),
        }
    return rows


def severity_adjudication_output_digest(path: Path, raw: bytes) -> str:
    """Strict semantic digest used by the process-owning execution provider."""

    name = Path(path).name
    if not re.fullmatch(
        r"verify_[A-Za-z][A-Za-z0-9-]{0,95}\.severity_adjudication_proposal\.json",
        name,
    ):
        raise AdjudicationWorkError(
            "severity adjudication output filename is not canonical"
        )
    proposal = parse_severity_adjudication_proposal(raw)
    return _digest(proposal)


def _provider_relative_path(root: Path, path: Path, label: str) -> str:
    try:
        resolved_root = root.resolve(strict=True)
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(resolved_root).as_posix()
    except (OSError, ValueError) as exc:
        raise AdjudicationWorkError(
            f"{label} is not inside the scratchpad"
        ) from exc
    if not relative or relative.startswith("../"):
        raise AdjudicationWorkError(f"{label} has an invalid relative path")
    return relative


def _provider_digest_from_name(path: Path, prefix: str) -> str:
    match = re.fullmatch(rf"{re.escape(prefix)}_([0-9a-f]{{64}})\.json", path.name)
    if not match:
        raise AdjudicationWorkError(
            f"provider {prefix} receipt has a non-content-addressed filename"
        )
    return match.group(1)


def _argv_flag_value(argv: Sequence[str], flag: str) -> str:
    positions = [index for index, value in enumerate(argv) if value == flag]
    if len(positions) != 1 or positions[0] + 1 >= len(argv):
        raise AdjudicationWorkError(f"worker argv requires exactly one {flag}")
    return str(argv[positions[0] + 1])


def _validate_backend_argv(
    intent: Mapping[str, Any], argv: Sequence[str]
) -> None:
    """Prevent a successful unrelated process from satisfying backend intent."""

    if isinstance(argv, (str, bytes)) or not argv or any(
        not isinstance(value, str) or not value or "\x00" in value
        for value in argv
    ):
        raise AdjudicationWorkError("worker argv is not a canonical argument vector")
    backend = _require_text(intent.get("effective_backend"), "effective backend")
    model = _require_text(intent.get("effective_model"), "effective model")
    executable = Path(str(argv[0])).name.casefold()
    values = list(argv)
    if backend == "fixture-subprocess":
        if (
            model != "fixture-python"
            or executable != Path(sys.executable).name.casefold()
            or len(values) < 3
            or values[1] != "-c"
        ):
            raise AdjudicationWorkError(
                "fixture backend requires the current Python executable and -c"
            )
        return
    if backend == "claude":
        if executable not in {"claude", "claude.exe", "claude.cmd", "claude.bat"}:
            raise AdjudicationWorkError(
                "claude backend intent requires the Claude CLI executable"
            )
        if "-p" not in values and "--print" not in values:
            raise AdjudicationWorkError("claude adjudicator must use headless print mode")
        if _argv_flag_value(values, "--model") != model:
            raise AdjudicationWorkError("claude argv model differs from launch intent")
        if _argv_flag_value(values, "--output-format") != "json":
            raise AdjudicationWorkError("claude adjudicator must use JSON output mode")
        if _argv_flag_value(values, "--add-dir") != intent.get("source_root"):
            raise AdjudicationWorkError(
                "claude adjudicator source root differs from launch intent"
            )
        if _argv_flag_value(values, "--mcp-config") != "{}":
            raise AdjudicationWorkError(
                "claude adjudicator must use the bound empty MCP configuration"
            )
        required = {
            "--no-session-persistence",
            "--dangerously-skip-permissions",
            "--exclude-dynamic-system-prompt-sections",
            "--strict-mcp-config",
        }
        missing = sorted(required.difference(values))
        if missing:
            raise AdjudicationWorkError(
                "claude adjudicator argv lacks required isolation flags: "
                + ", ".join(missing)
            )
        allowed_tools = _argv_flag_value(values, "--allowedTools")
        if {part.strip() for part in allowed_tools.split(",")} != {"Read", "Write"}:
            raise AdjudicationWorkError(
                "claude adjudicator tool authority must be exactly Read,Write"
            )
        denied_tools = {
            part.strip()
            for part in _argv_flag_value(values, "--disallowedTools").split(",")
        }
        required_denials = {
            "Bash", "Edit", "WebFetch", "WebSearch", "Task", "Agent", "mcp__*"
        }
        if not required_denials.issubset(denied_tools):
            raise AdjudicationWorkError(
                "claude adjudicator argv does not enforce the bound denylist"
            )
        return
    if backend == "codex":
        if executable not in {"codex", "codex.exe", "codex.cmd", "codex.bat"}:
            raise AdjudicationWorkError(
                "codex backend intent requires the Codex CLI executable"
            )
        if len(values) < 2 or values[1] != "exec":
            raise AdjudicationWorkError("codex adjudicator must use exec mode")
        if _argv_flag_value(values, "--model") != model:
            raise AdjudicationWorkError("codex argv model differs from launch intent")
        for flag in (
            "--ephemeral",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
        ):
            if flag not in values:
                raise AdjudicationWorkError(
                    f"codex adjudicator argv lacks required isolation flag {flag}"
                )
        if values[-1] != "-":
            raise AdjudicationWorkError(
                "codex adjudicator must receive the bound prompt on stdin"
            )
        return
    raise AdjudicationWorkError(f"unsupported adjudication backend {backend!r}")


def _provider_execution_from_paths(
    root: Path,
    *,
    completion_path: Path,
    publish_path: Path,
    intent: Mapping[str, Any],
) -> CompletedExecution:
    completion_sha256 = _provider_digest_from_name(completion_path, "completion")
    publish_sha256 = _provider_digest_from_name(publish_path, "publish")
    try:
        completion = validate_completed_execution(
            scratchpad=root,
            receipt_path=completion_path,
            publish_receipt_path=publish_path,
            parser_digest=severity_adjudication_output_digest,
            expected_completion_sha256=completion_sha256,
            expected_publish_sha256=publish_sha256,
        )
    except WorkerExecutionError as exc:
        raise AdjudicationWorkError(
            f"provider-owned worker completion does not replay: {exc}"
        ) from exc
    arm_relative = completion.get("arm_relative_path")
    if not isinstance(arm_relative, str) or Path(arm_relative).name != arm_relative:
        raise AdjudicationWorkError("provider completion has an invalid arm path")
    arm_path = completion_path.parent / arm_relative
    arm_sha256 = _require_hex64(
        completion.get("arm_sha256"), "provider arm_sha256"
    )
    arm = _read_json(arm_path)
    process_intent = arm.get("process_intent")
    if not isinstance(process_intent, Mapping):
        raise AdjudicationWorkError("provider arm process intent is malformed")
    materialized = process_intent.get("claude_runtime_materialization")
    if (
        str(intent.get("effective_backend") or "").casefold() == "claude"
        and isinstance(materialized, Mapping)
    ):
        if "--dangerously-skip-permissions" in (
            process_intent.get("argv") or []
        ):
            raise AdjudicationWorkError(
                "transactional Claude provider retained an unsafe bypass flag"
            )
    else:
        _validate_backend_argv(intent, process_intent.get("argv") or [])
    expected_timeout = _require_int(
        intent.get("timeout_seconds_per_worker"),
        "launch intent timeout_seconds_per_worker",
        minimum=1,
    )
    if process_intent.get("timeout_seconds") != str(expected_timeout):
        raise AdjudicationWorkError(
            "provider arm timeout differs from the immutable launch intent"
        )
    return CompletedExecution(
        receipt_path=completion_path,
        completion_sha256=completion_sha256,
        arm_path=arm_path,
        arm_sha256=arm_sha256,
        publish_receipt_path=publish_path,
        publish_sha256=publish_sha256,
        published_paths=(),
    )


def _recover_provider_execution(
    root: Path, *, shard_id: str, intent: Mapping[str, Any]
) -> CompletedExecution | None:
    evidence = root / ".worker_execution_receipts" / shard_id
    if not evidence.exists():
        return None
    if evidence.is_symlink() or not evidence.is_dir():
        raise AdjudicationWorkError("worker execution evidence directory is unsafe")
    completions = sorted(evidence.glob("completion_*.json"))
    publishes = sorted(
        path
        for path in evidence.glob("publish_*.json")
        if not path.name.startswith("publish_arm_")
    )
    if len(completions) == 1 and len(publishes) == 1:
        return _provider_execution_from_paths(
            root,
            completion_path=completions[0],
            publish_path=publishes[0],
            intent=intent,
        )
    # Any provider artifact means a prior attempt armed.  A caller may not
    # reinterpret partial observation as success or silently relaunch the same
    # immutable shard over it; reconciliation must expose this as repair debt.
    if any(evidence.iterdir()):
        raise AdjudicationWorkError(
            "worker execution has incomplete or ambiguous provider evidence"
        )
    return None


def _provider_worker_debt_detail(
    root: Path, shard: Mapping[str, Any]
) -> str | None:
    """Classify durable provider evidence that must never be relaunched.

    A single completion/publication pair is a recoverable receipt-first window.
    Every provider debt receipt, incomplete arm, or multiple complete chains is
    instead terminal repair debt for the whole immutable shard.
    """

    shard_id = _require_text(shard.get("shard_id"), "worker shard_id")
    evidence = root / ".worker_execution_receipts" / shard_id
    if not evidence.exists():
        return None
    if evidence.is_symlink() or not evidence.is_dir():
        return "UNSAFE_EVIDENCE_DIRECTORY: provider evidence path is unsafe"
    completions = sorted(evidence.glob("completion_*.json"))
    publishes = sorted(
        path
        for path in evidence.glob("publish_*.json")
        if not path.name.startswith("publish_arm_")
    )
    debts = sorted(evidence.glob("debt_*.json"))
    if len(completions) > 1 or len(publishes) > 1:
        return (
            "AMBIGUOUS_RECEIPT_CHAINS: provider evidence contains multiple "
            "completion or publication authorities"
        )

    reason_rows: list[str] = []
    for debt_path in debts:
        try:
            debt = _read_json(debt_path)
            if debt.get("schema_version") != "plamen.worker_execution_debt.v1":
                raise AdjudicationWorkError("provider debt schema mismatch")
            debt_unsigned = {
                key: value for key, value in debt.items()
                if key != "debt_sha256"
            }
            provider_digest = hashlib.sha256(
                (
                    json.dumps(
                        debt_unsigned,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
            ).hexdigest()
            if debt.get("debt_sha256") != provider_digest:
                raise AdjudicationWorkError(
                    "provider worker debt digest mismatch"
                )
            if debt_path.name != f"debt_{debt['debt_sha256']}.json":
                raise AdjudicationWorkError(
                    "provider debt filename is not content addressed"
                )
            arm_name = debt.get("arm_relative_path")
            arm_sha = _require_hex64(
                debt.get("arm_sha256"), "provider debt arm_sha256"
            )
            if (
                not isinstance(arm_name, str)
                or Path(arm_name).name != arm_name
                or arm_name != f"arm_{arm_sha}.json"
                or not (evidence / arm_name).is_file()
            ):
                raise AdjudicationWorkError(
                    "provider debt does not bind one durable arm"
                )
            reason = _require_text(
                debt.get("reason_code"), "provider debt reason_code"
            )
            detail = str(debt.get("detail") or "").strip()
            reason_rows.append(f"{reason}: {detail}" if detail else reason)
        except Exception as exc:
            return f"INVALID_PROVIDER_DEBT: {type(exc).__name__}: {exc}"
    if reason_rows:
        return "; ".join(sorted(set(reason_rows)))

    # A complete, unique pair is safe for the execution boundary to replay and
    # synthesize the consumer worker-run receipt after a crash.
    if len(completions) == 1 and len(publishes) == 1:
        return None

    meaningful = [
        path
        for path in evidence.iterdir()
        if path.name != "shard.lock" and path.name != "blobs"
    ]
    if meaningful:
        return (
            "INCOMPLETE_PROVIDER_EVIDENCE: an immutable worker attempt armed "
            "without one complete publication chain"
        )
    return None


def _execution_contract(
    root: Path,
    *,
    plan: Mapping[str, Any],
    shard: Mapping[str, Any],
    intent: Mapping[str, Any],
) -> tuple[ExecutionBindings, tuple[ExpectedOutput, ...]]:
    if Path(str(plan.get("working_directory"))).resolve(strict=True) != root.resolve(
        strict=True
    ):
        raise AdjudicationWorkError(
            "severity worker cwd must be the scratchpad that owns its staged outputs"
        )
    raw_assessors = intent.get("assessor_principals")
    if not isinstance(raw_assessors, list) or not raw_assessors:
        raise AdjudicationWorkError("launch intent has no assessor principal denominator")
    assessors = tuple(
        PrincipalInvocation(
            _require_text(row.get("identity"), "assessor identity"),
            _require_text(row.get("invocation_id"), "assessor invocation_id"),
        )
        for row in raw_assessors
        if isinstance(row, Mapping)
    )
    if len(assessors) != len(raw_assessors):
        raise AdjudicationWorkError("launch intent assessor principals are malformed")
    bindings = ExecutionBindings(
        run_id=_require_text(plan.get("run_id"), "work plan run_id"),
        shard_id=_require_text(shard.get("shard_id"), "worker shard_id"),
        plan=BoundInput(WORK_PLAN_NAME),
        manifest=BoundInput(MANIFEST_NAME),
        intent=BoundInput(
            _require_text(shard.get("launch_intent_file"), "launch intent file")
        ),
        context=BoundInput(
            _require_text(shard.get("context_file"), "context file")
        ),
        prompt=BoundInput(
            _require_text(shard.get("prompt_file"), "prompt file")
        ),
        tool_policy=BoundInput(
            _require_text(shard.get("tool_policy_file"), "tool policy file")
        ),
        worker=PrincipalInvocation(
            _require_text(intent.get("worker_identity"), "worker identity"),
            _require_text(intent.get("invocation_id"), "worker invocation_id"),
        ),
        assessors=assessors,
        effective_backend=_require_text(
            intent.get("effective_backend"), "effective backend"
        ),
        effective_model=_require_text(
            intent.get("effective_model"), "effective model"
        ),
    )
    staged = shard.get("staged_outputs")
    published = shard.get("expected_outputs")
    if not isinstance(staged, Mapping) or not isinstance(published, Mapping):
        raise AdjudicationWorkError("worker output contract is malformed")
    outputs = tuple(
        ExpectedOutput(
            candidate_id,
            _require_text(staged.get(candidate_id), "staged output filename"),
            _require_text(published.get(candidate_id), "published output filename"),
        )
        for candidate_id in shard.get("candidate_ids") or []
    )
    return bindings, outputs


def _persist_worker_run(
    root: Path,
    *,
    plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    shard: Mapping[str, Any],
    intent: Mapping[str, Any],
    execution: CompletedExecution,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": WORKER_RUN_SCHEMA,
        "run_id": plan["run_id"],
        "shard_id": shard["shard_id"],
        "plan_digest": plan["plan_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "intent_file": shard["launch_intent_file"],
        "intent_digest": intent["intent_digest"],
        "worker_identity": intent["worker_identity"],
        "invocation_id": intent["invocation_id"],
        "backend": intent["effective_backend"],
        "effective_model": intent["effective_model"],
        "assessor_principals": list(intent["assessor_principals"]),
        "provider_completion_file": _provider_relative_path(
            root, execution.receipt_path, "provider completion receipt"
        ),
        "provider_completion_sha256": execution.completion_sha256,
        "provider_publish_file": _provider_relative_path(
            root, execution.publish_receipt_path, "provider publish receipt"
        ),
        "provider_publish_sha256": execution.publish_sha256,
        "provider_arm_file": _provider_relative_path(
            root, execution.arm_path, "provider arm receipt"
        ),
        "provider_arm_sha256": execution.arm_sha256,
        "completion_status": "COMPLETED",
        "outputs": _worker_output_rows(root, shard=shard),
    }
    receipt = _signed(unsigned, digest_field="receipt_digest")
    receipt_path = _owned_child(
        root, _worker_run_name(shard), "worker-run receipt filename"
    )
    _write_derived_exact_or_missing(receipt_path, _canonical_json_bytes(receipt))
    return receipt


def execute_adjudication_worker(
    scratchpad: Path,
    *,
    shard_id: str,
    argv: Sequence[str],
    startup_authority_binding: Mapping[str, Any] | None = None,
    environment: Mapping[str, str] | None = None,
    environment_allowlist: Collection[str] = (),
    timeout_seconds: float | None = None,
    provider_executor: Callable[[], CompletedExecution] | None = None,
) -> dict[str, Any]:
    """Execute or replay one provider-observed adjudication worker shard.

    There is intentionally no API that accepts a caller-authored exit status,
    process identity, transport receipt, or proposal as completion authority.
    """

    root = Path(scratchpad)
    issues = validate_prepared_work(root)
    if issues:
        raise AdjudicationWorkError(
            "cannot execute worker for invalid work: " + "; ".join(issues)
        )
    plan = _read_json(root / WORK_PLAN_NAME)
    manifest = _read_json(root / MANIFEST_NAME)
    shard_identity = _require_text(shard_id, "worker shard_id")
    matches = [
        row
        for row in plan.get("shards") or []
        if row.get("shard_id") == shard_identity
    ]
    if len(matches) != 1:
        raise AdjudicationWorkError("worker shard_id is not uniquely planned")
    shard = matches[0]
    planned_timeout = _require_int(
        plan.get("timeout_seconds_per_worker"),
        "work plan timeout_seconds_per_worker",
        minimum=1,
    )
    if timeout_seconds is None:
        timeout_seconds = planned_timeout
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or float(timeout_seconds) != float(planned_timeout)
    ):
        raise AdjudicationWorkError(
            "worker timeout differs from the immutable work plan"
        )
    existing_path = _owned_child(
        root, _worker_run_name(shard), "worker-run receipt filename"
    )
    if existing_path.exists():
        first = str((shard.get("candidate_ids") or [""])[0])
        return validate_completed_worker_run_for_candidate(root, first)
    intent = _read_json(root / shard["launch_intent_file"])
    intent_backend = str(intent.get("effective_backend") or "").casefold()
    if (
        intent_backend in {"claude", "codex"}
        and startup_authority_binding is None
    ):
        raise AdjudicationWorkError(
            "model adjudication launch lacks startup authority"
        )
    if intent_backend == "claude" and provider_executor is None:
        raise AdjudicationWorkError(
            "Claude backend adjudication requires the transactional provider "
            "executor; "
            "legacy direct launch is forbidden"
        )
    bindings, outputs = _execution_contract(
        root, plan=plan, shard=shard, intent=intent
    )
    if provider_executor is None:
        _validate_backend_argv(intent, argv)
    elif str(intent.get("effective_backend") or "").casefold() != "claude":
        raise AdjudicationWorkError(
            "transactional provider executor is reserved for Claude"
        )
    elif "--dangerously-skip-permissions" in tuple(argv):
        raise AdjudicationWorkError(
            "transactional Claude launch metadata contains an unsafe bypass"
        )
    expected_environment_digest = environment_allowlist_sha256(
        environment_allowlist
    )
    if expected_environment_digest != plan.get("environment_allowlist_digest"):
        raise AdjudicationWorkError(
            "runtime environment allowlist differs from the immutable work plan"
        )
    execution = _recover_provider_execution(
        root, shard_id=shard_identity, intent=intent
    )
    if execution is None:
        try:
            if provider_executor is not None:
                execution = provider_executor()
                if type(execution) is not CompletedExecution:
                    raise AdjudicationWorkError(
                        "transactional provider returned no exact completion"
                    )
                execution = _provider_execution_from_paths(
                    root,
                    completion_path=execution.receipt_path,
                    publish_path=execution.publish_receipt_path,
                    intent=intent,
                )
            else:
                execution = run_observed_worker(
                scratchpad=root,
                bindings=bindings,
                argv=argv,
                cwd=plan["working_directory"],
                output_scope_relative=shard["staging_output_scope"],
                expected_outputs=outputs,
                parser_digest=severity_adjudication_output_digest,
                environment=environment,
                environment_allowlist=environment_allowlist,
                stdin_input=BoundInput(shard["prompt_file"]),
                timeout_seconds=timeout_seconds,
                    startup_authority_binding=startup_authority_binding,
                )
        except WorkerExecutionError as exc:
            raise AdjudicationWorkError(
                f"provider-owned worker execution did not complete: {exc}"
            ) from exc
    return _persist_worker_run(
        root,
        plan=plan,
        manifest=manifest,
        shard=shard,
        intent=intent,
        execution=execution,
    )


def validate_completed_worker_run_for_candidate(
    scratchpad: Path,
    candidate_id: str,
) -> dict[str, Any]:
    """Return the exact completed-run authority for one planned candidate."""

    root = Path(scratchpad)
    issues = validate_prepared_work(root)
    if issues:
        raise AdjudicationWorkError(
            "prepared work is invalid: " + "; ".join(issues)
        )
    candidate = _require_text(candidate_id, "worker-run candidate_id")
    plan = _read_json(root / WORK_PLAN_NAME)
    manifest = _read_json(root / MANIFEST_NAME)
    matches = [
        shard for shard in plan.get("shards") or []
        if candidate in (shard.get("candidate_ids") or [])
    ]
    if len(matches) != 1:
        raise AdjudicationWorkError(
            f"{candidate} has no unique adjudication worker owner"
        )
    shard = matches[0]
    receipt_path = _owned_child(
        root, _worker_run_name(shard), "worker-run receipt filename"
    )
    receipt = _read_json(receipt_path)
    expected_fields = {
        "schema_version", "run_id", "shard_id", "plan_digest",
        "manifest_digest", "intent_file", "intent_digest",
        "worker_identity", "invocation_id", "backend", "effective_model",
        "assessor_principals", "provider_completion_file",
        "provider_completion_sha256", "provider_publish_file",
        "provider_publish_sha256", "provider_arm_file",
        "provider_arm_sha256", "completion_status",
        "outputs", "receipt_digest",
    }
    unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    intent_path = _owned_child(
        root, shard["launch_intent_file"], "worker launch-intent filename"
    )
    intent = _read_json(intent_path)
    current_outputs = _worker_output_rows(root, shard=shard)
    if (
        set(receipt) != expected_fields
        or receipt.get("schema_version") != WORKER_RUN_SCHEMA
        or receipt.get("receipt_digest") != _digest(unsigned)
        or receipt.get("run_id") != plan.get("run_id")
        or receipt.get("shard_id") != shard.get("shard_id")
        or receipt.get("plan_digest") != plan.get("plan_digest")
        or receipt.get("manifest_digest") != manifest.get("manifest_digest")
        or receipt.get("intent_file") != intent_path.name
        or receipt.get("intent_digest") != intent.get("intent_digest")
        or receipt.get("worker_identity") != intent.get("worker_identity")
        or receipt.get("invocation_id") != intent.get("invocation_id")
        or receipt.get("backend") != intent.get("effective_backend")
        or receipt.get("effective_model") != intent.get("effective_model")
        or receipt.get("assessor_principals") != intent.get("assessor_principals")
        or not _HEX64_RE.fullmatch(
            str(receipt.get("provider_completion_sha256") or "")
        )
        or not _HEX64_RE.fullmatch(
            str(receipt.get("provider_publish_sha256") or "")
        )
        or not _HEX64_RE.fullmatch(str(receipt.get("provider_arm_sha256") or ""))
        or receipt.get("completion_status") != "COMPLETED"
        or receipt.get("outputs") != current_outputs
    ):
        raise AdjudicationWorkError(
            f"{candidate} worker-run completion receipt is invalid"
        )
    try:
        completion_path = root / _require_text(
            receipt.get("provider_completion_file"),
            "provider completion receipt path",
        )
        publish_path = root / _require_text(
            receipt.get("provider_publish_file"),
            "provider publish receipt path",
        )
        execution = _provider_execution_from_paths(
            root,
            completion_path=completion_path,
            publish_path=publish_path,
            intent=intent,
        )
    except (OSError, WorkerExecutionError, AdjudicationWorkError) as exc:
        raise AdjudicationWorkError(
            f"{candidate} provider-owned execution receipt is invalid: {exc}"
        ) from exc
    if (
        _provider_relative_path(root, execution.receipt_path, "provider completion")
        != receipt.get("provider_completion_file")
        or execution.completion_sha256
        != receipt.get("provider_completion_sha256")
        or _provider_relative_path(root, execution.publish_receipt_path, "provider publish")
        != receipt.get("provider_publish_file")
        or execution.publish_sha256 != receipt.get("provider_publish_sha256")
        or _provider_relative_path(root, execution.arm_path, "provider arm")
        != receipt.get("provider_arm_file")
        or execution.arm_sha256 != receipt.get("provider_arm_sha256")
    ):
        raise AdjudicationWorkError(
            f"{candidate} worker-run/provider authority binding mismatch"
        )
    return receipt


def _validate_existing_receipt(
    *,
    receipt: Mapping[str, Any],
    intent: Mapping[str, Any],
    item: Mapping[str, Any],
    proposal_path: Path,
    proposal: Mapping[str, Any],
    current_decision: Mapping[str, Any],
    worker_run: Mapping[str, Any],
) -> None:
    receipt_keys = {
        "schema_version",
        "candidate_id",
        "source_decision_digest",
        "adjudicator_input_sha256",
        "result_decision_digest",
        "proposal_file",
        "proposal_sha256",
        "proposal_size_bytes",
        "launch_receipt",
        "receipt_digest",
    }
    launch_keys = {
        "schema_version",
        "role",
        "run_id",
        "candidate_id",
        "constituent_ids",
        "worker_identity",
        "invocation_id",
        "backend",
        "launch_manifest_sha256",
        "input_sha256",
        "output_sha256",
    }
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    proposal_bytes = proposal_path.read_bytes()
    launch = receipt.get("launch_receipt") or {}
    candidate_id = item["candidate_id"]
    if (
        set(receipt) != receipt_keys
        or not isinstance(launch, Mapping)
        or set(launch) != launch_keys
        or receipt.get("schema_version")
        != "plamen.severity_adjudication_receipt.v1"
        or receipt.get("receipt_digest") != _digest(unsigned)
        or receipt.get("candidate_id") != candidate_id
        or receipt.get("source_decision_digest") != item["source_decision_digest"]
        or receipt.get("adjudicator_input_sha256")
        != item.get("adjudicator_input_sha256")
        or receipt.get("result_decision_digest") != current_decision.get("decision_digest")
        or receipt.get("proposal_file") != proposal_path.name
        or receipt.get("proposal_sha256") != hashlib.sha256(proposal_bytes).hexdigest()
        or receipt.get("proposal_size_bytes") != len(proposal_bytes)
        or launch.get("schema_version") != LAUNCH_RECEIPT_SCHEMA
        or launch.get("role") != "ADJUDICATOR"
        or launch.get("run_id") != intent.get("run_id")
        or launch.get("candidate_id") != candidate_id
        or launch.get("constituent_ids") != item.get("constituent_ids")
        or launch.get("worker_identity") != intent.get("worker_identity")
        or launch.get("invocation_id") != intent.get("invocation_id")
        or launch.get("backend") != worker_run.get("backend")
        or launch.get("launch_manifest_sha256")
        != worker_run.get("receipt_digest")
        or launch.get("input_sha256") != item.get("adjudicator_input_sha256")
        or launch.get("output_sha256") != _digest(proposal)
    ):
        raise AdjudicationWorkError(
            f"{candidate_id} adjudication receipt/launch binding mismatch"
        )
    history = list(current_decision.get("adjudication_history") or [])
    if not history:
        raise AdjudicationWorkError(
            f"{candidate_id} receipt exists without adjudication history"
        )
    event = history[-1]
    binding = (event.get("adjudicator_authority_binding") or {}).get("receipt") or {}
    if binding != launch or event.get("source_decision_digest") != item[
        "source_decision_digest"
    ]:
        raise AdjudicationWorkError(
            f"{candidate_id} adjudication history/receipt mismatch"
        )


def _validate_pending_receipt(
    *,
    receipt: Mapping[str, Any],
    intent: Mapping[str, Any],
    item: Mapping[str, Any],
    proposal_path: Path,
    proposal: Mapping[str, Any],
    current_decision: Mapping[str, Any],
    worker_run: Mapping[str, Any],
) -> None:
    """Prove a receipt-first crash is exactly the next bound transition."""

    candidate_id = item["candidate_id"]
    proposal_bytes = proposal_path.read_bytes()
    launch = {
        "schema_version": LAUNCH_RECEIPT_SCHEMA,
        "role": "ADJUDICATOR",
        "run_id": intent["run_id"],
        "candidate_id": candidate_id,
        "constituent_ids": list(item.get("constituent_ids") or []),
        "worker_identity": intent["worker_identity"],
        "invocation_id": intent["invocation_id"],
        "backend": worker_run["backend"],
        "launch_manifest_sha256": worker_run["receipt_digest"],
        "input_sha256": item["adjudicator_input_sha256"],
        "output_sha256": _digest(proposal),
    }
    try:
        updated = bind_severity_adjudication(
            proposal,
            decision=current_decision,
            adjudicator_launch_receipt=launch,
        )
    except Exception as exc:
        raise AdjudicationWorkError(
            f"{candidate_id} receipt-first transition cannot be replayed: {exc}"
        ) from exc
    unsigned = {
        "schema_version": "plamen.severity_adjudication_receipt.v1",
        "candidate_id": candidate_id,
        "source_decision_digest": item["source_decision_digest"],
        "adjudicator_input_sha256": item["adjudicator_input_sha256"],
        "result_decision_digest": updated["decision_digest"],
        "proposal_file": proposal_path.name,
        "proposal_sha256": hashlib.sha256(proposal_bytes).hexdigest(),
        "proposal_size_bytes": len(proposal_bytes),
        "launch_receipt": launch,
    }
    expected = {**unsigned, "receipt_digest": _digest(unsigned)}
    if receipt != expected:
        raise AdjudicationWorkError(
            f"{candidate_id} receipt-first artifact does not bind the exact next transition"
        )


def reconcile_adjudication_work(scratchpad: Path) -> dict[str, Any]:
    """Classify every denominator row after worker/binder progress.

    ``OUTPUT_READY`` is the only state that authorizes the caller to invoke the
    existing binder.  Every crash window, malformed output, source drift, cap
    overflow, or unresolved adjudication remains explicit debt.
    """

    root = Path(scratchpad)
    issues = validate_prepared_work(root)
    if issues:
        raise AdjudicationWorkError("cannot reconcile invalid work: " + "; ".join(issues))
    manifest = _read_json(root / MANIFEST_NAME)
    plan = _read_json(root / WORK_PLAN_NAME)
    items = {row["candidate_id"]: row for row in manifest["work_items"]}
    shard_for: dict[str, Mapping[str, Any]] = {}
    shard_owner: dict[str, Mapping[str, Any]] = {}
    shard_debt: dict[str, str] = {}
    for shard in plan["shards"]:
        intent = _read_json(root / shard["launch_intent_file"])
        debt_detail = _provider_worker_debt_detail(root, shard)
        if debt_detail:
            shard_debt[str(shard["shard_id"])] = debt_detail
        for candidate_id in shard["candidate_ids"]:
            shard_for[candidate_id] = intent
            shard_owner[candidate_id] = shard

    states: dict[str, str] = {}
    details: dict[str, str] = {}
    debt_by_id = {
        row["candidate_id"]: row for row in plan.get("debt_items") or []
    }
    actual_output_names = _glob_names(
        root, "verify_*.severity_adjudication_proposal.json"
    )
    for candidate_id in plan["denominator_ids"]:
        if candidate_id in debt_by_id:
            states[candidate_id] = debt_by_id[candidate_id]["state"]
            details[candidate_id] = debt_by_id[candidate_id]["reason"]
            continue
        owner = shard_owner[candidate_id]
        provider_debt = shard_debt.get(str(owner["shard_id"]))
        if provider_debt:
            states[candidate_id] = "WORKER_EXECUTION_DEBT"
            details[candidate_id] = provider_debt
            continue
        item = items[candidate_id]
        intent = shard_for[candidate_id]
        decision_path = root / f"verify_{candidate_id}.severity_decision.json"
        try:
            current = _read_json(decision_path)
            severity_adjudicator_input_digest(current)
        except Exception as exc:
            states[candidate_id] = "SOURCE_DECISION_INVALID"
            details[candidate_id] = str(exc)
            continue
        current_digest = str(current.get("decision_digest") or "")
        expected_output_name = item["expected_output_file"]
        case_matches = sorted(
            name
            for name in actual_output_names
            if name.casefold() == expected_output_name.casefold()
        )
        if case_matches and case_matches != [expected_output_name]:
            states[candidate_id] = "OUTPUT_CASE_COLLISION"
            details[candidate_id] = (
                "adjudication output filename casing differs from its exact "
                "assigned owner"
            )
            continue
        output_path = root / expected_output_name
        receipt_path = root / f"verify_{candidate_id}.severity_adjudication_receipt.json"
        proposal: Mapping[str, Any] | None = None
        worker_run: Mapping[str, Any] | None = None
        if output_path.exists():
            try:
                parsed = parse_severity_adjudication_proposal(output_path.read_bytes())
                proposal = parsed
            except Exception as exc:
                states[candidate_id] = "OUTPUT_INVALID"
                details[candidate_id] = str(exc)
                continue
        if proposal is not None:
            worker_run_path = root / _worker_run_name(shard_owner[candidate_id])
            if not worker_run_path.exists():
                states[candidate_id] = "OUTPUT_UNATTESTED"
                details[candidate_id] = (
                    "proposal exists without a completed driver worker-run receipt"
                )
                continue
            try:
                worker_run = validate_completed_worker_run_for_candidate(
                    root, candidate_id
                )
            except Exception as exc:
                states[candidate_id] = "WORKER_RUN_INVALID"
                details[candidate_id] = str(exc)
                continue
        receipt: Mapping[str, Any] | None = None
        if receipt_path.exists():
            try:
                loaded = _read_json(receipt_path)
                receipt = loaded
            except Exception as exc:
                states[candidate_id] = "RECEIPT_INVALID"
                details[candidate_id] = str(exc)
                continue

        if current_digest == item["source_decision_digest"]:
            if receipt is not None:
                if proposal is None:
                    states[candidate_id] = "RECEIPT_WITHOUT_OUTPUT"
                    details[candidate_id] = (
                        "receipt-first artifact exists but proposal output is missing"
                    )
                else:
                    try:
                        _validate_pending_receipt(
                            receipt=receipt,
                            intent=intent,
                            item=item,
                            proposal_path=output_path,
                            proposal=proposal,
                            current_decision=current,
                            worker_run=worker_run,
                        )
                    except Exception as exc:
                        states[candidate_id] = "RECEIPT_INVALID"
                        details[candidate_id] = str(exc)
                    else:
                        states[candidate_id] = "RECEIPT_PENDING_DECISION_COMMIT"
                        details[candidate_id] = (
                            "validated receipt-first commit exists while source "
                            "decision remains unchanged"
                        )
            elif proposal is not None:
                states[candidate_id] = "OUTPUT_READY"
            else:
                states[candidate_id] = "PENDING"
            continue
        if receipt is None:
            states[candidate_id] = "DECISION_COMMIT_WITHOUT_RECEIPT"
            details[candidate_id] = "decision changed without a bound raw-output receipt"
            continue
        if proposal is None:
            states[candidate_id] = "RECEIPT_WITHOUT_OUTPUT"
            details[candidate_id] = "receipt/decision exist but proposal output is missing"
            continue
        try:
            _validate_existing_receipt(
                receipt=receipt,
                intent=intent,
                item=item,
                proposal_path=output_path,
                proposal=proposal,
                current_decision=current,
                worker_run=worker_run,
            )
        except Exception as exc:
            states[candidate_id] = "BINDING_MISMATCH"
            details[candidate_id] = str(exc)
            continue
        status = str(current.get("status") or "")
        if status == "RESOLVED":
            states[candidate_id] = "COMPLETED"
        elif status == "UNRESOLVED_SEVERITY":
            states[candidate_id] = "COMPLETED_UNRESOLVED"
            details[candidate_id] = "independent adjudication retained unresolved severity"
        else:
            states[candidate_id] = "COMMITTED_NONTERMINAL"
            details[candidate_id] = f"bound adjudication ended in source status {status}"

    bind_ready = sorted(candidate for candidate, state in states.items() if state == "OUTPUT_READY")
    completed = sorted(candidate for candidate, state in states.items() if state == "COMPLETED")
    pending = sorted(candidate for candidate, state in states.items() if state == "PENDING")
    non_debt = {"OUTPUT_READY", "COMPLETED"}
    debt = sorted(candidate for candidate, state in states.items() if state not in non_debt)
    unsigned = {
        "schema_version": RECONCILIATION_SCHEMA,
        "run_id": plan["run_id"],
        "plan_digest": plan["plan_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "denominator_count": len(plan["denominator_ids"]),
        "denominator_ids": list(plan["denominator_ids"]),
        "states": {key: states[key] for key in sorted(states)},
        "details": {key: details[key] for key in sorted(details)},
        "pending_ids": pending,
        "bind_ready_ids": bind_ready,
        "completed_ids": completed,
        "debt_ids": debt,
        "all_terminal": not pending and not bind_ready,
        "all_resolved": len(completed) == len(plan["denominator_ids"]),
    }
    result = _signed(unsigned, digest_field="reconciliation_digest")
    _atomic_json(root / RECONCILIATION_NAME, result)
    return result


def validate_reconciliation(scratchpad: Path) -> list[str]:
    """Validate the persisted reconciliation against a fresh exact replay."""

    root = Path(scratchpad)
    path = root / RECONCILIATION_NAME
    try:
        persisted = _read_json(path)
        _verify_signed(
            persisted,
            digest_field="reconciliation_digest",
            label="adjudication reconciliation",
        )
        recomputed = reconcile_adjudication_work(root)
        if persisted != recomputed:
            raise AdjudicationWorkError("adjudication reconciliation replay mismatch")
    except Exception as exc:
        return [f"{type(exc).__name__}: {exc}"]
    return []


__all__ = [
    "AdjudicationWorkError",
    "MANIFEST_NAME",
    "WORK_PLAN_NAME",
    "RECONCILIATION_NAME",
    "build_adjudication_manifest",
    "execute_adjudication_worker",
    "prepare_adjudication_work",
    "reconcile_adjudication_work",
    "severity_adjudication_output_digest",
    "validate_completed_worker_run_for_candidate",
    "validate_prepared_work",
    "validate_reconciliation",
]
