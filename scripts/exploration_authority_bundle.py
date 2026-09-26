"""Immutable authority substrates for exploration repair and enumgap replay.

The live canonical identity projection is expected to change after new
findings are admitted.  Exploration-clear aliases therefore replay from an
immutable snapshot, never from the later live projection.  Repair execution
uses a separate immutable terminal companion; the authorization arm remains
unchanged because it is a model input.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from bounded_artifact_io import read_bounded_regular_bytes
from exploration_clear_lifecycle import (
    _canonical_alias_projection,
    _repair_response_rows,
)


PRIOR_SNAPSHOT_NAME = "exploration_clear_prior_identity_map.json"
PRIOR_ALIAS_NAME = "exploration_clear_prior_aliases.json"
PRIOR_SNAPSHOT_SCHEMA = "plamen.exploration_clear_prior_identity_map.v1"
PRIOR_ALIAS_SCHEMA = "plamen.exploration_clear_prior_aliases.v2"
REPAIR_TERMINAL_NAME = "exploration_clear_repair_result.json"
REPAIR_TERMINAL_SCHEMA = "plamen.exploration_clear_repair_result.v1"
REPAIR_PROVIDER_OUTCOME_NAME = "exploration_clear_repair_provider_outcome.json"
REPAIR_PROVIDER_OUTCOME_SCHEMA = "plamen.exploration_clear_provider_outcome.v1"

CANONICAL_MAP_NAME = "_canonical_finding_ids.json"
CANONICAL_MAP_SCHEMA = "plamen.canonical_finding_ids.v1"
REPAIR_PLAN_SCHEMA = "plamen.exploration_clear_repair_plan.v1"
REPAIR_ARM_SCHEMA = "plamen.exploration_clear_repair_attempt.v1"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_CID_RE = re.compile(r"^CID-[A-F0-9]{16}$", re.ASCII)
_INVOCATION_RE = re.compile(r"^ECRA-[A-F0-9]{24}$", re.ASCII)
_MAX_BYTES = 64 * 1024 * 1024
EXPLORATION_CLEAR_STAGED_GATE_SCHEMA = (
    "plamen.exploration_clear_staged_response_gate.v1"
)


def staged_exploration_clear_response_validator(
    outputs: Mapping[str, bytes], context: Mapping[str, Any],
) -> tuple[str, ...]:
    """Validate a complete repair denominator before MODEL publication.

    Exact source loci are adjudicated again by the lifecycle reconciler after
    publication.  This gate proves that the staged response is plan-bound and
    contains one duplicate-free row for every planned obligation, allowing
    those exact bytes to survive a late provider transport failure safely.
    """

    required_context = {
        "schema", "output_identity", "plan_id", "plan_hash",
        "obligation_ids",
    }
    if (
        not isinstance(context, Mapping)
        or set(context) != required_context
        or context.get("schema") != EXPLORATION_CLEAR_STAGED_GATE_SCHEMA
        or not isinstance(context.get("output_identity"), str)
        or not isinstance(context.get("plan_id"), str)
        or not isinstance(context.get("plan_hash"), str)
        or not isinstance(context.get("obligation_ids"), list)
    ):
        return ("exploration-clear staged context is malformed",)
    identity = str(context["output_identity"])
    obligation_ids = context["obligation_ids"]
    if (
        set(outputs) != {identity}
        or any(not isinstance(value, bytes) for value in outputs.values())
        or any(not isinstance(value, str) or not value for value in obligation_ids)
        or len(set(obligation_ids)) != len(obligation_ids)
        or obligation_ids != sorted(obligation_ids)
    ):
        return ("exploration-clear staged denominator is malformed",)
    raw = outputs[identity]
    if not raw or len(raw) > _MAX_BYTES:
        return ("exploration-clear staged response size is unsafe",)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return ("exploration-clear staged response is not UTF-8",)
    plan_id, plan_hash, rows, parse_debt = _repair_response_rows(text)
    issues = list(parse_debt)
    if plan_id != context["plan_id"] or plan_hash != context["plan_hash"]:
        issues.append("exploration-clear staged response does not bind the plan")
    row_ids = [cells[0] for cells in rows]
    if row_ids != obligation_ids:
        issues.append(
            "exploration-clear staged response obligation denominator differs"
        )
    for cells in rows:
        obligation_id, disposition, evidence, action_id, rationale = cells
        disposition = disposition.strip().upper()
        if disposition == "CLEAR":
            if not evidence.strip() or action_id.strip():
                issues.append(
                    f"{obligation_id}: CLEAR needs evidence and no action ID"
                )
        elif disposition in {"ADD", "ADDITIVE"}:
            if (
                not evidence.strip()
                or re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_.:-]{2,127}", action_id.strip()
                ) is None
            ):
                issues.append(
                    f"{obligation_id}: ADD needs evidence and one action ID"
                )
        elif disposition in {"UNRESOLVED", "UNAVAILABLE"}:
            if action_id.strip():
                issues.append(
                    f"{obligation_id}: unresolved disposition has an action ID"
                )
        else:
            issues.append(
                f"{obligation_id}: unsupported staged repair disposition"
            )
        if not rationale.strip():
            issues.append(f"{obligation_id}: staged rationale is empty")
    return tuple(dict.fromkeys(issues))


def exploration_clear_project_locus_inputs(
    text: str, project_root: Path,
) -> tuple[str, ...]:
    """Bind raw bytes for every existing production file cited as a locus."""

    results: set[str] = set()
    pattern = re.compile(
        r"(?<![A-Za-z0-9_:/\\])"
        r"(?P<path>(?![A-Za-z]:[\\/])"
        r"(?:[A-Za-z0-9_. -]+[\\/])*[A-Za-z0-9_. -]+)"
        r"(?::(?:L)?|#L)[1-9][0-9]*(?![A-Za-z0-9])",
        re.ASCII,
    )
    root = Path(project_root).resolve(strict=False)
    for match in pattern.finditer(text):
        relative = match.group("path").strip().replace("\\", "/")
        parsed = PurePosixPath(relative)
        if (
            not relative
            or parsed.is_absolute()
            or any(part in {"", ".", ".."} for part in parsed.parts)
        ):
            continue
        candidate = root.joinpath(*parsed.parts).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.is_file():
            results.add(f"project::{parsed.as_posix()}")
    return tuple(sorted(results))


def render_exploration_clear_repair_prompt(
    *, plan: Any, scratchpad: Path, project_root: Path,
) -> str:
    """Render the model-visible repair contract from immutable plan authority."""

    items = "\n".join(
        f"- {item.obligation_id}: finding={item.source_finding}; "
        f"axis={item.axis}; instance={item.instance}; "
        f"original={item.original_disposition}; evidence={item.original_evidence}"
        for item in plan.items
    )
    return f"""You are an independent exploration-completeness repair worker.

Analyze only the exact obligations in the driver-owned plan below. Inspect the
authorized production source when needed. You may CLEAR an obligation only
with an exact existing production `relative/file.ext:L<number>` locus or an
exact canonical prior identity recorded in
`{(scratchpad / PRIOR_ALIAS_NAME).as_posix()}`. If analysis reveals
a candidate, use ADD with one new stable action ID; this is unverified generator
output that must enter the normal independent verification path. Otherwise use
UNRESOLVED. You may not delete, merge, downgrade, or certify any finding.

Project root: {project_root.as_posix()}
Source exploration artifact: {(scratchpad / 'exploration_skeptic_findings.md').as_posix()}
Plan file: {(scratchpad / 'exploration_clear_repair_plan.json').as_posix()}
Output file: {(scratchpad / 'exploration_clear_repair_response.md').as_posix()}

Exact obligations:
{items}

Write exactly this Markdown structure, with one row for every obligation and no
additional table rows:

# Exploration Clear Repair

**Plan ID**: {plan.plan_id}
**Plan Hash**: {plan.plan_hash}

## Repair Dispositions

| Obligation ID | Disposition | Evidence | Action ID | Rationale |
|---|---|---|---|---|
| ECLR-... | CLEAR / ADD / UNRESOLVED | exact evidence | action ID only for ADD | concise rationale |

SCOPE: Write ONLY to your assigned output file. Do NOT read or write other agents' output files. Do NOT proceed to subsequent pipeline phases. Return your findings and stop.
"""


def exploration_attempt_matches_plan(payload: Any, plan: Any) -> bool:
    return bool(
        isinstance(payload, dict)
        and payload.get("schema_version") == REPAIR_ARM_SCHEMA
        and payload.get("plan_id") == plan.plan_id
        and payload.get("plan_hash") == plan.plan_hash
        and payload.get("source_receipt_hash") == plan.source_receipt_hash
        and payload.get("phase") == "exploration_clear"
        and isinstance(payload.get("model"), str)
        and bool(str(payload.get("model") or "").strip())
        and type(payload.get("timeout_s")) is int
        and 60 <= int(payload.get("timeout_s")) <= 3600
    )


def load_exploration_attempt(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def exploration_response_binds_plan(path: Path, plan: Any) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    plan_id = re.findall(
        r"(?im)^\s*\*\*Plan ID\*\*\s*:\s*(\S+)\s*$", text
    )
    plan_hash = re.findall(
        r"(?im)^\s*\*\*Plan Hash\*\*\s*:\s*([0-9a-f]+)\s*$", text
    )
    return plan_id == [plan.plan_id] and [
        value.lower() for value in plan_hash
    ] == [plan.plan_hash]


class ExplorationAuthorityError(ValueError):
    """An immutable exploration authority cannot be replayed exactly."""


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExplorationAuthorityError(
                f"duplicate JSON key in exploration authority: {key}"
            )
        result[key] = value
    return result


def _json_payload(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExplorationAuthorityError(f"{label} is not strict JSON") from exc
    if not isinstance(payload, dict):
        raise ExplorationAuthorityError(f"{label} root is not an object")
    return payload


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _file_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_records(payload: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    rows = payload.get("records")
    count = payload.get("record_count")
    if (
        payload.get("schema_version") != CANONICAL_MAP_SCHEMA
        or not isinstance(rows, list)
        or type(count) is not int
        or count != len(rows)
    ):
        raise ExplorationAuthorityError(
            "canonical identity snapshot source schema or denominator mismatch"
        )
    records: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise ExplorationAuthorityError(
                f"canonical identity row {index} is malformed"
            )
        required = ("canonical_id", "artifact", "local_id", "local_id_raw")
        if any(not isinstance(raw.get(key), str) for key in required):
            raise ExplorationAuthorityError(
                f"canonical identity row {index} field types are invalid"
            )
        canonical = str(raw["canonical_id"]).strip()
        artifact = str(raw["artifact"]).strip()
        if (
            _CID_RE.fullmatch(canonical) is None
            or not artifact
            or Path(artifact).name != artifact
            or not str(raw["local_id"]).strip()
            or not str(raw["local_id_raw"]).strip()
        ):
            raise ExplorationAuthorityError(
                f"canonical identity row {index} is not authority-shaped"
            )
        records.append(dict(raw))
    return tuple(records)


@dataclass(frozen=True)
class ImmutablePriorBundle:
    snapshot_payload: dict[str, Any]
    alias_payload: dict[str, Any]
    snapshot_bytes: bytes
    alias_bytes: bytes
    aliases: dict[str, str]
    ambiguous_aliases: dict[str, tuple[str, ...]]

    @property
    def output_vector(self) -> dict[str, bytes]:
        return {
            PRIOR_SNAPSHOT_NAME: self.snapshot_bytes,
            PRIOR_ALIAS_NAME: self.alias_bytes,
        }

    @property
    def exact_outputs(self) -> tuple[str, ...]:
        return (PRIOR_SNAPSHOT_NAME, PRIOR_ALIAS_NAME)


def build_immutable_prior_bundle(
    canonical_identity_map_bytes: bytes | None,
) -> ImmutablePriorBundle:
    """Freeze one canonical-prior generation and its alias projection."""

    if canonical_identity_map_bytes is not None and (
        not isinstance(canonical_identity_map_bytes, bytes)
        or not canonical_identity_map_bytes
        or len(canonical_identity_map_bytes) > _MAX_BYTES
    ):
        raise ExplorationAuthorityError(
            "canonical identity map byte denominator is invalid"
        )
    source_raw = canonical_identity_map_bytes or b""
    records = (
        _canonical_records(_json_payload(source_raw, "canonical identity map"))
        if canonical_identity_map_bytes is not None else ()
    )
    snapshot_unsigned = {
        "schema_version": PRIOR_SNAPSHOT_SCHEMA,
        "source_artifact": CANONICAL_MAP_NAME,
        "source_present": canonical_identity_map_bytes is not None,
        "source_sha256": _sha(source_raw) if source_raw else "",
        "source_size_bytes": len(source_raw),
        "source_content_b64": base64.b64encode(
            source_raw
        ).decode("ascii"),
    }
    snapshot_payload = {
        **snapshot_unsigned,
        "snapshot_digest": _digest(snapshot_unsigned),
    }
    snapshot_bytes = _file_bytes(snapshot_payload)
    aliases, ambiguous = _canonical_alias_projection(records)
    alias_unsigned = {
        "schema_version": PRIOR_ALIAS_SCHEMA,
        "snapshot_artifact": PRIOR_SNAPSHOT_NAME,
        "snapshot_sha256": _sha(snapshot_bytes),
        "snapshot_digest": snapshot_payload["snapshot_digest"],
        "aliases": dict(sorted(aliases.items())),
        "ambiguous_short_aliases": {
            key: list(values) for key, values in sorted(ambiguous.items())
        },
    }
    alias_payload = {
        **alias_unsigned,
        "alias_receipt_sha256": _digest(alias_unsigned),
    }
    alias_bytes = _file_bytes(alias_payload)
    return ImmutablePriorBundle(
        snapshot_payload=snapshot_payload,
        alias_payload=alias_payload,
        snapshot_bytes=snapshot_bytes,
        alias_bytes=alias_bytes,
        aliases=dict(aliases),
        ambiguous_aliases=dict(ambiguous),
    )


def load_immutable_prior_bundle_bytes(
    *, snapshot_bytes: bytes, alias_bytes: bytes,
) -> ImmutablePriorBundle:
    """Replay aliases exclusively from immutable snapshot bytes."""

    snapshot = _json_payload(snapshot_bytes, "exploration prior snapshot")
    alias = _json_payload(alias_bytes, "exploration prior aliases")
    snapshot_required = {
        "schema_version", "source_artifact", "source_sha256",
        "source_present", "source_size_bytes", "source_content_b64",
        "snapshot_digest",
    }
    if (
        set(snapshot) != snapshot_required
        or snapshot.get("schema_version") != PRIOR_SNAPSHOT_SCHEMA
        or snapshot.get("source_artifact") != CANONICAL_MAP_NAME
        or type(snapshot.get("source_present")) is not bool
        or type(snapshot.get("source_size_bytes")) is not int
        or not isinstance(snapshot.get("source_content_b64"), str)
    ):
        raise ExplorationAuthorityError(
            "exploration prior snapshot schema/key mismatch"
        )
    snapshot_unsigned = {
        key: value for key, value in snapshot.items()
        if key != "snapshot_digest"
    }
    if snapshot.get("snapshot_digest") != _digest(snapshot_unsigned):
        raise ExplorationAuthorityError(
            "exploration prior snapshot digest mismatch"
        )
    try:
        source_raw = base64.b64decode(
            snapshot["source_content_b64"], validate=True
        )
    except (ValueError, TypeError) as exc:
        raise ExplorationAuthorityError(
            "exploration prior source bytes are malformed"
        ) from exc
    present = snapshot["source_present"]
    if int(snapshot["source_size_bytes"]) != len(source_raw) or (
        present and (
            _HEX_RE.fullmatch(str(snapshot["source_sha256"])) is None
            or snapshot["source_sha256"] != _sha(source_raw)
        )
    ) or (not present and (source_raw or snapshot["source_sha256"] != "")):
        raise ExplorationAuthorityError(
            "exploration prior source byte binding is invalid"
        )
    records = (
        _canonical_records(_json_payload(
            source_raw, "snapshotted canonical identity map"
        )) if present else ()
    )
    aliases, ambiguous = _canonical_alias_projection(records)
    alias_required = {
        "schema_version", "snapshot_artifact", "snapshot_sha256",
        "snapshot_digest", "aliases", "ambiguous_short_aliases",
        "alias_receipt_sha256",
    }
    if (
        set(alias) != alias_required
        or alias.get("schema_version") != PRIOR_ALIAS_SCHEMA
        or alias.get("snapshot_artifact") != PRIOR_SNAPSHOT_NAME
        or alias.get("snapshot_sha256") != _sha(snapshot_bytes)
        or alias.get("snapshot_digest") != snapshot["snapshot_digest"]
        or alias.get("aliases") != dict(sorted(aliases.items()))
        or alias.get("ambiguous_short_aliases") != {
            key: list(values) for key, values in sorted(ambiguous.items())
        }
    ):
        raise ExplorationAuthorityError(
            "exploration prior alias semantic parity mismatch"
        )
    alias_unsigned = {
        key: value for key, value in alias.items()
        if key != "alias_receipt_sha256"
    }
    if alias.get("alias_receipt_sha256") != _digest(alias_unsigned):
        raise ExplorationAuthorityError(
            "exploration prior alias digest mismatch"
        )
    return ImmutablePriorBundle(
        snapshot_payload=dict(snapshot),
        alias_payload=dict(alias),
        snapshot_bytes=snapshot_bytes,
        alias_bytes=alias_bytes,
        aliases=dict(aliases),
        ambiguous_aliases=dict(ambiguous),
    )


def load_immutable_prior_bundle(root: str | Path) -> ImmutablePriorBundle:
    base = Path(root)
    try:
        snapshot_raw = read_bounded_regular_bytes(
            base / PRIOR_SNAPSHOT_NAME, _MAX_BYTES
        )
        alias_raw = read_bounded_regular_bytes(base / PRIOR_ALIAS_NAME, _MAX_BYTES)
    except (OSError, ValueError) as exc:
        raise ExplorationAuthorityError(
            f"exploration prior bundle is unavailable: {exc}"
        ) from exc
    return load_immutable_prior_bundle_bytes(
        snapshot_bytes=snapshot_raw, alias_bytes=alias_raw
    )


@dataclass(frozen=True)
class RepairProviderOutcome:
    terminal_status: str
    provider_status: str
    return_code: int
    failure_code: str
    provider_receipt_artifact: str
    provider_receipt_bytes: bytes
    outcome_artifact: str
    outcome_bytes: bytes


@dataclass(frozen=True)
class RepairTerminalCompanion:
    payload: dict[str, Any]
    file_bytes: bytes

    @property
    def exact_outputs(self) -> tuple[str, ...]:
        return (REPAIR_TERMINAL_NAME,)

    @property
    def output_vector(self) -> dict[str, bytes]:
        return {REPAIR_TERMINAL_NAME: self.file_bytes}


def compile_repair_provider_outcome(
    *,
    terminal_status: str,
    provider_status: str,
    return_code: int,
    failure_code: str,
    outcome_artifact: str,
    outcome_bytes: bytes,
    issues: tuple[str, ...] = (),
) -> RepairProviderOutcome:
    """Compile the driver's exact observation of one bounded provider turn."""

    terminal = str(terminal_status or "").strip().upper()
    provider = str(provider_status or "").strip().upper()
    if terminal not in {"COMPLETED", "UNAVAILABLE", "FAILED"}:
        raise ExplorationAuthorityError("provider outcome terminal status is invalid")
    if type(return_code) is not int or not isinstance(outcome_bytes, bytes):
        raise ExplorationAuthorityError("provider outcome observation is malformed")
    artifact = str(outcome_artifact or "").strip()
    if not artifact or Path(artifact).name != artifact:
        raise ExplorationAuthorityError("provider outcome artifact is invalid")
    payload = {
        "schema_version": REPAIR_PROVIDER_OUTCOME_SCHEMA,
        "terminal_status": terminal,
        "provider_status": provider,
        "return_code": return_code,
        "failure_code": str(failure_code or "").strip(),
        "outcome_artifact": artifact,
        "outcome_sha256": _sha(outcome_bytes),
        "outcome_size_bytes": len(outcome_bytes),
        "issues": list(dict.fromkeys(str(item) for item in issues if str(item))),
    }
    payload["outcome_receipt_digest"] = _digest(payload)
    raw = _file_bytes(payload)
    return RepairProviderOutcome(
        terminal_status=terminal,
        provider_status=provider,
        return_code=return_code,
        failure_code=str(failure_code or "").strip(),
        provider_receipt_artifact=REPAIR_PROVIDER_OUTCOME_NAME,
        provider_receipt_bytes=raw,
        outcome_artifact=artifact,
        outcome_bytes=outcome_bytes,
    )


def _validate_plan_arm(
    plan_raw: bytes, arm_raw: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = _json_payload(plan_raw, "exploration repair plan")
    arm = _json_payload(arm_raw, "exploration repair arm")
    plan_required = {
        "schema_version", "plan_id", "attempt", "source_receipt_hash",
        "source_artifact_sha256", "obligation_ids", "items", "plan_hash",
    }
    arm_required = {
        "schema_version", "plan_id", "plan_hash", "source_receipt_hash",
        "invocation_id", "status", "phase", "backend", "model",
        "timeout_s", "return_code",
    }
    plan_unsigned = {
        key: value for key, value in plan.items() if key != "plan_hash"
    }
    if (
        set(plan) != plan_required
        or plan.get("schema_version") != REPAIR_PLAN_SCHEMA
        or not re.fullmatch(r"ECRP-[A-F0-9]{24}", str(plan.get("plan_id") or ""))
        or plan.get("attempt") != 1
        or _HEX_RE.fullmatch(str(plan.get("source_receipt_hash") or "")) is None
        or _HEX_RE.fullmatch(str(plan.get("source_artifact_sha256") or "")) is None
        or not isinstance(plan.get("obligation_ids"), list)
        or not isinstance(plan.get("items"), list)
        or not isinstance(plan.get("plan_id"), str)
        or _HEX_RE.fullmatch(str(plan.get("plan_hash") or "")) is None
        or plan.get("plan_hash") != _digest(plan_unsigned)
    ):
        raise ExplorationAuthorityError("exploration repair plan is malformed")
    if (
        set(arm) != arm_required
        or arm.get("schema_version") != REPAIR_ARM_SCHEMA
        or arm.get("status") != "ARMED"
        or arm.get("return_code") is not None
        or arm.get("phase") != "exploration_clear"
        or arm.get("plan_id") != plan["plan_id"]
        or arm.get("plan_hash") != plan["plan_hash"]
        or arm.get("source_receipt_hash") != plan.get("source_receipt_hash")
        or _INVOCATION_RE.fullmatch(str(arm.get("invocation_id") or "")) is None
    ):
        raise ExplorationAuthorityError(
            "exploration repair arm is malformed or not bound to its plan"
        )
    return plan, arm


def build_repair_terminal_companion(
    *,
    plan_bytes: bytes,
    arm_bytes: bytes,
    outcome: RepairProviderOutcome,
) -> RepairTerminalCompanion:
    """Create a terminal receipt without replacing the immutable arm."""

    if not isinstance(outcome, RepairProviderOutcome):
        raise ExplorationAuthorityError("exploration provider outcome is invalid")
    plan, arm = _validate_plan_arm(plan_bytes, arm_bytes)
    terminal = str(outcome.terminal_status or "").strip().upper()
    provider_status = str(outcome.provider_status or "").strip().upper()
    if terminal not in {"COMPLETED", "UNAVAILABLE", "FAILED"}:
        raise ExplorationAuthorityError(
            "exploration repair terminal status is invalid"
        )
    if type(outcome.return_code) is not int:
        raise ExplorationAuthorityError(
            "exploration repair return code is invalid"
        )
    if terminal == "COMPLETED" and (
        outcome.return_code != 0 or provider_status != "COMPLETED"
    ):
        raise ExplorationAuthorityError(
            "completed exploration repair lacks completed provider outcome"
        )
    artifact = str(outcome.outcome_artifact or "").strip()
    provider_artifact = str(outcome.provider_receipt_artifact or "").strip()
    if Path(artifact).name != artifact or not artifact:
        raise ExplorationAuthorityError(
            "exploration repair outcome artifact is invalid"
        )
    provider_route = Path(provider_artifact)
    if (
        not provider_artifact
        or provider_route.is_absolute()
        or any(part in {"", ".", ".."} for part in provider_route.parts)
    ):
        raise ExplorationAuthorityError(
            "exploration repair provider receipt artifact is invalid"
        )
    if (
        not isinstance(outcome.provider_receipt_bytes, bytes)
        or not outcome.provider_receipt_bytes
        or not isinstance(outcome.outcome_bytes, bytes)
        or not outcome.outcome_bytes
        or len(outcome.provider_receipt_bytes) > _MAX_BYTES
        or len(outcome.outcome_bytes) > _MAX_BYTES
    ):
        raise ExplorationAuthorityError(
            "exploration repair outcome byte denominator is invalid"
        )
    provider_receipt = _json_payload(
        outcome.provider_receipt_bytes, "exploration provider outcome"
    )
    provider_unsigned = {
        key: value for key, value in provider_receipt.items()
        if key != "outcome_receipt_digest"
    }
    if (
        provider_receipt.get("schema_version") != REPAIR_PROVIDER_OUTCOME_SCHEMA
        or provider_receipt.get("outcome_receipt_digest") != _digest(provider_unsigned)
        or provider_receipt.get("terminal_status") != terminal
        or provider_receipt.get("provider_status") != provider_status
        or provider_receipt.get("return_code") != outcome.return_code
        or provider_receipt.get("failure_code") != str(outcome.failure_code or "").strip()
        or provider_receipt.get("outcome_artifact") != artifact
        or provider_receipt.get("outcome_sha256") != _sha(outcome.outcome_bytes)
        or provider_receipt.get("outcome_size_bytes") != len(outcome.outcome_bytes)
    ):
        raise ExplorationAuthorityError(
            "exploration provider outcome receipt is not exact"
        )
    unsigned = {
        "schema_version": REPAIR_TERMINAL_SCHEMA,
        "plan_artifact": "exploration_clear_repair_plan.json",
        "plan_sha256": _sha(plan_bytes),
        "arm_artifact": "exploration_clear_repair_attempt.json",
        "arm_sha256": _sha(arm_bytes),
        "plan_id": plan["plan_id"],
        "plan_hash": plan["plan_hash"],
        "invocation_id": arm["invocation_id"],
        "terminal_status": terminal,
        "provider_status": provider_status,
        "return_code": outcome.return_code,
        "failure_code": str(outcome.failure_code or "").strip(),
        "provider_receipt_artifact": provider_artifact,
        "provider_receipt_sha256": _sha(outcome.provider_receipt_bytes),
        "provider_receipt_size_bytes": len(outcome.provider_receipt_bytes),
        "outcome_artifact": artifact,
        "outcome_sha256": _sha(outcome.outcome_bytes),
        "outcome_size_bytes": len(outcome.outcome_bytes),
    }
    payload = {**unsigned, "result_digest": _digest(unsigned)}
    return RepairTerminalCompanion(payload=payload, file_bytes=_file_bytes(payload))


def validate_repair_terminal_companion(
    companion_bytes: bytes,
    *,
    plan_bytes: bytes,
    arm_bytes: bytes,
    provider_receipt_bytes: bytes,
    outcome_bytes: bytes,
) -> RepairTerminalCompanion:
    """Replay a terminal companion from all exact immutable inputs."""

    payload = _json_payload(companion_bytes, "exploration repair result")
    plan, arm = _validate_plan_arm(plan_bytes, arm_bytes)
    required = {
        "schema_version", "plan_artifact", "plan_sha256", "arm_artifact",
        "arm_sha256", "plan_id", "plan_hash", "invocation_id",
        "terminal_status", "provider_status", "return_code", "failure_code",
        "provider_receipt_artifact",
        "provider_receipt_sha256", "provider_receipt_size_bytes",
        "outcome_artifact", "outcome_sha256", "outcome_size_bytes",
        "result_digest",
    }
    if set(payload) != required or payload.get("schema_version") != REPAIR_TERMINAL_SCHEMA:
        raise ExplorationAuthorityError(
            "exploration repair result schema/key mismatch"
        )
    exact = {
        "plan_sha256": _sha(plan_bytes),
        "arm_sha256": _sha(arm_bytes),
        "plan_id": plan["plan_id"],
        "plan_hash": plan["plan_hash"],
        "invocation_id": arm["invocation_id"],
        "provider_receipt_sha256": _sha(provider_receipt_bytes),
        "provider_receipt_size_bytes": len(provider_receipt_bytes),
        "outcome_sha256": _sha(outcome_bytes),
        "outcome_size_bytes": len(outcome_bytes),
    }
    if any(payload.get(key) != value for key, value in exact.items()):
        raise ExplorationAuthorityError(
            "exploration repair result immutable input mismatch"
        )
    provider_receipt = _json_payload(
        provider_receipt_bytes, "exploration provider outcome"
    )
    provider_unsigned = {
        key: value for key, value in provider_receipt.items()
        if key != "outcome_receipt_digest"
    }
    if (
        provider_receipt.get("schema_version") != REPAIR_PROVIDER_OUTCOME_SCHEMA
        or provider_receipt.get("outcome_receipt_digest") != _digest(provider_unsigned)
        or provider_receipt.get("terminal_status") != payload.get("terminal_status")
        or provider_receipt.get("provider_status") != payload.get("provider_status")
        or provider_receipt.get("return_code") != payload.get("return_code")
        or provider_receipt.get("failure_code") != payload.get("failure_code")
        or provider_receipt.get("outcome_artifact") != payload.get("outcome_artifact")
        or provider_receipt.get("outcome_sha256") != _sha(outcome_bytes)
        or provider_receipt.get("outcome_size_bytes") != len(outcome_bytes)
    ):
        raise ExplorationAuthorityError(
            "exploration repair provider outcome replay mismatch"
        )
    if payload.get("plan_artifact") != "exploration_clear_repair_plan.json" or payload.get(
        "arm_artifact"
    ) != "exploration_clear_repair_attempt.json":
        raise ExplorationAuthorityError(
            "exploration repair result artifact routes are invalid"
        )
    provider_route = Path(str(payload.get("provider_receipt_artifact") or ""))
    if (
        provider_route.is_absolute()
        or any(part in {"", ".", ".."} for part in provider_route.parts)
    ):
        raise ExplorationAuthorityError(
            "exploration repair provider receipt route is invalid"
        )
    terminal = str(payload.get("terminal_status") or "")
    if terminal not in {"COMPLETED", "UNAVAILABLE", "FAILED"}:
        raise ExplorationAuthorityError(
            "exploration repair result terminal status is invalid"
        )
    if terminal == "COMPLETED" and (
        payload.get("return_code") != 0
        or payload.get("provider_status") != "COMPLETED"
    ):
        raise ExplorationAuthorityError(
            "exploration repair completed result is inconsistent"
        )
    unsigned = {
        key: value for key, value in payload.items() if key != "result_digest"
    }
    if payload.get("result_digest") != _digest(unsigned):
        raise ExplorationAuthorityError(
            "exploration repair result digest mismatch"
        )
    return RepairTerminalCompanion(
        payload=dict(payload), file_bytes=companion_bytes
    )
