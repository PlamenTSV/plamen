"""Dynamic, bounded verifier work planning for P0-AK.

``QueueWorkPlan`` is the persisted queue/output-ownership authority, but its
legacy shards are tied to a finite list of top-level phases.  This module does
not replace that identity authority.  It compiles it into an unbounded number
of deterministic child work units and enforces the verifier attention budget
before a launcher is allowed to run.

The module is intentionally provider-free: it never starts a process.  Claude
and Codex receive the same semantic assignments, while a typed runtime policy
and launch specification make backend/model/timeout/tool/process authority
explicit.  Planner and execution failures are retained as exact work-unit
debt; no fallback can append overflow rows to a final worker.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping
import uuid

from queue_work_items import QueueWorkPlan


VERIFIER_WORK_ROSTER_SCHEMA_VERSION = "plamen.verifier_work_roster.v1"
VERIFIER_WORK_UNIT_SCHEMA_VERSION = "plamen.verifier_work_unit.v1"
VERIFIER_RUNTIME_POLICY_SCHEMA_VERSION = "plamen.verifier_runtime_policy.v1"
VERIFIER_TOOL_POLICY_SCHEMA_VERSION = "plamen.verifier_tool_policy.v1"
VERIFIER_LAUNCH_SPEC_SCHEMA_VERSION = "plamen.verifier_launch_spec.v1"
VERIFIER_UNIT_RECEIPT_SCHEMA_VERSION = "plamen.verifier_unit_receipt.v1"
VERIFIER_ROSTER_STATUS_SCHEMA_VERSION = "plamen.verifier_roster_status.v1"
VERIFIER_ROSTER_DEBT_SCHEMA_VERSION = "plamen.verifier_roster_debt.v1"

DEFAULT_MAX_FINDINGS_PER_VERIFIER = 4
DEFAULT_MAX_CONCURRENCY = 4
DEFAULT_MAX_PROMPT_BYTES = 262_144
_POOL_ORDER = ("critical_high", "medium", "low_info")
_PIPELINES = frozenset({"sc", "l1"})
_MODES = frozenset({"light", "core", "thorough"})
_BACKENDS = frozenset({"claude", "codex"})
_TRANSPORTS = {
    "claude": frozenset({"headless", "pty"}),
    "codex": frozenset({"exec"}),
}
_RECEIPT_STATUSES = frozenset({"COMPLETED", "DEBT"})
_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]", re.ASCII)


class VerifierRosterError(ValueError):
    """A runtime roster cannot be produced without violating its contract."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerifierRosterError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> None:
        raise VerifierRosterError(f"invalid JSON constant: {value}")

    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("prompt_bytes must be bytes")
    return hashlib.sha256(value).hexdigest()


def claude_semantic_session_id(
    *,
    work_unit_id: str,
    work_unit_resume_digest: str,
    prompt_sha256: str,
) -> str:
    """Derive the provider session identity from immutable launch authority.

    Claude stream-json exposes the session identifier in its init event.  A
    random identifier would make an otherwise identical verifier launch spec
    drift across resume, while omitting it would leave the expected init event
    under-specified.  This UUID is therefore a projection of the already-bound
    work-unit, resume, and prompt identities; it is not a resumable provider
    session because every launch also carries ``--no-session-persistence``.
    """

    unit_id = _safe_id(work_unit_id, "work_unit_id")
    resume = _sha256(
        work_unit_resume_digest, "work_unit_resume_digest"
    )
    prompt = _sha256(prompt_sha256, "prompt_sha256")
    name = _canonical_json(
        {
            "schema": "plamen.claude_semantic_session.v1",
            "work_unit_id": unit_id,
            "work_unit_resume_digest": resume,
            "prompt_sha256": prompt,
        }
    )
    return str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        detail: list[str] = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("extra=" + ",".join(extra))
        raise VerifierRosterError(f"{label} fields differ: {'; '.join(detail)}")


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise VerifierRosterError(f"{field} must be non-empty text")
    return value


def _safe_id(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _SAFE_ID_RE.fullmatch(text) or text in {".", ".."}:
        raise VerifierRosterError(f"{field} is not a safe identity")
    return text


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _HEX_RE.fullmatch(text):
        raise VerifierRosterError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise VerifierRosterError(f"{field} must be a positive integer")
    return value


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VerifierRosterError(f"{field} must be a non-negative integer")
    return value


def _string_tuple(values: Iterable[Any], field: str) -> tuple[str, ...]:
    result = tuple(_text(value, field) for value in values)
    if len(set(result)) != len(result):
        raise VerifierRosterError(f"{field} contains duplicates")
    return result


def _text_sequence(values: Iterable[Any], field: str) -> tuple[str, ...]:
    """Validate ordered text where repeated values are semantically legal."""

    return tuple(_text(value, field) for value in values)


def _id_tuple(values: Iterable[Any], field: str) -> tuple[str, ...]:
    result = tuple(_safe_id(value, field) for value in values)
    if len(set(result)) != len(result):
        raise VerifierRosterError(f"{field} contains duplicate identities")
    return result


def _digest_tuple(values: Iterable[Any], field: str) -> tuple[str, ...]:
    return tuple(_sha256(value, field) for value in values)


def _absolute_path_text(value: Any) -> str:
    text = _text(value, "source_root")
    if not (text.startswith("/") or _WINDOWS_ABSOLUTE_RE.match(text)):
        raise VerifierRosterError(
            "source_root must be an absolute POSIX or drive-qualified Windows path"
        )
    if "\x00" in text:
        raise VerifierRosterError("source_root cannot contain NUL")
    return text


@dataclass(frozen=True, slots=True)
class VerifierToolPolicy:
    """Closed leaf-worker tool policy, independent of CLI spelling."""

    allowed_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]
    network_access: str = "DENY"
    mcp_access: str = "DENY"

    def __post_init__(self) -> None:
        allowed = tuple(sorted(_string_tuple(self.allowed_tools, "allowed_tools")))
        denied = tuple(sorted(_string_tuple(self.denied_tools, "denied_tools")))
        if set(allowed) & set(denied):
            raise VerifierRosterError("allowed_tools and denied_tools overlap")
        if not {"Task", "Agent"}.issubset(denied):
            raise VerifierRosterError("leaf verifier policy must deny Task and Agent")
        if self.network_access != "DENY":
            raise VerifierRosterError("verifier network_access must be DENY")
        if self.mcp_access != "DENY":
            raise VerifierRosterError("verifier mcp_access must be DENY")
        object.__setattr__(self, "allowed_tools", allowed)
        object.__setattr__(self, "denied_tools", denied)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_TOOL_POLICY_SCHEMA_VERSION,
            "allowed_tools": list(self.allowed_tools),
            "denied_tools": list(self.denied_tools),
            "network_access": self.network_access,
            "mcp_access": self.mcp_access,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierToolPolicy":
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "allowed_tools",
                    "denied_tools",
                    "network_access",
                    "mcp_access",
                }
            ),
            "verifier tool policy",
        )
        if value["schema_version"] != VERIFIER_TOOL_POLICY_SCHEMA_VERSION:
            raise VerifierRosterError("unsupported verifier tool policy schema")
        if not isinstance(value["allowed_tools"], list) or not isinstance(
            value["denied_tools"], list
        ):
            raise TypeError("tool lists must be JSON arrays")
        return cls(
            allowed_tools=tuple(value["allowed_tools"]),
            denied_tools=tuple(value["denied_tools"]),
            network_access=_text(value["network_access"], "network_access"),
            mcp_access=_text(value["mcp_access"], "mcp_access"),
        )


@dataclass(frozen=True, slots=True)
class VerifierRuntimePolicy:
    """Backend launch authority shared by every child in one roster."""

    backend: str
    model: str
    transport: str
    timeout_seconds: int
    max_concurrency: int
    max_prompt_bytes: int
    source_root: str
    tool_policy: VerifierToolPolicy
    foreground_only: bool = True
    background_children_allowed: bool = False
    child_join_policy: str = "REQUIRE_JOIN_BEFORE_RECEIPT"
    process_group_policy: str = "ISOLATED_PROCESS_GROUP"
    orphan_policy: str = "TERMINATE_TREE_AND_RETAIN_DEBT"

    def __post_init__(self) -> None:
        if self.backend not in _BACKENDS:
            raise VerifierRosterError("backend must be claude or codex")
        _text(self.model, "model")
        if self.transport not in _TRANSPORTS[self.backend]:
            raise VerifierRosterError(
                f"transport {self.transport!r} is invalid for {self.backend}"
            )
        _positive_int(self.timeout_seconds, "timeout_seconds")
        _positive_int(self.max_concurrency, "max_concurrency")
        _positive_int(self.max_prompt_bytes, "max_prompt_bytes")
        _absolute_path_text(self.source_root)
        if not isinstance(self.tool_policy, VerifierToolPolicy):
            raise TypeError("tool_policy must be VerifierToolPolicy")
        if self.foreground_only is not True:
            raise VerifierRosterError("verifier launches must be foreground-only")
        if self.background_children_allowed is not False:
            raise VerifierRosterError("background verifier children are forbidden")
        if self.child_join_policy != "REQUIRE_JOIN_BEFORE_RECEIPT":
            raise VerifierRosterError("all verifier children must join before receipt")
        if self.process_group_policy != "ISOLATED_PROCESS_GROUP":
            raise VerifierRosterError("verifier must run in an isolated process group")
        if self.orphan_policy != "TERMINATE_TREE_AND_RETAIN_DEBT":
            raise VerifierRosterError("verifier orphan policy must terminate and retain debt")

    @property
    def digest(self) -> str:
        return _digest(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_RUNTIME_POLICY_SCHEMA_VERSION,
            "backend": self.backend,
            "model": self.model,
            "transport": self.transport,
            "timeout_seconds": self.timeout_seconds,
            "max_concurrency": self.max_concurrency,
            "max_prompt_bytes": self.max_prompt_bytes,
            "source_root": self.source_root,
            "tool_policy": self.tool_policy.to_dict(),
            "foreground_only": self.foreground_only,
            "background_children_allowed": self.background_children_allowed,
            "child_join_policy": self.child_join_policy,
            "process_group_policy": self.process_group_policy,
            "orphan_policy": self.orphan_policy,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierRuntimePolicy":
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "backend",
                    "model",
                    "transport",
                    "timeout_seconds",
                    "max_concurrency",
                    "max_prompt_bytes",
                    "source_root",
                    "tool_policy",
                    "foreground_only",
                    "background_children_allowed",
                    "child_join_policy",
                    "process_group_policy",
                    "orphan_policy",
                }
            ),
            "verifier runtime policy",
        )
        if value["schema_version"] != VERIFIER_RUNTIME_POLICY_SCHEMA_VERSION:
            raise VerifierRosterError("unsupported verifier runtime policy schema")
        if not isinstance(value["foreground_only"], bool) or not isinstance(
            value["background_children_allowed"], bool
        ):
            raise TypeError("runtime process flags must be booleans")
        return cls(
            backend=_text(value["backend"], "backend"),
            model=_text(value["model"], "model"),
            transport=_text(value["transport"], "transport"),
            timeout_seconds=_positive_int(value["timeout_seconds"], "timeout_seconds"),
            max_concurrency=_positive_int(value["max_concurrency"], "max_concurrency"),
            max_prompt_bytes=_positive_int(
                value["max_prompt_bytes"], "max_prompt_bytes"
            ),
            source_root=_absolute_path_text(value["source_root"]),
            tool_policy=VerifierToolPolicy.from_dict(value["tool_policy"]),
            foreground_only=value["foreground_only"],
            background_children_allowed=value["background_children_allowed"],
            child_join_policy=_text(value["child_join_policy"], "child_join_policy"),
            process_group_policy=_text(
                value["process_group_policy"], "process_group_policy"
            ),
            orphan_policy=_text(value["orphan_policy"], "orphan_policy"),
        )


def build_verifier_runtime_policy(
    *,
    backend: str,
    model: str,
    timeout_seconds: int,
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
    max_prompt_bytes: int = DEFAULT_MAX_PROMPT_BYTES,
    source_root: str,
    transport: str | None = None,
    allowed_tools: Iterable[str] = ("Read", "Write", "Edit", "Bash", "Grep", "Glob"),
    denied_tools: Iterable[str] = (
        "Task",
        "Agent",
        "WebFetch",
        "WebSearch",
        "mcp__*",
    ),
) -> VerifierRuntimePolicy:
    """Build the closed runtime policy used by roster and launch receipts."""

    normalized_backend = str(backend).strip().lower()
    resolved_transport = transport or (
        "headless" if normalized_backend == "claude" else "exec"
    )
    return VerifierRuntimePolicy(
        backend=normalized_backend,
        model=str(model),
        transport=str(resolved_transport).strip().lower(),
        timeout_seconds=timeout_seconds,
        max_concurrency=max_concurrency,
        max_prompt_bytes=max_prompt_bytes,
        source_root=str(source_root),
        tool_policy=VerifierToolPolicy(
            allowed_tools=tuple(allowed_tools),
            denied_tools=tuple(denied_tools),
        ),
    )


@dataclass(frozen=True, slots=True)
class VerifierWorkUnit:
    """One bounded verifier child transaction."""

    work_unit_id: str
    tier_pool: str
    ordinal: int
    ordered_work_item_ids: tuple[str, ...]
    queue_record_digests: tuple[str, ...]
    source_shard_ids: tuple[str, ...]
    expected_output_files: tuple[str, ...]
    expected_output_identities: tuple[str, ...]
    row_set_digest: str
    output_ownership_digest: str
    complexity_weight: int
    max_findings: int
    max_complexity_weight: int
    parent_queue_work_plan_digest: str
    method_registry_digest: str
    context_packet_digest: str
    runtime_policy_digest: str

    def __post_init__(self) -> None:
        _safe_id(self.work_unit_id, "work_unit_id")
        if self.tier_pool not in _POOL_ORDER:
            raise VerifierRosterError("unknown verifier tier_pool")
        _positive_int(self.ordinal, "ordinal")
        ids = _id_tuple(self.ordered_work_item_ids, "ordered_work_item_ids")
        if not ids:
            raise VerifierRosterError("work unit cannot be empty")
        digests = _digest_tuple(self.queue_record_digests, "queue_record_digests")
        sources = _id_tuple(self.source_shard_ids, "source_shard_ids")
        files = _string_tuple(self.expected_output_files, "expected_output_files")
        identities = _string_tuple(
            self.expected_output_identities, "expected_output_identities"
        )
        lengths = {len(ids), len(digests), len(files), len(identities)}
        if len(lengths) != 1:
            raise VerifierRosterError("work unit identity vectors differ in length")
        max_findings = _positive_int(self.max_findings, "max_findings")
        max_weight = _positive_int(
            self.max_complexity_weight, "max_complexity_weight"
        )
        if len(ids) > max_findings:
            raise VerifierRosterError("work unit exceeds max_findings")
        weight = _positive_int(self.complexity_weight, "complexity_weight")
        if weight > max_weight:
            raise VerifierRosterError("work unit exceeds max_complexity_weight")
        for field in (
            "row_set_digest",
            "output_ownership_digest",
            "parent_queue_work_plan_digest",
            "method_registry_digest",
            "context_packet_digest",
            "runtime_policy_digest",
        ):
            _sha256(getattr(self, field), field)
        expected_row_digest = _digest(
            [
                {
                    "work_item_id": work_id,
                    "queue_record_digest": record_digest,
                    "expected_output_file": output_file,
                    "expected_output_identity": output_identity,
                }
                for work_id, record_digest, output_file, output_identity in zip(
                    ids, digests, files, identities, strict=True
                )
            ]
        )
        if self.row_set_digest != expected_row_digest:
            raise VerifierRosterError("work unit row_set_digest mismatch")
        expected_owner_digest = _digest(
            [
                {
                    "work_item_id": work_id,
                    "expected_output_file": output_file,
                    "expected_output_identity": output_identity,
                }
                for work_id, output_file, output_identity in zip(
                    ids, files, identities, strict=True
                )
            ]
        )
        if self.output_ownership_digest != expected_owner_digest:
            raise VerifierRosterError("work unit output_ownership_digest mismatch")
        object.__setattr__(self, "ordered_work_item_ids", ids)
        object.__setattr__(self, "queue_record_digests", digests)
        object.__setattr__(self, "source_shard_ids", sources)
        object.__setattr__(self, "expected_output_files", files)
        object.__setattr__(self, "expected_output_identities", identities)

    def _assignment_dict(self) -> dict[str, Any]:
        return {
            "work_unit_id": self.work_unit_id,
            "tier_pool": self.tier_pool,
            "ordinal": self.ordinal,
            "ordered_work_item_ids": list(self.ordered_work_item_ids),
            "queue_record_digests": list(self.queue_record_digests),
            "source_shard_ids": list(self.source_shard_ids),
            "expected_output_files": list(self.expected_output_files),
            "expected_output_identities": list(self.expected_output_identities),
            "row_set_digest": self.row_set_digest,
            "output_ownership_digest": self.output_ownership_digest,
            "complexity_weight": self.complexity_weight,
            "max_findings": self.max_findings,
            "max_complexity_weight": self.max_complexity_weight,
        }

    @property
    def assignment_digest(self) -> str:
        return _digest(self._assignment_dict())

    @property
    def resume_digest(self) -> str:
        # Deliberately do not include the whole parent plan digest here.  The
        # roster binds and validates the current parent globally, while a
        # child's resumability is local to its exact queue rows.  Otherwise a
        # late appended candidate would invalidate every already completed
        # sibling even though none of its row/method/context/runtime inputs
        # changed.  ``parent_queue_work_plan_digest`` remains immutable
        # provenance in the unit and roster records.
        return _digest(
            {
                "assignment_digest": self.assignment_digest,
                "method_registry_digest": self.method_registry_digest,
                "context_packet_digest": self.context_packet_digest,
                "runtime_policy_digest": self.runtime_policy_digest,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_WORK_UNIT_SCHEMA_VERSION,
            **self._assignment_dict(),
            "parent_queue_work_plan_digest": self.parent_queue_work_plan_digest,
            "method_registry_digest": self.method_registry_digest,
            "context_packet_digest": self.context_packet_digest,
            "runtime_policy_digest": self.runtime_policy_digest,
            "assignment_digest": self.assignment_digest,
            "resume_digest": self.resume_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierWorkUnit":
        keys = frozenset(
            {
                "schema_version",
                "work_unit_id",
                "tier_pool",
                "ordinal",
                "ordered_work_item_ids",
                "queue_record_digests",
                "source_shard_ids",
                "expected_output_files",
                "expected_output_identities",
                "row_set_digest",
                "output_ownership_digest",
                "complexity_weight",
                "max_findings",
                "max_complexity_weight",
                "parent_queue_work_plan_digest",
                "method_registry_digest",
                "context_packet_digest",
                "runtime_policy_digest",
                "assignment_digest",
                "resume_digest",
            }
        )
        _exact_keys(value, keys, "verifier work unit")
        if value["schema_version"] != VERIFIER_WORK_UNIT_SCHEMA_VERSION:
            raise VerifierRosterError("unsupported verifier work unit schema")
        for field in (
            "ordered_work_item_ids",
            "queue_record_digests",
            "source_shard_ids",
            "expected_output_files",
            "expected_output_identities",
        ):
            if not isinstance(value[field], list):
                raise TypeError(f"{field} must be a JSON array")
        unit = cls(
            work_unit_id=_safe_id(value["work_unit_id"], "work_unit_id"),
            tier_pool=_text(value["tier_pool"], "tier_pool"),
            ordinal=_positive_int(value["ordinal"], "ordinal"),
            ordered_work_item_ids=tuple(value["ordered_work_item_ids"]),
            queue_record_digests=tuple(value["queue_record_digests"]),
            source_shard_ids=tuple(value["source_shard_ids"]),
            expected_output_files=tuple(value["expected_output_files"]),
            expected_output_identities=tuple(value["expected_output_identities"]),
            row_set_digest=_sha256(value["row_set_digest"], "row_set_digest"),
            output_ownership_digest=_sha256(
                value["output_ownership_digest"], "output_ownership_digest"
            ),
            complexity_weight=_positive_int(
                value["complexity_weight"], "complexity_weight"
            ),
            max_findings=_positive_int(value["max_findings"], "max_findings"),
            max_complexity_weight=_positive_int(
                value["max_complexity_weight"], "max_complexity_weight"
            ),
            parent_queue_work_plan_digest=_sha256(
                value["parent_queue_work_plan_digest"],
                "parent_queue_work_plan_digest",
            ),
            method_registry_digest=_sha256(
                value["method_registry_digest"], "method_registry_digest"
            ),
            context_packet_digest=_sha256(
                value["context_packet_digest"], "context_packet_digest"
            ),
            runtime_policy_digest=_sha256(
                value["runtime_policy_digest"], "runtime_policy_digest"
            ),
        )
        if value["assignment_digest"] != unit.assignment_digest:
            raise VerifierRosterError("work unit assignment_digest mismatch")
        if value["resume_digest"] != unit.resume_digest:
            raise VerifierRosterError("work unit resume_digest mismatch")
        return unit


@dataclass(frozen=True, slots=True)
class VerifierWorkRoster:
    """Complete backend projection of one bounded semantic assignment."""

    pipeline: str
    ecosystem: str
    mode: str
    parent_queue_work_plan_digest: str
    ordered_work_item_ids: tuple[str, ...]
    max_findings_per_verifier: int
    max_complexity_weight: int
    complexity_weights_digest: str
    method_registry_digest: str
    context_packet_digest: str
    runtime_policy: VerifierRuntimePolicy
    work_units: tuple[VerifierWorkUnit, ...]

    def __post_init__(self) -> None:
        if self.pipeline not in _PIPELINES:
            raise VerifierRosterError("pipeline must be sc or l1")
        _safe_id(self.ecosystem, "ecosystem")
        if self.mode not in _MODES:
            raise VerifierRosterError("mode must be light, core, or thorough")
        _sha256(self.parent_queue_work_plan_digest, "parent_queue_work_plan_digest")
        ids = _id_tuple(self.ordered_work_item_ids, "ordered_work_item_ids")
        max_findings = _positive_int(
            self.max_findings_per_verifier, "max_findings_per_verifier"
        )
        max_weight = _positive_int(
            self.max_complexity_weight, "max_complexity_weight"
        )
        for field in (
            "complexity_weights_digest",
            "method_registry_digest",
            "context_packet_digest",
        ):
            _sha256(getattr(self, field), field)
        if not isinstance(self.runtime_policy, VerifierRuntimePolicy):
            raise TypeError("runtime_policy must be VerifierRuntimePolicy")
        units = tuple(self.work_units)
        if not all(isinstance(unit, VerifierWorkUnit) for unit in units):
            raise TypeError("work_units must contain VerifierWorkUnit records")
        unit_ids = [unit.work_unit_id for unit in units]
        if len(set(unit_ids)) != len(unit_ids):
            raise VerifierRosterError("work roster contains duplicate work_unit_id")
        assigned = [
            work_id for unit in units for work_id in unit.ordered_work_item_ids
        ]
        if Counter(assigned) != Counter(ids):
            raise VerifierRosterError("work roster is not an exact disjoint partition")
        # Tier pools are intentionally emitted in a fixed order for stable
        # dispatch. Preserve the authoritative queue order *within* each pool
        # without requiring differently tiered queue rows to be contiguous.
        for pool in _POOL_ORDER:
            pool_assigned = tuple(
                work_id
                for unit in units
                if unit.tier_pool == pool
                for work_id in unit.ordered_work_item_ids
            )
            pool_members = set(pool_assigned)
            expected_pool_order = tuple(
                work_id for work_id in ids if work_id in pool_members
            )
            if pool_assigned != expected_pool_order:
                raise VerifierRosterError(
                    f"work roster changed queue order within {pool}"
                )
        outputs = [name.casefold() for unit in units for name in unit.expected_output_files]
        if len(set(outputs)) != len(outputs):
            raise VerifierRosterError("work roster output ownership overlaps")
        canonical_order = sorted(
            units,
            key=lambda unit: (_POOL_ORDER.index(unit.tier_pool), unit.ordinal),
        )
        if list(units) != canonical_order:
            raise VerifierRosterError("work units are not in canonical tier/ordinal order")
        for unit in units:
            if len(unit.ordered_work_item_ids) > max_findings:
                raise VerifierRosterError("work unit exceeds roster row capacity")
            if unit.complexity_weight > max_weight:
                raise VerifierRosterError("work unit exceeds roster weight capacity")
            if unit.parent_queue_work_plan_digest != self.parent_queue_work_plan_digest:
                raise VerifierRosterError("work unit queue-plan binding mismatch")
            if unit.method_registry_digest != self.method_registry_digest:
                raise VerifierRosterError("work unit method binding mismatch")
            if unit.context_packet_digest != self.context_packet_digest:
                raise VerifierRosterError("work unit context binding mismatch")
            if unit.runtime_policy_digest != self.runtime_policy.digest:
                raise VerifierRosterError("work unit runtime-policy binding mismatch")
        object.__setattr__(self, "ordered_work_item_ids", ids)
        object.__setattr__(self, "work_units", units)

    def work_unit(self, work_unit_id: str) -> VerifierWorkUnit:
        for unit in self.work_units:
            if unit.work_unit_id == work_unit_id:
                return unit
        raise VerifierRosterError(f"unknown verifier work unit: {work_unit_id}")

    def _assignment_dict(self) -> dict[str, Any]:
        return {
            "pipeline": self.pipeline,
            "ecosystem": self.ecosystem,
            "mode": self.mode,
            "parent_queue_work_plan_digest": self.parent_queue_work_plan_digest,
            "ordered_work_item_ids": list(self.ordered_work_item_ids),
            "max_findings_per_verifier": self.max_findings_per_verifier,
            "max_complexity_weight": self.max_complexity_weight,
            "complexity_weights_digest": self.complexity_weights_digest,
            "work_units": [unit._assignment_dict() for unit in self.work_units],
        }

    @property
    def assignment_digest(self) -> str:
        return _digest(self._assignment_dict())

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_WORK_ROSTER_SCHEMA_VERSION,
            **self._assignment_dict(),
            "method_registry_digest": self.method_registry_digest,
            "context_packet_digest": self.context_packet_digest,
            "runtime_policy": self.runtime_policy.to_dict(),
            "runtime_policy_digest": self.runtime_policy.digest,
            "assignment_digest": self.assignment_digest,
            "work_units": [unit.to_dict() for unit in self.work_units],
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "roster_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierWorkRoster":
        keys = frozenset(
            {
                "schema_version",
                "pipeline",
                "ecosystem",
                "mode",
                "parent_queue_work_plan_digest",
                "ordered_work_item_ids",
                "max_findings_per_verifier",
                "max_complexity_weight",
                "complexity_weights_digest",
                "method_registry_digest",
                "context_packet_digest",
                "runtime_policy",
                "runtime_policy_digest",
                "assignment_digest",
                "work_units",
                "roster_digest",
            }
        )
        _exact_keys(value, keys, "verifier work roster")
        if value["schema_version"] != VERIFIER_WORK_ROSTER_SCHEMA_VERSION:
            raise VerifierRosterError("unsupported verifier work roster schema")
        if not isinstance(value["ordered_work_item_ids"], list) or not isinstance(
            value["work_units"], list
        ):
            raise TypeError("roster IDs and units must be JSON arrays")
        policy = VerifierRuntimePolicy.from_dict(value["runtime_policy"])
        if value["runtime_policy_digest"] != policy.digest:
            raise VerifierRosterError("runtime_policy_digest mismatch")
        roster = cls(
            pipeline=_text(value["pipeline"], "pipeline"),
            ecosystem=_safe_id(value["ecosystem"], "ecosystem"),
            mode=_text(value["mode"], "mode"),
            parent_queue_work_plan_digest=_sha256(
                value["parent_queue_work_plan_digest"],
                "parent_queue_work_plan_digest",
            ),
            ordered_work_item_ids=tuple(value["ordered_work_item_ids"]),
            max_findings_per_verifier=_positive_int(
                value["max_findings_per_verifier"],
                "max_findings_per_verifier",
            ),
            max_complexity_weight=_positive_int(
                value["max_complexity_weight"], "max_complexity_weight"
            ),
            complexity_weights_digest=_sha256(
                value["complexity_weights_digest"], "complexity_weights_digest"
            ),
            method_registry_digest=_sha256(
                value["method_registry_digest"], "method_registry_digest"
            ),
            context_packet_digest=_sha256(
                value["context_packet_digest"], "context_packet_digest"
            ),
            runtime_policy=policy,
            work_units=tuple(
                VerifierWorkUnit.from_dict(unit) for unit in value["work_units"]
            ),
        )
        if value["assignment_digest"] != roster.assignment_digest:
            raise VerifierRosterError("roster assignment_digest mismatch")
        if value["roster_digest"] != roster.digest:
            raise VerifierRosterError("roster_digest mismatch")
        return roster

    @classmethod
    def from_json(cls, text: str) -> "VerifierWorkRoster":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("verifier roster JSON must be an object")
        return cls.from_dict(value)


def _tier_pool(shard_id: str) -> str:
    normalized = shard_id.lower()
    if normalized.startswith("sc_"):
        normalized = normalized[3:]
    if normalized == "verify_crithigh" or normalized.startswith("verify_high_"):
        return "critical_high"
    if normalized.startswith("verify_medium_"):
        return "medium"
    if normalized.startswith("verify_low_"):
        return "low_info"
    raise VerifierRosterError(f"unrecognized verifier tier shard: {shard_id}")


def _normalized_weights(
    work_ids: tuple[str, ...],
    weights: Mapping[str, int] | None,
    max_complexity_weight: int,
) -> dict[str, int]:
    supplied = dict(weights or {})
    extra = sorted(set(supplied) - set(work_ids))
    if extra:
        raise VerifierRosterError(
            "complexity weights contain unknown work items: " + ", ".join(extra)
        )
    result: dict[str, int] = {}
    for work_id in work_ids:
        weight = supplied.get(work_id, 1)
        _positive_int(weight, f"complexity weight for {work_id}")
        if weight > max_complexity_weight:
            raise VerifierRosterError(
                f"complexity weight for {work_id} exceeds per-worker limit"
            )
        result[work_id] = weight
    return result


def build_verifier_work_roster(
    queue_plan: QueueWorkPlan,
    *,
    pipeline: str,
    ecosystem: str,
    mode: str,
    runtime_policy: VerifierRuntimePolicy,
    method_registry_digest: str,
    context_packet_digest: str,
    max_findings_per_verifier: int = DEFAULT_MAX_FINDINGS_PER_VERIFIER,
    max_complexity_weight: int | None = None,
    complexity_weights: Mapping[str, int] | None = None,
) -> VerifierWorkRoster:
    """Compile fixed queue shards into an exact, unbounded child roster."""

    if not isinstance(queue_plan, QueueWorkPlan):
        raise TypeError("queue_plan must be QueueWorkPlan")
    if not isinstance(runtime_policy, VerifierRuntimePolicy):
        raise TypeError("runtime_policy must be VerifierRuntimePolicy")
    normalized_pipeline = str(pipeline).strip().lower()
    normalized_mode = str(mode).strip().lower()
    max_findings = _positive_int(
        max_findings_per_verifier, "max_findings_per_verifier"
    )
    weight_limit = _positive_int(
        max_complexity_weight if max_complexity_weight is not None else max_findings,
        "max_complexity_weight",
    )
    method_digest = _sha256(method_registry_digest, "method_registry_digest")
    context_digest = _sha256(context_packet_digest, "context_packet_digest")
    queue_ids = queue_plan.ordered_work_item_ids
    weights = _normalized_weights(queue_ids, complexity_weights, weight_limit)

    membership: dict[str, tuple[str, str]] = {}
    for shard in queue_plan.shards:
        pool = _tier_pool(shard.shard_id)
        for work_id in shard.ordered_work_item_ids:
            if work_id in membership:
                raise VerifierRosterError(f"duplicate queue membership for {work_id}")
            membership[work_id] = (pool, shard.shard_id)
    if set(membership) != set(queue_ids):
        raise VerifierRosterError("queue plan tier membership is incomplete")

    owners = {owner.work_item_id: owner for owner in queue_plan.output_ownership}
    pool_ids = {
        pool: tuple(work_id for work_id in queue_ids if membership[work_id][0] == pool)
        for pool in _POOL_ORDER
    }
    units: list[VerifierWorkUnit] = []
    for pool in _POOL_ORDER:
        chunks: list[tuple[str, ...]] = []
        active: list[str] = []
        active_weight = 0
        for work_id in pool_ids[pool]:
            weight = weights[work_id]
            if active and (
                len(active) >= max_findings or active_weight + weight > weight_limit
            ):
                chunks.append(tuple(active))
                active = []
                active_weight = 0
            active.append(work_id)
            active_weight += weight
        if active:
            chunks.append(tuple(active))

        for ordinal, work_ids in enumerate(chunks, start=1):
            records = [
                {
                    "work_item_id": work_id,
                    "queue_record_digest": owners[work_id].work_item_digest,
                    "expected_output_file": owners[work_id].expected_output_file,
                    "expected_output_identity": owners[work_id].expected_output_identity,
                }
                for work_id in work_ids
            ]
            owner_records = [
                {
                    "work_item_id": record["work_item_id"],
                    "expected_output_file": record["expected_output_file"],
                    "expected_output_identity": record["expected_output_identity"],
                }
                for record in records
            ]
            source_shards: list[str] = []
            for work_id in work_ids:
                source = membership[work_id][1]
                if source not in source_shards:
                    source_shards.append(source)
            units.append(
                VerifierWorkUnit(
                    work_unit_id=(
                        f"verify-{pool.replace('_', '-')}-{ordinal:04d}"
                    ),
                    tier_pool=pool,
                    ordinal=ordinal,
                    ordered_work_item_ids=work_ids,
                    queue_record_digests=tuple(
                        record["queue_record_digest"] for record in records
                    ),
                    source_shard_ids=tuple(source_shards),
                    expected_output_files=tuple(
                        record["expected_output_file"] for record in records
                    ),
                    expected_output_identities=tuple(
                        record["expected_output_identity"] for record in records
                    ),
                    row_set_digest=_digest(records),
                    output_ownership_digest=_digest(owner_records),
                    complexity_weight=sum(weights[work_id] for work_id in work_ids),
                    max_findings=max_findings,
                    max_complexity_weight=weight_limit,
                    parent_queue_work_plan_digest=queue_plan.digest,
                    method_registry_digest=method_digest,
                    context_packet_digest=context_digest,
                    runtime_policy_digest=runtime_policy.digest,
                )
            )

    roster = VerifierWorkRoster(
        pipeline=normalized_pipeline,
        ecosystem=str(ecosystem).strip().lower(),
        mode=normalized_mode,
        parent_queue_work_plan_digest=queue_plan.digest,
        ordered_work_item_ids=queue_ids,
        max_findings_per_verifier=max_findings,
        max_complexity_weight=weight_limit,
        complexity_weights_digest=_digest(
            [{"work_item_id": work_id, "weight": weights[work_id]} for work_id in queue_ids]
        ),
        method_registry_digest=method_digest,
        context_packet_digest=context_digest,
        runtime_policy=runtime_policy,
        work_units=tuple(units),
    )
    # Redundant postcondition by design: no future constructor relaxation may
    # restore the legacy "append remainder to last worker" fallback.
    if any(
        len(unit.ordered_work_item_ids) > max_findings
        or unit.complexity_weight > weight_limit
        for unit in roster.work_units
    ):
        raise VerifierRosterError("planner produced an oversized work unit")
    return roster


@dataclass(frozen=True, slots=True)
class VerifierRosterDebt:
    reason_class: str
    affected_work_item_ids: tuple[str, ...]
    parent_queue_work_plan_digest: str
    work_unit_id: str | None
    detail: str
    fallback_action: str

    def __post_init__(self) -> None:
        _safe_id(self.reason_class, "reason_class")
        object.__setattr__(
            self,
            "affected_work_item_ids",
            _id_tuple(self.affected_work_item_ids, "affected_work_item_ids"),
        )
        _sha256(self.parent_queue_work_plan_digest, "parent_queue_work_plan_digest")
        if self.work_unit_id is not None:
            _safe_id(self.work_unit_id, "work_unit_id")
        _text(self.detail, "detail")
        _safe_id(self.fallback_action, "fallback_action")

    @property
    def debt_id(self) -> str:
        return "verifier-debt-" + _digest(
            {
                "reason_class": self.reason_class,
                "affected_work_item_ids": list(self.affected_work_item_ids),
                "parent_queue_work_plan_digest": self.parent_queue_work_plan_digest,
                "work_unit_id": self.work_unit_id,
                "detail": self.detail,
                "fallback_action": self.fallback_action,
            }
        )[:24]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_ROSTER_DEBT_SCHEMA_VERSION,
            "debt_id": self.debt_id,
            "reason_class": self.reason_class,
            "affected_work_item_ids": list(self.affected_work_item_ids),
            "parent_queue_work_plan_digest": self.parent_queue_work_plan_digest,
            "work_unit_id": self.work_unit_id,
            "detail": self.detail,
            "fallback_action": self.fallback_action,
        }


@dataclass(frozen=True, slots=True)
class VerifierRosterPlanningOutcome:
    roster: VerifierWorkRoster | None
    debts: tuple[VerifierRosterDebt, ...]

    def __post_init__(self) -> None:
        if self.roster is not None and self.debts:
            raise VerifierRosterError("successful roster planning cannot carry debt")
        if self.roster is None and not self.debts:
            raise VerifierRosterError("failed roster planning must carry visible debt")


def plan_verifier_work_roster_haltless(
    queue_plan: QueueWorkPlan,
    **kwargs: Any,
) -> VerifierRosterPlanningOutcome:
    """Return exact planner debt instead of compressing or halting the run."""

    try:
        roster = build_verifier_work_roster(queue_plan, **kwargs)
    except (VerifierRosterError, TypeError, ValueError, KeyError) as exc:
        return VerifierRosterPlanningOutcome(
            roster=None,
            debts=(
                VerifierRosterDebt(
                    reason_class="PLANNER_FAILURE",
                    affected_work_item_ids=queue_plan.ordered_work_item_ids,
                    parent_queue_work_plan_digest=queue_plan.digest,
                    work_unit_id=None,
                    detail=str(exc) or type(exc).__name__,
                    fallback_action="RETAIN_EXACT_VERIFICATION_DEBT",
                ),
            ),
        )
    return VerifierRosterPlanningOutcome(roster=roster, debts=())


def write_or_validate_verifier_work_roster(
    path: Path, roster: VerifierWorkRoster
) -> VerifierWorkRoster:
    """Atomically persist the roster; exact resume never rewrites it."""

    target = Path(path)
    if not isinstance(roster, VerifierWorkRoster):
        raise TypeError("roster must be VerifierWorkRoster")
    if target.is_file():
        recorded = VerifierWorkRoster.from_json(
            target.read_text(encoding="utf-8", errors="strict")
        )
        if recorded == roster:
            return recorded
        if (
            recorded.parent_queue_work_plan_digest
            == roster.parent_queue_work_plan_digest
        ):
            raise VerifierRosterError(
                "verifier roster drift for an unchanged QueueWorkPlan"
            )
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = roster.to_json() + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(target.parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return roster


def prepare_verifier_work_roster_haltless(
    path: Path,
    queue_plan: QueueWorkPlan,
    **kwargs: Any,
) -> VerifierRosterPlanningOutcome:
    """Plan and persist without erasing corrupt/stale authority on failure."""

    planned = plan_verifier_work_roster_haltless(queue_plan, **kwargs)
    if planned.roster is None:
        return planned
    try:
        recorded = write_or_validate_verifier_work_roster(path, planned.roster)
    except (OSError, UnicodeError, json.JSONDecodeError, VerifierRosterError) as exc:
        return VerifierRosterPlanningOutcome(
            roster=None,
            debts=(
                VerifierRosterDebt(
                    reason_class="ROSTER_PERSISTENCE_FAILURE",
                    affected_work_item_ids=queue_plan.ordered_work_item_ids,
                    parent_queue_work_plan_digest=queue_plan.digest,
                    work_unit_id=None,
                    detail=str(exc) or type(exc).__name__,
                    fallback_action="RETAIN_EXACT_VERIFICATION_DEBT",
                ),
            ),
        )
    return VerifierRosterPlanningOutcome(roster=recorded, debts=())


@dataclass(frozen=True, slots=True)
class VerifierLaunchSpec:
    work_unit_id: str
    work_unit_resume_digest: str
    backend: str
    model: str
    transport: str
    argv: tuple[str, ...]
    cwd: str
    timeout_seconds: int
    prompt_sha256: str
    prompt_size_bytes: int
    expected_output_files: tuple[str, ...]
    tool_policy_digest: str
    foreground_only: bool
    background_children_allowed: bool
    child_join_policy: str
    process_group_policy: str
    orphan_policy: str

    def __post_init__(self) -> None:
        _safe_id(self.work_unit_id, "work_unit_id")
        _sha256(self.work_unit_resume_digest, "work_unit_resume_digest")
        if self.backend not in _BACKENDS:
            raise VerifierRosterError("launch backend is invalid")
        _text(self.model, "model")
        if self.transport not in _TRANSPORTS[self.backend]:
            raise VerifierRosterError("launch transport is invalid")
        argv = _text_sequence(self.argv, "argv")
        _absolute_path_text(self.cwd)
        _positive_int(self.timeout_seconds, "timeout_seconds")
        _sha256(self.prompt_sha256, "prompt_sha256")
        _nonnegative_int(self.prompt_size_bytes, "prompt_size_bytes")
        outputs = _string_tuple(self.expected_output_files, "expected_output_files")
        _sha256(self.tool_policy_digest, "tool_policy_digest")
        if self.foreground_only is not True or self.background_children_allowed is not False:
            raise VerifierRosterError("launch spec permits background execution")
        if self.child_join_policy != "REQUIRE_JOIN_BEFORE_RECEIPT":
            raise VerifierRosterError("launch spec does not require child join")
        if self.process_group_policy != "ISOLATED_PROCESS_GROUP":
            raise VerifierRosterError("launch spec lacks isolated process group")
        if self.orphan_policy != "TERMINATE_TREE_AND_RETAIN_DEBT":
            raise VerifierRosterError("launch spec lacks terminate-and-debt policy")
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "expected_output_files", outputs)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_LAUNCH_SPEC_SCHEMA_VERSION,
            "work_unit_id": self.work_unit_id,
            "work_unit_resume_digest": self.work_unit_resume_digest,
            "backend": self.backend,
            "model": self.model,
            "transport": self.transport,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "prompt_sha256": self.prompt_sha256,
            "prompt_size_bytes": self.prompt_size_bytes,
            "expected_output_files": list(self.expected_output_files),
            "tool_policy_digest": self.tool_policy_digest,
            "foreground_only": self.foreground_only,
            "background_children_allowed": self.background_children_allowed,
            "child_join_policy": self.child_join_policy,
            "process_group_policy": self.process_group_policy,
            "orphan_policy": self.orphan_policy,
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "launch_spec_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierLaunchSpec":
        keys = frozenset(
            {
                "schema_version",
                "work_unit_id",
                "work_unit_resume_digest",
                "backend",
                "model",
                "transport",
                "argv",
                "cwd",
                "timeout_seconds",
                "prompt_sha256",
                "prompt_size_bytes",
                "expected_output_files",
                "tool_policy_digest",
                "foreground_only",
                "background_children_allowed",
                "child_join_policy",
                "process_group_policy",
                "orphan_policy",
                "launch_spec_digest",
            }
        )
        _exact_keys(value, keys, "verifier launch spec")
        if value["schema_version"] != VERIFIER_LAUNCH_SPEC_SCHEMA_VERSION:
            raise VerifierRosterError("unsupported verifier launch spec schema")
        if not isinstance(value["argv"], list) or not isinstance(
            value["expected_output_files"], list
        ):
            raise TypeError("launch argv and outputs must be JSON arrays")
        for field in ("foreground_only", "background_children_allowed"):
            if not isinstance(value[field], bool):
                raise TypeError(f"{field} must be a boolean")
        spec = cls(
            work_unit_id=_safe_id(value["work_unit_id"], "work_unit_id"),
            work_unit_resume_digest=_sha256(
                value["work_unit_resume_digest"], "work_unit_resume_digest"
            ),
            backend=_text(value["backend"], "backend"),
            model=_text(value["model"], "model"),
            transport=_text(value["transport"], "transport"),
            argv=tuple(value["argv"]),
            cwd=_absolute_path_text(value["cwd"]),
            timeout_seconds=_positive_int(
                value["timeout_seconds"], "timeout_seconds"
            ),
            prompt_sha256=_sha256(value["prompt_sha256"], "prompt_sha256"),
            prompt_size_bytes=_nonnegative_int(
                value["prompt_size_bytes"], "prompt_size_bytes"
            ),
            expected_output_files=tuple(value["expected_output_files"]),
            tool_policy_digest=_sha256(
                value["tool_policy_digest"], "tool_policy_digest"
            ),
            foreground_only=value["foreground_only"],
            background_children_allowed=value["background_children_allowed"],
            child_join_policy=_text(
                value["child_join_policy"], "child_join_policy"
            ),
            process_group_policy=_text(
                value["process_group_policy"], "process_group_policy"
            ),
            orphan_policy=_text(value["orphan_policy"], "orphan_policy"),
        )
        if value["launch_spec_digest"] != spec.digest:
            raise VerifierRosterError("launch_spec_digest mismatch")
        return spec

    @classmethod
    def from_json(cls, text: str) -> "VerifierLaunchSpec":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("verifier launch spec JSON must be an object")
        return cls.from_dict(value)


def build_verifier_launch_spec(
    roster: VerifierWorkRoster,
    work_unit_id: str,
    *,
    prompt_bytes: bytes,
    claude_executable: str = "claude",
    codex_executable: str = "codex",
) -> VerifierLaunchSpec:
    """Project one roster child into a deterministic foreground launch."""

    if not isinstance(roster, VerifierWorkRoster):
        raise TypeError("roster must be VerifierWorkRoster")
    unit = roster.work_unit(work_unit_id)
    policy = roster.runtime_policy
    if len(prompt_bytes) > policy.max_prompt_bytes:
        raise VerifierRosterError(
            f"bound verifier prompt exceeds max_prompt_bytes "
            f"({len(prompt_bytes)} > {policy.max_prompt_bytes})"
        )
    prompt_sha256 = _sha256_bytes(prompt_bytes)
    if policy.backend == "claude":
        # Claude process authority is compiled only after the durable worker
        # arm.  This launch spec binds semantic identity, not executable flags;
        # retaining a handcrafted bypass vector here would create an unsafe
        # fallback authority outside worker_transaction.
        argv = [str(claude_executable)]
    else:
        argv = [
            str(codex_executable),
            "exec",
            "--model",
            policy.model,
            "--json",
            "--ephemeral",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "--ignore-user-config",
            "--ignore-rules",
            "--add-dir",
            policy.source_root,
            "-",
        ]
    return VerifierLaunchSpec(
        work_unit_id=unit.work_unit_id,
        work_unit_resume_digest=unit.resume_digest,
        backend=policy.backend,
        model=policy.model,
        transport=policy.transport,
        argv=tuple(argv),
        cwd=policy.source_root,
        timeout_seconds=policy.timeout_seconds,
        prompt_sha256=prompt_sha256,
        prompt_size_bytes=len(prompt_bytes),
        expected_output_files=unit.expected_output_files,
        tool_policy_digest=_digest(policy.tool_policy.to_dict()),
        foreground_only=policy.foreground_only,
        background_children_allowed=policy.background_children_allowed,
        child_join_policy=policy.child_join_policy,
        process_group_policy=policy.process_group_policy,
        orphan_policy=policy.orphan_policy,
    )


@dataclass(frozen=True, slots=True)
class VerifierUnitReceipt:
    work_unit_id: str
    work_unit_resume_digest: str
    status: str
    launch_spec_digest: str | None
    output_receipt_digests: tuple[str, ...]
    gate_receipt_digests: tuple[str, ...]
    reason_class: str | None

    def __post_init__(self) -> None:
        _safe_id(self.work_unit_id, "work_unit_id")
        _sha256(self.work_unit_resume_digest, "work_unit_resume_digest")
        if self.status not in _RECEIPT_STATUSES:
            raise VerifierRosterError("unit receipt status is invalid")
        outputs = _digest_tuple(
            self.output_receipt_digests, "output_receipt_digests"
        )
        gates = _digest_tuple(self.gate_receipt_digests, "gate_receipt_digests")
        if self.status == "COMPLETED":
            if self.launch_spec_digest is None:
                raise VerifierRosterError("completed receipt lacks launch_spec_digest")
            _sha256(self.launch_spec_digest, "launch_spec_digest")
            if not outputs or not gates:
                raise VerifierRosterError(
                    "completed receipt requires output and gate receipt digests"
                )
            if self.reason_class is not None:
                raise VerifierRosterError("completed receipt cannot carry reason_class")
        else:
            if self.reason_class is None:
                raise VerifierRosterError("debt receipt requires reason_class")
            _safe_id(self.reason_class, "reason_class")
        object.__setattr__(self, "output_receipt_digests", outputs)
        object.__setattr__(self, "gate_receipt_digests", gates)

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_UNIT_RECEIPT_SCHEMA_VERSION,
            "work_unit_id": self.work_unit_id,
            "work_unit_resume_digest": self.work_unit_resume_digest,
            "status": self.status,
            "launch_spec_digest": self.launch_spec_digest,
            "output_receipt_digests": list(self.output_receipt_digests),
            "gate_receipt_digests": list(self.gate_receipt_digests),
            "reason_class": self.reason_class,
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "receipt_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "VerifierUnitReceipt":
        _exact_keys(
            value,
            frozenset(
                {
                    "schema_version",
                    "work_unit_id",
                    "work_unit_resume_digest",
                    "status",
                    "launch_spec_digest",
                    "output_receipt_digests",
                    "gate_receipt_digests",
                    "reason_class",
                    "receipt_digest",
                }
            ),
            "verifier unit receipt",
        )
        if value["schema_version"] != VERIFIER_UNIT_RECEIPT_SCHEMA_VERSION:
            raise VerifierRosterError("unsupported verifier unit receipt schema")
        if not isinstance(value["output_receipt_digests"], list) or not isinstance(
            value["gate_receipt_digests"], list
        ):
            raise TypeError("verifier receipt digest vectors must be JSON arrays")
        receipt = cls(
            work_unit_id=_safe_id(value["work_unit_id"], "work_unit_id"),
            work_unit_resume_digest=_sha256(
                value["work_unit_resume_digest"], "work_unit_resume_digest"
            ),
            status=_text(value["status"], "status"),
            launch_spec_digest=(
                None
                if value["launch_spec_digest"] is None
                else _sha256(value["launch_spec_digest"], "launch_spec_digest")
            ),
            output_receipt_digests=tuple(value["output_receipt_digests"]),
            gate_receipt_digests=tuple(value["gate_receipt_digests"]),
            reason_class=(
                None
                if value["reason_class"] is None
                else _safe_id(value["reason_class"], "reason_class")
            ),
        )
        if _sha256(value["receipt_digest"], "receipt_digest") != receipt.digest:
            raise VerifierRosterError("receipt_digest mismatch")
        return receipt

    @classmethod
    def from_json(cls, text: str) -> "VerifierUnitReceipt":
        value = _strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise TypeError("verifier unit receipt JSON must be an object")
        return cls.from_dict(value)

    @classmethod
    def completed_for(
        cls,
        unit: VerifierWorkUnit,
        *,
        launch_spec_digest: str,
        output_receipt_digests: Iterable[str],
        gate_receipt_digests: Iterable[str],
    ) -> "VerifierUnitReceipt":
        outputs = tuple(output_receipt_digests)
        if len(outputs) != len(unit.expected_output_files):
            raise VerifierRosterError(
                "completed receipt must bind every expected verifier output"
            )
        return cls(
            work_unit_id=unit.work_unit_id,
            work_unit_resume_digest=unit.resume_digest,
            status="COMPLETED",
            launch_spec_digest=launch_spec_digest,
            output_receipt_digests=outputs,
            gate_receipt_digests=tuple(gate_receipt_digests),
            reason_class=None,
        )

    @classmethod
    def debt_for(
        cls, unit: VerifierWorkUnit, *, reason_class: str
    ) -> "VerifierUnitReceipt":
        return cls(
            work_unit_id=unit.work_unit_id,
            work_unit_resume_digest=unit.resume_digest,
            status="DEBT",
            launch_spec_digest=None,
            output_receipt_digests=(),
            gate_receipt_digests=(),
            reason_class=reason_class,
        )


@dataclass(frozen=True, slots=True)
class VerifierRosterStatus:
    roster_digest: str
    state: str
    completed_work_unit_ids: tuple[str, ...]
    pending_work_unit_ids: tuple[str, ...]
    debts: tuple[VerifierRosterDebt, ...]

    def __post_init__(self) -> None:
        _sha256(self.roster_digest, "roster_digest")
        if self.state not in {"CLEAN", "COMPLETED_WITH_DEBT"}:
            raise VerifierRosterError("roster status state is invalid")
        object.__setattr__(
            self,
            "completed_work_unit_ids",
            _id_tuple(self.completed_work_unit_ids, "completed_work_unit_ids"),
        )
        object.__setattr__(
            self,
            "pending_work_unit_ids",
            _id_tuple(self.pending_work_unit_ids, "pending_work_unit_ids"),
        )
        if set(self.completed_work_unit_ids) & set(self.pending_work_unit_ids):
            raise VerifierRosterError("completed and pending work units overlap")
        if self.state == "CLEAN" and (self.pending_work_unit_ids or self.debts):
            raise VerifierRosterError("CLEAN roster status carries unresolved debt")

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VERIFIER_ROSTER_STATUS_SCHEMA_VERSION,
            "roster_digest": self.roster_digest,
            "state": self.state,
            "completed_work_unit_ids": list(self.completed_work_unit_ids),
            "pending_work_unit_ids": list(self.pending_work_unit_ids),
            "debts": [debt.to_dict() for debt in self.debts],
        }

    @property
    def digest(self) -> str:
        return _digest(self._unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "status_digest": self.digest}

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())


def reconcile_verifier_work_roster(
    roster: VerifierWorkRoster,
    receipts: Iterable[VerifierUnitReceipt],
) -> VerifierRosterStatus:
    """Reconcile exact child receipts; missing/mismatched children stay debt."""

    if not isinstance(roster, VerifierWorkRoster):
        raise TypeError("roster must be VerifierWorkRoster")
    by_id: dict[str, VerifierUnitReceipt] = {}
    duplicate_ids: set[str] = set()
    for receipt in receipts:
        if not isinstance(receipt, VerifierUnitReceipt):
            raise TypeError("receipts must contain VerifierUnitReceipt records")
        if receipt.work_unit_id in by_id:
            duplicate_ids.add(receipt.work_unit_id)
        else:
            by_id[receipt.work_unit_id] = receipt
    completed: list[str] = []
    pending: list[str] = []
    debts: list[VerifierRosterDebt] = []
    for unit in roster.work_units:
        receipt = by_id.get(unit.work_unit_id)
        reason: str | None = None
        detail = ""
        if unit.work_unit_id in duplicate_ids:
            reason = "AMBIGUOUS_RECEIPTS"
            detail = "multiple receipts claim the same verifier work unit"
        elif receipt is None:
            reason = "UNSTARTED_WORK_UNIT"
            detail = "no receipt exists for the planned verifier work unit"
        elif receipt.work_unit_resume_digest != unit.resume_digest:
            reason = "STALE_RECEIPT"
            detail = "receipt resume digest does not match current unit authority"
        elif (
            receipt.status == "COMPLETED"
            and len(receipt.output_receipt_digests)
            != len(unit.expected_output_files)
        ):
            reason = "INCOMPLETE_OUTPUT_RECEIPTS"
            detail = "completion receipt does not bind every expected output"
        elif receipt.status != "COMPLETED":
            reason = receipt.reason_class or "WORKER_EXECUTION_DEBT"
            detail = "worker did not produce a completion receipt"
        if reason is None:
            completed.append(unit.work_unit_id)
            continue
        pending.append(unit.work_unit_id)
        debts.append(
            VerifierRosterDebt(
                reason_class=reason,
                affected_work_item_ids=unit.ordered_work_item_ids,
                parent_queue_work_plan_digest=roster.parent_queue_work_plan_digest,
                work_unit_id=unit.work_unit_id,
                detail=detail,
                fallback_action="RETRY_EXACT_WORK_UNIT",
            )
        )
    unknown = sorted(set(by_id) - {unit.work_unit_id for unit in roster.work_units})
    for work_unit_id in unknown:
        debts.append(
            VerifierRosterDebt(
                reason_class="UNOWNED_RECEIPT",
                affected_work_item_ids=(),
                parent_queue_work_plan_digest=roster.parent_queue_work_plan_digest,
                work_unit_id=work_unit_id,
                detail="receipt is not owned by the current verifier roster",
                fallback_action="RETAIN_EXACT_VERIFICATION_DEBT",
            )
        )
    state = "CLEAN" if not pending and not debts else "COMPLETED_WITH_DEBT"
    return VerifierRosterStatus(
        roster_digest=roster.digest,
        state=state,
        completed_work_unit_ids=tuple(completed),
        pending_work_unit_ids=tuple(pending),
        debts=tuple(debts),
    )


def compile_verifier_transaction_phase_roster(
    roster: VerifierWorkRoster,
    *,
    run_id: str,
    phase: str,
    generation: int,
    work_plan_digests: Mapping[str, str],
) -> dict[str, Any]:
    """Bind every dynamic verifier unit into one final WorkerTransaction roster.

    This is the sole bridge from the semantic verifier roster to the process
    lifecycle roster.  It refuses missing, extra, or foreign units before any
    AttemptArm can be emitted.
    """

    if not isinstance(roster, VerifierWorkRoster):
        raise TypeError("roster must be VerifierWorkRoster")
    if not isinstance(work_plan_digests, Mapping):
        raise TypeError("work_plan_digests must be a mapping")
    expected = {unit.work_unit_id for unit in roster.work_units}
    if set(work_plan_digests) != expected:
        raise VerifierRosterError(
            "work-plan digests do not equal the exact verifier roster"
        )
    normalized = {
        unit_id: _sha256(
            work_plan_digests[unit_id],
            f"work plan digest for {unit_id}",
        )
        for unit_id in sorted(expected)
    }
    if not normalized:
        raise VerifierRosterError(
            "an empty verifier roster has no worker transaction to launch"
        )
    try:
        from worker_transaction import compile_phase_work_roster

        return compile_phase_work_roster(
            run_id=run_id,
            phase=phase,
            generation=generation,
            required_work_unit_ids=tuple(sorted(expected)),
            work_plan_digests=normalized,
        )
    except (TypeError, ValueError, RuntimeError) as exc:
        raise VerifierRosterError(
            f"cannot compile verifier transaction roster: {exc}"
        ) from exc
