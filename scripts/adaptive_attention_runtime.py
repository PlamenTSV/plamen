"""Backend-neutral Adaptive Attention runtime primitives.

This module compiles exact semantic prompts, projects the deterministic ready
queue, accounts for reservations, and joins *already authenticated* worker
receipts.  It does not mint PhaseIO, WorkerTransaction, provider, closure, or
lineage authority.  The default authority resolver therefore remains the
fail-closed resolver in :mod:`adaptive_attention_controller`.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import re
from typing import Any, Callable, Iterable, Mapping, Sequence

from adaptive_attention_authority import AttentionAuthorityResolver
from adaptive_attention_controller import (
    apply_attention_receipts,
    classify_attention_stop,
)
from adaptive_attention_types import (
    AcceptedEvidenceReceipt,
    AdaptiveAttentionError,
    AttentionClosureAuthority,
    AttentionDebt,
    AttentionDenominator,
    AttentionGenesisAuthority,
    AttentionJoinProjection,
    AttentionRoster,
    AttentionScope,
    AttentionStopBindings,
    AttentionStopReceipt,
    ChannelTerminalReceipt,
    EvidenceChannel,
    RosterAmendment,
    WorkerReceipt,
    canonical_json,
    digest_json,
    effective_roster_digest,
    effective_roster_material,
)


SEMANTIC_PROMPT_SCHEMA = "plamen.attention_semantic_prompt.v1"
BACKEND_PROMPT_SCHEMA = "plamen.attention_backend_prompt.v1"
READY_QUEUE_SCHEMA = "plamen.attention_ready_queue.v1"
USAGE_RECEIPT_SCHEMA = "plamen.attention_usage_receipt.v1"
RESERVATION_LEDGER_SCHEMA = "plamen.attention_reservation_ledger.v1"
CHANNEL_EXECUTION_SCHEMA = "plamen.attention_channel_execution.v1"
EXECUTION_RESULT_SCHEMA = "plamen.attention_execution_result.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$", re.ASCII)
_ALLOWED_DISPOSITIONS = (
    "BLOCKED",
    "CANDIDATE_PROPOSED",
    "EVIDENCE_PROPOSED",
    "INCONCLUSIVE",
    "NO_EVIDENCE_WITH_TRACE",
)
_GENERIC_NEGATIVES = frozenset(
    {"SAFE", "NO ISSUE", "NOT VULNERABLE", "NO ISSUE FOUND"}
)


def _exact_keys(
    value: Mapping[str, Any], expected: Iterable[str], label: str
) -> None:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    missing = set(expected) - set(value)
    extra = set(value) - set(expected)
    if missing or extra:
        raise AdaptiveAttentionError(
            f"{label} fields differ: missing={sorted(missing)} "
            f"unexpected={sorted(extra)}"
        )


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveAttentionError(f"{field} must be non-empty text")
    return value.strip()


def _identity(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _ID_RE.fullmatch(text) or text in {".", ".."}:
        raise AdaptiveAttentionError(f"{field} is not a canonical identity")
    return text


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field).lower()
    if not _SHA256_RE.fullmatch(text):
        raise AdaptiveAttentionError(f"{field} must be a SHA-256 digest")
    return text


def _nonnegative(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AdaptiveAttentionError(
            f"{field} must be a non-negative integer"
        )
    return value


def _positive(value: Any, field: str) -> int:
    checked = _nonnegative(value, field)
    if checked == 0:
        raise AdaptiveAttentionError(f"{field} must be positive")
    return checked


def _canonical_ids(
    values: Iterable[Any], field: str
) -> tuple[str, ...]:
    result = tuple(sorted({_identity(value, field) for value in values}))
    return result


@dataclass(frozen=True, slots=True)
class NormalizedWorkerDisposition:
    disposition: str
    retained_negative_proposal: bool


def normalize_worker_disposition(value: Any) -> NormalizedWorkerDisposition:
    """Normalize only the explicit disposition field.

    Free-form prose is deliberately not scanned with a broad regular
    expression.  Exact generic-negative labels become traced negative
    proposals; they never become closure.
    """

    raw = _text(value, "worker disposition").upper()
    normalized = re.sub(r"[\s_-]+", " ", raw).strip(" .,:;!?")
    canonical = normalized.replace(" ", "_")
    if canonical in _ALLOWED_DISPOSITIONS:
        return NormalizedWorkerDisposition(canonical, False)
    if normalized in _GENERIC_NEGATIVES:
        return NormalizedWorkerDisposition(
            "NO_EVIDENCE_WITH_TRACE", True
        )
    raise AdaptiveAttentionError(
        "unsupported exact worker disposition: " + normalized
    )


@dataclass(frozen=True, slots=True)
class CompiledSemanticPrompt:
    scope_digest: str
    denominator_digest: str
    channel_semantic_id: str
    channel_id: str
    channel_row_digest: str
    obligation_ids: tuple[str, ...]
    obligation_row_digests: tuple[tuple[str, str], ...]
    evidence_slice_id: str
    evidence_slice_digest: str
    expected_output: str
    allowed_dispositions: tuple[str, ...]
    semantic_prompt: str
    semantic_prompt_digest: str
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SEMANTIC_PROMPT_SCHEMA,
            "scope_digest": self.scope_digest,
            "denominator_digest": self.denominator_digest,
            "channel_semantic_id": self.channel_semantic_id,
            "channel_id": self.channel_id,
            "channel_row_digest": self.channel_row_digest,
            "obligation_ids": list(self.obligation_ids),
            "obligation_row_digests": [
                [identity, digest]
                for identity, digest in self.obligation_row_digests
            ],
            "evidence_slice_id": self.evidence_slice_id,
            "evidence_slice_digest": self.evidence_slice_digest,
            "expected_output": self.expected_output,
            "allowed_dispositions": list(self.allowed_dispositions),
            "semantic_prompt": self.semantic_prompt,
            "semantic_prompt_digest": self.semantic_prompt_digest,
            "artifact_digest": self.artifact_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "CompiledSemanticPrompt":
        _exact_keys(value, cls._fields(), "semantic prompt")
        if value["schema_version"] != SEMANTIC_PROMPT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported semantic prompt schema"
            )
        rows = tuple(
            (_identity(item[0], "obligation_id"), _sha256(item[1], "row"))
            for item in value["obligation_row_digests"]
            if isinstance(item, list) and len(item) == 2
        )
        row = cls(
            scope_digest=_sha256(value["scope_digest"], "scope_digest"),
            denominator_digest=_sha256(
                value["denominator_digest"], "denominator_digest"
            ),
            channel_semantic_id=_identity(
                value["channel_semantic_id"], "channel_semantic_id"
            ),
            channel_id=_identity(value["channel_id"], "channel_id"),
            channel_row_digest=_sha256(
                value["channel_row_digest"], "channel_row_digest"
            ),
            obligation_ids=_canonical_ids(
                value["obligation_ids"], "obligation_id"
            ),
            obligation_row_digests=rows,
            evidence_slice_id=_identity(
                value["evidence_slice_id"], "evidence_slice_id"
            ),
            evidence_slice_digest=_sha256(
                value["evidence_slice_digest"], "evidence_slice_digest"
            ),
            expected_output=_identity(
                value["expected_output"], "expected_output"
            ),
            allowed_dispositions=tuple(value["allowed_dispositions"]),
            semantic_prompt=_text(
                value["semantic_prompt"], "semantic_prompt"
            ),
            semantic_prompt_digest=_sha256(
                value["semantic_prompt_digest"],
                "semantic_prompt_digest",
            ),
            artifact_digest=_sha256(
                value["artifact_digest"], "artifact_digest"
            ),
        )
        if row.obligation_ids != tuple(
            identity for identity, _digest in rows
        ):
            raise AdaptiveAttentionError(
                "semantic prompt obligation row denominator differs"
            )
        if row.allowed_dispositions != _ALLOWED_DISPOSITIONS:
            raise AdaptiveAttentionError(
                "semantic prompt disposition contract differs"
            )
        if digest_json({"semantic_prompt": row.semantic_prompt}) != (
            row.semantic_prompt_digest
        ):
            raise AdaptiveAttentionError(
                "semantic prompt bytes do not replay"
            )
        payload = row.to_dict()
        artifact_digest = payload.pop("artifact_digest")
        if digest_json(payload) != artifact_digest:
            raise AdaptiveAttentionError(
                "semantic prompt artifact does not replay"
            )
        if row.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "semantic prompt canonical form does not replay"
            )
        return row

    @staticmethod
    def _fields() -> set[str]:
        return {
            "schema_version",
            "scope_digest",
            "denominator_digest",
            "channel_semantic_id",
            "channel_id",
            "channel_row_digest",
            "obligation_ids",
            "obligation_row_digests",
            "evidence_slice_id",
            "evidence_slice_digest",
            "expected_output",
            "allowed_dispositions",
            "semantic_prompt",
            "semantic_prompt_digest",
            "artifact_digest",
        }


def compile_semantic_prompt(
    *,
    scope: AttentionScope,
    denominator: AttentionDenominator,
    channel: EvidenceChannel,
) -> CompiledSemanticPrompt:
    AttentionScope.from_dict(scope.to_dict())
    AttentionDenominator.from_dict(denominator.to_dict())
    EvidenceChannel.from_dict(channel.to_dict())
    if (
        denominator.scope_digest != scope.scope_digest
        or channel.scope_digest != scope.scope_digest
    ):
        raise AdaptiveAttentionError(
            "semantic prompt inputs are outside the exact scope"
        )
    rows_by_id = {
        row.obligation_id: row for row in denominator.obligations
    }
    if not set(channel.obligation_ids) <= set(rows_by_id):
        raise AdaptiveAttentionError(
            "semantic prompt channel is outside the denominator"
        )
    obligation_rows = tuple(
        (identity, rows_by_id[identity].row_digest)
        for identity in channel.obligation_ids
    )
    semantic_contract = {
        "schema_version": "plamen.attention_worker_contract.v1",
        "scope_digest": scope.scope_digest,
        "denominator_digest": denominator.denominator_digest,
        "channel_semantic_id": channel.channel_semantic_id,
        "obligation_rows": [
            {
                "obligation_id": identity,
                "row_digest": rows_by_id[identity].row_digest,
                "kind": rows_by_id[identity].kind,
                "subject_ids": list(rows_by_id[identity].subject_ids),
                "methodology_bindings": [
                    binding.to_dict()
                    for binding in rows_by_id[
                        identity
                    ].methodology_bindings
                ],
                "closure_policy": rows_by_id[identity].closure_policy,
            }
            for identity in channel.obligation_ids
        ],
        "evidence_slice": channel.evidence_slice.to_dict(),
        "expected_output": channel.expected_output,
        "allowed_dispositions": list(_ALLOWED_DISPOSITIONS),
        "rules": [
            "Emit exactly one row for every assigned obligation.",
            "Bind every row to evidence identities and methodology steps.",
            "A negative conclusion is a proposal requiring independent review.",
            "Do not claim closure, merge authority, or report authority.",
        ],
    }
    prompt_text = (
        "Adaptive Attention evidence channel. Follow the exact canonical "
        "contract below and write only the assigned output.\n"
        + canonical_json(semantic_contract)
    )
    semantic_digest = digest_json({"semantic_prompt": prompt_text})
    values = {
        "schema_version": SEMANTIC_PROMPT_SCHEMA,
        "scope_digest": scope.scope_digest,
        "denominator_digest": denominator.denominator_digest,
        "channel_semantic_id": channel.channel_semantic_id,
        "channel_id": channel.channel_id,
        "channel_row_digest": channel.row_digest,
        "obligation_ids": list(channel.obligation_ids),
        "obligation_row_digests": [
            [identity, digest] for identity, digest in obligation_rows
        ],
        "evidence_slice_id": channel.evidence_slice_id,
        "evidence_slice_digest": channel.evidence_slice.row_digest,
        "expected_output": channel.expected_output,
        "allowed_dispositions": list(_ALLOWED_DISPOSITIONS),
        "semantic_prompt": prompt_text,
        "semantic_prompt_digest": semantic_digest,
    }
    return CompiledSemanticPrompt(
        scope_digest=scope.scope_digest,
        denominator_digest=denominator.denominator_digest,
        channel_semantic_id=channel.channel_semantic_id,
        channel_id=channel.channel_id,
        channel_row_digest=channel.row_digest,
        obligation_ids=channel.obligation_ids,
        obligation_row_digests=obligation_rows,
        evidence_slice_id=channel.evidence_slice_id,
        evidence_slice_digest=channel.evidence_slice.row_digest,
        expected_output=channel.expected_output,
        allowed_dispositions=_ALLOWED_DISPOSITIONS,
        semantic_prompt=prompt_text,
        semantic_prompt_digest=semantic_digest,
        artifact_digest=digest_json(values),
    )


@dataclass(frozen=True, slots=True)
class BackendLaunchPrompt:
    backend_family: str
    semantic_prompt_digest: str
    adapter_instructions: str
    adapter_digest: str
    final_launch_prompt: str
    final_launch_prompt_digest: str
    artifact_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": BACKEND_PROMPT_SCHEMA,
            "backend_family": self.backend_family,
            "semantic_prompt_digest": self.semantic_prompt_digest,
            "adapter_instructions": self.adapter_instructions,
            "adapter_digest": self.adapter_digest,
            "final_launch_prompt": self.final_launch_prompt,
            "final_launch_prompt_digest": self.final_launch_prompt_digest,
            "artifact_digest": self.artifact_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "BackendLaunchPrompt":
        _exact_keys(
            value,
            {
                "schema_version",
                "backend_family",
                "semantic_prompt_digest",
                "adapter_instructions",
                "adapter_digest",
                "final_launch_prompt",
                "final_launch_prompt_digest",
                "artifact_digest",
            },
            "backend launch prompt",
        )
        if value["schema_version"] != BACKEND_PROMPT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported backend launch prompt schema"
            )
        row = cls(
            backend_family=_identity(
                value["backend_family"], "backend_family"
            ),
            semantic_prompt_digest=_sha256(
                value["semantic_prompt_digest"],
                "semantic_prompt_digest",
            ),
            adapter_instructions=_text(
                value["adapter_instructions"], "adapter_instructions"
            ),
            adapter_digest=_sha256(
                value["adapter_digest"], "adapter_digest"
            ),
            final_launch_prompt=_text(
                value["final_launch_prompt"], "final_launch_prompt"
            ),
            final_launch_prompt_digest=_sha256(
                value["final_launch_prompt_digest"],
                "final_launch_prompt_digest",
            ),
            artifact_digest=_sha256(
                value["artifact_digest"], "artifact_digest"
            ),
        )
        adapter_payload = {
            "schema_version": BACKEND_PROMPT_SCHEMA,
            "backend_family": row.backend_family,
            "adapter_instructions": row.adapter_instructions,
        }
        if digest_json(adapter_payload) != row.adapter_digest:
            raise AdaptiveAttentionError(
                "backend adapter digest does not replay"
            )
        if digest_json(
            {"final_launch_prompt": row.final_launch_prompt}
        ) != row.final_launch_prompt_digest:
            raise AdaptiveAttentionError(
                "final launch prompt digest does not replay"
            )
        payload = row.to_dict()
        artifact_digest = payload.pop("artifact_digest")
        if digest_json(payload) != artifact_digest:
            raise AdaptiveAttentionError(
                "backend launch prompt artifact does not replay"
            )
        if row.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "backend launch prompt canonical form does not replay"
            )
        return row


def compile_backend_launch_prompt(
    *,
    semantic_prompt: CompiledSemanticPrompt,
    channel: EvidenceChannel,
    backend_family: str,
    adapter_instructions: str,
) -> BackendLaunchPrompt:
    CompiledSemanticPrompt.from_dict(semantic_prompt.to_dict())
    EvidenceChannel.from_dict(channel.to_dict())
    if (
        semantic_prompt.channel_id != channel.channel_id
        or semantic_prompt.channel_row_digest != channel.row_digest
        or semantic_prompt.channel_semantic_id
        != channel.channel_semantic_id
    ):
        raise AdaptiveAttentionError(
            "backend adapter channel binding differs from semantic prompt"
        )
    backend = _identity(backend_family, "backend_family")
    if backend != channel.runtime_policy.backend_family:
        raise AdaptiveAttentionError(
            "backend adapter family differs from the frozen runtime policy"
        )
    instructions = _text(adapter_instructions, "adapter_instructions")
    adapter_payload = {
        "schema_version": BACKEND_PROMPT_SCHEMA,
        "backend_family": backend,
        "adapter_instructions": instructions,
    }
    adapter_digest = digest_json(adapter_payload)
    final = (
        semantic_prompt.semantic_prompt
        + "\n\nTransport adapter instructions:\n"
        + instructions
    )
    final_digest = digest_json({"final_launch_prompt": final})
    payload = {
        **adapter_payload,
        "semantic_prompt_digest": semantic_prompt.semantic_prompt_digest,
        "adapter_digest": adapter_digest,
        "final_launch_prompt": final,
        "final_launch_prompt_digest": final_digest,
    }
    return BackendLaunchPrompt(
        backend_family=backend,
        semantic_prompt_digest=semantic_prompt.semantic_prompt_digest,
        adapter_instructions=instructions,
        adapter_digest=adapter_digest,
        final_launch_prompt=final,
        final_launch_prompt_digest=final_digest,
        artifact_digest=digest_json(payload),
    )


@dataclass(frozen=True, slots=True)
class AttentionReadyQueue:
    semantic_roster_digest: str
    effective_roster_digest: str
    terminal_channel_ids: tuple[str, ...]
    active_channel_ids: tuple[str, ...]
    satisfied_prerequisite_ids: tuple[str, ...]
    ready_channel_ids: tuple[str, ...]
    blocked_channel_ids: tuple[str, ...]
    dispatch_channel_ids: tuple[str, ...]
    max_concurrency: int
    queue_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": READY_QUEUE_SCHEMA,
            "semantic_roster_digest": self.semantic_roster_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "terminal_channel_ids": list(self.terminal_channel_ids),
            "active_channel_ids": list(self.active_channel_ids),
            "satisfied_prerequisite_ids": list(
                self.satisfied_prerequisite_ids
            ),
            "ready_channel_ids": list(self.ready_channel_ids),
            "blocked_channel_ids": list(self.blocked_channel_ids),
            "dispatch_channel_ids": list(self.dispatch_channel_ids),
            "max_concurrency": self.max_concurrency,
            "queue_digest": self.queue_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionReadyQueue":
        _exact_keys(
            value,
            {
                "schema_version",
                "semantic_roster_digest",
                "effective_roster_digest",
                "terminal_channel_ids",
                "active_channel_ids",
                "satisfied_prerequisite_ids",
                "ready_channel_ids",
                "blocked_channel_ids",
                "dispatch_channel_ids",
                "max_concurrency",
                "queue_digest",
            },
            "attention ready queue",
        )
        if value["schema_version"] != READY_QUEUE_SCHEMA:
            raise AdaptiveAttentionError("unsupported ready queue schema")
        row = cls(
            semantic_roster_digest=_sha256(
                value["semantic_roster_digest"],
                "semantic_roster_digest",
            ),
            effective_roster_digest=_sha256(
                value["effective_roster_digest"],
                "effective_roster_digest",
            ),
            terminal_channel_ids=_canonical_ids(
                value["terminal_channel_ids"], "terminal channel"
            ),
            active_channel_ids=_canonical_ids(
                value["active_channel_ids"], "active channel"
            ),
            satisfied_prerequisite_ids=_canonical_ids(
                value["satisfied_prerequisite_ids"], "prerequisite"
            ),
            ready_channel_ids=_canonical_ids(
                value["ready_channel_ids"], "ready channel"
            ),
            blocked_channel_ids=_canonical_ids(
                value["blocked_channel_ids"], "blocked channel"
            ),
            dispatch_channel_ids=tuple(
                _identity(item, "dispatch channel")
                for item in value["dispatch_channel_ids"]
            ),
            max_concurrency=_positive(
                value["max_concurrency"], "max_concurrency"
            ),
            queue_digest=_sha256(value["queue_digest"], "queue_digest"),
        )
        payload = row.to_dict()
        supplied = payload.pop("queue_digest")
        if digest_json(payload) != supplied:
            raise AdaptiveAttentionError(
                "attention ready queue content does not replay"
            )
        if not set(row.dispatch_channel_ids) <= set(
            row.ready_channel_ids
        ):
            raise AdaptiveAttentionError(
                "dispatch window is outside the ready queue"
            )
        if row.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention ready queue canonical form does not replay"
            )
        return row


def compile_ready_queue(
    *,
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    terminal_receipts: Iterable[ChannelTerminalReceipt],
    active_channel_ids: Iterable[str],
    satisfied_prerequisite_ids: Iterable[str],
    max_concurrency: int,
) -> AttentionReadyQueue:
    AttentionRoster.from_dict(roster.to_dict())
    effective_digest = effective_roster_digest(roster, amendments)
    channels, _debt, _rows = effective_roster_material(
        roster, amendments
    )
    channels_by_id = {row.channel_id: row for row in channels}
    terminals = tuple(
        sorted(
            (
                ChannelTerminalReceipt.from_dict(row.to_dict())
                for row in terminal_receipts
            ),
            key=lambda row: row.channel_id,
        )
    )
    if len({row.channel_id for row in terminals}) != len(terminals):
        raise AdaptiveAttentionError(
            "terminal receipts contain duplicate channels"
        )
    terminal_ids = tuple(row.channel_id for row in terminals)
    if not set(terminal_ids) <= set(channels_by_id):
        raise AdaptiveAttentionError(
            "terminal receipt is outside the effective roster"
        )
    for receipt in terminals:
        if (
            receipt.channel_row_digest
            != channels_by_id[receipt.channel_id].row_digest
        ):
            raise AdaptiveAttentionError(
                "terminal receipt channel binding is stale"
            )
    active = _canonical_ids(active_channel_ids, "active channel")
    if not set(active) <= set(channels_by_id):
        raise AdaptiveAttentionError(
            "active channel is outside the effective roster"
        )
    if set(active) & set(terminal_ids):
        raise AdaptiveAttentionError(
            "terminal channel cannot remain active"
        )
    satisfied = _canonical_ids(
        satisfied_prerequisite_ids, "satisfied prerequisite"
    )
    ready: list[str] = []
    blocked: list[str] = []
    for channel in channels:
        if channel.channel_id in set(active) | set(terminal_ids):
            continue
        if set(channel.prerequisite_ids) <= set(satisfied):
            ready.append(channel.channel_id)
        else:
            blocked.append(channel.channel_id)
    concurrency = _positive(max_concurrency, "max_concurrency")
    capacity = max(0, concurrency - len(active))
    dispatch = tuple(sorted(ready)[:capacity])
    payload = {
        "schema_version": READY_QUEUE_SCHEMA,
        "semantic_roster_digest": roster.semantic_roster_digest,
        "effective_roster_digest": effective_digest,
        "terminal_channel_ids": list(terminal_ids),
        "active_channel_ids": list(active),
        "satisfied_prerequisite_ids": list(satisfied),
        "ready_channel_ids": sorted(ready),
        "blocked_channel_ids": sorted(blocked),
        "dispatch_channel_ids": list(dispatch),
        "max_concurrency": concurrency,
    }
    return AttentionReadyQueue(
        semantic_roster_digest=roster.semantic_roster_digest,
        effective_roster_digest=effective_digest,
        terminal_channel_ids=terminal_ids,
        active_channel_ids=active,
        satisfied_prerequisite_ids=satisfied,
        ready_channel_ids=tuple(sorted(ready)),
        blocked_channel_ids=tuple(sorted(blocked)),
        dispatch_channel_ids=dispatch,
        max_concurrency=concurrency,
        queue_digest=digest_json(payload),
    )


def compile_worker_receipts(
    *,
    channel: EvidenceChannel,
    attempt: int,
    output_digest: str,
    rows: Iterable[Mapping[str, Any]],
) -> tuple[WorkerReceipt, ...]:
    """Compile exact worker rows without creating acceptance authority."""

    EvidenceChannel.from_dict(channel.to_dict())
    attempt_value = _positive(attempt, "attempt")
    output = _sha256(output_digest, "output_digest")
    normalized: dict[str, Mapping[str, Any]] = {}
    expected_fields = {
        "obligation_id",
        "disposition",
        "candidate_ids",
        "evidence_ids",
        "aliases",
    }
    for row in rows:
        _exact_keys(row, expected_fields, "worker output row")
        obligation_id = _identity(
            row["obligation_id"], "worker obligation_id"
        )
        if obligation_id in normalized:
            raise AdaptiveAttentionError(
                "worker output repeats an exact obligation"
            )
        normalized[obligation_id] = row
    if set(normalized) != set(channel.obligation_ids):
        raise AdaptiveAttentionError(
            "worker output must cover the exact obligation denominator"
        )
    receipts: list[WorkerReceipt] = []
    for sequence, obligation_id in enumerate(
        channel.obligation_ids, start=1
    ):
        row = normalized[obligation_id]
        disposition = normalize_worker_disposition(
            row["disposition"]
        )
        candidate_ids = _canonical_ids(
            row["candidate_ids"], "candidate identity"
        )
        evidence_ids = _canonical_ids(
            row["evidence_ids"], "evidence identity"
        )
        aliases = row["aliases"]
        if not isinstance(aliases, Mapping):
            raise AdaptiveAttentionError("aliases must be an object")
        if (
            disposition.disposition == "CANDIDATE_PROPOSED"
            and not candidate_ids
        ):
            raise AdaptiveAttentionError(
                "candidate proposal requires a candidate identity"
            )
        if (
            disposition.disposition
            in {"EVIDENCE_PROPOSED", "NO_EVIDENCE_WITH_TRACE"}
            and not evidence_ids
        ):
            raise AdaptiveAttentionError(
                "evidence or negative proposal requires an exact trace"
            )
        receipts.append(
            WorkerReceipt.create(
                sequence=sequence,
                attempt=attempt_value,
                channel_id=channel.channel_id,
                obligation_id=obligation_id,
                disposition=disposition.disposition,
                output_digest=output,
                candidate_ids=candidate_ids,
                evidence_ids=evidence_ids,
                aliases=aliases,
            )
        )
    return tuple(receipts)


@dataclass(frozen=True, slots=True)
class AttentionUsageReceipt:
    channel_id: str
    channel_row_digest: str
    reservation_digest: str
    observed_input_tokens: int
    observed_output_tokens: int
    observed_tool_invocations: int
    observed_timeout_slots: int
    provider_receipt_digest: str
    usage_digest: str

    @classmethod
    def create(
        cls,
        *,
        channel: EvidenceChannel,
        observed_input_tokens: int,
        observed_output_tokens: int,
        observed_tool_invocations: int,
        observed_timeout_slots: int,
        provider_receipt_digest: str,
    ) -> "AttentionUsageReceipt":
        EvidenceChannel.from_dict(channel.to_dict())
        observed = {
            "observed_input_tokens": _nonnegative(
                observed_input_tokens, "observed_input_tokens"
            ),
            "observed_output_tokens": _nonnegative(
                observed_output_tokens, "observed_output_tokens"
            ),
            "observed_tool_invocations": _nonnegative(
                observed_tool_invocations,
                "observed_tool_invocations",
            ),
            "observed_timeout_slots": _nonnegative(
                observed_timeout_slots, "observed_timeout_slots"
            ),
        }
        reservation = channel.resource_reservation
        ceilings = (
            ("observed_input_tokens", reservation.max_input_tokens),
            ("observed_output_tokens", reservation.max_output_tokens),
            (
                "observed_tool_invocations",
                reservation.max_tool_invocations,
            ),
            ("observed_timeout_slots", reservation.timeout_slots),
        )
        if any(observed[field] > maximum for field, maximum in ceilings):
            raise AdaptiveAttentionError(
                "observed usage exceeds the frozen reservation"
            )
        payload = {
            "schema_version": USAGE_RECEIPT_SCHEMA,
            "channel_id": channel.channel_id,
            "channel_row_digest": channel.row_digest,
            "reservation_digest": reservation.reservation_digest,
            **observed,
            "provider_receipt_digest": _sha256(
                provider_receipt_digest, "provider_receipt_digest"
            ),
        }
        return cls(
            channel_id=channel.channel_id,
            channel_row_digest=channel.row_digest,
            reservation_digest=reservation.reservation_digest,
            provider_receipt_digest=payload[
                "provider_receipt_digest"
            ],
            usage_digest=digest_json(payload),
            **observed,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": USAGE_RECEIPT_SCHEMA,
            "channel_id": self.channel_id,
            "channel_row_digest": self.channel_row_digest,
            "reservation_digest": self.reservation_digest,
            "observed_input_tokens": self.observed_input_tokens,
            "observed_output_tokens": self.observed_output_tokens,
            "observed_tool_invocations": (
                self.observed_tool_invocations
            ),
            "observed_timeout_slots": self.observed_timeout_slots,
            "provider_receipt_digest": self.provider_receipt_digest,
            "usage_digest": self.usage_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionUsageReceipt":
        _exact_keys(
            value,
            {
                "schema_version",
                "channel_id",
                "channel_row_digest",
                "reservation_digest",
                "observed_input_tokens",
                "observed_output_tokens",
                "observed_tool_invocations",
                "observed_timeout_slots",
                "provider_receipt_digest",
                "usage_digest",
            },
            "attention usage receipt",
        )
        if value["schema_version"] != USAGE_RECEIPT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention usage receipt schema"
            )
        payload = dict(value)
        usage_digest = payload.pop("usage_digest")
        if digest_json(payload) != _sha256(
            usage_digest, "usage_digest"
        ):
            raise AdaptiveAttentionError(
                "attention usage receipt does not replay"
            )
        return cls(
            channel_id=_identity(value["channel_id"], "channel_id"),
            channel_row_digest=_sha256(
                value["channel_row_digest"], "channel_row_digest"
            ),
            reservation_digest=_sha256(
                value["reservation_digest"], "reservation_digest"
            ),
            observed_input_tokens=_nonnegative(
                value["observed_input_tokens"],
                "observed_input_tokens",
            ),
            observed_output_tokens=_nonnegative(
                value["observed_output_tokens"],
                "observed_output_tokens",
            ),
            observed_tool_invocations=_nonnegative(
                value["observed_tool_invocations"],
                "observed_tool_invocations",
            ),
            observed_timeout_slots=_nonnegative(
                value["observed_timeout_slots"],
                "observed_timeout_slots",
            ),
            provider_receipt_digest=_sha256(
                value["provider_receipt_digest"],
                "provider_receipt_digest",
            ),
            usage_digest=usage_digest,
        )


@dataclass(frozen=True, slots=True)
class AttentionReservationLedger:
    effective_roster_digest: str
    reserved_attention_units: int
    reserved_input_tokens: int
    reserved_output_tokens: int
    reserved_tool_invocations: int
    reserved_timeout_slots: int
    observed_input_tokens: int
    observed_output_tokens: int
    observed_tool_invocations: int
    observed_timeout_slots: int
    refunded_attention_units: int
    unrefunded_channel_ids: tuple[str, ...]
    usage_receipt_digests: tuple[str, ...]
    ledger_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RESERVATION_LEDGER_SCHEMA,
            "effective_roster_digest": self.effective_roster_digest,
            "reserved_attention_units": self.reserved_attention_units,
            "reserved_input_tokens": self.reserved_input_tokens,
            "reserved_output_tokens": self.reserved_output_tokens,
            "reserved_tool_invocations": self.reserved_tool_invocations,
            "reserved_timeout_slots": self.reserved_timeout_slots,
            "observed_input_tokens": self.observed_input_tokens,
            "observed_output_tokens": self.observed_output_tokens,
            "observed_tool_invocations": self.observed_tool_invocations,
            "observed_timeout_slots": self.observed_timeout_slots,
            "refunded_attention_units": self.refunded_attention_units,
            "unrefunded_channel_ids": list(
                self.unrefunded_channel_ids
            ),
            "usage_receipt_digests": list(
                self.usage_receipt_digests
            ),
            "ledger_digest": self.ledger_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionReservationLedger":
        expected = {
            "schema_version",
            "effective_roster_digest",
            "reserved_attention_units",
            "reserved_input_tokens",
            "reserved_output_tokens",
            "reserved_tool_invocations",
            "reserved_timeout_slots",
            "observed_input_tokens",
            "observed_output_tokens",
            "observed_tool_invocations",
            "observed_timeout_slots",
            "refunded_attention_units",
            "unrefunded_channel_ids",
            "usage_receipt_digests",
            "ledger_digest",
        }
        _exact_keys(value, expected, "attention reservation ledger")
        if value["schema_version"] != RESERVATION_LEDGER_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention reservation ledger schema"
            )
        row = cls(
            effective_roster_digest=_sha256(
                value["effective_roster_digest"],
                "effective_roster_digest",
            ),
            reserved_attention_units=_nonnegative(
                value["reserved_attention_units"],
                "reserved_attention_units",
            ),
            reserved_input_tokens=_nonnegative(
                value["reserved_input_tokens"], "reserved_input_tokens"
            ),
            reserved_output_tokens=_nonnegative(
                value["reserved_output_tokens"],
                "reserved_output_tokens",
            ),
            reserved_tool_invocations=_nonnegative(
                value["reserved_tool_invocations"],
                "reserved_tool_invocations",
            ),
            reserved_timeout_slots=_nonnegative(
                value["reserved_timeout_slots"],
                "reserved_timeout_slots",
            ),
            observed_input_tokens=_nonnegative(
                value["observed_input_tokens"],
                "observed_input_tokens",
            ),
            observed_output_tokens=_nonnegative(
                value["observed_output_tokens"],
                "observed_output_tokens",
            ),
            observed_tool_invocations=_nonnegative(
                value["observed_tool_invocations"],
                "observed_tool_invocations",
            ),
            observed_timeout_slots=_nonnegative(
                value["observed_timeout_slots"],
                "observed_timeout_slots",
            ),
            refunded_attention_units=_nonnegative(
                value["refunded_attention_units"],
                "refunded_attention_units",
            ),
            unrefunded_channel_ids=_canonical_ids(
                value["unrefunded_channel_ids"],
                "unrefunded channel",
            ),
            usage_receipt_digests=tuple(
                sorted(
                    _sha256(item, "usage receipt digest")
                    for item in value["usage_receipt_digests"]
                )
            ),
            ledger_digest=_sha256(
                value["ledger_digest"], "ledger_digest"
            ),
        )
        payload = row.to_dict()
        supplied = payload.pop("ledger_digest")
        if digest_json(payload) != supplied:
            raise AdaptiveAttentionError(
                "attention reservation ledger does not replay"
            )
        if row.refunded_attention_units > row.reserved_attention_units:
            raise AdaptiveAttentionError(
                "reservation refund exceeds reserved attention units"
            )
        return row


def reserve_attention_runtime(
    *,
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    usage_receipts: Iterable[AttentionUsageReceipt],
) -> AttentionReservationLedger:
    effective_digest = effective_roster_digest(roster, amendments)
    channels, _debt, _rows = effective_roster_material(
        roster, amendments
    )
    channels_by_id = {row.channel_id: row for row in channels}
    usage_by_channel: dict[str, AttentionUsageReceipt] = {}
    for raw in usage_receipts:
        usage = AttentionUsageReceipt.from_dict(raw.to_dict())
        channel = channels_by_id.get(usage.channel_id)
        if channel is None:
            raise AdaptiveAttentionError(
                "usage receipt is outside the effective roster"
            )
        if (
            usage.channel_row_digest != channel.row_digest
            or usage.reservation_digest
            != channel.resource_reservation.reservation_digest
        ):
            raise AdaptiveAttentionError(
                "usage receipt has stale channel or reservation bindings"
            )
        reservation = channel.resource_reservation
        if (
            usage.observed_input_tokens > reservation.max_input_tokens
            or usage.observed_output_tokens
            > reservation.max_output_tokens
            or usage.observed_tool_invocations
            > reservation.max_tool_invocations
            or usage.observed_timeout_slots > reservation.timeout_slots
        ):
            raise AdaptiveAttentionError(
                "usage receipt exceeds its exact reservation"
            )
        if usage.channel_id in usage_by_channel:
            raise AdaptiveAttentionError(
                "duplicate usage receipt for channel"
            )
        usage_by_channel[usage.channel_id] = usage
    reservation_fields = (
        ("attention_units", "reserved_attention_units"),
        ("max_input_tokens", "reserved_input_tokens"),
        ("max_output_tokens", "reserved_output_tokens"),
        ("max_tool_invocations", "reserved_tool_invocations"),
        ("timeout_slots", "reserved_timeout_slots"),
    )
    totals = {
        output: sum(
            getattr(channel.resource_reservation, source)
            for channel in channels
        )
        for source, output in reservation_fields
    }
    observed = {
        "observed_input_tokens": sum(
            row.observed_input_tokens for row in usage_by_channel.values()
        ),
        "observed_output_tokens": sum(
            row.observed_output_tokens
            for row in usage_by_channel.values()
        ),
        "observed_tool_invocations": sum(
            row.observed_tool_invocations
            for row in usage_by_channel.values()
        ),
        "observed_timeout_slots": sum(
            row.observed_timeout_slots
            for row in usage_by_channel.values()
        ),
    }
    unrefunded = tuple(
        sorted(set(channels_by_id) - set(usage_by_channel))
    )
    # AU is an indivisible launch reservation.  Exact unused token/tool
    # capacity is telemetry; it is not converted into a newly dispatchable AU
    # in the same frozen roster.
    payload = {
        "schema_version": RESERVATION_LEDGER_SCHEMA,
        "effective_roster_digest": effective_digest,
        **totals,
        **observed,
        "refunded_attention_units": 0,
        "unrefunded_channel_ids": list(unrefunded),
        "usage_receipt_digests": sorted(
            row.usage_digest for row in usage_by_channel.values()
        ),
    }
    return AttentionReservationLedger(
        effective_roster_digest=effective_digest,
        refunded_attention_units=0,
        unrefunded_channel_ids=unrefunded,
        usage_receipt_digests=tuple(
            payload["usage_receipt_digests"]
        ),
        ledger_digest=digest_json(payload),
        **totals,
        **observed,
    )


@dataclass(frozen=True, slots=True)
class AttentionChannelExecution:
    channel_id: str
    accepted_receipts: tuple[AcceptedEvidenceReceipt, ...]
    terminal_receipt: ChannelTerminalReceipt
    usage_receipt: AttentionUsageReceipt | None
    execution_digest: str

    @classmethod
    def create(
        cls,
        *,
        channel: EvidenceChannel,
        accepted_receipts: Iterable[AcceptedEvidenceReceipt],
        terminal_receipt: ChannelTerminalReceipt,
        usage_receipt: AttentionUsageReceipt | None = None,
    ) -> "AttentionChannelExecution":
        accepted = tuple(
            sorted(
                (
                    AcceptedEvidenceReceipt.from_dict(row.to_dict())
                    for row in accepted_receipts
                ),
                key=lambda row: row.worker_receipt.sequence,
            )
        )
        terminal = ChannelTerminalReceipt.from_dict(
            terminal_receipt.to_dict()
        )
        if (
            terminal.channel_id != channel.channel_id
            or terminal.channel_row_digest != channel.row_digest
        ):
            raise AdaptiveAttentionError(
                "channel execution terminal binding is stale"
            )
        if accepted and terminal.terminal_state != "COMMITTED":
            raise AdaptiveAttentionError(
                "non-committed channel cannot expose accepted evidence"
            )
        if any(
            row.attempt_authority.channel_id != channel.channel_id
            for row in accepted
        ):
            raise AdaptiveAttentionError(
                "accepted evidence is outside the channel execution"
            )
        usage = (
            AttentionUsageReceipt.from_dict(usage_receipt.to_dict())
            if usage_receipt is not None
            else None
        )
        if usage is not None and usage.channel_id != channel.channel_id:
            raise AdaptiveAttentionError(
                "usage receipt is outside the channel execution"
            )
        payload = {
            "schema_version": CHANNEL_EXECUTION_SCHEMA,
            "channel_id": channel.channel_id,
            "accepted_receipt_digests": [
                row.accepted_receipt_digest for row in accepted
            ],
            "terminal_receipt_digest": terminal.receipt_digest,
            "usage_receipt_digest": (
                usage.usage_digest if usage is not None else ""
            ),
        }
        return cls(
            channel_id=channel.channel_id,
            accepted_receipts=accepted,
            terminal_receipt=terminal,
            usage_receipt=usage,
            execution_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CHANNEL_EXECUTION_SCHEMA,
            "channel_id": self.channel_id,
            "accepted_receipts": [
                row.to_dict() for row in self.accepted_receipts
            ],
            "terminal_receipt": self.terminal_receipt.to_dict(),
            "usage_receipt": (
                self.usage_receipt.to_dict()
                if self.usage_receipt is not None
                else None
            ),
            "execution_digest": self.execution_digest,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        channel: EvidenceChannel,
    ) -> "AttentionChannelExecution":
        _exact_keys(
            value,
            {
                "schema_version",
                "channel_id",
                "accepted_receipts",
                "terminal_receipt",
                "usage_receipt",
                "execution_digest",
            },
            "attention channel execution",
        )
        if value["schema_version"] != CHANNEL_EXECUTION_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention channel execution schema"
            )
        replayed = cls.create(
            channel=channel,
            accepted_receipts=(
                AcceptedEvidenceReceipt.from_dict(row)
                for row in value["accepted_receipts"]
            ),
            terminal_receipt=ChannelTerminalReceipt.from_dict(
                value["terminal_receipt"]
            ),
            usage_receipt=(
                AttentionUsageReceipt.from_dict(value["usage_receipt"])
                if value["usage_receipt"] is not None
                else None
            ),
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention channel execution content does not replay"
            )
        return replayed


class AttentionChannelCancelled(RuntimeError):
    """Typed adapter signal for a durably cancelled worker transaction."""


@dataclass(frozen=True, slots=True)
class AttentionExecutionResult:
    effective_roster_digest: str
    accepted_receipts: tuple[AcceptedEvidenceReceipt, ...]
    terminal_receipts: tuple[ChannelTerminalReceipt, ...]
    execution_debt: tuple[AttentionDebt, ...]
    usage_receipts: tuple[AttentionUsageReceipt, ...]
    result_digest: str

    @classmethod
    def create(
        cls,
        *,
        effective_roster_digest: str,
        accepted_receipts: Iterable[AcceptedEvidenceReceipt],
        terminal_receipts: Iterable[ChannelTerminalReceipt],
        execution_debt: Iterable[AttentionDebt],
        usage_receipts: Iterable[AttentionUsageReceipt] = (),
    ) -> "AttentionExecutionResult":
        accepted = tuple(
            sorted(
                (
                    AcceptedEvidenceReceipt.from_dict(row.to_dict())
                    for row in accepted_receipts
                ),
                key=lambda row: (
                    row.attempt_authority.channel_id,
                    row.worker_receipt.sequence,
                ),
            )
        )
        terminals = tuple(
            sorted(
                (
                    ChannelTerminalReceipt.from_dict(row.to_dict())
                    for row in terminal_receipts
                ),
                key=lambda row: row.channel_id,
            )
        )
        if len({row.channel_id for row in terminals}) != len(terminals):
            raise AdaptiveAttentionError(
                "execution result contains duplicate terminal channels"
            )
        terminal_by_id = {
            row.channel_id: row for row in terminals
        }
        accepted_channels = {
            row.attempt_authority.channel_id for row in accepted
        }
        if not accepted_channels <= {
            channel_id
            for channel_id, terminal in terminal_by_id.items()
            if terminal.terminal_state == "COMMITTED"
        }:
            raise AdaptiveAttentionError(
                "accepted evidence lacks an exact committed terminal"
            )
        debts = tuple(
            sorted(
                (
                    AttentionDebt.from_dict(row.to_dict())
                    for row in execution_debt
                ),
                key=lambda row: (
                    row.obligation_id,
                    row.reason_code,
                    row.debt_digest,
                ),
            )
        )
        usages = tuple(
            sorted(
                (
                    AttentionUsageReceipt.from_dict(row.to_dict())
                    for row in usage_receipts
                ),
                key=lambda row: row.channel_id,
            )
        )
        if not {row.channel_id for row in usages} <= set(terminal_by_id):
            raise AdaptiveAttentionError(
                "execution usage lacks an exact terminal receipt"
            )
        debt_terminal_ids = {
            channel_id
            for channel_id, terminal in terminal_by_id.items()
            if terminal.terminal_state in {"DEBT", "CANCELLED"}
        }
        represented_debt_terminals = {
            channel_id
            for debt in debts
            for channel_id in debt.failed_channel_ids
        }
        if debt_terminal_ids != represented_debt_terminals:
            raise AdaptiveAttentionError(
                "non-committed terminal channels and execution debt differ"
            )
        payload = {
            "schema_version": EXECUTION_RESULT_SCHEMA,
            "effective_roster_digest": _sha256(
                effective_roster_digest, "effective_roster_digest"
            ),
            "accepted_receipt_digests": [
                row.accepted_receipt_digest for row in accepted
            ],
            "terminal_receipt_digests": [
                row.receipt_digest for row in terminals
            ],
            "execution_debt_digests": [
                row.debt_digest for row in debts
            ],
            "usage_receipt_digests": [
                row.usage_digest for row in usages
            ],
        }
        return cls(
            effective_roster_digest=payload[
                "effective_roster_digest"
            ],
            accepted_receipts=accepted,
            terminal_receipts=terminals,
            execution_debt=debts,
            usage_receipts=usages,
            result_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EXECUTION_RESULT_SCHEMA,
            "effective_roster_digest": self.effective_roster_digest,
            "accepted_receipts": [
                row.to_dict() for row in self.accepted_receipts
            ],
            "terminal_receipts": [
                row.to_dict() for row in self.terminal_receipts
            ],
            "execution_debt": [
                row.to_dict() for row in self.execution_debt
            ],
            "usage_receipts": [
                row.to_dict() for row in self.usage_receipts
            ],
            "result_digest": self.result_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionExecutionResult":
        _exact_keys(
            value,
            {
                "schema_version",
                "effective_roster_digest",
                "accepted_receipts",
                "terminal_receipts",
                "execution_debt",
                "usage_receipts",
                "result_digest",
            },
            "attention execution result",
        )
        if value["schema_version"] != EXECUTION_RESULT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention execution result schema"
            )
        replayed = cls.create(
            effective_roster_digest=value[
                "effective_roster_digest"
            ],
            accepted_receipts=(
                AcceptedEvidenceReceipt.from_dict(row)
                for row in value["accepted_receipts"]
            ),
            terminal_receipts=(
                ChannelTerminalReceipt.from_dict(row)
                for row in value["terminal_receipts"]
            ),
            execution_debt=(
                AttentionDebt.from_dict(row)
                for row in value["execution_debt"]
            ),
            usage_receipts=(
                AttentionUsageReceipt.from_dict(row)
                for row in value["usage_receipts"]
            ),
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention execution result content does not replay"
            )
        return replayed


ChannelExecutor = Callable[
    [EvidenceChannel, CompiledSemanticPrompt], AttentionChannelExecution
]


def execute_ready_batch(
    *,
    scope: AttentionScope,
    denominator: AttentionDenominator,
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    queue: AttentionReadyQueue,
    executor: ChannelExecutor,
) -> AttentionExecutionResult:
    """Execute one bounded ready projection through an injected authority adapter."""

    queue = AttentionReadyQueue.from_dict(queue.to_dict())
    effective_digest = effective_roster_digest(roster, amendments)
    if queue.effective_roster_digest != effective_digest:
        raise AdaptiveAttentionError("ready queue roster binding is stale")
    channels, _debt, _rows = effective_roster_material(
        roster, amendments
    )
    channel_by_id = {row.channel_id: row for row in channels}
    dispatch = tuple(queue.dispatch_channel_ids)
    if not set(dispatch) <= set(channel_by_id):
        raise AdaptiveAttentionError(
            "ready queue dispatch is outside the effective roster"
        )
    prompts = {
        channel_id: compile_semantic_prompt(
            scope=scope,
            denominator=denominator,
            channel=channel_by_id[channel_id],
        )
        for channel_id in dispatch
    }
    executions: list[AttentionChannelExecution] = []
    terminals: list[ChannelTerminalReceipt] = []
    debts: list[AttentionDebt] = []
    if dispatch:
        with ThreadPoolExecutor(
            max_workers=min(queue.max_concurrency, len(dispatch))
        ) as pool:
            futures = {
                pool.submit(
                    executor,
                    channel_by_id[channel_id],
                    prompts[channel_id],
                ): channel_id
                for channel_id in dispatch
            }
            for future in as_completed(futures):
                channel_id = futures[future]
                channel = channel_by_id[channel_id]
                try:
                    execution = future.result()
                    if not isinstance(
                        execution, AttentionChannelExecution
                    ):
                        raise AdaptiveAttentionError(
                            "executor returned an untyped channel result"
                        )
                    if execution.channel_id != channel_id:
                        raise AdaptiveAttentionError(
                            "executor substituted a channel result"
                        )
                    executions.append(
                        AttentionChannelExecution.from_dict(
                            execution.to_dict(), channel=channel
                        )
                    )
                except AttentionChannelCancelled:
                    reason = "USER_CANCELLED"
                    output_digest = digest_json(
                        {
                            "schema_version": "plamen.attention_failure.v1",
                            "channel_id": channel_id,
                            "exception_class": (
                                "AttentionChannelCancelled"
                            ),
                        }
                    )
                    terminal = ChannelTerminalReceipt.create(
                        channel=channel,
                        terminal_state="CANCELLED",
                        output_digest=output_digest,
                        reason_code=reason,
                    )
                    terminals.append(terminal)
                    for obligation_id in channel.obligation_ids:
                        debts.append(
                            AttentionDebt.create(
                                obligation_id=obligation_id,
                                phase=scope.phase,
                                dependency_generation=(
                                    scope.dependency_generation
                                ),
                                provider=(
                                    channel.runtime_policy.provider_family
                                ),
                                reason_code=reason,
                                failed_channel_ids=(channel_id,),
                                attempts=1,
                                reserved_attention_units=(
                                    channel.resource_reservation.attention_units
                                ),
                                consumed_attention_units=(
                                    channel.resource_reservation.attention_units
                                ),
                                affected_identities=(
                                    channel.evidence_slice.subject_ids
                                ),
                                clean_assurance_forbidden=True,
                                clearing_condition=(
                                    "append a valid retry amendment after "
                                    "durable lease revocation"
                                ),
                            )
                        )
                except Exception as exc:
                    # Do not persist exception text; it can contain provider
                    # secrets or source bytes.  The class and exact channel
                    # binding are sufficient for deterministic debt.
                    reason = "EXECUTOR_FAILURE"
                    output_digest = digest_json(
                        {
                            "schema_version": "plamen.attention_failure.v1",
                            "channel_id": channel_id,
                            "exception_class": type(exc).__name__,
                        }
                    )
                    terminal = ChannelTerminalReceipt.create(
                        channel=channel,
                        terminal_state="DEBT",
                        output_digest=output_digest,
                        reason_code=reason,
                    )
                    terminals.append(terminal)
                    for obligation_id in channel.obligation_ids:
                        debts.append(
                            AttentionDebt.create(
                                obligation_id=obligation_id,
                                phase=scope.phase,
                                dependency_generation=(
                                    scope.dependency_generation
                                ),
                                provider=(
                                    channel.runtime_policy.provider_family
                                ),
                                reason_code=reason,
                                failed_channel_ids=(channel_id,),
                                attempts=1,
                                reserved_attention_units=(
                                    channel.resource_reservation.attention_units
                                ),
                                consumed_attention_units=(
                                    channel.resource_reservation.attention_units
                                ),
                                affected_identities=(
                                    channel.evidence_slice.subject_ids
                                ),
                                clean_assurance_forbidden=True,
                                clearing_condition=(
                                    "retry through a current authenticated "
                                    "worker transaction"
                                ),
                            )
                        )
    accepted: list[AcceptedEvidenceReceipt] = []
    usages: list[AttentionUsageReceipt] = []
    for execution in executions:
        accepted.extend(execution.accepted_receipts)
        terminals.append(execution.terminal_receipt)
        if execution.usage_receipt is not None:
            usages.append(execution.usage_receipt)
    return AttentionExecutionResult.create(
        effective_roster_digest=effective_digest,
        accepted_receipts=accepted,
        terminal_receipts=terminals,
        execution_debt=debts,
        usage_receipts=usages,
    )


def join_authenticated_receipts(
    *,
    scope: AttentionScope,
    denominator: AttentionDenominator,
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    accepted_receipts: Iterable[AcceptedEvidenceReceipt],
    genesis_authority: AttentionGenesisAuthority | None = None,
    prior_projection: AttentionJoinProjection | None = None,
    authority_resolver: AttentionAuthorityResolver | None = None,
) -> AttentionJoinProjection:
    """Join receipts through the controller's independent authority boundary."""

    accepted = tuple(
        sorted(
            (
                AcceptedEvidenceReceipt.from_dict(row.to_dict())
                for row in accepted_receipts
            ),
            key=lambda row: (
                row.attempt_authority.channel_id,
                row.worker_receipt.sequence,
            ),
        )
    )
    kwargs: dict[str, Any] = {
        "scope": scope,
        "obligations": (
            prior_projection.denominator_obligations
            if prior_projection is not None
            else denominator.obligations
        ),
        "roster": roster,
        "amendments": amendments,
        "accepted_receipts": accepted,
        "genesis_authority": genesis_authority,
        "prior_projection": prior_projection,
    }
    if authority_resolver is not None:
        kwargs["authority_resolver"] = authority_resolver
    return apply_attention_receipts(**kwargs)


def attention_join_requires_amendment(
    *,
    denominator: AttentionDenominator,
    join_projection: AttentionJoinProjection,
) -> tuple[str, ...]:
    """Return newly derived obligations that must enter a roster amendment."""

    base = {
        row.obligation_id for row in denominator.obligations
    }
    return tuple(
        sorted(
            {
                row.obligation_id
                for row in join_projection.denominator_obligations
            }
            - base
        )
    )


def finalize_attention_stop(
    *,
    scope: AttentionScope,
    denominator: AttentionDenominator,
    roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
    join_projection: AttentionJoinProjection,
    terminal_receipts: Iterable[ChannelTerminalReceipt],
    closure_authority: AttentionClosureAuthority | None,
    prior_projection: AttentionJoinProjection | None = None,
    authority_resolver: AttentionAuthorityResolver | None = None,
    runtime_debt: Iterable[AttentionDebt] = (),
    integrity_violations: Iterable[str] = (),
) -> tuple[AttentionStopBindings, AttentionStopReceipt]:
    """Build exact stop bindings and invoke the controller-owned predicate."""

    pending_amendment = attention_join_requires_amendment(
        denominator=denominator,
        join_projection=join_projection,
    )
    if pending_amendment:
        raise AdaptiveAttentionError(
            "join-derived obligations require a roster amendment before "
            "stop classification: "
            + ",".join(pending_amendment)
        )
    effective_digest = effective_roster_digest(roster, amendments)
    channels, _roster_debt, _rows = effective_roster_material(
        roster, amendments
    )
    channel_by_id = {row.channel_id: row for row in channels}
    terminals = tuple(
        sorted(
            (
                ChannelTerminalReceipt.from_dict(row.to_dict())
                for row in terminal_receipts
            ),
            key=lambda row: row.channel_id,
        )
    )
    if not {row.channel_id for row in terminals} <= set(channel_by_id):
        raise AdaptiveAttentionError(
            "stop terminal is outside the effective roster"
        )
    committed = tuple(
        row.channel_id
        for row in terminals
        if row.terminal_state == "COMMITTED"
    )
    reconciled = {
        obligation_id
        for channel_id in committed
        for obligation_id in channel_by_id[channel_id].obligation_ids
    }
    prior_candidates = (
        prior_projection.candidate_union
        if prior_projection is not None
        else ()
    )
    prior_evidence = (
        prior_projection.evidence_union
        if prior_projection is not None
        else ()
    )
    prior_aliases = (
        prior_projection.alias_map_dict()
        if prior_projection is not None
        else {}
    )
    bindings = AttentionStopBindings.create(
        scope=scope,
        denominator=denominator,
        effective_roster_digest_value=effective_digest,
        terminal_receipts=terminals,
        joined_channel_ids=committed,
        reconciled_obligation_ids=reconciled,
        prior_candidate_union=prior_candidates,
        candidate_union=join_projection.candidate_union,
        prior_evidence_union=prior_evidence,
        evidence_union=join_projection.evidence_union,
        prior_alias_map=prior_aliases,
        alias_map=join_projection.alias_map_dict(),
        integrity_violations=integrity_violations,
    )
    reasons = {
        debt.reason_code
        for debt in runtime_debt
    } | {
        terminal.reason_code
        for terminal in terminals
        if terminal.terminal_state != "COMMITTED"
    }
    kwargs: dict[str, Any] = {
        "scope": scope,
        "denominator": denominator,
        "obligations": join_projection.denominator_obligations,
        "roster": roster,
        "amendments": amendments,
        "bindings": bindings,
        "join_projection": join_projection,
        "closure_authority": closure_authority,
        "bounded_reason_codes": reasons,
    }
    if authority_resolver is not None:
        kwargs["authority_resolver"] = authority_resolver
    stop = classify_attention_stop(**kwargs)
    return bindings, stop


__all__ = [
    "AttentionChannelExecution",
    "AttentionChannelCancelled",
    "AttentionExecutionResult",
    "AttentionReadyQueue",
    "AttentionReservationLedger",
    "AttentionUsageReceipt",
    "BackendLaunchPrompt",
    "CompiledSemanticPrompt",
    "NormalizedWorkerDisposition",
    "compile_backend_launch_prompt",
    "compile_ready_queue",
    "compile_semantic_prompt",
    "compile_worker_receipts",
    "execute_ready_batch",
    "attention_join_requires_amendment",
    "finalize_attention_stop",
    "join_authenticated_receipts",
    "normalize_worker_disposition",
    "reserve_attention_runtime",
]
