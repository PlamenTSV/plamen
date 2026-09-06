"""Provider-free authority ports for adaptive-attention integration.

The adaptive-attention compiler must not interpret a caller-supplied SHA-256
string as proof that PhaseIO, a worker transaction, or a policy provider
actually committed anything.  This module defines exact requests made to an
integration-owned resolver.  It intentionally supplies no successful
production resolver: absence of that adapter resolves to typed debt.

Lineage mutation is likewise an integration responsibility.  The pure CAS
evaluator below defines the required compare-and-swap semantics, but it is not
an atomic storage implementation.  A production adapter must evaluate and
persist the request under the existing PhaseIO checked-commit authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Protocol


AUTHORITY_REQUEST_SCHEMA = "plamen.attention_authority_request.v1"
AUTHORITY_RESOLUTION_SCHEMA = "plamen.attention_authority_resolution.v1"
LINEAGE_REQUEST_SCHEMA = "plamen.attention_lineage_commit_request.v1"
LINEAGE_HEAD_SCHEMA = "plamen.attention_lineage_head.v1"
LINEAGE_DECISION_SCHEMA = "plamen.attention_lineage_cas_decision.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$", re.ASCII)


class AdaptiveAttentionAuthorityError(ValueError):
    """An authority request, decision, or resolution is malformed."""


def _digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise AdaptiveAttentionAuthorityError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def _identity(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise AdaptiveAttentionAuthorityError(
            f"{field} must be a canonical identity"
        )
    return value


def _positive_int(value: Any, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
    ):
        raise AdaptiveAttentionAuthorityError(
            f"{field} must be a positive integer"
        )
    return value


def _reasons(values: Iterable[str]) -> tuple[str, ...]:
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            raise AdaptiveAttentionAuthorityError(
                "authority debt reason must be text"
            )
        normalized = value.strip().upper()
        if not normalized or not _ID_RE.fullmatch(normalized):
            raise AdaptiveAttentionAuthorityError(
                "authority debt reason is not canonical"
            )
        result.add(normalized)
    return tuple(sorted(result))


@dataclass(frozen=True, slots=True)
class ChannelAttemptAuthorityRequest:
    scope_digest: str
    effective_roster_digest: str
    authority_digest: str
    channel_id: str
    channel_row_digest: str
    current_attempt: int
    lease_id: str
    phase_io_commit_digest: str
    transaction_commit_digest: str
    terminal_receipt_digest: str
    output_digest: str
    request_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope_digest: str,
        effective_roster_digest: str,
        authority_digest: str,
        channel_id: str,
        channel_row_digest: str,
        current_attempt: int,
        lease_id: str,
        phase_io_commit_digest: str,
        transaction_commit_digest: str,
        terminal_receipt_digest: str,
        output_digest: str,
    ) -> "ChannelAttemptAuthorityRequest":
        payload = {
            "schema_version": AUTHORITY_REQUEST_SCHEMA,
            "authority_kind": "CHANNEL_ATTEMPT",
            "scope_digest": _sha256(scope_digest, "scope_digest"),
            "effective_roster_digest": _sha256(
                effective_roster_digest, "effective_roster_digest"
            ),
            "authority_digest": _sha256(
                authority_digest, "authority_digest"
            ),
            "channel_id": _identity(channel_id, "channel_id"),
            "channel_row_digest": _sha256(
                channel_row_digest, "channel_row_digest"
            ),
            "current_attempt": _positive_int(
                current_attempt, "current_attempt"
            ),
            "lease_id": _identity(lease_id, "lease_id"),
            "phase_io_commit_digest": _sha256(
                phase_io_commit_digest, "phase_io_commit_digest"
            ),
            "transaction_commit_digest": _sha256(
                transaction_commit_digest,
                "transaction_commit_digest",
            ),
            "terminal_receipt_digest": _sha256(
                terminal_receipt_digest,
                "terminal_receipt_digest",
            ),
            "output_digest": _sha256(
                output_digest, "output_digest"
            ),
        }
        return cls(
            scope_digest=payload["scope_digest"],
            effective_roster_digest=payload[
                "effective_roster_digest"
            ],
            authority_digest=payload["authority_digest"],
            channel_id=payload["channel_id"],
            channel_row_digest=payload["channel_row_digest"],
            current_attempt=payload["current_attempt"],
            lease_id=payload["lease_id"],
            phase_io_commit_digest=payload[
                "phase_io_commit_digest"
            ],
            transaction_commit_digest=payload[
                "transaction_commit_digest"
            ],
            terminal_receipt_digest=payload[
                "terminal_receipt_digest"
            ],
            output_digest=payload["output_digest"],
            request_digest=_digest(payload),
        )


@dataclass(frozen=True, slots=True)
class ClosurePolicyAuthorityRequest:
    parent_digest: str
    obligation_id: str
    obligation_row_digest: str
    closure_policy: str
    authority_class: str
    join_digest: str
    provider_receipt_digest: str
    request_digest: str

    @classmethod
    def create(
        cls,
        *,
        parent_digest: str,
        obligation_id: str,
        obligation_row_digest: str,
        closure_policy: str,
        authority_class: str,
        join_digest: str,
        provider_receipt_digest: str,
    ) -> "ClosurePolicyAuthorityRequest":
        if not isinstance(closure_policy, str) or not closure_policy.strip():
            raise AdaptiveAttentionAuthorityError(
                "closure_policy must be non-empty text"
            )
        if not isinstance(authority_class, str) or not authority_class.strip():
            raise AdaptiveAttentionAuthorityError(
                "authority_class must be non-empty text"
            )
        payload = {
            "schema_version": AUTHORITY_REQUEST_SCHEMA,
            "authority_kind": "CLOSURE_POLICY",
            "parent_digest": _sha256(
                parent_digest, "parent_digest"
            ),
            "obligation_id": _identity(
                obligation_id, "obligation_id"
            ),
            "obligation_row_digest": _sha256(
                obligation_row_digest, "obligation_row_digest"
            ),
            "closure_policy": closure_policy.strip(),
            "authority_class": authority_class.strip().upper(),
            "join_digest": _sha256(join_digest, "join_digest"),
            "provider_receipt_digest": _sha256(
                provider_receipt_digest, "provider_receipt_digest"
            ),
        }
        return cls(
            parent_digest=payload["parent_digest"],
            obligation_id=payload["obligation_id"],
            obligation_row_digest=payload[
                "obligation_row_digest"
            ],
            closure_policy=payload["closure_policy"],
            authority_class=payload["authority_class"],
            join_digest=payload["join_digest"],
            provider_receipt_digest=payload[
                "provider_receipt_digest"
            ],
            request_digest=_digest(payload),
        )


@dataclass(frozen=True, slots=True)
class AttentionLineageCommitRequest:
    lineage_id: str
    scope_digest: str
    base_roster_digest: str
    effective_roster_digest: str
    expected_parent_join_digest: str
    proposed_join_digest: str
    join_sequence: int
    genesis_authority_digest: str
    request_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope_digest: str,
        base_roster_digest: str,
        effective_roster_digest: str,
        expected_parent_join_digest: str,
        proposed_join_digest: str,
        join_sequence: int,
        genesis_authority_digest: str,
    ) -> "AttentionLineageCommitRequest":
        scope = _sha256(scope_digest, "scope_digest")
        base_roster = _sha256(
            base_roster_digest, "base_roster_digest"
        )
        parent = (
            _sha256(
                expected_parent_join_digest,
                "expected_parent_join_digest",
            )
            if expected_parent_join_digest
            else ""
        )
        genesis = (
            _sha256(
                genesis_authority_digest,
                "genesis_authority_digest",
            )
            if genesis_authority_digest
            else ""
        )
        sequence = _positive_int(join_sequence, "join_sequence")
        if sequence == 1:
            if parent or not genesis:
                raise AdaptiveAttentionAuthorityError(
                    "genesis lineage commit needs only a genesis parent"
                )
        elif not parent or genesis:
            raise AdaptiveAttentionAuthorityError(
                "continuation lineage commit needs only a join parent"
            )
        lineage_payload = {
            "schema_version": LINEAGE_HEAD_SCHEMA,
            "scope_digest": scope,
            "base_roster_digest": base_roster,
        }
        payload = {
            "schema_version": LINEAGE_REQUEST_SCHEMA,
            "lineage_id": "AAL-" + _digest(lineage_payload)[:24].upper(),
            "scope_digest": scope,
            "base_roster_digest": base_roster,
            "effective_roster_digest": _sha256(
                effective_roster_digest, "effective_roster_digest"
            ),
            "expected_parent_join_digest": parent,
            "proposed_join_digest": _sha256(
                proposed_join_digest, "proposed_join_digest"
            ),
            "join_sequence": sequence,
            "genesis_authority_digest": genesis,
        }
        return cls(
            lineage_id=payload["lineage_id"],
            scope_digest=scope,
            base_roster_digest=base_roster,
            effective_roster_digest=payload[
                "effective_roster_digest"
            ],
            expected_parent_join_digest=parent,
            proposed_join_digest=payload["proposed_join_digest"],
            join_sequence=sequence,
            genesis_authority_digest=genesis,
            request_digest=_digest(payload),
        )


AuthorityRequest = (
    ChannelAttemptAuthorityRequest
    | ClosurePolicyAuthorityRequest
    | AttentionLineageCommitRequest
)


@dataclass(frozen=True, slots=True)
class AttentionAuthorityResolution:
    request_digest: str
    state: str
    reason_codes: tuple[str, ...]
    resolution_digest: str

    @classmethod
    def authenticated(
        cls, request: AuthorityRequest
    ) -> "AttentionAuthorityResolution":
        return cls._create(request, state="AUTHENTICATED", reasons=())

    @classmethod
    def debt(
        cls, request: AuthorityRequest, *reason_codes: str
    ) -> "AttentionAuthorityResolution":
        return cls._create(
            request, state="DEBT", reasons=reason_codes
        )

    @classmethod
    def _create(
        cls,
        request: AuthorityRequest,
        *,
        state: str,
        reasons: Iterable[str],
    ) -> "AttentionAuthorityResolution":
        if not isinstance(
            request,
            (
                ChannelAttemptAuthorityRequest,
                ClosurePolicyAuthorityRequest,
                AttentionLineageCommitRequest,
            ),
        ):
            raise TypeError("authority resolution needs an exact request")
        if state not in {"AUTHENTICATED", "DEBT"}:
            raise AdaptiveAttentionAuthorityError(
                "unsupported authority resolution state"
            )
        normalized = _reasons(reasons)
        if (state == "AUTHENTICATED") == bool(normalized):
            raise AdaptiveAttentionAuthorityError(
                "authenticated authority has no debt; debt needs reasons"
            )
        payload = {
            "schema_version": AUTHORITY_RESOLUTION_SCHEMA,
            "request_digest": request.request_digest,
            "state": state,
            "reason_codes": list(normalized),
        }
        return cls(
            request_digest=request.request_digest,
            state=state,
            reason_codes=normalized,
            resolution_digest=_digest(payload),
        )

    def replay_for(
        self, request: AuthorityRequest
    ) -> "AttentionAuthorityResolution":
        replayed = self._create(
            request,
            state=self.state,
            reasons=self.reason_codes,
        )
        if replayed != self:
            raise AdaptiveAttentionAuthorityError(
                "authority resolution content does not replay"
            )
        return replayed


class AttentionAuthorityResolver(Protocol):
    """Trusted integration port; implementations authenticate exact requests."""

    def resolve_channel_attempt(
        self, request: ChannelAttemptAuthorityRequest
    ) -> AttentionAuthorityResolution: ...

    def resolve_closure_policy(
        self, request: ClosurePolicyAuthorityRequest
    ) -> AttentionAuthorityResolution: ...

    def commit_lineage(
        self, request: AttentionLineageCommitRequest
    ) -> AttentionAuthorityResolution: ...

    def resolve_lineage(
        self, request: AttentionLineageCommitRequest
    ) -> AttentionAuthorityResolution: ...


class UnresolvedAttentionAuthorityResolver:
    """Fail-closed default used until real checked-commit adapters exist."""

    def resolve_channel_attempt(
        self, request: ChannelAttemptAuthorityRequest
    ) -> AttentionAuthorityResolution:
        return AttentionAuthorityResolution.debt(
            request,
            "PHASE_IO_COMMIT_AUTHORITY_UNRESOLVED",
            "TRANSACTION_COMMIT_AUTHORITY_UNRESOLVED",
        )

    def resolve_closure_policy(
        self, request: ClosurePolicyAuthorityRequest
    ) -> AttentionAuthorityResolution:
        return AttentionAuthorityResolution.debt(
            request, "PROVIDER_RECEIPT_AUTHORITY_UNRESOLVED"
        )

    def commit_lineage(
        self, request: AttentionLineageCommitRequest
    ) -> AttentionAuthorityResolution:
        return AttentionAuthorityResolution.debt(
            request, "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED"
        )

    def resolve_lineage(
        self, request: AttentionLineageCommitRequest
    ) -> AttentionAuthorityResolution:
        return AttentionAuthorityResolution.debt(
            request, "ATTENTION_LINEAGE_CHECKED_COMMIT_UNRESOLVED"
        )


@dataclass(frozen=True, slots=True)
class AttentionLineageHead:
    lineage_id: str
    join_sequence: int
    join_digest: str
    commit_request_digest: str
    head_digest: str

    @classmethod
    def create(
        cls, request: AttentionLineageCommitRequest
    ) -> "AttentionLineageHead":
        if not isinstance(request, AttentionLineageCommitRequest):
            raise TypeError("lineage head needs an exact commit request")
        payload = {
            "schema_version": LINEAGE_HEAD_SCHEMA,
            "lineage_id": request.lineage_id,
            "join_sequence": request.join_sequence,
            "join_digest": request.proposed_join_digest,
            "commit_request_digest": request.request_digest,
        }
        return cls(
            lineage_id=request.lineage_id,
            join_sequence=request.join_sequence,
            join_digest=request.proposed_join_digest,
            commit_request_digest=request.request_digest,
            head_digest=_digest(payload),
        )

    def replay(self) -> "AttentionLineageHead":
        payload = {
            "schema_version": LINEAGE_HEAD_SCHEMA,
            "lineage_id": _identity(
                self.lineage_id, "lineage_id"
            ),
            "join_sequence": _positive_int(
                self.join_sequence, "join_sequence"
            ),
            "join_digest": _sha256(
                self.join_digest, "join_digest"
            ),
            "commit_request_digest": _sha256(
                self.commit_request_digest,
                "commit_request_digest",
            ),
        }
        if _digest(payload) != _sha256(
            self.head_digest, "head_digest"
        ):
            raise AdaptiveAttentionAuthorityError(
                "lineage head content does not replay"
            )
        return self


@dataclass(frozen=True, slots=True)
class AttentionLineageCasDecision:
    request_digest: str
    state: str
    reason_codes: tuple[str, ...]
    decision_digest: str

    @classmethod
    def create(
        cls,
        request: AttentionLineageCommitRequest,
        *,
        state: str,
        reason_codes: Iterable[str] = (),
    ) -> "AttentionLineageCasDecision":
        if state not in {"COMMIT", "IDEMPOTENT", "CONFLICT"}:
            raise AdaptiveAttentionAuthorityError(
                "unsupported lineage CAS decision"
            )
        reasons = _reasons(reason_codes)
        if (state == "CONFLICT") != bool(reasons):
            raise AdaptiveAttentionAuthorityError(
                "only a lineage conflict carries reason codes"
            )
        payload = {
            "schema_version": LINEAGE_DECISION_SCHEMA,
            "request_digest": request.request_digest,
            "state": state,
            "reason_codes": list(reasons),
        }
        return cls(
            request_digest=request.request_digest,
            state=state,
            reason_codes=reasons,
            decision_digest=_digest(payload),
        )


def evaluate_lineage_checked_commit(
    *,
    current_head: AttentionLineageHead | None,
    committed_requests: Mapping[
        str, AttentionLineageCommitRequest
    ],
    request: AttentionLineageCommitRequest,
) -> tuple[AttentionLineageCasDecision, AttentionLineageHead]:
    """Evaluate one CAS while the integration provider holds its commit lock.

    Exact committed-request replay is idempotent, including replay after later
    descendants have committed.  Any other stale predecessor or second genesis
    is a conflicting branch.
    """

    if not isinstance(request, AttentionLineageCommitRequest):
        raise TypeError("lineage CAS needs an exact commit request")
    if current_head is not None and not isinstance(
        current_head, AttentionLineageHead
    ):
        raise TypeError("current_head must be an AttentionLineageHead")
    if current_head is not None:
        current_head.replay()
    committed = committed_requests.get(request.request_digest)
    if committed is not None:
        if committed != request:
            decision = AttentionLineageCasDecision.create(
                request,
                state="CONFLICT",
                reason_codes=("ATTENTION_LINEAGE_DIGEST_COLLISION",),
            )
            return decision, (
                current_head or AttentionLineageHead.create(request)
            )
        decision = AttentionLineageCasDecision.create(
            request, state="IDEMPOTENT"
        )
        return decision, (
            current_head or AttentionLineageHead.create(request)
        )
    if current_head is None:
        admissible = (
            request.join_sequence == 1
            and not request.expected_parent_join_digest
            and bool(request.genesis_authority_digest)
        )
    else:
        admissible = (
            request.lineage_id == current_head.lineage_id
            and request.join_sequence == current_head.join_sequence + 1
            and request.expected_parent_join_digest
            == current_head.join_digest
            and not request.genesis_authority_digest
        )
    if not admissible:
        decision = AttentionLineageCasDecision.create(
            request,
            state="CONFLICT",
            reason_codes=("ATTENTION_LINEAGE_CONFLICT",),
        )
        return decision, (
            current_head or AttentionLineageHead.create(request)
        )
    next_head = AttentionLineageHead.create(request)
    return (
        AttentionLineageCasDecision.create(request, state="COMMIT"),
        next_head,
    )


__all__ = [
    "AdaptiveAttentionAuthorityError",
    "AttentionAuthorityResolution",
    "AttentionAuthorityResolver",
    "AttentionLineageCasDecision",
    "AttentionLineageCommitRequest",
    "AttentionLineageHead",
    "ChannelAttemptAuthorityRequest",
    "ClosurePolicyAuthorityRequest",
    "UnresolvedAttentionAuthorityResolver",
    "evaluate_lineage_checked_commit",
]
