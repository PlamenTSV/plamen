"""Strict, provider-free value types for adaptive-attention compilation.

The module is intentionally limited to canonical JSON, immutable records,
content-addressed identities, and replay validation.  It performs no file IO,
process launch, scheduling, or closure-authority work.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence


ATTENTION_SCOPE_SCHEMA = "plamen.attention_scope.v1"
ATTENTION_OBLIGATION_SCHEMA = "plamen.attention_obligation.v1"
EVIDENCE_SLICE_SCHEMA = "plamen.evidence_slice.v1"
EVIDENCE_CHANNEL_SCHEMA = "plamen.evidence_channel.v1"
RUNTIME_POLICY_SCHEMA = "plamen.attention_runtime_policy.v1"
RESOURCE_RESERVATION_SCHEMA = "plamen.attention_resource_reservation.v1"
ATTENTION_BUDGET_SCHEMA = "plamen.attention_budget.v1"
ATTENTION_DENOMINATOR_SCHEMA = "plamen.attention_denominator.v1"
ATTENTION_ROSTER_SCHEMA = "plamen.attention_roster.v1"
ROSTER_AMENDMENT_SCHEMA = "plamen.attention_roster_amendment.v1"
AMENDMENT_OPERATION_SCHEMA = "plamen.attention_amendment_operation.v1"
ATTENTION_DEBT_SCHEMA = "plamen.attention_debt.v1"
ATTENTION_PLAN_SCHEMA = "plamen.attention_plan.v1"
ATTENTION_JOIN_PROJECTION_SCHEMA = "plamen.attention_join_projection.v1"
ATTENTION_STOP_SCHEMA = "plamen.attention_stop_receipt.v1"
WORKER_RECEIPT_SCHEMA = "plamen.attention_worker_receipt.v1"
CHANNEL_TERMINAL_RECEIPT_SCHEMA = "plamen.attention_channel_terminal_receipt.v1"
CHANNEL_ATTEMPT_AUTHORITY_SCHEMA = (
    "plamen.attention_channel_attempt_authority.v1"
)
ACCEPTED_EVIDENCE_RECEIPT_SCHEMA = (
    "plamen.attention_accepted_evidence_receipt.v1"
)
ATTENTION_GENESIS_AUTHORITY_SCHEMA = (
    "plamen.attention_genesis_authority.v1"
)
ATTENTION_STOP_BINDINGS_SCHEMA = "plamen.attention_stop_bindings.v1"
ATTENTION_CLOSURE_AUTHORITY_SCHEMA = (
    "plamen.attention_closure_authority.v1"
)
CLOSURE_POLICY_PARENT_SCHEMA = (
    "plamen.attention_closure_policy_parent.v1"
)

OBLIGATION_KINDS = frozenset(
    {
        "METHOD_STEP",
        "AXIS_CELL",
        "COMPONENT",
        "RELATION",
        "PROVIDER_DEBT",
        "CANDIDATE_CHALLENGE",
        "CHAIN_PAIR",
        "VERIFIER_ITEM",
        "REPORT_ITEM",
        "MERGE_ITEM",
        "EXPLORATION_ITEM",
    }
)
OBLIGATION_STATES = frozenset(
    {"UNCOVERED", "ASSIGNED", "EVIDENCED", "DISPUTED", "DEBT", "CLOSED"}
)
UNCERTAINTY_CLASSES = frozenset(
    {
        "KNOWN_GAP",
        "MISSING_EVIDENCE",
        "CONFLICT",
        "UNKNOWN_DENOMINATOR",
        "NONE",
    }
)
GRAPH_ORIGINS = frozenset({"NONE", "BASELINE", "TYPED_ADDITIVE"})
COVERAGE_KINDS = frozenset({"EXACT", "LOWER_BOUND", "UNKNOWN"})
STOP_CLASSIFICATIONS = frozenset(
    {"CLEAN_STOP", "BOUNDED_STOP_WITH_DEBT", "HALT"}
)
CHANNEL_STATES = frozenset(
    {"PLANNED", "DISPATCHED", "COMMITTED", "DEBT", "CANCELLED"}
)
WORKER_DISPOSITIONS = frozenset(
    {
        "EVIDENCE_PROPOSED",
        "CANDIDATE_PROPOSED",
        "NO_EVIDENCE_WITH_TRACE",
        "INCONCLUSIVE",
        "BLOCKED",
    }
)
GRAPH_TREATMENTS = frozenset({"legacy_off", "typed_additive"})

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$", re.ASCII)
_CANONICAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$", re.ASCII)
_CONTROLLER_STATE_TOKEN = object()


class AdaptiveAttentionError(ValueError):
    """An immutable adaptive-attention record violates its schema."""


def canonical_json(value: Any) -> str:
    """Return the one canonical JSON encoding used by every identity."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def strict_json_loads(text: str) -> Any:
    """Parse JSON while rejecting duplicate object keys and non-finite values."""

    if not isinstance(text, str):
        raise TypeError("JSON input must be text")

    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdaptiveAttentionError(
                    f"duplicate JSON object key: {key}"
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise AdaptiveAttentionError(f"invalid JSON constant: {value}")

    return json.loads(
        text,
        object_pairs_hook=strict_object,
        parse_constant=reject_constant,
    )


def _exact_keys(
    value: Mapping[str, Any], expected: Iterable[str], label: str
) -> None:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    expected_set = set(expected)
    actual = set(value)
    missing = sorted(expected_set - actual)
    extra = sorted(actual - expected_set)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("unexpected=" + ",".join(extra))
        raise AdaptiveAttentionError(
            f"{label} fields differ: {'; '.join(details)}"
        )


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveAttentionError(f"{field} must be non-empty text")
    return value.strip()


def _safe_text(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _SAFE_ID_RE.fullmatch(text) or text in {".", ".."}:
        raise AdaptiveAttentionError(f"{field} is not a safe identity")
    return text


def _canonical_id(value: Any, field: str) -> str:
    text = _text(value, field)
    if not _CANONICAL_ID_RE.fullmatch(text) or text in {".", ".."}:
        raise AdaptiveAttentionError(f"{field} is not a canonical identity")
    return text


def _sha256(value: Any, field: str) -> str:
    text = _text(value, field).lower()
    if not _SHA256_RE.fullmatch(text):
        raise AdaptiveAttentionError(f"{field} must be a SHA-256 digest")
    return text


def _enum(value: Any, choices: frozenset[str], field: str) -> str:
    text = _text(value, field).upper()
    if text not in choices:
        raise AdaptiveAttentionError(
            f"{field} must be one of {sorted(choices)}"
        )
    return text


def _nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdaptiveAttentionError(f"{field} must be an integer")
    if value < 0:
        raise AdaptiveAttentionError(f"{field} must be non-negative")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise AdaptiveAttentionError(f"{field} must be a boolean")
    return value


def _positive_int(value: Any, field: str) -> int:
    normalized = _nonnegative_int(value, field)
    if normalized == 0:
        raise AdaptiveAttentionError(f"{field} must be positive")
    return normalized


def _sorted_unique_text(
    values: Iterable[Any], field: str, *, allow_empty: bool = True
) -> tuple[str, ...]:
    normalized = tuple(sorted({_text(value, field) for value in values}))
    if not allow_empty and not normalized:
        raise AdaptiveAttentionError(f"{field} must not be empty")
    return normalized


def _row_json(record: Any) -> str:
    return canonical_json(
        record.to_dict() if hasattr(record, "to_dict") else record
    )


@dataclass(frozen=True, order=True, slots=True)
class SourceBinding:
    artifact_identity: str
    sha256: str

    @classmethod
    def create(
        cls,
        artifact_identity: "str | Mapping[str, Any] | SourceBinding",
        sha256: str | None = None,
    ) -> "SourceBinding":
        if isinstance(artifact_identity, cls):
            if sha256 is not None:
                raise AdaptiveAttentionError(
                    "sha256 must be omitted for an existing SourceBinding"
                )
            return artifact_identity
        if isinstance(artifact_identity, Mapping):
            _exact_keys(
                artifact_identity,
                {"artifact_identity", "sha256"},
                "source binding",
            )
            sha256 = artifact_identity["sha256"]
            artifact_identity = artifact_identity["artifact_identity"]
        if sha256 is None:
            raise AdaptiveAttentionError("source binding sha256 is required")
        return cls(
            artifact_identity=_safe_text(
                artifact_identity, "artifact_identity"
            ),
            sha256=_sha256(sha256, "source binding sha256"),
        )

    @property
    def binding_digest(self) -> str:
        return digest_json(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "artifact_identity": self.artifact_identity,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SourceBinding":
        return cls.create(value)


@dataclass(frozen=True, order=True, slots=True)
class MethodologyBinding:
    method_path: str
    file_digest: str
    step_id: str
    step_text_digest: str
    application_authority_id: str

    @classmethod
    def create(
        cls,
        value: "MethodologyBinding | Mapping[str, Any] | None" = None,
        *,
        method_path: str | None = None,
        file_digest: str | None = None,
        step_id: str | None = None,
        step_text_digest: str | None = None,
        application_authority_id: str | None = None,
    ) -> "MethodologyBinding":
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            _exact_keys(
                value,
                {
                    "method_path",
                    "file_digest",
                    "step_id",
                    "step_text_digest",
                    "application_authority_id",
                },
                "methodology binding",
            )
            method_path = value["method_path"]
            file_digest = value["file_digest"]
            step_id = value["step_id"]
            step_text_digest = value["step_text_digest"]
            application_authority_id = value[
                "application_authority_id"
            ]
        elif value is not None:
            raise TypeError("methodology binding must be an object")
        return cls(
            method_path=_safe_text(method_path, "method_path"),
            file_digest=_sha256(file_digest, "methodology file_digest"),
            step_id=_safe_text(step_id, "methodology step_id"),
            step_text_digest=_sha256(
                step_text_digest, "methodology step_text_digest"
            ),
            application_authority_id=_canonical_id(
                application_authority_id,
                "application_authority_id",
            ),
        )

    @property
    def binding_digest(self) -> str:
        return digest_json(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "method_path": self.method_path,
            "file_digest": self.file_digest,
            "step_id": self.step_id,
            "step_text_digest": self.step_text_digest,
            "application_authority_id": self.application_authority_id,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "MethodologyBinding":
        return cls.create(value)


@dataclass(frozen=True, slots=True)
class AttentionScope:
    snapshot_digest: str
    pipeline: str
    mode: str
    ecosystem: str
    phase: str
    dependency_generation: int
    phase_graph_digest: str
    active_phases: tuple[str, ...]
    graph_treatment: str
    scope_digest: str

    @classmethod
    def create(
        cls,
        *,
        snapshot_digest: str,
        pipeline: str,
        mode: str,
        ecosystem: str,
        phase: str,
        dependency_generation: int,
        phase_graph_digest: str,
        active_phases: Iterable[str],
        graph_treatment: str,
    ) -> "AttentionScope":
        payload = {
            "schema_version": ATTENTION_SCOPE_SCHEMA,
            "snapshot_digest": _sha256(
                snapshot_digest, "snapshot_digest"
            ),
            "pipeline": _safe_text(pipeline, "pipeline"),
            "mode": _safe_text(mode, "mode"),
            "ecosystem": _safe_text(ecosystem, "ecosystem"),
            "phase": _safe_text(phase, "phase"),
            "dependency_generation": _nonnegative_int(
                dependency_generation, "dependency_generation"
            ),
            "phase_graph_digest": _sha256(
                phase_graph_digest, "phase_graph_digest"
            ),
            "active_phases": _sorted_unique_text(
                active_phases, "active phase", allow_empty=False
            ),
            "graph_treatment": _text(
                graph_treatment, "graph_treatment"
            ).lower(),
        }
        if payload["graph_treatment"] not in GRAPH_TREATMENTS:
            raise AdaptiveAttentionError(
                "graph_treatment must be legacy_off or typed_additive"
            )
        return cls(
            snapshot_digest=payload["snapshot_digest"],
            pipeline=payload["pipeline"],
            mode=payload["mode"],
            ecosystem=payload["ecosystem"],
            phase=payload["phase"],
            dependency_generation=payload["dependency_generation"],
            phase_graph_digest=payload["phase_graph_digest"],
            active_phases=payload["active_phases"],
            graph_treatment=payload["graph_treatment"],
            scope_digest=digest_json(payload),
        )

    def identity_view(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_SCOPE_SCHEMA,
            "snapshot_digest": self.snapshot_digest,
            "pipeline": self.pipeline,
            "mode": self.mode,
            "ecosystem": self.ecosystem,
            "phase": self.phase,
            "dependency_generation": self.dependency_generation,
            "phase_graph_digest": self.phase_graph_digest,
            "active_phases": list(self.active_phases),
            "graph_treatment": self.graph_treatment,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.identity_view(), "scope_digest": self.scope_digest}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionScope":
        _exact_keys(
            value,
            {
                "schema_version", "snapshot_digest", "pipeline", "mode",
                "ecosystem", "phase", "dependency_generation",
                "phase_graph_digest", "active_phases", "graph_treatment",
                "scope_digest",
            },
            "attention scope",
        )
        if value["schema_version"] != ATTENTION_SCOPE_SCHEMA:
            raise AdaptiveAttentionError("unsupported attention scope schema")
        replayed = cls.create(
            snapshot_digest=value["snapshot_digest"],
            pipeline=value["pipeline"],
            mode=value["mode"],
            ecosystem=value["ecosystem"],
            phase=value["phase"],
            dependency_generation=value["dependency_generation"],
            phase_graph_digest=value["phase_graph_digest"],
            active_phases=value["active_phases"],
            graph_treatment=value["graph_treatment"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError("attention scope content does not replay")
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionObligation:
    obligation_id: str
    kind: str
    pipeline: str
    mode: str
    ecosystem: str
    phase: str
    snapshot_digest: str
    dependency_generation: int
    subject_ids: tuple[str, ...]
    source_bindings: tuple[SourceBinding, ...]
    methodology_bindings: tuple[MethodologyBinding, ...]
    predecessor_receipt_digests: tuple[str, ...]
    closure_policy: str
    mandatory: bool
    impact_rank: int
    uncertainty_class: str
    graph_origin: str
    state: str
    role_family: str
    methodology_family: str
    source_class: str
    proof_environment: str
    required_tool_classes: tuple[str, ...]
    dependency_fanout: int
    closure_blocking: bool
    enrichment_only: bool
    debt_reason_code: str
    provider: str
    clearing_condition: str
    closure_authority_digest: str
    row_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        kind: str,
        subject_ids: Iterable[str],
        source_bindings: Iterable[SourceBinding | Mapping[str, Any]],
        methodology_bindings: Iterable[
            MethodologyBinding | Mapping[str, Any]
        ] = (),
        predecessor_receipt_digests: Iterable[str] = (),
        closure_policy: str,
        mandatory: bool,
        impact_rank: int,
        uncertainty_class: str = "NONE",
        graph_origin: str = "NONE",
        state: str = "UNCOVERED",
        canonical_id: str | None = None,
        role_family: str = "analysis",
        methodology_family: str = "baseline",
        source_class: str = "source",
        proof_environment: str = "static",
        required_tool_classes: Iterable[str] = (),
        dependency_fanout: int = 0,
        closure_blocking: bool = True,
        enrichment_only: bool = False,
        debt_reason_code: str = "",
        provider: str = "",
        clearing_condition: str = "",
        closure_authority_digest: str = "",
        _controller_state_token: object | None = None,
    ) -> "AttentionObligation":
        if not isinstance(scope, AttentionScope):
            raise TypeError("scope must be an AttentionScope")
        kind_value = _enum(kind, OBLIGATION_KINDS, "kind")
        normalized_subjects = _sorted_unique_text(
            subject_ids, "subject_id", allow_empty=False
        )
        normalized_sources = tuple(
            sorted(
                {
                    SourceBinding.create(value)
                    for value in source_bindings
                },
                key=_row_json,
            )
        )
        if not normalized_sources:
            raise AdaptiveAttentionError(
                "source_bindings must not be empty"
            )
        normalized_methods = tuple(
            sorted(
                {
                    MethodologyBinding.create(value)
                    for value in methodology_bindings
                },
                key=_row_json,
            )
        )
        normalized_predecessors = tuple(
            sorted(
                {
                    _sha256(value, "predecessor receipt digest")
                    for value in predecessor_receipt_digests
                }
            )
        )
        impact_value = _nonnegative_int(impact_rank, "impact_rank")
        if impact_value > 4:
            raise AdaptiveAttentionError("impact_rank must be between 0 and 4")
        identity_payload = {
            "schema": ATTENTION_OBLIGATION_SCHEMA,
            "snapshot_digest": scope.snapshot_digest,
            "pipeline": scope.pipeline,
            "ecosystem": scope.ecosystem,
            "phase": scope.phase,
            "dependency_generation": scope.dependency_generation,
            "kind": kind_value,
            "subject_ids": list(normalized_subjects),
            "source_binding_digests": [
                value.binding_digest for value in normalized_sources
            ],
            "methodology_step_digests": [
                value.binding_digest for value in normalized_methods
            ],
            "closure_policy": _safe_text(
                closure_policy, "closure_policy"
            ),
        }
        generated_id = (
            f"AOB-{kind_value}-"
            f"{digest_json(identity_payload)[:24].upper()}"
        )
        obligation_id = (
            generated_id
            if canonical_id is None
            else _canonical_id(canonical_id, "canonical_id")
        )
        state_value = _enum(state, OBLIGATION_STATES, "state")
        if (
            state_value != "UNCOVERED"
            and _controller_state_token is not _CONTROLLER_STATE_TOKEN
        ):
            raise AdaptiveAttentionError(
                "controller-owned obligation state cannot be minted by "
                "public creation"
            )
        closure_digest = (
            _sha256(
                closure_authority_digest,
                "closure_authority_digest",
            )
            if closure_authority_digest
            else ""
        )
        if state_value == "CLOSED" and not closure_digest:
            raise AdaptiveAttentionError(
                "closed obligation requires closure authority"
            )
        if state_value != "CLOSED" and closure_digest:
            raise AdaptiveAttentionError(
                "non-closed obligation cannot bind closure authority"
            )
        values: dict[str, Any] = {
            "obligation_id": obligation_id,
            "kind": kind_value,
            "pipeline": scope.pipeline,
            "mode": scope.mode,
            "ecosystem": scope.ecosystem,
            "phase": scope.phase,
            "snapshot_digest": scope.snapshot_digest,
            "dependency_generation": scope.dependency_generation,
            "subject_ids": normalized_subjects,
            "source_bindings": normalized_sources,
            "methodology_bindings": normalized_methods,
            "predecessor_receipt_digests": normalized_predecessors,
            "closure_policy": identity_payload["closure_policy"],
            "mandatory": _boolean(mandatory, "mandatory"),
            "impact_rank": impact_value,
            "uncertainty_class": _enum(
                uncertainty_class,
                UNCERTAINTY_CLASSES,
                "uncertainty_class",
            ),
            "graph_origin": _enum(
                graph_origin, GRAPH_ORIGINS, "graph_origin"
            ),
            "state": state_value,
            "role_family": _safe_text(role_family, "role_family"),
            "methodology_family": _safe_text(
                methodology_family, "methodology_family"
            ),
            "source_class": _safe_text(source_class, "source_class"),
            "proof_environment": _safe_text(
                proof_environment, "proof_environment"
            ),
            "required_tool_classes": _sorted_unique_text(
                required_tool_classes, "required tool class"
            ),
            "dependency_fanout": _nonnegative_int(
                dependency_fanout, "dependency_fanout"
            ),
            "closure_blocking": _boolean(
                closure_blocking, "closure_blocking"
            ),
            "enrichment_only": _boolean(
                enrichment_only, "enrichment_only"
            ),
            "debt_reason_code": (
                _safe_text(debt_reason_code, "debt_reason_code")
                if debt_reason_code
                else ""
            ),
            "provider": (
                _safe_text(provider, "provider") if provider else ""
            ),
            "clearing_condition": (
                _text(clearing_condition, "clearing_condition")
                if clearing_condition
                else ""
            ),
            "closure_authority_digest": closure_digest,
        }
        row_without_digest = cls._dict_from_values(values)
        return cls(**values, row_digest=digest_json(row_without_digest))

    @staticmethod
    def _dict_from_values(values: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_OBLIGATION_SCHEMA,
            "obligation_id": values["obligation_id"],
            "kind": values["kind"],
            "pipeline": values["pipeline"],
            "mode": values["mode"],
            "ecosystem": values["ecosystem"],
            "phase": values["phase"],
            "snapshot_digest": values["snapshot_digest"],
            "dependency_generation": values["dependency_generation"],
            "subject_ids": list(values["subject_ids"]),
            "source_bindings": [
                value.to_dict() for value in values["source_bindings"]
            ],
            "methodology_bindings": [
                value.to_dict()
                for value in values["methodology_bindings"]
            ],
            "predecessor_receipt_digests": list(
                values["predecessor_receipt_digests"]
            ),
            "closure_policy": values["closure_policy"],
            "mandatory": values["mandatory"],
            "impact_rank": values["impact_rank"],
            "uncertainty_class": values["uncertainty_class"],
            "graph_origin": values["graph_origin"],
            "state": values["state"],
            "role_family": values["role_family"],
            "methodology_family": values["methodology_family"],
            "source_class": values["source_class"],
            "proof_environment": values["proof_environment"],
            "required_tool_classes": list(
                values["required_tool_classes"]
            ),
            "dependency_fanout": values["dependency_fanout"],
            "closure_blocking": values["closure_blocking"],
            "enrichment_only": values["enrichment_only"],
            "debt_reason_code": values["debt_reason_code"],
            "provider": values["provider"],
            "clearing_condition": values["clearing_condition"],
            "closure_authority_digest": values[
                "closure_authority_digest"
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        values = {
            field: getattr(self, field)
            for field in self.__dataclass_fields__
            if field != "row_digest"
        }
        return {
            **self._dict_from_values(values),
            "row_digest": self.row_digest,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionObligation":
        expected = {
            "schema_version",
            "obligation_id",
            "kind",
            "pipeline",
            "mode",
            "ecosystem",
            "phase",
            "snapshot_digest",
            "dependency_generation",
            "subject_ids",
            "source_bindings",
            "methodology_bindings",
            "predecessor_receipt_digests",
            "closure_policy",
            "mandatory",
            "impact_rank",
            "uncertainty_class",
            "graph_origin",
            "state",
            "role_family",
            "methodology_family",
            "source_class",
            "proof_environment",
            "required_tool_classes",
            "dependency_fanout",
            "closure_blocking",
            "enrichment_only",
            "debt_reason_code",
            "provider",
            "clearing_condition",
            "closure_authority_digest",
            "row_digest",
        }
        _exact_keys(value, expected, "attention obligation")
        if value["schema_version"] != ATTENTION_OBLIGATION_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention obligation schema"
            )
        scope = AttentionScope.create(
            snapshot_digest=value["snapshot_digest"],
            pipeline=value["pipeline"],
            mode=value["mode"],
            ecosystem=value["ecosystem"],
            phase=value["phase"],
            dependency_generation=value["dependency_generation"],
            phase_graph_digest="0" * 64,
            active_phases=(value["phase"],),
            graph_treatment="legacy_off",
        )
        raw_id = _canonical_id(value["obligation_id"], "obligation_id")
        generated_prefix = f"AOB-{_text(value['kind'], 'kind').upper()}-"
        canonical_id: str | None = raw_id
        if raw_id.startswith(generated_prefix):
            canonical_id = None
        row = cls.create(
            scope=scope,
            canonical_id=canonical_id,
            kind=value["kind"],
            subject_ids=value["subject_ids"],
            source_bindings=value["source_bindings"],
            methodology_bindings=value["methodology_bindings"],
            predecessor_receipt_digests=value[
                "predecessor_receipt_digests"
            ],
            closure_policy=value["closure_policy"],
            mandatory=value["mandatory"],
            impact_rank=value["impact_rank"],
            uncertainty_class=value["uncertainty_class"],
            graph_origin=value["graph_origin"],
            state=value["state"],
            role_family=value["role_family"],
            methodology_family=value["methodology_family"],
            source_class=value["source_class"],
            proof_environment=value["proof_environment"],
            required_tool_classes=value["required_tool_classes"],
            dependency_fanout=value["dependency_fanout"],
            closure_blocking=value["closure_blocking"],
            enrichment_only=value["enrichment_only"],
            debt_reason_code=value["debt_reason_code"],
            provider=value["provider"],
            clearing_condition=value["clearing_condition"],
            closure_authority_digest=value[
                "closure_authority_digest"
            ],
            _controller_state_token=_CONTROLLER_STATE_TOKEN,
        )
        # Phase-graph and graph-treatment digests are not obligation row
        # fields.  Reconstructing them with neutral values is safe because
        # obligation identity binds the snapshot/phase/generation/source
        # authorities listed by the public schema.
        if row.obligation_id != raw_id:
            raise AdaptiveAttentionError("obligation_id does not replay")
        if row.row_digest != value["row_digest"]:
            raise AdaptiveAttentionError("row_digest does not replay")
        return row

    @classmethod
    def from_json(cls, text: str) -> "AttentionObligation":
        value = strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise AdaptiveAttentionError(
                "attention obligation JSON must be an object"
            )
        return cls.from_dict(value)


_ALLOWED_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "UNCOVERED": frozenset({"ASSIGNED"}),
    "ASSIGNED": frozenset({"EVIDENCED", "DISPUTED", "DEBT"}),
    "EVIDENCED": frozenset(
        {"ASSIGNED", "DISPUTED", "CLOSED", "DEBT"}
    ),
    "DISPUTED": frozenset({"ASSIGNED", "CLOSED", "DEBT"}),
    "DEBT": frozenset({"ASSIGNED"}),
    "CLOSED": frozenset({"UNCOVERED", "DISPUTED"}),
}


def validate_obligation_transition(
    current_state: str,
    next_state: str,
    *,
    authority_class: str = "CONTROLLER",
    closure_authority: "AttentionClosureAuthority | None" = None,
) -> bool:
    current = _enum(
        current_state, OBLIGATION_STATES, "current obligation state"
    )
    target = _enum(
        next_state, OBLIGATION_STATES, "next obligation state"
    )
    authority = _text(authority_class, "authority_class").upper()
    if current == target:
        if target == "CLOSED" and not isinstance(
            closure_authority, AttentionClosureAuthority
        ):
            raise AdaptiveAttentionError(
                "closure_authority must be an exact typed terminal/join "
                "parent"
            )
        return True
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise AdaptiveAttentionError(
            f"invalid obligation transition: {current} -> {target}"
        )
    if target == "CLOSED":
        if not isinstance(closure_authority, AttentionClosureAuthority):
            if authority == "WORKER":
                raise AdaptiveAttentionError(
                    "worker authority cannot close an obligation"
                )
            raise AdaptiveAttentionError(
                "closure_authority must be an exact typed terminal/join "
                "parent"
            )
        if (
            current,
            target,
        ) != ("EVIDENCED", "CLOSED"):
            raise AdaptiveAttentionError(
                "closure authority can close only evidenced obligations"
            )
    return True


def transition_obligation(
    obligation: AttentionObligation,
    next_state: str,
    *,
    authority_class: str = "CONTROLLER",
    closure_authority: "AttentionClosureAuthority | None" = None,
) -> AttentionObligation:
    if not isinstance(obligation, AttentionObligation):
        raise TypeError("obligation must be an AttentionObligation")
    validate_obligation_transition(
        obligation.state,
        next_state,
        authority_class=authority_class,
        closure_authority=closure_authority,
    )
    target = _text(next_state, "next_state").upper()
    if target == obligation.state:
        return obligation
    closure_digest = ""
    if target == "CLOSED":
        assert closure_authority is not None
        authorized = dict(closure_authority.authorized_obligation_rows)
        if authorized.get(obligation.obligation_id) != obligation.row_digest:
            raise AdaptiveAttentionError(
                "closure authority does not bind the exact obligation row"
            )
        closure_digest = closure_authority.authority_digest
    changed = replace(
        obligation,
        state=target,
        closure_authority_digest=closure_digest,
        row_digest="",
    )
    values = {
        field: getattr(changed, field)
        for field in changed.__dataclass_fields__
        if field != "row_digest"
    }
    return replace(
        changed,
        row_digest=digest_json(
            AttentionObligation._dict_from_values(values)
        ),
    )


@dataclass(frozen=True, slots=True)
class EvidenceSlice:
    scope_digest: str
    source_bindings: tuple[SourceBinding, ...]
    subject_ids: tuple[str, ...]
    method_step_ids: tuple[str, ...]
    graph_marker: str
    predecessor_receipt_digests: tuple[str, ...]
    permitted_tool_classes: tuple[str, ...]
    max_prompt_projection_digest: str
    slice_id: str
    row_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        source_bindings: Iterable[SourceBinding | Mapping[str, Any]],
        subject_ids: Iterable[str],
        method_step_ids: Iterable[str],
        graph_marker: str,
        predecessor_receipt_digests: Iterable[str],
        permitted_tool_classes: Iterable[str],
        max_prompt_projection_digest: str,
    ) -> "EvidenceSlice":
        sources = tuple(
            sorted(
                {
                    SourceBinding.create(value)
                    for value in source_bindings
                },
                key=_row_json,
            )
        )
        if not sources:
            raise AdaptiveAttentionError(
                "evidence slice source_bindings must not be empty"
            )
        payload: dict[str, Any] = {
            "schema_version": EVIDENCE_SLICE_SCHEMA,
            "scope_digest": _sha256(scope.scope_digest, "scope_digest"),
            "source_bindings": [value.to_dict() for value in sources],
            "subject_ids": list(
                _sorted_unique_text(
                    subject_ids, "slice subject_id", allow_empty=False
                )
            ),
            "method_step_ids": list(
                _sorted_unique_text(method_step_ids, "method step id")
            ),
            "graph_marker": _safe_text(
                graph_marker, "graph_marker"
            ),
            "predecessor_receipt_digests": sorted(
                {
                    _sha256(value, "predecessor receipt digest")
                    for value in predecessor_receipt_digests
                }
            ),
            "permitted_tool_classes": list(
                _sorted_unique_text(
                    permitted_tool_classes, "permitted tool class"
                )
            ),
            "max_prompt_projection_digest": _sha256(
                max_prompt_projection_digest,
                "max_prompt_projection_digest",
            ),
        }
        slice_id = "AES-" + digest_json(payload)[:24].upper()
        return cls(
            scope_digest=payload["scope_digest"],
            source_bindings=sources,
            subject_ids=tuple(payload["subject_ids"]),
            method_step_ids=tuple(payload["method_step_ids"]),
            graph_marker=payload["graph_marker"],
            predecessor_receipt_digests=tuple(
                payload["predecessor_receipt_digests"]
            ),
            permitted_tool_classes=tuple(
                payload["permitted_tool_classes"]
            ),
            max_prompt_projection_digest=payload[
                "max_prompt_projection_digest"
            ],
            slice_id=slice_id,
            row_digest=digest_json({**payload, "slice_id": slice_id}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_SLICE_SCHEMA,
            "slice_id": self.slice_id,
            "scope_digest": self.scope_digest,
            "source_bindings": [
                value.to_dict() for value in self.source_bindings
            ],
            "subject_ids": list(self.subject_ids),
            "method_step_ids": list(self.method_step_ids),
            "graph_marker": self.graph_marker,
            "predecessor_receipt_digests": list(
                self.predecessor_receipt_digests
            ),
            "permitted_tool_classes": list(
                self.permitted_tool_classes
            ),
            "max_prompt_projection_digest": (
                self.max_prompt_projection_digest
            ),
            "row_digest": self.row_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceSlice":
        expected = {
            "schema_version", "slice_id", "scope_digest",
            "source_bindings", "subject_ids", "method_step_ids",
            "graph_marker", "predecessor_receipt_digests",
            "permitted_tool_classes", "max_prompt_projection_digest",
            "row_digest",
        }
        _exact_keys(value, expected, "evidence slice")
        if value["schema_version"] != EVIDENCE_SLICE_SCHEMA:
            raise AdaptiveAttentionError("unsupported evidence slice schema")
        if not isinstance(value["source_bindings"], list):
            raise AdaptiveAttentionError("source_bindings must be an array")
        sources = tuple(
            SourceBinding.from_dict(item)
            for item in value["source_bindings"]
        )
        payload = dict(value)
        row_digest = payload.pop("row_digest")
        slice_id = payload.pop("slice_id")
        if "AES-" + digest_json(payload)[:24].upper() != slice_id:
            raise AdaptiveAttentionError("evidence slice identity does not replay")
        payload["slice_id"] = slice_id
        if digest_json(payload) != _sha256(row_digest, "row_digest"):
            raise AdaptiveAttentionError("evidence slice content does not replay")
        replayed = cls(
            scope_digest=_sha256(value["scope_digest"], "scope_digest"),
            source_bindings=sources,
            subject_ids=_sorted_unique_text(
                value["subject_ids"], "subject_id", allow_empty=False
            ),
            method_step_ids=_sorted_unique_text(
                value["method_step_ids"], "method_step_id"
            ),
            graph_marker=_safe_text(value["graph_marker"], "graph_marker"),
            predecessor_receipt_digests=tuple(
                _sha256(item, "predecessor receipt digest")
                for item in value["predecessor_receipt_digests"]
            ),
            permitted_tool_classes=_sorted_unique_text(
                value["permitted_tool_classes"], "permitted tool class"
            ),
            max_prompt_projection_digest=_sha256(
                value["max_prompt_projection_digest"],
                "max_prompt_projection_digest",
            ),
            slice_id=slice_id,
            row_digest=row_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "evidence slice canonical form does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class RuntimeCapabilityPolicy:
    backend_family: str
    provider_family: str
    model_capability_tier: str
    allowed_tool_classes: tuple[str, ...]
    context_floor: int
    output_ceiling: int
    timeout_class: str
    runtime_policy_digest: str

    @classmethod
    def create(
        cls,
        *,
        backend_family: str,
        provider_family: str,
        model_capability_tier: str,
        allowed_tool_classes: Iterable[str],
        context_floor: int = 32_768,
        output_ceiling: int = 8_192,
        timeout_class: str = "phase-policy",
    ) -> "RuntimeCapabilityPolicy":
        payload = {
            "schema_version": RUNTIME_POLICY_SCHEMA,
            "backend_family": _safe_text(
                backend_family, "backend_family"
            ),
            "provider_family": _safe_text(
                provider_family, "provider_family"
            ),
            "model_capability_tier": _safe_text(
                model_capability_tier, "model_capability_tier"
            ),
            "allowed_tool_classes": list(
                _sorted_unique_text(
                    allowed_tool_classes, "allowed tool class"
                )
            ),
            "context_floor": _positive_int(
                context_floor, "context_floor"
            ),
            "output_ceiling": _positive_int(
                output_ceiling, "output_ceiling"
            ),
            "timeout_class": _safe_text(
                timeout_class, "timeout_class"
            ),
        }
        if payload["context_floor"] < 32_768:
            raise AdaptiveAttentionError(
                "context_floor is below the model-channel minimum"
            )
        if payload["output_ceiling"] < 2_048:
            raise AdaptiveAttentionError(
                "output_ceiling is below the model-channel minimum"
            )
        return cls(
            backend_family=payload["backend_family"],
            provider_family=payload["provider_family"],
            model_capability_tier=payload["model_capability_tier"],
            allowed_tool_classes=tuple(
                payload["allowed_tool_classes"]
            ),
            context_floor=payload["context_floor"],
            output_ceiling=payload["output_ceiling"],
            timeout_class=payload["timeout_class"],
            runtime_policy_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_POLICY_SCHEMA,
            "backend_family": self.backend_family,
            "provider_family": self.provider_family,
            "model_capability_tier": self.model_capability_tier,
            "allowed_tool_classes": list(self.allowed_tool_classes),
            "context_floor": self.context_floor,
            "output_ceiling": self.output_ceiling,
            "timeout_class": self.timeout_class,
            "runtime_policy_digest": self.runtime_policy_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "RuntimeCapabilityPolicy":
        _exact_keys(
            value,
            {
                "schema_version", "backend_family", "provider_family",
                "model_capability_tier", "allowed_tool_classes",
                "context_floor", "output_ceiling", "timeout_class",
                "runtime_policy_digest",
            },
            "runtime policy",
        )
        if value["schema_version"] != RUNTIME_POLICY_SCHEMA:
            raise AdaptiveAttentionError("unsupported runtime policy schema")
        replayed = cls.create(
            backend_family=value["backend_family"],
            provider_family=value["provider_family"],
            model_capability_tier=value["model_capability_tier"],
            allowed_tool_classes=value["allowed_tool_classes"],
            context_floor=value["context_floor"],
            output_ceiling=value["output_ceiling"],
            timeout_class=value["timeout_class"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError("runtime policy content does not replay")
        return replayed


@dataclass(frozen=True, slots=True)
class ResourceReservation:
    attention_units: int
    max_input_tokens: int
    max_output_tokens: int
    max_tool_invocations: int
    timeout_slots: int
    reservation_digest: str

    @classmethod
    def create(
        cls,
        *,
        attention_units: int,
        max_input_tokens: int,
        max_output_tokens: int,
        max_tool_invocations: int,
        timeout_slots: int,
    ) -> "ResourceReservation":
        payload = {
            "schema_version": RESOURCE_RESERVATION_SCHEMA,
            "attention_units": _nonnegative_int(
                attention_units, "attention_units"
            ),
            "max_input_tokens": _nonnegative_int(
                max_input_tokens, "max_input_tokens"
            ),
            "max_output_tokens": _nonnegative_int(
                max_output_tokens, "max_output_tokens"
            ),
            "max_tool_invocations": _nonnegative_int(
                max_tool_invocations, "max_tool_invocations"
            ),
            "timeout_slots": _nonnegative_int(
                timeout_slots, "timeout_slots"
            ),
        }
        if payload["attention_units"] > 0:
            if payload["max_input_tokens"] < 32_768:
                raise AdaptiveAttentionError(
                    "model reservation input capacity is below minimum"
                )
            if payload["max_output_tokens"] < 2_048:
                raise AdaptiveAttentionError(
                    "model reservation output capacity is below minimum"
                )
        return cls(
            attention_units=payload["attention_units"],
            max_input_tokens=payload["max_input_tokens"],
            max_output_tokens=payload["max_output_tokens"],
            max_tool_invocations=payload["max_tool_invocations"],
            timeout_slots=payload["timeout_slots"],
            reservation_digest=digest_json(payload),
        )

    @classmethod
    def model_channel(
        cls, *, attention_units: int = 1
    ) -> "ResourceReservation":
        units = _positive_int(attention_units, "attention_units")
        if units == 1:
            return cls.create(
                attention_units=1,
                max_input_tokens=65_536,
                max_output_tokens=8_192,
                max_tool_invocations=24,
                timeout_slots=1,
            )
        return cls.create(
            attention_units=units,
            max_input_tokens=65_536 * units,
            max_output_tokens=12_288
            if units == 2
            else 8_192 * units,
            max_tool_invocations=24 * units,
            timeout_slots=units,
        )

    @classmethod
    def mechanical(cls) -> "ResourceReservation":
        return cls.create(
            attention_units=0,
            max_input_tokens=0,
            max_output_tokens=0,
            max_tool_invocations=0,
            timeout_slots=0,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RESOURCE_RESERVATION_SCHEMA,
            "attention_units": self.attention_units,
            "max_input_tokens": self.max_input_tokens,
            "max_output_tokens": self.max_output_tokens,
            "max_tool_invocations": self.max_tool_invocations,
            "timeout_slots": self.timeout_slots,
            "reservation_digest": self.reservation_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "ResourceReservation":
        _exact_keys(
            value,
            {
                "schema_version", "attention_units", "max_input_tokens",
                "max_output_tokens", "max_tool_invocations",
                "timeout_slots", "reservation_digest",
            },
            "resource reservation",
        )
        if value["schema_version"] != RESOURCE_RESERVATION_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported resource reservation schema"
            )
        replayed = cls.create(
            attention_units=value["attention_units"],
            max_input_tokens=value["max_input_tokens"],
            max_output_tokens=value["max_output_tokens"],
            max_tool_invocations=value["max_tool_invocations"],
            timeout_slots=value["timeout_slots"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "resource reservation content does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionBudget:
    max_total_channels: int
    max_attention_units: int
    max_concurrency: int
    max_attempts_per_channel: int
    reserved_channels: int
    reserved_attention_units: int
    budget_digest: str

    @classmethod
    def create(
        cls,
        *,
        max_total_channels: int,
        max_attention_units: int,
        max_concurrency: int,
        max_attempts_per_channel: int,
        reserved_channels: int = 0,
        reserved_attention_units: int = 0,
    ) -> "AttentionBudget":
        payload = {
            "schema_version": ATTENTION_BUDGET_SCHEMA,
            "max_total_channels": _nonnegative_int(
                max_total_channels, "max_total_channels"
            ),
            "max_attention_units": _nonnegative_int(
                max_attention_units, "max_attention_units"
            ),
            "max_concurrency": _positive_int(
                max_concurrency, "max_concurrency"
            ),
            "max_attempts_per_channel": _positive_int(
                max_attempts_per_channel,
                "max_attempts_per_channel",
            ),
            "reserved_channels": _nonnegative_int(
                reserved_channels, "reserved_channels"
            ),
            "reserved_attention_units": _nonnegative_int(
                reserved_attention_units, "reserved_attention_units"
            ),
        }
        if payload["reserved_channels"] > payload["max_total_channels"]:
            raise AdaptiveAttentionError(
                "reserved channels exceed the channel cap"
            )
        if (
            payload["reserved_attention_units"]
            > payload["max_attention_units"]
        ):
            raise AdaptiveAttentionError(
                "reserved attention units exceed the AU cap"
            )
        return cls(
            max_total_channels=payload["max_total_channels"],
            max_attention_units=payload["max_attention_units"],
            max_concurrency=payload["max_concurrency"],
            max_attempts_per_channel=payload[
                "max_attempts_per_channel"
            ],
            reserved_channels=payload["reserved_channels"],
            reserved_attention_units=payload[
                "reserved_attention_units"
            ],
            budget_digest=digest_json(payload),
        )

    @property
    def remaining_channels(self) -> int:
        return self.max_total_channels - self.reserved_channels

    @property
    def remaining_attention_units(self) -> int:
        return (
            self.max_attention_units - self.reserved_attention_units
        )

    def semantic_view(self) -> dict[str, int | str]:
        return {
            "schema_version": ATTENTION_BUDGET_SCHEMA,
            "max_total_channels": self.max_total_channels,
            "max_attention_units": self.max_attention_units,
            "max_attempts_per_channel": self.max_attempts_per_channel,
            "reserved_channels": self.reserved_channels,
            "reserved_attention_units": self.reserved_attention_units,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.semantic_view(),
            "max_concurrency": self.max_concurrency,
            "budget_digest": self.budget_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionBudget":
        _exact_keys(
            value,
            {
                "schema_version", "max_total_channels",
                "max_attention_units", "max_concurrency",
                "max_attempts_per_channel", "reserved_channels",
                "reserved_attention_units", "budget_digest",
            },
            "attention budget",
        )
        if value["schema_version"] != ATTENTION_BUDGET_SCHEMA:
            raise AdaptiveAttentionError("unsupported attention budget schema")
        replayed = cls.create(
            max_total_channels=value["max_total_channels"],
            max_attention_units=value["max_attention_units"],
            max_concurrency=value["max_concurrency"],
            max_attempts_per_channel=value["max_attempts_per_channel"],
            reserved_channels=value["reserved_channels"],
            reserved_attention_units=value["reserved_attention_units"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError("attention budget content does not replay")
        return replayed


@dataclass(frozen=True, slots=True)
class ChannelTemplate:
    template_id: str
    obligation_kind: str
    role_id: str
    role_family: str
    methodology_family: str
    source_class: str
    proof_environment: str
    required_tool_classes: tuple[str, ...]
    dependency_generation: int
    closure_policy_family: str
    max_obligations: int
    attention_units: int
    template_digest: str

    @classmethod
    def create(
        cls,
        *,
        obligation_kind: str,
        role_id: str,
        role_family: str,
        methodology_family: str,
        source_class: str,
        proof_environment: str,
        required_tool_classes: Iterable[str],
        dependency_generation: int,
        closure_policy_family: str,
        max_obligations: int,
        attention_units: int,
    ) -> "ChannelTemplate":
        payload = {
            "obligation_kind": _enum(
                obligation_kind, OBLIGATION_KINDS, "obligation_kind"
            ),
            "role_id": _safe_text(role_id, "role_id"),
            "role_family": _safe_text(role_family, "role_family"),
            "methodology_family": _safe_text(
                methodology_family, "methodology_family"
            ),
            "source_class": _safe_text(
                source_class, "source_class"
            ),
            "proof_environment": _safe_text(
                proof_environment, "proof_environment"
            ),
            "required_tool_classes": list(
                _sorted_unique_text(
                    required_tool_classes,
                    "template required tool class",
                )
            ),
            "dependency_generation": _nonnegative_int(
                dependency_generation, "dependency_generation"
            ),
            "closure_policy_family": _safe_text(
                closure_policy_family, "closure_policy_family"
            ),
            "max_obligations": _positive_int(
                max_obligations, "max_obligations"
            ),
            "attention_units": _positive_int(
                attention_units, "attention_units"
            ),
        }
        template_digest = digest_json(payload)
        return cls(
            template_id="ACT-" + template_digest[:24].upper(),
            obligation_kind=payload["obligation_kind"],
            role_id=payload["role_id"],
            role_family=payload["role_family"],
            methodology_family=payload["methodology_family"],
            source_class=payload["source_class"],
            proof_environment=payload["proof_environment"],
            required_tool_classes=tuple(
                payload["required_tool_classes"]
            ),
            dependency_generation=payload["dependency_generation"],
            closure_policy_family=payload[
                "closure_policy_family"
            ],
            max_obligations=payload["max_obligations"],
            attention_units=payload["attention_units"],
            template_digest=template_digest,
        )

    def compatibility_key(self) -> tuple[Any, ...]:
        return (
            self.obligation_kind,
            self.role_family,
            self.methodology_family,
            self.source_class,
            self.proof_environment,
            self.required_tool_classes,
            self.dependency_generation,
            self.closure_policy_family,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "obligation_kind": self.obligation_kind,
            "role_id": self.role_id,
            "role_family": self.role_family,
            "methodology_family": self.methodology_family,
            "source_class": self.source_class,
            "proof_environment": self.proof_environment,
            "required_tool_classes": list(self.required_tool_classes),
            "dependency_generation": self.dependency_generation,
            "closure_policy_family": self.closure_policy_family,
            "max_obligations": self.max_obligations,
            "attention_units": self.attention_units,
            "template_digest": self.template_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ChannelTemplate":
        _exact_keys(value, cls.__dataclass_fields__, "channel template")
        replayed = cls.create(
            obligation_kind=value["obligation_kind"],
            role_id=value["role_id"],
            role_family=value["role_family"],
            methodology_family=value["methodology_family"],
            source_class=value["source_class"],
            proof_environment=value["proof_environment"],
            required_tool_classes=value["required_tool_classes"],
            dependency_generation=value["dependency_generation"],
            closure_policy_family=value["closure_policy_family"],
            max_obligations=value["max_obligations"],
            attention_units=value["attention_units"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "channel template content does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class EvidenceChannel:
    scope_digest: str
    channel_semantic_id: str
    channel_id: str
    obligation_ids: tuple[str, ...]
    evidence_slice: EvidenceSlice
    role_id: str
    role_family: str
    source_class: str
    methodology_bindings: tuple[MethodologyBinding, ...]
    graph_treatment_digest: str
    runtime_policy: RuntimeCapabilityPolicy
    independence_signature: tuple[str, ...]
    expected_output: str
    resource_reservation: ResourceReservation
    prerequisite_ids: tuple[str, ...]
    state: str
    row_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        obligation_ids: Iterable[str],
        evidence_slice: EvidenceSlice,
        role_id: str,
        role_family: str,
        source_class: str,
        methodology_bindings: Iterable[
            MethodologyBinding | Mapping[str, Any]
        ],
        graph_treatment_digest: str,
        runtime_policy: RuntimeCapabilityPolicy,
        independence_signature: Iterable[str],
        resource_reservation: ResourceReservation,
        prerequisite_ids: Iterable[str],
        state: str = "PLANNED",
    ) -> "EvidenceChannel":
        if not isinstance(evidence_slice, EvidenceSlice):
            raise TypeError("evidence_slice must be an EvidenceSlice")
        if not isinstance(
            runtime_policy, RuntimeCapabilityPolicy
        ):
            raise TypeError(
                "runtime_policy must be a RuntimeCapabilityPolicy"
            )
        if not isinstance(resource_reservation, ResourceReservation):
            raise TypeError(
                "resource_reservation must be a ResourceReservation"
            )
        raw_obligation_ids = tuple(
            _canonical_id(value, "channel obligation_id")
            for value in obligation_ids
        )
        if len(set(raw_obligation_ids)) != len(raw_obligation_ids):
            raise AdaptiveAttentionError(
                "channel obligation_ids must be unique"
            )
        normalized_obligation_ids = tuple(sorted(raw_obligation_ids))
        if not normalized_obligation_ids:
            raise AdaptiveAttentionError(
                "channel obligation_ids must not be empty"
            )
        methods = tuple(
            sorted(
                {
                    MethodologyBinding.create(value)
                    for value in methodology_bindings
                },
                key=_row_json,
            )
        )
        signature = tuple(
            _safe_text(value, "independence signature component")
            for value in independence_signature
        )
        if len(signature) < 5:
            raise AdaptiveAttentionError(
                "independence_signature needs role, methodology, source, "
                "proof environment, and slice identity"
            )
        semantic_payload = {
            "schema": EVIDENCE_CHANNEL_SCHEMA,
            "scope_digest": scope.scope_digest,
            "obligation_ids": list(normalized_obligation_ids),
            "evidence_slice_id": evidence_slice.slice_id,
            "role_id": _safe_text(role_id, "role_id"),
            "role_family": _safe_text(role_family, "role_family"),
            "source_class": _safe_text(
                source_class, "source_class"
            ),
            "methodology_binding_digests": [
                value.binding_digest for value in methods
            ],
            "graph_treatment_digest": _sha256(
                graph_treatment_digest, "graph_treatment_digest"
            ),
            "independence_signature": list(signature),
            "resource_reservation_digest": (
                resource_reservation.reservation_digest
            ),
            "prerequisite_ids": list(
                _sorted_unique_text(
                    prerequisite_ids, "prerequisite identity"
                )
            ),
        }
        semantic_id = "ACHS-" + digest_json(semantic_payload)[:24].upper()
        expected_output = (
            f"attention_{semantic_id.lower().replace('-', '_')}.json"
        )
        runtime_payload = {
            **semantic_payload,
            "channel_semantic_id": semantic_id,
            "expected_output": expected_output,
            "runtime_policy_digest": (
                runtime_policy.runtime_policy_digest
            ),
        }
        channel_id = "ACH-" + digest_json(runtime_payload)[:24].upper()
        row_payload = {
            "schema_version": EVIDENCE_CHANNEL_SCHEMA,
            "scope_digest": scope.scope_digest,
            "channel_semantic_id": semantic_id,
            "channel_id": channel_id,
            "obligation_ids": list(normalized_obligation_ids),
            "evidence_slice": evidence_slice.to_dict(),
            "role_id": semantic_payload["role_id"],
            "role_family": semantic_payload["role_family"],
            "source_class": semantic_payload["source_class"],
            "methodology_bindings": [
                value.to_dict() for value in methods
            ],
            "graph_treatment_digest": semantic_payload[
                "graph_treatment_digest"
            ],
            "runtime_policy": runtime_policy.to_dict(),
            "independence_signature": list(signature),
            "expected_output": expected_output,
            "resource_reservation": resource_reservation.to_dict(),
            "prerequisite_ids": semantic_payload["prerequisite_ids"],
            "state": _enum(state, CHANNEL_STATES, "channel state"),
        }
        return cls(
            scope_digest=scope.scope_digest,
            channel_semantic_id=semantic_id,
            channel_id=channel_id,
            obligation_ids=normalized_obligation_ids,
            evidence_slice=evidence_slice,
            role_id=semantic_payload["role_id"],
            role_family=semantic_payload["role_family"],
            source_class=semantic_payload["source_class"],
            methodology_bindings=methods,
            graph_treatment_digest=semantic_payload[
                "graph_treatment_digest"
            ],
            runtime_policy=runtime_policy,
            independence_signature=signature,
            expected_output=expected_output,
            resource_reservation=resource_reservation,
            prerequisite_ids=tuple(
                semantic_payload["prerequisite_ids"]
            ),
            state=row_payload["state"],
            row_digest=digest_json(row_payload),
        )

    @property
    def evidence_slice_id(self) -> str:
        return self.evidence_slice.slice_id

    def semantic_view(self) -> dict[str, Any]:
        return {
            "channel_semantic_id": self.channel_semantic_id,
            "obligation_ids": list(self.obligation_ids),
            "evidence_slice_id": self.evidence_slice.slice_id,
            "role_id": self.role_id,
            "role_family": self.role_family,
            "source_class": self.source_class,
            "methodology_binding_digests": [
                value.binding_digest
                for value in self.methodology_bindings
            ],
            "graph_treatment_digest": self.graph_treatment_digest,
            "independence_signature": list(
                self.independence_signature
            ),
            "expected_output": self.expected_output,
            "resource_reservation": (
                self.resource_reservation.to_dict()
            ),
            "prerequisite_ids": list(self.prerequisite_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": EVIDENCE_CHANNEL_SCHEMA,
            "scope_digest": self.scope_digest,
            "channel_semantic_id": self.channel_semantic_id,
            "channel_id": self.channel_id,
            "obligation_ids": list(self.obligation_ids),
            "evidence_slice": self.evidence_slice.to_dict(),
            "role_id": self.role_id,
            "role_family": self.role_family,
            "source_class": self.source_class,
            "methodology_bindings": [
                value.to_dict() for value in self.methodology_bindings
            ],
            "graph_treatment_digest": self.graph_treatment_digest,
            "runtime_policy": self.runtime_policy.to_dict(),
            "independence_signature": list(
                self.independence_signature
            ),
            "expected_output": self.expected_output,
            "resource_reservation": (
                self.resource_reservation.to_dict()
            ),
            "prerequisite_ids": list(self.prerequisite_ids),
            "state": self.state,
            "row_digest": self.row_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceChannel":
        expected = {
            "schema_version", "scope_digest", "channel_semantic_id",
            "channel_id", "obligation_ids", "evidence_slice", "role_id",
            "role_family", "source_class", "methodology_bindings",
            "graph_treatment_digest", "runtime_policy",
            "independence_signature", "expected_output",
            "resource_reservation", "prerequisite_ids", "state",
            "row_digest",
        }
        _exact_keys(value, expected, "evidence channel")
        if value["schema_version"] != EVIDENCE_CHANNEL_SCHEMA:
            raise AdaptiveAttentionError("unsupported evidence channel schema")
        evidence_slice = EvidenceSlice.from_dict(value["evidence_slice"])
        runtime = RuntimeCapabilityPolicy.from_dict(value["runtime_policy"])
        reservation = ResourceReservation.from_dict(
            value["resource_reservation"]
        )
        methods = tuple(
            MethodologyBinding.from_dict(item)
            for item in value["methodology_bindings"]
        )
        obligation_ids = tuple(
            sorted(
                _canonical_id(item, "channel obligation_id")
                for item in value["obligation_ids"]
            )
        )
        if len(set(obligation_ids)) != len(obligation_ids):
            raise AdaptiveAttentionError(
                "channel obligation_ids must be unique"
            )
        signature = tuple(
            _safe_text(item, "independence signature component")
            for item in value["independence_signature"]
        )
        semantic_payload = {
            "schema": EVIDENCE_CHANNEL_SCHEMA,
            "scope_digest": _sha256(value["scope_digest"], "scope_digest"),
            "obligation_ids": list(obligation_ids),
            "evidence_slice_id": evidence_slice.slice_id,
            "role_id": _safe_text(value["role_id"], "role_id"),
            "role_family": _safe_text(value["role_family"], "role_family"),
            "source_class": _safe_text(value["source_class"], "source_class"),
            "methodology_binding_digests": [
                item.binding_digest for item in methods
            ],
            "graph_treatment_digest": _sha256(
                value["graph_treatment_digest"], "graph_treatment_digest"
            ),
            "independence_signature": list(signature),
            "resource_reservation_digest": reservation.reservation_digest,
            "prerequisite_ids": list(
                _sorted_unique_text(
                    value["prerequisite_ids"], "prerequisite identity"
                )
            ),
        }
        semantic_id = "ACHS-" + digest_json(semantic_payload)[:24].upper()
        expected_output = (
            f"attention_{semantic_id.lower().replace('-', '_')}.json"
        )
        runtime_payload = {
            **semantic_payload,
            "channel_semantic_id": semantic_id,
            "expected_output": expected_output,
            "runtime_policy_digest": runtime.runtime_policy_digest,
        }
        channel_id = "ACH-" + digest_json(runtime_payload)[:24].upper()
        if (
            value["channel_semantic_id"] != semantic_id
            or value["channel_id"] != channel_id
            or value["expected_output"] != expected_output
        ):
            raise AdaptiveAttentionError(
                "evidence channel identity does not replay"
            )
        row_payload = dict(value)
        row_digest = row_payload.pop("row_digest")
        if digest_json(row_payload) != _sha256(row_digest, "row_digest"):
            raise AdaptiveAttentionError(
                "evidence channel content does not replay"
            )
        replayed = cls(
            scope_digest=semantic_payload["scope_digest"],
            channel_semantic_id=semantic_id,
            channel_id=channel_id,
            obligation_ids=obligation_ids,
            evidence_slice=evidence_slice,
            role_id=semantic_payload["role_id"],
            role_family=semantic_payload["role_family"],
            source_class=semantic_payload["source_class"],
            methodology_bindings=methods,
            graph_treatment_digest=semantic_payload[
                "graph_treatment_digest"
            ],
            runtime_policy=runtime,
            independence_signature=signature,
            expected_output=expected_output,
            resource_reservation=reservation,
            prerequisite_ids=tuple(semantic_payload["prerequisite_ids"]),
            state=_enum(value["state"], CHANNEL_STATES, "channel state"),
            row_digest=row_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "evidence channel canonical form does not replay"
            )
        return replayed


def channels_have_independent_evidence(
    left: EvidenceChannel, right: EvidenceChannel
) -> bool:
    """Return whether two completed channels qualify for diversity credit."""

    if left.expected_output == right.expected_output:
        return False
    if left.evidence_slice_id == right.evidence_slice_id:
        return False
    semantic_left = left.independence_signature[:4]
    semantic_right = right.independence_signature[:4]
    differences = sum(
        first != second
        for first, second in zip(semantic_left, semantic_right)
    )
    differences += (
        left.runtime_policy.provider_family
        != right.runtime_policy.provider_family
    )
    differences += (
        left.runtime_policy.model_capability_tier
        != right.runtime_policy.model_capability_tier
    )
    return differences >= 2


@dataclass(frozen=True, order=True, slots=True)
class AttentionDebt:
    obligation_id: str
    phase: str
    dependency_generation: int
    provider: str
    reason_code: str
    failed_channel_ids: tuple[str, ...]
    attempts: int
    reserved_attention_units: int
    consumed_attention_units: int
    affected_identities: tuple[str, ...]
    clean_assurance_forbidden: bool
    clearing_condition: str
    debt_digest: str

    @classmethod
    def create(
        cls,
        *,
        obligation_id: str,
        phase: str,
        dependency_generation: int,
        provider: str,
        reason_code: str,
        failed_channel_ids: Iterable[str] = (),
        attempts: int = 0,
        reserved_attention_units: int = 0,
        consumed_attention_units: int = 0,
        affected_identities: Iterable[str] = (),
        clean_assurance_forbidden: bool = True,
        clearing_condition: str,
    ) -> "AttentionDebt":
        payload = {
            "schema_version": ATTENTION_DEBT_SCHEMA,
            "obligation_id": _canonical_id(
                obligation_id, "debt obligation_id"
            ),
            "phase": _safe_text(phase, "debt phase"),
            "dependency_generation": _nonnegative_int(
                dependency_generation, "debt dependency_generation"
            ),
            "provider": _safe_text(provider, "debt provider"),
            "reason_code": _safe_text(
                reason_code, "debt reason_code"
            ).upper(),
            "failed_channel_ids": list(
                _sorted_unique_text(
                    failed_channel_ids, "failed channel identity"
                )
            ),
            "attempts": _nonnegative_int(attempts, "debt attempts"),
            "reserved_attention_units": _nonnegative_int(
                reserved_attention_units,
                "debt reserved_attention_units",
            ),
            "consumed_attention_units": _nonnegative_int(
                consumed_attention_units,
                "debt consumed_attention_units",
            ),
            "affected_identities": list(
                _sorted_unique_text(
                    affected_identities, "affected identity"
                )
            ),
            "clean_assurance_forbidden": _boolean(
                clean_assurance_forbidden,
                "clean_assurance_forbidden",
            ),
            "clearing_condition": _text(
                clearing_condition, "debt clearing_condition"
            ),
        }
        return cls(
            obligation_id=payload["obligation_id"],
            phase=payload["phase"],
            dependency_generation=payload[
                "dependency_generation"
            ],
            provider=payload["provider"],
            reason_code=payload["reason_code"],
            failed_channel_ids=tuple(payload["failed_channel_ids"]),
            attempts=payload["attempts"],
            reserved_attention_units=payload[
                "reserved_attention_units"
            ],
            consumed_attention_units=payload[
                "consumed_attention_units"
            ],
            affected_identities=tuple(
                payload["affected_identities"]
            ),
            clean_assurance_forbidden=payload[
                "clean_assurance_forbidden"
            ],
            clearing_condition=payload["clearing_condition"],
            debt_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_DEBT_SCHEMA,
            "obligation_id": self.obligation_id,
            "phase": self.phase,
            "dependency_generation": self.dependency_generation,
            "provider": self.provider,
            "reason_code": self.reason_code,
            "failed_channel_ids": list(self.failed_channel_ids),
            "attempts": self.attempts,
            "reserved_attention_units": self.reserved_attention_units,
            "consumed_attention_units": self.consumed_attention_units,
            "affected_identities": list(self.affected_identities),
            "clean_assurance_forbidden": (
                self.clean_assurance_forbidden
            ),
            "clearing_condition": self.clearing_condition,
            "debt_digest": self.debt_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionDebt":
        _exact_keys(
            value,
            {
                "schema_version", "obligation_id", "phase",
                "dependency_generation", "provider", "reason_code",
                "failed_channel_ids", "attempts",
                "reserved_attention_units", "consumed_attention_units",
                "affected_identities", "clean_assurance_forbidden",
                "clearing_condition", "debt_digest",
            },
            "attention debt",
        )
        if value["schema_version"] != ATTENTION_DEBT_SCHEMA:
            raise AdaptiveAttentionError("unsupported attention debt schema")
        replayed = cls.create(
            obligation_id=value["obligation_id"],
            phase=value["phase"],
            dependency_generation=value["dependency_generation"],
            provider=value["provider"],
            reason_code=value["reason_code"],
            failed_channel_ids=value["failed_channel_ids"],
            attempts=value["attempts"],
            reserved_attention_units=value["reserved_attention_units"],
            consumed_attention_units=value["consumed_attention_units"],
            affected_identities=value["affected_identities"],
            clean_assurance_forbidden=value[
                "clean_assurance_forbidden"
            ],
            clearing_condition=value["clearing_condition"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError("attention debt content does not replay")
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionDenominator:
    scope_digest: str
    coverage_kind: str
    obligations: tuple[AttentionObligation, ...]
    provider_debt_ids: tuple[str, ...]
    exact_obligation_count: int | None
    known_lower_bound_count: int
    denominator_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        coverage_kind: str,
        obligations: Iterable[AttentionObligation],
        provider_debt_ids: Iterable[str] = (),
    ) -> "AttentionDenominator":
        checked_rows = []
        for row in obligations:
            if not isinstance(row, AttentionObligation):
                raise TypeError(
                    "denominator obligation has an invalid type"
                )
            if AttentionObligation.from_dict(row.to_dict()) != row:
                raise AdaptiveAttentionError(
                    "denominator obligation does not replay"
                )
            checked_rows.append(row)
        rows = tuple(
            sorted(checked_rows, key=lambda row: row.obligation_id)
        )
        if len({row.obligation_id for row in rows}) != len(rows):
            raise AdaptiveAttentionError(
                "duplicate obligation identity in denominator"
            )
        if any(
            (
                row.snapshot_digest,
                row.pipeline,
                row.mode,
                row.ecosystem,
                row.phase,
                row.dependency_generation,
            )
            != (
                scope.snapshot_digest,
                scope.pipeline,
                scope.mode,
                scope.ecosystem,
                scope.phase,
                scope.dependency_generation,
            )
            for row in rows
        ):
            raise AdaptiveAttentionError(
                "denominator contains an obligation from another scope"
            )
        coverage = _enum(
            coverage_kind, COVERAGE_KINDS, "coverage_kind"
        )
        provider_ids = tuple(
            sorted(
                {
                    _canonical_id(value, "provider debt identity")
                    for value in provider_debt_ids
                }
            )
        )
        obligation_ids = {row.obligation_id for row in rows}
        if not set(provider_ids) <= obligation_ids:
            raise AdaptiveAttentionError(
                "provider debt identity is outside the denominator"
            )
        payload = {
            "schema_version": ATTENTION_DENOMINATOR_SCHEMA,
            "scope_digest": scope.scope_digest,
            "coverage_kind": coverage,
            "obligation_row_digests": [
                row.row_digest for row in rows
            ],
            "provider_debt_ids": list(provider_ids),
            "exact_obligation_count": (
                len(rows) if coverage == "EXACT" else None
            ),
            "known_lower_bound_count": len(rows),
        }
        return cls(
            scope_digest=scope.scope_digest,
            coverage_kind=coverage,
            obligations=rows,
            provider_debt_ids=provider_ids,
            exact_obligation_count=payload["exact_obligation_count"],
            known_lower_bound_count=len(rows),
            denominator_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_DENOMINATOR_SCHEMA,
            "scope_digest": self.scope_digest,
            "coverage_kind": self.coverage_kind,
            "obligations": [
                row.to_dict() for row in self.obligations
            ],
            "provider_debt_ids": list(self.provider_debt_ids),
            "exact_obligation_count": self.exact_obligation_count,
            "known_lower_bound_count": self.known_lower_bound_count,
            "denominator_digest": self.denominator_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionDenominator":
        _exact_keys(
            value,
            {
                "schema_version", "scope_digest", "coverage_kind",
                "obligations", "provider_debt_ids",
                "exact_obligation_count", "known_lower_bound_count",
                "denominator_digest",
            },
            "attention denominator",
        )
        if value["schema_version"] != ATTENTION_DENOMINATOR_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention denominator schema"
            )
        rows = tuple(
            AttentionObligation.from_dict(item)
            for item in value["obligations"]
        )
        if len({row.obligation_id for row in rows}) != len(rows):
            raise AdaptiveAttentionError(
                "attention denominator contains duplicate rows"
            )
        if tuple(
            sorted(rows, key=lambda row: row.obligation_id)
        ) != rows:
            raise AdaptiveAttentionError(
                "attention denominator rows are not canonical"
            )
        coverage = _enum(
            value["coverage_kind"], COVERAGE_KINDS, "coverage_kind"
        )
        exact_count = value["exact_obligation_count"]
        if exact_count is not None:
            exact_count = _nonnegative_int(
                exact_count, "exact_obligation_count"
            )
        lower_count = _nonnegative_int(
            value["known_lower_bound_count"],
            "known_lower_bound_count",
        )
        provider_ids = tuple(
            _canonical_id(item, "provider debt identity")
            for item in value["provider_debt_ids"]
        )
        if provider_ids != tuple(sorted(set(provider_ids))):
            raise AdaptiveAttentionError(
                "provider debt identities are not canonical and unique"
            )
        if not set(provider_ids) <= {
            row.obligation_id for row in rows
        }:
            raise AdaptiveAttentionError(
                "provider debt identity is outside the denominator"
            )
        payload = {
            "schema_version": ATTENTION_DENOMINATOR_SCHEMA,
            "scope_digest": _sha256(
                value["scope_digest"], "scope_digest"
            ),
            "coverage_kind": coverage,
            "obligation_row_digests": [
                row.row_digest for row in rows
            ],
            "provider_debt_ids": list(provider_ids),
            "exact_obligation_count": exact_count,
            "known_lower_bound_count": lower_count,
        }
        denominator_digest = _sha256(
            value["denominator_digest"], "denominator_digest"
        )
        if digest_json(payload) != denominator_digest:
            raise AdaptiveAttentionError(
                "attention denominator content does not replay"
            )
        if lower_count != len(rows) or (
            coverage == "EXACT" and exact_count != len(rows)
        ) or (coverage != "EXACT" and exact_count is not None):
            raise AdaptiveAttentionError(
                "attention denominator count semantics do not replay"
            )
        replayed = cls(
            scope_digest=payload["scope_digest"],
            coverage_kind=coverage,
            obligations=rows,
            provider_debt_ids=provider_ids,
            exact_obligation_count=exact_count,
            known_lower_bound_count=lower_count,
            denominator_digest=denominator_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention denominator canonical form does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionRoster:
    scope_digest: str
    denominator_digest: str
    denominator_obligation_ids: tuple[str, ...]
    denominator_obligation_rows: tuple[tuple[str, str], ...]
    budget_policy_digest: str
    max_attempts_per_channel: int
    graph_treatment_digest: str
    channels: tuple[EvidenceChannel, ...]
    debt: tuple[AttentionDebt, ...]
    total_reserved_attention_units: int
    total_reserved_channels: int
    semantic_roster_digest: str
    roster_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        denominator: AttentionDenominator,
        budget_policy_digest: str,
        max_attempts_per_channel: int,
        graph_treatment_digest: str,
        channels: Iterable[EvidenceChannel],
        debt: Iterable[AttentionDebt],
    ) -> "AttentionRoster":
        if AttentionDenominator.from_dict(
            denominator.to_dict()
        ) != denominator:
            raise AdaptiveAttentionError(
                "roster denominator does not replay"
            )
        channel_rows = tuple(
            sorted(channels, key=lambda row: row.channel_id)
        )
        for row in channel_rows:
            if EvidenceChannel.from_dict(row.to_dict()) != row:
                raise AdaptiveAttentionError(
                    "roster channel does not replay"
                )
            if row.scope_digest != scope.scope_digest:
                raise AdaptiveAttentionError(
                    "roster channel is outside the exact scope"
                )
        if len({row.channel_id for row in channel_rows}) != len(
            channel_rows
        ):
            raise AdaptiveAttentionError(
                "duplicate channel identity in roster"
            )
        semantic_ids = [
            row.channel_semantic_id for row in channel_rows
        ]
        if len(set(semantic_ids)) != len(semantic_ids):
            raise AdaptiveAttentionError(
                "duplicate semantic channel identity in roster"
            )
        debt_rows = tuple(
            sorted(
                debt, key=lambda row: (row.obligation_id, row.reason_code)
            )
        )
        for row in debt_rows:
            if AttentionDebt.from_dict(row.to_dict()) != row:
                raise AdaptiveAttentionError(
                    "roster debt does not replay"
                )
        obligation_ids = tuple(
            row.obligation_id for row in denominator.obligations
        )
        denominator_id_set = set(obligation_ids)
        scheduled_ids = [
            obligation_id
            for channel in channel_rows
            for obligation_id in channel.obligation_ids
        ]
        debt_ids = [row.obligation_id for row in debt_rows]
        if (
            len(set(scheduled_ids)) != len(scheduled_ids)
            or len(set(debt_ids)) != len(debt_ids)
        ):
            raise AdaptiveAttentionError(
                "roster contains duplicate obligation work rows"
            )
        if set(scheduled_ids) & set(debt_ids):
            raise AdaptiveAttentionError(
                "roster obligation cannot be both scheduled and debt"
            )
        if not (
            set(scheduled_ids) | set(debt_ids)
        ) <= denominator_id_set:
            raise AdaptiveAttentionError(
                "roster work is outside the denominator"
            )
        obligation_rows = tuple(
            (row.obligation_id, row.row_digest)
            for row in denominator.obligations
        )
        semantic_payload = {
            "schema_version": ATTENTION_ROSTER_SCHEMA,
            "scope_digest": scope.scope_digest,
            "denominator_digest": denominator.denominator_digest,
            "denominator_obligation_ids": list(obligation_ids),
            "denominator_obligation_rows": [
                [obligation_id, row_digest]
                for obligation_id, row_digest in obligation_rows
            ],
            "budget_policy_digest": _sha256(
                budget_policy_digest, "budget_policy_digest"
            ),
            "max_attempts_per_channel": _positive_int(
                max_attempts_per_channel,
                "max_attempts_per_channel",
            ),
            "graph_treatment_digest": _sha256(
                graph_treatment_digest, "graph_treatment_digest"
            ),
            "channels": [
                row.semantic_view()
                for row in sorted(
                    channel_rows,
                    key=lambda item: item.channel_semantic_id,
                )
            ],
            "debt_digests": [
                row.debt_digest for row in debt_rows
            ],
            "total_reserved_attention_units": sum(
                row.resource_reservation.attention_units
                for row in channel_rows
            ),
            "total_reserved_channels": len(channel_rows),
        }
        semantic_digest = digest_json(semantic_payload)
        concrete_payload = {
            **semantic_payload,
            "semantic_roster_digest": semantic_digest,
            "channel_ids": [
                row.channel_id for row in channel_rows
            ],
            "channel_row_digests": [
                row.row_digest for row in channel_rows
            ],
        }
        return cls(
            scope_digest=scope.scope_digest,
            denominator_digest=denominator.denominator_digest,
            denominator_obligation_ids=obligation_ids,
            denominator_obligation_rows=obligation_rows,
            budget_policy_digest=semantic_payload[
                "budget_policy_digest"
            ],
            max_attempts_per_channel=semantic_payload[
                "max_attempts_per_channel"
            ],
            graph_treatment_digest=semantic_payload[
                "graph_treatment_digest"
            ],
            channels=channel_rows,
            debt=debt_rows,
            total_reserved_attention_units=semantic_payload[
                "total_reserved_attention_units"
            ],
            total_reserved_channels=len(channel_rows),
            semantic_roster_digest=semantic_digest,
            roster_digest=digest_json(concrete_payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_ROSTER_SCHEMA,
            "scope_digest": self.scope_digest,
            "denominator_digest": self.denominator_digest,
            "denominator_obligation_ids": list(
                self.denominator_obligation_ids
            ),
            "denominator_obligation_rows": [
                [obligation_id, row_digest]
                for obligation_id, row_digest
                in self.denominator_obligation_rows
            ],
            "budget_policy_digest": self.budget_policy_digest,
            "max_attempts_per_channel": (
                self.max_attempts_per_channel
            ),
            "graph_treatment_digest": self.graph_treatment_digest,
            "channels": [row.to_dict() for row in self.channels],
            "debt": [row.to_dict() for row in self.debt],
            "total_reserved_attention_units": (
                self.total_reserved_attention_units
            ),
            "total_reserved_channels": self.total_reserved_channels,
            "semantic_roster_digest": self.semantic_roster_digest,
            "roster_digest": self.roster_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionRoster":
        _exact_keys(
            value,
            {
                "schema_version", "scope_digest", "denominator_digest",
                "denominator_obligation_ids",
                "denominator_obligation_rows", "budget_policy_digest",
                "max_attempts_per_channel",
                "graph_treatment_digest", "channels", "debt",
                "total_reserved_attention_units",
                "total_reserved_channels", "semantic_roster_digest",
                "roster_digest",
            },
            "attention roster",
        )
        if value["schema_version"] != ATTENTION_ROSTER_SCHEMA:
            raise AdaptiveAttentionError("unsupported attention roster schema")
        roster = cls(
            scope_digest=_sha256(value["scope_digest"], "scope_digest"),
            denominator_digest=_sha256(
                value["denominator_digest"], "denominator_digest"
            ),
            denominator_obligation_ids=tuple(
                _canonical_id(item, "denominator obligation identity")
                for item in value["denominator_obligation_ids"]
            ),
            denominator_obligation_rows=tuple(
                (
                    _canonical_id(
                        item[0], "denominator obligation identity"
                    ),
                    _sha256(item[1], "denominator obligation row digest"),
                )
                for item in value["denominator_obligation_rows"]
                if isinstance(item, list) and len(item) == 2
            ),
            budget_policy_digest=_sha256(
                value["budget_policy_digest"], "budget_policy_digest"
            ),
            max_attempts_per_channel=_positive_int(
                value["max_attempts_per_channel"],
                "max_attempts_per_channel",
            ),
            graph_treatment_digest=_sha256(
                value["graph_treatment_digest"],
                "graph_treatment_digest",
            ),
            channels=tuple(
                EvidenceChannel.from_dict(item)
                for item in value["channels"]
            ),
            debt=tuple(
                AttentionDebt.from_dict(item) for item in value["debt"]
            ),
            total_reserved_attention_units=_nonnegative_int(
                value["total_reserved_attention_units"],
                "total_reserved_attention_units",
            ),
            total_reserved_channels=_nonnegative_int(
                value["total_reserved_channels"],
                "total_reserved_channels",
            ),
            semantic_roster_digest=_sha256(
                value["semantic_roster_digest"],
                "semantic_roster_digest",
            ),
            roster_digest=_sha256(value["roster_digest"], "roster_digest"),
        )
        if roster.denominator_obligation_ids != tuple(
            sorted(set(roster.denominator_obligation_ids))
        ):
            raise AdaptiveAttentionError(
                "roster denominator identities are not canonical and unique"
            )
        if tuple(
            obligation_id
            for obligation_id, _row_digest
            in roster.denominator_obligation_rows
        ) != roster.denominator_obligation_ids:
            raise AdaptiveAttentionError(
                "roster denominator row bindings differ from identities"
            )
        if roster.channels != tuple(
            sorted(roster.channels, key=lambda row: row.channel_id)
        ):
            raise AdaptiveAttentionError(
                "roster channels are not canonical"
            )
        if len({row.channel_id for row in roster.channels}) != len(
            roster.channels
        ):
            raise AdaptiveAttentionError(
                "roster channel identities are not unique"
            )
        if len(
            {row.channel_semantic_id for row in roster.channels}
        ) != len(roster.channels):
            raise AdaptiveAttentionError(
                "roster semantic channel identities are not unique"
            )
        if roster.debt != tuple(
            sorted(
                roster.debt,
                key=lambda row: (row.obligation_id, row.reason_code),
            )
        ):
            raise AdaptiveAttentionError("roster debt is not canonical")
        effective_roster_digest(roster, ())
        if roster.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention roster content does not replay"
            )
        return roster


def effective_roster_digest(
    base_roster: AttentionRoster,
    amendments: Sequence["RosterAmendment"],
) -> str:
    if not isinstance(base_roster, AttentionRoster):
        raise TypeError("base_roster must be an AttentionRoster")
    for channel in base_roster.channels:
        channel_payload = channel.to_dict()
        channel_digest = channel_payload.pop("row_digest")
        if digest_json(channel_payload) != channel_digest:
            raise AdaptiveAttentionError(
                "base roster contains a stale channel row digest"
            )
    for debt in base_roster.debt:
        debt_payload = debt.to_dict()
        debt_digest = debt_payload.pop("debt_digest")
        if digest_json(debt_payload) != debt_digest:
            raise AdaptiveAttentionError(
                "base roster contains a stale debt digest"
            )
    if base_roster.denominator_obligation_ids != tuple(
        sorted(set(base_roster.denominator_obligation_ids))
    ):
        raise AdaptiveAttentionError(
            "base roster denominator identities are not canonical and unique"
        )
    if base_roster.channels != tuple(
        sorted(base_roster.channels, key=lambda row: row.channel_id)
    ):
        raise AdaptiveAttentionError("base roster channels are not canonical")
    if len({row.channel_id for row in base_roster.channels}) != len(
        base_roster.channels
    ):
        raise AdaptiveAttentionError(
            "base roster channel identities are not unique"
        )
    if len(
        {row.channel_semantic_id for row in base_roster.channels}
    ) != len(base_roster.channels):
        raise AdaptiveAttentionError(
            "base roster semantic channel identities are not unique"
        )
    if base_roster.debt != tuple(
        sorted(
            base_roster.debt,
            key=lambda row: (row.obligation_id, row.reason_code),
        )
    ):
        raise AdaptiveAttentionError("base roster debt is not canonical")
    if base_roster.total_reserved_channels != len(base_roster.channels):
        raise AdaptiveAttentionError("base roster channel count is stale")
    if base_roster.total_reserved_attention_units != sum(
        row.resource_reservation.attention_units
        for row in base_roster.channels
    ):
        raise AdaptiveAttentionError(
            "base roster attention-unit total is stale"
        )
    semantic_payload = {
        "schema_version": ATTENTION_ROSTER_SCHEMA,
        "scope_digest": base_roster.scope_digest,
        "denominator_digest": base_roster.denominator_digest,
        "denominator_obligation_ids": list(
            base_roster.denominator_obligation_ids
        ),
        "denominator_obligation_rows": [
            [obligation_id, row_digest]
            for obligation_id, row_digest
            in base_roster.denominator_obligation_rows
        ],
        "budget_policy_digest": base_roster.budget_policy_digest,
        "max_attempts_per_channel": (
            base_roster.max_attempts_per_channel
        ),
        "graph_treatment_digest": base_roster.graph_treatment_digest,
        "channels": [
            row.semantic_view()
            for row in sorted(
                base_roster.channels,
                key=lambda item: item.channel_semantic_id,
            )
        ],
        "debt_digests": [
            row.debt_digest for row in base_roster.debt
        ],
        "total_reserved_attention_units": (
            base_roster.total_reserved_attention_units
        ),
        "total_reserved_channels": base_roster.total_reserved_channels,
    }
    semantic_digest = digest_json(semantic_payload)
    concrete_payload = {
        **semantic_payload,
        "semantic_roster_digest": semantic_digest,
        "channel_ids": [
            row.channel_id for row in base_roster.channels
        ],
        "channel_row_digests": [
            row.row_digest for row in base_roster.channels
        ],
    }
    if (
        semantic_digest != base_roster.semantic_roster_digest
        or digest_json(concrete_payload) != base_roster.roster_digest
    ):
        raise AdaptiveAttentionError(
            "base roster content does not replay"
        )
    current = base_roster.roster_digest
    expected_sequence = 1
    known_rows = dict(base_roster.denominator_obligation_rows)
    if tuple(known_rows) != base_roster.denominator_obligation_ids:
        raise AdaptiveAttentionError(
            "base roster denominator row bindings are stale"
        )
    active_channels = {
        row.channel_id: row for row in base_roster.channels
    }
    active_semantic_ids = {
        row.channel_semantic_id: row.channel_id
        for row in base_roster.channels
    }
    active_debts = {
        row.debt_digest: row for row in base_roster.debt
    }
    for amendment in amendments:
        if amendment.sequence != expected_sequence:
            raise AdaptiveAttentionError(
                "roster amendment sequence is missing or reordered"
            )
        if amendment.prior_effective_roster_digest != current:
            raise AdaptiveAttentionError(
                "roster amendment chain is forked or torn"
            )
        try:
            replayed = RosterAmendment.create(
                sequence=amendment.sequence,
                prior_effective_roster_digest=(
                    amendment.prior_effective_roster_digest
                ),
                triggering_event_digest=amendment.triggering_event_digest,
                obligation_operations=(
                    amendment.obligation_operations
                ),
                new_channels=amendment.new_channels,
                uncovered_debt=amendment.uncovered_debt,
            )
        except (AdaptiveAttentionError, TypeError) as exc:
            raise AdaptiveAttentionError(
                "roster amendment content does not replay"
            ) from exc
        if replayed != amendment:
            raise AdaptiveAttentionError(
                "roster amendment content does not replay"
            )
        for operation in amendment.obligation_operations:
            prior_digest = known_rows.get(operation.obligation_id)
            if operation.operation == "NEW":
                if prior_digest is not None:
                    raise AdaptiveAttentionError(
                        "NEW amendment operation repeats an obligation"
                    )
                if (
                    operation.superseded_channel_ids
                    or operation.cleared_debt_digests
                ):
                    raise AdaptiveAttentionError(
                        "NEW amendment operation cannot retire prior work"
                    )
            else:
                if prior_digest != operation.prior_row_digest:
                    raise AdaptiveAttentionError(
                        "amendment prior obligation row is stale"
                    )
                expected_channels = {
                    channel_id
                    for channel_id, channel in active_channels.items()
                    if operation.obligation_id
                    in channel.obligation_ids
                }
                expected_debt = {
                    debt_digest
                    for debt_digest, debt in active_debts.items()
                    if debt.obligation_id == operation.obligation_id
                }
                if set(
                    operation.superseded_channel_ids
                ) != expected_channels:
                    raise AdaptiveAttentionError(
                        "amendment does not supersede the exact prior "
                        "obligation channels"
                    )
                if set(
                    operation.cleared_debt_digests
                ) != expected_debt:
                    raise AdaptiveAttentionError(
                        "amendment does not clear the exact prior "
                        "obligation debt"
                    )
                if not expected_channels and not expected_debt:
                    raise AdaptiveAttentionError(
                        "amendment retries an obligation without active work"
                    )
            known_rows[operation.obligation_id] = (
                operation.resulting_row_digest
            )
        expected_new_ids = tuple(
            operation.obligation_id
            for operation in amendment.obligation_operations
            if operation.operation == "NEW"
        )
        if amendment.new_obligation_ids != expected_new_ids:
            raise AdaptiveAttentionError(
                "amendment NEW identities differ from operations"
            )
        missing_superseded = set(
            amendment.superseded_channel_ids
        ) - set(active_channels)
        if missing_superseded:
            raise AdaptiveAttentionError(
                "amendment supersedes an inactive channel"
            )
        for channel_id in amendment.superseded_channel_ids:
            old_channel = active_channels.pop(channel_id)
            active_semantic_ids.pop(
                old_channel.channel_semantic_id, None
            )
        missing_cleared = set(
            amendment.cleared_debt_digests
        ) - set(active_debts)
        if missing_cleared:
            raise AdaptiveAttentionError(
                "amendment clears an inactive debt row"
            )
        for debt_digest in amendment.cleared_debt_digests:
            active_debts.pop(debt_digest)
        for channel in amendment.new_channels:
            if channel.scope_digest != base_roster.scope_digest:
                raise AdaptiveAttentionError(
                    "amendment channel is outside the base scope"
                )
            if channel.channel_id in active_channels:
                raise AdaptiveAttentionError(
                    "roster amendment repeats an active channel identity"
                )
            if channel.channel_semantic_id in active_semantic_ids:
                raise AdaptiveAttentionError(
                    "roster amendment repeats an active semantic channel"
                )
            active_channels[channel.channel_id] = channel
            active_semantic_ids[
                channel.channel_semantic_id
            ] = channel.channel_id
        for debt in amendment.uncovered_debt:
            if debt.debt_digest in active_debts:
                raise AdaptiveAttentionError(
                    "roster amendment repeats an active debt row"
                )
            active_debts[debt.debt_digest] = debt
        current = amendment.resulting_effective_roster_digest
        expected_sequence += 1
    return current


@dataclass(frozen=True, order=True, slots=True)
class AmendmentObligationOperation:
    operation: str
    obligation_id: str
    prior_row_digest: str
    resulting_row_digest: str
    superseded_channel_ids: tuple[str, ...]
    cleared_debt_digests: tuple[str, ...]
    operation_digest: str

    @classmethod
    def create(
        cls,
        *,
        operation: str,
        obligation_id: str,
        resulting_row_digest: str,
        prior_row_digest: str = "",
        superseded_channel_ids: Iterable[str] = (),
        cleared_debt_digests: Iterable[str] = (),
    ) -> "AmendmentObligationOperation":
        operation_value = _enum(
            operation,
            frozenset({"NEW", "REOPEN", "RETRY"}),
            "amendment operation",
        )
        prior = (
            _sha256(prior_row_digest, "prior_row_digest")
            if prior_row_digest
            else ""
        )
        if operation_value == "NEW" and prior:
            raise AdaptiveAttentionError(
                "NEW amendment operation cannot bind a prior row"
            )
        if operation_value != "NEW" and not prior:
            raise AdaptiveAttentionError(
                f"{operation_value} amendment operation requires a prior row"
            )
        resulting = _sha256(
            resulting_row_digest, "resulting_row_digest"
        )
        if operation_value == "REOPEN" and prior == resulting:
            raise AdaptiveAttentionError(
                "REOPEN amendment operation requires changed work bindings"
            )
        if operation_value == "RETRY" and prior != resulting:
            raise AdaptiveAttentionError(
                "RETRY amendment operation must preserve work bindings"
            )
        payload = {
            "schema_version": AMENDMENT_OPERATION_SCHEMA,
            "operation": operation_value,
            "obligation_id": _canonical_id(
                obligation_id, "amendment obligation identity"
            ),
            "prior_row_digest": prior,
            "resulting_row_digest": resulting,
            "superseded_channel_ids": list(
                _sorted_unique_text(
                    superseded_channel_ids,
                    "superseded channel identity",
                )
            ),
            "cleared_debt_digests": sorted(
                {
                    _sha256(value, "cleared debt digest")
                    for value in cleared_debt_digests
                }
            ),
        }
        return cls(
            operation=operation_value,
            obligation_id=payload["obligation_id"],
            prior_row_digest=prior,
            resulting_row_digest=resulting,
            superseded_channel_ids=tuple(
                payload["superseded_channel_ids"]
            ),
            cleared_debt_digests=tuple(
                payload["cleared_debt_digests"]
            ),
            operation_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": AMENDMENT_OPERATION_SCHEMA,
            "operation": self.operation,
            "obligation_id": self.obligation_id,
            "prior_row_digest": self.prior_row_digest,
            "resulting_row_digest": self.resulting_row_digest,
            "superseded_channel_ids": list(
                self.superseded_channel_ids
            ),
            "cleared_debt_digests": list(self.cleared_debt_digests),
            "operation_digest": self.operation_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AmendmentObligationOperation":
        _exact_keys(
            value,
            {
                "schema_version", "operation", "obligation_id",
                "prior_row_digest", "resulting_row_digest",
                "superseded_channel_ids", "cleared_debt_digests",
                "operation_digest",
            },
            "amendment obligation operation",
        )
        if value["schema_version"] != AMENDMENT_OPERATION_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported amendment operation schema"
            )
        replayed = cls.create(
            operation=value["operation"],
            obligation_id=value["obligation_id"],
            prior_row_digest=value["prior_row_digest"],
            resulting_row_digest=value["resulting_row_digest"],
            superseded_channel_ids=value["superseded_channel_ids"],
            cleared_debt_digests=value["cleared_debt_digests"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "amendment operation content does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class RosterAmendment:
    sequence: int
    amendment_id: str
    prior_effective_roster_digest: str
    triggering_event_digest: str
    obligation_operations: tuple[AmendmentObligationOperation, ...]
    new_obligation_ids: tuple[str, ...]
    superseded_channel_ids: tuple[str, ...]
    cleared_debt_digests: tuple[str, ...]
    new_channels: tuple[EvidenceChannel, ...]
    budget_reservations: tuple[ResourceReservation, ...]
    uncovered_debt: tuple[AttentionDebt, ...]
    resulting_effective_roster_digest: str
    amendment_digest: str

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        prior_effective_roster_digest: str,
        triggering_event_digest: str,
        obligation_operations: Iterable[
            AmendmentObligationOperation | Mapping[str, Any]
        ],
        new_channels: Iterable[EvidenceChannel],
        uncovered_debt: Iterable[AttentionDebt],
    ) -> "RosterAmendment":
        sequence_value = _positive_int(sequence, "amendment sequence")
        channels = tuple(
            sorted(new_channels, key=lambda row: row.channel_id)
        )
        if len({row.channel_id for row in channels}) != len(channels):
            raise AdaptiveAttentionError(
                "amendment contains duplicate channels"
            )
        if len(
            {row.channel_semantic_id for row in channels}
        ) != len(channels):
            raise AdaptiveAttentionError(
                "amendment contains duplicate semantic channels"
            )
        for row in channels:
            if EvidenceChannel.from_dict(row.to_dict()) != row:
                raise AdaptiveAttentionError(
                    "amendment channel does not replay"
                )
        operations = tuple(
            sorted(
                (
                    value
                    if isinstance(value, AmendmentObligationOperation)
                    else AmendmentObligationOperation.from_dict(value)
                    for value in obligation_operations
                ),
                key=lambda row: row.obligation_id,
            )
        )
        if len({row.obligation_id for row in operations}) != len(
            operations
        ):
            raise AdaptiveAttentionError(
                "amendment contains duplicate obligation operations"
            )
        affected_obligation_ids = tuple(
            row.obligation_id for row in operations
        )
        obligation_ids = tuple(
            row.obligation_id
            for row in operations
            if row.operation == "NEW"
        )
        superseded_channel_ids = tuple(
            sorted(
                {
                    channel_id
                    for row in operations
                    for channel_id in row.superseded_channel_ids
                }
            )
        )
        cleared_debt_digests = tuple(
            sorted(
                {
                    debt_digest
                    for row in operations
                    for debt_digest in row.cleared_debt_digests
                }
            )
        )
        debts = tuple(
            sorted(
                uncovered_debt,
                key=lambda row: (
                    row.obligation_id,
                    row.reason_code,
                ),
            )
        )
        for debt in debts:
            if AttentionDebt.from_dict(debt.to_dict()) != debt:
                raise AdaptiveAttentionError(
                    "amendment debt does not replay"
                )
        if not operations:
            raise AdaptiveAttentionError(
                "roster amendment must not be a no-op"
            )
        represented = {
            obligation_id
            for channel in channels
            for obligation_id in channel.obligation_ids
        } | {row.obligation_id for row in debts}
        if represented != set(affected_obligation_ids):
            raise AdaptiveAttentionError(
                "amendment obligations and work rows differ"
            )
        representation_counts: dict[str, int] = {
            obligation_id: 0
            for obligation_id in affected_obligation_ids
        }
        for channel in channels:
            for obligation_id in channel.obligation_ids:
                representation_counts[obligation_id] += 1
        for debt in debts:
            representation_counts[debt.obligation_id] += 1
        if any(count != 1 for count in representation_counts.values()):
            raise AdaptiveAttentionError(
                "amendment requires exactly one work row per obligation"
            )
        reservations = tuple(
            row.resource_reservation for row in channels
        )
        content_payload = {
            "prior_effective_roster_digest": _sha256(
                prior_effective_roster_digest,
                "prior_effective_roster_digest",
            ),
            "triggering_event_digest": _sha256(
                triggering_event_digest, "triggering_event_digest"
            ),
            "obligation_operation_digests": [
                row.operation_digest for row in operations
            ],
            "new_obligation_ids": list(obligation_ids),
            "superseded_channel_ids": list(
                superseded_channel_ids
            ),
            "cleared_debt_digests": list(cleared_debt_digests),
            "new_channel_row_digests": [
                row.row_digest for row in channels
            ],
            "budget_reservation_digests": [
                row.reservation_digest for row in reservations
            ],
            "uncovered_debt_digests": [
                row.debt_digest for row in debts
            ],
        }
        amendment_id = (
            "ARA-" + digest_json(content_payload)[:24].upper()
        )
        resulting_digest = digest_json(
            {
                "prior_effective_roster_digest": content_payload[
                    "prior_effective_roster_digest"
                ],
                "amendment_id": amendment_id,
                "new_channel_ids": [
                    row.channel_id for row in channels
                ],
                "uncovered_debt_digests": content_payload[
                    "uncovered_debt_digests"
                ],
            }
        )
        row_payload = {
            "schema_version": ROSTER_AMENDMENT_SCHEMA,
            "sequence": sequence_value,
            "amendment_id": amendment_id,
            **content_payload,
            "resulting_effective_roster_digest": resulting_digest,
        }
        return cls(
            sequence=sequence_value,
            amendment_id=amendment_id,
            prior_effective_roster_digest=content_payload[
                "prior_effective_roster_digest"
            ],
            triggering_event_digest=content_payload[
                "triggering_event_digest"
            ],
            obligation_operations=operations,
            new_obligation_ids=obligation_ids,
            superseded_channel_ids=superseded_channel_ids,
            cleared_debt_digests=cleared_debt_digests,
            new_channels=channels,
            budget_reservations=reservations,
            uncovered_debt=debts,
            resulting_effective_roster_digest=resulting_digest,
            amendment_digest=digest_json(row_payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ROSTER_AMENDMENT_SCHEMA,
            "sequence": self.sequence,
            "amendment_id": self.amendment_id,
            "prior_effective_roster_digest": (
                self.prior_effective_roster_digest
            ),
            "triggering_event_digest": self.triggering_event_digest,
            "obligation_operations": [
                row.to_dict() for row in self.obligation_operations
            ],
            "new_obligation_ids": list(self.new_obligation_ids),
            "superseded_channel_ids": list(
                self.superseded_channel_ids
            ),
            "cleared_debt_digests": list(
                self.cleared_debt_digests
            ),
            "new_channels": [
                row.to_dict() for row in self.new_channels
            ],
            "budget_reservations": [
                row.to_dict() for row in self.budget_reservations
            ],
            "uncovered_debt": [
                row.to_dict() for row in self.uncovered_debt
            ],
            "resulting_effective_roster_digest": (
                self.resulting_effective_roster_digest
            ),
            "amendment_digest": self.amendment_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "RosterAmendment":
        _exact_keys(
            value,
            {
                "schema_version", "sequence", "amendment_id",
                "prior_effective_roster_digest", "triggering_event_digest",
                "obligation_operations", "new_obligation_ids",
                "superseded_channel_ids", "cleared_debt_digests",
                "new_channels",
                "budget_reservations", "uncovered_debt",
                "resulting_effective_roster_digest", "amendment_digest",
            },
            "roster amendment",
        )
        if value["schema_version"] != ROSTER_AMENDMENT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported roster amendment schema"
            )
        replayed = cls.create(
            sequence=value["sequence"],
            prior_effective_roster_digest=value[
                "prior_effective_roster_digest"
            ],
            triggering_event_digest=value["triggering_event_digest"],
            obligation_operations=(
                AmendmentObligationOperation.from_dict(item)
                for item in value["obligation_operations"]
            ),
            new_channels=(
                EvidenceChannel.from_dict(item)
                for item in value["new_channels"]
            ),
            uncovered_debt=(
                AttentionDebt.from_dict(item)
                for item in value["uncovered_debt"]
            ),
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "roster amendment content does not replay"
            )
        return replayed


def effective_roster_material(
    base_roster: AttentionRoster,
    amendments: Sequence[RosterAmendment],
) -> tuple[
    tuple[EvidenceChannel, ...],
    tuple[AttentionDebt, ...],
    tuple[tuple[str, str], ...],
]:
    """Return the replayed active roster, debt, and obligation-row bindings.

    Superseded channels and cleared debt remain in amendment history but have
    no current scheduling or closure authority.
    """

    effective_roster_digest(base_roster, amendments)
    channels = {
        row.channel_id: row for row in base_roster.channels
    }
    debt = {row.debt_digest: row for row in base_roster.debt}
    rows = dict(base_roster.denominator_obligation_rows)
    for amendment in amendments:
        for channel_id in amendment.superseded_channel_ids:
            channels.pop(channel_id)
        for debt_digest in amendment.cleared_debt_digests:
            debt.pop(debt_digest)
        for operation in amendment.obligation_operations:
            rows[operation.obligation_id] = (
                operation.resulting_row_digest
            )
        channels.update(
            {row.channel_id: row for row in amendment.new_channels}
        )
        debt.update(
            {row.debt_digest: row for row in amendment.uncovered_debt}
        )
    return (
        tuple(sorted(channels.values(), key=lambda row: row.channel_id)),
        tuple(
            sorted(
                debt.values(),
                key=lambda row: (row.obligation_id, row.reason_code),
            )
        ),
        tuple(sorted(rows.items())),
    )


@dataclass(frozen=True, slots=True)
class AttentionGenesisAuthority:
    scope_digest: str
    denominator_digest: str
    effective_roster_digest: str
    denominator_rows: tuple[tuple[str, str], ...]
    genesis_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        denominator: AttentionDenominator,
        roster: AttentionRoster,
        amendments: Sequence[RosterAmendment] = (),
    ) -> "AttentionGenesisAuthority":
        if not isinstance(scope, AttentionScope):
            raise TypeError("scope must be an AttentionScope")
        if not isinstance(denominator, AttentionDenominator):
            raise TypeError(
                "denominator must be an AttentionDenominator"
            )
        if not isinstance(roster, AttentionRoster):
            raise TypeError("roster must be an AttentionRoster")
        AttentionScope.from_dict(scope.to_dict())
        AttentionDenominator.from_dict(denominator.to_dict())
        effective_digest = effective_roster_digest(roster, amendments)
        _channels, _debt, active_rows = effective_roster_material(
            roster, amendments
        )
        denominator_rows = tuple(
            (row.obligation_id, row.row_digest)
            for row in denominator.obligations
        )
        if denominator.scope_digest != scope.scope_digest:
            raise AdaptiveAttentionError(
                "genesis denominator is outside the attention scope"
            )
        if active_rows != denominator_rows:
            raise AdaptiveAttentionError(
                "genesis roster bindings differ from the denominator"
            )
        payload = {
            "schema_version": ATTENTION_GENESIS_AUTHORITY_SCHEMA,
            "scope_digest": scope.scope_digest,
            "denominator_digest": denominator.denominator_digest,
            "effective_roster_digest": effective_digest,
            "denominator_rows": [
                [obligation_id, row_digest]
                for obligation_id, row_digest in denominator_rows
            ],
        }
        return cls(
            scope_digest=scope.scope_digest,
            denominator_digest=denominator.denominator_digest,
            effective_roster_digest=effective_digest,
            denominator_rows=denominator_rows,
            genesis_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_GENESIS_AUTHORITY_SCHEMA,
            "scope_digest": self.scope_digest,
            "denominator_digest": self.denominator_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "denominator_rows": [
                [obligation_id, row_digest]
                for obligation_id, row_digest in self.denominator_rows
            ],
            "genesis_digest": self.genesis_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionGenesisAuthority":
        _exact_keys(
            value,
            {
                "schema_version", "scope_digest", "denominator_digest",
                "effective_roster_digest", "denominator_rows",
                "genesis_digest",
            },
            "attention genesis authority",
        )
        if value["schema_version"] != ATTENTION_GENESIS_AUTHORITY_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention genesis authority schema"
            )
        raw_rows = value["denominator_rows"]
        if not isinstance(raw_rows, list):
            raise AdaptiveAttentionError(
                "genesis denominator rows must be an array"
            )
        rows: list[tuple[str, str]] = []
        for item in raw_rows:
            if not isinstance(item, list) or len(item) != 2:
                raise AdaptiveAttentionError(
                    "genesis denominator row is malformed"
                )
            rows.append(
                (
                    _canonical_id(
                        item[0], "genesis obligation identity"
                    ),
                    _sha256(item[1], "genesis obligation row digest"),
                )
            )
        canonical_rows = tuple(rows)
        if canonical_rows != tuple(sorted(canonical_rows)) or len(
            {obligation_id for obligation_id, _digest in canonical_rows}
        ) != len(canonical_rows):
            raise AdaptiveAttentionError(
                "genesis denominator rows must be canonical and unique"
            )
        payload = dict(value)
        genesis_digest = payload.pop("genesis_digest")
        if digest_json(payload) != _sha256(
            genesis_digest, "genesis_digest"
        ):
            raise AdaptiveAttentionError(
                "attention genesis authority content does not replay"
            )
        return cls(
            scope_digest=_sha256(value["scope_digest"], "scope_digest"),
            denominator_digest=_sha256(
                value["denominator_digest"], "denominator_digest"
            ),
            effective_roster_digest=_sha256(
                value["effective_roster_digest"],
                "effective_roster_digest",
            ),
            denominator_rows=canonical_rows,
            genesis_digest=genesis_digest,
        )


@dataclass(frozen=True, slots=True)
class AttentionPlan:
    denominator_digest: str
    roster: AttentionRoster
    debt: tuple[AttentionDebt, ...]
    unscheduled_obligation_ids: tuple[str, ...]
    total_reserved_attention_units: int
    total_reserved_channels: int
    plan_digest: str

    @classmethod
    def create(
        cls,
        *,
        denominator: AttentionDenominator,
        roster: AttentionRoster,
        debt: Iterable[AttentionDebt],
    ) -> "AttentionPlan":
        if AttentionDenominator.from_dict(
            denominator.to_dict()
        ) != denominator:
            raise AdaptiveAttentionError(
                "plan denominator does not replay"
            )
        if AttentionRoster.from_dict(roster.to_dict()) != roster:
            raise AdaptiveAttentionError("plan roster does not replay")
        if denominator.denominator_digest != roster.denominator_digest:
            raise AdaptiveAttentionError(
                "plan roster does not bind the exact denominator"
            )
        debt_rows = tuple(
            sorted(
                debt,
                key=lambda row: (
                    row.obligation_id,
                    row.reason_code,
                ),
            )
        )
        if tuple(row.debt_digest for row in debt_rows) != tuple(
            row.debt_digest for row in roster.debt
        ):
            raise AdaptiveAttentionError(
                "plan debt differs from exact roster debt"
            )
        unscheduled = tuple(
            sorted({row.obligation_id for row in debt_rows})
        )
        payload = {
            "schema_version": ATTENTION_PLAN_SCHEMA,
            "denominator_digest": denominator.denominator_digest,
            "roster_digest": roster.roster_digest,
            "debt_digests": [
                row.debt_digest for row in debt_rows
            ],
            "unscheduled_obligation_ids": list(unscheduled),
            "total_reserved_attention_units": (
                roster.total_reserved_attention_units
            ),
            "total_reserved_channels": (
                roster.total_reserved_channels
            ),
        }
        return cls(
            denominator_digest=denominator.denominator_digest,
            roster=roster,
            debt=debt_rows,
            unscheduled_obligation_ids=unscheduled,
            total_reserved_attention_units=(
                roster.total_reserved_attention_units
            ),
            total_reserved_channels=roster.total_reserved_channels,
            plan_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_PLAN_SCHEMA,
            "denominator_digest": self.denominator_digest,
            "roster": self.roster.to_dict(),
            "debt": [row.to_dict() for row in self.debt],
            "unscheduled_obligation_ids": list(
                self.unscheduled_obligation_ids
            ),
            "total_reserved_attention_units": (
                self.total_reserved_attention_units
            ),
            "total_reserved_channels": self.total_reserved_channels,
            "plan_digest": self.plan_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionPlan":
        _exact_keys(
            value,
            {
                "schema_version", "denominator_digest", "roster", "debt",
                "unscheduled_obligation_ids",
                "total_reserved_attention_units",
                "total_reserved_channels", "plan_digest",
            },
            "attention plan",
        )
        if value["schema_version"] != ATTENTION_PLAN_SCHEMA:
            raise AdaptiveAttentionError("unsupported attention plan schema")
        roster = AttentionRoster.from_dict(value["roster"])
        debts = tuple(
            AttentionDebt.from_dict(item) for item in value["debt"]
        )
        if debts != tuple(
            sorted(
                debts,
                key=lambda row: (row.obligation_id, row.reason_code),
            )
        ):
            raise AdaptiveAttentionError("attention plan debt is not canonical")
        if tuple(row.debt_digest for row in debts) != tuple(
            row.debt_digest for row in roster.debt
        ):
            raise AdaptiveAttentionError(
                "attention plan debt differs from roster"
            )
        if (
            value["total_reserved_attention_units"]
            != roster.total_reserved_attention_units
            or value["total_reserved_channels"]
            != roster.total_reserved_channels
        ):
            raise AdaptiveAttentionError(
                "attention plan counts differ from exact roster"
            )
        if value["denominator_digest"] != roster.denominator_digest:
            raise AdaptiveAttentionError(
                "attention plan denominator differs from roster"
            )
        unscheduled = tuple(
            _canonical_id(item, "unscheduled obligation identity")
            for item in value["unscheduled_obligation_ids"]
        )
        expected_unscheduled = tuple(
            sorted({row.obligation_id for row in debts})
        )
        if unscheduled != expected_unscheduled:
            raise AdaptiveAttentionError(
                "attention plan unscheduled identities differ from debt"
            )
        payload = {
            "schema_version": ATTENTION_PLAN_SCHEMA,
            "denominator_digest": value["denominator_digest"],
            "roster_digest": roster.roster_digest,
            "debt_digests": [row.debt_digest for row in debts],
            "unscheduled_obligation_ids": list(
                value["unscheduled_obligation_ids"]
            ),
            "total_reserved_attention_units": value[
                "total_reserved_attention_units"
            ],
            "total_reserved_channels": value["total_reserved_channels"],
        }
        plan_digest = _sha256(value["plan_digest"], "plan_digest")
        if digest_json(payload) != plan_digest:
            raise AdaptiveAttentionError(
                "attention plan content does not replay"
            )
        replayed = cls(
            denominator_digest=_sha256(
                value["denominator_digest"], "denominator_digest"
            ),
            roster=roster,
            debt=debts,
            unscheduled_obligation_ids=unscheduled,
            total_reserved_attention_units=_nonnegative_int(
                value["total_reserved_attention_units"],
                "total_reserved_attention_units",
            ),
            total_reserved_channels=_nonnegative_int(
                value["total_reserved_channels"],
                "total_reserved_channels",
            ),
            plan_digest=plan_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention plan canonical form does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionJoinProjection:
    scope_digest: str
    effective_roster_digest: str
    parent_join_digest: str
    genesis_authority_digest: str
    join_sequence: int
    accepted_receipt_digests: tuple[str, ...]
    accepted_terminal_receipts: tuple[
        "ChannelTerminalReceipt", ...
    ]
    obligations: tuple[AttentionObligation, ...]
    challenge_obligations: tuple[AttentionObligation, ...]
    denominator_obligations: tuple[AttentionObligation, ...]
    candidate_union: tuple[str, ...]
    evidence_union: tuple[str, ...]
    alias_map: tuple[tuple[str, tuple[str, ...]], ...]
    retained_negative_proposal_ids: tuple[str, ...]
    authority_debt_reason_codes: tuple[str, ...]
    join_digest: str

    @classmethod
    def create(
        cls,
        *,
        obligations: Iterable[AttentionObligation],
        challenge_obligations: Iterable[AttentionObligation],
        candidate_union: Iterable[str],
        evidence_union: Iterable[str],
        alias_map: Mapping[str, Iterable[str]],
        retained_negative_proposal_ids: Iterable[str],
        scope_digest: str = "",
        effective_roster_digest: str = "",
        parent_join_digest: str = "",
        genesis_authority_digest: str = "",
        join_sequence: int = 0,
        accepted_receipt_digests: Iterable[str] = (),
        accepted_terminal_receipts: Iterable[
            "ChannelTerminalReceipt"
        ] = (),
        authority_debt_reason_codes: Iterable[str] = (),
    ) -> "AttentionJoinProjection":
        lineage_fields = (
            scope_digest,
            effective_roster_digest,
            parent_join_digest,
            genesis_authority_digest,
        )
        authenticated = any(lineage_fields)
        if authenticated:
            scope_digest_value = _sha256(
                scope_digest, "join scope_digest"
            )
            effective_digest_value = _sha256(
                effective_roster_digest,
                "join effective_roster_digest",
            )
            parent_digest = (
                _sha256(parent_join_digest, "parent_join_digest")
                if parent_join_digest
                else ""
            )
            genesis_digest = (
                _sha256(
                    genesis_authority_digest,
                    "genesis_authority_digest",
                )
                if genesis_authority_digest
                else ""
            )
            if bool(parent_digest) == bool(genesis_digest):
                raise AdaptiveAttentionError(
                    "authenticated join requires exactly one lineage parent"
                )
            sequence_value = _positive_int(
                join_sequence, "join_sequence"
            )
            if genesis_digest and sequence_value != 1:
                raise AdaptiveAttentionError(
                    "genesis join sequence must be one"
                )
        else:
            if any(lineage_fields) or join_sequence != 0:
                raise AdaptiveAttentionError(
                    "structural join lineage is malformed"
                )
            scope_digest_value = ""
            effective_digest_value = ""
            parent_digest = ""
            genesis_digest = ""
            sequence_value = 0
        accepted_digests = tuple(
            _sha256(value, "accepted receipt digest")
            for value in accepted_receipt_digests
        )
        if len(set(accepted_digests)) != len(accepted_digests):
            raise AdaptiveAttentionError(
                "join contains duplicate accepted evidence receipts"
            )
        if not authenticated and accepted_digests:
            raise AdaptiveAttentionError(
                "structural join cannot claim accepted evidence"
            )
        terminal_receipts = tuple(
            sorted(
                (
                    ChannelTerminalReceipt.from_dict(receipt.to_dict())
                    if isinstance(receipt, ChannelTerminalReceipt)
                    else ChannelTerminalReceipt.from_dict(receipt)
                    for receipt in accepted_terminal_receipts
                ),
                key=lambda row: row.channel_id,
            )
        )
        if len(
            {receipt.channel_id for receipt in terminal_receipts}
        ) != len(terminal_receipts):
            raise AdaptiveAttentionError(
                "join contains duplicate accepted channel terminals"
            )
        if bool(accepted_digests) != bool(terminal_receipts):
            raise AdaptiveAttentionError(
                "accepted evidence and channel terminals must co-occur"
            )
        if not authenticated and terminal_receipts:
            raise AdaptiveAttentionError(
                "structural join cannot claim accepted terminals"
            )
        raw_rows = tuple(obligations)
        raw_challenges = tuple(challenge_obligations)
        if any(not isinstance(row, AttentionObligation) for row in raw_rows):
            raise TypeError("join obligation has an invalid type")
        if any(
            not isinstance(row, AttentionObligation)
            for row in raw_challenges
        ):
            raise TypeError("join challenge obligation has an invalid type")
        if len({row.obligation_id for row in raw_rows}) != len(raw_rows):
            raise AdaptiveAttentionError(
                "join projection contains duplicate obligation rows"
            )
        if len(
            {row.obligation_id for row in raw_challenges}
        ) != len(raw_challenges):
            raise AdaptiveAttentionError(
                "join projection contains duplicate challenge rows"
            )
        rows = tuple(
            sorted(raw_rows, key=lambda row: row.obligation_id)
        )
        challenges = tuple(
            sorted(
                raw_challenges,
                key=lambda row: row.obligation_id,
            )
        )
        denominator_by_id: dict[str, AttentionObligation] = {}
        for row in (*rows, *challenges):
            existing = denominator_by_id.get(row.obligation_id)
            if existing is not None and existing.row_digest != row.row_digest:
                raise AdaptiveAttentionError(
                    "join projection contains divergent denominator rows"
                )
            AttentionObligation.from_dict(row.to_dict())
            denominator_by_id[row.obligation_id] = row
        denominator_rows = tuple(
            sorted(
                denominator_by_id.values(),
                key=lambda row: row.obligation_id,
            )
        )
        candidates = _sorted_unique_text(
            candidate_union, "candidate identity"
        )
        evidence = _sorted_unique_text(
            evidence_union, "evidence identity"
        )
        aliases = tuple(
            sorted(
                (
                    _canonical_id(alias, "candidate alias"),
                    _sorted_unique_text(
                        roots, "candidate root identity"
                    ),
                )
                for alias, roots in alias_map.items()
            )
        )
        negatives = tuple(
            sorted(
                {
                    _canonical_id(
                        value, "negative proposal obligation identity"
                    )
                    for value in retained_negative_proposal_ids
                }
            )
        )
        authority_debt = tuple(
            sorted(
                {
                    _safe_text(
                        value, "authority debt reason code"
                    ).upper()
                    for value in authority_debt_reason_codes
                }
            )
        )
        rows_by_id = {row.obligation_id: row for row in rows}
        for negative_id in negatives:
            if negative_id not in rows_by_id:
                raise AdaptiveAttentionError(
                    "retained negative proposal is outside the join "
                    "obligation denominator"
                )
            if not any(
                challenge.kind == "CANDIDATE_CHALLENGE"
                and negative_id in challenge.subject_ids
                and "negative-proposal" in challenge.subject_ids
                for challenge in challenges
            ):
                raise AdaptiveAttentionError(
                    "retained negative proposal lacks an exact challenge "
                    "denominator row"
                )
        candidate_set = set(candidates)
        missing_alias_roots = sorted(
            {
                root
                for _alias, roots in aliases
                for root in roots
                if root not in candidate_set
            }
        )
        if missing_alias_roots:
            raise AdaptiveAttentionError(
                "candidate alias roots are outside the canonical candidate "
                "union: "
                + ",".join(missing_alias_roots)
            )
        payload = {
            "schema_version": ATTENTION_JOIN_PROJECTION_SCHEMA,
            "scope_digest": scope_digest_value,
            "effective_roster_digest": effective_digest_value,
            "parent_join_digest": parent_digest,
            "genesis_authority_digest": genesis_digest,
            "join_sequence": sequence_value,
            "accepted_receipt_digests": list(accepted_digests),
            "accepted_terminal_receipt_digests": [
                receipt.receipt_digest
                for receipt in terminal_receipts
            ],
            "obligation_row_digests": [
                row.row_digest for row in rows
            ],
            "challenge_row_digests": [
                row.row_digest for row in challenges
            ],
            "denominator_row_digests": [
                row.row_digest for row in denominator_rows
            ],
            "candidate_union": list(candidates),
            "evidence_union": list(evidence),
            "alias_map": [
                [alias, list(roots)] for alias, roots in aliases
            ],
            "retained_negative_proposal_ids": list(negatives),
            "authority_debt_reason_codes": list(authority_debt),
        }
        return cls(
            scope_digest=scope_digest_value,
            effective_roster_digest=effective_digest_value,
            parent_join_digest=parent_digest,
            genesis_authority_digest=genesis_digest,
            join_sequence=sequence_value,
            accepted_receipt_digests=accepted_digests,
            accepted_terminal_receipts=terminal_receipts,
            obligations=rows,
            challenge_obligations=challenges,
            denominator_obligations=denominator_rows,
            candidate_union=candidates,
            evidence_union=evidence,
            alias_map=aliases,
            retained_negative_proposal_ids=negatives,
            authority_debt_reason_codes=authority_debt,
            join_digest=digest_json(payload),
        )

    def alias_map_dict(self) -> dict[str, tuple[str, ...]]:
        return dict(self.alias_map)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_JOIN_PROJECTION_SCHEMA,
            "scope_digest": self.scope_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "parent_join_digest": self.parent_join_digest,
            "genesis_authority_digest": self.genesis_authority_digest,
            "join_sequence": self.join_sequence,
            "accepted_receipt_digests": list(
                self.accepted_receipt_digests
            ),
            "accepted_terminal_receipts": [
                receipt.to_dict()
                for receipt in self.accepted_terminal_receipts
            ],
            "obligations": [row.to_dict() for row in self.obligations],
            "challenge_obligations": [
                row.to_dict() for row in self.challenge_obligations
            ],
            "denominator_obligations": [
                row.to_dict() for row in self.denominator_obligations
            ],
            "candidate_union": list(self.candidate_union),
            "evidence_union": list(self.evidence_union),
            "alias_map": [
                [alias, list(roots)] for alias, roots in self.alias_map
            ],
            "retained_negative_proposal_ids": list(
                self.retained_negative_proposal_ids
            ),
            "authority_debt_reason_codes": list(
                self.authority_debt_reason_codes
            ),
            "join_digest": self.join_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionJoinProjection":
        _exact_keys(
            value,
            {
                "schema_version", "scope_digest",
                "effective_roster_digest", "parent_join_digest",
                "genesis_authority_digest", "join_sequence",
                "accepted_receipt_digests",
                "accepted_terminal_receipts", "obligations",
                "challenge_obligations", "candidate_union",
                "denominator_obligations",
                "evidence_union", "alias_map",
                "retained_negative_proposal_ids",
                "authority_debt_reason_codes", "join_digest",
            },
            "attention join projection",
        )
        if value["schema_version"] != ATTENTION_JOIN_PROJECTION_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention join projection schema"
            )
        alias_map: dict[str, Iterable[str]] = {}
        for item in value["alias_map"]:
            if (
                not isinstance(item, list)
                or len(item) != 2
                or not isinstance(item[1], list)
            ):
                raise AdaptiveAttentionError(
                    "attention join alias entry is malformed"
                )
            alias_map[item[0]] = item[1]
        replayed = cls.create(
            scope_digest=value["scope_digest"],
            effective_roster_digest=value["effective_roster_digest"],
            parent_join_digest=value["parent_join_digest"],
            genesis_authority_digest=value[
                "genesis_authority_digest"
            ],
            join_sequence=value["join_sequence"],
            accepted_receipt_digests=value[
                "accepted_receipt_digests"
            ],
            accepted_terminal_receipts=(
                ChannelTerminalReceipt.from_dict(item)
                for item in value["accepted_terminal_receipts"]
            ),
            obligations=(
                AttentionObligation.from_dict(item)
                for item in value["obligations"]
            ),
            challenge_obligations=(
                AttentionObligation.from_dict(item)
                for item in value["challenge_obligations"]
            ),
            candidate_union=value["candidate_union"],
            evidence_union=value["evidence_union"],
            alias_map=alias_map,
            retained_negative_proposal_ids=value[
                "retained_negative_proposal_ids"
            ],
            authority_debt_reason_codes=value[
                "authority_debt_reason_codes"
            ],
        )
        supplied_denominator = tuple(
            AttentionObligation.from_dict(item)
            for item in value["denominator_obligations"]
        )
        if replayed.denominator_obligations != supplied_denominator:
            raise AdaptiveAttentionError(
                "attention join denominator does not replay"
            )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention join projection content does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class WorkerReceipt:
    receipt_id: str
    sequence: int
    attempt: int
    channel_id: str
    obligation_id: str
    disposition: str
    output_digest: str
    candidate_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    aliases: tuple[tuple[str, tuple[str, ...]], ...]
    receipt_digest: str

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        attempt: int = 1,
        channel_id: str,
        obligation_id: str,
        disposition: str,
        output_digest: str,
        candidate_ids: Iterable[str] = (),
        evidence_ids: Iterable[str] = (),
        aliases: Mapping[str, Iterable[str] | str] | None = None,
    ) -> "WorkerReceipt":
        alias_rows: list[tuple[str, tuple[str, ...]]] = []
        for alias, roots in (aliases or {}).items():
            root_values = (roots,) if isinstance(roots, str) else roots
            alias_rows.append(
                (
                    _canonical_id(alias, "candidate alias"),
                    _sorted_unique_text(
                        root_values, "candidate root identity"
                    ),
                )
            )
        normalized_aliases = tuple(sorted(alias_rows))
        payload = {
            "schema_version": WORKER_RECEIPT_SCHEMA,
            "sequence": _positive_int(sequence, "receipt sequence"),
            "attempt": _positive_int(attempt, "receipt attempt"),
            "channel_id": _canonical_id(channel_id, "channel_id"),
            "obligation_id": _canonical_id(
                obligation_id, "obligation_id"
            ),
            "disposition": _enum(
                disposition,
                WORKER_DISPOSITIONS,
                "worker receipt disposition",
            ),
            "output_digest": _sha256(
                output_digest, "worker receipt output_digest"
            ),
            "candidate_ids": list(
                _sorted_unique_text(
                    candidate_ids, "candidate identity"
                )
            ),
            "evidence_ids": list(
                _sorted_unique_text(
                    evidence_ids, "evidence identity"
                )
            ),
            "aliases": [
                [alias, list(roots)] for alias, roots in normalized_aliases
            ],
        }
        receipt_digest = digest_json(payload)
        return cls(
            receipt_id="AWR-" + receipt_digest[:24].upper(),
            sequence=payload["sequence"],
            attempt=payload["attempt"],
            channel_id=payload["channel_id"],
            obligation_id=payload["obligation_id"],
            disposition=payload["disposition"],
            output_digest=payload["output_digest"],
            candidate_ids=tuple(payload["candidate_ids"]),
            evidence_ids=tuple(payload["evidence_ids"]),
            aliases=normalized_aliases,
            receipt_digest=receipt_digest,
        )

    def aliases_dict(self) -> dict[str, tuple[str, ...]]:
        return dict(self.aliases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": WORKER_RECEIPT_SCHEMA,
            "receipt_id": self.receipt_id,
            "sequence": self.sequence,
            "attempt": self.attempt,
            "channel_id": self.channel_id,
            "obligation_id": self.obligation_id,
            "disposition": self.disposition,
            "output_digest": self.output_digest,
            "candidate_ids": list(self.candidate_ids),
            "evidence_ids": list(self.evidence_ids),
            "aliases": [
                [alias, list(roots)] for alias, roots in self.aliases
            ],
            "receipt_digest": self.receipt_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "WorkerReceipt":
        _exact_keys(
            value,
            {
                "schema_version",
                "receipt_id",
                "sequence",
                "attempt",
                "channel_id",
                "obligation_id",
                "disposition",
                "output_digest",
                "candidate_ids",
                "evidence_ids",
                "aliases",
                "receipt_digest",
            },
            "worker receipt",
        )
        if value["schema_version"] != WORKER_RECEIPT_SCHEMA:
            raise AdaptiveAttentionError("unsupported worker receipt schema")
        aliases = value["aliases"]
        if not isinstance(aliases, list):
            raise AdaptiveAttentionError("worker receipt aliases must be an array")
        alias_map: dict[str, Iterable[str]] = {}
        for entry in aliases:
            if (
                not isinstance(entry, list)
                or len(entry) != 2
                or not isinstance(entry[1], list)
            ):
                raise AdaptiveAttentionError(
                    "worker receipt alias entry is malformed"
                )
            alias_map[entry[0]] = entry[1]
        replayed = cls.create(
            sequence=value["sequence"],
            attempt=value["attempt"],
            channel_id=value["channel_id"],
            obligation_id=value["obligation_id"],
            disposition=value["disposition"],
            output_digest=value["output_digest"],
            candidate_ids=value["candidate_ids"],
            evidence_ids=value["evidence_ids"],
            aliases=alias_map,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "worker receipt content does not replay"
            )
        return replayed

    @classmethod
    def from_json(cls, text: str) -> "WorkerReceipt":
        value = strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise AdaptiveAttentionError("worker receipt JSON must be an object")
        return cls.from_dict(value)


@dataclass(frozen=True, slots=True)
class ChannelTerminalReceipt:
    channel_id: str
    channel_row_digest: str
    terminal_state: str
    output_digest: str
    reason_code: str
    receipt_digest: str

    @classmethod
    def create(
        cls,
        *,
        channel: EvidenceChannel,
        terminal_state: str,
        output_digest: str,
        reason_code: str = "",
    ) -> "ChannelTerminalReceipt":
        if not isinstance(channel, EvidenceChannel):
            raise TypeError("channel must be an EvidenceChannel")
        state = _enum(
            terminal_state,
            frozenset({"COMMITTED", "DEBT", "CANCELLED"}),
            "terminal_state",
        )
        reason = (
            _safe_text(reason_code, "reason_code").upper()
            if reason_code
            else ""
        )
        if state != "COMMITTED" and not reason:
            raise AdaptiveAttentionError(
                "non-committed terminal receipt requires a reason code"
            )
        payload = {
            "schema_version": CHANNEL_TERMINAL_RECEIPT_SCHEMA,
            "channel_id": channel.channel_id,
            "channel_row_digest": channel.row_digest,
            "terminal_state": state,
            "output_digest": _sha256(
                output_digest, "terminal output_digest"
            ),
            "reason_code": reason,
        }
        return cls(
            channel_id=channel.channel_id,
            channel_row_digest=channel.row_digest,
            terminal_state=state,
            output_digest=payload["output_digest"],
            reason_code=reason,
            receipt_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CHANNEL_TERMINAL_RECEIPT_SCHEMA,
            "channel_id": self.channel_id,
            "channel_row_digest": self.channel_row_digest,
            "terminal_state": self.terminal_state,
            "output_digest": self.output_digest,
            "reason_code": self.reason_code,
            "receipt_digest": self.receipt_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "ChannelTerminalReceipt":
        _exact_keys(
            value,
            {
                "schema_version",
                "channel_id",
                "channel_row_digest",
                "terminal_state",
                "output_digest",
                "reason_code",
                "receipt_digest",
            },
            "channel terminal receipt",
        )
        if value["schema_version"] != CHANNEL_TERMINAL_RECEIPT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported channel terminal receipt schema"
            )
        payload = dict(value)
        receipt_digest = payload.pop("receipt_digest")
        _canonical_id(payload["channel_id"], "channel_id")
        _sha256(payload["channel_row_digest"], "channel_row_digest")
        state = _enum(
            payload["terminal_state"],
            frozenset({"COMMITTED", "DEBT", "CANCELLED"}),
            "terminal_state",
        )
        _sha256(payload["output_digest"], "output_digest")
        reason = payload["reason_code"]
        if not isinstance(reason, str):
            raise AdaptiveAttentionError("reason_code must be text")
        if state != "COMMITTED" and not reason:
            raise AdaptiveAttentionError(
                "non-committed terminal receipt requires a reason code"
            )
        if digest_json(payload) != _sha256(
            receipt_digest, "receipt_digest"
        ):
            raise AdaptiveAttentionError(
                "channel terminal receipt content does not replay"
            )
        return cls(
            channel_id=payload["channel_id"],
            channel_row_digest=payload["channel_row_digest"],
            terminal_state=state,
            output_digest=payload["output_digest"],
            reason_code=reason,
            receipt_digest=receipt_digest,
        )


@dataclass(frozen=True, slots=True)
class ChannelAttemptAuthority:
    scope_digest: str
    effective_roster_digest: str
    channel_id: str
    channel_row_digest: str
    current_attempt: int
    lease_id: str
    phase_io_commit_digest: str
    transaction_commit_digest: str
    terminal_receipt: ChannelTerminalReceipt
    authority_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        effective_roster_digest_value: str,
        channel: EvidenceChannel,
        current_attempt: int,
        lease_id: str,
        phase_io_commit_digest: str,
        transaction_commit_digest: str,
        terminal_receipt: ChannelTerminalReceipt,
    ) -> "ChannelAttemptAuthority":
        if not isinstance(scope, AttentionScope):
            raise TypeError("scope must be an AttentionScope")
        if not isinstance(channel, EvidenceChannel):
            raise TypeError("channel must be an EvidenceChannel")
        if not isinstance(terminal_receipt, ChannelTerminalReceipt):
            raise TypeError(
                "terminal_receipt must be a ChannelTerminalReceipt"
            )
        AttentionScope.from_dict(scope.to_dict())
        EvidenceChannel.from_dict(channel.to_dict())
        terminal = ChannelTerminalReceipt.from_dict(
            terminal_receipt.to_dict()
        )
        if terminal.terminal_state != "COMMITTED":
            raise AdaptiveAttentionError(
                "accepted evidence requires a committed terminal transaction"
            )
        if (
            terminal.channel_id != channel.channel_id
            or terminal.channel_row_digest != channel.row_digest
        ):
            raise AdaptiveAttentionError(
                "terminal transaction does not bind the roster channel"
            )
        payload = {
            "schema_version": CHANNEL_ATTEMPT_AUTHORITY_SCHEMA,
            "scope_digest": scope.scope_digest,
            "effective_roster_digest": _sha256(
                effective_roster_digest_value,
                "effective_roster_digest",
            ),
            "channel_id": channel.channel_id,
            "channel_row_digest": channel.row_digest,
            "current_attempt": _positive_int(
                current_attempt, "current_attempt"
            ),
            "lease_id": _canonical_id(lease_id, "lease_id"),
            "phase_io_commit_digest": _sha256(
                phase_io_commit_digest, "phase_io_commit_digest"
            ),
            "transaction_commit_digest": _sha256(
                transaction_commit_digest,
                "transaction_commit_digest",
            ),
            "terminal_receipt_digest": terminal.receipt_digest,
        }
        return cls(
            scope_digest=payload["scope_digest"],
            effective_roster_digest=payload[
                "effective_roster_digest"
            ],
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
            terminal_receipt=terminal,
            authority_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CHANNEL_ATTEMPT_AUTHORITY_SCHEMA,
            "scope_digest": self.scope_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "channel_id": self.channel_id,
            "channel_row_digest": self.channel_row_digest,
            "current_attempt": self.current_attempt,
            "lease_id": self.lease_id,
            "phase_io_commit_digest": self.phase_io_commit_digest,
            "transaction_commit_digest": (
                self.transaction_commit_digest
            ),
            "terminal_receipt": self.terminal_receipt.to_dict(),
            "authority_digest": self.authority_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "ChannelAttemptAuthority":
        _exact_keys(
            value,
            {
                "schema_version", "scope_digest",
                "effective_roster_digest", "channel_id",
                "channel_row_digest", "current_attempt", "lease_id",
                "phase_io_commit_digest", "transaction_commit_digest",
                "terminal_receipt", "authority_digest",
            },
            "channel attempt authority",
        )
        if value["schema_version"] != CHANNEL_ATTEMPT_AUTHORITY_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported channel attempt authority schema"
            )
        terminal = ChannelTerminalReceipt.from_dict(
            value["terminal_receipt"]
        )
        payload = {
            "schema_version": value["schema_version"],
            "scope_digest": _sha256(
                value["scope_digest"], "scope_digest"
            ),
            "effective_roster_digest": _sha256(
                value["effective_roster_digest"],
                "effective_roster_digest",
            ),
            "channel_id": _canonical_id(
                value["channel_id"], "channel_id"
            ),
            "channel_row_digest": _sha256(
                value["channel_row_digest"], "channel_row_digest"
            ),
            "current_attempt": _positive_int(
                value["current_attempt"], "current_attempt"
            ),
            "lease_id": _canonical_id(value["lease_id"], "lease_id"),
            "phase_io_commit_digest": _sha256(
                value["phase_io_commit_digest"],
                "phase_io_commit_digest",
            ),
            "transaction_commit_digest": _sha256(
                value["transaction_commit_digest"],
                "transaction_commit_digest",
            ),
            "terminal_receipt_digest": terminal.receipt_digest,
        }
        authority_digest = _sha256(
            value["authority_digest"], "authority_digest"
        )
        if digest_json(payload) != authority_digest:
            raise AdaptiveAttentionError(
                "channel attempt authority content does not replay"
            )
        if (
            terminal.terminal_state != "COMMITTED"
            or terminal.channel_id != payload["channel_id"]
            or terminal.channel_row_digest
            != payload["channel_row_digest"]
        ):
            raise AdaptiveAttentionError(
                "channel attempt authority has a stale terminal transaction"
            )
        replayed = cls(
            scope_digest=payload["scope_digest"],
            effective_roster_digest=payload[
                "effective_roster_digest"
            ],
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
            terminal_receipt=terminal,
            authority_digest=authority_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "channel attempt authority canonical form does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class AcceptedEvidenceReceipt:
    attempt_authority: ChannelAttemptAuthority
    worker_receipt: WorkerReceipt
    previous_accepted_receipt_digest: str
    accepted_receipt_digest: str

    @classmethod
    def create(
        cls,
        *,
        attempt_authority: ChannelAttemptAuthority,
        worker_receipt: WorkerReceipt,
        previous_receipt: "AcceptedEvidenceReceipt | None" = None,
    ) -> "AcceptedEvidenceReceipt":
        if not isinstance(
            attempt_authority, ChannelAttemptAuthority
        ):
            raise TypeError(
                "attempt_authority must be a ChannelAttemptAuthority"
            )
        if not isinstance(worker_receipt, WorkerReceipt):
            raise TypeError(
                "worker_receipt must be a WorkerReceipt"
            )
        authority = ChannelAttemptAuthority.from_dict(
            attempt_authority.to_dict()
        )
        receipt = WorkerReceipt.from_dict(worker_receipt.to_dict())
        if (
            receipt.channel_id != authority.channel_id
            or receipt.attempt != authority.current_attempt
        ):
            raise AdaptiveAttentionError(
                "worker receipt is outside the current channel attempt"
            )
        if receipt.output_digest != (
            authority.terminal_receipt.output_digest
        ):
            raise AdaptiveAttentionError(
                "worker receipt output differs from the committed "
                "transaction output"
            )
        if receipt.sequence == 1:
            if previous_receipt is not None:
                raise AdaptiveAttentionError(
                    "first accepted receipt cannot have a sequence parent"
                )
            previous_digest = ""
        else:
            if previous_receipt is None:
                raise AdaptiveAttentionError(
                    "accepted receipt sequence is missing its exact parent"
                )
            if not isinstance(
                previous_receipt, AcceptedEvidenceReceipt
            ):
                raise TypeError(
                    "previous_receipt must be an AcceptedEvidenceReceipt"
                )
            previous = AcceptedEvidenceReceipt.from_dict(
                previous_receipt.to_dict()
            )
            if (
                previous.attempt_authority.authority_digest
                != authority.authority_digest
                or previous.worker_receipt.sequence
                != receipt.sequence - 1
            ):
                raise AdaptiveAttentionError(
                    "accepted receipt sequence parent is stale or forked"
                )
            previous_digest = previous.accepted_receipt_digest
        payload = {
            "schema_version": ACCEPTED_EVIDENCE_RECEIPT_SCHEMA,
            "attempt_authority_digest": authority.authority_digest,
            "worker_receipt_digest": receipt.receipt_digest,
            "previous_accepted_receipt_digest": previous_digest,
        }
        return cls(
            attempt_authority=authority,
            worker_receipt=receipt,
            previous_accepted_receipt_digest=previous_digest,
            accepted_receipt_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ACCEPTED_EVIDENCE_RECEIPT_SCHEMA,
            "attempt_authority": self.attempt_authority.to_dict(),
            "worker_receipt": self.worker_receipt.to_dict(),
            "previous_accepted_receipt_digest": (
                self.previous_accepted_receipt_digest
            ),
            "accepted_receipt_digest": self.accepted_receipt_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AcceptedEvidenceReceipt":
        _exact_keys(
            value,
            {
                "schema_version", "attempt_authority",
                "worker_receipt", "previous_accepted_receipt_digest",
                "accepted_receipt_digest",
            },
            "accepted evidence receipt",
        )
        if value["schema_version"] != ACCEPTED_EVIDENCE_RECEIPT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported accepted evidence receipt schema"
            )
        authority = ChannelAttemptAuthority.from_dict(
            value["attempt_authority"]
        )
        receipt = WorkerReceipt.from_dict(value["worker_receipt"])
        previous_digest = value[
            "previous_accepted_receipt_digest"
        ]
        if not isinstance(previous_digest, str):
            raise AdaptiveAttentionError(
                "previous accepted receipt digest must be text"
            )
        if previous_digest:
            previous_digest = _sha256(
                previous_digest,
                "previous_accepted_receipt_digest",
            )
        if (
            receipt.channel_id != authority.channel_id
            or receipt.attempt != authority.current_attempt
            or receipt.output_digest
            != authority.terminal_receipt.output_digest
        ):
            raise AdaptiveAttentionError(
                "accepted evidence receipt authority binding is stale"
            )
        if (receipt.sequence == 1) != (previous_digest == ""):
            raise AdaptiveAttentionError(
                "accepted receipt sequence parent is malformed"
            )
        payload = {
            "schema_version": ACCEPTED_EVIDENCE_RECEIPT_SCHEMA,
            "attempt_authority_digest": authority.authority_digest,
            "worker_receipt_digest": receipt.receipt_digest,
            "previous_accepted_receipt_digest": previous_digest,
        }
        accepted_digest = _sha256(
            value["accepted_receipt_digest"],
            "accepted_receipt_digest",
        )
        if digest_json(payload) != accepted_digest:
            raise AdaptiveAttentionError(
                "accepted evidence receipt content does not replay"
            )
        replayed = cls(
            attempt_authority=authority,
            worker_receipt=receipt,
            previous_accepted_receipt_digest=previous_digest,
            accepted_receipt_digest=accepted_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "accepted evidence receipt canonical form does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionStopBindings:
    scope_digest: str
    denominator_digest: str
    denominator_rows: tuple[
        tuple[str, str, tuple[str, ...]], ...
    ]
    effective_roster_digest: str
    terminal_receipts: tuple[ChannelTerminalReceipt, ...]
    joined_channel_ids: tuple[str, ...]
    reconciled_obligation_ids: tuple[str, ...]
    prior_candidate_union: tuple[str, ...]
    candidate_union: tuple[str, ...]
    prior_evidence_union: tuple[str, ...]
    evidence_union: tuple[str, ...]
    prior_alias_map: tuple[tuple[str, tuple[str, ...]], ...]
    alias_map: tuple[tuple[str, tuple[str, ...]], ...]
    integrity_violations: tuple[str, ...]
    bindings_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        denominator: AttentionDenominator,
        effective_roster_digest_value: str,
        terminal_receipts: Iterable[ChannelTerminalReceipt],
        joined_channel_ids: Iterable[str],
        reconciled_obligation_ids: Iterable[str],
        prior_candidate_union: Iterable[str] = (),
        candidate_union: Iterable[str] = (),
        prior_evidence_union: Iterable[str] = (),
        evidence_union: Iterable[str] = (),
        prior_alias_map: Mapping[str, Iterable[str] | str] | None = None,
        alias_map: Mapping[str, Iterable[str] | str] | None = None,
        integrity_violations: Iterable[str] = (),
    ) -> "AttentionStopBindings":
        if denominator.scope_digest != scope.scope_digest:
            raise AdaptiveAttentionError(
                "stop bindings scope and denominator differ"
            )
        receipts = tuple(
            sorted(terminal_receipts, key=lambda row: row.channel_id)
        )
        if any(not isinstance(row, ChannelTerminalReceipt) for row in receipts):
            raise TypeError("terminal receipt has an invalid type")
        if len({row.channel_id for row in receipts}) != len(receipts):
            raise AdaptiveAttentionError("duplicate terminal channel receipt")

        def normalize_aliases(
            values: Mapping[str, Iterable[str] | str] | None,
        ) -> tuple[tuple[str, tuple[str, ...]], ...]:
            result = []
            for alias, roots in (values or {}).items():
                roots_value = (roots,) if isinstance(roots, str) else roots
                result.append(
                    (
                        _canonical_id(alias, "candidate alias"),
                        _sorted_unique_text(
                            roots_value, "candidate root identity"
                        ),
                    )
                )
            return tuple(sorted(result))

        values: dict[str, Any] = {
            "scope_digest": _sha256(scope.scope_digest, "scope_digest"),
            "denominator_digest": _sha256(
                denominator.denominator_digest, "denominator_digest"
            ),
            "denominator_rows": tuple(
                (
                    row.obligation_id,
                    row.row_digest,
                    tuple(
                        binding.binding_digest
                        for binding in row.source_bindings
                    ),
                )
                for row in denominator.obligations
            ),
            "effective_roster_digest": _sha256(
                effective_roster_digest_value,
                "effective_roster_digest",
            ),
            "terminal_receipts": receipts,
            "joined_channel_ids": tuple(
                sorted(
                    {
                        _canonical_id(value, "joined channel identity")
                        for value in joined_channel_ids
                    }
                )
            ),
            "reconciled_obligation_ids": tuple(
                sorted(
                    {
                        _canonical_id(value, "reconciled obligation identity")
                        for value in reconciled_obligation_ids
                    }
                )
            ),
            "prior_candidate_union": _sorted_unique_text(
                prior_candidate_union, "prior candidate identity"
            ),
            "candidate_union": _sorted_unique_text(
                candidate_union, "candidate identity"
            ),
            "prior_evidence_union": _sorted_unique_text(
                prior_evidence_union, "prior evidence identity"
            ),
            "evidence_union": _sorted_unique_text(
                evidence_union, "evidence identity"
            ),
            "prior_alias_map": normalize_aliases(prior_alias_map),
            "alias_map": normalize_aliases(alias_map),
            "integrity_violations": tuple(
                sorted(
                    {
                        _safe_text(value, "integrity violation").upper()
                        for value in integrity_violations
                    }
                )
            ),
        }
        payload = {
            "schema_version": ATTENTION_STOP_BINDINGS_SCHEMA,
            **{
                key: (
                    [row.to_dict() for row in item]
                    if key == "terminal_receipts"
                    else (
                        [[alias, list(roots)] for alias, roots in item]
                        if key in {"prior_alias_map", "alias_map"}
                        else [
                            [obligation_id, row_digest, list(source_digests)]
                            for (
                                obligation_id,
                                row_digest,
                                source_digests,
                            ) in item
                        ]
                        if key == "denominator_rows"
                        else list(item)
                        if isinstance(item, tuple)
                        else item
                    )
                )
                for key, item in values.items()
            },
        }
        return cls(**values, bindings_digest=digest_json(payload))

    def alias_map_dict(self) -> dict[str, tuple[str, ...]]:
        return dict(self.alias_map)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_STOP_BINDINGS_SCHEMA,
            "scope_digest": self.scope_digest,
            "denominator_digest": self.denominator_digest,
            "denominator_rows": [
                [obligation_id, row_digest, list(source_digests)]
                for obligation_id, row_digest, source_digests
                in self.denominator_rows
            ],
            "effective_roster_digest": self.effective_roster_digest,
            "terminal_receipts": [
                row.to_dict() for row in self.terminal_receipts
            ],
            "joined_channel_ids": list(self.joined_channel_ids),
            "reconciled_obligation_ids": list(
                self.reconciled_obligation_ids
            ),
            "prior_candidate_union": list(
                self.prior_candidate_union
            ),
            "candidate_union": list(self.candidate_union),
            "prior_evidence_union": list(
                self.prior_evidence_union
            ),
            "evidence_union": list(self.evidence_union),
            "prior_alias_map": [
                [alias, list(roots)]
                for alias, roots in self.prior_alias_map
            ],
            "alias_map": [
                [alias, list(roots)] for alias, roots in self.alias_map
            ],
            "integrity_violations": list(self.integrity_violations),
            "bindings_digest": self.bindings_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionStopBindings":
        expected = {
            "schema_version",
            "scope_digest",
            "denominator_digest",
            "denominator_rows",
            "effective_roster_digest",
            "terminal_receipts",
            "joined_channel_ids",
            "reconciled_obligation_ids",
            "prior_candidate_union",
            "candidate_union",
            "prior_evidence_union",
            "evidence_union",
            "prior_alias_map",
            "alias_map",
            "integrity_violations",
            "bindings_digest",
        }
        _exact_keys(value, expected, "attention stop bindings")
        if value["schema_version"] != ATTENTION_STOP_BINDINGS_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention stop bindings schema"
            )
        if not isinstance(value["terminal_receipts"], list):
            raise AdaptiveAttentionError(
                "terminal_receipts must be an array"
            )

        def text_tuple(
            field: str,
            *,
            canonical_id: bool = False,
            uppercase: bool = False,
        ) -> tuple[str, ...]:
            raw = value[field]
            if not isinstance(raw, list):
                raise AdaptiveAttentionError(f"{field} must be an array")
            normalized = tuple(
                (
                    _canonical_id(item, field)
                    if canonical_id
                    else _safe_text(item, field)
                )
                for item in raw
            )
            if uppercase:
                normalized = tuple(item.upper() for item in normalized)
            if normalized != tuple(sorted(set(normalized))):
                raise AdaptiveAttentionError(
                    f"{field} must be canonical and unique"
                )
            return normalized

        def aliases(field: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
            raw = value[field]
            if not isinstance(raw, list):
                raise AdaptiveAttentionError(f"{field} must be an array")
            result = []
            for item in raw:
                if (
                    not isinstance(item, list)
                    or len(item) != 2
                    or not isinstance(item[1], list)
                ):
                    raise AdaptiveAttentionError(
                        f"{field} contains a malformed alias"
                    )
                roots = tuple(
                    _safe_text(root, field) for root in item[1]
                )
                if roots != tuple(sorted(set(roots))):
                    raise AdaptiveAttentionError(
                        f"{field} roots must be canonical and unique"
                    )
                result.append(
                    (_canonical_id(item[0], field), roots)
                )
            normalized = tuple(result)
            if normalized != tuple(sorted(normalized)):
                raise AdaptiveAttentionError(
                    f"{field} must be canonical"
                )
            if len({alias for alias, _roots in normalized}) != len(
                normalized
            ):
                raise AdaptiveAttentionError(
                    f"{field} aliases must be unique"
                )
            return normalized

        bindings_digest = _sha256(
            value["bindings_digest"], "bindings_digest"
        )
        payload = dict(value)
        payload.pop("bindings_digest")
        if digest_json(payload) != bindings_digest:
            raise AdaptiveAttentionError(
                "attention stop bindings content does not replay"
            )
        raw_denominator_rows = value["denominator_rows"]
        if not isinstance(raw_denominator_rows, list):
            raise AdaptiveAttentionError(
                "denominator_rows must be an array"
            )
        denominator_rows = []
        for item in raw_denominator_rows:
            if (
                not isinstance(item, list)
                or len(item) != 3
                or not isinstance(item[2], list)
            ):
                raise AdaptiveAttentionError(
                    "denominator row binding is malformed"
                )
            denominator_rows.append(
                (
                    _canonical_id(item[0], "denominator obligation identity"),
                    _sha256(item[1], "denominator row digest"),
                    tuple(
                        _sha256(source, "source binding digest")
                        for source in item[2]
                    ),
                )
            )
        if tuple(denominator_rows) != tuple(
            sorted(denominator_rows, key=lambda row: row[0])
        ) or len({row[0] for row in denominator_rows}) != len(
            denominator_rows
        ):
            raise AdaptiveAttentionError(
                "denominator row bindings must be canonical and unique"
            )
        terminal_receipts = tuple(
            ChannelTerminalReceipt.from_dict(item)
            for item in value["terminal_receipts"]
        )
        if terminal_receipts != tuple(
            sorted(terminal_receipts, key=lambda row: row.channel_id)
        ) or len({row.channel_id for row in terminal_receipts}) != len(
            terminal_receipts
        ):
            raise AdaptiveAttentionError(
                "terminal receipts must be canonical and unique"
            )
        replayed = cls(
            scope_digest=_sha256(value["scope_digest"], "scope_digest"),
            denominator_digest=_sha256(
                value["denominator_digest"], "denominator_digest"
            ),
            denominator_rows=tuple(denominator_rows),
            effective_roster_digest=_sha256(
                value["effective_roster_digest"],
                "effective_roster_digest",
            ),
            terminal_receipts=terminal_receipts,
            joined_channel_ids=text_tuple(
                "joined_channel_ids", canonical_id=True
            ),
            reconciled_obligation_ids=text_tuple(
                "reconciled_obligation_ids", canonical_id=True
            ),
            prior_candidate_union=text_tuple(
                "prior_candidate_union"
            ),
            candidate_union=text_tuple("candidate_union"),
            prior_evidence_union=text_tuple(
                "prior_evidence_union"
            ),
            evidence_union=text_tuple("evidence_union"),
            prior_alias_map=aliases("prior_alias_map"),
            alias_map=aliases("alias_map"),
            integrity_violations=text_tuple(
                "integrity_violations", uppercase=True
            ),
            bindings_digest=bindings_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention stop bindings canonical form does not replay"
            )
        return replayed


_CLOSURE_AUTHORITY_CLASS_BY_KIND = {
    "METHOD_STEP": "METHODOLOGY_APPLICATION",
    "CANDIDATE_CHALLENGE": "CENTRAL_NEGATIVE_CLOSURE",
    "VERIFIER_ITEM": "VERIFIER_COMPLETION",
    "REPORT_ITEM": "REPORT_AUTHORITY",
    "MERGE_ITEM": "CENTRAL_JOIN",
}


@dataclass(frozen=True, slots=True)
class ClosurePolicyParent:
    obligation_id: str
    obligation_row_digest: str
    closure_policy: str
    authority_class: str
    join_digest: str
    provider_receipt_digest: str
    parent_digest: str

    @classmethod
    def create(
        cls,
        *,
        obligation: AttentionObligation,
        join_projection: AttentionJoinProjection,
        authority_class: str,
        provider_receipt_digest: str,
    ) -> "ClosurePolicyParent":
        if not isinstance(obligation, AttentionObligation):
            raise TypeError(
                "obligation must be an AttentionObligation"
            )
        if not isinstance(join_projection, AttentionJoinProjection):
            raise TypeError(
                "join_projection must be an AttentionJoinProjection"
            )
        AttentionObligation.from_dict(obligation.to_dict())
        AttentionJoinProjection.from_dict(join_projection.to_dict())
        expected_class = _CLOSURE_AUTHORITY_CLASS_BY_KIND.get(
            obligation.kind,
            "EVIDENCE_CLOSURE_BROKER",
        )
        authority_value = _safe_text(
            authority_class, "closure authority class"
        ).upper()
        if authority_value != expected_class:
            raise AdaptiveAttentionError(
                "closure parent authority class does not implement the "
                "obligation policy"
            )
        payload = {
            "schema_version": CLOSURE_POLICY_PARENT_SCHEMA,
            "obligation_id": obligation.obligation_id,
            "obligation_row_digest": obligation.row_digest,
            "closure_policy": obligation.closure_policy,
            "authority_class": authority_value,
            "join_digest": join_projection.join_digest,
            "provider_receipt_digest": _sha256(
                provider_receipt_digest,
                "provider_receipt_digest",
            ),
        }
        return cls(
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
            parent_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CLOSURE_POLICY_PARENT_SCHEMA,
            "obligation_id": self.obligation_id,
            "obligation_row_digest": self.obligation_row_digest,
            "closure_policy": self.closure_policy,
            "authority_class": self.authority_class,
            "join_digest": self.join_digest,
            "provider_receipt_digest": self.provider_receipt_digest,
            "parent_digest": self.parent_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "ClosurePolicyParent":
        _exact_keys(
            value,
            {
                "schema_version", "obligation_id",
                "obligation_row_digest", "closure_policy",
                "authority_class", "join_digest",
                "provider_receipt_digest", "parent_digest",
            },
            "closure policy parent",
        )
        if value["schema_version"] != CLOSURE_POLICY_PARENT_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported closure policy parent schema"
            )
        payload = dict(value)
        parent_digest = payload.pop("parent_digest")
        normalized = {
            "schema_version": payload["schema_version"],
            "obligation_id": _canonical_id(
                payload["obligation_id"], "closure obligation identity"
            ),
            "obligation_row_digest": _sha256(
                payload["obligation_row_digest"],
                "closure obligation row digest",
            ),
            "closure_policy": _safe_text(
                payload["closure_policy"], "closure_policy"
            ),
            "authority_class": _safe_text(
                payload["authority_class"], "authority_class"
            ).upper(),
            "join_digest": _sha256(
                payload["join_digest"], "join_digest"
            ),
            "provider_receipt_digest": _sha256(
                payload["provider_receipt_digest"],
                "provider_receipt_digest",
            ),
        }
        if digest_json(normalized) != _sha256(
            parent_digest, "parent_digest"
        ):
            raise AdaptiveAttentionError(
                "closure policy parent content does not replay"
            )
        return cls(
            obligation_id=normalized["obligation_id"],
            obligation_row_digest=normalized[
                "obligation_row_digest"
            ],
            closure_policy=normalized["closure_policy"],
            authority_class=normalized["authority_class"],
            join_digest=normalized["join_digest"],
            provider_receipt_digest=normalized[
                "provider_receipt_digest"
            ],
            parent_digest=parent_digest,
        )


@dataclass(frozen=True, slots=True)
class AttentionClosureAuthority:
    scope_digest: str
    denominator_digest: str
    join_digest: str
    stop_bindings_digest: str
    authorized_obligation_rows: tuple[tuple[str, str], ...]
    closure_policy_parents: tuple[ClosurePolicyParent, ...]
    authority_digest: str

    @classmethod
    def create(
        cls,
        *,
        scope: AttentionScope,
        denominator: AttentionDenominator,
        join_projection: AttentionJoinProjection,
        stop_bindings: AttentionStopBindings,
        roster: AttentionRoster,
        amendments: Sequence[RosterAmendment] = (),
        closure_policy_parents: Iterable[
            ClosurePolicyParent
        ] = (),
    ) -> "AttentionClosureAuthority":
        if not isinstance(scope, AttentionScope):
            raise TypeError("scope must be an AttentionScope")
        if AttentionScope.from_dict(scope.to_dict()) != scope:
            raise AdaptiveAttentionError(
                "closure authority scope does not replay"
            )
        if not isinstance(denominator, AttentionDenominator):
            raise TypeError(
                "denominator must be an AttentionDenominator"
            )
        if AttentionDenominator.from_dict(
            denominator.to_dict()
        ) != denominator:
            raise AdaptiveAttentionError(
                "closure authority denominator does not replay"
            )
        if not isinstance(join_projection, AttentionJoinProjection):
            raise TypeError(
                "join_projection must be AttentionJoinProjection"
            )
        if not isinstance(stop_bindings, AttentionStopBindings):
            raise TypeError(
                "stop_bindings must be AttentionStopBindings"
            )
        if not isinstance(roster, AttentionRoster):
            raise TypeError("roster must be an AttentionRoster")
        AttentionJoinProjection.from_dict(join_projection.to_dict())
        AttentionStopBindings.from_dict(stop_bindings.to_dict())
        if not join_projection.scope_digest:
            raise AdaptiveAttentionError(
                "closure authority requires an authenticated join lineage"
            )
        if join_projection.authority_debt_reason_codes:
            raise AdaptiveAttentionError(
                "closure authority cannot consume unresolved runtime "
                "authority debt"
            )
        effective_digest = effective_roster_digest(roster, amendments)
        if (
            join_projection.scope_digest != scope.scope_digest
            or join_projection.effective_roster_digest
            != effective_digest
        ):
            raise AdaptiveAttentionError(
                "closure authority join lineage binding differs"
            )
        if stop_bindings.effective_roster_digest != effective_digest:
            raise AdaptiveAttentionError(
                "closure authority roster binding differs"
            )
        active_channels, effective_debt, effective_rows = (
            effective_roster_material(roster, amendments)
        )
        channels_by_id = {
            channel.channel_id: channel for channel in active_channels
        }
        if len(channels_by_id) != len(active_channels):
            raise AdaptiveAttentionError(
                "closure authority roster contains duplicate channels"
            )
        terminal_by_id = {
            receipt.channel_id: receipt
            for receipt in stop_bindings.terminal_receipts
        }
        if set(terminal_by_id) != set(channels_by_id):
            raise AdaptiveAttentionError(
                "closure authority requires exact terminal channel coverage"
            )
        if any(
            terminal_by_id[channel_id].channel_row_digest
            != channel.row_digest
            for channel_id, channel in channels_by_id.items()
        ):
            raise AdaptiveAttentionError(
                "closure authority terminal channel binding is stale"
            )
        accepted_terminal_by_id = {
            receipt.channel_id: receipt
            for receipt in join_projection.accepted_terminal_receipts
        }
        if set(accepted_terminal_by_id) != set(channels_by_id):
            raise AdaptiveAttentionError(
                "closure authority requires accepted evidence for every "
                "active channel"
            )
        if any(
            terminal_by_id[channel_id].receipt_digest
            != accepted_terminal_by_id[channel_id].receipt_digest
            for channel_id in channels_by_id
        ):
            raise AdaptiveAttentionError(
                "stop terminal differs from the accepted attempt "
                "transaction"
            )
        if (
            denominator.scope_digest != scope.scope_digest
            or stop_bindings.scope_digest != scope.scope_digest
        ):
            raise AdaptiveAttentionError(
                "closure authority scope bindings differ"
            )
        if (
            stop_bindings.denominator_digest
            != denominator.denominator_digest
        ):
            raise AdaptiveAttentionError(
                "closure authority denominator binding differs"
            )
        expected_denominator_rows = tuple(
            (
                row.obligation_id,
                row.row_digest,
                tuple(
                    binding.binding_digest
                    for binding in row.source_bindings
                ),
            )
            for row in denominator.obligations
        )
        if stop_bindings.denominator_rows != expected_denominator_rows:
            raise AdaptiveAttentionError(
                "closure authority denominator rows differ"
            )
        projected_by_id = {
            row.obligation_id: row
            for row in join_projection.denominator_obligations
        }
        if len(projected_by_id) != len(
            join_projection.denominator_obligations
        ):
            raise AdaptiveAttentionError(
                "closure authority join denominator has duplicates"
            )
        for base_row in denominator.obligations:
            projected = projected_by_id.get(base_row.obligation_id)
            if projected is None:
                raise AdaptiveAttentionError(
                    "closure authority join omits denominator obligation"
                )
            replayed_base = replace(
                projected,
                state=base_row.state,
                closure_authority_digest=(
                    base_row.closure_authority_digest
                ),
                row_digest=base_row.row_digest,
            )
            if replayed_base != base_row:
                raise AdaptiveAttentionError(
                    "closure authority join rewrites denominator rows"
                )
        non_evidenced = [
            row.obligation_id
            for row in join_projection.denominator_obligations
            if row.state != "EVIDENCED"
        ]
        if non_evidenced:
            raise AdaptiveAttentionError(
                "closure authority has unresolved challenge or "
                "non-EVIDENCED obligations: "
                + ",".join(non_evidenced)
            )
        join_denominator_ids = set(projected_by_id)
        chain_denominator_ids = {
            obligation_id for obligation_id, _row_digest in effective_rows
        }
        if chain_denominator_ids != join_denominator_ids:
            raise AdaptiveAttentionError(
                "closure authority roster denominator differs from join"
            )
        if effective_debt:
            raise AdaptiveAttentionError(
                "closure authority cannot consume uncovered debt"
            )
        if stop_bindings.integrity_violations:
            raise AdaptiveAttentionError(
                "closure authority cannot consume integrity violations"
            )
        if any(
            receipt.terminal_state != "COMMITTED"
            for receipt in stop_bindings.terminal_receipts
        ):
            raise AdaptiveAttentionError(
                "closure authority requires committed terminal receipts"
            )
        committed = {
            receipt.channel_id
            for receipt in stop_bindings.terminal_receipts
        }
        if set(stop_bindings.joined_channel_ids) != committed:
            raise AdaptiveAttentionError(
                "closure authority requires exact committed joins"
            )
        scheduled_obligations = {
            obligation_id
            for channel in active_channels
            for obligation_id in channel.obligation_ids
        }
        if scheduled_obligations != join_denominator_ids:
            raise AdaptiveAttentionError(
                "closure authority scheduled work differs from join "
                "denominator"
            )
        if set(stop_bindings.reconciled_obligation_ids) != (
            scheduled_obligations
        ):
            raise AdaptiveAttentionError(
                "closure authority requires exact obligation joins"
            )
        authorized = tuple(
            (
                row.obligation_id,
                row.row_digest,
            )
            for row in join_projection.denominator_obligations
        )
        parents = tuple(
            sorted(
                (
                    ClosurePolicyParent.from_dict(parent.to_dict())
                    if isinstance(parent, ClosurePolicyParent)
                    else ClosurePolicyParent.from_dict(parent)
                    for parent in closure_policy_parents
                ),
                key=lambda row: row.obligation_id,
            )
        )
        if len({row.obligation_id for row in parents}) != len(parents):
            raise AdaptiveAttentionError(
                "closure policy parents contain duplicate obligations"
            )
        parents_by_id = {
            parent.obligation_id: parent for parent in parents
        }
        if set(parents_by_id) != join_denominator_ids:
            raise AdaptiveAttentionError(
                "closure authority requires one policy parent per "
                "denominator obligation"
            )
        for row in join_projection.denominator_obligations:
            parent = parents_by_id[row.obligation_id]
            expected_class = _CLOSURE_AUTHORITY_CLASS_BY_KIND.get(
                row.kind, "EVIDENCE_CLOSURE_BROKER"
            )
            if (
                parent.obligation_row_digest != row.row_digest
                or parent.closure_policy != row.closure_policy
                or parent.authority_class != expected_class
                or parent.join_digest != join_projection.join_digest
            ):
                raise AdaptiveAttentionError(
                    "closure policy parent is stale or policy-incompatible"
                )
        payload = {
            "schema_version": ATTENTION_CLOSURE_AUTHORITY_SCHEMA,
            "scope_digest": scope.scope_digest,
            "denominator_digest": denominator.denominator_digest,
            "join_digest": join_projection.join_digest,
            "stop_bindings_digest": stop_bindings.bindings_digest,
            "authorized_obligation_rows": [
                [obligation_id, row_digest]
                for obligation_id, row_digest in authorized
            ],
            "closure_policy_parent_digests": [
                parent.parent_digest for parent in parents
            ],
        }
        return cls(
            scope_digest=scope.scope_digest,
            denominator_digest=denominator.denominator_digest,
            join_digest=join_projection.join_digest,
            stop_bindings_digest=stop_bindings.bindings_digest,
            authorized_obligation_rows=authorized,
            closure_policy_parents=parents,
            authority_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_CLOSURE_AUTHORITY_SCHEMA,
            "scope_digest": self.scope_digest,
            "denominator_digest": self.denominator_digest,
            "join_digest": self.join_digest,
            "stop_bindings_digest": self.stop_bindings_digest,
            "authorized_obligation_rows": [
                [obligation_id, row_digest]
                for obligation_id, row_digest
                in self.authorized_obligation_rows
            ],
            "closure_policy_parents": [
                parent.to_dict() for parent in self.closure_policy_parents
            ],
            "authority_digest": self.authority_digest,
        }

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AttentionClosureAuthority":
        _exact_keys(
            value,
            {
                "schema_version", "scope_digest",
                "denominator_digest", "join_digest",
                "stop_bindings_digest",
                "authorized_obligation_rows", "closure_policy_parents",
                "authority_digest",
            },
            "attention closure authority",
        )
        if value["schema_version"] != ATTENTION_CLOSURE_AUTHORITY_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention closure authority schema"
            )
        if not isinstance(value["authorized_obligation_rows"], list):
            raise AdaptiveAttentionError(
                "authorized_obligation_rows must be an array"
            )
        rows = []
        for item in value["authorized_obligation_rows"]:
            if not isinstance(item, list) or len(item) != 2:
                raise AdaptiveAttentionError(
                    "authorized obligation row is malformed"
                )
            rows.append(
                (
                    _canonical_id(item[0], "authorized obligation identity"),
                    _sha256(item[1], "authorized obligation row digest"),
                )
            )
        if tuple(rows) != tuple(sorted(rows)) or len(
            {obligation_id for obligation_id, _digest in rows}
        ) != len(rows):
            raise AdaptiveAttentionError(
                "authorized obligation rows must be canonical and unique"
            )
        parents = tuple(
            ClosurePolicyParent.from_dict(item)
            for item in value["closure_policy_parents"]
        )
        if parents != tuple(
            sorted(parents, key=lambda row: row.obligation_id)
        ) or len({row.obligation_id for row in parents}) != len(parents):
            raise AdaptiveAttentionError(
                "closure policy parents must be canonical and unique"
            )
        payload = {
            "schema_version": ATTENTION_CLOSURE_AUTHORITY_SCHEMA,
            "scope_digest": value["scope_digest"],
            "denominator_digest": value["denominator_digest"],
            "join_digest": value["join_digest"],
            "stop_bindings_digest": value["stop_bindings_digest"],
            "authorized_obligation_rows": value[
                "authorized_obligation_rows"
            ],
            "closure_policy_parent_digests": [
                parent.parent_digest for parent in parents
            ],
        }
        authority_digest = value["authority_digest"]
        if digest_json(payload) != _sha256(
            authority_digest, "authority_digest"
        ):
            raise AdaptiveAttentionError(
                "attention closure authority content does not replay"
            )
        replayed = cls(
            scope_digest=_sha256(value["scope_digest"], "scope_digest"),
            denominator_digest=_sha256(
                value["denominator_digest"], "denominator_digest"
            ),
            join_digest=_sha256(value["join_digest"], "join_digest"),
            stop_bindings_digest=_sha256(
                value["stop_bindings_digest"],
                "stop_bindings_digest",
            ),
            authorized_obligation_rows=tuple(rows),
            closure_policy_parents=parents,
            authority_digest=authority_digest,
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention closure authority canonical form does not replay"
            )
        return replayed


@dataclass(frozen=True, slots=True)
class AttentionStopReceipt:
    classification: str
    denominator_digest: str
    effective_roster_digest: str
    unresolved_obligation_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    clean_full_assurance_claim_allowed: bool
    stop_digest: str

    @classmethod
    def create(
        cls,
        *,
        classification: str,
        denominator_digest: str,
        effective_roster_digest_value: str,
        unresolved_obligation_ids: Iterable[str],
        reason_codes: Iterable[str],
        clean_full_assurance_claim_allowed: bool,
    ) -> "AttentionStopReceipt":
        classification_value = _enum(
            classification,
            STOP_CLASSIFICATIONS,
            "stop classification",
        )
        unresolved = tuple(
            sorted(
                {
                    _canonical_id(
                        value, "unresolved obligation identity"
                    )
                    for value in unresolved_obligation_ids
                }
            )
        )
        reasons = tuple(
            sorted(
                {
                    _safe_text(value, "stop reason code").upper()
                    for value in reason_codes
                }
            )
        )
        clean_allowed = _boolean(
            clean_full_assurance_claim_allowed,
            "clean_full_assurance_claim_allowed",
        )
        if classification_value == "CLEAN_STOP":
            if unresolved or reasons or not clean_allowed:
                raise AdaptiveAttentionError(
                    "clean stop cannot contain unresolved work or debt"
                )
        elif clean_allowed:
            raise AdaptiveAttentionError(
                "non-clean stop cannot allow a clean assurance claim"
            )
        payload = {
            "schema_version": ATTENTION_STOP_SCHEMA,
            "classification": classification_value,
            "denominator_digest": _sha256(
                denominator_digest, "denominator_digest"
            ),
            "effective_roster_digest": _sha256(
                effective_roster_digest_value,
                "effective_roster_digest",
            ),
            "unresolved_obligation_ids": list(unresolved),
            "reason_codes": list(reasons),
            "clean_full_assurance_claim_allowed": clean_allowed,
        }
        return cls(
            classification=classification_value,
            denominator_digest=payload["denominator_digest"],
            effective_roster_digest=payload[
                "effective_roster_digest"
            ],
            unresolved_obligation_ids=unresolved,
            reason_codes=reasons,
            clean_full_assurance_claim_allowed=clean_allowed,
            stop_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_STOP_SCHEMA,
            "classification": self.classification,
            "denominator_digest": self.denominator_digest,
            "effective_roster_digest": self.effective_roster_digest,
            "unresolved_obligation_ids": list(
                self.unresolved_obligation_ids
            ),
            "reason_codes": list(self.reason_codes),
            "clean_full_assurance_claim_allowed": (
                self.clean_full_assurance_claim_allowed
            ),
            "stop_digest": self.stop_digest,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AttentionStopReceipt":
        _exact_keys(
            value,
            {
                "schema_version", "classification", "denominator_digest",
                "effective_roster_digest", "unresolved_obligation_ids",
                "reason_codes", "clean_full_assurance_claim_allowed",
                "stop_digest",
            },
            "attention stop receipt",
        )
        if value["schema_version"] != ATTENTION_STOP_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported attention stop receipt schema"
            )
        replayed = cls.create(
            classification=value["classification"],
            denominator_digest=value["denominator_digest"],
            effective_roster_digest_value=value[
                "effective_roster_digest"
            ],
            unresolved_obligation_ids=value[
                "unresolved_obligation_ids"
            ],
            reason_codes=value["reason_codes"],
            clean_full_assurance_claim_allowed=value[
                "clean_full_assurance_claim_allowed"
            ],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "attention stop receipt content does not replay"
            )
        return replayed


def _artifact_to_json(self: Any) -> str:
    return canonical_json(self.to_dict())


def _artifact_from_json(cls: type[Any], text: str) -> Any:
    value = strict_json_loads(text)
    if not isinstance(value, Mapping):
        raise AdaptiveAttentionError(
            f"{cls.__name__} JSON must be an object"
        )
    return cls.from_dict(value)


for _artifact_class in (
    SourceBinding,
    MethodologyBinding,
    AttentionScope,
    AttentionObligation,
    EvidenceSlice,
    RuntimeCapabilityPolicy,
    ResourceReservation,
    AttentionBudget,
    ChannelTemplate,
    EvidenceChannel,
    AttentionDebt,
    AttentionDenominator,
    AttentionRoster,
    AmendmentObligationOperation,
    RosterAmendment,
    AttentionGenesisAuthority,
    AttentionPlan,
    AttentionJoinProjection,
    WorkerReceipt,
    ChannelTerminalReceipt,
    ChannelAttemptAuthority,
    AcceptedEvidenceReceipt,
    AttentionStopBindings,
    ClosurePolicyParent,
    AttentionClosureAuthority,
    AttentionStopReceipt,
):
    if not hasattr(_artifact_class, "to_json"):
        setattr(_artifact_class, "to_json", _artifact_to_json)
    if not hasattr(_artifact_class, "from_json"):
        setattr(
            _artifact_class,
            "from_json",
            classmethod(_artifact_from_json),
        )


__all__ = [
    "AdaptiveAttentionError",
    "AcceptedEvidenceReceipt",
    "AmendmentObligationOperation",
    "AttentionBudget",
    "AttentionDebt",
    "AttentionDenominator",
    "AttentionJoinProjection",
    "AttentionGenesisAuthority",
    "AttentionObligation",
    "AttentionPlan",
    "AttentionRoster",
    "AttentionScope",
    "AttentionStopReceipt",
    "AttentionStopBindings",
    "AttentionClosureAuthority",
    "ChannelTerminalReceipt",
    "ChannelAttemptAuthority",
    "ChannelTemplate",
    "EvidenceChannel",
    "EvidenceSlice",
    "ClosurePolicyParent",
    "MethodologyBinding",
    "ResourceReservation",
    "RosterAmendment",
    "RuntimeCapabilityPolicy",
    "SourceBinding",
    "WorkerReceipt",
    "canonical_json",
    "channels_have_independent_evidence",
    "digest_json",
    "effective_roster_digest",
    "effective_roster_material",
    "strict_json_loads",
    "transition_obligation",
    "validate_obligation_transition",
]
