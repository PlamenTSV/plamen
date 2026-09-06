"""Pure adapters from typed fixture rows to attention obligations.

Adapters never launch providers, mutate source authorities, or authorize
closure.  Missing and bounded providers are represented as obligations so a
caller cannot accidentally interpret absent enrichment as complete coverage.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from adaptive_attention_types import (
    AdaptiveAttentionError,
    AttentionObligation,
    AttentionScope,
    MethodologyBinding,
    SourceBinding,
    canonical_json,
    digest_json,
    transition_obligation,
)


ATTENTION_SOURCES_SCHEMA = "plamen.attention_sources.v1"
GRAPH_AUTHORITY_SCHEMA = "plamen.attention_graph_authority.v1"
_COVERAGE_ORDER = {"EXACT": 0, "LOWER_BOUND": 1, "UNKNOWN": 2}
_SOURCE_ROW_FIELDS = frozenset(
    {
        "provider", "kind", "canonical_id", "subject_ids",
        "artifact_identity", "artifact_sha256", "source_binding",
        "methodology_bindings", "predecessor_receipt_digests",
        "closure_policy", "mandatory", "impact_rank",
        "uncertainty_class", "graph_origin", "role_family",
        "methodology_family", "source_class", "proof_environment",
        "required_tool_classes", "dependency_fanout",
        "closure_blocking", "enrichment_only", "debt_reason_code",
        "clearing_condition",
    }
)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveAttentionError(f"{field} must be non-empty text")
    return value.strip()


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise AdaptiveAttentionError(f"{field} must be a boolean")
    return value


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdaptiveAttentionError(f"{field} must be an integer")
    return value


def _count_semantics(value: Any) -> str:
    normalized = _text(value, "count_semantics").upper()
    if normalized not in _COVERAGE_ORDER:
        raise AdaptiveAttentionError(
            "count_semantics must be EXACT, LOWER_BOUND, or UNKNOWN"
        )
    return normalized


def _combine_coverage(values: Iterable[str]) -> str:
    normalized = tuple(values)
    if not normalized:
        return "EXACT"
    return max(normalized, key=lambda value: _COVERAGE_ORDER[value])


@dataclass(frozen=True, slots=True)
class AdaptedAttentionSources:
    obligations: tuple[AttentionObligation, ...]
    coverage_kind: str
    provider_debt_ids: tuple[str, ...]
    source_digest: str

    @classmethod
    def create(
        cls,
        *,
        obligations: Iterable[AttentionObligation],
        coverage_kind: str,
    ) -> "AdaptedAttentionSources":
        coverage = _count_semantics(coverage_kind)
        by_id: dict[str, AttentionObligation] = {}
        for row in obligations:
            existing = by_id.get(row.obligation_id)
            if existing is not None and existing.row_digest != row.row_digest:
                raise AdaptiveAttentionError(
                    "duplicate obligation identity has divergent rows: "
                    + row.obligation_id
                )
            by_id[row.obligation_id] = row
        rows = tuple(sorted(by_id.values(), key=lambda row: row.obligation_id))
        provider_debt_ids = tuple(
            row.obligation_id
            for row in rows
            if row.kind == "PROVIDER_DEBT"
        )
        payload = {
            "schema_version": ATTENTION_SOURCES_SCHEMA,
            "coverage_kind": coverage,
            "obligation_row_digests": [row.row_digest for row in rows],
            "provider_debt_ids": list(provider_debt_ids),
        }
        return cls(
            obligations=rows,
            coverage_kind=coverage,
            provider_debt_ids=provider_debt_ids,
            source_digest=digest_json(payload),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ATTENTION_SOURCES_SCHEMA,
            "coverage_kind": self.coverage_kind,
            "obligations": [row.to_dict() for row in self.obligations],
            "provider_debt_ids": list(self.provider_debt_ids),
            "source_digest": self.source_digest,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "AdaptedAttentionSources":
        expected = {
            "schema_version", "coverage_kind", "obligations",
            "provider_debt_ids", "source_digest",
        }
        if not isinstance(value, Mapping):
            raise TypeError("adapted attention sources must be an object")
        if set(value) != expected:
            raise AdaptiveAttentionError(
                "adapted attention source fields differ"
            )
        if value["schema_version"] != ATTENTION_SOURCES_SCHEMA:
            raise AdaptiveAttentionError(
                "unsupported adapted attention sources schema"
            )
        if not isinstance(value["obligations"], list):
            raise AdaptiveAttentionError("obligations must be an array")
        replayed = cls.create(
            obligations=(
                AttentionObligation.from_dict(item)
                for item in value["obligations"]
            ),
            coverage_kind=value["coverage_kind"],
        )
        if replayed.to_dict() != dict(value):
            raise AdaptiveAttentionError(
                "adapted attention sources content does not replay"
            )
        return replayed

    @classmethod
    def from_json(cls, text: str) -> "AdaptedAttentionSources":
        from adaptive_attention_types import strict_json_loads

        value = strict_json_loads(text)
        if not isinstance(value, Mapping):
            raise AdaptiveAttentionError(
                "adapted attention sources JSON must be an object"
            )
        return cls.from_dict(value)


def _source_binding_from_row(row: Mapping[str, Any]) -> SourceBinding:
    if "source_binding" in row:
        return SourceBinding.create(row["source_binding"])
    return SourceBinding.create(
        _text(row.get("artifact_identity"), "artifact_identity"),
        _text(row.get("artifact_sha256"), "artifact_sha256"),
    )


def _methodology_bindings(
    row: Mapping[str, Any],
) -> tuple[MethodologyBinding, ...]:
    raw = row.get("methodology_bindings", ())
    if raw is None:
        return ()
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise AdaptiveAttentionError(
            "methodology_bindings must be an array"
        )
    return tuple(MethodologyBinding.create(value) for value in raw)


def _adapt_row(
    *, scope: AttentionScope, row: Mapping[str, Any]
) -> AttentionObligation:
    if not isinstance(row, Mapping):
        raise TypeError("attention source row must be an object")
    unknown = set(row) - _SOURCE_ROW_FIELDS - {"state"}
    if unknown:
        raise AdaptiveAttentionError(
            "attention source row has unexpected fields: "
            + ",".join(sorted(unknown))
        )
    if "state" in row:
        raise AdaptiveAttentionError(
            "source rows cannot supply controller-owned state"
        )
    provider = _text(row.get("provider"), "provider")
    kind = _text(row.get("kind"), "kind").upper()
    subject_ids = row.get("subject_ids")
    if not isinstance(subject_ids, Sequence) or isinstance(
        subject_ids, (str, bytes)
    ):
        raise AdaptiveAttentionError("subject_ids must be an array")
    canonical_id_value = row.get("canonical_id")
    canonical_id = (
        _text(canonical_id_value, "canonical_id")
        if canonical_id_value is not None
        else None
    )
    impact = _integer(row.get("impact_rank", 1), "impact_rank")
    mandatory = row.get("mandatory", True)
    if not isinstance(mandatory, bool):
        raise AdaptiveAttentionError("mandatory must be a boolean")
    uncovered = AttentionObligation.create(
        scope=scope,
        canonical_id=canonical_id,
        kind=kind,
        subject_ids=subject_ids,
        source_bindings=(_source_binding_from_row(row),),
        methodology_bindings=_methodology_bindings(row),
        predecessor_receipt_digests=row.get(
            "predecessor_receipt_digests", ()
        ),
        closure_policy=_text(
            row.get("closure_policy"), "closure_policy"
        ),
        mandatory=mandatory,
        impact_rank=impact,
        uncertainty_class=_text(
            row.get("uncertainty_class", "NONE"),
            "uncertainty_class",
        ).upper(),
        graph_origin=_text(
            row.get("graph_origin", "BASELINE"), "graph_origin"
        ).upper(),
        state="UNCOVERED",
        role_family=_text(
            row.get("role_family", "analysis"), "role_family"
        ),
        methodology_family=_text(
            row.get("methodology_family", "baseline"),
            "methodology_family",
        ),
        source_class=_text(
            row.get("source_class", provider), "source_class"
        ),
        proof_environment=_text(
            row.get("proof_environment", "static"),
            "proof_environment",
        ),
        required_tool_classes=row.get("required_tool_classes", ()),
        dependency_fanout=_integer(
            row.get("dependency_fanout", 0), "dependency_fanout"
        ),
        closure_blocking=_bool(
            row.get("closure_blocking", True), "closure_blocking"
        ),
        enrichment_only=_bool(
            row.get("enrichment_only", False), "enrichment_only"
        ),
        debt_reason_code=(
            _text(row["debt_reason_code"], "debt_reason_code")
            if row.get("debt_reason_code")
            else ""
        ),
        provider=provider,
        clearing_condition=(
            _text(row["clearing_condition"], "clearing_condition")
            if row.get("clearing_condition")
            else ""
        ),
    )
    return uncovered


def _provider_debt_row(
    *,
    scope: AttentionScope,
    provider: str,
    reason_code: str,
    clearing_condition: str,
    required: bool,
    count_semantics: str,
    canonical_id: str | None = None,
    subject_ids: Iterable[str] = (),
    detail_binding: Mapping[str, Any] | None = None,
) -> AttentionObligation:
    provider_value = _text(provider, "provider")
    reason = _text(reason_code, "reason_code").upper()
    coverage = _count_semantics(count_semantics)
    subjects = tuple(subject_ids) or (provider_value, reason)
    binding_payload = {
        "schema": "plamen.attention_provider_status.v1",
        "provider": provider_value,
        "reason_code": reason,
        "required": _bool(required, "required"),
        "count_semantics": coverage,
        "clearing_condition": _text(
            clearing_condition, "clearing_condition"
        ),
        "detail_binding": dict(detail_binding or {}),
    }
    source = SourceBinding.create(
        f"provider:{provider_value}",
        digest_json(binding_payload),
    )
    uncovered = AttentionObligation.create(
        scope=scope,
        canonical_id=canonical_id,
        kind="PROVIDER_DEBT",
        subject_ids=subjects,
        source_bindings=(source,),
        closure_policy="provider-current-recompile",
        mandatory=required,
        impact_rank=1,
        uncertainty_class=(
            "UNKNOWN_DENOMINATOR"
            if coverage != "EXACT"
            else "MISSING_EVIDENCE"
        ),
        graph_origin="NONE",
        state="UNCOVERED",
        role_family="provider-repair",
        methodology_family="provider-status",
        source_class="provider",
        proof_environment="authority",
        required_tool_classes=(),
        dependency_fanout=0,
        closure_blocking=required,
        enrichment_only=not required,
        debt_reason_code=reason,
        provider=provider_value,
        clearing_condition=binding_payload["clearing_condition"],
    )
    assigned = transition_obligation(uncovered, "ASSIGNED")
    return transition_obligation(assigned, "DEBT")


def adapt_provider_status(
    *,
    scope: AttentionScope,
    status: Mapping[str, Any],
) -> AdaptedAttentionSources:
    """Adapt one current/missing provider status without calling it."""

    if not isinstance(status, Mapping):
        raise TypeError("provider status must be an object")
    unknown = set(status) - {
        "provider", "available", "required", "count_semantics",
        "reason_code", "clearing_condition", "canonical_id",
        "subject_ids", "binding",
    }
    if unknown:
        raise AdaptiveAttentionError(
            "provider status has unexpected fields: "
            + ",".join(sorted(unknown))
        )
    provider = _text(status.get("provider"), "provider")
    available = _bool(status.get("available"), "available")
    coverage = _count_semantics(
        status.get("count_semantics", "EXACT")
    )
    if available:
        return AdaptedAttentionSources.create(
            obligations=(), coverage_kind=coverage
        )
    debt = _provider_debt_row(
        scope=scope,
        provider=provider,
        reason_code=_text(
            status.get("reason_code", "MISSING_PROVIDER"),
            "reason_code",
        ),
        clearing_condition=_text(
            status.get(
                "clearing_condition", "provider becomes current"
            ),
            "clearing_condition",
        ),
        required=_bool(status.get("required", True), "required"),
        count_semantics=coverage,
        canonical_id=(
            _text(status["canonical_id"], "canonical_id")
            if status.get("canonical_id")
            else None
        ),
        subject_ids=status.get("subject_ids", ()),
        detail_binding=status.get("binding"),
    )
    return AdaptedAttentionSources.create(
        obligations=(debt,), coverage_kind=coverage
    )


def adapt_attention_sources(
    *,
    scope: AttentionScope,
    rows: Iterable[Mapping[str, Any]],
    supplemental: Iterable[AdaptedAttentionSources] = (),
    provider_statuses: Iterable[Mapping[str, Any]] = (),
) -> AdaptedAttentionSources:
    """Normalize and deterministically merge all supplied typed sources."""

    obligations = [_adapt_row(scope=scope, row=row) for row in rows]
    coverage_values = ["EXACT"]
    for source in supplemental:
        if not isinstance(source, AdaptedAttentionSources):
            raise TypeError(
                "supplemental source must be AdaptedAttentionSources"
            )
        obligations.extend(source.obligations)
        coverage_values.append(source.coverage_kind)
    for status in provider_statuses:
        adapted = adapt_provider_status(scope=scope, status=status)
        obligations.extend(adapted.obligations)
        coverage_values.append(adapted.coverage_kind)
    return AdaptedAttentionSources.create(
        obligations=obligations,
        coverage_kind=_combine_coverage(coverage_values),
    )


def adapt_coverage_shortfalls(
    *,
    scope: AttentionScope,
    rows: Iterable[Mapping[str, Any]],
) -> AdaptedAttentionSources:
    """Convert legacy bounded-enumeration receipts to typed provider debt."""

    obligations: list[AttentionObligation] = []
    coverages: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise TypeError("coverage shortfall row must be an object")
        coverage = _count_semantics(
            row.get("count_semantics", "UNKNOWN")
        )
        coverages.append(coverage)
        receipt_id = _text(row.get("receipt_id"), "receipt_id")
        producer = _text(row.get("producer"), "producer")
        source_scope = _text(row.get("scope"), "shortfall scope")
        kind = _text(
            row.get("kind", "COVERAGE_SHORTFALL"),
            "shortfall kind",
        ).upper()
        detail = _text(row.get("detail"), "shortfall detail")
        obligations.append(
            _provider_debt_row(
                scope=scope,
                provider=producer,
                reason_code=kind,
                clearing_condition=detail,
                required=True,
                count_semantics=coverage,
                canonical_id=receipt_id,
                subject_ids=(source_scope, receipt_id),
                detail_binding={
                    "omitted": row.get("omitted"),
                    "kind": kind,
                    "scope": source_scope,
                },
            )
        )
    return AdaptedAttentionSources.create(
        obligations=obligations,
        coverage_kind=_combine_coverage(coverages),
    )


def adapt_graph_capability(
    *,
    scope: AttentionScope,
    authority: Mapping[str, Any] | None,
) -> AdaptedAttentionSources:
    """Adapt graph authority additively; absence never edits baseline rows."""

    if scope.graph_treatment == "legacy_off":
        raise AdaptiveAttentionError(
            "graph authority is forbidden when graph treatment is legacy_off"
        )
    if authority is None:
        authority = {
            "provider": "graph-authority",
            "available": False,
            "required": True,
            "count_semantics": "UNKNOWN",
            "reason_code": "MISSING_GRAPH_AUTHORITY",
            "clearing_condition": "publish a current typed graph binding",
        }
    if not isinstance(authority, Mapping):
        raise TypeError("graph authority must be an object")
    available = authority.get("available")
    if not isinstance(available, bool):
        raise AdaptiveAttentionError(
            "graph authority available must be a boolean"
        )
    if not available:
        return adapt_provider_status(
            scope=scope,
            status={
                key: value
                for key, value in authority.items()
                if key
                in {
                    "provider", "available", "required",
                    "count_semantics", "reason_code",
                    "clearing_condition", "canonical_id",
                    "subject_ids", "binding",
                }
            },
        )
    unknown = set(authority) - {
        "schema_version", "provider", "available", "required",
        "supported", "stale", "count_semantics", "binding",
        "row_count", "rows",
    }
    if unknown:
        raise AdaptiveAttentionError(
            "graph authority has unexpected fields: "
            + ",".join(sorted(unknown))
        )
    provider = _text(authority.get("provider"), "provider")
    required = _bool(authority.get("required", True), "required")
    coverage = _count_semantics(
        authority.get("count_semantics", "UNKNOWN")
    )
    rows = authority.get("rows", ())
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
        raise AdaptiveAttentionError(
            "graph authority rows must be an array"
        )
    failure: tuple[str, str, str] | None = None
    if authority.get("schema_version") != GRAPH_AUTHORITY_SCHEMA:
        failure = (
            "UNSUPPORTED_GRAPH_SCHEMA",
            "UNKNOWN",
            "publish a supported typed graph authority schema",
        )
    elif authority.get("supported", True) is not True:
        failure = (
            "UNSUPPORTED_GRAPH_AUTHORITY",
            "UNKNOWN",
            "publish a supported graph authority",
        )
    elif authority.get("stale", False) is not False:
        failure = (
            "STALE_GRAPH_AUTHORITY",
            "UNKNOWN",
            "publish a current graph authority receipt",
        )
    binding = authority.get("binding")
    expected_binding = {
        "snapshot_digest": scope.snapshot_digest,
        "phase_graph_digest": scope.phase_graph_digest,
        "dependency_generation": scope.dependency_generation,
    }
    if failure is None and binding != expected_binding:
        failure = (
            "STALE_GRAPH_BINDING",
            "UNKNOWN",
            "bind graph authority to the exact attention scope",
        )
    row_count = authority.get("row_count")
    if failure is None:
        try:
            count = _integer(row_count, "graph row_count")
        except AdaptiveAttentionError:
            failure = (
                "GRAPH_COUNT_MISMATCH",
                "UNKNOWN",
                "publish an exact typed graph row count",
            )
        else:
            if count != len(rows):
                failure = (
                    "GRAPH_COUNT_MISMATCH",
                    "UNKNOWN",
                    "publish an exact typed graph row count",
                )
    if failure is None and not rows:
        failure = (
            "EMPTY_GRAPH_AUTHORITY",
            "UNKNOWN",
            "publish non-empty graph rows or an exact empty proof",
        )
    if failure is None and coverage != "EXACT":
        failure = (
            "GRAPH_DENOMINATOR_" + coverage,
            coverage,
            "publish an exact graph denominator",
        )
    additive_rows: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise TypeError("graph authority row must be an object")
        copied = dict(row)
        copied["graph_origin"] = "TYPED_ADDITIVE"
        additive_rows.append(copied)
    if failure is None:
        return adapt_attention_sources(scope=scope, rows=additive_rows)
    reason, failure_coverage, clearing = failure
    debt = _provider_debt_row(
        scope=scope,
        provider=provider,
        reason_code=reason,
        clearing_condition=clearing,
        required=required,
        count_semantics=failure_coverage,
        detail_binding={
            "declared_count_semantics": coverage,
            "declared_row_count": row_count,
            "authority_binding": binding,
        },
    )
    return AdaptedAttentionSources.create(
        obligations=(debt,),
        coverage_kind=failure_coverage,
    )


def _adapt_kind_rows(
    *,
    scope: AttentionScope,
    rows: Iterable[Mapping[str, Any]],
    kind: str,
) -> AdaptedAttentionSources:
    normalized: list[dict[str, Any]] = []
    for row in rows:
        copied = dict(row)
        declared = _text(copied.get("kind", kind), "kind").upper()
        if declared != kind:
            raise AdaptiveAttentionError(
                f"source adapter expected {kind}, received {declared}"
            )
        copied["kind"] = kind
        normalized.append(copied)
    return adapt_attention_sources(scope=scope, rows=normalized)


def adapt_methodology_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="METHOD_STEP")


def adapt_security_aliases(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return adapt_attention_sources(scope=scope, rows=rows)


def adapt_axis_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="AXIS_CELL")


def adapt_component_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="COMPONENT")


def adapt_relation_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="RELATION")


def adapt_candidate_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(
        scope=scope, rows=rows, kind="CANDIDATE_CHALLENGE"
    )


def adapt_chain_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="CHAIN_PAIR")


def adapt_verifier_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="VERIFIER_ITEM")


def adapt_report_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="REPORT_ITEM")


def adapt_merge_rows(
    *, scope: AttentionScope, rows: Iterable[Mapping[str, Any]]
) -> AdaptedAttentionSources:
    return _adapt_kind_rows(scope=scope, rows=rows, kind="MERGE_ITEM")


__all__ = [
    "AdaptedAttentionSources",
    "adapt_attention_sources",
    "adapt_axis_rows",
    "adapt_candidate_rows",
    "adapt_chain_rows",
    "adapt_component_rows",
    "adapt_coverage_shortfalls",
    "adapt_graph_capability",
    "adapt_merge_rows",
    "adapt_methodology_rows",
    "adapt_provider_status",
    "adapt_relation_rows",
    "adapt_report_rows",
    "adapt_security_aliases",
    "adapt_verifier_rows",
]
