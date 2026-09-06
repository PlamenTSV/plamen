"""Typed P0-AF substrate for independently verified compound-chain claims.

This module is intentionally driver-neutral.  It defines the identity, work,
proof-scope, and report-binding contracts that production queue/report code can
integrate without treating constituent verifier artifacts as compound proof.
Markdown parsing and pipeline wiring belong at the integration boundary; this
module's records are the semantic authority once constructed.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from closure_broker_v2 import resolve_central_negative_closure


_IDENTITY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+$")
_CHAIN_ID_RE = re.compile(r"^CH-\d{1,6}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}


def _identity(value: str, *, chain: bool = False) -> str:
    normalized = str(value or "").strip().upper()
    matcher = _CHAIN_ID_RE if chain else _IDENTITY_RE
    if not matcher.fullmatch(normalized):
        kind = "chain" if chain else "finding"
        raise ValueError(f"invalid {kind} identity: {value!r}")
    return normalized


def _nonempty(value: str, field: str) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "")).strip()
    if not normalized:
        raise ValueError(f"{field} must not be empty")
    return normalized


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


class ProofScope(str, Enum):
    CONSTITUENT_MECHANISM = "CONSTITUENT_MECHANISM"
    COMPOSITION = "COMPOSITION"
    HARM = "HARM"


class EvidenceOrigin(str, Enum):
    COMPOUND_EXECUTION = "COMPOUND_EXECUTION"
    CONSTITUENT_EXECUTION = "CONSTITUENT_EXECUTION"
    STATIC_COMPOSITION_ANALYSIS = "STATIC_COMPOSITION_ANALYSIS"
    VERIFIER_PROSE = "VERIFIER_PROSE"


class EvidenceOutcome(str, Enum):
    CONFIRMS = "CONFIRMS"
    REFUTES = "REFUTES"
    INCONCLUSIVE = "INCONCLUSIVE"


class WorkReadiness(str, Enum):
    READY = "READY"
    BLOCKED_MISSING_CONSTITUENT = "BLOCKED_MISSING_CONSTITUENT"
    BLOCKED_IDENTITY_COLLISION = "BLOCKED_IDENTITY_COLLISION"


class CompoundVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    PARTIAL = "PARTIAL"
    CONTESTED_COMPOUND = "CONTESTED_COMPOUND"
    UNVERIFIED_COMPOUND = "UNVERIFIED_COMPOUND"


class AliasKind(str, Enum):
    RESTATEMENT = "RESTATEMENT"
    EQUIVALENT_COMPOUND = "EQUIVALENT_COMPOUND"


class ReportDisposition(str, Enum):
    BODY = "BODY"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    EXCLUDED_REFUTED = "EXCLUDED_REFUTED"


@dataclass(frozen=True, order=True)
class ConstituentAuthorityBinding:
    """Exact immutable authority for a non-finding composition constituent."""

    constituent_id: str
    constituent_kind: str
    fact_digest: str
    authority_digest: str
    source_artifact: str

    @classmethod
    def create(
        cls,
        value: "ConstituentAuthorityBinding | Mapping[str, Any]",
    ) -> "ConstituentAuthorityBinding":
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("evidence constituent binding must be an object")
        required = {
            "constituent_id",
            "constituent_kind",
            "fact_digest",
            "authority_digest",
            "source_artifact",
        }
        if set(value) != required:
            raise ValueError("evidence constituent binding fields mismatch")
        kind = str(value.get("constituent_kind") or "").strip().upper()
        if kind != "EVIDENCE_FACT":
            raise ValueError("only EVIDENCE_FACT bindings are supported")
        fact_digest = str(value.get("fact_digest") or "").strip().lower()
        authority_digest = str(
            value.get("authority_digest") or ""
        ).strip().lower()
        if not _SHA256_RE.fullmatch(fact_digest):
            raise ValueError("evidence constituent fact_digest is invalid")
        if not _SHA256_RE.fullmatch(authority_digest):
            raise ValueError("evidence constituent authority_digest is invalid")
        source_artifact = str(value.get("source_artifact") or "").strip()
        if not _ARTIFACT_NAME_RE.fullmatch(source_artifact):
            raise ValueError("evidence constituent source_artifact is invalid")
        return cls(
            constituent_id=_identity(str(value.get("constituent_id") or "")),
            constituent_kind=kind,
            fact_digest=fact_digest,
            authority_digest=authority_digest,
            source_artifact=source_artifact,
        )

    def to_record(self) -> dict[str, str]:
        return {
            "constituent_id": self.constituent_id,
            "constituent_kind": self.constituent_kind,
            "fact_digest": self.fact_digest,
            "authority_digest": self.authority_digest,
            "source_artifact": self.source_artifact,
        }


@dataclass(frozen=True, order=True)
class CompositionEdge:
    predecessor: str
    successor: str
    relation: str

    @classmethod
    def create(cls, predecessor: str, successor: str, relation: str) -> "CompositionEdge":
        return cls(
            predecessor=_identity(predecessor),
            successor=_identity(successor),
            relation=_nonempty(relation, "edge relation").lower(),
        )

    def to_record(self) -> dict[str, str]:
        return {
            "predecessor": self.predecessor,
            "successor": self.successor,
            "relation": self.relation,
        }


@dataclass(frozen=True)
class CompoundCandidate:
    chain_id: str
    constituents: tuple[str, ...]
    severity_upgrade_justified: bool
    ordering_edges: tuple[CompositionEdge, ...]
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    combined_impact_claim: str
    proposed_severity: str
    source_lineage: tuple[str, ...]
    coverage_lineage: tuple[str, ...]
    pipeline: str
    mode: str
    evidence_constituent_bindings: tuple[ConstituentAuthorityBinding, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        chain_id: str,
        constituents: Sequence[str],
        severity_upgrade_justified: bool,
        ordering_edges: Sequence[tuple[str, str, str] | CompositionEdge],
        preconditions: Sequence[str],
        postconditions: Sequence[str],
        combined_impact_claim: str,
        proposed_severity: str,
        source_lineage: Sequence[str],
        coverage_lineage: Sequence[str],
        pipeline: str,
        mode: str,
        evidence_constituent_bindings: Sequence[
            ConstituentAuthorityBinding | Mapping[str, Any]
        ] = (),
    ) -> "CompoundCandidate":
        canonical_constituents = tuple(_identity(item) for item in constituents)
        if len(canonical_constituents) < 2:
            raise ValueError("a compound candidate requires at least two constituents")
        if len(set(canonical_constituents)) != len(canonical_constituents):
            raise ValueError("compound candidate constituents must be unique")
        edges = tuple(
            edge
            if isinstance(edge, CompositionEdge)
            else CompositionEdge.create(edge[0], edge[1], edge[2])
            for edge in ordering_edges
        )
        constituent_set = set(canonical_constituents)
        for edge in edges:
            if edge.predecessor not in constituent_set or edge.successor not in constituent_set:
                raise ValueError("composition edge endpoint is not a constituent")
            if edge.predecessor == edge.successor:
                raise ValueError("composition edge cannot be a self-edge")
        severity = str(proposed_severity or "").strip().title()
        if severity not in _SEVERITIES:
            raise ValueError(f"invalid proposed severity: {proposed_severity!r}")
        normalized_pipeline = str(pipeline or "").strip().upper()
        if normalized_pipeline not in {"SC", "L1"}:
            raise ValueError(f"invalid pipeline: {pipeline!r}")
        normalized_mode = str(mode or "").strip().lower()
        if normalized_mode not in {"light", "core", "thorough"}:
            raise ValueError(f"invalid mode: {mode!r}")
        parsed_bindings = tuple(
            ConstituentAuthorityBinding.create(value)
            for value in evidence_constituent_bindings
        )
        bound_ids = [binding.constituent_id for binding in parsed_bindings]
        if len(bound_ids) != len(set(bound_ids)):
            raise ValueError("evidence constituent bindings must be unique")
        if any(identity not in constituent_set for identity in bound_ids):
            raise ValueError(
                "evidence constituent binding identity is not a constituent"
            )
        binding_by_id = {
            binding.constituent_id: binding for binding in parsed_bindings
        }
        ordered_bindings = tuple(
            binding_by_id[identity]
            for identity in canonical_constituents
            if identity in binding_by_id
        )
        return cls(
            chain_id=_identity(chain_id, chain=True),
            constituents=canonical_constituents,
            severity_upgrade_justified=bool(severity_upgrade_justified),
            ordering_edges=tuple(sorted(edges)),
            preconditions=tuple(_nonempty(item, "precondition") for item in preconditions),
            postconditions=tuple(_nonempty(item, "postcondition") for item in postconditions),
            combined_impact_claim=_nonempty(combined_impact_claim, "combined impact claim"),
            proposed_severity=severity,
            source_lineage=tuple(_nonempty(item, "source lineage") for item in source_lineage),
            coverage_lineage=tuple(_nonempty(item, "coverage lineage") for item in coverage_lineage),
            pipeline=normalized_pipeline,
            mode=normalized_mode,
            evidence_constituent_bindings=ordered_bindings,
        )

    def to_record(self, *, include_identity: bool = True) -> dict[str, Any]:
        record: dict[str, Any] = {
            "constituents": list(self.constituents),
            "severity_upgrade_justified": self.severity_upgrade_justified,
            "ordering_edges": [edge.to_record() for edge in self.ordering_edges],
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "combined_impact_claim": self.combined_impact_claim,
            "proposed_severity": self.proposed_severity,
            "source_lineage": list(self.source_lineage),
            "coverage_lineage": list(self.coverage_lineage),
            "pipeline": self.pipeline,
            "mode": self.mode,
        }
        if include_identity:
            record["chain_id"] = self.chain_id
        if self.evidence_constituent_bindings:
            record["evidence_constituent_bindings"] = [
                binding.to_record()
                for binding in self.evidence_constituent_bindings
            ]
        return record

    @property
    def digest(self) -> str:
        return _digest(self.to_record())

    @property
    def claim_fingerprint(self) -> str:
        # Producer lineage and public chain ID do not change semantic identity.
        record = self.to_record(include_identity=False)
        record.pop("source_lineage", None)
        record.pop("coverage_lineage", None)
        return _digest(record)


@dataclass(frozen=True)
class CompoundIssue:
    code: str
    subject_id: str
    detail: str
    candidate_digests: tuple[str, ...] = ()

    def to_record(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "subject_id": self.subject_id,
            "detail": self.detail,
            "candidate_digests": list(self.candidate_digests),
        }


@dataclass(frozen=True)
class AliasRelation:
    alias_id: str
    target_ids: tuple[str, ...]
    kind: AliasKind
    reason: str

    def to_record(self) -> dict[str, Any]:
        return {
            "alias_id": self.alias_id,
            "target_ids": list(self.target_ids),
            "kind": self.kind.value,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CompoundWorkItem:
    subject_id: str
    verification_identity: str
    constituent_ids: tuple[str, ...]
    ordering_edges: tuple[CompositionEdge, ...]
    preconditions: tuple[str, ...]
    postconditions: tuple[str, ...]
    combined_impact_claim: str
    proposed_severity: str
    required_proof_scopes: frozenset[ProofScope]
    readiness: WorkReadiness
    missing_constituents: tuple[str, ...]
    candidate_digest: str
    pipeline: str
    mode: str
    constituent_authority_bindings: tuple[
        ConstituentAuthorityBinding, ...
    ] = ()

    def to_record(self) -> dict[str, Any]:
        record = {
            "subject_id": self.subject_id,
            "verification_identity": self.verification_identity,
            "constituent_ids": list(self.constituent_ids),
            "ordering_edges": [edge.to_record() for edge in self.ordering_edges],
            "preconditions": list(self.preconditions),
            "postconditions": list(self.postconditions),
            "combined_impact_claim": self.combined_impact_claim,
            "proposed_severity": self.proposed_severity,
            "required_proof_scopes": sorted(scope.value for scope in self.required_proof_scopes),
            "readiness": self.readiness.value,
            "missing_constituents": list(self.missing_constituents),
            "candidate_digest": self.candidate_digest,
            "pipeline": self.pipeline,
            "mode": self.mode,
        }
        if self.constituent_authority_bindings:
            record["constituent_authority_bindings"] = [
                binding.to_record()
                for binding in self.constituent_authority_bindings
            ]
        return record


@dataclass(frozen=True)
class CompoundWorkPlan:
    work_items: tuple[CompoundWorkItem, ...]
    alias_relations: tuple[AliasRelation, ...]
    issues: tuple[CompoundIssue, ...]
    blocked_candidates: tuple[CompoundCandidate, ...]

    def to_record(self) -> dict[str, Any]:
        typed = any(
            item.constituent_authority_bindings for item in self.work_items
        ) or any(
            item.evidence_constituent_bindings for item in self.blocked_candidates
        )
        return {
            "schema_version": (
                "plamen.compound_work_plan.v2"
                if typed
                else "plamen.compound_work_plan.v1"
            ),
            "work_items": [item.to_record() for item in self.work_items],
            "alias_relations": [item.to_record() for item in self.alias_relations],
            "issues": [item.to_record() for item in self.issues],
            "blocked_candidates": [item.to_record() for item in self.blocked_candidates],
        }

    @property
    def digest(self) -> str:
        return _digest(self.to_record())


def compile_compound_work_plan(
    candidates: Iterable[CompoundCandidate],
    known_constituent_identities: Iterable[str],
    *,
    known_evidence_constituents: Iterable[
        ConstituentAuthorityBinding | Mapping[str, Any]
    ] = (),
) -> CompoundWorkPlan:
    """Compile justified chains into independent, collision-aware work items."""
    candidate_list = sorted(
        tuple(candidates), key=lambda item: (item.chain_id, item.digest)
    )
    known = {_identity(item) for item in known_constituent_identities}
    known_evidence: dict[str, ConstituentAuthorityBinding] = {}
    for raw_binding in known_evidence_constituents:
        binding = ConstituentAuthorityBinding.create(raw_binding)
        prior = known_evidence.get(binding.constituent_id)
        if prior is not None and prior != binding:
            raise ValueError(
                "conflicting known evidence constituent authority for "
                + binding.constituent_id
            )
        known_evidence[binding.constituent_id] = binding
    issues: list[CompoundIssue] = []
    blocked: list[CompoundCandidate] = []
    aliases: list[AliasRelation] = []
    work_items: list[CompoundWorkItem] = []

    by_chain_id: dict[str, list[CompoundCandidate]] = {}
    for candidate in candidate_list:
        by_chain_id.setdefault(candidate.chain_id, []).append(candidate)

    unique_candidates: list[CompoundCandidate] = []
    for chain_id, grouped in sorted(by_chain_id.items()):
        if len(grouped) > 1:
            digests = tuple(candidate.digest for candidate in grouped)
            issues.append(CompoundIssue(
                code="DUPLICATE_CHAIN_ID",
                subject_id=chain_id,
                detail="multiple compound candidates claim one public chain identity",
                candidate_digests=digests,
            ))
            blocked.extend(grouped)
            continue
        unique_candidates.append(grouped[0])

    justified: list[CompoundCandidate] = []
    for candidate in unique_candidates:
        if not candidate.severity_upgrade_justified:
            aliases.append(AliasRelation(
                alias_id=candidate.chain_id,
                target_ids=candidate.constituents,
                kind=AliasKind.RESTATEMENT,
                reason="severity upgrade not justified; retain coverage relation to constituents",
            ))
            continue
        justified.append(candidate)

    # Equivalent claims with distinct chain IDs share one verifier identity,
    # but the aliases remain explicit so report counting cannot duplicate them.
    by_claim: dict[str, list[CompoundCandidate]] = {}
    for candidate in justified:
        by_claim.setdefault(candidate.claim_fingerprint, []).append(candidate)

    canonical_candidates: list[CompoundCandidate] = []
    for fingerprint, grouped in sorted(by_claim.items()):
        del fingerprint
        ordered = sorted(grouped, key=lambda item: item.chain_id)
        canonical = ordered[0]
        canonical_candidates.append(canonical)
        for alias_candidate in ordered[1:]:
            aliases.append(AliasRelation(
                alias_id=alias_candidate.chain_id,
                target_ids=(canonical.chain_id,),
                kind=AliasKind.EQUIVALENT_COMPOUND,
                reason="equivalent typed composition claim uses canonical compound verifier",
            ))

    for candidate in sorted(canonical_candidates, key=lambda item: item.chain_id):
        declared_evidence = {
            binding.constituent_id: binding
            for binding in candidate.evidence_constituent_bindings
        }
        missing_values: list[str] = []
        for constituent_id in candidate.constituents:
            declared = declared_evidence.get(constituent_id)
            if declared is None:
                if constituent_id not in known:
                    missing_values.append(constituent_id)
                continue
            observed = known_evidence.get(constituent_id)
            if observed is None:
                missing_values.append(constituent_id)
                issues.append(CompoundIssue(
                    code="MISSING_EVIDENCE_CONSTITUENT",
                    subject_id=candidate.chain_id,
                    detail=(
                        "missing immutable evidence constituent authority: "
                        + constituent_id
                    ),
                    candidate_digests=(candidate.digest,),
                ))
            elif observed != declared:
                missing_values.append(constituent_id)
                issues.append(CompoundIssue(
                    code="EVIDENCE_CONSTITUENT_BINDING_MISMATCH",
                    subject_id=candidate.chain_id,
                    detail=(
                        "evidence constituent authority changed: "
                        + constituent_id
                    ),
                    candidate_digests=(candidate.digest,),
                ))
        missing = tuple(missing_values)
        collision = (
            candidate.chain_id in known
            or candidate.chain_id in known_evidence
        )
        if collision:
            readiness = WorkReadiness.BLOCKED_IDENTITY_COLLISION
            issues.append(CompoundIssue(
                code="IDENTITY_COLLISION",
                subject_id=candidate.chain_id,
                detail="compound identity already exists in the constituent identity namespace",
                candidate_digests=(candidate.digest,),
            ))
        elif missing:
            readiness = WorkReadiness.BLOCKED_MISSING_CONSTITUENT
        else:
            readiness = WorkReadiness.READY
        if missing:
            issues.append(CompoundIssue(
                code="MISSING_CONSTITUENT",
                subject_id=candidate.chain_id,
                detail="missing constituent identity/identities: " + ", ".join(missing),
                candidate_digests=(candidate.digest,),
            ))
        work_items.append(CompoundWorkItem(
            subject_id=candidate.chain_id,
            verification_identity=f"verify_{candidate.chain_id}",
            constituent_ids=candidate.constituents,
            ordering_edges=candidate.ordering_edges,
            preconditions=candidate.preconditions,
            postconditions=candidate.postconditions,
            combined_impact_claim=candidate.combined_impact_claim,
            proposed_severity=candidate.proposed_severity,
            required_proof_scopes=frozenset({ProofScope.COMPOSITION, ProofScope.HARM}),
            readiness=readiness,
            missing_constituents=missing,
            candidate_digest=candidate.digest,
            pipeline=candidate.pipeline,
            mode=candidate.mode,
            constituent_authority_bindings=(
                candidate.evidence_constituent_bindings
            ),
        ))

    return CompoundWorkPlan(
        work_items=tuple(work_items),
        alias_relations=tuple(sorted(aliases, key=lambda item: item.alias_id)),
        issues=tuple(sorted(issues, key=lambda item: (item.subject_id, item.code))),
        blocked_candidates=tuple(blocked),
    )


@dataclass(frozen=True)
class CompoundEvidence:
    evidence_id: str
    subject_id: str
    constituent_ids: tuple[str, ...]
    origin: EvidenceOrigin
    outcome: EvidenceOutcome
    proof_scopes: frozenset[ProofScope]
    executed: bool
    ordering_reachable: bool | None
    both_mechanisms_required: bool | None
    combined_harm_observed: bool | None
    command_digest: str
    result_digest: str

    @classmethod
    def create(
        cls,
        *,
        evidence_id: str,
        subject_id: str,
        constituent_ids: Sequence[str],
        origin: EvidenceOrigin,
        outcome: EvidenceOutcome,
        proof_scopes: Iterable[ProofScope],
        executed: bool,
        ordering_reachable: bool | None,
        both_mechanisms_required: bool | None,
        combined_harm_observed: bool | None,
        command_digest: str,
        result_digest: str,
    ) -> "CompoundEvidence":
        canonical_constituents = tuple(_identity(item) for item in constituent_ids)
        if len(canonical_constituents) < 2:
            raise ValueError("compound evidence requires at least two constituents")
        if len(set(canonical_constituents)) != len(canonical_constituents):
            raise ValueError("compound evidence constituents must be unique")
        return cls(
            evidence_id=_nonempty(evidence_id, "evidence ID"),
            subject_id=_identity(subject_id, chain=True),
            constituent_ids=canonical_constituents,
            origin=EvidenceOrigin(origin),
            outcome=EvidenceOutcome(outcome),
            proof_scopes=frozenset(ProofScope(scope) for scope in proof_scopes),
            executed=bool(executed),
            ordering_reachable=ordering_reachable,
            both_mechanisms_required=both_mechanisms_required,
            combined_harm_observed=combined_harm_observed,
            command_digest=str(command_digest or "").strip(),
            result_digest=str(result_digest or "").strip(),
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "subject_id": self.subject_id,
            "constituent_ids": list(self.constituent_ids),
            "origin": self.origin.value,
            "outcome": self.outcome.value,
            "proof_scopes": sorted(scope.value for scope in self.proof_scopes),
            "executed": self.executed,
            "ordering_reachable": self.ordering_reachable,
            "both_mechanisms_required": self.both_mechanisms_required,
            "combined_harm_observed": self.combined_harm_observed,
            "command_digest": self.command_digest,
            "result_digest": self.result_digest,
        }

    def is_exact_compound_evidence(self, candidate: CompoundCandidate) -> bool:
        return (
            self.subject_id == candidate.chain_id
            and self.constituent_ids == candidate.constituents
            and self.origin is EvidenceOrigin.COMPOUND_EXECUTION
            and ProofScope.COMPOSITION in self.proof_scopes
        )

    def is_proof_grade_confirmation(self, candidate: CompoundCandidate) -> bool:
        return (
            self.is_exact_compound_evidence(candidate)
            and self.outcome is EvidenceOutcome.CONFIRMS
            and self.executed
            and bool(self.command_digest)
            and bool(self.result_digest)
            and ProofScope.HARM in self.proof_scopes
            and self.ordering_reachable is True
            and self.both_mechanisms_required is True
            and self.combined_harm_observed is True
        )

    def is_typed_composition_refutation(self, candidate: CompoundCandidate) -> bool:
        """Return whether this is replayable negative composition evidence.

        A false composition fact in a typed record is not enough: the record
        must also identify an executed compound harness and bind both its
        command and result.  Even this predicate is supporting evidence only;
        terminal exclusion requires a matching independent central
        negative-closure authority supplied to the evaluator and binder.
        """
        return (
            self.is_exact_compound_evidence(candidate)
            and self.outcome is EvidenceOutcome.REFUTES
            and self.executed
            and bool(self.command_digest)
            and bool(self.result_digest)
            and (
                self.ordering_reachable is False
                or self.both_mechanisms_required is False
                or self.combined_harm_observed is False
            )
        )


@dataclass(frozen=True)
class CompoundVerificationResult:
    subject_id: str
    verification_identity: str
    verdict: CompoundVerdict
    proof_grade: bool
    proposed_severity: str
    constituent_verdicts: tuple[tuple[str, str], ...]
    accepted_evidence_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    debt_codes: tuple[str, ...]
    ordering_reachable: bool | None
    both_mechanisms_required: bool | None
    combined_harm_observed: bool | None
    closure_authority_digest: str = ""
    closure_provider_completion_sha256: str = ""
    closure_provider_publish_sha256: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": "plamen.compound_verification_result.v1",
            "subject_id": self.subject_id,
            "verification_identity": self.verification_identity,
            "verdict": self.verdict.value,
            "proof_grade": self.proof_grade,
            "proposed_severity": self.proposed_severity,
            "constituent_verdicts": [
                {"identity": identity, "verdict": verdict}
                for identity, verdict in self.constituent_verdicts
            ],
            "accepted_evidence_ids": list(self.accepted_evidence_ids),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "debt_codes": list(self.debt_codes),
            "ordering_reachable": self.ordering_reachable,
            "both_mechanisms_required": self.both_mechanisms_required,
            "combined_harm_observed": self.combined_harm_observed,
            "closure_authority_digest": self.closure_authority_digest,
            "closure_provider_completion_sha256": self.closure_provider_completion_sha256,
            "closure_provider_publish_sha256": self.closure_provider_publish_sha256,
        }


def evaluate_compound_work_item(
    candidate: CompoundCandidate,
    work_item: CompoundWorkItem,
    evidence: Iterable[CompoundEvidence],
    constituent_verdicts: Mapping[str, str],
    *,
    verifier_available: bool = True,
    closure_authority: Any = None,
) -> CompoundVerificationResult:
    """Adjudicate only evidence scoped to the compound composition itself."""
    if work_item.subject_id != candidate.chain_id or work_item.candidate_digest != candidate.digest:
        raise ValueError("work item is not bound to this compound candidate")
    all_evidence = tuple(evidence)
    supporting_ids = tuple(item.evidence_id for item in all_evidence)
    debts: set[str] = set()
    if work_item.readiness is not WorkReadiness.READY:
        debts.add(work_item.readiness.value)
    if not verifier_available:
        debts.add("VERIFIER_UNAVAILABLE")

    normalized_verdicts = {
        _identity(identity): str(verdict or "").strip().upper()
        for identity, verdict in constituent_verdicts.items()
    }
    for constituent in candidate.constituents:
        verdict = normalized_verdicts.get(constituent)
        if not verdict:
            debts.add("CONSTITUENT_VERDICT_MISSING")
        elif verdict == "REFUTED":
            debts.add("CONSTITUENT_REFUTED")
    constituent_statuses = tuple(
        (constituent, normalized_verdicts.get(constituent, "MISSING"))
        for constituent in candidate.constituents
    )

    exact: list[CompoundEvidence] = []
    for item in all_evidence:
        if item.is_exact_compound_evidence(candidate):
            exact.append(item)
        elif item.subject_id != candidate.chain_id:
            debts.add("EVIDENCE_SUBJECT_MISMATCH")
        elif item.constituent_ids != candidate.constituents:
            debts.add("EVIDENCE_CONSTITUENT_SCOPE_MISMATCH")
        elif item.origin is EvidenceOrigin.CONSTITUENT_EXECUTION:
            debts.add("CONSTITUENT_EVIDENCE_NOT_COMPOSITION_PROOF")

    if work_item.readiness is not WorkReadiness.READY or not verifier_available:
        return CompoundVerificationResult(
            subject_id=candidate.chain_id,
            verification_identity=work_item.verification_identity,
            verdict=CompoundVerdict.UNVERIFIED_COMPOUND,
            proof_grade=False,
            proposed_severity=candidate.proposed_severity,
            constituent_verdicts=constituent_statuses,
            accepted_evidence_ids=(),
            supporting_evidence_ids=supporting_ids,
            debt_codes=tuple(sorted(debts)),
            ordering_reachable=None,
            both_mechanisms_required=None,
            combined_harm_observed=None,
        )

    confirms = [item for item in exact if item.outcome is EvidenceOutcome.CONFIRMS]
    refutation_claims = [
        item for item in exact if item.outcome is EvidenceOutcome.REFUTES
    ]
    refutes = [
        item
        for item in refutation_claims
        if item.is_typed_composition_refutation(candidate)
    ]
    for item in refutation_claims:
        if not item.executed or not item.command_digest or not item.result_digest:
            debts.add("REFUTATION_EXECUTION_AUTHORITY_MISSING")
        elif item not in refutes:
            debts.add("REFUTATION_FACT_MISSING")
    if confirms and refutes:
        debts.add("CONFLICTING_COMPOSITION_EVIDENCE")
        return CompoundVerificationResult(
            subject_id=candidate.chain_id,
            verification_identity=work_item.verification_identity,
            verdict=CompoundVerdict.CONTESTED_COMPOUND,
            proof_grade=False,
            proposed_severity=candidate.proposed_severity,
            constituent_verdicts=constituent_statuses,
            accepted_evidence_ids=tuple(item.evidence_id for item in confirms + refutes),
            supporting_evidence_ids=supporting_ids,
            debt_codes=tuple(sorted(debts)),
            ordering_reachable=None,
            both_mechanisms_required=None,
            combined_harm_observed=None,
        )
    if refutes:
        selected = refutes[0]
        closure: Mapping[str, Any] | None = None
        if closure_authority is not None:
            try:
                candidate_closure = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        "candidate_id": candidate.chain_id,
                        "work_item_id": work_item.verification_identity,
                        "candidate_content_sha256": candidate.digest,
                    },
                    requested_effect="REFUTED_FULL",
                )
            except Exception:
                candidate_closure = None
            if (
                isinstance(candidate_closure, Mapping)
                and candidate_closure.get("status") == "AUTHORIZED"
                and candidate_closure.get("outcome") == "REFUTED_FULL"
            ):
                closure = candidate_closure
        if closure is None:
            debts.add("TERMINAL_NEGATIVE_CLOSURE_AUTHORITY_MISSING")
        return CompoundVerificationResult(
            subject_id=candidate.chain_id,
            verification_identity=work_item.verification_identity,
            verdict=CompoundVerdict.REFUTED,
            proof_grade=False,
            proposed_severity=candidate.proposed_severity,
            constituent_verdicts=constituent_statuses,
            accepted_evidence_ids=tuple(item.evidence_id for item in refutes),
            supporting_evidence_ids=supporting_ids,
            debt_codes=tuple(sorted(debts)),
            ordering_reachable=selected.ordering_reachable,
            both_mechanisms_required=selected.both_mechanisms_required,
            combined_harm_observed=selected.combined_harm_observed,
            closure_authority_digest=(
                str(closure.get("resolution_digest") or "") if closure else ""
            ),
            closure_provider_completion_sha256=(
                str(closure.get("provider_completion_sha256") or "")
                if closure else ""
            ),
            closure_provider_publish_sha256=(
                str(closure.get("provider_publish_sha256") or "")
                if closure else ""
            ),
        )
    proof_grade = [item for item in confirms if item.is_proof_grade_confirmation(candidate)]
    if proof_grade:
        selected = proof_grade[0]
        return CompoundVerificationResult(
            subject_id=candidate.chain_id,
            verification_identity=work_item.verification_identity,
            verdict=CompoundVerdict.CONFIRMED,
            proof_grade=True,
            proposed_severity=candidate.proposed_severity,
            constituent_verdicts=constituent_statuses,
            accepted_evidence_ids=tuple(item.evidence_id for item in proof_grade),
            supporting_evidence_ids=supporting_ids,
            debt_codes=tuple(sorted(debts)),
            ordering_reachable=selected.ordering_reachable,
            both_mechanisms_required=selected.both_mechanisms_required,
            combined_harm_observed=selected.combined_harm_observed,
        )
    if confirms:
        debts.add("COMPOUND_PROOF_SCOPE_INCOMPLETE")
        selected = confirms[0]
        return CompoundVerificationResult(
            subject_id=candidate.chain_id,
            verification_identity=work_item.verification_identity,
            verdict=CompoundVerdict.PARTIAL,
            proof_grade=False,
            proposed_severity=candidate.proposed_severity,
            constituent_verdicts=constituent_statuses,
            accepted_evidence_ids=tuple(item.evidence_id for item in confirms),
            supporting_evidence_ids=supporting_ids,
            debt_codes=tuple(sorted(debts)),
            ordering_reachable=selected.ordering_reachable,
            both_mechanisms_required=selected.both_mechanisms_required,
            combined_harm_observed=selected.combined_harm_observed,
        )

    debts.add("NO_COMPOSITION_EVIDENCE")
    return CompoundVerificationResult(
        subject_id=candidate.chain_id,
        verification_identity=work_item.verification_identity,
        verdict=CompoundVerdict.UNVERIFIED_COMPOUND,
        proof_grade=False,
        proposed_severity=candidate.proposed_severity,
        constituent_verdicts=constituent_statuses,
        accepted_evidence_ids=(),
        supporting_evidence_ids=supporting_ids,
        debt_codes=tuple(sorted(debts)),
        ordering_reachable=None,
        both_mechanisms_required=None,
        combined_harm_observed=None,
    )


@dataclass(frozen=True)
class CompoundReportBinding:
    report_identity: str
    evidence_identity: str
    supporting_constituent_ids: tuple[str, ...]
    composition_evidence_ids: tuple[str, ...]
    proposed_severity: str
    verdict: CompoundVerdict
    disposition: ReportDisposition
    proof_grade: bool
    closure_authority_digest: str = ""
    closure_provider_completion_sha256: str = ""
    closure_provider_publish_sha256: str = ""
    verification_identity: str = ""
    candidate_content_sha256: str = ""

    def to_record(self) -> dict[str, Any]:
        return {
            "schema_version": "plamen.compound_report_binding.v2",
            "report_identity": self.report_identity,
            "evidence_identity": self.evidence_identity,
            "supporting_constituent_ids": list(self.supporting_constituent_ids),
            "composition_evidence_ids": list(self.composition_evidence_ids),
            "proposed_severity": self.proposed_severity,
            "verdict": self.verdict.value,
            "disposition": self.disposition.value,
            "proof_grade": self.proof_grade,
            "closure_authority_digest": self.closure_authority_digest,
            "closure_provider_completion_sha256": self.closure_provider_completion_sha256,
            "closure_provider_publish_sha256": self.closure_provider_publish_sha256,
            "verification_identity": self.verification_identity,
            "candidate_content_sha256": self.candidate_content_sha256,
        }

    def with_evidence_identity(self, evidence_identity: str) -> "CompoundReportBinding":
        """Test/integration helper; validators must reject a substituted identity."""
        return replace(self, evidence_identity=_identity(evidence_identity))


def bind_compound_report(
    candidate: CompoundCandidate,
    result: CompoundVerificationResult | None,
    *,
    evidence: Iterable[CompoundEvidence] = (),
    closure_authority: Any = None,
) -> CompoundReportBinding:
    """Bind a chain to its own executed composition proof.

    A result receipt alone is insufficient.  The accepted evidence IDs must
    resolve to typed evidence whose subject, constituents, execution origin,
    and COMPOSITION/HARM scope match this candidate.
    """
    evidence_by_id = {item.evidence_id: item for item in evidence}
    closure: Mapping[str, Any] | None = None
    accepted = () if result is None else result.accepted_evidence_ids
    matched_confirmations = tuple(
        evidence_by_id[evidence_id]
        for evidence_id in accepted
        if evidence_id in evidence_by_id
        and evidence_by_id[evidence_id].is_proof_grade_confirmation(candidate)
    )
    matched_refutations = tuple(
        evidence_by_id[evidence_id]
        for evidence_id in accepted
        if evidence_id in evidence_by_id
        and evidence_by_id[evidence_id].is_typed_composition_refutation(candidate)
    )
    if result is None or result.subject_id != candidate.chain_id:
        verdict = CompoundVerdict.UNVERIFIED_COMPOUND
        disposition = ReportDisposition.HUMAN_REVIEW
        proof_grade = False
        evidence_ids: tuple[str, ...] = ()
    elif (
        result.verdict is CompoundVerdict.CONFIRMED
        and result.proof_grade
        and matched_confirmations
    ):
        verdict = result.verdict
        disposition = ReportDisposition.BODY
        proof_grade = True
        evidence_ids = tuple(item.evidence_id for item in matched_confirmations)
    elif result.verdict is CompoundVerdict.REFUTED:
        # Exact executed negative evidence cannot self-authorize exclusion.
        # The central receipt is resolved independently below; absent that
        # receipt the candidate stays visible for review.
        verdict = (
            CompoundVerdict.REFUTED
            if matched_refutations
            else CompoundVerdict.UNVERIFIED_COMPOUND
        )
        if closure_authority is not None and matched_refutations:
            try:
                candidate_closure = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        "candidate_id": candidate.chain_id,
                        "work_item_id": result.verification_identity,
                        "candidate_content_sha256": candidate.digest,
                    },
                    requested_effect="REFUTED_FULL",
                )
            except Exception:
                candidate_closure = None
            if (
                isinstance(candidate_closure, Mapping)
                and candidate_closure.get("status") == "AUTHORIZED"
                and candidate_closure.get("resolution_digest")
                == result.closure_authority_digest
            ):
                closure = candidate_closure
        disposition = (
            ReportDisposition.EXCLUDED_REFUTED
            if closure is not None
            else ReportDisposition.HUMAN_REVIEW
        )
        proof_grade = False
        evidence_ids = tuple(item.evidence_id for item in matched_refutations)
    else:
        verdict = (
            result.verdict
            if result.verdict not in {CompoundVerdict.CONFIRMED, CompoundVerdict.REFUTED}
            else CompoundVerdict.UNVERIFIED_COMPOUND
        )
        disposition = ReportDisposition.HUMAN_REVIEW
        proof_grade = False
        evidence_ids = ()
    return CompoundReportBinding(
        report_identity=candidate.chain_id,
        evidence_identity=candidate.chain_id,
        supporting_constituent_ids=candidate.constituents,
        composition_evidence_ids=evidence_ids,
        proposed_severity=candidate.proposed_severity,
        verdict=verdict,
        disposition=disposition,
        proof_grade=proof_grade,
        closure_authority_digest=(
            str(closure.get("resolution_digest") or "")
            if closure is not None
            else ""
        ),
        closure_provider_completion_sha256=(
            str(closure.get("provider_completion_sha256") or "")
            if closure is not None
            else ""
        ),
        closure_provider_publish_sha256=(
            str(closure.get("provider_publish_sha256") or "")
            if closure is not None
            else ""
        ),
        verification_identity=(
            result.verification_identity if result is not None else ""
        ),
        candidate_content_sha256=candidate.digest,
    )


def validate_compound_report_bindings(
    bindings: Iterable[CompoundReportBinding],
    *,
    standalone_report_identities: Iterable[str] = (),
    closure_decisions: Iterable[Mapping[str, Any]] = (),
    closure_authority: Any = None,
) -> tuple[CompoundIssue, ...]:
    """Expose proof substitution and primary-identity collisions.

    ``closure_decisions`` is retained only as a migration input.  Caller-owned
    mappings are never terminal; an exclusion must replay through the exact
    root-bound central resolver against the binding's subject/work/content.
    """
    standalone = {_identity(item) for item in standalone_report_identities}
    issues: list[CompoundIssue] = []
    seen: set[str] = set(standalone)
    # Deliberately do not inspect the legacy iterable: its values are
    # caller-owned and therefore supporting-only, regardless of their shape.
    for binding in bindings:
        if binding.evidence_identity != binding.report_identity:
            issues.append(CompoundIssue(
                code="CONSTITUENT_PROOF_SUBSTITUTION",
                subject_id=binding.report_identity,
                detail=(
                    f"compound report identity uses foreign proof identity "
                    f"{binding.evidence_identity}"
                ),
            ))
        if binding.report_identity in seen:
            issues.append(CompoundIssue(
                code="REPORT_IDENTITY_COLLISION",
                subject_id=binding.report_identity,
                detail="compound primary identity duplicates another report primary",
            ))
        else:
            seen.add(binding.report_identity)
        if (
            binding.evidence_identity != binding.report_identity
            and binding.evidence_identity in standalone
        ):
            issues.append(CompoundIssue(
                code="REPORT_IDENTITY_COLLISION",
                subject_id=binding.report_identity,
                detail="substituted evidence identity is independently reported",
            ))
        if binding.proof_grade and (
            binding.disposition is not ReportDisposition.BODY
            or not binding.composition_evidence_ids
        ):
            issues.append(CompoundIssue(
                code="INVALID_PROOF_GRADE_BINDING",
                subject_id=binding.report_identity,
                detail="proof-grade compound binding lacks body disposition or evidence",
            ))
        if binding.disposition is ReportDisposition.EXCLUDED_REFUTED:
            try:
                closure = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        "candidate_id": binding.report_identity,
                        "work_item_id": binding.verification_identity,
                        "candidate_content_sha256": (
                            binding.candidate_content_sha256
                        ),
                    },
                    requested_effect="REFUTED_FULL",
                )
            except Exception:
                closure = None
            if (
                not isinstance(closure, Mapping)
                or closure.get("status") != "AUTHORIZED"
                or closure.get("outcome") != "REFUTED_FULL"
                or closure.get("candidate_id") != binding.report_identity
                or closure.get("work_item_id") != binding.verification_identity
                or closure.get("candidate_content_sha256")
                != binding.candidate_content_sha256
                or closure.get("resolution_digest")
                != binding.closure_authority_digest
                or closure.get("provider_completion_sha256")
                != binding.closure_provider_completion_sha256
                or closure.get("provider_publish_sha256")
                != binding.closure_provider_publish_sha256
            ):
                issues.append(CompoundIssue(
                    code="UNAUTHORIZED_NEGATIVE_CLOSURE",
                    subject_id=binding.report_identity,
                    detail=(
                        "compound exclusion lacks independent terminal-negative "
                        "closure authority"
                    ),
                ))
        if (
            binding.disposition is ReportDisposition.BODY
            and binding.verdict is not CompoundVerdict.CONFIRMED
        ):
            issues.append(CompoundIssue(
                code="UNVERIFIED_COMPOUND_IN_BODY",
                subject_id=binding.report_identity,
                detail="non-confirmed compound cannot enter the proof-grade report body",
            ))
    return tuple(sorted(issues, key=lambda item: (item.subject_id, item.code, item.detail)))


@dataclass(frozen=True)
class CompoundPlanDelta:
    added_verification_identities: tuple[str, ...]
    removed_verification_identities: tuple[str, ...]
    changed_verification_identities: tuple[str, ...]

    @property
    def requires_descendant_invalidation(self) -> bool:
        return bool(
            self.added_verification_identities
            or self.removed_verification_identities
            or self.changed_verification_identities
        )


def diff_compound_work_plans(
    previous: CompoundWorkPlan, current: CompoundWorkPlan
) -> CompoundPlanDelta:
    """Return the exact compound work identities requiring queue invalidation."""
    old = {item.verification_identity: item.to_record() for item in previous.work_items}
    new = {item.verification_identity: item.to_record() for item in current.work_items}
    old_ids = set(old)
    new_ids = set(new)
    changed = sorted(identity for identity in old_ids & new_ids if old[identity] != new[identity])
    return CompoundPlanDelta(
        added_verification_identities=tuple(sorted(new_ids - old_ids)),
        removed_verification_identities=tuple(sorted(old_ids - new_ids)),
        changed_verification_identities=tuple(changed),
    )


__all__ = [
    "AliasKind",
    "AliasRelation",
    "CompoundCandidate",
    "CompoundEvidence",
    "CompoundIssue",
    "CompoundPlanDelta",
    "CompoundReportBinding",
    "CompoundVerdict",
    "CompoundVerificationResult",
    "CompoundWorkItem",
    "CompoundWorkPlan",
    "CompositionEdge",
    "EvidenceOrigin",
    "EvidenceOutcome",
    "ProofScope",
    "ReportDisposition",
    "WorkReadiness",
    "bind_compound_report",
    "compile_compound_work_plan",
    "diff_compound_work_plans",
    "evaluate_compound_work_item",
    "validate_compound_report_bindings",
]
