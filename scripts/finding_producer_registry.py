"""Typed registry for finding-producing artifacts and delivery projections.

The registry is intentionally content-neutral.  It records *how* producer
artifacts enter pipeline control planes, never what a protocol-specific issue
looks like.  Every consumer projection is derived from these records so adding
a producer in identity telemetry without delivery becomes mechanically
detectable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from fnmatch import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Sequence


REGISTRY_SCHEMA = "plamen.finding_producer_registry.v1"
APPLICATION_SKEPTIC_PROJECTION = "application_skeptic_proposals.md"
CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION = (
    "candidate_negative_skeptic_proposals.md"
)
APPLICATION_SKEPTIC_PROJECTION_SCHEMA = (
    "plamen.application_skeptic_proposal_projection.v1"
)
EXPLORATION_CLEAR_RECEIPT = "exploration_clear_receipt.json"
EXPLORATION_CLEAR_OBLIGATIONS = "exploration_clear_obligations.json"
REGISTERED_TYPED_ACTION_SCHEMA = "plamen.registered_typed_action.v1"
REGISTERED_ENUMERATION_OBLIGATION_SCHEMA = (
    "plamen.registered_enumeration_obligation.v1"
)

MARKDOWN_FINDING_ARTIFACT = "MARKDOWN_FINDINGS"
EXPLORATION_CLEAR_ARTIFACT = "EXPLORATION_CLEAR_RECEIPT_V1"
EXPLORATION_CLEAR_OBLIGATION_ARTIFACT = (
    "EXPLORATION_CLEAR_OBLIGATION_QUEUE_V1"
)
REGISTERED_ARTIFACT_FORMATS = frozenset(
    {
        MARKDOWN_FINDING_ARTIFACT,
        EXPLORATION_CLEAR_ARTIFACT,
        EXPLORATION_CLEAR_OBLIGATION_ARTIFACT,
    }
)

CANDIDATE_FIELD_LIMITS: Mapping[str, int] = {
    "title": 240,
    "mechanism": 6000,
    "harm": 4000,
}
CANDIDATE_FIELDS = frozenset(CANDIDATE_FIELD_LIMITS)

EFFECTIVE_EVIDENCE_SCOPES = frozenset(
    {
        "NONE",
        "UNSPECIFIED",
        "ANALYTICAL",
        "IN_SCOPE_SOURCE",
        "IN_SCOPE_EXECUTION",
        "EXTERNAL_PRIMARY",
    }
)
EFFECTIVE_PROOF_SCOPES = ("NONE", "ANALYTICAL", "MECHANISM", "REACHABILITY", "HARM")
EFFECTIVE_HARM_SCOPES = frozenset({"UNPROVEN", "CONDITIONAL", "MATERIAL_HARM"})
_PROOF_RANK = {value: index for index, value in enumerate(EFFECTIVE_PROOF_SCOPES)}


class ProducerResolutionError(ValueError):
    """A materialized artifact has no unique registry authority."""


class CandidateSchemaError(ValueError):
    """A candidate cannot enter a Markdown-bearing delivery projection."""

    def __init__(self, reasons: Sequence[str]):
        self.reasons = tuple(str(reason) for reason in reasons)
        super().__init__("; ".join(self.reasons))


class TypedProducerActionError(ValueError):
    """A typed producer artifact cannot be consumed without guessing."""


@dataclass(frozen=True)
class ProducerIdPrefix:
    """One context-free numeric producer namespace.

    ``lifecycle`` distinguishes prefixes emitted by current checked-in
    producer contracts from read-compatible historical namespaces.  It is not
    semantic or protocol metadata.
    """

    prefix: str
    lifecycle: str


@dataclass(frozen=True)
class ProducerIdClassification:
    """Non-authoritative syntax/registration result for one source ID."""

    raw_id: str
    normalized_id: str
    prefix: str
    ordinal_text: str
    status: str
    identity_debt: str
    identity_authority: bool = False


# This is the sole declarative namespace manifest shared by the registry,
# parser, and mechanical niche bridge.  The first tuple is independently
# fixture-checked against every prefix currently emitted by checked-in producer
# contracts.  The second preserves IDs accepted by older runs.
CURRENT_PRODUCER_ID_PREFIXES: tuple[str, ...] = (
    "AA", "AL", "AV", "BLS", "CBS", "CCT", "CFG", "CM", "CMI",
    "COS", "CPI", "CR", "CS", "CT", "CU", "DA", "DEP", "DEX",
    "EDA", "EPA", "EVT", "EX", "FA", "FC", "FL", "GCI", "GO",
    "GOV", "HF", "IBC", "IHR", "II", "LC", "LEND", "MG", "MP",
    "MSS", "NFT", "OD", "OF", "OO", "P2P", "PDA", "PSC", "PTB",
    "PV", "RPC", "RS", "SAF", "SC", "SGI", "SIG", "SL", "SLS",
    "SPEC", "SS", "SSC", "ST", "STR", "T22", "TF", "TPS", "TXI",
    "VA", "VL", "WED", "XE", "ZS",
)

COMPATIBILITY_PRODUCER_ID_PREFIXES: tuple[str, ...] = (
    "AB", "AC", "AR", "BS", "CI", "ED", "EIPF", "EN", "EP", "NS",
    "NSC", "NDA", "NEC", "NSGI", "OR", "RE", "REENT", "REF", "SA",
    "SCOUT", "SE", "SHIFT", "SR", "STATIC", "TS", "VS", "XFER",
)

PRODUCER_ID_PREFIX_MANIFEST: tuple[ProducerIdPrefix, ...] = tuple(
    ProducerIdPrefix(prefix=prefix, lifecycle="CURRENT_EMITTER")
    for prefix in CURRENT_PRODUCER_ID_PREFIXES
) + tuple(
    ProducerIdPrefix(prefix=prefix, lifecycle="READ_COMPATIBILITY")
    for prefix in COMPATIBILITY_PRODUCER_ID_PREFIXES
)

PRODUCER_ID_PREFIXES: tuple[str, ...] = tuple(
    row.prefix for row in PRODUCER_ID_PREFIX_MANIFEST
)
_PRODUCER_ID_PREFIX_SET = frozenset(PRODUCER_ID_PREFIXES)

# Normalized producer-local numeric IDs are ASCII upper-case prefixes of two
# through eight alphanumerics, one ASCII hyphen, and one or more ASCII digits.
# Case-insensitive input is normalized before registration is evaluated.
NORMALIZED_PRODUCER_ID_PATTERN = r"[A-Z][A-Z0-9]{1,7}-[0-9]+"
_NORMALIZED_PRODUCER_ID_RE = re.compile(
    rf"^(?P<prefix>[A-Z][A-Z0-9]{{1,7}})-(?P<ordinal>[0-9]+)$",
    re.IGNORECASE | re.ASCII,
)


def producer_numeric_id_pattern() -> str:
    """Return the manifest-derived context-free registered ID grammar."""

    prefixes = "|".join(
        re.escape(prefix)
        for prefix in sorted(PRODUCER_ID_PREFIXES, key=lambda value: (-len(value), value))
    )
    return rf"(?:{prefixes})-[0-9]+"


def classify_producer_id(
    value: object,
    *,
    producer: object | None = None,
) -> ProducerIdClassification:
    """Classify without granting identity authority.

    Unknown normalized IDs remain representable with reconciliation debt;
    malformed explicit IDs remain typed debt.  Neither result can authorize a
    producer or promotion by shape alone.
    """

    raw = str(value or "").strip()
    # Artifact-scoped read compatibility (for example niche EIP-N) is part of
    # registration authority even though it is deliberately excluded from the
    # global context-free manifest.  Check it before the normalized grammar so
    # every consumer classifies the same owned compatibility identity.
    if producer is not None and producer_accepts_local_id(producer, raw):
        normalized = raw.upper()
        prefix, _, ordinal = normalized.partition("-")
        return ProducerIdClassification(
            raw_id=raw,
            normalized_id=normalized,
            prefix=prefix,
            ordinal_text=ordinal,
            status="REGISTERED",
            identity_debt="",
        )
    match = _NORMALIZED_PRODUCER_ID_RE.fullmatch(raw)
    if match is None:
        return ProducerIdClassification(
            raw_id=raw,
            normalized_id="",
            prefix="",
            ordinal_text="",
            status="MALFORMED",
            identity_debt="MALFORMED_PRODUCER_ID",
        )
    prefix = match.group("prefix").upper()
    ordinal = match.group("ordinal")
    normalized = f"{prefix}-{ordinal}"
    if prefix in _PRODUCER_ID_PREFIX_SET:
        return ProducerIdClassification(
            raw_id=raw,
            normalized_id=normalized,
            prefix=prefix,
            ordinal_text=ordinal,
            status="REGISTERED",
            identity_debt="",
        )
    return ProducerIdClassification(
        raw_id=raw,
        normalized_id=normalized,
        prefix=prefix,
        ordinal_text=ordinal,
        status="UNKNOWN_WELL_FORMED",
        identity_debt="UNKNOWN_PRODUCER_PREFIX",
    )


@dataclass(frozen=True)
class RegisteredTypedAction:
    """Lossless internal adapter for a non-Markdown producer action.

    ``action_identity`` binds the producer-local ID to the exact lifecycle
    receipt and source-row lineage.  The evidence and rationale remain
    available to the independent consumer, while the delivery projection uses
    their hashes and lengths so adversarial producer text cannot inflate or
    inject into a Markdown control plane.
    """

    schema_version: str
    producer_key: str
    source_file: str
    source_artifact_hash: str
    action_id: str
    action_identity: str
    obligation_id: str
    source_finding: str
    axis: str
    instance: str
    evidence: str
    rationale: str
    lineage_source_file: str
    lineage_artifact_sha256: str
    lineage_source_row_sha256: str
    lineage_source_line: int
    lifecycle_receipt_hash: str
    proof_scope: str
    requires_independent_consumer: bool

    def delivery_row(self) -> dict[str, object]:
        """Project exact bounded facts into finding-delivery authority."""

        scopes = resolve_effective_scopes(
            producer=PRODUCERS_BY_KEY.get(self.producer_key),
            evidence_scope="ANALYTICAL",
            proof_scope=self.proof_scope,
            harm_scope="UNPROVEN",
        )
        return {
            "producer_key": self.producer_key,
            "source_file": self.source_file,
            "source_artifact_hash": self.source_artifact_hash,
            "action_id": self.action_id,
            "action_identity": self.action_identity,
            "local_id_valid": True,
            "action_kind": "ADDITIVE_CANDIDATE",
            "target_id": self.source_finding,
            "title": f"Exploration additive action {self.action_id}",
            "source_identity": f"{self.source_file}:{self.action_identity}",
            "obligation_id": self.obligation_id,
            "lineage_source_file": self.lineage_source_file,
            "lineage_artifact_sha256": self.lineage_artifact_sha256,
            "lineage_source_row_sha256": self.lineage_source_row_sha256,
            "lineage_source_line": self.lineage_source_line,
            "lifecycle_receipt_hash": self.lifecycle_receipt_hash,
            "evidence_scope": "ANALYTICAL",
            "proof_scope": self.proof_scope,
            "effective_evidence_scope": scopes["effective_evidence_scope"],
            "effective_proof_scope": scopes["effective_proof_scope"],
            "effective_harm_scope": scopes["effective_harm_scope"],
            "content_bearing": True,
            "origin_assessment": "",
            "requires_independent_consumer": True,
            "evidence_sha256": canonical_digest(self.evidence),
            "evidence_size_bytes": len(self.evidence.encode("utf-8")),
            "rationale_sha256": canonical_digest(self.rationale),
            "rationale_size_bytes": len(self.rationale.encode("utf-8")),
            "disposition": "PENDING",
            "reason": "unverified generator output requires an independent consumer",
        }


@dataclass(frozen=True)
class RegisteredEnumerationObligation:
    """Exact unresolved enumeration work; explicitly not a finding or proof."""

    schema_version: str
    producer_key: str
    source_file: str
    source_artifact_hash: str
    action_id: str
    action_identity: str
    source_finding: str
    axis: str
    instance: str
    disposition: str
    reason: str
    original_disposition: str
    original_evidence: str
    lineage_artifact_sha256: str
    lineage_source_row_sha256: str
    lineage_source_row_sha256s: tuple[str, ...]
    lineage_source_line: int
    lifecycle_receipt_hash: str
    obligation_queue_hash: str
    obligation_queue_count: int
    obligation_queue_tail: str
    proof_scope: str = "NONE"
    requires_independent_consumer: bool = True

    def delivery_row(self) -> dict[str, object]:
        return {
            "producer_key": self.producer_key,
            "source_file": self.source_file,
            "source_artifact_hash": self.source_artifact_hash,
            "action_id": self.action_id,
            "action_identity": self.action_identity,
            "local_id_valid": True,
            "action_kind": "ENUMERATION_OBLIGATION",
            "target_id": self.source_finding,
            "title": f"Unresolved exploration obligation {self.action_id}",
            "source_identity": f"{self.source_file}:{self.action_identity}",
            "lineage_artifact_sha256": self.lineage_artifact_sha256,
            "lineage_source_row_sha256": self.lineage_source_row_sha256,
            "lineage_source_row_sha256s": list(
                self.lineage_source_row_sha256s
            ),
            "lineage_source_line": self.lineage_source_line,
            "lifecycle_receipt_hash": self.lifecycle_receipt_hash,
            "obligation_queue_hash": self.obligation_queue_hash,
            "obligation_queue_count": self.obligation_queue_count,
            "obligation_queue_tail": self.obligation_queue_tail,
            "evidence_scope": "NONE",
            "proof_scope": "NONE",
            "effective_evidence_scope": "NONE",
            "effective_proof_scope": "NONE",
            "effective_harm_scope": "UNPROVEN",
            "content_bearing": False,
            "origin_assessment": "",
            "requires_independent_consumer": True,
            "reason_sha256": canonical_digest(self.reason),
            "original_evidence_sha256": canonical_digest(
                self.original_evidence
            ),
            "disposition": "INDEPENDENT_ENUMERATION_REQUIRED",
            "reason": (
                "unresolved enumeration obligation requires an exact "
                "independent-consumer disposition"
            ),
        }


def canonical_digest(value: Any) -> str:
    blob = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def normalize_evidence_scope(value: object) -> str:
    token = re.sub(r"[^A-Z0-9]+", "_", str(value or "").upper()).strip("_")
    aliases = {
        "": "UNSPECIFIED",
        "UNKNOWN": "UNSPECIFIED",
        "N_A": "UNSPECIFIED",
        "NONE": "NONE",
        "ANALYTICAL": "ANALYTICAL",
        "ANALYTICAL_CANDIDATE": "ANALYTICAL",
        "ANALYTICAL_DISAGREEMENT": "ANALYTICAL",
        "LOW_CONFIDENCE_ANALYTICAL_CANDIDATE": "ANALYTICAL",
        "UNVERIFIED_GENERATOR_OUTPUT": "ANALYTICAL",
        "IN_SCOPE_SOURCE": "IN_SCOPE_SOURCE",
        "CODE_TRACE": "IN_SCOPE_SOURCE",
        "IN_SCOPE_EXECUTION": "IN_SCOPE_EXECUTION",
        "EXECUTION": "IN_SCOPE_EXECUTION",
        "EXECUTION_RECEIPT": "IN_SCOPE_EXECUTION",
        "EXECUTED_MECHANISM": "IN_SCOPE_EXECUTION",
        "PRIMARY_EXTERNAL_CITED": "EXTERNAL_PRIMARY",
        "EXTERNAL_PRIMARY": "EXTERNAL_PRIMARY",
    }
    return aliases.get(token, "UNSPECIFIED")


def normalize_proof_scope(value: object) -> str:
    token = re.sub(r"[^A-Z0-9]+", "_", str(value or "").upper()).strip("_")
    aliases = {
        "": "ANALYTICAL",
        "NONE": "NONE",
        "UNSPECIFIED": "ANALYTICAL",
        "ANALYTICAL": "ANALYTICAL",
        "ANALYTICAL_CANDIDATE": "ANALYTICAL",
        "LOW_CONFIDENCE_ANALYTICAL_CANDIDATE": "ANALYTICAL",
        "UNVERIFIED_GENERATOR_OUTPUT": "ANALYTICAL",
        "MECHANISM": "MECHANISM",
        "MECHANISM_ONLY": "MECHANISM",
        "STATE_TRANSITION_ONLY": "MECHANISM",
        "EXECUTED_MECHANISM": "MECHANISM",
        "REACHABILITY": "REACHABILITY",
        "HARM": "HARM",
        "HARM_PROOF": "HARM",
        "MATERIAL_HARM": "HARM",
    }
    return aliases.get(token, "ANALYTICAL")


def normalize_harm_scope(value: object) -> str:
    token = re.sub(r"[^A-Z0-9]+", "_", str(value or "").upper()).strip("_")
    aliases = {
        "": "UNPROVEN",
        "NONE": "UNPROVEN",
        "UNKNOWN": "UNPROVEN",
        "UNPROVEN": "UNPROVEN",
        "LOW": "UNPROVEN",
        "CONDITIONAL": "CONDITIONAL",
        "CONDITIONAL_HARM": "CONDITIONAL",
        "HARM": "MATERIAL_HARM",
        "MATERIAL": "MATERIAL_HARM",
        "MATERIAL_HARM": "MATERIAL_HARM",
    }
    return aliases.get(token, "UNPROVEN")


def resolve_effective_scopes(
    *,
    producer: "FindingProducer | None" = None,
    evidence_scope: object = "",
    proof_scope: object = "",
    harm_scope: object = "",
) -> dict[str, object]:
    """Resolve closed scope facts and apply the producer's proof ceiling.

    A ceiling can only reduce a proof claim.  It does not delete the candidate;
    the mismatch is retained as typed debt for later independent verification.
    """

    evidence = normalize_evidence_scope(evidence_scope)
    raw_proof = proof_scope or (producer.proof_scope_default if producer else "")
    proof = normalize_proof_scope(raw_proof)
    ceiling = normalize_proof_scope(
        producer.proof_scope_ceiling if producer else "HARM"
    )
    debt: list[str] = []
    if _PROOF_RANK[proof] > _PROOF_RANK[ceiling]:
        debt.append(
            f"proof scope {str(raw_proof).strip().upper() or proof} exceeds "
            f"producer {producer.key if producer else 'default'} ceiling {ceiling}"
        )
        proof = ceiling
    harm = normalize_harm_scope(harm_scope)
    if proof != "HARM" and harm != "UNPROVEN":
        debt.append(
            f"harm scope {harm} is unsupported by effective proof scope {proof}"
        )
        harm = "UNPROVEN"
    return {
        "effective_evidence_scope": evidence,
        "effective_proof_scope": proof,
        "effective_harm_scope": harm,
        "scope_debt": tuple(debt),
    }

REQUIRED_DELIVERY_CONSUMERS: tuple[str, ...] = (
    "canonical_identity",
    "pre_dedup_promotion",
    "late_harvest",
    "containment",
    "resume_hashing",
    "human_review",
)


@dataclass(frozen=True)
class FindingProducer:
    key: str
    artifact_patterns: tuple[str, ...]
    local_id_patterns: tuple[str, ...]
    owner_phase: str
    required_consumers: frozenset[str]
    lineage_id_patterns: tuple[str, ...] = ()
    # Read-only aliases from historical artifacts.  They are deliberately
    # excluded from producer_id_pattern(), so a legacy namespace collision
    # cannot become a global prose/internal-ID grammar again.
    legacy_local_id_patterns: tuple[str, ...] = ()
    action_contract: str = "FINDING"
    content_policy: str = "CONTENT_BEARING_ONLY"
    proof_scope_default: str = "ANALYTICAL_CANDIDATE"
    proof_scope_ceiling: str = "HARM"
    artifact_format: str = MARKDOWN_FINDING_ARTIFACT

    def __post_init__(self) -> None:
        if not self.key or not self.artifact_patterns or not self.owner_phase:
            raise ValueError("producer key, artifacts, and owner phase are required")
        unknown = set(self.required_consumers) - set(REQUIRED_DELIVERY_CONSUMERS)
        if unknown:
            raise ValueError(f"unknown producer consumers: {sorted(unknown)}")
        if self.proof_scope_ceiling not in EFFECTIVE_PROOF_SCOPES:
            raise ValueError(f"invalid proof-scope ceiling {self.proof_scope_ceiling!r}")
        if self.artifact_format not in REGISTERED_ARTIFACT_FORMATS:
            raise ValueError(f"invalid registered artifact format {self.artifact_format!r}")


_ALL = frozenset(REQUIRED_DELIVERY_CONSUMERS)
_DELIVERY = _ALL

# First-pass discovery prefixes are assigned by the spawn manifest, so the
# registry cannot enumerate a closed semantic prefix list.  Keep the grammar
# syntactic and artifact-scoped: one manifest token plus a numeric ordinal.
# Canonical/report IDs and the two rescan namespaces are deliberately excluded
# so a generic breadth artifact cannot impersonate a downstream identity or a
# more-specific producer.
_DISCOVERY_LOCAL_ID_PATTERNS: tuple[str, ...] = (
    # ``F-N`` is the documented compatibility form emitted by legacy Claude
    # breadth workers and remains producer-local inside analysis_*.md. It is
    # not a report ID. Excluding it made P0-L reject valid live breadth output
    # before inventory could preserve it. Canonical inventory/report/chain
    # namespaces remain excluded.
    # Exclusions must be token-local because this grammar is embedded inside
    # larger scanners. A whole-string ``$`` lets ``C-02`` through when followed
    # by Markdown punctuation in a longer input.
    r"(?!(?:INV|C|H|M|L|I|CC|CH)-\d+(?![A-Za-z0-9_-]))"
    r"(?!(?:RS|PC)\d+-\d+(?![A-Za-z0-9_-]))"
    r"[A-Z][A-Z0-9]{0,31}-\d+",
)

# Graph-sweep workers likewise mint generic, producer-local source IDs.  The
# same bounded syntax covers the documented L<N>, CI, NS, ST, PANIC, PAIR and
# sweep-specific abbreviations without turning arbitrary Markdown headings or
# canonical inventory/report IDs into findings.
_L1_GRAPH_LOCAL_ID_PATTERNS: tuple[str, ...] = _DISCOVERY_LOCAL_ID_PATTERNS


FINDING_PRODUCERS: tuple[FindingProducer, ...] = (
    FindingProducer(
        key="breadth",
        artifact_patterns=("analysis_*.md",),
        local_id_patterns=_DISCOVERY_LOCAL_ID_PATTERNS,
        owner_phase="breadth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="depth_core",
        artifact_patterns=(
            "depth_consensus_invariant_findings.md",
            "depth_state_trace_findings.md",
            "depth_edge_case_findings.md",
            "depth_external_findings.md",
            "depth_token_flow_findings.md",
            "depth_network_surface_findings.md",
            "depth_methodology_repair_findings.md",
            "depth_iter2_*_findings.md",
            "depth_iter3_*_findings.md",
            "depth_da_*_findings.md",
            "design_stress_findings.md",
            "perturbation_findings.md",
        ),
        local_id_patterns=(
            r"DCI-\d+", r"DEC-\d+", r"DST-\d+", r"DX-\d+", r"DN-\d+",
            r"DNS-\d+", r"DA-[A-Z0-9_-]+-\d+", r"DA\d+-[A-Z0-9_-]+-\d+",
            r"DS-\d+", r"DE-\d+", r"DT-\d+", r"PERT-\d+", r"ATT-\d+",
            r"MAD-\d+",
        ),
        owner_phase="depth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="attention_repair",
        artifact_patterns=("attention_repair_findings.md",),
        local_id_patterns=(r"ATT-\d+",),
        owner_phase="attention_repair",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="rescan_and_per_contract",
        artifact_patterns=("analysis_rescan_*.md", "analysis_percontract_*.md"),
        # PCRE-N is minted deterministically by the driver's
        # analysis_percontract_reemit.md recovery producer.  It must share the
        # same registry projection as the artifact or canonical identity/report
        # consumers will treat an on-disk recovered candidate as nonexistent.
        # The live rescan/per-contract prompts mint RS<N>-<M>/PC<N>-<M>.
        # Retain the recovery/older role aliases so current on-disk runs remain
        # readable and the deterministic PCRE re-emitter stays first-class.
        local_id_patterns=(
            r"RS\d+-\d+", r"PC\d+-\d+",
            r"RSW-\d+", r"SP-\d+", r"PCRE-\d+",
        ),
        owner_phase="rescan",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        # The targeted rescan methodology repair is emitted after the accepted
        # rescan barrier.  Its historical ``analysis_*`` name also matches the
        # broad breadth glob, so it needs an exact producer contract or its
        # MAR identities are harvested under the wrong phase and then rejected.
        key="rescan_methodology_repair",
        artifact_patterns=("analysis_methodology_repair_rescan.md",),
        local_id_patterns=(r"MAR-\d+",),
        owner_phase="rescan",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_graph_sweep",
        artifact_patterns=("graph_sweep*.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_coverage_fill",
        artifact_patterns=("coverage_fill_*.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_panic_audit",
        artifact_patterns=("panic_audit_*.md", "panic_audit_summary.md"),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_symmetric_pair",
        artifact_patterns=("symmetric_pair_findings.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_field_validation",
        artifact_patterns=("field_validation_matrix.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_primitive_correctness",
        artifact_patterns=("primitive_correctness_findings.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_network_amplification",
        artifact_patterns=("network_amplification_findings.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="l1_lifecycle_replay",
        artifact_patterns=("lifecycle_replay_findings.md",),
        local_id_patterns=_L1_GRAPH_LOCAL_ID_PATTERNS,
        owner_phase="graph_sweeps",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="blind_spot",
        artifact_patterns=("blind_spot_*_findings.md",),
        local_id_patterns=(r"BLIND-[A-Z]?-?\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="scanner",
        artifact_patterns=("scanner_*_findings.md",),
        local_id_patterns=(r"SLITHER-\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="niche",
        artifact_patterns=("niche_*_findings.md",),
        local_id_patterns=(producer_numeric_id_pattern(),),
        # EIP-N used to be accepted as a niche producer identity.  Preserve
        # exact resume/read compatibility at a producer-owned artifact, but do
        # not project it into the global identity grammar: EIP-N is public.
        legacy_local_id_patterns=(r"EIP-\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="validation_sweep",
        artifact_patterns=("validation_sweep_findings.md", "scanner_validation_findings.md"),
        # The legacy scanner-validation adapter emits SLITHER-N while the
        # role-native validation sweep emits VS-N. Both are producer-local for
        # these exact artifacts; the broader scanner glob is not their owner.
        local_id_patterns=(r"VS-\d+", r"SLITHER-\d+"),
        owner_phase="depth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="sibling_propagation",
        artifact_patterns=("sibling_propagation_findings.md",),
        local_id_patterns=(r"SP-\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
    ),
    FindingProducer(
        key="medusa_fuzz",
        artifact_patterns=("medusa_fuzz_findings.md",),
        local_id_patterns=(r"MEDUSA-\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
        proof_scope_default="EXECUTED_MECHANISM",
        proof_scope_ceiling="MECHANISM",
    ),
    FindingProducer(
        key="trident_fuzz",
        artifact_patterns=("trident_fuzz_findings.md",),
        local_id_patterns=(r"FUZZ-\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
        proof_scope_default="EXECUTED_MECHANISM",
        proof_scope_ceiling="MECHANISM",
    ),
    FindingProducer(
        key="cargo_fuzz",
        artifact_patterns=("cargo_fuzz_findings.md",),
        local_id_patterns=(r"FUZZ-\d+",),
        owner_phase="depth",
        required_consumers=_DELIVERY,
        proof_scope_default="EXECUTED_MECHANISM",
        proof_scope_ceiling="MECHANISM",
    ),
    FindingProducer(
        key="foundry_invariant_fuzz",
        artifact_patterns=("invariant_fuzz_results.md",),
        local_id_patterns=(r"FUZZ-\d+",),
        owner_phase="depth",
        required_consumers=_ALL,
        action_contract="FUZZ_VIOLATION",
        proof_scope_default="EXECUTED_MECHANISM",
        proof_scope_ceiling="MECHANISM",
    ),
    FindingProducer(
        key="application_skeptic",
        artifact_patterns=(APPLICATION_SKEPTIC_PROJECTION,),
        local_id_patterns=(r"ASKP-\d+",),
        lineage_id_patterns=(r"ASCP-[A-F0-9]{24}", r"ASW-[A-F0-9]{24}"),
        owner_phase="application_skeptic",
        required_consumers=_ALL,
        # An exact independent-disagreement reopen is mandatory verifier work.
        # Optional depth confidence is telemetry and may not prevent its
        # inventory/queue delivery (NC-5).
        action_contract="UNVERIFIED_GENERATOR_OUTPUT",
        proof_scope_default="LOW_CONFIDENCE_ANALYTICAL_CANDIDATE",
        proof_scope_ceiling="ANALYTICAL",
    ),
    FindingProducer(
        key="candidate_negative_skeptic",
        artifact_patterns=(CANDIDATE_NEGATIVE_SKEPTIC_PROJECTION,),
        local_id_patterns=(r"ASKP-\d+",),
        lineage_id_patterns=(r"ASCP-[A-F0-9]{24}", r"ASW-[A-F0-9]{24}"),
        owner_phase="application_skeptic",
        required_consumers=_ALL,
        action_contract="UNVERIFIED_GENERATOR_OUTPUT",
        proof_scope_default="LOW_CONFIDENCE_ANALYTICAL_CANDIDATE",
        proof_scope_ceiling="ANALYTICAL",
    ),
    FindingProducer(
        key="exploration_skeptic",
        artifact_patterns=("exploration_skeptic_findings.md",),
        local_id_patterns=(r"SKEP-\d+", r"SKEP-LEGACY-[A-F0-9]{12}"),
        owner_phase="exploration_skeptic",
        required_consumers=_ALL,
        action_contract="NEW_UPGRADE_REOPEN",
    ),
    FindingProducer(
        key="exploration_clear_additive",
        artifact_patterns=(EXPLORATION_CLEAR_RECEIPT,),
        local_id_patterns=(r"SKEP-\d+", r"SKEP-LEGACY-[A-F0-9]{12}"),
        lineage_id_patterns=(r"ECLR-[A-F0-9]{24}",),
        owner_phase="exploration_skeptic",
        required_consumers=_ALL,
        action_contract="UNVERIFIED_GENERATOR_OUTPUT",
        content_policy="TYPED_ACTION_REQUIRES_INDEPENDENT_CONSUMER",
        proof_scope_default="UNVERIFIED_GENERATOR_OUTPUT",
        proof_scope_ceiling="ANALYTICAL",
        artifact_format=EXPLORATION_CLEAR_ARTIFACT,
    ),
    FindingProducer(
        key="exploration_clear_obligation",
        artifact_patterns=(EXPLORATION_CLEAR_OBLIGATIONS,),
        local_id_patterns=(r"ECLR-[A-F0-9]{24}",),
        lineage_id_patterns=(r"ECLR-[A-F0-9]{24}",),
        owner_phase="exploration_skeptic",
        required_consumers=_ALL,
        action_contract="ENUMERATION_OBLIGATION",
        content_policy="TYPED_NON_FINDING_HUMAN_REVIEW_DEBT",
        proof_scope_default="NONE",
        proof_scope_ceiling="NONE",
        artifact_format=EXPLORATION_CLEAR_OBLIGATION_ARTIFACT,
    ),
    FindingProducer(
        key="depth_self_exclusion_reemit",
        artifact_patterns=("depth_selfexcl_reemit_findings.md",),
        local_id_patterns=(r"DXRE-\d+", r"DXRE-[A-Z0-9_-]+"),
        owner_phase="depth",
        required_consumers=_ALL,
        action_contract="FINDING_OR_REVIEW_DISPOSITION",
        content_policy="CONTENT_OR_HUMAN_REVIEW",
    ),
)

PRODUCERS_BY_KEY: dict[str, FindingProducer] = {
    producer.key: producer for producer in FINDING_PRODUCERS
}


def _dedupe(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def producer_patterns(
    consumer: str,
    *,
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
    owner_phase: str | None = None,
) -> tuple[str, ...]:
    if consumer not in REQUIRED_DELIVERY_CONSUMERS:
        raise ValueError(f"unknown registry consumer {consumer!r}")
    return _dedupe(
        pattern
        for producer in producers
        if consumer in producer.required_consumers
        and (owner_phase is None or producer.owner_phase == owner_phase)
        for pattern in producer.artifact_patterns
    )


def producer_id_pattern(
    consumer: str = "pre_dedup_promotion",
    *,
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
    include_lineage: bool = False,
) -> str:
    parts = _dedupe(
        pattern
        for producer in producers
        if consumer in producer.required_consumers
        for pattern in (
            *producer.local_id_patterns,
            *(producer.lineage_id_patterns if include_lineage else ()),
        )
    )
    return r"(?:" + "|".join(parts) + r")"


def producer_accepts_current_local_id(
    producer: FindingProducer, finding_id: str
) -> bool:
    """Validate an ID minted by a current producer invocation."""

    return any(
        re.fullmatch(pattern, finding_id or "", re.IGNORECASE)
        for pattern in producer.local_id_patterns
    )


def producer_accepts_local_id(producer: FindingProducer, finding_id: str) -> bool:
    """Read a producer-owned current or historical local identity.

    This compatibility API is artifact-provenance scoped.  New producer
    outputs must use :func:`producer_accepts_current_local_id`.
    """

    return any(
        re.fullmatch(pattern, finding_id or "", re.IGNORECASE)
        for pattern in (
            *producer.local_id_patterns,
            *producer.legacy_local_id_patterns,
        )
    )


def producer_read_id_pattern(producer: FindingProducer) -> str:
    """Return producer-scoped current + legacy read grammar.

    Unlike :func:`producer_id_pattern`, this must only be used after artifact
    ownership has been resolved.  That provenance boundary is what makes a
    colliding legacy alias safe to recognize.
    """

    parts = _dedupe(
        (*producer.local_id_patterns, *producer.legacy_local_id_patterns)
    )
    return r"(?:" + "|".join(parts) + r")"


def producers_for_artifact(
    artifact_name: str,
    *,
    consumer: str | None = None,
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
) -> tuple[FindingProducer, ...]:
    return tuple(
        producer
        for producer in producers
        if (consumer is None or consumer in producer.required_consumers)
        and any(fnmatch(artifact_name, pattern) for pattern in producer.artifact_patterns)
    )


def _artifact_pattern_specificity(pattern: str, artifact_name: str) -> tuple[int, int, int]:
    exact = int(pattern == artifact_name)
    wildcard_count = sum(pattern.count(char) for char in "*?[")
    literal_count = len(re.sub(r"[\*\?\[\]]", "", pattern))
    return exact, literal_count, -wildcard_count


def producer_for_artifact(
    artifact_name: str,
    *,
    consumer: str | None = None,
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
) -> FindingProducer | None:
    candidates: list[tuple[tuple[int, int, int], FindingProducer, str]] = []
    for producer in producers_for_artifact(
        artifact_name, consumer=consumer, producers=producers
    ):
        matching_patterns = tuple(
            pattern
            for pattern in producer.artifact_patterns
            if fnmatch(artifact_name, pattern)
        )
        score, pattern = max(
            (_artifact_pattern_specificity(value, artifact_name), value)
            for value in matching_patterns
        )
        candidates.append((score, producer, pattern))
    if not candidates:
        return None
    best_score = max(row[0] for row in candidates)
    winners = [row for row in candidates if row[0] == best_score]
    if len(winners) != 1:
        detail = ", ".join(
            f"{producer.key}:{pattern}" for _, producer, pattern in winners
        )
        raise ProducerResolutionError(
            f"ambiguous producer authority for {artifact_name!r}: {detail}"
        )
    return winners[0][1]


def registry_payload(
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
) -> dict[str, object]:
    rows = []
    for producer in sorted(producers, key=lambda row: row.key):
        row = asdict(producer)
        row["required_consumers"] = sorted(producer.required_consumers)
        rows.append(row)
    return {"schema_version": REGISTRY_SCHEMA, "producers": rows}


def registry_digest(
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
) -> str:
    blob = json.dumps(
        registry_payload(producers), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def projected_registry(
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
) -> dict[str, tuple[str, ...]]:
    return {
        consumer: producer_patterns(consumer, producers=producers)
        for consumer in REQUIRED_DELIVERY_CONSUMERS
    }


def validate_registry_projection_completeness(
    *,
    producers: Sequence[FindingProducer] = FINDING_PRODUCERS,
    projections: Mapping[str, Sequence[str]] | None = None,
) -> list[str]:
    """Diff registry requirements against actual consumer projections."""
    actual = projected_registry(producers) if projections is None else projections
    issues: list[str] = []
    seen_keys: set[str] = set()
    for producer in producers:
        if producer.key in seen_keys:
            issues.append(f"duplicate producer key: {producer.key}")
        seen_keys.add(producer.key)
        for consumer in sorted(producer.required_consumers):
            available = set(actual.get(consumer, ()))
            missing = set(producer.artifact_patterns) - available
            if missing:
                issues.append(
                    f"producer {producer.key} missing from {consumer}: "
                    + ", ".join(sorted(missing))
                )
    return issues


def materialized_producer_paths(
    scratchpad: Path,
    consumer: str,
) -> tuple[Path, ...]:
    seen: set[Path] = set()
    out: list[Path] = []
    for pattern in producer_patterns(consumer):
        for path in sorted(Path(scratchpad).glob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                out.append(path)
    return tuple(out)


def producer_resume_digest(scratchpad: Path) -> str:
    rows: list[dict[str, object]] = []
    for path in materialized_producer_paths(scratchpad, "resume_hashing"):
        try:
            data = path.read_bytes()
            rows.append({
                "artifact": path.name,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        except Exception as exc:
            rows.append({"artifact": path.name, "error": type(exc).__name__})
    payload = {
        "registry_digest": registry_digest(),
        "artifacts": rows,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def artifact_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_registered_typed_actions(
    path: str | Path,
    *,
    consumer: str = "pre_dedup_promotion",
) -> tuple[RegisteredTypedAction, ...]:
    """Load exact actions from a registered non-Markdown producer artifact.

    This is the live consumer boundary for P0-F.  It deliberately returns no
    Markdown and grants no adjudication authority: every exported action is
    stamped ``UNVERIFIED_GENERATOR_OUTPUT`` and requires an independent
    consumer.  Schema, receipt, bound-source, and row-lineage validation are
    delegated to the lifecycle's fail-closed loader before adaptation.
    """

    artifact = Path(path)
    try:
        producer = producer_for_artifact(artifact.name, consumer=consumer)
    except ProducerResolutionError:
        raise
    if producer is None:
        raise TypedProducerActionError(
            f"artifact {artifact.name!r} has no registered producer"
        )
    if producer.artifact_format == MARKDOWN_FINDING_ARTIFACT:
        return ()
    if producer.artifact_format != EXPLORATION_CLEAR_ARTIFACT:
        raise TypedProducerActionError(
            f"producer {producer.key} has no typed action adapter"
        )

    # Lazy import keeps the registry usable by tools that do not ship or invoke
    # the exploration lifecycle while preserving its one authoritative parser.
    try:
        from exploration_clear_lifecycle import load_lifecycle_receipt  # type: ignore

        receipt = load_lifecycle_receipt(artifact)
    except Exception as exc:
        raise TypedProducerActionError(
            f"cannot validate {artifact.name}: {type(exc).__name__}: {exc}"
        ) from exc

    source_hash = artifact_sha256(artifact)
    out: list[RegisteredTypedAction] = []
    identities: set[str] = set()
    for index, action in enumerate(receipt.additive_actions):
        values = {
            "action_id": action.action_id,
            "obligation_id": action.obligation_id,
            "source_finding": action.source_finding,
            "axis": action.axis,
            "instance": action.instance,
            "evidence": action.evidence,
            "rationale": action.rationale,
            "artifact_sha256": action.artifact_sha256,
            "source_row_sha256": action.source_row_sha256,
            "proof_scope": action.proof_scope,
        }
        invalid_types = sorted(
            name for name, value in values.items() if not isinstance(value, str)
        )
        if invalid_types or not isinstance(action.source_line, int):
            raise TypedProducerActionError(
                f"{artifact.name}: additive action {index} has invalid field types: "
                + ", ".join(invalid_types or ["source_line"])
            )
        if not producer_accepts_current_local_id(producer, action.action_id):
            raise TypedProducerActionError(
                f"{artifact.name}:{action.action_id}: local ID is outside "
                f"producer {producer.key} grammar"
            )
        if not any(
            re.fullmatch(pattern, action.obligation_id, re.IGNORECASE)
            for pattern in producer.lineage_id_patterns
        ):
            raise TypedProducerActionError(
                f"{artifact.name}:{action.action_id}: malformed obligation lineage"
            )
        if (
            action.proof_scope != "UNVERIFIED_GENERATOR_OUTPUT"
            or action.requires_independent_consumer is not True
        ):
            raise TypedProducerActionError(
                f"{artifact.name}:{action.action_id}: additive action attempted "
                "to bypass independent verification"
            )
        if action.artifact_sha256 != receipt.artifact_sha256:
            raise TypedProducerActionError(
                f"{artifact.name}:{action.action_id}: lineage artifact digest mismatch"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", action.source_row_sha256):
            raise TypedProducerActionError(
                f"{artifact.name}:{action.action_id}: malformed source-row digest"
            )
        if action.source_line < 1:
            raise TypedProducerActionError(
                f"{artifact.name}:{action.action_id}: invalid source line"
            )

        identity_payload = {
            "schema_version": REGISTERED_TYPED_ACTION_SCHEMA,
            "producer_key": producer.key,
            "source_file": artifact.name,
            "source_artifact_hash": source_hash,
            "lifecycle_receipt_hash": receipt.receipt_hash,
            "action_id": action.action_id,
            "obligation_id": action.obligation_id,
            "lineage_artifact_sha256": action.artifact_sha256,
            "lineage_source_file": Path(receipt.source_artifact).name,
            "lineage_source_row_sha256": action.source_row_sha256,
            "lineage_source_line": action.source_line,
        }
        action_identity = (
            "ECTA-" + canonical_digest(identity_payload)[:24].upper()
        )
        if action_identity in identities:
            raise TypedProducerActionError(
                f"{artifact.name}: duplicate exact typed action identity {action_identity}"
            )
        identities.add(action_identity)
        out.append(
            RegisteredTypedAction(
                schema_version=REGISTERED_TYPED_ACTION_SCHEMA,
                producer_key=producer.key,
                source_file=artifact.name,
                source_artifact_hash=source_hash,
                action_id=action.action_id,
                action_identity=action_identity,
                obligation_id=action.obligation_id,
                source_finding=action.source_finding,
                axis=action.axis,
                instance=action.instance,
                evidence=action.evidence,
                rationale=action.rationale,
                lineage_source_file=Path(receipt.source_artifact).name,
                lineage_artifact_sha256=action.artifact_sha256,
                lineage_source_row_sha256=action.source_row_sha256,
                lineage_source_line=action.source_line,
                lifecycle_receipt_hash=receipt.receipt_hash,
                proof_scope=action.proof_scope,
                requires_independent_consumer=True,
            )
        )
    return tuple(out)


def read_registered_enumeration_obligations(
    path: str | Path,
    *,
    consumer: str = "pre_dedup_promotion",
) -> tuple[RegisteredEnumerationObligation, ...]:
    """Load the exact P0-F unresolved denominator without making findings.

    The persisted queue must equal the lifecycle receipt's deterministic queue
    byte-for-fact (schema, source hashes, count, tail, items, and queue hash).
    Returned obligations carry no proof authority and can only be cleared by an
    exact independent-consumer disposition or retained as human-review debt.
    """

    artifact = Path(path)
    producer = producer_for_artifact(artifact.name, consumer=consumer)
    if producer is None:
        raise TypedProducerActionError(
            f"artifact {artifact.name!r} has no registered producer"
        )
    if producer.artifact_format != EXPLORATION_CLEAR_OBLIGATION_ARTIFACT:
        return ()
    try:
        from exploration_clear_lifecycle import (  # type: ignore
            RECEIPT_NAME,
            load_lifecycle_receipt,
            obligation_queue,
        )

        receipt = load_lifecycle_receipt(artifact.parent / RECEIPT_NAME)
        payload = json.loads(artifact.read_text(encoding="utf-8"))
        expected = obligation_queue(receipt)
    except Exception as exc:
        raise TypedProducerActionError(
            f"cannot validate {artifact.name}: {type(exc).__name__}: {exc}"
        ) from exc
    if payload != expected:
        raise TypedProducerActionError(
            f"{artifact.name}: queue does not exactly match its lifecycle receipt"
        )
    if not isinstance(payload, dict):
        raise TypedProducerActionError(
            f"{artifact.name}: obligation queue must be an object"
        )

    queue_hash = str(payload["queue_hash"])
    count = int(payload["count"])
    tail = str(payload["tail"])
    out: list[RegisteredEnumerationObligation] = []
    identities: set[str] = set()
    for item in payload["items"]:
        action_id = str(item["obligation_id"])
        if not producer_accepts_current_local_id(producer, action_id):
            raise TypedProducerActionError(
                f"{artifact.name}:{action_id}: local ID is outside producer grammar"
            )
        identity_payload = {
            "schema_version": REGISTERED_ENUMERATION_OBLIGATION_SCHEMA,
            "producer_key": producer.key,
            "source_file": artifact.name,
            "source_artifact_hash": artifact_sha256(artifact),
            "lifecycle_receipt_hash": receipt.receipt_hash,
            "obligation_queue_hash": queue_hash,
            "obligation_queue_count": count,
            "obligation_queue_tail": tail,
            "action_id": action_id,
            "lineage_artifact_sha256": item["artifact_sha256"],
            "lineage_source_row_sha256": item["source_row_sha256"],
            "lineage_source_row_sha256s": item["source_row_sha256s"],
            "lineage_source_line": item["source_line"],
        }
        action_identity = (
            "ECOA-" + canonical_digest(identity_payload)[:24].upper()
        )
        if action_identity in identities:
            raise TypedProducerActionError(
                f"{artifact.name}: duplicate exact obligation identity {action_identity}"
            )
        identities.add(action_identity)
        out.append(
            RegisteredEnumerationObligation(
                schema_version=REGISTERED_ENUMERATION_OBLIGATION_SCHEMA,
                producer_key=producer.key,
                source_file=artifact.name,
                source_artifact_hash=artifact_sha256(artifact),
                action_id=action_id,
                action_identity=action_identity,
                source_finding=str(item["source_finding"]),
                axis=str(item["axis"]),
                instance=str(item["instance"]),
                disposition=str(item["disposition"]),
                reason=str(item["reason"]),
                original_disposition=str(item["original_disposition"]),
                original_evidence=str(item["original_evidence"]),
                lineage_artifact_sha256=str(item["artifact_sha256"]),
                lineage_source_row_sha256=str(item["source_row_sha256"]),
                lineage_source_row_sha256s=tuple(
                    str(value) for value in item["source_row_sha256s"]
                ),
                lineage_source_line=int(item["source_line"]),
                lifecycle_receipt_hash=receipt.receipt_hash,
                obligation_queue_hash=queue_hash,
                obligation_queue_count=count,
                obligation_queue_tail=tail,
            )
        )
    if len(out) != count or (out[-1].action_id if out else "") != tail:
        raise TypedProducerActionError(
            f"{artifact.name}: obligation denominator or tail mismatch"
        )
    return tuple(out)


def _load_bound_exploration_aliases(scratchpad: Path) -> dict[str, str]:
    """Load the one shared, semantically re-derived alias authority."""

    path = Path(scratchpad) / "exploration_clear_prior_aliases.json"
    if not path.is_file():
        return {}
    try:
        from exploration_clear_lifecycle import load_canonical_prior_authority

        return dict(load_canonical_prior_authority(scratchpad).aliases)
    except Exception as exc:
        raise TypedProducerActionError(
            f"cannot validate exploration alias authority: {exc}"
        ) from exc


def _require_active_phaseio_lineage(
    scratchpad: Path,
    *,
    identity: str,
    owner_suffixes: tuple[str, ...],
) -> dict[str, Any]:
    """Return one exact ACTIVE/OUTPUT_COMMITTED producer binding."""

    state_path = Path(scratchpad) / "_artifact_state.json"
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TypedProducerActionError(
            f"PhaseIO producer ledger is unavailable: {exc}"
        ) from exc
    bindings = state.get("artifact_bindings")
    units = state.get("work_units")
    if not isinstance(bindings, dict) or not isinstance(units, dict):
        raise TypedProducerActionError("PhaseIO producer ledger is malformed")
    binding = bindings.get(identity)
    if not isinstance(binding, dict):
        raise TypedProducerActionError(
            f"{identity}: committed PhaseIO producer binding is absent"
        )
    owner = str(binding.get("owner_key") or "")
    unit = units.get(owner)
    if (
        not owner.endswith(owner_suffixes)
        or binding.get("status") != "ACTIVE"
        or not isinstance(unit, dict)
        or unit.get("semantic_status") != "ACTIVE"
        or unit.get("execution_state") != "OUTPUT_COMMITTED"
        or unit.get("contract_digest") != binding.get("contract_digest")
        or unit.get("run_id") != binding.get("run_id")
    ):
        raise TypedProducerActionError(
            f"{identity}: PhaseIO producer is not ACTIVE/OUTPUT_COMMITTED"
        )
    root_name, relative = identity.split(":", 1)
    if root_name != "scratchpad":
        raise TypedProducerActionError(
            f"{identity}: unsupported registry producer root"
        )
    path = Path(scratchpad) / relative
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TypedProducerActionError(
            f"{identity}: committed producer bytes are unavailable"
        ) from exc
    if (
        binding.get("size") != len(raw)
        or binding.get("sha256") != hashlib.sha256(raw).hexdigest()
    ):
        raise TypedProducerActionError(
            f"{identity}: committed producer bytes drifted"
        )
    return unit


def validated_enumgap_obligation_dispositions(
    scratchpad: str | Path,
    *,
    production_root: str | Path | None = None,
) -> dict[str, dict[str, str]]:
    """Return independently recomputed terminal ECLR dispositions only.

    Missing authority is a normal empty result.  Once any authority artifact is
    present, partial/stale/forged state raises and therefore cannot clear
    registry debt.  This function disposes enumeration work only; it grants no
    evidence, proof, severity, finding, or report-body authority.
    """

    root = Path(scratchpad)
    authority_names = (
        "enumgap_worklist.json",
        "enumgap_exploration_findings.md",
        "enumgap_disposition_receipt.json",
        "enumgap_residual_obligations.json",
    )
    present = [name for name in authority_names if (root / name).is_file()]
    if not present:
        return {}
    if len(present) != len(authority_names):
        raise TypedProducerActionError(
            "enumgap disposition authority is partial: "
            + ", ".join(sorted(present))
        )
    _require_active_phaseio_lineage(
        root,
        identity="scratchpad:enumgap_worklist.json",
        owner_suffixes=("/enumgap_disposition/planning",),
    )
    _require_active_phaseio_lineage(
        root,
        identity="scratchpad:enumgap_exploration_findings.md",
        owner_suffixes=(
            "/enumgap_exploration/model",
            "/enumgap_exploration/empty_stub",
        ),
    )
    for name in (
        "enumgap_disposition_receipt.json",
        "enumgap_residual_obligations.json",
    ):
        _require_active_phaseio_lineage(
            root,
            identity=f"scratchpad:{name}",
            owner_suffixes=("/enumgap_disposition/reconcile",),
        )
    try:
        from enumgap_disposition import (  # type: ignore
            validate_enumgap_disposition_authority,
        )

        receipt = validate_enumgap_disposition_authority(
            root,
            production_root=(
                Path(production_root) if production_root is not None
                else root.parent
            ),
            canonical_prior_ids=_load_bound_exploration_aliases(root),
        )
    except TypedProducerActionError:
        raise
    except Exception as exc:
        raise TypedProducerActionError(
            f"enumgap disposition authority is invalid: {type(exc).__name__}: {exc}"
        ) from exc

    unresolved = set(receipt.get("unresolved_work_item_ids") or ())
    try:
        from enumeration_gate import (  # type: ignore
            parse_enumgap_exploration_findings,
            validated_enumgap_promotion_deliveries,
        )

        output_text = (root / "enumgap_exploration_findings.md").read_text(
            encoding="utf-8"
        )
    except (OSError, UnicodeError) as exc:
        raise TypedProducerActionError(
            f"cannot inspect enumgap emitted actions: {exc}"
        ) from exc
    valid_emitted_actions = {
        str(row["id"]): row
        for row in parse_enumgap_exploration_findings(output_text)
    }
    try:
        delivered_actions = validated_enumgap_promotion_deliveries(root)
    except Exception:
        # A stale/malformed delivery receipt can only withhold EMITTED_ACTION
        # disposal.  It must not revoke an independently proven source locus or
        # canonical-prior disposition in the same denominator.
        delivered_actions = {}
    allowed = {"PRODUCTION_LOCUS", "CANONICAL_PRIOR", "EMITTED_ACTION"}
    resolved: dict[str, dict[str, str]] = {}
    for row in receipt.get("dispositions") or ():
        if not isinstance(row, Mapping):
            continue
        identity = str(row.get("work_item_id") or "")
        if (
            str(row.get("kind") or "") != "EXPLORATION_CLEAR"
            or identity in unresolved
            or not re.fullmatch(r"ECLR-[A-F0-9]{24}", identity)
        ):
            continue
        resolution_kind = str(row.get("resolution_kind") or "")
        disposition = str(row.get("disposition") or "")
        source_item = row.get("source_item")
        if resolution_kind not in allowed or not isinstance(source_item, Mapping):
            continue
        if (
            source_item.get("work_item_id") != identity
            or source_item.get("kind") != "EXPLORATION_CLEAR"
            or source_item.get("proof_scope") != "NONE"
            or source_item.get("requires_independent_consumer") is not True
        ):
            continue
        if resolution_kind in {"PRODUCTION_LOCUS", "CANONICAL_PRIOR"}:
            if disposition != "CLEAR" or not row.get("resolved_reference"):
                continue
        elif (
            disposition not in {"FINDING", "UNRESOLVED"}
            or not row.get("emitted_action_id")
            or row.get("resolved_reference") != row.get("emitted_action_id")
            or str(row.get("emitted_action_id") or "").upper()
            not in valid_emitted_actions
            or str(row.get("emitted_action_id") or "").upper()
            not in delivered_actions
        ):
            continue
        resolved[identity] = {
            "resolution_kind": resolution_kind,
            "resolved_reference": str(row.get("resolved_reference") or ""),
            "enumgap_receipt_hash": str(receipt.get("receipt_hash") or ""),
            "enumgap_worklist_hash": str(
                (receipt.get("worklist") or {}).get("worklist_hash") or ""
            ),
            "enumgap_output_sha256": str(receipt.get("output_sha256") or ""),
        }
        if resolution_kind == "EMITTED_ACTION":
            delivery = delivered_actions[
                str(row.get("emitted_action_id") or "").upper()
            ]
            resolved[identity].update({
                "promotion_delivery_id": str(delivery["inventory_id"]),
                "promotion_source_block_sha256": str(
                    delivery["source_block_sha256"]
                ),
                "promotion_inventory_block_sha256": str(
                    delivery["inventory_block_sha256"]
                ),
            })
    return resolved


_APPLICATION_PROPOSAL_KEYS = frozenset(
    {
        "schema_version",
        "producer",
        "source_obligation_id",
        "source_work_item_id",
        "assessor_identity",
        "assessor_invocation_id",
        "assessor_evidence_sha256",
        "candidate",
        "proposal_id",
        "proposal_digest",
    }
)


def _bounded_projection_text(value: object, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise CandidateSchemaError((f"{field} must be text",))
    text = value.strip()
    reasons: list[str] = []
    if not text:
        reasons.append(f"{field} cannot be empty")
    encoded = text.encode("utf-8")
    if len(encoded) > limit:
        reasons.append(f"{field} exceeds {limit} UTF-8 bytes")
    if any(char in text for char in "\r\n"):
        reasons.append(f"{field} contains a line break")
    if any(ord(char) < 0x20 and char != "\t" for char in text):
        reasons.append(f"{field} contains a control character")
    if "<!--" in text or "PLAMEN_STATUS:" in text.upper():
        reasons.append(f"{field} contains a reserved projection control token")
    if field == "title" and any(char in text for char in "[]"):
        reasons.append("title contains a heading-delimiter bracket")
    if reasons:
        raise CandidateSchemaError(reasons)
    return text


def validate_application_skeptic_candidate(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise CandidateSchemaError(("candidate must be an object",))
    missing = sorted(CANDIDATE_FIELDS - set(value))
    extra = sorted(set(value) - CANDIDATE_FIELDS)
    reasons: list[str] = []
    if missing:
        reasons.append("candidate missing fields: " + ", ".join(missing))
    if extra:
        reasons.append(
            "candidate has "
            f"{len(extra)} unexpected field(s) "
            f"(names_sha256={canonical_digest(extra)})"
        )
    if reasons:
        raise CandidateSchemaError(reasons)
    normalized: dict[str, str] = {}
    aggregate: list[str] = []
    for field in sorted(CANDIDATE_FIELDS):
        try:
            normalized[field] = _bounded_projection_text(
                value[field], field, CANDIDATE_FIELD_LIMITS[field]
            )
        except CandidateSchemaError as exc:
            aggregate.extend(exc.reasons)
    if aggregate:
        raise CandidateSchemaError(aggregate)
    return normalized


def normalize_application_skeptic_proposal(
    raw: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(raw, Mapping):
        raise CandidateSchemaError(("proposal must be an object",))
    missing = sorted(_APPLICATION_PROPOSAL_KEYS - set(raw))
    extra = sorted(set(raw) - _APPLICATION_PROPOSAL_KEYS)
    if missing or extra:
        reasons = []
        if missing:
            reasons.append("proposal missing fields: " + ", ".join(missing))
        if extra:
            reasons.append("proposal has unexpected fields: " + ", ".join(extra))
        raise CandidateSchemaError(reasons)
    if raw.get("schema_version") != "plamen.finding_candidate_proposal.v1":
        raise CandidateSchemaError(("proposal schema_version mismatch",))
    if raw.get("producer") != "application_skeptic":
        raise CandidateSchemaError(("proposal producer mismatch",))
    proposal_id = str(raw.get("proposal_id") or "").strip().upper()
    if not re.fullmatch(r"ASCP-[A-F0-9]{24}", proposal_id):
        raise CandidateSchemaError(("proposal_id is invalid",))
    source_work_item_id = str(raw.get("source_work_item_id") or "").strip().upper()
    if not re.fullmatch(r"ASW-[A-F0-9]{24}", source_work_item_id):
        raise CandidateSchemaError(("source_work_item_id is invalid",))
    normalized: dict[str, object] = {
        "schema_version": str(raw["schema_version"]),
        "producer": "application_skeptic",
        "source_obligation_id": _bounded_projection_text(
            raw["source_obligation_id"], "source_obligation_id", 256
        ),
        "source_work_item_id": source_work_item_id,
        "assessor_identity": _bounded_projection_text(
            raw["assessor_identity"], "assessor_identity", 256
        ),
        "assessor_invocation_id": _bounded_projection_text(
            raw["assessor_invocation_id"], "assessor_invocation_id", 256
        ),
        "assessor_evidence_sha256": str(
            raw.get("assessor_evidence_sha256") or ""
        ).strip().casefold(),
        "candidate": validate_application_skeptic_candidate(raw["candidate"]),
    }
    if not re.fullmatch(r"[0-9a-f]{64}", normalized["assessor_evidence_sha256"]):
        raise CandidateSchemaError(("assessor_evidence_sha256 is invalid",))
    expected_digest = canonical_digest(normalized)
    declared_digest = str(raw.get("proposal_digest") or "").strip().casefold()
    expected_id = "ASCP-" + expected_digest[:24].upper()
    if declared_digest != expected_digest:
        raise CandidateSchemaError(("proposal_digest mismatch",))
    if proposal_id != expected_id:
        raise CandidateSchemaError(("proposal_id/content binding mismatch",))
    return {
        **normalized,
        "proposal_id": proposal_id,
        "proposal_digest": expected_digest,
    }


def _application_projection_text(
    normalized: Sequence[Mapping[str, object]],
) -> tuple[str, dict[str, str]]:
    mapping = {
        str(row["proposal_id"]): f"ASKP-{index}"
        for index, row in enumerate(normalized, start=1)
    }
    lines = [
        "# Application Skeptic Candidate Proposals",
        "",
        "Driver-owned projection of typed independent-disagreement proposals. "
        "Every row is an unproven, low-confidence analytical candidate routed "
        "through normal dedup/chain/verification.",
        "",
        f"**Projection Schema**: {APPLICATION_SKEPTIC_PROJECTION_SCHEMA}",
        "",
    ]
    for row in normalized:
        candidate = row["candidate"]
        assert isinstance(candidate, Mapping)
        local_id = mapping[str(row["proposal_id"])]
        source_identity = ":".join(
            (
                str(row["proposal_id"]),
                str(row["source_obligation_id"]),
                str(row["source_work_item_id"]),
            )
        )
        lines.extend(
            [
                f"### Finding [{local_id}]: {candidate['title']}",
                "**Action**: NEW",
                "**Severity**: Medium",
                "**Location**: unknown (independent methodology disagreement)",
                "**Evidence Scope**: ANALYTICAL_DISAGREEMENT",
                "**Proof Scope**: LOW_CONFIDENCE_ANALYTICAL_CANDIDATE",
                "**Harm Scope**: UNPROVEN",
                "**Harm Confidence**: LOW",
                f"**Proposal Schema**: {row['schema_version']}",
                f"**Proposal ID**: {row['proposal_id']}",
                f"**Proposal Digest**: {row['proposal_digest']}",
                f"**Source Obligation ID**: {row['source_obligation_id']}",
                f"**Source Work Item ID**: {row['source_work_item_id']}",
                f"**Assessor Identity**: {row['assessor_identity']}",
                f"**Assessor Invocation ID**: {row['assessor_invocation_id']}",
                f"**Assessor Evidence SHA-256**: {row['assessor_evidence_sha256']}",
                f"**Source Identity**: {source_identity}",
                f"**Description**: {candidate['mechanism']}",
                f"**Impact**: {candidate['harm']}",
                "",
            ]
        )
    lines.append("<!-- PLAMEN_STATUS: COMPLETE -->")
    return "\n".join(lines) + "\n", mapping


def _projection_field(block: str, label: str) -> str:
    match = re.search(
        rf"(?im)^\*\*{re.escape(label)}\*\*:\s*(.*?)\s*$", block
    )
    return match.group(1).strip() if match else ""


def _parse_application_skeptic_projection_text(text: str) -> list[dict[str, object]]:
    schema = _projection_field(text, "Projection Schema")
    if schema != APPLICATION_SKEPTIC_PROJECTION_SCHEMA:
        raise CandidateSchemaError(("application projection schema mismatch",))
    headings = list(
        re.finditer(
            r"(?m)^### Finding \[(ASKP-\d+)\]:\s*(.*?)\s*$", text
        )
    )
    out: list[dict[str, object]] = []
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[heading.start():end]
        raw = {
            "schema_version": _projection_field(block, "Proposal Schema"),
            "producer": "application_skeptic",
            "source_obligation_id": _projection_field(
                block, "Source Obligation ID"
            ),
            "source_work_item_id": _projection_field(block, "Source Work Item ID"),
            "assessor_identity": _projection_field(block, "Assessor Identity"),
            "assessor_invocation_id": _projection_field(
                block, "Assessor Invocation ID"
            ),
            "assessor_evidence_sha256": _projection_field(
                block, "Assessor Evidence SHA-256"
            ),
            "candidate": {
                "title": heading.group(2).strip(),
                "mechanism": _projection_field(block, "Description"),
                "harm": _projection_field(block, "Impact"),
            },
            "proposal_id": _projection_field(block, "Proposal ID"),
            "proposal_digest": _projection_field(block, "Proposal Digest"),
        }
        out.append(normalize_application_skeptic_proposal(raw))
    if len({row["proposal_id"] for row in out}) != len(out):
        raise CandidateSchemaError(("application projection duplicates proposal IDs",))
    return out


def parse_application_skeptic_proposal_projection(
    path: Path,
) -> list[dict[str, object]]:
    return _parse_application_skeptic_projection_text(
        Path(path).read_text(encoding="utf-8", errors="strict")
    )


def write_application_skeptic_proposal_projection(
    scratchpad: Path,
    proposals: Sequence[Mapping[str, object]],
    *,
    projection_name: str = APPLICATION_SKEPTIC_PROJECTION,
) -> dict[str, str]:
    """Project typed ASCP proposals into normal ASKP finding delivery.

    The caller passes the complete authoritative proposal set from the typed
    application-skeptic receipt.  This function never parses receipt prose and
    never upgrades analytical disagreement to proof.  ASKP IDs are assigned by
    sorted stable ASCP proposal identity, making the full projection byte-stable
    on resume.
    """
    normalized = sorted(
        (normalize_application_skeptic_proposal(raw) for raw in proposals),
        key=lambda row: str(row["proposal_id"]),
    )
    if len({row["proposal_id"] for row in normalized}) != len(normalized):
        raise CandidateSchemaError(("duplicate application-skeptic proposal",))
    content, mapping = _application_projection_text(normalized)
    if _parse_application_skeptic_projection_text(content) != normalized:
        raise CandidateSchemaError(("application projection render/parse parity failed",))
    if (
        not projection_name
        or Path(projection_name).name != projection_name
        or Path(projection_name).suffix.casefold() != ".md"
    ):
        raise CandidateSchemaError(("projection_name must be one Markdown basename",))
    path = Path(scratchpad) / projection_name
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.read_text(encoding="utf-8") == content:
            return mapping
    except OSError:
        pass
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)
    return mapping


def render_delivery_human_review_projection(
    receipt: Mapping[str, object],
) -> str:
    """Render the JSON delivery authority's review/debt subset losslessly."""

    declared_digest = receipt.get("receipt_digest")
    if declared_digest is not None:
        unsigned = {
            key: value for key, value in receipt.items() if key != "receipt_digest"
        }
        if declared_digest != canonical_digest(unsigned):
            raise ValueError("finding-delivery receipt digest mismatch")
    actions = receipt.get("actions")
    residual = receipt.get("residual_debt")
    if not isinstance(actions, list) or not isinstance(residual, list):
        raise ValueError("finding-delivery receipt lacks typed actions/residual debt")
    review_states = {
        "HUMAN_REVIEW",
        "RESIDUAL_DEBT",
        "ORIGIN_NEGATIVE_REVIEW_REQUIRED",
        "DELIVERY_REVIEW_REQUIRED",
        "INDEPENDENT_ENUMERATION_REQUIRED",
    }
    debt_rows = [
        row
        for row in actions
        if isinstance(row, Mapping) and row.get("disposition") in review_states
    ]
    if not debt_rows and not residual:
        return ""
    lines = [
        "# Registered Finding Delivery Debt",
        "",
        "These producer rows are retained for methodology/human review. "
        "Content-less rows are not vulnerability findings and must not "
        "enter the client finding body.",
        "",
        "| Source identity | Producer action | Title | Disposition | Reason |",
        "|---|---|---|---|---|",
    ]
    for row in debt_rows:
        source_identity = row.get("source_identity") or (
            f"{row.get('source_file')}:{row.get('action_id')}"
        )
        reason = str(row.get("reason") or "retained delivery debt").replace(
            "|", "/"
        )
        title = str(row.get("title") or "").replace("|", "/")
        lines.append(
            f"| {source_identity} | {row.get('action_id')} | {title} | "
            f"{row.get('disposition')} | {reason} |"
        )
    for detail in residual:
        lines.append(
            f"| registered-delivery | - | - | RESIDUAL_DEBT | "
            f"{str(detail).replace('|', '/')} |"
        )
    return "\n".join(lines) + "\n"
