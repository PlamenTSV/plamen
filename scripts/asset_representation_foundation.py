"""Typed, proposal-only foundation for asset-representation boundary work.

The current reference graph can enumerate names and references, but most of
its providers do not prove occurrence-level use/def, type, or representation
relations.  This module makes that limitation explicit.  Weak evidence adds
an ``asset_representation_boundary`` candidate; it never certifies that the
corresponding methodology was applied.

There is intentionally no universal "wrapped asset" classifier here.  The
operator and graph-v3 schemas reserve future evidence shapes, but neither is
terminal until an authorized out-of-tree principal/provider receipt substrate
exists and is independently validated.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

try:
    from enumeration_type_ir import normalize_source_binding_path
except ImportError:  # pragma: no cover - package import path
    from .enumeration_type_ir import normalize_source_binding_path


FOUNDATION_SCHEMA = "plamen.asset_representation_foundation.v1"
SEMANTIC_EDGE_SCHEMA = "plamen.occurrence_semantic_edges.v1"
OPERATOR_ATTESTATION_SCHEMA = "plamen.asset_representation_operator_attestations.v1"
OPERATOR_ATTESTATION_FILE = "asset_representation_operator_attestations.json"
RECON_FEATURE_SCHEMA_V3 = "plamen.recon_feature_facts.v3"
MECHANICAL_GRAPH_SCHEMA_V3 = "plamen.mechanical_graph.v3"

MODEL_PROPOSAL = "MODEL_PROPOSAL"
MECHANICAL_PROVIDER = "MECHANICAL_PROVIDER"
OPERATOR_ATTESTED = "OPERATOR_ATTESTED"
PROVENANCE_STATES = frozenset(
    {MODEL_PROPOSAL, MECHANICAL_PROVIDER, OPERATOR_ATTESTED}
)

UNAVAILABLE = "UNAVAILABLE"
IDENTIFIER_ONLY = "IDENTIFIER_ONLY"
REFERENCE_ONLY = "REFERENCE_ONLY"
EXACT_OCCURRENCE = "EXACT_OCCURRENCE_TYPE_USE_DEF"
CAPABILITY_STATES = frozenset(
    {UNAVAILABLE, IDENTIFIER_ONLY, REFERENCE_ONLY, EXACT_OCCURRENCE}
)

EXACT_RELATION_CAPABILITY = "EXACT_ASSET_REPRESENTATION_RELATION"
PROVIDER_CAPABILITY_MATRIX_VERSION = "asset-representation.providers.v2"
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_PATH_DRIVE = re.compile(r"^[A-Za-z]:")
_EDGE_KINDS = frozenset(
    {
        "NATIVE_PRIMITIVE_USE",
        "TYPE_OF",
        "USE_DEF",
        "VALUE_FLOW",
        "REPRESENTATION_TRANSITION",
    }
)


def _capability(
    provider: str,
    native_primitive: str,
    representation_relation: str,
    *,
    terminal: bool = False,
) -> dict[str, Any]:
    return {
        "provider": provider,
        "native_primitive": native_primitive,
        "representation_relation": representation_relation,
        "occurrence_use_def_type": (
            EXACT_OCCURRENCE
            if representation_relation == EXACT_OCCURRENCE
            else UNAVAILABLE
        ),
        "terminal_classification": bool(terminal),
    }


# Closed on purpose.  Adding a provider requires a fixture demonstrating the
# exact occurrence/type contract; an unrecognized provider fails open to debt.
_PROVIDER_CAPABILITY_MATRIX: dict[str, dict[str, Any]] = {
    "daml": _capability("daml", IDENTIFIER_ONLY, IDENTIFIER_ONLY),
    "evm-source": _capability("evm-source", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "go-source": _capability("go-source", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "move": _capability("move", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "move-source": _capability("move-source", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "rust-source": _capability("rust-source", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "scip": _capability("scip", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "scip-go": _capability("scip-go", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "scip-rust": _capability("scip-rust", IDENTIFIER_ONLY, REFERENCE_ONLY),
    "slither": _capability("slither", REFERENCE_ONLY, REFERENCE_ONLY),
    # Reserved v3 fact shape.  Parsing capability is not terminal authority:
    # there is no out-of-tree BAKE execution receipt/principal today.
    "typed-semantic-v3": _capability(
        "typed-semantic-v3", EXACT_OCCURRENCE, EXACT_OCCURRENCE, terminal=False
    ),
}


def provider_capability(provider: object) -> dict[str, Any]:
    key = str(provider or "").strip().casefold()
    row = _PROVIDER_CAPABILITY_MATRIX.get(key)
    if row is None:
        return _capability("UNKNOWN", UNAVAILABLE, UNAVAILABLE)
    return dict(row)


def provider_capability_matrix() -> list[dict[str, Any]]:
    return [dict(_PROVIDER_CAPABILITY_MATRIX[key]) for key in sorted(_PROVIDER_CAPABILITY_MATRIX)]


def provider_capability_matrix_payload() -> dict[str, Any]:
    providers = provider_capability_matrix()
    identity = {
        "version": PROVIDER_CAPABILITY_MATRIX_VERSION,
        "providers": providers,
    }
    digest = hashlib.sha256(
        json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest().upper()
    return {**identity, "sha256": digest}


def normalize_bound_path(path: object) -> str:
    value = normalize_source_binding_path(str(path or ""))
    # Source manifests treat a lexical `.` segment as the same path while
    # retaining `..` for the trust-boundary validator to reject explicitly.
    absolute = value.startswith("/")
    normalized = "/".join(
        part for part in value.split("/") if part not in {"", "."}
    )
    return ("/" if absolute else "") + normalized


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest().upper()


def feature_fact_binding(raw: Mapping[str, Any]) -> dict[str, Any]:
    relation = raw.get("relation")
    relation_binding = None
    if isinstance(relation, Mapping):
        relation_binding = {
            "kind": str(relation.get("kind") or "").strip().upper(),
            "object_id": str(relation.get("object_id") or "").strip(),
            "symbol": re.sub(
                r"[^A-Za-z0-9]+", "", str(relation.get("symbol") or "")
            ),
        }
    return {
        "subject_id": str(raw.get("subject_id") or "").strip(),
        "concept": str(raw.get("concept") or "").strip(),
        "polarity": str(raw.get("polarity") or "PRESENT").strip().upper(),
        "evidence_identity": str(
            raw.get("evidence_identity") or raw.get("fact_id") or ""
        ).strip(),
        "relation": relation_binding,
    }


def make_operator_attestation(
    raw: Mapping[str, Any],
    *,
    run_binding: Mapping[str, str],
    attestor_id: str,
    evidence_sha256: str,
) -> dict[str, str]:
    payload = {
        "authority": OPERATOR_ATTESTED,
        "provider": "operator-attestation",
        "capability": EXACT_RELATION_CAPABILITY,
        "attestor_id": str(attestor_id or "").strip(),
        "run_id": str(run_binding.get("run_id") or "").strip(),
        "source_snapshot_digest": str(
            run_binding.get("source_snapshot_digest") or ""
        ).strip().upper(),
        "fact_binding_sha256": _sha256(feature_fact_binding(raw)),
        "evidence_sha256": str(evidence_sha256 or "").strip().upper(),
    }
    return {
        "attestation_id": "ARO-" + _sha256(payload)[:24],
        **payload,
    }


def build_operator_attestation_registry(
    attestations: Sequence[Mapping[str, Any]],
    *,
    run_binding: Mapping[str, str],
) -> dict[str, Any]:
    rows = [dict(row) for row in attestations]
    rows.sort(key=lambda row: str(row.get("attestation_id") or ""))
    return {
        "schema_version": OPERATOR_ATTESTATION_SCHEMA,
        "run_id": str(run_binding.get("run_id") or ""),
        "source_snapshot_digest": str(
            run_binding.get("source_snapshot_digest") or ""
        ).upper(),
        "attestations": rows,
    }


def load_operator_attestation_registry(
    scratchpad: Path,
    *,
    run_binding: Mapping[str, str],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Load only a checkpoint-bound, out-of-band operator sidecar.

    Recon workers can write proposal files, so an ``OPERATOR_ATTESTED`` string
    inside a recon row is not authority by itself.  The exact sidecar bytes
    must have been bound into the driver-owned checkpoint before consumption.
    """

    root = Path(scratchpad)
    path = root / OPERATOR_ATTESTATION_FILE
    if not path.is_file():
        return {}, []
    issues: list[str] = []
    try:
        checkpoint = json.loads((root / "_v2_checkpoint.json").read_text(encoding="utf-8"))
        bindings = checkpoint.get("operator_attestation_bindings")
        expected_sha = (
            str(bindings.get(OPERATOR_ATTESTATION_FILE) or "").upper()
            if isinstance(bindings, Mapping)
            else ""
        )
        actual_sha = hashlib.sha256(path.read_bytes()).hexdigest().upper()
        if not _HEX64.fullmatch(expected_sha) or expected_sha != actual_sha:
            return {}, ["operator attestation sidecar is not checkpoint-bound"]
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, [f"operator attestation sidecar is malformed: {type(exc).__name__}"]
    if not isinstance(payload, Mapping) or payload.get("schema_version") != OPERATOR_ATTESTATION_SCHEMA:
        return {}, ["operator attestation sidecar schema mismatch"]
    if (
        str(payload.get("run_id") or "").casefold()
        != str(run_binding.get("run_id") or "").casefold()
        or str(payload.get("source_snapshot_digest") or "").casefold()
        != str(run_binding.get("source_snapshot_digest") or "").casefold()
    ):
        return {}, ["operator attestation sidecar run/source binding mismatch"]
    rows = payload.get("attestations")
    if not isinstance(rows, list):
        return {}, ["operator attestation rows are malformed"]
    registry: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            issues.append(f"operator attestation row {index} is malformed")
            continue
        attestation_id = str(raw.get("attestation_id") or "").strip()
        identity = {key: value for key, value in raw.items() if key != "attestation_id"}
        expected_id = "ARO-" + _sha256(identity)[:24]
        if attestation_id != expected_id or attestation_id in registry:
            issues.append(f"operator attestation row {index} identity is invalid")
            continue
        registry[attestation_id] = dict(raw)
    return registry, issues


def _semantic_edge_binds_feature(
    edge: Mapping[str, Any], raw: Mapping[str, Any]
) -> bool:
    fact = feature_fact_binding(raw)
    relation = fact.get("relation")
    return bool(
        isinstance(relation, Mapping)
        and str(edge.get("kind") or "").upper() == "REPRESENTATION_TRANSITION"
        and str(edge.get("subject_id") or "") == str(fact.get("subject_id") or "")
        and str(edge.get("object_id") or "")
        == str(relation.get("object_id") or "")
    )


def resolve_feature_authority(
    raw: Mapping[str, Any],
    *,
    origin: str,
    schema_version: str,
    run_binding: Mapping[str, str],
    graph_provider: str = "",
    operator_attestations: Mapping[str, Mapping[str, Any]] | None = None,
    semantic_edges: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Resolve provenance without minting terminal authority.

    ``OPERATOR_ATTESTED`` and graph-v3 are reserved evidence *shapes*.  A
    scratchpad/checkpoint pair and self-described graph fields are both inside
    the audit run's write boundary, so neither can independently certify work.
    ``authority_state`` is localized metadata for later migration/repair.
    """

    provider_default = str(graph_provider or "model-recon").strip().casefold()

    def proposal(
        state: str,
        *,
        provenance_state: str = MODEL_PROPOSAL,
        provider: str = provider_default,
        capability: str = IDENTIFIER_ONLY,
    ) -> tuple[dict[str, Any], list[str]]:
        return (
            {
                "provenance": provenance_state,
                "provider": provider or "unknown",
                "capability": capability,
                "authority_state": state,
                "terminal_application_authority": False,
            },
            [],
        )

    provenance = raw.get("provenance")
    if origin == "RECON":
        if schema_version != RECON_FEATURE_SCHEMA_V3:
            return proposal("LEGACY_MODEL_PROPOSAL")
        if not isinstance(provenance, Mapping):
            return proposal("MISSING_PROVENANCE_PROPOSAL")
        authority = str(provenance.get("authority") or "").strip().upper()
        if authority == MODEL_PROPOSAL:
            return proposal("DECLARED_MODEL_PROPOSAL")
        if authority == OPERATOR_ATTESTED:
            attestation_id = str(provenance.get("attestation_id") or "").strip()
            attested = (operator_attestations or {}).get(attestation_id)
            if not isinstance(attested, Mapping):
                return proposal("INVALID_OPERATOR_CLAIM")
            expected = _sha256(feature_fact_binding(raw))
            checks = (
                str(attested.get("capability") or "")
                == EXACT_RELATION_CAPABILITY,
                bool(str(attested.get("attestor_id") or "").strip()),
                str(attested.get("run_id") or "").casefold()
                == str(run_binding.get("run_id") or "").casefold(),
                str(attested.get("source_snapshot_digest") or "").casefold()
                == str(run_binding.get("source_snapshot_digest") or "").casefold(),
                str(attested.get("fact_binding_sha256") or "").casefold()
                == expected.casefold(),
                bool(_HEX64.fullmatch(str(attested.get("evidence_sha256") or ""))),
                str(attested.get("authority") or "").upper() == OPERATOR_ATTESTED,
            )
            if not all(checks):
                return proposal("INVALID_OPERATOR_CLAIM")
            return proposal(
                "RESERVED_OPERATOR_OUT_OF_TREE_AUTHORITY_UNAVAILABLE",
                provenance_state=OPERATOR_ATTESTED,
                provider="operator-attestation",
                capability=EXACT_RELATION_CAPABILITY,
            )
        if authority == MECHANICAL_PROVIDER:
            provider = str(provenance.get("provider") or "").strip().casefold()
            edge_id = str(provenance.get("semantic_edge_id") or "").strip()
            edge = (semantic_edges or {}).get(edge_id)
            structurally_bound = bool(
                isinstance(edge, Mapping)
                and str(edge.get("provider") or "").casefold() == provider
                and _semantic_edge_binds_feature(edge, raw)
                and str(provenance.get("capability") or "")
                == EXACT_RELATION_CAPABILITY
                and str(provenance.get("fact_binding_sha256") or "").casefold()
                == _sha256(feature_fact_binding(raw)).casefold()
                and str(provenance.get("source_sha256") or "").casefold()
                == str(edge.get("source_sha256") or "").casefold()
                and str(provenance.get("occurrence_id") or "")
                == str(edge.get("occurrence_id") or "")
            )
            if not structurally_bound:
                return proposal("INVALID_MECHANICAL_CLAIM")
            return proposal(
                "RESERVED_PROVIDER_OUT_OF_TREE_RECEIPT_UNAVAILABLE",
                provenance_state=MECHANICAL_PROVIDER,
                provider=provider,
                capability=EXACT_RELATION_CAPABILITY,
            )
        return proposal("INVALID_PROVENANCE_CLAIM")

    if origin == "GRAPH":
        provider = str(graph_provider or "").strip().casefold()
        capability = provider_capability(provider)
        if not isinstance(provenance, Mapping):
            return proposal(
                "GRAPH_PROPOSAL_ONLY",
                provider=provider,
                capability=capability["representation_relation"],
            )
        edge_id = str(provenance.get("semantic_edge_id") or "").strip()
        edge = (semantic_edges or {}).get(edge_id)
        structurally_bound = bool(
            schema_version == MECHANICAL_GRAPH_SCHEMA_V3
            and str(provenance.get("authority") or "").upper()
            == MECHANICAL_PROVIDER
            and str(provenance.get("capability") or "")
            == EXACT_RELATION_CAPABILITY
            and str(provenance.get("fact_binding_sha256") or "").casefold()
            == _sha256(feature_fact_binding(raw)).casefold()
            and isinstance(edge, Mapping)
            and _semantic_edge_binds_feature(edge, raw)
            and str(provenance.get("source_sha256") or "").casefold()
            == str(edge.get("source_sha256") or "").casefold()
            and str(provenance.get("occurrence_id") or "")
            == str(edge.get("occurrence_id") or "")
        )
        if not structurally_bound:
            return proposal(
                "INVALID_GRAPH_AUTHORITY_CLAIM",
                provider=provider,
                capability=capability["representation_relation"],
            )
        return proposal(
            "RESERVED_PROVIDER_OUT_OF_TREE_RECEIPT_UNAVAILABLE",
            provenance_state=MECHANICAL_PROVIDER,
            provider=provider,
            capability=EXACT_RELATION_CAPABILITY,
        )

    return proposal("INVALID_FEATURE_ORIGIN")


def _identifier_tokens(value: object) -> set[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(value or ""))
    return {
        token.casefold()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9]*", text)
        if token
    }


_NATIVE_TOKENS = frozenset({"native", "msgvalue", "gas", "value"})
_REPRESENTATION_TOKENS = frozenset(
    {"asset", "balance", "coin", "token", "wrap", "wrapped", "unwrap"}
)


def _normalized_locus(value: object) -> tuple[str, int]:
    text = str(value or "").strip()
    match = re.match(r"^(.*?):L?(\d+)$", text)
    if not match:
        return normalize_bound_path(text), 0
    return normalize_bound_path(match.group(1)), int(match.group(2))


def enumerate_asset_representation_candidates(graph: Mapping[str, Any]) -> dict[str, Any]:
    provider = str(graph.get("source") or "").strip().casefold()
    capability = provider_capability(provider)
    functions = graph.get("functions")
    issues: list[str] = []
    candidates: list[dict[str, Any]] = []
    if not isinstance(functions, Mapping):
        functions = {}
        issues.append("mechanical graph functions map unavailable")
    for identity, raw in sorted(functions.items(), key=lambda item: str(item[0])):
        info = raw if isinstance(raw, Mapping) else {}
        bare = str(info.get("bare") or re.split(r"::|\.", str(identity))[-1])
        callees = info.get("callees") if isinstance(info.get("callees"), list) else []
        name_tokens = _identifier_tokens(f"{identity} {bare}")
        callee_tokens = _identifier_tokens(" ".join(str(row) for row in callees))
        tokens = name_tokens | callee_tokens
        native = sorted(tokens & _NATIVE_TOKENS)
        representation = sorted(tokens & _REPRESENTATION_TOKENS)
        if not native or not representation:
            continue
        source_path, source_line = _normalized_locus(info.get("loc"))
        identity_payload = {
            "subject_id": f"fn:{identity}",
            "source_path": source_path,
            "source_line": source_line,
            "native_evidence": native,
            "representation_evidence": representation,
        }
        candidates.append(
            {
                "candidate_id": "ARB-" + _sha256(identity_payload)[:24],
                "obligation_class": "asset_representation_boundary",
                "subject_id": identity_payload["subject_id"],
                "occurrence_id": "function:" + str(identity),
                "source_path": source_path,
                "source_line": source_line,
                "native_evidence": native,
                "representation_evidence": representation,
                "provenance": MODEL_PROPOSAL,
                "provider": provider or "unknown",
                "provider_capability": capability["representation_relation"],
                "terminal_application_authority": False,
                "question": (
                    "Enumerate and verify the native-value and tokenized-asset "
                    "representation boundary at this exact subject."
                ),
            }
        )
    return {
        "schema_version": FOUNDATION_SCHEMA,
        "provider_capability": capability,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "issues": issues,
    }


def _safe_relative_source_path(value: object) -> str:
    path = normalize_bound_path(value)
    if (
        not path
        or path.startswith("/")
        or _SAFE_PATH_DRIVE.match(path)
        or any(part == ".." for part in path.split("/"))
    ):
        return ""
    return path


def extract_semantic_edge_foundation(graph: Mapping[str, Any]) -> dict[str, Any]:
    provider = str(graph.get("source") or "").strip().casefold()
    capability = provider_capability(provider)
    matrix = provider_capability_matrix_payload()

    def payload(
        *,
        state: str,
        edges: Sequence[Mapping[str, Any]] = (),
        repairs: Sequence[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        return {
            "schema_version": SEMANTIC_EDGE_SCHEMA,
            "migration_state": state,
            "provider_authority_state": "OUT_OF_TREE_RECEIPT_UNAVAILABLE",
            "provider_capability_matrix_version": matrix["version"],
            "provider_capability_matrix_sha256": matrix["sha256"],
            "provider_capability": capability,
            "semantic_edges": sorted(
                (dict(row) for row in edges), key=lambda row: row["edge_id"]
            ),
            "repair_obligations": sorted(
                (dict(row) for row in repairs), key=lambda row: row["repair_id"]
            ),
            # Malformation is localized in repair_obligations; it must not
            # poison the whole feature-fact phase.
            "issues": [],
        }

    if graph.get("schema_version") != MECHANICAL_GRAPH_SCHEMA_V3:
        return payload(state="EXPECTED_ABSENCE")

    def repair(index: int, raw: object, reason: str) -> dict[str, Any]:
        row = raw if isinstance(raw, Mapping) else {}
        occurrence = str(row.get("occurrence_id") or "").strip()
        subject = str(row.get("subject_id") or "").strip()
        object_id = occurrence or f"semantic_edges[{index}]"
        identity = {
            "pointer": f"semantic_edges[{index}]",
            "occurrence_id": occurrence,
            "subject_id": subject,
            "object_id": object_id,
            "provider": provider or "unknown",
            "reason": reason,
        }
        return {
            "repair_id": "ARR-" + _sha256(identity)[:24],
            **identity,
            "state": "UNACCOUNTED_REPAIR",
            "terminal_application_authority": False,
        }

    rows = graph.get("semantic_edges")
    if not isinstance(rows, list):
        return payload(
            state="DEGRADED_LOCAL_REPAIR",
            repairs=[repair(0, rows, "SEMANTIC_EDGE_COLLECTION_MALFORMED")],
        )

    parsed: list[tuple[int, dict[str, Any]]] = []
    repairs: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            repairs.append(repair(index, raw, "SEMANTIC_EDGE_ROW_MALFORMED"))
            continue
        kind = str(raw.get("kind") or "").strip().upper()
        subject = str(raw.get("subject_id") or "").strip()
        object_id = str(raw.get("object_id") or "").strip()
        occurrence = str(raw.get("occurrence_id") or "").strip()
        path = _safe_relative_source_path(raw.get("source_path"))
        digest = str(raw.get("source_sha256") or "").strip().upper()
        row_provider = str(raw.get("provider") or "").strip().casefold()
        try:
            line = int(raw.get("source_line") or 0)
            column = int(raw.get("source_column") or 0)
        except (TypeError, ValueError):
            line = column = 0
        valid = (
            kind in _EDGE_KINDS
            and bool(subject and object_id and occurrence and path)
            and line > 0
            and column >= 0
            and bool(_HEX64.fullmatch(digest))
            and row_provider == provider
            and capability["occurrence_use_def_type"] == EXACT_OCCURRENCE
        )
        if not valid:
            repairs.append(
                repair(index, raw, "SEMANTIC_EDGE_OCCURRENCE_OR_SOURCE_BINDING_INVALID")
            )
            continue
        identity = {
            "kind": kind,
            "subject_id": subject,
            "object_id": object_id,
            "occurrence_id": occurrence,
            "source_path": path,
            "source_line": line,
            "source_column": column,
            "source_sha256": digest,
            "provider": provider,
        }
        parsed.append(
            (
                index,
                {
                    "edge_id": "ASE-" + _sha256(identity)[:24],
                    **identity,
                    "provenance": MECHANICAL_PROVIDER,
                    "capability": EXACT_OCCURRENCE,
                    "authority_state": "FOUNDATION_ONLY",
                    "terminal_application_authority": False,
                },
            )
        )

    by_occurrence: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for item in parsed:
        by_occurrence.setdefault(item[1]["occurrence_id"], []).append(item)
    out: list[dict[str, Any]] = []
    for occurrence, group in sorted(by_occurrence.items()):
        if len(group) != 1:
            first_index, first = group[0]
            repairs.append(
                repair(
                    first_index,
                    first,
                    "SEMANTIC_EDGE_DUPLICATE_OR_CONFLICTING_OCCURRENCE",
                )
            )
            continue
        out.append(group[0][1])

    state = "DEGRADED_LOCAL_REPAIR" if repairs else "FOUNDATION_ONLY"
    return payload(state=state, edges=out, repairs=repairs)


__all__ = [
    "CAPABILITY_STATES",
    "EXACT_OCCURRENCE",
    "EXACT_RELATION_CAPABILITY",
    "FOUNDATION_SCHEMA",
    "IDENTIFIER_ONLY",
    "MECHANICAL_GRAPH_SCHEMA_V3",
    "MECHANICAL_PROVIDER",
    "MODEL_PROPOSAL",
    "OPERATOR_ATTESTATION_FILE",
    "OPERATOR_ATTESTATION_SCHEMA",
    "OPERATOR_ATTESTED",
    "PROVENANCE_STATES",
    "PROVIDER_CAPABILITY_MATRIX_VERSION",
    "RECON_FEATURE_SCHEMA_V3",
    "REFERENCE_ONLY",
    "SEMANTIC_EDGE_SCHEMA",
    "UNAVAILABLE",
    "enumerate_asset_representation_candidates",
    "extract_semantic_edge_foundation",
    "feature_fact_binding",
    "build_operator_attestation_registry",
    "load_operator_attestation_registry",
    "make_operator_attestation",
    "normalize_bound_path",
    "provider_capability",
    "provider_capability_matrix",
    "provider_capability_matrix_payload",
    "resolve_feature_authority",
]
