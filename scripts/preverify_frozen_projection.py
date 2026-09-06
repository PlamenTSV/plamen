"""Immutable paired pre-verification projection.

This provider imports the final mutable inventory only through either an exact
current-run PhaseIO producer or an explicitly replayed, same-run contiguous
semantic-mutation chain.  It then rebuilds ``finding_records.json`` from those
exact inventory bytes and publishes a content-addressed projection.  The
mutable roots are never replaced or re-blessed.

Evidence validation is advisory.  Authorized evidence bytes are frozen beside
the pair; missing or untrusted evidence produces visible repair debt and is
not included in ``logical_to_physical``, so it cannot remove a candidate.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from artifact_ledger import (
    active_committed_work_unit_authority_issues,
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_import_authority,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from bounded_artifact_io import read_bounded_regular_bytes
from chain_candidate_inventory_union import (
    ChainCandidateDeltaError,
    DELTA_DERIVATION_ALGORITHM,
    DELTA_DERIVATION_CONFORMANCE_SHA256,
    DELTA_RECEIPT_SCHEMA,
    DELTA_ROOT,
    DELTA_SCHEMA,
    DELTA_SOURCE_PREIMAGE_LEAVES,
    derive_preverify_chain_candidate_payload,
    prepare_preverify_chain_candidate_delta,
    validate_preverify_chain_candidate_derivation_conformance,
)
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
import plamen_mechanical as _mechanical
from preverify_chain_pair_projection import (
    PAIR_DERIVATION_ALGORITHM,
    PAIR_DERIVATION_CONFORMANCE_SHA256,
    RECEIPT_SCHEMA as PAIR_RECEIPT_SCHEMA,
    derive_preverify_chain_pair_relation,
    validate_preverify_chain_pair_derivation_conformance,
)


SCHEMA = "plamen.preverify_frozen_projection.v1"
RECEIPT_SCHEMA = "plamen.preverify_frozen_projection_receipt.v2"
DERIVATION_ALGORITHM = "plamen.preverify.frozen_derivation.v1"
# This value is a checked-in compatibility promise, not a digest of the
# current Python file.  ``derive_preverify_derivation_conformance_sha256``
# replays fixed vectors through every byte-producing primitive and must equal
# this constant before a receipt is written or accepted.
DERIVATION_CONFORMANCE_SHA256 = (
    "de2cdf47242adbf9eb82bf2fc4dab5156efd9abd78d508741d6c83c6c4d29795"
)
ROOT = "_preverify_frozen"
INVENTORY_LOGICAL = "findings_inventory.md"
RECORDS_LOGICAL = "finding_records.json"
EVIDENCE_LOGICAL = "inventory_evidence_validation.md"
FROZEN_SOURCE_PREIMAGE_LEAVES = {
    # Opaque immutable preimages use compact leaves.  The receipt maps every
    # semantic role explicitly, while the shorter physical names keep nested
    # SHA-256 generations usable under ordinary Windows path limits.
    "inventory": "i.bin",
    "evidence": "v.bin",
    "chain_candidate_delta": "d.json",
    "chain_candidate_delta_receipt": "r.json",
    "chain_candidate_source_hypotheses": "d_h.bin",
    "chain_candidate_source_finding_mapping": "d_m.bin",
    "chain_candidate_source_pair_receipt": "d_p.json",
    "chain_candidate_source_enabler_results": "d_e.bin",
    "chain_candidate_source_auto_map_receipt": "d_a.json",
    "semantic_mutations": "s.json",
}
MAX_SOURCE_BYTES = 64 * 1024 * 1024
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FINDING_HEADING = re.compile(
    r"(?im)^#{2,4}\s+Finding\s+\[([A-Za-z0-9_.-]+)\]\s*:"
)


class PreverifyFrozenProjectionError(ValueError):
    """The immutable final-input projection could not be authorized."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PreverifyFrozenProjectionError(
            f"projection value is not canonical JSON: {exc}"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes(value))


def _safe_relative(value: object, *, label: str) -> str:
    text = str(value or "")
    path = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PreverifyFrozenProjectionError(
            f"{label} is not a canonical relative POSIX path"
        )
    return text


def _binding(raw: bytes) -> dict[str, Any]:
    return {"sha256": _sha(raw), "size": len(raw)}


def _records_bytes(inventory_raw: bytes) -> bytes:
    try:
        text = inventory_raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PreverifyFrozenProjectionError(
            "final inventory is not strict UTF-8"
        ) from exc
    records = _mechanical._records_from_inventory_text(text)
    heading_ids = {
        match.group(1).upper() for match in _FINDING_HEADING.finditer(text)
    }
    record_ids = {
        str(row.get("inventory_id") or "").upper()
        for row in records
        if isinstance(row, Mapping)
    }
    if heading_ids != record_ids:
        missing = sorted(heading_ids - record_ids)
        unexpected = sorted(record_ids - heading_ids)
        raise PreverifyFrozenProjectionError(
            "deterministic finding-record reconstruction lost or invented "
            f"identity; missing={missing!r}; unexpected={unexpected!r}"
        )
    return _canonical_bytes({
        "schema_version": "plamen.finding_records.v2",
        "source": INVENTORY_LOGICAL,
        "source_sha256": _sha(inventory_raw),
        "records": records,
    })


def derive_preverify_finding_records_bytes(inventory_raw: bytes) -> bytes:
    """Return the sole deterministic records projection for inventory bytes."""

    return _records_bytes(bytes(inventory_raw))


def _inventory_sections(text: str) -> dict[str, str]:
    matches = list(_FINDING_HEADING.finditer(text))
    sections: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = (
            matches[index + 1].start()
            if index + 1 < len(matches)
            else len(text)
        )
        identity = match.group(1).upper()
        block = text[match.start():end].strip()
        if identity in sections and sections[identity] != block:
            raise PreverifyFrozenProjectionError(
                f"base inventory contains divergent duplicate identity {identity}"
            )
        sections[identity] = block
    return sections


def _normalized_block(value: str) -> str:
    return "\n".join(
        line.rstrip()
        for line in str(value or "").replace("\r\n", "\n").split("\n")
    ).strip()


def _validated_chain_candidate_delta(
    *,
    root: Path,
    project: Path,
    dimensions: Mapping[str, str],
    delta: Mapping[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, Any]],
    dict[str, bytes],
]:
    if not isinstance(delta, Mapping):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta is malformed"
        )
    generation = str(delta.get("generation_digest") or "")
    prefix = f"{DELTA_ROOT}/generation_{generation}/"
    candidate_path = _safe_relative(
        delta.get("candidate_path"),
        label="chain candidate delta payload",
    )
    receipt_path = _safe_relative(
        delta.get("receipt_path"),
        label="chain candidate delta receipt",
    )
    required = delta.get("required_paths")
    if (
        delta.get("schema_version") != DELTA_SCHEMA
        or delta.get("state") != "OUTPUT_COMMITTED"
        or delta.get("safe_to_consume") is not True
        or delta.get("run_id") != dimensions["run_id"]
        or delta.get("proof_authority") != "NONE"
        or not _HEX64.fullmatch(generation)
        or not str(delta.get("work_unit_key") or "").endswith(
            "/preverify_chain_candidate_delta." + generation
        )
        or candidate_path != prefix + "candidates.json"
        or receipt_path != prefix + "receipt.json"
        or not isinstance(required, list)
        or required != sorted(set(map(str, required)))
        or not {candidate_path, receipt_path}.issubset(set(required))
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta identity/run/generation is invalid"
        )
    authorities: dict[str, dict[str, Any]] = {}
    raw: dict[str, bytes] = {}
    for label, relative in (
        ("chain_candidate_delta", candidate_path),
        ("chain_candidate_delta_receipt", receipt_path),
    ):
        try:
            candidate_raw = read_bounded_regular_bytes(
                root.joinpath(*PurePosixPath(relative).parts),
                MAX_SOURCE_BYTES,
            )
            authority = _source_authority(
                root,
                project,
                relative,
                run_id=dimensions["run_id"],
            )
        except (
            ArtifactLedgerError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise PreverifyFrozenProjectionError(
                f"{relative}: chain candidate delta authority is unavailable: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if (
            authority.get("authority_kind") != "EXACT_PHASE_IO_PRODUCER"
            or authority.get("source_sha256") != _sha(candidate_raw)
            or authority.get("source_size") != len(candidate_raw)
        ):
            raise PreverifyFrozenProjectionError(
                f"{relative}: chain candidate delta authority does not bind bytes"
            )
        raw[label] = candidate_raw
        authorities[label] = dict(authority)
    try:
        payload = json.loads(
            raw["chain_candidate_delta"].decode(
                "utf-8", errors="strict"
            )
        )
        receipt = json.loads(
            raw["chain_candidate_delta_receipt"].decode(
                "utf-8", errors="strict"
            )
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyFrozenProjectionError(
            "chain candidate delta JSON is malformed"
        ) from exc
    if not isinstance(payload, dict) or not isinstance(receipt, dict):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta JSON is not an object"
        )
    unsigned_payload = {
        key: value for key, value in payload.items()
        if key != "candidate_digest"
    }
    unsigned_receipt = {
        key: value for key, value in receipt.items()
        if key != "receipt_digest"
    }
    preimage_bindings = receipt.get("source_preimage_bindings")
    required_roles = {
        "hypotheses",
        "finding_mapping",
        "pair_receipt",
        "enabler_results",
    }
    allowed_roles = {*required_roles, "auto_map_receipt"}
    if (
        not isinstance(preimage_bindings, Mapping)
        or not required_roles.issubset(set(preimage_bindings))
        or not set(preimage_bindings).issubset(allowed_roles)
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta source-preimage denominator is invalid"
        )
    source_preimages: dict[str, bytes] = {}
    source_paths: dict[str, str] = {}
    input_identities: dict[str, str] = {}
    for role in sorted(preimage_bindings):
        row = preimage_bindings.get(role)
        if not isinstance(row, Mapping) or set(row) != {
            "leaf",
            "input_identity",
            "sha256",
            "size",
        }:
            raise PreverifyFrozenProjectionError(
                "chain candidate delta source-preimage binding is malformed"
            )
        leaf = _safe_relative(
            row.get("leaf"),
            label=f"chain candidate {role} preimage leaf",
        )
        if (
            leaf != DELTA_SOURCE_PREIMAGE_LEAVES[role]
            or "/" in leaf
        ):
            raise PreverifyFrozenProjectionError(
                "chain candidate delta source-preimage leaf differs"
            )
        identity = str(row.get("input_identity") or "")
        if not identity.startswith("scratchpad:"):
            raise PreverifyFrozenProjectionError(
                "chain candidate delta preimage input identity is invalid"
            )
        _safe_relative(
            identity.removeprefix("scratchpad:"),
            label=f"chain candidate {role} input identity",
        )
        relative = f"{prefix}_sources/{leaf}"
        source_paths[role] = relative
        input_identities[role] = identity
        try:
            source_raw = read_bounded_regular_bytes(
                root.joinpath(*PurePosixPath(relative).parts),
                MAX_SOURCE_BYTES,
            )
            source_authority = _source_authority(
                root,
                project,
                relative,
                run_id=dimensions["run_id"],
            )
        except (
            ArtifactLedgerError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise PreverifyFrozenProjectionError(
                "chain candidate delta immutable source preimage is "
                f"unavailable: {type(exc).__name__}: {exc}"
            ) from exc
        if (
            row.get("sha256") != _sha(source_raw)
            or isinstance(row.get("size"), bool)
            or row.get("size") != len(source_raw)
            or source_authority.get("authority_kind")
            != "EXACT_PHASE_IO_PRODUCER"
            or source_authority.get("source_sha256") != _sha(source_raw)
            or source_authority.get("source_size") != len(source_raw)
        ):
            raise PreverifyFrozenProjectionError(
                "chain candidate delta immutable source preimage differs "
                "from its exact authority"
            )
        source_preimages[role] = source_raw
        raw["chain_candidate_source_" + role] = source_raw
        authorities["chain_candidate_source_" + role] = dict(
            source_authority
        )
    expected_required = sorted({
        candidate_path,
        receipt_path,
        *source_paths.values(),
    })
    if (
        required != expected_required
        or receipt.get("required_paths") != expected_required
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta required-path denominator differs"
        )
    if (
        receipt.get("derivation_algorithm")
        != DELTA_DERIVATION_ALGORITHM
        or receipt.get("derivation_conformance_sha256")
        != DELTA_DERIVATION_CONFORMANCE_SHA256
        or payload.get("derivation_algorithm")
        != DELTA_DERIVATION_ALGORITHM
        or payload.get("derivation_conformance_sha256")
        != DELTA_DERIVATION_CONFORMANCE_SHA256
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta derivation authority is unsupported"
        )
    try:
        validate_preverify_chain_candidate_derivation_conformance()
        validate_preverify_chain_pair_derivation_conformance()
    except (ChainCandidateDeltaError, TypeError, ValueError) as exc:
        raise PreverifyFrozenProjectionError(
            f"chain candidate delta derivation conformance failed: {exc}"
        ) from exc
    if (
        payload.get("schema_version") != DELTA_SCHEMA
        or payload.get("candidate_digest") != _digest(unsigned_payload)
        or receipt.get("schema_version") != DELTA_RECEIPT_SCHEMA
        or receipt.get("generation_digest") != generation
        or receipt.get("receipt_digest") != _digest(unsigned_receipt)
        or receipt.get("candidate_digest")
        != payload.get("candidate_digest")
        or receipt.get("candidate_path") != candidate_path
        or receipt.get("source_preimage_bindings")
        != preimage_bindings
        or any(
            payload.get(key) != dimensions[key]
            or receipt.get(key) != dimensions[key]
            for key in dimensions
        )
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta content/receipt digest is invalid"
        )
    generation_core = {
        "schema_version": DELTA_RECEIPT_SCHEMA,
        **dict(dimensions),
        "candidate_digest": payload.get("candidate_digest"),
        "candidate_ids": payload.get("candidate_ids"),
        "source_bindings": payload.get("source_bindings"),
        "source_authorities": payload.get("source_authorities"),
        "model_lineage": payload.get("model_lineage"),
        "source_preimage_bindings": preimage_bindings,
        "derivation_algorithm": DELTA_DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            DELTA_DERIVATION_CONFORMANCE_SHA256
        ),
    }
    if _digest(generation_core) != generation:
        raise PreverifyFrozenProjectionError(
            "chain candidate delta generation is not the declared source "
            "derivation"
        )
    try:
        ledger = read_artifact_ledger(root)
    except ArtifactLedgerError as exc:
        raise PreverifyFrozenProjectionError(
            f"chain candidate delta ledger replay failed: {exc}"
        ) from exc
    producer_keys = {
        str(row.get("producer_work_unit_key") or "")
        for row in authorities.values()
    }
    if producer_keys != {str(delta.get("work_unit_key") or "")}:
        raise PreverifyFrozenProjectionError(
            "chain candidate delta output bundle has split producer authority"
        )
    output_identities = [
        "scratchpad:" + relative for relative in expected_required
    ]
    commit_issues = active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=str(delta.get("work_unit_key") or ""),
        run_id=str(dimensions["run_id"]),
        expected_artifact_identities=output_identities,
    )
    unit = (
        ledger.get("work_units", {}).get(delta.get("work_unit_key"))
        if isinstance(ledger.get("work_units"), Mapping)
        else None
    )
    input_bindings = (
        unit.get("input_bindings")
        if isinstance(unit, Mapping)
        else None
    )
    if (
        commit_issues
        or not isinstance(input_bindings, Mapping)
        or set(input_bindings) != set(input_identities.values())
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta committed input/output authority differs: "
            + "; ".join(commit_issues)
        )
    for role, identity in input_identities.items():
        input_row = input_bindings.get(identity)
        if (
            not isinstance(input_row, Mapping)
            or input_row.get("sha256")
            != preimage_bindings[role].get("sha256")
            or input_row.get("size")
            != preimage_bindings[role].get("size")
        ):
            raise PreverifyFrozenProjectionError(
                "chain candidate delta source preimage does not replay its "
                "armed input binding"
            )
    try:
        pair_receipt = json.loads(
            source_preimages["pair_receipt"].decode(
                "utf-8", errors="strict"
            )
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyFrozenProjectionError(
            "chain candidate pair receipt preimage is malformed"
        ) from exc
    if (
        not isinstance(pair_receipt, Mapping)
        or pair_receipt.get("schema_version") != PAIR_RECEIPT_SCHEMA
        or pair_receipt.get("derivation_algorithm")
        != PAIR_DERIVATION_ALGORITHM
        or pair_receipt.get("derivation_conformance_sha256")
        != PAIR_DERIVATION_CONFORMANCE_SHA256
        or pair_receipt.get("relation_validation")
        != derive_preverify_chain_pair_relation(
            source_preimages["hypotheses"],
            source_preimages["finding_mapping"],
        )
        or pair_receipt.get("sources")
        != {
            "hypotheses.md": _binding(
                source_preimages["hypotheses"]
            ),
            "finding_mapping.md": _binding(
                source_preimages["finding_mapping"]
            ),
        }
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate pair preimage is not the versioned relation "
            "derivation"
        )
    source_authorities = payload.get("source_authorities")
    model_lineage = payload.get("model_lineage")
    source_bindings = payload.get("source_bindings")
    if (
        not isinstance(source_authorities, Mapping)
        or not isinstance(model_lineage, Mapping)
        or not isinstance(source_bindings, Mapping)
        or source_bindings
        != {
            "hypotheses.md": _binding(
                source_preimages["hypotheses"]
            ),
            "finding_mapping.md": _binding(
                source_preimages["finding_mapping"]
            ),
            "enabler_results.md": _binding(
                source_preimages["enabler_results"]
            ),
        }
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta semantic source denominator differs"
        )
    expected_payload, expected_debt = (
        derive_preverify_chain_candidate_payload(
            dimensions=dimensions,
            pair_sources={
                "hypotheses.md": source_preimages["hypotheses"],
                "finding_mapping.md": (
                    source_preimages["finding_mapping"]
                ),
            },
            enabler_raw=source_preimages["enabler_results"],
            source_authorities=source_authorities,
            lineage=model_lineage,
        )
    )
    if payload != expected_payload or payload.get("debt") != expected_debt:
        raise PreverifyFrozenProjectionError(
            "chain candidate delta payload is not the exact source "
            "rederivation"
        )
    candidates = payload.get("candidates")
    ids = payload.get("candidate_ids")
    if (
        not isinstance(candidates, list)
        or not isinstance(ids, list)
        or any(not isinstance(row, Mapping) for row in candidates)
        or any(not isinstance(identity, str) or not identity for identity in ids)
        or len(ids) != len(set(ids))
        or ids
        != [
            str(row.get("candidate_identity") or "")
            for row in candidates
        ]
        or payload.get("candidate_count") != len(candidates)
        or any(
            row.get("required_disposition") != "VERIFY_INDEPENDENTLY"
            or row.get("relation_kind") != "ENABLER_CONSTITUENT"
            or row.get("proof_authority") != "NONE"
            or not str(row.get("inventory_block") or "").strip()
            for row in candidates
        )
    ):
        raise PreverifyFrozenProjectionError(
            "chain candidate delta candidate denominator is malformed"
        )
    return payload, authorities, raw


def _union_chain_candidates(
    inventory_raw: bytes,
    delta: Mapping[str, Any] | None,
) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    try:
        inventory_text = inventory_raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PreverifyFrozenProjectionError(
            "base inventory is not strict UTF-8"
        ) from exc
    base_sections = _inventory_sections(inventory_text)
    base_ids = sorted(base_sections)
    if delta is None:
        fixed_point = {
            "base_ids": base_ids,
            "delta_ids": [],
            "frozen_ids": base_ids,
            "base_union_delta_equals_frozen": True,
            "candidate_records_removed": 0,
        }
        return inventory_raw, fixed_point, []

    candidates = list(delta.get("candidates") or [])
    delta_ids = [
        str(row.get("candidate_identity") or "").upper()
        for row in candidates
    ]
    append_blocks: list[str] = []
    collision_debt: list[dict[str, Any]] = []
    for row in candidates:
        identity = str(row.get("candidate_identity") or "").upper()
        block = str(row.get("inventory_block") or "").strip()
        prior = base_sections.get(identity)
        if prior is None:
            append_blocks.append(block)
            continue
        if _normalized_block(prior) != _normalized_block(block):
            collision_debt.append({
                "reason_code": "CHAIN_CANDIDATE_IDENTITY_COLLISION",
                "candidate_identity": identity,
                "base_block_sha256": _sha(
                    prior.encode("utf-8")
                ),
                "delta_block_sha256": _sha(
                    block.encode("utf-8")
                ),
                "candidate": dict(row),
                "candidate_disposition": "VISIBLE_HUMAN_REVIEW_DEBT",
                "proof_authority": "NONE",
            })
    if append_blocks:
        inventory_raw = (
            inventory_raw.rstrip()
            + b"\n\n"
            + ("\n\n".join(append_blocks) + "\n").encode("utf-8")
        )
    frozen_text = inventory_raw.decode("utf-8", errors="strict")
    frozen_ids = sorted(_inventory_sections(frozen_text))
    expected_ids = sorted(set(base_ids) | set(delta_ids))
    fixed_point = {
        "base_ids": base_ids,
        "delta_ids": delta_ids,
        "frozen_ids": frozen_ids,
        "base_union_delta_equals_frozen": expected_ids == frozen_ids,
        "candidate_records_removed": 0,
        "identity_collision_ids": sorted({
            str(row["candidate_identity"]) for row in collision_debt
        }),
    }
    if not fixed_point["base_union_delta_equals_frozen"]:
        raise PreverifyFrozenProjectionError(
            "chain candidate delivery fixed point is not exact"
        )
    return inventory_raw, fixed_point, collision_debt


def derive_preverify_inventory_union(
    base_inventory_raw: bytes,
    chain_candidate_payload: Mapping[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
    """Replay the versioned base-plus-chain-candidate byte union.

    This pure entry point is shared by the writer and the independent
    authority resolver.  The caller must authenticate and schema-validate the
    candidate payload before passing it here.
    """

    return _union_chain_candidates(
        bytes(base_inventory_raw),
        chain_candidate_payload,
    )


def _advisory_evidence_debt(
    *,
    status: str,
    reason_code: str,
) -> bytes:
    return (
        "# Inventory Evidence Validation — Advisory Repair Debt\n\n"
        f"- **Status**: {status}\n"
        f"- **Reason Code**: {reason_code}\n"
        "- **Authority**: ADVISORY_REPAIR_ONLY\n"
        "- **Candidate Disposition**: PRESERVE_ALL_FOR_VERIFICATION\n"
        "- **Proof Authority**: NONE\n"
    ).encode("utf-8")


def derive_preverify_advisory_evidence_debt(
    *,
    status: str,
    reason_code: str,
) -> bytes:
    """Return the canonical advisory-only evidence repair projection."""

    return _advisory_evidence_debt(
        status=str(status),
        reason_code=str(reason_code),
    )


def derive_preverify_derivation_conformance_sha256() -> str:
    """Return the frozen-derivation v1 golden-vector digest."""

    base = (
        b"### Finding [INV-1]: Base candidate\n"
        b"**Verdict**: NEEDS_VERIFICATION\n"
        b"**Severity**: Medium\n"
        b"**Location**: src/Base.sol:1\n"
    )
    delta_block = (
        "### Finding [EN-2]: Additive chain candidate\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Low\n"
        "**Location**: src/Chain.sol:2\n"
    )
    delta = {
        "candidate_ids": ["EN-2"],
        "candidate_count": 1,
        "candidates": [{
            "candidate_identity": "EN-2",
            "inventory_block": delta_block,
            "required_disposition": "VERIFY_INDEPENDENTLY",
            "relation_kind": "ENABLER_CONSTITUENT",
            "proof_authority": "NONE",
        }],
    }
    collision = {
        "candidate_ids": ["INV-1"],
        "candidate_count": 1,
        "candidates": [{
            "candidate_identity": "INV-1",
            "inventory_block": delta_block.replace("EN-2", "INV-1"),
            "required_disposition": "VERIFY_INDEPENDENTLY",
            "relation_kind": "ENABLER_CONSTITUENT",
            "proof_authority": "NONE",
        }],
    }
    no_delta_raw, no_delta_fixed, no_delta_debt = (
        derive_preverify_inventory_union(base)
    )
    appended_raw, appended_fixed, appended_debt = (
        derive_preverify_inventory_union(base, delta)
    )
    collision_raw, collision_fixed, collision_debt = (
        derive_preverify_inventory_union(base, collision)
    )
    vector = {
        "algorithm": DERIVATION_ALGORITHM,
        "no_delta_inventory": _binding(no_delta_raw),
        "no_delta_fixed_point": no_delta_fixed,
        "no_delta_debt": no_delta_debt,
        "append_inventory": _binding(appended_raw),
        "append_records": _binding(_records_bytes(appended_raw)),
        "append_fixed_point": appended_fixed,
        "append_debt": appended_debt,
        "collision_inventory": _binding(collision_raw),
        "collision_records": _binding(_records_bytes(collision_raw)),
        "collision_fixed_point": collision_fixed,
        "collision_debt": collision_debt,
        "advisory_absent": _binding(_advisory_evidence_debt(
            status="ABSENT",
            reason_code="EVIDENCE_PROJECTION_ABSENT",
        )),
        "advisory_unauthorized": _binding(_advisory_evidence_debt(
            status="PRESENT_UNAUTHORIZED",
            reason_code="EVIDENCE_PROJECTION_UNAUTHORIZED",
        )),
    }
    return _sha(_canonical_bytes(vector))


def validate_preverify_derivation_conformance() -> None:
    """Reject an implementation drift hidden behind the v1 algorithm ID."""

    actual = derive_preverify_derivation_conformance_sha256()
    if actual != DERIVATION_CONFORMANCE_SHA256:
        raise PreverifyFrozenProjectionError(
            "frozen derivation v1 conformance digest differs; allocate a new "
            f"algorithm identifier (expected {DERIVATION_CONFORMANCE_SHA256}, "
            f"got {actual})"
        )


def _source_authority(
    root: Path,
    project: Path,
    relative: str,
    *,
    run_id: str,
) -> dict[str, Any]:
    return semantic_import_authority(
        root,
        project,
        "scratchpad:" + relative,
        run_id=run_id,
    )


def _derive(
    *,
    root: Path,
    project: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    inventory_source: str,
    evidence_source: str,
    chain_candidate_delta: Mapping[str, Any] | None,
) -> dict[str, Any]:
    validate_preverify_derivation_conformance()
    inventory_path = root.joinpath(
        *PurePosixPath(inventory_source).parts
    )
    inventory_raw = read_bounded_regular_bytes(
        inventory_path,
        MAX_SOURCE_BYTES,
    )
    base_inventory_raw = inventory_raw
    try:
        inventory_authority = _source_authority(
            root,
            project,
            inventory_source,
            run_id=run_id,
        )
    except (ArtifactLedgerError, OSError, TypeError, ValueError) as exc:
        raise PreverifyFrozenProjectionError(
            "final inventory import lacks an exact current-run producer or "
            f"contiguous semantic-mutation chain: {type(exc).__name__}: {exc}"
        ) from exc
    if inventory_authority.get("source_sha256") != _sha(inventory_raw):
        raise PreverifyFrozenProjectionError(
            "final inventory import authority does not bind current bytes"
        )
    dimensions = {
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
        "run_id": run_id,
    }
    delta_payload: dict[str, Any] | None = None
    delta_authorities: dict[str, dict[str, Any]] = {}
    delta_source_raw: dict[str, bytes] = {}
    if chain_candidate_delta is not None:
        delta_payload, delta_authorities, delta_source_raw = (
            _validated_chain_candidate_delta(
                root=root,
                project=project,
                dimensions=dimensions,
                delta=chain_candidate_delta,
            )
        )
    inventory_raw, delivery_fixed_point, collision_debt = (
        _union_chain_candidates(inventory_raw, delta_payload)
    )
    records_raw = _records_bytes(inventory_raw)

    evidence_path = root.joinpath(*PurePosixPath(evidence_source).parts)
    evidence_authority: dict[str, Any] | None = None
    evidence_status = "ABSENT_REPAIR_DEBT"
    evidence_reason = "EVIDENCE_PROJECTION_ABSENT"
    evidence_semantic_use = False
    if evidence_path.is_file():
        try:
            candidate_raw = read_bounded_regular_bytes(
                evidence_path,
                MAX_SOURCE_BYTES,
            )
            candidate_authority = _source_authority(
                root,
                project,
                evidence_source,
                run_id=run_id,
            )
            if candidate_authority.get("source_sha256") != _sha(candidate_raw):
                raise PreverifyFrozenProjectionError(
                    "evidence authority does not bind current bytes"
                )
        except (
            ArtifactLedgerError,
            OSError,
            TypeError,
            ValueError,
        ):
            evidence_raw = _advisory_evidence_debt(
                status="PRESENT_UNAUTHORIZED",
                reason_code="EVIDENCE_PROJECTION_UNAUTHORIZED",
            )
            evidence_status = "PRESENT_UNAUTHORIZED_REPAIR_DEBT"
            evidence_reason = "EVIDENCE_PROJECTION_UNAUTHORIZED"
        else:
            evidence_raw = candidate_raw
            evidence_authority = candidate_authority
            evidence_status = "AUTHORIZED_ADVISORY"
            evidence_reason = ""
            evidence_semantic_use = True
    else:
        evidence_raw = _advisory_evidence_debt(
            status="ABSENT",
            reason_code=evidence_reason,
        )

    authorities = {
        "inventory": inventory_authority,
        **delta_authorities,
        **(
            {"evidence": evidence_authority}
            if evidence_authority is not None
            else {}
        ),
    }
    source_preimage_raw = {
        "inventory": base_inventory_raw,
        **delta_source_raw,
        **(
            {"evidence": evidence_raw}
            if evidence_semantic_use
            else {}
        ),
    }
    if any(
        isinstance(row, Mapping)
        and row.get("authority_kind")
        == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
        for row in authorities.values()
    ):
        source_preimage_raw["semantic_mutations"] = (
            read_bounded_regular_bytes(
                root / "_semantic_mutations.json",
                MAX_SOURCE_BYTES,
            )
        )
    source_preimage_bindings = {
        role: {
            "leaf": FROZEN_SOURCE_PREIMAGE_LEAVES[role],
            **_binding(raw),
        }
        for role, raw in sorted(source_preimage_raw.items())
    }
    generation_core = {
        "schema_version": SCHEMA,
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
        "run_id": run_id,
        "inventory_source": inventory_source,
        "evidence_source": evidence_source,
        "inventory": _binding(inventory_raw),
        "records": _binding(records_raw),
        "evidence": _binding(evidence_raw),
        "evidence_status": evidence_status,
        "evidence_reason_code": evidence_reason,
        "evidence_semantic_use": evidence_semantic_use,
        "source_authorities": authorities,
        "source_preimage_bindings": source_preimage_bindings,
        "chain_candidate_delta": (
            {
                "generation_digest": str(
                    chain_candidate_delta.get("generation_digest") or ""
                ),
                "candidate_digest": str(
                    delta_payload.get("candidate_digest") or ""
                ),
                "candidate_ids": list(
                    delta_payload.get("candidate_ids") or []
                ),
                "candidate_path": str(
                    chain_candidate_delta.get("candidate_path") or ""
                ),
                "receipt_path": str(
                    chain_candidate_delta.get("receipt_path") or ""
                ),
                "debt": list(delta_payload.get("debt") or []),
            }
            if (
                chain_candidate_delta is not None
                and delta_payload is not None
            )
            else None
        ),
        "candidate_delivery_fixed_point": delivery_fixed_point,
        "derivation_algorithm": DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            DERIVATION_CONFORMANCE_SHA256
        ),
    }
    generation_digest = _digest(generation_core)
    generation_root = f"{ROOT}/generation_{generation_digest}"
    paths = {
        INVENTORY_LOGICAL: f"{generation_root}/{INVENTORY_LOGICAL}",
        RECORDS_LOGICAL: f"{generation_root}/{RECORDS_LOGICAL}",
        EVIDENCE_LOGICAL: f"{generation_root}/{EVIDENCE_LOGICAL}",
    }
    receipt_path = f"{generation_root}/receipt.json"
    source_preimage_paths = {
        role: (
            f"{generation_root}/_sources/"
            + str(binding["leaf"])
        )
        for role, binding in source_preimage_bindings.items()
    }
    logical_to_physical = {
        INVENTORY_LOGICAL: paths[INVENTORY_LOGICAL],
        RECORDS_LOGICAL: paths[RECORDS_LOGICAL],
        **(
            {EVIDENCE_LOGICAL: paths[EVIDENCE_LOGICAL]}
            if evidence_semantic_use
            else {}
        ),
    }
    debt = [
        *(
            []
            if evidence_semantic_use
            else [{
                "artifact": evidence_source,
                "reason_code": evidence_reason,
                "authority": "ADVISORY_REPAIR_ONLY",
                "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
            }]
        ),
        *(
            list(delta_payload.get("debt") or [])
            if delta_payload is not None
            else []
        ),
        *collision_debt,
    ]
    unsigned_receipt = {
        **generation_core,
        "schema_version": RECEIPT_SCHEMA,
        "generation_digest": generation_digest,
        "logical_to_physical": logical_to_physical,
        "advisory_evidence_path": paths[EVIDENCE_LOGICAL],
        "required_paths": sorted({
            *logical_to_physical.values(),
            receipt_path,
        }),
        "debt": debt,
        "proof_authority": "NONE",
    }
    receipt = {
        **unsigned_receipt,
        "receipt_digest": _digest(unsigned_receipt),
    }
    return {
        "generation_digest": generation_digest,
        "generation_root": generation_root,
        "receipt_path": receipt_path,
        "logical_to_physical": logical_to_physical,
        "required_paths": tuple(unsigned_receipt["required_paths"]),
        "advisory_evidence_path": paths[EVIDENCE_LOGICAL],
        "debt": debt,
        "source_authorities": authorities,
        "outputs": {
            paths[INVENTORY_LOGICAL]: inventory_raw,
            paths[RECORDS_LOGICAL]: records_raw,
            paths[EVIDENCE_LOGICAL]: evidence_raw,
            **{
                source_preimage_paths[role]: raw
                for role, raw in source_preimage_raw.items()
            },
            receipt_path: _canonical_bytes(receipt),
        },
        "receipt": receipt,
    }


def reconstruct_preverify_frozen_contract_and_launch(
    *,
    generation_digest: str,
    exact_input_identities: tuple[str, ...],
    output_paths: tuple[str, ...],
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    """Reconstruct the exact provider PhaseIO contract from declared facts.

    The resolver uses this same constructor when replaying a stored commit.
    Keeping one constructor prevents a permissive downstream approximation
    from silently becoming a second provider specification.
    """

    generation = str(generation_digest or "").strip()
    if _HEX64.fullmatch(generation) is None:
        raise PreverifyFrozenProjectionError(
            "frozen projection generation digest is malformed"
        )
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase_name,
        f"preverify_frozen_projection.{generation}",
    )
    exact_inputs = tuple(
        sorted({str(identity) for identity in exact_input_identities})
    )
    outputs = tuple(sorted({str(path) for path in output_paths}))
    if not exact_inputs or not outputs:
        raise PreverifyFrozenProjectionError(
            "frozen projection input/output denominator is malformed"
        )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase_name,
        work_unit_id=f"preverify_frozen_projection.{generation}",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=_safe_relative(path, label="projection output"),
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    RECEIPT_SCHEMA
                    if str(path).endswith("/receipt.json")
                    else "plamen.finding_records.v2"
                    if str(path).endswith("/finding_records.json")
                    else "unstructured.v1"
                ),
                minimum_gate=(
                    "CONTENT_ADDRESSED_PAIRED_FINAL_INPUT_PROJECTION"
                ),
                consumers=(f"{phase_name}/t0.live_upstream_authority",),
            )
            for path in outputs
        ),
        immutable_inputs=exact_inputs,
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _contract_and_launch(
    *,
    derived: Mapping[str, Any],
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    authority_rows = derived.get("source_authorities")
    if not isinstance(authority_rows, Mapping):
        raise PreverifyFrozenProjectionError(
            "frozen projection source authority is malformed"
        )
    exact_inputs = {
        str(row["identity"])
        for row in authority_rows.values()
        if isinstance(row, Mapping)
    }
    if any(
        isinstance(row, Mapping)
        and row.get("authority_kind")
        == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
        for row in authority_rows.values()
    ):
        exact_inputs.add("scratchpad:_semantic_mutations.json")
    outputs = derived.get("outputs")
    if not isinstance(outputs, Mapping):
        raise PreverifyFrozenProjectionError(
            "frozen projection output denominator is malformed"
        )
    return reconstruct_preverify_frozen_contract_and_launch(
        generation_digest=str(derived["generation_digest"]),
        exact_input_identities=tuple(sorted(exact_inputs)),
        output_paths=tuple(sorted(str(path) for path in outputs)),
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase_name=phase_name,
        run_id=run_id,
    )


def _cas_create_or_exact(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        if read_bounded_regular_bytes(path, MAX_SOURCE_BYTES) != raw:
            raise PreverifyFrozenProjectionError(
                f"content-addressed output contains foreign bytes: {path}"
            )
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _validate_receipt(
    root: Path,
    derived: Mapping[str, Any],
) -> None:
    receipt_path = _safe_relative(
        derived.get("receipt_path"),
        label="projection receipt",
    )
    try:
        payload = json.loads(
            read_bounded_regular_bytes(
                root.joinpath(*PurePosixPath(receipt_path).parts),
                MAX_SOURCE_BYTES,
            ).decode("utf-8", errors="strict")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyFrozenProjectionError(
            "frozen projection receipt is unavailable or malformed"
        ) from exc
    unsigned = {
        key: item for key, item in payload.items()
        if key != "receipt_digest"
    }
    if (
        payload.get("schema_version") != RECEIPT_SCHEMA
        or payload.get("generation_digest")
        != derived.get("generation_digest")
        or payload.get("receipt_digest") != _digest(unsigned)
        or payload != derived.get("receipt")
    ):
        raise PreverifyFrozenProjectionError(
            "frozen projection receipt identity/digest differs from derivation"
        )


def prepare_preverify_frozen_projection(
    *,
    scratchpad: Path,
    project_root: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    inventory_source: str = INVENTORY_LOGICAL,
    evidence_source: str = EVIDENCE_LOGICAL,
    chain_pair_projection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Publish or replay one immutable final-input projection."""

    root = Path(scratchpad)
    project = Path(project_root)
    dimensions = {
        "pipeline": str(pipeline or "").strip().lower(),
        "mode": str(mode or "").strip().lower(),
        "ecosystem": str(ecosystem or "").strip().lower(),
        "backend": str(backend or "").strip().lower(),
        "phase_name": str(phase_name or "").strip().lower(),
        "run_id": str(run_id or "").strip(),
    }
    expected_phase = (
        "sc_verify_queue"
        if dimensions["pipeline"] == "sc"
        else "verify_queue"
    )
    if (
        dimensions["pipeline"] not in {"sc", "l1"}
        or dimensions["backend"] not in {"claude", "codex"}
        or not dimensions["mode"]
        or not dimensions["ecosystem"]
        or dimensions["phase_name"] != expected_phase
        or not dimensions["run_id"]
    ):
        raise PreverifyFrozenProjectionError(
            "frozen projection run tuple is invalid"
        )
    inventory_relative = _safe_relative(
        inventory_source,
        label="inventory source",
    )
    evidence_relative = _safe_relative(
        evidence_source,
        label="evidence source",
    )
    try:
        chain_candidate_delta = (
            prepare_preverify_chain_candidate_delta(
                scratchpad=root,
                project_root=project,
                chain_pair_projection=chain_pair_projection,
                **dimensions,
            )
            if (
                dimensions["pipeline"] == "sc"
                and chain_pair_projection is not None
            )
            else None
        )
    except ChainCandidateDeltaError as exc:
        raise PreverifyFrozenProjectionError(
            "chain candidate delta is not consumable: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    derived = _derive(
        root=root,
        project=project,
        inventory_source=inventory_relative,
        evidence_source=evidence_relative,
        chain_candidate_delta=chain_candidate_delta,
        **dimensions,
    )
    contract, launch = _contract_and_launch(
        derived=derived,
        **dimensions,
    )
    prior_input_issues = validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=dimensions["run_id"],
    )
    prior_output_issues = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=dimensions["run_id"],
        actor="DRIVER",
    )
    if not prior_input_issues and not prior_output_issues:
        _validate_receipt(root, derived)
    else:
        record_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
        )
        input_issues = validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
        )
        if input_issues:
            raise PreverifyFrozenProjectionError(
                "frozen projection PhaseIO input arm failed: "
                + "; ".join(input_issues)
            )
        # Re-derive after arm.  The generation and every byte must remain
        # identical; an intervening mutation becomes retryable debt.
        after_arm = _derive(
            root=root,
            project=project,
            inventory_source=inventory_relative,
            evidence_source=evidence_relative,
            chain_candidate_delta=chain_candidate_delta,
            **dimensions,
        )
        if (
            after_arm["generation_digest"] != derived["generation_digest"]
            or after_arm["outputs"] != derived["outputs"]
        ):
            raise PreverifyFrozenProjectionError(
                "frozen projection source denominator drifted after arm"
            )
        outputs = derived["outputs"]
        assert isinstance(outputs, Mapping)
        for relative, raw in sorted(outputs.items()):
            _cas_create_or_exact(
                root.joinpath(*PurePosixPath(str(relative)).parts),
                bytes(raw),
            )
        record_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
            actor="DRIVER",
        )
        output_issues = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
            actor="DRIVER",
        )
        if output_issues:
            raise PreverifyFrozenProjectionError(
                "frozen projection PhaseIO commit failed: "
                + "; ".join(output_issues)
            )
        _validate_receipt(root, derived)

    return {
        "schema_version": SCHEMA,
        "state": "OUTPUT_COMMITTED",
        "run_id": dimensions["run_id"],
        "generation_digest": derived["generation_digest"],
        "work_unit_key": contract.key,
        "receipt_path": derived["receipt_path"],
        "logical_to_physical": dict(derived["logical_to_physical"]),
        "required_paths": list(derived["required_paths"]),
        "advisory_evidence_path": derived["advisory_evidence_path"],
        "debt": list(derived["debt"]),
        "proof_authority": "NONE",
    }


__all__ = [
    "DERIVATION_ALGORITHM",
    "DERIVATION_CONFORMANCE_SHA256",
    "derive_preverify_advisory_evidence_debt",
    "derive_preverify_derivation_conformance_sha256",
    "derive_preverify_finding_records_bytes",
    "derive_preverify_inventory_union",
    "EVIDENCE_LOGICAL",
    "FROZEN_SOURCE_PREIMAGE_LEAVES",
    "INVENTORY_LOGICAL",
    "PreverifyFrozenProjectionError",
    "RECORDS_LOGICAL",
    "ROOT",
    "SCHEMA",
    "prepare_preverify_frozen_projection",
    "reconstruct_preverify_frozen_contract_and_launch",
    "validate_preverify_derivation_conformance",
]
