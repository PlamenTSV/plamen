"""Typed proposal delta for candidates minted only during chain analysis.

Chain analysis may create ``EN-N`` candidates after the canonical inventory
phase.  This provider enumerates those identities into an immutable PhaseIO
delta.  The later frozen-union producer incorporates the delta without
mutating the canonical inventory, and the ordinary discriminator pipeline
independently verifies every resulting work item.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping

from artifact_ledger import (
    ArtifactLedgerError,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_import_authority,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from bounded_artifact_io import read_bounded_regular_bytes
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)
from preverify_chain_pair_projection import (
    PAIR_DERIVATION_ALGORITHM,
    PAIR_DERIVATION_CONFORMANCE_SHA256,
    RECEIPT_SCHEMA as PAIR_RECEIPT_SCHEMA,
    SCHEMA as PAIR_SCHEMA,
    derive_preverify_chain_pair_relation,
    validate_preverify_chain_pair_derivation_conformance,
)


DELTA_SCHEMA = "plamen.preverify_chain_candidate_delta.v2"
DELTA_RECEIPT_SCHEMA = "plamen.preverify_chain_candidate_delta_receipt.v2"
DELTA_DERIVATION_ALGORITHM = (
    "plamen.preverify.chain_candidate_delta.v1"
)
DELTA_DERIVATION_CONFORMANCE_SHA256 = (
    "5335370999fe275f22013ff0d4e438ae6df66f08e909626a3ca49b197ea1f747"
)
DELTA_SOURCE_PREIMAGE_LEAVES = {
    # These immutable content-addressed leaves are opaque storage, not public
    # semantic filenames.  Keep them compact so ordinary Windows project roots
    # do not cross the legacy 260-character filesystem boundary merely because
    # a SHA-256 generation directory and source snapshot are nested together.
    "hypotheses": "h.bin",
    "finding_mapping": "m.bin",
    "pair_receipt": "p.json",
    "enabler_results": "e.bin",
    "auto_map_receipt": "a.json",
}
DELTA_ROOT = "_preverify_chain_candidate_delta"
MAX_BYTES = 64 * 1024 * 1024
SOURCES = (
    "hypotheses.md",
    "finding_mapping.md",
    "enabler_results.md",
)
_EN_ID = re.compile(r"(?<![A-Za-z0-9])EN-(\d+)(?![A-Za-z0-9])", re.I)
_H_ID = re.compile(r"(?<![A-Za-z0-9])H-(\d+)(?![A-Za-z0-9])", re.I)
_SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
_HEX64 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)


class ChainCandidateDeltaError(ValueError):
    """The typed chain-only candidate delta could not be authorized."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
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


def _text(raw: bytes, name: str, issues: list[str]) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError:
        issues.append(f"{name}: invalid UTF-8; replacement decoding applied")
        return raw.decode("utf-8", errors="replace")


def _cells(line: str) -> list[str]:
    return [
        re.sub(r"\s+", " ", cell.strip().strip("`*"))
        for cell in line.strip().strip("|").split("|")
    ]


def _hypothesis_rows(text: str) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|") or "---" in line:
            continue
        cells = _cells(line)
        hypothesis = next(
            (
                f"H-{match.group(1)}"
                for cell in cells
                if (match := _H_ID.search(cell)) is not None
            ),
            "",
        )
        if not hypothesis:
            continue
        enablers = sorted({
            f"EN-{match.group(1)}"
            for cell in cells
            for match in _EN_ID.finditer(cell)
        })
        severity = next(
            (
                canonical
                for canonical in _SEVERITIES
                if any(cell.casefold() == canonical.casefold() for cell in cells)
            ),
            "Low",
        )
        title = next(
            (
                cell for cell in cells
                if cell
                and not _H_ID.fullmatch(cell)
                and not _EN_ID.fullmatch(cell)
                and cell.casefold() != severity.casefold()
                and cell.casefold() not in {
                    "hypothesis id", "severity", "title",
                    "constituent findings", "location",
                }
            ),
            f"Chain-only candidate in {hypothesis}",
        )
        location = next(
            (
                cell for cell in cells
                if re.search(
                    r"\.(?:sol|rs|move|go|vy|daml)(?::\d+)?",
                    cell,
                    re.I,
                )
            ),
            "UNKNOWN",
        )
        rows[hypothesis] = {
            "severity": severity,
            "title": title,
            "location": location,
            "enablers": ",".join(enablers),
        }
    return rows


def _mapping(text: str) -> tuple[dict[str, str], list[str]]:
    mapping: dict[str, str] = {}
    issues: list[str] = []
    for line in text.splitlines():
        if not line.lstrip().startswith("|") or "---" in line:
            continue
        cells = _cells(line)
        enablers = [
            f"EN-{match.group(1)}"
            for cell in cells for match in _EN_ID.finditer(cell)
        ]
        hypotheses = [
            f"H-{match.group(1)}"
            for cell in cells for match in _H_ID.finditer(cell)
        ]
        if enablers and not hypotheses:
            issues.append(
                "finding_mapping.md: EN row lacks a hypothesis identity"
            )
        for enabler in enablers:
            if hypotheses:
                prior = mapping.get(enabler)
                if prior and prior != hypotheses[0]:
                    issues.append(
                        f"finding_mapping.md: {enabler} maps to multiple "
                        "hypotheses"
                    )
                else:
                    mapping[enabler] = hypotheses[0]
    return mapping, issues


def _enabler_sections(text: str) -> dict[str, dict[str, str]]:
    matches = list(re.finditer(
        r"^#{2,4}\s+(?:Finding\s+)?\[(EN-\d+)\]\s*:?\s*(.*?)\s*$",
        text,
        re.M | re.I,
    ))
    result: dict[str, dict[str, str]] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.end():end]

        def field(name: str) -> str:
            found = re.search(
                rf"^\s*\*{{0,2}}{re.escape(name)}\*{{0,2}}\s*:\s*(.+?)\s*$",
                block,
                re.M | re.I,
            )
            return re.sub(r"\s+", " ", found.group(1)).strip() if found else ""

        identity = match.group(1).upper()
        result[identity] = {
            "title": match.group(2).strip() or f"Chain-only candidate {identity}",
            "severity": field("Severity"),
            "location": field("Location") or field("Locations"),
            "description": field("Description"),
            "impact": field("Impact"),
        }
    return result


def _safe_cell(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").replace("|", "/")).strip()


def _candidate_block(
    identity: str,
    *,
    hypothesis: str,
    hypothesis_row: Mapping[str, str],
    section: Mapping[str, str],
) -> str:
    severity = str(section.get("severity") or hypothesis_row.get("severity") or "Low")
    if severity.casefold() not in {value.casefold() for value in _SEVERITIES}:
        severity = "Low"
    else:
        severity = next(
            value for value in _SEVERITIES
            if value.casefold() == severity.casefold()
        )
    title = _safe_cell(
        section.get("title")
        or hypothesis_row.get("title")
        or f"Chain-only candidate {identity}"
    )
    location = _safe_cell(
        section.get("location")
        or hypothesis_row.get("location")
        or "UNKNOWN"
    )
    description = _safe_cell(
        section.get("description")
        or (
            f"Chain analysis introduced {identity} as an independently "
            f"verifiable constituent of {hypothesis or 'an unresolved hypothesis'}."
        )
    )
    impact = _safe_cell(
        section.get("impact")
        or "Potential material harm requires independent verification."
    )
    return (
        f"\n\n### Finding [{identity}]: {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        f"**Severity**: {severity}\n"
        f"**Location**: {location}\n"
        "**Confidence**: 0.35\n"
        "**Source Artifact**: enabler_results.md\n"
        f"**Chain Hypothesis**: {hypothesis or 'UNRESOLVED'}\n"
        f"**Description**: {description}\n"
        f"**Impact**: {impact}\n"
        "**Proof Authority**: NONE\n"
        "**Relation Kind**: ENABLER_CONSTITUENT\n"
        "**Required Disposition**: VERIFY_INDEPENDENTLY\n"
    )


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
        raise ChainCandidateDeltaError(
            f"{label} is not a canonical relative POSIX path"
        )
    return text


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes(value))


def _binding(raw: bytes) -> dict[str, Any]:
    return {"sha256": _sha(raw), "size": len(raw)}


def _strict_json(root: Path, relative: str) -> dict[str, Any]:
    path = root.joinpath(*PurePosixPath(relative).parts)
    try:
        value = json.loads(
            read_bounded_regular_bytes(path, MAX_BYTES).decode(
                "utf-8", errors="strict"
            )
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ChainCandidateDeltaError(
            f"{relative}: typed JSON source is unavailable or malformed"
        ) from exc
    if not isinstance(value, dict):
        raise ChainCandidateDeltaError(
            f"{relative}: typed JSON source is not an object"
        )
    return value


def _exact_authority(
    root: Path,
    project: Path,
    relative: str,
    *,
    run_id: str,
) -> tuple[bytes, dict[str, Any]]:
    safe = _safe_relative(relative, label="chain candidate source")
    raw = read_bounded_regular_bytes(
        root.joinpath(*PurePosixPath(safe).parts),
        MAX_BYTES,
    )
    authority = semantic_import_authority(
        root,
        project,
        "scratchpad:" + safe,
        run_id=run_id,
    )
    if (
        authority.get("authority_kind") != "EXACT_PHASE_IO_PRODUCER"
        or authority.get("identity") != "scratchpad:" + safe
        or authority.get("run_id") != run_id
        or authority.get("source_sha256") != _sha(raw)
        or authority.get("source_size") != len(raw)
    ):
        raise ChainCandidateDeltaError(
            f"{safe}: exact current-run PhaseIO authority does not bind bytes"
        )
    return raw, dict(authority)


def _validated_pair_projection(
    *,
    root: Path,
    project: Path,
    projection: Mapping[str, Any],
    dimensions: Mapping[str, str],
) -> tuple[dict[str, bytes], dict[str, Any], dict[str, dict[str, Any]]]:
    """Validate the exact accepted pair projection and return its preimages."""

    if not isinstance(projection, Mapping):
        raise ChainCandidateDeltaError(
            "preverify chain-pair projection is absent"
        )
    generation = str(projection.get("generation_digest") or "")
    if (
        projection.get("schema_version")
        != PAIR_SCHEMA
        or projection.get("state") != "OUTPUT_COMMITTED"
        or projection.get("safe_to_consume") is not True
        or projection.get("run_id") != dimensions["run_id"]
        or projection.get("proof_authority") != "NONE"
        or not _HEX64.fullmatch(generation)
        or not str(projection.get("work_unit_key") or "").endswith(
            "/preverify_chain_pair_projection." + generation
        )
    ):
        raise ChainCandidateDeltaError(
            "preverify chain-pair projection identity is invalid"
        )
    aliases = projection.get("logical_to_physical")
    if not isinstance(aliases, Mapping) or set(aliases) != {
        "hypotheses.md",
        "finding_mapping.md",
    }:
        raise ChainCandidateDeltaError(
            "preverify chain-pair logical alias denominator is invalid"
        )
    prefix = f"_preverify_chain_pair/generation_{generation}/"
    physical = {
        logical: _safe_relative(value, label=f"{logical} projection")
        for logical, value in aliases.items()
    }
    if (
        len(set(physical.values())) != 2
        or any(not value.startswith(prefix) for value in physical.values())
    ):
        raise ChainCandidateDeltaError(
            "preverify chain-pair physical alias denominator is invalid"
        )
    receipt_relative = _safe_relative(
        projection.get("receipt_path"),
        label="chain-pair projection receipt",
    )
    if receipt_relative != prefix + "receipt.json":
        raise ChainCandidateDeltaError(
            "preverify chain-pair receipt path is invalid"
        )
    required = projection.get("required_paths")
    if (
        not isinstance(required, list)
        or required != sorted(set(map(str, required)))
        or not {*physical.values(), receipt_relative} <= set(required)
    ):
        raise ChainCandidateDeltaError(
            "preverify chain-pair required path denominator is invalid"
        )

    raw_sources: dict[str, bytes] = {}
    authorities: dict[str, dict[str, Any]] = {}
    for logical, relative in {
        **physical,
        "pair_receipt": receipt_relative,
    }.items():
        raw, authority = _exact_authority(
            root,
            project,
            relative,
            run_id=dimensions["run_id"],
        )
        raw_sources[logical] = raw
        authorities[logical] = authority

    receipt = _strict_json(root, receipt_relative)
    unsigned = {
        key: value for key, value in receipt.items()
        if key != "receipt_digest"
    }
    if (
        receipt.get("schema_version")
        != PAIR_RECEIPT_SCHEMA
        or receipt.get("derivation_algorithm")
        != PAIR_DERIVATION_ALGORITHM
        or receipt.get("derivation_conformance_sha256")
        != PAIR_DERIVATION_CONFORMANCE_SHA256
        or receipt.get("generation_digest") != generation
        or receipt.get("receipt_digest") != _digest(unsigned)
        or any(
            receipt.get(key) != dimensions[key]
            for key in (
                "pipeline",
                "mode",
                "ecosystem",
                "backend",
                "phase_name",
                "run_id",
            )
        )
        or receipt.get("logical_to_physical") != physical
    ):
        raise ChainCandidateDeltaError(
            "preverify chain-pair receipt identity/digest is invalid"
        )
    validate_preverify_chain_pair_derivation_conformance()
    source_bindings = receipt.get("sources")
    if (
        not isinstance(source_bindings, Mapping)
        or any(
            source_bindings.get(logical) != _binding(raw_sources[logical])
            for logical in ("hypotheses.md", "finding_mapping.md")
        )
    ):
        raise ChainCandidateDeltaError(
            "preverify chain-pair receipt does not bind projected pair bytes"
        )
    expected_relation = derive_preverify_chain_pair_relation(
        raw_sources["hypotheses.md"],
        raw_sources["finding_mapping.md"],
    )
    if receipt.get("relation_validation") != expected_relation:
        raise ChainCandidateDeltaError(
            "preverify chain-pair relation is not the declared source "
            "derivation"
        )
    return raw_sources, receipt, authorities


def _validate_model_lineage(
    *,
    root: Path,
    project: Path,
    dimensions: Mapping[str, str],
    pair_receipt: Mapping[str, Any],
    pair_sources: Mapping[str, bytes],
    enabler_authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Prove the final pair descends from the model that emitted the enabler."""

    pair_authorities = pair_receipt.get("source_authorities")
    if not isinstance(pair_authorities, Mapping):
        raise ChainCandidateDeltaError(
            "chain-pair projection lacks source-authority lineage"
        )
    current = [
        pair_authorities.get(relative)
        for relative in ("hypotheses.md", "finding_mapping.md")
    ]
    if not all(isinstance(row, Mapping) for row in current):
        raise ChainCandidateDeltaError(
            "chain-pair projection source-authority pair is malformed"
        )
    owners = {
        str(row.get("producer_work_unit_key") or "")
        for row in current
        if isinstance(row, Mapping)
    }
    contracts = {
        str(row.get("producer_contract_digest") or "")
        for row in current
        if isinstance(row, Mapping)
    }
    if len(owners) != 1 or len(contracts) != 1:
        raise ChainCandidateDeltaError(
            "chain-pair projection does not share one producer generation"
        )
    pair_owner = next(iter(owners))
    pair_contract = next(iter(contracts))
    enabler_owner = str(
        enabler_authority.get("producer_work_unit_key") or ""
    )
    enabler_contract = str(
        enabler_authority.get("producer_contract_digest") or ""
    )

    if pair_owner.endswith("/chain/model"):
        if (
            pair_owner != enabler_owner
            or pair_contract != enabler_contract
        ):
            raise ChainCandidateDeltaError(
                "chain pair and enabler do not share one model generation"
            )
        return {
            "lineage_kind": "DIRECT_MODEL_PAIR",
            "model_work_unit_key": enabler_owner,
            "model_contract_digest": enabler_contract,
            "auto_map_generation_digest": None,
        }

    matched = re.search(
        r"/chain/final_pair_auto_map_apply\.([0-9a-f]{64})$",
        pair_owner,
        re.ASCII,
    )
    if matched is None:
        raise ChainCandidateDeltaError(
            "final chain pair is not a model or registered paired successor"
        )
    generation = matched.group(1)
    if (
        enabler_owner != pair_owner
        or enabler_contract != pair_contract
    ):
        raise ChainCandidateDeltaError(
            "paired auto-map successor does not own the complete model bundle"
        )
    transaction_relative = (
        f"_chain_pair_auto_map/generation_{generation}/receipt.json"
    )
    transaction_raw, transaction_authority = _exact_authority(
        root,
        project,
        transaction_relative,
        run_id=dimensions["run_id"],
    )
    try:
        transaction = json.loads(
            transaction_raw.decode("utf-8", errors="strict")
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ChainCandidateDeltaError(
            "paired auto-map receipt is malformed"
        ) from exc
    unsigned = {
        key: value for key, value in transaction.items()
        if key != "receipt_digest"
    }
    if (
        not isinstance(transaction, dict)
        or transaction.get("schema_version")
        != "plamen.chain_pair_auto_map_receipt.v1"
        or transaction.get("generation_digest") != generation
        or transaction.get("receipt_digest") != _digest(unsigned)
        or any(
            transaction.get(key) != dimensions[key]
            for key in (
                "pipeline",
                "mode",
                "ecosystem",
                "backend",
                "run_id",
            )
        )
        or any(
            transaction.get("after", {}).get(relative)
            != _binding(pair_sources[relative])
            for relative in ("hypotheses.md", "finding_mapping.md")
        )
        or transaction.get("before", {}).get("enabler_results.md")
        != transaction.get("after", {}).get("enabler_results.md")
        or transaction.get("after", {}).get("enabler_results.md")
        != {
            "sha256": str(enabler_authority.get("source_sha256") or ""),
            "size": int(enabler_authority.get("source_size") or 0),
        }
    ):
        raise ChainCandidateDeltaError(
            "paired auto-map receipt does not bind the accepted pair"
        )
    original = transaction.get("source_authorities")
    if not isinstance(original, Mapping):
        raise ChainCandidateDeltaError(
            "paired auto-map receipt lacks original model lineage"
        )
    original_rows = [
        original.get(relative)
        for relative in (
            "hypotheses.md",
            "finding_mapping.md",
            "enabler_results.md",
        )
    ]
    if not all(isinstance(row, Mapping) for row in original_rows):
        raise ChainCandidateDeltaError(
            "paired auto-map original model authority is malformed"
        )
    original_owners = {
        str(row.get("producer_work_unit_key") or "")
        for row in original_rows
        if isinstance(row, Mapping)
    }
    original_contracts = {
        str(row.get("producer_contract_digest") or "")
        for row in original_rows
        if isinstance(row, Mapping)
    }
    if (
        len(original_owners) != 1
        or len(original_contracts) != 1
        or not next(iter(original_owners)).endswith("/chain/model")
    ):
        raise ChainCandidateDeltaError(
            "paired successor and enabler do not descend from one model"
        )
    model_owner = next(iter(original_owners))
    model_contract = next(iter(original_contracts))
    return {
        "lineage_kind": "PAIRED_AUTO_MAP_SUCCESSOR",
        "model_work_unit_key": model_owner,
        "model_contract_digest": model_contract,
        "auto_map_generation_digest": generation,
        "auto_map_receipt": transaction_relative,
        "auto_map_receipt_authority": transaction_authority,
        "_auto_map_receipt_raw": transaction_raw,
    }


def _candidate_record(
    identity: str,
    *,
    hypothesis: str,
    hypothesis_row: Mapping[str, str],
    section: Mapping[str, str],
) -> dict[str, Any]:
    severity = str(
        section.get("severity")
        or hypothesis_row.get("severity")
        or "Low"
    )
    if severity.casefold() not in {
        value.casefold() for value in _SEVERITIES
    }:
        severity = "Low"
    else:
        severity = next(
            value for value in _SEVERITIES
            if value.casefold() == severity.casefold()
        )
    title = _safe_cell(
        section.get("title")
        or hypothesis_row.get("title")
        or f"Chain-only candidate {identity}"
    )
    location = _safe_cell(
        section.get("location")
        or hypothesis_row.get("location")
        or "UNKNOWN"
    )
    description = _safe_cell(
        section.get("description")
        or (
            f"Chain analysis introduced {identity} as an independently "
            f"verifiable constituent of {hypothesis or 'an unresolved hypothesis'}."
        )
    )
    impact = _safe_cell(
        section.get("impact")
        or "Potential material harm requires independent verification."
    )
    block = _candidate_block(
        identity,
        hypothesis=hypothesis,
        hypothesis_row=hypothesis_row,
        section=section,
    )
    return {
        "candidate_identity": identity,
        "hypothesis_ids": [hypothesis] if hypothesis else [],
        "relation_kind": "ENABLER_CONSTITUENT",
        "required_disposition": "VERIFY_INDEPENDENTLY",
        "mandatory_verification": True,
        "severity_proposal": severity,
        "title": title,
        "location": location,
        "description": description,
        "impact": impact,
        "source_artifact": "enabler_results.md",
        "inventory_block": block,
        "proof_authority": "NONE",
    }


def derive_preverify_chain_candidate_payload(
    *,
    dimensions: Mapping[str, str],
    pair_sources: Mapping[str, bytes],
    enabler_raw: bytes,
    source_authorities: Mapping[str, Mapping[str, Any]],
    lineage: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[str] = []
    hypothesis_text = _text(
        pair_sources["hypotheses.md"],
        "hypotheses.md",
        issues,
    )
    mapping_text = _text(
        pair_sources["finding_mapping.md"],
        "finding_mapping.md",
        issues,
    )
    enabler_text = _text(
        enabler_raw,
        "enabler_results.md",
        issues,
    )
    hypotheses = _hypothesis_rows(hypothesis_text)
    mapped, mapping_issues = _mapping(mapping_text)
    issues.extend(mapping_issues)
    sections = _enabler_sections(enabler_text)
    hypothesis_enablers: dict[str, str] = {}
    for hypothesis, row in hypotheses.items():
        for identity in str(row.get("enablers") or "").split(","):
            identity = identity.strip().upper()
            if identity:
                prior = hypothesis_enablers.get(identity)
                if prior and prior != hypothesis:
                    issues.append(
                        f"hypotheses.md: {identity} occurs in multiple hypotheses"
                    )
                else:
                    hypothesis_enablers[identity] = hypothesis
    candidate_ids = sorted(
        {*mapped, *hypothesis_enablers, *sections},
        key=lambda value: int(value.split("-", 1)[1]),
    )
    if not mapped and hypothesis_enablers:
        issues.append(
            "finding_mapping.md: no EN relation was parseable; hypothesis "
            "identities were retained for independent verification"
        )
    candidates = [
        _candidate_record(
            identity,
            hypothesis=(
                mapped.get(identity)
                or hypothesis_enablers.get(identity, "")
            ),
            hypothesis_row=hypotheses.get(
                mapped.get(identity)
                or hypothesis_enablers.get(identity, ""),
                {},
            ),
            section=sections.get(identity, {}),
        )
        for identity in candidate_ids
    ]
    debt = [
        {
            "reason_code": "CHAIN_CANDIDATE_RELATION_AMBIGUITY",
            "issue": issue,
            "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
            "proof_authority": "NONE",
        }
        for issue in list(dict.fromkeys(issues))
    ]
    payload = {
        "schema_version": DELTA_SCHEMA,
        **dict(dimensions),
        "candidate_ids": candidate_ids,
        "candidate_count": len(candidates),
        "candidates": candidates,
        "source_bindings": {
            "hypotheses.md": _binding(pair_sources["hypotheses.md"]),
            "finding_mapping.md": _binding(
                pair_sources["finding_mapping.md"]
            ),
            "enabler_results.md": _binding(enabler_raw),
        },
        "source_authorities": {
            key: dict(value)
            for key, value in sorted(source_authorities.items())
        },
        "model_lineage": dict(lineage),
        "debt": debt,
        "base_inventory_mutated": False,
        "candidate_disposition": "VERIFY_INDEPENDENTLY",
        "proof_authority": "NONE",
        "derivation_algorithm": DELTA_DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            DELTA_DERIVATION_CONFORMANCE_SHA256
        ),
    }
    payload["candidate_digest"] = _digest(payload)
    return payload, debt


def _derive_delta_payload(
    *,
    dimensions: Mapping[str, str],
    pair_sources: Mapping[str, bytes],
    enabler_raw: bytes,
    source_authorities: Mapping[str, Mapping[str, Any]],
    lineage: Mapping[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compatibility seam routed through the declared public algorithm."""

    return derive_preverify_chain_candidate_payload(
        dimensions=dimensions,
        pair_sources=pair_sources,
        enabler_raw=enabler_raw,
        source_authorities=source_authorities,
        lineage=lineage,
    )


def derive_preverify_chain_candidate_derivation_conformance_sha256() -> str:
    """Return the chain-candidate v1 golden-vector digest."""

    dimensions = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
        "phase_name": "sc_verify_queue",
        "run_id": "00000000-0000-4000-8000-000000000001",
    }
    hypotheses = (
        b"# Hypotheses\n\n"
        b"| Hypothesis ID | Severity | Title | Constituent Findings | Location |\n"
        b"|---|---|---|---|---|\n"
        b"| H-1 | Medium | First | EN-2, EN-10 | src/F.sol:10 |\n"
    )
    mapping = (
        b"# Finding Mapping\n\n"
        b"| Finding ID | Hypothesis ID | Mapping Status |\n"
        b"|---|---|---|\n"
        b"| EN-10 | H-1 | CHAIN_GENERATED |\n"
        b"| EN-2 | H-1 | CHAIN_GENERATED |\n"
    )
    enabler = (
        b"# Enabler Results\n\n"
        b"### Finding [EN-2]: First candidate\n"
        b"**Severity**: High\n"
        b"**Location**: src/F.sol:20\n"
        b"**Description**: First mechanism.\n"
        b"**Impact**: First impact.\n\n"
        b"### Finding [EN-10]: Second candidate\n"
        b"**Severity**: Unknown\n"
        b"**Location**: src/F.sol:100\n"
        b"**Description**: Second mechanism with escaped \\\\| pipe.\n"
    )
    authorities = {
        name: {
            "schema_version": "plamen.semantic_import_authority.v1",
            "authority_kind": "EXACT_PHASE_IO_PRODUCER",
            "identity": "scratchpad:" + name,
            "run_id": dimensions["run_id"],
            "source_sha256": _sha(raw),
            "source_size": len(raw),
            "producer_work_unit_key": (
                "sc/thorough/evm/claude/chain/model"
            ),
            "producer_contract_digest": "1" * 64,
            "mutation_event_ids": [],
            "mutation_authority_digests": [],
        }
        for name, raw in {
            "hypotheses.md": hypotheses,
            "finding_mapping.md": mapping,
            "enabler_results.md": enabler,
        }.items()
    }
    result = derive_preverify_chain_candidate_payload(
        dimensions=dimensions,
        pair_sources={
            "hypotheses.md": hypotheses,
            "finding_mapping.md": mapping,
        },
        enabler_raw=enabler,
        source_authorities=authorities,
        lineage={
            "lineage_kind": "DIRECT_MODEL_PAIR",
            "model_work_unit_key": (
                "sc/thorough/evm/claude/chain/model"
            ),
            "model_contract_digest": "1" * 64,
            "auto_map_generation_digest": None,
        },
    )
    if (
        not isinstance(result, tuple)
        or len(result) != 2
        or not isinstance(result[0], Mapping)
        or not isinstance(result[1], list)
    ):
        vector: Any = {
            "algorithm": DELTA_DERIVATION_ALGORITHM,
            "invalid_result": result,
        }
    else:
        payload = dict(result[0])
        payload.pop("candidate_digest", None)
        payload.pop("derivation_conformance_sha256", None)
        vector = {
            "algorithm": DELTA_DERIVATION_ALGORITHM,
            "payload": payload,
            "debt": result[1],
        }
    return _sha(_canonical_bytes(vector))


def validate_preverify_chain_candidate_derivation_conformance() -> None:
    """Reject executable drift hidden behind the delta v1 algorithm ID."""

    actual = (
        derive_preverify_chain_candidate_derivation_conformance_sha256()
    )
    if actual != DELTA_DERIVATION_CONFORMANCE_SHA256:
        raise ChainCandidateDeltaError(
            "chain-candidate derivation v1 conformance digest differs; "
            "allocate a new algorithm identifier "
            f"(expected {DELTA_DERIVATION_CONFORMANCE_SHA256}, got {actual})"
        )


def _delta_contract(
    *,
    dimensions: Mapping[str, str],
    generation: str,
    source_authorities: Mapping[str, Mapping[str, Any]],
    outputs: Mapping[str, bytes],
    candidate_path: str,
    receipt_path: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    owner = canonical_work_unit_key(
        dimensions["pipeline"],
        dimensions["mode"],
        dimensions["ecosystem"],
        dimensions["backend"],
        dimensions["phase_name"],
        f"preverify_chain_candidate_delta.{generation}",
    )
    exact_inputs = tuple(sorted({
        str(row.get("identity") or "")
        for row in source_authorities.values()
        if isinstance(row, Mapping) and str(row.get("identity") or "")
    }))
    contract = PhaseIOContract(
        pipeline=dimensions["pipeline"],
        mode=dimensions["mode"],
        ecosystem=dimensions["ecosystem"],
        backend=dimensions["backend"],
        phase=dimensions["phase_name"],
        work_unit_id=f"preverify_chain_candidate_delta.{generation}",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=path,
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    DELTA_SCHEMA
                    if path == candidate_path
                    else (
                        DELTA_RECEIPT_SCHEMA
                        if path == receipt_path
                        else "unstructured.v1"
                    )
                ),
                minimum_gate=(
                    "TYPED_CHAIN_CANDIDATE_DELTA"
                    if path in {candidate_path, receipt_path}
                    else "IMMUTABLE_CHAIN_DERIVATION_PREIMAGE"
                ),
                consumers=(
                    f"{dimensions['phase_name']}/"
                    "preverify_frozen_projection",
                ),
            )
            for path in sorted(outputs)
        ),
        immutable_inputs=exact_inputs,
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


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
        if read_bounded_regular_bytes(path, MAX_BYTES) != raw:
            raise ChainCandidateDeltaError(
                f"content-addressed chain delta contains foreign bytes: {path}"
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


def prepare_preverify_chain_candidate_delta(
    *,
    scratchpad: Path,
    project_root: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    chain_pair_projection: Mapping[str, Any],
) -> dict[str, Any]:
    """Publish one immutable chain-only candidate proposal delta."""

    validate_preverify_chain_candidate_derivation_conformance()
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
    if (
        dimensions["pipeline"] != "sc"
        or dimensions["backend"] not in {"claude", "codex"}
        or not dimensions["mode"]
        or not dimensions["ecosystem"]
        or dimensions["phase_name"] != "sc_verify_queue"
        or not dimensions["run_id"]
    ):
        raise ChainCandidateDeltaError(
            "chain candidate delta run tuple is invalid"
        )
    pair_sources, pair_receipt, pair_authorities = (
        _validated_pair_projection(
            root=root,
            project=project,
            projection=chain_pair_projection,
            dimensions=dimensions,
        )
    )
    enabler_raw, enabler_authority = _exact_authority(
        root,
        project,
        "enabler_results.md",
        run_id=dimensions["run_id"],
    )
    lineage = _validate_model_lineage(
        root=root,
        project=project,
        dimensions=dimensions,
        pair_receipt=pair_receipt,
        pair_sources=pair_sources,
        enabler_authority=enabler_authority,
    )
    source_authorities = {
        **pair_authorities,
        "enabler_results.md": enabler_authority,
        **(
            {
                "auto_map_receipt": dict(
                    lineage["auto_map_receipt_authority"]
                )
            }
            if isinstance(
                lineage.get("auto_map_receipt_authority"), Mapping
            )
            else {}
        ),
    }
    source_preimage_raw: dict[str, bytes] = {
        "hypotheses": pair_sources["hypotheses.md"],
        "finding_mapping": pair_sources["finding_mapping.md"],
        "pair_receipt": pair_sources["pair_receipt"],
        "enabler_results": enabler_raw,
    }
    source_preimage_authority_keys = {
        "hypotheses": "hypotheses.md",
        "finding_mapping": "finding_mapping.md",
        "pair_receipt": "pair_receipt",
        "enabler_results": "enabler_results.md",
    }
    if isinstance(lineage.get("_auto_map_receipt_raw"), bytes):
        source_preimage_raw["auto_map_receipt"] = bytes(
            lineage["_auto_map_receipt_raw"]
        )
        source_preimage_authority_keys["auto_map_receipt"] = (
            "auto_map_receipt"
        )
    source_preimage_bindings = {
        role: {
            "leaf": DELTA_SOURCE_PREIMAGE_LEAVES[role],
            "input_identity": str(
                source_authorities[
                    source_preimage_authority_keys[role]
                ].get("identity")
                or ""
            ),
            **_binding(raw),
        }
        for role, raw in sorted(source_preimage_raw.items())
    }
    payload, debt = _derive_delta_payload(
        dimensions=dimensions,
        pair_sources=pair_sources,
        enabler_raw=enabler_raw,
        source_authorities=source_authorities,
        lineage={
            key: value for key, value in lineage.items()
            if key not in {
                "auto_map_receipt_authority",
                "_auto_map_receipt_raw",
            }
        },
    )
    generation_core = {
        "schema_version": DELTA_RECEIPT_SCHEMA,
        **dimensions,
        "candidate_digest": payload["candidate_digest"],
        "candidate_ids": payload["candidate_ids"],
        "source_bindings": payload["source_bindings"],
        "source_authorities": payload["source_authorities"],
        "model_lineage": payload["model_lineage"],
        "source_preimage_bindings": source_preimage_bindings,
        "derivation_algorithm": DELTA_DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            DELTA_DERIVATION_CONFORMANCE_SHA256
        ),
    }
    generation = _digest(generation_core)
    generation_root = f"{DELTA_ROOT}/generation_{generation}"
    candidate_path = f"{generation_root}/candidates.json"
    receipt_path = f"{generation_root}/receipt.json"
    source_preimage_paths = {
        role: (
            f"{generation_root}/_sources/"
            f"{DELTA_SOURCE_PREIMAGE_LEAVES[role]}"
        )
        for role in source_preimage_raw
    }
    required_paths = sorted({
        candidate_path,
        receipt_path,
        *source_preimage_paths.values(),
    })
    unsigned_receipt = {
        **generation_core,
        "generation_digest": generation,
        "candidate_path": candidate_path,
        "required_paths": required_paths,
        "debt": debt,
        "candidate_disposition": "VERIFY_INDEPENDENTLY",
        "base_inventory_mutated": False,
        "proof_authority": "NONE",
    }
    receipt = {
        **unsigned_receipt,
        "receipt_digest": _digest(unsigned_receipt),
    }
    outputs = {
        candidate_path: _canonical_bytes(payload),
        receipt_path: _canonical_bytes(receipt),
        **{
            source_preimage_paths[role]: raw
            for role, raw in source_preimage_raw.items()
        },
    }
    contract, launch = _delta_contract(
        dimensions=dimensions,
        generation=generation,
        source_authorities=source_authorities,
        outputs=outputs,
        candidate_path=candidate_path,
        receipt_path=receipt_path,
    )
    prior_inputs = validate_work_unit_inputs(
        root,
        project,
        contract,
        launch,
        run_id=dimensions["run_id"],
    )
    prior_outputs = validate_work_unit_artifacts(
        root,
        project,
        contract,
        launch,
        run_id=dimensions["run_id"],
        actor="DRIVER",
    )
    if prior_inputs or prior_outputs:
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
            raise ChainCandidateDeltaError(
                "chain candidate delta PhaseIO input arm failed: "
                + "; ".join(input_issues)
            )
        # Recompute the exact source authorities after arm to close ordinary
        # TOCTOU. The PhaseIO validator binds current hashes and producers.
        for row in source_authorities.values():
            identity = str(row.get("identity") or "")
            if not identity.startswith("scratchpad:"):
                continue
            relative = identity[len("scratchpad:"):]
            _exact_authority(
                root,
                project,
                relative,
                run_id=dimensions["run_id"],
            )
        for relative, raw in sorted(outputs.items()):
            _cas_create_or_exact(
                root.joinpath(*PurePosixPath(relative).parts),
                raw,
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
            raise ChainCandidateDeltaError(
                "chain candidate delta PhaseIO output commit failed: "
                + "; ".join(output_issues)
            )
    for relative, raw in outputs.items():
        if read_bounded_regular_bytes(
            root.joinpath(*PurePosixPath(relative).parts),
            MAX_BYTES,
        ) != raw:
            raise ChainCandidateDeltaError(
                f"{relative}: committed chain candidate delta bytes drifted"
            )
    return {
        "schema_version": DELTA_SCHEMA,
        "state": "OUTPUT_COMMITTED",
        "safe_to_consume": True,
        "run_id": dimensions["run_id"],
        "generation_digest": generation,
        "work_unit_key": contract.key,
        "candidate_path": candidate_path,
        "receipt_path": receipt_path,
        "required_paths": required_paths,
        "candidate_ids": list(payload["candidate_ids"]),
        "candidates": payload,
        "debt": debt,
        "proof_authority": "NONE",
    }


__all__ = [
    "ChainCandidateDeltaError",
    "DELTA_DERIVATION_ALGORITHM",
    "DELTA_DERIVATION_CONFORMANCE_SHA256",
    "DELTA_RECEIPT_SCHEMA",
    "DELTA_ROOT",
    "DELTA_SCHEMA",
    "DELTA_SOURCE_PREIMAGE_LEAVES",
    "derive_preverify_chain_candidate_derivation_conformance_sha256",
    "derive_preverify_chain_candidate_payload",
    "prepare_preverify_chain_candidate_delta",
    "validate_preverify_chain_candidate_derivation_conformance",
]
