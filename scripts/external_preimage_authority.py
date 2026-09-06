"""Closed validators for preserving unowned external MERGE prestates.

The artifact ledger calls this provider itself while holding its transaction
lock.  Callers cannot supply a receipt.  A VALID receipt attests only that the
raw preimage has the declared schema and an exact identity set suitable for a
preserve-only additive merge; it does not attest semantic truth or prior
producer ownership.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


ID_LEDGER_VALIDATOR_ID = "plamen.strict_id_ledger.v1"
AXIS_INVENTORY_VALIDATOR_ID = "plamen.axis_inventory_prestate.v1"
_ID_LEDGER_SCHEMA = "plamen.id_ledger.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FINDING_ID_RE = re.compile(r"^[A-Z]{1,8}-\d+[A-Z0-9-]*$")
_TITLE_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POLICY = {
    "validator_id": ID_LEDGER_VALIDATOR_ID,
    "schema_version": _ID_LEDGER_SCHEMA,
    "identity_normalization": "strip+uppercase",
    "unique_id_required": True,
    "title_hash": "sha256:<64-lower-hex>",
    "row_fingerprint": "sha256(canonical_json(allocation))",
    "required_fields": [
        "id",
        "prefix",
        "owner_phase",
        "owner_attempt",
        "owning_artifact",
        "title_hash",
        "title_preview",
        "allocated_at",
    ],
    "authority": "schema_identity_preserve_only",
}
POLICY_DIGEST = hashlib.sha256(
    json.dumps(
        _POLICY, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
).hexdigest()
_AXIS_INVENTORY_POLICY = {
    "validator_id": AXIS_INVENTORY_VALIDATOR_ID,
    "schema_version": "plamen.canonical_finding_inventory.v1",
    "identity_normalization": "canonical-uppercase-INV-heading",
    "unique_id_required": True,
    "operational_markdown_only": True,
    "row_fingerprint": "sha256(exact-finding-block-utf8)",
    "authority": "schema_identity_preserve_only",
}
AXIS_INVENTORY_POLICY_DIGEST = hashlib.sha256(
    json.dumps(
        _AXIS_INVENTORY_POLICY,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
).hexdigest()
_INVENTORY_HEADING_RE = re.compile(
    r"^(?P<marks>#{2,4})[ \t]+Finding[ \t]*"
    r"\[[ \t]*(?P<id>INV-[0-9]+)[ \t]*\][ \t]*:"
    r"[ \t]*(?P<title>[^\r\n]+?)[ \t]*$",
    re.MULTILINE | re.ASCII,
)
_INVENTORY_FINDING_LIKE_RE = re.compile(
    r"^#{1,6}[ \t]+Finding\b[^\r\n]*$",
    re.MULTILINE | re.IGNORECASE | re.ASCII,
)


class ExternalPreimageValidationError(ValueError):
    """The raw preimage is not valid for the closed validator policy."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(payload: Mapping[str, Any]) -> str:
    unsigned = dict(payload)
    unsigned.pop("receipt_digest", None)
    return _sha(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )


def _strict_json(raw: bytes) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise ExternalPreimageValidationError(
                    f"duplicate JSON key: {key!r}"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ExternalPreimageValidationError(
                    f"non-finite JSON value: {value}"
                )
            ),
        )
    except ExternalPreimageValidationError:
        raise
    except Exception as exc:
        raise ExternalPreimageValidationError(
            f"invalid UTF-8/JSON: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ExternalPreimageValidationError("ID ledger must be one object")
    return value


def _id_ledger_identities(
    raw: bytes,
) -> tuple[tuple[str, ...], tuple[dict[str, str], ...]]:
    payload = _strict_json(raw)
    if (
        set(payload) != {"schema_version", "allocations"}
        or payload.get("schema_version") != _ID_LEDGER_SCHEMA
        or not isinstance(payload.get("allocations"), list)
    ):
        raise ExternalPreimageValidationError("ID ledger schema is invalid")
    required = set(_POLICY["required_fields"])
    identities: list[str] = []
    fingerprints: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, allocation in enumerate(payload["allocations"]):
        if not isinstance(allocation, dict) or set(allocation) != required:
            raise ExternalPreimageValidationError(
                f"allocation {index} lacks required fields"
            )
        finding_id = str(allocation.get("id") or "").strip().upper()
        prefix = str(allocation.get("prefix") or "").strip().upper()
        title_preview = str(allocation.get("title_preview") or "")
        # Lazy import avoids the plamen_parsers -> artifact_ledger import
        # cycle while sharing the one canonical identity implementation.
        from plamen_parsers import _id_prefix_of
        if (
            allocation.get("id") != finding_id
            or not _FINDING_ID_RE.fullmatch(finding_id)
            or finding_id in seen
            or prefix != _id_prefix_of(finding_id)
            or allocation.get("prefix") != prefix
            or not isinstance(allocation.get("owner_attempt"), int)
            or isinstance(allocation.get("owner_attempt"), bool)
            or int(allocation["owner_attempt"]) < 1
            or not isinstance(allocation.get("owner_phase"), str)
            or not allocation["owner_phase"].strip()
            or not isinstance(allocation.get("owning_artifact"), str)
            or not allocation["owning_artifact"].strip()
            or not isinstance(allocation.get("title_preview"), str)
            or not title_preview.strip()
            or not isinstance(allocation.get("allocated_at"), str)
            or not allocation["allocated_at"].strip()
            or not isinstance(allocation.get("title_hash"), str)
            or not _TITLE_HASH_RE.fullmatch(
                allocation["title_hash"]
            )
        ):
            raise ExternalPreimageValidationError(
                f"allocation {index} identity or required field is invalid"
            )
        seen.add(finding_id)
        identities.append(finding_id)
        fingerprints.append(
            {
                "id": finding_id,
                "row_sha256": _sha(
                    json.dumps(
                        allocation,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ),
            }
        )
    return (
        tuple(sorted(identities)),
        tuple(sorted(fingerprints, key=lambda row: row["id"])),
    )


def _axis_inventory_identities(
    raw: bytes,
) -> tuple[tuple[str, ...], tuple[dict[str, str], ...]]:
    """Parse the exact preservable finding-ID surface from inventory Markdown."""

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ExternalPreimageValidationError(
            f"inventory is not strict UTF-8: {exc}"
        ) from exc
    # Lazy import avoids making artifact-ledger import startup depend on the
    # Markdown scanner while ensuring fenced/commented examples cannot become
    # merge identities.
    from operational_markdown import operational_markdown_view

    structural = operational_markdown_view(text)
    canonical = list(_INVENTORY_HEADING_RE.finditer(structural))
    finding_like = list(_INVENTORY_FINDING_LIKE_RE.finditer(structural))
    if {(row.start(), row.end()) for row in canonical} != {
        (row.start(), row.end()) for row in finding_like
    }:
        raise ExternalPreimageValidationError(
            "inventory contains a noncanonical operational finding heading"
        )
    identities: list[str] = []
    fingerprints: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, match in enumerate(canonical):
        finding_id = match.group("id")
        title = match.group("title").strip()
        if (
            finding_id != finding_id.upper()
            or not _FINDING_ID_RE.fullmatch(finding_id)
            or finding_id in seen
            or not title
        ):
            raise ExternalPreimageValidationError(
                "inventory finding identity/title is invalid or duplicated"
            )
        seen.add(finding_id)
        end = (
            canonical[index + 1].start()
            if index + 1 < len(canonical)
            else len(text)
        )
        block = text[match.start():end].rstrip()
        identities.append(finding_id)
        fingerprints.append(
            {"id": finding_id, "row_sha256": _sha(block.encode("utf-8"))}
        )
    return (
        tuple(sorted(identities)),
        tuple(sorted(fingerprints, key=lambda row: row["id"])),
    )


def derive_external_preimage_receipt(
    *,
    validator_id: str,
    work_unit_key: str,
    contract_digest: str,
    artifact_identity: str,
    raw: bytes,
    existed: bool,
) -> dict[str, Any]:
    """Rerun one closed validator and return its digest-bound receipt."""

    validator = str(validator_id or "")
    if validator not in {
        ID_LEDGER_VALIDATOR_ID,
        AXIS_INVENTORY_VALIDATOR_ID,
    }:
        raise ExternalPreimageValidationError(
            f"unregistered external preimage validator: {validator!r}"
        )
    if validator == ID_LEDGER_VALIDATOR_ID:
        if artifact_identity != "scratchpad:_id_ledger.json":
            raise ExternalPreimageValidationError(
                "strict ID-ledger validator is bound to "
                "scratchpad:_id_ledger.json"
            )
        policy_digest = POLICY_DIGEST
    else:
        if artifact_identity != "scratchpad:findings_inventory.md":
            raise ExternalPreimageValidationError(
                "axis inventory validator is bound to "
                "scratchpad:findings_inventory.md"
            )
        policy_digest = AXIS_INVENTORY_POLICY_DIGEST
    if not _SHA256_RE.fullmatch(str(contract_digest or "")):
        raise ExternalPreimageValidationError("contract digest is invalid")
    if existed:
        if validator == ID_LEDGER_VALIDATOR_ID:
            identities, row_fingerprints = _id_ledger_identities(raw)
        else:
            identities, row_fingerprints = _axis_inventory_identities(raw)
        status = "VALID_PRESERVE_ONLY"
    else:
        if raw != b"":
            raise ExternalPreimageValidationError(
                "absent external preimage must use empty raw bytes"
            )
        identities = ()
        row_fingerprints = ()
        status = "VALID_EMPTY_BASE"
    unsigned: dict[str, Any] = {
        "schema_version": "plamen.validated_external_preimage.v1",
        "validator_id": validator,
        "validator_policy_digest": policy_digest,
        "work_unit_key": str(work_unit_key),
        "contract_digest": str(contract_digest),
        "artifact_identity": artifact_identity,
        "raw_sha256": _sha(raw),
        "size": len(raw),
        "existed": bool(existed),
        "parsed_identities": list(identities),
        "row_fingerprints": list(row_fingerprints),
        "validation_status": status,
        "authority_scope": "SCHEMA_IDENTITY_PRESERVE_ONLY",
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def validate_external_preimage_receipt(
    receipt: Mapping[str, Any],
    *,
    validator_id: str,
    work_unit_key: str,
    contract_digest: str,
    artifact_identity: str,
    raw: bytes,
    existed: bool,
) -> None:
    expected = derive_external_preimage_receipt(
        validator_id=validator_id,
        work_unit_key=work_unit_key,
        contract_digest=contract_digest,
        artifact_identity=artifact_identity,
        raw=raw,
        existed=existed,
    )
    if dict(receipt) != expected:
        raise ExternalPreimageValidationError(
            "external preimage receipt differs from independent derivation"
        )


def validate_external_preimage_receipt_integrity(
    receipt: Mapping[str, Any],
) -> None:
    expected_fields = {
        "schema_version",
        "validator_id",
        "validator_policy_digest",
        "work_unit_key",
        "contract_digest",
        "artifact_identity",
        "raw_sha256",
        "size",
        "existed",
        "parsed_identities",
        "row_fingerprints",
        "validation_status",
        "authority_scope",
        "receipt_digest",
    }
    validator = str(receipt.get("validator_id") or "") if isinstance(
        receipt, Mapping
    ) else ""
    policy_digest = {
        ID_LEDGER_VALIDATOR_ID: POLICY_DIGEST,
        AXIS_INVENTORY_VALIDATOR_ID: AXIS_INVENTORY_POLICY_DIGEST,
    }.get(validator, "")
    if (
        not isinstance(receipt, Mapping)
        or set(receipt) != expected_fields
        or receipt.get("schema_version")
        != "plamen.validated_external_preimage.v1"
        or not policy_digest
        or receipt.get("validator_policy_digest") != policy_digest
        or not _SHA256_RE.fullmatch(str(receipt.get("contract_digest") or ""))
        or not _SHA256_RE.fullmatch(str(receipt.get("raw_sha256") or ""))
        or not isinstance(receipt.get("size"), int)
        or isinstance(receipt.get("size"), bool)
        or int(receipt["size"]) < 0
        or not isinstance(receipt.get("existed"), bool)
        or not isinstance(receipt.get("parsed_identities"), list)
        or not isinstance(receipt.get("row_fingerprints"), list)
        or receipt.get("validation_status")
        not in {"VALID_PRESERVE_ONLY", "VALID_EMPTY_BASE"}
        or receipt.get("authority_scope")
        != "SCHEMA_IDENTITY_PRESERVE_ONLY"
        or receipt.get("receipt_digest") != _digest(receipt)
    ):
        raise ExternalPreimageValidationError(
            "external preimage receipt integrity is invalid"
        )
    identities = receipt["parsed_identities"]
    if identities != sorted(set(identities)) or any(
        not _FINDING_ID_RE.fullmatch(str(value or ""))
        for value in identities
    ):
        raise ExternalPreimageValidationError(
            "external preimage receipt identity set is invalid"
        )
    fingerprints = receipt["row_fingerprints"]
    if (
        len(fingerprints) != len(identities)
        or any(
            not isinstance(row, dict)
            or set(row) != {"id", "row_sha256"}
            or row.get("id") != identities[index]
            or not _SHA256_RE.fullmatch(str(row.get("row_sha256") or ""))
            for index, row in enumerate(fingerprints)
        )
    ):
        raise ExternalPreimageValidationError(
            "external preimage receipt row fingerprints are invalid"
        )
    if receipt["validation_status"] == "VALID_EMPTY_BASE" and (
        receipt["existed"]
        or receipt["size"] != 0
        or receipt["raw_sha256"] != _sha(b"")
        or identities
        or fingerprints
    ):
        raise ExternalPreimageValidationError(
            "empty-base external preimage receipt is inconsistent"
        )


__all__ = [
    "AXIS_INVENTORY_POLICY_DIGEST",
    "AXIS_INVENTORY_VALIDATOR_ID",
    "ID_LEDGER_VALIDATOR_ID",
    "POLICY_DIGEST",
    "ExternalPreimageValidationError",
    "derive_external_preimage_receipt",
    "validate_external_preimage_receipt",
    "validate_external_preimage_receipt_integrity",
]
