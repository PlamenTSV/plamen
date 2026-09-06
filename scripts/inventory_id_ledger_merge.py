"""Pure inventory ID-allocation projection and additive ledger merge planning.

This provider performs no filesystem writes.  The driver owns PhaseIO
prebinding, the interprocess artifact lock, compare-and-swap, atomic writes,
and commit.  Keeping the planned successor bytes in the receipt makes a crash
after the ledger write resumable without reinterpreting the successor as its
own preimage.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from plamen_parsers import _ID_LEDGER_SCHEMA_VERSION


DELTA_SCHEMA = "plamen.inventory_id_allocation_delta.v1"
MERGE_RECEIPT_SCHEMA = "plamen.inventory_id_ledger_merge_receipt.v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INV_RE = re.compile(r"^INV-\d+$")
_ANY_ID_RE = re.compile(r"^[A-Z]{1,8}-\d+[A-Z0-9-]*$")
_ALLOCATION_FIELDS = {
    "id",
    "prefix",
    "owner_phase",
    "owner_attempt",
    "owning_artifact",
    "title_hash",
    "title_preview",
    "allocated_at",
}
_SUCCESS_STATUSES = {
    "EMPTY_BASE_CREATED",
    "TYPED_PREIMAGE_MERGED",
    "PREEXISTING_UNTYPED_PRESERVED",
}
_DEBT_STATUSES = {
    "IDENTITY_COLLISION_DEBT",
    "MALFORMED_PREEXISTING_REVIEW_DEBT",
}
_AUTHORITIES = {
    "TYPED_ACTIVE",
    "PREEXISTING_UNTYPED_PRESERVED",
    "ABSENT_CANONICAL_EMPTY",
}


class InventoryIDLedgerMergeError(ValueError):
    """The allocation projection or merge transition is not exact."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(payload: Mapping[str, Any], field: str) -> str:
    unsigned = dict(payload)
    unsigned.pop(field, None)
    return _sha(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise InventoryIDLedgerMergeError(
                    f"{label} contains duplicate key {key!r}"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                InventoryIDLedgerMergeError(
                    f"{label} contains non-finite value {value}"
                )
            ),
        )
    except InventoryIDLedgerMergeError:
        raise
    except Exception as exc:
        raise InventoryIDLedgerMergeError(
            f"{label} is malformed: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise InventoryIDLedgerMergeError(f"{label} must be one object")
    return value


def _allocation_identities(rows: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    return tuple(sorted(str(row.get("id") or "").upper() for row in rows))


def _validate_allocation_rows(
    rows: Any,
    *,
    inventory_only: bool,
    label: str,
) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise InventoryIDLedgerMergeError(f"{label} allocations must be a list")
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise InventoryIDLedgerMergeError(
                f"{label} allocation {index} is not an object"
            )
        row = dict(raw)
        raw_id = str(row.get("id") or "")
        finding_id = raw_id.strip().upper()
        title_hash = str(row.get("title_hash") or "").strip()
        title = str(row.get("title_preview") or "")
        from plamen_parsers import _id_prefix_of
        if (
            set(row) != _ALLOCATION_FIELDS
            or raw_id != finding_id
            or finding_id in seen
            or (inventory_only and not _INV_RE.fullmatch(finding_id))
            or (not inventory_only and not _ANY_ID_RE.fullmatch(finding_id))
            or row.get("prefix") != _id_prefix_of(finding_id)
            or not isinstance(row.get("owner_attempt"), int)
            or isinstance(row.get("owner_attempt"), bool)
            or int(row["owner_attempt"]) < 1
            or not isinstance(row.get("owner_phase"), str)
            or not row["owner_phase"].strip()
            or not isinstance(row.get("owning_artifact"), str)
            or not row["owning_artifact"].strip()
            or not isinstance(row.get("title_preview"), str)
            or not title.strip()
            or not isinstance(row.get("allocated_at"), str)
            or not row["allocated_at"].strip()
            or not isinstance(row.get("title_hash"), str)
            or not title_hash.startswith("sha256:")
            or not _SHA256_RE.fullmatch(title_hash[len("sha256:"):])
        ):
            raise InventoryIDLedgerMergeError(
                f"{label} allocation identity is invalid or duplicated: "
                f"{finding_id or index}"
            )
        row["id"] = finding_id
        seen.add(finding_id)
        result.append(row)
    return result


def build_inventory_allocation_delta(
    *,
    run_id: str,
    inventory_sha256: str,
    records_sha256: str,
    allocations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Build the immutable canonical inventory allocation projection."""

    run = str(run_id or "").strip()
    rows = _validate_allocation_rows(
        list(allocations),
        inventory_only=True,
        label="inventory allocation delta",
    )
    if (
        not run
        or not _SHA256_RE.fullmatch(str(inventory_sha256 or ""))
        or not _SHA256_RE.fullmatch(str(records_sha256 or ""))
    ):
        raise InventoryIDLedgerMergeError(
            "inventory allocation delta anchors are invalid"
        )
    unsigned: dict[str, Any] = {
        "schema_version": DELTA_SCHEMA,
        "run_id": run,
        "inventory_artifact": "findings_inventory.md",
        "inventory_sha256": str(inventory_sha256),
        "records_artifact": "finding_records.json",
        "records_sha256": str(records_sha256),
        "allocations": rows,
    }
    return {**unsigned, "delta_digest": _digest(unsigned, "delta_digest")}


def validate_inventory_allocation_delta(
    payload: Mapping[str, Any],
) -> None:
    expected = {
        "schema_version",
        "run_id",
        "inventory_artifact",
        "inventory_sha256",
        "records_artifact",
        "records_sha256",
        "allocations",
        "delta_digest",
    }
    if (
        not isinstance(payload, Mapping)
        or set(payload) != expected
        or payload.get("schema_version") != DELTA_SCHEMA
        or payload.get("inventory_artifact") != "findings_inventory.md"
        or payload.get("records_artifact") != "finding_records.json"
        or not str(payload.get("run_id") or "")
        or not _SHA256_RE.fullmatch(str(payload.get("inventory_sha256") or ""))
        or not _SHA256_RE.fullmatch(str(payload.get("records_sha256") or ""))
        or payload.get("delta_digest") != _digest(payload, "delta_digest")
    ):
        raise InventoryIDLedgerMergeError(
            "inventory allocation delta schema or digest is invalid"
        )
    _validate_allocation_rows(
        payload.get("allocations"),
        inventory_only=True,
        label="inventory allocation delta",
    )


def encode_inventory_allocation_delta(payload: Mapping[str, Any]) -> bytes:
    validate_inventory_allocation_delta(payload)
    return _json_bytes(payload)


def decode_inventory_allocation_delta(raw: bytes) -> dict[str, Any]:
    payload = _strict_object(raw, label="inventory allocation delta")
    validate_inventory_allocation_delta(payload)
    return payload


def _receipt(
    *,
    status: str,
    before_sha256: str,
    before_existed: bool,
    preexisting_authority: str,
    delta_digest: str,
    before_ids: Sequence[str],
    after_sha256: str,
    after_ids: Sequence[str],
    compatible_reuse_ids: Sequence[str],
    added_ids: Sequence[str],
    preimage_payload: str,
    successor_payload: str,
    issues: Sequence[str],
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "schema_version": MERGE_RECEIPT_SCHEMA,
        "status": str(status),
        "before_sha256": str(before_sha256),
        "before_existed": bool(before_existed),
        "preexisting_authority": str(preexisting_authority),
        "delta_digest": str(delta_digest),
        "before_ids": sorted({str(value).upper() for value in before_ids}),
        "after_sha256": str(after_sha256),
        "after_ids": sorted({str(value).upper() for value in after_ids}),
        "compatible_reuse_ids": sorted({
            str(value).upper() for value in compatible_reuse_ids
        }),
        "added_ids": sorted({str(value).upper() for value in added_ids}),
        "preimage_payload": str(preimage_payload),
        "successor_payload": str(successor_payload),
        "issues": [str(value) for value in issues],
    }
    return {**unsigned, "receipt_digest": _digest(unsigned, "receipt_digest")}


def build_inventory_id_ledger_merge_receipt(
    *,
    delta: Mapping[str, Any],
    before_raw: bytes | None,
    preexisting_typed: bool,
) -> dict[str, Any]:
    """Plan a collision-checked additive union over the exact preimage."""

    validate_inventory_allocation_delta(delta)
    existed = before_raw is not None
    raw = before_raw if before_raw is not None else b""
    before_sha = _sha(raw)
    authority = (
        "TYPED_ACTIVE"
        if preexisting_typed
        else "PREEXISTING_UNTYPED_PRESERVED"
        if existed
        else "ABSENT_CANONICAL_EMPTY"
    )
    if existed:
        try:
            payload = _strict_object(raw, label="pre-existing ID ledger")
            if (
                payload.get("schema_version") != _ID_LEDGER_SCHEMA_VERSION
                or set(payload) != {"schema_version", "allocations"}
            ):
                raise InventoryIDLedgerMergeError(
                    "pre-existing ID ledger schema is invalid"
                )
            before_rows = _validate_allocation_rows(
                payload.get("allocations"),
                inventory_only=False,
                label="pre-existing ID ledger",
            )
        except InventoryIDLedgerMergeError as exc:
            return _receipt(
                status="MALFORMED_PREEXISTING_REVIEW_DEBT",
                before_sha256=before_sha,
                before_existed=True,
                preexisting_authority=authority,
                delta_digest=str(delta["delta_digest"]),
                before_ids=(),
                after_sha256=before_sha,
                after_ids=(),
                compatible_reuse_ids=(),
                added_ids=(),
                preimage_payload=raw.decode("utf-8", errors="replace"),
                successor_payload="",
                issues=(str(exc),),
            )
    else:
        before_rows = []

    result = [dict(row) for row in before_rows]
    by_id = {str(row["id"]).upper(): row for row in result}
    compatible: list[str] = []
    added: list[str] = []
    collisions: list[str] = []
    for allocation in delta["allocations"]:
        row = dict(allocation)
        finding_id = str(row["id"]).upper()
        prior = by_id.get(finding_id)
        if prior is None:
            result.append(row)
            by_id[finding_id] = row
            added.append(finding_id)
        elif prior.get("title_hash") == row.get("title_hash"):
            compatible.append(finding_id)
        else:
            collisions.append(finding_id)
    before_ids = _allocation_identities(before_rows)
    if collisions:
        return _receipt(
            status="IDENTITY_COLLISION_DEBT",
            before_sha256=before_sha,
            before_existed=existed,
            preexisting_authority=authority,
            delta_digest=str(delta["delta_digest"]),
            before_ids=before_ids,
            after_sha256=before_sha,
            after_ids=before_ids,
            compatible_reuse_ids=compatible,
            added_ids=(),
            preimage_payload=(
                raw.decode("utf-8", errors="strict") if existed else ""
            ),
            successor_payload="",
            issues=(
                "semantic inventory ID collision: "
                + ", ".join(sorted(collisions)),
            ),
        )

    successor = _json_bytes(
        {
            "schema_version": _ID_LEDGER_SCHEMA_VERSION,
            "allocations": result,
        }
    )
    status = (
        "EMPTY_BASE_CREATED"
        if not existed
        else "TYPED_PREIMAGE_MERGED"
        if preexisting_typed
        else "PREEXISTING_UNTYPED_PRESERVED"
    )
    return _receipt(
        status=status,
        before_sha256=before_sha,
        before_existed=existed,
        preexisting_authority=authority,
        delta_digest=str(delta["delta_digest"]),
        before_ids=before_ids,
        after_sha256=_sha(successor),
        after_ids=_allocation_identities(result),
        compatible_reuse_ids=compatible,
        added_ids=added,
        preimage_payload=(
            raw.decode("utf-8", errors="strict") if existed else ""
        ),
        successor_payload=successor.decode("utf-8"),
        issues=(),
    )


def validate_inventory_id_ledger_merge_receipt(
    payload: Mapping[str, Any],
    *,
    delta: Mapping[str, Any],
) -> None:
    validate_inventory_allocation_delta(delta)
    expected = {
        "schema_version",
        "status",
        "before_sha256",
        "before_existed",
        "preexisting_authority",
        "delta_digest",
        "before_ids",
        "after_sha256",
        "after_ids",
        "compatible_reuse_ids",
        "added_ids",
        "preimage_payload",
        "successor_payload",
        "issues",
        "receipt_digest",
    }
    status = str(payload.get("status") or "")
    authority = str(payload.get("preexisting_authority") or "")
    if (
        not isinstance(payload, Mapping)
        or set(payload) != expected
        or payload.get("schema_version") != MERGE_RECEIPT_SCHEMA
        or payload.get("delta_digest") != delta.get("delta_digest")
        or not _SHA256_RE.fullmatch(str(payload.get("before_sha256") or ""))
        or not _SHA256_RE.fullmatch(str(payload.get("after_sha256") or ""))
        or payload.get("receipt_digest")
        != _digest(payload, "receipt_digest")
        or status not in (_SUCCESS_STATUSES | _DEBT_STATUSES)
        or authority not in _AUTHORITIES
        or not isinstance(payload.get("before_existed"), bool)
        or not all(
            isinstance(payload.get(field), list)
            for field in (
                "before_ids",
                "after_ids",
                "compatible_reuse_ids",
                "added_ids",
                "issues",
            )
        )
    ):
        raise InventoryIDLedgerMergeError(
            "inventory ID-ledger merge receipt is invalid"
        )
    def id_list(field: str) -> list[str]:
        values = payload[field]
        if (
            values != sorted(set(values))
            or any(
                not isinstance(value, str)
                or not _ANY_ID_RE.fullmatch(value)
                for value in values
            )
        ):
            raise InventoryIDLedgerMergeError(
                f"inventory ID-ledger receipt {field} is invalid"
            )
        return list(values)

    before_ids = id_list("before_ids")
    after_ids = id_list("after_ids")
    compatible_ids = id_list("compatible_reuse_ids")
    added_ids = id_list("added_ids")
    before_set = set(before_ids)
    after_set = set(after_ids)
    compatible_set = set(compatible_ids)
    added_set = set(added_ids)
    delta_set = {
        str(row["id"]) for row in delta.get("allocations") or []
    }
    if (
        not before_set.issubset(after_set)
        or compatible_set - (before_set & delta_set)
    ):
        raise InventoryIDLedgerMergeError(
            "inventory ID-ledger receipt identity algebra is invalid"
        )

    successor = str(payload.get("successor_payload") or "").encode("utf-8")
    preimage = str(payload.get("preimage_payload") or "").encode("utf-8")
    issues = payload.get("issues") or []
    if (
        bool(payload.get("before_existed")) != bool(preimage)
        or _sha(preimage) != payload.get("before_sha256")
    ):
        raise InventoryIDLedgerMergeError(
            "inventory ID-ledger receipt preimage payload is invalid"
        )
    if status in _SUCCESS_STATUSES:
        if (
            issues
            or not successor
            or after_set != before_set | delta_set
            or added_set != after_set - before_set
        ):
            raise InventoryIDLedgerMergeError(
                "successful inventory ID-ledger receipt algebra is invalid"
            )
        if _sha(successor) != payload.get("after_sha256"):
            raise InventoryIDLedgerMergeError(
                "inventory ID-ledger successor payload digest is invalid"
            )
        successor_payload = _strict_object(
            successor, label="inventory ID-ledger successor"
        )
        if successor_payload.get("schema_version") != _ID_LEDGER_SCHEMA_VERSION:
            raise InventoryIDLedgerMergeError(
                "inventory ID-ledger successor schema is invalid"
            )
        rows = _validate_allocation_rows(
            successor_payload.get("allocations"),
            inventory_only=False,
            label="inventory ID-ledger successor",
        )
        if list(_allocation_identities(rows)) != list(payload["after_ids"]):
            raise InventoryIDLedgerMergeError(
                "inventory ID-ledger successor identity set differs"
            )
    else:
        if (
            not issues
            or successor
            or after_set != before_set
            or added_set
            or payload.get("after_sha256")
            != payload.get("before_sha256")
        ):
            raise InventoryIDLedgerMergeError(
                "debt inventory ID-ledger receipt carries a successor"
            )

    existed = bool(payload.get("before_existed"))
    if authority == "ABSENT_CANONICAL_EMPTY" and (
        existed or before_ids or payload.get("before_sha256") != _sha(b"")
    ):
        raise InventoryIDLedgerMergeError(
            "absent inventory ID-ledger authority is inconsistent"
        )
    if status == "EMPTY_BASE_CREATED" and authority != "ABSENT_CANONICAL_EMPTY":
        raise InventoryIDLedgerMergeError(
            "empty-base merge status has non-empty authority"
        )
    if status == "TYPED_PREIMAGE_MERGED" and authority != "TYPED_ACTIVE":
        raise InventoryIDLedgerMergeError(
            "typed merge status has non-typed authority"
        )
    if (
        status == "PREEXISTING_UNTYPED_PRESERVED"
        and authority != "PREEXISTING_UNTYPED_PRESERVED"
    ):
        raise InventoryIDLedgerMergeError(
            "untyped preservation status has incompatible authority"
        )
    expected = build_inventory_id_ledger_merge_receipt(
        delta=delta,
        before_raw=preimage if payload["before_existed"] else None,
        preexisting_typed=authority == "TYPED_ACTIVE",
    )
    if dict(payload) != expected:
        raise InventoryIDLedgerMergeError(
            "inventory ID-ledger receipt differs from deterministic "
            "preimage re-derivation"
        )


def encode_inventory_id_ledger_merge_receipt(
    payload: Mapping[str, Any],
    *,
    delta: Mapping[str, Any],
) -> bytes:
    validate_inventory_id_ledger_merge_receipt(payload, delta=delta)
    return _json_bytes(payload)


def decode_inventory_id_ledger_merge_receipt(
    raw: bytes,
    *,
    delta: Mapping[str, Any],
) -> dict[str, Any]:
    payload = _strict_object(raw, label="inventory ID-ledger merge receipt")
    validate_inventory_id_ledger_merge_receipt(payload, delta=delta)
    return payload


__all__ = [
    "DELTA_SCHEMA",
    "MERGE_RECEIPT_SCHEMA",
    "InventoryIDLedgerMergeError",
    "build_inventory_allocation_delta",
    "build_inventory_id_ledger_merge_receipt",
    "decode_inventory_allocation_delta",
    "decode_inventory_id_ledger_merge_receipt",
    "encode_inventory_allocation_delta",
    "encode_inventory_id_ledger_merge_receipt",
    "validate_inventory_allocation_delta",
    "validate_inventory_id_ledger_merge_receipt",
]
