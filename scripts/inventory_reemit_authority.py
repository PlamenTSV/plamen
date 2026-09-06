"""Crash-safe additive repair for unresolved inventory reconciliation debt.

This provider never merges, refutes, downgrades, or deletes a candidate.  It
only re-emits an unresolved raw discovery as its own inventory finding and
binds that new block to the exact source artifact/block.  Later applied-lossless
dedup may consolidate it; until then it remains independently verifiable.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from inventory_reconciliation import (
    REEMIT_FILE,
    REEMIT_SCHEMA,
    _canonical_blocks,
    _digest,
    reconcile_inventory,
)


INTENT_SCHEMA = "plamen.inventory_reemit_intent.v2"
INTENT_FILE = "inventory_reemit_intent.json"
INVENTORY_FILE = "findings_inventory.md"
MATERIALIZATION_FILES = (INTENT_FILE, INVENTORY_FILE, REEMIT_FILE)


class InventoryReemitError(RuntimeError):
    """The additive repair transaction is stale, ambiguous, or malformed."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _strict_json(path: Path) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise InventoryReemitError(f"{path.name} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            path.read_text(encoding="utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                InventoryReemitError(f"{path.name} contains non-finite {value}")
            ),
        )
    except InventoryReemitError:
        raise
    except Exception as exc:
        raise InventoryReemitError(f"{path.name} is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise InventoryReemitError(f"{path.name} must contain one object")
    return value


def _atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.reemit.tmp")
    with temporary.open("wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _payload_digest(payload: Mapping[str, Any], field: str) -> str:
    unsigned = dict(payload)
    unsigned.pop(field, None)
    return _digest(unsigned)


def _normalized_severity(value: str) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "informational": "Informational",
        "info": "Informational",
    }
    text = str(value or "").strip().casefold()
    if text in mapping:
        return mapping[text]
    for token in ("critical", "high", "medium", "low", "informational", "info"):
        if re.search(rf"(?<![a-z]){token}(?![a-z])", text):
            return mapping[token]
    # Missing/novel severity must still reach Core's Medium+ verifier floor.
    # This is a provisional routing floor, not final report authority.
    return "Medium"


def _safe_field(value: Any, fallback: str) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text or fallback


def _demote_source_block(value: str) -> str:
    return re.sub(
        r"(?im)^#{2,6}\s+(?:Finding\s+)?\[([^\]]+)\]\s*[:=\-–—]*\s*",
        r"**Preserved source finding [\1]**: ",
        value.strip(),
    )


def _fence_source_block(value: str) -> str:
    """Embed source evidence without activating its Markdown headings.

    Raw findings can contain sibling-depth headings such as
    ``### Precondition Analysis``.  If those remain operational inside a new
    ``### Finding [INV-*]`` block, the canonical parser truncates the target
    and its receipt hash cannot replay.  Choose a fence longer than every
    backtick run in the source so the complete source bytes stay structurally
    inside the target while the canonical fields rendered above remain the
    mechanism/impact authority.
    """
    source = str(value or "").strip()
    longest = max((len(run) for run in re.findall(r"`+", source)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}markdown\n{source}\n{fence}"


def _inventory_ids(path: Path) -> set[int]:
    blocks, _issues = _canonical_blocks(path)
    result: set[int] = set()
    for block in blocks:
        match = re.fullmatch(r"INV-(\d+)", str(block.get("finding_id") or ""), re.I)
        if match:
            result.add(int(match.group(1)))
    return result


def _id_ledger_reservations(
    root: Path,
) -> tuple[bool, str, tuple[str, ...]]:
    """Return the exact durable inventory-ID reservation denominator.

    The allocation ledger is a reservation authority even when an old finding
    no longer appears in the current Markdown projection.  Treating only the
    visible inventory as allocated permits semantic ID reassignment.
    """

    path = root / "_id_ledger.json"
    if not path.exists():
        return False, _sha(b""), ()
    if not path.is_file() or path.is_symlink():
        raise InventoryReemitError("_id_ledger.json is missing or unsafe")
    raw = path.read_bytes()
    payload = _strict_json(path)
    if (
        payload.get("schema_version") != "plamen.id_ledger.v1"
        or set(payload) != {"schema_version", "allocations"}
        or not isinstance(payload.get("allocations"), list)
    ):
        raise InventoryReemitError("_id_ledger.json schema is invalid")
    reserved: set[str] = set()
    seen: set[str] = set()
    for index, row in enumerate(payload["allocations"]):
        if not isinstance(row, Mapping):
            raise InventoryReemitError(
                f"_id_ledger.json allocation {index} is invalid"
            )
        finding_id = str(row.get("id") or "").strip().upper()
        if not finding_id or finding_id in seen:
            raise InventoryReemitError(
                "_id_ledger.json allocation identities are invalid"
            )
        seen.add(finding_id)
        if re.fullmatch(r"INV-\d+", finding_id):
            reserved.add(finding_id)
    ordered = tuple(
        sorted(
            reserved,
            key=lambda value: (int(value.split("-", 1)[1]), value),
        )
    )
    return True, _sha(raw), ordered


def _render_block(row: Mapping[str, Any], target_id: str) -> str:
    source_ref = f"{row['source_artifact']}:{row['source_finding_id']}"
    title = _safe_field(row.get("source_title"), "Preserved discovery candidate")
    root = _safe_field(row.get("source_root_cause"), title)
    description = _safe_field(row.get("source_description"), root)
    impact = _safe_field(
        row.get("source_impact"),
        "Material impact remains unresolved and requires independent verification.",
    )
    preconditions = _safe_field(row.get("source_preconditions"), "")
    preserved = _fence_source_block(str(row.get("source_block") or ""))
    lines = [
        f"### Finding [{target_id}]: {title}",
        f"**Severity**: {_normalized_severity(str(row.get('source_severity') or ''))}",
        f"**Location**: {_safe_field(row.get('source_location'), 'UNKNOWN')}",
        "**Preferred Tag**: [RECONCILIATION-REEMIT]",
        f"**Source IDs**: {source_ref}",
        "**Verdict**: NEEDS_VERIFICATION",
        f"**Root Cause**: {root}",
        f"**Description**: {description}",
        f"**Impact**: {impact}",
    ]
    if preconditions:
        lines.append(f"**Preconditions**: {preconditions}")
    lines.extend(
        [
            f"**Re-emitted Candidate Key**: {row['candidate_key']}",
            "**Delivery State**: INDEPENDENT_VERIFICATION_REQUIRED",
            "**Preserved Source Block**:",
            preserved,
            "",
        ]
    )
    return "\n".join(lines)


def _build_intent(root: Path) -> tuple[dict[str, Any], bytes]:
    inventory = root / "findings_inventory.md"
    if not inventory.is_file() or inventory.is_symlink():
        raise InventoryReemitError("findings_inventory.md is missing or unsafe")
    reconciliation = reconcile_inventory(root, persist=False)
    debt = sorted(
        (
            row for row in reconciliation.get("candidates", [])
            if row.get("disposition") == "HUMAN_REVIEW_DEBT"
        ),
        key=lambda row: str(row.get("candidate_key") or ""),
    )
    before = inventory.read_bytes()
    (
        id_ledger_preimage_exists,
        id_ledger_preimage_sha256,
        reserved_inventory_ids,
    ) = _id_ledger_reservations(root)
    used = _inventory_ids(inventory)
    used.update(
        int(finding_id.split("-", 1)[1])
        for finding_id in reserved_inventory_ids
    )
    next_id = max(used, default=0) + 1
    rows: list[dict[str, Any]] = []
    blocks: list[str] = []
    for candidate in debt:
        while next_id in used:
            next_id += 1
        target_id = f"INV-{next_id:03d}"
        used.add(next_id)
        next_id += 1
        block = _render_block(candidate, target_id)
        block_sha = _sha(block.strip().encode("utf-8"))
        rows.append(
            {
                "candidate_key": candidate["candidate_key"],
                "source_artifact": candidate["source_artifact"],
                "source_sha256": candidate["source_sha256"],
                "source_finding_id": candidate["source_finding_id"],
                "source_block_sha256": candidate["source_block_sha256"],
                "target_finding_id": target_id,
                "target_block_sha256": block_sha,
                "effect": "ADDITIVE_REEMIT",
                "delivery_state": "INDEPENDENT_VERIFICATION_REQUIRED",
            }
        )
        blocks.append(block)
    after = before
    if blocks:
        after = before.rstrip() + b"\n\n" + "\n\n".join(blocks).encode("utf-8")
    unsigned: dict[str, Any] = {
        "schema_version": INTENT_SCHEMA,
        "inventory_artifact": "findings_inventory.md",
        "inventory_before_sha256": _sha(before),
        "inventory_after_sha256": _sha(after),
        "input_reconciliation_digest": reconciliation["receipt_digest"],
        "id_ledger_preimage_exists": id_ledger_preimage_exists,
        "id_ledger_preimage_sha256": id_ledger_preimage_sha256,
        "reserved_inventory_ids": list(reserved_inventory_ids),
        "reserved_inventory_ids_digest": _digest(
            {"reserved_inventory_ids": list(reserved_inventory_ids)}
        ),
        "rows": rows,
        "append_blocks": blocks,
    }
    intent = {**unsigned, "intent_digest": _digest(unsigned)}
    return intent, after


def _validate_intent(intent: Mapping[str, Any]) -> None:
    expected = {
        "schema_version", "inventory_artifact", "inventory_before_sha256",
        "inventory_after_sha256", "input_reconciliation_digest", "rows",
        "id_ledger_preimage_exists", "id_ledger_preimage_sha256",
        "reserved_inventory_ids", "reserved_inventory_ids_digest",
        "append_blocks", "intent_digest",
    }
    if set(intent) != expected or intent.get("schema_version") != INTENT_SCHEMA:
        raise InventoryReemitError("inventory re-emission intent schema is invalid")
    if intent.get("inventory_artifact") != INVENTORY_FILE:
        raise InventoryReemitError(
            "inventory re-emission intent does not target findings_inventory.md"
        )
    if intent.get("intent_digest") != _payload_digest(intent, "intent_digest"):
        raise InventoryReemitError("inventory re-emission intent digest is invalid")
    if not isinstance(intent.get("rows"), list) or not isinstance(
        intent.get("append_blocks"), list
    ) or len(intent["rows"]) != len(intent["append_blocks"]):
        raise InventoryReemitError("inventory re-emission intent denominator is invalid")
    for field in (
        "inventory_before_sha256",
        "inventory_after_sha256",
        "input_reconciliation_digest",
        "id_ledger_preimage_sha256",
        "reserved_inventory_ids_digest",
        "intent_digest",
    ):
        if not re.fullmatch(r"[0-9a-f]{64}", str(intent.get(field) or "")):
            raise InventoryReemitError(
                f"inventory re-emission intent {field} is invalid"
            )
    if not isinstance(intent.get("id_ledger_preimage_exists"), bool):
        raise InventoryReemitError(
            "inventory re-emission intent ID-ledger presence is invalid"
        )
    reserved = intent.get("reserved_inventory_ids")
    if (
        not isinstance(reserved, list)
        or any(not isinstance(value, str) for value in reserved)
        or any(not re.fullmatch(r"INV-\d+", value) for value in reserved)
        or reserved
        != sorted(
            set(reserved),
            key=lambda value: (int(value.split("-", 1)[1]), value),
        )
        or intent.get("reserved_inventory_ids_digest")
        != _digest({"reserved_inventory_ids": reserved})
    ):
        raise InventoryReemitError(
            "inventory re-emission reserved-ID denominator is invalid"
        )
    if (
        not intent["id_ledger_preimage_exists"]
        and (
            intent["id_ledger_preimage_sha256"] != _sha(b"")
            or reserved
        )
    ):
        raise InventoryReemitError(
            "absent ID-ledger preimage cannot reserve identities"
        )
    if not all(isinstance(block, str) for block in intent["append_blocks"]):
        raise InventoryReemitError(
            "inventory re-emission intent append blocks are invalid"
        )
    if not all(isinstance(row, Mapping) for row in intent["rows"]):
        raise InventoryReemitError("inventory re-emission intent rows are invalid")
    expected_row_fields = {
        "candidate_key",
        "source_artifact",
        "source_sha256",
        "source_finding_id",
        "source_block_sha256",
        "target_finding_id",
        "target_block_sha256",
        "effect",
        "delivery_state",
    }
    candidate_keys: set[str] = set()
    target_ids: set[str] = set()
    for index, (row, block) in enumerate(
        zip(intent["rows"], intent["append_blocks"], strict=True)
    ):
        if set(row) != expected_row_fields:
            raise InventoryReemitError(
                f"inventory re-emission intent row {index} schema is invalid"
            )
        candidate_key = str(row.get("candidate_key") or "")
        source_artifact = str(row.get("source_artifact") or "")
        source_finding_id = str(row.get("source_finding_id") or "")
        target_id = str(row.get("target_finding_id") or "")
        if (
            not candidate_key
            or candidate_key in candidate_keys
            or not source_finding_id
            or not source_artifact
            or Path(source_artifact).name != source_artifact
            or not re.fullmatch(r"INV-\d+", target_id)
            or target_id in target_ids
            or row.get("effect") != "ADDITIVE_REEMIT"
            or row.get("delivery_state")
            != "INDEPENDENT_VERIFICATION_REQUIRED"
            or target_id in set(reserved)
        ):
            raise InventoryReemitError(
                f"inventory re-emission intent row {index} binding is invalid"
            )
        for field in (
            "source_sha256",
            "source_block_sha256",
            "target_block_sha256",
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", str(row.get(field) or "")):
                raise InventoryReemitError(
                    f"inventory re-emission intent row {index} {field} is invalid"
                )
        header = re.match(
            r"^###\s+Finding\s+\[([^\]]+)\]",
            block.strip(),
            flags=re.I,
        )
        if (
            header is None
            or header.group(1).upper() != target_id.upper()
            or _sha(block.strip().encode("utf-8"))
            != row["target_block_sha256"]
        ):
            raise InventoryReemitError(
                f"inventory re-emission intent row {index} block is invalid"
            )
        candidate_keys.add(candidate_key)
        target_ids.add(target_id)


def _planned_after(before: bytes, intent: Mapping[str, Any]) -> bytes:
    blocks = intent["append_blocks"]
    after = before
    if blocks:
        after = before.rstrip() + b"\n\n" + "\n\n".join(blocks).encode("utf-8")
    if _sha(after) != intent["inventory_after_sha256"]:
        raise InventoryReemitError("inventory re-emission intent cannot reproduce after bytes")
    return after


def _build_receipt(intent: Mapping[str, Any]) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "schema_version": REEMIT_SCHEMA,
        "status": "APPLIED",
        "intent_sha256": _sha(_canonical_json(intent)),
        "inventory_artifact": intent["inventory_artifact"],
        "inventory_before_sha256": intent["inventory_before_sha256"],
        "inventory_after_sha256": intent["inventory_after_sha256"],
        "input_reconciliation_digest": intent["input_reconciliation_digest"],
        "rows": intent["rows"],
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def _write_receipt(root: Path, intent: Mapping[str, Any]) -> dict[str, Any]:
    receipt = _build_receipt(intent)
    _atomic_write(root / REEMIT_FILE, _canonical_json(receipt))
    return receipt


def plan_inventory_reemit_materialization(
    inventory_preimage: bytes,
    prepared_intent: Mapping[str, Any],
) -> dict[str, bytes]:
    """Return the complete, exact additive materialization without I/O.

    The caller supplies the authenticated inventory preimage and the prepared
    intent.  The returned mapping is the byte-level transition authority for
    every file this repair itself materializes.
    """

    if not isinstance(inventory_preimage, bytes):
        raise InventoryReemitError(
            "inventory re-emission preimage must be exact bytes"
        )
    intent = dict(prepared_intent)
    _validate_intent(intent)
    if _sha(inventory_preimage) != intent["inventory_before_sha256"]:
        raise InventoryReemitError(
            "inventory preimage differs from the prepared re-emission intent"
        )
    inventory_after = _planned_after(inventory_preimage, intent)
    receipt = _build_receipt(intent)
    return {
        INTENT_FILE: _canonical_json(intent),
        INVENTORY_FILE: inventory_after,
        REEMIT_FILE: _canonical_json(receipt),
    }


def validate_inventory_reemit_materialization(
    scratchpad: str | Path,
    planned_artifacts: Mapping[str, bytes],
) -> dict[str, Any]:
    """Validate exact materialized bytes and reconciliation without writing."""

    if set(planned_artifacts) != set(MATERIALIZATION_FILES):
        raise InventoryReemitError(
            "inventory re-emission materialization denominator is invalid"
        )
    expected: dict[str, bytes] = {}
    for name in MATERIALIZATION_FILES:
        raw = planned_artifacts.get(name)
        if not isinstance(raw, bytes):
            raise InventoryReemitError(
                f"{name} planned materialization must be exact bytes"
            )
        expected[name] = raw

    root = Path(scratchpad).resolve(strict=True)
    observed: dict[str, bytes] = {}
    for name in MATERIALIZATION_FILES:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise InventoryReemitError(f"{name} is missing or unsafe")
        try:
            observed[name] = path.read_bytes()
        except OSError as exc:
            raise InventoryReemitError(
                f"{name} is unavailable: {type(exc).__name__}: {exc}"
            ) from exc
        if observed[name] != expected[name]:
            raise InventoryReemitError(
                f"{name} differs from the planned exact bytes"
            )

    intent = _strict_json(root / INTENT_FILE)
    _validate_intent(intent)
    if _sha(observed[INVENTORY_FILE]) != intent["inventory_after_sha256"]:
        raise InventoryReemitError(
            "materialized inventory does not match the prepared successor"
        )
    receipt = _strict_json(root / REEMIT_FILE)
    if observed[REEMIT_FILE] != _canonical_json(_build_receipt(intent)):
        raise InventoryReemitError(
            "materialized re-emission receipt differs from the prepared intent"
        )

    replay = reconcile_inventory(root, persist=False)
    if replay.get("reemit_authority_sha256") != _sha(observed[REEMIT_FILE]):
        raise InventoryReemitError(
            "materialized re-emission receipt does not replay"
        )
    replay_by_key: dict[str, list[Mapping[str, Any]]] = {}
    for candidate in replay.get("candidates", []):
        if not isinstance(candidate, Mapping):
            continue
        key = str(candidate.get("candidate_key") or "")
        replay_by_key.setdefault(key, []).append(candidate)
    for row in receipt.get("rows", []):
        if not isinstance(row, Mapping):
            raise InventoryReemitError(
                "materialized re-emission receipt rows are malformed"
            )
        matches = replay_by_key.get(str(row.get("candidate_key") or ""), [])
        if (
            len(matches) != 1
            or matches[0].get("disposition") != "RETAINED"
            or matches[0].get("reason_code") != "RETAINED_BY_ADDITIVE_REEMIT"
            or str(matches[0].get("target_inventory_id") or "")
            != str(row.get("target_finding_id") or "")
        ):
            raise InventoryReemitError(
                "materialized re-emission does not replay exact candidate delivery"
            )

    for name in MATERIALIZATION_FILES:
        if (root / name).read_bytes() != expected[name]:
            raise InventoryReemitError(
                f"{name} changed while validating exact materialization"
            )
    return receipt


def build_inventory_reemit_plan(scratchpad: str | Path) -> dict[str, Any]:
    """Derive the exact additive plan without writing any byte."""

    root = Path(scratchpad).resolve(strict=True)
    receipt_path = root / REEMIT_FILE
    if receipt_path.is_file():
        receipt = _strict_json(receipt_path)
        return {
            "status": "ALREADY_APPLIED",
            "receipt": receipt,
            "intent": (
                _strict_json(root / INTENT_FILE)
                if (root / INTENT_FILE).is_file()
                else {}
            ),
        }
    intent_path = root / INTENT_FILE
    if intent_path.is_file():
        intent = _strict_json(intent_path)
        _validate_intent(intent)
    else:
        intent, _after = _build_intent(root)
    return {
        "status": "READY" if intent.get("rows") else "NO_DEBT",
        "intent": intent,
    }


def _apply_inventory_reemit_repair_for_tests(
    scratchpad: str | Path,
    *,
    prepared_intent: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply or resume one additive, content-addressed inventory repair."""

    root = Path(scratchpad).resolve(strict=True)
    inventory = root / INVENTORY_FILE
    intent_path = root / INTENT_FILE
    receipt_path = root / REEMIT_FILE
    if receipt_path.is_file():
        if intent_path.is_file() and inventory.is_file():
            planned = {
                INTENT_FILE: intent_path.read_bytes(),
                INVENTORY_FILE: inventory.read_bytes(),
                REEMIT_FILE: receipt_path.read_bytes(),
            }
            return validate_inventory_reemit_materialization(root, planned)
        current = reconcile_inventory(root, persist=False)
        if current.get("reemit_authority_sha256") != _sha(receipt_path.read_bytes()):
            raise InventoryReemitError("existing re-emission receipt does not replay")
        return _strict_json(receipt_path)

    if prepared_intent is not None:
        intent = dict(prepared_intent)
        _validate_intent(intent)
        if intent_path.is_file() and _strict_json(intent_path) != intent:
            raise InventoryReemitError(
                "persisted inventory re-emission intent differs from prepared plan"
            )
    elif intent_path.is_file():
        intent = _strict_json(intent_path)
        _validate_intent(intent)
    else:
        intent, _after = _build_intent(root)
        if not intent["rows"]:
            return {
                "schema_version": REEMIT_SCHEMA,
                "status": "NO_DEBT",
                "rows": [],
            }
    if not intent.get("rows"):
        return {
            "schema_version": REEMIT_SCHEMA,
            "status": "NO_DEBT",
            "rows": [],
        }
    current = inventory.read_bytes()
    current_sha = _sha(current)
    if current_sha not in {
        intent["inventory_before_sha256"],
        intent["inventory_after_sha256"],
    }:
        raise InventoryReemitError("inventory changed while arming re-emission")

    if current_sha == intent["inventory_before_sha256"]:
        planned = plan_inventory_reemit_materialization(current, intent)
    else:
        planned = {
            INTENT_FILE: _canonical_json(intent),
            INVENTORY_FILE: current,
            REEMIT_FILE: _canonical_json(_build_receipt(intent)),
        }
    if intent_path.is_file():
        planned[INTENT_FILE] = intent_path.read_bytes()
    else:
        _atomic_write(intent_path, planned[INTENT_FILE])
    if current_sha == intent["inventory_before_sha256"]:
        _atomic_write(inventory, planned[INVENTORY_FILE])

    receipt = _write_receipt(root, intent)
    validated = validate_inventory_reemit_materialization(root, planned)
    if validated != receipt:
        raise InventoryReemitError(
            "materialized re-emission receipt changed during finalization"
        )
    return validated


__all__ = [
    "INTENT_FILE",
    "INTENT_SCHEMA",
    "INVENTORY_FILE",
    "MATERIALIZATION_FILES",
    "InventoryReemitError",
    "build_inventory_reemit_plan",
    "plan_inventory_reemit_materialization",
    "validate_inventory_reemit_materialization",
]
