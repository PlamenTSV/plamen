"""Report Summary-parity receipt codec and validation.

Extracted unchanged from the driver so historical report-lineage consumers can
reuse the same checks without importing audit orchestration.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from phase_io_contracts import PhaseIOContract
from plamen_validators import derive_report_index_summary_master_parity

_REPORT_INDEX_SUMMARY_PARITY_SCHEMA = "plamen.report_index_summary_parity.v1"


def _summary_parity_receipt_digest(payload: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in payload.items()
        if key != "receipt_digest"
    }
    return hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _summary_parity_receipt_bytes(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(payload),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _build_summary_parity_receipt(
    derivation: Any,
    *,
    contract: PhaseIOContract,
    run_id: str,
    model_work_unit_key: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": _REPORT_INDEX_SUMMARY_PARITY_SCHEMA,
        "run_id": str(run_id),
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "artifact_identity": "scratchpad:report_index.md",
        "model_work_unit_key": str(model_work_unit_key),
        "before_sha256": str(derivation.before_sha256),
        "before_size": len(derivation.input_bytes),
        "after_sha256": str(derivation.after_sha256),
        "after_size": len(derivation.output_bytes),
        "summary_before_sha256": str(
            derivation.summary_before_sha256
        ),
        "summary_after_sha256": str(derivation.summary_after_sha256),
        "master_section_sha256": str(
            derivation.master_section_sha256
        ),
        "outside_summary_sha256": str(
            derivation.outside_summary_sha256
        ),
        "master_counts": dict(derivation.master_counts),
        "summary_counts_before": dict(derivation.summary_counts),
        "deltas": [
            {"label": label, "change": change}
            for label, change in derivation.deltas
        ],
        "repair_kind": "SUMMARY_COUNTS_FROM_MASTER_CARDINALITY",
    }
    payload["receipt_digest"] = _summary_parity_receipt_digest(payload)
    return payload


def _read_summary_parity_receipt(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = Path(path).read_bytes()
    payload = json.loads(raw.decode("utf-8", errors="strict"))
    if not isinstance(payload, dict):
        raise ValueError("Summary parity receipt must be a JSON object")
    if raw != _summary_parity_receipt_bytes(payload):
        raise ValueError("Summary parity receipt bytes are non-canonical")
    if payload.get("receipt_digest") != _summary_parity_receipt_digest(
        payload
    ):
        raise ValueError("Summary parity receipt digest is invalid")
    return payload, raw


def _validate_summary_parity_receipt(
    payload: Mapping[str, Any],
    *,
    contract: PhaseIOContract,
    run_id: str,
    model_work_unit_key: str,
    prestate: Mapping[str, Any],
    current: bytes,
    before_derivation: Any | None = None,
) -> list[str]:
    issues: list[str] = []
    expected_header = {
        "schema_version": _REPORT_INDEX_SUMMARY_PARITY_SCHEMA,
        "run_id": run_id,
        "work_unit_key": contract.key,
        "contract_digest": contract.digest,
        "artifact_identity": "scratchpad:report_index.md",
        "model_work_unit_key": model_work_unit_key,
        "repair_kind": "SUMMARY_COUNTS_FROM_MASTER_CARDINALITY",
    }
    for field, expected in expected_header.items():
        if payload.get(field) != expected:
            issues.append(
                f"Summary parity receipt {field} mismatch"
            )
    if payload.get("before_sha256") != prestate.get("sha256"):
        issues.append("Summary parity receipt/model preimage digest mismatch")
    if payload.get("before_size") != prestate.get("size"):
        issues.append("Summary parity receipt/model preimage size mismatch")
    if (
        prestate.get("predecessor_owner_key") != model_work_unit_key
        or prestate.get("status") != "ACTIVE_REGISTERED_PREDECESSOR"
    ):
        issues.append(
            "Summary parity successor is not bound to the exact active MODEL "
            "preimage"
        )
    if payload.get("receipt_digest") != _summary_parity_receipt_digest(
        payload
    ):
        issues.append("Summary parity receipt digest is invalid")

    if before_derivation is not None:
        expected = _build_summary_parity_receipt(
            before_derivation,
            contract=contract,
            run_id=run_id,
            model_work_unit_key=model_work_unit_key,
        )
        if dict(payload) != expected:
            issues.append(
                "Summary parity receipt disagrees with the pure preimage "
                "derivation"
            )
    current_sha256 = hashlib.sha256(current).hexdigest()
    if current_sha256 == payload.get("after_sha256"):
        current_derivation = derive_report_index_summary_master_parity(
            current
        )
        if (
            current_derivation.issues
            or current_derivation.repair_required
            or current_derivation.status not in {"CLEAN", "NOT_APPLICABLE"}
        ):
            issues.append(
                "Summary parity postimage is not a clean pure replay"
            )
        if len(current) != payload.get("after_size"):
            issues.append("Summary parity postimage size mismatch")
        for field, observed in (
            (
                "summary_after_sha256",
                current_derivation.summary_before_sha256,
            ),
            (
                "master_section_sha256",
                current_derivation.master_section_sha256,
            ),
            (
                "outside_summary_sha256",
                current_derivation.outside_summary_sha256,
            ),
        ):
            if payload.get(field) != observed:
                issues.append(
                    f"Summary parity postimage {field} mismatch"
                )
    return list(dict.fromkeys(issues))
