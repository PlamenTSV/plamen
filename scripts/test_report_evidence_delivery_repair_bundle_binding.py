"""Repair-attempt diagnostics must belong to the delivered evidence bundle."""
from __future__ import annotations

import json

import report_evidence_authority as E
from test_report_evidence_delivery_pure import _bundle_and_report


def _repair_receipt_bytes(
    *, repaired_bundle_digest: str, report_id: str = "H-01"
) -> bytes:
    receipt = {
        "schema_version": E.REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA,
        "request_digest": "1" * 64,
        "response_digest": "2" * 64,
        "baseline_bundle_digest": "3" * 64,
        "repaired_bundle_digest": repaired_bundle_digest,
        "repair_attempts": {report_id: 1},
        "receipt_digest": "",
    }
    receipt["receipt_digest"] = E._digest(receipt)
    return (
        json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def test_self_consistent_foreign_repair_receipt_has_no_delivery_authority():
    bundle, report = _bundle_and_report()
    without_repair = E.derive_final_report_evidence_delivery(report, bundle)
    foreign = _repair_receipt_bytes(repaired_bundle_digest="f" * 64)

    # RED before the semantic hardening: the self-digested foreign receipt is
    # currently accepted and changes repair_attempts/receipt_digest.
    assert E.derive_final_report_evidence_delivery(
        report, bundle, repair_receipt_bytes=foreign
    ) == without_repair


def test_current_bundle_repair_diagnostic_is_preserved_without_reclassification():
    bundle, report = _bundle_and_report()
    without_repair = E.derive_final_report_evidence_delivery(report, bundle)
    current = E.derive_final_report_evidence_delivery(
        report,
        bundle,
        repair_receipt_bytes=_repair_receipt_bytes(
            repaired_bundle_digest=bundle["bundle_digest"]
        ),
    )

    assert current["repair_attempts"] == {"H-01": 1}
    assert current["receipt_digest"] != without_repair["receipt_digest"]
    for field in (
        "structurally_delivered",
        "semantically_complete",
        "delivery_state",
        "missing_semantic_fields",
        "evidence_limitations",
        "hidden_quality_debt_report_ids",
        "typed_manifest_markdown_parity",
        "markdown_semantic_parity",
    ):
        assert current[field] == without_repair[field]
