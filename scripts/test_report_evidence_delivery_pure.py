"""Pure-delivery tests; authenticated byte parity is tested separately."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

import report_evidence_authority as E
from test_report_evidence_quality_p1_k import _record


def _bundle_and_report():
    record = _record(
        evidence_authenticity="CODE_TRACE", proof_scope="MECHANISM_ONLY",
        capabilities=["MECHANISM"],
    )
    bundle = E.build_report_evidence_bundle([record], expected_report_ids=["H-01"])
    markdown = f"### [H-01] {record['title']}\n\n"
    return bundle, E.project_report_evidence_markdown(markdown, bundle).encode()


def test_delivery_derivation_has_no_path_io_and_preserves_inputs(monkeypatch):
    bundle, raw = _bundle_and_report()
    before = deepcopy(bundle)

    def forbid(*_args, **_kwargs):
        raise AssertionError("pure delivery derivation reopened a path")

    with monkeypatch.context() as guard:
        for method in ("open", "read_bytes", "read_text", "write_bytes", "write_text"):
            guard.setattr(Path, method, forbid)
        receipt = E.derive_final_report_evidence_delivery(raw, bundle)
        assert E.derive_final_report_evidence_delivery(raw, bundle) == receipt
    assert bundle == before
    assert receipt["report_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["record_markdown_parity"] == {"H-01": True}
    assert receipt["unauthorized_proof_grade_report_ids"] == []


def test_pure_delivery_rejects_proof_widening_without_hiding_the_record():
    bundle, raw = _bundle_and_report()
    widened = raw + b"\nThe PoC proves harm.\n"
    receipt = E.derive_final_report_evidence_delivery(widened, bundle)
    assert receipt["expected_report_ids"] == ["H-01"]
    assert receipt["delivered_report_ids"] == ["H-01"]
    assert receipt["unauthorized_proof_grade_report_ids"] == ["H-01"]
    assert receipt["record_semantic_parity"] == {"H-01": False}
    assert receipt["delivery_state"] == "STRUCTURAL_DELIVERY_INCOMPLETE"


def test_pure_delivery_preserves_raw_hash_but_normalizes_text_newlines():
    bundle, lf = _bundle_and_report()
    crlf = lf.replace(b"\n", b"\r\n")
    first = E.derive_final_report_evidence_delivery(lf, bundle)
    second = E.derive_final_report_evidence_delivery(crlf, bundle)
    assert first["report_sha256"] != second["report_sha256"]
    assert second["report_sha256"] == hashlib.sha256(crlf).hexdigest()
    for key in ("record_markdown_parity", "record_semantic_parity", "delivery_state"):
        assert first[key] == second[key]


@pytest.mark.parametrize("repair", [b"{}", b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff"])
def test_invalid_repair_bytes_do_not_create_repair_attempts(repair):
    bundle, raw = _bundle_and_report()
    assert E.derive_final_report_evidence_delivery(
        raw, bundle, repair_receipt_bytes=repair
    ) == E.derive_final_report_evidence_delivery(raw, bundle)


def test_valid_repair_diagnostic_counts_are_preserved():
    bundle, raw = _bundle_and_report()
    repair = {
        "schema_version": E.REPORT_EVIDENCE_REPAIR_RECEIPT_SCHEMA,
        "request_digest": "a" * 64, "response_digest": "b" * 64,
        "baseline_bundle_digest": bundle["bundle_digest"],
        "repaired_bundle_digest": bundle["bundle_digest"],
        "repair_attempts": {"H-01": 1}, "receipt_digest": "",
    }
    repair["receipt_digest"] = E._digest(repair)
    receipt = E.derive_final_report_evidence_delivery(
        raw, bundle, repair_receipt_bytes=json.dumps(repair).encode()
    )
    assert receipt["repair_attempts"] == {"H-01": 1}
    # This is codec/diagnostic behavior, not proof of a committed repair.


def test_pure_delivery_preserves_exact_empty_bundle():
    bundle = E.build_report_evidence_bundle([], expected_report_ids=[])
    receipt = E.derive_final_report_evidence_delivery(b"# Audit\n", bundle)
    assert receipt["expected_report_ids"] == []
    assert receipt["delivered_report_ids"] == []
    assert receipt["structurally_delivered"] is True


def test_pure_delivery_rejects_malformed_bundle_and_nonbytes():
    with pytest.raises(E.ReportEvidenceError):
        E.derive_final_report_evidence_delivery(b"# Audit\n", {})
    bundle = E.build_report_evidence_bundle([], expected_report_ids=[])
    with pytest.raises(TypeError, match="exact report bytes"):
        E.derive_final_report_evidence_delivery("# Audit", bundle)
    with pytest.raises(TypeError, match="exact bytes"):
        E.derive_final_report_evidence_delivery(b"# Audit", bundle, repair_receipt_bytes={})
