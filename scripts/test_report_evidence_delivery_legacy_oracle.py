"""Byte oracles captured from the authenticated pre-extraction finalizer."""
import hashlib
import json
from pathlib import Path

import pytest

import report_evidence_authority as evidence
from test_report_evidence_runtime_p1_k import _write_inputs


LEGACY_RECEIPT_SHA256 = {
    "complete_fields": "1158784df43746840e428420adbbda485ecaee5e92246cf2fd9726c3d5688b26",
    "limited_fields": "835b91c59f28cb5a850aa8185fdb47d06892cea4e852e1c76afe1022136bedbc",
    "crlf_invalid_repair": "d8bd7e02738d4370cd26771fd03c96aa85ee17f1f2ea17cf9e50b9afa0dd804f",
}


@pytest.mark.parametrize("case", ("complete_fields", "limited_fields", "crlf_invalid_repair"))
def test_legacy_delivery_receipt_byte_oracle(tmp_path: Path, case: str):
    kwargs = {"include_assessment": False}
    if case != "complete_fields":
        kwargs.update(impact="", recommendation="")
    _write_inputs(tmp_path, **kwargs)
    runtime = evidence.materialize_report_evidence_runtime(tmp_path)
    report = evidence.project_report_evidence_markdown(
        "### [H-01] Paired accounting state can diverge\n\n"
        "**Severity**: High\n**Verdict**: CONFIRMED\n"
        "**Location**: src/Module.sol:L10-L30\n\n"
        "**Description**:\nOne transition updates one accounting leg without its pair.\n",
        runtime["bundle"],
    ).encode("utf-8")
    if case == "crlf_invalid_repair":
        report = report.replace(b"\n", b"\r\n")
        (tmp_path / "report_evidence_repair_receipt.json").write_bytes(
            b'{"diagnostic":1,"diagnostic":2}\n'
        )
    report_path = tmp_path / "AUDIT_REPORT.md"
    report_path.write_bytes(report)
    receipt = evidence.finalize_report_evidence_delivery(
        tmp_path, report_path=report_path,
    )
    receipt_path = tmp_path / "report_evidence_quality_receipt.json"
    raw = receipt_path.read_bytes()
    assert json.loads(raw) == receipt
    assert receipt["report_sha256"] == hashlib.sha256(report).hexdigest()
    assert receipt["expected_report_ids"] == ["H-01"]
    assert receipt["delivered_report_ids"] == ["H-01"]
    assert receipt["unauthorized_proof_grade_report_ids"] == []
    assert receipt["repair_attempts"] == {}
    before = (raw, receipt_path.stat().st_ino, receipt_path.stat().st_mtime_ns)
    assert evidence.finalize_report_evidence_delivery(
        tmp_path, report_path=report_path, compare_only=True,
    ) == receipt
    assert (
        receipt_path.read_bytes(), receipt_path.stat().st_ino,
        receipt_path.stat().st_mtime_ns,
    ) == before
    assert hashlib.sha256(raw).hexdigest() == LEGACY_RECEIPT_SHA256[case]
    repair_path = tmp_path / "report_evidence_repair_receipt.json"
    derived = evidence.derive_final_report_evidence_delivery(
        report, runtime["bundle"],
        repair_receipt_bytes=(repair_path.read_bytes() if repair_path.exists() else None),
    )
    assert derived == receipt
    assert evidence._canonical_bytes(derived) + b"\n" == raw


def test_finalizer_rejects_stale_runtime_before_publishing(tmp_path: Path):
    _write_inputs(tmp_path, include_assessment=False)
    evidence.materialize_report_evidence_runtime(tmp_path)
    source = tmp_path / "verify_INV-001.md"
    source.write_bytes(source.read_bytes() + b"\nChanged evidence\n")
    report_path = tmp_path / "AUDIT_REPORT.md"
    report_path.write_bytes(b"# Audit\n")
    with pytest.raises(evidence.ReportEvidenceError):
        evidence.finalize_report_evidence_delivery(
            tmp_path, report_path=report_path,
        )
    assert not (tmp_path / "report_evidence_quality_receipt.json").exists()
