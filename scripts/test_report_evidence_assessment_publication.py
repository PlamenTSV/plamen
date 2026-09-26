"""Advisory report assessment must not preempt the typed receipt producer."""
from __future__ import annotations

import pytest

import artifact_ledger as A
import plamen_driver as D
import plamen_validators as V
import report_evidence_authority as E
from test_report_evidence_adversarial_review_p1_k import _config, _authenticated_projected_report
from test_report_evidence_runtime_p1_k import _write_inputs


RECEIPT = "report_evidence_quality_receipt.json"


def _seed(tmp_path):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _write_inputs(root, execution_tag="[STATIC-TRACE]")
    config = _config(project, root, run_id="quality-assessment-run")
    report = project / "AUDIT_REPORT.md"
    report.write_text(_authenticated_projected_report(root, config), encoding="utf-8")
    return project, root, report, config


def _snapshot(root):
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns,
        )
        for path in root.rglob("*") if path.is_file()
    }


@pytest.mark.parametrize("existing_receipt", [False, True])
def test_authenticated_assessment_is_read_only(tmp_path, existing_receipt):
    project, root, report, _config_value = _seed(tmp_path)
    if existing_receipt:
        (root / RECEIPT).write_bytes(b'{"forged":true}\n')
    before = _snapshot(project)

    assessment = E.assess_final_report_evidence_delivery(
        root, report_path=report, project_root=project, run_id=_config_value["_run_id"],
    )

    assert assessment["structurally_delivered"] is True
    assert assessment["expected_report_ids"] == ["H-01"]
    assert _snapshot(project) == before


def test_quality_gate_assesses_before_typed_finalizer_publishes(tmp_path):
    project, root, report, config = _seed(tmp_path)
    V._run_report_quality_gate(root, str(project), config=config)
    assert "typed_report_evidence_delivery" in (root / "report_quality.md").read_text()
    assert not (root / RECEIPT).exists()

    assert D._finalize_report_evidence_quality(root, config) == []

    ledger = A.read_artifact_ledger(root)
    binding = ledger["artifact_bindings"][f"scratchpad:{RECEIPT}"]
    assert binding["owner_key"] == "sc/thorough/evm/claude/report_floor/evidence_quality"
    assert binding["status"] == "ACTIVE"
    unit = ledger["work_units"][binding["owner_key"]]
    assert unit["output_prestates"][f"scratchpad:{RECEIPT}"]["status"] == "ABSENT"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert E.finalize_report_evidence_delivery(
        root, report_path=report, compare_only=True,
        project_root=project, run_id=config["_run_id"],
    ) == E.assess_final_report_evidence_delivery(
        root, report_path=report, project_root=project, run_id=config["_run_id"],
    )


def test_gate_preserves_forged_receipt_and_finalizer_rejects_unowned_output(tmp_path):
    project, root, _report, config = _seed(tmp_path)
    receipt = root / RECEIPT
    receipt.write_bytes(b'{"forged":true}\n')
    before = _snapshot(root)[RECEIPT]

    V._run_report_quality_gate(root, str(project), config=config)
    assert _snapshot(root)[RECEIPT] == before
    issues = D._finalize_report_evidence_quality(root, config)

    assert any("UNOWNED_EXISTING_OUTPUT" in issue for issue in issues)
    assert _snapshot(root)[RECEIPT] == before
    assert f"scratchpad:{RECEIPT}" not in A.read_artifact_ledger(root)["artifact_bindings"]


@pytest.mark.parametrize("failure", ["runtime_drift", "missing_report"])
def test_assessment_rejects_invalid_inputs_without_publication(tmp_path, failure):
    project, root, report, _config_value = _seed(tmp_path)
    if failure == "runtime_drift":
        source = root / "verify_INV-001.md"
        source.write_bytes(source.read_bytes() + b"\nChanged source.\n")
    else:
        report.unlink()
    before = _snapshot(project)

    with pytest.raises(E.ReportEvidenceError):
        E.assess_final_report_evidence_delivery(
            root, report_path=report, project_root=project, run_id=_config_value["_run_id"],
        )

    assert _snapshot(project) == before
