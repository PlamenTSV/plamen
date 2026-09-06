"""P1-K live report-evidence boundary acceptance fixtures.

The report index/manifests remain compatibility artifacts.  These fixtures
require a typed, digest-bound authority before a body writer can render prose,
and a second reconciliation after assembly.  Semantic debt is deliverable only
when it is visible to the client; it is never silently treated as completion.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from evidence_capabilities import issue_executed_poc_scope_assessment
from execution_scope_runtime import materialize_execution_scope_assessments
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from report_evidence_authority import (
    ReportEvidenceError,
    apply_report_evidence_repair_response,
    finalize_report_evidence_delivery,
    materialize_report_evidence_runtime,
    prepare_report_evidence_repair_apply_plan,
    project_report_evidence_markdown,
    validate_report_evidence_runtime,
)
import report_evidence_authority as report_authority
from test_execution_proof_scope_p1_e import _record as _execution_record
from test_execution_scope_runtime_p1_e import (
    _bound_execution,
    _explicit_scope_rewind,
    _rich_record,
)
import plamen_mechanical as mechanical
import plamen_validators as validators
import plamen_driver as driver


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_inputs(
    scratchpad: Path,
    *,
    impact: str = "State divergence can expose accounted value to incorrect settlement.",
    recommendation: str = "Update both accounting legs atomically and assert the relation.",
    include_assessment: bool = False,
    execution_tag: str = "[POC-PASS]",
) -> None:
    (scratchpad / "body_manifests").mkdir(parents=True)
    (scratchpad / "report_records.json").write_text(
        json.dumps(
            {
                "schema_version": "plamen.report_records.v1",
                "source": "report_index.md",
                "active": [
                    {
                        "report_id": "H-01",
                        "finding_id": "INV-001",
                        "severity": "High",
                        "title": "Paired accounting state can diverge",
                        "location": "src/Module.sol:L10-L30",
                        "evidence": execution_tag,
                        "verdict": "CONFIRMED",
                        "absorbed_finding_ids": [],
                        "report_blocked": False,
                    }
                ],
                "excluded": [],
                "consolidation_map": [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = {
        "shard": "report_critical_high",
        "findings": [
            {
                "report_id": "H-01",
                "finding_id": "INV-001",
                "severity": "High",
                "title": "Paired accounting state can diverge",
                "location": "src/Module.sol:L10-L30",
                "evidence_tag": execution_tag,
                "verify_file": "verify_INV-001.md",
                "verify_files": ["verify_INV-001.md"],
                "verify_statuses": [
                    {
                        "file": "verify_INV-001.md",
                        "exists": True,
                        "evidence_missing": False,
                    }
                ],
                "description": "One transition updates the credited amount without its paired liability.",
                "poc_result": "The harness executed the encoded transition.",
                "recommendation": recommendation,
                "report_blocked": False,
            }
        ],
    }
    (scratchpad / "body_manifests" / "report_critical_high.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    verify = (
        "**Verdict**: CONFIRMED\n"
        "**Location**: src/Module.sol:L10-L30\n"
        f"**Evidence Tag**: {execution_tag}\n\n"
        "### Finding Summary\n"
        "One transition updates the credited amount without updating its paired liability.\n\n"
        "### Preconditions\n"
        "- The affected transition is reachable.\n"
        "- A non-zero amount is processed.\n\n"
        "### Impact\n"
        f"{impact}\n\n"
        "### Code Trace\n"
        "The cited transition writes one state leg and leaves the paired leg unchanged.\n\n"
        "### PoC Result\n"
        "The encoded transition executed, but prose alone does not authenticate its oracle scope.\n\n"
        "### Recommendation\n"
        f"{recommendation}\n"
    )
    (scratchpad / "verify_INV-001.md").write_text(verify, encoding="utf-8")
    if include_assessment:
        assessment = issue_executed_poc_scope_assessment(
            _execution_record(
                candidate_id="INV-001", constituent_ids=["INV-001"]
            )
        )
        (scratchpad / "verify_INV-001.execution_scope_assessment.json").write_text(
            json.dumps(assessment, indent=2) + "\n", encoding="utf-8"
        )


def test_runtime_is_materialized_before_body_render_and_dual_writes_manifests(
    tmp_path: Path,
):
    _write_inputs(tmp_path)
    result = materialize_report_evidence_runtime(tmp_path)

    assert result["bundle"]["expected_report_ids"] == ["H-01"]
    record = result["bundle"]["records"][0]
    assert record["mechanism"].startswith("One transition updates")
    assert record["preconditions"] == [
        "The affected transition is reachable.",
        "A non-zero amount is processed.",
    ]
    assert record["impact"].startswith("State divergence")
    assert record["affected_locations"] == ["src/Module.sol:L10-L30"]
    assert record["recommendation"].startswith("Update both accounting")
    assert (tmp_path / "report_evidence_records.json").exists()
    assert (tmp_path / "report_evidence_projection.md").exists()
    typed_manifest = json.loads(
        (tmp_path / "report_evidence_manifests" / "report_critical_high.json")
        .read_text(encoding="utf-8")
    )
    assert typed_manifest["findings"][0]["report_evidence_record_digest"] == record[
        "record_digest"
    ]
    assert typed_manifest["findings"][0]["report_evidence"] == record
    assert validate_report_evidence_runtime(tmp_path)["bundle"] == result["bundle"]


def test_bare_execution_and_confirmed_tags_never_mint_proof_grade(tmp_path: Path):
    _write_inputs(tmp_path, include_assessment=False, execution_tag="[POC-PASS] [CONFIRMED]")
    record = materialize_report_evidence_runtime(tmp_path)["bundle"]["records"][0]

    assert record["presentation_assurance"] == "CONFIRMED_MECHANISM"
    assert record["evidence_authenticity"] == "CODE_TRACE"
    assert "MISSING_TYPED_EXECUTION_EVIDENCE" in record["limitations"]


def test_standalone_p1e_shape_cannot_render_proof_grade_without_live_runtime(
    tmp_path: Path,
):
    _write_inputs(tmp_path, include_assessment=True)
    record = materialize_report_evidence_runtime(tmp_path)["bundle"]["records"][0]

    assert record["presentation_assurance"] != "PROOF_GRADE_HARM"
    assert record["evidence_authenticity"] == "CODE_TRACE"
    assert "INVALID_TYPED_EXECUTION_EVIDENCE" in record["limitations"]


def test_only_live_candidate_bound_p1e_harm_scope_can_render_proof_grade(
    tmp_path: Path,
):
    _write_inputs(tmp_path)
    project = tmp_path / "project"
    _bound_execution(tmp_path, project, candidate_id="INV-001")
    materialize_execution_scope_assessments(tmp_path, build_root=project)
    rich = _rich_record(tmp_path, "INV-001")
    _explicit_scope_rewind(tmp_path, "INV-001")
    (tmp_path / "verify_INV-001.execution_scope_evidence.json").write_text(
        json.dumps(rich, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(tmp_path, build_root=project)

    result = materialize_report_evidence_runtime(tmp_path)
    request = result["repair_request"]
    item = request["items"][0]
    delta = {
        field: (
            ["The encoded transition is reachable with a non-zero amount."]
            if field == "preconditions"
            else "A reachable inconsistent transition can misallocate value at settlement."
            if field == "impact"
            else "Update the paired values atomically and assert the relation."
            if field == "recommendation"
            else "The encoded transition leaves paired accounting state inconsistent."
        )
        for field in item["missing_fields"]
    }
    repaired = apply_report_evidence_repair_response(
        tmp_path,
        {
            "schema_version": "plamen.report_evidence_repair_response.v1",
            "request_digest": request["request_digest"],
            "items": [{
                "report_id": item["report_id"],
                "record_digest": item["record_digest"],
                "delta": delta,
            }],
        },
    )
    record = repaired["bundle"]["records"][0]
    assert record["presentation_assurance"] == "PROOF_GRADE_HARM"
    assert record["evidence_authenticity"] == "AUTHENTICATED_EXECUTION"
    assert {"EXECUTION", "HARM"}.issubset(record["capabilities"])


def test_live_p1e_underlying_drift_revokes_report_runtime_authority(
    tmp_path: Path,
):
    _write_inputs(tmp_path)
    project = tmp_path / "project"
    _row, oracle = _bound_execution(tmp_path, project, candidate_id="INV-001")
    materialize_execution_scope_assessments(tmp_path, build_root=project)
    rich = _rich_record(tmp_path, "INV-001")
    _explicit_scope_rewind(tmp_path, "INV-001")
    (tmp_path / "verify_INV-001.execution_scope_evidence.json").write_text(
        json.dumps(rich, indent=2), encoding="utf-8"
    )
    materialize_execution_scope_assessments(tmp_path, build_root=project)
    materialize_report_evidence_runtime(tmp_path)

    oracle.write_text("changed after execution\n", encoding="utf-8")
    with pytest.raises(ReportEvidenceError, match="no longer validates"):
        validate_report_evidence_runtime(tmp_path)


def test_consolidated_denominator_keeps_primary_and_absorbed_candidates(
    tmp_path: Path,
):
    _write_inputs(tmp_path, include_assessment=True)
    records_path = tmp_path / "report_records.json"
    records = json.loads(records_path.read_text(encoding="utf-8"))
    records["active"][0]["absorbed_finding_ids"] = ["INV-002"]
    records_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "body_manifests" / "report_critical_high.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["findings"][0]["absorbed_finding_ids"] = ["INV-002"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    record = materialize_report_evidence_runtime(tmp_path)["bundle"]["records"][0]
    assert record["candidate_ids"] == ["INV-001", "INV-002"]
    assert record["presentation_assurance"] != "PROOF_GRADE_HARM"
    assert "MULTI_CANDIDATE_ASSESSMENT_COVERAGE_PARTIAL" in record["limitations"]
    assert "MULTI_CANDIDATE_PROOF_SCOPE_UNRECONCILED" in record["limitations"]
    assert record["evidence_result"] == "INCONCLUSIVE"
    assert record["proof_scope"] == "NONE"
    assert "HARM" not in record["capabilities"]


def test_conflicting_candidate_identity_dual_write_is_rejected_before_union(
    tmp_path: Path,
):
    _write_inputs(tmp_path, include_assessment=False)
    records_path = tmp_path / "report_records.json"
    records = json.loads(records_path.read_text(encoding="utf-8"))
    records["active"][0]["candidate_ids"] = ["INV-002"]
    records["active"][0]["absorbed_finding_ids"] = ["INV-003"]
    records_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "body_manifests" / "report_critical_high.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["findings"][0]["finding_id"] = "INV-004"
    manifest["findings"][0]["candidate_ids"] = ["INV-005"]
    manifest["findings"][0]["absorbed_finding_ids"] = ["INV-006"]
    manifest["findings"][0]["verify_files"].append("verify_INV-007.md")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(ReportEvidenceError, match="dual-write conflict"):
        materialize_report_evidence_runtime(tmp_path)


def test_all_constituent_harm_assessments_still_need_compound_or_equivalence_scope(
    tmp_path: Path,
):
    _write_inputs(tmp_path, include_assessment=True)
    records_path = tmp_path / "report_records.json"
    records = json.loads(records_path.read_text(encoding="utf-8"))
    records["active"][0]["absorbed_finding_ids"] = ["INV-002"]
    records_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "body_manifests" / "report_critical_high.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["findings"][0]["verify_files"].append("verify_INV-002.md")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (tmp_path / "verify_INV-002.md").write_text(
        (tmp_path / "verify_INV-001.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    assessment = issue_executed_poc_scope_assessment(
        _execution_record(candidate_id="INV-002", constituent_ids=["INV-002"])
    )
    (tmp_path / "verify_INV-002.execution_scope_assessment.json").write_text(
        json.dumps(assessment, indent=2) + "\n", encoding="utf-8"
    )

    record = materialize_report_evidence_runtime(tmp_path)["bundle"]["records"][0]
    assert "MULTI_CANDIDATE_ASSESSMENT_COVERAGE_PARTIAL" in record["limitations"]
    assert "MULTI_CANDIDATE_PROOF_SCOPE_UNRECONCILED" in record["limitations"]
    assert record["presentation_assurance"] != "PROOF_GRADE_HARM"
    assert record["proof_scope"] == "NONE"
    assert "HARM" not in record["capabilities"]


def test_exact_repair_request_and_single_bounded_response(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    result = materialize_report_evidence_runtime(tmp_path)
    request = result["repair_request"]
    item = request["items"][0]
    assert item["missing_fields"] == ["impact", "recommendation"]
    assert item["attempt"] == 1

    response = {
        "schema_version": "plamen.report_evidence_repair_response.v1",
        "request_digest": request["request_digest"],
        "items": [
            {
                "report_id": "H-01",
                "record_digest": item["record_digest"],
                "delta": {
                    "impact": "The inconsistent state can misallocate value at settlement.",
                    "recommendation": "Update the paired values atomically and assert equality.",
                },
            }
        ],
    }
    repaired = apply_report_evidence_repair_response(tmp_path, response)
    assert repaired["bundle"]["records"][0]["impact"].startswith("The inconsistent")
    assert repaired["repair_attempts"] == {"H-01": 1}
    assert repaired["repair_request"]["items"] == []

    with pytest.raises(ReportEvidenceError, match="already consumed"):
        apply_report_evidence_repair_response(tmp_path, response)


def test_failed_repair_projects_client_visible_limitation_idempotently(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    result = materialize_report_evidence_runtime(tmp_path)
    body = """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.
"""
    once = project_report_evidence_markdown(body, result["bundle"])
    twice = project_report_evidence_markdown(once, result["bundle"])

    assert once == twice
    assert (
        "**Evidence assurance**: Confirmed mechanism; harm proof not established"
        in once
    )
    assert "**Evidence and report limitation**:" in once
    assert "impact and recommendation" in once.lower()
    assert "H-01" in once


def test_post_writer_mechanical_projection_preserves_section_and_closes_parity(
    tmp_path: Path,
):
    _write_inputs(tmp_path, impact="", recommendation="")
    materialize_report_evidence_runtime(tmp_path)
    body_path = tmp_path / "report_critical_high.md"
    body_path.write_text(
        """# Critical and High Findings

### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.
""",
        encoding="utf-8",
    )

    assert mechanical._repair_report_body_from_manifest(
        tmp_path, "report_body_writer_critical_high"
    ) >= 1
    projected = body_path.read_text(encoding="utf-8")
    assert "### [H-01]" in projected
    assert "Evidence and report limitation" in projected
    content_debt: list[str] = []
    assert validators._validate_tier_body_against_manifest(
        tmp_path, "report_critical_high", content_debt
    ) == []


def test_final_receipt_reconciles_typed_manifest_and_markdown(tmp_path: Path):
    _write_inputs(tmp_path, impact="", recommendation="")
    result = materialize_report_evidence_runtime(tmp_path)
    body = project_report_evidence_markdown(
        """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.
""",
        result["bundle"],
    )
    (tmp_path / "AUDIT_REPORT.md").write_text(body, encoding="utf-8")

    receipt = finalize_report_evidence_delivery(
        tmp_path, report_path=tmp_path / "AUDIT_REPORT.md"
    )
    assert receipt["structurally_delivered"] is True
    assert receipt["semantically_complete"] is False
    assert receipt["typed_manifest_markdown_parity"] is True
    assert receipt["delivery_state"] == "DEGRADED_DELIVERY"
    assert (tmp_path / "report_evidence_quality_receipt.json").exists()


def test_projection_stops_before_the_next_report_level_section(tmp_path: Path):
    """The final finding must not absorb later report sections or appendices."""

    result = materialize_report_evidence_runtime(_write_inputs(tmp_path) or tmp_path)
    report = """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
One transition updates one accounting leg without its pair.

## Priority Remediation Order

1. Repair the accounting transition.

## Appendix A

Retained review material.
"""
    projected = project_report_evidence_markdown(report, result["bundle"])

    marker = "<!-- PLAMEN_REPORT_EVIDENCE rid=H-01"
    assert projected.index(marker) < projected.index("## Priority Remediation Order")
    assert projected.count("## Priority Remediation Order") == 1
    assert projected.endswith("Retained review material.\n")


def test_typed_manifest_tamper_is_detected_without_reblessing(tmp_path: Path):
    _write_inputs(tmp_path)
    materialize_report_evidence_runtime(tmp_path)
    path = tmp_path / "report_evidence_manifests" / "report_critical_high.json"
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["findings"][0]["report_evidence"]["impact"] = "rewritten"
    path.write_text(json.dumps(tampered, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(ReportEvidenceError, match="non-canonical"):
        validate_report_evidence_runtime(tmp_path)
    assert "rewritten" in path.read_text(encoding="utf-8")


def test_bound_verifier_source_drift_invalidates_runtime(tmp_path: Path):
    _write_inputs(tmp_path)
    materialize_report_evidence_runtime(tmp_path)
    verify = tmp_path / "verify_INV-001.md"
    verify.write_text(
        verify.read_text(encoding="utf-8") + "\nlate mutation\n",
        encoding="utf-8",
    )

    with pytest.raises(ReportEvidenceError, match="source digest drift"):
        validate_report_evidence_runtime(tmp_path)


def test_limited_scope_section_cannot_ship_widened_proof_language(tmp_path: Path):
    _write_inputs(tmp_path, include_assessment=False)
    result = materialize_report_evidence_runtime(tmp_path)
    body = project_report_evidence_markdown(
        """### [H-01] Paired accounting state can diverge

**Severity**: High
**Verdict**: CONFIRMED
**Location**: src/Module.sol:L10-L30

**Description**:
The PoC proves the harm and exploitability described by this finding.
""",
        result["bundle"],
    )
    (tmp_path / "AUDIT_REPORT.md").write_text(body, encoding="utf-8")

    receipt = finalize_report_evidence_delivery(
        tmp_path, report_path=tmp_path / "AUDIT_REPORT.md"
    )
    assert receipt["unauthorized_proof_grade_report_ids"] == ["H-01"]
    assert receipt["delivery_state"] == "STRUCTURAL_DELIVERY_INCOMPLETE"


def test_duplicate_title_location_with_distinct_mechanism_is_not_fragmentation_loss(
    tmp_path: Path,
):
    _write_inputs(tmp_path)
    data = json.loads((tmp_path / "report_records.json").read_text(encoding="utf-8"))
    second = dict(data["active"][0])
    second.update({"report_id": "H-02", "finding_id": "INV-002"})
    data["active"].append(second)
    (tmp_path / "report_records.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8"
    )
    manifest_path = tmp_path / "body_manifests" / "report_critical_high.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    second_row = dict(manifest["findings"][0])
    second_row.update(
        {
            "report_id": "H-02",
            "finding_id": "INV-002",
            "verify_file": "verify_INV-002.md",
            "verify_files": ["verify_INV-002.md"],
        }
    )
    manifest["findings"].append(second_row)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    second_verify = (tmp_path / "verify_INV-001.md").read_text(encoding="utf-8").replace(
        "One transition updates the credited amount without updating its paired liability.",
        "A distinct finalization transition consumes the paired state twice.",
    )
    (tmp_path / "verify_INV-002.md").write_text(second_verify, encoding="utf-8")

    bundle = materialize_report_evidence_runtime(tmp_path)["bundle"]
    assert len(bundle["records"]) == 2
    assert bundle["records"][0]["mechanism"] != bundle["records"][1]["mechanism"]


def test_phase_io_contracts_own_pre_render_and_final_quality_sidecars():
    pre = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_body",
        work_unit_id="evidence_pre",
        exact_outputs=(
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_projection.md",
            "report_evidence_manifests/report_critical_high.json",
        ),
        exact_inputs=(
            "report_records.json",
            "body_manifests/report_critical_high.json",
            "verify_INV-001.md",
        ),
    )
    assert pre.model_invoked is False
    assert {item.schema_version for item in pre.outputs} >= {
        "plamen.report_evidence_bundle.v1",
        "plamen.report_evidence_repair_request.v1",
    }

    arm = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_body",
        work_unit_id="evidence_repair.arm",
        exact_outputs=(
            "report_evidence_repair_attempt.json",
            "_prompt_report_evidence_repair.md",
        ),
        exact_inputs=(
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
        ),
    )
    assert arm.model_invoked is False

    repair_model = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_body",
        work_unit_id="evidence_repair.model",
        exact_outputs=("report_evidence_repair_response.json",),
        exact_inputs=(
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_repair_attempt.json",
            "_prompt_report_evidence_repair.md",
            "verify_INV-001.md",
        ),
    )
    assert repair_model.model_invoked is True
    assert repair_model.outputs[0].writer == "MODEL"

    prepare = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_body",
        work_unit_id="evidence_repair.prepare",
        exact_outputs=("report_evidence_repair_apply_plan.json",),
        exact_inputs=(
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_repair_response.json",
        ),
    )
    assert prepare.model_invoked is False

    repair_apply = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_body",
        work_unit_id="evidence_repair.apply",
        exact_outputs=(
            "report_evidence_records.json",
            "report_evidence_repair_request.json",
            "report_evidence_projection.md",
            "report_evidence_repair_receipt.json",
            "report_evidence_manifests/report_critical_high.json",
        ),
        exact_inputs=(
            "report_evidence_repair_apply_plan.json",
            "report_evidence_repair_response.json",
            "body_manifests/report_critical_high.json",
        ),
    )
    assert repair_apply.model_invoked is False
    assert all(item.writer == "DRIVER" for item in repair_apply.outputs)
    assert repair_apply.bounded_lookup_inputs == ()

    final = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_floor",
        work_unit_id="evidence_quality",
        exact_outputs=("report_evidence_quality_receipt.json",),
        exact_inputs=(
            "report_evidence_records.json",
            "report_evidence_projection.md",
            "report_evidence_manifests/report_critical_high.json",
        ),
    )
    assert final.model_invoked is False
    assert final.outputs[0].minimum_gate == "TYPED_MANIFEST_MARKDOWN_DELIVERY_PARITY"


def test_driver_materializes_p1k_before_first_body_writer():
    source = Path(__file__).with_name("plamen_driver.py").read_text(encoding="utf-8")
    pre_hook = source.index("_ensure_report_evidence_before_body_writer(", source.index("# Phase E11 follow-up #1"))
    empty_skip = source.index("_maybe_skip_empty_body_writer(", pre_hook)
    assert pre_hook < empty_skip
    helper = source.index("def _materialize_report_evidence_pre_body(")
    assert source.index("materialize_report_evidence_runtime(", helper) < pre_hook


def test_live_body_writer_prompt_requires_typed_manifest_and_cannot_ignore_it(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    (scratchpad / "body_manifests").mkdir(parents=True)
    (scratchpad / "report_evidence_manifests").mkdir()
    for directory in ("body_manifests", "report_evidence_manifests"):
        (scratchpad / directory / "report_critical_high.json").write_text(
            '{"findings": []}\n', encoding="utf-8"
        )
    v1 = tmp_path / "plamen.md"
    v1.write_text("## Step 6b: Tier Writers\n\nlegacy\n", encoding="utf-8")
    phase = next(
        item for item in driver.SC_PHASES
        if item.name == "report_body_writer_critical_high"
    )
    prompt = driver.build_phase_prompt(v1, phase, {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "proven_only": False,
    })
    assert "report_evidence_manifests/report_critical_high.json" in prompt
    assert "legacy manifest, its matching typed evidence manifest" in prompt
    assert "Ignore every other" in prompt
    assert "scratchpad artifact for this phase" in prompt
    assert "Read only the manifest and the evidence files" not in prompt


def _driver_config(project: Path, scratchpad: Path) -> dict[str, object]:
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "cli_backend": "claude",
        "_run_id": "p1-k-live-driver-test",
    }


def _body_writer_phase(driver_module=driver):
    return next(
        item for item in driver_module.SC_PHASES
        if item.name == "report_body_writer_critical_high"
    )


def _bind_owned_report_sources(
    driver_module,
    project: Path,
    scratchpad: Path,
    config: dict[str, object],
    *,
    finding_id: str,
) -> None:
    # R10 is now a mandatory report-input authority, not an optional sidecar.
    # The caller supplies the production-authenticated R10 fixture. Materialize
    # and commit the exact DRIVER prework transaction before arming the model,
    # which establishes the ephemeral consumer-ready state only after replaying
    # both the R10 producer and the prework PhaseIO receipt.
    ready, prework_issues = driver_module._run_report_index_prework_transaction(
        scratchpad, config
    )
    assert ready is True
    assert prework_issues == []
    assert driver_module._r10_report_consumer_ready_issues(
        scratchpad, config
    ) == []

    report_phase = next(
        item for item in driver_module.SC_PHASES
        if item.name == "report_index"
    )
    assert driver_module._bind_typed_model_phase_inputs(
        report_phase, scratchpad, config
    ) == []
    (scratchpad / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Summary Counts\n\n"
        "| Severity | Count |\n"
        "|---|---|\n"
        "| Critical | 0 |\n"
        "| High | 1 |\n"
        "| Medium | 0 |\n"
        "| Low | 0 |\n"
        "| Informational | 0 |\n"
        "| Total | 1 |\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal Hypothesis |\n"
        "|---|---|---|---|---|---|---|\n"
        "| H-01 | Paired accounting state can diverge | High | "
        f"src/lib.rs:L42 | CONTESTED | - | {finding_id} |\n\n"
        "## Excluded Findings\n\n"
        "| Source ID | Reason |\n"
        "|---|---|\n",
        encoding="utf-8",
    )
    (scratchpad / "report_coverage.md").write_text(
        "# Report Coverage\n\n"
        "| Source Artifact | Candidate ID | Disposition |\n"
        "|---|---|---|\n"
        f"| verification_queue.md | {finding_id} | PROMOTED H-01 |\n",
        encoding="utf-8",
    )
    _model, model_issues = driver_module._record_report_index_model_preimage(
        report_phase, scratchpad, config
    )
    assert model_issues == []

    # This fixture targets the report-evidence/body boundary, not report-index
    # canonicalization (covered by its own suite). Publish the exact two
    # upstream report products under the *real* report_index/routing PhaseIO
    # identity so ownership validation exercises the same producer contract
    # as a live run without fabricating a verifier or bypassing R10 readiness.
    records = {
        "schema_version": "plamen.report_records.v1",
        "source": "report_index.md",
        "active": [{
            "report_id": "H-01",
            "finding_id": finding_id,
            "severity": "High",
            "title": "Paired accounting state can diverge",
            "location": "src/lib.rs:L42",
            "evidence": "[STATIC-TRACE]",
            "verdict": "CONTESTED",
            "absorbed_finding_ids": [],
            "report_blocked": False,
        }],
        "excluded": [],
        "consolidation_map": [],
    }
    body_manifest = {
        "shard": "report_critical_high",
        "findings": [{
            "report_id": "H-01",
            "finding_id": finding_id,
            "severity": "High",
            "title": "Paired accounting state can diverge",
            "location": "src/lib.rs:L42",
            "evidence_tag": "[STATIC-TRACE]",
            "verify_file": f"verify_{finding_id}.md",
            "verify_files": [f"verify_{finding_id}.md"],
            "verify_statuses": [{
                "file": f"verify_{finding_id}.md",
                "exists": True,
                "evidence_missing": False,
            }],
            "description": (
                "One transition updates credited state without its paired "
                "liability."
            ),
            "poc_result": "Independent verification remains contested.",
            "recommendation": (
                "Update both accounting legs atomically and assert the relation."
            ),
            "report_blocked": False,
        }],
    }
    outputs = (
        "report_records.json",
        "body_manifests/report_critical_high.json",
    )
    contract = resolve_phase_io_contract(
        pipeline=str(config["pipeline"]),
        mode=str(config["mode"]),
        ecosystem=str(config["language"]),
        backend=str(config["cli_backend"]),
        phase="report_index",
        work_unit_id="routing",
        exact_inputs=(),
        exact_outputs=outputs,
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
    record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )
    (scratchpad / "body_manifests").mkdir(exist_ok=True)
    for relative, payload in (
        (outputs[0], records),
        (outputs[1], body_manifest),
    ):
        (scratchpad / relative).write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=str(config["_run_id"]),
        actor="DRIVER",
    )


def test_live_prebody_and_body_writer_bind_exact_owned_source_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from test_r10_demotion_gate import (
        _authenticated_r10_report_prework_fixture,
    )

    project = tmp_path / "project"
    project.mkdir()
    _validator, current_driver, scratchpad, config, _contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            project,
            monkeypatch,
            fired=False,
            backend="codex",
        )
    )
    _bind_owned_report_sources(
        current_driver,
        project,
        scratchpad,
        config,
        finding_id="H-993",
    )

    body_phase = _body_writer_phase(current_driver)
    runtime, issues = current_driver._materialize_report_evidence_pre_body(
        body_phase, config, scratchpad
    )
    assert issues == [], issues
    assert runtime is not None
    assert current_driver._bind_typed_model_phase_inputs(
        body_phase, scratchpad, config
    ) == []

    ledger = read_artifact_ledger(scratchpad)
    key = (
        "sc/core/evm/codex/report_body/"
        "model.report_critical_high"
    )
    bound = ledger["work_units"][key]["input_bindings"]
    assert set(bound) == {
        "scratchpad:body_manifests/report_critical_high.json",
        "scratchpad:report_evidence_manifests/report_critical_high.json",
        "scratchpad:verify_H-993.md",
    }


def _repair_response_for_active_request(scratchpad: Path) -> dict[str, object]:
    request = json.loads(
        (scratchpad / "report_evidence_repair_request.json").read_text(
            encoding="utf-8"
        )
    )
    item = request["items"][0]
    values = {
        "mechanism": "The reachable transition leaves paired accounting state inconsistent.",
        "preconditions": ["The affected transition is reachable."],
        "impact": "A bounded accounting inconsistency can misallocate value at settlement.",
        "recommendation": "Update the paired values atomically and assert the relation.",
    }
    return {
        "schema_version": "plamen.report_evidence_repair_response.v1",
        "request_digest": request["request_digest"],
        "items": [{
            "report_id": item["report_id"],
            "record_digest": item["record_digest"],
            "delta": {
                field: values[field]
                for field in item["missing_fields"]
            },
        }],
    }


def test_live_driver_runs_exactly_one_claude_repair_and_resumes_without_relaunch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, impact="")
    launches: list[str] = []

    def _worker(**_kwargs):
        launches.append("claude")
        response = _repair_response_for_active_request(scratchpad)
        (scratchpad / "report_evidence_repair_response.json").write_text(
            json.dumps(response, sort_keys=True), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(
        driver, "_run_one_claude_headless_breadth_worker", _worker
    )
    phase = _body_writer_phase()
    config = _driver_config(project, scratchpad)

    assert driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    ) == []
    assert launches == ["claude"]
    assert (scratchpad / "report_evidence_repair_receipt.json").is_file()
    assert json.loads(
        (scratchpad / "report_evidence_repair_request.json").read_text(
            encoding="utf-8"
        )
    )["items"] == []
    repaired = validate_report_evidence_runtime(scratchpad)["bundle"]["records"][0]
    assert repaired["impact"].startswith("A bounded accounting inconsistency")
    assert repaired["presentation_assurance"] != "PROOF_GRADE_HARM"

    # Exact resume consumes the committed transaction and never re-launches.
    assert driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    ) == []
    assert launches == ["claude"]


def test_live_driver_armed_timeout_is_visible_and_never_relaunched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, recommendation="")
    launches: list[str] = []

    def _timeout(**_kwargs):
        launches.append("claude")
        return 1

    monkeypatch.setattr(
        driver, "_run_one_claude_headless_breadth_worker", _timeout
    )
    phase = _body_writer_phase()
    config = _driver_config(project, scratchpad)

    first = driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    )
    second = driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    )
    assert launches == ["claude"]
    assert any("no usable response" in issue for issue in first)
    assert any("will not be relaunched" in issue for issue in second)
    debt = (scratchpad / "report_evidence_runtime_debt.md").read_text(
        encoding="utf-8"
    )
    assert "P1K_PRE_BODY_DEBT" in debt
    assert not (scratchpad / "report_evidence_repair_receipt.json").exists()
    record = validate_report_evidence_runtime(scratchpad)["bundle"]["records"][0]
    assert record["recommendation"] == ""


def test_live_driver_restores_worker_input_mutation_before_accepting_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, impact="")
    verify_path = scratchpad / "verify_INV-001.md"
    original = verify_path.read_bytes()

    def _mutating_worker(**_kwargs):
        verify_path.write_text(
            "**Verdict**: CONFIRMED\n**Evidence Tag**: [POC-PASS]\n"
            "invented proof-grade harm\n",
            encoding="utf-8",
        )
        response = _repair_response_for_active_request(scratchpad)
        (scratchpad / "report_evidence_repair_response.json").write_text(
            json.dumps(response), encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(
        driver, "_run_one_claude_headless_breadth_worker", _mutating_worker
    )
    issues = driver._ensure_report_evidence_before_body_writer(
        _body_writer_phase(), _driver_config(project, scratchpad), scratchpad
    )
    assert verify_path.read_bytes() == original
    assert any("modified protected inputs" in issue for issue in issues)
    assert not (scratchpad / "report_evidence_repair_receipt.json").exists()
    record = validate_report_evidence_runtime(scratchpad)["bundle"]["records"][0]
    assert record["presentation_assurance"] != "PROOF_GRADE_HARM"


def test_live_driver_rejects_duplicate_key_response_without_relaunch_or_apply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    _write_inputs(scratchpad, impact="")
    launches: list[str] = []

    def _duplicate_key_worker(**_kwargs):
        launches.append("claude")
        response = _repair_response_for_active_request(scratchpad)
        raw = json.dumps(response)
        request_digest = response["request_digest"]
        raw = raw.replace(
            f'"request_digest": "{request_digest}"',
            f'"request_digest": "{request_digest}", '
            f'"request_digest": "{request_digest}"',
        )
        (scratchpad / "report_evidence_repair_response.json").write_text(
            raw, encoding="utf-8"
        )
        return 0

    monkeypatch.setattr(
        driver, "_run_one_claude_headless_breadth_worker", _duplicate_key_worker
    )
    phase = _body_writer_phase()
    config = _driver_config(project, scratchpad)
    first = driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    )
    # Once the invalid model output is ownership-bound, replacing it with a
    # syntactically valid answer must be detected as drift, not reblessed.
    (scratchpad / "report_evidence_repair_response.json").write_text(
        json.dumps(_repair_response_for_active_request(scratchpad)),
        encoding="utf-8",
    )
    second = driver._ensure_report_evidence_before_body_writer(
        phase, config, scratchpad
    )
    assert launches == ["claude"]
    assert any("duplicate key" in issue for issue in first)
    assert any("drifted before resume" in issue for issue in second), second
    assert not (scratchpad / "report_evidence_repair_receipt.json").exists()
    record = validate_report_evidence_runtime(scratchpad)["bundle"]["records"][0]
    assert record["impact"] == ""


def test_repair_apply_transaction_recovers_exactly_after_interrupted_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    _write_inputs(tmp_path, impact="")
    runtime = materialize_report_evidence_runtime(tmp_path)
    response = _repair_response_for_active_request(tmp_path)
    prepare_report_evidence_repair_apply_plan(tmp_path, response)
    original_write = report_authority._write_json
    writes = 0

    def _interrupt_second_write(path: Path, value):
        nonlocal writes
        writes += 1
        if writes == 2:
            raise OSError("simulated interrupted apply")
        return original_write(path, value)

    monkeypatch.setattr(
        report_authority, "_write_json", _interrupt_second_write
    )
    with pytest.raises(OSError, match="simulated interrupted apply"):
        apply_report_evidence_repair_response(tmp_path, response)
    assert not (tmp_path / "report_evidence_repair_receipt.json").exists()
    assert (
        json.loads((tmp_path / "report_evidence_records.json").read_text())[
            "bundle_digest"
        ]
        != runtime["bundle"]["bundle_digest"]
    )

    monkeypatch.setattr(report_authority, "_write_json", original_write)
    repaired = apply_report_evidence_repair_response(tmp_path, response)
    assert (tmp_path / "report_evidence_repair_receipt.json").is_file()
    assert repaired["bundle"]["records"][0]["impact"].startswith(
        "A bounded accounting inconsistency"
    )
    assert validate_report_evidence_runtime(tmp_path)["bundle"] == repaired["bundle"]
