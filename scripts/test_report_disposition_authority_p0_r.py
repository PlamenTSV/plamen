"""P0-R: report renderers cannot manufacture a non-body disposition."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import plamen_driver as driver
import semantic_dedup_authority as dedup
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
from plamen_driver import (
    _run_report_disposition_phase_io,
    _resume_phase_contract_issues,
)
from plamen_types import SC_PHASES
from plamen_validators import (
    _repair_report_index_dropouts,
    _validate_report_index_triage_safety,
)
from queue_work_items import (
    LineageLink,
    LocationRecord,
    QueueWorkPlan,
    QueueWorkItem,
    SeverityProposal,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
    queue_records_to_json,
)
from report_disposition_authority import (
    APPENDIX_SIDECAR_NAME,
    AUTHORITY_NAME,
    authorized_nonbody_internal_ids,
    reconcile_report_dispositions,
    validate_index_dispositions,
    validate_report_disposition_authority,
)
from verifier_work_roster import (
    VerifierLaunchSpec,
    VerifierUnitReceipt,
    VerifierWorkRoster,
    build_verifier_launch_spec,
    build_verifier_runtime_policy,
    build_verifier_work_roster,
)


RUN_ID = "12345678-1234-4567-8abc-1234567890ab"


def _seed_report_assembly_owner(
    scratchpad: Path,
    project_root: Path,
    *,
    mode: str = "core",
) -> None:
    """Recreate the chronological assembly boundary for a report fixture."""

    report_path = project_root / "AUDIT_REPORT.md"
    report_bytes = report_path.read_bytes()
    report_path.unlink()
    source = scratchpad / "report_assembly_fixture_source.md"
    source.write_text("# exact assembly fixture source\n", encoding="utf-8")
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode=mode,
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        exact_inputs=(source.name,),
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
        project_root,
        contract,
        launch,
        run_id=RUN_ID,
    )
    report_path.write_bytes(report_bytes)
    record_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )


def _item(
    finding_id: str = "INV-001",
    *,
    severity: str = "Medium",
    title: str = "Boundary transition loses accounting state",
) -> QueueWorkItem:
    return QueueWorkItem(
        candidate_identity=finding_id,
        work_item_id=finding_id,
        lineage=(
            LineageLink(
                identity=finding_id,
                relation="ORIGIN",
                source_artifact="findings_inventory.md",
            ),
        ),
        aliases=(),
        constituents=(),
        severity_proposal=SeverityProposal(
            level=severity,
            impact=severity,
            likelihood="Medium",
            rationale="Upstream impact and likelihood proposal.",
        ),
        evidence_class="code-trace",
        bug_class="state-accounting",
        preferred_tag="CODE-TRACE",
        queue_priority=1,
        location_records=(
            LocationRecord(
                artifact="src/module.rs",
                start_line=20,
                end_line=32,
                symbol="transition",
            ),
        ),
        primary_artifacts=("findings_inventory.md",),
        poc_class="unit",
        title=title,
    )


def _write_queue(sp: Path, items: list[QueueWorkItem]) -> None:
    (sp / "verification_queue.work_items.json").write_text(
        queue_records_to_json(items) + "\n", encoding="utf-8"
    )
    rows = [
        "# Verification Queue",
        "| Finding ID | Severity | Title | Location | Preferred Tag |",
        "|---|---|---|---|---|",
    ]
    rows.extend(
        f"| {item.work_item_id} | {item.severity_proposal.level} | "
        f"{item.title} | src/module.rs:20-32 | CODE-TRACE |"
        for item in items
    )
    (sp / "verification_queue.md").write_text("\n".join(rows) + "\n", encoding="utf-8")
    plan = build_queue_work_plan(
        items,
        {"verify_medium_a": [item.work_item_id for item in items]},
        planner_version="plamen.report-fixture.v1",
    )
    (sp / "verification_queue.work_plan.json").write_text(
        plan.to_json() + "\n", encoding="utf-8"
    )
    runtime_policy = build_verifier_runtime_policy(
        backend="claude",
        model="claude-opus-4-8",
        transport="pty",
        timeout_seconds=300,
        max_concurrency=2,
        source_root=str(sp.parent.resolve()),
    )
    roster = build_verifier_work_roster(
        plan,
        pipeline="sc",
        ecosystem="evm",
        mode="thorough",
        runtime_policy=runtime_policy,
        method_registry_digest="1" * 64,
        context_packet_digest="2" * 64,
    )
    (sp / "verification_runtime_roster.json").write_text(
        roster.to_json() + "\n", encoding="utf-8"
    )
    for unit in roster.work_units:
        unit_dir = sp / "_verifier_runtime_units" / unit.work_unit_id
        unit_dir.mkdir(parents=True, exist_ok=True)
        prompt = f"fixture prompt for {unit.work_unit_id}\n".encode("utf-8")
        spec = build_verifier_launch_spec(
            roster,
            unit.work_unit_id,
            prompt_bytes=prompt,
        )
        (unit_dir / "prompt.md").write_bytes(prompt)
        (unit_dir / "launch_spec.json").write_text(
            spec.to_json() + "\n", encoding="utf-8"
        )


def _refresh_runtime_unit_receipts(sp: Path) -> None:
    roster = VerifierWorkRoster.from_json(
        (sp / "verification_runtime_roster.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    for unit in roster.work_units:
        receipt_paths = [
            sp / f"verify_{work_id}.receipt.json"
            for work_id in unit.ordered_work_item_ids
        ]
        if not all(path.is_file() for path in receipt_paths):
            continue
        unit_dir = sp / "_verifier_runtime_units" / unit.work_unit_id
        spec = VerifierLaunchSpec.from_json(
            (unit_dir / "launch_spec.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
        gate_path = unit_dir / "gate_receipt.json"
        gate_path.write_text('{"fixture":"gate"}\n', encoding="utf-8")
        unit_receipt = VerifierUnitReceipt.completed_for(
            unit,
            launch_spec_digest=spec.digest,
            output_receipt_digests=[
                hashlib.sha256(path.read_bytes()).hexdigest()
                for path in receipt_paths
            ],
            gate_receipt_digests=[
                hashlib.sha256(gate_path.read_bytes()).hexdigest()
            ],
        )
        (unit_dir / "unit_receipt.json").write_text(
            unit_receipt.to_json() + "\n", encoding="utf-8"
        )


def _write_verifier(
    sp: Path,
    item: QueueWorkItem,
    status: str,
    *,
    extra: str = "",
) -> None:
    output = (
        f"# {item.work_item_id}\n\n"
        f"**Verdict**: {status}\n"
        f"**Severity**: {item.severity_proposal.level}\n"
        "**Description**: The exact candidate was independently reviewed.\n"
        "**Impact**: The candidate's complete claimed consequence was reviewed.\n"
        "**Recommendation**: Preserve the governing state relationship.\n"
        f"{extra}\n"
    ).encode("utf-8")
    proposal = b'{"typed":"severity-proposal"}\n'
    output_path = sp / item.expected_output_file
    proposal_path = sp / f"verify_{item.work_item_id}.severity_proposal.json"
    output_path.write_bytes(output)
    proposal_path.write_bytes(proposal)
    plan = QueueWorkPlan.from_json(
        (sp / "verification_queue.work_plan.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    roster = VerifierWorkRoster.from_json(
        (sp / "verification_runtime_roster.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    unit = next(
        unit for unit in roster.work_units
        if item.work_item_id in unit.ordered_work_item_ids
    )
    shard_id = next(
        shard.shard_id for shard in plan.shards
        if item.work_item_id in shard.ordered_work_item_ids
    )
    identity = VerifierOutputIdentity.for_assignment(item, plan, shard_id)
    spec = VerifierLaunchSpec.from_json(
        (
            sp / "_verifier_runtime_units" / unit.work_unit_id / "launch_spec.json"
        ).read_text(encoding="utf-8", errors="strict")
    )
    receipt = VerifierOutputReceipt.bind(
        identity,
        output,
        severity_proposal=proposal,
        launch_digest=spec.digest,
        verifier_backend=spec.backend,
    )
    (sp / f"verify_{item.work_item_id}.identity.json").write_text(
        json.dumps(identity.to_dict(), sort_keys=True), encoding="utf-8"
    )
    (sp / f"verify_{item.work_item_id}.receipt.json").write_text(
        receipt.to_json(), encoding="utf-8"
    )
    _refresh_runtime_unit_receipts(sp)


def _write_index(sp: Path, item: QueueWorkItem, report_id: str = "M-01") -> None:
    (sp / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n"
        f"| {report_id} | {item.title} | {item.severity_proposal.level} | "
        f"{item.work_item_id} |\n\n"
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n",
        encoding="utf-8",
    )


def _write_report(root: Path, item: QueueWorkItem, report_id: str = "M-01") -> str:
    text = (
        "# Security Audit Report\n\n"
        "## Summary\n\n"
        "| Severity | Count |\n|---|---:|\n"
        f"| {item.severity_proposal.level} | 1 |\n| Total | 1 |\n\n"
        "## Findings\n\n"
        f"### [{report_id}] {item.title}\n\n"
        f"**Severity**: {item.severity_proposal.level}\n\n"
        "**Location**: `src/module.rs:20-32`\n\n"
        "**Description**: A state transition can violate the governing relationship.\n\n"
        "**Impact**: A later account can receive an incorrect value.\n\n"
        "**Recommendation**: Enforce the relationship before committing state.\n"
    )
    (root / "AUDIT_REPORT.md").write_text(text, encoding="utf-8")
    return text


def _setup(
    tmp_path: Path,
    *,
    finding_id: str = "INV-001",
    status: str = "CONFIRMED",
    severity: str = "Medium",
    disposition: str = "APPENDIX",
    extra: str = "",
) -> tuple[Path, Path, QueueWorkItem, str]:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    item = _item(finding_id=finding_id, severity=severity)
    _write_queue(sp, [item])
    _write_verifier(sp, item, status, extra=extra)
    _write_index(sp, item)
    original = _write_report(tmp_path, item)
    (sp / "disposition.md").write_text(
        "# Material Harm Disposition\n\n"
        "| Report ID | Disposition | Reason |\n|---|---|---|\n"
        f"| M-01 | {disposition} | report writer proposal |\n",
        encoding="utf-8",
    )
    return sp, tmp_path, item, original


@pytest.mark.parametrize("status", ["CONFIRMED", "CONTESTED", "UNRESOLVED"])
def test_raw_appendix_proposal_cannot_relocate_reportable_finding(
    tmp_path: Path, status: str
) -> None:
    sp, root, _item_row, original = _setup(tmp_path, status=status)
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    assert (root / "AUDIT_REPORT.md").read_text(encoding="utf-8") == original
    row = result["authority"]["rows"][0]
    assert row["identity_accounted"] is True
    assert row["disposition_authorized"] is False
    assert row["public_retention_target"] == "BODY"


def test_unresolved_external_premise_stays_in_body(tmp_path: Path) -> None:
    sp, root, _item_row, _original = _setup(
        tmp_path,
        status="CONTESTED",
        extra="[UNPROVEN-EXTERNAL] [EXTERNAL-ASSUMPTION: pending evidence]",
    )
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    assert "[M-01]" in (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")


def test_exact_model_refutation_does_not_authorize_index_exclusion(
    tmp_path: Path,
) -> None:
    sp, _root, item, _original = _setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | INV-001 |\n",
        "",
    ).replace(
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n",
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n"
        "| INV-001 | Medium | low confidence prose |\n",
    )
    (sp / "report_index.md").write_text(index, encoding="utf-8")
    issues = validate_index_dispositions(sp, run_id=RUN_ID)
    assert any("INV-001" in issue and "unauthorized" in issue for issue in issues)
    assert "INV-001" not in authorized_nonbody_internal_ids(sp, run_id=RUN_ID)


def test_zero_harm_body_target_does_not_authorize_index_exclusion(
    tmp_path: Path,
) -> None:
    """A decision kind is not blanket authority for a different retention target."""
    sp, _root, item, _original = _setup(
        tmp_path,
        status="DROP_NON_SECURITY",
        severity="Low",
        disposition="BODY",
    )
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Low | INV-001 |\n",
        "",
    )
    index += "| INV-001 | Low | writer converted BODY target to exclusion |\n"
    (sp / "report_index.md").write_text(index, encoding="utf-8")

    authority = authorized_nonbody_internal_ids(sp, run_id=RUN_ID)
    assert "INV-001" not in authority
    issues = validate_index_dispositions(sp, run_id=RUN_ID)
    assert any("INV-001" in issue and "unauthorized" in issue for issue in issues)


def test_registry_owned_nested_identity_is_preserved_exactly_in_debt(
    tmp_path: Path,
) -> None:
    nested = "DA-STATE_EDGE-101"
    sp, _root, item, _original = _setup(
        tmp_path,
        finding_id=nested,
        status="REFUTED",
        disposition="BODY",
    )
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | {nested} |\n",
        "",
    )
    index += f"| {nested} | Medium | independently refuted |\n"
    (sp / "report_index.md").write_text(index, encoding="utf-8")

    result = reconcile_report_dispositions(sp, tmp_path, run_id=RUN_ID)
    assert result["authority"]["rows"][0]["candidate_id"] == nested
    assert not authorized_nonbody_internal_ids(sp, run_id=RUN_ID)
    issues = validate_index_dispositions(sp, run_id=RUN_ID)
    assert any(nested in issue for issue in issues)
    assert all("DA-STATE-EDGE-101" not in issue for issue in issues)


def test_multi_constituent_report_row_requires_all_members_authorize_appendix(
    tmp_path: Path,
) -> None:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    zero_harm = _item("INV-001", severity="Low", title="First member")
    confirmed = _item("INV-002", severity="Low", title="Second member")
    _write_queue(sp, [zero_harm, confirmed])
    _write_verifier(sp, zero_harm, "DROP_NON_SECURITY")
    _write_verifier(sp, confirmed, "CONFIRMED")
    (sp / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n"
        "| M-01 | Combined report row | Low | INV-001 + INV-002 |\n\n"
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n|---|---|---|\n",
        encoding="utf-8",
    )
    (sp / "disposition.md").write_text(
        "# Material Harm Disposition\n\n"
        "| Report ID | Disposition | Reason |\n|---|---|---|\n"
        "| M-01 | APPENDIX | writer proposal |\n",
        encoding="utf-8",
    )
    _write_report(tmp_path, zero_harm)

    result = reconcile_report_dispositions(sp, tmp_path, run_id=RUN_ID)
    assert result["moved"] == 0
    assert "[M-01]" in (tmp_path / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert any("INV-002" in issue or "all" in issue.lower() for issue in result["issues"])


def test_multi_constituent_model_zero_harm_never_authorizes_relocation(
    tmp_path: Path,
) -> None:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    first = _item("INV-001", severity="Low", title="First member")
    second = _item("INV-002", severity="Low", title="Second member")
    _write_queue(sp, [first, second])
    _write_verifier(sp, first, "DROP_NON_SECURITY")
    _write_verifier(sp, second, "DROP_NON_SECURITY")
    (sp / "report_index.md").write_text(
        "# Report Index\n\n## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n"
        "| M-01 | Combined report row | Low | INV-001 + INV-002 |\n",
        encoding="utf-8",
    )
    (sp / "disposition.md").write_text(
        "| Report ID | Disposition | Reason |\n|---|---|---|\n"
        "| M-01 | APPENDIX | writer proposal |\n",
        encoding="utf-8",
    )
    _write_report(tmp_path, first)

    result = reconcile_report_dispositions(sp, tmp_path, run_id=RUN_ID)
    assert result["moved"] == 0
    assert all(
        row["negative_proposal_status"] == "DROP_NON_SECURITY"
        and row["public_retention_target"] == "BODY"
        for row in result["authority"]["rows"]
    )


def test_confirmed_medium_excluded_as_low_confidence_is_rejected(
    tmp_path: Path,
) -> None:
    sp, _root, item, _original = _setup(tmp_path, status="CONFIRMED")
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | INV-001 |\n",
        "",
    )
    index += "| INV-001 | Medium | LOW_CONFIDENCE: writer assertion |\n"
    (sp / "report_index.md").write_text(index, encoding="utf-8")
    issues = validate_index_dispositions(sp, run_id=RUN_ID)
    assert issues and "INV-001" in issues[0]


def test_live_index_validator_blocks_raw_exclusion_prose(tmp_path: Path) -> None:
    sp, _root, item, _original = _setup(tmp_path, status="CONFIRMED")
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | INV-001 |\n",
        "",
    )
    index += "| INV-001 | Medium | REFUTED: report writer claim |\n"
    (sp / "report_index.md").write_text(index, encoding="utf-8")
    issues = _validate_report_index_triage_safety(sp)
    assert issues and any("INV-001" in issue for issue in issues)


def test_dropout_repair_preserves_upstream_body_when_nonbody_is_unauthorized(
    tmp_path: Path,
) -> None:
    sp, _root, item, _original = _setup(tmp_path, status="CONTESTED")
    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        f"| M-01 | {item.title} | Medium | INV-001 |\n",
        "",
    )
    index += "| INV-001 | Medium | LOW_CONFIDENCE: report writer claim |\n"
    (sp / "report_index.md").write_text(index, encoding="utf-8")
    assert _repair_report_index_dropouts(sp) == ["INV-001"]
    repaired = (sp / "report_index.md").read_text(encoding="utf-8")
    assert "| M-01 |" in repaired
    assert "| Medium |" in repaired
    assert "UNRESOLVED-DISPOSITION" in repaired


def test_model_zero_harm_plus_appendix_proposal_stays_losslessly_in_body(
    tmp_path: Path,
) -> None:
    sp, root, _item_row, original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    style_only = original.replace(
        "Boundary transition loses accounting state",
        "Documentation wording is inconsistent",
    ).replace(
        "A state transition can violate the governing relationship.",
        "A documentation label uses inconsistent wording.",
    ).replace(
        "A later account can receive an incorrect value.",
        "No runtime behavior changes; this is a style-only observation.",
    ).replace(
        "Enforce the relationship before committing state.",
        "Use one documentation label consistently.",
    )
    (root / "AUDIT_REPORT.md").write_text(style_only, encoding="utf-8")
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    report = (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "### [M-01]" in report
    assert "A documentation label uses inconsistent wording." in report
    assert "No runtime behavior changes; this is a style-only observation." in report
    assert "Use one documentation label consistently." in report
    authority = validate_report_disposition_authority(sp, root, run_id=RUN_ID)
    assert authority["rows"][0]["disposition_authorized"] is False
    sidecar = json.loads((sp / APPENDIX_SIDECAR_NAME).read_text(encoding="utf-8"))
    assert sidecar["row_count"] == 0
    assert original.encode("utf-8")


def test_unsupported_zero_harm_never_creates_appendix_detail_to_delete(
    tmp_path: Path,
) -> None:
    sp, root, _item_row, original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    style_only = original.replace(
        "A state transition can violate the governing relationship.",
        "UNIQUE-DESCRIPTION-CONTENT",
    ).replace(
        "A later account can receive an incorrect value.",
        "UNIQUE-IMPACT-CONTENT",
    ).replace(
        "Enforce the relationship before committing state.",
        "UNIQUE-RECOMMENDATION-CONTENT",
    )
    (root / "AUDIT_REPORT.md").write_text(style_only, encoding="utf-8")
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    delivered = (root / "AUDIT_REPORT.md").read_text(encoding="utf-8")
    assert "UNIQUE-DESCRIPTION-CONTENT" in delivered
    assert "Appendix observation [M-01]" not in delivered
    validate_report_disposition_authority(sp, root, run_id=RUN_ID)


def test_harm_bearing_low_cannot_be_relocated_by_quality_keyword(
    tmp_path: Path,
) -> None:
    sp, root, _item_row, _original = _setup(
        tmp_path,
        status="CONFIRMED",
        severity="Low",
        extra="This is described as defense-in-depth but can alter stored value.",
    )
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0


def test_missing_stale_or_tampered_verifier_receipt_vetoes_relocation(
    tmp_path: Path,
) -> None:
    sp, root, item, original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    receipt = sp / f"verify_{item.work_item_id}.receipt.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["output_sha256"] = "0" * 64
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    assert result["issues"]
    assert (root / "AUDIT_REPORT.md").read_text(encoding="utf-8") == original


@pytest.mark.parametrize("plan_state", ["missing", "malformed"])
def test_current_queue_work_plan_is_required_before_nonbody_relocation(
    tmp_path: Path,
    plan_state: str,
) -> None:
    sp, root, _item_row, original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    plan_path = sp / "verification_queue.work_plan.json"
    if plan_state == "missing":
        plan_path.unlink()
    else:
        plan_path.write_text("{malformed", encoding="utf-8")

    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    assert result["issues"]
    assert (root / "AUDIT_REPORT.md").read_text(encoding="utf-8") == original


@pytest.mark.parametrize("authority_state", ["missing-launch", "malformed-launch", "missing-unit-receipt"])
def test_current_provider_launch_authority_is_required_before_nonbody_relocation(
    tmp_path: Path,
    authority_state: str,
) -> None:
    sp, root, _item_row, original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    unit_dir = next((sp / "_verifier_runtime_units").iterdir())
    if authority_state == "missing-launch":
        (unit_dir / "launch_spec.json").unlink()
    elif authority_state == "malformed-launch":
        (unit_dir / "launch_spec.json").write_text("{malformed", encoding="utf-8")
    else:
        (unit_dir / "unit_receipt.json").unlink()

    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert result["moved"] == 0
    assert result["issues"]
    assert (root / "AUDIT_REPORT.md").read_text(encoding="utf-8") == original


def test_full_content_sidecar_tamper_is_detected_and_repeated_floor_is_idempotent(
    tmp_path: Path,
) -> None:
    sp, root, _item_row, _original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    report_path = root / "AUDIT_REPORT.md"
    style_only = report_path.read_text(encoding="utf-8").replace(
        "Boundary transition loses accounting state",
        "Documentation wording is inconsistent",
    ).replace(
        "A state transition can violate the governing relationship.",
        "A documentation label uses inconsistent wording.",
    ).replace(
        "A later account can receive an incorrect value.",
        "No runtime behavior changes; this is a style-only observation.",
    ).replace(
        "Enforce the relationship before committing state.",
        "Use one documentation label consistently.",
    )
    report_path.write_text(style_only, encoding="utf-8")
    first = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    report_after = (root / "AUDIT_REPORT.md").read_bytes()
    authority_after = (sp / AUTHORITY_NAME).read_bytes()
    sidecar_after = (sp / APPENDIX_SIDECAR_NAME).read_bytes()
    second = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert first["moved"] == 0 and second["moved"] == 0
    assert (root / "AUDIT_REPORT.md").read_bytes() == report_after
    assert (sp / AUTHORITY_NAME).read_bytes() == authority_after
    assert (sp / APPENDIX_SIDECAR_NAME).read_bytes() == sidecar_after

    payload = json.loads(sidecar_after)
    payload["authority_receipt_sha256"] = "0" * 64
    (sp / APPENDIX_SIDECAR_NAME).write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="sidecar|digest|section"):
        validate_report_disposition_authority(sp, root, run_id=RUN_ID)


def test_empty_sidecar_survives_unrelated_append_but_detects_receipt_tamper(
    tmp_path: Path,
) -> None:
    sp, root, _item_row, _original = _setup(
        tmp_path, status="DROP_NON_SECURITY", severity="Low"
    )
    report_path = root / "AUDIT_REPORT.md"
    report_path.write_text(
        report_path.read_text(encoding="utf-8")
        .replace("Boundary transition loses accounting state", "Documentation wording is inconsistent")
        .replace("A state transition can violate the governing relationship.", "A documentation label uses inconsistent wording.")
        .replace("A later account can receive an incorrect value.", "No runtime behavior changes; this is a style-only observation.")
        .replace("Enforce the relationship before committing state.", "Use one documentation label consistently."),
        encoding="utf-8",
    )
    assert reconcile_report_dispositions(sp, root, run_id=RUN_ID)["moved"] == 0
    report_path.write_text(
        report_path.read_text(encoding="utf-8") + "\n## Appendix E\n\nAuthorized assurance note.\n",
        encoding="utf-8",
    )
    validate_report_disposition_authority(sp, root, run_id=RUN_ID)
    sidecar_path = sp / APPENDIX_SIDECAR_NAME
    payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    payload["authority_receipt_sha256"] = "0" * 64
    sidecar_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="sidecar|digest|authority"):
        validate_report_disposition_authority(sp, root, run_id=RUN_ID)


def test_report_floor_phaseio_and_resume_detect_source_drift(tmp_path: Path) -> None:
    sp, root, _item_row, _original = _setup(
        tmp_path, status="CONFIRMED", disposition="BODY"
    )
    (sp / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": RUN_ID}), encoding="utf-8"
    )
    _seed_report_assembly_owner(sp, root)
    phase = next(item for item in SC_PHASES if item.name == "report_floor")
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root),
        "_run_id": RUN_ID,
    }
    result, issues = _run_report_disposition_phase_io(
        scratchpad=sp, config=config, phase=phase
    )
    assert issues == []
    assert result["moved"] == 0
    assert _resume_phase_contract_issues(
        sp, str(root), phase, "core", "evm", "sc", "claude"
    ) == []
    with (sp / "report_index.md").open("a", encoding="utf-8") as handle:
        handle.write("\n<!-- source drift -->\n")
    issues = _resume_phase_contract_issues(
        sp, str(root), phase, "core", "evm", "sc", "claude"
    )
    assert issues and any("drift" in issue.lower() or "mismatch" in issue.lower() for issue in issues)


def test_phaseio_contract_owns_authority_sidecar_marker_and_report() -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_floor",
        work_unit_id="disposition_authority",
        exact_inputs=("report_index.md", "verification_queue.work_items.json"),
    )
    outputs = {(artifact.root, artifact.path) for artifact in contract.outputs}
    assert outputs == {
        ("scratchpad", "report_disposition_authority.json"),
        ("scratchpad", "report_appendix_full_content.json"),
        ("scratchpad", "material_harm_floor.md"),
        ("scratchpad", "report_disposition_merge_intent.json"),
        ("project", "AUDIT_REPORT.md"),
    }


def test_report_disposition_phaseio_resumes_crash_after_semantic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sp, root, _item_row, _original = _setup(
        tmp_path, status="CONFIRMED", disposition="BODY"
    )
    (sp / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": RUN_ID}), encoding="utf-8"
    )
    _seed_report_assembly_owner(sp, root)
    phase = next(item for item in SC_PHASES if item.name == "report_floor")
    config = {
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root),
        "_run_id": RUN_ID,
    }
    real_commit = driver._commit_deterministic_driver_work_unit
    monkeypatch.setattr(
        driver,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: ["simulated crash before output commit"],
    )

    _result, issues = driver._run_report_disposition_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    )
    assert issues == ["simulated crash before output commit"]
    key = "sc/core/evm/claude/report_floor/disposition_authority"
    unit = read_artifact_ledger(sp)["work_units"][key]
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}
    assert (sp / "report_disposition_authority.json").is_file()
    assert (sp / "report_appendix_full_content.json").is_file()
    assert (sp / "report_disposition_merge_intent.json").is_file()
    assert (sp / "material_harm_floor.md").is_file()

    monkeypatch.setattr(
        driver, "_commit_deterministic_driver_work_unit", real_commit
    )
    _result, issues = driver._run_report_disposition_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    )
    assert issues == []
    unit = read_artifact_ledger(sp)["work_units"][key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["read_modify_write_transitions"][
        "project:AUDIT_REPORT.md"
    ]["write_mode"] == "MERGE"


def _finding(fid: str, title: str, source_ids: str) -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        "**Location**: src/module.rs:20-32\n"
        f"**Source IDs**: {source_ids}\n"
        "**Root Cause**: The same state relation is omitted.\n"
        "**Description**: The same transition accepts an invalid state.\n"
        "**Preconditions**: A caller reaches the transition.\n"
        "**Impact**: A later account receives an incorrect value.\n"
        "**Recommendation**: Enforce the state relationship.\n"
        "**External Premises**: None.\n"
        "**Evidence Scope**: Full claim.\n[CODE-TRACE]\n\n"
    )


def test_only_applied_alias_receipt_authorizes_consolidation(tmp_path: Path) -> None:
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    survivor = _item("INV-001")
    _write_queue(sp, [survivor])
    _write_verifier(sp, survivor, "CONFIRMED")
    pre = _finding("INV-001", "Canonical", "A-1, B-1") + _finding(
        "INV-002", "Variant", "B-1"
    )
    post = _finding("INV-001", "Canonical", "A-1, B-1")
    # Preserve the absorbed record through the exact member card required by
    # P0-Q's field-superset gate.
    record = dedup.extract_finding_records(pre)["INV-002"]
    post += dedup.preserved_member_card(record)
    (sp / "findings_inventory.md").write_bytes(post.encode("utf-8"))
    proposal_text = "# Semantic Dedup Decisions\n\nMERGE: INV-001, INV-002\n"
    proposals = dedup.parse_dedup_proposals(proposal_text)
    dedup.write_applied_receipt(
        sp,
        phase_name="sc_semantic_dedup",
        application_kind="PRIMARY",
        proposal_text=proposal_text,
        proposals=proposals,
        input_text=pre,
        output_text=post,
        applied_merges=[("INV-002", "INV-001", "field-complete equivalent")],
    )
    authorized = authorized_nonbody_internal_ids(sp, run_id=RUN_ID)
    assert authorized["INV-002"]["authority_kind"] == "AUTHORIZED_ALIAS"
    assert authorized["INV-002"]["alias_target"] == "INV-001"

    (sp / "report_index.md").write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n"
        "| M-01 | Canonical | Medium | INV-001 |\n\n"
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n"
        "| INV-002 | Medium | writer called an alias excluded |\n",
        encoding="utf-8",
    )
    assert any(
        "INV-002" in issue and "unauthorized" in issue
        for issue in validate_index_dispositions(sp, run_id=RUN_ID)
    )

    index = (sp / "report_index.md").read_text(encoding="utf-8")
    index = index.replace(
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n"
        "|---|---|---|\n"
        "| INV-002 | Medium | writer called an alias excluded |\n",
        "## Consolidation Map\n"
        "| Internal ID | Survivor | Reason |\n"
        "|---|---|---|\n"
        "| INV-002 | INV-001 | applied alias receipt |\n",
    )
    (sp / "report_index.md").write_text(index, encoding="utf-8")
    assert validate_index_dispositions(sp, run_id=RUN_ID) == []


def test_coverage_only_deferred_is_visible_debt_not_terminal_disposition(
    tmp_path: Path,
) -> None:
    sp, _root, _item_row, _original = _setup(tmp_path, status="CONFIRMED")
    (sp / "report_coverage.md").write_text(
        "## Coverage Ledger\n"
        "| Finding ID | Status | Reason |\n|---|---|---|\n"
        "| INV-777 | DEFERRED | report writer could not place it |\n",
        encoding="utf-8",
    )
    (sp / "report_index_coverage_seed.md").write_text(
        "| Finding ID | Severity |\n|---|---|\n| INV-777 | Medium |\n",
        encoding="utf-8",
    )
    issues = validate_index_dispositions(sp, run_id=RUN_ID)
    assert issues and any("INV-777" in issue and "debt" in issue.lower() for issue in issues)


def test_planned_fallback_id_cannot_account_for_missing_index_or_body(
    tmp_path: Path,
) -> None:
    """Routing fallback is a plan, never evidence of rendered retention."""
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    item = _item(finding_id="INV-901", severity="Medium")
    _write_queue(sp, [item])
    _write_verifier(sp, item, "CONFIRMED")
    (sp / "report_index.md").write_text(
        "# Report Index\n\n## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n\n"
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n|---|---|---|\n",
        encoding="utf-8",
    )
    (tmp_path / "AUDIT_REPORT.md").write_text(
        "# Security Audit Report\n\n## Findings\n\n_No findings._\n",
        encoding="utf-8",
    )

    result = reconcile_report_dispositions(sp, tmp_path, run_id=RUN_ID)
    row = next(
        value for value in result["authority"]["rows"]
        if value["candidate_id"] == item.work_item_id
    )
    assert row["identity_accounted"] is False
    assert row["report_ids"] == []
    assert row["planned_report_ids"] == ["M-01"]
    assert row["public_retention_target"] == "BODY"
    assert row["visible_debt"] is True
    assert any("INV-901" in issue and "BODY report route" in issue for issue in result["issues"])
    issues = validate_index_dispositions(sp, run_id=RUN_ID)
    assert any(
        "INV-901" in issue and "unresolved report disposition debt" in issue
        for issue in issues
    )


def test_index_only_body_assignment_is_visible_delivery_debt(
    tmp_path: Path,
) -> None:
    """A Master-index row cannot certify a body section that was never rendered."""
    sp, root, item, _original = _setup(tmp_path, status="CONFIRMED")
    (root / "AUDIT_REPORT.md").write_text(
        "# Security Audit Report\n\n## Findings\n\n_No findings._\n",
        encoding="utf-8",
    )

    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    assert any(
        item.work_item_id in issue and "not rendered" in issue
        for issue in result["issues"]
    )
    assert result["sidecar"]["body_delivery_debt_count"] == 1
    delivery = result["sidecar"]["body_delivery_rows"][0]
    assert delivery == {
        "candidate_id": item.work_item_id,
        "report_ids": ["M-01"],
        "rendered_report_ids": [],
        "complete": False,
    }
    with pytest.raises(ValueError, match="body delivery incomplete"):
        validate_report_disposition_authority(sp, root, run_id=RUN_ID)


def test_exact_model_refuted_excluded_row_is_visible_unauthorized_debt(
    tmp_path: Path,
) -> None:
    sp, root, item, _original = _setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    (sp / "report_index.md").write_text(
        "# Report Index\n\n## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n\n"
        "## Excluded Findings\n"
        "| Internal ID | Severity | Exclusion Reason |\n|---|---|---|\n"
        f"| {item.work_item_id} | Medium | independently refuted |\n",
        encoding="utf-8",
    )
    (root / "AUDIT_REPORT.md").write_text(
        "# Security Audit Report\n\n## Findings\n\n_No findings._\n",
        encoding="utf-8",
    )

    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    row = result["authority"]["rows"][0]
    assert row["report_ids"] == []
    assert row["identity_accounted"] is False
    assert row["accounting_route"] == "UNACCOUNTED"
    assert row["public_retention_target"] == "BODY"
    assert row["visible_debt"] is True
    assert any(item.work_item_id in issue for issue in result["issues"])
    assert any(
        item.work_item_id in issue
        for issue in validate_index_dispositions(sp, run_id=RUN_ID)
    )


def test_refutation_without_exact_excluded_row_remains_visible_debt(
    tmp_path: Path,
) -> None:
    sp, root, item, _original = _setup(
        tmp_path, status="REFUTED", disposition="BODY"
    )
    (sp / "report_index.md").write_text(
        "# Report Index\n\n## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis ID |\n"
        "|---|---|---|---|\n",
        encoding="utf-8",
    )
    (root / "AUDIT_REPORT.md").write_text(
        "# Security Audit Report\n\n## Findings\n\n_No findings._\n",
        encoding="utf-8",
    )
    result = reconcile_report_dispositions(sp, root, run_id=RUN_ID)
    row = result["authority"]["rows"][0]
    assert row["identity_accounted"] is False
    assert row["visible_debt"] is True
    assert any(item.work_item_id in issue for issue in result["issues"])
