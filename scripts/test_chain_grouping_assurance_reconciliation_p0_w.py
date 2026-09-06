"""P0-W: relation telemetry is not client-visible assurance debt.

These fixtures exercise the post-report reconciliation boundary.  A proposed
multi-member relation is ordinary telemetry when every member independently
survives current typed verification and report delivery.  Only an exact member
that is absent from that authority chain becomes a content-bearing limitation.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path

import pytest

import plamen_validators as validators
import plamen_driver as driver
from artifact_ledger import read_artifact_ledger
from assurance_limitations import (
    project_assurance_limitations,
    validate_assurance_projection,
)
from chain_grouping_assurance import (
    ASSURANCE_FILE,
    LIMITATIONS_FILE,
    validate_chain_grouping_assurance,
    write_chain_grouping_assurance,
)
from phase_io_contracts import resolve_phase_io_contract
from plamen_types import Checkpoint, SC_PHASES
from report_disposition_authority import reconcile_report_dispositions
from test_report_disposition_authority_p0_r import (
    RUN_ID,
    _item,
    _seed_report_assembly_owner,
    _write_queue,
    _write_verifier,
)


def _write_relation_sources(root: Path) -> None:
    (root / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: First independent transition\n"
        "**Severity**: Medium\n"
        "**Location**: src/module.rs:20\n"
        "**Root Cause**: UNIQUE-MECHANISM-ONE\n"
        "**Impact**: UNIQUE-IMPACT-ONE\n\n"
        "### Finding [INV-002]: Second independent transition\n"
        "**Severity**: Medium\n"
        "**Location**: src/module.rs:40\n"
        "**Root Cause**: UNIQUE-MECHANISM-TWO\n"
        "**Impact**: UNIQUE-IMPACT-TWO\n",
        encoding="utf-8",
    )
    (root / "hypotheses.md").write_text(
        "# Hypotheses\n\n"
        "| Hypothesis ID | Severity | Title | Source Findings | Invariant | Preconditions | Impact | Evidence | Composition |\n"
        "|---|---|---|---|---|---|---|---|---|\n"
        "| HM-01 | Medium | proposal-only composition | INV-001, INV-002 | I | P | X | E | C |\n",
        encoding="utf-8",
    )
    (root / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        "|---|---|---|---|\n"
        "| INV-001 | HM-01 | GROUPED | proposal only |\n"
        "| INV-002 | HM-01 | GROUPED | proposal only |\n",
        encoding="utf-8",
    )
    assert validators._repair_chain_anti_absorption_splits(root) == 2


def _write_index_and_report(
    scratchpad: Path,
    project_root: Path,
    items: list,
) -> None:
    report_ids = {
        item.work_item_id: f"M-{index:02d}"
        for index, item in enumerate(items, 1)
    }
    index_lines = [
        "# Report Index",
        "",
        "## Master Finding Index",
        "| Report ID | Title | Severity | Internal Hypothesis ID |",
        "|---|---|---|---|",
    ]
    index_lines.extend(
        f"| {report_ids[item.work_item_id]} | {item.title} | Medium | {item.work_item_id} |"
        for item in items
    )
    index_lines.extend(
        [
            "",
            "## Excluded Findings",
            "| Internal ID | Severity | Exclusion Reason |",
            "|---|---|---|",
            "",
        ]
    )
    (scratchpad / "report_index.md").write_text(
        "\n".join(index_lines), encoding="utf-8"
    )
    disposition_lines = [
        "# Material Harm Disposition",
        "",
        "| Report ID | Disposition | Reason |",
        "|---|---|---|",
    ]
    disposition_lines.extend(
        f"| {report_ids[item.work_item_id]} | BODY | retained finding |"
        for item in items
    )
    (scratchpad / "disposition.md").write_text(
        "\n".join(disposition_lines) + "\n", encoding="utf-8"
    )
    report_lines = ["# Security Audit Report", "", "## Findings", ""]
    for item in items:
        report_id = report_ids[item.work_item_id]
        report_lines.extend(
            [
                f"### [{report_id}] {item.title}",
                "",
                "**Severity**: Medium",
                "",
                "**Location**: `src/module.rs:20-32`",
                "",
                "**Description**: The complete independent claim remains visible.",
                "",
                "**Impact**: Protected state can lose integrity.",
                "",
                "**Recommendation**: Enforce the governing relationship.",
                "",
            ]
        )
    (project_root / "AUDIT_REPORT.md").write_text(
        "\n".join(report_lines), encoding="utf-8"
    )


def _setup_delivered_members(
    tmp_path: Path,
    delivered_ids: tuple[str, ...],
) -> tuple[Path, Path]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_relation_sources(scratchpad)
    items = [
        _item(
            finding_id=finding_id,
            title=(
                "First independent transition"
                if finding_id == "INV-001"
                else "Second independent transition"
            ),
        )
        for finding_id in delivered_ids
    ]
    _write_queue(scratchpad, items)
    for item in items:
        _write_verifier(scratchpad, item, "CONFIRMED")
    _write_index_and_report(scratchpad, tmp_path, items)
    result = reconcile_report_dispositions(
        scratchpad, tmp_path, run_id=RUN_ID
    )
    assert result["issues"] == []
    return scratchpad, tmp_path


def test_fully_delivered_independent_group_is_telemetry_not_assurance_debt(
    tmp_path: Path,
) -> None:
    scratchpad, project_root = _setup_delivered_members(
        tmp_path, ("INV-001", "INV-002")
    )

    receipt = write_chain_grouping_assurance(
        scratchpad, project_root, run_id=RUN_ID
    )

    assert receipt["assurance_debt_count"] == 0
    assert receipt["assurance_debts"] == []
    assert receipt["summary"] == {
        "relation_group_count": 1,
        "relation_member_count": 2,
        "independently_delivered_member_count": 2,
        "client_human_review_limitation_count": 0,
    }
    assert all(
        row["state"] == "INDEPENDENTLY_DELIVERED"
        for row in receipt["member_reconciliation"]
    )
    telemetry = (scratchpad / "chain_grouping_debt.md").read_text(
        encoding="utf-8"
    )
    assert "Relation Telemetry" in telemetry
    assert "Equivalence Debt" not in telemetry
    assert "client-visible assurance debt" not in telemetry.lower()
    limitations = (scratchpad / LIMITATIONS_FILE).read_text(encoding="utf-8")
    assert "Client human-review limitations: 0" in limitations
    assert validate_chain_grouping_assurance(
        scratchpad, project_root, run_id=RUN_ID
    ) == receipt


def test_missing_member_becomes_exact_content_bearing_hash_bound_debt(
    tmp_path: Path,
) -> None:
    # The relation is projected before the current queue is built.  The second
    # member is then absent from the complete verifier/report transaction.
    scratchpad, project_root = _setup_delivered_members(tmp_path, ("INV-001",))

    receipt = write_chain_grouping_assurance(
        scratchpad, project_root, run_id=RUN_ID
    )

    assert receipt["assurance_debt_count"] == 1
    debt = receipt["assurance_debts"][0]
    assert debt["member_id"] == "INV-002"
    assert debt["group_ids"] == ["HM-01"]
    assert debt["authority_effect"] == "NONE"
    assert debt["identity_effect"] == "RETAIN_INDEPENDENT_MEMBER"
    assert debt["severity_effect"] == "NONE"
    assert debt["disposition_effect"] == "NONE"
    assert debt["public_visibility"] == "CLIENT_HUMAN_REVIEW_LIMITATION"
    assert debt["missing_authority_stages"] == [
        "CURRENT_QUEUE_WORK_ITEM",
        "CURRENT_QUEUE_WORK_PLAN",
        "CURRENT_VERIFIER_ROSTER",
        "EXACT_VERIFIER_EXECUTION",
        "EXACT_REPORT_DELIVERY",
    ]
    assert "UNIQUE-MECHANISM-TWO" in debt["source_record_utf8"]
    assert "UNIQUE-IMPACT-TWO" in debt["source_record_utf8"]
    assert debt["source_record_sha256"] == hashlib.sha256(
        debt["source_record_utf8"].encode("utf-8")
    ).hexdigest()
    unsigned = {key: value for key, value in debt.items() if key != "debt_sha256"}
    expected_debt_digest = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    assert debt["debt_sha256"] == expected_debt_digest
    assert receipt["source_bindings"]["queue_work_plan_digest"]
    assert receipt["source_bindings"]["verifier_roster_digest"]
    assert receipt["source_bindings"]["report_disposition_receipt_sha256"]
    projection = (scratchpad / LIMITATIONS_FILE).read_text(encoding="utf-8")
    assert "Client human-review limitations: 1" in projection
    assert "INV-002" in projection
    assert "INV-001" not in projection


def test_group_alias_delivery_cannot_substitute_for_exact_member_delivery(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_relation_sources(scratchpad)
    group_item = replace(
        _item(
            finding_id="HM-01",
            title="A composition card is not independent member work",
        ),
        constituents=("INV-001", "INV-002"),
    )
    _write_queue(scratchpad, [group_item])
    _write_verifier(scratchpad, group_item, "CONFIRMED")
    _write_index_and_report(scratchpad, tmp_path, [group_item])
    result = reconcile_report_dispositions(
        scratchpad, tmp_path, run_id=RUN_ID
    )
    assert result["issues"] == []

    receipt = write_chain_grouping_assurance(
        scratchpad, tmp_path, run_id=RUN_ID
    )

    assert receipt["assurance_debt_count"] == 2
    assert [row["member_id"] for row in receipt["assurance_debts"]] == [
        "INV-001",
        "INV-002",
    ]
    assert all(
        "CURRENT_QUEUE_WORK_ITEM" in row["missing_authority_stages"]
        for row in receipt["assurance_debts"]
    )
    assert receipt["may_delete_demote_or_collapse"] is False


def test_assurance_receipt_replay_rejects_source_drift(tmp_path: Path) -> None:
    scratchpad, project_root = _setup_delivered_members(
        tmp_path, ("INV-001", "INV-002")
    )
    write_chain_grouping_assurance(scratchpad, project_root, run_id=RUN_ID)
    authority_path = scratchpad / "report_disposition_authority.json"
    authority_path.write_bytes(authority_path.read_bytes() + b" ")

    with pytest.raises(ValueError):
        validate_chain_grouping_assurance(
            scratchpad, project_root, run_id=RUN_ID
        )


def test_assurance_receipt_digest_tamper_is_rejected(tmp_path: Path) -> None:
    scratchpad, project_root = _setup_delivered_members(
        tmp_path, ("INV-001", "INV-002")
    )
    write_chain_grouping_assurance(scratchpad, project_root, run_id=RUN_ID)
    path = scratchpad / ASSURANCE_FILE
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["receipt_sha256"] = "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="receipt digest"):
        validate_chain_grouping_assurance(
            scratchpad, project_root, run_id=RUN_ID
        )


def test_driver_owned_report_envelope_append_does_not_stale_delivery_authority(
    tmp_path: Path,
) -> None:
    """Finding delivery and the final report envelope are separate authorities.

    The report-floor assurance renderer appends a managed client limitation
    block after disposition reconciliation.  That permitted envelope mutation
    must not invalidate the already replayed exact finding-delivery proof; the
    final report bytes are bound by the assurance-projection PhaseIO unit.
    """

    scratchpad, project_root = _setup_delivered_members(
        tmp_path, ("INV-001", "INV-002")
    )
    receipt = write_chain_grouping_assurance(
        scratchpad, project_root, run_id=RUN_ID
    )
    before = (project_root / "AUDIT_REPORT.md").read_bytes()

    with (project_root / "AUDIT_REPORT.md").open("ab") as handle:
        handle.write(
            b"\n<!-- PLAMEN:ASSURANCE-LIMITATIONS:START -->\n"
            b"## Audit Completeness and Assurance Limitations\n\n"
            b"Driver-owned envelope projection.\n"
            b"<!-- PLAMEN:ASSURANCE-LIMITATIONS:END -->\n"
        )

    assert (project_root / "AUDIT_REPORT.md").read_bytes() != before
    assert validate_chain_grouping_assurance(
        scratchpad, project_root, run_id=RUN_ID
    ) == receipt


def test_chain_grouping_assurance_phaseio_is_driver_only_and_exact() -> None:
    inputs = (
        "chain_grouping_relations.json",
        "findings_inventory.md",
        "report_disposition_authority.json",
        "verify_INV-001.md",
    )
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_floor",
        work_unit_id="chain_grouping_assurance",
        exact_inputs=inputs,
    )

    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{name}" for name in inputs
    }
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:chain_grouping_assurance_reconciliation.json",
        "scratchpad:chain_grouping_assurance_limitations.md",
    }
    assert {item.writer for item in contract.outputs} == {"DRIVER"}


def test_driver_writes_binds_and_resume_replays_chain_grouping_assurance(
    tmp_path: Path,
) -> None:
    scratchpad, project_root = _setup_delivered_members(
        tmp_path, ("INV-001", "INV-002")
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "scratchpad": str(scratchpad),
        "project_root": str(project_root),
        "_run_id": RUN_ID,
    }
    checkpoint = Checkpoint(run_id=RUN_ID)
    checkpoint.save(scratchpad)
    phase = next(item for item in SC_PHASES if item.name == "report_floor")
    _seed_report_assembly_owner(
        scratchpad, project_root, mode="thorough"
    )

    assert driver._write_and_record_chain_grouping_assurance(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    ) == []
    assert driver._validate_chain_grouping_assurance_phase_io(
        scratchpad=scratchpad,
        project_root=project_root,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    ) == []

    ledger = read_artifact_ledger(scratchpad)
    key = "sc/thorough/evm/claude/report_floor/chain_grouping_assurance"
    unit = ledger["work_units"][key]
    assert set(unit["artifacts"]) == {
        "scratchpad:chain_grouping_assurance_reconciliation.json",
        "scratchpad:chain_grouping_assurance_limitations.md",
    }
    assert "scratchpad:report_disposition_authority.json" in unit[
        "input_bindings"
    ]
    assert "scratchpad:verification_queue.work_plan.json" in unit[
        "input_bindings"
    ]

    assert driver._refresh_assurance_projection(
        checkpoint, scratchpad, config
    ) == []
    ledger = read_artifact_ledger(scratchpad)
    assurance_key = (
        "sc/thorough/evm/claude/report_floor/assurance_projection"
    )
    assurance_inputs = ledger["work_units"][assurance_key]["input_bindings"]
    assert "scratchpad:chain_grouping_assurance_reconciliation.json" in (
        assurance_inputs
    )
    assert "scratchpad:chain_grouping_assurance_limitations.md" in (
        assurance_inputs
    )

    # A downstream managed envelope append is outside this work unit and is
    # bound by the final assurance projection, not silently reblessed here.
    with (project_root / "AUDIT_REPORT.md").open("ab") as handle:
        handle.write(b"\n## Driver-owned final envelope\n")
    assert driver._validate_chain_grouping_assurance_phase_io(
        scratchpad=scratchpad,
        project_root=project_root,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    ) == []

    # Exact provider drift is independently replayed and cannot survive resume.
    with (scratchpad / "verify_INV-001.md").open("ab") as handle:
        handle.write(b"\nsource drift\n")
    issues = driver._validate_chain_grouping_assurance_phase_io(
        scratchpad=scratchpad,
        project_root=project_root,
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
    )
    assert issues and any("source" in issue.lower() for issue in issues)


def test_chain_grouping_assurance_precommit_crash_resumes_exact_prebind(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad, project_root = _setup_delivered_members(
        tmp_path, ("INV-001",)
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "scratchpad": str(scratchpad),
        "project_root": str(project_root),
        "_run_id": RUN_ID,
    }
    Checkpoint(run_id=RUN_ID).save(scratchpad)
    phase = next(item for item in SC_PHASES if item.name == "report_floor")
    real_commit = driver._commit_deterministic_driver_work_unit
    monkeypatch.setattr(
        driver,
        "_commit_deterministic_driver_work_unit",
        lambda **_kwargs: ["simulated crash before output commit"],
    )

    assert driver._write_and_record_chain_grouping_assurance(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    ) == ["simulated crash before output commit"]
    key = (
        "sc/thorough/evm/claude/report_floor/chain_grouping_assurance"
    )
    unit = read_artifact_ledger(scratchpad)["work_units"][key]
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert unit["artifacts"] == {}
    assert (scratchpad / ASSURANCE_FILE).is_file()
    assert (scratchpad / LIMITATIONS_FILE).is_file()

    monkeypatch.setattr(
        driver, "_commit_deterministic_driver_work_unit", real_commit
    )
    assert driver._write_and_record_chain_grouping_assurance(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    ) == []
    unit = read_artifact_ledger(scratchpad)["work_units"][key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"


def test_report_floor_orders_all_report_mutations_before_delivery_receipts() -> None:
    source = inspect.getsource(driver.main)
    floor = source.index('if phase.name == "report_floor"')
    external_note = source.index(
        "_append_external_research_appendix_note(", floor
    )
    disposition_transaction = source.index(
        "_run_report_disposition_phase_io(", floor
    )
    chain_assurance = source.index(
        "_write_and_record_chain_grouping_assurance(",
        disposition_transaction,
    )
    assurance_projection = source.index(
        "_refresh_assurance_projection(", chain_assurance
    )

    assert (
        external_note
        < disposition_transaction
        < chain_assurance
        < assurance_projection
    )


def test_missing_group_member_projects_into_canonical_assurance_manifest(
    tmp_path: Path,
) -> None:
    scratchpad, project_root = _setup_delivered_members(tmp_path, ("INV-001",))
    receipt = write_chain_grouping_assurance(
        scratchpad, project_root, run_id=RUN_ID
    )
    assert receipt["assurance_debt_count"] == 1
    checkpoint = Checkpoint(run_id=RUN_ID)

    assert project_assurance_limitations(
        checkpoint, scratchpad, project_root / "AUDIT_REPORT.md"
    ) == 1

    manifest = json.loads(
        (scratchpad / "assurance_limitations.json").read_text(encoding="utf-8")
    )
    assert manifest["clean_full_audit_claim_allowed"] is False
    assert manifest["rows"] == [
        {
            "phase": "chain",
            "work_unit_id": "INV-002",
            "state": "COMPLETED_WITH_DEBT",
            "assurance_impact": "DISCOVERY_RECALL",
            "gate_id": "chain_group_member_delivery_incomplete",
            "gate_class": "METHODOLOGY_APPLICATION",
            "affected_identities": ["INV-002"],
            "message": (
                "Exact chain-group member did not independently traverse: "
                "CURRENT_QUEUE_WORK_ITEM, CURRENT_QUEUE_WORK_PLAN, "
                "CURRENT_VERIFIER_ROSTER, EXACT_VERIFIER_EXECUTION, "
                "EXACT_REPORT_DELIVERY; source_record_sha256="
                + receipt["assurance_debts"][0]["source_record_sha256"]
            ),
            "failure_instance_id": receipt["assurance_debts"][0]["debt_sha256"],
        }
    ]
    assert validate_assurance_projection(
        checkpoint, scratchpad, project_root / "AUDIT_REPORT.md"
    ) == []
