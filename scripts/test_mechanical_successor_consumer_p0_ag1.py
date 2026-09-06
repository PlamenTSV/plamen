"""Consumer-side contract for immutable mechanical successor authority.

The mechanical executor owns receipt creation.  These fixtures pin the other
half of that boundary: the driver and report consumers may not mutate verifier
Markdown after the receipt, and may only promote/demote execution evidence
when the verdict row and successor authority validate together.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import inspect
import json
from pathlib import Path

import mechanical_verify as MV
import pytest
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from mechanical_successor_receipts import apply_mechanical_successor
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract
import plamen_driver as D
import plamen_parsers as P
import plamen_validators as V
from queue_work_items import (
    LineageLink,
    QueueWorkItem,
    SeverityProposal,
    VerifierOutputIdentity,
    VerifierOutputReceipt,
    build_queue_work_plan,
)
from report_index_machinery import (
    _verification_status,
    build_report_index_candidates_json,
)
from test_r10_demotion_gate import _authenticated_r10_report_prework_fixture


RUN_ID = "11111111-1111-4111-8111-111111111111"
DRIVER_ID = "sha256:" + "d" * 64


def _queue(scratchpad: Path) -> QueueWorkItem:
    item = QueueWorkItem(
        candidate_identity="H-01",
        work_item_id="H-01",
        lineage=(
            LineageLink(
                identity="H-01",
                relation="ORIGIN",
                source_artifact="findings_inventory.md",
            ),
        ),
        aliases=(),
        constituents=(),
        severity_proposal=SeverityProposal(level="High"),
        evidence_class="unclassified",
        bug_class="structural",
        preferred_tag="[CODE-TRACE]",
        queue_priority=1,
        location_records=(),
        primary_artifacts=("findings_inventory.md",),
        poc_class="structural",
        title="Bound finding",
    )
    P._write_queue_work_item_records_manifest(
        scratchpad / "verification_queue.md", (item,)
    )
    return item


def _bound_fixture(
    scratchpad: Path,
    *,
    mechanical_status: str = "FAIL",
) -> tuple[Path, bytes]:
    scratchpad.mkdir(parents=True, exist_ok=True)
    item = _queue(scratchpad)
    original = (
        b"# Verification: H-01\n\n"
        b"**Verdict**: CONFIRMED\n"
        b"**Severity**: High\n"
        b"**Evidence Tag**: [POC-PASS]\n"
        b"**Location**: src/A.sol:7\n"
        b"```solidity\nassertEq(actual, expected);\n```\n"
    )
    verify_path = scratchpad / "verify_H-01.md"
    verify_path.write_bytes(original)
    proposal_value = {
        "schema_version": "plamen.severity_proposal.v1",
        "candidate_id": "H-01",
        "constituent_ids": ["H-01"],
        "impact": {
            "class": "High",
            "harmed_asset": "protocol-controlled value",
            "harmed_capability": "availability",
            "premise_id": "PREM-I-1",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-I-1"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "likelihood": {
            "class": "Medium",
            "actor": "unprivileged caller",
            "preconditions": ["reachable state"],
            "premise_id": "PREM-L-1",
            "premise_kind": "INTERNAL",
            "evidence_ids": ["EVID-L-1"],
            "proof_scope": "IN_SCOPE_SOURCE",
        },
        "modifiers": [],
        "proposed_severity": "High",
        "adjustment": None,
        "constituent_premise_outcomes": {
            "H-01": {"impact": "SUPPORTED", "likelihood": "SUPPORTED"}
        },
    }
    proposal = json.dumps(
        proposal_value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    (scratchpad / "verify_H-01.severity_proposal.json").write_bytes(proposal)
    plan = build_queue_work_plan(
        (item,),
        {"sc_verify_shard_a": ("H-01",)},
        planner_version="test.plan.v1",
    )
    (scratchpad / "verification_queue.work_plan.json").write_bytes(
        (plan.to_json() + "\n").encode("utf-8")
    )
    identity = VerifierOutputIdentity.for_assignment(
        item,
        plan,
        "sc_verify_shard_a",
    )
    (scratchpad / "verify_H-01.identity.json").write_text(
        json.dumps(identity.to_dict(), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    receipt = VerifierOutputReceipt.bind(
        identity,
        original,
        severity_proposal=proposal,
        launch_digest="c" * 64,
        verifier_backend="claude",
    )
    (scratchpad / "verify_H-01.receipt.json").write_text(
        receipt.to_json(), encoding="utf-8"
    )

    result = MV.ExecResult(
        verify_file="verify_H-01.md",
        finding_id="H-01",
        language="evm",
        test_file_resolved="test/H01.t.sol",
        test_function="test_H01",
        test_command_used="forge test --match-test test_H01 -vv",
        status=mechanical_status,
        duration_s=1.0,
        stdout_tail=(
            "1 passed; 0 failed" if mechanical_status == "PASS"
            else "1 failed; 0 passed"
        ),
        recommended_tag=MV._recommended_tag(mechanical_status),
        race_mode=False,
    )
    manifest = {
        "generated_at": "2026-07-18T12:00:00",
        "counts": {mechanical_status: 1},
        "results": [asdict(result)],
    }
    manifest_path = scratchpad / "mechanical_verify_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    MV._write_verdict_manifest([result], scratchpad)
    apply_mechanical_successor(
        verify_path,
        asdict(result),
        manifest_path,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
    )
    MV._write_successor_authority_summary(
        scratchpad,
        run_identity=RUN_ID,
        driver_identity=DRIVER_ID,
        committed=1,
        rejections=[],
    )
    return verify_path, original


def _authority_view(scratchpad: Path) -> dict:
    return V._mechanical_successor_authority_view(scratchpad)


def _write_report_index(
    scratchpad: Path,
    *,
    status_column: str = "Verification",
    status: str = "CONFIRMED",
) -> Path:
    path = scratchpad / "report_index.md"
    path.write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        f"| Report ID | Title | Severity | Location | {status_column} | Trust Adj. | Internal Hypothesis |\n"
        "|---|---|---|---|---|---|---|\n"
        f"| H-01 | Bound finding | High | src/A.sol:7 | {status} | - | H-01 |\n",
        encoding="utf-8",
    )
    return path


def test_bound_inflated_prose_is_contested_without_rewriting_verifier_bytes(tmp_path):
    verify_path, original = _bound_fixture(tmp_path)
    before = verify_path.read_bytes()

    view = _authority_view(tmp_path)
    statuses = V._expected_report_index_statuses(tmp_path)

    assert view["status"] == "CLEAN"
    assert view["verdicts"]["H-01"]["authority_state"] == "BOUND"
    assert view["verdicts"]["H-01"]["integrity_state"] == "INFLATED_PROSE"
    assert statuses == {"H-01": "CONTESTED"}
    assert verify_path.read_bytes() == before
    assert verify_path.read_bytes().startswith(original)
    assert b"**Verdict**: CONFIRMED" in verify_path.read_bytes()


def test_unbound_or_tampered_successor_preserves_candidate_and_severity_but_never_verified(
    tmp_path,
):
    verify_path, _ = _bound_fixture(tmp_path, mechanical_status="PASS")
    receipt_path = tmp_path / "verify_H-01.mechanical_successor.receipt.json"
    receipt_path.write_bytes(receipt_path.read_bytes() + b"tamper")

    view = _authority_view(tmp_path)
    payload = build_report_index_candidates_json(tmp_path)
    row = payload["candidates"][0]

    assert view["status"] == "DEGRADED"
    assert view["verdicts"]["H-01"]["authority_state"] == "UNBOUND"
    assert V._expected_report_index_statuses(tmp_path) == {"H-01": "CONFIRMED"}
    assert row["canonical_id"] == "H-01"
    assert row["upstream_severity"] == "High"
    assert row["effective_severity_after_verdict_manifest"] == "High"
    assert row["mechanical_authority_state"] == "UNBOUND"
    assert _verification_status(row) == "CONFIRMED"


def test_report_candidate_uses_bound_manifest_demotion_and_retains_body_eligibility(
    tmp_path,
):
    _bound_fixture(tmp_path)

    payload = build_report_index_candidates_json(tmp_path)
    row = payload["candidates"][0]

    assert payload["row_count"] == 1
    assert row["integrity_state"] == "INFLATED_PROSE"
    assert row["effective_tag"] == "[CODE-TRACE] [INTEGRITY-DOWNGRADE]"
    assert row["mechanical_authority_state"] == "BOUND"
    assert row["effective_severity_after_verdict_manifest"] == "High"
    assert _verification_status(row) == "CONTESTED"
    assert "REPORTABLE" in row["allowed_actions"]


def test_report_index_status_is_bound_to_validated_successor_authority(tmp_path):
    _bound_fixture(tmp_path)
    index = _write_report_index(tmp_path)

    wrong = V._validate_report_index_status_authority(tmp_path)

    assert len(wrong) == 1
    assert "H-01" in wrong[0]
    assert "expected CONTESTED" in wrong[0]
    assert "found CONFIRMED" in wrong[0]

    receipt = V._project_report_index_status_authority(tmp_path)

    assert receipt["status"] == "CLEAN"
    assert receipt["authority_denominator_count"] == 1
    assert "| CONTESTED |" in index.read_text(encoding="utf-8")
    assert V._validate_report_index_status_authority(tmp_path) == []
    assert V._validate_report_index_inputs(tmp_path) == []


@pytest.mark.parametrize("status_column", ["Verification", "Verdict"])
def test_status_projection_is_idempotent_for_sc_and_l1_tables(
    tmp_path, status_column
):
    verify_path, verifier_bytes = _bound_fixture(tmp_path)
    index = _write_report_index(
        tmp_path, status_column=status_column, status="H-01; CONFIRMED"
    )

    first = V._project_report_index_status_authority(tmp_path)
    first_index = index.read_bytes()
    first_receipt = (tmp_path / "report_index_status_projection.json").read_bytes()
    second = V._project_report_index_status_authority(tmp_path)

    assert first == second
    assert index.read_bytes() == first_index
    assert (tmp_path / "report_index_status_projection.json").read_bytes() == first_receipt
    assert "H-01; CONTESTED" in index.read_text(encoding="utf-8")
    assert verify_path.read_bytes().startswith(verifier_bytes)
    assert V._validate_report_index_status_authority(tmp_path) == []


def test_status_projection_rejects_stale_index_and_tampered_receipt(tmp_path):
    _bound_fixture(tmp_path)
    index = _write_report_index(tmp_path)
    V._project_report_index_status_authority(tmp_path)

    index.write_text(
        index.read_text(encoding="utf-8").replace(
            "Bound finding", "Tampered title"
        ),
        encoding="utf-8",
    )
    assert "stale" in V._validate_report_index_status_authority(tmp_path)[0]

    V._project_report_index_status_authority(tmp_path)
    receipt = tmp_path / "report_index_status_projection.json"
    receipt.write_bytes(receipt.read_bytes() + b"tamper")
    assert "invalid" in V._validate_report_index_status_authority(tmp_path)[0]


def test_status_projection_marks_ambiguous_status_columns_as_typed_debt(tmp_path):
    _bound_fixture(tmp_path)
    index = tmp_path / "report_index.md"
    index.write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Verification | Verdict | Internal Hypothesis |\n"
        "|---|---|---|---|---|---|\n"
        "| H-01 | Bound finding | High | CONFIRMED | VERIFIED | H-01 |\n",
        encoding="utf-8",
    )

    receipt = V._project_report_index_status_authority(tmp_path)

    assert receipt["status"] == "DEGRADED"
    assert any(
        "column is not singular" in issue
        for issue in receipt["projection_issues"]
    )
    assert V._report_index_status_projection_debt(tmp_path)


def test_consolidation_cannot_resurrect_an_integrity_contested_constituent(
    tmp_path,
):
    _bound_fixture(tmp_path)
    queue = tmp_path / "verification_queue.md"
    queue.write_text(
        queue.read_text(encoding="utf-8").replace(
            "| H-01 | High | Bound finding | src/A.sol:7 | verify_H-01.md |\n",
            "| H-01 | High | Bound finding | src/A.sol:7 | verify_H-01.md |\n"
            "| H-02 | High | Confirmed sibling | src/B.sol:8 | verify_H-02.md |\n",
        ),
        encoding="utf-8",
    )
    (tmp_path / "verify_H-02.md").write_text(
        "# Verification: H-02\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Evidence Tag**: [CODE-TRACE]\n"
        "**Location**: src/B.sol:8\n",
        encoding="utf-8",
    )
    index = tmp_path / "report_index.md"
    index.write_text(
        "# Report Index\n\n"
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Verification | Internal Hypothesis |\n"
        "|---|---|---|---|---|\n"
        "| H-01 | Consolidated root cause | High | VERIFIED | H-01, H-02 |\n",
        encoding="utf-8",
    )

    receipt = V._project_report_index_status_authority(tmp_path)

    assert receipt["bindings"][0]["expected_status"] == "CONTESTED"
    assert "| CONTESTED |" in index.read_text(encoding="utf-8")
    assert "| VERIFIED |" not in index.read_text(encoding="utf-8")
    assert V._validate_report_index_status_authority(tmp_path) == []


def test_missing_successor_authority_projects_fail_open_status_and_typed_debt(
    tmp_path,
):
    _bound_fixture(tmp_path, mechanical_status="PASS")
    (tmp_path / "mechanical_successor_authority.json").unlink()
    index = _write_report_index(tmp_path, status="VERIFIED")

    receipt = V._project_report_index_status_authority(tmp_path)

    assert receipt["authority_status"] == "DEGRADED"
    assert receipt["status"] == "DEGRADED"
    assert receipt["authority_denominator_count"] == 1
    assert receipt["authority_debt"]
    assert "CONFIRMED" in index.read_text(encoding="utf-8")
    assert "VERIFIED" not in index.read_text(encoding="utf-8")
    assert V._validate_report_index_status_authority(tmp_path) == []
    assert V._report_index_status_projection_debt(tmp_path)


def test_clean_executor_manifest_cannot_omit_queue_denominator(tmp_path):
    _bound_fixture(tmp_path, mechanical_status="PASS")
    result_path = tmp_path / "mechanical_verify_manifest.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["counts"] = {}
    result["results"] = []
    result_path.write_text(json.dumps(result), encoding="utf-8")
    verdict_path = tmp_path / "verdict_manifest.json"
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    verdict["row_count"] = 0
    verdict["verdicts"] = []
    verdict_path.write_text(json.dumps(verdict), encoding="utf-8")
    (tmp_path / "mechanical_successor_authority.json").unlink()
    _write_report_index(tmp_path, status="VERIFIED")

    assert V._mechanical_successor_authority_view(tmp_path)["status"] == "CLEAN"
    receipt = V._project_report_index_status_authority(tmp_path)

    assert receipt["authority_denominator_count"] == 1
    assert receipt["status"] == "DEGRADED"
    assert any("omitted queue identity H-01" in row for row in receipt["authority_debt"])
    assert "CONFIRMED" in (tmp_path / "report_index.md").read_text(
        encoding="utf-8"
    )
    assert V._validate_report_index_status_authority(tmp_path) == []


def test_legacy_index_without_mechanical_authority_keeps_legacy_status(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    _queue(tmp_path)
    (tmp_path / "verify_H-01.md").write_text(
        "# Verification: H-01\n\n"
        "**Verdict**: CONFIRMED\n"
        "**Severity**: High\n"
        "**Evidence Tag**: [POC-PASS]\n"
        "**Location**: src/A.sol:7\n"
        "Execution evidence is present and the candidate remains reportable.\n",
        encoding="utf-8",
    )
    index = _write_report_index(tmp_path, status="VERIFIED")

    assert V._validate_report_index_status_authority(tmp_path) == []
    receipt = V._project_report_index_status_authority(tmp_path)

    assert receipt["authority_status"] == "ABSENT"
    assert receipt["authority_denominator_count"] == 0
    assert receipt["status"] == "CLEAN"
    assert "VERIFIED" in index.read_text(encoding="utf-8")
    assert V._validate_report_index_status_authority(tmp_path) == []


def test_assembler_body_status_revalidates_projection_receipt(tmp_path):
    _bound_fixture(tmp_path)
    _write_report_index(tmp_path, status="CONTESTED")
    (tmp_path / "report_coverage.md").write_text(
        "# Report Coverage\n", encoding="utf-8"
    )
    V._project_report_index_status_authority(tmp_path)

    wrong = "## High Findings\n\n### [H-01] Bound finding [VERIFIED]\n\nBody.\n"
    right = wrong.replace("[VERIFIED]", "[CONTESTED]")

    issues = V._validate_report_body_status_authority(tmp_path, wrong)
    assert issues and "expected CONTESTED" in issues[0]
    assert V._validate_report_body_status_authority(tmp_path, right) == []

    relocated = (
        "## Appendix C: Quality & Hardening Observations\n\n"
        "| ID | Severity | Title | Location | Reason |\n"
        "|---|---|---|---|---|\n"
        "| H-01 | High | Bound finding | src/A.sol:7 | quality only |\n"
    )
    assert V._validate_report_body_status_authority(tmp_path, relocated) == []


def test_driver_projects_degraded_authority_as_report_index_phase_debt(tmp_path):
    _bound_fixture(tmp_path, mechanical_status="PASS")
    (tmp_path / "mechanical_successor_authority.json").unlink()
    _write_report_index(tmp_path, status="VERIFIED")

    assert D._project_report_index_status_with_debt(tmp_path) == []

    sentinel = tmp_path / "report_index.degraded"
    assert sentinel.is_file()
    assert "REPORT_INDEX_STATUS_AUTHORITY_DEBT" in sentinel.read_text(
        encoding="utf-8"
    )
    receipt = json.loads(
        (tmp_path / "report_index_status_projection.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["status"] == "DEGRADED"
    assert V._validate_report_index_inputs(tmp_path) == []

    phase = next(p for p in D.SC_PHASES if p.name == "report_index")
    checkpoint = D.Checkpoint(run_id=RUN_ID)
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "_run_id": RUN_ID,
    }
    commit = D._commit_phase_from_disk_debt(
        phase, checkpoint, tmp_path, config, [phase], clean_transients=True
    )
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert phase.name in checkpoint.completed
    assert phase.name in checkpoint.degraded


def test_status_projection_receipt_is_canonical_owned_routing_input(
    tmp_path, monkeypatch
):
    _validator, driver, scratchpad, config, prework_contract, _launch = (
        _authenticated_r10_report_prework_fixture(
            tmp_path,
            monkeypatch,
            fired=True,
            backend="codex",
            suppress_candidate_inputs=False,
            split_parent_linkage=True,
            live_t9=True,
        )
    )
    assert config == {
        "_run_id": "run-r10-phaseio-test",
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "core",
        "language": "evm",
        "cli_backend": "codex",
        "scratchpad": str(scratchpad),
        "claude_exec_mode": "headless",
    }
    ready, issues = driver._run_report_index_prework_transaction(
        scratchpad, config
    )
    assert (ready, issues) == (True, [])
    assert driver._r10_report_consumer_ready_issues(
        scratchpad, config
    ) == []

    prework_ledger = read_artifact_ledger(scratchpad)
    prework = prework_ledger["work_units"][prework_contract.key]
    assert prework["run_id"] == config["_run_id"]
    assert prework["semantic_status"] == "ACTIVE"
    assert prework["execution_state"] == "OUTPUT_COMMITTED"
    conditional = prework["explicit_absence_authority"]
    expected_roster = sorted(
        f"scratchpad:{name}"
        for name in driver._R10_REPORT_PREWORK_ROSTER
    )
    assert conditional["roster_identities"] == expected_roster
    assert sorted(
        conditional["present_identities"]
        + conditional["absent_identities"]
    ) == expected_roster
    assert conditional["run_id"] == config["_run_id"]
    assert conditional["work_unit_key"] == prework_contract.key

    phase = next(
        p for p in driver.SC_PHASES if p.name == "report_index"
    )
    model_contract, _model_launch = (
        driver._typed_model_phase_contract_and_launch(
            phase, scratchpad, config
        )
    )
    assert model_contract is not None
    assert {
        (
            "scratchpad:_live_verify_queue_transaction/t0/"
            "resolved_plan.json"
        ),
        "scratchpad:verification_queue.work_items.json",
        "scratchpad:verify_queue_transaction.receipt.json",
    } <= set(model_contract.immutable_inputs)
    assert not {
        f"scratchpad:{name}"
        for name in driver._R10_REPORT_PREWORK_ROSTER
    } & set(model_contract.immutable_inputs)
    assert driver._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []

    (scratchpad / "report_index.md").write_text(
        "\n".join([
            "# Report Index",
            "",
            "## Summary Counts",
            "",
            "| Severity | Count |",
            "|---|---|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 0 |",
            "| Low | 1 |",
            "| Informational | 0 |",
            "| Total | 1 |",
            "",
            "## Master Finding Index",
            "",
            (
                "| Report ID | Title | Severity | Location | Verification | "
                "Trust Adj. | Internal Hypothesis |"
            ),
            "|---|---|---|---|---|---|---|",
            (
                "| L-01 | split-parent external premise | Low | "
                "src/lib.rs:L42 | CONTESTED | - | H-22 |"
            ),
            "",
            "## Excluded Findings",
            "",
            "| Source ID | Reason |",
            "|---|---|",
            "",
            "## Fixture Padding",
            "",
            "strict-split-parent-r10-retention " * 24,
            "",
        ]),
        encoding="utf-8",
    )
    (scratchpad / "report_coverage.md").write_text(
        "# Report Coverage\n\n"
        "## Raw Candidate Ledger\n\n"
        "| Source Artifact | Candidate ID | Disposition |\n"
        "|---|---|---|\n"
        "| verify_H-22.md | H-22 | PROMOTED L-01 |\n\n"
        + ("strict-split-parent-r10-coverage " * 24)
        + "\n",
        encoding="utf-8",
    )
    _model, model_issues = driver._record_report_index_model_preimage(
        phase, scratchpad, config
    )
    assert model_issues == []
    assert driver._run_report_index_canonicalization_transaction(
        phase, scratchpad, config
    ) == []
    _manifests, issues = driver._run_report_index_routing_transaction(
        scratchpad, config
    )
    assert issues == []

    ledger = read_artifact_ledger(scratchpad)
    routing = next(
        unit
        for key, unit in ledger["work_units"].items()
        if key.endswith("/report_index/routing")
    )
    canonical = next(
        unit
        for key, unit in ledger["work_units"].items()
        if key.endswith("/report_index/canonicalize")
    )
    identity = "scratchpad:report_index_status_projection.json"
    receipt_record = canonical["artifacts"][identity]
    assert receipt_record["writer"] == "DRIVER"
    assert receipt_record["status"] == "ACTIVE"
    assert identity in routing["input_bindings"]
    assert routing["input_bindings"][identity][
        "producer_work_unit_key"
    ] == canonical["work_unit_key"]


def test_skeptic_manifest_consumes_effective_bound_evidence_not_inflated_prose(
    tmp_path,
):
    _bound_fixture(tmp_path)

    rows = V._skeptic_expected_findings(tmp_path)

    assert len(rows) == 1
    assert rows[0]["finding_id"] == "H-01"
    assert rows[0]["evidence_tag"] == "[CODE-TRACE] [INTEGRITY-DOWNGRADE]"
    assert rows[0]["integrity_state"] == "INFLATED_PROSE"
    assert rows[0]["mechanical_authority_state"] == "BOUND"
    assert rows[0]["verdict_status"] == "CONTESTED"


def test_authority_view_is_read_only_and_idempotent(tmp_path):
    verify_path, _ = _bound_fixture(tmp_path)
    paths = sorted(path for path in tmp_path.iterdir() if path.is_file())
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}

    first = _authority_view(tmp_path)
    second = _authority_view(tmp_path)
    after = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(tmp_path.iterdir())
        if path.is_file()
    }

    assert first == second
    assert before == after
    assert verify_path.read_bytes()


def test_driver_has_no_post_receipt_verify_markdown_mutation_path():
    source = inspect.getsource(D.main)
    branch = source[
        source.index('if phase.name in ("sc_mechanical_verify", "mechanical_verify"):'):
        source.index("# v2.3.11: report_assemble", source.index(
            'if phase.name in ("sc_mechanical_verify", "mechanical_verify"):'
        ))
    ]

    assert "flip_verdict_on_integrity_downgrade" not in branch
    assert "vf.write_text" not in branch
    assert "_vf.write_text" not in branch
    assert "_validate_poc_pass_integrity" not in branch


def test_mechanical_precommit_rejection_becomes_typed_phase_debt(tmp_path):
    _bound_fixture(tmp_path, mechanical_status="PASS")
    receipt_path = tmp_path / "verify_H-01.mechanical_successor.receipt.json"
    receipt_path.write_bytes(receipt_path.read_bytes() + b"tamper")
    (tmp_path / "mechanical_verify_manifest.md").write_text(
        "# Mechanical Verify Manifest\n\n**Total verify files**: 1\n",
        encoding="utf-8",
    )
    phase = next(p for p in D.SC_PHASES if p.name == "sc_mechanical_verify")
    config = {
        "project_root": str(tmp_path),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "_run_id": RUN_ID,
    }

    issues = D._validate_verification_precommit(phase, tmp_path, config, [])

    assert any("MECHANICAL_SUCCESSOR_AUTHORITY" in issue for issue in issues)

    checkpoint = D.Checkpoint(run_id=RUN_ID)
    commit = D._commit_verification_transaction(
        phase,
        checkpoint,
        tmp_path,
        config,
        [phase],
        clean_transients=True,
    )
    assert commit.state == "COMPLETED_WITH_DEBT"
    assert phase.name in checkpoint.completed
    assert (tmp_path / f"{phase.name}.degraded").is_file()
    assert "MECHANICAL_SUCCESSOR_AUTHORITY" in (
        tmp_path / f"{phase.name}.degraded"
    ).read_text(encoding="utf-8")
