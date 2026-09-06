"""NC-5 mandatory reopened-candidate lifecycle regression fixtures.

These fixtures are intentionally protocol-neutral.  They exercise identity,
assignment, completion, and delivery authority without treating report prose
or a verifier's negative conclusion as terminal authority.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest

import mandatory_reverification as M
from queue_work_items import (
    QueueWorkItem,
    build_queue_work_plan,
    queue_records_to_json,
)


def _function_ast(function: object) -> ast.FunctionDef:
    """Parse one live function without depending on source offsets/text slices."""

    module = ast.parse(inspect.getsource(function))
    node = module.body[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def _call_name(call: ast.Call) -> str:
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _ordered_calls(node: ast.AST) -> list[tuple[int, str]]:
    return sorted(
        (call.lineno, _call_name(call))
        for call in ast.walk(node)
        if isinstance(call, ast.Call) and _call_name(call)
    )


def _mapping_get_is_not_true(
    node: ast.AST,
    *,
    receiver: str,
    key: str,
) -> bool:
    """Recognize ``mapping.get(key) is not True`` by AST semantics."""

    if not (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.IsNot)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value is True
        and isinstance(node.left, ast.Call)
        and isinstance(node.left.func, ast.Attribute)
        and node.left.func.attr == "get"
        and isinstance(node.left.func.value, ast.Name)
        and node.left.func.value.id == receiver
        and len(node.left.args) >= 1
        and isinstance(node.left.args[0], ast.Constant)
    ):
        return False
    return node.left.args[0].value == key


from finding_producer_registry import (
    canonical_digest,
    write_application_skeptic_proposal_projection,
)


@pytest.fixture(autouse=True)
def _isolate_legacy_mandatory_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep legacy NC-5 fixtures scoped to their declared proposal sources."""

    import security_obligation_authority as S

    monkeypatch.setattr(
        S,
        "read_pending_security_obligation_verification",
        lambda _scratchpad: [],
    )


def _item(
    work_id: str,
    *,
    severity: str = "Low",
    constituents: tuple[str, ...] = (),
) -> QueueWorkItem:
    return QueueWorkItem.from_legacy_row(
        {
            "finding id": work_id,
            "severity": severity,
            "title": f"Candidate {work_id}",
            "bug class": "state-transition",
            "preferred tag": "CODE-TRACE",
            "location": "src/Module.sol:L10",
            "primary artifact": "application_skeptic_proposals.md",
            "poc class": "structural",
            "constituents": list(constituents),
            "effective evidence scope": "IN_SCOPE_SOURCE",
            "effective proof scope": "ANALYTICAL",
            "effective harm scope": "UNPROVEN",
        }
    )


def _candidate(
    candidate_id: str,
    *,
    source_id: str,
    source_obligation: str,
    kind: str = "ADDITIVE_REOPEN",
) -> dict[str, object]:
    return {
        "obligation_kind": kind,
        "candidate_id": candidate_id,
        "source_candidate_id": source_id,
        "source_artifact": "application_skeptic_proposals.md",
        "source_artifact_sha256": "a" * 64,
        "source_proposal_id": "ASCP-" + source_id.replace("-", "")[:8].upper(),
        "source_obligation_id": source_obligation,
        "candidate_content_sha256": "b" * 64,
        "premise": "A reachable transition remains unevaluated.",
        "harm": "A protected state property may be violated.",
        "evidence": "src/Module.sol:L10-L18",
    }


def _denominator(*rows: dict[str, object]) -> dict[str, object]:
    return M.build_mandatory_reverification_denominator(
        run_id="run-nc5",
        candidates=list(rows),
        source_bindings=[{
            "artifact": "application_skeptic_proposals.md",
            "sha256": "a" * 64,
        }],
    )


def test_low_confidence_reopen_survives_all_ordinary_filters() -> None:
    denominator = _denominator(
        _candidate("INV-101", source_id="ASKP-1", source_obligation="ASW-1")
    )
    low = _item("INV-101", severity="Low")

    active, routing = M.route_mandatory_reverification(
        denominator=denominator,
        active_items=(),
        fallback_items=(low,),
    )

    assert active == (low,)
    assert routing["status"] == "READY"
    assert routing["routes"][0]["routing_kind"] == "RESTORED_AFTER_FILTER"
    assert routing["routes"][0]["ordinary_filter_bypass"] is True
    assert routing["routes"][0]["assigned_work_item_id"] == "INV-101"


def test_grouped_reopens_preserve_every_constituent_and_exact_binding() -> None:
    first = _candidate("INV-201", source_id="ASKP-1", source_obligation="ASW-1")
    second = _candidate("INV-202", source_id="ASKP-2", source_obligation="ASW-2")
    denominator = _denominator(first, second)
    grouped = _item("INV-201", constituents=("INV-202",))

    active, routing = M.route_mandatory_reverification(
        denominator=denominator,
        active_items=(grouped,),
        fallback_items=(),
    )

    assert active == (grouped,)
    assert [row["assigned_work_item_id"] for row in routing["routes"]] == [
        "INV-201",
        "INV-201",
    ]
    for row in routing["routes"]:
        assert row["assigned_constituent_ids"] == ["INV-201", "INV-202"]
        assert row["route_binding_digest"]
    assert len({row["obligation_id"] for row in routing["routes"]}) == 2


def test_each_reopen_is_assigned_once_and_roster_is_exact() -> None:
    denominator = _denominator(
        _candidate("INV-301", source_id="ASKP-1", source_obligation="ASW-1"),
        _candidate("INV-302", source_id="ASKP-2", source_obligation="ASW-2"),
    )
    items = (_item("INV-301"), _item("INV-302"))
    active, routing = M.route_mandatory_reverification(
        denominator=denominator,
        active_items=items,
        fallback_items=(),
    )
    plan = build_queue_work_plan(
        active,
        {"sc_verify_medium_a": [item.work_item_id for item in active]},
        planner_version="test.nc5",
    )
    roster = {
        "parent_queue_work_plan_digest": plan.digest,
        "ordered_work_item_ids": list(plan.ordered_work_item_ids),
        "work_units": [
            {"work_unit_id": "verify-medium-0001", "ordered_work_item_ids": ["INV-301"]},
            {"work_unit_id": "verify-medium-0002", "ordered_work_item_ids": ["INV-302"]},
        ],
        "roster_digest": "c" * 64,
    }

    assignment = M.bind_mandatory_reverification_assignments(
        denominator=denominator,
        routing=routing,
        queue_plan=plan,
        roster=roster,
    )

    assert assignment["status"] == "ASSIGNED"
    assert assignment["assignment_count"] == 2
    assert len({row["obligation_id"] for row in assignment["assignments"]}) == 2
    assert all(row["assignment_count"] == 1 for row in assignment["assignments"])


def test_missing_or_unrelated_output_cannot_complete_an_obligation() -> None:
    denominator = _denominator(
        _candidate("INV-401", source_id="ASKP-1", source_obligation="ASW-1")
    )
    active, routing = M.route_mandatory_reverification(
        denominator=denominator,
        active_items=(_item("INV-401"),),
        fallback_items=(),
    )
    plan = build_queue_work_plan(
        active,
        {"sc_verify_medium_a": ["INV-401"]},
        planner_version="test.nc5",
    )
    roster = {
        "parent_queue_work_plan_digest": plan.digest,
        "ordered_work_item_ids": ["INV-401"],
        "work_units": [{
            "work_unit_id": "verify-medium-0001",
            "ordered_work_item_ids": ["INV-401"],
        }],
        "roster_digest": "c" * 64,
    }
    assignment = M.bind_mandatory_reverification_assignments(
        denominator=denominator,
        routing=routing,
        queue_plan=plan,
        roster=roster,
    )

    missing = M.reconcile_mandatory_reverification_completion(
        denominator=denominator,
        assignment=assignment,
        completion_evidence={},
    )
    unrelated = M.reconcile_mandatory_reverification_completion(
        denominator=denominator,
        assignment=assignment,
        completion_evidence={
            "INV-999": {
                "completion_authorized": True,
                "output_sha256": "d" * 64,
                "receipt_sha256": "e" * 64,
            }
        },
    )

    for receipt in (missing, unrelated):
        assert receipt["status"] == "COMPLETED_WITH_DEBT"
        assert receipt["completed_obligation_count"] == 0
        assert receipt["retry_work_item_ids"] == ["INV-401"]
        assert receipt["rows"][0]["completion_state"] == "RETRY_REQUIRED"


def test_exact_output_completes_only_its_bound_obligation() -> None:
    denominator = _denominator(
        _candidate("INV-501", source_id="ASKP-1", source_obligation="ASW-1"),
        _candidate("INV-502", source_id="ASKP-2", source_obligation="ASW-2"),
    )
    items = (_item("INV-501"), _item("INV-502"))
    active, routing = M.route_mandatory_reverification(
        denominator=denominator,
        active_items=items,
        fallback_items=(),
    )
    plan = build_queue_work_plan(
        active,
        {"sc_verify_medium_a": ["INV-501", "INV-502"]},
        planner_version="test.nc5",
    )
    roster = {
        "parent_queue_work_plan_digest": plan.digest,
        "ordered_work_item_ids": list(plan.ordered_work_item_ids),
        "work_units": [{
            "work_unit_id": "verify-medium-0001",
            "ordered_work_item_ids": list(plan.ordered_work_item_ids),
        }],
        "roster_digest": "c" * 64,
    }
    assignment = M.bind_mandatory_reverification_assignments(
        denominator=denominator,
        routing=routing,
        queue_plan=plan,
        roster=roster,
    )
    receipt = M.reconcile_mandatory_reverification_completion(
        denominator=denominator,
        assignment=assignment,
        completion_evidence={
            "INV-501": {
                "completion_authorized": True,
                "output_sha256": "d" * 64,
                "receipt_sha256": "e" * 64,
            },
        },
    )

    states = {row["candidate_id"]: row["completion_state"] for row in receipt["rows"]}
    assert states == {"INV-501": "EXACTLY_COMPLETED", "INV-502": "RETRY_REQUIRED"}


def test_report_delivery_never_masquerades_as_verification() -> None:
    denominator = _denominator(
        _candidate("INV-601", source_id="ASKP-1", source_obligation="ASW-1")
    )
    delivery = M.reconcile_mandatory_reverification_delivery(
        denominator=denominator,
        completion=None,
        report_routes={
            "INV-601": {
                "report_delivery_state": "DELIVERED_BODY",
                "public_report_ids": ["M-1"],
            }
        },
    )

    assert delivery["rows"][0]["report_delivery_state"] == "DELIVERED_BODY"
    assert delivery["rows"][0]["verification_state"] == "RETRY_REQUIRED"
    assert delivery["status"] == "COMPLETED_WITH_DEBT"


def test_resume_is_byte_idempotent_and_stale_or_malformed_bindings_fail_closed(
    tmp_path: Path,
) -> None:
    denominator = _denominator(
        _candidate("INV-701", source_id="ASKP-1", source_obligation="ASW-1")
    )
    path = tmp_path / "mandatory_reverification_denominator.json"
    assert M.write_or_validate_mandatory_artifact(path, denominator) is True
    before = path.read_bytes()
    assert M.write_or_validate_mandatory_artifact(path, denominator) is False
    assert path.read_bytes() == before

    malformed = json.loads(before)
    malformed["candidates"][0]["premise"] = "changed after binding"
    with pytest.raises(M.MandatoryReverificationError):
        M.validate_mandatory_reverification_denominator(malformed)

    stale = dict(denominator)
    stale["run_id"] = "other-run"
    with pytest.raises(M.MandatoryReverificationError):
        M.write_or_validate_mandatory_artifact(path, stale)


def test_recovery_rows_preserve_exact_premise_harm_evidence_and_obligation() -> None:
    denominator = _denominator(
        _candidate(
            "INV-801",
            source_id="INV-801",
            source_obligation="FLO-801",
            kind="RECOVERY_INDEPENDENT_VERIFICATION",
        )
    )

    rows = M.mandatory_recovery_rows(denominator)

    assert len(rows) == 1
    assert rows[0]["finding_lifecycle_obligation_id"] == "FLO-801"
    assert rows[0]["source_work_item_id"] == "INV-801"
    assert rows[0]["mechanism"] == "A reachable transition remains unevaluated."
    assert rows[0]["harm"] == "A protected state property may be violated."
    assert rows[0]["evidence"] == "src/Module.sol:L10-L18"
    assert rows[0]["independent_discriminator_required"] is True
    assert rows[0]["terminal_authority"] is False


def test_recovery_completion_requires_exact_obligation_and_contract_binding() -> None:
    denominator = _denominator(
        _candidate(
            "INV-802",
            source_id="INV-802",
            source_obligation="FLO-802",
            kind="RECOVERY_INDEPENDENT_VERIFICATION",
        )
    )
    candidate = denominator["candidates"][0]
    work_id = M.mandatory_recovery_rows(denominator)[0]["work_item_id"]
    unrelated = {
        "MRV-UNRELATED": {
            "obligation_id": "MRV-UNRELATED",
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "source_obligation_id": "FLO-802",
            "work_item_id": work_id,
            "completion_authorized": True,
            "output_sha256": "1" * 64,
            "receipt_sha256": "2" * 64,
            "contract_digest": "3" * 64,
            "execution_receipt_digest": "4" * 64,
        }
    }
    retry = M.reconcile_mandatory_recovery_completion(
        denominator=denominator,
        recovery_evidence=unrelated,
    )
    assert retry["rows"][0]["completion_state"] == "RETRY_REQUIRED"

    exact = {
        candidate["obligation_id"]: {
            "obligation_id": candidate["obligation_id"],
            "candidate_packet_sha256": candidate["candidate_packet_sha256"],
            "source_obligation_id": candidate["source_obligation_id"],
            "work_item_id": work_id,
            "completion_authorized": True,
            "output_sha256": "1" * 64,
            "receipt_sha256": "2" * 64,
            "contract_digest": "3" * 64,
            "execution_receipt_digest": "4" * 64,
        }
    }
    completed = M.reconcile_mandatory_recovery_completion(
        denominator=denominator,
        recovery_evidence=exact,
    )
    assert completed["assignment_authority_kind"] == "RECOVERY_CONTRACT"
    assert completed["rows"][0]["completion_state"] == "EXACTLY_COMPLETED"
    assert completed["rows"][0]["assigned_work_item_id"] == work_id
    assert completed["terminal_negative_authority"] is False


def _proposal(source_work: str, title: str) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": "plamen.finding_candidate_proposal.v1",
        "producer": "application_skeptic",
        "source_obligation_id": f"OBL-{source_work}",
        "source_work_item_id": "ASW-" + source_work * 24,
        "assessor_identity": "independent-assessor",
        "assessor_invocation_id": f"assessment-{source_work}",
        "assessor_evidence_sha256": source_work.lower() * 64,
        "candidate": {
            "title": title,
            "mechanism": "A bounded alternate transition remains reachable.",
            "harm": "A security-relevant state property may be violated.",
        },
    }
    digest = canonical_digest(unsigned)
    return {
        **unsigned,
        "proposal_id": "ASCP-" + digest[:24].upper(),
        "proposal_digest": digest,
    }


def _seed_inventory() -> str:
    return (
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Existing candidate\n"
        "**Source IDs**: [BASE-1]\n"
        "**Severity**: Medium\n"
        "**Location**: src/Base.sol:L1\n"
        "**Preferred Tag**: CODE-TRACE\n"
        "**Primary Artifact**: breadth_findings.md\n\n"
        "**Description**: Existing bounded candidate.\n"
    )


def test_disk_compiler_joins_both_additive_sources_to_inventory_exactly(
    tmp_path: Path,
) -> None:
    import plamen_validators as V

    (tmp_path / "findings_inventory.md").write_text(
        _seed_inventory(), encoding="utf-8"
    )
    first = _proposal("A", "Application reopen")
    second = _proposal("B", "Candidate-negative reopen")
    write_application_skeptic_proposal_projection(tmp_path, [first])
    write_application_skeptic_proposal_projection(
        tmp_path,
        [second],
        projection_name="candidate_negative_skeptic_proposals.md",
    )
    assert set(V._promote_depth_findings_to_inventory(tmp_path)) == {"ASKP-1"}

    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-disk"
    )

    assert denominator["status"] == "READY"
    assert denominator["source_obligation_count"] == 2
    assert denominator["candidate_count"] == 2
    assert denominator["input_debt_count"] == 0
    assert {
        row["source_artifact"] for row in denominator["candidates"]
    } == {
        "application_skeptic_proposals.md",
        "candidate_negative_skeptic_proposals.md",
    }
    assert len({row["candidate_id"] for row in denominator["candidates"]}) == 2
    assert all(row["premise"] and row["harm"] and row["evidence"] for row in denominator["candidates"])


def test_disk_queue_apply_restores_filtered_item_and_is_idempotent(
    tmp_path: Path,
) -> None:
    import plamen_parsers as P
    import plamen_validators as V

    (tmp_path / "findings_inventory.md").write_text(
        _seed_inventory(), encoding="utf-8"
    )
    proposal = _proposal("C", "Filtered reopen")
    write_application_skeptic_proposal_projection(tmp_path, [proposal])
    V._promote_depth_findings_to_inventory(tmp_path)
    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-queue"
    )
    candidate_id = denominator["candidates"][0]["candidate_id"]
    P._write_mechanical_verification_queue_from_inventory(tmp_path)
    active_rows = P.parse_verification_queue_rows(tmp_path)
    filtered = next(row for row in active_rows if row["finding id"] == candidate_id)
    P._write_queue_subset_manifest(
        tmp_path / "verification_queue.md",
        [row for row in active_rows if row["finding id"] != candidate_id],
    )
    P._write_queue_excluded_manifest(
        tmp_path / "verification_queue_evidence_excluded.md", [filtered]
    )

    routing = M.apply_primary_reopens_to_queue(tmp_path, denominator)
    first_queue = (tmp_path / "verification_queue.work_items.json").read_bytes()
    first_routing = (tmp_path / M.ROUTING_FILE).read_bytes()
    replay = M.apply_primary_reopens_to_queue(tmp_path, denominator)

    assert routing == replay
    assert (tmp_path / "verification_queue.work_items.json").read_bytes() == first_queue
    assert (tmp_path / M.ROUTING_FILE).read_bytes() == first_routing
    assert candidate_id in {
        item.work_item_id
        for item in P._read_typed_queue_work_items(
            tmp_path / "verification_queue.md"
        )
    }
    assert candidate_id not in {
        row["finding id"]
        for row in P._read_queue_json_sidecar(
            tmp_path / "verification_queue_evidence_excluded.md"
        )
    }


def test_queue_transaction_recovers_crash_without_route_drift_or_split_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import plamen_parsers as P
    import plamen_validators as V

    (tmp_path / "findings_inventory.md").write_text(
        _seed_inventory(), encoding="utf-8"
    )
    write_application_skeptic_proposal_projection(
        tmp_path, [_proposal("D", "Crash-bound reopen")]
    )
    V._promote_depth_findings_to_inventory(tmp_path)
    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-crash"
    )
    candidate_id = denominator["candidates"][0]["candidate_id"]
    P._write_mechanical_verification_queue_from_inventory(tmp_path)
    active_rows = P.parse_verification_queue_rows(tmp_path)
    filtered = next(row for row in active_rows if row["finding id"] == candidate_id)
    P._write_queue_subset_manifest(
        tmp_path / "verification_queue.md",
        [row for row in active_rows if row["finding id"] != candidate_id],
    )
    P._write_queue_excluded_manifest(
        tmp_path / "verification_queue_evidence_excluded.md", [filtered]
    )

    original = M._replace_mandatory_queue_transaction_file
    calls = 0

    def crash(path: Path, raw: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("fixture crash between fixed-path replacements")
        original(path, raw)

    monkeypatch.setattr(M, "_replace_mandatory_queue_transaction_file", crash)
    with pytest.raises(OSError, match="fixture crash"):
        M.apply_primary_reopens_to_queue(tmp_path, denominator)
    assert (tmp_path / M.QUEUE_TRANSACTION_JOURNAL_FILE).is_file()

    monkeypatch.setattr(
        M, "_replace_mandatory_queue_transaction_file", original
    )
    routing = M.apply_primary_reopens_to_queue(tmp_path, denominator)

    assert routing["routes"][0]["routing_kind"] == "RESTORED_AFTER_FILTER"
    assert not (tmp_path / M.QUEUE_TRANSACTION_JOURNAL_FILE).exists()
    assert (tmp_path / M.QUEUE_TRANSACTION_RECEIPT_FILE).is_file()
    typed = P._read_typed_queue_work_items(tmp_path / "verification_queue.md")
    assert candidate_id in {item.work_item_id for item in typed}
    assert candidate_id not in {
        row["finding id"]
        for row in P._read_queue_json_sidecar(
            tmp_path / "verification_queue_evidence_excluded.md"
        )
    }


def test_malformed_source_projection_becomes_bound_visible_input_debt(
    tmp_path: Path,
) -> None:
    (tmp_path / "application_skeptic_proposals.md").write_text(
        "### Finding [ASKP-1]: malformed\n", encoding="utf-8"
    )
    denominator = M.compile_primary_reopen_denominator(
        tmp_path, run_id="run-debt"
    )
    assert denominator["status"] == "COMPLETED_WITH_DEBT"
    assert denominator["source_obligation_count"] == 1
    assert denominator["candidate_count"] == 0
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"] == (
        "SOURCE_PROJECTION_UNBOUND_OR_MALFORMED"
    )


def test_report_reopen_compiler_enumerates_exact_recovery_obligation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finding_lifecycle_authority import (
        build_finding_lifecycle,
        candidate_content_sha256,
        finding_verification_work_items,
    )

    run_id = "run-report-reopen"
    inventory = (
        "# Findings Inventory\n\n"
        "### Finding [INV-901]: Reopened candidate\n"
        "**Source IDs**: [SRC-901]\n"
        "**Severity**: Medium\n"
        "**Location**: src/Module.sol:10-18\n"
        "**Primary Artifact**: depth_findings.md\n"
        "**Description**: A reachable alternate transition remains unevaluated.\n"
        "**Impact**: A protected state property may be violated.\n"
    )
    (tmp_path / "findings_inventory.md").write_text(inventory, encoding="utf-8")
    (tmp_path / "verification_queue.work_items.json").write_text(
        queue_records_to_json((_item("INV-901", severity="Medium"),))
        + "\n",
        encoding="utf-8",
    )
    candidate: dict[str, object] = {
        "schema_version": "plamen.finding_lifecycle_candidate.v1",
        "run_id": run_id,
        "candidate_id": "INV-901",
        "lineage_ids": ["INV-901", "SRC-901"],
        "source_artifact": "verification_queue.work_items.json",
        "source_artifact_sha256": "a" * 64,
        "source_record_sha256": "b" * 64,
        "producer_identity": "typed-verification-queue",
        "producer_invocation_id": "queue-run",
        "producer_phase": "verify_queue",
        "entry_reason": "NORMAL_DISCOVERY",
        "origin_assessment": "ACTIVE_VERIFICATION_WORK",
        "upstream_severity": "Medium",
        "title": "Reopened candidate",
        "location": "src/Module.sol:10-18",
        "evidence_pointer": "verify_INV-901.md",
        "candidate_content_sha256": "",
        "location_quality": "EXACT",
        "source_provenance_quality": "EXACT",
        "scope_state": "IN_SCOPE",
    }
    candidate["candidate_content_sha256"] = candidate_content_sha256(candidate)
    decision = {
        "schema_version": "plamen.finding_lifecycle_decision.v1",
        "run_id": run_id,
        "decision_id": "RDA-901",
        "candidate_id": "INV-901",
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "decision_kind": "AUTHORIZED_DEFERRED",
        "evidence_basis": "INDEPENDENT_ANALYSIS",
        "evidence_sha256": "c" * 64,
        "proof_scope": "MECHANISM_ONLY",
        "discriminator_identity": "independent-verifier",
        "discriminator_invocation_id": "verify-run",
        "discriminator_phase": "verify",
        "alias_target_candidate_id": None,
        "reason_class": "NEGATIVE_PROPOSAL_REQUIRES_TYPED_AUTHORITY",
        "next_action": "complete exact independent re-verification",
        "public_retention_target": "BODY",
        "scope_snapshot_sha256": None,
    }
    lifecycle = build_finding_lifecycle(
        run_id=run_id,
        candidates=[candidate],
        decisions=[decision],
        projections=[],
        authority_identity="driver-report",
        authority_invocation_id="report-run",
    )
    work = finding_verification_work_items(lifecycle)
    recovery = next(
        row for row in work
        if row["obligation_kind"] == "RECOVERY_INDEPENDENT_VERIFICATION"
    )
    unsigned = {
        "schema_version": "plamen.report_disposition_authority.v1",
        "run_id": run_id,
        "authority": "DRIVER_DERIVED_FROM_TYPED_INDEPENDENT_DECISIONS",
        "report_writer_authoritative": False,
        "lexical_classifier_authoritative": False,
        "source_artifacts": [],
        "source_set_sha256": canonical_digest([]),
        "rows": [{
            "candidate_id": "INV-901",
            "authority_event_id": "RDA-901",
            "mandatory_reverification": True,
            "mandatory_reverification_id": recovery["obligation_id"],
            "public_retention_target": "BODY",
        }],
        "row_count": 1,
        "aliases": [],
        "alias_count": 0,
        "finding_lifecycle": lifecycle,
        "issues": [],
        "summary": {},
    }
    authority = {**unsigned, "receipt_sha256": canonical_digest(unsigned)}
    (tmp_path / "report_disposition_authority.json").write_text(
        json.dumps(authority), encoding="utf-8"
    )

    denominator = M.compile_report_reopen_denominator(
        tmp_path, run_id=run_id
    )

    assert denominator["candidate_count"] == 1
    assert denominator["input_debt_count"] == 0
    assert {row["artifact"] for row in denominator["source_bindings"]} == {
        "report_disposition_authority.json",
        "findings_inventory.md",
        "verification_queue.work_items.json",
    }
    row = denominator["candidates"][0]
    assert row["source_obligation_id"] == recovery["obligation_id"]
    assert row["premise"] == "A reachable alternate transition remains unevaluated."
    assert row["harm"] == "A protected state property may be violated."

    frozen_relative = (
        "_preverify_frozen/generation_"
        + "d" * 64
        + "/findings_inventory.md"
    )
    frozen_path = tmp_path / frozen_relative
    frozen_path.parent.mkdir(parents=True)
    frozen_path.write_text(inventory, encoding="utf-8")
    (tmp_path / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-OTHER]: Stale canonical candidate\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        M, "successor_projection_present", lambda _root: True
    )
    monkeypatch.setattr(
        M,
        "resolve_active_preverify_projection",
        lambda _root: {
            "run_id": run_id,
            "inventory_source_artifact": frozen_relative,
        },
    )
    frozen_denominator = M.compile_report_reopen_denominator(
        tmp_path, run_id=run_id
    )
    assert frozen_denominator["candidate_count"] == 1
    assert frozen_denominator["input_debt_count"] == 0
    assert frozen_relative in {
        source["artifact"]
        for source in frozen_denominator["source_bindings"]
    }


@pytest.mark.parametrize("source_name", ["../outside.txt", "C:/outside.txt"])
def test_report_reopen_rejects_escaping_source_paths_without_lexical_counting(
    tmp_path: Path,
    source_name: str,
) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.write_text(
        "RECOVERY_INDEPENDENT_VERIFICATION\n" * 200,
        encoding="utf-8",
    )
    sources = [{
        "path": source_name,
        "sha256": "0" * 64,
        "size_bytes": outside.stat().st_size,
    }]
    unsigned = {
        "schema_version": "plamen.report_disposition_authority.v1",
        "run_id": "run-path",
        "source_artifacts": sources,
        "source_set_sha256": canonical_digest(sources),
        "finding_lifecycle": {},
        "rows": [],
    }
    payload = {**unsigned, "receipt_sha256": canonical_digest(unsigned)}
    (tmp_path / "report_disposition_authority.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )

    denominator = M.compile_report_reopen_denominator(
        tmp_path, run_id="run-path"
    )

    assert denominator["candidate_count"] == 0
    assert denominator["source_obligation_count"] == 1
    assert denominator["input_debt_count"] == 1
    assert denominator["input_debts"][0]["reason_code"] == (
        "REPORT_RECOVERY_AUTHORITY_UNAVAILABLE"
    )


def test_report_reopen_rejects_symlink_source_before_adoption(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / "symlink-source.txt"
    outside.write_text("outside authority bytes", encoding="utf-8")
    link = tmp_path / "linked.txt"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    raw = outside.read_bytes()
    import hashlib
    sources = [{
        "path": link.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }]
    unsigned = {
        "schema_version": "plamen.report_disposition_authority.v1",
        "run_id": "run-symlink",
        "source_artifacts": sources,
        "source_set_sha256": canonical_digest(sources),
        "finding_lifecycle": {},
        "rows": [],
    }
    payload = {**unsigned, "receipt_sha256": canonical_digest(unsigned)}
    (tmp_path / "report_disposition_authority.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )

    denominator = M.compile_report_reopen_denominator(
        tmp_path, run_id="run-symlink"
    )

    assert denominator["candidate_count"] == 0
    assert denominator["input_debt_count"] == 1


def test_report_reopen_uses_public_disposition_validator_on_live_authority(
    tmp_path: Path,
) -> None:
    from report_disposition_authority import reconcile_report_dispositions
    from test_report_disposition_authority_p0_r import RUN_ID, _setup

    scratch, project, _item, _report = _setup(
        tmp_path,
        status="REFUTED",
        disposition="BODY",
    )
    (scratch / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-001]: Candidate INV-001\n"
        "**Source IDs**: [INV-001]\n"
        "**Severity**: Medium\n"
        "**Location**: src/Vault.sol:10-20\n"
        "**Primary Artifact**: verification_queue.md\n"
        "**Description**: A protected transition remains reachable.\n"
        "**Impact**: A protected state property may be violated.\n",
        encoding="utf-8",
    )
    result = reconcile_report_dispositions(
        scratch, project, run_id=RUN_ID
    )
    assert result["authority"]["rows"][0]["mandatory_reverification"] is True

    denominator = M.compile_report_reopen_denominator(
        scratch,
        run_id=RUN_ID,
        project_root=project,
    )

    assert denominator["candidate_count"] == 1
    assert denominator["input_debt_count"] == 0


def test_driver_wires_reopen_after_filters_before_both_shard_boundaries() -> None:
    # The live queue cutover replaced the old mutable driver call chain.  Test
    # the resolved transaction itself: T2 owns policy filtering, T3 adds the
    # mandatory reopen delta, T4 owns the pipeline-specific composition route,
    # T6 conserves all three deltas, and only then may T7 plan verifier shards.
    from test_live_verify_queue_transaction_semantic_closure import _plan

    expected_order = (
        "t2.live_policy_disposition",
        "t3.live_mandatory_delta",
        "t4.live_pipeline_composition_delta",
        "t6.live_final_typed_merge",
        "t7.live_frozen_context_and_shard_plan",
    )
    for pipeline in ("l1", "sc"):
        children = tuple(_plan(pipeline)["children"])
        identities = tuple(str(row["work_unit_id"]) for row in children)
        positions = tuple(identities.index(identity) for identity in expected_order)
        assert positions == tuple(sorted(positions))

        by_id = {str(row["work_unit_id"]): row for row in children}
        t6_inputs = set(map(str, by_id[expected_order[3]]["exact_inputs"]))
        assert (
            "_live_verify_queue_transaction/t3/queue_delta.work_items.json"
            in t6_inputs
        )
        assert (
            "_live_verify_queue_transaction/t3/"
            "mandatory_reverification_disposition.json"
            in t6_inputs
        )
        branch_token = "l1_delivery_status.json" if pipeline == "l1" else (
            "p0af_delivery_status.json"
        )
        assert any(path.endswith("/" + branch_token) for path in t6_inputs)


def test_unsafe_p0af_transaction_cannot_skip_mandatory_work_and_continue() -> None:
    import plamen_driver as D

    # The old inline P0-AF boolean no longer exists.  T4 is inside the sole
    # live transaction, whose publication result is fail-closed twice: the
    # boundary converts an unconsumable T9 result into an incomplete attempt,
    # and main terminates the phase as degraded rather than reaching shards.
    boundary = _function_ast(D._run_live_verify_queue_phase_boundary)
    unconsumable = [
        node
        for node in ast.walk(boundary)
        if isinstance(node, ast.If)
        and _mapping_get_is_not_true(
            node.test,
            receiver="cutover_result",
            key="safe_to_consume",
        )
    ]
    assert len(unconsumable) == 1
    assert any(
        isinstance(statement, ast.Return)
        and isinstance(statement.value, ast.Call)
        and _call_name(statement.value) == "incomplete"
        for statement in unconsumable[0].body
    )
    boundary_calls = _ordered_calls(boundary)
    incomplete_line = next(
        line
        for line, name in _ordered_calls(unconsumable[0])
        if name == "incomplete"
    )
    phase_commit_line = next(
        line
        for line, name in boundary_calls
        if name == "_commit_verification_transaction"
    )
    assert incomplete_line < phase_commit_line

    main = _function_ast(D.main)
    rejected = [
        node
        for node in ast.walk(main)
        if isinstance(node, ast.If)
        and _mapping_get_is_not_true(
            node.test,
            receiver="_live_queue_boundary",
            key="safe_to_continue",
        )
    ]
    assert len(rejected) == 1
    exits = [
        call
        for call in ast.walk(rejected[0])
        if isinstance(call, ast.Call) and _call_name(call) == "exit"
    ]
    assert len(exits) == 1
    assert (
        len(exits[0].args) == 1
        and isinstance(exits[0].args[0], ast.Name)
        and exits[0].args[0].id == "EXIT_DEGRADED"
    )


def test_post_verify_extract_reconciles_mandatory_completion_before_late_finds() -> None:
    import plamen_driver as D

    function = _function_ast(D._run_phase_validators)
    candidates = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.If)
        and {
            "_reconcile_mandatory_primary_reverification",
            "_route_post_verify_late_candidates",
        }.issubset({name for _, name in _ordered_calls(node)})
    ]
    boundary = min(candidates, key=lambda node: node.end_lineno - node.lineno)
    ordered = _ordered_calls(boundary)
    assert next(
        line for line, name in ordered
        if name == "_reconcile_mandatory_primary_reverification"
    ) < next(
        line for line, name in ordered
        if name == "_route_post_verify_late_candidates"
    )


def test_report_floor_runs_exact_recovery_before_final_assurance() -> None:
    import plamen_driver as D

    # Follow the live report-floor operations, independent of comments and
    # byte offsets: the disposition PhaseIO transaction validates/reconciles
    # authority internally, recovery consumes that disposition, and final
    # chain assurance can observe only the post-recovery state.
    function = _function_ast(D.main)
    required = {
        "_run_report_disposition_phase_io",
        "_run_mandatory_report_reverification",
        "_write_and_record_chain_grouping_assurance",
    }
    candidates = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.If)
        and required.issubset({name for _, name in _ordered_calls(node)})
    ]
    boundary = min(candidates, key=lambda node: node.end_lineno - node.lineno)
    calls = _ordered_calls(boundary)
    positions = {
        name: next(line for line, candidate in calls if candidate == name)
        for name in required
    }
    assert positions["_run_report_disposition_phase_io"] < positions[
        "_run_mandatory_report_reverification"
    ] < positions["_write_and_record_chain_grouping_assurance"]


def test_driver_collects_only_exact_compiler_bound_recovery_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import plamen_driver as D
    from test_verification_recovery_contract_p0_ai import _emit_recovery_outputs

    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    denominator = _denominator(
        _candidate(
            "INV-999",
            source_id="INV-999",
            source_obligation="FLO-999",
            kind="RECOVERY_INDEPENDENT_VERIFICATION",
        )
    )
    rows = M.mandatory_recovery_rows(denominator)

    def execute(spec, *, prompt_path, scratchpad, **_kwargs):
        _emit_recovery_outputs(
            spec, prompt_path=prompt_path, scratchpad=scratchpad
        )
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", execute)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "thorough",
        "_run_id": "run-nc5",
        "_verification_recovery_kind": "MANDATORY_REOPEN",
    }
    assert D._run_verify_recovery_shard(
        config,
        [(str(row["work_item_id"]), row) for row in rows],
    ) == []

    evidence, issues = D._mandatory_recovery_execution_evidence(
        scratch, denominator
    )
    assert issues == []
    candidate = denominator["candidates"][0]
    exact = evidence[candidate["obligation_id"]]
    assert exact["candidate_packet_sha256"] == candidate[
        "candidate_packet_sha256"
    ]
    assert exact["source_obligation_id"] == "FLO-999"
    assert exact["completion_authorized"] is True

    # A self-consistent but wrong packet binding cannot be adopted.
    directory = next((scratch / "_verification_recovery").glob("VREC-*"))
    contract = json.loads((directory / "contract.json").read_text(encoding="utf-8"))
    contract["rows"][0]["harm"] = "changed harm packet"
    (directory / "contract.json").write_text(json.dumps(contract), encoding="utf-8")
    stale, stale_issues = D._mandatory_recovery_execution_evidence(
        scratch, denominator
    )
    assert stale == {}
    assert stale_issues
