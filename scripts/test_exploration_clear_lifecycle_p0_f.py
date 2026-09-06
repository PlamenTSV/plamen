from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import exploration_clear_lifecycle as E


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _coverage(*rows: str) -> str:
    return (
        "# Exploration Completeness Findings\n\n"
        "## Coverage Record\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        + "".join(rows)
        + "\n## Notes\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| OUT-1 | Direction | ignored outside section | NO-GAP | explored |\n"
    )


def _compile(
    tmp_path: Path,
    text: str,
    *,
    canonical: dict[str, str] | None = None,
) -> E.LifecycleReceipt:
    artifact = _write(tmp_path / "scratch" / "exploration_skeptic_findings.md", text)
    return E.compile_initial_receipt(
        artifact,
        production_root=tmp_path / "repo",
        canonical_prior_ids=canonical or {},
    )


def _repair_response(plan: E.RepairPlan, *rows: str) -> str:
    return (
        "# Exploration Clear Repair Response\n\n"
        f"**Plan ID**: {plan.plan_id}\n"
        f"**Plan Hash**: {plan.plan_hash}\n\n"
        "## Repair Dispositions\n\n"
        "| Obligation ID | Disposition | Evidence | Action ID | Rationale |\n"
        "|---|---|---|---|---|\n"
        + "".join(rows)
    )


def _with_commitments(
    source: str,
    *rows: str,
    blocks: str = "",
) -> str:
    return source.replace(
        "\n## Notes",
        "\n## Invariant Commitment Record\n\n"
        "| Finding | Axis | Instance | Commitment | Reason |\n"
        "|---|---|---|---|---|\n"
        + "".join(rows)
        + "\n"
        + blocks
        + "\n## Notes",
    )


def _ci(ci_id: str, finding: str, instance: str) -> str:
    return (
        f"committed-invariant [{ci_id}]\n"
        "Locus: src/Module.sol:L2\n"
        "Shape: CONSERVATION\n"
        "Assertion: total credited value equals total settled value\n"
        "Falsify Class: conservation\n"
        f"Provenance: exploration NO-GAP @ {finding} / {instance}\n"
    )


def test_invariant_commitment_exact_zero_denominator_is_not_applicable(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | unsafe path | ADD | ECLRADD-1 |\n"),
    )
    assert receipt.invariant_commitment_denominator == 0
    assert receipt.invariant_commitment_status == "NOT_APPLICABLE"


def test_two_clears_cannot_share_one_committed_invariant(tmp_path: Path):
    _write(tmp_path / "repo" / "src" / "Module.sol", "one\ntwo\n")
    source = _with_commitments(
        _coverage(
            "| BASE-1 | Direction | first path | NO-GAP | src/Module.sol:L2 |\n",
            "| BASE-2 | Direction | second path | NO-GAP | src/Module.sol:L2 |\n",
        ),
        "| BASE-1 | Direction | first path | CI:CI-1 | - |\n",
        "| BASE-2 | Direction | second path | CI:CI-1 | - |\n",
        blocks=_ci("CI-1", "BASE-1", "first path"),
    )
    receipt = _compile(tmp_path, source)
    assert receipt.invariant_commitment_denominator == 2
    assert receipt.invariant_commitment_status == "DEBT"
    assert {row.status for row in receipt.invariant_commitments} == {"DEBT"}
    assert {row.disposition for row in receipt.obligations} == {
        "MISSING_COMMITTED_INVARIANT"
    }


@pytest.mark.parametrize(
    "blocks",
    (
        "committed-invariant [BROKEN]\nLocus: src/Module.sol:L2\n",
        _ci("CI-1", "BASE-1", "first path")
        + "\n"
        + _ci("CI-1", "BASE-1", "first path"),
    ),
    ids=("malformed-header", "duplicate-id"),
)
def test_malformed_or_duplicate_ci_reopens_clear(tmp_path: Path, blocks: str):
    _write(tmp_path / "repo" / "src" / "Module.sol", "one\ntwo\n")
    receipt = _compile(
        tmp_path,
        _with_commitments(
            _coverage(
                "| BASE-1 | Direction | first path | NO-GAP | src/Module.sol:L2 |\n"
            ),
            "| BASE-1 | Direction | first path | CI:CI-1 | - |\n",
            blocks=blocks,
        ),
    )
    assert receipt.invariant_commitment_status == "DEBT"
    assert receipt.obligations[0].disposition == "MISSING_COMMITTED_INVARIANT"


def test_missing_ci_can_only_reopen_not_reclear(tmp_path: Path):
    _write(tmp_path / "repo" / "src" / "Module.sol", "one\ntwo\n")
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Direction | first path | NO-GAP | src/Module.sol:L2 |\n"
        ),
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    oid = receipt.obligations[0].obligation_id
    repaired = E.reconcile_repair_attempt(
        receipt,
        plan,
        _repair_response(
            plan,
            f"| {oid} | CLEAR | src/Module.sol:L2 | - | still safe |\n",
        ),
        production_root=tmp_path / "repo",
        canonical_prior_ids={},
    )
    assert repaired.obligations[0].disposition == "UNRESOLVED"
    assert "cannot be repaired into another clear" in repaired.obligations[0].reason


def test_fixture_first_invalid_clear_yields_one_exact_repair_plan(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | inverse path | NO-GAP | explored |\n"),
    )
    assert receipt.status == "REPAIR_REQUIRED"
    assert len(receipt.obligations) == 1
    obligation = receipt.obligations[0]
    assert obligation.obligation_id.startswith("ECLR-")
    assert obligation.source_finding == "BASE-1"
    assert obligation.axis == "Direction"
    assert obligation.instance == "inverse path"
    assert obligation.artifact_sha256 == hashlib.sha256(
        (tmp_path / "scratch" / "exploration_skeptic_findings.md").read_bytes()
    ).hexdigest()
    assert obligation.source_row_sha256 == hashlib.sha256(
        b"| BASE-1 | Direction | inverse path | NO-GAP | explored |"
    ).hexdigest()

    plan = E.build_repair_plan(receipt)
    assert plan is not None
    assert plan.attempt == 1
    assert plan.obligation_ids == (obligation.obligation_id,)
    assert E.build_repair_plan(receipt, prior_plan=plan) is None


def test_section_and_header_scoping_ignores_lookalike_tables(tmp_path: Path):
    text = (
        "# Findings\n\n"
        "| Finding | Axis | Instance | Disposition | Evidence |\n"
        "|---|---|---|---|---|\n"
        "| OUT-1 | Direction | outside | NO-GAP | explored |\n\n"
        "## Coverage Record\n\n"
        "| Thing | Direction | Result | Proof | Notes |\n"
        "|---|---|---|---|---|\n"
        "| OUT-2 | Direction | header-lookalike | NO-GAP | explored |\n"
    )
    receipt = _compile(tmp_path, text)
    assert receipt.source_row_count == 0
    assert receipt.status == "DEGRADED"
    assert any("coverage header" in debt for debt in receipt.debt)


def test_stable_identity_survives_evidence_change_but_hash_detects_it(tmp_path: Path):
    first = _compile(
        tmp_path,
        _coverage("| BASE-1 | Neighbour | sibling path | NO-GAP | explored |\n"),
    )
    second = _compile(
        tmp_path,
        _coverage("| BASE-1 | Neighbour | sibling path | NO-GAP | reviewed |\n"),
    )
    assert first.obligations[0].obligation_id == second.obligations[0].obligation_id
    assert first.obligations[0].source_row_sha256 != second.obligations[0].source_row_sha256
    assert first.artifact_sha256 != second.artifact_sha256


def test_conflicting_duplicate_identity_is_debt_not_arbitrary_winner(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Direction | inverse path | NO-GAP | explored |\n",
            "| BASE-1 | Direction | inverse path | ASSESSED | reviewed |\n",
        ),
    )
    assert receipt.status == "DEGRADED"
    assert len(receipt.conflicts) == 1
    assert receipt.obligations[0].disposition == "UNRESOLVED_CONFLICT"
    assert receipt.obligations[0].obligation_id == receipt.conflicts[0].obligation_id


def test_real_production_path_and_line_closes_but_fake_or_out_of_range_does_not(tmp_path: Path):
    _write(tmp_path / "repo" / "src" / "Module.sol", "line one\nline two\n")
    source = _coverage(
        "| BASE-1 | Direction | valid | NO-GAP | src/Module.sol:L2 |\n",
        "| BASE-1 | Direction | missing | NO-GAP | src/Missing.sol:L2 |\n",
        "| BASE-1 | Direction | range | NO-GAP | src/Module.sol:L99 |\n",
        "| BASE-1 | Direction | traversal | NO-GAP | ../outside.sol:L1 |\n",
    ).replace(
        "\n## Notes",
        "\n## Invariant Commitment Record\n\n"
        "| Finding | Axis | Instance | Commitment | Reason |\n"
        "|---|---|---|---|---|\n"
        "| BASE-1 | Direction | valid | NOT_REQUIRED_NON_VALUE_BEARING | "
        "pure view with no funds, authorization, accounting, or liveness effect |\n\n"
        "## Notes",
    )
    receipt = _compile(
        tmp_path,
        source,
    )
    rows = {row.instance: row for row in receipt.rows}
    assert rows["valid"].resolution_kind == "PRODUCTION_LOCUS"
    assert rows["valid"].resolved_reference == "src/Module.sol:L2"
    assert {o.instance for o in receipt.obligations} == {"missing", "range", "traversal"}


def test_only_canonical_prior_referent_closes(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Similar-Mechanism | canonical | ASSESSED | captured by H-01 |\n",
            "| BASE-1 | Similar-Mechanism | alias | ASSESSED | captured by OLD-7 |\n",
            "| BASE-1 | Similar-Mechanism | invented | ASSESSED | captured by H-99 |\n",
        ),
        canonical={"H-01": "H-01", "OLD-7": "H-01"},
    )
    rows = {row.instance: row for row in receipt.rows}
    assert rows["canonical"].resolved_reference == "H-01"
    assert rows["alias"].resolved_reference == "H-01"
    assert rows["invented"].resolution_kind == "INVALID_CLEAR"


def test_one_attempt_repair_exact_locus_closes_and_blanket_wording_queues(tmp_path: Path):
    _write(tmp_path / "repo" / "src" / "Module.sol", "one\ntwo\nthree\n")
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Direction | closeable | NO-GAP | explored |\n",
            "| BASE-2 | Neighbour | blanket | ASSESSED | reviewed |\n",
        ),
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    ids = {o.instance: o.obligation_id for o in receipt.obligations}
    response = _repair_response(
        plan,
        f"| {ids['closeable']} | CLEAR | src/Module.sol:L3 |  | exact guard locus |\n",
        f"| {ids['blanket']} | CLEAR | fully reviewed |  | no issue |\n",
    )
    repaired = E.reconcile_repair_attempt(
        receipt,
        plan,
        response,
        production_root=tmp_path / "repo",
        canonical_prior_ids={},
    )
    assert repaired.repair_attempts == 1
    assert repaired.status == "DEGRADED"
    assert {o.instance for o in repaired.obligations} == {"blanket"}
    assert repaired.obligations[0].disposition == "UNRESOLVED"
    assert E.build_repair_plan(repaired, prior_plan=plan) is None


def test_repair_can_resolve_canonical_prior_or_emit_additive_action_without_self_certification(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Direction | prior-covered | NO-GAP | explored |\n",
            "| BASE-2 | Neighbour | unsafe sibling | NO-GAP | checked |\n",
        ),
        canonical={"OLD-1": "H-01"},
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    ids = {o.instance: o.obligation_id for o in receipt.obligations}
    response = _repair_response(
        plan,
        f"| {ids['prior-covered']} | CLEAR | already H-01 |  | prior captures instance |\n",
        f"| {ids['unsafe sibling']} | ADD |  | SKEP-014 | concrete unsafe result |\n",
    )
    repaired = E.reconcile_repair_attempt(
        receipt,
        plan,
        response,
        production_root=tmp_path / "repo",
        canonical_prior_ids={"H-01": "H-01", "OLD-1": "H-01"},
    )
    assert repaired.status == "ADDITIVE"
    assert repaired.obligations == ()
    assert len(repaired.additive_actions) == 1
    action = repaired.additive_actions[0]
    assert action.action_id == "SKEP-014"
    assert action.proof_scope == "UNVERIFIED_GENERATOR_OUTPUT"
    assert action.requires_independent_consumer is True


@pytest.mark.parametrize("kind", ["TIMEOUT", "UNAVAILABLE"])
def test_repair_unavailable_is_haltless_debt_with_exact_queue_tail(tmp_path: Path, kind: str):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | inverse | NO-GAP | explored |\n"),
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    degraded = E.record_repair_unavailable(receipt, plan, reason=kind)
    assert degraded.status == "DEGRADED"
    assert degraded.repair_attempts == 1
    assert degraded.obligations[0].disposition == "UNAVAILABLE"
    queue = E.obligation_queue(degraded)
    assert queue["count"] == 1
    assert queue["tail"] == degraded.obligations[0].obligation_id
    assert queue["items"][0]["obligation_id"] == queue["tail"]


def test_response_must_bind_exact_plan_and_cannot_omit_or_invent_rows(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | inverse | NO-GAP | explored |\n"),
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    wrong = _repair_response(plan, "| ECLR-invented | UNRESOLVED |  |  | no evidence |\n")
    reconciled = E.reconcile_repair_attempt(
        receipt,
        plan,
        wrong,
        production_root=tmp_path / "repo",
        canonical_prior_ids={},
    )
    assert reconciled.status == "DEGRADED"
    assert reconciled.obligations[0].disposition == "UNRESOLVED"
    assert any("unexpected obligation" in debt for debt in reconciled.debt)
    assert any("missing repair disposition" in debt for debt in reconciled.debt)


def test_resume_and_writes_are_byte_idempotent_without_legacy_sentinel(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | inverse | NO-GAP | explored |\n"),
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    degraded = E.record_repair_unavailable(receipt, plan, reason="TIMEOUT")
    out = tmp_path / "scratch"
    paths = E.write_lifecycle_artifacts(out, degraded, plan=plan)
    before = {p.name: p.read_bytes() for p in paths}
    loaded = E.load_lifecycle_receipt(out / E.RECEIPT_NAME)
    paths2 = E.write_lifecycle_artifacts(out, loaded, plan=plan)
    after = {p.name: p.read_bytes() for p in paths2}
    assert before == after
    assert loaded == degraded
    assert E.build_repair_plan(loaded, prior_plan=plan) is None
    assert not (out / "exploration_skeptic.instance_gap").exists()
    queue = json.loads((out / E.OBLIGATION_QUEUE_NAME).read_text(encoding="utf-8"))
    assert queue["items"] == E.obligation_queue(loaded)["items"]


def test_additive_source_row_is_exported_not_auto_adjudicated(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Direction | unsafe inverse | GAP-FILLED | SKEP-008 |\n",
            "| BASE-2 | Neighbour | unknown sibling | UNRESOLVED | none |\n",
        ),
    )
    assert receipt.status == "DEGRADED"
    assert receipt.additive_actions[0].action_id == "SKEP-008"
    assert receipt.additive_actions[0].proof_scope == "UNVERIFIED_GENERATOR_OUTPUT"
    assert receipt.additive_actions[0].requires_independent_consumer
    assert receipt.obligations[0].disposition == "UNRESOLVED"
    assert not hasattr(receipt, "verified_findings")


def test_generic_instance_cannot_clear_even_with_a_real_locus(tmp_path: Path):
    _write(tmp_path / "repo" / "src" / "Module.sol", "one\ntwo\n")
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | Direction | NO-GAP | src/Module.sol:L2 |\n"),
    )
    assert receipt.status == "REPAIR_REQUIRED"
    assert receipt.obligations[0].instance == "Direction"
    assert receipt.rows[0].resolution_kind == "INVALID_CLEAR"


def test_absolute_and_traversal_locus_cannot_alias_a_real_relative_file(tmp_path: Path):
    _write(tmp_path / "repo" / "outside.sol", "one\n")
    receipt = _compile(
        tmp_path,
        _coverage(
            "| BASE-1 | Direction | absolute | NO-GAP | /outside.sol:L1 |\n",
            "| BASE-2 | Direction | traversal | NO-GAP | ../outside.sol:L1 |\n",
        ),
    )
    assert {row.instance for row in receipt.obligations} == {"absolute", "traversal"}


def test_persisted_plan_and_source_binding_fail_closed_on_tamper(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | inverse | NO-GAP | explored |\n"),
    )
    plan = E.build_repair_plan(receipt)
    assert plan is not None
    out = tmp_path / "scratch"
    E.write_lifecycle_artifacts(out, receipt, plan=plan)
    assert E.load_repair_plan(out / E.REPAIR_PLAN_NAME) == plan

    plan_path = out / E.REPAIR_PLAN_NAME
    payload = json.loads(plan_path.read_text(encoding="utf-8"))
    payload["plan_id"] = "ECRP-TAMPERED"
    plan_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(E.ExplorationClearError, match="digest mismatch"):
        E.load_repair_plan(plan_path)

    source = Path(receipt.source_artifact)
    source.write_text(source.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")
    with pytest.raises(E.ExplorationClearError, match="source artifact digest mismatch"):
        E.load_lifecycle_receipt(out / E.RECEIPT_NAME)


def test_clean_queue_has_exact_zero_denominator_and_writes_do_not_mutate_report_state(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Direction | inverse | ASSESSED | captured by H-01 |\n"),
        canonical={"H-01": "H-01"},
    )
    out = tmp_path / "scratch"
    inventory = _write(out / "hypothesis_inventory.md", "inventory-owned\n")
    report = _write(out / "AUDIT_REPORT.md", "report-owned\n")
    E.write_lifecycle_artifacts(out, receipt)
    queue = E.obligation_queue(receipt)
    assert queue["count"] == 0
    assert queue["tail"] == ""
    assert queue["items"] == []
    assert inventory.read_text(encoding="utf-8") == "inventory-owned\n"
    assert report.read_text(encoding="utf-8") == "report-owned\n"


def test_reopened_projection_is_additive_and_still_requires_independent_consumption(tmp_path: Path):
    receipt = _compile(
        tmp_path,
        _coverage("| BASE-1 | Neighbour | sibling | RE-OPENED | SKEP-099 |\n"),
    )
    assert receipt.status == "ADDITIVE"
    assert receipt.additive_actions[0].action_id == "SKEP-099"
    assert receipt.additive_actions[0].requires_independent_consumer is True
