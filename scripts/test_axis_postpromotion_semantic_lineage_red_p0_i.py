"""RED integration spec for normal post-axis semantic inventory successors."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import axis_disposition as AXIS
from axis_promotion_lineage import (
    AxisPromotionLineageError,
    authorize_downstream_inventory_tail,
)
import plamen_driver as DRIVER
from artifact_ledger import (
    arm_semantic_mutation,
    finalize_semantic_mutation,
    semantic_import_authority,
)
from assurance_limitations import build_current_assurance_manifest
from plamen_mechanical import apply_llm_dedup_decisions
from plamen_types import Checkpoint
from semantic_dedup_authority import load_applied_aliases
from test_axis_assurance_projection_p0_i import _axis_rows
from test_axis_p0i_independent_review_probes import _commit_tail
from test_axis_resume_canonical_recovery_red_p0_i import (
    RUN_ID,
    _committed_model_fixture,
    _harvest_negative,
)


@pytest.mark.parametrize(
    "tail_authority",
    ("phaseio", "FINDING_PROMOTION", "GATE_P_ADDITIVE_PROMOTION"),
)
@pytest.mark.parametrize("dedup_survivor", ("axis", "tail"))
def test_axis_resume_and_assurance_accept_receipt_authorized_sc_dedup_successor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tail_authority: str,
    dedup_survivor: str,
) -> None:
    """A later normal precision phase must not invalidate axis delivery."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert issues == []
    _harvest_negative(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    if tail_authority == "phaseio":
        _commit_tail(
            project=project,
            scratchpad=scratchpad,
            ordinal=1,
        )
    else:
        additive = arm_semantic_mutation(
            scratchpad,
            project,
            artifact_identity="scratchpad:findings_inventory.md",
            mutation_kind=tail_authority,
            run_id=RUN_ID,
        )
        inventory = scratchpad / "findings_inventory.md"
        inventory.write_bytes(
            inventory.read_bytes()
            + (
                "\n### Finding [INV-901]: review tail 1\n"
                "**Source IDs**: REVIEW:1\n"
                "**Verdict**: NEEDS_VERIFICATION\n"
                "**Severity**: Low\n"
                "**Location**: contracts/Review.sol:L1\n"
                "**Description**: independently committed tail\n"
                "**Impact**: independently committed impact\n"
            ).encode("utf-8")
        )
        additive = finalize_semantic_mutation(
            scratchpad,
            project,
            str(additive["event_id"]),
            run_id=RUN_ID,
            affected_record_ids=("INV-901",),
        )
        assert additive["status"] == "INVALIDATION_APPLIED"
    plan = json.loads(
        (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).read_text(
            encoding="utf-8"
        )
    )
    axis_inventory_id = str(plan["planned_deliveries"][0]["inventory_id"])
    tail_inventory_id = "INV-901"
    (scratchpad / "dedup_decisions.md").write_text(
        "# Semantic Dedup Decisions\n\n"
        "### GROUP: "
        + (
            f"{axis_inventory_id} represents "
            f"{axis_inventory_id}, {tail_inventory_id}\n"
            if dedup_survivor == "axis"
            else f"{tail_inventory_id} represents "
            f"{tail_inventory_id}, {axis_inventory_id}\n"
        )
        +
        "- Pattern: shared review grouping\n",
        encoding="utf-8",
    )
    assert apply_llm_dedup_decisions(
        scratchpad, "sc_semantic_dedup"
    ) == 0
    deduped = (
        scratchpad / "findings_inventory_deduped.md"
    ).read_bytes()
    assert deduped != (
        scratchpad / "findings_inventory.md"
    ).read_bytes()
    # This is the same receipt check used by the live SC canonical swap.
    load_applied_aliases(
        scratchpad,
        canonical_text=deduped.decode("utf-8", errors="strict"),
    )
    event = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="RECEIPT_AUTHORIZED_SEMANTIC_DEDUP",
        run_id=RUN_ID,
    )
    (scratchpad / "findings_inventory.md").write_bytes(deduped)
    finalized = finalize_semantic_mutation(
        scratchpad,
        project,
        str(event["event_id"]),
        run_id=RUN_ID,
    )
    assert finalized["status"] == "INVALIDATION_APPLIED"
    virtual = semantic_import_authority(
        scratchpad,
        project,
        "scratchpad:findings_inventory.md",
        run_id=RUN_ID,
    )
    assert virtual["authority_kind"] == "CONTIGUOUS_SEMANTIC_MUTATION_CHAIN"
    semantic_delivery = authorize_downstream_inventory_tail(
        scratchpad=scratchpad,
        project_root=project,
        run_id=RUN_ID,
        promotion_plan=plan,
        current_inventory_raw=(
            scratchpad / "findings_inventory.md"
        ).read_bytes(),
    )
    expected_action_ids = {
        str(row["action_id"])
        for row in plan["planned_deliveries"]
    } | set(plan["preexisting_action_ids"])
    assert set(semantic_delivery["preserved_action_ids"]) == (
        expected_action_ids
    ), {
        "preserved": semantic_delivery["preserved_action_ids"],
        "expected": sorted(expected_action_ids),
    }

    resume_issues = DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=RUN_ID,
    )
    assurance_rows = _axis_rows(
        build_current_assurance_manifest(
            Checkpoint(run_id=RUN_ID),
            scratchpad,
            project,
        )
    )
    assert resume_issues == [], {
        "resume_issues": resume_issues,
        "assurance_rows": assurance_rows,
    }
    assert assurance_rows == [], assurance_rows


def test_axis_resume_accepts_additive_tail_with_no_change_dedup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A precision no-op must not erase prior typed additive authority."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert issues == []
    _harvest_negative(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    plan = json.loads(
        (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).read_text(
            encoding="utf-8"
        )
    )

    inventory = scratchpad / "findings_inventory.md"
    for ordinal, kind in enumerate(
        ("FINDING_PROMOTION", "GATE_P_ADDITIVE_PROMOTION"),
        1,
    ):
        finding_id = f"INV-{900 + ordinal}"
        additive = arm_semantic_mutation(
            scratchpad,
            project,
            artifact_identity="scratchpad:findings_inventory.md",
            mutation_kind=kind,
            run_id=RUN_ID,
        )
        inventory.write_bytes(
            inventory.read_bytes()
            + (
                f"\n### Finding [{finding_id}]: review tail {ordinal}\n"
                f"**Source IDs**: REVIEW:{ordinal}\n"
                "**Verdict**: NEEDS_VERIFICATION\n"
                "**Severity**: Low\n"
                "**Location**: contracts/Review.sol:L1\n"
                "**Description**: independently committed tail\n"
                "**Impact**: independently committed impact\n"
            ).encode("utf-8")
        )
        additive = finalize_semantic_mutation(
            scratchpad,
            project,
            str(additive["event_id"]),
            run_id=RUN_ID,
            affected_record_ids=(finding_id,),
        )
        assert additive["transition_authority"]["transition_kind"] == (
            "STRICT_APPEND"
        )

    (scratchpad / "dedup_decisions.md").write_text(
        "# Semantic Dedup Decisions\n\n"
        "KEEP: [INV-901]\n"
        "KEEP: [INV-902]\n",
        encoding="utf-8",
    )
    assert apply_llm_dedup_decisions(
        scratchpad, "sc_semantic_dedup"
    ) == 0
    canonical = inventory.read_bytes()
    deduped = (
        scratchpad / "findings_inventory_deduped.md"
    ).read_bytes()
    assert deduped == canonical
    load_applied_aliases(
        scratchpad,
        canonical_text=deduped.decode("utf-8", errors="strict"),
    )
    precision = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="RECEIPT_AUTHORIZED_SEMANTIC_DEDUP",
        run_id=RUN_ID,
    )
    inventory.write_bytes(deduped)
    precision = finalize_semantic_mutation(
        scratchpad,
        project,
        str(precision["event_id"]),
        run_id=RUN_ID,
    )
    assert precision["status"] == "NO_CHANGE"

    semantic_delivery = authorize_downstream_inventory_tail(
        scratchpad=scratchpad,
        project_root=project,
        run_id=RUN_ID,
        promotion_plan=plan,
        current_inventory_raw=inventory.read_bytes(),
    )
    assert semantic_delivery["authority_kind"] == (
        "RECEIPT_AUTHORIZED_SEMANTIC_SUCCESSOR"
    )
    assert DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=RUN_ID,
    ) == []
    assert _axis_rows(
        build_current_assurance_manifest(
            Checkpoint(run_id=RUN_ID),
            scratchpad,
            project,
        )
    ) == []


def test_axis_resume_accepts_crash_after_typed_additive_before_dedup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An incomplete later phase must not force a completed axis rewind."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert issues == []
    _harvest_negative(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    plan = json.loads(
        (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).read_text(
            encoding="utf-8"
        )
    )

    additive = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="GATE_P_ADDITIVE_PROMOTION",
        run_id=RUN_ID,
    )
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_bytes(
        inventory.read_bytes()
        + (
            "\n### Finding [INV-901]: review tail 1\n"
            "**Source IDs**: REVIEW:1\n"
            "**Verdict**: NEEDS_VERIFICATION\n"
            "**Severity**: Low\n"
            "**Location**: contracts/Review.sol:L1\n"
            "**Description**: independently committed tail\n"
            "**Impact**: independently committed impact\n"
        ).encode("utf-8")
    )
    additive = finalize_semantic_mutation(
        scratchpad,
        project,
        str(additive["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-901",),
    )
    assert additive["transition_authority"]["transition_kind"] == (
        "STRICT_APPEND"
    )

    semantic_delivery = authorize_downstream_inventory_tail(
        scratchpad=scratchpad,
        project_root=project,
        run_id=RUN_ID,
        promotion_plan=plan,
        current_inventory_raw=inventory.read_bytes(),
    )
    assert semantic_delivery["authority_kind"] == (
        "RECEIPT_AUTHORIZED_SEMANTIC_SUCCESSOR"
    )
    assert DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=RUN_ID,
    ) == []
    assert _axis_rows(
        build_current_assurance_manifest(
            Checkpoint(run_id=RUN_ID),
            scratchpad,
            project,
        )
    ) == []


def test_additive_label_cannot_authorize_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation labels cannot self-certify destructive inventory writes."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert issues == []
    _harvest_negative(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    plan = json.loads(
        (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).read_text(
            encoding="utf-8"
        )
    )

    event = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=RUN_ID,
    )
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text(
        "# Findings Inventory\n\n"
        "### Finding [INV-901]: destructive replacement\n"
        "**Source IDs**: REVIEW:1\n"
        "**Severity**: Low\n"
        "**Description**: the axis block was removed\n",
        encoding="utf-8",
    )
    event = finalize_semantic_mutation(
        scratchpad,
        project,
        str(event["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-901",),
    )
    assert event["transition_authority"]["transition_kind"] == "REPLACEMENT"

    with pytest.raises(
        AxisPromotionLineageError,
        match=r"(?i)(append|lineage|successor|authority|binding)",
    ):
        authorize_downstream_inventory_tail(
            scratchpad=scratchpad,
            project_root=project,
            run_id=RUN_ID,
            promotion_plan=plan,
            current_inventory_raw=inventory.read_bytes(),
        )


def test_axis_resume_accepts_typed_late_additive_after_dedup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The live SC verify boundary may append a late recall candidate."""

    (
        project,
        scratchpad,
        phase,
        config,
        _worklist,
        _frozen,
        _digest,
    ) = _committed_model_fixture(
        tmp_path,
        monkeypatch,
        backend="claude",
        disposition="FINDING",
    )
    application, issues = DRIVER._finalize_axis_coverage_boundary(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    assert application["application_record_complete"] is True
    assert issues == []
    _harvest_negative(
        phase=phase,
        config=config,
        scratchpad=scratchpad,
    )
    plan = json.loads(
        (scratchpad / AXIS.AXIS_PROMOTION_PLAN_NAME).read_text(
            encoding="utf-8"
        )
    )
    inventory = scratchpad / "findings_inventory.md"
    axis_inventory_id = str(plan["planned_deliveries"][0]["inventory_id"])

    pre_dedup = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=RUN_ID,
    )
    inventory.write_bytes(
        inventory.read_bytes()
        + (
            "\n### Finding [INV-901]: pre-dedup tail\n"
            "**Source IDs**: REVIEW:1\n"
            "**Severity**: Low\n"
            "**Description**: pre-dedup additive candidate\n"
            "**Impact**: candidate impact\n"
        ).encode("utf-8")
    )
    pre_dedup = finalize_semantic_mutation(
        scratchpad,
        project,
        str(pre_dedup["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-901",),
    )
    assert pre_dedup["transition_authority"]["transition_kind"] == (
        "STRICT_APPEND"
    )

    (scratchpad / "dedup_decisions.md").write_text(
        "# Semantic Dedup Decisions\n\n"
        f"### GROUP: INV-901 represents "
        f"INV-901, {axis_inventory_id}\n"
        "- Pattern: shared review grouping\n",
        encoding="utf-8",
    )
    assert apply_llm_dedup_decisions(
        scratchpad, "sc_semantic_dedup"
    ) == 0
    deduped = (
        scratchpad / "findings_inventory_deduped.md"
    ).read_bytes()
    load_applied_aliases(
        scratchpad,
        canonical_text=deduped.decode("utf-8", errors="strict"),
    )
    dedup = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="RECEIPT_AUTHORIZED_SEMANTIC_DEDUP",
        run_id=RUN_ID,
    )
    inventory.write_bytes(deduped)
    dedup = finalize_semantic_mutation(
        scratchpad,
        project,
        str(dedup["event_id"]),
        run_id=RUN_ID,
    )
    assert dedup["transition_authority"]["transition_kind"] == "REPLACEMENT"

    late = arm_semantic_mutation(
        scratchpad,
        project,
        artifact_identity="scratchpad:findings_inventory.md",
        mutation_kind="FINDING_PROMOTION",
        run_id=RUN_ID,
    )
    inventory.write_bytes(
        inventory.read_bytes()
        + (
            "\n### Finding [INV-902]: late verify candidate\n"
            "**Source IDs**: REVIEW:2\n"
            "**Severity**: Low\n"
            "**Description**: late additive candidate\n"
            "**Impact**: candidate impact\n"
        ).encode("utf-8")
    )
    late = finalize_semantic_mutation(
        scratchpad,
        project,
        str(late["event_id"]),
        run_id=RUN_ID,
        affected_record_ids=("INV-902",),
    )
    assert late["transition_authority"]["transition_kind"] == "STRICT_APPEND"

    semantic_delivery = authorize_downstream_inventory_tail(
        scratchpad=scratchpad,
        project_root=project,
        run_id=RUN_ID,
        promotion_plan=plan,
        current_inventory_raw=inventory.read_bytes(),
    )
    assert semantic_delivery["authority_kind"] == (
        "RECEIPT_AUTHORIZED_SEMANTIC_SUCCESSOR"
    )
    assert DRIVER._axis_disposition_resume_issues(
        scratchpad=scratchpad,
        project_root=project,
        pipeline="sc",
        mode="thorough",
        language="evm",
        backend="claude",
        run_id=RUN_ID,
    ) == []
    assert _axis_rows(
        build_current_assurance_manifest(
            Checkpoint(run_id=RUN_ID),
            scratchpad,
            project,
        )
    ) == []
