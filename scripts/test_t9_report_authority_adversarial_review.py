"""Adversarial RED fixtures for T9 report-universe authority.

The first report cutover fixtures prove that the new authenticated loader
rejects a changed publication when callers actually use it.  These tests pin
the stronger architectural contract: no exported report-universe or delta
API may provide a lower-authority path around that loader once a live
verify-queue transaction exists.

Tests only.  Production fixes belong to the implementation owner.
"""
from __future__ import annotations

from pathlib import Path
import json
import shutil

import pytest

import post_verify_candidate_delta as DELTA
from post_verify_candidate_delta import PostVerifyCandidateDeltaError
from queue_work_items import (
    build_queue_work_plan,
    queue_records_to_json,
)
from test_report_candidate_universe_t9_publication_red import (
    RUN_ID,
    _TypedPublicationExecutor,
    _commit_t9,
    _base_item,
    _stale_item,
)
import verify_queue_transaction as TRANSACTION
from queue_work_items import QueueWorkItem
from plamen_parsers import render_verification_queue_work_item_markdown


@pytest.fixture
def committed_t9(
    tmp_path: Path,
) -> tuple[Path, Path]:
    project = tmp_path / "project"
    root, _plan = _commit_t9(project)
    return project, root


def _replace_base_with_stale_valid_queue(root: Path) -> None:
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json((_stale_item(),)) + "\n",
        encoding="utf-8",
    )


def test_exported_report_loader_cannot_bypass_t9_with_valid_stale_base(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    _replace_base_with_stale_valid_queue(root)

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|commit|receipt)",
    ):
        DELTA.load_report_candidate_universe(root, run_id=RUN_ID)


def test_exported_authority_loader_rejects_wrong_run_without_delta(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(run|t9|publication|authority)",
    ):
        DELTA.load_candidate_universe_authority(
            root,
            run_id="different-current-run",
        )


def test_fabricated_publication_dataclass_is_not_an_authority_capability(
    committed_t9: tuple[Path, Path],
) -> None:
    project, root = committed_t9
    _replace_base_with_stale_valid_queue(root)
    items, binding = DELTA._load_base(root)
    counterfeit = DELTA.AuthenticatedQueuePublication(
        scratchpad_root=str(root.resolve()),
        project_root=str(project.resolve()),
        run_id=RUN_ID,
        plan_digest="0" * 64,
        final_receipt_sha256="0" * 64,
        active_output_denominator=(
            "verification_queue.work_items.json",
            "verification_queue.work_plan.json",
            "verification_queue.md",
            "verify_queue_transaction.receipt.json",
        ),
        base_queue_binding=binding,
        work_plan_digest="0" * 64,
        items=items,
    )

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|capability|receipt|plan)",
    ):
        DELTA.load_candidate_universe_authority(
            root,
            run_id=RUN_ID,
            authenticated_publication=counterfeit,
        )


def test_live_private_state_cannot_downgrade_to_legacy_when_markers_are_lost(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    (root / DELTA.QUEUE_PLAN_AUTHORITY).unlink()
    (root / "verify_queue_transaction.receipt.json").unlink()
    assert (root / "_live_verify_queue_transaction").is_dir()
    assert (root / "verification_queue.work_items.json").is_file()

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|plan|receipt|live)",
    ):
        DELTA.load_current_report_candidate_universe_authority(
            root,
            run_id=RUN_ID,
        )


def test_live_ledger_state_cannot_downgrade_after_private_tree_loss(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    (root / "verify_queue_transaction.receipt.json").unlink()
    shutil.rmtree(root / "_live_verify_queue_transaction")
    assert (root / "_artifact_state.json").is_file()
    assert (root / "verification_queue.work_items.json").is_file()

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|ledger|plan|receipt|live)",
    ):
        DELTA.load_current_report_candidate_universe_authority(
            root,
            run_id=RUN_ID,
        )


def test_delta_writer_cannot_bind_to_tampered_live_base(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    _replace_base_with_stale_valid_queue(root)
    (root / "post_verify_extract.md").write_text(
        "# Post Verify Extract\n\n**Status**: CLEAN_NO_CANDIDATES\n",
        encoding="utf-8",
    )

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|commit|receipt)",
    ):
        DELTA.write_or_validate_post_verify_candidate_delta(
            root,
            run_id=RUN_ID,
            operator_proposals=(),
        )


def test_publication_capability_reports_exact_active_t9_denominator(
    committed_t9: tuple[Path, Path],
) -> None:
    project, root = committed_t9

    publication = DELTA.load_authenticated_queue_publication(
        root,
        project_root=project,
        run_id=RUN_ID,
    )

    materialized = {
        relative
        for relative in publication.active_output_denominator
        if (root / relative).is_file()
    }
    assert set(publication.active_output_denominator) == materialized, (
        "the capability may not turn the plan's inactive conditional outputs "
        "into an allegedly active denominator when an older receipt omits its "
        "redundant active-output projection"
    )


def test_live_candidate_authority_exposes_complete_t9_phaseio_inputs(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9

    authority = DELTA.load_current_report_candidate_universe_authority(
        root,
        run_id=RUN_ID,
    )
    assert {
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
        "verification_queue.md",
        "verify_queue_transaction.receipt.json",
        DELTA.QUEUE_PLAN_AUTHORITY,
    } <= set(authority.input_artifacts), (
        "the central universe authority must expose its complete T9 proof "
        "preimages so every downstream PhaseIO contract binds the same "
        "denominator without caller-specific reconstruction"
    )


def _canonical_stage_projection(root: Path) -> Path:
    authority = DELTA.load_current_report_candidate_universe_authority(
        root,
        run_id=RUN_ID,
    )
    stage = root / ".pio" / "ri" / "test-projection" / "staged_target"
    stage.mkdir(parents=True)
    for relative in authority.input_artifacts:
        source = root / relative
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return stage


def test_authenticated_canonical_stage_uses_exact_typed_projection(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    stage = _canonical_stage_projection(root)

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|live)",
    ):
        DELTA.load_current_report_candidate_universe_authority(
            stage,
            run_id=RUN_ID,
        )

    with DELTA.authenticated_historical_typed_stage_scope(
        root,
        stage,
        run_id=RUN_ID,
    ):
        projected = DELTA.load_current_report_candidate_universe_authority(
            stage,
            run_id=RUN_ID,
        )
    live = DELTA.load_current_report_candidate_universe_authority(
        root,
        run_id=RUN_ID,
    )
    assert projected.candidates == live.candidates


def test_authenticated_canonical_stage_rejects_one_byte_input_drift(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    stage = _canonical_stage_projection(root)
    base = stage / "verification_queue.work_items.json"
    base.write_bytes(base.read_bytes() + b" ")

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(differs|authenticated|input)",
    ):
        with DELTA.authenticated_historical_typed_stage_scope(
            root,
            stage,
            run_id=RUN_ID,
        ):
            pass

class _SameIdentitySemanticDriftExecutor(_TypedPublicationExecutor):
    def _public_bytes(self) -> dict[str, bytes]:
        rows = super()._public_bytes()
        original = _base_item()
        drifted = QueueWorkItem.from_legacy_row({
            "finding id": original.work_item_id,
            "severity": original.severity_proposal.level,
            "title": original.title,
            "bug class": "DIFFERENT_ROUTING_CLASS",
            "preferred tag": "INVARIANT-FUZZ",
            "location": "src/Other.sol:999",
            "primary artifact": "different_inventory.md",
            "poc class": "economic",
        })
        rows["verification_queue.md"] = (
            render_verification_queue_work_item_markdown((drifted,))
            .encode("utf-8")
        )
        return rows


class _InvalidUtf8MarkdownExecutor(_TypedPublicationExecutor):
    def _public_bytes(self) -> dict[str, bytes]:
        rows = super()._public_bytes()
        rows["verification_queue.md"] += b"\n<!-- invalid-byte: \xff -->\n"
        return rows


def test_t9_markdown_must_match_all_typed_routing_semantics(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    # Reuse the production T0--T9 topology and seed helper, varying only the
    # semantic fixture's Markdown projection.
    import test_live_verify_queue_transaction_semantic_closure as LIVE

    plan = LIVE._plan("sc", "claude")
    LIVE._seed_inputs(root, project, "sc", "claude")
    result = TRANSACTION.execute_live_verify_queue_transaction(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=RUN_ID,
        semantic_executor=_SameIdentitySemanticDriftExecutor(plan),
    )
    assert result["state"] == "OUTPUT_COMMITTED"

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(markdown|typed|projection|routing|location|poc)",
    ):
        DELTA.load_authenticated_queue_publication(
            root,
            project_root=project,
            run_id=RUN_ID,
        )


def test_t9_markdown_authority_requires_strict_utf8(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    import test_live_verify_queue_transaction_semantic_closure as LIVE

    plan = LIVE._plan("sc", "claude")
    LIVE._seed_inputs(root, project, "sc", "claude")
    result = TRANSACTION.execute_live_verify_queue_transaction(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=RUN_ID,
        semantic_executor=_InvalidUtf8MarkdownExecutor(plan),
    )
    assert result["state"] == "OUTPUT_COMMITTED"

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(markdown|utf-8|encoding|projection)",
    ):
        DELTA.load_authenticated_queue_publication(
            root,
            project_root=project,
            run_id=RUN_ID,
        )


def test_coherent_queue_rewrite_during_validation_is_not_admitted(
    committed_t9: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, root = committed_t9
    original_validate = TRANSACTION.validate_live_verify_queue_publication

    def validate_then_rewrite(**kwargs):
        decision = original_validate(**kwargs)
        assert decision["safe_to_consume"] is True
        stale = _stale_item()
        stale_items = (stale,)
        stale_plan = build_queue_work_plan(
            stale_items,
            {"fixture-0": (stale.work_item_id,)},
            planner_version="toctou-stale-v1",
        )
        (root / "verification_queue.work_items.json").write_text(
            queue_records_to_json(stale_items) + "\n",
            encoding="utf-8",
        )
        (root / "verification_queue.work_plan.json").write_text(
            stale_plan.to_json() + "\n",
            encoding="utf-8",
        )
        (root / "verification_queue.md").write_text(
            render_verification_queue_work_item_markdown(stale_items),
            encoding="utf-8",
        )
        return decision

    monkeypatch.setattr(
        TRANSACTION,
        "validate_live_verify_queue_publication",
        validate_then_rewrite,
    )

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(t9|publication|authority|changed|race|commit)",
    ):
        DELTA.load_authenticated_queue_publication(
            root,
            project_root=project,
            run_id=RUN_ID,
        )


def test_implicit_live_loader_cannot_accept_prior_run_against_checkpoint(
    committed_t9: tuple[Path, Path],
) -> None:
    _project, root = committed_t9
    (root / "_v2_checkpoint.json").write_text(
        json.dumps({"run_id": "new-current-run"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        PostVerifyCandidateDeltaError,
        match="(?i)(run|checkpoint|t9|publication|authority)",
    ):
        DELTA.load_current_report_candidate_universe_authority(root)
