"""RED fixtures for the report candidate-universe T9 presence bypass.

These fixtures deliberately start from a ledger-committed T9 publication.
They pin one production read capability, ``load_authenticated_queue_publication``,
instead of allowing report consumers to infer authority from the presence of
``verification_queue.work_items.json``.

The fixture executor is intentionally narrow: T0--T9 ownership and publication
are production code, while the semantic payload is a single valid typed queue
record plus its lossless Markdown projection and exact work plan.  This keeps
the tests about publication authority rather than rediscovering queue-building
semantics already covered elsewhere.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import post_verify_candidate_delta as DELTA
from post_verify_candidate_delta import PostVerifyCandidateDeltaError
from queue_work_items import (
    QueueWorkItem,
    QueueWorkPlan,
    build_queue_work_plan,
    queue_records_to_json,
)
from plamen_parsers import render_verification_queue_work_item_markdown
import test_live_verify_queue_transaction_semantic_closure as LIVE
import verify_queue_transaction as TRANSACTION


RUN_ID = "live-sc-claude"


def _base_item() -> QueueWorkItem:
    return QueueWorkItem.from_legacy_row({
        "finding id": "BASE-1",
        "severity": "Medium",
        "title": "Committed base candidate",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Base.sol:10",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })


def _stale_item() -> QueueWorkItem:
    return QueueWorkItem.from_legacy_row({
        "finding id": "STALE-1",
        "severity": "Low",
        "title": "Stale replacement candidate",
        "bug class": "STALE_PROJECTION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Stale.sol:7",
        "primary artifact": "older_findings_inventory.md",
        "poc class": "structural",
    })


class _TypedPublicationExecutor(LIVE._LiveSemanticExecutor):
    """Publish one typed queue while retaining the production T9 transaction."""

    def __init__(
        self,
        plan: Mapping[str, Any],
        *,
        markdown_disagreement: bool = False,
    ) -> None:
        super().__init__(plan)
        self.markdown_disagreement = markdown_disagreement

    def _public_bytes(self) -> dict[str, bytes]:
        rows = super()._public_bytes()
        item = _base_item()
        items = (item,)
        work_plan = build_queue_work_plan(
            items,
            {"fixture-0": (item.work_item_id,)},
            planner_version="t9-red-fixture-v1",
        )
        markdown_items = () if self.markdown_disagreement else items
        rows["verification_queue.work_items.json"] = (
            queue_records_to_json(items) + "\n"
        ).encode("utf-8")
        rows["verification_queue.work_plan.json"] = (
            work_plan.to_json() + "\n"
        ).encode("utf-8")
        rows["verification_queue.md"] = (
            render_verification_queue_work_item_markdown(markdown_items)
            .encode("utf-8")
        )
        return rows


def _commit_t9(
    project: Path,
    *,
    markdown_disagreement: bool = False,
) -> tuple[Path, Mapping[str, Any]]:
    plan = LIVE._plan("sc", "claude")
    root = project / ".scratchpad"
    LIVE._seed_inputs(root, project, "sc", "claude")
    result = TRANSACTION.execute_live_verify_queue_transaction(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=RUN_ID,
        semantic_executor=_TypedPublicationExecutor(
            plan,
            markdown_disagreement=markdown_disagreement,
        ),
    )
    assert result["state"] == "OUTPUT_COMMITTED"
    decision = TRANSACTION.validate_live_verify_queue_publication(
        scratchpad=root,
        project_root=project,
        plan=plan,
        run_id=RUN_ID,
    )
    assert decision["safe_to_consume"] is True, decision["issues"]
    return root, plan


@pytest.fixture
def committed_t9(
    tmp_path: Path,
) -> tuple[Path, Path, Mapping[str, Any]]:
    project = tmp_path / "project"
    root, plan = _commit_t9(project)
    return project, root, plan


def _publication_loader():
    loader = getattr(DELTA, "load_authenticated_queue_publication", None)
    assert callable(loader), (
        "production must expose load_authenticated_queue_publication; report "
        "code cannot infer T9 authority from sidecar presence"
    )
    return loader


def _load_publication(
    *,
    project: Path,
    root: Path,
    plan: Mapping[str, Any],
):
    return _publication_loader()(
        root,
        project_root=project,
        plan=plan,
        run_id=RUN_ID,
    )


def _rejection_detail(
    *,
    project: Path,
    root: Path,
    plan: Mapping[str, Any],
) -> str:
    """Accept an explicit exception or an explicit unsafe/debt decision."""

    try:
        result = _load_publication(project=project, root=root, plan=plan)
    except PostVerifyCandidateDeltaError as exc:
        return str(exc)
    if isinstance(result, Mapping):
        assert result.get("safe_to_consume") is False
        return repr({
            "issues": result.get("issues"),
            "debts": result.get("debts"),
        })
    safe = getattr(result, "safe_to_consume", None)
    assert safe is False, "an unauthenticated T9 publication was admitted"
    return repr({
        "issues": getattr(result, "issues", None),
        "debts": getattr(result, "debts", None),
    })


@pytest.mark.parametrize("replacement", ("empty", "stale"))
def test_valid_typed_empty_or_stale_sidecar_cannot_replace_committed_t9_base(
    committed_t9: tuple[Path, Path, Mapping[str, Any]],
    replacement: str,
) -> None:
    project, root, plan = committed_t9
    items = () if replacement == "empty" else (_stale_item(),)
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json(items) + "\n",
        encoding="utf-8",
    )

    detail = _rejection_detail(project=project, root=root, plan=plan)

    assert any(
        token in detail.casefold()
        for token in ("t9", "publication", "commit", "receipt", "authority")
    ), detail


def test_sidecar_and_work_plan_coherent_mutation_rejects_unchanged_t9_receipt(
    committed_t9: tuple[Path, Path, Mapping[str, Any]],
) -> None:
    project, root, plan = committed_t9
    current_plan = QueueWorkPlan.from_json(
        (root / "verification_queue.work_plan.json").read_text(
            encoding="utf-8",
        )
    )
    empty_plan = build_queue_work_plan(
        (),
        {shard.shard_id: () for shard in current_plan.shards},
        planner_version=current_plan.planner_version,
    )
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json(()) + "\n",
        encoding="utf-8",
    )
    (root / "verification_queue.work_plan.json").write_text(
        empty_plan.to_json() + "\n",
        encoding="utf-8",
    )

    detail = _rejection_detail(project=project, root=root, plan=plan)

    assert any(
        token in detail.casefold()
        for token in ("t9", "publication", "commit", "receipt", "authority")
    ), detail


def test_t9_committed_markdown_typed_disagreement_is_explicit_debt_or_rejection(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root, plan = _commit_t9(project, markdown_disagreement=True)

    detail = _rejection_detail(project=project, root=root, plan=plan)

    lowered = detail.casefold()
    assert "markdown" in lowered, detail
    assert "typed" in lowered or "work item" in lowered, detail


def test_post_verify_delta_is_additive_over_authenticated_t9_base(
    committed_t9: tuple[Path, Path, Mapping[str, Any]],
) -> None:
    project, root, plan = committed_t9
    (root / "verify_BASE-1.md").write_text(
        "# Verification\n",
        encoding="utf-8",
    )
    (root / "post_verify_extract.md").write_text(
        (
            "# Post Verify Extract\n\n"
            "### Finding [VER-1]: Late candidate\n"
            "**Severity**: Medium\n"
            "**Location**: src/Late.sol:20\n"
            "**Root Cause**: An independently observed late mechanism remains.\n"
            "**Impact**: A protected state transition may be violated.\n"
            "**Source Verify File**: verify_BASE-1.md\n"
        ),
        encoding="utf-8",
    )
    DELTA.write_or_validate_post_verify_candidate_delta(
        root,
        run_id=RUN_ID,
        operator_proposals=(),
    )
    publication = _load_publication(
        project=project,
        root=root,
        plan=plan,
    )

    authority = DELTA.load_candidate_universe_authority(
        root,
        run_id=RUN_ID,
        authenticated_publication=publication,
    )

    ids = {candidate.item.work_item_id for candidate in authority.candidates}
    late_ids = ids - {"BASE-1"}
    assert len(late_ids) == 1
    assert next(iter(late_ids)).startswith("VER-")
    # Model-proposed late IDs are intentionally non-authoritative; the
    # lifecycle derives a stable content identity instead.
    assert "VER-1" not in late_ids
    assert authority.union_record_count == 2
    assert authority.base_queue_binding["record_count"] == 1
