"""Generic queue-denominator checks for mechanical verification precommit."""
from __future__ import annotations

import json
from pathlib import Path

import plamen_driver as D
import plamen_parsers as P
import mechanical_precommit_coverage as coverage
import pytest
from queue_work_items import (
    LineageLink,
    QueueWorkItem,
    SeverityProposal,
    build_queue_work_plan,
)


def _item(work_id: str, severity: str) -> QueueWorkItem:
    return QueueWorkItem(
        candidate_identity=work_id,
        work_item_id=work_id,
        lineage=(LineageLink(
            identity=work_id,
            relation="ORIGIN",
            source_artifact="findings_inventory.md",
        ),),
        aliases=(),
        constituents=(),
        severity_proposal=SeverityProposal(level=severity),
        evidence_class="unclassified",
        bug_class="generic",
        preferred_tag="[CODE-TRACE]",
        queue_priority=1,
        location_records=(),
        primary_artifacts=("findings_inventory.md",),
        poc_class="property",
        title="Generic queue item",
    )


def _queue(root: Path, items: tuple[QueueWorkItem, ...]) -> None:
    P._write_queue_work_item_records_manifest(
        root / "verification_queue.md", items
    )
    partitions = (
        {"sc_verify_shard_a": tuple(item.work_item_id for item in items)}
        if items else {}
    )
    plan = build_queue_work_plan(
        items, partitions, planner_version="test.plan.v1"
    )
    (root / "verification_queue.work_plan.json").write_text(
        plan.to_json() + "\n", encoding="utf-8"
    )


def _results(root: Path, finding_ids: tuple[str, ...]) -> None:
    rows = [{"finding_id": finding_id} for finding_id in finding_ids]
    (root / "mechanical_verify_manifest.json").write_text(
        json.dumps({"generated_at": "test", "counts": {}, "results": rows}),
        encoding="utf-8",
    )


def _config(mode: str = "thorough") -> dict[str, object]:
    return {
        "pipeline": "sc",
        "mode": mode,
        "language": "evm",
        "cli_backend": "claude",
    }


def test_result_manifest_read_is_bounded_before_parsing(tmp_path, monkeypatch):
    from io import BytesIO

    sizes = []

    class ObservedStream(BytesIO):
        def read(self, size=-1):
            sizes.append(size)
            assert size == 17
            return super().read(size)

    monkeypatch.setattr(coverage, "_MAX_MANIFEST_BYTES", 16)
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: ObservedStream(b"x" * 18))
    with pytest.raises(ValueError, match="exceeds byte budget"):
        coverage._strict_result_ids(tmp_path / "manifest.json")
    assert sizes == [17]


def test_precommit_rejects_zero_results_for_mandatory_queue_identity(
    tmp_path: Path,
) -> None:
    _queue(tmp_path, (_item("H-01", "High"),))
    _results(tmp_path, ())
    (tmp_path / "mechanical_verify_manifest.md").write_text(
        "# Mechanical Verify Manifest\n\n**Total verify files**: 0\n",
        encoding="utf-8",
    )
    phase = next(
        phase for phase in D.SC_PHASES if phase.name == "sc_mechanical_verify"
    )

    issues = D._validate_verification_precommit(
        phase, tmp_path, _config(), [phase]
    )

    assert any(
        "omitted mandatory queue identities: H-01" in issue
        for issue in issues
    )


def test_typed_empty_queue_accepts_empty_result_denominator(tmp_path: Path) -> None:
    _queue(tmp_path, ())
    _results(tmp_path, ())
    assert D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config()
    ) == []


def test_policy_optional_queue_item_need_not_have_mechanical_result(
    tmp_path: Path,
) -> None:
    _queue(tmp_path, (_item("L-01", "Low"),))
    _results(tmp_path, ())
    assert D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config("light")
    ) == []


def test_matching_mandatory_result_satisfies_only_identity_denominator(
    tmp_path: Path,
) -> None:
    _queue(tmp_path, (_item("H-01", "High"),))
    # This deliberately skeletal row is sufficient only for this identity
    # denominator helper. Existing result-schema, status, successor, and
    # execution-attempt gates remain responsible for proof acceptance.
    _results(tmp_path, ("H-01",))
    assert D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config()
    ) == []


def test_missing_typed_queue_is_explicit_authority_debt(tmp_path: Path) -> None:
    _results(tmp_path, ())
    issues = D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config()
    )
    assert any("typed queue authority invalid" in issue for issue in issues)


def test_duplicate_case_colliding_result_id_is_rejected(tmp_path: Path) -> None:
    _queue(tmp_path, (_item("H-01", "High"),))
    _results(tmp_path, ("H-01", "h-01"))
    issues = D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config()
    )
    assert any("duplicate/case-colliding identity" in issue for issue in issues)


def test_foreign_result_id_is_rejected(tmp_path: Path) -> None:
    _queue(tmp_path, (_item("H-01", "High"),))
    _results(tmp_path, ("H-01", "H-FOREIGN"))
    issues = D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config()
    )
    assert any("foreign queue identities: H-FOREIGN" in issue for issue in issues)


def test_stale_work_plan_is_typed_authority_debt(tmp_path: Path) -> None:
    _queue(tmp_path, (_item("H-01", "High"),))
    P._write_queue_work_item_records_manifest(
        tmp_path / "verification_queue.md", (_item("H-02", "High"),)
    )
    _results(tmp_path, ())
    issues = D._mechanical_precommit_queue_coverage_issues(
        tmp_path, _config()
    )
    assert any("typed queue authority invalid" in issue for issue in issues)
