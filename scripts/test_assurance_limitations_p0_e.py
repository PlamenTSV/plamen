"""P0-E: degraded recall work must be visible inside the delivered report."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

import assurance_limitations as assurance
from assurance_limitations import (
    END_MARKER,
    START_MARKER,
    build_assurance_manifest,
    project_assurance_limitations,
    validate_assurance_projection,
)
from plamen_types import Checkpoint, GateFailure, PhaseCommit


def _checkpoint(
    phase: str,
    *,
    gate_class: str = "METHODOLOGY_APPLICATION",
    message: str = "bounded repair exhausted",
) -> Checkpoint:
    run_id = str(uuid.uuid4())
    failure = GateFailure(
        gate_id=f"{phase}.p0e.synthetic",
        gate_class=gate_class,
        message=message,
        affected_identities=("OBL-1",),
    )
    commit = PhaseCommit(
        phase_name=phase,
        state="COMPLETED_WITH_DEBT",
        run_id=run_id,
        unresolved_failures=(failure,),
    )
    return Checkpoint(
        completed=[phase],
        degraded=[phase],
        run_id=run_id,
        phase_commits={phase: commit},
    )


def test_exploration_and_axis_debt_are_discovery_recall_limitations():
    for phase in ("exploration_skeptic", "axis_coverage"):
        manifest = build_assurance_manifest(_checkpoint(phase))
        assert manifest["row_count"] == 1
        assert manifest["rows"][0]["assurance_impact"] == "DISCOVERY_RECALL"
        assert manifest["clean_full_audit_claim_allowed"] is False


def test_optional_context_only_research_is_enrichment_not_verification():
    manifest = build_assurance_manifest(_checkpoint("rag_sweep"))
    assert manifest["rows"][0]["assurance_impact"] == "ENRICHMENT_ONLY"


def test_recall_positive_followup_phases_are_not_mislabeled_as_enrichment():
    for phase in ("invariants_p2", "chain_iter2", "post_verify_extract"):
        manifest = build_assurance_manifest(_checkpoint(phase))
        assert manifest["rows"][0]["assurance_impact"] == "DISCOVERY_RECALL"
        assert manifest["clean_full_audit_claim_allowed"] is False


def test_verifier_and_report_debt_keep_distinct_impact_classes():
    assert build_assurance_manifest(_checkpoint("sc_verify_low_a"))["rows"][0][
        "assurance_impact"
    ] == "VERIFICATION_CONFIDENCE"
    assert build_assurance_manifest(_checkpoint("report_index"))["rows"][0][
        "assurance_impact"
    ] == "REPORT_INTEGRITY"


def test_legacy_degraded_without_typed_commit_is_retained_not_erased():
    checkpoint = Checkpoint(degraded=["exploration_skeptic"])
    manifest = build_assurance_manifest(checkpoint)
    assert manifest["row_count"] == 1
    assert manifest["rows"][0]["gate_class"] == "LEGACY_UNTYPED_DEGRADATION"
    assert manifest["rows"][0]["assurance_impact"] == "DISCOVERY_RECALL"


def test_manifest_is_bound_to_the_authoritative_checkpoint_run():
    one = _checkpoint("axis_coverage")
    two = Checkpoint(
        completed=list(one.completed),
        degraded=list(one.degraded),
        run_id=str(uuid.uuid4()),
        phase_commits={},
    )
    failure = next(iter(one.phase_commits.values())).unresolved_failures[0]
    two.phase_commits["axis_coverage"] = PhaseCommit(
        phase_name="axis_coverage",
        state="COMPLETED_WITH_DEBT",
        run_id=two.run_id,
        unresolved_failures=(failure,),
    )

    first = build_assurance_manifest(one)
    second = build_assurance_manifest(two)
    assert first["rows"] == second["rows"]
    assert first["run_id"] == one.run_id
    assert second["run_id"] == two.run_id
    assert first["manifest_sha256"] != second["manifest_sha256"]


def test_projection_is_exact_idempotent_and_model_rewrite_is_detected(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n\n## Summary\nClean and complete.\n", encoding="utf-8")
    checkpoint = _checkpoint("exploration_skeptic")

    first = project_assurance_limitations(checkpoint, scratchpad, report)
    first_bytes = report.read_bytes()
    second = project_assurance_limitations(checkpoint, scratchpad, report)
    assert first == second == 1
    assert report.read_bytes() == first_bytes
    rendered = report.read_text(encoding="utf-8")
    assert rendered.count("## Audit Completeness and Assurance Limitations") == 1
    assert "DISCOVERY_RECALL" in rendered
    assert "must not be represented as a clean or full audit" in rendered
    assert validate_assurance_projection(checkpoint, scratchpad, report) == []

    report.write_text(rendered.replace("DISCOVERY_RECALL", "ENRICHMENT_ONLY"), encoding="utf-8")
    issues = validate_assurance_projection(checkpoint, scratchpad, report)
    assert issues and "differs from the driver-owned projection" in issues[0]


def test_projection_preserves_unmanaged_report_bytes_and_validates_md_sidecar(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    unmanaged = b"# Audit Report\r\n\r\n## Summary\r\nQualified.  \r\n"
    report.write_bytes(unmanaged)
    checkpoint = _checkpoint("axis_coverage")

    project_assurance_limitations(checkpoint, scratchpad, report)
    assert report.read_bytes().startswith(unmanaged.rstrip(b"\r\n"))
    assert validate_assurance_projection(checkpoint, scratchpad, report) == []

    sidecar = scratchpad / "assurance_limitations.md"
    sidecar.write_text("model-authored replacement\n", encoding="utf-8")
    issues = validate_assurance_projection(checkpoint, scratchpad, report)
    assert issues and "sidecar differs" in issues[0]


def test_omitted_and_duplicate_driver_blocks_are_rejected_then_repaired(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    base = "# Audit Report\n\n## Summary\nQualified.\n"
    report.write_text(base, encoding="utf-8")
    checkpoint = _checkpoint("axis_coverage")
    project_assurance_limitations(checkpoint, scratchpad, report)
    section = (scratchpad / "assurance_limitations.md").read_text(encoding="utf-8")

    report.write_text(base, encoding="utf-8")
    issues = validate_assurance_projection(checkpoint, scratchpad, report)
    assert issues and "omits" in issues[0]

    report.write_text(base.rstrip() + "\n\n" + section + "\n" + section, encoding="utf-8")
    issues = validate_assurance_projection(checkpoint, scratchpad, report)
    assert issues and "duplicate" in issues[0]

    project_assurance_limitations(checkpoint, scratchpad, report)
    assert validate_assurance_projection(checkpoint, scratchpad, report) == []
    assert report.read_text(encoding="utf-8").count(START_MARKER) == 1


def test_orphaned_marker_or_heading_cannot_be_hidden_by_reprojection(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n", encoding="utf-8")
    checkpoint = _checkpoint("axis_coverage")
    project_assurance_limitations(checkpoint, scratchpad, report)
    tampered = report.read_text(encoding="utf-8").replace(
        START_MARKER, "<!-- damaged assurance marker -->", 1
    )
    report.write_text(tampered, encoding="utf-8")

    # Reprojection may append a fresh valid block, but it must not legitimize
    # the orphaned old heading/end marker left by a model or assembler rewrite.
    project_assurance_limitations(checkpoint, scratchpad, report)
    issues = validate_assurance_projection(checkpoint, scratchpad, report)
    assert issues and "orphaned or duplicate" in issues[0]


def test_typed_messages_cannot_inject_managed_block_markers(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n", encoding="utf-8")
    checkpoint = _checkpoint(
        "axis_coverage",
        message=f"worker copied {END_MARKER} and {START_MARKER}",
    )

    project_assurance_limitations(checkpoint, scratchpad, report)
    rendered = report.read_text(encoding="utf-8")
    assert rendered.count(START_MARKER) == 1
    assert rendered.count(END_MARKER) == 1
    assert validate_assurance_projection(checkpoint, scratchpad, report) == []


def test_report_replace_fault_preserves_report_and_validation_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    original = b"# Audit Report\n\n## Summary\nClean.\n"
    report.write_bytes(original)
    checkpoint = _checkpoint("axis_coverage")
    real_replace = assurance.os.replace

    def fail_report_replace(source, destination):
        if Path(destination) == report:
            raise OSError("synthetic report replacement failure")
        return real_replace(source, destination)

    monkeypatch.setattr(assurance.os, "replace", fail_report_replace)
    with pytest.raises(OSError, match="synthetic report replacement failure"):
        project_assurance_limitations(checkpoint, scratchpad, report)

    assert report.read_bytes() == original
    assert not list(tmp_path.glob(f".{report.name}.*.tmp"))
    issues = validate_assurance_projection(checkpoint, scratchpad, report)
    assert issues and "omits" in issues[0]


def test_unreadable_or_missing_projection_artifacts_are_validation_debt(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n", encoding="utf-8")
    checkpoint = _checkpoint("axis_coverage")

    assert "manifest unreadable" in validate_assurance_projection(
        checkpoint, scratchpad, report
    )[0]
    (scratchpad / "assurance_limitations.json").write_text("{", encoding="utf-8")
    assert "manifest unreadable" in validate_assurance_projection(
        checkpoint, scratchpad, report
    )[0]

    project_assurance_limitations(checkpoint, scratchpad, report)
    report.unlink()
    assert "report unreadable" in validate_assurance_projection(
        checkpoint, scratchpad, report
    )[0]


def test_resolved_retry_removes_stale_managed_section_and_clean_run_has_no_banner(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n", encoding="utf-8")
    assert project_assurance_limitations(
        _checkpoint("axis_coverage"), scratchpad, report
    ) == 1

    clean = Checkpoint()
    assert project_assurance_limitations(clean, scratchpad, report) == 0
    assert "Audit Completeness and Assurance Limitations" not in report.read_text(
        encoding="utf-8"
    )
    manifest = json.loads(
        (scratchpad / "assurance_limitations.json").read_text(encoding="utf-8")
    )
    assert manifest["row_count"] == 0
    assert validate_assurance_projection(clean, scratchpad, report) == []


def test_resume_projection_is_stable_across_checkpoint_roundtrip(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    report = tmp_path / "AUDIT_REPORT.md"
    report.write_text("# Audit Report\n", encoding="utf-8")
    checkpoint = _checkpoint("axis_coverage")
    checkpoint.save(scratchpad)
    project_assurance_limitations(checkpoint, scratchpad, report)
    before_report = report.read_bytes()
    before_manifest = (scratchpad / "assurance_limitations.json").read_bytes()

    resumed = Checkpoint.load(scratchpad)
    project_assurance_limitations(resumed, scratchpad, report)
    assert report.read_bytes() == before_report
    assert (scratchpad / "assurance_limitations.json").read_bytes() == before_manifest
