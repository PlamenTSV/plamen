"""An empty report needs typed authority, not empty counts or copied markers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_validators as V


STUB_ISSUE = "AUDIT_REPORT.md is a stub (0 finding sections)"
TIERS = ("critical_high", "medium", "low_info")


def _empty_report(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    scratch = project / ".scratchpad"
    scratch.mkdir()
    (project / "AUDIT_REPORT.md").write_text(
        "# Audit Report\n\n## Summary\n\nNo active findings.\n",
        encoding="utf-8",
    )
    config = {
        "_run_id": "quality-empty-run",
        "pipeline": "sc", "mode": "core", "language": "evm",
        "cli_backend": "codex", "project_root": str(project),
        "scratchpad": str(scratch),
    }
    return project, scratch, config


@pytest.mark.parametrize("explicit_context", [False, True])
def test_zero_counts_without_committed_authority_remain_stub(tmp_path, explicit_context):
    project, scratch, config = _empty_report(tmp_path)
    (scratch / "report_index.md").write_text(
        "# Report Index\n\nNo active assignments.\n", encoding="utf-8",
    )
    kwargs = {"config": config} if explicit_context else {}
    issues = V._run_report_quality_gate(scratch, str(project), **kwargs)
    assert STUB_ISSUE in issues
    quality = (scratch / "report_quality.md").read_text(encoding="utf-8")
    assert "| stub_guard | FAIL |" in quality
    assert "Overall: FAIL" in quality


@pytest.mark.parametrize("explicit_context", [False, True])
def test_copied_empty_markers_and_sidecars_supply_no_authority(tmp_path, explicit_context):
    project, scratch, config = _empty_report(tmp_path)
    (scratch / "body_manifests").mkdir()
    for tier in TIERS:
        output = f"report_{tier}.md"
        (scratch / output).write_text(
            "# Empty tier\nPLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER\n",
            encoding="utf-8",
        )
        (scratch / "body_manifests" / f"report_{tier}.empty.json").write_text(
            json.dumps({
                "auth": "PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER",
                "shard": f"report_{tier}", "assigned_count": 0, "output": output,
            }),
            encoding="utf-8",
        )
    kwargs = {"config": config} if explicit_context else {}
    assert STUB_ISSUE in V._run_report_quality_gate(scratch, str(project), **kwargs)


def _nonempty_index(scratch: Path):
    (scratch / "report_index.md").write_text(
        "## Master Finding Index\n"
        "| Report ID | Title | Severity | Internal Hypothesis |\n"
        "|---|---|---|---|\n"
        "| H-01 | Missing report section | High | INV-1 |\n",
        encoding="utf-8",
    )


def test_staged_report_keeps_source_project_root_for_typed_replay(tmp_path, monkeypatch):
    project, scratch, config = _empty_report(tmp_path)
    (project / "AUDIT_REPORT.md").replace(scratch / "AUDIT_REPORT.md")
    replay_roots = []
    original = V._empty_tier_sidecar_valid

    def record_replay(*args, **kwargs):
        replay_roots.append(kwargs["project_root"])
        return original(*args, **kwargs)

    monkeypatch.setattr(V, "_empty_tier_sidecar_valid", record_replay)
    # No authority is invented: the missing committed tier still rejects.
    assert STUB_ISSUE in V._run_report_quality_gate(scratch, str(scratch), config=config)
    assert replay_roots == [project]


@pytest.mark.parametrize("missing_root", [None, "", 0, [], {}])
def test_malformed_authority_project_root_cannot_authorize_empty_report(tmp_path, missing_root):
    project, scratch, config = _empty_report(tmp_path)
    config["project_root"] = missing_root
    assert STUB_ISSUE in V._run_report_quality_gate(scratch, str(project), config=config)


def test_nonempty_assignments_cannot_enter_empty_exemption(tmp_path, monkeypatch):
    project, scratch, config = _empty_report(tmp_path)
    _nonempty_index(scratch)

    def unexpected_empty_replay(*_args, **_kwargs):
        pytest.fail("nonempty assignments must not enter the empty-report exemption")

    monkeypatch.setattr(V, "_empty_tier_sidecar_valid", unexpected_empty_replay)
    issues = V._run_report_quality_gate(scratch, str(project), config=config)
    assert STUB_ISSUE in issues
    assert any("report body ID set mismatch" in issue for issue in issues)


def test_appendix_only_nonempty_denominator_is_not_an_authenticated_empty_run(tmp_path):
    project, scratch, config = _empty_report(tmp_path)
    _nonempty_index(scratch)
    (scratch / "disposition.md").write_text(
        "| Report ID | Disposition | Reason |\n|---|---|---|\n"
        "| H-01 | APPENDIX | Separate placement decision |\n",
        encoding="utf-8",
    )
    assert STUB_ISSUE in V._run_report_quality_gate(
        scratch, str(project), config=config,
    )
