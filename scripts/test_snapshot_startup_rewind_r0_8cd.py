"""Driver wiring contract for R0-8c/d content-bound resume."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import plamen_driver as D
from audit_snapshot import LEGACY_UNBOUND, MATCH, MISMATCH, NEW


def _component(digest_char: str) -> dict:
    return {
        "digest": digest_char * 64,
        "path_set_digest": digest_char * 64,
        "file_count": 1,
        "byte_count": 1,
    }


def _bound_snapshot(digest_char: str = "a") -> dict:
    raw = {
        "schema": "plamen.audit-input-snapshot.v1",
        "components": {
            "source_scope": {
                **_component(digest_char),
                "language": "evm",
                "pipeline": "sc",
                "git_head": "UNAVAILABLE",
                "coverage_limitations": [],
            },
            "audit_config": {
                "digest": digest_char * 64,
                "field_count": 1,
            },
            "methodology": _component(digest_char),
            "toolchain": _component(digest_char),
        },
    }
    import hashlib

    payload = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    raw["snapshot_digest"] = hashlib.sha256(payload).hexdigest()
    return raw


def _config(project: Path, scratchpad: Path) -> dict:
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "codex",
    }


def test_new_audit_binds_snapshot_without_archive(tmp_path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    checkpoint, verdict, archive = D._bind_checkpoint_audit_snapshot(
        D.Checkpoint(),
        scratchpad,
        _config(project, scratchpad),
        config_path=config_path,
        checkpoint_existed=False,
    )

    assert verdict.state == NEW
    assert archive is None
    assert checkpoint.audit_snapshot == current
    assert config_path.exists()


def test_matching_resume_preserves_checkpoint_and_artifacts(tmp_path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    inventory = scratchpad / "findings_inventory.md"
    inventory.write_text("preserve")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    checkpoint = D.Checkpoint(completed=["recon"], audit_snapshot=current)

    rebound, verdict, archive = D._bind_checkpoint_audit_snapshot(
        checkpoint,
        scratchpad,
        _config(project, scratchpad),
        config_path=config_path,
        checkpoint_existed=True,
    )
    assert rebound is checkpoint
    assert verdict.state == MATCH
    assert archive is None
    assert inventory.read_text() == "preserve"


@pytest.mark.parametrize("legacy", [True, False])
def test_legacy_or_mismatched_progress_is_full_safe_rewind(
    tmp_path, monkeypatch, legacy
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    (scratchpad / "_plamen.log").write_text("preserve live log")
    (scratchpad / ".plamen_run.lock").write_text("preserve live lock")
    (scratchpad / "findings_inventory.md").write_text("stale answer")
    (scratchpad / "_v2_checkpoint.json").write_text("stale checkpoint")
    report = project / "AUDIT_REPORT.md"
    report.write_text("stale report")
    current = _bound_snapshot("b")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    archived_reports: list[Path] = []

    def _archive_prior(root: Path):
        archived_reports.append(Path(root))
        report.rename(project / ".prior-report.md")
        return project / ".prior-report.md"

    monkeypatch.setattr(D, "_archive_prior_audit_artifacts", _archive_prior)
    stored = None if legacy else _bound_snapshot("a")
    old = D.Checkpoint(completed=["recon", "breadth"], audit_snapshot=stored)

    rebound, verdict, archive = D._bind_checkpoint_audit_snapshot(
        old,
        scratchpad,
        _config(project, scratchpad),
        config_path=config_path,
        checkpoint_existed=True,
    )

    assert verdict.state == (LEGACY_UNBOUND if legacy else MISMATCH)
    assert rebound is not old
    assert rebound.completed == [] and rebound.degraded == []
    assert rebound.audit_snapshot == current
    assert archive is not None and archive.exists()
    assert (archive / "findings_inventory.md").read_text() == "stale answer"
    assert not (scratchpad / "findings_inventory.md").exists()
    assert config_path.exists()
    assert (scratchpad / "_plamen.log").exists()
    assert (scratchpad / ".plamen_run.lock").exists()
    assert (scratchpad / D._AUDIT_FRESH_SENTINEL_NAME).exists()
    assert (scratchpad / "snapshot_rewind_receipt.json").exists()
    assert archived_reports == [project]
    assert not report.exists()


def test_legacy_empty_checkpoint_is_not_silently_trusted(tmp_path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    (scratchpad / "partial_recon.md").write_text("partial old evidence")
    current = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)

    rebound, verdict, archive = D._bind_checkpoint_audit_snapshot(
        D.Checkpoint(),
        scratchpad,
        _config(project, scratchpad),
        config_path=config_path,
        checkpoint_existed=True,
    )
    assert verdict.state == LEGACY_UNBOUND
    assert archive is not None
    assert not (scratchpad / "partial_recon.md").exists()
    assert rebound.audit_snapshot == current


def test_archive_failure_never_continues_against_stale_artifacts(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config_path = scratchpad / "config.json"
    config_path.write_text("{}")
    current = _bound_snapshot("b")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    monkeypatch.setattr(
        D,
        "archive_stale_scratchpad",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("archive failed")),
    )

    with pytest.raises(RuntimeError, match="archive failed"):
        D._bind_checkpoint_audit_snapshot(
            D.Checkpoint(completed=["recon"], audit_snapshot=_bound_snapshot("a")),
            scratchpad,
            _config(project, scratchpad),
            config_path=config_path,
            checkpoint_existed=True,
        )


def test_snapshot_binding_precedes_recon_prepass_in_main_source():
    source = Path(D.__file__).read_text(encoding="utf-8", errors="replace")
    bind_call = source.index("_bind_checkpoint_audit_snapshot(", source.index("def main("))
    prepass_call = source.index("run_recon_prepass(config)", bind_call)
    assert bind_call < prepass_call


def test_phase_boundary_drift_fails_closed_with_durable_receipt(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = _config(project, scratchpad)
    config["_audit_snapshot"] = _bound_snapshot("a")
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: _bound_snapshot("b"))

    with pytest.raises(D.AuditInputDriftError, match="source_scope"):
        D._assert_audit_snapshot_still_bound(config, scratchpad, "verify:pre")
    receipt = json.loads((scratchpad / "audit_input_drift.json").read_text())
    assert receipt["phase"] == "verify:pre"
    assert receipt["changed_components"] == ["source_scope", "audit_config", "methodology", "toolchain"]
    assert receipt["action"].startswith("restart from recon")


def test_matching_phase_boundary_does_not_emit_drift_receipt(
    tmp_path, monkeypatch
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    current = _bound_snapshot("a")
    config = _config(project, scratchpad)
    config["_audit_snapshot"] = current
    monkeypatch.setattr(D, "build_audit_snapshot", lambda *_a, **_k: current)
    D._assert_audit_snapshot_still_bound(config, scratchpad, "report:pre")
    assert not (scratchpad / "audit_input_drift.json").exists()


def test_phase_validator_rechecks_snapshot_after_worker_execution():
    source = Path(D.__file__).read_text(encoding="utf-8", errors="replace")
    start = source.index("def _run_phase_validators(")
    end = source.index("\ndef ", start + 4)
    validator = source[start:end]
    assert "_assert_audit_snapshot_still_bound(" in validator
