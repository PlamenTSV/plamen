"""Bridge dispatch tests; empty-tier authority itself is tested separately."""
from pathlib import Path
from types import SimpleNamespace

import pytest

import report_empty_tier as empty
import rooted_path_io as rooted
from artifact_ledger import ArtifactLedgerError
from report_body_driver_bridge import run_report_body_driver_bridge


@pytest.mark.parametrize("read_only", [False, True])
@pytest.mark.parametrize("committed", [False, True])
def test_absent_manifest_requires_committed_empty_tier(
    tmp_path, monkeypatch, read_only, committed,
):
    calls = []

    def validate(**kwargs):
        calls.append(kwargs)
        return committed

    def forbidden(*args, **kwargs):
        pytest.fail("absent manifest must not enter MODEL publication")

    monkeypatch.setattr(empty, "validate_committed_empty_report_tier", validate)
    phase = SimpleNamespace(name="report_body_writer_critical_high")
    config = {"project_root": str(tmp_path)}
    result = run_report_body_driver_bridge(
        phase, tmp_path, config, resolve_model=forbidden,
        record_model=forbidden, read_only=read_only,
    )
    assert bool(result) is not committed
    if not committed:
        assert "empty report body has no committed producer" in result[0]
    assert calls == [dict(
        scratchpad=tmp_path, project_root=tmp_path,
        config=config, phase_name=phase.name,
    )]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("error", [
    ArtifactLedgerError("foreign empty producer"),
    rooted.RootedPathIOError("unreadable empty producer"),
])
def test_absent_manifest_invalid_empty_authority_is_diagnostic(
    tmp_path, monkeypatch, error,
):
    def invalid(**kwargs):
        raise error

    monkeypatch.setattr(empty, "validate_committed_empty_report_tier", invalid)
    result = run_report_body_driver_bridge(
        SimpleNamespace(name="report_body_writer_medium"), tmp_path,
        {"project_root": str(tmp_path)}, resolve_model=None, record_model=None,
        read_only=True,
    )
    assert result and str(error) in result[0]


@pytest.mark.parametrize("kind", ["directory", "broken_symlink", "malformed"])
def test_present_invalid_manifest_never_falls_back_to_empty_authority(
    tmp_path: Path, monkeypatch, kind,
):
    manifest = tmp_path / "body_manifests/report_medium.json"
    manifest.parent.mkdir()
    if kind == "directory":
        manifest.mkdir()
    elif kind == "broken_symlink":
        manifest.symlink_to(tmp_path / "absent")
    else:
        manifest.write_bytes(b"not-json")

    def forbidden(**kwargs):
        pytest.fail("invalid present manifest must not select empty authority")

    monkeypatch.setattr(empty, "validate_committed_empty_report_tier", forbidden)
    result = run_report_body_driver_bridge(
        SimpleNamespace(name="report_body_writer_medium"), tmp_path,
        {"project_root": str(tmp_path)}, resolve_model=None, record_model=None,
        read_only=True,
    )
    assert result
