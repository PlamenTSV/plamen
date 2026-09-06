"""Fixture-first tests for the report source-path roster authority."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

from audit_snapshot import (  # noqa: E402
    SnapshotInputError,
    build_audit_snapshot,
    build_production_source_path_authority,
    canonical_production_source_path_authority_bytes,
    validate_production_source_path_authority,
)
import report_capture_phaseio_authority as RCA  # noqa: E402


def _implementation(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "plamen_driver.py").write_text("VERSION = 1\n")
    (root / "prompts" / "phase.md").write_text("method v1\n")
    (root / "rules" / "rule.md").write_text("rule v1\n")
    return root


def _fixture(tmp_path: Path):
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "Vault.sol").write_text("contract Vault {}\n")
    (project / "README.md").write_text("context\n")
    implementation = _implementation(tmp_path / "plamen")
    config = {
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
    }
    snapshot = build_audit_snapshot(config, implementation)
    return project, config, snapshot


def test_source_path_authority_is_bound_to_complete_snapshot_and_roster(
    tmp_path: Path,
) -> None:
    _project, config, snapshot = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)

    assert authority["source_paths"] == ["src/Vault.sol"]
    assert authority["source_path_count"] == 1
    assert authority["snapshot_digest"] == snapshot["snapshot_digest"]
    assert authority["source_scope_digest"] == (
        snapshot["components"]["source_scope"]["digest"]
    )
    raw = canonical_production_source_path_authority_bytes(
        authority, expected_snapshot=snapshot
    )
    assert json.loads(raw.decode("utf-8")) == authority


def test_source_path_authority_rejects_source_gain_after_snapshot(
    tmp_path: Path,
) -> None:
    project, config, snapshot = _fixture(tmp_path)
    (project / "src" / "Late.sol").write_text("contract Late {}\n")

    with pytest.raises(SnapshotInputError, match="changed|source scope"):
        build_production_source_path_authority(config, snapshot)


def test_source_path_authority_rejects_forged_snapshot_or_roster(
    tmp_path: Path,
) -> None:
    _project, config, snapshot = _fixture(tmp_path)
    authority = build_production_source_path_authority(config, snapshot)
    forged_snapshot = copy.deepcopy(snapshot)
    forged_snapshot["snapshot_digest"] = "f" * 64
    with pytest.raises(SnapshotInputError, match="snapshot"):
        build_production_source_path_authority(config, forged_snapshot)

    forged_authority = copy.deepcopy(authority)
    forged_authority["source_paths"].append("src/Injected.sol")
    forged_authority["source_path_count"] += 1
    with pytest.raises(SnapshotInputError, match="digest|content|authority"):
        validate_production_source_path_authority(
            forged_authority, expected_snapshot=snapshot
        )


def test_driver_transaction_commits_roster_for_default_source_capture(
    tmp_path: Path,
) -> None:
    project, config, snapshot = _fixture(tmp_path)
    scratch = project / ".scratchpad"
    scratch.mkdir()
    config.update(
        {
            "_run_id": "123e4567-e89b-42d3-a456-426614174000",
            "_audit_snapshot": snapshot,
        }
    )
    import plamen_driver as driver

    assert driver._run_report_source_path_authority_transaction(
        scratch, config
    ) == []
    raw = (scratch / "report_source_path_authority.json").read_bytes()
    assert canonical_production_source_path_authority_bytes(
        json.loads(raw.decode("utf-8")), expected_snapshot=snapshot
    ) == raw

    prepared = RCA.prepare_report_source_capture(
        scratchpad=scratch,
        project_root=project,
        run_id=config["_run_id"],
        expected_config=config,
        metadata={
            "pipeline": "sc",
            "mode": "thorough",
            "ecosystem": "evm",
            "backend": "claude",
            "project_name": "fixture-project",
            "report_date": "2026-08-04",
            "run_id": config["_run_id"],
            "scope": "src/",
            "source_snapshot_sha256": snapshot["snapshot_digest"],
        },
    )
    assert "report_source_path_authority.json" in prepared.exact_input_paths
    requirement = next(
        row
        for row in prepared.contract.input_authority_requirements
        if row.identity == "scratchpad:report_source_path_authority.json"
    )
    assert requirement.allow_raw is False
    assert requirement.expected_producer_work_unit_key.endswith(
        "/report_assemble/source_path_authority"
    )
