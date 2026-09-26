from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import audit_snapshot
import program_facts_driver_integration as integration


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _degraded_preparation() -> dict[str, str]:
    unsigned = {
        "schema_version": "plamen.evm_input_preparation.v1",
        "status": "DEGRADED",
        "reason": "fixture materialization is intentionally deferred",
    }
    return {
        **unsigned,
        "preparation_sha256": hashlib.sha256(_canonical(unsigned)).hexdigest(),
    }


def _config(tmp_path: Path) -> dict[str, object]:
    project = tmp_path / "project"
    source = project / "src" / "Main.sol"
    source.parent.mkdir(parents=True)
    source.write_text(
        "pragma solidity ^0.8.20; contract Main {}\n",
        encoding="utf-8",
    )
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir()
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "_snapshot_input_preparation": _degraded_preparation(),
    }


def test_snapshot_visible_config_replays_degraded_preparation_exactly(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    projected = integration._snapshot_visible_config(config)

    assert projected["_snapshot_input_preparation"] == config[
        "_snapshot_input_preparation"
    ]
    assert projected["_snapshot_input_preparation"]["status"] == "DEGRADED"
    assert audit_snapshot._source_component(projected) == (
        audit_snapshot._source_component(config)
    )
    limitation = audit_snapshot._source_component(projected)[
        "coverage_limitations"
    ][-1]
    assert "is DEGRADED" in limitation
    assert "fixture materialization is intentionally deferred" in limitation
    assert "is PREPARED" not in limitation


def test_snapshot_visible_config_does_not_accept_tampered_preparation(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    config["_snapshot_input_preparation"] = {
        **config["_snapshot_input_preparation"],
        "status": "PREPARED",
    }
    projected = integration._snapshot_visible_config(config)

    with pytest.raises(
        audit_snapshot.SnapshotInputError,
        match="deterministic input preparation receipt does not replay",
    ):
        audit_snapshot._source_component(projected)
