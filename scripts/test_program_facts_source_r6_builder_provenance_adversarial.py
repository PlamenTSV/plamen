"""Independent RED: a replaced public snapshot builder is not authority."""

from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

import audit_snapshot
from program_facts_source_manifest import (
    ProgramFactsSourceManifestError,
    capture_program_facts_audit_snapshot_authority,
)
from program_facts_types import canonical_json_bytes
from test_program_facts_source_manifest import _fixture


def _live_fixture(tmp_path):
    project, source, config, _synthetic_snapshot = _fixture(tmp_path)
    installed_root = Path(__file__).resolve().parents[1]
    snapshot = audit_snapshot.build_audit_snapshot(
        config,
        installed_root,
    )
    capture_program_facts_audit_snapshot_authority(
        snapshot,
        config=config,
    )
    return project, source, config, snapshot


def test_replaced_public_snapshot_builder_cannot_mint_audit_authority(
    tmp_path,
    monkeypatch,
) -> None:
    _project, _source, config, genuine = _live_fixture(tmp_path)
    forged = deepcopy(genuine)
    forged["components"]["audit_config"]["digest"] = "d" * 64
    forged["components"]["methodology"]["digest"] = "e" * 64
    forged["components"]["toolchain"]["digest"] = "f" * 64
    unsigned = dict(forged)
    unsigned.pop("snapshot_digest")
    forged["snapshot_digest"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    assert audit_snapshot._valid_snapshot(forged)

    monkeypatch.setattr(
        audit_snapshot,
        "build_audit_snapshot",
        lambda _config, _implementation_root: deepcopy(forged),
    )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="builder was replaced or mutated",
    ):
        capture_program_facts_audit_snapshot_authority(
            forged,
            config=config,
        )
