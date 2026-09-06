"""Independent RED: self-signed component roots must not mint audit authority."""

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


def test_resigned_non_source_root_cannot_mint_audit_snapshot_authority(
    tmp_path,
) -> None:
    _project, _source, config, snapshot = _live_fixture(tmp_path)
    for component, replacement in (
        ("audit_config", "d" * 64),
        ("methodology", "e" * 64),
        ("toolchain", "f" * 64),
    ):
        forged = deepcopy(snapshot)
        assert forged["components"][component]["digest"] != replacement
        forged["components"][component]["digest"] = replacement

        composed = dict(forged)
        composed.pop("snapshot_digest")
        forged["snapshot_digest"] = hashlib.sha256(
            canonical_json_bytes(composed)
        ).hexdigest()
        assert audit_snapshot._valid_snapshot(forged)

        with pytest.raises(
            ProgramFactsSourceManifestError,
            match="identity differs from canonical live audit",
        ):
            capture_program_facts_audit_snapshot_authority(
                forged,
                config=config,
            )


def test_resigned_source_root_cannot_mint_audit_snapshot_authority(
    tmp_path,
) -> None:
    _project, _source, config, snapshot = _live_fixture(tmp_path)
    forged = deepcopy(snapshot)
    replacement = "a" * 64
    assert forged["components"]["source_scope"]["digest"] != replacement
    forged["components"]["source_scope"]["digest"] = replacement
    composed = dict(forged)
    composed.pop("snapshot_digest")
    forged["snapshot_digest"] = hashlib.sha256(
        canonical_json_bytes(composed)
    ).hexdigest()
    assert audit_snapshot._valid_snapshot(forged)

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="identity differs from canonical live audit",
    ):
        capture_program_facts_audit_snapshot_authority(
            forged,
            config=config,
        )
