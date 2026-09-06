"""Independent RED: pinned builder code must not trust replaced dependencies."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

import audit_snapshot
from program_facts_source_manifest import (
    ProgramFactsSourceManifestError,
    capture_program_facts_audit_snapshot_authority,
)
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


def test_pinned_builder_cannot_mint_through_replaced_component_helpers(
    tmp_path,
    monkeypatch,
) -> None:
    _project, _source, config, genuine = _live_fixture(tmp_path)
    public_builder = audit_snapshot.build_audit_snapshot
    installed_root = Path(__file__).resolve().parents[1]
    components = deepcopy(genuine["components"])
    components["audit_config"]["digest"] = "d" * 64
    components["methodology"]["digest"] = "e" * 64
    components["toolchain"]["digest"] = "f" * 64

    monkeypatch.setattr(
        audit_snapshot,
        "_config_component",
        lambda _config: deepcopy(components["audit_config"]),
    )
    monkeypatch.setattr(
        audit_snapshot,
        "_methodology_component",
        lambda _root: deepcopy(components["methodology"]),
    )
    monkeypatch.setattr(
        audit_snapshot,
        "_toolchain_component",
        lambda _root, *, project_root=None: deepcopy(
            components["toolchain"]
        ),
    )
    assert audit_snapshot.build_audit_snapshot is public_builder
    forged = public_builder(config, installed_root)
    assert audit_snapshot._valid_snapshot(forged)

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match="builder dependency was replaced or mutated",
    ):
        capture_program_facts_audit_snapshot_authority(
            forged,
            config=config,
        )
