"""Source R4/R5 trust-root and one-capture regression fixtures."""

from __future__ import annotations

from copy import deepcopy
import copy
from pathlib import Path
import pickle

import pytest

import audit_snapshot
import program_facts_source_manifest as source_api
from program_facts_source_manifest import (
    build_program_facts_source_manifest,
)
from test_program_facts_source_manifest import _fixture


@pytest.fixture(autouse=True)
def _neutral_runtime_tools(monkeypatch):
    # Keep the real runtime-observation function inside the pinned semantic
    # builder closure.  Neutralize only PATH resolution so this source-focused
    # fixture neither executes optional tools nor depends on platform-specific
    # executable hardlink layouts.
    monkeypatch.setattr(
        audit_snapshot.shutil,
        "which",
        lambda _command: None,
    )


class _TopLevelSplitSnapshot(dict):
    def get(self, key, default=None):
        if key == "snapshot_digest":
            return "f" * 64
        return super().get(key, default)


class _NestedNoReread(dict):
    def get(self, key, default=None):
        raise AssertionError("validated nested snapshot was reread")


class _ConfigNoReread(dict):
    def __init__(self, value):
        super().__init__(value)
        self.items_calls = 0

    def items(self):
        self.items_calls += 1
        return super().items()

    def get(self, key, default=None):
        raise AssertionError("validated config was reread")


def test_builder_uses_one_top_level_snapshot_capture(tmp_path) -> None:
    _project, _source, config, snapshot = _fixture(tmp_path)
    authority = build_program_facts_source_manifest(
        config,
        _TopLevelSplitSnapshot(snapshot),
    )
    assert authority.record["snapshot_ref"]["snapshot_digest"] == (
        f"sha256:{snapshot['snapshot_digest']}"
    )


def test_builder_uses_one_recursive_snapshot_capture(tmp_path) -> None:
    _project, _source, config, snapshot = _fixture(tmp_path)
    split = deepcopy(snapshot)
    split["components"] = _NestedNoReread(split["components"])
    authority = build_program_facts_source_manifest(config, split)
    assert authority.record["snapshot_ref"]["source_scope_digest"] == (
        "sha256:"
        + snapshot["components"]["source_scope"]["digest"]
    )


def test_builder_uses_one_recursive_config_capture(tmp_path) -> None:
    _project, _source, config, snapshot = _fixture(tmp_path)
    split = _ConfigNoReread(config)
    authority = build_program_facts_source_manifest(split, snapshot)
    assert authority.parent_authority_established
    assert split.items_calls == 1


def test_audit_snapshot_authority_is_opaque_and_semantically_replayed(
    tmp_path,
) -> None:
    project, _source, config, _snapshot = _fixture(tmp_path)
    snapshot = audit_snapshot.build_audit_snapshot(
        config,
        Path(__file__).resolve().parents[1],
    )
    authority = source_api.capture_program_facts_audit_snapshot_authority(
        snapshot,
        config=config,
    )
    assert authority.snapshot_digest == snapshot["snapshot_digest"]
    assert authority.audit_identity.to_dict() == {
        "snapshot_digest": snapshot["snapshot_digest"],
        "source_scope_digest": snapshot["components"]["source_scope"][
            "digest"
        ],
        "audit_config_digest": snapshot["components"]["audit_config"][
            "digest"
        ],
        "methodology_digest": snapshot["components"]["methodology"]["digest"],
        "toolchain_digest": snapshot["components"]["toolchain"]["digest"],
    }
    replayed = source_api.replay_program_facts_audit_snapshot_authority(
        authority,
        project_root=project,
        config=config,
    )
    assert replayed.snapshot_digest == snapshot["snapshot_digest"]
    assert (
        replayed.source_scope_digest
        == snapshot["components"]["source_scope"]["digest"]
    )
    assert replayed.audit_identity == authority.audit_identity
    with pytest.raises(TypeError):
        copy.copy(authority)
    with pytest.raises(TypeError):
        pickle.dumps(authority)

    object.__setattr__(authority, "toolchain_digest", "f" * 64)
    with pytest.raises(
        source_api.ProgramFactsSourceManifestError,
        match="exact issued audit-snapshot authority",
    ):
        source_api.replay_program_facts_audit_snapshot_authority(
            authority,
            project_root=project,
            config=config,
        )


def test_audit_snapshot_authority_rejects_stateful_parent_substitution(
    tmp_path,
) -> None:
    _project, _source, config, _snapshot = _fixture(tmp_path)
    snapshot = audit_snapshot.build_audit_snapshot(
        config,
        Path(__file__).resolve().parents[1],
    )
    authority = source_api.capture_program_facts_audit_snapshot_authority(
        _TopLevelSplitSnapshot(snapshot),
        config=config,
    )
    assert authority.snapshot_digest == snapshot["snapshot_digest"]
    assert authority.snapshot_digest != "f" * 64
