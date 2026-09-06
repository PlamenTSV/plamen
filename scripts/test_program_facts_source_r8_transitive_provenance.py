"""Source R8 transitive audit-snapshot builder provenance regressions.

Every case changes exactly the dependency named by the test.  In particular,
these fixtures must not replace ``_runtime_tool_entries`` (or another protected
helper) merely to make the snapshot deterministic: doing so would let that
unrelated replacement satisfy the expected rejection and mask a regression in
the dependency under test.
"""

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


@pytest.mark.parametrize(
    ("helper_name", "component_name", "forged_digest"),
    [
        ("_config_component", "audit_config", "d" * 64),
        ("_methodology_component", "methodology", "e" * 64),
        ("_toolchain_component", "toolchain", "f" * 64),
    ],
)
def test_each_direct_component_replacement_is_not_canonical_authority(
    tmp_path,
    monkeypatch,
    helper_name,
    component_name,
    forged_digest,
) -> None:
    _project, _source, config, _snapshot = _fixture(tmp_path)
    installed_root = Path(__file__).resolve().parents[1]
    genuine = audit_snapshot.build_audit_snapshot(config, installed_root)
    forged_component = deepcopy(genuine["components"][component_name])
    forged_component["digest"] = forged_digest
    if helper_name == "_config_component":
        replacement = lambda _config: deepcopy(forged_component)
    elif helper_name == "_methodology_component":
        replacement = lambda _root: deepcopy(forged_component)
    else:
        replacement = (
            lambda _root, *, project_root=None: deepcopy(forged_component)
        )
    monkeypatch.setattr(audit_snapshot, helper_name, replacement)

    forged = audit_snapshot.build_audit_snapshot(config, installed_root)
    assert audit_snapshot._valid_snapshot(forged)
    assert (
        forged["components"][component_name]["digest"]
        == forged_digest
    )
    assert forged["snapshot_digest"] != genuine["snapshot_digest"]

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match=rf"builder dependency.*{helper_name}",
    ):
        capture_program_facts_audit_snapshot_authority(
            forged,
            config=config,
        )


@pytest.mark.parametrize(
    ("name", "replacement"),
    [
        ("_semantic_config", lambda _config: {"language": "forged"}),
        ("_METHODOLOGY_DIRS", ()),
    ],
)
def test_nested_helper_or_semantic_constant_replacement_is_rejected(
    tmp_path,
    monkeypatch,
    name,
    replacement,
) -> None:
    _project, _source, config, _snapshot = _fixture(tmp_path)
    installed_root = Path(__file__).resolve().parents[1]
    genuine = audit_snapshot.build_audit_snapshot(config, installed_root)
    monkeypatch.setattr(audit_snapshot, name, replacement)
    forged = audit_snapshot.build_audit_snapshot(config, installed_root)
    assert audit_snapshot._valid_snapshot(forged)
    assert forged["snapshot_digest"] != genuine["snapshot_digest"]

    expected_reason = (
        "builder dependency.*_semantic_config"
        if name == "_semantic_config"
        else r"builder constant changed: _METHODOLOGY_DIRS"
    )
    with pytest.raises(
        ProgramFactsSourceManifestError,
        match=expected_reason,
    ):
        capture_program_facts_audit_snapshot_authority(
            forged,
            config=config,
        )


def test_in_place_semantic_container_mutation_is_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    _project, _source, config, _snapshot = _fixture(tmp_path)
    installed_root = Path(__file__).resolve().parents[1]
    genuine = audit_snapshot.build_audit_snapshot(config, installed_root)

    monkeypatch.setitem(
        audit_snapshot._SOURCE_SUFFIXES,
        "forged-r8",
        (".forged-r8",),
    )
    forged = audit_snapshot.build_audit_snapshot(config, installed_root)
    assert audit_snapshot._valid_snapshot(forged)

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match=r"builder constant changed: _SOURCE_SUFFIXES",
    ):
        capture_program_facts_audit_snapshot_authority(
            forged,
            config=config,
        )


def test_local_helper_code_mutation_is_rejected_without_rebinding(
    tmp_path,
    monkeypatch,
) -> None:
    _project, _source, config, _snapshot = _fixture(tmp_path)
    installed_root = Path(__file__).resolve().parents[1]
    genuine = audit_snapshot.build_audit_snapshot(config, installed_root)

    helper = audit_snapshot._config_component
    original_code = helper.__code__
    replacement_code = (lambda _config: {}).__code__
    monkeypatch.setattr(helper, "__code__", replacement_code)
    assert audit_snapshot._config_component is helper
    assert helper.__code__ is replacement_code
    assert helper.__code__ is not original_code

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match=r"builder dependency.*_config_component",
    ):
        capture_program_facts_audit_snapshot_authority(
            genuine,
            config=config,
        )


def test_local_helper_keyword_defaults_mutation_is_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    _project, _source, config, _snapshot = _fixture(tmp_path)
    installed_root = Path(__file__).resolve().parents[1]
    genuine = audit_snapshot.build_audit_snapshot(config, installed_root)
    helper = audit_snapshot._toolchain_component
    monkeypatch.setattr(
        helper,
        "__kwdefaults__",
        {"project_root": tmp_path / "forged-default"},
    )

    # The builder supplies this keyword explicitly.  Provenance must still
    # fail closed rather than treating mutable function defaults as outside
    # the trust root.  Use the already captured intact snapshot so unrelated
    # runtime-tool observations cannot become a second reason for rejection.
    assert helper.__kwdefaults__ == {
        "project_root": tmp_path / "forged-default"
    }

    with pytest.raises(
        ProgramFactsSourceManifestError,
        match=r"builder dependency.*_toolchain_component",
    ):
        capture_program_facts_audit_snapshot_authority(
            genuine,
            config=config,
        )
