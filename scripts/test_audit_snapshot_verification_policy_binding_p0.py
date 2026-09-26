"""Verification policy is methodology and must be frozen as audit input."""
from __future__ import annotations

import hashlib
from pathlib import Path

import audit_snapshot as S
import pytest


def _implementation(root: Path) -> Path:
    (root / "agents").mkdir(parents=True)
    (root / "agents" / "verifier.md").write_text(
        "apply the bound verification policy\n",
        encoding="utf-8",
    )
    (root / "verification_policy").mkdir()
    (root / "verification_policy" / "verification_method_registry.v1.json").write_text(
        '{"schema_version":"fixture.registry.v1","operators":[]}\n',
        encoding="utf-8",
    )
    matrix = root / "docs" / "l1-mode" / "severity-matrix.md"
    matrix.parent.mkdir(parents=True)
    matrix.write_text("# L1 severity matrix\n", encoding="utf-8")
    return root


def test_verification_policy_bytes_are_part_of_methodology_snapshot(
    tmp_path: Path,
) -> None:
    implementation = _implementation(tmp_path / "plamen")
    builder = getattr(S, "build_methodology_snapshot_component", None)
    assert callable(builder), (
        "audit_snapshot must expose the canonical methodology-component "
        "builder so downstream deterministic providers cannot duplicate its "
        "directory or digest rules"
    )

    before = builder(implementation)
    policy = (
        implementation
        / "verification_policy"
        / "verification_method_registry.v1.json"
    )
    policy.write_text(
        '{"schema_version":"fixture.registry.v1","operators":[{"id":"changed"}]}\n',
        encoding="utf-8",
    )
    after = builder(implementation)

    assert before["file_count"] == 2
    assert after["file_count"] == 2
    assert before["path_set_digest"] == after["path_set_digest"]
    assert before["digest"] != after["digest"]


def test_l1_severity_matrix_is_an_exact_pipeline_methodology_input(
    tmp_path: Path,
) -> None:
    implementation = _implementation(tmp_path / "plamen")
    matrix = implementation / "docs" / "l1-mode" / "severity-matrix.md"
    matrix.write_text("# L1 severity matrix\noriginal\n", encoding="utf-8")

    sc_before = S.build_methodology_snapshot_component(
        implementation, pipeline="sc"
    )
    l1_before = S.build_methodology_snapshot_component(
        implementation, pipeline="l1"
    )
    matrix.write_text("# L1 severity matrix\nchanged\n", encoding="utf-8")
    sc_after = S.build_methodology_snapshot_component(
        implementation, pipeline="sc"
    )
    l1_after = S.build_methodology_snapshot_component(
        implementation, pipeline="l1"
    )

    assert sc_after == sc_before
    assert l1_after["file_count"] == l1_before["file_count"]
    assert l1_after["path_set_digest"] == l1_before["path_set_digest"]
    assert l1_after["digest"] != l1_before["digest"]

    matrix.unlink()
    with pytest.raises(
        S.SnapshotInputError,
        match="selected methodology input is missing",
    ):
        S.build_methodology_snapshot_component(implementation, pipeline="l1")


def test_full_l1_snapshot_binds_selected_severity_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    implementation = _implementation(tmp_path / "plamen")
    project = tmp_path / "project"
    project.mkdir()
    (project / "go.mod").write_text(
        "module example.invalid/node\n\ngo 1.22\n",
        encoding="utf-8",
    )
    (project / "main.go").write_text("package main\n", encoding="utf-8")
    config = {
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad"),
        "mode": "core",
        "pipeline": "l1",
        "language": "go",
        "cli_backend": "codex",
    }
    monkeypatch.setattr(S, "_runtime_tool_entries", lambda **_kwargs: [])

    before = S.build_audit_snapshot(config, implementation)
    matrix = implementation / "docs" / "l1-mode" / "severity-matrix.md"
    matrix.write_text("# L1 severity matrix\nchanged\n", encoding="utf-8")
    after = S.build_audit_snapshot(config, implementation)

    assert before["components"]["methodology"] != after["components"]["methodology"]
    assert S.classify_snapshot(
        before, after, has_prior_progress=True
    ).state == S.MISMATCH


def test_canonical_semantic_config_bytes_match_component_and_ignore_runtime_fields() -> None:
    config = {
        "pipeline": "sc",
        "mode": "core",
        "project_root": "/project",
        "_run_id": "runtime-only",
    }
    raw = S.canonical_semantic_config_bytes(config)
    component = S.build_audit_config_snapshot_component(config)

    assert component == {
        "digest": hashlib.sha256(raw).hexdigest(),
        "field_count": 3,
    }
    assert S.canonical_semantic_config_bytes(
        {**config, "_run_id": "changed", "_transient": {"value": 1}}
    ) == raw


def test_audit_config_component_enumerates_semantic_config_once() -> None:
    class SingleUseConfig(dict[str, object]):
        enumerations = 0

        def items(self):
            self.enumerations += 1
            if self.enumerations != 1:
                raise AssertionError("config was enumerated more than once")
            return super().items()

    config = SingleUseConfig(
        pipeline="l1",
        mode="core",
        project_root="/project",
        _run_id="runtime-only",
    )
    component = S.build_audit_config_snapshot_component(config)

    expected_raw = (
        b'{"mode":"core","pipeline":"l1","project_root":"/project"}'
    )
    assert config.enumerations == 1
    assert component == {
        "digest": hashlib.sha256(expected_raw).hexdigest(),
        "field_count": 3,
    }
