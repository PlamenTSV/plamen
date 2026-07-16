"""R0-8c/d: audited-input snapshots make resume evidence reproducible.

These fixtures exercise the pure snapshot/archive substrate.  Driver wiring is
covered separately because it must run before recon pre-pass preservation.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

import pytest

from audit_snapshot import (
    LEGACY_UNBOUND,
    MATCH,
    MISMATCH,
    NEW,
    SnapshotInputError,
    archive_stale_scratchpad,
    build_audit_snapshot,
    classify_snapshot,
    materialize_remote_documents,
)
from plamen_types import Checkpoint


def _implementation_tree(root: Path) -> Path:
    for directory in ("scripts", "prompts", "rules", "agents"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    (root / "scripts" / "plamen_driver.py").write_text("VERSION = 1\n")
    (root / "prompts" / "phase.md").write_text("method v1\n")
    (root / "rules" / "rule.md").write_text("rule v1\n")
    return root


def _project(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "Vault.sol").write_text("contract Vault {}\n")
    (root / "foundry.toml").write_text("[profile.default]\n")
    return root


def _config(project: Path, scratchpad: Path) -> dict:
    return {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "mode": "thorough",
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "codex",
        "scope_notes": "production contracts",
    }


def _snapshot(tmp_path: Path) -> tuple[dict, Path, Path, dict]:
    project = _project(tmp_path / "project")
    implementation = _implementation_tree(tmp_path / "plamen")
    config = _config(project, project / ".scratchpad")
    return build_audit_snapshot(config, implementation), project, implementation, config


def test_snapshot_is_deterministic_and_has_component_digests(tmp_path):
    first, _project_root, implementation, config = _snapshot(tmp_path)
    second = build_audit_snapshot(config, implementation)

    assert first == second
    assert first["schema"] == "plamen.audit-input-snapshot.v1"
    assert set(first["components"]) == {
        "source_scope",
        "audit_config",
        "methodology",
        "toolchain",
    }
    assert all(len(component["digest"]) == 64 for component in first["components"].values())
    assert first["snapshot_digest"]


def test_production_source_change_invalidates_snapshot(tmp_path):
    before, project, implementation, config = _snapshot(tmp_path)
    (project / "src" / "Vault.sol").write_text("contract Vault { uint x; }\n")
    after = build_audit_snapshot(config, implementation)

    verdict = classify_snapshot(before, after, has_prior_progress=True)
    assert verdict.state == MISMATCH
    assert "source_scope" in verdict.changed_components


@pytest.mark.parametrize(
    ("relative", "contents"),
    [
        ("test/poc_regression.sol", "contract GeneratedPoC {}\n"),
        ("tests/ExploitTest.sol", "contract ExploitTest {}\n"),
        ("src/poc_generated.sol", "contract GeneratedPoC {}\n"),
        ("src/Vault.t.sol", "contract VaultTest {}\n"),
    ],
)
def test_generated_poc_and_test_sources_do_not_expand_frozen_scope(
    tmp_path, relative, contents
):
    before, project, implementation, config = _snapshot(tmp_path)
    target = project / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(contents)
    after = build_audit_snapshot(config, implementation)

    verdict = classify_snapshot(before, after, has_prior_progress=True)
    assert verdict.state == MATCH


def test_new_production_file_invalidates_frozen_scope(tmp_path):
    before, project, implementation, config = _snapshot(tmp_path)
    (project / "src" / "Accounting.sol").write_text("contract Accounting {}\n")
    after = build_audit_snapshot(config, implementation)
    assert classify_snapshot(before, after, has_prior_progress=True).state == MISMATCH


def test_manifest_and_scope_file_are_part_of_audited_input(tmp_path):
    before, project, implementation, config = _snapshot(tmp_path)
    scope = project / "scope.txt"
    scope.write_text("src/Vault.sol\n")
    config["scope_file"] = str(scope)
    bound = build_audit_snapshot(config, implementation)

    scope.write_text("src/Accounting.sol\n")
    with pytest.raises(SnapshotInputError, match="scope target is missing"):
        build_audit_snapshot(config, implementation)
    (project / "src" / "Accounting.sol").write_text("contract Accounting {}\n")
    changed_scope = build_audit_snapshot(config, implementation)
    assert "source_scope" in classify_snapshot(
        bound, changed_scope, has_prior_progress=True
    ).changed_components

    (project / "foundry.toml").write_text("[profile.default]\noptimizer = true\n")
    changed_manifest = build_audit_snapshot(config, implementation)
    assert "source_scope" in classify_snapshot(
        changed_scope, changed_manifest, has_prior_progress=True
    ).changed_components

    # The pre-scope baseline is necessarily different because scope_file is a
    # semantic config input as well as a content-bound scope artifact.
    assert classify_snapshot(before, bound, has_prior_progress=True).state == MISMATCH


def test_external_docs_tree_is_content_bound(tmp_path):
    _before, project, implementation, config = _snapshot(tmp_path)
    docs = tmp_path / "external-docs"
    docs.mkdir()
    (docs / "architecture.md").write_text("v1\n")
    config["docs_path"] = str(docs)
    bound = build_audit_snapshot(config, implementation)
    (docs / "architecture.md").write_text("v2\n")
    changed = build_audit_snapshot(config, implementation)
    verdict = classify_snapshot(bound, changed, has_prior_progress=True)
    assert verdict.state == MISMATCH
    assert "source_scope" in verdict.changed_components


def test_methodology_tool_and_semantic_config_drift_are_distinct(tmp_path):
    before, _project_root, implementation, config = _snapshot(tmp_path)

    (implementation / "prompts" / "phase.md").write_text("method v2\n")
    method_changed = build_audit_snapshot(config, implementation)
    verdict = classify_snapshot(before, method_changed, has_prior_progress=True)
    assert verdict.state == MISMATCH
    assert verdict.changed_components == ("methodology",)

    (implementation / "prompts" / "phase.md").write_text("method v1\n")
    (implementation / "scripts" / "plamen_driver.py").write_text("VERSION = 2\n")
    tool_changed = build_audit_snapshot(config, implementation)
    verdict = classify_snapshot(before, tool_changed, has_prior_progress=True)
    assert verdict.changed_components == ("toolchain",)

    (implementation / "scripts" / "plamen_driver.py").write_text("VERSION = 1\n")
    changed_config = dict(config, mode="core")
    config_changed = build_audit_snapshot(changed_config, implementation)
    verdict = classify_snapshot(before, config_changed, has_prior_progress=True)
    assert verdict.changed_components == ("audit_config",)


def test_runtime_private_config_keys_do_not_create_resume_drift(tmp_path):
    before, _project_root, implementation, config = _snapshot(tmp_path)
    config["_active_phase_names"] = ["recon", "breadth"]
    config["_runtime_nonce"] = "changes every process"
    after = build_audit_snapshot(config, implementation)
    assert classify_snapshot(before, after, has_prior_progress=True).state == MATCH


def test_plamen_behavior_environment_is_toolchain_bound(tmp_path, monkeypatch):
    monkeypatch.delenv("PLAMEN_GRAPH_LOCATION_RESOLUTION_MIN_RATIO", raising=False)
    before, _project_root, implementation, config = _snapshot(tmp_path)
    monkeypatch.setenv("PLAMEN_GRAPH_LOCATION_RESOLUTION_MIN_RATIO", "0.95")
    after = build_audit_snapshot(config, implementation)
    verdict = classify_snapshot(before, after, has_prior_progress=True)
    assert verdict.state == MISMATCH
    assert verdict.changed_components == ("toolchain",)


def test_snapshot_state_machine_is_honest_about_legacy_progress(tmp_path):
    current, _project_root, _implementation, _config = _snapshot(tmp_path)
    assert classify_snapshot(None, current, has_prior_progress=False).state == NEW
    assert classify_snapshot(None, current, has_prior_progress=True).state == LEGACY_UNBOUND
    assert classify_snapshot(current, current, has_prior_progress=True).state == MATCH


def test_invalid_or_partial_stored_snapshot_is_legacy_unbound(tmp_path):
    current, _project_root, _implementation, _config = _snapshot(tmp_path)
    partial = {"schema": current["schema"], "components": {}}
    verdict = classify_snapshot(partial, current, has_prior_progress=True)
    assert verdict.state == LEGACY_UNBOUND
    assert verdict.changed_components == ("snapshot_binding",)


def test_checkpoint_round_trips_snapshot_and_rejects_non_object(tmp_path):
    current, _project_root, _implementation, _config = _snapshot(tmp_path)
    scratchpad = tmp_path / "checkpoint"
    scratchpad.mkdir()
    Checkpoint(completed=["recon"], audit_snapshot=current).save(scratchpad)
    loaded = Checkpoint.load(scratchpad)
    assert loaded.audit_snapshot == current

    raw = json.loads((scratchpad / "_v2_checkpoint.json").read_text())
    raw["audit_snapshot"] = "forged"
    (scratchpad / "_v2_checkpoint.json").write_text(json.dumps(raw))
    with pytest.raises(RuntimeError, match="audit_snapshot must be null or an object"):
        Checkpoint.load(scratchpad)


def test_archive_moves_stale_products_and_preserves_live_control_files(tmp_path):
    scratchpad = tmp_path / "project" / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "inventory.md").write_text("stale")
    (scratchpad / "nested").mkdir()
    (scratchpad / "nested" / "finding.md").write_text("stale")
    (scratchpad / "_v2_checkpoint.json").write_text(json.dumps({"completed": ["recon"]}))
    (scratchpad / "_plamen.log").write_text("open log is preserved")
    (scratchpad / ".plamen_run.lock").write_text("live lock is preserved")

    receipt = archive_stale_scratchpad(
        scratchpad,
        project_root=scratchpad.parent,
        reason="source_scope",
        preserve_names={"_plamen.log", ".plamen_run.lock"},
    )

    assert receipt.moved_names == ("_v2_checkpoint.json", "inventory.md", "nested")
    assert (scratchpad / "_plamen.log").exists()
    assert (scratchpad / ".plamen_run.lock").exists()
    assert not (scratchpad / "inventory.md").exists()
    assert (receipt.archive_dir / "inventory.md").read_text() == "stale"
    assert (receipt.archive_dir / "snapshot_mismatch_receipt.json").exists()


def test_archive_is_collision_safe_and_does_not_nest_inside_scratchpad(tmp_path):
    scratchpad = tmp_path / "project" / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "a.md").write_text("one")
    first = archive_stale_scratchpad(
        scratchpad, project_root=scratchpad.parent, reason="methodology"
    )
    (scratchpad / "a.md").write_text("two")
    second = archive_stale_scratchpad(
        scratchpad, project_root=scratchpad.parent, reason="toolchain"
    )

    assert first.archive_dir != second.archive_dir
    assert first.archive_dir.parent == scratchpad.parent / ".plamen-stale-snapshots"
    assert second.archive_dir.parent == scratchpad.parent / ".plamen-stale-snapshots"
    assert not first.archive_dir.is_relative_to(scratchpad)
    assert (first.archive_dir / "a.md").read_text() == "one"
    assert (second.archive_dir / "a.md").read_text() == "two"


@pytest.mark.parametrize(
    ("pipeline", "language", "relative"),
    [
        ("sc", "evm", "contracts/Pool.vy"),
        ("sc", "evm", "contracts/Upper.SOL"),
        ("l1", "rust", "runtime/module.move"),
        ("l1", "rust", "api/state.proto"),
        ("l1", "go", "api/state.proto"),
    ],
)
def test_mixed_ecosystem_source_types_are_content_bound(
    tmp_path, pipeline, language, relative
):
    project = _project(tmp_path / "project")
    implementation = _implementation_tree(tmp_path / "plamen")
    target = project / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("version one\n")
    config = _config(project, project / ".scratchpad")
    config.update(pipeline=pipeline, language=language)
    before = build_audit_snapshot(config, implementation)
    target.write_text("version two\n")
    after = build_audit_snapshot(config, implementation)
    assert classify_snapshot(before, after, has_prior_progress=True).state == MISMATCH


def test_dirty_contextual_assumption_is_bound(tmp_path):
    before, project, implementation, config = _snapshot(tmp_path)
    readme = project / "README.md"
    readme.write_text("rate is stable\n")
    with_readme = build_audit_snapshot(config, implementation)
    readme.write_text("rate changes per block\n")
    changed = build_audit_snapshot(config, implementation)
    assert classify_snapshot(with_readme, changed, has_prior_progress=True).state == MISMATCH
    assert classify_snapshot(before, with_readme, has_prior_progress=True).state == MISMATCH


@pytest.mark.parametrize(
    "manifest",
    [
        "Move.lock",
        "Anchor.toml",
        "rust-toolchain.toml",
        "go.work",
        ".gitmodules",
        "hardhat.config.cjs",
        "bun.lockb",
    ],
)
def test_ecosystem_manifest_and_lock_mutations_are_bound(tmp_path, manifest):
    _base, project, implementation, config = _snapshot(tmp_path)
    target = project / manifest
    target.write_text("v1\n")
    before = build_audit_snapshot(config, implementation)
    target.write_text("v2\n")
    after = build_audit_snapshot(config, implementation)
    assert classify_snapshot(before, after, has_prior_progress=True).state == MISMATCH


def test_explicit_scope_target_bypasses_default_dependency_exclusion(tmp_path):
    _base, project, implementation, config = _snapshot(tmp_path)
    dependency = project / "node_modules" / "vendor" / "Explicit.sol"
    dependency.parent.mkdir(parents=True)
    dependency.write_text("contract Explicit {}\n")
    scope = project / "scope.txt"
    scope.write_text("node_modules/vendor/Explicit.sol\n")
    config["scope_file"] = str(scope)
    before = build_audit_snapshot(config, implementation)
    dependency.write_text("contract Explicit { uint changed; }\n")
    after = build_audit_snapshot(config, implementation)
    assert classify_snapshot(before, after, has_prior_progress=True).state == MISMATCH


def test_explicit_vyper_scope_fails_closed_without_end_to_end_lane(tmp_path):
    _base, project, implementation, config = _snapshot(tmp_path)
    vyper = project / "contracts" / "Vault.vy"
    vyper.parent.mkdir(parents=True)
    vyper.write_text("# vyper source\n")
    scope = project / "scope.txt"
    scope.write_text("contracts/Vault.vy\n")
    config["scope_file"] = str(scope)
    with pytest.raises(SnapshotInputError, match="no end-to-end Vyper"):
        build_audit_snapshot(config, implementation)

    config["allow_incomplete_vyper_coverage"] = True
    degraded = build_audit_snapshot(config, implementation)
    limitations = degraded["components"]["source_scope"]["coverage_limitations"]
    assert limitations and limitations[0].startswith("VYPER_END_TO_END")


def test_remote_inputs_and_missing_roots_fail_closed(tmp_path):
    project = _project(tmp_path / "project")
    implementation = _implementation_tree(tmp_path / "plamen")
    config = _config(project, project / ".scratchpad")
    config["docs_path"] = "https://example.invalid/architecture.md"
    with pytest.raises(SnapshotInputError, match="immutable local input bundle"):
        build_audit_snapshot(config, implementation)

    config.pop("docs_path")
    config["project_root"] = str(tmp_path / "missing")
    with pytest.raises(SnapshotInputError, match="missing or not a directory"):
        build_audit_snapshot(config, implementation)


def test_remote_document_is_fetched_to_immutable_content_bound_bundle(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        payload = b"assumption version one\n"

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("ETag", '"fixture"')
            self.end_headers()
            self.wfile.write(type(self).payload)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        project = _project(tmp_path / "project")
        implementation = _implementation_tree(tmp_path / "plamen")
        config = _config(project, project / ".scratchpad")
        source_url = f"http://127.0.0.1:{server.server_port}/architecture.txt"
        config["docs_path"] = source_url
        first_bundle = materialize_remote_documents(config)
        assert first_bundle is not None and first_bundle.is_dir()
        assert config["docs_source_urls"] == [source_url]
        first = build_audit_snapshot(config, implementation)

        second_config = _config(project, project / ".scratchpad")
        second_config["docs_path"] = source_url
        Handler.payload = b"assumption version two\n"
        second_bundle = materialize_remote_documents(second_config)
        second = build_audit_snapshot(second_config, implementation)
        assert first_bundle != second_bundle
        assert classify_snapshot(first, second, has_prior_progress=True).state == MISMATCH
    finally:
        server.shutdown()
        thread.join(timeout=5)

def test_strict_snapshot_schema_rejects_forged_nested_shapes(tmp_path):
    current, _project_root, _implementation, _config_value = _snapshot(tmp_path)
    for mutate in (
        lambda value: value["components"]["source_scope"].update(digest="z" * 64),
        lambda value: value["components"]["toolchain"].update(unexpected=True),
        lambda value: value["components"]["methodology"].pop("byte_count"),
        lambda value: value.update(unexpected=True),
    ):
        forged = json.loads(json.dumps(current))
        mutate(forged)
        unsigned = dict(forged)
        unsigned.pop("snapshot_digest", None)
        import hashlib

        forged["snapshot_digest"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with pytest.raises(ValueError, match="current audit snapshot is invalid"):
            classify_snapshot(current, forged, has_prior_progress=True)


def test_archive_rejects_escape_and_symlink_scratchpad(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(RuntimeError, match="contained by project_root"):
        archive_stale_scratchpad(
            outside, project_root=project, reason="scope"
        )

    link = project / ".scratchpad"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    with pytest.raises(RuntimeError, match="symlink/junction"):
        archive_stale_scratchpad(
            link, project_root=project, reason="scope"
        )


def test_archive_receipt_failure_rolls_back_without_split_evidence(
    tmp_path, monkeypatch
):
    import audit_snapshot as snapshot_module

    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    (scratchpad / "a.md").write_text("one")
    (scratchpad / "b.md").write_text("two")
    real_atomic_json = snapshot_module._atomic_json

    def fail_receipt(path, value):
        if path.name == "snapshot_mismatch_receipt.json":
            raise OSError("injected receipt failure")
        return real_atomic_json(path, value)

    monkeypatch.setattr(snapshot_module, "_atomic_json", fail_receipt)
    with pytest.raises(RuntimeError, match="atomically quarantine"):
        archive_stale_scratchpad(
            scratchpad, project_root=project, reason="toolchain"
        )
    assert (scratchpad / "a.md").read_text() == "one"
    assert (scratchpad / "b.md").read_text() == "two"
    assert not list((project / ".plamen-stale-snapshots").iterdir())
