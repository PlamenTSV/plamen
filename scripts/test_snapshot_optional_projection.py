"""Optional snapshot membership must not manufacture audit-input drift."""
import json

import pytest
import audit_snapshot as snapshot
from audit_snapshot import MATCH, MISMATCH, build_audit_snapshot, classify_snapshot
from test_audit_snapshot_r0_8cd import (
    _snapshot,
    _isolate_host_runtime_tool_identity,
)


@pytest.mark.parametrize("pipeline,language", [("sc", "evm"), ("sc", "solana"), ("l1", "go")])
def test_absent_optional_projection_is_not_snapshot_drift(tmp_path, pipeline, language):
    _current, project_root, implementation, config = _snapshot(tmp_path)
    if language == "solana":
        (project_root / "src" / "lib.rs").write_text("pub fn entry() {}\n")
    elif language == "go":
        (project_root / "src" / "main.go").write_text("package main\n")
    config.update(pipeline=pipeline, language=language)
    before = build_audit_snapshot(config, implementation)
    after = build_audit_snapshot(config, implementation)
    assert "evm_analysis_projection" not in before["components"]
    assert before["snapshot_digest"] == after["snapshot_digest"]
    verdict = classify_snapshot(before, after, has_prior_progress=True)
    assert verdict.state == MATCH
    assert verdict.changed_components == ()


def test_optional_projection_appearance_and_disappearance_are_drift(tmp_path):
    absent, _project_root, _implementation, _config = _snapshot(tmp_path)
    present = json.loads(json.dumps(absent))
    source = present["components"]["source_scope"]
    source["coverage_limitations"] = [
        item for item in source["coverage_limitations"]
        if not item.startswith("EVM_ANALYSIS_PROJECTION_UNAVAILABLE:")
    ]
    projection = {
        key: "a" * 64 for key in snapshot._EVM_PROJECTION_COMPONENT_KEYS
        if key != "digest"
    }
    projection.update(
        kind="evm_analysis_projection.v1",
        receipt_byte_count=1,
        materialization_lineage_byte_count=1,
        original_source_scope_sha256=source["digest"],
    )
    projection["digest"] = snapshot._sha256(snapshot._canonical_json(projection))
    present["components"]["evm_analysis_projection"] = projection
    present.pop("snapshot_digest")
    present["snapshot_digest"] = snapshot._sha256(snapshot._canonical_json(present))
    assert snapshot._valid_snapshot(present)
    for before, after in ((absent, present), (present, absent)):
        verdict = classify_snapshot(before, after, has_prior_progress=True)
        assert verdict.state == MISMATCH
        assert "evm_analysis_projection" in verdict.changed_components
    assert classify_snapshot(present, present, has_prior_progress=True).state == MATCH
    changed = json.loads(json.dumps(present))
    changed_projection = changed["components"]["evm_analysis_projection"]
    changed_projection["receipt_byte_count"] = 2
    changed_projection.pop("digest")
    changed_projection["digest"] = snapshot._sha256(
        snapshot._canonical_json(changed_projection)
    )
    changed.pop("snapshot_digest")
    changed["snapshot_digest"] = snapshot._sha256(snapshot._canonical_json(changed))
    verdict = classify_snapshot(present, changed, has_prior_progress=True)
    assert verdict.state == MISMATCH
    assert verdict.changed_components == ("evm_analysis_projection",)
