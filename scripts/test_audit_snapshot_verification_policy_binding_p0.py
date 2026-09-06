"""Verification policy is methodology and must be frozen as audit input."""
from __future__ import annotations

from pathlib import Path

import audit_snapshot as S


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
