"""Synthetic exact-source continuity through the live late-recall floor."""
from __future__ import annotations

import hashlib
from pathlib import Path

import inventory_source_action_authority as SOURCE
import plamen_driver as D
import plamen_mechanical as M
import plamen_validators as V
from test_inventory_aggregate_source_action_delivery_p0_z import _source


NAME = "analysis_core_state.md"
LOCAL_ID = "B1-1"


def _entry():
    return {
        "title": "exact candidate", "severity": "Medium",
        "location": "src/A.sol:L10", "local_id": LOCAL_ID,
        "source_ids": [LOCAL_ID], "source_actions": [(NAME, LOCAL_ID)],
        "description": "exact candidate mechanism", "root_cause": "exact candidate mechanism",
        "impact": "material effect if reachable", "verdict": "NEEDS_VERIFICATION",
    }


def _assert_exact(text: str, raw: bytes):
    source_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
    assert f"**Source Actions**: {NAME}:{LOCAL_ID}@{source_hash}" in text
    assert V._inventory_structural_source_hash_action_referents(text) == {
        (NAME, LOCAL_ID, source_hash): {"INV-001"},
    }


def test_shared_inventory_renderer_preserves_authenticated_source_triple(tmp_path: Path):
    raw = _source(LOCAL_ID).encode()
    (tmp_path / NAME).write_bytes(raw)
    entries = [_entry()]
    assert SOURCE.bind_exact_source_actions(tmp_path, [NAME], entries) == []
    assert len(entries[0]["source_actions"][0]) == 3
    assert M._render_inventory_from_merged_entries(tmp_path, entries) == (1, 1)
    _assert_exact((tmp_path / "findings_inventory.md").read_text(), raw)


def test_late_floor_stage_preserves_current_source_generation(tmp_path: Path):
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    raw = _source(LOCAL_ID).encode()
    captured = {NAME: raw}
    # This is the real isolated staging seam used by the authority-bound
    # late-floor successor. It must not write canonical output into live root.
    canonical, _derived, count, sources = D._late_floor_evaluate_proposal(
        root=root, project=project, captured=captured,
    )
    assert count == 1 and sources == 1
    assert not list(root.iterdir())
    _assert_exact(canonical["findings_inventory.md"].decode(), raw)
    (root / NAME).write_bytes(raw)
    for name, content in canonical.items():
        (root / name).write_bytes(content)

    def delivery():
        return V._build_registered_finding_delivery_receipt_payload(
            root, V._scan_registered_finding_delivery_sources(root),
            (root / "findings_inventory.md").read_text(),
        )

    actions = {row["action_id"]: row for row in delivery()["actions"]}
    assert actions[LOCAL_ID]["disposition"] == "PROMOTED_FINDING"
    before = {name: (root / name).read_bytes() for name in canonical}
    (root / NAME).write_bytes(raw + b"\nSynthetic source generation changed.\n")
    actions = {row["action_id"]: row for row in delivery()["actions"]}
    assert actions[LOCAL_ID]["disposition"] == "RESIDUAL_DEBT"
    assert {name: (root / name).read_bytes() for name in canonical} == before


def test_shared_renderer_does_not_upgrade_unbound_pair_to_authority(tmp_path: Path):
    assert M._render_inventory_from_merged_entries(tmp_path, [_entry()]) == (1, 1)
    text = (tmp_path / "findings_inventory.md").read_text()
    assert V._inventory_structural_source_hash_action_referents(text) == {}
