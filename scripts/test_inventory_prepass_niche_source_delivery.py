"""Exact recon-prepass niche delivery into the inventory denominator."""
from __future__ import annotations

import hashlib
from pathlib import Path

import plamen_mechanical as mechanical
from inventory_aggregate_authority import build_inventory_aggregate_derivation
from inventory_reconciliation import reconcile_inventory
from plamen_validators import _validate_inventory_chunk_structure


def _finding(finding_id: str, title: str, location: str) -> str:
    return (
        f"### Finding [{finding_id}]: {title}\n"
        "**Severity**: Low\n"
        f"**Location**: {location}\n"
        f"**Root Cause**: exact mechanism for {title}\n"
        f"**Description**: exact description for {title}\n"
        f"**Impact**: exact impact for {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _chunk_finding(
    finding_id: str,
    title: str,
    location: str,
    source_reference: str,
) -> str:
    return _finding(finding_id, title, location).replace(
        "**Verdict**: NEEDS_VERIFICATION\n",
        f"**Source IDs**: {source_reference}\n"
        "**Verdict**: NEEDS_VERIFICATION\n",
    )


def test_declared_prepass_niche_findings_reach_inventory_denominator_once(
    tmp_path: Path,
) -> None:
    sources = {
        "niche_permissionless_setters_findings.md": (
            "PSET-1",
            "Permissionless callback setter",
            "contracts/Gateway.sol:L10",
        ),
        "niche_interface_parity_findings.md": (
            "IFACE-1",
            "Interface parity mismatch",
            "contracts/IRouter.sol:L20",
        ),
        # This name deliberately matches both analysis_*.md and the narrower
        # analysis_rescan_*.md pattern. Planning must still assign it once.
        "analysis_rescan_1.md": (
            "RS1-1",
            "Rescan candidate",
            "contracts/Router.sol:L30",
        ),
    }
    for name, (finding_id, title, location) in sources.items():
        (tmp_path / name).write_text(
            _finding(finding_id, title, location), encoding="utf-8"
        )

    # A filename that merely resembles a niche output has no source authority.
    (tmp_path / "niche_unregistered_findings.md").write_text(
        _finding("N-1", "Unregistered candidate", "contracts/Other.sol:L40"),
        encoding="utf-8",
    )

    plan = mechanical.ensure_inventory_shard_plan(tmp_path)
    assigned = [
        str(row["path"])
        for shard_rows in plan.values()
        for row in shard_rows
    ]
    assert sorted(assigned) == sorted(sources)
    assert all(assigned.count(name) == 1 for name in sources)
    assert "niche_unregistered_findings.md" not in assigned

    chunk = "# Inventory Chunk\n\n## Per-Finding Detail\n\n"
    for index, (name, (source_id, title, location)) in enumerate(
        sources.items(), start=1
    ):
        chunk += _chunk_finding(
            f"CC-{index:02d}", title, location, f"{name}:{source_id}"
        )
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        chunk, encoding="utf-8"
    )

    assert _validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_a"
    ) == []

    receipt = reconcile_inventory(
        tmp_path, phase_name="inventory_chunk_a", persist=False
    )
    assert receipt["artifact_issues"] == []
    assert receipt["denominator_count"] == len(sources)
    assert receipt["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 0,
        "RETAINED": len(sources),
        "TOTAL": len(sources),
    }
    assert {
        (row["source_artifact"], row["source_finding_id"])
        for row in receipt["candidates"]
    } == {
        (name, values[0]) for name, values in sources.items()
    }

    source_names = tuple(sorted(
        name
        for name in (
            *sources,
            "inventory_chunk_a.manifest.md",
            "findings_inventory_chunk_a.md",
        )
        if (tmp_path / name).is_file()
    ))
    payload = build_inventory_aggregate_derivation(
        tmp_path,
        derivation_kind="single_shard",
        run_id="prepass-niche-composition",
        source_names=source_names,
        source_bindings=[
            {
                "artifact": name,
                "sha256": hashlib.sha256(
                    (tmp_path / name).read_bytes()
                ).hexdigest(),
            }
            for name in source_names
        ],
    )
    inventory = payload["output_payloads"]["findings_inventory.md"]
    assert inventory.count("**Source Actions**:") == len(sources)
    for name, (finding_id, _title, _location) in sources.items():
        digest = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        assert f"{name}:{finding_id}@sha256:{digest}" in inventory


def test_declared_empty_and_nonfinding_prepass_inputs_do_not_invent_candidates(
    tmp_path: Path,
) -> None:
    (tmp_path / "niche_permissionless_setters_findings.md").write_text(
        "# Permissionless setters\n\nNo candidate was produced.\n",
        encoding="utf-8",
    )
    (tmp_path / "niche_interface_parity_findings.md").write_text(
        "", encoding="utf-8"
    )
    (tmp_path / "niche_unregistered_findings.md").write_text(
        _finding("N-1", "Unregistered candidate", "contracts/Other.sol:L40"),
        encoding="utf-8",
    )

    plan = mechanical.ensure_inventory_shard_plan(tmp_path)
    assigned = [
        str(row["path"])
        for shard_rows in plan.values()
        for row in shard_rows
    ]
    assert sorted(assigned) == [
        "niche_interface_parity_findings.md",
        "niche_permissionless_setters_findings.md",
    ]
    assert "niche_unregistered_findings.md" not in assigned

    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Inventory Chunk\n\nNo findings.\n", encoding="utf-8"
    )
    receipt = reconcile_inventory(
        tmp_path, phase_name="inventory_chunk_a", persist=False
    )
    assert receipt["artifact_issues"] == []
    assert receipt["denominator_count"] == 0
    assert receipt["candidates"] == []
    assert receipt["summary"]["TOTAL"] == 0
