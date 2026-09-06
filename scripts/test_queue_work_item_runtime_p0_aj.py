"""Runtime wiring fixtures for the P0-AJ typed verification queue."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

import plamen_parsers as P
from queue_work_items import (
    QUEUE_RECORD_SET_SCHEMA_VERSION,
    LineageLink,
    queue_records_from_json,
    validate_exact_partition,
)


def _row(fid: str, severity: str = "High", *, stale: str = "") -> dict[str, str]:
    return {
        "queue #": "1",
        "finding id": fid,
        "expected output file": stale or f"verify_{fid}.md",
        "severity": severity,
        "title": f"Title {fid}",
        "bug class": "state-transition",
        "preferred tag": "CODE-TRACE",
        "location": "contracts/pool.rs:41",
        "primary artifact": "depth_state_findings.md",
        "poc class": "integration",
    }


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


@pytest.mark.parametrize(
    "project",
    (P.compute_verify_shards, P.compute_sc_verify_shards),
)
@pytest.mark.parametrize("rows", ([], [_row("H-1"), _row("M-1", "Medium")]))
def test_verify_shard_projection_is_byte_pure_and_resume_stable(
    tmp_path: Path,
    project,
    rows: list[dict[str, str]],
) -> None:
    P._write_queue_subset_manifest(tmp_path / "verification_queue.md", rows)
    before = _tree_bytes(tmp_path)

    first = project(tmp_path)
    after_first = _tree_bytes(tmp_path)
    second = project(tmp_path)

    assert first == second
    assert after_first == before
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize(
    "project",
    (P.compute_verify_shards, P.compute_sc_verify_shards),
)
def test_verify_shard_projection_preserves_valid_crlf_typed_authority_bytes(
    tmp_path: Path,
    project,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1")])
    typed = target.with_suffix(".work_items.json")
    typed.write_bytes(typed.read_bytes().replace(b"\n", b"\r\n"))
    before = _tree_bytes(tmp_path)

    first = project(tmp_path)
    second = project(tmp_path)

    assert first == second
    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize(
    "project",
    (P.compute_verify_shards, P.compute_sc_verify_shards),
)
@pytest.mark.parametrize("rows", ([], [_row("H-1")]))
def test_verify_shard_projection_uses_pure_in_memory_fallback_without_creating_authority(
    tmp_path: Path,
    project,
    rows: list[dict[str, str]],
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, rows)
    typed = target.with_suffix(".work_items.json")
    typed.unlink()
    before = _tree_bytes(tmp_path)

    shards = project(tmp_path)

    assert not typed.exists()
    assert _tree_bytes(tmp_path) == before
    assert {
        row["finding id"]
        for shard_rows in shards.values()
        for row in shard_rows
    } == {row["finding id"] for row in rows}


@pytest.mark.parametrize(
    "project",
    (P.compute_verify_shards, P.compute_sc_verify_shards),
)
def test_verify_shard_projection_rejects_stale_typed_authority_without_repair(
    tmp_path: Path,
    project,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1")])
    stale_typed = target.with_suffix(".work_items.json").read_bytes()
    P._write_queue_subset_manifest(target, [_row("H-2")])
    target.with_suffix(".work_items.json").write_bytes(stale_typed)
    before = _tree_bytes(tmp_path)

    with pytest.raises(ValueError, match="typed queue/Markdown identity drift"):
        project(tmp_path)

    assert _tree_bytes(tmp_path) == before


@pytest.mark.parametrize(
    "project",
    (P.compute_verify_shards, P.compute_sc_verify_shards),
)
def test_verify_shard_projection_rejects_legacy_typed_schema_without_migration(
    tmp_path: Path,
    project,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1")])
    typed = target.with_suffix(".work_items.json")
    payload = json.loads(typed.read_text(encoding="utf-8"))
    assert payload["schema_version"] == QUEUE_RECORD_SET_SCHEMA_VERSION
    payload["schema_version"] = "plamen.queue_work_items.v2"
    typed.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    before = _tree_bytes(tmp_path)

    with pytest.raises(ValueError, match="canonical typed queue schema"):
        project(tmp_path)

    assert _tree_bytes(tmp_path) == before


def test_canonical_row_never_preserves_stale_executable_filename() -> None:
    row = P._canonical_queue_row(
        _row("H-22", stale="verify_INV-041.md")
    )
    assert row["finding id"] == "H-22"
    assert row["expected output file"] == "verify_H-22.md"


def test_canonical_row_and_typed_sidecar_preserve_independent_policy(
    tmp_path: Path,
) -> None:
    row = {
        **_row("DA-7", "Low"),
        "required disposition": "VERIFY_INDEPENDENTLY",
        "relation kind": "ENABLER_CONSTITUENT",
    }
    target = tmp_path / "verification_queue.md"

    P._write_queue_subset_manifest(target, [row])

    canonical = P._read_queue_json_sidecar(target)[0]
    typed = queue_records_from_json(
        target.with_suffix(".work_items.json").read_text(encoding="utf-8")
    )[0]
    assert canonical["required disposition"] == "VERIFY_INDEPENDENTLY"
    assert canonical["relation kind"] == "ENABLER_CONSTITUENT"
    assert typed.required_disposition == "VERIFY_INDEPENDENTLY"


def test_queue_manifest_dual_writes_digest_bound_typed_records(
    tmp_path: Path,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(
        target,
        [_row("H-22", stale="verify_INV-041.md"), _row("M-7", "Medium")],
    )
    typed = target.with_suffix(".work_items.json")
    assert typed.is_file()
    items = queue_records_from_json(typed.read_text(encoding="utf-8"))
    assert [item.work_item_id for item in items] == ["H-22", "M-7"]
    h22 = next(item for item in items if item.work_item_id == "H-22")
    assert h22.expected_output_file == "verify_H-22.md"
    assert "INV-041" in h22.aliases


def test_l1_sharding_conserves_exact_typed_queue_partition(
    tmp_path: Path,
) -> None:
    rows = [
        _row("H-1", "High"),
        _row("M-1", "Medium"),
        _row("L-1", "Low"),
        _row("I-1", "Informational"),
    ]
    P._write_queue_subset_manifest(tmp_path / "verification_queue.md", rows)
    shards = P.compute_verify_shards(tmp_path)
    items = queue_records_from_json(
        (tmp_path / "verification_queue.work_items.json").read_text(
            encoding="utf-8"
        )
    )
    conservation = validate_exact_partition(
        items,
        {
            name: [row["finding id"] for row in shard_rows]
            for name, shard_rows in shards.items()
        },
    )
    assert conservation.ok


def test_lossy_legacy_projection_does_not_discard_typed_alias_lineage(
    tmp_path: Path,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(
        target, [_row("H-22", stale="verify_INV-041.md")]
    )
    shards = P.compute_verify_shards(tmp_path)
    assert any(
        row.get("finding id") == "H-22"
        for shard_rows in shards.values()
        for row in shard_rows
    )
    (item,) = P._read_typed_queue_work_items(target)
    assert item.candidate_identity == "H-22"
    assert "INV-041" in item.aliases
    assert any(
        link.identity == "INV-041" and link.relation == "MIGRATION_DEBT"
        for link in item.lineage
    )


def test_typed_authority_accepts_rich_typed_only_fields_with_exact_markdown(
    tmp_path: Path,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1")])
    (base,) = P._read_typed_queue_work_items(target)
    rich = replace(
        base,
        aliases=("INV-041",),
        constituents=("INV-041", "INV-042"),
        lineage=(
            *base.lineage,
            LineageLink(
                identity="INV-041",
                relation="CONSTITUENT",
                parent_identity="H-1",
                source_artifact="finding_mapping.md",
            ),
            LineageLink(
                identity="INV-042",
                relation="CONSTITUENT",
                parent_identity="H-1",
                source_artifact="finding_mapping.md",
            ),
        ),
    )
    P._write_queue_work_item_records_manifest(target, (rich,))

    replay = P._require_typed_queue_authority(
        target, P.parse_verification_queue_rows(tmp_path)
    )

    assert replay == (rich,)
    assert replay[0].constituents == ("INV-041", "INV-042")
    assert replay[0].aliases == ("INV-041",)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("| 1 | H-1 |", "| 9 | H-1 |"),
        ("| H-1 | verify_H-1.md |", "| H-9 | verify_H-1.md |"),
        ("verify_H-1.md", "verify_H-9.md"),
        ("| High |", "| Medium |"),
        ("| Title H-1 |", "| Altered title |"),
        ("| state-transition |", "| authorization |"),
        ("| CODE-TRACE |", "| TEST-PASS |"),
        ("| contracts/pool.rs:41 |", "| contracts/pool.rs:99 |"),
        ("| depth_state_findings.md |", "| findings_inventory.md |"),
        ("| integration |", "| structural |"),
    ],
)
def test_typed_authority_rejects_every_rendered_field_mutation(
    tmp_path: Path,
    old: str,
    new: str,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1")])
    original = target.read_text(encoding="utf-8")
    assert old in original
    target.write_text(original.replace(old, new, 1), encoding="utf-8")

    with pytest.raises(ValueError):
        P._require_typed_queue_authority(
            target, P.parse_verification_queue_rows(tmp_path)
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "reordered"])
def test_typed_authority_rejects_row_denominator_or_order_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1"), _row("H-2")])
    lines = target.read_text(encoding="utf-8").splitlines()
    row_indexes = [
        index for index, line in enumerate(lines)
        if line.startswith("| 1 |") or line.startswith("| 2 |")
    ]
    assert len(row_indexes) == 2
    first, second = row_indexes
    if mutation == "missing":
        del lines[first]
    elif mutation == "extra":
        lines.insert(second + 1, lines[first])
    else:
        lines[first], lines[second] = lines[second], lines[first]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(ValueError):
        P._require_typed_queue_authority(
            target, P.parse_verification_queue_rows(tmp_path)
        )


def test_duplicate_current_identity_fails_before_shard_launch(
    tmp_path: Path,
) -> None:
    (tmp_path / "verification_queue.md").write_text(
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Expected Output File | Severity | Title | "
        "Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---|---|---|---|---|---|---|---|---|---|\n"
        "| 1 | H-1 | verify_H-1.md | High | A | state | CODE-TRACE | a.sol:1 | a | integration |\n"
        "| 2 | H-1 | verify_INV-9.md | High | B | state | CODE-TRACE | b.sol:2 | b | integration |\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate work_item_id"):
        P.compute_verify_shards(tmp_path)


def test_typed_sidecar_tamper_is_not_silently_accepted(tmp_path: Path) -> None:
    target = tmp_path / "verification_queue.md"
    P._write_queue_subset_manifest(target, [_row("H-1")])
    sidecar = target.with_suffix(".work_items.json")
    sidecar.write_text(
        sidecar.read_text(encoding="utf-8").replace('"H-1"', '"H-9"', 1),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="record_set_digest mismatch|lineage"):
        P._read_typed_queue_work_items(target)
