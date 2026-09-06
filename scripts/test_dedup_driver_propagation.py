"""Driver-side dedup tests: absorbed->survivor propagation + multi-round
carry-forward exclusion list.

These cover the plamen_driver.py changes for the dedup-throughput upgrade:

  * ``_dedup_absorbed_survivor_mapping`` — parse both the LLM ``MERGED into``
    rows and the mechanical ``MECHANICAL_MERGE/SUPPLEMENT`` rows into a
    {absorbed: {survivor, coupled}} map.
  * ``_write_dedup_absorbed_map`` — driver-owned sidecar read by Chain Agent 1.
  * ``_propagate_dedup_absorbed_to_finding_mapping`` — records absorbed IDs as
    constituents of their survivor's hypothesis (sidecar always; in-place edit
    of finding_mapping.md when it exists).
  * ``_build_dedup_round_exclusion_block`` / ``_stage_dedup_round_packet`` —
    multi-round carry-forward so each pair is decided exactly once.

ZERO-DATA-LOSS posture: propagation is purely additive; carry-forward prevents
re-deciding (oscillation) but never blind-merges. No merge is applied here.
"""

import shutil
from pathlib import Path

import plamen_driver as d
from plamen_mechanical import apply_llm_dedup_decisions


def _install_receipted_aliases(
    scratchpad: Path, pairs: list[tuple[str, str]],
) -> None:
    """Apply real SC merges and swap the receipted result to canonical."""
    all_ids = sorted({fid for pair in pairs for fid in pair})
    absorbed = {item for item, _survivor in pairs}
    blocks: list[str] = []
    for index, fid in enumerate(all_ids, 1):
        source_ids = f"S-{index}"
        for absorbed_id, survivor_id in pairs:
            if fid == survivor_id:
                absorbed_index = all_ids.index(absorbed_id) + 1
                source_ids += f", S-{absorbed_index}"
        line = index * 20
        if fid not in absorbed:
            location = f"src/module.rs:{line}-{line + 19}"
        else:
            survivor = next(s for a, s in pairs if a == fid)
            survivor_index = all_ids.index(survivor) + 1
            survivor_line = survivor_index * 20
            location = f"src/module.rs:{survivor_line + 2}-{survivor_line + 4}"
        blocks.append(
            f"### Finding [{fid}]: finding {fid}\n"
            "**Severity**: Medium\n"
            f"**Location**: {location}\n"
            f"**Source IDs**: {source_ids}\n"
            "**Root Cause**: shared root cause\n"
            "**Description**: shared mechanism\n"
            "**Impact**: material impact\n"
            "**Recommendation**: apply the shared fix\n\n"
        )
    decisions = "# Semantic Dedup Decisions\n\n" + "\n".join(
        f"MERGE: {survivor}, {absorbed_id}"
        for absorbed_id, survivor in pairs
    ) + "\n"
    (scratchpad / "findings_inventory.md").write_text("".join(blocks), encoding="utf-8")
    (scratchpad / "dedup_decisions.md").write_text(decisions, encoding="utf-8")
    assert apply_llm_dedup_decisions(scratchpad, "sc_semantic_dedup") == len(pairs)
    shutil.copy2(
        scratchpad / "findings_inventory_deduped.md",
        scratchpad / "findings_inventory.md",
    )


# ---------------------------------------------------------------------------
# _dedup_absorbed_survivor_mapping
# ---------------------------------------------------------------------------

def test_absorbed_mapping_consumes_applied_receipt_only(tmp_path: Path):
    _install_receipted_aliases(
        tmp_path, [("INV-013", "INV-014"), ("INV-061", "INV-062")]
    )
    m = d._dedup_absorbed_survivor_mapping(tmp_path)
    assert m["INV-013"]["survivor"] == "INV-014"
    assert m["INV-013"]["coupled"] == "field-complete-preserved"
    assert m["INV-061"]["survivor"] == "INV-062"


def test_absorbed_mapping_empty_when_no_decisions(tmp_path: Path):
    assert d._dedup_absorbed_survivor_mapping(tmp_path) == {}
    (tmp_path / "dedup_decisions.md").write_text(
        "# Decisions\n\n**Status**: PASSTHROUGH\n", encoding="utf-8"
    )
    assert d._dedup_absorbed_survivor_mapping(tmp_path) == {}


# ---------------------------------------------------------------------------
# _propagate_dedup_absorbed_to_finding_mapping
# ---------------------------------------------------------------------------

def test_propagate_writes_sidecar_when_no_finding_mapping(tmp_path: Path):
    _install_receipted_aliases(tmp_path, [("INV-010", "INV-011")])
    n = d._propagate_dedup_absorbed_to_finding_mapping(tmp_path)
    assert n == 1
    sidecar = tmp_path / "dedup_absorbed_map.md"
    assert sidecar.exists()
    body = sidecar.read_text(encoding="utf-8")
    assert "INV-010" in body and "INV-011" in body
    assert "field-complete-preserved" in body


def test_propagate_records_constituent_in_existing_finding_mapping(tmp_path: Path):
    _install_receipted_aliases(tmp_path, [("INV-010", "INV-011")])
    # finding_mapping already has INV-011 -> H-5 (chain ran)
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        "|------------|---------------|----------------|-------|\n"
        "| INV-011 | H-5 | BASELINE_ONE_TO_ONE | preserved |\n",
        encoding="utf-8",
    )
    n = d._propagate_dedup_absorbed_to_finding_mapping(tmp_path)
    assert n == 1
    fm = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    # INV-010 now mapped to survivor's hypothesis H-5 as a dedup constituent.
    row = [ln for ln in fm.splitlines() if ln.strip().startswith("| INV-010")]
    assert row, "INV-010 constituent row not appended"
    assert "H-5" in row[0]
    assert "DEDUP" in row[0].upper()
    assert "INV-011" in row[0]  # survivor referenced in note


def test_propagate_does_not_duplicate_already_mapped_absorbed(tmp_path: Path):
    _install_receipted_aliases(tmp_path, [("INV-010", "INV-011")])
    # finding_mapping ALREADY contains INV-010 (chain re-added it).
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        "|------------|---------------|----------------|-------|\n"
        "| INV-011 | H-5 | OK | s |\n"
        "| INV-010 | H-5 | OK | already mapped |\n",
        encoding="utf-8",
    )
    before = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    d._propagate_dedup_absorbed_to_finding_mapping(tmp_path)
    after = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    # No duplicate INV-010 row appended.
    assert after.count("| INV-010") == 1
    assert before.count("| INV-010") == 1


def test_propagate_survivor_missing_falls_back_not_dropped(tmp_path: Path):
    # Survivor INV-099 is NOT in finding_mapping (chain dropped/renamed it).
    _install_receipted_aliases(tmp_path, [("INV-098", "INV-099")])
    (tmp_path / "finding_mapping.md").write_text(
        "# Finding Mapping\n\n"
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |\n"
        "|------------|---------------|----------------|-------|\n"
        "| INV-011 | H-5 | OK | s |\n",
        encoding="utf-8",
    )
    n = d._propagate_dedup_absorbed_to_finding_mapping(tmp_path)
    assert n == 1
    fm = (tmp_path / "finding_mapping.md").read_text(encoding="utf-8")
    # Absorbed ID still recorded (never silently dropped).
    assert "| INV-098" in fm


# ---------------------------------------------------------------------------
# Multi-round carry-forward
# ---------------------------------------------------------------------------

def _round_file(tmp_path: Path, n: int, pair_lines: list[str]) -> Path:
    header = [
        "# Dedup Candidate Pairs (Round %d)" % n,
        "",
        "| Finding A | Finding B | Title Score | Signal | Same Sev? |",
        "|-----------|-----------|-------------|--------|-----------|",
    ]
    p = tmp_path / f"dedup_candidate_pairs_round{n}.md"
    p.write_text("\n".join(header + pair_lines) + "\n", encoding="utf-8")
    return p


def test_build_exclusion_block_from_prior_decisions(tmp_path: Path):
    (tmp_path / "dedup_decisions.md").write_text(
        "| INV-010 | MERGED into INV-011 | x | y |\n"
        "| INV-020 | KEEP SEPARATE | | distinct fix |\n",
        encoding="utf-8",
    )
    block = d._build_dedup_round_exclusion_block(tmp_path)
    assert "## Already-decided exclusion list" in block
    for fid in ("INV-010", "INV-011", "INV-020"):
        assert fid in block


def test_stage_round_prepends_exclusion_and_is_per_round(tmp_path: Path):
    _round_file(
        tmp_path, 1,
        ["| INV-001: a | INV-002: a | 1.00 | location overlap | yes |"],
    )
    _round_file(
        tmp_path, 2,
        ["| INV-003: b | INV-004: b | 1.00 | location overlap | yes |"],
    )
    # Round 1: no prior decisions -> empty exclusion list.
    staged = d._stage_dedup_round_packet(tmp_path, 1)
    assert staged is not None
    live1 = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
    assert "INV-001" in live1 and "INV-002" in live1
    assert "INV-003" not in live1  # round 2 not in round 1 packet

    # Simulate round-1 decision then stage round 2.
    (tmp_path / "dedup_decisions.md").write_text(
        "| INV-001 | MERGED into INV-002 | coupled | n |\n", encoding="utf-8"
    )
    staged2 = d._stage_dedup_round_packet(tmp_path, 2)
    assert staged2 is not None
    live2 = (tmp_path / "dedup_candidate_pairs.md").read_text(encoding="utf-8")
    # Round 2 packet carries the carry-forward exclusion list with round-1 IDs.
    assert "## Already-decided exclusion list" in live2
    assert "INV-001" in live2 and "INV-002" in live2  # excluded
    assert "INV-003" in live2 and "INV-004" in live2  # this round's live pairs


def test_multiround_carryforward_no_redecide(tmp_path: Path):
    """Each pair is decided exactly once; round 2 excludes round-1 IDs."""
    _round_file(
        tmp_path, 1,
        ["| INV-010: x | INV-011: x | 1.00 | location overlap | yes |"],
    )
    _round_file(
        tmp_path, 2,
        ["| INV-020: y | INV-021: y | 1.00 | location overlap | yes |"],
    )
    rounds = d._dedup_round_files(tmp_path)
    assert [d._dedup_round_index(p.name) for p in rounds] == [1, 2]

    # Round 1 decision recorded.
    d._stage_dedup_round_packet(tmp_path, 1)
    (tmp_path / "dedup_decisions.md").write_text(
        "| INV-010 | MERGED into INV-011 | coupled | n |\n", encoding="utf-8"
    )
    # Round 2 exclusion list must contain ALL round-1 decided IDs.
    block = d._build_dedup_round_exclusion_block(tmp_path)
    assert "INV-010" in block and "INV-011" in block
    # And round-2 pairs are NOT yet in the exclusion list.
    assert "INV-020" not in block and "INV-021" not in block


def test_round_files_sorted_numerically(tmp_path: Path):
    for n in (10, 2, 1):
        _round_file(tmp_path, n, ["| INV-1: a | INV-2: a | 1.0 | x | yes |"])
    idx = [d._dedup_round_index(p.name) for p in d._dedup_round_files(tmp_path)]
    assert idx == [1, 2, 10]


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
