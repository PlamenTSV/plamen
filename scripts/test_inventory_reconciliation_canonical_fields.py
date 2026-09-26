"""Canonical producer fields stay lossless through inventory reconciliation."""

from __future__ import annotations

from pathlib import Path

from inventory_reconciliation import (
    _canonical_blocks,
    _semantic_preservation_deltas,
    reconcile_inventory,
)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _canonical_finding(
    finding_id: str,
    *,
    source_ids: str = "",
    mechanism: str = "The unchecked branch preserves a stale balance.",
    harm: str = "Depositors lose their withdrawable balance.",
) -> str:
    source_line = (
        f"**Source IDs** (upstream candidate references): {source_ids}\n"
        if source_ids
        else ""
    )
    description_line = f"**Description**: {mechanism}\n" if mechanism else ""
    return (
        f"### Finding [{finding_id}]: Canonical template fixture\n\n"
        f"{source_line}"
        "**Severity**: High\n"
        "**Location**: src/Fixture.sol:L7\n"
        "**Root Cause**: The state update is incomplete.\n"
        "**Depth Evidence** (depth agents only): [TRACE:entry -> stale state -> exit]\n"
        f"{description_line}"
        f"**Material Harm** (MANDATORY): {harm}\n"
        "**Preconditions** (reachable branch): The affected balance is nonzero.\n"
    )


def test_literal_canonical_annotations_are_fields_and_lookahead_boundaries(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "analysis_fixture.md"
    _write(artifact, _canonical_finding("F-01", source_ids="B-01"))

    blocks, issues = _canonical_blocks(artifact)

    assert issues == []
    assert len(blocks) == 1
    block = blocks[0]
    assert block["source_ids"] == ["B-01"]
    assert block["root_cause"] == "The state update is incomplete."
    assert "Depth Evidence" not in block["root_cause"]
    assert block["description"] == "The unchecked branch preserves a stale balance."
    assert block["impact"] == "Depositors lose their withdrawable balance."
    assert block["preconditions"] == "The affected balance is nonzero."


def test_description_is_the_generic_mechanism_fallback(tmp_path: Path) -> None:
    artifact = tmp_path / "analysis_fixture.md"
    finding = _canonical_finding("F-01").replace(
        "**Root Cause**: The state update is incomplete.\n", ""
    )
    _write(artifact, finding)

    blocks, issues = _canonical_blocks(artifact)

    assert issues == []
    assert blocks[0]["root_cause"] == (
        "The unchecked branch preserves a stale balance."
    )

    candidate = {"source_root_cause": blocks[0]["root_cause"]}
    target = {
        "root_cause": "A differently worded synthesis.",
        "description": blocks[0]["description"],
        "impact": "",
        "preconditions": "",
    }
    assert "ROOT_CAUSE" not in _semantic_preservation_deltas(candidate, target)


def test_unparseable_mandatory_mechanism_is_explicit_reconciliation_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    raw = _canonical_finding("F-01", mechanism="").replace(
        "**Root Cause**: The state update is incomplete.\n", ""
    )
    target = _canonical_finding(
        "INV-001",
        source_ids="analysis_fixture.md:F-01",
        mechanism="A downstream writer supplied a mechanism.",
    )
    _write(scratchpad / "analysis_fixture.md", raw)
    _write(
        scratchpad / "inventory_chunk_a.manifest.md",
        "# Inventory shard\n\n| File |\n|---|\n| analysis_fixture.md |\n",
    )
    _write(scratchpad / "findings_inventory_chunk_a.md", target)
    _write(scratchpad / "findings_inventory.md", target)

    receipt = reconcile_inventory(scratchpad)

    assert receipt["denominator_count"] == 1
    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "FINAL_SEMANTIC_PRESERVATION_DEBT"
    assert "UNPARSEABLE_ROOT_CAUSE" in row["required_preservation_axes"]
    assert row["mandatory_reverification"] is True
    assert row["mandatory_reverification_id"]


def test_unparseable_mandatory_harm_is_explicit_reconciliation_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    raw = _canonical_finding("F-01", harm="").replace(
        "**Material Harm** (MANDATORY): \n", ""
    )
    target = _canonical_finding(
        "INV-001",
        source_ids="analysis_fixture.md:F-01",
        harm="A downstream writer supplied a harm premise.",
    )
    _write(scratchpad / "analysis_fixture.md", raw)
    _write(
        scratchpad / "inventory_chunk_a.manifest.md",
        "# Inventory shard\n\n| File |\n|---|\n| analysis_fixture.md |\n",
    )
    _write(scratchpad / "findings_inventory_chunk_a.md", target)
    _write(scratchpad / "findings_inventory.md", target)

    receipt = reconcile_inventory(scratchpad)

    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "FINAL_SEMANTIC_PRESERVATION_DEBT"
    assert "UNPARSEABLE_IMPACT" in row["required_preservation_axes"]
    assert row["mandatory_reverification"] is True


def _methodology_repair_source() -> str:
    return (
        "### Finding [MAB-1]: Stale accounting survives cancellation\n\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: High\n"
        "**Location**: src/Queue.sol:L41\n"
        "**Methodology Steps**: lifecycle cancellation invariant\n\n"
        "The cancellation branch clears the request but does not restore the "
        "reserved balance used by later withdrawals.\n"
        "**External Assumption**: A later withdrawal consumes the reserve.\n"
        "**Impact**: Depositors can lose access to their reserved principal.\n\n"
        "### Finding [MAB-2]: Finalization omits the paired state update\n\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Medium\n"
        "**Location**: src/Queue.sol:L88\n"
        "**Methodology Step(s)**: aggregate lifecycle accounting\n\n"
        "Finalization advances the lifecycle flag without decrementing the "
        "pending aggregate consumed by the capacity check.\n"
        "**External Assumption**: Capacity remains otherwise available.\n"
        "**Impact**: Users can be prevented from creating otherwise valid requests.\n"
    )


def _inventory_finding(
    finding_id: str,
    source_ids: str,
    mechanism: str,
    impact: str,
) -> str:
    return (
        f"### Finding [{finding_id}]: Preserved methodology repair\n\n"
        "**Severity**: High\n"
        "**Location**: src/Queue.sol:L41\n"
        f"**Description**: {mechanism}\n"
        f"**Impact**: {impact}\n"
        f"**Source IDs**: {source_ids}\n"
    )


def test_mab_unlabeled_mechanisms_are_losslessly_reconciled_with_crlf(
    tmp_path: Path,
) -> None:
    source_name = "analysis_methodology_repair_breadth.md"
    source = _methodology_repair_source()
    (tmp_path / source_name).write_bytes(
        source.replace("\n", "\r\n").encode("utf-8")
    )
    _write(
        tmp_path / "inventory_chunk_a.manifest.md",
        "# Inventory shard\n\n| File |\n|---|\n"
        f"| {source_name} |\n",
    )
    mechanisms = {
        "MAB-1": (
            "The cancellation branch clears the request but does not restore the "
            "reserved balance used by later withdrawals."
        ),
        "MAB-2": (
            "Finalization advances the lifecycle flag without decrementing the "
            "pending aggregate consumed by the capacity check."
        ),
    }
    impacts = {
        "MAB-1": "Depositors can lose access to their reserved principal.",
        "MAB-2": "Users can be prevented from creating otherwise valid requests.",
    }
    chunk = "# Inventory chunk\n\n" + "".join(
        _inventory_finding(
            f"CC-{ordinal}", source_id, mechanisms[source_id], impacts[source_id]
        )
        for ordinal, source_id in ((23, "MAB-1"), (24, "MAB-2"))
    )
    final = "# Finding Inventory\n\n" + "".join(
        _inventory_finding(
            f"INV-{ordinal:03d}",
            f"{source_id}, CC-{chunk_id}",
            mechanisms[source_id],
            impacts[source_id],
        )
        for ordinal, chunk_id, source_id in (
            (1, 23, "MAB-1"),
            (2, 24, "MAB-2"),
        )
    )
    _write(tmp_path / "findings_inventory_chunk_a.md", chunk)
    _write(tmp_path / "findings_inventory.md", final)

    receipt = reconcile_inventory(tmp_path)

    assert receipt["denominator_count"] == 2
    rows = {row["source_finding_id"]: row for row in receipt["candidates"]}
    assert set(rows) == {"MAB-1", "MAB-2"}
    for finding_id, mechanism in mechanisms.items():
        row = rows[finding_id]
        assert row["source_root_cause"] == mechanism
        assert row["source_description"] == mechanism
        assert row["source_impact"] == impacts[finding_id]
        assert row["required_preservation_axes"] == []
        assert row["disposition"] == "RETAINED"


def test_unlabeled_recovery_cannot_mint_empty_mechanism_or_missing_harm(
    tmp_path: Path,
) -> None:
    source_name = "analysis_methodology_repair_breadth.md"
    raw = (
        "### Finding [MAB-1]: Rendered-empty opening paragraph\n\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Medium\n"
        "**Location**: src/Queue.sol:L41\n"
        "**Methodology Steps**: cancellation invariant\n\n"
        "&#8203;\n\n"
        "**Impact**: Depositors lose access to reserved principal.\n\n"
        "### Finding [MAB-2]: Missing material harm\n\n"
        "**Verdict**: NEEDS_VERIFICATION\n"
        "**Severity**: Medium\n"
        "**Location**: src/Queue.sol:L88\n"
        "**Methodology Step(s)**: aggregate lifecycle accounting\n\n"
        "The transition leaves the pending aggregate stale.\n\n"
    )
    _write(tmp_path / source_name, raw)
    _write(
        tmp_path / "inventory_chunk_a.manifest.md",
        "# Inventory shard\n\n| File |\n|---|\n"
        f"| {source_name} |\n",
    )
    chunk = "# Inventory chunk\n\n" + _inventory_finding(
        "CC-23",
        "MAB-1",
        "A downstream writer supplied a mechanism.",
        "Depositors lose access to reserved principal.",
    ) + _inventory_finding(
        "CC-24",
        "MAB-2",
        "The transition leaves the pending aggregate stale.",
        "A downstream writer supplied an impact.",
    )
    final = "# Finding Inventory\n\n" + _inventory_finding(
        "INV-001",
        "MAB-1, CC-23",
        "A downstream writer supplied a mechanism.",
        "Depositors lose access to reserved principal.",
    ) + _inventory_finding(
        "INV-002",
        "MAB-2, CC-24",
        "The transition leaves the pending aggregate stale.",
        "A downstream writer supplied an impact.",
    )
    _write(tmp_path / "findings_inventory_chunk_a.md", chunk)
    _write(tmp_path / "findings_inventory.md", final)

    rows = {
        row["source_finding_id"]: row
        for row in reconcile_inventory(tmp_path)["candidates"]
    }

    assert rows["MAB-1"]["source_root_cause"] == ""
    assert rows["MAB-1"]["disposition"] == "HUMAN_REVIEW_DEBT"
    assert "UNPARSEABLE_ROOT_CAUSE" in rows["MAB-1"][
        "required_preservation_axes"
    ]
    assert rows["MAB-2"]["source_root_cause"] == (
        "The transition leaves the pending aggregate stale."
    )
    assert rows["MAB-2"]["source_impact"] == ""
    assert rows["MAB-2"]["disposition"] == "HUMAN_REVIEW_DEBT"
    assert "UNPARSEABLE_IMPACT" in rows["MAB-2"][
        "required_preservation_axes"
    ]


def test_run8_mab_prefix_recovers_mechanism_but_does_not_invent_impact(
    tmp_path: Path,
) -> None:
    mechanisms = {
        "MAB-1": (
            "The fee setter has no upper bound, so a value at the denominator "
            "consumes all input and a larger value halts fee-bearing flows."
        ),
        "MAB-2": (
            "Packed Solana message integers retain EVM byte order, so a native "
            "decoder reads incorrect amounts and field lengths."
        ),
        "MAB-3": (
            "The Solana account envelope uses dynamic ABI offsets and padded "
            "words instead of the destination account and data layout."
        ),
    }
    artifact = tmp_path / "analysis_methodology_repair_breadth.md"
    text = ""
    for index, (finding_id, mechanism) in enumerate(mechanisms.items(), start=1):
        methodology_label = "row" if index == 2 else "rows"
        text += (
            f"## Finding [{finding_id}]: Run8 producer shape\n\n"
            "**Severity:** High\n\n"
            f"**Methodology {methodology_label}:** SERIALIZATION step {index}\n\n"
            f"{mechanism}\n\n"
            "Evidence: `src/Fixture.sol:42`.\n\n"
            "[EXTERNAL-ASSUMPTION: a native destination decoder is used.]\n\n"
            "Recommendation: enforce the missing invariant.\n\n"
        )
    _write(artifact, text)

    blocks, issues = _canonical_blocks(artifact)

    assert issues == []
    assert len(blocks) == 3
    for block in blocks:
        finding_id = block["finding_id"]
        assert block["description"] == mechanisms[finding_id]
        assert block["root_cause"] == mechanisms[finding_id]
        assert block["impact"] == ""
        candidate = {
            "source_root_cause": block["root_cause"],
            "source_impact": block["impact"],
            "source_preconditions": "",
        }
        target = {
            "root_cause": block["root_cause"],
            "description": block["description"],
            # Attempt 2 copied the combined paragraph into Impact.  That does
            # not make an absent source harm facet parseable or authoritative.
            "impact": block["description"],
            "preconditions": "",
        }
        assert _semantic_preservation_deltas(candidate, target) == [
            "UNPARSEABLE_IMPACT"
        ]
