"""Gate P subject identity and pre-dedup ordering contracts.

These fixtures deliberately avoid protocol-specific names and mechanisms.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from pathlib import Path

import plamen_mechanical as mechanical
import inventory_reconciliation
import plamen_driver as driver


_SEED = (
    "# Promotion Coverage Seed\n\n"
    "| Finding/Hyp ID | Expected Severity | Verdict | Mapped Hypothesis | Dedup Relation |\n"
    "|---|---|---|---|---|\n"
    "| SAME-7 | | RETAINED | | |\n"
)


def _setup(tmp_path: Path) -> Path:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "findings_inventory.md").write_text(
        "# Finding Inventory\n\n"
        "### Finding [INV-001]: baseline\n"
        "**Severity**: Low\n"
        "**Location**: `src/Base.sol:L1`\n",
        encoding="utf-8",
    )
    (scratchpad / "promotion_coverage_seed.md").write_text(
        _SEED, encoding="utf-8"
    )
    return scratchpad


def _block(description: str) -> str:
    return (
        "## Finding [SAME-7]: boundary update can corrupt accounting\n"
        "**Severity**: Medium\n"
        "**Location**: `src/State.sol:L70`\n"
        f"**Description**: {description}\n"
        "**Impact**: Stored accounting can become inconsistent.\n"
    )


def test_subject_is_full_canonical_sha256_bound_to_exact_inputs(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    source = scratchpad / "depth_state_findings.md"
    source.write_text(
        "# Findings\n\n"
        + _block("The first transition misses a boundary check.")
        + "\n"
        + _block("The second transition misses a distinct boundary check."),
        encoding="utf-8",
    )

    rows = [
        row for row in mechanical.compute_promotion_orphans(scratchpad)
        if row.get("orig_id") == "SAME-7"
    ]
    assert len(rows) == 2, (
        "an ID/location/shape collision is not lossless-equivalence authority"
    )
    assert len({row["subject_sha256"] for row in rows}) == 2
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    for row in rows:
        assert len(row["subject_sha256"]) == 64
        assert row["source_artifact_sha256"] == source_sha256
        assert len(row["record_sha256"]) == 64
        payload = {
            "location": row["location"],
            "producer_key": row["producer_key"],
            "record_sha256": row["record_sha256"],
            "schema": "plamen.gate_p.subject.v1",
            "shape": row["shape"],
            "source_artifact": row["source_file"],
            "source_artifact_sha256": source_sha256,
        }
        expected = hashlib.sha256(
            json.dumps(
                payload, ensure_ascii=False, allow_nan=False,
                sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        assert row["subject_sha256"] == expected


def test_id_in_coverage_seed_does_not_suppress_subject(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_state_findings.md").write_text(
        "# Findings\n\n" + _block(
            "The transition misses a boundary check despite the reused local ID."
        ),
        encoding="utf-8",
    )
    rows = mechanical.compute_promotion_orphans(scratchpad)
    assert any(row.get("orig_id") == "SAME-7" for row in rows)


def test_only_exact_delivered_subject_in_seed_suppresses(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_state_findings.md").write_text(
        "# Findings\n\n"
        + _block("The first transition misses a boundary check.")
        + "\n"
        + _block("The second transition misses a distinct boundary check."),
        encoding="utf-8",
    )
    initial = mechanical.compute_promotion_orphans(scratchpad)
    assert len(initial) == 2
    delivered = initial[0]["subject_sha256"]
    (scratchpad / "promotion_coverage_seed.md").write_text(
        _SEED
        + "\n## Delivered Promotion Subjects\n\n"
        + "| Subject SHA256 | Status |\n|---|---|\n"
        + f"| {delivered} | DELIVERED |\n",
        encoding="utf-8",
    )

    remaining = mechanical.compute_promotion_orphans(scratchpad)
    assert [row["subject_sha256"] for row in remaining] == [
        row["subject_sha256"] for row in initial
        if row["subject_sha256"] != delivered
    ]
    ids, _verdicts = mechanical._promo_seed_ids(scratchpad)
    assert delivered.upper() not in ids


def test_reconciled_subjects_accept_only_validated_one_to_one_retention(
    tmp_path: Path, monkeypatch
):
    scratchpad = _setup(tmp_path)
    source_sha256 = hashlib.sha256(b"source artifact").hexdigest()
    retained_record = hashlib.sha256(b"retained record").hexdigest()
    debt_record = hashlib.sha256(b"debt record").hexdigest()
    (scratchpad / "inventory_reconciliation.json").write_text(
        json.dumps({
            "candidates": [
                {
                    "disposition": "RETAINED",
                    "target_inventory_id": "INV-010",
                    "producer_key": "depth",
                    "source_artifact": "depth_state_findings.md",
                    "source_sha256": source_sha256,
                    "source_block_sha256": retained_record,
                    "source_location": "`src/State.sol:L70`",
                },
                {
                    "disposition": "HUMAN_REVIEW_DEBT",
                    "target_inventory_id": "",
                    "producer_key": "depth",
                    "source_artifact": "depth_state_findings.md",
                    "source_sha256": source_sha256,
                    "source_block_sha256": debt_record,
                    "source_location": "`src/State.sol:L70`",
                },
            ]
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        inventory_reconciliation,
        "validate_inventory_reconciliation",
        lambda _root: [],
    )
    subjects = mechanical.promotion_reconciled_subjects(scratchpad)
    expected_payload = {
        "location": "src/State.sol:L70",
        "producer_key": "depth",
        "record_sha256": retained_record,
        "schema": "plamen.gate_p.subject.v1",
        "shape": "finding_block",
        "source_artifact": "depth_state_findings.md",
        "source_artifact_sha256": source_sha256,
    }
    expected = hashlib.sha256(json.dumps(
        expected_payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    assert subjects == {expected}


def test_compute_skips_exact_reconciled_retention_but_not_debt(
    tmp_path: Path, monkeypatch
):
    scratchpad = _setup(tmp_path)
    source = scratchpad / "depth_state_findings.md"
    source.write_text(
        "# Findings\n\n"
        + _block("The transition misses a boundary check and needs review."),
        encoding="utf-8",
    )
    candidate = mechanical.compute_promotion_orphans(scratchpad)[0]
    base = {
        "producer_key": candidate["producer_key"],
        "source_artifact": source.name,
        "source_sha256": candidate["source_artifact_sha256"],
        "source_block_sha256": candidate["record_sha256"],
        "source_location": candidate["location"],
    }
    receipt = scratchpad / "inventory_reconciliation.json"
    monkeypatch.setattr(
        inventory_reconciliation,
        "validate_inventory_reconciliation",
        lambda _root: [],
    )

    receipt.write_text(json.dumps({"candidates": [{
        **base,
        "disposition": "RETAINED",
        "target_inventory_id": "INV-010",
    }]}), encoding="utf-8")
    assert mechanical.compute_promotion_orphans(scratchpad) == []

    receipt.write_text(json.dumps({"candidates": [{
        **base,
        "disposition": "HUMAN_REVIEW_DEBT",
        "target_inventory_id": "",
    }]}), encoding="utf-8")
    reopened = mechanical.compute_promotion_orphans(scratchpad)
    assert [row["subject_sha256"] for row in reopened] == [
        candidate["subject_sha256"]
    ]


def test_harvest_is_deterministic_when_glob_order_changes(
    tmp_path: Path, monkeypatch
):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_z_findings.md").write_text(
        "# Z\n\n" + _block("A transition misses the last boundary check."),
        encoding="utf-8",
    )
    (scratchpad / "depth_a_findings.md").write_text(
        "# A\n\n" + _block("A transition misses the first boundary check."),
        encoding="utf-8",
    )
    original = mechanical._PROMO_FEEDER_GLOBS
    monkeypatch.setattr(
        mechanical,
        "_PROMO_FEEDER_GLOBS",
        ("depth_z*.md", "depth_a*.md") + original,
    )
    first = [row["subject_sha256"] for row in mechanical.compute_promotion_orphans(scratchpad)]
    monkeypatch.setattr(
        mechanical,
        "_PROMO_FEEDER_GLOBS",
        ("depth_a*.md", "depth_z*.md") + original,
    )
    second = [row["subject_sha256"] for row in mechanical.compute_promotion_orphans(scratchpad)]
    assert first == second


def test_inventory_subject_recovers_crash_before_receipt(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_state_findings.md").write_text(
        "# Findings\n\n"
        + _block("The transition misses a boundary check and needs verification."),
        encoding="utf-8",
    )
    first = mechanical.route_promotion_orphans(scratchpad)
    assert first["emitted_to_inventory"] == 1
    inventory_before = (scratchpad / "findings_inventory.md").read_bytes()
    (scratchpad / "promotion_gate_receipt.md").unlink()

    second = mechanical.route_promotion_orphans(scratchpad)
    assert second["emitted_to_inventory"] == 0
    assert (scratchpad / "findings_inventory.md").read_bytes() == inventory_before
    assert inventory_before.count(b"**Promotion Subject SHA256**:") == 1


def test_route_collapses_only_an_exact_repeated_subject(tmp_path: Path):
    scratchpad = _setup(tmp_path)
    (scratchpad / "depth_state_findings.md").write_text(
        "# Findings\n\n"
        + _block("The transition misses one boundary check and needs review."),
        encoding="utf-8",
    )
    row = mechanical.compute_promotion_orphans(scratchpad)[0]
    result = mechanical.route_promotion_orphans(
        scratchpad, [row, dict(row)]
    )
    assert result["emitted_to_inventory"] == 1
    inventory = (scratchpad / "findings_inventory.md").read_text(encoding="utf-8")
    assert inventory.count("**Promotion Subject SHA256**:") == 1


def test_gate_p_harvest_precedes_semantic_dedup_under_mutation_authority():
    source = Path(__file__).with_name("plamen_driver.py").read_text(encoding="utf-8")
    sc_start = source.index(
        'if phase.name == "sc_semantic_dedup" and config.get("pipeline") == "sc":'
    )
    sc_end = source.index(
        'if phase.name == "attention_repair" and config.get("pipeline") == "sc":',
        sc_start,
    )
    sc_block = source[sc_start:sc_end]
    assert sc_block.index("_run_gate_p_with_semantic_invalidation(") < sc_block.index(
        "_compute_dedup_candidate_blocks(scratchpad)"
    )

    l1_prepare = inspect.getsource(
        driver._prepare_l1_semantic_dedup_inventory
    )
    assert l1_prepare.index(
        "_run_gate_p_with_semantic_invalidation("
    ) < l1_prepare.index("_run_l1_dedup_pair_candidate_phase(")
    assert "_run_gate_p_with_semantic_invalidation(" not in inspect.getsource(
        driver._run_live_verify_queue_phase_boundary
    )
