from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

import chain_tail_authority as CTA


def _row(a: str, b: str, *, signal: str = "state-graph: Vault.balance", **extra):
    return {
        "a": a,
        "b": b,
        "a_sev": "High",
        "b_sev": "Medium",
        "signal": signal,
        "score": 9.0,
        "graph_backed": signal.startswith("state-graph:"),
        **extra,
    }


def _output(rows: list[dict], *, numbered: bool = False, schema: str = "canonical") -> str:
    heading = "## 2. Tail Pair Dispositions" if numbered else "## Tail Pair Dispositions"
    if schema == "aliases":
        lines = [heading, "", "| Pair | A | B | Result | Rationale |", "|---|---|---|---|---|"]
    else:
        lines = [
            heading,
            "",
            "| Pair ID | Finding A | Finding B | Disposition | Evidence |",
            "|---|---|---|---|---|",
        ]
    for row in rows:
        lines.append(
            f"| {row['pair_id']} | {row['a']} | {row['b']} | "
            f"{row.get('disposition', 'EXPLORED')} | "
            f"{row.get('evidence', 'Compared exact producer and consumer loci; no composition.')} |"
        )
    return "\n".join(lines) + "\n"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture_file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _materialize_fixture_rearm_postimages(
    root: Path,
    plan: dict,
) -> None:
    postimages = plan["postimages"]
    assert set(postimages) == set(CTA.MUTABLE_CONTROL_PATHS)
    for relative in CTA.MUTABLE_CONTROL_PATHS:
        path = root / relative
        raw = postimages[relative]
        if relative.endswith(f"/{CTA.CONTROL_JOURNAL_NAME}"):
            assert path.read_bytes() == raw
            continue
        CTA._atomic_bytes(path, raw)


def _budget_stop_predecessor(
    root: Path,
) -> None:
    CTA.initialize_chain_tail(
        root,
        [_row(f"H-{i}", f"M-{i}") for i in range(1, 5)],
        shard_size=2,
    )
    first = CTA.current_chain_tail_shard(root)
    (root / "chain_iteration2.md").write_text(
        _output(first["rows"]), encoding="utf-8"
    )
    receipt = CTA.run_chain_tail_shard_loop(
        root,
        lambda _shard: pytest.fail(
            "budget should stop before another launch"
        ),
        max_shards_per_run=1,
    )
    assert receipt["status"] == "BUDGET_STOP"


def _budget_stop_rearm_poststate(
    root: Path,
) -> dict:
    _budget_stop_predecessor(root)
    with CTA._scheduler_lock(root):
        plan = CTA.plan_rearm_unresolved_chain_tail(root)
        _materialize_fixture_rearm_postimages(root, plan)
    return plan


def _complete_rearmed_control_generation(
    root: Path,
) -> dict:
    _budget_stop_rearm_poststate(root)
    retry = CTA.prepare_next_chain_tail_shard(root)
    (root / "chain_iteration2.md").write_text(
        _output(retry["rows"]), encoding="utf-8"
    )
    completed = CTA.run_chain_tail_shard_loop(
        root,
        lambda _shard: pytest.fail(
            "the materialized retry should complete the denominator"
        ),
        max_shards_per_run=2,
    )
    assert completed["status"] == "COMPLETE"
    assert completed["unresolved_pairs"] == 0
    return completed


@pytest.mark.parametrize("numbered", [False, True])
def test_exact_and_numbered_heading_consume_all_packet_rows(tmp_path: Path, numbered: bool):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1"), _row("H-2", "M-2")])
    shard = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(
        _output(shard["rows"], numbered=numbered), encoding="utf-8"
    )
    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    assert receipt["mechanical_consumed_pairs"] == 2
    assert receipt["status"] == "COMPLETE"
    assert CTA.validate_chain_tail_authority(tmp_path) == []


def test_targeted_header_alias_normalization_is_manifest_bound(tmp_path: Path):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    shard = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(
        _output(shard["rows"], schema="aliases"), encoding="utf-8"
    )
    assert CTA.reconcile_chain_tail_output(tmp_path)["status"] == "COMPLETE"


def test_one_missing_row_remains_explicit_debt_never_clean(tmp_path: Path):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1"), _row("H-2", "M-2")])
    shard = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(
        _output(shard["rows"][:1]), encoding="utf-8"
    )
    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    assert receipt["unresolved_pairs"] == 1
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    missing = [row for row in ledger["pairs"] if row["disposition"] == "UNRESOLVED_COMPOSITION"]
    assert missing[0]["reason"] == "MISSING_WORKER_ROW"


def test_substantive_schema_drift_persists_debt(tmp_path: Path):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    (tmp_path / "chain_iteration2.md").write_text(
        "## 9. Tail Pair Dispositions\n\n| Left | Right | Opinion | Why |\n"
        "|---|---|---|---|\n| H-1 | M-1 | safe | checked source |\n",
        encoding="utf-8",
    )
    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    assert "TABLE_SCHEMA_DRIFT" in receipt["issues"]


def test_overflow_advances_in_deterministic_resume_idempotent_shards(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path, [_row(f"H-{i}", f"M-{i}") for i in range(1, 8)], shard_size=3
    )
    first = CTA.current_chain_tail_shard(tmp_path)
    assert [row["a"] for row in first["rows"]] == ["H-1", "H-2", "H-3"]
    assert CTA.current_chain_tail_shard(tmp_path) == first
    (tmp_path / "chain_iteration2.md").write_text(_output(first["rows"]), encoding="utf-8")
    assert CTA.reconcile_chain_tail_output(tmp_path)["status"] == "CONTINUE"
    second = CTA.prepare_next_chain_tail_shard(tmp_path)
    assert [row["a"] for row in second["rows"]] == ["H-4", "H-5", "H-6"]
    assert CTA.prepare_next_chain_tail_shard(tmp_path) == second


def test_duplicate_and_reversed_pairs_retain_distinct_ids_and_family_members(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path,
        [_row("H-1", "M-1"), _row("M-1", "H-1"), _row("H-1", "M-1")],
    )
    manifest = _load(tmp_path / CTA.MANIFEST_NAME)
    assert len({row["pair_id"] for row in manifest["pairs"]}) == 3
    assert len(manifest["families"]) == 1
    assert len(next(iter(manifest["families"].values()))["member_pair_ids"]) == 3


def test_explicit_equivalence_family_splits_on_divergent_evidence(tmp_path: Path):
    rows = [
        _row("H-1", "M-1", equivalence_key="shared-write-family"),
        _row("H-2", "M-2", equivalence_key="shared-write-family"),
    ]
    CTA.initialize_chain_tail(tmp_path, rows)
    shard = CTA.current_chain_tail_shard(tmp_path)
    output_rows = [
        {**shard["rows"][0], "disposition": "EXPLORED", "evidence": "No state handoff at A.sol:L10."},
        {**shard["rows"][1], "disposition": "REJECTED", "evidence": "Independent lifecycle at B.sol:L20."},
    ]
    (tmp_path / "chain_iteration2.md").write_text(_output(output_rows), encoding="utf-8")
    CTA.reconcile_chain_tail_output(tmp_path)
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    assert len({row["resolved_family_id"] for row in ledger["pairs"]}) == 2


def test_graph_identity_family_groups_distinct_pairs_without_losing_members(
    tmp_path: Path,
):
    rows = [
        _row("H-1", "M-1", signal="state-graph: SYM-STATE-001"),
        _row("H-2", "M-2", signal="state-graph: SYM-STATE-001"),
    ]
    CTA.initialize_chain_tail(tmp_path, rows)
    manifest = _load(tmp_path / CTA.MANIFEST_NAME)
    assert len(manifest["families"]) == 1
    family = next(iter(manifest["families"].values()))
    assert family["member_pair_ids"] == [
        manifest["pairs"][0]["pair_id"],
        manifest["pairs"][1]["pair_id"],
    ]


def test_pair_generator_failure_is_unknown_debt(tmp_path: Path):
    receipt = CTA.initialize_failed_chain_tail(tmp_path, "synthetic generator failure")
    assert receipt["status"] == "FAILED_GENERATOR"
    assert CTA.validate_chain_tail_authority(tmp_path)


def test_budget_stop_retains_exact_remaining_ids_and_bounded_projection(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path, [_row(f"H-{i}", f"M-{i}") for i in range(1, 25)], shard_size=3
    )
    first = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(_output(first["rows"]), encoding="utf-8")
    CTA.reconcile_chain_tail_output(tmp_path)
    receipt = CTA.mark_chain_tail_budget_stop(tmp_path, "CHAIN_TAIL_SHARD_BUDGET")
    assert receipt["status"] == "BUDGET_STOP"
    assert receipt["unresolved_pairs"] == 21
    assert len((tmp_path / CTA.PROJECTION_NAME).read_bytes()) <= CTA.DEFAULT_PROJECTION_BYTE_CEILING


def test_7500_debt_rows_are_exact_sidecar_bounded_client_projection(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path,
        [
            _row(f"H-{i}", f"INV-{i + 8000}", signal="ident: settle")
            for i in range(1, 7502)
        ],
        shard_size=15,
        activate_first_shard=False,
    )
    CTA.mark_chain_tail_budget_stop(tmp_path, "CHAIN_TAIL_SHARD_BUDGET")
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    projection = (tmp_path / CTA.PROJECTION_NAME).read_text(encoding="utf-8")
    assert len(ledger["pairs"]) == 7501
    assert len(projection.encode("utf-8")) <= CTA.DEFAULT_PROJECTION_BYTE_CEILING
    assert projection.count("| CP-") <= CTA.DEFAULT_PROJECTION_SAMPLE_ROWS
    assert CTA.validate_chain_tail_authority(tmp_path) == []
    from plamen_mechanical import _build_human_review_appendix

    appendix = _build_human_review_appendix(tmp_path)
    assert len(appendix.encode("utf-8")) < 20_000
    assert ledger["ledger_sha256"] in appendix
    assert appendix.count("source-ref-") <= CTA.DEFAULT_PROJECTION_SAMPLE_ROWS * 2


@pytest.mark.parametrize("tamper", ["receipt-denominator", "ledger", "missing-ledger"])
def test_summary_or_sidecar_mismatch_fails_closed(tmp_path: Path, tamper: str):
    CTA.initialize_chain_tail(tmp_path, [])
    if tamper == "receipt-denominator":
        payload = _load(tmp_path / CTA.RECEIPT_NAME)
        payload["denominator"] = 99
        (tmp_path / CTA.RECEIPT_NAME).write_text(json.dumps(payload), encoding="utf-8")
    elif tamper == "ledger":
        payload = _load(tmp_path / CTA.LEDGER_NAME)
        payload["cursor"] = 1
        (tmp_path / CTA.LEDGER_NAME).write_text(json.dumps(payload), encoding="utf-8")
    else:
        (tmp_path / CTA.LEDGER_NAME).unlink()
    assert CTA.validate_chain_tail_authority(tmp_path)


def test_new_composition_requires_chain_identity_and_routes_as_unproven_candidate(tmp_path: Path):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    shard = CTA.current_chain_tail_shard(tmp_path)
    row = {
        **shard["rows"][0],
        "disposition": "COMPOSED",
        "evidence": "CH-77 links the postcondition to the dependent precondition.",
    }
    (tmp_path / "chain_iteration2.md").write_text(
        "## Chain Hypothesis CH-77 — Combined lifecycle failure\n\n"
        "**Constituent Findings**: H-1, M-1\n\n"
        "**Combined Impact**: Requires independent verification.\n\n"
        + _output([row]),
        encoding="utf-8",
    )
    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    candidates = _load(tmp_path / CTA.COMPOSITION_CANDIDATES_NAME)
    assert receipt["status"] == "COMPLETE"
    assert candidates["candidates"][0]["chain_id"] == "CH-77"
    assert candidates["candidates"][0]["proof_authority"] == "NONE"
    assert candidates["candidates"][0]["route"] == "ORDINARY_VERIFICATION"


def test_divergent_duplicate_chain_identity_in_one_shard_is_durable_debt(
    tmp_path: Path,
):
    """One shard-local CH label may not ambiguously bind two different claims."""
    CTA.initialize_chain_tail(
        tmp_path, [_row("H-1", "M-1"), _row("H-2", "M-2")]
    )
    shard = CTA.current_chain_tail_shard(tmp_path)
    composed_rows = [
        {
            **row,
            "disposition": "COMPOSED",
            "evidence": "CH-9 links this exact pair into a composed mechanism.",
        }
        for row in shard["rows"]
    ]
    (tmp_path / "chain_iteration2.md").write_text(
        "## Chain Hypothesis CH-9 — first claim\n\n"
        "**Constituent Findings**: H-1, M-1\n\n"
        "**Combined Impact**: First, materially distinct composition.\n\n"
        "## Chain Hypothesis CH-9 — second claim\n\n"
        "**Constituent Findings**: H-2, M-2\n\n"
        "**Combined Impact**: Second, divergent composition.\n\n"
        + _output(composed_rows),
        encoding="utf-8",
    )

    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    candidates = _load(tmp_path / CTA.COMPOSITION_CANDIDATES_NAME)

    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    assert receipt["unresolved_pairs"] == 2
    assert {row["reason"] for row in ledger["pairs"]} == {
        "DIVERGENT_DUPLICATE_CHAIN_IDENTITY"
    }
    assert all(not row["chain_id"] for row in ledger["pairs"])
    assert candidates["candidates"] == []
    assert CTA.validate_chain_tail_authority(tmp_path, require_complete=True)

    finalized = CTA.finalize_chain_tail_aggregate_output(tmp_path)
    aggregate = (tmp_path / "chain_iteration2.md").read_text(encoding="utf-8")
    archive = (
        tmp_path / CTA.SHARD_ARCHIVE_DIR / "shard_0000.md"
    ).read_text(encoding="utf-8")
    assert finalized["status"] == "DEGRADED_UNRESOLVED"
    assert "first claim" not in aggregate and "second claim" not in aggregate
    assert "first claim" in archive and "second claim" in archive
    assert CTA.validate_chain_tail_authority(tmp_path) == []


def test_validator_rejects_legacy_terminal_rows_bound_to_divergent_duplicate_chain(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(
        tmp_path, [_row("H-1", "M-1"), _row("H-2", "M-2")]
    )
    shard = CTA.current_chain_tail_shard(tmp_path)
    composed_rows = [
        {**row, "disposition": "COMPOSED", "evidence": "CH-9 composed path."}
        for row in shard["rows"]
    ]
    (tmp_path / "chain_iteration2.md").write_text(
        "## Chain Hypothesis CH-9 — first claim\n\nFirst distinct claim.\n\n"
        "## Chain Hypothesis CH-9 — second claim\n\nSecond divergent claim.\n\n"
        + _output(composed_rows),
        encoding="utf-8",
    )
    CTA.reconcile_chain_tail_output(tmp_path)

    # Recreate the pre-hardening terminal shape with internally valid digests.
    manifest, ledger = CTA._load_manifest_ledger(tmp_path)
    for row in ledger["pairs"]:
        row.update({
            "disposition": "COMPOSED",
            "reason": "",
            "evidence": "CH-9 composed path.",
            "chain_id": "CH-9",
        })
    CTA._write_ledger(tmp_path / CTA.LEDGER_NAME, ledger)
    manifest, ledger = CTA._load_manifest_ledger(tmp_path)
    CTA._write_composition_candidates(tmp_path, manifest, ledger)
    CTA._write_receipt_and_projection(tmp_path, manifest, ledger)

    issues = CTA.validate_chain_tail_authority(tmp_path)

    assert any("divergent duplicate chain identity" in issue for issue in issues)


def test_byte_identical_duplicate_chain_section_is_deduplicated_not_degraded(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    shard = CTA.current_chain_tail_shard(tmp_path)
    row = {
        **shard["rows"][0],
        "disposition": "COMPOSED",
        "evidence": "CH-9 composed path.",
    }
    section = "## Chain Hypothesis CH-9 — same claim\n\nExact same body.\n\n"
    (tmp_path / "chain_iteration2.md").write_text(
        section + section + _output([row]), encoding="utf-8"
    )

    assert CTA.reconcile_chain_tail_output(tmp_path)["status"] == "COMPLETE"
    receipt = CTA.finalize_chain_tail_aggregate_output(tmp_path)
    aggregate = (tmp_path / "chain_iteration2.md").read_text(encoding="utf-8")

    assert receipt["status"] == "COMPLETE"
    assert aggregate.count("## Chain Hypothesis CH-9") == 1
    assert CTA.validate_chain_tail_authority(tmp_path, require_complete=True) == []


def _rewrite_receipt_with_valid_digest(tmp_path: Path, **changes: object) -> None:
    receipt = _load(tmp_path / CTA.RECEIPT_NAME)
    receipt.update(changes)
    receipt["authority_digest"] = CTA._digest(receipt, "authority_digest")
    (tmp_path / CTA.RECEIPT_NAME).write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    (tmp_path / CTA.PROJECTION_NAME).write_text(
        CTA._render_projection(receipt, ledger), encoding="utf-8"
    )


def test_redigested_false_complete_is_rejected_from_active_manifest_ledger_state(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    _rewrite_receipt_with_valid_digest(tmp_path, status="COMPLETE")

    issues = CTA.validate_chain_tail_authority(tmp_path)

    assert any("semantic status" in issue for issue in issues)


def test_receipt_active_shard_index_is_recomputed_from_ledger(tmp_path: Path):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    _rewrite_receipt_with_valid_digest(tmp_path, active_shard_index=999)

    issues = CTA.validate_chain_tail_authority(tmp_path)

    assert any("active shard" in issue for issue in issues)


def test_active_shard_cursor_cannot_be_redigested_into_consistent_receipt(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(
        tmp_path,
        [_row("H-1", "M-1"), _row("H-2", "M-2")],
        shard_size=1,
    )
    manifest, ledger = CTA._load_manifest_ledger(tmp_path)
    ledger["cursor"] = manifest["denominator"]
    CTA._write_ledger(tmp_path / CTA.LEDGER_NAME, ledger)
    manifest, ledger = CTA._load_manifest_ledger(tmp_path)
    CTA._write_receipt_and_projection(tmp_path, manifest, ledger)

    issues = CTA.validate_chain_tail_authority(tmp_path)

    assert any("cursor" in issue for issue in issues)


def test_redigested_false_complete_cannot_erase_budget_stop(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path,
        [_row("H-1", "M-1"), _row("H-2", "M-2")],
        shard_size=1,
        activate_first_shard=False,
    )
    CTA.mark_chain_tail_budget_stop(tmp_path, "CHAIN_TAIL_SHARD_BUDGET")
    _rewrite_receipt_with_valid_digest(tmp_path, status="COMPLETE")

    issues = CTA.validate_chain_tail_authority(tmp_path)

    assert any("semantic status" in issue for issue in issues)


def test_no_real_signal_pairs_is_clean_noop(tmp_path: Path):
    receipt = CTA.initialize_chain_tail(tmp_path, [])
    assert receipt["status"] == "COMPLETE"
    assert receipt["denominator"] == 0
    assert CTA.validate_chain_tail_authority(tmp_path) == []


def _primary_coverage(rows: list[tuple[str, str, str, str]]) -> str:
    lines = [
        "# Composition Coverage",
        "",
        "| Finding A | Finding B | Explored? | Result | Notes |",
        "|---|---|---|---|---|",
    ]
    lines.extend(
        f"| {a} | {b} | YES | {result} | {notes} |"
        for a, b, result, notes in rows
    )
    return "\n".join(lines) + "\n"


def test_primary_bounded_coverage_is_consumed_before_tail_and_is_idempotent(
    tmp_path: Path,
):
    rows = [
        _row("H-1", "M-1", initial_route="CHAIN_AGENT2"),
        _row("H-2", "M-2", initial_route="CHAIN_AGENT2"),
        _row("H-3", "M-3", initial_route="CHAIN_ITER2"),
        _row("H-4", "M-4", initial_route="CHAIN_ITER2"),
    ]
    CTA.initialize_chain_tail(
        tmp_path, rows, shard_size=2, activate_first_shard=False
    )
    (tmp_path / "composition_coverage.md").write_text(
        _primary_coverage([
            ("H-1", "M-1", "No composition", "Compared exact state lifecycle."),
            ("H-2", "M-2", "Independent", "No producer/consumer handoff."),
        ]),
        encoding="utf-8",
    )
    (tmp_path / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n", encoding="utf-8"
    )

    first = CTA.ingest_primary_chain_coverage(tmp_path)
    shard = CTA.current_chain_tail_shard(tmp_path)
    before = (tmp_path / CTA.LEDGER_NAME).read_bytes()
    second = CTA.ingest_primary_chain_coverage(tmp_path)

    assert first["status"] == "PENDING"
    assert second == first
    assert (tmp_path / CTA.LEDGER_NAME).read_bytes() == before
    assert [(row["a"], row["b"]) for row in shard["rows"]] == [
        ("H-3", "M-3"), ("H-4", "M-4")
    ]
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    assert [row["disposition"] for row in ledger["pairs"][:2]] == [
        "REJECTED", "REJECTED"
    ]


def test_registry_owned_nested_ids_survive_manifest_and_primary_reconciliation(
    tmp_path: Path,
):
    """P0-T's exact denominator must use the shared producer-ID grammar."""
    a = "DA-STATE_EDGE-101"
    b = "DA-STATE_EDGE-102"
    CTA.initialize_chain_tail(
        tmp_path,
        [_row(a, b, initial_route="CHAIN_AGENT2")],
        activate_first_shard=False,
    )
    (tmp_path / "composition_coverage.md").write_text(
        _primary_coverage([
            (a, b, "Independent", "Compared the exact state-transition loci."),
        ]),
        encoding="utf-8",
    )
    (tmp_path / "chain_hypotheses.md").write_text("# Chains\n", encoding="utf-8")

    receipt = CTA.ingest_primary_chain_coverage(tmp_path)
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    assert receipt["status"] == "COMPLETE"
    assert receipt["mechanical_consumed_pairs"] == 1
    assert [(row["a"], row["b"]) for row in ledger["pairs"]] == [(a, b)]


def test_missing_primary_row_remains_in_exact_unresolved_shard(tmp_path: Path):
    rows = [
        _row("H-1", "M-1", initial_route="CHAIN_AGENT2"),
        _row("H-2", "M-2", initial_route="CHAIN_AGENT2"),
        _row("H-3", "M-3", initial_route="CHAIN_ITER2"),
    ]
    CTA.initialize_chain_tail(
        tmp_path, rows, shard_size=2, activate_first_shard=False
    )
    (tmp_path / "composition_coverage.md").write_text(
        _primary_coverage([
            ("H-1", "M-1", "No composition", "Exact lifecycle compared."),
        ]),
        encoding="utf-8",
    )
    (tmp_path / "chain_hypotheses.md").write_text("# Chains\n", encoding="utf-8")

    receipt = CTA.ingest_primary_chain_coverage(tmp_path)
    shard = CTA.current_chain_tail_shard(tmp_path)

    assert receipt["status"] == "PENDING"
    assert [(row["a"], row["b"]) for row in shard["rows"]] == [
        ("H-2", "M-2"), ("H-3", "M-3")
    ]
    ledger = _load(tmp_path / CTA.LEDGER_NAME)
    assert ledger["pairs"][1]["reason"] == "PRIMARY_COVERAGE_MISSING_ROW"


def test_cursor_advances_over_preterminal_gap_before_next_active_shard(
    tmp_path: Path,
):
    rows = [
        _row("H-1", "M-1", initial_route="CHAIN_ITER2"),
        _row("H-2", "M-2", initial_route="CHAIN_AGENT2"),
        _row("H-3", "M-3", initial_route="CHAIN_ITER2"),
    ]
    CTA.initialize_chain_tail(
        tmp_path, rows, shard_size=1, activate_first_shard=False
    )
    (tmp_path / "composition_coverage.md").write_text(
        _primary_coverage([
            ("H-2", "M-2", "Independent", "Exact lifecycle compared."),
        ]),
        encoding="utf-8",
    )
    (tmp_path / "chain_hypotheses.md").write_text("# Chains\n", encoding="utf-8")
    CTA.ingest_primary_chain_coverage(tmp_path)
    first = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(
        _output(first["rows"]), encoding="utf-8"
    )
    CTA.reconcile_chain_tail_output(tmp_path)

    second = CTA.prepare_next_chain_tail_shard(tmp_path)
    ledger = _load(tmp_path / CTA.LEDGER_NAME)

    assert [(row["a"], row["b"]) for row in second["rows"]] == [("H-3", "M-3")]
    assert ledger["cursor"] == 2
    assert CTA.validate_chain_tail_authority(tmp_path) == []


def test_primary_composition_routes_unproven_only_when_chain_section_exists(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(
        tmp_path,
        [_row("H-1", "M-1", initial_route="CHAIN_AGENT2")],
        activate_first_shard=False,
    )
    (tmp_path / "composition_coverage.md").write_text(
        _primary_coverage([
            ("H-1", "M-1", "COMPOSED CH-7", "Postcondition reaches precondition."),
        ]),
        encoding="utf-8",
    )
    (tmp_path / "chain_hypotheses.md").write_text(
        "## Chain Hypothesis CH-7 — lifecycle composition\n\n"
        "**Constituent Findings**: H-1, M-1\n",
        encoding="utf-8",
    )

    receipt = CTA.ingest_primary_chain_coverage(tmp_path)
    candidates = _load(tmp_path / CTA.COMPOSITION_CANDIDATES_NAME)

    assert receipt["status"] == "COMPLETE"
    assert candidates["candidates"][0]["chain_id"] == "CH-7"
    assert candidates["candidates"][0]["proof_authority"] == "NONE"
    assert candidates["candidates"][0]["route"] == "ORDINARY_VERIFICATION"
    assert CTA.validate_chain_tail_authority(tmp_path, require_complete=True) == []


def test_worker_15_of_15_mechanical_zero_surfaces_mismatch(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path, [_row(f"H-{i}", f"M-{i}") for i in range(1, 16)], shard_size=15
    )
    (tmp_path / "chain_iteration2.md").write_text(
        "# Chain Iteration 2\n\n15 / 15 covered\n\n"
        "## 2. Tail Pair Dispositions\n\n"
        "| Left | Right | Opinion | Why |\n|---|---|---|---|\n"
        "| H-1 | M-1 | safe | prose only |\n",
        encoding="utf-8",
    )
    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    assert receipt["worker_claimed_pairs"] == 15
    assert receipt["mechanical_consumed_pairs"] == 0
    assert "WORKER_MECHANICAL_COUNT_MISMATCH" in receipt["issues"]
    projection = (tmp_path / CTA.PROJECTION_NAME).read_text(encoding="utf-8")
    assert "worker/mechanical mismatch" in projection.lower()


def test_terminal_rows_with_worker_count_mismatch_are_not_called_complete(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(tmp_path, [_row("H-1", "M-1")])
    shard = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(
        "0 / 1 covered\n\n" + _output(shard["rows"]), encoding="utf-8"
    )
    receipt = CTA.reconcile_chain_tail_output(tmp_path)
    assert receipt["terminal_pairs"] == 1
    assert receipt["worker_mechanical_mismatch"] is True
    assert receipt["status"] == "DEGRADED_ASSURANCE_MISMATCH"
    assert CTA.validate_chain_tail_authority(tmp_path, require_complete=True)


def test_projection_renderer_parity_detects_digest_edit(tmp_path: Path):
    CTA.initialize_chain_tail(tmp_path, [])
    path = tmp_path / CTA.PROJECTION_NAME
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "**Exact denominator**: 0", "**Exact denominator**: 1"
        ),
        encoding="utf-8",
    )
    assert any("projection" in issue.lower() for issue in CTA.validate_chain_tail_authority(tmp_path))


def test_shard_loop_closes_overflow_and_normalizes_cross_shard_chain_ids(tmp_path: Path):
    CTA.initialize_chain_tail(
        tmp_path, [_row(f"H-{i}", f"M-{i}") for i in range(1, 6)], shard_size=2
    )
    first = CTA.current_chain_tail_shard(tmp_path)
    first_rows = [
        {**first["rows"][0], "disposition": "COMPOSED", "evidence": "CH-1 composed path."},
        {**first["rows"][1], "disposition": "REJECTED", "evidence": "Independent state at L20."},
    ]
    (tmp_path / "chain_iteration2.md").write_text(
        "## Chain Hypothesis CH-1 — First composition\n\n"
        "**Constituent Findings**: H-1, M-1\n\n"
        + _output(first_rows),
        encoding="utf-8",
    )

    calls: list[list[str]] = []

    def execute(shard: dict) -> int:
        calls.append(list(shard["pair_ids"]))
        rows = []
        prefix = ""
        for index, row in enumerate(shard["rows"]):
            if shard["shard_index"] == 1 and index == 0:
                rows.append({**row, "disposition": "COMPOSED", "evidence": "CH-1 second path."})
                prefix = (
                    "## Chain Hypothesis CH-1 — Second composition\n\n"
                    "**Constituent Findings**: H-3, M-3\n\n"
                )
            else:
                rows.append({**row, "disposition": "EXPLORED", "evidence": "Exact loci compared."})
        (tmp_path / "chain_iteration2.md").write_text(prefix + _output(rows), encoding="utf-8")
        return 0

    receipt = CTA.run_chain_tail_shard_loop(
        tmp_path, execute, max_shards_per_run=3
    )
    assert receipt["status"] == "COMPLETE"
    assert len(calls) == 2
    aggregate = (tmp_path / "chain_iteration2.md").read_text(encoding="utf-8")
    assert "CH-1 — First composition" in aggregate
    assert "CH-2 — Second composition" in aggregate
    assert CTA.validate_chain_tail_authority(tmp_path, require_complete=True) == []


def test_shard_loop_honest_budget_stop_and_resume_continues_same_manifest(
    tmp_path: Path,
    monkeypatch,
):
    CTA.initialize_chain_tail(
        tmp_path, [_row(f"H-{i}", f"M-{i}") for i in range(1, 7)], shard_size=2
    )
    first = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(_output(first["rows"]), encoding="utf-8")
    manifest_digest = _load(tmp_path / CTA.MANIFEST_NAME)["manifest_sha256"]
    receipt = CTA.run_chain_tail_shard_loop(
        tmp_path, lambda _shard: pytest.fail("budget should stop before next launch"),
        max_shards_per_run=1,
    )
    assert receipt["status"] == "BUDGET_STOP"
    assert receipt["unresolved_pairs"] == 4
    journal_path = (
        tmp_path / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    assert journal_path.is_file()
    journal = _load(journal_path)
    assert journal["schema_version"] == (
        "plamen.chain_tail.scheduler_journal.v1"
    )
    assert journal["authority"] == "NONE"
    journal_bytes = journal_path.read_bytes()
    journal_stat = journal_path.lstat()
    journal_identity = (
        journal_stat.st_dev,
        journal_stat.st_ino,
        journal_stat.st_nlink,
    )
    assert journal_stat.st_nlink == 1
    frozen_root_projection = {
        name: (tmp_path / name).read_bytes()
        for name in (
            CTA.COMPOSITION_CANDIDATES_NAME,
            CTA.PROJECTION_NAME,
        )
    }
    original_plan = CTA.plan_rearm_unresolved_chain_tail
    captured: dict[str, dict] = {}

    def capture_plan(root: Path) -> dict:
        plan = original_plan(root)
        if "planned_rearm" not in captured:
            captured["planned_rearm"] = copy.deepcopy(plan)
        return plan

    monkeypatch.setattr(
        CTA, "plan_rearm_unresolved_chain_tail", capture_plan
    )
    generation = CTA.rearm_unresolved_chain_tail(tmp_path)
    planned_rearm = captured["planned_rearm"]
    assert generation["status"] == "CONTINUE"
    assert generation == planned_rearm["receipt"]
    assert CTA.validate_rearm_unresolved_chain_tail_generation(
        tmp_path, planned_rearm
    ) == []
    journal_stat_after = journal_path.lstat()
    assert journal_path.read_bytes() == journal_bytes
    assert (
        journal_stat_after.st_dev,
        journal_stat_after.st_ino,
        journal_stat_after.st_nlink,
    ) == journal_identity
    assert journal_stat_after.st_nlink == 1
    retry = CTA.prepare_next_chain_tail_shard(tmp_path)
    assert retry["pair_ids"]
    assert _load(tmp_path / CTA.MANIFEST_NAME)["manifest_sha256"] == manifest_digest
    (tmp_path / "chain_iteration2.md").write_text(
        _output(retry["rows"]), encoding="utf-8"
    )

    def execute(shard: dict) -> int:
        (tmp_path / "chain_iteration2.md").write_text(
            _output(shard["rows"]), encoding="utf-8"
        )
        return 0

    completed = CTA.run_chain_tail_shard_loop(
        tmp_path, execute, max_shards_per_run=4
    )
    assert completed["status"] == "COMPLETE"
    assert completed["unresolved_pairs"] == 0
    assert {
        name: (tmp_path / name).read_bytes()
        for name in frozen_root_projection
    } == frozen_root_projection
    assert CTA.validate_chain_tail_authority(tmp_path, require_complete=True) == []


def test_direct_shard_loop_rejects_malformed_scheduler_journal_before_mutation(
    tmp_path: Path,
):
    CTA.initialize_chain_tail(
        tmp_path, [_row("H-1", "M-1")], shard_size=1
    )
    shard = CTA.current_chain_tail_shard(tmp_path)
    (tmp_path / "chain_iteration2.md").write_text(
        _output(shard["rows"]), encoding="utf-8"
    )
    journal_path = (
        tmp_path / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    journal_path.write_text(
        json.dumps(
            {
                "schema_version": (
                    "plamen.chain_tail.scheduler_journal.tampered"
                ),
                "authority": "NONE",
                "sequence": 0,
                "started_shards": {},
                "events": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    frozen = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    launched = {"count": 0}

    def must_not_launch(_shard: dict) -> int:
        launched["count"] += 1
        return 0

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="chain-tail scheduler journal schema mismatch",
    ):
        CTA.run_chain_tail_shard_loop(
            tmp_path,
            must_not_launch,
            max_shards_per_run=1,
        )

    assert launched["count"] == 0
    assert {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    } == frozen


_REARM_VALIDATOR_TAMPERS = (
    "wrong_pass",
    "wrong_next_shard",
    "detached_receipt",
    "missing_postimage",
    "extra_postimage",
    *(
        f"postimage_bytes:{relative}"
        for relative in CTA.MUTABLE_CONTROL_PATHS
    ),
    "live_output_bytes",
)


def test_atomic_json_fresh_write_is_exact_lf_canonical(
    tmp_path: Path,
):
    payload = {
        "schema_version": "fixture.v1",
        "authority": "NONE",
        "nested": {"value": 1},
    }
    path = tmp_path / "fresh.json"

    CTA._atomic_json(path, payload)

    assert path.read_bytes() == CTA._render_json_postimage(payload)
    assert b"\r" not in path.read_bytes()


@pytest.mark.parametrize("newline_form", ["lf", "crlf"])
def test_rearm_validator_preserves_canonical_journal_newline_forms(
    tmp_path: Path,
    newline_form: str,
):
    _budget_stop_predecessor(tmp_path)
    journal_path = (
        tmp_path / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    payload = _load(journal_path)
    journal_bytes = CTA._render_json_postimage(payload)
    if newline_form == "crlf":
        journal_bytes = journal_bytes.replace(b"\n", b"\r\n")
    journal_path.write_bytes(journal_bytes)
    journal_stat = journal_path.lstat()
    journal_identity = (
        journal_stat.st_dev,
        journal_stat.st_ino,
        journal_stat.st_nlink,
    )
    assert journal_identity[2] == 1

    with CTA._scheduler_lock(tmp_path):
        plan = CTA.plan_rearm_unresolved_chain_tail(tmp_path)
        assert plan["postimages"][
            f"{CTA.CONTROL_DIR}/{CTA.CONTROL_JOURNAL_NAME}"
        ] == journal_bytes
        _materialize_fixture_rearm_postimages(tmp_path, plan)

    assert CTA.validate_rearm_unresolved_chain_tail_generation(
        tmp_path, plan
    ) == []
    journal_stat_after = journal_path.lstat()
    assert journal_path.read_bytes() == journal_bytes
    assert (
        journal_stat_after.st_dev,
        journal_stat_after.st_ino,
        journal_stat_after.st_nlink,
    ) == journal_identity


@pytest.mark.parametrize(
    "encoding",
    ["compact", "cr_only", "trailing_space"],
)
def test_rearm_validator_rejects_paired_noncanonical_journal_without_mutation(
    tmp_path: Path,
    encoding: str,
):
    _budget_stop_predecessor(tmp_path)
    journal_path = (
        tmp_path / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    payload = _load(journal_path)
    canonical = CTA._render_json_postimage(payload)
    if encoding == "compact":
        journal_bytes = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
    elif encoding == "cr_only":
        journal_bytes = canonical.replace(b"\n", b"\r")
    elif encoding == "trailing_space":
        journal_bytes = canonical + b" "
    else:
        raise AssertionError(f"unknown journal encoding: {encoding}")
    journal_path.write_bytes(journal_bytes)

    with CTA._scheduler_lock(tmp_path):
        plan = CTA.plan_rearm_unresolved_chain_tail(tmp_path)
        _materialize_fixture_rearm_postimages(tmp_path, plan)
    frozen = _fixture_file_bytes(tmp_path)

    issues = CTA.validate_rearm_unresolved_chain_tail_generation(
        tmp_path, plan
    )

    assert issues
    assert _fixture_file_bytes(tmp_path) == frozen


def test_authority_validator_selects_control_candidate_without_mutation(
    tmp_path: Path,
):
    _complete_rearmed_control_generation(tmp_path)
    candidate_path = (
        tmp_path
        / CTA.CONTROL_DIR
        / CTA.COMPOSITION_CANDIDATES_NAME
    )
    candidates = _load(candidate_path)
    candidates["candidate_digest"] = "0" * 64
    candidate_path.write_bytes(CTA._render_json_postimage(candidates))
    frozen = _fixture_file_bytes(tmp_path)

    issues = CTA.validate_chain_tail_authority(
        tmp_path, require_complete=True
    )

    assert issues == ["chain composition candidate digest mismatch"]
    assert _fixture_file_bytes(tmp_path) == frozen


def test_authority_validator_selects_control_projection_without_mutation(
    tmp_path: Path,
):
    _complete_rearmed_control_generation(tmp_path)
    projection_path = (
        tmp_path / CTA.CONTROL_DIR / CTA.PROJECTION_NAME
    )
    projection_path.write_bytes(b"\xff")
    frozen = _fixture_file_bytes(tmp_path)

    issues = CTA.validate_chain_tail_authority(
        tmp_path, require_complete=True
    )

    assert len(issues) == 1
    assert issues[0].startswith(
        "chain-tail client projection invalid: UnicodeDecodeError:"
    )
    assert _fixture_file_bytes(tmp_path) == frozen


@pytest.mark.parametrize("mutation", _REARM_VALIDATOR_TAMPERS)
def test_rearm_validator_rejects_tamper_without_mutation(
    tmp_path: Path,
    mutation: str,
):
    plan = _budget_stop_rearm_poststate(tmp_path)
    candidate = copy.deepcopy(plan)
    live_restore: tuple[Path, bytes] | None = None
    if mutation == "wrong_pass":
        candidate["pass_index"] += 1
    elif mutation == "wrong_next_shard":
        candidate["next_shard_index"] += 1
    elif mutation == "detached_receipt":
        receipt = dict(candidate["receipt"])
        receipt["pass_index"] += 1
        receipt["authority_digest"] = CTA._digest(
            receipt, "authority_digest"
        )
        candidate["receipt"] = receipt
    elif mutation == "missing_postimage":
        candidate["postimages"].pop(
            CTA.MUTABLE_CONTROL_PATHS[0]
        )
    elif mutation == "extra_postimage":
        candidate["postimages"][
            "_chain_tail_control/unregistered.json"
        ] = b"{}\n"
    elif mutation.startswith("postimage_bytes:"):
        relative = mutation.split(":", 1)[1]
        candidate["postimages"][relative] += b" "
    elif mutation == "live_output_bytes":
        path = tmp_path / CTA.MUTABLE_CONTROL_PATHS[0]
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        live_restore = (path, original)
    else:
        raise AssertionError(f"unknown rearm validator mutation: {mutation}")
    frozen = _fixture_file_bytes(tmp_path)

    issues = CTA.validate_rearm_unresolved_chain_tail_generation(
        tmp_path, candidate
    )

    assert issues
    assert _fixture_file_bytes(tmp_path) == frozen
    if live_restore is not None:
        live_restore[0].write_bytes(live_restore[1])
