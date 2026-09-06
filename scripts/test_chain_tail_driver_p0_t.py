from __future__ import annotations

import json
from pathlib import Path

import chain_tail_authority as CTA
import plamen_driver as D
import plamen_parsers as P
import plamen_validators as V
from plamen_types import Phase


def _row(index: int) -> dict:
    return {
        "a": f"H-{index}",
        "b": f"M-{index}",
        "a_sev": "High",
        "b_sev": "Medium",
        "signal": "state-graph: Vault.balance",
        "graph_backed": True,
        "score": 8.0,
    }


def _write_output(path: Path, rows: list[dict]) -> None:
    lines = [
        "# Chain Iteration 2",
        "",
        "## Tail Pair Dispositions",
        "",
        "| Pair ID | Finding A | Finding B | Disposition | Evidence |",
        "|---|---|---|---|---|",
    ]
    lines.extend(
        f"| {row['pair_id']} | {row['a']} | {row['b']} | EXPLORED | exact source loci compared |"
        for row in rows
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _phase() -> Phase:
    return Phase(
        "chain_iter2",
        ["Phase 4c Iteration 2: Chain Composition Re-evaluation"],
        ["chain_iteration2.md"],
        base_timeout_s=30,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )


def _config(tmp_path: Path, sp: Path, *, max_shards: int = 8) -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "scratchpad": str(sp),
        "_run_id": "run-p0-t-fixture",
        "chain_tail_max_shards_per_run": max_shards,
        # These fixtures intentionally exercise the pre-isolation direct
        # library adapter. Production never sets this compatibility grant.
        "_allow_legacy_chain_tail_adapter": True,
    }


def test_driver_launches_every_bounded_continuation_then_validator_is_clean(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    CTA.initialize_chain_tail(sp, [_row(i) for i in range(1, 6)], shard_size=2)
    _write_output(sp / "chain_iteration2.md", CTA.current_chain_tail_shard(sp)["rows"])
    launches: list[int] = []

    def fake_run_phase(_phase, config, attempt):
        shard = CTA.current_chain_tail_shard(sp)
        launches.append(shard["shard_index"])
        assert config["_chain_tail_manifest_sha256"] == shard["manifest_sha256"]
        assert attempt == 1001 + shard["shard_index"]
        _write_output(sp / "chain_iteration2.md", shard["rows"])
        return 0

    monkeypatch.setattr(D, "run_phase", fake_run_phase)
    receipt = D._run_chain_iter2_bounded_continuations(
        _phase(), sp, _config(tmp_path, sp)
    )
    assert launches == [1, 2]
    assert receipt["status"] == "COMPLETE"
    assert V._validate_chain_iter2(sp, "thorough") == []
    assert not (sp / "chain_iter2.degraded").exists()
    assert D._resume_phase_contract_issues(
        sp, str(tmp_path), _phase(), "thorough", "evm", "sc", "claude"
    ) == []


def test_driver_budget_stop_is_durable_debt_and_resume_contract_rejects_clean(
    tmp_path: Path, monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    CTA.initialize_chain_tail(sp, [_row(i) for i in range(1, 6)], shard_size=2)
    _write_output(sp / "chain_iteration2.md", CTA.current_chain_tail_shard(sp)["rows"])
    monkeypatch.setattr(
        D,
        "run_phase",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("budget must stop before a continuation launch")
        ),
    )
    receipt = D._run_chain_iter2_bounded_continuations(
        _phase(), sp, _config(tmp_path, sp, max_shards=1)
    )
    assert receipt["status"] == "BUDGET_STOP"
    assert receipt["unresolved_pairs"] == 3
    assert V._validate_chain_iter2(sp, "thorough") == []
    assert "BUDGET_STOP" in (sp / "chain_iter2.degraded").read_text(encoding="utf-8")
    assert D._resume_phase_contract_issues(
        sp, str(tmp_path), _phase(), "thorough", "evm", "sc", "claude"
    )


def test_legacy_tail_cannot_retroactively_certify_shard_transcript(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    CTA.initialize_chain_tail(sp, [_row(1)], shard_size=1)
    _write_output(sp / "chain_iteration2.md", CTA.current_chain_tail_shard(sp)["rows"])
    CTA.run_chain_tail_shard_loop(sp, lambda _shard: 0, max_shards_per_run=1)
    issues = D._record_chain_tail_authority_phase_io(
        sp, _config(tmp_path, sp), _phase()
    )
    assert issues
    assert any("roster denominator mismatch" in issue for issue in issues)
    state_path = sp / "_artifact_state.json"
    state = (
        json.loads(state_path.read_text(encoding="utf-8"))
        if state_path.is_file()
        else {"work_units": {}}
    )
    key = (
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0000.s0001"
    )
    assert state["work_units"].get(key, {}).get("execution_state") != (
        "OUTPUT_COMMITTED"
    )


def test_legacy_primary_coverage_cannot_mint_missing_terminal_receipt(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    CTA.initialize_chain_tail(
        sp,
        [{**_row(1), "initial_route": "CHAIN_AGENT2"}],
        activate_first_shard=False,
    )
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|---|---|---|---|---|\n"
        "| H-1 | M-1 | YES | No composition | Exact lifecycle compared. |\n",
        encoding="utf-8",
    )
    (sp / "chain_hypotheses.md").write_text("# Chain Hypotheses\n", encoding="utf-8")
    assert CTA.ingest_primary_chain_coverage(sp)["status"] == "COMPLETE"
    CTA.finalize_chain_tail_aggregate_output(sp)

    issues = D._record_chain_tail_authority_phase_io(
        sp, _config(tmp_path, sp), _phase()
    )
    assert any("committed terminal receipt" in issue for issue in issues)
    state_path = sp / "_artifact_state.json"
    state = (
        json.loads(state_path.read_text(encoding="utf-8"))
        if state_path.is_file()
        else {"work_units": {}}
    )
    key = (
        "sc/thorough/evm/claude/chain_iter2/"
        "tail_reconcile.p0000.s0000"
    )
    assert state["work_units"].get(key, {}).get("execution_state") != (
        "OUTPUT_COMMITTED"
    )


def test_v2_pre_spawn_skip_uses_hash_bound_completion_not_static_packet(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    CTA.initialize_chain_tail(sp, [_row(1)], shard_size=1)
    assert P._chain_iter2_has_no_unexplored_pairs(sp) is False


def test_legacy_zero_rows_cannot_replace_missing_typed_chain_tail_authority(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|---|---|---|---|---|\n",
        encoding="utf-8",
    )

    assert P._chain_iter2_has_no_unexplored_pairs(sp) is False


def test_malformed_typed_manifest_or_receipt_cannot_clean_noop_from_legacy_rows(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Explored? | Result | Notes |\n"
        "|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    (sp / CTA.MANIFEST_NAME).write_text("{malformed", encoding="utf-8")
    assert P._chain_iter2_has_no_unexplored_pairs(sp) is False

    CTA.initialize_chain_tail(sp, [], shard_size=1)
    root_receipt = sp / CTA.RECEIPT_NAME
    root_receipt.write_text("{malformed", encoding="utf-8")
    frozen_root_receipt = root_receipt.read_bytes()
    assert P._chain_iter2_has_no_unexplored_pairs(sp) is False
    _write_output(sp / "chain_iteration2.md", CTA.current_chain_tail_shard(sp)["rows"])
    CTA.run_chain_tail_shard_loop(sp, lambda _shard: 0, max_shards_per_run=1)
    assert P._chain_iter2_has_no_unexplored_pairs(sp) is True
    assert root_receipt.read_bytes() == frozen_root_receipt

    selected = CTA._read_progress_receipt(sp)
    assert selected["status"] == "COMPLETE"
    control_receipt = sp / CTA.CONTROL_DIR / CTA.RECEIPT_NAME
    receipt = json.loads(control_receipt.read_text(encoding="utf-8"))
    receipt["status"] = "BUDGET_STOP"
    receipt["authority_digest"] = CTA._digest(receipt, "authority_digest")
    control_receipt.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    assert P._chain_iter2_has_no_unexplored_pairs(sp) is False
    assert root_receipt.read_bytes() == frozen_root_receipt


def test_isolation_is_sticky_after_missing_or_corrupt_journal(
    tmp_path: Path,
    monkeypatch,
):
    for state in ("missing", "corrupt"):
        root = tmp_path / state
        root.mkdir()
        sp = root / ".scratchpad"
        sp.mkdir()
        for name in (
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ):
            (sp / name).write_text(f"# {name}\n", encoding="utf-8")
        CTA.initialize_chain_tail(
            sp, [_row(1)], shard_size=1, activate_first_shard=False
        )
        shard = CTA.prepare_next_chain_tail_shard(sp)
        CTA.materialize_isolated_chain_tail_shard(
            sp,
            shard,
            source_names=(
                "composition_coverage.md",
                "chain_hypotheses.md",
                "findings_inventory.md",
            ),
        )
        journal = sp / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
        if state == "missing":
            journal.unlink()
        else:
            journal.write_text("{corrupt", encoding="utf-8")
        (sp / "chain_iteration2.md").write_text(
            "# stale root output must not become legacy authority\n",
            encoding="utf-8",
        )

        launches: list[str] = []
        monkeypatch.setattr(
            D,
            "run_phase",
            lambda *_args, **_kwargs: launches.append("legacy") or 0,
        )
        if state == "missing":
            receipt = D._run_chain_iter2_bounded_continuations(
                _phase(), sp, _config(root, sp)
            )
            assert receipt["status"] == "DEGRADED_UNRESOLVED"
            assert any(
                "legacy fallback is forbidden" in issue
                for issue in receipt["issues"]
            )
        else:
            issues = D._chain_tail_final_reconcile_readiness_issues(sp)
            assert any("scheduler journal is invalid" in issue for issue in issues)
        assert launches == []


def test_explicit_legacy_eligibility_has_no_isolation_markers(
    tmp_path: Path,
    monkeypatch,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    CTA.initialize_chain_tail(sp, [_row(1)], shard_size=1)
    assert not (
        sp / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    ).exists()
    assert not any(
        path.is_dir()
        for path in (sp / CTA.SHARD_ARCHIVE_DIR).glob("shard_[0-9][0-9][0-9][0-9]")
    )
    _write_output(sp / "chain_iteration2.md", CTA.current_chain_tail_shard(sp)["rows"])
    launches: list[int] = []

    def legacy_run(_phase, _config, attempt):
        shard = CTA.current_chain_tail_shard(sp)
        launches.append(attempt)
        _write_output(sp / "chain_iteration2.md", shard["rows"])
        return 0

    monkeypatch.setattr(D, "run_phase", legacy_run)
    receipt = D._run_chain_iter2_bounded_continuations(
        _phase(), sp, _config(tmp_path, sp)
    )
    assert receipt["status"] == "COMPLETE"
    assert launches == []


def test_final_typed_aggregate_merges_legacy_coverage_without_pair_id_corruption(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "chain_hypotheses.md").write_text(
        "# Chain Hypotheses\n\n_No chains yet._\n", encoding="utf-8"
    )
    (sp / "composition_coverage.md").write_text(
        "# Composition Coverage\n\n"
        "| Finding A | Finding B | Disposition | Evidence |\n"
        "|---|---|---|---|\n",
        encoding="utf-8",
    )
    CTA.initialize_chain_tail(sp, [_row(1)], shard_size=1)
    _write_output(sp / "chain_iteration2.md", CTA.current_chain_tail_shard(sp)["rows"])
    CTA.run_chain_tail_shard_loop(sp, lambda _shard: 0, max_shards_per_run=1)
    result = D._apply_chain_iter2_driver_merge(
        sp, _config(tmp_path, sp)
    )
    assert result["status"] == "APPLIED"
    coverage = (sp / "composition_coverage.md").read_text(encoding="utf-8")
    assert "| H-1 | M-1 | EXPLORED |" in coverage
    assert "CP-" not in coverage
