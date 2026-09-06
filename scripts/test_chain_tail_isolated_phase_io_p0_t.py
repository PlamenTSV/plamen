from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

import chain_tail_authority as CTA
import claude_phase_tool_policy as CTP
import plamen_driver as D
import plamen_validators as V
import pytest
from artifact_ledger import (
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    LaunchSpec,
    registered_projection_handoff,
    resolve_phase_io_contract,
)
from plamen_types import Phase


def _row(index: int, *, route: str = "CHAIN_ITER2") -> dict:
    return {
        "a": f"H-{index}",
        "b": f"M-{index}",
        "a_sev": "High",
        "b_sev": "Medium",
        "signal": f"state-graph: Vault.balance.{index}",
        "graph_backed": True,
        "score": 8.0,
        "initial_route": route,
    }


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


def test_retry_quarantine_never_moves_isolated_chain_tail_transaction(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    transcript = (
        scratchpad
        / "_chain_tail_shards"
        / "shard_0001"
        / "attempt_1.output.md"
    )
    transcript.parent.mkdir(parents=True)
    transcript.write_text("# committed transcript\n" + ("evidence\n" * 100), encoding="utf-8")
    phase = Phase(
        "chain_iter2",
        ["Phase 4c Iteration 2: Chain Composition Re-evaluation"],
        ["_chain_tail_shards/shard_0001/attempt_1.output.md"],
        base_timeout_s=30,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )

    moved = V._quarantine_stale_on_retry(
        scratchpad,
        phase,
        ["attempt_1.output.md failed semantic validation"],
    )

    assert moved == []
    assert transcript.exists()
    assert not (scratchpad / "_retry_quarantine" / phase.name).exists()


def test_retry_quarantine_preserves_nested_relative_path_on_restore(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    nested = scratchpad / "nested" / "owned.md"
    nested.parent.mkdir(parents=True)
    body = "# owned\n" + ("semantic evidence\n" * 100)
    nested.write_text(body, encoding="utf-8")
    phase = Phase(
        "nested_phase",
        ["Nested test phase"],
        ["nested/owned.md"],
        base_timeout_s=30,
        modes={"thorough"},
        critical=False,
        model="sonnet",
    )

    moved = V._quarantine_stale_on_retry(
        scratchpad,
        phase,
        ["nested/owned.md failed semantic validation"],
    )
    assert moved == ["nested/owned.md"]
    assert not nested.exists()
    assert (
        scratchpad
        / "_retry_quarantine"
        / phase.name
        / "nested"
        / "owned.md"
    ).exists()

    V._restore_quarantined_on_retry_failure(scratchpad, phase)

    assert nested.read_text(encoding="utf-8") == body


def _config(tmp_path: Path, scratchpad: Path) -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "scratchpad": str(scratchpad),
        "_run_id": "run-chain-tail-isolated",
    }


def _terminal_work_unit_key(
    config: Mapping[str, object],
    role: str,
    pass_index: int,
    shard_count: int,
) -> str:
    assert role in {"tail_snapshot", "tail_reconcile", "driver_merge"}
    assert type(pass_index) is int and 0 <= pass_index <= 9999
    assert type(shard_count) is int and 0 <= shard_count <= 9999
    return (
        f"{str(config.get('pipeline') or 'sc')}/"
        f"{str(config.get('mode') or 'thorough')}/"
        f"{str(config.get('language') or 'unknown')}/"
        f"{str(config.get('cli_backend') or 'claude')}/chain_iter2/"
        f"{role}.p{pass_index:04d}.s{shard_count:04d}"
    )


def _write_sources(scratchpad: Path) -> None:
    for name, body in (
        ("composition_coverage.md", "# Composition Coverage\n"),
        ("chain_hypotheses.md", "# Chain Hypotheses\n"),
        ("findings_inventory.md", "# Findings Inventory\n"),
    ):
        (scratchpad / name).write_text(body, encoding="utf-8")


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
        f"| {row['pair_id']} | {row['a']} | {row['b']} | EXPLORED | "
        "exact source loci compared |"
        for row in rows
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _isolated_one(tmp_path: Path) -> tuple[Path, dict, dict]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad, [_row(1)], shard_size=1, activate_first_shard=False
    )
    shard = CTA.prepare_next_chain_tail_shard(scratchpad)
    isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        shard,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    return scratchpad, shard, isolated


def _initialize_with_live_producer(
    tmp_path: Path,
    scratchpad: Path,
    rows: list[dict],
    *,
    shard_size: int,
    backend: str = "claude",
) -> None:
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = backend
    config["_chain_state_resolution_initializes_tail"] = True
    contract, launch = D._chain_state_resolution_contract_and_launch(
        scratchpad=scratchpad,
        config=config,
        phase=_phase(),
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert issues == []
    tail_execute, tail_issues = D._arm_chain_tail_initial_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=_phase(),
    )
    assert tail_execute is True
    assert tail_issues == []
    (scratchpad / "chain_state_resolution.json").write_text(
        '{"schema_version":"plamen.chain_state_resolution.v1"}\n',
        encoding="utf-8",
    )
    # The live state-resolution transaction owns the complete chain-prep
    # scaffold and initial tail denominator.  These bounded fixtures exercise
    # the tail authority in isolation, so materialize neutral chain-prep
    # projections before the tail initializer writes its typed bundle.
    for name, body in {
        "chain_candidate_pairs.md": "# Chain Candidate Pairs\n\n(none)\n",
        "chain_candidate_pairs_full.md": (
            "# Chain Candidate Pairs (Full)\n\n(none)\n"
        ),
        "variable_finding_map.md": "# Variable Finding Map\n\n(none)\n",
        "enabler_results.md": "# Enabler Results\n\n(none)\n",
        "chain_enabler_baseline.md": (
            "# Chain Enabler Baseline\n\n(none)\n"
        ),
    }.items():
        (scratchpad / name).write_text(body, encoding="utf-8")
    CTA.initialize_chain_tail(
        scratchpad, rows, shard_size=shard_size, activate_first_shard=False
    )
    assert D._commit_chain_tail_initial_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=_phase(),
    ) == []
    assert D._commit_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=config["_run_id"],
    ) == []


def _commit_one_isolated_model(
    tmp_path: Path,
) -> tuple[Path, dict, Phase, dict]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [_row(1)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = dict(config["_chain_tail_active_isolated"])

    def model_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(D, "run_phase", model_success)
        assert D._run_isolated_chain_tail_model_attempt(
            phase, config, 1
        ) == 0
    return scratchpad, config, phase, isolated


def _primary_source_bytes(newline: bytes) -> tuple[bytes, bytes]:
    coverage = newline.join(
        (
            b"# Composition Coverage",
            b"",
            b"| Finding A | Finding B | Explored? | Result | Notes |",
            b"|---|---|---|---|---|",
            b"| H-1 | M-1 | YES | No composition | Exact lifecycle compared. |",
            b"",
        )
    )
    hypotheses = newline.join((b"# Chain Hypotheses", b""))
    return coverage, hypotheses


def _commit_chain_agent2_model(
    tmp_path: Path,
    scratchpad: Path,
    config: dict,
    *,
    coverage: bytes,
    hypotheses: bytes,
) -> None:
    inputs = (
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
        "variable_finding_map.md",
        "chain_candidate_pairs.md",
        "findings_inventory.md",
    )
    for name in inputs:
        path = scratchpad / name
        if not path.is_file():
            path.write_text(
                f"# {name}\nsource-bound input\n", encoding="utf-8"
            )
    for name in (
        "composition_coverage.md",
        "chain_hypotheses.md",
        "synthesis_full.md",
    ):
        (scratchpad / name).unlink(missing_ok=True)
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend=str(config["cli_backend"]),
        phase="chain_agent2",
        work_unit_id="model",
        exact_inputs=inputs,
        exact_outputs=(
            "chain_hypotheses.md",
            "composition_coverage.md",
            "synthesis_full.md",
        ),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="sonnet",
        timeout_s=30,
        exec_mode="headless",
        tool_policy=("filesystem",),
    )
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    (scratchpad / "composition_coverage.md").write_bytes(coverage)
    (scratchpad / "chain_hypotheses.md").write_bytes(hypotheses)
    (scratchpad / "synthesis_full.md").write_bytes(
        b"# Synthesis Full\nsource-bound model output\n"
    )
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    ) == []


def _prepare_zero_work_primary_predecessor(
    tmp_path: Path,
    scratchpad: Path,
) -> dict:
    """Reproduce the production MODEL -> primary-control zero-work path."""

    config = _config(tmp_path, scratchpad)
    coverage, hypotheses = _primary_source_bytes(b"\n")
    _commit_chain_agent2_model(
        tmp_path,
        scratchpad,
        config,
        coverage=coverage,
        hypotheses=hypotheses,
    )
    receipt, issues = D._run_chain_tail_primary_reconciliation_transaction(
        scratchpad, config, _phase()
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    primary_key = (
        "sc/thorough/evm/claude/chain_iter2/tail_primary_control"
    )
    assert state["work_units"][primary_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    journal_identity = (
        f"scratchpad:{CTA.CONTROL_DIR}/{CTA.CONTROL_JOURNAL_NAME}"
    )
    assert state["artifact_bindings"][journal_identity]["owner_key"] == (
        primary_key
    )
    return config


def _tamper_committed_unit_authority(
    scratchpad: Path,
    *,
    work_unit_key: str,
    mutation: str,
) -> None:
    state_path = scratchpad / "_artifact_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    unit = state["work_units"][work_unit_key]
    commit = unit["commit_authority"]
    if mutation == "schema":
        unit["schema"] = "plamen.artifact-work-unit.tampered"
    elif mutation == "launch_manifest":
        unit["launch_manifest"]["model"] = "tampered-model"
    elif mutation == "commit_receipt":
        commit["receipt_digest"] = "0" * 64
    elif mutation == "run_id":
        unit["run_id"] = "foreign-run"
    elif mutation == "snapshot_generation":
        snapshot_identity = "scratchpad:chain_tail_terminal_snapshot.json"
        snapshot_binding = unit["input_bindings"][snapshot_identity]
        snapshot_binding["producer_work_unit_key"] = (
            "sc/thorough/evm/codex/chain_iter2/tail_snapshot.foreign"
        )
        unit["input_set_digest"] = D._input_set_digest(unit["input_bindings"])
        commit["input_set_digest"] = unit["input_set_digest"]
    elif mutation == "output_authority_cas":
        digest = str(commit["output_authority_digest"])
        (
            scratchpad
            / "_artifact_output_authority_cas"
            / f"{digest}.json"
        ).unlink()
        return
    elif mutation == "output_authority_journal":
        journal_path = scratchpad / "_artifact_output_authorities.json"
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
        journal["authorities"].pop(str(commit["output_authority_key"]))
        journal_path.write_text(
            json.dumps(journal, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return
    else:
        raise AssertionError(f"unknown authority mutation: {mutation}")
    state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _prepare_one_driver_merge(
    project_root: Path,
) -> tuple[Path, dict, Phase]:
    scratchpad = project_root / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        project_root,
        scratchpad,
        [_row(1)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(project_root, scratchpad)
    config["cli_backend"] = "codex"
    coverage, hypotheses = _primary_source_bytes(b"\n")
    _commit_chain_agent2_model(
        project_root,
        scratchpad,
        config,
        coverage=coverage,
        hypotheses=hypotheses,
    )
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    isolated = dict(config["_chain_tail_active_isolated"])

    def model_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(D, "run_phase", model_success)
        assert D._run_isolated_chain_tail_model_attempt(
            phase, config, 1
        ) == 0
    final, final_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert final_issues == []
    assert final["status"] == "COMPLETE"
    return scratchpad, config, phase


def _commit_one_driver_merge(
    project_root: Path,
) -> tuple[Path, dict, dict]:
    scratchpad, config, _phase_row = _prepare_one_driver_merge(
        project_root
    )
    merged, merge_issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad, config
    )
    assert merge_issues == []
    assert merged["status"] == "APPLIED"
    return scratchpad, config, merged


@pytest.fixture(scope="module")
def _completed_driver_merge_baseline(
    tmp_path_factory,
) -> Path:
    project_root = tmp_path_factory.mktemp(
        "chain-tail-current-merge-baseline"
    )
    _commit_one_driver_merge(project_root)
    return project_root


def _assert_current_reconcile_parent_authority(
    project_root: Path,
    scratchpad: Path,
    config: Mapping[str, object],
) -> None:
    state = D.read_artifact_ledger(scratchpad)
    pass_index, shard_count, _generation_id = (
        D._current_chain_tail_generation(scratchpad)
    )
    parent_key = _terminal_work_unit_key(
        config, "tail_reconcile", pass_index, shard_count
    )
    parent_inputs = {
        f"scratchpad:{D._CHAIN_TAIL_CONTROL_MANIFEST}",
        "scratchpad:chain_tail_terminal_snapshot.json",
        *(
            {"scratchpad:chain_hypotheses.md"}
            if (scratchpad / "chain_hypotheses.md").is_file()
            else set()
        ),
    }
    _unit, parent_issues = D._full_committed_producer_authority(
        scratchpad,
        project_root,
        ledger=state,
        outer_work_unit_key=parent_key,
        run_id=str(config["_run_id"]),
        expected_input_identities=tuple(sorted(parent_inputs)),
        expected_output_identities=tuple(
            f"scratchpad:{name}"
            for name in D._CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS
        ),
        actor="DRIVER",
        require_live_input_authority=False,
    )
    assert parent_issues == []
    source_binding = state["artifact_bindings"][
        "scratchpad:chain_iteration2.md"
    ]
    assert source_binding["owner_key"] == parent_key


@pytest.fixture
def _restored_completed_driver_merge(
    _completed_driver_merge_baseline: Path,
):
    project_root = _completed_driver_merge_baseline
    scratchpad = project_root / ".scratchpad"
    config = _config(project_root, scratchpad)
    config["cli_backend"] = "codex"
    receipt = json.loads(
        (
            scratchpad
            / "_chain_iter2_merge_receipt.p0000.s0001.json"
        ).read_text(encoding="utf-8")
    )
    _assert_current_reconcile_parent_authority(
        project_root, scratchpad, config
    )
    before = _scratchpad_file_bytes(scratchpad)
    clean_replay, clean_issues = (
        D._run_and_record_chain_iter2_driver_merge(
            scratchpad, config
        )
    )
    current_lineage_issue = (
        "chain iteration 2 driver merge requires one strictly earlier "
        "monotonic prestate lineage"
    )
    assert (
        (clean_issues == [] and clean_replay == receipt)
        or (
            clean_issues == [current_lineage_issue]
            and clean_replay == {
                "status": "FAILED",
                "issues": [current_lineage_issue],
            }
        )
    )
    assert _scratchpad_file_bytes(scratchpad) == before
    physical_before = {
        relative: (scratchpad / relative).stat().st_ino
        for relative in before
    }
    yield scratchpad, config, receipt

    receipt_relative = (
        "_chain_iter2_merge_receipt.p0000.s0001.json"
    )
    receipt_path = scratchpad / receipt_relative
    away_path = scratchpad / (
        receipt_relative + ".fixture-away"
    )
    if away_path.is_file():
        assert not receipt_path.exists()
        away_path.rename(receipt_path)
    current_files = {
        path.relative_to(scratchpad).as_posix()
        for path in scratchpad.rglob("*")
        if path.is_file()
    }
    assert current_files - set(before) == set()
    assert set(before) - current_files == set()
    for relative, body in before.items():
        path = scratchpad / relative
        assert path.is_file()
        if path.read_bytes() != body:
            path.write_bytes(body)
    assert _scratchpad_file_bytes(scratchpad) == before
    assert {
        relative: (scratchpad / relative).stat().st_ino
        for relative in physical_before
    } == physical_before
    _assert_current_reconcile_parent_authority(
        project_root, scratchpad, config
    )


def _scratchpad_file_bytes(scratchpad: Path) -> dict[str, bytes]:
    return {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in sorted(scratchpad.rglob("*"))
        if path.is_file()
    }


def test_raw_primary_markdown_without_chain_agent2_producer_cannot_commit(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [{**_row(1), "initial_route": "CHAIN_AGENT2"}],
        shard_size=1,
        backend="claude",
    )
    coverage, hypotheses = _primary_source_bytes(b"\n")
    (scratchpad / "composition_coverage.md").write_bytes(coverage)
    (scratchpad / "chain_hypotheses.md").write_bytes(hypotheses)
    config = _config(tmp_path, scratchpad)

    _receipt, issues = D._run_chain_tail_primary_reconciliation_transaction(
        scratchpad, config, _phase()
    )

    assert any("ChainAgent2 MODEL producer" in issue for issue in issues)
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    primary_key = "sc/thorough/evm/claude/chain_iter2/tail_primary"
    assert state["work_units"].get(primary_key, {}).get(
        "execution_state"
    ) != "OUTPUT_COMMITTED"
    assert not (scratchpad / "chain_tail_primary_receipt.json").exists()


@pytest.mark.parametrize("newline", (b"\n", b"\r\n"), ids=("lf", "crlf"))
def test_primary_exact_chain_agent2_producer_binds_raw_bytes_end_to_end(
    tmp_path: Path, newline: bytes,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [{**_row(1), "initial_route": "CHAIN_AGENT2"}],
        shard_size=1,
        backend="claude",
    )
    config = _config(tmp_path, scratchpad)
    coverage, hypotheses = _primary_source_bytes(newline)
    _commit_chain_agent2_model(
        tmp_path,
        scratchpad,
        config,
        coverage=coverage,
        hypotheses=hypotheses,
    )

    receipt, issues = D._run_chain_tail_primary_reconciliation_transaction(
        scratchpad, config, _phase()
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"
    primary = json.loads(
        (scratchpad / "chain_tail_primary_receipt.json").read_text(
            encoding="utf-8"
        )
    )
    assert primary["composition_coverage_sha256"] == CTA._sha256_bytes(
        coverage
    )
    assert primary["chain_hypotheses_sha256"] == CTA._sha256_bytes(hypotheses)
    assert primary["chain_agent2_model_binding"]["work_unit_key"].endswith(
        "/chain_agent2/model"
    )
    assert D._chain_tail_final_reconcile_readiness_issues(scratchpad) == []
    final, final_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, _phase()
    )
    assert final_issues == []
    assert final["status"] == "COMPLETE"


def test_primary_chain_agent2_output_byte_drift_rejects_before_driver_commit(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [{**_row(1), "initial_route": "CHAIN_AGENT2"}],
        shard_size=1,
        backend="claude",
    )
    config = _config(tmp_path, scratchpad)
    coverage, hypotheses = _primary_source_bytes(b"\r\n")
    _commit_chain_agent2_model(
        tmp_path,
        scratchpad,
        config,
        coverage=coverage,
        hypotheses=hypotheses,
    )
    (scratchpad / "composition_coverage.md").write_bytes(coverage + b"drift")

    _receipt, issues = D._run_chain_tail_primary_reconciliation_transaction(
        scratchpad, config, _phase()
    )

    assert any(
        "content hash changed since work-unit record" in issue
        for issue in issues
    )
    assert any(
        "live bytes differ from issued output authority" in issue
        for issue in issues
    )
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    assert not any(
        key.endswith(
            (
                "/chain_iter2/tail_primary",
                "/chain_iter2/tail_primary_control",
            )
        )
        for key in state["work_units"]
    )
    assert not (scratchpad / "chain_tail_primary_receipt.json").exists()


def test_primary_chain_agent2_full_receipt_authority_matrix(
    tmp_path: Path,
):
    for mutation in (
        "launch_manifest",
        "commit_receipt",
        "output_authority_cas",
        "output_authority_journal",
    ):
        root = tmp_path / mutation
        root.mkdir()
        scratchpad = root / ".scratchpad"
        scratchpad.mkdir()
        _write_sources(scratchpad)
        _initialize_with_live_producer(
            root,
            scratchpad,
            [{**_row(1), "initial_route": "CHAIN_AGENT2"}],
            shard_size=1,
            backend="claude",
        )
        config = _config(root, scratchpad)
        coverage, hypotheses = _primary_source_bytes(b"\n")
        _commit_chain_agent2_model(
            root,
            scratchpad,
            config,
            coverage=coverage,
            hypotheses=hypotheses,
        )
        _tamper_committed_unit_authority(
            scratchpad,
            work_unit_key=(
                "sc/thorough/evm/claude/chain_agent2/model"
            ),
            mutation=mutation,
        )

        model_binding, direct_issues = (
            D._chain_agent2_model_producer_binding(
                scratchpad,
                expected_work_unit_key=(
                    "sc/thorough/evm/claude/chain_agent2/model"
                ),
                expected_run_id=config["_run_id"],
                expected_binding=None,
            )
        )
        assert model_binding is None, mutation
        assert direct_issues, mutation

        _receipt, issues = (
            D._run_chain_tail_primary_reconciliation_transaction(
                scratchpad, config, _phase()
            )
        )

        assert issues, mutation
        assert any(
            "producer" in issue.lower()
            or "authority" in issue.lower()
            for issue in issues
        ), (mutation, issues)
        assert not (
            scratchpad / "chain_tail_primary_receipt.json"
        ).exists()


def test_isolated_shard_materialization_binds_authoritative_sources_and_copies(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad, [_row(1), _row(2)], shard_size=1, activate_first_shard=False
    )
    shard = CTA.prepare_next_chain_tail_shard(scratchpad)
    isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        shard,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )

    shard_root = scratchpad / isolated["shard_root"]
    assert shard_root == scratchpad / "_chain_tail_shards" / "shard_0000"
    assert (shard_root / "work_unit.json").is_file()
    assert (shard_root / "chain_candidate_pairs_iter2.md").is_file()
    assert not (shard_root / "chain_iteration2.md").exists()
    assert not (shard_root / "disposition_receipt.json").exists()

    work = json.loads((shard_root / "work_unit.json").read_text(encoding="utf-8"))
    assert work["pair_ids"] == shard["pair_ids"]
    assert work["manifest_sha256"] == shard["manifest_sha256"]
    assert set(work["authoritative_sources"]) == {
        "composition_coverage.md",
        "chain_hypotheses.md",
        "findings_inventory.md",
    }
    for source, binding in work["authoritative_sources"].items():
        assert binding["authority_identity"] == f"scratchpad:{source}"
        assert len(binding["authority_sha256"]) == 64
        assert binding["copy_path"].startswith(
            "_chain_tail_shards/shard_0000/"
        )
        assert binding["copy_sha256"] == binding["authority_sha256"]


def test_model_then_disposition_units_are_armed_before_their_outputs(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad, [_row(1)], shard_size=1, activate_first_shard=False
    )
    shard = CTA.prepare_next_chain_tail_shard(scratchpad)
    isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        shard,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    config = _config(tmp_path, scratchpad)

    model_contract, model_launch = D._chain_tail_shard_model_contract_and_launch(
        scratchpad=scratchpad,
        config=config,
        phase=_phase(),
        isolated=isolated,
    )
    model_outputs = [
        output.identity.split(":", 1)[1] for output in model_contract.outputs
    ]
    assert model_outputs == [isolated["transcript_path"]]
    assert not (scratchpad / isolated["transcript_path"]).exists()
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        model_contract,
        model_launch,
        run_id=config["_run_id"],
    )
    assert validate_work_unit_inputs(
        scratchpad,
        tmp_path,
        model_contract,
        model_launch,
        run_id=config["_run_id"],
    ) == []

    _write_output(scratchpad / isolated["transcript_path"], shard["rows"])
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        model_contract,
        model_launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        model_contract,
        model_launch,
        run_id=config["_run_id"],
        actor="MODEL",
    ) == []

    disposition_contract, disposition_launch = (
        D._chain_tail_shard_disposition_contract_and_launch(
            scratchpad=scratchpad,
            config=config,
            phase=_phase(),
            isolated=isolated,
        )
    )
    assert not (scratchpad / isolated["disposition_receipt_path"]).exists()
    assert f"scratchpad:{isolated['transcript_path']}" in set(
        disposition_contract.immutable_inputs
    )
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        disposition_contract,
        disposition_launch,
        run_id=config["_run_id"],
    )
    assert validate_work_unit_inputs(
        scratchpad,
        tmp_path,
        disposition_contract,
        disposition_launch,
        run_id=config["_run_id"],
    ) == []


def test_final_reconcile_contract_requires_every_started_terminal_receipt(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad, [_row(1), _row(2)], shard_size=1, activate_first_shard=False
    )
    first = CTA.prepare_next_chain_tail_shard(scratchpad)
    isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        first,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    _write_output(scratchpad / isolated["transcript_path"], first["rows"])

    # A started shard without a disposition receipt is not terminal and may
    # never be silently omitted from the final exact input set.
    issues = D._chain_tail_final_reconcile_readiness_issues(scratchpad)
    assert any("started shard 0000 is not terminal" in issue for issue in issues)
    try:
        D._chain_tail_final_contract_and_launch(
            scratchpad=scratchpad,
            config=_config(tmp_path, scratchpad),
            phase=_phase(),
        )
    except ValueError as exc:
        assert "not terminal" in str(exc)
    else:
        raise AssertionError("final reconcile contract accepted a non-terminal shard")


def test_two_shards_never_share_model_output_authority(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad, [_row(1), _row(2)], shard_size=1, activate_first_shard=False
    )
    first = CTA.prepare_next_chain_tail_shard(scratchpad)
    first_isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        first,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    _write_output(scratchpad / first_isolated["transcript_path"], first["rows"])
    CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=first_isolated["transcript_path"],
        disposition_receipt_name=first_isolated["disposition_receipt_path"],
    )
    second = CTA.prepare_next_chain_tail_shard(scratchpad)
    second_isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        second,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    assert first_isolated["transcript_path"] != second_isolated["transcript_path"]
    assert first_isolated["work_unit_path"] != second_isolated["work_unit_path"]
    assert first_isolated["disposition_receipt_path"] != second_isolated[
        "disposition_receipt_path"
    ]
    assert not (scratchpad / "chain_iteration2.md").exists()


def test_isolated_driver_commits_model_before_disposition_and_final_publication(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="codex"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]
    assert phase.expected_artifacts == [isolated["transcript_path"]]

    def fake_inner(_phase, inner_config, _attempt):
        assert Path(inner_config["scratchpad"]) == (
            scratchpad / isolated["shard_root"]
        )
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", fake_inner)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    assert D._chain_tail_final_reconcile_readiness_issues(scratchpad) == []

    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    model_key = "sc/thorough/evm/codex/chain_iter2/tail_shard_model.0000"
    disposition_key = (
        "sc/thorough/evm/codex/chain_iter2/tail_shard_disposition.0000"
    )
    assert state["work_units"][model_key]["execution_state"] == "OUTPUT_COMMITTED"
    assert state["work_units"][disposition_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    disposition = json.loads(
        (scratchpad / isolated["disposition_receipt_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert disposition["model_binding"]["work_unit_key"] == model_key
    assert disposition["terminal_status"] == "COMMITTED"

    final_receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert issues == []
    assert final_receipt["status"] == "COMPLETE"
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 0, 1
    )
    assert state["work_units"][final_key]["execution_state"] == "OUTPUT_COMMITTED"
    assert D._chain_tail_phase_completion_issues(scratchpad) == []


def test_soft_phase_cannot_complete_with_pending_chain_tail_rows(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1
    )
    CTA.begin_isolated_chain_tail_scheduler(scratchpad)

    issues = D._chain_tail_phase_completion_issues(scratchpad)

    assert any("PENDING_ANALYSIS" in issue for issue in issues)


def test_claude_hook_grants_only_the_unique_shard_transcript(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]
    shard_root = scratchpad / isolated["shard_root"]
    snapshot = shard_root / "_prompt_chain_iter2.attempt1.md"
    snapshot.write_text("isolated chain-tail prompt\n", encoding="utf-8")
    inner_config = dict(config)
    inner_config["scratchpad"] = str(shard_root)
    inner_config["_chain_tail_authority_scratchpad"] = str(scratchpad)

    state = D._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=shard_root,
        config=inner_config,
        attempt=1,
        prompt_snapshot=snapshot,
    )
    assert state is not None
    policy = CTP.load_policy(Path(state["policy_path"]))
    assert {
        Path(path).resolve() for path in policy["exact_write_files"]
    } == {(scratchpad / isolated["transcript_path"]).resolve()}
    read_paths = {Path(row["path"]).resolve() for row in policy["exact_read_files"]}
    assert (scratchpad / "findings_inventory.md").resolve() in read_paths
    assert (
        scratchpad / isolated["shard_root"] / "findings_inventory.md"
    ).resolve() in read_paths
    assert (scratchpad / "chain_iteration2.md").resolve() not in {
        Path(path).resolve() for path in policy["exact_write_files"]
    }


def test_budget_stop_owns_the_complete_mutable_control_generation(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1), _row(2)], shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def model_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    config["chain_tail_max_shards_per_run"] = 1

    receipt = D._run_chain_iter2_bounded_continuations(
        phase, scratchpad, config
    )

    assert receipt["status"] == "BUDGET_STOP", receipt
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    key = (
        "sc/thorough/evm/codex/chain_iter2/"
        "tail_budget_stop.p0000.s0001"
    )
    unit = state["work_units"][key]
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert set(unit["artifacts"]) == {
        f"scratchpad:{path}" for path in CTA.MUTABLE_CONTROL_PATHS
    }


def test_budget_stop_commit_fault_resumes_without_control_drift(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1), _row(2)], shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def model_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    original_commit = D._commit_deterministic_driver_work_unit
    injected = {"done": False}

    def fail_budget_commit_once(**kwargs):
        if (
            kwargs["contract"].work_unit_id.startswith("tail_budget_stop.")
            and not injected["done"]
        ):
            injected["done"] = True
            return ["injected budget-stop commit failure"]
        return original_commit(**kwargs)

    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit", fail_budget_commit_once
    )
    _first, first_issues = D._run_chain_tail_budget_stop_transaction(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
        reason="CHAIN_TAIL_SHARD_BUDGET",
    )
    assert first_issues == ["injected budget-stop commit failure"]
    frozen = {
        path: (scratchpad / path).read_bytes()
        for path in CTA.MUTABLE_CONTROL_PATHS
    }

    second, second_issues = D._run_chain_tail_budget_stop_transaction(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
        reason="CHAIN_TAIL_SHARD_BUDGET",
    )

    assert second_issues == []
    assert second["status"] == "BUDGET_STOP"
    assert all(
        (scratchpad / path).read_bytes() == data
        for path, data in frozen.items()
    )


def test_isolated_continuation_loop_closes_multiple_unique_shards(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [_row(1), _row(2), _row(3)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    config["chain_tail_max_shards_per_run"] = 4
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []

    def dispatch(active_phase, active_config, attempt):
        if active_config.get("_chain_tail_inner_launch"):
            isolated = active_config["_chain_tail_active_isolated"]
            _write_output(
                Path(active_config["scratchpad"]) / "chain_iteration2.md",
                isolated["rows"],
            )
            return 0
        return D._run_isolated_chain_tail_model_attempt(
            active_phase, active_config, attempt
        )

    monkeypatch.setattr(D, "run_phase", dispatch)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    receipt = D._run_chain_iter2_bounded_continuations(
        phase, scratchpad, config
    )
    assert receipt["status"] == "COMPLETE"
    journal = json.loads(
        (
            scratchpad
            / CTA.CONTROL_DIR
            / CTA.CONTROL_JOURNAL_NAME
        ).read_text(encoding="utf-8")
    )
    assert sorted(journal["started_shards"]) == ["0000", "0001", "0002"]
    assert {
        row["terminal_status"]
        for row in journal["started_shards"].values()
    } == {"COMMITTED"}
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    assert all(
        (
            f"sc/thorough/evm/codex/chain_iter2/"
            f"tail_shard_model.{index:04d}"
        )
        in state["work_units"]
        for index in range(3)
    )


def test_claude_final_attempt_failure_commits_one_terminal_driver_debt(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="claude"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]
    launches = {"count": 0}

    def fail_model(_phase, _config, _attempt):
        launches["count"] += 1
        return 1

    monkeypatch.setattr(D, "run_phase", fail_model)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 1
    assert CTA._load_manifest_ledger(scratchpad)[1]["active_shard"] is not None
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 2) == 1

    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    failure_key = (
        "sc/thorough/evm/claude/chain_iter2/tail_shard_failure.0000"
    )
    assert state["work_units"][failure_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    assert CTA._load_manifest_ledger(scratchpad)[1]["active_shard"] is None
    disposition_path = scratchpad / isolated["disposition_receipt_path"]
    disposition = json.loads(disposition_path.read_text(encoding="utf-8"))
    abandoned = disposition["abandoned_model_binding"]
    assert abandoned["work_unit_key"].endswith(
        "/chain_iter2/tail_shard_model.0000"
    )
    assert abandoned["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert abandoned["semantic_status"] == "INPUTS_BOUND"
    assert abandoned["output_present"] is False
    assert not (scratchpad / isolated["transcript_path"]).exists()
    disposition_before = disposition_path.read_bytes()
    journal_before = json.loads(
        (
            scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
        ).read_text(encoding="utf-8")
    )

    # A process replay may revisit the exhausted attempt, but the same failure
    # transaction remains the sole terminal producer and semantic application.
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 2) == 1
    state_after = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    failure_keys = [
        key
        for key in state_after["work_units"]
        if key.endswith("/chain_iter2/tail_shard_failure.0000")
    ]
    assert failure_keys == [failure_key]
    assert disposition_path.read_bytes() == disposition_before
    journal_after = json.loads(
        (
            scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
        ).read_text(encoding="utf-8")
    )
    assert journal_after["events"] == journal_before["events"]
    assert launches["count"] == 3


def test_isolated_failure_uses_caller_attempt_budget_authority(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="claude"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    monkeypatch.setattr(D, "run_phase", lambda *_args, **_kwargs: 1)
    monkeypatch.setattr(
        D, "_codex_max_attempts_for_phase", lambda _backend, _phase: 4
    )

    for attempt in (1, 2, 3):
        assert D._run_isolated_chain_tail_model_attempt(
            phase, config, attempt
        ) == 1
        assert CTA._load_manifest_ledger(scratchpad)[1]["active_shard"] is not None
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 4) == 1
    assert CTA._load_manifest_ledger(scratchpad)[1]["active_shard"] is None


def test_continuation_exception_commits_terminal_failure_and_degraded_final(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [_row(1), _row(2)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    config["chain_tail_max_shards_per_run"] = 4
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def first_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", first_success)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0

    def continuation_exception(*_args, **_kwargs):
        raise RuntimeError("injected continuation callback failure")

    monkeypatch.setattr(D, "run_phase", continuation_exception)
    receipt = D._run_chain_iter2_bounded_continuations(
        phase, scratchpad, config
    )

    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    assert CTA._load_manifest_ledger(scratchpad)[1]["active_shard"] is None
    snapshot = json.loads(
        (
            scratchpad / CTA.TERMINAL_SNAPSHOT_NAME
        ).read_text(encoding="utf-8")
    )
    root_ledger = json.loads(
        (scratchpad / CTA.LEDGER_NAME).read_text(encoding="utf-8")
    )
    control_ledger = json.loads(
        (
            scratchpad / CTA.CONTROL_DIR / CTA.LEDGER_NAME
        ).read_text(encoding="utf-8")
    )
    assert "TRANSCRIPTLESS_TERMINAL_DEBT" in (
        snapshot["semantic_ledger"]["issues"]
    )
    assert snapshot["semantic_ledger"] == root_ledger == control_ledger
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    failure_key = "sc/thorough/evm/codex/chain_iter2/tail_shard_failure.0001"
    assert state["work_units"][failure_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 0, 2
    )
    assert state["work_units"][final_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    assert D._chain_tail_phase_completion_issues(scratchpad) == []


def test_committed_model_is_preserved_when_terminal_disposition_path_fails(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="codex"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]
    launches = {"count": 0}

    def model_success(_phase, inner_config, _attempt):
        launches["count"] += 1
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    monkeypatch.setattr(
        CTA,
        "reconcile_chain_tail_output",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("injected disposition failure")
        ),
    )

    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == (
        D.EXIT_ERROR
    )
    transcript = scratchpad / isolated["transcript_path"]
    transcript_before = transcript.read_bytes()
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 2) == (
        D.EXIT_ERROR
    )

    disposition = json.loads(
        (
            scratchpad / isolated["disposition_receipt_path"]
        ).read_text(encoding="utf-8")
    )
    assert disposition["terminal_kind"] == "FAILURE"
    assert disposition["transcript_path"] == isolated["transcript_path"]
    assert disposition["transcript_sha256"] == CTA._sha256_bytes(
        transcript_before
    )
    assert disposition["model_binding"]["work_unit_key"].endswith(
        "/chain_iter2/tail_shard_model.0000"
    )
    assert transcript.read_bytes() == transcript_before
    assert launches["count"] == 1
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    failure_key = "sc/thorough/evm/codex/chain_iter2/tail_shard_failure.0000"
    failure_unit = state["work_units"][failure_key]
    assert failure_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert (
        f"scratchpad:{isolated['transcript_path']}"
        in failure_unit["input_bindings"]
    )
    final_receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert issues == []
    assert final_receipt["status"] == "DEGRADED_UNRESOLVED"
    assert transcript.is_file()
    assert transcript.read_bytes() == transcript_before
    state_after_final = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    assert (
        f"scratchpad:{isolated['transcript_path']}"
        in state_after_final["work_units"][failure_key]["input_bindings"]
    )
    snapshot = json.loads(
        (
            scratchpad / CTA.TERMINAL_SNAPSHOT_NAME
        ).read_text(encoding="utf-8")
    )
    root_ledger = json.loads(
        (scratchpad / CTA.LEDGER_NAME).read_text(encoding="utf-8")
    )
    control_ledger = json.loads(
        (
            scratchpad / CTA.CONTROL_DIR / CTA.LEDGER_NAME
        ).read_text(encoding="utf-8")
    )
    assert "TRANSCRIPTLESS_TERMINAL_DEBT" not in (
        snapshot["semantic_ledger"]["issues"]
    )
    assert "TRANSCRIPTLESS_TERMINAL_DEBT" not in root_ledger["issues"]
    assert "TRANSCRIPTLESS_TERMINAL_DEBT" not in control_ledger["issues"]


def test_zero_work_final_publication_is_prearmed_with_clean_outputs(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [], shard_size=1
    )
    phase = _phase()
    config = _prepare_zero_work_primary_predecessor(
        tmp_path, scratchpad
    )
    original_arm = D._arm_deterministic_driver_work_unit
    observed = {"owned_predecessor": False}
    expected_owner_by_identity = {
        **{
            f"scratchpad:{name}": (
                "sc/thorough/evm/claude/chain/state_resolution"
            )
            for name in D._CHAIN_TAIL_FINAL_ROOT_OUTPUTS
            if name != "chain_iteration2.md"
        },
        **{
            f"scratchpad:{name}": (
                "sc/thorough/evm/claude/chain_iter2/"
                "tail_primary_control"
            )
            for name in D._CHAIN_TAIL_MUTABLE_CONTROL_OUTPUTS
        },
    }

    def asserting_arm(**kwargs):
        contract = kwargs["contract"]
        if contract.work_unit_id == "tail_reconcile.p0000.s0000":
            ledger = json.loads(
                (scratchpad / "_artifact_state.json").read_text(
                    encoding="utf-8"
                )
            )
            observed["owned_predecessor"] = all(
                (
                    (
                        not D._phase_identity_path(
                            output.identity,
                            scratchpad=scratchpad,
                            project_root=tmp_path,
                        ).exists()
                        and output.identity
                        == "scratchpad:chain_iteration2.md"
                    )
                    or (
                        output.identity in expected_owner_by_identity
                        and
                        ledger["artifact_bindings"][output.identity][
                            "owner_key"
                        ]
                        == expected_owner_by_identity[output.identity]
                    )
                )
                for output in contract.outputs
            )
        return original_arm(**kwargs)

    monkeypatch.setattr(D, "_arm_deterministic_driver_work_unit", asserting_arm)
    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert observed["owned_predecessor"] is True


@pytest.mark.parametrize(
    "tamper",
    ("copy_bytes", "authority_bytes", "work_digest", "copy_alias"),
)
def test_strict_work_loader_rejects_every_source_binding_tamper(
    tmp_path: Path, tamper: str,
):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    work_path = scratchpad / isolated["work_unit_path"]
    work = json.loads(work_path.read_text(encoding="utf-8"))
    binding = work["authoritative_sources"]["findings_inventory.md"]
    if tamper == "copy_bytes":
        (scratchpad / binding["copy_path"]).write_text(
            "# forged private copy\n", encoding="utf-8"
        )
    elif tamper == "authority_bytes":
        (scratchpad / "findings_inventory.md").write_text(
            "# authority changed after work definition\n", encoding="utf-8"
        )
    elif tamper == "work_digest":
        work["work_unit_sha256"] = "0" * 64
        work_path.write_text(json.dumps(work), encoding="utf-8")
    else:
        binding["copy_path"] = "findings_inventory.md"
        work["work_unit_sha256"] = CTA._digest(work, "work_unit_sha256")
        work_path.write_text(json.dumps(work), encoding="utf-8")

    with pytest.raises(CTA.ChainTailAuthorityError):
        CTA.load_isolated_chain_tail_work_unit(
            scratchpad,
            isolated,
            expected_source_names=(
                "composition_coverage.md",
                "chain_hypotheses.md",
                "findings_inventory.md",
            ),
        )


def test_work_loader_rejects_mutate_and_rehash_copy(tmp_path: Path):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    work_path = scratchpad / isolated["work_unit_path"]
    work = json.loads(work_path.read_text(encoding="utf-8"))
    binding = work["authoritative_sources"]["findings_inventory.md"]
    copy_path = scratchpad / binding["copy_path"]
    copy_path.write_text("# forged but rehashed copy\n", encoding="utf-8")
    binding["copy_sha256"] = CTA._sha256_bytes(copy_path.read_bytes())
    work["work_unit_sha256"] = CTA._digest(work, "work_unit_sha256")
    work_path.write_text(json.dumps(work), encoding="utf-8")

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="source/copy byte binding mismatch",
    ):
        CTA.load_isolated_chain_tail_work_unit(
            scratchpad,
            isolated,
            expected_source_names=isolated["authoritative_source_paths"],
        )


def test_work_loader_rejects_mutate_original_after_arm(tmp_path: Path):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    config = _config(tmp_path, scratchpad)
    contract, launch = D._chain_tail_shard_model_contract_and_launch(
        scratchpad=scratchpad,
        config=config,
        phase=_phase(),
        isolated=isolated,
    )
    execute, issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=tmp_path,
        contract=contract,
        launch=launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert issues == []

    (scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\nchanged after MODEL pre-arm\n",
        encoding="utf-8",
    )
    assert validate_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="source/copy byte binding mismatch",
    ):
        CTA.load_isolated_chain_tail_work_unit(
            scratchpad,
            isolated,
            expected_source_names=isolated["authoritative_source_paths"],
        )


def test_work_loader_rejects_swapped_valid_work_paths(tmp_path: Path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad,
        [_row(1), _row(2)],
        shard_size=1,
        activate_first_shard=False,
    )
    first = CTA.prepare_next_chain_tail_shard(scratchpad)
    first_isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        first,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    _write_output(
        scratchpad / first_isolated["transcript_path"],
        first["rows"],
    )
    CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=first_isolated["transcript_path"],
        disposition_receipt_name=first_isolated["disposition_receipt_path"],
    )
    second = CTA.prepare_next_chain_tail_shard(scratchpad)
    second_isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        second,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    swapped = dict(second_isolated)
    swapped["work_unit_path"] = first_isolated["work_unit_path"]

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="escapes its authority namespace",
    ):
        CTA.load_isolated_chain_tail_work_unit(
            scratchpad,
            swapped,
            expected_source_names=swapped["authoritative_source_paths"],
        )


def test_work_loader_rejects_cross_run_or_cross_shard_substitution(
    tmp_path: Path,
):
    source_root = tmp_path / "source-run"
    target_root = tmp_path / "target-run"
    source_root.mkdir()
    target_root.mkdir()
    source_scratchpad, _source_shard, source_isolated = _isolated_one(source_root)
    target_scratchpad, _target_shard, target_isolated = _isolated_one(target_root)
    (source_scratchpad / "findings_inventory.md").write_text(
        "# Findings Inventory\nsource-run-only bytes\n",
        encoding="utf-8",
    )
    source_work_path = source_scratchpad / source_isolated["work_unit_path"]
    source_work = json.loads(source_work_path.read_text(encoding="utf-8"))
    source_binding = source_work["authoritative_sources"][
        "findings_inventory.md"
    ]
    source_copy = source_scratchpad / source_binding["copy_path"]
    source_copy.write_bytes(
        (source_scratchpad / "findings_inventory.md").read_bytes()
    )
    source_binding["authority_sha256"] = CTA._sha256_bytes(
        source_copy.read_bytes()
    )
    source_binding["copy_sha256"] = source_binding["authority_sha256"]
    source_work["work_unit_sha256"] = CTA._digest(
        source_work, "work_unit_sha256"
    )
    source_work_path.write_text(json.dumps(source_work), encoding="utf-8")

    target_work_path = target_scratchpad / target_isolated["work_unit_path"]
    target_work_path.write_bytes(source_work_path.read_bytes())
    target_copy = (
        target_scratchpad
        / source_work["authoritative_sources"]["findings_inventory.md"][
            "copy_path"
        ]
    )
    target_copy.write_bytes(source_copy.read_bytes())

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="source/copy byte binding mismatch",
    ):
        CTA.load_isolated_chain_tail_work_unit(
            target_scratchpad,
            target_isolated,
            expected_source_names=target_isolated[
                "authoritative_source_paths"
            ],
        )

    cross_shard = dict(target_isolated)
    cross_shard["shard_index"] = 1
    with pytest.raises(CTA.ChainTailAuthorityError):
        CTA.load_isolated_chain_tail_work_unit(
            target_scratchpad,
            cross_shard,
            expected_source_names=cross_shard[
                "authoritative_source_paths"
            ],
        )


@pytest.mark.parametrize(
    "hostile_path",
    (
        "../_chain_tail_shards/shard_0000/work_unit.json",
        "_chain_tail_shards/shard_0000/../shard_0000/work_unit.json",
        "_CHAIN_TAIL_SHARDS/SHARD_0000/WORK_UNIT.JSON",
    ),
)
def test_work_loader_rejects_traversal_absolute_alias_and_case_variants(
    tmp_path: Path,
    hostile_path: str,
):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    hostile = dict(isolated)
    hostile["work_unit_path"] = hostile_path
    with pytest.raises(CTA.ChainTailAuthorityError):
        CTA.load_isolated_chain_tail_work_unit(
            scratchpad,
            hostile,
            expected_source_names=hostile["authoritative_source_paths"],
        )

    absolute = dict(isolated)
    absolute["work_unit_path"] = str(
        (scratchpad / isolated["work_unit_path"]).resolve()
    )
    with pytest.raises(CTA.ChainTailAuthorityError):
        CTA.load_isolated_chain_tail_work_unit(
            scratchpad,
            absolute,
            expected_source_names=absolute["authoritative_source_paths"],
        )


def test_scheduler_lock_rejected_contender_cannot_delete_owner_lock(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    with CTA._scheduler_lock(scratchpad):
        lock = scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_LOCK_NAME
        owner_bytes = lock.read_bytes()
        with pytest.raises(CTA.ChainTailAuthorityError):
            with CTA._scheduler_lock(scratchpad):
                pass
        assert lock.read_bytes() == owner_bytes
        with pytest.raises(CTA.ChainTailAuthorityError):
            with CTA._scheduler_lock(scratchpad):
                pass
        assert lock.read_bytes() == owner_bytes


@pytest.mark.parametrize("corruption", ("missing", "changed"))
def test_scheduler_owned_cleanup_rejects_missing_or_changed_lock(
    tmp_path: Path,
    corruption: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    lock = scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_LOCK_NAME

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match=f"scheduler lock (?:is missing|ownership token changed)",
    ):
        with CTA._scheduler_lock(scratchpad):
            if corruption == "missing":
                lock.unlink()
            else:
                lock.write_bytes(b"not-the-owner-token")


def test_scheduler_owned_cleanup_rejects_nonregular_or_unreadable_lock(
    tmp_path: Path,
    monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    lock = scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_LOCK_NAME

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="scheduler lock is not a regular file",
    ):
        with CTA._scheduler_lock(scratchpad):
            lock.unlink()
            lock.mkdir()
    lock.rmdir()

    original_read_bytes = Path.read_bytes

    def fail_owner_read(path: Path):
        if path == lock:
            raise OSError("injected owner-token read failure")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_owner_read)
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="cannot read owned .*scheduler lock",
    ):
        with CTA._scheduler_lock(scratchpad):
            pass


def test_scheduler_owned_cleanup_surfaces_unlink_failure(
    tmp_path: Path,
    monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    lock = scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_LOCK_NAME
    original_unlink = Path.unlink

    def fail_owner_unlink(path: Path, *args, **kwargs):
        if path == lock:
            raise OSError("injected owner lock unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_owner_unlink)
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="cannot release owned .*scheduler lock",
    ):
        with CTA._scheduler_lock(scratchpad):
            pass


@pytest.mark.parametrize("failure", ("zero_write", "partial_then_error"))
def test_scheduler_lock_acquisition_failures_do_not_leak_owner_state(
    tmp_path: Path,
    monkeypatch,
    failure: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    lock = scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_LOCK_NAME
    original_write = os.write
    calls = {"count": 0}

    def fail_write(descriptor: int, data: bytes) -> int:
        calls["count"] += 1
        if failure == "zero_write":
            return 0
        if calls["count"] == 1:
            return original_write(descriptor, data[:7])
        raise OSError("injected scheduler-token write failure")

    monkeypatch.setattr(os, "write", fail_write)
    with pytest.raises((OSError, CTA.ChainTailAuthorityError)):
        with CTA._scheduler_lock(scratchpad):
            pass
    assert not lock.exists()


@pytest.mark.parametrize(
    "fail_suffix",
    (
        "/terminal_plan.json",
        "/_chain_tail_control/chain_tail_disposition_ledger.json",
        "/disposition_receipt.json",
        "/_chain_tail_control/chain_composition_verification_candidates.json",
        "/_chain_tail_control/chain_tail_coverage_receipt.json",
        "/_chain_tail_control/scheduler_journal.json",
    ),
)
def test_terminal_plan_failpoints_roll_forward_without_stranding_active_shard(
    tmp_path: Path, monkeypatch, fail_suffix: str,
):
    scratchpad, shard, isolated = _isolated_one(tmp_path)
    _write_output(scratchpad / isolated["transcript_path"], shard["rows"])
    original = CTA._atomic_json
    injected = {"done": False}

    def fail_once(path, payload):
        normalized = Path(path).as_posix()
        if not injected["done"] and normalized.endswith(fail_suffix):
            injected["done"] = True
            raise OSError(f"injected failpoint: {fail_suffix}")
        return original(path, payload)

    monkeypatch.setattr(CTA, "_atomic_json", fail_once)
    with pytest.raises(OSError):
        CTA.reconcile_chain_tail_output(
            scratchpad,
            output_name=isolated["transcript_path"],
            disposition_receipt_name=isolated["disposition_receipt_path"],
        )
    assert injected["done"] is True
    monkeypatch.setattr(CTA, "_atomic_json", original)

    receipt = CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=isolated["transcript_path"],
        disposition_receipt_name=isolated["disposition_receipt_path"],
    )
    assert receipt["status"] == "COMPLETE"
    _manifest, ledger = CTA._load_manifest_ledger(scratchpad)
    assert ledger["active_shard"] is None
    assert (scratchpad / isolated["terminal_plan_path"]).is_file()
    assert (scratchpad / isolated["disposition_receipt_path"]).is_file()
    journal = json.loads(
        (
            scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
        ).read_text(encoding="utf-8")
    )
    assert journal["started_shards"]["0000"]["terminal_status"] == "COMMITTED"


def test_failure_terminal_plan_resumes_after_semantic_state_write(
    tmp_path: Path, monkeypatch,
):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    original = CTA._atomic_json
    injected = {"done": False}

    def fail_receipt_once(path, payload):
        normalized = Path(path).as_posix()
        if (
            not injected["done"]
            and normalized.endswith("/disposition_receipt.json")
        ):
            injected["done"] = True
            raise OSError("injected failure receipt failpoint")
        return original(path, payload)

    monkeypatch.setattr(CTA, "_atomic_json", fail_receipt_once)
    with pytest.raises(OSError):
        CTA.record_isolated_chain_tail_failure(
            scratchpad,
            disposition_receipt_name=isolated["disposition_receipt_path"],
            reason="CHAIN_TAIL_WORKER_FAILURE",
        )
    monkeypatch.setattr(CTA, "_atomic_json", original)
    receipt = CTA.record_isolated_chain_tail_failure(
        scratchpad,
        disposition_receipt_name=isolated["disposition_receipt_path"],
        reason="CHAIN_TAIL_WORKER_FAILURE",
    )
    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    disposition = json.loads(
        (scratchpad / isolated["disposition_receipt_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert disposition["terminal_status"] == "DEBT"


def test_committed_model_is_not_rerun_when_disposition_commit_resumes(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="codex"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]
    launches = {"model": 0}

    def fake_inner(_phase, inner_config, _attempt):
        launches["model"] += 1
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    original_commit = D._commit_deterministic_driver_work_unit
    injected = {"done": False}

    def fail_disposition_commit_once(**kwargs):
        if (
            kwargs["contract"].work_unit_id.startswith(
                "tail_shard_disposition."
            )
            and not injected["done"]
        ):
            injected["done"] = True
            return ["injected disposition commit failure"]
        return original_commit(**kwargs)

    monkeypatch.setattr(D, "run_phase", fake_inner)
    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit",
        fail_disposition_commit_once,
    )
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 1
    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit", original_commit
    )
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 2) == 0
    assert launches["model"] == 1


def test_snapshot_commit_and_final_arm_failpoints_resume_without_root_drift(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="codex"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def fake_inner(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", fake_inner)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    original_commit = D._commit_deterministic_driver_work_unit
    injected_commit = {"done": False}

    def fail_snapshot_commit_once(**kwargs):
        if (
            kwargs["contract"].work_unit_id == "tail_snapshot.p0000.s0001"
            and not injected_commit["done"]
        ):
            injected_commit["done"] = True
            return ["injected snapshot commit failure"]
        return original_commit(**kwargs)

    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit",
        fail_snapshot_commit_once,
    )
    _receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert issues == ["injected snapshot commit failure"]
    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit", original_commit
    )
    frozen = {
        name: (scratchpad / name).read_bytes()
        for name in (
            CTA.LEDGER_NAME,
            CTA.RECEIPT_NAME,
            CTA.COMPOSITION_CANDIDATES_NAME,
            CTA.PROJECTION_NAME,
        )
    }
    original_arm = D._arm_deterministic_driver_work_unit
    injected_arm = {"done": False}

    def fail_final_arm_once(**kwargs):
        if (
            kwargs["contract"].work_unit_id == "tail_reconcile.p0000.s0001"
            and not injected_arm["done"]
        ):
            injected_arm["done"] = True
            return False, ["injected final arm failure"]
        return original_arm(**kwargs)

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", fail_final_arm_once
    )
    _receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert issues == ["injected final arm failure"]
    assert all(
        (scratchpad / name).read_bytes() == data
        for name, data in frozen.items()
    )
    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", original_arm
    )
    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"


def test_final_readiness_cannot_omit_terminal_shard_by_deleting_journal_row(
    tmp_path: Path,
):
    scratchpad, shard, isolated = _isolated_one(tmp_path)
    _write_output(scratchpad / isolated["transcript_path"], shard["rows"])
    CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=isolated["transcript_path"],
        disposition_receipt_name=isolated["disposition_receipt_path"],
    )
    journal_path = (
        scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["started_shards"] = {}
    journal_path.write_text(json.dumps(journal), encoding="utf-8")

    issues = D._chain_tail_final_reconcile_readiness_issues(scratchpad)
    assert any("denominator" in issue or "roster" in issue for issue in issues)


def test_final_denominator_reconstructs_after_journal_delete(tmp_path: Path):
    scratchpad, shard, isolated = _isolated_one(tmp_path)
    _write_output(scratchpad / isolated["transcript_path"], shard["rows"])
    CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=isolated["transcript_path"],
        disposition_receipt_name=isolated["disposition_receipt_path"],
    )
    journal_path = (
        scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    journal_path.unlink()

    snapshot = CTA.build_chain_tail_terminal_snapshot(scratchpad)
    assert [row["shard_index"] for row in snapshot["terminal_records"]] == [0]
    assert len(snapshot["semantic_ledger"]["pairs"]) == 1
    issues = D._chain_tail_final_reconcile_readiness_issues(scratchpad)
    assert any("scheduler journal is missing" in issue for issue in issues)


def test_final_denominator_ignores_phantom_and_reordered_journal_rows(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad,
        [_row(1), _row(2)],
        shard_size=1,
        activate_first_shard=False,
    )
    for _index in range(2):
        shard = CTA.prepare_next_chain_tail_shard(scratchpad)
        isolated = CTA.materialize_isolated_chain_tail_shard(
            scratchpad,
            shard,
            source_names=(
                "composition_coverage.md",
                "chain_hypotheses.md",
                "findings_inventory.md",
            ),
        )
        _write_output(
            scratchpad / isolated["transcript_path"],
            shard["rows"],
        )
        CTA.reconcile_chain_tail_output(
            scratchpad,
            output_name=isolated["transcript_path"],
            disposition_receipt_name=isolated[
                "disposition_receipt_path"
            ],
        )

    baseline = CTA.build_chain_tail_terminal_snapshot(scratchpad)
    journal_path = (
        scratchpad / CTA.CONTROL_DIR / CTA.CONTROL_JOURNAL_NAME
    )
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["started_shards"] = dict(
        reversed(list(journal["started_shards"].items()))
    )
    journal["events"] = list(reversed(journal["events"]))
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    reordered = CTA.build_chain_tail_terminal_snapshot(scratchpad)
    assert reordered == baseline
    reordered_issues = D._chain_tail_final_reconcile_readiness_issues(
        scratchpad
    )
    assert not any("roster denominator mismatch" in row for row in reordered_issues)

    journal["started_shards"]["9999"] = dict(
        journal["started_shards"]["0000"],
        shard_index=9999,
    )
    journal_path.write_text(json.dumps(journal), encoding="utf-8")
    phantom_issues = D._chain_tail_final_reconcile_readiness_issues(
        scratchpad
    )
    assert any("roster denominator mismatch" in row for row in phantom_issues)


def test_terminal_snapshot_rejects_mutate_rehash_delete_and_reorder_projection(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    CTA.initialize_chain_tail(
        scratchpad,
        [_row(1), _row(2)],
        shard_size=2,
        activate_first_shard=False,
    )
    shard = CTA.prepare_next_chain_tail_shard(scratchpad)
    isolated = CTA.materialize_isolated_chain_tail_shard(
        scratchpad,
        shard,
        source_names=(
            "composition_coverage.md",
            "chain_hypotheses.md",
            "findings_inventory.md",
        ),
    )
    _write_output(scratchpad / isolated["transcript_path"], shard["rows"])
    CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=isolated["transcript_path"],
        disposition_receipt_name=isolated["disposition_receipt_path"],
    )
    control_path = scratchpad / CTA.CONTROL_DIR / CTA.LEDGER_NAME
    pristine = control_path.read_bytes()
    baseline = CTA.build_chain_tail_terminal_snapshot(scratchpad)

    mutated = json.loads(pristine.decode("utf-8"))
    mutated["pairs"][0]["evidence"] = "forged semantic projection"
    mutated["ledger_sha256"] = CTA._digest(mutated, "ledger_sha256")
    control_path.write_text(json.dumps(mutated), encoding="utf-8")
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="control ledger diverges",
    ):
        CTA.build_chain_tail_terminal_snapshot(scratchpad)

    control_path.write_bytes(pristine)
    control_path.unlink()
    with pytest.raises(CTA.ChainTailAuthorityError):
        CTA.build_chain_tail_terminal_snapshot(scratchpad)

    control_path.write_bytes(pristine)
    reordered = json.loads(pristine.decode("utf-8"))
    reordered["pairs"] = list(reversed(reordered["pairs"]))
    reordered["ledger_sha256"] = CTA._digest(reordered, "ledger_sha256")
    control_path.write_text(json.dumps(reordered), encoding="utf-8")
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="control ledger diverges",
    ):
        CTA.build_chain_tail_terminal_snapshot(scratchpad)

    control_path.write_bytes(pristine)
    assert CTA.build_chain_tail_terminal_snapshot(scratchpad) == baseline


def test_failed_terminal_shard_finalizes_as_transcriptless_debt(
    tmp_path: Path,
):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    CTA.record_isolated_chain_tail_failure(
        scratchpad,
        disposition_receipt_name=isolated["disposition_receipt_path"],
        reason="CHAIN_TAIL_WORKER_FAILURE",
    )
    receipt = CTA.finalize_chain_tail_aggregate_output(scratchpad)
    assert receipt["status"] in {"BUDGET_STOP", "DEGRADED_UNRESOLVED"}
    aggregate = (scratchpad / "chain_iteration2.md").read_text(encoding="utf-8")
    assert "CHAIN_TAIL_WORKER_FAILURE" in aggregate


def test_transcriptless_failure_never_treats_empty_path_as_directory(
    tmp_path: Path,
    monkeypatch,
):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    CTA.record_isolated_chain_tail_failure(
        scratchpad,
        disposition_receipt_name=isolated["disposition_receipt_path"],
        reason="CHAIN_TAIL_WORKER_FAILURE",
    )
    disposition = json.loads(
        (scratchpad / isolated["disposition_receipt_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert disposition["transcript_path"] == ""
    original_read_bytes = Path.read_bytes

    def reject_directory_read(path: Path):
        if path == scratchpad:
            raise AssertionError("empty transcript path became scratchpad directory")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_directory_read)
    snapshot = CTA.build_chain_tail_terminal_snapshot(scratchpad)
    assert snapshot["terminal_records"][0]["transcript_path"] == ""
    assert snapshot["terminal_records"][0]["terminal_status"] == "DEBT"


def test_unowned_terminal_receipt_never_satisfies_final_readiness(
    tmp_path: Path,
):
    scratchpad, _shard, isolated = _isolated_one(tmp_path)
    CTA.record_isolated_chain_tail_failure(
        scratchpad,
        disposition_receipt_name=isolated["disposition_receipt_path"],
        reason="CHAIN_TAIL_WORKER_FAILURE",
    )
    issues = D._chain_tail_final_reconcile_readiness_issues(scratchpad)
    assert any("producer" in issue or "OUTPUT_COMMITTED" in issue for issue in issues)


def test_terminal_driver_rejects_cross_run_cross_shard_and_hash_mismatch(
    tmp_path: Path,
):
    success_root = tmp_path / "success"
    success_root.mkdir()
    scratchpad, _config_value, _phase_value, isolated = (
        _commit_one_isolated_model(success_root)
    )
    assert D._chain_tail_final_reconcile_readiness_issues(scratchpad) == []
    state_path = scratchpad / "_artifact_state.json"
    pristine = state_path.read_bytes()
    state = json.loads(pristine.decode("utf-8"))
    terminal_key = next(
        key
        for key in state["work_units"]
        if key.endswith("/chain_iter2/tail_shard_disposition.0000")
    )

    cross_run = json.loads(pristine.decode("utf-8"))
    cross_run["work_units"][terminal_key]["run_id"] = "foreign-run"
    state_path.write_text(json.dumps(cross_run), encoding="utf-8")
    assert any(
        "run" in issue.lower()
        for issue in D._chain_tail_final_reconcile_readiness_issues(
            scratchpad
        )
    )

    cross_shard = json.loads(pristine.decode("utf-8"))
    moved = cross_shard["work_units"].pop(terminal_key)
    cross_shard["work_units"][
        terminal_key.replace(".0000", ".0001")
    ] = moved
    state_path.write_text(json.dumps(cross_shard), encoding="utf-8")
    assert any(
        "producer" in issue
        for issue in D._chain_tail_final_reconcile_readiness_issues(
            scratchpad
        )
    )

    wrong_hash = json.loads(pristine.decode("utf-8"))
    receipt_identity = (
        f"scratchpad:{isolated['disposition_receipt_path']}"
    )
    wrong_hash["work_units"][terminal_key]["artifacts"][
        receipt_identity
    ]["sha256"] = "0" * 64
    state_path.write_text(json.dumps(wrong_hash), encoding="utf-8")
    assert any(
        "artifact binding mismatch" in issue
        for issue in D._chain_tail_final_reconcile_readiness_issues(
            scratchpad
        )
    )
    state_path.write_bytes(pristine)

    failure_root = tmp_path / "failure"
    failure_root.mkdir()
    failure_scratchpad = failure_root / ".scratchpad"
    failure_scratchpad.mkdir()
    _write_sources(failure_scratchpad)
    _initialize_with_live_producer(
        failure_root,
        failure_scratchpad,
        [_row(1)],
        shard_size=1,
        backend="codex",
    )
    failure_phase = _phase()
    failure_config = _config(failure_root, failure_scratchpad)
    failure_config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(
        failure_phase, failure_scratchpad, failure_config
    ) == []
    failure_isolated = failure_config["_chain_tail_active_isolated"]
    assert D._run_chain_tail_failure_transaction(
        scratchpad=failure_scratchpad,
        config=failure_config,
        phase=failure_phase,
        isolated=failure_isolated,
        reason="CHAIN_TAIL_WORKER_FAILURE",
    ) == []
    assert D._chain_tail_final_reconcile_readiness_issues(
        failure_scratchpad
    ) == []


def test_terminal_driver_full_receipt_authority_matrix(
    tmp_path: Path,
):
    for mutation in (
        "schema",
        "launch_manifest",
        "commit_receipt",
        "output_authority_cas",
        "output_authority_journal",
    ):
        root = tmp_path / mutation
        root.mkdir()
        scratchpad, _config_value, _phase_value, isolated = (
            _commit_one_isolated_model(root)
        )
        state = json.loads(
            (scratchpad / "_artifact_state.json").read_text(
                encoding="utf-8"
            )
        )
        receipt_identity = (
            f"scratchpad:{isolated['disposition_receipt_path']}"
        )
        terminal_key = next(
            key
            for key, unit in state["work_units"].items()
            if (
                key.endswith(
                    "/chain_iter2/tail_shard_disposition.0000"
                )
                and receipt_identity in (unit.get("artifacts") or {})
            )
        )
        _tamper_committed_unit_authority(
            scratchpad,
            work_unit_key=terminal_key,
            mutation=mutation,
        )

        issues = D._chain_tail_final_reconcile_readiness_issues(
            scratchpad
        )

        assert issues, mutation
        assert any(
            "producer" in issue.lower()
            or "authority" in issue.lower()
            for issue in issues
        ), (mutation, issues)


def test_tail_reconcile_merge_parent_full_receipt_and_generation_matrix(
    tmp_path: Path,
    monkeypatch,
):
    expected_issue = (
        "chain iteration 2 driver merge requires the exact committed "
        "tail_reconcile parent"
    )
    for mutation in (
        "launch_manifest",
        "commit_receipt",
        "output_authority_cas",
        "output_authority_journal",
        "run_id",
        "snapshot_generation",
    ):
        root = tmp_path / mutation
        root.mkdir()
        scratchpad, config, phase, _isolated = (
            _commit_one_isolated_model(root)
        )
        final, final_issues = (
            D._run_chain_tail_final_reconcile_transaction(
                scratchpad, config, phase
            )
        )
        assert final_issues == []
        assert final["status"] == "COMPLETE"
        final_key = _terminal_work_unit_key(
            config, "tail_reconcile", 0, 1
        )
        _tamper_committed_unit_authority(
            scratchpad,
            work_unit_key=final_key,
            mutation=mutation,
        )

        receipt, issues = D._run_and_record_chain_iter2_driver_merge(
            scratchpad, config
        )

        assert receipt["status"] == "FAILED", mutation
        assert issues == [expected_issue], (mutation, issues)
        state = json.loads(
            (scratchpad / "_artifact_state.json").read_text(
                encoding="utf-8"
            )
        )
        assert (
            _terminal_work_unit_key(
                config, "driver_merge", 0, 1
            )
            not in state["work_units"]
        )

    positive_root = tmp_path / "positive"
    positive_root.mkdir()
    positive_scratchpad = positive_root / ".scratchpad"
    positive_scratchpad.mkdir()
    _write_sources(positive_scratchpad)
    _initialize_with_live_producer(
        positive_root,
        positive_scratchpad,
        [_row(1)],
        shard_size=1,
        backend="codex",
    )
    positive_phase = _phase()
    positive_config = _config(
        positive_root, positive_scratchpad
    )
    positive_config["cli_backend"] = "codex"
    coverage, hypotheses = _primary_source_bytes(b"\n")
    _commit_chain_agent2_model(
        positive_root,
        positive_scratchpad,
        positive_config,
        coverage=coverage,
        hypotheses=hypotheses,
    )
    assert D._bind_typed_model_phase_inputs(
        positive_phase, positive_scratchpad, positive_config
    ) == []
    positive_isolated = dict(
        positive_config["_chain_tail_active_isolated"]
    )

    def model_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            positive_isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    assert D._run_isolated_chain_tail_model_attempt(
        positive_phase, positive_config, 1
    ) == 0
    final, final_issues = D._run_chain_tail_final_reconcile_transaction(
        positive_scratchpad, positive_config, positive_phase
    )
    assert final_issues == []
    assert final["status"] == "COMPLETE"
    merged, merge_issues = D._run_and_record_chain_iter2_driver_merge(
        positive_scratchpad, positive_config
    )
    assert merge_issues == []
    assert merged["status"] == "APPLIED"
    merge_paths = (
        "chain_hypotheses.md",
        "composition_coverage.md",
        "_chain_iter2_merge_receipt.p0000.s0001.json",
    )
    first_postimages = {
        name: (positive_scratchpad / name).read_bytes()
        for name in merge_paths
    }
    first_events = list(merged["events"])
    assert len(first_events) == 2
    assert len({
        event["artifact_identity"] for event in first_events
    }) == len(first_events)

    replayed, replay_issues = D._run_and_record_chain_iter2_driver_merge(
        positive_scratchpad, positive_config
    )

    assert replay_issues == []
    assert replayed == merged
    assert {
        name: (positive_scratchpad / name).read_bytes()
        for name in merge_paths
    } == first_postimages
    state = json.loads(
        (positive_scratchpad / "_artifact_state.json").read_text(
            encoding="utf-8"
        )
    )
    merge_keys = [
        key
        for key in state["work_units"]
        if key.endswith("/chain_iter2/driver_merge.p0000.s0001")
    ]
    assert merge_keys == [
        _terminal_work_unit_key(
            positive_config, "driver_merge", 0, 1
        )
    ]
    merge_unit = state["work_units"][merge_keys[0]]
    assert merge_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert merge_unit["semantic_status"] == "ACTIVE"

    scoped_snapshot = _terminal_work_unit_key(
        positive_config, "tail_snapshot", 0, 1
    )
    scoped_reconcile = _terminal_work_unit_key(
        positive_config, "tail_reconcile", 0, 1
    )
    legacy_keys = (
        "sc/thorough/evm/codex/chain_iter2/tail_snapshot",
        "sc/thorough/evm/codex/chain_iter2/tail_reconcile",
        # Detection is intentionally configuration/backend independent.
        "sc/thorough/evm/legacy/chain_iter2/driver_merge",
    )
    state["work_units"][legacy_keys[0]] = json.loads(json.dumps(
        state["work_units"][scoped_snapshot]
    ))
    state["work_units"][legacy_keys[1]] = json.loads(json.dumps(
        state["work_units"][scoped_reconcile]
    ))
    state["work_units"][legacy_keys[2]] = json.loads(json.dumps(
        state["work_units"][merge_keys[0]]
    ))
    state_path = positive_scratchpad / "_artifact_state.json"
    state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    fixed_files = {
        "_chain_iter2_merge_receipt.json": b'{"legacy":"receipt"}\n',
        "_chain_iter2_merge_intent.json": b'{"legacy":"intent"}\n',
        "_chain_iter2_merge_failure.json": b'{"legacy":"failure"}\n',
    }
    for name, body in fixed_files.items():
        (positive_scratchpad / name).write_bytes(body)
    frozen_state = state_path.read_bytes()

    scoped_replay, scoped_replay_issues = (
        D._run_and_record_chain_iter2_driver_merge(
            positive_scratchpad,
            positive_config,
        )
    )
    assert scoped_replay_issues == []
    assert scoped_replay == merged
    assert state_path.read_bytes() == frozen_state
    assert all(
        (positive_scratchpad / name).read_bytes() == body
        for name, body in fixed_files.items()
    )
    legacy_issues = D._chain_tail_phase_completion_issues(
        positive_scratchpad,
        expected_run_id=positive_config["_run_id"],
        config=positive_config,
    )
    legacy_issue = next(
        issue
        for issue in legacy_issues
        if "CHAIN_TAIL_LEGACY_FIXED_GENERATION" in issue
    )
    assert all(key in legacy_issue for key in legacy_keys)
    assert all(name in legacy_issue for name in fixed_files)
    assert state_path.read_bytes() == frozen_state
    assert all(
        (positive_scratchpad / name).read_bytes() == body
        for name, body in fixed_files.items()
    )


def test_current_driver_merge_replay_is_read_only_and_exact(
    monkeypatch,
    _restored_completed_driver_merge,
):
    scratchpad, config, committed_receipt = (
        _restored_completed_driver_merge
    )
    before = _scratchpad_file_bytes(scratchpad)

    def forbidden_arm(**_kwargs):
        raise AssertionError(
            "committed current-generation replay must be read-only"
        )

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", forbidden_arm
    )
    replayed, replay_issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad, config
    )

    assert replay_issues == []
    assert replayed == committed_receipt
    assert len(replayed["events"]) == 2
    assert len({
        event["artifact_identity"] for event in replayed["events"]
    }) == 2
    assert _scratchpad_file_bytes(scratchpad) == before


@pytest.mark.parametrize(
    "mutation",
    (
        "one_current_one_prior_binding",
        "target_binding_digest",
        "committed_authority",
        "missing_receipt",
        "malformed_receipt",
        "receipt_shape_mismatch",
        "receipt_identity_delta_mismatch",
        "receipt_source_mismatch",
        "receipt_event_mismatch",
        "receipt_target_before_mismatch",
        "receipt_target_mismatch",
        "live_target_mismatch",
        "current_unit_absent",
        "invalid_execution_state",
        "quarantined_semantic_status",
    ),
)
def test_current_driver_merge_replay_authority_fails_closed_without_mutation(
    monkeypatch,
    _restored_completed_driver_merge,
    mutation: str,
):
    scratchpad, config, _committed_receipt = (
        _restored_completed_driver_merge
    )
    state_path = scratchpad / "_artifact_state.json"
    receipt_path = (
        scratchpad
        / "_chain_iter2_merge_receipt.p0000.s0001.json"
    )
    state = json.loads(state_path.read_text(encoding="utf-8"))
    merge_key = _terminal_work_unit_key(
        config, "driver_merge", 0, 1
    )
    target_identities = (
        "scratchpad:chain_hypotheses.md",
        "scratchpad:composition_coverage.md",
    )
    if mutation == "one_current_one_prior_binding":
        state["artifact_bindings"][target_identities[0]][
            "owner_key"
        ] = "sc/thorough/evm/codex/chain_agent2/model"
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif mutation == "target_binding_digest":
        state["artifact_bindings"][target_identities[0]][
            "sha256"
        ] = "0" * 64
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif mutation == "committed_authority":
        _tamper_committed_unit_authority(
            scratchpad,
            work_unit_key=merge_key,
            mutation="launch_manifest",
        )
    elif mutation == "missing_receipt":
        receipt_path.rename(
            receipt_path.with_name(receipt_path.name + ".fixture-away")
        )
    elif mutation == "malformed_receipt":
        receipt_path.write_bytes(b"{malformed")
    elif mutation in {
        "receipt_shape_mismatch",
        "receipt_identity_delta_mismatch",
        "receipt_source_mismatch",
        "receipt_event_mismatch",
        "receipt_target_before_mismatch",
        "receipt_target_mismatch",
    }:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if mutation == "receipt_shape_mismatch":
            receipt["unexpected_field"] = "must fail exact v1 shape"
        elif mutation == "receipt_identity_delta_mismatch":
            receipt["added_chain_ids"] = ["FORGED-DELTA"]
        elif mutation == "receipt_source_mismatch":
            receipt["source_sha256"] = "0" * 64
        elif mutation == "receipt_event_mismatch":
            receipt["events"][0]["after_sha256"] = "0" * 64
        elif mutation == "receipt_target_before_mismatch":
            receipt["targets"]["chain_hypotheses.md"][
                "before_sha256"
            ] = "0" * 64
        else:
            receipt["targets"]["chain_hypotheses.md"][
                "after_sha256"
            ] = "0" * 64
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif mutation == "live_target_mismatch":
        (scratchpad / "chain_hypotheses.md").write_bytes(
            b"# externally modified current target\n"
        )
    elif mutation == "current_unit_absent":
        state["work_units"].pop(merge_key)
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif mutation == "invalid_execution_state":
        state["work_units"][merge_key]["execution_state"] = (
            "INVALID_CURRENT_STATE"
        )
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif mutation == "quarantined_semantic_status":
        state["work_units"][merge_key]["semantic_status"] = (
            "QUARANTINED"
        )
        state_path.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        raise AssertionError(f"unknown current replay mutation: {mutation}")
    before = _scratchpad_file_bytes(scratchpad)

    def forbidden_arm(**_kwargs):
        raise AssertionError(
            "invalid current-generation claim must fail read-only"
        )

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", forbidden_arm
    )
    failed, failure_issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad, config
    )

    expected_issue = (
        "chain iteration 2 driver merge current-generation replay "
        "authority invalid"
    )
    assert failed == {
        "status": "FAILED",
        "issues": [expected_issue],
    }, mutation
    assert failure_issues == [expected_issue], mutation
    assert _scratchpad_file_bytes(scratchpad) == before, mutation


def test_driver_merge_preexecution_recovery_retains_lineage_admission(
    tmp_path: Path,
    monkeypatch,
):
    project_root = tmp_path / "preexecution-recovery"
    project_root.mkdir()
    scratchpad, config, _phase_row = _prepare_one_driver_merge(
        project_root
    )
    contract, launch = D._chain_iter2_driver_merge_contract_and_launch(
        scratchpad, config
    )
    execute, arm_issues = D._arm_deterministic_driver_work_unit(
        scratchpad=scratchpad,
        project_root=project_root,
        contract=contract,
        launch=launch,
        run_id=config["_run_id"],
    )
    assert execute is True
    assert arm_issues == []
    merge_key = _terminal_work_unit_key(
        config, "driver_merge", 0, 1
    )
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    merge_unit = state["work_units"][merge_key]
    assert merge_unit["execution_state"] == (
        "INPUTS_BOUND_PREEXECUTION"
    )
    assert merge_unit["artifacts"] == {}
    assert all(
        state["artifact_bindings"][identity]["owner_key"] != merge_key
        for identity in (
            "scratchpad:chain_hypotheses.md",
            "scratchpad:composition_coverage.md",
        )
    )
    state_path = scratchpad / "_artifact_state.json"
    preexecution_state = state_path.read_bytes()
    preexecution_tree = _scratchpad_file_bytes(scratchpad)
    state_identity = state_path.stat().st_ino
    original_arm = D._arm_deterministic_driver_work_unit

    def forbidden_arm(**_kwargs):
        raise AssertionError(
            "malformed current PREEXECUTION must fail before arm"
        )

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", forbidden_arm
    )
    expected_issue = (
        "chain iteration 2 driver merge current-generation replay "
        "authority invalid"
    )
    for mutation in (
        "run_id",
        "contract_digest",
        "launch_digest",
        "input_binding_sha256",
    ):
        malformed = json.loads(preexecution_state.decode("utf-8"))
        merge_unit = malformed["work_units"][merge_key]
        if mutation == "input_binding_sha256":
            merge_unit["input_bindings"][
                "scratchpad:chain_iteration2.md"
            ]["sha256"] = "0" * 64
        else:
            merge_unit[mutation] = (
                "other-run"
                if mutation == "run_id"
                else "0" * 64
            )
        state_path.write_text(
            json.dumps(malformed, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        malformed_tree = _scratchpad_file_bytes(scratchpad)

        failed, failure_issues = (
            D._run_and_record_chain_iter2_driver_merge(
                scratchpad, config
            )
        )

        assert failed == {
            "status": "FAILED",
            "issues": [expected_issue],
        }, mutation
        assert failure_issues == [expected_issue], mutation
        assert _scratchpad_file_bytes(scratchpad) == malformed_tree
        state_path.write_bytes(preexecution_state)
        assert _scratchpad_file_bytes(scratchpad) == preexecution_tree
        assert state_path.stat().st_ino == state_identity
        _assert_current_reconcile_parent_authority(
            project_root, scratchpad, config
        )
    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", original_arm
    )

    recovered, recovery_issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad, config
    )

    assert recovery_issues == []
    assert recovered["status"] == "APPLIED"
    recovered_state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    assert recovered_state["work_units"][merge_key][
        "execution_state"
    ] == "OUTPUT_COMMITTED"
    assert all(
        recovered_state["artifact_bindings"][identity]["owner_key"]
        == merge_key
        for identity in (
            "scratchpad:chain_hypotheses.md",
            "scratchpad:composition_coverage.md",
        )
    )


def test_driver_merge_rejects_raw_unowned_existing_prestates(
    tmp_path: Path,
):
    scratchpad, config, phase, _isolated = _commit_one_isolated_model(
        tmp_path
    )
    final, final_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert final_issues == []
    assert final["status"] == "COMPLETE"

    receipt, issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad, config
    )

    expected = (
        "chain iteration 2 driver merge requires one strictly earlier "
        "monotonic prestate lineage"
    )
    assert receipt["status"] == "FAILED"
    assert issues == [expected]
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    assert _terminal_work_unit_key(
        config, "driver_merge", 0, 1
    ) not in state["work_units"]


def test_first_driver_merge_after_rearm_accepts_one_exact_model_sibling_pair(
    tmp_path: Path,
    monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [_row(1), _row(2)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"

    def model_success(_phase, inner_config, _attempt):
        active = config["_chain_tail_active_isolated"]
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            active["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    coverage, hypotheses = _primary_source_bytes(b"\n")
    _commit_chain_agent2_model(
        tmp_path,
        scratchpad,
        config,
        coverage=coverage,
        hypotheses=hypotheses,
    )
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    assert D._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0
    first, first_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert first_issues == []
    assert first["status"] == "DEGRADED_UNRESOLVED"
    assert not (
        scratchpad / "_chain_iter2_merge_receipt.p0000.s0001.json"
    ).exists()

    rearmed, rearm_issues = D._run_chain_tail_rearm_transaction(
        scratchpad, config, phase
    )
    assert rearm_issues == []
    assert rearmed["status"] == "CONTINUE"
    config.pop("_chain_tail_active_isolated", None)
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    assert D._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0
    second, second_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert second_issues == []
    assert second["status"] == "COMPLETE"

    state_path = scratchpad / "_artifact_state.json"
    pristine_state = state_path.read_bytes()
    mixed_state = json.loads(pristine_state.decode("utf-8"))
    mixed_state["artifact_bindings"][
        "scratchpad:composition_coverage.md"
    ]["owner_key"] = _terminal_work_unit_key(
        config, "driver_merge", 0, 1
    )
    state_path.write_text(
        json.dumps(mixed_state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    rejected, rejected_issues = (
        D._run_and_record_chain_iter2_driver_merge(
            scratchpad, config
        )
    )
    assert rejected["status"] == "FAILED"
    assert rejected_issues == [
        "chain iteration 2 driver merge requires one strictly earlier "
        "monotonic prestate lineage"
    ]
    assert _terminal_work_unit_key(
        config, "driver_merge", 1, 2
    ) not in json.loads(
        state_path.read_text(encoding="utf-8")
    )["work_units"]
    state_path.write_bytes(pristine_state)

    merged, merge_issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad, config
    )

    assert merge_issues == []
    assert merged["status"] == "APPLIED"
    assert merged["work_unit_key"] == _terminal_work_unit_key(
        config, "driver_merge", 1, 2
    )
    assert (
        scratchpad / "_chain_iter2_merge_receipt.p0001.s0002.json"
    ).is_file()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert _terminal_work_unit_key(
        config, "driver_merge", 0, 1
    ) not in state["work_units"]
    assert _terminal_work_unit_key(
        config, "driver_merge", 1, 2
    ) in state["work_units"]


def test_terminal_generation_handoffs_require_exact_tuple_relations():
    prefix = "sc/thorough/evm/codex/"

    def key(role: str, generation: str) -> str:
        return f"{prefix}chain_iter2/{role}.{generation}"

    snapshot_identity = "scratchpad:chain_tail_terminal_snapshot.json"
    root_identity = f"scratchpad:{CTA.LEDGER_NAME}"
    control_identity = (
        f"scratchpad:{CTA.CONTROL_DIR}/{CTA.LEDGER_NAME}"
    )
    merge_identity = "scratchpad:chain_hypotheses.md"

    for role, identity in (
        ("tail_snapshot", snapshot_identity),
        ("tail_reconcile", root_identity),
        ("driver_merge", merge_identity),
    ):
        assert registered_projection_handoff(
            key(role, "p0000.s0001"),
            key(role, "p0001.s0001"),
            identity,
        )
        assert registered_projection_handoff(
            key(role, "p0000.s0001"),
            key(role, "p0002.s0000"),
            identity,
        )
        assert not registered_projection_handoff(
            key(role, "p0000.s0001"),
            key(role, "p0000.s0001"),
            identity,
        )
        assert not registered_projection_handoff(
            key(role, "p0001.s0001"),
            key(role, "p0000.s9999"),
            identity,
        )

    assert registered_projection_handoff(
        key("tail_snapshot", "p0003.s0007"),
        key("tail_reconcile", "p0003.s0007"),
        snapshot_identity,
    )
    assert not registered_projection_handoff(
        key("tail_snapshot", "p0003.s0007"),
        key("tail_reconcile", "p0003.s0008"),
        snapshot_identity,
    )
    assert registered_projection_handoff(
        key("tail_reconcile", "p0003.s0007"),
        key("driver_merge", "p0003.s0007"),
        "scratchpad:chain_iteration2.md",
    )
    assert not registered_projection_handoff(
        key("tail_reconcile", "p0003.s0007"),
        key("driver_merge", "p0004.s0007"),
        "scratchpad:chain_iteration2.md",
    )
    assert registered_projection_handoff(
        key("tail_reconcile", "p0003.s0007"),
        f"{prefix}chain_iter2/tail_rearm_control.p0004.s0007",
        root_identity,
    )
    assert registered_projection_handoff(
        key("tail_reconcile", "p0003.s0007"),
        f"{prefix}chain_iter2/tail_rearm_control.p0004.s0007",
        control_identity,
    )
    assert not registered_projection_handoff(
        key("tail_reconcile", "p0003.s0007"),
        f"{prefix}chain_iter2/tail_rearm_control.p0004.s0008",
        root_identity,
    )

    model_key = f"{prefix}chain_agent2/model"
    for generation in ("p0000.s0007", "p0001.s0007", "p0099.s1234"):
        assert registered_projection_handoff(
            model_key,
            key("driver_merge", generation),
            merge_identity,
        )
    assert not registered_projection_handoff(
        model_key,
        key("driver_merge", "p0001.s0007"),
        "scratchpad:synthesis_full.md",
    )
    assert not registered_projection_handoff(
        f"{prefix}chain/model",
        key("driver_merge", "p0001.s0007"),
        merge_identity,
    )


def test_fixed_terminal_work_units_are_explicit_legacy_debt():
    common = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "codex",
        "phase": "chain_iter2",
    }
    for fixed_role in ("tail_snapshot", "tail_reconcile", "driver_merge"):
        with pytest.raises(
            ValueError,
            match="CHAIN_TAIL_LEGACY_FIXED_GENERATION",
        ):
            resolve_phase_io_contract(
                **common,
                work_unit_id=fixed_role,
            )
    for malformed in (
        "tail_snapshot.p000.s0000",
        "tail_snapshot.p10000.s0000",
        "tail_reconcile.p0000.s0000.lookalike",
        "driver_merge.p0000.s000",
    ):
        with pytest.raises(
            ValueError,
            match="CHAIN_TAIL_TERMINAL_GENERATION_MALFORMED",
        ):
            resolve_phase_io_contract(
                **common,
                work_unit_id=malformed,
            )
    normalized_alias = resolve_phase_io_contract(
        **common,
        work_unit_id="driver_merge.P0000.s0000",
    )
    assert normalized_alias.work_unit_id == "driver_merge.p0000.s0000"

    snapshot = resolve_phase_io_contract(
        **common,
        work_unit_id="tail_snapshot.p0004.s0000",
        exact_inputs=(
            CTA.CONTROL_MANIFEST_PATH,
            *CTA.MUTABLE_CONTROL_PATHS,
        ),
        exact_outputs=(CTA.TERMINAL_SNAPSHOT_NAME,),
    )
    assert snapshot.outputs[0].consumers == (
        "chain_iter2/tail_reconcile.p0004.s0000",
    )
    assert snapshot.outputs[0].schema_version == (
        CTA.TERMINAL_SNAPSHOT_SCHEMA
    )
    with pytest.raises(
        ValueError,
        match="snapshot input denominator",
    ):
        resolve_phase_io_contract(
            **common,
            work_unit_id="tail_snapshot.p0004.s0000",
            exact_inputs=(CTA.CONTROL_MANIFEST_PATH,),
            exact_outputs=(CTA.TERMINAL_SNAPSHOT_NAME,),
        )
    shard_zero_required = tuple(
        f"{CTA.SHARD_ARCHIVE_DIR}/shard_0000/{name}"
        for name in (
            "work_unit.json",
            "terminal_plan.json",
            "disposition_receipt.json",
        )
    )
    with pytest.raises(
        ValueError,
        match="snapshot input denominator",
    ):
        resolve_phase_io_contract(
            **common,
            work_unit_id="tail_snapshot.p0004.s0001",
            exact_inputs=(
                CTA.CONTROL_MANIFEST_PATH,
                *CTA.MUTABLE_CONTROL_PATHS,
                *shard_zero_required[:-1],
            ),
            exact_outputs=(CTA.TERMINAL_SNAPSHOT_NAME,),
        )
    reconcile_outputs = (
        CTA.LEDGER_NAME,
        CTA.RECEIPT_NAME,
        CTA.COMPOSITION_CANDIDATES_NAME,
        CTA.PROJECTION_NAME,
        "chain_iteration2.md",
        *CTA.MUTABLE_CONTROL_PATHS,
    )
    reconcile = resolve_phase_io_contract(
        **common,
        work_unit_id="tail_reconcile.p0004.s0000",
        exact_inputs=(
            CTA.CONTROL_MANIFEST_PATH,
            CTA.TERMINAL_SNAPSHOT_NAME,
        ),
        exact_outputs=reconcile_outputs,
    )
    assert set(reconcile.immutable_inputs) == {
        f"scratchpad:{CTA.CONTROL_MANIFEST_PATH}",
        f"scratchpad:{CTA.TERMINAL_SNAPSHOT_NAME}",
    }
    with pytest.raises(
        ValueError,
        match="publication input denominator",
    ):
        resolve_phase_io_contract(
            **common,
            work_unit_id="tail_reconcile.p0004.s0000",
            exact_inputs=(CTA.CONTROL_MANIFEST_PATH,),
            exact_outputs=reconcile_outputs,
        )


def test_terminal_producer_key_parser_rejects_prefix_and_suffix_lookalikes():
    generation_id = "p0003.s0007"
    valid_reconcile = (
        "sc/thorough/evm/codex/chain_iter2/"
        f"tail_reconcile.{generation_id}"
    )
    valid_snapshot = (
        "sc/thorough/evm/codex/chain_iter2/"
        f"tail_snapshot.{generation_id}"
    )
    assert CTA._terminal_producer_prefix(
        valid_reconcile,
        role="tail_reconcile",
        generation_id=generation_id,
    ) == ("sc", "thorough", "evm", "codex", "chain_iter2")
    assert CTA._terminal_producer_prefix(
        valid_snapshot,
        role="tail_snapshot",
        generation_id=generation_id,
    ) == ("sc", "thorough", "evm", "codex", "chain_iter2")

    invalid = (
        f"evil/{valid_reconcile}",
        f"{valid_reconcile}/extra",
        f"{valid_reconcile}.lookalike",
        valid_reconcile.replace(
            "/chain_iter2/",
            "/chain_iter2.evil/",
        ),
        valid_reconcile.replace(
            "tail_reconcile.",
            "evil_tail_reconcile.",
        ),
    )
    for candidate in invalid:
        with pytest.raises(
            CTA.ChainTailAuthorityError,
            match="exact generation-scoped key",
        ):
            CTA._terminal_producer_prefix(
                candidate,
                role="tail_reconcile",
                generation_id=generation_id,
            )


def test_terminal_generation_helper_rejects_an_active_shard(
    tmp_path: Path,
):
    scratchpad, _shard, _isolated = _isolated_one(tmp_path)
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="not quiescent and bounded",
    ):
        CTA.chain_tail_control_generation(scratchpad)
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="not quiescent and bounded",
    ):
        D._current_chain_tail_generation(scratchpad)
    failed, failed_issues = D._run_and_record_chain_iter2_driver_merge(
        scratchpad,
        _config(tmp_path, scratchpad),
    )
    assert failed["status"] == "FAILED"
    assert "work_unit_key" not in failed
    assert "contract_digest" not in failed
    assert failed_issues == [
        "chain iteration 2 merge PhaseIO failed: "
        "ChainTailAuthorityError: chain-tail terminal generation is not "
        "quiescent and bounded"
    ]
    assert failed["issues"] == failed_issues
    assert not any(
        (scratchpad / name).exists()
        for name in (
            "_chain_iter2_merge_receipt.json",
            "_chain_iter2_merge_intent.json",
            "_chain_iter2_merge_failure.json",
        )
    )
    assert list(scratchpad.glob("_chain_iter2_merge_*.json")) == []
    state_path = scratchpad / "_artifact_state.json"
    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        assert state.get("work_units", {}) == {}
    ledger_path = scratchpad / CTA.CONTROL_DIR / CTA.LEDGER_NAME
    baseline = json.loads(ledger_path.read_text(encoding="utf-8"))
    for malformed_active in ("active", [], [1]):
        malformed = json.loads(json.dumps(baseline))
        malformed["active_shard"] = malformed_active
        malformed["ledger_sha256"] = CTA._digest(
            malformed, "ledger_sha256"
        )
        ledger_path.write_text(
            json.dumps(malformed, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with pytest.raises(
            CTA.ChainTailAuthorityError,
            match="not quiescent and bounded",
        ):
            CTA.chain_tail_control_generation(scratchpad)


def test_terminal_snapshot_uses_committed_transcript_not_archive(
    tmp_path: Path,
):
    root = tmp_path / "committed"
    root.mkdir()
    scratchpad, _config_value, _phase_value, isolated = (
        _commit_one_isolated_model(root)
    )
    baseline = CTA.build_chain_tail_terminal_snapshot(scratchpad)
    legacy_archive = (
        scratchpad / CTA.SHARD_ARCHIVE_DIR / "shard_0000.md"
    )
    legacy_archive.write_text(
        "# mutable legacy archive\nnot committed evidence\n",
        encoding="utf-8",
    )
    assert CTA.build_chain_tail_terminal_snapshot(scratchpad) == baseline
    legacy_archive.write_text(
        "# tampered mutable legacy archive\n",
        encoding="utf-8",
    )
    assert CTA.build_chain_tail_terminal_snapshot(scratchpad) == baseline
    second_archive = (
        scratchpad / CTA.SHARD_ARCHIVE_DIR / "shard_0001.md"
    )
    second_archive.write_text("# cross-shard substitution\n", encoding="utf-8")
    legacy_archive.write_bytes(second_archive.read_bytes())
    assert CTA.build_chain_tail_terminal_snapshot(scratchpad) == baseline
    legacy_archive.unlink()
    assert CTA.build_chain_tail_terminal_snapshot(scratchpad) == baseline

    transcript = scratchpad / isolated["transcript_path"]
    transcript.write_text(
        "# tampered committed transcript\n",
        encoding="utf-8",
    )
    issues = D._chain_tail_final_reconcile_readiness_issues(scratchpad)
    assert any("transcript digest mismatch" in issue for issue in issues)


def test_orphan_chain_section_is_visible_debt_not_silently_dropped(
    tmp_path: Path,
):
    scratchpad, shard, isolated = _isolated_one(tmp_path)
    output = scratchpad / isolated["transcript_path"]
    _write_output(output, shard["rows"])
    original = output.read_text(encoding="utf-8")
    output.write_text(
        "# Chain Iteration 2\n\n"
        "## Chain Hypothesis CH-77\n\n"
        "A model-proposed chain with no pair-table reference.\n\n"
        + original.split("## Tail Pair Dispositions", 1)[1].join(
            ("## Tail Pair Dispositions", "")
        ),
        encoding="utf-8",
    )
    CTA.reconcile_chain_tail_output(
        scratchpad,
        output_name=isolated["transcript_path"],
        disposition_receipt_name=isolated["disposition_receipt_path"],
    )
    disposition = json.loads(
        (scratchpad / isolated["disposition_receipt_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert "ORPHAN_CHAIN_SECTION" in disposition["issues"]
    candidates = json.loads(
        (
            scratchpad
            / CTA.CONTROL_DIR
            / CTA.COMPOSITION_CANDIDATES_NAME
        ).read_text(encoding="utf-8")
    )
    assert any(
        row.get("chain_id") == "CH-77"
        and row.get("route") == "HUMAN_REVIEW"
        for row in candidates["candidates"]
    )


def test_final_publication_capability_is_consumed_until_new_prearm(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [], shard_size=1
    )
    config = _prepare_zero_work_primary_predecessor(
        tmp_path, scratchpad
    )
    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, _phase()
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"
    assert not (
        scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    ).exists()
    frozen = _all_fixture_file_bytes(scratchpad)
    snapshot = json.loads(
        (
            scratchpad / CTA.TERMINAL_SNAPSHOT_NAME
        ).read_text(encoding="utf-8")
    )
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 0, 0
    )
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    final_unit = state["work_units"][final_key]

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="chain-tail final publication capability is absent",
    ):
        CTA.commit_final_chain_tail_publication(
            scratchpad,
            snapshot_sha256=str(snapshot["snapshot_sha256"]),
            producer_key=final_key,
            producer_contract_digest=str(
                final_unit["contract_digest"]
            ),
        )

    assert _all_fixture_file_bytes(scratchpad) == frozen


def test_complete_zero_work_rearm_rejects_before_any_mutation(
    tmp_path: Path,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [], shard_size=1
    )
    config = _prepare_zero_work_primary_predecessor(
        tmp_path, scratchpad
    )
    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, _phase()
    )
    assert issues == []
    assert receipt["status"] == "COMPLETE"
    frozen = _all_fixture_file_bytes(scratchpad)

    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="chain-tail rearm has no unresolved denominator",
    ):
        CTA.rearm_unresolved_chain_tail(scratchpad)

    assert _all_fixture_file_bytes(scratchpad) == frozen
    assert not any(
        path.name.endswith(".tmp")
        for path in scratchpad.rglob("*")
        if path.is_file()
    )


def test_three_publication_generations_preserve_pass_and_republish(
    tmp_path: Path,
    monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [_row(1), _row(2), _row(3)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"

    def model_success(_phase, inner_config, _attempt):
        active = config["_chain_tail_active_isolated"]
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            active["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    assert D._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0

    first, first_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert first_issues == []
    assert first["status"] == "DEGRADED_UNRESOLVED"
    first_snapshot = json.loads(
        (scratchpad / CTA.TERMINAL_SNAPSHOT_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert first_snapshot["schema_version"] == CTA.TERMINAL_SNAPSHOT_SCHEMA
    assert first_snapshot["terminal_generation"] == {
        "pass_index": 0,
        "shard_count": 1,
        "generation_id": "p0000.s0001",
    }
    assert first_snapshot["semantic_ledger"]["pass_index"] == 0
    canonical_names = (
        CTA.LEDGER_NAME,
        CTA.RECEIPT_NAME,
        CTA.COMPOSITION_CANDIDATES_NAME,
        CTA.PROJECTION_NAME,
        "chain_iteration2.md",
    )
    first_root_bytes = {
        name: (scratchpad / name).read_bytes()
        for name in canonical_names
    }
    assert CTA._terminal_publication_is_complete(scratchpad) is True

    control_ledger_path = (
        scratchpad / CTA.CONTROL_DIR / CTA.LEDGER_NAME
    )
    pristine_control_ledger = control_ledger_path.read_bytes()
    for field in ("cursor", "shards"):
        mutated_control = json.loads(
            pristine_control_ledger.decode("utf-8")
        )
        if field == "cursor":
            mutated_control["cursor"] = (
                int(mutated_control.get("cursor") or 0) + 1
            )
        else:
            mutated_control["shards"] = []
        mutated_control["ledger_sha256"] = CTA._digest(
            mutated_control, "ledger_sha256"
        )
        control_ledger_path.write_text(
            json.dumps(mutated_control),
            encoding="utf-8",
        )
        assert (
            CTA._terminal_publication_is_complete(scratchpad) is False
        ), field
        control_ledger_path.write_bytes(pristine_control_ledger)
        assert CTA._terminal_publication_is_complete(scratchpad) is True

    shard_archive_prestate = sorted(
        path.relative_to(scratchpad).as_posix()
        for path in (scratchpad / CTA.SHARD_ARCHIVE_DIR).rglob("*")
    )
    rearmed, rearm_issues = D._run_chain_tail_rearm_transaction(
        scratchpad, config, phase
    )
    assert rearm_issues == []
    assert rearmed["status"] == "CONTINUE"
    assert sorted(
        path.relative_to(scratchpad).as_posix()
        for path in (scratchpad / CTA.SHARD_ARCHIVE_DIR).rglob("*")
    ) == shard_archive_prestate
    assert {
        name: (scratchpad / name).read_bytes()
        for name in canonical_names
    } == first_root_bytes
    assert CTA._terminal_publication_is_complete(scratchpad) is False

    config.pop("_chain_tail_active_isolated", None)
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    assert D._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0
    assert {
        name: (scratchpad / name).read_bytes()
        for name in canonical_names
    } == first_root_bytes

    second, second_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert second_issues == []
    assert second["status"] == "DEGRADED_UNRESOLVED"
    second_snapshot = json.loads(
        (scratchpad / CTA.TERMINAL_SNAPSHOT_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert second_snapshot["terminal_generation"] == {
        "pass_index": 1,
        "shard_count": 2,
        "generation_id": "p0001.s0002",
    }
    assert second_snapshot["semantic_ledger"]["pass_index"] == 1
    second_root_bytes = {
        name: (scratchpad / name).read_bytes()
        for name in canonical_names
    }
    assert second_root_bytes != first_root_bytes
    assert not (
        scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    ).exists()
    assert CTA._terminal_publication_is_complete(scratchpad) is True

    rearmed, rearm_issues = D._run_chain_tail_rearm_transaction(
        scratchpad, config, phase
    )
    assert rearm_issues == []
    assert rearmed["status"] == "CONTINUE"
    config.pop("_chain_tail_active_isolated", None)
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    assert D._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0
    third, third_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert third_issues == []
    assert third["status"] == "COMPLETE"
    third_snapshot = json.loads(
        (scratchpad / CTA.TERMINAL_SNAPSHOT_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert third_snapshot["terminal_generation"] == {
        "pass_index": 2,
        "shard_count": 3,
        "generation_id": "p0002.s0003",
    }
    assert third_snapshot["semantic_ledger"]["pass_index"] == 2
    assert CTA._terminal_publication_is_complete(scratchpad) is True

    state_path = scratchpad / "_artifact_state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    for pass_index, shard_count in ((0, 1), (1, 2), (2, 3)):
        assert _terminal_work_unit_key(
            config, "tail_snapshot", pass_index, shard_count
        ) in state["work_units"]
        assert _terminal_work_unit_key(
            config, "tail_reconcile", pass_index, shard_count
        ) in state["work_units"]
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 2, 3
    )
    state["work_units"][final_key]["launch_manifest"][
        "model"
    ] = "tampered-model"
    state_path.write_text(
        json.dumps(state, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    assert CTA._terminal_publication_is_complete(scratchpad) is False


@pytest.mark.parametrize(
    "failure_stage",
    (
        "POST_ARM",
        "POST_SUCCESSOR_STEP_1",
        "POST_SUCCESSOR_STEP_2",
        "POST_SUCCESSOR_STEP_3",
        "POST_SUCCESSOR_STEP_4",
        "ALL_5_PRECOMMIT",
        "POST_COMMIT",
    ),
)
def test_typed_rearm_transaction_recovers_each_commit_boundary_once(
    tmp_path: Path,
    monkeypatch,
    failure_stage: str,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path,
        scratchpad,
        [_row(1), _row(2)],
        shard_size=1,
        backend="codex",
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"

    def model_success(_phase, inner_config, _attempt):
        active = config["_chain_tail_active_isolated"]
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            active["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    assert D._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    assert D._run_isolated_chain_tail_model_attempt(
        phase, config, 1
    ) == 0
    first, first_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert first_issues == []
    assert first["status"] == "DEGRADED_UNRESOLVED"
    assert CTA._terminal_publication_is_complete(scratchpad) is True

    root_names = (
        CTA.LEDGER_NAME,
        CTA.RECEIPT_NAME,
        CTA.COMPOSITION_CANDIDATES_NAME,
        CTA.PROJECTION_NAME,
        "chain_iteration2.md",
    )
    frozen_root = {
        name: (scratchpad / name).read_bytes()
        for name in root_names
    }
    frozen_archive = {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in (scratchpad / CTA.SHARD_ARCHIVE_DIR).rglob("*")
        if path.is_file()
    }
    control_prestate = {
        relative: (scratchpad / relative).read_bytes()
        for relative in CTA.MUTABLE_CONTROL_PATHS
    }
    planned_rearm = CTA.plan_rearm_unresolved_chain_tail(
        scratchpad
    )
    assert planned_rearm["pass_index"] == 1
    assert planned_rearm["next_shard_index"] == 1
    assert set(planned_rearm["postimages"]) == set(
        CTA.MUTABLE_CONTROL_PATHS
    )
    assert {
        relative: (scratchpad / relative).read_bytes()
        for relative in CTA.MUTABLE_CONTROL_PATHS
    } == control_prestate
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 0, 1
    )
    rearm_key = (
        "sc/thorough/evm/codex/chain_iter2/"
        "tail_rearm_control.p0001.s0001"
    )
    registered_identities = {
        *(
            f"scratchpad:{name}"
            for name in (
                CTA.LEDGER_NAME,
                CTA.RECEIPT_NAME,
                CTA.COMPOSITION_CANDIDATES_NAME,
                CTA.PROJECTION_NAME,
                "chain_iteration2.md",
            )
        ),
        *(
            f"scratchpad:{relative}"
            for relative in CTA.MUTABLE_CONTROL_PATHS
        ),
    }
    assert all(
        registered_projection_handoff(
            final_key, rearm_key, identity
        )
        for identity in registered_identities
    )
    assert not registered_projection_handoff(
        final_key, rearm_key, "scratchpad:unrelated.md"
    )
    assert not registered_projection_handoff(
        _terminal_work_unit_key(
            config, "tail_snapshot", 0, 1
        ),
        rearm_key,
        f"scratchpad:{CTA.LEDGER_NAME}",
    )
    assert not registered_projection_handoff(
        final_key,
        (
            "sc/thorough/evm/codex/chain_iter2/"
            "tail_shard_prepare_control.0001"
        ),
        f"scratchpad:{CTA.LEDGER_NAME}",
    )
    wrong_generation = dict(planned_rearm)
    wrong_generation["pass_index"] = 2
    assert CTA.validate_rearm_unresolved_chain_tail_generation(
        scratchpad, wrong_generation
    )
    with pytest.raises(
        ValueError,
        match="rearm control generation denominator mismatch",
    ):
        resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="codex",
            phase="chain_iter2",
            work_unit_id="tail_rearm_control.p0001.s0001",
            exact_inputs=(
                CTA.CONTROL_MANIFEST_PATH,
                CTA.LEDGER_NAME,
                CTA.RECEIPT_NAME,
                CTA.COMPOSITION_CANDIDATES_NAME,
                CTA.PROJECTION_NAME,
                "chain_iteration2.md",
            ),
            exact_outputs=(
                *CTA.MUTABLE_CONTROL_PATHS,
                CTA.LEDGER_NAME,
            ),
        )
    original_arm = D._arm_deterministic_driver_work_unit
    original_commit = D._commit_deterministic_driver_work_unit
    original_complete = D.complete_driver_successor_step
    injected = {"done": False}
    completed_steps: dict[int, int] = {}

    def is_rearm_contract(args: tuple, kwargs: dict) -> bool:
        contract = (
            kwargs.get("contract")
            if kwargs.get("contract") is not None
            else args[2] if len(args) > 2 else None
        )
        return bool(
            contract is not None
            and str(contract.work_unit_id).startswith(
                "tail_rearm_control."
            )
        )

    def fail_after_arm(*args, **kwargs):
        result = original_arm(*args, **kwargs)
        if (
            failure_stage == "POST_ARM"
            and is_rearm_contract(args, kwargs)
            and not injected["done"]
        ):
            injected["done"] = True
            assert result == (True, [])
            raise OSError("injected rearm crash after arm")
        return result

    def fail_after_successor_step(*args, **kwargs):
        result = original_complete(*args, **kwargs)
        if is_rearm_contract(args, kwargs):
            ordinal = int(kwargs.get("ordinal") or 0)
            completed_steps[ordinal] = (
                completed_steps.get(ordinal, 0) + 1
            )
            if (
                failure_stage == f"POST_SUCCESSOR_STEP_{ordinal}"
                and not injected["done"]
            ):
                injected["done"] = True
                raise OSError(
                    "injected rearm crash after successor step "
                    f"{ordinal}"
                )
        return result

    def fail_at_commit_boundary(*args, **kwargs):
        if (
            failure_stage == "ALL_5_PRECOMMIT"
            and is_rearm_contract(args, kwargs)
            and not injected["done"]
        ):
            injected["done"] = True
            raise OSError("injected rearm crash before commit")
        result = original_commit(*args, **kwargs)
        if (
            failure_stage == "POST_COMMIT"
            and is_rearm_contract(args, kwargs)
            and not injected["done"]
        ):
            injected["done"] = True
            assert result == []
            raise OSError("injected rearm crash after commit")
        return result

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", fail_after_arm
    )
    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit",
        fail_at_commit_boundary,
    )
    monkeypatch.setattr(
        D, "complete_driver_successor_step",
        fail_after_successor_step,
    )
    _failed, failure_issues = D._run_chain_tail_rearm_transaction(
        scratchpad, config, phase
    )
    assert injected["done"] is True
    assert any("injected rearm crash" in issue for issue in failure_issues)
    assert {
        name: (scratchpad / name).read_bytes()
        for name in root_names
    } == frozen_root
    assert {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in (scratchpad / CTA.SHARD_ARCHIVE_DIR).rglob("*")
        if path.is_file()
    } == frozen_archive

    monkeypatch.setattr(
        D, "_arm_deterministic_driver_work_unit", original_arm
    )
    monkeypatch.setattr(
        D, "_commit_deterministic_driver_work_unit", original_commit
    )
    recovered, recovery_issues = D._run_chain_tail_rearm_transaction(
        scratchpad, config, phase
    )
    assert recovery_issues == []
    assert recovered["status"] == "CONTINUE"
    assert recovered["pass_index"] == 1
    control_postimage = {
        relative: (scratchpad / relative).read_bytes()
        for relative in CTA.MUTABLE_CONTROL_PATHS
    }
    assert control_postimage == planned_rearm["postimages"]
    assert CTA.validate_rearm_unresolved_chain_tail_generation(
        scratchpad, planned_rearm
    ) == []
    assert completed_steps == {
        ordinal: 1 for ordinal in range(1, 6)
    }
    monkeypatch.setattr(
        D, "complete_driver_successor_step", original_complete
    )

    replayed, replay_issues = D._run_chain_tail_rearm_transaction(
        scratchpad, config, phase
    )
    assert replay_issues == []
    assert replayed == recovered
    assert {
        relative: (scratchpad / relative).read_bytes()
        for relative in CTA.MUTABLE_CONTROL_PATHS
    } == control_postimage
    assert {
        name: (scratchpad / name).read_bytes()
        for name in root_names
    } == frozen_root
    assert {
        path.relative_to(scratchpad).as_posix(): path.read_bytes()
        for path in (scratchpad / CTA.SHARD_ARCHIVE_DIR).rglob("*")
        if path.is_file()
    } == frozen_archive

    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(
            encoding="utf-8"
        )
    )
    rearm_keys = [
        key
        for key in state["work_units"]
        if "/chain_iter2/tail_rearm_control." in key
    ]
    assert rearm_keys == [rearm_key]
    rearm_unit = state["work_units"][rearm_keys[0]]
    assert rearm_unit["execution_state"] == "OUTPUT_COMMITTED"
    assert rearm_unit["semantic_status"] == "ACTIVE"


def test_final_marker_unlink_crash_recovers_after_output_commit_without_root_drift(
    tmp_path: Path, monkeypatch,
):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_sources(scratchpad)
    _initialize_with_live_producer(
        tmp_path, scratchpad, [_row(1)], shard_size=1, backend="codex"
    )
    phase = _phase()
    config = _config(tmp_path, scratchpad)
    config["cli_backend"] = "codex"
    assert D._bind_typed_model_phase_inputs(phase, scratchpad, config) == []
    isolated = config["_chain_tail_active_isolated"]

    def model_success(_phase, inner_config, _attempt):
        _write_output(
            Path(inner_config["scratchpad"]) / "chain_iteration2.md",
            isolated["rows"],
        )
        return 0

    monkeypatch.setattr(D, "run_phase", model_success)
    assert D._run_isolated_chain_tail_model_attempt(phase, config, 1) == 0
    original_commit = CTA.commit_final_chain_tail_publication
    injected = {"done": False}

    def fail_marker_unlink_once(*_args, **_kwargs):
        if not injected["done"]:
            injected["done"] = True
            raise OSError("injected final publication marker unlink failure")
        return original_commit(*_args, **_kwargs)

    monkeypatch.setattr(
        CTA, "commit_final_chain_tail_publication", fail_marker_unlink_once
    )
    _first, first_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )
    assert any("marker unlink failure" in issue for issue in first_issues)
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 0, 1
    )
    assert state["work_units"][final_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    marker = scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    assert marker.is_file()
    frozen = {
        name: (scratchpad / name).read_bytes()
        for name in (
            CTA.LEDGER_NAME,
            CTA.RECEIPT_NAME,
            CTA.COMPOSITION_CANDIDATES_NAME,
            CTA.PROJECTION_NAME,
            "chain_iteration2.md",
        )
    }

    second, second_issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )

    assert second_issues == []
    assert second["status"] == "COMPLETE"
    assert not marker.exists()
    assert all(
        (scratchpad / name).read_bytes() == body
        for name, body in frozen.items()
    )
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="^chain-tail rearm has no unresolved denominator$",
    ):
        CTA.rearm_unresolved_chain_tail(scratchpad)
    assert all(
        (scratchpad / name).read_bytes() == body
        for name, body in frozen.items()
    )


def _final_marker_unlink_boundary(
    root: Path,
    edge: str,
) -> tuple[Path, dict, Phase, dict, str]:
    """Produce one physical exact-current final commit at an unlink edge."""

    assert edge in {"BEFORE", "AFTER"}
    scratchpad, config, phase, _isolated = _commit_one_isolated_model(root)
    injected = {"done": False}

    def fail_exact_unlink(
        operation: str,
        observed_edge: str,
        path: Path,
    ) -> None:
        if (
            not injected["done"]
            and operation == "MARKER_UNLINK"
            and observed_edge == edge
            and path.name == CTA.PUBLICATION_ARMED_NAME
        ):
            injected["done"] = True
            raise OSError(
                f"injected exact marker unlink {edge.lower()} failure"
            )

    with CTA.observe_chain_tail_durable_transitions(fail_exact_unlink):
        _first, first_issues = D._run_chain_tail_final_reconcile_transaction(
            scratchpad, config, phase
        )
    assert injected["done"] is True
    assert any(
        f"marker unlink {edge.lower()} failure" in issue
        for issue in first_issues
    )
    final_key = _terminal_work_unit_key(
        config, "tail_reconcile", 0, 1
    )
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    final_unit = state["work_units"][final_key]
    assert final_unit["semantic_status"] == "ACTIVE"
    assert final_unit["execution_state"] == "OUTPUT_COMMITTED"
    marker = scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    assert marker.is_file() is (edge == "BEFORE")
    receipt = json.loads(
        (scratchpad / CTA.RECEIPT_NAME).read_text(encoding="utf-8")
    )
    return scratchpad, config, phase, receipt, final_key


def _all_fixture_file_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def _assert_final_replay_denominator_frozen(
    scratchpad: Path,
    *,
    final_key: str,
    require_output_authority_cas: bool = True,
) -> dict[str, bytes]:
    """Freeze every declared final byte plus the exact commit authorities."""

    frozen = _all_fixture_file_bytes(scratchpad)
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    final_unit = state["work_units"][final_key]
    output_authority_digest = str(
        final_unit["commit_authority"]["output_authority_digest"]
    )
    required = {
        "_artifact_state.json",
        "_artifact_output_authorities.json",
        CTA.TERMINAL_SNAPSHOT_NAME,
        D._CHAIN_TAIL_CONTROL_MANIFEST,
        *D._CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS,
    }
    output_authority_cas = (
        "_artifact_output_authority_cas/"
        f"{output_authority_digest}.json"
    )
    if require_output_authority_cas:
        required.add(output_authority_cas)
    else:
        assert output_authority_cas not in frozen
    assert required.issubset(frozen)
    assert len(D._CHAIN_TAIL_FINAL_PUBLICATION_OUTPUTS) == 10
    return frozen


@pytest.mark.parametrize("edge", ("BEFORE", "AFTER"))
def test_exact_current_final_marker_unlink_replay_is_read_only(
    tmp_path: Path,
    edge: str,
):
    root = tmp_path / edge.lower()
    root.mkdir()
    scratchpad, config, phase, expected_receipt, final_key = (
        _final_marker_unlink_boundary(root, edge)
    )
    frozen = _assert_final_replay_denominator_frozen(
        scratchpad, final_key=final_key
    )
    marker_relative = (
        f"{CTA.CONTROL_DIR}/{CTA.PUBLICATION_ARMED_NAME}"
    )

    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )

    assert issues == []
    assert receipt == expected_receipt
    assert receipt["status"] == "COMPLETE"
    expected_files = dict(frozen)
    if edge == "BEFORE":
        expected_files.pop(marker_relative)
    assert _all_fixture_file_bytes(scratchpad) == expected_files
    assert not (
        scratchpad
        / CTA.CONTROL_DIR
        / CTA.PUBLICATION_ARMED_NAME
    ).exists()
    assert not (
        scratchpad
        / CTA.CONTROL_DIR
        / f"{CTA.PUBLICATION_ARMED_NAME}.tmp"
    ).exists()


_FINAL_REPLAY_BEFORE_CORRUPTIONS = (
    "marker_digest",
    "marker_snapshot",
    "marker_producer",
    "marker_contract",
    "unit_run",
    "unit_status",
    "unit_state",
    "unit_snapshot_binding",
    "unit_commit_receipt",
    "unit_output_authority_cas",
    "live_receipt",
    "mixed_control_ledger",
)

_FINAL_REPLAY_AFTER_CORRUPTIONS = (
    "unit_status",
    "live_chain_output",
    "mixed_root_ledger",
)


def _write_fixture_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _corrupt_exact_current_final_replay(
    scratchpad: Path,
    *,
    final_key: str,
    mutation: str,
) -> None:
    marker_path = (
        scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    )
    state_path = scratchpad / "_artifact_state.json"
    if mutation.startswith("marker_"):
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if mutation == "marker_digest":
            marker["marker_sha256"] = "0" * 64
        elif mutation == "marker_snapshot":
            marker["snapshot_sha256"] = "0" * 64
            marker["marker_sha256"] = CTA._digest(
                marker, "marker_sha256"
            )
        elif mutation == "marker_producer":
            marker["producer_key"] = (
                "sc/thorough/evm/codex/chain_iter2/"
                "tail_reconcile.foreign"
            )
            marker["marker_sha256"] = CTA._digest(
                marker, "marker_sha256"
            )
        elif mutation == "marker_contract":
            marker["producer_contract_digest"] = "0" * 64
            marker["marker_sha256"] = CTA._digest(
                marker, "marker_sha256"
            )
        else:
            raise AssertionError(f"unknown marker mutation: {mutation}")
        _write_fixture_json(marker_path, marker)
        return

    if mutation.startswith("unit_"):
        state = json.loads(state_path.read_text(encoding="utf-8"))
        unit = state["work_units"][final_key]
        if mutation == "unit_run":
            unit["run_id"] = "foreign-run"
        elif mutation == "unit_status":
            unit["semantic_status"] = "QUARANTINED"
        elif mutation == "unit_state":
            unit["execution_state"] = "INPUTS_BOUND_PREEXECUTION"
        elif mutation == "unit_snapshot_binding":
            snapshot_identity = (
                "scratchpad:chain_tail_terminal_snapshot.json"
            )
            unit["input_bindings"][snapshot_identity][
                "producer_work_unit_key"
            ] = (
                "sc/thorough/evm/codex/chain_iter2/"
                "tail_snapshot.foreign"
            )
            unit["input_set_digest"] = D._input_set_digest(
                unit["input_bindings"]
            )
            unit["commit_authority"]["input_set_digest"] = (
                unit["input_set_digest"]
            )
        elif mutation == "unit_commit_receipt":
            unit["commit_authority"]["receipt_digest"] = "0" * 64
        elif mutation == "unit_output_authority_cas":
            digest = str(
                unit["commit_authority"]["output_authority_digest"]
            )
            (
                scratchpad
                / "_artifact_output_authority_cas"
                / f"{digest}.json"
            ).unlink()
            return
        else:
            raise AssertionError(f"unknown unit mutation: {mutation}")
        _write_fixture_json(state_path, state)
        return

    if mutation == "live_receipt":
        path = scratchpad / CTA.RECEIPT_NAME
        path.write_bytes(path.read_bytes() + b" ")
        return
    if mutation == "live_chain_output":
        path = scratchpad / "chain_iteration2.md"
        path.write_bytes(path.read_bytes() + b" ")
        return
    if mutation in {"mixed_control_ledger", "mixed_root_ledger"}:
        path = (
            scratchpad / CTA.CONTROL_DIR / CTA.LEDGER_NAME
            if mutation == "mixed_control_ledger"
            else scratchpad / CTA.LEDGER_NAME
        )
        ledger = json.loads(path.read_text(encoding="utf-8"))
        ledger["issues"] = list(
            dict.fromkeys(
                [
                    *(ledger.get("issues") or []),
                    "MIXED_GENERATION_FIXTURE",
                ]
            )
        )
        ledger["ledger_sha256"] = CTA._digest(
            ledger, "ledger_sha256"
        )
        _write_fixture_json(path, ledger)
        return
    raise AssertionError(f"unknown final replay mutation: {mutation}")


@pytest.mark.parametrize(
    "mutation",
    _FINAL_REPLAY_BEFORE_CORRUPTIONS,
)
def test_exact_current_final_before_replay_corruption_fails_closed(
    tmp_path: Path,
    mutation: str,
):
    root = tmp_path / mutation
    root.mkdir()
    scratchpad, config, phase, _expected_receipt, final_key = (
        _final_marker_unlink_boundary(root, "BEFORE")
    )
    _corrupt_exact_current_final_replay(
        scratchpad, final_key=final_key, mutation=mutation
    )
    frozen = _assert_final_replay_denominator_frozen(
        scratchpad,
        final_key=final_key,
        require_output_authority_cas=(
            mutation != "unit_output_authority_cas"
        ),
    )

    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )

    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    assert (
        "chain-tail final publication current-generation replay "
        "authority invalid"
    ) in issues
    assert _all_fixture_file_bytes(scratchpad) == frozen
    marker = (
        scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    )
    assert marker.is_file()
    assert marker.read_bytes() == frozen[
        f"{CTA.CONTROL_DIR}/{CTA.PUBLICATION_ARMED_NAME}"
    ]
    assert not marker.with_name(f"{marker.name}.tmp").exists()


@pytest.mark.parametrize(
    "mutation",
    _FINAL_REPLAY_AFTER_CORRUPTIONS,
)
def test_exact_current_final_after_replay_corruption_fails_closed(
    tmp_path: Path,
    mutation: str,
):
    root = tmp_path / mutation
    root.mkdir()
    scratchpad, config, phase, _expected_receipt, final_key = (
        _final_marker_unlink_boundary(root, "AFTER")
    )
    _corrupt_exact_current_final_replay(
        scratchpad, final_key=final_key, mutation=mutation
    )
    frozen = _assert_final_replay_denominator_frozen(
        scratchpad, final_key=final_key
    )

    receipt, issues = D._run_chain_tail_final_reconcile_transaction(
        scratchpad, config, phase
    )

    assert receipt["status"] == "DEGRADED_UNRESOLVED"
    assert (
        "chain-tail final publication current-generation replay "
        "authority invalid"
    ) in issues
    assert _all_fixture_file_bytes(scratchpad) == frozen
    marker = (
        scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
    )
    assert not marker.exists()
    assert not marker.with_name(f"{marker.name}.tmp").exists()


def test_final_publication_full_generation_marker_fault_matrix(
    tmp_path: Path,
):
    baseline_root = tmp_path / "baseline"
    baseline_root.mkdir()
    baseline_scratchpad, baseline_config, baseline_phase, _isolated = (
        _commit_one_isolated_model(baseline_root)
    )
    marker_events: list[tuple[str, str, str]] = []

    def record_marker(operation: str, edge: str, path: Path) -> None:
        if path.name.startswith(CTA.PUBLICATION_ARMED_NAME):
            marker_events.append(
                (
                    operation,
                    edge,
                    path.relative_to(baseline_scratchpad).as_posix(),
                )
            )

    with CTA.observe_chain_tail_durable_transitions(record_marker):
        baseline_receipt, baseline_issues = (
            D._run_chain_tail_final_reconcile_transaction(
                baseline_scratchpad,
                baseline_config,
                baseline_phase,
            )
        )
    assert baseline_issues == []
    assert baseline_receipt["status"] == "COMPLETE"
    assert {row[0] for row in marker_events} == {
        "TEMP_WRITE",
        "ATOMIC_REPLACE",
        "MARKER_UNLINK",
    }
    assert {row[1] for row in marker_events} == {"BEFORE", "AFTER"}
    canonical_names = (
        CTA.TERMINAL_SNAPSHOT_NAME,
        CTA.LEDGER_NAME,
        CTA.RECEIPT_NAME,
        CTA.COMPOSITION_CANDIDATES_NAME,
        CTA.PROJECTION_NAME,
        "chain_iteration2.md",
    )
    canonical = {
        name: (baseline_scratchpad / name).read_bytes()
        for name in canonical_names
    }

    for fail_index, expected in enumerate(marker_events):
        root = tmp_path / f"marker-{fail_index:02d}"
        root.mkdir()
        scratchpad, config, phase, _isolated = _commit_one_isolated_model(root)
        current = {"value": 0}

        def fail_marker(operation: str, edge: str, path: Path) -> None:
            if not path.name.startswith(CTA.PUBLICATION_ARMED_NAME):
                return
            index = current["value"]
            current["value"] += 1
            if index == fail_index:
                relative = path.relative_to(scratchpad).as_posix()
                assert (operation, edge, relative) == expected
                raise OSError(
                    "injected publication marker transition failure"
                )

        with CTA.observe_chain_tail_durable_transitions(fail_marker):
            _first, first_issues = D._run_chain_tail_final_reconcile_transaction(
                scratchpad,
                config,
                phase,
            )
        assert first_issues
        second, second_issues = D._run_chain_tail_final_reconcile_transaction(
            scratchpad,
            config,
            phase,
        )
        assert second_issues == [], (fail_index, expected, second_issues)
        assert second["status"] == "COMPLETE"
        assert not (
            scratchpad / CTA.CONTROL_DIR / CTA.PUBLICATION_ARMED_NAME
        ).exists()
        assert not (
            scratchpad
            / CTA.CONTROL_DIR
            / f"{CTA.PUBLICATION_ARMED_NAME}.tmp"
        ).exists()
        assert {
            name: (scratchpad / name).read_bytes()
            for name in canonical_names
        } == canonical

    mutated = json.loads(
        (baseline_scratchpad / CTA.LEDGER_NAME).read_text(encoding="utf-8")
    )
    mutated["pairs"][0]["evidence"] = "unauthorized next-generation mutation"
    mutated["ledger_sha256"] = CTA._digest(mutated, "ledger_sha256")
    (baseline_scratchpad / CTA.LEDGER_NAME).write_text(
        json.dumps(mutated),
        encoding="utf-8",
    )
    mutated_root_bytes = {
        name: (baseline_scratchpad / name).read_bytes()
        for name in canonical_names
    }
    assert CTA._terminal_publication_is_complete(baseline_scratchpad) is False
    with pytest.raises(
        CTA.ChainTailAuthorityError,
        match="chain-tail rearm terminal predecessor is invalid or stale",
    ):
        CTA.rearm_unresolved_chain_tail(baseline_scratchpad)
    assert {
        name: (baseline_scratchpad / name).read_bytes()
        for name in canonical_names
    } == mutated_root_bytes
    _mutated_receipt, mutation_issues = (
        D._run_chain_tail_final_reconcile_transaction(
            baseline_scratchpad,
            baseline_config,
            baseline_phase,
        )
    )
    assert mutation_issues
    assert {
        name: (baseline_scratchpad / name).read_bytes()
        for name in canonical_names
    } == mutated_root_bytes
