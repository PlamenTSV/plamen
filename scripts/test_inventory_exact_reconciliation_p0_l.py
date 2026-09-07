"""P0-L exact raw-discovery -> chunk -> final-inventory reconciliation.

The reconciliation is a recall boundary, not a truncation heuristic.  Every
canonical finding block in every shard-assigned source artifact must reach a
concrete inventory block, receive a source-bound typed disposition, or remain
content-bearing repair/human-review debt.  Percent coverage never authorizes
loss.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from inventory_reconciliation import (  # noqa: E402
    AUTHORITY_SCHEMA,
    NEGATIVE_EVIDENCE_SCHEMA,
    reconcile_inventory,
    validate_inventory_reconciliation,
    write_inventory_reconciliation,
)
from inventory_reemit_authority import (  # noqa: E402
    _apply_inventory_reemit_repair_for_tests,
)
import plamen_validators as V  # noqa: E402
import plamen_driver as D  # noqa: E402
import rooted_path_io as rooted_io  # noqa: E402
from artifact_ledger import (  # noqa: E402
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from assurance_limitations import build_current_assurance_manifest  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    LaunchSpec,
    canonical_work_unit_key,
    registered_projection_handoff,
    resolve_phase_io_contract,
)
from plamen_types import (  # noqa: E402
    Checkpoint,
    GateFailure,
    RetryReceipt,
    SC_PHASES,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_inventory_retry_handoff_is_exact_same_shard_successor_only() -> None:
    def key(shard: str, attempt: int) -> str:
        return canonical_work_unit_key(
            "sc",
            "thorough",
            "evm",
            "codex",
            f"inventory_chunk_{shard}",
            f"model.attempt{attempt:04d}",
        )

    identity = "scratchpad:findings_inventory_chunk_a.md"
    assert registered_projection_handoff(key("a", 1), key("a", 2), identity)
    assert registered_projection_handoff(key("a", 2), key("a", 3), identity)
    assert not registered_projection_handoff(key("a", 1), key("a", 3), identity)
    assert not registered_projection_handoff(
        key("a", 1),
        key("b", 2),
        identity,
    )
    assert not registered_projection_handoff(
        key("a", 1),
        key("a", 2),
        "scratchpad:findings_inventory_chunk_b.md",
    )


def _finding(fid: str, title: str, *, loc: str = "src/Module.sol:L10") -> str:
    return (
        f"### Finding [{fid}]: {title}\n"
        "**Severity**: Medium\n"
        f"**Location**: {loc}\n"
        f"**Root Cause**: mechanism for {title}\n"
        f"**Description**: description for {title}\n"
        f"**Impact**: material effect for {title}\n"
        "**Verdict**: NEEDS_VERIFICATION\n\n"
    )


def _manifest(root: Path, shard: str, *sources: str) -> None:
    lines = [
        f"# {shard} manifest",
        "",
        "| File | Estimated signals |",
        "|------|-------------------|",
        *(f"| {source} | 1 |" for source in sources),
        "",
    ]
    (root / f"{shard}.manifest.md").write_text("\n".join(lines), encoding="utf-8")


def _chunk(root: Path, shard: str, rows: list[tuple[str, str, tuple[str, ...]]]) -> None:
    text = "# Inventory Chunk\n\n## Per-Finding Detail\n\n"
    for local_id, title, source_ids in rows:
        text += _finding(local_id, title).replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            "**Source IDs**: " + ", ".join(source_ids) + "\n"
            "**Preferred Tag**: [CODE-TRACE]\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
        )
    (root / f"findings_{shard}.md").write_text(text, encoding="utf-8")


def _inventory(root: Path, rows: list[tuple[str, str, tuple[str, ...]]], *, suffix: str = "") -> None:
    text = "# Finding Inventory\n\n## Findings\n\n"
    for inv_id, title, source_ids in rows:
        text += _finding(inv_id, title).replace(
            "**Verdict**: NEEDS_VERIFICATION\n",
            "**Source IDs**: " + ", ".join(source_ids) + "\n"
            "**Verdict**: NEEDS_VERIFICATION\n",
        )
    text += suffix
    (root / "findings_inventory.md").write_text(text, encoding="utf-8")


def _one_retained_candidate(root: Path) -> None:
    (root / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "Generic flow mismatch"), encoding="utf-8"
    )
    _manifest(root, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(
        root,
        "inventory_chunk_a",
        [("CC-1", "Generic flow mismatch", ("TF-1",))],
    )
    _inventory(
        root,
        [("INV-001", "Generic flow mismatch", ("TF-1", "CC-1"))],
    )


def _activate_chunk_model(
    project: Path,
    scratchpad: Path,
    config: dict,
    phase_name: str = "inventory_chunk_a",
    attempt: int = 1,
) -> None:
    output = scratchpad / f"findings_{phase_name}.md"
    raw = output.read_bytes()
    output.unlink()
    config.setdefault("_active_model_attempts", {})[phase_name] = attempt
    config.setdefault("_phase_io_model_attempts", {})[phase_name] = attempt
    phase = next(item for item in SC_PHASES if item.name == phase_name)
    contract, launch = D._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert contract is not None and launch is not None
    record_work_unit_inputs(
        scratchpad, project, contract, launch, run_id=config["_run_id"]
    )
    output.write_bytes(raw)
    record_work_unit_artifacts(
        scratchpad,
        project,
        contract,
        launch,
        run_id=config["_run_id"],
        actor="MODEL",
    )


def _write_bound_inventory_prompt(
    root: Path, phase_name: str, attempt: int, payload: dict,
) -> Path:
    prompt = root / f"_prompt_{phase_name}.attempt{attempt}.md"
    prompt.write_text(
        "# retry\n\n```json\n"
        + json.dumps(payload, indent=2, sort_keys=True)
        + "\n```\n",
        encoding="utf-8",
        newline="\n",
    )
    return prompt


def _seal_inventory_retry_terminal(
    root: Path,
    phase: object,
    config: dict,
    checkpoint: Checkpoint,
    *,
    attempt: int,
    issue: str,
    terminal_rc: int = 0,
) -> RetryReceipt:
    plan = config["_inventory_retry_prompt_plans"][phase.name]
    _write_bound_inventory_prompt(root, phase.name, attempt, plan)
    output_digest = D._inventory_retry_artifact_digest(
        phase, root, config["project_root"]
    )
    failures_after = D._gate_failures_from_issues(
        phase,
        [issue],
        contract_digest=D._resolved_phase_contract_digest(phase, config),
        output_digest=output_digest,
        scratchpad=root,
        input_digest=D._resolved_phase_input_digest(phase, config),
    )
    receipt = D._build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=root,
        attempt=attempt,
        failures_before=(),
        failures_after=failures_after,
        output_digest_before="plan-bound",
        output_digest_after=output_digest,
        work_unit_id="transport",
        terminal_rc=terminal_rc,
    )
    D._write_inventory_terminal_authority(
        root,
        receipt=receipt,
        failures_after=failures_after,
        full_gate_passed=False,
    )
    D._write_retry_receipt(
        root,
        receipt,
        phase=phase,
        config=config,
        failures_after=failures_after,
        full_gate_passed=False,
        terminal_rc=terminal_rc,
    )
    return receipt


def test_inventory_retry_can_replace_quarantined_prior_attempt(
    tmp_path: Path,
) -> None:
    run_id = "inventory-retry-lineage-fixture"
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "Retry candidate"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", source.name)
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [("CC-1", "Incomplete retry candidate", ("TF-1",))],
    )
    output = tmp_path / "findings_inventory_chunk_a.md"
    exact_inputs = ("inventory_chunk_a.manifest.md", source.name)

    def authority(attempt: int) -> tuple[object, LaunchSpec]:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="codex",
            phase="inventory_chunk_a",
            work_unit_id=f"model.attempt{attempt:04d}",
            exact_inputs=exact_inputs,
            exact_outputs=(output.name,),
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="fixture-model",
            timeout_s=30,
            exec_mode="headless",
            tool_policy=("filesystem",),
        )
        return contract, launch

    first_contract, first_launch = authority(1)
    first_raw = output.read_bytes()
    output.unlink()
    record_work_unit_inputs(
        tmp_path, tmp_path, first_contract, first_launch, run_id=run_id
    )
    output.write_bytes(first_raw)
    first = record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        first_contract,
        first_launch,
        run_id=run_id,
        actor="MODEL",
    )
    assert first["semantic_status"] == "ACTIVE"

    output.rename(tmp_path / "findings_inventory_chunk_a.attempt1.rejected.md")
    rejected = record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        first_contract,
        first_launch,
        run_id=run_id,
        status="QUARANTINED",
        actor="MODEL",
        precommit_issues=("attempt 1 rejected before retry",),
    )
    assert rejected["semantic_status"] == "QUARANTINED"

    second_contract, second_launch = authority(2)
    record_work_unit_inputs(
        tmp_path, tmp_path, second_contract, second_launch, run_id=run_id
    )
    output.write_text(
        "# Inventory Chunk\n\n## Source Summary\n\nRetry.\n\n"
        "## Master Table\n\n| ID | Title |\n|---|---|\n| CC-1 | Retry |\n\n"
        "## Per-Finding Detail\n\n"
        + _finding("CC-1", "Complete retry candidate"),
        encoding="utf-8",
    )
    second = record_work_unit_artifacts(
        tmp_path,
        tmp_path,
        second_contract,
        second_launch,
        run_id=run_id,
        actor="MODEL",
    )
    assert second["semantic_status"] == "ACTIVE"
    assert second["execution_state"] == "OUTPUT_COMMITTED"


def test_production_inventory_retry_prestate_terminalizes_then_cleans_attempts(
    tmp_path: Path,
) -> None:
    phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "scratchpad": str(tmp_path),
        "_run_id": "74567891-1234-4234-8234-123456789abc",
        "_active_model_attempts": {phase.name: 1},
        "_phase_io_model_attempts": {phase.name: 1},
    }
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "retry lineage"), encoding="utf-8")
    _manifest(tmp_path, phase.name, source.name)
    _chunk(
        tmp_path, phase.name,
        [("CC-1", "attempt one", ("TF-1",))],
    )
    _activate_chunk_model(tmp_path, tmp_path, config, phase.name)
    output = tmp_path / "findings_inventory_chunk_a.md"
    checkpoint = Checkpoint(run_id=config["_run_id"])

    for prior, successor in ((1, 2), (2, 3)):
        D._authorize_inventory_retry_launch(
            checkpoint=checkpoint,
            phase=phase,
            config=config,
            scratchpad=tmp_path,
            attempt=successor,
            issues=[f"fixture rejection of attempt {prior}"],
        )
        archived, issues = D._prepare_inventory_retry_prestate(
            phase, tmp_path, config,
            prior_attempt=prior, next_attempt=successor,
        )
        assert issues == []
        assert archived == [output.name]
        assert not output.exists()
        prior_key = canonical_work_unit_key(
            "sc", "thorough", "evm", "codex", phase.name,
            f"model.attempt{prior:04d}",
        )
        assert read_artifact_ledger(tmp_path)["work_units"][prior_key][
            "semantic_status"
        ] == "QUARANTINED"

        config["_active_model_attempts"][phase.name] = successor
        config["_phase_io_model_attempts"][phase.name] = successor
        assert D._bind_typed_model_phase_inputs(phase, tmp_path, config) == []
        _chunk(
            tmp_path, phase.name,
            [("CC-1", f"attempt {successor}", ("TF-1",))],
        )
        assert D._record_typed_model_phase_artifacts(
            phase, tmp_path, config
        ) == []
        if successor == 2:
            _seal_inventory_retry_terminal(
                tmp_path,
                phase,
                config,
                checkpoint,
                attempt=2,
                issue="fixture rejection of attempt two",
            )

    assert output.exists(), "attempt 3 launcher published a fresh output"


def test_inventory_resume_recovers_durable_successor_without_runtime_maps(
    tmp_path: Path,
) -> None:
    phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "codex",
        "project_root": str(tmp_path),
        "scratchpad": str(tmp_path),
        "_run_id": "84567891-1234-4234-8234-123456789abc",
        "_active_model_attempts": {phase.name: 1},
        "_phase_io_model_attempts": {phase.name: 1},
    }
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "resume lineage"), encoding="utf-8")
    _manifest(tmp_path, phase.name, source.name)
    _chunk(
        tmp_path, phase.name,
        [("CC-1", "attempt one", ("TF-1",))],
    )
    _activate_chunk_model(tmp_path, tmp_path, config, phase.name)

    fresh_config = {
        key: value
        for key, value in config.items()
        if key not in {"_active_model_attempts", "_phase_io_model_attempts"}
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh_config
    )

    assert issues == []
    assert (prior, successor) == (1, 2)

    assert "_active_model_attempts" not in fresh_config
    assert "_phase_io_model_attempts" not in fresh_config


def _active_inventory_retry_fixture(
    root: Path, *, run_id: str, backend: str = "codex"
) -> tuple[object, dict, Path]:
    phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    config = {
        "pipeline": "sc", "mode": "thorough", "language": "evm",
        "cli_backend": backend, "project_root": str(root),
        "scratchpad": str(root), "_run_id": run_id,
        "_active_model_attempts": {phase.name: 1},
        "_phase_io_model_attempts": {phase.name: 1},
    }
    if backend == "claude":
        config["claude_exec_mode"] = "headless"
    source = root / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "adversarial retry"), encoding="utf-8")
    _manifest(root, phase.name, source.name)
    _chunk(root, phase.name, [("CC-1", "attempt one", ("TF-1",))])
    _activate_chunk_model(root, root, config, phase.name)
    return phase, config, root / "findings_inventory_chunk_a.md"


def test_inventory_retry_launch_vetoes_missing_or_drifted_plan_before_move(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="c4567891-1234-4234-8234-123456789abc"
    )
    original = output.read_bytes()

    assert D._run_phase_once(phase, config, attempt=2) == D.EXIT_ERROR
    assert output.read_bytes() == original
    assert not (
        tmp_path / "_retry_quarantine" / phase.name / "attempt-0001"
        / output.name
    ).exists()

    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture exact reconciliation rejection"],
    )
    plan = (
        tmp_path / "_retry_plans" / phase.name
        / "phase.attempt-0002.json"
    )
    payload = json.loads(plan.read_text(encoding="utf-8"))
    plan_raw = plan.read_bytes()
    different_failures = D._gate_failures_from_issues(
        phase,
        ["different retry authority must not overwrite attempt 2"],
        contract_digest=D._resolved_phase_contract_digest(phase, config),
        output_digest=D._resolved_phase_artifact_digest(
            phase, tmp_path, config["project_root"]
        ),
        scratchpad=tmp_path,
        input_digest=D._resolved_phase_input_digest(phase, config),
    )
    with pytest.raises(Exception):
        D._write_retry_plan(
            tmp_path,
            checkpoint,
            phase,
            config,
            different_failures,
            attempt=2,
        )
    assert plan.read_bytes() == plan_raw

    plan_failures = tuple(
        GateFailure.from_dict(row) for row in payload["failed_predicates"]
    )
    archived, bind_issues = D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    assert bind_issues == [] and archived == [output.name]
    output.write_bytes(original)
    _activate_chunk_model(tmp_path, tmp_path, config, phase.name, attempt=2)
    monkeypatch.setattr(
        D, "_inventory_quarantined_artifact_rows",
        lambda *_args, **_kwargs: ([], []),
    )
    _write_bound_inventory_prompt(tmp_path, phase.name, 2, payload)
    receipt = D._build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        failures_before=plan_failures,
        failures_after=(),
        output_digest_before=payload["output_digest_before"],
        output_digest_after=payload["output_digest_before"],
    )
    assert receipt.retry_plan_digest == payload["plan_digest"]
    wrong_first = replace(
        receipt,
        work_unit_id="wrong-first-publication",
        retry_plan_digest="0" * 64,
    )
    with pytest.raises(Exception):
        D._write_retry_receipt(tmp_path, wrong_first)
    assert not (
        tmp_path / "_retry_receipts" / phase.name
        / "wrong-first-publication.attempt2.json"
    ).exists()
    receipt_path = D._write_retry_receipt(
        tmp_path,
        receipt,
        phase=phase,
        config=config,
        failures_after=(),
        full_gate_passed=True,
        terminal_rc=0,
    )
    receipt_raw = receipt_path.read_bytes()
    with pytest.raises(Exception):
        D._write_retry_receipt(
            tmp_path,
            replace(receipt, retry_plan_digest="0" * 64),
            phase=phase,
            config=config,
            failures_after=(),
            full_gate_passed=True,
            terminal_rc=0,
        )
    assert receipt_path.read_bytes() == receipt_raw

    payload["semantic_retry"] = not payload["semantic_retry"]
    plan.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    assert D._run_phase_once(phase, config, attempt=2) == D.EXIT_ERROR
    assert output.read_bytes() == original
    assert (
        tmp_path / "_retry_quarantine" / phase.name / "attempt-0001"
        / output.name
    ).read_bytes() == original


def test_inventory_retry_receipt_rejects_contradictory_first_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="c5567891-1234-4234-8234-123456789abc"
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture exact reconciliation rejection"],
    )
    plan = config["_inventory_retry_prompt_plans"][phase.name]
    _write_bound_inventory_prompt(tmp_path, phase.name, 2, plan)
    current_output = D._inventory_retry_artifact_digest(
        phase, tmp_path, config["project_root"]
    )
    actual_after = D._gate_failures_from_issues(
        phase,
        ["inventory chunk structure: missing exact source identity"],
        contract_digest=D._resolved_phase_contract_digest(phase, config),
        output_digest=current_output,
        scratchpad=tmp_path,
        input_digest=D._resolved_phase_input_digest(phase, config),
    )
    original = output.read_bytes()
    archived, bind_issues = D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    assert bind_issues == [] and archived == [output.name]
    output.write_bytes(original)
    _activate_chunk_model(tmp_path, tmp_path, config, phase.name, attempt=2)
    monkeypatch.setattr(
        D, "_inventory_quarantined_artifact_rows",
        lambda *_args, **_kwargs: ([], []),
    )
    receipt = D._build_retry_receipt(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        failures_before=(),
        failures_after=actual_after,
        output_digest_before="plan-bound",
        output_digest_after=current_output,
        work_unit_id="contradictory-status",
    )
    with pytest.raises(Exception, match="terminal semantics"):
        D._write_retry_receipt(
            tmp_path,
            replace(receipt, status="CLEARED"),
            phase=phase,
            config=config,
            failures_after=actual_after,
            full_gate_passed=False,
            terminal_rc=0,
        )
    assert not (
        tmp_path / "_retry_receipts" / phase.name
        / "contradictory-status.attempt2.json"
    ).exists()

    wrong_after = replace(
        receipt,
        work_unit_id="contradictory-after-state",
        failure_instance_ids_after=("foreign-failure-identity",),
    )
    with pytest.raises(Exception, match="terminal semantics"):
        D._write_retry_receipt(
            tmp_path,
            wrong_after,
            phase=phase,
            config=config,
            failures_after=actual_after,
            full_gate_passed=False,
            terminal_rc=0,
        )
    assert not (
        tmp_path / "_retry_receipts" / phase.name
        / "contradictory-after-state.attempt2.json"
    ).exists()

    wrong_rc = replace(
        receipt,
        work_unit_id="contradictory-terminal-rc",
        terminal_rc=1,
        status="FAILED",
    )
    with pytest.raises(Exception, match="terminal semantics"):
        D._write_retry_receipt(
            tmp_path,
            wrong_rc,
            phase=phase,
            config=config,
            failures_after=actual_after,
            full_gate_passed=False,
            terminal_rc=0,
        )
    assert not (
        tmp_path / "_retry_receipts" / phase.name
        / "contradictory-terminal-rc.attempt2.json"
    ).exists()


def test_inventory_retry_integrated_path_rejects_quarantine_symlink_escape(
    tmp_path: Path,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="d4567891-1234-4234-8234-123456789abc"
    )
    original = output.read_bytes()
    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture exact reconciliation rejection"],
    )
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    quarantine_root = tmp_path / "_retry_quarantine"
    quarantine_root.mkdir()
    try:
        os.symlink(
            outside,
            quarantine_root / phase.name,
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    assert D._run_phase_once(phase, config, attempt=2) == D.EXIT_ERROR
    assert output.read_bytes() == original
    assert list(outside.iterdir()) == []


def test_containment_snapshot_retires_directory_symlink_and_resume_is_clean(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    foreign = outside / "report_index.md"
    foreign.write_bytes(b"external authority")
    link = scratchpad / "linked"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not os.path.lexists(link)
    assert foreign.read_bytes() == b"external authority"
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    event = state["containment_events"][-1]
    assert event["schema"] == "plamen.containment-reparse-retirement/v1"
    assert event["path"] == "linked"
    assert event["disposition"] == "REPARSE_OBJECT_RETIRED_NOFOLLOW"

    # A fresh-process resume must not be poisoned by the retired name.
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert foreign.read_bytes() == b"external authority"

    # Excluded containment roots and cycles are not an escape hatch: inspect
    # the link object before applying the exclusion and never traverse it.
    excluded_link = scratchpad / "_overflow"
    os.symlink(outside, excluded_link, target_is_directory=True)
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not os.path.lexists(excluded_link)
    cycle = scratchpad / "cycle"
    os.symlink(scratchpad, cycle, target_is_directory=True)
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not os.path.lexists(cycle)
    assert foreign.read_bytes() == b"external authority"

    os.symlink(outside, link, target_is_directory=True)
    moved, failed = V._quarantine_foreign_phase_writes(
        scratchpad,
        str(tmp_path),
        "inventory_chunk_a",
        ["linked/report_index.md"],
    )
    assert moved == ["linked/report_index.md"]
    assert failed == []
    assert not os.path.lexists(link)
    assert foreign.read_bytes() == b"external authority"


def test_containment_artifact_state_symlink_is_never_read_or_copied(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    external_state = outside / "attacker-state.json"
    external_raw = (
        b'{"artifacts":{"external":{"payload":"'
        + (b"Z" * (2 * 1024 * 1024))
        + b'"}}}'
    )
    external_state.write_bytes(external_raw)
    state_link = scratchpad / "_artifact_state.json"
    try:
        os.symlink(external_state, state_link)
    except OSError as exc:
        pytest.skip(f"file symlink unavailable: {exc}")

    assert V._read_artifact_state(scratchpad) == {
        "version": 1,
        "artifacts": {},
    }
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert external_state.read_bytes() == external_raw
    assert not os.path.islink(state_link)
    state = json.loads(state_link.read_text(encoding="utf-8"))
    assert "external" not in state["artifacts"]
    assert any(
        row.get("path") == "_artifact_state.json"
        and row.get("disposition") == "REPARSE_OBJECT_RETIRED_NOFOLLOW"
        for row in state["containment_events"]
    )


def test_containment_control_and_state_reparses_recover_together(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    external_state = outside / "state.json"
    external_state.write_bytes(b'{"external":"unchanged"}')
    external_journal = outside / "journal"
    external_quarantine = outside / "quarantine"
    external_evidence = outside / "evidence"
    external_journal.mkdir()
    external_quarantine.mkdir()
    external_evidence.mkdir()
    try:
        os.symlink(
            external_state,
            scratchpad / "_artifact_state.json",
        )
        os.symlink(
            external_journal,
            scratchpad / "_containment_reparse_journal",
            target_is_directory=True,
        )
        os.symlink(
            external_quarantine,
            scratchpad / "_containment_reparse_quarantine",
            target_is_directory=True,
        )
        os.symlink(
            external_evidence,
            scratchpad / "_containment_reparse_evidence",
            target_is_directory=True,
        )
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert external_state.read_bytes() == b'{"external":"unchanged"}'
    assert list(external_journal.iterdir()) == []
    assert list(external_quarantine.iterdir()) == []
    assert list(external_evidence.iterdir()) == []
    assert (scratchpad / "_containment_reparse_journal").is_dir()
    assert (scratchpad / "_containment_reparse_quarantine").is_dir()
    state = json.loads((
        scratchpad / "_artifact_state.json"
    ).read_text(encoding="utf-8"))
    retired = {
        row.get("path") for row in state["containment_events"]
        if row.get("disposition") == "REPARSE_OBJECT_RETIRED_NOFOLLOW"
    }
    assert {
        "_artifact_state.json",
        "_containment_reparse_journal",
        "_containment_reparse_quarantine",
        "_containment_reparse_evidence",
    }.issubset(retired)


@pytest.mark.parametrize(
    "control_name",
    [
        "_containment_reparse_journal",
        "_containment_reparse_quarantine",
        "_containment_reparse_evidence",
    ],
)
def test_containment_exact_control_regular_file_is_retired_and_resume_safe(
    tmp_path: Path, control_name: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    poisoned = scratchpad / control_name
    poisoned.write_bytes(b"attacker-control-bytes")

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert poisoned.is_dir() and not poisoned.is_symlink()
    state = json.loads((scratchpad / "_artifact_state.json").read_text(
        encoding="utf-8"
    ))
    matching = [
        row for row in state["containment_events"]
        if row.get("path") == control_name
    ]
    assert len(matching) == 1
    txid = matching[0]["transaction_id"]
    archive = (
        scratchpad / "_containment_reparse_quarantine"
        / f"{txid}.control.link"
    )
    assert archive.read_bytes() == b"attacker-control-bytes"


def test_containment_evidence_control_hardlink_is_retired_without_peer_mutation(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    external = tmp_path / "external-evidence-peer"
    external.write_bytes(b"hardlink peer exact")
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    os.link(external, poisoned)

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert poisoned.is_dir() and not poisoned.is_symlink()
    assert external.read_bytes() == b"hardlink peer exact"
    state = json.loads((scratchpad / "_artifact_state.json").read_text(
        encoding="utf-8"
    ))
    event = next(
        row for row in state["containment_events"]
        if row.get("path") == V._CONTAINMENT_REPARSE_EVIDENCE
    )
    assert (
        scratchpad / V._CONTAINMENT_REPARSE_QUARANTINE
        / f"{event['transaction_id']}.control.link"
    ).read_bytes() == b"hardlink peer exact"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_containment_evidence_control_special_file_is_resumable(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    os.mkfifo(scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE)
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert (scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE).is_dir()


@pytest.mark.skipif(os.name != "nt", reason="NTFS evidence junction regression")
def test_containment_evidence_control_junction_bootstraps_without_traversal(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside-evidence"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(poisoned), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"junction creation unavailable: {result.stderr}")

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert poisoned.is_dir() and not rooted_io.is_reparse(poisoned)
    assert marker.read_bytes() == b"external exact"


def test_containment_evidence_control_bootstrap_move_crash_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    try:
        os.symlink(outside, poisoned, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    original_move = rooted_io.durable_quarantine_reparse
    crashed = False

    def _crash_after_move(*args: object, **kwargs: object) -> tuple[int, ...]:
        nonlocal crashed
        result = original_move(*args, **kwargs)
        if (
            not crashed
            and str(args[1]) == V._CONTAINMENT_REPARSE_EVIDENCE
        ):
            crashed = True
            raise RuntimeError("crash after evidence-control bootstrap move")
        return result

    monkeypatch.setattr(
        rooted_io, "durable_quarantine_reparse", _crash_after_move
    )
    with pytest.raises(RuntimeError, match="bootstrap move"):
        V._snapshot_file_state(scratchpad, str(tmp_path))
    assert marker.read_bytes() == b"external exact"
    assert any(
        path.name.startswith("._containment-control-evidence-")
        and path.name.endswith(".prepared.json")
        for path in scratchpad.iterdir()
    )

    monkeypatch.setattr(
        rooted_io, "durable_quarantine_reparse", original_move
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert poisoned.is_dir() and not rooted_io.is_reparse(poisoned)
    assert marker.read_bytes() == b"external exact"


@pytest.mark.parametrize(
    "control_tag",
    ["state", "journal", "quarantine", "evidence"],
)
def test_containment_control_authority_survives_32769_prior_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_tag: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    flood_count = V._CONTAINMENT_CONTROL_SCAN_MAX_ENTRIES + 1
    for ordinal in range(flood_count):
        (scratchpad / f"!flood-{ordinal:05d}").write_bytes(b"")
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    if control_tag == "state":
        source_name = "_artifact_state.json"
        external_object = outside / "state.json"
        external_object.write_bytes(b'{"external":"exact"}\n')
        os.symlink(external_object, scratchpad / source_name)
    else:
        source_name = V._CONTAINMENT_CONTROL_NAMES[control_tag]
        external_object = outside
        os.symlink(
            external_object,
            scratchpad / source_name,
            target_is_directory=True,
        )
    original_move = rooted_io.durable_quarantine_reparse
    crashed = False

    def _crash_after_source_move(
        *args: object, **kwargs: object,
    ) -> tuple[int, ...]:
        nonlocal crashed
        result = original_move(*args, **kwargs)
        if not crashed and str(args[1]) == source_name:
            crashed = True
            raise RuntimeError("crash after starved control move")
        return result

    monkeypatch.setattr(
        rooted_io, "durable_quarantine_reparse", _crash_after_source_move
    )
    with pytest.raises(RuntimeError, match="starved control move"):
        V._snapshot_file_state(scratchpad, str(tmp_path))
    assert marker.read_bytes() == b"external exact"
    if control_tag != "state":
        authority = V._containment_control_authority_path(
            scratchpad, control_tag
        )
        assert authority.is_file()
        payload = json.loads(authority.read_text(encoding="utf-8"))
        assert (scratchpad / payload["bootstrap_relative"]).is_symlink()
        assert (scratchpad / (
            f"{V._CONTAINMENT_CONTROL_PREFIX}{control_tag}-"
            f"{payload['transaction_id']}.prepared.json"
        )).is_file()

    monkeypatch.setattr(
        rooted_io, "durable_quarantine_reparse", original_move
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    for ordinal in range(flood_count):
        (scratchpad / f"!flood-{ordinal:05d}").unlink()
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert marker.read_bytes() == b"external exact"
    if control_tag == "state":
        assert external_object.read_bytes() == b'{"external":"exact"}\n'
    else:
        assert list(outside.iterdir()) == [marker]
        assert not V._containment_control_authority_path(
            scratchpad, control_tag
        ).exists()
        assert not list(scratchpad.glob(
            f"{V._CONTAINMENT_CONTROL_PREFIX}{control_tag}-*.prepared.json"
        ))
        assert not list(scratchpad.glob(
            f"{V._CONTAINMENT_CONTROL_PREFIX}{control_tag}-*.link"
        ))
    state = json.loads((scratchpad / "_artifact_state.json").read_text(
        encoding="utf-8"
    ))
    events = [
        row for row in state["containment_events"]
        if row.get("path") == source_name
        and row.get("disposition")
        in {
            "REPARSE_OBJECT_RETIRED_NOFOLLOW",
            "INVALID_ARTIFACT_STATE_OBJECT_RETIRED_NOFOLLOW",
        }
    ]
    assert len(events) == 1


@pytest.mark.parametrize(
    "shape", ["ordinary", "directory", "symlink", "hardlink"],
)
def test_containment_control_authority_poison_is_retired_and_resumable(
    tmp_path: Path,
    shape: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned_root = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    os.symlink(outside, poisoned_root, target_is_directory=True)
    authority = V._containment_control_authority_path(scratchpad, "evidence")
    peer = outside / "authority-peer"
    peer.write_bytes(b"foreign authority exact")
    if shape == "ordinary":
        authority.write_bytes(b'{"attacker":true}\n')
    elif shape == "directory":
        authority.mkdir()
        (authority / "child").write_bytes(b"foreign child")
    elif shape == "symlink":
        os.symlink(peer, authority)
    else:
        os.link(peer, authority)

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert poisoned_root.is_dir() and not rooted_io.is_reparse(poisoned_root)
    assert marker.read_bytes() == b"external exact"
    assert peer.read_bytes() == b"foreign authority exact"
    assert not authority.exists()
    foreign = list(scratchpad.glob(
        f"._foreign-{authority.name}-*.object"
    ))
    assert len(foreign) == 1


def test_containment_control_authority_reservation_crash_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    os.symlink(outside, poisoned, target_is_directory=True)
    crashed = False

    def _crash_after_authority(
        _path: Path, payload: object,
    ) -> None:
        nonlocal crashed
        if (
            not crashed
            and isinstance(payload, dict)
            and payload["tag"] == "evidence"
        ):
            crashed = True
            raise RuntimeError("crash after fixed control authority")

    monkeypatch.setattr(
        V, "_containment_control_authority_reserved_hook", _crash_after_authority
    )
    with pytest.raises(RuntimeError, match="fixed control authority"):
        V._snapshot_file_state(scratchpad, str(tmp_path))
    assert rooted_io.is_reparse(poisoned)
    assert V._containment_control_authority_path(
        scratchpad, "evidence"
    ).is_file()

    monkeypatch.setattr(
        V, "_containment_control_authority_reserved_hook", lambda *_args: None
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert poisoned.is_dir() and not rooted_io.is_reparse(poisoned)
    assert marker.read_bytes() == b"external exact"


def test_containment_control_authority_collision_crash_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    os.symlink(outside, poisoned, target_is_directory=True)
    authority = V._containment_control_authority_path(scratchpad, "evidence")
    authority.write_bytes(b'{"attacker":true}\n')
    original_retire = V._retire_containment_namespace_collision
    crashed = False

    def _crash_after_collision(path: Path) -> Path:
        nonlocal crashed
        result = original_retire(path)
        if not crashed and path == authority:
            crashed = True
            raise RuntimeError("crash after control authority collision")
        return result

    monkeypatch.setattr(
        V, "_retire_containment_namespace_collision", _crash_after_collision
    )
    with pytest.raises(RuntimeError, match="authority collision"):
        V._snapshot_file_state(scratchpad, str(tmp_path))
    assert rooted_io.is_reparse(poisoned)
    assert not authority.exists()

    monkeypatch.setattr(
        V, "_retire_containment_namespace_collision", original_retire
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert poisoned.is_dir() and not rooted_io.is_reparse(poisoned)
    assert marker.read_bytes() == b"external exact"


def test_containment_control_authority_replacement_race_is_resumable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    os.symlink(outside, poisoned, target_is_directory=True)
    authority = V._containment_control_authority_path(scratchpad, "evidence")
    authority.write_bytes(b'{"attacker":true}\n')
    replacement = scratchpad / "replacement-authority"
    replacement.write_bytes(b'{"replacement":true}\n')
    raced: list[str] = []

    def _replace_during_lock(source: Path, _destination: Path) -> None:
        if source != authority:
            return
        try:
            os.replace(replacement, source)
        except OSError:
            raced.append("DENIED")
        else:
            raced.append("REPLACED")

    monkeypatch.setattr(
        rooted_io, "_reparse_pre_quarantine_hook", _replace_during_lock
    )
    try:
        V._snapshot_file_state(scratchpad, str(tmp_path))
    except (OSError, RuntimeError, rooted_io.RootedPathIOError):
        pass
    monkeypatch.setattr(
        rooted_io, "_reparse_pre_quarantine_hook", lambda *_args: None
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert raced
    assert poisoned.is_dir() and not rooted_io.is_reparse(poisoned)
    assert marker.read_bytes() == b"external exact"


def test_containment_matching_control_name_overflow_cannot_starve_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    poisoned = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    os.symlink(outside, poisoned, target_is_directory=True)
    monkeypatch.setattr(V, "_CONTAINMENT_CONTROL_SCAN_MAX_ENTRIES", 32)
    for ordinal in range(33):
        digest = hashlib.sha256(f"foreign-{ordinal}".encode()).hexdigest()
        (scratchpad / (
            f"{V._CONTAINMENT_CONTROL_PREFIX}evidence-{digest}.prepared.json"
        )).write_bytes(b"{}\n")

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert poisoned.is_dir() and not rooted_io.is_reparse(poisoned)
    assert not V._containment_control_authority_path(
        scratchpad, "evidence"
    ).exists()


@pytest.mark.parametrize("shape", ["directory", "hardlink"])
def test_containment_invalid_artifact_state_shape_is_transactionally_retired(
    tmp_path: Path, shape: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    state_path = scratchpad / "_artifact_state.json"
    external = tmp_path / "external-state-bytes"
    if shape == "directory":
        state_path.mkdir()
        (state_path / "marker").write_bytes(b"directory-child")
    else:
        external.write_bytes(b"hardlink-target")
        os.link(external, state_path)

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert state_path.is_file() and not state_path.is_symlink()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    matching = [
        row for row in state["containment_events"]
        if row.get("path") == "_artifact_state.json"
        and row.get("disposition")
        == "INVALID_ARTIFACT_STATE_OBJECT_RETIRED_NOFOLLOW"
    ]
    assert len(matching) == 1
    txid = matching[0]["transaction_id"]
    archive = (
        scratchpad / "_containment_reparse_quarantine" / f"{txid}.link"
    )
    if shape == "directory":
        assert archive.is_dir()
        assert (archive / "marker").read_bytes() == b"directory-child"
    else:
        assert archive.read_bytes() == b"hardlink-target"
        assert external.read_bytes() == b"hardlink-target"


def test_containment_2049_malformed_prepared_rows_are_aggregate_inert_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    (scratchpad / "_containment_reparse_journal").mkdir()
    (scratchpad / "_containment_reparse_quarantine").mkdir()
    journal = scratchpad / "_containment_reparse_journal"
    for ordinal in range(2049):
        name = hashlib.sha256(str(ordinal).encode()).hexdigest()
        (journal / f"{name}.prepared.json").write_bytes(b"{}\n")

    V._recover_containment_reparse_transactions(
        scratchpad, allowed_source_roots=(scratchpad, tmp_path)
    )
    V._recover_containment_reparse_transactions(
        scratchpad, allowed_source_roots=(scratchpad, tmp_path)
    )

    state = json.loads((scratchpad / "_artifact_state.json").read_text(
        encoding="utf-8"
    ))
    debts = [
        row for row in state["containment_events"]
        if row.get("disposition")
        == "INVALID_PREPARED_ROWS_PRESERVED_AS_INERT_DEBT"
    ]
    assert len(debts) == 1
    assert debts[0]["count"] == 2049
    assert len(debts[0]["samples"]) == 16


def _write_forged_containment_prepared_for_live_object(
    scratchpad: Path,
    source_root: Path,
    relative: str,
) -> Path:
    source = source_root / relative
    identity_payload = {
        "schema": "plamen.containment-reparse-transaction.prepared/v1",
        "phase_name": "inventory_chunk_a",
        "source_root": os.fspath(source_root),
        "source_root_identity": list(
            V._containment_identity(rooted_io.lstat(source_root))
        ),
        "source_relative": relative,
        "source_identity": list(V._containment_identity(rooted_io.lstat(source))),
    }
    txid = hashlib.sha256(json.dumps(
        identity_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    unsigned = {
        **identity_payload,
        "transaction_id": txid,
        "quarantine_relative": (
            f"_containment_reparse_quarantine/{txid}.link"
        ),
    }
    prepared = {
        **unsigned,
        "prepared_digest": hashlib.sha256(json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")).hexdigest(),
    }
    journal = scratchpad / "_containment_reparse_journal"
    journal.mkdir(exist_ok=True)
    (scratchpad / "_containment_reparse_quarantine").mkdir(exist_ok=True)
    path = journal / f"{txid}.prepared.json"
    path.write_text(
        json.dumps(prepared, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _containment_retirement_txid(
    source_root: Path,
    relative: str,
    *,
    phase_name: str = "inventory_chunk_a",
) -> str:
    source = source_root / relative
    identity_payload = {
        "schema": "plamen.containment-reparse-transaction.prepared/v1",
        "phase_name": phase_name,
        "source_root": os.fspath(source_root),
        "source_root_identity": list(
            V._containment_identity(rooted_io.lstat(source_root))
        ),
        "source_relative": relative,
        "source_identity": list(V._containment_identity(rooted_io.lstat(source))),
    }
    return hashlib.sha256(json.dumps(
        identity_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


@pytest.mark.parametrize(
    "shape",
    ["mismatch", "malformed", "directory", "symlink", "hardlink"],
)
def test_containment_evidence_segment_collision_is_retired_before_mutation(
    tmp_path: Path,
    shape: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external target exact")
    rogue = scratchpad / "rogue"
    try:
        os.symlink(outside, rogue, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    txid = _containment_retirement_txid(
        scratchpad, "rogue", phase_name="containment_snapshot"
    )
    evidence = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    evidence.mkdir()
    collision = evidence / f"{txid}.json"
    external_collision = outside / "collision-target"
    external_collision.write_bytes(b"external collision bytes")
    if shape == "mismatch":
        collision.write_text(
            json.dumps({"attacker": True}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    elif shape == "malformed":
        collision.write_bytes(b"{malformed")
    elif shape == "directory":
        collision.mkdir()
        (collision / "child.txt").write_bytes(b"directory child exact")
    elif shape == "symlink":
        try:
            os.symlink(external_collision, collision)
        except OSError as exc:
            pytest.skip(f"file symlink unavailable: {exc}")
    else:
        os.link(external_collision, collision)

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert not os.path.lexists(rogue)
    assert marker.read_bytes() == b"external target exact"
    assert external_collision.read_bytes() == b"external collision bytes"
    canonical = json.loads(collision.read_text(encoding="utf-8"))
    assert canonical["transaction_id"] == txid
    assert canonical["path"] == "rogue"
    retired = list(evidence.glob(f"._foreign-{txid}.json-*.object"))
    assert len(retired) == 1
    if shape == "directory":
        assert rooted_io.read_bytes(
            retired[0] / "child.txt",
            label="retired evidence collision child",
            require_single_link=True,
            max_bytes=64,
        ) == b"directory child exact"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_containment_evidence_special_file_collision_is_resumable(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    rogue = scratchpad / "rogue"
    os.symlink(outside, rogue, target_is_directory=True)
    txid = _containment_retirement_txid(
        scratchpad, "rogue", phase_name="containment_snapshot"
    )
    evidence = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    evidence.mkdir()
    os.mkfifo(evidence / f"{txid}.json")

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not os.path.lexists(rogue)
    assert json.loads((evidence / f"{txid}.json").read_text(
        encoding="utf-8"
    ))["path"] == "rogue"


@pytest.mark.parametrize("crash_point", ["after_collision", "after_reservation"])
def test_containment_evidence_collision_recovers_every_reservation_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    crash_point: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    rogue = scratchpad / "rogue"
    try:
        os.symlink(outside, rogue, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    txid = _containment_retirement_txid(scratchpad, "rogue")
    evidence = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    evidence.mkdir()
    segment = evidence / f"{txid}.json"
    segment.write_bytes(b'{"attacker":true}\n')
    if crash_point == "after_collision":
        monkeypatch.setattr(
            V,
            "_containment_evidence_collision_hook",
            lambda *_args: (_ for _ in ()).throw(
                RuntimeError("crash after evidence collision retirement")
            ),
        )
    else:
        monkeypatch.setattr(
            V,
            "_containment_evidence_reserved_hook",
            lambda *_args: (_ for _ in ()).throw(
                RuntimeError("crash after evidence reservation")
            ),
        )
    with pytest.raises(RuntimeError, match="crash after evidence"):
        V._retire_exact_reparse_object(
            scratchpad, "rogue", phase_name="inventory_chunk_a"
        )
    assert os.path.lexists(rogue)

    monkeypatch.setattr(
        V, "_containment_evidence_collision_hook", lambda *_args: None
    )
    monkeypatch.setattr(
        V, "_containment_evidence_reserved_hook", lambda *_args: None
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not os.path.lexists(rogue)
    assert marker.read_bytes() == b"external exact"
    assert json.loads(segment.read_text(encoding="utf-8"))["path"] == "rogue"


def test_containment_evidence_collision_replacement_race_never_touches_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    rogue = scratchpad / "rogue"
    try:
        os.symlink(outside, rogue, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")
    txid = _containment_retirement_txid(scratchpad, "rogue")
    evidence = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    evidence.mkdir()
    segment = evidence / f"{txid}.json"
    segment.write_bytes(b'{"attacker":true}\n')
    replacement = evidence / "replacement.json"
    replacement.write_bytes(b'{"replacement":true}\n')
    raced: list[str] = []

    def _replace_during_lock(source: Path, _destination: Path) -> None:
        if source.name != segment.name:
            return
        try:
            os.replace(replacement, source)
        except OSError:
            raced.append("DENIED")
        else:
            raced.append("REPLACED")

    monkeypatch.setattr(
        rooted_io, "_reparse_pre_quarantine_hook", _replace_during_lock
    )
    try:
        V._retire_exact_reparse_object(
            scratchpad, "rogue", phase_name="inventory_chunk_a"
        )
    except Exception:
        pass
    monkeypatch.setattr(
        rooted_io, "_reparse_pre_quarantine_hook", lambda *_args: None
    )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert raced
    assert not os.path.lexists(rogue)
    assert marker.read_bytes() == b"external exact"
    assert json.loads(segment.read_text(encoding="utf-8"))["path"] == "rogue"


def test_containment_forged_prepared_for_ordinary_file_is_inert_and_resumable(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    victim = project / "victim.txt"
    victim.write_bytes(b"ordinary project bytes must never move")
    prepared = _write_forged_containment_prepared_for_live_object(
        scratchpad, project, "victim.txt"
    )

    for _ in range(2):
        V._recover_containment_reparse_transactions(
            scratchpad, allowed_source_roots=(scratchpad, project)
        )

    assert victim.read_bytes() == b"ordinary project bytes must never move"
    assert prepared.is_file()
    assert list((scratchpad / "_containment_reparse_quarantine").iterdir()) == []
    state = json.loads((scratchpad / "_artifact_state.json").read_text(
        encoding="utf-8"
    ))
    debts = [
        row for row in state["containment_events"]
        if row.get("disposition")
        == "INVALID_PREPARED_ROWS_PRESERVED_AS_INERT_DEBT"
    ]
    assert len(debts) == 1
    assert debts[0]["count"] == 1


def test_containment_2049_ordinary_file_forgeries_do_not_consume_valid_cap(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    project = tmp_path / "project"
    scratchpad.mkdir()
    project.mkdir()
    victims: list[Path] = []
    for ordinal in range(V._CONTAINMENT_REPARSE_MAX_TRANSACTIONS + 1):
        victim = project / f"victim-{ordinal:04d}.txt"
        victim.write_bytes(f"ordinary-{ordinal}".encode("ascii"))
        victims.append(victim)
        _write_forged_containment_prepared_for_live_object(
            scratchpad, project, victim.name
        )

    V._recover_containment_reparse_transactions(
        scratchpad, allowed_source_roots=(scratchpad, project)
    )
    V._recover_containment_reparse_transactions(
        scratchpad, allowed_source_roots=(scratchpad, project)
    )

    assert all(path.read_bytes().startswith(b"ordinary-") for path in victims)
    assert list((scratchpad / "_containment_reparse_quarantine").iterdir()) == []
    state = json.loads((scratchpad / "_artifact_state.json").read_text(
        encoding="utf-8"
    ))
    debts = [
        row for row in state["containment_events"]
        if row.get("disposition")
        == "INVALID_PREPARED_ROWS_PRESERVED_AS_INERT_DEBT"
    ]
    assert len(debts) == 1
    assert debts[0]["count"] == V._CONTAINMENT_REPARSE_MAX_TRANSACTIONS + 1


@pytest.mark.parametrize(
    "crash_point",
    [
        "after_prepared",
        "after_quarantine",
        "after_retired",
        "after_evidence",
        "after_committed",
    ],
)
def test_containment_near_cap_state_reserves_segment_before_every_mutation(
    tmp_path: Path,
    crash_point: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    state_path = scratchpad / "_artifact_state.json"
    prefix = b'{"artifacts":{},"padding":"'
    suffix = b'"}\n'
    state_raw = prefix + (
        b"A" * (V._ARTIFACT_STATE_MAX_BYTES - len(prefix) - len(suffix))
    ) + suffix
    assert len(state_raw) == V._ARTIFACT_STATE_MAX_BYTES
    state_path.write_bytes(state_raw)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    link = scratchpad / "rogue"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    def _crash(point: str) -> None:
        if point == crash_point:
            raise RuntimeError(f"near-cap crash at {point}")

    with pytest.raises(RuntimeError, match="near-cap crash"):
        V._retire_exact_reparse_object(
            scratchpad,
            "rogue",
            phase_name="inventory_chunk_a",
            failure_injector=_crash,
        )
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert state_path.read_bytes() == state_raw
    assert not os.path.lexists(link)
    assert marker.read_bytes() == b"external exact"
    evidence = list((
        scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    ).glob("[0-9a-f]*.json"))
    assert len(evidence) == 1
    event = json.loads(evidence[0].read_text(encoding="utf-8"))
    assert event["path"] == "rogue"
    assert event["disposition"] == "REPARSE_OBJECT_RETIRED_NOFOLLOW"
    assert not list((
        scratchpad / V._CONTAINMENT_REPARSE_JOURNAL
    ).glob("*.json"))


@pytest.mark.parametrize("control_tag", ["journal", "evidence"])
def test_containment_control_archive_plus_flat_prepared_recovers_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    control_tag: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker.txt"
    marker.write_bytes(b"external exact")
    poisoned = scratchpad / V._CONTAINMENT_CONTROL_NAMES[control_tag]
    try:
        os.symlink(outside, poisoned, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    pending, debts = V._prepare_containment_control_roots(scratchpad)
    assert debts == [] and len(pending) == 1
    payload = pending[0]
    prepared = scratchpad / (
        f"._containment-control-{control_tag}-"
        f"{payload['transaction_id']}.prepared.json"
    )
    original_unlink = rooted_io.durable_unlink
    crashed = False

    def _crash_prepared_cleanup(path: Path) -> None:
        nonlocal crashed
        if Path(path) == prepared and not crashed:
            crashed = True
            raise RuntimeError("crash before flat prepared cleanup")
        original_unlink(path)

    monkeypatch.setattr(rooted_io, "durable_unlink", _crash_prepared_cleanup)
    with pytest.raises(RuntimeError, match="flat prepared cleanup"):
        V._finalize_containment_control_roots(scratchpad, pending)
    assert prepared.is_file()
    assert os.path.lexists(
        scratchpad / str(payload["quarantine_relative"])
    )

    monkeypatch.setattr(rooted_io, "durable_unlink", original_unlink)
    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not prepared.exists()
    assert marker.read_bytes() == b"external exact"
    assert os.path.lexists(
        scratchpad / str(payload["quarantine_relative"])
    )


def test_containment_state_reparse_cannot_deadlock_prior_retirement(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    external_state = outside / "state.json"
    external_state.write_bytes(b'{"external":"unchanged"}')
    target = outside / "target"
    target.mkdir()
    link = scratchpad / "!link"
    try:
        os.symlink(target, link, target_is_directory=True)
        os.symlink(external_state, scratchpad / "_artifact_state.json")
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    with pytest.raises(Exception):
        V._retire_exact_reparse_object(
            scratchpad,
            "!link",
            phase_name="inventory_chunk_a",
        )
    assert not os.path.lexists(link)

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert external_state.read_bytes() == b'{"external":"unchanged"}'
    state = json.loads((
        scratchpad / "_artifact_state.json"
    ).read_text(encoding="utf-8"))
    retired = {row.get("path") for row in state["containment_events"]}
    assert {"!link", "_artifact_state.json"}.issubset(retired)


def test_containment_malformed_prepared_row_is_inert_not_resume_dos(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    journal = scratchpad / "_containment_reparse_journal"
    journal.mkdir()
    poison = journal / (("0" * 64) + ".prepared.json")
    poison.write_bytes(b'{"schema":"attacker"}')

    V._snapshot_file_state(scratchpad, str(tmp_path))
    V._snapshot_file_state(scratchpad, str(tmp_path))

    assert poison.read_bytes() == b'{"schema":"attacker"}'
    state = json.loads((
        scratchpad / "_artifact_state.json"
    ).read_text(encoding="utf-8"))
    debts = [
        row for row in state["containment_events"]
        if row.get("disposition")
        == "INVALID_PREPARED_ROWS_PRESERVED_AS_INERT_DEBT"
    ]
    assert len(debts) == 1
    assert debts[0]["count"] == 1
    assert poison.name in debts[0]["samples"]


def _invalid_prepared_scan_debt(
    journal: Path,
    prepared_names: list[str],
) -> dict:
    values: list[int] = []
    reason = (
        "RuntimeError: containment reparse prepared record is malformed"
    )
    for name in prepared_names:
        identity = list(V._containment_identity(rooted_io.lstat(journal / name)))
        digest = hashlib.sha256(json.dumps(
            {"name": name, "identity": identity, "reason": reason},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).digest()
        values.append(int.from_bytes(digest, "big"))
    return {
        "schema": "plamen.containment-invalid-journal-debt/v2",
        "disposition": "INVALID_PREPARED_ROWS_PRESERVED_AS_INERT_DEBT",
        "count": len(values),
        "multiset_sum": f"{sum(values) % (1 << 256):064x}",
        "multiset_xor": f"{__import__('functools').reduce(int.__xor__, values, 0):064x}",
        "samples": sorted(prepared_names)[:16],
        "journal_identity": list(
            V._containment_identity(rooted_io.lstat(journal))
        ),
    }


@pytest.mark.parametrize("shape", ["ordinary", "directory", "symlink", "hardlink"])
def test_containment_scan_debt_segment_collision_is_retired_and_resumable(
    tmp_path: Path,
    shape: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    journal = scratchpad / V._CONTAINMENT_REPARSE_JOURNAL
    quarantine = scratchpad / V._CONTAINMENT_REPARSE_QUARANTINE
    evidence = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    journal.mkdir()
    quarantine.mkdir()
    evidence.mkdir()
    prepared_name = ("0" * 64) + ".prepared.json"
    (journal / prepared_name).write_bytes(b"{}\n")
    debt = _invalid_prepared_scan_debt(journal, [prepared_name])
    debt_id = hashlib.sha256(json.dumps(
        debt, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    segment = evidence / f"debt-{debt_id}.json"
    external = tmp_path / "external-debt-target"
    external.write_bytes(b"external debt bytes")
    if shape == "ordinary":
        segment.write_bytes(b'{"attacker":true}\n')
    elif shape == "directory":
        segment.mkdir()
        (segment / "child").write_bytes(b"child exact")
    elif shape == "symlink":
        try:
            os.symlink(external, segment)
        except OSError as exc:
            pytest.skip(f"file symlink unavailable: {exc}")
    else:
        os.link(external, segment)

    for _ in range(2):
        V._recover_containment_reparse_transactions(
            scratchpad, allowed_source_roots=(scratchpad, tmp_path)
        )

    event = json.loads(segment.read_text(encoding="utf-8"))
    assert event["debt_id"] == debt_id
    assert event["count"] == 1
    assert external.read_bytes() == b"external debt bytes"
    assert len(list(evidence.glob(
        f"._foreign-debt-{debt_id}.json-*.object"
    ))) == 1


def test_containment_2049_invalid_rows_cannot_use_debt_segment_collision_as_cap(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    journal = scratchpad / V._CONTAINMENT_REPARSE_JOURNAL
    quarantine = scratchpad / V._CONTAINMENT_REPARSE_QUARANTINE
    evidence = scratchpad / V._CONTAINMENT_REPARSE_EVIDENCE
    journal.mkdir()
    quarantine.mkdir()
    evidence.mkdir()
    prepared_names: list[str] = []
    for ordinal in range(V._CONTAINMENT_REPARSE_MAX_TRANSACTIONS + 1):
        name = f"{ordinal:064x}.prepared.json"
        (journal / name).write_bytes(b"{}\n")
        prepared_names.append(name)
    debt = _invalid_prepared_scan_debt(journal, prepared_names)
    debt_id = hashlib.sha256(json.dumps(
        debt, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")).hexdigest()
    segment = evidence / f"debt-{debt_id}.json"
    segment.write_bytes(b'{"attacker":true}\n')

    for _ in range(2):
        V._recover_containment_reparse_transactions(
            scratchpad, allowed_source_roots=(scratchpad, tmp_path)
        )

    event = json.loads(segment.read_text(encoding="utf-8"))
    assert event["count"] == V._CONTAINMENT_REPARSE_MAX_TRANSACTIONS + 1
    assert len(event["samples"]) == 16
    assert len(list(evidence.glob(
        f"._foreign-debt-{debt_id}.json-*.object"
    ))) == 1


def test_containment_completed_rows_do_not_consume_outstanding_cap(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    journal = scratchpad / "_containment_reparse_journal"
    journal.mkdir()
    for index in range(V._CONTAINMENT_REPARSE_MAX_TRANSACTIONS + 1):
        (journal / f"{index:064x}.committed.json").write_bytes(b"{}")

    V._snapshot_file_state(scratchpad, str(tmp_path))


@pytest.mark.parametrize(
    "crash_point",
    [
        "after_prepared",
        "after_quarantine",
        "after_retired",
        "after_evidence",
        "after_committed",
    ],
)
def test_containment_reparse_retirement_recovers_every_durable_prefix(
    tmp_path: Path,
    crash_point: str,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "authority.txt"
    external.write_bytes(b"external target remains exact")
    link = scratchpad / "rogue"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink unavailable: {exc}")

    def _crash(point: str) -> None:
        if point == crash_point:
            raise RuntimeError(f"injected crash at {point}")

    with pytest.raises(RuntimeError, match="injected crash"):
        V._retire_exact_reparse_object(
            scratchpad,
            "rogue",
            phase_name="inventory_chunk_a",
            failure_injector=_crash,
        )

    V._snapshot_file_state(scratchpad, str(tmp_path))
    assert not os.path.lexists(link)
    assert external.read_bytes() == b"external target remains exact"
    state = json.loads(
        (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
    )
    events = [
        row for row in state["containment_events"]
        if row.get("path") == "rogue"
    ]
    assert len(events) == 1
    txid = events[0]["transaction_id"]
    journal = scratchpad / "_containment_reparse_journal"
    assert not (journal / f"{txid}.prepared.json").exists()
    assert not (journal / f"{txid}.retired.json").exists()
    assert not (journal / f"{txid}.committed.json").exists()
    assert os.path.lexists(
        scratchpad / "_containment_reparse_quarantine" / f"{txid}.link"
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows handle race regression")
def test_containment_reparse_parent_swap_is_denied_by_retained_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    parent = scratchpad / "nested"
    parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    external = outside / "child.txt"
    external.write_bytes(b"never mutate me")
    link = parent / "rogue"
    os.symlink(outside, link, target_is_directory=True)
    moved_parent = scratchpad / "nested-swapped"
    moved_root = tmp_path / "scratch-swapped"
    swap_denied: list[bool] = []

    def _swap(_source: Path, _destination: Path) -> None:
        for source, destination in (
            (parent, moved_parent),
            (scratchpad, moved_root),
        ):
            try:
                os.replace(source, destination)
            except OSError:
                swap_denied.append(True)
            else:
                swap_denied.append(False)

    monkeypatch.setattr(rooted_io, "_reparse_pre_quarantine_hook", _swap)
    assert V._retire_exact_reparse_object(
        scratchpad,
        "nested/rogue",
        phase_name="inventory_chunk_a",
    )
    assert swap_denied == [True, True]
    assert parent.is_dir()
    assert not os.path.lexists(link)
    assert external.read_bytes() == b"never mutate me"


@pytest.mark.skipif(os.name != "nt", reason="Windows ancestor-chain race")
@pytest.mark.parametrize("swapped_chain", ["source", "destination"])
def test_containment_windows_prehandle_nested_swap_never_mutates_displaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swapped_chain: str,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    source_parent = (
        nested / "source" if swapped_chain == "source" else root / "source"
    )
    destination_parent = (
        nested / "quarantine"
        if swapped_chain == "destination"
        else root / "quarantine"
    )
    source_parent.mkdir(parents=True)
    destination_parent.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "marker.txt"
    marker.write_bytes(b"external target exact")
    link = source_parent / "rogue"
    os.symlink(target, link, target_is_directory=True)
    expected = V._containment_identity(os.lstat(link))
    displaced_root = tmp_path / "outside"
    displaced_root.mkdir()
    displaced = displaced_root / "nested"

    def _swap(*_args: object) -> None:
        os.replace(nested, displaced)
        os.symlink(displaced, nested, target_is_directory=True)

    monkeypatch.setattr(rooted_io, "_reparse_pre_handle_hook", _swap)
    for _ in range(2):
        with pytest.raises(Exception):
            rooted_io.durable_quarantine_reparse(
                root,
                (
                    "nested/source/rogue"
                    if swapped_chain == "source" else "source/rogue"
                ),
                root,
                (
                    "nested/quarantine/rogue.link"
                    if swapped_chain == "destination"
                    else "quarantine/rogue.link"
                ),
                expected_identity=expected,
            )
        monkeypatch.setattr(
            rooted_io, "_reparse_pre_handle_hook", lambda *_args: None
        )
    displaced_link = (
        displaced / "source" / "rogue"
        if swapped_chain == "source" else root / "source" / "rogue"
    )
    assert os.path.lexists(displaced_link)
    assert not os.path.lexists(displaced / "quarantine" / "rogue.link")
    assert not os.path.lexists(root / "quarantine" / "rogue.link")
    assert marker.read_bytes() == b"external target exact"


@pytest.mark.skipif(os.name != "nt", reason="Windows authority-root lock")
def test_containment_windows_prehandle_root_swap_is_denied_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    source_parent = root / "source"
    destination_parent = root / "quarantine"
    source_parent.mkdir(parents=True)
    destination_parent.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    link = source_parent / "rogue"
    os.symlink(target, link, target_is_directory=True)
    expected = V._containment_identity(os.lstat(link))
    displaced = tmp_path / "displaced-root"
    denied: list[bool] = []

    def _swap(*_args: object) -> None:
        try:
            os.replace(root, displaced)
        except OSError:
            denied.append(True)
        else:
            denied.append(False)
        raise RuntimeError("stop after authority-root swap probe")

    monkeypatch.setattr(rooted_io, "_reparse_pre_handle_hook", _swap)
    with pytest.raises(RuntimeError, match="authority-root swap probe"):
        rooted_io.durable_quarantine_reparse(
            root,
            "source/rogue",
            root,
            "quarantine/rogue.link",
            expected_identity=expected,
        )

    assert denied == [True]
    assert os.path.lexists(link)
    assert not os.path.lexists(destination_parent / "rogue.link")


@pytest.mark.skipif(os.name == "nt", reason="POSIX ancestor-chain race")
@pytest.mark.parametrize("swapped_chain", ["root", "source", "destination"])
def test_containment_posix_prehandle_swap_never_mutates_displaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swapped_chain: str,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    source_parent = (
        nested / "source" if swapped_chain == "source" else root / "source"
    )
    destination_parent = (
        nested / "quarantine"
        if swapped_chain == "destination" else root / "quarantine"
    )
    source_parent.mkdir(parents=True)
    destination_parent.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "target"
    target.mkdir()
    marker = target / "marker.txt"
    marker.write_bytes(b"external target exact")
    link = source_parent / "rogue"
    os.symlink(target, link, target_is_directory=True)
    expected = V._containment_identity(os.lstat(link))
    outside = tmp_path / "outside"
    outside.mkdir()

    def _swap(*_args: object) -> None:
        if swapped_chain == "root":
            displaced = outside / "root"
            os.rename(root, displaced)
            os.symlink(displaced, root, target_is_directory=True)
        else:
            displaced = outside / "nested"
            os.rename(nested, displaced)
            os.symlink(displaced, nested, target_is_directory=True)

    monkeypatch.setattr(rooted_io, "_reparse_pre_handle_hook", _swap)
    with pytest.raises(Exception):
        rooted_io.durable_quarantine_reparse(
            root,
            (
                "nested/source/rogue"
                if swapped_chain == "source" else "source/rogue"
            ),
            root,
            (
                "nested/quarantine/rogue.link"
                if swapped_chain == "destination"
                else "quarantine/rogue.link"
            ),
            expected_identity=expected,
        )

    displaced_link = (
        outside / "root" / "source" / "rogue"
        if swapped_chain == "root"
        else outside / "nested" / "source" / "rogue"
        if swapped_chain == "source"
        else root / "source" / "rogue"
    )
    assert os.path.lexists(displaced_link)
    assert marker.read_bytes() == b"external target exact"


@pytest.mark.skipif(os.name == "nt", reason="POSIX dir-fd race regression")
def test_containment_posix_parent_swap_never_publishes_external(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    source_parent = root / "source"
    destination_parent = root / "quarantine"
    source_parent.mkdir(parents=True)
    destination_parent.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "target"
    target.mkdir()
    link = source_parent / "rogue"
    os.symlink(target, link, target_is_directory=True)
    retained_destination = root / "quarantine-retained"

    def _swap(_source: Path, _destination: Path) -> None:
        os.rename(destination_parent, retained_destination)
        os.symlink(outside, destination_parent, target_is_directory=True)

    monkeypatch.setattr(rooted_io, "_reparse_pre_quarantine_hook", _swap)
    rooted_io.durable_quarantine_reparse(
        root,
        "source/rogue",
        root,
        "quarantine/rogue.link",
        expected_identity=V._containment_identity(os.lstat(link)),
    )

    assert list(outside.iterdir()) == []
    assert os.path.lexists(retained_destination / "rogue.link")
    assert not os.path.lexists(link)


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction regression")
def test_containment_snapshot_retires_real_windows_junction_without_traversal(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    outside = tmp_path / "outside-junction"
    outside.mkdir()
    foreign = outside / "findings_inventory.md"
    foreign.write_bytes(b"must remain external")
    junction = scratchpad / "junction"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"junction creation unavailable: {result.stderr}")
    try:
        V._snapshot_file_state(scratchpad, str(tmp_path))
        assert not os.path.lexists(junction)
        assert foreign.read_bytes() == b"must remain external"
        state = json.loads(
            (scratchpad / "_artifact_state.json").read_text(encoding="utf-8")
        )
        assert state["containment_events"][-1]["path"] == "junction"

        # Repeated resume remains bounded and does not touch the target.
        V._snapshot_file_state(scratchpad, str(tmp_path))
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        moved, failed = V._quarantine_foreign_phase_writes(
            scratchpad,
            str(tmp_path),
            "inventory_chunk_a",
            ["junction/findings_inventory.md"],
        )
        assert moved == ["junction/findings_inventory.md"]
        assert failed == []
        assert not os.path.lexists(junction)
        assert foreign.read_bytes() == b"must remain external"
    finally:
        if os.path.lexists(junction):
            os.rmdir(junction)


def test_containment_snapshot_enforces_bounded_file_denominator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad = tmp_path / "scratch"
    scratchpad.mkdir()
    for index in range(3):
        (scratchpad / f"row-{index}.md").write_bytes(b"x")
    monkeypatch.setattr(V, "_SCRATCHPAD_STATE_MAX_FILES", 2)

    with pytest.raises(RuntimeError, match="bounded file limit"):
        V._snapshot_file_state(scratchpad, str(tmp_path))


def test_inventory_retry_rejects_live_output_mutation_before_quarantine_or_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="d5567891-1234-4234-8234-123456789abc"
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture exact reconciliation rejection"],
    )
    mutated = output.read_bytes() + b"\nforeign mutation after sealed plan\n"
    output.write_bytes(mutated)
    launches: list[int] = []
    monkeypatch.setattr(
        D,
        "build_phase_prompt",
        lambda *_args, **_kwargs: launches.append(2) or "fixture prompt",
    )

    assert D._run_phase_once(phase, config, attempt=2) == D.EXIT_ERROR
    assert launches == []
    assert output.read_bytes() == mutated
    assert not (tmp_path / "_retry_quarantine").exists()


def test_inventory_retry_rejects_postbuild_prompt_translation_plan_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path, run_id="d8567891-1234-4234-8234-123456789abc"
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture exact reconciliation rejection"],
    )
    plan = config["_inventory_retry_prompt_plans"][phase.name]
    canonical = json.dumps(plan, indent=2, sort_keys=True)
    monkeypatch.setattr(
        D,
        "build_phase_prompt",
        lambda *_args, **_kwargs: "# retry\n\n```json\n" + canonical + "\n```\n",
    )
    monkeypatch.setattr(
        D,
        "_translate_prompt_for_codex",
        lambda text, **_kwargs: text.replace(
            plan["plan_digest"], "0" * 64
        ),
    )

    assert D._run_phase_once(phase, config, attempt=2) == D.EXIT_ERROR
    assert not (
        tmp_path / f"_prompt_{phase.name}.attempt2.md"
    ).exists()


def test_inventory_retry_attempt_three_requires_durable_attempt_two_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="d6567891-1234-4234-8234-123456789abc"
    )
    config["_active_model_attempts"][phase.name] = 2
    config["_phase_io_model_attempts"][phase.name] = 2
    launches: list[int] = []
    monkeypatch.setattr(
        D,
        "run_phase",
        lambda *_args, **_kwargs: launches.append(3) or 0,
    )

    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=Checkpoint(run_id=config["_run_id"]),
        scratchpad=tmp_path,
        attempt=3,
        issues=["attempt three must not skip durable attempt two"],
    ) == D.EXIT_ERROR
    assert launches == []
    assert output.exists()
    assert not (
        tmp_path / "_retry_plans" / phase.name
        / "phase.attempt-0003.json"
    ).exists()


def test_inventory_retry_attempt_three_accepts_exact_attempt_two_lineage(
    tmp_path: Path,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="d7567891-1234-4234-8234-123456789abc"
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["attempt one rejection"],
    )
    archived, issues = D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    assert issues == [] and archived == [output.name]
    _chunk(tmp_path, phase.name, [("CC-2", "attempt two", ("TF-1",))])
    _activate_chunk_model(
        tmp_path, tmp_path, config, phase.name, attempt=2
    )
    config["_active_model_attempts"][phase.name] = 2
    config["_phase_io_model_attempts"][phase.name] = 2
    _seal_inventory_retry_terminal(
        tmp_path,
        phase,
        config,
        checkpoint,
        attempt=2,
        issue="attempt two rejection",
    )

    failures = D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=3,
        issues=["attempt two rejection"],
    )

    assert failures
    plan = json.loads((
        tmp_path / "_retry_plans" / phase.name
        / "phase.attempt-0003.json"
    ).read_text(encoding="utf-8"))
    assert plan["attempt"] == 3


@pytest.mark.parametrize(
    "transport_issue,return_code",
    [
        ("Codex unavailable-model transport recovery", 1),
        ("Codex model-capacity transport recovery", 1),
        ("Codex rejected-model transport recovery", 1),
        ("Codex content-filter transport recovery", 1),
        ("operator-resumed interrupted MODEL attempt", 0),
        ("Anthropic overload transport recovery", 1),
        ("provider rate-limit transport recovery", 1),
    ],
)
def test_inventory_retry_transport_wrappers_publish_plan_bound_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transport_issue: str,
    return_code: int,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4())
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _fake_run(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt
        )
        if return_code == 0:
            _chunk(
                tmp_path,
                phase.name,
                [("CC-2", "transport completion", ("TF-1",))],
            )
            _activate_chunk_model(
                tmp_path, tmp_path, config, phase.name, attempt=attempt
            )
        return return_code

    monkeypatch.setattr(D, "run_phase", _fake_run)

    rc = D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=2,
        issues=[transport_issue],
    )

    assert rc == return_code
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    receipt = RetryReceipt.from_dict(
        json.loads(receipt_path.read_text(encoding="utf-8"))
    )
    plan = config["_inventory_retry_prompt_plans"][phase.name]
    assert receipt.retry_plan_digest == plan["plan_digest"]
    assert receipt.terminal_rc == return_code
    if return_code:
        assert receipt.status == "FAILED"
    else:
        assert receipt.status != "INTERRUPTED"
    assert receipt.prompt_digest == hashlib.sha256(
        (tmp_path / f"_prompt_{phase.name}.attempt2.md").read_bytes()
    ).hexdigest()


def test_inventory_retry_transport_receipt_uses_full_validator_not_shallow_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4())
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])
    shallow_results: list[bool] = []

    def _fake_run(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt
        )
        output.write_text(
            "# superficially substantial but structurally invalid\n"
            + ("x" * max(4096, phase.min_artifact_bytes + 32)),
            encoding="utf-8",
        )
        shallow_results.append(
            D.gate_passes(tmp_path, config["project_root"], phase)[0]
        )
        _write_bound_inventory_prompt(
            tmp_path,
            phase.name,
            attempt,
            config["_inventory_retry_prompt_plans"][phase.name],
        )
        _activate_chunk_model(
            tmp_path, tmp_path, config, phase.name, attempt=attempt
        )
        return 0

    monkeypatch.setattr(D, "run_phase", _fake_run)
    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture semantic rejection"],
    ) == 0
    assert shallow_results == [True]
    receipt = RetryReceipt.from_dict(json.loads((
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    ).read_text(encoding="utf-8")))
    assert receipt.status != "CLEARED"
    assert receipt.failure_instance_ids_after
    assert receipt.gate_ids_after


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_inventory_retry_interruption_has_plan_bound_terminal_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4()), backend=backend
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _fake_run(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt
        )
        return -3

    monkeypatch.setattr(D, "run_phase", _fake_run)
    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=2,
        issues=["operator interrupted transport"],
    ) == -3
    receipt = RetryReceipt.from_dict(json.loads((
        tmp_path / "_retry_receipts" / phase.name
        / "transport.interruption-0001.attempt2.json"
    ).read_text(encoding="utf-8")))
    assert receipt.status == "INTERRUPTED"
    assert receipt.terminal_rc == -3
    assert receipt.retry_plan_digest == (
        config["_inventory_retry_prompt_plans"][phase.name]["plan_digest"]
    )
    assert receipt.failure_instance_ids_after
    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts", "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert issues == []
    assert (prior, successor) == (1, 2)


def _bind_inventory_retry_attempt_for_terminal_test(
    root: Path,
    phase: object,
    config: dict,
    attempt: int,
    *,
    expect_archive: bool = True,
) -> None:
    archived, issues = D._prepare_inventory_retry_prestate(
        phase,
        root,
        config,
        prior_attempt=attempt - 1,
        next_attempt=attempt,
    )
    assert issues == []
    assert archived == (
        ["findings_inventory_chunk_a.md"] if expect_archive else []
    )
    config["_active_model_attempts"][phase.name] = attempt
    config["_phase_io_model_attempts"][phase.name] = attempt
    assert D._bind_typed_model_phase_inputs(phase, root, config) == []
    _write_bound_inventory_prompt(
        root,
        phase.name,
        attempt,
        config["_inventory_retry_prompt_plans"][phase.name],
    )


def _produce_failed_inventory_retry_attempt(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    backend: str,
    attempt: int = 2,
) -> tuple[object, dict, Checkpoint]:
    phase, config, _output = _active_inventory_retry_fixture(
        root, run_id=str(__import__("uuid").uuid4()), backend=backend
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _terminal_rc1(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            root,
            phase,
            config,
            attempt,
            expect_archive=(attempt == 2),
        )
        return 1

    monkeypatch.setattr(D, "run_phase", _terminal_rc1)
    for ordinal in range(2, attempt + 1):
        assert D._run_retry_phase(
            phase,
            config,
            checkpoint=checkpoint,
            scratchpad=root,
            attempt=ordinal,
            issues=[f"fixture attempt {ordinal} failed"],
        ) == 1
    return phase, config, checkpoint


@pytest.mark.parametrize(
    "fault_point,receipt_already_published",
    [
        ("after_terminal_authority", False),
        ("after_receipt_publication", True),
    ],
)
def test_inventory_retry_terminal_authority_recovers_receipt_fault_prefixes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_point: str,
    receipt_already_published: bool,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4())
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _fake_run(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=(attempt == 2)
        )
        return 1

    def _fault(point: str) -> None:
        if point == fault_point:
            raise RuntimeError(f"injected receipt crash at {point}")

    monkeypatch.setattr(D, "run_phase", _fake_run)
    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture terminal receipt crash"],
        receipt_failure_injector=_fault,
    ) == D.EXIT_ERROR

    authority = (
        tmp_path / "_retry_terminal" / phase.name
        / "transport.attempt-0002.json"
    )
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    assert authority.is_file()
    assert receipt_path.is_file() is receipt_already_published

    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts",
            "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert issues == []
    assert (prior, successor) == (2, 3)
    recovered = RetryReceipt.from_dict(json.loads(
        receipt_path.read_text(encoding="utf-8")
    ))
    assert recovered.terminal_rc == 1
    assert recovered.status == "FAILED"


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_inventory_retry_plan_receipt_and_model_ledger_share_exact_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    phase, config, _checkpoint = _produce_failed_inventory_retry_attempt(
        tmp_path, monkeypatch, backend=backend
    )
    plan = json.loads((
        tmp_path / "_retry_plans" / phase.name
        / "phase.attempt-0002.json"
    ).read_text(encoding="utf-8"))
    receipt = RetryReceipt.from_dict(json.loads((
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    ).read_text(encoding="utf-8")))
    _key, unit = D._inventory_attempt_unit(phase, tmp_path, config, 2)
    assert unit is not None
    assert {
        plan["contract_digest"],
        receipt.contract_digest,
        unit["contract_digest"],
    } == {unit["contract_digest"]}
    assert {
        plan["launch_digest"],
        receipt.launch_digest,
        unit["launch_digest"],
    } == {unit["launch_digest"]}
    assert receipt.created_at == unit["recorded_at"]


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_inventory_terminal_recovery_rejects_noncanonical_exact_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
) -> None:
    phase, config, _checkpoint = _produce_failed_inventory_retry_attempt(
        tmp_path, monkeypatch, backend=backend
    )
    authority = (
        tmp_path / "_retry_terminal" / phase.name
        / "transport.attempt-0002.json"
    )
    payload = json.loads(authority.read_text(encoding="utf-8"))
    authority.write_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    receipt_path.unlink()

    issues = D._recover_inventory_terminal_receipt(
        phase, tmp_path, config, 2
    )
    assert any("bytes are noncanonical" in issue for issue in issues)
    assert not receipt_path.exists()


@pytest.mark.parametrize("backend", ["codex", "claude"])
@pytest.mark.parametrize("field", ["schema_id", "schema_version", "created_at"])
def test_inventory_terminal_recovery_derives_known_receipt_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    field: str,
) -> None:
    phase, config, _checkpoint = _produce_failed_inventory_retry_attempt(
        tmp_path, monkeypatch, backend=backend
    )
    authority = (
        tmp_path / "_retry_terminal" / phase.name
        / "transport.attempt-0002.json"
    )
    payload = json.loads(authority.read_text(encoding="utf-8"))
    if field == "schema_id":
        payload["receipt"][field] = "attacker.retry.schema/v99"
    elif field == "schema_version":
        payload["receipt"][field] += 1
    else:
        payload["receipt"][field] = "2099-01-01T00:00:00+00:00"
    unsigned = dict(payload)
    unsigned.pop("authority_digest")
    payload["authority_digest"] = D._stable_payload_digest(unsigned)
    authority.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    receipt_path.unlink()

    issues = D._recover_inventory_terminal_receipt(
        phase, tmp_path, config, 2
    )
    assert issues
    assert not receipt_path.exists()


@pytest.mark.parametrize("backend", ["codex", "claude"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("gate_class", "ADVISORY_QUALITY"),
        ("evidence_paths", ["attacker/evidence.md"]),
        ("repair_owner", "attacker-owner"),
        ("fallback_policy", "NO_SHIP_QUARANTINE"),
        ("allowed_fallback", "attacker fallback"),
        ("schema_id", "attacker.failure.schema/v9"),
        ("schema_version", 9),
    ],
)
def test_inventory_terminal_recovery_rejects_failure_semantic_field_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    field: str,
    value: object,
) -> None:
    phase, config, _checkpoint = _produce_failed_inventory_retry_attempt(
        tmp_path, monkeypatch, backend=backend
    )
    authority = (
        tmp_path / "_retry_terminal" / phase.name
        / "transport.attempt-0002.json"
    )
    payload = json.loads(authority.read_text(encoding="utf-8"))
    assert payload["failures_after"]
    payload["failures_after"][0][field] = value
    unsigned = dict(payload)
    unsigned.pop("authority_digest")
    payload["authority_digest"] = D._stable_payload_digest(unsigned)
    authority.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    receipt_path.unlink()

    issues = D._recover_inventory_terminal_receipt(
        phase, tmp_path, config, 2
    )
    assert issues
    assert not receipt_path.exists()


@pytest.mark.parametrize("backend", ["codex", "claude"])
@pytest.mark.parametrize("ledger_field", ["contract_digest", "launch_digest"])
def test_inventory_terminal_recovery_rejects_split_model_ledger_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    ledger_field: str,
) -> None:
    phase, config, _checkpoint = _produce_failed_inventory_retry_attempt(
        tmp_path, monkeypatch, backend=backend
    )
    key, unit = D._inventory_attempt_unit(phase, tmp_path, config, 2)
    assert unit is not None
    state = V._read_artifact_state(tmp_path)
    state["work_units"][key][ledger_field] = "0" * 64
    V._write_artifact_state(tmp_path, state)
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    receipt_path.unlink()

    issues = D._recover_inventory_terminal_receipt(
        phase, tmp_path, config, 2
    )
    assert any("MODEL ledger identity" in issue for issue in issues)
    assert not receipt_path.exists()


@pytest.mark.parametrize("backend", ["codex", "claude"])
@pytest.mark.parametrize("mutation", ["tampered", "missing_middle", "extra"])
def test_inventory_completed_attempt_validates_all_interruption_generations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backend: str,
    mutation: str,
) -> None:
    phase, config, checkpoint = _produce_failed_inventory_retry_attempt(
        tmp_path, monkeypatch, backend=backend
    )

    def _interrupt(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=False
        )
        return -3

    monkeypatch.setattr(D, "run_phase", _interrupt)
    interruption_count = 2 if mutation == "missing_middle" else 1
    for _ in range(interruption_count):
        assert D._run_retry_phase(
            phase,
            config,
            checkpoint=checkpoint,
            scratchpad=tmp_path,
            attempt=3,
            issues=["fixture attempt three interrupted"],
        ) == -3

    def _terminal(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=False
        )
        return 1

    monkeypatch.setattr(D, "run_phase", _terminal)
    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=3,
        issues=["fixture attempt three completed"],
    ) == 1

    terminal_dir = tmp_path / "_retry_terminal" / phase.name
    receipt_dir = tmp_path / "_retry_receipts" / phase.name
    first_authority = (
        terminal_dir / "transport.interruption-0001.attempt-0003.json"
    )
    if mutation == "tampered":
        payload = json.loads(first_authority.read_text(encoding="utf-8"))
        first_authority.write_bytes(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        )
    elif mutation == "missing_middle":
        first_authority.unlink()
        (receipt_dir / "transport.interruption-0001.attempt3.json").unlink()
    else:
        (terminal_dir / (
            "transport.interruption-0004.attempt-0003.json"
        )).write_bytes(first_authority.read_bytes())

    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts", "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert (prior, successor) == (3, 3)
    assert issues


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_inventory_final_semantic_attempt_interruption_replays_without_attempt4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path,
        run_id=str(__import__("uuid").uuid4()),
        backend=backend,
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _terminal_rc1(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=(attempt == 2)
        )
        return 1

    monkeypatch.setattr(D, "run_phase", _terminal_rc1)
    assert D._run_retry_phase(
        phase, config, checkpoint=checkpoint, scratchpad=tmp_path,
        attempt=2, issues=["attempt two failed"],
    ) == 1

    def _interrupt(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=False
        )
        output.write_bytes(b"interrupted attempt-three partial postimage")
        return -3

    monkeypatch.setattr(D, "run_phase", _interrupt)
    assert D._run_retry_phase(
        phase, config, checkpoint=checkpoint, scratchpad=tmp_path,
        attempt=3, issues=["attempt three interrupted"],
    ) == -3
    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts", "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    assert D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    ) == (2, 3, [])
    assert D._recover_inventory_terminal_receipt(
        phase, tmp_path, fresh, 2
    ) == []
    assert D._transport_resume_attempt(phase, 3) == 3

    resumed_launches: list[int] = []

    def _resumed_terminal(_phase: object, _config: dict, attempt: int) -> int:
        resumed_launches.append(attempt)
        return _terminal_rc1(_phase, _config, attempt)

    monkeypatch.setattr(D, "run_phase", _resumed_terminal)
    assert D._run_retry_phase(
        phase, config, checkpoint=checkpoint, scratchpad=tmp_path,
        attempt=3, issues=["attempt three resumed"],
    ) == 1
    assert resumed_launches == [3]
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert (prior, successor) == (3, 3)
    assert any("budget is exhausted" in issue for issue in issues)


@pytest.mark.parametrize("backend", ["codex", "claude"])
def test_inventory_interruption_generation_budget_is_bounded_without_attempt4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path,
        run_id=str(__import__("uuid").uuid4()),
        backend=backend,
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _rc1(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=(attempt == 2)
        )
        return 1

    monkeypatch.setattr(D, "run_phase", _rc1)
    assert D._run_retry_phase(
        phase, config, checkpoint=checkpoint, scratchpad=tmp_path,
        attempt=2, issues=["attempt two failed"],
    ) == 1

    launches: list[int] = []

    def _interrupt(_phase: object, _config: dict, attempt: int) -> int:
        launches.append(attempt)
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt, expect_archive=False
        )
        return -3

    monkeypatch.setattr(D, "run_phase", _interrupt)
    for _generation in range(D._INVENTORY_INTERRUPT_TRANSPORT_MAX):
        assert D._run_retry_phase(
            phase, config, checkpoint=checkpoint, scratchpad=tmp_path,
            attempt=3, issues=["attempt three transport interrupted"],
        ) == -3
    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts", "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert (prior, successor) == (3, 3)
    assert any("generation budget is exhausted" in issue for issue in issues)
    assert launches == [3, 3, 3]
    assert not any(
        "attempt4" in path.name or "attempt-0004" in path.name
        for path in tmp_path.rglob("*")
    )
def test_inventory_retry_resume_refuses_terminal_without_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4())
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _fake_run(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt
        )
        return 1

    def _fault(point: str) -> None:
        if point == "after_terminal_before_authority":
            raise RuntimeError("injected crash before terminal authority")

    monkeypatch.setattr(D, "run_phase", _fake_run)
    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture missing terminal authority"],
        receipt_failure_injector=_fault,
    ) == D.EXIT_ERROR
    assert not (
        tmp_path / "_retry_terminal" / phase.name
        / "transport.attempt-0002.json"
    ).exists()

    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts",
            "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert (prior, successor) == (2, 2)
    assert any(
        "attempt 2 has no durable terminal or interrupted transport authority"
        in issue
        for issue in issues
    ), issues


def test_inventory_retry_resume_checks_every_terminal_attempt_without_gaps(
    tmp_path: Path,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4())
    )
    plan_parent = tmp_path / "_retry_plans" / phase.name
    plan_parent.mkdir(parents=True)
    for attempt in (2, 3):
        (plan_parent / f"phase.attempt-{attempt:04d}.json").write_text(
            "fixture input only\n", encoding="utf-8"
        )
        _chunk(
            tmp_path,
            phase.name,
            [(f"CC-{attempt}", f"attempt {attempt}", ("TF-1",))],
        )
        _activate_chunk_model(
            tmp_path, tmp_path, config, phase.name, attempt=attempt
        )

    fresh = {
        key: value for key, value in config.items()
        if key not in {"_active_model_attempts", "_phase_io_model_attempts"}
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )

    assert (prior, successor) == (3, 3)
    assert any(
        "attempt 2 has no durable terminal or interrupted transport authority"
        in row
        for row in issues
    ), issues
    assert not any("attempt 3" in row for row in issues), issues


def test_inventory_retry_receipt_writer_exception_recovers_from_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, _output = _active_inventory_retry_fixture(
        tmp_path, run_id=str(__import__("uuid").uuid4())
    )
    checkpoint = Checkpoint(run_id=config["_run_id"])

    def _fake_run(_phase: object, _config: dict, attempt: int) -> int:
        _bind_inventory_retry_attempt_for_terminal_test(
            tmp_path, phase, config, attempt
        )
        return 1

    original_writer = D._write_retry_receipt

    def _publication_failure(*_args: object, **_kwargs: object) -> Path:
        raise OSError("injected receipt publication failure")

    monkeypatch.setattr(D, "run_phase", _fake_run)
    monkeypatch.setattr(D, "_write_retry_receipt", _publication_failure)
    assert D._run_retry_phase(
        phase,
        config,
        checkpoint=checkpoint,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture receipt publication exception"],
    ) == D.EXIT_ERROR
    receipt_path = (
        tmp_path / "_retry_receipts" / phase.name
        / "transport.attempt2.json"
    )
    assert not receipt_path.exists()

    monkeypatch.setattr(D, "_write_retry_receipt", original_writer)
    fresh = {
        key: value for key, value in config.items()
        if key not in {
            "_active_model_attempts",
            "_phase_io_model_attempts",
            "_inventory_retry_prompt_plans",
        }
    }
    prior, successor, issues = D._inventory_resume_attempt_transition(
        phase, tmp_path, fresh
    )
    assert issues == []
    assert (prior, successor) == (2, 3)
    recovered = RetryReceipt.from_dict(json.loads(
        receipt_path.read_text(encoding="utf-8")
    ))
    assert recovered.terminal_rc == 1
    assert recovered.status == "FAILED"


def test_inventory_retry_restart_replays_terminalized_archive_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="e4567891-1234-4234-8234-123456789abc"
    )
    original = output.read_bytes()
    checkpoint = Checkpoint(run_id=config["_run_id"])
    D._authorize_inventory_retry_launch(
        checkpoint=checkpoint,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=2,
        issues=["fixture exact reconciliation rejection"],
    )
    archived, issues = D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    assert issues == []
    assert archived == [output.name]
    fresh = {
        key: value for key, value in config.items()
        if key not in {"_active_model_attempts", "_phase_io_model_attempts"}
    }
    monkeypatch.setattr(
        D,
        "_bind_typed_model_phase_inputs",
        lambda *_args, **_kwargs: ["fixture stop before provider"],
    )

    assert D._run_phase_once(phase, fresh, attempt=2) == D.EXIT_ERROR
    backup = (
        tmp_path / "_retry_quarantine" / phase.name
        / "attempt-0001" / output.name
    )
    assert not output.exists()
    assert backup.read_bytes() == original

    fresh.pop("_active_model_attempts", None)
    fresh.pop("_phase_io_model_attempts", None)
    assert D._run_phase_once(phase, fresh, attempt=2) == D.EXIT_ERROR
    assert not output.exists()
    assert backup.read_bytes() == original


def test_inventory_quarantine_restore_and_cleanup_are_same_run_only(
    tmp_path: Path,
) -> None:
    phase, config, output = _active_inventory_retry_fixture(
        tmp_path, run_id="f4567891-1234-4234-8234-123456789abc"
    )
    original = output.read_bytes()
    archived, issues = D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    assert issues == [] and archived == [output.name]
    backup = (
        tmp_path / "_retry_quarantine" / phase.name
        / "attempt-0001" / output.name
    )

    other_run = "04567891-1234-4234-8234-123456789abc"
    V._cleanup_quarantine_backups(tmp_path, phase, run_id=other_run)
    V._restore_quarantined_on_retry_failure(
        tmp_path, phase, run_id=other_run
    )
    assert backup.read_bytes() == original
    assert not output.exists()

    V._restore_quarantined_on_retry_failure(
        tmp_path, phase, run_id=config["_run_id"]
    )
    assert output.read_bytes() == original
    assert backup.read_bytes() == original


def test_inventory_nested_quarantine_restores_newest_ledger_bound_bytes(
    tmp_path: Path,
) -> None:
    phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    config = {
        "pipeline": "sc", "mode": "thorough", "language": "evm",
        "cli_backend": "codex", "project_root": str(tmp_path),
        "scratchpad": str(tmp_path),
        "_run_id": "94567891-1234-4234-8234-123456789abc",
        "_active_model_attempts": {phase.name: 1},
        "_phase_io_model_attempts": {phase.name: 1},
    }
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "restore lineage"), encoding="utf-8")
    _manifest(tmp_path, phase.name, source.name)
    _chunk(
        tmp_path, phase.name,
        [("CC-1", "attempt one", ("TF-1",))],
    )
    output = tmp_path / "findings_inventory_chunk_a.md"
    expected = output.read_bytes()
    _activate_chunk_model(tmp_path, tmp_path, config, phase.name)
    archived, issues = D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    assert issues == []
    assert archived == [output.name]
    assert not output.exists()

    V._restore_quarantined_on_retry_failure(
        tmp_path, phase, run_id=config["_run_id"]
    )

    assert output.read_bytes() == expected
    assert (
        tmp_path / "_retry_quarantine" / phase.name
        / "attempt-0001" / output.name
    ).read_bytes() == expected


@pytest.mark.parametrize(
    "tamper,backup_survives",
    [(False, True), (True, True)],
)
def test_inventory_nested_quarantine_cleanup_requires_exact_ledger_bytes(
    tmp_path: Path,
    tamper: bool,
    backup_survives: bool,
) -> None:
    phase = next(
        item for item in SC_PHASES if item.name == "inventory_chunk_a"
    )
    config = {
        "pipeline": "sc", "mode": "thorough", "language": "evm",
        "cli_backend": "codex", "project_root": str(tmp_path),
        "scratchpad": str(tmp_path),
        "_run_id": "a4567891-1234-4234-8234-123456789abc",
        "_active_model_attempts": {phase.name: 1},
        "_phase_io_model_attempts": {phase.name: 1},
    }
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "cleanup lineage"), encoding="utf-8")
    _manifest(tmp_path, phase.name, source.name)
    _chunk(
        tmp_path, phase.name,
        [("CC-1", "attempt one", ("TF-1",))],
    )
    output = tmp_path / "findings_inventory_chunk_a.md"
    _activate_chunk_model(tmp_path, tmp_path, config, phase.name)
    D._prepare_inventory_retry_prestate(
        phase, tmp_path, config, prior_attempt=1, next_attempt=2
    )
    backup = (
        tmp_path / "_retry_quarantine" / phase.name
        / "attempt-0001" / output.name
    )
    if tamper:
        backup.write_bytes(backup.read_bytes() + b"\ntampered\n")
    replacement = b"accepted replacement" * 20
    output.write_bytes(replacement)

    V._cleanup_quarantine_backups(
        tmp_path, phase, run_id=config["_run_id"]
    )

    assert output.read_bytes() == replacement
    assert backup.exists() is backup_survives


def _activate_canonical_inventory(
    project: Path,
    scratchpad: Path,
    config: dict,
) -> None:
    _activate_chunk_model(project, scratchpad, config)
    (scratchpad / "findings_inventory.md").unlink(missing_ok=True)
    result, issues = D._run_inventory_canonical_aggregate_transaction(
        scratchpad=scratchpad,
        config=config,
        phase=next(item for item in SC_PHASES if item.name == "inventory"),
        derivation_kind="single_shard",
    )
    assert result["finding_count"] == 1
    assert issues == []


def _authority(
    root: Path,
    *,
    source: str,
    source_id: str,
    disposition: str,
    target: str = "",
    evidence_file: str = "",
    evidence_record_id: str = "",
) -> None:
    source_path = root / source
    result = reconcile_inventory(root, persist=False)
    candidate = next(
        row for row in result["candidates"]
        if row["source_artifact"] == source and row["source_finding_id"] == source_id
    )
    row = {
        "candidate_key": candidate["candidate_key"],
        "source_artifact": source,
        "source_sha256": _sha(source_path),
        "source_finding_id": source_id,
        "source_block_sha256": candidate["source_block_sha256"],
        "disposition": disposition,
        "target_artifact": "findings_inventory.md" if target else "",
        "target_finding_id": target,
        "alias_union": [candidate["candidate_key"]] if disposition == "MERGED_ALIAS" else [],
        "decision_provider_id": "inventory-adjudicator",
        "evidence_provider_id": "source-reviewer" if disposition == "SUPPORTED_REFUTATION" else "",
        "evidence_artifact": evidence_file,
        "evidence_sha256": _sha(root / evidence_file) if evidence_file else "",
        "evidence_record_id": evidence_record_id,
    }
    payload = {
        "schema_version": AUTHORITY_SCHEMA,
        "rows": [row],
    }
    (root / "inventory_disposition_authority.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def test_100_percent_retained_across_two_shards_and_ecosystems(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "EVM flow mismatch"), encoding="utf-8"
    )
    (tmp_path / "graph_sweep_move.md").write_text(
        _finding("DST-7", "Move state transition gap", loc="sources/module.move:L22"),
        encoding="utf-8",
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _manifest(tmp_path, "inventory_chunk_b", "graph_sweep_move.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "EVM flow mismatch", ("TF-1",))])
    _chunk(tmp_path, "inventory_chunk_b", [("CC-2", "Move state transition gap", ("DST-7",))])
    _inventory(
        tmp_path,
        [
            ("INV-001", "EVM flow mismatch", ("TF-1", "CC-1")),
            ("INV-002", "Move state transition gap", ("DST-7", "CC-2")),
        ],
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"] == {
        "AUTHORIZED_MERGE": 0,
        "AUTHORIZED_REFUTATION": 0,
        "HUMAN_REVIEW_DEBT": 0,
        "RETAINED": 2,
        "TOTAL": 2,
    }
    assert receipt["registry_debt_count"] == 0
    assert {
        row["registry_status"] for row in receipt["source_artifacts"]
    } == {"REGISTERED"}
    assert validate_inventory_reconciliation(tmp_path) == []
    assert V._validate_inventory_parity(tmp_path) == []


def test_inventory_reconciliation_has_registered_driver_only_phase_io(
    tmp_path: Path,
) -> None:
    _one_retained_candidate(tmp_path)
    receipt = write_inventory_reconciliation(tmp_path)
    inputs = D._inventory_reconciliation_input_paths(tmp_path, receipt)
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="inventory",
        work_unit_id="exact_reconciliation",
        exact_inputs=inputs,
    )
    assert contract.model_invoked is False
    assert set(contract.immutable_inputs) == {
        f"scratchpad:{path}" for path in inputs
    }
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:inventory_reconciliation.json",
        "scratchpad:inventory_reconciliation_human_review.md",
    }
    assert {item.writer for item in contract.outputs} == {"DRIVER"}


def test_inventory_reconciliation_phase_io_binds_and_resume_detects_source_drift(
    tmp_path: Path,
) -> None:
    run_id = "23456789-1234-4234-8234-123456789abc"
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    _one_retained_candidate(sp)
    assert V._validate_inventory_parity(sp) == []
    Checkpoint(run_id=run_id).save(sp)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "_run_id": run_id,
    }
    _activate_canonical_inventory(project, sp, config)
    assert V._validate_inventory_parity(sp) == []
    phase = next(item for item in SC_PHASES if item.name == "inventory")
    assert D._record_inventory_reconciliation_phase_io(
        scratchpad=sp,
        config=config,
        phase=phase,
    ) == []
    assert D._validate_inventory_reconciliation_phase_io(
        scratchpad=sp,
        project_root=project,
        phase_name="inventory",
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=phase.base_timeout_s,
    ) == []
    ledger = read_artifact_ledger(sp)
    unit = ledger["work_units"][
        "sc/thorough/evm/claude/inventory/exact_reconciliation"
    ]
    assert set(unit["artifacts"]) == {
        "scratchpad:inventory_reconciliation.json",
        "scratchpad:inventory_reconciliation_human_review.md",
    }
    assert "scratchpad:analysis_evm_flow.md" in unit["input_bindings"]
    with (sp / "analysis_evm_flow.md").open("ab") as handle:
        handle.write(b"\ncurrent source drift\n")
    issues = D._validate_inventory_reconciliation_phase_io(
        scratchpad=sp,
        project_root=project,
        phase_name="inventory",
        mode="thorough",
        language="evm",
        pipeline="sc",
        backend="claude",
        timeout_s=phase.base_timeout_s,
    )
    assert issues
    assert any("differ" in issue.lower() or "drift" in issue.lower() for issue in issues)


def test_unresolved_inventory_candidate_is_projected_as_recall_limitation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    sp = project / ".scratchpad"
    sp.mkdir(parents=True)
    (sp / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "Generic flow mismatch")
        + _finding("TF-2", "Generic sibling mismatch"),
        encoding="utf-8",
    )
    _manifest(sp, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(
        sp,
        "inventory_chunk_a",
        [("CC-1", "Generic flow mismatch", ("TF-1",))],
    )
    _inventory(
        sp,
        [("INV-001", "Generic flow mismatch", ("TF-1", "CC-1"))],
    )
    receipt = write_inventory_reconciliation(sp)
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    checkpoint = Checkpoint(
        run_id="3456789a-1234-4234-8234-123456789abc"
    )
    manifest = build_current_assurance_manifest(checkpoint, sp, project)
    rows = [
        row for row in manifest["rows"]
        if row["gate_id"] == "inventory_candidate_unresolved"
    ]
    assert len(rows) == 1
    assert rows[0]["assurance_impact"] == "DISCOVERY_RECALL"
    assert rows[0]["affected_identities"] == ["TF-2"]
    assert manifest["clean_full_audit_claim_allowed"] is False


@pytest.mark.parametrize("total,omitted", [(100, 1), (100, 54)])
def test_any_omitted_identity_is_debt_never_threshold_accepted(
    tmp_path: Path, total: int, omitted: int
) -> None:
    source = "".join(_finding(f"TF-{i}", f"candidate {i}") for i in range(1, total + 1))
    (tmp_path / "analysis_evm_flow.md").write_text(source, encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    kept = total - omitted
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [(f"CC-{i}", f"candidate {i}", (f"TF-{i}",)) for i in range(1, kept + 1)],
    )
    _inventory(
        tmp_path,
        [(f"INV-{i:03d}", f"candidate {i}", (f"TF-{i}", f"CC-{i}")) for i in range(1, kept + 1)],
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == omitted
    assert receipt["summary"]["RETAINED"] == kept
    limitations = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert f"### Finding [TF-{total}]" in limitations
    issues = V._validate_inventory_parity(tmp_path)
    assert any("NEEDS_INVENTORY_REVIEW" in issue for issue in issues)
    _apply_inventory_reemit_repair_for_tests(tmp_path)
    repaired = reconcile_inventory(tmp_path)
    assert repaired["summary"]["HUMAN_REVIEW_DEBT"] == 0
    reemit = json.loads(
        (tmp_path / "inventory_reemit_receipt.json").read_text(encoding="utf-8")
    )
    assert len(reemit["rows"]) == omitted


def test_many_to_one_merge_requires_and_preserves_full_alias_union(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_a.md").write_text(_finding("TF-1", "shared mechanism A"), encoding="utf-8")
    (tmp_path / "analysis_evm_b.md").write_text(_finding("RSW-2", "shared mechanism B"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_a.md", "analysis_evm_b.md")
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [("CC-1", "shared mechanism", ("TF-1", "RSW-2"))],
    )
    _inventory(tmp_path, [("INV-001", "shared mechanism", ("TF-1", "RSW-2", "CC-1"))])
    inventory_path = tmp_path / "findings_inventory.md"
    inventory_path.write_text(
        inventory_path.read_text(encoding="utf-8").replace(
            "**Root Cause**: mechanism for shared mechanism\n",
            "**Root Cause**: mechanism for shared mechanism A | "
            "mechanism for shared mechanism B\n",
        ).replace(
            "**Impact**: material effect for shared mechanism\n",
            "**Impact**: material effect for shared mechanism A | "
            "material effect for shared mechanism B\n",
        ),
        encoding="utf-8",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 2
    assert {row["target_inventory_id"] for row in receipt["candidates"]} == {""}
    assert all(
        row["reason_code"] == "MULTI_SOURCE_COLLAPSE_REQUIRES_EQUIVALENCE"
        for row in receipt["candidates"]
    )
    review = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert review.count("mechanism for shared mechanism A") == 1
    assert review.count("mechanism for shared mechanism B") == 1
    assert all(row["proposed_target_finding_id"] == "INV-001" for row in receipt["candidates"])
    assert all(row["proposed_target_block_sha256"] for row in receipt["candidates"])


def test_bare_summary_mention_does_not_count_as_retained_block(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(_finding("TF-1", "omitted body"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Inventory Chunk\n\n| Source ID | Disposition |\n|---|---|\n| TF-1 | retained |\n",
        encoding="utf-8",
    )
    _inventory(
        tmp_path,
        [],
        suffix="| Source ID | Disposition |\n|---|---|\n| TF-1 | retained |\n",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] == "MISSING_CHUNK_DISPOSITION"


def test_one_to_one_source_id_cannot_hide_semantic_drift(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "source mechanism", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "rewritten mechanism", ("TF-1", "CC-1"))])

    receipt = write_inventory_reconciliation(tmp_path)

    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "FINAL_SEMANTIC_PRESERVATION_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}
    assert row["proposed_target_finding_id"] == "INV-001"
    review = (tmp_path / "inventory_reconciliation_human_review.md").read_text(
        encoding="utf-8"
    )
    assert "mechanism for source mechanism" in review
    assert "material effect for source mechanism" in review


def test_chunk_source_id_cannot_hide_semantic_drift(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "source mechanism"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "rewritten mechanism", ("TF-1",))])

    receipt = write_inventory_reconciliation(
        tmp_path, phase_name="inventory_chunk_a"
    )

    row = receipt["candidates"][0]
    assert row["disposition"] == "HUMAN_REVIEW_DEBT"
    assert row["reason_code"] == "CHUNK_SEMANTIC_PRESERVATION_DEBT"
    assert set(row["required_preservation_axes"]) == {"ROOT_CAUSE", "IMPACT"}


def test_chunk_utf8_em_dash_is_not_equivalent_to_powershell_mojibake(
    tmp_path: Path,
) -> None:
    utf8_title = "allowance—boundary"
    mojibake_title = "allowanceâ€”boundary"
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", utf8_title), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [("CC-1", mojibake_title, ("TF-1",))],
    )

    rejected = reconcile_inventory(
        tmp_path, phase_name="inventory_chunk_a", persist=False
    )["candidates"][0]
    assert rejected["disposition"] == "HUMAN_REVIEW_DEBT"
    assert set(rejected["required_preservation_axes"]) == {
        "ROOT_CAUSE", "IMPACT",
    }

    _chunk(
        tmp_path,
        "inventory_chunk_a",
        [("CC-1", utf8_title, ("TF-1",))],
    )
    accepted = reconcile_inventory(
        tmp_path, phase_name="inventory_chunk_a", persist=False
    )["candidates"][0]
    assert accepted["disposition"] == "RETAINED"
    raw = (tmp_path / "findings_inventory_chunk_a.md").read_bytes()
    assert "—".encode("utf-8") in raw
    assert "â€”".encode("utf-8") not in raw


@pytest.mark.parametrize("evidence_scope", ["IN_SCOPE_SOURCE", "IN_SCOPE_EXECUTION"])
def test_source_bound_negative_evidence_is_supporting_only(
    tmp_path: Path,
    evidence_scope: str,
) -> None:
    (tmp_path / "graph_sweep_move.md").write_text(
        _finding("DST-7", "candidate to refute", loc="sources/m.move:L7"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "graph_sweep_move.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text("# no retained finding\n", encoding="utf-8")
    _inventory(tmp_path, [])

    preliminary = reconcile_inventory(tmp_path, persist=False)
    candidate = preliminary["candidates"][0]
    evidence = {
        "schema_version": NEGATIVE_EVIDENCE_SCHEMA,
        "provider_id": "source-reviewer",
        "records": [
            {
                "record_id": "NEG-1",
                "candidate_key": candidate["candidate_key"],
                "source_artifact": "graph_sweep_move.md",
                "source_sha256": _sha(tmp_path / "graph_sweep_move.md"),
                "source_finding_id": "DST-7",
                "source_block_sha256": candidate["source_block_sha256"],
                "verdict": "REFUTED",
                "evidence_scope": evidence_scope,
                "proof_scope": "HARM",
                "evidence_pointer": "sources/m.move:L7",
                "evidence_digest": hashlib.sha256(b"independent source trace").hexdigest(),
            }
        ],
    }
    (tmp_path / "inventory_negative_evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _authority(
        tmp_path,
        source="graph_sweep_move.md",
        source_id="DST-7",
        disposition="SUPPORTED_REFUTATION",
        evidence_file="inventory_negative_evidence.json",
        evidence_record_id="NEG-1",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["AUTHORIZED_REFUTATION"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] == "INVALID_REFUTATION_AUTHORITY"
    assert any(
        "NEEDS_INVENTORY_REVIEW" in issue
        for issue in V._validate_inventory_parity(tmp_path)
    )
    _apply_inventory_reemit_repair_for_tests(tmp_path)
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 0


def test_refutation_without_authority_stays_debt(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(_finding("TF-1", "unsafe negative"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text(
        "# Chunk\n\n| Source ID | Verdict |\n|---|---|\n| TF-1 | REFUTED |\n", encoding="utf-8"
    )
    _inventory(tmp_path, [])

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["disposition"] == "HUMAN_REVIEW_DEBT"


def test_structural_merge_label_requires_applied_equivalence_authority(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "authorized alias"), encoding="utf-8"
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_text("# no retained finding\n", encoding="utf-8")
    _inventory(tmp_path, [("INV-001", "canonical mechanism", ("OTHER-1",))])
    _authority(
        tmp_path,
        source="analysis_evm_flow.md",
        source_id="TF-1",
        disposition="MERGED_ALIAS",
        target="INV-001",
    )

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["AUTHORIZED_MERGE"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["target_inventory_id"] == ""
    assert receipt["candidates"][0]["reason_code"] == (
        "MERGE_REQUIRES_APPLIED_EQUIVALENCE_AUTHORITY"
    )
    assert any(
        "NEEDS_INVENTORY_REVIEW" in issue
        for issue in V._validate_inventory_parity(tmp_path)
    )
    _apply_inventory_reemit_repair_for_tests(tmp_path)
    assert reconcile_inventory(tmp_path)["summary"]["HUMAN_REVIEW_DEBT"] == 0


def test_malformed_chunk_preserves_raw_content_as_debt(tmp_path: Path) -> None:
    raw = _finding("TF-9", "raw content survives")
    (tmp_path / "analysis_evm_flow.md").write_text(raw, encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    (tmp_path / "findings_inventory_chunk_a.md").write_bytes(b"\xff\xfe\x00broken")
    _inventory(tmp_path, [])

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert "raw content survives" in (
        tmp_path / "inventory_reconciliation_human_review.md"
    ).read_text(encoding="utf-8")
    assert receipt["artifact_issues"]


def test_chunk_gate_reconciles_every_assigned_raw_identity_before_final_merge(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "retained") + _finding("TF-2", "omitted"),
        encoding="utf-8",
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "retained", ("TF-1",))])

    issues = V._validate_inventory_chunk_structure(
        tmp_path, "inventory_chunk_a"
    )

    assert any("exact reconciliation" in issue and "1/2" in issue for issue in issues)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(tmp_path),
        "_run_id": "34567891-1234-4234-8234-123456789abc",
    }
    _activate_chunk_model(tmp_path, tmp_path, config)
    assert D._record_inventory_reconciliation_phase_io_named(
        scratchpad=tmp_path,
        config=config,
        phase_name="inventory_chunk_a",
        timeout_s=30,
    ) == []
    receipt = json.loads(
        (tmp_path / "inventory_chunk_a.reconciliation.json").read_text(
            encoding="utf-8"
        )
    )
    assert receipt["summary"]["RETAINED"] == 1
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert "### Finding [TF-2]" in (
        tmp_path / "inventory_chunk_a.human_review.md"
    ).read_text(encoding="utf-8")


def test_stale_source_hash_invalidates_authority_toward_debt(tmp_path: Path) -> None:
    source = tmp_path / "analysis_evm_flow.md"
    source.write_text(_finding("TF-1", "first version"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", source.name)
    (tmp_path / "findings_inventory_chunk_a.md").write_text("# empty\n", encoding="utf-8")
    _inventory(tmp_path, [("INV-001", "merge target", ("OTHER-1",))])
    _authority(
        tmp_path,
        source=source.name,
        source_id="TF-1",
        disposition="MERGED_ALIAS",
        target="INV-001",
    )
    source.write_text(_finding("TF-1", "changed version"), encoding="utf-8")

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 1
    assert receipt["candidates"][0]["reason_code"] in {
        "STALE_DISPOSITION_AUTHORITY",
        "MISSING_CHUNK_DISPOSITION",
    }


def test_resume_is_byte_idempotent_and_tamper_is_recomputed(tmp_path: Path) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(_finding("TF-1", "stable"), encoding="utf-8")
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "stable", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "stable", ("TF-1", "CC-1"))])

    write_inventory_reconciliation(tmp_path)
    receipt_path = tmp_path / "inventory_reconciliation.json"
    debt_path = tmp_path / "inventory_reconciliation_human_review.md"
    first = (receipt_path.read_bytes(), debt_path.read_bytes())
    write_inventory_reconciliation(tmp_path)
    assert first == (receipt_path.read_bytes(), debt_path.read_bytes())

    payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    payload["summary"]["RETAINED"] = 999
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    assert validate_inventory_reconciliation(tmp_path)
    write_inventory_reconciliation(tmp_path)
    assert validate_inventory_reconciliation(tmp_path) == []


def test_shard_plan_hash_drift_invalidates_receipt_and_reopens_denominator(
    tmp_path: Path,
) -> None:
    (tmp_path / "analysis_evm_flow.md").write_text(
        _finding("TF-1", "first"), encoding="utf-8"
    )
    (tmp_path / "graph_sweep_move.md").write_text(
        _finding("DST-7", "late plan row", loc="sources/m.move:L9"),
        encoding="utf-8",
    )
    _manifest(tmp_path, "inventory_chunk_a", "analysis_evm_flow.md")
    _chunk(tmp_path, "inventory_chunk_a", [("CC-1", "first", ("TF-1",))])
    _inventory(tmp_path, [("INV-001", "first", ("TF-1", "CC-1"))])
    first = write_inventory_reconciliation(tmp_path)
    first_manifest_hash = first["manifest_artifacts"][0]["sha256"]

    _manifest(
        tmp_path,
        "inventory_chunk_a",
        "analysis_evm_flow.md",
        "graph_sweep_move.md",
    )

    assert validate_inventory_reconciliation(tmp_path)
    second = write_inventory_reconciliation(tmp_path)
    assert second["manifest_artifacts"][0]["sha256"] != first_manifest_hash
    assert second["summary"]["TOTAL"] == 2
    assert second["summary"]["HUMAN_REVIEW_DEBT"] == 1


def test_empty_audit_is_exact_clean_path(tmp_path: Path) -> None:
    _inventory(tmp_path, [])

    receipt = write_inventory_reconciliation(tmp_path)

    assert receipt["summary"]["TOTAL"] == 0
    assert receipt["summary"]["HUMAN_REVIEW_DEBT"] == 0
    assert V._validate_inventory_parity(tmp_path) == []
