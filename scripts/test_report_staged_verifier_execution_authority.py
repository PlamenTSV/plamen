"""Report staging preserves genuine verifier MODEL/control authority."""
from __future__ import annotations

from pathlib import Path
import json
import pytest

import plamen_driver as D
import plamen_validators as V
import test_report_index_canonical_phaseio_adversarial_red as report_fixture
import test_security_obligation_lifecycle_p1_c as lifecycle_fixture
from test_r10_demotion_gate import _strict_phaseio_split_parent_canonical_case


def _live_verifier(tmp_path: Path):
    config = report_fixture._config(
        tmp_path,
        pipeline="sc",
        backend="codex",
        run_id=lifecycle_fixture.RUN_ID,
    )
    root = Path(config["scratchpad"])
    item = lifecycle_fixture._item("INV-001", ("SEC-FIXTURE-001",))

    # This fixture launches a harmless local child through the current compat
    # transport and commits genuine MODEL plus DRIVER control authorities.
    lifecycle_fixture._write_runtime(root, [item], verdict="CONFIRMED")
    return config, root, item


@pytest.mark.parametrize("mechanical_successor", [False, True])
def test_declared_report_stage_replays_genuine_verifier_execution_authority(
    tmp_path: Path, monkeypatch, mechanical_successor: bool,
) -> None:
    """Copied canonical inputs must retain the live MODEL/control decision."""
    config, root, item = _live_verifier(tmp_path)
    if mechanical_successor:
        lifecycle_fixture._apply_successor(root, item.work_item_id)
    assert V._verifier_completion_authority_issues(
        root, item.work_item_id
    ) == []

    # R10 report prework is orthogonal to this exact verifier read-set test.
    # Keep MODEL/control replay and the production input enumeration intact.
    monkeypatch.setattr(D, "_r10_report_consumer_ready_issues", lambda *_a: [])
    contract, _launch = D._report_index_canonical_contract_and_launch(
        root, config
    )
    stage = tmp_path / "staged-verifier-execution-authority"
    report_fixture._copy_declared_scratchpad_inputs(root, stage, contract)
    # The production stage separately projects the validated mutable ledger;
    # it is deliberately not a self-referential canonical immutable input.
    D.read_artifact_ledger(root)
    (stage / "_artifact_state.json").write_bytes(
        (root / "_artifact_state.json").read_bytes()
    )

    # This historical fixture has no live T9 publication, so it cannot mint
    # the production-only authenticated historical stage scope. The direct
    # replay isolates whether the canonical contract declared every MODEL and
    # control input needed to preserve the already-valid completion decision.
    assert V._verifier_completion_authority_issues(
        stage, item.work_item_id
    ) == []


@pytest.mark.parametrize("record_field", [
    "attempt_completion_relative_path",
    "provider_completion_relative_path",
    "incorporation_relative_path",
])
@pytest.mark.parametrize("damage", ["missing", "tampered"])
def test_report_read_set_rejects_damaged_model_execution_record(
    tmp_path: Path, record_field: str, damage: str,
) -> None:
    _config, root, item = _live_verifier(tmp_path)
    assert V._verifier_completion_authority_issues(root, item.work_item_id) == []
    ledger = D.read_artifact_ledger(root)
    binding = ledger["artifact_bindings"][f"scratchpad:verify_{item.work_item_id}.md"]
    execution = ledger["work_units"][binding["owner_key"]]["execution_authority"]
    path = root / execution[record_field]
    if damage == "missing":
        path.rename(path.with_name(path.name + ".retained"))
    else:
        path.write_bytes(b"{}\n")

    with pytest.raises(ValueError):
        D._report_verifier_phaseio_graph_paths(root)


@pytest.mark.parametrize(
    "crash_point",
    ["before_canonical_commit", "after_publish:report_index.md"],
)
def test_genuine_verifier_execution_receipts_survive_canonical_retry(
    tmp_path: Path, monkeypatch, crash_point: str,
) -> None:
    """A report crash retains, and retry replays, the genuine MODEL chain."""

    validator, driver, root, config, phase, _severity = (
        _strict_phaseio_split_parent_canonical_case(tmp_path, monkeypatch, live_t9=True)
    )
    _model_receipt, model_issues = driver._record_report_index_model_preimage(
        phase, root, config
    )
    assert model_issues == []
    ledger = driver.read_artifact_ledger(root)
    binding = ledger["artifact_bindings"]["scratchpad:verify_H-22.md"]
    unit = ledger["work_units"][binding["owner_key"]]
    execution = unit["execution_authority"]
    fields = (
        "attempt_completion_relative_path",
        "provider_completion_relative_path",
        "incorporation_relative_path",
    )
    transaction_bytes = {
        execution[field]: (root / execution[field]).read_bytes()
        for field in fields
    }

    fired = False

    def crash_once(point: str) -> None:
        nonlocal fired
        if point == crash_point and not fired:
            fired = True
            raise RuntimeError(f"fixture canonical crash: {point}")

    with pytest.raises(RuntimeError, match="fixture canonical crash"):
        early_result = driver._run_report_index_canonicalization_transaction(
            phase, root, config, fault_inject=crash_once
        )
        pytest.fail(f"canonical transaction returned before injected fault: {early_result!r}")
    assert fired is True
    # The first published output precedes the live journal. Recovery at that
    # prefix is governed by the armed ledger and immutable source snapshots;
    # the journal is required only after the complete bundle is published.
    if crash_point == "before_canonical_commit":
        assert (root / driver._REPORT_INDEX_CANONICAL_JOURNAL).is_file()
    assert {
        relative: (root / relative).read_bytes()
        for relative in transaction_bytes
    } == transaction_bytes
    contract, _launch = driver._report_index_canonical_contract_and_launch(
        root, config
    )
    recovery = driver._report_index_canonical_recovery_dir(root, contract)
    assert (recovery / "source_manifest.json").is_file()
    crashed_unit = driver.read_artifact_ledger(root)["work_units"][contract.key]
    assert crashed_unit["execution_state"] != "OUTPUT_COMMITTED"

    # Canonical recovery must consume the committed verifier authority.  It
    # may not obtain a fresh MODEL result to replace receipts retained above.
    def forbidden_relaunch(*_args, **_kwargs):
        raise AssertionError("canonical retry relaunched the verifier")

    monkeypatch.setattr(
        driver, "_execute_dynamic_verifier_launch", forbidden_relaunch
    )
    assert driver._run_report_index_canonicalization_transaction(
        phase, root, config
    ) == []
    committed = driver.read_artifact_ledger(root)["work_units"][contract.key]
    assert committed["semantic_status"] == "ACTIVE"
    assert committed["execution_state"] == "OUTPUT_COMMITTED"
    assert {
        relative: (root / relative).read_bytes()
        for relative in transaction_bytes
    } == transaction_bytes
    assert validator._verifier_completion_authority_issues(root, "H-22") == []
    receipt = json.loads(
        (root / driver._REPORT_INDEX_CANONICAL_RECEIPT).read_text(
            encoding="utf-8", errors="strict"
        )
    )
    assert receipt["run_id"] == config["_run_id"]
