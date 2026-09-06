"""Driver contracts for bounded BB reconciliation at report-index."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import bb_verification_policy as BB
import plamen_driver as D
from artifact_ledger import read_artifact_ledger
from test_bb_policy_terminal_driver_populated_red import (
    NORMATIVE_SENTINEL,
    _compile,
    _populated as _bb_populated,
)


_R10_PRESENT = (
    "external_assumption_undemotion_compute.json",
    "external_assumption_undemotion_debt.json",
)
_R10_ABSENT = (
    "external_assumption_undemotions.json",
    "external_assumption_undemotions.md",
)


def _populated(tmp_path: Path, monkeypatch):
    """Compose the BB fixture with the real mandatory R10 producer."""
    scratchpad, candidate, unit, config, recovery = _bb_populated(
        tmp_path, monkeypatch
    )
    for name, payload in {
        "finding_mapping.md": "# Finding Mapping\n",
        "dedup_decisions.md": "# Dedup Decisions\n",
    }.items():
        path = scratchpad / name
        if not path.exists():
            path.write_text(payload, encoding="utf-8")
    phase = SimpleNamespace(
        name="sc_verify_aggregate",
        base_timeout_s=30,
    )
    compute, issues = D._write_and_record_r10_phase_io(
        scratchpad=scratchpad,
        config=config,
        phase=phase,
    )
    assert compute["outcome"] == "CLEAN_ZERO"
    assert issues
    assert any("authority" in issue.lower() for issue in issues)
    assert all((scratchpad / name).is_file() for name in _R10_PRESENT)
    assert not any((scratchpad / name).exists() for name in _R10_ABSENT)

    ledger = read_artifact_ledger(scratchpad)
    producer_keys = {
        str(record.get("owner_key") or "")
        for identity, record in ledger["artifacts"].items()
        if identity in set(_R10_PRESENT)
    }
    assert len(producer_keys) == 1
    producer_key = producer_keys.pop()
    assert producer_key.endswith(
        "/sc_verify_aggregate/external_assumption_undemotion_reconcile"
    )
    producer = ledger["work_units"][producer_key]
    assert producer["run_id"] == config["_run_id"]
    assert producer["execution_state"] == "OUTPUT_COMMITTED"
    assert producer["semantic_status"] == "ACTIVE"
    return scratchpad, candidate, unit, config, recovery


def _publish_report_projection(
    scratchpad: Path,
    config: dict,
    terminal: dict,
) -> dict:
    projection = BB.build_downstream_reconciliation_projection(
        terminal,
        consumer_kind="REPORT",
    )
    D._commit_bb_policy_driver_projection(
        scratchpad=scratchpad,
        config=config,
        work_unit_id="downstream.report",
        exact_inputs=(BB.TERMINAL_RECONCILIATION_PATH,),
        target=scratchpad / BB.REPORT_RECONCILIATION_PATH,
        payload=projection,
    )
    return projection


def test_report_consumer_binds_only_exact_bounded_projection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    terminal = _compile(scratchpad, config)
    projection = _publish_report_projection(
        scratchpad, config, terminal
    )

    assert D._prepare_bb_policy_report_consumer(
        scratchpad, config
    ) == []
    assert config["_bb_policy_report_projection_ready"] is True
    assert config["_bb_policy_report_projection_sha256"] == projection[
        "projection_sha256"
    ]
    contract, _launch = D._report_index_prework_contract_and_launch(
        scratchpad, config
    )
    exact_report_inputs = {
        "scratchpad:" + BB.REPORT_RECONCILIATION_PATH,
        *(f"scratchpad:{name}" for name in _R10_PRESENT),
    }
    assert exact_report_inputs <= set(contract.immutable_inputs)
    assert not {
        f"scratchpad:{name}" for name in _R10_ABSENT
    } & set(contract.immutable_inputs)

    execute, issues = D._arm_report_index_prework_artifacts(
        scratchpad, config
    )
    assert execute is True, issues
    assert issues == []
    ledger = read_artifact_ledger(scratchpad)
    prework = ledger["work_units"][contract.key]
    absence = prework["explicit_absence_authority"]
    assert absence["roster_identities"] == sorted(
        f"scratchpad:{name}" for name in D._R10_REPORT_PREWORK_ROSTER
    )
    assert absence["absent_identities"] == sorted(
        f"scratchpad:{name}" for name in _R10_ABSENT
    )
    assert D._r10_report_prework_authority_issues(
        scratchpad,
        config,
        contract=contract,
        launch=_launch,
    ) == []

    suffix = D._bb_policy_report_prompt_suffix(
        scratchpad, config
    )
    assert BB.REPORT_RECONCILIATION_PATH in suffix
    assert projection["projection_sha256"] in suffix
    assert "RETAIN_REQUEUE_REVIEW" in suffix
    assert NORMATIVE_SENTINEL not in suffix
    assert "operator_projection" not in suffix


def test_report_consumer_rejects_projection_drift_without_exposing_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    terminal = _compile(scratchpad, config)
    _publish_report_projection(scratchpad, config, terminal)
    path = scratchpad / BB.REPORT_RECONCILIATION_PATH
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["normative_text"] = NORMATIVE_SENTINEL
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    issues = D._prepare_bb_policy_report_consumer(
        scratchpad, config
    )
    assert issues
    assert "_bb_policy_report_projection_ready" not in config
    assert D._bb_policy_report_prompt_suffix(
        scratchpad, config
    ) == ""


def test_non_bb_report_consumer_is_exact_noop(tmp_path: Path) -> None:
    config = {"pipeline": "sc", "mode": "thorough"}
    before = dict(config)
    assert D._prepare_bb_policy_report_consumer(
        tmp_path, config
    ) == []
    assert config == before
    assert D._bb_policy_report_prompt_suffix(tmp_path, config) == ""


def test_report_model_phaseio_accepts_projection_as_exact_input() -> None:
    dimensions = {
        "pipeline": "sc",
        "mode": "thorough",
        "ecosystem": "evm",
        "backend": "claude",
    }
    static = D.resolve_phase_io_contract(
        **dimensions,
        phase="report_index",
        work_unit_id="model",
    )
    exact = tuple(
        identity.split(":", 1)[1]
        for identity in static.immutable_inputs
    ) + (BB.REPORT_RECONCILIATION_PATH,)
    model = D.resolve_phase_io_contract(
        **dimensions,
        phase="report_index",
        work_unit_id="model",
        exact_inputs=exact,
    )
    assert (
        "scratchpad:" + BB.REPORT_RECONCILIATION_PATH
        in model.immutable_inputs
    )

    producer = D.resolve_phase_io_contract(
        **dimensions,
        phase="bb_policy",
        work_unit_id="downstream.report",
        exact_inputs=(BB.TERMINAL_RECONCILIATION_PATH,),
        exact_outputs=(BB.REPORT_RECONCILIATION_PATH,),
    )
    assert producer.outputs[0].consumers == ("report_index/model",)
