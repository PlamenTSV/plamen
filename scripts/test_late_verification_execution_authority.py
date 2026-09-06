"""Independent evidence-chain authority for late verification candidates."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import plamen_driver as DRIVER
from artifact_ledger import read_artifact_ledger
from plamen_mechanical import _write_mechanical_report_index
from post_verify_candidate_delta import (
    load_post_verify_late_delivery_statuses,
    write_or_validate_post_verify_candidate_delta,
)
from queue_work_items import QueueWorkItem, queue_records_to_json
from recovery_execution_authority import (
    RecoveryExecutionAuthorityError,
    load_late_verification_authority,
    write_or_validate_late_verification_authority,
)
from test_verification_recovery_contract_p0_ai import (
    _emit_recovery_outputs,
    _semantic_row,
)


ROOT = Path(__file__).resolve().parent.parent
RUN_ID = "late-authority-run"
R10_PRESENT = (
    "external_assumption_undemotion_compute.json",
    "external_assumption_undemotion_debt.json",
)
R10_ABSENT = (
    "external_assumption_undemotions.json",
    "external_assumption_undemotions.md",
)


def _seed_delta(root: Path) -> str:
    base = QueueWorkItem.from_legacy_row({
        "finding id": "INV-1",
        "severity": "Medium",
        "title": "Base candidate",
        "bug class": "STATE_TRANSITION",
        "preferred tag": "CODE-TRACE",
        "location": "src/Base.sol:10",
        "primary artifact": "findings_inventory.md",
        "poc class": "structural",
    })
    (root / "verification_queue.work_items.json").write_text(
        queue_records_to_json((base,)) + "\n",
        encoding="utf-8",
    )
    (root / "post_verify_extract.md").write_text(
        "# Post Verify Extract\n\n"
        "### Finding [VER-1]: Late candidate\n"
        "**Severity**: Medium\n"
        "**Location**: src/Late.sol:20\n"
        "**Root Cause**: A late independent mechanism remains.\n"
        "**Impact**: A protected state transition may be violated.\n"
        "**Source Verify File**: verify_INV-1.md\n",
        encoding="utf-8",
    )
    (root / "verify_INV-1.md").write_text(
        "# Verification\n\n**Verdict**: CONFIRMED\n",
        encoding="utf-8",
    )
    delta = write_or_validate_post_verify_candidate_delta(
        root, run_id=RUN_ID, operator_proposals=()
    )
    return str(delta["rows"][0]["work_item"]["work_item_id"])


def test_late_authority_replays_compiler_launch_execution_and_operator_chain(
    tmp_path: Path,
    monkeypatch,
) -> None:
    project = tmp_path / "repo"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    candidate_id = _seed_delta(scratch)

    def execute(spec, *, prompt_path, scratchpad, **_kwargs):
        _emit_recovery_outputs(
            spec, prompt_path=prompt_path, scratchpad=scratchpad
        )
        return 0

    monkeypatch.setattr(DRIVER, "_execute_dynamic_verifier_launch", execute)
    config = {
        "scratchpad": str(scratch),
        "project_root": str(project),
        "pipeline": "sc",
        "language": "evm",
        "cli_backend": "claude",
        "mode": "core",
        "_run_id": RUN_ID,
        "_verification_recovery_kind": "POST_VERIFY_SIDE_OBSERVATION",
    }
    assert DRIVER._run_verify_recovery_shard(
        config,
        [(candidate_id, _semantic_row(candidate_id))],
    ) == []

    payload = write_or_validate_late_verification_authority(
        scratch, run_id=RUN_ID, repo_root=ROOT
    )

    assert payload["status"] == "CLEAN"
    assert payload["terminal_negative_authority"] is False
    assert payload["row_count"] == 1
    row = payload["rows"][0]
    assert row["candidate_id"] == candidate_id
    assert row["delivery_state"] == "INDEPENDENT_VERIFICATION_RECORDED"
    assert row["evidence_authority"] == (
        "COMPILER_BOUND_INDEPENDENT_VERIFICATION"
    )
    assert row["terminal_negative_authority"] is False
    assert row["contract_digest"]
    assert row["launch_spec_digest"]
    assert row["execution_receipt_digest"]
    assert row["operator_receipt_digest"]
    assert load_late_verification_authority(
        scratch, run_id=RUN_ID, repo_root=ROOT
    ) == payload
    status = load_post_verify_late_delivery_statuses(
        scratch, run_id=RUN_ID
    )[candidate_id]
    assert status.delivery_state == "INDEPENDENT_VERIFICATION_RECORDED"
    assert status.verifier_status == "CONTESTED"
    exact_inputs = set(
        DRIVER._report_candidate_input_paths(scratch, run_id=RUN_ID)
    )
    assert {
        "verification_queue.work_items.json",
        "post_verify_candidate_delta.json",
        "post_verify_extract.md",
        "post_verify_late_verification_authority.json",
        row["contract_artifact"],
        row["launch_spec_artifact"],
        row["execution_artifact"],
        row["verify_artifact"],
        row["severity_proposal_artifact"],
        row["operator_application_artifact"],
        row["operator_receipt_artifact"],
    }.issubset(exact_inputs)

    phase = SimpleNamespace(
        name="sc_verify_aggregate",
        base_timeout_s=30,
    )
    compute, r10_issues = DRIVER._write_and_record_r10_phase_io(
        scratchpad=scratch,
        config=config,
        phase=phase,
    )
    assert compute["mode"] == "core"
    assert compute["outcome"] == "CLEAN_ZERO"
    assert r10_issues
    assert any("authority" in issue.lower() for issue in r10_issues)
    assert all((scratch / name).is_file() for name in R10_PRESENT)
    assert not any((scratch / name).exists() for name in R10_ABSENT)

    original_r10_bytes = {
        name: (scratch / name).read_bytes() for name in R10_PRESENT
    }
    replayed, replay_issues = DRIVER._write_and_record_r10_phase_io(
        scratchpad=scratch,
        config=config,
        phase=phase,
    )
    assert replayed == compute
    assert replay_issues == []
    assert {
        name: (scratch / name).read_bytes() for name in R10_PRESENT
    } == original_r10_bytes

    ledger = read_artifact_ledger(scratch)
    producer_keys = {
        str(record.get("owner_key") or "")
        for identity, record in ledger["artifacts"].items()
        if identity in set(R10_PRESENT)
    }
    assert len(producer_keys) == 1
    producer_key = producer_keys.pop()
    assert producer_key.endswith(
        "/sc_verify_aggregate/"
        "external_assumption_undemotion_reconcile"
    )
    producer = ledger["work_units"][producer_key]
    assert producer["run_id"] == RUN_ID
    assert producer["semantic_status"] == "ACTIVE"
    assert producer["execution_state"] == "OUTPUT_COMMITTED"
    assert producer["commit_authority"]["attempt_ordinal"] == 1

    records = producer["artifacts"]
    compute_identity = "scratchpad:" + R10_PRESENT[0]
    debt_identity = "scratchpad:" + R10_PRESENT[1]
    assert records[compute_identity]["status"] == "ACTIVE"
    assert records[compute_identity]["writer"] == "DRIVER"
    assert records[debt_identity]["status"] == "ACTIVE"
    assert records[debt_identity]["writer"] == "DRIVER"
    assert records[debt_identity]["conditional_receipt"]["state"] == (
        "PRODUCED"
    )
    for name in R10_ABSENT:
        record = records["scratchpad:" + name]
        assert record["status"] == "MISSING"
        assert record["conditional_receipt"]["state"] == (
            "NOT_TRIGGERED"
        )

    prework, _launch = DRIVER._report_index_prework_contract_and_launch(
        scratch,
        config,
    )
    prework_inputs = {
        identity.split(":", 1)[1]
        for identity in prework.immutable_inputs
    }
    assert exact_inputs.issubset(prework_inputs)
    assert set(R10_PRESENT) <= prework_inputs
    assert not set(R10_ABSENT) & prework_inputs

    for config_delta in (
        {"_run_id": "foreign-run"},
        {"mode": "light"},
    ):
        with pytest.raises(ValueError):
            DRIVER._report_index_prework_contract_and_launch(
                scratch,
                {**config, **config_delta},
            )

    for name in R10_PRESENT:
        path = scratch / name
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        with pytest.raises(ValueError):
            DRIVER._report_index_prework_contract_and_launch(
                scratch,
                config,
            )
        path.write_bytes(original)

    compute_path = scratch / R10_PRESENT[0]
    original_compute = compute_path.read_bytes()
    tampered_compute = json.loads(original_compute.decode("utf-8"))
    tampered_compute["receipt_digest"] = "0" * 64
    compute_path.write_text(
        json.dumps(
            tampered_compute,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        DRIVER._report_index_prework_contract_and_launch(
            scratch,
            config,
        )
    compute_path.write_bytes(original_compute)

    debt_path = scratch / R10_PRESENT[1]
    original_debt = debt_path.read_bytes()
    debt_path.unlink()
    with pytest.raises(ValueError):
        DRIVER._report_index_prework_contract_and_launch(
            scratch,
            config,
        )
    debt_path.write_bytes(original_debt)

    replayed_prework, replayed_launch = (
        DRIVER._report_index_prework_contract_and_launch(
            scratch,
            config,
        )
    )
    assert replayed_prework == prework
    assert replayed_launch == _launch
    assert _write_mechanical_report_index(
        scratch, prepare_body=False
    ) == 2
    records = json.loads(
        (scratch / "report_records.json").read_text(encoding="utf-8")
    )
    late_record = next(
        record
        for record in records["active"]
        if record["finding_id"] == candidate_id
    )
    assert late_record["report_blocked"] is False
    assert late_record["verdict"] == "CONTESTED"


def test_late_authority_self_consistent_summary_forgery_is_rejected(
    tmp_path: Path,
) -> None:
    scratch = tmp_path
    _seed_delta(scratch)
    payload = write_or_validate_late_verification_authority(
        scratch, run_id=RUN_ID, repo_root=ROOT
    )
    assert payload["status"] == "COMPLETED_WITH_DEBT"
    path = scratch / "post_verify_late_verification_authority.json"
    forged = json.loads(path.read_text(encoding="utf-8"))
    forged["rows"][0]["delivery_state"] = (
        "INDEPENDENT_VERIFICATION_RECORDED"
    )
    unsigned = {
        key: value for key, value in forged.items()
        if key != "authority_digest"
    }
    from verification_method_compiler import stable_digest

    forged["authority_digest"] = stable_digest(unsigned)
    path.write_text(json.dumps(forged), encoding="utf-8")

    with pytest.raises(RecoveryExecutionAuthorityError):
        load_late_verification_authority(
            scratch, run_id=RUN_ID, repo_root=ROOT
        )
