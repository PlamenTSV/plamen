"""P0-H live driver/PhaseIO/assurance cutover acceptance fixtures."""
from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    replace_uncommitted_driver_input_denominator,
    validate_work_unit_inputs,
)
from assurance_limitations import (
    assurance_projection_input_paths,
    build_current_assurance_manifest,
)
from phase_io_contracts import resolve_phase_io_contract
import plamen_driver as D
import plamen_parsers as P
import plamen_validators as V
from plamen_types import Checkpoint
from plamen_types import L1_PHASES, SC_PHASES
from severity_decision_ledger import project_report_severity
from test_trust_evidence_provider_p0_h import (
    FID,
    RUN_ID,
    _checkpoint,
    _synthetically_adjudicate,
    _trust_decision,
    _write_severity_state,
)
from trust_evidence_provider import (
    PROVIDER_RECEIPT_FILE,
    build_trust_evidence_provider_state,
    constrain_trust_sensitive_report_projection,
    ensure_trust_evidence_provider_state,
    write_trust_evidence_provider_state,
)
from trust_evidence_authority import (
    TrustEvidenceResolution,
    read_trust_review_debt,
    record_trust_review_debt,
)


def _config(root: Path) -> dict:
    return {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(root.parent),
        "scratchpad": str(root),
        "_run_id": RUN_ID,
    }


def test_trust_provider_phase_io_contract_is_driver_only_and_exact() -> None:
    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="severity_adjudication_shadow",
        work_unit_id="trust_evidence_reconcile",
        exact_inputs=(
            "severity_decision_ledger.shadow.json",
            "verify_INV-041.severity_decision.json",
        ),
    )

    assert contract.model_invoked is False
    assert {item.identity for item in contract.outputs} == {
        "scratchpad:trust_evidence_authority.json",
        "scratchpad:trust_evidence_provider_receipt.json",
    }
    assert {item.writer for item in contract.outputs} == {"DRIVER"}
    assert set(contract.immutable_inputs) == {
        "scratchpad:severity_decision_ledger.shadow.json",
        "scratchpad:verify_INV-041.severity_decision.json",
    }
    assert {
        item.minimum_gate for item in contract.outputs
    } == {"ZERO_NEGATIVE_AUTHORITY_EXACT_RECONCILIATION"}


def test_preverification_boundary_replaces_unowned_ledger_with_empty_authority(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    (tmp_path / "trust_evidence_authority.json").write_text(
        json.dumps({"records": [{"decision": "AUTHORIZED_TRUST_LIMITATION"}]}),
        encoding="utf-8",
    )

    issues = D._ensure_preverification_trust_boundary(tmp_path, run_id=RUN_ID)

    assert issues == []
    authority = json.loads(
        (tmp_path / "trust_evidence_authority.json").read_text(encoding="utf-8")
    )
    receipt = json.loads(
        (tmp_path / PROVIDER_RECEIPT_FILE).read_text(encoding="utf-8")
    )
    assert authority["records"] == []
    assert receipt["negative_authority"] == "NONE"
    assert "TRUST_SEVERITY_LEDGER_MISSING" in receipt["global_debts"]


def test_post_severity_cutover_records_exact_phase_io_and_resume_validation(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [])
    config = _config(tmp_path)

    debts = D._reconcile_trust_evidence_provider_state(tmp_path, config)

    assert debts == []
    assert D._trust_evidence_provider_resume_issues(tmp_path, config) == []
    ledger = json.loads((tmp_path / "_artifact_state.json").read_text())
    key = (
        "sc/thorough/evm/claude/severity_adjudication_shadow/"
        "trust_evidence_reconcile"
    )
    unit = ledger["work_units"][key]
    assert set(unit["artifacts"]) == {
        "scratchpad:trust_evidence_authority.json",
        "scratchpad:trust_evidence_provider_receipt.json",
    }
    assert all(row["status"] == "ACTIVE" for row in unit["artifacts"].values())

    receipt_path = tmp_path / PROVIDER_RECEIPT_FILE
    payload = json.loads(receipt_path.read_text())
    payload["negative_authority"] = "AUTHORIZED"
    receipt_path.write_text(json.dumps(payload), encoding="utf-8")
    assert D._trust_evidence_provider_resume_issues(tmp_path, config)


def test_trust_candidate_debt_is_report_visible_assurance(tmp_path: Path) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [_trust_decision()])
    config = _config(tmp_path)
    debts = D._reconcile_trust_evidence_provider_state(tmp_path, config)
    assert any("INV-041" in item for item in debts)

    checkpoint = Checkpoint(run_id=RUN_ID)
    manifest = build_current_assurance_manifest(
        checkpoint, tmp_path, tmp_path.parent
    )
    rows = [
        row for row in manifest["rows"]
        if row["gate_id"] == "trust_evidence_authority_unavailable"
    ]
    assert len(rows) == 1
    assert rows[0]["affected_identities"] == ["INV-041"]
    assert rows[0]["assurance_impact"] == "VERIFICATION_CONFIDENCE"


def test_completed_resume_establishes_trust_boundary_before_consumers(
    tmp_path: Path, monkeypatch
) -> None:
    """Exercise the factored startup sequence, not lexical source ordering."""

    _checkpoint(tmp_path)
    events: list[str] = []

    def late_consumer() -> None:
        assert (tmp_path / PROVIDER_RECEIPT_FILE).is_file()
        assert (tmp_path / "trust_evidence_authority.json").is_file()
        events.append("late-consumer")

    issues = D._run_startup_trust_boundary_before_consumers(
        tmp_path,
        run_id=RUN_ID,
        consumers=(late_consumer,),
    )

    assert issues == []
    assert events == ["late-consumer"]


def test_postseverity_boundary_precedes_gate_and_is_required_in_both_graphs() -> None:
    import ast
    import inspect
    import textwrap

    tree = ast.parse(textwrap.dedent(inspect.getsource(D.main)))
    calls = [
        (node.func.id, node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    by_name: dict[str, list[int]] = {}
    for name, line in calls:
        by_name.setdefault(name, []).append(line)
    startup = min(by_name["_run_startup_trust_boundary_before_consumers"])
    late = min(by_name["_repair_late_verification_backfill"])
    completed = min(by_name["_reconcile_completed_checkpoint_artifacts"])
    assert startup < late < completed

    adjudication = min(by_name["_run_severity_adjudication_shadow_phase"])
    trust = min(by_name["_reconcile_trust_evidence_provider_state"])
    gate = min(line for line in by_name["gate_passes"] if line > trust)
    commit = min(line for line in by_name["PhaseCommitController"] if line > trust)
    assert adjudication < trust < gate < commit
    for graph in (SC_PHASES, L1_PHASES):
        phase = next(
            item for item in graph
            if item.name == "severity_adjudication_shadow"
        )
        assert {
            "trust_evidence_authority.json",
            "trust_evidence_provider_receipt.json",
        }.issubset(set(phase.expected_artifacts))


def test_trust_modifier_cannot_project_a_lower_tier_without_provider_authority(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    decision = _synthetically_adjudicate(_trust_decision())
    _write_severity_state(tmp_path, [decision])
    write_trust_evidence_provider_state(tmp_path, run_id=RUN_ID)

    unconstrained = project_report_severity(decision)
    assert unconstrained["severity"] == "Medium"
    constrained = constrain_trust_sensitive_report_projection(
        tmp_path,
        decision=decision,
        projection=unconstrained,
        run_id=RUN_ID,
    )
    assert constrained["severity"] == "High"
    assert constrained["severity_status"] == "UNRESOLVED_TRUST_AUTHORITY"

    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "severity_authority_cutover": True,
                "severity_authority_run_id": RUN_ID,
                "severity_authority_source_receipts": {
                    FID: decision["source_receipt_digest"]
                },
            }
        ),
        encoding="utf-8",
    )
    assert V._typed_report_severity_adjustment_authorizes(
        tmp_path, [FID], final_severity="Medium"
    ) is False


def test_deleting_both_provider_files_after_severity_state_is_assurance_debt(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    _write_severity_state(tmp_path, [_trust_decision()])
    write_trust_evidence_provider_state(tmp_path, run_id=RUN_ID)
    (tmp_path / "trust_evidence_authority.json").unlink()
    (tmp_path / PROVIDER_RECEIPT_FILE).unlink()

    manifest = build_current_assurance_manifest(
        Checkpoint(run_id=RUN_ID), tmp_path, tmp_path.parent
    )
    rows = [
        row for row in manifest["rows"]
        if row["gate_id"] == "trust_evidence_provider_invalid"
    ]
    assert len(rows) == 1
    assert rows[0]["state"] == "COMPLETED_WITH_DEBT"


def test_consumer_trust_debt_is_strictly_replayed_into_assurance(
    tmp_path: Path,
) -> None:
    from test_trust_evidence_authority_p0_h import _row, _verify_text

    _checkpoint(tmp_path)
    source = tmp_path / f"verify_{FID}.md"
    source.write_text(_verify_text(), encoding="utf-8")
    text = source.read_text(encoding="utf-8")
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True

    debt_paths = sorted(tmp_path.glob(f"trust_evidence_debt_{FID}_*.json"))
    assert len(debt_paths) == 2
    inputs = set(assurance_projection_input_paths(tmp_path))
    assert {path.name for path in debt_paths}.issubset(inputs)
    manifest = build_current_assurance_manifest(
        Checkpoint(run_id=RUN_ID), tmp_path, tmp_path.parent
    )
    visible = [
        row for row in manifest["rows"]
        if row["gate_id"] == "trust_evidence_consumer_debt"
        and FID in row["affected_identities"]
    ]
    assert {row["work_unit_id"] for row in visible} == {
        f"{FID}:severity_modifier",
        f"{FID}:verification_exemption",
    }


def test_provider_write_failure_cannot_fall_back_to_a_legacy_authorized_ledger(
    tmp_path: Path, monkeypatch
) -> None:
    import trust_evidence_provider as provider
    from test_trust_evidence_authority_p0_h import _row, _verify_text, _write_authority

    source = _write_authority(tmp_path)
    text = source.read_text(encoding="utf-8")

    def fail_write(_path: Path, _payload: dict) -> None:
        raise OSError("synthetic provider write failure")

    monkeypatch.setattr(provider, "_atomic_json", fail_write)
    paths, issues = ensure_trust_evidence_provider_state(tmp_path)
    assert paths == ()
    assert issues
    assert not (tmp_path / PROVIDER_RECEIPT_FILE).exists()

    # Driver-owned consumers require the provider receipt; the otherwise valid
    # out-of-tree ledger cannot authorize a severity reduction or PoC exemption.
    assert P._enforce_severity_matrix(
        text, _row(), scratchpad=tmp_path, source_artifact=source
    ) == "Critical"
    assert V._poc_contract_required(_row(), "thorough", text, tmp_path) is True


def test_consumer_debt_is_current_run_and_closed_consumer_only(
    tmp_path: Path,
) -> None:
    _checkpoint(tmp_path)
    resolution = TrustEvidenceResolution(
        finding_id=FID,
        authorized=False,
        state="UNRESOLVED",
        debts=("TRUST_PROVIDER_REQUIRED",),
    )
    path = record_trust_review_debt(
        tmp_path,
        resolution=resolution,
        consumer="severity_modifier",
        retained_severity="High",
    )
    payload = read_trust_review_debt(path, expected_run_id=RUN_ID)
    assert payload["run_id"] == RUN_ID
    assert payload["consumer"] == "severity_modifier"

    stale_run = "87654321-4321-4321-8321-cba987654321"
    _checkpoint(tmp_path, run_id=stale_run)
    import pytest
    with pytest.raises(ValueError, match="run"):
        read_trust_review_debt(path, expected_run_id=stale_run)
    with pytest.raises(ValueError, match="consumer"):
        record_trust_review_debt(
            tmp_path,
            resolution=resolution,
            consumer="arbitrary_consumer",
        )


def test_postseverity_reconcile_binds_input_arriving_at_ensure_boundary(
    tmp_path: Path, monkeypatch
) -> None:
    _checkpoint(tmp_path)
    decision = _synthetically_adjudicate(_trust_decision())
    _write_severity_state(tmp_path, [decision])
    config = _config(tmp_path)
    original = D.build_trust_evidence_provider_state
    injected = False

    def inject_then_build(root: Path, *, run_id: str):
        nonlocal injected
        if not injected:
            injected = True
            (Path(root) / "severity_adjudication_late.json").write_text(
                json.dumps({"schema_version": "fixture.input.v1"}),
                encoding="utf-8",
            )
        return original(root, run_id=run_id)

    monkeypatch.setattr(
        D, "build_trust_evidence_provider_state", inject_then_build
    )
    D._reconcile_trust_evidence_provider_state(tmp_path, config)

    ledger = json.loads((tmp_path / "_artifact_state.json").read_text())
    key = (
        "sc/thorough/evm/claude/severity_adjudication_shadow/"
        "trust_evidence_reconcile"
    )
    inputs = set(ledger["work_units"][key]["input_bindings"])
    assert "scratchpad:severity_adjudication_late.json" in inputs
    assert D._trust_evidence_provider_resume_issues(tmp_path, config) == []


def test_postseverity_reconcile_recovers_input_arriving_after_first_input_record(
    tmp_path: Path, monkeypatch
) -> None:
    """A provisional dynamic contract must not poison the canonical unit."""

    _checkpoint(tmp_path)
    decision = _synthetically_adjudicate(_trust_decision())
    _write_severity_state(tmp_path, [decision])
    config = _config(tmp_path)
    original = D.record_work_unit_inputs
    calls = 0

    def record_then_inject(*args, **kwargs):
        nonlocal calls
        unit = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            (tmp_path / "severity_adjudication_after_record.json").write_text(
                json.dumps({"schema_version": "fixture.input.v1"}),
                encoding="utf-8",
            )
        return unit

    monkeypatch.setattr(D, "record_work_unit_inputs", record_then_inject)
    first = D._reconcile_trust_evidence_provider_state(tmp_path, config)
    assert not any(
        marker in issue
        for issue in first
        for marker in ("contract digest changed", "inputs did not stabilize")
    )

    key = (
        "sc/thorough/evm/claude/severity_adjudication_shadow/"
        "trust_evidence_reconcile"
    )
    unit = read_artifact_ledger(tmp_path)["work_units"][key]
    assert unit["semantic_status"] == "ACTIVE"
    assert set(unit["artifacts"]) == {
        "scratchpad:trust_evidence_authority.json",
        "scratchpad:trust_evidence_provider_receipt.json",
    }
    assert (
        "scratchpad:severity_adjudication_after_record.json"
        in unit["input_bindings"]
    )
    history = unit["input_rebind_history"]
    assert len(history) == 1
    assert history[0]["reason_code"] == (
        "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
    )

    monkeypatch.setattr(D, "record_work_unit_inputs", original)
    second = D._reconcile_trust_evidence_provider_state(tmp_path, config)
    assert not any("contract digest changed" in issue for issue in second)
    replay = read_artifact_ledger(tmp_path)["work_units"][key]
    assert replay["input_rebind_history"] == history
    assert D._trust_evidence_provider_resume_issues(tmp_path, config) == []


def _provisional_trust_unit(tmp_path: Path):
    _checkpoint(tmp_path)
    decision = _synthetically_adjudicate(_trust_decision())
    _write_severity_state(tmp_path, [decision])
    config = _config(tmp_path)
    ledger, receipt = build_trust_evidence_provider_state(
        tmp_path, run_id=RUN_ID
    )
    contract, launch = D._trust_provider_contract_and_launch(
        tmp_path, config, receipt
    )
    unit = record_work_unit_inputs(
        tmp_path, tmp_path.parent, contract, launch, run_id=RUN_ID
    )
    write_trust_evidence_provider_state(
        tmp_path, run_id=RUN_ID, planned_state=(ledger, receipt)
    )
    (tmp_path / "severity_adjudication_guard_late.json").write_text(
        json.dumps({"schema_version": "fixture.guard.v1"}),
        encoding="utf-8",
    )
    _next_ledger, next_receipt = build_trust_evidence_provider_state(
        tmp_path, run_id=RUN_ID
    )
    replacement, replacement_launch = D._trust_provider_contract_and_launch(
        tmp_path, config, next_receipt
    )
    return contract, launch, unit, replacement, replacement_launch


def test_postseverity_reconcile_recovers_crash_persisted_provisional_unit(
    tmp_path: Path,
) -> None:
    _contract, _launch, _unit, replacement, _replacement_launch = (
        _provisional_trust_unit(tmp_path)
    )
    config = _config(tmp_path)

    first = D._reconcile_trust_evidence_provider_state(tmp_path, config)
    assert not any(
        marker in issue
        for issue in first
        for marker in ("contract digest changed", "inputs did not stabilize")
    )

    unit = read_artifact_ledger(tmp_path)["work_units"][replacement.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert (
        "scratchpad:severity_adjudication_guard_late.json"
        in unit["input_bindings"]
    )
    history = unit["input_rebind_history"]
    assert len(history) == 1

    second = D._reconcile_trust_evidence_provider_state(tmp_path, config)
    assert not any("contract digest changed" in issue for issue in second)
    replay = read_artifact_ledger(tmp_path)["work_units"][replacement.key]
    assert replay["input_rebind_history"] == history
    assert D._trust_evidence_provider_resume_issues(tmp_path, config) == []


def test_postseverity_no_drift_crash_replay_uses_normal_idempotent_bind(
    tmp_path: Path, monkeypatch,
) -> None:
    contract, _launch, _unit, _replacement, _replacement_launch = (
        _provisional_trust_unit(tmp_path)
    )
    (tmp_path / "severity_adjudication_guard_late.json").unlink()

    def unexpected_recovery(*_args, **_kwargs):
        raise AssertionError("same-contract provisional replay used CAS recovery")

    monkeypatch.setattr(
        D,
        "recover_uncommitted_driver_input_denominator",
        unexpected_recovery,
    )
    config = _config(tmp_path)
    issues = D._reconcile_trust_evidence_provider_state(tmp_path, config)
    assert not any(
        marker in issue
        for issue in issues
        for marker in ("PhaseIO reconciliation failed", "contract digest changed")
    )

    unit = read_artifact_ledger(tmp_path)["work_units"][contract.key]
    assert unit["semantic_status"] == "ACTIVE"
    assert not unit.get("input_rebind_history")
    assert D._trust_evidence_provider_resume_issues(tmp_path, config) == []


def test_uncommitted_driver_input_rebind_rejects_wrong_cas_without_mutation(
    tmp_path: Path,
) -> None:
    contract, _launch, unit, replacement, replacement_launch = (
        _provisional_trust_unit(tmp_path)
    )
    before = (tmp_path / "_artifact_state.json").read_bytes()
    with pytest.raises(ArtifactLedgerError, match="compare-and-swap"):
        replace_uncommitted_driver_input_denominator(
            tmp_path,
            tmp_path.parent,
            contract,
            replacement,
            replacement_launch,
            run_id=RUN_ID,
            expected_prior_input_set_digest="0" * 64,
            reason_code=(
                "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
            ),
        )
    assert (tmp_path / "_artifact_state.json").read_bytes() == before
    assert unit["artifacts"] == {}


def test_uncommitted_driver_input_rebind_rejects_outputs_and_cross_run(
    tmp_path: Path,
) -> None:
    contract, launch, unit, replacement, replacement_launch = (
        _provisional_trust_unit(tmp_path)
    )
    with pytest.raises(ArtifactLedgerError, match="another run"):
        replace_uncommitted_driver_input_denominator(
            tmp_path,
            tmp_path.parent,
            contract,
            replacement,
            replacement_launch,
            run_id="another-run",
            expected_prior_input_set_digest=unit["input_set_digest"],
            reason_code=(
                "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
            ),
        )

    record_work_unit_artifacts(
        tmp_path,
        tmp_path.parent,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    before = (tmp_path / "_artifact_state.json").read_bytes()
    with pytest.raises(ArtifactLedgerError, match="recorded artifacts"):
        replace_uncommitted_driver_input_denominator(
            tmp_path,
            tmp_path.parent,
            contract,
            replacement,
            replacement_launch,
            run_id=RUN_ID,
            expected_prior_input_set_digest=unit["input_set_digest"],
            reason_code=(
                "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
            ),
        )
    assert (tmp_path / "_artifact_state.json").read_bytes() == before


def test_input_rebind_history_tamper_is_resume_visible(tmp_path: Path) -> None:
    contract, _launch, unit, replacement, replacement_launch = (
        _provisional_trust_unit(tmp_path)
    )
    replace_uncommitted_driver_input_denominator(
        tmp_path,
        tmp_path.parent,
        contract,
        replacement,
        replacement_launch,
        run_id=RUN_ID,
        expected_prior_input_set_digest=unit["input_set_digest"],
        reason_code="DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT",
    )
    path = tmp_path / "_artifact_state.json"
    ledger = json.loads(path.read_text(encoding="utf-8"))
    key = replacement.key
    ledger["work_units"][key]["input_rebind_history"][0][
        "reason_code"
    ] = "FORGED_REBIND"
    path.write_text(json.dumps(ledger), encoding="utf-8")

    issues = validate_work_unit_inputs(
        tmp_path,
        tmp_path.parent,
        replacement,
        replacement_launch,
        run_id=RUN_ID,
    )
    assert any("input rebind history" in issue for issue in issues)


def test_uncommitted_driver_input_rebind_rejects_non_driver_or_static_change(
    tmp_path: Path,
) -> None:
    cases = {
        "model_invoked": lambda contract: replace(
            contract, model_invoked=True
        ),
        "model_writer": lambda contract: replace(
            contract,
            outputs=(
                replace(
                    contract.outputs[0],
                    artifact_class="REQUIRED",
                    writer="MODEL",
                ),
                *contract.outputs[1:],
            ),
        ),
        "static_output": lambda contract: replace(
            contract,
            outputs=(
                replace(contract.outputs[0], minimum_gate="FORGED_GATE"),
                *contract.outputs[1:],
            ),
        ),
    }
    for name, mutate in cases.items():
        root = tmp_path / name
        root.mkdir()
        contract, _launch, unit, replacement, replacement_launch = (
            _provisional_trust_unit(root)
        )
        forged = mutate(replacement)
        before = (root / "_artifact_state.json").read_bytes()
        expected = (
            "deterministic DRIVER ownership"
            if name != "static_output"
            else "static contract manifest"
        )
        with pytest.raises(ArtifactLedgerError, match=expected):
            replace_uncommitted_driver_input_denominator(
                root,
                root.parent,
                contract,
                forged,
                replacement_launch,
                run_id=RUN_ID,
                expected_prior_input_set_digest=unit["input_set_digest"],
                reason_code=(
                    "DYNAMIC_INPUT_DENOMINATOR_DRIFT_BEFORE_OUTPUT_COMMIT"
                ),
            )
        assert (root / "_artifact_state.json").read_bytes() == before


def test_record_inputs_cannot_rebless_committed_driver_outputs(
    tmp_path: Path,
) -> None:
    contract, launch, _unit, _replacement, _replacement_launch = (
        _provisional_trust_unit(tmp_path)
    )
    (tmp_path / "severity_adjudication_guard_late.json").unlink()
    committed = record_work_unit_artifacts(
        tmp_path,
        tmp_path.parent,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    before = (tmp_path / "_artifact_state.json").read_bytes()
    same = record_work_unit_inputs(
        tmp_path,
        tmp_path.parent,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert same == committed
    assert (tmp_path / "_artifact_state.json").read_bytes() == before

    severity_ledger = tmp_path / "severity_decision_ledger.shadow.json"
    severity_ledger.write_text(
        severity_ledger.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ArtifactLedgerError, match="semantic invalidation"):
        record_work_unit_inputs(
            tmp_path,
            tmp_path.parent,
            contract,
            launch,
            run_id=RUN_ID,
        )
    assert (tmp_path / "_artifact_state.json").read_bytes() == before


def test_second_atomic_write_failure_is_fail_closed_with_legacy_ledger(
    tmp_path: Path, monkeypatch
) -> None:
    import trust_evidence_provider as provider
    from test_trust_evidence_authority_p0_h import (
        SCOPE,
        _write_authority,
    )
    from trust_evidence_authority import resolve_trust_evidence

    source = _write_authority(tmp_path)
    original = provider._atomic_json
    calls: list[str] = []

    def fail_second(path: Path, payload: dict) -> None:
        calls.append(path.name)
        if len(calls) == 2:
            raise OSError("synthetic ledger-write crash")
        original(path, payload)

    monkeypatch.setattr(provider, "_atomic_json", fail_second)
    paths, issues = provider.ensure_trust_evidence_provider_state(tmp_path)
    assert paths == () and issues
    assert calls == [
        "trust_evidence_provider_receipt.json",
        "trust_evidence_authority.json",
    ]
    resolution = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        require_provider=True,
        **SCOPE,
    )
    assert resolution.authorized is False
    assert "TRUST_LEDGER_TAMPERED" in resolution.debts


def test_default_resolver_requires_provider_and_legacy_opt_out_is_named(
    tmp_path: Path,
) -> None:
    from test_trust_evidence_authority_p0_h import SCOPE, _write_authority
    from trust_evidence_authority import (
        resolve_legacy_trust_evidence,
        resolve_trust_evidence,
    )

    source = _write_authority(tmp_path)
    default = resolve_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        **SCOPE,
    )
    legacy = resolve_legacy_trust_evidence(
        tmp_path,
        finding_id=FID,
        source_artifact=source,
        **SCOPE,
    )
    assert default.authorized is False
    assert default.debts == ("TRUST_PROVIDER_REQUIRED",)
    assert legacy.authorized is True


def test_live_shadow_report_projection_retains_trust_demoted_tier(
    tmp_path: Path,
) -> None:
    import severity_runtime
    from test_severity_adjudication_work_p0_ag3 import (
        RUN_ID as ADJUDICATION_RUN_ID,
        _execute_shard,
        _prepare,
    )

    _checkpoint(tmp_path, run_id=ADJUDICATION_RUN_ID)
    decision = _trust_decision(run_id=ADJUDICATION_RUN_ID)
    _write_severity_state(tmp_path, [decision])
    plan = _prepare(tmp_path)
    proposal = {
        "schema_version": "plamen.severity_adjudication_proposal.v1",
        "decision": "ACCEPT_PROPOSED",
        "resolved_severity": "Medium",
        "resolved_premise_ids": [f"PREM-L-{FID}"],
        "evidence_ids": [f"EVID-L-{FID}"],
        "proof_scope": "IN_SCOPE_SOURCE",
        "rationale": "Independent severity adjudication accepts the typed tier.",
        "resolved_axes": {"impact": "High", "likelihood": "Medium"},
        "constituent_resolutions": {},
    }
    worker_run = _execute_shard(
        tmp_path, plan, FID, proposals={FID: proposal}
    )
    shard = next(row for row in plan["shards"] if FID in row["candidate_ids"])
    intent = json.loads((tmp_path / shard["launch_intent_file"]).read_text())
    written, issues = severity_runtime.bind_shadow_adjudication_for_candidate(
        tmp_path,
        FID,
        backend=intent["backend"],
        launch_digest=worker_run["receipt_digest"],
        run_id=ADJUDICATION_RUN_ID,
        worker_identity=intent["worker_identity"],
        invocation_id=intent["invocation_id"],
    )
    assert written and not issues
    write_trust_evidence_provider_state(
        tmp_path, run_id=ADJUDICATION_RUN_ID
    )
    (tmp_path / "report_index.md").write_text(
        "## Master Finding Index\n\n"
        "| Report ID | Title | Severity | Trust Adjustment | Source Findings |\n"
        "|---|---|---|---|---|\n"
        f"| H-01 | Generic retained claim | High | None | {FID} |\n",
        encoding="utf-8",
    )
    (tmp_path / "report_critical_high.md").write_text(
        "## [H-01] Generic retained claim\n\n**Severity**: High\n",
        encoding="utf-8",
    )
    (tmp_path / "report_medium.md").write_text("", encoding="utf-8")
    (tmp_path / "report_low_info.md").write_text("", encoding="utf-8")

    receipt = severity_runtime.write_shadow_report_severity_receipt(
        tmp_path, run_id=ADJUDICATION_RUN_ID
    )
    row = next(item for item in receipt["rows"] if item["candidate_id"] == FID)
    assert row["authorized_severity"] == "High"
    assert row["severity_status"] == "UNRESOLVED_TRUST_AUTHORITY"
    assert receipt["unresolved_candidate_ids"] == [FID]
