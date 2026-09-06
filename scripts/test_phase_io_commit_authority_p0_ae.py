"""P0-AE commit authority: output bytes never certify their own inputs.

These fixtures exercise the shared ledger boundary directly.  They deliberately
do not depend on driver call ordering: every caller must get the same
recall-safe, proposal-only quarantine when pre-execution authority is absent or
stale.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import artifact_ledger as AL
from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
)
from phase_io_contracts import (
    ArtifactSpec,
    ConditionalOutputReceipt,
    LaunchSpec,
    PhaseIOContract,
)


def _contract(
    unit: str,
    *,
    output: str = "result.md",
    inputs: tuple[str, ...] = (),
    model: bool = True,
    write_mode: str = "REPLACE",
    artifact_class: str = "REQUIRED",
    schema_version: str = "unstructured.v1",
    consumers: tuple[str, ...] = (),
    condition_id: str = "",
) -> PhaseIOContract:
    key = f"sc/thorough/evm/claude/depth/{unit}"
    return PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id=unit,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=output,
                owner_key=key,
                artifact_class=artifact_class,
                writer="MODEL" if model else "DRIVER",
                write_mode=write_mode,
                schema_version=schema_version,
                consumers=consumers,
                condition_id=condition_id,
            ),
        ),
        immutable_inputs=inputs,
        model_invoked=model,
    )


def _launch(contract: PhaseIOContract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="sonnet" if contract.model_invoked else "driver",
        timeout_s=30,
        exec_mode="pty" if contract.model_invoked else "python",
    )


def _write_ledger(sp: Path, payload: dict) -> None:
    (sp / "_artifact_state.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _commit(
    sp: Path,
    project: Path,
    contract: PhaseIOContract,
    *,
    run_id: str = "run-commit",
    **kwargs,
) -> dict:
    if (
        not contract.model_invoked
        and contract.key not in read_artifact_ledger(sp)["work_units"]
    ):
        staged: dict[Path, bytes] = {}
        for spec in contract.outputs:
            path = sp / spec.path if spec.root == "scratchpad" else project / spec.path
            if path.is_file():
                staged[path] = path.read_bytes()
                path.unlink()
        record_work_unit_inputs(
            sp,
            project,
            contract,
            _launch(contract),
            run_id=run_id,
        )
        for path, payload in staged.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
    return record_work_unit_artifacts(
        sp,
        project,
        contract,
        _launch(contract),
        run_id=run_id,
        actor="MODEL" if contract.model_invoked else "DRIVER",
        **kwargs,
    )


def _assert_quarantined_everywhere(
    sp: Path, contract: PhaseIOContract, identity: str
) -> dict:
    ledger = read_artifact_ledger(sp)
    unit = ledger["work_units"][contract.key]
    assert unit["semantic_status"] == "QUARANTINED"
    assert unit["artifacts"][identity]["status"] == "QUARANTINED"
    assert unit["artifacts"][identity]["authority_level"] == "PROPOSAL_ONLY"
    assert ledger["artifact_bindings"][identity]["status"] == "QUARANTINED"
    assert ledger["artifact_bindings"][identity]["authority_level"] == "PROPOSAL_ONLY"
    assert ledger["artifacts"][identity.split(":", 1)[1]]["status"] == "QUARANTINED"
    return unit


def test_nonempty_denominator_without_preexecution_receipt_cannot_be_active(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("input\n", encoding="utf-8")
    (sp / "result.md").write_text("finding-bearing output\n", encoding="utf-8")
    contract = _contract("worker.no_receipt", inputs=("scratchpad:input.md",))

    unit = _commit(sp, tmp_path, contract)

    unit = _assert_quarantined_everywhere(
        sp, contract, "scratchpad:result.md"
    )
    assert "MISSING_PREEXECUTION_INPUT_RECEIPT" in unit["commit_authority"]["reason_codes"]
    assert (sp / "result.md").read_text(encoding="utf-8") == "finding-bearing output\n"


def test_separate_model_retry_unit_can_repair_uncommitted_prior_bytes(
    tmp_path: Path,
):
    """A retry binds prior bytes as prestate, never as accepted authority."""

    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("stable input\n", encoding="utf-8")
    first = _contract(
        "worker.depth-edge-case",
        inputs=("scratchpad:input.md",),
    )
    second = _contract(
        "worker.depth-edge-case.attempt-0002",
        inputs=("scratchpad:input.md",),
    )
    record_work_unit_inputs(
        sp, tmp_path, first, _launch(first), run_id="run-commit"
    )
    (sp / "result.md").write_text(
        "incomplete candidate-bearing attempt\n", encoding="utf-8"
    )

    bound = record_work_unit_inputs(
        sp, tmp_path, second, _launch(second), run_id="run-commit"
    )
    prestate = bound["output_prestates"]["scratchpad:result.md"]
    assert prestate["status"] == "AUTHORIZED_MODEL_RETRY_PRESTATE"
    assert prestate["predecessor_owner_key"] == first.key
    # The prior attempt still has no accepted artifact authority.
    ledger = read_artifact_ledger(sp)
    assert ledger["work_units"][first.key]["artifacts"] == {}
    assert "scratchpad:result.md" not in ledger["artifact_bindings"]

    (sp / "result.md").write_text(
        "repaired candidate-bearing output\n", encoding="utf-8"
    )
    unit = _commit(sp, tmp_path, second)
    assert unit["semantic_status"] == "ACTIVE"
    assert (
        read_artifact_ledger(sp)["artifact_bindings"]["scratchpad:result.md"][
            "owner_key"
        ]
        == second.key
    )


def test_model_retry_prestate_rejects_nonadjacent_or_drifted_authority(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("stable input\n", encoding="utf-8")
    first = _contract(
        "worker.depth-edge-case",
        inputs=("scratchpad:input.md",),
    )
    record_work_unit_inputs(
        sp, tmp_path, first, _launch(first), run_id="run-commit"
    )
    (sp / "result.md").write_text("untrusted retry bytes\n", encoding="utf-8")

    skipped = _contract(
        "worker.depth-edge-case.attempt-0003",
        inputs=("scratchpad:input.md",),
    )
    skipped_bound = record_work_unit_inputs(
        sp, tmp_path, skipped, _launch(skipped), run_id="run-commit"
    )
    assert (
        skipped_bound["output_prestates"]["scratchpad:result.md"]["status"]
        == "UNOWNED_EXISTING_OUTPUT"
    )

    # Even the adjacent retry cannot borrow authority after semantic input
    # drift; its prestate stays untrusted and its output cannot commit cleanly.
    (sp / "input.md").write_text("drifted input\n", encoding="utf-8")
    adjacent = _contract(
        "worker.depth-edge-case.attempt-0002",
        inputs=("scratchpad:input.md",),
    )
    adjacent_bound = record_work_unit_inputs(
        sp, tmp_path, adjacent, _launch(adjacent), run_id="run-commit"
    )
    assert (
        adjacent_bound["output_prestates"]["scratchpad:result.md"]["status"]
        == "UNOWNED_EXISTING_OUTPUT"
    )


@pytest.mark.parametrize("corruption", ("input_debt", "malformed_receipt"))
def test_input_debt_or_malformed_receipt_quarantines_at_commit(
    tmp_path: Path, corruption: str,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    if corruption == "input_debt":
        # Missing at binding remains debt even if the file appears before output.
        contract = _contract("worker.input_debt", inputs=("scratchpad:input.md",))
        launch = _launch(contract)
        record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-commit")
        (sp / "input.md").write_text("late\n", encoding="utf-8")
    else:
        (sp / "input.md").write_text("stable\n", encoding="utf-8")
        contract = _contract("worker.malformed", inputs=("scratchpad:input.md",))
        launch = _launch(contract)
        record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-commit")
        ledger = read_artifact_ledger(sp)
        ledger["work_units"][contract.key]["input_set_digest"] = "0" * 64
        _write_ledger(sp, ledger)
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")

    _commit(sp, tmp_path, contract)

    unit = _assert_quarantined_everywhere(sp, contract, "scratchpad:result.md")
    assert unit["commit_authority"]["reason_codes"]


def test_caller_precommit_issues_are_not_ignored(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("stable\n", encoding="utf-8")
    contract = _contract("worker.domain_debt", inputs=("scratchpad:input.md",))
    record_work_unit_inputs(
        sp, tmp_path, contract, _launch(contract), run_id="run-commit"
    )
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")

    _commit(
        sp,
        tmp_path,
        contract,
        precommit_issues=("DOMAIN_VALIDATION: malformed model receipt",),
    )

    unit = _assert_quarantined_everywhere(sp, contract, "scratchpad:result.md")
    assert unit["commit_authority"]["precommit_issues"] == [
        "DOMAIN_VALIDATION: malformed model receipt"
    ]


def test_live_input_drift_and_producer_authority_drift_quarantine(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("before\n", encoding="utf-8")
    contract = _contract("worker.live_drift", inputs=("scratchpad:input.md",))
    record_work_unit_inputs(
        sp, tmp_path, contract, _launch(contract), run_id="run-commit"
    )
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")
    (sp / "input.md").write_text("after\n", encoding="utf-8")

    _commit(sp, tmp_path, contract)

    unit = _assert_quarantined_everywhere(sp, contract, "scratchpad:result.md")
    assert "INPUT_CONTENT_HASH_CHANGED" in unit["commit_authority"]["reason_codes"]

    # A downstream binding sees proposal-only bytes, never transitive authority.
    downstream = _contract(
        "worker.downstream",
        output="downstream.md",
        inputs=("scratchpad:result.md",),
    )
    bound = record_work_unit_inputs(
        sp, tmp_path, downstream, _launch(downstream), run_id="run-commit"
    )
    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["input_bindings"]["scratchpad:result.md"]["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ("run", "RUN_ID_MISMATCH"),
        ("contract", "CONTRACT_DIGEST_MISMATCH"),
        ("manifest", "CONTRACT_MANIFEST_MISMATCH"),
        ("launch", "LAUNCH_DIGEST_MISMATCH"),
        ("denominator", "INPUT_DENOMINATOR_MISMATCH"),
        ("rebind", "INPUT_REBIND_HISTORY_INVALID"),
    ),
)
def test_commit_cas_metadata_debt_is_quarantined_not_reblessed(
    tmp_path: Path, mutation: str, reason: str,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("stable\n", encoding="utf-8")
    contract = _contract(f"worker.cas_{mutation}", inputs=("scratchpad:input.md",))
    launch = _launch(contract)
    record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-commit")
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")
    ledger = read_artifact_ledger(sp)
    unit = ledger["work_units"][contract.key]
    if mutation == "run":
        unit["run_id"] = "foreign-run"
    elif mutation == "contract":
        unit["contract_digest"] = "f" * 64
    elif mutation == "manifest":
        unit["contract_manifest"]["mode"] = "light"
    elif mutation == "launch":
        unit["launch_digest"] = "e" * 64
    elif mutation == "denominator":
        unit["input_bindings"].pop("scratchpad:input.md")
    else:
        unit["input_rebind_history"] = [{}]
    _write_ledger(sp, ledger)

    committed = _commit(sp, tmp_path, contract)

    assert committed["semantic_status"] == "QUARANTINED"
    assert reason in committed["commit_authority"]["reason_codes"]


def test_producer_unit_drift_is_rechecked_even_when_global_bytes_match(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "producer.md").write_text("stable producer\n", encoding="utf-8")
    producer = _contract("worker.source", output="producer.md", model=False)
    _commit(sp, tmp_path, producer)
    consumer = _contract(
        "worker.producer_drift",
        inputs=("scratchpad:producer.md",),
    )
    launch = _launch(consumer)
    record_work_unit_inputs(sp, tmp_path, consumer, launch, run_id="run-commit")
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")
    ledger = read_artifact_ledger(sp)
    ledger["work_units"][producer.key]["semantic_status"] = "QUARANTINED"
    _write_ledger(sp, ledger)

    committed = _commit(sp, tmp_path, consumer)

    assert committed["semantic_status"] == "QUARANTINED"
    assert "INPUT_PRODUCER_UNIT_NOT_ACTIVE" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_output_validation_requires_clean_commit_and_exact_global_binding(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("stable\n", encoding="utf-8")
    contract = _contract("worker.clean", inputs=("scratchpad:input.md",))
    launch = _launch(contract)
    record_work_unit_inputs(sp, tmp_path, contract, launch, run_id="run-commit")
    (sp / "result.md").write_text("output\n", encoding="utf-8")
    _commit(sp, tmp_path, contract)
    assert validate_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-commit"
    ) == []

    ledger = read_artifact_ledger(sp)
    ledger["artifact_bindings"]["scratchpad:result.md"]["owner_key"] = (
        "sc/thorough/evm/claude/depth/foreign"
    )
    _write_ledger(sp, ledger)
    issues = validate_work_unit_artifacts(
        sp, tmp_path, contract, launch, run_id="run-commit"
    )
    assert any("global artifact binding" in issue for issue in issues)


def test_exact_zero_input_contract_gets_explicit_compatible_receipt(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "result.md").write_text("deterministic\n", encoding="utf-8")
    contract = _contract("worker.zero", model=False)

    unit = _commit(sp, tmp_path, contract)

    assert unit["semantic_status"] == "ACTIVE"
    assert unit["input_bindings"] == {}
    assert unit["input_receipt_kind"] == "EXPLICIT_ZERO_INPUT"
    assert unit["execution_state"] == "OUTPUT_COMMITTED"
    assert unit["commit_authority"]["state"] == "ACTIVE"


def test_legacy_exact_zero_input_row_requires_audited_migration_authority(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "result.md").write_text("legacy deterministic\n", encoding="utf-8")
    contract = _contract("worker.legacy_zero", model=False)
    _commit(sp, tmp_path, contract)
    ledger = read_artifact_ledger(sp)
    unit = ledger["work_units"][contract.key]
    unit.pop("commit_authority")
    unit.pop("execution_state")
    unit.pop("input_receipt_kind")
    unit["input_set_digest"] = ""
    for table in ("artifact_bindings", "artifacts"):
        for row in ledger[table].values():
            if isinstance(row, dict):
                row.pop("authority_level", None)
    _write_ledger(sp, ledger)

    migrated = _commit(sp, tmp_path, contract)

    assert migrated["semantic_status"] == "QUARANTINED"
    assert "PREEXECUTION_STATE_INVALID" in (
        migrated["commit_authority"]["reason_codes"]
    )


def test_output_attempt_is_durable_and_cannot_retro_bind_or_reactivate(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("input\n", encoding="utf-8")
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")
    contract = _contract("worker.retro", inputs=("scratchpad:input.md",))
    launch = _launch(contract)
    first = _commit(sp, tmp_path, contract)
    assert first["execution_state"] == "OUTPUT_QUARANTINED"

    with pytest.raises(ArtifactLedgerError, match="output|execution|committed"):
        record_work_unit_inputs(
            sp, tmp_path, contract, launch, run_id="run-commit"
        )
    second = _commit(sp, tmp_path, contract)
    assert second["semantic_status"] == "QUARANTINED"
    assert second["commit_authority"]["attempt_ordinal"] == 2


def test_preexisting_model_output_cannot_receive_a_late_first_input_receipt(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "input.md").write_text("input\n", encoding="utf-8")
    (sp / "result.md").write_text("already executed\n", encoding="utf-8")
    contract = _contract("worker.late_first_bind", inputs=("scratchpad:input.md",))

    bound = record_work_unit_inputs(
        sp, tmp_path, contract, _launch(contract), run_id="run-commit"
    )
    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["output_prestates"]["scratchpad:result.md"]["status"] == (
        "UNOWNED_EXISTING_OUTPUT"
    )

    committed = _commit(sp, tmp_path, contract)
    assert committed["semantic_status"] == "QUARANTINED"
    assert "OUTPUT_PRESTATE_INVALID" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_same_path_owner_conflict_is_quarantined_and_visible_to_prior_owner(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "shared.md").write_text("same bytes\n", encoding="utf-8")
    first = _contract("worker.first", output="shared.md", model=False)
    second = _contract("worker.second", output="shared.md", model=False)
    _commit(sp, tmp_path, first)
    _commit(sp, tmp_path, second)

    _assert_quarantined_everywhere(sp, second, "scratchpad:shared.md")
    prior_issues = validate_work_unit_artifacts(
        sp, tmp_path, first, _launch(first), run_id="run-commit"
    )
    assert any("global artifact binding" in issue for issue in prior_issues)


def test_explicit_quarantine_preserves_bytes_as_proposal_only(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    output = sp / "result.md"
    output.write_text("## Candidate C-1\nmaterial detail\n", encoding="utf-8")
    contract = _contract("worker.explicit_quarantine", model=False)

    _commit(sp, tmp_path, contract, status="QUARANTINED")

    _assert_quarantined_everywhere(sp, contract, "scratchpad:result.md")
    assert output.read_text(encoding="utf-8").startswith("## Candidate C-1")


def test_superseded_is_separate_terminal_state_and_idempotent(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "result.md").write_text("retained history\n", encoding="utf-8")
    contract = _contract("worker.retire", model=False)
    _commit(sp, tmp_path, contract)

    first = _commit(sp, tmp_path, contract, status="SUPERSEDED")
    second = _commit(sp, tmp_path, contract, status="SUPERSEDED")

    assert first["semantic_status"] == "SUPERSEDED"
    assert second["semantic_status"] == "SUPERSEDED"
    assert second["artifacts"]["scratchpad:result.md"]["status"] == "SUPERSEDED"
    assert second["commit_authority"]["state"] == "SUPERSEDED"
    assert second["commit_authority"]["reason_codes"] == []


def test_append_binds_exact_active_preimage_and_prefix_successor(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    shared = sp / "shared.md"
    shared.write_text("trusted base\n", encoding="utf-8")
    producer = _contract(
        "worker.append_base", output="shared.md", model=False
    )
    _commit(sp, tmp_path, producer)
    append = _contract(
        "worker.append_successor",
        output="shared.md",
        model=True,
        write_mode="APPEND",
    )
    launch = _launch(append)

    bound = record_work_unit_inputs(
        sp, tmp_path, append, launch, run_id="run-commit"
    )
    assert bound["semantic_status"] == "INPUTS_BOUND"
    preimage = bound["output_prestates"]["scratchpad:shared.md"]
    assert preimage["sha256"] == AL._sha256(shared)
    shared.write_text("trusted base\nsuccessor\n", encoding="utf-8")

    committed = _commit(sp, tmp_path, append)

    assert committed["semantic_status"] == "ACTIVE"
    transition = committed["commit_authority"]["read_modify_write_transitions"][
        "scratchpad:shared.md"
    ]
    assert transition["preimage_sha256"] == preimage["sha256"]
    assert transition["successor_sha256"] == AL._sha256(shared)
    assert transition["prefix_preserved"] is True


def test_append_cannot_launder_tampered_active_base(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    shared = sp / "shared.md"
    shared.write_text("trusted base\n", encoding="utf-8")
    producer = _contract(
        "worker.append_tampered_base", output="shared.md", model=False
    )
    _commit(sp, tmp_path, producer)
    shared.write_text("tampered base\n", encoding="utf-8")
    append = _contract(
        "worker.append_after_tamper",
        output="shared.md",
        model=True,
        write_mode="APPEND",
    )

    bound = record_work_unit_inputs(
        sp, tmp_path, append, _launch(append), run_id="run-commit"
    )
    assert bound["semantic_status"] == "INPUT_DEBT"
    shared.write_text("tampered base\nappended candidate\n", encoding="utf-8")
    committed = _commit(sp, tmp_path, append)

    _assert_quarantined_everywhere(
        sp, append, "scratchpad:shared.md"
    )
    assert "READ_MODIFY_WRITE_PREIMAGE_INVALID" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_shape_equal_driver_projection_is_not_registered_lineage(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    shared = sp / "shared.md"
    shared.write_text("first projection\n", encoding="utf-8")
    common = {
        "output": "shared.md",
        "model": False,
        "artifact_class": "DRIVER_GENERATED",
        "schema_version": "x.v1",
        "consumers": ("consumer/x",),
    }
    first = _contract("unrelated_a", **common)
    second = _contract("unrelated_b", **common)
    _commit(sp, tmp_path, first)
    record_work_unit_inputs(
        sp, tmp_path, second, _launch(second), run_id="run-commit"
    )
    shared.write_text("unrelated replacement\n", encoding="utf-8")

    committed = _commit(sp, tmp_path, second)

    _assert_quarantined_everywhere(sp, second, "scratchpad:shared.md")
    assert "OUTPUT_OWNER_CONFLICT" in committed["commit_authority"]["reason_codes"]


def test_malformed_legacy_producer_cannot_transitively_authorize_consumer(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "source.md").write_text("source\n", encoding="utf-8")
    producer = _contract("producer", output="source.md", model=False)
    _commit(sp, tmp_path, producer)
    ledger = read_artifact_ledger(sp)
    producer_unit = ledger["work_units"][producer.key]
    producer_unit.pop("execution_state")
    producer_unit.pop("commit_authority")
    producer_unit.pop("contract_manifest")
    _write_ledger(sp, ledger)
    consumer = _contract(
        "consumer",
        inputs=("scratchpad:source.md",),
    )

    bound = record_work_unit_inputs(
        sp, tmp_path, consumer, _launch(consumer), run_id="run-commit"
    )
    assert bound["semantic_status"] == "INPUT_DEBT"
    (sp / "result.md").write_text("candidate\n", encoding="utf-8")
    committed = _commit(sp, tmp_path, consumer)

    assert committed["semantic_status"] == "QUARANTINED"
    assert "INPUT_PRODUCER_UNIT_NOT_ACTIVE" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_producer_launch_drift_breaks_transitive_authority(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "source.md").write_text("source\n", encoding="utf-8")
    producer = _contract("launch_source", output="source.md", model=False)
    _commit(sp, tmp_path, producer)
    ledger = read_artifact_ledger(sp)
    ledger["artifact_bindings"]["scratchpad:source.md"]["launch_digest"] = (
        "f" * 64
    )
    _write_ledger(sp, ledger)
    consumer = _contract(
        "launch_consumer",
        inputs=("scratchpad:source.md",),
    )

    bound = record_work_unit_inputs(
        sp, tmp_path, consumer, _launch(consumer), run_id="run-commit"
    )

    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["input_bindings"]["scratchpad:source.md"]["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


@pytest.mark.parametrize(
    "corruption",
    ("binding_sha", "binding_run", "binding_status", "unit_status", "legacy_sha"),
)
def test_same_owner_recommit_cannot_self_heal_corrupt_prior_tables(
    tmp_path: Path, corruption: str,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "result.md").write_text("stable output\n", encoding="utf-8")
    contract = _contract(f"same_owner_{corruption}", model=False)
    _commit(sp, tmp_path, contract)
    ledger = read_artifact_ledger(sp)
    identity = "scratchpad:result.md"
    if corruption == "binding_sha":
        ledger["artifact_bindings"][identity]["sha256"] = "f" * 64
    elif corruption == "binding_run":
        ledger["artifact_bindings"][identity]["run_id"] = "foreign-run"
    elif corruption == "binding_status":
        ledger["artifact_bindings"][identity]["status"] = "QUARANTINED"
    elif corruption == "unit_status":
        ledger["work_units"][contract.key]["artifacts"][identity]["status"] = (
            "QUARANTINED"
        )
    else:
        ledger["artifacts"]["result.md"]["sha256"] = "f" * 64
    _write_ledger(sp, ledger)

    committed = _commit(sp, tmp_path, contract)

    assert committed["semantic_status"] == "QUARANTINED"
    assert "PRIOR_LEDGER_STATE_MISMATCH" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_zero_input_model_output_requires_prelaunch_receipt(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "result.md").write_text("post-hoc model bytes\n", encoding="utf-8")
    contract = _contract("worker.zero_model", model=True)

    committed = _commit(sp, tmp_path, contract)

    _assert_quarantined_everywhere(sp, contract, "scratchpad:result.md")
    assert "MISSING_PREEXECUTION_INPUT_RECEIPT" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_snapshot_rejects_same_stat_content_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "race.md"
    path.write_bytes(b"AAAA")
    before = path.stat()
    real_sha = AL._sha256
    calls = 0

    def racing_sha(target: Path) -> str:
        nonlocal calls
        calls += 1
        digest = real_sha(target)
        if calls == 1:
            target.write_bytes(b"BBBB")
            AL.os.utime(
                target,
                ns=(before.st_atime_ns, before.st_mtime_ns),
            )
        return digest

    monkeypatch.setattr(AL, "_sha256", racing_sha)

    snapshot, error = AL._stable_artifact_snapshot(path)

    assert snapshot is None
    assert error == "UNSTABLE_FILE_CONTENT"


def test_unbounded_precommit_debt_is_bounded_and_quarantined_haltlessly(
    tmp_path: Path,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "result.md").write_text("retained candidate\n", encoding="utf-8")
    contract = _contract("large_domain_debt", model=False)
    issues = [f"domain issue {index:03d}" for index in range(129)]

    first = _commit(
        sp, tmp_path, contract, precommit_issues=issues
    )
    second = _commit(
        sp, tmp_path, contract, precommit_issues=list(reversed(issues))
    )

    assert first["semantic_status"] == "QUARANTINED"
    receipt = first["commit_authority"]
    assert receipt["precommit_issue_count"] == 129
    assert receipt["precommit_issue_overflow"] == 65
    assert len(receipt["precommit_issues"]) == 64
    assert len(receipt["precommit_issue_digest"]) == 64
    assert second["commit_authority"]["precommit_issue_digest"] == (
        receipt["precommit_issue_digest"]
    )
    assert (sp / "result.md").read_text(encoding="utf-8") == (
        "retained candidate\n"
    )


@pytest.mark.parametrize("present", (False, True))
def test_failed_conditional_receipt_is_quarantined_at_commit(
    tmp_path: Path, present: bool,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    contract = _contract(
        "conditional_failed",
        output="conditional.md",
        model=False,
        artifact_class="CONDITIONAL",
        condition_id="candidate_present",
    )
    if present:
        (sp / "conditional.md").write_text(
            "partial retained candidate\n", encoding="utf-8"
        )
    receipt = ConditionalOutputReceipt(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:conditional.md",
        condition_id="candidate_present",
        state="FAILED",
        expected_denominator=1,
        failure_ids=("missing-row",),
    )

    committed = _commit(
        sp,
        tmp_path,
        contract,
        conditional_receipts={"scratchpad:conditional.md": receipt},
    )

    assert committed["semantic_status"] == "QUARANTINED"
    assert "CONDITIONAL_RECEIPT_FAILED" in (
        committed["commit_authority"]["reason_codes"]
    )
    if present:
        assert committed["artifacts"]["scratchpad:conditional.md"][
            "authority_level"
        ] == "PROPOSAL_ONLY"


def test_not_triggered_conditional_cannot_hide_stale_output(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "conditional.md").write_text("stale candidate\n", encoding="utf-8")
    contract = _contract(
        "conditional_not_triggered",
        output="conditional.md",
        model=False,
        artifact_class="CONDITIONAL",
        condition_id="candidate_present",
    )
    receipt = ConditionalOutputReceipt(
        work_unit_key=contract.key,
        contract_digest=contract.digest,
        artifact_identity="scratchpad:conditional.md",
        condition_id="candidate_present",
        state="NOT_TRIGGERED",
        expected_denominator=0,
    )

    committed = _commit(
        sp,
        tmp_path,
        contract,
        conditional_receipts={"scratchpad:conditional.md": receipt},
    )

    assert committed["semantic_status"] == "QUARANTINED"
    assert "CONDITIONAL_RECEIPT_OUTPUT_MISMATCH" in (
        committed["commit_authority"]["reason_codes"]
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows case-insensitive path fixture")
def test_windows_case_alias_cannot_gain_second_active_owner(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    first_path = sp / "Case.md"
    first_path.write_text("owned bytes\n", encoding="utf-8")
    first = _contract("case_owner", output="Case.md", model=False)
    _commit(sp, tmp_path, first)
    second = _contract("case_alias", output="case.md", model=False)

    bound = record_work_unit_inputs(
        sp, tmp_path, second, _launch(second), run_id="run-commit"
    )
    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["output_prestates"]["scratchpad:case.md"]["status"] == (
        "PHYSICAL_OWNER_CONFLICT"
    )
    committed = _commit(sp, tmp_path, second)
    assert committed["semantic_status"] == "QUARANTINED"


def test_cross_root_alias_cannot_gain_second_active_owner(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    shared = sp / "same.md"
    shared.write_text("owned bytes\n", encoding="utf-8")
    first = _contract("scratch_owner", output="same.md", model=False)
    _commit(sp, tmp_path, first)
    key = "sc/thorough/evm/claude/depth/project_alias"
    second = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="project_alias",
        outputs=(
            ArtifactSpec(
                root="project",
                path=".scratchpad/same.md",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        model_invoked=False,
    )

    bound = record_work_unit_inputs(
        sp, tmp_path, second, _launch(second), run_id="run-commit"
    )

    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["output_prestates"]["project:.scratchpad/same.md"]["status"] == (
        "PHYSICAL_OWNER_CONFLICT"
    )


def test_hardlink_alias_cannot_gain_second_active_owner(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    original = sp / "original.md"
    original.write_text("owned bytes\n", encoding="utf-8")
    first = _contract("hardlink_owner", output="original.md", model=False)
    _commit(sp, tmp_path, first)
    alias = sp / "alias.md"
    try:
        os.link(original, alias)
    except OSError:
        pytest.skip("hardlinks unavailable")
    second = _contract("hardlink_alias", output="alias.md", model=False)

    bound = record_work_unit_inputs(
        sp, tmp_path, second, _launch(second), run_id="run-commit"
    )

    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["output_prestates"]["scratchpad:alias.md"]["status"] == (
        "PHYSICAL_OWNER_CONFLICT"
    )


def test_symlink_escape_degrades_without_reading_outside_root(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("outside bytes\n", encoding="utf-8")
    link = sp / "escape.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    contract = _contract("escape_alias", output="escape.md", model=False)

    bound = record_work_unit_inputs(
        sp, tmp_path, contract, _launch(contract), run_id="run-commit"
    )
    committed = _commit(sp, tmp_path, contract)

    assert bound["semantic_status"] == "INPUT_DEBT"
    assert bound["output_prestates"]["scratchpad:escape.md"]["status"] == (
        "UNSAFE_PHYSICAL_PATH"
    )
    assert committed["semantic_status"] == "QUARANTINED"
    assert "OUTPUT_PHYSICAL_PATH_UNSAFE" in (
        committed["commit_authority"]["reason_codes"]
    )
    assert outside.read_text(encoding="utf-8") == "outside bytes\n"
