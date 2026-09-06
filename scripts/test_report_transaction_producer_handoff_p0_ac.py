"""Report transactions advance producer authority without self-reblessing."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    arm_semantic_mutation,
    authorize_deterministic_work_unit_reexecution,
    finalize_semantic_mutation,
    recover_armed_semantic_mutations,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_mutation_events,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
)
from report_mutation_transaction import apply_report_mutation_transaction


RUN_ID = "report-successor-run"
BOUNDARIES = (
    "BACKUP_DURABLE",
    "PAYLOADS_DURABLE",
    "ARMED_DURABLE",
    "SIDECARS_DURABLE",
    "REPORT_REPLACED",
    "COMMIT_DURABLE",
)


def _launch(contract: PhaseIOContract) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def _producer() -> PhaseIOContract:
    key = "sc/thorough/evm/claude/report_floor/assurance_projection"
    return PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_floor",
        work_unit_id="assurance_projection",
        outputs=(
            ArtifactSpec(
                root="project",
                path="AUDIT_REPORT.md",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
            ),
        ),
        immutable_inputs=("scratchpad:source.json",),
        model_invoked=False,
    )


def _consumer(unit: str) -> PhaseIOContract:
    return PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="severity_adjudication_shadow",
        work_unit_id=unit,
        outputs=(),
        immutable_inputs=("project:AUDIT_REPORT.md",),
        model_invoked=False,
    )


def _disposition_consumer() -> PhaseIOContract:
    key = "sc/thorough/evm/claude/report_floor/disposition_authority"
    return PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_floor",
        work_unit_id="disposition_authority",
        outputs=(
            ArtifactSpec(
                root="project",
                path="AUDIT_REPORT.md",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="MERGE",
            ),
        ),
        immutable_inputs=("scratchpad:source.json",),
        model_invoked=False,
    )


def _seed(tmp_path: Path, before: bytes) -> tuple[Path, PhaseIOContract, LaunchSpec]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "source.json").write_bytes(b'{"authority":"fixture"}\n')
    assembly_key = "sc/thorough/evm/claude/report_assemble/assembly"
    assembly = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="report_assemble",
        work_unit_id="assembly",
        outputs=(
            ArtifactSpec(
                root="project",
                path="AUDIT_REPORT.md",
                owner_key=assembly_key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        immutable_inputs=("scratchpad:source.json",),
        model_invoked=False,
    )
    assembly_launch = _launch(assembly)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        assembly,
        assembly_launch,
        run_id=RUN_ID,
    )
    (tmp_path / "AUDIT_REPORT.md").write_bytes(before)
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        assembly,
        assembly_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    producer = _producer()
    launch = _launch(producer)
    record_work_unit_inputs(
        scratchpad, tmp_path, producer, launch, run_id=RUN_ID
    )
    report_ids = tuple(sorted({
        match.group(1).upper()
        for match in re.finditer(
            rb"\[([CHMLI]-[0-9]+)\]", before, re.IGNORECASE
        )
    }))
    digest = hashlib.sha256(before).hexdigest()
    merge_event = DriverMergeEvent(
        work_unit_key=producer.key,
        contract_digest=producer.digest,
        artifact_identity="project:AUDIT_REPORT.md",
        before_sha256=digest,
        after_sha256=digest,
        source_identities=("scratchpad:source.json",),
        identities_before=tuple(
            item.decode("ascii") for item in report_ids
        ),
        identities_after=tuple(
            item.decode("ascii") for item in report_ids
        ),
    )
    record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        producer,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events={"project:AUDIT_REPORT.md": merge_event},
    )
    return scratchpad, producer, launch


@pytest.mark.parametrize(
    ("before", "after"),
    (
        (b"# Audit Report\n\n## Summary\n\nNo findings.\n", b"# Audit Report\n\n## Summary\n\nNo findings.\n\n## Appendix\n"),
        (b"# Audit Report\n\n### [H-001] Finding\n\nBody.\n", b"# Audit Report\n\n### [H-001] Finding\n\nBody revised.\n"),
    ),
)
def test_committed_report_successor_is_an_authenticated_consumer_input(
    tmp_path: Path, before: bytes, after: bytes
) -> None:
    scratchpad, _, _ = _seed(tmp_path, before)
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )
    consumer = _consumer("final_report_projection_fixture")
    launch = _launch(consumer)
    unit = record_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    )

    binding = unit["input_bindings"]["project:AUDIT_REPORT.md"]
    assert binding["status"] == "ACTIVE"
    assert binding["producer_work_unit_key"].startswith("semantic-mutation:")
    assert validate_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    ) == []


@pytest.mark.parametrize("boundary", BOUNDARIES)
def test_crash_recovery_preserves_one_contiguous_report_successor(
    tmp_path: Path, boundary: str
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)

    def crash(name: str) -> None:
        if name == boundary:
            raise RuntimeError(f"crash:{name}")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={"report_dedup.canonical_candidate.md": after},
            fault_hook=crash,
        )
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )
    consumer = _consumer(f"crash_consumer_{boundary.lower()}")
    launch = _launch(consumer)
    record_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    )
    assert validate_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    ) == []


def test_post_commit_report_tamper_is_not_reblessed(tmp_path: Path) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )
    (tmp_path / "AUDIT_REPORT.md").write_bytes(b"tampered third state\n")
    consumer = _consumer("tamper_consumer")
    launch = _launch(consumer)
    unit = record_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    )
    assert unit["input_bindings"]["project:AUDIT_REPORT.md"]["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_forged_terminal_report_semantic_event_is_not_producer_authority(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\nforged successor\n"
    scratchpad, _, _ = _seed(tmp_path, before)
    event = arm_semantic_mutation(
        scratchpad,
        tmp_path,
        artifact_identity="project:AUDIT_REPORT.md",
        mutation_kind="REPORT_TRANSACTION_FORGED",
        run_id=RUN_ID,
    )
    (tmp_path / "AUDIT_REPORT.md").write_bytes(after)
    finalize_semantic_mutation(
        scratchpad, tmp_path, event["event_id"], run_id=RUN_ID
    )

    consumer = _consumer("forged_event_consumer")
    launch = _launch(consumer)
    unit = record_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    )
    assert unit["input_bindings"]["project:AUDIT_REPORT.md"]["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


def test_final_assurance_reexecution_accepts_only_durable_report_successor(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Appendix\n"
    scratchpad, producer, launch = _seed(tmp_path, before)
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )

    plan = authorize_deterministic_work_unit_reexecution(
        scratchpad,
        tmp_path,
        producer,
        launch,
        run_id=RUN_ID,
        durable_mutation_successor_identities=("project:AUDIT_REPORT.md",),
    )
    assert plan is not None
    assert plan["changed_input_identities"] == ["project:AUDIT_REPORT.md"]

    rebound = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        producer,
        launch,
        run_id=RUN_ID,
    )
    assert rebound["semantic_status"] == "INPUTS_BOUND"
    assert rebound["output_prestates"]["project:AUDIT_REPORT.md"][
        "status"
    ] == "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR"


def test_disposition_merge_accepts_registered_assurance_semantic_successor(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Dedup-normalized appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )

    disposition = _disposition_consumer()
    unit = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        disposition,
        _launch(disposition),
        run_id=RUN_ID,
    )

    prestate = unit["output_prestates"]["project:AUDIT_REPORT.md"]
    assert prestate["status"] == (
        "ACTIVE_REGISTERED_SEMANTIC_PREDECESSOR"
    )


@pytest.mark.parametrize("changes_report", (False, True))
def test_disposition_commit_accepts_only_its_authenticated_report_successor(
    tmp_path: Path,
    changes_report: bool,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    deduped = before + b"\n## Dedup-normalized appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=deduped,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": deduped},
    )
    disposition = _disposition_consumer()
    launch = _launch(disposition)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        disposition,
        launch,
        run_id=RUN_ID,
    )

    successor = (
        deduped + b"\n## Decision-authorized appendix\n"
        if changes_report
        else deduped
    )
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_floor.disposition",
        post_report=successor,
        exact_inputs=("source.json",),
        sidecars={"report_floor.disposition.candidate.md": successor},
    )
    merge_event = DriverMergeEvent(
        work_unit_key=disposition.key,
        contract_digest=disposition.digest,
        artifact_identity="project:AUDIT_REPORT.md",
        before_sha256=hashlib.sha256(deduped).hexdigest(),
        after_sha256=hashlib.sha256(successor).hexdigest(),
        source_identities=("scratchpad:source.json",),
        identities_before=(),
        identities_after=(),
    )
    committed = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        disposition,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events={"project:AUDIT_REPORT.md": merge_event},
    )

    assert committed["semantic_status"] == "ACTIVE"
    assert committed["execution_state"] == "OUTPUT_COMMITTED"
    plan = authorize_deterministic_work_unit_reexecution(
        scratchpad,
        tmp_path,
        _producer(),
        _launch(_producer()),
        run_id=RUN_ID,
        authenticated_successor_owners={
            "project:AUDIT_REPORT.md": (disposition.key,),
        },
    )
    assert plan is not None
    assert plan["changed_input_identities"] == [
        "project:AUDIT_REPORT.md"
    ]
    rebound = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        _producer(),
        _launch(_producer()),
        run_id=RUN_ID,
    )
    assert rebound["semantic_status"] == "INPUTS_BOUND"
    assert rebound["output_prestates"]["project:AUDIT_REPORT.md"][
        "status"
    ] == "ACTIVE_PREIMAGE"


def test_disposition_commit_rejects_forged_post_arm_report_successor(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    deduped = before + b"\n## Dedup-normalized appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=deduped,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": deduped},
    )
    disposition = _disposition_consumer()
    launch = _launch(disposition)
    record_work_unit_inputs(
        scratchpad,
        tmp_path,
        disposition,
        launch,
        run_id=RUN_ID,
    )

    successor = deduped + b"\nforged unreceipted successor\n"
    forged = arm_semantic_mutation(
        scratchpad,
        tmp_path,
        artifact_identity="project:AUDIT_REPORT.md",
        mutation_kind="REPORT_TRANSACTION_FORGED_POST_ARM",
        run_id=RUN_ID,
    )
    (tmp_path / "AUDIT_REPORT.md").write_bytes(successor)
    finalize_semantic_mutation(
        scratchpad,
        tmp_path,
        forged["event_id"],
        run_id=RUN_ID,
    )
    merge_event = DriverMergeEvent(
        work_unit_key=disposition.key,
        contract_digest=disposition.digest,
        artifact_identity="project:AUDIT_REPORT.md",
        before_sha256=hashlib.sha256(deduped).hexdigest(),
        after_sha256=hashlib.sha256(successor).hexdigest(),
        source_identities=("scratchpad:source.json",),
        identities_before=(),
        identities_after=(),
    )
    committed = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        disposition,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events={"project:AUDIT_REPORT.md": merge_event},
    )

    assert committed["semantic_status"] == "QUARANTINED"
    assert "SEMANTIC_OUTPUT_PRESTATE_ADVANCED_AFTER_ARM" in (
        committed["commit_authority"]["reason_codes"]
    )


def test_startup_recovery_replays_durable_preimage_report_transaction_arm(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)

    def crash(name: str) -> None:
        if name == "ARMED_DURABLE":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={"report_dedup.canonical_candidate.md": after},
            fault_hook=crash,
        )

    recovered = recover_armed_semantic_mutations(
        scratchpad, tmp_path, run_id=RUN_ID
    )
    assert len(recovered) == 1
    assert semantic_mutation_events(scratchpad)[0]["status"] == (
        "INVALIDATION_APPLIED"
    )
    assert (tmp_path / "AUDIT_REPORT.md").read_bytes() == after
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )
    assert semantic_mutation_events(scratchpad)[0]["status"] == (
        "INVALIDATION_APPLIED"
    )


def test_startup_recovery_defers_semantic_arm_without_transaction_manifest(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)

    def crash(name: str) -> None:
        if name == "BACKUP_DURABLE":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={"report_dedup.canonical_candidate.md": after},
            fault_hook=crash,
        )

    assert recover_armed_semantic_mutations(
        scratchpad, tmp_path, run_id=RUN_ID
    ) == []
    assert semantic_mutation_events(scratchpad)[0]["status"] == "ARMED"
    assert (tmp_path / "AUDIT_REPORT.md").read_bytes() == before


def test_startup_recovery_finalizes_postimage_report_transaction_arm(
    tmp_path: Path,
) -> None:
    before = b"# Audit Report\n\n### [H-001] Finding\n\nBody.\n"
    after = b"# Audit Report\n\n### [H-001] Finding\n\nBody revised.\n"
    scratchpad, _, _ = _seed(tmp_path, before)

    def crash(name: str) -> None:
        if name == "REPORT_REPLACED":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={"report_dedup.canonical_candidate.md": after},
            fault_hook=crash,
        )

    recovered = recover_armed_semantic_mutations(
        scratchpad, tmp_path, run_id=RUN_ID
    )
    assert len(recovered) == 1
    assert recovered[0]["status"] == "INVALIDATION_APPLIED"
    apply_report_mutation_transaction(
        scratchpad=scratchpad,
        project_root=tmp_path,
        run_id=RUN_ID,
        phase="report_dedup",
        post_report=after,
        exact_inputs=("source.json",),
        sidecars={"report_dedup.canonical_candidate.md": after},
    )
    assert len(semantic_mutation_events(scratchpad)) == 1


def test_startup_recovery_cannot_bless_postimage_after_input_drift(
    tmp_path: Path,
) -> None:
    """Postimage bytes alone are not proof that the transaction committed."""

    before = b"# Audit Report\n\n### [H-001] Finding\n\nBody.\n"
    after = b"# Audit Report\n\n### [H-001] Finding\n\nBody revised.\n"
    scratchpad, _, _ = _seed(tmp_path, before)

    def crash(name: str) -> None:
        if name == "REPORT_REPLACED":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={"report_dedup.canonical_candidate.md": after},
            fault_hook=crash,
        )
    (scratchpad / "source.json").write_bytes(b'{"authority":"drifted"}\n')

    with pytest.raises(ArtifactLedgerError, match="report transaction"):
        recover_armed_semantic_mutations(
            scratchpad, tmp_path, run_id=RUN_ID
        )
    event = semantic_mutation_events(scratchpad)[0]
    assert event["status"] == "ARMED"

    consumer = _consumer("uncommitted_postimage_consumer")
    launch = _launch(consumer)
    unit = record_work_unit_inputs(
        scratchpad, tmp_path, consumer, launch, run_id=RUN_ID
    )
    assert unit["input_bindings"]["project:AUDIT_REPORT.md"]["status"] == (
        "PRODUCER_AUTHORITY_MISMATCH"
    )


@pytest.mark.parametrize(
    ("sidecar_action", "succeeds"),
    (("missing", True), ("tampered", False)),
)
def test_startup_recovery_republishes_missing_but_refuses_tampered_sidecar(
    tmp_path: Path, sidecar_action: str, succeeds: bool
) -> None:
    before = b"# Audit Report\n\n## Summary\n\nNo findings.\n"
    after = before + b"\n## Appendix\n"
    scratchpad, _, _ = _seed(tmp_path, before)
    relative = "report_dedup.canonical_candidate.md"

    def crash(name: str) -> None:
        if name == "REPORT_REPLACED":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={relative: after},
            fault_hook=crash,
        )
    public = scratchpad / relative
    if sidecar_action == "missing":
        public.unlink()
    else:
        public.write_bytes(b"tampered\n")

    if succeeds:
        recovered = recover_armed_semantic_mutations(
            scratchpad, tmp_path, run_id=RUN_ID
        )
        assert len(recovered) == 1
        assert public.read_bytes() == after
    else:
        with pytest.raises(ArtifactLedgerError, match="sidecar"):
            recover_armed_semantic_mutations(
                scratchpad, tmp_path, run_id=RUN_ID
            )
        assert semantic_mutation_events(scratchpad)[0]["status"] == "ARMED"


@pytest.mark.parametrize(
    ("receipt_action", "succeeds"),
    (("intact", True), ("missing", True), ("tampered", False)),
)
def test_commit_before_semantic_finalize_requires_exact_receipt_recovery(
    tmp_path: Path, receipt_action: str, succeeds: bool
) -> None:
    before = b"# Audit Report\n\n### [H-001] Finding\n\nBody.\n"
    after = b"# Audit Report\n\n### [H-001] Finding\n\nBody revised.\n"
    scratchpad, _, _ = _seed(tmp_path, before)

    def crash(name: str) -> None:
        if name == "COMMIT_DURABLE":
            raise RuntimeError("crash")

    with pytest.raises(RuntimeError, match="crash"):
        apply_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=tmp_path,
            run_id=RUN_ID,
            phase="report_dedup",
            post_report=after,
            exact_inputs=("source.json",),
            sidecars={"report_dedup.canonical_candidate.md": after},
            fault_hook=crash,
        )
    receipt = (
        scratchpad
        / "_report_transactions"
        / "report_dedup"
        / "receipt.json"
    )
    if receipt_action == "missing":
        receipt.unlink()
    elif receipt_action == "tampered":
        receipt.write_bytes(b'{}\n')

    if succeeds:
        recovered = recover_armed_semantic_mutations(
            scratchpad, tmp_path, run_id=RUN_ID
        )
        assert len(recovered) == 1
        assert receipt.is_file()
        assert semantic_mutation_events(scratchpad)[0]["status"] == (
            "INVALIDATION_APPLIED"
        )
    else:
        with pytest.raises(ArtifactLedgerError, match="receipt"):
            recover_armed_semantic_mutations(
                scratchpad, tmp_path, run_id=RUN_ID
            )
        assert semantic_mutation_events(scratchpad)[0]["status"] == "ARMED"
