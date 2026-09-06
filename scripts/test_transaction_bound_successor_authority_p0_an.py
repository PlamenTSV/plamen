"""Adversarial contract for transaction-bound predecessor consumption.

A deterministic MERGE successor may consume one unchanged artifact from a
committed producer bundle while advancing declared siblings from that same
bundle.  The arm must bind the complete historical producer denominator and
the exact planned transitions before any write.  It must not weaken ordinary
bundle-wide tamper revocation.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

import artifact_ledger as AL
from artifact_ledger import (
    begin_driver_successor_step,
    complete_driver_successor_step,
    plan_driver_successor_transaction,
    read_artifact_ledger,
    recover_quarantined_deterministic_work_unit_prestate,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from phase_io_contracts import (
    ArtifactSpec,
    DriverMergeEvent,
    LaunchSpec,
    PhaseIOContract,
)


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "run-transaction-bound-successor"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _artifact(
    *,
    owner: str,
    path: str,
    write_mode: str = "REPLACE",
    consumers: tuple[str, ...] = (),
) -> ArtifactSpec:
    return ArtifactSpec(
        root="scratchpad",
        path=path,
        owner_key=owner,
        artifact_class="DRIVER_GENERATED",
        writer="DRIVER",
        write_mode=write_mode,
        consumers=consumers,
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
    )


def _fixture(
    tmp_path: Path,
    *,
    additional_consumers: tuple[str, ...] = (),
) -> tuple[
    Path,
    PhaseIOContract,
    LaunchSpec,
    PhaseIOContract,
    LaunchSpec,
    dict[str, DriverMergeEvent],
    dict[str, bytes],
]:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    producer_key = (
        "sc/thorough/evm/claude/inventory/canonical_aggregate"
    )
    consumer_key = (
        "sc/thorough/evm/claude/inventory/additive_reemit"
    )
    relative_consumer = "inventory/additive_reemit"
    producer_consumers = (
        relative_consumer,
        *additional_consumers,
    )
    producer = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="canonical_aggregate",
        outputs=(
            _artifact(
                owner=producer_key,
                path="inventory_id_allocation_delta.json",
                consumers=producer_consumers,
            ),
            _artifact(
                owner=producer_key,
                path="findings_inventory.md",
                consumers=producer_consumers,
            ),
            _artifact(
                owner=producer_key,
                path="finding_records.json",
                consumers=producer_consumers,
            ),
            _artifact(
                owner=producer_key,
                path="inventory_merge_receipt.md",
            ),
        ),
        model_invoked=False,
    )
    assert producer.key == producer_key
    producer_launch = _launch(producer)
    before = {
        "inventory_id_allocation_delta.json": b'{"stable":true}\n',
        "findings_inventory.md": b'{"ids":["A"]}\n',
        "finding_records.json": b'{"ids":["A"]}\n',
        "inventory_merge_receipt.md": b'{"unrelated":true}\n',
    }
    record_work_unit_inputs(
        scratch,
        tmp_path,
        producer,
        producer_launch,
        run_id=RUN_ID,
    )
    for name, raw in before.items():
        (scratch / name).write_bytes(raw)
    producer_unit = record_work_unit_artifacts(
        scratch,
        tmp_path,
        producer,
        producer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    assert producer_unit["semantic_status"] == "ACTIVE"

    consumer = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="additive_reemit",
        outputs=(
            _artifact(
                owner=consumer_key,
                path="findings_inventory.md",
                write_mode="MERGE",
            ),
            _artifact(
                owner=consumer_key,
                path="finding_records.json",
                write_mode="MERGE",
            ),
        ),
        immutable_inputs=(
            "scratchpad:inventory_id_allocation_delta.json",
        ),
        model_invoked=False,
    )
    assert consumer.key == consumer_key
    consumer_launch = _launch(consumer)
    after = {
        "findings_inventory.md": b'{"ids":["A","B"]}\n',
        "finding_records.json": b'{"ids":["A","B"]}\n',
    }
    events = {
        f"scratchpad:{name}": DriverMergeEvent(
            work_unit_key=consumer.key,
            contract_digest=consumer.digest,
            artifact_identity=f"scratchpad:{name}",
            before_sha256=_digest(before[name]),
            after_sha256=_digest(raw),
            source_identities=(
                "scratchpad:inventory_id_allocation_delta.json",
            ),
            identities_before=("A",),
            identities_after=("A", "B"),
        )
        for name, raw in after.items()
    }
    return (
        scratch,
        producer,
        producer_launch,
        consumer,
        consumer_launch,
        events,
        {**before, **after},
    )


def _arm(
    scratch: Path,
    project: Path,
    consumer: PhaseIOContract,
    launch: LaunchSpec,
    events: dict[str, DriverMergeEvent],
    raw: dict[str, bytes],
) -> tuple[dict, object]:
    plan = plan_driver_successor_transaction(
        scratch,
        project,
        consumer,
        launch,
        run_id=RUN_ID,
        planned_output_bytes={
            "scratchpad:findings_inventory.md": raw[
                "findings_inventory.md"
            ],
            "scratchpad:finding_records.json": raw[
                "finding_records.json"
            ],
        },
        merge_events=events,
    )
    unit = record_work_unit_inputs(
        scratch,
        project,
        consumer,
        launch,
        run_id=RUN_ID,
        successor_plan=plan,
    )
    return unit, plan


def _apply_step(
    scratch: Path,
    project: Path,
    consumer: PhaseIOContract,
    launch: LaunchSpec,
    *,
    ordinal: int,
    name: str,
    raw: bytes,
) -> None:
    begin_driver_successor_step(
        scratch,
        project,
        consumer,
        launch,
        run_id=RUN_ID,
        ordinal=ordinal,
    )
    (scratch / name).write_bytes(raw)
    complete_driver_successor_step(
        scratch,
        project,
        consumer,
        launch,
        run_id=RUN_ID,
        ordinal=ordinal,
    )


def test_declared_partial_successor_resumes_and_commits_exactly(
    tmp_path: Path,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    armed, plan = _arm(
        scratch, tmp_path, consumer, consumer_launch, events, raw
    )
    assert armed["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert armed["successor_consumption_authority"][
        "schema"
    ] == "plamen.driver-successor-authority.v1"

    _apply_step(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        ordinal=1,
        name="findings_inventory.md",
        raw=raw["findings_inventory.md"],
    )
    assert validate_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    ) == []
    resumed = record_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        successor_plan=plan,
    )
    assert resumed["successor_consumption_authority"] == armed[
        "successor_consumption_authority"
    ]
    assert [
        (row["ordinal"], row["state"])
        for row in resumed["successor_progress_authority"]["events"]
    ] == [(1, "STEP_ARMED"), (1, "STEP_APPLIED")]

    _apply_step(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        ordinal=2,
        name="finding_records.json",
        raw=raw["finding_records.json"],
    )
    assert validate_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    ) == []

    unit = record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
    )
    assert unit["semantic_status"] == "ACTIVE"
    assert unit["commit_authority"][
        "successor_consumption_authority_digest"
    ] == armed["successor_consumption_authority"][
        "authority_digest"
    ]
    assert validate_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []


def test_authenticated_progress_does_not_exempt_unrelated_bundle_sibling(
    tmp_path: Path,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    _apply_step(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        ordinal=1,
        name="findings_inventory.md",
        raw=raw["findings_inventory.md"],
    )
    (scratch / "inventory_merge_receipt.md").write_bytes(
        b'{"unrelated":"tampered-after-prefix"}\n'
    )

    issues = validate_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    )

    assert issues
    assert any(
        "inventory_merge_receipt.md" in issue
        or "historical producer" in issue
        for issue in issues
    )


@pytest.mark.parametrize(
    ("target", "replacement", "expected_fragment"),
    (
        (
            "inventory_id_allocation_delta.json",
            b'{"stable":false}\n',
            "inventory_id_allocation_delta.json",
        ),
        (
            "inventory_merge_receipt.md",
            b'{"unrelated":"tampered"}\n',
            "producer",
        ),
        (
            "findings_inventory.md",
            b'{"ids":["A","THIRD"]}\n',
            "producer",
        ),
    ),
)
def test_successor_authority_does_not_rebless_unplanned_drift(
    tmp_path: Path,
    target: str,
    replacement: bytes,
    expected_fragment: str,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        _raw,
    ) = _fixture(tmp_path)
    _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        _raw,
    )
    if target == "findings_inventory.md":
        begin_driver_successor_step(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            run_id=RUN_ID,
            ordinal=1,
        )
    (scratch / target).write_bytes(replacement)

    issues = validate_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    )

    assert issues
    assert any(
        expected_fragment.lower() in issue.lower() for issue in issues
    )
    unit = read_artifact_ledger(scratch)["work_units"][consumer.key]
    assert unit["semantic_status"] == "INPUTS_BOUND"


def test_commit_rejects_merge_events_that_differ_from_the_armed_plan(
    tmp_path: Path,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    for ordinal, name in enumerate(
        ("findings_inventory.md", "finding_records.json"),
        start=1,
    ):
        _apply_step(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            ordinal=ordinal,
            name=name,
            raw=raw[name],
        )
    changed = dict(events)
    original = events["scratchpad:findings_inventory.md"]
    changed["scratchpad:findings_inventory.md"] = DriverMergeEvent(
        work_unit_key=consumer.key,
        contract_digest=consumer.digest,
        artifact_identity=original.artifact_identity,
        before_sha256=original.before_sha256,
        after_sha256=original.after_sha256,
        source_identities=original.source_identities,
        identities_before=original.identities_before,
        identities_after=("A", "B", "FORGED"),
    )

    unit = record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=changed,
    )

    assert unit["semantic_status"] == "QUARANTINED"
    assert "PLANNED_MERGE_EVENT_MISMATCH" in unit[
        "commit_authority"
    ]["reason_codes"]


@pytest.mark.parametrize(
    "mutation",
    (
        "transitions_empty",
        "transitions_wrong_type",
        "transitions_duplicate",
        "transition_extra_field",
        "transition_missing_field",
        "merge_event_wrong_type",
        "merge_event_extra_field",
        "plan_extra_field",
    ),
)
def test_malformed_successor_plan_commits_durable_quarantine(
    tmp_path: Path,
    mutation: str,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    for ordinal, name in enumerate(
        ("findings_inventory.md", "finding_records.json"),
        start=1,
    ):
        _apply_step(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            ordinal=ordinal,
            name=name,
            raw=raw[name],
        )
    ledger = read_artifact_ledger(scratch)
    authority = ledger["work_units"][consumer.key][
        "successor_consumption_authority"
    ]
    plan = authority["plan"]
    transitions = plan["transitions"]
    if mutation == "transitions_empty":
        plan["transitions"] = []
    elif mutation == "transitions_wrong_type":
        plan["transitions"] = {}
    elif mutation == "transitions_duplicate":
        plan["transitions"] = [
            dict(transitions[0]),
            dict(transitions[0]),
        ]
    elif mutation == "transition_extra_field":
        transitions[0]["unexpected"] = True
    elif mutation == "transition_missing_field":
        transitions[0].pop("after_sha256")
    elif mutation == "merge_event_wrong_type":
        transitions[0]["merge_event"] = []
    elif mutation == "merge_event_extra_field":
        transitions[0]["merge_event"]["unexpected"] = True
    elif mutation == "plan_extra_field":
        plan["unexpected"] = True
    else:  # pragma: no cover - closed parametrization
        raise AssertionError(mutation)
    AL.write_artifact_ledger(scratch, ledger)

    unit = record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
    )

    assert unit["semantic_status"] == "QUARANTINED"
    assert unit["execution_state"] == "OUTPUT_QUARANTINED"
    assert "SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID" in unit[
        "commit_authority"
    ]["reason_codes"]
    assert unit["commit_authority"][
        "successor_consumption_authority_state"
    ] == "INVALID_UNAVAILABLE"


@pytest.mark.parametrize(
    "mutation",
    (
        "planned_delete",
        "planned_empty",
        "planned_alter",
        "planned_add",
        "authority_delete",
        "authority_alter",
    ),
)
def test_successor_commit_fields_are_replayed_not_self_certified(
    tmp_path: Path,
    mutation: str,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    for ordinal, name in enumerate(
        ("findings_inventory.md", "finding_records.json"),
        start=1,
    ):
        _apply_step(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            ordinal=ordinal,
            name=name,
            raw=raw[name],
        )
    record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
    )
    ledger = read_artifact_ledger(scratch)
    commit = ledger["work_units"][consumer.key]["commit_authority"]
    if mutation == "planned_delete":
        commit.pop("planned_merge_event_digests")
    elif mutation == "planned_empty":
        commit["planned_merge_event_digests"] = {}
    elif mutation == "planned_alter":
        identity = sorted(commit["planned_merge_event_digests"])[0]
        commit["planned_merge_event_digests"][identity] = "0" * 64
    elif mutation == "planned_add":
        commit["planned_merge_event_digests"][
            "scratchpad:unexpected.json"
        ] = "0" * 64
    elif mutation == "authority_delete":
        commit.pop("successor_consumption_authority_digest")
    elif mutation == "authority_alter":
        commit["successor_consumption_authority_digest"] = "0" * 64
    else:  # pragma: no cover - closed parametrization
        raise AssertionError(mutation)
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratch, ledger)

    issues = validate_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert any(
        "successor-specific commit binding" in issue for issue in issues
    )


def test_tampered_peer_state_cannot_release_overlapping_successor_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alternate_relative = "inventory/alternate_reemit"
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(
        tmp_path,
        additional_consumers=(alternate_relative,),
    )
    _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    journal = AL._read_driver_successor_authority_ledger(scratch)
    first_key = next(iter(journal["authorities"]))
    journal["authorities"][first_key]["state"] = "INACTIVE"
    AL._write_driver_successor_authority_ledger(scratch, journal)

    alternate_key = (
        "sc/thorough/evm/claude/inventory/alternate_reemit"
    )
    alternate = PhaseIOContract(
        **BASE,
        phase="inventory",
        work_unit_id="alternate_reemit",
        outputs=(
            _artifact(
                owner=alternate_key,
                path="findings_inventory.md",
                write_mode="MERGE",
            ),
            _artifact(
                owner=alternate_key,
                path="finding_records.json",
                write_mode="MERGE",
            ),
        ),
        immutable_inputs=(
            "scratchpad:inventory_id_allocation_delta.json",
        ),
        model_invoked=False,
    )
    alternate_launch = _launch(alternate)
    alternate_events = {
        identity: DriverMergeEvent(
            work_unit_key=alternate.key,
            contract_digest=alternate.digest,
            artifact_identity=event.artifact_identity,
            before_sha256=event.before_sha256,
            after_sha256=event.after_sha256,
            source_identities=event.source_identities,
            identities_before=event.identities_before,
            identities_after=event.identities_after,
        )
        for identity, event in events.items()
    }
    monkeypatch.setattr(
        AL,
        "registered_projection_handoff",
        lambda *_args, **_kwargs: True,
    )
    plan = plan_driver_successor_transaction(
        scratch,
        tmp_path,
        alternate,
        alternate_launch,
        run_id=RUN_ID,
        planned_output_bytes={
            "scratchpad:findings_inventory.md": raw[
                "findings_inventory.md"
            ],
            "scratchpad:finding_records.json": raw[
                "finding_records.json"
            ],
        },
        merge_events=alternate_events,
    )

    with pytest.raises(
        AL.ArtifactLedgerError,
        match="peer|journal|claim|authority",
    ):
        record_work_unit_inputs(
            scratch,
            tmp_path,
            alternate,
            alternate_launch,
            run_id=RUN_ID,
            successor_plan=plan,
        )


def test_reconstructed_progress_projection_cannot_certify_unordered_writes(
    tmp_path: Path,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    armed, _plan = _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    authority = armed["successor_consumption_authority"]
    # Perform both writes without the trusted begin/complete APIs, then
    # reconstruct the public progress projection from plan-visible fields.
    (scratch / "finding_records.json").write_bytes(
        raw["finding_records.json"]
    )
    (scratch / "findings_inventory.md").write_bytes(
        raw["findings_inventory.md"]
    )
    forged_events: list[dict] = []
    prior_digest = ""
    for transition in authority["plan"]["transitions"]:
        for state in ("STEP_ARMED", "STEP_APPLIED"):
            unsigned = {
                "schema": AL._DRIVER_SUCCESSOR_PROGRESS_EVENT_SCHEMA,
                "authority_digest": authority["authority_digest"],
                "plan_digest": authority["plan_digest"],
                "run_id": authority["run_id"],
                "work_unit_key": authority["work_unit_key"],
                "ordinal": transition["ordinal"],
                "state": state,
                "prior_event_digest": prior_digest,
                "transition_digest": AL._canonical_json_digest(
                    dict(transition)
                ),
            }
            event = {
                **unsigned,
                "event_digest": AL._canonical_json_digest(unsigned),
            }
            forged_events.append(event)
            prior_digest = event["event_digest"]
    # Reconstruct both mutable projections, including the locally recomputable
    # receipt in the main ledger.  The trusted append path also publishes each
    # event to write-once CAS; those objects cannot be synthesized by merely
    # rewriting the projections.
    ledger = read_artifact_ledger(scratch)
    unit = ledger["work_units"][consumer.key]
    progress_authority = dict(unit["successor_progress_authority"])
    progress_authority["events"] = forged_events
    progress_authority["head_event_digest"] = forged_events[-1][
        "event_digest"
    ]
    progress_authority["receipt_digest"] = (
        AL._driver_successor_progress_authority_digest(
            progress_authority
        )
    )
    unit["successor_progress_authority"] = progress_authority
    ledger["work_units"][consumer.key] = unit
    AL.write_artifact_ledger(scratch, ledger)
    AL._write_driver_successor_progress(
        scratch,
        {
            "schema": AL._DRIVER_SUCCESSOR_PROGRESS_SCHEMA,
            "transactions": {
                authority["authority_digest"]: {
                    "authority_digest": authority[
                        "authority_digest"
                    ],
                    "plan_digest": authority["plan_digest"],
                    "run_id": authority["run_id"],
                    "work_unit_key": authority["work_unit_key"],
                    "events": forged_events,
                }
            },
        },
    )

    unit = record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
    )

    assert unit["semantic_status"] == "QUARANTINED"
    assert "SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID" in unit[
        "commit_authority"
    ]["reason_codes"]


def test_artifact_ledger_arm_publish_flushes_before_and_after_replace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    events: list[str] = []
    real_fsync = AL.os.fsync
    real_replace = AL._durable_replace

    def _fsync(descriptor: int) -> None:
        events.append("file_fsync")
        real_fsync(descriptor)

    def _replace(source: Path, destination: Path) -> None:
        events.append("replace")
        real_replace(source, destination)
        events.append("metadata_sync")

    monkeypatch.setattr(AL.os, "fsync", _fsync)
    monkeypatch.setattr(AL, "_durable_replace", _replace)

    AL.write_artifact_ledger(scratch, AL._empty())

    assert events.index("file_fsync") < events.index("replace")
    assert events.index("replace") < events.index("metadata_sync")
    assert read_artifact_ledger(scratch) == AL._empty()


def test_write_once_cas_uses_durable_no_clobber_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    unsigned = {
        "schema": "fixture.authority.v1",
        "value": "immutable",
    }
    digest = AL._canonical_json_digest(unsigned)
    publications: list[tuple[Path, Path]] = []

    def _publish(source: Path, destination: Path) -> None:
        publications.append((Path(source), Path(destination)))
        os.replace(source, destination)

    monkeypatch.setattr(
        AL.rooted_io,
        "durable_publish_new",
        _publish,
    )
    AL._write_once_authority_cas(
        scratch,
        directory_name="_fixture_authority_cas",
        authority_digest=digest,
        unsigned_authority=unsigned,
        label="fixture authority",
    )

    assert len(publications) == 1
    source, destination = publications[0]
    assert source.parent == destination.parent
    assert destination.name == f"{digest}.json"
    assert destination.is_file()


def test_write_once_cas_recovers_exact_interrupted_link_prefix(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    unsigned = {
        "schema": "fixture.authority.v1",
        "value": "recoverable",
    }
    digest = AL._canonical_json_digest(unsigned)
    directory = scratch / "_fixture_authority_cas"
    directory.mkdir()
    target = directory / f"{digest}.json"
    staging = directory / f".{digest}.publishing.tmp"
    raw = AL._canonical_json_bytes(unsigned)
    staging.write_bytes(raw)
    os.link(staging, target)
    assert target.stat().st_nlink == 2

    AL._write_once_authority_cas(
        scratch,
        directory_name=directory.name,
        authority_digest=digest,
        unsigned_authority=unsigned,
        label="fixture authority",
    )

    assert not staging.exists()
    assert target.read_bytes() == raw
    assert target.stat().st_nlink == 1


def test_write_once_cas_forced_link_fallback_recovers_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    unsigned = {
        "schema": "fixture.authority.v1",
        "value": "forced-fallback",
    }
    digest = AL._canonical_json_digest(unsigned)
    directory = scratch / "_fixture_authority_cas"
    target = directory / f"{digest}.json"
    staging = directory / f".{digest}.publishing.tmp"
    real_retire = AL.rooted_io._retire_publication_source
    real_lexists = AL.rooted_io.lexists
    interrupted = False
    suppress_finally_cleanup = True

    def _forced_fallback(source: Path, destination: Path) -> None:
        AL.rooted_io._durable_publish_new_link_fallback(
            Path(source),
            Path(destination),
        )

    def _interrupt_once(source: Path) -> None:
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise OSError("simulated power loss after CAS link")
        real_retire(source)

    def _power_loss_lexists(path: Path) -> bool:
        if (
            interrupted
            and suppress_finally_cleanup
            and Path(path) == staging
        ):
            return False
        return real_lexists(path)

    monkeypatch.setattr(
        AL.rooted_io,
        "durable_publish_new",
        _forced_fallback,
    )
    monkeypatch.setattr(
        AL.rooted_io,
        "_retire_publication_source",
        _interrupt_once,
    )
    monkeypatch.setattr(
        AL.rooted_io,
        "lexists",
        _power_loss_lexists,
    )
    with pytest.raises(OSError, match="power loss after CAS link"):
        AL._write_once_authority_cas(
            scratch,
            directory_name=directory.name,
            authority_digest=digest,
            unsigned_authority=unsigned,
            label="fixture authority",
        )
    assert staging.is_file()
    assert target.is_file()
    assert target.stat().st_nlink == 2

    suppress_finally_cleanup = False
    AL._write_once_authority_cas(
        scratch,
        directory_name=directory.name,
        authority_digest=digest,
        unsigned_authority=unsigned,
        label="fixture authority",
    )

    assert not staging.exists()
    assert target.read_bytes() == AL._canonical_json_bytes(unsigned)
    assert target.stat().st_nlink == 1


@pytest.mark.parametrize("persist_journal", [False, True])
def test_successor_arm_recovers_from_cas_or_journal_only_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    persist_journal: bool,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    plan = plan_driver_successor_transaction(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        planned_output_bytes={
            "scratchpad:findings_inventory.md": raw[
                "findings_inventory.md"
            ],
            "scratchpad:finding_records.json": raw[
                "finding_records.json"
            ],
        },
        merge_events=events,
    )
    real_write = AL._write_driver_successor_authority_ledger

    def _interrupt_after_optional_journal(
        root: Path, payload: dict,
    ) -> None:
        if persist_journal:
            real_write(root, payload)
        raise OSError("simulated durable-arm interruption")

    monkeypatch.setattr(
        AL,
        "_write_driver_successor_authority_ledger",
        _interrupt_after_optional_journal,
    )
    with pytest.raises(OSError, match="durable-arm interruption"):
        record_work_unit_inputs(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            run_id=RUN_ID,
            successor_plan=plan,
        )
    assert consumer.key not in read_artifact_ledger(scratch)["work_units"]

    monkeypatch.setattr(
        AL, "_write_driver_successor_authority_ledger", real_write
    )
    recovered = record_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        successor_plan=plan,
    )
    assert recovered["semantic_status"] == "INPUTS_BOUND"
    assert recovered["successor_consumption_authority"][
        "plan_digest"
    ] == plan.digest


def test_successor_arm_recovers_after_main_ledger_publish_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    plan = plan_driver_successor_transaction(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        planned_output_bytes={
            "scratchpad:findings_inventory.md": raw[
                "findings_inventory.md"
            ],
            "scratchpad:finding_records.json": raw[
                "finding_records.json"
            ],
        },
        merge_events=events,
    )
    real_write = AL.write_artifact_ledger
    interrupted = False

    def _interrupt_after_arm(root: Path, ledger: dict) -> None:
        nonlocal interrupted
        real_write(root, ledger)
        unit = ledger.get("work_units", {}).get(consumer.key)
        if (
            not interrupted
            and isinstance(unit, dict)
            and "successor_consumption_authority" in unit
        ):
            interrupted = True
            raise OSError("simulated post-arm ledger interruption")

    monkeypatch.setattr(AL, "write_artifact_ledger", _interrupt_after_arm)
    with pytest.raises(OSError, match="post-arm ledger interruption"):
        record_work_unit_inputs(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            run_id=RUN_ID,
            successor_plan=plan,
        )
    monkeypatch.setattr(AL, "write_artifact_ledger", real_write)

    recovered = record_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        successor_plan=plan,
    )
    assert recovered["semantic_status"] == "INPUTS_BOUND"
    assert recovered["successor_progress_authority"]["events"] == []


def test_successor_arm_and_progress_are_durable_before_first_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    ordering: list[str] = []
    real_cas = AL._write_once_authority_cas
    real_journal = AL._write_driver_successor_authority_ledger
    real_ledger = AL.write_artifact_ledger

    def _cas(*args, **kwargs):
        label = str(kwargs.get("label") or "")
        ordering.append(
            "progress_cas" if "progress event" in label else "arm_cas"
        )
        return real_cas(*args, **kwargs)

    def _journal(*args, **kwargs):
        ordering.append("arm_journal")
        return real_journal(*args, **kwargs)

    def _ledger(*args, **kwargs):
        ordering.append("main_ledger")
        return real_ledger(*args, **kwargs)

    monkeypatch.setattr(AL, "_write_once_authority_cas", _cas)
    monkeypatch.setattr(
        AL, "_write_driver_successor_authority_ledger", _journal
    )
    monkeypatch.setattr(AL, "write_artifact_ledger", _ledger)
    _armed, _plan = _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    begin_driver_successor_step(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        ordinal=1,
    )
    ordering.append("first_output_write")
    (scratch / "findings_inventory.md").write_bytes(
        raw["findings_inventory.md"]
    )

    assert ordering.index("arm_cas") < ordering.index("arm_journal")
    assert ordering.index("arm_journal") < ordering.index("main_ledger")
    assert ordering.index("progress_cas") < ordering.index(
        "first_output_write"
    )
    assert max(
        index
        for index, name in enumerate(ordering)
        if name == "main_ledger"
    ) < ordering.index("first_output_write")


def test_driver_successor_progress_rejects_duplicate_json_keys(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    (scratch / AL._DRIVER_SUCCESSOR_PROGRESS_NAME).write_text(
        '{"schema":"plamen.driver-successor-progress.v1",'
        '"schema":"plamen.driver-successor-progress.v1",'
        '"transactions":{}}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        AL.ArtifactLedgerError,
        match="duplicate key",
    ):
        AL._read_driver_successor_progress(scratch)


def test_control_ledgers_reject_hardlinks_and_duplicate_keys(
    tmp_path: Path,
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    AL.write_artifact_ledger(scratch, AL._empty())
    os.link(
        scratch / AL.LEDGER_NAME,
        scratch / "_artifact_state.alias.json",
    )
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="single-link|bounded no-follow",
    ):
        read_artifact_ledger(scratch)

    duplicate_root = tmp_path / "duplicate"
    duplicate_root.mkdir()
    (
        duplicate_root / AL._DRIVER_SUCCESSOR_AUTHORITY_LEDGER_NAME
    ).write_text(
        '{"schema":"plamen.driver-successor-authorities.v1",'
        '"authorities":{},"authorities":{}}\n',
        encoding="utf-8",
    )
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="duplicate key",
    ):
        AL._read_driver_successor_authority_ledger(duplicate_root)

    progress_root = tmp_path / "progress"
    progress_root.mkdir()
    empty_progress = {
        "schema": AL._DRIVER_SUCCESSOR_PROGRESS_SCHEMA,
        "transactions": {},
    }
    AL._write_driver_successor_progress(
        progress_root, empty_progress
    )
    os.link(
        progress_root / AL._DRIVER_SUCCESSOR_PROGRESS_NAME,
        progress_root / "_driver_successor_progress.alias.json",
    )
    with pytest.raises(
        AL.ArtifactLedgerError,
        match="no-follow regular file",
    ):
        AL._write_driver_successor_progress(
            progress_root, empty_progress
        )


def test_quarantined_merge_successor_recovers_and_retries_without_surgery(
    tmp_path: Path,
) -> None:
    (
        scratch,
        _producer,
        _producer_launch,
        consumer,
        consumer_launch,
        events,
        raw,
    ) = _fixture(tmp_path)
    _armed, plan = _arm(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        events,
        raw,
    )
    for ordinal, name in enumerate(
        ("findings_inventory.md", "finding_records.json"),
        start=1,
    ):
        _apply_step(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            ordinal=ordinal,
            name=name,
            raw=raw[name],
        )
    changed = dict(events)
    original = events["scratchpad:findings_inventory.md"]
    changed["scratchpad:findings_inventory.md"] = DriverMergeEvent(
        work_unit_key=consumer.key,
        contract_digest=consumer.digest,
        artifact_identity=original.artifact_identity,
        before_sha256=original.before_sha256,
        after_sha256=original.after_sha256,
        source_identities=original.source_identities,
        identities_before=original.identities_before,
        identities_after=("A", "B", "FORGED"),
    )
    quarantined = record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=changed,
    )
    assert quarantined["semantic_status"] == "QUARANTINED"
    for name in ("findings_inventory.md", "finding_records.json"):
        (scratch / name).write_bytes(b'{"ids":["A"]}\n')

    assert recover_quarantined_deterministic_work_unit_prestate(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
    )
    recovered = read_artifact_ledger(scratch)["work_units"][
        consumer.key
    ]
    assert recovered["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert recovered["successor_consumption_authority"][
        "plan_digest"
    ] == plan.digest
    assert recovered["successor_progress_authority"]["events"] == []

    record_work_unit_inputs(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        successor_plan=plan,
    )
    for ordinal, name in enumerate(
        ("findings_inventory.md", "finding_records.json"),
        start=1,
    ):
        _apply_step(
            scratch,
            tmp_path,
            consumer,
            consumer_launch,
            ordinal=ordinal,
            name=name,
            raw=raw[name],
        )
    active = record_work_unit_artifacts(
        scratch,
        tmp_path,
        consumer,
        consumer_launch,
        run_id=RUN_ID,
        actor="DRIVER",
        merge_events=events,
    )
    assert active["semantic_status"] == "ACTIVE"
