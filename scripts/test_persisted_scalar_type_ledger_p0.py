"""Exact JSON scalar typing at persisted ledger trust boundaries.

JSON booleans must never satisfy integer authority fields merely because
``bool`` is a subclass of ``int`` in Python or because ``True == 1`` and
``False == 0``.  These tests exercise the persisted readers and the narrow
semantic-import/commit helpers that consume their records.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import artifact_ledger as AL
import verify_queue_context_authority as VQ
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


RUN_ID = "12345678-1234-4234-8234-123456789abc"
IDENTITY = "scratchpad:one.bin"
DIGEST = hashlib.sha256(b"x").hexdigest()
CONTRACT_DIGEST = hashlib.sha256(b"contract").hexdigest()


def _semantic_event(
    *,
    before_size: Any = 1,
    after_size: Any = 1,
    ordinal: int = 1,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema": "plamen.semantic_mutation.v1",
        "event_id": "",
        "run_id": RUN_ID,
        "mutation_kind": "FIXTURE_REWRITE",
        "artifact_identity": IDENTITY,
        "status": "NO_CHANGE",
        "before": {
            "status": "ACTIVE",
            "size": before_size,
            "sha256": DIGEST,
        },
        "after": {
            "status": "ACTIVE",
            "size": after_size,
            "sha256": DIGEST,
        },
        "affected_record_ids": [],
        "invalidated_work_unit_keys": [],
        "plan_digest": "",
        "checkpoint_reconciled": True,
        "reconciled_by_run_id": RUN_ID,
    }
    event["event_id"] = AL._semantic_mutation_event_id(event, ordinal)
    event["event_digest"] = AL._mutation_event_digest(event)
    return event


def _write_semantic_payload(root: Path, event: dict[str, Any]) -> None:
    (root / AL.SEMANTIC_MUTATION_LEDGER_NAME).write_text(
        json.dumps({
            "schema": "plamen.semantic_mutations.v1",
            "events": [event],
        }),
        encoding="utf-8",
    )


def _historical_binding(*, size: Any = 1) -> dict[str, Any]:
    return {
        "identity": IDENTITY,
        "owner_key": "sc/core/evm/claude/fixture/producer",
        "status": "ACTIVE",
        "run_id": RUN_ID,
        "contract_digest": CONTRACT_DIGEST,
        "sha256": DIGEST,
        "size": size,
    }


def _semantic_source_binding(
    event: dict[str, Any],
    historical: dict[str, Any],
    *,
    size: Any = 1,
) -> dict[str, Any]:
    authority_core = AL._semantic_virtual_producer_core(
        identity=IDENTITY,
        run_id=RUN_ID,
        producer=historical,
        mutation_event_ids=[event["event_id"]],
        mutation_authority_digests=[
            AL.semantic_mutation_authority_digest(event)
        ],
        live_state={"size": size, "sha256": DIGEST},
    )
    return {
        "identity": IDENTITY,
        "status": "ACTIVE",
        "sha256": DIGEST,
        "size": size,
        "producer_work_unit_key": f"semantic-mutation:{event['event_id']}",
        "producer_contract_digest": (
            AL._semantic_virtual_producer_digest(authority_core)
        ),
    }


def _commit_fixture(
    tmp_path: Path,
    *,
    output: bytes = b"x",
) -> tuple[Path, PhaseIOContract, LaunchSpec]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    key = "sc/core/evm/claude/fixture/scalar_types"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="fixture",
        work_unit_id="scalar_types",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="output.md",
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="REPLACE",
        ),),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    AL.record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    (scratchpad / "output.md").write_bytes(output)
    AL.record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return scratchpad, contract, launch


def _mutate_commit(
    scratchpad: Path,
    contract: PhaseIOContract,
    field: str,
    value: Any,
) -> dict[str, Any]:
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    commit = unit["commit_authority"]
    commit[field] = value
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratchpad, ledger)
    return unit


def _output_identity(contract: PhaseIOContract) -> str:
    return contract.outputs[0].identity


def _mutate_projection_sizes(
    scratchpad: Path,
    contract: PhaseIOContract,
    *,
    value: Any,
    projections: tuple[str, ...],
) -> tuple[dict[str, Any], dict[str, Any]]:
    ledger = AL.read_artifact_ledger(scratchpad)
    identity = _output_identity(contract)
    unit = ledger["work_units"][contract.key]
    commit = unit["commit_authority"]
    if "commit" in projections:
        commit["expected_output_records"][identity]["size"] = value
    if "work_unit" in projections:
        unit["artifacts"][identity]["size"] = value
    if "binding" in projections:
        ledger["artifact_bindings"][identity]["size"] = value
    if "legacy" in projections:
        ledger["artifacts"]["output.md"]["size"] = value
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratchpad, ledger)
    return ledger, unit


def _current_output_authority(
    scratchpad: Path,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    journal = json.loads(
        (scratchpad / AL._OUTPUT_AUTHORITY_LEDGER_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert len(journal["authorities"]) == 1
    authority_key, authority = next(iter(journal["authorities"].items()))
    return journal, authority_key, authority


def _persist_mutated_output_authority(
    scratchpad: Path,
    contract: PhaseIOContract,
    *,
    projection: str,
    value: Any,
) -> tuple[dict[str, Any], str, str]:
    journal, authority_key, authority = _current_output_authority(scratchpad)
    identity = _output_identity(contract)
    authority[projection][identity]["size"] = value
    unsigned = {
        key: item
        for key, item in authority.items()
        if key != "authority_digest"
    }
    authority_digest = AL._canonical_json_digest(unsigned)
    authority["authority_digest"] = authority_digest
    journal["authorities"][authority_key] = authority
    (scratchpad / AL._OUTPUT_AUTHORITY_LEDGER_NAME).write_text(
        json.dumps(journal, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    cas_path = (
        scratchpad
        / AL._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f"{authority_digest}.json"
    )
    cas_path.write_bytes(AL._canonical_json_bytes(unsigned))

    ledger = AL.read_artifact_ledger(scratchpad)
    commit = ledger["work_units"][contract.key]["commit_authority"]
    commit["output_authority_digest"] = authority_digest
    if projection == "expected_output_records":
        commit["expected_output_records"][identity]["size"] = value
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratchpad, ledger)
    return ledger, authority_key, authority_digest


def _coherently_reseal_output_authority_only(
    scratchpad: Path,
    contract: PhaseIOContract,
    *,
    projection: str,
    value: Any,
) -> dict[str, Any]:
    journal, authority_key, authority = _current_output_authority(scratchpad)
    identity = _output_identity(contract)
    old_digest = authority["authority_digest"]
    authority[projection][identity]["size"] = value
    unsigned = {
        key: item
        for key, item in authority.items()
        if key != "authority_digest"
    }
    authority_digest = AL._canonical_json_digest(unsigned)
    authority["authority_digest"] = authority_digest
    journal["authorities"][authority_key] = authority
    (scratchpad / AL._OUTPUT_AUTHORITY_LEDGER_NAME).write_text(
        json.dumps(journal, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    cas_root = scratchpad / AL._OUTPUT_AUTHORITY_CAS_DIRECTORY
    (cas_root / f"{authority_digest}.json").write_bytes(
        AL._canonical_json_bytes(unsigned)
    )
    (cas_root / f"{old_digest}.json").unlink()

    ledger = AL.read_artifact_ledger(scratchpad)
    commit = ledger["work_units"][contract.key]["commit_authority"]
    commit["output_authority_digest"] = authority_digest
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)
    AL.write_artifact_ledger(scratchpad, ledger)
    return ledger


def test_ledger_root_boolean_version_is_not_integer_version(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / AL.LEDGER_NAME).write_text(
        json.dumps({
            "version": True,
            "artifacts": {},
            "artifact_bindings": {},
            "work_units": {},
        }),
        encoding="utf-8",
    )

    with pytest.raises(AL.ArtifactLedgerError, match="version"):
        AL.read_artifact_ledger(scratchpad)


@pytest.mark.parametrize("version", (1, 2))
def test_ledger_root_valid_integer_versions_remain_compatible(
    tmp_path: Path,
    version: int,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / AL.LEDGER_NAME).write_text(
        json.dumps({
            "version": version,
            "artifacts": {},
            "artifact_bindings": {},
            "work_units": {},
        }),
        encoding="utf-8",
    )

    assert AL.read_artifact_ledger(scratchpad)["version"] == 2


@pytest.mark.parametrize(
    "snapshot",
    (
        {"status": "ACTIVE", "size": True, "sha256": DIGEST},
        {"status": "MISSING", "size": False, "sha256": ""},
    ),
    ids=("active-one-byte-bool", "missing-zero-byte-bool"),
)
def test_semantic_snapshot_rejects_boolean_size(
    snapshot: dict[str, Any],
) -> None:
    assert AL._valid_semantic_artifact_snapshot(snapshot) is False


@pytest.mark.parametrize(
    ("before_size", "after_size"),
    ((True, 1), (1, True)),
    ids=("boolean-preimage", "boolean-postimage"),
)
def test_persisted_semantic_mutation_rejects_boolean_snapshot_size(
    tmp_path: Path,
    before_size: Any,
    after_size: Any,
) -> None:
    event = _semantic_event(
        before_size=before_size,
        after_size=after_size,
    )
    _write_semantic_payload(tmp_path, event)

    with pytest.raises(AL.ArtifactLedgerError, match="state failure"):
        AL.semantic_mutation_events(tmp_path)


def test_frozen_semantic_import_rejects_boolean_source_binding_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = {
        "identity": IDENTITY,
        "status": "ACTIVE",
        "sha256": DIGEST,
        "size": True,
        "producer_work_unit_key": "fixture/producer",
        "producer_contract_digest": CONTRACT_DIGEST,
    }
    monkeypatch.setattr(
        AL,
        "semantic_input_producer_authority_issues",
        lambda *_args, **_kwargs: [],
    )

    with pytest.raises(AL.ArtifactLedgerError, match="binding is malformed"):
        AL.semantic_import_authority_from_snapshot(
            {}, None, IDENTITY, binding, run_id=RUN_ID
        )


def test_frozen_semantic_import_rejects_boolean_historical_size() -> None:
    event = _semantic_event()
    historical = _historical_binding(size=True)
    source = _semantic_source_binding(event, historical)
    payload = {
        "schema": "plamen.semantic_mutations.v1",
        "events": [event],
    }

    with pytest.raises(
        AL.ArtifactLedgerError,
        match="historical producer snapshot is unavailable",
    ):
        AL.semantic_import_authority_from_snapshot(
            {"artifact_bindings": {IDENTITY: historical}},
            payload,
            IDENTITY,
            source,
            run_id=RUN_ID,
        )


def test_frozen_semantic_import_rejects_boolean_event_postimage_size() -> None:
    event = _semantic_event(after_size=True)
    historical = _historical_binding()
    source = _semantic_source_binding(event, historical)
    payload = {
        "schema": "plamen.semantic_mutations.v1",
        "events": [event],
    }

    with pytest.raises(AL.ArtifactLedgerError, match="postimage is malformed"):
        AL.semantic_import_authority_from_snapshot(
            {"artifact_bindings": {IDENTITY: historical}},
            payload,
            IDENTITY,
            source,
            run_id=RUN_ID,
        )


@pytest.mark.parametrize(
    ("producer_size", "live_size"),
    ((True, 1), (1, True)),
    ids=("boolean-historical-size", "boolean-live-size"),
)
def test_live_semantic_mutation_authority_rejects_boolean_size(
    tmp_path: Path,
    producer_size: Any,
    live_size: Any,
) -> None:
    event = _semantic_event()
    _write_semantic_payload(tmp_path, event)
    producer = _historical_binding(size=producer_size)

    assert AL._semantic_mutation_producer_authority(
        tmp_path,
        project_root=tmp_path,
        identity=IDENTITY,
        producer=producer,
        live_state={
            "status": "ACTIVE",
            "size": live_size,
            "sha256": DIGEST,
        },
    ) is None


@pytest.mark.parametrize(
    ("field", "value"),
    (("attempt_ordinal", True), ("precommit_issue_count", False)),
    ids=("boolean-attempt", "boolean-precommit-count"),
)
def test_prior_commit_receipt_rejects_boolean_integer_fields(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    scratchpad, contract, _launch = _commit_fixture(tmp_path)
    unit = _mutate_commit(scratchpad, contract, field, value)

    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    ) is False


@pytest.mark.parametrize(
    ("field", "value"),
    (("attempt_ordinal", True), ("precommit_issue_count", False)),
    ids=("boolean-attempt", "boolean-precommit-count"),
)
def test_final_commit_validation_rejects_boolean_integer_fields(
    tmp_path: Path,
    field: str,
    value: Any,
) -> None:
    scratchpad, contract, launch = _commit_fixture(tmp_path)
    _mutate_commit(scratchpad, contract, field, value)

    issues = AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )

    assert any("output commit authority receipt invalid" in issue for issue in issues)


@pytest.mark.parametrize(
    ("raw", "boolean_size"),
    ((b"x", True), (b"", False)),
    ids=("one-byte-true", "zero-byte-false"),
)
def test_b1_coherent_ledger_only_boolean_sizes_cannot_remain_active(
    tmp_path: Path,
    raw: bytes,
    boolean_size: bool,
) -> None:
    scratchpad, contract, launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger, unit = _mutate_projection_sizes(
        scratchpad,
        contract,
        value=boolean_size,
        projections=("commit", "work_unit", "binding", "legacy"),
    )
    identity = _output_identity(contract)
    _journal, _key, authority = _current_output_authority(scratchpad)

    assert authority["expected_output_records"][identity]["size"] == len(raw)
    assert type(
        authority["expected_output_records"][identity]["size"]
    ) is int
    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    ) is False
    assert AL.active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=contract.key,
        run_id=RUN_ID,
        expected_artifact_identities=(identity,),
    )
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )


@pytest.mark.parametrize(
    "projection",
    ("commit", "work_unit", "binding", "legacy"),
)
@pytest.mark.parametrize(
    ("raw", "boolean_size"),
    ((b"x", True), (b"", False)),
    ids=("one-byte-true", "zero-byte-false"),
)
def test_b1_each_ledger_projection_boolean_size_is_explicit_debt(
    tmp_path: Path,
    projection: str,
    raw: bytes,
    boolean_size: bool,
) -> None:
    scratchpad, contract, launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger, _unit = _mutate_projection_sizes(
        scratchpad,
        contract,
        value=boolean_size,
        projections=(projection,),
    )
    identity = _output_identity(contract)

    assert AL.active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=contract.key,
        run_id=RUN_ID,
        expected_artifact_identities=(identity,),
    )
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )


@pytest.mark.parametrize(
    ("raw", "boolean_size"),
    ((b"x", True), (b"", False)),
    ids=("one-byte-true", "zero-byte-false"),
)
def test_b2_ledger_only_boolean_sizes_cannot_grant_producer_or_import(
    tmp_path: Path,
    raw: bytes,
    boolean_size: bool,
) -> None:
    scratchpad, contract, _launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger, _unit = _mutate_projection_sizes(
        scratchpad,
        contract,
        value=boolean_size,
        projections=("commit", "work_unit", "binding", "legacy"),
    )
    identity = _output_identity(contract)
    source_binding = {
        "identity": identity,
        "status": "ACTIVE",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "producer_work_unit_key": contract.key,
        "producer_contract_digest": contract.digest,
    }

    producer_issues = AL.semantic_input_producer_authority_issues(
        ledger,
        source_binding,
        run_id=RUN_ID,
    )

    assert producer_issues
    with pytest.raises(AL.ArtifactLedgerError):
        AL.semantic_import_authority_from_snapshot(
            ledger,
            None,
            identity,
            source_binding,
            run_id=RUN_ID,
        )


@pytest.mark.parametrize(
    "projection",
    ("expected_output_records", "observed_outputs"),
)
@pytest.mark.parametrize(
    ("raw", "boolean_size"),
    ((b"x", True), (b"", False)),
    ids=("one-byte-true", "zero-byte-false"),
)
def test_b3_redigested_output_authority_boolean_size_is_not_clean(
    tmp_path: Path,
    projection: str,
    raw: bytes,
    boolean_size: bool,
) -> None:
    scratchpad, contract, launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger, authority_key, _digest = _persist_mutated_output_authority(
        scratchpad,
        contract,
        projection=projection,
        value=boolean_size,
    )
    authority = json.loads(
        (scratchpad / AL._OUTPUT_AUTHORITY_LEDGER_NAME).read_text(
            encoding="utf-8"
        )
    )["authorities"][authority_key]

    with pytest.raises(AL.ArtifactLedgerError):
        AL._validated_output_authority_envelope(
            authority,
            authority_key=authority_key,
        )
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )
    assert AL.active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    ) or projection == "observed_outputs"


@pytest.mark.parametrize(
    "projection",
    ("expected_output_records", "observed_outputs"),
)
@pytest.mark.parametrize(
    ("raw", "boolean_size"),
    ((b"x", True), (b"", False)),
    ids=("one-byte-true", "zero-byte-false"),
)
def test_b4_coherent_external_authority_reseal_cannot_grant_producer(
    tmp_path: Path,
    projection: str,
    raw: bytes,
    boolean_size: bool,
) -> None:
    scratchpad, contract, launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger = _coherently_reseal_output_authority_only(
        scratchpad,
        contract,
        projection=projection,
        value=boolean_size,
    )
    identity = _output_identity(contract)
    unit = ledger["work_units"][contract.key]
    binding = ledger["artifact_bindings"][identity]
    source_binding = {
        "identity": identity,
        "status": "ACTIVE",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "producer_work_unit_key": contract.key,
        "producer_contract_digest": contract.digest,
    }
    assert type(unit["artifacts"][identity]["size"]) is int
    assert type(
        unit["commit_authority"][
            "expected_output_records"
        ][identity]["size"]
    ) is int
    assert type(binding["size"]) is int
    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    ) is False
    assert AL.semantic_input_producer_authority_issues(
        ledger,
        source_binding,
        run_id=RUN_ID,
    )
    with pytest.raises(AL.ArtifactLedgerError):
        authority = AL.semantic_import_authority_from_snapshot(
            ledger,
            None,
            identity,
            source_binding,
            run_id=RUN_ID,
        )
        assert authority["authority_kind"] != "EXACT_PHASE_IO_PRODUCER"
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )


@pytest.mark.parametrize(
    "projection",
    ("expected_output_records", "observed_outputs"),
)
@pytest.mark.parametrize(
    ("raw", "boolean_size"),
    ((b"x", True), (b"", False)),
    ids=("one-byte-true", "zero-byte-false"),
)
def test_malformed_issued_output_size_quarantines_without_crashing(
    tmp_path: Path,
    projection: str,
    raw: bytes,
    boolean_size: bool,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    key = "sc/core/evm/claude/fixture/scalar_commit_boundary"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="fixture",
        work_unit_id="scalar_commit_boundary",
        outputs=(ArtifactSpec(
            root="scratchpad",
            path="output.md",
            owner_key=key,
            artifact_class="DRIVER_GENERATED",
            writer="DRIVER",
            write_mode="REPLACE",
        ),),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=(),
    )
    AL.record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=RUN_ID
    )
    (scratchpad / "output.md").write_bytes(raw)
    ledger = AL.read_artifact_ledger(scratchpad)
    authority = AL._issue_output_commit_authority(
        scratchpad,
        tmp_path,
        ledger,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        expected_output_records=None,
        execution_authority=None,
    )
    identity = _output_identity(contract)
    authority[projection][identity]["size"] = boolean_size
    unsigned = {
        field: value
        for field, value in authority.items()
        if field != "authority_digest"
    }
    authority["authority_digest"] = AL._canonical_json_digest(unsigned)

    work_unit = AL._record_work_unit_artifacts_unlocked(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
        output_commit_authority=authority,
    )

    assert work_unit["semantic_status"] == "QUARANTINED"
    assert work_unit["execution_state"] == "OUTPUT_QUARANTINED"
    reasons = work_unit["commit_authority"]["reason_codes"]
    assert (
        "EXPECTED_OUTPUT_SIZE_INVALID" in reasons
        if projection == "expected_output_records"
        else "OUTPUT_COMMIT_AUTHORITY_DENOMINATOR_MISMATCH" in reasons
    )
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )


@pytest.mark.parametrize("raw", (b"", b"x"), ids=("zero", "one"))
def test_nested_integer_output_records_remain_active_and_clean(
    tmp_path: Path,
    raw: bytes,
) -> None:
    scratchpad, contract, launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    _journal, authority_key, authority = _current_output_authority(
        scratchpad
    )

    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    )
    assert AL._validated_output_authority_envelope(
        authority,
        authority_key=authority_key,
    )[0] == (RUN_ID, contract.key, 1)
    assert AL.active_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    ) == []
    assert AL.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    ) == []


@pytest.mark.parametrize("raw", (b"", b"x"), ids=("zero", "one"))
def test_valid_legacy_commit_without_source_actor_hints_remains_active(
    tmp_path: Path,
    raw: bytes,
) -> None:
    scratchpad, contract, _launch = _commit_fixture(
        tmp_path, output=raw
    )
    ledger = AL.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    commit = unit["commit_authority"]
    commit.pop("output_authority_source")
    commit.pop("output_authority_actor")
    commit["receipt_digest"] = AL._commit_receipt_digest(commit)

    assert AL._active_commit_receipt_is_valid(
        unit,
        work_unit_key=contract.key,
        run_id=RUN_ID,
    )


def test_verify_context_size_parser_rejects_boolean() -> None:
    assert VQ._as_size(True) is None


def test_verify_context_boolean_size_degrades_to_issue(
    tmp_path: Path,
) -> None:
    artifact = "application_skeptic_proposals.md"
    raw = b"# proposal\n"
    (tmp_path / artifact).write_bytes(raw)
    identity = f"scratchpad:{artifact}"
    owner_key = "sc/thorough/evm/claude/application_skeptic/reconcile"
    record = {
        "identity": identity,
        "owner_key": owner_key,
        "status": "ACTIVE",
        "run_id": RUN_ID,
        "contract_digest": CONTRACT_DIGEST,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": True,
    }
    snapshot = VQ.capture_verify_queue_context_snapshot(
        tmp_path,
        {
            "version": 2,
            "artifact_bindings": {identity: dict(record)},
            "work_units": {
                owner_key: {
                    "work_unit_key": owner_key,
                    "execution_state": "OUTPUT_COMMITTED",
                    "semantic_status": "ACTIVE",
                    "run_id": RUN_ID,
                    "contract_digest": CONTRACT_DIGEST,
                    "artifacts": {identity: dict(record)},
                },
            },
        },
    )

    selection = VQ.select_verify_queue_context(
        snapshot,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        run_id=RUN_ID,
    )

    assert selection.accepted_paths == ()
    assert selection.safe_base_routing is True
    assert any("SIZE_MISMATCH" in issue.codes for issue in selection.issues)


def test_valid_integer_compatibility_is_preserved() -> None:
    assert AL._valid_semantic_artifact_snapshot({
        "status": "ACTIVE",
        "size": 1,
        "sha256": DIGEST,
    })
    assert AL._valid_semantic_artifact_snapshot({
        "status": "MISSING",
        "size": 0,
        "sha256": "",
    })
    assert VQ._as_size(0) == 0
    assert VQ._as_size(1) == 1
