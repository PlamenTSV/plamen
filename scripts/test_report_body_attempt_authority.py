"""Closed attempt identities for report-body MODEL/projection generations."""
from __future__ import annotations

from pathlib import Path

import pytest

import artifact_ledger as A
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    parse_report_body_attempt_work_unit,
    registered_projection_handoff,
    report_body_attempt_work_unit_id,
    resolve_phase_io_contract,
)
from report_body_attempt_authority import (
    require_report_body_attempt_authority,
    resolve_report_body_model_attempt_ordinal,
)


RUN_ID = "82345678-1234-4abc-8def-1234567890ab"
SHARD = "report_critical_high"
INPUTS = (
    "body_manifests/report_critical_high.json",
    "report_evidence_manifests/report_critical_high.json",
    "verify_H-01.md",
)


@pytest.mark.parametrize("role", ("model", "evidence_projection"))
@pytest.mark.parametrize(
    "field", ("pipeline", "mode", "ecosystem", "backend", "phase", "work_unit_id"),
)
@pytest.mark.parametrize("alias", ("uppercase", "leading_space", "trailing_space"))
def test_report_body_resolver_rejects_normalized_identity_aliases(role, field, alias):
    dimensions = {
        "pipeline": "sc", "mode": "core", "ecosystem": "evm",
        "backend": "codex", "phase": "report_body",
        "work_unit_id": report_body_attempt_work_unit_id(role, SHARD, 1),
    }
    value = dimensions[field]
    dimensions[field] = (
        value.upper() if alias == "uppercase"
        else " " + value if alias == "leading_space"
        else value + " "
    )
    inputs = INPUTS if role == "model" else (*INPUTS, "report_evidence_records.json")
    outputs = (f"{SHARD}.md",) if role == "model" else (
        f"{SHARD}.md", f"report_evidence_projection_receipts/{SHARD}.json",
    )
    with pytest.raises(ValueError, match="report-body .*non-canonical alias"):
        resolve_phase_io_contract(
            **dimensions, exact_inputs=inputs, exact_outputs=outputs,
        )


def _model(ordinal: int):
    contract = resolve_phase_io_contract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="report_body",
        work_unit_id=report_body_attempt_work_unit_id("model", SHARD, ordinal),
        exact_inputs=INPUTS,
        exact_outputs=(f"{SHARD}.md",),
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="gpt-5.6-sol",
        timeout_s=30,
        exec_mode="headless",
    )
    return contract, launch


def _owned_inputs(root: Path, project: Path) -> None:
    owner = "sc/core/evm/backend-neutral/report_fixture/body_inputs"
    outputs = tuple(
        ArtifactSpec(
            root="scratchpad", path=name, owner_key=owner,
            artifact_class="DRIVER_GENERATED", writer="DRIVER",
            write_mode="CREATE", consumers=(
                "report_body/model.report_critical_high",
                "report_body/model.report_critical_high.attempt-0002",
                "report_body/model.report_critical_high.attempt-0003",
            ),
        )
        for name in INPUTS
    )
    contract = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm",
        backend="backend-neutral", phase="report_fixture",
        work_unit_id="body_inputs", outputs=outputs, model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver", timeout_s=30, exec_mode="python",
    )
    A.record_work_unit_inputs(root, project, contract, launch, run_id=RUN_ID)
    for name in INPUTS:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((name + "\n").encode())
    A.record_work_unit_artifacts(
        root, project, contract, launch, run_id=RUN_ID, actor="DRIVER",
    )


def _admitted_model_chain(root: Path, project: Path, count: int) -> None:
    _owned_inputs(root, project)
    for ordinal in range(1, count + 1):
        contract, launch = _model(ordinal)
        if ordinal > 1:
            require_report_body_attempt_authority(
                root, contract=contract, launch=launch, run_id=RUN_ID,
            )
        A.record_work_unit_inputs(
            root, project, contract, launch, run_id=RUN_ID,
        )
        if ordinal == 1:
            (root / f"{SHARD}.md").write_bytes(b"admitted model body\n")


def _resolved_ordinal(
    root: Path, *, run_id: str = RUN_ID,
    configured_ordinal: int | None = None,
) -> int:
    return resolve_report_body_model_attempt_ordinal(
        root,
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        run_id=run_id, shard=SHARD,
        configured_ordinal=configured_ordinal,
    )


def test_report_body_resume_ordinal_is_recovered_read_only(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _admitted_model_chain(root, project, 2)
    ledger_path = root / A.LEDGER_NAME
    frozen = (
        ledger_path.read_bytes(), ledger_path.stat().st_ino,
        ledger_path.stat().st_mtime_ns,
    )

    assert _resolved_ordinal(root) == 2
    assert (
        ledger_path.read_bytes(), ledger_path.stat().st_ino,
        ledger_path.stat().st_mtime_ns,
    ) == frozen


def test_explicit_report_body_ordinal_remains_a_live_request(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _admitted_model_chain(root, project, 2)

    assert _resolved_ordinal(root, configured_ordinal=3) == 3


def test_report_body_resume_ordinal_rejects_foreign_run(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _admitted_model_chain(root, project, 1)

    with pytest.raises(A.ArtifactLedgerError, match="receipt differs"):
        _resolved_ordinal(
            root, run_id="92345678-1234-4abc-8def-1234567890ab",
        )


def test_report_body_resume_ordinal_rejects_malformed_matching_alias(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _admitted_model_chain(root, project, 1)
    ledger = A.read_artifact_ledger(root)
    key = _model(1)[0].key
    unit = ledger["work_units"].pop(key)
    malformed = key + ".attempt-0001"
    unit["work_unit_key"] = malformed
    unit["contract_manifest"]["key"] = malformed
    ledger["work_units"][malformed] = unit
    A.write_artifact_ledger(root, ledger)

    with pytest.raises(A.ArtifactLedgerError, match="malformed identity"):
        _resolved_ordinal(root)


@pytest.mark.parametrize(
    "mutate_key",
    (
        lambda key: key.rsplit("/", 1)[0] + "/nested/" + key.rsplit("/", 1)[1],
        lambda key: key.replace("/core/", "/Core/", 1),
        lambda key: key.rsplit("/", 1)[0] + "/" + key.rsplit("/", 1)[1].upper(),
        lambda key: key.rsplit("/", 1)[0] + (
            "/EVIDENCE_PROJECTION." + SHARD
        ),
    ),
    ids=(
        "nested-component", "dimension-case-alias", "work-unit-case-alias",
        "projection-work-unit-case-alias",
    ),
)
def test_report_body_history_rejects_noncanonical_target_keys(
    tmp_path: Path, mutate_key,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _admitted_model_chain(root, project, 1)
    ledger = A.read_artifact_ledger(root)
    contract, launch = _model(1)
    unit = ledger["work_units"].pop(contract.key)
    alias = mutate_key(contract.key)
    unit["work_unit_key"] = alias
    unit["contract_manifest"]["key"] = alias
    ledger["work_units"][alias] = unit
    A.write_artifact_ledger(root, ledger)

    invalid_identity = "non-canonical target key|malformed identity"
    with pytest.raises(A.ArtifactLedgerError, match=invalid_identity):
        _resolved_ordinal(root)
    with pytest.raises(A.ArtifactLedgerError, match=invalid_identity):
        require_report_body_attempt_authority(
            root, contract=contract, launch=launch, run_id=RUN_ID,
        )


def test_report_body_resume_ordinal_rejects_history_gap(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _admitted_model_chain(root, project, 3)
    ledger = A.read_artifact_ledger(root)
    ledger["work_units"].pop(_model(2)[0].key)
    A.write_artifact_ledger(root, ledger)

    with pytest.raises(A.ArtifactLedgerError, match="not contiguous"):
        _resolved_ordinal(root)


@pytest.mark.parametrize("role", ("model", "evidence_projection"))
@pytest.mark.parametrize("ordinal", (1, 2, 9999))
def test_report_body_attempt_identity_round_trip(role: str, ordinal: int) -> None:
    work = report_body_attempt_work_unit_id(role, SHARD, ordinal)
    assert parse_report_body_attempt_work_unit(work) == (role, SHARD, ordinal)
    assert (".attempt-" not in work) is (ordinal == 1)


@pytest.mark.parametrize(
    "work",
    (
        "model.report_critical_high.attempt-0001",
        "model.report_critical_high.attempt-002",
        "model.report_critical_high.attempt-10000",
        "model.report_critical_high_b2",
        "evidence_projection.report_critical_high.ATTEMPT-0002",
    ),
)
def test_report_body_attempt_identity_rejects_aliases(work: str) -> None:
    assert parse_report_body_attempt_work_unit(work) is None


@pytest.mark.parametrize("role", ("model", "evidence_projection"))
def test_typed_fallback_is_registered_terminal_presentation_successor(
    role: str,
) -> None:
    predecessor = (
        "sc/core/evm/codex/report_body/"
        + report_body_attempt_work_unit_id(role, SHARD, 2)
    )
    successor = (
        "sc/core/evm/codex/report_body/"
        f"{SHARD}.typed_fallback"
    )
    assert registered_projection_handoff(
        predecessor,
        successor,
        f"scratchpad:{SHARD}.md",
    )
    assert not registered_projection_handoff(
        predecessor,
        successor,
        "scratchpad:report_medium.md",
    )


@pytest.mark.parametrize(
    "work",
    (
        "model.report_critical_high.attempt-",
        "model.report_critical_high.attempt-abcd",
        "model.report_critical_high.attempt-12x4",
    ),
)
def test_malformed_report_body_retry_suffix_returns_closed_debt(
    tmp_path: Path, work: str,
) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    owner = f"sc/core/evm/codex/report_body/{work}"
    contract = PhaseIOContract(
        pipeline="sc", mode="core", ecosystem="evm", backend="codex",
        phase="report_body", work_unit_id=work,
        outputs=(ArtifactSpec(
            root="scratchpad", path=f"{SHARD}.md", owner_key=owner,
            artifact_class="REQUIRED", writer="MODEL", write_mode="REPLACE",
        ),),
    )
    assert A._authorized_model_retry_predecessor(
        root,
        project,
        contract,
        {"work_units": {}, "artifact_bindings": {}},
        identity=f"scratchpad:{SHARD}.md",
        run_id=RUN_ID,
    ) is None


def test_report_body_attempt_contract_uses_shard_not_suffix() -> None:
    contract, _launch = _model(2)
    assert contract.work_unit_id == "model.report_critical_high.attempt-0002"
    assert tuple(spec.path for spec in contract.outputs) == (
        "report_critical_high.md",
    )
    assert contract.immutable_inputs == tuple(
        sorted(f"scratchpad:{name}" for name in INPUTS)
    )


@pytest.mark.parametrize(
    ("prior_role", "prior_n", "next_role", "next_n", "accepted"),
    (
        ("model", 1, "evidence_projection", 1, True),
        ("model", 1, "model", 2, True),
        ("evidence_projection", 1, "model", 2, True),
        ("model", 1, "model", 3, False),
        ("evidence_projection", 1, "evidence_projection", 2, False),
        ("model", 2, "evidence_projection", 1, False),
    ),
)
def test_report_body_handoff_is_same_or_exact_next_generation(
    prior_role: str, prior_n: int, next_role: str, next_n: int, accepted: bool,
) -> None:
    prefix = "sc/core/evm/codex/report_body/"
    prior = prefix + report_body_attempt_work_unit_id(prior_role, SHARD, prior_n)
    successor = prefix + report_body_attempt_work_unit_id(next_role, SHARD, next_n)
    assert registered_projection_handoff(
        prior, successor, "scratchpad:report_critical_high.md"
    ) is accepted
    assert not registered_projection_handoff(
        prior, successor, "scratchpad:report_medium.md"
    )


def test_absent_history_cannot_start_attempt_two(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    contract, _launch = _model(2)
    with pytest.raises(A.ArtifactLedgerError, match="only attempt 1"):
        require_report_body_attempt_authority(
            root, contract=contract, launch=_launch, run_id=RUN_ID,
        )


def test_long_failed_attempt_chain_is_iterative_and_structural_only() -> None:
    identity = f"scratchpad:{SHARD}.md"
    key_prefix = "sc/core/evm/codex/report_body"
    work_units = {}
    top_prestate = None
    prior_contract = None
    prior_launch = None
    for ordinal in range(1, 1201):
        contract, launch = _model(ordinal)
        if ordinal == 1:
            prestate = {
                "identity": identity,
                "status": "ABSENT",
                "existed": False,
                "sha256": "",
                "size": 0,
            }
        else:
            assert prior_contract is not None and prior_launch is not None
            prestate = {
                "identity": identity,
                "status": "AUTHORIZED_MODEL_RETRY_PRESTATE",
                "existed": True,
                "sha256": f"{ordinal - 1:064x}",
                "size": ordinal,
                "predecessor_owner_key": prior_contract.key,
                "predecessor_contract_digest": prior_contract.digest,
                "predecessor_launch_digest": prior_launch.digest,
            }
        prestates = {identity: prestate}
        work_units[contract.key] = {
            "schema": "plamen.artifact-work-unit.v2",
            "work_unit_key": contract.key,
            "run_id": RUN_ID,
            "semantic_status": "INPUTS_BOUND",
            "execution_state": "INPUTS_BOUND_PREEXECUTION",
            "artifacts": {},
            "contract_digest": contract.digest,
            "contract_manifest": contract.to_dict(),
            "launch_digest": launch.digest,
            "launch_manifest": launch.to_dict(),
            "output_prestates": prestates,
            "output_prestate_digest": A._output_prestate_digest(prestates),
        }
        top_prestate = prestate
        prior_contract, prior_launch = contract, launch
    ledger = {"work_units": work_units, "artifact_bindings": {}}
    assert top_prestate is not None
    assert all(
        unit["artifacts"] == {}
        and "execution_authority" not in unit
        and "commit_authority" not in unit
        for unit in work_units.values()
    )
    assert A._report_body_retry_prestate_chain_replays(
        ledger,
        top_prestate,
        identity=identity,
        run_id=RUN_ID,
        key_prefix=key_prefix,
        shard=SHARD,
        upper_ordinal=1200,
    )


def test_exact_next_uncommitted_retry_is_prestate_only(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root = project / ".scratchpad"
    root.mkdir(parents=True)
    _owned_inputs(root, project)
    first, first_launch = _model(1)
    A.record_work_unit_inputs(
        root, project, first, first_launch, run_id=RUN_ID,
    )
    (root / f"{SHARD}.md").write_bytes(b"uncommitted attempt one\n")

    second, second_launch = _model(2)
    selected = require_report_body_attempt_authority(
        root, contract=second, launch=second_launch, run_id=RUN_ID,
    )
    assert selected.ordinal == 2
    assert selected.predecessor_owner_key == first.key
    assert selected.resume_existing is False
    A.record_work_unit_inputs(
        root, project, second, second_launch, run_id=RUN_ID,
    )
    state = A.read_artifact_ledger(root)
    second_unit = state["work_units"][second.key]
    prestate = second_unit["output_prestates"][f"scratchpad:{SHARD}.md"]
    assert prestate["status"] == "AUTHORIZED_MODEL_RETRY_PRESTATE"
    assert prestate["predecessor_owner_key"] == first.key
    assert second_unit["artifacts"] == {}
    assert f"scratchpad:{SHARD}.md" not in state["artifact_bindings"]

    third, third_launch = _model(3)
    third_selected = require_report_body_attempt_authority(
        root, contract=third, launch=third_launch, run_id=RUN_ID,
    )
    assert third_selected.predecessor_owner_key == second.key
    A.record_work_unit_inputs(
        root, project, third, third_launch, run_id=RUN_ID,
    )
    third_unit = A.read_artifact_ledger(root)["work_units"][third.key]
    assert third_unit["output_prestates"][
        f"scratchpad:{SHARD}.md"
    ]["status"] == "AUTHORIZED_MODEL_RETRY_PRESTATE"
    assert third_unit["artifacts"] == {}

    fifth, fifth_launch = _model(5)
    with pytest.raises(A.ArtifactLedgerError, match="exact successor"):
        require_report_body_attempt_authority(
            root, contract=fifth, launch=fifth_launch, run_id=RUN_ID,
        )
