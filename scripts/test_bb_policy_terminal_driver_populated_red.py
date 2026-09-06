"""Populated-driver RED contracts for terminal BB policy reconciliation.

Unlike the pure contracts in ``test_bb_policy_terminal_reconciliation_red``,
these fixtures create a real mixed primary/recovery scratchpad and commit each
BB policy artifact through artifact-ledger/PhaseIO ownership.  Only provider
execution and unrelated audit construction are faked.  The production BB
enumerator, terminal compiler, PhaseIO transaction, resume path, and policy
semantics remain live.

Driver contract
===============

``_compile_bb_policy_terminal_reconciliation(scratchpad, config)`` must:

* derive the candidate denominator from
  ``load_current_report_candidate_universe_authority``;
* derive ``candidate_state_sha256`` from the complete current authority packet:
  queue work-item digest, any report-authoritative severity decision, and every
  non-severity-change recovery row that can determine current severity;
* use current authoritative severity, never stale projection prose;
* enumerate primary consumers from the committed runtime roster and recovery
  consumers from committed ``bb_policy/projection.<id>`` PhaseIO outputs;
* require exact co-rooted work/application/receipt ownership:
  DRIVER ``bb_policy/projection.<id>``, MODEL verifier method output, and
  DRIVER ``bb_policy/consumption.<id>`` respectively;
* treat a committed expected projection with no receipt as
  ``RETAIN_REQUEUE_REVIEW`` rather than omitting it;
* reject stale/cross-run/mutated committed bytes, wrong owners, extra
  committed consumers, and unledgered/orphan triples;
* write ``.bb/verification_policy_reconciliation.json`` in one
  DRIVER-owned PhaseIO transaction whose immutable inputs include the ingress,
  candidate authority, roster, and every accepted triple;
* replay byte-exactly without changing its output or commit authority.

The terminal evidence references bind the actual artifact bytes from disk.
They must not substitute the SHA-256 of a semantic reserialization for the
hash of the artifact that downstream users can open.

Current-severity policy drift uses a distinct additive recovery lane.  A mere
UNRESOLVED/PROPOSAL_ONLY policy application at the *same* severity remains
ordinary reconciliation debt and must not recursively mint a severity-change
recovery.  A real severity change uses recovery kind
``BB_POLICY_SEVERITY_CHANGE`` through the compiler-backed recovery contract;
it never mutates the primary verification queue.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path, PurePosixPath

import pytest

import artifact_ledger
import bb_verification_policy as BB
import plamen_driver as D
from artifact_ledger import (
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
)
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract
from post_verify_candidate_delta import (
    load_current_report_candidate_universe_authority,
)
from test_bb_primary_dynamic_verifier_driver import (
    NORMATIVE_SENTINEL,
    _application_for,
    _runtime_fixture,
)
from test_dynamic_verifier_runtime_integration_p0_ak import (
    _write_operator_application,
)
from test_verification_recovery_contract_p0_ai import _semantic_row
from test_verifier_output_receipt_runtime_p0_aj import (
    _ignore_poc_gate,
    _proposal_bytes,
    _verify_bytes,
)
from verification_recovery_contract import (
    build_verification_recovery_contract,
)


TERMINAL_PATH = PurePosixPath(
    ".bb/verification_policy_reconciliation.json"
)


def _canonical_bytes(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write_json(path: Path, payload: dict, *, compact: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (
        _canonical_bytes(payload) + b"\n"
        if compact
        else (
            json.dumps(payload, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    )
    path.write_bytes(raw)


def _launch_for(contract: PhaseIOContract, *, model: str) -> LaunchSpec:
    return LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model=model,
        timeout_s=60,
        exec_mode="python",
        tool_policy=("filesystem",),
    )


def _commit_fixture_artifact(
    *,
    scratchpad: Path,
    project_root: Path,
    config: dict,
    phase: str,
    work_unit_id: str,
    relative_path: str,
    payload: dict,
    writer: str,
    immutable_inputs: tuple[str, ...],
    compact: bool,
) -> None:
    owner = (
        f"{config['pipeline']}/{config['mode']}/{config['language']}/"
        f"{config['cli_backend']}/{phase}/{work_unit_id}"
    )
    contract = PhaseIOContract(
        pipeline=config["pipeline"],
        mode=config["mode"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        phase=phase,
        work_unit_id=work_unit_id,
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path=relative_path,
                owner_key=owner,
                artifact_class=(
                    "REQUIRED" if writer == "MODEL" else "DRIVER_GENERATED"
                ),
                writer=writer,
                write_mode="CREATE",
                schema_version="fixture.bb-policy-artifact.v1",
                minimum_gate="EXACT_FIXTURE_PHASEIO_BINDING",
            ),
        ),
        immutable_inputs=immutable_inputs,
        model_invoked=(writer == "MODEL"),
    )
    launch = _launch_for(
        contract, model=("fixture-model" if writer == "MODEL" else "driver")
    )
    record_work_unit_inputs(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=config["_run_id"],
    )
    _write_json(
        scratchpad / PurePosixPath(relative_path),
        payload,
        compact=compact,
    )
    record_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=config["_run_id"],
        actor=writer,
    )


def _run_primary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, object, object, dict]:
    scratchpad, phase, items, roster, unit, config = _runtime_fixture(
        tmp_path,
        pipeline="sc",
        backend="claude",
        with_bb=True,
    )
    by_id = {item.work_item_id: item for item in items}
    paths = D._dynamic_verifier_unit_paths(
        scratchpad, unit.work_unit_id
    )
    _commit_fixture_artifact(
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        config=config,
        phase="fixture_upstream",
        work_unit_id="bb_terminal_roster",
        relative_path=D._DYNAMIC_VERIFIER_ROSTER_NAME,
        payload=json.loads(roster.to_json()),
        writer="DRIVER",
        immutable_inputs=(),
        compact=False,
    )

    def fake_execute(_spec, **_kwargs):
        for work_id in unit.ordered_work_item_ids:
            (scratchpad / f"verify_{work_id}.md").write_bytes(
                _verify_bytes(work_id)
            )
            (
                scratchpad
                / f"verify_{work_id}.severity_proposal.json"
            ).write_bytes(_proposal_bytes(by_id[work_id]))
            _write_operator_application(
                scratchpad, unit.work_unit_id, work_id
            )
        work = json.loads(
            paths["bb_policy_work"].read_text(encoding="utf-8")
        )
        paths["bb_policy_application"].write_bytes(
            _canonical_bytes(_application_for(work)) + b"\n"
        )
        return 0

    monkeypatch.setattr(D, "_execute_dynamic_verifier_launch", fake_execute)
    _ignore_poc_gate(monkeypatch)
    assert D._run_dynamic_verifier_unit(
        phase, scratchpad, config, roster, unit
    ) == []
    return scratchpad, items[0], unit, config


def _bound_ingress(scratchpad: Path, config: dict) -> dict:
    expected = D.build_bb_policy_ingress_payload(
        config, driver_run_id=config["_run_id"]
    )
    assert expected is not None
    return D._load_bound_bb_policy_ingress(scratchpad, expected)


def _commit_recovery_triple(
    *,
    scratchpad: Path,
    config: dict,
    recovery_kind: str = "GENERIC_RECOVERY",
    severity: str = "high",
    include_application: bool = True,
    include_receipt: bool = True,
) -> dict[str, Path | dict]:
    ingress = _bound_ingress(scratchpad, config)
    recovery_row = _semantic_row(
        "H-01", evidence=f"bb-populated-{recovery_kind.lower()}"
    )
    recovery_row.update({
        "severity": severity,
        "source_work_item_id": "H-01",
        "source_identity": "bb-populated:H-01",
    })
    contract = build_verification_recovery_contract(
        run_id=config["_run_id"],
        recovery_kind=recovery_kind,
        rows=[recovery_row],
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        pipeline=config["pipeline"],
        ecosystem=config["language"],
        backend=config["cli_backend"],
        repo_root=Path(__file__).resolve().parent.parent,
    )
    consumer_id = str(contract["recovery_id"])
    directory = (
        scratchpad / "_verification_recovery" / consumer_id
    )
    contract_path = directory / "contract.json"
    work_path = directory / "bb_policy_work.json"
    application_path = directory / "bb_policy_application.json"
    receipt_path = directory / "bb_policy_consumption_receipt.json"
    contract_relative = contract_path.relative_to(scratchpad).as_posix()
    _commit_fixture_artifact(
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        config=config,
        phase="verify_recovery",
        work_unit_id=f"contract.{consumer_id.lower()}",
        relative_path=contract_relative,
        payload=contract,
        writer="DRIVER",
        immutable_inputs=(),
        compact=False,
    )
    work = D._expected_verify_recovery_bb_policy(
        scratchpad=scratchpad,
        config=config,
        contract=contract,
    )
    assert work is not None
    work_relative = work_path.relative_to(scratchpad).as_posix()
    projection_issues = D._record_p1dm_driver_transaction(
        scratchpad,
        config,
        phase_name="bb_policy",
        work_unit_id=f"projection.{consumer_id.lower()}",
        exact_inputs=(BB.LOCAL_INGRESS_PATH,),
        exact_outputs=(work_relative,),
        action=lambda: D._write_or_validate_bb_policy_json(
            work_path,
            work,
            validator=BB.validate_work_projection,
        ),
        validate=lambda: (
            ()
            if BB.validate_work_projection(
                json.loads(work_path.read_text(encoding="utf-8"))
            )
            == work
            else ("fixture recovery work drift",)
        ),
    )
    assert projection_issues == []

    application = _application_for(work)
    if include_application:
        application_relative = application_path.relative_to(
            scratchpad
        ).as_posix()
        _commit_fixture_artifact(
            scratchpad=scratchpad,
            project_root=Path(config["project_root"]),
            config=config,
            phase="verify_recovery",
            work_unit_id=f"method_model.{consumer_id.lower()}",
            relative_path=application_relative,
            payload=application,
            writer="MODEL",
            immutable_inputs=(f"scratchpad:{work_relative}",),
            compact=True,
        )

    receipt = BB.build_consumption_receipt(
        ingress,
        work_projection=work,
        proposal=application,
        launch_digest="8" * 64,
        method_dispatch_sha256="9" * 64,
        verifier_output_sha256="a" * 64,
        corroborations=(),
    )
    if include_receipt:
        assert include_application
        receipt_relative = receipt_path.relative_to(
            scratchpad
        ).as_posix()
        consumption_issues = D._record_p1dm_driver_transaction(
            scratchpad,
            config,
            phase_name="bb_policy",
            work_unit_id=f"consumption.{consumer_id.lower()}",
            exact_inputs=(
                work_relative,
                application_path.relative_to(scratchpad).as_posix(),
            ),
            exact_outputs=(receipt_relative,),
            action=lambda: D._write_or_validate_bb_policy_json(
                receipt_path,
                receipt,
                validator=BB.validate_consumption_receipt,
            ),
            validate=lambda: (
                ()
                if BB.validate_consumption_receipt(
                    json.loads(
                        receipt_path.read_text(encoding="utf-8")
                    )
                )
                == receipt
                else ("fixture recovery receipt drift",)
            ),
        )
        assert consumption_issues == []
    return {
        "consumer_id": consumer_id,
        "directory": directory,
        "contract_path": contract_path,
        "work_path": work_path,
        "application_path": application_path,
        "receipt_path": receipt_path,
        "contract": contract,
        "work": work,
        "application": application,
        "receipt": receipt,
    }


def _populated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, object, object, dict, dict[str, Path | dict]]:
    scratchpad, candidate, unit, config = _run_primary(
        tmp_path, monkeypatch
    )
    recovery = _commit_recovery_triple(
        scratchpad=scratchpad,
        config=config,
    )
    return scratchpad, candidate, unit, config, recovery


def _compile(
    scratchpad: Path,
    config: dict,
) -> dict:
    terminal = D._compile_bb_policy_terminal_reconciliation(
        scratchpad, config
    )
    assert terminal is not None
    return terminal


def _terminal_bytes(scratchpad: Path) -> bytes:
    return (scratchpad / TERMINAL_PATH).read_bytes()


def _primary_paths(scratchpad: Path, unit) -> dict[str, Path]:
    paths = D._dynamic_verifier_unit_paths(
        scratchpad, unit.work_unit_id
    )
    return {
        key: paths[key]
        for key in (
            "bb_policy_work",
            "bb_policy_application",
            "bb_policy_receipt",
        )
    }


def test_populated_driver_enumerates_exact_owned_primary_and_recovery_triples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, candidate, unit, config, recovery = _populated(
        tmp_path, monkeypatch
    )
    terminal = _compile(scratchpad, config)
    universe = load_current_report_candidate_universe_authority(
        scratchpad,
        run_id=config["_run_id"],
        project_root=Path(config["project_root"]),
    )
    assert len(universe.candidates) == 1
    bound = universe.candidates[0]
    assert bound.item.work_item_id == candidate.work_item_id == "H-01"
    recovery_contract = recovery["contract"]
    recovery_row = recovery_contract["rows"][0]
    severity_ledger_path = (
        scratchpad / D.SEVERITY_ADJUDICATION_SOURCE_LEDGER_NAME
    )
    severity_ledger = json.loads(
        severity_ledger_path.read_text(encoding="utf-8")
    )
    decision = next(
        row
        for row in severity_ledger["decisions"]
        if row["candidate_id"] == "H-01"
    )
    expected_candidate_state = {
        "candidate_id": "H-01",
        "current_severity": "high",
        "impact_ids": [],
        "queue_work_item_sha256": bound.item.digest,
        "severity_decision_sha256": decision["decision_digest"],
        "recovery_rows": [
            {
                "recovery_id": recovery_contract["recovery_id"],
                "contract_digest": recovery_contract["contract_digest"],
                "work_item_id": recovery_row["work_item_id"],
                "consumer_kind": "RECOVERY",
                "severity": "high",
            }
        ],
    }
    assert terminal["candidate_denominator"] == [
        {
            "candidate_id": "H-01",
            "current_severity": "high",
            "impact_ids": [],
            "candidate_state_sha256": _sha(
                _canonical_bytes(expected_candidate_state)
            ),
        }
    ]
    expected_ids = {
        unit.work_unit_id,
        recovery["consumer_id"],
    }
    assert {
        row["consumer_work_unit_id"]
        for row in terminal["expected_consumptions"]
    } == expected_ids
    expected_by_id = {
        row["consumer_work_unit_id"]: row
        for row in terminal["expected_consumptions"]
    }
    assert expected_by_id[unit.work_unit_id] == {
        "consumer_work_unit_id": unit.work_unit_id,
        "consumer_kind": "PRIMARY",
        "recovery_id": None,
        "work_items": [
            {
                "candidate_id": "H-01",
                "work_item_id": "H-01",
                "severity": "high",
                "impact_ids": [],
            }
        ],
    }
    assert expected_by_id[recovery["consumer_id"]] == {
        "consumer_work_unit_id": recovery["consumer_id"],
        "consumer_kind": "RECOVERY",
        "recovery_id": recovery["consumer_id"],
        "work_items": [
            {
                "candidate_id": "H-01",
                "work_item_id": "H-01",
                "severity": "high",
                "impact_ids": [],
            }
        ],
    }
    assert {
        row["consumer_work_unit_id"]
        for row in terminal["consumption_results"]
    } == expected_ids
    assert terminal["missing_consumption_ids"] == []
    assert terminal["candidate_results"][0][
        "reconciliation_state"
    ] == "RETAIN_REQUEUE_REVIEW"

    primary = _primary_paths(scratchpad, unit)
    paths = {
        unit.work_unit_id: (
            primary["bb_policy_work"],
            primary["bb_policy_application"],
            primary["bb_policy_receipt"],
        ),
        recovery["consumer_id"]: (
            recovery["work_path"],
            recovery["application_path"],
            recovery["receipt_path"],
        ),
    }
    ledger = read_artifact_ledger(scratchpad)
    for consumer_id, triple in paths.items():
        work_path, application_path, receipt_path = triple
        owned = [
            ledger["artifact_bindings"][
                "scratchpad:"
                + Path(path).relative_to(scratchpad).as_posix()
            ]
            for path in triple
        ]
        assert owned[0]["writer"] == "DRIVER"
        assert owned[0]["owner_key"].endswith(
            "/bb_policy/projection." + str(consumer_id).lower()
        )
        assert owned[1]["writer"] == "MODEL"
        assert owned[1]["owner_key"].endswith(
            "/method_model." + str(consumer_id).lower()
        )
        assert owned[2]["writer"] == "DRIVER"
        assert owned[2]["owner_key"].endswith(
            "/bb_policy/consumption." + str(consumer_id).lower()
        )
    for row in terminal["consumption_results"]:
        work_path, application_path, receipt_path = paths[
            row["consumer_work_unit_id"]
        ]
        assert row["work_projection_artifact_sha256"] == _sha(
            Path(work_path).read_bytes()
        )
        assert row["application_artifact_sha256"] == _sha(
            Path(application_path).read_bytes()
        )
        assert row["receipt_artifact_sha256"] == _sha(
            Path(receipt_path).read_bytes()
        )

    loaded = BB.validate_terminal_reconciliation(
        json.loads(_terminal_bytes(scratchpad)),
        expected_ingress_sha256=terminal["ingress_sha256"],
        expected_driver_run_id=config["_run_id"],
        expected_candidate_denominator_sha256=terminal[
            "candidate_denominator_sha256"
        ],
    )
    assert loaded == terminal
    terminal_identity = f"scratchpad:{TERMINAL_PATH.as_posix()}"
    owner = ledger["artifact_bindings"][terminal_identity]
    assert owner["writer"] == "DRIVER"
    assert owner["owner_key"].endswith(
        "/bb_policy/terminal_reconciliation"
    )
    work_unit = ledger["work_units"][owner["owner_key"]]
    exact_inputs = set(work_unit["input_bindings"])
    assert f"scratchpad:{BB.LOCAL_INGRESS_PATH}" in exact_inputs
    for relative in (
        "verification_queue.md",
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
        D._DYNAMIC_VERIFIER_ROSTER_NAME,
    ):
        assert "scratchpad:" + relative in exact_inputs
    assert (
        "scratchpad:" + D.SEVERITY_ADJUDICATION_SOURCE_LEDGER_NAME
    ) in exact_inputs
    for triple in paths.values():
        for path in triple:
            assert (
                "scratchpad:"
                + Path(path).relative_to(scratchpad).as_posix()
            ) in exact_inputs
    assert (
        "scratchpad:"
        + Path(recovery["contract_path"])
        .relative_to(scratchpad)
        .as_posix()
    ) in exact_inputs


def test_populated_terminal_resume_is_byte_and_commit_authority_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    first = _compile(scratchpad, config)
    first_bytes = _terminal_bytes(scratchpad)
    first_ledger = read_artifact_ledger(scratchpad)
    owner_key = first_ledger["artifact_bindings"][
        f"scratchpad:{TERMINAL_PATH.as_posix()}"
    ]["owner_key"]
    first_authority = copy.deepcopy(
        first_ledger["work_units"][owner_key]
    )

    second = _compile(scratchpad, config)
    second_ledger = read_artifact_ledger(scratchpad)
    assert second == first
    assert _terminal_bytes(scratchpad) == first_bytes
    assert second_ledger["work_units"][owner_key] == first_authority


@pytest.mark.parametrize("consumer_kind", ["SKEPTIC", "REPORT"])
def test_populated_downstream_projection_contains_actual_refs_not_policy_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    consumer_kind: str,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    terminal = _compile(scratchpad, config)
    projection = BB.build_downstream_reconciliation_projection(
        terminal, consumer_kind=consumer_kind
    )
    assert projection["consumer_kind"] == consumer_kind
    assert projection["reconciliation_sha256"] == terminal[
        "reconciliation_sha256"
    ]
    assert projection["evidence_refs"]
    for ref in projection["evidence_refs"]:
        path = scratchpad / PurePosixPath(ref["artifact"])
        assert ref["artifact_sha256"] == _sha(path.read_bytes())
        assert set(ref) == {
            "artifact", "artifact_sha256", "evidence_id"
        }
    encoded = json.dumps(projection, sort_keys=True)
    assert NORMATIVE_SENTINEL not in encoded
    assert "normative_text" not in encoded
    assert "operator_projection" not in encoded
    ledger = read_artifact_ledger(scratchpad)
    owner = ledger["artifact_bindings"][
        f"scratchpad:{TERMINAL_PATH.as_posix()}"
    ]
    contract = ledger["work_units"][owner["owner_key"]][
        "contract_manifest"
    ]
    output = contract["outputs"][0]
    assert set(output["consumers"]) == {
        "bb_policy/severity_reverification",
        "bb_policy/downstream.skeptic",
        "bb_policy/downstream.report",
    }


def test_committed_recovery_projection_without_receipt_is_visible_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    partial = _commit_recovery_triple(
        scratchpad=scratchpad,
        config=config,
        recovery_kind="RESUME_QUEUE_DROPOUT",
        include_application=True,
        include_receipt=False,
    )
    terminal = _compile(scratchpad, config)
    partial_id = partial["consumer_id"]
    assert partial_id in {
        row["consumer_work_unit_id"]
        for row in terminal["expected_consumptions"]
    }
    assert terminal["missing_consumption_ids"] == [
        partial_id
    ]
    candidate = terminal["candidate_results"][0]
    assert candidate["reconciliation_state"] == "RETAIN_REQUEUE_REVIEW"
    assert candidate["requeue_required"] is True
    assert candidate["human_review_required"] is True


@pytest.mark.parametrize(
    "artifact_kind",
    ["work_path", "application_path", "receipt_path"],
)
def test_mutated_committed_triple_is_rejected_without_terminal_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    artifact_kind: str,
) -> None:
    scratchpad, _candidate, _unit, config, recovery = _populated(
        tmp_path, monkeypatch
    )
    _compile(scratchpad, config)
    before = _terminal_bytes(scratchpad)
    path = Path(recovery[artifact_kind])
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(BB.BBVerificationPolicyError):
        _compile(scratchpad, config)
    assert _terminal_bytes(scratchpad) == before


@pytest.mark.parametrize(
    "orphan_shape",
    ["triple", "application_only", "receipt_only"],
)
def test_unledgered_orphan_bb_artifacts_are_rejected_not_adopted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    orphan_shape: str,
) -> None:
    scratchpad, _candidate, _unit, config, recovery = _populated(
        tmp_path, monkeypatch
    )
    _compile(scratchpad, config)
    before = _terminal_bytes(scratchpad)
    orphan = (
        scratchpad
        / "_verification_recovery"
        / "VREC-orphan-0001"
    )
    orphan.mkdir(parents=True)
    names = {
        "work_path": "bb_policy_work.json",
        "application_path": "bb_policy_application.json",
        "receipt_path": "bb_policy_consumption_receipt.json",
    }
    selected = (
        tuple(names)
        if orphan_shape == "triple"
        else (
            ("application_path",)
            if orphan_shape == "application_only"
            else ("receipt_path",)
        )
    )
    for key in selected:
        (orphan / names[key]).write_bytes(
            Path(recovery[key]).read_bytes()
        )
    with pytest.raises(BB.BBVerificationPolicyError):
        _compile(scratchpad, config)
    assert _terminal_bytes(scratchpad) == before


def test_ledger_owner_mutation_is_rejected_without_terminal_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _candidate, _unit, config, recovery = _populated(
        tmp_path, monkeypatch
    )
    _compile(scratchpad, config)
    before = _terminal_bytes(scratchpad)
    ledger_path = scratchpad / artifact_ledger.LEDGER_NAME
    payload = json.loads(ledger_path.read_text(encoding="utf-8"))
    identity = (
        "scratchpad:"
        + Path(recovery["receipt_path"]).relative_to(
            scratchpad
        ).as_posix()
    )
    payload["artifact_bindings"][identity][
        "owner_key"
    ] = "sc/thorough/evm/claude/report/forged-owner"
    _write_json(ledger_path, payload)
    with pytest.raises(BB.BBVerificationPolicyError):
        _compile(scratchpad, config)
    assert _terminal_bytes(scratchpad) == before


def test_candidate_authority_mutation_is_rejected_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    _compile(scratchpad, config)
    before = _terminal_bytes(scratchpad)
    candidate_authority = (
        scratchpad / "verification_queue.work_items.json"
    )
    candidate_authority.write_bytes(
        candidate_authority.read_bytes() + b" "
    )
    with pytest.raises(BB.BBVerificationPolicyError):
        _compile(scratchpad, config)
    assert _terminal_bytes(scratchpad) == before


def test_same_severity_policy_debt_does_not_mint_severity_change_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    terminal = _compile(scratchpad, config)
    assert terminal["candidate_results"][0][
        "reconciliation_state"
    ] == "RETAIN_REQUEUE_REVIEW"
    ingress = _bound_ingress(scratchpad, config)
    queue_before = {
        path.name: path.read_bytes()
        for path in scratchpad.glob("verification_queue*")
        if path.is_file()
    }
    plan = BB.build_severity_reverification_plan(
        ingress,
        candidate_denominator=terminal["candidate_denominator"],
        reconciliation=terminal,
    )
    assert plan["obligations"] == []
    queue_after = {
        path.name: path.read_bytes()
        for path in scratchpad.glob("verification_queue*")
        if path.is_file()
    }
    assert queue_after == queue_before


def test_real_severity_change_kind_roundtrips_through_recovery_compiler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratchpad, _candidate, _unit, config, _recovery = _populated(
        tmp_path, monkeypatch
    )
    terminal = _compile(scratchpad, config)
    ingress = _bound_ingress(scratchpad, config)
    changed_candidates = copy.deepcopy(
        terminal["candidate_denominator"]
    )
    changed_candidates[0]["current_severity"] = "critical"
    changed_candidates[0]["candidate_state_sha256"] = hashlib.sha256(
        (
            changed_candidates[0]["candidate_state_sha256"]
            + ":critical"
        ).encode("utf-8")
    ).hexdigest()
    records = []
    for row in terminal["consumption_results"]:
        records.append({
            "consumer_work_unit_id": row["consumer_work_unit_id"],
            "consumer_kind": row["consumer_kind"],
            "recovery_id": row["recovery_id"],
            "work_projection_artifact": row[
                "work_projection_artifact"
            ],
            "work_projection_artifact_sha256": row[
                "work_projection_artifact_sha256"
            ],
            "application_artifact": row["application_artifact"],
            "application_artifact_sha256": row[
                "application_artifact_sha256"
            ],
            "receipt_artifact": row["receipt_artifact"],
            "receipt_artifact_sha256": row[
                "receipt_artifact_sha256"
            ],
            "work_projection": json.loads(
                (
                    scratchpad
                    / PurePosixPath(row["work_projection_artifact"])
                ).read_text(encoding="utf-8")
            ),
            "application": json.loads(
                (
                    scratchpad
                    / PurePosixPath(row["application_artifact"])
                ).read_text(encoding="utf-8")
            ),
            "receipt": json.loads(
                (
                    scratchpad
                    / PurePosixPath(row["receipt_artifact"])
                ).read_text(encoding="utf-8")
            ),
        })
    artifact_bytes = {
        str(row[field]): (
            scratchpad / PurePosixPath(str(row[field]))
        ).read_bytes()
        for row in terminal["consumption_results"]
        for field in (
            "work_projection_artifact",
            "application_artifact",
            "receipt_artifact",
        )
    }
    drifted = BB.build_terminal_reconciliation(
        ingress,
        candidate_denominator=changed_candidates,
        expected_consumptions=terminal["expected_consumptions"],
        consumption_records=records,
        artifact_bytes_by_path=artifact_bytes,
    )
    plan = BB.build_severity_reverification_plan(
        ingress,
        candidate_denominator=changed_candidates,
        reconciliation=drifted,
    )
    assert len(plan["obligations"]) == 1
    assert D._bb_policy_recovery_consumer_kind(
        "BB_POLICY_SEVERITY_CHANGE"
    ) == "BB_POLICY_SEVERITY_CHANGE"

    queue_before = {
        path.name: path.read_bytes()
        for path in scratchpad.glob("verification_queue*")
        if path.is_file()
    }
    severity_recovery_row = _semantic_row(
        "H-01", evidence="bb-real-severity-change"
    )
    severity_recovery_row.update({
        "severity": "Critical",
        "source_work_item_id": "H-01",
        "source_identity": "bb-severity-change:H-01",
    })
    contract = build_verification_recovery_contract(
        run_id=config["_run_id"],
        recovery_kind="BB_POLICY_SEVERITY_CHANGE",
        rows=[severity_recovery_row],
        scratchpad=scratchpad,
        project_root=Path(config["project_root"]),
        pipeline="sc",
        ecosystem="evm",
        backend="claude",
        repo_root=Path(__file__).resolve().parent.parent,
    )
    work = D._expected_verify_recovery_bb_policy(
        scratchpad=scratchpad,
        config=config,
        contract=contract,
    )
    assert work is not None
    assert work["consumer_kind"] == "BB_POLICY_SEVERITY_CHANGE"
    assert work["consumer_work_unit_id"] == contract["recovery_id"]
    assert work["work_items"][0]["severity"] == "critical"
    queue_after = {
        path.name: path.read_bytes()
        for path in scratchpad.glob("verification_queue*")
        if path.is_file()
    }
    assert queue_after == queue_before
