from __future__ import annotations

import hashlib
from pathlib import Path

import artifact_ledger as ledger_api
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


BASE = {
    "pipeline": "sc",
    "mode": "thorough",
    "ecosystem": "evm",
    "backend": "claude",
}
RUN_ID = "run-auxiliary-publication"
INTENT_FIELD = "auxiliary_publication_intent_digest"
AUTHORITY_FIELD = "auxiliary_publication_authority_digest"


def _authorities() -> dict[str, str]:
    return {
        INTENT_FIELD: hashlib.sha256(b"publication intent").hexdigest(),
        AUTHORITY_FIELD: hashlib.sha256(b"publication authority").hexdigest(),
    }


def _contract_and_launch() -> tuple[PhaseIOContract, LaunchSpec]:
    key = "sc/thorough/evm/claude/recon/prepass.attempt-0002"
    contract = PhaseIOContract(
        **BASE,
        phase="recon",
        work_unit_id="prepass.attempt-0002",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="auxiliary-publication.json",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
        model_invoked=False,
        required_commit_actor="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        **BASE,
        model="driver",
        timeout_s=30,
        exec_mode="python",
    )
    return contract, launch


def _arm_metadata(
    scratchpad: Path,
    project_root: Path,
    *,
    extra: dict[str, str] | None = None,
) -> tuple[PhaseIOContract, LaunchSpec, dict[str, str]]:
    contract, launch = _contract_and_launch()
    ledger_api.record_work_unit_inputs(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=RUN_ID,
    )
    authority = _authorities()
    before = ledger_api.read_artifact_ledger(scratchpad)
    expected_digest = ledger_api.artifact_ledger_digest(before)

    def attach(ledger: dict[str, object]) -> None:
        unit = ledger["work_units"][contract.key]
        unit.update(authority)
        unit.update(extra or {})

    ledger_api.compare_and_swap_artifact_ledger(
        scratchpad,
        expected_digest=expected_digest,
        mutator=attach,
    )
    return contract, launch, authority


def _commit_with_metadata(
    tmp_path: Path,
) -> tuple[Path, PhaseIOContract, LaunchSpec, dict[str, str]]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    contract, launch, authority = _arm_metadata(
        scratchpad,
        tmp_path,
        extra={
            "arbitrary_caller_metadata": "must not survive",
            "auxiliary_publication_unregistered_digest": "f" * 64,
        },
    )
    (scratchpad / "auxiliary-publication.json").write_text(
        '{"state":"published"}\n',
        encoding="utf-8",
    )
    committed = ledger_api.record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    assert committed["execution_state"] == "OUTPUT_COMMITTED"
    return scratchpad, contract, launch, authority


def test_registered_metadata_survives_generic_commit_and_terminal_replay(
    tmp_path: Path,
) -> None:
    scratchpad, contract, launch, authority = _commit_with_metadata(tmp_path)
    # Simulate process loss immediately after the generic ledger commit: use
    # only the freshly persisted terminal row for recovery validation.
    unit = ledger_api.read_artifact_ledger(scratchpad)["work_units"][
        contract.key
    ]
    commit = unit["commit_authority"]
    for field, expected in authority.items():
        assert unit[field] == expected
        assert commit[field] == expected
    assert commit["receipt_digest"] == ledger_api._commit_receipt_digest(commit)
    assert "arbitrary_caller_metadata" not in unit
    assert "arbitrary_caller_metadata" not in commit
    assert "auxiliary_publication_unregistered_digest" not in unit
    assert "auxiliary_publication_unregistered_digest" not in commit
    assert ledger_api.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    ) == []


def test_metadata_mutation_breaks_terminal_commit_authority(
    tmp_path: Path,
) -> None:
    scratchpad, contract, launch, _authority = _commit_with_metadata(tmp_path)
    ledger = ledger_api.read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][contract.key]
    unit[INTENT_FIELD] = "0" * 64
    ledger_api.write_artifact_ledger(scratchpad, ledger)

    issues = ledger_api.validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    assert any("active producer authority does not replay" in row for row in issues)


def test_commit_receipt_digest_covers_registered_metadata(tmp_path: Path) -> None:
    scratchpad, contract, _launch, _authority = _commit_with_metadata(tmp_path)
    unit = ledger_api.read_artifact_ledger(scratchpad)["work_units"][
        contract.key
    ]
    commit = unit["commit_authority"]
    original_receipt_digest = commit["receipt_digest"]
    commit[AUTHORITY_FIELD] = "0" * 64
    assert ledger_api._commit_receipt_digest(commit) != original_receipt_digest


def test_one_sided_registered_metadata_cannot_commit_active(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    contract, launch = _contract_and_launch()
    ledger_api.record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
    )
    before = ledger_api.read_artifact_ledger(scratchpad)

    def attach_one_side(ledger: dict[str, object]) -> None:
        ledger["work_units"][contract.key][INTENT_FIELD] = "1" * 64

    ledger_api.compare_and_swap_artifact_ledger(
        scratchpad,
        expected_digest=ledger_api.artifact_ledger_digest(before),
        mutator=attach_one_side,
    )
    (scratchpad / "auxiliary-publication.json").write_text(
        '{}\n', encoding="utf-8"
    )
    committed = ledger_api.record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    assert committed["execution_state"] == "OUTPUT_QUARANTINED"
    assert "REGISTERED_INPUT_BOUND_COMMIT_METADATA_INVALID" in committed[
        "commit_authority"
    ]["reason_codes"]
    assert INTENT_FIELD not in committed
    assert AUTHORITY_FIELD not in committed
