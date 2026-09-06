from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

from artifact_ledger import (
    ArtifactLedgerError,
    read_artifact_ledger,
    recover_quarantined_deterministic_work_unit_prestate,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    write_artifact_ledger,
)
from phase_io_contracts import (
    InputAuthorityRequirement,
    LaunchSpec,
    PhaseIOContract,
)
from test_program_facts_phase_io_contract import (
    CHECKPOINT_CAPTURE,
    CORE_INPUTS,
    METHODOLOGY_OUTPUTS,
    OUTPUTS,
    _claim_inputs,
    _commit_capture,
    _commit_checkpoint_capture,
    _expected_output_records,
    _launch,
    _resolve,
    _resolve_checkpoint_capture,
    _resolve_methodology_capture,
    _write_inputs,
)


def _commit_receipt_digest(receipt: dict[str, object]) -> str:
    unsigned = {
        key: value
        for key, value in receipt.items()
        if key != "receipt_digest"
    }
    return hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _rewrite_owned_artifact_rows(
    scratchpad: Path,
    *,
    work_unit_key: str,
    relative_path: str,
    raw: bytes,
) -> None:
    path = scratchpad / relative_path
    path.write_bytes(raw)
    metadata = path.stat()
    digest = hashlib.sha256(raw).hexdigest()
    identity = f"scratchpad:{relative_path}"
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][work_unit_key]
    unit["artifacts"][identity].update(
        sha256=digest,
        size=len(raw),
        mtime_ns=metadata.st_mtime_ns,
    )
    ledger["artifact_bindings"][identity].update(
        sha256=digest,
        size=len(raw),
        mtime_ns=metadata.st_mtime_ns,
    )
    ledger["artifacts"][relative_path].update(
        sha256=digest,
        size=len(raw),
        mtime_ns=metadata.st_mtime_ns,
    )
    write_artifact_ledger(scratchpad, ledger)


def _directory_reparse(link: Path, target: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode:
            pytest.skip(f"NTFS junction unavailable: {completed.stderr}")
    else:
        link.symlink_to(target, target_is_directory=True)


def test_program_facts_rejects_raw_input_output_hardlink_alias(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "raw-input-output-hardlink"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )

    os.link(
        scratchpad / CHECKPOINT_CAPTURE,
        scratchpad / OUTPUTS[0],
    )
    _write_inputs(scratchpad, OUTPUTS[1:])
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )

    assert os.path.samefile(
        scratchpad / CHECKPOINT_CAPTURE,
        scratchpad / OUTPUTS[0],
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert "INPUT_OUTPUT_PHYSICAL_ALIAS_CONFLICT" in unit[
        "commit_authority"
    ]["reason_codes"]
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )


def test_program_facts_contract_post_issue_mutation_is_rejected(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_inputs(scratchpad, CORE_INPUTS)
    contract = _resolve()
    launch = _launch(contract)
    object.__setattr__(contract, "input_authority_requirements", ())

    with pytest.raises(ArtifactLedgerError, match="authority|seal|mutat"):
        record_work_unit_inputs(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id="contract-object-mutation",
        )


def test_program_facts_exact_contract_to_dict_spoof_is_rejected(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    _write_inputs(scratchpad, CORE_INPUTS)
    contract = _resolve()
    launch = _launch(contract)
    issued_manifest = contract.to_dict()
    object.__setattr__(contract, "input_authority_requirements", ())
    object.__setattr__(
        contract,
        "to_dict",
        lambda: issued_manifest,
    )

    with pytest.raises(ArtifactLedgerError, match="authority|seal|mutat"):
        record_work_unit_inputs(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id="exact-contract-to-dict-spoof",
        )


def test_program_facts_launch_post_issue_mutation_is_rejected(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "launch-object-mutation"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve_methodology_capture()
    launch = _launch(contract)
    # Timeout remains structurally valid and is not rejected by the closed
    # model/tool profile alone.  The issuance seal must detect this mutation.
    object.__setattr__(launch, "timeout_s", launch.timeout_s + 1)

    with pytest.raises(ArtifactLedgerError, match="authority|seal|mutat"):
        record_work_unit_inputs(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id=run_id,
        )


def test_program_facts_contract_subclass_manifest_spoof_is_rejected(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    canonical = _resolve()

    class NarrowedContract(PhaseIOContract):
        def to_dict(self) -> dict[str, object]:
            return canonical.to_dict()

    spoof = NarrowedContract(
        pipeline=canonical.pipeline,
        mode=canonical.mode,
        ecosystem=canonical.ecosystem,
        backend=canonical.backend,
        phase=canonical.phase,
        work_unit_id=canonical.work_unit_id,
        outputs=(canonical.outputs[0],),
        immutable_inputs=(f"scratchpad:{CHECKPOINT_CAPTURE}",),
        model_invoked=False,
        input_authority_requirements=(
            InputAuthorityRequirement(
                identity=f"scratchpad:{CHECKPOINT_CAPTURE}",
                allow_raw=True,
                require_same_run=False,
                require_exact_contract=False,
                require_exact_launch=False,
            ),
        ),
        launch_profile="DRIVER_PYTHON_NO_TOOLS",
        required_commit_actor="DRIVER",
    )

    with pytest.raises(ArtifactLedgerError, match="exact|authority|type"):
        record_work_unit_inputs(
            scratchpad,
            tmp_path,
            spoof,
            _launch(canonical),
            run_id="contract-subclass-spoof",
        )


def test_program_facts_consistent_forged_producer_launch_is_quarantined(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "consistent-forged-producer-launch"
    capture, _capture_launch = _commit_capture(
        scratchpad, tmp_path, run_id=run_id
    )
    ledger = read_artifact_ledger(scratchpad)
    unit = ledger["work_units"][capture.key]
    fake_manifest = dict(unit["launch_manifest"])
    fake_manifest["timeout_s"] = int(fake_manifest["timeout_s"]) + 1
    fake_launch = LaunchSpec(
        work_unit_key=fake_manifest["work_unit_key"],
        pipeline=fake_manifest["pipeline"],
        mode=fake_manifest["mode"],
        ecosystem=fake_manifest["ecosystem"],
        backend=fake_manifest["backend"],
        model=fake_manifest["model"],
        timeout_s=fake_manifest["timeout_s"],
        exec_mode=fake_manifest["exec_mode"],
        tool_policy=tuple(fake_manifest["tool_policy"]),
        launch_version=fake_manifest["launch_version"],
    )
    fake_digest = fake_launch.digest
    unit["launch_manifest"] = fake_manifest
    unit["launch_digest"] = fake_digest
    commit = unit["commit_authority"]
    commit["launch_digest"] = fake_digest
    commit["receipt_digest"] = _commit_receipt_digest(commit)
    for path in METHODOLOGY_OUTPUTS:
        identity = f"scratchpad:{path}"
        unit["artifacts"][identity]["launch_digest"] = fake_digest
        ledger["artifact_bindings"][identity][
            "launch_digest"
        ] = fake_digest
        ledger["artifacts"][path]["launch_digest"] = fake_digest
    write_artifact_ledger(scratchpad, ledger)

    bake = _resolve()
    bake_launch = _launch(bake)
    armed = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS)
    committed = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
        actor="DRIVER",
    )

    assert armed["semantic_status"] == "INPUT_DEBT"
    assert committed["semantic_status"] == "QUARANTINED"
    assert "INPUT_EXPECTED_LAUNCH_MISMATCH" in committed[
        "commit_authority"
    ]["reason_codes"]


def test_program_facts_create_prestate_quarantines(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "create-prestate"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    (scratchpad / OUTPUTS[0]).write_bytes(b"pre-existing\n")
    contract = _resolve()
    launch = _launch(contract)
    armed = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS[1:])
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )

    assert armed["semantic_status"] == "INPUT_DEBT"
    assert unit["semantic_status"] == "QUARANTINED"
    assert "OUTPUT_PRESTATE_INVALID" in unit[
        "commit_authority"
    ]["reason_codes"]


def test_program_facts_live_foreign_physical_owner_quarantines(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "foreign-live-owner"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    _claim_inputs(
        scratchpad,
        tmp_path,
        ("foreign-owned.json",),
        run_id=run_id,
        writer="DRIVER",
    )
    os.link(
        scratchpad / "foreign-owned.json",
        scratchpad / OUTPUTS[0],
    )
    contract = _resolve()
    launch = _launch(contract)
    armed = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS[1:])
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )

    assert armed["semantic_status"] == "INPUT_DEBT"
    assert unit["semantic_status"] == "QUARANTINED"
    assert "OUTPUT_PHYSICAL_OWNER_CONFLICT" in unit[
        "commit_authority"
    ]["reason_codes"]


@pytest.mark.parametrize(
    ("pipeline", "ecosystem"),
    (
        ("sc", "evm"),
        ("sc", "solana"),
        ("sc", "soroban"),
        ("sc", "aptos"),
        ("sc", "sui"),
        ("l1", "go"),
        ("l1", "rust"),
        ("l1", "daml"),
    ),
)
def test_program_facts_native_is_registered_model_free_in_every_mode(
    pipeline: str,
    ecosystem: str,
) -> None:
    for mode in ("light", "core", "thorough"):
        capture = _resolve_methodology_capture(
            pipeline=pipeline,
            ecosystem=ecosystem,
            backend="native",
            mode=mode,
        )
        capture_launch = _launch(capture)
        bake = _resolve(
            pipeline=pipeline,
            ecosystem=ecosystem,
            backend="native",
            mode=mode,
        )
        bake_launch = _launch(bake)

        assert capture.model_invoked is False
        assert bake.model_invoked is False
        assert capture.launch_profile == "DRIVER_PYTHON_NO_TOOLS"
        assert bake.launch_profile == "DRIVER_PYTHON_NO_TOOLS"
        assert capture_launch.model == bake_launch.model == "driver"
        assert capture_launch.exec_mode == bake_launch.exec_mode == "python"
        assert capture_launch.tool_policy == bake_launch.tool_policy == ()
        requirements = {
            requirement.identity: requirement
            for requirement in bake.input_authority_requirements
            if not requirement.allow_raw
        }
        methodology = {
            identity: requirement
            for identity, requirement in requirements.items()
            if identity
            in {
                f"scratchpad:{path}"
                for path in METHODOLOGY_OUTPUTS
            }
        }
        assert set(methodology) == {
            f"scratchpad:{path}" for path in METHODOLOGY_OUTPUTS
        }
        assert {
            requirement.expected_producer_work_unit_key
            for requirement in methodology.values()
        } == {capture.key}
        assert {
            requirement.expected_launch_digest
            for requirement in methodology.values()
        } == {capture_launch.digest}
        checkpoint_capture = _resolve_checkpoint_capture(
            pipeline=pipeline,
            ecosystem=ecosystem,
            backend="native",
            mode=mode,
        )
        checkpoint_requirement = requirements[
            f"scratchpad:{CHECKPOINT_CAPTURE}"
        ]
        assert (
            checkpoint_requirement.expected_producer_work_unit_key
            == checkpoint_capture.key
        )
        assert (
            checkpoint_requirement.expected_launch_digest
            == _launch(checkpoint_capture).digest
        )


def test_post_arm_in_root_output_file_symlink_never_becomes_active(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "post-arm-file-symlink"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    target = scratchpad / "untracked-target.json"
    target.write_bytes(b'{"untracked":true}\n')
    try:
        (scratchpad / OUTPUTS[0]).symlink_to(target)
    except OSError as exc:
        pytest.skip(f"file symlink unavailable: {exc}")
    _write_inputs(scratchpad, OUTPUTS[1:])
    expected = _expected_output_records(scratchpad, contract)

    try:
        unit = record_work_unit_artifacts(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=expected,
        )
    except ArtifactLedgerError:
        return
    assert unit["semantic_status"] != "ACTIVE"
    assert unit["execution_state"] != "OUTPUT_COMMITTED"


@pytest.mark.parametrize("alias_kind", ("directory_symlink", "junction"))
def test_post_arm_output_directory_reparse_never_becomes_active(
    tmp_path: Path,
    alias_kind: str,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = f"post-arm-{alias_kind}"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve_methodology_capture()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    target = scratchpad / f"_{alias_kind}_target"
    target.mkdir()
    link = scratchpad / "_program_facts_methodology"
    try:
        if alias_kind == "junction":
            _directory_reparse(link, target)
        else:
            link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory alias unavailable: {exc}")
    _write_inputs(scratchpad, METHODOLOGY_OUTPUTS)
    expected = _expected_output_records(scratchpad, contract)

    try:
        unit = record_work_unit_artifacts(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=expected,
        )
    except ArtifactLedgerError:
        return
    assert unit["semantic_status"] != "ACTIVE"
    assert unit["execution_state"] != "OUTPUT_COMMITTED"


def test_alias_swap_during_stable_descriptor_open_never_becomes_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import artifact_ledger as ledger_module

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "descriptor-alias-swap"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    _write_inputs(scratchpad, OUTPUTS)
    victim = scratchpad / OUTPUTS[0]
    alias = scratchpad / "same-size-alias.json"
    alias.write_bytes(b"[]\n")
    victim.write_bytes(b"{}\n")
    expected = _expected_output_records(scratchpad, contract)
    original_open = ledger_module.os.open
    swapped = False

    def swap_on_open(file: object, flags: int, *args: object) -> int:
        nonlocal swapped
        candidate = Path(file) if isinstance(file, (str, bytes, os.PathLike)) else None
        try:
            targets_victim = bool(
                candidate is not None
                and os.path.samefile(candidate, victim)
            )
        except OSError:
            targets_victim = False
        if (
            not swapped
            and targets_victim
        ):
            swapped = True
            held = victim.with_name(".held-original.json")
            os.replace(victim, held)
            os.replace(alias, victim)
            descriptor = original_open(file, flags, *args)
            os.replace(victim, alias)
            os.replace(held, victim)
            return descriptor
        return original_open(file, flags, *args)

    monkeypatch.setattr(ledger_module.os, "open", swap_on_open)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=expected,
    )

    assert swapped
    assert unit["semantic_status"] != "ACTIVE"
    assert unit["execution_state"] != "OUTPUT_COMMITTED"


def test_self_consistent_methodology_ledger_rewrite_cannot_rebless_bytes(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "methodology-row-rewrite"
    capture, capture_launch = _commit_capture(
        scratchpad, tmp_path, run_id=run_id
    )
    _rewrite_owned_artifact_rows(
        scratchpad,
        work_unit_key=capture.key,
        relative_path=METHODOLOGY_OUTPUTS[0],
        raw=b'{"rewritten":true}\n',
    )

    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        capture,
        capture_launch,
        run_id=run_id,
        actor="DRIVER",
    )
    bake = _resolve()
    bake_launch = _launch(bake)
    armed = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
    )
    _write_inputs(scratchpad, OUTPUTS)
    committed = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=_expected_output_records(scratchpad, bake),
    )

    assert armed["semantic_status"] == "INPUT_DEBT"
    assert committed["semantic_status"] == "QUARANTINED"


def test_joint_sidecar_and_ledger_rewrite_cannot_replace_cas_authority(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "joint-sidecar-ledger-rewrite"
    capture, _capture_launch = _commit_capture(
        scratchpad, tmp_path, run_id=run_id
    )
    rewritten = b'{"joint_rewrite":true}\n'
    _rewrite_owned_artifact_rows(
        scratchpad,
        work_unit_key=capture.key,
        relative_path=METHODOLOGY_OUTPUTS[0],
        raw=rewritten,
    )
    authority_sidecar = (
        scratchpad / "_artifact_output_authorities.json"
    )
    if authority_sidecar.is_file():
        payload = json.loads(authority_sidecar.read_text(encoding="utf-8"))
        ledger = read_artifact_ledger(scratchpad)
        commit = ledger["work_units"][capture.key]["commit_authority"]
        authority = payload["authorities"][commit["output_authority_key"]]
        identity = f"scratchpad:{METHODOLOGY_OUTPUTS[0]}"
        digest = hashlib.sha256(rewritten).hexdigest()
        authority["expected_output_records"][identity] = {
            "sha256": digest,
            "size": len(rewritten),
        }
        authority["observed_outputs"][identity].update(
            sha256=digest,
            size=len(rewritten),
        )
        unsigned = {
            key: value
            for key, value in authority.items()
            if key != "authority_digest"
        }
        authority["authority_digest"] = hashlib.sha256(
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        authority_sidecar.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    bake = _resolve()
    bake_launch = _launch(bake)
    armed = record_work_unit_inputs(
        scratchpad,
        tmp_path,
        bake,
        bake_launch,
        run_id=run_id,
    )

    assert armed["semantic_status"] == "INPUT_DEBT"


def test_bake_without_expected_records_and_consistent_row_rewrite_stays_debt(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "bake-missing-authority-row-rewrite"
    _commit_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    _write_inputs(scratchpad, OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    _rewrite_owned_artifact_rows(
        scratchpad,
        work_unit_key=contract.key,
        relative_path=OUTPUTS[0],
        raw=b'{"rewritten":true}\n',
    )

    issues = validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    )
    assert unit["semantic_status"] == "QUARANTINED"
    assert "OUTPUT_COMMIT_AUTHORITY_REQUIRED" in unit[
        "commit_authority"
    ]["reason_codes"]
    assert issues


def test_recovery_rejects_missing_expected_output_records(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "recovery-missing-output-authority"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve_methodology_capture()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    _write_inputs(scratchpad, METHODOLOGY_OUTPUTS)
    unit = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        precommit_issues=("forced quarantine",),
        expected_output_records=_expected_output_records(
            scratchpad, contract
        ),
    )
    assert unit["semantic_status"] == "QUARANTINED"
    for relative in METHODOLOGY_OUTPUTS:
        (scratchpad / relative).unlink()
    ledger = read_artifact_ledger(scratchpad)
    commit = ledger["work_units"][contract.key]["commit_authority"]
    commit.pop("expected_output_records", None)
    commit["receipt_digest"] = _commit_receipt_digest(commit)
    write_artifact_ledger(scratchpad, ledger)

    with pytest.raises(
        ArtifactLedgerError,
        match="expected.output|output authority",
    ):
        recover_quarantined_deterministic_work_unit_prestate(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id=run_id,
        )


def test_orphaned_preledger_output_authority_replays_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import artifact_ledger as ledger_module

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    run_id = "orphaned-output-authority-resume"
    _commit_checkpoint_capture(scratchpad, tmp_path, run_id=run_id)
    contract = _resolve_methodology_capture()
    launch = _launch(contract)
    record_work_unit_inputs(
        scratchpad, tmp_path, contract, launch, run_id=run_id
    )
    _write_inputs(scratchpad, METHODOLOGY_OUTPUTS)
    expected = _expected_output_records(scratchpad, contract)
    original_commit = ledger_module._record_work_unit_artifacts_unlocked

    def crash_before_ledger_mutation(*args: object, **kwargs: object) -> object:
        raise RuntimeError("simulated crash after output authority issuance")

    monkeypatch.setattr(
        ledger_module,
        "_record_work_unit_artifacts_unlocked",
        crash_before_ledger_mutation,
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        record_work_unit_artifacts(
            scratchpad,
            tmp_path,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=expected,
        )
    prior = read_artifact_ledger(scratchpad)["work_units"][contract.key]
    assert prior["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert (scratchpad / "_artifact_output_authorities.json").is_file()
    assert any(
        (scratchpad / "_artifact_output_authority_cas").glob("*.json")
    )

    monkeypatch.setattr(
        ledger_module,
        "_record_work_unit_artifacts_unlocked",
        original_commit,
    )
    resumed = record_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=expected,
    )

    assert resumed["semantic_status"] == "ACTIVE"
    assert validate_work_unit_artifacts(
        scratchpad,
        tmp_path,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
    ) == []
