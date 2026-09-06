"""Attempt ordinals are owned by the append-only issuance history."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import artifact_ledger as L
from phase_io_contracts import ArtifactSpec, LaunchSpec, PhaseIOContract


RUN_ID = "12345678-1234-4234-8234-123456789abc"


def _contract() -> tuple[PhaseIOContract, LaunchSpec]:
    key = "sc/core/evm/claude/fixture/zero_input_driver"
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="claude",
        phase="fixture",
        work_unit_id="zero_input_driver",
        outputs=(
            ArtifactSpec(
                root="scratchpad",
                path="driver_output.md",
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="REPLACE",
            ),
        ),
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
    return contract, launch


def _first_commit(tmp_path: Path) -> tuple[Path, PhaseIOContract, LaunchSpec]:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    contract, launch = _contract()
    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    (scratch / "driver_output.md").write_text(
        "identical deterministic bytes\n", encoding="utf-8"
    )
    L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    return scratch, contract, launch


def _journal(scratch: Path) -> dict:
    return json.loads(
        (scratch / L._OUTPUT_AUTHORITY_LEDGER_NAME).read_text(
            encoding="utf-8"
        )
    )


def _attempts(scratch: Path, contract: PhaseIOContract) -> list[int]:
    return sorted(
        int(row["attempt_ordinal"])
        for row in _journal(scratch)["authorities"].values()
        if row.get("run_id") == RUN_ID
        and row.get("work_unit_key") == contract.key
    )


def _projection_snapshot(scratch: Path) -> tuple[bytes | None, tuple[tuple[str, bytes], ...]]:
    journal = scratch / L._OUTPUT_AUTHORITY_LEDGER_NAME
    cas = scratch / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
    return (
        journal.read_bytes() if journal.exists() else None,
        tuple(
            (entry.name, entry.read_bytes())
            for entry in sorted(cas.iterdir(), key=lambda row: row.name)
        )
        if cas.exists()
        else (),
    )


def _authority_for_scope(
    original: dict,
    *,
    attempt: int,
    run_id: str | None = None,
    work_unit_key: str | None = None,
    actor: str | None = None,
) -> dict:
    unsigned = {
        name: value
        for name, value in original.items()
        if name != "authority_digest"
    }
    unsigned["run_id"] = run_id or str(original["run_id"])
    unsigned["work_unit_key"] = (
        work_unit_key or str(original["work_unit_key"])
    )
    unsigned["attempt_ordinal"] = attempt
    unsigned["authority_key"] = L._output_authority_key(
        run_id=unsigned["run_id"],
        work_unit_key=unsigned["work_unit_key"],
        attempt_ordinal=attempt,
    )
    if actor is not None:
        unsigned["actor"] = actor
    return {
        **unsigned,
        "authority_digest": L._canonical_json_digest(unsigned),
    }


def _write_journal_row(scratch: Path, authority: dict) -> None:
    payload = _journal(scratch)
    payload["authorities"][authority["authority_key"]] = authority
    L._write_output_authority_ledger(scratch, payload)


def _write_cas_row(scratch: Path, authority: dict) -> Path:
    unsigned = {
        name: value
        for name, value in authority.items()
        if name != "authority_digest"
    }
    L._write_once_output_authority_cas(
        scratch,
        authority_digest=authority["authority_digest"],
        unsigned_authority=unsigned,
    )
    return (
        scratch
        / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f'{authority["authority_digest"]}.json'
    )


@pytest.mark.parametrize(
    "attack",
    [
        "name_add",
        "name_remove",
        "same_bytes_replace",
        "hardlink",
        "ads",
        "directory_swap",
        "ancestor_reparse",
    ],
)
def test_bound_cas_projection_rejects_namespace_and_identity_mutation(
    tmp_path: Path,
    monkeypatch,
    attack: str,
) -> None:
    scratch, _contract_value, _launch = _first_commit(tmp_path)
    cas_directory = scratch / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
    cas_path = next(cas_directory.glob("*.json"))
    real_read = L._read_stable_regular_bytes_in_bound_directory
    attacked = False

    def mutate_then_read(path: Path, **kwargs):
        nonlocal attacked
        if not attacked:
            attacked = True
            if attack == "name_add":
                (cas_directory / "unexpected").write_bytes(b"extra")
            elif attack == "name_remove":
                cas_path.unlink()
            elif attack == "same_bytes_replace":
                replacement = scratch / "same-bytes.tmp"
                replacement.write_bytes(cas_path.read_bytes())
                os.replace(replacement, cas_path)
            elif attack == "hardlink":
                os.link(cas_path, cas_directory / "hardlink-alias")
            elif attack == "ads":
                named = Path(str(cas_path) + ":attacker")
                try:
                    named.write_bytes(b"hidden")
                except OSError as exc:
                    pytest.skip(f"fixture volume has no named streams: {exc}")
            elif attack == "directory_swap":
                old = scratch / "cas-old"
                cas_directory.rename(old)
                cas_directory.mkdir()
                (cas_directory / cas_path.name).write_bytes(
                    (old / cas_path.name).read_bytes()
                )
            else:
                moved = tmp_path / "scratchpad-real"
                scratch.rename(moved)
                try:
                    os.symlink(moved, scratch, target_is_directory=True)
                except OSError as exc:
                    moved.rename(scratch)
                    pytest.skip(f"directory reparse fixture unavailable: {exc}")
        return real_read(path, **kwargs)

    monkeypatch.setattr(
        L,
        "_read_stable_regular_bytes_in_bound_directory",
        mutate_then_read,
    )
    with pytest.raises(L.ArtifactLedgerError):
        L._inspect_output_authority_cas_projection(scratch)


@pytest.mark.parametrize("damage", ["corrupt", "remove"])
def test_damaged_current_commit_never_reuses_valid_journal_attempt_one(
    tmp_path: Path, damage: str
) -> None:
    scratch, contract, launch = _first_commit(tmp_path)
    ledger = L.read_artifact_ledger(scratch)
    unit = ledger["work_units"][contract.key]
    if damage == "corrupt":
        unit["commit_authority"]["receipt_digest"] = "0" * 64
    else:
        unit.pop("commit_authority")
    L.write_artifact_ledger(scratch, ledger)

    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    replayed = L.read_artifact_ledger(scratch)["work_units"][contract.key]
    assert replayed["commit_authority"]["attempt_ordinal"] == 2
    assert replayed["semantic_status"] == "QUARANTINED"
    assert _attempts(scratch, contract) == [1, 2]


def test_corrupt_journal_fails_closed_instead_of_reusing_attempt_one(
    tmp_path: Path,
) -> None:
    scratch, contract, launch = _first_commit(tmp_path)
    ledger = L.read_artifact_ledger(scratch)
    ledger["work_units"][contract.key].pop("commit_authority")
    L.write_artifact_ledger(scratch, ledger)
    journal_path = scratch / L._OUTPUT_AUTHORITY_LEDGER_NAME
    payload = _journal(scratch)
    row = next(iter(payload["authorities"].values()))
    row["authority_digest"] = "0" * 64
    journal_path.write_text(json.dumps(payload), encoding="utf-8")

    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    with pytest.raises(L.ArtifactLedgerError):
        L.record_work_unit_artifacts(
            scratch,
            tmp_path,
            contract,
            launch,
            run_id=RUN_ID,
            actor="DRIVER",
        )

    assert L.read_artifact_ledger(scratch)["work_units"][contract.key][
        "semantic_status"
    ] == "ACTIVE"


def test_missing_journal_recovers_from_cas_and_consumes_attempt(
    tmp_path: Path,
) -> None:
    scratch, contract, launch = _first_commit(tmp_path)
    ledger = L.read_artifact_ledger(scratch)
    ledger["work_units"][contract.key].pop("commit_authority")
    L.write_artifact_ledger(scratch, ledger)
    (scratch / L._OUTPUT_AUTHORITY_LEDGER_NAME).unlink()

    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    replayed = L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert replayed["commit_authority"]["attempt_ordinal"] == 2
    assert replayed["semantic_status"] == "QUARANTINED"
    assert _attempts(scratch, contract) == [1, 2]


def test_missing_cas_recovers_from_journal_and_consumes_attempt(
    tmp_path: Path,
) -> None:
    scratch, contract, launch = _first_commit(tmp_path)
    first = next(iter(_journal(scratch)["authorities"].values()))
    first_cas = (
        scratch
        / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f'{first["authority_digest"]}.json'
    )
    first_cas.unlink()

    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    replayed = L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert replayed["commit_authority"]["attempt_ordinal"] == 2
    assert first_cas.is_file()
    assert _attempts(scratch, contract) == [1, 2]


def test_noncontiguous_journal_fails_closed(tmp_path: Path) -> None:
    scratch, contract, launch = _first_commit(tmp_path)
    # A clean ordinary replay allocates attempt 2.
    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )
    ledger = L.read_artifact_ledger(scratch)
    ledger["work_units"][contract.key].pop("commit_authority")
    L.write_artifact_ledger(scratch, ledger)
    payload = _journal(scratch)
    removed = next(
        row
        for row in payload["authorities"].values()
        if row["attempt_ordinal"] == 1
    )
    payload["authorities"] = {
        key: row
        for key, row in payload["authorities"].items()
        if row["attempt_ordinal"] != 1
    }
    (scratch / L._OUTPUT_AUTHORITY_LEDGER_NAME).write_text(
        json.dumps(payload), encoding="utf-8"
    )
    (
        scratch
        / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f'{removed["authority_digest"]}.json'
    ).unlink()

    with pytest.raises(L.ArtifactLedgerError):
        L.record_work_unit_artifacts(
            scratch,
            tmp_path,
            contract,
            launch,
            run_id=RUN_ID,
            actor="DRIVER",
        )


def test_identical_bytes_recommit_allocates_a_new_immutable_attempt(
    tmp_path: Path,
) -> None:
    scratch, contract, launch = _first_commit(tmp_path)

    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    replayed = L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert replayed["commit_authority"]["attempt_ordinal"] == 2
    assert _attempts(scratch, contract) == [1, 2]


@pytest.mark.parametrize("history", [None, [{"malformed": True}]])
def test_mutable_reexecution_history_cannot_reuse_a_journal_ordinal(
    tmp_path: Path, history: list[dict] | None
) -> None:
    scratch, contract, launch = _first_commit(tmp_path)
    ledger = L.read_artifact_ledger(scratch)
    unit = ledger["work_units"][contract.key]
    unit.pop("commit_authority")
    if history is None:
        unit.pop("semantic_reexecution_history", None)
    else:
        unit["semantic_reexecution_history"] = history
    L.write_artifact_ledger(scratch, ledger)

    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    replayed = L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert replayed["commit_authority"]["attempt_ordinal"] == 2
    assert replayed["semantic_status"] == "QUARANTINED"
    assert _attempts(scratch, contract) == [1, 2]


def test_cross_run_journal_does_not_allocate_current_run_attempt(tmp_path: Path) -> None:
    scratch, contract, _launch = _first_commit(tmp_path)
    fresh_ledger = L.read_artifact_ledger(scratch)

    assert L._attempt_ordinal_from_ledger(
        scratch, fresh_ledger, contract, run_id="other-run"
    ) == 1


def test_crash_after_cas_consumes_attempt_before_changed_bytes_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    contract, launch = _contract()
    L.record_work_unit_inputs(
        scratch, tmp_path, contract, launch, run_id=RUN_ID
    )
    output = scratch / "driver_output.md"
    output.write_text("first postimage\n", encoding="utf-8")
    real_write = L._write_output_authority_ledger

    def _crash_after_cas(*_args, **_kwargs) -> None:
        raise OSError("simulated crash after output-authority CAS")

    monkeypatch.setattr(
        L, "_write_output_authority_ledger", _crash_after_cas
    )
    with pytest.raises(OSError, match="after output-authority CAS"):
        L.record_work_unit_artifacts(
            scratch,
            tmp_path,
            contract,
            launch,
            run_id=RUN_ID,
            actor="DRIVER",
        )
    assert len(list(
        (scratch / L._OUTPUT_AUTHORITY_CAS_DIRECTORY).glob("*.json")
    )) == 1

    monkeypatch.setattr(L, "_write_output_authority_ledger", real_write)
    output.write_text("different retry postimage\n", encoding="utf-8")
    replayed = L.record_work_unit_artifacts(
        scratch,
        tmp_path,
        contract,
        launch,
        run_id=RUN_ID,
        actor="DRIVER",
    )

    assert replayed["commit_authority"]["attempt_ordinal"] == 2
    assert _attempts(scratch, contract) == [1, 2]


def test_rehashed_journal_and_second_cas_for_one_logical_attempt_fail_closed(
    tmp_path: Path,
) -> None:
    scratch, contract, _launch = _first_commit(tmp_path)
    payload = _journal(scratch)
    key, original = next(iter(payload["authorities"].items()))
    forged_unsigned = {
        name: value
        for name, value in original.items()
        if name != "authority_digest"
    }
    forged_unsigned["actor"] = "FORGED-REPLACEMENT"
    forged_digest = L._canonical_json_digest(forged_unsigned)
    L._write_once_output_authority_cas(
        scratch,
        authority_digest=forged_digest,
        unsigned_authority=forged_unsigned,
    )
    payload["authorities"][key] = {
        **forged_unsigned,
        "authority_digest": forged_digest,
    }
    L._write_output_authority_ledger(scratch, payload)

    with pytest.raises(
        L.ArtifactLedgerError,
        match="duplicate|bijection|logical",
    ):
        L._attempt_ordinal_from_ledger(
            scratch,
            L.read_artifact_ledger(scratch),
            contract,
            run_id=RUN_ID,
        )


@pytest.mark.parametrize(
    "damage",
    [
        "journal_only_gap",
        "cas_only_gap",
        "later_disagreement",
        "malformed_later_row",
        "invalid_scope_beside_repairable_scope",
    ],
)
def test_phase_a_rejection_preserves_journal_and_cas_bytes(
    tmp_path: Path, damage: str
) -> None:
    scratch, contract, _launch = _first_commit(tmp_path)
    original = next(iter(_journal(scratch)["authorities"].values()))
    gap = _authority_for_scope(original, attempt=3)

    if damage == "journal_only_gap":
        _write_journal_row(scratch, gap)
    elif damage == "cas_only_gap":
        _write_cas_row(scratch, gap)
    elif damage == "later_disagreement":
        repairable = _authority_for_scope(
            original,
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
        )
        _write_journal_row(scratch, repairable)
        original_cas = (
            scratch
            / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
            / f'{original["authority_digest"]}.json'
        )
        original_cas.unlink()
        _write_cas_row(
            scratch,
            _authority_for_scope(
                original,
                attempt=1,
                actor="FORGED-REPLACEMENT",
            ),
        )
    elif damage == "malformed_later_row":
        payload = _journal(scratch)
        payload["authorities"]["f" * 64] = {
            "schema": L._OUTPUT_AUTHORITY_SCHEMA,
            "authority_key": "f" * 64,
        }
        L._write_output_authority_ledger(scratch, payload)
    else:
        repairable = _authority_for_scope(
            original,
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            work_unit_key=f"{contract.key}/peer",
        )
        _write_journal_row(scratch, repairable)
        _write_journal_row(scratch, gap)

    before = _projection_snapshot(scratch)
    with pytest.raises(L.ArtifactLedgerError):
        L._reconcile_output_authority_history(scratch)
    assert _projection_snapshot(scratch) == before


def test_valid_one_sided_rows_recover_independently_across_scopes(
    tmp_path: Path,
) -> None:
    scratch, contract, _launch = _first_commit(tmp_path)
    original = next(iter(_journal(scratch)["authorities"].values()))
    journal_only = _authority_for_scope(
        original,
        attempt=1,
        run_id="other-run",
    )
    cas_only = _authority_for_scope(
        original,
        attempt=1,
        work_unit_key=f"{contract.key}/peer",
    )
    _write_journal_row(scratch, journal_only)
    _write_cas_row(scratch, cas_only)

    reconciled = L._reconcile_output_authority_history(scratch)

    assert reconciled["authorities"][journal_only["authority_key"]] == journal_only
    assert reconciled["authorities"][cas_only["authority_key"]] == cas_only
    assert (
        scratch
        / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f'{journal_only["authority_digest"]}.json'
    ).is_file()


@pytest.mark.parametrize("boundary", ["before", "after"])
def test_phase_b_cas_repair_recovers_across_injected_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    scratch, contract, _launch = _first_commit(tmp_path)
    original = next(iter(_journal(scratch)["authorities"].values()))
    cas_path = (
        scratch
        / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
        / f'{original["authority_digest"]}.json'
    )
    cas_path.unlink()
    real_write = L._write_once_output_authority_cas

    def _interrupt(*args, **kwargs) -> None:
        if boundary == "after":
            real_write(*args, **kwargs)
        raise OSError(f"crash {boundary} CAS repair publication")

    monkeypatch.setattr(L, "_write_once_output_authority_cas", _interrupt)
    with pytest.raises(OSError, match=f"crash {boundary}"):
        L._reconcile_output_authority_history(scratch)

    monkeypatch.setattr(L, "_write_once_output_authority_cas", real_write)
    reconciled = L._reconcile_output_authority_history(scratch)
    assert reconciled["authorities"][original["authority_key"]] == original
    assert cas_path.is_file()
    assert L._attempt_ordinal_from_ledger(
        scratch,
        L.read_artifact_ledger(scratch),
        contract,
        run_id=RUN_ID,
    ) == 2


@pytest.mark.parametrize("boundary", ["before", "after"])
def test_phase_b_journal_repair_recovers_across_injected_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    scratch, contract, _launch = _first_commit(tmp_path)
    original = next(iter(_journal(scratch)["authorities"].values()))
    (scratch / L._OUTPUT_AUTHORITY_LEDGER_NAME).unlink()
    real_write = L._write_output_authority_ledger

    def _interrupt(*args, **kwargs) -> None:
        if boundary == "after":
            real_write(*args, **kwargs)
        raise OSError(f"crash {boundary} journal repair publication")

    monkeypatch.setattr(L, "_write_output_authority_ledger", _interrupt)
    with pytest.raises(OSError, match=f"crash {boundary}"):
        L._reconcile_output_authority_history(scratch)

    monkeypatch.setattr(L, "_write_output_authority_ledger", real_write)
    reconciled = L._reconcile_output_authority_history(scratch)
    assert reconciled["authorities"][original["authority_key"]] == original
    assert L._attempt_ordinal_from_ledger(
        scratch,
        L.read_artifact_ledger(scratch),
        contract,
        run_id=RUN_ID,
    ) == 2


def test_phase_b_cas_repair_resumes_exact_staging_prefix(tmp_path: Path) -> None:
    scratch, _contract_value, _launch = _first_commit(tmp_path)
    original = next(iter(_journal(scratch)["authorities"].values()))
    digest = original["authority_digest"]
    cas_directory = scratch / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
    cas_path = cas_directory / f"{digest}.json"
    staging = cas_directory / f".{digest}.publishing.tmp"
    cas_path.unlink()
    unsigned = {
        name: value
        for name, value in original.items()
        if name != "authority_digest"
    }
    staging.write_bytes(L._canonical_json_bytes(unsigned))

    reconciled = L._reconcile_output_authority_history(scratch)

    assert reconciled["authorities"][original["authority_key"]] == original
    assert cas_path.is_file()
    assert not staging.exists()


def test_phase_b_cas_repair_retires_exact_linked_staging_prefix(
    tmp_path: Path,
) -> None:
    scratch, _contract_value, _launch = _first_commit(tmp_path)
    original = next(iter(_journal(scratch)["authorities"].values()))
    digest = original["authority_digest"]
    cas_directory = scratch / L._OUTPUT_AUTHORITY_CAS_DIRECTORY
    cas_path = cas_directory / f"{digest}.json"
    staging = cas_directory / f".{digest}.publishing.tmp"
    os.link(cas_path, staging)

    reconciled = L._reconcile_output_authority_history(scratch)

    assert reconciled["authorities"][original["authority_key"]] == original
    assert cas_path.is_file()
    assert not staging.exists()
    assert cas_path.stat().st_nlink == 1
