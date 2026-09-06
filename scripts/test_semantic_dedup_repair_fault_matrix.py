"""Adversarial crash/replay matrix for committed semantic-dedup repair.

These tests deliberately stay below the LLM and parser layers.  They prove
that repair is an exact replay of an already committed five-output
generation, and that damaged repair metadata or private authority never
becomes permission to publish bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

import plamen_driver as DRIVER
from artifact_ledger import (
    read_artifact_ledger,
    write_artifact_ledger,
)
from semantic_dedup_transaction import (
    INVENTORY,
    OUTPUTS,
    REPAIR_FAILPOINTS,
    REPAIR_PENDING,
    ROOT,
    SemanticDedupTransactionError,
    repair_committed_semantic_dedup_transaction,
)
from test_l1_semantic_dedup_prequeue_transaction_red import (
    RUN_ID as DRIVER_RUN_ID,
    ROOT_OUTPUT_NAMES,
    _required_apply,
    _seed,
)
from test_semantic_dedup_transaction_core import (
    PHASE,
    RUN,
    _fixture,
    _generation,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _repair_arm_authority(
    request: Any,
    pending: Mapping[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "schema_version": (
            "plamen.exact_committed_output_repair_arm_authority.v1"
        ),
        "state": "ARMED",
        "run_id": request.run_id,
        "phase": request.phase,
        "generation_digest": request.generation_digest,
        "intent_sha256": request.intent_sha256,
        "authority_binding_sha256": _sha(
            _canonical(request.authority_binding)
        ),
        "transaction_receipt_sha256": pending[
            "transaction_receipt_sha256"
        ],
        "repair_pending_sha256": pending["repair_pending_sha256"],
        "work_unit_key": "test:l1:semantic-dedup:prequeue-apply",
        "contract_digest": "c" * 64,
        "launch_digest": "d" * 64,
        "observed_outputs": dict(pending["observed_outputs"]),
        "target_outputs": dict(pending["target_outputs"]),
        "output_identities": sorted(
            f"scratchpad:{relative}" for relative in OUTPUTS
        ),
    }
    return {
        **unsigned,
        "authority_digest": _sha(_canonical(unsigned)),
    }


def _repair_finalize_authority(
    request: Any,
    pending: Mapping[str, Any],
) -> dict[str, Any]:
    arm = _repair_arm_authority(request, pending)
    unsigned = {
        "schema_version": (
            "plamen.exact_committed_output_repair_finalize_authority.v1"
        ),
        "state": "REPAIRED_ACTIVE",
        "run_id": request.run_id,
        "phase": request.phase,
        "generation_digest": request.generation_digest,
        "transaction_receipt_sha256": pending[
            "transaction_receipt_sha256"
        ],
        "repair_pending_sha256": pending["repair_pending_sha256"],
        "work_unit_key": "test:l1:semantic-dedup:prequeue-apply",
        "contract_digest": "c" * 64,
        "launch_digest": "d" * 64,
        "repair_arm_authority_digest": arm["authority_digest"],
        "restored_outputs": {
            f"scratchpad:{relative}": {}
            for relative in OUTPUTS
        },
    }
    return {
        **unsigned,
        "authority_digest": _sha(_canonical(unsigned)),
    }


def _commit_then_damage(
    root: Path,
    *,
    output: str = INVENTORY,
    delete: bool = False,
) -> tuple[dict[str, Any], dict[str, bytes], bytes]:
    kwargs, authority = _fixture(root)
    committed = DRIVER.apply_semantic_dedup_transaction(**kwargs)
    assert committed.safe_to_consume is True
    expected = dict(authority.expected_outputs)
    path = root / output
    original = path.read_bytes()
    if delete:
        path.unlink()
        assert not path.exists()
    else:
        path.write_bytes(b"UNAUTHENTICATED THIRD STATE\n" + original[:7])
        assert path.read_bytes() != original
    return kwargs, expected, original


def _repair(
    root: Path,
    kwargs: Mapping[str, Any],
    *,
    run_id: str = RUN,
    phase: str = PHASE,
    authority_binding: Mapping[str, Any] | None = None,
    repair_arm_authority=_repair_arm_authority,
    repair_finalize_authority=_repair_finalize_authority,
    fault_hook=None,
):
    return repair_committed_semantic_dedup_transaction(
        scratchpad=root,
        run_id=run_id,
        phase=phase,
        authority_binding=(
            kwargs["authority_binding"]
            if authority_binding is None
            else authority_binding
        ),
        authority=kwargs["authority"],
        repair_arm_authority=repair_arm_authority,
        repair_finalize_authority=repair_finalize_authority,
        fault_hook=fault_hook,
    )


def _root_snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        relative: (
            (root / relative).read_bytes()
            if (root / relative).is_file()
            else None
        )
        for relative in OUTPUTS
    }


def _make_symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (NotImplementedError, OSError) as exc:
        pytest.skip(
            f"host does not permit symlink fixture: {type(exc).__name__}: {exc}"
        )
    assert link.is_symlink()


def _driver_repaired_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, dict[str, Any], dict[str, bytes], Mapping[str, Any]]:
    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=DRIVER_RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    expected = {
        name: (scratchpad / name).read_bytes()
        for name in ROOT_OUTPUT_NAMES
    }
    (scratchpad / INVENTORY).write_bytes(b"FIRST DAMAGED INVENTORY\n")
    repaired = DRIVER._ensure_l1_prequeue_successor_for_downstream(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=DRIVER_RUN_ID,
        downstream_phase="rag_sweep",
    )
    assert repaired["safe_to_consume"] is True
    assert repaired["repaired"] is True
    assert repaired["repair_receipt_path"]
    return project, scratchpad, config, expected, repaired


def _repair_unit(
    ledger: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    matches = [
        (str(key), unit)
        for key, unit in (ledger.get("work_units") or {}).items()
        if isinstance(unit, dict)
        and unit.get("committed_output_repair_history")
    ]
    assert len(matches) == 1
    return matches[0]


def _assert_driver_quarantine_without_public_mutation(
    *,
    project: Path,
    scratchpad: Path,
    config: Mapping[str, Any],
) -> Mapping[str, Any]:
    before = _root_snapshot(scratchpad)
    result = DRIVER._ensure_l1_prequeue_successor_for_downstream(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=DRIVER_RUN_ID,
        downstream_phase="rag_sweep",
    )
    assert result["safe_to_consume"] is False
    assert result["repaired"] is False
    assert result["state"] == "QUARANTINED"
    assert result["issues"]
    assert _root_snapshot(scratchpad) == before
    return result


@pytest.mark.parametrize("failpoint", REPAIR_FAILPOINTS)
def test_every_repair_fault_boundary_resumes_to_exact_committed_postimages(
    tmp_path: Path,
    failpoint: str,
) -> None:
    kwargs, expected, _ = _commit_then_damage(tmp_path)
    fired = False

    def fault(name: str) -> None:
        nonlocal fired
        if name == failpoint and not fired:
            fired = True
            raise RuntimeError(f"repair-fault:{name}")

    with pytest.raises(RuntimeError, match="repair-fault:"):
        _repair(tmp_path, kwargs, fault_hook=fault)
    assert fired

    resumed = _repair(tmp_path, kwargs)
    assert resumed.safe_to_consume is True
    assert resumed.state in {"RECOVERED", "ALREADY_RECOVERED"}
    assert not (tmp_path / REPAIR_PENDING).exists()
    for relative, raw in expected.items():
        assert (tmp_path / relative).read_bytes() == raw


@pytest.mark.parametrize("relative", OUTPUTS)
@pytest.mark.parametrize("mutation", ("CORRUPT", "DELETE"))
def test_each_public_output_corruption_or_deletion_repairs_byte_exactly(
    tmp_path: Path,
    relative: str,
    mutation: str,
) -> None:
    kwargs, expected, _ = _commit_then_damage(
        tmp_path,
        output=relative,
        delete=mutation == "DELETE",
    )

    repaired = _repair(tmp_path, kwargs)

    assert repaired.repaired is True
    assert repaired.safe_to_consume is True
    assert repaired.repair_receipt_path
    for output, raw in expected.items():
        assert (tmp_path / output).read_bytes() == raw


def test_repair_replay_is_byte_idempotent(
    tmp_path: Path,
) -> None:
    kwargs, expected, _ = _commit_then_damage(tmp_path)
    first = _repair(tmp_path, kwargs)
    assert first.repaired is True
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    replay = _repair(tmp_path, kwargs)
    after = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }

    assert replay.repaired is False
    assert replay.recovered is True
    assert replay.state == "ALREADY_RECOVERED"
    assert before == after
    for relative, raw in expected.items():
        assert (tmp_path / relative).read_bytes() == raw


def test_tampered_repair_pending_fails_closed_before_publication(
    tmp_path: Path,
) -> None:
    kwargs, _, _ = _commit_then_damage(tmp_path)

    def fault(name: str) -> None:
        if name == "AFTER_REPAIR_PENDING_DURABLE":
            raise RuntimeError(name)

    with pytest.raises(RuntimeError):
        _repair(tmp_path, kwargs, fault_hook=fault)
    pending = tmp_path / REPAIR_PENDING
    assert pending.is_file()
    roots_before = _root_snapshot(tmp_path)
    pending.write_bytes(pending.read_bytes() + b" ")

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert _root_snapshot(tmp_path) == roots_before


def test_tampered_repair_receipt_fails_closed_before_repairing_new_damage(
    tmp_path: Path,
) -> None:
    kwargs, expected, _ = _commit_then_damage(tmp_path)
    repaired = _repair(tmp_path, kwargs)
    receipt = tmp_path / repaired.repair_receipt_path
    assert receipt.is_file()
    receipt.write_bytes(receipt.read_bytes() + b" ")
    (tmp_path / INVENTORY).write_bytes(b"SECOND UNAUTHENTICATED STATE\n")
    roots_before = _root_snapshot(tmp_path)

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert _root_snapshot(tmp_path) == roots_before
    assert (tmp_path / INVENTORY).read_bytes() != expected[INVENTORY]


@pytest.mark.parametrize("context", ("WRONG_RUN", "WRONG_BINDING"))
def test_wrong_run_or_binding_never_starts_repair(
    tmp_path: Path,
    context: str,
) -> None:
    kwargs, _, _ = _commit_then_damage(tmp_path)
    roots_before = _root_snapshot(tmp_path)
    run_id = RUN
    binding = dict(kwargs["authority_binding"])
    if context == "WRONG_RUN":
        run_id = "another-run"
        binding["run_id"] = run_id
    else:
        binding["contract_digest"] = "e" * 64

    with pytest.raises(SemanticDedupTransactionError):
        _repair(
            tmp_path,
            kwargs,
            run_id=run_id,
            authority_binding=binding,
        )

    assert _root_snapshot(tmp_path) == roots_before
    assert not (tmp_path / REPAIR_PENDING).exists()


@pytest.mark.parametrize(
    "authority_to_tamper",
    ("PRIVATE_POSTIMAGE", "TRANSACTION_RECEIPT"),
)
def test_invalid_private_generation_or_commit_receipt_never_repairs(
    tmp_path: Path,
    authority_to_tamper: str,
) -> None:
    kwargs, expected, _ = _commit_then_damage(tmp_path)
    generation = _generation(tmp_path)
    intent = json.loads((generation / "i.json").read_text(encoding="utf-8"))
    if authority_to_tamper == "PRIVATE_POSTIMAGE":
        payload = generation / intent["outputs"][INVENTORY]["after"]["payload"]
        payload.write_bytes(payload.read_bytes() + b"TAMPER")
    else:
        digest = generation.name.removeprefix("g_")
        receipt = tmp_path / ROOT / f"c_{digest}.json"
        receipt.write_bytes(receipt.read_bytes() + b" ")
    roots_before = _root_snapshot(tmp_path)

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert _root_snapshot(tmp_path) == roots_before
    assert (tmp_path / INVENTORY).read_bytes() != expected[INVENTORY]
    assert not (tmp_path / REPAIR_PENDING).exists()


def test_pre_arm_rejection_leaves_zero_public_mutation(
    tmp_path: Path,
) -> None:
    """A durable pending pointer is not permission to touch public roots."""

    kwargs, _, _ = _commit_then_damage(tmp_path)
    missing = tmp_path / "dedup_absorbed_map.md"
    missing.unlink()
    roots_before = _root_snapshot(tmp_path)
    finalize_calls: list[str] = []

    def reject_arm(_request: Any, _pending: Mapping[str, Any]):
        raise RuntimeError("independent PRE arm rejected")

    def observe_finalize(
        request: Any,
        pending: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        finalize_calls.append(request.generation_digest)
        return _repair_finalize_authority(request, pending)

    with pytest.raises(
        SemanticDedupTransactionError,
        match="PRE arm authority rejected",
    ):
        _repair(
            tmp_path,
            kwargs,
            repair_arm_authority=reject_arm,
            repair_finalize_authority=observe_finalize,
        )

    assert _root_snapshot(tmp_path) == roots_before
    assert finalize_calls == []
    assert (tmp_path / REPAIR_PENDING).is_file()
    assert not list((tmp_path / ROOT).glob("r_*.json"))


@pytest.mark.parametrize("relative", OUTPUTS)
def test_public_output_directory_is_never_replaced(
    tmp_path: Path,
    relative: str,
) -> None:
    kwargs, authority = _fixture(tmp_path)
    committed = DRIVER.apply_semantic_dedup_transaction(**kwargs)
    assert committed.safe_to_consume is True
    path = tmp_path / relative
    path.unlink()
    path.mkdir()
    untouched = {
        name: (tmp_path / name).read_bytes()
        for name in OUTPUTS
        if name != relative
    }

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert path.is_dir() and not path.is_symlink()
    for name, raw in untouched.items():
        assert (tmp_path / name).read_bytes() == raw
    assert not (tmp_path / REPAIR_PENDING).exists()


@pytest.mark.parametrize("relative", OUTPUTS)
def test_public_output_symlink_is_never_followed_or_replaced(
    tmp_path: Path,
    relative: str,
) -> None:
    kwargs, _ = _fixture(tmp_path)
    committed = DRIVER.apply_semantic_dedup_transaction(**kwargs)
    assert committed.safe_to_consume is True
    path = tmp_path / relative
    path.unlink()
    target = tmp_path / f"{Path(relative).name}.foreign"
    foreign = b"FOREIGN SYMLINK TARGET\n"
    target.write_bytes(foreign)
    _make_symlink_or_skip(path, target)
    untouched = {
        name: (tmp_path / name).read_bytes()
        for name in OUTPUTS
        if name != relative
    }

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert path.is_symlink()
    assert target.read_bytes() == foreign
    for name, raw in untouched.items():
        assert (tmp_path / name).read_bytes() == raw
    assert not (tmp_path / REPAIR_PENDING).exists()


def test_repair_pending_symlink_is_rejected_without_public_mutation(
    tmp_path: Path,
) -> None:
    kwargs, _, _ = _commit_then_damage(tmp_path)
    pending = tmp_path / REPAIR_PENDING
    target = tmp_path / "foreign-repair-pending.json"
    foreign = b'{"foreign":true}'
    target.write_bytes(foreign)
    _make_symlink_or_skip(pending, target)
    roots_before = _root_snapshot(tmp_path)

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert pending.is_symlink()
    assert target.read_bytes() == foreign
    assert _root_snapshot(tmp_path) == roots_before


def test_repair_receipt_symlink_is_rejected_without_new_repair(
    tmp_path: Path,
) -> None:
    kwargs, _, _ = _commit_then_damage(tmp_path)
    repaired = _repair(tmp_path, kwargs)
    receipt = tmp_path / repaired.repair_receipt_path
    original = receipt.read_bytes()
    receipt.unlink()
    target = tmp_path / "foreign-repair-receipt.json"
    target.write_bytes(original)
    _make_symlink_or_skip(receipt, target)
    (tmp_path / INVENTORY).write_bytes(b"SECOND DAMAGE\n")
    roots_before = _root_snapshot(tmp_path)

    with pytest.raises(SemanticDedupTransactionError):
        _repair(tmp_path, kwargs)

    assert receipt.is_symlink()
    assert target.read_bytes() == original
    assert _root_snapshot(tmp_path) == roots_before


@pytest.mark.parametrize(
    "tamper",
    ("ARM_AUTHORITY_DIGEST", "FINALIZE_AUTHORITY_DIGEST", "HISTORY_DIGEST"),
)
def test_ledger_repair_history_tamper_quarantines_without_public_mutation(
    tmp_path: Path,
    tamper: str,
) -> None:
    project, scratchpad, config, _, _ = _driver_repaired_fixture(tmp_path)
    ledger = read_artifact_ledger(scratchpad)
    _key, unit = _repair_unit(ledger)
    history = unit["committed_output_repair_history"]
    row = history[-1]
    if tamper == "ARM_AUTHORITY_DIGEST":
        row["arm_authority"]["authority_digest"] = "0" * 64
        unsigned = {k: v for k, v in row.items() if k != "history_digest"}
        row["history_digest"] = _sha(_canonical(unsigned))
    elif tamper == "FINALIZE_AUTHORITY_DIGEST":
        row["finalize_authority"]["authority_digest"] = "0" * 64
        unsigned = {k: v for k, v in row.items() if k != "history_digest"}
        row["history_digest"] = _sha(_canonical(unsigned))
    else:
        row["history_digest"] = "0" * 64
    write_artifact_ledger(scratchpad, ledger)

    assert not DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=DRIVER_RUN_ID,
    )
    _assert_driver_quarantine_without_public_mutation(
        project=project,
        scratchpad=scratchpad,
        config=config,
    )


@pytest.mark.parametrize(
    "projection",
    ("UNIT_RECORD", "GLOBAL_BINDING", "LEGACY_RECORD"),
)
def test_repair_authority_digest_projection_tamper_quarantines(
    tmp_path: Path,
    projection: str,
) -> None:
    project, scratchpad, config, _, _ = _driver_repaired_fixture(tmp_path)
    ledger = read_artifact_ledger(scratchpad)
    _key, unit = _repair_unit(ledger)
    identity = f"scratchpad:{INVENTORY}"
    if projection == "UNIT_RECORD":
        unit["artifacts"][identity]["repair_authority_digest"] = "0" * 64
    elif projection == "GLOBAL_BINDING":
        ledger["artifact_bindings"][identity][
            "repair_authority_digest"
        ] = "0" * 64
    else:
        ledger["artifacts"][INVENTORY][
            "repair_authority_digest"
        ] = "0" * 64
    write_artifact_ledger(scratchpad, ledger)

    assert not DRIVER._l1_prequeue_apply_is_committed(
        scratchpad,
        config=config,
        run_id=DRIVER_RUN_ID,
    )
    _assert_driver_quarantine_without_public_mutation(
        project=project,
        scratchpad=scratchpad,
        config=config,
    )


def test_repeated_corruption_after_immutable_receipt_is_quarantined(
    tmp_path: Path,
) -> None:
    project, scratchpad, config, _, repaired = _driver_repaired_fixture(
        tmp_path
    )
    receipt = scratchpad / str(repaired["repair_receipt_path"])
    receipt_before = receipt.read_bytes()
    ledger_before = read_artifact_ledger(scratchpad)
    _key, unit_before = _repair_unit(ledger_before)
    history_before = json.loads(
        json.dumps(unit_before["committed_output_repair_history"])
    )
    second_damage = b"SECOND DAMAGE AFTER IMMUTABLE REPAIR RECEIPT\n"
    (scratchpad / INVENTORY).write_bytes(second_damage)

    result = _assert_driver_quarantine_without_public_mutation(
        project=project,
        scratchpad=scratchpad,
        config=config,
    )

    assert any(
        token in " ".join(str(v) for v in result["issues"]).lower()
        for token in ("third state", "repair", "authority", "changed")
    )
    assert (scratchpad / INVENTORY).read_bytes() == second_damage
    assert receipt.read_bytes() == receipt_before
    assert not (scratchpad / REPAIR_PENDING).exists()
    ledger_after = read_artifact_ledger(scratchpad)
    _key, unit_after = _repair_unit(ledger_after)
    assert unit_after["committed_output_repair_history"] == history_before


@pytest.mark.parametrize("failpoint", REPAIR_FAILPOINTS)
def test_driver_helper_quarantines_crash_then_resumes_existing_repair_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
) -> None:
    """The shared downstream helper resumes core repair; it does not reanalyse."""

    project = tmp_path / "project"
    project.mkdir()
    scratchpad, config = _seed(project)
    applied = _required_apply()(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=DRIVER_RUN_ID,
    )
    assert applied["safe_to_consume"] is True
    expected = {
        name: (scratchpad / name).read_bytes()
        for name in ROOT_OUTPUT_NAMES
    }
    (scratchpad / INVENTORY).write_bytes(b"TRUNCATED INVENTORY\n")

    real_repair = DRIVER.repair_committed_semantic_dedup_transaction
    injected = False

    def crash_once(**kwargs):
        nonlocal injected

        def fault(name: str) -> None:
            nonlocal injected
            if name == failpoint and not injected:
                injected = True
                raise RuntimeError(f"repair-fault:{name}")

        kwargs["fault_hook"] = fault
        return real_repair(**kwargs)

    monkeypatch.setattr(
        DRIVER,
        "repair_committed_semantic_dedup_transaction",
        crash_once,
    )
    first = DRIVER._ensure_l1_prequeue_successor_for_downstream(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=DRIVER_RUN_ID,
        downstream_phase="rag_sweep",
    )
    assert injected is True
    assert first["safe_to_consume"] is False
    assert first["state"] == "QUARANTINED"
    if failpoint == "AFTER_REPAIR_PENDING_CLEARED":
        assert not (scratchpad / REPAIR_PENDING).exists()
        assert list((scratchpad / ROOT).glob("r_*.json"))
    else:
        assert (scratchpad / REPAIR_PENDING).is_file()

    monkeypatch.setattr(
        DRIVER,
        "repair_committed_semantic_dedup_transaction",
        real_repair,
    )
    resumed = DRIVER._ensure_l1_prequeue_successor_for_downstream(
        scratchpad=scratchpad,
        project_root=project,
        config=config,
        run_id=DRIVER_RUN_ID,
        downstream_phase="rag_sweep",
    )

    assert resumed["safe_to_consume"] is True
    assert resumed["state"] in {"RECOVERED", "ALREADY_RECOVERED"}
    assert not (scratchpad / REPAIR_PENDING).exists()
    assert resumed["repair_receipt_path"], (
        "a crash after public postimages became exact must still finish the "
        "already-armed repair transaction and preserve its observed-damage "
        "receipt before downstream consumption"
    )
    for relative, raw in expected.items():
        assert (scratchpad / relative).read_bytes() == raw
