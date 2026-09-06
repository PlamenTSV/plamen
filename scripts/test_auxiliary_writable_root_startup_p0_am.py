from __future__ import annotations

import copy
from concurrent.futures import ProcessPoolExecutor
import json
import os
from pathlib import Path

import pytest

import auxiliary_writable_root_lease as lease_authority
import auxiliary_writable_root_startup as startup_authority


RUN_ID = "12345678-1234-4abc-8def-1234567890ab"
EPOCH_A = "a" * 32
EPOCH_B = "b" * 32


def _runtime_namespace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> Path:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(
        lease_authority,
        "_default_runtime_namespace",
        lambda: namespace,
    )
    return namespace


def _failure_receipt(
    epoch: str,
    failure_type: str = "OSError",
) -> dict[str, object]:
    return startup_authority.compile_startup_receipt(
        run_id=RUN_ID,
        startup_epoch=epoch,
        failure_type=failure_type,
    )


def _persist_failure_receipt_process(
    scratchpad: str,
    epoch: str,
    failure_type: str,
) -> tuple[str, str]:
    """Spawn-safe worker used to exercise the advisory lock."""

    import auxiliary_writable_root_startup as authority

    receipt = authority.compile_startup_receipt(
        run_id=RUN_ID,
        startup_epoch=epoch,
        failure_type=failure_type,
    )
    path = authority.persist_startup_receipt(
        scratchpad=Path(scratchpad),
        receipt=receipt,
    )
    return epoch, path.name


def test_clean_reconciliation_persists_immutable_epoch_and_permit_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    monkeypatch.setattr(startup_authority.uuid, "uuid4", lambda: type(
        "_UUID",
        (),
        {"hex": EPOCH_A},
    )())

    receipt = startup_authority.reconcile_and_persist_startup_receipt(
        scratchpad=scratchpad,
        run_id=RUN_ID,
    )

    assert receipt["startup_epoch"] == EPOCH_A
    assert receipt["allocation_disposition"] == "ALLOW_NEW_LEASES"
    replay = startup_authority.load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )
    binding = replay["binding"]
    assert binding == {
        "schema": startup_authority.STARTUP_BINDING_SCHEMA,
        "run_id": RUN_ID,
        "startup_epoch": EPOCH_A,
        "current_pointer_sha256": replay["current_pointer_sha256"],
        "receipt_relative_path": replay["receipt_relative_path"],
        "receipt_sha256": receipt["receipt_sha256"],
        "allocation_disposition": "ALLOW_NEW_LEASES",
    }
    assert startup_authority.replay_startup_permit_binding(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        binding=binding,
    )["binding"] == binding
    receipt_path = scratchpad / replay["receipt_relative_path"]
    assert receipt_path.is_file()
    assert receipt_path.parent.name == (
        startup_authority.STARTUP_RECEIPT_DIRECTORY_NAME
    )


def test_historical_permit_evidence_survives_a_later_startup_epoch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Completed work stays replayable although old authority cannot relaunch."""

    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    epochs = iter((EPOCH_A, EPOCH_B))
    monkeypatch.setattr(
        startup_authority.uuid,
        "uuid4",
        lambda: type("_UUID", (), {"hex": next(epochs)})(),
    )

    first = startup_authority.reconcile_and_persist_startup_receipt(
        scratchpad=scratchpad,
        run_id=RUN_ID,
    )
    first_replay = startup_authority.load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )
    evidence = {
        "binding": first_replay["binding"],
        "current_pointer": first_replay["current_pointer"],
    }
    startup_authority.reconcile_and_persist_startup_receipt(
        scratchpad=scratchpad,
        run_id=RUN_ID,
    )

    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="epoch authority mismatched",
    ):
        startup_authority.replay_startup_permit_binding(
            scratchpad=scratchpad,
            expected_run_id=RUN_ID,
            binding=first_replay["binding"],
        )
    historical = startup_authority.replay_startup_permit_evidence(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        evidence=evidence,
    )
    assert historical["receipt"]["receipt_sha256"] == first["receipt_sha256"]
    assert historical["binding"] == first_replay["binding"]


def test_historical_permit_evidence_rejects_pointer_or_receipt_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    monkeypatch.setattr(
        startup_authority.uuid,
        "uuid4",
        lambda: type("_UUID", (), {"hex": EPOCH_A})(),
    )
    startup_authority.reconcile_and_persist_startup_receipt(
        scratchpad=scratchpad,
        run_id=RUN_ID,
    )
    replay = startup_authority.load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )
    evidence = {
        "binding": replay["binding"],
        "current_pointer": replay["current_pointer"],
    }

    changed_pointer = copy.deepcopy(evidence)
    changed_pointer["current_pointer"]["pointer_sha256"] = "f" * 64
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="pointer",
    ):
        startup_authority.replay_startup_permit_evidence(
            scratchpad=scratchpad,
            expected_run_id=RUN_ID,
            evidence=changed_pointer,
        )

    receipt_path = scratchpad / replay["receipt_relative_path"]
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="receipt",
    ):
        startup_authority.replay_startup_permit_evidence(
            scratchpad=scratchpad,
            expected_run_id=RUN_ID,
            evidence=evidence,
        )


def test_stale_allow_is_invalidated_before_later_receipt_publication_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The old singleton defect: failed DENY publication left ALLOW live."""

    _runtime_namespace(monkeypatch, tmp_path)
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    report = lease_authority.reconcile_auxiliary_writable_root_leases()
    allow = startup_authority.compile_startup_receipt(
        run_id=RUN_ID,
        startup_epoch=EPOCH_A,
        reconciliation=report,
    )
    startup_authority.persist_startup_receipt(
        scratchpad=scratchpad,
        receipt=allow,
    )

    def fail_immutable(*args: object, **kwargs: object) -> Path:
        raise startup_authority.AuxiliaryWritableRootStartupError(
            "injected immutable publication failure"
        )

    monkeypatch.setattr(
        startup_authority,
        "_publish_immutable_receipt",
        fail_immutable,
    )
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="injected",
    ):
        startup_authority.persist_startup_receipt(
            scratchpad=scratchpad,
            receipt=_failure_receipt(EPOCH_B),
        )

    pointer = json.loads(
        (
            scratchpad / startup_authority.STARTUP_CURRENT_NAME
        ).read_text("utf-8")
    )
    assert pointer["startup_epoch"] == EPOCH_B
    assert pointer["state"] == "RECONCILING"
    for epoch in (EPOCH_A, EPOCH_B):
        with pytest.raises(
            startup_authority.AuxiliaryWritableRootStartupError,
            match="epoch|COMPLETE",
        ):
            startup_authority.load_and_replay_startup_receipt(
                scratchpad=scratchpad,
                expected_run_id=RUN_ID,
                expected_startup_epoch=epoch,
            )


def test_failed_complete_cas_leaves_reconciling_not_permit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    original_replace = startup_authority._replace_record
    calls = 0

    def fail_complete(path: Path, raw: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise startup_authority.AuxiliaryWritableRootStartupError(
                "injected complete publication failure"
            )
        original_replace(path, raw)

    monkeypatch.setattr(
        startup_authority,
        "_replace_record",
        fail_complete,
    )
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="publication",
    ):
        startup_authority.persist_startup_receipt(
            scratchpad=scratchpad,
            receipt=_failure_receipt(EPOCH_A),
        )
    pointer = json.loads(
        (
            scratchpad / startup_authority.STARTUP_CURRENT_NAME
        ).read_text("utf-8")
    )
    assert pointer["state"] == "RECONCILING"
    assert pointer["startup_epoch"] == EPOCH_A

    # A restart using the same durable outcome adopts the exact immutable
    # receipt and completes without creating a second receipt.
    monkeypatch.setattr(
        startup_authority,
        "_replace_record",
        original_replace,
    )
    recovered_path = startup_authority.persist_startup_receipt(
        scratchpad=scratchpad,
        receipt=_failure_receipt(EPOCH_A),
    )
    assert recovered_path.is_file()
    assert len(
        list(
            (
                scratchpad
                / startup_authority.STARTUP_RECEIPT_DIRECTORY_NAME
            ).glob("*.json")
        )
    ) == 1
    assert startup_authority.load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )["allocation_permitted"] is False


def test_epoch_reuse_with_different_receipt_is_denied_and_invalidates_prior(
    tmp_path: Path,
) -> None:
    first = _failure_receipt(EPOCH_A, "OSError")
    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=first,
    )
    second = _failure_receipt(EPOCH_A, "RuntimeError")

    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="epoch",
    ):
        startup_authority.persist_startup_receipt(
            scratchpad=tmp_path,
            receipt=second,
        )

    pointer = json.loads(
        (
            tmp_path / startup_authority.STARTUP_CURRENT_NAME
        ).read_text("utf-8")
    )
    assert pointer["state"] == "RECONCILING"
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="COMPLETE",
    ):
        startup_authority.load_and_replay_startup_receipt(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            expected_startup_epoch=EPOCH_A,
        )


def test_ambiguous_post_replace_failure_rolls_complete_back_to_reconciling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    original_replace = startup_authority._replace_record
    calls = 0

    def replace_then_fail(path: Path, raw: bytes) -> None:
        nonlocal calls
        calls += 1
        original_replace(path, raw)
        if calls == 2:
            raise startup_authority.AuxiliaryWritableRootStartupError(
                "injected post-replace durability failure"
            )

    monkeypatch.setattr(
        startup_authority,
        "_replace_record",
        replace_then_fail,
    )
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="post-replace",
    ):
        startup_authority.persist_startup_receipt(
            scratchpad=tmp_path,
            receipt=_failure_receipt(EPOCH_A),
        )

    pointer = json.loads(
        (
            tmp_path / startup_authority.STARTUP_CURRENT_NAME
        ).read_text("utf-8")
    )
    assert pointer["state"] == "RECONCILING"
    assert pointer["startup_epoch"] == EPOCH_A


def test_invalid_provider_report_is_sanitized_durable_denial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / "scratchpad"
    scratchpad.mkdir()
    monkeypatch.setattr(
        startup_authority,
        "reconcile_auxiliary_writable_root_leases",
        lambda: {},
    )
    monkeypatch.setattr(startup_authority.uuid, "uuid4", lambda: type(
        "_UUID",
        (),
        {"hex": EPOCH_A},
    )())

    receipt = startup_authority.reconcile_and_persist_startup_receipt(
        scratchpad=scratchpad,
        run_id=RUN_ID,
    )

    assert receipt["allocation_disposition"] == "DENY_NEW_LEASES"
    assert receipt["reconciliation"] is None
    assert receipt["failure"]["exception_type"] == (
        "AuxiliaryWritableRootStartupError"
    )
    loaded = startup_authority.load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )
    assert loaded["allocation_permitted"] is False
    assert loaded["binding"] is None


def test_denial_never_replays_as_permit_binding(tmp_path: Path) -> None:
    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=_failure_receipt(EPOCH_A),
    )
    loaded = startup_authority.load_and_replay_startup_receipt(
        scratchpad=tmp_path,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )
    assert loaded["binding"] is None
    forged = {
        "schema": startup_authority.STARTUP_BINDING_SCHEMA,
        "run_id": RUN_ID,
        "startup_epoch": EPOCH_A,
        "current_pointer_sha256": loaded["current_pointer_sha256"],
        "receipt_relative_path": loaded["receipt_relative_path"],
        "receipt_sha256": loaded["receipt_sha256"],
        "allocation_disposition": "DENY_NEW_LEASES",
    }
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="permit",
    ):
        startup_authority.replay_startup_permit_binding(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            binding=forged,
        )


def test_permit_binding_rejects_memory_tamper_and_newer_epoch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    report = lease_authority.reconcile_auxiliary_writable_root_leases()
    first = startup_authority.compile_startup_receipt(
        run_id=RUN_ID,
        startup_epoch=EPOCH_A,
        reconciliation=report,
    )
    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=first,
    )
    binding = startup_authority.load_and_replay_startup_receipt(
        scratchpad=tmp_path,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )["binding"]
    drifted = copy.deepcopy(binding)
    drifted["receipt_sha256"] = "f" * 64
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="binding",
    ):
        startup_authority.replay_startup_permit_binding(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            binding=drifted,
        )

    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=_failure_receipt(EPOCH_B),
    )
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="epoch|binding",
    ):
        startup_authority.replay_startup_permit_binding(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            binding=binding,
        )


def test_two_process_startups_serialize_to_one_exact_complete_pointer(
    tmp_path: Path,
) -> None:
    epochs = (EPOCH_A, EPOCH_B)
    with ProcessPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                _persist_failure_receipt_process,
                str(tmp_path),
                epoch,
                failure,
            )
            for epoch, failure in zip(
                epochs,
                ("OSError", "RuntimeError"),
                strict=True,
            )
        ]
        assert {future.result(timeout=30)[0] for future in futures} == set(
            epochs
        )

    accepted: list[str] = []
    for epoch in epochs:
        try:
            replay = startup_authority.load_and_replay_startup_receipt(
                scratchpad=tmp_path,
                expected_run_id=RUN_ID,
                expected_startup_epoch=epoch,
            )
        except startup_authority.AuxiliaryWritableRootStartupError:
            continue
        assert replay["allocation_disposition"] == "DENY_NEW_LEASES"
        accepted.append(epoch)
    assert len(accepted) == 1
    receipts = list(
        (tmp_path / startup_authority.STARTUP_RECEIPT_DIRECTORY_NAME).glob(
            "*.json"
        )
    )
    assert len(receipts) == 2


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (
            (b'{"x":' * 80) + b"0" + (b"}" * 80),
            "depth",
        ),
        (
            b'{"x":' + (b"9" * 10_000) + b"}",
            "integer",
        ),
        (
            json.dumps({"x": "z" * 40_000}).encode("utf-8"),
            "string",
        ),
    ],
    ids=["depth", "integer", "string"],
)
def test_bounded_json_rejects_depth_integer_and_string(
    tmp_path: Path,
    raw: bytes,
    message: str,
) -> None:
    current = tmp_path / startup_authority.STARTUP_CURRENT_NAME
    current.write_bytes(raw)
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match=message,
    ):
        startup_authority.load_and_replay_startup_receipt(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            expected_startup_epoch=EPOCH_A,
        )


def test_abandoned_temporaries_are_cleaned_or_quarantined(
    tmp_path: Path,
) -> None:
    regular = tmp_path / ".aux-root-startup-orphan.tmp"
    regular.write_text("partial", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("do not follow", encoding="utf-8")
    alias = tmp_path / ".aux-root-startup-alias.tmp"
    try:
        alias.symlink_to(outside)
    except OSError:
        alias = None

    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=_failure_receipt(EPOCH_A),
    )

    assert not regular.exists()
    assert outside.read_text("utf-8") == "do not follow"
    if alias is not None:
        assert not os.path.lexists(alias)
        quarantine = (
            tmp_path / startup_authority.STARTUP_QUARANTINE_DIRECTORY_NAME
        )
        assert any(quarantine.iterdir())


def test_receipt_hardlink_and_scratchpad_alias_are_rejected(
    tmp_path: Path,
) -> None:
    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=_failure_receipt(EPOCH_A),
    )
    loaded = startup_authority.load_and_replay_startup_receipt(
        scratchpad=tmp_path,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )
    receipt_path = tmp_path / loaded["receipt_relative_path"]
    os.link(receipt_path, tmp_path / "foreign-hardlink.json")
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="single-link",
    ):
        startup_authority.load_and_replay_startup_receipt(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            expected_startup_epoch=EPOCH_A,
        )

    alias = tmp_path.parent / f"{tmp_path.name}-alias"
    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation unavailable")
    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="alias",
    ):
        startup_authority.load_and_replay_startup_receipt(
            scratchpad=alias,
            expected_run_id=RUN_ID,
            expected_startup_epoch=EPOCH_A,
        )


def test_current_pointer_hardlink_is_rejected(tmp_path: Path) -> None:
    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=_failure_receipt(EPOCH_A),
    )
    current = tmp_path / startup_authority.STARTUP_CURRENT_NAME
    os.link(current, tmp_path / "foreign-current-hardlink.json")

    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="single-link",
    ):
        startup_authority.load_and_replay_startup_receipt(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            expected_startup_epoch=EPOCH_A,
        )


def test_nested_reconciliation_tamper_fails_after_outer_rehash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _runtime_namespace(monkeypatch, tmp_path)
    receipt = startup_authority.compile_startup_receipt(
        run_id=RUN_ID,
        startup_epoch=EPOCH_A,
        reconciliation=(
            lease_authority.reconcile_auxiliary_writable_root_leases()
        ),
    )
    tampered = copy.deepcopy(receipt)
    tampered["reconciliation"]["complete"] = False
    core = dict(tampered)
    core.pop("receipt_sha256")
    tampered["receipt_sha256"] = (
        startup_authority.digest_startup_payload(core)
    )

    assert startup_authority.replay_startup_receipt(tampered) == {
        "valid": False,
        "reason": "STARTUP_RECEIPT_REPLAY_FAILED",
    }


def test_rehashed_pointer_cannot_change_receipt_disposition(
    tmp_path: Path,
) -> None:
    startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=_failure_receipt(EPOCH_A),
    )
    path = tmp_path / startup_authority.STARTUP_CURRENT_NAME
    pointer = json.loads(path.read_text("utf-8"))
    pointer["allocation_disposition"] = "ALLOW_NEW_LEASES"
    core = dict(pointer)
    core.pop("pointer_sha256")
    pointer["pointer_sha256"] = startup_authority.digest_startup_payload(
        core
    )
    path.write_bytes(startup_authority.canonical_startup_bytes(pointer))

    with pytest.raises(
        startup_authority.AuxiliaryWritableRootStartupError,
        match="semantics",
    ):
        startup_authority.load_and_replay_startup_receipt(
            scratchpad=tmp_path,
            expected_run_id=RUN_ID,
            expected_startup_epoch=EPOCH_A,
        )


def test_receipt_path_is_immutable_and_digest_addressed(tmp_path: Path) -> None:
    receipt = _failure_receipt(EPOCH_A)
    first_path = startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=receipt,
    )
    first_raw = first_path.read_bytes()

    second_path = startup_authority.persist_startup_receipt(
        scratchpad=tmp_path,
        receipt=receipt,
    )

    assert second_path == first_path
    assert first_path.read_bytes() == first_raw
    assert EPOCH_A in first_path.name
    assert receipt["receipt_sha256"] in first_path.name


def _exact_ordinary_windows_scratchpad(base: Path) -> Path:
    target_length = 246
    raw = str(base)
    if raw.startswith(("\\\\?\\", "\\\\.\\")):
        raise AssertionError("fixture root must use an ordinary Windows path")
    if not base.is_absolute() or any(part in {".", ".."} for part in base.parts):
        raise AssertionError("fixture root must be absolute and alias-free")
    root = base.absolute()
    if str(root) != raw:
        raise AssertionError("fixture root spelling must already be canonical")
    padding_length = target_length - len(raw) - 1
    if not 1 <= padding_length <= 255:
        raise AssertionError("fixture root cannot reach exact safe length")
    component = "x" * padding_length
    if component in {".", ".."} or any(
        separator in component for separator in ("/", "\\")
    ):
        raise AssertionError("fixture padding component is invalid")
    scratchpad = root / component
    if scratchpad.parent != root or scratchpad.relative_to(root) != Path(component):
        raise AssertionError("fixture scratchpad must be one exact child")
    if len(str(scratchpad.absolute())) != target_length:
        raise AssertionError("fixture scratchpad length is not exact")
    return scratchpad


def test_windows_write_through_handles_extended_length_scratchpad(
    tmp_path: Path,
) -> None:
    if os.name != "nt":
        pytest.skip("Windows extended-length path contract")
    scratchpad = _exact_ordinary_windows_scratchpad(tmp_path)
    scratchpad.mkdir(parents=True)
    assert len(str(scratchpad.absolute())) == 246
    assert len(
        str((scratchpad / startup_authority.STARTUP_LOCK_NAME).absolute())
    ) == 284
    assert len(
        str((scratchpad / startup_authority.STARTUP_CURRENT_NAME).absolute())
    ) == 292

    path = startup_authority.persist_startup_receipt(
        scratchpad=scratchpad,
        receipt=_failure_receipt(EPOCH_A),
    )

    assert len(str(path.absolute())) == 399
    assert startup_authority.load_and_replay_startup_receipt(
        scratchpad=scratchpad,
        expected_run_id=RUN_ID,
        expected_startup_epoch=EPOCH_A,
    )["receipt_relative_path"] == path.relative_to(scratchpad).as_posix()
