"""Resource-bound regressions for cleanup ledger inventory."""

from pathlib import Path
from types import SimpleNamespace
import os
import builtins
import errno
import copy

import pytest

import owned_directory_guard as G

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("code", ["VALID_CODE", "private/path", "X" * 97, None])
def test_startup_failure_detail_only_exposes_bounded_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code,
) -> None:
    import auxiliary_writable_root_lease as aux

    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: tmp_path / "runtime")

    def fail(_directory):
        raise G.OwnedDirectoryGuardError(code, "private diagnostic message")

    monkeypatch.setattr(G, "reconcile_owned_directory_cleanup_ledgers", fail)
    report = aux.reconcile_auxiliary_writable_root_leases()
    detail = report["details"][0]["reason"]
    expected = "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN:OwnedDirectoryGuardError"
    assert detail == expected
    if code == "VALID_CODE":
        assert report["details"][0]["cause_code"] == "VALID_CODE"
        tampered = copy.deepcopy(report)
        tampered["details"][0]["cause_code"] = "DIFFERENT_CODE"
        assert aux.replay_auxiliary_writable_root_reconciliation(tampered)["valid"] is False
        legacy = copy.deepcopy(report)
        del legacy["details"][0]["cause_code"]
        assert aux.replay_auxiliary_writable_root_reconciliation(legacy)["valid"] is False
        # Synthetic legacy-shaped report, issued with its own correct digest.
        del legacy["report_sha256"]
        legacy = aux._finalize_reconciliation_report(legacy)
        assert aux.replay_auxiliary_writable_root_reconciliation(legacy)["valid"] is True
    else:
        assert "cause_code" not in report["details"][0]
    assert "private" not in str(report)
    assert report["allocation_disposition"] == "DENY_NEW_LEASES"
    assert aux.replay_auxiliary_writable_root_reconciliation(report)["valid"] is True


@pytest.mark.parametrize("partial_write", [False, True])
def test_disk_full_before_durable_intent_preserves_root_and_denies_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, partial_write: bool,
) -> None:
    import auxiliary_writable_root_lease as aux

    namespace = tmp_path / "provider-runtime"
    namespace.mkdir()
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    root = tmp_path / "synthetic-owned-profile"
    root.mkdir()
    marker = root / "sentinel"
    marker.write_bytes(b"must-remain")
    guard = G.bind_owned_directory(
        root, subject_binding_sha256="a" * 64,
        ledger_directory=namespace / aux.PROFILE_LIFECYCLE_DIRECTORY_NAME,
    )
    original_write = G.os.write
    writes = []

    def disk_full(descriptor, data):
        writes.append(len(data))
        if partial_write and len(writes) == 1:
            return original_write(descriptor, data[:17])
        raise OSError(errno.ENOSPC, "synthetic disk full")

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(G.os, "write", disk_full)
            with pytest.raises(G.OwnedDirectoryGuardError, match="not durable"):
                guard.revoke_after_zero(
                    zero_population_evidence_sha256="b" * 64,
                    cleanup_mode="NORMAL_COMPLETION",
                )
        assert len(writes) == (2 if partial_write else 1)
        assert marker.read_bytes() == b"must-remain"
        damaged = guard.ledger_path.read_bytes()
        assert len(damaged) == (17 if partial_write else 0)
        report = aux.reconcile_auxiliary_writable_root_leases()
        assert report["complete"] is False
        assert report["allocation_disposition"] == "DENY_NEW_LEASES"
        assert report["reason"] == "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN"
        assert guard.ledger_path.read_bytes() == damaged
        assert marker.read_bytes() == b"must-remain"
    finally:
        guard.close_without_cleanup_for_test()


def test_startup_terminal_ledger_accumulation_denies_new_leases(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Characterize retention debt, not acceptance of indefinite denial."""
    import auxiliary_writable_root_lease as aux

    namespace = tmp_path / "provider-runtime"
    namespace.mkdir()
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    directory = namespace / aux.PROFILE_LIFECYCLE_DIRECTORY_NAME
    ledgers = {}
    for index in range(2):
        root = tmp_path / f"synthetic-profile-{index}"
        root.mkdir()
        guard = G.bind_owned_directory(
            root, subject_binding_sha256="a" * 64, ledger_directory=directory,
        )
        try:
            guard.revoke_after_zero(
                zero_population_evidence_sha256="b" * 64,
                cleanup_mode="NORMAL_COMPLETION",
            )
            assert not root.exists()
            assert G.replay_owned_directory_cleanup_ledger(guard.ledger_path)["terminal"]
            ledgers[guard.ledger_path] = guard.ledger_path.read_bytes()
        finally:
            guard.close_without_cleanup_for_test()

    monkeypatch.setattr(G, "_MAX_RECONCILIATION_LEDGERS", 1)
    report = aux.reconcile_auxiliary_writable_root_leases()
    assert report["complete"] is False
    assert report["allocation_disposition"] == "DENY_NEW_LEASES"
    assert report["reason"] == "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN"
    assert {path: path.read_bytes() for path in ledgers} == ledgers
    assert any(row.get("cause_code") == "RECONCILIATION_ENTRY_BOUND"
               for row in report["details"])
    assert aux.replay_auxiliary_writable_root_reconciliation(report)["valid"] is True


@pytest.mark.parametrize("interrupted", [False, True])
def test_startup_real_profile_replay_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interrupted: bool,
) -> None:
    import auxiliary_writable_root_lease as aux

    namespace = tmp_path / "provider-runtime"
    namespace.mkdir()
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    directory = namespace / aux.PROFILE_LIFECYCLE_DIRECTORY_NAME
    root = tmp_path / "synthetic-owned-profile"
    root.mkdir()
    guard = G.bind_owned_directory(
        root, subject_binding_sha256="a" * 64, ledger_directory=directory,
    )
    try:
        kwargs = dict(
            zero_population_evidence_sha256="b" * 64,
            cleanup_mode="NORMAL_COMPLETION",
        )
        if interrupted:
            with pytest.raises(G.OwnedDirectoryGuardInjectedCrash):
                guard.revoke_after_zero(**kwargs, _fault_after_stage="INTENT_DURABLE")
        else:
            guard.revoke_after_zero(**kwargs)
        first = aux.reconcile_auxiliary_writable_root_leases()
        assert first["complete"] is True
        detail = next(row for row in first["details"]
                      if row["disposition"] == "PROFILE_LIFECYCLE_REPLAYED")
        assert detail["scanned"] == detail["terminal"] == 1
        assert detail["recovered"] == int(interrupted)
        assert detail["completion_authority"] is False
        assert not root.exists()
        terminal_bytes = guard.ledger_path.read_bytes()

        second = aux.reconcile_auxiliary_writable_root_leases()
        assert second["complete"] is True
        replay = next(row for row in second["details"]
                      if row["disposition"] == "PROFILE_LIFECYCLE_REPLAYED")
        assert replay["scanned"] == replay["terminal"] == 1
        assert replay["recovered"] == 0
        assert replay["completion_authority"] is False
        assert guard.ledger_path.read_bytes() == terminal_bytes
        assert not root.exists()
    finally:
        guard.close_without_cleanup_for_test()


def test_startup_real_invalid_profile_inventory_preserves_outer_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import auxiliary_writable_root_lease as aux

    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(aux, "_default_runtime_namespace", lambda: namespace)
    lease = aux.reserve_auxiliary_writable_root(
        attempt_id="synthetic-invalid-profile-inventory",
        purpose="claude-profile",
    ).arm(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="synthetic-no-process",
    )
    marker = lease.root / "sentinel"
    marker.write_text("must-remain", encoding="utf-8")
    directory = namespace / aux.PROFILE_LIFECYCLE_DIRECTORY_NAME
    directory.mkdir(exist_ok=True)
    invalid = directory / "unexpected-entry.txt"
    invalid.write_text("invalid inventory", encoding="utf-8")

    def forbidden(*_args, **_kwargs):
        pytest.fail("startup reached owner inspection or outer cleanup")

    monkeypatch.setattr(aux, "_provider_owner_status", forbidden)
    monkeypatch.setattr(aux, "_cleanup_orphaned_journal_root", forbidden)
    report = aux.reconcile_auxiliary_writable_root_leases()

    assert report["complete"] is False
    assert report["allocation_disposition"] == "DENY_NEW_LEASES"
    assert report["reason"] == "PROFILE_LIFECYCLE_RECOVERY_UNPROVEN"
    assert marker.read_text(encoding="utf-8") == "must-remain"
    assert invalid.read_text(encoding="utf-8") == "invalid inventory"


def test_missing_directory_remains_explicit_empty_result(tmp_path: Path) -> None:
    directory = tmp_path / "missing-ledgers"
    result = G.reconcile_owned_directory_cleanup_ledgers(directory)
    assert result["directory_present"] is False
    assert result["complete"] is True
    assert result["reason"] == "NO_PROFILE_LIFECYCLE_DIRECTORY"
    assert result["scanned"] == result["recovered"] == result["terminal"] == 0
    assert result["completion_authority"] is False
    assert not directory.exists()


def test_inaccessible_directory_is_not_reported_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "inaccessible-ledgers"
    directory.mkdir()

    def denied(_path, *_args, **_kwargs):
        raise PermissionError("fixture metadata access denied")

    with monkeypatch.context() as scoped:
        scoped.setattr(G.os, "lstat", denied)
        with pytest.raises(G.OwnedDirectoryGuardError, match="cannot be inventoried"):
            G.reconcile_owned_directory_cleanup_ledgers(directory)
    assert directory.is_dir()


def test_ledger_growth_after_stat_is_read_bounded_and_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_bytes(b"x")
    reads = []
    monkeypatch.setattr(G, "_MAX_LEDGER_BYTES", 128)

    class Reader:
        def __enter__(self):
            self.handle = builtins.open(ledger, "rb")
            return self

        def read(self, size):
            reads.append(size)
            return self.handle.read(size)

        def __exit__(self, *_args):
            self.handle.close()

    def grow_then_open(_path, mode):
        assert mode == "rb"
        ledger.write_bytes(b"x" * 256)
        return Reader()

    monkeypatch.setattr(G, "open", grow_then_open, raising=False)
    with pytest.raises(G.OwnedDirectoryGuardError, match="byte bound"):
        G._ledger_records(ledger)
    assert reads == [129]
    assert ledger.stat().st_size == 256


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows long-ledger lifecycle")
@pytest.mark.parametrize("interrupted", [False, True])
@pytest.mark.parametrize("long_owned_root", [False, True])
def test_long_ledger_reconciliation_replays_and_recovers(
    tmp_path: Path, interrupted: bool, long_owned_root: bool,
) -> None:
    parent = tmp_path.resolve()
    long_base = parent / ("l" * (270 - len(str(parent)) - 1))
    assert long_base.parent == parent and len(str(long_base)) == 270
    base_native = "\\\\?\\" + str(long_base)
    os.mkdir(base_native)
    directory = long_base / "ledgers" if long_owned_root else long_base
    root = (long_base if long_owned_root else parent) / "owned"
    root_native = "\\\\?\\" + str(root)
    os.mkdir(root_native)
    native = "\\\\?\\" + str(directory)
    if long_owned_root:
        os.mkdir(native)
    guard = None
    try:
        guard = G.bind_owned_directory(
            root, subject_binding_sha256="a" * 64, ledger_directory=directory,
        )
        kwargs = dict(
            zero_population_evidence_sha256="b" * 64,
            cleanup_mode="NORMAL_COMPLETION",
        )
        if interrupted:
            with pytest.raises(G.OwnedDirectoryGuardInjectedCrash):
                guard.revoke_after_zero(**kwargs, _fault_after_stage="INTENT_DURABLE")
        else:
            guard.revoke_after_zero(**kwargs)
        result = G.reconcile_owned_directory_cleanup_ledgers(directory)
        assert result["directory_present"] is True
        assert result["complete"] is True
        assert result["scanned"] == result["terminal"] == 1
        assert result["recovered"] == int(interrupted)
        assert result["completion_authority"] is False
        assert not os.path.lexists(root_native)
    finally:
        if guard is not None:
            guard.close_without_cleanup_for_test()
            ledger_native = "\\\\?\\" + str(guard.ledger_path)
            if os.path.lexists(ledger_native):
                os.unlink(ledger_native)
        os.rmdir(native)
        if os.path.lexists(root_native):
            os.rmdir(root_native)
        if long_owned_root:
            os.rmdir(base_native)


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows long-directory boundary")
def test_existing_long_ledger_directory_is_not_reported_missing(tmp_path: Path) -> None:
    parent = tmp_path.resolve()
    padding = 270 - len(str(parent)) - 1
    assert 1 <= padding <= 255
    directory = parent / ("l" * padding)
    assert directory.parent == parent
    assert len(str(directory)) == 270
    native = "\\\\?\\" + str(directory)
    os.mkdir(native)
    try:
        assert os.path.isdir(native)
        result = G.reconcile_owned_directory_cleanup_ledgers(directory)
        assert result["directory_present"] is True
        assert result["complete"] is True
        assert result["scanned"] == 0
    finally:
        os.rmdir(native)


def test_reconciliation_accepts_exact_entry_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "owned"
    root.mkdir()
    directory = tmp_path / "ledgers"
    guard = G.bind_owned_directory(
        root, subject_binding_sha256="a" * 64, ledger_directory=directory,
    )
    guard.revoke_after_zero(
        zero_population_evidence_sha256="b" * 64,
        cleanup_mode="NORMAL_COMPLETION",
    )
    before = guard.ledger_path.read_bytes()
    monkeypatch.setattr(G, "_MAX_RECONCILIATION_LEDGERS", 1)
    result = G.reconcile_owned_directory_cleanup_ledgers(directory)
    assert result["complete"] is True
    assert result["scanned"] == 1
    assert result["terminal"] == 1
    assert result["recovered"] == 0
    assert result["completion_authority"] is False
    assert guard.ledger_path.read_bytes() == before


def test_reconciliation_stops_enumeration_at_entry_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "bounded-ledgers"
    directory.mkdir()
    observed = []
    closed = []

    class Entries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append(True)

        def __iter__(self):
            for index in range(4):
                observed.append(index)
                yield SimpleNamespace(path=str(directory / f"guard-{index:032x}.jsonl"))

    monkeypatch.setattr(G, "_MAX_RECONCILIATION_LEDGERS", 2)
    def unexpected_replay(*_args, **_kwargs):
        pytest.fail("overflow must be rejected before replay or recovery")

    monkeypatch.setattr(G, "replay_owned_directory_cleanup_ledger", unexpected_replay)
    monkeypatch.setattr(G, "recover_owned_directory_cleanup", unexpected_replay)
    with monkeypatch.context() as scoped:
        scoped.setattr(G.os, "scandir", lambda _directory: Entries())
        with pytest.raises(G.OwnedDirectoryGuardError, match="count exceeded"):
            G.reconcile_owned_directory_cleanup_ledgers(directory)
    assert observed == [0, 1, 2]
    assert closed == [True]
    assert list(directory.iterdir()) == []
