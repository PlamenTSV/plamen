from __future__ import annotations

import json
import os
from pathlib import Path
import stat

import pytest

import owned_directory_guard as G


_SUBJECT = "a" * 64
_ZERO = "b" * 64


def _bind(tmp_path: Path, *, name: str = "owned-root") -> G.OwnedDirectoryGuard:
    root = tmp_path / name
    root.mkdir()
    return G.bind_owned_directory(
        root,
        subject_binding_sha256=_SUBJECT,
        ledger_directory=tmp_path / "guard-ledgers",
    )


def test_guard_binding_is_opaque_redacted_and_noninheritable(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    binding = guard.binding

    assert binding["schema"] == G.GUARD_BINDING_SCHEMA
    assert binding["subject_binding_sha256"] == _SUBJECT
    assert binding["retained_parent_authority"] is True
    assert binding["retained_root_authority"] is True
    assert binding["handles_noninheritable"] is True
    serialized = json.dumps(binding, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "owned-root" not in serialized
    assert "HANDLE" not in repr(guard)
    with pytest.raises(TypeError):
        guard.__reduce__()
    guard.close_without_cleanup_for_test()


def test_guard_removes_nested_unicode_and_readonly_tree(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    root = tmp_path / "owned-root"
    nested = root / "δelta" / "nested"
    nested.mkdir(parents=True)
    readonly = nested / "readonly.txt"
    readonly.write_text("owned", encoding="utf-8")
    readonly.chmod(stat.S_IRUSR)

    receipt = guard.revoke_after_zero(
        zero_population_evidence_sha256=_ZERO,
        cleanup_mode="NORMAL_COMPLETION",
    )

    assert receipt["schema"] == G.GUARD_REVOCATION_SCHEMA
    assert receipt["terminal_stage"] == "VERIFIED_ABSENT"
    assert receipt["bound_root_link_absent"] is True
    assert receipt["completion_authority"] is False
    assert receipt["recovered"] is False
    assert not os.path.lexists(root)
    replay = G.replay_owned_directory_cleanup_ledger(
        guard.ledger_path,
        expected_subject_binding_sha256=_SUBJECT,
    )
    assert [row["stage"] for row in replay["records"]] == [
        "INTENT_DURABLE",
        "QUARANTINE_CONFIRMED",
        "TREE_EMPTY",
        "ROOT_DISPOSITION_SET",
        "VERIFIED_ABSENT",
    ]
    assert replay["terminal"] is True


def test_guard_unlinks_reparse_or_symlink_without_following_target(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    root = tmp_path / "owned-root"
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "must-survive.txt"
    sentinel.write_text("outside", encoding="utf-8")
    alias = root / "outside-alias"
    try:
        alias.symlink_to(outside, target_is_directory=True)
    except OSError as exc:
        guard.close_without_cleanup_for_test()
        pytest.skip(f"directory links unavailable: {exc}")

    receipt = guard.revoke_after_zero(
        zero_population_evidence_sha256=_ZERO,
        cleanup_mode="EMERGENCY_ZERO_POPULATION_CLEANUP",
    )

    assert receipt["bound_root_link_absent"] is True
    assert sentinel.read_text(encoding="utf-8") == "outside"


def test_retained_root_blocks_live_root_substitution_on_windows(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    root = tmp_path / "owned-root"
    parked = tmp_path / "parked"

    if os.name == "nt":
        with pytest.raises(OSError):
            root.rename(parked)
        assert root.is_dir()
    else:
        root.rename(parked)
        root.mkdir()
        with pytest.raises(
            G.OwnedDirectoryGuardError,
            match="identity|substitut",
        ):
            guard.revoke_after_zero(
                zero_population_evidence_sha256=_ZERO,
                cleanup_mode="NORMAL_COMPLETION",
            )
        assert parked.is_dir()
    guard.close_without_cleanup_for_test()


def test_quarantine_collision_is_debt_and_never_traversed(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    root = tmp_path / "owned-root"
    collision = root.parent / guard.quarantine_component_for_test
    collision.mkdir()
    sentinel = collision / "must-survive.txt"
    sentinel.write_text("collision", encoding="utf-8")

    with pytest.raises(
        G.OwnedDirectoryGuardError,
        match="quarantine|collision",
    ):
        guard.revoke_after_zero(
            zero_population_evidence_sha256=_ZERO,
            cleanup_mode="NORMAL_COMPLETION",
        )

    assert root.is_dir()
    assert sentinel.read_text(encoding="utf-8") == "collision"
    guard.close_without_cleanup_for_test()


@pytest.mark.parametrize(
    "stage",
    [
        "INTENT_DURABLE",
        "QUARANTINE_CONFIRMED",
        "TREE_EMPTY",
        "ROOT_DISPOSITION_SET",
    ],
)
def test_crash_replay_finishes_cleanup_without_completion(
    tmp_path: Path,
    stage: str,
) -> None:
    guard = _bind(tmp_path, name=f"owned-{stage.lower()}")
    root = tmp_path / f"owned-{stage.lower()}"
    nested = root / "nested"
    nested.mkdir()
    (nested / "owned.txt").write_text("owned", encoding="utf-8")

    with pytest.raises(G.OwnedDirectoryGuardInjectedCrash):
        guard.revoke_after_zero(
            zero_population_evidence_sha256=_ZERO,
            cleanup_mode="NORMAL_COMPLETION",
            _fault_after_stage=stage,
        )

    receipt = G.recover_owned_directory_cleanup(
        guard.ledger_path,
        expected_subject_binding_sha256=_SUBJECT,
    )
    assert receipt["terminal_stage"] == "VERIFIED_ABSENT"
    assert receipt["recovered"] is True
    assert receipt["completion_authority"] is False
    assert not os.path.lexists(root)


def test_corrupt_ledger_never_becomes_cleanup_success(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    with pytest.raises(G.OwnedDirectoryGuardInjectedCrash):
        guard.revoke_after_zero(
            zero_population_evidence_sha256=_ZERO,
            cleanup_mode="NORMAL_COMPLETION",
            _fault_after_stage="INTENT_DURABLE",
        )
    with guard.ledger_path.open("ab") as handle:
        handle.write(b'{"forged":true}\n')
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(
        G.OwnedDirectoryGuardError,
        match="ledger|digest|record",
    ):
        G.recover_owned_directory_cleanup(
            guard.ledger_path,
            expected_subject_binding_sha256=_SUBJECT,
        )
    assert (tmp_path / "owned-root").is_dir()


def test_invalid_zero_authority_is_rejected_before_namespace_mutation(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path)
    with pytest.raises(
        G.OwnedDirectoryGuardError,
        match="zero-population",
    ):
        guard.revoke_after_zero(
            zero_population_evidence_sha256="not-a-digest",
            cleanup_mode="NORMAL_COMPLETION",
        )
    assert (tmp_path / "owned-root").is_dir()
    assert not guard.ledger_path.exists()
    guard.close_without_cleanup_for_test()


@pytest.mark.skipif(os.name != "nt", reason="Windows ABI contract")
def test_windows_abi_layout_is_exact() -> None:
    layout = G.windows_abi_layout()
    assert layout == {
        "FILE_ID_INFO.size": 24,
        "FILE_ID_EXTD_DIR_INFO.size": 96,
        "FILE_ID_EXTD_DIR_INFO.FileName.offset": 88,
        "FILE_RENAME_INFO.size": 24,
        "FILE_RENAME_INFO.RootDirectory.offset": 8,
        "FILE_RENAME_INFO.FileNameLength.offset": 16,
        "FILE_RENAME_INFO.FileName.offset": 20,
        "UNICODE_STRING.size": 16,
        "OBJECT_ATTRIBUTES.size": 48,
    }


def test_startup_reconciliation_finishes_interrupted_guard_cleanup(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path, name="owned-reconcile")
    root = tmp_path / "owned-reconcile"
    (root / "secret.txt").write_text("owned", encoding="utf-8")
    with pytest.raises(G.OwnedDirectoryGuardInjectedCrash):
        guard.revoke_after_zero(
            zero_population_evidence_sha256=_ZERO,
            cleanup_mode="NORMAL_COMPLETION",
            _fault_after_stage="INTENT_DURABLE",
        )

    receipt = G.reconcile_owned_directory_cleanup_ledgers(
        tmp_path / "guard-ledgers"
    )

    assert receipt["complete"] is True
    assert receipt["scanned"] == 1
    assert receipt["recovered"] == 1
    assert receipt["terminal"] == 1
    assert receipt["completion_authority"] is False
    assert not os.path.lexists(root)


def test_startup_reconciliation_fails_closed_on_corrupt_guard_ledger(
    tmp_path: Path,
) -> None:
    guard = _bind(tmp_path, name="owned-corrupt-startup")
    root = tmp_path / "owned-corrupt-startup"
    with pytest.raises(G.OwnedDirectoryGuardInjectedCrash):
        guard.revoke_after_zero(
            zero_population_evidence_sha256=_ZERO,
            cleanup_mode="NORMAL_COMPLETION",
            _fault_after_stage="INTENT_DURABLE",
        )
    with guard.ledger_path.open("ab") as handle:
        handle.write(b'{"forged":true}\n')
        handle.flush()
        os.fsync(handle.fileno())

    with pytest.raises(
        G.OwnedDirectoryGuardError,
        match="ledger|reconciliation|record",
    ):
        G.reconcile_owned_directory_cleanup_ledgers(
            tmp_path / "guard-ledgers"
        )
    assert root.is_dir()
