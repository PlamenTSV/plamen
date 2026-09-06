from __future__ import annotations

import ctypes
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest

import auxiliary_writable_root_lease as auxiliary
import test_worker_execution_receipts as worker_fixtures
import test_wer_claude_runtime_lifecycle_p0_am as claude_runtime_fixtures
import worker_execution_receipts as worker_receipts
from owned_process_scope import OwnedProcessScope
from windows_low_integrity_lease import (
    LEASE_DIRECTORY_ENV,
    LEASE_TEST_OVERRIDE_ENV,
    WindowsLowIntegrityExecutionLease,
    WindowsLowIntegrityLeaseError,
    set_windows_low_integrity_root,
)
from windows_private_execution_root import (
    WindowsPrivateExecutionRootError,
    create_windows_private_execution_root,
)


pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL/MIC fixture")


def _isolated_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LEASE_TEST_OVERRIDE_ENV, "1")
    monkeypatch.setenv(LEASE_DIRECTORY_ENV, str(tmp_path / "lease"))


def _icacls(path: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"), str(path), *args],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )


def _current_sid() -> str:
    command = [
        str(Path(os.environ["SystemRoot"]) / "System32" / "whoami.exe"),
        "/user",
        "/fo",
        "csv",
        "/nh",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)
    # "DOMAIN\\name","S-1-..."
    return result.stdout.strip().split('","', 1)[1].rstrip('"\r\n')


def test_modify_only_baseline_reproduces_write_owner_error5(tmp_path: Path) -> None:
    root = tmp_path / "modify-only"
    root.mkdir()
    result = _icacls(root, "/inheritance:r", "/grant:r", f"*{_current_sid()}:(OI)(CI)M")
    assert result.returncode == 0, result.stderr
    with pytest.raises(WindowsLowIntegrityLeaseError, match=r"failed: 5"):
        set_windows_low_integrity_root(root)


def test_private_root_handle_low_restore_and_fresh_leaf(tmp_path: Path) -> None:
    path = tmp_path / "private"
    authority = create_windows_private_execution_root(path)
    assert authority.binding["dacl"]["access_mask"] == 0x001F01FF
    assert authority.binding["retained_no_share_delete"] is True
    authority.lower_to_low_integrity()
    (path / "child.txt").write_text("ok", encoding="utf-8")
    authority.restore_medium_integrity_tree()
    authority.close_after_medium_restore()
    assert (path / "child.txt").read_text(encoding="utf-8") == "ok"
    with pytest.raises(WindowsPrivateExecutionRootError, match="fresh leaf"):
        create_windows_private_execution_root(path)


def test_retained_root_blocks_path_swap_and_rejects_dacl_drift(tmp_path: Path) -> None:
    path = tmp_path / "private"
    authority = create_windows_private_execution_root(path)
    moved = tmp_path / "moved"
    try:
        os.replace(path, tmp_path / "moved")
    except PermissionError:
        # Older Windows rename paths honor the omitted FILE_SHARE_DELETE.
        authority.replay()
    else:
        # Newer POSIX-style rename paths may move an opened directory.  The
        # retained final-path replay still rejects the substitution before use.
        with pytest.raises(WindowsPrivateExecutionRootError, match="path drifted"):
            authority.replay()
        os.replace(moved, path)
    authority.replay()
    result = _icacls(path, "/inheritance:e")
    assert result.returncode == 0, result.stderr
    with pytest.raises(WindowsPrivateExecutionRootError, match="DACL"):
        authority.replay()


def test_preexisting_reparse_is_rejected_without_following(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink privilege unavailable: {exc}")
    with pytest.raises(WindowsPrivateExecutionRootError, match="fresh leaf"):
        create_windows_private_execution_root(link)
    assert not any(target.iterdir())


def test_reparse_parent_is_rejected_before_leaf_creation(tmp_path: Path) -> None:
    target = tmp_path / "target-parent"
    target.mkdir()
    link = tmp_path / "linked-parent"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlink privilege unavailable: {exc}")
    with pytest.raises(
        WindowsPrivateExecutionRootError,
        match="ancestor is aliased",
    ):
        create_windows_private_execution_root(link / "private")
    assert not (target / "private").exists()


def test_private_authority_integrates_with_low_lease(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolated_lease(tmp_path, monkeypatch)
    authority = create_windows_private_execution_root(tmp_path / "private")
    lease = WindowsLowIntegrityExecutionLease(
        writable_roots=(authority.path,),
        writable_root_authorities=(authority,),
        owner_identity=f"private-{uuid.uuid4().hex}",
    )
    assert authority.binding["integrity_state"] == "LOW"
    (authority.path / "inside.txt").write_text("inside", encoding="utf-8")
    lease.release_after_proven_closure()
    assert authority.binding["integrity_state"] == "MEDIUM"
    authority.close_after_medium_restore()


def test_real_low_job_writes_private_root_not_medium_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch_acl_before = _icacls(tmp_path).stdout
    authority = create_windows_private_execution_root(tmp_path / "allowed")
    denied = tmp_path / "denied"
    denied.mkdir()
    denied_acl_before = _icacls(denied).stdout
    result_path = authority.path / "result.txt"
    scope = OwnedProcessScope(
        writable_roots=(authority.path,),
        windows_private_root_authorities=(authority,),
        persistent_identity=f"private-job-{uuid.uuid4().hex}",
    )
    code = (
        "from pathlib import Path; import time\n"
        f"allowed=Path({str(authority.path / 'written.txt')!r})\n"
        f"denied=Path({str(denied / 'forbidden.txt')!r})\n"
        f"result=Path({str(result_path)!r})\n"
        "allowed.write_text('ok')\n"
        "try:\n denied.write_text('bad')\nexcept PermissionError:\n result.write_text('denied')\n"
        "time.sleep(30)\n"
    )
    process = scope.create_process(
        scope.wrap_argv((sys.executable, "-I", "-S", "-c", code)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        **scope.popen_kwargs(),
    )
    try:
        scope.attach(process)
        deadline = time.monotonic() + 10
        while not result_path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert result_path.read_text(encoding="utf-8") == "denied"
        assert not (denied / "forbidden.txt").exists()
    finally:
        if scope.attached and not scope.closed:
            scope.terminate()
            process.wait(timeout=10)
            scope.close()
        elif process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    authority.replay()
    authority.close_after_medium_restore()
    assert _icacls(tmp_path).stdout == scratch_acl_before
    assert _icacls(denied).stdout == denied_acl_before


def test_auxiliary_lease_carries_private_authority_and_abort_closes_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = tmp_path / "provider-runtime"
    monkeypatch.setattr(
        auxiliary,
        "_default_runtime_namespace",
        lambda: namespace,
    )
    reservation = auxiliary.reserve_auxiliary_writable_root(
        attempt_id="private-attempt",
        purpose="provider-state",
    )
    lease = reservation.arm(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="private-scope",
    )
    authority = lease.windows_private_execution_root_authority
    assert authority is not None
    assert authority.path == lease.root
    receipt = lease.abort_before_process_scope(
        attempt_arm_sha256="a" * 64,
        process_scope_identity="private-scope",
        reason_code="FIXTURE_ABORT",
    )
    assert receipt["root_absent_after"] is True
    assert lease.windows_private_execution_root_authority is None
    assert not lease.root.exists()


def test_real_wer_provider_uses_private_root_without_scratch_acl_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch_acl_before = _icacls(tmp_path).stdout
    real_create = worker_receipts.create_windows_private_execution_root
    observed: list[object] = []
    observed_bindings: list[dict[str, object]] = []

    def capture(path: Path) -> object:
        authority = real_create(path)
        observed.append(authority)
        observed_bindings.append(authority.binding)
        return authority

    monkeypatch.setattr(
        worker_receipts,
        "create_windows_private_execution_root",
        capture,
    )
    completed = worker_fixtures._run(tmp_path)
    assert completed.completion_sha256
    assert len(observed) == 1
    binding = observed_bindings[0]
    assert binding["protocol"] == "WINDOWS_RETAINED_PRIVATE_EXECUTION_ROOT_V1"
    with pytest.raises(WindowsPrivateExecutionRootError, match="closed"):
        observed[0].replay()  # type: ignore[attr-defined]
    assert _icacls(tmp_path).stdout == scratch_acl_before
    output = tmp_path / "worker-out"
    moved = tmp_path / "worker-out-moved"
    os.replace(output, moved)
    os.replace(moved, output)


def test_real_command_capable_claude_fixture_uses_private_mic_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        claude_runtime_fixtures.A,
        "_default_runtime_namespace",
        lambda: claude_runtime_fixtures._fixture_runtime_namespace(tmp_path),
    )
    claude_runtime_fixtures.provider_fixtures._install_observers(
        monkeypatch,
        Path(sys.executable).resolve(strict=True),
    )
    monkeypatch.setattr(
        worker_receipts,
        "_recheck_claude_executable_before_launch",
        lambda *_args, **_kwargs: None,
    )
    case = claude_runtime_fixtures._case(
        tmp_path,
        label="private-mic-claude",
    )
    scratch_acl_before = _icacls(tmp_path).stdout
    provider_calls = claude_runtime_fixtures._install_fake_cli(
        monkeypatch,
        (case,),
    )
    observed: list[object] = []
    real_create = worker_receipts.create_windows_private_execution_root

    def capture(path: Path) -> object:
        authority = real_create(path)
        observed.append(authority)
        return authority

    monkeypatch.setattr(
        worker_receipts,
        "create_windows_private_execution_root",
        capture,
    )
    completed = worker_receipts.run_observed_worker(**case.wer_kwargs())
    monkeypatch.undo()
    assert completed.completion_sha256
    assert provider_calls
    assert len(observed) == 1
    assert _icacls(tmp_path).stdout == scratch_acl_before
    with pytest.raises(WindowsPrivateExecutionRootError, match="closed"):
        observed[0].replay()  # type: ignore[attr-defined]
