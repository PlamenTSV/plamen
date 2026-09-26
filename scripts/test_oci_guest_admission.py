"""Fake-only adversarial tests for the governed OCI guest admission boundary."""

from __future__ import annotations

from contextlib import contextmanager
import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import pickle
import re
import stat
import tempfile
import threading

import pytest

import oci_guest_admission as O


class _ReplayLedger:
    """Test double only; production must inject a crash-safe atomic store."""
    def __init__(self) -> None:
        self.rows: dict[str, str] = {}
        self.lock = threading.Lock()

    def consume(self, attempt: str, digest: str) -> bool:
        with self.lock:
            if attempt in self.rows:
                return False
            self.rows[attempt] = digest
            return True


class _Revalidator:
    def __init__(self, observed: tuple[O.RevalidatedMount, ...] | None = None) -> None:
        self.observed = observed
        self.active = False

    def create_with_leases(self, attempt: str, mounts: tuple[O.MountBinding, ...], view: O.GuestLaunchAdmission, launcher):
        self.active = True
        try:
            observed = self.observed or tuple(
                O.RevalidatedMount(row.source_root_identity, row.source_identity)
                for row in mounts
            )
            expected = tuple(O.RevalidatedMount(row.source_root_identity, row.source_identity) for row in mounts)
            if observed != expected:
                raise O.GuestAdmissionError("mount source identity changed before provider create")
            pins = tuple(
                O.PinnedProviderMount(
                    row.purpose, row.destination, row.mode,
                    O.PinnedSourceReference("pin:" + f"{index * 2 + 1:064x}", 42, 500 + index, "root", row.source_root_identity),
                    O.PinnedSourceReference("pin:" + f"{index * 2 + 2:064x}", 42, 600 + index, "source", row.source_identity),
                )
                for index, row in enumerate(mounts)
            )
            outcome = launcher(view, pins)
            if type(outcome) is not O.ProviderCreateResult:
                raise O.GuestAdmissionError("provider create did not return a typed mount receipt")
            required = O.ProviderCreateReceipt(
                attempt,
                tuple(O.CreatedMountReceipt(row.purpose, row.destination, row.mode, row.source_root_identity, row.source_identity) for row in mounts),
            )
            if outcome.receipt != required:
                raise O.GuestAdmissionError("created mounts differ from the held source leases")
            return outcome.value
        finally:
            self.active = False


class _PinningAuthority:
    def __init__(
        self, *, supported: bool = True, unsafe_inodes: set[int] | None = None,
        mount_id: int = 700, mount_proof_available: bool = True,
    ) -> None:
        self.supported = supported
        self.counter = 0
        self.unsafe_inodes = unsafe_inodes or set()
        self.mount_id = mount_id
        self.mount_proof_available = mount_proof_available

    def supports_descriptor_mounts(self) -> bool:
        return self.supported

    def source_metadata_is_safe(self, _fd: int, status: os.stat_result) -> bool:
        return status.st_ino not in self.unsafe_inodes

    def native_mount_proof(self, _directory_fd: int) -> O.NativeMountProof | None:
        if not self.mount_proof_available:
            return None
        status = os.fstat(_directory_fd)
        return O.NativeMountProof(
            status.st_dev, status.st_ino, self.mount_id,
            "PROVIDER_AUTHENTICATED_MOUNT_ID", "e" * 64, True, True
        )

    @contextmanager
    def acquire_pin(self, **_kwargs: object):
        self.counter += 1
        yield "pin:" + f"{self.counter:064x}"


class _Supervisor:
    """Test double; production must persist and recover armed attempts."""
    def __init__(self, *, fail: str | None = None, secret: str = "") -> None:
        self.fail = fail
        self.secret = secret
        self.calls: list[tuple[str, str]] = []

    def _transition(self, name: str, cgroup: O.CgroupAuthority) -> bool:
        self.calls.append((name, cgroup.provider_attempt_id))
        if self.fail == name:
            raise RuntimeError(self.secret or f"{name} failed")
        return True

    def arm(self, cgroup: O.CgroupAuthority, _receipt_sha256: str) -> bool:
        return self._transition("arm", cgroup)

    def mark_running(self, cgroup: O.CgroupAuthority) -> bool:
        return self._transition("running", cgroup)

    def mark_terminal(self, cgroup: O.CgroupAuthority, _receipt_sha256: str) -> bool:
        return self._transition("terminal", cgroup)


def _identity(seed: str = "7", *, inode: int = 101) -> O.SourceIdentity:
    return O.SourceIdentity(
        device=42,
        inode=inode,
        uid=501,
        gid=20,
        mode=0o700,
        object_kind="directory",
        snapshot_format=O.SOURCE_SNAPSHOT_FORMAT,
        snapshot_sha256=seed * 64,
        regular_file_count=0,
        directory_count=1,
        total_bytes=0,
        max_depth=0,
        native_mount_id=700,
        native_mount_id_kind="PROVIDER_AUTHENTICATED_MOUNT_ID",
        mount_topology_sha256="e" * 64,
        mount_proof_authenticated=True,
        submounts_absent=True,
        symlink_entries_absent=True,
        special_files_absent=True,
        hardlinks_absent=True,
        xattrs_absent=True,
        compressed_files_absent=True,
    )


def _expectation() -> O.GuestAdmissionExpectation:
    attempt = "attempt-oci-001"
    mounts = (
        O.MountBinding(
            source_root="/Users/alice/work/dodo",
            source_root_identity=_identity("7", inode=101),
            source="/Users/alice/work/dodo",
            source_identity=_identity("7", inode=101),
            destination="/workspace/project", mode="ro", purpose="project-source",
        ),
        O.MountBinding(
            source_root="/Users/alice/work/plamen-runtime",
            source_root_identity=_identity("8", inode=102),
            source="/Users/alice/work/plamen-runtime",
            source_identity=_identity("8", inode=102),
            destination="/opt/plamen", mode="ro", purpose="runtime",
        ),
        O.MountBinding(
            source_root="/Users/alice/work/dodo-scratch",
            source_root_identity=_identity("9", inode=103),
            source="/Users/alice/work/dodo-scratch",
            source_identity=_identity("9", inode=103),
            destination="/workspace/scratch", mode="rw", purpose="scratchpad",
        ),
    )
    return O.GuestAdmissionExpectation(
        image_manifest_digest="sha256:" + "1" * 64,
        config_sha256="2" * 64,
        launch_envelope_sha256="3" * 64,
        runtime_closure_sha256="4" * 64,
        provider_attempt_id=attempt,
        helpers=(
            O.HelperBinding("/opt/plamen/scripts/linux_cgroup_exec.py", "5" * 64),
            O.HelperBinding("/opt/plamen/scripts/plamen_driver.py", "6" * 64),
        ),
        mounts=mounts,
        cgroup=O.CgroupAuthority(
            path=f"/sys/fs/cgroup/plamen/{attempt}", filesystem_device=55,
            inode=901, identity_sha256="a" * 64, provider_attempt_id=attempt,
        ),
        landlock=O.LandlockAuthority(abi_version=5, ruleset_sha256="b" * 64),
        execution=O.ExecutionAuthority(
            uid=1000, gid=1000, seccomp_profile_sha256="c" * 64,
            network_policy_sha256="d" * 64,
        ),
        host_home="/Users/alice",
    )


def _identity_dict(value: O.SourceIdentity) -> dict[str, object]:
    return {
        "device": value.device, "inode": value.inode, "uid": value.uid, "gid": value.gid,
        "mode": value.mode, "object_kind": value.object_kind,
        "snapshot_format": value.snapshot_format,
        "snapshot_sha256": value.snapshot_sha256,
        "regular_file_count": value.regular_file_count,
        "directory_count": value.directory_count,
        "total_bytes": value.total_bytes,
        "max_depth": value.max_depth,
        "native_mount_id": value.native_mount_id,
        "native_mount_id_kind": value.native_mount_id_kind,
        "mount_topology_sha256": value.mount_topology_sha256,
        "mount_proof_authenticated": value.mount_proof_authenticated,
        "submounts_absent": value.submounts_absent,
        "symlink_entries_absent": value.symlink_entries_absent,
        "special_files_absent": value.special_files_absent,
        "hardlinks_absent": value.hardlinks_absent,
        "xattrs_absent": value.xattrs_absent,
        "compressed_files_absent": value.compressed_files_absent,
    }


def _receipt(expected: O.GuestAdmissionExpectation | None = None) -> dict[str, object]:
    expected = expected or _expectation()
    cgroup, landlock, execution = expected.cgroup, expected.landlock, expected.execution
    return {
        "schema": O.SCHEMA,
        "image": {"manifest_digest": expected.image_manifest_digest, "platform": {"os": "linux", "architecture": "arm64"}},
        "bindings": {
            "config_sha256": expected.config_sha256,
            "launch_envelope_sha256": expected.launch_envelope_sha256,
            "runtime_closure_sha256": expected.runtime_closure_sha256,
            "provider_attempt_id": expected.provider_attempt_id,
            "helpers": [{"path": row.path, "sha256": row.sha256} for row in expected.helpers],
        },
        "rootfs": {"readonly": True},
        "mounts": [{
            "kind": row.kind, "source_root": row.source_root,
            "source_root_identity": _identity_dict(row.source_root_identity),
            "source": row.source, "source_identity": _identity_dict(row.source_identity),
            "destination": row.destination, "mode": row.mode, "purpose": row.purpose,
        } for row in expected.mounts],
        "capabilities": {
            "cgroup_v2": {
                "filesystem": cgroup.filesystem, "path": cgroup.path,
                "filesystem_device": cgroup.filesystem_device, "inode": cgroup.inode,
                "identity_sha256": cgroup.identity_sha256,
                "provider_attempt_id": cgroup.provider_attempt_id,
                "delegated": cgroup.delegated, "provider_owns_tree": cgroup.provider_owns_tree,
                "pre_execution_assignment": cgroup.pre_execution_assignment,
                "cgroup_type": cgroup.cgroup_type, "cgroup_kill": cgroup.cgroup_kill,
                "termination_scope": cgroup.termination_scope,
                "exhaustive_descendant_termination_authority": cgroup.exhaustive_descendant_termination_authority,
            },
            "landlock": {
                "abi_version": landlock.abi_version,
                "handled_access_fs": list(landlock.handled_access_fs),
                "ruleset_sha256": landlock.ruleset_sha256, "active": landlock.active,
                "ruleset_status": landlock.ruleset_status, "no_new_privs": landlock.no_new_privs,
                "thread_state": landlock.thread_state,
                "restricted_thread_count": landlock.restricted_thread_count,
                "allowed_write_paths": list(landlock.allowed_write_paths),
                "write_confinement": landlock.write_confinement,
                "exhaustive_write_confinement_authority": landlock.exhaustive_write_confinement_authority,
            },
        },
        "execution": {
            "uid": execution.uid, "gid": execution.gid,
            "supplemental_groups": list(execution.supplemental_groups),
            "capabilities_drop": list(execution.capabilities_drop),
            "capabilities_add": list(execution.capabilities_add),
            "inherited_environment": execution.inherited_environment,
            "ssh_agent_forwarding": execution.ssh_agent_forwarding,
            "published_sockets": list(execution.published_sockets),
            "host_devices": list(execution.host_devices),
            "nested_virtualization": execution.nested_virtualization,
            "init": execution.init, "no_new_privileges": execution.no_new_privileges,
            "seccomp_status": execution.seccomp_status,
            "seccomp_profile_sha256": execution.seccomp_profile_sha256,
            "masked_paths": list(execution.masked_paths),
            "readonly_paths": list(execution.readonly_paths),
            "network_mode": execution.network_mode,
            "network_enforcement": execution.network_enforcement,
            "network_policy_sha256": execution.network_policy_sha256,
            "no_dns": execution.no_dns,
        },
    }


def _raw(receipt: dict[str, object]) -> bytes:
    return O.canonical_receipt_bytes(receipt)


def _admit(
    expected: O.GuestAdmissionExpectation | None = None,
    receipt: dict[str, object] | None = None,
    ledger: _ReplayLedger | None = None,
    termination_observer: object | None = None,
    supervisor: object | None = None,
):
    expected = expected or _expectation()
    return O.admit_oci_guest(
        _raw(receipt or _receipt(expected)), expected,
        replay_consumer=ledger or _ReplayLedger(),
        termination_observer=termination_observer or _TerminationObserver(),
        durable_supervisor=supervisor or _Supervisor(),
    )


def _create_result(expected: O.GuestAdmissionExpectation, value: object = "created") -> O.ProviderCreateResult[object]:
    return O.ProviderCreateResult(
        value,
        O.ProviderCreateReceipt(
            expected.provider_attempt_id,
            tuple(
                O.CreatedMountReceipt(row.purpose, row.destination, row.mode, row.source_root_identity, row.source_identity)
                for row in expected.mounts
            ),
        ),
    )


def _assert_sanitized(error: BaseException, secret: str) -> None:
    assert secret not in str(error)
    assert len(str(error)) < 200
    assert error.__cause__ is None
    assert error.__context__ is None


def test_valid_receipt_launches_once_under_lease_and_view_expires() -> None:
    expected = _fresh_filesystem_expectation()
    raw = _raw(_receipt(expected))
    capability = O.admit_oci_guest(raw, expected, replay_consumer=_ReplayLedger(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())
    revalidator = _trusted_revalidator()
    escaped: list[O.GuestLaunchAdmission] = []

    def launch(view: O.GuestLaunchAdmission, _pins: tuple[O.PinnedProviderMount, ...]) -> O.ProviderCreateResult[str]:
        assert all(pin.source.handle.startswith("pin:") for pin in _pins)
        assert view.provider_attempt_id == expected.provider_attempt_id
        assert view.receipt_sha256 == hashlib.sha256(raw).hexdigest()
        assert view.landlock.abi_version == 5
        assert view.execution.network_mode == "GOVERNED_PROXY_ONLY"
        escaped.append(view)
        return _create_result(expected, "created")  # type: ignore[return-value]

    launched = capability.consume_for_launch(expected, source_revalidator=revalidator, launcher=launch)
    assert launched.value == "created"
    assert type(launched.termination) is O.CgroupTerminationCapability
    assert capability.consumed is True
    with pytest.raises(O.GuestAdmissionError, match="no longer active"):
        _ = escaped[0].provider_attempt_id
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        capability.consume_for_launch(expected, source_revalidator=revalidator, launcher=launch)


def test_launch_rebinding_failure_does_not_consume_local_capability() -> None:
    expected = _fresh_filesystem_expectation()
    capability = _admit(expected)
    changed = replace(expected, config_sha256="e" * 64)
    with pytest.raises(O.GuestAdmissionError, match="launch values differ"):
        capability.consume_for_launch(changed, source_revalidator=_trusted_revalidator(), launcher=lambda _view, _pins: _create_result(changed))
    assert capability.consumed is False


def test_single_consumer_is_atomic_across_threads() -> None:
    expected = _fresh_filesystem_expectation()
    capability = _admit(expected)
    successes: list[str] = []
    failures: list[BaseException] = []

    def consume() -> None:
        try:
            successes.append(capability.consume_for_launch(expected, source_revalidator=_trusted_revalidator(), launcher=lambda _view, _pins: _create_result(expected, "ok")).value)
        except BaseException as exc:
            failures.append(exc)

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert successes == ["ok"]
    assert len(failures) == 7
    assert all(isinstance(exc, O.GuestAdmissionError) for exc in failures)


def test_persistent_replay_consumer_is_required_and_duplicate_fails() -> None:
    expected, ledger = _expectation(), _ReplayLedger()
    raw = _raw(_receipt(expected))
    with pytest.raises(O.GuestAdmissionError, match="persistent atomic replay"):
        O.admit_oci_guest(raw, expected, replay_consumer=None, termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())  # type: ignore[arg-type]
    O.admit_oci_guest(raw, expected, replay_consumer=ledger, termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        O.admit_oci_guest(raw, expected, replay_consumer=ledger, termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())

    changed = replace(expected, image_manifest_digest="sha256:" + "e" * 64)
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        O.admit_oci_guest(_raw(_receipt(changed)), changed, replay_consumer=ledger, termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())


def test_terminal_observer_is_bound_at_admission_and_required() -> None:
    expected = _expectation()
    with pytest.raises(O.GuestAdmissionError, match="bound cgroup kill observer"):
        O.admit_oci_guest(
            _raw(_receipt(expected)), expected, replay_consumer=_ReplayLedger(),
            termination_observer=None, durable_supervisor=_Supervisor(),  # type: ignore[arg-type]
        )


def test_durable_supervisor_is_bound_at_admission_and_required() -> None:
    expected = _expectation()
    with pytest.raises(O.GuestAdmissionError, match="durable launch supervisor"):
        O.admit_oci_guest(
            _raw(_receipt(expected)), expected, replay_consumer=_ReplayLedger(),
            termination_observer=_TerminationObserver(), durable_supervisor=None,  # type: ignore[arg-type]
        )


def test_replay_consumer_exception_and_non_boolean_fail_closed() -> None:
    expected, raw = _expectation(), _raw(_receipt())

    class Broken:
        def consume(self, *_args: object) -> bool:
            raise OSError("secret storage detail")

    class Truthy:
        def consume(self, *_args: object) -> int:
            return 1

    with pytest.raises(O.GuestAdmissionError, match="replay consumption failed") as caught:
        O.admit_oci_guest(raw, expected, replay_consumer=Broken(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())
    assert caught.value.__cause__ is None
    assert "secret storage detail" not in str(caught.value)
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        O.admit_oci_guest(raw, expected, replay_consumer=Truthy(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())


def test_direct_capability_and_launch_view_forging_surfaces_are_closed() -> None:
    assert not hasattr(O.OciGuestAdmission, "_issue")
    assert not hasattr(O, "_LAUNCH_SEAL")
    with pytest.raises(TypeError, match="issued"):
        O.OciGuestAdmission()
    with pytest.raises(TypeError, match="launcher callback"):
        O.GuestLaunchAdmission(schema=O.SCHEMA)
    forged_capability = object.__new__(O.OciGuestAdmission)
    with pytest.raises(AttributeError):
        forged_capability._expectation = _expectation()  # type: ignore[attr-defined]
    with pytest.raises(O.GuestAdmissionError, match="issued OCI"):
        _ = forged_capability.consumed
    with pytest.raises(O.GuestAdmissionError, match="issued OCI"):
        expected = _expectation()
        forged_capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: _create_result(expected),
        )
    forged = object.__new__(O.GuestLaunchAdmission)
    with pytest.raises(O.GuestAdmissionError, match="no longer active"):
        _ = forged.schema


def test_one_shot_capability_cannot_be_truth_tested_copied_or_serialized() -> None:
    capability = _admit()
    with pytest.raises(TypeError, match="consumed"):
        bool(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)


def test_unissued_revalidator_never_invokes_launcher() -> None:
    expected = _expectation()
    wrong = list(O.RevalidatedMount(row.source_root_identity, row.source_identity) for row in expected.mounts)
    wrong[0] = O.RevalidatedMount(_identity("7", inode=999), expected.mounts[0].source_identity)
    invoked: list[bool] = []
    observer, supervisor = _TerminationObserver(), _Supervisor()
    capability = _admit(expected, termination_observer=observer, supervisor=supervisor)
    with pytest.raises(O.GuestAdmissionError, match="issued descriptor/native-proof"):
        capability.consume_for_launch(expected, source_revalidator=_Revalidator(tuple(wrong)), launcher=lambda _view, _pins: invoked.append(True))
    assert invoked == []
    assert capability.consumed is False
    assert observer.calls == []
    assert supervisor.calls == []


def test_object_new_descriptor_revalidator_cannot_bypass_native_proof_issuance() -> None:
    expected = _expectation()
    forged = object.__new__(O.DescriptorSnapshotSourceRevalidator)
    object.__setattr__(forged, "_pinning_authority", _PinningAuthority())
    invoked: list[bool] = []
    capability = _admit(expected)
    with pytest.raises(O.GuestAdmissionError, match="issued descriptor/native-proof"):
        capability.consume_for_launch(
            expected, source_revalidator=forged,
            launcher=lambda _view, _pins: invoked.append(True),
        )
    assert invoked == []
    assert capability.consumed is False


def test_launcher_failure_is_ambiguously_consumed() -> None:
    expected = _fresh_filesystem_expectation()
    observer, supervisor = _TerminationObserver(), _Supervisor()
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )
    secret = "/Users/alice/.ssh/id_ed25519 --proxy-token top-secret"

    def fail(_view: O.GuestLaunchAdmission, _pins: tuple[O.PinnedProviderMount, ...]) -> O.ProviderCreateResult[None]:
        assert supervisor.calls == [("arm", expected.provider_attempt_id)]
        raise TimeoutError(secret)

    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified") as caught:
        capability.consume_for_launch(expected, source_revalidator=_trusted_revalidator(), launcher=fail)
    _assert_sanitized(caught.value, secret)
    assert capability.consumed is True
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: _create_result(expected),
        )


def test_ambiguous_supervisor_arm_is_burned_and_kill_is_attempted() -> None:
    expected = _fresh_filesystem_expectation()
    secret = "/private/supervisor-arm TOKEN=secret"
    observer = _TerminationObserver()
    supervisor = _Supervisor(fail="arm", secret=secret)
    invoked: list[bool] = []
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )
    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified") as caught:
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: invoked.append(True),
        )
    _assert_sanitized(caught.value, secret)
    assert invoked == []
    assert capability.consumed is True
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_invalid_provider_result_is_killed_and_durably_closed() -> None:
    expected = _fresh_filesystem_expectation()
    observer, supervisor = _TerminationObserver(), _Supervisor()
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )
    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified"):
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: object(),  # type: ignore[return-value]
        )
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_revalidator_exception_before_provider_create_is_sanitized_without_kill() -> None:
    expected = _fresh_filesystem_expectation()
    observer, supervisor = _TerminationObserver(), _Supervisor()
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )
    secret = "/Users/alice/project --publish /private/agent.sock TOKEN=value"

    class BrokenAuthority(_PinningAuthority):
        def supports_descriptor_mounts(self) -> bool:
            raise RuntimeError(secret)

    with pytest.raises(O.GuestAdmissionError, match="before provider create") as caught:
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(BrokenAuthority()),
            launcher=lambda _view, _pins: _create_result(expected),
        )
    _assert_sanitized(caught.value, secret)
    assert capability.consumed is False
    assert observer.calls == []
    assert supervisor.calls == []


def test_running_journal_failure_kills_guest_and_sanitizes_diagnostics() -> None:
    expected = _fresh_filesystem_expectation()
    secret = "/workspace/project ARGV=secret PROXY_PASSWORD=secret"
    observer, supervisor = _TerminationObserver(), _Supervisor(
        fail="running", secret=secret
    )
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )
    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified") as caught:
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: _create_result(expected),
        )
    _assert_sanitized(caught.value, secret)
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("running", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_any_post_create_finalization_exception_kills_guest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _fresh_filesystem_expectation()
    secret = "/private/finalizer ARGV=secret"
    observer, supervisor = _TerminationObserver(), _Supervisor()
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )

    def broken_finalizer(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError(secret)

    monkeypatch.setattr(O, "LaunchedGuest", broken_finalizer)
    with pytest.raises(O.GuestAdmissionError, match="finalization failed.*cleanup was verified") as caught:
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: _create_result(expected),
        )
    _assert_sanitized(caught.value, secret)
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("running", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_ambiguous_cleanup_failure_returns_no_launch_or_termination_authority() -> None:
    expected = _fresh_filesystem_expectation()
    secret = "/private/cgroup diagnostic --token=secret"

    class BrokenObserver:
        def kill_then_observe(self, _cgroup: O.CgroupAuthority) -> object:
            raise OSError(secret)

    supervisor = _Supervisor()
    capability = _admit(
        expected, termination_observer=BrokenObserver(), supervisor=supervisor
    )
    with pytest.raises(O.GuestAdmissionError, match="cleanup is unproven") as caught:
        capability.consume_for_launch(
            expected, source_revalidator=_trusted_revalidator(),
            launcher=lambda _view, _pins: (_ for _ in ()).throw(TimeoutError(secret)),
        )
    _assert_sanitized(caught.value, secret)
    assert capability.consumed is True
    assert supervisor.calls == [("arm", expected.provider_attempt_id)]


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("image", "manifest_digest"), "sha256:" + "e" * 64, "image manifest digest differs"),
        (("image", "platform", "os"), "darwin", "linux/arm64"),
        (("bindings", "config_sha256"), "e" * 64, "config digest differs"),
        (("rootfs", "readonly"), False, "not read-only"),
        (("capabilities", "cgroup_v2", "cgroup_type"), "threaded", "cgroup-v2 authority"),
        (("capabilities", "cgroup_v2", "cgroup_kill"), "MISSING", "cgroup-v2 authority"),
        (("capabilities", "cgroup_v2", "provider_attempt_id"), "attempt-other", "bound to the provider attempt"),
        (("capabilities", "landlock", "abi_version"), 1, "Landlock ABI"),
        (("capabilities", "landlock", "no_new_privs"), False, "Landlock authority"),
        (("capabilities", "landlock", "thread_state"), "MULTITHREADED", "Landlock authority"),
        (("capabilities", "landlock", "handled_access_fs"), list(O.LANDLOCK_HANDLED_ACCESS_FS[:-1]), "handled filesystem rights"),
        (("execution", "uid"), 0, "guest uid"),
        (("execution", "capabilities_add"), ["SYS_ADMIN"], "process/network authority"),
        (("execution", "inherited_environment"), True, "process/network authority"),
        (("execution", "ssh_agent_forwarding"), True, "process/network authority"),
        (("execution", "published_sockets"), ["/var/run/docker.sock"], "published sockets"),
        (("execution", "host_devices"), ["/dev/kvm"], "host devices"),
        (("execution", "nested_virtualization"), True, "process/network authority"),
        (("execution", "network_mode"), "internal", "process/network authority"),
        (("execution", "network_enforcement"), "APPLE_INTERNAL_FLAG", "process/network authority"),
        (("execution", "no_dns"), False, "process/network authority"),
    ],
)
def test_security_binding_tamper_is_rejected(path: tuple[str, ...], replacement: object, message: str) -> None:
    receipt = _receipt()
    cursor: object = receipt
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match=message):
        _admit(receipt=receipt)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("purpose", "anything-goes"),
        ("destination", "/usr"),
        ("destination", "/"),
        ("mode", "rw"),
    ],
)
def test_closed_mount_purpose_destination_mode_roster(field: str, value: str) -> None:
    receipt = _receipt()
    receipt["mounts"][0][field] = value  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="closed purpose policy|path alias"):
        _admit(receipt=receipt)


@pytest.mark.parametrize(
    "source",
    [
        "/etc", "/Users/bob", "/var/run", "/run/containerd/containerd.sock",
        "/Users/alice", "/Users/alice/.ssh", "/Users/alice/work/secrets",
        "/Users/alice/Library/Keychains/login.keychain-db",
        "/Users/alice/work/runtime.sock",
    ],
)
def test_broad_sensitive_and_socket_source_bindings_are_rejected(source: str) -> None:
    receipt = _receipt()
    receipt["mounts"][0]["source_root"] = source  # type: ignore[index]
    receipt["mounts"][0]["source"] = source  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="host home|governed host home|credential|socket"):
        _admit(receipt=receipt)


def test_source_must_be_inside_its_governed_root() -> None:
    receipt = _receipt()
    receipt["mounts"][0]["source_root"] = "/Users/alice/work/project-root"  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="outside its governed source root"):
        _admit(receipt=receipt)


def test_helper_must_be_strictly_under_readonly_runtime_mount() -> None:
    expected = _expectation()
    with pytest.raises(O.GuestAdmissionError, match="outside the read-only runtime"):
        replace(expected, helpers=(O.HelperBinding("/workspace/scratch/driver.py", "f" * 64),))


def test_source_snapshot_symlink_or_special_file_claim_is_rejected() -> None:
    for key in ("symlink_entries_absent", "special_files_absent"):
        receipt = _receipt()
        receipt["mounts"][0]["source_identity"][key] = False  # type: ignore[index]
        with pytest.raises(O.GuestAdmissionError, match="unsafe object"):
            _admit(receipt=receipt)


def test_constructor_bounds_match_receipt_string_bounds() -> None:
    overlong = "/" + "a" * O.MAX_STRING_BYTES
    with pytest.raises(O.GuestAdmissionError, match="byte bound"):
        O.HelperBinding(overlong, "1" * 64)
    with pytest.raises(O.GuestAdmissionError, match="byte bound"):
        replace(_expectation(), host_home=overlong)


def test_duplicate_unknown_noncanonical_and_oversized_receipts_are_rejected() -> None:
    expected = _expectation()
    canonical = _raw(_receipt(expected))
    duplicate = canonical.replace(
        b'"schema":"plamen.oci_guest_admission.v1"',
        b'"schema":"plamen.oci_guest_admission.v1","schema":"forged"', 1,
    )
    with pytest.raises(O.GuestAdmissionError, match="duplicate object key"):
        O.admit_oci_guest(duplicate, expected, replay_consumer=_ReplayLedger(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())
    unknown = _receipt(expected)
    unknown["credential_sha256"] = "f" * 64
    with pytest.raises(O.GuestAdmissionError, match="keys are invalid"):
        _admit(expected, unknown)
    with pytest.raises(O.GuestAdmissionError, match="not canonical"):
        O.admit_oci_guest(json.dumps(_receipt(expected), indent=2).encode(), expected, replay_consumer=_ReplayLedger(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())
    with pytest.raises(O.GuestAdmissionError, match="byte ceiling"):
        O.admit_oci_guest(canonical + b" " * O.MAX_RECEIPT_BYTES, expected, replay_consumer=_ReplayLedger(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())


def test_huge_duplicate_key_is_bounded_before_detail_and_never_reflected() -> None:
    huge = b"x" * 30_000
    raw = b'{"' + huge + b'":1,"' + huge + b'":2}\n'
    with pytest.raises(O.GuestAdmissionError, match="object key exceeds") as caught:
        O.admit_oci_guest(raw, _expectation(), replay_consumer=_ReplayLedger(), termination_observer=_TerminationObserver(), durable_supervisor=_Supervisor())
    assert len(str(caught.value)) < 160
    assert caught.value.__cause__ is None
    assert "x" * 100 not in str(caught.value)


def test_receipt_input_objects_are_not_mutated() -> None:
    receipt = _receipt()
    before = copy.deepcopy(receipt)
    _admit(receipt=receipt)
    assert receipt == before


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("init", False),
        ("no_new_privileges", False),
        ("seccomp_status", "UNCONFINED"),
        ("masked_paths", []),
        ("readonly_paths", []),
    ],
)
def test_init_seccomp_and_exact_protected_paths_are_required(field: str, replacement: object) -> None:
    receipt = _receipt()
    receipt["execution"][field] = replacement  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="process/network authority"):
        _admit(receipt=receipt)


def test_governed_source_trees_may_not_overlap() -> None:
    receipt = _receipt()
    receipt["mounts"][2]["source_root"] = "/Users/alice/work/dodo/scratch"  # type: ignore[index]
    receipt["mounts"][2]["source"] = "/Users/alice/work/dodo/scratch"  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="source trees overlap"):
        _admit(receipt=receipt)


def _filesystem_identity(path: Path) -> O.SourceIdentity:
    return O.snapshot_source_identity(str(path), metadata_authority=_PinningAuthority())


def _filesystem_expectation(tmp_path: Path, *, symlink_project: bool = False) -> O.GuestAdmissionExpectation:
    home = tmp_path / "home"
    home.mkdir()
    project_real = home / "project-real"
    project_real.mkdir()
    project = home / "project"
    if symlink_project:
        project.symlink_to(project_real, target_is_directory=True)
    else:
        project.mkdir()
    runtime = home / "runtime"
    runtime.mkdir()
    scratch = home / "scratch"
    scratch.mkdir()
    paths = (project, runtime, scratch)
    policies = (("/workspace/project", "ro", "project-source"), ("/opt/plamen", "ro", "runtime"), ("/workspace/scratch", "rw", "scratchpad"))
    mounts = tuple(
        O.MountBinding(
            source_root=str(path), source_root_identity=_filesystem_identity(project_real if symlink_project and path == project else path),
            source=str(path), source_identity=_filesystem_identity(project_real if symlink_project and path == project else path),
            destination=destination, mode=mode, purpose=purpose,
        )
        for path, (destination, mode, purpose) in zip(paths, policies, strict=True)
    )
    return replace(_expectation(), mounts=mounts, host_home=str(home))


_TEMPORARY_LAUNCH_TREES: list[tempfile.TemporaryDirectory[str]] = []


def _fresh_filesystem_expectation() -> O.GuestAdmissionExpectation:
    lease = tempfile.TemporaryDirectory(prefix="plamen-oci-admission-test-")
    _TEMPORARY_LAUNCH_TREES.append(lease)
    # macOS spells its temporary directory through the /var -> /private/var
    # compatibility symlink.  Resolve the test root so the production
    # componentwise O_NOFOLLOW walk sees the canonical native path.
    return _filesystem_expectation(Path(lease.name).resolve())


def _trusted_revalidator(
    authority: _PinningAuthority | None = None,
) -> O.DescriptorSnapshotSourceRevalidator:
    return O.DescriptorSnapshotSourceRevalidator(authority or _PinningAuthority())


def test_componentwise_nofollow_revalidation_rejects_symlink(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path, symlink_project=True)
    capability = _admit(expected)
    with pytest.raises(O.GuestAdmissionError, match="source validation"):
        capability.consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(_PinningAuthority()),
            launcher=lambda _view, _pins: pytest.fail("launcher must not run"),
        )


def test_path_retarget_between_admission_and_create_is_detected(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path)
    capability = _admit(expected)
    project = Path(expected.mounts[0].source)
    project.rename(project.with_name("project-old"))
    project.mkdir()
    with pytest.raises(O.GuestAdmissionError, match="source validation"):
        capability.consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(_PinningAuthority()),
            launcher=lambda _view, _pins: pytest.fail("launcher must not run"),
        )


def test_descriptor_revalidator_requires_external_snapshot_lease() -> None:
    with pytest.raises(O.GuestAdmissionError, match="descriptor-pinning authority"):
        O.DescriptorSnapshotSourceRevalidator(None)  # type: ignore[arg-type]


def test_descriptor_revalidator_refuses_authority_without_native_mount_proof() -> None:
    class LegacyAuthority:
        def supports_descriptor_mounts(self) -> bool:
            return True

        def source_metadata_is_safe(self, _fd: int, _status: os.stat_result) -> bool:
            return True

        @contextmanager
        def acquire_pin(self, **_kwargs: object):
            yield "pin:" + "1" * 64

    with pytest.raises(O.GuestAdmissionError, match="descriptor-pinning authority"):
        O.DescriptorSnapshotSourceRevalidator(LegacyAuthority())  # type: ignore[arg-type]


def test_snapshot_refuses_absent_authenticated_native_mount_proof(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    with pytest.raises(O.GuestAdmissionError, match="native mount-ID/no-submount"):
        O.snapshot_source_identity(
            str(project),
            metadata_authority=_PinningAuthority(mount_proof_available=False),
        )


def test_native_mount_proof_must_bind_the_same_descriptor(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()

    class WrongDescriptorProof(_PinningAuthority):
        def native_mount_proof(self, directory_fd: int) -> O.NativeMountProof:
            status = os.fstat(directory_fd)
            return O.NativeMountProof(
                status.st_dev, status.st_ino + 1, self.mount_id,
                "PROVIDER_AUTHENTICATED_MOUNT_ID", "e" * 64, True, True,
            )

    with pytest.raises(O.GuestAdmissionError, match="different source descriptor"):
        O.snapshot_source_identity(
            str(project), metadata_authority=WrongDescriptorProof()
        )


def test_native_mount_proof_exception_is_sanitized(tmp_path: Path) -> None:
    secret = "/private/mountinfo provider diagnostics TOKEN=secret"
    project = tmp_path / "project"
    project.mkdir()

    class BrokenMountProof(_PinningAuthority):
        def native_mount_proof(self, _directory_fd: int) -> O.NativeMountProof:
            raise RuntimeError(secret)

    with pytest.raises(O.GuestAdmissionError, match="proof is unavailable") as caught:
        O.snapshot_source_identity(
            str(project), metadata_authority=BrokenMountProof()
        )
    _assert_sanitized(caught.value, secret)


def test_same_device_different_native_mount_id_rejects_before_create(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path)
    replacement_authority = _PinningAuthority(mount_id=701)
    replacement = O.snapshot_source_identity(
        expected.mounts[0].source, metadata_authority=replacement_authority
    )
    assert replacement.device == expected.mounts[0].source_identity.device
    assert replacement.native_mount_id != expected.mounts[0].source_identity.native_mount_id
    observer, supervisor, invoked = _TerminationObserver(), _Supervisor(), []
    capability = _admit(
        expected, termination_observer=observer, supervisor=supervisor
    )
    with pytest.raises(O.GuestAdmissionError, match="source validation"):
        capability.consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(
                replacement_authority
            ),
            launcher=lambda _view, _pins: invoked.append(True),
        )
    assert invoked == []
    assert observer.calls == []
    assert supervisor.calls == []


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("native_mount_id", 701),
        ("mount_topology_sha256", "f" * 64),
        ("submounts_absent", False),
        ("mount_proof_authenticated", False),
    ],
)
def test_receipt_mount_topology_proof_is_exact_and_authenticated(
    field: str, replacement: object
) -> None:
    receipt = _receipt()
    receipt["mounts"][0]["source_identity"][field] = replacement  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="mount roster differs|no-submount proof"):
        _admit(receipt=receipt)


def test_descriptor_boundary_sanitizes_pinning_authority_exception() -> None:
    secret = "/Users/alice/.ssh/id_rsa --publish /tmp/agent.sock PROXY=secret"

    class BrokenAuthority(_PinningAuthority):
        def supports_descriptor_mounts(self) -> bool:
            raise RuntimeError(secret)

    expected = _expectation()
    view = object.__new__(O.GuestLaunchAdmission)
    with pytest.raises(O.GuestAdmissionError, match="validation/create failed") as caught:
        O.DescriptorSnapshotSourceRevalidator(BrokenAuthority()).create_with_leases(
            expected.provider_attempt_id, expected.mounts, view,
            lambda _view, _pins: _create_result(expected),
        )
    _assert_sanitized(caught.value, secret)


def test_snapshot_boundary_sanitizes_metadata_authority_exception(tmp_path: Path) -> None:
    secret = "/Users/alice/credentials provider-argv proxy-token"
    project = tmp_path / "project"
    project.mkdir()

    class BrokenMetadata(_PinningAuthority):
        def source_metadata_is_safe(self, _fd: int, _status: os.stat_result) -> bool:
            raise RuntimeError(secret)

    with pytest.raises(O.GuestAdmissionError, match="metadata proof failed") as caught:
        O.snapshot_source_identity(str(project), metadata_authority=BrokenMetadata())
    _assert_sanitized(caught.value, secret)


def test_unsupported_descriptor_mount_pinning_refuses_before_create(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path)
    invoked: list[bool] = []
    with pytest.raises(O.GuestAdmissionError, match="source validation"):
        _admit(expected).consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(_PinningAuthority(supported=False)),
            launcher=lambda _view, _pins: invoked.append(True),
        )
    assert invoked == []


def test_rename_replacement_during_create_breaks_retained_parent_name_identity(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path)
    project = Path(expected.mounts[0].source)
    pinner = _PinningAuthority()

    def replace_during_create(view: O.GuestLaunchAdmission, pins: tuple[O.PinnedProviderMount, ...]):
        assert not hasattr(view, "mounts")
        assert all(pin.source.handle.startswith("pin:") for pin in pins)
        project.rename(project.with_name("project-held"))
        project.mkdir()
        return _create_result(expected, "claimed-held-mounted")

    observer, supervisor = _TerminationObserver(), _Supervisor()
    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified"):
        _admit(expected, termination_observer=observer, supervisor=supervisor).consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(pinner),
            launcher=replace_during_create,
        )
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_created_mount_receipt_must_match_held_content_identity(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path)

    def wrong_receipt(_view: O.GuestLaunchAdmission, _pins: tuple[O.PinnedProviderMount, ...]):
        rows = list(_create_result(expected).receipt.mounts)
        rows[0] = replace(rows[0], source_identity=replace(rows[0].source_identity, inode=rows[0].source_identity.inode + 1))
        return O.ProviderCreateResult("wrong", O.ProviderCreateReceipt(expected.provider_attempt_id, tuple(rows)))

    observer, supervisor = _TerminationObserver(), _Supervisor()
    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified"):
        _admit(expected, termination_observer=observer, supervisor=supervisor).consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(_PinningAuthority()),
            launcher=wrong_receipt,
        )
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_held_tree_mutation_during_create_is_detected_after_receipt(tmp_path: Path) -> None:
    expected = _filesystem_expectation(tmp_path)
    project = Path(expected.mounts[0].source)

    def mutate_held_tree(_view: O.GuestLaunchAdmission, _pins: tuple[O.PinnedProviderMount, ...]):
        (project / "late.txt").write_text("late", encoding="utf-8")
        return _create_result(expected)

    observer, supervisor = _TerminationObserver(), _Supervisor()
    with pytest.raises(O.GuestAdmissionError, match="cleanup was verified"):
        _admit(expected, termination_observer=observer, supervisor=supervisor).consume_for_launch(
            expected,
            source_revalidator=O.DescriptorSnapshotSourceRevalidator(_PinningAuthority()),
            launcher=mutate_held_tree,
        )
    assert observer.calls == [expected.cgroup]
    assert supervisor.calls == [
        ("arm", expected.provider_attempt_id),
        ("terminal", expected.provider_attempt_id),
    ]


def test_off_tree_hardlink_is_rejected_by_exact_tree_census(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    credential = tmp_path / "credential"
    credential.write_text("secret", encoding="utf-8")
    os.link(credential, project / "copied-credential")
    with pytest.raises(O.GuestAdmissionError, match="multiple hard links"):
        O.snapshot_source_identity(str(project), metadata_authority=_PinningAuthority())


@pytest.mark.parametrize("hazard", ["xattr", "compression"])
def test_xattr_and_compression_proof_failure_is_rejected(tmp_path: Path, hazard: str) -> None:
    project = tmp_path / hazard
    project.mkdir()
    payload = project / "payload"
    payload.write_bytes(b"payload")
    authority = _PinningAuthority(unsafe_inodes={payload.stat().st_ino})
    with pytest.raises(O.GuestAdmissionError, match="xattrs or compressed"):
        O.snapshot_source_identity(str(project), metadata_authority=authority)


def test_tree_census_is_exact_and_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "project"
    nested = project / "nested"
    nested.mkdir(parents=True)
    (project / "one").write_bytes(b"1")
    (nested / "two").write_bytes(b"22")
    identity = O.snapshot_source_identity(str(project), metadata_authority=_PinningAuthority())
    assert (identity.regular_file_count, identity.directory_count, identity.total_bytes, identity.max_depth) == (2, 2, 3, 1)
    monkeypatch.setattr(O, "MAX_TREE_ENTRIES", 1)
    with pytest.raises(O.GuestAdmissionError, match="entry bound"):
        O.snapshot_source_identity(str(project), metadata_authority=_PinningAuthority())


class _TerminationObserver:
    def __init__(self, observation: O.CgroupTerminationObservation | None = None) -> None:
        self.observation = observation
        self.calls: list[O.CgroupAuthority] = []

    def kill_then_observe(self, cgroup: O.CgroupAuthority) -> O.CgroupTerminationObservation:
        self.calls.append(cgroup)
        return self.observation or O.CgroupTerminationObservation(
            provider_attempt_id=cgroup.provider_attempt_id,
            cgroup_path=cgroup.path,
            filesystem_device=cgroup.filesystem_device,
            inode=cgroup.inode,
            identity_sha256=cgroup.identity_sha256,
            kill_write_sha256=O.CGROUP_KILL_WRITE_SHA256,
            kill_generation=41,
            events_read_generation=42,
            cgroup_events=b"populated 0\nfrozen 0\n",
        )


def _launched(
    expected: O.GuestAdmissionExpectation | None = None,
    observer: _TerminationObserver | None = None,
    supervisor: _Supervisor | None = None,
) -> O.LaunchedGuest[object]:
    expected = expected or _fresh_filesystem_expectation()
    return _admit(
        expected, termination_observer=observer or _TerminationObserver(),
        supervisor=supervisor or _Supervisor(),
    ).consume_for_launch(
        expected, source_revalidator=_trusted_revalidator(),
        launcher=lambda _view, _pins: _create_result(expected),
    )


def test_terminal_capability_is_issued_after_launch_and_one_shot() -> None:
    observer = _TerminationObserver()
    supervisor = _Supervisor()
    launched = _launched(observer=observer, supervisor=supervisor)
    evidence = launched.termination.terminate()
    assert evidence.populated == 0
    assert evidence.kill_generation == 41
    assert evidence.events_read_generation == 42
    assert observer.calls == [_expectation().cgroup]
    assert supervisor.calls == [
        ("arm", _expectation().provider_attempt_id),
        ("running", _expectation().provider_attempt_id),
        ("terminal", _expectation().provider_attempt_id),
    ]
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        launched.termination.terminate()


def test_fabricated_terminal_receipt_or_capability_cannot_authorize() -> None:
    assert not hasattr(O, "verify_cgroup_terminal_evidence")
    forged = object.__new__(O.CgroupTerminationCapability)
    with pytest.raises(AttributeError):
        forged._cgroup = _expectation().cgroup  # type: ignore[attr-defined]
    with pytest.raises(O.GuestAdmissionError, match="issued cgroup termination"):
        forged.terminate()
    with pytest.raises(TypeError, match="issued by a termination"):
        O.CgroupTerminalEvidence(populated=0)
    forged_evidence = object.__new__(O.CgroupTerminalEvidence)
    with pytest.raises(O.GuestAdmissionError, match="issued terminal evidence"):
        _ = forged_evidence.populated


def test_terminal_observer_exception_is_sanitized_and_capability_is_burned() -> None:
    secret = "/sys/fs/cgroup/private ARGV=secret PROXY=secret"

    class BrokenObserver(_TerminationObserver):
        def kill_then_observe(self, _cgroup: O.CgroupAuthority) -> O.CgroupTerminationObservation:
            raise RuntimeError(secret)

    launched = _launched(observer=BrokenObserver())
    with pytest.raises(O.GuestAdmissionError, match="failed ambiguously") as caught:
        launched.termination.terminate()
    _assert_sanitized(caught.value, secret)
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        launched.termination.terminate()


def test_terminal_journal_exception_is_sanitized_after_kill() -> None:
    secret = "/private/supervisor-journal TOKEN=secret"
    supervisor = _Supervisor(fail="terminal", secret=secret)
    launched = _launched(supervisor=supervisor)
    with pytest.raises(O.GuestAdmissionError, match="terminal-state recording") as caught:
        launched.termination.terminate()
    _assert_sanitized(caught.value, secret)


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("provider_attempt_id", "attempt-other", "different cgroup attempt"),
        ("cgroup_path", "/sys/fs/cgroup/plamen/attempt-other", "different cgroup attempt"),
        ("inode", 999, "different cgroup attempt"),
        ("identity_sha256", "f" * 64, "different cgroup attempt"),
        ("kill_write_sha256", "f" * 64, "exact cgroup.kill write"),
        ("cgroup_events", b"populated 1\nfrozen 0\n", "not proven unpopulated"),
    ],
)
def test_terminal_observation_binds_kill_read_and_exact_attempt(field: str, replacement: object, message: str) -> None:
    expected = _fresh_filesystem_expectation()
    valid = _TerminationObserver().kill_then_observe(expected.cgroup)
    observation = replace(valid, **{field: replacement})
    with pytest.raises(O.GuestAdmissionError, match=message):
        _launched(expected, _TerminationObserver(observation)).termination.terminate()


def test_terminal_read_generation_must_follow_kill_generation() -> None:
    expected = _expectation()
    with pytest.raises(O.GuestAdmissionError, match="observed after"):
        O.CgroupTerminationObservation(
            expected.provider_attempt_id, expected.cgroup.path,
            expected.cgroup.filesystem_device, expected.cgroup.inode,
            expected.cgroup.identity_sha256, O.CGROUP_KILL_WRITE_SHA256,
            42, 42, b"populated 0\nfrozen 0\n",
        )


# V2 is a distinct stopped-guest contract for the POSIX supervisor. All
# executable authorities below are deliberately TEST_ONLY; production V2 is a
# hard-stop until its native/out-of-process verifier is integrated.

_V2_MOUNT_POLICY = (
    ("project-merged", "/workspace/project", "rw"),
    ("scratch", "/workspace/scratch", "rw"),
    ("state", "/workspace/state", "rw"),
    ("control", "/workspace/control", "ro"),
    ("seccomp", "/run/plamen/seccomp", "ro"),
    ("credentials", "/run/plamen/credentials", "ro"),
    ("backend-context", "/run/plamen/backend", "ro"),
    ("runtime", "/opt/plamen", "ro"),
    ("docs", "/workspace/docs", "ro"),
    ("scope", "/workspace/scope", "ro"),
)


def _v2_expectation() -> O.GuestAdmissionExpectationV2:
    attempt = "attempt-v2-001"
    mounts = tuple(
        O.SupervisorMountBindingV2(
            source_root=(
                "/Users/alice/work/credentials"
                if purpose == "credentials"
                else f"/Users/alice/work/v2-{purpose}"
            ),
            source_root_identity=_identity(
                format(index + 1, "x")[-1], inode=200 + index,
            ),
            source=(
                "/Users/alice/work/credentials"
                if purpose == "credentials"
                else f"/Users/alice/work/v2-{purpose}"
            ),
            source_identity=_identity(
                format(index + 1, "x")[-1], inode=200 + index,
            ),
            destination=destination, mode=mode, purpose=purpose,
            provider_mount_identity_sha256=format(index + 1, "x")[-1] * 64,
        )
        for index, (purpose, destination, mode) in enumerate(_V2_MOUNT_POLICY)
    )
    target_lower = O.HostOverlayLowerBindingV2(
        source_root="/Users/alice/work/dodo-lower",
        source_root_identity=_identity("b", inode=299),
        source="/Users/alice/work/dodo-lower",
        source_identity=_identity("b", inode=299),
        provider_mount_identity_sha256="b" * 64,
    )
    helpers = (
        O.HelperBinding("/opt/plamen/scripts/linux_cgroup_exec.py", "5" * 64),
        O.HelperBinding("/opt/plamen/scripts/plamen_driver.py", "6" * 64),
    )
    materialization = O.RuntimeMaterializationBindingV2(
        source_roster_sha256="0" * 64,
        composition_manifest_sha256="1" * 64,
        archive_sha256="2" * 64,
        archive_diff_id="sha256:" + "2" * 64,
        archive_size=10240,
        receipt_sha256="3" * 64,
        installed_census_sha256="4" * 64,
        sbom_sha256="5" * 64,
        provenance_sha256="6" * 64,
        entry_count=100,
        expanded_bytes=4096,
    )
    image_reference = "registry.invalid/plamen@sha256:" + "0" * 64
    image_closure = hashlib.sha256(O._canonical_bytes({
        "apple_container_configuration_sha256": "9" * 64,
        "config_digest": "sha256:" + "8" * 64,
        "index_digest": "sha256:" + "0" * 64,
        "manifest_digest": "sha256:" + "1" * 64,
        "platform": {"architecture": "arm64", "os": "linux"},
        "reference": image_reference,
    })).hexdigest()
    backend_admission = hashlib.sha256(O._canonical_bytes({
        "config_sha256": "2" * 64,
        "helpers": [{"path": row.path, "sha256": row.sha256} for row in helpers],
        "image_closure_sha256": image_closure,
        "launch_envelope_sha256": "3" * 64,
        "provider_attempt_id": attempt,
        "runtime_closure_sha256": "4" * 64,
        "runtime_materialization": {
            name: getattr(materialization, name)
            for name in O._RUNTIME_MATERIALIZATION_KEYS_V2
        },
    })).hexdigest()
    return O.GuestAdmissionExpectationV2(
        image_reference=image_reference,
        image_index_digest="sha256:" + "0" * 64,
        image_manifest_digest="sha256:" + "1" * 64,
        image_config_digest="sha256:" + "8" * 64,
        apple_container_configuration_sha256="9" * 64,
        platform_os="linux", platform_architecture="arm64",
        provider_kind="APPLE_CONTAINER", provider_identity_sha256="c" * 64,
        config_sha256="2" * 64, launch_envelope_sha256="3" * 64,
        runtime_closure_sha256="4" * 64,
        runtime_materialization=materialization,
        image_closure_sha256=image_closure,
        backend_admission_sha256=backend_admission,
        provider_attempt_id=attempt,
        helpers=helpers,
        mounts=mounts, target_lower=target_lower,
        lower_binding_sha256=O._lower_binding_sha256_v2(target_lower, mounts[0]),
        precreate_layout_sha256="d" * 64,
        postcreate_layout_sha256="e" * 64,
        cgroup=O.CgroupAuthority(
            path=f"/sys/fs/cgroup/plamen/{attempt}", filesystem_device=55,
            inode=902, identity_sha256="f" * 64,
            provider_attempt_id=attempt,
        ),
        landlock=O.LandlockAuthority(
            abi_version=5, ruleset_sha256="a" * 64,
            allowed_write_paths=(
                "/workspace/project", "/workspace/scratch", "/workspace/state",
            ),
        ),
        execution=O.ExecutionAuthorityV2(
            uid=1000, gid=1000, seccomp_profile_sha256="7" * 64,
            network_policy_sha256="8" * 64,
        ),
        host_home="/Users/alice",
    )


def _v2_mount_dict(value: O.SupervisorMountBindingV2) -> dict[str, object]:
    return {
        "kind": value.kind, "source_root": value.source_root,
        "source_root_identity": _identity_dict(value.source_root_identity),
        "source": value.source,
        "source_identity": _identity_dict(value.source_identity),
        "destination": value.destination, "mode": value.mode,
        "purpose": value.purpose,
        "provider_mount_identity_sha256": value.provider_mount_identity_sha256,
    }


def _v2_lower_dict(value: O.HostOverlayLowerBindingV2) -> dict[str, object]:
    return {
        "kind": value.kind, "source_root": value.source_root,
        "source_root_identity": _identity_dict(value.source_root_identity),
        "source": value.source,
        "source_identity": _identity_dict(value.source_identity),
        "attachment": value.attachment, "mode": value.mode,
        "purpose": value.purpose,
        "provider_mount_identity_sha256": value.provider_mount_identity_sha256,
    }


def _v2_receipt(
    expected: O.GuestAdmissionExpectationV2 | None = None,
) -> dict[str, object]:
    expected = expected or _v2_expectation()
    cgroup, landlock, execution = expected.cgroup, expected.landlock, expected.execution
    return {
        "schema": O.TEST_ONLY_SCHEMA_V2,
        "image": {
            "reference": expected.image_reference,
            "index_digest": expected.image_index_digest,
            "manifest_digest": expected.image_manifest_digest,
            "config_digest": expected.image_config_digest,
            "apple_container_configuration_sha256": expected.apple_container_configuration_sha256,
            "platform": {
                "os": expected.platform_os,
                "architecture": expected.platform_architecture,
            },
        },
        "provider": {
            "kind": expected.provider_kind,
            "identity_sha256": expected.provider_identity_sha256,
            "provider_attempt_id": expected.provider_attempt_id,
        },
        "bindings": {
            "config_sha256": expected.config_sha256,
            "launch_envelope_sha256": expected.launch_envelope_sha256,
            "runtime_closure_sha256": expected.runtime_closure_sha256,
            "runtime_materialization": {
                name: getattr(expected.runtime_materialization, name)
                for name in O._RUNTIME_MATERIALIZATION_KEYS_V2
            },
            "image_closure_sha256": expected.image_closure_sha256,
            "backend_admission_sha256": expected.backend_admission_sha256,
            "provider_attempt_id": expected.provider_attempt_id,
            "helpers": [
                {"path": row.path, "sha256": row.sha256}
                for row in expected.helpers
            ],
        },
        "rootfs": {"readonly": True},
        "mounts": [_v2_mount_dict(row) for row in expected.mounts],
        "overlay": {
            "target_lower": _v2_lower_dict(expected.target_lower),
            "project_merged_provider_mount_identity_sha256": (
                expected.mounts[0].provider_mount_identity_sha256
            ),
            "lower_binding_sha256": expected.lower_binding_sha256,
        },
        "capabilities": {
            "cgroup_v2": {
                "filesystem": cgroup.filesystem, "path": cgroup.path,
                "filesystem_device": cgroup.filesystem_device,
                "inode": cgroup.inode, "identity_sha256": cgroup.identity_sha256,
                "provider_attempt_id": cgroup.provider_attempt_id,
                "delegated": cgroup.delegated,
                "provider_owns_tree": cgroup.provider_owns_tree,
                "pre_execution_assignment": cgroup.pre_execution_assignment,
                "cgroup_type": cgroup.cgroup_type,
                "cgroup_kill": cgroup.cgroup_kill,
                "termination_scope": cgroup.termination_scope,
                "exhaustive_descendant_termination_authority": (
                    cgroup.exhaustive_descendant_termination_authority
                ),
            },
            "landlock": {
                "abi_version": landlock.abi_version,
                "handled_access_fs": list(landlock.handled_access_fs),
                "ruleset_sha256": landlock.ruleset_sha256,
                "active": landlock.active, "ruleset_status": landlock.ruleset_status,
                "no_new_privs": landlock.no_new_privs,
                "thread_state": landlock.thread_state,
                "restricted_thread_count": landlock.restricted_thread_count,
                "allowed_write_paths": list(landlock.allowed_write_paths),
                "write_confinement": landlock.write_confinement,
                "exhaustive_write_confinement_authority": (
                    landlock.exhaustive_write_confinement_authority
                ),
            },
        },
        "execution": {
            "uid": execution.uid, "gid": execution.gid,
            "supplemental_groups": list(execution.supplemental_groups),
            "capabilities_drop": list(execution.capabilities_drop),
            "capabilities_add": list(execution.capabilities_add),
            "inherited_environment": execution.inherited_environment,
            "ssh_agent_forwarding": execution.ssh_agent_forwarding,
            "published_sockets": list(execution.published_sockets),
            "host_devices": list(execution.host_devices),
            "nested_virtualization": execution.nested_virtualization,
            "init": execution.init,
            "no_new_privileges": execution.no_new_privileges,
            "seccomp_status": execution.seccomp_status,
            "seccomp_profile_sha256": execution.seccomp_profile_sha256,
            "masked_paths": list(execution.masked_paths),
            "readonly_paths": list(execution.readonly_paths),
            "network_mode": execution.network_mode,
            "network_enforcement": execution.network_enforcement,
            "network_policy_sha256": execution.network_policy_sha256,
            "no_dns": execution.no_dns,
        },
        "lifecycle": {
            "state": "CREATED_STOPPED", "create_stopped": True,
            "initial_process_count": 0, "workload_nonexecuting": True,
            "precreate_layout_sha256": expected.precreate_layout_sha256,
            "postcreate_layout_sha256": expected.postcreate_layout_sha256,
        },
    }


class _StoppedGuestProviderV2:
    def __init__(self, expected: O.GuestAdmissionExpectationV2) -> None:
        self.expected = expected
        self.calls: list[str] = []
        self.replace_by_phase: dict[str, dict[str, object]] = {}
        self.raw_result: object | None = None

    def observe_stopped_guest(self, attempt: str, phase: str) -> object:
        self.calls.append(phase)
        assert attempt == self.expected.provider_attempt_id
        if self.raw_result is not None:
            return self.raw_result
        value = O.TestOnlyV2StoppedGuestObservation(
            phase=phase, provider_attempt_id=attempt,
            provider_kind=self.expected.provider_kind,
            provider_identity_sha256=self.expected.provider_identity_sha256,
            image_reference=self.expected.image_reference,
            image_index_digest=self.expected.image_index_digest,
            image_manifest_digest=self.expected.image_manifest_digest,
            image_config_digest=self.expected.image_config_digest,
            apple_container_configuration_sha256=(
                self.expected.apple_container_configuration_sha256
            ),
            image_closure_sha256=self.expected.image_closure_sha256,
            backend_admission_sha256=self.expected.backend_admission_sha256,
            platform_os=self.expected.platform_os,
            platform_architecture=self.expected.platform_architecture,
            network_mode=self.expected.execution.network_mode,
            network_policy_sha256=self.expected.execution.network_policy_sha256,
            lifecycle_state="CREATED_STOPPED", workload_process_count=0,
            precreate_layout_sha256=self.expected.precreate_layout_sha256,
            postcreate_layout_sha256=self.expected.postcreate_layout_sha256,
            mounts=self.expected.mounts, target_lower=self.expected.target_lower,
            lower_binding_sha256=self.expected.lower_binding_sha256,
        )
        changes = self.replace_by_phase.get(phase)
        return replace(value, **changes) if changes else value


def _admit_v2(
    expected: O.GuestAdmissionExpectationV2 | None = None,
    receipt: dict[str, object] | None = None,
    ledger: _ReplayLedger | None = None,
    provider: _StoppedGuestProviderV2 | None = None,
) -> tuple[O.TestOnlySupervisorGuestAdmissionV2, _StoppedGuestProviderV2, object]:
    expected = expected or _v2_expectation()
    provider = provider or _StoppedGuestProviderV2(expected)
    authority = O._bind_stopped_guest_authority_v2_for_testing(provider)
    admitted = O._admit_oci_guest_v2_for_testing(
        _raw(receipt or _v2_receipt(expected)), expected,
        replay_consumer=ledger or _ReplayLedger(),
        stopped_guest_authority=authority,
    )
    return admitted, provider, authority


def test_v2_exact_ten_mount_stopped_guest_admits_and_starts_once() -> None:
    expected = _v2_expectation()
    admitted, provider, authority = _admit_v2(expected)
    assert admitted.schema == O.TEST_ONLY_SCHEMA_V2
    assert admitted.provider_attempt_id == expected.provider_attempt_id
    assert re.fullmatch(r"[0-9a-f]{64}", admitted.admission_sha256)
    assert provider.calls == ["PRE_ADMISSION", "POST_ADMISSION"]
    started = admitted.consume_for_start(
        expected, stopped_guest_authority=authority,
        starter=lambda proof: (proof.provider_attempt_id, "started"),
    )
    assert started == (expected.provider_attempt_id, "started")
    assert provider.calls == ["PRE_ADMISSION", "POST_ADMISSION", "PRE_START"]
    assert admitted.consumed is True
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        admitted.consume_for_start(
            expected, stopped_guest_authority=authority,
            starter=lambda _proof: None,
        )


@pytest.mark.parametrize(
    "path",
    [
        ("image", "index_digest"),
        ("image", "config_digest"),
        ("image", "apple_container_configuration_sha256"),
        ("bindings", "runtime_materialization", "installed_census_sha256"),
        ("bindings", "runtime_materialization", "sbom_sha256"),
        ("bindings", "runtime_materialization", "provenance_sha256"),
        ("bindings", "image_closure_sha256"),
        ("bindings", "backend_admission_sha256"),
    ],
)
def test_v2_image_materialization_and_backend_bindings_reject_substitution(path) -> None:
    receipt = _v2_receipt()
    cursor = receipt
    for component in path[:-1]:
        cursor = cursor[component]
    cursor[path[-1]] = "e" * 64 if not str(cursor[path[-1]]).startswith("sha256:") else "sha256:" + "e" * 64
    with pytest.raises(O.GuestAdmissionError):
        _admit_v2(receipt=receipt)


def test_v2_stopped_observation_rebind_of_index_is_rejected() -> None:
    expected = _v2_expectation()
    provider = _StoppedGuestProviderV2(expected)
    provider.replace_by_phase["PRE_ADMISSION"] = {
        "image_index_digest": "sha256:" + "e" * 64,
        "image_reference": "registry.invalid/plamen@sha256:" + "e" * 64,
    }
    with pytest.raises(O.GuestAdmissionError, match="observation differs"):
        _admit_v2(expected=expected, provider=provider)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda rows: rows.pop(), "roster size"),
        (lambda rows: rows.append(copy.deepcopy(rows[-1])), "roster size"),
        (lambda rows: rows.reverse(), "closed purpose"),
        (
            lambda rows: rows.__setitem__(
                1, {**rows[1], "destination": "/workspace/project"},
            ),
            "duplicate|closed purpose",
        ),
        (
            lambda rows: rows.__setitem__(2, {**rows[2], "mode": "ro"}),
            "closed purpose",
        ),
        (
            lambda rows: rows.__setitem__(
                4,
                {
                    **rows[4],
                    "destination": "/run/plamen/seccomp/../backend",
                },
            ),
            "path alias",
        ),
    ],
)
def test_v2_missing_extra_reordered_aliased_and_wrong_mounts_fail(
    mutation, message: str,
) -> None:
    receipt = _v2_receipt()
    mutation(receipt["mounts"])  # type: ignore[arg-type]
    with pytest.raises(O.GuestAdmissionError, match=message):
        _admit_v2(receipt=receipt)


def test_v2_legacy_and_test_receipts_cannot_enter_production() -> None:
    expected = _v2_expectation()
    # Production always fails before a Python registry, sentinel, schema, or
    # callback can mint an admission capability.
    for receipt in (_receipt(), _v2_receipt(expected)):
        with pytest.raises(O.GuestAdmissionError, match="native/out-of-process"):
            O.admit_oci_guest_v2(
                _raw(receipt), expected, replay_consumer=_ReplayLedger(),
                native_admission_authority=object(),
            )
    production_schema = _v2_receipt(expected)
    production_schema["schema"] = O.SCHEMA_V2
    with pytest.raises(O.GuestAdmissionError, match="TEST_ONLY.*schema"):
        _admit_v2(expected=expected, receipt=production_schema)
    with pytest.raises(O.GuestAdmissionError, match="typed V2"):
        O._admit_oci_guest_v2_for_testing(
            _raw(_v2_receipt()), _expectation(), replay_consumer=_ReplayLedger(),
            stopped_guest_authority=object(),  # type: ignore[arg-type]
        )


def test_v2_registry_transplant_and_introspection_cannot_mint_production() -> None:
    expected = _v2_expectation()
    provider = _StoppedGuestProviderV2(expected)
    fake = object.__new__(O.TestOnlyStoppedGuestAdmissionAuthorityV2)
    # A forged unregistered test object is rejected by the test-only seam.
    with pytest.raises(O.GuestAdmissionError, match="issued TEST_ONLY"):
        O._admit_oci_guest_v2_for_testing(
            _raw(_v2_receipt(expected)), expected,
            replay_consumer=_ReplayLedger(), stopped_guest_authority=fake,
        )
    # Even a same-process registry transplant only compromises TEST_ONLY state;
    # the production entry point has no code path which consults that registry.
    O._TEST_ONLY_STOPPED_AUTHORITY_REGISTRY_V2[fake] = provider
    test_capability = O._admit_oci_guest_v2_for_testing(
        _raw(_v2_receipt(expected)), expected,
        replay_consumer=_ReplayLedger(), stopped_guest_authority=fake,
    )
    assert test_capability.schema == O.TEST_ONLY_SCHEMA_V2
    with pytest.raises(O.GuestAdmissionError, match="native/out-of-process"):
        O.admit_oci_guest_v2(
            _raw(_v2_receipt(expected)), expected,
            replay_consumer=_ReplayLedger(),
            native_admission_authority=test_capability,
        )
    assert "TEST_ONLY" in O.TestOnlySupervisorGuestAdmissionV2.__doc__
    assert O.TEST_ONLY_SCHEMA_V2 != O.SCHEMA_V2


def test_v2_overlay_lower_drift_and_merged_rebinding_fail() -> None:
    receipt = _v2_receipt()
    receipt["overlay"]["target_lower"]["source_identity"]["inode"] = 777  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="target-lower|lower binding"):
        _admit_v2(receipt=receipt)

    receipt = _v2_receipt()
    receipt["overlay"]["project_merged_provider_mount_identity_sha256"] = "f" * 64  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="different project-merged"):
        _admit_v2(receipt=receipt)


def test_v2_cross_role_descriptor_or_provider_mount_reuse_fails() -> None:
    receipt = _v2_receipt()
    receipt["mounts"][1]["source_identity"] = copy.deepcopy(receipt["mounts"][0]["source_identity"])  # type: ignore[index]
    receipt["mounts"][1]["source_root_identity"] = copy.deepcopy(receipt["mounts"][0]["source_root_identity"])  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="descriptors overlap"):
        _admit_v2(receipt=receipt)

    receipt = _v2_receipt()
    receipt["mounts"][1]["provider_mount_identity_sha256"] = receipt["mounts"][0]["provider_mount_identity_sha256"]  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="provider mount identities overlap"):
        _admit_v2(receipt=receipt)

    # A provider can assign a fresh mount ID/topology proof to a bind alias of
    # the same underlying object.  Cross-role uniqueness must therefore reject
    # device/inode reuse independently of every provider-scoped identity.
    receipt = _v2_receipt()
    project_identity = receipt["mounts"][0]["source_identity"]  # type: ignore[index]
    for key in ("source_root_identity", "source_identity"):
        scratch_identity = receipt["mounts"][1][key]  # type: ignore[index]
        scratch_identity["device"] = project_identity["device"]
        scratch_identity["inode"] = project_identity["inode"]
        scratch_identity["native_mount_id"] = 1701
        scratch_identity["mount_topology_sha256"] = "f" * 64
    assert (
        receipt["mounts"][1]["provider_mount_identity_sha256"]  # type: ignore[index]
        != receipt["mounts"][0]["provider_mount_identity_sha256"]  # type: ignore[index]
    )
    with pytest.raises(O.GuestAdmissionError, match="source descriptors overlap"):
        _admit_v2(receipt=receipt)


def test_v2_credentials_and_backend_cannot_leak_through_other_roles() -> None:
    receipt = _v2_receipt()
    receipt["mounts"][8]["source_root"] = "/Users/alice/work/credentials"  # type: ignore[index]
    receipt["mounts"][8]["source"] = "/Users/alice/work/credentials"  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="duplicate|credential"):
        _admit_v2(receipt=receipt)

    receipt = _v2_receipt()
    receipt["mounts"][6]["source_root"] = "/Users/alice/work/secrets"  # type: ignore[index]
    receipt["mounts"][6]["source"] = "/Users/alice/work/secrets"  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="credential"):
        _admit_v2(receipt=receipt)


@pytest.mark.parametrize(
    "hazard",
    [
        "mount_proof_authenticated", "submounts_absent",
        "symlink_entries_absent", "special_files_absent", "hardlinks_absent",
        "xattrs_absent", "compressed_files_absent",
    ],
)
def test_v2_link_submount_special_xattr_and_compression_claims_fail(
    hazard: str,
) -> None:
    receipt = _v2_receipt()
    receipt["mounts"][4]["source_identity"][hazard] = False  # type: ignore[index]
    receipt["mounts"][4]["source_root_identity"][hazard] = False  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match="unsafe object|no-submount"):
        _admit_v2(receipt=receipt)


def test_v2_native_race_after_replay_is_fail_closed_and_burned() -> None:
    expected = _v2_expectation()
    provider = _StoppedGuestProviderV2(expected)
    provider.replace_by_phase["POST_ADMISSION"] = {
        "postcreate_layout_sha256": "9" * 64,
    }
    ledger = _ReplayLedger()
    with pytest.raises(O.TestOnlyV2ProviderCleanupRequired) as caught:
        _admit_v2(expected=expected, ledger=ledger, provider=provider)
    assert caught.value.provider_attempt_id == expected.provider_attempt_id
    assert caught.value.phase == "POST_ADMISSION"
    assert ledger.rows.keys() == {expected.provider_attempt_id}
    assert provider.calls == ["PRE_ADMISSION", "POST_ADMISSION"]


def test_v2_pre_start_race_prevents_workload_effect() -> None:
    expected = _v2_expectation()
    admitted, provider, authority = _admit_v2(expected)
    provider.replace_by_phase["PRE_START"] = {"workload_process_count": 1}
    invoked: list[bool] = []
    with pytest.raises(O.TestOnlyV2ProviderCleanupRequired) as caught:
        admitted.consume_for_start(
            expected, stopped_guest_authority=authority,
            starter=lambda _proof: invoked.append(True),
        )
    assert invoked == []
    assert caught.value.provider_attempt_id == expected.provider_attempt_id
    assert caught.value.phase == "PRE_START"
    assert admitted.consumed is True

    # Clearing the provider race cannot make the poisoned capability retryable.
    provider.replace_by_phase.pop("PRE_START")
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        admitted.consume_for_start(
            expected, stopped_guest_authority=authority,
            starter=lambda _proof: invoked.append(True),
        )
    assert invoked == []


def test_v2_pre_admission_workload_poisons_durable_replay_before_rejection() -> None:
    expected = _v2_expectation()
    provider = _StoppedGuestProviderV2(expected)
    provider.replace_by_phase["PRE_ADMISSION"] = {"workload_process_count": 1}
    ledger = _ReplayLedger()

    with pytest.raises(O.TestOnlyV2ProviderCleanupRequired) as caught:
        _admit_v2(expected=expected, ledger=ledger, provider=provider)
    assert caught.value.provider_attempt_id == expected.provider_attempt_id
    assert caught.value.phase == "PRE_ADMISSION"
    assert ledger.rows.keys() == {expected.provider_attempt_id}

    provider.replace_by_phase.pop("PRE_ADMISSION")
    with pytest.raises(O.GuestAdmissionError, match="already consumed"):
        _admit_v2(expected=expected, ledger=ledger, provider=provider)
    assert provider.calls == [
        "PRE_ADMISSION", "PRE_ADMISSION",
    ]


def test_v2_python_bool_is_not_stopped_guest_proof() -> None:
    expected = _v2_expectation()
    provider = _StoppedGuestProviderV2(expected)
    provider.raw_result = True
    authority = O._bind_stopped_guest_authority_v2_for_testing(provider)
    with pytest.raises(O.GuestAdmissionError, match="untyped"):
        O._admit_oci_guest_v2_for_testing(
            _raw(_v2_receipt(expected)), expected,
            replay_consumer=_ReplayLedger(), stopped_guest_authority=authority,
        )
    with pytest.raises(O.GuestAdmissionError, match="native/out-of-process"):
        O.bind_native_stopped_guest_authority_v2(provider)


@pytest.mark.parametrize(
    ("path", "replacement", "message"),
    [
        (("lifecycle", "create_stopped"), False, "created-stopped"),
        (("lifecycle", "initial_process_count"), True, "created-stopped"),
        (("lifecycle", "workload_nonexecuting"), False, "created-stopped"),
        (("provider", "kind"), "PODMAN_ROOTLESS", "provider identity"),
        (("provider", "identity_sha256"), "9" * 64, "provider identity"),
        (("image", "platform", "architecture"), "amd64", "platform"),
        (("execution", "network_mode"), "bridge", "process/network"),
    ],
)
def test_v2_lifecycle_provider_platform_and_network_are_exact(
    path: tuple[str, ...], replacement: object, message: str,
) -> None:
    receipt = _v2_receipt()
    cursor: object = receipt
    for component in path[:-1]:
        cursor = cursor[component]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]
    with pytest.raises(O.GuestAdmissionError, match=message):
        _admit_v2(receipt=receipt)
