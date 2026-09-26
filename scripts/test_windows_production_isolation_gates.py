"""Adversarial gates for the Windows production isolation boundary."""

from __future__ import annotations

import ctypes
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import owned_process_scope as scope
import windows_hyperv_provider_sandbox as hcs
import windows_low_integrity_lease as lease


ROOT = Path(__file__).resolve().parents[1]
NATIVE_HCS_SOURCE = ROOT / "native/windows/plamen_windows_hcs_provider.c"
NATIVE_HCS_HEADER = ROOT / "native/windows/plamen_windows_hcs_provider.h"


def _capability_states():
    return {
        name: {"configured": True, "observed": True, "enforced": True}
        for name in hcs.WINDOWS_CAPABILITIES
    }


def _boundary_evidence():
    return {
        "provider_environment": {
            "schema_version": "plamen.program_facts_evm_provider_environment.v1",
            "environment_digest": "1" * 64,
            "sandbox_receipt_digest": "2" * 64,
            "platform": "WINDOWS",
            "linux_boundary": None,
            "windows_boundary": {
                "boundary_profile": hcs.BOUNDARY_PROFILE,
                "provided_capabilities": list(hcs.WINDOWS_CAPABILITIES),
            },
        },
        "capability_states": _capability_states(),
        "host_filesystem_shares": [],
        "network_adapters": [],
        "guest_job_breakaway_allowed": False,
        "inherited_handles": ["STDIN", "STDOUT", "STDERR"],
        "inherited_handle_allowlist": ["STDIN", "STDOUT", "STDERR"],
        "borrowed_capabilities": [],
        "permit_upgraded_capabilities": [],
        "linux_shaped_evidence": False,
        "generic_windows_tag_only": False,
    }


def _resource_evidence():
    return {
        "boundary_profile": hcs.BOUNDARY_PROFILE,
        "capability_states": _capability_states(),
        "readback": {
            "job_memory_and_process_limits": True,
            "hcs_compute_system_limits": True,
            "vhdx_capacity_and_file_record_bound": True,
        },
        "quota_evidence": {
            "fixed_vhdx_capacity": True,
            "fixed_ntfs_file_record_bound": True,
            "sparse_logical_and_allocated_bounds": True,
        },
        "terminal_evidence": {
            "active_process_zero": True,
            "descendant_count_zero": True,
        },
        "cleanup_evidence": {
            "output_flushed": True,
            "vhdx_flushed": True,
            "vhdx_detached": True,
            "hcs_terminated": True,
        },
    }


class _NativeCall:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class _JobApi:
    def __init__(self) -> None:
        self.closed: list[int] = []
        self.configured: tuple[int, int, int] | None = None
        self.CreateJobObjectW = _NativeCall(lambda _security, _name: 91)
        self.SetInformationJobObject = _NativeCall(self._set)
        self.QueryInformationJobObject = _NativeCall(self._query)
        self.CloseHandle = _NativeCall(self._close)

    def _set(self, handle, info_class, raw, _size):
        limits = raw._obj
        self.configured = (
            int(limits.BasicLimitInformation.LimitFlags),
            int(limits.BasicLimitInformation.ActiveProcessLimit),
            int(limits.JobMemoryLimit),
        )
        return 1

    def _query(self, _handle, _info_class, raw, _size, returned):
        assert self.configured is not None
        flags, process_limit, memory_limit = self.configured
        raw._obj.BasicLimitInformation.LimitFlags = flags
        raw._obj.BasicLimitInformation.ActiveProcessLimit = process_limit
        raw._obj.JobMemoryLimit = memory_limit
        returned._obj.value = ctypes.sizeof(raw._obj)
        return 1

    def _close(self, handle):
        self.closed.append(int(handle))
        return 1


def test_job_creation_enforces_and_reads_back_aggregate_limits(monkeypatch) -> None:
    api = _JobApi()
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: api, raising=False)

    assert scope.OwnedProcessScope._create_windows_job() == 91
    assert api.configured is not None
    flags, process_limit, memory_limit = api.configured
    assert flags & scope._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert flags & scope._JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    assert flags & scope._JOB_OBJECT_LIMIT_JOB_MEMORY
    assert process_limit == scope._WINDOWS_JOB_ACTIVE_PROCESS_LIMIT
    assert memory_limit == scope._WINDOWS_JOB_MEMORY_LIMIT_BYTES
    assert api.closed == []


def test_job_limit_readback_divergence_closes_authority(monkeypatch) -> None:
    api = _JobApi()

    def divergent(_handle, _info_class, raw, _size, returned):
        assert api.configured is not None
        flags, process_limit, memory_limit = api.configured
        raw._obj.BasicLimitInformation.LimitFlags = flags
        raw._obj.BasicLimitInformation.ActiveProcessLimit = process_limit + 1
        raw._obj.JobMemoryLimit = memory_limit
        returned._obj.value = ctypes.sizeof(raw._obj)
        return 1

    api.QueryInformationJobObject = _NativeCall(divergent)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_a, **_k: api, raising=False)

    with pytest.raises(
        scope.OwnedProcessScopeError,
        match="resource-limit readback diverged",
    ):
        scope.OwnedProcessScope._create_windows_job()
    assert api.closed == [91]


def test_lease_state_read_is_bounded_before_payload_allocation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    state = tmp_path / "state.json"
    state.write_bytes(b"{" + b" " * lease.MAX_LEASE_STATE_BYTES + b"}")
    monkeypatch.setattr(lease, "_is_reparse", lambda _path: False)
    with pytest.raises(
        lease.WindowsLowIntegrityLeaseError,
        match="fixed byte bound",
    ):
        lease._read_state(state)


def test_lease_state_write_rejects_oversized_owner_before_touching_disk(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state.json"
    with pytest.raises(
        lease.WindowsLowIntegrityLeaseError,
        match="fixed byte bound",
    ):
        lease._write_state(
            state,
            {"owner": "x" * (lease.MAX_LEASE_STATE_BYTES + 1)},
        )
    assert not state.exists()


def test_lease_root_denominator_is_not_caller_unbounded(tmp_path: Path) -> None:
    roots = tuple(tmp_path / str(index) for index in range(lease.MAX_WRITABLE_ROOTS + 1))
    with pytest.raises(
        lease.WindowsLowIntegrityLeaseError,
        match="at most",
    ):
        lease._canonical_roots(roots, lease_directory=tmp_path / "lease")


def test_hcs_probe_cannot_turn_source_files_into_production_authority(
    tmp_path: Path,
) -> None:
    provider = tmp_path / "native" / "windows" / "plamen_windows_hcs_provider.exe"
    provider.parent.mkdir(parents=True)
    provider.write_bytes(b"not a signed installed provider")
    receipt = provider.with_name("plamen_windows_hcs_provider.install-receipt.json")
    receipt.write_text(
        '{"schema":"plamen.windows_hcs_install_receipt.v1",'
        '"boundary_profile":"WINDOWS_HYPERV_HCS_PROVIDER_BOUNDARY_V1",'
        '"provider_sha256":"' + "0" * 64 + '","provider_size":31}',
        encoding="utf-8",
    )
    capability = hcs.windows_hyperv_hcs_runtime_capability(install_root=tmp_path)
    assert capability["production_ready"] is False
    assert capability["host_platform"] != "WINDOWS" or capability[
        "limitation"
    ] != "LIVE_NATIVE_HCS_DOCTOR_RECEIPT_ACCEPTED"


def test_hcs_install_identity_reads_are_bounded_and_single_link(
    tmp_path: Path,
) -> None:
    provider = tmp_path / "native/windows/plamen_windows_hcs_provider.exe"
    provider.parent.mkdir(parents=True)
    receipt = provider.with_name("plamen_windows_hcs_provider.install-receipt.json")
    provider.write_bytes(b"MZ")
    alias = provider.with_name("provider-hardlink.exe")
    os.link(provider, alias)
    receipt.write_bytes(b"{}")
    hardlinked = hcs.windows_hyperv_hcs_runtime_capability(install_root=tmp_path)
    assert hardlinked["native_provider_identity"] is None

    alias.unlink()
    with provider.open("wb") as stream:
        stream.truncate(hcs.MAX_NATIVE_PROVIDER_BYTES + 1)
    oversized_provider = hcs.windows_hyperv_hcs_runtime_capability(
        install_root=tmp_path
    )
    assert oversized_provider["native_provider_identity"] is None

    provider.write_bytes(b"MZ")
    with receipt.open("wb") as stream:
        stream.truncate(hcs.MAX_NATIVE_INSTALL_RECEIPT_BYTES + 1)
    oversized_receipt = hcs.windows_hyperv_hcs_runtime_capability(
        install_root=tmp_path
    )
    assert oversized_receipt["native_install_receipt_identity"] is None


def test_native_doctor_capture_kills_output_over_fixed_memory_bound() -> None:
    return_code, stdout, stderr = hcs._run_native_doctor_bounded(
        [
            sys.executable,
            "-c",
            "import os\nwhile True: os.write(1, b'x' * 4096)",
        ],
        environment=os.environ,
        timeout_seconds=10,
    )
    assert return_code != 0
    assert len(stdout) == hcs.MAX_NATIVE_DOCTOR_OUTPUT_BYTES + 1
    assert stderr == b""


def test_doctor_receipt_is_bound_to_fresh_challenge_and_exact_provider() -> None:
    challenge = b"one fresh native doctor challenge"
    identity = {
        "path": "C:/Program Files/Plamen/provider.exe",
        "size": 4096,
        "sha256": "a" * 64,
    }
    receipt = {
        "schema": "plamen.windows_hcs_doctor_receipt.v1",
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "provider_identity": dict(identity),
        "compute_system_properties_sha256": "b" * 64,
        "boundary_evidence": _boundary_evidence(),
        "resource_evidence": _resource_evidence(),
        "observed_at_windows_filetime": 133_700_000_000_000_000,
    }
    accepted = hcs.validate_windows_hcs_doctor_receipt_v1(
        receipt,
        expected_challenge=challenge,
        expected_provider_identity=identity,
    )
    assert accepted["accepted"] is True
    assert len(accepted["doctor_receipt_sha256"]) == 64

    replay = deepcopy(receipt)
    with pytest.raises(hcs.WindowsHyperVProviderError, match="replayed"):
        hcs.validate_windows_hcs_doctor_receipt_v1(
            replay,
            expected_challenge=b"a different fresh challenge",
            expected_provider_identity=identity,
        )
    forged = deepcopy(receipt)
    forged["provider_identity"]["sha256"] = "c" * 64
    with pytest.raises(hcs.WindowsHyperVProviderError, match="identity diverged"):
        hcs.validate_windows_hcs_doctor_receipt_v1(
            forged,
            expected_challenge=challenge,
            expected_provider_identity=identity,
        )


def test_native_diagnostic_is_non_promoting_and_replay_bound() -> None:
    challenge = b"native service probe challenge"
    identity = {
        "path": os.path.abspath("provider.exe"),
        "size": 8192,
        "sha256": "a" * 64,
    }
    diagnostic = {
        "schema": "plamen.windows_hcs_native_doctor.diagnostic.v1",
        "challenge_sha256": hashlib.sha256(challenge).hexdigest(),
        "provider_identity": dict(identity),
        "provider_file_identity": {
            "volume_serial": 41,
            "file_index_high": 1,
            "file_index_low": 2,
            "number_of_links": 1,
            "last_write_filetime": 133_700_000_000_000_000,
        },
        "hcs_api_surface_available": True,
        "hcs_service_probe": "ENUMERATE_COMPUTE_SYSTEMS_OK",
        "hcs_enumeration_sha256": "b" * 64,
        "disposable_empty_vm_probe": {
            "configuration_sha256": hcs.EMPTY_VM_CONFIGURATION_SHA256,
            "properties_sha256": "d" * 64,
            "created": True,
            "started": False,
            "terminated": True,
        },
        "observed_at_windows_filetime": 133_700_000_000_000_001,
        "production_ready": False,
        "limitation": "LIVE_GUEST_STORAGE_JOB_NETWORK_PROBE_NOT_IMPLEMENTED",
    }
    accepted = hcs.validate_windows_hcs_native_diagnostic_v1(
        diagnostic,
        expected_challenge=challenge,
        expected_provider_identity=identity,
    )
    assert accepted["accepted_diagnostic"] is True
    assert accepted["production_ready"] is False

    with pytest.raises(hcs.WindowsHyperVProviderError, match="replayed"):
        hcs.validate_windows_hcs_native_diagnostic_v1(
            diagnostic,
            expected_challenge=b"a different native challenge",
            expected_provider_identity=identity,
        )
    forged = deepcopy(diagnostic)
    forged["provider_identity"]["sha256"] = "c" * 64
    with pytest.raises(hcs.WindowsHyperVProviderError, match="identity diverged"):
        hcs.validate_windows_hcs_native_diagnostic_v1(
            forged,
            expected_challenge=challenge,
            expected_provider_identity=identity,
        )
    promoted = deepcopy(diagnostic)
    promoted["production_ready"] = True
    with pytest.raises(hcs.WindowsHyperVProviderError, match="incomplete"):
        hcs.validate_windows_hcs_native_diagnostic_v1(
            promoted,
            expected_challenge=challenge,
            expected_provider_identity=identity,
        )
    false_lifecycle = deepcopy(diagnostic)
    false_lifecycle["disposable_empty_vm_probe"]["started"] = True
    with pytest.raises(hcs.WindowsHyperVProviderError, match="incomplete"):
        hcs.validate_windows_hcs_native_diagnostic_v1(
            false_lifecycle,
            expected_challenge=challenge,
            expected_provider_identity=identity,
        )


def _visual_studio_compile_command(output: Path) -> list[str]:
    arguments = [
        "cl.exe",
        "/nologo",
        "/std:c11",
        "/W4",
        "/WX",
        "/DUNICODE",
        "/D_UNICODE",
        f"/Fo{output.with_suffix('.obj')}",
        f"/Fd{output.with_suffix('.pdb')}",
        os.fspath(NATIVE_HCS_SOURCE),
        "bcrypt.lib",
        "/link",
        "/DYNAMICBASE",
        "/NXCOMPAT",
        "/HIGHENTROPYVA",
        f"/OUT:{output}",
    ]
    compiler = shutil.which("cl.exe")
    if (
        compiler is not None
        and os.environ.get("INCLUDE")
        and os.environ.get("LIB")
    ):
        arguments[0] = compiler
        return arguments

    program_files = os.environ.get("ProgramFiles(x86)")
    if not program_files:
        pytest.fail("ProgramFiles(x86) is absent; MSVC discovery is impossible")
    vswhere = Path(program_files) / "Microsoft Visual Studio/Installer/vswhere.exe"
    if not vswhere.is_file():
        pytest.fail("vswhere.exe is absent; the Windows native gate cannot compile")
    discovery = subprocess.run(
        [
            os.fspath(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=30,
    )
    installation = discovery.stdout.strip()
    if discovery.returncode != 0 or not installation:
        pytest.fail("MSVC x64 tools are absent; the Windows native gate cannot compile")
    developer_shell = Path(installation) / "Common7/Tools/VsDevCmd.bat"
    if not developer_shell.is_file():
        pytest.fail("VsDevCmd.bat is absent; the Windows native gate cannot compile")
    command = subprocess.list2cmdline(arguments)
    return [
        os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe"),
        "/d",
        "/s",
        "/c",
        f'call "{developer_shell}" -no_logo -arch=x64 -host_arch=x64 >nul && {command}',
    ]


@pytest.mark.skipif(os.name != "nt", reason="requires the Windows SDK and HCS")
@pytest.mark.integration
def test_native_windows_hcs_doctor_compiles_and_binds_live_probe(
    tmp_path: Path,
) -> None:
    assert NATIVE_HCS_SOURCE.is_file()
    assert NATIVE_HCS_HEADER.is_file()
    provider = tmp_path / "native/windows/plamen_windows_hcs_provider.exe"
    provider.parent.mkdir(parents=True)
    compiled = subprocess.run(
        _visual_studio_compile_command(provider),
        check=False,
        capture_output=True,
        timeout=120,
    )
    assert compiled.returncode == 0, (
        compiled.stdout.decode("utf-8", errors="replace")
        + compiled.stderr.decode("utf-8", errors="replace")
    )
    assert provider.is_file()

    for invalid in (b"0" * 30, b"0" * 514, b"g" * 64):
        denied = subprocess.run(
            [
                os.fspath(provider),
                "doctor",
                "--challenge-hex",
                invalid.decode("ascii"),
            ],
            check=False,
            capture_output=True,
            timeout=10,
        )
        assert denied.returncode == 2
        assert denied.stdout == b""

    challenge = os.urandom(32)
    probe = subprocess.run(
        [
            os.fspath(provider),
            "doctor",
            "--challenge-hex",
            challenge.hex(),
        ],
        check=False,
        capture_output=True,
        timeout=45,
    )
    if probe.returncode == 4:
        assert probe.stdout == b""
        pytest.xfail("this Windows host does not expose a usable HCS service")
    assert probe.returncode == 3, probe.stderr.decode("utf-8", errors="replace")
    assert probe.stderr == b""
    document = json.loads(probe.stdout.decode("utf-8", errors="strict"))
    assert set(document) == {
        "schema",
        "challenge_sha256",
        "provider_identity",
        "provider_file_identity",
        "hcs_api_surface_available",
        "hcs_service_probe",
        "hcs_enumeration_sha256",
        "disposable_empty_vm_probe",
        "observed_at_windows_filetime",
        "production_ready",
        "limitation",
    }
    assert document["schema"] == "plamen.windows_hcs_native_doctor.diagnostic.v1"
    assert document["challenge_sha256"] == hashlib.sha256(challenge).hexdigest()
    assert Path(document["provider_identity"]["path"]).samefile(provider)
    provider_bytes = provider.read_bytes()
    assert document["provider_identity"] == {
        "path": document["provider_identity"]["path"],
        "size": len(provider_bytes),
        "sha256": hashlib.sha256(provider_bytes).hexdigest(),
    }
    assert set(document["provider_file_identity"]) == {
        "volume_serial",
        "file_index_high",
        "file_index_low",
        "number_of_links",
        "last_write_filetime",
    }
    assert document["provider_file_identity"]["number_of_links"] == 1
    assert document["provider_file_identity"]["last_write_filetime"] > 0
    assert document["hcs_api_surface_available"] is True
    assert document["hcs_service_probe"] == "ENUMERATE_COMPUTE_SYSTEMS_OK"
    assert len(document["hcs_enumeration_sha256"]) == 64
    int(document["hcs_enumeration_sha256"], 16)
    assert set(document["disposable_empty_vm_probe"]) == {
        "configuration_sha256",
        "properties_sha256",
        "created",
        "started",
        "terminated",
    }
    assert document["disposable_empty_vm_probe"]["configuration_sha256"] == (
        hcs.EMPTY_VM_CONFIGURATION_SHA256
    )
    assert len(document["disposable_empty_vm_probe"]["properties_sha256"]) == 64
    int(document["disposable_empty_vm_probe"]["properties_sha256"], 16)
    assert document["disposable_empty_vm_probe"]["created"] is True
    assert document["disposable_empty_vm_probe"]["started"] is False
    assert document["disposable_empty_vm_probe"]["terminated"] is True
    assert document["observed_at_windows_filetime"] > 0
    assert document["production_ready"] is False
    assert document["limitation"] == (
        "LIVE_GUEST_STORAGE_JOB_NETWORK_PROBE_NOT_IMPLEMENTED"
    )

    install_receipt = provider.with_name(
        "plamen_windows_hcs_provider.install-receipt.json"
    )
    install_receipt.write_text(
        json.dumps(
            {
                "schema": "plamen.windows_hcs_install_receipt.v1",
                "boundary_profile": hcs.BOUNDARY_PROFILE,
                "provider_sha256": hashlib.sha256(provider_bytes).hexdigest(),
                "provider_size": len(provider_bytes),
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    capability = hcs.windows_hyperv_hcs_runtime_capability(install_root=tmp_path)
    assert capability["production_ready"] is False
    assert capability["limitation"] == (
        "LIVE_ISOLATED_GUEST_DOCTOR_RECEIPT_REQUIRED"
    )
    assert capability["native_doctor_diagnostic"]["accepted_diagnostic"] is True


@pytest.mark.skipif(os.name != "nt", reason="requires a native Windows HCS host")
@pytest.mark.integration
@pytest.mark.xfail(
    reason=(
        "native helper exists, but disposable-guest VHDX/Job/HCS terminal "
        "evidence and its accepted doctor receipt are not implemented"
    ),
    strict=True,
)
def test_live_windows_hcs_doctor_is_required_for_production() -> None:
    capability = hcs.require_windows_hyperv_hcs_runtime()
    assert capability["production_ready"] is True
