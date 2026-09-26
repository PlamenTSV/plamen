"""Fake-only adversarial tests; never discovers or runs Apple container."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any, Callable

import pytest

import apple_container_provider as A


_DIGEST = "sha256:" + "b" * 64
_MANIFEST_DIGEST = "sha256:" + "d" * 64
_IMAGE = "ghcr.io/plamen/runtime@" + _DIGEST
_IMAGE_CONFIG: dict[str, Any] = {
    "architecture": "arm64", "os": "linux",
    "config": {"Env": ["PATH=/usr/bin:/bin", "PYTHONUTF8=1"],
               "Entrypoint": ["/usr/bin/python3"]},
    "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "c" * 64]},
}
_CONFIG_DIGEST = hashlib.sha256(
    json.dumps(_IMAGE_CONFIG, allow_nan=False, sort_keys=True,
               separators=(",", ":")).encode()
).hexdigest()
_NETWORK_POLICY = "1" * 64
_EGRESS_ADMISSION = hashlib.sha256(b"egress-admission").hexdigest()
_NETWORK_NAME = "plamen-egress-001"
_NETWORK_RUN = "run-dodo-001"
_NETWORK_AUTHORITY = "6" * 32
_NETWORK_SUBNET = "192.168.250.0/28"
_NETWORK_GATEWAY = "192.168.250.1"
_NETWORK_ADDRESS = "192.168.250.2/28"
_NETWORK_MAC = "02:42:ac:11:00:02"
_NETWORK_LABELS = tuple(sorted({
    "io.plamen.provider": "apple-container-v3",
    "io.plamen.run": _NETWORK_RUN,
    "io.plamen.network-sha256": _NETWORK_POLICY,
    "io.plamen.egress-admission-sha256": _EGRESS_ADMISSION,
    "io.plamen.network-role": "governed-egress",
    "io.plamen.network-authority": _NETWORK_AUTHORITY,
}.items()))
_NETWORK_TOPOLOGY = hashlib.sha256(json.dumps({
    "attempt_owned": True, "authority_nonce": _NETWORK_AUTHORITY,
    "internal": True,
    "topology_mode": "hostOnly",
    "effective_egress_mode": "VERIFIED_CONNECT_ALLOWLIST",
    "hostname": "plamen-dodo-001",
    "ipv4_address": _NETWORK_ADDRESS,
    "ipv4_gateway": _NETWORK_GATEWAY, "ipv4_subnet": _NETWORK_SUBNET,
    "ipv6_absent": True,
    "labels": [list(item) for item in _NETWORK_LABELS], "mtu": 1280,
    "mac_address": _NETWORK_MAC,
    "attachment_variant": A.SUPPORTED_NETWORK_ATTACHMENT_VARIANT,
    "name": _NETWORK_NAME, "no_dns": True,
    "plugin": "container-network-vmnet", "policy_sha256": _NETWORK_POLICY,
    "egress_admission_sha256": _EGRESS_ADMISSION,
    "run_identity": _NETWORK_RUN,
}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
_PIN = A.AppleContainerVersionPin(
    cli_version="1.3.1", cli_build="release",
    cli_commit=A.SUPPORTED_APPLE_CONTAINER_COMMIT,
    cli_executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
    cli_signing_identifier=A.SUPPORTED_CLI_SIGNING_IDENTIFIER,
    cli_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
    server_executable_path=str(A.DEFAULT_SERVER_EXECUTABLE),
    server_version="1.3.1", server_build="release",
    server_commit=A.SUPPORTED_APPLE_CONTAINER_COMMIT,
    server_banner_commit=A.SUPPORTED_APPLE_CONTAINER_COMMIT[:7],
    server_executable_sha256=A.SUPPORTED_SERVER_EXECUTABLE_SHA256,
    server_signing_identifier=A.SUPPORTED_SERVER_SIGNING_IDENTIFIER,
    server_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
    containerization_version="0.42.0", containerization_build="release",
    containerization_commit=A.SUPPORTED_CONTAINERIZATION_COMMIT,
    containerization_binary_sha256="f" * 64,
    init_image_reference=A.SUPPORTED_INIT_IMAGE_REFERENCE,
    init_image_index_digest=A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST,
    init_image_manifest_digest=A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST,
    plugin_root=str(A.DEFAULT_PLUGIN_ROOT),
    core_images_plugin_sha256=A.SUPPORTED_CORE_IMAGES_PLUGIN_SHA256,
    network_vmnet_plugin_sha256=A.SUPPORTED_NETWORK_VMNET_PLUGIN_SHA256,
    runtime_linux_plugin_sha256=A.SUPPORTED_RUNTIME_LINUX_PLUGIN_SHA256,
    machine_apiserver_plugin_sha256=A.SUPPORTED_MACHINE_APISERVER_PLUGIN_SHA256,
    plugin_signing_team_id=A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
    plugin_closure_sha256=A.SUPPORTED_PLUGIN_CLOSURE_SHA256,
    package_identifier=A.SUPPORTED_PACKAGE_IDENTIFIER,
    package_version=A.SUPPORTED_APPLE_CONTAINER_VERSION,
    package_install_location=A.SUPPORTED_PACKAGE_INSTALL_LOCATION,
    package_authorization=A.SUPPORTED_PACKAGE_AUTHORIZATION,
    package_signing_team_id=A.SUPPORTED_INSTALLER_TEAM_ID,
    package_installer_leaf_sha256=A.SUPPORTED_INSTALLER_LEAF_SHA256,
    package_receipt_sha256="8" * 64,
    package_signed=True,
    package_notarized=True,
    package_timestamped=True,
    kernel_archive_url=A.SUPPORTED_KERNEL_ARCHIVE_URL,
    kernel_archive_sha256=A.SUPPORTED_KERNEL_ARCHIVE_SHA256,
    kernel_archive_size=A.SUPPORTED_KERNEL_ARCHIVE_SIZE,
    kernel_binary_member=A.SUPPORTED_KERNEL_BINARY_MEMBER,
    kernel_binary_sha256=A.SUPPORTED_KERNEL_BINARY_SHA256,
    implicit_kernel_install_disabled=True,
    host_operating_system="Version 26.6.2 (Build 25G83)",
)
_PROVENANCE_DIGEST = hashlib.sha256(json.dumps(
    list(_PIN.provenance), sort_keys=True, separators=(",", ":")
).encode()).hexdigest()


def _result(stdout: bytes = b"", stderr: bytes = b"", *, returncode: int = 0,
            stdout_observed: int | None = None, stderr_observed: int | None = None,
            stdout_digest: str | None = None) -> A.RunnerResult:
    return A.RunnerResult(
        returncode, stdout, stderr,
        len(stdout) if stdout_observed is None else stdout_observed,
        len(stderr) if stderr_observed is None else stderr_observed,
        stdout_digest, None,
    )


def _json_result(value: object) -> A.RunnerResult:
    return _result(json.dumps(value, separators=(",", ":")).encode())


def _component_facts(path: str) -> tuple[tuple[str, ...], str]:
    current = ""
    identities: list[str] = []
    for component in (item for item in path.split("/") if item):
        current += "/" + component
        identities.append(hashlib.sha256(current.encode()).hexdigest())
    values = tuple(identities)
    return values, hashlib.sha256(json.dumps(
        list(values), sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()


@dataclass(frozen=True)
class Outcome:
    result: A.RunnerResult
    descendants_extinct: bool = True
    network_policy_enforced: bool = True
    network_accessed: bool = False
    registry_accessed: bool = False
    image_fetch_performed: bool = False
    guest_network_policy_sha256: str | None = _NETWORK_POLICY
    guest_network_topology_sha256: str | None = _NETWORK_TOPOLOGY
    guest_network_policy_enforced: bool = True
    guest_network_internal: bool = True
    guest_network_attempt_owned: bool = True
    guest_network_no_dns: bool = True
    guest_network_ipv6_absent: bool = True
    guest_network_object_verified: bool = True
    guest_network_attachment_verified: bool = True
    guest_network_name: str | None = _NETWORK_NAME
    guest_network_ipv4_subnet: str | None = _NETWORK_SUBNET
    guest_network_ipv4_gateway: str | None = _NETWORK_GATEWAY
    guest_network_ipv4_address: str | None = _NETWORK_ADDRESS
    guest_network_mac_address: str | None = _NETWORK_MAC
    guest_network_attachment_variant: str | None = A.SUPPORTED_NETWORK_ATTACHMENT_VARIANT
    guest_network_labels: tuple[tuple[str, str], ...] = _NETWORK_LABELS
    guest_network_plugin: str | None = "container-network-vmnet"
    init_image_reference: str | None = A.SUPPORTED_INIT_IMAGE_REFERENCE
    init_image_index_digest: str | None = A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
    init_image_manifest_digest: str | None = A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
    init_image_verified: bool = True
    mounted_identity_override: str | None = None
    provenance: tuple[str, ...] = _PIN.provenance
    issue_evidence: bool = True


class FakeAuthority:
    """One object models callbacks owned by a separately trusted native bootstrap."""

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.init_image_response: object = _json_result(_init_image_document())
        self.calls: list[tuple[tuple[str, ...], int, int, bool, int]] = []
        self.mount_capability_runs: list[tuple[tuple[str, ...], tuple[int, ...]]] = []
        self.records: dict[str, A.MutationRecord] = {}
        self.images: dict[str, A.ImageAdmissionRecord] = {}
        self.begin_calls: list[A.MutationRecord] = []
        self.complete_calls: list[A.MutationRecord] = []
        self.journal_load_count = 0
        self.mount_open_count = 0
        self.mount_revalidate_count = 0
        self.mount_close_count = 0
        self.exec_open_count = 0
        self.exec_post_count = 0
        self.exec_close_count = 0
        self.fail_begin = False
        self.lose_begin = False
        self.fail_complete = False
        self.lose_complete = False
        self.fail_revalidate = False
        self.fail_mount_close = False
        self.fail_exec_post = False
        self.fail_exec_post_at: int | None = None
        self.fail_exec_close = False
        self.fail_image_save = False
        self.lose_image_save = False
        self.mount_changes: dict[str, object] = {}
        self.executable_changes: dict[str, object] = {}
        self.driver_records: dict[tuple[str, str], A.DriverLifecycleRecord] = {}
        self.driver_processes: dict[str, dict[str, object]] = {}
        self.driver_wait_results: dict[str, tuple[A.RunnerResult, dict[str, object]]] = {}
        self.driver_journal_lock = threading.RLock()
        self.driver_start_calls = 0
        self.driver_start_entered: threading.Event | None = None
        self.driver_start_release: threading.Event | None = None
        self.driver_wait_calls = 0
        self.driver_wait_entered: threading.Event | None = None
        self.driver_wait_release: threading.Event | None = None
        self.driver_recover_process_calls = 0
        self.driver_recover_wait_calls = 0
        self.driver_journal_load_count = 0
        self.driver_revoke_calls = 0
        self.driver_wait_outcomes: list[object] = []
        self.driver_process_changes: dict[str, object] = {}
        self.driver_wait_changes: dict[str, object] = {}
        self.fail_driver_cas_state_once: A.DriverLifecycleState | None = None
        self.lose_driver_cas_state_once: A.DriverLifecycleState | None = None
        self.raise_after_driver_cas_state_once: A.DriverLifecycleState | None = None
        A.TEST_ONLY_register_same_process_authority(
            self, open_executable=self.open_executable,
            post_fstat_executable=self.post_fstat_executable,
            close_executable=self.close_executable, invoke=self.invoke,
            journal_load=self.journal_load, journal_begin=self.journal_begin,
            journal_complete=self.journal_complete, image_load=self.image_load,
            image_save=self.image_save, mount_open=self.mount_open,
            mount_revalidate=self.mount_revalidate, mount_close=self.mount_close,
            driver_start=self.driver_start, driver_wait=self.driver_wait,
            driver_recover_process=self.driver_recover_process,
            driver_recover_wait=self.driver_recover_wait,
            driver_revoke=self.driver_revoke,
            driver_journal_load=self.driver_journal_load,
            driver_journal_cas=self.driver_journal_cas,
        )

    def open_executable(self, path: str, digest: str) -> object:
        self.exec_open_count += 1
        values: dict[str, object] = {
            "path": path, "sha256": digest, "device": 1, "inode": 2,
            "size": 3, "mode": 0o755, "descriptor_held": True,
        }
        values.update(self.executable_changes)
        return A._issue_executable_capability(self, **values)  # type: ignore[arg-type]

    def post_fstat_executable(self, capability: object) -> None:
        self.exec_post_count += 1
        if self.fail_exec_post or self.fail_exec_post_at == self.exec_post_count:
            raise OSError("/secret/executable")
        A._mark_executable_post_fstat(self, capability, unchanged=True)

    def close_executable(self, capability: object) -> None:
        self.exec_close_count += 1
        if self.fail_exec_close:
            raise OSError("/secret/executable")
        A._mark_executable_closed(self, capability)

    def invoke(self, arguments: tuple[str, ...], *, executable_capability: object,
               mount_capabilities: tuple[object, ...], timeout: int,
               output_limit: int, deny_network: bool) -> A.RunnerResult:
        self.calls.append((arguments, timeout, output_limit, deny_network,
                           len(mount_capabilities)))
        self.mount_capability_runs.append(
            (arguments, tuple(id(item) for item in mount_capabilities))
        )
        if arguments == ("image", "inspect", A.SUPPORTED_INIT_IMAGE_REFERENCE):
            value = self.init_image_response
        else:
            if not self.responses:
                raise AssertionError("unexpected fake command")
            value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            value = value(arguments)
        outcome = value if isinstance(value, Outcome) else Outcome(value)
        assert isinstance(outcome.result, A.RunnerResult)
        if outcome.issue_evidence:
            mount_facts = tuple(A._TEST_ONLY_MOUNT_REGISTRY[id(item)]
                                for item in mount_capabilities)
            A._issue_invocation_evidence(
                self, outcome.result, executable_capability=executable_capability,
                mount_capabilities=mount_capabilities,
                mounted_identity_sha256=(outcome.mounted_identity_override
                    if outcome.mounted_identity_override is not None else
                    A.TEST_ONLY_AppleContainerProvider._mount_facts_digest(mount_facts)
                    if mount_capabilities else None),
                provenance=outcome.provenance,
                descendants_extinct=outcome.descendants_extinct,
                network_policy_enforced=outcome.network_policy_enforced,
                network_accessed=outcome.network_accessed,
                registry_accessed=outcome.registry_accessed,
                image_fetch_performed=outcome.image_fetch_performed,
                guest_network_policy_sha256=outcome.guest_network_policy_sha256,
                guest_network_topology_sha256=outcome.guest_network_topology_sha256,
                guest_network_policy_enforced=outcome.guest_network_policy_enforced,
                guest_network_internal=outcome.guest_network_internal,
                guest_network_attempt_owned=outcome.guest_network_attempt_owned,
                guest_network_no_dns=outcome.guest_network_no_dns,
                guest_network_ipv6_absent=outcome.guest_network_ipv6_absent,
                guest_network_object_verified=outcome.guest_network_object_verified,
                guest_network_attachment_verified=outcome.guest_network_attachment_verified,
                guest_network_name=outcome.guest_network_name,
                guest_network_ipv4_subnet=outcome.guest_network_ipv4_subnet,
                guest_network_ipv4_gateway=outcome.guest_network_ipv4_gateway,
                guest_network_ipv4_address=outcome.guest_network_ipv4_address,
                guest_network_mac_address=outcome.guest_network_mac_address,
                guest_network_attachment_variant=outcome.guest_network_attachment_variant,
                guest_network_labels=outcome.guest_network_labels,
                guest_network_plugin=outcome.guest_network_plugin,
                init_image_reference=outcome.init_image_reference,
                init_image_index_digest=outcome.init_image_index_digest,
                init_image_manifest_digest=outcome.init_image_manifest_digest,
                init_image_verified=outcome.init_image_verified,
            )
        return outcome.result

    def journal_load(self, identity: str) -> A.MutationRecord | None:
        self.journal_load_count += 1
        return self.records.get(identity)

    def journal_begin(self, record: A.MutationRecord,
                      previous: A.MutationRecord | None) -> A.MutationRecord:
        self.begin_calls.append(record)
        if self.fail_begin:
            raise OSError("/secret/journal")
        if self.records.get(record.identity) != previous:
            raise OSError("journal compare-and-swap failed")
        if not self.lose_begin:
            self.records[record.identity] = record
        return record

    def journal_complete(self, pending: A.MutationRecord,
                         postcondition: str) -> A.MutationRecord:
        self.complete_calls.append(pending)
        if self.fail_complete:
            raise OSError("/secret/journal")
        if self.records.get(pending.identity) != pending:
            raise OSError("journal terminal compare-and-swap failed")
        terminal = replace(pending, state=A.MutationState.TERMINAL,
                           postcondition_sha256=postcondition)
        if not self.lose_complete:
            self.records[pending.identity] = terminal
        return terminal

    def image_load(self, reference: str) -> A.ImageAdmissionRecord | None:
        return self.images.get(reference)

    def image_save(self, record: A.ImageAdmissionRecord,
                   previous: A.ImageAdmissionRecord | None) -> A.ImageAdmissionRecord:
        if self.fail_image_save:
            raise OSError("/secret/image-journal")
        if self.images.get(record.image_reference) != previous:
            raise OSError("image journal compare-and-swap failed")
        if not self.lose_image_save:
            self.images[record.image_reference] = record
        return record

    def mount_open(self, mount: A.MountSpec) -> object:
        self.mount_open_count += 1
        digest = hashlib.sha256(mount.source.encode()).hexdigest()
        identities, component_digest = _component_facts(mount.source)
        values: dict[str, object] = {
            "source": mount.source, "target": mount.target, "readonly": mount.readonly,
            "device": 7, "inode": int(digest[:8], 16), "mode": 0o755,
            "uid": 501, "gid": 20, "link_count": 1,
            "size": 123,
            "kind": "file" if mount.source.endswith(".tar") else "directory",
            "component_chain_sha256": component_digest,
            "component_identities": identities, "content_sha256": digest,
            "descriptor_nofollow": True, "filesystem_alias_free": True,
            "recursive_metadata_complete": True, "symlink_entries_absent": True,
            "special_entries_absent": True, "hardlink_entries_absent": True,
            "cross_filesystem_entries_absent": True,
            "sensitive_entries_absent": True, "socket_entries_absent": True,
            "compressed_entries_absent": True,
            "archive_members_validated": mount.target == "/.plamen/image-archive",
            "oci_layout_sha256": ("5" * 64
                if mount.target == "/.plamen/image-archive" else None),
            "oci_index_digest": (_DIGEST
                if mount.target == "/.plamen/image-archive" else None),
            "oci_index_media_type": (A.OCI_IMAGE_INDEX_MEDIA_TYPE
                if mount.target == "/.plamen/image-archive" else None),
            "oci_manifest_digest": (_MANIFEST_DIGEST
                if mount.target == "/.plamen/image-archive" else None),
            "oci_manifest_media_type": (A.OCI_IMAGE_MANIFEST_MEDIA_TYPE
                if mount.target == "/.plamen/image-archive" else None),
            "oci_configuration_sha256": (_CONFIG_DIGEST
                if mount.target == "/.plamen/image-archive" else None),
            "xattr_names": (),
            "xattr_showcompression_used": True, "filesystem_root_alias": False,
        }
        values.update(self.mount_changes)
        return A._issue_mount_capability(self, **values)  # type: ignore[arg-type]

    def mount_revalidate(self, capability: object) -> None:
        self.mount_revalidate_count += 1
        if self.fail_revalidate:
            raise OSError("/secret/mount")
        A._mark_mount_revalidated(self, capability, unchanged=True)

    def mount_close(self, capability: object) -> None:
        self.mount_close_count += 1
        if self.fail_mount_close:
            raise OSError("/secret/mount")
        A._mark_mount_closed(self, capability)

    def mount_digest(self, spec: A.ContainerSpec) -> str:
        docs = []
        for item in sorted(spec.mounts, key=lambda value: value.target):
            digest = hashlib.sha256(item.source.encode()).hexdigest()
            identities, component_digest = _component_facts(item.source)
            docs.append({
                "component_chain_sha256": component_digest,
                "component_identities": list(identities), "device": 7, "gid": 20,
                "inode": int(digest[:8], 16), "kind": "directory",
                "link_count": 1 if item.readonly else None,
                "mode": 0o755, "size": 123 if item.readonly else None,
                "readonly": item.readonly, "source": item.source,
                "content_sha256": digest if item.readonly else None,
                "descriptor_nofollow": True, "filesystem_alias_free": True,
                "recursive_metadata_complete": True,
                "symlink_entries_absent": True, "special_entries_absent": True,
                "hardlink_entries_absent": True,
                "cross_filesystem_entries_absent": True,
                "sensitive_entries_absent": True, "socket_entries_absent": True,
                "compressed_entries_absent": True,
                "archive_members_validated": False, "oci_layout_sha256": None,
                "oci_index_digest": None, "oci_index_media_type": None,
                "oci_manifest_digest": None, "oci_manifest_media_type": None,
                "oci_configuration_sha256": None,
                "target": item.target, "uid": 501, "xattr_names": [],
                "xattr_showcompression_used": True,
            })
        return hashlib.sha256(json.dumps(docs, sort_keys=True,
                            separators=(",", ":")).encode()).hexdigest()

    def _issue_process(self, values: dict[str, object]) -> object:
        supplied = dict(values)
        supplied.update(self.driver_process_changes)
        return A._issue_driver_process_capability(  # type: ignore[arg-type]
            self, **supplied,
        )

    def driver_start(self, command: tuple[str, ...], **values: object) -> object:
        with self.driver_journal_lock:
            self.driver_start_calls += 1
        if self.driver_start_entered is not None:
            self.driver_start_entered.set()
        if self.driver_start_release is not None:
            if not self.driver_start_release.wait(timeout=2):
                raise OSError("driver start test barrier timed out")
        nonce = values["start_operation_nonce"]
        assert isinstance(nonce, str)
        facts: dict[str, object] = {
            "command": command,
            "executable_capability": values["executable_capability"],
            "mount_capabilities": values["mount_capabilities"],
            "mounted_identity_sha256": values["mounted_identity_sha256"],
            "provenance": values["provenance"],
            "container_id": values["container_id"],
            "attempt_id": values["attempt_id"],
            "spec_sha256": values["spec_sha256"],
            "launch_request_sha256": values["launch_request_sha256"],
            "launch_policy_sha256": values["launch_policy_sha256"],
            "driver_argv_sha256": values["driver_argv_sha256"],
            "driver_environment_sha256": values["driver_environment_sha256"],
            "driver_cwd_sha256": values["driver_cwd_sha256"],
            "driver_stdin_sha256": values["driver_stdin_sha256"],
            "pass_fd_roster_sha256": values["pass_fd_roster_sha256"],
            "start_operation_nonce": nonce,
            "native_process_id": "native-process-001",
            "native_process_handle_sha256": "4" * 64,
            "start_timestamp": "2026-09-08T01:00:00Z",
            "rosetta_required": values["rosetta_required"],
            "native_process_retained": True,
            "stdout_pipe_bound": True,
            "stderr_pipe_bound": True,
            "stdin_devnull": True,
            "guest_network_policy_sha256": values["guest_network_policy_sha256"],
            "guest_network_topology_sha256": values["guest_network_topology_sha256"],
            "guest_network_policy_enforced": True,
        }
        self.driver_processes[nonce] = facts
        return self._issue_process(facts)

    def driver_recover_process(
        self, record: A.DriverLifecycleRecord, **values: object,
    ) -> object | None:
        self.driver_recover_process_calls += 1
        stored = self.driver_processes.get(record.start_operation_nonce)
        if stored is None:
            return None
        recovered = dict(stored)
        recovered.update(
            command=values["command"],
            executable_capability=values["executable_capability"],
            mount_capabilities=values["mount_capabilities"],
            mounted_identity_sha256=values["mounted_identity_sha256"],
        )
        return self._issue_process(recovered)

    def _issue_wait(
        self, result: A.RunnerResult, capability: object,
        values: dict[str, object],
    ) -> A.RunnerResult:
        process = A._driver_process_facts(capability)
        assert process is not None
        evidence: dict[str, object] = {
            "process_capability": capability,
            "native_process_handle_sha256": process.native_process_handle_sha256,
            "wait_operation_nonce": values["wait_operation_nonce"],
            "start_timestamp": process.start_timestamp,
            "end_timestamp": "2026-09-08T01:01:00Z",
            "native_process_extinction_sha256": "5" * 64,
            "cleanup_sha256": "6" * 64,
            "stop_argv_sha256": "7" * 64,
            "stop_stdout_sha256": "8" * 64,
            "stop_stderr_sha256": "9" * 64,
            "stopped_observation_sha256": "a" * 64,
            "guest_population_extinction_sha256": "b" * 64,
            "descendants_extinct": True,
            "guest_process_extinct": True,
            "backend_egress_revoked": True,
            "stop_control_process_reaped": True,
            "stop_control_process_group_extinct": True,
            "guest_population_zero": True,
            "container_vm_stopped": True,
        }
        evidence.update(self.driver_wait_changes)
        A._issue_driver_wait_evidence(  # type: ignore[arg-type]
            self, result, **evidence,
        )
        nonce = values["wait_operation_nonce"]
        assert isinstance(nonce, str)
        self.driver_wait_results[nonce] = (result, {
            key: value for key, value in evidence.items()
            if key != "process_capability"
        })
        return result

    def driver_wait(self, capability: object, **values: object) -> A.RunnerResult:
        with self.driver_journal_lock:
            self.driver_wait_calls += 1
        if self.driver_wait_entered is not None:
            self.driver_wait_entered.set()
        if self.driver_wait_release is not None:
            if not self.driver_wait_release.wait(timeout=2):
                raise OSError("driver wait test barrier timed out")
        if self.driver_wait_outcomes:
            outcome = self.driver_wait_outcomes.pop(0)
            if isinstance(outcome, BaseException):
                raise outcome
            assert isinstance(outcome, A.RunnerResult)
            result = outcome
        else:
            result = _result(b'{"type":"result"}\n')
        return self._issue_wait(result, capability, values)

    def driver_recover_wait(
        self, record: A.DriverLifecycleRecord, *, process_capability: object,
        wait_operation_nonce: str | None, output_limit: int,
    ) -> A.RunnerResult | None:
        del output_limit
        self.driver_recover_wait_calls += 1
        if wait_operation_nonce is None:
            return None
        retained = self.driver_wait_results.get(wait_operation_nonce)
        if retained is None:
            return None
        result, evidence = retained
        recovered = dict(evidence)
        recovered["process_capability"] = process_capability
        process = A._driver_process_facts(process_capability)
        assert process is not None
        recovered["native_process_handle_sha256"] = process.native_process_handle_sha256
        A._issue_driver_wait_evidence(self, result, **recovered)  # type: ignore[arg-type]
        return result

    def driver_revoke(self, capability: object, **values: object) -> None:
        self.driver_revoke_calls += 1
        nonce = values["wait_operation_nonce"]
        retained = self.driver_wait_results.get(nonce) if isinstance(nonce, str) else None
        cleanup = retained[1]["cleanup_sha256"] if retained is not None else "6" * 64
        A._mark_driver_process_revoked(
            self, capability, native_process_extinct=True,
            guest_process_extinct=True, backend_egress_revoked=True,
            cleanup_sha256=cleanup, native_process_extinction_sha256="5" * 64,
            stop_argv_sha256="7" * 64, stop_stdout_sha256="8" * 64,
            stop_stderr_sha256="9" * 64,
            stopped_observation_sha256="a" * 64,
            guest_population_extinction_sha256="b" * 64,
            stop_control_process_reaped=True,
            stop_control_process_group_extinct=True,
            guest_population_zero=True, container_vm_stopped=True,
        )

    def driver_journal_load(
        self, container_id: str, attempt_id: str,
    ) -> A.DriverLifecycleRecord | None:
        with self.driver_journal_lock:
            self.driver_journal_load_count += 1
            return self.driver_records.get((container_id, attempt_id))

    def driver_journal_cas(
        self, record: A.DriverLifecycleRecord,
        previous: A.DriverLifecycleRecord | None,
    ) -> A.DriverLifecycleRecord:
        with self.driver_journal_lock:
            key = (record.container_id, record.attempt_id)
            if self.driver_records.get(key) != previous:
                raise OSError("driver journal compare-and-swap failed")
            if self.fail_driver_cas_state_once is record.state:
                self.fail_driver_cas_state_once = None
                raise OSError("driver journal failure")
            if self.lose_driver_cas_state_once is record.state:
                self.lose_driver_cas_state_once = None
                return record
            self.driver_records[key] = record
            if self.raise_after_driver_cas_state_once is record.state:
                self.raise_after_driver_cas_state_once = None
                raise OSError("driver journal acknowledgement lost")
            return record


def _host() -> A.HostPlatform:
    return A.HostPlatform("Darwin", "arm64", (26, 6, 2))


def _version_response(*, banner_commit: str = A.SUPPORTED_APPLE_CONTAINER_COMMIT[:7],
                      row_commit: str = A.SUPPORTED_APPLE_CONTAINER_COMMIT,
                      version: str = "1.3.1",
                      cli_commit: str = A.SUPPORTED_APPLE_CONTAINER_COMMIT) -> A.RunnerResult:
    return _json_result([
        {"appName": "container", "buildType": "release",
         "commit": cli_commit, "version": version},
        {"appName": "container-apiserver", "buildType": "release",
         "commit": row_commit,
         "version": f"container-apiserver version {version} "
                    f"(build: release, commit: {banner_commit})"},
    ])


def _status_response(*, version: str = "1.3.1",
                     commit: str = A.SUPPORTED_APPLE_CONTAINER_COMMIT,
                     **changes: object) -> A.RunnerResult:
    value: dict[str, object] = {
        "status": "running",
        "appRoot": "/Users/test/Library/Application Support/com.apple.container",
        "installRoot": "/usr/local/",
        "logRoot": "/Users/test/Library/Logs/com.apple.container",
        "apiServerVersion": f"container-apiserver version {version} "
                            f"(build: release, commit: {commit[:7]})",
        "apiServerCommit": commit,
        "apiServerBuild": "release",
        "apiServerAppName": "container-apiserver",
    }
    value.update(changes)
    return _json_result(value)


def _spec(*, rosetta_required: bool = False) -> A.ContainerSpec:
    egress_admission = _EGRESS_ADMISSION
    return A.ContainerSpec(
        name="plamen-dodo-001", run_identity="run-dodo-001",
        audit_attempt_id="dodo-001",
        request_fingerprint_sha256=hashlib.sha256(b"request-fingerprint").hexdigest(),
        config_sha256=hashlib.sha256(b"audit-config").hexdigest(),
        runtime_closure_sha256=hashlib.sha256(b"runtime-closure").hexdigest(),
        image_closure_sha256=hashlib.sha256(b"image-closure").hexdigest(),
        provider_provenance_sha256=_PROVENANCE_DIGEST,
        backend_admission_sha256=hashlib.sha256(b"backend-admission").hexdigest(),
        credential_isolation_sha256=hashlib.sha256(b"credential-isolation").hexdigest(),
        egress_admission_sha256=egress_admission,
        image_reference=_IMAGE, image_digest=_DIGEST,
        image_manifest_digest=_MANIFEST_DIGEST,
        image_configuration_sha256=_CONFIG_DIGEST,
        init_image_reference=A.SUPPORTED_INIT_IMAGE_REFERENCE,
        init_image_digest=A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST,
        init_image_manifest_digest=A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST,
        entrypoint="/usr/bin/python3",
        arguments=("-B", "/opt/plamen/scripts/plamen_driver.py", "resume"),
        working_directory="/workspace/project",
        mounts=tuple(
            A.MountSpec(
                f"/private/plamen/{index:02d}-{target.rsplit('/', 1)[-1]}",
                target, readonly,
            )
            for index, (target, readonly) in enumerate(A._AUDIT_MOUNT_POLICY)
        ),
        networks=(A.NetworkSpec(
            _NETWORK_NAME, "plamen-dodo-001", _NETWORK_POLICY,
            egress_admission,
            _NETWORK_TOPOLOGY, _NETWORK_RUN, _NETWORK_AUTHORITY, _NETWORK_SUBNET,
            _NETWORK_GATEWAY, _NETWORK_LABELS,
            mac_address=_NETWORK_MAC, ipv4_address=_NETWORK_ADDRESS,
        ),),
        expected_environment=("PATH=/usr/bin:/bin", "PYTHONUTF8=1"),
        labels=(("audit.role", "driver"),), cpus=4,
        memory_bytes=4 * 1024**3, uid=1000, gid=1000,
        rosetta_required=rosetta_required,
    )


def _driver_request(spec: A.ContainerSpec) -> A.DriverLaunchRequest:
    return A.DriverLaunchRequest(
        spec.name, spec.audit_attempt_id, spec.fingerprint, "9" * 64,
        A._canonical_digest([spec.entrypoint, *spec.arguments]),
        A._canonical_digest(list(spec.expected_environment)),
        A._canonical_digest(spec.working_directory),
        A._canonical_digest("DEVNULL"), A._canonical_digest([]),
        spec.rosetta_required,
    )


def _image_document(spec: A.ContainerSpec) -> list[dict[str, object]]:
    return [{
        "id": spec.image_digest.removeprefix("sha256:"),
        "configuration": {
            "creationDate": "2026-09-08T00:00:00Z", "name": spec.image_reference,
            "descriptor": {"digest": spec.image_digest,
                           "mediaType": "application/vnd.oci.image.index.v1+json",
                           "size": 321},
        },
        "variants": [{"platform": {"os": "linux", "architecture": "arm64"},
                      "digest": spec.image_manifest_digest, "size": 123,
                      "config": deepcopy(_IMAGE_CONFIG)}],
    }]


def _init_image_document() -> list[dict[str, object]]:
    return [{
        "id": A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST.removeprefix("sha256:"),
        "configuration": {
            "creationDate": "2026-09-08T00:00:00Z",
            "name": A.SUPPORTED_INIT_IMAGE_REFERENCE,
            "descriptor": {
                "digest": A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST,
                "mediaType": A.OCI_IMAGE_INDEX_MEDIA_TYPE,
                "size": 321,
            },
        },
        "variants": [{
            "platform": {"os": "linux", "architecture": "arm64"},
            "digest": A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST,
            "size": 123,
            "config": {"architecture": "arm64", "os": "linux"},
        }],
    }]


def _inspect_document(spec: A.ContainerSpec, record: A.MutationRecord, *, state: str,
                      creation_date: str = "2026-09-08T00:00:00Z") -> list[dict[str, object]]:
    return [{
        "id": spec.name,
        "configuration": {
            "id": spec.name,
            "image": {"reference": spec.image_reference,
                      "descriptor": {"digest": spec.image_digest,
                                     "mediaType": "application/vnd.oci.image.index.v1+json",
                                     "size": 123}},
            "mounts": [{"type": {"virtiofs": {}}, "source": item.source,
                        "destination": item.target,
                        "options": ["ro"] if item.readonly else []}
                       for item in sorted(spec.mounts, key=lambda value: value.target)],
            "publishedPorts": [], "publishedSockets": [],
            "labels": spec.expected_labels(record), "sysctls": {},
            "networks": [{"network": item.name,
                          "options": {"hostname": spec.name,
                                      "macAddress": item.mac_address, "mtu": item.mtu}}
                         for item in spec.networks],
            "dns": None, "rosetta": spec.rosetta_required,
            "initProcess": {"executable": spec.entrypoint,
                            "arguments": list(spec.arguments),
                            "environment": list(spec.expected_environment),
                            "workingDirectory": spec.working_directory,
                            "terminal": False,
                            "user": {"id": {"uid": spec.uid, "gid": spec.gid}},
                            "supplementalGroups": [], "rlimits": []},
            "platform": {"os": "linux", "architecture": "arm64"},
            "resources": {"cpus": spec.cpus, "memoryInBytes": spec.memory_bytes,
                          "storage": None, "cpuOverhead": 1},
            "runtimeHandler": "container-runtime-linux", "virtualization": False,
            "ssh": False, "readOnly": True, "useInit": True,
            "capAdd": [], "capDrop": ["ALL"], "shmSize": None,
            "stopSignal": None, "maskedPaths": None, "readonlyPaths": None,
            "creationDate": creation_date,
        },
        "status": {"state": state,
                   "networks": [{"network": item.name,
                                  "hostname": spec.name,
                                  "ipv4Address": item.ipv4_address,
                                  "ipv4Gateway": item.ipv4_gateway,
                                  "macAddress": item.mac_address,
                                  "mtu": item.mtu,
                                  "variant": item.attachment_variant}
                                 for item in spec.networks]},
    }]


def _seed(authority: FakeAuthority, spec: A.ContainerSpec, state: str,
          *, creation_date: str = "2026-09-08T00:00:00Z") -> A.MutationRecord:
    pending = A.MutationRecord(
        "plamen.apple-container.mutation.v3", A.MutationState.PENDING, spec.name,
        spec.fingerprint, authority.mount_digest(spec),
        "delete" if state == "absent" else "start" if state == "running" else "create",
        state, "1" * 32, "2" * 32, "3" * 32, _PROVENANCE_DIGEST, None,
    )
    postcondition = (A._absence_digest(pending) if state == "absent" else
                     hashlib.sha256(json.dumps(
                         _inspect_document(spec, pending, state=state,
                                           creation_date=creation_date)[0]["configuration"],
                         sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    terminal = replace(pending, state=A.MutationState.TERMINAL,
                       postcondition_sha256=postcondition)
    authority.records[spec.name] = terminal
    return terminal


def _provider(authority: FakeAuthority, *, preflight: bool = True) -> A.TEST_ONLY_AppleContainerProvider:
    provider = A.TEST_ONLY_AppleContainerProvider(
        executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
        version_pin=_PIN, authority=authority,
        host_probe=_host, timeout_seconds=2, output_limit_bytes=4096,
    )
    if preflight:
        provider.preflight()
    return provider


def _authority(responses: list[object] = ()) -> FakeAuthority:
    return FakeAuthority([_version_response(), _status_response(), *responses])


def _queue_driver_start(
    authority: FakeAuthority, spec: A.ContainerSpec, *, initial: bool = True,
) -> None:
    record = authority.records[spec.name]
    if initial:
        authority.responses.extend([
            _result((spec.name + "\n").encode()),
            _json_result(_inspect_document(spec, record, state="stopped")),
        ])
    authority.responses.append(
        _json_result(_inspect_document(spec, record, state="running"))
    )


def _admission(spec: A.ContainerSpec) -> A.ImageAdmissionRecord:
    return A.ImageAdmissionRecord(
        "plamen.apple-container.image-admission.v3", A.ImageAdmissionState.TERMINAL,
        spec.image_reference, spec.image_digest, spec.image_manifest_digest,
        spec.image_configuration_sha256,
        "linux", "arm64", "f" * 64, "3" * 32, _PROVENANCE_DIGEST,
        hashlib.sha256(json.dumps(_image_document(spec)[0], sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest(),
    )


def test_broker_v2_commitment_and_ten_mount_admission_are_exact() -> None:
    spec = _spec()
    assert tuple(spec.broker_v2_commitment) == (
        "request_fingerprint", "attempt_id", "run_identity", "config_sha256",
        "runtime_closure_sha256", "image_closure_sha256",
        "provider_provenance_sha256", "backend_admission_sha256",
        "credential_isolation_sha256", "egress_admission_sha256",
    )
    assert tuple((row.target, row.readonly) for row in spec.mounts) == (
        A._AUDIT_MOUNT_POLICY
    )
    assert spec.networks[0].topology_mode == "hostOnly"
    assert spec.networks[0].effective_egress_mode == "VERIFIED_CONNECT_ALLOWLIST"
    assert spec.networks[0].egress_admission_sha256 == spec.egress_admission_sha256


@pytest.mark.parametrize("field", [
    "request_fingerprint_sha256", "config_sha256", "runtime_closure_sha256",
    "image_closure_sha256", "provider_provenance_sha256",
    "backend_admission_sha256", "credential_isolation_sha256",
    "egress_admission_sha256",
])
def test_each_broker_v2_commitment_digest_is_required(field: str) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="digest"):
        replace(_spec(), **{field: "0" * 63})


def test_production_provider_is_separate_from_test_only_registries() -> None:
    assert A.AppleContainerProvider is not A.TEST_ONLY_AppleContainerProvider
    assert not hasattr(A, "_AUTHORITY_REGISTRY")
    assert not hasattr(A, "_EXECUTABLE_REGISTRY")
    assert not hasattr(A, "_MOUNT_REGISTRY")
    with pytest.raises(A.AppleContainerUnavailableError, match="native"):
        A.AppleContainerProvider(authority=object())


def test_preflight_exact_official_shapes_and_every_call_provenance() -> None:
    authority = _authority()
    receipt = _provider(authority).preflight()
    assert receipt.executable_path == str(A.DEFAULT_EXECUTABLE)
    assert receipt.executable_sha256 == A.SUPPORTED_CLI_EXECUTABLE_SHA256
    assert receipt.cli_version == "1.3.1"
    assert receipt.cli_signing_identifier == A.SUPPORTED_CLI_SIGNING_IDENTIFIER
    assert receipt.cli_signing_team_id == A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID
    assert receipt.package_identifier == A.SUPPORTED_PACKAGE_IDENTIFIER
    assert receipt.package_version == A.SUPPORTED_APPLE_CONTAINER_VERSION
    assert receipt.package_install_location == A.SUPPORTED_PACKAGE_INSTALL_LOCATION
    assert receipt.package_authorization == "root"
    assert receipt.package_signing_team_id == A.SUPPORTED_INSTALLER_TEAM_ID
    assert receipt.package_signed is True
    assert receipt.package_notarized is True
    assert receipt.package_timestamped is True
    assert receipt.server_executable_path == str(A.DEFAULT_SERVER_EXECUTABLE)
    assert receipt.server_executable_sha256 == A.SUPPORTED_SERVER_EXECUTABLE_SHA256
    assert receipt.server_signing_identifier == A.SUPPORTED_SERVER_SIGNING_IDENTIFIER
    assert receipt.server_signing_team_id == A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID
    assert receipt.plugin_root == str(A.DEFAULT_PLUGIN_ROOT)
    assert receipt.core_images_plugin_sha256 == A.SUPPORTED_CORE_IMAGES_PLUGIN_SHA256
    assert receipt.network_vmnet_plugin_sha256 == A.SUPPORTED_NETWORK_VMNET_PLUGIN_SHA256
    assert receipt.runtime_linux_plugin_sha256 == A.SUPPORTED_RUNTIME_LINUX_PLUGIN_SHA256
    assert receipt.machine_apiserver_plugin_sha256 == (
        A.SUPPORTED_MACHINE_APISERVER_PLUGIN_SHA256
    )
    assert receipt.plugin_signing_team_id == A.SUPPORTED_RUNTIME_SIGNING_TEAM_ID
    assert receipt.plugin_closure_sha256 == A.SUPPORTED_PLUGIN_CLOSURE_SHA256
    assert receipt.containerization_version == "0.42.0"
    assert receipt.containerization_commit == A.SUPPORTED_CONTAINERIZATION_COMMIT
    assert receipt.init_image_reference == A.SUPPORTED_INIT_IMAGE_REFERENCE
    assert receipt.init_image_index_digest == A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
    assert receipt.init_image_manifest_digest == A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
    assert receipt.init_image_postcondition_sha256 == hashlib.sha256(json.dumps(
        _init_image_document()[0], sort_keys=True, separators=(",", ":")
    ).encode()).hexdigest()
    assert receipt.kernel_archive_sha256 == A.SUPPORTED_KERNEL_ARCHIVE_SHA256
    assert receipt.kernel_archive_size == A.SUPPORTED_KERNEL_ARCHIVE_SIZE
    assert receipt.kernel_binary_member == A.SUPPORTED_KERNEL_BINARY_MEMBER
    assert receipt.kernel_binary_sha256 == A.SUPPORTED_KERNEL_BINARY_SHA256
    assert receipt.implicit_kernel_install_disabled is True
    assert [item[0] for item in authority.calls] == [
        ("system", "version", "--format", "json"),
        ("system", "status", "--format", "json"),
        ("image", "inspect", A.SUPPORTED_INIT_IMAGE_REFERENCE),
    ]
    assert all(item[3] for item in authority.calls)
    assert authority.exec_open_count == authority.exec_post_count == authority.exec_close_count == 3


def test_newer_compatible_signed_observation_is_admitted_without_release_pin() -> None:
    commit = "1" * 40
    newer = replace(
        _PIN,
        cli_version="1.4.0", server_version="1.4.0", package_version="1.4.0",
        cli_commit=commit, server_commit=commit, server_banner_commit=commit[:7],
        cli_executable_sha256="c" * 64,
        server_executable_sha256="d" * 64,
        containerization_version="0.43.0",
        containerization_commit="2" * 40,
        containerization_binary_sha256="e" * 64,
    )
    provenance = newer.provenance
    authority = FakeAuthority([
        Outcome(_version_response(
            version="1.4.0", cli_commit=commit, row_commit=commit,
            banner_commit=commit[:7],
        ), provenance=provenance),
        Outcome(_status_response(version="1.4.0", commit=commit),
                provenance=provenance),
    ])
    authority.init_image_response = Outcome(
        _json_result(_init_image_document()), provenance=provenance,
    )
    provider = A.TEST_ONLY_AppleContainerProvider(
        executable_sha256=newer.cli_executable_sha256,
        version_pin=newer, authority=authority, host_probe=_host,
        timeout_seconds=2, output_limit_bytes=4096,
    )
    receipt = provider.preflight()
    assert receipt.cli_version == receipt.server_version == "1.4.0"
    assert receipt.executable_sha256 == "c" * 64


def test_newer_version_without_exact_capability_schema_is_rejected() -> None:
    commit = "1" * 40
    newer = replace(
        _PIN,
        cli_version="1.4.0", server_version="1.4.0", package_version="1.4.0",
        cli_commit=commit, server_commit=commit, server_banner_commit=commit[:7],
        cli_executable_sha256="c" * 64,
    )
    malformed = json.loads(_version_response(
        version="1.4.0", cli_commit=commit, row_commit=commit,
        banner_commit=commit[:7],
    ).stdout)
    malformed[0]["capabilities"] = ["start", "stop"]
    authority = FakeAuthority([
        Outcome(_json_result(malformed), provenance=newer.provenance),
    ])
    provider = A.TEST_ONLY_AppleContainerProvider(
        executable_sha256=newer.cli_executable_sha256,
        version_pin=newer, authority=authority, host_probe=_host,
    )
    with pytest.raises(A.AppleContainerProtocolError, match="schema"):
        provider.preflight()


def test_staged_kata_member_pin_is_exact_but_not_installed_proof() -> None:
    assert A.SUPPORTED_KERNEL_BINARY_MEMBER == (
        "./opt/kata/share/kata-containers/vmlinux-6.18.35-197-debug"
    )
    assert A.SUPPORTED_KERNEL_BINARY_SHA256 == (
        "fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d"
    )
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_PIN, kernel_binary_sha256="9" * 64)


@pytest.mark.parametrize("changes", [
    {"init_image_reference":
        "ghcr.io/apple/containerization/vminit:0.42.0"},
    {"init_image_reference":
        "GHCR.IO/apple/containerization/vminit@"
        + A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST},
    {"init_image_reference": "ghcr.io/apple/containerization/vminit@sha256:"
        + "9" * 64, "init_image_index_digest": "sha256:" + "9" * 64},
    {"init_image_manifest_digest": "sha256:" + "8" * 64},
])
def test_version_pin_rejects_mutable_aliased_or_rebound_init_image(
    changes: dict[str, str],
) -> None:
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_PIN, **changes)


@pytest.mark.parametrize("field,value", [
    ("cli_executable_sha256", "0" * 64),
    ("cli_signing_identifier", "com.apple.container"),
    ("cli_signing_team_id", "AAAAAAAAAA"),
    ("server_executable_sha256", "0" * 64),
    ("server_signing_identifier", "com.apple.container.server"),
    ("server_signing_team_id", "AAAAAAAAAA"),
    ("core_images_plugin_sha256", "0" * 64),
    ("network_vmnet_plugin_sha256", "0" * 64),
    ("runtime_linux_plugin_sha256", "0" * 64),
    ("machine_apiserver_plugin_sha256", "0" * 64),
    ("plugin_signing_team_id", "AAAAAAAAAA"),
    ("plugin_closure_sha256", "0" * 64),
])
def test_version_pin_rejects_runtime_binary_or_signature_substitution(
    field: str, value: str,
) -> None:
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_PIN, **{field: value})


@pytest.mark.parametrize("changes", [
    {"init_image_reference":
        "ghcr.io/apple/containerization/vminit:0.42.0"},
    {"init_image_reference":
        "GHCR.IO/apple/containerization/vminit@"
        + A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST},
    {"init_image_reference": "ghcr.io/apple/containerization/vminit@sha256:"
        + "9" * 64, "init_image_digest": "sha256:" + "9" * 64},
    {"init_image_manifest_digest": "sha256:" + "8" * 64},
])
def test_container_spec_rejects_mutable_aliased_or_rebound_init_image(
    changes: dict[str, str],
) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="init image"):
        replace(_spec(), **changes)


@pytest.mark.parametrize("mutate", [
    lambda d: d[0]["configuration"].update(
        name="ghcr.io/apple/containerization/vminit:0.42.0"
    ),
    lambda d: d[0].update(id="9" * 64),
    lambda d: d[0]["configuration"]["descriptor"].update(
        digest="sha256:" + "9" * 64
    ),
    lambda d: d[0]["variants"][0].update(digest="sha256:" + "8" * 64),
    lambda d: d[0]["variants"][0]["platform"].update(architecture="amd64"),
    lambda d: d[0].update(unexpected=True),
])
def test_preflight_rejects_init_image_alias_digest_platform_or_schema_drift(
    mutate: Callable[[Any], None],
) -> None:
    document = _init_image_document()
    mutate(document)
    authority = _authority()
    authority.init_image_response = _json_result(document)
    with pytest.raises(A.AppleContainerProviderError):
        _provider(authority, preflight=False).preflight()


def test_unregistered_or_identity_copy_authority_cannot_preflight() -> None:
    class Forgery:
        pass
    provider = A.TEST_ONLY_AppleContainerProvider(
        executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
        version_pin=_PIN, authority=Forgery(), host_probe=_host)
    with pytest.raises(A.AppleContainerUnavailableError, match="authority"):
        provider.preflight()
    uninitialized = object.__new__(FakeAuthority)
    provider = A.TEST_ONLY_AppleContainerProvider(
        executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256, version_pin=_PIN,
        authority=uninitialized, host_probe=_host,
    )
    with pytest.raises(A.AppleContainerUnavailableError, match="authority"):
        provider.preflight()
    assert not hasattr(A, "RunnerSecurityContract")
    assert not hasattr(A, "InvocationSecurityReceipt")


def test_registration_captures_exact_callbacks_and_public_results_carry_no_authority() -> None:
    authority = _authority()
    captured = authority.invoke
    authority.invoke = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("swapped"))  # type: ignore[method-assign]
    _provider(authority)
    assert authority.calls and captured.__self__ is authority

    weak = FakeAuthority([Outcome(_version_response(), issue_evidence=False)])
    provider = _provider(weak, preflight=False)
    with pytest.raises(A.AppleContainerUnavailableError, match="evidence"):
        provider.preflight()


def test_invocation_evidence_is_bound_to_the_exact_result_object() -> None:
    class SwappedResultAuthority(FakeAuthority):
        def invoke(self, *args: object, **kwargs: object) -> A.RunnerResult:
            result = super().invoke(*args, **kwargs)  # type: ignore[arg-type]
            evidence = A._TEST_ONLY_INVOCATION_REGISTRY.pop(id(result))
            A._TEST_ONLY_INVOCATION_REGISTRY[id(result)] = replace(
                evidence, result=replace(result)
            )
            return result

    authority = SwappedResultAuthority([_version_response()])
    with pytest.raises(A.AppleContainerUnavailableError, match="evidence"):
        _provider(authority, preflight=False).preflight()
    assert authority.exec_close_count == 1


def test_vulnerable_130_and_nonexact_banner_commit_are_rejected() -> None:
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_PIN, cli_version="1.3.0", server_version="1.3.0",
                containerization_version="0.41.0", containerization_commit="1" * 40)
    for banner in ("def", "def1234", "def1234567"):
        authority = FakeAuthority([_version_response(banner_commit=banner)])
        with pytest.raises((A.AppleContainerProtocolError, A.AppleContainerUnavailableError)):
            _provider(authority, preflight=False).preflight()


@pytest.mark.parametrize("changes", [
    {"apiServerCommit": "a" * 40},
    {"apiServerVersion": "1.3.1"},
    {"apiServerBuild": "debug"},
    {"apiServerAppName": "container"},
    {"installRoot": "/tmp/container"},
    {"appRoot": "/usr/local"},
    {"securityMode": "off"},
    {"logRoot": "relative/log"},
])
def test_exact_official_status_schema_and_identity_fail_closed(
    changes: dict[str, object],
) -> None:
    status = json.loads(_status_response().stdout)
    status.update(changes)
    authority = FakeAuthority([_version_response(), _json_result(status)])
    with pytest.raises(A.AppleContainerProviderError):
        _provider(authority, preflight=False).preflight()


def test_official_optional_status_log_root_may_be_omitted_or_null() -> None:
    for include_null in (False, True):
        status = json.loads(_status_response().stdout)
        if include_null:
            status["logRoot"] = None
        else:
            status.pop("logRoot")
        authority = FakeAuthority([_version_response(), _json_result(status)])
        assert _provider(authority, preflight=False).preflight().server_version == "1.3.1"


@pytest.mark.parametrize("name", [
    "../driver", "driver/../victim", "driver\\victim", "ab..cd", ".", "..",
    "driver-", "driver_", "driver.", "driver\u2215victim", "driver\uff0fvictim",
    "driver\u2044victim", "driver%2fvictim",
])
def test_generated_ids_are_single_component_ascii(name: str) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="canonical"):
        replace(_spec(), name=name)


@pytest.mark.parametrize("reference", [
    "ghcr.io/plamen/runtime:latest", "user:password@ghcr.io/plamen/runtime@" + _DIGEST,
    "ghcr.io:99999/plamen/runtime@" + _DIGEST,
    "ghcr..io/plamen/runtime@" + _DIGEST,
    "ghcr.io//plamen/runtime@" + _DIGEST,
    "GHCR.io/plamen/runtime@" + _DIGEST,
    "ghcr.io/plamen/runtime@" + _DIGEST + "?token=x",
])
def test_oci_references_reject_tags_credentials_ports_aliases_and_queries(reference: str) -> None:
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_spec(), image_reference=reference)


def test_index_and_platform_manifest_digests_are_distinct_exact_pins() -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="manifest digest"):
        replace(_spec(), image_manifest_digest=_DIGEST)


@pytest.mark.parametrize("key", [
    "io.plamen.network-role", "io.plamen.network-authority",
    "IO.PLAMEN.NETWORK-AUTHORITY", "Io.PlAmEn.future-security-control",
])
def test_entire_plamen_security_label_namespace_is_reserved_case_insensitively(
    key: str,
) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="label"):
        replace(_spec(), labels=((key, "forged"),))


@pytest.mark.parametrize("source,target", [
    ("/", "/workspace"), ("//", "/workspace"), ("///private/x", "/workspace"),
    ("/System/Volumes/Data", "/workspace"), ("/private/a/../b", "/workspace"),
    ("/private/a", "/"), ("/private/a", "//workspace"),
    ("/private/a", "/workspace/"),
])
def test_mount_roots_double_slash_and_canonical_aliases_rejected(source: str, target: str) -> None:
    with pytest.raises(A.AppleContainerConfigurationError):
        A.MountSpec(source, target, True)


@pytest.mark.parametrize("changes", [
    {"kind": "file", "link_count": 2}, {"xattr_names": ("com.apple.quarantine",)},
    {"xattr_showcompression_used": False}, {"filesystem_root_alias": True},
    {"component_chain_sha256": "not-a-digest"},
])
def test_mount_hardlink_xattr_showcompression_and_root_evidence_exact(changes: dict[str, object]) -> None:
    authority = _authority([])
    authority.mount_changes.update(changes)
    provider = _provider(authority)
    with pytest.raises(A.AppleContainerUnavailableError, match="mount"):
        provider.recover(_spec())
    assert authority.mount_close_count >= 1


def test_mounts_revalidated_passed_and_closed_for_recover_calls() -> None:
    spec = _spec()
    authority = _authority([_result(b"")])
    assert _provider(authority).recover(spec).decision == A.RecoveryDecision.ABSENT
    list_call = authority.calls[-1]
    assert list_call[0] == ("list", "--all", "--quiet")
    assert list_call[4] == len(spec.mounts)
    assert authority.mount_revalidate_count >= authority.mount_open_count
    assert authority.mount_close_count == authority.mount_open_count
    assert not any(item.owner is authority for item in A._TEST_ONLY_MOUNT_REGISTRY.values())
    assert not any(item.owner is authority for item in A._TEST_ONLY_EXECUTABLE_REGISTRY.values())
    assert not any(item.owner is authority for item in A._TEST_ONLY_INVOCATION_REGISTRY.values())


def test_mount_close_failure_attempts_every_lease_and_fails_closed() -> None:
    spec = _spec()
    authority = _authority([])
    authority.fail_mount_close = True
    with pytest.raises(A.AppleContainerAmbiguousError, match="revoked"):
        _provider(authority).recover(spec)
    assert authority.mount_close_count == len(spec.mounts)
    assert any(item.owner is authority for item in A._TEST_ONLY_MOUNT_REGISTRY.values())


@pytest.mark.parametrize("timeout", [True, 0, -1, 1.5, float("nan"), float("inf"), 301])
def test_timeout_rejects_bool_fractional_nonfinite_and_huge(timeout: object) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="timeout"):
        A.TEST_ONLY_AppleContainerProvider(
            executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256, version_pin=_PIN,
                                 authority=object(), timeout_seconds=timeout)  # type: ignore[arg-type]


@pytest.mark.parametrize("observed", [True, -1, A.MAX_STREAM_TOTAL_BYTES + 1, 2**100])
def test_stream_totals_are_bounded_integers(observed: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _result(b"x", stdout_observed=observed)  # type: ignore[arg-type]


def test_complete_retained_stream_digest_is_recomputed() -> None:
    with pytest.raises(ValueError, match="inconsistent"):
        _result(b"abc", stdout_digest="0" * 64)
    result = _result(b"abc")
    assert result.stdout_full_sha256 == hashlib.sha256(b"abc").hexdigest()


@pytest.mark.parametrize("payload", [b"NaN", b"Infinity", b"1.5", b"1e100", b"9223372036854775808"])
def test_json_rejects_nonfinite_fractional_and_oversized_numbers(payload: bytes) -> None:
    authority = FakeAuthority([_result(payload)])
    with pytest.raises(A.AppleContainerProtocolError):
        _provider(authority, preflight=False).preflight()


def test_10k_argv_sensitive_values_and_mutable_options_are_closed() -> None:
    spec = _spec()
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(spec, arguments=tuple("x" for _ in range(10_000)))
    for argument in ("--token=hunter2", "password=hunter2", "--pull"):
        with pytest.raises(A.AppleContainerConfigurationError, match="sensitive|forbidden"):
            replace(spec, arguments=(argument,))
    with pytest.raises(A.AppleContainerConfigurationError):
        A._validate_argv(("image", "load", "--input", "/tmp/a", "--force"), "image-load")
    for arguments, operation in (
        (("system", "start", "--enable-kernel-install"), "system-start"),
        (("kill", "--signal", "KILL", "../victim"), "kill"),
        (("stop", "--time", "1", "../victim"), "stop"),
        (("logs", "-n", "1", "../victim"), "logs"),
        (("image", "load", "--input", "/private/tmp/runtime.tar"), "image-load"),
        (("image", "inspect", "runtime:latest"), "image-inspect"),
    ):
        with pytest.raises(A.AppleContainerConfigurationError):
            A._validate_argv(arguments, operation)
    spec = _spec()
    pending = A.MutationRecord(
        "plamen.apple-container.mutation.v3", A.MutationState.PENDING, spec.name,
        spec.fingerprint, "4" * 64, "create", "stopped",
        "1" * 32, "2" * 32, "3" * 32, _PROVENANCE_DIGEST, None,
    )
    create = list(A.TEST_ONLY_AppleContainerProvider._create_arguments(spec, pending))
    create[0] = "run"
    with pytest.raises(A.AppleContainerConfigurationError, match="grammar"):
        A._validate_argv(tuple(create), "create")
    create[0] = "create"
    create[1:1] = ["--uid", "1000"]
    with pytest.raises(A.AppleContainerConfigurationError, match="duplicated"):
        A._validate_argv(tuple(create), "create")


@pytest.mark.parametrize("flag,value", [
    ("--name", "plamen-other-001"),
    ("--platform", "linux/amd64"),
    ("--cpus", "5"),
    ("--memory", str(5 * 1024**3)),
    ("--uid", "1001"),
    ("--gid", "1001"),
    ("--workdir", "/other"),
    ("--entrypoint", "/bin/sh"),
    ("--cap-drop", "NET_ADMIN"),
    ("--network", "plamen-egress-other,mac=02:42:ac:11:00:02,mtu=1280"),
])
def test_create_argv_values_are_exactly_bound_to_admitted_spec(
    flag: str, value: str,
) -> None:
    spec = _spec()
    pending = A.MutationRecord(
        "plamen.apple-container.mutation.v3", A.MutationState.PENDING, spec.name,
        spec.fingerprint, "4" * 64, "create", "stopped",
        "1" * 32, "2" * 32, "3" * 32, _PROVENANCE_DIGEST, None,
    )
    original = A.TEST_ONLY_AppleContainerProvider._create_arguments(spec, pending)
    A._validate_argv(
        original, "create", create_spec=spec, create_record=pending
    )
    changed = list(original)
    changed[changed.index(flag) + 1] = value
    with pytest.raises(A.AppleContainerConfigurationError, match="values or ordering"):
        A._validate_argv(
            tuple(changed), "create", create_spec=spec, create_record=pending
        )


def test_create_argv_labels_mounts_arguments_and_order_are_exact() -> None:
    spec = _spec()
    pending = A.MutationRecord(
        "plamen.apple-container.mutation.v3", A.MutationState.PENDING, spec.name,
        spec.fingerprint, "4" * 64, "create", "stopped",
        "1" * 32, "2" * 32, "3" * 32, _PROVENANCE_DIGEST, None,
    )
    original = A.TEST_ONLY_AppleContainerProvider._create_arguments(spec, pending)
    mutations: list[tuple[str, ...]] = []
    for flag in ("--label", "--mount"):
        changed = list(original)
        changed[changed.index(flag) + 1] += "x"
        mutations.append(tuple(changed))
    changed = list(original)
    changed[-1] = "other"
    mutations.append(tuple(changed))
    changed = list(original)
    cpus = changed.index("--cpus")
    memory = changed.index("--memory")
    changed[cpus:cpus + 2], changed[memory:memory + 2] = (
        changed[memory:memory + 2], changed[cpus:cpus + 2]
    )
    mutations.append(tuple(changed))
    for arguments in mutations:
        with pytest.raises(A.AppleContainerConfigurationError, match="values or ordering"):
            A._validate_argv(
                arguments, "create", create_spec=spec, create_record=pending
            )


@pytest.mark.parametrize("outcome", [
    Outcome(_result(b"[]"), provenance=("wrong",) * 6),
    Outcome(_result(b"[]"), descendants_extinct=False),
    Outcome(_result(b"[]"), network_policy_enforced=False),
    Outcome(_result(b"[]"), network_accessed=True),
    Outcome(_result(b"[]"), registry_accessed=True),
    Outcome(_result(b"[]"), image_fetch_performed=True),
    Outcome(_result(b"[]"), network_accessed=0),  # type: ignore[arg-type]
    Outcome(_result(b"[]"), registry_accessed=0),  # type: ignore[arg-type]
    Outcome(_result(b"[]"), image_fetch_performed=0),  # type: ignore[arg-type]
    Outcome(_result(b"[]"), issue_evidence=False),
])
def test_each_call_requires_exact_provenance_extinction_and_native_network_denial(outcome: Outcome) -> None:
    authority = FakeAuthority([outcome])
    with pytest.raises(A.AppleContainerUnavailableError, match="evidence"):
        _provider(authority, preflight=False).preflight()
    assert authority.exec_close_count == 1


@pytest.mark.parametrize("which", ["post", "close"])
def test_executable_descriptor_kept_through_post_fstat_and_close(which: str) -> None:
    authority = FakeAuthority([_version_response()])
    authority.fail_exec_post = which == "post"
    authority.fail_exec_close = which == "close"
    with pytest.raises(A.AppleContainerAmbiguousError, match="cleanup"):
        _provider(authority, preflight=False).preflight()
    assert any(item.owner is authority for item in A._TEST_ONLY_EXECUTABLE_REGISTRY.values())


def test_exact_terminal_postcondition_rejects_deleted_recreated_container() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "running")
    authority.responses.extend([
        _result((spec.name + "\n").encode()),
        _json_result(_inspect_document(spec, record, state="running",
                                       creation_date="2026-09-09T00:00:00Z")),
    ])
    receipt = _provider(authority).recover(spec)
    assert receipt.decision == A.RecoveryDecision.MISMATCH
    assert receipt.reason_code == "POSTCONDITION_REPLAY_MISMATCH"


def test_attempt_generation_spec_image_mount_config_labels_are_exact() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "running")
    labels = spec.expected_labels(record)
    assert set(labels) >= {
        A._ATTEMPT_LABEL, A._GENERATION_LABEL, A._SPEC_LABEL, A._IMAGE_LABEL,
        A._IMAGE_MANIFEST_LABEL, A._INIT_IMAGE_LABEL,
        A._INIT_IMAGE_MANIFEST_LABEL, A._MOUNT_LABEL, A._CONFIG_LABEL,
    }
    document = _inspect_document(spec, record, state="running")
    config = document[0]["configuration"]
    assert isinstance(config, dict)
    labels = dict(labels)
    labels[A._GENERATION_LABEL] = "9" * 32
    config["labels"] = labels
    authority.responses.extend([_result((spec.name + "\n").encode()), _json_result(document)])
    receipt = _provider(authority).recover(spec)
    assert receipt.reason_code == "LABEL_MISMATCH"


def test_missing_journal_never_adopts_existing_exact_identity() -> None:
    spec = _spec()
    authority = _authority([_result((spec.name + "\n").encode())])
    receipt = _provider(authority).recover(spec)
    assert receipt.reason_code == "MISSING_CREATION_AUTHORITY"


@pytest.mark.parametrize("operation,expected_state,postcondition", [
    ("future-operation", None, "0" * 64),
    ("delete", "absent", "0" * 64),
])
def test_recovery_rejects_unknown_operation_and_malformed_terminal_evidence(
    operation: str, expected_state: object, postcondition: str,
) -> None:
    spec = _spec()
    authority = _authority()
    valid = _seed(authority, spec, "stopped")
    authority.records[spec.name] = replace(
        valid, operation=operation, expected_state=expected_state,
        postcondition_sha256=postcondition,
    )  # type: ignore[arg-type]
    with pytest.raises(A.AppleContainerProtocolError, match="journal"):
        _provider(authority).recover(spec)
    assert not any(call[0][0] == "list" for call in authority.calls)


def test_terminal_stopped_record_never_adopts_unjournalled_running_state() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "stopped")
    # State is outside the immutable configuration digest; starting is still an
    # authenticated mutation and cannot be inferred from a matching config.
    authority.responses.extend([
        _result((spec.name + "\n").encode()),
        _json_result(_inspect_document(spec, record, state="running")),
    ])
    receipt = _provider(authority).recover(spec)
    assert receipt.reason_code == "UNJOURNALLED_START"


@pytest.mark.parametrize("field,value", [
    ("rosetta", 0), ("virtualization", 0), ("ssh", 0),
    ("readOnly", 1), ("useInit", 1),
    ("publishedPorts", False), ("publishedSockets", False),
    ("sysctls", False), ("capAdd", False), ("capDrop", False),
    ("dns", False), ("shmSize", False),
    ("maskedPaths", False), ("readonlyPaths", False),
])
def test_inspect_security_fields_require_exact_scalar_and_container_types(
    field: str, value: object,
) -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "stopped")
    document = _inspect_document(spec, record, state="stopped")
    configuration = document[0]["configuration"]
    assert isinstance(configuration, dict)
    configuration[field] = value
    authority.responses.extend([
        _result((spec.name + "\n").encode()), _json_result(document),
    ])
    receipt = _provider(authority).recover(spec)
    assert receipt.decision == A.RecoveryDecision.MISMATCH
    assert receipt.reason_code == "SECURITY_CONFIGURATION_MISMATCH"


@pytest.mark.parametrize("location,field", [
    ("resources", "cpus"), ("resources", "memoryInBytes"),
    ("resources", "cpuOverhead"), ("user", "uid"), ("user", "gid"),
])
def test_inspect_resource_and_guest_ids_reject_boolean_integer_aliases(
    location: str, field: str,
) -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "stopped")
    document = _inspect_document(spec, record, state="stopped")
    configuration = document[0]["configuration"]
    assert isinstance(configuration, dict)
    if location == "resources":
        values = configuration["resources"]
    else:
        process = configuration["initProcess"]
        assert isinstance(process, dict)
        user = process["user"]
        assert isinstance(user, dict)
        values = user["id"]
    assert isinstance(values, dict)
    values[field] = True
    authority.responses.extend([
        _result((spec.name + "\n").encode()), _json_result(document),
    ])
    with pytest.raises(A.AppleContainerProtocolError, match="bounded integer"):
        _provider(authority).recover(spec)


def test_pending_restart_terminalizes_only_exact_configuration_digest() -> None:
    spec = _spec()
    authority = _authority()
    pending = A.MutationRecord(
        "plamen.apple-container.mutation.v3", A.MutationState.PENDING, spec.name,
        spec.fingerprint, authority.mount_digest(spec), "start", "running",
        "4" * 32, "2" * 32, "3" * 32, _PROVENANCE_DIGEST, None,
    )
    authority.records[spec.name] = pending
    document = _inspect_document(spec, pending, state="running")
    authority.responses.extend([
        _result((spec.name + "\n").encode()), _json_result(document),
        _json_result(document),
    ])
    assert _provider(authority).recover(spec).decision == A.RecoveryDecision.RUNNING_MATCH
    terminal = authority.records[spec.name]
    assert terminal.state == A.MutationState.TERMINAL
    assert terminal.postcondition_sha256 == hashlib.sha256(json.dumps(
        document[0]["configuration"], sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()


def test_image_admission_is_separate_load_then_exact_inspect_no_force() -> None:
    spec = _spec()
    authority = _authority([_result(b"loaded\n"), _json_result(_image_document(spec))])
    provider = _provider(authority)
    record = provider.admit_local_image(spec, "/private/plamen/runtime.tar")
    assert authority.images[spec.image_reference] == record
    operations = [call[0] for call in authority.calls]
    assert ("image", "load", "--input", "/private/plamen/runtime.tar") in operations
    assert ("image", "inspect", spec.image_reference) in operations
    assert not any("--force" in call for call in operations)
    assert all(call[3] for call in authority.calls)


def test_provider_v4_binds_retained_archive_and_layout_receipt() -> None:
    spec = _spec()
    authority = _authority([_result(), _json_result(_image_document(spec))])
    authority.mount_changes["oci_layout_receipt_sha256"] = "9" * 64
    admitted = _provider(authority).admit_local_image_v4(
        spec, "/private/plamen/runtime.tar"
    )
    assert admitted.schema == "plamen.apple-container.image-admission.v4"
    assert admitted.archive_content_sha256 == hashlib.sha256(
        b"/private/plamen/runtime.tar").hexdigest()
    assert admitted.archive_size == 123
    assert admitted.layout_receipt_sha256 == "9" * 64
    assert admitted.image_closure_sha256 == spec.image_closure_sha256


def test_provider_v4_refuses_missing_layout_receipt_before_journal() -> None:
    authority = _authority()
    with pytest.raises(A.AppleContainerUnavailableError,
                       match="layout receipt authority is absent"):
        _provider(authority).admit_local_image_v4(
            _spec(), "/private/plamen/runtime.tar")
    assert authority.images == {}


def test_provider_v3_remains_distinct_when_v4_facts_exist() -> None:
    spec = _spec()
    authority = _authority([_result(), _json_result(_image_document(spec))])
    authority.mount_changes["oci_layout_receipt_sha256"] = "9" * 64
    admitted = _provider(authority).admit_local_image(
        spec, "/private/plamen/runtime.tar")
    assert admitted.schema == "plamen.apple-container.image-admission.v3"
    assert (admitted.archive_content_sha256, admitted.archive_size,
            admitted.layout_receipt_sha256, admitted.image_closure_sha256) == (
                None, None, None, None)


def test_provider_v4_exact_replay_only_inspects_without_second_load() -> None:
    spec = _spec()
    authority = _authority([_result(), _json_result(_image_document(spec)),
                            _json_result(_image_document(spec))])
    authority.mount_changes["oci_layout_receipt_sha256"] = "9" * 64
    provider = _provider(authority)
    first = provider.admit_local_image_v4(spec, "/private/plamen/runtime.tar")
    assert provider.admit_local_image_v4(spec, "/private/plamen/runtime.tar") == first
    assert sum("load" in call[0] for call in authority.calls) == 1


@pytest.mark.parametrize("first_v4", [False, True])
def test_provider_image_admission_cannot_switch_lanes(first_v4: bool) -> None:
    spec = _spec()
    authority = _authority([_result(), _json_result(_image_document(spec))])
    authority.mount_changes["oci_layout_receipt_sha256"] = "9" * 64
    provider = _provider(authority)
    first = provider.admit_local_image_v4 if first_v4 else provider.admit_local_image
    second = provider.admit_local_image if first_v4 else provider.admit_local_image_v4
    record = first(spec, "/private/plamen/runtime.tar")
    before = len(authority.calls)
    with pytest.raises(A.AppleContainerMismatchError, match="compatibility lane"):
        second(spec, "/private/plamen/runtime.tar")
    assert len(authority.calls) == before
    assert provider._load_image_record(spec.image_reference) == record


def test_provider_v4_create_gate_rejects_foreign_closure_before_inspect() -> None:
    spec = _spec()
    authority = _authority([_result(), _json_result(_image_document(spec))])
    authority.mount_changes["oci_layout_receipt_sha256"] = "9" * 64
    provider = _provider(authority)
    provider.admit_local_image_v4(spec, "/private/plamen/runtime.tar")
    before = len(authority.calls)
    with pytest.raises(A.AppleContainerMismatchError, match="admission is unavailable"):
        provider._require_admitted_image(replace(spec, image_closure_sha256="7" * 64))
    assert len(authority.calls) == before


@pytest.mark.parametrize("mutate", [
    lambda d: d[0].update(id="a" * 64),
    lambda d: d[0]["configuration"].update(name="evil.invalid/x@" + _DIGEST),
    lambda d: d[0]["variants"][0]["platform"].update(architecture="amd64"),
    lambda d: d[0]["variants"][0].update(config={}),
    lambda d: d[0].update(futureSecurityField=True),
])
def test_local_image_digest_platform_config_and_schema_are_exact(mutate: Callable[[Any], None]) -> None:
    spec = _spec()
    document = _image_document(spec)
    mutate(document)
    authority = _authority([_result(b"loaded\n"), _json_result(document)])
    with pytest.raises(A.AppleContainerProviderError):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")


@pytest.mark.parametrize("field,value", [
    ("size", True), ("size", 0), ("size", 2**63),
    ("creationDate", True), ("creationDate", None),
    ("creationDate", "2026-09-08 00:00:00"),
])
def test_image_index_size_and_creation_date_have_exact_bounded_types(
    field: str, value: object,
) -> None:
    spec = _spec()
    document = _image_document(spec)
    configuration = document[0]["configuration"]
    assert isinstance(configuration, dict)
    if field == "size":
        descriptor = configuration["descriptor"]
        assert isinstance(descriptor, dict)
        descriptor[field] = value
    else:
        configuration[field] = value
    authority = _authority([_result(b"loaded\n"), _json_result(document)])
    with pytest.raises(A.AppleContainerAmbiguousError, match="image load"):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")
    assert authority.images[spec.image_reference].state == A.ImageAdmissionState.PENDING


def test_create_refuses_local_miss_and_never_calls_create() -> None:
    spec = _spec()
    authority = _authority([_result(b"")])
    with pytest.raises(A.AppleContainerMismatchError, match="admission"):
        _provider(authority).create(spec)
    assert not any(call[0][0] == "create" for call in authority.calls)


def test_create_pending_before_call_and_no_fetch_pull_load_or_force() -> None:
    spec = _spec()
    authority = _authority()
    authority.images[spec.image_reference] = _admission(spec)

    def create_result(arguments: tuple[str, ...]) -> A.RunnerResult:
        pending = authority.records[spec.name]
        assert pending.state == A.MutationState.PENDING
        assert arguments[0] == "create"
        assert not {"pull", "--pull", "--force", "load"}.intersection(arguments)
        return _result((spec.name + "\n").encode())

    def inspect_result(_arguments: tuple[str, ...]) -> A.RunnerResult:
        return _json_result(_inspect_document(spec, authority.records[spec.name], state="stopped"))

    authority.responses.extend([
        _result(b""), _json_result(_image_document(spec)), create_result, inspect_result,
    ])
    receipt = _provider(authority).create(spec)
    assert receipt.observed_state == "stopped"
    assert receipt.init_image_reference == A.SUPPORTED_INIT_IMAGE_REFERENCE
    assert receipt.init_image_index_digest == A.SUPPORTED_INIT_IMAGE_INDEX_DIGEST
    assert receipt.init_image_manifest_digest == A.SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
    assert authority.records[spec.name].state == A.MutationState.TERMINAL
    create_call = next(call for call in authority.calls if call[0][0] == "create")
    assert create_call[3] is True and create_call[4] == len(spec.mounts)
    argv = create_call[0]
    init_index = argv.index("--init-image")
    workload_index = argv.index(spec.image_reference)
    assert argv[init_index + 1] == A.SUPPORTED_INIT_IMAGE_REFERENCE
    assert init_index < workload_index < argv.index(spec.arguments[0], workload_index)


def test_create_reinspects_init_image_under_lease_and_rejects_rebind_before_begin() -> None:
    spec = _spec()
    authority = _authority([_result(b""), _json_result(_image_document(spec))])
    authority.images[spec.image_reference] = _admission(spec)
    provider = _provider(authority)
    changed = _init_image_document()
    changed[0]["variants"][0]["digest"] = "sha256:" + "8" * 64
    authority.init_image_response = _json_result(changed)
    with pytest.raises(A.AppleContainerMismatchError, match="local image digest"):
        provider.create(spec)
    assert authority.begin_calls == []
    assert not any(call[0][0] == "create" for call in authority.calls)
    init_calls = [call for call in authority.calls
                  if call[0] == ("image", "inspect", spec.init_image_reference)]
    assert len(init_calls) == 2
    assert init_calls[-1][4] == len(spec.mounts)


@pytest.mark.parametrize("changes", [
    {"init_image_verified": False},
    {"init_image_reference": "ghcr.io/apple/containerization/vminit:0.42.0"},
    {"init_image_index_digest": "sha256:" + "9" * 64},
    {"init_image_manifest_digest": "sha256:" + "8" * 64},
])
def test_create_requires_native_execution_bound_init_image_evidence(
    changes: dict[str, object],
) -> None:
    spec = _spec()
    authority = _authority([
        _result(b""), _json_result(_image_document(spec)),
        Outcome(_result((spec.name + "\n").encode()), **changes),
    ])
    authority.images[spec.image_reference] = _admission(spec)
    with pytest.raises(A.AppleContainerAmbiguousError, match="ambiguous"):
        _provider(authority).create(spec)
    assert authority.records[spec.name].state is A.MutationState.PENDING


def test_oversized_create_argv_is_rejected_before_pending_journal() -> None:
    spec = replace(_spec(), arguments=tuple("x" * 1000 for _ in range(128)))
    authority = _authority([_result(b""), _json_result(_image_document(spec))])
    authority.images[spec.image_reference] = _admission(spec)
    with pytest.raises(A.AppleContainerConfigurationError, match="argument roster"):
        _provider(authority).create(spec)
    assert authority.begin_calls == []
    assert spec.name not in authority.records
    assert not any(call[0][0] == "create" for call in authority.calls)


@pytest.mark.parametrize("boundary", ["invoke", "identity", "inspect", "terminal"])
def test_failpoints_after_pending_remain_ambiguous_and_cleanup(boundary: str) -> None:
    spec = _spec()
    authority = _authority()
    authority.images[spec.image_reference] = _admission(spec)
    authority.responses.extend([_result(b""), _json_result(_image_document(spec))])
    if boundary == "invoke":
        authority.responses.append(OSError("/private/secret token=hunter2"))
    elif boundary == "identity":
        authority.responses.append(_result(b"unexpected\n"))
    else:
        authority.responses.extend([
            _result((spec.name + "\n").encode()),
            _result(b"not-json") if boundary == "inspect" else
            (lambda _a: _json_result(_inspect_document(
                spec, authority.records[spec.name], state="stopped"))),
        ])
        authority.fail_complete = boundary == "terminal"
    with pytest.raises(A.AppleContainerAmbiguousError) as caught:
        _provider(authority).create(spec)
    assert "hunter2" not in str(caught.value) and "/private" not in str(caught.value)
    assert authority.records[spec.name].state == A.MutationState.PENDING
    assert authority.mount_close_count == authority.mount_open_count


def test_journal_pending_must_be_durable_before_mutation() -> None:
    spec = _spec()
    authority = _authority([_result(b""), _json_result(_image_document(spec))])
    authority.images[spec.image_reference] = _admission(spec)
    authority.lose_begin = True
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        _provider(authority).create(spec)
    assert not any(call[0][0] == "create" for call in authority.calls)


@pytest.mark.parametrize("fail", ["raise", "lose"])
def test_journal_begin_failpoints_never_reach_mutating_cli(fail: str) -> None:
    spec = _spec()
    authority = _authority([_result(b""), _json_result(_image_document(spec))])
    authority.images[spec.image_reference] = _admission(spec)
    authority.fail_begin = fail == "raise"
    authority.lose_begin = fail == "lose"
    with pytest.raises(A.AppleContainerUnavailableError):
        _provider(authority).create(spec)
    assert not any(call[0][0] == "create" for call in authority.calls)


@pytest.mark.parametrize("fail", ["load", "save-raise", "save-lose"])
def test_image_admission_failpoints_never_create_durable_authority(fail: str) -> None:
    spec = _spec()
    responses: list[object] = [OSError("/secret/archive")] if fail == "load" else [
        _result(b"loaded\n"), _json_result(_image_document(spec))
    ]
    authority = _authority(responses)
    authority.fail_image_save = fail == "save-raise"
    authority.lose_image_save = fail == "save-lose"
    with pytest.raises(A.AppleContainerProviderError):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")
    if fail == "load":
        assert authority.images[spec.image_reference].state == A.ImageAdmissionState.PENDING
    else:
        assert spec.image_reference not in authority.images
    assert authority.mount_close_count == authority.mount_open_count


@pytest.mark.parametrize("operation,before_state", [
    ("start", "stopped"), ("stop", "running"), ("kill", "running"),
    ("delete", "stopped"),
])
def test_each_lifecycle_mutation_failpoint_is_restart_ambiguous(
    operation: str, before_state: str
) -> None:
    spec = _spec()
    authority = _authority()
    terminal = _seed(authority, spec, before_state)
    authority.responses.extend([
        _result((spec.name + "\n").encode()),
        _json_result(_inspect_document(spec, terminal, state=before_state)),
        OSError("/secret/native-runner"),
    ])
    provider = _provider(authority)
    method = getattr(provider, operation)
    with pytest.raises(A.AppleContainerAmbiguousError):
        method(spec, spec.name)
    assert authority.records[spec.name].state == A.MutationState.PENDING
    authority.responses.extend([
        _version_response(), _status_response(),
        _result((spec.name + "\n").encode()),
    ])
    if operation != "delete":
        authority.responses.append(_json_result(_inspect_document(
            spec, authority.records[spec.name], state=before_state
        )))
    receipt = _provider(authority).recover(spec)
    assert receipt.reason_code == "PRIOR_MUTATION_AMBIGUOUS"
    assert authority.mount_close_count == authority.mount_open_count


def test_stop_delete_and_recovery_pass_fresh_revalidated_mount_leases() -> None:
    spec = _spec()
    authority = _authority()
    terminal = _seed(authority, spec, "running")

    def doc(state: str) -> Callable[[tuple[str, ...]], A.RunnerResult]:
        return lambda _a: _json_result(_inspect_document(
            spec, authority.records[spec.name], state=state))

    authority.responses.extend([
        _result((spec.name + "\n").encode()), _json_result(_inspect_document(spec, terminal, state="running")),
        _result((spec.name + "\n").encode()), doc("stopped"),
        _result((spec.name + "\n").encode()), doc("stopped"),
        _result((spec.name + "\n").encode()), _result(b""),
    ])
    provider = _provider(authority)
    assert provider.stop(spec, spec.name).observed_state == "stopped"
    assert provider.delete(spec, spec.name).observed_state == "absent"
    lifecycle = [call for call in authority.calls if call[0][0] in {"list", "inspect", "stop", "delete"}]
    assert lifecycle and all(call[4] == len(spec.mounts) for call in lifecycle)
    assert authority.mount_revalidate_count >= authority.mount_open_count
    assert authority.mount_close_count == authority.mount_open_count


def test_unknown_container_status_or_configuration_fields_fail_closed() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "running")
    document = _inspect_document(spec, record, state="running")
    status = document[0]["status"]
    assert isinstance(status, dict)
    status["pid"] = 1
    authority.responses.extend([_result((spec.name + "\n").encode()), _json_result(document)])
    with pytest.raises(A.AppleContainerProtocolError, match="schema"):
        _provider(authority).recover(spec)


def test_swift_omitted_nil_container_fields_match_explicit_nulls() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "running")
    document = _inspect_document(spec, record, state="running")
    configuration = document[0]["configuration"]
    assert isinstance(configuration, dict)
    for key in ("dns", "shmSize", "stopSignal", "maskedPaths", "readonlyPaths"):
        configuration.pop(key)
    resources = configuration["resources"]
    assert isinstance(resources, dict)
    resources.pop("storage")
    terminal = replace(
        record,
        postcondition_sha256=hashlib.sha256(json.dumps(
            configuration, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
    )
    authority.records[spec.name] = terminal
    authority.responses.extend([
        _result((spec.name + "\n").encode()), _json_result(document),
    ])
    assert _provider(authority).recover(spec).decision == A.RecoveryDecision.RUNNING_MATCH


def test_swift_optional_started_date_is_known_and_typed() -> None:
    spec = _spec()
    for value, accepted in (("2026-09-08T00:00:00Z", True), (17, False)):
        authority = _authority()
        record = _seed(authority, spec, "running")
        document = _inspect_document(spec, record, state="running")
        document[0]["status"]["startedDate"] = value
        authority.responses.extend([
            _result((spec.name + "\n").encode()), _json_result(document),
        ])
        if accepted:
            assert _provider(authority).recover(spec).decision == A.RecoveryDecision.RUNNING_MATCH
        else:
            with pytest.raises(A.AppleContainerProtocolError, match="started date"):
                _provider(authority).recover(spec)


def test_repr_receipts_and_errors_are_redacted() -> None:
    spec = _spec()
    rendered = repr(spec)
    assert "/private/plamen" not in rendered
    assert spec.image_reference not in rendered
    assert "/usr/bin/python3" not in rendered
    authority = FakeAuthority([OSError("/private/passwords TOKEN=hunter2")])
    with pytest.raises(A.AppleContainerUnavailableError) as caught:
        _provider(authority, preflight=False).preflight()
    assert "/private" not in str(caught.value) and "hunter2" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_module_has_no_raw_subprocess_native_or_network_implementation() -> None:
    source = Path(A.__file__).read_text(encoding="utf-8")
    assert "ctypes" not in source
    assert "subprocess" not in source
    assert "urllib" not in source
    assert "requests" not in source
    assert "Popen" not in source


def test_full_release_revisions_and_binary_identities_are_mandatory() -> None:
    for changes in (
        {"cli_commit": "a" * 39},
        {"server_commit": "d" * 39, "server_banner_commit": "d" * 39},
        {"cli_commit": "a" * 40},
        {"cli_executable_sha256": "a" * 63},
        {"server_executable_sha256": "e" * 63},
        {"containerization_binary_sha256": "f" * 63},
        {"server_executable_path": "/tmp/container-apiserver"},
        {"plugin_root": "/tmp/plugins"},
        {"plugin_closure_sha256": "7" * 63},
        {"package_receipt_sha256": "8" * 63},
        {"package_identifier": "com.example.container"},
        {"package_version": "1.3.0"},
        {"package_install_location": "/opt/local"},
        {"package_authorization": "none"},
        {"package_signing_team_id": "OTHERTEAM"},
        {"package_installer_leaf_sha256": "9" * 64},
        {"package_signed": False},
        {"package_notarized": False},
        {"package_timestamped": False},
        {"kernel_archive_url": "https://example.invalid/kernel.tar.zst"},
        {"kernel_archive_sha256": "a" * 64},
        {"kernel_archive_size": A.SUPPORTED_KERNEL_ARCHIVE_SIZE + 1},
        {"kernel_binary_member": "../../host"},
        {"kernel_binary_sha256": "a" * 63},
        {"kernel_binary_sha256": "9" * 64},
        {"implicit_kernel_install_disabled": False},
    ):
        with pytest.raises(A.AppleContainerConfigurationError):
            replace(_PIN, **changes)
    with pytest.raises(A.AppleContainerConfigurationError, match="authenticated observation"):
        A.TEST_ONLY_AppleContainerProvider(
            executable_sha256="9" * 64, version_pin=_PIN,
            authority=object(), host_probe=_host,
        )
    with pytest.raises(A.AppleContainerConfigurationError, match="package-installed"):
        A.TEST_ONLY_AppleContainerProvider(
            executable=Path("/tmp/container"),
            executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
            version_pin=_PIN, authority=object(), host_probe=_host,
        )


@pytest.mark.parametrize("uid,gid", [(0, 1000), (1000, 0), (0, 0)])
def test_guest_identity_must_be_nonroot(uid: int, gid: int) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="uid/gid"):
        replace(_spec(), uid=uid, gid=gid)


@pytest.mark.parametrize("uid,gid", [(True, 1000), (1000, True)])
def test_guest_identity_rejects_boolean_integer_aliases(uid: object, gid: object) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="integer"):
        replace(_spec(), uid=uid, gid=gid)  # type: ignore[arg-type]


def test_exactly_one_attempt_owned_internal_network_is_required() -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="exactly one"):
        replace(_spec(), networks=())
    with pytest.raises(A.AppleContainerConfigurationError, match="network authority"):
        replace(_spec().networks[0], internal=False)
    with pytest.raises(A.AppleContainerConfigurationError, match="labels"):
        replace(_spec().networks[0], run_identity="run-other")
    with pytest.raises(A.AppleContainerConfigurationError, match="exactly one"):
        replace(_spec(), run_identity="run-other")


def test_audit_attempt_and_provider_run_identities_are_distinct_and_exact() -> None:
    spec = _spec()
    assert spec.audit_attempt_id == "dodo-001"
    assert spec.run_identity == "run-dodo-001"
    assert spec.expected_labels(
        A.MutationRecord(
            "plamen.apple-container.mutation.v3", A.MutationState.PENDING,
            spec.name, spec.fingerprint, "1" * 64, "create", "stopped",
            "2" * 32, "3" * 32, "4" * 32, _PROVENANCE_DIGEST, None,
        )
    )["io.plamen.audit-attempt"] == spec.audit_attempt_id
    with pytest.raises(A.AppleContainerConfigurationError, match="audit attempt"):
        replace(spec, audit_attempt_id="other-001")
    with pytest.raises(A.AppleContainerMismatchError, match="launch request"):
        A._validate_launch_for_spec(
            spec, replace(_driver_request(spec), attempt_id=spec.run_identity)
        )

    network_labels = tuple(
        (key, "run-other-001" if key == "io.plamen.run" else value)
        for key, value in spec.networks[0].labels
    )
    topology = spec.networks[0].topology_document()
    topology.update(
        run_identity="run-other-001",
        labels=[list(item) for item in sorted(network_labels)],
    )
    changed_run = replace(
        spec, run_identity="run-other-001",
        networks=(replace(
            spec.networks[0], run_identity="run-other-001",
            labels=network_labels, topology_sha256=A._canonical_digest(topology),
        ),),
    )
    assert changed_run.audit_attempt_id == spec.audit_attempt_id
    assert changed_run.name == spec.name
    assert changed_run.fingerprint != spec.fingerprint


@pytest.mark.parametrize("changes", [
    {"ipv4_subnet": "192.168.250.1/28"},
    {"ipv4_subnet": "8.8.8.0/28", "ipv4_gateway": "8.8.8.1"},
    {"ipv4_gateway": "192.168.250.2"},
    {"ipv4_address": "192.168.250.1/28"},
    {"ipv4_address": "192.168.251.2/28"},
    {"ipv6_absent": False},
    {"mac_address": "03:42:ac:11:00:02"},
    {"attachment_variant": "allocation-only"},
    {"authority_nonce": "6" * 31},
    {"labels": (("io.plamen.provider", "apple-container-v3"),)},
    {"plugin": "untrusted-network-plugin"},
    {"name": "plamen-egress-"},
    {"topology_sha256": "9" * 64},
])
def test_network_subnet_labels_plugin_and_topology_are_exact(
    changes: dict[str, object]
) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="network|topology"):
        replace(_spec().networks[0], **changes)


@pytest.mark.parametrize("source", [
    "/tmp/plamen-a", "/var/plamen-a", "/etc/plamen-a",
    "/private/tmp/plamen-a", "/private/var/plamen-a", "/private/etc/plamen-a",
    "/System/Volumes/Data/Users/alice/project", "/Users/alice/.codex",
    "/Users/alice/Library/Keychains", "/private/tmp/ssh-agent.sock",
])
def test_macos_alias_and_sensitive_mount_sources_are_rejected(source: str) -> None:
    with pytest.raises(A.AppleContainerConfigurationError, match="alias|sensitive"):
        A.MountSpec(source, "/workspace", True)


@pytest.mark.parametrize("changes", [
    {"content_sha256": "bad"}, {"descriptor_nofollow": False},
    {"filesystem_alias_free": False}, {"recursive_metadata_complete": False},
    {"symlink_entries_absent": False}, {"special_entries_absent": False},
    {"hardlink_entries_absent": False},
    {"cross_filesystem_entries_absent": False},
    {"sensitive_entries_absent": False}, {"socket_entries_absent": False},
    {"compressed_entries_absent": False},
])
def test_descriptor_native_recursive_mount_proofs_are_required(
    changes: dict[str, object]
) -> None:
    authority = _authority([])
    authority.mount_changes.update(changes)
    with pytest.raises(A.AppleContainerUnavailableError, match="mount"):
        _provider(authority).recover(_spec())
    assert authority.mount_close_count >= 1


def test_mount_identity_is_held_from_journal_begin_through_mutation() -> None:
    class ChangeAfterJournal(FakeAuthority):
        def journal_begin(self, record: A.MutationRecord,
                          previous: A.MutationRecord | None) -> A.MutationRecord:
            written = super().journal_begin(record, previous)
            for facts in A._TEST_ONLY_MOUNT_REGISTRY.values():
                if facts.owner is self and not facts.closed:
                    facts.inode += 1
                    facts.content_sha256 = "9" * 64
            return written

    spec = _spec()
    authority = ChangeAfterJournal([
        _version_response(), _status_response(), _result(b""),
        _json_result(_image_document(spec)),
    ])
    authority.images[spec.image_reference] = _admission(spec)
    with pytest.raises(A.AppleContainerAmbiguousError, match="ambiguous"):
        _provider(authority).create(spec)
    assert authority.records[spec.name].state == A.MutationState.PENDING
    assert not any(call[0][0] == "create" for call in authority.calls)


def test_native_mounted_identity_must_equal_the_held_lease() -> None:
    authority = _authority([
        Outcome(_result(b""), mounted_identity_override="9" * 64),
    ])
    with pytest.raises(A.AppleContainerUnavailableError, match="evidence"):
        _provider(authority).recover(_spec())


def test_runtime_network_attachment_must_equal_the_governed_topology() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "running")
    document = _inspect_document(spec, record, state="running")
    document[0]["status"]["networks"].append({
        "network": "external", "hostname": spec.name,
        "ipv4Address": "192.168.251.2/28", "ipv4Gateway": "192.168.251.1",
        "macAddress": "02:42:ac:11:00:03", "mtu": 1500,
        "variant": A.SUPPORTED_NETWORK_ATTACHMENT_VARIANT,
    })
    authority.responses.extend([
        _result((spec.name + "\n").encode()), _json_result(document),
    ])
    receipt = _provider(authority).recover(spec)
    assert receipt.decision == A.RecoveryDecision.MISMATCH
    assert receipt.reason_code == "RUNTIME_NETWORK_MISMATCH"


@pytest.mark.parametrize("changes", [
    {"guest_network_policy_enforced": False},
    {"guest_network_internal": False},
    {"guest_network_attempt_owned": False},
    {"guest_network_no_dns": False},
    {"guest_network_ipv6_absent": False},
    {"guest_network_object_verified": False},
    {"guest_network_attachment_verified": False},
    {"guest_network_policy_sha256": "9" * 64},
    {"guest_network_topology_sha256": "9" * 64},
    {"guest_network_name": "default"},
    {"guest_network_ipv4_subnet": "192.168.251.0/28"},
    {"guest_network_ipv4_gateway": "192.168.250.2"},
    {"guest_network_ipv4_address": "192.168.250.3/28"},
    {"guest_network_mac_address": "02:42:ac:11:00:03"},
    {"guest_network_attachment_variant": "other"},
    {"guest_network_labels": ()},
    {"guest_network_plugin": "other"},
])
def test_native_guest_network_authority_is_exact(changes: dict[str, object]) -> None:
    outcome = replace(Outcome(_result(b"")), **changes)
    with pytest.raises(A.AppleContainerUnavailableError, match="evidence"):
        _provider(_authority([outcome])).recover(_spec())


def test_create_uses_only_the_documented_internal_network_form() -> None:
    spec = _spec()
    pending = A.MutationRecord(
        "plamen.apple-container.mutation.v3", A.MutationState.PENDING, spec.name,
        spec.fingerprint, "4" * 64, "create", "stopped",
        "1" * 32, "2" * 32, "3" * 32, _PROVENANCE_DIGEST, None,
    )
    arguments = A.TEST_ONLY_AppleContainerProvider._create_arguments(spec, pending)
    assert "none" not in arguments
    positions = [index for index, value in enumerate(arguments) if value == "--network"]
    assert len(positions) == 1
    assert arguments[positions[0] + 1].startswith(spec.networks[0].name + ",")


def test_archive_identity_change_during_load_is_ambiguous_and_not_admitted() -> None:
    spec = _spec()
    authority = _authority()

    def mutate_archive(_arguments: tuple[str, ...]) -> A.RunnerResult:
        for facts in A._TEST_ONLY_MOUNT_REGISTRY.values():
            if facts.owner is authority and facts.target == "/.plamen/image-archive":
                facts.inode += 1
                facts.content_sha256 = "9" * 64
        return _result(b"loaded\n")

    authority.responses.extend([mutate_archive])
    with pytest.raises(A.AppleContainerAmbiguousError, match="image load"):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")
    assert authority.images[spec.image_reference].state == A.ImageAdmissionState.PENDING


@pytest.mark.parametrize("changes", [
    {"archive_members_validated": False},
    {"oci_layout_sha256": None},
    {"oci_layout_sha256": "bad"},
    {"oci_index_digest": "bad"},
    {"oci_index_media_type": "application/x-evil"},
    {"oci_manifest_digest": "bad"},
    {"oci_manifest_media_type": "application/x-evil"},
    {"oci_configuration_sha256": "bad"},
    {"symlink_entries_absent": False},
    {"hardlink_entries_absent": False},
])
def test_archive_member_and_oci_layout_proof_precedes_image_load(
    changes: dict[str, object]
) -> None:
    spec = _spec()
    authority = _authority([])
    authority.mount_changes.update(changes)
    with pytest.raises(A.AppleContainerUnavailableError, match="mount"):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")
    assert not any(call[0][:2] == ("image", "load") for call in authority.calls)


@pytest.mark.parametrize("changes", [
    {"oci_index_digest": "sha256:" + "9" * 64},
    {"oci_manifest_digest": "sha256:" + "9" * 64},
    {"oci_configuration_sha256": "9" * 64},
])
def test_archive_exact_descriptor_pins_precede_image_load(
    changes: dict[str, object],
) -> None:
    authority = _authority([])
    authority.mount_changes.update(changes)
    with pytest.raises(A.AppleContainerMismatchError, match="archive descriptors"):
        _provider(authority).admit_local_image(
            _spec(), "/private/plamen/runtime.tar"
        )
    assert not any(call[0][:2] == ("image", "load") for call in authority.calls)


def test_provider_archive_target_is_reserved_from_container_mounts() -> None:
    spec = _spec()
    with pytest.raises(A.AppleContainerConfigurationError, match="reserved"):
        replace(spec, mounts=spec.mounts + (
            A.MountSpec("/private/plamen/runtime.tar", "/.plamen/image-archive", True),
        ))


def test_pending_image_load_is_never_adopted_after_restart() -> None:
    spec = _spec()
    authority = _authority()
    authority.images[spec.image_reference] = replace(
        _admission(spec), state=A.ImageAdmissionState.PENDING,
        postcondition_sha256=None,
    )
    with pytest.raises(A.AppleContainerAmbiguousError, match="prior image load"):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")


def test_local_image_media_type_is_exact() -> None:
    spec = _spec()
    document = _image_document(spec)
    document[0]["configuration"]["descriptor"]["mediaType"] = "application/x-evil"
    authority = _authority([_result(b"loaded\n"), _json_result(document)])
    with pytest.raises(A.AppleContainerAmbiguousError, match="image load"):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")
    assert authority.images[spec.image_reference].state == A.ImageAdmissionState.PENDING


def test_huge_integer_output_fails_with_typed_sanitized_error() -> None:
    authority = FakeAuthority([_result(b"[" + b"9" * 5000 + b"]")])
    with pytest.raises(A.AppleContainerProtocolError, match="oversized integer") as caught:
        _provider(authority, preflight=False).preflight()
    assert caught.value.__cause__ is None


def test_host_probe_and_hostile_typed_fields_fail_sanitized() -> None:
    authority = FakeAuthority([])

    def broken_host() -> A.HostPlatform:
        raise OSError("/private/passwords TOKEN=hunter2")

    provider = A.TEST_ONLY_AppleContainerProvider(
        executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
        version_pin=_PIN, authority=authority,
        host_probe=broken_host,
    )
    with pytest.raises(A.AppleContainerUnavailableError, match="platform") as caught:
        provider.preflight()
    assert caught.value.__cause__ is None and "hunter2" not in str(caught.value)
    with pytest.raises(A.AppleContainerConfigurationError):
        A.TEST_ONLY_AppleContainerProvider(
            executable=None,  # type: ignore[arg-type]
            executable_sha256=A.SUPPORTED_CLI_EXECUTABLE_SHA256,
            version_pin=_PIN, authority=authority, host_probe=_host,
        )
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_spec(), run_identity=1)  # type: ignore[arg-type]
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(_spec().networks[0], labels=(([], "x"),))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        A.RunnerResult(0, b"x", b"", 2, 0, 7, None)  # type: ignore[arg-type]


def test_mutation_journal_begin_is_compare_and_swap() -> None:
    class RacingJournal(FakeAuthority):
        def journal_begin(self, record: A.MutationRecord,
                          previous: A.MutationRecord | None) -> A.MutationRecord:
            self.records[record.identity] = replace(record, mutation_nonce="9" * 32)
            return super().journal_begin(record, previous)

    spec = _spec()
    authority = RacingJournal([
        _version_response(), _status_response(), _result(b""),
        _json_result(_image_document(spec)),
    ])
    authority.images[spec.image_reference] = _admission(spec)
    with pytest.raises(A.AppleContainerUnavailableError, match="durably recorded"):
        _provider(authority).create(spec)
    assert not any(call[0][0] == "create" for call in authority.calls)


def test_journals_are_bound_to_the_exact_provider_provenance() -> None:
    spec = _spec()
    authority = _authority()
    record = _seed(authority, spec, "stopped")
    authority.records[spec.name] = replace(
        record, provider_provenance_sha256="9" * 64,
    )
    with pytest.raises(A.AppleContainerProtocolError, match="journal"):
        _provider(authority).recover(spec)

    image_authority = _authority([_result(b"")])
    image_authority.images[spec.image_reference] = replace(
        _admission(spec), provider_provenance_sha256="9" * 64,
    )
    with pytest.raises(A.AppleContainerProtocolError, match="image admission"):
        _provider(image_authority).create(spec)
    assert not any(call[0][0] == "create" for call in image_authority.calls)


def test_primary_failure_never_suppresses_executable_cleanup_ambiguity() -> None:
    authority = FakeAuthority([OSError("/secret/token=hunter2")])
    authority.fail_exec_close = True
    with pytest.raises(A.AppleContainerAmbiguousError, match="cleanup") as caught:
        _provider(authority, preflight=False).preflight()
    assert "hunter2" not in str(caught.value) and "/secret" not in str(caught.value)


def test_descriptor_identity_alias_and_ancestor_overlap_are_rejected() -> None:
    authority = _authority([])
    identities, digest = _component_facts("/private/plamen/shared")
    authority.mount_changes.update(
        component_identities=identities, component_chain_sha256=digest,
    )
    with pytest.raises(A.AppleContainerUnavailableError, match="mount"):
        _provider(authority).recover(_spec())

    spec = _spec()
    with pytest.raises(A.AppleContainerConfigurationError, match="targets overlap"):
        replace(spec, mounts=spec.mounts + (
            A.MountSpec(
                "/private/plamen/third", "/workspace/project/nested", True,
            ),
        ))


def test_root_object_alias_and_truncated_component_chain_are_rejected() -> None:
    authority = _authority([])
    first_inode = int(hashlib.sha256(
        "/private/plamen/project".encode()
    ).hexdigest()[:8], 16)
    authority.mount_changes["inode"] = first_inode
    with pytest.raises(A.AppleContainerUnavailableError, match="mount"):
        _provider(authority).recover(_spec())

    truncated = _authority([])
    identities, _digest = _component_facts("/private/plamen/project")
    shortened = identities[:-1]
    truncated.mount_changes.update(
        component_identities=shortened,
        component_chain_sha256=hashlib.sha256(json.dumps(
            list(shortened), sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
    )
    with pytest.raises(A.AppleContainerUnavailableError, match="mount"):
        _provider(truncated).recover(_spec())


def test_one_mount_lease_spans_intent_mutation_and_postcondition() -> None:
    spec = _spec()
    authority = _authority()
    authority.images[spec.image_reference] = _admission(spec)
    authority.responses.extend([
        _result(b""), _json_result(_image_document(spec)),
        lambda _a: _result((spec.name + "\n").encode()),
        lambda _a: _json_result(_inspect_document(
            spec, authority.records[spec.name], state="stopped"
        )),
    ])
    _provider(authority).create(spec)
    relevant = [ids for arguments, ids in authority.mount_capability_runs
                if arguments[0] in {"list", "create", "inspect"} and ids]
    assert len(relevant) >= 3
    assert all(ids == relevant[0] for ids in relevant)
    assert authority.mount_open_count == authority.mount_close_count == len(spec.mounts)


def test_driver_start_is_exact_attached_nonblocking_and_wait_is_exit_authority() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)

    started = provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1
    assert A._driver_process_facts(started.process_capability).command == (
        "start", "--attach", spec.name,
    )
    assert started.receipt.launch_policy_sha256 == request.launch_policy_sha256
    assert started.receipt.cli_executable_sha256 == _PIN.cli_executable_sha256
    assert started.receipt.rosetta_required is False

    authority.driver_wait_outcomes.append(_result(b"stream-json\n", b"warning\n", returncode=7))
    waited = provider.wait_driver(spec, request, started)
    assert waited.receipt.exit_code == 7
    assert waited.stdout == b"stream-json\n"
    assert waited.stderr == b"warning\n"
    assert waited.receipt.descendants_extinct is True
    assert waited.receipt.backend_egress_revoked is True
    assert waited.receipt.start_receipt_sha256 == started.receipt.receipt_sha256
    assert authority.driver_wait_calls == authority.driver_revoke_calls == 1
    assert not any(call[0][0] == "logs" for call in authority.calls)

    with pytest.raises(A.AppleContainerUnavailableError, match="capability"):
        provider.wait_driver(spec, request, started)


def test_driver_start_duplicate_and_fake_capability_fail_closed() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)

    with pytest.raises(A.AppleContainerMismatchError, match="already delivered"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1

    forged = object.__new__(A.DriverStartResult)
    object.__setattr__(forged, "receipt", started.receipt)
    object.__setattr__(forged, "process_capability", object())
    with pytest.raises(A.AppleContainerUnavailableError, match="capability"):
        provider.wait_driver(spec, request, forged)


def test_two_thread_driver_wait_consumes_one_capability_once() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    barrier = threading.Barrier(3)
    outcomes: list[object] = []

    def waiter() -> None:
        barrier.wait()
        try:
            outcomes.append(provider.wait_driver(spec, request, started))
        except Exception as error:  # noqa: BLE001 - exact competing outcome is asserted
            outcomes.append(error)

    threads = [threading.Thread(target=waiter) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)
    assert sum(type(item) is A.DriverWaitResult for item in outcomes) == 1
    assert sum(type(item) is A.AppleContainerUnavailableError for item in outcomes) == 1
    assert authority.driver_wait_calls == 1


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX fork is required")
def test_driver_process_capability_is_invalidated_after_fork() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    callback_baseline = (
        authority.mount_open_count,
        authority.journal_load_count,
        authority.driver_journal_load_count,
        authority.driver_recover_process_calls,
        authority.driver_recover_wait_calls,
        authority.driver_wait_calls,
        authority.driver_revoke_calls,
    )
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no branch - child has its own process image
        os.close(read_fd)
        errors: list[str] = []
        try:
            provider.recover(spec)
            errors.append("UNEXPECTED_RECOVER_SUCCESS")
        except Exception as error:  # noqa: BLE001 - serialized child result
            errors.append(type(error).__name__)
        try:
            provider._open_mounts(spec.mounts)
            errors.append("UNEXPECTED_HELPER_SUCCESS")
        except Exception as error:  # noqa: BLE001 - serialized child result
            errors.append(type(error).__name__)
        class HostileStart:
            @property
            def process_capability(self) -> object:
                os.write(write_fd, b"PROPERTY_RAN|")
                return object()
        try:
            provider._burn_driver_process(HostileStart())  # type: ignore[arg-type]
            errors.append("UNEXPECTED_BURN_SUCCESS")
        except Exception as error:  # noqa: BLE001 - serialized child result
            errors.append(type(error).__name__)
        callback_after = (
            authority.mount_open_count,
            authority.journal_load_count,
            authority.driver_journal_load_count,
            authority.driver_recover_process_calls,
            authority.driver_recover_wait_calls,
            authority.driver_wait_calls,
            authority.driver_revoke_calls,
        )
        deltas = tuple(after - before for before, after in
                       zip(callback_baseline, callback_after))
        counts = (
            len(A._TEST_ONLY_AUTHORITY_REGISTRY), len(A._TEST_ONLY_EXECUTABLE_REGISTRY),
            len(A._TEST_ONLY_MOUNT_REGISTRY), len(A._TEST_ONLY_INVOCATION_REGISTRY),
            len(A._TEST_ONLY_DRIVER_PROCESS_REGISTRY), len(A._TEST_ONLY_DRIVER_WAIT_REGISTRY),
        )
        outcome = f"{','.join(errors)}:{deltas}:{counts}"
        os.write(write_fd, outcome.encode("ascii"))
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    outcome = os.read(read_fd, 1024).decode("ascii")
    os.close(read_fd)
    waited_pid, status = os.waitpid(pid, 0)
    assert waited_pid == pid and os.waitstatus_to_exitcode(status) == 0
    assert outcome == (
        "AppleContainerUnavailableError,AppleContainerUnavailableError,"
        "AppleContainerUnavailableError:"
        "(0, 0, 0, 0, 0, 0, 0):(0, 0, 0, 0, 0, 0)"
    )

    # The child invalidation cannot consume or revoke the issuer's capability.
    waited = provider.wait_driver(spec, request, started)
    assert waited.receipt.exit_code == 0
    assert authority.driver_wait_calls == authority.driver_revoke_calls == 1


def test_driver_start_crash_after_arm_recovers_without_duplicate_effect() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    record = _seed(authority, spec, "stopped")
    authority.raise_after_driver_cas_state_once = A.DriverLifecycleState.START_ARMED
    authority.responses.extend([
        _result((spec.name + "\n").encode()),
        _json_result(_inspect_document(spec, record, state="stopped")),
    ])
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 0

    authority.responses.extend([
        _json_result(_inspect_document(spec, record, state="running")),
    ])
    provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1


def test_driver_start_claim_crash_hard_stops_without_duplicate_effect() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    record = _seed(authority, spec, "stopped")
    authority.raise_after_driver_cas_state_once = A.DriverLifecycleState.START_CLAIMED
    authority.responses.extend([
        _result((spec.name + "\n").encode()),
        _json_result(_inspect_document(spec, record, state="stopped")),
    ])
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 0
    assert authority.driver_records[(spec.name, spec.audit_attempt_id)].state is (
        A.DriverLifecycleState.START_CLAIMED
    )

    # A fresh provider cannot know whether the claimant died just before or
    # just after the native effect.  It may recover the exact nonce, but must
    # never originate another attached start.
    with pytest.raises(A.AppleContainerAmbiguousError, match="cannot be recovered"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 0


def test_driver_start_claim_is_atomic_across_provider_instances() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    first = _provider(authority)
    authority.responses.extend([_version_response(), _status_response()])
    second = _provider(authority)
    record = _seed(authority, spec, "stopped")
    armed = first._arm_driver_start(request)
    authority.driver_records[(spec.name, spec.audit_attempt_id)] = armed
    authority.driver_start_entered = threading.Event()
    authority.driver_start_release = threading.Event()
    authority.responses.append(
        _json_result(_inspect_document(spec, record, state="running"))
    )
    outcomes: list[object] = []

    def launch(provider: A.TEST_ONLY_AppleContainerProvider) -> None:
        try:
            outcomes.append(provider.start_driver(spec, request))
        except Exception as error:  # noqa: BLE001 - exact competing outcome asserted
            outcomes.append(error)

    winner = threading.Thread(target=launch, args=(first,))
    winner.start()
    assert authority.driver_start_entered.wait(timeout=2)
    loser = threading.Thread(target=launch, args=(second,))
    loser.start()
    loser.join(timeout=2)
    authority.driver_start_release.set()
    winner.join(timeout=2)

    assert not winner.is_alive() and not loser.is_alive()
    assert authority.driver_start_calls == 1
    assert sum(type(item) is A.DriverStartResult for item in outcomes) == 1
    assert sum(type(item) is A.AppleContainerAmbiguousError for item in outcomes) == 1


@pytest.mark.parametrize(
    "state",
    [A.DriverLifecycleState.START_EFFECT, A.DriverLifecycleState.START_COMMITTED],
)
def test_driver_start_post_effect_checkpoint_failure_is_extinguished_and_terminal(
    state: A.DriverLifecycleState,
) -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    authority.fail_driver_cas_state_once = state
    _queue_driver_start(authority, spec)
    with pytest.raises(A.AppleContainerAmbiguousError, match="durability"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1


def test_driver_start_post_effect_inspect_failure_is_extinguished_and_journalled() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    record = _seed(authority, spec, "stopped")
    authority.responses.extend([
        _result((spec.name + "\n").encode()),
        _json_result(_inspect_document(spec, record, state="stopped")),
        _json_result(_inspect_document(spec, record, state="stopped")),
    ])
    with pytest.raises(A.AppleContainerMismatchError, match="running container"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1


def test_driver_start_post_effect_executable_cleanup_failure_still_extinguishes() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    authority.fail_exec_post_at = authority.exec_post_count + 3
    _queue_driver_start(authority, spec)
    with pytest.raises(A.AppleContainerAmbiguousError, match="cleanup"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1
    assert authority.driver_revoke_calls == 1
    journal = authority.driver_records[(spec.name, spec.audit_attempt_id)]
    assert journal.state is A.DriverLifecycleState.START_ABORTED
    assert journal.start_abort_egress_revoked is True
    assert not any(
        facts.owner is authority
        for facts in A._TEST_ONLY_DRIVER_PROCESS_REGISTRY.values()
    )
    assert authority.driver_revoke_calls == 1
    journal = authority.driver_records[(spec.name, spec.audit_attempt_id)]
    assert journal.state is A.DriverLifecycleState.START_ABORTED
    assert journal.start_abort_extinction_sha256 == "5" * 64
    assert journal.start_abort_cleanup_sha256 == "6" * 64
    assert journal.start_abort_egress_revoked is True
    assert not any(
        facts.owner is authority
        for facts in A._TEST_ONLY_DRIVER_PROCESS_REGISTRY.values()
    )
    with pytest.raises(A.AppleContainerMismatchError, match="lifecycle"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1
    assert authority.driver_revoke_calls == 1
    journal = authority.driver_records[(spec.name, spec.audit_attempt_id)]
    assert journal.state is A.DriverLifecycleState.START_ABORTED
    assert journal.start_abort_extinction_sha256 == "5" * 64
    assert journal.start_abort_cleanup_sha256 == "6" * 64
    assert journal.start_abort_egress_revoked is True

    with pytest.raises(A.AppleContainerMismatchError, match="lifecycle"):
        provider.start_driver(spec, request)
    assert authority.driver_start_calls == 1


@pytest.mark.parametrize(
    "state",
    [A.DriverLifecycleState.WAIT_EFFECT, A.DriverLifecycleState.WAIT_COMMITTED],
)
def test_driver_wait_crash_recovery_never_duplicates_native_wait(
    state: A.DriverLifecycleState,
) -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.fail_driver_cas_state_once = state

    with pytest.raises(A.AppleContainerAmbiguousError, match="durability"):
        provider.wait_driver(spec, request, started)
    assert authority.driver_wait_calls == 1
    waited = provider.recover_driver_wait(spec, request)
    assert waited.receipt.exit_code == 0
    assert authority.driver_wait_calls == 1
    assert authority.driver_recover_wait_calls >= 2


def test_driver_wait_crash_after_arm_starts_only_one_native_wait() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.raise_after_driver_cas_state_once = A.DriverLifecycleState.WAIT_ARMED
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        provider.wait_driver(spec, request, started)
    assert authority.driver_wait_calls == 0
    waited = provider.recover_driver_wait(spec, request)
    assert waited.receipt.exit_code == 0
    assert authority.driver_wait_calls == 1


def test_driver_wait_claim_ack_loss_hard_stops_without_duplicate_wait() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.raise_after_driver_cas_state_once = A.DriverLifecycleState.WAIT_CLAIMED
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        provider.wait_driver(spec, request, started)
    assert authority.driver_wait_calls == 0
    assert authority.driver_records[(spec.name, spec.audit_attempt_id)].state is (
        A.DriverLifecycleState.WAIT_CLAIMED
    )
    prior_revokes = authority.driver_revoke_calls
    with pytest.raises(A.AppleContainerAmbiguousError, match="cannot be recovered"):
        provider.recover_driver_wait(spec, request)
    assert authority.driver_wait_calls == 0
    # The recovery loser must not terminate a process which may still belong
    # to the unacknowledged claim owner.
    assert authority.driver_revoke_calls == prior_revokes


def test_wait_claim_loser_executable_cleanup_failure_never_revokes_process() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.raise_after_driver_cas_state_once = A.DriverLifecycleState.WAIT_CLAIMED
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        provider.wait_driver(spec, request, started)
    assert authority.driver_records[(spec.name, spec.audit_attempt_id)].state is (
        A.DriverLifecycleState.WAIT_CLAIMED
    )

    prior_revokes = authority.driver_revoke_calls
    authority.fail_exec_post_at = authority.exec_post_count + 1
    with pytest.raises(A.AppleContainerAmbiguousError, match="cleanup journal"):
        provider.recover_driver_wait(spec, request)
    assert authority.driver_recover_process_calls >= 1
    assert authority.driver_wait_calls == 0
    assert authority.driver_revoke_calls == prior_revokes
    assert authority.driver_records[(spec.name, spec.audit_attempt_id)].state is (
        A.DriverLifecycleState.WAIT_CLAIMED
    )


def test_start_claim_loser_abort_check_precedes_native_revoke() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    facts = A._driver_process_facts(started.process_capability)
    assert facts is not None
    key = (spec.name, spec.audit_attempt_id)
    committed = authority.driver_records[key]
    claimed = A._transition_driver_record(
        committed, A.DriverLifecycleState.START_CLAIMED,
        native_process_id=None, native_process_handle_sha256=None,
        start_timestamp=None, start_effect_sha256=None,
    )
    authority.driver_records[key] = claimed
    prior_revokes = authority.driver_revoke_calls
    with pytest.raises(A.AppleContainerAmbiguousError, match="claim"):
        provider._abort_started_driver(
            request, started.process_capability, facts,
            owns_start_claim=False,
        )
    assert authority.driver_revoke_calls == prior_revokes
    assert authority.driver_records[key] is claimed

    # Restore the exact durable commitment so the legitimate issuer can reap.
    authority.driver_records[key] = committed
    assert provider.wait_driver(spec, request, started).receipt.exit_code == 0


def test_driver_wait_claim_is_atomic_across_provider_instances() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    first = _provider(authority)
    authority.responses.extend([_version_response(), _status_response()])
    second = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = first.start_driver(spec, request)
    authority.raise_after_driver_cas_state_once = A.DriverLifecycleState.WAIT_ARMED
    with pytest.raises(A.AppleContainerUnavailableError, match="durability"):
        first.wait_driver(spec, request, started)
    authority.driver_revoke_calls = 0
    authority.driver_wait_entered = threading.Event()
    authority.driver_wait_release = threading.Event()
    outcomes: list[object] = []

    def recover(provider: A.TEST_ONLY_AppleContainerProvider) -> None:
        try:
            outcomes.append(provider.recover_driver_wait(spec, request))
        except Exception as error:  # noqa: BLE001 - exact competing outcome asserted
            outcomes.append(error)

    winner = threading.Thread(target=recover, args=(first,))
    winner.start()
    assert authority.driver_wait_entered.wait(timeout=2)
    loser = threading.Thread(target=recover, args=(second,))
    loser.start()
    loser.join(timeout=2)
    authority.driver_wait_release.set()
    winner.join(timeout=2)

    assert not winner.is_alive() and not loser.is_alive()
    assert authority.driver_wait_calls == 1
    assert authority.driver_revoke_calls == 1
    assert sum(type(item) is A.DriverWaitResult for item in outcomes) == 1
    assert sum(type(item) is A.AppleContainerAmbiguousError for item in outcomes) == 1


def test_driver_wait_rejects_exit_substitution_and_output_overflow_then_revokes() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.driver_wait_changes["native_process_handle_sha256"] = "7" * 64
    with pytest.raises(A.AppleContainerProtocolError, match="wait evidence"):
        provider.wait_driver(spec, request, started)
    assert authority.driver_revoke_calls == 1

    second_authority = _authority()
    second_provider = _provider(second_authority)
    _seed(second_authority, spec, "stopped")
    _queue_driver_start(second_authority, spec)
    second = second_provider.start_driver(spec, request)
    second_authority.driver_wait_outcomes.append(
        _result(b"x" * (A.DRIVER_MAX_OUTPUT_BYTES + 1))
    )
    with pytest.raises(A.AppleContainerProtocolError, match="wait evidence"):
        second_provider.wait_driver(spec, request, second)
    assert second_authority.driver_revoke_calls == 1


@pytest.mark.parametrize("field,value", [
    ("stop_argv_sha256", None),
    ("stop_stdout_sha256", None),
    ("stop_stderr_sha256", None),
    ("stopped_observation_sha256", None),
    ("guest_population_extinction_sha256", None),
    ("stop_control_process_reaped", False),
    ("stop_control_process_group_extinct", False),
    ("guest_population_zero", False),
    ("container_vm_stopped", False),
])
def test_driver_wait_requires_explicit_stop_and_vm_extinction_evidence(
    field: str, value: object,
) -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.driver_wait_changes[field] = value
    with pytest.raises(A.AppleContainerProtocolError, match="wait evidence"):
        provider.wait_driver(spec, request, started)
    assert authority.driver_revoke_calls == 1


def test_driver_wait_recovery_rejects_durable_exit_substitution() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.fail_driver_cas_state_once = A.DriverLifecycleState.WAIT_COMMITTED
    with pytest.raises(A.AppleContainerAmbiguousError, match="durability"):
        provider.wait_driver(spec, request, started)
    key = (spec.name, spec.audit_attempt_id)
    effect = authority.driver_records[key]
    assert effect.state is A.DriverLifecycleState.WAIT_EFFECT
    authority.driver_records[key] = A._transition_driver_record(
        effect, A.DriverLifecycleState.WAIT_EFFECT, exit_code=17,
    )
    with pytest.raises(A.AppleContainerMismatchError, match="exit differs"):
        provider.recover_driver_wait(spec, request)
    assert authority.driver_wait_calls == 1


def test_truncated_driver_output_binds_exact_retained_prefix() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    authority.driver_wait_outcomes.append(
        _result(b"prefix", stdout_observed=10, stdout_digest="8" * 64)
    )
    waited = provider.wait_driver(spec, request, started)
    assert waited.receipt.stdout_truncated is True
    assert waited.receipt.stdout_sha256 == "8" * 64
    assert waited.receipt.stdout_retained_sha256 == hashlib.sha256(b"prefix").hexdigest()
    with pytest.raises(A.AppleContainerProtocolError, match="digest differs"):
        replace(waited, stdout=b"forged")


def test_driver_wait_timeout_forces_process_guest_and_egress_extinction() -> None:
    spec = _spec()
    request = _driver_request(spec)
    authority = _authority()
    provider = _provider(authority)
    _seed(authority, spec, "stopped")
    _queue_driver_start(authority, spec)
    started = provider.start_driver(spec, request)
    capability = started.process_capability
    authority.driver_wait_outcomes.append(TimeoutError("/secret/backend-token"))
    with pytest.raises(A.AppleContainerAmbiguousError, match="journalled") as caught:
        provider.wait_driver(spec, request, started)
    assert "secret" not in str(caught.value)
    facts = A._driver_process_facts(capability)
    assert facts is None or (
        facts.native_process_extinct
        and facts.guest_process_extinct
        and facts.backend_egress_revoked
    )
    assert authority.driver_revoke_calls == 1


def test_rosetta_is_request_bound_dodo_only_and_exact_create_flag() -> None:
    spec = _spec(rosetta_required=True)
    request = _driver_request(spec)
    assert request.rosetta_required is True
    authority = _authority()
    provider = _provider(authority)
    record = _seed(authority, spec, "absent")
    authority.images[spec.image_reference] = _admission(spec)
    authority.responses.extend([
        _result(b""), _json_result(_image_document(spec)),
        lambda _a: _result((spec.name + "\n").encode()),
        lambda _a: _json_result(_inspect_document(
            spec, authority.records[spec.name], state="stopped"
        )),
    ])
    provider.create(spec)
    record = authority.records[spec.name]
    create = next(call[0] for call in authority.calls if call[0][0] == "create")
    assert create.count("--rosetta") == 1

    without = replace(request, rosetta_required=False)
    with pytest.raises(A.AppleContainerMismatchError, match="launch request"):
        provider.start_driver(spec, without)
    plain = _spec()
    injected = replace(_driver_request(plain), rosetta_required=True)
    with pytest.raises(A.AppleContainerMismatchError, match="launch request"):
        A._validate_launch_for_spec(plain, injected)
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(
            spec, name="plamen-other-001",
            networks=(replace(spec.networks[0], hostname="plamen-other-001"),),
        )
    with pytest.raises(A.AppleContainerConfigurationError):
        replace(
            spec, run_identity="run-other-001",
            networks=(replace(spec.networks[0], run_identity="run-other-001"),),
        )

    rosetta_mismatch = _inspect_document(spec, record, state="stopped")
    rosetta_mismatch[0]["configuration"]["rosetta"] = False  # type: ignore[index]
    mismatch_authority = _authority([
        _result((spec.name + "\n").encode()),
        _json_result(rosetta_mismatch),
    ])
    mismatch_authority.records[spec.name] = record
    recovered = _provider(mismatch_authority).recover(spec)
    assert recovered.decision is A.RecoveryDecision.MISMATCH
    assert recovered.reason_code == "SECURITY_CONFIGURATION_MISMATCH"

    pending_plain = replace(
        _seed(mismatch_authority, plain, "stopped"),
        state=A.MutationState.PENDING, postcondition_sha256=None,
    )
    plain_argv = list(A.TEST_ONLY_AppleContainerProvider._create_arguments(plain, pending_plain))
    plain_argv.insert(plain_argv.index("--network"), "--rosetta")
    with pytest.raises(A.AppleContainerConfigurationError, match="ordering differ"):
        A._validate_argv(
            tuple(plain_argv), "create", create_spec=plain,
            create_record=pending_plain,
        )
    pending_rosetta = replace(
        record, state=A.MutationState.PENDING, postcondition_sha256=None,
    )
    omitted = tuple(
        item for item in A.TEST_ONLY_AppleContainerProvider._create_arguments(spec, pending_rosetta)
        if item != "--rosetta"
    )
    with pytest.raises(A.AppleContainerConfigurationError, match="ordering differ"):
        A._validate_argv(
            omitted, "create", create_spec=spec, create_record=pending_rosetta,
        )


def test_image_terminal_record_is_compare_and_swap_or_remains_pending() -> None:
    class FailTerminalImageCAS(FakeAuthority):
        def image_save(self, record: A.ImageAdmissionRecord,
                       previous: A.ImageAdmissionRecord | None) -> A.ImageAdmissionRecord:
            if record.state == A.ImageAdmissionState.TERMINAL:
                raise OSError("terminal image CAS lost")
            return super().image_save(record, previous)

    spec = _spec()
    authority = FailTerminalImageCAS([
        _version_response(), _status_response(), _result(b"loaded\n"),
        _json_result(_image_document(spec)),
    ])
    with pytest.raises(A.AppleContainerAmbiguousError, match="durability"):
        _provider(authority).admit_local_image(spec, "/private/plamen/runtime.tar")
    assert authority.images[spec.image_reference].state == A.ImageAdmissionState.PENDING
