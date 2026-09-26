"""Fail-closed, injectable Apple ``container`` control plane.

This module never discovers or launches the CLI itself.  A native bootstrap must
register exact callbacks which keep an authenticated executable descriptor open,
track and reap every descendant, keep every admitted path component open through
the invocation, authenticate and fsync compare-and-swap journals, and prove the
signed package/binary/plugin closure on every call.  For a guest-networked call,
that bootstrap must inspect the exact attempt-labelled ``hostOnly`` network and
the container attachment and independently enforce the policy digest at a native
host boundary; Apple ``--internal`` by itself is not treated as egress denial.
Recursive mount facts must be descriptor-native and reject symlinks, hardlinks,
special/socket nodes, filesystem crossings, aliases, compression, xattrs, and
sensitive descendants.  Python code in this interpreter is part of the trusted computing base:
the private issuer registry prevents accidental/self-described claim forgery, not
malicious code already executing in the same process.

The native bootstrap must provision the exact pinned Kata kernel separately and,
if it starts Apple services, use ``system start --disable-kernel-install``.  This
provider deliberately has no system-start operation and cannot fetch a kernel.
The ``kernel_binary_sha256`` pin below is the digest of the selected member in
the staged upstream archive; it is provenance input, not proof of an installed
kernel.  Installed-kernel identity remains a native-bootstrap obligation.

Apple container 1.3.0 is intentionally unsupported: it pins containerization
0.41.0, affected by GHSA-x7pf-2jmj-pgcq.  The native install authority supplies
the observed signed executable/package/plugin closure.  This module admits a
stable 1.3.1-or-newer CLI only when its CLI, API server and package versions are
internally consistent and its exact command schemas/behavior remain compatible;
it never turns a newly observed version string into trust by itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import importlib.machinery
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import sys
import threading
import types
import unicodedata
from typing import Any, Callable, Mapping, Sequence


DEFAULT_EXECUTABLE = Path("/usr/local/bin/container")
DEFAULT_SERVER_EXECUTABLE = Path("/usr/local/bin/container-apiserver")
DEFAULT_PLUGIN_ROOT = Path("/usr/local/libexec/container/plugins")
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_OUTPUT_LIMIT_BYTES = 1024 * 1024
NATIVE_MODULE_NAME = "_plamen_native_supervisor"
NATIVE_ABI_SCHEMA = "plamen.native-broker.v2"
NATIVE_PRODUCTION_ACQUISITION = (
    "AVAILABLE_AUTHENTICATED_NATIVE_SESSION"
)
MAX_JSON_BYTES = 1024 * 1024
MAX_STREAM_TOTAL_BYTES = 16 * 1024 * 1024
MAX_ARG_COUNT = 512
MAX_ARG_BYTES = 64 * 1024
MAX_SINGLE_ARG_BYTES = 4096
MAX_TIMEOUT_SECONDS = 300
DRIVER_MAX_OUTPUT_BYTES = 1024 * 1024
DRIVER_MAX_TOTAL_OUTPUT_BYTES = 16 * 1024 * 1024
SUPPORTED_APPLE_CONTAINER_VERSION = "1.3.1"
SUPPORTED_APPLE_CONTAINER_COMMIT = "a9a62e28f6beb88940122a3d7b286f2d5ae8053a"
SUPPORTED_CONTAINERIZATION_VERSION = "0.42.0"
SUPPORTED_CONTAINERIZATION_COMMIT = "c0185aea5c04fcd4d1cfe9359e0066a380835403"
SUPPORTED_CLI_SIGNING_IDENTIFIER = "com.apple.container.cli"
SUPPORTED_SERVER_SIGNING_IDENTIFIER = "com.apple.container.apiserver"
SUPPORTED_RUNTIME_SIGNING_TEAM_ID = "UPBK2H6LZM"
SUPPORTED_CLI_EXECUTABLE_SHA256 = (
    "c6f8ef172248f7b8a30fa3e502359bba678bc993991c37b848dbead1914e86b1"
)
SUPPORTED_SERVER_EXECUTABLE_SHA256 = (
    "ace7e2200c4302b7184e29f4063d346305869202c8bda794eaae0613e39f79e2"
)
SUPPORTED_CORE_IMAGES_PLUGIN_SHA256 = (
    "89bd502b4c914a08dbca68350dbf6bad331acc510e9b83245f757a583cc388fc"
)
SUPPORTED_NETWORK_VMNET_PLUGIN_SHA256 = (
    "fcc48b3c1f393025df004de378704d69db7d06da9695ec44f291b8b2a65dd8f3"
)
SUPPORTED_RUNTIME_LINUX_PLUGIN_SHA256 = (
    "9528b7c70f5f84a3318ed5616d20bd5247af9672502cae6278f6ea52b2d69369"
)
SUPPORTED_MACHINE_APISERVER_PLUGIN_SHA256 = (
    "94424e93d4a0f10cfcf6297d7d1d5a302eebc789b1c9449df2250062cb912659"
)
SUPPORTED_PLUGIN_CLOSURE_SHA256 = hashlib.sha256(json.dumps({
    "core-images": SUPPORTED_CORE_IMAGES_PLUGIN_SHA256,
    "machine-apiserver": SUPPORTED_MACHINE_APISERVER_PLUGIN_SHA256,
    "network-vmnet": SUPPORTED_NETWORK_VMNET_PLUGIN_SHA256,
    "runtime-linux": SUPPORTED_RUNTIME_LINUX_PLUGIN_SHA256,
    "signing_team_id": SUPPORTED_RUNTIME_SIGNING_TEAM_ID,
}, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
SUPPORTED_PACKAGE_IDENTIFIER = "com.apple.container-installer"
SUPPORTED_PACKAGE_INSTALL_LOCATION = "/usr/local"
SUPPORTED_PACKAGE_AUTHORIZATION = "root"
SUPPORTED_INSTALLER_TEAM_ID = "UPBK2H6LZM"
SUPPORTED_INSTALLER_LEAF_SHA256 = "4519b43d00f55ec63138d403de1f3c542390eae3d82e59c1843846fbdfe14f5b"
SUPPORTED_KERNEL_ARCHIVE_URL = (
    "https://github.com/kata-containers/kata-containers/releases/download/3.32.0/"
    "kata-static-3.32.0-arm64.tar.zst"
)
SUPPORTED_KERNEL_ARCHIVE_SHA256 = "8736c054d9223974735394f822000823baef509e1c33405ec798240fa9b6e4b5"
SUPPORTED_KERNEL_ARCHIVE_SIZE = 696_573_576
SUPPORTED_KERNEL_BINARY_MEMBER = "./opt/kata/share/kata-containers/vmlinux-6.18.35-197-debug"
SUPPORTED_KERNEL_BINARY_SHA256 = "fb2cfb79eb1ae19447a85d75682d7fa5cfec97e24beb2609a492b806e8072c8d"
SUPPORTED_INIT_IMAGE_INDEX_DIGEST = (
    "sha256:cde8a93f9861c664bf2b74b4e2893cf877680806f12e7e989eb9c51b2f2e93bf"
)
SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST = (
    "sha256:71f6c228becbb32398ee44b8569249524722c2e11030f61cc7a5673695e5a422"
)
SUPPORTED_INIT_IMAGE_REFERENCE = (
    "ghcr.io/apple/containerization/vminit@"
    + SUPPORTED_INIT_IMAGE_INDEX_DIGEST
)

_SAFE_CONTAINER_ID = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?")
_OBSERVED_CONTAINER_ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?")
_SAFE_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SAFE_NETWORK_ID = re.compile(r"[a-z0-9](?:[a-z0-9_.-]{0,61}[a-z0-9])?")
_SAFE_LABEL_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}")
_SAFE_LABEL_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_SEMVER = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHORT_COMMIT = re.compile(r"[0-9a-f]{7}")
_BUILD = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")
_RFC3339_UTC = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z"
)
_DODO_CONTAINER_ID = re.compile(r"plamen-dodo-[a-z0-9](?:[a-z0-9_.-]{0,49}[a-z0-9])?")
_DODO_ATTEMPT_ID = re.compile(r"dodo-[A-Za-z0-9][A-Za-z0-9_.:-]{0,115}")
_SERVER_VERSION = re.compile(
    r"container-apiserver version (?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?) "
    r"\(build: (?P<build>[0-9A-Za-z][0-9A-Za-z._-]{0,63}), "
    r"commit: (?P<commit>[0-9a-f]{7})\)"
)
_OCI_REFERENCE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[1-9][0-9]{0,4})/)?"
    r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*@(?P<digest>sha256:[0-9a-f]{64})"
)
_SENSITIVE = (
    "APIKEY", "ACCESSTOKEN", "AUTH", "BEARER", "COOKIE", "CREDENTIAL",
    "KEY", "LOGIN", "PASSWORD", "PASSPHRASE", "PRIVATE", "SECRET", "TOKEN",
)

_OWNER_LABEL = "io.plamen.provider"
_RUN_LABEL = "io.plamen.run"
_AUDIT_ATTEMPT_LABEL = "io.plamen.audit-attempt"
_SPEC_LABEL = "io.plamen.spec-sha256"
_ATTEMPT_LABEL = "io.plamen.attempt-nonce"
_GENERATION_LABEL = "io.plamen.generation"
_IMAGE_LABEL = "io.plamen.image-sha256"
_IMAGE_MANIFEST_LABEL = "io.plamen.image-manifest-sha256"
_IMAGE_CLOSURE_LABEL = "io.plamen.image-closure-sha256"
_INIT_IMAGE_LABEL = "io.plamen.init-image-sha256"
_INIT_IMAGE_MANIFEST_LABEL = "io.plamen.init-image-manifest-sha256"
_MOUNT_LABEL = "io.plamen.mount-sha256"
_CONFIG_LABEL = "io.plamen.config-sha256"
_NETWORK_LABEL = "io.plamen.network-sha256"
_NETWORK_TOPOLOGY_LABEL = "io.plamen.network-topology-sha256"
_BACKEND_ADMISSION_LABEL = "io.plamen.backend-admission-sha256"
_EGRESS_ADMISSION_LABEL = "io.plamen.egress-admission-sha256"
_NETWORK_ROLE_LABEL = "io.plamen.network-role"
_NETWORK_ROLE_VALUE = "governed-egress"
_NETWORK_AUTHORITY_LABEL = "io.plamen.network-authority"
_OWNER_VALUE = "apple-container-v3"
OCI_IMAGE_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_IMAGE_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
SUPPORTED_NETWORK_ATTACHMENT_VARIANT = "reserved"
NETWORK_NONE_POLICY_SHA256 = hashlib.sha256(
    b"plamen.apple-container.network-none.v1\n"
).hexdigest()
_RESERVED_LABELS = frozenset(
    {_OWNER_LABEL, _RUN_LABEL, _AUDIT_ATTEMPT_LABEL, _SPEC_LABEL,
     _ATTEMPT_LABEL, _GENERATION_LABEL,
     _IMAGE_LABEL, _INIT_IMAGE_LABEL, _INIT_IMAGE_MANIFEST_LABEL,
     _IMAGE_CLOSURE_LABEL, _BACKEND_ADMISSION_LABEL,
     _EGRESS_ADMISSION_LABEL,
     _MOUNT_LABEL, _CONFIG_LABEL, _NETWORK_LABEL,
     _NETWORK_TOPOLOGY_LABEL, _IMAGE_MANIFEST_LABEL, _NETWORK_ROLE_LABEL,
     _NETWORK_AUTHORITY_LABEL}
)

_AUDIT_MOUNT_POLICY = (
    ("/workspace/project", True),
    ("/workspace/scratch", False),
    ("/workspace/state", False),
    ("/workspace/control", True),
    ("/run/plamen/seccomp", True),
    ("/run/plamen/credentials", True),
    ("/run/plamen/backend", True),
    ("/opt/plamen", True),
    ("/workspace/docs", True),
    ("/workspace/scope", True),
)

_SENSITIVE_PATH_COMPONENTS = frozenset({
    ".aws", ".claude", ".codex", ".docker", ".gnupg", ".ssh",
    "credentials", "keychain", "keychains", "passwords", "secrets", "tokens",
})

_CONFIGURATION_REQUIRED_FIELDS = frozenset(
    {"id", "image", "mounts", "publishedPorts", "publishedSockets", "labels",
     "sysctls", "networks", "rosetta", "initProcess", "platform", "resources",
     "runtimeHandler", "virtualization", "ssh", "readOnly", "useInit", "capAdd",
     "capDrop", "creationDate"}
)
_CONFIGURATION_OPTIONAL_FIELDS = frozenset(
    {"dns", "shmSize", "stopSignal", "maskedPaths", "readonlyPaths"}
)
_PROCESS_FIELDS = frozenset(
    {"executable", "arguments", "environment", "workingDirectory", "terminal",
     "user", "supplementalGroups", "rlimits"}
)
_RESOURCE_REQUIRED_FIELDS = frozenset({"cpus", "memoryInBytes", "cpuOverhead"})
_RESOURCE_OPTIONAL_FIELDS = frozenset({"storage"})


class AppleContainerProviderError(RuntimeError):
    """Base error.  Messages deliberately exclude command output and paths."""


class AppleContainerConfigurationError(AppleContainerProviderError, ValueError):
    pass


class AppleContainerUnavailableError(AppleContainerProviderError):
    pass


class AppleContainerProtocolError(AppleContainerProviderError):
    pass


class AppleContainerAmbiguousError(AppleContainerProviderError):
    pass


class AppleContainerMismatchError(AppleContainerProviderError):
    pass


@dataclass(frozen=True)
class AppleContainerVersionPin:
    cli_version: str
    cli_build: str
    cli_commit: str
    cli_executable_sha256: str
    cli_signing_identifier: str
    cli_signing_team_id: str
    server_executable_path: str
    server_version: str
    server_build: str
    server_commit: str
    server_banner_commit: str
    server_executable_sha256: str
    server_signing_identifier: str
    server_signing_team_id: str
    containerization_version: str
    containerization_build: str
    containerization_commit: str
    containerization_binary_sha256: str
    init_image_reference: str
    init_image_index_digest: str
    init_image_manifest_digest: str
    plugin_root: str
    core_images_plugin_sha256: str
    network_vmnet_plugin_sha256: str
    runtime_linux_plugin_sha256: str
    machine_apiserver_plugin_sha256: str
    plugin_signing_team_id: str
    plugin_closure_sha256: str
    package_identifier: str
    package_version: str
    package_install_location: str
    package_authorization: str
    package_signing_team_id: str
    package_installer_leaf_sha256: str
    package_receipt_sha256: str
    package_signed: bool
    package_notarized: bool
    package_timestamped: bool
    kernel_archive_url: str
    kernel_archive_sha256: str
    kernel_archive_size: int
    kernel_binary_member: str
    kernel_binary_sha256: str
    implicit_kernel_install_disabled: bool
    host_operating_system: str

    def __post_init__(self) -> None:
        for value in (self.cli_version, self.server_version, self.containerization_version):
            if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
                raise AppleContainerConfigurationError("version pin is malformed")
        for value in (self.cli_build, self.server_build, self.containerization_build):
            if not isinstance(value, str) or _BUILD.fullmatch(value) is None:
                raise AppleContainerConfigurationError("build pin is malformed")
        for value in (self.cli_commit, self.server_commit, self.containerization_commit):
            if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
                raise AppleContainerConfigurationError("commit pin is malformed")
        if (not isinstance(self.server_banner_commit, str)
                or _SHORT_COMMIT.fullmatch(self.server_banner_commit) is None):
            raise AppleContainerConfigurationError("server banner commit pin is malformed")
        for value in (self.cli_executable_sha256, self.server_executable_sha256,
                      self.containerization_binary_sha256, self.plugin_closure_sha256,
                      self.core_images_plugin_sha256,
                      self.network_vmnet_plugin_sha256,
                      self.runtime_linux_plugin_sha256,
                      self.machine_apiserver_plugin_sha256,
                      self.package_installer_leaf_sha256, self.package_receipt_sha256,
                      self.kernel_archive_sha256, self.kernel_binary_sha256):
            if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
                raise AppleContainerConfigurationError("binary identity pin is malformed")
            if value == "0" * 64:
                raise AppleContainerConfigurationError(
                    "binary identity observation cannot be zero"
                )
        if (isinstance(self.kernel_archive_size, bool)
                or not isinstance(self.kernel_archive_size, int)
                or self.kernel_archive_size != SUPPORTED_KERNEL_ARCHIVE_SIZE):
            raise AppleContainerConfigurationError("kernel archive size pin is malformed")
        _validate_public_text(self.host_operating_system, "host operating system", maximum=256)
        def stable_core(value: str) -> tuple[int, int, int] | None:
            if "-" in value or "+" in value:
                return None
            return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]

        plugin_closure = hashlib.sha256(json.dumps({
            "core-images": self.core_images_plugin_sha256,
            "machine-apiserver": self.machine_apiserver_plugin_sha256,
            "network-vmnet": self.network_vmnet_plugin_sha256,
            "runtime-linux": self.runtime_linux_plugin_sha256,
            "signing_team_id": self.plugin_signing_team_id,
        }, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        cli_core = stable_core(self.cli_version)
        containerization_core = stable_core(self.containerization_version)
        init_reference = _OCI_REFERENCE.fullmatch(self.init_image_reference)
        if (cli_core is None
                or cli_core < (1, 3, 1)
                or containerization_core is None
                or containerization_core < (0, 42, 0)
                or self.server_version != self.cli_version
                or self.package_version != self.cli_version
                or self.server_build != self.cli_build
                or self.server_commit != self.cli_commit
                or init_reference is None
                or init_reference.group("digest") != self.init_image_index_digest
                or _SHA256.fullmatch(self.init_image_manifest_digest) is None
                or self.init_image_reference != SUPPORTED_INIT_IMAGE_REFERENCE
                or self.init_image_index_digest != SUPPORTED_INIT_IMAGE_INDEX_DIGEST
                or self.init_image_manifest_digest
                   != SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
                or self.cli_signing_identifier != SUPPORTED_CLI_SIGNING_IDENTIFIER
                or self.cli_signing_team_id != SUPPORTED_RUNTIME_SIGNING_TEAM_ID
                or self.server_executable_path != str(DEFAULT_SERVER_EXECUTABLE)
                or self.server_signing_identifier
                   != SUPPORTED_SERVER_SIGNING_IDENTIFIER
                or self.server_signing_team_id
                   != SUPPORTED_RUNTIME_SIGNING_TEAM_ID
                or self.server_banner_commit != self.server_commit[:7]
                or self.plugin_root != str(DEFAULT_PLUGIN_ROOT)
                or self.plugin_signing_team_id
                   != SUPPORTED_RUNTIME_SIGNING_TEAM_ID
                or self.plugin_closure_sha256 != plugin_closure
                or self.package_identifier != SUPPORTED_PACKAGE_IDENTIFIER
                or self.package_install_location != SUPPORTED_PACKAGE_INSTALL_LOCATION
                or self.package_authorization != SUPPORTED_PACKAGE_AUTHORIZATION
                or self.package_signing_team_id != SUPPORTED_INSTALLER_TEAM_ID
                or self.package_installer_leaf_sha256 != SUPPORTED_INSTALLER_LEAF_SHA256
                or self.package_signed is not True
                or self.package_notarized is not True
                or self.package_timestamped is not True
                or self.kernel_archive_url != SUPPORTED_KERNEL_ARCHIVE_URL
                or self.kernel_archive_sha256 != SUPPORTED_KERNEL_ARCHIVE_SHA256
                or self.kernel_binary_member != SUPPORTED_KERNEL_BINARY_MEMBER
                or self.kernel_binary_sha256 != SUPPORTED_KERNEL_BINARY_SHA256
                or self.implicit_kernel_install_disabled is not True):
            raise AppleContainerConfigurationError(
                "Apple container compatibility authority is inconsistent or below the safe baseline"
            )

    @property
    def provenance(self) -> tuple[str, ...]:
        return (
            self.cli_version, self.cli_build, self.cli_commit,
            str(DEFAULT_EXECUTABLE), self.cli_executable_sha256,
            self.cli_signing_identifier, self.cli_signing_team_id,
            self.server_version, self.server_build, self.server_commit,
            self.server_executable_path, self.server_executable_sha256,
            self.server_signing_identifier, self.server_signing_team_id,
            self.containerization_version, self.containerization_build,
            self.containerization_commit, self.containerization_binary_sha256,
            self.init_image_reference, self.init_image_index_digest,
            self.init_image_manifest_digest,
            self.plugin_root, self.core_images_plugin_sha256,
            self.network_vmnet_plugin_sha256, self.runtime_linux_plugin_sha256,
            self.machine_apiserver_plugin_sha256,
            self.plugin_signing_team_id, self.plugin_closure_sha256,
            self.package_identifier, self.package_version,
            self.package_install_location, self.package_authorization,
            self.package_signing_team_id, self.package_installer_leaf_sha256,
            self.package_receipt_sha256, "SIGNED", "NOTARIZED", "TIMESTAMPED",
            self.host_operating_system,
            self.kernel_archive_url, self.kernel_archive_sha256,
            str(self.kernel_archive_size), self.kernel_binary_member,
            self.kernel_binary_sha256, "IMPLICIT_KERNEL_INSTALL_DISABLED",
        )


@dataclass(frozen=True)
class RunnerResult:
    returncode: int
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    stdout_observed_bytes: int = 0
    stderr_observed_bytes: int = 0
    stdout_full_sha256: str | None = None
    stderr_full_sha256: str | None = None

    def __post_init__(self) -> None:
        if (isinstance(self.returncode, bool) or not isinstance(self.returncode, int)
                or not -(2**31) <= self.returncode <= 2**31 - 1):
            raise TypeError("runner returncode must be a bounded integer")
        if not isinstance(self.stdout, bytes) or not isinstance(self.stderr, bytes):
            raise TypeError("runner streams must be bytes")
        for label, retained, observed, supplied in (
            ("stdout", self.stdout, self.stdout_observed_bytes, self.stdout_full_sha256),
            ("stderr", self.stderr, self.stderr_observed_bytes, self.stderr_full_sha256),
        ):
            if (isinstance(observed, bool) or not isinstance(observed, int)
                    or observed < len(retained) or observed > MAX_STREAM_TOTAL_BYTES):
                raise ValueError(f"runner {label} byte count is invalid")
            computed = hashlib.sha256(retained).hexdigest()
            if observed == len(retained):
                if supplied is not None and supplied != computed:
                    raise ValueError(f"runner {label} full-stream digest is inconsistent")
                object.__setattr__(self, f"{label}_full_sha256", computed)
            elif not isinstance(supplied, str) or _HEX64.fullmatch(supplied) is None:
                raise ValueError(f"runner {label} truncated digest is unavailable")


class MutationState(str, Enum):
    PENDING = "PENDING"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True)
class MutationRecord:
    schema: str
    state: MutationState
    identity: str
    spec_sha256: str
    mount_identity_sha256: str
    operation: str
    expected_state: str
    attempt_nonce: str
    mutation_nonce: str
    generation: str
    provider_provenance_sha256: str
    postcondition_sha256: str | None = None


class ImageAdmissionState(str, Enum):
    PENDING = "PENDING"
    TERMINAL = "TERMINAL"


@dataclass(frozen=True)
class ImageAdmissionRecord:
    schema: str
    state: ImageAdmissionState
    image_reference: str
    index_digest: str
    manifest_digest: str
    configuration_sha256: str
    platform_os: str
    platform_architecture: str
    archive_identity_sha256: str
    admission_nonce: str
    provider_provenance_sha256: str
    postcondition_sha256: str | None = None
    archive_content_sha256: str | None = None
    archive_size: int | None = None
    layout_receipt_sha256: str | None = None
    image_closure_sha256: str | None = None


@dataclass(frozen=True)
class HostPlatform:
    system: str
    architecture: str
    version: tuple[int, int, int]


def probe_host_platform() -> HostPlatform:
    pieces = platform.mac_ver()[0].split(".") if platform.mac_ver()[0] else []
    try:
        version = tuple(int(value) for value in (pieces + ["0", "0"])[:3])
    except ValueError:
        version = (0, 0, 0)
    return HostPlatform(platform.system(), platform.machine(), version)  # type: ignore[arg-type]


@dataclass(frozen=True)
class MountSpec:
    source: str = field(repr=False)
    target: str = field(repr=False)
    readonly: bool = True

    def __post_init__(self) -> None:
        _validate_absolute_path(self.source, "mount source", posix=False)
        _validate_absolute_path(self.target, "mount target", posix=True)
        _validate_mount_source_policy(self.source)
        if not isinstance(self.readonly, bool):
            raise AppleContainerConfigurationError("mount readonly flag must be boolean")
        for value in (self.source, self.target):
            if (value in {"/", "//", "/System/Volumes/Data"}
                    or value.startswith("//") or value.endswith("/")):
                raise AppleContainerConfigurationError("container mounts must not use root aliases")
            if any(character in value for character in ("\x00", "\n", "\r", ",")):
                raise AppleContainerConfigurationError("mount path is invalid")


@dataclass(frozen=True)
class NetworkSpec:
    name: str
    hostname: str
    policy_sha256: str
    egress_admission_sha256: str
    topology_sha256: str
    run_identity: str
    authority_nonce: str
    ipv4_subnet: str
    ipv4_gateway: str
    labels: tuple[tuple[str, str], ...]
    mtu: int = 1280
    mac_address: str | None = None
    ipv4_address: str = ""
    attachment_variant: str = SUPPORTED_NETWORK_ATTACHMENT_VARIANT
    plugin: str = "container-network-vmnet"
    internal: bool = True
    attempt_owned: bool = True
    no_dns: bool = True
    ipv6_absent: bool = True
    topology_mode: str = "hostOnly"
    effective_egress_mode: str = "VERIFIED_CONNECT_ALLOWLIST"

    def __post_init__(self) -> None:
        _validate_public_text(self.name, "network name", maximum=63)
        _validate_public_text(self.hostname, "hostname", maximum=63)
        if _SAFE_NETWORK_ID.fullmatch(self.name) is None or ".." in self.name:
            raise AppleContainerConfigurationError("network name is not canonical")
        if (not isinstance(self.policy_sha256, str)
                or _HEX64.fullmatch(self.policy_sha256) is None
                or self.policy_sha256 == NETWORK_NONE_POLICY_SHA256):
            raise AppleContainerConfigurationError("governed network policy is invalid")
        if (type(self.egress_admission_sha256) is not str
                or _HEX64.fullmatch(self.egress_admission_sha256) is None):
            raise AppleContainerConfigurationError(
                "verified egress admission is invalid"
            )
        if (not isinstance(self.topology_sha256, str)
                or _HEX64.fullmatch(self.topology_sha256) is None
                or not isinstance(self.run_identity, str)
                or _SAFE_RUN_ID.fullmatch(self.run_identity) is None
                or not isinstance(self.authority_nonce, str)
                or _HEX32.fullmatch(self.authority_nonce) is None
                or self.internal is not True or self.attempt_owned is not True
                or self.no_dns is not True or self.ipv6_absent is not True
                or self.topology_mode != "hostOnly"
                or self.effective_egress_mode
                   != "VERIFIED_CONNECT_ALLOWLIST"):
            raise AppleContainerConfigurationError("governed internal network authority is invalid")
        if not isinstance(self.ipv4_subnet, str) or not isinstance(self.ipv4_gateway, str):
            raise AppleContainerConfigurationError("governed network subnet is invalid")
        try:
            subnet = ipaddress.IPv4Network(self.ipv4_subnet, strict=True)
            gateway = ipaddress.IPv4Address(self.ipv4_gateway)
            address = ipaddress.IPv4Interface(self.ipv4_address)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError, TypeError):
            raise AppleContainerConfigurationError("governed network subnet is invalid") from None
        private_ranges = tuple(ipaddress.IPv4Network(value) for value in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        ))
        if (not 24 <= subnet.prefixlen <= 30
                or not any(subnet.subnet_of(item) for item in private_ranges)
                or gateway != subnet.network_address + 1
                or address.network != subnet or str(address) != self.ipv4_address
                or address.ip in {subnet.network_address, subnet.broadcast_address, gateway}):
            raise AppleContainerConfigurationError("governed network subnet is invalid")
        expected_labels = {
            _OWNER_LABEL: _OWNER_VALUE, _RUN_LABEL: self.run_identity,
            _NETWORK_LABEL: self.policy_sha256,
            _EGRESS_ADMISSION_LABEL: self.egress_admission_sha256,
            _NETWORK_ROLE_LABEL: _NETWORK_ROLE_VALUE,
            _NETWORK_AUTHORITY_LABEL: self.authority_nonce,
        }
        if (not isinstance(self.labels, tuple)
                or any(not isinstance(item, tuple) or len(item) != 2 for item in self.labels)
                or any(not isinstance(key, str) or not isinstance(value, str)
                       or _SAFE_LABEL_KEY.fullmatch(key) is None
                       or _SAFE_LABEL_VALUE.fullmatch(value) is None
                       for key, value in self.labels)
                or dict(self.labels) != expected_labels
                or len(self.labels) != len(expected_labels)):
            raise AppleContainerConfigurationError("governed network labels are invalid")
        if self.plugin != "container-network-vmnet":
            raise AppleContainerConfigurationError("governed network plugin is invalid")
        if (isinstance(self.mtu, bool) or not isinstance(self.mtu, int)
                or not 576 <= self.mtu <= 65535):
            raise AppleContainerConfigurationError("network MTU is invalid")
        if (not isinstance(self.mac_address, str) or re.fullmatch(
                r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", self.mac_address
            ) is None or int(self.mac_address[:2], 16) & 0b11 != 0b10):
            raise AppleContainerConfigurationError("network MAC address is invalid")
        if self.attachment_variant != SUPPORTED_NETWORK_ATTACHMENT_VARIANT:
            raise AppleContainerConfigurationError("network attachment variant is invalid")
        if self.topology_sha256 != _canonical_digest(self.topology_document()):
            raise AppleContainerConfigurationError("governed network topology digest differs")

    def topology_document(self) -> dict[str, Any]:
        return {
            "attempt_owned": self.attempt_owned,
            "authority_nonce": self.authority_nonce,
            "internal": self.internal,
            "topology_mode": self.topology_mode,
            "effective_egress_mode": self.effective_egress_mode,
            "hostname": self.hostname,
            "ipv4_gateway": self.ipv4_gateway,
            "ipv4_address": self.ipv4_address,
            "ipv4_subnet": self.ipv4_subnet,
            "ipv6_absent": self.ipv6_absent,
            "labels": [list(item) for item in sorted(self.labels)],
            "mtu": self.mtu,
            "mac_address": self.mac_address.lower() if self.mac_address else None,
            "attachment_variant": self.attachment_variant,
            "name": self.name,
            "no_dns": self.no_dns,
            "plugin": self.plugin,
            "policy_sha256": self.policy_sha256,
            "egress_admission_sha256": self.egress_admission_sha256,
            "run_identity": self.run_identity,
        }


@dataclass(frozen=True)
class ContainerSpec:
    name: str
    run_identity: str
    audit_attempt_id: str
    request_fingerprint_sha256: str
    config_sha256: str
    runtime_closure_sha256: str
    image_closure_sha256: str
    provider_provenance_sha256: str
    backend_admission_sha256: str
    credential_isolation_sha256: str
    egress_admission_sha256: str
    image_reference: str = field(repr=False)
    image_digest: str
    image_manifest_digest: str
    image_configuration_sha256: str
    init_image_reference: str = field(repr=False)
    init_image_digest: str
    init_image_manifest_digest: str
    entrypoint: str = field(repr=False)
    arguments: tuple[str, ...] = field(repr=False)
    working_directory: str = field(repr=False)
    mounts: tuple[MountSpec, ...] = field(repr=False)
    expected_environment: tuple[str, ...] = field(default=(), repr=False)
    labels: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    networks: tuple[NetworkSpec, ...] = ()
    cpus: int = 4
    memory_bytes: int = 8 * 1024 * 1024 * 1024
    uid: int = 1000
    gid: int = 1000
    rootfs_readonly: bool = True
    use_init: bool = True
    platform_os: str = "linux"
    platform_architecture: str = "arm64"
    runtime_handler: str = "container-runtime-linux"
    stop_signal: str | None = None
    cpu_overhead: int = 1
    storage_bytes: int | None = None
    rosetta_required: bool = False

    def __post_init__(self) -> None:
        _validate_container_id(self.name)
        if (not isinstance(self.run_identity, str)
                or _SAFE_RUN_ID.fullmatch(self.run_identity) is None):
            raise AppleContainerConfigurationError("run identity is not canonical")
        if (not isinstance(self.audit_attempt_id, str)
                or _SAFE_RUN_ID.fullmatch(self.audit_attempt_id) is None
                or self.name != f"plamen-{self.audit_attempt_id}"):
            raise AppleContainerConfigurationError(
                "audit attempt identity does not bind the container name"
            )
        for value, label in (
            (self.request_fingerprint_sha256, "request fingerprint"),
            (self.config_sha256, "audit configuration"),
            (self.runtime_closure_sha256, "runtime closure"),
            (self.image_closure_sha256, "image closure"),
            (self.provider_provenance_sha256, "provider provenance"),
            (self.backend_admission_sha256, "backend admission"),
            (self.credential_isolation_sha256, "credential isolation"),
            (self.egress_admission_sha256, "egress admission"),
        ):
            if type(value) is not str or _HEX64.fullmatch(value) is None:
                raise AppleContainerConfigurationError(f"{label} digest is malformed")
        match = _OCI_REFERENCE.fullmatch(self.image_reference) if isinstance(
            self.image_reference, str
        ) else None
        if (match is None or match.group("digest") != self.image_digest
                or not isinstance(self.image_digest, str)
                or _SHA256.fullmatch(self.image_digest) is None):
            raise AppleContainerConfigurationError(
                "image reference must be a canonical digest-only OCI reference"
            )
        _validate_oci_reference(self.image_reference)
        if (not isinstance(self.image_manifest_digest, str)
                or _SHA256.fullmatch(self.image_manifest_digest) is None
                or self.image_manifest_digest == self.image_digest):
            raise AppleContainerConfigurationError("image manifest digest is malformed")
        if (not isinstance(self.image_configuration_sha256, str)
                or _HEX64.fullmatch(self.image_configuration_sha256) is None):
            raise AppleContainerConfigurationError("image configuration digest is malformed")
        init_match = _OCI_REFERENCE.fullmatch(self.init_image_reference) if isinstance(
            self.init_image_reference, str
        ) else None
        if (
            init_match is None
            or init_match.group("digest") != self.init_image_digest
            or self.init_image_reference != SUPPORTED_INIT_IMAGE_REFERENCE
            or self.init_image_digest != SUPPORTED_INIT_IMAGE_INDEX_DIGEST
            or self.init_image_manifest_digest
               != SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
            or self.init_image_digest == self.init_image_manifest_digest
        ):
            raise AppleContainerConfigurationError(
                "init image must be the exact immutable linux/arm64 pin"
            )
        _validate_oci_reference(self.init_image_reference)
        _validate_absolute_path(self.entrypoint, "entrypoint", posix=True)
        _validate_absolute_path(self.working_directory, "working directory", posix=True)
        if (not isinstance(self.arguments, tuple) or not self.arguments
                or len(self.arguments) > 128):
            raise AppleContainerConfigurationError("container driver arguments are invalid")
        for argument in self.arguments:
            _validate_public_text(argument, "container argument", maximum=MAX_SINGLE_ARG_BYTES)
            if (_looks_sensitive(argument)
                    or argument.casefold() in {"pull", "--pull", "--force", "load"}):
                raise AppleContainerConfigurationError("sensitive container argument is forbidden")
        if (not isinstance(self.mounts, tuple) or len(self.mounts) > 32
                or any(type(item) is not MountSpec for item in self.mounts)):
            raise AppleContainerConfigurationError("too many container mounts")
        if any(item.target == "/.plamen" or item.target.startswith("/.plamen/")
               for item in self.mounts):
            raise AppleContainerConfigurationError("container mount target is reserved")
        sources = [item.source.casefold() for item in self.mounts]
        targets = [item.target.casefold() for item in self.mounts]
        if len(sources) != len(set(sources)) or len(targets) != len(set(targets)):
            raise AppleContainerConfigurationError("container mount paths collide")
        target_parts = tuple(PurePosixPath(item.target).parts for item in self.mounts)
        for index, left in enumerate(target_parts):
            for right in target_parts[index + 1:]:
                shared = min(len(left), len(right))
                if left[:shared] == right[:shared]:
                    raise AppleContainerConfigurationError(
                        "container mount targets overlap"
                    )
        if tuple((item.target, item.readonly) for item in self.mounts) != (
            _AUDIT_MOUNT_POLICY
        ):
            raise AppleContainerConfigurationError(
                "container mount roster differs from the exact audit policy"
            )
        if (not isinstance(self.networks, tuple)
                or any(type(item) is not NetworkSpec for item in self.networks)
                or len(self.networks) != 1
                or self.networks[0].run_identity != self.run_identity):
            raise AppleContainerConfigurationError(
                "exactly one attempt-owned internal network is required"
            )
        for network in self.networks:
            if (network.hostname != self.name
                    or network.egress_admission_sha256
                       != self.egress_admission_sha256):
                raise AppleContainerConfigurationError(
                    "network admission must bind the exact container identity"
                )
        if not isinstance(self.expected_environment, tuple):
            raise AppleContainerConfigurationError("expected image environment is malformed")
        _validate_environment(self.expected_environment)
        if not isinstance(self.labels, tuple):
            raise AppleContainerConfigurationError("container labels are malformed")
        seen: set[str] = set()
        for item in self.labels:
            if not isinstance(item, tuple) or len(item) != 2:
                raise AppleContainerConfigurationError("container label is invalid or sensitive")
            key, value = item
            if (not isinstance(key, str) or not isinstance(value, str)
                    or key.casefold() in seen
                    or key.casefold().startswith("io.plamen.")
                    or _SAFE_LABEL_KEY.fullmatch(key) is None
                    or _SAFE_LABEL_VALUE.fullmatch(value) is None
                    or _looks_sensitive(key) or _looks_sensitive(value)):
                raise AppleContainerConfigurationError("container label is invalid or sensitive")
            seen.add(key.casefold())
        for label, value in (("cpus", self.cpus), ("memory_bytes", self.memory_bytes),
                             ("uid", self.uid), ("gid", self.gid),
                             ("cpu_overhead", self.cpu_overhead)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise AppleContainerConfigurationError(f"{label} must be an integer")
        if not 1 <= self.cpus <= 64:
            raise AppleContainerConfigurationError("container CPU count is out of range")
        if not (512 * 1024 * 1024 <= self.memory_bytes <= 1024**4) or self.memory_bytes % 1024**2:
            raise AppleContainerConfigurationError("container memory is invalid")
        if not (1 <= self.uid <= 2**32 - 1 and 1 <= self.gid <= 2**32 - 1):
            raise AppleContainerConfigurationError("container uid/gid is out of range")
        if (self.cpu_overhead != 1 or self.storage_bytes is not None
                or self.rootfs_readonly is not True or self.use_init is not True):
            raise AppleContainerConfigurationError("mandatory isolation defaults were changed")
        if self.platform_os != "linux" or self.platform_architecture != "arm64":
            raise AppleContainerConfigurationError("Apple provider requires linux/arm64")
        if self.runtime_handler != "container-runtime-linux":
            raise AppleContainerConfigurationError("runtime handler is not permitted")
        if type(self.rosetta_required) is not bool:
            raise AppleContainerConfigurationError("Rosetta requirement must be boolean")
        if self.rosetta_required and (
            _DODO_CONTAINER_ID.fullmatch(self.name) is None
            or _DODO_ATTEMPT_ID.fullmatch(self.audit_attempt_id) is None
        ):
            raise AppleContainerConfigurationError(
                "Rosetta is restricted to the request-bound Apple Silicon DODO lane"
            )
        if self.stop_signal is not None:
            _validate_public_text(self.stop_signal, "stop signal", maximum=32)

    def core_document(self) -> dict[str, Any]:
        return {
            "arguments": list(self.arguments), "cpu_overhead": self.cpu_overhead,
            "backend_admission_sha256": self.backend_admission_sha256,
            "config_sha256": self.config_sha256,
            "cpus": self.cpus, "entrypoint": self.entrypoint,
            "environment": list(self.expected_environment), "gid": self.gid,
            "image_configuration_sha256": self.image_configuration_sha256,
            "image_closure_sha256": self.image_closure_sha256,
            "image_digest": self.image_digest,
            "image_manifest_digest": self.image_manifest_digest,
            "image_reference": self.image_reference,
            "init_image_digest": self.init_image_digest,
            "init_image_manifest_digest": self.init_image_manifest_digest,
            "init_image_reference": self.init_image_reference,
            "labels": [list(item) for item in sorted(self.labels)],
            "memory_bytes": self.memory_bytes,
            "credential_isolation_sha256": self.credential_isolation_sha256,
            "egress_admission_sha256": self.egress_admission_sha256,
            "mounts": [{"readonly": item.readonly, "source": item.source,
                        "target": item.target} for item in sorted(self.mounts, key=lambda x: x.target)],
            "name": self.name,
            "networks": [{"hostname": item.hostname, "mac_address": item.mac_address,
                          "mtu": item.mtu, "name": item.name,
                          "ipv4_subnet": item.ipv4_subnet,
                          "ipv4_gateway": item.ipv4_gateway,
                          "ipv4_address": item.ipv4_address,
                          "labels": [list(value) for value in sorted(item.labels)],
                          "plugin": item.plugin,
                          "policy_sha256": item.policy_sha256,
                          "topology_sha256": item.topology_sha256,
                          "run_identity": item.run_identity,
                          "authority_nonce": item.authority_nonce,
                          "internal": item.internal, "attempt_owned": item.attempt_owned,
                          "no_dns": item.no_dns,
                          "ipv6_absent": item.ipv6_absent,
                          "attachment_variant": item.attachment_variant}
                         for item in self.networks],
            "platform": {"architecture": self.platform_architecture, "os": self.platform_os},
            "rootfs_readonly": self.rootfs_readonly, "run_identity": self.run_identity,
            "audit_attempt_id": self.audit_attempt_id,
            "provider_provenance_sha256": self.provider_provenance_sha256,
            "request_fingerprint_sha256": self.request_fingerprint_sha256,
            "runtime_closure_sha256": self.runtime_closure_sha256,
            "rosetta_required": self.rosetta_required,
            "runtime_handler": self.runtime_handler, "stop_signal": self.stop_signal,
            "storage_bytes": self.storage_bytes, "uid": self.uid,
            "use_init": self.use_init, "working_directory": self.working_directory,
        }

    @property
    def fingerprint(self) -> str:
        return _canonical_digest(self.core_document())

    @property
    def network_policy_sha256(self) -> str:
        return self.networks[0].policy_sha256

    @property
    def broker_v2_commitment(self) -> dict[str, str]:
        """Exact ordered common commitment from the native broker-v2 ABI."""
        return {
            "request_fingerprint": self.request_fingerprint_sha256,
            "attempt_id": self.audit_attempt_id,
            "run_identity": self.run_identity,
            "config_sha256": self.config_sha256,
            "runtime_closure_sha256": self.runtime_closure_sha256,
            "image_closure_sha256": self.image_closure_sha256,
            "provider_provenance_sha256": self.provider_provenance_sha256,
            "backend_admission_sha256": self.backend_admission_sha256,
            "credential_isolation_sha256": self.credential_isolation_sha256,
            "egress_admission_sha256": self.egress_admission_sha256,
        }

    def expected_labels(self, record: MutationRecord) -> dict[str, str]:
        result = dict(self.labels)
        result.update({
            _OWNER_LABEL: _OWNER_VALUE, _RUN_LABEL: self.run_identity,
            _AUDIT_ATTEMPT_LABEL: self.audit_attempt_id,
            _SPEC_LABEL: self.fingerprint, _ATTEMPT_LABEL: record.attempt_nonce,
            _GENERATION_LABEL: record.generation,
            _IMAGE_LABEL: self.image_digest.removeprefix("sha256:"),
            _IMAGE_MANIFEST_LABEL: self.image_manifest_digest.removeprefix("sha256:"),
            _IMAGE_CLOSURE_LABEL: self.image_closure_sha256,
            _INIT_IMAGE_LABEL: self.init_image_digest.removeprefix("sha256:"),
            _INIT_IMAGE_MANIFEST_LABEL:
                self.init_image_manifest_digest.removeprefix("sha256:"),
            _MOUNT_LABEL: record.mount_identity_sha256,
            _CONFIG_LABEL: self.image_configuration_sha256,
            _NETWORK_LABEL: self.network_policy_sha256,
            _NETWORK_TOPOLOGY_LABEL: self.networks[0].topology_sha256,
            _BACKEND_ADMISSION_LABEL: self.backend_admission_sha256,
            _EGRESS_ADMISSION_LABEL: self.egress_admission_sha256,
        })
        return result


@dataclass(frozen=True)
class PreflightReceipt:
    executable_path: str
    executable_sha256: str
    cli_version: str
    cli_build: str
    cli_commit: str
    cli_signing_identifier: str
    cli_signing_team_id: str
    server_executable_path: str
    server_executable_sha256: str
    server_version: str
    server_build: str
    server_commit: str
    server_signing_identifier: str
    server_signing_team_id: str
    containerization_version: str
    containerization_build: str
    containerization_commit: str
    containerization_binary_sha256: str
    init_image_reference: str
    init_image_index_digest: str
    init_image_manifest_digest: str
    init_image_postcondition_sha256: str
    plugin_root: str
    core_images_plugin_sha256: str
    network_vmnet_plugin_sha256: str
    runtime_linux_plugin_sha256: str
    machine_apiserver_plugin_sha256: str
    plugin_signing_team_id: str
    plugin_closure_sha256: str
    package_identifier: str
    package_version: str
    package_install_location: str
    package_authorization: str
    package_signing_team_id: str
    package_receipt_sha256: str
    package_installer_leaf_sha256: str
    package_signed: bool
    package_notarized: bool
    package_timestamped: bool
    kernel_archive_url: str
    kernel_archive_sha256: str
    kernel_archive_size: int
    kernel_binary_member: str
    kernel_binary_sha256: str
    implicit_kernel_install_disabled: bool
    host_architecture: str
    host_os_major: int


class RecoveryDecision(str, Enum):
    RUNNING_MATCH = "RUNNING_MATCH"
    STOPPED_MATCH = "STOPPED_MATCH"
    ABSENT = "ABSENT"
    MISMATCH = "MISMATCH"


@dataclass(frozen=True)
class RecoveryReceipt:
    decision: RecoveryDecision
    container_id: str | None
    spec_sha256: str
    observed_state: str | None
    observation_sha256: str | None
    reason_code: str | None = None
    rosetta_required: bool = False


@dataclass(frozen=True)
class OperationReceipt:
    operation: str
    container_id: str
    spec_sha256: str
    observed_state: str | None
    stdout_sha256: str
    stderr_sha256: str
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    init_image_reference: str
    init_image_index_digest: str
    init_image_manifest_digest: str
    rosetta_required: bool = False


@dataclass(frozen=True)
class LogsReceipt(OperationReceipt):
    pass


@dataclass(frozen=True)
class DriverLaunchRequest:
    """Canonical, request-bound description of the already-created init process."""

    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_policy_sha256: str
    driver_argv_sha256: str
    driver_environment_sha256: str
    driver_cwd_sha256: str
    driver_stdin_sha256: str
    pass_fd_roster_sha256: str
    rosetta_required: bool
    operation_sequence: int = 1
    schema: str = "plamen.apple-container.driver-launch.v1"

    def __post_init__(self) -> None:
        _validate_container_id(self.container_id)
        if (self.schema != "plamen.apple-container.driver-launch.v1"
                or not isinstance(self.attempt_id, str)
                or _SAFE_RUN_ID.fullmatch(self.attempt_id) is None
                or type(self.operation_sequence) is not int
                or self.operation_sequence != 1
                or type(self.rosetta_required) is not bool):
            raise AppleContainerConfigurationError("driver launch request is malformed")
        for value in (
            self.spec_sha256, self.launch_policy_sha256,
            self.driver_argv_sha256, self.driver_environment_sha256,
            self.driver_cwd_sha256, self.driver_stdin_sha256,
            self.pass_fd_roster_sha256,
        ):
            if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
                raise AppleContainerConfigurationError(
                    "driver launch request digest is malformed"
                )

    @property
    def request_sha256(self) -> str:
        return _canonical_digest({
            "attempt_id": self.attempt_id,
            "container_id": self.container_id,
            "driver_argv_sha256": self.driver_argv_sha256,
            "driver_cwd_sha256": self.driver_cwd_sha256,
            "driver_environment_sha256": self.driver_environment_sha256,
            "driver_stdin_sha256": self.driver_stdin_sha256,
            "launch_policy_sha256": self.launch_policy_sha256,
            "operation_sequence": self.operation_sequence,
            "pass_fd_roster_sha256": self.pass_fd_roster_sha256,
            "rosetta_required": self.rosetta_required,
            "schema": self.schema,
            "spec_sha256": self.spec_sha256,
        })


class DriverLifecycleState(str, Enum):
    START_ARMED = "START_ARMED"
    START_CLAIMED = "START_CLAIMED"
    START_EFFECT = "START_EFFECT"
    START_COMMITTED = "START_COMMITTED"
    WAIT_ARMED = "WAIT_ARMED"
    WAIT_CLAIMED = "WAIT_CLAIMED"
    WAIT_EFFECT = "WAIT_EFFECT"
    WAIT_COMMITTED = "WAIT_COMMITTED"
    START_ABORTED = "START_ABORTED"


@dataclass(frozen=True)
class DriverLifecycleRecord:
    schema: str
    state: DriverLifecycleState
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_request_sha256: str
    launch_policy_sha256: str
    driver_argv_sha256: str
    driver_environment_sha256: str
    driver_cwd_sha256: str
    driver_stdin_sha256: str
    pass_fd_roster_sha256: str
    start_operation_nonce: str
    wait_operation_nonce: str | None
    native_process_id: str | None
    native_process_handle_sha256: str | None
    cli_executable_sha256: str
    start_timestamp: str | None
    end_timestamp: str | None
    exit_code: int | None
    stdout_sha256: str | None
    stderr_sha256: str | None
    stdout_retained_sha256: str | None
    stderr_retained_sha256: str | None
    stdout_observed_bytes: int | None
    stderr_observed_bytes: int | None
    stdout_retained_bytes: int | None
    stderr_retained_bytes: int | None
    stdout_truncated: bool | None
    stderr_truncated: bool | None
    native_process_extinction_sha256: str | None
    cleanup_sha256: str | None
    stop_argv_sha256: str | None
    stop_stdout_sha256: str | None
    stop_stderr_sha256: str | None
    stopped_observation_sha256: str | None
    guest_population_extinction_sha256: str | None
    descendants_extinct: bool | None
    guest_process_extinct: bool | None
    backend_egress_revoked: bool | None
    stop_control_process_reaped: bool | None
    stop_control_process_group_extinct: bool | None
    guest_population_zero: bool | None
    container_vm_stopped: bool | None
    rosetta_required: bool
    provider_provenance_sha256: str
    start_effect_sha256: str | None
    start_abort_extinction_sha256: str | None
    start_abort_cleanup_sha256: str | None
    start_abort_egress_revoked: bool | None
    start_receipt_sha256: str | None
    start_journal_checkpoint_sha256: str | None
    wait_effect_sha256: str | None
    journal_checkpoint_sha256: str

    def __post_init__(self) -> None:
        _validate_driver_record(self)


@dataclass(frozen=True)
class DriverStartReceipt:
    schema: str
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_request_sha256: str
    launch_policy_sha256: str
    driver_argv_sha256: str
    driver_environment_sha256: str
    driver_cwd_sha256: str
    driver_stdin_sha256: str
    pass_fd_roster_sha256: str
    start_operation_nonce: str
    operation_sequence: int
    native_process_id: str
    native_process_handle_sha256: str
    cli_executable_sha256: str
    provider_provenance_sha256: str
    start_timestamp: str
    start_effect_sha256: str
    journal_checkpoint_sha256: str
    rosetta_required: bool

    def __post_init__(self) -> None:
        if (self.schema != "plamen.apple-container.driver-start.v1"
                or type(self.operation_sequence) is not int
                or self.operation_sequence != 1
                or type(self.rosetta_required) is not bool):
            raise AppleContainerProtocolError("driver start receipt is malformed")
        _validate_container_id(self.container_id)
        if (not isinstance(self.attempt_id, str)
                or _SAFE_RUN_ID.fullmatch(self.attempt_id) is None
                or not isinstance(self.native_process_id, str)
                or _SAFE_RUN_ID.fullmatch(self.native_process_id) is None
                or not isinstance(self.start_operation_nonce, str)
                or _HEX32.fullmatch(self.start_operation_nonce) is None):
            raise AppleContainerProtocolError("driver start receipt identity is malformed")
        _timestamp(self.start_timestamp, "driver start timestamp")
        for value in (
            self.spec_sha256, self.launch_request_sha256,
            self.launch_policy_sha256, self.driver_argv_sha256,
            self.driver_environment_sha256, self.driver_cwd_sha256,
            self.driver_stdin_sha256, self.pass_fd_roster_sha256,
            self.native_process_handle_sha256,
            self.cli_executable_sha256, self.provider_provenance_sha256,
            self.start_effect_sha256,
            self.journal_checkpoint_sha256,
        ):
            if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
                raise AppleContainerProtocolError("driver start receipt digest is malformed")

    @property
    def receipt_sha256(self) -> str:
        return _canonical_digest(self.__dict__)


@dataclass(frozen=True)
class DriverStartResult:
    receipt: DriverStartReceipt
    process_capability: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.receipt) is not DriverStartReceipt:
            raise AppleContainerProtocolError("driver start result is malformed")
        facts = _driver_process_facts(self.process_capability)
        if (facts is None or facts.native_process_handle_sha256
                != self.receipt.native_process_handle_sha256):
            raise AppleContainerUnavailableError(
                "driver start result lacks its opaque native process capability"
            )


@dataclass(frozen=True)
class DriverWaitReceipt:
    schema: str
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_request_sha256: str
    start_receipt_sha256: str
    launch_policy_sha256: str
    driver_argv_sha256: str
    driver_environment_sha256: str
    driver_cwd_sha256: str
    driver_stdin_sha256: str
    pass_fd_roster_sha256: str
    start_operation_nonce: str
    wait_operation_nonce: str
    operation_sequence: int
    native_process_id: str
    native_process_handle_sha256: str
    cli_executable_sha256: str
    provider_provenance_sha256: str
    exit_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_retained_sha256: str
    stderr_retained_sha256: str
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    stdout_retained_bytes: int
    stderr_retained_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    start_timestamp: str
    end_timestamp: str
    native_process_extinction_sha256: str
    cleanup_sha256: str
    stop_argv_sha256: str
    stop_stdout_sha256: str
    stop_stderr_sha256: str
    stopped_observation_sha256: str
    guest_population_extinction_sha256: str
    descendants_extinct: bool
    guest_process_extinct: bool
    backend_egress_revoked: bool
    stop_control_process_reaped: bool
    stop_control_process_group_extinct: bool
    guest_population_zero: bool
    container_vm_stopped: bool
    journal_checkpoint_sha256: str
    rosetta_required: bool

    def __post_init__(self) -> None:
        if (self.schema != "plamen.apple-container.driver-wait.v2"
                or type(self.operation_sequence) is not int
                or self.operation_sequence != 2
                or type(self.exit_code) is not int
                or not 0 <= self.exit_code <= 255
                or type(self.rosetta_required) is not bool
                or self.descendants_extinct is not True
                or self.guest_process_extinct is not True
                or self.backend_egress_revoked is not True
                or self.stop_control_process_reaped is not True
                or self.stop_control_process_group_extinct is not True
                or self.guest_population_zero is not True
                or self.container_vm_stopped is not True):
            raise AppleContainerProtocolError("driver wait receipt is malformed")
        _validate_container_id(self.container_id)
        if (not isinstance(self.attempt_id, str)
                or _SAFE_RUN_ID.fullmatch(self.attempt_id) is None
                or not isinstance(self.native_process_id, str)
                or _SAFE_RUN_ID.fullmatch(self.native_process_id) is None
                or not isinstance(self.start_operation_nonce, str)
                or _HEX32.fullmatch(self.start_operation_nonce) is None
                or not isinstance(self.wait_operation_nonce, str)
                or _HEX32.fullmatch(self.wait_operation_nonce) is None
                or self.wait_operation_nonce == self.start_operation_nonce):
            raise AppleContainerProtocolError("driver wait receipt identity is malformed")
        _timestamp(self.start_timestamp, "driver start timestamp")
        _timestamp(self.end_timestamp, "driver end timestamp")
        if (_timestamp_value(self.end_timestamp, "driver end timestamp")
                < _timestamp_value(self.start_timestamp, "driver start timestamp")):
            raise AppleContainerProtocolError(
                "driver end timestamp precedes its start"
            )
        for value in (
            self.spec_sha256, self.launch_request_sha256,
            self.start_receipt_sha256, self.launch_policy_sha256,
            self.driver_argv_sha256, self.driver_environment_sha256,
            self.driver_cwd_sha256, self.driver_stdin_sha256,
            self.pass_fd_roster_sha256,
            self.native_process_handle_sha256, self.cli_executable_sha256,
            self.provider_provenance_sha256,
            self.stdout_sha256, self.stderr_sha256,
            self.stdout_retained_sha256, self.stderr_retained_sha256,
            self.native_process_extinction_sha256, self.cleanup_sha256,
            self.stop_argv_sha256, self.stop_stdout_sha256,
            self.stop_stderr_sha256, self.stopped_observation_sha256,
            self.guest_population_extinction_sha256,
            self.journal_checkpoint_sha256,
        ):
            if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
                raise AppleContainerProtocolError("driver wait receipt digest is malformed")
        for observed, retained, truncated in (
            (self.stdout_observed_bytes, self.stdout_retained_bytes,
             self.stdout_truncated),
            (self.stderr_observed_bytes, self.stderr_retained_bytes,
             self.stderr_truncated),
        ):
            if (type(observed) is not int or type(retained) is not int
                    or not 0 <= retained <= DRIVER_MAX_OUTPUT_BYTES
                    or not retained <= observed <= DRIVER_MAX_TOTAL_OUTPUT_BYTES
                    or type(truncated) is not bool
                    or truncated is not (observed != retained)):
                raise AppleContainerProtocolError("driver wait stream evidence is malformed")

    @property
    def receipt_sha256(self) -> str:
        return _canonical_digest(self.__dict__)


@dataclass(frozen=True)
class DriverWaitResult:
    receipt: DriverWaitReceipt
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (type(self.receipt) is not DriverWaitReceipt
                or type(self.stdout) is not bytes or type(self.stderr) is not bytes
                or len(self.stdout) != self.receipt.stdout_retained_bytes
                or len(self.stderr) != self.receipt.stderr_retained_bytes):
            raise AppleContainerProtocolError("driver wait result is malformed")
        for retained, observed, full_digest, retained_digest in (
            (self.stdout, self.receipt.stdout_observed_bytes,
             self.receipt.stdout_sha256, self.receipt.stdout_retained_sha256),
            (self.stderr, self.receipt.stderr_observed_bytes,
             self.receipt.stderr_sha256, self.receipt.stderr_retained_sha256),
        ):
            digest = hashlib.sha256(retained).hexdigest()
            if (digest != retained_digest
                    or (observed == len(retained) and digest != full_digest)):
                raise AppleContainerProtocolError("driver wait result digest differs")


APPLE_FUZZ_EXECUTION_REQUEST_SCHEMA = (
    "plamen.apple-container.fuzz-execution-request.v1"
)
APPLE_FUZZ_EXECUTION_BUNDLE_SCHEMA = (
    "plamen.apple-container.fuzz-execution-bundle.v1"
)
APPLE_NATIVE_FUZZ_LAUNCH_SCHEMA = (
    "plamen.apple-container.native-fuzz-launch.v1"
)
APPLE_NATIVE_FUZZ_TERMINAL_SCHEMA = (
    "plamen.apple-container.native-fuzz-terminal.v1"
)
APPLE_NATIVE_FUZZ_DELETE_SCHEMA = (
    "plamen.apple-container.native-fuzz-delete.v1"
)
APPLE_NATIVE_FUZZ_BUNDLE_SCHEMA = (
    "plamen.apple-container.native-fuzz-bundle.v1"
)
APPLE_FUZZ_OPERATION_KEY_SCHEMA = (
    "plamen.apple-container.fuzz-operation-key.v1"
)


def apple_fuzz_operation_key(
    authority_digest: str,
    phase_io_binding_digest: str,
    attempt_id: str,
    guest_executable_sha256: str,
) -> str:
    """Derive the exact replay key for one authenticated fuzz campaign."""

    for value in (
        authority_digest, phase_io_binding_digest, guest_executable_sha256,
    ):
        if type(value) is not str or _HEX64.fullmatch(value) is None:
            raise AppleContainerConfigurationError(
                "Apple fuzz operation identity is malformed"
            )
    if type(attempt_id) is not str or _SAFE_RUN_ID.fullmatch(attempt_id) is None:
        raise AppleContainerConfigurationError(
            "Apple fuzz operation identity is malformed"
        )
    return _canonical_digest({
        "attempt_id": attempt_id,
        "authority_digest": authority_digest,
        "guest_executable_sha256": guest_executable_sha256,
        "phase_io_binding_digest": phase_io_binding_digest,
        "schema": APPLE_FUZZ_OPERATION_KEY_SCHEMA,
    })


def derive_apple_fuzz_container_id(
    authority_digest: str, operation_key_sha256: str,
) -> str:
    """Mirror the native provider's fixed, non-ambient identifier derivation."""

    for value in (authority_digest, operation_key_sha256):
        if type(value) is not str or _HEX64.fullmatch(value) is None:
            raise AppleContainerConfigurationError(
                "Apple fuzz container identity is malformed"
            )
    digest = hashlib.sha256(
        b"plamen.apple-container.id.v1\x00"
        + bytes.fromhex(authority_digest)
        + bytes.fromhex(operation_key_sha256)
    ).hexdigest()
    return "plamen-" + digest[:32]


def _stable_version_at_least(value: str, baseline: tuple[int, int, int]) -> bool:
    if type(value) is not str or _SEMVER.fullmatch(value) is None:
        return False
    if "-" in value or "+" in value:
        return False
    try:
        return tuple(int(item) for item in value.split(".")) >= baseline
    except (TypeError, ValueError):
        return False


def validate_compatible_preflight_receipt(receipt: PreflightReceipt) -> None:
    """Revalidate the immutable, native-issued compatible-latest observation.

    This is a consumer check, not an issuer.  Authenticity still comes from the
    native provider and the external PhaseIO binding; Python callers cannot
    promote a constructed value into production authority.
    """

    if type(receipt) is not PreflightReceipt:
        raise AppleContainerProtocolError("Apple preflight receipt is malformed")
    plugin_closure = _canonical_digest({
        "core-images": receipt.core_images_plugin_sha256,
        "machine-apiserver": receipt.machine_apiserver_plugin_sha256,
        "network-vmnet": receipt.network_vmnet_plugin_sha256,
        "runtime-linux": receipt.runtime_linux_plugin_sha256,
        "signing_team_id": receipt.plugin_signing_team_id,
    })
    digests = (
        receipt.executable_sha256, receipt.server_executable_sha256,
        receipt.containerization_binary_sha256,
        receipt.init_image_postcondition_sha256,
        receipt.core_images_plugin_sha256,
        receipt.network_vmnet_plugin_sha256,
        receipt.runtime_linux_plugin_sha256,
        receipt.machine_apiserver_plugin_sha256,
        receipt.plugin_closure_sha256, receipt.package_receipt_sha256,
        receipt.package_installer_leaf_sha256,
        receipt.kernel_archive_sha256, receipt.kernel_binary_sha256,
    )
    if (
        not _stable_version_at_least(receipt.cli_version, (1, 3, 1))
        or not _stable_version_at_least(
            receipt.containerization_version, (0, 42, 0)
        )
        or receipt.server_version != receipt.cli_version
        or receipt.package_version != receipt.cli_version
        or receipt.server_build != receipt.cli_build
        or receipt.server_commit != receipt.cli_commit
        or type(receipt.cli_commit) is not str
        or _COMMIT.fullmatch(receipt.cli_commit) is None
        or type(receipt.containerization_commit) is not str
        or _COMMIT.fullmatch(receipt.containerization_commit) is None
        or receipt.executable_path != str(DEFAULT_EXECUTABLE)
        or receipt.server_executable_path != str(DEFAULT_SERVER_EXECUTABLE)
        or receipt.cli_signing_identifier != SUPPORTED_CLI_SIGNING_IDENTIFIER
        or receipt.server_signing_identifier
        != SUPPORTED_SERVER_SIGNING_IDENTIFIER
        or receipt.cli_signing_team_id != SUPPORTED_RUNTIME_SIGNING_TEAM_ID
        or receipt.server_signing_team_id != SUPPORTED_RUNTIME_SIGNING_TEAM_ID
        or receipt.plugin_signing_team_id != SUPPORTED_RUNTIME_SIGNING_TEAM_ID
        or receipt.plugin_root != str(DEFAULT_PLUGIN_ROOT)
        or receipt.plugin_closure_sha256 != plugin_closure
        or receipt.package_identifier != SUPPORTED_PACKAGE_IDENTIFIER
        or receipt.package_install_location != SUPPORTED_PACKAGE_INSTALL_LOCATION
        or receipt.package_authorization != SUPPORTED_PACKAGE_AUTHORIZATION
        or receipt.package_signing_team_id != SUPPORTED_INSTALLER_TEAM_ID
        or receipt.package_installer_leaf_sha256
        != SUPPORTED_INSTALLER_LEAF_SHA256
        or receipt.package_signed is not True
        or receipt.package_notarized is not True
        or receipt.package_timestamped is not True
        or receipt.init_image_reference != SUPPORTED_INIT_IMAGE_REFERENCE
        or receipt.init_image_index_digest != SUPPORTED_INIT_IMAGE_INDEX_DIGEST
        or receipt.init_image_manifest_digest
        != SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
        or receipt.kernel_archive_url != SUPPORTED_KERNEL_ARCHIVE_URL
        or receipt.kernel_archive_sha256 != SUPPORTED_KERNEL_ARCHIVE_SHA256
        or receipt.kernel_archive_size != SUPPORTED_KERNEL_ARCHIVE_SIZE
        or receipt.kernel_binary_member != SUPPORTED_KERNEL_BINARY_MEMBER
        or receipt.kernel_binary_sha256 != SUPPORTED_KERNEL_BINARY_SHA256
        or receipt.implicit_kernel_install_disabled is not True
        or receipt.host_architecture not in {"arm64", "arm64e"}
        or type(receipt.host_os_major) is not int
        or receipt.host_os_major < 26
        or any(type(value) is not str or _HEX64.fullmatch(value) is None
               or value == "0" * 64 for value in digests)
    ):
        raise AppleContainerProtocolError(
            "Apple preflight compatibility observation is inconsistent"
        )


def apple_container_preflight_sha256(receipt: PreflightReceipt) -> str:
    validate_compatible_preflight_receipt(receipt)
    return _canonical_digest(receipt.__dict__)


@dataclass(frozen=True)
class AppleFuzzExecutionRequest:
    authority_digest: str
    prepared_campaign_digest: str
    secure_launcher_digest: str
    phase_io_binding_digest: str
    provider_preflight_sha256: str
    provider_provenance_sha256: str
    cli_executable_sha256: str
    guest_executable_sha256: str
    operation_key_sha256: str
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_policy_sha256: str
    guest_argv: tuple[str, ...]
    guest_environment: tuple[str, ...]
    guest_cwd: str
    timeout_seconds: float
    init_image_reference: str
    init_image_index_digest: str
    init_image_manifest_digest: str
    rosetta_required: bool
    schema: str = APPLE_FUZZ_EXECUTION_REQUEST_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != APPLE_FUZZ_EXECUTION_REQUEST_SCHEMA
            or type(self.guest_argv) is not tuple or not self.guest_argv
            or len(self.guest_argv) > MAX_ARG_COUNT
            or type(self.guest_environment) is not tuple
            or type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(float(self.timeout_seconds))
            or not 0 < float(self.timeout_seconds) <= 3600
            or type(self.rosetta_required) is not bool
        ):
            raise AppleContainerConfigurationError(
                "Apple fuzz execution request is malformed"
            )
        _validate_container_id(self.container_id)
        if type(self.attempt_id) is not str or _SAFE_RUN_ID.fullmatch(
            self.attempt_id
        ) is None:
            raise AppleContainerConfigurationError(
                "Apple fuzz attempt identity is malformed"
            )
        _validate_absolute_path(self.guest_argv[0], "fuzz executable", posix=True)
        for item in self.guest_argv[1:]:
            _validate_public_text(item, "fuzz argument", maximum=MAX_SINGLE_ARG_BYTES)
        _validate_environment(self.guest_environment)
        _validate_absolute_path(self.guest_cwd, "fuzz working directory", posix=True)
        for value in (
            self.authority_digest, self.prepared_campaign_digest,
            self.secure_launcher_digest, self.phase_io_binding_digest,
            self.provider_preflight_sha256, self.provider_provenance_sha256,
            self.cli_executable_sha256, self.guest_executable_sha256,
            self.operation_key_sha256,
            self.spec_sha256,
            self.launch_policy_sha256,
        ):
            if type(value) is not str or _HEX64.fullmatch(value) is None:
                raise AppleContainerConfigurationError(
                    "Apple fuzz execution request digest is malformed"
                )
        if self.container_id != derive_apple_fuzz_container_id(
            self.authority_digest, self.operation_key_sha256
        ):
            raise AppleContainerConfigurationError(
                "Apple fuzz container identity differs"
            )
        if (
            self.init_image_reference != SUPPORTED_INIT_IMAGE_REFERENCE
            or self.init_image_index_digest != SUPPORTED_INIT_IMAGE_INDEX_DIGEST
            or self.init_image_manifest_digest
            != SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
        ):
            raise AppleContainerConfigurationError(
                "Apple fuzz init image authority differs"
            )

    @property
    def request_sha256(self) -> str:
        return _canonical_digest(self.__dict__)


@dataclass(frozen=True)
class AppleFuzzExecutionBundle:
    request_sha256: str
    launch_request: DriverLaunchRequest
    start_receipt: DriverStartReceipt
    wait_result: DriverWaitResult
    delete_receipt: OperationReceipt
    schema: str = APPLE_FUZZ_EXECUTION_BUNDLE_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != APPLE_FUZZ_EXECUTION_BUNDLE_SCHEMA
            or type(self.request_sha256) is not str
            or _HEX64.fullmatch(self.request_sha256) is None
            or type(self.launch_request) is not DriverLaunchRequest
            or type(self.start_receipt) is not DriverStartReceipt
            or type(self.wait_result) is not DriverWaitResult
            or type(self.delete_receipt) is not OperationReceipt
        ):
            raise AppleContainerProtocolError(
                "Apple fuzz execution bundle is malformed"
            )


def _fuzz_digest(value: Any, label: str) -> None:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise AppleContainerProtocolError(f"{label} is malformed")


@dataclass(frozen=True, slots=True)
class AppleNativeFuzzLaunchReceipt:
    request_sha256: str
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_policy_sha256: str
    launch_request_sha256: str
    created_receipt_sha256: str
    start_receipt_sha256: str
    driver_argv_sha256: str
    driver_environment_sha256: str
    driver_cwd_sha256: str
    driver_stdin_sha256: str
    pass_fd_roster_sha256: str
    mount_roster_sha256: str
    start_operation_nonce: str
    native_process_id: int
    native_process_handle_sha256: str
    start_monotonic_ms: int
    provider_preflight_sha256: str
    provider_provenance_sha256: str
    cli_executable_sha256: str
    guest_executable_sha256: str
    rosetta_required: bool
    schema: str = APPLE_NATIVE_FUZZ_LAUNCH_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != APPLE_NATIVE_FUZZ_LAUNCH_SCHEMA
            or type(self.native_process_id) is not int
            or self.native_process_id <= 0
            or type(self.start_monotonic_ms) is not int
            or self.start_monotonic_ms <= 0
            or type(self.rosetta_required) is not bool
            or type(self.attempt_id) is not str
            or _SAFE_RUN_ID.fullmatch(self.attempt_id) is None
        ):
            raise AppleContainerProtocolError(
                "native Apple fuzz launch receipt is malformed"
            )
        _validate_container_id(self.container_id)
        for value in (
            self.request_sha256, self.spec_sha256, self.launch_policy_sha256,
            self.launch_request_sha256, self.created_receipt_sha256,
            self.start_receipt_sha256, self.driver_argv_sha256,
            self.driver_environment_sha256, self.driver_cwd_sha256,
            self.driver_stdin_sha256, self.pass_fd_roster_sha256,
            self.mount_roster_sha256, self.start_operation_nonce,
            self.native_process_handle_sha256,
            self.provider_preflight_sha256,
            self.provider_provenance_sha256, self.cli_executable_sha256,
            self.guest_executable_sha256,
        ):
            _fuzz_digest(value, "native Apple fuzz launch digest")


@dataclass(frozen=True, slots=True)
class AppleNativeFuzzTerminalReceipt:
    request_sha256: str
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_request_sha256: str
    start_receipt_sha256: str
    terminal_receipt_sha256: str
    start_operation_nonce: str
    wait_operation_nonce: str
    revoke_operation_nonce: str
    native_process_id: int
    native_process_handle_sha256: str
    exit_code: int
    start_monotonic_ms: int
    end_monotonic_ms: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_retained_sha256: str
    stderr_retained_sha256: str
    stdout_observed_bytes: int
    stderr_observed_bytes: int
    stdout_retained_bytes: int
    stderr_retained_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    native_process_extinction_sha256: str
    cleanup_sha256: str
    stop_argv_sha256: str
    stop_stdout_sha256: str
    stop_stderr_sha256: str
    stopped_observation_sha256: str
    guest_population_extinction_sha256: str
    descendants_extinct: bool
    guest_process_extinct: bool
    backend_egress_revoked: bool
    stop_control_process_reaped: bool
    stop_control_process_group_extinct: bool
    guest_population_zero: bool
    container_vm_stopped: bool
    provider_preflight_sha256: str
    provider_provenance_sha256: str
    cli_executable_sha256: str
    guest_executable_sha256: str
    rosetta_required: bool
    schema: str = APPLE_NATIVE_FUZZ_TERMINAL_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != APPLE_NATIVE_FUZZ_TERMINAL_SCHEMA
            or type(self.native_process_id) is not int
            or self.native_process_id <= 0
            or type(self.exit_code) is not int
            or not 0 <= self.exit_code <= 255
            or type(self.start_monotonic_ms) is not int
            or type(self.end_monotonic_ms) is not int
            or self.start_monotonic_ms <= 0
            or self.end_monotonic_ms < self.start_monotonic_ms
            or type(self.rosetta_required) is not bool
            or type(self.attempt_id) is not str
            or _SAFE_RUN_ID.fullmatch(self.attempt_id) is None
            or self.descendants_extinct is not True
            or self.guest_process_extinct is not True
            or self.backend_egress_revoked is not True
            or self.stop_control_process_reaped is not True
            or self.stop_control_process_group_extinct is not True
            or self.guest_population_zero is not True
            or self.container_vm_stopped is not True
        ):
            raise AppleContainerProtocolError(
                "native Apple fuzz terminal receipt is malformed"
            )
        _validate_container_id(self.container_id)
        for observed, retained, truncated in (
            (self.stdout_observed_bytes, self.stdout_retained_bytes,
             self.stdout_truncated),
            (self.stderr_observed_bytes, self.stderr_retained_bytes,
             self.stderr_truncated),
        ):
            if (
                type(observed) is not int or type(retained) is not int
                or not 0 <= retained <= observed <= DRIVER_MAX_TOTAL_OUTPUT_BYTES
                or retained > DRIVER_MAX_OUTPUT_BYTES
                or type(truncated) is not bool
                or truncated is not (observed != retained)
            ):
                raise AppleContainerProtocolError(
                    "native Apple fuzz stream evidence is malformed"
                )
        for value in (
            self.request_sha256, self.spec_sha256,
            self.launch_request_sha256, self.start_receipt_sha256,
            self.terminal_receipt_sha256, self.start_operation_nonce,
            self.wait_operation_nonce, self.revoke_operation_nonce,
            self.native_process_handle_sha256, self.stdout_sha256,
            self.stderr_sha256, self.stdout_retained_sha256,
            self.stderr_retained_sha256,
            self.native_process_extinction_sha256, self.cleanup_sha256,
            self.stop_argv_sha256, self.stop_stdout_sha256,
            self.stop_stderr_sha256, self.stopped_observation_sha256,
            self.guest_population_extinction_sha256,
            self.provider_preflight_sha256,
            self.provider_provenance_sha256, self.cli_executable_sha256,
            self.guest_executable_sha256,
        ):
            _fuzz_digest(value, "native Apple fuzz terminal digest")
        if (
            self.start_operation_nonce == self.wait_operation_nonce
            or self.start_operation_nonce == self.revoke_operation_nonce
            or self.wait_operation_nonce == self.revoke_operation_nonce
        ):
            raise AppleContainerProtocolError(
                "native Apple fuzz operation nonces alias"
            )


@dataclass(frozen=True, slots=True)
class AppleNativeFuzzDeleteReceipt:
    request_sha256: str
    container_id: str
    spec_sha256: str
    terminal_receipt_sha256: str
    delete_receipt_sha256: str
    cleanup_sha256: str
    absence_sha256: str
    descendants_extinct: bool
    guest_process_extinct: bool
    backend_egress_revoked: bool
    absent: bool
    provider_preflight_sha256: str
    guest_executable_sha256: str
    schema: str = APPLE_NATIVE_FUZZ_DELETE_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != APPLE_NATIVE_FUZZ_DELETE_SCHEMA
            or self.descendants_extinct is not True
            or self.guest_process_extinct is not True
            or self.backend_egress_revoked is not True
            or self.absent is not True
        ):
            raise AppleContainerProtocolError(
                "native Apple fuzz delete receipt is malformed"
            )
        _validate_container_id(self.container_id)
        for value in (
            self.request_sha256, self.spec_sha256,
            self.terminal_receipt_sha256, self.delete_receipt_sha256,
            self.cleanup_sha256, self.absence_sha256,
            self.provider_preflight_sha256, self.guest_executable_sha256,
        ):
            _fuzz_digest(value, "native Apple fuzz delete digest")


@dataclass(frozen=True, slots=True)
class AppleNativeFuzzExecutionBundle:
    request_sha256: str
    launch: AppleNativeFuzzLaunchReceipt
    terminal: AppleNativeFuzzTerminalReceipt
    deleted: AppleNativeFuzzDeleteReceipt
    lifecycle_sha256: str
    native_mount_roster_sha256: str
    native_provider_admission_sha256: str
    native_provider_provenance_sha256: str
    native_spec_sha256: str
    stdout: bytes = field(repr=False)
    stderr: bytes = field(repr=False)
    schema: str = APPLE_NATIVE_FUZZ_BUNDLE_SCHEMA

    def __post_init__(self) -> None:
        if (
            self.schema != APPLE_NATIVE_FUZZ_BUNDLE_SCHEMA
            or type(self.launch) is not AppleNativeFuzzLaunchReceipt
            or type(self.terminal) is not AppleNativeFuzzTerminalReceipt
            or type(self.deleted) is not AppleNativeFuzzDeleteReceipt
            or type(self.stdout) is not bytes or type(self.stderr) is not bytes
        ):
            raise AppleContainerProtocolError(
                "native Apple fuzz execution bundle is malformed"
            )
        _fuzz_digest(self.request_sha256, "native Apple fuzz request")
        _fuzz_digest(self.lifecycle_sha256, "native Apple fuzz lifecycle")
        _fuzz_digest(self.native_mount_roster_sha256,
                     "native Apple fuzz mount roster")
        _fuzz_digest(self.native_provider_admission_sha256,
                     "native Apple fuzz provider admission")
        _fuzz_digest(self.native_provider_provenance_sha256,
                     "native Apple fuzz provider provenance")
        _fuzz_digest(self.native_spec_sha256, "native Apple fuzz spec")


def validate_apple_native_fuzz_execution_bundle(
    request: AppleFuzzExecutionRequest,
    bundle: AppleNativeFuzzExecutionBundle,
) -> None:
    """Authenticate the exact native create/start/stop/delete projection."""

    if type(request) is not AppleFuzzExecutionRequest or type(
        bundle
    ) is not AppleNativeFuzzExecutionBundle:
        raise AppleContainerProtocolError(
            "native Apple fuzz execution bundle is malformed"
        )
    launch, terminal, deleted = bundle.launch, bundle.terminal, bundle.deleted
    common = (
        bundle.request_sha256 == request.request_sha256
        and launch.request_sha256 == request.request_sha256
        and terminal.request_sha256 == request.request_sha256
        and deleted.request_sha256 == request.request_sha256
        and launch.container_id == request.container_id
        and terminal.container_id == request.container_id
        and deleted.container_id == request.container_id
        and launch.attempt_id == request.attempt_id
        and terminal.attempt_id == request.attempt_id
        and launch.spec_sha256 == bundle.native_spec_sha256
        and terminal.spec_sha256 == bundle.native_spec_sha256
        and deleted.spec_sha256 == bundle.native_spec_sha256
        and launch.launch_policy_sha256 == request.launch_policy_sha256
        and terminal.launch_request_sha256 == launch.launch_request_sha256
        and terminal.start_receipt_sha256 == launch.start_receipt_sha256
        and deleted.terminal_receipt_sha256
            == terminal.terminal_receipt_sha256
        and terminal.native_process_id == launch.native_process_id
        and terminal.native_process_handle_sha256
            == launch.native_process_handle_sha256
        and terminal.start_operation_nonce == launch.start_operation_nonce
        and terminal.start_monotonic_ms == launch.start_monotonic_ms
        and launch.mount_roster_sha256 == bundle.native_mount_roster_sha256
    )
    for observed in (launch, terminal):
        common = common and (
            observed.provider_preflight_sha256
                == request.provider_preflight_sha256
            and observed.provider_provenance_sha256
                == request.provider_provenance_sha256
            and observed.cli_executable_sha256
                == request.cli_executable_sha256
            and observed.guest_executable_sha256
                == request.guest_executable_sha256
            and observed.rosetta_required is request.rosetta_required
        )
    common = common and (
        deleted.provider_preflight_sha256 == request.provider_preflight_sha256
        and deleted.guest_executable_sha256
            == request.guest_executable_sha256
        and terminal.descendants_extinct is True
        and terminal.guest_process_extinct is True
        and terminal.backend_egress_revoked is True
        and terminal.stop_control_process_reaped is True
        and terminal.stop_control_process_group_extinct is True
        and terminal.guest_population_zero is True
        and terminal.container_vm_stopped is True
        and deleted.descendants_extinct is True
        and deleted.guest_process_extinct is True
        and deleted.backend_egress_revoked is True
        and deleted.absent is True
    )
    if not common:
        raise AppleContainerMismatchError(
            "native Apple fuzz receipt binding differs"
        )
    if (
        len(bundle.stdout) != terminal.stdout_retained_bytes
        or len(bundle.stderr) != terminal.stderr_retained_bytes
        or hashlib.sha256(bundle.stdout).hexdigest()
            != terminal.stdout_retained_sha256
        or hashlib.sha256(bundle.stderr).hexdigest()
            != terminal.stderr_retained_sha256
        or (
            terminal.stdout_observed_bytes == len(bundle.stdout)
            and terminal.stdout_sha256 != terminal.stdout_retained_sha256
        )
        or (
            terminal.stderr_observed_bytes == len(bundle.stderr)
            and terminal.stderr_sha256 != terminal.stderr_retained_sha256
        )
    ):
        raise AppleContainerMismatchError(
            "native Apple fuzz retained output differs"
        )


def validate_apple_fuzz_execution_bundle(
    request: AppleFuzzExecutionRequest,
    bundle: AppleFuzzExecutionBundle,
) -> None:
    """Authenticate a complete start/wait/VM-stop/delete execution chain."""

    if type(request) is not AppleFuzzExecutionRequest or type(
        bundle
    ) is not AppleFuzzExecutionBundle:
        raise AppleContainerProtocolError("Apple fuzz execution bundle is malformed")
    launch = bundle.launch_request
    start = bundle.start_receipt
    wait = bundle.wait_result.receipt
    deleted = bundle.delete_receipt
    expected_argv_sha256 = _canonical_digest(list(request.guest_argv))
    expected_environment_sha256 = _canonical_digest(list(request.guest_environment))
    expected_cwd_sha256 = _canonical_digest(request.guest_cwd)
    expected_stdin_sha256 = _canonical_digest("DEVNULL")
    expected_pass_fds_sha256 = _canonical_digest([])
    if (
        bundle.request_sha256 != request.request_sha256
        or launch.container_id != request.container_id
        or launch.attempt_id != request.attempt_id
        or launch.spec_sha256 != request.spec_sha256
        or launch.launch_policy_sha256 != request.launch_policy_sha256
        or launch.driver_argv_sha256 != expected_argv_sha256
        or launch.driver_environment_sha256 != expected_environment_sha256
        or launch.driver_cwd_sha256 != expected_cwd_sha256
        or launch.driver_stdin_sha256 != expected_stdin_sha256
        or launch.pass_fd_roster_sha256 != expected_pass_fds_sha256
        or launch.rosetta_required is not request.rosetta_required
        or start.container_id != launch.container_id
        or start.attempt_id != launch.attempt_id
        or start.spec_sha256 != launch.spec_sha256
        or start.launch_request_sha256 != launch.request_sha256
        or start.launch_policy_sha256 != launch.launch_policy_sha256
        or start.driver_argv_sha256 != launch.driver_argv_sha256
        or start.driver_environment_sha256 != launch.driver_environment_sha256
        or start.driver_cwd_sha256 != launch.driver_cwd_sha256
        or start.driver_stdin_sha256 != launch.driver_stdin_sha256
        or start.pass_fd_roster_sha256 != launch.pass_fd_roster_sha256
        or start.cli_executable_sha256 != request.cli_executable_sha256
        or start.provider_provenance_sha256
        != request.provider_provenance_sha256
        or start.rosetta_required is not request.rosetta_required
        or wait.container_id != start.container_id
        or wait.attempt_id != start.attempt_id
        or wait.spec_sha256 != start.spec_sha256
        or wait.launch_request_sha256 != launch.request_sha256
        or wait.start_receipt_sha256 != start.receipt_sha256
        or wait.launch_policy_sha256 != start.launch_policy_sha256
        or wait.driver_argv_sha256 != start.driver_argv_sha256
        or wait.driver_environment_sha256 != start.driver_environment_sha256
        or wait.driver_cwd_sha256 != start.driver_cwd_sha256
        or wait.driver_stdin_sha256 != start.driver_stdin_sha256
        or wait.pass_fd_roster_sha256 != start.pass_fd_roster_sha256
        or wait.native_process_id != start.native_process_id
        or wait.native_process_handle_sha256
        != start.native_process_handle_sha256
        or wait.cli_executable_sha256 != request.cli_executable_sha256
        or wait.provider_provenance_sha256
        != request.provider_provenance_sha256
        or wait.rosetta_required is not request.rosetta_required
        or wait.descendants_extinct is not True
        or wait.guest_process_extinct is not True
        or wait.backend_egress_revoked is not True
        or wait.stop_control_process_reaped is not True
        or wait.stop_control_process_group_extinct is not True
        or wait.guest_population_zero is not True
        or wait.container_vm_stopped is not True
        or any(type(value) is not str or _HEX64.fullmatch(value) is None
               for value in (
                   wait.stop_argv_sha256, wait.stop_stdout_sha256,
                   wait.stop_stderr_sha256, wait.stopped_observation_sha256,
                   wait.guest_population_extinction_sha256,
               ))
        or deleted.operation != "delete"
        or deleted.container_id != request.container_id
        or deleted.spec_sha256 != request.spec_sha256
        or deleted.observed_state != "absent"
        or deleted.stdout_truncated is not False
        or deleted.stderr_truncated is not False
        or deleted.init_image_reference != request.init_image_reference
        or deleted.init_image_index_digest != request.init_image_index_digest
        or deleted.init_image_manifest_digest
        != request.init_image_manifest_digest
        or deleted.rosetta_required is not request.rosetta_required
        or any(type(value) is not str or _HEX64.fullmatch(value) is None
               for value in (deleted.stdout_sha256, deleted.stderr_sha256))
    ):
        raise AppleContainerProtocolError(
            "Apple fuzz start/wait/stop/delete authority differs"
        )


@dataclass(frozen=True)
class _AuthorityCallbacks:
    owner: object
    open_executable: Callable[[str, str], object]
    post_fstat_executable: Callable[[object], None]
    close_executable: Callable[[object], None]
    invoke: Callable[..., RunnerResult]
    journal_load: Callable[[str], MutationRecord | None]
    journal_begin: Callable[[MutationRecord, MutationRecord | None], MutationRecord]
    journal_complete: Callable[[MutationRecord, str], MutationRecord]
    image_load: Callable[[str], ImageAdmissionRecord | None]
    image_save: Callable[[ImageAdmissionRecord, ImageAdmissionRecord | None], ImageAdmissionRecord]
    mount_open: Callable[[MountSpec], object]
    mount_revalidate: Callable[[object], None]
    mount_close: Callable[[object], None]
    driver_start: Callable[..., object] | None = None
    driver_wait: Callable[..., RunnerResult] | None = None
    driver_recover_process: Callable[..., object | None] | None = None
    driver_recover_wait: Callable[..., RunnerResult | None] | None = None
    driver_revoke: Callable[[object], None] | None = None
    driver_journal_load: Callable[[str, str], DriverLifecycleRecord | None] | None = None
    driver_journal_cas: Callable[
        [DriverLifecycleRecord, DriverLifecycleRecord | None], DriverLifecycleRecord
    ] | None = None


@dataclass
class _ExecutableFacts:
    owner: object
    path: str
    sha256: str
    device: int
    inode: int
    size: int
    mode: int
    descriptor_held: bool
    capability: object | None = None
    used: bool = False
    postchecked: bool = False
    closed: bool = False


@dataclass
class _MountFacts:
    owner: object
    source: str
    target: str
    readonly: bool
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    link_count: int
    size: int
    kind: str
    component_chain_sha256: str
    component_identities: tuple[str, ...]
    content_sha256: str
    descriptor_nofollow: bool
    filesystem_alias_free: bool
    recursive_metadata_complete: bool
    symlink_entries_absent: bool
    special_entries_absent: bool
    hardlink_entries_absent: bool
    cross_filesystem_entries_absent: bool
    sensitive_entries_absent: bool
    socket_entries_absent: bool
    compressed_entries_absent: bool
    archive_members_validated: bool
    oci_layout_sha256: str | None
    oci_index_digest: str | None
    oci_index_media_type: str | None
    oci_manifest_digest: str | None
    oci_manifest_media_type: str | None
    oci_configuration_sha256: str | None
    xattr_names: tuple[str, ...]
    xattr_showcompression_used: bool
    filesystem_root_alias: bool
    oci_layout_receipt_sha256: str | None = None
    capability: object | None = None
    revalidations: int = 0
    closed: bool = False


@dataclass(frozen=True)
class _InvocationEvidence:
    owner: object
    result: RunnerResult
    executable_capability: object
    mount_capabilities: tuple[object, ...]
    mounted_identity_sha256: str | None
    provenance: tuple[str, ...]
    descendants_extinct: bool
    network_policy_enforced: bool
    network_accessed: bool
    registry_accessed: bool
    image_fetch_performed: bool
    guest_network_policy_sha256: str | None
    guest_network_topology_sha256: str | None
    guest_network_policy_enforced: bool
    guest_network_internal: bool
    guest_network_attempt_owned: bool
    guest_network_no_dns: bool
    guest_network_ipv6_absent: bool
    guest_network_object_verified: bool
    guest_network_attachment_verified: bool
    guest_network_name: str | None
    guest_network_ipv4_subnet: str | None
    guest_network_ipv4_gateway: str | None
    guest_network_ipv4_address: str | None
    guest_network_mac_address: str | None
    guest_network_attachment_variant: str | None
    guest_network_labels: tuple[tuple[str, str], ...]
    guest_network_plugin: str | None
    init_image_reference: str | None
    init_image_index_digest: str | None
    init_image_manifest_digest: str | None
    init_image_verified: bool


@dataclass
class _DriverProcessFacts:
    owner: object
    capability: object
    command: tuple[str, ...]
    executable_capability: object
    mount_capabilities: tuple[object, ...]
    mounted_identity_sha256: str
    provenance: tuple[str, ...]
    container_id: str
    attempt_id: str
    spec_sha256: str
    launch_request_sha256: str
    launch_policy_sha256: str
    driver_argv_sha256: str
    driver_environment_sha256: str
    driver_cwd_sha256: str
    driver_stdin_sha256: str
    pass_fd_roster_sha256: str
    start_operation_nonce: str
    native_process_id: str
    native_process_handle_sha256: str
    start_timestamp: str
    rosetta_required: bool
    native_process_retained: bool
    stdout_pipe_bound: bool
    stderr_pipe_bound: bool
    stdin_devnull: bool
    guest_network_policy_sha256: str
    guest_network_topology_sha256: str
    guest_network_policy_enforced: bool
    creator_pid: int
    delivered: bool = False
    consumed: bool = False
    revoked: bool = False
    native_process_extinct: bool = False
    guest_process_extinct: bool = False
    backend_egress_revoked: bool = False
    cleanup_sha256: str | None = None
    native_process_extinction_sha256: str | None = None
    stop_argv_sha256: str | None = None
    stop_stdout_sha256: str | None = None
    stop_stderr_sha256: str | None = None
    stopped_observation_sha256: str | None = None
    guest_population_extinction_sha256: str | None = None
    stop_control_process_reaped: bool = False
    stop_control_process_group_extinct: bool = False
    guest_population_zero: bool = False
    container_vm_stopped: bool = False


@dataclass(frozen=True)
class _DriverWaitEvidence:
    owner: object
    result: RunnerResult
    process_capability: object
    native_process_handle_sha256: str
    wait_operation_nonce: str
    start_timestamp: str
    end_timestamp: str
    native_process_extinction_sha256: str
    cleanup_sha256: str
    stop_argv_sha256: str
    stop_stdout_sha256: str
    stop_stderr_sha256: str
    stopped_observation_sha256: str
    guest_population_extinction_sha256: str
    descendants_extinct: bool
    guest_process_extinct: bool
    backend_egress_revoked: bool
    stop_control_process_reaped: bool
    stop_control_process_group_extinct: bool
    guest_population_zero: bool
    container_vm_stopped: bool


@dataclass
class _MountLease:
    capabilities: tuple[object, ...]
    identity_sha256: str
    closed: bool = False


_TEST_ONLY_AUTHORITY_REGISTRY: dict[int, _AuthorityCallbacks] = {}
_TEST_ONLY_EXECUTABLE_REGISTRY: dict[int, _ExecutableFacts] = {}
_TEST_ONLY_MOUNT_REGISTRY: dict[int, _MountFacts] = {}
_TEST_ONLY_INVOCATION_REGISTRY: dict[int, _InvocationEvidence] = {}
_TEST_ONLY_DRIVER_PROCESS_REGISTRY: dict[int, _DriverProcessFacts] = {}
_TEST_ONLY_DRIVER_WAIT_REGISTRY: dict[int, _DriverWaitEvidence] = {}
_REGISTRY_LOCK = threading.RLock()
_REGISTRY_PID = os.getpid()


def _invalidate_registries_after_fork() -> None:
    """Drop every inherited Python-side authority in the child process."""
    global _REGISTRY_LOCK, _REGISTRY_PID
    _TEST_ONLY_AUTHORITY_REGISTRY.clear()
    _TEST_ONLY_EXECUTABLE_REGISTRY.clear()
    _TEST_ONLY_MOUNT_REGISTRY.clear()
    _TEST_ONLY_INVOCATION_REGISTRY.clear()
    _TEST_ONLY_DRIVER_PROCESS_REGISTRY.clear()
    _TEST_ONLY_DRIVER_WAIT_REGISTRY.clear()
    _REGISTRY_LOCK = threading.RLock()
    _REGISTRY_PID = os.getpid()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_invalidate_registries_after_fork)


class _OpaqueCapability:
    __slots__ = ()


class _OpaqueDriverProcessCapability:
    __slots__ = ()


def TEST_ONLY_register_same_process_authority(
    authority: object, *, open_executable: Callable[[str, str], object],
    post_fstat_executable: Callable[[object], None],
    close_executable: Callable[[object], None], invoke: Callable[..., RunnerResult],
    journal_load: Callable[[str], MutationRecord | None],
    journal_begin: Callable[[MutationRecord, MutationRecord | None], MutationRecord],
    journal_complete: Callable[[MutationRecord, str], MutationRecord],
    image_load: Callable[[str], ImageAdmissionRecord | None],
    image_save: Callable[[ImageAdmissionRecord, ImageAdmissionRecord | None], ImageAdmissionRecord],
    mount_open: Callable[[MountSpec], object], mount_revalidate: Callable[[object], None],
    mount_close: Callable[[object], None],
    driver_start: Callable[..., object] | None = None,
    driver_wait: Callable[..., RunnerResult] | None = None,
    driver_recover_process: Callable[..., object | None] | None = None,
    driver_recover_wait: Callable[..., RunnerResult | None] | None = None,
    driver_revoke: Callable[[object], None] | None = None,
    driver_journal_load: Callable[[str, str], DriverLifecycleRecord | None] | None = None,
    driver_journal_cas: Callable[
        [DriverLifecycleRecord, DriverLifecycleRecord | None], DriverLifecycleRecord
    ] | None = None,
) -> None:
    """Trusted-bootstrap hook; captures exact callbacks once for this process.

    The callback return values are evidence contracts, not native proofs.  A
    production implementation must derive them from held descriptors, signed
    receipts, durable authenticated storage, provider inspection, and enforced
    host policy.  Tests in this module family intentionally use fake callbacks.
    """
    callbacks = (open_executable, post_fstat_executable, close_executable, invoke,
                 journal_load, journal_begin, journal_complete, image_load, image_save,
                 mount_open, mount_revalidate, mount_close)
    if authority is None or not all(callable(item) for item in callbacks):
        raise AppleContainerConfigurationError("authority callbacks are incomplete")
    with _REGISTRY_LOCK:
        if id(authority) in _TEST_ONLY_AUTHORITY_REGISTRY:
            raise AppleContainerConfigurationError("authority is already registered")
        _TEST_ONLY_AUTHORITY_REGISTRY[id(authority)] = _AuthorityCallbacks(
            authority, *callbacks, driver_start, driver_wait,
            driver_recover_process, driver_recover_wait, driver_revoke,
            driver_journal_load, driver_journal_cas,
        )


def _issue_executable_capability(
    owner: object, *, path: str, sha256: str, device: int,
    inode: int, size: int, mode: int, descriptor_held: bool,
) -> object:
    capability = _OpaqueCapability()
    facts = _ExecutableFacts(owner, path, sha256, device, inode, size, mode, descriptor_held)
    facts.capability = capability
    with _REGISTRY_LOCK:
        _TEST_ONLY_EXECUTABLE_REGISTRY[id(capability)] = facts
    return capability


def _mark_executable_post_fstat(owner: object, capability: object, *, unchanged: bool) -> None:
    with _REGISTRY_LOCK:
        facts = _TEST_ONLY_EXECUTABLE_REGISTRY.get(id(capability))
        if (facts is None or facts.owner is not owner or facts.capability is not capability
                or unchanged is not True or facts.closed):
            raise AppleContainerUnavailableError("executable post-launch identity is unproven")
        facts.postchecked = True


def _mark_executable_closed(owner: object, capability: object) -> None:
    with _REGISTRY_LOCK:
        facts = _TEST_ONLY_EXECUTABLE_REGISTRY.get(id(capability))
        if facts is None or facts.owner is not owner or facts.capability is not capability:
            raise AppleContainerUnavailableError("executable capability close is unproven")
        facts.closed = True


def _issue_mount_capability(
    owner: object, *, source: str, target: str, readonly: bool,
    device: int, inode: int, mode: int, uid: int, gid: int, link_count: int, size: int,
    kind: str, component_chain_sha256: str, content_sha256: str,
    component_identities: tuple[str, ...],
    descriptor_nofollow: bool, filesystem_alias_free: bool,
    recursive_metadata_complete: bool, symlink_entries_absent: bool,
    special_entries_absent: bool, hardlink_entries_absent: bool,
    cross_filesystem_entries_absent: bool,
    sensitive_entries_absent: bool, socket_entries_absent: bool,
    compressed_entries_absent: bool,
    archive_members_validated: bool, oci_layout_sha256: str | None,
    oci_index_digest: str | None, oci_index_media_type: str | None,
    oci_manifest_digest: str | None, oci_manifest_media_type: str | None,
    oci_configuration_sha256: str | None,
    xattr_names: tuple[str, ...],
    xattr_showcompression_used: bool, filesystem_root_alias: bool = False,
    oci_layout_receipt_sha256: str | None = None,
) -> object:
    capability = _OpaqueCapability()
    facts = _MountFacts(owner, source, target, readonly, device, inode, mode, uid, gid,
                        link_count, size, kind, component_chain_sha256,
                        component_identities, content_sha256,
                        descriptor_nofollow, filesystem_alias_free,
                        recursive_metadata_complete, symlink_entries_absent,
                        special_entries_absent, hardlink_entries_absent,
                        cross_filesystem_entries_absent,
                        sensitive_entries_absent, socket_entries_absent,
                        compressed_entries_absent, archive_members_validated,
                        oci_layout_sha256, oci_index_digest, oci_index_media_type,
                        oci_manifest_digest, oci_manifest_media_type,
                        oci_configuration_sha256, xattr_names,
                        xattr_showcompression_used, filesystem_root_alias)
    facts.oci_layout_receipt_sha256 = oci_layout_receipt_sha256
    facts.capability = capability
    with _REGISTRY_LOCK:
        _TEST_ONLY_MOUNT_REGISTRY[id(capability)] = facts
    return capability


def _mark_mount_revalidated(owner: object, capability: object, *, unchanged: bool) -> None:
    with _REGISTRY_LOCK:
        facts = _TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
        if (facts is None or facts.owner is not owner or facts.capability is not capability
                or unchanged is not True or facts.closed):
            raise AppleContainerUnavailableError("mount identity changed before invocation")
        facts.revalidations += 1


def _mark_mount_closed(owner: object, capability: object) -> None:
    with _REGISTRY_LOCK:
        facts = _TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
        if facts is None or facts.owner is not owner or facts.capability is not capability:
            raise AppleContainerUnavailableError("mount capability close is unproven")
        facts.closed = True


def _issue_invocation_evidence(
    owner: object, result: RunnerResult, *, executable_capability: object,
    mount_capabilities: tuple[object, ...], provenance: tuple[str, ...],
    mounted_identity_sha256: str | None,
    descendants_extinct: bool, network_policy_enforced: bool,
    network_accessed: bool = False, registry_accessed: bool = False,
    image_fetch_performed: bool = False,
    guest_network_policy_sha256: str | None = None,
    guest_network_topology_sha256: str | None = None,
    guest_network_policy_enforced: bool = False,
    guest_network_internal: bool = False,
    guest_network_attempt_owned: bool = False,
    guest_network_no_dns: bool = False,
    guest_network_ipv6_absent: bool = False,
    guest_network_object_verified: bool = False,
    guest_network_attachment_verified: bool = False,
    guest_network_name: str | None = None,
    guest_network_ipv4_subnet: str | None = None,
    guest_network_ipv4_gateway: str | None = None,
    guest_network_ipv4_address: str | None = None,
    guest_network_mac_address: str | None = None,
    guest_network_attachment_variant: str | None = None,
    guest_network_labels: tuple[tuple[str, str], ...] = (),
    guest_network_plugin: str | None = None,
    init_image_reference: str | None = None,
    init_image_index_digest: str | None = None,
    init_image_manifest_digest: str | None = None,
    init_image_verified: bool = False,
) -> None:
    evidence = _InvocationEvidence(
        owner, result, executable_capability, mount_capabilities,
        mounted_identity_sha256, provenance,
        descendants_extinct, network_policy_enforced, network_accessed,
        registry_accessed, image_fetch_performed, guest_network_policy_sha256,
        guest_network_topology_sha256, guest_network_policy_enforced,
        guest_network_internal, guest_network_attempt_owned, guest_network_no_dns,
        guest_network_ipv6_absent, guest_network_object_verified,
        guest_network_attachment_verified,
        guest_network_name, guest_network_ipv4_subnet, guest_network_ipv4_gateway,
        guest_network_ipv4_address, guest_network_mac_address,
        guest_network_attachment_variant,
        guest_network_labels, guest_network_plugin,
        init_image_reference, init_image_index_digest,
        init_image_manifest_digest, init_image_verified,
    )
    with _REGISTRY_LOCK:
        if id(result) in _TEST_ONLY_INVOCATION_REGISTRY:
            raise AppleContainerUnavailableError("invocation evidence identity collided")
        _TEST_ONLY_INVOCATION_REGISTRY[id(result)] = evidence


def _issue_driver_process_capability(
    owner: object, *, command: tuple[str, ...], executable_capability: object,
    mount_capabilities: tuple[object, ...], mounted_identity_sha256: str,
    provenance: tuple[str, ...], container_id: str, attempt_id: str,
    spec_sha256: str, launch_request_sha256: str, launch_policy_sha256: str,
    driver_argv_sha256: str, driver_environment_sha256: str,
    driver_cwd_sha256: str, driver_stdin_sha256: str,
    pass_fd_roster_sha256: str,
    start_operation_nonce: str, native_process_id: str,
    native_process_handle_sha256: str, start_timestamp: str,
    rosetta_required: bool, native_process_retained: bool,
    stdout_pipe_bound: bool, stderr_pipe_bound: bool, stdin_devnull: bool,
    guest_network_policy_sha256: str,
    guest_network_topology_sha256: str,
    guest_network_policy_enforced: bool,
) -> object:
    """TEST/bootstrap seam for registering native-issued process evidence."""
    capability = _OpaqueDriverProcessCapability()
    facts = _DriverProcessFacts(
        owner, capability, command, executable_capability, mount_capabilities,
        mounted_identity_sha256, provenance, container_id, attempt_id,
        spec_sha256, launch_request_sha256, launch_policy_sha256,
        driver_argv_sha256, driver_environment_sha256, driver_cwd_sha256,
        driver_stdin_sha256, pass_fd_roster_sha256,
        start_operation_nonce, native_process_id, native_process_handle_sha256,
        start_timestamp, rosetta_required, native_process_retained,
        stdout_pipe_bound, stderr_pipe_bound, stdin_devnull,
        guest_network_policy_sha256, guest_network_topology_sha256,
        guest_network_policy_enforced, os.getpid(),
    )
    with _REGISTRY_LOCK:
        if id(capability) in _TEST_ONLY_DRIVER_PROCESS_REGISTRY:
            raise AppleContainerUnavailableError("driver process capability identity collided")
        _TEST_ONLY_DRIVER_PROCESS_REGISTRY[id(capability)] = facts
    return capability


def _driver_process_facts(capability: object) -> _DriverProcessFacts | None:
    with _REGISTRY_LOCK:
        facts = _TEST_ONLY_DRIVER_PROCESS_REGISTRY.get(id(capability))
    if (facts is None or facts.capability is not capability
            or facts.creator_pid != os.getpid()):
        return None
    return facts


def _issue_driver_wait_evidence(
    owner: object, result: RunnerResult, *, process_capability: object,
    native_process_handle_sha256: str, wait_operation_nonce: str,
    start_timestamp: str, end_timestamp: str,
    native_process_extinction_sha256: str, cleanup_sha256: str,
    stop_argv_sha256: str, stop_stdout_sha256: str,
    stop_stderr_sha256: str, stopped_observation_sha256: str,
    guest_population_extinction_sha256: str,
    descendants_extinct: bool, guest_process_extinct: bool,
    backend_egress_revoked: bool,
    stop_control_process_reaped: bool,
    stop_control_process_group_extinct: bool,
    guest_population_zero: bool, container_vm_stopped: bool,
) -> None:
    evidence = _DriverWaitEvidence(
        owner=owner, result=result, process_capability=process_capability,
        native_process_handle_sha256=native_process_handle_sha256,
        wait_operation_nonce=wait_operation_nonce,
        start_timestamp=start_timestamp, end_timestamp=end_timestamp,
        native_process_extinction_sha256=native_process_extinction_sha256,
        cleanup_sha256=cleanup_sha256, stop_argv_sha256=stop_argv_sha256,
        stop_stdout_sha256=stop_stdout_sha256,
        stop_stderr_sha256=stop_stderr_sha256,
        stopped_observation_sha256=stopped_observation_sha256,
        guest_population_extinction_sha256=guest_population_extinction_sha256,
        descendants_extinct=descendants_extinct,
        guest_process_extinct=guest_process_extinct,
        backend_egress_revoked=backend_egress_revoked,
        stop_control_process_reaped=stop_control_process_reaped,
        stop_control_process_group_extinct=stop_control_process_group_extinct,
        guest_population_zero=guest_population_zero,
        container_vm_stopped=container_vm_stopped,
    )
    with _REGISTRY_LOCK:
        if id(result) in _TEST_ONLY_DRIVER_WAIT_REGISTRY:
            raise AppleContainerUnavailableError("driver wait evidence identity collided")
        _TEST_ONLY_DRIVER_WAIT_REGISTRY[id(result)] = evidence


def _mark_driver_process_revoked(
    owner: object, capability: object, *, native_process_extinct: bool,
    guest_process_extinct: bool, backend_egress_revoked: bool,
    cleanup_sha256: str, native_process_extinction_sha256: str,
    stop_argv_sha256: str, stop_stdout_sha256: str,
    stop_stderr_sha256: str, stopped_observation_sha256: str,
    guest_population_extinction_sha256: str,
    stop_control_process_reaped: bool,
    stop_control_process_group_extinct: bool,
    guest_population_zero: bool, container_vm_stopped: bool,
) -> None:
    facts = _driver_process_facts(capability)
    if (facts is None or facts.owner is not owner or facts.revoked
            or native_process_extinct is not True
            or guest_process_extinct is not True
            or backend_egress_revoked is not True
            or stop_control_process_reaped is not True
            or stop_control_process_group_extinct is not True
            or guest_population_zero is not True
            or container_vm_stopped is not True
            or not isinstance(cleanup_sha256, str)
            or _HEX64.fullmatch(cleanup_sha256) is None
            or not isinstance(native_process_extinction_sha256, str)
            or _HEX64.fullmatch(native_process_extinction_sha256) is None
            or any(not isinstance(value, str) or _HEX64.fullmatch(value) is None
                   for value in (stop_argv_sha256, stop_stdout_sha256,
                                 stop_stderr_sha256,
                                 stopped_observation_sha256,
                                 guest_population_extinction_sha256))):
        raise AppleContainerUnavailableError("driver process revocation is unproven")
    facts.revoked = True
    facts.native_process_extinct = True
    facts.guest_process_extinct = True
    facts.backend_egress_revoked = True
    facts.cleanup_sha256 = cleanup_sha256
    facts.native_process_extinction_sha256 = native_process_extinction_sha256
    facts.stop_argv_sha256 = stop_argv_sha256
    facts.stop_stdout_sha256 = stop_stdout_sha256
    facts.stop_stderr_sha256 = stop_stderr_sha256
    facts.stopped_observation_sha256 = stopped_observation_sha256
    facts.guest_population_extinction_sha256 = guest_population_extinction_sha256
    facts.stop_control_process_reaped = True
    facts.stop_control_process_group_extinct = True
    facts.guest_population_zero = True
    facts.container_vm_stopped = True


@dataclass(frozen=True)
class _InspectedContainer:
    container_id: str
    state: str
    matches: bool
    observation_sha256: str
    configuration_sha256: str
    mismatch_code: str | None


def _validate_public_text(value: Any, label: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise AppleContainerConfigurationError(f"{label} is invalid")
    if unicodedata.normalize("NFC", value) != value:
        raise AppleContainerConfigurationError(f"{label} is not NFC canonical")
    if any(ord(character) < 0x20 or ord(character) == 0x7f for character in value):
        raise AppleContainerConfigurationError(f"{label} contains a control character")


def _validate_absolute_path(value: Any, label: str, *, posix: bool) -> None:
    _validate_public_text(value, label, maximum=MAX_SINGLE_ARG_BYTES)
    if value.startswith("//"):
        raise AppleContainerConfigurationError(f"{label} is not canonical")
    pieces = value.split("/")
    if any(piece in {"", ".", ".."} for piece in pieces[1:]):
        raise AppleContainerConfigurationError(f"{label} is not canonical")
    if posix:
        path = PurePosixPath(value)
        if not path.is_absolute() or str(path) != value:
            raise AppleContainerConfigurationError(f"{label} is not canonical")
    elif not os.path.isabs(value) or os.path.normpath(value) != value:
        raise AppleContainerConfigurationError(f"{label} is not canonical")


def _validate_mount_source_policy(value: str) -> None:
    folded = tuple(unicodedata.normalize("NFKC", part).casefold()
                   for part in value.split("/") if part)
    if (value == "/System/Volumes/Data" or value.startswith("/System/Volumes/Data/")
            or value in {"/tmp", "/var", "/etc", "/private/tmp", "/private/var",
                         "/private/etc"}
            or value.startswith(("/tmp/", "/var/", "/etc/", "/private/tmp/",
                                 "/private/var/", "/private/etc/"))):
        raise AppleContainerConfigurationError("mount source uses a macOS filesystem alias")
    lowered = "/" + "/".join(folded)
    if (any(part in _SENSITIVE_PATH_COMPONENTS or "keychain" in part for part in folded)
            or lowered.endswith((".sock", "/ssh-agent"))
            or "/com.apple.launchd." in lowered
            or "/ssh-" in lowered
            or "/containerd" in lowered):
        raise AppleContainerConfigurationError("mount source names sensitive host material")


def _looks_sensitive(value: str) -> bool:
    normalized = "".join(character for character in value.upper() if character.isalnum())
    return any(fragment in normalized for fragment in _SENSITIVE)


def _validate_oci_reference(reference: str) -> None:
    name, separator, _digest = reference.partition("@")
    if separator != "@" or "//" in name or name.startswith(("/", ".")):
        raise AppleContainerConfigurationError("image reference is not canonical")
    parts = name.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise AppleContainerConfigurationError("image reference is not canonical")
    first = parts[0]
    if ":" in first:
        host, port = first.rsplit(":", 1)
        if (not port.isdigit() or port.startswith("0")
                or not 1 <= int(port) <= 65535):
            raise AppleContainerConfigurationError("image registry port is invalid")
    else:
        host = first
    if "." in host and any(not label or label.startswith("-") or label.endswith("-")
                           for label in host.split(".")):
        raise AppleContainerConfigurationError("image registry host is not canonical")


def _validate_environment(environment: Sequence[str]) -> None:
    seen: set[str] = set()
    for entry in environment:
        if not isinstance(entry, str) or "=" not in entry:
            raise AppleContainerConfigurationError("expected image environment is malformed")
        name, value = entry.split("=", 1)
        if (_ENV_NAME.fullmatch(name) is None or name.casefold() in seen
                or _looks_sensitive(name) or _looks_sensitive(value)
                or len(entry.encode("utf-8")) > MAX_SINGLE_ARG_BYTES
                or unicodedata.normalize("NFC", entry) != entry
                or any(character in entry for character in ("\x00", "\n", "\r"))):
            raise AppleContainerConfigurationError("expected image environment is unsafe")
        seen.add(name.casefold())


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _driver_record_payload(record: DriverLifecycleRecord) -> dict[str, Any]:
    return {
        key: (value.value if isinstance(value, Enum) else value)
        for key, value in record.__dict__.items()
        if key != "journal_checkpoint_sha256"
    }


def _driver_record(**values: Any) -> DriverLifecycleRecord:
    provisional = DriverLifecycleRecord.__new__(DriverLifecycleRecord)
    for field_name in DriverLifecycleRecord.__dataclass_fields__:
        object.__setattr__(
            provisional, field_name,
            values.get(field_name, "0" * 64)
            if field_name == "journal_checkpoint_sha256"
            else values[field_name],
        )
    checkpoint = _canonical_digest(_driver_record_payload(provisional))
    values["journal_checkpoint_sha256"] = checkpoint
    return DriverLifecycleRecord(**values)


def _validate_driver_record(record: DriverLifecycleRecord) -> None:
    if (record.schema != "plamen.apple-container.driver-lifecycle.v2"
            or type(record.state) is not DriverLifecycleState
            or not isinstance(record.attempt_id, str)
            or _SAFE_RUN_ID.fullmatch(record.attempt_id) is None
            or type(record.rosetta_required) is not bool):
        raise AppleContainerProtocolError("driver lifecycle journal is malformed")
    _validate_container_id(record.container_id)
    for value in (
        record.spec_sha256, record.launch_request_sha256,
        record.launch_policy_sha256, record.driver_argv_sha256,
        record.driver_environment_sha256, record.driver_cwd_sha256,
        record.driver_stdin_sha256, record.pass_fd_roster_sha256,
        record.cli_executable_sha256,
        record.provider_provenance_sha256, record.journal_checkpoint_sha256,
    ):
        if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
            raise AppleContainerProtocolError("driver lifecycle journal digest is malformed")
    if (not isinstance(record.start_operation_nonce, str)
            or _HEX32.fullmatch(record.start_operation_nonce) is None
            or (record.wait_operation_nonce is not None
                and (not isinstance(record.wait_operation_nonce, str)
                     or _HEX32.fullmatch(record.wait_operation_nonce) is None))):
        raise AppleContainerProtocolError("driver lifecycle journal nonce is malformed")
    if record.journal_checkpoint_sha256 != _canonical_digest(
        _driver_record_payload(record)
    ):
        raise AppleContainerProtocolError("driver lifecycle checkpoint differs")

    start_effect = record.state not in {
        DriverLifecycleState.START_ARMED,
        DriverLifecycleState.START_CLAIMED,
    }
    wait_armed = record.state in {
        DriverLifecycleState.WAIT_ARMED,
        DriverLifecycleState.WAIT_CLAIMED,
        DriverLifecycleState.WAIT_EFFECT,
        DriverLifecycleState.WAIT_COMMITTED,
    }
    wait_effect = record.state in {
        DriverLifecycleState.WAIT_EFFECT,
        DriverLifecycleState.WAIT_COMMITTED,
    }
    start_aborted = record.state is DriverLifecycleState.START_ABORTED
    if start_effect:
        if (not isinstance(record.native_process_id, str)
                or _SAFE_RUN_ID.fullmatch(record.native_process_id) is None
                or not isinstance(record.native_process_handle_sha256, str)
                or _HEX64.fullmatch(record.native_process_handle_sha256) is None
                or not isinstance(record.start_timestamp, str)
                or not isinstance(record.start_effect_sha256, str)
                or _HEX64.fullmatch(record.start_effect_sha256) is None):
            raise AppleContainerProtocolError("driver start effect journal is malformed")
        _timestamp(record.start_timestamp, "driver start timestamp")
    elif any(value is not None for value in (
        record.native_process_id, record.native_process_handle_sha256,
        record.start_timestamp, record.start_effect_sha256,
    )):
        raise AppleContainerProtocolError(
            "driver start pre-effect journal contains effect evidence"
        )
    abort_values = (
        record.start_abort_extinction_sha256,
        record.start_abort_cleanup_sha256,
        record.start_abort_egress_revoked,
    )
    if start_aborted:
        if (
            not isinstance(record.start_abort_extinction_sha256, str)
            or _HEX64.fullmatch(record.start_abort_extinction_sha256) is None
            or not isinstance(record.start_abort_cleanup_sha256, str)
            or _HEX64.fullmatch(record.start_abort_cleanup_sha256) is None
            or record.start_abort_egress_revoked is not True
        ):
            raise AppleContainerProtocolError("driver start abort journal is malformed")
    elif any(value is not None for value in abort_values):
        raise AppleContainerProtocolError("driver journal contains premature start abort")
    if wait_armed is not (record.wait_operation_nonce is not None):
        raise AppleContainerProtocolError("driver wait arm journal is malformed")
    if wait_armed:
        if (record.wait_operation_nonce == record.start_operation_nonce
                or not isinstance(record.start_receipt_sha256, str)
                or _HEX64.fullmatch(record.start_receipt_sha256) is None
                or not isinstance(record.start_journal_checkpoint_sha256, str)
                or _HEX64.fullmatch(record.start_journal_checkpoint_sha256) is None):
            raise AppleContainerProtocolError("driver wait lacks its start commitment")
        if _start_receipt_from_record(record).receipt_sha256 != record.start_receipt_sha256:
            raise AppleContainerProtocolError(
                "driver wait start commitment differs"
            )
    elif (record.start_receipt_sha256 is not None
          or record.start_journal_checkpoint_sha256 is not None):
        raise AppleContainerProtocolError("driver start journal has premature wait binding")

    result_values = (
        record.end_timestamp, record.exit_code, record.stdout_sha256,
        record.stderr_sha256, record.stdout_retained_sha256,
        record.stderr_retained_sha256, record.stdout_observed_bytes,
        record.stderr_observed_bytes, record.stdout_retained_bytes,
        record.stderr_retained_bytes, record.stdout_truncated,
        record.stderr_truncated, record.native_process_extinction_sha256,
        record.cleanup_sha256, record.descendants_extinct,
        record.guest_process_extinct, record.backend_egress_revoked,
        record.stop_argv_sha256, record.stop_stdout_sha256,
        record.stop_stderr_sha256, record.stopped_observation_sha256,
        record.guest_population_extinction_sha256,
        record.stop_control_process_reaped,
        record.stop_control_process_group_extinct,
        record.guest_population_zero, record.container_vm_stopped,
        record.wait_effect_sha256,
    )
    if not wait_effect:
        if any(value is not None for value in result_values):
            raise AppleContainerProtocolError("driver journal contains premature wait evidence")
        return
    if (not isinstance(record.end_timestamp, str)
            or type(record.exit_code) is not int
            or not 0 <= record.exit_code <= 255
            or record.descendants_extinct is not True
            or record.guest_process_extinct is not True
            or record.backend_egress_revoked is not True
            or record.stop_control_process_reaped is not True
            or record.stop_control_process_group_extinct is not True
            or record.guest_population_zero is not True
            or record.container_vm_stopped is not True):
        raise AppleContainerProtocolError("driver wait effect journal is malformed")
    _timestamp(record.end_timestamp, "driver end timestamp")
    if (_timestamp_value(record.end_timestamp, "driver end timestamp")
            < _timestamp_value(record.start_timestamp, "driver start timestamp")):
        raise AppleContainerProtocolError("driver end timestamp precedes its start")
    for value in (
        record.stdout_sha256, record.stderr_sha256,
        record.stdout_retained_sha256, record.stderr_retained_sha256,
        record.native_process_extinction_sha256, record.cleanup_sha256,
        record.stop_argv_sha256, record.stop_stdout_sha256,
        record.stop_stderr_sha256, record.stopped_observation_sha256,
        record.guest_population_extinction_sha256,
        record.wait_effect_sha256,
    ):
        if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
            raise AppleContainerProtocolError("driver wait effect digest is malformed")
    for observed, retained, truncated, full_digest, retained_digest in (
        (record.stdout_observed_bytes, record.stdout_retained_bytes,
         record.stdout_truncated, record.stdout_sha256,
         record.stdout_retained_sha256),
        (record.stderr_observed_bytes, record.stderr_retained_bytes,
         record.stderr_truncated, record.stderr_sha256,
         record.stderr_retained_sha256),
    ):
        if (type(observed) is not int or type(retained) is not int
                or not 0 <= retained <= DRIVER_MAX_OUTPUT_BYTES
                or not retained <= observed <= DRIVER_MAX_TOTAL_OUTPUT_BYTES
                or type(truncated) is not bool
                or truncated is not (observed != retained)
                or (not truncated and full_digest != retained_digest)):
                raise AppleContainerProtocolError("driver wait effect stream evidence is malformed")


def _transition_driver_record(
    record: DriverLifecycleRecord, state: DriverLifecycleState, **changes: Any,
) -> DriverLifecycleRecord:
    values = dict(record.__dict__)
    values.pop("journal_checkpoint_sha256", None)
    values.update(changes)
    values["state"] = state
    return _driver_record(**values)


def _validate_launch_for_spec(spec: ContainerSpec, request: DriverLaunchRequest) -> None:
    if (type(request) is not DriverLaunchRequest
            or request.container_id != spec.name
            or request.attempt_id != spec.audit_attempt_id
            or request.spec_sha256 != spec.fingerprint
            or request.rosetta_required is not spec.rosetta_required
            or request.driver_argv_sha256
               != _canonical_digest([spec.entrypoint, *spec.arguments])
            or request.driver_environment_sha256
               != _canonical_digest(list(spec.expected_environment))
            or request.driver_cwd_sha256
               != _canonical_digest(spec.working_directory)
            or request.driver_stdin_sha256 != _canonical_digest("DEVNULL")
            or request.pass_fd_roster_sha256 != _canonical_digest([])):
        raise AppleContainerMismatchError(
            "driver launch request differs from the admitted container process"
        )


def _timestamp_value(value: str, label: str) -> datetime:
    _timestamp(value, label)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except (TypeError, ValueError, OverflowError):
        raise AppleContainerProtocolError(f"{label} is malformed") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _driver_start_effect_sha256(facts: _DriverProcessFacts) -> str:
    return _canonical_digest({
        "attempt_id": facts.attempt_id,
        "cli_executable_sha256": facts.provenance[4],
        "command": list(facts.command),
        "container_id": facts.container_id,
        "guest_network_policy_sha256": facts.guest_network_policy_sha256,
        "guest_network_topology_sha256": facts.guest_network_topology_sha256,
        "driver_argv_sha256": facts.driver_argv_sha256,
        "driver_cwd_sha256": facts.driver_cwd_sha256,
        "driver_environment_sha256": facts.driver_environment_sha256,
        "driver_stdin_sha256": facts.driver_stdin_sha256,
        "launch_policy_sha256": facts.launch_policy_sha256,
        "launch_request_sha256": facts.launch_request_sha256,
        "mounted_identity_sha256": facts.mounted_identity_sha256,
        "native_process_handle_sha256": facts.native_process_handle_sha256,
        "native_process_id": facts.native_process_id,
        "rosetta_required": facts.rosetta_required,
        "pass_fd_roster_sha256": facts.pass_fd_roster_sha256,
        "spec_sha256": facts.spec_sha256,
        "start_operation_nonce": facts.start_operation_nonce,
        "start_timestamp": facts.start_timestamp,
    })


def _start_receipt_from_record(record: DriverLifecycleRecord) -> DriverStartReceipt:
    checkpoint = (
        record.start_journal_checkpoint_sha256
        if record.start_journal_checkpoint_sha256 is not None
        else record.journal_checkpoint_sha256
    )
    if any(value is None for value in (
        record.native_process_id, record.native_process_handle_sha256,
        record.start_timestamp, record.start_effect_sha256,
    )):
        raise AppleContainerProtocolError("driver start record is incomplete")
    return DriverStartReceipt(
        "plamen.apple-container.driver-start.v1", record.container_id,
        record.attempt_id, record.spec_sha256, record.launch_request_sha256,
        record.launch_policy_sha256, record.driver_argv_sha256,
        record.driver_environment_sha256, record.driver_cwd_sha256,
        record.driver_stdin_sha256, record.pass_fd_roster_sha256,
        record.start_operation_nonce, 1,
        record.native_process_id,  # type: ignore[arg-type]
        record.native_process_handle_sha256,  # type: ignore[arg-type]
        record.cli_executable_sha256,
        record.provider_provenance_sha256,
        record.start_timestamp,  # type: ignore[arg-type]
        record.start_effect_sha256,  # type: ignore[arg-type]
        checkpoint, record.rosetta_required,
    )


def _driver_wait_effect_sha256(
    record: DriverLifecycleRecord, result: RunnerResult,
    evidence: _DriverWaitEvidence,
) -> str:
    return _canonical_digest({
        "attempt_id": record.attempt_id,
        "backend_egress_revoked": evidence.backend_egress_revoked,
        "cleanup_sha256": evidence.cleanup_sha256,
        "container_id": record.container_id,
        "descendants_extinct": evidence.descendants_extinct,
        "guest_process_extinct": evidence.guest_process_extinct,
        "guest_population_zero": evidence.guest_population_zero,
        "container_vm_stopped": evidence.container_vm_stopped,
        "stop_control_process_reaped": evidence.stop_control_process_reaped,
        "stop_control_process_group_extinct":
            evidence.stop_control_process_group_extinct,
        "stop_argv_sha256": evidence.stop_argv_sha256,
        "stop_stdout_sha256": evidence.stop_stdout_sha256,
        "stop_stderr_sha256": evidence.stop_stderr_sha256,
        "stopped_observation_sha256": evidence.stopped_observation_sha256,
        "guest_population_extinction_sha256":
            evidence.guest_population_extinction_sha256,
        "end_timestamp": evidence.end_timestamp,
        "exit_code": result.returncode,
        "native_process_extinction_sha256":
            evidence.native_process_extinction_sha256,
        "native_process_handle_sha256": record.native_process_handle_sha256,
        "stderr_observed_bytes": result.stderr_observed_bytes,
        "stderr_retained_bytes": len(result.stderr),
        "stderr_retained_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_sha256": result.stderr_full_sha256,
        "stdout_observed_bytes": result.stdout_observed_bytes,
        "stdout_retained_bytes": len(result.stdout),
        "stdout_retained_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout_sha256": result.stdout_full_sha256,
        "wait_operation_nonce": record.wait_operation_nonce,
    })


def _wait_result_from_record(
    record: DriverLifecycleRecord, result: RunnerResult,
) -> DriverWaitResult:
    if record.start_receipt_sha256 is None:
        raise AppleContainerProtocolError("driver wait lacks its start receipt")
    receipt = DriverWaitReceipt(
        "plamen.apple-container.driver-wait.v2", record.container_id,
        record.attempt_id, record.spec_sha256, record.launch_request_sha256,
        record.start_receipt_sha256, record.launch_policy_sha256,
        record.driver_argv_sha256, record.driver_environment_sha256,
        record.driver_cwd_sha256, record.driver_stdin_sha256,
        record.pass_fd_roster_sha256,
        record.start_operation_nonce,
        record.wait_operation_nonce,  # type: ignore[arg-type]
        2, record.native_process_id,  # type: ignore[arg-type]
        record.native_process_handle_sha256,  # type: ignore[arg-type]
        record.cli_executable_sha256,
        record.provider_provenance_sha256,
        record.exit_code,  # type: ignore[arg-type]
        record.stdout_sha256, record.stderr_sha256,  # type: ignore[arg-type]
        record.stdout_retained_sha256,  # type: ignore[arg-type]
        record.stderr_retained_sha256,  # type: ignore[arg-type]
        record.stdout_observed_bytes, record.stderr_observed_bytes,  # type: ignore[arg-type]
        record.stdout_retained_bytes, record.stderr_retained_bytes,  # type: ignore[arg-type]
        record.stdout_truncated, record.stderr_truncated,  # type: ignore[arg-type]
        record.start_timestamp, record.end_timestamp,  # type: ignore[arg-type]
        record.native_process_extinction_sha256,  # type: ignore[arg-type]
        record.cleanup_sha256,  # type: ignore[arg-type]
        record.stop_argv_sha256, record.stop_stdout_sha256,  # type: ignore[arg-type]
        record.stop_stderr_sha256,  # type: ignore[arg-type]
        record.stopped_observation_sha256,  # type: ignore[arg-type]
        record.guest_population_extinction_sha256,  # type: ignore[arg-type]
        record.descendants_extinct, record.guest_process_extinct,  # type: ignore[arg-type]
        record.backend_egress_revoked,  # type: ignore[arg-type]
        record.stop_control_process_reaped,  # type: ignore[arg-type]
        record.stop_control_process_group_extinct,  # type: ignore[arg-type]
        record.guest_population_zero, record.container_vm_stopped,  # type: ignore[arg-type]
        record.journal_checkpoint_sha256, record.rosetta_required,
    )
    return DriverWaitResult(receipt, result.stdout, result.stderr)


def _strict_json(result: RunnerResult, label: str) -> Any:
    if result.stdout_observed_bytes > MAX_JSON_BYTES:
        raise AppleContainerProtocolError(f"{label} exceeds the JSON byte budget")
    if result.stdout_observed_bytes != len(result.stdout):
        raise AppleContainerProtocolError(f"{label} JSON was truncated")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in items:
            if key in output:
                raise AppleContainerProtocolError(f"{label} contains a duplicate JSON key")
            output[key] = value
        return output

    def bounded_integer(token: str) -> int:
        if len(token) > 20:
            raise AppleContainerProtocolError(f"{label} contains an oversized integer")
        try:
            return int(token)
        except ValueError:
            raise AppleContainerProtocolError(f"{label} contains an invalid integer") from None

    def reject_float(_token: str) -> None:
        raise AppleContainerProtocolError(f"{label} contains an unsupported number")

    try:
        document = json.loads(
            result.stdout.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
            parse_int=bounded_integer, parse_float=reject_float,
            parse_constant=lambda _token: (_ for _ in ()).throw(
                AppleContainerProtocolError(f"{label} contains a non-finite number")
            ),
        )
    except AppleContainerProtocolError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise AppleContainerProtocolError(f"{label} is not valid JSON") from None
    stack = [(document, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > 100_000 or depth > 64:
            raise AppleContainerProtocolError(f"{label} exceeds the JSON shape budget")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and (not math.isfinite(current) or not current.is_integer()):
            raise AppleContainerProtocolError(f"{label} contains an unsupported number")
        elif isinstance(current, int) and not isinstance(current, bool) and abs(current) > 2**63 - 1:
            raise AppleContainerProtocolError(f"{label} contains an oversized integer")
    return document


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise AppleContainerProtocolError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise AppleContainerProtocolError(f"{label} must be an array")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise AppleContainerProtocolError(f"{label} must be a string")
    return value


def _status_host_path(value: Any, label: str) -> str:
    """Validate a provider-returned host path without disclosing it in errors."""
    raw = _string(value, label)
    normalized = raw[:-1] if len(raw) > 1 and raw.endswith("/") else raw
    try:
        _validate_absolute_path(normalized, label, posix=False)
    except AppleContainerConfigurationError:
        raise AppleContainerProtocolError(f"{label} is not canonical") from None
    if normalized == "/":
        raise AppleContainerProtocolError(f"{label} is not canonical")
    return normalized


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AppleContainerProtocolError(f"{label} must be a bounded integer")
    return value


def _timestamp(value: Any, label: str) -> str:
    raw = _string(value, label)
    if len(raw.encode("utf-8")) > 128 or _RFC3339_UTC.fullmatch(raw) is None:
        raise AppleContainerProtocolError(f"{label} must be a canonical UTC timestamp")
    return raw


class TEST_ONLY_AppleContainerProvider:
    """In-process semantic lifecycle harness; never production authority."""

    def __init__(
        self, *, executable: Path = DEFAULT_EXECUTABLE,
        executable_sha256: str | None = None,
        version_pin: AppleContainerVersionPin | None = None,
        authority: object | None = None,
        host_probe: Callable[[], HostPlatform] = probe_host_platform,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        output_limit_bytes: int = DEFAULT_OUTPUT_LIMIT_BYTES,
    ) -> None:
        try:
            executable = Path(executable)
        except (TypeError, ValueError, OSError):
            raise AppleContainerConfigurationError(
                "container executable path is invalid"
            ) from None
        if not executable.is_absolute() or executable != DEFAULT_EXECUTABLE:
            raise AppleContainerConfigurationError(
                "container executable must use the package-installed path"
            )
        if (not isinstance(executable_sha256, str)
                or _HEX64.fullmatch(executable_sha256) is None
                or executable_sha256 == "0" * 64):
            raise AppleContainerConfigurationError(
                "container executable observation is malformed"
            )
        if (version_pin is not None
                and executable_sha256 != version_pin.cli_executable_sha256):
            raise AppleContainerConfigurationError(
                "container executable differs from authenticated observation"
            )
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int)
                or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS):
            raise AppleContainerConfigurationError("provider timeout bound is invalid")
        if (isinstance(output_limit_bytes, bool) or not isinstance(output_limit_bytes, int)
                or not 1024 <= output_limit_bytes <= MAX_JSON_BYTES):
            raise AppleContainerConfigurationError("provider output bound is invalid")
        self._executable = str(executable)
        self._executable_sha256 = executable_sha256
        self._version_pin = version_pin
        self._authority = authority
        self._host_probe = host_probe
        self._timeout = timeout_seconds
        self._output_limit = output_limit_bytes
        self._creator_pid = os.getpid()
        self._creator_interpreter_token = (id(sys), id(sys.modules))
        self._callbacks: _AuthorityCallbacks | None = None
        self._preflight: PreflightReceipt | None = None
        self._lock = threading.RLock()

    def _guard_process(self) -> None:
        if (
            self._creator_pid != os.getpid()
            or self._creator_interpreter_token != (id(sys), id(sys.modules))
            or _REGISTRY_PID != os.getpid()
        ):
            raise AppleContainerUnavailableError(
                "provider authority cannot cross a process or interpreter boundary"
            )

    def _acquire_callbacks(self) -> _AuthorityCallbacks:
        self._guard_process()
        if self._authority is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        with _REGISTRY_LOCK:
            callbacks = _TEST_ONLY_AUTHORITY_REGISTRY.get(id(self._authority))
        if callbacks is None or callbacks.owner is not self._authority:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        return callbacks

    def _open_executable(self) -> tuple[object, _ExecutableFacts]:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        try:
            capability = self._callbacks.open_executable(
                self._executable, self._executable_sha256
            )
        except Exception:
            raise AppleContainerUnavailableError("container executable is unavailable") from None
        with _REGISTRY_LOCK:
            facts = _TEST_ONLY_EXECUTABLE_REGISTRY.get(id(capability))
        invalid = (facts is None or facts.owner is not self._authority
                or facts.capability is not capability
                or facts.path != self._executable or facts.sha256 != self._executable_sha256
                or facts.descriptor_held is not True or facts.used or facts.closed
                or facts.size < 1 or facts.size > 128 * 1024 * 1024
                or any(isinstance(value, bool) or not isinstance(value, int) or value < 0
                       for value in (facts.device, facts.inode, facts.size, facts.mode)))
        if invalid:
            try:
                self._callbacks.close_executable(capability)
                closed = _TEST_ONLY_EXECUTABLE_REGISTRY.get(id(capability))
                if (closed is None or closed.owner is not self._authority
                        or closed.capability is not capability or not closed.closed):
                    raise AppleContainerAmbiguousError(
                        "invalid executable capability revocation is unproven"
                    )
            except Exception:
                raise AppleContainerAmbiguousError(
                    "invalid executable capability revocation is unproven"
                ) from None
            with _REGISTRY_LOCK:
                _TEST_ONLY_EXECUTABLE_REGISTRY.pop(id(capability), None)
            raise AppleContainerUnavailableError("executable descriptor authority is invalid")
        if facts is None:  # Kept explicit so optimized Python cannot remove the guard.
            raise AppleContainerUnavailableError("executable descriptor authority is invalid")
        return capability, facts

    def _open_mounts(self, mounts: Sequence[MountSpec]) -> tuple[tuple[object, ...], tuple[_MountFacts, ...]]:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        capabilities: list[object] = []
        facts_list: list[_MountFacts] = []
        try:
            for mount in sorted(mounts, key=lambda item: item.target):
                capability = self._callbacks.mount_open(mount)
                capabilities.append(capability)
                with _REGISTRY_LOCK:
                    facts = _TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
                is_image_archive = mount.target == "/.plamen/image-archive"
                if (facts is None or facts.owner is not self._authority
                        or facts.capability is not capability
                        or facts.source != mount.source or facts.target != mount.target
                        or facts.readonly is not mount.readonly or facts.closed
                        or not isinstance(facts.kind, str)
                        or facts.kind not in {"file", "directory"}
                        or not isinstance(facts.component_chain_sha256, str)
                        or _HEX64.fullmatch(facts.component_chain_sha256) is None
                        or not isinstance(facts.component_identities, tuple)
                        or not facts.component_identities
                        or len(facts.component_identities)
                           != len(tuple(item for item in mount.source.split("/") if item))
                        or any(not isinstance(item, str) or _HEX64.fullmatch(item) is None
                               for item in facts.component_identities)
                        or facts.component_chain_sha256
                           != _canonical_digest(list(facts.component_identities))
                        or not isinstance(facts.content_sha256, str)
                        or _HEX64.fullmatch(facts.content_sha256) is None
                        or facts.descriptor_nofollow is not True
                        or facts.filesystem_alias_free is not True
                        or facts.recursive_metadata_complete is not True
                        or facts.symlink_entries_absent is not True
                        or facts.special_entries_absent is not True
                        or facts.hardlink_entries_absent is not True
                        or facts.cross_filesystem_entries_absent is not True
                        or facts.sensitive_entries_absent is not True
                        or facts.socket_entries_absent is not True
                        or facts.compressed_entries_absent is not True
                        or facts.archive_members_validated is not is_image_archive
                        or (is_image_archive and (
                            not isinstance(facts.oci_layout_sha256, str)
                            or _HEX64.fullmatch(facts.oci_layout_sha256) is None
                            or not isinstance(facts.oci_index_digest, str)
                            or _SHA256.fullmatch(facts.oci_index_digest) is None
                            or facts.oci_index_media_type != OCI_IMAGE_INDEX_MEDIA_TYPE
                            or not isinstance(facts.oci_manifest_digest, str)
                            or _SHA256.fullmatch(facts.oci_manifest_digest) is None
                            or facts.oci_manifest_media_type != OCI_IMAGE_MANIFEST_MEDIA_TYPE
                            or not isinstance(facts.oci_configuration_sha256, str)
                            or _HEX64.fullmatch(facts.oci_configuration_sha256) is None))
                        or (not is_image_archive and any(value is not None for value in (
                            facts.oci_layout_sha256, facts.oci_index_digest,
                            facts.oci_index_media_type, facts.oci_manifest_digest,
                            facts.oci_manifest_media_type,
                            facts.oci_configuration_sha256,
                            facts.oci_layout_receipt_sha256,
                        )))
                        or facts.xattr_names != ()
                        or facts.xattr_showcompression_used is not True
                        or facts.filesystem_root_alias is not False
                        or any(isinstance(value, bool) or not isinstance(value, int)
                               or value < 0 or value > 2**63 - 1
                               for value in (facts.device, facts.inode, facts.mode, facts.uid,
                                             facts.gid, facts.link_count, facts.size))
                        or facts.link_count < 1
                        or (facts.kind == "file" and facts.link_count != 1)):
                    raise AppleContainerUnavailableError("mount identity authority is invalid")
                facts_list.append(facts)
            if len({id(item) for item in capabilities}) != len(capabilities):
                raise AppleContainerUnavailableError("mount capabilities collide")
            roots = tuple((item.device, item.inode) for item in facts_list)
            if len(set(roots)) != len(roots):
                raise AppleContainerUnavailableError("mount sources alias by object identity")
            chains = tuple(item.component_identities for item in facts_list)
            for index, left in enumerate(chains):
                for right in chains[index + 1:]:
                    shared = min(len(left), len(right))
                    if left[:shared] == right[:shared]:
                        raise AppleContainerUnavailableError(
                            "mount sources alias or overlap by descriptor identity"
                        )
            return tuple(capabilities), tuple(facts_list)
        except Exception:
            cleanup_failed = False
            for capability in capabilities:
                try:
                    self._close_mount(capability)
                except AppleContainerProviderError:
                    cleanup_failed = True
            if cleanup_failed:
                raise AppleContainerAmbiguousError(
                    "mount authority failed and capability revocation is unproven"
                ) from None
            raise AppleContainerUnavailableError("mount authority could not admit a source") from None

    def _revalidate_mounts(self, capabilities: tuple[object, ...]) -> None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        for capability in capabilities:
            with _REGISTRY_LOCK:
                before_facts = _TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
            if (before_facts is None or before_facts.capability is not capability):
                raise AppleContainerUnavailableError(
                    "mount revalidation evidence is unavailable"
                )
            before = before_facts.revalidations
            try:
                self._callbacks.mount_revalidate(capability)
            except Exception:
                raise AppleContainerUnavailableError("mount identity changed before invocation") from None
            facts = _TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
            if (facts is None or facts.owner is not self._authority
                    or facts.capability is not capability or facts.closed
                    or facts.revalidations != before + 1):
                raise AppleContainerUnavailableError("mount revalidation evidence is unavailable")

    def _close_mount(self, capability: object) -> None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerAmbiguousError("mount capability revocation is unavailable")
        try:
            self._callbacks.mount_close(capability)
            facts = _TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
            if (facts is None or facts.owner is not self._authority
                    or facts.capability is not capability or not facts.closed):
                raise AppleContainerUnavailableError("mount capability was not revoked")
        except Exception:
            raise AppleContainerAmbiguousError("mount capability was not revoked") from None
        else:
            with _REGISTRY_LOCK:
                _TEST_ONLY_MOUNT_REGISTRY.pop(id(capability), None)

    def _close_all_mounts(self, capabilities: Sequence[object]) -> None:
        self._guard_process()
        failed = False
        for capability in capabilities:
            try:
                self._close_mount(capability)
            except AppleContainerProviderError:
                failed = True
        if failed:
            raise AppleContainerAmbiguousError("one or more mount capabilities were not revoked")

    @staticmethod
    def _mount_facts_digest(facts: Sequence[_MountFacts]) -> str:
        return _canonical_digest([
            {"component_chain_sha256": item.component_chain_sha256,
             "component_identities": list(item.component_identities),
             "compressed_entries_absent": item.compressed_entries_absent,
             "archive_members_validated": item.archive_members_validated,
             "oci_layout_sha256": item.oci_layout_sha256,
             "oci_index_digest": item.oci_index_digest,
             "oci_index_media_type": item.oci_index_media_type,
             "oci_manifest_digest": item.oci_manifest_digest,
             "oci_manifest_media_type": item.oci_manifest_media_type,
             "oci_configuration_sha256": item.oci_configuration_sha256,
             "content_sha256": item.content_sha256 if item.readonly else None,
             "descriptor_nofollow": item.descriptor_nofollow,
             "device": item.device, "filesystem_alias_free": item.filesystem_alias_free,
             "gid": item.gid, "inode": item.inode, "kind": item.kind,
             "link_count": item.link_count if item.readonly else None,
             "mode": item.mode,
             "readonly": item.readonly,
             "recursive_metadata_complete": item.recursive_metadata_complete,
             "symlink_entries_absent": item.symlink_entries_absent,
             "special_entries_absent": item.special_entries_absent,
             "hardlink_entries_absent": item.hardlink_entries_absent,
             "cross_filesystem_entries_absent": item.cross_filesystem_entries_absent,
             "sensitive_entries_absent": item.sensitive_entries_absent,
             "socket_entries_absent": item.socket_entries_absent,
             "size": item.size if item.readonly else None,
             "source": item.source, "target": item.target,
             "uid": item.uid, "xattr_names": [], "xattr_showcompression_used": True}
            for item in facts
        ])

    def _lease_facts(self, lease: _MountLease) -> tuple[_MountFacts, ...]:
        self._guard_process()
        if lease.closed:
            raise AppleContainerUnavailableError("mount lease is no longer active")
        with _REGISTRY_LOCK:
            facts = tuple(_TEST_ONLY_MOUNT_REGISTRY.get(id(capability))
                          for capability in lease.capabilities)
        if any(item is None or item.owner is not self._authority or item.closed
               or item.capability is not capability
               for item, capability in zip(facts, lease.capabilities)):
            raise AppleContainerUnavailableError("mount lease identity is unavailable")
        return facts  # type: ignore[return-value]

    def _revalidate_lease(self, lease: _MountLease) -> None:
        self._guard_process()
        self._revalidate_mounts(lease.capabilities)
        if self._mount_facts_digest(self._lease_facts(lease)) != lease.identity_sha256:
            raise AppleContainerUnavailableError("mount lease identity changed")

    def _open_mount_lease(self, mounts: Sequence[MountSpec]) -> _MountLease:
        self._guard_process()
        capabilities, facts = self._open_mounts(mounts)
        lease = _MountLease(capabilities, self._mount_facts_digest(facts))
        try:
            self._revalidate_lease(lease)
            return lease
        except Exception:
            try:
                self._close_all_mounts(capabilities)
            finally:
                lease.closed = True
            raise

    def _close_mount_lease(self, lease: _MountLease) -> None:
        self._guard_process()
        if lease.closed:
            raise AppleContainerAmbiguousError("mount lease was already revoked")
        try:
            self._close_all_mounts(lease.capabilities)
        finally:
            lease.closed = True

    def _mount_digest(self, spec: ContainerSpec) -> str:
        self._guard_process()
        lease = self._open_mount_lease(spec.mounts)
        try:
            return lease.identity_sha256
        finally:
            self._close_mount_lease(lease)

    def _invoke(
        self, arguments: Sequence[str], *, operation: str,
        mount_lease: _MountLease | None = None, deny_network: bool,
        guest_network: NetworkSpec | None = None,
        create_spec: ContainerSpec | None = None,
        create_record: MutationRecord | None = None,
        require_preflight: bool = True, timeout_seconds: int | None = None,
        output_limit: int | None = None,
    ) -> RunnerResult:
        self._guard_process()
        if require_preflight and self._preflight is None:
            raise AppleContainerUnavailableError("provider has not passed preflight")
        if self._callbacks is None or self._version_pin is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        argv = tuple(arguments)
        _validate_argv(
            argv, operation, create_spec=create_spec, create_record=create_record
        )
        timeout = self._timeout if timeout_seconds is None else timeout_seconds
        bound = self._output_limit if output_limit is None else output_limit
        if (isinstance(timeout, bool) or not isinstance(timeout, int)
                or not 1 <= timeout <= MAX_TIMEOUT_SECONDS
                or isinstance(bound, bool) or not isinstance(bound, int)
                or not 1024 <= bound <= MAX_JSON_BYTES):
            raise AppleContainerConfigurationError("invocation bounds are invalid")
        mount_caps = mount_lease.capabilities if mount_lease is not None else ()
        executable_cap: object | None = None
        invocation_started = False
        try:
            if mount_lease is not None:
                self._revalidate_lease(mount_lease)
            executable_cap, executable_facts = self._open_executable()
            executable_facts.used = True
            invocation_started = True
            result = self._callbacks.invoke(
                argv, executable_capability=executable_cap,
                mount_capabilities=mount_caps, timeout=timeout,
                output_limit=bound, deny_network=deny_network,
            )
            with _REGISTRY_LOCK:
                evidence = _TEST_ONLY_INVOCATION_REGISTRY.pop(id(result), None)
            if not isinstance(result, RunnerResult):
                raise AppleContainerProtocolError("native runner returned an invalid result")
            if (evidence is None or evidence.owner is not self._authority
                    or evidence.result is not result
                    or evidence.executable_capability is not executable_cap
                    or len(evidence.mount_capabilities) != len(mount_caps)
                    or any(actual is not expected for actual, expected in
                           zip(evidence.mount_capabilities, mount_caps))
                    or (mount_lease is not None
                        and evidence.mounted_identity_sha256 != mount_lease.identity_sha256)
                    or evidence.provenance != self._version_pin.provenance
                    or evidence.descendants_extinct is not True
                    or (deny_network and (evidence.network_policy_enforced is not True
                                         or evidence.network_accessed is not False
                                         or evidence.registry_accessed is not False
                                         or evidence.image_fetch_performed is not False))
                    or (guest_network is not None
                        and (evidence.guest_network_policy_enforced is not True
                             or evidence.guest_network_internal is not True
                             or evidence.guest_network_attempt_owned is not True
                             or evidence.guest_network_no_dns is not True
                             or evidence.guest_network_ipv6_absent is not True
                             or evidence.guest_network_object_verified is not True
                             or evidence.guest_network_attachment_verified is not True
                             or evidence.guest_network_policy_sha256
                             != guest_network.policy_sha256
                             or evidence.guest_network_topology_sha256
                             != guest_network.topology_sha256
                             or evidence.guest_network_name != guest_network.name
                             or evidence.guest_network_ipv4_subnet
                             != guest_network.ipv4_subnet
                             or evidence.guest_network_ipv4_gateway
                             != guest_network.ipv4_gateway
                             or evidence.guest_network_ipv4_address
                             != guest_network.ipv4_address
                             or evidence.guest_network_mac_address
                             != guest_network.mac_address
                             or evidence.guest_network_attachment_variant
                             != guest_network.attachment_variant
                             or evidence.guest_network_labels
                             != tuple(sorted(guest_network.labels))
                             or evidence.guest_network_plugin != guest_network.plugin))
                    or (create_spec is not None
                        and (evidence.init_image_verified is not True
                             or evidence.init_image_reference
                             != create_spec.init_image_reference
                             or evidence.init_image_index_digest
                             != create_spec.init_image_digest
                             or evidence.init_image_manifest_digest
                             != create_spec.init_image_manifest_digest))):
                raise AppleContainerUnavailableError(
                    "invocation lacks exact descriptor/extinction/provenance evidence"
                )
            if len(result.stdout) > bound or len(result.stderr) > bound:
                raise AppleContainerProtocolError("native runner violated the output bound")
            if result.returncode != 0:
                raise AppleContainerUnavailableError(f"container {operation} failed")
            if mount_lease is not None:
                self._revalidate_lease(mount_lease)
            return result
        except AppleContainerProviderError:
            raise
        except Exception:
            raise AppleContainerUnavailableError(f"container {operation} could not execute") from None
        finally:
            close_failed = False
            if executable_cap is not None:
                try:
                    before = _TEST_ONLY_EXECUTABLE_REGISTRY[id(executable_cap)]
                    self._callbacks.post_fstat_executable(executable_cap)
                    if not before.postchecked:
                        close_failed = True
                    self._callbacks.close_executable(executable_cap)
                    facts = _TEST_ONLY_EXECUTABLE_REGISTRY.get(id(executable_cap))
                    if (facts is None or facts.owner is not self._authority
                            or facts.capability is not executable_cap or not facts.closed):
                        close_failed = True
                except Exception:
                    close_failed = True
                if not close_failed:
                    with _REGISTRY_LOCK:
                        _TEST_ONLY_EXECUTABLE_REGISTRY.pop(id(executable_cap), None)
            if close_failed and invocation_started:
                raise AppleContainerAmbiguousError(
                    "native executable capability cleanup is unproven"
                ) from None

    def preflight(self) -> PreflightReceipt:
        self._guard_process()
        with self._lock:
            if self._preflight is not None:
                return self._preflight
            try:
                host = self._host_probe()
            except Exception:
                raise AppleContainerUnavailableError("host platform probe failed") from None
            if (not isinstance(host, HostPlatform)
                    or not isinstance(host.system, str)
                    or not isinstance(host.architecture, str)
                    or not isinstance(host.version, tuple) or len(host.version) != 3
                    or any(isinstance(item, bool) or not isinstance(item, int)
                           or not 0 <= item <= 999 for item in host.version)):
                raise AppleContainerUnavailableError("host platform evidence is invalid")
            if (host.system != "Darwin" or host.architecture not in {"arm64", "arm64e"}
                    or host.version < (26, 0, 0)):
                raise AppleContainerUnavailableError("Apple container requires arm64 macOS 26 or newer")
            if self._version_pin is None:
                raise AppleContainerUnavailableError(
                    "authenticated installed-version provenance is required"
                )
            self._callbacks = self._acquire_callbacks()
            version_result = self._invoke(
                ("system", "version", "--format", "json"), operation="system-version",
                deny_network=True, require_preflight=False, output_limit=MAX_JSON_BYTES,
            )
            rows = _list(_strict_json(version_result, "container system version"),
                         "container system version")
            parsed: dict[str, Mapping[str, Any]] = {}
            for value in rows:
                row = _mapping(value, "container version row")
                if set(row) != {"appName", "buildType", "commit", "version"}:
                    raise AppleContainerProtocolError("container version row has an unknown schema")
                name = _string(row.get("appName"), "container version appName")
                if name in parsed:
                    raise AppleContainerProtocolError("container version components collide")
                parsed[name] = row
            if set(parsed) != {"container", "container-apiserver"}:
                raise AppleContainerUnavailableError("CLI and API-server identities are required")
            self._verify_versions(parsed)
            status_result = self._invoke(
                ("system", "status", "--format", "json"), operation="system-status",
                deny_network=True, require_preflight=False, output_limit=MAX_JSON_BYTES,
            )
            status = _mapping(_strict_json(status_result, "container system status"),
                              "container system status")
            required_status_fields = {
                "status", "appRoot", "installRoot", "apiServerVersion",
                "apiServerCommit", "apiServerBuild", "apiServerAppName",
            }
            allowed_status_fields = required_status_fields | {"logRoot"}
            if (not required_status_fields.issubset(status)
                    or not set(status).issubset(allowed_status_fields)):
                raise AppleContainerProtocolError("container status has an unknown schema")
            pin = self._version_pin
            app_root = _status_host_path(status.get("appRoot"), "container app root")
            install_root = _status_host_path(status.get("installRoot"),
                                             "container install root")
            log_root = status.get("logRoot")
            if log_root is not None:
                _status_host_path(log_root, "container log root")
            server_text = _string(status.get("apiServerVersion"),
                                  "container status API server version")
            match = _SERVER_VERSION.fullmatch(server_text)
            if match is None:
                raise AppleContainerProtocolError(
                    "container status API server version is malformed"
                )
            if (status.get("status") != "running" or app_root == install_root
                    or install_root != pin.package_install_location
                    or _string(status.get("apiServerCommit"),
                               "container status API server commit") != pin.server_commit
                    or _string(status.get("apiServerBuild"),
                               "container status API server build") != pin.server_build
                    or _string(status.get("apiServerAppName"),
                               "container status API server appName") != "container-apiserver"
                    or match.group("version") != pin.server_version
                    or match.group("build") != pin.server_build
                    or match.group("commit") != pin.server_banner_commit):
                raise AppleContainerUnavailableError(
                    "container status differs from authenticated compatible observation"
                )
            init_image_postcondition = self._verify_init_image(
                require_preflight=False
            )
            self._preflight = PreflightReceipt(
                self._executable, self._executable_sha256,
                pin.cli_version, pin.cli_build, pin.cli_commit,
                pin.cli_signing_identifier, pin.cli_signing_team_id,
                pin.server_executable_path, pin.server_executable_sha256,
                pin.server_version, pin.server_build, pin.server_commit,
                pin.server_signing_identifier, pin.server_signing_team_id,
                pin.containerization_version, pin.containerization_build,
                pin.containerization_commit, pin.containerization_binary_sha256,
                pin.init_image_reference, pin.init_image_index_digest,
                pin.init_image_manifest_digest, init_image_postcondition,
                pin.plugin_root, pin.core_images_plugin_sha256,
                pin.network_vmnet_plugin_sha256, pin.runtime_linux_plugin_sha256,
                pin.machine_apiserver_plugin_sha256,
                pin.plugin_signing_team_id, pin.plugin_closure_sha256,
                pin.package_identifier,
                pin.package_version, pin.package_install_location,
                pin.package_authorization, pin.package_signing_team_id,
                pin.package_receipt_sha256,
                pin.package_installer_leaf_sha256,
                pin.package_signed,
                pin.package_notarized,
                pin.package_timestamped,
                pin.kernel_archive_url, pin.kernel_archive_sha256,
                pin.kernel_archive_size, pin.kernel_binary_member,
                pin.kernel_binary_sha256, pin.implicit_kernel_install_disabled,
                host.architecture, host.version[0],
            )
            return self._preflight

    def _verify_versions(self, rows: Mapping[str, Mapping[str, Any]]) -> None:
        self._guard_process()
        if self._version_pin is None:
            raise AppleContainerUnavailableError(
                "authenticated installed-version provenance is required"
            )
        pin = self._version_pin
        cli = rows["container"]
        server = rows["container-apiserver"]
        cli_values = tuple(_string(cli.get(key), f"container CLI {key}")
                           for key in ("version", "buildType", "commit"))
        server_text = _string(server.get("version"), "API server version")
        server_build = _string(server.get("buildType"), "API server build")
        server_commit = _string(server.get("commit"), "API server commit")
        match = _SERVER_VERSION.fullmatch(server_text)
        if match is None:
            raise AppleContainerProtocolError("API server version text is malformed")
        if (match.group("build") != server_build
                or match.group("commit") != pin.server_banner_commit):
            raise AppleContainerProtocolError("API server version fields are inconsistent")
        if (cli_values != (pin.cli_version, pin.cli_build, pin.cli_commit)
                or match.group("version") != pin.server_version
                or server_build != pin.server_build or server_commit != pin.server_commit):
            raise AppleContainerUnavailableError(
                "component identity differs from authenticated compatible observation"
            )

    def _journal_load(self, identity: str) -> MutationRecord | None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        try:
            record = self._callbacks.journal_load(identity)
        except Exception:
            raise AppleContainerUnavailableError("mutation journal cannot be read") from None
        if record is not None:
            self._validate_record(record, identity)
        return record

    def _validate_record(self, record: MutationRecord, identity: str) -> None:
        self._guard_process()
        if self._version_pin is None:
            raise AppleContainerUnavailableError(
                "authenticated installed-version provenance is required"
            )
        expected = {"create": "stopped", "start": "running", "stop": "stopped",
                    "kill": "stopped", "delete": "absent"}
        if (not isinstance(record, MutationRecord)
                or record.schema != "plamen.apple-container.mutation.v3"
                or record.identity != identity
                or not isinstance(record.spec_sha256, str)
                or _HEX64.fullmatch(record.spec_sha256) is None
                or not isinstance(record.mount_identity_sha256, str)
                or _HEX64.fullmatch(record.mount_identity_sha256) is None
                or record.provider_provenance_sha256
                   != _canonical_digest(list(self._version_pin.provenance))
                or not isinstance(record.state, MutationState)
                or not isinstance(record.operation, str)
                or record.operation not in expected
                or record.expected_state != expected[record.operation]
                or not isinstance(record.attempt_nonce, str)
                or _HEX32.fullmatch(record.attempt_nonce) is None
                or not isinstance(record.mutation_nonce, str)
                or _HEX32.fullmatch(record.mutation_nonce) is None
                or not isinstance(record.generation, str)
                or _HEX32.fullmatch(record.generation) is None
                or (record.state == MutationState.PENDING and record.postcondition_sha256 is not None)
                or (record.state == MutationState.TERMINAL
                    and (not isinstance(record.postcondition_sha256, str)
                         or _HEX64.fullmatch(record.postcondition_sha256) is None))
                or (record.state == MutationState.TERMINAL
                    and record.operation == "delete"
                    and record.postcondition_sha256 != _absence_digest(record))):
            raise AppleContainerProtocolError("mutation journal record is malformed")

    def _prepare_pending(self, spec: ContainerSpec, operation: str,
                         expected_state: str, mount_digest: str
                         ) -> tuple[MutationRecord, MutationRecord | None]:
        self._guard_process()
        if self._callbacks is None or self._version_pin is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        expected = {"create": "stopped", "start": "running", "stop": "stopped",
                    "kill": "stopped", "delete": "absent"}
        if operation not in expected or expected_state != expected[operation]:
            raise AppleContainerConfigurationError("mutation operation is unsupported")
        current = self._journal_load(spec.name)
        if current is not None and current.state == MutationState.PENDING:
            raise AppleContainerAmbiguousError("a prior mutation remains ambiguous")
        if current is not None and (current.spec_sha256 != spec.fingerprint
                                    or current.mount_identity_sha256 != mount_digest):
            raise AppleContainerMismatchError("journal authority differs from requested spec")
        if operation == "create":
            if current is not None and current.expected_state != "absent":
                raise AppleContainerMismatchError("create generation is not absent")
            attempt_nonce, generation = secrets.token_hex(16), secrets.token_hex(16)
        else:
            if current is None or current.expected_state == "absent":
                raise AppleContainerMismatchError("container creation authority is unavailable")
            attempt_nonce, generation = current.attempt_nonce, current.generation
        pending = MutationRecord(
            "plamen.apple-container.mutation.v3", MutationState.PENDING, spec.name,
            spec.fingerprint, mount_digest, operation, expected_state,
            attempt_nonce, secrets.token_hex(16), generation,
            _canonical_digest(list(self._version_pin.provenance)), None,
        )
        self._validate_record(pending, spec.name)
        return pending, current

    def _persist_pending(self, pending: MutationRecord,
                         current: MutationRecord | None) -> MutationRecord:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        try:
            written = self._callbacks.journal_begin(pending, current)
        except Exception:
            raise AppleContainerUnavailableError("mutation intent was not durably recorded") from None
        if written != pending or self._journal_load(pending.identity) != pending:
            raise AppleContainerUnavailableError("mutation intent durability is unproven")
        return pending

    def _begin(self, spec: ContainerSpec, operation: str, expected_state: str,
               mount_digest: str) -> MutationRecord:
        self._guard_process()
        pending, current = self._prepare_pending(
            spec, operation, expected_state, mount_digest
        )
        return self._persist_pending(pending, current)

    def _complete(self, pending: MutationRecord, postcondition: str) -> MutationRecord:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        try:
            terminal = self._callbacks.journal_complete(pending, postcondition)
        except Exception:
            raise AppleContainerAmbiguousError("mutation terminal durability is unproven") from None
        expected = MutationRecord(
            pending.schema, MutationState.TERMINAL, pending.identity,
            pending.spec_sha256, pending.mount_identity_sha256, pending.operation,
            pending.expected_state, pending.attempt_nonce, pending.mutation_nonce,
            pending.generation, pending.provider_provenance_sha256, postcondition,
        )
        if terminal != expected or self._journal_load(pending.identity) != expected:
            raise AppleContainerAmbiguousError("mutation terminal durability is unproven")
        return expected

    def _list_ids(self, spec: ContainerSpec, lease: _MountLease) -> tuple[str, ...]:
        self._guard_process()
        result = self._invoke(("list", "--all", "--quiet"), operation="list",
                              mount_lease=lease, deny_network=True,
                              guest_network=spec.networks[0])
        if result.stdout_observed_bytes != len(result.stdout):
            raise AppleContainerProtocolError("container identity roster was truncated")
        try:
            identities = tuple(line for line in result.stdout.decode("utf-8").splitlines() if line)
        except UnicodeError:
            raise AppleContainerProtocolError("container identity roster is not UTF-8") from None
        if len(identities) > 4096 or len(identities) != len(set(identities)):
            raise AppleContainerProtocolError("container identity roster is invalid")
        if any(_OBSERVED_CONTAINER_ID.fullmatch(item) is None or ".." in item for item in identities):
            raise AppleContainerProtocolError("container identity roster contains an unsafe ID")
        return identities

    def recover(self, spec: ContainerSpec) -> RecoveryReceipt:
        self._guard_process()
        with self._lock:
            if self._preflight is None:
                raise AppleContainerUnavailableError("provider has not passed preflight")
            lease = self._open_mount_lease(spec.mounts)
            try:
                return self._recover_with_lease(spec, lease)
            finally:
                self._close_mount_lease(lease)

    def _recover_with_lease(self, spec: ContainerSpec,
                            lease: _MountLease) -> RecoveryReceipt:
        self._guard_process()
        mount_digest = lease.identity_sha256
        record = self._journal_load(spec.name)
        identities = self._list_ids(spec, lease)
        exact = spec.name in identities
        if any(item != spec.name and item.casefold() == spec.name.casefold() for item in identities):
            return self._mismatch(spec, "CASE_ALIAS_COLLISION")
        if record is not None and (record.spec_sha256 != spec.fingerprint
                                   or record.mount_identity_sha256 != mount_digest):
            return self._mismatch(spec, "JOURNAL_AUTHORITY_MISMATCH")
        if record is not None and record.state == MutationState.PENDING:
            record = self._recover_pending(spec, record, exact, lease)
            if record.state == MutationState.PENDING:
                return self._mismatch(spec, "PRIOR_MUTATION_AMBIGUOUS")
        if not exact:
            if record is None:
                return RecoveryReceipt(RecoveryDecision.ABSENT, None, spec.fingerprint,
                                       None, None,
                                       rosetta_required=spec.rosetta_required)
            if record.expected_state == "absent" and record.postcondition_sha256 == _absence_digest(record):
                return RecoveryReceipt(RecoveryDecision.ABSENT, None, spec.fingerprint,
                                       None, record.postcondition_sha256,
                                       rosetta_required=spec.rosetta_required)
            return self._mismatch(spec, "CONTAINER_DISAPPEARED")
        if record is None:
            return self._mismatch(spec, "MISSING_CREATION_AUTHORITY")
        if record.expected_state == "absent":
            return self._mismatch(spec, "CONTAINER_REAPPEARED")
        inspected = self._inspect(spec, record, lease)
        if not inspected.matches:
            return RecoveryReceipt(RecoveryDecision.MISMATCH, spec.name, spec.fingerprint,
                                   inspected.state, inspected.observation_sha256,
                                   inspected.mismatch_code, spec.rosetta_required)
        if record.state != MutationState.TERMINAL or record.postcondition_sha256 != inspected.configuration_sha256:
            return RecoveryReceipt(RecoveryDecision.MISMATCH, spec.name, spec.fingerprint,
                                   inspected.state, inspected.observation_sha256,
                                   "POSTCONDITION_REPLAY_MISMATCH", spec.rosetta_required)
        if record.expected_state == "stopped" and inspected.state == "running":
            return RecoveryReceipt(RecoveryDecision.MISMATCH, spec.name, spec.fingerprint,
                                   inspected.state, inspected.observation_sha256,
                                   "UNJOURNALLED_START", spec.rosetta_required)
        decision = {"running": RecoveryDecision.RUNNING_MATCH,
                    "stopped": RecoveryDecision.STOPPED_MATCH}.get(inspected.state)
        if decision is None:
            return self._mismatch(spec, "UNSAFE_STATE")
        return RecoveryReceipt(decision, spec.name, spec.fingerprint, inspected.state,
                               inspected.observation_sha256,
                               rosetta_required=spec.rosetta_required)

    def _recover_pending(self, spec: ContainerSpec, record: MutationRecord,
                         exact: bool, lease: _MountLease) -> MutationRecord:
        self._guard_process()
        if record.expected_state == "absent":
            return record if exact else self._complete(record, _absence_digest(record))
        if not exact:
            return record
        inspected = self._inspect(spec, record, lease)
        if inspected.matches and inspected.state == record.expected_state:
            return self._complete(record, inspected.configuration_sha256)
        return record

    @staticmethod
    def _mismatch(spec: ContainerSpec, reason: str) -> RecoveryReceipt:
        return RecoveryReceipt(RecoveryDecision.MISMATCH, None, spec.fingerprint,
                               None, None, reason, spec.rosetta_required)

    def _inspect(self, spec: ContainerSpec, record: MutationRecord,
                 lease: _MountLease) -> _InspectedContainer:
        self._guard_process()
        result = self._invoke(("inspect", spec.name), operation="inspect",
                              mount_lease=lease, deny_network=True,
                              guest_network=spec.networks[0],
                              output_limit=MAX_JSON_BYTES)
        document = _list(_strict_json(result, "container inspect"), "container inspect")
        if len(document) != 1:
            raise AppleContainerProtocolError("container inspect must contain one object")
        raw = _mapping(document[0], "container inspect item")
        if set(raw) != {"id", "configuration", "status"}:
            raise AppleContainerProtocolError("container inspect top-level schema changed")
        configuration = _mapping(raw.get("configuration"), "container configuration")
        status = _mapping(raw.get("status"), "container status")
        status_fields = set(status)
        if (not {"state", "networks"}.issubset(status_fields)
                or not status_fields.issubset({"state", "networks", "startedDate"})):
            raise AppleContainerProtocolError("container state schema changed")
        if not isinstance(status.get("networks"), list):
            raise AppleContainerProtocolError("container state networks are malformed")
        state = _string(status.get("state"), "container state")
        started_date = status.get("startedDate")
        if (started_date is not None and (
                not isinstance(started_date, str)
                or not started_date or len(started_date.encode("utf-8")) > 128
                or any(ord(character) < 0x20 or ord(character) == 0x7f
                       for character in started_date))):
            raise AppleContainerProtocolError("container started date is malformed")
        if state not in {"running", "stopped", "stopping", "unknown"}:
            raise AppleContainerProtocolError("container state is unsupported")
        mismatch = ("IDENTITY_MISMATCH" if raw.get("id") != spec.name
                    or configuration.get("id") != spec.name
                    else self._configuration_mismatch(configuration, spec, record))
        if mismatch is None:
            expected_networks = sorted((
                item.name, spec.name, item.ipv4_address, item.ipv4_gateway,
                item.mac_address, item.mtu, item.attachment_variant,
            ) for item in spec.networks)
            observed_networks = _parse_network_attachments(status.get("networks"))
            if observed_networks != expected_networks:
                mismatch = "RUNTIME_NETWORK_MISMATCH"
        return _InspectedContainer(
            spec.name, state, mismatch is None, _canonical_digest(raw),
            _canonical_digest(configuration), mismatch,
        )

    def _configuration_mismatch(self, configuration: Mapping[str, Any],
                                spec: ContainerSpec, record: MutationRecord) -> str | None:
        self._guard_process()
        configuration_fields = set(configuration)
        if (not _CONFIGURATION_REQUIRED_FIELDS.issubset(configuration_fields)
                or not configuration_fields.issubset(
                    _CONFIGURATION_REQUIRED_FIELDS | _CONFIGURATION_OPTIONAL_FIELDS
                )):
            return "CONFIGURATION_SCHEMA_MISMATCH"
        image = _mapping(configuration.get("image"), "container image")
        if set(image) != {"reference", "descriptor"} or image.get("reference") != spec.image_reference:
            return "IMAGE_SCHEMA_MISMATCH"
        descriptor = _mapping(image.get("descriptor"), "image descriptor")
        if set(descriptor) != {"digest", "mediaType", "size"}:
            return "IMAGE_SCHEMA_MISMATCH"
        if descriptor.get("digest") != spec.image_digest:
            return "IMAGE_DIGEST_MISMATCH"
        if descriptor.get("mediaType") != OCI_IMAGE_INDEX_MEDIA_TYPE:
            return "IMAGE_MEDIA_TYPE_MISMATCH"
        _integer(descriptor.get("size"), "image descriptor size", minimum=1)
        labels = _mapping(configuration.get("labels"), "container labels")
        if labels != spec.expected_labels(record):
            return "LABEL_MISMATCH"
        platform_value = _mapping(configuration.get("platform"), "container platform")
        if set(platform_value) != {"os", "architecture"} or platform_value != {
            "os": "linux", "architecture": "arm64"
        }:
            return "PLATFORM_MISMATCH"
        exact_containers = {
            "publishedPorts": [], "publishedSockets": [], "sysctls": {},
            "capAdd": [], "capDrop": ["ALL"],
        }
        for key, wanted in exact_containers.items():
            if type(configuration.get(key)) is not type(wanted) or configuration.get(key) != wanted:
                return "SECURITY_CONFIGURATION_MISMATCH"
        for key, wanted in {
            "rosetta": spec.rosetta_required, "virtualization": False, "ssh": False,
            "readOnly": True, "useInit": True,
        }.items():
            if type(configuration.get(key)) is not bool or configuration.get(key) is not wanted:
                return "SECURITY_CONFIGURATION_MISMATCH"
        for key in ("dns", "shmSize", "maskedPaths", "readonlyPaths"):
            if configuration.get(key) is not None:
                return "SECURITY_CONFIGURATION_MISMATCH"
        if (type(configuration.get("runtimeHandler")) is not str
                or configuration.get("runtimeHandler") != spec.runtime_handler
                or configuration.get("stopSignal") != spec.stop_signal
                or (spec.stop_signal is None and configuration.get("stopSignal") is not None)
                or (spec.stop_signal is not None
                    and type(configuration.get("stopSignal")) is not str)):
            return "SECURITY_CONFIGURATION_MISMATCH"
        creation_date = configuration.get("creationDate")
        if (type(creation_date) is not str
                or len(creation_date.encode("utf-8")) > 128
                or _RFC3339_UTC.fullmatch(creation_date) is None):
            return "CREATION_DATE_MISMATCH"
        resources = _mapping(configuration.get("resources"), "resources")
        resource_fields = set(resources)
        if (not _RESOURCE_REQUIRED_FIELDS.issubset(resource_fields)
                or not resource_fields.issubset(
                    _RESOURCE_REQUIRED_FIELDS | _RESOURCE_OPTIONAL_FIELDS
                )):
            return "RESOURCE_SCHEMA_MISMATCH"
        cpus = _integer(resources.get("cpus"), "container CPUs", minimum=1, maximum=64)
        memory = _integer(resources.get("memoryInBytes"), "container memory", minimum=1)
        overhead = _integer(resources.get("cpuOverhead"), "container CPU overhead", minimum=1)
        if (cpus != spec.cpus
                or memory != spec.memory_bytes
                or resources.get("storage") is not None
                or overhead != 1):
            return "RESOURCE_MISMATCH"
        process = _mapping(configuration.get("initProcess"), "init process")
        if set(process) != _PROCESS_FIELDS:
            return "PROCESS_SCHEMA_MISMATCH"
        user = _mapping(process.get("user"), "container user")
        user_id = _mapping(user.get("id"), "container user ID")
        if set(user) != {"id"} or set(user_id) != {"uid", "gid"}:
            return "PROCESS_SCHEMA_MISMATCH"
        uid = _integer(user_id.get("uid"), "container uid", minimum=1, maximum=2**32 - 1)
        gid = _integer(user_id.get("gid"), "container gid", minimum=1, maximum=2**32 - 1)
        if (process.get("executable") != spec.entrypoint
                or process.get("arguments") != list(spec.arguments)
                or process.get("environment") != list(spec.expected_environment)
                or process.get("workingDirectory") != spec.working_directory
                or process.get("terminal") is not False
                or uid != spec.uid or gid != spec.gid
                or process.get("supplementalGroups") != [] or process.get("rlimits") != []):
            return "PROCESS_MISMATCH"
        expected_mounts = sorted((item.source, item.target, item.readonly) for item in spec.mounts)
        if _parse_mounts(configuration.get("mounts")) != expected_mounts:
            return "MOUNT_MISMATCH"
        expected_networks = sorted((item.name, spec.name, item.mtu,
                                    item.mac_address.lower() if item.mac_address else None)
                                   for item in spec.networks)
        if _parse_network_configurations(configuration.get("networks")) != expected_networks:
            return "NETWORK_MISMATCH"
        return None

    def admit_local_image(self, spec: ContainerSpec, archive_path: str) -> ImageAdmissionRecord:
        """Compatibility lane: provider-v3 physical archive admission."""
        return self._admit_local_image(spec, archive_path, provider_v4=False)

    def admit_local_image_v4(self, spec: ContainerSpec,
                             archive_path: str) -> ImageAdmissionRecord:
        """Admit an archive whose retained authority includes content/layout facts."""
        return self._admit_local_image(spec, archive_path, provider_v4=True)

    def _admit_local_image(self, spec: ContainerSpec, archive_path: str, *,
                           provider_v4: bool) -> ImageAdmissionRecord:
        self._guard_process()
        with self._lock:
            if self._preflight is None or self._callbacks is None:
                raise AppleContainerUnavailableError("provider has not passed preflight")
            archive = MountSpec(archive_path, "/.plamen/image-archive", True)
            lease = self._open_mount_lease((archive,))
            try:
                facts = self._lease_facts(lease)
                if facts[0].kind != "file":
                    raise AppleContainerConfigurationError("image archive must be a regular file")
                if (facts[0].oci_index_digest != spec.image_digest
                        or facts[0].oci_manifest_digest != spec.image_manifest_digest
                        or facts[0].oci_configuration_sha256
                           != spec.image_configuration_sha256):
                    raise AppleContainerMismatchError(
                        "image archive descriptors differ from the exact image pins"
                    )
                archive_digest = lease.identity_sha256
                if provider_v4:
                    if (not isinstance(facts[0].oci_layout_receipt_sha256, str)
                            or _HEX64.fullmatch(
                                facts[0].oci_layout_receipt_sha256
                            ) is None
                            or facts[0].oci_layout_receipt_sha256 == "0" * 64):
                        raise AppleContainerUnavailableError(
                            "retained OCI layout receipt authority is absent"
                        )
                    archive_content_sha256 = facts[0].content_sha256
                    archive_size = facts[0].size
                    layout_receipt_sha256 = facts[0].oci_layout_receipt_sha256
                    image_closure_sha256 = spec.image_closure_sha256
                else:
                    archive_content_sha256 = None
                    archive_size = None
                    layout_receipt_sha256 = None
                    image_closure_sha256 = None
                previous = self._load_image_record(spec.image_reference)
                expected_schema = (
                    "plamen.apple-container.image-admission.v4" if provider_v4
                    else "plamen.apple-container.image-admission.v3"
                )
                if previous is not None and previous.schema != expected_schema:
                    raise AppleContainerMismatchError(
                        "image admission compatibility lane differs"
                    )
                if previous is not None and previous.state == ImageAdmissionState.PENDING:
                    raise AppleContainerAmbiguousError("a prior image load remains ambiguous")
                if (previous is not None and previous.state == ImageAdmissionState.TERMINAL
                        and previous.image_reference == spec.image_reference
                        and previous.index_digest == spec.image_digest
                        and previous.manifest_digest == spec.image_manifest_digest
                        and previous.configuration_sha256 == spec.image_configuration_sha256
                        and previous.archive_identity_sha256 == archive_digest
                        and previous.schema == expected_schema
                        and previous.archive_content_sha256 == archive_content_sha256
                        and previous.archive_size == archive_size
                        and previous.layout_receipt_sha256 == layout_receipt_sha256
                        and previous.image_closure_sha256 == image_closure_sha256):
                    postcondition = self._verify_local_image(spec, mount_lease=lease)
                    if previous.postcondition_sha256 != postcondition:
                        raise AppleContainerMismatchError("local image postcondition changed")
                    return previous
                pending = ImageAdmissionRecord(
                    ("plamen.apple-container.image-admission.v4" if provider_v4
                     else "plamen.apple-container.image-admission.v3"),
                    ImageAdmissionState.PENDING, spec.image_reference,
                    spec.image_digest, spec.image_manifest_digest,
                    spec.image_configuration_sha256, "linux", "arm64",
                    archive_digest, secrets.token_hex(16),
                    _canonical_digest(list(self._version_pin.provenance)), None,
                    archive_content_sha256, archive_size,
                    layout_receipt_sha256, image_closure_sha256,
                )
                self._store_image_record(pending, previous, ambiguous=False)
                try:
                    self._invoke(("image", "load", "--input", archive_path),
                                 operation="image-load", mount_lease=lease,
                                 deny_network=True)
                    postcondition = self._verify_local_image(spec, mount_lease=lease)
                    terminal = ImageAdmissionRecord(
                        pending.schema, ImageAdmissionState.TERMINAL,
                        pending.image_reference, pending.index_digest,
                        pending.manifest_digest,
                        pending.configuration_sha256, pending.platform_os,
                        pending.platform_architecture, pending.archive_identity_sha256,
                        pending.admission_nonce, pending.provider_provenance_sha256,
                        postcondition, pending.archive_content_sha256,
                        pending.archive_size, pending.layout_receipt_sha256,
                        pending.image_closure_sha256,
                    )
                    self._store_image_record(terminal, pending, ambiguous=True)
                    return terminal
                except AppleContainerAmbiguousError:
                    raise
                except Exception:
                    raise AppleContainerAmbiguousError(
                        "local image load outcome is journalled as ambiguous"
                    ) from None
            finally:
                self._close_mount_lease(lease)

    def _load_image_record(self, reference: str) -> ImageAdmissionRecord | None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        try:
            record = self._callbacks.image_load(reference)
        except Exception:
            raise AppleContainerUnavailableError("image admission journal cannot be read") from None
        if record is not None:
            self._validate_image_record(record, reference)
        return record

    def _validate_image_record(self, record: ImageAdmissionRecord, reference: str) -> None:
        self._guard_process()
        if self._version_pin is None:
            raise AppleContainerUnavailableError(
                "authenticated installed-version provenance is required"
            )
        reference_match = (_OCI_REFERENCE.fullmatch(record.image_reference)
                           if (isinstance(record, ImageAdmissionRecord)
                               and isinstance(record.image_reference, str)) else None)
        if (not isinstance(record, ImageAdmissionRecord)
                or record.schema not in {
                    "plamen.apple-container.image-admission.v3",
                    "plamen.apple-container.image-admission.v4",
                }
                or not isinstance(record.state, ImageAdmissionState)
                or record.image_reference != reference
                or reference_match is None
                or not isinstance(record.index_digest, str)
                or _SHA256.fullmatch(record.index_digest) is None
                or not isinstance(record.manifest_digest, str)
                or _SHA256.fullmatch(record.manifest_digest) is None
                or reference_match.group("digest") != record.index_digest
                or not isinstance(record.configuration_sha256, str)
                or _HEX64.fullmatch(record.configuration_sha256) is None
                or record.platform_os != "linux" or record.platform_architecture != "arm64"
                or not isinstance(record.archive_identity_sha256, str)
                or _HEX64.fullmatch(record.archive_identity_sha256) is None
                or not isinstance(record.admission_nonce, str)
                or _HEX32.fullmatch(record.admission_nonce) is None
                or record.provider_provenance_sha256
                   != _canonical_digest(list(self._version_pin.provenance))
                or (record.schema == "plamen.apple-container.image-admission.v3"
                    and any(value is not None for value in (
                        record.archive_content_sha256, record.archive_size,
                        record.layout_receipt_sha256,
                        record.image_closure_sha256,
                    )))
                or (record.schema == "plamen.apple-container.image-admission.v4"
                    and (not isinstance(record.archive_content_sha256, str)
                         or _HEX64.fullmatch(record.archive_content_sha256) is None
                         or record.archive_content_sha256 == "0" * 64
                         or isinstance(record.archive_size, bool)
                         or not isinstance(record.archive_size, int)
                         or record.archive_size < 1
                         or not isinstance(record.layout_receipt_sha256, str)
                         or _HEX64.fullmatch(record.layout_receipt_sha256) is None
                         or record.layout_receipt_sha256 == "0" * 64
                         or not isinstance(record.image_closure_sha256, str)
                         or _HEX64.fullmatch(record.image_closure_sha256) is None))
                or (record.state == ImageAdmissionState.PENDING
                    and record.postcondition_sha256 is not None)
                or (record.state == ImageAdmissionState.TERMINAL
                    and (not isinstance(record.postcondition_sha256, str)
                         or _HEX64.fullmatch(record.postcondition_sha256) is None))):
            raise AppleContainerProtocolError("image admission journal record is malformed")

    def _store_image_record(self, record: ImageAdmissionRecord,
                            previous: ImageAdmissionRecord | None, *, ambiguous: bool) -> None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        self._validate_image_record(record, record.image_reference)
        try:
            written = self._callbacks.image_save(record, previous)
            loaded = self._callbacks.image_load(record.image_reference)
        except Exception:
            error = (AppleContainerAmbiguousError if ambiguous
                     else AppleContainerUnavailableError)
            raise error("image admission durability is unproven") from None
        if written != record or loaded != record:
            error = (AppleContainerAmbiguousError if ambiguous
                     else AppleContainerUnavailableError)
            raise error("image admission durability is unproven")

    def _verify_exact_local_image(
        self, reference: str, index_digest: str, manifest_digest: str, *,
        configuration_sha256: str | None,
        mount_lease: _MountLease | None = None,
        guest_network: NetworkSpec | None = None,
        require_preflight: bool = True,
    ) -> str:
        self._guard_process()
        match = _OCI_REFERENCE.fullmatch(reference) if isinstance(reference, str) else None
        if (match is None or match.group("digest") != index_digest
                or not isinstance(index_digest, str)
                or _SHA256.fullmatch(index_digest) is None
                or not isinstance(manifest_digest, str)
                or _SHA256.fullmatch(manifest_digest) is None
                or index_digest == manifest_digest
                or (configuration_sha256 is not None
                    and (not isinstance(configuration_sha256, str)
                         or _HEX64.fullmatch(configuration_sha256) is None))):
            raise AppleContainerConfigurationError("local image pin is malformed")
        _validate_oci_reference(reference)
        result = self._invoke(("image", "inspect", reference),
                              operation="image-inspect", deny_network=True,
                              mount_lease=mount_lease,
                              guest_network=guest_network,
                              require_preflight=require_preflight,
                              output_limit=MAX_JSON_BYTES)
        values = _list(_strict_json(result, "container image inspect"),
                       "container image inspect")
        if len(values) != 1:
            raise AppleContainerMismatchError("exact local image is unavailable")
        resource = _mapping(values[0], "image resource")
        if set(resource) != {"id", "configuration", "variants"}:
            raise AppleContainerProtocolError("image resource schema changed")
        configuration = _mapping(resource.get("configuration"), "image configuration")
        if set(configuration) != {"creationDate", "name", "descriptor"}:
            raise AppleContainerProtocolError("image configuration schema changed")
        descriptor = _mapping(configuration.get("descriptor"), "image index descriptor")
        if set(descriptor) != {"digest", "mediaType", "size"}:
            raise AppleContainerProtocolError("image descriptor schema changed")
        _integer(descriptor.get("size"), "image index descriptor size", minimum=1)
        _timestamp(configuration.get("creationDate"), "image creation date")
        if descriptor.get("mediaType") != OCI_IMAGE_INDEX_MEDIA_TYPE:
            raise AppleContainerMismatchError("local image media type differs")
        if configuration.get("name") != reference:
            raise AppleContainerMismatchError("local image reference differs")
        variants = _list(resource.get("variants"), "image variants")
        matches: list[Mapping[str, Any]] = []
        for raw in variants:
            variant = _mapping(raw, "image variant")
            if set(variant) != {"platform", "digest", "size", "config"}:
                raise AppleContainerProtocolError("image variant schema changed")
            platform_value = _mapping(variant.get("platform"), "image platform")
            if set(platform_value) != {"os", "architecture"}:
                raise AppleContainerProtocolError("image platform schema changed")
            _integer(variant.get("size"), "image variant size", minimum=1)
            _mapping(variant.get("config"), "image variant configuration")
            if platform_value == {"os": "linux", "architecture": "arm64"}:
                matches.append(variant)
        if len(matches) != 1:
            raise AppleContainerMismatchError("exact linux/arm64 image variant is unavailable")
        variant = matches[0]
        if (resource.get("id") != index_digest.removeprefix("sha256:")
                or descriptor.get("digest") != index_digest
                or variant.get("digest") != manifest_digest
                or (configuration_sha256 is not None
                    and _canonical_digest(variant.get("config"))
                    != configuration_sha256)):
            raise AppleContainerMismatchError("local image digest or configuration differs")
        return _canonical_digest(resource)

    def _verify_local_image(self, spec: ContainerSpec, *,
                            mount_lease: _MountLease | None = None,
                            guest_network: NetworkSpec | None = None) -> str:
        return self._verify_exact_local_image(
            spec.image_reference, spec.image_digest, spec.image_manifest_digest,
            configuration_sha256=spec.image_configuration_sha256,
            mount_lease=mount_lease, guest_network=guest_network,
        )

    def _verify_init_image(self, spec: ContainerSpec | None = None, *,
                           mount_lease: _MountLease | None = None,
                           require_preflight: bool = True) -> str:
        if spec is None:
            if self._version_pin is None:
                raise AppleContainerUnavailableError(
                    "authenticated installed-version provenance is required"
                )
            reference = self._version_pin.init_image_reference
            index_digest = self._version_pin.init_image_index_digest
            manifest_digest = self._version_pin.init_image_manifest_digest
        else:
            reference = spec.init_image_reference
            index_digest = spec.init_image_digest
            manifest_digest = spec.init_image_manifest_digest
        if (reference != SUPPORTED_INIT_IMAGE_REFERENCE
                or index_digest != SUPPORTED_INIT_IMAGE_INDEX_DIGEST
                or manifest_digest != SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST):
            raise AppleContainerMismatchError("init image pin differs")
        return self._verify_exact_local_image(
            reference, index_digest, manifest_digest,
            configuration_sha256=None, mount_lease=mount_lease,
            require_preflight=require_preflight,
        )

    def _require_admitted_image(
        self, spec: ContainerSpec, *, mount_lease: _MountLease | None = None,
    ) -> None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        record = self._load_image_record(spec.image_reference)
        if (record is None or record.state != ImageAdmissionState.TERMINAL
                or record.image_reference != spec.image_reference
                or record.index_digest != spec.image_digest
                or record.manifest_digest != spec.image_manifest_digest
                or record.configuration_sha256 != spec.image_configuration_sha256
                or record.platform_os != "linux" or record.platform_architecture != "arm64"
                or (record.schema == "plamen.apple-container.image-admission.v4"
                    and record.image_closure_sha256 != spec.image_closure_sha256)
                or _HEX64.fullmatch(record.archive_identity_sha256) is None
                or record.postcondition_sha256 is None):
            raise AppleContainerMismatchError("governed local image admission is unavailable")
        postcondition = self._verify_local_image(spec, mount_lease=mount_lease)
        if postcondition != record.postcondition_sha256:
            raise AppleContainerMismatchError("local image postcondition changed")

    def _require_admitted_init_image(
        self, spec: ContainerSpec, *, mount_lease: _MountLease | None = None,
    ) -> None:
        self._guard_process()
        receipt = self._preflight
        if (receipt is None
                or receipt.init_image_reference != spec.init_image_reference
                or receipt.init_image_index_digest != spec.init_image_digest
                or receipt.init_image_manifest_digest != spec.init_image_manifest_digest
                or receipt.init_image_reference != SUPPORTED_INIT_IMAGE_REFERENCE
                or receipt.init_image_index_digest != SUPPORTED_INIT_IMAGE_INDEX_DIGEST
                or receipt.init_image_manifest_digest
                   != SUPPORTED_INIT_IMAGE_MANIFEST_DIGEST
                or not isinstance(receipt.init_image_postcondition_sha256, str)
                or _HEX64.fullmatch(receipt.init_image_postcondition_sha256) is None):
            raise AppleContainerMismatchError("governed init image admission is unavailable")
        postcondition = self._verify_init_image(spec, mount_lease=mount_lease)
        if postcondition != receipt.init_image_postcondition_sha256:
            raise AppleContainerMismatchError("init image postcondition changed")

    def _require_driver_callbacks(self) -> _AuthorityCallbacks:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerUnavailableError("trusted native authority is unavailable")
        callbacks = self._callbacks
        required = (
            callbacks.driver_start, callbacks.driver_wait,
            callbacks.driver_recover_process, callbacks.driver_recover_wait,
            callbacks.driver_revoke, callbacks.driver_journal_load,
            callbacks.driver_journal_cas,
        )
        if not all(callable(item) for item in required):
            raise AppleContainerUnavailableError(
                "authenticated native driver runner is unavailable"
            )
        return callbacks

    def _load_driver_record(
        self, request: DriverLaunchRequest,
    ) -> DriverLifecycleRecord | None:
        self._guard_process()
        callbacks = self._require_driver_callbacks()
        try:
            record = callbacks.driver_journal_load(  # type: ignore[misc]
                request.container_id, request.attempt_id
            )
        except Exception:
            raise AppleContainerUnavailableError(
                "driver lifecycle journal cannot be read"
            ) from None
        if record is None:
            return None
        if type(record) is not DriverLifecycleRecord:
            raise AppleContainerProtocolError("driver lifecycle journal is malformed")
        _validate_driver_record(record)
        if (record.container_id != request.container_id
                or record.attempt_id != request.attempt_id
                or record.spec_sha256 != request.spec_sha256
                or record.launch_request_sha256 != request.request_sha256
                or record.launch_policy_sha256 != request.launch_policy_sha256
                or record.driver_argv_sha256 != request.driver_argv_sha256
                or record.driver_environment_sha256
                   != request.driver_environment_sha256
                or record.driver_cwd_sha256 != request.driver_cwd_sha256
                or record.driver_stdin_sha256 != request.driver_stdin_sha256
                or record.pass_fd_roster_sha256
                   != request.pass_fd_roster_sha256
                or record.cli_executable_sha256 != self._executable_sha256
                or record.rosetta_required is not request.rosetta_required
                or self._version_pin is None
                or record.provider_provenance_sha256
                   != _canonical_digest(list(self._version_pin.provenance))):
            raise AppleContainerMismatchError(
                "driver lifecycle journal differs from the launch request"
            )
        return record

    def _store_driver_record(
        self, record: DriverLifecycleRecord,
        previous: DriverLifecycleRecord | None, *, effect_started: bool,
    ) -> DriverLifecycleRecord:
        self._guard_process()
        callbacks = self._require_driver_callbacks()
        try:
            written = callbacks.driver_journal_cas(record, previous)  # type: ignore[misc]
            loaded = callbacks.driver_journal_load(  # type: ignore[misc]
                record.container_id, record.attempt_id
            )
        except Exception:
            error = AppleContainerAmbiguousError if effect_started else AppleContainerUnavailableError
            raise error("driver lifecycle checkpoint durability is unproven") from None
        if written != record or loaded != record:
            error = AppleContainerAmbiguousError if effect_started else AppleContainerUnavailableError
            raise error("driver lifecycle checkpoint durability is unproven")
        return record

    def _arm_driver_start(
        self, request: DriverLaunchRequest,
    ) -> DriverLifecycleRecord:
        self._guard_process()
        if self._version_pin is None:
            raise AppleContainerUnavailableError(
                "authenticated installed-version provenance is required"
            )
        return _driver_record(
            schema="plamen.apple-container.driver-lifecycle.v2",
            state=DriverLifecycleState.START_ARMED,
            container_id=request.container_id,
            attempt_id=request.attempt_id,
            spec_sha256=request.spec_sha256,
            launch_request_sha256=request.request_sha256,
            launch_policy_sha256=request.launch_policy_sha256,
            driver_argv_sha256=request.driver_argv_sha256,
            driver_environment_sha256=request.driver_environment_sha256,
            driver_cwd_sha256=request.driver_cwd_sha256,
            driver_stdin_sha256=request.driver_stdin_sha256,
            pass_fd_roster_sha256=request.pass_fd_roster_sha256,
            start_operation_nonce=secrets.token_hex(16),
            wait_operation_nonce=None,
            native_process_id=None,
            native_process_handle_sha256=None,
            cli_executable_sha256=self._executable_sha256,
            start_timestamp=None,
            end_timestamp=None,
            exit_code=None,
            stdout_sha256=None,
            stderr_sha256=None,
            stdout_retained_sha256=None,
            stderr_retained_sha256=None,
            stdout_observed_bytes=None,
            stderr_observed_bytes=None,
            stdout_retained_bytes=None,
            stderr_retained_bytes=None,
            stdout_truncated=None,
            stderr_truncated=None,
            native_process_extinction_sha256=None,
            cleanup_sha256=None,
            stop_argv_sha256=None,
            stop_stdout_sha256=None,
            stop_stderr_sha256=None,
            stopped_observation_sha256=None,
            guest_population_extinction_sha256=None,
            descendants_extinct=None,
            guest_process_extinct=None,
            backend_egress_revoked=None,
            stop_control_process_reaped=None,
            stop_control_process_group_extinct=None,
            guest_population_zero=None,
            container_vm_stopped=None,
            rosetta_required=request.rosetta_required,
            provider_provenance_sha256=_canonical_digest(
                list(self._version_pin.provenance)
            ),
            start_effect_sha256=None,
            start_abort_extinction_sha256=None,
            start_abort_cleanup_sha256=None,
            start_abort_egress_revoked=None,
            start_receipt_sha256=None,
            start_journal_checkpoint_sha256=None,
            wait_effect_sha256=None,
        )

    def _validate_driver_process(
        self, capability: object, *, spec: ContainerSpec,
        request: DriverLaunchRequest, record: DriverLifecycleRecord,
        command: tuple[str, ...], executable_capability: object,
        mount_lease: _MountLease,
    ) -> _DriverProcessFacts:
        self._guard_process()
        facts = _driver_process_facts(capability)
        mount_caps = mount_lease.capabilities
        network = spec.networks[0]
        invalid = (
            facts is None or facts.owner is not self._authority
            or facts.capability is not capability or facts.command != command
            or facts.executable_capability is not executable_capability
            or len(facts.mount_capabilities) != len(mount_caps)
            or any(actual is not expected for actual, expected in
                   zip(facts.mount_capabilities, mount_caps))
            or facts.mounted_identity_sha256 != mount_lease.identity_sha256
            or self._version_pin is None
            or facts.provenance != self._version_pin.provenance
            or facts.container_id != spec.name
            or facts.attempt_id != request.attempt_id
            or facts.spec_sha256 != spec.fingerprint
            or facts.launch_request_sha256 != request.request_sha256
            or facts.launch_policy_sha256 != request.launch_policy_sha256
            or facts.driver_argv_sha256 != request.driver_argv_sha256
            or facts.driver_environment_sha256
               != request.driver_environment_sha256
            or facts.driver_cwd_sha256 != request.driver_cwd_sha256
            or facts.driver_stdin_sha256 != request.driver_stdin_sha256
            or facts.pass_fd_roster_sha256 != request.pass_fd_roster_sha256
            or facts.start_operation_nonce != record.start_operation_nonce
            or facts.creator_pid != os.getpid()
            or not isinstance(facts.native_process_id, str)
            or _SAFE_RUN_ID.fullmatch(facts.native_process_id) is None
            or not isinstance(facts.native_process_handle_sha256, str)
            or _HEX64.fullmatch(facts.native_process_handle_sha256) is None
            or not isinstance(facts.start_timestamp, str)
            or facts.rosetta_required is not spec.rosetta_required
            or facts.native_process_retained is not True
            or facts.stdout_pipe_bound is not True
            or facts.stderr_pipe_bound is not True
            or facts.stdin_devnull is not True
            or facts.guest_network_policy_sha256 != network.policy_sha256
            or facts.guest_network_topology_sha256 != network.topology_sha256
            or facts.guest_network_policy_enforced is not True
            or facts.consumed or facts.revoked
        )
        if invalid or facts is None:
            raise AppleContainerUnavailableError(
                "native driver process capability is invalid"
            )
        _timestamp(facts.start_timestamp, "driver start timestamp")
        return facts

    def _finish_async_executable(self, capability: object) -> None:
        self._guard_process()
        if self._callbacks is None:
            raise AppleContainerAmbiguousError(
                "native executable capability cleanup is unavailable"
            )
        failed = False
        try:
            before = _TEST_ONLY_EXECUTABLE_REGISTRY[id(capability)]
            self._callbacks.post_fstat_executable(capability)
            if not before.postchecked:
                failed = True
            self._callbacks.close_executable(capability)
            facts = _TEST_ONLY_EXECUTABLE_REGISTRY.get(id(capability))
            if (facts is None or facts.owner is not self._authority
                    or facts.capability is not capability or not facts.closed):
                failed = True
        except Exception:
            failed = True
        if failed:
            raise AppleContainerAmbiguousError(
                "native executable capability cleanup is unproven"
            ) from None
        with _REGISTRY_LOCK:
            _TEST_ONLY_EXECUTABLE_REGISTRY.pop(id(capability), None)

    def _discard_unadmitted_driver_process(self, capability: object) -> None:
        self._guard_process()
        facts = _driver_process_facts(capability)
        callbacks = self._require_driver_callbacks()
        if facts is None or facts.owner is not self._authority:
            try:
                callbacks.driver_revoke(  # type: ignore[misc]
                    capability, wait_operation_nonce="0" * 32,
                    reason="START_ADMISSION_FAILURE",
                )
            except Exception:
                pass
            raise AppleContainerAmbiguousError(
                "unadmitted native driver process extinction is unproven"
            )
        self._revoke_driver_process(
            capability, facts, wait_operation_nonce="0" * 32,
            reason="START_ADMISSION_FAILURE",
        )
        with _REGISTRY_LOCK:
            _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)

    def _native_start_or_recover(
        self, spec: ContainerSpec, request: DriverLaunchRequest,
        record: DriverLifecycleRecord, lease: _MountLease, *,
        allow_new_start: bool,
    ) -> tuple[object, _DriverProcessFacts]:
        self._guard_process()
        callbacks = self._require_driver_callbacks()
        command = ("start", "--attach", spec.name)
        _validate_argv(command, "driver-start")
        self._revalidate_lease(lease)
        executable_capability, executable_facts = self._open_executable()
        executable_facts.used = True
        capability: object | None = None
        process_facts: _DriverProcessFacts | None = None
        admitted = False
        try:
            try:
                capability = callbacks.driver_recover_process(  # type: ignore[misc]
                    record, command=command,
                    executable_capability=executable_capability,
                    mount_capabilities=lease.capabilities,
                    mounted_identity_sha256=lease.identity_sha256,
                )
            except Exception:
                raise AppleContainerAmbiguousError(
                    "native driver process recovery is unproven"
                ) from None
            if capability is None:
                if not allow_new_start:
                    raise AppleContainerAmbiguousError(
                        "attached driver process effect cannot be recovered"
                    )
                try:
                    capability = callbacks.driver_start(  # type: ignore[misc]
                        command, executable_capability=executable_capability,
                        mount_capabilities=lease.capabilities,
                        mounted_identity_sha256=lease.identity_sha256,
                        provenance=self._version_pin.provenance,  # type: ignore[union-attr]
                        container_id=spec.name, attempt_id=request.attempt_id,
                        spec_sha256=spec.fingerprint,
                        launch_request_sha256=request.request_sha256,
                        launch_policy_sha256=request.launch_policy_sha256,
                        driver_argv_sha256=request.driver_argv_sha256,
                        driver_environment_sha256=request.driver_environment_sha256,
                        driver_cwd_sha256=request.driver_cwd_sha256,
                        driver_stdin_sha256=request.driver_stdin_sha256,
                        pass_fd_roster_sha256=request.pass_fd_roster_sha256,
                        start_operation_nonce=record.start_operation_nonce,
                        rosetta_required=spec.rosetta_required,
                        guest_network_policy_sha256=spec.network_policy_sha256,
                        guest_network_topology_sha256=spec.networks[0].topology_sha256,
                        timeout=self._timeout, output_limit=self._output_limit,
                        deny_host_network=True,
                    )
                except Exception:
                    raise AppleContainerAmbiguousError(
                        "attached driver start outcome is journalled as ambiguous"
                    ) from None
            facts = self._validate_driver_process(
                capability, spec=spec, request=request, record=record,
                command=command, executable_capability=executable_capability,
                mount_lease=lease,
            )
            process_facts = facts
            self._revalidate_lease(lease)
            admitted = True
            return capability, facts
        finally:
            try:
                self._finish_async_executable(executable_capability)
            except Exception:
                if capability is not None:
                    if process_facts is not None:
                        try:
                            self._abort_started_driver(
                                request, capability, process_facts,
                                owns_start_claim=allow_new_start,
                            )
                        finally:
                            with _REGISTRY_LOCK:
                                _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)
                    else:
                        self._discard_unadmitted_driver_process(capability)
                raise
            else:
                if capability is not None and not admitted:
                    if process_facts is not None:
                        try:
                            self._abort_started_driver(
                                request, capability, process_facts,
                                owns_start_claim=allow_new_start,
                            )
                        finally:
                            with _REGISTRY_LOCK:
                                _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)
                    else:
                        self._discard_unadmitted_driver_process(capability)

    def _burn_driver_process(
        self, start: DriverStartResult,
    ) -> tuple[object, _DriverProcessFacts]:
        self._guard_process()
        capability = getattr(start, "process_capability", None)
        with _REGISTRY_LOCK:
            facts = _TEST_ONLY_DRIVER_PROCESS_REGISTRY.get(id(capability))
            if (facts is None or facts.capability is not capability
                    or facts.consumed or facts.revoked):
                raise AppleContainerUnavailableError(
                    "driver process capability is unavailable"
                )
            # Burn before validating any caller-controlled receipt field.
            facts.consumed = True
        if type(start) is not DriverStartResult or type(start.receipt) is not DriverStartReceipt:
            raise AppleContainerMismatchError("driver start result is not canonical")
        return capability, facts

    def _revoke_driver_process(
        self, capability: object, facts: _DriverProcessFacts, *,
        wait_operation_nonce: str, reason: str,
        expected_cleanup_sha256: str | None = None,
        expected_extinction_sha256: str | None = None,
        expected_stop_argv_sha256: str | None = None,
        expected_stop_stdout_sha256: str | None = None,
        expected_stop_stderr_sha256: str | None = None,
        expected_stopped_observation_sha256: str | None = None,
        expected_guest_population_extinction_sha256: str | None = None,
    ) -> None:
        self._guard_process()
        callbacks = self._require_driver_callbacks()
        try:
            callbacks.driver_revoke(  # type: ignore[misc]
                capability, wait_operation_nonce=wait_operation_nonce,
                reason=reason,
            )
        except Exception:
            raise AppleContainerAmbiguousError(
                "driver extinction and network revocation are unproven"
            ) from None
        if (not facts.revoked or not facts.native_process_extinct
                or not facts.guest_process_extinct
                or not facts.backend_egress_revoked
                or not facts.stop_control_process_reaped
                or not facts.stop_control_process_group_extinct
                or not facts.guest_population_zero
                or not facts.container_vm_stopped
                or not isinstance(facts.cleanup_sha256, str)
                or _HEX64.fullmatch(facts.cleanup_sha256) is None
                or not isinstance(facts.native_process_extinction_sha256, str)
                or _HEX64.fullmatch(facts.native_process_extinction_sha256) is None
                or any(not isinstance(value, str)
                       or _HEX64.fullmatch(value) is None for value in (
                           facts.stop_argv_sha256, facts.stop_stdout_sha256,
                           facts.stop_stderr_sha256,
                           facts.stopped_observation_sha256,
                           facts.guest_population_extinction_sha256,
                       ))
                or (expected_cleanup_sha256 is not None
                    and facts.cleanup_sha256 != expected_cleanup_sha256)
                or (expected_extinction_sha256 is not None
                    and facts.native_process_extinction_sha256
                       != expected_extinction_sha256)
                or (expected_stop_argv_sha256 is not None
                    and facts.stop_argv_sha256 != expected_stop_argv_sha256)
                or (expected_stop_stdout_sha256 is not None
                    and facts.stop_stdout_sha256 != expected_stop_stdout_sha256)
                or (expected_stop_stderr_sha256 is not None
                    and facts.stop_stderr_sha256 != expected_stop_stderr_sha256)
                or (expected_stopped_observation_sha256 is not None
                    and facts.stopped_observation_sha256
                       != expected_stopped_observation_sha256)
                or (expected_guest_population_extinction_sha256 is not None
                    and facts.guest_population_extinction_sha256
                       != expected_guest_population_extinction_sha256)):
            raise AppleContainerAmbiguousError(
                "driver extinction and network revocation are unproven"
            )

    def _abort_started_driver(
        self, request: DriverLaunchRequest, capability: object,
        facts: _DriverProcessFacts, *, owns_start_claim: bool,
    ) -> None:
        """Extinguish an undelivered start and durably bind the terminal debt."""
        self._guard_process()
        # State and claim authority are checked before the irreversible native
        # revoke.  In particular, a cold WAIT_CLAIMED recovery may hold a
        # duplicate process handle while another provider owns the wait; that
        # loser must never kill the live process during local cleanup.
        current = self._load_driver_record(request)
        if current is None or current.state not in {
            DriverLifecycleState.START_CLAIMED,
            DriverLifecycleState.START_EFFECT,
            DriverLifecycleState.START_COMMITTED,
            DriverLifecycleState.START_ABORTED,
        }:
            raise AppleContainerAmbiguousError(
                "driver start cleanup journal is unavailable"
            )
        if (current.state is DriverLifecycleState.START_CLAIMED
                and owns_start_claim is not True):
            raise AppleContainerAmbiguousError(
                "driver start cleanup claim is unavailable"
            )
        effect_sha256 = _driver_start_effect_sha256(facts)
        if current.state in {
            DriverLifecycleState.START_EFFECT,
            DriverLifecycleState.START_COMMITTED,
            DriverLifecycleState.START_ABORTED,
        } and (
            current.native_process_id != facts.native_process_id
            or current.native_process_handle_sha256
               != facts.native_process_handle_sha256
            or current.start_timestamp != facts.start_timestamp
            or current.start_effect_sha256 != effect_sha256
        ):
            raise AppleContainerAmbiguousError(
                "driver start cleanup identity differs"
            )
        if current.state is DriverLifecycleState.START_ABORTED:
            if (
                current.start_abort_extinction_sha256
                   != facts.native_process_extinction_sha256
                or current.start_abort_cleanup_sha256 != facts.cleanup_sha256
                or current.start_abort_egress_revoked is not True
            ):
                raise AppleContainerAmbiguousError(
                    "driver start cleanup evidence differs"
                )
            return
        self._revoke_driver_process(
            capability, facts, wait_operation_nonce="0" * 32,
            reason="START_POST_EFFECT_FAILURE",
        )
        aborted = _transition_driver_record(
            current, DriverLifecycleState.START_ABORTED,
            native_process_id=facts.native_process_id,
            native_process_handle_sha256=facts.native_process_handle_sha256,
            start_timestamp=facts.start_timestamp,
            start_effect_sha256=effect_sha256,
            start_abort_extinction_sha256=
                facts.native_process_extinction_sha256,
            start_abort_cleanup_sha256=facts.cleanup_sha256,
            start_abort_egress_revoked=True,
        )
        self._store_driver_record(aborted, current, effect_started=True)

    def _validate_wait_evidence(
        self, result: RunnerResult, *, capability: object,
        facts: _DriverProcessFacts, record: DriverLifecycleRecord,
    ) -> _DriverWaitEvidence:
        self._guard_process()
        with _REGISTRY_LOCK:
            evidence = _TEST_ONLY_DRIVER_WAIT_REGISTRY.pop(id(result), None)
        invalid = (
            type(result) is not RunnerResult
            or evidence is None or evidence.owner is not self._authority
            or evidence.result is not result
            or evidence.process_capability is not capability
            or evidence.native_process_handle_sha256
               != facts.native_process_handle_sha256
            or evidence.wait_operation_nonce != record.wait_operation_nonce
            or evidence.start_timestamp != facts.start_timestamp
            or not isinstance(evidence.end_timestamp, str)
            or not isinstance(evidence.native_process_extinction_sha256, str)
            or _HEX64.fullmatch(evidence.native_process_extinction_sha256) is None
            or not isinstance(evidence.cleanup_sha256, str)
            or _HEX64.fullmatch(evidence.cleanup_sha256) is None
            or any(not isinstance(value, str) or _HEX64.fullmatch(value) is None
                   for value in (evidence.stop_argv_sha256,
                                 evidence.stop_stdout_sha256,
                                 evidence.stop_stderr_sha256,
                                 evidence.stopped_observation_sha256,
                                 evidence.guest_population_extinction_sha256))
            or evidence.descendants_extinct is not True
            or evidence.guest_process_extinct is not True
            or evidence.backend_egress_revoked is not True
            or evidence.stop_control_process_reaped is not True
            or evidence.stop_control_process_group_extinct is not True
            or evidence.guest_population_zero is not True
            or evidence.container_vm_stopped is not True
            or type(result.returncode) is not int
            or not 0 <= result.returncode <= 255
            or len(result.stdout) > DRIVER_MAX_OUTPUT_BYTES
            or len(result.stderr) > DRIVER_MAX_OUTPUT_BYTES
            or result.stdout_observed_bytes > DRIVER_MAX_TOTAL_OUTPUT_BYTES
            or result.stderr_observed_bytes > DRIVER_MAX_TOTAL_OUTPUT_BYTES
        )
        if invalid or evidence is None:
            raise AppleContainerProtocolError(
                "native driver wait evidence is malformed"
            )
        if (_timestamp_value(evidence.end_timestamp, "driver end timestamp")
                < _timestamp_value(facts.start_timestamp, "driver start timestamp")):
            raise AppleContainerProtocolError(
                "driver end timestamp precedes its start"
            )
        return evidence

    def _native_wait_or_recover(
        self, capability: object, facts: _DriverProcessFacts,
        record: DriverLifecycleRecord, *, allow_new_wait: bool,
    ) -> tuple[RunnerResult, _DriverWaitEvidence]:
        self._guard_process()
        callbacks = self._require_driver_callbacks()
        try:
            try:
                result = callbacks.driver_recover_wait(  # type: ignore[misc]
                    record, process_capability=capability,
                    wait_operation_nonce=record.wait_operation_nonce,
                    output_limit=DRIVER_MAX_OUTPUT_BYTES,
                )
            except Exception:
                raise AppleContainerAmbiguousError(
                    "native driver wait recovery is unproven"
                ) from None
            if result is None:
                if not allow_new_wait:
                    raise AppleContainerAmbiguousError(
                        "driver wait effect cannot be recovered"
                    )
                try:
                    result = callbacks.driver_wait(  # type: ignore[misc]
                        capability,
                        wait_operation_nonce=record.wait_operation_nonce,
                        timeout=self._timeout,
                        output_limit=DRIVER_MAX_OUTPUT_BYTES,
                    )
                except Exception:
                    raise AppleContainerAmbiguousError(
                        "driver wait outcome is journalled as ambiguous"
                    ) from None
            evidence = self._validate_wait_evidence(
                result, capability=capability, facts=facts, record=record,
            )
        except Exception:
            # Only the caller which won the durable WAIT_CLAIMED CAS may
            # terminate on a failed new wait.  A cold loser may hold a
            # duplicate recovery handle, but revoking it could kill the
            # process from under the actual claim owner.
            if allow_new_wait:
                self._revoke_driver_process(
                    capability, facts,
                    wait_operation_nonce=record.wait_operation_nonce or "0" * 32,
                    reason="WAIT_FAILURE",
                )
            with _REGISTRY_LOCK:
                _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)
            raise
        self._revoke_driver_process(
            capability, facts,
            wait_operation_nonce=record.wait_operation_nonce or "0" * 32,
            reason="WAIT_COMPLETE",
            expected_cleanup_sha256=evidence.cleanup_sha256,
            expected_extinction_sha256=evidence.native_process_extinction_sha256,
            expected_stop_argv_sha256=evidence.stop_argv_sha256,
            expected_stop_stdout_sha256=evidence.stop_stdout_sha256,
            expected_stop_stderr_sha256=evidence.stop_stderr_sha256,
            expected_stopped_observation_sha256=
                evidence.stopped_observation_sha256,
            expected_guest_population_extinction_sha256=
                evidence.guest_population_extinction_sha256,
        )
        return result, evidence

    def _complete_driver_wait(
        self, spec: ContainerSpec, request: DriverLaunchRequest,
        capability: object, facts: _DriverProcessFacts,
        current: DriverLifecycleRecord, *, allow_new_wait: bool,
    ) -> DriverWaitResult:
        self._guard_process()
        try:
            result, evidence = self._native_wait_or_recover(
                capability, facts, current, allow_new_wait=allow_new_wait,
            )
            effect_sha256 = _driver_wait_effect_sha256(current, result, evidence)
            if current.state is DriverLifecycleState.WAIT_CLAIMED:
                effect = _transition_driver_record(
                    current, DriverLifecycleState.WAIT_EFFECT,
                    end_timestamp=evidence.end_timestamp,
                    exit_code=result.returncode,
                    stdout_sha256=result.stdout_full_sha256,
                    stderr_sha256=result.stderr_full_sha256,
                    stdout_retained_sha256=
                        hashlib.sha256(result.stdout).hexdigest(),
                    stderr_retained_sha256=
                        hashlib.sha256(result.stderr).hexdigest(),
                    stdout_observed_bytes=result.stdout_observed_bytes,
                    stderr_observed_bytes=result.stderr_observed_bytes,
                    stdout_retained_bytes=len(result.stdout),
                    stderr_retained_bytes=len(result.stderr),
                    stdout_truncated=result.stdout_observed_bytes != len(result.stdout),
                    stderr_truncated=result.stderr_observed_bytes != len(result.stderr),
                    native_process_extinction_sha256=
                        evidence.native_process_extinction_sha256,
                    cleanup_sha256=evidence.cleanup_sha256,
                    stop_argv_sha256=evidence.stop_argv_sha256,
                    stop_stdout_sha256=evidence.stop_stdout_sha256,
                    stop_stderr_sha256=evidence.stop_stderr_sha256,
                    stopped_observation_sha256=
                        evidence.stopped_observation_sha256,
                    guest_population_extinction_sha256=
                        evidence.guest_population_extinction_sha256,
                    descendants_extinct=evidence.descendants_extinct,
                    guest_process_extinct=evidence.guest_process_extinct,
                    backend_egress_revoked=evidence.backend_egress_revoked,
                    stop_control_process_reaped=
                        evidence.stop_control_process_reaped,
                    stop_control_process_group_extinct=
                        evidence.stop_control_process_group_extinct,
                    guest_population_zero=evidence.guest_population_zero,
                    container_vm_stopped=evidence.container_vm_stopped,
                    wait_effect_sha256=effect_sha256,
                )
                current = self._store_driver_record(
                    effect, current, effect_started=True,
                )
            else:
                expected = (
                    current.end_timestamp, current.exit_code,
                    current.stdout_sha256, current.stderr_sha256,
                    current.stdout_retained_sha256,
                    current.stderr_retained_sha256,
                    current.stdout_observed_bytes, current.stderr_observed_bytes,
                    current.stdout_retained_bytes, current.stderr_retained_bytes,
                    current.stdout_truncated, current.stderr_truncated,
                    current.native_process_extinction_sha256,
                    current.cleanup_sha256, current.stop_argv_sha256,
                    current.stop_stdout_sha256, current.stop_stderr_sha256,
                    current.stopped_observation_sha256,
                    current.guest_population_extinction_sha256,
                    current.descendants_extinct,
                    current.guest_process_extinct,
                    current.backend_egress_revoked,
                    current.stop_control_process_reaped,
                    current.stop_control_process_group_extinct,
                    current.guest_population_zero, current.container_vm_stopped,
                    current.wait_effect_sha256,
                )
                actual = (
                    evidence.end_timestamp, result.returncode,
                    result.stdout_full_sha256, result.stderr_full_sha256,
                    hashlib.sha256(result.stdout).hexdigest(),
                    hashlib.sha256(result.stderr).hexdigest(),
                    result.stdout_observed_bytes, result.stderr_observed_bytes,
                    len(result.stdout), len(result.stderr),
                    result.stdout_observed_bytes != len(result.stdout),
                    result.stderr_observed_bytes != len(result.stderr),
                    evidence.native_process_extinction_sha256,
                    evidence.cleanup_sha256, evidence.stop_argv_sha256,
                    evidence.stop_stdout_sha256, evidence.stop_stderr_sha256,
                    evidence.stopped_observation_sha256,
                    evidence.guest_population_extinction_sha256,
                    evidence.descendants_extinct,
                    evidence.guest_process_extinct,
                    evidence.backend_egress_revoked,
                    evidence.stop_control_process_reaped,
                    evidence.stop_control_process_group_extinct,
                    evidence.guest_population_zero,
                    evidence.container_vm_stopped, effect_sha256,
                )
                if expected != actual:
                    raise AppleContainerMismatchError(
                        "recovered driver exit differs from its journalled effect"
                    )
            if current.state is DriverLifecycleState.WAIT_EFFECT:
                current = self._store_driver_record(
                    _transition_driver_record(
                        current, DriverLifecycleState.WAIT_COMMITTED,
                    ),
                    current, effect_started=True,
                )
            return _wait_result_from_record(current, result)
        finally:
            with _REGISTRY_LOCK:
                _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)

    def wait_driver(
        self, spec: ContainerSpec, request: DriverLaunchRequest,
        start: DriverStartResult,
    ) -> DriverWaitResult:
        self._guard_process()
        with self._lock:
            capability, facts = self._burn_driver_process(start)
            wait_nonce = "0" * 32
            try:
                _validate_launch_for_spec(spec, request)
                current = self._load_driver_record(request)
                if (current is None
                        or current.state is not DriverLifecycleState.START_COMMITTED):
                    raise AppleContainerMismatchError(
                        "driver start commitment is unavailable"
                    )
                canonical_start = _start_receipt_from_record(current)
                if (start.receipt != canonical_start
                        or facts.owner is not self._authority
                        or facts.container_id != spec.name
                        or facts.attempt_id != request.attempt_id
                        or facts.spec_sha256 != spec.fingerprint
                        or facts.launch_request_sha256 != request.request_sha256
                        or facts.launch_policy_sha256 != request.launch_policy_sha256
                        or facts.driver_argv_sha256 != request.driver_argv_sha256
                        or facts.driver_environment_sha256
                           != request.driver_environment_sha256
                        or facts.driver_cwd_sha256 != request.driver_cwd_sha256
                        or facts.driver_stdin_sha256 != request.driver_stdin_sha256
                        or facts.pass_fd_roster_sha256
                           != request.pass_fd_roster_sha256
                        or facts.native_process_id != current.native_process_id
                        or facts.native_process_handle_sha256
                           != current.native_process_handle_sha256):
                    raise AppleContainerMismatchError(
                        "driver start result differs from its durable commitment"
                    )
                armed = _transition_driver_record(
                    current, DriverLifecycleState.WAIT_ARMED,
                    wait_operation_nonce=secrets.token_hex(16),
                    start_receipt_sha256=canonical_start.receipt_sha256,
                    start_journal_checkpoint_sha256=current.journal_checkpoint_sha256,
                )
                wait_nonce = armed.wait_operation_nonce or wait_nonce
                current = self._store_driver_record(
                    armed, current, effect_started=False,
                )
                current = self._store_driver_record(
                    _transition_driver_record(
                        current, DriverLifecycleState.WAIT_CLAIMED,
                    ),
                    current, effect_started=False,
                )
                return self._complete_driver_wait(
                    spec, request, capability, facts, current,
                    allow_new_wait=True,
                )
            except Exception:
                if not facts.revoked:
                    self._revoke_driver_process(
                        capability, facts, wait_operation_nonce=wait_nonce,
                        reason="WAIT_FAILURE",
                    )
                with _REGISTRY_LOCK:
                    _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)
                raise

    def recover_driver_wait(
        self, spec: ContainerSpec, request: DriverLaunchRequest,
    ) -> DriverWaitResult:
        self._guard_process()
        with self._lock:
            _validate_launch_for_spec(spec, request)
            current = self._load_driver_record(request)
            if current is None or current.state not in {
                DriverLifecycleState.WAIT_ARMED,
                DriverLifecycleState.WAIT_CLAIMED,
                DriverLifecycleState.WAIT_EFFECT,
                DriverLifecycleState.WAIT_COMMITTED,
            }:
                raise AppleContainerMismatchError(
                    "driver wait recovery has no durable authority"
                )
            lease = self._open_mount_lease(spec.mounts)
            try:
                owns_wait_claim = False
                if current.state is DriverLifecycleState.WAIT_ARMED:
                    current = self._store_driver_record(
                        _transition_driver_record(
                            current, DriverLifecycleState.WAIT_CLAIMED,
                        ),
                        current, effect_started=False,
                    )
                    owns_wait_claim = True
                capability, facts = self._native_start_or_recover(
                    spec, request, current, lease, allow_new_start=False,
                )
                with _REGISTRY_LOCK:
                    if facts.consumed or facts.revoked:
                        raise AppleContainerUnavailableError(
                            "recovered driver process capability is unavailable"
                        )
                    facts.consumed = True
                return self._complete_driver_wait(
                    spec, request, capability, facts, current,
                    # Only the winner of the shared durable claim may invoke
                    # the one-shot native wait.  Existing claim/effect records
                    # are recovery-only.
                    allow_new_wait=owns_wait_claim,
                )
            finally:
                self._close_mount_lease(lease)

    def start_driver(
        self, spec: ContainerSpec, request: DriverLaunchRequest,
    ) -> DriverStartResult:
        self._guard_process()
        with self._lock:
            if self._preflight is None:
                raise AppleContainerUnavailableError("provider has not passed preflight")
            _validate_launch_for_spec(spec, request)
            self._require_driver_callbacks()
            lease = self._open_mount_lease(spec.mounts)
            capability: object | None = None
            delivered = False
            try:
                current = self._load_driver_record(request)
                owns_start_claim = False
                if current is None:
                    if self._recover_with_lease(spec, lease).decision is not RecoveryDecision.STOPPED_MATCH:
                        raise AppleContainerMismatchError(
                            "driver start requires an exact stopped container"
                        )
                    current = self._store_driver_record(
                        self._arm_driver_start(request), None,
                        effect_started=False,
                    )
                else:
                    if current.state in {
                        DriverLifecycleState.WAIT_ARMED,
                        DriverLifecycleState.WAIT_CLAIMED,
                        DriverLifecycleState.WAIT_EFFECT,
                        DriverLifecycleState.WAIT_COMMITTED,
                        DriverLifecycleState.START_ABORTED,
                    }:
                        raise AppleContainerMismatchError(
                            "driver start lifecycle has already advanced to wait"
                        )
                    with _REGISTRY_LOCK:
                        delivered = any(
                            facts.owner is self._authority
                            and facts.container_id == spec.name
                            and facts.attempt_id == request.attempt_id
                            and facts.launch_request_sha256 == request.request_sha256
                            and facts.delivered and not facts.consumed and not facts.revoked
                            for facts in _TEST_ONLY_DRIVER_PROCESS_REGISTRY.values()
                        )
                    if delivered:
                        raise AppleContainerMismatchError(
                            "driver start capability was already delivered"
                        )
                if current.state is DriverLifecycleState.START_ARMED:
                    # Claim the nonce durably before the external effect.  The
                    # authority CAS is shared by all provider instances, so at
                    # most one caller may originate the attached start.  A
                    # later caller seeing START_CLAIMED may only recover native
                    # evidence; it cannot infer that the first caller died
                    # before the effect and issue a duplicate start.
                    current = self._store_driver_record(
                        _transition_driver_record(
                            current, DriverLifecycleState.START_CLAIMED,
                        ),
                        current, effect_started=False,
                    )
                    owns_start_claim = True
                capability, facts = self._native_start_or_recover(
                    spec, request, current, lease,
                    allow_new_start=owns_start_claim,
                )
                effect_sha256 = _driver_start_effect_sha256(facts)
                if current.state is DriverLifecycleState.START_CLAIMED:
                    effect = _transition_driver_record(
                        current, DriverLifecycleState.START_EFFECT,
                        native_process_id=facts.native_process_id,
                        native_process_handle_sha256=facts.native_process_handle_sha256,
                        start_timestamp=facts.start_timestamp,
                        start_effect_sha256=effect_sha256,
                    )
                    current = self._store_driver_record(
                        effect, current, effect_started=True
                    )
                elif (current.native_process_id != facts.native_process_id
                      or current.native_process_handle_sha256
                         != facts.native_process_handle_sha256
                      or current.start_timestamp != facts.start_timestamp
                      or current.start_effect_sha256 != effect_sha256):
                    raise AppleContainerMismatchError(
                        "recovered driver process differs from its journalled effect"
                    )
                inspected_record = self._journal_load(spec.name)
                if inspected_record is None:
                    raise AppleContainerMismatchError(
                        "container creation authority is unavailable"
                    )
                inspected = self._inspect(spec, inspected_record, lease)
                if not inspected.matches or inspected.state != "running":
                    raise AppleContainerMismatchError(
                        "attached driver did not enter the exact running container"
                    )
                if current.state is DriverLifecycleState.START_EFFECT:
                    current = self._store_driver_record(
                        _transition_driver_record(
                            current, DriverLifecycleState.START_COMMITTED
                        ),
                        current, effect_started=True,
                    )
                receipt = _start_receipt_from_record(current)
                facts.delivered = True
                delivered = True
                return DriverStartResult(receipt, capability)
            finally:
                try:
                    self._close_mount_lease(lease)
                finally:
                    if capability is not None and not delivered:
                        facts = _driver_process_facts(capability)
                        try:
                            if facts is None or facts.owner is not self._authority:
                                self._discard_unadmitted_driver_process(capability)
                            elif not facts.revoked:
                                self._abort_started_driver(
                                    request, capability, facts,
                                    owns_start_claim=owns_start_claim,
                                )
                        finally:
                            with _REGISTRY_LOCK:
                                _TEST_ONLY_DRIVER_PROCESS_REGISTRY.pop(id(capability), None)

    def create(self, spec: ContainerSpec) -> OperationReceipt:
        self._guard_process()
        with self._lock:
            lease = self._open_mount_lease(spec.mounts)
            try:
                if self._recover_with_lease(spec, lease).decision != RecoveryDecision.ABSENT:
                    raise AppleContainerMismatchError("create requires an unoccupied exact identity")
                self._require_admitted_image(spec, mount_lease=lease)
                self._require_admitted_init_image(spec, mount_lease=lease)
                self._revalidate_lease(lease)
                pending, previous = self._prepare_pending(
                    spec, "create", "stopped", lease.identity_sha256
                )
                command = self._create_arguments(spec, pending)
                _validate_argv(
                    command, "create", create_spec=spec, create_record=pending
                )
                pending = self._persist_pending(pending, previous)
                return self._mutate_after_begin(
                    spec, pending, command, "create",
                    "stopped", lease=lease,
                )
            finally:
                self._close_mount_lease(lease)

    @staticmethod
    def _create_arguments(spec: ContainerSpec, record: MutationRecord) -> tuple[str, ...]:
        result = [
            "create", "--name", spec.name, "--platform", "linux/arm64", "--cpus",
            str(spec.cpus), "--memory", str(spec.memory_bytes), "--uid", str(spec.uid),
            "--gid", str(spec.gid), "--workdir", spec.working_directory,
            "--entrypoint", spec.entrypoint, "--read-only", "--init", "--cap-drop",
            "ALL", "--no-dns", "--init-image", spec.init_image_reference,
        ]
        if spec.rosetta_required:
            result.append("--rosetta")
        if spec.networks:
            for network in spec.networks:
                value = network.name
                if network.mac_address:
                    value += f",mac={network.mac_address.lower()}"
                value += f",mtu={network.mtu}"
                result.extend(("--network", value))
        for key, value in sorted(spec.expected_labels(record).items()):
            result.extend(("--label", f"{key}={value}"))
        for mount in sorted(spec.mounts, key=lambda item: item.target):
            value = f"type=bind,source={mount.source},target={mount.target}"
            if mount.readonly:
                value += ",readonly"
            result.extend(("--mount", value))
        result.append(spec.image_reference)
        result.extend(spec.arguments)
        return tuple(result)

    def _mutate_after_begin(self, spec: ContainerSpec, pending: MutationRecord,
                            command: tuple[str, ...], operation: str,
                            expected_state: str, *, lease: _MountLease,
                            timeout: int | None = None) -> OperationReceipt:
        self._guard_process()
        try:
            if pending.mount_identity_sha256 != lease.identity_sha256:
                raise AppleContainerMismatchError("mutation mount lease differs from journal")
            result = self._invoke(
                command, operation=operation, mount_lease=lease,
                deny_network=True, timeout_seconds=timeout,
                guest_network=spec.networks[0],
                create_spec=spec if operation == "create" else None,
                create_record=pending if operation == "create" else None,
            )
            _require_identity_output(result, spec.name, operation)
            if expected_state == "absent":
                if any(item.casefold() == spec.name.casefold()
                       for item in self._list_ids(spec, lease)):
                    raise AppleContainerMismatchError("delete did not prove exact absence")
                inspected = _InspectedContainer(spec.name, "absent", True,
                    _absence_digest(pending), _absence_digest(pending), None)
            else:
                inspected = self._inspect(spec, pending, lease)
                if not inspected.matches or inspected.state != expected_state:
                    raise AppleContainerMismatchError("mutation postcondition differs")
            self._complete(pending, inspected.configuration_sha256)
            return _operation_receipt(operation, inspected, spec, result)
        except AppleContainerAmbiguousError:
            raise
        except Exception:
            raise AppleContainerAmbiguousError(
                f"container {operation} outcome is journalled as ambiguous"
            ) from None

    def _transition(self, spec: ContainerSpec, container_id: str, *, operation: str,
                    required: RecoveryDecision, expected_state: str,
                    command: tuple[str, ...], timeout: int | None = None) -> OperationReceipt:
        self._guard_process()
        with self._lock:
            if container_id != spec.name:
                raise AppleContainerMismatchError("container ID does not match the spec")
            lease = self._open_mount_lease(spec.mounts)
            try:
                if self._recover_with_lease(spec, lease).decision != required:
                    raise AppleContainerMismatchError("lifecycle precondition differs")
                _validate_argv(command, operation)
                pending = self._begin(
                    spec, operation, expected_state, lease.identity_sha256
                )
                return self._mutate_after_begin(
                    spec, pending, command, operation, expected_state,
                    lease=lease, timeout=timeout,
                )
            finally:
                self._close_mount_lease(lease)

    def start(self, spec: ContainerSpec, container_id: str) -> OperationReceipt:
        self._guard_process()
        return self._transition(spec, container_id, operation="start",
                                required=RecoveryDecision.STOPPED_MATCH,
                                expected_state="running", command=("start", container_id))

    def stop(self, spec: ContainerSpec, container_id: str, *, grace_seconds: int = 10) -> OperationReceipt:
        self._guard_process()
        if (isinstance(grace_seconds, bool) or not isinstance(grace_seconds, int)
                or not 0 <= grace_seconds <= 295):
            raise AppleContainerConfigurationError("stop grace period is invalid")
        return self._transition(spec, container_id, operation="stop",
                                required=RecoveryDecision.RUNNING_MATCH,
                                expected_state="stopped",
                                command=("stop", "--time", str(grace_seconds), container_id),
                                timeout=max(self._timeout, grace_seconds + 5))

    def kill(self, spec: ContainerSpec, container_id: str) -> OperationReceipt:
        self._guard_process()
        return self._transition(spec, container_id, operation="kill",
                                required=RecoveryDecision.RUNNING_MATCH,
                                expected_state="stopped",
                                command=("kill", "--signal", "KILL", container_id))

    def delete(self, spec: ContainerSpec, container_id: str) -> OperationReceipt:
        self._guard_process()
        return self._transition(spec, container_id, operation="delete",
                                required=RecoveryDecision.STOPPED_MATCH,
                                expected_state="absent", command=("delete", container_id))

    def status(self, spec: ContainerSpec, container_id: str) -> RecoveryReceipt:
        self._guard_process()
        if container_id != spec.name:
            raise AppleContainerMismatchError("container ID does not match the spec")
        return self.recover(spec)

    inspect = status

    def logs(self, spec: ContainerSpec, container_id: str, *, lines: int = 1000,
             sink: Callable[[bytes, bytes], None] | None = None) -> LogsReceipt:
        self._guard_process()
        if (isinstance(lines, bool) or not isinstance(lines, int)
                or not 0 <= lines <= 100_000):
            raise AppleContainerConfigurationError("log line bound is invalid")
        with self._lock:
            lease = self._open_mount_lease(spec.mounts)
            try:
                if container_id != spec.name or self._recover_with_lease(spec, lease).decision not in {
                    RecoveryDecision.RUNNING_MATCH, RecoveryDecision.STOPPED_MATCH
                }:
                    raise AppleContainerMismatchError("logs target did not reconcile")
                result = self._invoke(
                    ("logs", "-n", str(lines), container_id), operation="logs",
                    mount_lease=lease, deny_network=True,
                    guest_network=spec.networks[0],
                )
                if sink is not None:
                    sink(result.stdout, result.stderr)
                state = self._recover_with_lease(spec, lease)
                inspected = _InspectedContainer(spec.name, state.observed_state or "unknown", True,
                                                state.observation_sha256 or "0" * 64,
                                                state.observation_sha256 or "0" * 64, None)
                base = _operation_receipt("logs", inspected, spec, result)
                return LogsReceipt(**base.__dict__)
            finally:
                self._close_mount_lease(lease)


_NATIVE_PROVIDER_TYPE_NAMES = (
    "NativeAuthorityConsumer", "SupervisorAuthorities", "ProviderAuthority",
)
_NATIVE_PROVIDER_METHODS = (
    "provider_kind", "create_stopped", "inspect_stopped", "resume_guest",
    "start_driver", "wait_driver", "delete_guest",
)


def _native_provider_surface() -> tuple[type[Any], type[Any], type[Any], object]:
    """Authenticate the preloaded native surface without executing imports."""
    try:
        module_table = types.ModuleType.__getattribute__(sys, "__dict__").get(
            "modules"
        )
        if type(module_table) is not dict:
            raise TypeError
        module = module_table.get(NATIVE_MODULE_NAME)
        if type(module) is not types.ModuleType:
            raise TypeError
        namespace = types.ModuleType.__getattribute__(module, "__dict__")
        spec = namespace.get("__spec__")
        if type(namespace) is not dict or type(spec) is not importlib.machinery.ModuleSpec:
            raise TypeError
        spec_namespace = object.__getattribute__(spec, "__dict__")
        loader = spec_namespace.get("loader")
        if type(loader) is not importlib.machinery.ExtensionFileLoader:
            raise TypeError
        loader_namespace = object.__getattribute__(loader, "__dict__")
        native_types = tuple(namespace.get(name) for name in _NATIVE_PROVIDER_TYPE_NAMES)
        metadata = (
            namespace.get("__name__"), namespace.get("__file__"),
            namespace.get("BROKER_V2_ABI_SCHEMA"),
            namespace.get("BROKER_V2_PRODUCTION_ACQUISITION"),
            spec_namespace.get("name"), spec_namespace.get("origin"),
            loader_namespace.get("name"), loader_namespace.get("path"),
        )
        if (any(type(item) is not str for item in metadata)
                or any(not item or len(item) > 4096 or "\x00" in item
                       for item in metadata)):
            raise TypeError
        name, module_file, abi, acquisition, spec_name, origin, loader_name, loader_path = metadata
        if (name != NATIVE_MODULE_NAME or spec_name != NATIVE_MODULE_NAME
                or loader_name != NATIVE_MODULE_NAME or module_file != origin
                or loader_path != origin or abi != NATIVE_ABI_SCHEMA
                or acquisition != NATIVE_PRODUCTION_ACQUISITION
                or namespace.get("TEST_ONLY_BUILD") is not False
                or namespace.get("BROKER_V2_INITIAL_AUTHORITY_AVAILABLE") is not True
                or not any(origin.endswith(suffix)
                           for suffix in importlib.machinery.EXTENSION_SUFFIXES)
                or any(type(item) is not type for item in native_types)):
            raise TypeError
        for native_type in native_types:
            if (type.__getattribute__(native_type, "__module__")
                    != NATIVE_MODULE_NAME
                    or type.__getattribute__(native_type, "__flags__") & (1 << 9)):
                raise TypeError
        consumer_type, bundle_type, provider_type = native_types
        for native_type in (consumer_type, bundle_type):
            type_namespace = type.__getattribute__(native_type, "__dict__")
            if (type(type_namespace) is not types.MappingProxyType
                    or type(type_namespace.get("consume_once"))
                       is not types.MethodDescriptorType):
                raise TypeError
        provider_namespace = type.__getattribute__(provider_type, "__dict__")
        if (type(provider_namespace) is not types.MappingProxyType
                or any(type(provider_namespace.get(method))
                       is not types.MethodDescriptorType
                       for method in _NATIVE_PROVIDER_METHODS)):
            raise TypeError
        initial = namespace.get("INITIAL_AUTHORITY")
        if type(initial) is not consumer_type:
            raise TypeError
        return consumer_type, bundle_type, provider_type, initial
    except BaseException:
        pass
    raise AppleContainerUnavailableError(
        "native Apple provider authority is unavailable"
    )


class AppleContainerProvider:
    """Production boundary reserved for native broker-v2 provider authority."""

    __slots__ = ()

    def __new__(cls, *_args: object, **kwargs: object) -> "AppleContainerProvider":
        # Native ABI/lifecycle completeness is authenticated before touching a
        # caller-provided capability or any provider input.
        _consumer_type, _bundle_type, provider_type, _initial = (
            _native_provider_surface()
        )
        authority = kwargs.get("authority")
        if type(authority) is not provider_type:
            raise AppleContainerUnavailableError(
                "native Apple provider authority is unavailable"
            )
        raise AppleContainerUnavailableError(
            "native Apple provider lifecycle adapter is unavailable"
        )

    @staticmethod
    def _unavailable(*_args: object, **_kwargs: object) -> None:
        _native_provider_surface()
        raise AppleContainerUnavailableError(
            "native Apple provider lifecycle adapter is unavailable"
        )

    create_stopped = _unavailable
    inspect_stopped = _unavailable
    resume_guest = _unavailable
    start_driver = _unavailable
    wait_driver = _unavailable
    delete_guest = _unavailable
    create = _unavailable
    delete = _unavailable


def _validate_argv(arguments: tuple[str, ...], operation: str, *,
                   create_spec: ContainerSpec | None = None,
                   create_record: MutationRecord | None = None) -> None:
    if not arguments or len(arguments) > MAX_ARG_COUNT:
        raise AppleContainerConfigurationError("CLI argument roster is invalid")
    total = 0
    for argument in arguments:
        if not isinstance(argument, str) or not argument:
            raise AppleContainerConfigurationError("CLI argument is invalid")
        encoded = argument.encode("utf-8")
        total += len(encoded)
        if (len(encoded) > MAX_SINGLE_ARG_BYTES or total > MAX_ARG_BYTES
                or unicodedata.normalize("NFC", argument) != argument
                or any(ord(character) < 0x20 or ord(character) == 0x7f for character in argument)):
            raise AppleContainerConfigurationError("CLI argument roster is invalid")
    exact = {
        "system-version": ("system", "version", "--format", "json"),
        "system-status": ("system", "status", "--format", "json"),
        "list": ("list", "--all", "--quiet"),
    }
    # System lifecycle is intentionally absent. In particular, this provider
    # never runs `system start`, whose default path may install/fetch a kernel.
    supported_operations = {
        *exact, "inspect", "start", "stop", "kill", "delete", "logs",
        "image-load", "image-inspect", "create", "driver-start",
    }
    if operation not in supported_operations:
        raise AppleContainerConfigurationError("CLI operation is unsupported")
    if operation in exact and arguments != exact[operation]:
        raise AppleContainerConfigurationError("CLI grammar is closed")
    if operation in {"inspect", "start", "delete"}:
        if len(arguments) != 2 or arguments[0] != operation:
            raise AppleContainerConfigurationError("CLI grammar is closed")
        _validate_container_id(arguments[1])
    if operation == "driver-start":
        if (len(arguments) != 3
                or arguments[:2] != ("start", "--attach")):
            raise AppleContainerConfigurationError("CLI grammar is closed")
        _validate_container_id(arguments[2])
    if operation == "kill" and (len(arguments) != 4 or arguments[:3] != ("kill", "--signal", "KILL")):
        raise AppleContainerConfigurationError("CLI grammar is closed")
    if operation == "stop" and (len(arguments) != 4 or arguments[:2] != ("stop", "--time")
                                or not arguments[2].isdigit()
                                or len(arguments[2]) > 3 or int(arguments[2]) > 295):
        raise AppleContainerConfigurationError("CLI grammar is closed")
    if operation == "logs" and (len(arguments) != 4 or arguments[:2] != ("logs", "-n")
                                or not arguments[2].isdigit()
                                or len(arguments[2]) > 6 or int(arguments[2]) > 100_000):
        raise AppleContainerConfigurationError("CLI grammar is closed")
    if operation in {"kill", "stop", "logs"}:
        _validate_container_id(arguments[-1])
    if operation == "image-load" and (len(arguments) != 4
                                      or arguments[:3] != ("image", "load", "--input")):
        raise AppleContainerConfigurationError("CLI grammar is closed")
    if operation == "image-load":
        _validate_absolute_path(arguments[-1], "image archive", posix=False)
        _validate_mount_source_policy(arguments[-1])
    if operation == "image-inspect" and (len(arguments) != 3
                                         or arguments[:2] != ("image", "inspect")):
        raise AppleContainerConfigurationError("CLI grammar is closed")
    if operation == "image-inspect" and _OCI_REFERENCE.fullmatch(arguments[-1]) is None:
        raise AppleContainerConfigurationError("image inspect reference is invalid")
    if operation == "image-inspect":
        _validate_oci_reference(arguments[-1])
    forbidden = {"pull", "--pull", "--force", "--registry", "--username", "--password",
                 "--token", "--credential", "--env", "-e"}
    if any(item.casefold() in forbidden
           or (item.startswith("-") and _looks_sensitive(item)) for item in arguments):
        raise AppleContainerConfigurationError("credential-bearing or mutable CLI option is forbidden")
    if operation == "create":
        if arguments[0] != "create":
            raise AppleContainerConfigurationError("CLI grammar is closed")
        allowed = {"--name", "--platform", "--cpus", "--memory", "--uid", "--gid",
                   "--workdir", "--entrypoint", "--read-only", "--init", "--cap-drop",
                   "--no-dns", "--init-image", "--network", "--label", "--mount",
                   "--rosetta"}
        index = 1
        valueless = {"--read-only", "--init", "--no-dns", "--rosetta"}
        repeatable = {"--label", "--mount"}
        seen: dict[str, int] = {}
        while index < len(arguments) and arguments[index].startswith("--"):
            flag = arguments[index]
            if flag not in allowed:
                raise AppleContainerConfigurationError("create CLI option is unsupported")
            seen[flag] = seen.get(flag, 0) + 1
            if flag not in repeatable and seen[flag] != 1:
                raise AppleContainerConfigurationError("create CLI option is duplicated")
            if flag in valueless:
                index += 1
            else:
                if index + 1 >= len(arguments) or arguments[index + 1].startswith("--"):
                    raise AppleContainerConfigurationError("create CLI option lacks a value")
                index += 2
        required_once = allowed - repeatable - {"--rosetta"}
        if not required_once.issubset(seen) or seen.get("--network") != 1:
            raise AppleContainerConfigurationError("create CLI isolation options are incomplete")
        if index >= len(arguments) or _OCI_REFERENCE.fullmatch(arguments[index]) is None:
            raise AppleContainerConfigurationError("create image position is invalid")
        _validate_oci_reference(arguments[index])
        if (type(create_spec) is not ContainerSpec
                or type(create_record) is not MutationRecord
                or create_record.state != MutationState.PENDING
                or create_record.identity != create_spec.name
                or create_record.spec_sha256 != create_spec.fingerprint
                or create_record.operation != "create"
                or create_record.expected_state != "stopped"):
            raise AppleContainerConfigurationError(
                "create CLI lacks exact admitted-spec authority"
            )
        if arguments != TEST_ONLY_AppleContainerProvider._create_arguments(create_spec, create_record):
            raise AppleContainerConfigurationError(
                "create CLI values or ordering differ from the admitted spec"
            )


def _validate_container_id(container_id: Any) -> None:
    if (not isinstance(container_id, str) or _SAFE_CONTAINER_ID.fullmatch(container_id) is None
            or ".." in container_id or unicodedata.normalize("NFC", container_id) != container_id):
        raise AppleContainerConfigurationError("container name is not canonical")


def _parse_mounts(value: Any) -> list[tuple[str, str, bool]]:
    parsed: list[tuple[str, str, bool]] = []
    for raw in _list(value, "container mounts"):
        mount = _mapping(raw, "container mount")
        if set(mount) != {"type", "source", "destination", "options"}:
            return [("<unsupported>", "<unsupported>", False)]
        if mount.get("type") not in ("virtiofs", {"virtiofs": {}}):
            return [("<unsupported>", "<unsupported>", False)]
        options = _list(mount.get("options"), "container mount options")
        if options not in ([], ["ro"]):
            return [("<unsupported>", "<unsupported>", False)]
        parsed.append((_string(mount.get("source"), "mount source"),
                       _string(mount.get("destination"), "mount destination"),
                       options == ["ro"]))
    return sorted(parsed)


def _parse_network_configurations(value: Any) -> list[tuple[str, str, int, str | None]]:
    parsed: list[tuple[str, str, int, str | None]] = []
    for raw in _list(value, "container networks"):
        network = _mapping(raw, "container network")
        if set(network) != {"network", "options"}:
            return [("<unsupported>", "<unsupported>", -1, None)]
        options = _mapping(network.get("options"), "network options")
        if (not {"hostname", "mtu"}.issubset(options)
                or not set(options).issubset({"hostname", "macAddress", "mtu"})):
            return [("<unsupported>", "<unsupported>", -1, None)]
        mac = options.get("macAddress")
        if mac is not None and not isinstance(mac, str):
            raise AppleContainerProtocolError("network MAC is malformed")
        parsed.append((_string(network.get("network"), "network name"),
                       _string(options.get("hostname"), "network hostname"),
                       _integer(options.get("mtu"), "network MTU", minimum=576, maximum=65535),
                       mac.lower() if mac else None))
    return sorted(parsed)


def _parse_network_attachments(
    value: Any,
) -> list[tuple[str, str, str, str, str | None, int, str | None]]:
    parsed: list[tuple[str, str, str, str, str | None, int, str | None]] = []
    required = {"network", "hostname", "ipv4Address", "ipv4Gateway"}
    allowed = required | {"ipv6Address", "macAddress", "mtu", "variant"}
    for raw in _list(value, "container network attachments"):
        attachment = _mapping(raw, "container network attachment")
        fields = set(attachment)
        if not required.issubset(fields) or not fields.issubset(allowed):
            return [("<unsupported>", "<unsupported>", "", "", None, -1, None)]
        if attachment.get("ipv6Address") is not None:
            return [("<unsupported>", "<unsupported>", "", "", None, -1, None)]
        address = _string(attachment.get("ipv4Address"), "network IPv4 address")
        gateway = _string(attachment.get("ipv4Gateway"), "network IPv4 gateway")
        try:
            if str(ipaddress.IPv4Interface(address)) != address:
                raise ValueError
            if str(ipaddress.IPv4Address(gateway)) != gateway:
                raise ValueError
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
            raise AppleContainerProtocolError("network attachment address is malformed") from None
        mac = attachment.get("macAddress")
        if mac is not None and not isinstance(mac, str):
            raise AppleContainerProtocolError("network MAC is malformed")
        variant = attachment.get("variant")
        if variant is not None and not isinstance(variant, str):
            raise AppleContainerProtocolError("network variant is malformed")
        parsed.append((
            _string(attachment.get("network"), "network name"),
            _string(attachment.get("hostname"), "network hostname"),
            address, gateway, mac.lower() if mac else None,
            _integer(attachment.get("mtu"), "network MTU", minimum=576, maximum=65535),
            variant,
        ))
    return sorted(parsed)


def _absence_digest(record: MutationRecord) -> str:
    return _canonical_digest({"attempt_nonce": record.attempt_nonce,
                              "generation": record.generation,
                              "id": record.identity, "state": "absent"})


def _require_identity_output(result: RunnerResult, container_id: str, operation: str) -> None:
    if result.stdout_observed_bytes != len(result.stdout):
        raise AppleContainerProtocolError(f"container {operation} identity output was truncated")
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeError:
        raise AppleContainerProtocolError(f"container {operation} identity output is invalid") from None
    if output not in {container_id, container_id + "\n"}:
        raise AppleContainerProtocolError(f"container {operation} returned an unexpected identity")


def _operation_receipt(operation: str, inspected: _InspectedContainer,
                       spec: ContainerSpec, result: RunnerResult) -> OperationReceipt:
    if result.stdout_full_sha256 is None or result.stderr_full_sha256 is None:
        raise AppleContainerProtocolError("full stream digests are unavailable")
    return OperationReceipt(
        operation, inspected.container_id, spec.fingerprint, inspected.state,
        result.stdout_full_sha256, result.stderr_full_sha256,
        result.stdout_observed_bytes, result.stderr_observed_bytes,
        result.stdout_observed_bytes != len(result.stdout),
        result.stderr_observed_bytes != len(result.stderr),
        spec.init_image_reference, spec.init_image_digest,
        spec.init_image_manifest_digest,
        spec.rosetta_required,
    )
