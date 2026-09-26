"""Deterministic, offline composition contract for the Plamen guest runtime.

The production entrypoint in this module is intentionally unavailable.  Python
cannot keep retained file descriptors, a build-guest process handle, and the
resulting publication authority away from code running in the same interpreter.
``materialize_runtime_image`` therefore fails on its first statement until the
native broker owns that boundary.

The explicit ``_TEST_ONLY_`` seam is a content compositor and verifier.  It
never opens a source pathname, executes a package hook, consults a package
cache, reads credentials, or performs network I/O.  Each payload and its source
manifest arrive as distinct, retained O_RDONLY descriptors.  The caller also
supplies an already-open, unlinked O_RDWR/O_RDONLY descriptor pair for the
output, so this module never reopens the result by pathname.

Raw Debian packages and wheels are deliberately *not* installed here.  Their
semantics require a pinned Linux build guest.  Such inputs raise the typed
``NetworklessLinuxBuilderRequired`` error before the output is touched; the
exception carries the exact broker protocol that a later native implementation
must authenticate.  The compositor accepts only already-installed canonical
trees and inert files produced by that protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import io
import json
import os
import posixpath
import re
import stat
import tarfile
import tempfile
from typing import Any, BinaryIO, Callable, Mapping, Sequence
import unicodedata
import zlib

import opengrep_release_policy as _opengrep_policy

try:  # pragma: no cover - Windows is a production hard-stop
    import fcntl as _fcntl
except ImportError:  # pragma: no cover
    _fcntl = None


SCHEMA_VERSION = "plamen.runtime_composition_manifest.test.v1"
SOURCE_MANIFEST_SCHEMA_VERSION = "plamen.runtime_source_manifest.test.v1"
NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION = (
    "plamen.runtime_composition_manifest.native-retained.v1"
)
APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION = (
    "plamen.runtime_composition_manifest.apple-container.v2"
)
APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SCHEMA = (
    "plamen.apple-container.runtime-image-generation-policy.v1"
)
APPLE_CONTAINER_IMAGE_GENERATION_POLICY_PATH = (
    "verification_policy/apple_container_runtime_image_generation.v1.json"
)
APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SHA256 = (
    "91cfd69a7ed61aaf04ca0c44c7136ba0a683f5ff72ec9e5b9e851e05699a94b3"
)
APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SIZE = 3_706
NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION = (
    "plamen.runtime_source_manifest.native-retained.v1"
)
NATIVE_RETAINED_AUTHENTICATION_SCOPE = "NATIVE_RETAINED_SOURCE_INPUT"
RECEIPT_SCHEMA_VERSION = "plamen.runtime_materialization_receipt.test.v1"
CENSUS_SCHEMA_VERSION = "plamen.installed_runtime_census.v1"
PROVENANCE_SCHEMA_VERSION = "plamen.source_output_provenance.v1"
BUILDER_PROTOCOL_SCHEMA_VERSION = "plamen.networkless_linux_builder.v1"

PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "file",
        "path": "verification_policy/apple_container_runtime_image_generation.v1.json",
    },
)

MAX_INPUT_BYTES = 8 * 1024 * 1024 * 1024
MAX_EXPANDED_BYTES = 12 * 1024 * 1024 * 1024
MAX_ENTRIES = 131_072
MAX_SOURCE_MANIFEST_BYTES = 64 * 1024
MAX_COMPOSITION_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PATH_BYTES = 240
MAX_COMPONENT_BYTES = 100
_READ_CHUNK = 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")

_REQUIRED_ROLES = (
    "base_rootfs",
    "debian_package_state",
    "plamen_guest",
    "cpython",
    "plamen_package",
    "codex",
    "claude",
    "foundry",
    "medusa",
    "solc_amd64",
    "amd64_compat",
)

# The released operation-4 wire above is intentionally immutable: its native
# producer signs an exact eleven-row denominator.  The next Apple Container
# image generation adds OpenGrep as a distinct, independently acquired static
# payload.  Keeping the candidate roster under a new schema prevents older
# native producers from silently signing a shifted ordinal table.
APPLE_CONTAINER_REQUIRED_ROLES = _REQUIRED_ROLES + ("opengrep",)

_APPLE_CONTAINER_STATIC_MEMBER_POLICY: tuple[Mapping[str, Any], ...] = (
    {
        "acquisition_policy": {
            "path": "verification_policy/foundry_acquisition.v1.json",
            "sha256": "b52bbbcd7eb6900bc6d6fdafbd45465cad4a47ab211ac5a1438f180f9e2eff6a",
            "size": 2_307,
        },
        "artifact_id": "foundry-1.8.1-linux-arm64",
        "payload": {
            "sha256": "b19dfe910e75b23aabd21f58181f561bca73d51a24be39fa3b900ecd5f0d288b",
            "size": 269_271_040,
        },
        "platform": "linux/arm64",
        "producer_receipt": {
            "path": "verification_policy/foundry_acquisition_receipt.v1.json",
            "schema": "plamen.foundry-acquisition-receipt.v1",
            "sha256": "1bd453b262415bc1153d4ecdecc99e134b96df45f3d511b7a2f144ed87ede436",
            "size": 1_616,
        },
        "required_paths": [
            "/usr/local/lib/plamen/toolchains/foundry/bin/anvil",
            "/usr/local/lib/plamen/toolchains/foundry/bin/cast",
            "/usr/local/lib/plamen/toolchains/foundry/bin/chisel",
            "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
        ],
        "role": "foundry",
        "source_manifest": {
            "path": "verification_policy/foundry_runtime_source_manifest.v1.json",
            "sha256": "6f380e0dd982ebc76a77e5c463b765c04ed440ebf2ed873bf691d4d927bed9f9",
            "size": 745,
        },
        "version": "1.8.1",
    },
    {
        "acquisition_policy": {
            "path": "verification_policy/medusa_acquisition.v1.json",
            "sha256": "4112703567b4c398207eaf09c75503840704be44b663a43e82fae42aa32a0208",
            "size": 1_696,
        },
        "artifact_id": "medusa-1.5.1-linux-x64",
        "payload": {
            "sha256": "86e54c586e49e6bf9676f448218e10475afacb0a8bd5ca1aea234f66db7169d6",
            "size": 23_748_448,
        },
        "platform": "linux/amd64",
        "producer_receipt": {
            "path": "verification_policy/medusa_acquisition_receipt.v1.json",
            "schema": "plamen.medusa-acquisition-receipt.v1",
            "sha256": "208b814ab650db58fb326d58930ae5db47162905a938e6c3532d9d6ff18a7f97",
            "size": 1_237,
        },
        "required_paths": ["/usr/local/lib/plamen/toolchains/medusa/bin/medusa"],
        "role": "medusa",
        "source_manifest": {
            "path": "verification_policy/medusa_runtime_source_manifest.v1.json",
            "sha256": "3353512eebb22a052ba2e5a87c2fe86055381b729498df3299b4d36dedf09260",
            "size": 555,
        },
        "version": "1.5.1",
    },
    {
        "acquisition_policy": {
            "path": _opengrep_policy.POLICY_PATH,
            "sha256": _opengrep_policy.POLICY_SHA256,
            "size": _opengrep_policy.POLICY_SIZE,
        },
        "artifact_id": _opengrep_policy.ARTIFACT_ID,
        "payload": {
            "sha256": _opengrep_policy.PAYLOAD_SHA256,
            "size": _opengrep_policy.PAYLOAD_SIZE,
        },
        "platform": _opengrep_policy.PLATFORM,
        "producer_receipt": None,
        "required_paths": [_opengrep_policy.INSTALL_PATH],
        "role": _opengrep_policy.ROLE,
        "source_manifest": {
            "path": _opengrep_policy.SOURCE_MANIFEST_PATH,
            "sha256": _opengrep_policy.SOURCE_MANIFEST_SHA256,
            "size": _opengrep_policy.SOURCE_MANIFEST_SIZE,
        },
        "version": _opengrep_policy.VERSION,
    },
)

_APPLE_CONTAINER_IMAGE_POLICY_MISSING_AUTHORITIES = (
    "APPLE_CONTAINER_RUNTIME_IMAGE_ADMISSION_RECEIPT",
    "NATIVE_OPERATION4_OPENGREP_ROLE_POLICY",
    "NATIVE_OPENGREP_SIGSTORE_ACQUISITION_RECEIPT",
    "NATIVE_RETAINED_FD_RUNTIME_MATERIALIZATION_RECEIPT",
    "PRODUCTION_OCI_LAYOUT_RECEIPT",
    "SIGNED_APPLE_CONTAINER_RUNTIME_IMAGE_GENERATION",
)

_ROLE_CONTRACT: Mapping[str, tuple[str, frozenset[str]]] = {
    "base_rootfs": ("/", frozenset({"application/vnd.plamen.canonical-rootfs.tar"})),
    "debian_package_state": (
        "/usr/local/lib/plamen/attestations/debian-packages.json",
        frozenset({"application/vnd.plamen.debian-package-state+json"}),
    ),
    "plamen_guest": (
        "/usr/local",
        frozenset({"application/vnd.plamen.preinstalled-tree.tar"}),
    ),
    "cpython": (
        "/usr",
        frozenset({"application/vnd.plamen.preinstalled-tree.tar"}),
    ),
    "plamen_package": (
        "/opt/plamen",
        frozenset({"application/vnd.plamen.preinstalled-tree.tar"}),
    ),
    "codex": (
        "/usr/local/lib/plamen/bin/codex",
        frozenset({"application/vnd.plamen.authenticated-tar-member"}),
    ),
    "claude": (
        "/usr/local/lib/plamen/bin/claude",
        frozenset({"application/vnd.plamen.authenticated-tar-member"}),
    ),
    "foundry": (
        "/usr/local/lib/plamen/toolchains/foundry",
        frozenset({"application/vnd.plamen.preinstalled-tree.tar"}),
    ),
    "medusa": (
        "/usr/local/lib/plamen/toolchains/medusa/bin/medusa",
        frozenset({"application/vnd.plamen.executable"}),
    ),
    "solc_amd64": (
        "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
        frozenset({"application/vnd.plamen.executable"}),
    ),
    "amd64_compat": (
        "/usr/local/lib/plamen/compat/amd64",
        frozenset({"application/vnd.plamen.preinstalled-tree.tar"}),
    ),
    "opengrep": (
        "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep",
        frozenset({"application/vnd.plamen.executable"}),
    ),
}

_REQUIRED_OUTPUTS: Mapping[str, tuple[str, ...]] = {
    "base_rootfs": (
        "/bin/sh",
        "/etc/passwd",
        "/lib/aarch64-linux-gnu/libc.so.6",
        "/lib/aarch64-linux-gnu/libdl.so.2",
        "/lib/aarch64-linux-gnu/libm.so.6",
        "/lib/aarch64-linux-gnu/libpthread.so.0",
        "/lib/aarch64-linux-gnu/librt.so.1",
        "/lib/ld-linux-aarch64.so.1",
        "/usr/bin/env",
        "/var/lib/dpkg/status",
    ),
    "debian_package_state": ("/usr/local/lib/plamen/attestations/debian-packages.json",),
    "plamen_guest": (
        "/usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
        "/usr/local/libexec/plamen-guest",
    ),
    "cpython": ("/usr/bin/python3",),
    "plamen_package": ("/opt/plamen/scripts/plamen_driver.py",),
    "codex": ("/usr/local/lib/plamen/bin/codex",),
    "claude": ("/usr/local/lib/plamen/bin/claude",),
    "foundry": (
        "/usr/local/lib/plamen/toolchains/foundry/bin/anvil",
        "/usr/local/lib/plamen/toolchains/foundry/bin/cast",
        "/usr/local/lib/plamen/toolchains/foundry/bin/chisel",
        "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
    ),
    "medusa": ("/usr/local/lib/plamen/toolchains/medusa/bin/medusa",),
    "solc_amd64": ("/usr/local/lib/plamen/toolchains/solc-amd64/solc",),
    "amd64_compat": ("/usr/local/lib/plamen/compat/amd64/lib64/ld-linux-x86-64.so.2",),
    "opengrep": ("/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep",),
}

_REQUIRED_EXECUTABLE_OUTPUTS = frozenset(
    {
        "/usr/local/libexec/plamen-guest",
        "/usr/bin/python3",
        "/usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
        "/usr/local/lib/plamen/bin/codex",
        "/usr/local/lib/plamen/bin/claude",
        "/usr/local/lib/plamen/toolchains/foundry/bin/anvil",
        "/usr/local/lib/plamen/toolchains/foundry/bin/cast",
        "/usr/local/lib/plamen/toolchains/foundry/bin/chisel",
        "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
        "/usr/local/lib/plamen/toolchains/medusa/bin/medusa",
        "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
        "/usr/local/lib/plamen/compat/amd64/lib64/ld-linux-x86-64.so.2",
        "/usr/local/lib/plamen/toolchains/opengrep/bin/opengrep",
    }
)
_ROLE_PLATFORM = {
    "base_rootfs": "linux/arm64",
    "debian_package_state": "linux/arm64",
    "plamen_guest": "linux/arm64",
    "cpython": "linux/arm64",
    "plamen_package": "linux/noarch",
    "codex": "linux/arm64",
    "claude": "linux/arm64",
    "foundry": "linux/arm64",
    "medusa": "linux/amd64",
    "solc_amd64": "linux/amd64",
    "amd64_compat": "linux/amd64",
    "opengrep": "linux/arm64",
}
_SOLC_EXECUTION_POLICY = {
    "binary": "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
    "binary_platform": "linux/amd64",
    "compatibility_root": "/usr/local/lib/plamen/compat/amd64",
    "foundry_binary": "/usr/local/lib/plamen/toolchains/foundry/bin/forge",
    "foundry_environment": ["FOUNDRY_OFFLINE=true"],
    "foundry_fixed_arguments": [
        "--offline",
        "--use",
        "/usr/local/lib/plamen/toolchains/solc-amd64/solc",
    ],
    "generic_linux_arm64": "DENY_WITHOUT_AUTHENTICATED_EMULATION",
    "macos_arm64_guest": "REQUEST_BOUND_ROSETTA_ONLY",
    "provider_inherited_environment": [],
}

# `/opt/plamen` is supplied later as the authenticated, read-only V3 source
# mount.  Nothing baked into the image may be placed beneath that mount except
# the `plamen_package` source tree itself, or the provider would hide the image
# bytes at launch.  Executable/runtime assets live in disjoint, root-owned
# namespaces and are invoked by absolute path rather than PATH lookup.
_PLAMEN_SOURCE_ROOT = "opt/plamen"
_BAKED_PLAMEN_ROOT = "usr/local/lib/plamen"
_GUEST_BOOTSTRAP = "usr/local/libexec/plamen-guest"
_GUEST_ARTIFACT_FILES = frozenset(
    {
        _GUEST_BOOTSTRAP,
        "usr/local/lib/plamen/native/cpython-312/_plamen_native_supervisor.so",
    }
)
_GUEST_ARTIFACT_DIRECTORIES = frozenset(
    parent
    for path in _GUEST_ARTIFACT_FILES
    for parent in (
        "/".join(path.split("/")[:index])
        for index in range(1, len(path.split("/")))
    )
)

_UNSUPPORTED_INSTALL_MEDIA = frozenset(
    {
        "application/vnd.debian.binary-package",
        "application/vnd.python.wheel",
    }
)
_ARCHIVE_MEDIA = frozenset(
    {
        "application/vnd.plamen.canonical-rootfs.tar",
        "application/vnd.plamen.preinstalled-tree.tar",
    }
)
_RAW_MEDIA = frozenset(
    {
        "application/vnd.plamen.executable",
        "application/vnd.plamen.authenticated-tar-member",
        "application/vnd.plamen.debian-package-state+json",
    }
)

_COMPOSITION_KEYS = frozenset(
    {
        "schema_version",
        "target",
        "authentication_scope",
        "network",
        "environment_denials",
        "limits",
        "installation_policy",
        "sources",
    }
)
_SOURCE_KEYS = frozenset(
    {
        "artifact_id",
        "role",
        "media_type",
        "destination",
        "payload_sha256",
        "payload_size",
        "source_manifest_sha256",
        "source_manifest_size",
        "required_paths",
    }
)
_SOURCE_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "artifact_id",
        "role",
        "media_type",
        "version",
        "platform",
        "source_reference",
        "authentication_scope",
        "payload_sha256",
        "payload_size",
        "required_paths",
    }
)
_BACKEND_ARCHIVE_SOURCE_MANIFEST_KEYS = _SOURCE_MANIFEST_KEYS | frozenset(
    {
        "archive_member",
        "archive_member_count",
        "archive_member_roster_sha256",
        "installed_sha256",
        "installed_size",
    }
)
_LIMITS = {
    "input_bytes": MAX_INPUT_BYTES,
    "expanded_bytes": MAX_EXPANDED_BYTES,
    "entries": MAX_ENTRIES,
}
_ENVIRONMENT_DENIALS = {"exact_names": ["GLIBC_TUNABLES"], "prefixes": ["LD_"]}
_INSTALLATION_POLICY = {
    "ambient_caches": "DENY",
    "dpkg": "NETWORKLESS_LINUX_BUILDER_ONLY",
    "pip": "NETWORKLESS_LINUX_BUILDER_ONLY",
    "package_scripts": "AUTHENTICATED_AND_CENSUSED_IN_BUILD_GUEST",
    "triggers": "AUTHENTICATED_AND_CENSUSED_IN_BUILD_GUEST",
}

_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "production_authority",
        "target",
        "archive",
        "composition_manifest_sha256",
        "source_roster_sha256",
        "installed",
        "environment_denials",
        "network",
        "package_execution",
        "next_required_authority",
        "solc_execution_policy",
    }
)
_ARCHIVE_RECEIPT_KEYS = frozenset({"media_type", "sha256", "size", "diff_id"})
_INSTALLED_RECEIPT_KEYS = frozenset(
    {"entry_count", "expanded_bytes", "census_sha256", "sbom_sha256", "provenance_sha256"}
)
_PACKAGE_EXECUTION_KEYS = frozenset(
    {
        "compositor_executed_scripts",
        "compositor_executed_triggers",
        "observed_installer_script_entries",
        "observed_trigger_entries",
    }
)

NETWORKLESS_LINUX_BUILDER_PROTOCOL: Mapping[str, Any] = {
    "schema_version": BUILDER_PROTOCOL_SCHEMA_VERSION,
    "authority": "NATIVE_RETAINED_FD_BUILD_GUEST_BROKER_REQUIRED",
    "target": "linux/arm64",
    "network": "DENY",
    "input_handoff": "EXACT_ORDERED_O_RDONLY_DESCRIPTOR_ROSTER",
    "output_handoff": "UNLINKED_SAME_INODE_RDWR_RDONLY_DESCRIPTOR_PAIR",
    "environment": {
        "allow": [
            "HOME=/nonexistent",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "PIP_CONFIG_FILE=/dev/null",
            "PIP_DISABLE_PIP_VERSION_CHECK=1",
            "PIP_NO_CACHE_DIR=1",
            "PYTHONHASHSEED=0",
            "SOURCE_DATE_EPOCH=0",
        ],
        "deny_exact": ["GLIBC_TUNABLES"],
        "deny_prefix": ["LD_"],
    },
    "package_inputs": {
        "amd64_compat": "PINNED_EXTRACT_ONLY_NO_POSTINSTALL_REQUEST_BOUND_ROSETTA",
        "debian": "EXACT_HASHED_DEB_ROSTER_NO_APT_RESOLUTION",
        "python": "EXACT_HASHED_WHEEL_ROSTER_NO_INDEX_NO_DEPS_REQUIRE_HASHES",
    },
    "required_evidence": [
        "authenticated_base_and_input_descriptor_roster",
        "installer_binary_and_argument_digest",
        "network_namespace_denial_receipt",
        "maintainer_script_and_trigger_digest_roster",
        "wheel_entrypoint_and_installer-metadata_digest_roster",
        "complete_installed_file_census",
        "source_to_output_provenance",
        "same_fd_recursive_elf_and_shebang_closure",
        "durable_start_wait_recover_revoke_receipts",
    ],
    "terminal_output": "CANONICAL_PREINSTALLED_TREE_DESCRIPTORS_ONLY",
}


class RuntimeMaterializationError(RuntimeError):
    """The runtime composition evidence or descriptor set is invalid."""


class RuntimeMaterializationUnsupported(RuntimeMaterializationError):
    """A production operation lacks native retained-FD authority."""


class NetworklessLinuxBuilderRequired(RuntimeMaterializationUnsupported):
    """Safe package installation requires the authenticated Linux builder."""

    def __init__(self, artifact_ids: Sequence[str]) -> None:
        self.artifact_ids = tuple(artifact_ids)
        self.protocol_bytes = _canonical_json(NETWORKLESS_LINUX_BUILDER_PROTOCOL)
        super().__init__(
            "NETWORKLESS_LINUX_BUILDER_REQUIRED:" + ",".join(self.artifact_ids)
        )


@dataclass(frozen=True, slots=True)
class RetainedRuntimeInput:
    """TEST_ONLY ownership transfer for one payload/manifest descriptor pair."""

    artifact_id: str
    payload_descriptor: int
    source_manifest_descriptor: int


@dataclass(frozen=True, slots=True)
class TestOnlyMaterializedRuntime:
    """Content evidence only; this object is never release authority."""

    archive_descriptor: int
    receipt_bytes: bytes
    census_bytes: bytes
    sbom_bytes: bytes
    provenance_bytes: bytes


@dataclass(frozen=True, slots=True)
class _FDIdentity:
    dev: int
    ino: int
    mode: int
    uid: int
    gid: int
    size: int
    mtime_ns: int
    ctime_ns: int


@dataclass(slots=True)
class _Entry:
    path: str
    kind: str
    mode: int
    size: int
    sha256: str | None
    offset: int | None
    sources: list[str]
    installer_script: bool = False
    trigger_metadata: bool = False
    linkname: str = ""


class _PreadFile(io.RawIOBase):
    """Seekable descriptor view whose cursor is not shared with the caller."""

    def __init__(self, descriptor: int, size: int) -> None:
        self._descriptor = descriptor
        self._size = size
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("invalid seek mode")
        if position < 0:
            raise ValueError("negative seek position")
        self._position = position
        return position

    def readinto(self, buffer: Any) -> int:
        if self._position >= self._size:
            return 0
        count = min(len(buffer), self._size - self._position)
        data = os.pread(self._descriptor, count, self._position)
        if not data:
            raise RuntimeMaterializationError("retained archive payload was truncated")
        buffer[: len(data)] = data
        self._position += len(data)
        return len(data)


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _require_sha256(value: Any, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise RuntimeMaterializationError(f"{label} is not an exact sha256")
    return value


def _exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise RuntimeMaterializationError(f"{label} does not have the exact schema")
    return value


def _bounded_json(raw: bytes, *, maximum: int, label: str) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > maximum:
        raise RuntimeMaterializationError(f"{label} exceeds its canonical byte bound")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeMaterializationError(f"{label} is malformed") from error
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > 65_536 or depth > 20:
            raise RuntimeMaterializationError(f"{label} exceeds its structural bound")
        if type(node) is dict:
            stack.extend((key, depth + 1) for key in node)
            stack.extend((item, depth + 1) for item in node.values())
        elif type(node) is list:
            stack.extend((item, depth + 1) for item in node)
        elif type(node) is str and len(node.encode("utf-8")) > 65_536:
            raise RuntimeMaterializationError(f"{label} contains an oversized string")
        elif node is not None and type(node) not in (str, int, bool):
            raise RuntimeMaterializationError(f"{label} contains an unsupported value")
    if not hmac.compare_digest(raw, _canonical_json(value)):
        raise RuntimeMaterializationError(f"{label} is not canonical JSON")
    return value


def _fd_identity(descriptor: int, label: str, access: int) -> _FDIdentity:
    if type(descriptor) is not int or descriptor < 0 or _fcntl is None or os.name != "posix":
        raise RuntimeMaterializationError(f"{label} descriptor authority is unavailable")
    try:
        metadata = os.fstat(descriptor)
        flags = _fcntl.fcntl(descriptor, _fcntl.F_GETFL)
        inheritable = os.get_inheritable(descriptor)
    except OSError as error:
        raise RuntimeMaterializationError(f"{label} descriptor cannot be inspected") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeMaterializationError(f"{label} descriptor is not a regular file")
    if flags & os.O_ACCMODE != access:
        expected = "read-only" if access == os.O_RDONLY else "read-write"
        raise RuntimeMaterializationError(f"{label} descriptor must be {expected}")
    if flags & getattr(os, "O_APPEND", 0):
        raise RuntimeMaterializationError(f"{label} descriptor must not append")
    if inheritable:
        raise RuntimeMaterializationError(f"{label} descriptor must not be inheritable")
    return _FDIdentity(
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _same_object(first: _FDIdentity, second: _FDIdentity) -> bool:
    return (first.dev, first.ino) == (second.dev, second.ino)


def _read_exact(descriptor: int, expected_size: int, label: str) -> bytes:
    if type(expected_size) is not int or isinstance(expected_size, bool) or expected_size < 0:
        raise RuntimeMaterializationError(f"{label} size is invalid")
    chunks: list[bytes] = []
    offset = 0
    while offset < expected_size:
        data = os.pread(descriptor, min(_READ_CHUNK, expected_size - offset), offset)
        if not data:
            raise RuntimeMaterializationError(f"{label} was truncated")
        chunks.append(data)
        offset += len(data)
    if os.pread(descriptor, 1, expected_size):
        raise RuntimeMaterializationError(f"{label} grew during consumption")
    return b"".join(chunks)


def _hash_fd(descriptor: int, expected_size: int, label: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < expected_size:
        data = os.pread(descriptor, min(_READ_CHUNK, expected_size - offset), offset)
        if not data:
            raise RuntimeMaterializationError(f"{label} was truncated")
        digest.update(data)
        offset += len(data)
    if os.pread(descriptor, 1, expected_size):
        raise RuntimeMaterializationError(f"{label} grew during consumption")
    return digest.hexdigest()


def _normalize_path(value: Any, label: str, *, absolute: bool) -> str:
    if type(value) is not str or not value or "\x00" in value or "\\" in value:
        raise RuntimeMaterializationError(f"{label} is malformed")
    if unicodedata.normalize("NFC", value) != value:
        raise RuntimeMaterializationError(f"{label} is not NFC normalized")
    if absolute != value.startswith("/"):
        raise RuntimeMaterializationError(f"{label} has the wrong path form")
    raw = value[1:] if absolute else value
    if raw.endswith("/"):
        raw = raw[:-1]
    parts = raw.split("/") if raw else []
    if any(part in ("", ".", "..") for part in parts):
        raise RuntimeMaterializationError(f"{label} is not canonical")
    if len(value.encode("utf-8")) > MAX_PATH_BYTES:
        raise RuntimeMaterializationError(f"{label} exceeds the path bound")
    if any(len(part.encode("utf-8")) > MAX_COMPONENT_BYTES for part in parts):
        raise RuntimeMaterializationError(f"{label} component exceeds the path bound")
    return ("/" if absolute else "") + "/".join(parts)


def _output_path(destination: str, member: str | None = None) -> str:
    prefix = destination[1:]
    if member is None:
        return prefix
    return member if not prefix else prefix + "/" + member


def _validate_source_row(row: Any) -> dict[str, Any]:
    value = _exact_keys(row, _SOURCE_KEYS, "composition source")
    artifact_id = value["artifact_id"]
    role = value["role"]
    if type(artifact_id) is not str or _ARTIFACT_ID.fullmatch(artifact_id) is None:
        raise RuntimeMaterializationError("source artifact_id is invalid")
    if role not in _ROLE_CONTRACT:
        raise RuntimeMaterializationError("source role is unsupported")
    media_type = value["media_type"]
    destination = _normalize_path(value["destination"], "source destination", absolute=True)
    required_destination, accepted_media = _ROLE_CONTRACT[role]
    if destination != required_destination:
        raise RuntimeMaterializationError(f"{role} destination is not canonical")
    if media_type not in accepted_media and media_type not in _UNSUPPORTED_INSTALL_MEDIA:
        raise RuntimeMaterializationError(f"{role} media type is unsupported")
    _require_sha256(value["payload_sha256"], "payload sha256")
    _require_sha256(value["source_manifest_sha256"], "source manifest sha256")
    for key in ("payload_size", "source_manifest_size"):
        number = value[key]
        if type(number) is not int or isinstance(number, bool) or number < 0:
            raise RuntimeMaterializationError(f"{key} is invalid")
    if value["source_manifest_size"] > MAX_SOURCE_MANIFEST_BYTES:
        raise RuntimeMaterializationError("source manifest exceeds its byte bound")
    paths = value["required_paths"]
    if type(paths) is not list or not paths or len(paths) > 128:
        raise RuntimeMaterializationError("required_paths is invalid")
    normalized = [_normalize_path(path, "required output path", absolute=True) for path in paths]
    if normalized != sorted(set(normalized), key=lambda item: item.encode("utf-8")):
        raise RuntimeMaterializationError("required_paths is not an exact ordered set")
    if tuple(normalized) != _REQUIRED_OUTPUTS[role]:
        raise RuntimeMaterializationError(f"{role} required_paths is not the pinned OCI contract")
    if any(
        destination != "/"
        and path != destination
        and not path.startswith(destination + "/")
        for path in normalized
    ):
        raise RuntimeMaterializationError("required output path escapes its destination")
    return value


def _validate_composition_manifest(
    raw: bytes,
    expected_sha256: str,
    *,
    expected_schema_version: str = SCHEMA_VERSION,
    expected_authentication_scope: str = "TEST_ONLY_EXACT_CONTENT",
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if (expected_schema_version, expected_authentication_scope) not in {
        (SCHEMA_VERSION, "TEST_ONLY_EXACT_CONTENT"),
        (
            NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION,
            NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        ),
        (
            APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION,
            NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        ),
    }:
        raise RuntimeMaterializationError("composition validation policy is unsupported")
    _require_sha256(expected_sha256, "composition manifest sha256")
    if not hmac.compare_digest(_digest(raw), expected_sha256):
        raise RuntimeMaterializationError("composition manifest digest mismatch")
    value = _exact_keys(
        _bounded_json(raw, maximum=MAX_COMPOSITION_MANIFEST_BYTES, label="composition manifest"),
        _COMPOSITION_KEYS,
        "composition manifest",
    )
    if (
        value["schema_version"] != expected_schema_version
        or value["target"] != "linux/arm64"
        or value["authentication_scope"] != expected_authentication_scope
        or value["network"] != "DENY"
        or value["environment_denials"] != _ENVIRONMENT_DENIALS
        or value["limits"] != _LIMITS
        or value["installation_policy"] != _INSTALLATION_POLICY
    ):
        raise RuntimeMaterializationError("composition policy is not exact")
    required_roles = (
        APPLE_CONTAINER_REQUIRED_ROLES
        if expected_schema_version == APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION
        else _REQUIRED_ROLES
    )
    if type(value["sources"]) is not list or len(value["sources"]) != len(required_roles):
        raise RuntimeMaterializationError("composition source roster is not exact")
    sources = [_validate_source_row(row) for row in value["sources"]]
    roles = tuple(row["role"] for row in sources)
    if roles != required_roles:
        raise RuntimeMaterializationError("composition role roster/order is not exact")
    artifact_ids = [row["artifact_id"] for row in sources]
    if len(set(artifact_ids)) != len(artifact_ids):
        raise RuntimeMaterializationError("composition artifact ids are not unique")
    total = sum(row["payload_size"] + row["source_manifest_size"] for row in sources)
    if total > MAX_INPUT_BYTES:
        raise RuntimeMaterializationError("composition inputs exceed the 8 GiB bound")
    return value, sources


def validate_apple_container_composition_candidate(
    raw: bytes, *, expected_sha256: str,
) -> tuple[dict[str, Any], tuple[dict[str, Any], ...]]:
    """Validate the next Apple Container image input roster without issuing authority.

    This is deliberately only a setup-plan validator.  In particular it does
    not materialize an image, sign a receipt, or promote the candidate to a
    runtime authority.  The native operation-4 producer must first implement
    the distinct v2 roster and bind every retained payload, source manifest,
    acquisition receipt, and policy row.
    """

    value, rows = _validate_composition_manifest(
        raw,
        expected_sha256,
        expected_schema_version=APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION,
        expected_authentication_scope=NATIVE_RETAINED_AUTHENTICATION_SCOPE,
    )
    return value, tuple(rows)


def load_apple_container_image_generation_policy(raw: bytes) -> dict[str, Any]:
    """Validate the exact blocked installer policy without minting authority.

    The policy binds the already-reviewed Forge and Medusa producer receipts
    and the exact OpenGrep acquisition inputs.  OpenGrep deliberately has no
    producer receipt in this generation: an eleven-role native operation-4
    signer cannot authenticate a twelfth role.  Consequently this function
    can return policy data, but no runtime-image or image-member capability.
    """

    if type(raw) is not bytes or len(raw) != APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SIZE:
        raise RuntimeMaterializationError("Apple Container image policy size differs")
    if not hmac.compare_digest(
        _digest(raw), APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SHA256
    ):
        raise RuntimeMaterializationError("Apple Container image policy digest differs")
    value = _bounded_json(
        raw,
        maximum=MAX_COMPOSITION_MANIFEST_BYTES,
        label="Apple Container image policy",
    )
    _exact_keys(
        value,
        frozenset({"cache", "composition", "generation", "schema"}),
        "Apple Container image policy",
    )
    if value["schema"] != APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SCHEMA:
        raise RuntimeMaterializationError("Apple Container image policy schema differs")
    if value["cache"] != {
        "ambient_cache": "DENY",
        "content_identity": "SHA256_PLUS_SIZE",
        "network_scope": "INSTALLER_SETUP_ONLY",
        "retained_inputs": "EXACT_O_RDONLY_DESCRIPTOR_ROSTER",
        "runtime_network": "DENY",
        "transaction": "PRIVATE_STAGE_VALIDATE_ATOMIC_COMMIT_OR_ROLLBACK",
    }:
        raise RuntimeMaterializationError("Apple Container cache policy differs")
    composition = _exact_keys(
        value["composition"],
        frozenset({"required_role_order", "schema", "static_members", "target"}),
        "Apple Container composition policy",
    )
    if (
        composition["schema"] != APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION
        or composition["target"] != "linux/arm64"
        or composition["required_role_order"] != list(APPLE_CONTAINER_REQUIRED_ROLES)
        or composition["static_members"] != list(_APPLE_CONTAINER_STATIC_MEMBER_POLICY)
    ):
        raise RuntimeMaterializationError("Apple Container composition policy differs")
    generation = _exact_keys(
        value["generation"],
        frozenset(
            {
                "container_runtime",
                "format",
                "host_platform",
                "missing_authorities",
                "production_authority",
                "receipt_schema",
                "state",
            }
        ),
        "Apple Container generation policy",
    )
    if generation != {
        "container_runtime": "APPLE_CONTAINER",
        "format": "OCI_IMAGE_LAYOUT_SINGLE_COMPLETE_ROOT_LAYER",
        "host_platform": "macos/arm64",
        "missing_authorities": list(_APPLE_CONTAINER_IMAGE_POLICY_MISSING_AUTHORITIES),
        "production_authority": False,
        "receipt_schema": "plamen.apple-container.runtime-image-generation-receipt.v1",
        "state": "CANDIDATE_BLOCKED",
    }:
        raise RuntimeMaterializationError("Apple Container generation state differs")
    return value


def _validate_source_manifest(
    raw: bytes,
    source: Mapping[str, Any],
    *,
    expected_schema_version: str = SOURCE_MANIFEST_SCHEMA_VERSION,
    expected_authentication_scope: str = "TEST_ONLY_EXACT_CONTENT",
) -> dict[str, Any]:
    backend_archive = (
        source.get("role") in {"codex", "claude"}
        and source.get("media_type")
        == "application/vnd.plamen.authenticated-tar-member"
    )
    if (expected_schema_version, expected_authentication_scope) not in {
        (SOURCE_MANIFEST_SCHEMA_VERSION, "TEST_ONLY_EXACT_CONTENT"),
        (
            NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
            NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        ),
    }:
        raise RuntimeMaterializationError("source validation policy is unsupported")
    value = _exact_keys(
        _bounded_json(raw, maximum=MAX_SOURCE_MANIFEST_BYTES, label="source manifest"),
        (
            _BACKEND_ARCHIVE_SOURCE_MANIFEST_KEYS
            if backend_archive else _SOURCE_MANIFEST_KEYS
        ),
        "source manifest",
    )
    if (
        value["schema_version"] != expected_schema_version
        or value["artifact_id"] != source["artifact_id"]
        or value["role"] != source["role"]
        or value["media_type"] != source["media_type"]
        or value["authentication_scope"] != expected_authentication_scope
        or value["payload_sha256"] != source["payload_sha256"]
        or value["payload_size"] != source["payload_size"]
        or value["required_paths"] != source["required_paths"]
        or value["platform"] != _ROLE_PLATFORM[source["role"]]
    ):
        raise RuntimeMaterializationError("source manifest does not bind its composition row")
    for name in ("version", "platform", "source_reference"):
        if type(value[name]) is not str or not value[name] or len(value[name].encode("utf-8")) > 4096:
            raise RuntimeMaterializationError(f"source manifest {name} is invalid")
    if backend_archive:
        member = _normalize_path(
            value["archive_member"], "backend archive member", absolute=False,
        )
        expected = (
            r"package/claude(?:\.exe)?" if source["role"] == "claude"
            else r"package/vendor/[^/]+/bin/codex(?:\.exe)?"
        )
        if (
            re.fullmatch(expected, member) is None
            or type(value["archive_member_count"]) is not int
            or isinstance(value["archive_member_count"], bool)
            or value["archive_member_count"] <= 0
            or value["archive_member_count"] > MAX_ENTRIES
            or _SHA256.fullmatch(
                str(value["archive_member_roster_sha256"] or "")
            ) is None
            or _SHA256.fullmatch(str(value["installed_sha256"] or "")) is None
            or type(value["installed_size"]) is not int
            or isinstance(value["installed_size"], bool)
            or value["installed_size"] <= 0
            or value["installed_size"] > MAX_INPUT_BYTES
        ):
            raise RuntimeMaterializationError(
                "backend archive-member source contract differs"
            )
    return value


def render_backend_archive_source_manifest(
    *, selector: str, resolved_version: str,
    payload: Mapping[str, Any], installed: Mapping[str, Any],
) -> bytes:
    """Derive the role-5/role-6 extraction contract from a validated receipt.

    Signature/registry validation remains the native acquisition producer's
    responsibility.  This pure renderer accepts only the exact already-
    validated receipt projections and binds both archive census and selected
    executable identity into the source manifest consumed by operation 4.
    """

    payload_fields = {
        "source_url", "size", "sha256", "sha512_sri", "archive_format",
        "member_count", "member_roster_sha256", "selected_member",
        "path_traversal_rejected",
    }
    installed_fields = {
        "platform", "relative_path", "executable_size", "executable_sha256",
        "closure_count", "closure_bytes", "closure_sha256", "code_signature",
    }
    if (
        selector not in {"codex", "claude"}
        or type(resolved_version) is not str
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", resolved_version) is None
        or type(payload) is not dict or set(payload) != payload_fields
        or type(installed) is not dict or set(installed) != installed_fields
        or installed.get("platform") != "linux-arm64"
        or payload.get("archive_format") != "tar.gz"
        or payload.get("path_traversal_rejected") is not True
        or type(payload.get("source_url")) is not str
        or not payload["source_url"].startswith("https://")
        or "@" in payload["source_url"].split("/", 3)[2]
        or type(payload.get("size")) is not int
        or isinstance(payload.get("size"), bool)
        or not 0 < payload["size"] <= MAX_INPUT_BYTES
        or _SHA256.fullmatch(str(payload.get("sha256") or "")) is None
        or type(payload.get("member_count")) is not int
        or isinstance(payload.get("member_count"), bool)
        or not 0 < payload["member_count"] <= MAX_ENTRIES
        or _SHA256.fullmatch(
            str(payload.get("member_roster_sha256") or "")
        ) is None
        or _SHA256.fullmatch(
            str(installed.get("executable_sha256") or "")
        ) is None
        or type(installed.get("executable_size")) is not int
        or isinstance(installed.get("executable_size"), bool)
        or not 0 < installed["executable_size"] <= MAX_INPUT_BYTES
    ):
        raise RuntimeMaterializationError(
            "validated backend archive projection differs"
        )
    member = _normalize_path(
        payload.get("selected_member"), "backend archive member",
        absolute=False,
    )
    expected = (
        r"package/claude(?:\.exe)?" if selector == "claude"
        else r"package/vendor/[^/]+/bin/codex(?:\.exe)?"
    )
    if re.fullmatch(expected, member) is None:
        raise RuntimeMaterializationError(
            "validated backend selected member differs"
        )
    artifact_id = f"{selector}-{resolved_version}-linux-arm64"
    destination = _ROLE_CONTRACT[selector][0]
    return _canonical_json({
        "archive_member": member,
        "archive_member_count": payload["member_count"],
        "archive_member_roster_sha256": payload["member_roster_sha256"],
        "artifact_id": artifact_id,
        "authentication_scope": NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        "installed_sha256": installed["executable_sha256"],
        "installed_size": installed["executable_size"],
        "media_type": "application/vnd.plamen.authenticated-tar-member",
        "payload_sha256": payload["sha256"],
        "payload_size": payload["size"],
        "platform": "linux/arm64",
        "required_paths": [destination],
        "role": selector,
        "schema_version": NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
        "source_reference": payload["source_url"],
        "version": resolved_version,
    })


def _script_flags(path: str) -> tuple[bool, bool]:
    basename = path.rsplit("/", 1)[-1]
    installer = (
        "/DEBIAN/" in "/" + path
        or ".data/scripts/" in path
        or bool(re.search(r"(?:^|/)var/lib/dpkg/info/[^/]+\.(?:preinst|postinst|prerm|postrm|config)$", path))
        or path.endswith(".dist-info/entry_points.txt")
        or path.endswith((".pth", "/sitecustomize.py", "/usercustomize.py"))
    )
    trigger = (
        basename == "triggers"
        or "/triggers/" in "/" + path
        or bool(re.search(r"(?:^|/)var/lib/dpkg/info/[^/]+\.triggers$", path))
    )
    return installer, trigger


def _claim_entry(entries: dict[str, _Entry], collision_keys: dict[str, str], entry: _Entry) -> None:
    normalized = unicodedata.normalize("NFC", entry.path).casefold()
    prior_spelling = collision_keys.get(normalized)
    if prior_spelling is not None and prior_spelling != entry.path:
        raise RuntimeMaterializationError(
            f"output has a case/NFC collision: {prior_spelling!r}, {entry.path!r}"
        )
    collision_keys[normalized] = entry.path
    prior = entries.get(entry.path)
    if prior is not None:
        if prior.kind == entry.kind == "directory":
            prior.sources[:] = sorted(set(prior.sources + entry.sources))
            prior.installer_script = prior.installer_script or entry.installer_script
            prior.trigger_metadata = prior.trigger_metadata or entry.trigger_metadata
            return
        raise RuntimeMaterializationError(f"output path collision at {entry.path!r}")
    if len(entries) >= MAX_ENTRIES:
        raise RuntimeMaterializationError("runtime exceeds the 131072-entry bound")
    entries[entry.path] = entry


def _ensure_parents(entries: dict[str, _Entry], collision_keys: dict[str, str], path: str, source: str) -> None:
    parts = path.split("/")[:-1]
    for index in range(1, len(parts) + 1):
        parent = "/".join(parts[:index])
        _claim_entry(
            entries,
            collision_keys,
            _Entry(parent, "directory", 0o755, 0, None, None, [source]),
        )


def _copy_member_to_spool(member_stream: BinaryIO, size: int, spool: BinaryIO) -> tuple[int, str]:
    offset = spool.tell()
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = member_stream.read(min(_READ_CHUNK, remaining))
        if not chunk:
            raise RuntimeMaterializationError("archive member was truncated")
        spool.write(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
    if member_stream.read(1):
        raise RuntimeMaterializationError("archive member exceeded its declared size")
    return offset, digest.hexdigest()


def _mapped_link_target(
    member: tarfile.TarInfo,
    source: Mapping[str, Any],
    mapped_path: str,
    source_name: str,
) -> str:
    target = member.linkname
    if (
        type(target) is not str
        or not target
        or target != target.strip()
        or "\x00" in target
        or "\\" in target
        or unicodedata.normalize("NFC", target) != target
        or len(target.encode("utf-8")) > MAX_PATH_BYTES
    ):
        raise RuntimeMaterializationError("archive link target is malformed")
    if member.issym() and not target.startswith("/"):
        resolved_source = posixpath.normpath(
            posixpath.join(posixpath.dirname(source_name), target)
        )
    else:
        resolved_source = posixpath.normpath(target.lstrip("/"))
    if resolved_source in ("", ".", "..") or resolved_source.startswith("../"):
        raise RuntimeMaterializationError("archive link target escapes its source root")
    resolved_source = _normalize_path(
        resolved_source, "archive link target", absolute=False
    )
    mapped_target = _output_path(source["destination"], resolved_source)
    _normalize_path("/" + mapped_target, "installed link target", absolute=True)
    if source["role"] != "base_rootfs":
        destination = source["destination"].removeprefix("/")
        if mapped_target != destination and not mapped_target.startswith(destination + "/"):
            raise RuntimeMaterializationError("archive link escapes its installed component")
    if member.islnk():
        return mapped_target
    return posixpath.relpath(mapped_target, posixpath.dirname(mapped_path))


def _link_destination(path: str, entry: _Entry) -> str:
    if entry.kind == "hardlink":
        return entry.linkname
    if entry.kind != "symlink":
        raise RuntimeMaterializationError("runtime link kind is unsupported")
    target = (
        entry.linkname.removeprefix("/")
        if entry.linkname.startswith("/")
        else posixpath.normpath(posixpath.join(posixpath.dirname(path), entry.linkname))
    )
    if target in ("", ".", "..") or target.startswith("../"):
        raise RuntimeMaterializationError("installed symlink escapes the rootfs")
    return _normalize_path(target, "installed symlink target", absolute=False)


def _resolve_output(entries: Mapping[str, _Entry], requested: str) -> _Entry:
    current = requested.removeprefix("/")
    visited: set[str] = set()
    for _ in range(41):
        if current in visited:
            raise RuntimeMaterializationError("runtime link graph contains a cycle")
        visited.add(current)
        parts = current.split("/")
        redirected = False
        for index in range(len(parts), 0, -1):
            prefix = "/".join(parts[:index])
            entry = entries.get(prefix)
            if entry is None:
                continue
            suffix = parts[index:]
            if entry.kind in {"symlink", "hardlink"}:
                target = _link_destination(prefix, entry)
                current = posixpath.join(target, *suffix) if suffix else target
                redirected = True
                break
            if suffix and entry.kind != "directory":
                raise RuntimeMaterializationError("runtime path descends from a non-directory")
            if not suffix:
                return entry
        if not redirected:
            raise RuntimeMaterializationError("required runtime path is absent")
    raise RuntimeMaterializationError("runtime link graph exceeds its depth bound")


def _validate_links(entries: Mapping[str, _Entry]) -> None:
    for path, entry in entries.items():
        if entry.kind == "hardlink":
            target = entries.get(entry.linkname)
            if target is None or target.kind != "file":
                raise RuntimeMaterializationError("runtime hardlink target is not a regular file")
        elif entry.kind == "symlink":
            _link_destination(path, entry)


def _expand_archive(
    descriptor: int,
    source: Mapping[str, Any],
    entries: dict[str, _Entry],
    collision_keys: dict[str, str],
    spool: BinaryIO,
    expanded: list[int],
    *,
    decoded_factory: Callable[[], BinaryIO] | None = None,
) -> None:
    per_archive = min(
        MAX_EXPANDED_BYTES,
        max(64 * 1024 * 1024, source["payload_size"] * 200),
    )
    decoded_file = (
        decoded_factory()
        if decoded_factory is not None
        else tempfile.TemporaryFile(mode="w+b")
    )
    with decoded_file as decoded:
        signature = os.pread(descriptor, 2, 0)
        decoded_size = 0
        if signature == b"\x1f\x8b":
            decoder = zlib.decompressobj(zlib.MAX_WBITS | 16)
            source_offset = 0
            while source_offset < source["payload_size"]:
                chunk = os.pread(
                    descriptor,
                    min(_READ_CHUNK, source["payload_size"] - source_offset),
                    source_offset,
                )
                if not chunk:
                    raise RuntimeMaterializationError("runtime archive was truncated")
                source_offset += len(chunk)
                pending = chunk
                while pending:
                    remaining = per_archive - decoded_size
                    if remaining < 0:
                        raise RuntimeMaterializationError(
                            "runtime archive decompression exceeds its bound"
                        )
                    inflated = decoder.decompress(
                        pending,
                        min(_READ_CHUNK, remaining + 1),
                    )
                    decoded_size += len(inflated)
                    if decoded_size > per_archive:
                        raise RuntimeMaterializationError(
                            "runtime archive decompression exceeds its bound"
                        )
                    decoded.write(inflated)
                    if decoder.unused_data:
                        raise RuntimeMaterializationError(
                            "runtime archive has concatenated or trailing gzip data"
                        )
                    pending = decoder.unconsumed_tail
            inflated = decoder.flush()
            decoded_size += len(inflated)
            if decoded_size > per_archive:
                raise RuntimeMaterializationError("runtime archive decompression exceeds its bound")
            decoded.write(inflated)
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise RuntimeMaterializationError("runtime archive gzip member is incomplete")
        else:
            source_offset = 0
            while source_offset < source["payload_size"]:
                chunk = os.pread(
                    descriptor,
                    min(_READ_CHUNK, source["payload_size"] - source_offset),
                    source_offset,
                )
                if not chunk:
                    raise RuntimeMaterializationError("runtime archive was truncated")
                decoded.write(chunk)
                decoded_size += len(chunk)
                source_offset += len(chunk)
                if decoded_size > per_archive:
                    raise RuntimeMaterializationError("runtime archive exceeds its per-source bound")
        if decoded_size <= 0:
            raise RuntimeMaterializationError("runtime source archive is empty")
        decoded.flush()
        decoded.seek(0)
        try:
            archive = tarfile.open(fileobj=decoded, mode="r:")
        except (tarfile.TarError, OSError) as error:
            raise RuntimeMaterializationError("runtime source archive is malformed") from error
        expected_tar_payload = 0
        source_member_names: set[str] = set()
        with archive:
            if archive.pax_headers:
                raise RuntimeMaterializationError("archive global extended metadata is forbidden")
            for member in archive:
                source_name = member.name[:-1] if member.name.endswith("/") else member.name
                if source_name in source_member_names:
                    raise RuntimeMaterializationError("archive contains a duplicate source member")
                source_member_names.add(source_name)
                expected_tar_payload += 512
                if source_name in ("", ".") and member.isdir():
                    continue
                member = member
                if member.pax_headers:
                    raise RuntimeMaterializationError("archive member extended metadata is forbidden")
                name = _normalize_path(source_name, "archive member", absolute=False)
                path = _output_path(source["destination"], name)
                _normalize_path("/" + path, "installed output path", absolute=True)
                if source["role"] == "plamen_guest" and (
                    (member.isdir() and path not in _GUEST_ARTIFACT_DIRECTORIES)
                    or (not member.isdir() and path not in _GUEST_ARTIFACT_FILES)
                    or member.issym()
                    or member.islnk()
                ):
                    raise RuntimeMaterializationError(
                        "native guest artifact roster is not exact"
                    )
                if source["role"] == "base_rootfs" and (
                    path == _PLAMEN_SOURCE_ROOT
                    or path.startswith(_PLAMEN_SOURCE_ROOT + "/")
                    or path == _BAKED_PLAMEN_ROOT
                    or path.startswith(_BAKED_PLAMEN_ROOT + "/")
                    or path == _GUEST_BOOTSTRAP
                ):
                    raise RuntimeMaterializationError(
                        "base rootfs occupies a reserved Plamen namespace"
                    )
                if source["role"] == "cpython" and (
                    path == _PLAMEN_SOURCE_ROOT
                    or path.startswith(_PLAMEN_SOURCE_ROOT + "/")
                    or path == _BAKED_PLAMEN_ROOT
                    or path.startswith(_BAKED_PLAMEN_ROOT + "/")
                    or path == _GUEST_BOOTSTRAP
                ):
                    raise RuntimeMaterializationError(
                        "CPython tree occupies another component's namespace"
                    )
                if any(
                    component in {"glibc-hwcaps", "tls", "atomics"}
                    for component in path.split("/")
                ):
                    raise RuntimeMaterializationError(
                        "runtime archive contains a forbidden hwcaps namespace"
                    )
                if path in {"etc/ld.so.cache", "etc/ld.so.preload"}:
                    raise RuntimeMaterializationError(
                        "runtime archive contains forbidden loader state"
                    )
                if any(
                    component == ".wh..wh..opq" or component.startswith(".wh.")
                    for component in path.split("/")
                ):
                    raise RuntimeMaterializationError(
                        "runtime archive contains an OCI whiteout"
                    )
                if (
                    path.split("/", 1)[0] in {"dev", "proc", "run", "sys", "tmp"}
                    and not member.isdir()
                ):
                    raise RuntimeMaterializationError("runtime archive populates an ephemeral namespace")
                if member.ischr() or member.isblk() or member.isfifo() or member.type not in (
                    tarfile.REGTYPE,
                    tarfile.AREGTYPE,
                    tarfile.DIRTYPE,
                    tarfile.SYMTYPE,
                    tarfile.LNKTYPE,
                ):
                    raise RuntimeMaterializationError("archive devices and special entries are forbidden")
                if member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
                    raise RuntimeMaterializationError("archive privileged mode bits are forbidden")
                installer, trigger = _script_flags(path)
                if source["role"] != "base_rootfs" and (
                    "/DEBIAN/" in "/" + path or ".data/scripts/" in path
                ):
                    raise RuntimeMaterializationError("uninstalled package scripts are forbidden")
                if member.isdir():
                    if member.size != 0:
                        raise RuntimeMaterializationError("archive directory has a payload")
                    _claim_entry(
                        entries,
                        collision_keys,
                        _Entry(path, "directory", 0o755, 0, None, None, [source["artifact_id"]], installer, trigger),
                    )
                    continue
                _ensure_parents(entries, collision_keys, path, source["artifact_id"])
                if member.issym() or member.islnk():
                    if member.size != 0:
                        raise RuntimeMaterializationError("archive link has a payload")
                    linkname = _mapped_link_target(member, source, path, name)
                    kind = "symlink" if member.issym() else "hardlink"
                    _claim_entry(
                        entries,
                        collision_keys,
                        _Entry(
                            path,
                            kind,
                            0o777 if kind == "symlink" else (0o555 if member.mode & 0o111 else 0o444),
                            0,
                            _digest((kind + "\0" + linkname).encode("utf-8")),
                            None,
                            [source["artifact_id"]],
                            installer,
                            trigger,
                            linkname,
                        ),
                    )
                    continue
                if not member.isfile() or member.size < 0:
                    raise RuntimeMaterializationError("archive entry kind is forbidden")
                expected_tar_payload += ((member.size + 511) // 512) * 512
                expanded[0] += member.size
                if expanded[0] > MAX_EXPANDED_BYTES:
                    raise RuntimeMaterializationError("runtime exceeds the 12 GiB expanded bound")
                stream = archive.extractfile(member)
                if stream is None:
                    raise RuntimeMaterializationError("archive member payload is unavailable")
                offset, digest = _copy_member_to_spool(stream, member.size, spool)
                mode = 0o555 if member.mode & 0o111 else 0o444
                _claim_entry(
                    entries,
                    collision_keys,
                    _Entry(path, "file", mode, member.size, digest, offset, [source["artifact_id"]], installer, trigger),
                )
        minimal_tar_size = expected_tar_payload + 1024
        blocked_tar_size = (
            (minimal_tar_size + tarfile.RECORDSIZE - 1)
            // tarfile.RECORDSIZE
            * tarfile.RECORDSIZE
        )
        if decoded_size not in {minimal_tar_size, blocked_tar_size}:
            raise RuntimeMaterializationError("runtime archive terminator is not canonical")
        remaining = decoded_size - expected_tar_payload
        trailing_offset = expected_tar_payload
        while remaining:
            chunk = os.pread(decoded.fileno(), min(_READ_CHUNK, remaining), trailing_offset)
            if not chunk or any(chunk):
                raise RuntimeMaterializationError("runtime archive has hidden or trailing records")
            trailing_offset += len(chunk)
            remaining -= len(chunk)


def _validate_debian_package_state(raw: bytes) -> None:
    value = _bounded_json(raw, maximum=16 * 1024 * 1024, label="Debian package state")
    if type(value) is not dict or frozenset(value) != {"schema_version", "packages"}:
        raise RuntimeMaterializationError("Debian package state schema is not exact")
    if value["schema_version"] != "plamen.debian_package_state.v1" or type(value["packages"]) is not list:
        raise RuntimeMaterializationError("Debian package state schema is unsupported")
    prior: tuple[str, str, str] | None = None
    for row in value["packages"]:
        if type(row) is not dict or frozenset(row) != {"architecture", "name", "status", "version"}:
            raise RuntimeMaterializationError("Debian package record schema is not exact")
        if any(type(row[key]) is not str or not row[key] for key in row):
            raise RuntimeMaterializationError("Debian package record is invalid")
        key = (row["name"], row["architecture"], row["version"])
        if prior is not None and key <= prior:
            raise RuntimeMaterializationError("Debian package records are not strictly ordered")
        if row["status"] != "install ok installed":
            raise RuntimeMaterializationError("Debian package state is not fully installed")
        prior = key


def _add_raw(
    descriptor: int,
    source: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    entries: dict[str, _Entry],
    collision_keys: dict[str, str],
    spool: BinaryIO,
    expanded: list[int],
) -> None:
    if source["media_type"] == "application/vnd.plamen.authenticated-tar-member":
        _add_authenticated_archive_member(
            descriptor, source, source_manifest, entries, collision_keys,
            spool, expanded,
        )
        return
    raw = _read_exact(descriptor, source["payload_size"], "runtime source payload")
    if source["media_type"] == "application/vnd.plamen.debian-package-state+json":
        _validate_debian_package_state(raw)
        mode = 0o444
    else:
        if not raw:
            raise RuntimeMaterializationError("runtime executable is empty")
        mode = 0o555
    path = _output_path(source["destination"])
    _ensure_parents(entries, collision_keys, path, source["artifact_id"])
    expanded[0] += len(raw)
    if expanded[0] > MAX_EXPANDED_BYTES:
        raise RuntimeMaterializationError("runtime exceeds the 12 GiB expanded bound")
    offset = spool.tell()
    spool.write(raw)
    installer, trigger = _script_flags(path)
    _claim_entry(
        entries,
        collision_keys,
        _Entry(path, "file", mode, len(raw), _digest(raw), offset, [source["artifact_id"]], installer, trigger),
    )


def _add_authenticated_archive_member(
    descriptor: int,
    source: Mapping[str, Any],
    source_manifest: Mapping[str, Any],
    entries: dict[str, _Entry],
    collision_keys: dict[str, str],
    spool: BinaryIO,
    expanded: list[int],
) -> None:
    """Extract exactly one receipt-bound executable from an npm tarball."""

    selected_name = source_manifest["archive_member"]
    names: list[str] = []
    seen: set[str] = set()
    selected: tarfile.TarInfo | None = None
    retained = _PreadFile(descriptor, source["payload_size"])
    try:
        archive = tarfile.open(fileobj=retained, mode="r:gz")
    except (tarfile.TarError, OSError) as error:
        raise RuntimeMaterializationError(
            "backend archive payload is malformed"
        ) from error
    with archive:
        for member in archive:
            name = member.name
            parts = name.split("/")
            if (
                not name or name.startswith("/") or "\\" in name
                or any(part in {"", ".", ".."} for part in parts)
                or name in seen
                or member.issym() or member.islnk() or member.isdev()
                or not (member.isfile() or member.isdir())
                or member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
            ):
                raise RuntimeMaterializationError(
                    "backend archive contains an unsafe member"
                )
            _normalize_path(name, "backend archive member", absolute=False)
            seen.add(name)
            names.append(name)
            if name == selected_name:
                if selected is not None or not member.isfile():
                    raise RuntimeMaterializationError(
                        "backend archive selected member differs"
                    )
                selected = member
        roster = sorted(names, key=lambda value: value.encode("utf-8"))
        roster_raw = json.dumps(
            roster, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        if (
            len(roster) != source_manifest["archive_member_count"]
            or not hmac.compare_digest(
                _digest(roster_raw),
                source_manifest["archive_member_roster_sha256"],
            )
            or selected is None
            or selected.size != source_manifest["installed_size"]
        ):
            raise RuntimeMaterializationError(
                "backend archive-member census differs"
            )
        stream = archive.extractfile(selected)
        if stream is None:
            raise RuntimeMaterializationError(
                "backend archive selected member is unavailable"
            )
        offset, digest = _copy_member_to_spool(
            stream, source_manifest["installed_size"], spool,
        )
    if not hmac.compare_digest(digest, source_manifest["installed_sha256"]):
        raise RuntimeMaterializationError(
            "backend archive selected member digest differs"
        )
    path = _output_path(source["destination"])
    _ensure_parents(entries, collision_keys, path, source["artifact_id"])
    expanded[0] += source_manifest["installed_size"]
    if expanded[0] > MAX_EXPANDED_BYTES:
        raise RuntimeMaterializationError(
            "runtime exceeds the 12 GiB expanded bound"
        )
    installer, trigger = _script_flags(path)
    _claim_entry(
        entries,
        collision_keys,
        _Entry(
            path, "file", 0o555, source_manifest["installed_size"], digest,
            offset, [source["artifact_id"]], installer, trigger,
        ),
    )


def _make_census(entries: Mapping[str, _Entry]) -> bytes:
    return _canonical_json(
        {
            "schema_version": CENSUS_SCHEMA_VERSION,
            "entries": [
                {
                    "kind": row.kind,
                    "linkname": row.linkname,
                    "mode": f"{row.mode:04o}",
                    "path": row.path,
                    "sha256": row.sha256,
                    "size": row.size,
                }
                for row in sorted(entries.values(), key=lambda item: item.path.encode("utf-8"))
            ],
        }
    )


def _make_provenance(entries: Mapping[str, _Entry], manifest_sha256: str) -> bytes:
    return _canonical_json(
        {
            "schema_version": PROVENANCE_SCHEMA_VERSION,
            "composition_manifest_sha256": manifest_sha256,
            "outputs": [
                {
                    "installer_script": row.installer_script,
                    "path": row.path,
                    "sources": sorted(set(row.sources)),
                    "trigger_metadata": row.trigger_metadata,
                }
                for row in sorted(entries.values(), key=lambda item: item.path.encode("utf-8"))
            ],
        }
    )


def _make_sbom(
    entries: Mapping[str, _Entry],
    sources: Sequence[Mapping[str, Any]],
    source_manifests: Mapping[str, Mapping[str, Any]],
    manifest_sha256: str,
) -> bytes:
    return _canonical_json(
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: Plamen-runtime-materializer"]},
            "dataLicense": "CC0-1.0",
            "documentNamespace": f"https://plamen.invalid/runtime/{manifest_sha256}",
            "files": [
                {
                    "SPDXID": "SPDXRef-File-" + hashlib.sha256(row.path.encode()).hexdigest()[:24],
                    "checksums": [{"algorithm": "SHA256", "checksumValue": row.sha256}],
                    "fileName": "/" + row.path,
                }
                for row in sorted(entries.values(), key=lambda item: item.path.encode("utf-8"))
                if row.kind == "file"
            ],
            "name": "plamen-audit-runtime",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package-" + row["artifact_id"],
                    "checksums": [{"algorithm": "SHA256", "checksumValue": row["payload_sha256"]}],
                    "downloadLocation": "NOASSERTION",
                    "name": row["artifact_id"],
                    "versionInfo": source_manifests[row["artifact_id"]]["version"],
                }
                for row in sources
            ],
            "spdxVersion": "SPDX-2.3",
        }
    )


def _source_roster_sha256(sources: Sequence[Mapping[str, Any]]) -> str:
    return _digest(
        _canonical_json(
            [
                {
                    "artifact_id": row["artifact_id"],
                    "payload_sha256": row["payload_sha256"],
                    "source_manifest_sha256": row["source_manifest_sha256"],
                }
                for row in sources
            ]
        )
    )


def _write_archive(descriptor: int, entries: Mapping[str, _Entry], spool: BinaryIO) -> tuple[str, int]:
    os.ftruncate(descriptor, 0)
    os.lseek(descriptor, 0, os.SEEK_SET)
    duplicate = os.dup(descriptor)
    try:
        with os.fdopen(duplicate, "wb", closefd=True) as output:
            duplicate = -1
            with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for entry in sorted(entries.values(), key=lambda item: item.path.encode("utf-8")):
                    info = tarfile.TarInfo(entry.path + ("/" if entry.kind == "directory" else ""))
                    info.mode = entry.mode
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    if entry.kind == "directory":
                        info.type = tarfile.DIRTYPE
                        info.size = 0
                        archive.addfile(info)
                    elif entry.kind == "file":
                        info.type = tarfile.REGTYPE
                        info.size = entry.size
                        assert entry.offset is not None
                        source = _PreadFile(spool.fileno(), entry.offset + entry.size)
                        source.seek(entry.offset)
                        archive.addfile(info, source)
                    else:
                        info.type = (
                            tarfile.SYMTYPE
                            if entry.kind == "symlink"
                            else tarfile.LNKTYPE
                        )
                        info.size = 0
                        info.linkname = entry.linkname
                        archive.addfile(info)
            output.flush()
            os.fsync(output.fileno())
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    size = os.fstat(descriptor).st_size
    return _hash_fd(descriptor, size, "canonical runtime archive"), size


def _close_many(descriptors: Sequence[int], *, exclude: frozenset[int] = frozenset()) -> None:
    for descriptor in dict.fromkeys(descriptors):
        if descriptor in exclude or type(descriptor) is not int or descriptor < 0:
            continue
        try:
            os.close(descriptor)
        except OSError:
            pass


def materialize_runtime_image(*args: Any, **kwargs: Any) -> None:
    raise RuntimeMaterializationUnsupported(
        "NATIVE_RETAINED_FD_BUILD_GUEST_AUTHORITY_REQUIRED:"
        "APPLE_CONTAINER_V2_STATIC_TOOL_ROSTER_UNSIGNED"
    )


def _TEST_ONLY_materialize_runtime_image(
    composition_manifest_bytes: bytes,
    *,
    expected_manifest_sha256: str,
    retained_inputs: Sequence[RetainedRuntimeInput],
    output_writer_descriptor: int,
    output_reader_descriptor: int,
    declared_environment: Mapping[str, str] | None = None,
) -> TestOnlyMaterializedRuntime:
    """Compose exact content; ownership of every supplied descriptor transfers."""

    input_descriptors: list[int] = []
    for row in retained_inputs if isinstance(retained_inputs, Sequence) else ():
        if isinstance(row, RetainedRuntimeInput):
            input_descriptors.extend((row.payload_descriptor, row.source_manifest_descriptor))
    success = False
    try:
        _, sources = _validate_composition_manifest(
            composition_manifest_bytes, expected_manifest_sha256
        )
        if type(retained_inputs) not in (tuple, list) or len(retained_inputs) != len(sources):
            raise RuntimeMaterializationError("retained input roster is not exact")
        environment = {} if declared_environment is None else declared_environment
        if type(environment) is not dict or any(type(k) is not str or type(v) is not str for k, v in environment.items()):
            raise RuntimeMaterializationError("declared environment is invalid")
        if any(name == "GLIBC_TUNABLES" or name.startswith("LD_") for name in environment):
            raise RuntimeMaterializationError("forbidden loader environment is present")

        writer_identity = _fd_identity(output_writer_descriptor, "output writer", os.O_RDWR)
        reader_identity = _fd_identity(output_reader_descriptor, "output reader", os.O_RDONLY)
        if output_writer_descriptor == output_reader_descriptor or not _same_object(writer_identity, reader_identity):
            raise RuntimeMaterializationError("output descriptors do not identify the same object")
        if writer_identity.size != 0 or stat.S_IMODE(writer_identity.mode) != 0o600:
            raise RuntimeMaterializationError("output object must be an empty owner-private file")
        if os.fstat(output_writer_descriptor).st_nlink != 0 or os.fstat(output_reader_descriptor).st_nlink != 0:
            raise RuntimeMaterializationError("output object must be unlinked before composition")

        observed_objects = {(writer_identity.dev, writer_identity.ino)}
        source_manifests: dict[str, Mapping[str, Any]] = {}
        source_identities: list[tuple[int, _FDIdentity]] = []
        unsupported: list[str] = []
        for source, retained in zip(sources, retained_inputs, strict=True):
            if type(retained) is not RetainedRuntimeInput or retained.artifact_id != source["artifact_id"]:
                raise RuntimeMaterializationError("retained input order/identity is not exact")
            payload_identity = _fd_identity(retained.payload_descriptor, "source payload", os.O_RDONLY)
            manifest_identity = _fd_identity(retained.source_manifest_descriptor, "source manifest", os.O_RDONLY)
            for identity in (payload_identity, manifest_identity):
                key = (identity.dev, identity.ino)
                if key in observed_objects:
                    raise RuntimeMaterializationError("retained descriptors alias")
                observed_objects.add(key)
            if payload_identity.size != source["payload_size"] or manifest_identity.size != source["source_manifest_size"]:
                raise RuntimeMaterializationError("retained input size does not match its manifest")
            if not hmac.compare_digest(
                _hash_fd(retained.payload_descriptor, payload_identity.size, "source payload"),
                source["payload_sha256"],
            ):
                raise RuntimeMaterializationError("source payload digest mismatch")
            raw_manifest = _read_exact(
                retained.source_manifest_descriptor,
                manifest_identity.size,
                "source manifest",
            )
            if not hmac.compare_digest(_digest(raw_manifest), source["source_manifest_sha256"]):
                raise RuntimeMaterializationError("source manifest digest mismatch")
            source_manifests[source["artifact_id"]] = _validate_source_manifest(raw_manifest, source)
            source_identities.extend(
                (
                    (retained.payload_descriptor, payload_identity),
                    (retained.source_manifest_descriptor, manifest_identity),
                )
            )
            if source["media_type"] in _UNSUPPORTED_INSTALL_MEDIA:
                unsupported.append(source["artifact_id"])
        if unsupported:
            raise NetworklessLinuxBuilderRequired(unsupported)

        entries: dict[str, _Entry] = {}
        collision_keys: dict[str, str] = {}
        expanded = [0]
        with tempfile.TemporaryFile(mode="w+b") as spool:
            for source, retained in zip(sources, retained_inputs, strict=True):
                if source["media_type"] in _ARCHIVE_MEDIA:
                    _expand_archive(
                        retained.payload_descriptor,
                        source,
                        entries,
                        collision_keys,
                        spool,
                        expanded,
                    )
                elif source["media_type"] in _RAW_MEDIA:
                    _add_raw(
                        retained.payload_descriptor, source,
                        source_manifests[source["artifact_id"]],
                        entries,
                        collision_keys,
                        spool,
                        expanded,
                    )
                else:  # guarded above and retained as a deny-by-default assertion
                    raise RuntimeMaterializationError("runtime media type has no compositor")
            _validate_links(entries)
            for source in sources:
                for path in source["required_paths"]:
                    try:
                        resolved = _resolve_output(entries, path)
                    except RuntimeMaterializationError as error:
                        raise RuntimeMaterializationError(
                            f"required output for {source['artifact_id']!r} is absent"
                        ) from error
                    if resolved.kind != "file":
                        raise RuntimeMaterializationError(
                            f"required output for {source['artifact_id']!r} is not a file"
                        )
                    if path in _REQUIRED_EXECUTABLE_OUTPUTS and resolved.mode & 0o111 == 0:
                        raise RuntimeMaterializationError(
                            f"required output for {source['artifact_id']!r} is not executable"
                        )
            if len(entries) > MAX_ENTRIES or expanded[0] > MAX_EXPANDED_BYTES:
                raise RuntimeMaterializationError("runtime expansion exceeds its exact limits")

            census = _make_census(entries)
            provenance = _make_provenance(entries, expected_manifest_sha256)
            sbom = _make_sbom(entries, sources, source_manifests, expected_manifest_sha256)
            spool.flush()
            archive_sha256, archive_size = _write_archive(
                output_writer_descriptor, entries, spool
            )

        for descriptor, identity in source_identities:
            after = _fd_identity(descriptor, "retained source", os.O_RDONLY)
            if after != identity:
                raise RuntimeMaterializationError("retained source changed during composition")
        post_writer = _fd_identity(output_writer_descriptor, "output writer", os.O_RDWR)
        post_reader = _fd_identity(output_reader_descriptor, "output reader", os.O_RDONLY)
        if not _same_object(post_writer, post_reader) or post_writer.size != archive_size:
            raise RuntimeMaterializationError("retained output identity changed")
        if not hmac.compare_digest(
            _hash_fd(output_reader_descriptor, archive_size, "retained runtime archive"),
            archive_sha256,
        ):
            raise RuntimeMaterializationError("retained output digest changed")
        os.fchmod(output_writer_descriptor, 0o400)
        receipt = _canonical_json(
            {
                "schema_version": RECEIPT_SCHEMA_VERSION,
                "status": "TEST_ONLY_CONTENT_COMPOSED_PENDING_NATIVE_AUTHORITY",
                "production_authority": False,
                "target": "linux/arm64",
                "archive": {
                    "media_type": "application/vnd.oci.image.layer.v1.tar",
                    "sha256": archive_sha256,
                    "size": archive_size,
                    "diff_id": "sha256:" + archive_sha256,
                },
                "composition_manifest_sha256": expected_manifest_sha256,
                "source_roster_sha256": _source_roster_sha256(sources),
                "installed": {
                    "entry_count": len(entries),
                    "expanded_bytes": expanded[0],
                    "census_sha256": _digest(census),
                    "sbom_sha256": _digest(sbom),
                    "provenance_sha256": _digest(provenance),
                },
                "environment_denials": _ENVIRONMENT_DENIALS,
                "network": "DENY",
                "package_execution": {
                    "compositor_executed_scripts": False,
                    "compositor_executed_triggers": False,
                    "observed_installer_script_entries": sum(row.installer_script for row in entries.values()),
                    "observed_trigger_entries": sum(row.trigger_metadata for row in entries.values()),
                },
                "next_required_authority": "NATIVE_RETAINED_FD_BUILD_GUEST_AND_OCI_LOCK",
                "solc_execution_policy": _SOLC_EXECUTION_POLICY,
            }
        )
        success = True
        return TestOnlyMaterializedRuntime(
            output_reader_descriptor, receipt, census, sbom, provenance
        )
    finally:
        _close_many(input_descriptors)
        if not success:
            try:
                os.ftruncate(output_writer_descriptor, 0)
            except OSError:
                pass
        _close_many((output_writer_descriptor,))
        if not success:
            _close_many((output_reader_descriptor,))


def _TEST_ONLY_verify_materialized_runtime(
    archive_descriptor: int,
    *,
    composition_manifest_bytes: bytes,
    receipt_bytes: bytes,
    census_bytes: bytes,
    sbom_bytes: bytes,
    provenance_bytes: bytes,
    expected_manifest_sha256: str,
) -> None:
    """Independently replay all external evidence against the retained archive."""

    identity = _fd_identity(archive_descriptor, "runtime archive", os.O_RDONLY)
    _, sources = _validate_composition_manifest(
        composition_manifest_bytes, expected_manifest_sha256
    )
    receipt = _bounded_json(receipt_bytes, maximum=2 * 1024 * 1024, label="runtime receipt")
    if (
        type(receipt) is not dict
        or frozenset(receipt) != _RECEIPT_KEYS
        or receipt.get("schema_version") != RECEIPT_SCHEMA_VERSION
    ):
        raise RuntimeMaterializationError("runtime receipt schema is unsupported")
    _require_sha256(expected_manifest_sha256, "composition manifest sha256")
    if (
        receipt.get("production_authority") is not False
        or receipt.get("status") != "TEST_ONLY_CONTENT_COMPOSED_PENDING_NATIVE_AUTHORITY"
        or receipt.get("composition_manifest_sha256") != expected_manifest_sha256
        or receipt.get("environment_denials") != _ENVIRONMENT_DENIALS
        or receipt.get("network") != "DENY"
        or receipt.get("target") != "linux/arm64"
        or receipt.get("next_required_authority")
        != "NATIVE_RETAINED_FD_BUILD_GUEST_AND_OCI_LOCK"
        or receipt.get("solc_execution_policy") != _SOLC_EXECUTION_POLICY
    ):
        raise RuntimeMaterializationError("runtime receipt policy binding is invalid")
    _require_sha256(receipt.get("source_roster_sha256"), "source roster sha256")
    if receipt["source_roster_sha256"] != _source_roster_sha256(sources):
        raise RuntimeMaterializationError("runtime source roster binding is invalid")
    archive = receipt.get("archive")
    if type(archive) is not dict or frozenset(archive) != _ARCHIVE_RECEIPT_KEYS:
        raise RuntimeMaterializationError("runtime archive receipt is malformed")
    _require_sha256(archive.get("sha256"), "runtime archive sha256")
    if (
        archive["media_type"] != "application/vnd.oci.image.layer.v1.tar"
        or type(archive["size"]) is not int
        or isinstance(archive["size"], bool)
        or archive["size"] != identity.size
    ):
        raise RuntimeMaterializationError("runtime archive size/media binding is invalid")
    observed_sha256 = _hash_fd(archive_descriptor, identity.size, "runtime archive")
    if archive["sha256"] != observed_sha256 or archive["diff_id"] != "sha256:" + observed_sha256:
        raise RuntimeMaterializationError("runtime archive digest binding is invalid")
    installed = receipt.get("installed")
    if type(installed) is not dict or frozenset(installed) != _INSTALLED_RECEIPT_KEYS:
        raise RuntimeMaterializationError("runtime installed evidence is malformed")
    for name in ("census_sha256", "sbom_sha256", "provenance_sha256"):
        _require_sha256(installed.get(name), f"runtime {name}")
    if (
        type(installed.get("entry_count")) is not int
        or isinstance(installed.get("entry_count"), bool)
        or not 0 < installed["entry_count"] <= MAX_ENTRIES
        or type(installed.get("expanded_bytes")) is not int
        or isinstance(installed.get("expanded_bytes"), bool)
        or not 0 <= installed["expanded_bytes"] <= MAX_EXPANDED_BYTES
    ):
        raise RuntimeMaterializationError("runtime installed bounds are invalid")
    package_execution = receipt.get("package_execution")
    if (
        type(package_execution) is not dict
        or frozenset(package_execution) != _PACKAGE_EXECUTION_KEYS
        or package_execution["compositor_executed_scripts"] is not False
        or package_execution["compositor_executed_triggers"] is not False
        or type(package_execution["observed_installer_script_entries"]) is not int
        or isinstance(package_execution["observed_installer_script_entries"], bool)
        or package_execution["observed_installer_script_entries"] < 0
        or type(package_execution["observed_trigger_entries"]) is not int
        or isinstance(package_execution["observed_trigger_entries"], bool)
        or package_execution["observed_trigger_entries"] < 0
    ):
        raise RuntimeMaterializationError("runtime package-execution evidence is invalid")
    if (
        installed["census_sha256"] != _digest(census_bytes)
        or installed["sbom_sha256"] != _digest(sbom_bytes)
        or installed["provenance_sha256"] != _digest(provenance_bytes)
    ):
        raise RuntimeMaterializationError("runtime evidence digest binding is invalid")
    census = _bounded_json(census_bytes, maximum=64 * 1024 * 1024, label="runtime census")
    if (
        type(census) is not dict
        or frozenset(census) != {"schema_version", "entries"}
        or census.get("schema_version") != CENSUS_SCHEMA_VERSION
    ):
        raise RuntimeMaterializationError("runtime census schema is unsupported")
    expected_rows = census.get("entries")
    if type(expected_rows) is not list or len(expected_rows) != installed["entry_count"]:
        raise RuntimeMaterializationError("runtime census count is invalid")
    prior_path: str | None = None
    for row in expected_rows:
        if type(row) is not dict or frozenset(row) != {
            "kind",
            "linkname",
            "mode",
            "path",
            "sha256",
            "size",
        }:
            raise RuntimeMaterializationError("runtime census entry schema is not exact")
        path = _normalize_path(row["path"], "runtime census path", absolute=False)
        if prior_path is not None and path.encode("utf-8") <= prior_path.encode("utf-8"):
            raise RuntimeMaterializationError("runtime census is not strictly ordered")
        prior_path = path
    observed_rows: list[dict[str, Any]] = []
    view = io.BufferedReader(_PreadFile(archive_descriptor, identity.size), buffer_size=_READ_CHUNK)
    try:
        tar = tarfile.open(fileobj=view, mode="r:")
    except tarfile.TarError as error:
        raise RuntimeMaterializationError("runtime archive is malformed") from error
    with tar:
        for member in tar:
            name = member.name[:-1] if member.name.endswith("/") else member.name
            if member.isdir():
                digest = None
                size = 0
                kind = "directory"
                linkname = ""
            elif member.isfile():
                stream = tar.extractfile(member)
                if stream is None:
                    raise RuntimeMaterializationError("runtime archive file is unavailable")
                digest_state = hashlib.sha256()
                size = 0
                for chunk in iter(lambda: stream.read(_READ_CHUNK), b""):
                    digest_state.update(chunk)
                    size += len(chunk)
                digest = digest_state.hexdigest()
                kind = "file"
                linkname = ""
            elif member.issym() or member.islnk():
                linkname = member.linkname
                kind = "symlink" if member.issym() else "hardlink"
                digest = _digest((kind + "\0" + linkname).encode("utf-8"))
                size = 0
            else:
                raise RuntimeMaterializationError("runtime archive contains a forbidden entry")
            if member.uid != 0 or member.gid != 0 or member.mtime != 0 or member.uname or member.gname:
                raise RuntimeMaterializationError("runtime archive metadata is not normalized")
            observed_rows.append(
                {
                    "kind": kind,
                    "linkname": linkname,
                    "mode": f"{member.mode:04o}",
                    "path": name,
                    "sha256": digest,
                    "size": size,
                }
            )
    observed_rows.sort(key=lambda row: row["path"].encode("utf-8"))
    if observed_rows != expected_rows:
        raise RuntimeMaterializationError("runtime census does not equal the archive")
    if sum(row["size"] for row in observed_rows if row["kind"] == "file") != installed["expanded_bytes"]:
        raise RuntimeMaterializationError("runtime expanded byte count is invalid")
    sbom = _bounded_json(sbom_bytes, maximum=64 * 1024 * 1024, label="runtime SBOM")
    provenance = _bounded_json(
        provenance_bytes, maximum=64 * 1024 * 1024, label="runtime provenance"
    )
    if (
        type(sbom) is not dict
        or frozenset(sbom)
        != {
            "SPDXID",
            "creationInfo",
            "dataLicense",
            "documentNamespace",
            "files",
            "name",
            "packages",
            "spdxVersion",
        }
        or sbom.get("spdxVersion") != "SPDX-2.3"
    ):
        raise RuntimeMaterializationError("runtime SBOM schema is unsupported")
    if (
        type(provenance) is not dict
        or frozenset(provenance)
        != {"schema_version", "composition_manifest_sha256", "outputs"}
        or provenance.get("schema_version") != PROVENANCE_SCHEMA_VERSION
        or provenance.get("composition_manifest_sha256") != expected_manifest_sha256
        or type(provenance.get("outputs")) is not list
    ):
        raise RuntimeMaterializationError("runtime provenance schema is unsupported")
    for row in provenance["outputs"]:
        if (
            type(row) is not dict
            or frozenset(row)
            != {"installer_script", "path", "sources", "trigger_metadata"}
            or type(row["installer_script"]) is not bool
            or type(row["trigger_metadata"]) is not bool
            or type(row["sources"]) is not list
            or not row["sources"]
            or row["sources"] != sorted(set(row["sources"]))
        ):
            raise RuntimeMaterializationError("runtime provenance output schema is invalid")
    census_paths = [row["path"] for row in expected_rows]
    provenance_paths = [row.get("path") for row in provenance.get("outputs", [])]
    sbom_file_paths = [row.get("fileName", "")[1:] for row in sbom.get("files", [])]
    if provenance_paths != census_paths:
        raise RuntimeMaterializationError("source provenance is not complete")
    if sbom_file_paths != [row["path"] for row in expected_rows if row["kind"] == "file"]:
        raise RuntimeMaterializationError("runtime SBOM file census is not complete")
    if package_execution["observed_installer_script_entries"] != sum(
        row["installer_script"] for row in provenance["outputs"]
    ) or package_execution["observed_trigger_entries"] != sum(
        row["trigger_metadata"] for row in provenance["outputs"]
    ):
        raise RuntimeMaterializationError("runtime package-execution census is inconsistent")


def staged_input_schema_bytes() -> bytes:
    """Return a canonical, non-authoritative description of the exact interface."""

    return _canonical_json(
        {
            "composition_manifest": {
                "schema_version": SCHEMA_VERSION,
                "exact_keys": sorted(_COMPOSITION_KEYS),
                "source_exact_keys": sorted(_SOURCE_KEYS),
                "backend_archive_source_manifest_exact_keys": sorted(
                    _BACKEND_ARCHIVE_SOURCE_MANIFEST_KEYS
                ),
                "required_role_order": list(_REQUIRED_ROLES),
                "apple_container_v2_required_role_order": list(
                    APPLE_CONTAINER_REQUIRED_ROLES
                ),
            },
            "descriptor_roster": [
                "payload O_RDONLY",
                "source-manifest O_RDONLY",
            ],
            "limits": _LIMITS,
            "output": "preopened unlinked same-inode O_RDWR/O_RDONLY pair",
            "production_status": (
                "NATIVE_RETAINED_FD_BUILD_GUEST_AUTHORITY_REQUIRED:"
                "APPLE_CONTAINER_V2_STATIC_TOOL_ROSTER_UNSIGNED"
            ),
            "schema_version": "plamen.runtime_materializer_staged_input_schema.v1",
            "unsupported_install_media": sorted(_UNSUPPORTED_INSTALL_MEDIA),
        }
    )


__all__ = [
    "APPLE_CONTAINER_COMPOSITION_SCHEMA_VERSION",
    "APPLE_CONTAINER_IMAGE_GENERATION_POLICY_PATH",
    "APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SCHEMA",
    "APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SHA256",
    "APPLE_CONTAINER_IMAGE_GENERATION_POLICY_SIZE",
    "APPLE_CONTAINER_REQUIRED_ROLES",
    "BUILDER_PROTOCOL_SCHEMA_VERSION",
    "CENSUS_SCHEMA_VERSION",
    "MAX_ENTRIES",
    "MAX_EXPANDED_BYTES",
    "MAX_INPUT_BYTES",
    "NETWORKLESS_LINUX_BUILDER_PROTOCOL",
    "NetworklessLinuxBuilderRequired",
    "PROVENANCE_SCHEMA_VERSION",
    "RECEIPT_SCHEMA_VERSION",
    "RetainedRuntimeInput",
    "RuntimeMaterializationError",
    "RuntimeMaterializationUnsupported",
    "SCHEMA_VERSION",
    "SOURCE_MANIFEST_SCHEMA_VERSION",
    "TestOnlyMaterializedRuntime",
    "materialize_runtime_image",
    "load_apple_container_image_generation_policy",
    "render_backend_archive_source_manifest",
    "staged_input_schema_bytes",
    "validate_apple_container_composition_candidate",
]
