"""One-shot custody for native source-bootstrap setup descriptors.

The setup materializer resolves only the reviewed immutable upstream objects,
derives the two frozen Plamen projections through a retained source authority,
and keeps every result in a caller-owned private store.  The signed fixed-role
producer then supplies seven retained role triples.  No repository, cache, or
HOME pathname is accepted as authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
from types import ModuleType
from typing import Any, Callable, Mapping, NoReturn, Protocol
import urllib.error
import urllib.parse
import urllib.request

if os.name == "posix":
    import fcntl
else:
    fcntl = None


FIXED_ROLE_ORDINALS = (0, 1, 2, 3, 4, 7, 10)
OUTPUT_COUNT = 5
SCRATCH_COUNT = 24
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_LABEL = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOSED_ENV = {
    "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin",
    "PYTHONHASHSEED": "0",
}
_ROLE_NAMES = {
    0: "base_rootfs", 1: "debian_package_state", 2: "plamen_guest",
    3: "cpython", 4: "plamen_package", 7: "foundry",
    10: "amd64_compat",
}
_MATERIAL_SOURCE_ROLES = {
    0: (
        "runtime_role10_base_rootfs_acquisition_policy",
        "runtime_role10_base_rootfs_source_manifest",
    ),
    1: (
        "runtime_role10_debian_package_state_acquisition_policy",
        "runtime_role10_debian_package_state_source_manifest",
    ),
    2: ("runtime_role10_plamen_guest_acquisition_policy", None),
    3: (
        "runtime_role10_cpython_acquisition_policy",
        "runtime_role10_cpython_source_manifest",
    ),
    4: ("runtime_role10_plamen_package_acquisition_policy", None),
    7: (
        "foundry_acquisition_policy", "foundry_runtime_source_manifest",
    ),
    10: (
        "amd64_compat_acquisition_policy",
        "amd64_compat_runtime_source_manifest",
    ),
}
_SEMANTIC_SOURCE_ROLES = {
    7: "foundry_acquisition_receipt",
    10: "amd64_compat_acquisition_receipt",
}
_POLICY_IDENTITY = {
    0: (3224, "0b99540e2f193533ec15808820b914ae6638860fed9cab64b11897b1e58abd45"),
    1: (1247, "a2ab7976b0d65e3144ed24672796e4f6c249f234dd758b2e3db8eb6ab570ed6c"),
    2: (1106, "02927beca9af860b8001fc5add064484c28f8e68a8076d99629965e55c605401"),
    3: (1762, "9484a90eae84561a57c85971b34469a1eca7f12a849e670761be1b7ab8826e38"),
    4: (1172, "430ba913907e7c71594b2fbeae33309d32e3ce6e135a5cb593a1aad190ac891b"),
    7: (2307, "b52bbbcd7eb6900bc6d6fdafbd45465cad4a47ab211ac5a1438f180f9e2eff6a"),
    10: (2562, "d7951743a7c7f4573ded15905320a56debbee12578d561144086456a110b8d7e"),
}
_RUNTIME_STATIC_RECEIPT_IDENTITY = {
    0: (1064, "41cffd26c10b7842e976c809f00273caf26f0a72cdba0fda38887ce277a47309"),
    1: (1176, "ea38e4b6ee41511f00b2d583f4dc5875318b71abfd0b436160fdc043375e6a98"),
    3: (1322, "15ae3230f2c05b4d14fade1628dfb8287185344bff343997e1de196167908dd0"),
}
_UPSTREAM_URLS = {
    3: (
        "https://github.com/astral-sh/python-build-standalone/releases/"
        "download/20251010/cpython-3.12.12%2B20251010-aarch64-unknown-"
        "linux-gnu-install_only.tar.gz"
    ),
    7: (
        "https://github.com/foundry-rs/foundry/releases/download/v1.8.1/"
        "foundry_v1.8.1_linux_arm64.tar.gz"
    ),
}
_UPSTREAM_IDENTITY = {
    3: (80_116_339, "21bcf71dccb56ef611f50543b04e63e6585ac063463f2d248cb4ec28118d264d"),
    7: (114_076_891, "27a32bd282d73018ab4d043de15ab0320b561c71b4bf3a549b130a0806e79f5c"),
}
_UPSTREAM_ROOTFS_IDENTITY = (
    28_117_289,
    "75782e20ea1f4a9d9259bc20a5ecbbea8d5943bf5370bf0f5727900728f1cc9a",
)
_FINAL_IDENTITY = {
    0: (100_236_788, "70b69e00fbe608f857f0cc44b0b4b504423fe9008df287d260760ed2a84da7f0"),
    1: (8_923, "6a77fdab20a14a27c0401cceff7f85393b45cc341695dd75325358e30d88640c"),
    3: (222_525_440, "0bf0e5d7680c37a46edc59ed9ce274cd311d229387decc16ef8c7318df09c711"),
    7: (269_271_040, "b19dfe910e75b23aabd21f58181f561bca73d51a24be39fa3b900ecd5f0d288b"),
    10: (3_112_960, "4e9c886e6558a93cfbdab5cec905852209fc3c61a867c9672a0162522e36e490"),
}
_MANIFEST_IDENTITY = {
    0: (857, "64ce7200e0ea45abd9f6d9a4dfcade1718d17ce56b0725975e23b9a6f41d5eac"),
    1: (696, "446977b75da213f7bffdfef8c09332271de8ff0a4b8ea582886c326404890006"),
    3: (636, "19747fd0434e6475b8b20a67ef8421b3e3c58caf198b2e0e3d3526011324a734"),
    7: (745, "6f380e0dd982ebc76a77e5c463b765c04ed440ebf2ed873bf691d4d927bed9f9"),
    10: (652, "5d05126bd00f1765d09a5a27dba8b144a81fcc96e6c50f9ff5410b740dda74a0"),
}
_SEMANTIC_IDENTITY = {
    7: (1616, "1bd453b262415bc1153d4ecdecc99e134b96df45f3d511b7a2f144ed87ede436"),
    10: (2504, "808eeea571533676faf9cd9d41b7a146f62f4a3baee29ee3d4d89965eca26fa0"),
}
_MAX_SOURCE_MEMBER = 16 * 1024 * 1024
_READ_CHUNK = 1024 * 1024


class NativeFixedRoleAcquisitionError(RuntimeError):
    """The setup descriptor roster or its custody differs."""


def _fail(message: str) -> NoReturn:
    raise NativeFixedRoleAcquisitionError(message) from None


@dataclass(frozen=True, slots=True)
class FixedRoleMaterializedInput:
    ordinal: int
    payload_fd: int
    semantic_receipt_fd: int
    source_manifest_fd: int
    reviewed_policy_fd: int


@dataclass(frozen=True, slots=True)
class FixedRoleRecord:
    ordinal: int
    policy_sha256: str
    payload_fd: int
    producer_receipt_fd: int
    source_manifest_fd: int


class NativeFixedRoleIssuer(Protocol):
    def __call__(
        self,
        staged_generation_root_fd: int,
        inputs: tuple[FixedRoleMaterializedInput, ...],
    ) -> tuple[FixedRoleRecord, ...]: ...


class RetainedFixedRoleSourceAuthority(Protocol):
    _PLAMEN_RETAINED_FIXED_ROLE_SOURCE_V1: bool

    def duplicate_member(self, role: str) -> int: ...

    def duplicate_projection_manifest(self, role: str) -> int: ...

    def duplicate_projection_member(self, role: str, index: int) -> int: ...


class SetupHTTPSFetcher(Protocol):
    _PLAMEN_SETUP_HTTPS_FETCHER_V1: bool

    def fetch_exact(
        self, url: str, *, writer_fd: int, expected_size: int,
        expected_sha256: str, allowed_hosts: tuple[str, ...],
        maximum_redirects: int,
        redirect_targets: tuple[tuple[str, str], ...] = (),
        authorization: str | None = None,
    ) -> None: ...

    def anonymous_bearer_token(
        self, *, endpoint: str, audience: str, scope: str,
    ) -> str: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DefaultSetupHTTPSFetcher:
    """Exact, proxy-free setup transport; downloaded bytes grant no authority."""

    __slots__ = ("_opener",)
    _PLAMEN_SETUP_HTTPS_FETCHER_V1 = True

    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )

    def _open(
        self, url: str, *, allowed_hosts: tuple[str, ...],
        maximum_redirects: int,
        redirect_targets: tuple[tuple[str, str], ...],
        authorization: str | None,
    ):
        current = url
        current_authorization = authorization
        for count in range(maximum_redirects + 1):
            parsed = urllib.parse.urlsplit(current)
            if (
                parsed.scheme != "https" or parsed.username is not None
                or parsed.password is not None or parsed.hostname not in allowed_hosts
                or parsed.fragment
            ):
                _fail("setup HTTPS endpoint escaped its reviewed authority")
            headers = {
                "Accept-Encoding": "identity",
                "User-Agent": "plamen-native-setup/1",
            }
            if current_authorization is not None:
                headers["Authorization"] = current_authorization
            request = urllib.request.Request(current, headers=headers, method="GET")
            try:
                return self._opener.open(request, timeout=60)
            except urllib.error.HTTPError as error:
                if error.code not in {301, 302, 303, 307, 308}:
                    raise
                location = error.headers.get("Location")
                error.close()
                if count >= maximum_redirects or not location:
                    _fail("setup HTTPS redirect policy differs")
                redirected = urllib.parse.urljoin(current, location)
                target = urllib.parse.urlsplit(redirected)
                if (
                    target.scheme != "https" or target.username is not None
                    or target.password is not None or target.fragment
                    or (target.hostname, target.path) not in redirect_targets
                ):
                    _fail("setup HTTPS redirect target differs")
                if target.hostname != parsed.hostname:
                    current_authorization = None
                current = redirected
        _fail("setup HTTPS redirect policy differs")

    def fetch_exact(
        self, url: str, *, writer_fd: int, expected_size: int,
        expected_sha256: str, allowed_hosts: tuple[str, ...],
        maximum_redirects: int,
        redirect_targets: tuple[tuple[str, str], ...] = (),
        authorization: str | None = None,
    ) -> None:
        if (
            type(url) is not str or type(expected_size) is not int
            or not 0 < expected_size <= 512 * 1024 * 1024
            or type(expected_sha256) is not str
            or _HEX64.fullmatch(expected_sha256) is None
            or type(allowed_hosts) is not tuple or not allowed_hosts
            or type(maximum_redirects) is not int
            or not 0 <= maximum_redirects <= 5
            or type(redirect_targets) is not tuple
            or any(
                type(row) is not tuple or len(row) != 2
                or type(row[0]) is not str or row[0] not in allowed_hosts
                or type(row[1]) is not str or not row[1].startswith("/")
                for row in redirect_targets
            )
        ):
            _fail("setup HTTPS request differs")
        digest = hashlib.sha256()
        total = 0
        try:
            response = self._open(
                url, allowed_hosts=allowed_hosts,
                maximum_redirects=maximum_redirects,
                redirect_targets=redirect_targets,
                authorization=authorization,
            )
            with response:
                if getattr(response, "status", 200) != 200:
                    _fail("setup HTTPS response status differs")
                while total < expected_size:
                    block = response.read(min(_READ_CHUNK, expected_size - total))
                    if not block:
                        break
                    view = memoryview(block)
                    while view:
                        amount = os.write(writer_fd, view)
                        if amount <= 0:
                            _fail("setup HTTPS store write failed")
                        view = view[amount:]
                    digest.update(block)
                    total += len(block)
                if response.read(1):
                    _fail("setup HTTPS response exceeds its reviewed size")
        except NativeFixedRoleAcquisitionError:
            raise
        except (OSError, urllib.error.URLError, TimeoutError):
            _fail("setup HTTPS transport failed")
        if total != expected_size or digest.hexdigest() != expected_sha256:
            _fail("setup HTTPS object identity differs")

    def anonymous_bearer_token(
        self, *, endpoint: str, audience: str, scope: str,
    ) -> str:
        if (
            endpoint != "https://auth.docker.io/token"
            or audience != "registry.docker.io"
            or scope != "repository:library/debian:pull"
        ):
            _fail("registry authentication authority differs")
        query = urllib.parse.urlencode({"service": audience, "scope": scope})
        response = self._open(
            endpoint + "?" + query, allowed_hosts=("auth.docker.io",),
            maximum_redirects=0, redirect_targets=(), authorization=None,
        )
        try:
            with response:
                raw = response.read(16 * 1024 + 1)
        except (OSError, urllib.error.URLError, TimeoutError):
            _fail("registry authentication failed")
        if len(raw) > 16 * 1024:
            _fail("registry authentication response is oversized")
        try:
            value = json.loads(raw.decode("ascii"))
        except (UnicodeError, ValueError):
            _fail("registry authentication response is malformed")
        token = value.get("token") if type(value) is dict else None
        if (
            type(token) is not str or not 32 <= len(token) <= 8192
            or any(ord(character) < 0x21 or ord(character) > 0x7e for character in token)
        ):
            _fail("registry authentication token differs")
        return token


class ProductionFixedRoleMaterializationAuthority:
    """Opaque custody for the 28 exact native fixed-role input descriptors."""

    __slots__ = ("_lock", "_inputs", "_closed", "_cleanup")
    _PLAMEN_PRODUCTION_FIXED_ROLE_MATERIALIZATION_V1 = True

    def __init__(
        self, inputs: tuple[FixedRoleMaterializedInput, ...],
        cleanup: Callable[[], None],
    ) -> None:
        self._lock = threading.Lock()
        self._inputs = inputs
        self._closed = False
        self._cleanup = cleanup

    def materialized_inputs(self) -> tuple[FixedRoleMaterializedInput, ...]:
        with self._lock:
            if self._closed:
                _fail("production fixed-role materialization is closed")
            _validate_materialized_inputs(self._inputs)
            return self._inputs

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            inputs = self._inputs
            self._inputs = ()
            cleanup = self._cleanup
            self._cleanup = lambda: None
        _close_many([
            descriptor for row in inputs for descriptor in (
                row.payload_fd, row.semantic_receipt_fd,
                row.source_manifest_fd, row.reviewed_policy_fd,
            )
        ])
        cleanup()


def _fd_flags(descriptor: int) -> tuple[int, int]:
    if fcntl is None:
        _fail("native setup descriptors require POSIX")
    if type(descriptor) is not int or descriptor < 3:
        _fail("native setup descriptor differs")
    try:
        return fcntl.fcntl(descriptor, fcntl.F_GETFL), fcntl.fcntl(
            descriptor, fcntl.F_GETFD
        )
    except OSError:
        _fail("native setup descriptor is unavailable")


def _identity(
    descriptor: int, *, access: int, links: int, empty: bool | None,
) -> tuple[int, int]:
    flags, descriptor_flags = _fd_flags(descriptor)
    try:
        info = os.fstat(descriptor)
    except OSError:
        _fail("native setup descriptor is unavailable")
    if (
        flags & os.O_ACCMODE != access
        or not descriptor_flags & fcntl.FD_CLOEXEC
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != links
        or stat.S_IMODE(info.st_mode) & 0o022
        or (empty is True and info.st_size != 0)
        or (empty is False and info.st_size <= 0)
    ):
        _fail("native setup descriptor identity differs")
    return info.st_dev, info.st_ino


def _close_many(descriptors: list[int] | tuple[int, ...]) -> None:
    for descriptor in reversed(descriptors):
        if type(descriptor) is int and descriptor >= 3:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _sha256_fd(descriptor: int) -> str:
    try:
        size = os.fstat(descriptor).st_size
    except OSError:
        _fail("native setup descriptor is unavailable")
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        block = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not block:
            _fail("native setup descriptor changed during hashing")
        digest.update(block)
        offset += len(block)
    if os.fstat(descriptor).st_size != size:
        _fail("native setup descriptor changed during hashing")
    return digest.hexdigest()


def _read_fd_exact(descriptor: int, maximum: int, label: str) -> bytes:
    try:
        info = os.fstat(descriptor)
    except OSError:
        _fail(f"{label} descriptor is unavailable")
    if not 0 < info.st_size <= maximum:
        _fail(f"{label} size differs")
    result = bytearray()
    while len(result) < info.st_size:
        block = os.pread(
            descriptor, min(_READ_CHUNK, info.st_size - len(result)), len(result),
        )
        if not block:
            _fail(f"{label} changed during read")
        result.extend(block)
    if os.fstat(descriptor).st_size != info.st_size:
        _fail(f"{label} changed during read")
    return bytes(result)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        try:
            amount = os.write(descriptor, view)
        except OSError:
            _fail("fixed-role private-store write failed")
        if amount <= 0:
            _fail("fixed-role private-store write failed")
        view = view[amount:]


def _seal_materialized_pair(
    writer: int, reader: int, *, size: int, sha256: str,
) -> int:
    try:
        os.fsync(writer)
        info = os.fstat(writer)
        if info.st_size != size or _sha256_fd(reader) != sha256:
            _fail("fixed-role materialized identity differs")
        os.fchmod(writer, 0o400)
        os.fsync(writer)
        os.close(writer)
        writer = -1
        _identity(reader, access=os.O_RDONLY, links=1, empty=False)
        if stat.S_IMODE(os.fstat(reader).st_mode) != 0o400:
            _fail("fixed-role materialized mode differs")
        return reader
    finally:
        if writer >= 0:
            try:
                os.close(writer)
            except OSError:
                pass


def _duplicate_source_member(
    authority: RetainedFixedRoleSourceAuthority, role: str,
    *, expected: tuple[int, str] | None = None,
) -> int:
    try:
        descriptor = authority.duplicate_member(role)
    except BaseException as exc:
        if isinstance(exc, NativeFixedRoleAcquisitionError):
            raise
        _fail(f"retained source member {role} is unavailable")
    try:
        _identity(descriptor, access=os.O_RDONLY, links=1, empty=False)
        if expected is not None:
            size, digest = expected
            if os.fstat(descriptor).st_size != size or _sha256_fd(descriptor) != digest:
                _fail(f"retained source member {role} differs")
        return descriptor
    except BaseException:
        _close_many([descriptor])
        raise


def _load_retained_runtime_policy_module(
    authority: RetainedFixedRoleSourceAuthority,
) -> ModuleType:
    descriptor = _duplicate_source_member(
        authority, "runtime_role10_acquisition",
    )
    try:
        raw = _read_fd_exact(
            descriptor, _MAX_SOURCE_MEMBER, "runtime role policy module",
        )
    finally:
        os.close(descriptor)
    module = ModuleType("_plamen_retained_runtime_role10_acquisition")
    module.__file__ = "<retained:runtime_role10_acquisition>"
    module.__package__ = ""
    previous = sys.modules.get(module.__name__)
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        _fail("retained runtime role policy module failed closed")
    finally:
        if previous is None:
            sys.modules.pop(module.__name__, None)
        else:
            sys.modules[module.__name__] = previous
    required = (
        "load_exact_reviewed_policy", "render_source_manifest_candidate",
        "render_static_semantic_receipt",
        "render_frozen_plamen_semantic_receipt",
        "validate_debian_package_state_payload",
    )
    if any(not callable(getattr(module, name, None)) for name in required):
        _fail("retained runtime role policy interface differs")
    return module


def _load_retained_elf_closure_module(
    authority: RetainedFixedRoleSourceAuthority,
) -> ModuleType:
    """Load only the frozen cache-free recipe retained by the source roster."""

    descriptor = _duplicate_source_member(authority, "native_elf_loader_closure")
    try:
        raw = _read_fd_exact(
            descriptor, _MAX_SOURCE_MEMBER, "cache-free rootfs recipe module",
        )
    finally:
        os.close(descriptor)
    module = ModuleType("_plamen_retained_elf_loader_closure")
    module.__file__ = "<retained:native_elf_loader_closure>"
    module.__package__ = ""
    previous = sys.modules.get(module.__name__)
    sys.modules[module.__name__] = module
    try:
        exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        _fail("retained cache-free rootfs recipe failed closed")
    finally:
        if previous is None:
            sys.modules.pop(module.__name__, None)
        else:
            sys.modules[module.__name__] = previous
    required = ("derive_cache_free_rootfs", "pinned_provenance_bytes")
    if any(not callable(getattr(module, name, None)) for name in required):
        _fail("retained cache-free rootfs recipe interface differs")
    expected_constants = {
        "RECIPE_VERSION": "plamen.debian_arm64_cache_free.v1",
        "SOURCE_LAYER_SHA256": _UPSTREAM_ROOTFS_IDENTITY[1],
        "SOURCE_LAYER_SIZE": _UPSTREAM_ROOTFS_IDENTITY[0],
        "DERIVED_LAYER_SHA256": _FINAL_IDENTITY[0][1],
        "DERIVED_LAYER_SIZE": _FINAL_IDENTITY[0][0],
        "DERIVATION_MANIFEST_SHA256":
            "0960d7dd99bbd7acc6027579118eb1f8402400f888c35df095cebd949811edf3",
    }
    if any(getattr(module, key, None) != value for key, value in expected_constants.items()):
        _fail("retained cache-free rootfs recipe identity differs")
    return module


def _safe_tar_name(value: str) -> str:
    if (
        type(value) is not str or not value or value.startswith(("/", "\\"))
        or "\\" in value or "\x00" in value
    ):
        _fail("fixed-role archive member path differs")
    normalized = value[:-1] if value.endswith("/") else value
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        _fail("fixed-role archive member path differs")
    try:
        normalized.encode("utf-8", "strict")
    except UnicodeError:
        _fail("fixed-role archive member encoding differs")
    return normalized


@dataclass(slots=True)
class _TarProjectionMember:
    path: str
    kind: str
    mode: int
    size: int
    offset: int
    linkname: str


class _SpoolView(io.RawIOBase):
    def __init__(self, descriptor: int, offset: int, size: int) -> None:
        self._descriptor = descriptor
        self._start = offset
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
        raw = os.pread(self._descriptor, count, self._start + self._position)
        if not raw:
            _fail("fixed-role transform spool was truncated")
        buffer[:len(raw)] = raw
        self._position += len(raw)
        return len(raw)


def _canonical_ustar(
    source_fd: int, writer_fd: int, *, role: int,
    selected: Mapping[str, tuple[str, str]] | None = None,
) -> None:
    """Apply the three reviewed archive transforms without pathname I/O."""

    source_size = os.fstat(source_fd).st_size
    source = _SpoolView(source_fd, 0, source_size)
    members: list[_TarProjectionMember] = []
    names: set[str] = set()
    with tempfile.TemporaryFile(mode="w+b") as spool:
        try:
            archive = tarfile.open(fileobj=source, mode="r:*")
        except (tarfile.TarError, OSError):
            _fail("fixed-role upstream archive is malformed")
        with archive:
            if archive.pax_headers:
                _fail("fixed-role archive global metadata is forbidden")
            for item in archive:
                if item.pax_headers:
                    _fail("fixed-role archive extended metadata is forbidden")
                name = _safe_tar_name(item.name)
                if name in names:
                    _fail("fixed-role archive contains duplicate members")
                names.add(name)
                output: str | None = None
                expected_kind: str | None = None
                if role == 3:
                    if not name.startswith("python/"):
                        _fail("CPython archive escaped its reviewed prefix")
                    output = name[len("python/"):]
                    if not output or output.startswith("share/terminfo/"):
                        continue
                    if item.isdir():
                        continue
                    if not (item.isfile() or item.issym()):
                        _fail("CPython archive member kind differs")
                elif role == 7:
                    allowed = {"anvil", "cast", "chisel", "forge", "solar"}
                    if name not in allowed or not item.isfile():
                        _fail("Foundry archive roster differs")
                    output = "bin/" + name
                elif role == 10:
                    if selected is None or name not in selected:
                        continue
                    output, expected_kind = selected[name]
                    if expected_kind == "file" and not item.isfile():
                        _fail("amd64 compatibility file kind differs")
                    if expected_kind == "symlink" and not item.issym():
                        _fail("amd64 compatibility symlink kind differs")
                else:
                    _fail("fixed-role archive transform is unsupported")
                if output is None:
                    continue
                output = _safe_tar_name(output)
                if any(row.path == output for row in members):
                    _fail("fixed-role archive projection collides")
                if item.issym():
                    link = item.linkname
                    if type(link) is not str or not link or "\x00" in link:
                        _fail("fixed-role archive symlink differs")
                    members.append(_TarProjectionMember(
                        output, "symlink", 0o555, 0, 0, link,
                    ))
                    continue
                if item.size < 0 or item.size > 512 * 1024 * 1024:
                    _fail("fixed-role archive member size differs")
                extracted = archive.extractfile(item)
                if extracted is None:
                    _fail("fixed-role archive member payload is unavailable")
                offset = spool.tell()
                remaining = item.size
                while remaining:
                    block = extracted.read(min(_READ_CHUNK, remaining))
                    if not block:
                        _fail("fixed-role archive member was truncated")
                    spool.write(block)
                    remaining -= len(block)
                if extracted.read(1):
                    _fail("fixed-role archive member exceeds its header size")
                members.append(_TarProjectionMember(
                    output, "file", 0o555 if item.mode & 0o111 else 0o444,
                    item.size, offset, "",
                ))
        if role == 7 and {row.path for row in members} != {
            "bin/anvil", "bin/cast", "bin/chisel", "bin/forge", "bin/solar",
        }:
            _fail("Foundry archive roster differs")
        if role == 10 and selected is not None and {
            row.path for row in members
        } != {value[0] for value in selected.values()}:
            _fail("amd64 compatibility archive roster differs")
        # ``TemporaryFile`` is buffered.  The views handed to tarfile use
        # descriptor-relative reads, so publish the buffered bytes to the
        # descriptor before any view can consume them.
        spool.flush()
        duplicate = os.dup(writer_fd)
        try:
            with os.fdopen(duplicate, "wb", closefd=True) as output:
                duplicate = -1
                with tarfile.open(
                    fileobj=output, mode="w", format=tarfile.USTAR_FORMAT,
                ) as rendered:
                    for row in sorted(members, key=lambda value: value.path.encode("utf-8")):
                        info = tarfile.TarInfo(row.path)
                        info.mode = row.mode
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ""
                        if row.kind == "symlink":
                            info.type = tarfile.SYMTYPE
                            info.size = 0
                            info.linkname = row.linkname
                            rendered.addfile(info)
                        else:
                            info.type = tarfile.REGTYPE
                            info.size = row.size
                            rendered.addfile(
                                info, _SpoolView(spool.fileno(), row.offset, row.size),
                            )
                output.flush()
                os.fsync(output.fileno())
        finally:
            if duplicate >= 0:
                os.close(duplicate)


def _render_debian_package_state(source_fd: int) -> bytes:
    source = _SpoolView(source_fd, 0, os.fstat(source_fd).st_size)
    try:
        archive = tarfile.open(fileobj=source, mode="r:*")
    except (tarfile.TarError, OSError):
        _fail("Debian rootfs archive is malformed")
    status: bytes | None = None
    with archive:
        for item in archive:
            name = item.name[2:] if item.name.startswith("./") else item.name
            if name != "var/lib/dpkg/status":
                continue
            if status is not None or not item.isfile() or item.size > 16 * 1024 * 1024:
                _fail("Debian package-state source member differs")
            stream = archive.extractfile(item)
            if stream is None:
                _fail("Debian package-state source is unavailable")
            status = stream.read(item.size + 1)
            if len(status) != item.size:
                _fail("Debian package-state source was truncated")
    if status is None:
        _fail("Debian package-state source is absent")
    try:
        text = status.decode("utf-8", "strict").replace("\r\n", "\n")
    except UnicodeError:
        _fail("Debian package-state source encoding differs")
    packages: list[dict[str, str]] = []
    for paragraph in text.strip("\n").split("\n\n"):
        fields: dict[str, str] = {}
        current: str | None = None
        for line in paragraph.split("\n"):
            if line.startswith((" ", "\t")):
                if current is None:
                    _fail("Debian package-state continuation differs")
                fields[current] += "\n" + line
                continue
            key, separator, value = line.partition(": ")
            if not separator or not key or key in fields:
                _fail("Debian package-state field differs")
            fields[key] = value
            current = key
        required = ("Package", "Architecture", "Version", "Status")
        if any(not fields.get(name) for name in required):
            _fail("Debian package-state package identity differs")
        if fields["Status"] == "install ok installed":
            packages.append({
                "architecture": fields["Architecture"],
                "name": fields["Package"], "status": fields["Status"],
                "version": fields["Version"],
            })
    packages.sort(key=lambda row: (row["name"], row["architecture"], row["version"]))
    return json.dumps(
        {"packages": packages, "schema_version": "plamen.debian_package_state.v1"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _bounded_canonical_json(raw: bytes, label: str) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_SOURCE_MEMBER or raw.endswith((b"\n", b"\r")):
        _fail(f"{label} bytes differ")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError):
        _fail(f"{label} is malformed")
    if (
        type(value) is not dict
        or json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii") != raw
    ):
        _fail(f"{label} is not canonical JSON")
    return value


def _projection_payload(
    authority: RetainedFixedRoleSourceAuthority, role: str, writer_fd: int,
) -> dict[str, Any]:
    manifest_fd = -1
    member_fds: list[int] = []
    try:
        manifest_fd = authority.duplicate_projection_manifest(role)
        _identity(manifest_fd, access=os.O_RDONLY, links=1, empty=False)
        raw = _read_fd_exact(
            manifest_fd, _MAX_SOURCE_MEMBER, f"{role} projection manifest",
        )
        manifest_sha256 = hashlib.sha256(raw).hexdigest()
        value = _bounded_canonical_json(raw, f"{role} projection manifest")
        expected_fields = {
            "projection_authority", "role", "roster_sha256", "rows",
            "schema", "source_commit",
        }
        authority_row = value.get("projection_authority")
        rows = value.get("rows")
        if (
            set(value) != expected_fields
            or value.get("schema") != "plamen.fixed-role-source-projection.v1"
            or value.get("role") != role
            or type(value.get("source_commit")) is not str
            or re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is None
            or type(value.get("roster_sha256")) is not str
            or _HEX64.fullmatch(value["roster_sha256"]) is None
            or type(authority_row) is not dict
            or set(authority_row) != {"schema", "sha256", "size"}
            or type(authority_row.get("schema")) is not str
            or not authority_row["schema"].startswith(
                "plamen.native-" if role == "plamen_guest"
                else "plamen.runtime-source-projection."
            )
            or type(authority_row.get("sha256")) is not str
            or _HEX64.fullmatch(authority_row["sha256"]) is None
            or type(authority_row.get("size")) is not int
            or not 0 < authority_row["size"] <= _MAX_SOURCE_MEMBER
            or type(rows) is not list or not rows or len(rows) > 32768
        ):
            _fail(f"{role} projection authority differs")
        normalized: list[dict[str, Any]] = []
        prior: bytes | None = None
        roster = hashlib.sha256()
        roster.update(b"PLAMEN-FIXED-ROLE-SOURCE-PROJECTION-V1\0")
        for index, row in enumerate(rows):
            if (
                type(row) is not dict
                or set(row) != {"mode", "path", "sha256", "size"}
                or type(row.get("path")) is not str
                or type(row.get("mode")) is not int
                or row["mode"] not in {0o400, 0o500}
                or type(row.get("size")) is not int
                or not 0 < row["size"] <= 2 * 1024 * 1024 * 1024
                or type(row.get("sha256")) is not str
                or _HEX64.fullmatch(row["sha256"]) is None
            ):
                _fail(f"{role} projection row differs")
            path = _safe_tar_name(row["path"])
            encoded = path.encode("utf-8")
            if prior is not None and encoded <= prior:
                _fail(f"{role} projection rows are not strictly ordered")
            prior = encoded
            descriptor = authority.duplicate_projection_member(role, index)
            member_fds.append(descriptor)
            _identity(descriptor, access=os.O_RDONLY, links=1, empty=False)
            if (
                os.fstat(descriptor).st_size != row["size"]
                or _sha256_fd(descriptor) != row["sha256"]
            ):
                _fail(f"{role} projection member differs")
            roster.update(len(encoded).to_bytes(4, "big"))
            roster.update(encoded)
            roster.update(row["mode"].to_bytes(4, "big"))
            roster.update(row["size"].to_bytes(8, "big"))
            roster.update(bytes.fromhex(row["sha256"]))
            normalized.append({**row, "path": path, "fd": descriptor})
        if roster.hexdigest() != value["roster_sha256"]:
            _fail(f"{role} projection roster differs")
        duplicate = os.dup(writer_fd)
        try:
            with os.fdopen(duplicate, "wb", closefd=True) as output:
                duplicate = -1
                with tarfile.open(
                    fileobj=output, mode="w", format=tarfile.USTAR_FORMAT,
                ) as archive:
                    for row in normalized:
                        info = tarfile.TarInfo(row["path"])
                        info.mode = 0o555 if row["mode"] & 0o100 else 0o444
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ""
                        info.type = tarfile.REGTYPE
                        info.size = row["size"]
                        archive.addfile(
                            info, _SpoolView(row["fd"], 0, row["size"]),
                        )
                output.flush()
                os.fsync(output.fileno())
        finally:
            if duplicate >= 0:
                os.close(duplicate)
        return {
            "manifest_sha256": manifest_sha256,
            "projection_authority_schema": authority_row["schema"],
            "projection_authority_sha256": authority_row["sha256"],
            "projection_authority_size": authority_row["size"],
            "projection_roster_sha256": value["roster_sha256"],
            "source_commit": value["source_commit"],
        }
    except (OSError, NativeFixedRoleAcquisitionError):
        raise
    except BaseException:
        _fail(f"{role} retained projection failed")
    finally:
        _close_many(member_fds)
        if manifest_fd >= 0:
            os.close(manifest_fd)


def _temporary_download(
    private_store: RetainedPrivateStoreFactory, fetcher: SetupHTTPSFetcher,
    label: str, url: str, identity: tuple[int, str], *,
    hosts: tuple[str, ...], redirects: int,
    redirect_targets: tuple[tuple[str, str], ...] = (),
    authorization: str | None = None,
) -> int:
    writer, reader = private_store.pair(label, linked=False)
    try:
        fetcher.fetch_exact(
            url, writer_fd=writer, expected_size=identity[0],
            expected_sha256=identity[1], allowed_hosts=hosts,
            maximum_redirects=redirects, authorization=authorization,
            redirect_targets=redirect_targets,
        )
        os.fsync(writer)
        if (
            os.fstat(reader).st_size != identity[0]
            or _sha256_fd(reader) != identity[1]
        ):
            _fail("downloaded fixed-role input differs")
        os.close(writer)
        writer = -1
        return reader
    except BaseException:
        _close_many([reader])
        raise
    finally:
        _close_many([writer])


def _new_linked_output(
    private_store: RetainedPrivateStoreFactory, label: str,
) -> tuple[int, int]:
    writer, reader = private_store.pair(label, linked=True)
    try:
        os.ftruncate(writer, 0)
        os.lseek(writer, 0, os.SEEK_SET)
    except OSError:
        _close_many([reader, writer])
        try:
            private_store.unlink_linked(label)
        except NativeFixedRoleAcquisitionError:
            pass
        raise
    return writer, reader


def _open_relative_directory(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for component in parts:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC | _NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def run_native_fixed_role_issue_cli(
    *, executable_fd: int, staged_generation_root_fd: int,
    executable_path: str | None = None,
    inputs: tuple[FixedRoleMaterializedInput, ...], timeout_seconds: int = 1800,
) -> tuple[FixedRoleRecord, ...]:
    """Invoke only the retained signed ``sign-fixed-roles-v1`` command.

    The executable is reached through its inherited descriptor.  The child
    receives exactly the root plus seven four-descriptor tuples; policy facts,
    roles, hashes and output names are compiled into the child.
    """

    _validate_materialized_inputs(inputs)
    if (
        type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600
        or type(executable_fd) is not int or executable_fd < 3
        or type(staged_generation_root_fd) is not int
        or staged_generation_root_fd < 3
    ):
        _fail("native fixed-role command arguments differ")
    flags, descriptor_flags = _fd_flags(executable_fd)
    executable_info = os.fstat(executable_fd)
    if (
        flags & os.O_ACCMODE != os.O_RDONLY
        or not descriptor_flags & fcntl.FD_CLOEXEC
        or not stat.S_ISREG(executable_info.st_mode)
        or executable_info.st_uid not in {0, os.geteuid()}
        or executable_info.st_nlink < 1
        or stat.S_IMODE(executable_info.st_mode) & 0o022
        or not stat.S_IMODE(executable_info.st_mode) & 0o100
    ):
        _fail("native fixed-role executable authority differs")
    executable_before: os.stat_result | None = None
    if sys.platform == "darwin":
        if (
            type(executable_path) is not str
            or not executable_path.startswith("/")
            or os.path.realpath(executable_path) != executable_path
        ):
            _fail("native fixed-role Darwin executable path is not canonical")
        try:
            executable_before = os.stat(executable_path, follow_symlinks=False)
        except OSError:
            _fail("native fixed-role Darwin executable path is unavailable")
        if (
            not stat.S_ISREG(executable_before.st_mode)
            or (executable_before.st_dev, executable_before.st_ino)
            != (executable_info.st_dev, executable_info.st_ino)
        ):
            _fail("native fixed-role Darwin executable rejoin differs")
        executable_argv = executable_path
    else:
        if executable_path is not None:
            _fail("native fixed-role executable path is Darwin-only")
        executable_argv = f"/dev/fd/{executable_fd}"
    descriptors = [staged_generation_root_fd]
    descriptors.extend(
        descriptor
        for row in inputs
        for descriptor in (
            row.payload_fd, row.semantic_receipt_fd,
            row.source_manifest_fd, row.reviewed_policy_fd,
        )
    )
    descriptors.append(executable_fd)
    if len(descriptors) != 30 or len(set(descriptors)) != len(descriptors):
        _fail("native fixed-role command descriptor roster differs")
    argv = [
        executable_argv, "sign-fixed-roles-v1",
        *(str(descriptor) for descriptor in descriptors[:-1]),
    ]
    try:
        completed = subprocess.run(
            argv, check=False, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=_CLOSED_ENV, close_fds=True, pass_fds=tuple(descriptors),
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("native fixed-role command failed")
    if completed.returncode != 0 or completed.stdout:
        _fail("native fixed-role command denied acquisition")
    if executable_before is not None:
        try:
            executable_after = os.stat(executable_argv, follow_symlinks=False)
        except OSError:
            _fail("native fixed-role Darwin executable path disappeared")
        if (
            executable_after.st_dev, executable_after.st_ino,
            executable_after.st_mode, executable_after.st_uid,
            executable_after.st_gid, executable_after.st_nlink,
            executable_after.st_size, executable_after.st_mtime_ns,
            executable_after.st_ctime_ns,
        ) != (
            executable_before.st_dev, executable_before.st_ino,
            executable_before.st_mode, executable_before.st_uid,
            executable_before.st_gid, executable_before.st_nlink,
            executable_before.st_size, executable_before.st_mtime_ns,
            executable_before.st_ctime_ns,
        ):
            _fail("native fixed-role Darwin executable changed during issue")

    authority_fd = -1
    opened: list[int] = []
    try:
        authority_fd = _open_relative_directory(
            staged_generation_root_fd,
            ("share", "plamen", "native-source-authority-v1"),
        )
        rows: list[FixedRoleRecord] = []
        for row in inputs:
            prefix = f"{row.ordinal:02d}-{_ROLE_NAMES[row.ordinal]}"
            payload_fd = os.open(
                prefix + ".payload", os.O_RDONLY | _CLOEXEC | _NOFOLLOW,
                dir_fd=authority_fd,
            )
            opened.append(payload_fd)
            producer_fd = os.open(
                prefix + ".producer-receipt",
                os.O_RDONLY | _CLOEXEC | _NOFOLLOW, dir_fd=authority_fd,
            )
            opened.append(producer_fd)
            manifest_fd = os.open(
                prefix + ".source-manifest",
                os.O_RDONLY | _CLOEXEC | _NOFOLLOW, dir_fd=authority_fd,
            )
            opened.append(manifest_fd)
            for descriptor in (payload_fd, producer_fd, manifest_fd):
                _identity(
                    descriptor, access=os.O_RDONLY, links=1, empty=False,
                )
                if stat.S_IMODE(os.fstat(descriptor).st_mode) != 0o400:
                    _fail("native fixed-role published mode differs")
            producer_size = os.fstat(producer_fd).st_size
            if producer_size <= 512:
                _fail("native fixed-role producer receipt is truncated")
            footer = os.pread(producer_fd, 512, producer_size - 512)
            policy_sha256 = _sha256_fd(row.reviewed_policy_fd)
            if (
                len(footer) != 512 or footer[:8] != b"PLMOP4R1"
                or int.from_bytes(footer[12:14], "big") != row.ordinal
                or footer[44:76].hex() != policy_sha256
                or hashlib.sha256(footer[:480]).digest() != footer[480:]
            ):
                _fail("native fixed-role producer footer differs")
            rows.append(FixedRoleRecord(
                ordinal=row.ordinal, policy_sha256=policy_sha256,
                payload_fd=payload_fd, producer_receipt_fd=producer_fd,
                source_manifest_fd=manifest_fd,
            ))
        opened.clear()
        return tuple(rows)
    except (OSError, NativeFixedRoleAcquisitionError):
        _close_many(opened)
        _fail("native fixed-role publication replay failed")
    finally:
        if authority_fd >= 0:
            os.close(authority_fd)


class RetainedPrivateStoreFactory:
    """Descriptor-relative allocator for setup-only private stores."""

    __slots__ = ("_root_fd", "_lock", "_used")

    def __init__(self, root_fd: int) -> None:
        flags, descriptor_flags = _fd_flags(root_fd)
        try:
            info = os.fstat(root_fd)
        except OSError:
            _fail("private-store root is unavailable")
        if (
            flags & os.O_ACCMODE != os.O_RDONLY
            or not descriptor_flags & fcntl.FD_CLOEXEC
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            _fail("private-store root authority differs")
        self._root_fd = root_fd
        self._lock = threading.Lock()
        self._used: set[str] = set()

    def pair(self, label: str, *, linked: bool) -> tuple[int, int]:
        if (
            type(label) is not str
            or _LABEL.fullmatch(label) is None
            or type(linked) is not bool
        ):
            _fail("private-store label differs")
        writer = reader = -1
        with self._lock:
            if label in self._used:
                _fail("private-store label is duplicated")
            self._used.add(label)
            try:
                writer = os.open(
                    label,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW,
                    0o600,
                    dir_fd=self._root_fd,
                )
                reader = os.open(
                    label, os.O_RDONLY | _CLOEXEC | _NOFOLLOW,
                    dir_fd=self._root_fd,
                )
                if not linked:
                    os.unlink(label, dir_fd=self._root_fd)
                    os.fsync(self._root_fd)
                expected_links = 1 if linked else 0
                writer_identity = _identity(
                    writer, access=os.O_RDWR, links=expected_links, empty=True,
                )
                reader_identity = _identity(
                    reader, access=os.O_RDONLY, links=expected_links, empty=True,
                )
                if writer_identity != reader_identity:
                    _fail("private-store descriptor pair differs")
                return writer, reader
            except BaseException:
                _close_many([reader, writer])
                if linked:
                    try:
                        os.unlink(label, dir_fd=self._root_fd)
                        os.fsync(self._root_fd)
                    except OSError:
                        pass
                raise

    def unlink_linked(self, label: str) -> None:
        if type(label) is not str or _LABEL.fullmatch(label) is None:
            _fail("private-store label differs")
        with self._lock:
            try:
                os.unlink(label, dir_fd=self._root_fd)
                os.fsync(self._root_fd)
            except FileNotFoundError:
                return
            except OSError:
                _fail("linked private-store cleanup failed")


@dataclass(frozen=True, slots=True)
class FixedRoleSetupTransfer:
    """Complete one-shot source-bootstrap descriptor transfer."""

    fixed_roles: tuple[FixedRoleRecord, ...]
    verifier_key_pair: tuple[int, int]
    grouped_pair: tuple[int, int]
    terminal_pair: tuple[int, int]
    output_pairs: tuple[tuple[int, int], ...]
    scratch_fds: tuple[int, ...]
    coordinator_receipt_pair: tuple[int, int]

    def descriptors(self) -> tuple[int, ...]:
        return (
            *(fd for row in self.fixed_roles for fd in (
                row.payload_fd, row.producer_receipt_fd,
                row.source_manifest_fd,
            )),
            *self.verifier_key_pair,
            *self.grouped_pair,
            *self.terminal_pair,
            *(fd for pair in self.output_pairs for fd in pair),
            *self.scratch_fds,
            *self.coordinator_receipt_pair,
        )


class FixedRoleAcquisitionAuthority:
    """Opaque, idempotently disposable, atomically single-consume custody."""

    __slots__ = ("_lock", "_transfer", "_consumed", "_closed", "_cleanup")
    _PLAMEN_FIXED_ROLE_ACQUISITION_V1 = True

    def __init__(
        self, transfer: FixedRoleSetupTransfer, cleanup: Callable[[], None],
    ) -> None:
        self._lock = threading.Lock()
        self._transfer: FixedRoleSetupTransfer | None = transfer
        self._consumed = False
        self._closed = False
        self._cleanup: Callable[[], None] | None = cleanup

    def consume(self) -> FixedRoleSetupTransfer:
        with self._lock:
            if self._closed or self._consumed or self._transfer is None:
                _fail("fixed-role acquisition authority is already consumed")
            value = self._transfer
            self._transfer = None
            self._consumed = True
            self._cleanup = None
            return value

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            transfer = self._transfer
            self._transfer = None
            cleanup = self._cleanup
            self._cleanup = None
        if transfer is not None:
            _close_many(list(transfer.descriptors()))
        if cleanup is not None:
            cleanup()


def _validate_materialized_inputs(
    value: tuple[FixedRoleMaterializedInput, ...],
) -> None:
    if type(value) is not tuple or len(value) != len(FIXED_ROLE_ORDINALS):
        _fail("fixed-role materialized input roster differs")
    identities: set[tuple[int, int]] = set()
    for expected, row in zip(FIXED_ROLE_ORDINALS, value, strict=True):
        if type(row) is not FixedRoleMaterializedInput or row.ordinal != expected:
            _fail("fixed-role materialized input ordinal differs")
        for descriptor in (
            row.payload_fd, row.semantic_receipt_fd,
            row.source_manifest_fd, row.reviewed_policy_fd,
        ):
            identity = _identity(
                descriptor, access=os.O_RDONLY, links=1, empty=False,
            )
            if identity in identities:
                _fail("fixed-role materialized inputs alias")
            identities.add(identity)


def _validate_fixed_records(value: object) -> tuple[FixedRoleRecord, ...]:
    if type(value) is not tuple or len(value) != len(FIXED_ROLE_ORDINALS):
        _fail("native fixed-role projection roster differs")
    identities: set[tuple[int, int]] = set()
    rows: list[FixedRoleRecord] = []
    observed_descriptors: list[int] = []
    try:
        for expected, row in zip(FIXED_ROLE_ORDINALS, value, strict=True):
            if (
                type(row) is not FixedRoleRecord
                or row.ordinal != expected
                or _HEX64.fullmatch(row.policy_sha256) is None
                or row.policy_sha256 == "0" * 64
            ):
                _fail("native fixed-role projection row differs")
            for descriptor in (
                row.payload_fd, row.producer_receipt_fd,
                row.source_manifest_fd,
            ):
                observed_descriptors.append(descriptor)
                identity = _identity(
                    descriptor, access=os.O_RDONLY, links=1, empty=False,
                )
                if identity in identities:
                    _fail("native fixed-role projection aliases")
                identities.add(identity)
            rows.append(row)
        return tuple(rows)
    except BaseException:
        _close_many(observed_descriptors)
        raise


def acquire_production_fixed_role_materialized_inputs(
    *, source_authority: RetainedFixedRoleSourceAuthority,
    private_store: RetainedPrivateStoreFactory,
    fetcher: SetupHTTPSFetcher | None = None,
) -> ProductionFixedRoleMaterializationAuthority:
    """Materialize the seven fixed operation-4 roles during setup only.

    Repository members and frozen projections enter only through the retained
    source authority.  Network transport is limited to exact reviewed objects;
    every downloaded and derived byte is re-hashed before the native producer
    sees it.  The returned authority owns all 28 descriptors and linked private
    leaves until ``close()``.
    """

    if (
        getattr(source_authority, "_PLAMEN_RETAINED_FIXED_ROLE_SOURCE_V1", None)
        is not True
        or not callable(getattr(source_authority, "duplicate_member", None))
        or not callable(
            getattr(source_authority, "duplicate_projection_manifest", None)
        )
        or not callable(
            getattr(source_authority, "duplicate_projection_member", None)
        )
        or type(private_store) is not RetainedPrivateStoreFactory
    ):
        _fail("production fixed-role source authority differs")
    transport: SetupHTTPSFetcher = (
        DefaultSetupHTTPSFetcher() if fetcher is None else fetcher
    )
    if (
        getattr(transport, "_PLAMEN_SETUP_HTTPS_FETCHER_V1", None) is not True
        or not callable(getattr(transport, "fetch_exact", None))
        or not callable(getattr(transport, "anonymous_bearer_token", None))
    ):
        _fail("production fixed-role setup transport differs")

    owned: list[int] = []
    linked_labels: list[str] = []
    policies: dict[int, int] = {}
    manifests: dict[int, int] = {}
    semantics: dict[int, int] = {}
    payloads: dict[int, int] = {}
    upstream: list[int] = []

    def output_pair(label: str) -> tuple[int, int]:
        writer, reader = _new_linked_output(private_store, label)
        linked_labels.append(label)
        owned.extend((writer, reader))
        return writer, reader

    def seal_output(
        label: str, writer: int, reader: int, identity: tuple[int, str] | None,
    ) -> int:
        size = os.fstat(reader).st_size
        digest = _sha256_fd(reader)
        if identity is not None and (size, digest) != identity:
            _fail(f"{label} golden identity differs")
        result = _seal_materialized_pair(
            writer, reader, size=size, sha256=digest,
        )
        owned.remove(writer)
        return result

    try:
        runtime_policy = _load_retained_runtime_policy_module(source_authority)
        elf_closure = _load_retained_elf_closure_module(source_authority)
        for ordinal in FIXED_ROLE_ORDINALS:
            policy_role, manifest_role = _MATERIAL_SOURCE_ROLES[ordinal]
            policy_fd = _duplicate_source_member(
                source_authority, policy_role, expected=_POLICY_IDENTITY[ordinal],
            )
            policies[ordinal] = policy_fd
            owned.append(policy_fd)
            if manifest_role is not None:
                manifest_fd = _duplicate_source_member(
                    source_authority, manifest_role,
                    expected=_MANIFEST_IDENTITY[ordinal],
                )
                manifests[ordinal] = manifest_fd
                owned.append(manifest_fd)
        for ordinal, source_role in _SEMANTIC_SOURCE_ROLES.items():
            semantic_fd = _duplicate_source_member(
                source_authority, source_role,
                expected=_SEMANTIC_IDENTITY[ordinal],
            )
            semantics[ordinal] = semantic_fd
            owned.append(semantic_fd)

        token = transport.anonymous_bearer_token(
            endpoint="https://auth.docker.io/token",
            audience="registry.docker.io",
            scope="repository:library/debian:pull",
        )
        authorization = "Bearer " + token
        rootfs_source = _temporary_download(
            private_store, transport, "upstream-role-0",
            "https://registry-1.docker.io/v2/library/debian/blobs/sha256:"
            + _UPSTREAM_ROOTFS_IDENTITY[1],
            _UPSTREAM_ROOTFS_IDENTITY,
            hosts=("registry-1.docker.io", "production.cloudfront.docker.com"),
            redirects=1,
            redirect_targets=((
                "production.cloudfront.docker.com",
                "/registry-v2/docker/registry/v2/blobs/sha256/75/"
                + _UPSTREAM_ROOTFS_IDENTITY[1] + "/data",
            ),),
            authorization=authorization,
        )
        upstream.append(rootfs_source)

        # Role 1 is a projection of the authenticated original layer.  Role 0
        # is the independently golden-bound cache-free derivation of that same
        # retained descriptor; it must not inherit the host loader cache.
        package_raw = _render_debian_package_state(rootfs_source)
        base_writer, base_reader = output_pair("materialized-role-0-payload")
        try:
            derivation = elf_closure.derive_cache_free_rootfs(
                rootfs_source, base_writer,
                authenticated_provenance=elf_closure.pinned_provenance_bytes(),
            )
        except BaseException:
            _fail("cache-free base-rootfs derivation failed")
        if (
            getattr(derivation, "source_sha256", None),
            getattr(derivation, "source_size", None),
            getattr(derivation, "derived_sha256", None),
            getattr(derivation, "derived_size", None),
            getattr(derivation, "manifest_sha256", None),
        ) != (
            _UPSTREAM_ROOTFS_IDENTITY[1], _UPSTREAM_ROOTFS_IDENTITY[0],
            _FINAL_IDENTITY[0][1], _FINAL_IDENTITY[0][0],
            "0960d7dd99bbd7acc6027579118eb1f8402400f888c35df095cebd949811edf3",
        ):
            _fail("cache-free base-rootfs derivation identity differs")
        payloads[0] = seal_output(
            "base_rootfs payload", base_writer, base_reader, _FINAL_IDENTITY[0],
        )

        package_writer, package_reader = output_pair("materialized-role-1-payload")
        _write_all(package_writer, package_raw)
        payloads[1] = seal_output(
            "debian_package_state payload", package_writer, package_reader,
            _FINAL_IDENTITY[1],
        )
        runtime_policy.validate_debian_package_state_payload(package_raw)

        for ordinal in (2, 4):
            role = _ROLE_NAMES[ordinal]
            writer, reader = output_pair(f"materialized-role-{ordinal}-payload")
            evidence = _projection_payload(
                source_authority, role, writer,
            )
            payloads[ordinal] = seal_output(
                f"{role} payload", writer, reader, None,
            )
            payload_size = os.fstat(reader).st_size
            payload_sha256 = _sha256_fd(reader)
            policy_raw = _read_fd_exact(
                policies[ordinal], _MAX_SOURCE_MEMBER, f"{role} policy",
            )
            source_manifest = runtime_policy.render_source_manifest_candidate(
                policy_raw, payload_sha256=payload_sha256,
                payload_size=payload_size,
                source_reference=(
                    "git+https://github.com/PlamenTSV/plamen.git@"
                    + evidence["source_commit"]
                ),
                version=evidence["source_commit"],
            )
            manifest_writer, manifest_reader = output_pair(
                f"materialized-role-{ordinal}-manifest",
            )
            _write_all(manifest_writer, source_manifest)
            manifests[ordinal] = seal_output(
                f"{role} source manifest", manifest_writer, manifest_reader, None,
            )
            semantic = runtime_policy.render_frozen_plamen_semantic_receipt(
                policy_raw, payload_sha256=payload_sha256,
                payload_size=payload_size,
                source_manifest_raw=source_manifest,
                projection_authority_schema=evidence[
                    "projection_authority_schema"
                ],
                projection_authority_sha256=evidence[
                    "projection_authority_sha256"
                ],
                projection_authority_size=evidence[
                    "projection_authority_size"
                ],
                projection_roster_sha256=evidence[
                    "projection_roster_sha256"
                ],
                source_commit=evidence["source_commit"],
            )
            semantic_writer, semantic_reader = output_pair(
                f"materialized-role-{ordinal}-semantic",
            )
            _write_all(semantic_writer, semantic)
            semantics[ordinal] = seal_output(
                f"{role} semantic receipt", semantic_writer, semantic_reader, None,
            )

        for ordinal in (3, 7):
            role = _ROLE_NAMES[ordinal]
            downloaded = _temporary_download(
                private_store, transport, f"upstream-role-{ordinal}",
                _UPSTREAM_URLS[ordinal], _UPSTREAM_IDENTITY[ordinal],
                hosts=(
                    "github.com", "objects.githubusercontent.com",
                    "release-assets.githubusercontent.com",
                ), redirects=5,
            )
            upstream.append(downloaded)
            writer, reader = output_pair(f"materialized-role-{ordinal}-payload")
            _canonical_ustar(downloaded, writer, role=ordinal)
            payloads[ordinal] = seal_output(
                f"{role} payload", writer, reader, _FINAL_IDENTITY[ordinal],
            )

        amd64_layer = _temporary_download(
            private_store, transport, "upstream-role-10",
            "https://registry-1.docker.io/v2/library/debian/blobs/sha256:"
            "a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71",
            (28_232_655,
             "a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71"),
            hosts=("registry-1.docker.io", "production.cloudfront.docker.com"),
            redirects=1,
            redirect_targets=((
                "production.cloudfront.docker.com",
                "/registry-v2/docker/registry/v2/blobs/sha256/a8/"
                "a8ac7f6c67abc236e4c745052c404112b8fab6fe8ac3a329d1ef3b867ad67c71/data",
            ),),
            authorization=authorization,
        )
        upstream.append(amd64_layer)
        selected = {
            "lib": ("lib", "symlink"),
            "lib64": ("lib64", "symlink"),
            "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": (
                "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "file",
            ),
            "usr/lib/x86_64-linux-gnu/libc.so.6": (
                "usr/lib/x86_64-linux-gnu/libc.so.6", "file",
            ),
            "usr/lib/x86_64-linux-gnu/libdl.so.2": (
                "usr/lib/x86_64-linux-gnu/libdl.so.2", "file",
            ),
            "usr/lib/x86_64-linux-gnu/libm.so.6": (
                "usr/lib/x86_64-linux-gnu/libm.so.6", "file",
            ),
            "usr/lib/x86_64-linux-gnu/libpthread.so.0": (
                "usr/lib/x86_64-linux-gnu/libpthread.so.0", "file",
            ),
            "usr/lib/x86_64-linux-gnu/librt.so.1": (
                "usr/lib/x86_64-linux-gnu/librt.so.1", "file",
            ),
            "usr/lib64/ld-linux-x86-64.so.2": (
                "usr/lib64/ld-linux-x86-64.so.2", "symlink",
            ),
        }
        amd64_writer, amd64_reader = output_pair("materialized-role-10-payload")
        _canonical_ustar(
            amd64_layer, amd64_writer, role=10, selected=selected,
        )
        payloads[10] = seal_output(
            "amd64_compat payload", amd64_writer, amd64_reader,
            _FINAL_IDENTITY[10],
        )

        for ordinal in (0, 1, 3):
            role = _ROLE_NAMES[ordinal]
            policy_raw = _read_fd_exact(
                policies[ordinal], _MAX_SOURCE_MEMBER, f"{role} policy",
            )
            manifest_raw = _read_fd_exact(
                manifests[ordinal], _MAX_SOURCE_MEMBER,
                f"{role} source manifest",
            )
            semantic = runtime_policy.render_static_semantic_receipt(
                policy_raw, source_manifest_raw=manifest_raw,
            )
            if (
                len(semantic), hashlib.sha256(semantic).hexdigest()
            ) != _RUNTIME_STATIC_RECEIPT_IDENTITY[ordinal]:
                _fail(f"{role} semantic receipt golden identity differs")
            writer, reader = output_pair(f"materialized-role-{ordinal}-semantic")
            _write_all(writer, semantic)
            semantics[ordinal] = seal_output(
                f"{role} semantic receipt", writer, reader,
                _RUNTIME_STATIC_RECEIPT_IDENTITY[ordinal],
            )

        inputs = tuple(
            FixedRoleMaterializedInput(
                ordinal, payloads[ordinal], semantics[ordinal],
                manifests[ordinal], policies[ordinal],
            )
            for ordinal in FIXED_ROLE_ORDINALS
        )
        _validate_materialized_inputs(inputs)
        _close_many(upstream)
        upstream.clear()
        owned.clear()

        def cleanup() -> None:
            failures = []
            for label in reversed(linked_labels):
                try:
                    private_store.unlink_linked(label)
                except NativeFixedRoleAcquisitionError as exc:
                    failures.append(exc)
            if failures:
                raise failures[0]

        return ProductionFixedRoleMaterializationAuthority(inputs, cleanup)
    except BaseException:
        _close_many(upstream)
        _close_many(owned)
        for label in reversed(linked_labels):
            try:
                private_store.unlink_linked(label)
            except NativeFixedRoleAcquisitionError:
                pass
        raise


def acquire_fixed_role_inputs(
    *, staged_generation_root_fd: int,
    materialized_inputs: tuple[FixedRoleMaterializedInput, ...],
    native_issue: NativeFixedRoleIssuer,
    private_store: RetainedPrivateStoreFactory,
) -> FixedRoleAcquisitionAuthority:
    """Acquire fixed roles plus every empty store required by argc80 issue-v1.

    The returned authority is process-local and single-use.  Output, grouped,
    and terminal pairs are already unlinked.  The coordinator receipt and
    empty verifier-key pairs remain linked for deterministic stage publication;
    only native ``sign-backends-v1`` may populate the verifier key.
    """

    if (
        type(staged_generation_root_fd) is not int
        or staged_generation_root_fd < 3
        or not callable(native_issue)
        or type(private_store) is not RetainedPrivateStoreFactory
    ):
        _fail("fixed-role acquisition arguments differ")
    _validate_materialized_inputs(materialized_inputs)
    owned: list[int] = []
    try:
        verifier = private_store.pair("producer-verifier-key", linked=True)
        owned.extend(verifier)
        grouped = private_store.pair("operation4-group", linked=False)
        owned.extend(grouped)
        terminal = private_store.pair("operation4-terminal", linked=False)
        owned.extend(terminal)
        outputs_list: list[tuple[int, int]] = []
        for index in range(OUTPUT_COUNT):
            pair = private_store.pair(f"operation4-output-{index}", linked=False)
            outputs_list.append(pair)
            owned.extend(pair)
        scratch_list: list[int] = []
        for index in range(SCRATCH_COUNT):
            writer, reader = private_store.pair(
                f"operation4-scratch-{index}", linked=False,
            )
            os.close(reader)
            scratch_list.append(writer)
            owned.append(writer)
        receipt = private_store.pair("coordinator-receipt", linked=True)
        owned.extend(receipt)
        fixed = _validate_fixed_records(
            native_issue(staged_generation_root_fd, materialized_inputs)
        )
        owned.extend(
            descriptor
            for row in fixed
            for descriptor in (
                row.payload_fd, row.producer_receipt_fd,
                row.source_manifest_fd,
            )
        )
        transfer = FixedRoleSetupTransfer(
            fixed_roles=fixed,
            verifier_key_pair=verifier,
            grouped_pair=grouped,
            terminal_pair=terminal,
            output_pairs=tuple(outputs_list),
            scratch_fds=tuple(scratch_list),
            coordinator_receipt_pair=receipt,
        )
        descriptors = transfer.descriptors()
        if len(descriptors) != 63 or len(set(descriptors)) != len(descriptors):
            _fail("fixed-role setup descriptor roster differs")
        owned.clear()
        return FixedRoleAcquisitionAuthority(
            transfer,
            lambda: (
                private_store.unlink_linked("producer-verifier-key"),
                private_store.unlink_linked("coordinator-receipt"),
            ),
        )
    except BaseException:
        _close_many(owned)
        for label in ("producer-verifier-key", "coordinator-receipt"):
            try:
                private_store.unlink_linked(label)
            except NativeFixedRoleAcquisitionError:
                pass
        raise


__all__ = (
    "DefaultSetupHTTPSFetcher",
    "FIXED_ROLE_ORDINALS",
    "FixedRoleAcquisitionAuthority",
    "FixedRoleMaterializedInput",
    "FixedRoleRecord",
    "FixedRoleSetupTransfer",
    "NativeFixedRoleAcquisitionError",
    "ProductionFixedRoleMaterializationAuthority",
    "RetainedPrivateStoreFactory",
    "acquire_fixed_role_inputs",
    "acquire_production_fixed_role_materialized_inputs",
    "run_native_fixed_role_issue_cli",
)
