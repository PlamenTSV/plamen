#!/usr/bin/env python3
"""Descriptor-retained setup producer for latest Linux-arm64 AI backends.

This module is the only production boundary which turns the reviewed word
``latest`` into exact Codex and Claude archive bytes.  It does not install the
archives and it never resolves at audit time.  Its result is an opaque,
process-local authority matching the native operation-4 signer seam.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import stat
import tarfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, NoReturn, Protocol
from urllib.parse import urlsplit

try:
    import fcntl
except ImportError as exc:  # pragma: no cover - POSIX production module
    raise RuntimeError("native backend acquisition requires POSIX fcntl") from exc

try:
    from . import backend_acquisition as receipt_authority
except ImportError:  # pragma: no cover - direct script import
    import backend_acquisition as receipt_authority  # type: ignore[no-redef]


PLATFORM = "linux-arm64"
_POLICY_MEMBER = "native_backend_latest_acquisition_policy"
_MAX_POLICY = 1024 * 1024
_MAX_METADATA = 8 * 1024 * 1024
_MAX_LATEST = 256
_MAX_MANIFEST = 8 * 1024 * 1024
_MAX_ARCHIVE = 1024 * 1024 * 1024
_MAX_ARCHIVE_MEMBERS = 32768
_MAX_PROBE_STDOUT = 8 * 1024 * 1024
_MAX_PROBE_STDERR = 2 * 1024 * 1024
_READ_CHUNK = 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TRANSACTION = re.compile(r"[A-Za-z0-9._-]{1,200}")
_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}")


class NativeBackendAcquisitionError(RuntimeError):
    """Latest-backend setup failed closed before native signing."""


def _fail(message: str) -> NoReturn:
    raise NativeBackendAcquisitionError(message) from None


class RetainedBackendSourceAuthority(Protocol):
    _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1: bool

    def duplicate_member(self, role: str) -> int: ...


class BackendPrivateStore(Protocol):
    def pair(self, label: str, *, linked: bool) -> tuple[int, int]: ...

    def unlink_linked(self, label: str) -> None: ...


class LinuxArm64ProbeAuthority(Protocol):
    _PLAMEN_LINUX_ARM64_BACKEND_PROBE_AUTHORITY_V1: bool

    def run(
        self, *, selector: str, executable_fd: int,
        executable_sha256: str, executable_size: int,
        resolved_version: str, argv: tuple[str, ...],
    ) -> Mapping[str, Any]: ...


class BackendSetupTransport(Protocol):
    _PLAMEN_BACKEND_SETUP_TRANSPORT_V1: bool

    def fetch_json(self, url: str) -> Mapping[str, Any]: ...

    def fetch_bytes(self, url: str) -> bytes: ...

    def download(self, url: str, *, writer_fd: int) -> None: ...

    def endpoints(self) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class _Identity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str


def _sha256_fd(descriptor: int, size: int | None = None) -> str:
    try:
        expected = os.fstat(descriptor).st_size if size is None else size
    except OSError:
        _fail("backend descriptor is unavailable")
    digest = hashlib.sha256()
    offset = 0
    while offset < expected:
        try:
            block = os.pread(
                descriptor, min(_READ_CHUNK, expected - offset), offset,
            )
        except OSError:
            _fail("backend descriptor read failed")
        if not block:
            _fail("backend descriptor changed during hashing")
        digest.update(block)
        offset += len(block)
    if os.fstat(descriptor).st_size != expected:
        _fail("backend descriptor changed during hashing")
    return digest.hexdigest()


def _identity(
    descriptor: int, *, access: int = os.O_RDONLY,
    links: int = 1, nonempty: bool = True,
) -> _Identity:
    if type(descriptor) is not int or descriptor < 3:
        _fail("backend descriptor differs")
    try:
        flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
        info = os.fstat(descriptor)
    except OSError:
        _fail("backend descriptor is unavailable")
    if (
        flags & os.O_ACCMODE != access
        or not descriptor_flags & fcntl.FD_CLOEXEC
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != links
        or stat.S_IMODE(info.st_mode) & 0o022
        or info.st_size < 0
        or (nonempty and info.st_size == 0)
    ):
        _fail("backend descriptor identity differs")
    return _Identity(
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
        _sha256_fd(descriptor, info.st_size),
    )


def _same_identity(descriptor: int, expected: _Identity) -> None:
    observed = _identity(descriptor, links=expected.links)
    if observed != expected:
        _fail("backend retained descriptor changed")


def _read_fd(descriptor: int, maximum: int, label: str) -> bytes:
    before = _identity(descriptor)
    if before.size > maximum:
        _fail(label + " is oversized")
    result = bytearray()
    while len(result) < before.size:
        block = os.pread(
            descriptor,
            min(_READ_CHUNK, before.size - len(result)),
            len(result),
        )
        if not block:
            _fail(label + " changed during read")
        result.extend(block)
    _same_identity(descriptor, before)
    return bytes(result)


def _write_all(descriptor: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        try:
            amount = os.write(descriptor, view)
        except OSError:
            _fail("backend private-store write failed")
        if amount <= 0:
            _fail("backend private-store write failed")
        view = view[amount:]


def _seal_pair(
    writer: int, reader: int, *, links: int, mode: int,
) -> tuple[int, _Identity]:
    try:
        os.fsync(writer)
        os.fchmod(writer, mode)
        os.fsync(writer)
        os.close(writer)
        writer = -1
        identity = _identity(reader, links=links)
        if stat.S_IMODE(identity.mode) != mode:
            _fail("backend sealed descriptor mode differs")
        return reader, identity
    finally:
        if writer >= 0:
            try:
                os.close(writer)
            except OSError:
                pass


def _close_many(descriptors: list[int] | tuple[int, ...]) -> None:
    for descriptor in reversed(descriptors):
        if type(descriptor) is int and descriptor >= 3:
            try:
                os.close(descriptor)
            except OSError:
                pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class DefaultBackendSetupTransport:
    """Proxy-free TLS transport with an exact host/path and no redirects."""

    __slots__ = ("_opener", "_seen", "_lock")
    _PLAMEN_BACKEND_SETUP_TRANSPORT_V1 = True

    def __init__(self) -> None:
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )
        self._seen: list[str] = []
        self._lock = threading.Lock()

    @staticmethod
    def _admit_url(url: str) -> None:
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except (TypeError, ValueError):
            _fail("backend setup URL is malformed")
        if (
            type(url) is not str or len(url) > 8192
            or parsed.scheme != "https" or parsed.username is not None
            or parsed.password is not None or port is not None
            or parsed.query or parsed.fragment
            or parsed.hostname not in {"registry.npmjs.org", "downloads.claude.ai"}
            or not parsed.path.startswith("/")
            or "\\" in parsed.path or "/../" in parsed.path
        ):
            _fail("backend setup URL authority differs")
        if parsed.hostname == "downloads.claude.ai" and not parsed.path.startswith(
            "/claude-code-releases/"
        ):
            _fail("backend setup URL path differs")

    def _claim(self, url: str) -> None:
        self._admit_url(url)
        with self._lock:
            if url in self._seen:
                _fail("backend setup endpoint was fetched more than once")
            self._seen.append(url)

    def _open(self, url: str):
        self._claim(url)
        request = urllib.request.Request(
            url, headers={
                "Accept-Encoding": "identity",
                "User-Agent": "plamen-native-backend-acquisition/1",
            }, method="GET",
        )
        try:
            response = self._opener.open(request, timeout=120)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            raise NativeBackendAcquisitionError(
                "backend setup HTTPS request failed"
            ) from exc
        if (
            response.status != 200 or response.geturl() != url
            or response.headers.get("Content-Encoding", "identity").lower()
            not in {"", "identity"}
        ):
            response.close()
            _fail("backend setup HTTPS response differs")
        return response

    def _fetch(self, url: str, maximum: int) -> bytes:
        response = self._open(url)
        try:
            stated = response.headers.get("Content-Length")
            if stated is not None and (
                not stated.isdigit() or int(stated) > maximum
            ):
                _fail("backend setup response length differs")
            raw = response.read(maximum + 1)
        finally:
            response.close()
        if not raw or len(raw) > maximum:
            _fail("backend setup response size differs")
        return raw

    def fetch_json(self, url: str) -> Mapping[str, Any]:
        raw = self._fetch(url, _MAX_METADATA)
        def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    _fail("backend metadata has a duplicate object key")
                value[key] = item
            return value
        try:
            value = json.loads(
                raw.decode("utf-8"), parse_constant=lambda _value: _fail(
                    "backend metadata has a non-finite number"
                ),
                object_pairs_hook=exact_object,
            )
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise NativeBackendAcquisitionError(
                "backend metadata is malformed"
            ) from exc
        if type(value) is not dict:
            _fail("backend metadata root differs")
        return value

    def fetch_bytes(self, url: str) -> bytes:
        maximum = _MAX_LATEST if url.endswith("/latest") else _MAX_MANIFEST
        return self._fetch(url, maximum)

    def download(self, url: str, *, writer_fd: int) -> None:
        if _identity(writer_fd, access=os.O_RDWR, links=1, nonempty=False).size != 0:
            _fail("backend payload writer is not empty")
        response = self._open(url)
        total = 0
        try:
            stated = response.headers.get("Content-Length")
            if stated is not None and (
                not stated.isdigit() or not 0 < int(stated) <= _MAX_ARCHIVE
            ):
                _fail("backend archive response length differs")
            while True:
                block = response.read(_READ_CHUNK)
                if not block:
                    break
                total += len(block)
                if total > _MAX_ARCHIVE:
                    _fail("backend archive is oversized")
                _write_all(writer_fd, block)
        finally:
            response.close()
        if total == 0 or (stated is not None and total != int(stated)):
            _fail("backend archive response was truncated")

    def endpoints(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._seen)


def _validate_transport(transport: BackendSetupTransport) -> None:
    if (
        getattr(transport, "_PLAMEN_BACKEND_SETUP_TRANSPORT_V1", None)
        is not True
        or not callable(getattr(transport, "fetch_json", None))
        or not callable(getattr(transport, "fetch_bytes", None))
        or not callable(getattr(transport, "download", None))
        or not callable(getattr(transport, "endpoints", None))
    ):
        _fail("backend setup transport authority differs")


def _policy_from_source(
    source_authority: RetainedBackendSourceAuthority,
) -> tuple[dict[str, Any], str]:
    if (
        getattr(
            source_authority, "_PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1", None,
        ) is not True
        or not callable(getattr(source_authority, "duplicate_member", None))
    ):
        _fail("retained backend source authority differs")
    descriptor = -1
    try:
        descriptor = source_authority.duplicate_member(_POLICY_MEMBER)
        raw = _read_fd(descriptor, _MAX_POLICY, "backend acquisition policy")
        return receipt_authority.load_policy_bytes(raw)
    except receipt_authority.BackendAcquisitionError as exc:
        raise NativeBackendAcquisitionError(str(exc)) from exc
    finally:
        if descriptor >= 3:
            os.close(descriptor)


def _canonical(value: Any) -> bytes:
    return receipt_authority.canonical_json(value)


def _archive_projection(
    *, selector: str, payload_fd: int, source_url: str,
    expected_integrity: str, expected_shasum: str,
    executable_writer: int, executable_reader: int,
) -> tuple[dict[str, Any], dict[str, Any], _Identity]:
    payload_identity = _identity(payload_fd)
    if payload_identity.size > _MAX_ARCHIVE:
        _fail("backend retained archive is oversized")
    sha512 = hashlib.sha512()
    sha1 = hashlib.sha1(usedforsecurity=False)
    offset = 0
    while offset < payload_identity.size:
        block = os.pread(
            payload_fd, min(_READ_CHUNK, payload_identity.size - offset), offset,
        )
        if not block:
            _fail("backend archive changed during authentication")
        sha512.update(block); sha1.update(block); offset += len(block)
    observed_sri = "sha512-" + base64.b64encode(sha512.digest()).decode("ascii")
    if observed_sri != expected_integrity or sha1.hexdigest() != expected_shasum:
        _fail("backend archive registry integrity differs")

    selected_pattern = re.compile(
        r"package/claude" if selector == "claude" else
        r"package/vendor/aarch64-unknown-linux-musl/bin/codex"
    )
    names: list[str] = []
    selected = None
    fileobj = os.fdopen(os.dup(payload_fd), "rb", closefd=True)
    try:
        with tarfile.open(fileobj=fileobj, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
                _fail("backend archive member count differs")
            seen: set[str] = set()
            for member in members:
                name = member.name
                parts = name.split("/")
                if (
                    not name or len(name.encode("utf-8")) > 4096
                    or name.startswith("/") or "\\" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or name in seen or member.issym() or member.islnk()
                    or member.isdev() or (member.mode & 0o7000)
                    or (not member.isfile() and not member.isdir())
                ):
                    _fail("backend archive has an unsafe member")
                seen.add(name); names.append(name)
                if member.isfile() and selected_pattern.fullmatch(name):
                    if selected is not None or not member.mode & 0o111:
                        _fail("backend archive executable member differs")
                    selected = member
            if selected is None:
                _fail("backend archive executable member is absent")
            extracted = archive.extractfile(selected)
            if extracted is None:
                _fail("backend archive executable cannot be read")
            executable_digest = hashlib.sha256()
            executable_size = 0
            while True:
                block = extracted.read(_READ_CHUNK)
                if not block:
                    break
                executable_size += len(block)
                if executable_size > _MAX_ARCHIVE:
                    _fail("backend executable is oversized")
                executable_digest.update(block)
                _write_all(executable_writer, block)
            if executable_size != selected.size or executable_size < 64:
                _fail("backend executable size differs")
    except (tarfile.TarError, OSError) as exc:
        raise NativeBackendAcquisitionError(
            "backend archive is not a valid tar.gz"
        ) from exc
    finally:
        fileobj.close()

    executable_reader, executable_identity = _seal_pair(
        executable_writer, executable_reader, links=0, mode=0o500,
    )
    head = os.pread(executable_reader, 64, 0)
    if (
        len(head) != 64 or head[:4] != b"\x7fELF"
        or head[4] != 2 or head[5] != 1
        or int.from_bytes(head[18:20], "little") != 183
    ):
        _fail("backend executable is not Linux AArch64 ELF64")
    roster = sorted(names, key=lambda item: item.encode("utf-8"))
    payload = {
        "source_url": source_url,
        "size": payload_identity.size,
        "sha256": payload_identity.sha256,
        "sha512_sri": observed_sri,
        "archive_format": "tar.gz",
        "member_count": len(roster),
        "member_roster_sha256": hashlib.sha256(_canonical(roster)).hexdigest(),
        "selected_member": selected.name,
        "path_traversal_rejected": True,
    }
    destination = (
        "/usr/local/lib/plamen/bin/codex" if selector == "codex"
        else "/usr/local/lib/plamen/bin/claude"
    )
    closure = [{
        "mode": 0o500, "path": destination,
        "sha256": executable_identity.sha256,
        "size": executable_identity.size,
    }]
    installed = {
        "platform": PLATFORM,
        "relative_path": (
            "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
            if selector == "claude" else
            "node_modules/@openai/codex-linux-arm64/"
            "vendor/aarch64-unknown-linux-musl/bin/codex"
        ),
        "executable_size": executable_identity.size,
        "executable_sha256": executable_identity.sha256,
        "closure_count": 1,
        "closure_bytes": executable_identity.size,
        "closure_sha256": hashlib.sha256(_canonical(closure)).hexdigest(),
        "code_signature": {
            "mode": "REGISTRY_SIGNATURE_ONLY", "identifier": None,
            "team_identifier": None, "cdhash_sha256": None,
        },
    }
    _same_identity(payload_fd, payload_identity)
    return payload, installed, executable_identity


def _run_probes(
    *, authority: LinuxArm64ProbeAuthority, selector: str,
    version: str, executable_fd: int, executable_identity: _Identity,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    if (
        getattr(
            authority, "_PLAMEN_LINUX_ARM64_BACKEND_PROBE_AUTHORITY_V1", None,
        ) is not True or not callable(getattr(authority, "run", None))
    ):
        _fail("Linux-arm64 backend probe authority differs")
    required = policy["backends"][selector]["cli_contract"][
        "help_required_flags" if selector == "claude"
        else "exec_help_required_flags"
    ]
    result: dict[str, Any] = {}
    for name, argv in (
        ("version", ("--version",)),
        ("help", ("--help",) if selector == "claude" else ("exec", "--help")),
    ):
        before = _identity(executable_fd, links=0)
        if before != executable_identity:
            _fail("backend probe executable changed")
        try:
            observed = authority.run(
                selector=selector, executable_fd=executable_fd,
                executable_sha256=before.sha256,
                executable_size=before.size, resolved_version=version,
                argv=argv,
            )
        except BaseException as exc:
            if isinstance(exc, NativeBackendAcquisitionError):
                raise
            raise NativeBackendAcquisitionError(
                "Linux-arm64 backend probe failed"
            ) from exc
        if (
            type(observed) is not dict
            or set(observed) != {"returncode", "stdout", "stderr"}
            or type(observed.get("returncode")) is not int
            or type(observed.get("stdout")) is not bytes
            or type(observed.get("stderr")) is not bytes
            or len(observed["stdout"]) > _MAX_PROBE_STDOUT
            or len(observed["stderr"]) > _MAX_PROBE_STDERR
        ):
            _fail("backend probe result differs")
        try:
            normalized = observed["stdout"].decode("utf-8", "strict").strip()
        except UnicodeError:
            _fail("backend probe output is not UTF-8")
        expected_version = (
            f"{version} (Claude Code)" if selector == "claude"
            else f"codex-cli {version}"
        )
        if observed["returncode"] != 0 or (
            name == "version" and normalized != expected_version
        ) or (
            name == "help" and any(
                re.search(
                    r"(?<![A-Za-z0-9_-])" + re.escape(flag)
                    + r"(?![A-Za-z0-9_-])",
                    normalized,
                ) is None
                for flag in required
            )
        ):
            _fail("backend CLI conformance probe differs")
        result[name] = {
            "argv": list(argv), "returncode": observed["returncode"],
            "stdout_sha256": hashlib.sha256(observed["stdout"]).hexdigest(),
            "stderr_sha256": hashlib.sha256(observed["stderr"]).hexdigest(),
            "normalized_output": normalized,
            "observed_contract": [] if name == "version" else list(required),
        }
        if _identity(executable_fd, links=0) != executable_identity:
            _fail("backend probe executable changed")
    return result


def _render_source_manifest(
    *, selector: str, version: str,
    payload: Mapping[str, Any], installed: Mapping[str, Any],
) -> bytes:
    destination = (
        "/usr/local/lib/plamen/bin/codex" if selector == "codex"
        else "/usr/local/lib/plamen/bin/claude"
    )
    return _canonical({
        "archive_member": payload["selected_member"],
        "archive_member_count": payload["member_count"],
        "archive_member_roster_sha256": payload["member_roster_sha256"],
        "artifact_id": f"{selector}-{version}-linux-arm64",
        "authentication_scope": "NATIVE_RETAINED_SOURCE_INPUT",
        "installed_sha256": installed["executable_sha256"],
        "installed_size": installed["executable_size"],
        "media_type": "application/vnd.plamen.authenticated-tar-member",
        "payload_sha256": payload["sha256"],
        "payload_size": payload["size"],
        "platform": "linux/arm64",
        "required_paths": [destination],
        "role": selector,
        "schema_version": "plamen.runtime_source_manifest.native-retained.v1",
        "source_reference": payload["source_url"],
        "version": version,
    }) + b"\n"


def _install_binding(
    *, selector: str, transaction_id: str, policy_sha256: str,
    resolution: Mapping[str, Any], payload: Mapping[str, Any],
    installed: Mapping[str, Any], probes: Mapping[str, Any],
    source_manifest: bytes,
) -> dict[str, Any]:
    generation_preimage = {
        "schema": "plamen.native-backend-generation-identity.v1",
        "selector": selector, "policy_sha256": policy_sha256,
        "resolved_version": resolution["version"],
        "resolved_release": resolution["platform_package"]["version"],
        "payload_sha256": payload["sha256"], "payload_size": payload["size"],
        "executable_sha256": installed["executable_sha256"],
        "executable_size": installed["executable_size"],
        "closure_sha256": installed["closure_sha256"],
        "source_manifest_sha256": hashlib.sha256(source_manifest).hexdigest(),
    }
    generation_id = "npm-" + hashlib.sha256(
        _canonical(generation_preimage)
    ).hexdigest()
    acquisition_preimage = {
        "schema": "plamen.native-backend-setup-acquisition.v1",
        "transaction_id": transaction_id, "generation_id": generation_id,
        "registry": resolution, "payload": payload,
        "installed": installed, "probes": probes,
        "source_manifest_sha256": hashlib.sha256(source_manifest).hexdigest(),
        "source_manifest_size": len(source_manifest),
    }
    return {
        "transaction_id": transaction_id,
        "generation_id": generation_id,
        "install_receipt_sha256": hashlib.sha256(
            _canonical(acquisition_preimage)
        ).hexdigest(),
        "source_manifest_sha256": hashlib.sha256(source_manifest).hexdigest(),
        "source_manifest_size": len(source_manifest),
    }


def _unsigned_receipt(
    *, selector: str, policy_sha256: str,
    resolution: Mapping[str, Any], transport: Mapping[str, Any],
    payload: Mapping[str, Any], installed: Mapping[str, Any],
    probes: Mapping[str, Any], install: Mapping[str, Any],
) -> bytes:
    registry = dict(resolution)
    registry.pop("upstream_release", None)
    return _canonical({
        "schema": receipt_authority.RECEIPT_SCHEMA,
        "selector": selector,
        "policy_schema": receipt_authority.POLICY_SCHEMA,
        "policy_sha256": policy_sha256,
        "resolved_version": resolution["version"],
        "resolved_release": resolution["platform_package"]["version"],
        "registry": registry,
        "upstream": (
            dict(resolution["upstream_release"])
            if selector == "claude" else None
        ),
        "transport": dict(transport), "payload": dict(payload),
        "installed": dict(installed), "probes": dict(probes),
        "install": dict(install),
    })


class ProductionBackendInputAuthority:
    """Opaque retained codex/claude input triples for the native signer."""

    __slots__ = ("_records", "_identities", "_labels", "_store", "_closed", "_lock")
    _PLAMEN_PRODUCTION_BACKEND_INPUTS_V1 = True

    def __init__(
        self, records: tuple[dict[str, Any], ...],
        identities: tuple[_Identity, ...], labels: tuple[str, ...],
        store: BackendPrivateStore,
    ) -> None:
        self._records = records; self._identities = identities
        self._labels = labels; self._store = store
        self._closed = False; self._lock = threading.Lock()

    def records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            if self._closed:
                _fail("production backend input authority is closed")
            descriptors = tuple(
                row[field] for row in self._records
                for field in (
                    "unsigned_receipt_fd", "payload_fd", "source_manifest_fd",
                )
            )
            if len(set(descriptors)) != 6:
                _fail("production backend input descriptor aliases")
            for descriptor, identity in zip(
                descriptors, self._identities, strict=True,
            ):
                _same_identity(descriptor, identity)
            return tuple(dict(row) for row in self._records)

    def close(self) -> bool:
        with self._lock:
            if self._closed:
                return True
            self._closed = True
            records = self._records; labels = self._labels
            self._records = (); self._labels = ()
        _close_many([
            row[field] for row in records
            for field in (
                "unsigned_receipt_fd", "payload_fd", "source_manifest_fd",
            )
        ])
        errors = []
        for label in reversed(labels):
            try:
                self._store.unlink_linked(label)
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise NativeBackendAcquisitionError(
                "production backend input cleanup failed"
            ) from errors[0]
        return True


def acquire_production_linux_arm64_backend_inputs(
    *, source_authority: RetainedBackendSourceAuthority,
    private_store: BackendPrivateStore, transaction_id: str,
    probe_authority: LinuxArm64ProbeAuthority,
    transport: BackendSetupTransport | None = None,
) -> ProductionBackendInputAuthority:
    """Resolve, authenticate, probe, and retain Codex/Claude exactly once."""

    if type(transaction_id) is not str or _TRANSACTION.fullmatch(transaction_id) is None:
        _fail("backend setup transaction identity differs")
    if (
        not callable(getattr(private_store, "pair", None))
        or not callable(getattr(private_store, "unlink_linked", None))
    ):
        _fail("backend private-store authority differs")
    selected_transport = transport or DefaultBackendSetupTransport()
    _validate_transport(selected_transport)
    policy, policy_sha256 = _policy_from_source(source_authority)
    linked_labels: list[str] = []
    owned: list[int] = []
    executable_fds: list[int] = []
    try:
        try:
            resolutions = receipt_authority.resolve_latest_backends(
                policy, fetch_json=selected_transport.fetch_json,
                fetch_bytes=selected_transport.fetch_bytes, platform=PLATFORM,
            )
        except receipt_authority.BackendAcquisitionError as exc:
            raise NativeBackendAcquisitionError(str(exc)) from exc
        if set(resolutions) != {"codex", "claude"}:
            _fail("latest backend resolution roster differs")
        materialized: dict[str, dict[str, Any]] = {}
        for selector in ("codex", "claude"):
            resolution = resolutions[selector]
            version = resolution.get("version")
            if type(version) is not str or re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+", version,
            ) is None:
                _fail("latest backend resolved version is not canonical")
            platform_row = resolution.get("platform_package")
            if type(platform_row) is not dict:
                _fail("latest backend platform resolution differs")
            payload_label = f"backend-{selector}-linux-arm64-payload"
            payload_writer, payload_reader = private_store.pair(
                payload_label, linked=True,
            )
            linked_labels.append(payload_label); owned.append(payload_reader)
            try:
                selected_transport.download(
                    platform_row["tarball_url"], writer_fd=payload_writer,
                )
                payload_reader, _payload_identity = _seal_pair(
                    payload_writer, payload_reader, links=1, mode=0o400,
                )
                payload_writer = -1
            finally:
                if payload_writer >= 0:
                    try:
                        os.close(payload_writer)
                    except OSError:
                        pass
            executable_writer, executable_reader = private_store.pair(
                f"backend-{selector}-probe-executable", linked=False,
            )
            executable_fds.append(executable_reader)
            try:
                payload, installed, executable_identity = _archive_projection(
                    selector=selector, payload_fd=payload_reader,
                    source_url=platform_row["tarball_url"],
                    expected_integrity=platform_row["integrity"],
                    expected_shasum=platform_row["shasum"],
                    executable_writer=executable_writer,
                    executable_reader=executable_reader,
                )
                executable_writer = -1
            finally:
                if executable_writer >= 0:
                    try:
                        os.close(executable_writer)
                    except OSError:
                        pass
            if selector == "claude":
                upstream = resolution.get("upstream_release")
                if (
                    type(upstream) is not dict
                    or upstream.get("platform") != PLATFORM
                    or upstream.get("executable_sha256")
                    != installed["executable_sha256"]
                    or upstream.get("executable_size")
                    != installed["executable_size"]
                ):
                    _fail("Claude archive differs from official manifest")
            probes = _run_probes(
                authority=probe_authority, selector=selector,
                version=version, executable_fd=executable_reader,
                executable_identity=executable_identity, policy=policy,
            )
            source_manifest = _render_source_manifest(
                selector=selector, version=version,
                payload=payload, installed=installed,
            )
            materialized[selector] = {
                "resolution": resolution, "payload": payload,
                "installed": installed, "probes": probes,
                "source_manifest": source_manifest,
                "payload_fd": payload_reader,
            }

        endpoints = selected_transport.endpoints()
        if (
            type(endpoints) is not tuple or len(endpoints) != 8
            or len(set(endpoints)) != len(endpoints)
            or any(type(item) is not str for item in endpoints)
        ):
            _fail("backend setup endpoint census differs")
        transport_projection = {
            "tls_minimum": "1.2", "redirect_count": 0,
            "credentials": "FORBIDDEN", "proxy_environment": "IGNORED",
            "endpoints_sha256": hashlib.sha256(_canonical(list(endpoints))).hexdigest(),
        }
        records: list[dict[str, Any]] = []
        identities: list[_Identity] = []
        for selector, role in (("codex", 5), ("claude", 6)):
            row = materialized[selector]
            install = _install_binding(
                selector=selector, transaction_id=transaction_id,
                policy_sha256=policy_sha256, resolution=row["resolution"],
                payload=row["payload"], installed=row["installed"],
                probes=row["probes"], source_manifest=row["source_manifest"],
            )
            unsigned = _unsigned_receipt(
                selector=selector, policy_sha256=policy_sha256,
                resolution=row["resolution"], transport=transport_projection,
                payload=row["payload"], installed=row["installed"],
                probes=row["probes"], install=install,
            )
            receipt_label = f"backend-{selector}-unsigned-receipt"
            manifest_label = f"backend-{selector}-source-manifest"
            receipt_writer, receipt_reader = private_store.pair(
                receipt_label, linked=True,
            )
            linked_labels.append(receipt_label); owned.append(receipt_reader)
            try:
                _write_all(receipt_writer, unsigned)
                receipt_reader, receipt_identity = _seal_pair(
                    receipt_writer, receipt_reader, links=1, mode=0o400,
                )
                receipt_writer = -1
            finally:
                if receipt_writer >= 0:
                    try:
                        os.close(receipt_writer)
                    except OSError:
                        pass
            manifest_writer, manifest_reader = private_store.pair(
                manifest_label, linked=True,
            )
            linked_labels.append(manifest_label); owned.append(manifest_reader)
            try:
                _write_all(manifest_writer, row["source_manifest"])
                manifest_reader, manifest_identity = _seal_pair(
                    manifest_writer, manifest_reader, links=1, mode=0o400,
                )
                manifest_writer = -1
            finally:
                if manifest_writer >= 0:
                    try:
                        os.close(manifest_writer)
                    except OSError:
                        pass
            payload_fd = row["payload_fd"]
            records.append({
                "selector": selector, "role": role,
                "unsigned_receipt_fd": receipt_reader,
                "payload_fd": payload_fd,
                "source_manifest_fd": manifest_reader,
            })
            identities.extend((
                receipt_identity, _identity(payload_fd), manifest_identity,
            ))
        authority = ProductionBackendInputAuthority(
            tuple(records), tuple(identities), tuple(linked_labels), private_store,
        )
        owned.clear(); linked_labels.clear()
        return authority
    except BaseException:
        _close_many(owned)
        for label in reversed(linked_labels):
            try:
                private_store.unlink_linked(label)
            except BaseException:
                pass
        raise
    finally:
        _close_many(executable_fds)


__all__ = [
    "BackendSetupTransport", "DefaultBackendSetupTransport",
    "LinuxArm64ProbeAuthority", "NativeBackendAcquisitionError",
    "ProductionBackendInputAuthority",
    "acquire_production_linux_arm64_backend_inputs",
]
