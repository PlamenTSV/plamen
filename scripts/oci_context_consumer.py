"""Fail-closed consumer boundary for authenticated deterministic OCI output.

No Python object is a production capability or authenticated receipt.  The
production entry point remains sealed until a native/out-of-process consumer
can authenticate an opaque release-authority receipt, own immutable input and
executable snapshots, and publish via descriptor-relative operations.

The conspicuous ``TEST_ONLY_*`` seam validates the complete canonical release
receipt and performs an exact, descriptor-relative OCI graph/rootfs census on
both first publication and COMMITTED recovery.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import gzip
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import stat
import tarfile
import threading
from typing import Any, NoReturn
import unicodedata

try:  # Import-safe on Windows; operational TEST_ONLY paths fail closed.
    import fcntl
except ImportError:  # pragma: no cover - Windows CI
    fcntl = None  # type: ignore[assignment]

import oci_release_authority as release_authority


REQUEST_SCHEMA = "plamen.oci_context_consumer_request.v3"
RECEIPT_SCHEMA = "plamen.oci_context_consumer_receipt.v3"
PROTOCOL = release_authority.PROTOCOL
TEST_ONLY_PROTOCOL = release_authority.TEST_ONLY_PROTOCOL

_MAX_INPUTS = 4096
_MAX_TOTAL_INPUT_BYTES = 8 * 1024 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{32,128}\Z")
_MODE = re.compile(r"0[0-7]{3}\Z")
_BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")


class OCIContextConsumerError(RuntimeError):
    """The authenticated context could not be consumed safely."""


class AmbiguousContextAttemptError(OCIContextConsumerError):
    """A consumer may have published output without a durable receipt."""


def _translate(exc: Exception) -> OCIContextConsumerError:
    if isinstance(exc, release_authority.AmbiguousReleaseAttemptError):
        return AmbiguousContextAttemptError("AMBIGUOUS_PRIOR_CONTEXT_ATTEMPT")
    if isinstance(exc, OCIContextConsumerError):
        return exc
    if isinstance(exc, release_authority.OCIReleaseAuthorityError):
        return OCIContextConsumerError(str(exc))
    return OCIContextConsumerError("context operation failed closed")


def _text(value: Any, label: str, pattern: re.Pattern[str] | None = None) -> str:
    try:
        return release_authority._text(value, label, pattern)
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None


def _sha256(value: Any, label: str) -> str:
    return _text(value, label, _SHA256)


def _positive(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    try:
        return release_authority._positive(value, label, maximum)
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None


def _nonnegative(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    try:
        return release_authority._nonnegative(value, label, maximum)
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None


def _canonical_bytes(value: Any) -> bytes:
    try:
        return release_authority._canonical_bytes(value)
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None


def _parse(raw: bytes, label: str) -> dict[str, Any]:
    try:
        return release_authority._parse_canonical_json(raw, label)
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OCIContextConsumerError(f"{label} does not have the exact schema")
    return value


def _identity(info: os.stat_result) -> dict[str, int]:
    return release_authority._stable_identity(info)


def _parent_identity(info: os.stat_result) -> dict[str, int]:
    value = _identity(info)
    value.pop("nlink")
    return value


def _validate_identity(value: Any, label: str, *, directory: bool = False) -> dict[str, int]:
    keys = {"device", "inode", "mode", "uid", "gid"} if directory else {"device", "inode", "mode", "uid", "gid", "nlink"}
    row = _exact(value, keys, label)
    result = {key: _nonnegative(item, f"{label} {key}") for key, item in row.items()}
    if not directory and result["nlink"] < 1:
        raise OCIContextConsumerError(f"{label} link count is invalid")
    return result


# Production boundary: deliberately no Python capability or receipt class.
def consume_context(
    *, native_context_capability: object, authenticated_release_receipt: object,
    **_request: Any,
) -> NoReturn:
    raise OCIContextConsumerError("NATIVE_CONTEXT_CONSUMER_INTEGRATION_REQUIRED")


class TEST_ONLY_ContextInput:
    """Descriptor metadata accepted only by the explicit TEST_ONLY consumer."""

    __slots__ = ("path", "sha256", "size", "mode", "descriptor")

    def __init__(self, *, path: str, sha256: str, size: int, mode: str, descriptor: int) -> None:
        self.path = path
        self.sha256 = sha256
        self.size = size
        self.mode = mode
        self.descriptor = descriptor


class _RetainedInput:
    __slots__ = ("row", "descriptor", "identity")

    def __init__(self, row: dict[str, Any], descriptor: int, identity: dict[str, int]) -> None:
        self.row = row
        self.descriptor = descriptor
        self.identity = identity


def _input_row(value: TEST_ONLY_ContextInput, number: int) -> dict[str, Any]:
    if type(value) is not TEST_ONLY_ContextInput:
        raise OCIContextConsumerError("inputs require the exact TEST_ONLY_ContextInput type")
    try:
        path = release_authority._relative_path(value.path, f"input {number} path")
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None
    return {
        "path": path, "sha256": _sha256(value.sha256, f"input {number} sha256"),
        "size": _nonnegative(value.size, f"input {number} size"),
        "mode": _text(value.mode, f"input {number} mode", _MODE),
    }


def _retain_inputs(values: Sequence[TEST_ONLY_ContextInput]) -> tuple[_RetainedInput, ...]:
    release_authority._require_posix()
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not 1 <= len(values) <= _MAX_INPUTS:
        raise OCIContextConsumerError("context input roster is outside its bound")
    retained: list[_RetainedInput] = []
    paths: set[str] = set()
    identities: set[tuple[int, int]] = set()
    total = 0
    try:
        for number, value in enumerate(values):
            row = _input_row(value, number)
            if row["path"].casefold() in paths:
                raise OCIContextConsumerError("context input path is duplicated/aliased")
            paths.add(row["path"].casefold())
            descriptor, metadata = release_authority._duplicate_readonly_file(value.descriptor, f"input {number}", _MAX_TOTAL_INPUT_BYTES)
            info = os.fstat(descriptor)
            identity = _identity(info)
            inode = (identity["device"], identity["inode"])
            if inode in identities:
                os.close(descriptor)
                raise OCIContextConsumerError("context input aliases another descriptor")
            identities.add(inode)
            if metadata != {"sha256": row["sha256"], "size": row["size"]} or f"0{stat.S_IMODE(info.st_mode):03o}" != row["mode"]:
                os.close(descriptor)
                raise OCIContextConsumerError("context input does not match its commitment")
            total += row["size"]
            if total > _MAX_TOTAL_INPUT_BYTES:
                os.close(descriptor)
                raise OCIContextConsumerError("context inputs exceed their total bound")
            retained.append(_RetainedInput(row, descriptor, identity))
        return tuple(retained)
    except BaseException:
        for item in retained:
            os.close(item.descriptor)
        raise


def _retain_parent(descriptor: int) -> tuple[int, dict[str, int]]:
    release_authority._require_posix()
    if isinstance(descriptor, bool) or not isinstance(descriptor, int) or descriptor < 0:
        raise OCIContextConsumerError("output-parent descriptor is invalid")
    duplicate = release_authority._dup_cloexec(descriptor)
    try:
        flags = int(fcntl.fcntl(duplicate, fcntl.F_GETFL))
        info = os.fstat(duplicate)
        if flags & os.O_ACCMODE != os.O_RDONLY or not stat.S_ISDIR(info.st_mode):
            raise OCIContextConsumerError("output-parent must be a read-only directory descriptor")
        return duplicate, _parent_identity(info)
    except BaseException:
        os.close(duplicate)
        raise


def _destination_identity(parent_fd: int, basename: str) -> dict[str, int] | None:
    try:
        info = os.stat(basename, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        raise OCIContextConsumerError("published output is not an ordinary directory")
    return _identity(info)


def _safe_component(value: str) -> str:
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value or unicodedata.normalize("NFC", value) != value:
        raise OCIContextConsumerError("output contains a non-canonical path component")
    return value


def _read_exact_file_at(parent_fd: int, name: str, expected: Mapping[str, Any]) -> bytes:
    descriptor = os.open(
        _safe_component(name),
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OCIContextConsumerError("output contains a link, alias, or special file")
        if before.st_size != expected["size"] or f"0{stat.S_IMODE(before.st_mode):03o}" != expected["mode"]:
            raise OCIContextConsumerError("output file metadata differs from its commitment")
        data = b""
        while len(data) < before.st_size:
            chunk = os.read(descriptor, before.st_size - len(data))
            if not chunk:
                raise OCIContextConsumerError("output file was truncated during census")
            data += chunk
        if os.read(descriptor, 1) or _identity(os.fstat(descriptor)) != _identity(before):
            raise OCIContextConsumerError("output file changed during census")
        if not hashlib.sha256(data).hexdigest() == expected["sha256"]:
            raise OCIContextConsumerError("output file digest differs from its commitment")
        os.fsync(descriptor)
        return data
    finally:
        os.close(descriptor)


def _open_directory_at(parent_fd: int, name: str) -> int:
    descriptor = os.open(
        _safe_component(name),
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=parent_fd,
    )
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OCIContextConsumerError("output path is not a directory")
    return descriptor


def _read_layout_tree(parent_fd: int, basename: str, commitments: Mapping[str, Any]) -> tuple[dict[str, bytes], dict[str, int]]:
    root_fd = _open_directory_at(parent_fd, basename)
    expected_files = {item["path"]: item for item in commitments["layout_files"]}
    expected_dirs: set[str] = set()
    for path in expected_files:
        parent = PurePosixPath(path).parent
        while parent.as_posix() != ".":
            expected_dirs.add(parent.as_posix())
            parent = parent.parent
    observed_files: dict[str, bytes] = {}
    observed_dirs: set[str] = set()

    def descend(directory_fd: int, prefix: str) -> None:
        names = os.listdir(directory_fd)
        if len({name.casefold() for name in names}) != len(names):
            raise OCIContextConsumerError("output contains case-colliding aliases")
        for name in sorted(names):
            _safe_component(name)
            relative = f"{prefix}/{name}" if prefix else name
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if relative not in expected_dirs:
                    raise OCIContextConsumerError("output contains an unexpected directory")
                child = _open_directory_at(directory_fd, name)
                try:
                    observed_dirs.add(relative)
                    descend(child, relative)
                    os.fsync(child)  # bottom-up durability
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                expected = expected_files.get(relative)
                if expected is None:
                    raise OCIContextConsumerError("output contains an unexpected file")
                observed_files[relative] = _read_exact_file_at(directory_fd, name, expected)
            else:
                raise OCIContextConsumerError("output contains a link or special node")
        # Caller fsyncs nested dirs after their children; root is below.

    try:
        descend(root_fd, "")
        if set(observed_files) != set(expected_files) or observed_dirs != expected_dirs:
            raise OCIContextConsumerError("output does not contain the exact committed closure")
        os.fsync(root_fd)
        return observed_files, _identity(os.fstat(root_fd))
    finally:
        os.close(root_fd)


def _oci_descriptor(value: Any, media_type: str, digest: str, size: int, label: str, *, platform: Mapping[str, str] | None = None) -> None:
    keys = {"mediaType", "digest", "size"} | ({"platform"} if platform is not None else set())
    row = _exact(value, keys, label)
    if row["mediaType"] != media_type or row["digest"] != digest or row["size"] != size:
        raise OCIContextConsumerError(f"{label} does not match its commitment")
    if platform is not None and row["platform"] != dict(platform):
        raise OCIContextConsumerError(f"{label} platform differs from its commitment")


def _canonical_oci_json(raw: bytes, label: str) -> dict[str, Any]:
    return _parse(raw, label)


def _tar_census(raw_gzip: bytes, layer: Mapping[str, Any]) -> list[dict[str, Any]]:
    return _tar_census_stream(io.BytesIO(raw_gzip), layer)


class _BoundedLayerReader:
    """Hash a bounded decompressed stream without retaining the entire rootfs."""

    def __init__(self, stream: Any, expected_size: int) -> None:
        self.stream = stream
        self.expected_size = expected_size
        self.observed = 0
        self.digest = hashlib.sha256()

    def read(self, size: int) -> bytes:
        if type(size) is not int or size < 0:
            raise OCIContextConsumerError("layer reads require a finite bound")
        size = min(size, 1024 * 1024, self.expected_size - self.observed + 1)
        raw = self.stream.read(size)
        self.observed += len(raw)
        if self.observed > self.expected_size:
            raise OCIContextConsumerError("layer expanded size differs from its commitment")
        self.digest.update(raw)
        return raw


def _tar_census_stream(compressed_stream: Any, layer: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Pure census over a retained stream; not execution or release authority."""
    if (type(layer.get("uncompressed_size")) is not int
            or not 0 < layer["uncompressed_size"] <= release_authority._MAX_TOTAL_EXPANDED):
        raise OCIContextConsumerError("layer expanded size is outside its bound")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        with gzip.GzipFile(fileobj=compressed_stream, mode="rb") as decoded:
            stream = _BoundedLayerReader(decoded, layer["uncompressed_size"])
            with tarfile.open(fileobj=stream, mode="r|") as archive:
                _census_tar_members(archive, entries, seen)
            # Tar parsing stops at its end marker. Drain the exact gzip member
            # to authenticate all padding/trailing bytes and its final CRC.
            while stream.read(1024 * 1024):
                pass
            if stream.observed != layer["uncompressed_size"]:
                raise OCIContextConsumerError("layer expanded size differs from its commitment")
            if "sha256:" + stream.digest.hexdigest() != layer["diff_id"]:
                raise OCIContextConsumerError("layer DiffID differs from its commitment")
    except (tarfile.TarError, OSError, EOFError) as exc:
        if isinstance(exc, OCIContextConsumerError):
            raise
        raise OCIContextConsumerError("layer tar/gzip stream is malformed") from exc
    return sorted(entries, key=lambda item: item["path"].encode("utf-8"))


def _census_tar_members(archive: Any, entries: list[dict[str, Any]], seen: set[str]) -> None:
    for member in archive:
        if len(entries) >= release_authority._MAX_ARTIFACTS + release_authority._MAX_DIRECTORIES:
            raise OCIContextConsumerError("layer census entry count exceeds its bound")
        name = member.name[:-1] if member.isdir() and member.name.endswith("/") else member.name
        try:
            path = release_authority._relative_path(name, "layer member path")
        except release_authority.OCIReleaseAuthorityError as exc:
            raise _translate(exc) from None
        folded = path.casefold()
        if folded in seen:
            raise OCIContextConsumerError("layer contains a duplicate/aliased path")
        seen.add(folded)
        if (
            PurePosixPath(path).name.startswith(".wh.")
            or member.uid != 0
            or member.gid != 0
            or member.mtime != 0
            or member.uname not in {"", "root"}
            or member.gname not in {"", "root"}
            or member.pax_headers
        ):
            raise OCIContextConsumerError("layer member metadata is not deterministic")
        mode = f"0{member.mode & 0o777:03o}"
        if member.isdir():
            entries.append({"kind": "directory", "linkname": "", "mode": mode, "path": path, "sha256": None, "size": 0})
        elif member.isfile():
            handle = archive.extractfile(member)
            if handle is None:
                raise OCIContextConsumerError("layer file body is absent")
            if not 0 <= member.size <= release_authority._MAX_TOTAL_EXPANDED:
                raise OCIContextConsumerError("layer member size is outside its bound")
            digest, remaining = hashlib.sha256(), member.size
            while remaining:
                body = handle.read(min(remaining, 1024 * 1024))
                if not body:
                    raise OCIContextConsumerError("layer member size is inconsistent")
                digest.update(body)
                remaining -= len(body)
            if handle.read(1):
                raise OCIContextConsumerError("layer member size is inconsistent")
            entries.append({"kind": "file", "linkname": "", "mode": mode, "path": path, "sha256": digest.hexdigest(), "size": member.size})
        elif member.issym() or member.islnk():
            kind = "symlink" if member.issym() else "hardlink"
            linkname = member.linkname
            if not isinstance(linkname, str) or not linkname or "\x00" in linkname:
                raise OCIContextConsumerError("layer link target is malformed")
            entries.append({"kind": kind, "linkname": linkname, "mode": mode, "path": path, "sha256": hashlib.sha256((kind + "\0" + linkname).encode("utf-8")).hexdigest(), "size": 0})
        else:
            raise OCIContextConsumerError("layer contains a special member")


def _verify_oci_graph(
    files: Mapping[str, bytes], commitments: Mapping[str, Any], *,
    layer_streams: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if files["oci-layout"] != b'{"imageLayoutVersion":"1.0.0"}\n':
        raise OCIContextConsumerError("oci-layout marker is not exact")
    index = _canonical_oci_json(files["index.json"], "OCI index")
    _exact(index, {"schemaVersion", "mediaType", "manifests"}, "OCI index")
    if index["schemaVersion"] != 2 or index["mediaType"] != release_authority.INDEX_MEDIA_TYPE or not isinstance(index["manifests"], list) or len(index["manifests"]) != 1:
        raise OCIContextConsumerError("OCI index graph is unsupported")
    manifest_commitment = commitments["manifest"]
    _oci_descriptor(index["manifests"][0], release_authority.MANIFEST_MEDIA_TYPE, manifest_commitment["digest"], manifest_commitment["size"], "index manifest descriptor", platform=commitments["platform"])

    manifest_path = f"blobs/sha256/{manifest_commitment['digest'].split(':', 1)[1]}"
    manifest = _canonical_oci_json(files[manifest_path], "OCI manifest")
    _exact(manifest, {"schemaVersion", "mediaType", "config", "layers"}, "OCI manifest")
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != release_authority.MANIFEST_MEDIA_TYPE or not isinstance(manifest["layers"], list) or len(manifest["layers"]) != len(commitments["layers"]):
        raise OCIContextConsumerError("OCI manifest graph is unsupported")
    config_commitment = commitments["config"]
    _oci_descriptor(manifest["config"], release_authority.CONFIG_MEDIA_TYPE, config_commitment["digest"], config_commitment["size"], "manifest config descriptor")
    for number, layer in enumerate(commitments["layers"]):
        _oci_descriptor(manifest["layers"][number], release_authority.LAYER_MEDIA_TYPE, layer["digest"], layer["size"], f"manifest layer {number}")

    config_path = f"blobs/sha256/{config_commitment['digest'].split(':', 1)[1]}"
    config_raw = files[config_path]
    config = _canonical_oci_json(config_raw, "OCI config")
    if hashlib.sha256(config_raw[:-1]).hexdigest() != commitments["apple_container_configuration_sha256"]:
        raise OCIContextConsumerError("Apple Container configuration digest differs from exact canonical bytes")
    if not {"architecture", "os", "rootfs"} <= set(config) or config["architecture"] != commitments["platform"]["architecture"] or config["os"] != commitments["platform"]["os"]:
        raise OCIContextConsumerError("OCI config platform differs from its commitment")
    rootfs = _exact(config["rootfs"], {"type", "diff_ids"}, "OCI config rootfs")
    if rootfs["type"] != "layers" or rootfs["diff_ids"] != [layer["diff_id"] for layer in commitments["layers"]]:
        raise OCIContextConsumerError("OCI config DiffIDs differ from the layer roster")

    all_entries: dict[str, dict[str, Any]] = {}
    seen_folded: set[str] = set()
    for layer in commitments["layers"]:
        layer_path = f"blobs/sha256/{layer['digest'].split(':', 1)[1]}"
        layer_entries = (_tar_census(files[layer_path], layer) if layer_streams is None
                         else _tar_census_stream(layer_streams[layer_path], layer))
        for item in layer_entries:
            folded = item["path"].casefold()
            if folded in seen_folded:
                raise OCIContextConsumerError("layers contain a duplicate/aliased path")
            seen_folded.add(folded)
            # OCI layer replacement semantics are not admitted by this fixed
            # protocol; every rootfs path is represented exactly once.
            all_entries[item["path"]] = item
    return sorted(all_entries.values(), key=lambda item: item["path"].encode("utf-8"))


def _full_output_census(parent_fd: int, basename: str, commitments: Mapping[str, Any]) -> tuple[str, dict[str, int]]:
    try:
        normalized = release_authority.validate_output_commitments(commitments)
    except release_authority.OCIReleaseAuthorityError as exc:
        raise _translate(exc) from None
    files, output_identity = _read_layout_tree(parent_fd, basename, normalized)
    observed_entries = _verify_oci_graph(files, normalized)
    if observed_entries != normalized["rootfs_entries"]:
        raise OCIContextConsumerError("layer census differs from installed-runtime commitments")
    census = {
        "schema_version": "plamen.oci_output_census.v3",
        "commitments_sha256": release_authority.commitments_sha256(normalized),
        "layout_files": [
            {"path": path, "sha256": hashlib.sha256(files[path]).hexdigest(), "size": len(files[path])}
            for path in sorted(files)
        ],
        "rootfs_entries": observed_entries,
    }
    # All artifact/blob files and nested directories were fsynced bottom-up.
    # Now order durability at the containing parent before journal COMMIT.
    os.fsync(parent_fd)
    return hashlib.sha256(_canonical_bytes(census)).hexdigest(), output_identity


_TEST_CONTEXT_RECEIPT_KEYS = {
    "schema_version", "status", "protocol", "request_sha256", "attempt_id",
    "context_nonce", "release_receipt_sha256", "release_nonce", "lock_sha256",
    "commitments_sha256", "input_closure_sha256", "output_parent_identity",
    "output_basename", "output_identity", "output_census_sha256",
}


class _TestOnlyVerifiedContextReceipt:
    __slots__ = ("_bytes", "_recovered")

    def __init__(self, raw: bytes, recovered: bool = False) -> None:
        self._bytes = raw
        self._recovered = recovered

    @property
    def canonical_bytes(self) -> bytes:
        return self._bytes

    @property
    def value(self) -> dict[str, Any]:
        return json.loads(self._bytes.decode("utf-8"))

    @property
    def recovered(self) -> bool:
        return self._recovered


def _validate_test_context_receipt(raw: bytes, request: Mapping[str, Any]) -> dict[str, Any]:
    value = _parse(raw, "TEST-ONLY context receipt")
    _exact(value, _TEST_CONTEXT_RECEIPT_KEYS, "TEST-ONLY context receipt")
    expected = {
        "schema_version": RECEIPT_SCHEMA, "status": "TEST_ONLY_CONSUMED",
        "protocol": TEST_ONLY_PROTOCOL,
        "request_sha256": hashlib.sha256(_canonical_bytes(dict(request))).hexdigest(),
        "attempt_id": request["attempt_id"], "context_nonce": request["context_nonce"],
        "release_receipt_sha256": request["release_receipt_sha256"],
        "release_nonce": request["release_nonce"], "lock_sha256": request["lock_sha256"],
        "commitments_sha256": request["commitments_sha256"],
        "input_closure_sha256": request["input_closure_sha256"],
        "output_parent_identity": request["output_parent_identity"],
        "output_basename": request["output_basename"],
    }
    for key, item in expected.items():
        if value.get(key) != item:
            raise OCIContextConsumerError("TEST-ONLY context receipt does not bind the request")
    _validate_identity(value["output_identity"], "receipt output identity")
    _sha256(value["output_census_sha256"], "receipt output census")
    return value


class _TestOnlyContextConsumer:
    __slots__ = ("_executable", "_ledger", "_lock", "_used")

    def __init__(self, executable: release_authority._TestOnlyExecutable, ledger: str | os.PathLike[str]) -> None:
        self._executable = executable
        self._ledger = os.fspath(ledger)
        self._lock = threading.Lock()
        self._used = False

    def consume_for_testing(
        self, *, attempt_id: str, context_nonce: str,
        release_receipt: release_authority._TestOnlyVerifiedReleaseReceipt,
        inputs: Sequence[TEST_ONLY_ContextInput], output_parent_fd: int,
        output_basename: str, timeout_seconds: Any,
    ) -> _TestOnlyVerifiedContextReceipt:
        with self._lock:
            if self._used:
                raise OCIContextConsumerError("TEST-ONLY context consumer is one-shot")
            self._used = True
        try:
            release_authority._timeout(timeout_seconds)
            if type(release_receipt) is not release_authority._TestOnlyVerifiedReleaseReceipt:
                raise OCIContextConsumerError("exact TEST-ONLY release receipt type is required")
            try:
                release_value = release_authority._validate_test_release_receipt(release_receipt.canonical_bytes)
            except release_authority.OCIReleaseAuthorityError as exc:
                raise _translate(exc) from None
            attempt = _text(attempt_id, "attempt id", _NONCE)
            nonce = _text(context_nonce, "context nonce", _NONCE)
            basename = _text(output_basename, "output basename", _BASENAME)
            retained = _retain_inputs(inputs)
            parent_fd, parent_identity = _retain_parent(output_parent_fd)
            try:
                roster = [item.row for item in retained]
                materialization = release_value["commitments"]["runtime_materialization"]
                expected_materialization = {
                    value["path"]: {key: value[key] for key in ("path", "sha256", "size")}
                    for value in (
                        materialization["composition_manifest"],
                        materialization["archive"], materialization["receipt"],
                        materialization["census"], materialization["sbom"],
                        materialization["provenance"],
                    )
                }
                observed_materialization = {
                    value["path"]: {key: value[key] for key in ("path", "sha256", "size")}
                    for value in roster
                    if value["path"] in expected_materialization
                }
                if observed_materialization != expected_materialization:
                    raise OCIContextConsumerError(
                        "retained runtime materialization evidence is incomplete"
                    )
                closure = hashlib.sha256(_canonical_bytes(roster)).hexdigest()
                request = {
                    "schema_version": REQUEST_SCHEMA, "protocol": TEST_ONLY_PROTOCOL,
                    "attempt_id": attempt, "context_nonce": nonce,
                    "release_receipt_sha256": hashlib.sha256(release_receipt.canonical_bytes).hexdigest(),
                    "release_nonce": release_value["release_nonce"],
                    "lock_sha256": release_value["lock_sha256"],
                    "commitments": release_value["commitments"],
                    "commitments_sha256": release_value["commitments_sha256"],
                    "inputs": roster, "input_closure_sha256": closure,
                    "output_parent_identity": parent_identity, "output_basename": basename,
                    "test_executable_provenance": release_authority._test_executable_provenance(self._executable._record),
                }
                request_raw = _canonical_bytes(request)
                request_digest = hashlib.sha256(request_raw).hexdigest()
                with release_authority._DurableAttempt(self._ledger, "context-test-only", attempt, nonce) as journal:
                    raw = journal.admit(request_digest)
                    recovered = raw is not None
                    if raw is None:
                        if _destination_identity(parent_fd, basename) is not None:
                            raise OCIContextConsumerError("output destination already exists")
                        raw = release_authority._run_test_helper(
                            self._executable, role="context-consume-test-only",
                            request=request_raw,
                            descriptors=tuple((f"input-{number}", item.descriptor) for number, item in enumerate(retained)) + (("output-parent", parent_fd),),
                            timeout_seconds=timeout_seconds,
                        )
                        for item in retained:
                            if os.lseek(item.descriptor, 0, os.SEEK_CUR) != item.row["size"]:
                                raise OCIContextConsumerError("TEST-ONLY helper did not consume every input")
                            if (
                                _identity(os.fstat(item.descriptor)) != item.identity
                                or release_authority._file_sha256(item.descriptor, item.row["size"]) != item.row["sha256"]
                            ):
                                raise OCIContextConsumerError("TEST-ONLY input changed during consumption")
                        value = _validate_test_context_receipt(raw, request)
                        census, identity = _full_output_census(parent_fd, basename, release_value["commitments"])
                        if value["output_identity"] != identity or value["output_census_sha256"] != census:
                            raise OCIContextConsumerError("TEST-ONLY receipt does not bind exact output census")
                        if _parent_identity(os.fstat(parent_fd)) != parent_identity:
                            raise OCIContextConsumerError("output-parent identity changed")
                        journal.commit(request_digest, raw)
                    else:
                        if _destination_identity(parent_fd, basename) is None:
                            raise OCIContextConsumerError("COMMITTED output is absent")
                        value = _validate_test_context_receipt(raw, request)
                        census, identity = _full_output_census(parent_fd, basename, release_value["commitments"])
                        if value["output_identity"] != identity or value["output_census_sha256"] != census:
                            raise OCIContextConsumerError("COMMITTED output failed complete recensus")
                        if _parent_identity(os.fstat(parent_fd)) != parent_identity:
                            raise OCIContextConsumerError("output-parent identity changed")
                return _TestOnlyVerifiedContextReceipt(raw, recovered)
            finally:
                os.close(parent_fd)
                for item in retained:
                    os.close(item.descriptor)
        except Exception as exc:
            raise _translate(exc) from None


def TEST_ONLY_create_context_consumer(
    executable: release_authority._TestOnlyExecutable,
    ledger_directory: str | os.PathLike[str],
) -> _TestOnlyContextConsumer:
    if type(executable) is not release_authority._TestOnlyExecutable:
        raise TypeError("TEST-ONLY consumer requires exact TEST-ONLY executable")
    return _TestOnlyContextConsumer(executable, ledger_directory)


__all__ = [
    "AmbiguousContextAttemptError", "OCIContextConsumerError", "PROTOCOL",
    "RECEIPT_SCHEMA", "REQUEST_SCHEMA", "consume_context",
]
