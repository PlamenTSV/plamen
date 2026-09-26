"""Private acquisition boundary for Codex ``auth.json`` material.

This module deliberately has no import-time I/O and emits no credential
evidence.  On Darwin and Linux it opens an exact, canonical absolute path by
walking every component with no-follow descriptors, validates the private
file through the retained descriptor, and owns the bytes until a trusted
private sink consumes them once.

Credential bytes and credential-derived digests are never returned, logged,
or placed in a receipt.  The only intentional exposure is the mutable
``bytearray`` passed synchronously to the trusted sink.  That buffer is erased
as soon as the callback returns or raises.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
import threading
import traceback
from typing import Callable, Protocol, TypeAlias
import weakref


MAX_CODEX_AUTH_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


class CodexStoredAuthSourceError(RuntimeError):
    """The requested stored-auth operation could not be proven safe."""

    def __init__(self, message: str, *, reason_code: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class _DuplicateJsonKey(ValueError):
    pass


_StatSignature: TypeAlias = tuple[int, int, int, int, int, int, int, int]
_Sink: TypeAlias = Callable[[bytearray], None]


class DarwinDescriptorSecurityVerifier(Protocol):
    """Trusted descriptor-native verifier supplied by a compiled boundary.

    A true result means the descriptor has no extended ACL and no xattr,
    including attributes visible only with Darwin's XATTR_SHOWCOMPRESSION.
    The verifier must fail closed and must not reopen a pathname.
    """

    def __call__(self, source_descriptor: int, /) -> bool: ...


_DescriptorSecurityVerifier: TypeAlias = DarwinDescriptorSecurityVerifier


def _redacted_error(reason_code: str, message: str) -> CodexStoredAuthSourceError:
    # Keep all path and OS exception detail outside the durable exception.
    return CodexStoredAuthSourceError(message, reason_code=reason_code)


def _zero(buffer: bytearray | None) -> None:
    if buffer is None:
        return
    buffer[:] = b"\x00" * len(buffer)


def _close(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except OSError:
        pass


def _platform_supported() -> bool:
    return sys.platform == "darwin" or sys.platform.startswith("linux")


def _exact_components(value: str | os.PathLike[str]) -> tuple[str, ...]:
    if not _platform_supported():
        raise _redacted_error(
            "UNSUPPORTED_HOST",
            "Codex stored auth is supported only on Darwin and Linux",
        )
    try:
        text = os.fspath(value)
    except (TypeError, ValueError):
        raise _redacted_error(
            "INVALID_PATH", "Codex auth path is malformed"
        ) from None
    if (
        not isinstance(text, str)
        or not text
        or "\x00" in text
        or text != text.strip()
        or not text.startswith("/")
        or os.path.normpath(text) != text
        or text == "/"
    ):
        raise _redacted_error(
            "INVALID_PATH", "Codex auth path must be exact, canonical, and absolute"
        )
    components = tuple(text.split("/")[1:])
    if (
        not components
        or components[-1] != "auth.json"
        or any(not item or item in {".", ".."} for item in components)
    ):
        raise _redacted_error(
            "INVALID_PATH", "Codex auth path must name an exact auth.json file"
        )
    return components


def _signature(info: os.stat_result) -> _StatSignature:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(getattr(info, "st_nlink", 0)),
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", 0)),
        int(getattr(info, "st_ctime_ns", 0)),
    )


def _validate_auth_stat(info: os.stat_result) -> None:
    if not stat.S_ISREG(int(info.st_mode)):
        raise _redacted_error(
            "SOURCE_NOT_REGULAR", "Codex auth source is not a regular file"
        )
    if stat.S_IMODE(int(info.st_mode)) != 0o600:
        raise _redacted_error(
            "SOURCE_MODE", "Codex auth source is not owner-only mode 0600"
        )
    if int(info.st_uid) != int(os.getuid()):
        raise _redacted_error(
            "SOURCE_OWNER", "Codex auth source is not owned by the current user"
        )
    if int(getattr(info, "st_nlink", 0)) != 1:
        raise _redacted_error(
            "SOURCE_HARDLINK", "Codex auth source has an unsafe link count"
        )
    if int(info.st_size) <= 0 or int(info.st_size) > MAX_CODEX_AUTH_BYTES:
        raise _redacted_error(
            "SOURCE_SIZE", "Codex auth source has an invalid bounded size"
        )


def _validate_no_extended_security(
    descriptor: int,
    darwin_verifier: _DescriptorSecurityVerifier | None,
) -> None:
    if sys.platform == "darwin":
        if darwin_verifier is None:
            raise _redacted_error(
                "DARWIN_SECURITY_VERIFIER_REQUIRED",
                "Darwin descriptor security requires a compiled verifier",
            )
        try:
            verified = darwin_verifier(descriptor)
        except BaseException as exc:
            traceback.clear_frames(exc.__traceback__)
            exc.__traceback__ = None
            exc.__cause__ = None
            exc.__context__ = None
            raise _redacted_error(
                "SOURCE_METADATA_UNPROVEN",
                "Codex auth extended security could not be proven absent",
            ) from None
        if verified is not True:
            raise _redacted_error(
                "SOURCE_EXTENDED_SECURITY",
                "Codex auth source has an ACL or extended attribute",
            ) from None
        return

    # Linux exposes POSIX ACLs as system.posix_acl_* xattrs.  Reject every
    # descriptor-bound xattr rather than attempting an allowlist.
    listxattr = getattr(os, "listxattr", None)
    if listxattr is None:
        raise _redacted_error(
            "SOURCE_METADATA_UNPROVEN",
            "Codex auth extended security could not be proven absent",
        )
    try:
        attributes = listxattr(descriptor)
    except OSError:
        raise _redacted_error(
            "SOURCE_METADATA_UNPROVEN",
            "Codex auth extended security could not be proven absent",
        ) from None
    if attributes:
        attributes = []
        raise _redacted_error(
            "SOURCE_XATTR", "Codex auth source has extended attributes"
        ) from None
    attributes = []


class _SourceLease:
    """Retained descriptor chain for one exact absolute source binding."""

    __slots__ = (
        "directory_descriptors",
        "directory_names",
        "darwin_verifier",
        "file_descriptor",
        "file_name",
        "source_signature",
    )

    def __init__(
        self,
        *,
        directory_descriptors: tuple[int, ...],
        directory_names: tuple[str, ...],
        darwin_verifier: _DescriptorSecurityVerifier | None,
        file_descriptor: int,
        file_name: str,
        source_signature: _StatSignature,
    ) -> None:
        self.directory_descriptors = directory_descriptors
        self.directory_names = directory_names
        self.darwin_verifier = darwin_verifier
        self.file_descriptor = file_descriptor
        self.file_name = file_name
        self.source_signature = source_signature

    def close(self) -> None:
        descriptor = self.file_descriptor
        self.file_descriptor = -1
        _close(descriptor)
        for descriptor in reversed(self.directory_descriptors):
            _close(descriptor)
        self.directory_descriptors = ()
        self.directory_names = ()
        self.darwin_verifier = None
        self.file_name = ""


def _open_source_lease(
    components: tuple[str, ...],
    *,
    darwin_verifier: _DescriptorSecurityVerifier | None,
) -> _SourceLease:
    directory_descriptors: list[int] = []
    file_descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        flags
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    # O_NONBLOCK prevents a malicious FIFO/device leaf from blocking before
    # the retained descriptor can be proven to be a regular file.
    file_flags = (
        flags
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        root = os.open("/", directory_flags)
        directory_descriptors.append(root)
        for name in components[:-1]:
            child = -1
            try:
                child = os.open(
                    name,
                    directory_flags,
                    dir_fd=directory_descriptors[-1],
                )
                child_info = os.fstat(child)
                if not stat.S_ISDIR(int(child_info.st_mode)):
                    raise _redacted_error(
                        "ANCESTRY_NOT_DIRECTORY",
                        "Codex auth ancestry contains a non-directory component",
                    )
                directory_descriptors.append(child)
                child = -1
            finally:
                _close(child)
        file_descriptor = os.open(
            components[-1], file_flags, dir_fd=directory_descriptors[-1]
        )
        source_info = os.fstat(file_descriptor)
        _validate_auth_stat(source_info)
        _validate_no_extended_security(file_descriptor, darwin_verifier)
        lease = _SourceLease(
            directory_descriptors=tuple(directory_descriptors),
            directory_names=tuple(components[:-1]),
            darwin_verifier=darwin_verifier,
            file_descriptor=file_descriptor,
            file_name=components[-1],
            source_signature=_signature(source_info),
        )
        directory_descriptors = []
        file_descriptor = -1
        return lease
    except CodexStoredAuthSourceError:
        raise
    except (OSError, OverflowError, ValueError):
        raise _redacted_error(
            "SOURCE_OPEN", "Codex auth source could not be opened safely"
        ) from None
    finally:
        _close(file_descriptor)
        for descriptor in reversed(directory_descriptors):
            _close(descriptor)


def _replay_source_lease(lease: _SourceLease) -> None:
    valid = True
    try:
        descriptors = lease.directory_descriptors
        names = lease.directory_names
        if (
            lease.file_descriptor < 0
            or not descriptors
            or len(descriptors) != len(names) + 1
            or lease.file_name != "auth.json"
        ):
            valid = False
        if valid:
            root_info = os.fstat(descriptors[0])
            if not stat.S_ISDIR(int(root_info.st_mode)):
                valid = False
        if valid:
            for index, name in enumerate(names):
                named = os.stat(
                    name,
                    dir_fd=descriptors[index],
                    follow_symlinks=False,
                )
                opened = os.fstat(descriptors[index + 1])
                if (
                    not stat.S_ISDIR(int(named.st_mode))
                    or stat.S_ISLNK(int(named.st_mode))
                    or (int(named.st_dev), int(named.st_ino))
                    != (int(opened.st_dev), int(opened.st_ino))
                ):
                    valid = False
                    break
        if valid:
            named_source = os.stat(
                lease.file_name,
                dir_fd=descriptors[-1],
                follow_symlinks=False,
            )
            opened_source = os.fstat(lease.file_descriptor)
            _validate_auth_stat(named_source)
            _validate_auth_stat(opened_source)
            _validate_no_extended_security(
                lease.file_descriptor,
                lease.darwin_verifier,
            )
            if (
                _signature(named_source) != lease.source_signature
                or _signature(opened_source) != lease.source_signature
                or (int(named_source.st_dev), int(named_source.st_ino))
                != (int(opened_source.st_dev), int(opened_source.st_ino))
            ):
                valid = False
    except CodexStoredAuthSourceError:
        valid = False
    except (OSError, OverflowError, ValueError):
        valid = False
    if not valid:
        raise _redacted_error(
            "SOURCE_CHANGED", "Codex auth source identity changed"
        ) from None


def _read_bounded_material(descriptor: int) -> bytearray:
    material = bytearray()
    scratch = bytearray(_READ_CHUNK_BYTES)
    try:
        while True:
            count = os.readv(descriptor, (scratch,))
            if count == 0:
                break
            if count < 0 or count > len(scratch):
                raise _redacted_error(
                    "SOURCE_READ", "Codex auth source returned an invalid read"
                )
            if len(material) + count > MAX_CODEX_AUTH_BYTES:
                raise _redacted_error(
                    "SOURCE_SIZE", "Codex auth source exceeded its bounded size"
                )
            material.extend(memoryview(scratch)[:count])
            scratch[:count] = b"\x00" * count
        return material
    except CodexStoredAuthSourceError:
        _zero(material)
        raise
    except (OSError, OverflowError, ValueError):
        _zero(material)
        raise _redacted_error(
            "SOURCE_READ", "Codex auth source could not be read safely"
        ) from None
    finally:
        _zero(scratch)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey()
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _validate_strict_json_object(raw: bytearray) -> None:
    document: object = None
    decoded: str | None = None
    failed = False
    caught: BaseException | None = None
    try:
        if raw[:3] == bytearray(b"\xef\xbb\xbf"):
            failed = True
        else:
            # json.loads(bytes) also auto-detects UTF-16/32.  auth.json is an
            # exact UTF-8 boundary, so perform the strict decode explicitly.
            decoded = raw.decode("utf-8", errors="strict")
            document = json.loads(
                decoded,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_json_constant,
            )
            failed = not isinstance(document, dict)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJsonKey, ValueError, RecursionError) as exc:
        failed = True
        caught = exc
    if caught is not None:
        traceback.clear_frames(caught.__traceback__)
    # Do not leave parsed credential strings in a traceback frame.
    caught = None
    document = None
    decoded = None
    raw = bytearray()
    if failed:
        raise _redacted_error(
            "INVALID_JSON", "Codex auth source is not a strict JSON object"
        ) from None


_STATE_LOCK = threading.RLock()
_PENDING: dict[str, tuple[bytearray, _SourceLease]] = {}
_PATH_PENDING: dict[
    str, tuple[object, _DescriptorSecurityVerifier | None]
] = {}
_ISSUED: dict[
    int,
    tuple[
        weakref.ReferenceType[CodexStoredAuthCapability],
        str,
        int,
        bytearray | None,
        _SourceLease | None,
    ],
] = {}


class CodexStoredAuthCapability:
    """Opaque, process-bound, noncopyable ownership of Codex auth bytes.

    Material lives in the issuer registry, not on this Python object.  This
    prevents accidental disclosure through slots, vars(), or direct
    gc.get_referents(capability).  It is not a claim that a malicious process
    hosting this module cannot inspect Python memory; callers needing that
    custody boundary must request native custody and receive a fail-closed
    typed result until a compiled broker is integrated.
    """

    __slots__ = ("__weakref__",)

    def __init_subclass__(cls, **_kwargs: object) -> None:
        raise TypeError("Codex stored-auth capability cannot be subclassed")

    def __init__(
        self,
        *,
        _issuance_id: str | None = None,
    ) -> None:
        pending: tuple[bytearray, _SourceLease] | None = None
        if isinstance(_issuance_id, str):
            with _STATE_LOCK:
                pending = _PENDING.pop(_issuance_id, None)
        if (
            pending is None
            or not isinstance(pending[0], bytearray)
            or not isinstance(pending[1], _SourceLease)
        ):
            raise TypeError("Codex stored-auth capability requires private acquisition")
        material, lease = pending
        key = id(self)

        def retire(reference: weakref.ReferenceType[CodexStoredAuthCapability]) -> None:
            resources: tuple[bytearray | None, _SourceLease | None] = (None, None)
            with _STATE_LOCK:
                current = _ISSUED.get(key)
                if current is not None and current[0] is reference:
                    _ISSUED.pop(key, None)
                    resources = (current[3], current[4])
            _zero(resources[0])
            if resources[1] is not None:
                resources[1].close()

        reference = weakref.ref(self, retire)
        with _STATE_LOCK:
            _ISSUED[key] = (
                reference,
                "READY",
                os.getpid(),
                material,
                lease,
            )

    def __repr__(self) -> str:
        return "<CodexStoredAuthCapability opaque>"

    def __copy__(self) -> None:
        raise TypeError("Codex stored-auth capability cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("Codex stored-auth capability cannot be copied")

    def __reduce__(self) -> None:
        raise TypeError("Codex stored-auth capability cannot be serialized")

    def __reduce_ex__(self, _protocol: int) -> None:
        raise TypeError("Codex stored-auth capability cannot be serialized")

    def __getstate__(self) -> None:
        raise TypeError("Codex stored-auth capability cannot be serialized")

    def __detach(self, next_state: str) -> tuple[bytearray, _SourceLease]:
        with _STATE_LOCK:
            current = _ISSUED.get(id(self))
            if (
                type(self) is not CodexStoredAuthCapability
                or current is None
                or current[0]() is not self
                or current[1] != "READY"
                or current[2] != os.getpid()
                or not isinstance(current[3], bytearray)
                or not isinstance(current[4], _SourceLease)
            ):
                raise _redacted_error(
                    "CAPABILITY_CONSUMED",
                    "Codex stored-auth capability is no longer available",
                )
            material = current[3]
            lease = current[4]
            _ISSUED[id(self)] = (
                current[0],
                next_state,
                current[2],
                None,
                None,
            )
            return material, lease

    def __finish(self, state: str) -> None:
        with _STATE_LOCK:
            current = _ISSUED.get(id(self))
            if current is not None and current[0]() is self:
                _ISSUED[id(self)] = (
                    current[0],
                    state,
                    current[2],
                    None,
                    None,
                )

    def discard(self) -> None:
        """Erase held material without exposing it."""

        material, lease = self.__detach("DISCARDING")
        try:
            _zero(material)
            lease.close()
        finally:
            self.__finish("DISCARDED")

    def consume_into_private_sink(self, sink: _Sink) -> None:
        """Provide mutable bytes once to a synchronous trusted private sink.

        The sink must return ``None``.  Its buffer becomes all-zero immediately
        after it returns or raises, so a sink must complete its private copy
        during the callback.
        """

        if not callable(sink):
            raise _redacted_error(
                "INVALID_SINK", "Codex auth private sink must be callable"
            )
        material, lease = self.__detach("CONSUMING")
        sink_failed = False
        sink_returned_value = False
        caught: BaseException | None = None
        source_failure: tuple[str, str] | None = None
        sink_material: bytearray | None = None
        try:
            _replay_source_lease(lease)
            sink_material = bytearray(material)
            # Erase issuer-owned storage before invoking external code.  The
            # callback receives an independent mutable buffer, which is also
            # erased below even when the callback raises or re-enters.
            _zero(material)
            try:
                result = sink(sink_material)
                sink_returned_value = result is not None
                result = None
            except BaseException as exc:
                sink_failed = True
                caught = exc
        except BaseException as exc:
            if isinstance(exc, CodexStoredAuthSourceError):
                source_failure = (exc.reason_code, str(exc))
            else:
                source_failure = (
                    "SOURCE_REPLAY_FAILED",
                    "Codex auth source replay failed closed",
                )
            traceback.clear_frames(exc.__traceback__)
            exc.__traceback__ = None
            exc.__cause__ = None
            exc.__context__ = None
        finally:
            if caught is not None:
                traceback.clear_frames(caught.__traceback__)
                caught.__traceback__ = None
                caught.__cause__ = None
                caught.__context__ = None
            caught = None
            _zero(sink_material)
            _zero(material)
            lease.close()
            self.__finish("REJECTED" if source_failure else "CONSUMED")
        material = bytearray()
        sink_material = bytearray()
        lease = None
        if source_failure is not None:
            reason_code, message = source_failure
            source_failure = None
            raise _redacted_error(reason_code, message) from None
        if sink_failed:
            raise _redacted_error(
                "SINK_FAILED", "Codex auth private sink failed"
            ) from None
        if sink_returned_value:
            raise _redacted_error(
                "SINK_RETURNED_VALUE",
                "Codex auth private sink must not return credential material",
            ) from None


def _acquire_from_path_token(path_token: str) -> CodexStoredAuthCapability:
    with _STATE_LOCK:
        pending_path = _PATH_PENDING.get(path_token)
    if pending_path is None:
        raise _redacted_error(
            "INVALID_PATH_TOKEN", "Codex auth path authority is unavailable"
        )
    source_path, darwin_verifier = pending_path
    components = _exact_components(source_path)  # type: ignore[arg-type]
    source_path = None
    pending_path = None
    lease: _SourceLease | None = None
    material: bytearray | None = None
    issued = False
    try:
        lease = _open_source_lease(
            components,
            darwin_verifier=darwin_verifier,
        )
        darwin_verifier = None
        _replay_source_lease(lease)
        material = _read_bounded_material(lease.file_descriptor)
        _replay_source_lease(lease)
        if len(material) != lease.source_signature[5]:
            raise _redacted_error(
                "SOURCE_CHANGED", "Codex auth source byte count changed"
            )
        _validate_strict_json_object(material)
        _replay_source_lease(lease)
        issuance_id = secrets.token_hex(32)
        with _STATE_LOCK:
            _PENDING[issuance_id] = (material, lease)
        try:
            capability = CodexStoredAuthCapability(
                _issuance_id=issuance_id,
            )
        finally:
            with _STATE_LOCK:
                _PENDING.pop(issuance_id, None)
        issued = True
        return capability
    finally:
        if not issued:
            _zero(material)
            if lease is not None:
                lease.close()


def acquire_codex_stored_auth(
    source_path: str | os.PathLike[str],
    *,
    require_native_custody: bool = False,
    darwin_descriptor_security_verifier: (
        _DescriptorSecurityVerifier | None
    ) = None,
) -> CodexStoredAuthCapability:
    """Acquire an exact Darwin/Linux ``auth.json`` as a one-shot capability.

    ``require_native_custody=True`` is the explicit production boundary for
    callers that do not trust the hosting Python process.  It fails closed
    until an out-of-process compiled credential broker owns the material.  On
    Darwin, ``darwin_descriptor_security_verifier`` is also mandatory and
    must implement the descriptor-native contract above; pure Python exposes
    neither flistxattr(XATTR_SHOWCOMPRESSION) nor an ACL descriptor API.
    """

    path_token = secrets.token_hex(32)
    with _STATE_LOCK:
        _PATH_PENDING[path_token] = (
            source_path,
            darwin_descriptor_security_verifier,
        )
    source_path = None  # remove the raw path from this traceback-visible frame
    darwin_descriptor_security_verifier = None
    failure: tuple[str, str] | None = None
    capability: CodexStoredAuthCapability | None = None
    try:
        if require_native_custody:
            raise _redacted_error(
                "NATIVE_CUSTODY_REQUIRED",
                "Codex auth native custody is not available",
            )
        capability = _acquire_from_path_token(path_token)
    except BaseException as exc:
        if isinstance(exc, CodexStoredAuthSourceError):
            failure = (exc.reason_code, str(exc))
        else:
            failure = (
                "ACQUISITION_FAILED",
                "Codex auth acquisition failed closed",
            )
        traceback.clear_frames(exc.__traceback__)
        exc.__traceback__ = None
        exc.__cause__ = None
        exc.__context__ = None
    finally:
        with _STATE_LOCK:
            _PATH_PENDING.pop(path_token, None)
    path_token = ""
    if failure is not None:
        reason_code, message = failure
        failure = None
        rejected = _redacted_error(reason_code, message)
        rejected.__cause__ = None
        rejected.__context__ = None
        raise rejected from None
    if capability is None:
        raise _redacted_error(
            "ACQUISITION_FAILED", "Codex auth acquisition failed closed"
        ) from None
    return capability


__all__ = (
    "CodexStoredAuthCapability",
    "CodexStoredAuthSourceError",
    "DarwinDescriptorSecurityVerifier",
    "MAX_CODEX_AUTH_BYTES",
    "acquire_codex_stored_auth",
)
