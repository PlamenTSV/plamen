"""Stable bounded reads for untrusted scratchpad control artifacts."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import BinaryIO, Iterator, Mapping, Pattern


_WINDOWS_REPARSE_POINT = 0x400


class BoundedNamespaceCaptureError(ValueError):
    """A retained namespace was unsafe, ambiguous, or changed in flight."""


def _stable_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        int(value.st_mode),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", 0)),
        int(getattr(value, "st_dev", 0)),
        int(getattr(value, "st_ino", 0)),
        int(getattr(value, "st_nlink", 1)),
        int(getattr(value, "st_file_attributes", 0) or 0),
    )


def _directory_identity(value: os.stat_result) -> tuple[int, ...]:
    """Stable root identity excluding membership-driven metadata."""

    return (
        int(value.st_mode),
        int(getattr(value, "st_dev", 0)),
        int(getattr(value, "st_ino", 0)),
        int(getattr(value, "st_file_attributes", 0) or 0),
    )


def _require_real_regular(
    value: os.stat_result,
    *,
    label: str,
    limit: int,
    require_single_link: bool,
) -> None:
    attributes = int(getattr(value, "st_file_attributes", 0) or 0)
    if (
        not stat.S_ISREG(value.st_mode)
        or stat.S_ISLNK(value.st_mode)
        or attributes & _WINDOWS_REPARSE_POINT
    ):
        raise BoundedNamespaceCaptureError(
            f"namespace member must be a regular non-link: {label}"
        )
    if value.st_size < 0 or value.st_size > limit:
        raise BoundedNamespaceCaptureError(
            f"namespace member exceeds {limit} bytes: {label}"
        )
    if require_single_link and int(getattr(value, "st_nlink", 0) or 0) != 1:
        raise BoundedNamespaceCaptureError(
            f"namespace member must have exactly one link (nlink == 1): {label}"
        )


@dataclass(frozen=True)
class CapturedRegularFile:
    """One immutable byte view retained by an open file description."""

    name: str
    raw: bytes
    sha256: str
    size: int
    physical_identity: tuple[int, ...]


@dataclass
class RetainedNamespaceCapture:
    """Complete flat namespace plus handles held until the caller commits.

    The bytes are read exactly once.  Revalidation never reparses or rereads a
    source; it proves that the names and the pathname/handle identities still
    denote the captured objects.  On POSIX the retained file descriptions keep
    renamed objects inspectable, while the exact namespace comparison detects
    the rename.  On Windows the CRT handles are retained and the same identity
    and namespace checks apply; the subsequent PhaseIO commit supplies the
    second content-CAS check at the authority boundary.
    """

    root: Path
    pattern: Pattern[str]
    files: Mapping[str, CapturedRegularFile]
    namespace: tuple[str, ...]
    namespace_sha256: str
    total_size: int
    _root_identity: tuple[int, ...] = field(repr=False)
    _handles: dict[str, BinaryIO] = field(repr=False)
    _per_file_limit: int = field(repr=False)
    _require_single_link: bool = field(repr=False)
    _closed: bool = field(default=False, repr=False)

    def revalidate(self) -> None:
        if self._closed:
            raise BoundedNamespaceCaptureError("namespace capture is closed")
        try:
            root_row = self.root.lstat()
        except OSError as exc:
            raise BoundedNamespaceCaptureError(
                "namespace capture root changed during retention"
            ) from exc
        attributes = int(getattr(root_row, "st_file_attributes", 0) or 0)
        if (
            not stat.S_ISDIR(root_row.st_mode)
            or stat.S_ISLNK(root_row.st_mode)
            or attributes & _WINDOWS_REPARSE_POINT
            or _directory_identity(root_row) != self._root_identity
        ):
            raise BoundedNamespaceCaptureError(
                "namespace capture root identity drift"
            )
        try:
            names = tuple(sorted(
                (
                    entry.name
                    for entry in os.scandir(self.root)
                    if self.pattern.fullmatch(entry.name)
                ),
                key=lambda item: (item.casefold(), item),
            ))
        except OSError as exc:
            raise BoundedNamespaceCaptureError(
                "namespace enumeration changed during retention"
            ) from exc
        if names != self.namespace:
            raise BoundedNamespaceCaptureError(
                "namespace membership drift during retained capture"
            )
        for name in self.namespace:
            handle = self._handles.get(name)
            if handle is None or handle.closed:
                raise BoundedNamespaceCaptureError(
                    f"retained namespace handle missing: {name}"
                )
            try:
                path_row = (self.root / name).lstat()
                handle_row = os.fstat(handle.fileno())
            except OSError as exc:
                raise BoundedNamespaceCaptureError(
                    f"namespace member identity drift: {name}"
                ) from exc
            _require_real_regular(
                path_row,
                label=name,
                limit=self._per_file_limit,
                require_single_link=self._require_single_link,
            )
            _require_real_regular(
                handle_row,
                label=name,
                limit=self._per_file_limit,
                require_single_link=self._require_single_link,
            )
            expected = self.files[name].physical_identity
            if (
                _stable_identity(path_row) != expected
                or _stable_identity(handle_row) != expected
            ):
                raise BoundedNamespaceCaptureError(
                    f"namespace member changed during retained capture: {name}"
                )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for handle in self._handles.values():
            try:
                handle.close()
            except OSError:
                pass
        self._handles.clear()


@contextmanager
def retain_bounded_regular_namespace(
    root: Path,
    name_pattern: str | Pattern[str],
    *,
    per_file_limit: int,
    total_limit: int,
    max_members: int = 4096,
    require_single_link: bool = True,
) -> Iterator[RetainedNamespaceCapture]:
    """Capture one complete flat file namespace and retain every opened file.

    The caller must call ``capture.revalidate()`` after parsing and immediately
    before its transactional publication.  The context manager performs both
    an initial and a final revalidation as defense in depth.
    """

    candidate = Path(os.path.abspath(os.fspath(root)))
    pattern = re.compile(name_pattern) if isinstance(name_pattern, str) else name_pattern
    if not hasattr(pattern, "fullmatch"):
        raise TypeError("name_pattern must be a string or compiled regex")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in (per_file_limit, total_limit, max_members)
    ):
        raise ValueError("namespace bounds must be non-negative integers")
    root_row = candidate.lstat()
    attributes = int(getattr(root_row, "st_file_attributes", 0) or 0)
    if (
        not stat.S_ISDIR(root_row.st_mode)
        or stat.S_ISLNK(root_row.st_mode)
        or attributes & _WINDOWS_REPARSE_POINT
    ):
        raise BoundedNamespaceCaptureError(
            "namespace capture root must be a real directory"
        )
    root_identity = _directory_identity(root_row)
    handles: dict[str, BinaryIO] = {}
    captures: dict[str, CapturedRegularFile] = {}
    try:
        entries = [
            entry for entry in os.scandir(candidate)
            if pattern.fullmatch(entry.name)
        ]
        entries.sort(key=lambda entry: (entry.name.casefold(), entry.name))
        if len(entries) > max_members:
            raise BoundedNamespaceCaptureError(
                f"namespace exceeds {max_members} members"
            )
        folded = [entry.name.casefold() for entry in entries]
        if len(folded) != len(set(folded)):
            raise BoundedNamespaceCaptureError(
                "namespace contains a casefold name alias"
            )
        total = 0
        for entry in entries:
            name = entry.name
            if Path(name).name != name or not name.isascii():
                raise BoundedNamespaceCaptureError(
                    f"namespace member name is not canonical ASCII: {name!r}"
                )
            path_row = (candidate / name).lstat()
            _require_real_regular(
                path_row,
                label=name,
                limit=per_file_limit,
                require_single_link=require_single_link,
            )
            handle = (candidate / name).open("rb")
            handles[name] = handle
            handle_before = os.fstat(handle.fileno())
            _require_real_regular(
                handle_before,
                label=name,
                limit=per_file_limit,
                require_single_link=require_single_link,
            )
            raw = handle.read(per_file_limit + 1)
            handle_after = os.fstat(handle.fileno())
            if (
                len(raw) > per_file_limit
                or _stable_identity(path_row) != _stable_identity(handle_before)
                or _stable_identity(handle_before) != _stable_identity(handle_after)
                or len(raw) != handle_after.st_size
            ):
                raise BoundedNamespaceCaptureError(
                    f"namespace member changed during one-pass read: {name}"
                )
            total += len(raw)
            if total > total_limit:
                raise BoundedNamespaceCaptureError(
                    f"namespace exceeds {total_limit} total bytes"
                )
            captures[name] = CapturedRegularFile(
                name=name,
                raw=raw,
                sha256=hashlib.sha256(raw).hexdigest(),
                size=len(raw),
                physical_identity=_stable_identity(handle_after),
            )
        namespace = tuple(captures)
        namespace_raw = "\n".join(namespace).encode("ascii")
        capture = RetainedNamespaceCapture(
            root=candidate,
            pattern=pattern,
            files=dict(captures),
            namespace=namespace,
            namespace_sha256=hashlib.sha256(namespace_raw).hexdigest(),
            total_size=total,
            _root_identity=root_identity,
            _handles=handles,
            _per_file_limit=per_file_limit,
            _require_single_link=require_single_link,
        )
        capture.revalidate()
        try:
            yield capture
            capture.revalidate()
        finally:
            capture.close()
    except Exception:
        for handle in handles.values():
            try:
                handle.close()
            except OSError:
                pass
        raise


def read_bounded_regular_bytes(
    path: Path,
    limit: int,
    *,
    require_single_link: bool = False,
) -> bytes:
    """Read at most ``limit`` bytes from one stable non-link regular file."""

    target = Path(path)
    if not isinstance(limit, int) or limit < 0:
        raise ValueError("bounded read limit must be a non-negative integer")
    if not isinstance(require_single_link, bool):
        raise ValueError("require_single_link must be a boolean")

    def _require_safe_link_count(value: os.stat_result) -> None:
        if require_single_link and int(getattr(value, "st_nlink", 0) or 0) != 1:
            raise ValueError(
                f"artifact must have exactly one link (nlink == 1): {target.name}"
            )

    before = target.lstat()
    attributes = int(getattr(before, "st_file_attributes", 0) or 0)
    if stat.S_ISLNK(before.st_mode) or attributes & _WINDOWS_REPARSE_POINT:
        raise ValueError(f"artifact must not be a link or reparse point: {target.name}")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError(f"artifact is not a regular file: {target.name}")
    _require_safe_link_count(before)
    if before.st_size > limit:
        raise ValueError(f"artifact exceeds {limit} bytes: {target.name}")

    with target.open("rb") as stream:
        opened_before = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened_before.st_mode):
            raise ValueError(f"opened artifact is not regular: {target.name}")
        _require_safe_link_count(opened_before)
        if opened_before.st_size > limit:
            raise ValueError(f"artifact exceeds {limit} bytes: {target.name}")
        raw = stream.read(limit + 1)
        opened_after = os.fstat(stream.fileno())
        _require_safe_link_count(opened_after)
    after = target.lstat()
    _require_safe_link_count(after)

    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if (
        len(raw) > limit
        or any(
            getattr(before, field) != getattr(opened_before, field)
            or getattr(opened_before, field) != getattr(opened_after, field)
            or getattr(opened_after, field) != getattr(after, field)
            for field in stable_fields
        )
        or after.st_size != len(raw)
    ):
        raise ValueError(f"artifact changed during bounded read: {target.name}")
    return raw


__all__ = [
    "BoundedNamespaceCaptureError",
    "CapturedRegularFile",
    "RetainedNamespaceCapture",
    "read_bounded_regular_bytes",
    "retain_bounded_regular_namespace",
]
