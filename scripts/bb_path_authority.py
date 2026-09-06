"""Root-anchored immutable artifact authority for the public BB adapter."""
from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import unicodedata


_REPARSE = 0x400
_RESERVED = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CLOCK$",
        "CONIN$",
        "CONOUT$",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)
_FORBIDDEN = frozenset('<>:"\\|?*')
_WINDOWS_EXTENDED_PREFIX = "\\\\?\\"
_WINDOWS_DEVICE_PREFIX = "\\\\.\\"


class BBPathAuthorityError(OSError):
    pass


@dataclass(frozen=True)
class RootedPublication:
    relative_path: str
    sha256: str
    size: int
    status: str
    path: Path


def canonical_relative_name(relative: str) -> str:
    if (
        not isinstance(relative, str)
        or not relative
        or "\x00" in relative
        or relative.startswith("/")
        or "\\" in relative
        or unicodedata.normalize("NFC", relative) != relative
        or len(relative.encode("utf-8")) > 4096
        or any(char in _FORBIDDEN for char in relative)
        or any(ord(char) < 32 or ord(char) == 127 for char in relative)
    ):
        raise BBPathAuthorityError("artifact name is not portable canonical text")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or pure.as_posix() != relative:
        raise BBPathAuthorityError("artifact name is not canonical relative POSIX")
    for component in pure.parts:
        if (
            component in {"", ".", ".."}
            or component.endswith((" ", "."))
            or len(component.encode("utf-8")) > 255
            or component.split(".", 1)[0].upper() in _RESERVED
        ):
            raise BBPathAuthorityError(
                f"artifact component is unsafe: {component!r}"
            )
    return relative


def _absolute(path: str | os.PathLike[str]) -> Path:
    raw = os.fspath(path)
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or unicodedata.normalize("NFC", raw) != raw
    ):
        raise BBPathAuthorityError("authority path is not canonical text")
    if os.name == "nt" and raw.startswith(
        (_WINDOWS_EXTENDED_PREFIX, _WINDOWS_DEVICE_PREFIX)
    ):
        raise BBPathAuthorityError(
            "caller-supplied Windows device namespace paths are forbidden"
        )
    return Path(os.path.abspath(raw))


def _native(path: Path) -> Path:
    if os.name != "nt":
        return path
    raw = str(path)
    if raw.startswith(_WINDOWS_EXTENDED_PREFIX):
        return path
    if raw.startswith("\\\\"):
        raw = _WINDOWS_EXTENDED_PREFIX + "UNC\\" + raw[2:]
    else:
        raw = _WINDOWS_EXTENDED_PREFIX + raw
    return Path(raw)


def _lexical(path: Path) -> Path:
    raw = str(path)
    if os.name != "nt":
        return path
    unc_prefix = _WINDOWS_EXTENDED_PREFIX + "UNC\\"
    if raw.startswith(unc_prefix):
        return Path("\\\\" + raw[len(unc_prefix):])
    if raw.startswith(_WINDOWS_EXTENDED_PREFIX):
        return Path(raw[len(_WINDOWS_EXTENDED_PREFIX):])
    return path


def _resolved(path: Path) -> Path:
    return _lexical(_native(path).resolve(strict=True))


def _is_reparse(row: os.stat_result) -> bool:
    return bool(int(getattr(row, "st_file_attributes", 0)) & _REPARSE)


def _chain(path: Path):
    absolute = _absolute(path)
    cursor = Path(absolute.anchor)
    yield cursor
    for component in absolute.parts[1:]:
        cursor = cursor / component
        yield cursor


def _directory(path: Path, label: str) -> os.stat_result:
    try:
        native = _native(path)
        row = native.lstat()
    except OSError as exc:
        raise BBPathAuthorityError(f"{label} is unavailable: {exc}") from exc
    is_junction = getattr(native, "is_junction", None)
    if (
        native.is_symlink()
        or _is_reparse(row)
        or (callable(is_junction) and is_junction())
        or not stat.S_ISDIR(row.st_mode)
    ):
        raise BBPathAuthorityError(f"{label} is link/reparse-backed or non-directory")
    return row


def validate_directory_root(
    root: str | os.PathLike[str],
    *,
    label: str,
) -> Path:
    lexical = _absolute(root)
    for current in _chain(lexical):
        _directory(current, label)
    try:
        resolved = _resolved(lexical)
    except OSError as exc:
        raise BBPathAuthorityError(f"{label} cannot resolve: {exc}") from exc
    if not _native(resolved).is_dir():
        raise BBPathAuthorityError(f"{label} is not a directory")
    return lexical


def _ensure_parent(root: Path, relative: str, label: str) -> Path:
    root = validate_directory_root(root, label=label)
    parts = PurePosixPath(canonical_relative_name(relative)).parts
    cursor = root
    for component in parts[:-1]:
        cursor = cursor / component
        try:
            os.mkdir(_native(cursor), 0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise BBPathAuthorityError(
                f"{label} parent creation failed: {exc}"
            ) from exc
        _directory(cursor, label)
        if not _resolved(cursor).is_relative_to(
            _resolved(root)
        ):
            raise BBPathAuthorityError(f"{label} parent escapes root")
    return cursor


def _path(
    root: str | os.PathLike[str],
    relative: str,
    *,
    create_parents: bool,
    label: str,
) -> tuple[Path, Path]:
    canonical = canonical_relative_name(relative)
    root_path = validate_directory_root(root, label=label)
    if create_parents:
        parent = _ensure_parent(root_path, canonical, label)
    else:
        parent = root_path.joinpath(*PurePosixPath(canonical).parts[:-1])
        for current in _chain(parent):
            _directory(current, label)
    return parent / PurePosixPath(canonical).name, root_path


def read_rooted_bytes(
    root: str | os.PathLike[str],
    relative: str,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes <= 0
    ):
        raise BBPathAuthorityError("read ceiling is invalid")
    path, root_path = _path(
        root,
        relative,
        create_parents=False,
        label=label,
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(_native(path), flags)
    except OSError as exc:
        raise BBPathAuthorityError(f"{label} cannot open: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
            or before.st_size > max_bytes
        ):
            raise BBPathAuthorityError(
                f"{label} is not a bounded single-link regular file"
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        raise BBPathAuthorityError(f"{label} exceeds its size ceiling")
    native = _native(path)
    row = native.lstat()
    resolved = _resolved(path)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or (row.st_dev, row.st_ino) != (after.st_dev, after.st_ino)
        or native.is_symlink()
        or _is_reparse(row)
        or not resolved.is_relative_to(_resolved(root_path))
        or len(raw) != after.st_size
    ):
        raise BBPathAuthorityError(f"{label} identity/containment drifted")
    validate_directory_root(path.parent, label=f"{label} parent")
    return raw


def _fsync_parent(path: Path) -> None:
    try:
        descriptor = os.open(
            _native(path),
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
    except OSError as exc:
        if os.name == "nt" and exc.errno in {
            errno.EACCES,
            errno.EINVAL,
            errno.EISDIR,
            errno.EPERM,
        }:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_rooted_bytes(
    root: str | os.PathLike[str],
    relative: str,
    raw: bytes,
    *,
    label: str,
    replay_exact: bool,
    max_bytes: int,
) -> RootedPublication:
    if not isinstance(raw, bytes) or len(raw) > max_bytes:
        raise BBPathAuthorityError(f"{label} payload is invalid or oversized")
    canonical = canonical_relative_name(relative)
    path, root_path = _path(
        root,
        canonical,
        create_parents=True,
        label=label,
    )
    digest = hashlib.sha256(raw).hexdigest()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    created = False
    descriptor = -1
    opened: os.stat_result | None = None
    try:
        try:
            descriptor = os.open(_native(path), flags, 0o600)
            created = True
        except FileExistsError:
            if not replay_exact:
                raise BBPathAuthorityError(f"{label} already exists")
            observed = read_rooted_bytes(
                root_path,
                canonical,
                label=label,
                max_bytes=max_bytes,
            )
            if observed != raw:
                raise BBPathAuthorityError(f"{label} exact replay differs")
            return RootedPublication(
                canonical, digest, len(raw), "EXACT_REPLAY", path
            )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or int(getattr(opened, "st_nlink", 1)) != 1
        ):
            raise BBPathAuthorityError(f"{label} opened unsafe object")
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise BBPathAuthorityError(f"{label} short write")
            offset += written
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = -1
        native = _native(path)
        row = native.lstat()
        if (
            (opened.st_dev, opened.st_ino)
            != (after.st_dev, after.st_ino)
            or after.st_size != len(raw)
            or (row.st_dev, row.st_ino) != (after.st_dev, after.st_ino)
            or native.is_symlink()
            or _is_reparse(row)
            or not _resolved(path).is_relative_to(
                _resolved(root_path)
            )
        ):
            raise BBPathAuthorityError(
                f"{label} post-open identity/containment drifted"
            )
        if (
            read_rooted_bytes(
                root_path,
                canonical,
                label=label,
                max_bytes=max_bytes,
            )
            != raw
        ):
            raise BBPathAuthorityError(f"{label} post-write bytes drifted")
        _fsync_parent(path.parent)
        return RootedPublication(canonical, digest, len(raw), "CREATED", path)
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created and opened is not None:
            try:
                native = _native(path)
                row = native.lstat()
                if (
                    not native.is_symlink()
                    and not _is_reparse(row)
                    and (row.st_dev, row.st_ino)
                    == (opened.st_dev, opened.st_ino)
                ):
                    native.unlink()
                    _fsync_parent(path.parent)
            except OSError:
                pass
        raise


__all__ = [
    "BBPathAuthorityError",
    "RootedPublication",
    "canonical_relative_name",
    "publish_rooted_bytes",
    "read_rooted_bytes",
    "validate_directory_root",
]
