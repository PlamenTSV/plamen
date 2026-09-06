"""Compare-only collector for the quarantined release fixture roster.

This utility can prove that the current, hash-pinned fixture sources collect
to the committed node roster.  It never writes or replaces that authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import unicodedata
from typing import Any, Callable


REPO = Path(__file__).resolve().parent.parent
MANIFEST = Path(__file__).with_name(
    "release_fast_lane_fixture_governance_manifest.json"
)
PREEXISTING_EXACT_RED_IGNORE = (
    "review_fixtures/program_facts_runtime_gate3/g3_00_schema_crosscheck/"
    "test_crosscheck_schema_contracts_stdlib_v1_transport_totality_"
    "amendment_red.py"
)
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SOURCES = 256
MAX_NODES = 20_000
_REPARSE_POINT = 0x400
_OPEN_RACE_HOOK: Callable[[Path, str], None] | None = None


class CollectionAuthorityError(RuntimeError):
    """The committed input authority or fresh collection is not exact."""


def _reject_duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionAuthorityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _portable_relative(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CollectionAuthorityError(f"{label} must be a non-empty string")
    if value != unicodedata.normalize("NFC", value):
        raise CollectionAuthorityError(f"{label} is not NFC-normalized")
    if "\\" in value or "\x00" in value or "\r" in value or "\n" in value:
        raise CollectionAuthorityError(f"{label} is not canonical POSIX text")
    raw_parts = value.split("/")
    path = PurePosixPath(value)
    if path.is_absolute() or path.anchor or any(
        part in ("", ".", "..") for part in raw_parts
    ):
        raise CollectionAuthorityError(f"{label} is not repository-relative")
    if ":" in path.parts[0]:
        raise CollectionAuthorityError(f"{label} has an absolute drive prefix")
    return value


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
    )


def _windows_final_handle_path(descriptor: int) -> str:
    import ctypes
    import msvcrt

    handle = msvcrt.get_osfhandle(descriptor)
    function = ctypes.windll.kernel32.GetFinalPathNameByHandleW
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    function.restype = ctypes.c_uint32
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = function(handle, buffer, capacity, 0)
    if not length or length >= capacity:
        raise CollectionAuthorityError("opened source final path is unavailable")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.abspath(value)


@dataclass
class _WindowsDirectoryPin:
    path: Path
    handle: int
    identity: tuple[int, ...]
    final_path: str


@dataclass
class _BoundSource:
    descriptor: int
    root: Path
    parts: tuple[str, ...]
    expected_infos: list[os.stat_result]
    posix_directories: list[int] = field(default_factory=list)
    windows_directories: list[_WindowsDirectoryPin] = field(default_factory=list)

    def replay(self) -> None:
        paths = [self.root]
        current = self.root
        for part in self.parts[:-1]:
            current = current / part
            paths.append(current)
        if os.name == "posix":
            if len(paths) != len(self.posix_directories):
                raise CollectionAuthorityError("retained POSIX ancestry is incomplete")
            for path, descriptor, expected in zip(
                paths, self.posix_directories, self.expected_infos[:-1]
            ):
                if not (
                    _same_identity(os.fstat(descriptor), expected)
                    and _same_identity(path.lstat(), expected)
                ):
                    raise CollectionAuthorityError(
                        "retained POSIX ancestor identity changed"
                    )
            return
        if len(paths) != len(self.windows_directories):
            raise CollectionAuthorityError("retained Windows ancestry is incomplete")
        for path, pin in zip(paths, self.windows_directories):
            identity, final_path = _windows_directory_handle_state(pin.handle)
            if (
                identity != pin.identity
                or final_path != pin.final_path
                or not _windows_stat_matches_directory_handle(path.lstat(), identity)
            ):
                raise CollectionAuthorityError(
                    "retained Windows ancestor identity changed"
                )

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1
        for descriptor in reversed(self.posix_directories):
            os.close(descriptor)
        self.posix_directories.clear()
        if self.windows_directories:
            import ctypes

            close_handle = ctypes.WinDLL(
                "kernel32", use_last_error=True
            ).CloseHandle
            close_handle.argtypes = (ctypes.c_void_p,)
            close_handle.restype = ctypes.c_int
            for pin in reversed(self.windows_directories):
                close_handle(pin.handle)
            self.windows_directories.clear()


def _windows_directory_handle_state(handle: int) -> tuple[tuple[int, ...], str]:
    import ctypes
    from ctypes import wintypes

    class _FILETIME(ctypes.Structure):
        _fields_ = (
            ("low", wintypes.DWORD),
            ("high", wintypes.DWORD),
        )

    class _INFO(ctypes.Structure):
        _fields_ = (
            ("attributes", wintypes.DWORD),
            ("creation", _FILETIME),
            ("access", _FILETIME),
            ("write", _FILETIME),
            ("volume", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        )

    information = _INFO()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = kernel.GetFileInformationByHandle
    function.argtypes = (wintypes.HANDLE, ctypes.POINTER(_INFO))
    function.restype = wintypes.BOOL
    if not function(handle, ctypes.byref(information)):
        raise CollectionAuthorityError("retained Windows directory info unavailable")
    attributes = int(information.attributes)
    if not attributes & 0x10 or attributes & _REPARSE_POINT:
        raise CollectionAuthorityError("retained Windows ancestor is not a directory")
    identity = (
        attributes,
        int(information.volume),
        int(information.index_high),
        int(information.index_low),
        int(information.links),
    )
    function = kernel.GetFinalPathNameByHandleW
    function.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    function.restype = wintypes.DWORD
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = function(handle, buffer, capacity, 0)
    if not length or length >= capacity:
        raise CollectionAuthorityError("retained Windows directory path unavailable")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return identity, os.path.normcase(os.path.abspath(value))


def _windows_stat_matches_directory_handle(
    row: os.stat_result, identity: tuple[int, ...]
) -> bool:
    file_index = (identity[2] << 32) | identity[3]
    return (
        stat.S_ISDIR(row.st_mode)
        and not stat.S_ISLNK(row.st_mode)
        and not _is_reparse(row)
        and int(getattr(row, "st_ino", 0)) == file_index
        and int(getattr(row, "st_nlink", 1)) == identity[4]
    )


def _open_windows_directory(path: Path, expected: os.stat_result) -> _WindowsDirectoryPin:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x80000000,
        0x00000001 | 0x00000002,
        None,
        3,
        0x00200000 | 0x02000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise CollectionAuthorityError("Windows ancestor no-delete handle denied")
    try:
        identity, final_path = _windows_directory_handle_state(handle)
        expected_path = os.path.normcase(os.path.abspath(path))
        if (
            final_path != expected_path
            or not _windows_stat_matches_directory_handle(expected, identity)
        ):
            raise CollectionAuthorityError("Windows ancestor handle identity changed")
        return _WindowsDirectoryPin(path, handle, identity, final_path)
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def _open_bound_source(
    root: Path,
    parts: tuple[str, ...],
    expected_infos: list[os.stat_result],
) -> _BoundSource:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if os.name != "posix":
        bound = _BoundSource(-1, root, parts, expected_infos)
        try:
            paths = [root]
            current = root
            for part in parts[:-1]:
                current = current / part
                paths.append(current)
            for path, expected_info in zip(paths, expected_infos[:-1]):
                bound.windows_directories.append(
                    _open_windows_directory(path, expected_info)
                )
            descriptor = os.open(root.joinpath(*parts), flags)
            expected = os.path.normcase(os.path.abspath(root.joinpath(*parts)))
            observed = os.path.normcase(_windows_final_handle_path(descriptor))
            if observed != expected:
                os.close(descriptor)
                raise CollectionAuthorityError("opened source escaped its expected path")
            bound.descriptor = descriptor
            bound.replay()
            return bound
        except BaseException:
            bound.close()
            raise

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root, directory_flags)
    bound = _BoundSource(-1, root, parts, expected_infos, [directory])
    try:
        if not _same_identity(os.fstat(directory), expected_infos[0]):
            raise CollectionAuthorityError("repository root changed before handle open")
        for index, part in enumerate(parts[:-1], start=1):
            child = os.open(part, directory_flags, dir_fd=directory)
            try:
                if not _same_identity(os.fstat(child), expected_infos[index]):
                    raise CollectionAuthorityError(
                        "authority ancestor changed before handle-relative open"
                    )
            except BaseException:
                os.close(child)
                raise
            directory = child
            bound.posix_directories.append(child)
        descriptor = os.open(parts[-1], flags, dir_fd=directory)
        if not _same_identity(os.fstat(descriptor), expected_infos[-1]):
            os.close(descriptor)
            raise CollectionAuthorityError(
                "source changed before handle-relative open"
            )
        bound.descriptor = descriptor
        bound.replay()
        return bound
    except BaseException:
        bound.close()
        raise


def _stable_regular_bytes(
    root: Path,
    relative: str,
    *,
    expected_sha256: str | None,
    maximum: int,
) -> bytes:
    relative = _portable_relative(relative, label="source path")
    current = root
    root_info = current.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or _is_reparse(root_info):
        raise CollectionAuthorityError("repository root is not an unaliased directory")
    parts = PurePosixPath(relative).parts
    component_infos = [root_info]
    for index, part in enumerate(parts):
        with os.scandir(current) as entries:
            matches = []
            for ordinal, entry in enumerate(entries, start=1):
                if ordinal > 20_000:
                    raise CollectionAuthorityError(
                        f"authority directory entry bound exceeded: {relative}"
                    )
                if entry.name.casefold() == part.casefold():
                    matches.append(entry.name)
        if matches != [part]:
            raise CollectionAuthorityError(
                f"authority path spelling is not exact: {relative}"
            )
        current = current / matches[0]
        info = current.lstat()
        component_infos.append(info)
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info):
            raise CollectionAuthorityError(f"aliased authority path: {relative}")
        if index + 1 < len(parts) and not stat.S_ISDIR(info.st_mode):
            raise CollectionAuthorityError(f"non-directory authority ancestor: {relative}")
    before = component_infos[-1]
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise CollectionAuthorityError(
            f"source is not a bounded single-link regular file: {relative}"
        )
    if _OPEN_RACE_HOOK is not None:
        _OPEN_RACE_HOOK(root, relative)
    bound = _open_bound_source(root, parts, component_infos)
    descriptor = bound.descriptor
    try:
        opened = os.fstat(descriptor)
        if not _same_identity(before, opened):
            raise CollectionAuthorityError(f"source changed before read: {relative}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise CollectionAuthorityError(f"source exceeds byte bound: {relative}")
        replay = os.fstat(descriptor)
        after = current.lstat()
        root_after = root.lstat()
        bound.replay()
        if not (
            _same_identity(root_info, root_after)
            and _same_identity(before, replay)
            and _same_identity(before, after)
        ):
            raise CollectionAuthorityError(f"source changed during read: {relative}")
    finally:
        bound.close()
    raw = b"".join(chunks)
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise CollectionAuthorityError(f"source hash drift: {relative}")
    return raw


def load_manifest(root: Path = REPO, manifest: Path = MANIFEST) -> dict[str, Any]:
    try:
        relative = manifest.relative_to(root).as_posix()
    except ValueError as exc:
        raise CollectionAuthorityError("manifest must be repository-relative") from exc
    raw = _stable_regular_bytes(
        root,
        relative,
        expected_sha256=None,
        maximum=MAX_MANIFEST_BYTES,
    )
    if b"\r" in raw or not raw.endswith(b"\n"):
        raise CollectionAuthorityError("manifest must use exact LF termination")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectionAuthorityError("manifest must be strict UTF-8") from exc
    payload = json.loads(text, object_pairs_hook=_reject_duplicate_key)
    if not isinstance(payload, dict):
        raise CollectionAuthorityError("manifest root must be an object")
    if payload.get("schema_version") != "plamen.release_fast_lane_fixture_governance.v2":
        raise CollectionAuthorityError("unsupported fixture-governance schema")
    return payload


def validate_sources(payload: dict[str, Any], root: Path = REPO) -> list[str]:
    rows = payload.get("files")
    if not isinstance(rows, list) or not (1 <= len(rows) <= MAX_SOURCES):
        raise CollectionAuthorityError("source roster is missing or exceeds its bound")
    paths: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            raise CollectionAuthorityError("source roster row is not an object")
        path = _portable_relative(row.get("path"), label="source path")
        digest = row.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or any(
            char not in "0123456789abcdef" for char in digest
        ):
            raise CollectionAuthorityError(f"invalid source hash: {path}")
        if not path.startswith(("Temp/", "review_fixtures/")):
            raise CollectionAuthorityError(f"foreign source root: {path}")
        _stable_regular_bytes(
            root,
            path,
            expected_sha256=digest,
            maximum=MAX_SOURCE_BYTES,
        )
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise CollectionAuthorityError("duplicate source path")
    if len({path.casefold() for path in paths}) != len(paths):
        raise CollectionAuthorityError("case-colliding source path")
    return sorted(paths)


def canonical_roster(nodes: list[str]) -> bytes:
    if not (1 <= len(nodes) <= MAX_NODES):
        raise CollectionAuthorityError("node roster is missing or exceeds its bound")
    normalized: list[str] = []
    for node in nodes:
        if not isinstance(node, str) or "::" not in node:
            raise CollectionAuthorityError("malformed node identity")
        if node != unicodedata.normalize("NFC", node):
            raise CollectionAuthorityError("node identity is not NFC-normalized")
        if "\\" in node or "\r" in node or "\n" in node or "\x00" in node:
            raise CollectionAuthorityError("node identity is not canonical text")
        source, _separator, suffix = node.partition("::")
        _portable_relative(source, label="node source")
        if not suffix:
            raise CollectionAuthorityError("node identity has an empty pytest suffix")
        normalized.append(node)
    if len(normalized) != len(set(normalized)):
        raise CollectionAuthorityError("duplicate node identity")
    return ("\n".join(normalized) + "\n").encode("utf-8")


def validate_committed_roster(
    payload: dict[str, Any], source_paths: list[str]
) -> tuple[list[str], str]:
    authority = payload.get("authority", {}).get("fixture_node_roster")
    if not isinstance(authority, dict):
        raise CollectionAuthorityError("fixture node authority is missing")
    nodes = authority.get("nodes")
    if not isinstance(nodes, list):
        raise CollectionAuthorityError("fixture node roster is not a list")
    raw = canonical_roster(nodes)
    digest = hashlib.sha256(raw).hexdigest()
    if authority.get("node_count") != len(nodes) or authority.get("sha256") != digest:
        raise CollectionAuthorityError("fixture node authority count/hash mismatch")
    sources = set(source_paths)
    represented: set[str] = set()
    for node in nodes:
        source = node.split("::", 1)[0]
        if source not in sources:
            raise CollectionAuthorityError(f"foreign node source: {source}")
        represented.add(source)
    if represented != sources:
        raise CollectionAuthorityError("fixture node roster omits a governed source")
    return nodes, digest


def _fixed_subprocess_environment() -> dict[str, str]:
    retained = (
        "COMSPEC",
        "PATHEXT",
        "SystemRoot",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    )
    environment = {key: os.environ[key] for key in retained if key in os.environ}
    environment.update(
        {
            "NO_COLOR": "1",
            "PYTHONHASHSEED": "0",
            "PYTEST_ADDOPTS": "",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TERM": "dumb",
        }
    )
    return environment


def collect_nodes(root: Path, source_paths: list[str]) -> list[str]:
    command = [
        sys.executable,
        "-I",
        "-B",
        "-c",
        (
            "import runpy,sys;"
            f"sys.path.insert(0,{str(root)!r});"
            "runpy.run_module('pytest',run_name='__main__')"
        ),
        "--collect-only",
        "-q",
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        "-m",
        "not integration",
        f"--ignore={PREEXISTING_EXACT_RED_IGNORE}",
        *source_paths,
    ]
    completed = subprocess.run(
        command,
        cwd=root,
        env=_fixed_subprocess_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
    )
    if completed.returncode != 0:
        raise CollectionAuthorityError(
            f"fixture collection failed with exit {completed.returncode}: "
            + (
                completed.stderr + b"\n" + completed.stdout
            ).decode("utf-8", errors="replace")[-4000:]
        )
    if completed.stderr:
        raise CollectionAuthorityError("fixture collection emitted stderr")
    try:
        lines = completed.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise CollectionAuthorityError("fixture collection output is not UTF-8") from exc
    prefixes = tuple(f"{path}::" for path in source_paths)
    nodes = [line for line in lines if line.startswith(prefixes)]
    canonical_roster(nodes)
    return nodes


def compare(root: Path = REPO, manifest: Path = MANIFEST) -> dict[str, Any]:
    payload = load_manifest(root, manifest)
    source_paths = validate_sources(payload, root)
    committed, committed_sha = validate_committed_roster(payload, source_paths)
    fresh = collect_nodes(root, source_paths)
    fresh_sha = hashlib.sha256(canonical_roster(fresh)).hexdigest()
    return {
        "match": fresh == committed,
        "source_count": len(source_paths),
        "committed_count": len(committed),
        "committed_sha256": committed_sha,
        "fresh_count": len(fresh),
        "fresh_sha256": fresh_sha,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO)
    arguments = parser.parse_args(argv)
    root = arguments.root.absolute()
    manifest = root / "scripts" / MANIFEST.name
    try:
        result = compare(root, manifest)
    except (CollectionAuthorityError, OSError, ValueError) as exc:
        print(f"fixture roster comparison failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
