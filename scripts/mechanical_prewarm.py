"""Bounded POSIX-V2 compiler-cache prewarm workspace publication.

This is deliberately a reduced-isolation compatibility facility.  It proves
neither network denial, native containment/WER, nor escaped-descendant absence.
It copies the complete admitted build root (apart from this exact session's
scratchpad subtree) so build-system inputs are not silently omitted.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
from types import MappingProxyType
from typing import Any, Callable, Mapping, NoReturn
import uuid
import weakref
import re
import threading
import sys
import tomllib

import audit_snapshot as _snapshot
import posix_v2_compat_runtime as _compat
from supply_chain_gate import project_supply_chain_admission


_MAX_FILES = 100_000
_MAX_BYTES = 8 * 1024 * 1024 * 1024
_MAX_DEPTH = 64
_MAX_NAME_BYTES = 255
_STDOUT_LIMIT = 32 * 1024 * 1024
_STDERR_LIMIT = 8 * 1024 * 1024
_WORKSPACE_PARENT = "compat-prewarm-workspaces"
_DRIVER_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")


class CompatPrewarmError(RuntimeError):
    """A prewarm admission or publication failed closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _fail(code: str, message: str, cause: BaseException | None = None) -> NoReturn:
    error = CompatPrewarmError(code, message)
    if cause is None:
        raise error
    raise error from cause


@dataclass(frozen=True)
class CompatPrewarmResult:
    workspace_root: Path
    ok: bool
    note: str
    terminals: tuple[_compat.PosixV2CompatMechanicalPoCTerminal, ...]
    cargo_ok: bool | None = None
    cargo_note: str | None = None


@dataclass(frozen=True)
class CompatCandidateProcess:
    """Completed-process projection backed by one compatibility terminal."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    terminal_status: str
    receipt_relative_path: str
    request_sha256: str
    duration_seconds: float


@dataclass(frozen=True)
class _Cached:
    session_ref: weakref.ReferenceType[Any]
    source_root: Path
    source_identity_sha256: str
    source_census_sha256: str
    snapshot_sha256: str
    admission_sha256: str
    input_key: str
    request_sha256s: tuple[str, ...]
    result: CompatPrewarmResult


@dataclass
class _Reservation:
    session_ref: weakref.ReferenceType[Any]
    workspace_root: Path
    work_record: Mapping[str, Any]
    work_sha256: str
    request_sha256s: list[str]
    supply_chain_admission: object
    audit_snapshot: Mapping[str, Any]
    assert_snapshot_current: Callable[[], None]
    source_mutation: tuple[int, ...]


_CACHE: dict[tuple[int, str], _Cached] = {}
_LINEAGE: dict[tuple[int, str, str, str], str] = {}
_WORK_LOCK = threading.RLock()
_SESSION_REFS: dict[int, weakref.ReferenceType[Any]] = {}
_RESERVATIONS: dict[tuple[int, str], _Reservation] = {}
_ACTIVE_CALLS: set[tuple[int, str]] = set()


def _forget_session(session_id: int) -> None:
    with _WORK_LOCK:
        _SESSION_REFS.pop(session_id, None)
        for key in tuple(_CACHE):
            if key[0] == session_id:
                _CACHE.pop(key, None)
        for key in tuple(_LINEAGE):
            if key[0] == session_id:
                _LINEAGE.pop(key, None)
        for key in tuple(_RESERVATIONS):
            if key[0] == session_id:
                _RESERVATIONS.pop(key, None)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False,
                          sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        _fail("CANONICAL_INPUT", "prewarm input is not canonical JSON", exc)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mapping_sha(value: Mapping[str, Any]) -> str:
    return _sha(_canonical(dict(value)))


def _snapshot_copy(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        _fail("AUDIT_SNAPSHOT", "audit snapshot is absent or malformed")
    try:
        copied = json.loads(_snapshot._canonical_json(dict(value)))
    except (ValueError, TypeError) as exc:
        _fail("AUDIT_SNAPSHOT", "audit snapshot cannot be copied canonically", exc)
    if not _snapshot._valid_snapshot(copied):
        _fail("AUDIT_SNAPSHOT", "audit snapshot structure is invalid")
    unsigned = {"schema": copied["schema"], "components": copied["components"]}
    if copied["snapshot_digest"] != _sha(_snapshot._canonical_json(unsigned)):
        _fail("AUDIT_SNAPSHOT", "audit snapshot canonical digest differs")
    return copied


def _assert_snapshot(callback: Callable[[], None], expected: Mapping[str, Any]) -> None:
    if not callable(callback):
        _fail("AUDIT_SNAPSHOT", "snapshot-current callback is not callable")
    try:
        callback()
    except CompatPrewarmError:
        raise
    except Exception as exc:
        _fail("AUDIT_SNAPSHOT", "audit snapshot drift guard rejected the launch", exc)
    # Re-validate the retained immutable value as well.  The callback owns
    # fresh recomputation; neither a checkpoint nor a self-hash substitutes.
    current = _snapshot_copy(expected)
    if current["snapshot_digest"] != expected["snapshot_digest"]:
        _fail("AUDIT_SNAPSHOT", "retained audit snapshot changed")


def _identity(path: Path) -> tuple[dict[str, int], tuple[int, ...]]:
    try:
        lexical = path.lstat()
        resolved = path.resolve(strict=True)
        observed = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        _fail("SOURCE_ROOT", "source build root is unavailable", exc)
    if stat.S_ISLNK(lexical.st_mode) or not stat.S_ISDIR(observed.st_mode):
        _fail("SOURCE_ROOT", "source build root is aliased or not a directory")
    runner = {"device": int(observed.st_dev), "inode": int(observed.st_ino),
              "mode": int(observed.st_mode), "owner": int(observed.st_uid),
              "group": int(observed.st_gid)}
    mutation = (int(observed.st_dev), int(observed.st_ino), int(observed.st_mode),
                int(observed.st_uid), int(observed.st_gid), int(observed.st_size),
                int(observed.st_mtime_ns), int(observed.st_ctime_ns))
    return runner, mutation


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _admit_source(raw: Path, session: Any) -> tuple[Path, dict[str, int], tuple[int, ...]]:
    if not isinstance(raw, Path) or not raw.is_absolute():
        _fail("SOURCE_ROOT", "source_build_root must be an absolute Path")
    identity, mutation = _identity(raw)
    source = raw.resolve(strict=True)
    if raw != source:
        _fail("SOURCE_ROOT", "source build root must be canonical and unaliased")
    if (not _within(source, session.project_root)
            or _within(source, session.scratchpad)):
        _fail("SOURCE_ROOT", "source build root is outside the session project")
    cursor = raw
    while True:
        try:
            if stat.S_ISLNK(cursor.lstat().st_mode):
                _fail("SOURCE_ROOT", "source build root has an aliased ancestor")
        except OSError as exc:
            _fail("SOURCE_ROOT", "source ancestor is unavailable", exc)
        if cursor == session.project_root:
            break
        parent = cursor.parent
        if parent == cursor or not _within(parent.resolve(strict=True), session.project_root):
            _fail("SOURCE_ROOT", "source ancestry does not reach the session project")
        cursor = parent
    return source, identity, mutation


def _file_digest(path: Path, expected: os.stat_result, output_fd: int | None = None) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size < 0 or before.st_size > _MAX_BYTES):
            _fail("SOURCE_MEMBER", f"unsupported source member: {path}")
        remaining = int(before.st_size)
        digest = hashlib.sha256()
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                _fail("SOURCE_DRIFT", f"source member shortened: {path}")
            digest.update(chunk)
            if output_fd is not None:
                view = memoryview(chunk)
                while view:
                    written = os.write(output_fd, view)
                    if written <= 0:
                        _fail("PUBLICATION", f"short copy write for source member: {path}")
                    view = view[written:]
            remaining -= len(chunk)
        after = os.fstat(fd)
        stable = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                            s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if os.read(fd, 1) or stable(before) != stable(after) or stable(before) != stable(expected):
            _fail("SOURCE_DRIFT", f"source member changed during capture: {path}")
        return digest.hexdigest()
    except CompatPrewarmError:
        raise
    except OSError as exc:
        _fail("SOURCE_MEMBER", f"source member cannot be read safely: {path}", exc)
    finally:
        if "fd" in locals():
            os.close(fd)


def _walk_error(exc: OSError) -> NoReturn:
    _fail("TREE_WALK", "tree walk could not observe the complete denominator", exc)


def _census(root: Path, excluded: Path | None) -> tuple[str, int, int]:
    rows: list[dict[str, object]] = []
    total = 0
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False,
                                        onerror=_walk_error):
        here = Path(current)
        depth = len(here.relative_to(root).parts)
        if depth > _MAX_DEPTH:
            _fail("SOURCE_BOUND", "source tree exceeds maximum depth")
        dirs.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        retained: list[str] = []
        for name in dirs:
            child = here / name
            observed = child.lstat()
            if len(os.fsencode(name)) > _MAX_NAME_BYTES or stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                _fail("SOURCE_MEMBER", f"unsupported directory member: {child}")
            if excluded is not None and child == excluded:
                continue
            retained.append(name)
        dirs[:] = retained
        for name in files:
            child = here / name
            observed = child.lstat()
            if len(os.fsencode(name)) > _MAX_NAME_BYTES or not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
                _fail("SOURCE_MEMBER", f"unsupported file member: {child}")
            digest = _file_digest(child, observed)
            total += int(observed.st_size)
            if len(rows) >= _MAX_FILES or total > _MAX_BYTES:
                _fail("SOURCE_BOUND", "source tree exceeds file or byte bound")
            rows.append({"path": child.relative_to(root).as_posix(),
                         "size": int(observed.st_size), "sha256": digest,
                         "executable": bool(observed.st_mode & 0o111)})
    return _sha(_canonical(rows)), len(rows), total


def _copy_tree(source: Path, stage: Path, excluded: Path) -> tuple[str, int, int]:
    stage.mkdir(mode=0o700)
    rows: list[dict[str, object]] = []
    total = 0
    for current, dirs, files in os.walk(source, topdown=True, followlinks=False,
                                        onerror=_walk_error):
        here = Path(current)
        relative = here.relative_to(source)
        if len(relative.parts) > _MAX_DEPTH:
            _fail("SOURCE_BOUND", "copy tree exceeds maximum depth")
        target = stage / relative
        dirs.sort(key=os.fsencode)
        files.sort(key=os.fsencode)
        retained: list[str] = []
        for name in dirs:
            child = here / name
            observed = child.lstat()
            if len(os.fsencode(name)) > _MAX_NAME_BYTES or stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode):
                _fail("SOURCE_MEMBER", f"unsupported directory member: {child}")
            if child == excluded:
                continue
            (target / name).mkdir(mode=stat.S_IMODE(observed.st_mode) & 0o777)
            retained.append(name)
        dirs[:] = retained
        for name in files:
            child = here / name
            observed = child.lstat()
            if len(os.fsencode(name)) > _MAX_NAME_BYTES or not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1:
                _fail("SOURCE_MEMBER", f"unsupported file member: {child}")
            total += int(observed.st_size)
            if len(rows) >= _MAX_FILES or total > _MAX_BYTES:
                _fail("SOURCE_BOUND", "copy tree exceeds file or byte bound")
            destination = target / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            safe_mode = stat.S_IMODE(observed.st_mode) & 0o777
            fd = os.open(destination, flags, safe_mode)
            try:
                digest = _file_digest(child, observed, fd)
                os.fchmod(fd, safe_mode)
            finally:
                os.close(fd)
            copied = destination.lstat()
            copied_digest = _file_digest(destination, copied)
            if copied_digest != digest:
                _fail("COPY_DRIFT", f"copied member differs: {child}")
            rows.append({"path": child.relative_to(source).as_posix(),
                         "size": int(observed.st_size), "sha256": digest,
                         "executable": bool(safe_mode & 0o111)})
    return _sha(_canonical(rows)), len(rows), total


def _manifest(language: str, root: Path) -> str:
    candidates = {
        "evm": ("foundry.toml",),
        "solana": ("Cargo.toml",), "soroban": ("Cargo.toml",),
        "l1_rust": ("Cargo.toml",), "rust": ("Cargo.toml",),
        "aptos": ("Move.toml",), "sui": ("Move.toml",),
        "cairo": ("Scarb.toml",),
        "go": ("go.mod",), "l1_go": ("go.mod",),
    }.get(language, ("Cargo.toml", "foundry.toml", "Move.toml", "Scarb.toml"))
    present = [name for name in candidates if (root / name).is_file()]
    if len(present) != 1:
        _fail("BUILD_MANIFEST", "exactly one supported root build manifest is required")
    return present[0]


def _lang_cfg(registry: dict, language: str) -> dict:
    if type(registry) is not dict:
        _fail("REGISTRY", "registry must be a plain dictionary")
    languages = registry.get("languages")
    value = languages.get(language) if isinstance(languages, dict) else registry.get(language)
    return value if isinstance(value, dict) else {}


def _select_solc(source: Path, language: str, session: Any) -> dict[str, Any] | None:
    """Capture an explicit default-profile compiler without invoking a shim.

    SVM prefers an existing ~/.svm, otherwise the platform data directory.
    This is local byte/identity admission, not compiler-release provenance.
    Unpinned auto-detection remains Forge's responsibility and stays offline.
    """
    if language != "evm":
        return None
    manifest = source / "foundry.toml"
    binding = _compat._poc_file_binding(
        manifest, label="compiler selection manifest", maximum=_compat._MAX_PHASE_IO_OUTPUT_BYTES)
    fd = os.open(manifest, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(_compat._MAX_PHASE_IO_OUTPUT_BYTES + 1)
    if len(raw) != binding["size"] or _sha(raw) != binding["sha256"]:
        _fail("SOLC_SELECTION", "compiler selection manifest changed")
    try:
        profile = tomllib.loads(raw.decode("utf-8")).get("profile", {}).get("default", {})
    except (UnicodeError, ValueError, AttributeError) as exc:
        _fail("SOLC_SELECTION", "default compiler profile is malformed", exc)
    if not isinstance(profile, dict):
        _fail("SOLC_SELECTION", "default compiler profile is not a table")
    selectors = [profile[key] for key in ("solc", "solc_version", "solc-version") if key in profile]
    if not selectors:
        return None
    if any(type(value) is not str or not value.strip() for value in selectors):
        _fail("SOLC_SELECTION", "compiler selection must be a nonempty string")
    if len(set(selectors)) != 1:
        _fail("SOLC_SELECTION", "conflicting default compiler selectors")
    selector = selectors[0]
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", selector):
        home = Path.home()
        legacy = home / ".svm"
        if sys.platform == "darwin":
            data = home / "Library/Application Support"
        else:
            data = Path(os.environ.get("XDG_DATA_HOME") or home / ".local/share")
        if not data.is_absolute():
            _fail("SOLC_SELECTION", "compiler data root must be absolute")
        cache = legacy if legacy.exists() or not data.exists() else data / "svm"
        candidate = cache / selector / f"solc-{selector}"
    else:
        candidate = Path(selector)
        if not candidate.is_absolute():
            _fail("SOLC_SELECTION", "relative/custom compiler commands are not admitted")
    try:
        selected = candidate.resolve(strict=True)
    except OSError as exc:
        _fail("SOLC_UNAVAILABLE", f"selected compiler {selector!r} is not installed; offline prewarm will not download it", exc)
    if _within(selected, session.project_root) or _within(selected, session.scratchpad):
        _fail("SOLC_SELECTION", "selected compiler is target-controlled")
    observed = _compat._poc_file_binding(
        selected, label="selected native solc", maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    with selected.open("rb") as stream:
        magic = stream.read(4)
    if magic not in {b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                     b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                     b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}:
        _fail("SOLC_SELECTION", "selected compiler is not a native binary; scripts/shims are not invoked")
    if not os.access(selected, os.X_OK):
        _fail("SOLC_SELECTION", "selected compiler is not executable")
    return {"selector": selector, "source_path": os.fspath(selected),
            "source_binding": observed,
            "workspace_relative_path": ".prewarm-home/.plamen-solc/solc"}


def _stage_solc(selection: Mapping[str, Any] | None, stage: Path) -> None:
    if selection is None:
        return
    source = Path(selection["source_path"])
    destination = stage / selection["workspace_relative_path"]
    destination.parent.mkdir(mode=0o700)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
    try:
        digest = _file_digest(source, source.lstat(), fd)
        os.fchmod(fd, 0o500)
    finally:
        os.close(fd)
    current = _compat._poc_file_binding(source, label="retained native solc",
                                       maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    copied = _compat._poc_file_binding(destination, label="staged native solc",
                                      maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    if (current != selection["source_binding"] or digest != current["sha256"]
            or copied["sha256"] != digest or copied["size"] != current["size"]):
        _fail("SOLC_DRIFT", "selected compiler changed during workspace capture")


def _check_solc(selection: Mapping[str, Any] | None, workspace: Path,
                workspace_binding: Mapping[str, Any] | None) -> None:
    if selection is None:
        return
    current = _compat._poc_file_binding(Path(selection["source_path"]),
        label="retained native solc", maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    copied = _compat._poc_file_binding(workspace / selection["workspace_relative_path"],
        label="workspace native solc", maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    if current != selection["source_binding"] or copied != workspace_binding:
        _fail("SOLC_DRIFT", "admitted compiler source or workspace copy changed")


def _commands(language: str, registry: dict) -> tuple[list[str], list[str] | None]:
    cfg = _lang_cfg(registry, language)
    if language == "evm":
        primary = ["forge", "build"]
    else:
        raw = str(cfg.get("build_command") or "").strip()
        if not raw:
            _fail("BUILD_COMMAND", f"no build_command for {language!r}")
        try:
            primary = shlex.split(raw, posix=True)
        except ValueError as exc:
            _fail("BUILD_COMMAND", "build_command has malformed POSIX quoting", exc)
        if not primary:
            _fail("BUILD_COMMAND", "build_command is empty")
    cargo = None
    if language in {"solana", "soroban", "l1_rust"}:
        try:
            cargo = shlex.split(str(cfg.get("test_prewarm_command") or
                                    "cargo test --no-run").strip(), posix=True)
        except ValueError as exc:
            _fail("BUILD_COMMAND", "test_prewarm_command has malformed POSIX quoting", exc)
        if not cargo:
            _fail("BUILD_COMMAND", "test_prewarm_command is empty")
    return primary, cargo


def _resolve_command(command: list[str], session: Any) -> tuple[list[str], dict[str, Any], tuple[str, ...]]:
    if not command:
        _fail("EXECUTABLE", "compiler command is empty")
    ambient = os.environ.get("PATH")
    if not ambient:
        _fail("EXECUTABLE", "driver PATH is absent")
    safe_dirs: list[str] = []
    for raw in ambient.split(os.pathsep):
        if not raw or not Path(raw).is_absolute():
            _fail("EXECUTABLE", "driver PATH contains an empty or relative member")
        try:
            member = Path(raw).resolve(strict=True)
        except OSError as exc:
            _fail("EXECUTABLE", "driver PATH member is unavailable", exc)
        if not member.is_dir() or _within(member, session.project_root) or _within(member, session.scratchpad):
            _fail("EXECUTABLE", "driver PATH contains an unsafe member")
        rendered = os.fspath(member)
        if rendered not in safe_dirs:
            safe_dirs.append(rendered)
    search = os.pathsep.join(safe_dirs)
    located = command[0] if os.path.isabs(command[0]) else shutil.which(command[0], path=search)
    if not located:
        _fail("EXECUTABLE", f"compiler executable is unavailable: {command[0]}")
    executable = Path(located).resolve(strict=True)
    if _within(executable, session.project_root) or _within(executable, session.scratchpad):
        _fail("EXECUTABLE", "resolved compiler is target-controlled")
    binding = _compat._poc_file_binding(executable, label="prewarm executable",
                                        maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    if not os.access(executable, os.X_OK):
        _fail("EXECUTABLE", "compiler executable is not executable")
    return [os.fspath(executable), *command[1:]], binding, tuple(safe_dirs)


def _terminal_outcome(session: object, terminal: object) -> tuple[bool, str]:
    raw = _compat.project_posix_v2_compat_mechanical_poc_terminal(session, terminal)
    payload = json.loads(raw)
    ok = payload["status"] == "COMPLETED" and payload["returncode"] == 0
    if ok:
        return True, "warm ok (rc=0; reduced POSIX-V2 isolation)"
    stdout, stderr = _compat.project_posix_v2_compat_mechanical_poc_streams(
        session, terminal)
    def tail(raw_stream: bytes) -> str:
        return raw_stream[-2048:].decode("utf-8", errors="replace").replace("\x00", "�")
    return False, (
        f"prewarm {payload['status'].lower()} rc={payload['returncode']} "
        f"stdout_complete={payload['stdout_observation_complete']} "
        f"stderr_complete={payload['stderr_observation_complete']} "
        f"stdout_tail={tail(stdout)!r} stderr_tail={tail(stderr)!r} "
        "(authenticated bounded streams; cache retained; reduced POSIX-V2 isolation)"
    )


def _run_compat_prewarm(*, session_authority: object, source_build_root: Path,
                       language: str, registry: dict, driver_identity: str,
                       audit_snapshot: Mapping[str, Any],
                       assert_snapshot_current: Callable[[], None],
                       supply_chain_admission: object,
                       timeout_seconds: int) -> CompatPrewarmResult:
    """Publish a bounded full-root copy and run one or two PREWARM_BUILD attempts."""
    try:
        session = _compat._session_record(session_authority)
    except Exception as exc:
        _fail("SESSION_AUTHORITY", "live compatibility session is required", exc)
    session_id = id(session_authority)
    if session_id not in _SESSION_REFS:
        _SESSION_REFS[session_id] = weakref.ref(
            session_authority, lambda _ref, identifier=session_id: _forget_session(identifier))
    if type(language) is not str or not language or type(driver_identity) is not str or _DRIVER_ID_RE.fullmatch(driver_identity) is None:
        _fail("IDENTITY", "language must be non-empty and driver identity must be sha256:<64hex>")
    if type(timeout_seconds) is not int or isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 86_400:
        _fail("TIMEOUT", "timeout_seconds is outside 1..86400")
    snapshot = _snapshot_copy(audit_snapshot)
    snapshot_language = snapshot["components"]["source_scope"]["language"]
    accepted_snapshot_languages = {"l1_rust": "rust", "l1_go": "go"}
    if snapshot_language not in {language, accepted_snapshot_languages.get(language)}:
        _fail("AUDIT_SNAPSHOT", "snapshot language differs from prewarm language")
    source, source_identity, source_mutation = _admit_source(source_build_root, session)
    _assert_snapshot(assert_snapshot_current, snapshot)
    try:
        admission = dict(project_supply_chain_admission(
            supply_chain_admission, posix_compat_session=session_authority))
    except Exception as exc:
        _fail("SUPPLY_CHAIN_ADMISSION", "live supply-chain admission rejected", exc)
    if Path(str(admission.get("scan_root", ""))).resolve(strict=False) != source:
        _fail("SUPPLY_CHAIN_ADMISSION", "admission belongs to another build root")
    source_sha, _, _ = _census(source, session.scratchpad)
    if _identity(source)[1] != source_mutation:
        _fail("SOURCE_DRIFT", "source build root identity changed during admission")
    manifest = _manifest(language, source)
    solc_selection = _select_solc(source, language, session)
    primary_cmd, cargo_cmd = _commands(language, registry)
    resolved_primary, primary_exe, primary_path = _resolve_command(primary_cmd, session)
    resolved_cargo = cargo_exe = None
    if cargo_cmd is not None:
        resolved_cargo, cargo_exe, cargo_path = _resolve_command(cargo_cmd, session)
    else:
        cargo_path = ()
    input_record = {
        "schema": "plamen.compat_prewarm_inputs.v1",
        "session_binding_sha256": session.binding["session_binding_sha256"],
        "source_root": os.fspath(source),
        "source_root_identity_sha256": _mapping_sha(source_identity),
        "source_census_sha256": source_sha,
        "audit_snapshot_sha256": snapshot["snapshot_digest"],
        "audit_source_scope_sha256": snapshot["components"]["source_scope"]["digest"],
        "supply_chain_admission_sha256": admission["admission_sha256"],
        "driver_identity": driver_identity, "language": language,
        "registry_sha256": _sha(_canonical(registry)), "manifest": manifest,
        "commands": [resolved_primary] + ([] if resolved_cargo is None else [resolved_cargo]),
        "executables": [dict(primary_exe)] + ([] if cargo_exe is None else [dict(cargo_exe)]),
        "selected_driver_path": list(dict.fromkeys((*primary_path, *cargo_path))),
        "timeout_seconds": timeout_seconds,
        "secondary_compiler": solc_selection,
    }
    input_key = _sha(_canonical(input_record))
    cache_key = (session_id, input_key)
    lineage_key = (session_id, os.fspath(source), language, driver_identity)
    committed_input = _LINEAGE.get(lineage_key)
    if committed_input is not None and committed_input != input_key:
        _fail("REPLAY_INPUT_DRIFT", "committed prewarm inputs changed in the live session")
    prior = _CACHE.get(cache_key)
    if prior is not None:
        if prior.session_ref() is not session_authority:
            _fail("REPLAY", "cached prewarm belongs to an expired session")
        _assert_snapshot(assert_snapshot_current, snapshot)
        project_supply_chain_admission(supply_chain_admission,
                                       posix_compat_session=session_authority)
        if _census(source, session.scratchpad)[0] != source_sha:
            _fail("SOURCE_DRIFT", "source changed since committed prewarm")
        if _mapping_sha(_identity(source)[0]) != prior.source_identity_sha256:
            _fail("SOURCE_DRIFT", "source root identity changed since committed prewarm")
        for terminal in prior.result.terminals:
            _compat.project_posix_v2_compat_mechanical_poc_terminal(session_authority, terminal)
        last_payload = json.loads(
            _compat.project_posix_v2_compat_mechanical_poc_terminal(
                session_authority, prior.result.terminals[-1]))
        current_workspace, current_workspace_identity = _compat._safe_directory(
            prior.result.workspace_root, "retained prewarm workspace")
        retained_work = _RESERVATIONS.get(cache_key)
        if retained_work is None:
            _fail("REPLAY", "retained work context is unavailable")
        if (current_workspace != prior.result.workspace_root
                or _mapping_sha(current_workspace_identity)
                != retained_work.work_record["workspace_root_identity_sha256"]
                or _compat._poc_tree_digest(current_workspace)[0]
                != last_payload["workspace_post_tree_sha256"]):
            _fail("WORKSPACE_DRIFT", "retained prewarm workspace changed before replay")
        _check_solc(solc_selection, current_workspace,
                    retained_work.work_record["secondary_compiler_workspace_binding"])
        return prior.result
    reservation = _RESERVATIONS.get(cache_key)
    if reservation is not None:
        if reservation.session_ref() is not session_authority:
            _fail("REPLAY", "reserved prewarm belongs to an expired session")
        _fail("INCOMPLETE_WORK", "the exact process-local prewarm was reserved but did not publish a return value; it will not be relaunched")

    parent = session.scratchpad / _WORKSPACE_PARENT
    parent.mkdir(mode=0o700, exist_ok=True)
    _compat._safe_directory(parent, "prewarm workspace parent")
    nonce = uuid.uuid4().hex
    stage = parent / f".stage-{nonce}"
    final = parent / f"workspace-{nonce}"
    copied_sha, copied_files, copied_bytes = _copy_tree(source, stage, session.scratchpad)
    if (copied_sha, copied_files, copied_bytes) != _census(source, session.scratchpad):
        _fail("COPY_DRIFT", "staged census differs from selected source census")
    staged_sha, staged_files, staged_bytes = _census(stage, None)
    if (staged_sha, staged_files, staged_bytes) != (copied_sha, copied_files, copied_bytes):
        _fail("COPY_DRIFT", "staged workspace bytes differ from copied census")
    if _census(source, session.scratchpad)[0] != source_sha:
        _fail("SOURCE_DRIFT", "source changed across workspace capture")
    if _identity(source)[1] != source_mutation:
        _fail("SOURCE_DRIFT", "source root identity changed across workspace capture")
    for name in (".prewarm-home", ".prewarm-tmp", ".prewarm-cache", ".cargo-home"):
        (stage / name).mkdir(mode=0o700)
    _stage_solc(solc_selection, stage)
    try:
        os.rename(stage, final)
    except OSError as exc:
        _fail("PUBLICATION", "atomic workspace publication failed; staging retained", exc)
    workspace_identity, _workspace_mutation = _identity(final)
    workspace_tree, _, _ = _compat._poc_tree_digest(final)
    solc_workspace_binding = None
    if solc_selection is not None:
        solc_workspace_binding = _compat._poc_file_binding(
            final / solc_selection["workspace_relative_path"], label="published native solc",
            maximum=_compat._POC_MAX_EXECUTABLE_BYTES)
    subject = _compat._poc_file_binding(final / manifest, label="prewarm build manifest",
                                        maximum=_compat._MAX_PHASE_IO_OUTPUT_BYTES)
    path_members: list[str] = []
    for command in ([resolved_primary] + ([] if resolved_cargo is None else [resolved_cargo])):
        directory = os.fspath(Path(command[0]).parent)
        if directory not in path_members:
            path_members.append(directory)
    for directory in (*primary_path, *cargo_path):
        if directory not in path_members:
            path_members.append(directory)
    environment = {
        "PATH": os.pathsep.join(path_members), "HOME": os.fspath(final / ".prewarm-home"),
        "TMPDIR": os.fspath(final / ".prewarm-tmp"),
        "XDG_CACHE_HOME": os.fspath(final / ".prewarm-cache"),
        "CARGO_HOME": os.fspath(final / ".cargo-home"), "CI": "1",
        "FOUNDRY_OFFLINE": "true", "CARGO_NET_OFFLINE": "true",
    }
    if solc_selection is not None:
        environment["FOUNDRY_SOLC"] = os.fspath(final / solc_selection["workspace_relative_path"])
    work_record = dict(input_record)
    work_record.update({"workspace_root": os.fspath(final),
                        "workspace_root_identity_sha256": _mapping_sha(workspace_identity),
                        "workspace_pre_tree_sha256": workspace_tree,
                        "selected_manifest_binding": dict(subject),
                        "environment": environment,
                        "secondary_compiler_workspace_binding": solc_workspace_binding,
                        "limits": {"stdout": _STDOUT_LIMIT, "stderr": _STDERR_LIMIT},
                        "reduced_isolation": True, "network_denial_proven": False,
                        "native_broker_authority": False, "wer_authority": False})
    work_sha = _sha(_canonical(work_record))
    reservation = _Reservation(
        weakref.ref(session_authority), final,
        MappingProxyType(dict(work_record)), work_sha, [],
        supply_chain_admission, MappingProxyType(dict(snapshot)),
        assert_snapshot_current, source_mutation,
    )
    _RESERVATIONS[cache_key] = reservation
    _LINEAGE[lineage_key] = input_key

    def launch(command: list[str], executable: Mapping[str, Any], attempt: int) -> object:
        _assert_snapshot(assert_snapshot_current, snapshot)
        _check_solc(solc_selection, final, solc_workspace_binding)
        current_admission = project_supply_chain_admission(
            supply_chain_admission, posix_compat_session=session_authority)
        if current_admission["admission_sha256"] != admission["admission_sha256"]:
            _fail("SUPPLY_CHAIN_ADMISSION", "admission changed before launch")
        if _census(source, session.scratchpad)[0] != source_sha:
            _fail("SOURCE_DRIFT", "source changed before compiler launch")
        if _identity(source)[1] != source_mutation:
            _fail("SOURCE_DRIFT", "source root identity changed before compiler launch")
        request = {
            "schema": _compat.POC_REQUEST_SCHEMA, "request_sha256": "",
            "session_binding_sha256": session.binding["session_binding_sha256"],
            "run_id": session.binding["run_id"], "purpose": "PREWARM_BUILD",
            "work_unit_id": "prewarm-" + work_sha[:48], "finding_id": None,
            "constituent_id": None, "attempt_number": attempt,
            "work_authority_sha256": work_sha, "policy_sha256": None,
            "verifier_receipt_sha256": None,
            "supply_chain_admission_sha256": admission["admission_sha256"],
            "audit_snapshot_sha256": snapshot["snapshot_digest"],
            "source_census_sha256": source_sha, "source_build_root": os.fspath(source),
            "source_build_root_identity_sha256": _mapping_sha(source_identity),
            "workspace_root": os.fspath(final),
            "workspace_root_identity_sha256": _mapping_sha(workspace_identity),
            "workspace_pre_tree_sha256": workspace_tree,
            "subject_kind": "BUILD_MANIFEST", "subject_relative_path": manifest,
            "subject_sha256": subject["sha256"],
            "subject_size": subject["size"], "test_function": None,
            "tool_id": Path(command[0]).name, "executable_path": command[0],
            "executable_sha256": executable["sha256"], "executable_size": executable["size"],
            "argv": command, "cwd_relative_path": ".", "environment": environment,
            "timeout_seconds": timeout_seconds, "stdout_limit_bytes": _STDOUT_LIMIT,
            "stderr_limit_bytes": _STDERR_LIMIT, "expected_outputs": [],
            "offline_intent": True,
        }
        unsigned = dict(request)
        unsigned.pop("request_sha256")
        request["request_sha256"] = _mapping_sha(unsigned)
        reservation.request_sha256s.append(request["request_sha256"])
        terminal = _compat.execute_posix_v2_compat_mechanical_poc(
            session_authority=session_authority, request_bytes=_canonical(request))
        _assert_snapshot(assert_snapshot_current, snapshot)
        _check_solc(solc_selection, final, solc_workspace_binding)
        project_supply_chain_admission(
            supply_chain_admission, posix_compat_session=session_authority)
        if (_census(source, session.scratchpad)[0] != source_sha
                or _identity(source)[1] != source_mutation):
            _fail("SOURCE_DRIFT", "source changed during compiler execution")
        return terminal

    terminals: list[Any] = []
    primary_terminal = launch(resolved_primary, primary_exe, 1)
    terminals.append(primary_terminal)
    ok, note = _terminal_outcome(session_authority, primary_terminal)
    primary_request_sha = json.loads(
        _compat.project_posix_v2_compat_mechanical_poc_terminal(
            session_authority, primary_terminal))["request_sha256"]
    cargo_ok: bool | None = None
    cargo_note: str | None = None
    partial = CompatPrewarmResult(final, ok, note, tuple(terminals), None, None)
    _CACHE[cache_key] = _Cached(weakref.ref(session_authority), source,
                                _mapping_sha(source_identity), source_sha,
                                snapshot["snapshot_digest"], admission["admission_sha256"],
                                input_key, (primary_request_sha,), partial)
    _LINEAGE[lineage_key] = input_key
    if resolved_cargo is not None and cargo_exe is not None:
        # The first attempt mutates the workspace, so bind the second request
        # to its actual current pre-tree rather than recycling stale metadata.
        workspace_tree, _, _ = _compat._poc_tree_digest(final)
        try:
            cargo_terminal = launch(resolved_cargo, cargo_exe, 2)
        except BaseException as exc:
            failed = CompatPrewarmResult(
                final, ok, note, tuple(terminals), False,
                f"cargo test-target prewarm incomplete: {type(exc).__name__}: {exc}")
            _CACHE[cache_key] = _Cached(
                weakref.ref(session_authority), source,
                _mapping_sha(source_identity), source_sha,
                snapshot["snapshot_digest"], admission["admission_sha256"],
                input_key, tuple(reservation.request_sha256s), failed)
            raise
        terminals.append(cargo_terminal)
        cargo_ok, cargo_note = _terminal_outcome(session_authority, cargo_terminal)
        cargo_request_sha = json.loads(
            _compat.project_posix_v2_compat_mechanical_poc_terminal(
                session_authority, cargo_terminal))["request_sha256"]
    else:
        cargo_request_sha = None
    result = CompatPrewarmResult(final, ok, note, tuple(terminals), cargo_ok, cargo_note)
    _CACHE[cache_key] = _Cached(weakref.ref(session_authority), source,
                                _mapping_sha(source_identity), source_sha,
                                snapshot["snapshot_digest"], admission["admission_sha256"],
                                input_key, ((primary_request_sha,) if cargo_request_sha is None
                                            else (primary_request_sha, cargo_request_sha)), result)
    _LINEAGE[lineage_key] = input_key
    return result


def run_compat_prewarm(*, session_authority: object, source_build_root: Path,
                       language: str, registry: dict, driver_identity: str,
                       audit_snapshot: Mapping[str, Any],
                       assert_snapshot_current: Callable[[], None],
                       supply_chain_admission: object,
                       timeout_seconds: int) -> CompatPrewarmResult:
    """Serialize publication/execution and replay a process-local retained work."""
    with _WORK_LOCK:
        active_key = (id(session_authority), os.fspath(source_build_root))
        if active_key in _ACTIVE_CALLS:
            _fail("REENTRANT_WORK", "the same session/source prewarm is already active")
        _ACTIVE_CALLS.add(active_key)
        try:
            return _run_compat_prewarm(
                session_authority=session_authority,
                source_build_root=source_build_root,
                language=language,
                registry=registry,
                driver_identity=driver_identity,
                audit_snapshot=audit_snapshot,
                assert_snapshot_current=assert_snapshot_current,
                supply_chain_admission=supply_chain_admission,
                timeout_seconds=timeout_seconds,
            )
        finally:
            _ACTIVE_CALLS.discard(active_key)


def _candidate_reservation(
    session_authority: object,
    prewarm: CompatPrewarmResult,
) -> _Reservation:
    """Recover only the live reservation that issued this exact result object."""

    matches: list[_Reservation] = []
    for key, cached in _CACHE.items():
        if (
            key[0] == id(session_authority)
            and cached.session_ref() is session_authority
            and cached.result is prewarm
        ):
            reservation = _RESERVATIONS.get(key)
            if (
                reservation is not None
                and reservation.session_ref() is session_authority
                and reservation.workspace_root == prewarm.workspace_root
            ):
                matches.append(reservation)
    if len(matches) != 1:
        _fail(
            "CANDIDATE_PREWARM_AUTHORITY",
            "exact live prewarm reservation is absent or ambiguous",
        )
    return matches[0]


def run_compat_candidate(
    *,
    session_authority: object,
    prewarm: CompatPrewarmResult,
    verify_path: Path,
    finding_id: str,
    constituent_id: str,
    test_relative_path: str,
    test_function: str | None,
    argv: list[str] | tuple[str, ...],
    environment_overrides: Mapping[str, str] | None,
    timeout_seconds: float,
    attempt_number: int = 1,
) -> CompatCandidateProcess:
    """Execute one materialized candidate through the typed Seatbelt boundary.

    The candidate reuses the exact admitted compiler workspace and live
    supply-chain/snapshot authorities from ``run_compat_prewarm``.  Arbitrary
    caller environments are never inherited; only the two per-test semantic
    overrides currently derived by the mechanical verifier are admitted.
    """

    with _WORK_LOCK:
        reservation = _candidate_reservation(session_authority, prewarm)
        session = _compat._session_record(session_authority)
        record = dict(reservation.work_record)
        snapshot = dict(reservation.audit_snapshot)
        _assert_snapshot(reservation.assert_snapshot_current, snapshot)
        admission = dict(project_supply_chain_admission(
            reservation.supply_chain_admission,
            posix_compat_session=session_authority,
        ))
        if admission.get("admission_sha256") != record.get(
            "supply_chain_admission_sha256"
        ):
            _fail("CANDIDATE_SUPPLY_CHAIN", "live admission changed")
        source = Path(str(record["source_root"]))
        if (
            _census(source, session.scratchpad)[0]
            != record.get("source_census_sha256")
            or _identity(source)[1] != reservation.source_mutation
        ):
            _fail("CANDIDATE_SOURCE_DRIFT", "source changed after prewarm")
        workspace, workspace_identity = _compat._safe_directory(
            prewarm.workspace_root, "candidate prewarm workspace"
        )
        if workspace != reservation.workspace_root:
            _fail("CANDIDATE_WORKSPACE", "prewarm workspace identity changed")

        command = [str(item) for item in argv]
        if not command or any(not item or "\x00" in item for item in command):
            _fail("CANDIDATE_COMMAND", "candidate argv is empty or malformed")
        environment = dict(record.get("environment") or {})
        allowed_overrides = {"CGO_ENABLED", "FOUNDRY_PROFILE"}
        for name, value in dict(environment_overrides or {}).items():
            if name not in allowed_overrides:
                _fail(
                    "CANDIDATE_ENVIRONMENT",
                    f"unregistered semantic environment override {name!r}",
                )
            if type(value) is not str or not value or "\x00" in value:
                _fail("CANDIDATE_ENVIRONMENT", f"invalid override {name!r}")
            environment[name] = value
        located = (
            command[0]
            if os.path.isabs(command[0])
            else shutil.which(command[0], path=environment.get("PATH"))
        )
        if not located:
            _fail("CANDIDATE_EXECUTABLE", f"tool is unavailable: {command[0]}")
        executable = Path(located).resolve(strict=True)
        if _within(executable, session.project_root) or _within(
            executable, session.scratchpad
        ):
            _fail("CANDIDATE_EXECUTABLE", "resolved tool is target-controlled")
        command[0] = os.fspath(executable)
        executable_binding = _compat._poc_file_binding(
            executable,
            label="candidate executable",
            maximum=_compat._POC_MAX_EXECUTABLE_BYTES,
        )
        subject_path = workspace / test_relative_path
        subject_binding = _compat._poc_file_binding(
            subject_path,
            label="materialized candidate source",
            maximum=_compat._MAX_PHASE_IO_OUTPUT_BYTES,
        )
        verify_raw = Path(verify_path).read_bytes()
        if not verify_raw:
            _fail("CANDIDATE_VERIFIER", "verifier artifact is empty")
        receipt_path = Path(verify_path).with_name(
            f"{Path(verify_path).stem}.receipt.json"
        )
        try:
            from queue_work_items import VerifierOutputReceipt

            receipt_raw = receipt_path.read_bytes()
            receipt = VerifierOutputReceipt.from_json(
                receipt_raw.decode("utf-8", errors="strict")
            )
        except Exception as exc:
            _fail(
                "CANDIDATE_VERIFIER",
                "canonical verifier receipt is unavailable or malformed",
                exc,
            )
        if (
            receipt_raw != receipt.to_json().encode("utf-8")
            or receipt.identity.work_item_id != finding_id
            or receipt.identity.expected_output_file != Path(verify_path).name
            or len(verify_raw) < receipt.output_size_bytes
            or _sha(verify_raw[: receipt.output_size_bytes])
            != receipt.output_sha256
        ):
            _fail(
                "CANDIDATE_VERIFIER",
                "verifier receipt does not bind the candidate source artifact",
            )
        policy = {
            "schema": "plamen.compat_candidate_policy.v1",
            "argv": command,
            "finding_id": finding_id,
            "source_sha256": subject_binding["sha256"],
            "test_function": test_function,
            "test_relative_path": test_relative_path,
            "timeout_seconds": float(timeout_seconds),
            "verifier_output_sha256": receipt.output_sha256,
        }
        policy_sha256 = _sha(_canonical(policy))
        verifier_receipt_sha256 = _sha(receipt_raw)
        workspace_tree, _workspace_files, _workspace_bytes = (
            _compat._poc_tree_digest(workspace)
        )
        work_authority = {
            "schema": "plamen.compat_candidate_work_authority.v1",
            "prewarm_work_sha256": reservation.work_sha256,
            "policy_sha256": policy_sha256,
            "verifier_receipt_sha256": verifier_receipt_sha256,
            "workspace_pre_tree_sha256": workspace_tree,
        }
        request = {
            "schema": _compat.POC_REQUEST_SCHEMA,
            "request_sha256": "",
            "session_binding_sha256": session.binding[
                "session_binding_sha256"
            ],
            "run_id": session.binding["run_id"],
            "purpose": "CANDIDATE_POC",
            "work_unit_id": f"verify.{finding_id}",
            "finding_id": finding_id,
            "constituent_id": constituent_id,
            "attempt_number": int(attempt_number),
            "work_authority_sha256": _sha(_canonical(work_authority)),
            "policy_sha256": policy_sha256,
            "verifier_receipt_sha256": verifier_receipt_sha256,
            "supply_chain_admission_sha256": admission["admission_sha256"],
            "audit_snapshot_sha256": snapshot["snapshot_digest"],
            "source_census_sha256": record["source_census_sha256"],
            "source_build_root": os.fspath(source),
            "source_build_root_identity_sha256": record[
                "source_root_identity_sha256"
            ],
            "workspace_root": os.fspath(workspace),
            "workspace_root_identity_sha256": _mapping_sha(workspace_identity),
            "workspace_pre_tree_sha256": workspace_tree,
            "subject_kind": "GENERATED_POC_TEST",
            "subject_relative_path": test_relative_path,
            "subject_sha256": subject_binding["sha256"],
            "subject_size": subject_binding["size"],
            "test_function": test_function,
            "tool_id": executable.name,
            "executable_path": os.fspath(executable),
            "executable_sha256": executable_binding["sha256"],
            "executable_size": executable_binding["size"],
            "argv": command,
            "cwd_relative_path": ".",
            "environment": environment,
            "timeout_seconds": float(timeout_seconds),
            "stdout_limit_bytes": _STDOUT_LIMIT,
            "stderr_limit_bytes": _STDERR_LIMIT,
            "expected_outputs": [],
            "offline_intent": True,
        }
        unsigned = dict(request)
        unsigned.pop("request_sha256")
        request["request_sha256"] = _mapping_sha(unsigned)
        reservation.request_sha256s.append(request["request_sha256"])
        terminal = _compat.execute_posix_v2_compat_mechanical_poc(
            session_authority=session_authority,
            request_bytes=_canonical(request),
        )
        terminal_raw = _compat.project_posix_v2_compat_mechanical_poc_terminal(
            session_authority, terminal
        )
        terminal_value = json.loads(terminal_raw)
        stdout_raw, stderr_raw = _compat.project_posix_v2_compat_mechanical_poc_streams(
            session_authority, terminal
        )
        _assert_snapshot(reservation.assert_snapshot_current, snapshot)
        current_admission = dict(project_supply_chain_admission(
            reservation.supply_chain_admission,
            posix_compat_session=session_authority,
        ))
        if current_admission.get("admission_sha256") != admission.get(
            "admission_sha256"
        ):
            _fail("CANDIDATE_SUPPLY_CHAIN", "admission changed during execution")
        if (
            _census(source, session.scratchpad)[0]
            != record.get("source_census_sha256")
            or _identity(source)[1] != reservation.source_mutation
        ):
            _fail("CANDIDATE_SOURCE_DRIFT", "source changed during execution")
        if not (
            terminal_value.get("actual_tool_started") is True
            and terminal_value.get("actual_tool_completion_observed") is True
            and terminal_value.get("status") in {"COMPLETED", "NONZERO_EXIT"}
            and isinstance(terminal_value.get("returncode"), int)
        ):
            if terminal_value.get("status") == "TIMED_OUT":
                import subprocess

                raise subprocess.TimeoutExpired(
                    command,
                    timeout_seconds,
                    output=stdout_raw,
                    stderr=stderr_raw,
                )
            _fail(
                "CANDIDATE_TERMINAL",
                "compatibility terminal did not authenticate completed tool execution "
                f"({terminal_value.get('status')})",
            )
        return CompatCandidateProcess(
            args=tuple(command),
            returncode=int(terminal_value["returncode"]),
            stdout=stdout_raw.decode("utf-8", errors="replace"),
            stderr=stderr_raw.decode("utf-8", errors="replace"),
            terminal_status=str(terminal_value["status"]),
            receipt_relative_path=Path(
                str(terminal_value["stdout_retained_path"])
            ).with_suffix(".json").as_posix(),
            request_sha256=str(terminal_value["request_sha256"]),
            duration_seconds=(
                float(terminal_value.get("duration_monotonic_ns") or 0)
                / 1_000_000_000
            ),
        )


__all__ = [
    "CompatCandidateProcess",
    "CompatPrewarmError",
    "CompatPrewarmResult",
    "run_compat_candidate",
    "run_compat_prewarm",
]
