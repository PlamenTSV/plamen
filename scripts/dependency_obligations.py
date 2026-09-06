"""Deterministic external-dependency obligation inventory for recon wave B.

The provider enumerates direct, non-local dependencies that production source
actually references.  It does not decide whether a dependency is dangerous;
it creates a bounded research obligation so an unavailable fetch is visible
instead of becoming an empty ledger.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
import unicodedata
from typing import Any, Iterable

SCHEMA = "plamen.external-dependency-obligations.v1"
MAX_OBLIGATIONS = 100
MAX_TRAVERSAL_DIRECTORIES = 20_000
MAX_TRAVERSAL_FILES = 50_000
MAX_TRAVERSAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_TRAVERSAL_ENTRIES = MAX_TRAVERSAL_DIRECTORIES + MAX_TRAVERSAL_FILES
MAX_TRAVERSAL_DEPTH = 128
_SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".go", ".move", ".daml")
_SKIP_DIRS = {
    ".git", ".scratchpad", "artifacts", "cache", "dist", "node_modules",
    "out", "target", "vendor", "build", "coverage", "test", "tests",
}
_SKIP_DIR_PREFIXES = (".scratchpad", ".plamen-stale-snapshots")


def _is_skipped_directory_name(folded_name: str) -> bool:
    """Return whether a canonical directory name is outside source authority.

    Plamen permits distinct preserved/new-run scratchpads such as
    ``.scratchpad-rerun-*``. Those runtime trees and stale-snapshot archives
    are never production dependency inputs, just like the canonical
    ``.scratchpad`` directory.
    """

    return folded_name in _SKIP_DIRS or folded_name.startswith(
        _SKIP_DIR_PREFIXES
    )


class DependencyTraversalError(ValueError):
    """Typed fail-closed dependency-denominator traversal failure."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        observed: int | None = None,
        limit: int | None = None,
    ) -> None:
        self.code = str(code)
        self.observed = observed
        self.limit = limit
        suffix = (
            f" (observed={observed}, limit={limit})"
            if observed is not None and limit is not None
            else ""
        )
        super().__init__(f"dependency traversal {self.code}: {detail}{suffix}")


@dataclass(frozen=True)
class DependencyRootIdentity:
    platform: str
    mode: int
    device: int
    inode: int
    file_attributes: int
    reparse_tag: int

    def payload(self) -> dict[str, int | str]:
        return {
            "schema": "plamen.dependency-root-identity.v1",
            "platform": self.platform,
            "mode": self.mode,
            "device": self.device,
            "inode": self.inode,
            "file_attributes": self.file_attributes,
            "reparse_tag": self.reparse_tag,
        }


@dataclass(frozen=True)
class DependencyFileCensus:
    root: Path
    root_identity: DependencyRootIdentity
    files: tuple[Path, ...]

    def __iter__(self):
        return iter(self.files)

    def __len__(self) -> int:
        return len(self.files)

    def __contains__(self, value: object) -> bool:
        return value in self.files


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0) or 0)
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400) or 0x400)
    )


def _object_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_mode),
        int(getattr(metadata, "st_dev", 0) or 0),
        int(getattr(metadata, "st_ino", 0) or 0),
        int(getattr(metadata, "st_file_attributes", 0) or 0),
        int(getattr(metadata, "st_reparse_tag", 0) or 0),
    )


def _root_identity(metadata: os.stat_result) -> DependencyRootIdentity:
    return DependencyRootIdentity(
        platform="windows" if os.name == "nt" else "posix",
        mode=int(metadata.st_mode),
        device=int(getattr(metadata, "st_dev", 0) or 0),
        inode=int(getattr(metadata, "st_ino", 0) or 0),
        file_attributes=int(
            getattr(metadata, "st_file_attributes", 0) or 0
        ),
        reparse_tag=int(getattr(metadata, "st_reparse_tag", 0) or 0),
    )


def dependency_root_identity(
    root: Path,
) -> tuple[Path, DependencyRootIdentity]:
    """Admit the original lexical project root and bind its native object."""

    from rooted_path_io import RootedPathIOError, checked_directory

    try:
        checked_root = checked_directory(
            Path(root).absolute(),
            label="dependency project root",
        )
        resolved = checked_root.resolve(strict=True)
        metadata = checked_root.lstat()
    except (OSError, RootedPathIOError) as exc:
        raise DependencyTraversalError(
            "UNSAFE_ROOT", "project root has an unsafe alias/reparse ancestor"
        ) from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        raise DependencyTraversalError(
            "UNSAFE_ROOT", "project root is not an ordinary directory"
        )
    return resolved, _root_identity(metadata)


def _canonical_name(name: str) -> tuple[str, str]:
    normalized = unicodedata.normalize("NFC", name)
    try:
        normalized.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DependencyTraversalError(
            "UNSAFE_NAME",
            f"non-UTF-8 dependency path component: {name!r}",
        ) from exc
    if (
        not name
        or name in {".", ".."}
        or ":" in name
        or normalized != name
    ):
        raise DependencyTraversalError(
            "UNSAFE_NAME",
            f"non-canonical dependency path component: {name!r}",
        )
    return normalized.casefold(), normalized


def collect_unvendored_files(root: Path) -> DependencyFileCensus:
    """Return one bounded, root-confined, no-reparse dependency census.

    Excluded trees are pruned before descent.  Reparse/symlink entries are not
    part of the denominator, matching the signed source authority.  Ambiguous
    case/NFC namespaces and traversal-limit exhaustion fail closed instead of
    silently signing a partial dependency denominator.
    """

    original_root = Path(root)
    root, admitted_root_identity = dependency_root_identity(original_root)
    try:
        root_metadata = root.lstat()
    except OSError as exc:
        raise DependencyTraversalError("ROOT_UNREADABLE", str(root)) from exc
    if not stat.S_ISDIR(root_metadata.st_mode) or _is_reparse(root_metadata):
        raise DependencyTraversalError(
            "UNSAFE_ROOT", "project root is not an ordinary directory"
        )

    files: list[Path] = []
    directory_count = 0
    file_count = 0
    total_bytes = 0
    entry_count = 0

    def _walk(directory: Path, depth: int) -> None:
        nonlocal directory_count, file_count, total_bytes, entry_count
        if depth > MAX_TRAVERSAL_DEPTH:
            raise DependencyTraversalError(
                "DEPTH_LIMIT",
                "directory depth exceeds the deterministic bound",
                observed=depth,
                limit=MAX_TRAVERSAL_DEPTH,
            )
        directory_count += 1
        if directory_count > MAX_TRAVERSAL_DIRECTORIES:
            raise DependencyTraversalError(
                "DIRECTORY_LIMIT",
                "directory census exceeds the deterministic bound",
                observed=directory_count,
                limit=MAX_TRAVERSAL_DIRECTORIES,
            )
        try:
            before = directory.lstat()
        except OSError as exc:
            raise DependencyTraversalError(
                "DIRECTORY_UNREADABLE", str(directory.relative_to(root))
            ) from exc
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
        ):
            raise DependencyTraversalError(
                "DIRECTORY_CHANGED", str(directory.relative_to(root))
            )
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory) as scanner:
                for entry in scanner:
                    entry_count += 1
                    if entry_count > MAX_TRAVERSAL_ENTRIES:
                        raise DependencyTraversalError(
                            "ENTRY_LIMIT",
                            "namespace census exceeds the deterministic bound",
                            observed=entry_count,
                            limit=MAX_TRAVERSAL_ENTRIES,
                        )
                    entries.append(entry)
        except DependencyTraversalError:
            raise
        except OSError as exc:
            raise DependencyTraversalError(
                "DIRECTORY_UNREADABLE", str(directory.relative_to(root))
            ) from exc

        ordered: list[tuple[str, str, os.DirEntry[str]]] = []
        aliases: set[str] = set()
        for entry in entries:
            folded, normalized = _canonical_name(entry.name)
            if folded in aliases:
                raise DependencyTraversalError(
                    "NAME_ALIAS",
                    f"case/NFC alias in {directory.relative_to(root)}: {entry.name!r}",
                )
            aliases.add(folded)
            ordered.append((folded, normalized, entry))
        ordered.sort(key=lambda row: (row[0], row[1].encode("utf-8")))

        for folded, _normalized, entry in ordered:
            path = directory / entry.name
            try:
                # DirEntry.stat() does not expose stable dev/inode identity on
                # all supported Windows Python builds; take both identity
                # samples through the same no-follow path primitive.
                metadata = path.lstat()
            except OSError as exc:
                raise DependencyTraversalError(
                    "ENTRY_UNREADABLE", str(path.relative_to(root))
                ) from exc
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if _is_skipped_directory_name(folded):
                    continue
                try:
                    resolved = path.resolve(strict=True)
                except OSError as exc:
                    raise DependencyTraversalError(
                        "DIRECTORY_UNREADABLE", str(path.relative_to(root))
                    ) from exc
                if resolved != path or not resolved.is_relative_to(root):
                    raise DependencyTraversalError(
                        "ROOT_ESCAPE", str(path.relative_to(root))
                    )
                _walk(path, depth + 1)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            try:
                resolved = path.resolve(strict=True)
                confirmed = path.lstat()
            except OSError as exc:
                raise DependencyTraversalError(
                    "ENTRY_UNREADABLE", str(path.relative_to(root))
                ) from exc
            if (
                resolved != path
                or not resolved.is_relative_to(root)
                or stat.S_ISLNK(confirmed.st_mode)
                or _is_reparse(confirmed)
                or _object_identity(metadata) != _object_identity(confirmed)
            ):
                raise DependencyTraversalError(
                    "ENTRY_CHANGED", str(path.relative_to(root))
                )
            file_count += 1
            if file_count > MAX_TRAVERSAL_FILES:
                raise DependencyTraversalError(
                    "FILE_LIMIT",
                    "file census exceeds the deterministic bound",
                    observed=file_count,
                    limit=MAX_TRAVERSAL_FILES,
                )
            total_bytes += int(metadata.st_size)
            if total_bytes > MAX_TRAVERSAL_BYTES:
                raise DependencyTraversalError(
                    "BYTE_LIMIT",
                    "file-byte census exceeds the deterministic bound",
                    observed=total_bytes,
                    limit=MAX_TRAVERSAL_BYTES,
                )
            files.append(path)

        try:
            after = directory.lstat()
        except OSError as exc:
            raise DependencyTraversalError(
                "DIRECTORY_CHANGED", str(directory.relative_to(root))
            ) from exc
        if _object_identity(before) != _object_identity(after):
            raise DependencyTraversalError(
                "DIRECTORY_CHANGED", str(directory.relative_to(root))
            )

    _walk(root, 0)
    confirmed_root, confirmed_identity = dependency_root_identity(original_root)
    if confirmed_root != root or confirmed_identity != admitted_root_identity:
        raise DependencyTraversalError(
            "ROOT_CHANGED", "project root identity changed during census"
        )
    return DependencyFileCensus(
        root=root,
        root_identity=admitted_root_identity,
        files=tuple(files),
    )


def validate_unvendored_files(
    root: Path,
    admitted_files: DependencyFileCensus | Iterable[Path],
) -> DependencyFileCensus:
    """Replay an admitted roster before either enumerating or signing it."""

    original_root = Path(root)
    canonical = collect_unvendored_files(original_root)
    root = canonical.root
    current_root_identity = canonical.root_identity
    if isinstance(admitted_files, DependencyFileCensus):
        if (
            admitted_files.root != root
            or admitted_files.root_identity != current_root_identity
        ):
            raise DependencyTraversalError(
                "ROOT_CHANGED", "admitted dependency root identity changed"
            )
        bound_root_identity = admitted_files.root_identity
        roster = admitted_files.files
    else:
        bound_root_identity = current_root_identity
        roster = tuple(Path(path) for path in admitted_files)
    if len(roster) > MAX_TRAVERSAL_FILES:
        raise DependencyTraversalError(
            "FILE_LIMIT",
            "admitted file roster exceeds the deterministic bound",
            observed=len(roster),
            limit=MAX_TRAVERSAL_FILES,
        )
    if roster != canonical.files:
        if (
            len(roster) == len(canonical.files)
            and set(roster) == set(canonical.files)
        ):
            code = "ROSTER_ORDER"
            detail = "admitted dependency roster is not canonical"
        else:
            code = "ROSTER_MISMATCH"
            detail = "admitted dependency roster is not the complete census"
        raise DependencyTraversalError(code, detail)
    total_bytes = 0
    aliases: set[tuple[str, ...]] = set()
    previous_key: tuple[tuple[str, bytes], ...] | None = None
    for path in roster:
        try:
            relative = path.relative_to(root)
        except ValueError as exc:
            raise DependencyTraversalError(
                "ROSTER_ESCAPE", "admitted dependency roster escaped project root"
            ) from exc
        if not relative.parts or any(
            _is_skipped_directory_name(_canonical_name(part)[0])
            for part in relative.parts[:-1]
        ):
            raise DependencyTraversalError(
                "ROSTER_EXCLUDED", str(relative)
            )
        folded_parts = tuple(_canonical_name(part)[0] for part in relative.parts)
        alias = folded_parts
        if alias in aliases:
            raise DependencyTraversalError("NAME_ALIAS", str(relative))
        aliases.add(alias)
        key = tuple(
            (folded, part.encode("utf-8"))
            for folded, part in zip(folded_parts, relative.parts)
        )
        if previous_key is not None and key <= previous_key:
            raise DependencyTraversalError(
                "ROSTER_ORDER", "admitted dependency roster is not canonical"
            )
        previous_key = key
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise DependencyTraversalError("ENTRY_UNREADABLE", str(relative)) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or resolved != path
            or not resolved.is_relative_to(root)
        ):
            raise DependencyTraversalError("ENTRY_CHANGED", str(relative))
        total_bytes += int(metadata.st_size)
        if total_bytes > MAX_TRAVERSAL_BYTES:
            raise DependencyTraversalError(
                "BYTE_LIMIT",
                "admitted file-byte roster exceeds the deterministic bound",
                observed=total_bytes,
                limit=MAX_TRAVERSAL_BYTES,
            )
    confirmed_root, confirmed_root_identity = dependency_root_identity(original_root)
    if (
        confirmed_root != root
        or confirmed_root_identity != bound_root_identity
    ):
        raise DependencyTraversalError(
            "ROOT_CHANGED", "project root identity changed during roster replay"
        )
    return DependencyFileCensus(
        root=root,
        root_identity=bound_root_identity,
        files=roster,
    )


def iter_unvendored_files(root: Path) -> Iterable[Path]:
    """Compatibility iterator over the bounded admitted file census."""

    yield from collect_unvendored_files(root)


def _production_files(
    root: Path,
    suffixes: tuple[str, ...],
    admitted_files: Iterable[Path] | None = None,
) -> list[Path]:
    from recon_prepass import _is_production_source_path

    wanted = {suffix.casefold() for suffix in suffixes}
    out: list[Path] = []
    for path in (
        admitted_files
        if admitted_files is not None
        else iter_unvendored_files(root)
    ):
        if not path.is_file() or path.suffix.casefold() not in wanted:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if _is_production_source_path(path, root):
            out.append(path)
    return sorted(out)


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _relative_locus(root: Path, path: Path, line: int) -> str:
    return f"{path.relative_to(root).as_posix()}:L{line}"


def _stable_id(kind: str, name: str, locus: str) -> str:
    digest = hashlib.sha256(
        f"{kind}\0{name.casefold()}\0{locus.casefold()}".encode("utf-8")
    ).hexdigest()[:12].upper()
    return f"DEP-{digest}"


def _row(kind: str, name: str, locus: str, evidence: str) -> dict[str, str]:
    return {
        "obligation_id": _stable_id(kind, name, locus),
        "dependency": name,
        "kind": kind,
        "source_location": locus,
        "declaration_evidence": " ".join(evidence.split())[:500],
        "research_question": (
            "Determine the externally defined semantics, temporal guarantees, "
            "failure behavior, and integration assumptions relied on at this locus."
        ),
    }


def _solidity_rows(root: Path, files: Iterable[Path]) -> list[dict[str, str]]:
    files = tuple(files)
    rows: list[dict[str, str]] = []
    import_re = re.compile(
        r"(?m)^\s*import\s+(?:[^;]*?\sfrom\s+)?[\"'](?P<path>[^\"']+)[\"']\s*;"
    )
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in import_re.finditer(text):
            imported = match.group("path")
            if imported.startswith((".", "/")):
                continue
            parts = imported.split("/")
            name = "/".join(parts[:2]) if imported.startswith("@") else parts[0]
            locus = _relative_locus(root, path, _line_for(text, match.start()))
            rows.append(_row("source-import", name, locus, match.group(0)))
    # Preserve the existing structural interface-without-implementation signal
    # without asking recon_prepass to perform a second, unbounded tree walk.
    try:
        from recon_prepass import (
            _EVM_CONTRACT_DECL_RE,
            _EVM_INTERFACE_DECL_RE,
            _EVM_STDLIB_INTERFACE_NAMES,
            _MAX_EXTERNAL_DEPENDENCY_MARKERS,
        )

        interface_decls: dict[str, str] = {}
        contract_impls: set[str] = set()
        texts: dict[Path, str] = {}
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            texts[path] = text
            for match in _EVM_INTERFACE_DECL_RE.finditer(text):
                name = match.group(1)
                interface_decls.setdefault(
                    name,
                    _relative_locus(root, path, _line_for(text, match.start())),
                )
            for match in _EVM_CONTRACT_DECL_RE.finditer(text):
                contract_impls.add(match.group(1))
        markers = 0
        for name, locus in sorted(interface_decls.items()):
            if name in _EVM_STDLIB_INTERFACE_NAMES or name in contract_impls:
                continue
            call_re = re.compile(
                rf"\b{re.escape(name)}\s*\([^)]*\)\s*\.\s*\w+\s*\("
            )
            if any(call_re.search(text) for text in texts.values()):
                rows.append(_row("external-interface", name, locus, name))
                markers += 1
            if markers >= _MAX_EXTERNAL_DEPENDENCY_MARKERS:
                break
    except Exception:
        pass
    return rows


def _cargo_rows(
    root: Path,
    rust_files: list[Path],
    admitted_files: Iterable[Path] | None = None,
) -> list[dict[str, str]]:
    referenced = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in rust_files
    )
    rows: list[dict[str, str]] = []
    for manifest in (
        path for path in (
            admitted_files
            if admitted_files is not None
            else iter_unvendored_files(root)
        )
        if path.name == "Cargo.toml"
    ):
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        tables = [data.get("dependencies", {})]
        workspace = data.get("workspace", {})
        if isinstance(workspace, dict):
            tables.append(workspace.get("dependencies", {}))
        for table in tables:
            if not isinstance(table, dict):
                continue
            for name, spec in table.items():
                if isinstance(spec, dict) and ("path" in spec or spec.get("workspace") is True):
                    continue
                source_name = str(name).replace("-", "_")
                match = re.search(
                    rf"(?m)^\s*(?:use\s+)?{re.escape(source_name)}(?:::|\b)", referenced
                )
                if not match:
                    continue
                locus = f"{manifest.relative_to(root).as_posix()}:L1"
                rows.append(_row("cargo-direct", str(name), locus, repr(spec)))
    return rows


def _go_rows(
    root: Path,
    go_files: list[Path],
    admitted_files: Iterable[Path] | None = None,
) -> list[dict[str, str]]:
    imported: set[str] = set()
    import_re = re.compile(r'(?m)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"\n]+)"')
    for path in go_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        imported.update(import_re.findall(text))
    rows: list[dict[str, str]] = []
    for manifest in (
        path for path in (
            admitted_files
            if admitted_files is not None
            else iter_unvendored_files(root)
        )
        if path.name == "go.mod"
    ):
        text = manifest.read_text(encoding="utf-8", errors="replace")
        in_require = False
        for line_no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            match = re.match(r"(?:require\s+)?([^\s]+)\s+v[^\s]+", line)
            if not match or (not in_require and not line.startswith("require ")):
                continue
            name = match.group(1)
            if not any(path == name or path.startswith(name + "/") for path in imported):
                continue
            locus = f"{manifest.relative_to(root).as_posix()}:L{line_no}"
            rows.append(_row("go-direct", name, locus, raw))
    return rows


def _move_rows(
    root: Path,
    admitted_files: Iterable[Path] | None = None,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for manifest in (
        path for path in (
            admitted_files
            if admitted_files is not None
            else iter_unvendored_files(root)
        )
        if path.name == "Move.toml"
    ):
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        for table_name in ("dependencies", "dev-dependencies"):
            table = data.get(table_name, {})
            if not isinstance(table, dict):
                continue
            for name, spec in table.items():
                if isinstance(spec, dict) and "local" in spec:
                    continue
                locus = f"{manifest.relative_to(root).as_posix()}:L1"
                rows.append(_row("move-direct", str(name), locus, repr(spec)))
    return rows


def _daml_rows(
    root: Path,
    admitted_files: Iterable[Path] | None = None,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for manifest in (
        path for path in (
            admitted_files
            if admitted_files is not None
            else iter_unvendored_files(root)
        )
        if path.name == "daml.yaml"
    ):
        text = manifest.read_text(encoding="utf-8", errors="replace")
        in_dependencies = False
        for line_no, raw in enumerate(text.splitlines(), 1):
            if re.match(r"^dependencies\s*:", raw):
                in_dependencies = True
                continue
            if in_dependencies and raw and not raw.startswith((" ", "\t", "-")):
                in_dependencies = False
            if not in_dependencies:
                continue
            match = re.match(r"\s*-\s*(\S+)", raw)
            if match:
                locus = f"{manifest.relative_to(root).as_posix()}:L{line_no}"
                rows.append(_row("daml-direct", match.group(1), locus, raw))
    return rows


def enumerate_dependency_obligations(
    project_root: Path,
    config: dict[str, Any],
    *,
    admitted_files: DependencyFileCensus | Iterable[Path] | None = None,
) -> dict[str, Any]:
    original_root = Path(project_root)
    census = (
        collect_unvendored_files(original_root)
        if admitted_files is None
        else validate_unvendored_files(original_root, admitted_files)
    )
    root = census.root
    files = _production_files(root, _SOURCE_SUFFIXES, census)
    by_suffix: dict[str, list[Path]] = {}
    for path in files:
        by_suffix.setdefault(path.suffix.casefold(), []).append(path)
    rows: list[dict[str, str]] = []
    rows.extend(_solidity_rows(root, by_suffix.get(".sol", [])))
    rows.extend(_cargo_rows(root, by_suffix.get(".rs", []), census))
    rows.extend(_go_rows(root, by_suffix.get(".go", []), census))
    if by_suffix.get(".move") or str(config.get("language", "")).lower() in {"aptos", "sui"}:
        rows.extend(_move_rows(root, census))
    if by_suffix.get(".daml"):
        rows.extend(_daml_rows(root, census))
    deduped = {
        row["obligation_id"]: row
        for row in rows
    }
    ordered = [deduped[key] for key in sorted(deduped)]
    retained = ordered[:MAX_OBLIGATIONS]
    return {
        "schema": SCHEMA,
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": retained,
        "observed_count": len(ordered),
        "retained_count": len(retained),
        "truncated": len(ordered) > len(retained),
        "overflow_ids": [row["obligation_id"] for row in ordered[MAX_OBLIGATIONS:]],
    }


def write_dependency_obligations(
    scratchpad: Path, project_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    result = enumerate_dependency_obligations(project_root, config)
    path = Path(scratchpad) / "external_dependency_obligations.json"
    path.write_bytes(render_dependency_obligations(result))
    return result


def render_dependency_obligations(obligations: dict[str, Any]) -> bytes:
    """Render deterministic obligation authority without publishing it."""
    return (json.dumps(obligations, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


_LEDGER_COLUMNS = (
    "Obligation ID",
    "Dependency",
    "Integration Surface",
    "Assumed Behavior",
    "Real Behavior",
    "Source",
    "Conformance",
    "Fetch Status",
)


def _parse_research_rows(text: str) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    header: list[str] | None = None
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if header is None and "Obligation ID" in cells:
            header = cells
            continue
        if header is None or len(cells) != len(header):
            continue
        if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        row = dict(zip(header, cells))
        obligation_id = row.get("Obligation ID", "").upper()
        if re.fullmatch(r"DEP-[A-F0-9]{12}", obligation_id):
            rows[obligation_id] = row
    return rows


def reconcile_dependency_research_ledger(
    scratchpad: Path,
    obligations: dict[str, Any],
    *,
    worker_text: str = "",
    publish: bool = True,
) -> dict[str, Any]:
    """Write one canonical row per deterministic obligation, even on failure."""
    scratchpad = Path(scratchpad)
    worker_rows = _parse_research_rows(worker_text)
    lines = [
        "# External Dependency Research Ledger",
        "",
        "> Deterministic obligation parity: every enumerated dependency has a row. "
        "`NEEDS_DEPENDENCY_RESEARCH` and `FETCH_FAILED` are unresolved evidence, "
        "never permission to assume favorable external behavior.",
        "",
        "| " + " | ".join(_LEDGER_COLUMNS) + " |",
        "|" + "|".join("---" for _ in _LEDGER_COLUMNS) + "|",
    ]
    researched = 0
    unresolved = 0
    expected_ids: list[str] = []
    for obligation in obligations.get("obligations", []):
        oid = str(obligation["obligation_id"]).upper()
        expected_ids.append(oid)
        worker = worker_rows.get(oid, {})
        real = worker.get("Real Behavior", "").strip()
        source = worker.get("Source", "").strip()
        raw_status = worker.get("Fetch Status", "").strip().upper()
        source_grounded = bool(source and source != "-" and re.search(r"https?://|[A-Za-z0-9_./-]+:L\d+", source))
        if raw_status == "FETCH_FAILED":
            status = "FETCH_FAILED"
        elif real and real not in {"-", "UNRESOLVED", "UNKNOWN"} and source_grounded:
            status = "RESEARCHED"
        else:
            status = "NEEDS_DEPENDENCY_RESEARCH"
        if status == "RESEARCHED":
            researched += 1
        else:
            unresolved += 1
        values = (
            oid,
            str(obligation["dependency"]),
            worker.get("Integration Surface", "").strip()
            or str(obligation["source_location"]),
            worker.get("Assumed Behavior", "").strip()
            or str(obligation["research_question"]),
            real or "UNRESOLVED",
            source or "-",
            worker.get("Conformance", "").strip() or "UNKNOWN",
            status,
        )
        lines.append("| " + " | ".join(value.replace("|", "\\|") for value in values) + " |")
    if not expected_ids:
        lines.extend(["", "No external dependency obligations were mechanically enumerated."])
    lines.append("")
    ledger_bytes = ("\n".join(lines) + "\n").encode("utf-8")
    if publish:
        (scratchpad / "external_dependency_research.md").write_bytes(ledger_bytes)

    overflow = bool(obligations.get("truncated"))
    limitation_bytes: bytes | None = None
    if unresolved or overflow:
        limitation_bytes = (
            "# External Dependency Research Coverage\n\n"
            f"Status: UNKNOWN — {unresolved} unresolved of {len(expected_ids)} "
            "retained obligation(s).\n"
            + (
                f"Enumeration overflow: observed {obligations.get('observed_count')} "
                f"but retained {obligations.get('retained_count')}; human review required.\n"
                if overflow else ""
            )
        ).encode("utf-8")
        if publish:
            (scratchpad / "report_semantic_dependency_research.md").write_bytes(
                limitation_bytes
            )
    elif publish:
        (scratchpad / "report_semantic_dependency_research.md").unlink(
            missing_ok=True
        )
    return {
        "expected_ids": expected_ids,
        "researched": researched,
        "unresolved": unresolved,
        "truncated": overflow,
        "_rendered_outputs": {
            "external_dependency_research.md": ledger_bytes,
            **(
                {"report_semantic_dependency_research.md": limitation_bytes}
                if limitation_bytes is not None
                else {}
            ),
        },
    }


def validate_dependency_ledger_parity(
    obligations: dict[str, Any], ledger_text: str
) -> tuple[bool, list[str]]:
    expected = {
        str(row["obligation_id"]).upper()
        for row in obligations.get("obligations", [])
    }
    actual = set(_parse_research_rows(ledger_text))
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    issues = []
    if missing:
        issues.append("missing obligation rows: " + ", ".join(missing))
    if extra:
        issues.append("unexpected obligation rows: " + ", ".join(extra))
    return not issues, issues
