"""Single-read authority for Plamen's reviewed toolchain controls.

The version lock and governance registry are one control pair.  Consumers must
not parse either file independently: doing so permits mixed revisions and makes
setup authorize inputs that runtime later rejects.

This module is deliberately stdlib-only so it is usable by setup, snapshotting,
recon, and the coverage ledger before optional dependencies are installed.
"""

from __future__ import annotations

import ast
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping


TOOLCHAIN_GOVERNANCE_SCHEMA = "plamen.toolchain_governance.v1"
TOOLCHAIN_VERSION_LOCK_SCHEMA = "plamen.toolchain_version_lock.v1"
TOOLCHAIN_GOVERNANCE_FILENAME = "toolchain_governance.v1.json"
TOOLCHAIN_VERSION_LOCK_FILENAME = "toolchain_version_lock.v1.json"
PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "control",
        "mode": "named-files",
        "root": "verification_policy",
        "names": (
            "protobuf_reviewed_content.v1.json",
            "toolchain_governance.v1.json",
            "toolchain_version_lock.v1.json",
        ),
    },
)
# Public runtime entry points are reviewed; all transitive Python and typed
# data dependencies are derived from reachable source. Intentionally dynamic
# public entry points remain explicit, but runtime data never lives in a
# second central filename allowlist.
_RUNTIME_ENTRYPOINTS = (
    "plamen.py",
    "scripts/audit_snapshot.py",
    "scripts/enumeration_type_ir.py",
    "scripts/artifact_ledger.py",
    "scripts/ci_dependency_authority.py",
    "scripts/phase_io_contracts.py",
    "scripts/plamen_mcp_runtime.py",
    "scripts/program_facts_bake.py",
    "scripts/program_facts_evm_provider.py",
    "scripts/program_facts_evm_wtx.py",
    "scripts/program_facts_loader.py",
    "scripts/program_facts_provider_api.py",
    "scripts/provider_command_authority.py",
    "scripts/recon_prepass.py",
    "scripts/refresh_ci_dependency_evidence.py",
    "scripts/rooted_path_io.py",
    "scripts/worker_execution_receipts.py",
    "scripts/worker_transaction.py",
)
_RUNTIME_CLOSURE_SCHEMA = "plamen.toolchain-runtime-closure.v1"
_RUNTIME_CLOSURE_PATH = Path(
    "verification_policy/toolchain_runtime_closure.v1.json"
)
_RUNTIME_DENIED_BASENAMES = {
    "claude_test_launch_authority.py",
}
_MAX_RUNTIME_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_RUNTIME_ASSET_BYTES = 16 * 1024 * 1024
_MAX_RUNTIME_TREE_FILES = 512
_MAX_RUNTIME_LOCAL_MODULE_FILES = 1024
TOOLCHAIN_RUNTIME_REQUIRED_FILES: tuple[str, ...]
TOOLCHAIN_RUNTIME_ASSET_ROWS: tuple[Mapping[str, str], ...]
_MAX_CONTROL_BYTES = 2 * 1024 * 1024
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^\d+\.\d+\.\d+$")


class ToolchainControlError(ValueError):
    """The local reviewed control pair is unreadable or semantically invalid."""


@dataclass(frozen=True)
class _RuntimeDirectoryEntry:
    name: str
    casefolded_name: str
    identity: tuple[int, int, int, int, int]
    is_regular: bool
    is_directory: bool
    is_alias: bool


@dataclass(frozen=True)
class _RuntimeDirectoryState:
    identity: tuple[int, int, int, int, int]
    entries: tuple[_RuntimeDirectoryEntry, ...]


class _RuntimePathIndex:
    """Per-derivation canonical path index with an exact final replay."""

    def __init__(self, root: Path) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self._states: dict[Path, _RuntimeDirectoryState] = {}
        self._labels: dict[Path, str] = {}
        self._sealed = False

    def _scan(self, directory: Path, label: str) -> _RuntimeDirectoryState:
        directory = Path(os.path.abspath(os.fspath(directory)))
        try:
            _reject_alias_ancestry(directory, label)
            before = directory.lstat()
            if (
                not stat.S_ISDIR(before.st_mode)
                or directory.is_symlink()
                or _is_reparse_point(directory)
            ):
                raise ToolchainControlError(
                    f"{label} parent is not a canonical directory"
                )
            rows: list[_RuntimeDirectoryEntry] = []
            folded: dict[str, str] = {}
            with os.scandir(directory) as entries:
                for entry in entries:
                    info = entry.stat(follow_symlinks=False)
                    attributes = int(
                        getattr(info, "st_file_attributes", 0)
                    )
                    reparse = int(
                        getattr(
                            stat,
                            "FILE_ATTRIBUTE_REPARSE_POINT",
                            0x400,
                        )
                    )
                    alias = stat.S_ISLNK(info.st_mode) or bool(
                        attributes & reparse
                    )
                    key = entry.name.casefold()
                    prior = folded.get(key)
                    if prior is not None and prior != entry.name:
                        raise ToolchainControlError(
                            f"{label} directory has a case-fold alias: "
                            f"{prior} versus {entry.name}"
                        )
                    folded[key] = entry.name
                    rows.append(
                        _RuntimeDirectoryEntry(
                            name=entry.name,
                            casefolded_name=key,
                            identity=_identity(info),
                            is_regular=stat.S_ISREG(info.st_mode),
                            is_directory=stat.S_ISDIR(info.st_mode),
                            is_alias=alias,
                        )
                    )
            after = directory.lstat()
            _reject_alias_ancestry(directory, label)
            if _identity(before) != _identity(after):
                raise ToolchainControlError(
                    f"{label} parent changed while indexed"
                )
            return _RuntimeDirectoryState(
                identity=_identity(after),
                entries=tuple(sorted(rows, key=lambda row: row.name)),
            )
        except ToolchainControlError:
            raise
        except OSError as exc:
            raise ToolchainControlError(
                f"{label} parent is unreadable"
            ) from exc

    def _state(self, directory: Path, label: str) -> _RuntimeDirectoryState:
        if self._sealed:
            raise ToolchainControlError("runtime path index is sealed")
        directory = Path(os.path.abspath(os.fspath(directory)))
        state = self._states.get(directory)
        if state is None:
            state = self._scan(directory, label)
            self._states[directory] = state
            self._labels[directory] = label
        return state

    def _require(
        self,
        relative: str,
        label: str,
        *,
        directory: bool,
    ) -> Path:
        value = _canonical_runtime_relative(relative, label)
        cursor = self.root
        parts = Path(value).parts
        if not parts:
            if directory:
                self._state(cursor, label)
                return cursor
            raise ToolchainControlError(f"{label} path is invalid")
        for ordinal, component in enumerate(parts):
            state = self._state(cursor, label)
            matches = [
                row
                for row in state.entries
                if row.casefolded_name == component.casefold()
            ]
            if len(matches) != 1 or matches[0].name != component:
                raise ToolchainControlError(
                    f"{label} path spelling/case alias is not canonical: "
                    f"{relative}"
                )
            row = matches[0]
            if row.is_alias:
                raise ToolchainControlError(
                    f"{label} ancestor must not be a symlink, junction, "
                    "or reparse point"
                )
            leaf = ordinal == len(parts) - 1
            if (leaf and directory and not row.is_directory) or (
                leaf and not directory and not row.is_regular
            ):
                raise ToolchainControlError(
                    f"{label} path has the wrong file type: {relative}"
                )
            if not leaf and not row.is_directory:
                raise ToolchainControlError(
                    f"{label} ancestor is not a directory: {relative}"
                )
            cursor /= row.name
        return cursor

    def require_file(self, relative: str, label: str) -> Path:
        return self._require(relative, label, directory=False)

    def require_directory(self, relative: str, label: str) -> Path:
        return self._require(relative, label, directory=True)

    def python_files(
        self,
        relative: str,
        *,
        recursive: bool,
        label: str,
        admit: Callable[[Path], bool] | None = None,
    ) -> tuple[str, ...]:
        pending = [Path(relative)]
        found: list[str] = []
        while pending:
            current_relative = pending.pop()
            directory = self.require_directory(
                current_relative.as_posix(),
                label,
            )
            state = self._state(directory, label)
            for row in state.entries:
                child = current_relative / row.name
                if row.is_alias:
                    raise ToolchainControlError(
                        f"{label} local module tree traverses an alias: "
                        f"{child.as_posix()}"
                    )
                if row.is_regular and row.name.endswith(".py"):
                    if admit is None or admit(child):
                        found.append(child.as_posix())
                elif (
                    recursive
                    and row.is_directory
                    and row.name != "__pycache__"
                ):
                    pending.append(child)
                elif not row.is_regular and not row.is_directory:
                    raise ToolchainControlError(
                        f"{label} local module tree has a non-regular entry: "
                        f"{child.as_posix()}"
                    )
            if len(found) > _MAX_RUNTIME_LOCAL_MODULE_FILES:
                raise ToolchainControlError(
                    f"{label} local module denominator exceeds its bound"
                )
        return tuple(sorted(found))

    def verify_unchanged(self) -> None:
        if self._sealed:
            raise ToolchainControlError(
                "runtime path index was already replayed"
            )
        for directory in sorted(
            self._states,
            key=lambda path: os.fspath(path).casefold(),
        ):
            expected = self._states[directory]
            observed = self._scan(
                directory,
                self._labels[directory],
            )
            if observed != expected:
                raise ToolchainControlError(
                    "runtime path index changed during derivation: "
                    f"{directory}"
                )
        self._sealed = True


def _runtime_module_map(
    root: Path,
    *,
    path_index: _RuntimePathIndex,
) -> dict[str, str]:
    """Map importable local module names to repository-relative paths."""

    modules: dict[str, str] = {}
    scripts = root / "scripts"
    if scripts.is_dir():
        for relative in path_index.python_files(
            "scripts",
            recursive=False,
            label="runtime local module map",
            admit=lambda path: (
                not path.name.startswith("test_")
                and path.name not in _RUNTIME_DENIED_BASENAMES
            ),
        ):
            path = root / relative
            modules[path.stem] = relative
            modules[f"scripts.{path.stem}"] = relative
    package = root / "plamen_l1"
    if package.is_dir():
        for relative in path_index.python_files(
            "plamen_l1",
            recursive=True,
            label="runtime local module map",
            admit=lambda path: not path.name.startswith("test_"),
        ):
            path = root / relative
            relative_path = Path(relative)
            pieces = list(relative_path.with_suffix("").parts)
            if pieces[-1] == "__init__":
                pieces.pop()
            module = ".".join(pieces)
            if module:
                modules[module] = relative_path.as_posix()
    if (root / "plamen.py").is_file():
        path_index.require_file("plamen.py", "runtime local module map")
        modules["plamen"] = "plamen.py"
    return modules


def _module_for_path(relative: str) -> str:
    path = Path(relative)
    pieces = list(path.with_suffix("").parts)
    if pieces and pieces[-1] == "__init__":
        pieces.pop()
    if pieces and pieces[0] == "scripts":
        return pieces[-1]
    return ".".join(pieces)


def _local_import_targets(
    tree: ast.AST,
    *,
    importer: str,
    importer_is_package: bool = False,
    modules: Mapping[str, str],
) -> set[str]:
    targets: set[str] = set()
    package = (
        importer if importer_is_package else importer.rpartition(".")[0]
    )
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                base = package.split(".") if package else []
                keep = max(0, len(base) - node.level + 1)
                module = ".".join([*base[:keep], module]).strip(".")
            if module:
                names.append(module)
            names.extend(
                ".".join(part for part in (module, alias.name) if part)
                for alias in node.names
                if alias.name != "*"
            )
        for name in names:
            candidate = name
            while candidate:
                relative = modules.get(candidate)
                if relative is not None:
                    targets.add(relative)
                    break
                candidate = candidate.rpartition(".")[0]
    return targets


def _local_literal_file_targets(
    tree: ast.AST,
    *,
    importer_relative: str,
    module_paths: set[str],
) -> set[str]:
    """Resolve bounded sibling ``with_name("*.py")`` runtime references."""

    targets: set[str] = set()
    parent = Path(importer_relative).parent
    for node in ast.walk(tree):
        if (
            not isinstance(node, ast.Call)
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr != "with_name"
            or len(node.args) != 1
            or node.keywords
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
        ):
            continue
        name = node.args[0].value
        candidate_name = Path(name)
        if (
            candidate_name.name != name
            or candidate_name.suffix != ".py"
            or name.startswith(".")
        ):
            continue
        candidate = (parent / candidate_name).as_posix()
        if candidate in module_paths:
            targets.add(candidate)
    return targets


def _local_literal_dynamic_import_targets(
    tree: ast.AST,
    *,
    modules: Mapping[str, str],
) -> set[str]:
    """Close dynamic imports over every locally importable module.

    Literal imports retain their precise local target.  A non-literal import
    can select any local module visible from the shipped root, so the only
    mechanically sound package denominator is the complete bounded local
    module map.  External distributions remain governed by dependency
    authority; this function closes only repository-local code.
    """

    targets, unresolved = _local_dynamic_import_analysis(
        tree,
        modules=modules,
    )
    if unresolved:
        targets.update(modules.values())
    return targets


def _local_dynamic_import_analysis(
    tree: ast.AST,
    *,
    modules: Mapping[str, str],
) -> tuple[set[str], bool]:
    """Return precise local targets and whether selection was non-literal.

    Keeping the uncertainty bit separate lets the closure builder stop
    repeatedly walking every subsequent AST after it has already scheduled
    the complete bounded local-module universe.  Every source is still parsed
    for syntax and inspected for typed runtime-asset declarations.
    """

    nodes = tuple(ast.walk(tree))
    importlib_names = {"importlib"}
    import_module_names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "importlib":
                    importlib_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            for alias in node.names:
                if alias.name == "import_module":
                    import_module_names.add(alias.asname or alias.name)
    targets: set[str] = set()
    unresolved = False
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        is_import = (
            isinstance(node.func, ast.Name)
            and node.func.id in {"__import__", *import_module_names}
        ) or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in importlib_names
        )
        if not is_import:
            continue
        argument: ast.AST | None = node.args[0] if node.args else None
        if argument is None:
            for keyword in node.keywords:
                if keyword.arg == "name":
                    argument = keyword.value
                    break
        if not (
            argument is not None
            and isinstance(argument, ast.Constant)
            and isinstance(argument.value, str)
        ):
            unresolved = True
            continue
        candidate = argument.value
        while candidate:
            relative = modules.get(candidate)
            if relative is not None:
                targets.add(relative)
                break
            candidate = candidate.rpartition(".")[0]
    return targets, unresolved


def _literal_runtime_asset_declarations(
    tree: ast.AST,
    *,
    importer_relative: str,
) -> tuple[Mapping[str, Any], ...]:
    declarations: list[Mapping[str, Any]] = []
    for node in tree.body if isinstance(tree, ast.Module) else ():
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        target = (
            node.target
            if isinstance(node, ast.AnnAssign)
            else node.targets[0] if len(node.targets) == 1 else None
        )
        if not (
            isinstance(target, ast.Name)
            and target.id == "PLAMEN_RUNTIME_ASSETS"
        ):
            continue
        value_node = node.value
        try:
            value = ast.literal_eval(value_node)
        except Exception as exc:
            raise ToolchainControlError(
                "runtime asset declaration is not literal: "
                f"{importer_relative}"
            ) from exc
        if not isinstance(value, (tuple, list)):
            raise ToolchainControlError(
                "runtime asset declaration must be a tuple/list: "
                f"{importer_relative}"
            )
        for row in value:
            if not isinstance(row, dict):
                raise ToolchainControlError(
                    "runtime asset declaration row is invalid: "
                    f"{importer_relative}"
                )
            declarations.append(dict(row))
    return tuple(declarations)


def _canonical_runtime_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ToolchainControlError(f"{label} path is invalid")
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or "\\" in value
    ):
        raise ToolchainControlError(f"{label} path is not canonical")
    return value


def _bounded_runtime_asset(
    root: Path,
    relative: str,
    label: str,
    *,
    path_index: _RuntimePathIndex,
) -> None:
    path = root / relative
    try:
        _require_canonical_runtime_spelling(
            root,
            relative,
            f"{label} runtime asset",
            path_index=path_index,
        )
        info = path.lstat()
    except OSError as exc:
        raise ToolchainControlError(
            f"{label} runtime asset is missing: {relative}"
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or _is_reparse_point(path)
        or int(getattr(info, "st_nlink", 1)) != 1
        or info.st_size > _MAX_RUNTIME_ASSET_BYTES
    ):
        raise ToolchainControlError(
            f"{label} runtime asset is not a bounded unaliased regular file: "
            f"{relative}"
        )


def _expand_runtime_asset_declaration(
    root: Path,
    declaration: Mapping[str, Any],
    *,
    importer_relative: str,
    path_index: _RuntimePathIndex,
) -> tuple[tuple[str, str], ...]:
    mode = declaration.get("mode")
    kind = declaration.get("kind")
    if kind not in {"runtime-data", "control"}:
        raise ToolchainControlError(
            f"runtime asset kind is invalid: {importer_relative}"
        )
    paths: list[str] = []
    if mode == "file":
        if set(declaration) != {"kind", "mode", "path"}:
            raise ToolchainControlError(
                f"runtime file declaration keys invalid: {importer_relative}"
            )
        paths.append(
            _canonical_runtime_relative(
                declaration.get("path"), importer_relative
            )
        )
    elif mode == "named-files":
        if set(declaration) != {"kind", "mode", "root", "names"}:
            raise ToolchainControlError(
                "runtime named-files declaration keys invalid: "
                f"{importer_relative}"
            )
        base = _canonical_runtime_relative(
            declaration.get("root"), importer_relative
        )
        names = declaration.get("names")
        if (
            not isinstance(names, (tuple, list))
            or not names
            or len(names) > _MAX_RUNTIME_TREE_FILES
        ):
            raise ToolchainControlError(
                f"runtime named-files denominator invalid: {importer_relative}"
            )
        for name in names:
            canonical_name = _canonical_runtime_relative(
                name, importer_relative
            )
            if len(Path(canonical_name).parts) != 1:
                raise ToolchainControlError(
                    "runtime named-file must be one basename: "
                    f"{importer_relative}"
                )
            paths.append((Path(base) / canonical_name).as_posix())
    elif mode == "tree":
        if set(declaration) != {
            "kind",
            "mode",
            "root",
            "pattern",
            "max_files",
        }:
            raise ToolchainControlError(
                f"runtime tree declaration keys invalid: {importer_relative}"
            )
        base = _canonical_runtime_relative(
            declaration.get("root"), importer_relative
        )
        pattern = declaration.get("pattern")
        maximum = declaration.get("max_files")
        if (
            not isinstance(pattern, str)
            or pattern not in {"*.json", "*.md", "*.py"}
            or not isinstance(maximum, int)
            or maximum <= 0
            or maximum > _MAX_RUNTIME_TREE_FILES
        ):
            raise ToolchainControlError(
                f"runtime tree declaration bound invalid: {importer_relative}"
            )
        directory = root / base
        _require_canonical_runtime_spelling(
            root,
            base,
            f"{importer_relative} runtime tree",
            path_index=path_index,
            directory=True,
        )
        if (
            not directory.is_dir()
            or directory.is_symlink()
            or _is_reparse_point(directory)
        ):
            raise ToolchainControlError(
                f"runtime tree root invalid: {importer_relative}:{base}"
            )
        paths.extend(
            path.relative_to(root).as_posix()
            for path in sorted(directory.rglob(pattern))
            if path.is_file()
        )
        if not paths or len(paths) > maximum:
            raise ToolchainControlError(
                f"runtime tree file bound invalid: {importer_relative}:{base}"
            )
    else:
        raise ToolchainControlError(
            f"runtime asset mode is invalid: {importer_relative}"
        )
    rows: list[tuple[str, str]] = []
    for relative in paths:
        _bounded_runtime_asset(
            root,
            relative,
            importer_relative,
            path_index=path_index,
        )
        rows.append((relative, str(kind)))
    return tuple(rows)


def derive_runtime_dependency_closure(root: Path) -> tuple[str, ...]:
    """Derive a cycle-safe local-import closure from public entry points."""

    root = Path(root)
    path_index = _RuntimePathIndex(root)
    modules = _runtime_module_map(root, path_index=path_index)
    module_paths = set(modules.values())
    missing_entries = [
        relative
        for relative in _RUNTIME_ENTRYPOINTS
        if not (root / relative).is_file()
    ]
    if missing_entries:
        raise ToolchainControlError(
            "runtime closure entry points missing: "
            + ", ".join(missing_entries)
        )
    visited: set[str] = set()
    declared_assets: dict[str, str] = {}
    pending = list(_RUNTIME_ENTRYPOINTS)
    complete_local_universe_scheduled = False
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        path = root / relative
        if path.name.startswith("test_") or path.name in (
            _RUNTIME_DENIED_BASENAMES
        ):
            raise ToolchainControlError(
                f"test/private module entered runtime closure: {relative}"
            )
        try:
            _require_canonical_runtime_spelling(
                root,
                relative,
                "runtime dependency",
                path_index=path_index,
            )
            info = path.lstat()
        except OSError as exc:
            raise ToolchainControlError(
                f"runtime dependency is unreadable: {relative}"
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or path.is_symlink()
            or _is_reparse_point(path)
            or info.st_size > _MAX_RUNTIME_SOURCE_BYTES
        ):
            raise ToolchainControlError(
                f"runtime dependency is not a bounded regular file: {relative}"
            )
        try:
            tree = ast.parse(
                path.read_text(encoding="utf-8"),
                filename=relative,
            )
        except (OSError, SyntaxError, UnicodeError) as exc:
            raise ToolchainControlError(
                f"runtime dependency is unreadable: {relative}"
            ) from exc
        visited.add(relative)
        if not complete_local_universe_scheduled:
            importer = _module_for_path(relative)
            for dependency in sorted(
                _local_import_targets(
                    tree,
                    importer=importer,
                    importer_is_package=path.name == "__init__.py",
                    modules=modules,
                )
            ):
                if dependency not in visited:
                    pending.append(dependency)
            dynamic_targets, unresolved_dynamic = (
                _local_dynamic_import_analysis(
                    tree,
                    modules=modules,
                )
            )
            for dependency in sorted(dynamic_targets):
                if dependency not in visited:
                    pending.append(dependency)
            if unresolved_dynamic:
                # A non-literal local import can select any module in this
                # bounded map.  Once all are scheduled, later import/file
                # graph walks cannot enlarge the Python-source denominator.
                for dependency in sorted(module_paths):
                    if dependency not in visited:
                        pending.append(dependency)
                complete_local_universe_scheduled = True
            else:
                for dependency in sorted(
                    _local_literal_file_targets(
                        tree,
                        importer_relative=relative,
                        module_paths=module_paths,
                    )
                ):
                    if dependency not in visited:
                        pending.append(dependency)
        for declaration in _literal_runtime_asset_declarations(
            tree,
            importer_relative=relative,
        ):
            for asset, kind in _expand_runtime_asset_declaration(
                root,
                declaration,
                importer_relative=relative,
                path_index=path_index,
            ):
                prior = declared_assets.get(asset)
                if prior is not None and prior != kind:
                    raise ToolchainControlError(
                        f"runtime asset kind conflict: {asset}"
                    )
                declared_assets[asset] = kind
    visited.update(declared_assets)
    visited.add(_RUNTIME_CLOSURE_PATH.as_posix())
    # The authority deriving the denominator is itself part of the denominator.
    visited.add("scripts/toolchain_control_authority.py")
    casefolded: dict[str, str] = {}
    for relative in sorted(visited):
        key = relative.casefold()
        prior = casefolded.get(key)
        if prior is not None and prior != relative:
            raise ToolchainControlError(
                "runtime path case-fold alias is not canonical: "
                f"{prior} versus {relative}"
            )
        casefolded[key] = relative
    path_index.verify_unchanged()
    return tuple(sorted(visited))


def _runtime_asset_rows_for_files(
    root: Path,
    files: tuple[str, ...],
) -> tuple[dict[str, str], ...]:
    root = Path(root)
    rows: list[dict[str, str]] = []
    for relative in files:
        if relative == _RUNTIME_CLOSURE_PATH.as_posix():
            continue
        path = root / relative
        kind = "python-source" if relative.endswith(".py") else "runtime-data"
        if relative.startswith("verification_policy/"):
            kind = "control"
        raw = path.read_bytes()
        try:
            canonical = raw.decode("utf-8").replace(
                "\r\n", "\n"
            ).encode("utf-8")
            digest_mode = "utf8-lf-v1"
        except UnicodeError:
            canonical = raw
            digest_mode = "raw-v1"
        rows.append(
            {
                "digest_mode": digest_mode,
                "kind": kind,
                "path": relative,
                "sha256": hashlib.sha256(canonical).hexdigest(),
            }
        )
    return tuple(sorted(rows, key=lambda row: row["path"]))


def derive_runtime_asset_rows(root: Path) -> tuple[dict[str, str], ...]:
    root = Path(root)
    return _runtime_asset_rows_for_files(
        root,
        derive_runtime_dependency_closure(root),
    )


def render_runtime_closure_manifest(root: Path) -> bytes:
    """Render the checked runtime-closure authority deterministically."""

    root = Path(root)
    files = derive_runtime_dependency_closure(root)
    payload = {
        "assets": list(_runtime_asset_rows_for_files(root, files)),
        "derivation": "python-ast-typed-runtime-closure-v2",
        "entrypoints": list(_RUNTIME_ENTRYPOINTS),
        "files": list(files),
        "manifest_control": {
            "kind": "control",
            "path": _RUNTIME_CLOSURE_PATH.as_posix(),
        },
        "schema": _RUNTIME_CLOSURE_SCHEMA,
    }
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("ascii")


def load_runtime_closure_manifest(root: Path) -> dict[str, Any]:
    """Load and strictly validate the shipped runtime closure manifest."""

    path = Path(root) / _RUNTIME_CLOSURE_PATH
    payload = _json_object(
        _read_control(path, "toolchain runtime closure manifest"),
        "toolchain runtime closure manifest",
    )
    if set(payload) != {
        "schema",
        "derivation",
        "entrypoints",
        "files",
        "assets",
        "manifest_control",
    }:
        raise ToolchainControlError(
            "toolchain runtime closure manifest keys are invalid"
        )
    files = payload.get("files")
    assets = payload.get("assets")
    manifest_control = payload.get("manifest_control")
    if (
        payload.get("schema") != _RUNTIME_CLOSURE_SCHEMA
        or payload.get("derivation") != "python-ast-typed-runtime-closure-v2"
        or payload.get("entrypoints") != list(_RUNTIME_ENTRYPOINTS)
        or not isinstance(files, list)
        or files != sorted(set(files))
        or any(
            not isinstance(relative, str)
            or not relative
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
            or "\\" in relative
            for relative in files
        )
        or not isinstance(assets, list)
        or assets != sorted(assets, key=lambda row: row.get("path", ""))
        or len(assets) != len(files) - 1
        or any(
            not isinstance(row, dict)
            or set(row) != {
                "digest_mode",
                "kind",
                "path",
                "sha256",
            }
            or row.get("digest_mode") not in {"utf8-lf-v1", "raw-v1"}
            or row.get("kind")
            not in {"python-source", "runtime-data", "control"}
            or row.get("path") not in files
            or row.get("path") == _RUNTIME_CLOSURE_PATH.as_posix()
            or not isinstance(row.get("sha256"), str)
            or _HEX_64.fullmatch(row["sha256"]) is None
            for row in assets
        )
        or manifest_control
        != {
            "kind": "control",
            "path": _RUNTIME_CLOSURE_PATH.as_posix(),
        }
    ):
        raise ToolchainControlError(
            "toolchain runtime closure manifest is invalid"
        )
    return dict(payload)


def runtime_required_missing(
    root: Path,
    *,
    required_files: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Return the exact shipped runtime/control paths absent from ``root``."""

    required = (
        TOOLCHAIN_RUNTIME_REQUIRED_FILES
        if required_files is None
        else required_files
    )
    expected = {
        row["path"]: (row["digest_mode"], row["sha256"])
        for row in TOOLCHAIN_RUNTIME_ASSET_ROWS
    }
    missing: list[str] = []
    for relative in required:
        path = Path(root) / relative
        if not path.is_file():
            missing.append(relative)
            continue
        digest_row = expected.get(relative)
        if digest_row is not None:
            try:
                raw = path.read_bytes()
                mode, digest = digest_row
                canonical = (
                    raw.decode("utf-8")
                    .replace("\r\n", "\n")
                    .encode("utf-8")
                    if mode == "utf8-lf-v1"
                    else raw
                )
                observed = hashlib.sha256(canonical).hexdigest()
            except (OSError, UnicodeError):
                missing.append(relative)
                continue
            if observed != digest:
                missing.append(relative)
    return tuple(missing)


@dataclass(frozen=True)
class ToolchainControls:
    lock: Mapping[str, Any]
    governance: Mapping[str, Any]
    locked: Mapping[str, Mapping[str, Any]]
    governed: Mapping[str, Mapping[str, Any]]
    lock_sha256: str
    governance_sha256: str
    lock_path: Path
    governance_path: Path


# Identity names, providers, probes, and acquisition specifications are closed
# control semantics.  Keeping this denominator in one shared module ensures a
# data-only edit cannot redirect setup and runtime together to another package.
_IDENTITY_CONTRACTS: dict[str, dict[str, Any]] = {
    "slither": {
        "identity_kind": "python_distribution",
        "package_name": "slither-analyzer",
        "python_module": "slither",
        "expected_version": "0.11.5",
        "install_spec": "slither-analyzer==0.11.5",
        "version_probe": ["python-importlib-metadata", "slither-analyzer"],
        "version_output_parser": "PYTHON_METADATA_EXACT",
    },
    "scip-go": {
        "identity_kind": "command",
        "package_name": "github.com/scip-code/scip-go/cmd/scip-go",
        "go_command_path": "github.com/scip-code/scip-go/cmd/scip-go",
        "go_module_path": "github.com/scip-code/scip-go",
        "expected_version": "0.2.7",
        "install_spec": "github.com/scip-code/scip-go/cmd/scip-go@v0.2.7",
        "version_probe": ["scip-go", "--version"],
        "version_output_parser": "SCIP_GO_EXACT_V1",
    },
    "protobuf": {
        "identity_kind": "python_distribution",
        "package_name": "protobuf",
        "python_module": "google.protobuf",
        "generated_module_path": "plamen_l1/scip_pb2.py",
        "generated_code_version": "7.34.1",
        "expected_version": "7.35.1",
        "install_spec": "protobuf==7.35.1",
        "version_probe": ["python-importlib-metadata", "protobuf"],
        "version_output_parser": "PYTHON_METADATA_EXACT",
    },
}

_LOCKED_CONTENT_AUTHORITY = {
    "mode": "OBSERVED_NONAUTHORITATIVE",
    "reviewed_content_sha256": [],
}
_PROTOBUF_REVIEWED_CONTENT_SCHEMA = "plamen.protobuf_reviewed_content.v1"
_PROTOBUF_REVIEWED_CONTENT_PATH = (
    "verification_policy/protobuf_reviewed_content.v1.json"
)
_PROTOBUF_REVIEWED_KINDS = (
    "wheel",
    "record",
    "normalized_record_rows",
    "distribution_path_set",
    "distribution_files",
    "module",
    "generated_module",
)
_RUNTIME_STATUSES = {
    "MATCH",
    "MISMATCH",
    "UNAVAILABLE",
    "EXTERNAL_MANAGER",
    "DEBT",
    "UNREGISTERED",
    "REVOKED",
    "OBSERVED_NONAUTHORITATIVE",
}


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
    except OSError:
        return True
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & reparse)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
        int(stat.S_IFMT(info.st_mode)),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _reject_alias_ancestry(path: Path, label: str) -> None:
    """Reject symlink/junction/reparse aliases at any lexical path component.

    ``Path.resolve`` cannot be used for this check because it erases the very
    alias boundary being validated.  Walk the absolute lexical path instead,
    including the leaf, and fail closed if any component is unreadable.
    """
    cursor = Path(os.path.abspath(os.fspath(path)))
    while True:
        if cursor.is_symlink() or _is_reparse_point(cursor):
            location = "file" if cursor == Path(os.path.abspath(os.fspath(path))) else "ancestor"
            raise ToolchainControlError(
                f"{label} {location} must not be a symlink, junction, "
                "or reparse point"
            )
        parent = cursor.parent
        if parent == cursor:
            return
        cursor = parent


def _require_canonical_runtime_spelling(
    root: Path,
    relative: str,
    label: str,
    *,
    path_index: _RuntimePathIndex | None = None,
    directory: bool = False,
) -> None:
    """Require exact on-disk component spelling without resolving aliases."""

    index = (
        _RuntimePathIndex(root)
        if path_index is None
        else path_index
    )
    if directory:
        index.require_directory(relative, label)
    else:
        index.require_file(relative, label)
    if path_index is None:
        index.verify_unchanged()


def _read_control(path: Path, label: str) -> bytes:
    path = Path(path)
    try:
        _reject_alias_ancestry(path, label)
        before = path.stat()
        if not stat.S_ISREG(before.st_mode):
            raise ToolchainControlError(f"{label} must be a regular file")
        if int(getattr(before, "st_nlink", 1)) != 1:
            raise ToolchainControlError(
                f"{label} has an unexpected hardlink alias"
            )
        if before.st_size > _MAX_CONTROL_BYTES:
            raise ToolchainControlError(f"{label} exceeds the size ceiling")
        with path.open("rb") as stream:
            opened_before = os.fstat(stream.fileno())
            if _identity(opened_before) != _identity(before):
                raise ToolchainControlError(f"{label} changed before read")
            raw = stream.read(_MAX_CONTROL_BYTES + 1)
            opened_after = os.fstat(stream.fileno())
        after = path.stat()
        _reject_alias_ancestry(path, label)
        if (
            len(raw) > _MAX_CONTROL_BYTES
            or _identity(opened_before) != _identity(opened_after)
            or _identity(before) != _identity(after)
            or int(getattr(after, "st_nlink", 1)) != 1
        ):
            raise ToolchainControlError(f"{label} changed while being read")
        return raw
    except ToolchainControlError:
        raise
    except Exception as exc:
        raise ToolchainControlError(
            f"{label} is unreadable: {type(exc).__name__}"
        ) from exc


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise ToolchainControlError(
            f"{label} is not valid JSON: {type(exc).__name__}"
        ) from exc
    if not isinstance(payload, dict):
        raise ToolchainControlError(f"{label} root must be an object")
    return payload


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _reviewed_content_digest_rows(evidence: Mapping[str, Any]) -> list[dict[str, str]]:
    wheel = evidence.get("wheel")
    record = evidence.get("record")
    closure = evidence.get("installed_closure")
    module = evidence.get("module")
    generated = evidence.get("generated_module")
    if not all(isinstance(value, dict) for value in (
        wheel, record, closure, module, generated
    )):
        raise ToolchainControlError(
            "protobuf reviewed-content evidence is invalid"
        )
    values = (
        wheel.get("sha256"),
        record.get("sha256"),
        record.get("normalized_rows_sha256"),
        closure.get("path_set_sha256"),
        closure.get("files_sha256"),
        module.get("sha256"),
        generated.get("sha256"),
    )
    if any(
        not isinstance(value, str) or _HEX_64.fullmatch(value) is None
        for value in values
    ):
        raise ToolchainControlError(
            "protobuf reviewed-content digest is invalid"
        )
    return [
        {"content_kind": kind, "sha256": digest}
        for kind, digest in zip(_PROTOBUF_REVIEWED_KINDS, values)
    ]


def _validate_protobuf_reviewed_evidence(
    evidence: Mapping[str, Any],
) -> list[dict[str, str]]:
    if set(evidence) != {
        "schema_version",
        "package_name",
        "version",
        "wheel",
        "record",
        "installed_closure",
        "module",
        "generated_module",
    } or (
        evidence.get("schema_version") != _PROTOBUF_REVIEWED_CONTENT_SCHEMA
        or evidence.get("package_name") != "protobuf"
        or evidence.get("version") != "7.35.1"
    ):
        raise ToolchainControlError(
            "protobuf reviewed-content evidence schema is invalid"
        )
    wheel = evidence["wheel"]
    record = evidence["record"]
    closure = evidence["installed_closure"]
    module = evidence["module"]
    generated = evidence["generated_module"]
    if (
        set(wheel) != {
            "filename", "bytes", "sha256", "python_tag", "abi_tag",
            "platform_tag",
        }
        or wheel.get("filename")
        != "protobuf-7.35.1-cp310-abi3-win_amd64.whl"
        or wheel.get("bytes") != 439996
        or wheel.get("sha256")
        != "230a75ddfc2de4806e56696ce9640c1cdfdb6543b7cfce98d42a4c0a0e7bdb87"
        or wheel.get("python_tag") != "cp310"
        or wheel.get("abi_tag") != "abi3"
        or wheel.get("platform_tag") != "win_amd64"
    ):
        raise ToolchainControlError(
            "protobuf reviewed wheel identity is invalid"
        )
    record_rows = record.get("rows") if isinstance(record, dict) else None
    members = closure.get("members") if isinstance(closure, dict) else None
    if (
        not isinstance(record_rows, list)
        or not record_rows
        or record.get("path") != "protobuf-7.35.1.dist-info/RECORD"
        or record.get("row_count") != len(record_rows)
        or not isinstance(record.get("bytes"), int)
        or not isinstance(members, list)
        or not members
        or closure.get("file_count") != len(members)
        or not isinstance(closure.get("logical_bytes"), int)
        or set(module) != {"name", "path", "bytes", "sha256"}
        or module.get("name") != "google.protobuf"
        or module.get("path") != "google/protobuf/__init__.py"
        or set(generated) != {"path", "version", "bytes", "sha256"}
        or generated.get("path") != "plamen_l1/scip_pb2.py"
        or generated.get("version") != "7.34.1"
    ):
        raise ToolchainControlError(
            "protobuf installed-content evidence is invalid"
        )
    paths: list[str] = []
    for row in record_rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "hash", "bytes"}
            or not isinstance(row.get("path"), str)
            or not row["path"]
            or row["path"].startswith("/")
            or ".." in Path(row["path"]).parts
            or not isinstance(row.get("hash"), str)
            or not isinstance(row.get("bytes"), (int, type(None)))
        ):
            raise ToolchainControlError(
                "protobuf normalized RECORD row is invalid"
            )
        paths.append(row["path"])
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ToolchainControlError(
            "protobuf normalized RECORD rows are not a unique sorted set"
        )
    normalized_rows = hashlib.sha256(
        _canonical_json_bytes(record_rows)
    ).hexdigest()
    if normalized_rows != record.get("normalized_rows_sha256"):
        raise ToolchainControlError(
            "protobuf normalized RECORD digest is invalid"
        )
    member_paths: list[str] = []
    path_set = hashlib.sha256()
    contents = hashlib.sha256()
    logical_bytes = 0
    for member in members:
        if (
            not isinstance(member, dict)
            or set(member) != {"path", "sha256", "bytes"}
            or not isinstance(member.get("path"), str)
            or not member["path"]
            or member["path"].startswith("/")
            or ".." in Path(member["path"]).parts
            or not isinstance(member.get("sha256"), str)
            or _HEX_64.fullmatch(member["sha256"]) is None
            or not isinstance(member.get("bytes"), int)
            or member["bytes"] < 0
        ):
            raise ToolchainControlError(
                "protobuf installed-closure member is invalid"
            )
        name = member["path"]
        encoded = name.encode("utf-8")
        path_set.update(len(encoded).to_bytes(8, "big"))
        path_set.update(encoded)
        contents.update(len(encoded).to_bytes(8, "big"))
        contents.update(encoded)
        contents.update(bytes.fromhex(member["sha256"]))
        contents.update(member["bytes"].to_bytes(8, "big"))
        logical_bytes += member["bytes"]
        member_paths.append(name)
    if (
        member_paths != sorted(member_paths)
        or len(member_paths) != len(set(member_paths))
        or closure.get("logical_bytes") != logical_bytes
        or closure.get("path_set_sha256") != path_set.hexdigest()
        or closure.get("files_sha256") != contents.hexdigest()
        or module.get("path") not in member_paths
        or record.get("path") not in member_paths
    ):
        raise ToolchainControlError(
            "protobuf installed-closure digest is invalid"
        )
    return _reviewed_content_digest_rows(evidence)


def _validate_lock(
    lock: Mapping[str, Any],
    *,
    repository_root: Path,
) -> dict[str, dict[str, Any]]:
    identities = lock.get("identities")
    if (
        lock.get("schema_version") != TOOLCHAIN_VERSION_LOCK_SCHEMA
        or not isinstance(identities, list)
        or len(identities) != len(_IDENTITY_CONTRACTS)
    ):
        raise ToolchainControlError("toolchain version lock schema is invalid")
    locked: dict[str, dict[str, Any]] = {}
    for row in identities:
        if not isinstance(row, dict):
            raise ToolchainControlError(
                "toolchain version lock identity is invalid"
            )
        identity_id = str(row.get("identity_id") or "")
        contract = _IDENTITY_CONTRACTS.get(identity_id)
        if contract is None or identity_id in locked:
            raise ToolchainControlError(
                "toolchain version lock identity is invalid"
            )
        for field, expected in contract.items():
            if row.get(field) != expected:
                if field in {
                    "generated_module_path",
                    "generated_code_version",
                }:
                    raise ToolchainControlError(
                        "toolchain version-lock generated/runtime identity "
                        "binding "
                        f"is invalid: {identity_id}:{field}"
                    )
                raise ToolchainControlError(
                    f"toolchain version-lock identity/probe is invalid: "
                    f"{identity_id}:{field}"
                )
        content_authority = row.get("content_authority")
        content_valid = content_authority == _LOCKED_CONTENT_AUTHORITY
        if identity_id == "protobuf":
            if not isinstance(content_authority, dict) or set(content_authority) != {
                "mode",
                "evidence_path",
                "evidence_schema",
                "evidence_sha256",
                "reviewed_content_sha256",
            }:
                content_valid = False
            else:
                evidence_path = content_authority.get("evidence_path")
                evidence_digest = content_authority.get("evidence_sha256")
                content_valid = bool(
                    content_authority.get("mode") == "REVIEWED_CONTENT_MATCH"
                    and evidence_path == _PROTOBUF_REVIEWED_CONTENT_PATH
                    and content_authority.get("evidence_schema")
                    == _PROTOBUF_REVIEWED_CONTENT_SCHEMA
                    and isinstance(evidence_digest, str)
                    and _HEX_64.fullmatch(evidence_digest) is not None
                )
                if content_valid:
                    evidence_file = repository_root / str(evidence_path)
                    evidence_raw = _read_control(
                        evidence_file,
                        "protobuf reviewed-content evidence",
                    )
                    if hashlib.sha256(evidence_raw).hexdigest() != evidence_digest:
                        raise ToolchainControlError(
                            "protobuf reviewed-content evidence digest is invalid"
                        )
                    else:
                        evidence = _json_object(
                            evidence_raw,
                            "protobuf reviewed-content evidence",
                        )
                        content_valid = (
                            content_authority.get("reviewed_content_sha256")
                            == _validate_protobuf_reviewed_evidence(evidence)
                        )
                        if not content_valid:
                            raise ToolchainControlError(
                                "protobuf reviewed-content digest rows are invalid"
                            )
        if (
            row.get("acquisition_scope") != "SETUP_ONLY"
            or row.get("deterministic_provider_authority_requires")
            != "REVIEWED_CONTENT_MATCH"
            or not content_valid
            or not _SEMVER.fullmatch(str(row.get("expected_version") or ""))
        ):
            raise ToolchainControlError(
                f"toolchain version lock identity is invalid: {identity_id}"
            )
        rationale = str(row.get("version_rationale") or "").strip()
        evidence = row.get("release_evidence")
        if (
            not rationale
            or not isinstance(evidence, list)
            or not evidence
            or any(
                not isinstance(item, dict)
                or not str(item.get("authority") or "").strip()
                or not str(item.get("url") or "").startswith("https://")
                or not str(item.get("supports") or "").strip()
                for item in evidence
            )
        ):
            raise ToolchainControlError(
                f"toolchain version lock release evidence is invalid: "
                f"{identity_id}"
            )
        locked[identity_id] = dict(row)
    if set(locked) != set(_IDENTITY_CONTRACTS):
        raise ToolchainControlError(
            "toolchain version lock identities are incomplete"
        )
    return locked


def _valid_revocation(value: Any) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "blocked_version_substrings",
        "blocked_executable_sha256",
    }:
        return False
    versions = value["blocked_version_substrings"]
    digests = value["blocked_executable_sha256"]
    return bool(
        isinstance(versions, list)
        and all(
            isinstance(token, str) and 0 < len(token.strip()) <= 128
            for token in versions
        )
        and isinstance(digests, list)
        and all(
            isinstance(digest, str)
            and _HEX_64.fullmatch(digest.casefold()) is not None
            for digest in digests
        )
    )


def _validate_governance(
    governance: Mapping[str, Any],
    *,
    observed_lock_sha256: str,
    locked: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    reviewed = governance.get("reviewed_version_lock")
    tools = governance.get("tools")
    if (
        governance.get("schema_version") != TOOLCHAIN_GOVERNANCE_SCHEMA
        or not isinstance(reviewed, dict)
        or reviewed.get("path")
        != f"verification_policy/{TOOLCHAIN_VERSION_LOCK_FILENAME}"
        or reviewed.get("schema_version") != TOOLCHAIN_VERSION_LOCK_SCHEMA
        or reviewed.get("sha256") != observed_lock_sha256
        or not isinstance(reviewed.get("runtime_statuses"), list)
        or set(reviewed["runtime_statuses"]) != _RUNTIME_STATUSES
        or len(reviewed["runtime_statuses"])
        != len(set(reviewed["runtime_statuses"]))
        or not isinstance(tools, list)
        or not tools
    ):
        raise ToolchainControlError(
            "toolchain governance/version-lock digest or schema is invalid"
        )
    governed: dict[str, dict[str, Any]] = {}
    references: dict[str, list[str]] = {}
    for row in tools:
        if not isinstance(row, dict):
            raise ToolchainControlError(
                "toolchain governance identity is invalid"
            )
        tool_id = str(row.get("tool_id") or "").strip()
        update = row.get("update_policy")
        authority = row.get("runtime_authority")
        if (
            not tool_id
            or tool_id in governed
            or not isinstance(update, dict)
            or not isinstance(authority, dict)
            or not _valid_revocation(row.get("revocation_policy"))
            or not str(row.get("version_policy") or "").strip()
            or not str(row.get("integrity_policy") or "").strip()
        ):
            raise ToolchainControlError(
                f"toolchain governance identity/revocation is invalid: "
                f"{tool_id}"
            )
        state = str(update.get("state") or "")
        scope = str(update.get("acquisition_scope") or "")
        semantic_match = False
        if state == "REVIEWED_VERSION_OBSERVED_CONTENT":
            reference = str(update.get("version_lock_identity") or "")
            if tool_id not in locked or reference != tool_id:
                raise ToolchainControlError(
                    "each version-lock identity must have exactly one "
                    f"matching governance row: {tool_id}"
                )
            semantic_match = (
                scope == "SETUP_ONLY"
                and authority
                == {
                    "identity_status": "OBSERVED_NONAUTHORITATIVE",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": (
                        "NO_AUTHORITY_WITHOUT_REVIEWED_CONTENT"
                    ),
                }
            )
            if reference:
                references.setdefault(reference, []).append(tool_id)
        elif state == "REVIEWED_CONTENT_MATCH":
            reference = str(update.get("version_lock_identity") or "")
            locked_row = locked.get(tool_id)
            semantic_match = bool(
                tool_id == "protobuf"
                and reference == tool_id
                and locked_row is not None
                and locked_row.get("content_authority", {}).get("mode")
                == "REVIEWED_CONTENT_MATCH"
                and scope == "SETUP_ONLY"
                and authority
                == {
                    "identity_status": "MATCH",
                    "deterministic_provider_authority": True,
                    "mismatch_effect": (
                        "REVOKE_ON_REVIEWED_CONTENT_MISMATCH"
                    ),
                }
            )
            if reference:
                references.setdefault(reference, []).append(tool_id)
        elif state == "GOVERNED_DEBT":
            semantic_match = (
                scope == "SETUP_ONLY"
                and update.get("unresolved_debt") is True
                and bool(str(update.get("reason") or "").strip())
                and authority
                == {
                    "identity_status": "DEBT",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": (
                        "CAPABILITY_DEBT_NO_CLEAN_AUTHORITY"
                    ),
                }
            )
        elif state in {
            "EXTERNAL_TOOLCHAIN_MANAGER",
            "EXTERNAL_PLATFORM_MANAGER",
        }:
            semantic_match = (
                scope == "EXTERNAL_OPERATOR_SETUP"
                and authority
                == {
                    "identity_status": "EXTERNAL_MANAGER",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "SNAPSHOT_OBSERVED_IDENTITY_ONLY",
                }
            )
        elif state == "HUMAN_REVIEWED_DIGEST_REQUIRED":
            semantic_match = (
                scope == "EXTERNAL_OPERATOR_SETUP"
                and authority
                == {
                    "identity_status": "DEBT",
                    "deterministic_provider_authority": False,
                    "mismatch_effect": "FAIL_WITHOUT_REVIEWED_DIGEST",
                }
            )
        if not semantic_match:
            raise ToolchainControlError(
                f"toolchain governance semantics are invalid: {tool_id}"
            )
        governed[tool_id] = dict(row)
    if any(references.get(identity) != [identity] for identity in locked):
        raise ToolchainControlError(
            "each version-lock identity must have exactly one matching "
            "governance row"
        )
    if set(references) != set(locked):
        raise ToolchainControlError(
            "toolchain governance references an unknown version-lock identity"
        )
    return governed


def load_toolchain_controls(
    governance_path: Path,
    lock_path: Path | None = None,
) -> ToolchainControls:
    """Read and validate one exact governance/version-lock pair once."""

    governance_path = Path(governance_path)
    lock_path = (
        Path(lock_path)
        if lock_path is not None
        else governance_path.parent / TOOLCHAIN_VERSION_LOCK_FILENAME
    )
    lock_raw = _read_control(lock_path, "toolchain version lock")
    governance_raw = _read_control(
        governance_path, "toolchain governance"
    )
    lock = _json_object(lock_raw, "toolchain version lock")
    governance = _json_object(governance_raw, "toolchain governance")
    lock_digest = hashlib.sha256(lock_raw).hexdigest()
    governance_digest = hashlib.sha256(governance_raw).hexdigest()
    reviewed = governance.get("reviewed_version_lock")
    if (
        not isinstance(reviewed, dict)
        or reviewed.get("sha256") != lock_digest
    ):
        raise ToolchainControlError(
            "toolchain governance/version-lock digest is invalid"
        )
    locked = _validate_lock(
        lock,
        # Reviewed content is a packaged runtime asset, never a sibling chosen
        # by a caller-supplied temporary control-pair location.
        repository_root=_MODULE_ROOT,
    )
    governed = _validate_governance(
        governance,
        observed_lock_sha256=lock_digest,
        locked=locked,
    )
    return ToolchainControls(
        lock=lock,
        governance=governance,
        locked=locked,
        governed=governed,
        lock_sha256=lock_digest,
        governance_sha256=governance_digest,
        lock_path=lock_path,
        governance_path=governance_path,
    )


_MODULE_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices={"render-runtime-closure"},
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.write_bytes(render_runtime_closure_manifest(args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

if (_MODULE_ROOT / _RUNTIME_CLOSURE_PATH).is_file():
    _RUNTIME_MANIFEST = load_runtime_closure_manifest(_MODULE_ROOT)
    TOOLCHAIN_RUNTIME_REQUIRED_FILES = tuple(_RUNTIME_MANIFEST["files"])
    TOOLCHAIN_RUNTIME_ASSET_ROWS = tuple(_RUNTIME_MANIFEST["assets"])
else:
    # Bootstrap only: once the generated manifest is checked in, every public
    # install consumes that exact denominator and fails closed if it is invalid.
    TOOLCHAIN_RUNTIME_REQUIRED_FILES = derive_runtime_dependency_closure(
        _MODULE_ROOT
    )
    TOOLCHAIN_RUNTIME_ASSET_ROWS = derive_runtime_asset_rows(_MODULE_ROOT)
