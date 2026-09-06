"""Deterministic static inventory for mechanical-gate registry v2.

The inventory is deliberately an observation/validation tool.  It neither
wraps production decisions nor grants runtime authority.  Dynamic decision
identities, aliases of the registry API, reflection, unreviewed code drift, and
direct calls around a declared wrapper are rejected instead of guessed.

During Stage 1, source-bound ``LEGACY_NOT_MIGRATED`` rows describe current
production owners without claiming that literal governance wrappers exist.
Where a safe transitive AST closure cannot be derived, the legacy row binds the
complete owner-module bytes under an explicit conservative algorithm.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
import fnmatch
from functools import cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Mapping, Sequence
import unicodedata

from mechanical_gate_registry import (
    ACTIVATION_RUNTIME_STATES,
    BACKENDS,
    DECISION_CODE_DIGEST_ALGORITHM,
    ECOSYSTEMS,
    GateActivation,
    LEGACY_MODULE_CODE_DIGEST_ALGORITHM,
    LIFECYCLE_STATES,
    MechanicalGateRegistry,
    MODES,
    PHASES,
    PIPELINES,
    RUNTIME_COUNTED_STATES,
    SOURCE_TREE_DIGEST_ALGORITHM,
    validate_mechanical_gate_registry,
)


INVENTORY_SCHEMA_VERSION = (
    "plamen.mechanical_gate_activation_inventory.v1"
)
GENERATOR_VERSION = "plamen.mechanical_gate_inventory.stage1-v1"
_REGISTER_APIS = frozenset(
    {"evaluate_registered_gate", "record_registered_gate"}
)
_REGISTER_API_MODULE = "mechanical_gate_runtime"
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._][a-z0-9]+)+$")
_SYMBOL_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$"
)
_SAFE_BUILTIN_CALLS = frozenset(
    {
        "all",
        "any",
        "bool",
        "dict",
        "enumerate",
        "int",
        "isinstance",
        "len",
        "list",
        "max",
        "min",
        "range",
        "set",
        "sorted",
        "str",
        "sum",
        "tuple",
        "zip",
    }
)
_REPARSE_ATTRIBUTE = 0x400
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_TREE_BYTES = 1024 * 1024 * 1024
MAX_SOURCE_FILE_COUNT = 100_000
PORTABLE_SOURCE_FILE_MODE = 0o644
PORTABLE_EXECUTABLE_SOURCE_FILE_MODE = 0o755
_INVENTORY_KEYS = frozenset(
    {
        "schema_version",
        "source_tree_digest_algorithm",
        "source_tree_digest",
        "generator_version",
        "generator_digest",
        "runtime_authority_granted",
        "activations",
    }
)
_INVENTORY_ROW_KEYS = frozenset(
    {
        "gate_id",
        "activation_id",
        "module",
        "wrapper_symbol",
        "implementation_symbols",
        "hook_id",
        "source_line",
        "phases",
        "pipelines",
        "modes",
        "ecosystems",
        "backends",
        "lifecycle_state",
        "runtime_state",
        "decision_code_digest_algorithm",
        "code_digest",
        "source_tree_digest",
        "literal_runtime_registration_present",
    }
)


class ActivationInventoryError(ValueError):
    """Literal discovery, source identity, or parity validation failed."""


@dataclass(frozen=True, slots=True)
class LiteralActivation:
    gate_id: str
    activation_id: str
    module: str
    wrapper_symbol: str
    source_line: int
    evaluator_symbol: str | None
    api_symbol: str


@dataclass(frozen=True, slots=True)
class _ParsedModule:
    relative_path: str
    module_name: str
    path: Path
    tree: ast.Module
    source_sha256: str


@dataclass(frozen=True, slots=True)
class _SourceEntry:
    relative_path: str
    path: Path
    raw: bytes
    mode: int
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _SourceSnapshot:
    root: Path
    entries: tuple[_SourceEntry, ...]


@dataclass(frozen=True, slots=True)
class _SymbolNode:
    module_path: str
    module_name: str
    symbol: str
    node: ast.AST


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ActivationInventoryError(
            "inventory value is not canonical JSON"
        ) from exc


def _is_excluded(relative: str, patterns: Sequence[str]) -> bool:
    pure = PurePosixPath(relative)
    for pattern in patterns:
        normalized = pattern.replace("\\", "/")
        if pure.match(normalized) or fnmatch.fnmatchcase(relative, normalized):
            return True
    return False


def _reject_source_alias_components(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ActivationInventoryError(
            "production source escaped the source root"
        ) from exc
    cursor = root
    for component in relative.parts:
        cursor = cursor / component
        try:
            row = cursor.lstat()
        except OSError as exc:
            raise ActivationInventoryError(
                "production source component cannot be inspected"
            ) from exc
        if stat.S_ISLNK(row.st_mode) or bool(
            getattr(row, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
        ):
            raise ActivationInventoryError(
                "production source path contains a symlink or reparse point"
            )


def _production_files(
    source_root: Path | str,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> tuple[Path, tuple[Path, ...]]:
    lexical_root = Path(source_root)
    root_parts = lexical_root.parts
    colon_parts = (
        root_parts[1:]
        if lexical_root.drive and root_parts
        else root_parts
    )
    if any(":" in component for component in colon_parts):
        raise ActivationInventoryError(
            "source root contains a noncanonical stream-qualified component"
        )
    try:
        lexical_row = lexical_root.lstat()
    except OSError as exc:
        raise ActivationInventoryError(
            "source root cannot be inspected before resolution"
        ) from exc
    if stat.S_ISLNK(lexical_row.st_mode) or bool(
        getattr(lexical_row, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    ):
        raise ActivationInventoryError(
            "source root is a symlink or reparse point"
        )
    try:
        root = lexical_root.resolve(strict=True)
    except OSError as exc:
        raise ActivationInventoryError(
            "source root cannot be resolved"
        ) from exc
    if not root.is_dir():
        raise ActivationInventoryError("source root is not a directory")
    result: list[Path] = []
    for declared in production_roots:
        normalized_declared = (
            declared.replace("\\", "/")
            if isinstance(declared, str)
            else ""
        )
        if (
            not isinstance(declared, str)
            or not declared
            or normalized_declared.startswith("/")
            or ":" in normalized_declared
            or ".." in normalized_declared.split("/")
        ):
            raise ActivationInventoryError(
                "production root is not a safe relative path"
            )
        candidate = root / declared
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ActivationInventoryError(
                "production root escapes or is absent"
            ) from exc
        row = candidate.lstat()
        if stat.S_ISLNK(row.st_mode) or bool(
            getattr(row, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
        ):
            raise ActivationInventoryError(
                "production root is a symlink or reparse point"
            )
        if not stat.S_ISDIR(row.st_mode):
            raise ActivationInventoryError(
                "production root is not a directory"
            )
        for path in resolved.rglob("*.py"):
            relative = path.relative_to(root).as_posix()
            if _is_excluded(relative, production_excludes):
                continue
            _reject_source_alias_components(root, path)
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or bool(
                getattr(info, "st_file_attributes", 0)
                & _REPARSE_ATTRIBUTE
            ):
                raise ActivationInventoryError(
                    f"production source is aliased: {relative}"
                )
            if not stat.S_ISREG(info.st_mode):
                raise ActivationInventoryError(
                    f"production source is not regular: {relative}"
                )
            result.append(path)
    unique = sorted(
        set(result),
        key=lambda item: item.relative_to(root).as_posix().encode("utf-8"),
    )
    spellings: dict[str, str] = {}
    for path in unique:
        relative = path.relative_to(root).as_posix()
        folded = relative.casefold()
        previous = spellings.setdefault(folded, relative)
        if previous != relative:
            raise ActivationInventoryError(
                "production modules collide under filesystem case folding"
            )
    return root, tuple(unique)


def _source_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(
            getattr(
                info,
                "st_ctime_ns",
                int(info.st_ctime * 1_000_000_000),
            )
        ),
    )


def _source_path_identity(info: os.stat_result) -> tuple[int, ...]:
    """Fields reported consistently by path-stat and descriptor-stat."""

    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _read_source_entry(root: Path, path: Path) -> _SourceEntry:
    relative = path.relative_to(root).as_posix()
    try:
        lexical = path.lstat()
    except OSError as exc:
        raise ActivationInventoryError(
            f"production source cannot be inspected: {relative}"
        ) from exc
    if (
        not stat.S_ISREG(lexical.st_mode)
        or stat.S_ISLNK(lexical.st_mode)
        or bool(
            getattr(lexical, "st_file_attributes", 0)
            & _REPARSE_ATTRIBUTE
        )
    ):
        raise ActivationInventoryError(
            f"production source is not a direct regular file: {relative}"
        )
    if lexical.st_size > MAX_SOURCE_FILE_BYTES:
        raise ActivationInventoryError(
            f"production source exceeds the per-file byte bound: {relative}"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _source_path_identity(lexical)
            != _source_path_identity(opened)
        ):
            raise ActivationInventoryError(
                f"production source identity changed before open: {relative}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(
                descriptor,
                min(65536, MAX_SOURCE_FILE_BYTES + 1 - total),
            )
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > MAX_SOURCE_FILE_BYTES:
                raise ActivationInventoryError(
                    "production source exceeds the per-file byte bound: "
                    f"{relative}"
                )
        after = os.fstat(descriptor)
        try:
            lexical_after = path.lstat()
        except OSError as exc:
            raise ActivationInventoryError(
                f"production source disappeared during capture: {relative}"
            ) from exc
        if (
            _source_identity(opened) != _source_identity(after)
            or _source_identity(lexical) != _source_identity(lexical_after)
            or _source_path_identity(after)
            != _source_path_identity(lexical_after)
        ):
            raise ActivationInventoryError(
                f"production source changed during capture: {relative}"
            )
    except ActivationInventoryError:
        raise
    except OSError as exc:
        raise ActivationInventoryError(
            f"production source cannot be captured: {relative}"
        ) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) != opened.st_size:
        raise ActivationInventoryError(
            f"production source size changed during capture: {relative}"
        )
    return _SourceEntry(
        relative_path=relative,
        path=path,
        raw=raw,
        mode=stat.S_IMODE(opened.st_mode),
        device=int(opened.st_dev),
        inode=int(opened.st_ino),
        size=len(raw),
        modified_ns=int(opened.st_mtime_ns),
        changed_ns=int(
            getattr(
                opened,
                "st_ctime_ns",
                int(opened.st_ctime * 1_000_000_000),
            )
        ),
    )


def _capture_source_snapshot_once(
    source_root: Path | str,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> _SourceSnapshot:
    root, paths = _production_files(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    if len(paths) > MAX_SOURCE_FILE_COUNT:
        raise ActivationInventoryError(
            "production source exceeds the file-count bound"
        )
    entries: list[_SourceEntry] = []
    total = 0
    for path in paths:
        entry = _read_source_entry(root, path)
        total += entry.size
        if total > MAX_SOURCE_TREE_BYTES:
            raise ActivationInventoryError(
                "production source exceeds the total byte bound"
            )
        entries.append(entry)
    return _SourceSnapshot(root=root, entries=tuple(entries))


def _snapshot_signature(
    snapshot: _SourceSnapshot,
) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        (
            entry.relative_path,
            entry.mode,
            entry.device,
            entry.inode,
            entry.size,
            entry.modified_ns,
            entry.changed_ns,
            hashlib.sha256(entry.raw).hexdigest(),
        )
        for entry in snapshot.entries
    )


def _assert_snapshot_current(
    snapshot: _SourceSnapshot,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> None:
    observed = _capture_source_snapshot_once(
        snapshot.root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    if (
        observed.root != snapshot.root
        or _snapshot_signature(observed) != _snapshot_signature(snapshot)
    ):
        raise ActivationInventoryError(
            "production source generation changed during inventory construction"
        )


def _capture_source_snapshot(
    source_root: Path | str,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> _SourceSnapshot:
    snapshot = _capture_source_snapshot_once(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    _assert_snapshot_current(
        snapshot,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    return snapshot


def _parse_snapshot(
    snapshot: _SourceSnapshot,
) -> tuple[_ParsedModule, ...]:
    modules: list[_ParsedModule] = []
    for entry in snapshot.entries:
        try:
            text = entry.raw.decode("utf-8", errors="strict")
            tree = ast.parse(text, filename=entry.relative_path)
        except (UnicodeDecodeError, SyntaxError) as exc:
            raise ActivationInventoryError(
                f"cannot parse production source: {entry.relative_path}"
            ) from exc
        module_name = entry.relative_path[:-3].replace("/", ".")
        if module_name.endswith(".__init__"):
            module_name = module_name[: -len(".__init__")]
        modules.append(
            _ParsedModule(
                relative_path=entry.relative_path,
                module_name=module_name,
                path=entry.path,
                tree=tree,
                source_sha256=hashlib.sha256(entry.raw).hexdigest(),
            )
        )
    return tuple(modules)


def _parse_modules(
    source_root: Path | str,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> tuple[Path, tuple[_ParsedModule, ...]]:
    snapshot = _capture_source_snapshot(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    return snapshot.root, _parse_snapshot(snapshot)


def _source_tree_digest_from_snapshot(snapshot: _SourceSnapshot) -> str:
    def portable_mode(entry: _SourceEntry) -> int:
        return (
            PORTABLE_EXECUTABLE_SOURCE_FILE_MODE
            if entry.mode & 0o111
            else PORTABLE_SOURCE_FILE_MODE
        )

    envelope = {
        "algorithm": SOURCE_TREE_DIGEST_ALGORITHM,
        "entries": [
            {
                "path": entry.relative_path,
                "mode": portable_mode(entry),
                "size": entry.size,
                "sha256": hashlib.sha256(entry.raw).hexdigest(),
            }
            for entry in snapshot.entries
        ],
    }
    return hashlib.sha256(_canonical_bytes(envelope)).hexdigest()


def compute_source_tree_digest(
    source_root: Path | str,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> str:
    """Bind normalized relative name, mode, size, and bytes for every source."""

    snapshot = _capture_source_snapshot(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    return _source_tree_digest_from_snapshot(snapshot)


def _call_leaf(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _reference_symbol(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cursor: ast.AST = node
        while isinstance(cursor, ast.Attribute):
            parts.append(cursor.attr)
            cursor = cursor.value
        if isinstance(cursor, ast.Name):
            parts.append(cursor.id)
            return ".".join(reversed(parts))
    return None


def _namespace_reflection_root(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and _call_leaf(node.func) in {
            "globals",
            "locals",
            "vars",
            "__import__",
        }
    ) or (
        isinstance(node, ast.Attribute)
        and node.attr == "__dict__"
    )


def _safe_literal_namespace_get(node: ast.AST | None) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and _namespace_reflection_root(node.func.value)
        and 1 <= len(node.args) <= 2
        and not node.keywords
    ):
        return False
    key = _constant_string(node.args[0])
    if key is None or key in _REGISTER_APIS:
        return False
    return (
        len(node.args) == 1
        or not _contains_namespace_authority(node.args[1])
    )


@cache
def _contains_namespace_authority(node: ast.AST | None) -> bool:
    """Track namespace capabilities through arbitrary AST composition."""

    if node is None:
        return False
    if _safe_literal_namespace_get(node):
        return False
    if (
        isinstance(node, ast.Name)
        and node.id in {"globals", "locals", "vars", "__import__"}
    ):
        return True
    if _namespace_reflection_root(node):
        return True
    return any(
        _contains_namespace_authority(child)
        for child in ast.iter_child_nodes(node)
    )


@cache
def _contains_registered_api_reference(node: ast.AST | None) -> bool:
    if node is None:
        return False
    if (
        isinstance(node, (ast.Name, ast.Attribute))
        and _call_leaf(node) in _REGISTER_APIS
    ):
        return True
    return any(
        _contains_registered_api_reference(child)
        for child in ast.iter_child_nodes(node)
    )


def _constant_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _constant_string(node.left)
        right = _constant_string(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not (
                isinstance(value, ast.Constant)
                and type(value.value) is str
            ):
                return None
            parts.append(value.value)
        return "".join(parts)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        template = _constant_string(node.func.value)
        if template is None:
            return None
        positional: list[str] = []
        for argument in node.args:
            value = _constant_string(argument)
            if value is None:
                return None
            positional.append(value)
        keywords: dict[str, str] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                return None
            value = _constant_string(keyword.value)
            if value is None:
                return None
            keywords[keyword.arg] = value
        try:
            return template.format(*positional, **keywords)
        except (IndexError, KeyError, ValueError):
            return None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _constant_string(node.func.value)
        if separator is None:
            return None
        parts: list[str] = []
        for element in node.args[0].elts:
            value = _constant_string(element)
            if value is None:
                return None
            parts.append(value)
        return separator.join(parts)
    return None


def _literal_truth_value(node: ast.AST) -> bool | None:
    """Return a truth value only when Python semantics are statically exact."""

    unknown = _STATIC_VALUE_UNKNOWN
    scalar = _literal_scalar_value(node)
    if scalar is not unknown:
        return bool(scalar)
    cardinality = _literal_container_cardinality(node)
    if cardinality is not None:
        return cardinality != 0
    if isinstance(node, ast.Compare):
        values = (
            _literal_scalar_value(node.left),
            *(_literal_scalar_value(item) for item in node.comparators),
        )
        if any(value is unknown for value in values):
            return None
        comparisons = zip(values, node.ops, values[1:])
        try:
            return all(
                _apply_static_comparison(left, operator, right)
                for left, operator, right in comparisons
            )
        except (TypeError, ValueError):
            return None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _literal_truth_value(node.operand)
        return None if operand is None else not operand
    if isinstance(node, ast.BoolOp):
        values = tuple(_literal_truth_value(value) for value in node.values)
        if isinstance(node.op, ast.And):
            if False in values:
                return False
            if values and all(value is True for value in values):
                return True
        if isinstance(node.op, ast.Or):
            if True in values:
                return True
            if values and all(value is False for value in values):
                return False
    return None


_STATIC_VALUE_UNKNOWN = object()


def _literal_container_cardinality(node: ast.AST) -> int | None:
    if (
        isinstance(node, ast.Constant)
        and type(node.value) in {str, bytes}
    ):
        return len(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        total = 0
        for element in node.elts:
            if isinstance(element, ast.Starred):
                nested = _literal_container_cardinality(element.value)
                if nested is None:
                    return None
                total += nested
            else:
                total += 1
        return total
    if isinstance(node, ast.Dict):
        total = 0
        for key, value in zip(node.keys, node.values):
            if key is None:
                nested = _literal_container_cardinality(value)
                if nested is None:
                    return None
                total += nested
            else:
                total += 1
        return total
    return None


def _literal_scalar_value(node: ast.AST) -> object:
    if isinstance(node, ast.Constant):
        value = node.value
        if value is None or type(value) in {
            bool,
            int,
            float,
            complex,
            str,
            bytes,
        }:
            return value
    if isinstance(node, ast.UnaryOp):
        operand = _literal_scalar_value(node.operand)
        if operand is _STATIC_VALUE_UNKNOWN:
            return _STATIC_VALUE_UNKNOWN
        try:
            if isinstance(node.op, ast.UAdd):
                result = +operand  # type: ignore[operator]
            elif isinstance(node.op, ast.USub):
                result = -operand  # type: ignore[operator]
            elif isinstance(node.op, ast.Invert):
                result = ~operand  # type: ignore[operator]
            else:
                return _STATIC_VALUE_UNKNOWN
        except (TypeError, ValueError, OverflowError):
            return _STATIC_VALUE_UNKNOWN
        return _bounded_static_scalar(result)
    if isinstance(node, ast.BinOp):
        left = _literal_scalar_value(node.left)
        right = _literal_scalar_value(node.right)
        if (
            left is _STATIC_VALUE_UNKNOWN
            or right is _STATIC_VALUE_UNKNOWN
        ):
            return _STATIC_VALUE_UNKNOWN
        try:
            if isinstance(node.op, ast.Add):
                result = left + right  # type: ignore[operator]
            elif isinstance(node.op, ast.Sub):
                result = left - right  # type: ignore[operator]
            elif isinstance(node.op, ast.Mult):
                result = left * right  # type: ignore[operator]
            elif isinstance(node.op, ast.FloorDiv):
                result = left // right  # type: ignore[operator]
            elif isinstance(node.op, ast.Mod):
                result = left % right  # type: ignore[operator]
            elif isinstance(node.op, ast.Pow):
                result = left**right  # type: ignore[operator]
            elif isinstance(node.op, ast.LShift):
                result = left << right  # type: ignore[operator]
            elif isinstance(node.op, ast.RShift):
                result = left >> right  # type: ignore[operator]
            elif isinstance(node.op, ast.BitOr):
                result = left | right  # type: ignore[operator]
            elif isinstance(node.op, ast.BitXor):
                result = left ^ right  # type: ignore[operator]
            elif isinstance(node.op, ast.BitAnd):
                result = left & right  # type: ignore[operator]
            else:
                return _STATIC_VALUE_UNKNOWN
        except (TypeError, ValueError, ZeroDivisionError, OverflowError):
            return _STATIC_VALUE_UNKNOWN
        return _bounded_static_scalar(result)
    return _STATIC_VALUE_UNKNOWN


def _bounded_static_scalar(value: object) -> object:
    if type(value) is int and value.bit_length() <= 256:
        return value
    if type(value) in {float, complex, bool}:
        return value
    if isinstance(value, (str, bytes)) and len(value) <= 4096:
        return value
    return _STATIC_VALUE_UNKNOWN


def _apply_static_comparison(
    left: object,
    operator: ast.cmpop,
    right: object,
) -> bool:
    if isinstance(operator, ast.Eq):
        return left == right
    if isinstance(operator, ast.NotEq):
        return left != right
    if isinstance(operator, ast.Lt):
        return left < right  # type: ignore[operator]
    if isinstance(operator, ast.LtE):
        return left <= right  # type: ignore[operator]
    if isinstance(operator, ast.Gt):
        return left > right  # type: ignore[operator]
    if isinstance(operator, ast.GtE):
        return left >= right  # type: ignore[operator]
    if isinstance(operator, ast.Is):
        return left is right
    if isinstance(operator, ast.IsNot):
        return left is not right
    raise ValueError("unsupported static comparison")


class _ReachabilityPruningVisitor(ast.NodeVisitor):
    """Exclude calls hidden in expressions that are statically unreachable."""

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        truth = _literal_truth_value(node.test)
        selected = (
            node.body
            if truth is True
            else node.orelse
            if truth is False
            else (*node.body, *node.orelse)
        )
        for statement in selected:
            self.visit(statement)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        if _literal_truth_value(node.test) is not False:
            for statement in node.body:
                self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)

    def visit_IfExp(self, node: ast.IfExp) -> None:
        self.visit(node.test)
        truth = _literal_truth_value(node.test)
        if truth is True:
            self.visit(node.body)
        elif truth is False:
            self.visit(node.orelse)
        else:
            self.visit(node.body)
            self.visit(node.orelse)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        for value in node.values:
            self.visit(value)
            truth = _literal_truth_value(value)
            if isinstance(node.op, ast.And) and truth is False:
                break
            if isinstance(node.op, ast.Or) and truth is True:
                break


def _visit_function_definition_header(
    visitor: ast.NodeVisitor,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> None:
    """Visit expressions evaluated outside the function body's context."""

    for decorator in node.decorator_list:
        visitor.visit(decorator)
    arguments = node.args
    annotated = [
        *arguments.posonlyargs,
        *arguments.args,
        *arguments.kwonlyargs,
    ]
    if arguments.vararg is not None:
        annotated.append(arguments.vararg)
    if arguments.kwarg is not None:
        annotated.append(arguments.kwarg)
    for argument in annotated:
        if argument.annotation is not None:
            visitor.visit(argument.annotation)
    for default in arguments.defaults:
        visitor.visit(default)
    for default in arguments.kw_defaults:
        if default is not None:
            visitor.visit(default)
    if node.returns is not None:
        visitor.visit(node.returns)
    for type_parameter in getattr(node, "type_params", ()):
        visitor.visit(type_parameter)


class _LiteralCallVisitor(_ReachabilityPruningVisitor):
    def __init__(
        self,
        module: _ParsedModule,
        direct_names: frozenset[str],
        module_names: frozenset[str],
    ) -> None:
        self.module = module
        self.function_stack: list[str] = []
        self.class_stack: list[str] = []
        self.direct_names = direct_names
        self.module_names = module_names
        self.rows: list[LiteralActivation] = []
        self.dynamic_errors: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        _visit_function_definition_header(self, node)
        self.function_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        _visit_function_definition_header(self, node)
        self.function_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.function_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def _registered_api(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name) and node.id in self.direct_names:
            return node.id
        if (
            isinstance(node, ast.Attribute)
            and node.attr in _REGISTER_APIS
            and isinstance(node.value, ast.Name)
            and node.value.id in self.module_names
        ):
            return node.attr
        return None

    def visit_Call(self, node: ast.Call) -> None:
        leaf = _call_leaf(node.func)
        if isinstance(node.func, ast.Call):
            dynamic_leaf = _call_leaf(node.func.func)
            if (
                dynamic_leaf == "getattr"
                and len(node.func.args) >= 2
                and _constant_string(node.func.args[1]) in _REGISTER_APIS
            ):
                self.dynamic_errors.append(
                    f"{self.module.relative_path}:{node.lineno}: computed reflection of registered gate API is forbidden"
                )
        if leaf == "__import__" and node.args:
            if _constant_string(node.args[0]) == _REGISTER_API_MODULE:
                self.dynamic_errors.append(
                    f"{self.module.relative_path}:{node.lineno}: dynamic import of registered gate runtime is forbidden"
                )
        api = self._registered_api(node.func)
        if leaf in _REGISTER_APIS and api is None:
            self.dynamic_errors.append(
                f"{self.module.relative_path}:{node.lineno}: registered gate API lookalike or unbound reference"
            )
        if api is not None:
            location = f"{self.module.relative_path}:{node.lineno}"
            if (
                len(self.function_stack) != 1
                or self.class_stack
            ):
                self.dynamic_errors.append(
                    f"{location}: registered gate call must be in one top-level wrapper"
                )
            gate_node = node.args[0] if node.args else None
            activation_node = next(
                (
                    keyword.value
                    for keyword in node.keywords
                    if keyword.arg == "activation_id"
                ),
                None,
            )
            if (
                not isinstance(gate_node, ast.Constant)
                or type(gate_node.value) is not str
                or not isinstance(activation_node, ast.Constant)
                or type(activation_node.value) is not str
            ):
                self.dynamic_errors.append(
                    f"{location}: gate and activation IDs must be source literals"
                )
            else:
                evaluator_node = next(
                    (
                        keyword.value
                        for keyword in node.keywords
                        if keyword.arg == "evaluator"
                    ),
                    None,
                )
                self.rows.append(
                    LiteralActivation(
                        gate_id=gate_node.value,
                        activation_id=activation_node.value,
                        module=self.module.relative_path,
                        wrapper_symbol=(
                            self.function_stack[-1]
                            if self.function_stack
                            else "<module>"
                        ),
                        source_line=node.lineno,
                        evaluator_symbol=_reference_symbol(evaluator_node),
                        api_symbol=api,
                    )
                )
        self.generic_visit(node)


def _registered_api_bindings(
    module: _ParsedModule,
) -> tuple[frozenset[str], frozenset[str]]:
    direct: set[str] = set()
    module_names: set[str] = set()
    for node in module.tree.body:
        if (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module == _REGISTER_API_MODULE
        ):
            for alias in node.names:
                if alias.name in _REGISTER_APIS:
                    if alias.asname is not None and alias.asname != alias.name:
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{node.lineno}: registered gate API alias is forbidden"
                        )
                    direct.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _REGISTER_API_MODULE:
                    if alias.asname is not None:
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{node.lineno}: registered gate module alias is forbidden"
                        )
                    module_names.add(_REGISTER_API_MODULE)
    return frozenset(direct), frozenset(module_names)


def _reject_api_aliases(modules: Sequence[_ParsedModule]) -> None:
    _contains_namespace_authority.cache_clear()
    _contains_registered_api_reference.cache_clear()
    by_module_name = _module_name_index(modules)

    def resolved_import_name(
        owner: _ParsedModule,
        node: ast.ImportFrom,
    ) -> str:
        base = node.module or ""
        if not node.level:
            return base
        package = owner.module_name.rpartition(".")[0]
        parts = package.split(".") if package else []
        if node.level > len(parts) + 1:
            return ""
        prefix = parts[: len(parts) - node.level + 1]
        return ".".join(
            part for part in (*prefix, base) if part
        )

    def star_target_can_export_authority(
        owner: _ParsedModule,
        node: ast.ImportFrom,
        seen: set[str] | None = None,
    ) -> bool:
        target_name = resolved_import_name(owner, node)
        if target_name == _REGISTER_API_MODULE:
            return True
        target = by_module_name.get(target_name)
        if target is None:
            return True
        observed = set() if seen is None else set(seen)
        if target_name in observed:
            return True
        observed.add(target_name)
        for statement in target.tree.body:
            if isinstance(
                statement,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ) and statement.name in _REGISTER_APIS:
                return True
            if isinstance(statement, ast.Import):
                if any(
                    alias.name == _REGISTER_API_MODULE
                    for alias in statement.names
                ):
                    return True
            if not isinstance(statement, ast.ImportFrom):
                continue
            imported_name = resolved_import_name(target, statement)
            if imported_name == _REGISTER_API_MODULE and any(
                alias.name == "*"
                or alias.name in _REGISTER_APIS
                for alias in statement.names
            ):
                return True
            if any(alias.name == "*" for alias in statement.names) and (
                star_target_can_export_authority(
                    target, statement, observed
                )
            ):
                return True
        return False

    for module in modules:
        direct_names, module_names = _registered_api_bindings(module)
        risky_star_import = any(
            isinstance(statement, ast.ImportFrom)
            and any(alias.name == "*" for alias in statement.names)
            and star_target_can_export_authority(module, statement)
            for statement in module.tree.body
        )
        if not direct_names and not module_names and not risky_star_import:
            # The static ratchet governs the direct registry-runtime import
            # closure. Runtime caller/activation receipts are the authority
            # for code that could recover the module through Python's dynamic
            # import machinery.
            continue
        nodes = tuple(ast.walk(module.tree))
        parents = {
            child: parent
            for parent in nodes
            for child in ast.iter_child_nodes(parent)
        }
        protected_bindings = {
            *_REGISTER_APIS,
            _REGISTER_API_MODULE,
        }
        direct_call_nodes = {
            id(node.func)
            for node in nodes
            if isinstance(node, ast.Call)
            and (
                (
                    isinstance(node.func, ast.Name)
                    and node.func.id in direct_names
                )
                or (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in _REGISTER_APIS
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in module_names
                )
            )
        }
        for node in nodes:
            if (
                isinstance(node, ast.arg)
                and node.arg in protected_bindings
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: registered gate authority is shadowed by a parameter"
                )
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, (ast.Store, ast.Del))
                and node.id in protected_bindings
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: registered gate authority is shadowed by a local binding"
                )
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if (
                        alias.name == "*"
                        and star_target_can_export_authority(module, node)
                    ):
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{node.lineno}: star "
                            "import can hide registered decision authority"
                        )
                    if (
                        alias.name in _REGISTER_APIS
                        and alias.asname is not None
                        and alias.asname != alias.name
                    ):
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{node.lineno}: registered gate API alias is forbidden"
                        )
                    local = alias.asname or alias.name
                    actual_api_import = (
                        node.level == 0
                        and node.module == _REGISTER_API_MODULE
                        and alias.name in _REGISTER_APIS
                        and local == alias.name
                    )
                    if (
                        local in protected_bindings
                        and not actual_api_import
                    ):
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{node.lineno}: import shadows registered gate authority"
                        )
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".", 1)[0]
                    actual_module_import = (
                        alias.name == _REGISTER_API_MODULE
                        and alias.asname is None
                    )
                    if (
                        local in protected_bindings
                        and not actual_module_import
                    ):
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{node.lineno}: import shadows registered gate authority"
                        )
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ) and node.name in _REGISTER_APIS:
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: local registered gate API lookalike is forbidden"
                )
            if isinstance(
                node,
                (ast.Assign, ast.AnnAssign, ast.NamedExpr),
            ):
                value = node.value
                if _contains_namespace_authority(value):
                    raise ActivationInventoryError(
                        f"{module.relative_path}:{node.lineno}: dynamic "
                        "namespace authority cannot escape through an alias"
                    )
                if _contains_registered_api_reference(value):
                    raise ActivationInventoryError(
                        f"{module.relative_path}:{node.lineno}: registered gate API cannot escape through an alias or callback table"
                    )
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in _REGISTER_APIS
                and id(node) not in direct_call_nodes
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: computed registered gate API dispatch is forbidden"
                )
            if (
                isinstance(node, ast.Name)
                and isinstance(node.ctx, ast.Load)
                and node.id in module_names
            ):
                parent = parents.get(node)
                exact_static_api_call = (
                    isinstance(parent, ast.Attribute)
                    and parent.value is node
                    and parent.attr in _REGISTER_APIS
                    and id(parent) in direct_call_nodes
                )
                constant_non_api_getattr = (
                    isinstance(parent, ast.Call)
                    and _call_leaf(parent.func) == "getattr"
                    and bool(parent.args)
                    and parent.args[0] is node
                    and len(parent.args) >= 2
                    and _constant_string(parent.args[1]) is not None
                    and _constant_string(parent.args[1])
                    not in _REGISTER_APIS
                )
                if not (
                    exact_static_api_call or constant_non_api_getattr
                ):
                    raise ActivationInventoryError(
                        f"{module.relative_path}:{node.lineno}: registered "
                        "gate module cannot escape through reflection, an "
                        "alias, or a callback"
                    )
            if (
                isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom))
                and node.value is not None
                and _contains_namespace_authority(node.value)
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: dynamic "
                    "namespace authority cannot escape through a return"
                )
            if (
                isinstance(node, ast.Subscript)
                and _namespace_reflection_root(node.value)
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: dynamic namespace "
                    "subscript can hide registered decision authority"
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and _namespace_reflection_root(node.func.value)
            ):
                key = (
                    _constant_string(node.args[0])
                    if len(node.args) >= 1
                    else None
                )
                if key is None or key in _REGISTER_APIS:
                    raise ActivationInventoryError(
                        f"{module.relative_path}:{node.lineno}: dynamic "
                        "namespace lookup can hide registered decision "
                        "authority"
                    )
            if (
                isinstance(node, ast.Call)
                and not _namespace_reflection_root(node)
                and not _safe_literal_namespace_get(node)
                and _contains_namespace_authority(node)
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{node.lineno}: composed "
                    "namespace authority can hide registered decision "
                    "dispatch"
                )
            if isinstance(node, ast.Call) and _call_leaf(node.func) == "getattr":
                attribute = (
                    _constant_string(node.args[1])
                    if len(node.args) >= 2
                    else None
                )
                reflection_target = (
                    bool(node.args)
                    and _namespace_reflection_root(node.args[0])
                )
                if attribute in _REGISTER_APIS:
                    raise ActivationInventoryError(
                        f"{module.relative_path}:{node.lineno}: reflected registered gate API is forbidden"
                    )
                if attribute is None and reflection_target:
                    raise ActivationInventoryError(
                        f"{module.relative_path}:{node.lineno}: computed "
                        "callable reflection can hide registered decision "
                        "authority"
                    )


def discover_literal_activations(
    source_root: Path | str,
    *,
    production_roots: Sequence[str],
    production_excludes: Sequence[str] = (),
) -> tuple[LiteralActivation, ...]:
    """Discover literal gate wrapper calls from the frozen production tree."""

    snapshot = _capture_source_snapshot(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    rows = _discover_literal_activations_from_modules(
        _parse_snapshot(snapshot)
    )
    _assert_snapshot_current(
        snapshot,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    return rows


def _discover_literal_activations_from_modules(
    modules: Sequence[_ParsedModule],
) -> tuple[LiteralActivation, ...]:
    _reject_api_aliases(modules)
    rows: list[LiteralActivation] = []
    errors: list[str] = []
    for module in modules:
        direct_names, module_names = _registered_api_bindings(module)
        visitor = _LiteralCallVisitor(
            module, direct_names, module_names
        )
        visitor.visit(module.tree)
        rows.extend(visitor.rows)
        errors.extend(visitor.dynamic_errors)
    if errors:
        raise ActivationInventoryError("; ".join(sorted(errors)))
    keys = [(row.gate_id, row.activation_id) for row in rows]
    if len(keys) != len(set(keys)):
        raise ActivationInventoryError(
            "duplicate literal gate/activation identity"
        )
    wrappers: dict[tuple[str, str], list[LiteralActivation]] = {}
    for row in rows:
        wrappers.setdefault(
            (row.module, row.wrapper_symbol), []
        ).append(row)
    hidden = [
        key for key, values in wrappers.items() if len(values) != 1
    ]
    if hidden:
        raise ActivationInventoryError(
            "one wrapper hides multiple independently fireable decisions: "
            + ", ".join(f"{module}:{symbol}" for module, symbol in hidden)
        )
    return tuple(
        sorted(
            rows,
            key=lambda row: (
                row.gate_id.encode("utf-8"),
                row.activation_id.encode("utf-8"),
                row.module.encode("utf-8"),
                row.source_line,
            ),
        )
    )


def _top_level_symbols(
    modules: Sequence[_ParsedModule],
) -> dict[tuple[str, str], _SymbolNode]:
    result: dict[tuple[str, str], _SymbolNode] = {}
    for module in modules:
        for node in module.tree.body:
            names: list[str] = []
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                names = [node.name]
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets: list[ast.AST]
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                else:
                    targets = [node.target]
                names = [
                    target.id
                    for target in targets
                    if isinstance(target, ast.Name)
            ]
            for name in names:
                key = (module.relative_path, name)
                previous = result.get(key)
                if previous is None:
                    combined = node
                else:
                    previous_nodes = (
                        list(previous.node.body)
                        if isinstance(previous.node, ast.Module)
                        else [previous.node]
                    )
                    combined = ast.Module(
                        body=[*previous_nodes, node],
                        type_ignores=[],
                    )
                result[key] = _SymbolNode(
                    module_path=module.relative_path,
                    module_name=module.module_name,
                    symbol=name,
                    node=combined,
                )
    return result


def _module_name_index(
    modules: Sequence[_ParsedModule],
) -> dict[str, _ParsedModule]:
    """Resolve package-qualified and production-root import spellings."""

    result: dict[str, _ParsedModule] = {}
    for module in modules:
        aliases = {module.module_name}
        if "." in module.module_name:
            aliases.add(module.module_name.split(".", 1)[1])
        for alias in aliases:
            previous = result.setdefault(alias, module)
            if previous.relative_path != module.relative_path:
                raise ActivationInventoryError(
                    "production modules have an ambiguous import spelling: "
                    f"{alias}"
                )
    return result


def _import_bindings(
    modules: Sequence[_ParsedModule],
) -> dict[tuple[str, str], tuple[str, str]]:
    by_name = _module_name_index(modules)
    result: dict[tuple[str, str], tuple[str, str]] = {}
    for module in modules:
        package = module.module_name.rpartition(".")[0]
        for node in module.tree.body:
            if not isinstance(node, ast.ImportFrom) or node.module is None:
                continue
            base = node.module
            if node.level:
                parts = package.split(".") if package else []
                if node.level > len(parts) + 1:
                    continue
                prefix = parts[: len(parts) - node.level + 1]
                base = ".".join([*prefix, node.module])
            target_module = by_name.get(base)
            if target_module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                result[(module.relative_path, local)] = (
                    target_module.relative_path,
                    alias.name,
                )
    return result


def _module_import_bindings(
    modules: Sequence[_ParsedModule],
) -> dict[tuple[str, str], str]:
    by_name = _module_name_index(modules)
    result: dict[tuple[str, str], str] = {}
    for module in modules:
        package = module.module_name.rpartition(".")[0]
        for node in module.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = by_name.get(alias.name)
                    if target is None:
                        continue
                    local = alias.asname or alias.name
                    result[(module.relative_path, local)] = (
                        target.relative_path
                    )
                continue
            if not isinstance(node, ast.ImportFrom):
                continue
            base = node.module or ""
            if node.level:
                parts = package.split(".") if package else []
                if node.level > len(parts) + 1:
                    continue
                prefix = parts[: len(parts) - node.level + 1]
                base = ".".join(
                    part for part in (*prefix, node.module or "") if part
                )
            for alias in node.names:
                if alias.name == "*":
                    continue
                candidate = ".".join(
                    part for part in (base, alias.name) if part
                )
                target = by_name.get(candidate)
                if target is None:
                    continue
                local = alias.asname or alias.name
                result[(module.relative_path, local)] = target.relative_path
    return result


def _resolve_imported_symbol(
    key: tuple[str, str],
    imports: Mapping[tuple[str, str], tuple[str, str]],
) -> tuple[str, str]:
    seen: set[tuple[str, str]] = set()
    current = key
    while current in imports:
        if current in seen:
            raise ActivationInventoryError(
                "repository-local import cycle obscures decision authority"
            )
        seen.add(current)
        current = imports[current]
    return current


def _closure_symbols(
    modules: Sequence[_ParsedModule],
    activation: GateActivation,
) -> tuple[_SymbolNode, ...]:
    symbols = _top_level_symbols(modules)
    imports = _import_bindings(modules)
    module_imports = _module_import_bindings(modules)
    seeds = [activation.wrapper_symbol, *activation.implementation_symbols]
    pending: list[tuple[str, str]] = []
    for symbol in seeds:
        if "." in symbol:
            raise ActivationInventoryError(
                "fixture inventory supports top-level declared symbols only"
            )
        pending.append((activation.module, symbol))
    selected: dict[tuple[str, str], _SymbolNode] = {}
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        node = symbols.get(key)
        if node is None:
            imported = imports.get(key)
            if imported is not None:
                pending.append(imported)
                continue
            raise ActivationInventoryError(
                f"declared decision symbol is absent: {key[0]}:{key[1]}"
            )
        selected[key] = node
        parameters: set[str] = set()
        if isinstance(node.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            parameters = {
                argument.arg
                for argument in (
                    *node.node.args.posonlyargs,
                    *node.node.args.args,
                    *node.node.args.kwonlyargs,
                )
            }
            if node.node.args.vararg is not None:
                parameters.add(node.node.args.vararg.arg)
            if node.node.args.kwarg is not None:
                parameters.add(node.node.args.kwarg.arg)
        nested_function_names = {
            candidate.name
            for candidate in ast.walk(node.node)
            if isinstance(
                candidate, (ast.FunctionDef, ast.AsyncFunctionDef)
            )
            and candidate is not node.node
        }
        for candidate in ast.walk(node.node):
            if isinstance(candidate, ast.Call):
                if (
                    isinstance(candidate.func, ast.Name)
                    and candidate.func.id in parameters
                ):
                    raise ActivationInventoryError(
                        "decision closure calls through a parameter callback"
                    )
                if isinstance(
                    candidate.func,
                    (ast.Call, ast.Lambda, ast.Subscript),
                ):
                    raise ActivationInventoryError(
                        "decision closure contains ambiguous computed dispatch"
                    )
                if isinstance(candidate.func, ast.Name):
                    local_call = (node.module_path, candidate.func.id)
                    if (
                        candidate.func.id not in _SAFE_BUILTIN_CALLS
                        and candidate.func.id not in _REGISTER_APIS
                        and candidate.func.id not in nested_function_names
                        and local_call not in symbols
                        and local_call not in imports
                    ):
                        raise ActivationInventoryError(
                            "decision closure contains an unresolved callable"
                        )
                elif isinstance(candidate.func, ast.Attribute):
                    reference = _reference_symbol(candidate.func)
                    if reference is None:
                        raise ActivationInventoryError(
                            "decision closure contains ambiguous attribute dispatch"
                        )
                    base = reference.rsplit(".", 1)[0]
                    if base in parameters:
                        raise ActivationInventoryError(
                            "decision closure calls through a parameter object"
                        )
                    if (
                        (node.module_path, base) not in module_imports
                        and candidate.func.attr not in _REGISTER_APIS
                    ):
                        raise ActivationInventoryError(
                            "decision closure contains an unbound method dispatch"
                        )
            if isinstance(candidate, ast.Name) and isinstance(
                candidate.ctx, ast.Load
            ):
                local_key = (node.module_path, candidate.id)
                if local_key in symbols or local_key in imports:
                    pending.append(local_key)
            elif isinstance(candidate, ast.Attribute):
                reference = _reference_symbol(candidate)
                if reference is None or "." not in reference:
                    continue
                base, leaf = reference.rsplit(".", 1)
                imported_module = module_imports.get(
                    (node.module_path, base)
                )
                if imported_module is not None:
                    imported_key = (imported_module, leaf)
                    if imported_key in symbols:
                        pending.append(imported_key)
    return tuple(
        selected[key]
        for key in sorted(
            selected,
            key=lambda item: (
                item[0].encode("utf-8"),
                item[1].encode("utf-8"),
            ),
        )
    )


def compute_decision_code_digest(
    source_root: Path | str,
    activation: GateActivation,
    *,
    production_roots: Sequence[str] = ("scripts",),
    production_excludes: Sequence[str] = (),
) -> str:
    """Digest the normalized literal wrapper and transitive local AST closure."""

    _, modules = _parse_modules(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    return _compute_decision_code_digest_from_modules(modules, activation)


def _compute_decision_code_digest_from_modules(
    modules: Sequence[_ParsedModule],
    activation: GateActivation,
) -> str:
    closure = _closure_symbols(modules, activation)
    rows = [
        {
            "module": item.module_path,
            "symbol": item.symbol,
            "ast": ast.dump(
                item.node,
                annotate_fields=True,
                include_attributes=False,
            ),
        }
        for item in closure
    ]
    envelope = {
        "algorithm": DECISION_CODE_DIGEST_ALGORITHM,
        "closure": rows,
    }
    return hashlib.sha256(_canonical_bytes(envelope)).hexdigest()


def compute_legacy_module_code_digest(
    source_root: Path | str,
    activation: GateActivation,
    *,
    production_roots: Sequence[str] = ("scripts",),
    production_excludes: Sequence[str] = (),
) -> str:
    """Conservatively bind one complete legacy owner module."""

    _, modules = _parse_modules(
        source_root,
        production_roots=production_roots,
        production_excludes=production_excludes,
    )
    return _compute_legacy_module_code_digest_from_modules(
        modules, activation
    )


def _compute_legacy_module_code_digest_from_modules(
    modules: Sequence[_ParsedModule],
    activation: GateActivation,
) -> str:
    matches = [
        module
        for module in modules
        if module.relative_path == activation.module
    ]
    if len(matches) != 1:
        raise ActivationInventoryError(
            "legacy activation owner module is not unique"
        )
    envelope = {
        "algorithm": LEGACY_MODULE_CODE_DIGEST_ALGORITHM,
        "module": activation.module,
        "module_sha256": matches[0].source_sha256,
    }
    return hashlib.sha256(_canonical_bytes(envelope)).hexdigest()


def compute_declared_activation_code_digest(
    source_root: Path | str,
    activation: GateActivation,
    *,
    production_roots: Sequence[str] = ("scripts",),
    production_excludes: Sequence[str] = (),
) -> str:
    """Compute exactly the digest algorithm declared by an activation."""

    if activation.code_digest_algorithm == DECISION_CODE_DIGEST_ALGORITHM:
        return compute_decision_code_digest(
            source_root,
            activation,
            production_roots=production_roots,
            production_excludes=production_excludes,
        )
    if (
        activation.runtime_state == "LEGACY_NOT_MIGRATED"
        and activation.code_digest_algorithm
        == LEGACY_MODULE_CODE_DIGEST_ALGORITHM
    ):
        return compute_legacy_module_code_digest(
            source_root,
            activation,
            production_roots=production_roots,
            production_excludes=production_excludes,
        )
    raise ActivationInventoryError(
        "activation declares an unsupported code-digest algorithm"
    )


def _compute_declared_activation_code_digest_from_modules(
    modules: Sequence[_ParsedModule],
    activation: GateActivation,
) -> str:
    if activation.code_digest_algorithm == DECISION_CODE_DIGEST_ALGORITHM:
        return _compute_decision_code_digest_from_modules(
            modules, activation
        )
    if (
        activation.runtime_state == "LEGACY_NOT_MIGRATED"
        and activation.code_digest_algorithm
        == LEGACY_MODULE_CODE_DIGEST_ALGORITHM
    ):
        return _compute_legacy_module_code_digest_from_modules(
            modules, activation
        )
    raise ActivationInventoryError(
        "activation declares an unsupported code-digest algorithm"
    )


def _declared_wrapper_source_line(
    modules: Sequence[_ParsedModule],
    activation: GateActivation,
) -> int:
    symbols = _top_level_symbols(modules)
    wrapper = activation.wrapper_symbol.rsplit(".", 1)[-1]
    row = symbols.get((activation.module, wrapper))
    if row is None or not hasattr(row.node, "lineno"):
        raise ActivationInventoryError(
            "declared legacy owner symbol is absent from current source: "
            f"{activation.module}:{activation.wrapper_symbol}"
        )
    return int(row.node.lineno)


def _generator_digest_from_snapshot(snapshot: _SourceSnapshot) -> str:
    generator = Path(__file__).resolve()
    for entry in snapshot.entries:
        try:
            if entry.path.resolve(strict=True) == generator:
                return hashlib.sha256(entry.raw).hexdigest()
        except OSError as exc:
            raise ActivationInventoryError(
                "inventory generator identity cannot be resolved"
            ) from exc
    generator_root = generator.parent.parent
    first = _read_source_entry(generator_root, generator)
    second = _read_source_entry(generator_root, generator)
    if _snapshot_signature(
        _SourceSnapshot(generator_root, (first,))
    ) != _snapshot_signature(
        _SourceSnapshot(generator_root, (second,))
    ):
        raise ActivationInventoryError(
            "inventory generator changed during inventory construction"
        )
    return hashlib.sha256(first.raw).hexdigest()


def _registry_activation_index(
    registry: MechanicalGateRegistry,
) -> dict[tuple[str, str], tuple[Any, GateActivation]]:
    result: dict[tuple[str, str], tuple[Any, GateActivation]] = {}
    for record in registry.gate_records:
        for activation in record.activations:
            key = (record.gate_id, activation.activation_id)
            if key in result:
                raise ActivationInventoryError(
                    "registry repeats a gate/activation identity"
                )
            result[key] = (record, activation)
    return result


def build_activation_inventory(
    source_root: Path | str,
    registry: MechanicalGateRegistry,
) -> dict[str, Any]:
    """Build a deterministic fixture manifest without writing a baseline."""

    registry = validate_mechanical_gate_registry(registry)
    roots = tuple(registry.registry_scope["production_roots"])
    excludes = tuple(registry.registry_scope["production_excludes"])
    snapshot = _capture_source_snapshot(
        source_root,
        production_roots=roots,
        production_excludes=excludes,
    )
    source_tree_digest = _source_tree_digest_from_snapshot(snapshot)
    modules = _parse_snapshot(snapshot)
    discovered = _discover_literal_activations_from_modules(modules)
    _validate_wrapper_liveness(modules, registry)
    registry_rows = _registry_activation_index(registry)
    rows: list[dict[str, Any]] = []
    for literal in discovered:
        key = (literal.gate_id, literal.activation_id)
        registered = registry_rows.get(key)
        if registered is None:
            raise ActivationInventoryError(
                f"literal activation is absent from registry: {key}"
            )
        gate, activation = registered
        if literal.api_symbol == "evaluate_registered_gate":
            if (
                literal.evaluator_symbol is None
                or literal.evaluator_symbol
                not in activation.implementation_symbols
            ):
                raise ActivationInventoryError(
                    f"literal evaluator is not the declared implementation: {key}"
                )
        rows.append(
            {
                "gate_id": gate.gate_id,
                "activation_id": activation.activation_id,
                "module": literal.module,
                "wrapper_symbol": literal.wrapper_symbol,
                "implementation_symbols": list(
                    activation.implementation_symbols
                ),
                "hook_id": activation.hook_id,
                "source_line": literal.source_line,
                "phases": list(activation.phases),
                "pipelines": list(activation.pipelines),
                "modes": list(activation.modes),
                "ecosystems": list(activation.ecosystems),
                "backends": list(activation.backends),
                "lifecycle_state": gate.lifecycle_state,
                "runtime_state": activation.runtime_state,
                "decision_code_digest_algorithm": (
                    DECISION_CODE_DIGEST_ALGORITHM
                ),
                "code_digest": (
                    _compute_declared_activation_code_digest_from_modules(
                        modules,
                        activation,
                    )
                ),
                "source_tree_digest": source_tree_digest,
                "literal_runtime_registration_present": True,
            }
        )
    for gate, activation in registry_rows.values():
        if activation.runtime_state != "LEGACY_NOT_MIGRATED":
            continue
        rows.append(
            {
                "gate_id": gate.gate_id,
                "activation_id": activation.activation_id,
                "module": activation.module,
                "wrapper_symbol": activation.wrapper_symbol,
                "implementation_symbols": list(
                    activation.implementation_symbols
                ),
                "hook_id": activation.hook_id,
                "source_line": _declared_wrapper_source_line(
                    modules, activation
                ),
                "phases": list(activation.phases),
                "pipelines": list(activation.pipelines),
                "modes": list(activation.modes),
                "ecosystems": list(activation.ecosystems),
                "backends": list(activation.backends),
                "lifecycle_state": gate.lifecycle_state,
                "runtime_state": activation.runtime_state,
                "decision_code_digest_algorithm": (
                    activation.code_digest_algorithm
                ),
                "code_digest": (
                    _compute_declared_activation_code_digest_from_modules(
                        modules,
                        activation,
                    )
                ),
                "source_tree_digest": source_tree_digest,
                "literal_runtime_registration_present": False,
            }
        )
    rows.sort(
        key=lambda row: (
            str(row["gate_id"]).encode("utf-8"),
            str(row["activation_id"]).encode("utf-8"),
        )
    )
    runtime_authority_granted = bool(rows) and all(
        row["runtime_state"] == "RUNTIME"
        and row["literal_runtime_registration_present"] is True
        for row in rows
    )
    inventory = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "source_tree_digest_algorithm": SOURCE_TREE_DIGEST_ALGORITHM,
        "source_tree_digest": source_tree_digest,
        "generator_version": GENERATOR_VERSION,
        "generator_digest": _generator_digest_from_snapshot(snapshot),
        "runtime_authority_granted": runtime_authority_granted,
        "activations": rows,
    }
    _assert_snapshot_current(
        snapshot,
        production_roots=roots,
        production_excludes=excludes,
    )
    return inventory


def _validate_inventory_shape_impl(
    inventory: Mapping[str, Any],
) -> None:
    if not isinstance(inventory, Mapping):
        raise ActivationInventoryError("activation inventory must be an object")
    if frozenset(inventory) != _INVENTORY_KEYS:
        raise ActivationInventoryError(
            "activation inventory has a non-closed top-level shape"
        )
    if inventory["schema_version"] != INVENTORY_SCHEMA_VERSION:
        raise ActivationInventoryError(
            "activation inventory schema is invalid"
        )
    if (
        inventory["source_tree_digest_algorithm"]
        != SOURCE_TREE_DIGEST_ALGORITHM
    ):
        raise ActivationInventoryError(
            "activation inventory source-tree algorithm is invalid"
        )
    for key in ("source_tree_digest", "generator_digest"):
        value = inventory[key]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ActivationInventoryError(
                f"activation inventory {key} is not SHA-256"
            )
    if inventory["generator_version"] != GENERATOR_VERSION:
        raise ActivationInventoryError(
            "activation inventory generator version is invalid"
        )
    if type(inventory["runtime_authority_granted"]) is not bool:
        raise ActivationInventoryError(
            "activation inventory runtime authority must be boolean"
        )
    rows = inventory["activations"]
    if not isinstance(rows, list):
        raise ActivationInventoryError(
            "activation inventory rows must be an array"
        )
    keys: list[tuple[str, str]] = []
    folded_keys: set[tuple[str, str]] = set()
    module_spellings: dict[str, str] = {}

    def strict_text(value: Any, label: str) -> str:
        if (
            type(value) is not str
            or not value
            or unicodedata.normalize("NFC", value) != value
        ):
            raise ActivationInventoryError(f"{label} is not canonical text")
        return value

    def identifier(value: Any, label: str) -> str:
        text = strict_text(value, label)
        if not _ID_RE.fullmatch(text):
            raise ActivationInventoryError(
                f"{label} is not a canonical identifier"
            )
        return text

    def symbol(value: Any, label: str) -> str:
        text = strict_text(value, label)
        if not _SYMBOL_RE.fullmatch(text):
            raise ActivationInventoryError(
                f"{label} is not a canonical symbol"
            )
        return text

    def closed_array(
        value: Any,
        label: str,
        allowed: Sequence[str],
    ) -> tuple[str, ...]:
        if not isinstance(value, list) or not value:
            raise ActivationInventoryError(
                f"{label} must be a nonempty array"
            )
        parsed = tuple(strict_text(item, label) for item in value)
        if any(item not in allowed for item in parsed):
            raise ActivationInventoryError(f"{label} has an invalid value")
        if parsed != tuple(
            sorted(set(parsed), key=lambda item: item.encode("utf-8"))
        ):
            raise ActivationInventoryError(
                f"{label} is not sorted and unique"
            )
        return parsed

    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or frozenset(row) != _INVENTORY_ROW_KEYS:
            raise ActivationInventoryError(
                f"activation inventory row {index} has a non-closed shape"
            )
        gate_id = identifier(row["gate_id"], f"row {index} gate_id")
        activation_id = identifier(
            row["activation_id"], f"row {index} activation_id"
        )
        if not activation_id.startswith(gate_id + "."):
            raise ActivationInventoryError(
                "activation row is outside its gate namespace"
            )
        keys.append((gate_id, activation_id))
        folded = (gate_id.casefold(), activation_id.casefold())
        if folded in folded_keys:
            raise ActivationInventoryError(
                "activation inventory contains case-folded duplicate IDs"
            )
        folded_keys.add(folded)
        module = strict_text(row["module"], f"row {index} module")
        if (
            "\\" in module
            or ":" in module
            or not module.endswith(".py")
            or module.startswith("/")
            or PurePosixPath(module).as_posix() != module
            or any(part in {"", ".", ".."} for part in module.split("/"))
        ):
            raise ActivationInventoryError(
                "activation module path is not canonical"
            )
        previous = module_spellings.setdefault(module.casefold(), module)
        if previous != module:
            raise ActivationInventoryError(
                "activation modules collide under filesystem case folding"
            )
        symbol(row["wrapper_symbol"], f"row {index} wrapper_symbol")
        implementation_symbols = row["implementation_symbols"]
        if (
            not isinstance(implementation_symbols, list)
            or not implementation_symbols
        ):
            raise ActivationInventoryError(
                "implementation_symbols must be a nonempty array"
            )
        parsed_symbols = tuple(
            symbol(item, f"row {index} implementation_symbols")
            for item in implementation_symbols
        )
        if parsed_symbols != tuple(
            sorted(set(parsed_symbols), key=lambda item: item.encode("utf-8"))
        ):
            raise ActivationInventoryError(
                "implementation_symbols are not sorted and unique"
            )
        identifier(row["hook_id"], f"row {index} hook_id")
        if type(row["source_line"]) is not int or row["source_line"] < 1:
            raise ActivationInventoryError(
                "activation source line must be a positive integer"
            )
        closed_array(row["phases"], f"row {index} phases", PHASES)
        closed_array(row["pipelines"], f"row {index} pipelines", PIPELINES)
        closed_array(row["modes"], f"row {index} modes", MODES)
        closed_array(
            row["ecosystems"], f"row {index} ecosystems", ECOSYSTEMS
        )
        closed_array(row["backends"], f"row {index} backends", BACKENDS)
        if row["lifecycle_state"] not in LIFECYCLE_STATES:
            raise ActivationInventoryError(
                "activation lifecycle state is invalid"
            )
        if row["runtime_state"] not in ACTIVATION_RUNTIME_STATES:
            raise ActivationInventoryError(
                "activation runtime state is invalid"
            )
        if (
            row["decision_code_digest_algorithm"]
            not in {
                DECISION_CODE_DIGEST_ALGORITHM,
                LEGACY_MODULE_CODE_DIGEST_ALGORITHM,
            }
        ):
            raise ActivationInventoryError(
                "decision-code digest algorithm is invalid"
            )
        literal_present = row["literal_runtime_registration_present"]
        if type(literal_present) is not bool:
            raise ActivationInventoryError(
                "literal runtime registration flag is not boolean"
            )
        if row["runtime_state"] == "RUNTIME" and literal_present is not True:
            raise ActivationInventoryError(
                "runtime activation lacks literal registration evidence"
            )
        if (
            row["runtime_state"] == "LEGACY_NOT_MIGRATED"
            and literal_present is not False
        ):
            raise ActivationInventoryError(
                "legacy migration row cannot claim a literal wrapper"
            )
        for digest_key in ("code_digest", "source_tree_digest"):
            value = row[digest_key]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in value
                )
            ):
                raise ActivationInventoryError(
                    f"activation row {digest_key} is invalid"
                )
        if row["source_tree_digest"] != inventory["source_tree_digest"]:
            raise ActivationInventoryError(
                "activation row source-tree digest differs from top-level"
            )
    if keys != sorted(
        keys,
        key=lambda pair: (
            pair[0].encode("utf-8"),
            pair[1].encode("utf-8"),
        ),
    ):
        raise ActivationInventoryError(
            "activation inventory rows are not deterministically sorted"
        )
    if len(keys) != len(set(keys)):
        raise ActivationInventoryError(
            "activation inventory contains duplicate IDs"
        )
    expected_runtime_authority = bool(rows) and all(
        row["runtime_state"] == "RUNTIME"
        and row["literal_runtime_registration_present"] is True
        for row in rows
    )
    if (
        inventory["runtime_authority_granted"]
        is not expected_runtime_authority
    ):
        raise ActivationInventoryError(
            "activation inventory runtime authority is inconsistent"
        )


def _validate_inventory_shape(inventory: Mapping[str, Any]) -> None:
    try:
        _validate_inventory_shape_impl(inventory)
    except ActivationInventoryError:
        raise
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise ActivationInventoryError(
            "activation inventory input is malformed"
        ) from exc


def activation_inventory_digest(
    inventory: Mapping[str, Any],
) -> str:
    try:
        _validate_inventory_shape(inventory)
        return hashlib.sha256(_canonical_bytes(inventory)).hexdigest()
    except ActivationInventoryError:
        raise
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError) as exc:
        raise ActivationInventoryError(
            "activation inventory input is malformed"
        ) from exc


class _FunctionContextVisitor(_ReachabilityPruningVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.calls: list[tuple[str | None, ast.Call]] = []
        self.scoped_calls: list[
            tuple[tuple[str, ...], ast.Call]
        ] = []
        self.imports: list[
            tuple[str | None, ast.Import | ast.ImportFrom]
        ] = []
        self.assignments: list[
            tuple[str | None, ast.Assign | ast.AnnAssign]
        ] = []
        self.names: list[tuple[str | None, ast.Name]] = []
        self.attributes: list[tuple[str | None, ast.Attribute]] = []
        self.subscripts: list[tuple[str | None, ast.Subscript]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        _visit_function_definition_header(self, node)
        self.stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        _visit_function_definition_header(self, node)
        self.stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append((self.stack[-1] if self.stack else None, node))
        self.scoped_calls.append((tuple(self.stack), node))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        self.imports.append((self.stack[-1] if self.stack else None, node))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.imports.append((self.stack[-1] if self.stack else None, node))

    def visit_Assign(self, node: ast.Assign) -> None:
        self.assignments.append(
            (self.stack[-1] if self.stack else None, node)
        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.assignments.append(
            (self.stack[-1] if self.stack else None, node)
        )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.names.append((self.stack[-1] if self.stack else None, node))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.attributes.append(
            (self.stack[-1] if self.stack else None, node)
        )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self.subscripts.append(
            (self.stack[-1] if self.stack else None, node)
        )
        self.generic_visit(node)


def validate_no_direct_call_bypass(
    source_root: Path | str,
    registry: MechanicalGateRegistry,
) -> None:
    """Reject known implementation use outside its one registered boundary."""

    registry = validate_mechanical_gate_registry(registry)
    roots = tuple(registry.registry_scope["production_roots"])
    excludes = tuple(registry.registry_scope["production_excludes"])
    _, modules = _parse_modules(
        source_root,
        production_roots=roots,
        production_excludes=excludes,
    )
    _reject_api_aliases(modules)
    imports = _import_bindings(modules)
    module_imports = _module_import_bindings(modules)
    owner_targets: dict[
        tuple[str, str],
        tuple[str, str, frozenset[tuple[str, str]]],
    ] = {}
    all_impl_names: set[str] = set()
    for gate in registry.gate_records:
        for activation in gate.activations:
            targets = frozenset(
                _resolve_imported_symbol(
                    (activation.module, symbol.rsplit(".", 1)[-1]),
                    imports,
                )
                for symbol in activation.implementation_symbols
            )
            owner = (
                activation.module,
                activation.wrapper_symbol.rsplit(".", 1)[-1],
                targets,
            )
            for symbol in activation.implementation_symbols:
                all_impl_names.add(symbol.rsplit(".", 1)[-1])
            for target in targets:
                existing = owner_targets.get(target)
                if existing is not None and existing != owner:
                    raise ActivationInventoryError(
                        "one implementation symbol has multiple gate owners"
                    )
                owner_targets[target] = owner

    def resolve_reference(
        module_path: str,
        node: ast.AST,
    ) -> tuple[str, str] | None:
        reference = _reference_symbol(node)
        if reference is None:
            return None
        if "." not in reference:
            return _resolve_imported_symbol(
                (module_path, reference), imports
            )
        base, leaf = reference.rsplit(".", 1)
        imported_module = module_imports.get((module_path, base))
        if imported_module is None:
            return None
        return (imported_module, leaf)

    def is_implementation_body(
        module_path: str,
        current: str | None,
        owner: tuple[str, str, frozenset[tuple[str, str]]],
    ) -> bool:
        _wrapper_module, _wrapper, targets = owner
        return current is not None and (module_path, current) in targets

    for module in modules:
        parents = {
            child: parent
            for parent in ast.walk(module.tree)
            for child in ast.iter_child_nodes(parent)
        }

        def is_exact_evaluator_reference(
            node: ast.AST,
            current: str | None,
            owner: tuple[
                str,
                str,
                frozenset[tuple[str, str]],
            ],
        ) -> bool:
            wrapper_module, wrapper, _targets = owner
            if (
                module.relative_path != wrapper_module
                or current != wrapper
            ):
                return False
            keyword = parents.get(node)
            if (
                not isinstance(keyword, ast.keyword)
                or keyword.arg != "evaluator"
            ):
                return False
            call = parents.get(keyword)
            return (
                isinstance(call, ast.Call)
                and _call_leaf(call.func) in _REGISTER_APIS
            )

        visitor = _FunctionContextVisitor()
        visitor.visit(module.tree)
        for current, call in visitor.calls:
            leaf = _call_leaf(call.func)
            target = resolve_reference(module.relative_path, call.func)
            owner = owner_targets.get(target) if target is not None else None
            if owner is not None and not is_implementation_body(
                module.relative_path, current, owner
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{call.lineno}: direct implementation call bypasses {owner[1]}"
                )
            if leaf == "getattr":
                for argument in call.args:
                    if _constant_string(argument) in all_impl_names:
                        raise ActivationInventoryError(
                            f"{module.relative_path}:{call.lineno}: reflection can bypass a registered decision"
                        )
            if (
                leaf == "get"
                and isinstance(call.func, ast.Attribute)
                and _namespace_reflection_root(call.func.value)
                and call.args
                and _constant_string(call.args[0]) in all_impl_names
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{call.lineno}: namespace lookup "
                    "can bypass a registered decision"
                )
        for _current, subscript in visitor.subscripts:
            key = _constant_string(subscript.slice)
            if key not in all_impl_names:
                continue
            value = subscript.value
            dictionary_reflection = (
                isinstance(value, ast.Call)
                and _call_leaf(value.func) in {"globals", "vars", "locals"}
            ) or (
                isinstance(value, ast.Attribute)
                and value.attr == "__dict__"
            )
            if dictionary_reflection:
                raise ActivationInventoryError(
                    f"{module.relative_path}:{subscript.lineno}: dictionary reflection can bypass a registered decision"
                )

        references: tuple[
            tuple[str | None, ast.Name | ast.Attribute], ...
        ] = (
            *visitor.names,
            *visitor.attributes,
        )
        for current, reference_node in references:
            if isinstance(reference_node, ast.Name) and not isinstance(
                reference_node.ctx, ast.Load
            ):
                continue
            target = resolve_reference(
                module.relative_path, reference_node
            )
            owner = owner_targets.get(target) if target is not None else None
            if owner is not None and not (
                is_implementation_body(
                    module.relative_path, current, owner
                )
                or is_exact_evaluator_reference(
                    reference_node, current, owner
                )
            ):
                raise ActivationInventoryError(
                    f"{module.relative_path}:{reference_node.lineno}: "
                    "implementation reference escapes its exact evaluator "
                    "binding"
                )

            module_reference = _reference_symbol(reference_node)
            imported_module = (
                module_imports.get(
                    (module.relative_path, module_reference)
                )
                if module_reference is not None
                else None
            )
            if imported_module is None or not any(
                target_module == imported_module
                for target_module, _symbol in owner_targets
            ):
                continue
            parent = parents.get(reference_node)
            if (
                isinstance(parent, ast.Attribute)
                and parent.value is reference_node
                and parent.attr != "__dict__"
            ):
                continue
            if (
                isinstance(parent, ast.Call)
                and _call_leaf(parent.func) == "getattr"
                and bool(parent.args)
                and parent.args[0] is reference_node
                and len(parent.args) >= 2
                and (
                    attribute := _constant_string(parent.args[1])
                )
                is not None
                and attribute not in all_impl_names
            ):
                continue
            raise ActivationInventoryError(
                f"{module.relative_path}:{reference_node.lineno}: "
                "registered implementation module escapes through an alias "
                "or callback"
            )


def _validate_wrapper_liveness(
    modules: Sequence[_ParsedModule],
    registry: MechanicalGateRegistry,
) -> None:
    imports = _import_bindings(modules)
    module_imports = _module_import_bindings(modules)
    by_name = _module_name_index(modules)
    symbols = _top_level_symbols(modules)
    star_imports: dict[str, tuple[str, ...]] = {}
    for module in modules:
        targets: list[str] = []
        package = module.module_name.rpartition(".")[0]
        for node in module.tree.body:
            if (
                not isinstance(node, ast.ImportFrom)
                or not any(alias.name == "*" for alias in node.names)
            ):
                continue
            base = node.module or ""
            if node.level:
                parts = package.split(".") if package else []
                if node.level > len(parts) + 1:
                    continue
                prefix = parts[: len(parts) - node.level + 1]
                base = ".".join(
                    part
                    for part in (*prefix, node.module or "")
                    if part
                )
            target_module = by_name.get(base)
            if target_module is not None:
                targets.append(target_module.relative_path)
        star_imports[module.relative_path] = tuple(sorted(set(targets)))

    def resolve_star_import(
        module_path: str,
        symbol: str,
    ) -> tuple[str, str] | None:
        candidates = [
            (target_module, symbol)
            for target_module in star_imports.get(module_path, ())
            if (target_module, symbol) in symbols
        ]
        if len(candidates) > 1:
            raise ActivationInventoryError(
                "ambiguous star import obscures declared gate liveness"
            )
        return candidates[0] if candidates else None

    edges: dict[tuple[str, str], set[tuple[str, str]]] = {}
    roots: set[tuple[str, str]] = set()
    for module in modules:
        visitor = _FunctionContextVisitor()
        visitor.visit(module.tree)
        local_imports: dict[
            tuple[str, str], tuple[str, str]
        ] = {}
        local_module_imports: dict[tuple[str, str], str] = {}
        package = module.module_name.rpartition(".")[0]
        for current, node in visitor.imports:
            if current is None:
                continue
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target_module = by_name.get(alias.name)
                    if target_module is not None:
                        local_module_imports[
                            (current, alias.asname or alias.name)
                        ] = target_module.relative_path
                continue
            base = node.module or ""
            if node.level:
                parts = package.split(".") if package else []
                if node.level > len(parts) + 1:
                    continue
                prefix = parts[: len(parts) - node.level + 1]
                base = ".".join(
                    part
                    for part in (*prefix, node.module or "")
                    if part
                )
            target_module = by_name.get(base)
            if target_module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local_imports[
                    (current, alias.asname or alias.name)
                ] = (target_module.relative_path, alias.name)
        for current, node in visitor.assignments:
            if current is None:
                continue
            value = node.value
            if (
                not isinstance(value, ast.Call)
                or not isinstance(value.func, ast.Attribute)
                or value.func.attr != "import_module"
                or not value.args
            ):
                continue
            module_name = _constant_string(value.args[0])
            target_module = (
                by_name.get(module_name)
                if module_name is not None
                else None
            )
            if target_module is None:
                continue
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else (node.target,)
            )
            for target_node in targets:
                if isinstance(target_node, ast.Name):
                    local_module_imports[
                        (current, target_node.id)
                    ] = target_module.relative_path
        nested_references = {
            (current, node.id)
            for current, node in visitor.names
            if current is not None
            and isinstance(node.ctx, ast.Load)
        }
        for scope, call in visitor.scoped_calls:
            current = scope[-1] if scope else None
            caller_symbol = scope[0] if scope else None
            if (
                len(scope) > 1
                and (scope[0], scope[-1]) not in nested_references
            ):
                continue
            reference = _reference_symbol(call.func)
            if reference is None:
                continue
            if "." in reference:
                base, leaf = reference.rsplit(".", 1)
                imported_module = (
                    local_module_imports.get((current, base))
                    if current is not None
                    else None
                ) or module_imports.get((module.relative_path, base))
                target = (
                    (imported_module, leaf)
                    if imported_module is not None
                    else None
                )
            else:
                target = (
                    local_imports.get((current, reference))
                    if current is not None
                    else None
                ) or _resolve_imported_symbol(
                    (module.relative_path, reference),
                    imports,
                )
                if target not in symbols:
                    target = resolve_star_import(
                        module.relative_path, reference
                    )
            if target is None or target not in symbols:
                continue
            if caller_symbol is None:
                roots.add(target)
                continue
            caller = (module.relative_path, caller_symbol)
            if caller in symbols and caller != target:
                edges.setdefault(caller, set()).add(target)
        for node in module.tree.body:
            if not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                continue
            caller = (module.relative_path, node.name)
            for loop in (
                candidate
                for candidate in ast.walk(node)
                if isinstance(candidate, (ast.For, ast.AsyncFor))
            ):
                bound = {
                    candidate.id
                    for candidate in ast.walk(loop.target)
                    if isinstance(candidate, ast.Name)
                }
                invoked = {
                    call.func.id
                    for call in ast.walk(ast.Module(body=loop.body))
                    if isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id in bound
                }
                if not invoked:
                    continue
                for reference_node in ast.walk(loop.iter):
                    if not isinstance(reference_node, ast.Name):
                        continue
                    target = _resolve_imported_symbol(
                        (module.relative_path, reference_node.id),
                        imports,
                    )
                    if target not in symbols:
                        target = resolve_star_import(
                            module.relative_path, reference_node.id
                        )
                    if target in symbols and target != caller:
                        edges.setdefault(caller, set()).add(target)
    reachable = set(roots)
    pending = list(roots)
    while pending:
        caller = pending.pop()
        for target in edges.get(caller, set()):
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    for gate in registry.gate_records:
        for activation in gate.activations:
            wrapper = activation.wrapper_symbol.rsplit(".", 1)[-1]
            if (
                activation.runtime_state
                in {"RUNTIME", "LEGACY_NOT_MIGRATED"}
                and (activation.module, wrapper) not in reachable
            ):
                raise ActivationInventoryError(
                    "declared gate owner is statically unreachable: "
                    f"{activation.module}:{wrapper}"
                )


def validate_activation_parity(
    registry: MechanicalGateRegistry,
    inventory: Mapping[str, Any],
    *,
    source_root: Path | str,
) -> dict[str, Any]:
    """Recompute the fixture inventory and reject any authority drift."""

    registry = validate_mechanical_gate_registry(registry)
    _validate_inventory_shape(inventory)
    roots = tuple(registry.registry_scope["production_roots"])
    excludes = tuple(registry.registry_scope["production_excludes"])
    if any(
        activation.runtime_state == "RUNTIME"
        for gate in registry.gate_records
        for activation in gate.activations
    ):
        validate_no_direct_call_bypass(source_root, registry)
    recomputed = build_activation_inventory(source_root, registry)

    declared_runtime = {
        (gate.gate_id, activation.activation_id)
        for gate in registry.gate_records
        if gate.lifecycle_state in RUNTIME_COUNTED_STATES
        for activation in gate.activations
        if activation.runtime_state
        in {"RUNTIME", "LEGACY_NOT_MIGRATED"}
    }
    observed = {
        (row["gate_id"], row["activation_id"])
        for row in recomputed["activations"]
    }
    if observed != declared_runtime:
        missing = sorted(declared_runtime - observed)
        unknown = sorted(observed - declared_runtime)
        raise ActivationInventoryError(
            f"activation parity failed; missing={missing}, unknown={unknown}"
        )
    if dict(inventory) != recomputed:
        raise ActivationInventoryError(
            "activation inventory differs from deterministic source discovery"
        )
    expected_tree = registry.migration["source_tree_digest"]
    if recomputed["source_tree_digest"] != expected_tree:
        raise ActivationInventoryError(
            "source-tree digest drifted from registry migration authority"
        )
    if (
        registry.activation_inventory["source_tree_digest"]
        != recomputed["source_tree_digest"]
    ):
        raise ActivationInventoryError(
            "activation-inventory source-tree authority drifted"
        )
    if (
        registry.activation_inventory["generator_version"]
        != recomputed["generator_version"]
        or registry.activation_inventory["generator_digest"]
        != recomputed["generator_digest"]
    ):
        raise ActivationInventoryError(
            "inventory generator authority drifted"
        )
    if (
        registry.activation_inventory["manifest_sha256"]
        != activation_inventory_digest(inventory)
    ):
        raise ActivationInventoryError(
            "activation manifest digest does not match registry authority"
        )
    registered = _registry_activation_index(registry)
    for row in recomputed["activations"]:
        gate, activation = registered[
            (row["gate_id"], row["activation_id"])
        ]
        if (
            row["module"] != activation.module
            or row["wrapper_symbol"] != activation.wrapper_symbol
            or tuple(row["implementation_symbols"])
            != activation.implementation_symbols
            or row["hook_id"] != activation.hook_id
            or tuple(row["phases"]) != activation.phases
            or tuple(row["pipelines"]) != activation.pipelines
            or tuple(row["modes"]) != activation.modes
            or tuple(row["ecosystems"]) != activation.ecosystems
            or tuple(row["backends"]) != activation.backends
            or row["lifecycle_state"] != gate.lifecycle_state
            or row["runtime_state"] != activation.runtime_state
            or row["decision_code_digest_algorithm"]
            != activation.code_digest_algorithm
            or row["code_digest"] != activation.code_digest
        ):
            raise ActivationInventoryError(
                f"selector, symbol, lifecycle, or code drift: {row['activation_id']}"
            )
    return {
        "valid": True,
        "activation_count": len(observed),
        "source_tree_digest": recomputed["source_tree_digest"],
        "inventory_sha256": activation_inventory_digest(inventory),
        "runtime_authority_granted": recomputed[
            "runtime_authority_granted"
        ],
    }


__all__ = [
    "ActivationInventoryError",
    "GENERATOR_VERSION",
    "INVENTORY_SCHEMA_VERSION",
    "LiteralActivation",
    "activation_inventory_digest",
    "build_activation_inventory",
    "compute_decision_code_digest",
    "compute_declared_activation_code_digest",
    "compute_legacy_module_code_digest",
    "compute_source_tree_digest",
    "discover_literal_activations",
    "validate_activation_parity",
    "validate_no_direct_call_bypass",
]
