"""Canonical content-independent production-source scope predicates.

This module is deliberately small and stdlib-only.  Recon graph producers,
snapshot binding, and post-agent graph consumers must classify a path the same
way without importing one another (or depending on a test/runtime shim for a
different phase).
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import AbstractSet


PRODUCTION_SOURCE_SKIP_PARTS = frozenset({
    "test", "tests", "fuzz", "fuzzing", "script", "scripts", "fixture",
    "fixtures", "mock", "mocks", "spec", "specs", "benchmark", "benchmarks",
    "medusa", "echidna", "halmos", ".medusa-tests",
})

PRODUCTION_SOURCE_SKIP_NAME_RE = re.compile(
    r"(^|[_\-.])(mock|stub|fake|fixture|test|spec|fuzz)([_\-.]|$)",
    re.IGNORECASE,
)


def is_production_source_path(path: Path, root: Path) -> bool:
    """Return whether *path* is eligible for production-source analysis.

    Directory-walker exclusions (build output, dependencies, VCS metadata)
    remain a caller concern because different producers intentionally walk
    different universes.  This predicate owns only the shared semantic
    exclusion of test, fixture, mock, fuzz, and benchmark paths.
    """
    try:
        relative = path.resolve().relative_to(root.resolve())
    except Exception:
        relative = path
    parents = [part.lower() for part in relative.parts[:-1]]
    if any(part in PRODUCTION_SOURCE_SKIP_PARTS for part in parents):
        return False
    stem = relative.stem.lower()
    if stem.startswith(("mock", "stub", "fake")):
        return False
    if stem.endswith(("mock", "stub", "fake", "fixture", "test", "spec", "fuzz")):
        return False
    return PRODUCTION_SOURCE_SKIP_NAME_RE.search(relative.name) is None


def walker_accepts_relative_path(
    raw_path: str,
    *,
    skip_dir_names: AbstractSet[str],
) -> bool:
    """Apply walker pruning plus the canonical production predicate.

    This is intended for artifact paths that need producer-parity checking
    without touching the filesystem.  Parent traversal and absolute paths are
    rejected because neither can be emitted by a bounded project-root walk.
    """
    normalized = str(raw_path or "").replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    parts = tuple(part for part in normalized.split("/") if part not in {"", "."})
    if not parts or ".." in parts or Path(normalized).is_absolute():
        return False
    parents = tuple(part.casefold() for part in parts[:-1])
    folded_skips = {str(part).casefold() for part in skip_dir_names}
    if any(part.startswith(".") or part in folded_skips for part in parents):
        return False
    root = Path.cwd() / "__plamen_production_scope__"
    return is_production_source_path(root.joinpath(*parts), root)


__all__ = [
    "PRODUCTION_SOURCE_SKIP_NAME_RE",
    "PRODUCTION_SOURCE_SKIP_PARTS",
    "is_production_source_path",
    "walker_accepts_relative_path",
]
