"""Portable lexical limits for untrusted relative artifact paths.

Traversal validation and filesystem representability are separate concerns.
An otherwise relative path can still make ``stat(2)`` fail when one component
exceeds ``NAME_MAX`` (the Run 71 failure) or when the encoded pathname is
unreasonably large.  Boundary adapters call this module *before* constructing
or probing a filesystem path; semantic allow-lists remain the caller's job.
"""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any


MAX_RELATIVE_PATH_BYTES = 1024
MAX_PATH_COMPONENT_BYTES = 255


class PortablePathContractError(ValueError):
    """Raised when a path token cannot be represented portably."""


def assert_lexically_bounded_relative_path(
    value: Any,
    *,
    label: str = "relative path",
    max_path_bytes: int = MAX_RELATIVE_PATH_BYTES,
    max_component_bytes: int = MAX_PATH_COMPONENT_BYTES,
) -> str:
    """Return *value* after bounded UTF-8/component validation.

    This deliberately does not normalize separators, whitespace, traversal,
    globs, or platform syntax.  Callers perform those policy checks first or
    afterwards according to their existing wire contract.  The invariant here
    is smaller: no model/provider string reaches a filesystem syscall unless
    its encoded pathname and every encoded component are bounded.
    """

    if not isinstance(value, str) or not value:
        raise PortablePathContractError(f"{label} is empty or not a string")
    try:
        encoded = value.encode("utf-8", errors="strict")
        parts = PurePosixPath(value).parts
        component_sizes = tuple(
            len(part.encode("utf-8", errors="strict")) for part in parts
        )
    except (UnicodeError, ValueError) as exc:
        raise PortablePathContractError(
            f"{label} is not strict UTF-8 path text"
        ) from exc
    if "\x00" in value or "\r" in value or "\n" in value:
        raise PortablePathContractError(f"{label} contains a control delimiter")
    if len(encoded) > max_path_bytes:
        raise PortablePathContractError(
            f"{label} exceeds {max_path_bytes} encoded bytes"
        )
    if not parts or any(size > max_component_bytes for size in component_sizes):
        raise PortablePathContractError(
            f"{label} contains a component exceeding "
            f"{max_component_bytes} encoded bytes"
        )
    return value


__all__ = [
    "MAX_PATH_COMPONENT_BYTES",
    "MAX_RELATIVE_PATH_BYTES",
    "PortablePathContractError",
    "assert_lexically_bounded_relative_path",
]
