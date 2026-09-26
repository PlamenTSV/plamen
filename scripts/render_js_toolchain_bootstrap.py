#!/usr/bin/env python3
"""Deterministically render or verify the reviewed JS bootstrap anchor.

The renderer deliberately does not bless archive drift.  Node and Yarn archive
identities are frozen below, while source/control changes must be named with an
explicit ``--allow-source-change`` argument and remain inside the fixed member
roster.  Output is written to stdout; publication remains a reviewed source
change performed by the caller.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Iterable


SCHEMA = "plamen.js-toolchain-bootstrap.v1"
TRUST_ASSUMPTION = (
    "EXTERNAL_AUTHENTICATED_DISTRIBUTION_AND_INSTALL_PROVENANCE_V1"
)
ANCHOR_RELATIVE_PATH = Path("verification_policy/js_toolchain_bootstrap.v1.json")
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MEMBER_KEYS = frozenset({"digest_mode", "kind", "path", "sha256", "size"})

# Ordering is part of the release surface and matches the reviewed bootstrap.
MEMBERS = (
    ("runtime/toolchains/js/node/node-v24.20.0-darwin-arm64.tar.gz", "runtime-data", "raw-v1"),
    ("runtime/toolchains/js/node/node-v24.20.0-darwin-x64.tar.gz", "runtime-data", "raw-v1"),
    ("runtime/toolchains/js/node/node-v24.20.0-linux-arm64.tar.xz", "runtime-data", "raw-v1"),
    ("runtime/toolchains/js/node/node-v24.20.0-linux-x64.tar.xz", "runtime-data", "raw-v1"),
    ("runtime/toolchains/js/node/node-v24.20.0-win-arm64.zip", "runtime-data", "raw-v1"),
    ("runtime/toolchains/js/node/node-v24.20.0-win-x64.zip", "runtime-data", "raw-v1"),
    ("runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz", "runtime-data", "raw-v1"),
    ("scripts/js_dependency_materializer_authority.py", "python-source", "utf8-lf-v1"),
    ("scripts/js_dependency_materializer_runtime.py", "python-source", "utf8-lf-v1"),
    ("scripts/js_lock_authority.py", "python-source", "utf8-lf-v1"),
    ("scripts/js_toolchain_authority.py", "python-source", "utf8-lf-v1"),
    ("verification_policy/js_toolchain_authority.v1.json", "control", "utf8-lf-v1"),
)

ARCHIVE_IDENTITIES = {
    "runtime/toolchains/js/node/node-v24.20.0-darwin-arm64.tar.gz": (
        "40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8",
        52_813_331,
    ),
    "runtime/toolchains/js/node/node-v24.20.0-darwin-x64.tar.gz": (
        "9e5b2644cf107befb6aefca676b96d3296bc10138096f022ed378d6233ed81f4",
        54_021_618,
    ),
    "runtime/toolchains/js/node/node-v24.20.0-linux-arm64.tar.xz": (
        "5f4ddab610c1ab2016b3c227cebdbf6d9495161487e4739c7b90090595f465f7",
        30_778_928,
    ),
    "runtime/toolchains/js/node/node-v24.20.0-linux-x64.tar.xz": (
        "2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2",
        31_838_904,
    ),
    "runtime/toolchains/js/node/node-v24.20.0-win-arm64.zip": (
        "31c6799744de8a54601643098040c68c3697e56c94e407d61d0e5fa5f34191d7",
        33_621_271,
    ),
    "runtime/toolchains/js/node/node-v24.20.0-win-x64.zip": (
        "6cac9ffbca8f6a47091e4b5c772e0606049c3871cb67d900c0cedde630e545ba",
        37_539_751,
    ),
    "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz": (
        "88268464199d1611fcf73ce9c0a6c4d44c7d5363682720d8506f6508addf36a0",
        1_247_457,
    ),
}


class BootstrapRenderError(RuntimeError):
    """The source release cannot produce the reviewed bootstrap anchor."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BootstrapRenderError("bootstrap anchor contains duplicate keys")
        value[key] = item
    return value


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")


def _read_member(root: Path, relative: str, digest_mode: str) -> tuple[str, int]:
    path = root / relative
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BootstrapRenderError(f"bootstrap member is unreadable: {relative}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_MEMBER_BYTES
        ):
            raise BootstrapRenderError(f"bootstrap member is unsafe: {relative}")
        raw = bytearray()
        while True:
            block = os.read(descriptor, min(1024 * 1024, MAX_MEMBER_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            if len(raw) > MAX_MEMBER_BYTES:
                raise BootstrapRenderError(f"bootstrap member exceeds bound: {relative}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BootstrapRenderError(f"bootstrap member drifted while read: {relative}")
    finally:
        os.close(descriptor)
    payload = bytes(raw)
    if digest_mode == "utf8-lf-v1":
        try:
            payload = payload.decode("utf-8", "strict").replace("\r\n", "\n").encode("utf-8")
        except UnicodeError as exc:
            raise BootstrapRenderError(f"bootstrap member is not UTF-8: {relative}") from exc
    elif digest_mode != "raw-v1":
        raise BootstrapRenderError(f"bootstrap member digest mode is invalid: {relative}")
    return hashlib.sha256(payload).hexdigest(), int(before.st_size)


def _load_anchor(root: Path) -> dict[str, Any]:
    try:
        raw = (root / ANCHOR_RELATIVE_PATH).read_bytes()
        value = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                BootstrapRenderError("bootstrap anchor contains a non-finite number")
            ),
        )
    except BootstrapRenderError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise BootstrapRenderError("bootstrap anchor is unreadable or malformed") from exc
    if type(value) is not dict or set(value) != {
        "schema", "signed_set", "signed_set_sha256", "trust_assumption"
    }:
        raise BootstrapRenderError("bootstrap anchor schema differs")
    if value.get("schema") != SCHEMA or value.get("trust_assumption") != TRUST_ASSUMPTION:
        raise BootstrapRenderError("bootstrap anchor authority differs")
    rows = value.get("signed_set")
    if type(rows) is not list or len(rows) != len(MEMBERS):
        raise BootstrapRenderError("bootstrap member roster differs")
    for row, expected in zip(rows, MEMBERS, strict=True):
        if (
            type(row) is not dict
            or set(row) != MEMBER_KEYS
            or (row.get("path"), row.get("kind"), row.get("digest_mode")) != expected
        ):
            raise BootstrapRenderError("bootstrap member roster differs")
    return value


def render_anchor(
    root: Path,
    *,
    allowed_source_changes: Iterable[str] = (),
) -> bytes:
    """Render exact anchor bytes after explicitly authorizing source deltas."""

    root = root.resolve(strict=True)
    current = _load_anchor(root)
    allowed = frozenset(allowed_source_changes)
    source_members = frozenset(path for path, kind, _mode in MEMBERS if kind != "runtime-data")
    if not allowed.issubset(source_members):
        raise BootstrapRenderError("allowed source change is outside the fixed roster")

    rows: list[dict[str, object]] = []
    changed: set[str] = set()
    for old, (relative, kind, digest_mode) in zip(current["signed_set"], MEMBERS, strict=True):
        digest, size = _read_member(root, relative, digest_mode)
        if kind == "runtime-data":
            if (digest, size) != ARCHIVE_IDENTITIES[relative]:
                raise BootstrapRenderError(f"reviewed archive identity differs: {relative}")
            if (old["sha256"], old["size"]) != ARCHIVE_IDENTITIES[relative]:
                raise BootstrapRenderError(f"anchor archive identity differs: {relative}")
        elif (old["sha256"], old["size"]) != (digest, size):
            changed.add(relative)
        rows.append(
            {
                "digest_mode": digest_mode,
                "kind": kind,
                "path": relative,
                "sha256": digest,
                "size": size,
            }
        )
    if changed != allowed:
        unexpected = sorted(changed ^ allowed)
        raise BootstrapRenderError(
            "reviewed source-change set differs: " + ", ".join(unexpected)
        )

    value = {
        "schema": SCHEMA,
        "signed_set": rows,
        "signed_set_sha256": hashlib.sha256(_canonical(rows)).hexdigest(),
        "trust_assumption": TRUST_ASSUMPTION,
    }
    return (json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2) + "\n").encode("ascii")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "render"))
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--allow-source-change", action="append", default=[])
    arguments = parser.parse_args(argv)
    rendered = render_anchor(
        arguments.root,
        allowed_source_changes=arguments.allow_source_change,
    )
    if arguments.command == "render":
        sys.stdout.buffer.write(rendered)
        return 0
    observed = (arguments.root / ANCHOR_RELATIVE_PATH).read_bytes()
    if observed != rendered:
        raise BootstrapRenderError("bootstrap anchor bytes differ from deterministic render")
    print(hashlib.sha256(observed).hexdigest())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BootstrapRenderError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
