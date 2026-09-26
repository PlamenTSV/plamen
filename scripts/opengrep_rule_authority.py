"""Portable, release-bound authority for the installed OpenGrep rule trees.

The source builder is the only API that consults Git.  It is used while
building/installing a release to bind the public upstream, exact revision,
and current tracked bytes.  Runtime replay deliberately uses only the
installed manifest and ordinary filesystem metadata, so an installed Plamen
package never needs (or contains) submodule ``.git`` metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping


RULE_AUTHORITY_SCHEMA = "plamen.opengrep-rule-tree-authority.v1"
RULE_AUTHORITY_FILENAME = "rule-tree-authority.v1.json"
TREE_DIGEST_ALGORITHM = "sha256-path-size-content-v1"
CONTENT_DIGEST_ALGORITHM = "sha256-ordered-file-sha256-v1"
# Reviewed release pin for the manifest's unsigned authority digest.  The
# manifest cannot authorize replacement rule bytes merely by recomputing its
# own unkeyed digest; a rule revision intentionally requires this code pin to
# change in the same reviewed release.
EXPECTED_RULE_AUTHORITY_SHA256 = (
    "35df81eb7c272bb0972302517c988e915356201d8aaec2be991eff47e694e545"
)
MAX_RULE_FILES = 20_000
MAX_RULE_BYTES = 512 * 1024 * 1024
MAX_AUTHORITY_BYTES = 64 * 1024

# Public source governance is release code, not data accepted from the
# installed manifest.  Changing an upstream or revision therefore requires a
# reviewed source change and regeneration of the deterministic attestation.
OPENGREP_RULE_SOURCES: Mapping[str, tuple[str, str]] = {
    "aptos-move-rules": (
        "https://github.com/aptos-labs/semgrep-move-rules.git",
        "9ee5c476c6161d9eece74fd2f38685eb483b999c",
    ),
    "decurity-rules": (
        "https://github.com/Decurity/semgrep-smart-contracts.git",
        "2e878a89ac7bba1f8435e8a68e3ecb7700096cd5",
    ),
    "opengrep-rules": (
        "https://github.com/opengrep/opengrep-rules.git",
        "f1d2b562b414783763fd02a6ed2736eaed622efa",
    ),
}
OPENGREP_RULE_REVISIONS: Mapping[str, str] = {
    name: revision for name, (_source, revision) in OPENGREP_RULE_SOURCES.items()
}

# The runtime scanner consumes only these reviewed language roots.  The
# source authority above still authenticates each complete upstream checkout;
# this projection is the smaller, exact installed package denominator.  Each
# selected subtree is independently pinned so an installed package can replay
# authority without carrying unrelated upstream test/docs/language assets.
OPENGREP_RULE_PROJECTION: Mapping[str, tuple[str, ...]] = {
    "aptos-move-rules": ("rules",),
    "decurity-rules": ("rust", "solidity/security"),
    "opengrep-rules": ("rust", "solidity"),
}
EXPECTED_RULE_PROJECTION: Mapping[str, Mapping[str, tuple[int, int, str, str]]] = {
    "aptos-move-rules": {
        "rules": (
            17,
            46677,
            "42e36bbc65f4bc6ab3cc4936c57dbd349a0a6f11af26031907bbb531ea9b9317",
            "d465c40e06c28cd69371aa56bb8fb5d2a66d54df3ac21553031872143e3a15eb",
        ),
    },
    "decurity-rules": {
        "rust": (
            4,
            7375,
            "e3f9862cefe2aa002a3c8d206a9d14554ea06f1b65d7c91a9b59ae67b67dc6b5",
            "4c2470d2cba5d4ef0463f25f4240eb307dce2f46032d8e9dd87f3b70e2690e12",
        ),
        "solidity/security": (
            84,
            852471,
            "c610e3aed2c33681801cbec66b7b4e457dc785941331935c9bf9f3b1e6cfd03f",
            "1ce8ee4c2b4a315f01d98309c89511292816b18991248da52d3ba4b9de5983e2",
        ),
    },
    "opengrep-rules": {
        "rust": (
            20,
            11687,
            "a42e454f1383cf8067346070327bd3884994972b13a5c639292a788f4cc5f0f9",
            "7218315deee3ce3ea431514a3d4740c1eb79960c853f6b7c5f413ae33d13eeef",
        ),
        "solidity": (
            100,
            769042,
            "b61cec025377ac618160a721264345d97ea8218e6a6eab3c079ba7f2cfadc111",
            "b19b4006d580af413ae17d281810fca769061dce2f325491903b9f67cb7500b2",
        ),
    },
}

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_HEX_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$", re.ASCII)


class OpenGrepRuleAuthorityError(RuntimeError):
    """The packaged rule denominator cannot be authenticated exactly."""


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def _is_link_or_reparse(path: Path) -> bool:
    observed = os.lstat(path)
    if stat.S_ISLNK(observed.st_mode):
        return True
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(int(getattr(observed, "st_file_attributes", 0) or 0) & reparse)


def _capture_rule_tree(
    root: Path,
    *,
    source_checkout: bool,
) -> dict[str, Any]:
    root = Path(root)
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        raise OpenGrepRuleAuthorityError(
            f"rule tree is absent or unreadable: {root.name}: {type(exc).__name__}"
        ) from exc
    if not stat.S_ISDIR(root_stat.st_mode) or _is_link_or_reparse(root):
        raise OpenGrepRuleAuthorityError(
            f"rule tree is not an ordinary local directory: {root.name}"
        )

    file_rows: list[tuple[str, int, str]] = []
    folded_paths: set[str] = set()
    directory_count = 0
    total_bytes = 0

    def walk_error(exc: OSError) -> None:
        raise OpenGrepRuleAuthorityError(
            f"rule tree is unreadable: {root.name}: {type(exc).__name__}"
        ) from exc

    for dirpath, dirnames, filenames in os.walk(
        root, followlinks=False, onerror=walk_error
    ):
        directory_count += 1
        if directory_count > MAX_RULE_FILES:
            raise OpenGrepRuleAuthorityError("rule tree directory bound exceeded")
        directory = Path(dirpath)
        retained_dirs: list[str] = []
        local_names: set[str] = set()
        for name in sorted((*dirnames, *filenames), key=str.casefold):
            folded = name.casefold()
            if folded in local_names:
                raise OpenGrepRuleAuthorityError(
                    f"rule tree contains a case-colliding name: {root.name}/{name}"
                )
            local_names.add(folded)
        for name in sorted(dirnames, key=str.casefold):
            candidate = directory / name
            if name == ".git":
                if source_checkout and directory == root:
                    continue
                raise OpenGrepRuleAuthorityError(
                    f"packaged rule tree contains forbidden .git metadata: {root.name}"
                )
            if _is_link_or_reparse(candidate):
                raise OpenGrepRuleAuthorityError(
                    f"rule tree contains a directory link/reparse point: {root.name}/{name}"
                )
            retained_dirs.append(name)
        dirnames[:] = retained_dirs

        for name in sorted(filenames, key=str.casefold):
            candidate = directory / name
            if name == ".git":
                if source_checkout and directory == root:
                    continue
                raise OpenGrepRuleAuthorityError(
                    f"packaged rule tree contains forbidden .git metadata: {root.name}"
                )
            if _is_link_or_reparse(candidate):
                raise OpenGrepRuleAuthorityError(
                    f"rule tree contains a file link/reparse point: {root.name}/{name}"
                )
            observed = os.lstat(candidate)
            if not stat.S_ISREG(observed.st_mode):
                raise OpenGrepRuleAuthorityError(
                    f"rule tree contains a non-regular file: {root.name}/{name}"
                )
            if int(getattr(observed, "st_nlink", 1)) != 1:
                raise OpenGrepRuleAuthorityError(
                    f"rule tree contains a hard-linked file: {root.name}/{name}"
                )
            if observed.st_size < 0 or observed.st_size > MAX_RULE_BYTES - total_bytes:
                raise OpenGrepRuleAuthorityError("rule tree file/byte bound exceeded")
            relative = candidate.relative_to(root).as_posix()
            folded = relative.casefold()
            if folded in folded_paths:
                raise OpenGrepRuleAuthorityError(
                    f"rule tree contains a case-colliding path: {root.name}/{relative}"
                )
            try:
                raw = candidate.read_bytes()
            except OSError as exc:
                raise OpenGrepRuleAuthorityError(
                    f"rule file is unreadable: {root.name}/{relative}: {type(exc).__name__}"
                ) from exc
            # Re-check metadata after reading so a concurrent replacement does
            # not silently establish authority from mixed observations.
            after = os.lstat(candidate)
            if (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
                observed.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ):
                raise OpenGrepRuleAuthorityError(
                    f"rule file changed during capture: {root.name}/{relative}"
                )
            total_bytes += len(raw)
            if len(file_rows) >= MAX_RULE_FILES or total_bytes > MAX_RULE_BYTES:
                raise OpenGrepRuleAuthorityError("rule tree file/byte bound exceeded")
            file_rows.append((relative, len(raw), hashlib.sha256(raw).hexdigest()))
            folded_paths.add(folded)

    file_rows.sort(key=lambda row: row[0].encode("utf-8"))
    content_hasher = hashlib.sha256()
    tree_hasher = hashlib.sha256()
    for relative, size, digest in file_rows:
        content_hasher.update(digest.encode("ascii") + b"\n")
        tree_hasher.update(relative.encode("utf-8"))
        tree_hasher.update(b"\0" + str(size).encode("ascii") + b"\0")
        tree_hasher.update(digest.encode("ascii") + b"\n")
    return {
        "byte_count": total_bytes,
        "content_sha256": content_hasher.hexdigest(),
        "file_count": len(file_rows),
        "files": tuple(file_rows),
        "paths": tuple(row[0] for row in file_rows),
        "tree_sha256": tree_hasher.hexdigest(),
    }


def _git(root: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ("git", "-C", os.fspath(root), *args),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OpenGrepRuleAuthorityError(
            f"cannot inspect source Git authority for {root.name}: {type(exc).__name__}"
        ) from exc
    if result.returncode != 0:
        raise OpenGrepRuleAuthorityError(
            f"source Git authority rejected {root.name}: {' '.join(args)}"
        )
    return bytes(result.stdout)


def _normalized_git_source(value: str) -> str:
    source = value.strip()
    match = re.fullmatch(r"git@github\.com:(.+)", source, re.IGNORECASE)
    if match:
        source = "https://github.com/" + match.group(1)
    source = source.rstrip("/")
    if not source.casefold().endswith(".git"):
        source += ".git"
    return source.casefold()


def _read_authority_bytes(path: Path, *, label: str) -> bytes:
    try:
        observed = os.lstat(path)
        if (
            not stat.S_ISREG(observed.st_mode)
            or _is_link_or_reparse(path)
            or int(getattr(observed, "st_nlink", 1)) != 1
            or observed.st_size < 2
            or observed.st_size > MAX_AUTHORITY_BYTES
        ):
            raise OpenGrepRuleAuthorityError(
                f"{label} is not an ordinary bounded file"
            )
        raw = path.read_bytes()
        after = os.lstat(path)
        if (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise OpenGrepRuleAuthorityError(f"{label} changed during capture")
        return raw
    except OpenGrepRuleAuthorityError:
        raise
    except OSError as exc:
        raise OpenGrepRuleAuthorityError(
            f"{label} is unreadable: {type(exc).__name__}"
        ) from exc


def build_source_rule_authority(rules_base: Path) -> bytes:
    """Build deterministic manifest bytes from exact, clean Git submodules."""
    base = Path(rules_base)
    rows: list[dict[str, Any]] = []
    for name, (expected_source, expected_revision) in sorted(
        OPENGREP_RULE_SOURCES.items()
    ):
        root = base / name
        if not os.path.lexists(root / ".git"):
            raise OpenGrepRuleAuthorityError(
                f"source rule checkout has no Git metadata: {name}"
            )
        head = _git(root, "rev-parse", "HEAD").decode("ascii", "strict").strip()
        if head != expected_revision:
            raise OpenGrepRuleAuthorityError(
                f"source rule revision mismatch for {name}: expected {expected_revision}, got {head}"
            )
        origin = _git(root, "config", "--get", "remote.origin.url").decode(
            "utf-8", "strict"
        ).strip()
        if _normalized_git_source(origin) != _normalized_git_source(expected_source):
            raise OpenGrepRuleAuthorityError(
                f"source rule upstream mismatch for {name}"
            )
        if _git(root, "status", "--porcelain", "--untracked-files=all"):
            raise OpenGrepRuleAuthorityError(
                f"source rule checkout is dirty: {name}"
            )
        tracked_raw = _git(root, "ls-files", "-z")
        tracked = tracked_raw.decode("utf-8", "strict").split("\0")
        if tracked and tracked[-1] == "":
            tracked.pop()
        if len(tracked) != len(set(path.casefold() for path in tracked)):
            raise OpenGrepRuleAuthorityError(
                f"source rule Git index contains case-colliding paths: {name}"
            )
        captured = _capture_rule_tree(root, source_checkout=True)
        if tuple(sorted(tracked, key=lambda path: path.encode("utf-8"))) != captured["paths"]:
            raise OpenGrepRuleAuthorityError(
                f"source rule filesystem denominator differs from Git index: {name}"
            )
        if (
            _git(root, "rev-parse", "HEAD").decode("ascii", "strict").strip()
            != expected_revision
            or _git(root, "status", "--porcelain", "--untracked-files=all")
        ):
            raise OpenGrepRuleAuthorityError(
                f"source rule checkout changed during capture: {name}"
            )
        rows.append({
            "byte_count": captured["byte_count"],
            "content_sha256": captured["content_sha256"],
            "file_count": captured["file_count"],
            "name": name,
            "revision": expected_revision,
            "source": expected_source,
            "tree_sha256": captured["tree_sha256"],
        })
    unsigned: dict[str, Any] = {
        "content_digest_algorithm": CONTENT_DIGEST_ALGORITHM,
        "schema": RULE_AUTHORITY_SCHEMA,
        "tree_digest_algorithm": TREE_DIGEST_ALGORITHM,
        "trees": rows,
    }
    unsigned["authority_sha256"] = hashlib.sha256(_canonical_json(unsigned)).hexdigest()
    return _canonical_json(unsigned)


def _validate_full_installed_rule_authority(rules_base: Path) -> dict[str, Path]:
    """Replay an installed manifest and exact trees without invoking Git."""
    base = Path(rules_base)
    manifest_path = base / RULE_AUTHORITY_FILENAME
    try:
        raw = _read_authority_bytes(
            manifest_path, label="installed rule authority manifest"
        )
        manifest = json.loads(raw.decode("utf-8", "strict"))
    except OpenGrepRuleAuthorityError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OpenGrepRuleAuthorityError(
            f"installed rule authority manifest is unreadable: {type(exc).__name__}"
        ) from exc
    if not isinstance(manifest, dict) or _canonical_json(manifest) != raw:
        raise OpenGrepRuleAuthorityError(
            "installed rule authority manifest is not canonical"
        )
    if set(manifest) != {
        "authority_sha256",
        "content_digest_algorithm",
        "schema",
        "tree_digest_algorithm",
        "trees",
    }:
        raise OpenGrepRuleAuthorityError("installed rule authority keys are invalid")
    authority_sha256 = manifest.pop("authority_sha256", None)
    try:
        if (
            not isinstance(authority_sha256, str)
            or not _HEX64_RE.fullmatch(authority_sha256)
            or hashlib.sha256(_canonical_json(manifest)).hexdigest()
            != authority_sha256
            or authority_sha256 != EXPECTED_RULE_AUTHORITY_SHA256
        ):
            raise OpenGrepRuleAuthorityError(
                "installed rule authority digest is invalid"
            )
    finally:
        manifest["authority_sha256"] = authority_sha256
    if (
        manifest.get("schema") != RULE_AUTHORITY_SCHEMA
        or manifest.get("tree_digest_algorithm") != TREE_DIGEST_ALGORITHM
        or manifest.get("content_digest_algorithm") != CONTENT_DIGEST_ALGORITHM
    ):
        raise OpenGrepRuleAuthorityError("installed rule authority policy differs")
    rows = manifest.get("trees")
    if not isinstance(rows, list) or len(rows) != len(OPENGREP_RULE_SOURCES):
        raise OpenGrepRuleAuthorityError("installed rule authority tree roster differs")
    available: dict[str, Path] = {}
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "byte_count",
            "content_sha256",
            "file_count",
            "name",
            "revision",
            "source",
            "tree_sha256",
        }:
            raise OpenGrepRuleAuthorityError("installed rule authority row is malformed")
        name = row.get("name")
        if not isinstance(name, str) or name in seen or name not in OPENGREP_RULE_SOURCES:
            raise OpenGrepRuleAuthorityError("installed rule authority tree name differs")
        seen.add(name)
        expected_source, expected_revision = OPENGREP_RULE_SOURCES[name]
        if row.get("source") != expected_source or row.get("revision") != expected_revision:
            raise OpenGrepRuleAuthorityError(
                f"installed rule source/revision attestation differs: {name}"
            )
        if (
            not isinstance(row.get("file_count"), int)
            or isinstance(row.get("file_count"), bool)
            or row["file_count"] < 1
            or not isinstance(row.get("byte_count"), int)
            or isinstance(row.get("byte_count"), bool)
            or row["byte_count"] < 1
            or not _HEX64_RE.fullmatch(str(row.get("content_sha256", "")))
            or not _HEX64_RE.fullmatch(str(row.get("tree_sha256", "")))
            or not _HEX_REVISION_RE.fullmatch(str(row.get("revision", "")))
        ):
            raise OpenGrepRuleAuthorityError(
                f"installed rule attestation values are malformed: {name}"
            )
        captured = _capture_rule_tree(base / name, source_checkout=False)
        replay = _capture_rule_tree(base / name, source_checkout=False)
        if replay != captured:
            raise OpenGrepRuleAuthorityError(
                f"installed rule tree changed during validation: {name}"
            )
        for field in ("file_count", "byte_count", "content_sha256", "tree_sha256"):
            if captured[field] != row[field]:
                raise OpenGrepRuleAuthorityError(
                    f"installed rule tree content differs: {name}:{field}"
                )
        available[name] = base / name
    if seen != set(OPENGREP_RULE_SOURCES):
        raise OpenGrepRuleAuthorityError("installed rule authority tree roster is incomplete")
    return available


def validate_source_rule_authority(rules_base: Path) -> dict[str, Path]:
    """Require checked-in manifest bytes to match the exact clean source checkout."""
    base = Path(rules_base)
    expected = build_source_rule_authority(base)
    observed = _read_authority_bytes(
        base / RULE_AUTHORITY_FILENAME,
        label="source rule authority manifest",
    )
    if observed != expected:
        raise OpenGrepRuleAuthorityError(
            "source rule authority manifest is stale; regenerate before installation"
        )
    if json.loads(expected)["authority_sha256"] != EXPECTED_RULE_AUTHORITY_SHA256:
        raise OpenGrepRuleAuthorityError(
            "source rule authority differs from the reviewed release pin"
        )
    return {name: base / name for name in OPENGREP_RULE_SOURCES}


def _validated_projection_capture(
    base: Path,
    *,
    require_exact_package: bool,
) -> tuple[tuple[str, int, str], ...]:
    """Replay the release-pinned rule subset and return its exact census."""

    if (
        set(OPENGREP_RULE_PROJECTION) != set(OPENGREP_RULE_SOURCES)
        or set(EXPECTED_RULE_PROJECTION) != set(OPENGREP_RULE_SOURCES)
    ):
        raise OpenGrepRuleAuthorityError("rule projection tree roster differs")
    manifest_raw = _read_authority_bytes(
        base / RULE_AUTHORITY_FILENAME,
        label="rule authority manifest",
    )
    census: dict[str, tuple[int, str]] = {
        RULE_AUTHORITY_FILENAME: (
            len(manifest_raw), hashlib.sha256(manifest_raw).hexdigest(),
        )
    }
    for name in sorted(OPENGREP_RULE_SOURCES):
        prefixes = OPENGREP_RULE_PROJECTION[name]
        expected_rows = EXPECTED_RULE_PROJECTION[name]
        if (
            not isinstance(prefixes, tuple)
            or not prefixes
            or set(prefixes) != set(expected_rows)
            or len(prefixes) != len(set(prefix.casefold() for prefix in prefixes))
        ):
            raise OpenGrepRuleAuthorityError(
                f"rule projection policy is malformed: {name}"
            )
        tree_roster: set[str] = set()
        for prefix in prefixes:
            if (
                not isinstance(prefix, str)
                or not prefix
                or "\\" in prefix
                or any(part in {"", ".", "..", ".git"} for part in prefix.split("/"))
            ):
                raise OpenGrepRuleAuthorityError(
                    f"rule projection prefix is malformed: {name}"
                )
            captured = _capture_rule_tree(
                base / name / Path(*prefix.split("/")),
                source_checkout=False,
            )
            expected = expected_rows[prefix]
            observed = (
                captured["file_count"],
                captured["byte_count"],
                captured["content_sha256"],
                captured["tree_sha256"],
            )
            if observed != expected:
                raise OpenGrepRuleAuthorityError(
                    f"rule projection content differs: {name}/{prefix}"
                )
            for relative, size, digest in captured["files"]:
                projected = f"{prefix}/{relative}"
                if projected.casefold() in {
                    value.casefold() for value in tree_roster
                }:
                    raise OpenGrepRuleAuthorityError(
                        f"rule projection paths overlap: {name}/{projected}"
                    )
                tree_roster.add(projected)
                installed_path = f"{name}/{projected}"
                if installed_path in census:
                    raise OpenGrepRuleAuthorityError(
                        f"rule projection path is duplicated: {installed_path}"
                    )
                census[installed_path] = (size, digest)
        if require_exact_package:
            packaged = _capture_rule_tree(
                base / name,
                source_checkout=False,
            )
            if packaged["paths"] != tuple(
                sorted(tree_roster, key=lambda path: path.encode("utf-8"))
            ):
                raise OpenGrepRuleAuthorityError(
                    f"installed rule projection has ungoverned assets: {name}"
                )
    return tuple(
        (path, *census[path])
        for path in sorted(census, key=lambda value: value.encode("utf-8"))
    )


def source_rule_projection_census(
    rules_base: Path,
) -> tuple[tuple[str, int, str], ...]:
    """Return the exact source census admitted to the installed rule package."""

    base = Path(rules_base)
    validate_source_rule_authority(base)
    census = _validated_projection_capture(base, require_exact_package=False)
    # Close the capture interval over Git revision, cleanliness, and manifest
    # bytes so a concurrent source replacement cannot yield a mixed census.
    validate_source_rule_authority(base)
    return census


def source_rule_projection_roster(rules_base: Path) -> tuple[str, ...]:
    """Return the exact source paths admitted to the installed rule package."""

    return tuple(row[0] for row in source_rule_projection_census(rules_base))


def installed_rule_projection_census(
    rules_base: Path,
) -> tuple[tuple[str, int, str], ...]:
    """Return the authenticated install census from a full or lean package."""

    base = Path(rules_base)
    validate_installed_rule_authority(base)
    census = _validated_projection_capture(base, require_exact_package=False)
    validate_installed_rule_authority(base)
    return census


def installed_rule_projection_roster(rules_base: Path) -> tuple[str, ...]:
    """Return the authenticated install roster from a full or lean package."""

    return tuple(row[0] for row in installed_rule_projection_census(rules_base))


def validate_installed_rule_projection(rules_base: Path) -> dict[str, Path]:
    """Validate the exact reduced installed rule projection without Git."""

    base = Path(rules_base)
    # The manifest is the release/revision anchor.  A projected installation
    # cannot replay its full-tree aggregates, but it must carry the exact
    # canonical, release-pinned manifest bytes.
    raw = _read_authority_bytes(
        base / RULE_AUTHORITY_FILENAME,
        label="installed rule authority manifest",
    )
    try:
        manifest = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OpenGrepRuleAuthorityError(
            f"installed rule authority manifest is unreadable: {type(exc).__name__}"
        ) from exc
    if not isinstance(manifest, dict) or _canonical_json(manifest) != raw:
        raise OpenGrepRuleAuthorityError(
            "installed rule authority manifest is not canonical"
        )
    unsigned = dict(manifest)
    authority_sha256 = unsigned.pop("authority_sha256", None)
    if (
        set(manifest) != {
            "authority_sha256",
            "content_digest_algorithm",
            "schema",
            "tree_digest_algorithm",
            "trees",
        }
        or not isinstance(authority_sha256, str)
        or not _HEX64_RE.fullmatch(authority_sha256)
        or hashlib.sha256(_canonical_json(unsigned)).hexdigest()
        != authority_sha256
        or authority_sha256 != EXPECTED_RULE_AUTHORITY_SHA256
    ):
        raise OpenGrepRuleAuthorityError(
            "installed rule authority digest is invalid"
        )
    _validated_projection_capture(base, require_exact_package=True)
    return {name: base / name for name in OPENGREP_RULE_SOURCES}


def validate_installed_rule_authority(rules_base: Path) -> dict[str, Path]:
    """Replay either a complete legacy tree set or the governed projection."""

    try:
        return _validate_full_installed_rule_authority(rules_base)
    except OpenGrepRuleAuthorityError as full_error:
        try:
            return validate_installed_rule_projection(rules_base)
        except OpenGrepRuleAuthorityError as projection_error:
            raise OpenGrepRuleAuthorityError(
                "installed rule package matches neither admitted layout: "
                f"full={full_error}; projection={projection_error}"
            ) from projection_error


__all__ = [
    "CONTENT_DIGEST_ALGORITHM",
    "EXPECTED_RULE_AUTHORITY_SHA256",
    "MAX_AUTHORITY_BYTES",
    "OPENGREP_RULE_REVISIONS",
    "OPENGREP_RULE_PROJECTION",
    "OPENGREP_RULE_SOURCES",
    "EXPECTED_RULE_PROJECTION",
    "OpenGrepRuleAuthorityError",
    "RULE_AUTHORITY_FILENAME",
    "RULE_AUTHORITY_SCHEMA",
    "TREE_DIGEST_ALGORITHM",
    "build_source_rule_authority",
    "installed_rule_projection_census",
    "installed_rule_projection_roster",
    "source_rule_projection_census",
    "source_rule_projection_roster",
    "validate_installed_rule_authority",
    "validate_installed_rule_projection",
    "validate_source_rule_authority",
]
