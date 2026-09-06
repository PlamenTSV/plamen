"""Prepare, but never launch, an isolated legacy-Claude Plamen audit.

The deterministic driver is the sole audit orchestrator.  This module owns only
the pre-launch filesystem boundary needed when a source checkout already holds
prior audit evidence:

* discover and hash-seal prior scratchpads/reports without modifying them;
* copy the source into a distinct, previously nonexistent workspace while
  excluding prior audit evidence;
* write one clean ``.scratchpad/config.json`` for the Claude backend; and
* render exact fresh and resume argument vectors for the shared driver.

It deliberately contains no process-launch primitive.  A caller must separately
execute the emitted driver argv after reviewing the receipts.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
from typing import Any, Iterable


SEAL_SCHEMA = "plamen.prior-audit-evidence-seal.v1"
PREPARATION_SCHEMA = "plamen.terminal-audit-preparation.v1"
_MAX_EVIDENCE_ENTRIES = 1_000_000
_MAX_COPY_ENTRIES = 2_000_000
_PRIOR_DIRECTORY_NAMES = frozenset({
    ".scratchpad",
    ".plamen-stale-snapshots",
    ".medusa-tests",
})
_PRIOR_DIRECTORY_PREFIXES = (
    # Alternate scratchpads are unsafe audit inputs even though the driver
    # itself writes only the canonical name.  Older/manual runs commonly used
    # suffixes such as ``.scratchpad-run-2``.
    ".scratchpad",
    ".plamen_archive_",
)
_PRIOR_FILE_PATTERNS = (
    "AUDIT_REPORT*.md",
    "*_RCA.md",
    "*-RCA.md",
    "CONSOLIDATION-FIX-NOTES.md",
)
_SC_LANGUAGES = frozenset({"evm", "solana", "aptos", "sui", "soroban", "daml"})
_L1_LANGUAGES = frozenset({"go", "rust"})
_LANGUAGES = _SC_LANGUAGES | _L1_LANGUAGES
_MODES = frozenset({"light", "core", "thorough"})
_L1_TIERS = frozenset({"t0", "t1", "t2", "t3"})
_FORK_MODES = frozenset({"standalone", "upstream_diff", "both"})


class TerminalAuditPreparationError(RuntimeError):
    """A preparation boundary could not be established without ambiguity."""


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _render_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _is_junction(path: Path) -> bool:
    try:
        return bool(hasattr(path, "is_junction") and path.is_junction())
    except OSError:
        return True


def _is_reparse_point(path: Path) -> bool:
    """Recognize Windows reparse points not covered by symlink/junction APIs."""

    try:
        info = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    attributes = int(getattr(info, "st_file_attributes", 0))
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return bool(attributes & marker)


def _stable_path(path: Path, *, strict: bool) -> Path:
    try:
        return path.resolve(strict=strict)
    except OSError as exc:
        raise TerminalAuditPreparationError(
            f"cannot resolve preparation path {path}: {exc}"
        ) from exc


def _assert_no_existing_link_components(path: Path, *, label: str) -> None:
    """Reject a link/reparse component before resolving an output identity."""

    lexical = Path(path).expanduser().absolute()
    candidates = [*reversed(lexical.parents), lexical]
    for candidate in candidates:
        # Filesystem anchors are not user-selected output parents.
        if candidate == Path(candidate.anchor):
            continue
        try:
            linked = (
                candidate.is_symlink()
                or _is_junction(candidate)
                or _is_reparse_point(candidate)
            )
        except OSError as exc:
            raise TerminalAuditPreparationError(
                f"cannot inspect {label} path component {candidate}: {exc}"
            ) from exc
        if linked:
            raise TerminalAuditPreparationError(
                f"{label} path contains a link component: {candidate}"
            )


def _path_state(path: Path) -> tuple[int, int, int, int, int]:
    value = path.stat(follow_symlinks=False)
    return (
        int(value.st_size),
        int(value.st_mtime_ns),
        int(getattr(value, "st_ctime_ns", 0)),
        int(getattr(value, "st_dev", 0)),
        int(getattr(value, "st_ino", 0)),
    )


def _forbidden_identity_boundary(
    paths: Iterable[Path],
) -> tuple[tuple[Path, ...], frozenset[tuple[int, int]]]:
    resolved: list[Path] = []
    file_ids: set[tuple[int, int]] = set()
    for value in paths:
        try:
            path = Path(value).resolve(strict=False)
        except OSError as exc:
            # The forbidden path itself is sensitive control input.  Never
            # echo its basename/path into logs or receipts on failure.
            raise TerminalAuditPreparationError(
                "cannot resolve forbidden evaluation input identity"
            ) from exc
        resolved.append(path)
        if path.exists():
            try:
                info = path.stat()
            except OSError as exc:
                raise TerminalAuditPreparationError(
                    f"cannot inspect forbidden evaluation input identity: {exc}"
                ) from exc
            file_ids.add((int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0))))
    return tuple(resolved), frozenset(file_ids)


def _matches_forbidden_identity(
    path: Path,
    forbidden_paths: tuple[Path, ...],
    forbidden_file_ids: frozenset[tuple[int, int]],
) -> bool:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path.absolute()
    for forbidden in forbidden_paths:
        if resolved == forbidden or (forbidden.is_dir() and _is_relative_to(resolved, forbidden)):
            return True
    if path.exists():
        try:
            info = path.stat()
        except OSError:
            return True
        identity = (int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0)))
        if identity in forbidden_file_ids:
            return True
    return False


def _assert_no_forbidden_source_aliases(
    source: Path,
    forbidden_paths: tuple[Path, ...],
    forbidden_file_ids: frozenset[tuple[int, int]],
) -> None:
    """Reject path, symlink, junction, or hardlink aliases without reading bytes."""

    seen = 0
    for directory, dirnames, filenames in os.walk(source, followlinks=False):
        base = Path(directory)
        retained: list[str] = []
        for name in sorted(dirnames, key=str.casefold):
            seen += 1
            if seen > _MAX_COPY_ENTRIES:
                raise TerminalAuditPreparationError(
                    "forbidden-input alias scan exceeded its entry bound"
                )
            candidate = base / name
            if _matches_forbidden_identity(
                candidate, forbidden_paths, forbidden_file_ids
            ):
                raise TerminalAuditPreparationError(
                    "forbidden evaluation input is aliased inside the audit source"
                )
            if (
                not candidate.is_symlink()
                and not _is_junction(candidate)
                and not _is_reparse_point(candidate)
            ):
                retained.append(name)
        dirnames[:] = retained
        for name in sorted(filenames, key=str.casefold):
            seen += 1
            if seen > _MAX_COPY_ENTRIES:
                raise TerminalAuditPreparationError(
                    "forbidden-input alias scan exceeded its entry bound"
                )
            if _matches_forbidden_identity(
                base / name, forbidden_paths, forbidden_file_ids
            ):
                raise TerminalAuditPreparationError(
                    "forbidden evaluation input is aliased inside the audit source"
                )


def _validated_source_link_target(
    path: Path,
    source: Path,
    evidence_roots: tuple[Path, ...],
    forbidden_paths: tuple[Path, ...],
    forbidden_file_ids: frozenset[tuple[int, int]],
    evidence_file_ids: frozenset[tuple[int, int]] = frozenset(),
) -> str:
    """Return a safe relative file-link target without reading target bytes."""

    try:
        raw_target = os.readlink(path)
    except OSError as exc:
        raise TerminalAuditPreparationError(
            f"cannot read source link target {path}: {exc}"
        ) from exc
    target_path = Path(raw_target)
    if target_path.is_absolute():
        raise TerminalAuditPreparationError(
            f"source link escapes source via an absolute target: {path}"
        )
    try:
        resolved = (path.parent / target_path).resolve(strict=True)
    except OSError as exc:
        raise TerminalAuditPreparationError(
            f"source link has no exact readable target: {path}: {exc}"
        ) from exc
    if not _is_relative_to(resolved, source):
        raise TerminalAuditPreparationError(f"source link escapes source: {path}")
    normalized_evidence = tuple(root.absolute() for root in evidence_roots)
    if any(
        resolved == root or _is_relative_to(resolved, root)
        for root in normalized_evidence
    ):
        raise TerminalAuditPreparationError(
            f"source link enters excluded prior-audit evidence: {path}"
        )
    if _matches_forbidden_identity(
        resolved, forbidden_paths, forbidden_file_ids
    ):
        raise TerminalAuditPreparationError(
            f"source link intersects forbidden evaluation input: {path}"
        )
    if _has_file_identity(resolved, evidence_file_ids):
        raise TerminalAuditPreparationError(
            f"source link aliases excluded prior-audit evidence: {path}"
        )
    if resolved.is_dir():
        # The driver's bound source snapshot rejects directory links.  A
        # launcher must not emit a workspace that is guaranteed to fail.
        raise TerminalAuditPreparationError(
            f"source directory symlink is unsupported by the driver: {path}"
        )
    return raw_target


def _assert_safe_source_links(
    source: Path,
    evidence_roots: tuple[Path, ...],
    forbidden_paths: tuple[Path, ...],
    forbidden_file_ids: frozenset[tuple[int, int]],
    evidence_file_ids: frozenset[tuple[int, int]] = frozenset(),
) -> None:
    """Validate every copy-eligible source link without dereferencing its bytes."""

    normalized_evidence = tuple(path.absolute() for path in evidence_roots)

    def excluded(path: Path) -> bool:
        absolute = path.absolute()
        return any(
            absolute == root or _is_relative_to(absolute, root)
            for root in normalized_evidence
        )

    seen = 0
    for directory, dirnames, filenames in os.walk(source, followlinks=False):
        base = Path(directory)
        retained: list[str] = []
        for name in sorted(dirnames, key=str.casefold):
            seen += 1
            if seen > _MAX_COPY_ENTRIES:
                raise TerminalAuditPreparationError(
                    "source-link validation exceeded its entry bound"
                )
            candidate = base / name
            if excluded(candidate):
                continue
            if candidate.is_symlink():
                _validated_source_link_target(
                    candidate,
                    source,
                    normalized_evidence,
                    forbidden_paths,
                    forbidden_file_ids,
                    evidence_file_ids,
                )
                continue
            if _is_junction(candidate) or _is_reparse_point(candidate):
                raise TerminalAuditPreparationError(
                    f"source contains an untrusted reparse point: {candidate}"
                )
            retained.append(name)
        dirnames[:] = retained
        for name in sorted(filenames, key=str.casefold):
            seen += 1
            if seen > _MAX_COPY_ENTRIES:
                raise TerminalAuditPreparationError(
                    "source-link validation exceeded its entry bound"
                )
            candidate = base / name
            if excluded(candidate):
                continue
            if candidate.is_symlink():
                _validated_source_link_target(
                    candidate,
                    source,
                    normalized_evidence,
                    forbidden_paths,
                    forbidden_file_ids,
                    evidence_file_ids,
                )
            elif _is_junction(candidate) or _is_reparse_point(candidate):
                raise TerminalAuditPreparationError(
                    f"source contains an untrusted reparse point: {candidate}"
                )


def _atomic_write_new_or_same(path: Path, raw: bytes) -> None:
    if path.is_symlink() or _is_junction(path):
        raise TerminalAuditPreparationError(f"receipt destination is a link: {path}")
    if path.exists():
        if not path.is_file() or path.read_bytes() != raw:
            raise TerminalAuditPreparationError(
                f"receipt destination already contains different evidence: {path}"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_existing_link_components(path.parent, label="receipt")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise TerminalAuditPreparationError(
            f"temporary receipt path already exists: {temporary}"
        )
    try:
        with temporary.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        # Publish without replacement.  ``os.replace`` would overwrite a
        # receipt another process created after the existence check.  A
        # same-directory hard link gives an atomic create-if-absent boundary
        # while retaining the fully flushed temporary preimage.
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if path.is_symlink() or _is_junction(path) or _is_reparse_point(path):
                raise TerminalAuditPreparationError(
                    f"receipt destination became a link: {path}"
                )
            if not path.is_file() or path.read_bytes() != raw:
                raise TerminalAuditPreparationError(
                    f"receipt destination already contains different evidence: {path}"
                )
        if not path.is_file() or path.read_bytes() != raw:
            raise TerminalAuditPreparationError(
                f"published preparation receipt failed exact reread: {path}"
            )
    except Exception as exc:
        raise TerminalAuditPreparationError(
            f"could not persist preparation receipt {path}: {exc}"
        ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _is_prior_directory_name(name: str) -> bool:
    folded = name.casefold()
    return (
        folded in {value.casefold() for value in _PRIOR_DIRECTORY_NAMES}
        or any(folded.startswith(prefix.casefold()) for prefix in _PRIOR_DIRECTORY_PREFIXES)
    )


def _is_prior_file_name(name: str) -> bool:
    folded = name.casefold()
    return any(fnmatch.fnmatchcase(folded, pattern.casefold()) for pattern in _PRIOR_FILE_PATTERNS)


def discover_prior_audit_evidence(project_root: Path) -> tuple[Path, ...]:
    """Enumerate known prior-run roots and report artifacts without following links."""

    root = _stable_path(Path(project_root), strict=True)
    if not root.is_dir():
        raise TerminalAuditPreparationError(f"source project is not a directory: {root}")
    found: list[Path] = []
    seen = 0
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        retained: list[str] = []
        for name in sorted(dirnames, key=str.casefold):
            seen += 1
            if seen > _MAX_EVIDENCE_ENTRIES:
                raise TerminalAuditPreparationError("prior-evidence discovery exceeded its entry bound")
            candidate = base / name
            if _is_prior_directory_name(name):
                found.append(candidate.absolute())
                continue
            if (
                candidate.is_symlink()
                or _is_junction(candidate)
                or _is_reparse_point(candidate)
            ):
                # Do not cross an opaque filesystem boundary merely to search
                # for evidence.  A specifically named link is handled above.
                continue
            retained.append(name)
        dirnames[:] = retained
        for name in sorted(filenames, key=str.casefold):
            seen += 1
            if seen > _MAX_EVIDENCE_ENTRIES:
                raise TerminalAuditPreparationError("prior-evidence discovery exceeded its entry bound")
            if _is_prior_file_name(name):
                found.append((base / name).absolute())
    # Pre-P0-AO fresh runs moved root-level reports into a dot-prefixed sibling
    # directory.  Those archives carry no reliable project identifier, so the
    # only recall-safe deterministic policy is to seal every convention-matching
    # sibling.  This may be conservatively over-inclusive when projects share a
    # parent, but it is read-only and cannot expose any archive to the new run.
    try:
        siblings = sorted(root.parent.iterdir(), key=lambda value: value.name.casefold())
    except OSError as exc:
        raise TerminalAuditPreparationError(
            f"cannot enumerate legacy sibling archives beside {root}: {exc}"
        ) from exc
    for candidate in siblings:
        if candidate == root:
            continue
        if candidate.name.casefold().startswith(".plamen_archive_"):
            found.append(candidate.absolute())
    unique = {os.path.normcase(str(path)): path for path in found}
    return tuple(unique[key] for key in sorted(unique))


def _snapshot_evidence_root(path: Path) -> dict[str, Any]:
    root = Path(path).absolute()
    if not root.exists() and not root.is_symlink():
        raise TerminalAuditPreparationError(f"prior evidence disappeared during sealing: {root}")
    entries: list[dict[str, Any]] = []
    count = 0

    def visit(current: Path, relative: str) -> None:
        nonlocal count
        count += 1
        if count > _MAX_EVIDENCE_ENTRIES:
            raise TerminalAuditPreparationError("prior-evidence seal exceeded its entry bound")
        before = _path_state(current)
        if current.is_symlink() or _is_junction(current):
            try:
                target = os.readlink(current)
            except OSError as exc:
                raise TerminalAuditPreparationError(
                    f"cannot read prior-evidence link {current}: {exc}"
                ) from exc
            record = {
                "relative_path": relative,
                "type": "link",
                "target": target,
            }
        elif _is_reparse_point(current):
            raise TerminalAuditPreparationError(
                f"unsupported prior-evidence reparse point: {current}"
            )
        elif current.is_file():
            record = {
                "relative_path": relative,
                "type": "file",
                "bytes": before[0],
                "sha256": _sha256_file(current),
            }
        elif current.is_dir():
            record = {"relative_path": relative, "type": "directory"}
            try:
                children = sorted(current.iterdir(), key=lambda value: value.name.casefold())
            except OSError as exc:
                raise TerminalAuditPreparationError(
                    f"cannot enumerate prior evidence {current}: {exc}"
                ) from exc
            for child in children:
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                visit(child, child_relative)
        else:
            raise TerminalAuditPreparationError(
                f"unsupported prior-evidence filesystem entry: {current}"
            )
        after = _path_state(current)
        if before != after:
            raise TerminalAuditPreparationError(
                f"prior evidence changed while being sealed: {current}"
            )
        entries.append(record)

    visit(root, ".")
    entries.sort(key=lambda row: (str(row["relative_path"]).casefold(), str(row["type"])))
    return {"path": str(root), "entries": entries}


def _build_prior_evidence_seal(
    project_root: Path, evidence_roots: Iterable[Path] | None = None
) -> dict[str, Any]:
    root = _stable_path(Path(project_root), strict=True)
    selected = tuple(evidence_roots) if evidence_roots is not None else discover_prior_audit_evidence(root)
    normalized: list[Path] = []
    seen: set[str] = set()
    for value in selected:
        candidate = Path(value).absolute()
        key = os.path.normcase(str(candidate))
        if key not in seen:
            seen.add(key)
            normalized.append(candidate)
    evidence = [_snapshot_evidence_root(path) for path in sorted(normalized, key=lambda p: str(p).casefold())]
    unsigned: dict[str, Any] = {
        "schema_version": SEAL_SCHEMA,
        "project_root": str(root),
        "evidence_root_count": len(evidence),
        "entry_count": sum(len(row["entries"]) for row in evidence),
        "evidence_roots": evidence,
        "hash_algorithm": "sha256",
        "authentication": "UNKEYED_INTEGRITY_ONLY",
    }
    unsigned["manifest_sha256"] = _sha256_bytes(_canonical_bytes(unsigned))
    return unsigned


def _evidence_file_identities(evidence_roots: Iterable[Path]) -> frozenset[tuple[int, int]]:
    """Enumerate regular-file identities inside sealed evidence without bytes."""

    identities: set[tuple[int, int]] = set()
    seen = 0

    def visit(path: Path) -> None:
        nonlocal seen
        seen += 1
        if seen > _MAX_EVIDENCE_ENTRIES:
            raise TerminalAuditPreparationError(
                "prior-evidence identity scan exceeded its entry bound"
            )
        if path.is_symlink() or _is_junction(path) or _is_reparse_point(path):
            return
        try:
            info = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise TerminalAuditPreparationError(
                "cannot inspect prior-evidence identity"
            ) from exc
        if path.is_file():
            identities.add(
                (int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0)))
            )
        elif path.is_dir():
            try:
                children = sorted(path.iterdir(), key=lambda value: value.name.casefold())
            except OSError as exc:
                raise TerminalAuditPreparationError(
                    "cannot enumerate prior-evidence identities"
                ) from exc
            for child in children:
                visit(child)

    for root in evidence_roots:
        visit(Path(root))
    return frozenset(identities)


def _has_file_identity(path: Path, identities: frozenset[tuple[int, int]]) -> bool:
    if not identities or not path.exists():
        return False
    try:
        info = path.stat()
    except OSError:
        return True
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
    ) in identities


def _require_external_receipt(path: Path, protected_roots: Iterable[Path]) -> Path:
    raw_destination = Path(path)
    _assert_no_existing_link_components(raw_destination, label="receipt")
    destination = _stable_path(raw_destination, strict=False)
    for value in protected_roots:
        protected = _stable_path(Path(value), strict=False)
        if _is_relative_to(destination, protected):
            raise TerminalAuditPreparationError(
                f"receipt must be outside protected source/workspace: {destination}"
            )
    return destination


def seal_prior_audit_evidence(project_root: Path, receipt_path: Path) -> dict[str, Any]:
    """Hash-seal prior evidence to an external receipt; never mutate the project."""

    root = _stable_path(Path(project_root), strict=True)
    destination = _require_external_receipt(Path(receipt_path), (root,))
    payload = _build_prior_evidence_seal(root)
    _atomic_write_new_or_same(destination, _render_json(payload))
    return payload


def verify_prior_audit_evidence_seal(receipt_path: Path) -> tuple[str, ...]:
    issues: list[str] = []
    path = Path(receipt_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as exc:
        return (f"seal receipt is unreadable: {type(exc).__name__}: {exc}",)
    if payload.get("schema_version") != SEAL_SCHEMA:
        issues.append("seal receipt schema is unsupported")
    recorded_digest = str(payload.get("manifest_sha256") or "")
    unsigned = {key: value for key, value in payload.items() if key != "manifest_sha256"}
    if _sha256_bytes(_canonical_bytes(unsigned)) != recorded_digest:
        issues.append("seal receipt manifest digest is invalid")
        return tuple(issues)
    try:
        project_root = Path(str(payload["project_root"]))
        current_roots = discover_prior_audit_evidence(project_root)
        recorded_roots = tuple(
            Path(str(row["path"])) for row in payload.get("evidence_roots", [])
        )
        current_keys = {os.path.normcase(str(path.absolute())) for path in current_roots}
        recorded_keys = {os.path.normcase(str(path.absolute())) for path in recorded_roots}
        if current_keys != recorded_keys:
            issues.append("prior-evidence root set drifted after sealing")
        rebuilt = _build_prior_evidence_seal(project_root, recorded_roots)
        if rebuilt.get("manifest_sha256") != recorded_digest:
            issues.append("prior-evidence manifest drifted after sealing")
    except Exception as exc:
        issues.append(f"prior-evidence drift check failed: {type(exc).__name__}: {exc}")
    return tuple(issues)


def _excluded_from_workspace(
    path: Path,
    evidence_roots: tuple[Path, ...],
    evidence_file_ids: frozenset[tuple[int, int]] = frozenset(),
) -> bool:
    absolute = path.absolute()
    if any(absolute == root or _is_relative_to(absolute, root) for root in evidence_roots):
        return True
    return (
        _is_prior_directory_name(path.name)
        or _is_prior_file_name(path.name)
        or _has_file_identity(path, evidence_file_ids)
    )


def _copy_isolated_project(
    source_project: Path,
    workspace_project: Path,
    evidence_roots: tuple[Path, ...],
    forbidden_paths: tuple[Path, ...] = (),
    forbidden_file_ids: frozenset[tuple[int, int]] = frozenset(),
    evidence_file_ids: frozenset[tuple[int, int]] = frozenset(),
) -> dict[str, Any]:
    source = _stable_path(source_project, strict=True)
    destination = _stable_path(workspace_project, strict=False)
    if destination.exists() or destination.is_symlink() or _is_junction(destination):
        raise TerminalAuditPreparationError(
            f"isolated workspace must not exist: {destination}"
        )
    if _is_relative_to(destination, source) or _is_relative_to(source, destination):
        raise TerminalAuditPreparationError(
            "source and isolated workspace must not be nested"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    _assert_no_existing_link_components(destination.parent, label="workspace")
    destination.mkdir(exist_ok=False)
    entries: list[dict[str, Any]] = []
    omitted: list[str] = []
    count = 0

    def copy_entry(src: Path, dst: Path, relative: str) -> None:
        nonlocal count
        count += 1
        if count > _MAX_COPY_ENTRIES:
            raise TerminalAuditPreparationError("isolated workspace copy exceeded its entry bound")
        if _excluded_from_workspace(src, evidence_roots, evidence_file_ids):
            omitted.append(relative)
            return
        if _matches_forbidden_identity(src, forbidden_paths, forbidden_file_ids):
            raise TerminalAuditPreparationError(
                "forbidden evaluation input appeared in the source during copy"
            )
        before = _path_state(src)
        if src.is_symlink():
            target = _validated_source_link_target(
                src,
                source,
                evidence_roots,
                forbidden_paths,
                forbidden_file_ids,
                evidence_file_ids,
            )
            os.symlink(target, dst, target_is_directory=False)
            entries.append({"relative_path": relative, "type": "link", "target": target})
        elif _is_junction(src) or _is_reparse_point(src):
            raise TerminalAuditPreparationError(
                f"source contains a junction that cannot be frozen safely: {src}"
            )
        elif src.is_dir():
            dst.mkdir(exist_ok=False)
            entries.append({"relative_path": relative, "type": "directory"})
            for child in sorted(src.iterdir(), key=lambda value: value.name.casefold()):
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                copy_entry(child, dst / child.name, child_relative)
        elif src.is_file():
            source_digest = _sha256_file(src)
            shutil.copy2(src, dst, follow_symlinks=False)
            destination_digest = _sha256_file(dst)
            if source_digest != destination_digest:
                raise TerminalAuditPreparationError(
                    f"isolated copy digest mismatch for {relative}"
                )
            entries.append(
                {
                    "relative_path": relative,
                    "type": "file",
                    "bytes": before[0],
                    "sha256": source_digest,
                }
            )
        else:
            raise TerminalAuditPreparationError(
                f"source contains unsupported filesystem entry: {src}"
            )
        after = _path_state(src)
        if before != after:
            raise TerminalAuditPreparationError(
                f"source changed while creating isolated workspace: {src}"
            )

    source_before = _path_state(source)
    for child in sorted(source.iterdir(), key=lambda value: value.name.casefold()):
        copy_entry(child, destination / child.name, child.name)
    if source_before != _path_state(source):
        raise TerminalAuditPreparationError(
            "source root changed while creating isolated workspace"
        )
    entries.sort(key=lambda row: (str(row["relative_path"]).casefold(), str(row["type"])))
    unsigned = {
        "source_project": str(source),
        "workspace_project": str(destination),
        "entry_count": len(entries),
        "entries": entries,
        "omitted_prior_evidence": sorted(omitted, key=str.casefold),
    }
    unsigned["manifest_sha256"] = _sha256_bytes(_canonical_bytes(unsigned))
    return unsigned


def _safe_manifest_relative(value: Any) -> str | None:
    relative = str(value or "")
    candidate = Path(relative)
    if (
        not relative
        or relative == "."
        or "\\" in relative
        or candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.as_posix() != relative
    ):
        return None
    return relative


def _workspace_copy_rows(workspace: Path) -> list[dict[str, Any]]:
    """Rebuild prepared source rows, excluding the launcher-owned scratchpad."""

    rows: list[dict[str, Any]] = []
    count = 0

    def visit(path: Path, relative: str) -> None:
        nonlocal count
        count += 1
        if count > _MAX_COPY_ENTRIES:
            raise TerminalAuditPreparationError(
                "prepared workspace validation exceeded its entry bound"
            )
        before = _path_state(path)
        if path.is_symlink():
            try:
                target = os.readlink(path)
            except OSError as exc:
                raise TerminalAuditPreparationError(
                    "prepared workspace link is unreadable"
                ) from exc
            rows.append({"relative_path": relative, "type": "link", "target": target})
        elif _is_junction(path) or _is_reparse_point(path):
            raise TerminalAuditPreparationError(
                f"prepared workspace contains an unsafe reparse point: {relative}"
            )
        elif path.is_dir():
            rows.append({"relative_path": relative, "type": "directory"})
            try:
                children = sorted(path.iterdir(), key=lambda value: value.name.casefold())
            except OSError as exc:
                raise TerminalAuditPreparationError(
                    f"prepared workspace directory is unreadable: {relative}"
                ) from exc
            for child in children:
                child_relative = f"{relative}/{child.name}"
                visit(child, child_relative)
        elif path.is_file():
            rows.append(
                {
                    "relative_path": relative,
                    "type": "file",
                    "bytes": before[0],
                    "sha256": _sha256_file(path),
                }
            )
        else:
            raise TerminalAuditPreparationError(
                f"prepared workspace contains an unsupported entry: {relative}"
            )
        if before != _path_state(path):
            raise TerminalAuditPreparationError(
                f"prepared workspace changed during validation: {relative}"
            )

    root_before = _path_state(workspace)
    for child in sorted(workspace.iterdir(), key=lambda value: value.name.casefold()):
        if child.name.casefold() == ".scratchpad":
            continue
        visit(child, child.name)
    if root_before != _path_state(workspace):
        raise TerminalAuditPreparationError(
            "prepared workspace root changed during validation"
        )
    rows.sort(key=lambda row: (str(row["relative_path"]).casefold(), str(row["type"])))
    return rows


def _workspace_copy_issues(payload: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    copied = payload.get("source_copy")
    if not isinstance(copied, dict):
        return ["source-copy manifest is missing"]
    recorded_digest = str(copied.get("manifest_sha256") or "")
    unsigned_copy = {
        key: value for key, value in copied.items() if key != "manifest_sha256"
    }
    if _sha256_bytes(_canonical_bytes(unsigned_copy)) != recorded_digest:
        return ["source-copy manifest digest is invalid"]
    if copied.get("source_project") != payload.get("source_project"):
        issues.append("source-copy source identity drifted")
    if copied.get("workspace_project") != payload.get("workspace_project"):
        issues.append("source-copy workspace identity drifted")
    entries = copied.get("entries")
    if not isinstance(entries, list) or copied.get("entry_count") != len(entries):
        issues.append("source-copy entry denominator is invalid")
        return issues
    if len(entries) > _MAX_COPY_ENTRIES:
        issues.append("source-copy entry denominator exceeds its bound")
        return issues
    relatives: list[str] = []
    for row in entries:
        if not isinstance(row, dict):
            issues.append("source-copy row is not an object")
            return issues
        relative = _safe_manifest_relative(row.get("relative_path"))
        if relative is None:
            issues.append("source-copy row has an unsafe relative path")
            return issues
        relatives.append(relative.casefold())
    if len(relatives) != len(set(relatives)):
        issues.append("source-copy manifest has a portable path collision")
        return issues
    try:
        workspace = Path(str(payload["workspace_project"]))
        _assert_no_existing_link_components(workspace, label="workspace")
        workspace = _stable_path(workspace, strict=True)
        if not workspace.is_dir():
            issues.append("prepared workspace is not a directory")
            return issues
        actual = _workspace_copy_rows(workspace)
        if actual != entries:
            issues.append("prepared workspace bytes/entry set drifted from source-copy manifest")
    except Exception as exc:
        issues.append(f"prepared workspace validation failed: {type(exc).__name__}: {exc}")
    return issues


def _validate_preparation_roots(
    source_project: Path,
    workspace_project: Path,
    prior_evidence_receipt: Path,
    preparation_receipt: Path,
) -> tuple[Path, Path, Path, Path]:
    source = _stable_path(source_project, strict=True)
    if not source.is_dir():
        raise TerminalAuditPreparationError(f"source project is not a directory: {source}")
    _assert_no_existing_link_components(workspace_project, label="workspace")
    workspace = _stable_path(workspace_project, strict=False)
    if workspace.exists() or workspace.is_symlink() or _is_junction(workspace):
        raise TerminalAuditPreparationError(
            f"isolated workspace must not exist: {workspace}"
        )
    if _is_relative_to(workspace, source) or _is_relative_to(source, workspace):
        raise TerminalAuditPreparationError("source and isolated workspace must not be nested")
    seal = _require_external_receipt(prior_evidence_receipt, (source, workspace))
    preparation = _require_external_receipt(preparation_receipt, (source, workspace))
    if seal == preparation:
        raise TerminalAuditPreparationError("seal and preparation receipts must be distinct")
    return source, workspace, seal, preparation


def prepare_legacy_claude_run(
    *,
    source_project: Path,
    workspace_project: Path,
    prior_evidence_receipt: Path,
    preparation_receipt: Path,
    driver_path: Path,
    language: str,
    mode: str = "thorough",
    pipeline: str = "sc",
    tier: str = "t1",
    subsystem_scope: str = "",
    fork_mode: str = "standalone",
    forbidden_input_paths: Iterable[Path] = (),
    python_executable: Path | None = None,
    cli_backend: str = "claude",
    claude_exec_mode: str = "headless",
) -> dict[str, Any]:
    """Prepare one clean Claude run and return argv; never execute the argv."""

    normalized_language = str(language).strip().lower()
    normalized_mode = str(mode).strip().lower()
    normalized_pipeline = str(pipeline).strip().lower()
    normalized_cli_backend = str(cli_backend).strip().lower()
    normalized_claude_exec_mode = str(claude_exec_mode).strip().lower()
    if (
        normalized_cli_backend,
        normalized_claude_exec_mode,
    ) not in {
        ("claude", "headless"),
        ("claude-headless", "headless"),
    }:
        raise TerminalAuditPreparationError(
            "unsupported Claude launch authority: "
            f"cli_backend={cli_backend!r}, "
            f"claude_exec_mode={claude_exec_mode!r}"
        )
    if normalized_mode not in _MODES:
        raise TerminalAuditPreparationError(f"unsupported mode: {mode!r}")
    if normalized_pipeline not in {"sc", "l1"}:
        raise TerminalAuditPreparationError(f"unsupported pipeline: {pipeline!r}")
    if normalized_pipeline != "sc" or normalized_mode != "thorough":
        raise TerminalAuditPreparationError(
            "authenticated contained Claude headless is supported only for "
            "Smart Contract Thorough audits; choose the public Codex launcher"
        )
    expected_languages = (
        _L1_LANGUAGES if normalized_pipeline == "l1" else _SC_LANGUAGES
    )
    if normalized_language not in expected_languages:
        raise TerminalAuditPreparationError(
            f"unsupported {normalized_pipeline} language: {language!r}"
        )
    normalized_tier = str(tier).strip().lower()
    normalized_fork_mode = str(fork_mode).strip().lower()
    if normalized_pipeline == "l1" and normalized_tier not in _L1_TIERS:
        raise TerminalAuditPreparationError(f"unsupported L1 tier: {tier!r}")
    if normalized_pipeline == "l1" and normalized_fork_mode not in _FORK_MODES:
        raise TerminalAuditPreparationError(
            f"unsupported L1 fork mode: {fork_mode!r}"
        )
    source, workspace, seal_path, prep_path = _validate_preparation_roots(
        Path(source_project),
        Path(workspace_project),
        Path(prior_evidence_receipt),
        Path(preparation_receipt),
    )
    forbidden_paths, forbidden_file_ids = _forbidden_identity_boundary(
        forbidden_input_paths
    )
    for forbidden in forbidden_paths:
        if _is_relative_to(forbidden, source) or _is_relative_to(source, forbidden):
            raise TerminalAuditPreparationError(
                "forbidden evaluation input overlaps the audit source; "
                "prepare a sanitized source destination first"
            )
        if _is_relative_to(forbidden, workspace) or _is_relative_to(workspace, forbidden):
            raise TerminalAuditPreparationError(
                "forbidden evaluation input overlaps the isolated workspace"
            )
    _assert_no_forbidden_source_aliases(
        source, forbidden_paths, forbidden_file_ids
    )
    _assert_no_existing_link_components(Path(driver_path), label="driver")
    driver = _stable_path(Path(driver_path), strict=True)
    canonical_driver = _stable_path(Path(__file__).with_name("plamen_driver.py"), strict=True)
    if driver != canonical_driver or not driver.is_file():
        raise TerminalAuditPreparationError(
            "driver_path must name the canonical shared sibling plamen_driver.py"
        )
    requested_python = (
        Path(python_executable) if python_executable is not None else Path(sys.executable)
    )
    _assert_no_existing_link_components(requested_python, label="Python executable")
    python = _stable_path(
        requested_python,
        strict=True,
    )
    canonical_python = _stable_path(Path(sys.executable), strict=True)
    if python != canonical_python or not python.is_file():
        raise TerminalAuditPreparationError(
            "Python executable must be the current canonical sys.executable"
        )
    for control_path in (seal_path, prep_path, driver, python):
        if _matches_forbidden_identity(
            control_path, forbidden_paths, forbidden_file_ids
        ):
            raise TerminalAuditPreparationError(
                "forbidden evaluation input aliases a preparation control path"
            )

    evidence_roots = discover_prior_audit_evidence(source)
    evidence_file_ids = _evidence_file_identities(evidence_roots)
    _assert_safe_source_links(
        source,
        evidence_roots,
        forbidden_paths,
        forbidden_file_ids,
        evidence_file_ids,
    )
    # The evidence receipt is committed before any workspace byte is created.
    # Build from the already-reviewed root set so no discovery/copy gap can
    # silently change which prior-run bytes were excluded.
    seal = _build_prior_evidence_seal(source, evidence_roots)
    _atomic_write_new_or_same(seal_path, _render_json(seal))
    copied = _copy_isolated_project(
        source,
        workspace,
        evidence_roots,
        forbidden_paths,
        forbidden_file_ids,
        evidence_file_ids,
    )
    # Close the discovery/seal/copy interval before committing launch control
    # bytes.  A rename, replacement, or added prior artifact leaves the partial
    # destination explicit but can never produce a green preparation receipt.
    current_roots = discover_prior_audit_evidence(source)
    current_keys = {os.path.normcase(str(path.absolute())) for path in current_roots}
    sealed_keys = {os.path.normcase(str(path.absolute())) for path in evidence_roots}
    rebuilt_seal = _build_prior_evidence_seal(source, evidence_roots)
    if current_keys != sealed_keys or rebuilt_seal.get("manifest_sha256") != seal.get(
        "manifest_sha256"
    ):
        raise TerminalAuditPreparationError(
            "prior evidence drifted during preparation"
        )

    scratchpad = workspace / ".scratchpad"
    scratchpad.mkdir(exist_ok=False)
    config_path = scratchpad / "config.json"
    if normalized_pipeline == "l1":
        config = {
            "project_root": str(workspace),
            "scratchpad": str(scratchpad.resolve()),
            "mode": normalized_mode,
            "pipeline": "l1",
            "language": normalized_language,
            "cli_backend": normalized_cli_backend,
            "claude_exec_mode": normalized_claude_exec_mode,
            "tier": normalized_tier,
            "subsystem_scope": str(subsystem_scope or ""),
            "fork_mode": normalized_fork_mode,
            "docs_path": "",
            "proven_only": False,
        }
    else:
        config = {
            "project_root": str(workspace),
            "scratchpad": str(scratchpad.resolve()),
            "mode": normalized_mode,
            "pipeline": "sc",
            "language": normalized_language,
            "cli_backend": normalized_cli_backend,
            "claude_exec_mode": normalized_claude_exec_mode,
            "docs_path": "",
            "scope_file": "",
            "scope_notes": "",
            "proven_only": False,
        }
    config_raw = _render_json(config)
    _atomic_write_new_or_same(config_path, config_raw)
    fresh_argv = [
        str(python),
        str(driver),
        "--startup-intent",
        "START_NEW_RUN",
        str(config_path.resolve()),
    ]
    resume_argv = [
        str(python),
        str(driver),
        "--startup-intent",
        "RESUME_EXISTING",
        str(config_path.resolve()),
    ]
    unsigned: dict[str, Any] = {
        "schema_version": PREPARATION_SCHEMA,
        "source_project": str(source),
        "workspace_project": str(workspace),
        "scratchpad": str(scratchpad.resolve()),
        "config_path": str(config_path.resolve()),
        "config_sha256": _sha256_bytes(config_raw),
        "prior_evidence_receipt": str(seal_path),
        "prior_evidence_receipt_sha256": _sha256_file(seal_path),
        "prior_evidence_manifest_sha256": seal["manifest_sha256"],
        "source_copy": copied,
        "python_executable": str(python),
        "driver_path": str(driver),
        "driver_sha256": _sha256_file(driver),
        "fresh_argv": fresh_argv,
        "resume_argv": resume_argv,
        "backend": "claude",
        "cli_backend": normalized_cli_backend,
        "claude_exec_mode": normalized_claude_exec_mode,
        "mode": normalized_mode,
        "pipeline": normalized_pipeline,
        "language": normalized_language,
        # No basename/path digest is persisted: an unkeyed path hash is a
        # dictionary/equality oracle.  The boundary is intentionally attestable
        # only as policy/count, never as secret-path identity.
        "forbidden_input_policy": "IDENTITY_ONLY_NO_BYTES_OR_PATH_DISCLOSURE_V1",
        "forbidden_input_count": len(forbidden_paths),
        "launched": False,
        "phase_orchestration": "DRIVER_ONLY",
    }
    if normalized_pipeline == "l1":
        unsigned.update(
            {
                "tier": normalized_tier,
                "subsystem_scope": str(subsystem_scope or ""),
                "fork_mode": normalized_fork_mode,
            }
        )
    unsigned["preparation_sha256"] = _sha256_bytes(_canonical_bytes(unsigned))
    _atomic_write_new_or_same(prep_path, _render_json(unsigned))
    verification_issues = verify_preparation_receipt(prep_path)
    if verification_issues:
        raise TerminalAuditPreparationError(
            "prepared audit failed its exact pre-launch verification: "
            + "; ".join(verification_issues)
        )
    return unsigned


def verify_preparation_receipt(receipt_path: Path) -> tuple[str, ...]:
    issues: list[str] = []
    try:
        payload = json.loads(Path(receipt_path).read_text(encoding="utf-8", errors="strict"))
    except Exception as exc:
        return (f"preparation receipt is unreadable: {type(exc).__name__}: {exc}",)
    if payload.get("schema_version") != PREPARATION_SCHEMA:
        issues.append("preparation receipt schema is unsupported")
    digest = str(payload.get("preparation_sha256") or "")
    unsigned = {key: value for key, value in payload.items() if key != "preparation_sha256"}
    if _sha256_bytes(_canonical_bytes(unsigned)) != digest:
        issues.append("preparation receipt digest is invalid")
        return tuple(issues)
    try:
        workspace_raw = Path(str(payload["workspace_project"]))
        source_raw = Path(str(payload["source_project"]))
        _assert_no_existing_link_components(workspace_raw, label="workspace")
        workspace = _stable_path(workspace_raw, strict=True)
        source = _stable_path(source_raw, strict=True)
        expected_scratchpad = workspace / ".scratchpad"
        expected_config_path = expected_scratchpad / "config.json"
        config_path = Path(str(payload["config_path"]))
        if config_path != expected_config_path or Path(
            str(payload.get("scratchpad") or "")
        ) != expected_scratchpad:
            issues.append("prepared config path/scratchpad escapes canonical workspace layout")
            return tuple(issues)
        _assert_no_existing_link_components(config_path, label="config")
        if _sha256_file(config_path) != payload.get("config_sha256"):
            issues.append("prepared config bytes drifted")
        config = json.loads(config_path.read_text(encoding="utf-8", errors="strict"))
        pipeline = str(payload.get("pipeline") or "")
        language = str(payload.get("language") or "")
        mode = str(payload.get("mode") or "")
        cli_backend = str(payload.get("cli_backend") or "")
        claude_exec_mode = str(payload.get("claude_exec_mode") or "")
        if (cli_backend, claude_exec_mode) not in {
            ("claude", "headless"),
            ("claude-headless", "headless"),
        }:
            issues.append("preparation receipt Claude launch authority is invalid")
        if pipeline != "sc" or mode != "thorough":
            issues.append(
                "preparation receipt requests an unsupported contained Claude route"
            )
        if pipeline == "l1":
            expected_config = {
                "project_root": str(workspace),
                "scratchpad": str(expected_scratchpad),
                "mode": mode,
                "pipeline": "l1",
                "language": language,
                "cli_backend": cli_backend,
                "claude_exec_mode": claude_exec_mode,
                "tier": str(payload.get("tier") or ""),
                "subsystem_scope": str(payload.get("subsystem_scope") or ""),
                "fork_mode": str(payload.get("fork_mode") or ""),
                "docs_path": "",
                "proven_only": False,
            }
        else:
            expected_config = {
                "project_root": str(workspace),
                "scratchpad": str(expected_scratchpad),
                "mode": mode,
                "pipeline": "sc",
                "language": language,
                "cli_backend": cli_backend,
                "claude_exec_mode": claude_exec_mode,
                "docs_path": "",
                "scope_file": "",
                "scope_notes": "",
                "proven_only": False,
            }
        if config != expected_config:
            issues.append("prepared config schema/value contract drifted")
        if (
            pipeline not in {"sc", "l1"}
            or mode not in _MODES
            or language not in (_L1_LANGUAGES if pipeline == "l1" else _SC_LANGUAGES)
        ):
            issues.append("preparation receipt pipeline/mode/language contract is invalid")
        if payload.get("backend") != "claude":
            issues.append("preparation receipt is not bound to Claude")
        if payload.get("launched") is not False or payload.get("phase_orchestration") != "DRIVER_ONLY":
            issues.append("preparation receipt crossed its non-launch/orchestration boundary")
        if payload.get("forbidden_input_policy") != "IDENTITY_ONLY_NO_BYTES_OR_PATH_DISCLOSURE_V1":
            issues.append("forbidden-input privacy policy marker is invalid")
        if "forbidden_input_path_sha256" in payload:
            issues.append("forbidden-input path digest disclosure is present")
        count = payload.get("forbidden_input_count")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            issues.append("forbidden-input count is invalid")

        canonical_driver = _stable_path(Path(__file__).with_name("plamen_driver.py"), strict=True)
        canonical_python = _stable_path(Path(sys.executable), strict=True)
        driver_path = Path(str(payload.get("driver_path") or ""))
        python_path = Path(str(payload.get("python_executable") or ""))
        if driver_path != canonical_driver:
            issues.append("shared driver path is not canonical")
        elif _sha256_file(driver_path) != payload.get("driver_sha256"):
            issues.append("shared driver bytes drifted after preparation")
        if python_path != canonical_python:
            issues.append("Python executable path is not canonical")
        expected_fresh = [
            str(canonical_python),
            str(canonical_driver),
            "--startup-intent",
            "START_NEW_RUN",
            str(expected_config_path),
        ]
        expected_resume = [
            str(canonical_python),
            str(canonical_driver),
            "--startup-intent",
            "RESUME_EXISTING",
            str(expected_config_path),
        ]
        if payload.get("fresh_argv") != expected_fresh:
            issues.append("fresh driver argv drifted")
        if payload.get("resume_argv") != expected_resume:
            issues.append("resume driver argv drifted")
        if "--fresh" in payload.get("fresh_argv", []) or "--fresh" in payload.get("resume_argv", []):
            issues.append("deprecated in-place --fresh alias is present")
        prior_path = Path(str(payload["prior_evidence_receipt"]))
        if _sha256_file(prior_path) != payload.get("prior_evidence_receipt_sha256"):
            issues.append("prior-evidence receipt bytes drifted")
        prior_payload = json.loads(prior_path.read_text(encoding="utf-8", errors="strict"))
        if prior_payload.get("manifest_sha256") != payload.get(
            "prior_evidence_manifest_sha256"
        ):
            issues.append("prior-evidence manifest identity drifted")
        for issue in verify_prior_audit_evidence_seal(prior_path):
            issues.append(f"prior-evidence {issue}")
        issues.extend(_workspace_copy_issues(payload))
        try:
            receipt = _require_external_receipt(Path(receipt_path), (source, workspace))
            if receipt != _stable_path(Path(receipt_path), strict=True):
                issues.append("preparation receipt path identity drifted")
        except Exception as exc:
            issues.append(f"preparation receipt containment failed: {type(exc).__name__}: {exc}")
    except Exception as exc:
        issues.append(f"preparation receipt validation failed: {type(exc).__name__}: {exc}")
    return tuple(issues)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prepare (never launch) an isolated legacy-Claude Plamen audit"
    )
    parser.add_argument("--source-project", required=True, type=Path)
    parser.add_argument("--workspace-project", required=True, type=Path)
    parser.add_argument("--prior-evidence-receipt", required=True, type=Path)
    parser.add_argument("--preparation-receipt", required=True, type=Path)
    parser.add_argument("--driver", required=True, type=Path)
    parser.add_argument("--language", required=True, choices=sorted(_LANGUAGES))
    parser.add_argument("--mode", default="thorough", choices=sorted(_MODES))
    parser.add_argument("--pipeline", default="sc", choices=("sc", "l1"))
    parser.add_argument("--tier", default="t1", choices=sorted(_L1_TIERS))
    parser.add_argument("--subsystem-scope", default="")
    parser.add_argument("--fork-mode", default="standalone", choices=sorted(_FORK_MODES))
    parser.add_argument(
        "--cli-backend",
        default="claude",
        choices=("claude", "claude-headless"),
    )
    parser.add_argument(
        "--claude-exec-mode",
        default="headless",
        choices=("headless",),
    )
    parser.add_argument(
        "--forbidden-input",
        action="append",
        default=[],
        type=Path,
        help="evaluation/ground-truth path that must remain out of the audit input",
    )
    args = parser.parse_args(argv)
    payload = prepare_legacy_claude_run(
        source_project=args.source_project,
        workspace_project=args.workspace_project,
        prior_evidence_receipt=args.prior_evidence_receipt,
        preparation_receipt=args.preparation_receipt,
        driver_path=args.driver,
        language=args.language,
        mode=args.mode,
        pipeline=args.pipeline,
        tier=args.tier,
        subsystem_scope=args.subsystem_scope,
        fork_mode=args.fork_mode,
        forbidden_input_paths=tuple(args.forbidden_input),
        cli_backend=args.cli_backend,
        claude_exec_mode=args.claude_exec_mode,
    )
    print(json.dumps({
        "preparation_receipt": str(args.preparation_receipt.resolve()),
        "preparation_sha256": payload["preparation_sha256"],
        "fresh_argv": payload["fresh_argv"],
        "resume_argv": payload["resume_argv"],
        "verified": True,
        "launched": False,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
