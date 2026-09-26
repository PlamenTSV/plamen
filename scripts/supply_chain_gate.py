#!/usr/bin/env python3
"""Plamen — Supply-Chain Pre-Exec Safety Gate (ITEM H2).

The driver runs the TARGET repo's *own* untrusted install/build/test/fuzz
commands (forge/npm/yarn/pnpm/cargo/...) with no vetting. This module is a
mechanical, hermetic, fail-closed gate called BEFORE any such subprocess so a
poisoned dependency lockfile cannot execute an install-time payload on the
auditor's machine.

Design
------
- **Hermetic**: the actual scanner invocation is isolated behind
  ``_call_offline_scanner`` so tests can monkeypatch it directly instead of
  needing a real network-connected scanner binary. No network calls are made
  by this module itself (``osv-scanner --offline`` / ``cargo audit
  --no-fetch`` are mechanically no-fetch). ``npm audit --offline`` is
  explicitly ineligible because npm skips advisory lookup in that mode.
- **Fail-closed**: a typed malicious-package signal (scanner hit, IoC denylist
  match, or the install-script/base64 heuristic) raises
  :class:`SupplyChainAbortError` — a TRUE circuit breaker. The caller MUST
  NOT swallow this specific exception before its own install/build/test
  subprocess: once raised, none of the later scans/subprocesses run.
- **Fail closed on incomplete verification**: if a compatible scanner is
  absent, times out, exits abnormally, or emits malformed output, dependencies
  cannot be verified and the guarded target command does not run.
- **Generic across ecosystems**: no protocol/project-specific names. The IoC
  denylist is append-only and ships empty; it is a defense-in-depth
  complement to the offline scanner, not the primary detector.

This module owns ``SupplyChainAbortError`` for both of its call sites
(``recon_prepass.py``'s EVM dependency-install path and
``mechanical_verify.py``'s pre-test-exec path). It is deliberately narrow —
NOT a general-purpose/reusable phase-abort helper.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import weakref
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, List, Mapping, Optional, Sequence

from owned_process_runner import run_owned_process

log = logging.getLogger("plamen.supply_chain_gate")

__all__ = [
    "SupplyChainAbortError",
    "SupplyChainAdmission",
    "gate_supply_chain",
    "project_supply_chain_admission",
    "denylist_has_not_shrunk",
    "DEFAULT_IOC_DENYLIST",
]


class SupplyChainAbortError(Exception):
    """Raised ONLY by :func:`gate_supply_chain` when a malicious-package
    supply-chain signal is found in the TARGET repo's dependency lockfile(s),
    or when no offline scanner binary is available to verify them at all
    (fail-closed on inability-to-verify).

    Narrow to its 2 call sites — ``recon_prepass._prepare_evm_build`` and
    ``mechanical_verify.run_phase5b_mechanical_verify`` — this is NOT a
    reusable/general phase-abort mechanism; do not raise it elsewhere.
    """


class OfflineScanState(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass(frozen=True)
class OfflineScanResult:
    state: OfflineScanState
    output: str = ""
    reason: str = ""
    returncode: int | None = None


@dataclass(frozen=True)
class _ValidatedCompatSession:
    project_root: Path
    scratchpad: Path
    session_binding_sha256: str
    run_id: str


@dataclass(frozen=True)
class _CompatTransportResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    receipt_path: Path | None = None
    stdout_raw_sha256: str = ""
    stderr_raw_sha256: str = ""


class SupplyChainAdmission:
    """Opaque, process-local result of the explicit compatibility gate."""

    __slots__ = ("__token", "__weakref__")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise TypeError("supply-chain admissions are gate-issued")

    def __reduce__(self) -> object:
        raise TypeError("supply-chain admissions cannot be serialized")

    def __repr__(self) -> str:
        return "<SupplyChainAdmission opaque>"


@dataclass(frozen=True)
class _AdmissionRecord:
    token: str
    authority_ref: weakref.ReferenceType[Any]
    session_authority_ref: weakref.ReferenceType[Any]
    projection: Mapping[str, object]


_ADMISSIONS: dict[int, _AdmissionRecord] = {}


@dataclass(frozen=True)
class _CompatScanObservation:
    result_ref: weakref.ReferenceType[Any]
    session_ref: weakref.ReferenceType[Any]
    scanner_id: str
    lockfile: str
    receipt_path: Path
    receipt_sha256: str
    raw_stdout_sha256: str
    normalized_output_sha256: str
    gate_nonce: str
    staged_input_manifest_sha256: str


_COMPAT_SCAN_OBSERVATIONS: dict[int, _CompatScanObservation] = {}


@dataclass(frozen=True)
class _CompatInputSnapshot:
    rows: tuple[dict[str, object], ...]
    contents: Mapping[str, bytes]


_POSIX_COMPAT_RECEIPT_SCHEMA = (
    "plamen.posix_v2_compat_supply_chain_execution.v1"
)
_POSIX_COMPAT_RECEIPT_DIR = "_posix_v2_compat_supply_chain_receipts"
_POSIX_COMPAT_STDOUT_MAX_BYTES = 32 * 1024 * 1024
_POSIX_COMPAT_STDERR_MAX_BYTES = 8 * 1024 * 1024
_POSIX_COMPAT_KILL_GRACE_SECONDS = 2.0


# Append-only IoC denylist of known-malicious dependency name/version
# substrings. NEVER remove an entry — shrinking this list silently un-blocks
# a previously-known-bad dependency (see `denylist_has_not_shrunk`). New
# entries may be appended freely. Ships empty: this is a defense-in-depth
# complement to the offline scanner (Signal 3 below), not the primary
# detector, and per the no-overfit rule it must stay generic — no
# protocol/contest-specific data lives here.
DEFAULT_IOC_DENYLIST: frozenset[str] = frozenset()

_LOCKFILE_NAMES = (
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "npm-shrinkwrap.json", "Cargo.lock", "soldeer.lock", "go.sum",
    "Move.lock",
)
_LOCKFILE_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "__pycache__",
    "node_modules", "target", "build", "dist", "out", "artifacts",
    "cache", ".next", ".idea", ".vscode",
}
_LOCKFILE_SKIP_DIR_KEYS = frozenset(
    str(value).casefold() for value in _LOCKFILE_SKIP_DIRS
)
_LOCKFILE_WALK_MAX_DIRS = 20_000
_LOCKFILE_WALK_MAX_ENTRIES = 250_000


def _is_lockfile_skip_dir(name: str) -> bool:
    """Keep audit-generated mutable evidence out of the source denominator."""

    folded = str(name).casefold()
    return (
        folded in _LOCKFILE_SKIP_DIR_KEYS
        or folded.startswith(".scratchpad")
        or folded.startswith(".plamen-stale-snapshots")
    )

# Offline/local dependency-vulnerability scanners, in preference order. None
# of these are hard dependencies — `_pick_scanner_binary` degrades to "none
# found" (the one fail-closed hard stop) rather than assuming any is present.
_SCANNER_BINARIES = ("osv-scanner", "cargo-audit")
_LOCKFILE_SCANNERS = {
    "package-lock.json": ("osv-scanner",),
    # Neither OSV's documented lockfile list nor another genuinely offline
    # advisory provider covers npm-shrinkwrap. npm audit --offline explicitly
    # skips advisory lookup and therefore cannot verify this denominator row.
    "npm-shrinkwrap.json": (),
    "yarn.lock": ("osv-scanner",),
    "pnpm-lock.yaml": ("osv-scanner",),
    "Cargo.lock": ("osv-scanner", "cargo-audit"),
    # OSV-Scanner does not list Soldeer or Move lockfiles as supported.
    # Keep both in the denominator, but never translate "file ignored" into
    # a zero-vulnerability claim.
    "soldeer.lock": (),
    "go.sum": ("osv-scanner",),
    "Move.lock": (),
}

_INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall")

# Obfuscated-payload shape: an eval/Function-constructor call whose argument
# chain decodes base64 (atob(...) or Buffer.from(..., 'base64')). This is a
# generic obfuscation-chain shape, not a specific package signature.
_BASE64_EVAL_RE = re.compile(
    r"(eval\s*\(|new\s+Function\s*\()\s*[^)]*"
    r"(atob\(|Buffer\.from\([^,]+,\s*['\"]base64['\"]\))",
    re.IGNORECASE,
)

_MAL_ADVISORY_ID_RE = re.compile(r"^MAL-[0-9]{4}-[0-9]+$")


class _ScannerSchemaError(ValueError):
    """The scanner succeeded, but its result cannot be classified safely."""


@dataclass(frozen=True)
class _ScannerRiskAssessment:
    """Typed result of classifying one scanner's validated JSON payload."""

    vulnerability_count: int
    malicious_evidence: tuple[str, ...] = ()


def _is_exact_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_object(value: object, path: str) -> dict:
    if not isinstance(value, dict):
        raise _ScannerSchemaError(f"{path} is not an object")
    return value


def _require_list(value: object, path: str) -> list:
    if not isinstance(value, list):
        raise _ScannerSchemaError(f"{path} is not an array")
    return value


def _optional_string_list(record: dict, key: str, path: str) -> list[str]:
    if key not in record:
        return []
    values = _require_list(record[key], f"{path}.{key}")
    if not all(isinstance(value, str) for value in values):
        raise _ScannerSchemaError(f"{path}.{key} contains a non-string")
    return values


def _mal_id_evidence(values: Iterable[str], path: str) -> list[str]:
    evidence: list[str] = []
    for value in values:
        if value.startswith("MAL-") and not _MAL_ADVISORY_ID_RE.fullmatch(value):
            raise _ScannerSchemaError(
                f"{path} contains a malformed MAL advisory identifier"
            )
        if _MAL_ADVISORY_ID_RE.fullmatch(value):
            evidence.append(f"{path}={value}")
    return evidence


def _osv_risk_assessment(payload: dict) -> _ScannerRiskAssessment:
    results = _require_list(payload.get("results"), "OSV.results")
    evidence: list[str] = []
    vulnerability_count = 0
    for result_index, raw_result in enumerate(results):
        result_path = f"OSV.results[{result_index}]"
        result = _require_object(raw_result, result_path)
        packages = _require_list(result.get("packages"), f"{result_path}.packages")
        for package_index, raw_package in enumerate(packages):
            package_path = f"{result_path}.packages[{package_index}]"
            package = _require_object(raw_package, package_path)
            vulnerabilities = _require_list(
                package.get("vulnerabilities"),
                f"{package_path}.vulnerabilities",
            )
            for vulnerability_index, raw_vulnerability in enumerate(
                vulnerabilities
            ):
                vulnerability_path = (
                    f"{package_path}.vulnerabilities[{vulnerability_index}]"
                )
                vulnerability = _require_object(
                    raw_vulnerability, vulnerability_path
                )
                advisory_id = vulnerability.get("id")
                if not isinstance(advisory_id, str) or not advisory_id:
                    raise _ScannerSchemaError(
                        f"{vulnerability_path}.id is not a non-empty string"
                    )
                vulnerability_count += 1
                evidence.extend(
                    _mal_id_evidence([advisory_id], f"{vulnerability_path}.id")
                )
                aliases = _optional_string_list(
                    vulnerability, "aliases", vulnerability_path
                )
                evidence.extend(
                    _mal_id_evidence(aliases, f"{vulnerability_path}.aliases")
                )
    return _ScannerRiskAssessment(
        vulnerability_count=vulnerability_count,
        malicious_evidence=tuple(evidence),
    )


def _npm_risk_assessment(payload: dict) -> _ScannerRiskAssessment:
    report_version = payload.get("auditReportVersion")
    if not _is_exact_int(report_version) or report_version != 2:
        raise _ScannerSchemaError("npm.auditReportVersion is not exactly 2")
    vulnerabilities = _require_object(
        payload.get("vulnerabilities"), "npm.vulnerabilities"
    )
    metadata = _require_object(payload.get("metadata"), "npm.metadata")
    vulnerability_totals = _require_object(
        metadata.get("vulnerabilities"), "npm.metadata.vulnerabilities"
    )
    expected_severities = {
        "info", "low", "moderate", "high", "critical", "total"
    }
    if set(vulnerability_totals) != expected_severities:
        raise _ScannerSchemaError(
            "npm.metadata.vulnerabilities has unexpected or missing keys"
        )
    evidence: list[str] = []
    for severity, count in vulnerability_totals.items():
        if not _is_exact_int(count) or count < 0:
            raise _ScannerSchemaError(
                "npm.metadata.vulnerabilities contains an invalid count"
            )
    if vulnerability_totals["total"] != sum(
        vulnerability_totals[severity]
        for severity in expected_severities - {"total"}
    ):
        raise _ScannerSchemaError(
            "npm.metadata.vulnerabilities total does not match severity counts"
        )
    if vulnerability_totals["total"] != len(vulnerabilities):
        raise _ScannerSchemaError(
            "npm.metadata.vulnerabilities total does not match result rows"
        )
    for dependency_name, raw_vulnerability in vulnerabilities.items():
        if not isinstance(dependency_name, str):
            raise _ScannerSchemaError("npm.vulnerabilities has a non-string key")
        vulnerability_path = f"npm.vulnerabilities[{dependency_name!r}]"
        vulnerability = _require_object(raw_vulnerability, vulnerability_path)
        via = _require_list(vulnerability.get("via"), f"{vulnerability_path}.via")
        for via_index, raw_advisory in enumerate(via):
            advisory_path = f"{vulnerability_path}.via[{via_index}]"
            if isinstance(raw_advisory, str):
                # npm uses strings here for transitive dependency references.
                continue
            advisory = _require_object(raw_advisory, advisory_path)
            if "source" not in advisory or not _is_exact_int(advisory["source"]):
                raise _ScannerSchemaError(
                    f"{advisory_path}.source is not an integer"
                )
            cwes = _optional_string_list(advisory, "cwe", advisory_path)
            if "CWE-506" in cwes:
                evidence.append(f"{advisory_path}.cwe=CWE-506")
    return _ScannerRiskAssessment(
        vulnerability_count=len(vulnerabilities),
        malicious_evidence=tuple(evidence),
    )


def _cargo_risk_assessment(payload: dict) -> _ScannerRiskAssessment:
    vulnerabilities = _require_object(
        payload.get("vulnerabilities"), "cargo-audit.vulnerabilities"
    )
    rows = _require_list(
        vulnerabilities.get("list"), "cargo-audit.vulnerabilities.list"
    )
    found = vulnerabilities.get("found")
    count = vulnerabilities.get("count")
    if not isinstance(found, bool):
        raise _ScannerSchemaError("cargo-audit.vulnerabilities.found is not a bool")
    if not _is_exact_int(count) or count < 0:
        raise _ScannerSchemaError("cargo-audit.vulnerabilities.count is invalid")
    if count != len(rows) or found is not bool(rows):
        raise _ScannerSchemaError(
            "cargo-audit vulnerability count/found fields disagree with list"
        )
    evidence: list[str] = []
    for row_index, raw_row in enumerate(rows):
        row_path = f"cargo-audit.vulnerabilities.list[{row_index}]"
        row = _require_object(raw_row, row_path)
        advisory = _require_object(row.get("advisory"), f"{row_path}.advisory")
        advisory_id = advisory.get("id")
        if not isinstance(advisory_id, str) or not advisory_id:
            raise _ScannerSchemaError(
                f"{row_path}.advisory.id is not a non-empty string"
            )
        evidence.extend(
            _mal_id_evidence([advisory_id], f"{row_path}.advisory.id")
        )
        aliases = _optional_string_list(advisory, "aliases", f"{row_path}.advisory")
        evidence.extend(
            _mal_id_evidence(aliases, f"{row_path}.advisory.aliases")
        )
        categories = _optional_string_list(
            advisory, "categories", f"{row_path}.advisory"
        )
        if "malicious" in categories:
            evidence.append(f"{row_path}.advisory.categories=malicious")
    return _ScannerRiskAssessment(
        vulnerability_count=len(rows),
        malicious_evidence=tuple(evidence),
    )


def _scanner_risk_assessment(binary: str, payload: dict) -> _ScannerRiskAssessment:
    scanner_id = _scanner_id(binary)
    if scanner_id == "osv-scanner":
        return _osv_risk_assessment(payload)
    if scanner_id == "npm":
        return _npm_risk_assessment(payload)
    if scanner_id == "cargo-audit":
        return _cargo_risk_assessment(payload)
    raise _ScannerSchemaError(f"unsupported scanner result: {binary}")


def denylist_has_not_shrunk(previous: Iterable[str], current: Iterable[str]) -> bool:
    """Return True iff every entry in `previous` is still present in
    `current`. The denylist is append-only by policy; this is the mechanical
    check that turns "denylist-shrink = corruption" into a testable
    invariant rather than a documentation-only convention."""
    return set(previous) <= set(current)


def _name_key(name: str) -> str:
    """Canonical comparison key for security-sensitive filenames.

    Case-folding on every host is conservative: it prevents a checkout that
    was prepared on a case-sensitive filesystem from becoming a hidden
    denominator entry when the same tree is audited on Windows or a default
    macOS filesystem.
    """

    return str(name).casefold()


def _path_is_link_or_reparse(path: Path) -> bool:
    """Reject links and Windows reparse points without Python-version gaps."""

    try:
        observed = os.lstat(path)
    except OSError as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: cannot inspect project path metadata: "
            f"{path} ({type(exc).__name__})"
        ) from exc
    if stat.S_ISLNK(observed.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if int(getattr(observed, "st_file_attributes", 0) or 0) & reparse_flag:
        return True
    # Keep the public API as defense in depth on Python versions that expose
    # it, but never rely on it as the sole reparse authority.
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            return bool(is_junction())
        except OSError as exc:
            raise SupplyChainAbortError(
                "supply-chain gate: cannot inspect project junction metadata: "
                f"{path} ({type(exc).__name__})"
            ) from exc
    return False


def _find_lockfiles(root: Path) -> List[Path]:
    """Enumerate the bounded project-wide lockfile denominator."""
    root = Path(root)
    if not root.is_dir():
        return []
    if _path_is_link_or_reparse(root):
        raise SupplyChainAbortError(
            "supply-chain gate: project root is a link/reparse point and "
            f"cannot be bounded safely: {root}"
        )
    found: List[Path] = []
    directories = 0
    entries = 0
    lock_names = {_name_key(name) for name in _LOCKFILE_NAMES}

    def walk_error(exc: OSError) -> None:
        raise SupplyChainAbortError(
            "supply-chain gate: lockfile denominator is unreadable: "
            f"{type(exc).__name__}"
        ) from exc

    try:
        for dirpath, dirnames, filenames in os.walk(
            root, followlinks=False, onerror=walk_error
        ):
            directories += 1
            entries += len(dirnames) + len(filenames)
            if (
                directories > _LOCKFILE_WALK_MAX_DIRS
                or entries > _LOCKFILE_WALK_MAX_ENTRIES
            ):
                raise SupplyChainAbortError(
                    "supply-chain gate: lockfile denominator walk exceeded "
                    "its bounded project limits; cannot verify completely"
                )
            directory = Path(dirpath)
            retained: list[str] = []
            for name in sorted(dirnames):
                if _is_lockfile_skip_dir(name):
                    continue
                candidate = directory / name
                if _path_is_link_or_reparse(candidate):
                    raise SupplyChainAbortError(
                        "supply-chain gate: untrusted project contains a "
                        f"directory link/junction in the scan scope: {candidate}"
                    )
                retained.append(name)
            dirnames[:] = retained
            for name in sorted(filenames):
                if _name_key(name) not in lock_names:
                    continue
                candidate = directory / name
                if _path_is_link_or_reparse(candidate):
                    raise SupplyChainAbortError(
                        "supply-chain gate: lockfile is not a regular local "
                        f"file: {candidate}"
                    )
                try:
                    observed = os.lstat(candidate)
                except OSError as exc:
                    raise SupplyChainAbortError(
                        "supply-chain gate: cannot inspect lockfile metadata: "
                        f"{candidate} ({type(exc).__name__})"
                    ) from exc
                if not stat.S_ISREG(observed.st_mode):
                    raise SupplyChainAbortError(
                        "supply-chain gate: lockfile is not a regular local "
                        f"file: {candidate}"
                    )
                found.append(candidate)
    except SupplyChainAbortError:
        raise
    except OSError as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: lockfile denominator is unreadable: "
            f"{type(exc).__name__}"
        ) from exc
    return sorted(
        found,
        key=lambda path: path.relative_to(root).as_posix(),
    )


def _pick_scanner_binary(
    candidates: Sequence[str] = _SCANNER_BINARIES,
) -> Optional[str]:
    for b in candidates:
        if shutil.which(b):
            return b
    return None


class _AuthorizedScanner(str):
    """Logical scanner id carrying its pre-resolved executable authority.

    The string value deliberately remains the historical scanner id so the
    private test seam and result parser stay stable.  Production subprocesses
    use ``executable`` and therefore never perform a second PATH lookup from
    an untrusted checkout cwd.
    """

    executable: str

    def __new__(cls, scanner_id: str, executable: str):
        value = str.__new__(cls, scanner_id)
        value.executable = executable
        return value


def _path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _resolve_scanner_authority(
    scanner_id: str,
    untrusted_root: Path,
) -> Optional[_AuthorizedScanner]:
    """Resolve once and reject executable authority from the target tree."""

    raw = shutil.which(scanner_id)
    if not raw:
        return None
    executable = Path(raw).expanduser()
    try:
        executable = executable.resolve(strict=False)
    except OSError as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: scanner executable cannot be resolved: "
            f"{scanner_id} ({type(exc).__name__})"
        ) from exc
    if _path_is_within(executable, untrusted_root):
        raise SupplyChainAbortError(
            "supply-chain gate: refusing scanner executable resolved from "
            f"the untrusted target checkout: {executable}"
        )
    return _AuthorizedScanner(scanner_id, str(executable))


def _scanner_id(binary: str) -> str:
    return str(binary).casefold()


def _scanner_executable(binary: str) -> str:
    return str(getattr(binary, "executable", binary))


def _validated_scanner_json(
    binary: str,
    raw: str,
) -> tuple[Optional[dict], str]:
    """Parse and minimally type-check a scanner's documented JSON envelope."""
    if not isinstance(raw, str) or not raw.strip():
        return None, "scanner emitted no JSON object"
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as exc:
        return None, f"malformed scanner JSON: {type(exc).__name__}"
    if not isinstance(payload, dict):
        return None, "scanner JSON root is not an object"
    scanner_id = _scanner_id(binary)
    if scanner_id == "osv-scanner":
        if not isinstance(payload.get("results"), list):
            return None, "OSV JSON is missing results[]"
    elif scanner_id == "npm":
        if not isinstance(payload.get("vulnerabilities"), dict):
            return None, "npm JSON is missing vulnerabilities{}"
        if not isinstance(payload.get("metadata"), dict):
            return None, "npm JSON is missing metadata{}"
    elif scanner_id == "cargo-audit":
        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, dict) or not isinstance(
            vulnerabilities.get("list"), list
        ):
            return None, "cargo-audit JSON is missing vulnerabilities.list[]"
    return payload, ""


def _validated_posix_v2_compat_session(
    session_authority: object,
    *,
    scan_root: Path,
) -> _ValidatedCompatSession:
    """Validate the exact opaque same-process compatibility session."""

    if os.name == "nt":
        raise SupplyChainAbortError(
            "supply-chain gate: POSIX V2 compatibility is unavailable on Windows"
        )
    try:
        from posix_v2_compat_runtime import (
            _COMPAT_BACKENDS,
            COMPATIBILITY_MODE,
            require_posix_v2_compat_session,
        )

        authority = require_posix_v2_compat_session(session_authority)
        binding = dict(authority.binding)
        # This gate scans dependency lockfiles for malicious packages; it is
        # entirely backend-agnostic (``backend`` appears nowhere else in this
        # module).  It previously required the literal ``"codex"``, which meant
        # a Claude-backend session -- minted and fully supported by the compat
        # runtime -- was rejected here, aborting startup before recon and
        # making the Claude backend unrunnable on POSIX compatibility.  Bind to
        # the runtime's supported-backend denominator so the two cannot drift
        # again, while still refusing an absent or unsupported backend.
        if (
            binding.get("mode") != COMPATIBILITY_MODE
            or binding.get("backend") not in _COMPAT_BACKENDS
            or not isinstance(binding.get("session_binding_sha256"), str)
            or len(binding["session_binding_sha256"]) != 64
            or not isinstance(binding.get("run_id"), str)
            or not binding["run_id"]
        ):
            raise ValueError("session binding is incomplete")
        project_root = Path(str(binding["project_root"])).resolve(strict=True)
        scratchpad = Path(str(binding["scratchpad"])).resolve(strict=True)
        resolved_scan_root = Path(scan_root).resolve(strict=True)
        project_meta = os.lstat(project_root)
        scratch_meta = os.lstat(scratchpad)
    except Exception as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: exact POSIX V2 compatibility session could "
            f"not be admitted ({type(exc).__name__})"
        ) from exc
    if (
        not stat.S_ISDIR(project_meta.st_mode)
        or not stat.S_ISDIR(scratch_meta.st_mode)
        or _path_is_link_or_reparse(project_root)
        or _path_is_link_or_reparse(scratchpad)
        or scratchpad == project_root
        or not _path_is_within(scratchpad, project_root)
        or not _path_is_within(resolved_scan_root, project_root)
        or _path_is_within(resolved_scan_root, scratchpad)
    ):
        raise SupplyChainAbortError(
            "supply-chain gate: POSIX V2 compatibility roots violate the "
            "read-only-project/scratchpad-write boundary"
        )
    return _ValidatedCompatSession(
        project_root=project_root,
        scratchpad=scratchpad,
        session_binding_sha256=binding["session_binding_sha256"],
        run_id=binding["run_id"],
    )


def _compat_safe_path(project_root: Path, executable: str) -> str:
    """Retain only executable search directories outside the target tree."""

    candidates = [str(Path(executable).parent)]
    candidates.extend(os.environ.get("PATH", os.defpath).split(os.pathsep))
    candidates.extend(os.defpath.split(os.pathsep))
    retained: list[str] = []
    for raw in candidates:
        if not raw:
            continue
        try:
            candidate = Path(raw).expanduser().resolve(strict=True)
        except OSError:
            continue
        if not candidate.is_dir() or _path_is_within(candidate, project_root):
            continue
        rendered = str(candidate)
        if rendered not in retained:
            retained.append(rendered)
    return os.pathsep.join(retained)


def _compat_environment(
    *,
    scanner_id: str,
    project_root: Path,
    executable: str,
    transient: Path,
) -> dict[str, str]:
    isolated_home = transient / "home"
    temp_root = transient / "tmp"
    cache = transient / "cache"
    for directory in (isolated_home, temp_root, cache):
        directory.mkdir(mode=0o700)
    npm_user_config = transient / "npmrc"
    npm_user_config.write_text("# Plamen neutral npm policy\n", encoding="utf-8")
    npm_user_config.chmod(0o600)
    # OSV's pre-provisioned offline database lives below the account cache on
    # macOS. Seatbelt admits those bytes read-only while denying all writes
    # outside this invocation's scratch transient. Other scanners receive an
    # isolated HOME so npm/cargo logs and caches cannot target the account.
    try:
        import pwd

        account_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(
            strict=True
        )
    except (ImportError, KeyError, OSError) as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: account home cannot be resolved safely"
        ) from exc
    child_home = account_home if scanner_id == "osv-scanner" else isolated_home
    env = {
        "PATH": _compat_safe_path(project_root, executable),
        "HOME": str(child_home),
        "TMPDIR": str(temp_root),
        "TMP": str(temp_root),
        "TEMP": str(temp_root),
        "XDG_CACHE_HOME": str(cache),
        "NPM_CONFIG_CACHE": str(cache / "npm"),
        "npm_config_cache": str(cache / "npm"),
        "NPM_CONFIG_USERCONFIG": str(npm_user_config),
        "npm_config_userconfig": str(npm_user_config),
        "NPM_CONFIG_OFFLINE": "true",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_PACKAGE_LOCK_ONLY": "true",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "CARGO_HOME": str(cache / "cargo"),
        "CARGO_NET_OFFLINE": "true",
    }
    for name in ("LANG", "LC_ALL", "LC_CTYPE"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _scheme_string(value: str) -> str:
    if (
        not value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
    ):
        raise SupplyChainAbortError(
            "supply-chain gate: Seatbelt path contains unsupported bytes"
        )
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _compat_execution_argv(
    argv: Sequence[str], *, writable_root: Path,
) -> tuple[list[str], str]:
    """Wrap macOS execution in write-denying Seatbelt confinement."""

    requested = [str(value) for value in argv]
    if sys.platform != "darwin":
        return requested, "UNAVAILABLE_NON_DARWIN"
    sandbox_exec = Path("/usr/bin/sandbox-exec")
    try:
        metadata = sandbox_exec.stat(follow_symlinks=False)
        resolved = sandbox_exec.resolve(strict=True)
    except OSError as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: macOS Seatbelt provider is unavailable"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise SupplyChainAbortError(
            "supply-chain gate: macOS Seatbelt provider is not executable"
        )
    profile = "\n".join(
        (
            "(version 1)",
            "(allow default)",
            "(deny file-write*)",
            "(allow file-write* (subpath "
            + _scheme_string(str(writable_root))
            + "))",
        )
    ) + "\n"
    return [str(resolved), "-p", profile, *requested], "DARWIN_SEATBELT"


def _compat_scanner_command(
    scanner_id: str,
    executable: str,
    lockfile: Path,
    transient: Path,
) -> tuple[list[str], Path] | OfflineScanResult:
    if scanner_id == "osv-scanner":
        target = lockfile
        if lockfile.name == "go.sum":
            target = lockfile.with_name("go.mod")
            if not target.is_file():
                return OfflineScanResult(
                    OfflineScanState.UNAVAILABLE,
                    reason="go.sum requires its governed go.mod manifest",
                )
        neutral_config = transient / "osv-scanner.toml"
        neutral_config.write_text("# Plamen neutral policy\n", encoding="utf-8")
        neutral_config.chmod(0o600)
        return (
            [
                executable,
                "scan",
                "--offline",
                "--offline-vulnerabilities",
                "-L",
                str(target.resolve()),
                "--format",
                "json",
                "--config",
                str(neutral_config),
            ],
            transient,
        )
    if scanner_id == "npm":
        return OfflineScanResult(
            OfflineScanState.UNAVAILABLE,
            reason="npm audit --offline skips advisory lookup",
        )
    if scanner_id == "cargo-audit":
        advisory_root = Path(
            os.environ.get("PLAMEN_RUSTSEC_DB", "")
        ).expanduser()
        if not advisory_root.is_dir():
            return OfflineScanResult(
                OfflineScanState.UNAVAILABLE,
                reason="PLAMEN_RUSTSEC_DB is not a local directory",
            )
        return (
            [
                executable,
                "audit",
                "--json",
                "--no-fetch",
                "--db",
                str(advisory_root.resolve()),
                "--file",
                str(lockfile.resolve()),
            ],
            transient,
        )
    return OfflineScanResult(
        OfflineScanState.UNAVAILABLE,
        reason=f"unsupported scanner executable: {scanner_id}",
    )


def _read_bounded_output(
    handle, *, label: str, maximum: int, strict_utf8: bool = False,
) -> tuple[str, int, str]:
    handle.flush()
    size = int(os.fstat(handle.fileno()).st_size)
    if size > maximum:
        raise SupplyChainAbortError(
            f"supply-chain gate: compatibility {label} exceeded the bounded "
            f"output limit ({maximum} bytes)"
        )
    handle.seek(0)
    raw = handle.read(maximum + 1)
    if len(raw) != size:
        raise SupplyChainAbortError(
            f"supply-chain gate: compatibility {label} changed while reading"
        )
    try:
        text = raw.decode(
            "utf-8", errors="strict" if strict_utf8 else "replace"
        )
    except UnicodeDecodeError as exc:
        raise SupplyChainAbortError(
            f"supply-chain gate: compatibility {label} is not valid UTF-8"
        ) from exc
    return text, size, hashlib.sha256(raw).hexdigest()


def _terminate_compat_process_group(proc: subprocess.Popen) -> None:
    """Best-effort bounded termination of the compatibility process group."""

    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    try:
        proc.wait(timeout=_POSIX_COMPAT_KILL_GRACE_SECONDS)
        return
    except (subprocess.TimeoutExpired, OSError):
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except (OSError, ProcessLookupError):
            pass
    try:
        proc.wait(timeout=_POSIX_COMPAT_KILL_GRACE_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        pass


def _write_posix_v2_compat_receipt(
    session: _ValidatedCompatSession,
    *,
    scanner_id: str,
    executable: str,
    lockfile: Path,
    argv: Sequence[str],
    execution_argv: Sequence[str],
    write_confinement: str,
    transient: Path,
    result: _CompatTransportResult,
    stdout_bytes: int,
    stderr_bytes: int,
    staged_input_manifest_sha256: str = "",
) -> Path:
    receipt_root = session.scratchpad / _POSIX_COMPAT_RECEIPT_DIR
    try:
        receipt_root.mkdir(mode=0o700, exist_ok=True)
        metadata = os.lstat(receipt_root)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _path_is_link_or_reparse(receipt_root)
            or not _path_is_within(receipt_root, session.scratchpad)
        ):
            raise OSError("receipt root is not a local scratchpad directory")
        relative_lock = lockfile.resolve().relative_to(
            session.project_root
        ).as_posix()
        receipt_name = hashlib.sha256(
            f"{scanner_id}\0{relative_lock}\0{os.urandom(32).hex()}".encode("utf-8")
        ).hexdigest() + ".json"
        payload: Mapping[str, object] = {
            "schema_version": _POSIX_COMPAT_RECEIPT_SCHEMA,
            "state": "COMMITTED",
            "transport": "posix_v2_compat_subprocess_group",
            "scanner_id": scanner_id,
            "scanner_executable": executable,
            "session_binding_sha256": session.session_binding_sha256,
            "lockfile": relative_lock,
            "argv": list(argv),
            "execution_argv": list(execution_argv),
            "working_directory": transient.name,
            "read_only_intent_roots": [str(session.project_root)],
            "writable_roots": [str(transient)],
            "security_properties": {
                "reduced_isolation": True,
                "native_owned_process_runner": False,
                "native_broker_authority": False,
                "wer_authority": False,
                "population_zero_proven": False,
                "shell": False,
                "new_process_group": True,
                "bounded_file_output": True,
                "write_confinement": write_confinement,
            },
            "timeout_seconds": 120,
            "timed_out": result.timed_out,
            "returncode": result.returncode,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
            "stdout_sha256": hashlib.sha256(
                result.stdout.encode("utf-8", errors="replace")
            ).hexdigest() if not result.stdout_raw_sha256 else result.stdout_raw_sha256,
            "stderr_sha256": hashlib.sha256(
                result.stderr.encode("utf-8", errors="replace")
            ).hexdigest() if not result.stderr_raw_sha256 else result.stderr_raw_sha256,
            "staged_input_manifest_sha256": staged_input_manifest_sha256,
        }
        raw = (
            json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="w+b", dir=receipt_root, prefix=".pending-", delete=False
        ) as pending:
            pending_path = Path(pending.name)
            os.fchmod(pending.fileno(), 0o600)
            pending.write(raw)
            pending.flush()
            os.fsync(pending.fileno())
        destination = receipt_root / receipt_name
        os.replace(pending_path, destination)
        directory_fd = os.open(receipt_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception as exc:
        try:
            if "pending_path" in locals() and pending_path.exists():
                pending_path.unlink()
        except OSError:
            pass
        raise SupplyChainAbortError(
            "supply-chain gate: compatibility execution receipt could not be "
            f"committed ({type(exc).__name__})"
        ) from exc
    log.warning(
        "supply_chain_gate: POSIX V2 reduced-isolation scanner receipt=%s "
        "population_zero_proven=false",
        destination,
    )
    return destination


def _run_posix_v2_compat_scanner(
    binary: str,
    lockfile: Path,
    session_authority: object,
    *,
    scan_root: Path | None = None,
    admitted_inputs: Mapping[str, bytes] | None = None,
    input_manifest_sha256: str = "",
) -> OfflineScanResult | _CompatTransportResult:
    session = _validated_posix_v2_compat_session(
        session_authority, scan_root=lockfile.parent
    )
    scanner_id = _scanner_id(binary)
    executable = _scanner_executable(binary)
    transient_path = Path(
        tempfile.mkdtemp(
            prefix=".posix-v2-supply-chain-",
            dir=session.scratchpad,
        )
    )
    transient_path.chmod(0o700)
    try:
        scanner_lockfile = lockfile
        if scan_root is not None and admitted_inputs is not None:
            resolved_scan_root = scan_root.resolve(strict=True)
            staging_root = transient_path / "admitted-inputs"
            staging_root.mkdir(mode=0o700)
            for relative, raw in admitted_inputs.items():
                destination = staging_root / relative
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                destination.write_bytes(raw)
                destination.chmod(0o600)
                if destination.read_bytes() != raw:
                    raise SupplyChainAbortError(
                        "supply-chain gate: staged scanner input differs from admission"
                    )
            scanner_lockfile = staging_root / lockfile.resolve().relative_to(
                resolved_scan_root
            )
            if not scanner_lockfile.is_file():
                raise SupplyChainAbortError(
                    "supply-chain gate: admitted scanner lockfile was not staged"
                )
        command = _compat_scanner_command(
            scanner_id, executable, scanner_lockfile, transient_path
        )
        if isinstance(command, OfflineScanResult):
            return command
        argv, run_cwd = command
        env = _compat_environment(
            scanner_id=scanner_id,
            project_root=session.project_root,
            executable=executable,
            transient=transient_path,
        )
        execution_argv, write_confinement = _compat_execution_argv(
            argv, writable_root=transient_path
        )
        timed_out = False
        with tempfile.TemporaryFile(mode="w+b", dir=transient_path) as stdout_file, \
                tempfile.TemporaryFile(mode="w+b", dir=transient_path) as stderr_file:
            try:
                proc = subprocess.Popen(
                    execution_argv,
                    cwd=str(run_cwd),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                    close_fds=True,
                )
                try:
                    returncode = proc.wait(timeout=120)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _terminate_compat_process_group(proc)
                    returncode = 124
            except (OSError, subprocess.SubprocessError) as exc:
                returncode = 125
                stderr_file.write(
                    (f"compatibility scanner transport failed: "
                     f"{type(exc).__name__}").encode("utf-8")
                )
            stdout, stdout_bytes, stdout_raw_sha256 = _read_bounded_output(
                stdout_file,
                label="stdout",
                maximum=_POSIX_COMPAT_STDOUT_MAX_BYTES,
                strict_utf8=True,
            )
            stderr, stderr_bytes, stderr_raw_sha256 = _read_bounded_output(
                stderr_file,
                label="stderr",
                maximum=_POSIX_COMPAT_STDERR_MAX_BYTES,
            )
        result = _CompatTransportResult(
            returncode=int(returncode),
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            stdout_raw_sha256=stdout_raw_sha256,
            stderr_raw_sha256=stderr_raw_sha256,
        )
        receipt_path = _write_posix_v2_compat_receipt(
            session,
            scanner_id=scanner_id,
            executable=executable,
            lockfile=lockfile,
            argv=argv,
            execution_argv=execution_argv,
            write_confinement=write_confinement,
            transient=transient_path,
            result=result,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            staged_input_manifest_sha256=input_manifest_sha256,
        )
        return _CompatTransportResult(
            returncode=result.returncode, stdout=result.stdout,
            stderr=result.stderr, timed_out=result.timed_out,
            receipt_path=receipt_path,
            stdout_raw_sha256=result.stdout_raw_sha256,
            stderr_raw_sha256=result.stderr_raw_sha256,
        )
    finally:
        shutil.rmtree(transient_path, ignore_errors=True)


def _call_offline_scanner(
    binary: str,
    lockfile: Path,
    *,
    posix_compat_session: object | None = None,
    _compat_gate_nonce: str | None = None,
    _compat_scan_root: Path | None = None,
    _compat_admitted_inputs: Mapping[str, bytes] | None = None,
    _compat_input_manifest_sha256: str | None = None,
) -> OfflineScanResult:
    """Run a no-fetch scanner and return a typed transport/schema result."""
    if _scanner_id(binary) == "npm":
        return OfflineScanResult(
            OfflineScanState.UNAVAILABLE,
            reason="npm audit --offline skips advisory lookup",
        )
    if posix_compat_session is not None:
        try:
            proc = _run_posix_v2_compat_scanner(
                binary, lockfile, posix_compat_session,
                scan_root=_compat_scan_root,
                admitted_inputs=_compat_admitted_inputs,
                input_manifest_sha256=_compat_input_manifest_sha256 or "",
            )
        except Exception as exc:
            log.warning(
                "supply_chain_gate: POSIX V2 scanner call failed (%s on %s): %s",
                binary,
                lockfile,
                exc,
            )
            return OfflineScanResult(
                OfflineScanState.FAILED,
                reason=(
                    "POSIX V2 compatibility scanner transport failed: "
                    f"{type(exc).__name__}"
                ),
            )
        if isinstance(proc, OfflineScanResult):
            return proc
        raw = proc.stdout or ""
        if proc.timed_out:
            return OfflineScanResult(
                OfflineScanState.FAILED,
                reason="scanner timed out; process group terminated",
                returncode=proc.returncode,
            )
        if proc.returncode not in (0, 1):
            return OfflineScanResult(
                OfflineScanState.FAILED,
                reason=f"scanner exited with rc={proc.returncode}",
                returncode=proc.returncode,
            )
        payload, issue = _validated_scanner_json(_scanner_id(binary), raw)
        if payload is None:
            return OfflineScanResult(
                OfflineScanState.FAILED,
                reason=issue,
                returncode=proc.returncode,
            )
        result = OfflineScanResult(
            OfflineScanState.SUCCEEDED,
            output=json.dumps(payload, sort_keys=True),
            returncode=proc.returncode,
        )
        session = _validated_posix_v2_compat_session(
            posix_compat_session, scan_root=lockfile.parent,
        )
        relative = lockfile.resolve().relative_to(session.project_root).as_posix()
        receipt_path = proc.receipt_path
        if receipt_path is None:
            raise SupplyChainAbortError(
                "supply-chain gate: current scanner execution has no receipt path"
            )
        try:
            receipt_raw = receipt_path.read_bytes()
            receipt_payload = json.loads(receipt_raw)
        except (OSError, ValueError, TypeError) as exc:
            raise SupplyChainAbortError(
                "supply-chain gate: current scanner receipt cannot be observed"
            ) from exc
        raw_stdout_sha256 = proc.stdout_raw_sha256
        if not raw_stdout_sha256:
            raise SupplyChainAbortError(
                "supply-chain gate: current scanner stdout byte digest is absent"
            )
        if (
            not isinstance(receipt_payload, dict)
            or receipt_payload.get("stdout_sha256") != raw_stdout_sha256
            or receipt_payload.get("returncode") != proc.returncode
            or receipt_payload.get("session_binding_sha256")
            != session.session_binding_sha256
            or receipt_payload.get("staged_input_manifest_sha256")
            != (_compat_input_manifest_sha256 or "")
        ):
            raise SupplyChainAbortError(
                "supply-chain gate: current result and execution receipt differ"
            )
        result_id = id(result)
        def forget(_reference: object, *, key: int = result_id) -> None:
            _COMPAT_SCAN_OBSERVATIONS.pop(key, None)
        _COMPAT_SCAN_OBSERVATIONS[result_id] = _CompatScanObservation(
            result_ref=weakref.ref(result, forget),
            session_ref=weakref.ref(posix_compat_session),
            scanner_id=_scanner_id(binary), lockfile=relative,
            receipt_path=receipt_path,
            receipt_sha256=hashlib.sha256(receipt_raw).hexdigest(),
            raw_stdout_sha256=raw_stdout_sha256,
            normalized_output_sha256=hashlib.sha256(
                result.output.encode("utf-8")
            ).hexdigest(),
            gate_nonce=_compat_gate_nonce or "",
            staged_input_manifest_sha256=(
                _compat_input_manifest_sha256 or ""
            ),
        )
        return result

    neutral_context: Optional[tempfile.TemporaryDirectory[str]] = None
    run_cwd = lockfile.parent
    run_env = None
    scanner_id = _scanner_id(binary)
    executable = _scanner_executable(binary)
    if scanner_id == "osv-scanner":
        target = lockfile
        if lockfile.name == "go.sum":
            target = lockfile.with_name("go.mod")
            if not target.is_file():
                return OfflineScanResult(
                    OfflineScanState.UNAVAILABLE,
                    reason="go.sum requires its governed go.mod manifest",
                )
        neutral_context = tempfile.TemporaryDirectory(prefix="plamen-osv-")
        run_cwd = Path(neutral_context.name)
        neutral_config = run_cwd / "osv-scanner.toml"
        neutral_config.write_text("# Plamen neutral policy\n", encoding="utf-8")
        cmd = [
            executable,
            "scan",
            "--offline",
            "--offline-vulnerabilities",
            "-L",
            str(target.resolve()),
            "--format",
            "json",
            "--config",
            str(neutral_config),
        ]
    elif scanner_id == "npm":
        return OfflineScanResult(
            OfflineScanState.UNAVAILABLE,
            reason="npm audit --offline skips advisory lookup",
        )
    elif scanner_id == "cargo-audit":
        advisory_root = Path(
            os.environ.get("PLAMEN_RUSTSEC_DB", "")
        ).expanduser()
        if not advisory_root.is_dir():
            return OfflineScanResult(
                OfflineScanState.UNAVAILABLE,
                reason="PLAMEN_RUSTSEC_DB is not a local directory",
            )
        neutral_context = tempfile.TemporaryDirectory(
            prefix="plamen-cargo-audit-"
        )
        run_cwd = Path(neutral_context.name)
        isolated_cargo_home = run_cwd / "cargo-home"
        isolated_cargo_home.mkdir()
        run_env = dict(os.environ)
        run_env["CARGO_HOME"] = str(isolated_cargo_home)
        run_env["CARGO_NET_OFFLINE"] = "true"
        cmd = [
            executable,
            "audit",
            "--json",
            "--no-fetch",
            "--db",
            str(advisory_root),
            "--file",
            str(lockfile.resolve()),
        ]
    else:
        return OfflineScanResult(
            OfflineScanState.UNAVAILABLE,
            reason=f"unsupported scanner executable: {binary}",
        )
    try:
        proc = run_owned_process(
            cmd,
            cwd=str(run_cwd),
            env=run_env,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            writable_roots=(run_cwd,),
        )
    except Exception as exc:
        log.warning(
            "supply_chain_gate: scanner call failed (%s on %s): %s",
            binary,
            lockfile,
            exc,
        )
        return OfflineScanResult(
            OfflineScanState.FAILED,
            reason=f"scanner transport failed: {type(exc).__name__}",
        )
    finally:
        if neutral_context is not None:
            neutral_context.cleanup()
    # Scanner diagnostics/progress belong to stderr and are untrusted prose,
    # never part of the machine-readable classification authority.
    raw = proc.stdout or ""
    if proc.returncode not in (0, 1):
        return OfflineScanResult(
            OfflineScanState.FAILED,
            reason=f"scanner exited with rc={proc.returncode}",
            returncode=proc.returncode,
        )
    payload, issue = _validated_scanner_json(scanner_id, raw)
    if payload is None:
        return OfflineScanResult(
            OfflineScanState.FAILED,
            reason=issue,
            returncode=proc.returncode,
        )
    return OfflineScanResult(
        OfflineScanState.SUCCEEDED,
        output=json.dumps(payload, sort_keys=True),
        returncode=proc.returncode,
    )


def _denylist_hit(text: str, denylist: Iterable[str]) -> Optional[str]:
    for entry in denylist:
        if entry and entry in text:
            return entry
    return None


def _install_script_heuristic_hit(
    root: Path, *, fail_on_read_error: bool = False,
) -> Optional[str]:
    """Offline, no-network heuristic: flag pre/post/install script hooks
    combined with a base64+eval-style obfuscation chain in the TARGET repo's
    own manifest files. Best-effort — a miss here does not weaken the other
    signals; a hit fail-closed aborts."""
    for name in ("package.json", "package-lock.json"):
        p = root / name
        try:
            if not p.is_file():
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            if fail_on_read_error:
                raise SupplyChainAbortError(
                    "supply-chain gate: heuristic source cannot be read "
                    f"exactly: {p} ({type(exc).__name__})"
                ) from exc
            continue
        if _BASE64_EVAL_RE.search(text):
            return f"base64/eval obfuscation chain in {name}"
        has_install_hook = any(f'"{k}"' in text for k in _INSTALL_SCRIPT_KEYS)
        if has_install_hook and "base64" in text.lower() and (
            "eval(" in text or "Function(" in text
        ):
            return f"install-script hook + base64/eval in {name}"
    return None


def _compat_input_snapshot(root: Path, lockfiles: Sequence[Path]) -> _CompatInputSnapshot:
    """Bind the bounded physical identities and bytes of all implicit inputs."""

    resolved_root = root.resolve(strict=True)
    inputs: dict[Path, set[str]] = {}
    for lockfile in lockfiles:
        path = lockfile.resolve(strict=True)
        inputs.setdefault(path, set()).add("LOCKFILE")
        if _name_key(path.name) == _name_key("go.sum"):
            inputs.setdefault(path.with_name("go.mod"), set()).add("SCANNER_IMPLICIT")
        if _name_key(path.name) in {
            _name_key("package-lock.json"), _name_key("npm-shrinkwrap.json")
        }:
            inputs.setdefault(path.with_name("package.json"), set()).add("SCANNER_IMPLICIT")
    inputs.setdefault(resolved_root / "package.json", set()).add("HEURISTIC_INPUT")
    rows: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    for path in sorted(inputs, key=lambda item: item.relative_to(resolved_root).as_posix()):
        relative = path.relative_to(resolved_root).as_posix()
        kinds = tuple(sorted(inputs[path]))
        try:
            before = os.lstat(path)
        except FileNotFoundError:
            rows.append({"kinds": kinds, "path": relative, "state": "ABSENT"})
            continue
        except OSError as exc:
            raise SupplyChainAbortError(
                "supply-chain gate: compatibility input cannot be inspected "
                f"exactly: {path} ({type(exc).__name__})"
            ) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or _path_is_link_or_reparse(path)
            or before.st_size < 0
            or before.st_size > 128 * 1024 * 1024
        ):
            raise SupplyChainAbortError(
                f"supply-chain gate: compatibility input type or size is unsafe: {path}"
            )
        try:
            raw = path.read_bytes()
            after = os.lstat(path)
        except OSError as exc:
            raise SupplyChainAbortError(
                "supply-chain gate: compatibility input cannot be read "
                f"exactly: {path} ({type(exc).__name__})"
            ) from exc
        identity = lambda observed: (
            int(observed.st_dev), int(observed.st_ino), int(observed.st_mode),
            int(observed.st_uid), int(observed.st_gid), int(observed.st_nlink),
            int(observed.st_size), int(observed.st_mtime_ns), int(observed.st_ctime_ns),
        )
        if identity(before) != identity(after) or len(raw) != before.st_size:
            raise SupplyChainAbortError(
                f"supply-chain gate: compatibility input changed while read: {path}"
            )
        rows.append({
            "kinds": kinds, "path": relative, "state": "PRESENT",
            "identity": {
                "device": int(before.st_dev), "inode": int(before.st_ino),
                "mode": int(before.st_mode), "owner": int(before.st_uid),
                "group": int(before.st_gid), "link_count": int(before.st_nlink),
                "size": int(before.st_size), "mtime_ns": int(before.st_mtime_ns),
                "ctime_ns": int(before.st_ctime_ns),
            },
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        contents[relative] = raw
    return _CompatInputSnapshot(
        rows=tuple(rows), contents=MappingProxyType(contents),
    )


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _compat_snapshot_heuristic_hit(snapshot: _CompatInputSnapshot) -> Optional[str]:
    for name in ("package.json", "package-lock.json"):
        raw = snapshot.contents.get(name)
        if raw is None:
            continue
        text = raw.decode("utf-8", errors="replace")
        if _BASE64_EVAL_RE.search(text):
            return f"base64/eval obfuscation chain in {name}"
        has_install_hook = any(f'"{key}"' in text for key in _INSTALL_SCRIPT_KEYS)
        if has_install_hook and "base64" in text.lower() and (
            "eval(" in text or "Function(" in text
        ):
            return f"install-script hook + base64/eval in {name}"
    return None


def _compat_receipt_evidence(
    session: _ValidatedCompatSession, *, scanner: str, lockfile: Path,
    result: OfflineScanResult, session_authority: object, gate_nonce: str,
    input_manifest_sha256: str,
) -> dict[str, object]:
    relative = lockfile.resolve().relative_to(session.project_root).as_posix()
    observation = _COMPAT_SCAN_OBSERVATIONS.pop(id(result), None)
    if (
        observation is None
        or observation.result_ref() is not result
        or observation.session_ref() is not session_authority
        or observation.scanner_id != _scanner_id(scanner)
        or observation.lockfile != relative
        or observation.gate_nonce != gate_nonce
        or observation.staged_input_manifest_sha256 != input_manifest_sha256
        or observation.normalized_output_sha256
        != hashlib.sha256(result.output.encode("utf-8")).hexdigest()
    ):
        raise SupplyChainAbortError(
            "supply-chain gate: scanner result lacks current process-local execution lineage"
        )
    path = observation.receipt_path
    try:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or _path_is_link_or_reparse(path) or metadata.st_size <= 0 or metadata.st_size > 2 * 1024 * 1024:
            raise OSError("receipt type or size is invalid")
        raw = path.read_bytes()
        confirmed = os.lstat(path)
        payload = json.loads(raw)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SupplyChainAbortError(
            "supply-chain gate: actual compatibility scanner evidence is missing or malformed "
            f"({type(exc).__name__})"
        ) from exc
    if len(raw) != metadata.st_size or (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_ctime_ns) != (confirmed.st_dev, confirmed.st_ino, confirmed.st_mtime_ns, confirmed.st_ctime_ns):
        raise SupplyChainAbortError("supply-chain gate: scanner receipt changed while admitted")
    required = {
        "schema_version": _POSIX_COMPAT_RECEIPT_SCHEMA, "state": "COMMITTED",
        "scanner_id": _scanner_id(scanner), "session_binding_sha256": session.session_binding_sha256,
        "lockfile": relative, "timed_out": False,
        "staged_input_manifest_sha256": input_manifest_sha256,
    }
    if not isinstance(payload, dict) or any(payload.get(key) != value for key, value in required.items()) or payload.get("returncode") != result.returncode or hashlib.sha256(raw).hexdigest() != observation.receipt_sha256 or payload.get("stdout_sha256") != observation.raw_stdout_sha256:
        raise SupplyChainAbortError("supply-chain gate: scanner receipt does not bind the admitted execution")
    return {
        "lockfile": relative, "scanner_id": _scanner_id(scanner),
        "receipt_path": path.relative_to(session.scratchpad).as_posix(),
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "scanner_output_sha256": observation.normalized_output_sha256,
        "returncode": result.returncode,
        "staged_input_manifest_sha256": input_manifest_sha256,
    }


def _freeze_admission_value(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_admission_value(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_admission_value(item) for item in value)
    return value


def _plain_admission_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _plain_admission_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_admission_value(item) for item in value]
    return value


def _issue_admission(session_authority: object, projection: Mapping[str, object]) -> SupplyChainAdmission:
    authority = object.__new__(SupplyChainAdmission)
    token = os.urandom(32).hex()
    object.__setattr__(authority, "_SupplyChainAdmission__token", token)
    issued_projection = dict(projection)
    issued_projection["admission_sha256"] = _canonical_sha(issued_projection)
    authority_id = id(authority)
    def forget(_reference: object, *, key: int = authority_id) -> None:
        _ADMISSIONS.pop(key, None)
    _ADMISSIONS[authority_id] = _AdmissionRecord(
        token=token, authority_ref=weakref.ref(authority, forget),
        session_authority_ref=weakref.ref(session_authority),
        projection=_freeze_admission_value(issued_projection),
    )
    return authority


def project_supply_chain_admission(
    admission: object, *, posix_compat_session: object,
) -> Mapping[str, object]:
    """Replay a live admission, rejecting expiry, forgery, or input/evidence drift."""

    if type(admission) is not SupplyChainAdmission:
        raise SupplyChainAbortError("supply-chain gate: admission has the wrong exact type")
    record = _ADMISSIONS.get(id(admission))
    try:
        token = object.__getattribute__(admission, "_SupplyChainAdmission__token")
    except BaseException as exc:
        raise SupplyChainAbortError("supply-chain gate: admission shell is incomplete") from exc
    if record is None or record.authority_ref() is not admission or record.token != token or record.session_authority_ref() is not posix_compat_session:
        raise SupplyChainAbortError("supply-chain gate: admission is forged or belongs to another session")
    projection = dict(record.projection)
    scan_root = Path(str(projection["scan_root"]))
    session = _validated_posix_v2_compat_session(posix_compat_session, scan_root=scan_root)
    try:
        resolved_scan_root = scan_root.resolve(strict=True)
    except OSError as exc:
        raise SupplyChainAbortError("supply-chain gate: admitted scan root is unavailable") from exc
    lockfiles = _find_lockfiles(resolved_scan_root)
    inputs = _compat_input_snapshot(resolved_scan_root, lockfiles)
    claimed_digest = projection.pop("admission_sha256", None)
    if claimed_digest != _canonical_sha(_plain_admission_value(projection)):
        raise SupplyChainAbortError("supply-chain gate: admission projection digest differs")
    projection["admission_sha256"] = claimed_digest
    if projection.get("project_root") != str(session.project_root) or projection.get("scan_root") != str(resolved_scan_root) or projection.get("run_id") != session.run_id or projection.get("session_binding_sha256") != session.session_binding_sha256 or projection.get("input_denominator_sha256") != _canonical_sha(inputs.rows):
        raise SupplyChainAbortError("supply-chain gate: admission session or relevant inputs drifted")
    evidence_rows = projection.get("scanner_evidence", ())
    expected_locks = {
        path.resolve().relative_to(session.project_root).as_posix()
        for path in lockfiles
    }
    if not isinstance(evidence_rows, tuple) or {
        row.get("lockfile") for row in evidence_rows if isinstance(row, Mapping)
    } != expected_locks or len(evidence_rows) != len(expected_locks):
        raise SupplyChainAbortError("supply-chain gate: scanner evidence denominator is incomplete")
    for evidence in evidence_rows:
        if not isinstance(evidence, Mapping):
            raise SupplyChainAbortError("supply-chain gate: scanner evidence projection is malformed")
        path = session.scratchpad / str(evidence.get("receipt_path", ""))
        try:
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode) or _path_is_link_or_reparse(path) or metadata.st_size <= 0 or metadata.st_size > 2 * 1024 * 1024:
                raise OSError("receipt type or size is invalid")
            raw = path.read_bytes()
        except OSError as exc:
            raise SupplyChainAbortError("supply-chain gate: scanner evidence is missing") from exc
        if hashlib.sha256(raw).hexdigest() != evidence.get("receipt_sha256"):
            raise SupplyChainAbortError("supply-chain gate: scanner evidence drifted")
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise SupplyChainAbortError("supply-chain gate: scanner evidence is malformed") from exc
        if not isinstance(payload, dict) or payload.get("schema_version") != _POSIX_COMPAT_RECEIPT_SCHEMA or payload.get("state") != "COMMITTED" or payload.get("session_binding_sha256") != session.session_binding_sha256 or payload.get("scanner_id") != evidence.get("scanner_id") or payload.get("lockfile") != evidence.get("lockfile") or payload.get("timed_out") is not False or payload.get("returncode") != evidence.get("returncode") or payload.get("staged_input_manifest_sha256") != projection.get("input_denominator_sha256") or evidence.get("staged_input_manifest_sha256") != projection.get("input_denominator_sha256"):
            raise SupplyChainAbortError("supply-chain gate: scanner evidence no longer validates")
    return MappingProxyType(projection)


def gate_supply_chain(
    root: Path,
    *,
    denylist: Optional[Sequence[str]] = None,
    posix_compat_session: object | None = None,
) -> SupplyChainAdmission | None:
    """Fail-closed pre-exec safety gate.

    Call BEFORE any subprocess that installs/builds/tests dependencies
    resolved from the (untrusted) TARGET repo. This is a TRUE circuit
    breaker: on any fail-closed condition it raises immediately, before
    later signals are even checked, and the caller must let that exception
    prevent the guarded subprocess from running.

    Raises :class:`SupplyChainAbortError` when:
      - an append-only IoC denylist entry matches a found lockfile, OR
      - the install-script/base64 heuristic fires, OR
      - the offline scanner reports typed malicious-package/IoC evidence, OR
      - lockfile(s) are present but no compatible offline scanner is
        available, OR
      - scanner transport, exit status, or output schema is incomplete.

    No lockfiles and a heuristic finding nothing return normally and are
    logged. Scanner failure never becomes a clean result.

    Env override: ``PLAMEN_SKIP_SUPPLY_CHAIN_GATE=1`` disables the gate
    entirely (explicit opt-out for trusted/offline dev environments — never
    the default, and always logged when used).
    """
    root = Path(root)
    compat_session: _ValidatedCompatSession | None = None
    compat_inputs: _CompatInputSnapshot | None = None
    scanner_evidence: list[dict[str, object]] = []
    ordinary_risk_count = 0
    compat_gate_nonce = os.urandom(32).hex() if posix_compat_session is not None else ""
    if posix_compat_session is not None:
        # Exact opaque same-process authority is checked before lockfile,
        # executable, or opt-out inspection; no config/env marker can activate
        # or bypass this strict post-session path.
        compat_session = _validated_posix_v2_compat_session(
            posix_compat_session, scan_root=root
        )
        try:
            resolved_requested_root = root.resolve(strict=True)
        except OSError as exc:
            raise SupplyChainAbortError(
                "supply-chain gate: compatibility scan root is unavailable"
            ) from exc
        root = resolved_requested_root
    if (
        os.environ.get("PLAMEN_SKIP_SUPPLY_CHAIN_GATE") == "1"
        and posix_compat_session is None
    ):
        log.warning("supply_chain_gate: SKIPPED via PLAMEN_SKIP_SUPPLY_CHAIN_GATE=1 "
                     "for %s", root)
        return
    if os.environ.get("PLAMEN_SKIP_SUPPLY_CHAIN_GATE") == "1":
        raise SupplyChainAbortError(
            "supply-chain gate: PLAMEN_SKIP_SUPPLY_CHAIN_GATE cannot bypass "
            "the POSIX V2 compatibility post-session gate"
        )

    active_denylist = tuple(denylist) if denylist is not None else tuple(DEFAULT_IOC_DENYLIST)
    lockfiles = _find_lockfiles(root)
    if compat_session is not None:
        compat_inputs = _compat_input_snapshot(root, lockfiles)

    # --- Signal 1: append-only IoC denylist (no binary required) ----------
    for lf in lockfiles:
        if compat_inputs is not None:
            relative = lf.resolve().relative_to(root).as_posix()
            admitted = compat_inputs.contents.get(relative)
            if admitted is None:
                raise SupplyChainAbortError(
                    "supply-chain gate: admitted lockfile bytes are missing"
                )
            text = admitted.decode("utf-8", errors="replace")
        else:
            try:
                text = lf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
        hit = _denylist_hit(text, active_denylist)
        if hit:
            log.error("supply_chain_gate: denylisted IoC %r found in %s", hit, lf)
            raise SupplyChainAbortError(
                f"supply-chain gate: denylisted dependency IoC {hit!r} found in "
                f"{lf}. Aborting before install/build/test — fail-closed."
            )

    # --- Signal 2: install-script + base64/eval heuristic (no binary) -----
    heuristic_hit = (
        _compat_snapshot_heuristic_hit(compat_inputs)
        if compat_inputs is not None
        else _install_script_heuristic_hit(root)
    )
    if heuristic_hit:
        log.error("supply_chain_gate: install-script heuristic fired (%s) in %s",
                   heuristic_hit, root)
        raise SupplyChainAbortError(
            f"supply-chain gate: suspicious install-script heuristic fired "
            f"({heuristic_hit}) under {root}. Aborting before "
            "install/build/test — fail-closed."
        )

    # --- Signal 3: offline dependency-vulnerability scanner ---------------
    if not lockfiles:
        log.info("supply_chain_gate: no lockfile found under %s — scanner step "
                  "skipped (nothing to verify)", root)
        if compat_session is None:
            return None
        confirmed_inputs = _compat_input_snapshot(root, _find_lockfiles(root))
        if confirmed_inputs != compat_inputs or compat_inputs is None:
            raise SupplyChainAbortError(
                "supply-chain gate: relevant supply-chain inputs drifted during admission"
            )
        projection = {
            "schema_version": "plamen.posix_v2_compat_supply_chain_admission.v1",
            "status": "ADMITTED", "scanner_applicability": "NOT_APPLICABLE",
            "scope_limit": "no dependency lockfile was present; dependencies were not proven safe",
            "run_id": compat_session.run_id,
            "project_root": str(compat_session.project_root),
            "scan_root": str(root),
            "session_binding_sha256": compat_session.session_binding_sha256,
            "input_denominator": compat_inputs.rows,
            "input_denominator_sha256": _canonical_sha(compat_inputs.rows),
            "lockfile_count": 0, "scanner_evidence": (),
            "ordinary_vulnerability_count": 0,
        }
        return _issue_admission(posix_compat_session, projection)

    resolved_scanners = {
        scanner_id: resolved
        for scanner_id in _SCANNER_BINARIES
        if (
            resolved := _resolve_scanner_authority(scanner_id, root)
        ) is not None
    }
    if not resolved_scanners:
        # The ONE legitimate hard stop: dependencies exist but cannot be
        # verified at all.
        log.error(
            "supply_chain_gate: %d lockfile(s) present under %s but no offline "
            "scanner binary is on PATH (tried %s) — cannot verify target "
            "dependencies. Fail-closed.",
            len(lockfiles), root, ", ".join(_SCANNER_BINARIES),
        )
        raise SupplyChainAbortError(
            "supply-chain gate: no offline scanner binary available "
            f"(tried {', '.join(_SCANNER_BINARIES)}) — cannot verify target "
            f"dependencies under {root} are safe to install/build/test. "
            "Fail-closed."
        )

    for lf in lockfiles:
        candidates = next(
            (
                scanner_ids
                for lock_name, scanner_ids in _LOCKFILE_SCANNERS.items()
                if _name_key(lock_name) == _name_key(lf.name)
            ),
            (),
        )
        available = [
            resolved_scanners[candidate]
            for candidate in candidates
            if candidate in resolved_scanners
        ]
        if not available:
            tried = ", ".join(candidates) or "no compatible scanner"
            raise SupplyChainAbortError(
                f"supply-chain gate: {lf.name} is in the verification "
                f"denominator but no compatible offline scanner is available "
                f"(tried {tried}). Fail-closed."
            )
        failures: list[str] = []
        output: Optional[str] = None
        binary = available[0]
        for binary in available:
            if posix_compat_session is None:
                # Preserve the historical two-argument seam and the normal
                # OwnedProcessRunner transport exactly.
                result = _call_offline_scanner(binary, lf)
            else:
                result = _call_offline_scanner(
                    binary,
                    lf,
                    posix_compat_session=posix_compat_session,
                    _compat_gate_nonce=compat_gate_nonce,
                    _compat_scan_root=root,
                    _compat_admitted_inputs=(
                        None if compat_inputs is None else compat_inputs.contents
                    ),
                    _compat_input_manifest_sha256=(
                        "" if compat_inputs is None
                        else _canonical_sha(compat_inputs.rows)
                    ),
                )
            # Compatibility for the historical private fixture seam.
            if isinstance(result, str):
                if compat_session is not None:
                    raise SupplyChainAbortError(
                        "supply-chain gate: compatibility scanner fixture output "
                        "has no actual execution receipt"
                    )
                output = result
                break
            if result.state is OfflineScanState.SUCCEEDED:
                output = result.output
                break
            failures.append(
                f"{binary}={result.state.value}:{result.reason}"
            )
        if output is None:
            raise SupplyChainAbortError(
                f"supply-chain gate: no available scanner could verify {lf}: "
                + "; ".join(failures)
                + ". Fail-closed."
            )
        payload, issue = _validated_scanner_json(binary, output)
        if payload is None:
            raise SupplyChainAbortError(
                f"supply-chain gate: {binary} result for {lf} cannot be "
                f"classified safely ({issue}). Fail-closed."
            )
        try:
            assessment = _scanner_risk_assessment(binary, payload)
        except _ScannerSchemaError as exc:
            raise SupplyChainAbortError(
                f"supply-chain gate: {binary} result for {lf} has an "
                f"unsupported or malformed schema ({exc}). Fail-closed."
            ) from exc
        if assessment.malicious_evidence:
            evidence = ", ".join(assessment.malicious_evidence)
            log.error(
                "supply_chain_gate: %s reported typed malicious-package "
                "evidence for %s: %s",
                binary,
                lf,
                evidence,
            )
            raise SupplyChainAbortError(
                f"supply-chain gate: {binary} reported typed "
                f"malicious-package/IoC evidence for {lf} ({evidence}). "
                "Aborting before install/build/test -- fail-closed."
            )
        if compat_session is not None:
            if not isinstance(result, OfflineScanResult):
                raise SupplyChainAbortError(
                    "supply-chain gate: compatibility scanner result is not typed"
                )
            scanner_evidence.append(_compat_receipt_evidence(
                compat_session, scanner=binary, lockfile=lf, result=result,
                session_authority=posix_compat_session,
                gate_nonce=compat_gate_nonce,
                input_manifest_sha256=_canonical_sha(compat_inputs.rows),
            ))
        ordinary_risk_count += assessment.vulnerability_count
        if assessment.vulnerability_count:
            log.warning(
                "supply_chain_gate: %s reported %d ordinary dependency "
                "vulnerability record(s) for %s; retained as audit risk, "
                "not misclassified as malicious-package evidence",
                binary,
                assessment.vulnerability_count,
                lf,
            )
    log.info(
        "supply_chain_gate: %d lockfile(s) scanned without a blocking signal "
        "under %s", len(lockfiles), root,
    )
    if compat_session is None:
        return None
    confirmed_inputs = _compat_input_snapshot(root, _find_lockfiles(root))
    if confirmed_inputs != compat_inputs or compat_inputs is None:
        raise SupplyChainAbortError(
            "supply-chain gate: relevant supply-chain inputs drifted during admission"
        )
    projection = {
        "schema_version": "plamen.posix_v2_compat_supply_chain_admission.v1",
        "status": "ADMITTED", "scanner_applicability": "APPLICABLE",
        "scope_limit": "offline scanners classify their supported lockfile formats from private admitted-byte copies; staging closes input TOCTOU but does not prove network isolation or full process containment; ordinary vulnerabilities remain audit risk and admission is not a dependency-safety proof",
        "run_id": compat_session.run_id,
        "project_root": str(compat_session.project_root),
        "scan_root": str(root),
        "session_binding_sha256": compat_session.session_binding_sha256,
        "input_denominator": compat_inputs.rows,
        "input_denominator_sha256": _canonical_sha(compat_inputs.rows),
        "lockfile_count": len(lockfiles),
        "scanner_evidence": tuple(scanner_evidence),
        "ordinary_vulnerability_count": ordinary_risk_count,
    }
    return _issue_admission(posix_compat_session, projection)
