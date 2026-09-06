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
  by this module itself (``osv-scanner --offline`` / ``npm audit --offline`` /
  ``cargo audit --no-fetch`` are mechanically no-fetch).
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
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from owned_process_runner import run_owned_process

log = logging.getLogger("plamen.supply_chain_gate")

__all__ = [
    "SupplyChainAbortError",
    "gate_supply_chain",
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
_SCANNER_BINARIES = ("osv-scanner", "npm", "cargo-audit")
_LOCKFILE_SCANNERS = {
    "package-lock.json": ("osv-scanner", "npm"),
    "npm-shrinkwrap.json": ("npm",),
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


def _call_offline_scanner(binary: str, lockfile: Path) -> OfflineScanResult:
    """Run a no-fetch scanner and return a typed transport/schema result."""
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
        cmd = [
            executable, "audit", "--json", "--offline",
            "--prefix", str(lockfile.parent),
        ]
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


def _install_script_heuristic_hit(root: Path) -> Optional[str]:
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
        except OSError:
            continue
        if _BASE64_EVAL_RE.search(text):
            return f"base64/eval obfuscation chain in {name}"
        has_install_hook = any(f'"{k}"' in text for k in _INSTALL_SCRIPT_KEYS)
        if has_install_hook and "base64" in text.lower() and (
            "eval(" in text or "Function(" in text
        ):
            return f"install-script hook + base64/eval in {name}"
    return None


def gate_supply_chain(root: Path, *, denylist: Optional[Sequence[str]] = None) -> None:
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
    if os.environ.get("PLAMEN_SKIP_SUPPLY_CHAIN_GATE") == "1":
        log.warning("supply_chain_gate: SKIPPED via PLAMEN_SKIP_SUPPLY_CHAIN_GATE=1 "
                     "for %s", root)
        return

    active_denylist = tuple(denylist) if denylist is not None else tuple(DEFAULT_IOC_DENYLIST)
    root = Path(root)
    lockfiles = _find_lockfiles(root)

    # --- Signal 1: append-only IoC denylist (no binary required) ----------
    for lf in lockfiles:
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
    heuristic_hit = _install_script_heuristic_hit(root)
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
        return

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
            result = _call_offline_scanner(binary, lf)
            # Compatibility for the historical private fixture seam.
            if isinstance(result, str):
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
