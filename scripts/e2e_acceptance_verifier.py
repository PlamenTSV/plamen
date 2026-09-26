#!/usr/bin/env python3
"""Fail-closed, read-only acceptance check for a strict V3 SC Thorough audit.

The expected-identity document is trusted operator input.  Audit artifacts are
not allowed to assert their own package, source, or target identities.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import audit_completion_receipt as completion_authority


EXPECTED_SC_THOROUGH_PHASES = (
    "recon", "instantiate", "breadth", "rescan_prepare", "rescan",
    "inventory_prepare", "inventory_chunk_a", "inventory_chunk_b",
    "inventory_chunk_c", "inventory", "invariants", "invariants_p2",
    "depth", "attention_repair", "exploration_skeptic",
    "enumgap_exploration", "axis_coverage", "application_skeptic",
    "sc_semantic_dedup", "rag_sweep", "chain", "chain_agent2",
    "chain_iter2", "sc_verify_queue", "sc_verify_crithigh",
    "sc_verify_high_b", "sc_verify_high_c", "sc_verify_high_d",
    "sc_verify_high_e", "sc_verify_high_f", "sc_verify_high_g",
    "sc_verify_high_h", "sc_verify_high_i", "sc_verify_high_j",
    "sc_verify_medium_a", "sc_verify_medium_b", "sc_verify_medium_c",
    "sc_verify_medium_d", "sc_verify_medium_e", "sc_verify_medium_f",
    "sc_verify_medium_g", "sc_verify_medium_h", "sc_verify_medium_i",
    "sc_verify_medium_j", "sc_verify_low_a", "sc_verify_low_b",
    "sc_verify_low_c", "sc_verify_low_d", "sc_verify_low_e",
    "sc_verify_low_f", "sc_verify_low_g", "sc_verify_low_h",
    "sc_verify_low_i", "sc_verify_low_j", "sc_verify_aggregate",
    "sc_mechanical_verify", "post_verify_extract", "skeptic", "crossbatch",
    "severity_adjudication_shadow", "report_index",
    "report_body_writer_critical_high", "report_body_writer_medium",
    "report_body_writer_low_info", "report_critical_high",
    "report_critical_high_merge", "report_medium", "report_medium_merge",
    "report_low_info", "report_low_info_merge", "report_assemble",
    "report_dedup_agent", "report_dedup", "report_disposition",
    "report_floor",
)

IDENTITY_SCHEMA = "plamen.strict_sc_thorough_acceptance_identity.v1"
VERDICT_SCHEMA = "plamen.strict_sc_thorough_acceptance_verdict.v1"
LEGACY_DRIVER_TERMINAL_SCHEMA = completion_authority.LEGACY_DRIVER_TERMINAL_SCHEMA
DRIVER_TERMINAL_SCHEMA = completion_authority.DRIVER_TERMINAL_SCHEMA
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_BAD_STATUS = re.compile(
    r"(?:DEBT|DEGRADED|FAIL|ERROR|INCOMPLETE|UNRESOLVED|UNAVAILABLE|ARMED|PENDING)"
)
_SUCCESS_STATUS = frozenset(
    {
        "CLEAN", "CLEARED", "CLOSED", "COMPLETE", "COMPLETED", "FINISHED",
        "NOT_REQUIRED", "RESOLVED", "SUCCESS", "SUCCEEDED",
    }
)
_MAX_JSON = 32 * 1024 * 1024
_RUNTIME_CONFIG_KEYS = frozenset({"scratchpad", "fresh", "fresh_restart", "resume", "hibernate"})


@dataclass(frozen=True)
class AcceptanceIssue:
    code: str
    detail: str


@dataclass(frozen=True)
class AcceptanceVerdict:
    accepted: bool
    issues: tuple[AcceptanceIssue, ...]
    run_id: str
    report_sha256: str
    bindings: tuple[tuple[str, str], ...]
    evidence_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "bindings": dict(self.bindings),
            "evidence_sha256": self.evidence_sha256,
            "issues": [{"code": row.code, "detail": row.detail} for row in self.issues],
            "report_sha256": self.report_sha256,
            "run_id": self.run_id,
            "schema_version": VERDICT_SCHEMA,
        }


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, limit: int = _MAX_JSON) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError("not a regular non-symlink file")
    if info.st_size > limit:
        raise ValueError(f"file exceeds {limit} bytes")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("file identity changed before read")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ValueError(f"file exceeds {limit} bytes")
        finished = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    data = b"".join(chunks)
    if (
        len(data) != opened.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)
    ):
        raise ValueError("file changed while being read")
    return data


def _read_json(path: Path) -> Mapping[str, Any]:
    raw = _read_regular(path)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    if not isinstance(value, dict):
        raise ValueError("JSON root is not an object")
    return value


def _semantic_config(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in config.items()
        if not key.startswith("_") and key not in _RUNTIME_CONFIG_KEYS
    }


def _real(path: Path) -> str:
    return str(path.resolve(strict=True))


def _git_head(root: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        raise ValueError("git HEAD is unavailable")
    value = proc.stdout.strip().lower()
    if not _COMMIT.fullmatch(value):
        raise ValueError("git returned a non-canonical commit")
    return value


def _git_tracked_clean(root: Path, scope: Path | None = None) -> bool:
    arguments = ["."]
    if scope is not None:
        arguments = [scope.resolve().relative_to(root.resolve()).as_posix()]
    for cached in (False, True):
        command = ["git", "-C", str(root), "diff", "--quiet"]
        if cached:
            command.append("--cached")
        command.extend(["HEAD", "--", *arguments])
        proc = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        if proc.returncode != 0:
            return False
    return True


def _issue(issues: list[AcceptanceIssue], code: str, detail: str) -> None:
    issues.append(AcceptanceIssue(code, detail[:500]))


def _expect_hex(value: Any, *, commit: bool = False) -> bool:
    return isinstance(value, str) and bool((_COMMIT if commit else _HEX64).fullmatch(value))


def _load_required(
    path: Path, code: str, issues: list[AcceptanceIssue]
) -> Mapping[str, Any] | None:
    try:
        return _read_json(path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        _issue(issues, code, f"{path.name}: {exc}")
        return None


def _validate_identity(
    identity: Mapping[str, Any],
    scratchpad: Path,
    project: Path,
    snapshot: Mapping[str, Any] | None,
    issues: list[AcceptanceIssue],
) -> None:
    exact = {
        "schema_version", "run_id", "installed_package_root",
        "installed_package_receipt", "installed_package_receipt_sha256",
        "installed_generation_receipt", "installed_generation_receipt_sha256",
        "installed_package_generation_sha256", "plamen_source_root",
        "plamen_source_commit", "target_repository_root", "target_commit",
        "audit_snapshot_digest", "methodology_digest", "toolchain_digest",
    }
    if set(identity) != exact:
        _issue(issues, "IDENTITY_SCHEMA_INVALID", "identity keys are not exact")
        return
    if identity.get("schema_version") != IDENTITY_SCHEMA:
        _issue(issues, "IDENTITY_SCHEMA_INVALID", "unexpected schema_version")
    if not _UUID4.fullmatch(str(identity.get("run_id", ""))):
        _issue(issues, "IDENTITY_RUN_ID_INVALID", "run_id is not canonical UUID4")
    for field in (
        "installed_package_receipt_sha256", "installed_generation_receipt_sha256",
        "installed_package_generation_sha256",
        "audit_snapshot_digest", "methodology_digest", "toolchain_digest",
    ):
        if not _expect_hex(identity.get(field)):
            _issue(issues, "IDENTITY_DIGEST_INVALID", field)
    for field in ("plamen_source_commit", "target_commit"):
        if not _expect_hex(identity.get(field), commit=True):
            _issue(issues, "IDENTITY_COMMIT_INVALID", field)

    try:
        installed = Path(str(identity["installed_package_root"])).resolve(strict=True)
        if not installed.is_dir() or installed.is_symlink():
            raise ValueError("installed root is not a real directory")
        receipt_path = Path(str(identity["installed_package_receipt"]))
        generation_path = Path(str(identity["installed_generation_receipt"]))
        if not receipt_path.is_absolute() or not generation_path.is_absolute():
            raise ValueError("receipt authority paths are not absolute")
        package_digest, generation_receipt_digest, generation = (
            completion_authority.validate_installed_authority(
                installed_root=installed,
                package_receipt_path=receipt_path,
                generation_receipt_path=generation_path,
            )
        )
        if package_digest != identity["installed_package_receipt_sha256"]:
            _issue(issues, "INSTALLED_RECEIPT_DIGEST_MISMATCH", str(receipt_path))
        if generation_receipt_digest != identity["installed_generation_receipt_sha256"]:
            _issue(issues, "INSTALLED_GENERATION_RECEIPT_MISMATCH", str(generation_path))
        if generation != identity["installed_package_generation_sha256"]:
            _issue(issues, "INSTALLED_GENERATION_MISMATCH", "receipt generation differs")
    except (
        OSError, UnicodeError, ValueError, json.JSONDecodeError, KeyError,
        completion_authority.CompletionReceiptError,
    ) as exc:
        _issue(issues, "INSTALLED_PACKAGE_IDENTITY_INVALID", str(exc))

    for root_field, commit_field, code in (
        ("plamen_source_root", "plamen_source_commit", "PLAMEN_SOURCE_COMMIT_MISMATCH"),
        ("target_repository_root", "target_commit", "TARGET_COMMIT_MISMATCH"),
    ):
        try:
            root = Path(str(identity[root_field])).resolve(strict=True)
            if not root.is_dir() or root.is_symlink():
                raise ValueError("repository root is not a real directory")
            observed = _git_head(root)
            if observed != identity[commit_field]:
                _issue(issues, code, f"expected {identity[commit_field]}, observed {observed}")
            scope = project if root_field == "target_repository_root" else None
            if not _git_tracked_clean(root, scope):
                _issue(issues, code, "tracked or staged content is not frozen at expected commit")
        except (OSError, ValueError, KeyError) as exc:
            _issue(issues, code, str(exc))

    if snapshot is not None:
        components = snapshot.get("components")
        if not isinstance(components, dict):
            components = {}
        comparisons = (
            ("snapshot_digest", "audit_snapshot_digest", "AUDIT_SNAPSHOT_IDENTITY_MISMATCH"),
            ("methodology", "methodology_digest", "METHODOLOGY_IDENTITY_MISMATCH"),
            ("toolchain", "toolchain_digest", "TOOLCHAIN_IDENTITY_MISMATCH"),
        )
        for component, expected_field, code in comparisons:
            observed = snapshot.get(component) if component == "snapshot_digest" else components.get(component)
            if isinstance(observed, dict):
                observed = observed.get("digest")
            if observed != identity.get(expected_field):
                _issue(issues, code, f"checkpoint does not bind {expected_field}")
        source = components.get("source_scope")
        if not isinstance(source, dict) or source.get("git_head") != identity.get("target_commit"):
            _issue(issues, "TARGET_SNAPSHOT_COMMIT_MISMATCH", "source snapshot does not bind target commit")

    try:
        if _real(scratchpad) != _real(project / ".scratchpad"):
            _issue(issues, "SCRATCHPAD_PROJECT_MISMATCH", "scratchpad is not project/.scratchpad")
    except (OSError, ValueError) as exc:
        _issue(issues, "SCRATCHPAD_PROJECT_MISMATCH", str(exc))


def _validate_phase_state(checkpoint: Mapping[str, Any], issues: list[AcceptanceIssue]) -> None:
    config = checkpoint.get("config")
    try:
        expected = list(
            completion_authority.realized_phase_plan_from_checkpoint(checkpoint)
        )
    except completion_authority.CompletionReceiptError as exc:
        active = config.get("_active_phase_names") if isinstance(config, dict) else None
        expected = list(active) if isinstance(active, list) else []
        _issue(issues, "PHASE_PLAN_NOT_EXACT", str(exc))
        if checkpoint.get("completed") != expected:
            _issue(
                issues, "TERMINAL_EXIT_NOT_PROVEN",
                "completed phase list differs from the realized phase plan",
            )
    commits = checkpoint.get("phase_commits")
    if not isinstance(commits, dict) or set(commits) != set(expected):
        _issue(issues, "PHASE_COMMITS_INCOMPLETE", "phase commit keyset is not exact")
        commits = commits if isinstance(commits, dict) else {}
    run_id = checkpoint.get("run_id")
    commit_keys = {
        "phase_name", "state", "run_id", "work_unit_id", "contract_digest",
        "launch_digest", "artifact_digest", "unresolved_failures",
        "clearance_events", "committed_at",
    }
    for phase in expected:
        row = commits.get(phase)
        if not isinstance(row, dict):
            continue
        if set(row) != commit_keys or row.get("phase_name") != phase or row.get("run_id") != run_id:
            _issue(issues, "PHASE_COMMIT_INVALID", phase)
            continue
        if row.get("state") != "CLEAN" or row.get("unresolved_failures") != []:
            _issue(issues, "PHASE_COMMIT_NOT_CLEAN", phase)
        if row.get("work_unit_id") != "phase":
            _issue(issues, "PHASE_COMMIT_INVALID", f"{phase}: work_unit_id")
        for field in ("contract_digest", "launch_digest", "artifact_digest"):
            if not _expect_hex(row.get(field)):
                _issue(issues, "PHASE_COMMIT_INVALID", f"{phase}: {field}")
    degraded = checkpoint.get("degraded")
    if degraded != []:
        _issue(issues, "DEGRADATION_REMAINS", "checkpoint degraded list is not empty")
    if checkpoint.get("runtime_debts") != {}:
        _issue(issues, "RUNTIME_DEBT_REMAINS", "checkpoint runtime_debts is not empty")
    if checkpoint.get("rate_limited_at") is not None:
        _issue(issues, "RATE_LIMIT_STATE_REMAINS", "rate_limited_at is not null")
    if isinstance(config, dict):
        for field in ("_active_model_attempts", "_phase_io_model_attempts"):
            attempts = config.get(field, {})
            if not isinstance(attempts, dict):
                _issue(issues, "RETRY_STATE_INVALID", field)
                continue
            bad = [key for key, value in attempts.items() if type(value) is not int or value != 1]
            if bad:
                _issue(issues, "RETRY_REMAINS", f"{field}: {','.join(sorted(map(str, bad)))}")


def _validate_snapshot_and_config(
    checkpoint: Mapping[str, Any], external: Mapping[str, Any], project: Path,
    scratchpad: Path, issues: list[AcceptanceIssue]
) -> Mapping[str, Any] | None:
    snapshot = checkpoint.get("audit_snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("schema") != "plamen.audit-input-snapshot.v1":
        _issue(issues, "AUDIT_SNAPSHOT_INVALID", "missing or wrong schema")
        return None
    digest = snapshot.get("snapshot_digest")
    body = dict(snapshot)
    body.pop("snapshot_digest", None)
    if not _expect_hex(digest) or _sha256(_canonical(body)) != digest:
        _issue(issues, "AUDIT_SNAPSHOT_DIGEST_INVALID", "snapshot self-digest does not verify")
    if external.get("pipeline") != "sc" or external.get("mode") != "thorough":
        _issue(issues, "CONFIG_MODE_INVALID", "expected pipeline=sc and mode=thorough")
    internal = checkpoint.get("config")
    if not isinstance(internal, dict) or _semantic_config(internal) != _semantic_config(external):
        _issue(issues, "CONFIG_CHECKPOINT_MISMATCH", "semantic config differs from checkpoint")
    components = snapshot.get("components")
    if not isinstance(components, dict):
        _issue(issues, "AUDIT_SNAPSHOT_INVALID", "components is not an object")
        components = {}
    audit_config = components.get("audit_config")
    expected_config = _semantic_config(external)
    if (
        not isinstance(audit_config, dict)
        or audit_config.get("digest") != _sha256(_canonical(expected_config))
        or audit_config.get("field_count") != len(expected_config)
    ):
        _issue(issues, "CONFIG_SNAPSHOT_MISMATCH", "audit_config binding is invalid")
    try:
        if _real(Path(str(external.get("project_root")))) != _real(project):
            _issue(issues, "CONFIG_PROJECT_MISMATCH", "project_root differs")
        if _real(Path(str(external.get("scratchpad")))) != _real(scratchpad):
            _issue(issues, "CONFIG_SCRATCHPAD_MISMATCH", "scratchpad differs")
    except (OSError, ValueError) as exc:
        _issue(issues, "CONFIG_PATH_INVALID", str(exc))
    return snapshot


def _typed_schema(obj: Mapping[str, Any]) -> str:
    value = obj.get("schema_version", obj.get("schema", ""))
    return value.lower() if isinstance(value, str) else ""


def _scan_residual_state(scratchpad: Path, issues: list[AcceptanceIssue]) -> None:
    try:
        entries = list(scratchpad.iterdir())
    except OSError as exc:
        _issue(issues, "SCRATCHPAD_SCAN_FAILED", str(exc))
        return
    for path in entries:
        name = path.name.lower()
        try:
            if name.endswith(".degraded"):
                _read_regular(path, 1024 * 1024)
                _issue(issues, "DEGRADATION_MARKER_REMAINS", path.name)
            if re.search(r"(?:attempt|retry)[._-]?[2-9][0-9]*", name):
                _read_regular(path, _MAX_JSON)
                _issue(issues, "RETRY_ARTIFACT_REMAINS", path.name)
        except (OSError, ValueError) as exc:
            _issue(issues, "RESIDUAL_ARTIFACT_INVALID", f"{path.name}: {exc}")

    ledger = scratchpad / "phase_completion_debt.md"
    try:
        if ledger.exists():
            text = _read_regular(ledger, 8 * 1024 * 1024).decode("utf-8")
            rows = [line for line in text.splitlines() if line.startswith("|")]
            if len(rows) > 2:
                _issue(issues, "PHASE_DEBT_LEDGER_NOT_EMPTY", f"{len(rows) - 2} row(s)")
    except (OSError, UnicodeError, ValueError) as exc:
        _issue(issues, "PHASE_DEBT_LEDGER_INVALID", str(exc))

    for path in entries:
        name = path.name.lower()
        if (
            not name.endswith(".json")
            or ("debt" not in name and "obligation" not in name)
        ):
            continue
        obj = _load_required(path, "TYPED_RESIDUAL_ARTIFACT_INVALID", issues)
        if obj is None:
            continue
        schema = _typed_schema(obj)
        if "debt" in schema:
            recognized = False
            for key in (
                "count", "debt_count", "unresolved_count", "blocking_debt_count",
                "blocking_count", "active_count",
            ):
                if key in obj:
                    recognized = True
                    value = obj.get(key)
                    if type(value) is not int or value != 0:
                        _issue(issues, "DEBT_ARTIFACT_REMAINS", f"{path.name}: {key}={value!r}")
            for key in ("status", "state", "report_disposition", "source_authority_status"):
                if key in obj:
                    recognized = True
                    value = obj.get(key)
                    if not isinstance(value, str) or value.upper() not in _SUCCESS_STATUS:
                        _issue(issues, "DEBT_ARTIFACT_REMAINS", f"{path.name}: {key}={value!r}")
            for key in ("clean_authority", "publication_eligible", "report_authoritative"):
                if key in obj:
                    recognized = True
                    if obj.get(key) is not True:
                        _issue(issues, "DEBT_ARTIFACT_REMAINS", f"{path.name}: {key} is not true")
            if not recognized:
                _issue(issues, "DEBT_ARTIFACT_UNCLASSIFIED", f"{path.name}: {schema}")
        if "obligation" in schema:
            for key in ("active_count", "unresolved_count", "blocking_count", "debt_count"):
                value = obj.get(key)
                if value is not None and (type(value) is not int or value != 0):
                    _issue(issues, "UNRESOLVED_OBLIGATION_REMAINS", f"{path.name}: {key}={value!r}")
            for key in ("status", "authority_status", "source_authority_status", "report_disposition"):
                value = obj.get(key)
                if isinstance(value, str) and _BAD_STATUS.search(value.upper()):
                    _issue(issues, "UNRESOLVED_OBLIGATION_REMAINS", f"{path.name}: {key}={value}")

    candidates = [
        path for path in entries
        if path.name.lower().endswith(".json")
        and (
            "repair_attempt" in path.name.lower()
            or "repair_execution_receipt" in path.name.lower()
            or "repair_provider_outcome" in path.name.lower()
            or "repair_result" in path.name.lower()
        )
    ]
    for path in candidates:
        obj = _load_required(path, "REPAIR_ARTIFACT_INVALID", issues)
        if obj is None:
            continue
        statuses = {
            key: obj[key]
            for key in ("status", "state", "provider_status", "terminal_status")
            if key in obj
        }
        if not statuses:
            _issue(issues, "REPAIR_PROVIDER_FAILURE_REMAINS", f"{path.name}: no terminal status")
        for key, status in statuses.items():
            if not isinstance(status, str) or status.upper() not in _SUCCESS_STATUS:
                _issue(issues, "REPAIR_PROVIDER_FAILURE_REMAINS", f"{path.name}: {key}={status!r}")
        code = obj.get("return_code", 0)
        if type(code) is not int or code != 0:
            _issue(issues, "REPAIR_PROVIDER_FAILURE_REMAINS", f"{path.name}: return_code={code!r}")
        if obj.get("issues") not in (None, []):
            _issue(issues, "REPAIR_PROVIDER_FAILURE_REMAINS", f"{path.name}: issues")
        if obj.get("failure_code") not in (None, ""):
            _issue(issues, "REPAIR_PROVIDER_FAILURE_REMAINS", f"{path.name}: failure_code")


def _validate_obligation_ledger(scratchpad: Path, issues: list[AcceptanceIssue]) -> None:
    ledger = _load_required(scratchpad / "obligation_ledger.json", "OBLIGATION_LEDGER_INVALID", issues)
    if ledger is None:
        return
    if set(ledger) != {"schema_version", "active_count", "mode", "obligations", "row_count"}:
        _issue(issues, "OBLIGATION_LEDGER_INVALID", "keys are not exact")
        return
    rows = ledger.get("obligations")
    if not isinstance(rows, list):
        _issue(issues, "OBLIGATION_LEDGER_INVALID", "obligations is not a list")
        return
    active = sum(
        1 for row in rows
        if isinstance(row, dict) and str(row.get("status", "")).lower() == "active"
    )
    if (
        ledger.get("schema_version") != "plamen.obligation_ledger.v1"
        or ledger.get("mode") != "thorough"
        or type(ledger.get("row_count")) is not int
        or ledger.get("row_count") != len(rows)
        or type(ledger.get("active_count")) is not int
        or ledger.get("active_count") != active
        or active != 0
    ):
        _issue(issues, "UNRESOLVED_OBLIGATION_REMAINS", "canonical obligation counts do not close")
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or str(row.get("status", "")).lower() not in {"covered", "retained"}:
            _issue(issues, "UNRESOLVED_OBLIGATION_REMAINS", f"row {index} is not covered/retained")


def _validate_driver_terminal_receipt(
    *, scratchpad: Path, checkpoint_path: Path, report_path: Path,
    checkpoint: Mapping[str, Any] | None, identity: Mapping[str, Any] | None,
    report_sha256: str, issues: list[AcceptanceIssue],
) -> str:
    receipt = _load_required(
        scratchpad / "_driver_terminal_receipt.json",
        "DRIVER_TERMINAL_RECEIPT_MISSING_OR_INVALID",
        issues,
    )
    if receipt is None:
        return ""
    schema = receipt.get("schema_version")
    if schema == LEGACY_DRIVER_TERMINAL_SCHEMA:
        _issue(
            issues,
            "LEGACY_DRIVER_TERMINAL_RECEIPT_NON_ACCEPTING",
            "v1 terminal receipts do not authenticate V3 semantic closure",
        )
        return str(receipt.get("receipt_sha256") or "")
    exact = {
        "schema_version", "run_id", "pipeline", "mode", "exit_code",
        "phase_count", "realized_phase_plan_sha256", "checkpoint_sha256",
        "report_sha256", "audit_snapshot_digest", "plamen_source_commit",
        "installed_package_receipt_sha256", "installed_generation_receipt_sha256",
        "installed_package_generation_sha256",
        "target_commit", "terminal_closure", "completed_at", "receipt_sha256",
    }
    unsigned = dict(receipt)
    claimed_digest = unsigned.pop("receipt_sha256", None)
    if set(receipt) != exact or receipt.get("schema_version") != DRIVER_TERMINAL_SCHEMA:
        _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", "keys or schema are not exact")
    if not _expect_hex(claimed_digest) or _sha256(_canonical(unsigned)) != claimed_digest:
        _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", "self-digest does not verify")
    try:
        checkpoint_sha = _sha256(_read_regular(checkpoint_path))
        current_report_sha = _sha256(_read_regular(report_path, 64 * 1024 * 1024))
    except (OSError, ValueError) as exc:
        _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", f"bound artifact unreadable: {exc}")
        return str(claimed_digest or "")
    snapshot = checkpoint.get("audit_snapshot") if isinstance(checkpoint, dict) else None
    realized_phases: tuple[str, ...] = ()
    try:
        realized_phases = completion_authority.realized_phase_plan_from_checkpoint(
            checkpoint if isinstance(checkpoint, Mapping) else {}
        )
    except completion_authority.CompletionReceiptError as exc:
        _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", str(exc))
    expected = {
        "run_id": checkpoint.get("run_id") if isinstance(checkpoint, dict) else None,
        "pipeline": "sc",
        "mode": "thorough",
        "exit_code": 0,
        "phase_count": len(realized_phases),
        "realized_phase_plan_sha256": completion_authority.phase_names_sha256(
            realized_phases
        ) if realized_phases else "",
        "checkpoint_sha256": checkpoint_sha,
        "report_sha256": report_sha256,
        "audit_snapshot_digest": snapshot.get("snapshot_digest") if isinstance(snapshot, dict) else None,
        "plamen_source_commit": identity.get("plamen_source_commit") if identity else None,
        "installed_package_receipt_sha256": identity.get("installed_package_receipt_sha256") if identity else None,
        "installed_generation_receipt_sha256": identity.get("installed_generation_receipt_sha256") if identity else None,
        "installed_package_generation_sha256": identity.get("installed_package_generation_sha256") if identity else None,
        "target_commit": identity.get("target_commit") if identity else None,
    }
    if current_report_sha != report_sha256:
        _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", "report changed during terminal validation")
    for key, value in expected.items():
        if receipt.get(key) != value:
            _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", f"{key} binding differs")
    claimed_closure = receipt.get("terminal_closure")
    try:
        completion_authority.validate_terminal_closure(
            claimed_closure if isinstance(claimed_closure, Mapping) else {}
        )
        if checkpoint is None:
            raise completion_authority.CompletionReceiptError(
                "checkpoint is unavailable for terminal closure replay"
            )
        recomputed_closure = completion_authority.recompute_terminal_closure(
            scratchpad=scratchpad,
            project_root=report_path.parent,
            checkpoint=checkpoint,
        )
        if dict(claimed_closure) != recomputed_closure:
            raise completion_authority.CompletionReceiptError(
                "terminal closure differs from independent replay"
            )
    except completion_authority.CompletionReceiptError as exc:
        _issue(issues, "TERMINAL_CLOSURE_INVALID", str(exc))
    if not isinstance(receipt.get("completed_at"), str) or not receipt.get("completed_at"):
        _issue(issues, "DRIVER_TERMINAL_RECEIPT_INVALID", "completed_at is absent")
    return str(claimed_digest or "")


def verify_sc_thorough_e2e(
    *, scratchpad: Path, config_path: Path, project_root: Path,
    expected_identity_path: Path,
) -> AcceptanceVerdict:
    """Validate immutable evidence without changing or launching anything."""
    issues: list[AcceptanceIssue] = []
    try:
        scratchpad = scratchpad.resolve(strict=True)
        project_root = project_root.resolve(strict=True)
        if not scratchpad.is_dir() or scratchpad.is_symlink():
            raise ValueError("scratchpad is not a real directory")
        if not project_root.is_dir() or project_root.is_symlink():
            raise ValueError("project is not a real directory")
    except (OSError, ValueError) as exc:
        return AcceptanceVerdict(False, (AcceptanceIssue("INPUT_PATH_INVALID", str(exc)),), "", "", (), "")

    checkpoint = _load_required(scratchpad / "_v2_checkpoint.json", "CHECKPOINT_INVALID", issues)
    external = _load_required(config_path, "CONFIG_INVALID", issues)
    identity = _load_required(expected_identity_path, "IDENTITY_INVALID", issues)
    marker = _load_required(scratchpad / "_audit_started_with_markers.json", "START_MARKER_INVALID", issues)
    snapshot: Mapping[str, Any] | None = None
    run_id = ""
    if checkpoint is not None:
        run_id = str(checkpoint.get("run_id", ""))
        expected_checkpoint_keys = {
            "audit_snapshot", "completed", "config", "degraded", "phase_commits",
            "rate_limited_at", "run_id", "runtime_debts", "semantic_mutation_acks",
        }
        if set(checkpoint) != expected_checkpoint_keys:
            _issue(issues, "CHECKPOINT_SCHEMA_INVALID", "checkpoint keys are not exact")
        if not _UUID4.fullmatch(run_id):
            _issue(issues, "CHECKPOINT_RUN_ID_INVALID", run_id)
        _validate_phase_state(checkpoint, issues)
        if external is not None:
            snapshot = _validate_snapshot_and_config(checkpoint, external, project_root, scratchpad, issues)
    if marker is not None:
        marker_keys = {"schema_version", "started_at", "driver_version", "mode", "pipeline"}
        if (
            set(marker) != marker_keys
            or marker.get("schema_version") != 1
            or marker.get("pipeline") != "sc"
            or marker.get("mode") != "thorough"
            or not isinstance(marker.get("started_at"), str)
            or not isinstance(marker.get("driver_version"), str)
        ):
            _issue(issues, "START_MARKER_INVALID", "not SC Thorough")
    if identity is not None:
        if run_id and identity.get("run_id") != run_id:
            _issue(issues, "RUN_IDENTITY_MISMATCH", "identity and checkpoint run_id differ")
        _validate_identity(identity, scratchpad, project_root, snapshot, issues)

    report_sha = ""
    report_path = project_root / "AUDIT_REPORT.md"
    try:
        report_raw = _read_regular(report_path, 64 * 1024 * 1024)
        if not report_raw.strip():
            raise ValueError("report is empty")
        report_sha = _sha256(report_raw)
    except (OSError, ValueError) as exc:
        _issue(issues, "TERMINAL_REPORT_INVALID", str(exc))
    terminal_receipt_sha = _validate_driver_terminal_receipt(
        scratchpad=scratchpad,
        checkpoint_path=scratchpad / "_v2_checkpoint.json",
        report_path=report_path,
        checkpoint=checkpoint,
        identity=identity,
        report_sha256=report_sha,
        issues=issues,
    )
    _validate_obligation_ledger(scratchpad, issues)
    _scan_residual_state(scratchpad, issues)

    issues = sorted(set(issues), key=lambda row: (row.code, row.detail))
    bindings = {
        "audit_snapshot": str(snapshot.get("snapshot_digest", "")) if snapshot else "",
        "checkpoint": _sha256(_canonical(checkpoint)) if checkpoint is not None else "",
        "config": _sha256(_canonical(external)) if external is not None else "",
        "driver_terminal_receipt": terminal_receipt_sha,
        "expected_identity": _sha256(_canonical(identity)) if identity is not None else "",
        "installed_package_receipt": str(identity.get("installed_package_receipt_sha256", "")) if identity else "",
        "installed_generation_receipt": str(identity.get("installed_generation_receipt_sha256", "")) if identity else "",
        "plamen_source_commit": str(identity.get("plamen_source_commit", "")) if identity else "",
        "report": report_sha,
        "target_commit": str(identity.get("target_commit", "")) if identity else "",
    }
    evidence = {
        "accepted": not issues,
        "bindings": bindings,
        "issue_codes": [row.code for row in issues],
        "report_sha256": report_sha,
        "run_id": run_id,
        "phase_count": len(
            checkpoint.get("completed", [])
            if isinstance(checkpoint, Mapping) else []
        ),
        "snapshot_digest": snapshot.get("snapshot_digest", "") if snapshot else "",
    }
    return AcceptanceVerdict(
        not issues, tuple(issues), run_id, report_sha,
        tuple(sorted(bindings.items())), _sha256(_canonical(evidence)),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratchpad", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--expected-identity", required=True, type=Path)
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    verdict = verify_sc_thorough_e2e(
        scratchpad=args.scratchpad,
        config_path=args.config,
        project_root=args.project,
        expected_identity_path=args.expected_identity,
    )
    print(json.dumps(verdict.as_dict(), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0 if verdict.accepted else 1


if __name__ == "__main__":
    sys.exit(main())
