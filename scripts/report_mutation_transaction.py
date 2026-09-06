"""Durable single-report mutation transaction used by Python report phases.

The canonical report is the only delivery object in this transaction.  Every
candidate/mapping projection is made durable before the atomic canonical
replace.  The transaction deliberately retains its preimage and payloads after
commit so a later integrity review can reproduce both sides of the mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Callable, Mapping, Sequence


SCHEMA = "plamen.report_mutation_transaction.v1"
RECEIPT_SCHEMA = "plamen.report_mutation_transaction_receipt.v1"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ReportMutationTransactionError(RuntimeError):
    """The open report transaction cannot be recovered without ambiguity."""


@dataclass(frozen=True)
class ReportMutationResult:
    phase: str
    run_id: str
    recovered: bool
    changed: bool
    pre_report_sha256: str
    post_report_sha256: str
    receipt_sha256: str


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fsync_parent(path: Path) -> None:
    """Persist directory metadata where the host exposes directory fsync."""
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_bytes(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_parent(path)
    finally:
        temporary.unlink(missing_ok=True)


def _exclusive_bytes(path: Path, raw: bytes, *, label: str) -> None:
    """Publish complete bytes once; never expose or overwrite a partial file.

    ``O_EXCL`` on the destination prevents overwrite but still exposes the
    destination name while its contents are being streamed.  A killed process
    can therefore leave a truncated object at the transaction's immutable
    control path.  Write and fsync a private sibling first, then publish it via
    an atomic hard-link create.  ``os.link`` has create-if-absent semantics on
    both supported host families; a racing/existing destination is accepted
    only when it is already byte-identical.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".immutable.tmp", dir=str(path.parent)
    )
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            try:
                current = path.read_bytes()
            except OSError as exc:
                raise ReportMutationTransactionError(
                    f"{label} exists but is unreadable: {exc}"
                ) from exc
            if current != raw:
                raise ReportMutationTransactionError(
                    f"{label} already exists with non-matching bytes"
                )
            return
        _fsync_parent(path)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_relative(value: str) -> str:
    normalized = str(value or "").replace("\\", "/").strip()
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or normalized.startswith("/")
    ):
        raise ReportMutationTransactionError(
            f"report transaction path is not a safe relative path: {value!r}"
        )
    return path.as_posix()


def _regular_path(root: Path, relative: str, *, allow_missing: bool) -> Path:
    normalized = _safe_relative(relative)
    path = root / normalized
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=False)
    except OSError as exc:
        raise ReportMutationTransactionError(
            f"report transaction path cannot be resolved: {relative}: {exc}"
        ) from exc
    if not resolved_path.is_relative_to(resolved_root):
        raise ReportMutationTransactionError(
            f"report transaction path escapes its scratchpad: {relative}"
        )
    cursor = root
    if cursor.is_symlink():
        raise ReportMutationTransactionError(
            "report transaction refuses a symlink scratchpad"
        )
    for part in PurePosixPath(normalized).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ReportMutationTransactionError(
                f"report transaction refuses symlink path component: {relative}"
            )
    if path.exists() and not path.is_file():
        raise ReportMutationTransactionError(
            f"report transaction path is not a regular file: {relative}"
        )
    if not allow_missing and not path.is_file():
        raise ReportMutationTransactionError(
            f"report transaction input is missing: {relative}"
        )
    return path


def _input_rows(root: Path, relatives: Sequence[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for relative in sorted({_safe_relative(item) for item in relatives}):
        path = _regular_path(root, relative, allow_missing=True)
        if not path.is_file():
            rows.append({"path": relative, "present": False})
            continue
        raw = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "present": True,
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
        )
    return rows


def capture_report_transaction_inputs(
    scratchpad: Path, relatives: Sequence[str]
) -> tuple[dict[str, Any], ...]:
    """Freeze the exact present/absent source denominator before computation."""
    return tuple(_input_rows(Path(scratchpad), relatives))


def _validate_inputs(root: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    for row in rows:
        relative = _safe_relative(str(row.get("path") or ""))
        path = _regular_path(root, relative, allow_missing=True)
        present = path.is_file()
        if present != bool(row.get("present")):
            raise ReportMutationTransactionError(
                f"report transaction input presence changed: {relative}"
            )
        if not present:
            continue
        raw = path.read_bytes()
        if (
            row.get("sha256") != _sha(raw)
            or row.get("size_bytes") != len(raw)
        ):
            raise ReportMutationTransactionError(
                f"report transaction input changed: {relative}"
            )


def _signed_payload(unsigned: Mapping[str, Any], digest_key: str) -> dict[str, Any]:
    payload = dict(unsigned)
    payload[digest_key] = _sha(_canonical(unsigned))
    return payload


def _validate_signed(
    payload: Mapping[str, Any], *, digest_key: str, schema: str
) -> None:
    unsigned = dict(payload)
    recorded = unsigned.pop(digest_key, "")
    if payload.get("schema_version") != schema or not _HEX64.fullmatch(
        str(recorded)
    ) or recorded != _sha(_canonical(unsigned)):
        raise ReportMutationTransactionError(
            "report transaction manifest/receipt is stale or tampered"
        )


def _boundary(
    hook: Callable[[str], None] | None,
    name: str,
) -> None:
    if hook is not None:
        hook(name)


def _semantic_mutation_kind(phase_name: str) -> str:
    """Return the stable semantic-ledger identity for one report transaction."""

    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "_", phase_name).strip("._")
    if not normalized:
        raise ReportMutationTransactionError("report transaction phase is unsafe")
    return f"REPORT_TRANSACTION_{normalized}".upper()


def _report_semantic_mutation_event(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    phase_name: str,
    pre_sha256: str,
    pre_size: int,
    current_report: bytes,
) -> dict[str, Any]:
    """Reuse or durably arm the exact report transition before canonical write.

    A report transaction and its semantic-mutation event are one authority
    chain.  Recovery may encounter the canonical preimage or postimage, so it
    must reuse the original event rather than arm from whichever bytes happen
    to be live after a crash.
    """

    from artifact_ledger import (
        ArtifactLedgerError,
        arm_semantic_mutation,
        semantic_mutation_events,
    )

    kind = _semantic_mutation_kind(phase_name)
    try:
        matches = [
            row
            for row in semantic_mutation_events(scratchpad)
            if row.get("run_id") == run_id
            and row.get("mutation_kind") == kind
            and row.get("artifact_identity") == "project:AUDIT_REPORT.md"
        ]
    except ArtifactLedgerError as exc:
        raise ReportMutationTransactionError(
            f"report transaction semantic authority is unreadable: {exc}"
        ) from exc
    if len(matches) > 1:
        raise ReportMutationTransactionError(
            "report transaction semantic authority is ambiguous"
        )
    expected_before = {
        "status": "ACTIVE",
        "size": pre_size,
        "sha256": pre_sha256,
    }
    if matches:
        event = dict(matches[0])
        if event.get("before") != expected_before:
            raise ReportMutationTransactionError(
                "report transaction semantic preimage authority changed"
            )
        return event
    if _sha(current_report) != pre_sha256 or len(current_report) != pre_size:
        raise ReportMutationTransactionError(
            "report transaction has no pre-write semantic authority"
        )
    try:
        event = arm_semantic_mutation(
            scratchpad,
            project_root,
            artifact_identity="project:AUDIT_REPORT.md",
            mutation_kind=kind,
            run_id=run_id,
        )
    except ArtifactLedgerError as exc:
        raise ReportMutationTransactionError(
            f"report transaction semantic arm failed: {exc}"
        ) from exc
    if event.get("before") != expected_before:
        raise ReportMutationTransactionError(
            "report transaction semantic arm did not bind the exact preimage"
        )
    return event


def _finalize_report_semantic_mutation(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    event: Mapping[str, Any],
    post_sha256: str,
    post_size: int,
) -> None:
    """Finalize only the semantic event that reaches the committed postimage."""

    from artifact_ledger import ArtifactLedgerError, finalize_semantic_mutation

    try:
        finalized = finalize_semantic_mutation(
            scratchpad,
            project_root,
            str(event.get("event_id") or ""),
            run_id=run_id,
        )
    except ArtifactLedgerError as exc:
        raise ReportMutationTransactionError(
            f"report transaction semantic finalize failed: {exc}"
        ) from exc
    expected_after = {
        "status": "ACTIVE",
        "size": post_size,
        "sha256": post_sha256,
    }
    if finalized.get("after") != expected_after or finalized.get("status") not in {
        "NO_CHANGE",
        "INVALIDATION_APPLIED",
    }:
        raise ReportMutationTransactionError(
            "report transaction semantic successor does not match committed bytes"
        )


def apply_report_mutation_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    phase: str,
    post_report: bytes,
    exact_inputs: Sequence[str],
    sidecars: Mapping[str, bytes],
    expected_inputs: Sequence[Mapping[str, Any]] | None = None,
    fault_hook: Callable[[str], None] | None = None,
) -> ReportMutationResult:
    """Atomically apply or recover one exact report mutation.

    Recovery accepts only the exact pre-report or exact post-report.  An input,
    payload, public sidecar, run identity, or manifest mismatch is never
    repaired in place because doing so could erase the only forensic preimage.
    """
    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    phase_name = str(phase or "").strip()
    if not run or not phase_name:
        raise ReportMutationTransactionError(
            "report transaction requires non-empty run and phase identities"
        )
    report_path = project / "AUDIT_REPORT.md"
    if root.is_symlink() or not root.is_dir():
        raise ReportMutationTransactionError(
            "report transaction scratchpad is missing or a symlink"
        )
    if report_path.is_symlink() or not report_path.is_file():
        raise ReportMutationTransactionError(
            "canonical AUDIT_REPORT.md is missing, non-regular, or a symlink"
        )
    pre_now = report_path.read_bytes()
    post = bytes(post_report)
    post_sha = _sha(post)

    safe_sidecars: dict[str, bytes] = {}
    sidecar_sources: dict[str, str] = {}
    for relative, raw in sidecars.items():
        normalized = _safe_relative(relative)
        if normalized in safe_sidecars:
            raise ReportMutationTransactionError(
                "report transaction sidecar identity collision after path "
                f"normalization: {sidecar_sources[normalized]!r}, {relative!r}"
            )
        safe_sidecars[normalized] = bytes(raw)
        sidecar_sources[normalized] = str(relative)
    transaction_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", phase_name).strip("._")
    if not transaction_key:
        raise ReportMutationTransactionError("report transaction phase is unsafe")
    tx_dir = root / "_report_transactions" / transaction_key
    tx_parent = root / "_report_transactions"
    if tx_parent.exists() and (tx_parent.is_symlink() or not tx_parent.is_dir()):
        raise ReportMutationTransactionError(
            "report transaction root is not a regular directory"
        )
    if tx_dir.exists() and (tx_dir.is_symlink() or not tx_dir.is_dir()):
        raise ReportMutationTransactionError(
            "report transaction phase directory is not a regular directory"
        )
    manifest_path = tx_dir / "transaction.json"
    receipt_path = tx_dir / "receipt.json"
    backup_path = tx_dir / "AUDIT_REPORT.preimage"
    payload_dir = tx_dir / "payloads"
    for control in (manifest_path, receipt_path, backup_path):
        if control.is_symlink() or (control.exists() and not control.is_file()):
            raise ReportMutationTransactionError(
                f"report transaction control path is unsafe: {control.name}"
            )
    manifest_exists = manifest_path.is_file()
    recovered = manifest_exists or backup_path.exists() or payload_dir.exists()

    captured_inputs = (
        [dict(row) for row in expected_inputs]
        if expected_inputs is not None
        else _input_rows(root, exact_inputs)
    )
    if captured_inputs != _input_rows(root, exact_inputs):
        raise ReportMutationTransactionError(
            "report transaction input changed after its computation snapshot"
        )

    semantic_event: dict[str, Any]
    if manifest_exists:
        try:
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8", errors="strict")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReportMutationTransactionError(
                f"report transaction manifest is unreadable: {exc}"
            ) from exc
        _validate_signed(
            manifest, digest_key="transaction_sha256", schema=SCHEMA
        )
        if manifest.get("run_id") != run or manifest.get("phase") != phase_name:
            raise ReportMutationTransactionError(
                "report transaction run/phase identity changed"
            )
        if manifest.get("state") not in {"ARMED", "COMMITTED"}:
            raise ReportMutationTransactionError(
                "report transaction state is not recoverable"
            )
        if manifest.get("post_report_sha256") != post_sha or manifest.get(
            "post_report_size_bytes"
        ) != len(post):
            raise ReportMutationTransactionError(
                "report transaction intended post-report changed"
            )
        expected_rows = captured_inputs
        if manifest.get("inputs") != expected_rows:
            raise ReportMutationTransactionError(
                "report transaction exact input set changed"
            )
        _validate_inputs(root, manifest.get("inputs") or [])
        sidecar_rows = manifest.get("sidecars") or []
        expected_sidecar_rows = [
            {
                "path": relative,
                "payload": f"payloads/{index:04d}.bin",
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
            for index, (relative, raw) in enumerate(sorted(safe_sidecars.items()))
        ]
        if sidecar_rows != expected_sidecar_rows:
            raise ReportMutationTransactionError(
                "report transaction sidecar set changed"
            )
        pre_sha = str(manifest.get("pre_report_sha256") or "")
        pre_size = int(manifest.get("pre_report_size_bytes") or -1)
        if not backup_path.is_file():
            raise ReportMutationTransactionError(
                "report transaction preimage backup is unavailable"
            )
        backup = backup_path.read_bytes()
        if _sha(backup) != pre_sha or len(backup) != pre_size:
            raise ReportMutationTransactionError(
                "report transaction preimage backup is stale or tampered"
            )
        current_sha = _sha(pre_now)
        if current_sha not in {pre_sha, post_sha} or len(pre_now) not in {
            pre_size,
            len(post),
        }:
            raise ReportMutationTransactionError(
                "canonical report changed outside its armed transaction"
            )
        semantic_event = _report_semantic_mutation_event(
            scratchpad=root,
            project_root=project,
            run_id=run,
            phase_name=phase_name,
            pre_sha256=pre_sha,
            pre_size=pre_size,
            current_report=pre_now,
        )
    else:
        pre_sha = _sha(pre_now)
        pre_size = len(pre_now)
        semantic_event = _report_semantic_mutation_event(
            scratchpad=root,
            project_root=project,
            run_id=run,
            phase_name=phase_name,
            pre_sha256=pre_sha,
            pre_size=pre_size,
            current_report=pre_now,
        )
        _exclusive_bytes(backup_path, pre_now, label="report transaction preimage")
        _boundary(fault_hook, "BACKUP_DURABLE")
        input_rows = captured_inputs
        sidecar_rows = [
            {
                "path": relative,
                "payload": f"payloads/{index:04d}.bin",
                "sha256": _sha(raw),
                "size_bytes": len(raw),
            }
            for index, (relative, raw) in enumerate(sorted(safe_sidecars.items()))
        ]
        for row, (_, raw) in zip(sidecar_rows, sorted(safe_sidecars.items())):
            payload_path = _regular_path(
                tx_dir, str(row["payload"]), allow_missing=True
            )
            _exclusive_bytes(
                payload_path,
                raw,
                label=f"report transaction payload {row['path']}",
            )
        _boundary(fault_hook, "PAYLOADS_DURABLE")
        unsigned = {
            "schema_version": SCHEMA,
            "state": "ARMED",
            "run_id": run,
            "phase": phase_name,
            "report": "project:AUDIT_REPORT.md",
            "pre_report_sha256": pre_sha,
            "pre_report_size_bytes": pre_size,
            "post_report_sha256": post_sha,
            "post_report_size_bytes": len(post),
            "inputs": input_rows,
            "sidecars": sidecar_rows,
        }
        manifest = _signed_payload(unsigned, "transaction_sha256")
        _atomic_bytes(manifest_path, _canonical(manifest) + b"\n")
        _boundary(fault_hook, "ARMED_DURABLE")

    _validate_inputs(root, manifest.get("inputs") or [])

    # Validate payloads and public sidecars. Missing public sidecars are the
    # only recoverable state; non-matching bytes mean external mutation.
    for row in manifest.get("sidecars") or []:
        payload_path = _regular_path(
            tx_dir, str(row.get("payload") or ""), allow_missing=False
        )
        raw = payload_path.read_bytes()
        if row.get("sha256") != _sha(raw) or row.get("size_bytes") != len(raw):
            raise ReportMutationTransactionError(
                f"report transaction sidecar payload is tampered: {row.get('path')}"
            )
        public = _regular_path(root, str(row.get("path") or ""), allow_missing=True)
        if public.is_file():
            if public.read_bytes() != raw:
                raise ReportMutationTransactionError(
                    f"report transaction public sidecar changed: {row.get('path')}"
                )
        else:
            # Public projections are transaction-owned create-once objects.
            # Atomic no-overwrite publication prevents a concurrent producer
            # from being silently replaced between the missing check and the
            # sidecar write.
            _exclusive_bytes(
                public,
                raw,
                label=f"report transaction public sidecar {row.get('path')}",
            )
    _boundary(fault_hook, "SIDECARS_DURABLE")

    # Close the input-TOCTOU window at the final mutation boundary.  Candidate
    # computation and ARM are useless authority if a source changed while the
    # public sidecars were being projected.
    _validate_inputs(root, manifest.get("inputs") or [])

    current = report_path.read_bytes()
    current_sha = _sha(current)
    if current_sha == pre_sha and current != post:
        _atomic_bytes(report_path, post)
    elif current_sha != post_sha:
        raise ReportMutationTransactionError(
            "canonical report changed outside its armed transaction"
        )
    _boundary(fault_hook, "REPORT_REPLACED")

    # Re-read every committed surface after the replace boundary.  A concurrent
    # writer or fault hook must leave the transaction ARMED, never manufacture a
    # receipt for bytes that were not actually delivered.
    delivered = report_path.read_bytes()
    if _sha(delivered) != post_sha or len(delivered) != len(post):
        raise ReportMutationTransactionError(
            "canonical report changed before transaction commit"
        )
    _validate_inputs(root, manifest.get("inputs") or [])
    for row in manifest.get("sidecars") or []:
        public = _regular_path(
            root, str(row.get("path") or ""), allow_missing=False
        )
        raw = public.read_bytes()
        if row.get("sha256") != _sha(raw) or row.get("size_bytes") != len(raw):
            raise ReportMutationTransactionError(
                f"report transaction sidecar changed before commit: {row.get('path')}"
            )

    committed_unsigned = {
        key: value
        for key, value in manifest.items()
        if key not in {"transaction_sha256", "state"}
    }
    committed_unsigned["state"] = "COMMITTED"
    committed = _signed_payload(committed_unsigned, "transaction_sha256")
    _atomic_bytes(manifest_path, _canonical(committed) + b"\n")
    receipt_unsigned = {
        "schema_version": RECEIPT_SCHEMA,
        "run_id": run,
        "phase": phase_name,
        "transaction_sha256": committed["transaction_sha256"],
        "pre_report_sha256": pre_sha,
        "post_report_sha256": post_sha,
        "changed": pre_sha != post_sha,
        "sidecar_sha256": {
            str(row["path"]): str(row["sha256"])
            for row in committed.get("sidecars") or []
        },
    }
    receipt = _signed_payload(receipt_unsigned, "receipt_sha256")
    if receipt_path.is_file():
        try:
            prior = json.loads(
                receipt_path.read_text(encoding="utf-8", errors="strict")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReportMutationTransactionError(
                f"report transaction receipt is unreadable: {exc}"
            ) from exc
        _validate_signed(
            prior, digest_key="receipt_sha256", schema=RECEIPT_SCHEMA
        )
        if prior != receipt:
            raise ReportMutationTransactionError(
                "report transaction receipt changed"
            )
    else:
        _atomic_bytes(receipt_path, _canonical(receipt) + b"\n")
    _boundary(fault_hook, "COMMIT_DURABLE")
    _finalize_report_semantic_mutation(
        scratchpad=root,
        project_root=project,
        run_id=run,
        event=semantic_event,
        post_sha256=post_sha,
        post_size=len(post),
    )
    return ReportMutationResult(
        phase=phase_name,
        run_id=run,
        recovered=recovered,
        changed=pre_sha != post_sha,
        pre_report_sha256=pre_sha,
        post_report_sha256=post_sha,
        receipt_sha256=str(receipt["receipt_sha256"]),
    )


def recover_report_mutation_transaction(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    phase: str,
    report_candidate_sidecar: str,
) -> ReportMutationResult | None:
    """Finish an already-armed transaction without recomputing from post bytes.

    The intended report bytes and every public sidecar are recovered from the
    immutable transaction payloads.  A pre-ARM orphan returns ``None`` so the
    caller can deterministically recompute; no preimage or payload is replaced.
    """
    root = Path(scratchpad)
    phase_name = str(phase or "").strip()
    transaction_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", phase_name).strip("._")
    tx_dir = root / "_report_transactions" / transaction_key
    manifest_path = tx_dir / "transaction.json"
    if manifest_path.is_symlink():
        raise ReportMutationTransactionError(
            "report transaction manifest path is a symlink"
        )
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8", errors="strict")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportMutationTransactionError(
            f"report transaction manifest is unreadable: {exc}"
        ) from exc
    _validate_signed(manifest, digest_key="transaction_sha256", schema=SCHEMA)
    sidecars: dict[str, bytes] = {}
    for row in manifest.get("sidecars") or []:
        relative = _safe_relative(str(row.get("path") or ""))
        payload = _regular_path(
            tx_dir, str(row.get("payload") or ""), allow_missing=False
        )
        sidecars[relative] = payload.read_bytes()
    candidate_key = _safe_relative(report_candidate_sidecar)
    if candidate_key not in sidecars:
        raise ReportMutationTransactionError(
            "report transaction lacks its canonical report candidate sidecar"
        )
    exact_inputs = tuple(
        str(row.get("path") or "") for row in manifest.get("inputs") or []
    )
    return apply_report_mutation_transaction(
        scratchpad=root,
        project_root=Path(project_root),
        run_id=run_id,
        phase=phase_name,
        post_report=sidecars[candidate_key],
        exact_inputs=exact_inputs,
        sidecars=sidecars,
    )


def recover_report_transaction_semantic_event(
    *,
    scratchpad: Path,
    project_root: Path,
    run_id: str,
    event: Mapping[str, Any],
) -> ReportMutationResult | None:
    """Replay the one transaction that owns an ARMED report mutation event.

    Generic semantic-mutation recovery must not infer transaction completion
    from canonical report bytes alone.  This adapter locates the exact signed
    report manifest, binds it to the event's preimage/run/kind, derives the
    canonical candidate only from an immutable payload whose digest equals the
    intended postimage, and then enters the ordinary transaction recovery
    path.  That path revalidates the complete input and sidecar denominator
    before it commits or finalizes producer authority.

    ``None`` is reserved for the crash window in which the semantic arm is
    durable but no matching transaction manifest is yet durable.  The owning
    phase can safely recompute/replay from the unchanged preimage.
    """

    root = Path(scratchpad)
    project = Path(project_root)
    run = str(run_id or "").strip()
    if (
        not run
        or event.get("run_id") != run
        or event.get("status") != "ARMED"
        or event.get("artifact_identity") != "project:AUDIT_REPORT.md"
        or not str(event.get("mutation_kind") or "").startswith(
            "REPORT_TRANSACTION_"
        )
    ):
        raise ReportMutationTransactionError(
            "report transaction semantic event identity/state is invalid"
        )
    before = event.get("before")
    if (
        not isinstance(before, Mapping)
        or before.get("status") != "ACTIVE"
        or not isinstance(before.get("size"), int)
        or not _HEX64.fullmatch(str(before.get("sha256") or ""))
    ):
        raise ReportMutationTransactionError(
            "report transaction semantic event preimage is invalid"
        )

    transaction_root = root / "_report_transactions"
    if not transaction_root.exists():
        return None
    if transaction_root.is_symlink() or not transaction_root.is_dir():
        raise ReportMutationTransactionError(
            "report transaction root is not a regular directory"
        )
    matches: list[tuple[dict[str, Any], Path]] = []
    for child in sorted(transaction_root.iterdir(), key=lambda item: item.name):
        if child.is_symlink() or not child.is_dir():
            raise ReportMutationTransactionError(
                "report transaction contains an unsafe phase directory"
            )
        manifest_path = child / "transaction.json"
        if manifest_path.is_symlink():
            raise ReportMutationTransactionError(
                "report transaction manifest path is a symlink"
            )
        if not manifest_path.exists():
            continue
        if not manifest_path.is_file():
            raise ReportMutationTransactionError(
                "report transaction manifest is not a regular file"
            )
        try:
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8", errors="strict")
            )
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReportMutationTransactionError(
                f"report transaction manifest is unreadable: {exc}"
            ) from exc
        _validate_signed(manifest, digest_key="transaction_sha256", schema=SCHEMA)
        phase_name = str(manifest.get("phase") or "")
        if (
            manifest.get("run_id") == run
            and _semantic_mutation_kind(phase_name)
            == str(event.get("mutation_kind") or "")
            and manifest.get("report") == "project:AUDIT_REPORT.md"
            and manifest.get("pre_report_sha256") == before.get("sha256")
            and manifest.get("pre_report_size_bytes") == before.get("size")
        ):
            matches.append((manifest, child))
    if not matches:
        return None
    if len(matches) != 1:
        raise ReportMutationTransactionError(
            "report transaction semantic event has ambiguous manifests"
        )
    manifest, tx_dir = matches[0]
    candidate_paths: list[str] = []
    for row in manifest.get("sidecars") or []:
        if not isinstance(row, Mapping):
            raise ReportMutationTransactionError(
                "report transaction sidecar row is malformed"
            )
        if (
            row.get("sha256") == manifest.get("post_report_sha256")
            and row.get("size_bytes") == manifest.get("post_report_size_bytes")
        ):
            payload = _regular_path(
                tx_dir, str(row.get("payload") or ""), allow_missing=False
            )
            raw = payload.read_bytes()
            if _sha(raw) != row.get("sha256") or len(raw) != row.get("size_bytes"):
                raise ReportMutationTransactionError(
                    "report transaction canonical candidate payload is tampered"
                )
            candidate_paths.append(_safe_relative(str(row.get("path") or "")))
    if not candidate_paths:
        raise ReportMutationTransactionError(
            "report transaction has no immutable canonical candidate payload"
        )
    return recover_report_mutation_transaction(
        scratchpad=root,
        project_root=project,
        run_id=run,
        phase=str(manifest.get("phase") or ""),
        report_candidate_sidecar=sorted(set(candidate_paths))[0],
    )


def validate_report_transaction_semantic_successor(
    *,
    scratchpad: Path,
    project_root: Path,
    event: Mapping[str, Any],
) -> bool:
    """Prove a terminal report event came from one fully committed transaction.

    The semantic ledger is a lineage index, not a second report writer.  A
    caller-created terminal event must therefore never become current producer
    authority unless a signed transaction receipt binds the same exact
    preimage, postimage, inputs, sidecars, run, and phase.
    """

    try:
        root = Path(scratchpad)
        project = Path(project_root)
        run = str(event.get("run_id") or "")
        kind = str(event.get("mutation_kind") or "")
        before = event.get("before")
        after = event.get("after")
        if (
            not run
            or event.get("artifact_identity") != "project:AUDIT_REPORT.md"
            or event.get("status") not in {"NO_CHANGE", "INVALIDATION_APPLIED"}
            or not kind.startswith("REPORT_TRANSACTION_")
            or not isinstance(before, Mapping)
            or not isinstance(after, Mapping)
        ):
            return False
        tx_root = root / "_report_transactions"
        if tx_root.is_symlink() or not tx_root.is_dir():
            return False
        matched: list[tuple[dict[str, Any], Path]] = []
        for child in sorted(tx_root.iterdir(), key=lambda item: item.name):
            if child.is_symlink() or not child.is_dir():
                return False
            manifest_path = child / "transaction.json"
            if not manifest_path.is_file() or manifest_path.is_symlink():
                continue
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8", errors="strict")
            )
            _validate_signed(
                manifest, digest_key="transaction_sha256", schema=SCHEMA
            )
            phase_name = str(manifest.get("phase") or "")
            expected_key = re.sub(
                r"[^A-Za-z0-9_.-]+", "_", phase_name
            ).strip("._")
            if child.name != expected_key:
                return False
            if (
                manifest.get("run_id") == run
                and _semantic_mutation_kind(phase_name) == kind
                and manifest.get("report") == "project:AUDIT_REPORT.md"
                and manifest.get("pre_report_sha256") == before.get("sha256")
                and manifest.get("pre_report_size_bytes") == before.get("size")
                and manifest.get("post_report_sha256") == after.get("sha256")
                and manifest.get("post_report_size_bytes") == after.get("size")
            ):
                matched.append((manifest, child))
        if len(matched) != 1:
            return False
        manifest, tx_dir = matched[0]
        if manifest.get("state") != "COMMITTED":
            return False
        backup = tx_dir / "AUDIT_REPORT.preimage"
        if backup.is_symlink() or not backup.is_file():
            return False
        backup_raw = backup.read_bytes()
        if (
            _sha(backup_raw) != manifest.get("pre_report_sha256")
            or len(backup_raw) != manifest.get("pre_report_size_bytes")
        ):
            return False
        _validate_inputs(root, manifest.get("inputs") or [])
        for row in manifest.get("sidecars") or []:
            if not isinstance(row, Mapping):
                return False
            payload = _regular_path(
                tx_dir, str(row.get("payload") or ""), allow_missing=False
            )
            public = _regular_path(
                root, str(row.get("path") or ""), allow_missing=False
            )
            payload_raw = payload.read_bytes()
            public_raw = public.read_bytes()
            if (
                payload_raw != public_raw
                or _sha(payload_raw) != row.get("sha256")
                or len(payload_raw) != row.get("size_bytes")
            ):
                return False
        report_path = project / "AUDIT_REPORT.md"
        if report_path.is_symlink() or not report_path.is_file():
            return False
        report_raw = report_path.read_bytes()
        if (
            _sha(report_raw) != manifest.get("post_report_sha256")
            or len(report_raw) != manifest.get("post_report_size_bytes")
        ):
            return False
        receipt_path = tx_dir / "receipt.json"
        if receipt_path.is_symlink() or not receipt_path.is_file():
            return False
        receipt = json.loads(
            receipt_path.read_text(encoding="utf-8", errors="strict")
        )
        _validate_signed(
            receipt, digest_key="receipt_sha256", schema=RECEIPT_SCHEMA
        )
        expected_unsigned = {
            "schema_version": RECEIPT_SCHEMA,
            "run_id": run,
            "phase": str(manifest.get("phase") or ""),
            "transaction_sha256": str(manifest.get("transaction_sha256") or ""),
            "pre_report_sha256": str(manifest.get("pre_report_sha256") or ""),
            "post_report_sha256": str(manifest.get("post_report_sha256") or ""),
            "changed": before.get("sha256") != after.get("sha256"),
            "sidecar_sha256": {
                str(row.get("path") or ""): str(row.get("sha256") or "")
                for row in manifest.get("sidecars") or []
                if isinstance(row, Mapping)
            },
        }
        return receipt == _signed_payload(expected_unsigned, "receipt_sha256")
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        ReportMutationTransactionError,
        TypeError,
        ValueError,
    ):
        return False


def report_mutation_transaction_state(
    *, scratchpad: Path, run_id: str, phase: str
) -> str | None:
    """Return a validated transaction state, or ``None`` when none is armed."""
    phase_name = str(phase or "").strip()
    transaction_key = re.sub(r"[^A-Za-z0-9_.-]+", "_", phase_name).strip("._")
    manifest_path = (
        Path(scratchpad)
        / "_report_transactions"
        / transaction_key
        / "transaction.json"
    )
    if manifest_path.is_symlink():
        raise ReportMutationTransactionError(
            "report transaction manifest path is a symlink"
        )
    if not manifest_path.is_file():
        return None
    try:
        payload = json.loads(
            manifest_path.read_text(encoding="utf-8", errors="strict")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportMutationTransactionError(
            f"report transaction manifest is unreadable: {exc}"
        ) from exc
    _validate_signed(payload, digest_key="transaction_sha256", schema=SCHEMA)
    if payload.get("run_id") != str(run_id or "") or payload.get("phase") != phase_name:
        raise ReportMutationTransactionError(
            "report transaction run/phase identity changed"
        )
    state = str(payload.get("state") or "")
    if state not in {"ARMED", "COMMITTED"}:
        raise ReportMutationTransactionError(
            "report transaction state is not recoverable"
        )
    return state


__all__ = [
    "ReportMutationResult",
    "ReportMutationTransactionError",
    "apply_report_mutation_transaction",
    "capture_report_transaction_inputs",
    "recover_report_mutation_transaction",
    "recover_report_transaction_semantic_event",
    "report_mutation_transaction_state",
    "validate_report_transaction_semantic_successor",
]
