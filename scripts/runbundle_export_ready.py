"""Optional, non-blocking export-ready marker for completed audits.

The marker contains digests only.  It neither exports a bundle nor contacts an
evaluator, and audit success never depends on its availability.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

try:
    import runbundle_contracts as C
    import runbundle_privacy as P
except ImportError:  # pragma: no cover
    from . import runbundle_contracts as C
    from . import runbundle_privacy as P


EXPORT_READY_SCHEMA = "plamen.run-export-ready.v1"
MAX_CONTROL_BYTES = 128 << 20
MAX_REPORT_BYTES = 1 << 30


class RunBundleExportReadyError(ValueError):
    """An export-ready marker or its exact input binding is invalid."""


_FIELDS = frozenset(
    {
        "schema_version",
        "run_id",
        "checkpoint_sha256",
        "checkpoint_byte_length",
        "artifact_ledger_sha256",
        "artifact_ledger_byte_length",
        "final_report_sha256",
        "final_report_byte_length",
        "report_gate_state",
        "receipt_sha256",
    }
)


def _read(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        return P.read_stable_regular_bytes(
            path, maximum_bytes=maximum, label=label
        )
    except P.RunBundlePrivacyError as exc:
        raise RunBundleExportReadyError(str(exc)) from exc


def validate_export_ready_marker(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _FIELDS:
        raise RunBundleExportReadyError("export-ready marker is not closed")
    row = C.strict_json_loads(
        C.canonical_document_bytes(value), require_canonical=True
    )
    if row["schema_version"] != EXPORT_READY_SCHEMA:
        raise RunBundleExportReadyError("unknown export-ready marker schema")
    if (
        not isinstance(row["run_id"], str)
        or not row["run_id"]
        or any(char.isspace() for char in row["run_id"])
        or "/" in row["run_id"]
        or "\\" in row["run_id"]
    ):
        raise RunBundleExportReadyError("export-ready run ID is invalid")
    for field in (
        "checkpoint_sha256",
        "artifact_ledger_sha256",
        "final_report_sha256",
    ):
        if (
            not isinstance(row[field], str)
            or len(row[field]) != 64
            or any(char not in "0123456789abcdef" for char in row[field])
        ):
            raise RunBundleExportReadyError(f"{field} is not SHA-256")
    for field in (
        "checkpoint_byte_length",
        "artifact_ledger_byte_length",
        "final_report_byte_length",
    ):
        if (
            not isinstance(row[field], int)
            or isinstance(row[field], bool)
            or row[field] < 0
        ):
            raise RunBundleExportReadyError(f"{field} is invalid")
    if row["report_gate_state"] not in {
        "PASSED",
        "DEGRADED",
        "FAILED",
        "UNKNOWN",
    }:
        raise RunBundleExportReadyError("report gate state is invalid")
    try:
        C.verify_embedded_sha256(row, "receipt_sha256")
        P.validate_public_payload(row)
    except (C.RunBundleContractError, P.RunBundlePrivacyError) as exc:
        raise RunBundleExportReadyError(str(exc)) from exc
    return row


def build_export_ready_marker(
    *,
    run_id: str,
    checkpoint: Path,
    artifact_ledger: Path,
    report: Path,
    report_gate_state: str,
) -> dict[str, Any]:
    first = {
        "checkpoint": _read(
            checkpoint, maximum=MAX_CONTROL_BYTES, label="checkpoint"
        ),
        "artifact_ledger": _read(
            artifact_ledger, maximum=MAX_CONTROL_BYTES, label="artifact ledger"
        ),
        "report": _read(report, maximum=MAX_REPORT_BYTES, label="final report"),
    }
    # Detect cross-file mutation during the capture window.
    second = {
        "checkpoint": _read(
            checkpoint, maximum=MAX_CONTROL_BYTES, label="checkpoint recheck"
        ),
        "artifact_ledger": _read(
            artifact_ledger,
            maximum=MAX_CONTROL_BYTES,
            label="artifact ledger recheck",
        ),
        "report": _read(
            report, maximum=MAX_REPORT_BYTES, label="final report recheck"
        ),
    }
    if first != second:
        raise RunBundleExportReadyError("export-ready inputs changed during capture")
    marker = {
        "schema_version": EXPORT_READY_SCHEMA,
        "run_id": run_id,
        "checkpoint_sha256": C.sha256_bytes(first["checkpoint"]),
        "checkpoint_byte_length": len(first["checkpoint"]),
        "artifact_ledger_sha256": C.sha256_bytes(first["artifact_ledger"]),
        "artifact_ledger_byte_length": len(first["artifact_ledger"]),
        "final_report_sha256": C.sha256_bytes(first["report"]),
        "final_report_byte_length": len(first["report"]),
        "report_gate_state": report_gate_state,
    }
    return validate_export_ready_marker(
        C.bind_embedded_sha256(marker, "receipt_sha256")
    )


def verify_export_ready_inputs(
    marker: Mapping[str, Any],
    *,
    checkpoint: Path,
    artifact_ledger: Path,
    report: Path,
) -> dict[str, Any]:
    row = validate_export_ready_marker(dict(marker))
    bindings = (
        (
            checkpoint,
            MAX_CONTROL_BYTES,
            "checkpoint",
            "checkpoint_sha256",
            "checkpoint_byte_length",
        ),
        (
            artifact_ledger,
            MAX_CONTROL_BYTES,
            "artifact ledger",
            "artifact_ledger_sha256",
            "artifact_ledger_byte_length",
        ),
        (
            report,
            MAX_REPORT_BYTES,
            "final report",
            "final_report_sha256",
            "final_report_byte_length",
        ),
    )
    for path, maximum, label, digest_field, length_field in bindings:
        raw = _read(path, maximum=maximum, label=label)
        if (
            len(raw) != row[length_field]
            or C.sha256_bytes(raw) != row[digest_field]
        ):
            raise RunBundleExportReadyError(
                f"export-ready {label} changed or drifted"
            )
    return row


def write_export_ready_marker(
    *,
    out: Path,
    marker: Mapping[str, Any],
) -> Path:
    row = validate_export_ready_marker(dict(marker))
    target = Path(out).resolve()
    if target.exists():
        raise RunBundleExportReadyError(
            "export-ready output already exists; overwrite is forbidden"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name("." + target.name + ".publishing")
    if temporary.exists():
        raise RunBundleExportReadyError(
            "export-ready temporary output already exists"
        )
    try:
        temporary.write_bytes(C.canonical_document_bytes(row))
        temporary.replace(target)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise RunBundleExportReadyError(
            "could not publish export-ready marker"
        ) from exc
    return target


__all__ = [
    "EXPORT_READY_SCHEMA",
    "MAX_CONTROL_BYTES",
    "MAX_REPORT_BYTES",
    "RunBundleExportReadyError",
    "build_export_ready_marker",
    "validate_export_ready_marker",
    "verify_export_ready_inputs",
    "write_export_ready_marker",
]
