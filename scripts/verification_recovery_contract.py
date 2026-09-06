"""Compiler-backed contract for every verifier recovery path.

Recovery is a distinct bounded work unit.  It never edits the primary queue or
work plan, and it uses the same method registry, context packets, output
contract, and operator-receipt binding as ordinary verifier units.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Mapping, Sequence

from verification_method_compiler import (
    CONTEXT_SCHEMA,
    DISPATCH_SCHEMA,
    build_verification_context_packets,
    compile_verification_method_dispatch,
    dispatch_receipt_payload,
    stable_digest,
)


CONTRACT_SCHEMA = "plamen.verification_recovery_contract.v1"
DEFAULT_MAX_ROWS = 4

_FIELDS = frozenset({
    "schema_version", "run_id", "recovery_id", "recovery_kind", "pipeline",
    "ecosystem", "backend", "row_count", "rows", "max_rows",
    "manifest_path", "manifest_markdown", "manifest_sha256",
    "context_path", "context_packets", "method_dispatch_path",
    "method_dispatch", "prompt_path", "prompt_markdown", "prompt_sha256",
    "expected_model_outputs", "expected_operator_receipts", "contract_digest",
})
_ROW_FIELDS = frozenset({
    "work_item_id", "severity", "title", "bug_class", "poc_class",
    "location_records", "primary_artifacts", "mechanism", "harm", "evidence",
    "source_candidate_digest", "source_work_item_id", "source_identity",
    "source_operator_receipt", "source_operator_receipt_sha256",
    "source_operator_receipt_digest", "finding_lifecycle_obligation_id",
    "producer_identity", "required_discriminator_identity",
    "independent_discriminator_required",
})
_KINDS = frozenset({
    "RESUME_QUEUE_DROPOUT", "POST_VERIFY_SIDE_OBSERVATION",
    "LATE_OPERATOR_CANDIDATE", "GROUPED_SCOPE_REPAIR",
    "REPORT_INDEX_DROPOUT", "MANDATORY_REOPEN", "GENERIC_RECOVERY",
    "BB_POLICY_SEVERITY_CHANGE",
})
_BACKENDS = frozenset({"claude", "codex"})
_PIPELINES = frozenset({"sc", "l1"})
_HEX64 = frozenset("0123456789abcdef")


class RecoveryContractError(ValueError):
    """A recovery unit cannot be compiled or replayed exactly."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise RecoveryContractError(f"record is not canonical JSON: {exc}") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RecoveryContractError(f"{label} must be an object")
    if set(value) != set(fields):
        raise RecoveryContractError(
            f"{label} schema mismatch; missing={sorted(fields - set(value))}; "
            f"extra={sorted(set(value) - fields)}"
        )
    return dict(value)


def _text(value: Any, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise RecoveryContractError(f"{field} must be canonical text")
    if not allow_empty and not value:
        raise RecoveryContractError(f"{field} must be non-empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise RecoveryContractError(f"{field} contains control characters")
    return value


def _sha256(value: Any, field: str) -> str:
    item = _text(value, field)
    if len(item) != 64 or any(char not in _HEX64 for char in item):
        raise RecoveryContractError(f"{field} must be a lowercase SHA-256 digest")
    return item


def _canonical_path(value: Any, field: str) -> str:
    item = _text(value, field)
    if "\\" in item or PurePosixPath(item).is_absolute() or ".." in PurePosixPath(item).parts:
        raise RecoveryContractError(f"{field} must be a canonical relative POSIX path")
    if PurePosixPath(item).as_posix() != item:
        raise RecoveryContractError(f"{field} is not normalized")
    return item


def _normalize_locations(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RecoveryContractError("location_records must be an array")
    rows: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise RecoveryContractError("location record must be an object")
        artifact = str(item.get("artifact") or "").strip().replace("\\", "/")
        if not artifact:
            continue
        rows.append({
            "artifact": artifact,
            "start_line": item.get("start_line"),
            "end_line": item.get("end_line"),
            "symbol": item.get("symbol"),
            "note": item.get("note"),
        })
    return rows


def _locations_from_row(row: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = _normalize_locations(row.get("location_records"))
    if records:
        return records
    raw = str(row.get("location") or "").strip().replace("\\", "/")
    if not raw:
        return []
    match = re.fullmatch(r"(.+?):(\d+)(?:-(\d+))?(?::(.+))?", raw)
    if match:
        start = int(match.group(2))
        return [{
            "artifact": match.group(1),
            "start_line": start,
            "end_line": int(match.group(3) or start),
            "symbol": match.group(4) or None,
            "note": None,
        }]
    return [{
        "artifact": raw,
        "start_line": None,
        "end_line": None,
        "symbol": None,
        "note": "unparsed source location",
    }]


def _optional_text(value: Any, field: str) -> str | None:
    if value is None or value == "":
        return None
    return _text(str(value).strip(), field)


def _optional_sha256(value: Any, field: str) -> str | None:
    if value is None or value == "":
        return None
    return _sha256(value, field)


def _normalize_primary_artifacts(row: Mapping[str, Any]) -> list[str]:
    raw = row.get("primary_artifacts")
    if raw is None:
        raw = row.get("primary artifact") or row.get("primary_artifact")
    if isinstance(raw, str):
        values = [value.strip() for value in raw.split(",") if value.strip()]
    elif isinstance(raw, list):
        values = [str(value).strip() for value in raw if str(value).strip()]
    elif raw is None:
        values = []
    else:
        raise RecoveryContractError("primary_artifacts must be text or an array")
    return list(dict.fromkeys(values))


def _normalize_row(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RecoveryContractError("recovery row must be an object")
    work_id = value.get("work_item_id") or value.get("finding id") or value.get("finding_id")
    title = _text(str(value.get("title") or work_id or "").strip(), "title")
    producer = _optional_text(value.get("producer_identity"), "producer_identity")
    discriminator = _optional_text(
        value.get("required_discriminator_identity"),
        "required_discriminator_identity",
    )
    independent = value.get("independent_discriminator_required", False)
    if not isinstance(independent, bool):
        raise RecoveryContractError(
            "independent_discriminator_required must be boolean"
        )
    if independent and producer is not None and producer == discriminator:
        raise RecoveryContractError(
            "recovery producer and required discriminator must be independent"
        )
    source_work_id = _optional_text(
        value.get("source_work_item_id"), "source_work_item_id"
    )
    source_identity = _optional_text(
        value.get("source_identity"), "source_identity"
    ) or source_work_id
    return {
        "work_item_id": _text(str(work_id or "").strip(), "work_item_id"),
        "severity": _text(str(value.get("severity") or "Unknown").strip(), "severity"),
        "title": title,
        "bug_class": _text(
            str(value.get("bug_class") or value.get("bug class") or "unclassified").strip(),
            "bug_class",
        ),
        "poc_class": _text(
            str(value.get("poc_class") or value.get("poc class") or "structural")
            .strip().replace(" ", "-").lower(),
            "poc_class",
        ),
        "location_records": _locations_from_row(value),
        "primary_artifacts": _normalize_primary_artifacts(value),
        "mechanism": _text(
            str(value.get("mechanism") or title).strip(), "mechanism"
        ),
        "harm": _text(
            str(
                value.get("harm")
                or "Material-harm scope remains unresolved and requires independent verification."
            ).strip(),
            "harm",
        ),
        "evidence": _text(
            str(
                value.get("evidence")
                or value.get("evidence_pointer")
                or value.get("primary artifact")
                or value.get("primary_artifact")
                or "unbound-source-evidence"
            ).strip(),
            "evidence",
        ),
        "source_candidate_digest": _optional_sha256(
            value.get("source_candidate_digest"), "source_candidate_digest"
        ),
        "source_work_item_id": source_work_id,
        "source_identity": source_identity,
        "source_operator_receipt": _optional_text(
            value.get("source_operator_receipt"), "source_operator_receipt"
        ),
        "source_operator_receipt_sha256": _optional_sha256(
            value.get("source_operator_receipt_sha256"),
            "source_operator_receipt_sha256",
        ),
        "source_operator_receipt_digest": _optional_sha256(
            value.get("source_operator_receipt_digest"),
            "source_operator_receipt_digest",
        ),
        "finding_lifecycle_obligation_id": _optional_text(
            value.get("finding_lifecycle_obligation_id"),
            "finding_lifecycle_obligation_id",
        ),
        "producer_identity": producer,
        "required_discriminator_identity": discriminator,
        "independent_discriminator_required": independent,
    }


def _render_manifest(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# Verification Recovery Manifest", "",
        "This is a distinct recovery denominator. It does not amend the primary queue.",
        "", "| Work Item ID | Severity | Title | Bug Class | PoC Class |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        cells = [
            str(row["work_item_id"]), str(row["severity"]), str(row["title"]),
            str(row["bug_class"]), str(row["poc_class"]),
        ]
        cells = [item.replace("|", "/").replace("\n", " ") for item in cells]
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend(["", "## Exact row records", "", "```json", _canonical_json(list(rows)), "```", ""])
    return "\n".join(lines)


def _render_prompt(
    *,
    recovery_id: str,
    recovery_kind: str,
    compiled_prompt: str,
    row_count: int,
) -> str:
    return f"""# Independent Verification Recovery Work Unit

- Recovery ID: {recovery_id}
- Recovery reason: {recovery_kind}
- Exact assigned rows: {row_count}

This is a distinct bounded verifier work unit. Verify only its manifest rows.
The producer of a late observation cannot be its discriminator. Do not edit the
primary verification queue, primary work plan, or primary verifier roster.
Write every exact output named by the compiled contract to the audit
scratchpad. The driver, not this worker, binds operator receipts after launch.

---

{compiled_prompt.rstrip()}
"""


def _identity_seed(
    *,
    run_id: str,
    recovery_kind: str,
    pipeline: str,
    ecosystem: str,
    backend: str,
    rows: Sequence[Mapping[str, Any]],
    context_packets: Mapping[str, Any],
    registry_digest: str,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "recovery_kind": recovery_kind,
        "pipeline": pipeline,
        "ecosystem": ecosystem,
        "backend": backend,
        "rows": list(rows),
        "context_digest": context_packets["context_digest"],
        "registry_digest": registry_digest,
    }


def build_verification_recovery_contract(
    *,
    run_id: str,
    recovery_kind: str,
    rows: Sequence[Mapping[str, Any]],
    scratchpad: Path,
    project_root: Path,
    pipeline: str,
    ecosystem: str,
    backend: str,
    repo_root: Path | None = None,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> dict[str, Any]:
    run = _text(run_id, "run_id")
    kind = _text(recovery_kind, "recovery_kind").upper()
    if kind not in _KINDS:
        raise RecoveryContractError("recovery_kind is unsupported")
    pipeline_n = str(pipeline or "").strip().lower()
    backend_n = str(backend or "").strip().lower()
    ecosystem_n = _text(str(ecosystem or "").strip().lower(), "ecosystem")
    if pipeline_n not in _PIPELINES:
        raise RecoveryContractError("pipeline must be sc or l1")
    if backend_n not in _BACKENDS:
        raise RecoveryContractError("backend must be claude or codex")
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or not 1 <= max_rows <= 16:
        raise RecoveryContractError("max_rows must be a bounded integer in [1,16]")
    normalized = [_normalize_row(row) for row in rows]
    if not normalized:
        raise RecoveryContractError("recovery contract requires at least one row")
    if len(normalized) > max_rows:
        raise RecoveryContractError(
            f"recovery denominator exceeds bounded max_rows={max_rows}"
        )
    if len({row["work_item_id"] for row in normalized}) != len(normalized):
        raise RecoveryContractError("recovery denominator contains duplicate work items")
    normalized.sort(key=lambda row: row["work_item_id"])
    context = build_verification_context_packets(
        rows=normalized,
        scratchpad=Path(scratchpad),
        project_root=Path(project_root),
    )
    # Compile once with a provisional canonical path only to obtain the
    # registry digest used in the non-circular recovery identity.
    provisional = compile_verification_method_dispatch(
        pipeline=pipeline_n,
        ecosystem=ecosystem_n,
        backend=backend_n,
        rows=normalized,
        context_packets=context,
        manifest_path="_verification_recovery/pending/manifest.md",
        scratchpad_path=(Path(scratchpad) / "_verification_recovery" / "pending").as_posix(),
        root=repo_root,
    )
    recovery_digest = _digest(_identity_seed(
        run_id=run,
        recovery_kind=kind,
        pipeline=pipeline_n,
        ecosystem=ecosystem_n,
        backend=backend_n,
        rows=normalized,
        context_packets=context,
        registry_digest=provisional["registry_digest"],
    ))
    recovery_id = "VREC-" + recovery_digest.upper()
    directory = f"_verification_recovery/{recovery_id}"
    manifest_path = f"{directory}/manifest.md"
    context_path = f"{directory}/verification_context_packets.json"
    dispatch_path = f"{directory}/method_dispatch.json"
    prompt_path = f"{directory}/prompt.md"
    dispatch = compile_verification_method_dispatch(
        pipeline=pipeline_n,
        ecosystem=ecosystem_n,
        backend=backend_n,
        rows=normalized,
        context_packets=context,
        manifest_path=manifest_path,
        scratchpad_path=(Path(scratchpad) / PurePosixPath(directory)).as_posix(),
        root=repo_root,
    )
    manifest = _render_manifest(normalized)
    prompt = _render_prompt(
        recovery_id=recovery_id,
        recovery_kind=kind,
        compiled_prompt=dispatch["prompt_markdown"],
        row_count=len(normalized),
    )
    expected_model_outputs: list[str] = []
    expected_operator_receipts: list[str] = []
    for row in normalized:
        work_id = row["work_item_id"]
        expected_model_outputs.extend([
            f"verify_{work_id}.md",
            f"verify_{work_id}.severity_proposal.json",
            f"verify_{work_id}.operator_application.json",
        ])
        expected_operator_receipts.append(f"verify_{work_id}.operator_receipt.json")
    unsigned = {
        "schema_version": CONTRACT_SCHEMA,
        "run_id": run,
        "recovery_id": recovery_id,
        "recovery_kind": kind,
        "pipeline": pipeline_n,
        "ecosystem": ecosystem_n,
        "backend": backend_n,
        "row_count": len(normalized),
        "rows": normalized,
        "max_rows": max_rows,
        "manifest_path": manifest_path,
        "manifest_markdown": manifest,
        "manifest_sha256": _bytes_digest(manifest.encode("utf-8")),
        "context_path": context_path,
        "context_packets": context,
        "method_dispatch_path": dispatch_path,
        "method_dispatch": dispatch_receipt_payload(dispatch),
        "prompt_path": prompt_path,
        "prompt_markdown": prompt,
        "prompt_sha256": _bytes_digest(prompt.encode("utf-8")),
        "expected_model_outputs": expected_model_outputs,
        "expected_operator_receipts": expected_operator_receipts,
    }
    return validate_verification_recovery_contract({
        **unsigned, "contract_digest": _digest(unsigned)
    }, repo_root=repo_root)


def validate_verification_recovery_contract(
    value: Mapping[str, Any], *, repo_root: Path | None = None
) -> dict[str, Any]:
    row = _exact(value, _FIELDS, "recovery contract")
    if row["schema_version"] != CONTRACT_SCHEMA:
        raise RecoveryContractError("recovery contract schema mismatch")
    for field in ("run_id", "recovery_id", "recovery_kind", "ecosystem"):
        _text(row[field], field)
    if row["pipeline"] not in _PIPELINES or row["backend"] not in _BACKENDS:
        raise RecoveryContractError("recovery pipeline/backend is invalid")
    if row["recovery_kind"] not in _KINDS:
        raise RecoveryContractError("recovery kind is invalid")
    if not isinstance(row["rows"], list):
        raise RecoveryContractError("recovery rows must be an array")
    normalized = []
    for value in row["rows"]:
        item = _exact(value, _ROW_FIELDS, "recovery row")
        normalized.append(_normalize_row(item))
    if normalized != row["rows"]:
        raise RecoveryContractError("recovery rows are not canonical")
    if row["row_count"] != len(normalized):
        raise RecoveryContractError("recovery row count mismatch")
    if not isinstance(row["max_rows"], int) or isinstance(row["max_rows"], bool):
        raise RecoveryContractError("max_rows must be an integer")
    if not 1 <= len(normalized) <= row["max_rows"] <= 16:
        raise RecoveryContractError("recovery row denominator is not bounded")
    for field in ("manifest_path", "context_path", "method_dispatch_path", "prompt_path"):
        _canonical_path(row[field], field)
        if not row[field].startswith(f"_verification_recovery/{row['recovery_id']}/"):
            raise RecoveryContractError(f"{field} is outside recovery identity")
    expected_manifest = _render_manifest(normalized)
    if row["manifest_markdown"] != expected_manifest:
        raise RecoveryContractError("recovery manifest differs from exact rows")
    if _sha256(row["manifest_sha256"], "manifest_sha256") != _bytes_digest(expected_manifest.encode("utf-8")):
        raise RecoveryContractError("recovery manifest digest mismatch")
    context = row["context_packets"]
    if not isinstance(context, Mapping) or context.get("schema_version") != CONTEXT_SCHEMA:
        raise RecoveryContractError("recovery context packet schema mismatch")
    context_unsigned = {key: value for key, value in context.items() if key != "context_digest"}
    if _sha256(context.get("context_digest"), "context_digest") != stable_digest(context_unsigned):
        raise RecoveryContractError("recovery context packet digest mismatch")
    dispatch = row["method_dispatch"]
    if not isinstance(dispatch, Mapping) or dispatch.get("schema_version") != DISPATCH_SCHEMA:
        raise RecoveryContractError("recovery method dispatch schema mismatch")
    recomputed = compile_verification_method_dispatch(
        pipeline=row["pipeline"],
        ecosystem=row["ecosystem"],
        backend=row["backend"],
        rows=normalized,
        context_packets=context,
        manifest_path=row["manifest_path"],
        scratchpad_path=str(
            Path(str(context["scratchpad"]))
            / PurePosixPath(row["manifest_path"]).parent
        ).replace("\\", "/"),
        root=repo_root,
    )
    if dispatch_receipt_payload(recomputed) != dict(dispatch):
        raise RecoveryContractError("recovery method dispatch differs from registry/context")
    expected_recovery_digest = _digest(_identity_seed(
        run_id=row["run_id"],
        recovery_kind=row["recovery_kind"],
        pipeline=row["pipeline"],
        ecosystem=row["ecosystem"],
        backend=row["backend"],
        rows=normalized,
        context_packets=context,
        registry_digest=dispatch["registry_digest"],
    ))
    if row["recovery_id"] != "VREC-" + expected_recovery_digest.upper():
        raise RecoveryContractError("recovery identity digest mismatch")
    expected_prompt = _render_prompt(
        recovery_id=row["recovery_id"],
        recovery_kind=row["recovery_kind"],
        compiled_prompt=recomputed["prompt_markdown"],
        row_count=len(normalized),
    )
    if row["prompt_markdown"] != expected_prompt:
        raise RecoveryContractError("recovery prompt differs from compiled method prompt")
    if _sha256(row["prompt_sha256"], "prompt_sha256") != _bytes_digest(expected_prompt.encode("utf-8")):
        raise RecoveryContractError("recovery prompt digest mismatch")
    expected_outputs: list[str] = []
    expected_receipts: list[str] = []
    for item in normalized:
        work_id = item["work_item_id"]
        expected_outputs.extend([
            f"verify_{work_id}.md",
            f"verify_{work_id}.severity_proposal.json",
            f"verify_{work_id}.operator_application.json",
        ])
        expected_receipts.append(f"verify_{work_id}.operator_receipt.json")
    if row["expected_model_outputs"] != expected_outputs:
        raise RecoveryContractError("recovery model output denominator mismatch")
    if row["expected_operator_receipts"] != expected_receipts:
        raise RecoveryContractError("recovery operator receipt denominator mismatch")
    unsigned = {key: row[key] for key in _FIELDS if key != "contract_digest"}
    if _sha256(row["contract_digest"], "contract_digest") != _digest(unsigned):
        raise RecoveryContractError("recovery contract digest mismatch")
    return row


def write_or_validate_verification_recovery_contract(
    path: Path, value: Mapping[str, Any], *, repo_root: Path | None = None
) -> bool:
    target = Path(path)
    contract = validate_verification_recovery_contract(value, repo_root=repo_root)
    rendered = json.dumps(contract, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if target.is_file():
        try:
            existing = json.loads(target.read_text(encoding="utf-8", errors="strict"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RecoveryContractError(f"existing recovery contract is unreadable: {exc}") from exc
        if validate_verification_recovery_contract(existing, repo_root=repo_root) != contract:
            raise RecoveryContractError("existing recovery contract differs from current inputs")
        if target.read_text(encoding="utf-8", errors="strict") != rendered:
            raise RecoveryContractError("existing recovery contract bytes are non-canonical")
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temporary = Path(raw)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return True


def materialize_verification_recovery_contract(
    scratchpad: Path, value: Mapping[str, Any], *, repo_root: Path | None = None
) -> dict[str, Path]:
    """Write or validate the contract and every immutable launch input."""
    contract = validate_verification_recovery_contract(value, repo_root=repo_root)
    root = Path(scratchpad)
    mapping = {
        "contract": root / PurePosixPath(contract["manifest_path"]).parent / "contract.json",
        "manifest": root / PurePosixPath(contract["manifest_path"]),
        "context": root / PurePosixPath(contract["context_path"]),
        "dispatch": root / PurePosixPath(contract["method_dispatch_path"]),
        "prompt": root / PurePosixPath(contract["prompt_path"]),
    }
    write_or_validate_verification_recovery_contract(
        mapping["contract"], contract, repo_root=repo_root
    )
    payloads = {
        "manifest": contract["manifest_markdown"],
        "context": json.dumps(contract["context_packets"], indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        "dispatch": json.dumps(contract["method_dispatch"], indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        "prompt": contract["prompt_markdown"],
    }
    for key, content in payloads.items():
        path = mapping[key]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file():
            if path.read_text(encoding="utf-8", errors="strict") != content:
                raise RecoveryContractError(f"existing recovery {key} differs from contract")
            continue
        path.write_text(content, encoding="utf-8", newline="\n")
    return mapping


__all__ = [
    "CONTRACT_SCHEMA", "DEFAULT_MAX_ROWS", "RecoveryContractError",
    "build_verification_recovery_contract",
    "materialize_verification_recovery_contract",
    "validate_verification_recovery_contract",
    "write_or_validate_verification_recovery_contract",
]
