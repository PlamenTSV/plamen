#!/usr/bin/env python3.12
"""Read-only validation of requirement-to-proof reconciliation records.

This is a continuation-document verifier, not a production runtime gate.  It
does not update the canonical requirement ledger, evidence index, or any proof
record.  A record is only proof-capable when every required facet is backed by
current, subject-specific, explicitly classified evidence.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = "plamen.continuation.requirements-reconciliation.v1"
DEFAULT_LEDGER = "docs/continuation/REQUIREMENTS.jsonl"
DEFAULT_RECONCILIATION = "docs/continuation/REQUIREMENTS_RECONCILIATION.jsonl"
DEFAULT_EVIDENCE_INDEX = "docs/continuation/EVIDENCE_INDEX.json"
ACTIVE_STATUS = "ACTIVE_REQUIRED"
FACETS = (
    "implementation",
    "production_reachability",
    "focused_tests",
    "full_suite",
    "fault_migration_resume",
    "package",
    "backend",
    "platform",
    "no_silent_loss",
    "current_snapshot",
)
AGGREGATE_TYPES = frozenset({"namespace", "requirement_set", "ordering_edges"})
CLOSING_DISPOSITIONS = frozenset(
    {"CLOSED", "SUPERSEDED_WITH_PROOF", "NOT_APPLICABLE_WITH_PROOF"}
)
DISPOSITIONS = CLOSING_DISPOSITIONS | {"OPEN", "ACTIVE"}
CLASSIFICATIONS = frozenset(
    {"PASS", "PENDING", "FAILURE", "DEFICIT", "UNCLASSIFIED"}
)
HEX64 = frozenset("0123456789abcdef")
ORDERING_POLICY = "urn:plamen:policy:ordering-edges-graph-only:v1"


class ReconciliationError(ValueError):
    """The reconciliation corpus is incomplete, stale, or ambiguous."""


@dataclass(frozen=True)
class LedgerRow:
    key: str
    line_number: int
    line_sha256: str
    payload: Mapping[str, Any]


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ReconciliationError(f"value is not canonical JSON: {exc}") from exc


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return _sha_bytes(_canonical(value).encode("utf-8"))


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in HEX64 for character in value)
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReconciliationError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _decode_json(raw: str, label: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ReconciliationError(f"{label}: invalid JSON constant {value}")

    try:
        return json.loads(
            raw,
            object_pairs_hook=_strict_object,
            parse_constant=reject_constant,
        )
    except ReconciliationError:
        raise
    except json.JSONDecodeError as exc:
        raise ReconciliationError(f"{label}: invalid JSON: {exc}") from exc


def _read_json(path: Path) -> Mapping[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ReconciliationError(f"cannot read {path}: {exc}") from exc
    value = _decode_json(raw, str(path))
    if not isinstance(value, dict):
        raise ReconciliationError(f"{path} must contain one JSON object")
    return value


def _read_jsonl(path: Path) -> list[tuple[int, bytes, Mapping[str, Any]]]:
    try:
        raw = path.read_bytes()
        raw.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise ReconciliationError(f"cannot read {path}: {exc}") from exc
    result: list[tuple[int, bytes, Mapping[str, Any]]] = []
    for line_number, terminated_line in enumerate(raw.splitlines(keepends=True), start=1):
        line = terminated_line[:-1] if terminated_line.endswith(b"\n") else terminated_line
        if not line.strip():
            raise ReconciliationError(f"{path}:{line_number}: blank JSONL line")
        value = _decode_json(line.decode("utf-8"), f"{path}:{line_number}")
        if not isinstance(value, dict):
            raise ReconciliationError(f"{path}:{line_number}: object required")
        result.append((line_number, line, value))
    if not result:
        raise ReconciliationError(f"{path}: at least one JSONL object is required")
    return result


def _require_keys(
    value: Mapping[str, Any],
    required: Iterable[str],
    *,
    optional: Iterable[str] = (),
    label: str,
) -> None:
    required_set = set(required)
    allowed = required_set | set(optional)
    missing = sorted(required_set - set(value))
    unknown = sorted(set(value) - allowed)
    if missing:
        raise ReconciliationError(f"{label}: missing fields {missing}")
    if unknown:
        raise ReconciliationError(f"{label}: unknown fields {unknown}")


def ledger_key(payload: Mapping[str, Any]) -> str:
    record_type = payload.get("record_type")
    namespace = payload.get("namespace")
    if not isinstance(record_type, str) or not record_type:
        raise ReconciliationError("ledger row has no record_type")
    if not isinstance(namespace, str) or not namespace:
        raise ReconciliationError(f"{record_type} ledger row has no namespace")
    if record_type in {"requirement", "requirement_set", "program_gate"}:
        identifier = payload.get("id")
        if not isinstance(identifier, str) or not identifier:
            raise ReconciliationError(f"{record_type} ledger row has no id")
        return f"{record_type}:{namespace}:{identifier}"
    if record_type in {"namespace", "ordering_edges"}:
        return f"{record_type}:{namespace}"
    raise ReconciliationError(f"unsupported ACTIVE_REQUIRED record_type {record_type!r}")


def load_active_ledger(path: Path) -> tuple[str, list[LedgerRow]]:
    file_sha256 = _sha_bytes(path.read_bytes())
    active: list[LedgerRow] = []
    seen: set[str] = set()
    for line_number, line, payload in _read_jsonl(path):
        if payload.get("status") != ACTIVE_STATUS:
            continue
        key = ledger_key(payload)
        if key in seen:
            raise ReconciliationError(f"duplicate ACTIVE_REQUIRED ledger key {key}")
        seen.add(key)
        active.append(LedgerRow(key, line_number, _sha_bytes(line), payload))
    if not active:
        raise ReconciliationError("ledger contains no ACTIVE_REQUIRED rows")
    return file_sha256, active


def _child_specs(rows: Sequence[LedgerRow]) -> list[tuple[str, str, str, int, str]]:
    targets = [
        row
        for row in rows
        if row.payload.get("record_type") == "requirement_set"
        and row.payload.get("id") == "AUG-AUDIT-001"
    ]
    if len(targets) != 1:
        raise ReconciliationError("exactly one active AUG-AUDIT-001 row is required")
    parent = targets[0]
    issue_sets = parent.payload.get("issue_sets")
    if not isinstance(issue_sets, dict):
        raise ReconciliationError("AUG-AUDIT-001 issue_sets must be an object")
    result: list[tuple[str, str, str, int, str]] = []
    seen: set[str] = set()
    for group, details in issue_sets.items():
        if not isinstance(group, str) or not isinstance(details, dict):
            raise ReconciliationError("AUG-AUDIT-001 issue set is malformed")
        count = details.get("count")
        identifiers = details.get("ids")
        if not isinstance(count, int) or isinstance(count, bool):
            raise ReconciliationError(f"issue set {group} count must be an integer")
        if not isinstance(identifiers, list) or count != len(identifiers):
            raise ReconciliationError(f"issue set {group} count/ids mismatch")
        for identifier in identifiers:
            if not isinstance(identifier, str) or not identifier or identifier in seen:
                raise ReconciliationError(f"duplicate or invalid issue id {identifier!r}")
            seen.add(identifier)
            proof_key = f"child:{parent.key}:{identifier}"
            result.append(
                (proof_key, parent.key, group, parent.line_number, parent.line_sha256)
            )
    if len(result) != 64:
        raise ReconciliationError(
            f"AUG-AUDIT-001 must expand to exactly 64 child proofs, got {len(result)}"
        )
    return result


def _required_facets() -> dict[str, dict[str, Any]]:
    return {
        name: {"applicability": "REQUIRED", "receipt_ids": []}
        for name in FACETS
    }


def _ordering_facets() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "applicability": "NOT_APPLICABLE_WITH_POLICY",
            "policy_ref": ORDERING_POLICY,
            "rationale": "This ledger row constrains graph order and carries no proof facet.",
            "receipt_ids": [],
        }
        for name in FACETS
    }


def build_seed_documents(
    root: Path,
    ledger_path: Path,
    evidence_index_path: Path,
) -> list[dict[str, Any]]:
    """Return the truthful OPEN/UNMAPPED seed without writing it."""

    ledger_sha256, rows = load_active_ledger(ledger_path)
    child_specs = _child_specs(rows)
    try:
        ledger_ref = ledger_path.resolve().relative_to(root.resolve()).as_posix()
        evidence_ref = evidence_index_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ReconciliationError("ledger and evidence index must be inside root") from exc
    documents: list[dict[str, Any]] = [
        {
            "record_type": "reconciliation_metadata",
            "schema": SCHEMA,
            "ledger_ref": ledger_ref,
            "ledger_sha256": ledger_sha256,
            "evidence_index_ref": evidence_ref,
            "active_required_count": len(rows),
            "child_proof_count": len(child_specs),
            "facet_names": list(FACETS),
            "seed_policy": "OPEN_UNMAPPED_NO_COMPLETION_CLAIM",
        }
    ]
    for row in rows:
        record_type = row.payload["record_type"]
        record: dict[str, Any] = {
            "record_type": "ledger_reconciliation",
            "ledger_key": row.key,
            "ledger_record_type": record_type,
            "namespace": row.payload["namespace"],
            "ledger_id": row.payload.get("id"),
            "ledger_line": row.line_number,
            "ledger_line_sha256": row.line_sha256,
            "aggregate": record_type in AGGREGATE_TYPES,
            "mapping_state": "UNMAPPED",
            "disposition": "OPEN",
            "derived_status": "OPEN",
            "implementation_witnesses": [],
            "test_witnesses": [],
            "receipts": [],
            "facets": (
                _ordering_facets()
                if record_type == "ordering_edges"
                else _required_facets()
            ),
        }
        if record_type == "ordering_edges":
            record["graph_constraints"] = row.payload.get("edges")
        documents.append(record)
    parent = next(row for row in rows if row.key == child_specs[0][1])
    id_to_group: dict[str, str] = {}
    for group, details in parent.payload["issue_sets"].items():
        for identifier in details["ids"]:
            id_to_group[identifier] = group
    for proof_key, parent_key, _group, parent_line, parent_sha in child_specs:
        child_id = proof_key.rsplit(":", 1)[1]
        documents.append(
            {
                "record_type": "child_proof",
                "proof_key": proof_key,
                "parent_ledger_key": parent_key,
                "child_id": child_id,
                "issue_set": id_to_group[child_id],
                "parent_ledger_line": parent_line,
                "parent_ledger_line_sha256": parent_sha,
                "mapping_state": "UNMAPPED",
                "disposition": "OPEN",
                "derived_status": "OPEN",
                "implementation_witnesses": [],
                "test_witnesses": [],
                "receipts": [],
                "facets": _required_facets(),
            }
        )
    return documents


def render_jsonl(documents: Sequence[Mapping[str, Any]]) -> str:
    return "".join(_canonical(document) + "\n" for document in documents)


def _path_in_root(root: Path, relative: Any, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ReconciliationError(f"{label}: canonical relative POSIX path required")
    candidate = Path(relative)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ReconciliationError(f"{label}: unsafe relative path {relative!r}")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ReconciliationError(f"{label}: path escapes root") from exc
    if not resolved.is_file():
        raise ReconciliationError(f"{label}: file does not resolve: {relative}")
    return resolved


def _validate_blob(root: Path, witness: Mapping[str, Any], label: str) -> Path:
    _require_keys(witness, {"path", "sha256"}, label=label)
    if not _is_sha256(witness["sha256"]):
        raise ReconciliationError(f"{label}: invalid sha256")
    path = _path_in_root(root, witness["path"], label)
    actual = _sha_bytes(path.read_bytes())
    if actual != witness["sha256"]:
        raise ReconciliationError(
            f"{label}: witness blob hash drift for {witness['path']}: "
            f"expected {witness['sha256']}, got {actual}"
        )
    return path


def _python_symbols(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise ReconciliationError(f"cannot parse Python witness {path}: {exc}") from exc
    symbols: set[str] = set()

    def visit(body: Sequence[ast.stmt], prefix: tuple[str, ...] = ()) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = ".".join((*prefix, node.name))
                symbols.add(name)
                if isinstance(node, ast.ClassDef):
                    visit(node.body, (*prefix, node.name))

    visit(tree.body)
    return symbols


def _validate_source_witness(root: Path, value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReconciliationError(f"{label}: object required")
    _require_keys(value, {"path", "sha256", "symbol"}, label=label)
    path = _validate_blob(root, {"path": value["path"], "sha256": value["sha256"]}, label)
    symbol = value["symbol"]
    if path.suffix != ".py" or not isinstance(symbol, str) or not symbol:
        raise ReconciliationError(f"{label}: Python symbol witness required")
    if symbol not in _python_symbols(path):
        raise ReconciliationError(f"{label}: source symbol does not resolve: {symbol}")
    return dict(value)


def _node_parts(nodeid: Any, label: str) -> tuple[str, list[str]]:
    if not isinstance(nodeid, str) or "::" not in nodeid:
        raise ReconciliationError(f"{label}: pytest nodeid with :: required")
    path, *parts = nodeid.split("::")
    cleaned = [part.split("[", 1)[0] for part in parts]
    if not path or not cleaned or any(not part for part in cleaned):
        raise ReconciliationError(f"{label}: malformed pytest nodeid")
    return path, cleaned


def _validate_test_witness(root: Path, value: Any, label: str) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ReconciliationError(f"{label}: object required")
    _require_keys(value, {"nodeid", "sha256"}, label=label)
    relative, parts = _node_parts(value["nodeid"], label)
    path = _validate_blob(root, {"path": relative, "sha256": value["sha256"]}, label)
    if path.suffix != ".py":
        raise ReconciliationError(f"{label}: Python test module required")
    symbol = ".".join(parts)
    if symbol not in _python_symbols(path):
        raise ReconciliationError(f"{label}: test node does not resolve: {value['nodeid']}")
    return dict(value)


def _validate_blob_list(root: Path, value: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ReconciliationError(f"{label}: list required")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            raise ReconciliationError(f"{item_label}: object required")
        _validate_blob(root, item, item_label)
        path = item["path"]
        if path in seen:
            raise ReconciliationError(f"{label}: duplicate path {path}")
        seen.add(path)
        result.append(dict(item))
    return result


def _evidence_records(index: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    records = index.get("records")
    if not isinstance(records, list):
        raise ReconciliationError("evidence index records must be a list")
    result: dict[str, Mapping[str, Any]] = {}
    for offset, record in enumerate(records):
        if not isinstance(record, dict) or not isinstance(record.get("id"), str):
            raise ReconciliationError(f"evidence index record {offset} has no id")
        identifier = record["id"]
        if identifier in result:
            raise ReconciliationError(f"duplicate evidence index id {identifier}")
        result[identifier] = record
    return result


def _classification(record: Mapping[str, Any]) -> str:
    # Deliberately do not infer from IDs, prose, filenames, pass totals, or exit text.
    value = record.get("proof_classification", "UNCLASSIFIED")
    return value if value in CLASSIFICATIONS else "UNCLASSIFIED"


def _validate_evidence_ref(
    root: Path,
    evidence_path: Path,
    records: Mapping[str, Mapping[str, Any]],
    value: Any,
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, str) or value.count("#") != 1:
        raise ReconciliationError(f"{label}: path#record-id evidence reference required")
    relative, fragment = value.split("#", 1)
    resolved = _path_in_root(root, relative, label)
    if resolved != evidence_path.resolve():
        raise ReconciliationError(f"{label}: evidence reference targets the wrong index")
    if fragment not in records:
        raise ReconciliationError(f"{label}: unresolved evidence fragment {fragment!r}")
    return records[fragment]


def _validate_facets(value: Any, label: str) -> tuple[dict[str, Any], set[str]]:
    if not isinstance(value, dict) or set(value) != set(FACETS):
        missing = sorted(set(FACETS) - set(value) if isinstance(value, dict) else FACETS)
        unknown = sorted(set(value) - set(FACETS)) if isinstance(value, dict) else []
        raise ReconciliationError(
            f"{label}: every facet must be explicit; missing={missing}, unknown={unknown}"
        )
    used: set[str] = set()
    result: dict[str, Any] = {}
    for facet in FACETS:
        item = value[facet]
        if not isinstance(item, dict):
            raise ReconciliationError(f"{label}.{facet}: object required")
        applicability = item.get("applicability")
        if applicability == "REQUIRED":
            _require_keys(item, {"applicability", "receipt_ids"}, label=f"{label}.{facet}")
        elif applicability == "NOT_APPLICABLE_WITH_POLICY":
            _require_keys(
                item,
                {"applicability", "policy_ref", "rationale", "receipt_ids"},
                label=f"{label}.{facet}",
            )
            if not isinstance(item["policy_ref"], str) or not item["policy_ref"]:
                raise ReconciliationError(f"{label}.{facet}: policy_ref required")
            if not isinstance(item["rationale"], str) or not item["rationale"]:
                raise ReconciliationError(f"{label}.{facet}: rationale required")
        else:
            raise ReconciliationError(f"{label}.{facet}: invalid applicability")
        receipt_ids = item["receipt_ids"]
        if not isinstance(receipt_ids, list) or any(
            not isinstance(identifier, str) or not identifier for identifier in receipt_ids
        ):
            raise ReconciliationError(f"{label}.{facet}: receipt_ids must be strings")
        if len(receipt_ids) != len(set(receipt_ids)):
            raise ReconciliationError(f"{label}.{facet}: duplicate receipt id")
        if applicability == "NOT_APPLICABLE_WITH_POLICY" and receipt_ids:
            raise ReconciliationError(f"{label}.{facet}: N/A facet cannot cite receipts")
        used.update(receipt_ids)
        result[facet] = item
    return result, used


def _validate_receipt(
    root: Path,
    ledger_sha256: str,
    evidence_path: Path,
    evidence_records: Mapping[str, Mapping[str, Any]],
    subject_key: str,
    value: Any,
    record_implementations: set[tuple[str, str, str]],
    record_tests: set[str],
    label: str,
) -> tuple[str, str, frozenset[str]]:
    if not isinstance(value, dict):
        raise ReconciliationError(f"{label}: object required")
    required = {
        "id",
        "subject_key",
        "evidence_ref",
        "classification",
        "proven_facets",
        "source_witnesses",
        "worktree_witness",
        "argv",
        "runtime",
        "backend",
        "exit_code",
        "collected_nodeids",
        "artifact_hashes",
        "package_hashes",
        "scope",
        "limits",
        "snapshot_binding",
    }
    _require_keys(value, required, label=label)
    identifier = value["id"]
    if not isinstance(identifier, str) or not identifier:
        raise ReconciliationError(f"{label}: receipt id required")
    if value["subject_key"] != subject_key:
        raise ReconciliationError(
            f"{label}: receipt subject {value['subject_key']!r} cannot prove {subject_key!r}"
        )
    indexed = _validate_evidence_ref(
        root, evidence_path, evidence_records, value["evidence_ref"], label
    )
    classification = _classification(indexed)
    if value["classification"] != classification:
        raise ReconciliationError(
            f"{label}: classification must equal explicit evidence-index classification "
            f"{classification}"
        )
    proven_facets = value["proven_facets"]
    if (
        not isinstance(proven_facets, list)
        or not proven_facets
        or len(proven_facets) != len(set(proven_facets))
        or any(facet not in FACETS for facet in proven_facets)
    ):
        raise ReconciliationError(f"{label}: explicit unique proven_facets required")
    source_values = value["source_witnesses"]
    if not isinstance(source_values, list):
        raise ReconciliationError(f"{label}.source_witnesses: list required")
    sources = [
        _validate_source_witness(root, item, f"{label}.source_witnesses[{index}]")
        for index, item in enumerate(source_values)
    ]
    if "implementation" in proven_facets and not any(
        (item["path"], item["sha256"], item["symbol"]) in record_implementations
        for item in sources
    ):
        raise ReconciliationError(
            f"{label}: implementation proof lacks a record implementation witness"
        )
    worktree = value["worktree_witness"]
    if not isinstance(worktree, dict):
        raise ReconciliationError(f"{label}.worktree_witness: object required")
    _require_keys(worktree, {"files", "manifest_sha256"}, label=f"{label}.worktree_witness")
    files = _validate_blob_list(root, worktree["files"], f"{label}.worktree_witness.files")
    if not files or worktree["manifest_sha256"] != _digest(files):
        raise ReconciliationError(f"{label}: invalid worktree witness manifest")
    witness_pairs = {(item["path"], item["sha256"]) for item in files}
    for item in sources:
        if (item["path"], item["sha256"]) not in witness_pairs:
            raise ReconciliationError(f"{label}: source witness absent from worktree manifest")
    argv = value["argv"]
    if not isinstance(argv, list) or not argv or any(
        not isinstance(argument, str) or not argument for argument in argv
    ):
        raise ReconciliationError(f"{label}: exact non-empty argv vector required")
    runtime = value["runtime"]
    if not isinstance(runtime, dict):
        raise ReconciliationError(f"{label}.runtime: object required")
    _require_keys(runtime, {"python_version", "platform"}, label=f"{label}.runtime")
    if not all(isinstance(runtime[key], str) and runtime[key] for key in runtime):
        raise ReconciliationError(f"{label}.runtime: explicit Python/runtime platform required")
    if not runtime["python_version"].startswith("3.12"):
        raise ReconciliationError(f"{label}.runtime: Python 3.12 evidence required")
    backend = value["backend"]
    if not isinstance(backend, dict):
        raise ReconciliationError(f"{label}.backend: object required")
    _require_keys(backend, {"name", "model"}, label=f"{label}.backend")
    if not all(isinstance(backend[key], str) and backend[key] for key in backend):
        raise ReconciliationError(f"{label}.backend: explicit backend/model required")
    exit_code = value["exit_code"]
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise ReconciliationError(f"{label}: integer exit_code required")
    if classification == "PASS" and exit_code != 0:
        raise ReconciliationError(f"{label}: PASS evidence must have exit_code 0")
    nodeids = value["collected_nodeids"]
    if not isinstance(nodeids, list) or len(nodeids) != len(set(nodeids)):
        raise ReconciliationError(f"{label}: unique collected_nodeids list required")
    for index, nodeid in enumerate(nodeids):
        if nodeid not in record_tests:
            raise ReconciliationError(f"{label}: collected nodeid is not a record witness: {nodeid}")
        relative, _ = _node_parts(nodeid, f"{label}.collected_nodeids[{index}]")
        if not any(item["path"] == relative for item in files):
            raise ReconciliationError(f"{label}: collected node file absent from worktree witness")
    if "focused_tests" in proven_facets and not nodeids:
        raise ReconciliationError(f"{label}: focused_tests proof requires collected nodeids")
    artifacts = _validate_blob_list(root, value["artifact_hashes"], f"{label}.artifact_hashes")
    packages = _validate_blob_list(root, value["package_hashes"], f"{label}.package_hashes")
    for item in (*artifacts, *packages):
        if (item["path"], item["sha256"]) not in witness_pairs:
            raise ReconciliationError(f"{label}: artifact/package absent from worktree manifest")
    if "package" in proven_facets and not packages:
        raise ReconciliationError(f"{label}: package proof requires a package hash")
    if "backend" in proven_facets and (
        backend["name"] == "NOT_APPLICABLE" or backend["model"] == "NOT_APPLICABLE"
    ):
        raise ReconciliationError(f"{label}: backend proof requires an exact backend/model")
    if not isinstance(value["scope"], str) or not value["scope"]:
        raise ReconciliationError(f"{label}: explicit scope required")
    limits = value["limits"]
    if not isinstance(limits, list) or not limits or any(
        not isinstance(limit, str) or not limit for limit in limits
    ):
        raise ReconciliationError(f"{label}: explicit non-empty limits required")
    binding = value["snapshot_binding"]
    if not isinstance(binding, dict):
        raise ReconciliationError(f"{label}.snapshot_binding: object required")
    _require_keys(
        binding,
        {"ledger_sha256", "worktree_manifest_sha256"},
        label=f"{label}.snapshot_binding",
    )
    if binding["ledger_sha256"] != ledger_sha256:
        raise ReconciliationError(f"{label}: current ledger snapshot mismatch")
    if binding["worktree_manifest_sha256"] != worktree["manifest_sha256"]:
        raise ReconciliationError(f"{label}: current worktree snapshot mismatch")
    return identifier, classification, frozenset(proven_facets)


def _base_status(
    record: Mapping[str, Any],
    facets: Mapping[str, Mapping[str, Any]],
    receipt_proofs: Mapping[str, tuple[str, frozenset[str]]],
) -> str:
    if record["mapping_state"] == "UNMAPPED":
        return "OPEN"
    if record["disposition"] not in CLOSING_DISPOSITIONS:
        return "OPEN"
    for facet in FACETS:
        item = facets[facet]
        if item["applicability"] == "NOT_APPLICABLE_WITH_POLICY":
            continue
        if not item["receipt_ids"] or not all(
            receipt_proofs.get(identifier, ("UNCLASSIFIED", frozenset()))[0] == "PASS"
            and facet in receipt_proofs.get(
                identifier, ("UNCLASSIFIED", frozenset())
            )[1]
            for identifier in item["receipt_ids"]
        ):
            return "OPEN"
    return "PROVEN"


def validate_reconciliation(
    root: Path,
    ledger_path: Path,
    reconciliation_path: Path,
    evidence_index_path: Path,
) -> dict[str, Any]:
    """Validate all records and return a deterministic read-only summary."""

    root = root.resolve()
    ledger_sha256, ledger_rows = load_active_ledger(ledger_path)
    expected = {row.key: row for row in ledger_rows}
    children = _child_specs(ledger_rows)
    expected_children = {spec[0]: spec for spec in children}
    documents = _read_jsonl(reconciliation_path)
    for jsonl_line, line, payload in documents:
        if line != _canonical(payload).encode("utf-8"):
            raise ReconciliationError(
                f"{reconciliation_path}:{jsonl_line}: canonical deterministic JSON required"
            )
    metadata = documents[0][2]
    _require_keys(
        metadata,
        {
            "record_type",
            "schema",
            "ledger_ref",
            "ledger_sha256",
            "evidence_index_ref",
            "active_required_count",
            "child_proof_count",
            "facet_names",
            "seed_policy",
        },
        label="reconciliation metadata",
    )
    if metadata["record_type"] != "reconciliation_metadata" or metadata["schema"] != SCHEMA:
        raise ReconciliationError("reconciliation metadata schema mismatch")
    if metadata["ledger_sha256"] != ledger_sha256:
        raise ReconciliationError("reconciliation is not bound to the current ledger snapshot")
    if metadata["active_required_count"] != len(ledger_rows):
        raise ReconciliationError("metadata ACTIVE_REQUIRED count mismatch")
    if metadata["child_proof_count"] != len(children):
        raise ReconciliationError("metadata child proof count mismatch")
    if metadata["facet_names"] != list(FACETS):
        raise ReconciliationError("metadata facet_names mismatch")
    if metadata["seed_policy"] != "OPEN_UNMAPPED_NO_COMPLETION_CLAIM":
        raise ReconciliationError("metadata seed policy mismatch")
    ledger_ref_path = _path_in_root(root, metadata["ledger_ref"], "metadata ledger_ref")
    evidence_ref_path = _path_in_root(
        root, metadata["evidence_index_ref"], "metadata evidence_index_ref"
    )
    if ledger_ref_path != ledger_path.resolve():
        raise ReconciliationError("metadata ledger_ref targets the wrong ledger")
    if evidence_ref_path != evidence_index_path.resolve():
        raise ReconciliationError("metadata evidence_index_ref targets the wrong index")
    evidence_records = _evidence_records(_read_json(evidence_index_path))

    ledger_records: dict[str, Mapping[str, Any]] = {}
    child_records: dict[str, Mapping[str, Any]] = {}
    locations: dict[str, str] = {}
    global_receipts: set[str] = set()
    base_statuses: dict[str, str] = {}
    for jsonl_line, _line, record in documents[1:]:
        record_type = record.get("record_type")
        label = f"{reconciliation_path}:{jsonl_line}"
        if record_type == "ledger_reconciliation":
            required = {
                "record_type", "ledger_key", "ledger_record_type", "namespace",
                "ledger_id", "ledger_line", "ledger_line_sha256", "aggregate",
                "mapping_state", "disposition", "derived_status",
                "implementation_witnesses", "test_witnesses", "receipts", "facets",
            }
            _require_keys(record, required, optional={"graph_constraints"}, label=label)
            key = record["ledger_key"]
            if not isinstance(key, str) or key not in expected:
                raise ReconciliationError(f"{label}: unknown ledger key {key!r}")
            if key in ledger_records:
                raise ReconciliationError(f"{label}: duplicate ledger key {key}")
            row = expected[key]
            if record["ledger_record_type"] != row.payload["record_type"]:
                raise ReconciliationError(f"{label}: ledger record type mismatch")
            if record["namespace"] != row.payload["namespace"]:
                raise ReconciliationError(f"{label}: namespace mismatch")
            if record["ledger_id"] != row.payload.get("id"):
                raise ReconciliationError(f"{label}: ledger id mismatch")
            if record["ledger_line"] != row.line_number:
                raise ReconciliationError(f"{label}: ledger line mismatch")
            if record["ledger_line_sha256"] != row.line_sha256:
                raise ReconciliationError(f"{label}: ledger row-line hash mismatch")
            aggregate = row.payload["record_type"] in AGGREGATE_TYPES
            if record["aggregate"] is not aggregate:
                raise ReconciliationError(f"{label}: aggregate classification mismatch")
            if row.payload["record_type"] == "ordering_edges":
                if record.get("graph_constraints") != row.payload.get("edges"):
                    raise ReconciliationError(f"{label}: ordering graph constraints mismatch")
                if record["receipts"]:
                    raise ReconciliationError(f"{label}: ordering_edges is graph-only")
            elif "graph_constraints" in record:
                raise ReconciliationError(f"{label}: graph_constraints only belong to ordering_edges")
            ledger_records[key] = record
        elif record_type == "child_proof":
            required = {
                "record_type", "proof_key", "parent_ledger_key", "child_id",
                "issue_set", "parent_ledger_line", "parent_ledger_line_sha256",
                "mapping_state", "disposition", "derived_status",
                "implementation_witnesses", "test_witnesses", "receipts", "facets",
            }
            _require_keys(record, required, label=label)
            key = record["proof_key"]
            if not isinstance(key, str) or key not in expected_children:
                raise ReconciliationError(f"{label}: unknown child proof {key!r}")
            if key in child_records:
                raise ReconciliationError(f"{label}: duplicate child proof {key}")
            _proof_key, parent_key, group, parent_line, parent_sha = expected_children[key]
            child_id = key.rsplit(":", 1)[1]
            expected_values = (parent_key, child_id, group, parent_line, parent_sha)
            actual_values = (
                record["parent_ledger_key"], record["child_id"], record["issue_set"],
                record["parent_ledger_line"], record["parent_ledger_line_sha256"],
            )
            if actual_values != expected_values:
                raise ReconciliationError(f"{label}: child proof parent/issue binding mismatch")
            child_records[key] = record
        else:
            raise ReconciliationError(f"{label}: unsupported record_type {record_type!r}")
        locations[key] = label

    missing = sorted(set(expected) - set(ledger_records))
    unknown = sorted(set(ledger_records) - set(expected))
    if missing or unknown or len(ledger_records) != len(expected):
        raise ReconciliationError(
            f"ACTIVE_REQUIRED row bijection failed: missing={missing}, unknown={unknown}"
        )
    missing_children = sorted(set(expected_children) - set(child_records))
    unknown_children = sorted(set(child_records) - set(expected_children))
    if missing_children or unknown_children or len(child_records) != 64:
        raise ReconciliationError(
            f"AUG-AUDIT-001 child bijection failed: missing={missing_children}, "
            f"unknown={unknown_children}"
        )

    all_records = {**ledger_records, **child_records}
    for key, record in all_records.items():
        label = locations[key]
        if record["mapping_state"] not in {"UNMAPPED", "MAPPED"}:
            raise ReconciliationError(f"{label}: invalid mapping_state")
        if record["disposition"] not in DISPOSITIONS:
            raise ReconciliationError(f"{label}: invalid disposition")
        if record["derived_status"] not in {"OPEN", "PROVEN"}:
            raise ReconciliationError(f"{label}: invalid derived_status")
        implementation_values = record["implementation_witnesses"]
        if not isinstance(implementation_values, list):
            raise ReconciliationError(f"{label}.implementation_witnesses: list required")
        implementations = [
            _validate_source_witness(
                root, value, f"{label}.implementation_witnesses[{index}]"
            )
            for index, value in enumerate(implementation_values)
        ]
        implementation_keys = {
            (value["path"], value["sha256"], value["symbol"])
            for value in implementations
        }
        test_values = record["test_witnesses"]
        if not isinstance(test_values, list):
            raise ReconciliationError(f"{label}.test_witnesses: list required")
        tests = [
            _validate_test_witness(root, value, f"{label}.test_witnesses[{index}]")
            for index, value in enumerate(test_values)
        ]
        test_nodeids = {value["nodeid"] for value in tests}
        if len(test_nodeids) != len(tests):
            raise ReconciliationError(f"{label}: duplicate test witness")
        facets, used_receipts = _validate_facets(record["facets"], f"{label}.facets")
        receipts = record["receipts"]
        if not isinstance(receipts, list):
            raise ReconciliationError(f"{label}.receipts: list required")
        receipt_proofs: dict[str, tuple[str, frozenset[str]]] = {}
        for index, receipt in enumerate(receipts):
            identifier, classification, proven_facets = _validate_receipt(
                root,
                ledger_sha256,
                evidence_index_path,
                evidence_records,
                key,
                receipt,
                implementation_keys,
                test_nodeids,
                f"{label}.receipts[{index}]",
            )
            if identifier in receipt_proofs or identifier in global_receipts:
                raise ReconciliationError(f"{label}: duplicate receipt id {identifier}")
            receipt_proofs[identifier] = (classification, proven_facets)
            global_receipts.add(identifier)
        if used_receipts != set(receipt_proofs):
            raise ReconciliationError(
                f"{label}: facet/receipt bijection failed; cited={sorted(used_receipts)}, "
                f"present={sorted(receipt_proofs)}"
            )
        if record["mapping_state"] == "UNMAPPED":
            if (
                record["disposition"] != "OPEN"
                or implementations
                or tests
                or receipts
            ):
                raise ReconciliationError(f"{label}: UNMAPPED records must remain empty OPEN debt")
        else:
            if facets["implementation"]["applicability"] == "REQUIRED" and not implementations:
                raise ReconciliationError(f"{label}: mapped implementation locator required")
            if facets["focused_tests"]["applicability"] == "REQUIRED" and not tests:
                raise ReconciliationError(f"{label}: mapped focused test node required")
        if record.get("ledger_record_type") == "ordering_edges":
            for facet in FACETS:
                item = facets[facet]
                if (
                    item["applicability"] != "NOT_APPLICABLE_WITH_POLICY"
                    or item["policy_ref"] != ORDERING_POLICY
                ):
                    raise ReconciliationError(f"{label}: ordering_edges facets are graph-only")
        base_statuses[key] = _base_status(record, facets, receipt_proofs)

    derived = dict(base_statuses)
    for key, record in ledger_records.items():
        if record["ledger_record_type"] == "ordering_edges":
            derived[key] = "OPEN"
        elif record["ledger_record_type"] == "requirement_set":
            child_states = [
                derived[child_key]
                for child_key, spec in expected_children.items()
                if spec[1] == key
            ]
            if not child_states or any(state != "PROVEN" for state in child_states):
                derived[key] = "OPEN"
    for key, record in ledger_records.items():
        if record["ledger_record_type"] == "namespace":
            descendants = [
                other_key
                for other_key, other in ledger_records.items()
                if other_key != key and other["namespace"] == record["namespace"]
            ]
            if not descendants or any(derived[item] != "PROVEN" for item in descendants):
                derived[key] = "OPEN"
    for key, record in all_records.items():
        if record["derived_status"] != derived[key]:
            raise ReconciliationError(
                f"{locations[key]}: derived_status must be {derived[key]}, not "
                f"{record['derived_status']}; status is mechanically derived"
            )

    return {
        "schema": SCHEMA,
        "ledger_sha256": ledger_sha256,
        "active_required_count": len(ledger_records),
        "child_proof_count": len(child_records),
        "aggregate_count": sum(record["aggregate"] for record in ledger_records.values()),
        "open_count": sum(state == "OPEN" for state in derived.values()),
        "proven_count": sum(state == "PROVEN" for state in derived.values()),
        "completion_claim": False,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--ledger", default=DEFAULT_LEDGER)
    parser.add_argument("--reconciliation", default=DEFAULT_RECONCILIATION)
    parser.add_argument("--evidence-index", default=DEFAULT_EVIDENCE_INDEX)
    parser.add_argument(
        "--print-seed",
        action="store_true",
        help="print a truthful OPEN/UNMAPPED seed to stdout; never writes files",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if sys.version_info[:2] != (3, 12):
        print("requirements reconciliation requires Python 3.12", file=sys.stderr)
        return 2
    args = _parser().parse_args(argv)
    root = args.root.resolve()
    ledger = _path_in_root(root, args.ledger, "--ledger")
    evidence = _path_in_root(root, args.evidence_index, "--evidence-index")
    try:
        if args.print_seed:
            sys.stdout.write(render_jsonl(build_seed_documents(root, ledger, evidence)))
        else:
            reconciliation = _path_in_root(
                root, args.reconciliation, "--reconciliation"
            )
            print(
                _canonical(
                    validate_reconciliation(root, ledger, reconciliation, evidence)
                )
            )
    except ReconciliationError as exc:
        print(f"requirements reconciliation invalid: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
