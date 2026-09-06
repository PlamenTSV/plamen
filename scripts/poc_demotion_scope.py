"""Typed scope boundary for grouped-PoC negative-review proposals (P0-O).

The verifier's prose/title similarity may nominate a constituent for repair,
but it cannot authorize a severity reduction.  An executed PoC ledger can bind
a proposal to a known constituent, harm premise, and assertion; that answers
which claim was exercised, not whether a negative lifecycle effect should be
applied.  The driver hashes those source bytes into an immutable scope receipt
and emits uncovered members as bounded reverification debt.

This module intentionally does not run a verifier or mutate the canonical
verification queue.  Its repair sidecar is a typed work manifest.  Until the
work is consumed, every grouped parent and constituent remains report-visible
at its pre-proposal severity.  A separate typed adjudicator/lifecycle receipt
would be required before any severity or disposition mutation can be enabled.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


SCOPE_SCHEMA = "plamen.poc_demotion_scope.v1"
REPAIR_SCHEMA = "plamen.poc_demotion_scope_repair.v1"
RECOVERY_PLAN_SCHEMA = "plamen.poc_demotion_scope_recovery_plan.v1"
RECOVERY_ATTEMPT_SCHEMA = "plamen.poc_demotion_scope_recovery_attempt.v1"
RECOVERY_UNIT_RECEIPT_SCHEMA = "plamen.poc_demotion_scope_recovery_unit_receipt.v1"
RECOVERY_STATUS_SCHEMA = "plamen.poc_demotion_scope_recovery_status.v1"
RECOVERY_DIR = "_poc_demotion_scope_recovery"

_SCOPE_HEADING_RE = re.compile(
    r"(?im)^#{2,4}\s+PoC\s+Constituent\s+Evidence\s+Scope\s*$"
)
_FIELD_RE_TEMPLATE = r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?{name}(?:\*\*)?\s*:\s*(.+?)\s*$"
_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d+[A-Z]?$", re.ASCII)
_REQUIRED_HEADERS = (
    "constituent id",
    "harm premise id",
    "assertion id",
    "proof scope",
    "binding kind",
)
_HARM_SCOPE = "HARM"
_MECHANISM_SCOPES = frozenset({"MECHANISM", "MECHANISM_ONLY"})
_BINDING_KINDS = frozenset({"EXACT", "SHARED"})


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _receipt_digest(payload: Mapping[str, Any]) -> str:
    body = dict(payload)
    body.pop("receipt_digest", None)
    return _sha256_bytes(_canonical_json_bytes(body))


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.p0o.tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    payload["receipt_digest"] = _receipt_digest(payload)
    _atomic_write(
        path,
        (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("utf-8"),
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _read_strict_json(path: Path) -> dict[str, Any]:
    def _reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    value = json.loads(
        path.read_text(encoding="utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )
    if not isinstance(value, dict):
        raise TypeError(f"{path.name} must contain one JSON object")
    return value


def _validate_receipt_digest(value: Mapping[str, Any], label: str) -> None:
    digest = value.get("receipt_digest")
    if not isinstance(digest, str) or digest != _receipt_digest(value):
        raise ValueError(f"{label} receipt_digest mismatch")


def _file_sha256(path: Path) -> str | None:
    try:
        return _sha256_bytes(path.read_bytes())
    except OSError:
        return None


def _field(content: str, name: str) -> str:
    match = re.search(
        _FIELD_RE_TEMPLATE.format(name=re.escape(name)), content
    )
    if not match:
        return ""
    return re.sub(r"[*`_]", "", match.group(1)).strip()


def _normalize_id(value: str) -> str:
    token = re.sub(r"[*`_]", "", value or "").strip()
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1].strip()
    token = token.upper()
    return token if _ID_RE.fullmatch(token) else ""


def _split_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _separator(cells: Sequence[str]) -> bool:
    return bool(cells) and all(bool(re.fullmatch(r":?-{3,}:?", c)) for c in cells)


def _parse_scope_rows(content: str) -> tuple[list[dict[str, str]], list[str]]:
    """Parse only the table under the exact P0-O scope heading.

    A malformed or duplicate row is a fail-closed scope error.  No prose or
    other Markdown table can manufacture demotion authority.
    """
    heading = _SCOPE_HEADING_RE.search(content or "")
    if not heading:
        return [], []
    tail = content[heading.end():]
    next_heading = re.search(r"(?m)^#{2,4}\s+", tail)
    section = tail[: next_heading.start()] if next_heading else tail
    lines = section.splitlines()
    header_index = -1
    headers: list[str] = []
    for index, line in enumerate(lines):
        cells = _split_table_row(line)
        normalized = [re.sub(r"\s+", " ", c.lower()).strip() for c in cells]
        if all(required in normalized for required in _REQUIRED_HEADERS):
            header_index = index
            headers = normalized
            break
    if header_index < 0:
        return [], ["missing exact scope table header"]
    if header_index + 1 >= len(lines) or not _separator(_split_table_row(lines[header_index + 1])):
        return [], ["missing scope table separator"]

    parsed: list[dict[str, str]] = []
    issues: list[str] = []
    seen: set[str] = set()
    for line in lines[header_index + 2:]:
        cells = _split_table_row(line)
        if not cells:
            if parsed:
                break
            continue
        if len(cells) != len(headers):
            issues.append("scope row column count mismatch")
            continue
        row = dict(zip(headers, cells))
        cid = _normalize_id(row.get("constituent id", ""))
        premise = re.sub(r"[*`_]", "", row.get("harm premise id", "")).strip().upper()
        assertion = re.sub(r"[*`_]", "", row.get("assertion id", "")).strip().upper()
        proof_scope = re.sub(r"[\s`*_\-]+", "_", row.get("proof scope", "")).strip("_").upper()
        binding = re.sub(r"[\s`*_\-]+", "_", row.get("binding kind", "")).strip("_").upper()
        if not cid:
            issues.append("invalid constituent ID")
            continue
        if cid in seen:
            issues.append(f"duplicate constituent ID {cid}")
            continue
        seen.add(cid)
        if not premise or not assertion:
            issues.append(f"{cid}: missing premise/assertion binding")
        if proof_scope not in {_HARM_SCOPE, *_MECHANISM_SCOPES}:
            issues.append(f"{cid}: invalid proof scope {proof_scope or '<empty>'}")
        if binding not in _BINDING_KINDS:
            issues.append(f"{cid}: invalid binding kind {binding or '<empty>'}")
        parsed.append({
            "constituent_id": cid,
            "harm_premise_id": premise,
            "assertion_id": assertion,
            "proof_scope": proof_scope,
            "binding_kind": binding,
        })
    if not parsed and not issues:
        issues.append("scope table contains no data rows")
    return parsed, issues


def _executed_failure_binding(content: str) -> tuple[bool, dict[str, str]]:
    attempted = _field(content, "Attempted").upper()
    compiled = _field(content, "Compiled").upper()
    result = _field(content, "Result").upper()
    test_file = _field(content, "Test File")
    command = _field(content, "Command")
    mechanical = _field(content, "Mechanical Status").upper()
    tag = _field(content, "Evidence Tag").upper()
    executed = (
        attempted == "YES"
        and compiled.startswith("YES")
        and (
            result.startswith("FAIL")
            or "FAIL" in mechanical
        )
        and "POC-FAIL" in tag
        and test_file.upper() not in {"", "N/A", "NA", "NONE"}
        and command.upper() not in {"", "N/A", "NA", "NONE"}
    )
    return executed, {
        "attempted": attempted,
        "compiled": compiled,
        "result": result,
        "mechanical_status": mechanical,
        "evidence_tag": tag,
        "test_file": test_file,
        "command": command,
    }


def assess_grouped_poc_failure(
    *,
    scratchpad: Path,
    hypothesis_id: str,
    verify_path: Path,
    verify_content: str,
    constituent_ids: Sequence[str],
    inventory_meta: Mapping[str, Mapping[str, str]],
    lexical_match_kind: str,
    lexical_scores: Sequence[tuple[str, float]],
) -> dict[str, Any]:
    """Return one deterministic scope decision for a grouped PoC failure."""
    root = Path(scratchpad)
    constituents = sorted(dict.fromkeys(cid.upper() for cid in constituent_ids))
    known = set(constituents)
    rows, parse_issues = _parse_scope_rows(verify_content)
    executed, execution = _executed_failure_binding(verify_content)
    unknown = sorted({row["constituent_id"] for row in rows} - known)
    if unknown:
        parse_issues.append("unknown constituent ID(s): " + ", ".join(unknown))

    scope_status = "AMBIGUOUS"
    authority = "NONE"
    demoted: list[str] = []
    preserved = list(constituents)
    repair = list(constituents)
    reason = "no exact constituent-to-harm assertion scope ledger"

    if not executed:
        scope_status = "EXECUTION_UNBOUND"
        reason = "grouped PoC failure lacks a mechanically bounded executed-test ledger"
    elif parse_issues:
        scope_status = "INVALID_SCOPE_LEDGER"
        reason = "; ".join(sorted(dict.fromkeys(parse_issues)))
    elif not rows:
        # Lexical similarity remains observable routing telemetry only.
        scope_status = "AMBIGUOUS"
        reason = "verifier supplied no constituent/premise/assertion binding"
    else:
        proof_scopes = {row["proof_scope"] for row in rows}
        binding_kinds = {row["binding_kind"] for row in rows}
        if proof_scopes & _MECHANISM_SCOPES:
            scope_status = "MECHANISM_ONLY"
            reason = "execution proves or disproves mechanism only, not claimed harm"
        elif binding_kinds == {"SHARED"}:
            row_ids = {row["constituent_id"] for row in rows}
            assertions = {row["assertion_id"] for row in rows}
            premises = {row["harm_premise_id"] for row in rows}
            if row_ids == known and len(assertions) == 1 and len(premises) == 1:
                scope_status = "SCOPED_SHARED_ALL"
                authority = "GROUP_WIDE"
                demoted = list(constituents)
                preserved = []
                repair = []
                reason = "every constituent is explicitly bound to the same executed harm assertion"
            else:
                scope_status = "AMBIGUOUS_SHARED_SCOPE"
                reason = "shared assertion does not bind the exact full constituent set"
        elif binding_kinds == {"EXACT"}:
            demoted = sorted(row["constituent_id"] for row in rows)
            preserved = sorted(known - set(demoted))
            repair = list(preserved)
            scope_status = "SCOPED_EXACT"
            authority = "EXACT_CONSTITUENT_ONLY"
            reason = "negative-review proposal limited to exact constituent/harm/assertion bindings"
        else:
            scope_status = "INVALID_SCOPE_LEDGER"
            reason = "mixed EXACT/SHARED scope cannot establish proof authority"

    # Bind the physical bytes, not ``Path.read_text``'s platform newline
    # projection. This keeps Windows CRLF receipts stable across resume.
    verify_hash = _file_sha256(verify_path) or _sha256_bytes(
        verify_content.encode("utf-8")
    )
    execution_evidence_id = "P0O-EV-" + _sha256_bytes(_canonical_json_bytes({
        "hypothesis_id": hypothesis_id,
        "verify_sha256": verify_hash,
        "execution": execution,
    }))[:20].upper()
    return {
        "hypothesis_id": hypothesis_id,
        "scope_status": scope_status,
        # Compatibility field: this classifies the maximum *scope of the
        # proposal*.  It is not severity/lifecycle authority.
        "demotion_authority": authority,
        "severity_effect_authority": "NONE",
        "severity_mutation_authorized": False,
        "constituent_ids": constituents,
        "demoted_constituent_ids": demoted,
        "preserved_constituent_ids": preserved,
        "reverification_constituent_ids": repair,
        "requires_split_projection": authority == "EXACT_CONSTITUENT_ONLY",
        "scope_rows": rows,
        "scope_issues": sorted(dict.fromkeys(parse_issues)),
        "reason": reason,
        "execution": execution,
        "execution_evidence_id": execution_evidence_id,
        "source_verify_file": verify_path.name,
        "source_verify_sha256": verify_hash,
        "lexical_routing_telemetry": {
            "match_kind": lexical_match_kind,
            "scores": [
                {"constituent_id": cid, "jaccard": round(float(score), 6)}
                for cid, score in sorted(lexical_scores)
            ],
            "authority": "NONE",
        },
        "pre_demotion_records": [
            {
                "constituent_id": cid,
                "severity": str(inventory_meta.get(cid, {}).get("severity") or "Unknown"),
                "title": str(inventory_meta.get(cid, {}).get("title") or cid),
                "location": str(inventory_meta.get(cid, {}).get("location") or "Unresolved"),
            }
            for cid in constituents
        ],
    }


def write_grouped_poc_scope_artifacts(
    scratchpad: Path,
    groups: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Persist scope receipt + bounded repair work idempotently and atomically."""
    root = Path(scratchpad)
    normalized_groups = []
    for group in sorted(groups, key=lambda g: str(g["hypothesis_id"])):
        normalized = dict(group)
        normalized["severity_effect_authority"] = "NONE"
        normalized["severity_mutation_authorized"] = False
        normalized_groups.append(normalized)
    input_files = (
        "verification_queue.md",
        "verification_queue.json",
        "finding_mapping.md",
        "hypotheses.md",
        "chain_hypotheses.md",
        "findings_inventory.md",
    )
    input_digests = {
        name: digest
        for name in input_files
        if (digest := _file_sha256(root / name)) is not None
    }
    receipt: dict[str, Any] = {
        "schema": SCOPE_SCHEMA,
        "authority": "SCOPE_PROPOSAL_ONLY",
        "severity_mutation_authorized": False,
        "report_authoritative": False,
        "input_digests": input_digests,
        "groups": normalized_groups,
        "monotonicity": "negative scope evidence cannot lower severity",
    }
    _write_json(root / "poc_demotion_scope_receipt.json", receipt)

    work_items: list[dict[str, Any]] = []
    for group in normalized_groups:
        pending = list(group.get("reverification_constituent_ids") or [])
        if not pending:
            continue
        record_by_id = {
            str(row.get("constituent_id")): row
            for row in group.get("pre_demotion_records") or []
        }
        item_core = {
            "hypothesis_id": str(group.get("hypothesis_id") or ""),
            "constituent_ids": pending,
            "reason": str(group.get("reason") or "ambiguous proof scope"),
            "execution_evidence_id": str(group.get("execution_evidence_id") or ""),
            "source_verify_sha256": str(group.get("source_verify_sha256") or ""),
        }
        work_id = "P0O-WORK-" + _sha256_bytes(_canonical_json_bytes(item_core))[:20].upper()
        work_items.append({
            "work_id": work_id,
            **item_core,
            "constituents": [record_by_id[cid] for cid in pending if cid in record_by_id],
            "status": "PENDING_REVERIFICATION",
            "fallback_if_unavailable": "UNVERIFIED_UNRESOLVED_HUMAN_REVIEW",
            "retention_until_closed": "PRE_DEMOTION_SEVERITY_REPORT_VISIBLE",
        })
    repair: dict[str, Any] = {
        "schema": REPAIR_SCHEMA,
        "authority": "ADDITIVE_REVERIFICATION_WORK_ONLY",
        "source_scope_receipt_digest": receipt["receipt_digest"],
        "work_items": work_items,
    }
    _write_json(root / "poc_demotion_scope_repair.json", repair)

    md_path = root / "poc_demotion_scope_debt.md"
    if work_items:
        lines = [
            "# Grouped PoC Proof-Scope Repair Debt\n\n",
            "These constituents retain their pre-demotion severity until bounded "
            "reverification closes the exact proof-scope obligation. This file is "
            "human-review visibility, not demotion authority.\n\n",
            "| Work ID | Hypothesis ID | Constituents | State | Retention |\n",
            "|---|---|---|---|---|\n",
        ]
        for item in work_items:
            lines.append(
                f"| {item['work_id']} | {item['hypothesis_id']} | "
                f"{', '.join(item['constituent_ids'])} | {item['status']} | "
                f"{item['retention_until_closed']} |\n"
            )
        _atomic_write(md_path, "".join(lines).encode("utf-8"))
    elif md_path.exists():
        md_path.unlink()
    return receipt, repair


def load_validated_scope_repair(
    scratchpad: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load the exact P0-O scope/repair authority or raise.

    Validation is deliberately cross-artifact and source-bound. A valid
    self-digest on one JSON file is not enough to schedule work.
    """
    root = Path(scratchpad)
    scope = _read_strict_json(root / "poc_demotion_scope_receipt.json")
    repair = _read_strict_json(root / "poc_demotion_scope_repair.json")
    _validate_receipt_digest(scope, "grouped PoC scope")
    _validate_receipt_digest(repair, "grouped PoC repair")
    if scope.get("schema") != SCOPE_SCHEMA:
        raise ValueError("unsupported grouped PoC scope schema")
    if repair.get("schema") != REPAIR_SCHEMA:
        raise ValueError("unsupported grouped PoC repair schema")
    if repair.get("source_scope_receipt_digest") != scope["receipt_digest"]:
        raise ValueError("grouped PoC repair is stale for scope receipt")
    if scope.get("authority") != "SCOPE_PROPOSAL_ONLY":
        raise ValueError("grouped PoC scope authority marker mismatch")
    if scope.get("severity_mutation_authorized") is not False:
        raise ValueError("grouped PoC scope unexpectedly authorizes severity mutation")
    if scope.get("report_authoritative") is not False:
        raise ValueError("grouped PoC scope unexpectedly gained report authority")
    if repair.get("authority") != "ADDITIVE_REVERIFICATION_WORK_ONLY":
        raise ValueError("grouped PoC repair authority marker mismatch")
    groups = scope.get("groups")
    work_items = repair.get("work_items")
    if not isinstance(groups, list) or not isinstance(work_items, list):
        raise TypeError("grouped PoC scope/repair rows must be JSON arrays")
    groups_by_id: dict[str, dict[str, Any]] = {}
    for group in groups:
        if not isinstance(group, dict):
            raise TypeError("grouped PoC scope group must be an object")
        hypothesis_id = str(group.get("hypothesis_id") or "")
        if not hypothesis_id or hypothesis_id in groups_by_id:
            raise ValueError("grouped PoC scope hypothesis identities are invalid")
        source_name = str(group.get("source_verify_file") or "")
        source_hash = str(group.get("source_verify_sha256") or "")
        if not source_name or not re.fullmatch(r"verify_[A-Za-z0-9_.-]+\.md", source_name):
            raise ValueError(f"{hypothesis_id} source verify filename is invalid")
        if _file_sha256(root / source_name) != source_hash:
            raise ValueError(f"{hypothesis_id} source verifier bytes changed")
        groups_by_id[hypothesis_id] = group

    seen_constituents: set[str] = set()
    for item in work_items:
        if not isinstance(item, dict):
            raise TypeError("grouped PoC repair item must be an object")
        hypothesis_id = str(item.get("hypothesis_id") or "")
        group = groups_by_id.get(hypothesis_id)
        if group is None:
            raise ValueError(f"repair item references unknown group {hypothesis_id}")
        constituent_ids = item.get("constituent_ids")
        if not isinstance(constituent_ids, list) or not constituent_ids:
            raise ValueError(f"{hypothesis_id} repair has no constituent IDs")
        normalized = [_normalize_id(str(value)) for value in constituent_ids]
        if any(not value for value in normalized) or len(set(normalized)) != len(normalized):
            raise ValueError(f"{hypothesis_id} repair constituent identities are invalid")
        if normalized != list(group.get("reverification_constituent_ids") or []):
            raise ValueError(f"{hypothesis_id} repair denominator differs from scope receipt")
        overlap = seen_constituents & set(normalized)
        if overlap:
            raise ValueError(
                "constituent appears in multiple grouped repair items: "
                + ", ".join(sorted(overlap))
            )
        seen_constituents.update(normalized)
        if item.get("status") != "PENDING_REVERIFICATION":
            raise ValueError(f"{hypothesis_id} repair status is not pending")
        if item.get("retention_until_closed") != "PRE_DEMOTION_SEVERITY_REPORT_VISIBLE":
            raise ValueError(f"{hypothesis_id} repair retention policy mismatch")
        item_core = {
            "hypothesis_id": hypothesis_id,
            "constituent_ids": normalized,
            "reason": str(item.get("reason") or ""),
            "execution_evidence_id": str(item.get("execution_evidence_id") or ""),
            "source_verify_sha256": str(item.get("source_verify_sha256") or ""),
        }
        expected_work_id = "P0O-WORK-" + _sha256_bytes(
            _canonical_json_bytes(item_core)
        )[:20].upper()
        if item.get("work_id") != expected_work_id:
            raise ValueError(f"{hypothesis_id} repair work identity mismatch")
        if item_core["source_verify_sha256"] != group.get("source_verify_sha256"):
            raise ValueError(f"{hypothesis_id} repair source binding mismatch")
        records = item.get("constituents")
        if not isinstance(records, list):
            raise TypeError(f"{hypothesis_id} repair constituent records must be an array")
        records_by_id = {
            _normalize_id(str(record.get("constituent_id") or "")): record
            for record in records
            if isinstance(record, dict)
        }
        if set(records_by_id) != set(normalized):
            raise ValueError(f"{hypothesis_id} repair record coverage mismatch")
        for cid, record in records_by_id.items():
            if not str(record.get("severity") or "").strip():
                raise ValueError(f"{cid} repair severity is missing")
            if not str(record.get("title") or "").strip():
                raise ValueError(f"{cid} repair title is missing")
            if not str(record.get("location") or "").strip():
                raise ValueError(f"{cid} repair location is missing")
    return scope, repair


def _compile_scope_recovery_plan(
    scope: Mapping[str, Any],
    repair: Mapping[str, Any],
    *,
    max_findings_per_unit: int,
) -> dict[str, Any]:
    if isinstance(max_findings_per_unit, bool) or not isinstance(max_findings_per_unit, int):
        raise TypeError("max_findings_per_unit must be an integer")
    if not 1 <= max_findings_per_unit <= 4:
        raise ValueError("grouped PoC recovery unit bound must be between 1 and 4")
    ordered_rows: list[dict[str, str]] = []
    for item in repair["work_items"]:
        records = {
            str(record["constituent_id"]): record
            for record in item["constituents"]
        }
        for cid in item["constituent_ids"]:
            record = records[cid]
            ordered_rows.append({
                "finding id": cid,
                "severity": str(record["severity"]),
                "title": str(record["title"]),
                "location": str(record["location"]),
                "bug class": "grouped-proof-scope-repair",
                "preferred tag": "[CODE-TRACE]",
                "primary artifact": str(item["hypothesis_id"]),
                "poc class": "structural",
                "scope work id": str(item["work_id"]),
                "scope receipt digest": str(scope["receipt_digest"]),
            })
    plan_core = {
        "schema": RECOVERY_PLAN_SCHEMA,
        "source_scope_receipt_digest": scope["receipt_digest"],
        "source_repair_receipt_digest": repair["receipt_digest"],
        "max_findings_per_unit": max_findings_per_unit,
        "ordered_constituent_ids": [row["finding id"] for row in ordered_rows],
    }
    namespace = _sha256_bytes(_canonical_json_bytes(plan_core))[:12]
    units: list[dict[str, Any]] = []
    for offset in range(0, len(ordered_rows), max_findings_per_unit):
        rows = ordered_rows[offset: offset + max_findings_per_unit]
        ordinal = len(units) + 1
        unit_core = {
            "unit_id": f"p0o-repair-{namespace}-{ordinal:04d}",
            "ordinal": ordinal,
            "rows": rows,
            "expected_output_files": [
                output_name
                for row in rows
                for output_name in (
                    f"verify_{row['finding id']}.md",
                    f"verify_{row['finding id']}.severity_proposal.json",
                )
            ],
        }
        units.append({**unit_core, "unit_digest": _sha256_bytes(_canonical_json_bytes(unit_core))})
    plan: dict[str, Any] = {**plan_core, "units": units}
    plan["receipt_digest"] = _receipt_digest(plan)
    return plan


def build_scope_recovery_plan(
    scratchpad: Path,
    *,
    max_findings_per_unit: int = 4,
) -> dict[str, Any]:
    """Compile pending exact IDs into bounded, deterministic recovery units."""
    scope, repair = load_validated_scope_repair(scratchpad)
    plan = _compile_scope_recovery_plan(
        scope, repair, max_findings_per_unit=max_findings_per_unit
    )
    _write_json(Path(scratchpad) / "poc_demotion_scope_recovery_plan.json", plan)
    return plan


def load_validated_recovery_plan(scratchpad: Path) -> dict[str, Any]:
    """Load a plan only when it exactly matches the current scope/repair debt."""
    root = Path(scratchpad)
    plan = _read_strict_json(root / "poc_demotion_scope_recovery_plan.json")
    _validate_receipt_digest(plan, "grouped PoC recovery plan")
    if plan.get("schema") != RECOVERY_PLAN_SCHEMA:
        raise ValueError("unsupported grouped PoC recovery plan schema")
    bound = plan.get("max_findings_per_unit")
    scope, repair = load_validated_scope_repair(root)
    expected = _compile_scope_recovery_plan(
        scope, repair, max_findings_per_unit=bound
    )
    if plan != expected:
        raise ValueError("grouped PoC recovery plan differs from current debt")
    return plan


def recovery_unit_paths(scratchpad: Path, unit_id: str) -> dict[str, Path]:
    if not re.fullmatch(r"p0o-repair-[0-9a-f]{12}-\d{4}", unit_id):
        raise ValueError("invalid grouped PoC recovery unit identity")
    directory = Path(scratchpad) / RECOVERY_DIR / unit_id
    return {
        "directory": directory,
        "attempt": directory / "attempt.json",
        "manifest": directory / "manifest.md",
        "prompt": directory / "prompt.md",
        "receipt": directory / "receipt.json",
        "debt": directory / "debt.json",
    }


def write_recovery_attempt(
    scratchpad: Path,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
) -> dict[str, Any]:
    """Arm one immutable at-most-once unit before provider launch."""
    paths = recovery_unit_paths(scratchpad, str(unit["unit_id"]))
    paths["directory"].mkdir(parents=True, exist_ok=True)
    if paths["attempt"].is_file():
        recorded = _read_strict_json(paths["attempt"])
        _validate_receipt_digest(recorded, "grouped PoC recovery attempt")
        if recorded.get("schema") != RECOVERY_ATTEMPT_SCHEMA:
            raise ValueError("unsupported grouped PoC recovery attempt schema")
        if recorded.get("plan_receipt_digest") != plan.get("receipt_digest"):
            raise ValueError("grouped PoC recovery attempt plan drift")
        if recorded.get("unit_id") != unit.get("unit_id") or recorded.get("unit_digest") != unit.get("unit_digest"):
            raise ValueError("grouped PoC recovery attempt unit drift")
        expected_ids = [str(row["finding id"]) for row in unit["rows"]]
        if recorded.get("ordered_constituent_ids") != expected_ids:
            raise ValueError("grouped PoC recovery attempt denominator drift")
        if recorded.get("expected_output_files") != unit.get("expected_output_files"):
            raise ValueError("grouped PoC recovery attempt output ownership drift")
        return recorded
    before: dict[str, dict[str, Any]] = {}
    for name in unit["expected_output_files"]:
        path = Path(scratchpad) / str(name)
        before[str(name)] = {
            "exists": path.is_file(),
            "sha256": _file_sha256(path),
        }
    attempt: dict[str, Any] = {
        "schema": RECOVERY_ATTEMPT_SCHEMA,
        "state": "ARMED",
        "plan_receipt_digest": str(plan["receipt_digest"]),
        "unit_id": str(unit["unit_id"]),
        "unit_digest": str(unit["unit_digest"]),
        "ordered_constituent_ids": [
            str(row["finding id"]) for row in unit["rows"]
        ],
        "expected_output_files": list(unit["expected_output_files"]),
        "outputs_before_launch": before,
        "launch_policy": "FOREGROUND_BOUNDED_LATE_RECOVERY",
        "max_findings": int(plan["max_findings_per_unit"]),
    }
    _write_json(paths["attempt"], attempt)
    return attempt


def write_recovery_unit_receipt(
    scratchpad: Path,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
    *,
    status: str,
    issues: Sequence[str] = (),
    prompt_sha256: str | None = None,
) -> dict[str, Any]:
    if status not in {"COMPLETED", "DEBT"}:
        raise ValueError("grouped PoC recovery receipt status is invalid")
    normalized_issues = list(dict.fromkeys(
        str(issue) for issue in issues if str(issue)
    ))
    if status == "COMPLETED" and normalized_issues:
        raise ValueError("COMPLETED grouped PoC recovery receipt cannot retain issues")
    if status == "DEBT" and not normalized_issues:
        raise ValueError("DEBT grouped PoC recovery receipt requires an issue")
    paths = recovery_unit_paths(scratchpad, str(unit["unit_id"]))
    attempt = _read_strict_json(paths["attempt"])
    _validate_receipt_digest(attempt, "grouped PoC recovery attempt")
    if attempt.get("unit_digest") != unit.get("unit_digest"):
        raise ValueError("grouped PoC recovery attempt/unit mismatch")
    output_records: dict[str, dict[str, Any]] = {}
    for name in unit["expected_output_files"]:
        path = Path(scratchpad) / str(name)
        output_records[str(name)] = {
            "exists": path.is_file(),
            "sha256": _file_sha256(path),
            "size_bytes": path.stat().st_size if path.is_file() else 0,
        }
    if status == "COMPLETED" and any(
        not record["exists"] or not record["sha256"] or record["size_bytes"] <= 0
        for record in output_records.values()
    ):
        raise ValueError(
            "COMPLETED grouped PoC recovery receipt requires every bound output"
        )
    receipt: dict[str, Any] = {
        "schema": RECOVERY_UNIT_RECEIPT_SCHEMA,
        "status": status,
        "proof_authority": "INDEPENDENT_REVERIFICATION" if status == "COMPLETED" else "NONE",
        "plan_receipt_digest": str(plan["receipt_digest"]),
        "unit_id": str(unit["unit_id"]),
        "unit_digest": str(unit["unit_digest"]),
        "attempt_receipt_digest": str(attempt["receipt_digest"]),
        "ordered_constituent_ids": [str(row["finding id"]) for row in unit["rows"]],
        "expected_output_files": list(unit["expected_output_files"]),
        "output_records": output_records,
        "prompt_sha256": prompt_sha256,
        "issues": normalized_issues,
        "fallback_action": (
            "NONE" if status == "COMPLETED"
            else "RETAIN_PRE_DEMOTION_SEVERITY_FOR_HUMAN_REVIEW"
        ),
    }
    _write_json(paths["receipt"], receipt)
    if status == "DEBT":
        _write_json(paths["debt"], {
            "schema": "plamen.poc_demotion_scope_recovery_debt.v1",
            "unit_id": unit["unit_id"],
            "affected_constituent_ids": receipt["ordered_constituent_ids"],
            "issues": receipt["issues"],
            "retention": "PRE_DEMOTION_SEVERITY_REPORT_VISIBLE",
        })
    elif paths["debt"].exists():
        paths["debt"].unlink()
    return receipt


def validate_recovery_unit_receipt(
    scratchpad: Path,
    plan: Mapping[str, Any],
    unit: Mapping[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    paths = recovery_unit_paths(scratchpad, str(unit["unit_id"]))
    if not paths["receipt"].is_file():
        return None, [f"{unit['unit_id']}: recovery receipt missing"]
    try:
        receipt = _read_strict_json(paths["receipt"])
        _validate_receipt_digest(receipt, "grouped PoC recovery unit")
        if receipt.get("schema") != RECOVERY_UNIT_RECEIPT_SCHEMA:
            raise ValueError("unsupported grouped PoC recovery unit schema")
        if receipt.get("plan_receipt_digest") != plan.get("receipt_digest"):
            raise ValueError("grouped PoC recovery unit plan binding mismatch")
        if receipt.get("unit_id") != unit.get("unit_id") or receipt.get("unit_digest") != unit.get("unit_digest"):
            raise ValueError("grouped PoC recovery unit identity mismatch")
        expected_ids = [str(row["finding id"]) for row in unit["rows"]]
        if receipt.get("ordered_constituent_ids") != expected_ids:
            raise ValueError("grouped PoC recovery unit denominator mismatch")
        if receipt.get("expected_output_files") != unit.get("expected_output_files"):
            raise ValueError("grouped PoC recovery unit output ownership mismatch")
        status = str(receipt.get("status") or "")
        issues = receipt.get("issues")
        if not isinstance(issues, list) or any(not isinstance(issue, str) for issue in issues):
            raise TypeError("grouped PoC recovery unit issues are invalid")
        if status == "COMPLETED":
            if receipt.get("proof_authority") != "INDEPENDENT_REVERIFICATION":
                raise ValueError("completed grouped PoC recovery authority mismatch")
            if issues:
                raise ValueError("completed grouped PoC recovery retained debt")
            if receipt.get("fallback_action") != "NONE":
                raise ValueError("completed grouped PoC recovery fallback mismatch")
        elif status == "DEBT":
            if receipt.get("proof_authority") != "NONE":
                raise ValueError("debt grouped PoC recovery gained proof authority")
            if not issues:
                raise ValueError("debt grouped PoC recovery lacks an issue")
            if receipt.get("fallback_action") != "RETAIN_PRE_DEMOTION_SEVERITY_FOR_HUMAN_REVIEW":
                raise ValueError("debt grouped PoC recovery retention mismatch")
        else:
            raise ValueError("grouped PoC recovery unit status is invalid")
        for name in unit["expected_output_files"]:
            record = (receipt.get("output_records") or {}).get(name)
            path = Path(scratchpad) / str(name)
            if not isinstance(record, dict):
                raise ValueError(f"{name} recovery output record missing")
            if record.get("exists") != path.is_file() or record.get("sha256") != _file_sha256(path):
                raise ValueError(f"{name} recovery output bytes changed")
            if record.get("size_bytes") != (path.stat().st_size if path.is_file() else 0):
                raise ValueError(f"{name} recovery output size changed")
            if status == "COMPLETED" and (
                not path.is_file()
                or not record.get("sha256")
                or int(record.get("size_bytes") or 0) <= 0
            ):
                raise ValueError(f"{name} completed recovery output is absent")
        return receipt, []
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return None, [
            f"{unit['unit_id']}: recovery receipt invalid: {type(exc).__name__}: {exc}"
        ]


def write_recovery_status(
    scratchpad: Path,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    states: list[dict[str, Any]] = []
    recovered: list[str] = []
    unresolved: list[str] = []
    for unit in plan["units"]:
        receipt, issues = validate_recovery_unit_receipt(scratchpad, plan, unit)
        status = str(receipt.get("status")) if receipt else "PENDING"
        ids = [str(row["finding id"]) for row in unit["rows"]]
        if status == "COMPLETED" and not issues:
            recovered.extend(ids)
        else:
            unresolved.extend(ids)
        states.append({
            "unit_id": unit["unit_id"],
            "status": status,
            "constituent_ids": ids,
            "issues": issues or list((receipt or {}).get("issues") or []),
        })
    payload: dict[str, Any] = {
        "schema": RECOVERY_STATUS_SCHEMA,
        "state": "CLEAN" if not unresolved else "COMPLETED_WITH_DEBT",
        "plan_receipt_digest": str(plan["receipt_digest"]),
        "source_scope_receipt_digest": str(plan["source_scope_receipt_digest"]),
        "source_repair_receipt_digest": str(plan["source_repair_receipt_digest"]),
        "recovered_constituent_ids": recovered,
        "unresolved_constituent_ids": unresolved,
        "unit_states": states,
        "unresolved_retention": "PRE_DEMOTION_SEVERITY_REPORT_VISIBLE",
    }
    _write_json(Path(scratchpad) / "poc_demotion_scope_recovery_status.json", payload)
    return payload


def load_validated_recovery_status(scratchpad: Path) -> dict[str, Any]:
    """Load the driver status and re-prove every unit/output binding.

    Report consumers use this instead of trusting a free-standing JSON marker.
    A missing or invalid status is ordinary pending repair, never permission to
    lower a constituent's retained severity.
    """
    root = Path(scratchpad)
    plan = load_validated_recovery_plan(root)
    status = _read_strict_json(root / "poc_demotion_scope_recovery_status.json")
    _validate_receipt_digest(status, "grouped PoC recovery status")
    if status.get("schema") != RECOVERY_STATUS_SCHEMA:
        raise ValueError("unsupported grouped PoC recovery status schema")
    if status.get("plan_receipt_digest") != plan.get("receipt_digest"):
        raise ValueError("grouped PoC recovery status plan binding mismatch")
    for field in (
        "source_scope_receipt_digest",
        "source_repair_receipt_digest",
    ):
        if status.get(field) != plan.get(field):
            raise ValueError(f"grouped PoC recovery status {field} mismatch")

    states = status.get("unit_states")
    if not isinstance(states, list) or len(states) != len(plan["units"]):
        raise ValueError("grouped PoC recovery status unit denominator mismatch")
    recovered: list[str] = []
    unresolved: list[str] = []
    expected_states: list[dict[str, Any]] = []
    for unit in plan["units"]:
        receipt, validation_issues = validate_recovery_unit_receipt(root, plan, unit)
        receipt_status = str(receipt.get("status")) if receipt else "PENDING"
        ids = [str(row["finding id"]) for row in unit["rows"]]
        if receipt_status == "COMPLETED" and not validation_issues:
            recovered.extend(ids)
        else:
            unresolved.extend(ids)
        expected_states.append({
            "unit_id": unit["unit_id"],
            "status": receipt_status,
            "constituent_ids": ids,
            "issues": validation_issues or list((receipt or {}).get("issues") or []),
        })
    if status.get("unit_states") != expected_states:
        raise ValueError("grouped PoC recovery status differs from unit receipts")
    if status.get("recovered_constituent_ids") != recovered:
        raise ValueError("grouped PoC recovery recovered-set mismatch")
    if status.get("unresolved_constituent_ids") != unresolved:
        raise ValueError("grouped PoC recovery unresolved-set mismatch")
    expected_state = "CLEAN" if not unresolved else "COMPLETED_WITH_DEBT"
    if status.get("state") != expected_state:
        raise ValueError("grouped PoC recovery summary state mismatch")
    if status.get("unresolved_retention") != "PRE_DEMOTION_SEVERITY_REPORT_VISIBLE":
        raise ValueError("grouped PoC recovery status retention mismatch")
    return status
