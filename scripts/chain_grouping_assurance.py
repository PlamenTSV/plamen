"""P0-W post-delivery assurance reconciliation for chain relations.

``chain_grouping_relations.json`` is proposal/relation telemetry.  It carries
no authority to collapse findings and its ordinary ``INDEPENDENT_MEMBERS``
state is not itself a client-visible limitation.  This module closes the
separate, later question: did every exact relation member independently pass
through the *current* typed verifier transaction and an exact report delivery?

The resulting receipt is monotonic.  It can only record an independently
delivered member or retain an exact, content-bearing member as human-review
debt.  It has no identity, confidence, severity, demotion, deletion, alias, or
collapse authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping

from chain_grouping_authority import (
    APPLIED_FILE,
    RELATION_FILE,
    load_validated_chain_grouping_relations,
)
from queue_work_items import (
    QueueWorkPlan,
    queue_record_set_digest,
    queue_records_from_json,
)
from report_disposition_authority import (
    APPENDIX_SIDECAR_NAME,
    AUTHORITY_NAME as REPORT_AUTHORITY_FILE,
    validate_report_disposition_authority,
)
from verifier_work_roster import VerifierWorkRoster
from preverify_projection_authority import (
    resolve_active_preverify_projection,
    successor_projection_present,
)


ASSURANCE_SCHEMA = "plamen.chain_grouping_assurance_reconciliation.v1"
DEBT_SCHEMA = "plamen.chain_grouping_assurance_debt.v1"
ASSURANCE_FILE = "chain_grouping_assurance_reconciliation.json"
LIMITATIONS_FILE = "chain_grouping_assurance_limitations.md"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_FINDING_HEADING_RE = re.compile(
    r"^#{2,4}\s*Finding\s*\[\s*"
    r"([A-Za-z][A-Za-z0-9_-]{1,95})\s*\]\s*:\s*(.+?)\s*$",
    re.MULTILINE | re.ASCII,
)
_STAGE_ORDER = (
    "SOURCE_CONTENT_BINDING",
    "CURRENT_QUEUE_WORK_ITEM",
    "CURRENT_QUEUE_WORK_PLAN",
    "CURRENT_VERIFIER_ROSTER",
    "EXACT_VERIFIER_EXECUTION",
    "EXACT_REPORT_DELIVERY",
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_sha(path: Path) -> str | None:
    try:
        return _sha_bytes(path.read_bytes())
    except OSError:
        return None


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def _strict_json(path: Path) -> dict[str, Any]:
    def _reject(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    parsed = json.loads(
        path.read_text(encoding="utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject,
    )
    if not isinstance(parsed, dict):
        raise TypeError(f"{path.name} must contain one JSON object")
    return parsed


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.p0w-assurance.tmp")
    with open(temporary, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _inventory_records(root: Path) -> tuple[dict[str, dict[str, str]], str]:
    if successor_projection_present(root):
        projection = resolve_active_preverify_projection(root)
        raw = projection["inventory_raw"]
        text = projection["inventory_text"]
    else:
        path = root / "findings_inventory.md"
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    matches = list(_FINDING_HEADING_RE.finditer(text))
    records: dict[str, dict[str, str]] = {}
    for index, match in enumerate(matches):
        member_id = match.group(1).strip().upper()
        if member_id in records:
            # Duplicate identity makes exact content ambiguous.  Retain no
            # arbitrary block; the reconciliation will expose source-binding
            # debt for that identity.
            records[member_id] = {
                "state": "AMBIGUOUS",
                "title": "",
                "content": "",
                "sha256": _sha_bytes(b""),
            }
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        content = text[match.start():end]
        records[member_id] = {
            "state": "BOUND",
            "title": match.group(2).strip(),
            "content": content,
            "sha256": _sha_bytes(content.encode("utf-8")),
        }
    return records, _sha_bytes(raw)


def _load_current_authority(
    root: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Load each authority layer independently and fail toward retention."""

    issues: list[str] = []
    items = ()
    plan: QueueWorkPlan | None = None
    roster: VerifierWorkRoster | None = None
    report: dict[str, Any] | None = None

    try:
        items = queue_records_from_json(
            (root / "verification_queue.work_items.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        issues.append(
            f"current typed queue unavailable: {type(exc).__name__}: {exc}"
        )

    try:
        plan = QueueWorkPlan.from_json(
            (root / "verification_queue.work_plan.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
        plan.validate_against(items)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        plan = None
        issues.append(
            f"current QueueWorkPlan unavailable: {type(exc).__name__}: {exc}"
        )

    try:
        roster = VerifierWorkRoster.from_json(
            (root / "verification_runtime_roster.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
        if plan is None:
            raise ValueError("current QueueWorkPlan is unavailable")
        if roster.parent_queue_work_plan_digest != plan.digest:
            raise ValueError("verifier roster is stale for current QueueWorkPlan")
        if roster.ordered_work_item_ids != plan.ordered_work_item_ids:
            raise ValueError("verifier roster denominator differs from QueueWorkPlan")
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        roster = None
        issues.append(
            f"current verifier roster unavailable: {type(exc).__name__}: {exc}"
        )

    try:
        report = validate_report_disposition_authority(
            root, project_root, run_id=run_id
        )
        if plan is None or roster is None:
            raise ValueError("current verifier transaction is unavailable")
        report_ids = [str(row.get("candidate_id") or "") for row in report["rows"]]
        if len(report_ids) != len(set(report_ids)):
            raise ValueError("report disposition authority has duplicate candidate IDs")
        if set(report_ids) != set(plan.ordered_work_item_ids):
            raise ValueError(
                "report disposition denominator differs from current QueueWorkPlan"
            )
    except (OSError, UnicodeError, TypeError, ValueError, KeyError) as exc:
        report = None
        issues.append(
            f"current report delivery authority unavailable: {type(exc).__name__}: {exc}"
        )

    item_by_id = {item.work_item_id: item for item in items}
    plan_ids = set(plan.ordered_work_item_ids) if plan is not None else set()
    roster_ids = set(roster.ordered_work_item_ids) if roster is not None else set()
    report_by_id = (
        {str(row["candidate_id"]): row for row in report["rows"]}
        if report is not None
        else {}
    )
    provider_sources: dict[str, str] = {}
    if report is not None:
        for source in report.get("source_artifacts") or []:
            path = str(source.get("path") or "")
            if (
                path.startswith("_verifier_runtime_units/")
                or path.startswith("verify_")
            ):
                provider_sources[path] = str(source.get("sha256") or "")

    return {
        "issues": sorted(set(issues)),
        "items": item_by_id,
        "plan": plan,
        "plan_ids": plan_ids,
        "roster": roster,
        "roster_ids": roster_ids,
        "report": report,
        "report_by_id": report_by_id,
        "provider_sources": dict(sorted(provider_sources.items())),
    }


def _member_stage_states(member_id: str, current: Mapping[str, Any]) -> dict[str, bool]:
    row = current["report_by_id"].get(member_id)
    return {
        "CURRENT_QUEUE_WORK_ITEM": member_id in current["items"],
        "CURRENT_QUEUE_WORK_PLAN": member_id in current["plan_ids"],
        "CURRENT_VERIFIER_ROSTER": member_id in current["roster_ids"],
        "EXACT_VERIFIER_EXECUTION": bool(
            row and str(row.get("verifier_receipt_digest") or "")
        ),
        "EXACT_REPORT_DELIVERY": bool(
            row
            and row.get("identity_accounted") is True
            and row.get("visible_debt") is False
            and str(row.get("public_retention_target") or "")
            in {"BODY", "APPENDIX", "EXCLUDED"}
        ),
    }


def _source_bindings(
    root: Path,
    project_root: Path,
    relation: Mapping[str, Any],
    inventory_sha256: str,
    current: Mapping[str, Any],
) -> dict[str, Any]:
    plan = current["plan"]
    roster = current["roster"]
    report = current["report"]
    item_values = tuple(current["items"].values())
    return {
        "relation_receipt_digest": relation["receipt_digest"],
        "relation_file_sha256": _file_sha(root / RELATION_FILE),
        "applied_relation_file_sha256": _file_sha(root / APPLIED_FILE),
        "findings_inventory_sha256": inventory_sha256,
        "queue_record_set_digest": (
            queue_record_set_digest(item_values) if item_values else None
        ),
        "queue_work_items_file_sha256": _file_sha(
            root / "verification_queue.work_items.json"
        ),
        "queue_work_plan_digest": plan.digest if plan is not None else None,
        "queue_work_plan_file_sha256": _file_sha(
            root / "verification_queue.work_plan.json"
        ),
        "verifier_roster_digest": roster.digest if roster is not None else None,
        "verifier_roster_file_sha256": _file_sha(
            root / "verification_runtime_roster.json"
        ),
        "provider_artifact_sha256": current["provider_sources"],
        "report_disposition_receipt_sha256": (
            report.get("receipt_sha256") if report is not None else None
        ),
        "report_disposition_source_set_sha256": (
            report.get("source_set_sha256") if report is not None else None
        ),
        "report_disposition_file_sha256": _file_sha(root / REPORT_AUTHORITY_FILE),
        "report_delivery_sidecar_sha256": _file_sha(
            root / APPENDIX_SIDECAR_NAME
        ),
        # Do not bind the mutable report envelope here.  The independently
        # validated report-disposition authority above proves exact finding
        # delivery and replays its body/appendix preservation predicates from
        # the current report.  A later driver-owned assurance projection is
        # allowed to append its managed limitation block without changing any
        # finding delivery.  The report_floor assurance PhaseIO transaction
        # separately binds the final AUDIT_REPORT.md bytes after that last
        # mutation.  Hashing the envelope at both layers would create a cycle:
        # projecting this receipt's debts would immediately stale this receipt.
        "report_envelope_authority": "FINAL_ASSURANCE_PHASE_IO",
    }


def build_chain_grouping_assurance(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    root = Path(scratchpad)
    project = Path(project_root)
    relation = load_validated_chain_grouping_relations(root)
    inventory_records, inventory_sha256 = _inventory_records(root)
    current = _load_current_authority(root, project, run_id=run_id)

    memberships: dict[str, list[str]] = {}
    for group in relation["groups"]:
        for member_id in group["members"]:
            memberships.setdefault(str(member_id), []).append(str(group["group_id"]))

    reconciled: list[dict[str, Any]] = []
    debts: list[dict[str, Any]] = []
    for member_id in sorted(memberships, key=lambda value: (value.casefold(), value)):
        source = inventory_records.get(
            member_id,
            {
                "state": "MISSING",
                "title": "",
                "content": "",
                "sha256": _sha_bytes(b""),
            },
        )
        stage_states = _member_stage_states(member_id, current)
        source_bound = source["state"] == "BOUND"
        all_stages = source_bound and all(stage_states.values())
        missing = [
            stage
            for stage in _STAGE_ORDER
            if (
                not source_bound
                if stage == "SOURCE_CONTENT_BINDING"
                else not stage_states[stage]
            )
        ]
        row = {
            "member_id": member_id,
            "group_ids": sorted(set(memberships[member_id])),
            "state": (
                "INDEPENDENTLY_DELIVERED"
                if all_stages
                else "CLIENT_HUMAN_REVIEW_LIMITATION"
            ),
            "source_record_state": source["state"],
            "source_record_sha256": source["sha256"],
            "stage_states": {
                "SOURCE_CONTENT_BINDING": source_bound,
                **stage_states,
            },
            "missing_authority_stages": missing,
        }
        reconciled.append(row)
        if all_stages:
            continue
        unsigned_debt = {
            "schema_version": DEBT_SCHEMA,
            "member_id": member_id,
            "group_ids": row["group_ids"],
            "title": source["title"],
            "source_artifact": "findings_inventory.md",
            "source_artifact_sha256": inventory_sha256,
            "source_record_state": source["state"],
            "source_record_utf8": source["content"],
            "source_record_sha256": source["sha256"],
            "missing_authority_stages": missing,
            "authority_effect": "NONE",
            "identity_effect": "RETAIN_INDEPENDENT_MEMBER",
            "confidence_effect": "NONE",
            "severity_effect": "NONE",
            "disposition_effect": "NONE",
            "collapse_effect": "FORBIDDEN",
            "required_action": "INDEPENDENT_VERIFICATION_OR_HUMAN_REVIEW",
            "public_visibility": "CLIENT_HUMAN_REVIEW_LIMITATION",
        }
        debts.append({**unsigned_debt, "debt_sha256": _digest(unsigned_debt)})

    unsigned: dict[str, Any] = {
        "schema_version": ASSURANCE_SCHEMA,
        "run_id": run_id,
        "authority": "DRIVER_RECONCILIATION_ONLY",
        "relation_status_is_assurance_debt": False,
        "may_delete_demote_or_collapse": False,
        "source_bindings": _source_bindings(
            root, project, relation, inventory_sha256, current
        ),
        "authority_validation_state": (
            "CLEAN" if not current["issues"] else "DEGRADED_RETAIN_ALL"
        ),
        "authority_validation_issues": current["issues"],
        "member_reconciliation": reconciled,
        "assurance_debts": debts,
        "assurance_debt_count": len(debts),
        "summary": {
            "relation_group_count": len(relation["groups"]),
            "relation_member_count": len(memberships),
            "independently_delivered_member_count": sum(
                row["state"] == "INDEPENDENTLY_DELIVERED" for row in reconciled
            ),
            "client_human_review_limitation_count": len(debts),
        },
    }
    return {**unsigned, "receipt_sha256": _digest(unsigned)}


def _render_limitations(payload: Mapping[str, Any]) -> str:
    count = int(payload["assurance_debt_count"])
    lines = [
        "# Chain Grouping Assurance Reconciliation (P0-W)",
        "",
        "Relation proposals are telemetry, not limitations. This projection "
        "contains only exact members that did not independently traverse the "
        "current typed verifier and report-delivery authority chain.",
        "",
        f"**Client human-review limitations: {count}**",
        "",
    ]
    if not count:
        lines.extend(
            [
                "No chain-group member creates a client human-review limitation.",
                "",
            ]
        )
        return "\n".join(lines)
    lines.extend(
        [
            "| Member | Relation Groups | Missing Authority Stages | Source Record SHA-256 | Required Action |",
            "|---|---|---|---|---|",
        ]
    )
    for debt in payload["assurance_debts"]:
        lines.append(
            f"| {debt['member_id']} | {', '.join(debt['group_ids'])} | "
            f"{', '.join(debt['missing_authority_stages'])} | "
            f"{debt['source_record_sha256']} | {debt['required_action']} |"
        )
    lines.extend(
        [
            "",
            "This projection grants no authority to delete, demote, alias, "
            "consolidate, or collapse any finding.",
            "",
        ]
    )
    return "\n".join(lines)


def write_chain_grouping_assurance(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    root = Path(scratchpad)
    payload = build_chain_grouping_assurance(root, Path(project_root), run_id=run_id)
    _atomic_write(root / ASSURANCE_FILE, _canonical_bytes(payload) + b"\n")
    _atomic_write(
        root / LIMITATIONS_FILE,
        _render_limitations(payload).encode("utf-8"),
    )
    return payload


def validate_chain_grouping_assurance(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    root = Path(scratchpad)
    payload = _strict_json(root / ASSURANCE_FILE)
    if payload.get("schema_version") != ASSURANCE_SCHEMA:
        raise ValueError("chain grouping assurance schema mismatch")
    receipt = payload.get("receipt_sha256")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if receipt != _digest(unsigned):
        raise ValueError("chain grouping assurance receipt digest mismatch")
    if payload.get("run_id") != run_id:
        raise ValueError("chain grouping assurance run_id mismatch")
    debts = payload.get("assurance_debts")
    if not isinstance(debts, list) or payload.get("assurance_debt_count") != len(debts):
        raise ValueError("chain grouping assurance debt denominator mismatch")
    for debt in debts:
        if not isinstance(debt, dict) or debt.get("schema_version") != DEBT_SCHEMA:
            raise ValueError("chain grouping assurance debt schema mismatch")
        digest = debt.get("debt_sha256")
        debt_unsigned = {
            key: value for key, value in debt.items() if key != "debt_sha256"
        }
        if digest != _digest(debt_unsigned):
            raise ValueError("chain grouping assurance debt digest mismatch")
        content = str(debt.get("source_record_utf8") or "")
        if debt.get("source_record_sha256") != _sha_bytes(content.encode("utf-8")):
            raise ValueError("chain grouping assurance debt content hash mismatch")
    rebuilt = build_chain_grouping_assurance(
        root, Path(project_root), run_id=run_id
    )
    if rebuilt != payload:
        raise ValueError("chain grouping assurance does not replay from current sources")
    expected_projection = _render_limitations(payload).encode("utf-8")
    if (root / LIMITATIONS_FILE).read_bytes() != expected_projection:
        raise ValueError("chain grouping assurance limitation projection drift")
    return payload


__all__ = [
    "ASSURANCE_FILE",
    "ASSURANCE_SCHEMA",
    "DEBT_SCHEMA",
    "LIMITATIONS_FILE",
    "build_chain_grouping_assurance",
    "validate_chain_grouping_assurance",
    "write_chain_grouping_assurance",
]
