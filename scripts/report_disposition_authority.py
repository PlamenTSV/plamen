"""P0-R decision-authorized report retention and appendix projection.

Markdown remains a client/model projection.  This module joins the exact typed
verification queue, driver-bound verifier output receipts, the applied semantic
dedup receipt, and the finding lifecycle substrate.  Report writers and lexical
classifiers can request or veto a relocation; neither can authorize one.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping

from finding_lifecycle_authority import (
    build_finding_lifecycle,
    candidate_content_sha256,
    validate_finding_lifecycle,
)
from closure_broker_v2 import (
    REFUTED_FULL,
    ZERO_HARM,
    load_central_negative_closure_authority,
    resolve_central_negative_closure,
)
from negative_closure_policy import supporting_negative_resolution
from plamen_parsers import (
    _INTERNAL_FINDING_ID_RE,
    _extract_report_ids_from_body,
    _verifier_status_from_text,
    classify_body_or_appendix,
    get_tier_assignments,
    parse_disposition_md,
    parse_report_index_assignments,
    read_queue_work_plan,
)
from queue_work_items import (
    QueueWorkItem,
    VerifierOutputReceipt,
)
from post_verify_candidate_delta import (
    BoundReportCandidate,
    load_current_report_candidate_universe_authority,
    load_post_verify_late_delivery_statuses,
)
from recovery_execution_authority import (
    load_late_verification_authority,
)
from semantic_dedup_authority import (
    DedupAuthorityError,
    PRIMARY_RECEIPT_NAME,
    SUPPLEMENTAL_RECEIPT_NAME,
    load_applied_aliases,
)
from verifier_work_roster import (
    VerifierLaunchSpec,
    VerifierUnitReceipt,
    VerifierWorkRoster,
)
from report_mutation_transaction import (
    ReportMutationTransactionError,
    apply_report_mutation_transaction,
    capture_report_transaction_inputs,
    recover_report_mutation_transaction,
    report_mutation_transaction_state,
)


AUTHORITY_NAME = "report_disposition_authority.json"
APPENDIX_SIDECAR_NAME = "report_appendix_full_content.json"
AUTHORITY_SCHEMA = "plamen.report_disposition_authority.v1"
APPENDIX_SCHEMA = "plamen.report_appendix_full_content.v1"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# One registry-owned identity grammar is shared by every report join.  A local
# regex previously normalized valid underscores into hyphens and could create a
# different authority identity from the verification queue's exact key.
_ID_RE = _INTERNAL_FINDING_ID_RE
_REPORT_ID_RE = re.compile(r"^[CHMLI]-\d+$", re.IGNORECASE)
_SEVERITY_BY_LETTER = {
    "C": "Critical",
    "H": "High",
    "M": "Medium",
    "L": "Low",
    "I": "Informational",
}
_REFUTED = {
    "REFUTED",
    "FALSE_POSITIVE",
    "DROP_FALSE_POSITIVE",
    "INFEASIBLE",
}
_ZERO_HARM = {"DROP_NON_SECURITY", "DROP_DESIGN_CONFIRMATION"}
_CONTESTED = {
    "CONTESTED",
    "UNRESOLVED",
    "PARTIAL",
    "LOW_CONFIDENCE",
    "UNVERIFIED",
    "UNCONFIRMED",
    "DROP_UNACTIONABLE_SPECULATION",
    "APPENDIX_ONLY",
    "SCHEMA_INVALID",
    "LOCATION_INVALID",
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _norm_id(value: str) -> str:
    value = str(value or "").strip().strip("`[]() ").upper()
    match = _ID_RE.search(value)
    if not match:
        return ""
    return match.group(1).upper()


def _severity(value: str, finding_id: str = "") -> str:
    text = str(value or "").strip().lower()
    for name in ("Critical", "High", "Medium", "Low", "Informational"):
        if name.lower() in text:
            return name
    if text == "info":
        return "Informational"
    return _SEVERITY_BY_LETTER.get(str(finding_id or "")[:1].upper(), "Unknown")


def _atomic_bytes(path: Path, content: bytes) -> None:
    path = Path(path)
    if path.is_file() and path.read_bytes() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _source_row(root: Path, path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha(raw),
        "size_bytes": len(raw),
    }


def _bound_queue_items(
    scratchpad: Path,
    *,
    run_id: str | None = None,
) -> tuple[BoundReportCandidate, ...]:
    return load_current_report_candidate_universe_authority(
        scratchpad,
        run_id=run_id,
        project_root=Path(scratchpad).parent,
    ).candidates


def _queue_items(
    scratchpad: Path,
    *,
    run_id: str | None = None,
) -> tuple[QueueWorkItem, ...]:
    return tuple(
        row.item for row in _bound_queue_items(scratchpad, run_id=run_id)
    )


def _location(item: QueueWorkItem) -> str:
    if not item.location_records:
        return ""
    row = item.location_records[0]
    suffix = ""
    if row.start_line is not None:
        suffix = f":{row.start_line}"
        if row.end_line is not None and row.end_line != row.start_line:
            suffix += f"-{row.end_line}"
    return f"{row.artifact}{suffix}"


def _candidate(
    bound: BoundReportCandidate,
    *,
    run_id: str,
) -> dict[str, Any]:
    item = bound.item
    lineage = [link.identity for link in item.lineage]
    lineage.extend(item.aliases)
    lineage.extend(item.constituents)
    lineage.append(item.work_item_id)
    lineage = sorted(set(lineage), key=lambda value: (value.casefold(), value))
    location = _location(item)
    candidate: dict[str, Any] = {
        "schema_version": "plamen.finding_lifecycle_candidate.v1",
        "run_id": run_id,
        "candidate_id": item.work_item_id,
        "lineage_ids": lineage,
        "source_artifact": bound.authority_artifact,
        "source_artifact_sha256": bound.authority_artifact_sha256,
        "source_record_sha256": bound.authority_record_digest,
        "producer_identity": (
            "typed-verification-queue"
            if bound.source_kind == "BASE_VERIFICATION_QUEUE"
            else "typed-post-verification-delta"
        ),
        "producer_invocation_id": bound.source_artifact_sha256,
        "producer_phase": (
            "verify_queue"
            if bound.source_kind == "BASE_VERIFICATION_QUEUE"
            else "post_verify_extract"
        ),
        "entry_reason": (
            "NORMAL_DISCOVERY"
            if bound.source_kind == "BASE_VERIFICATION_QUEUE"
            else "POST_VERIFY_SIDE_OBSERVATION"
        ),
        "origin_assessment": (
            "ACTIVE_VERIFICATION_WORK"
            if bound.source_kind == "BASE_VERIFICATION_QUEUE"
            else "LATE_DISCOVERY_REQUIRES_INDEPENDENT_DISPOSITION"
        ),
        "upstream_severity": _severity(item.severity_proposal.level, item.work_item_id),
        "title": item.title or f"Candidate {item.work_item_id}",
        "location": location,
        "evidence_pointer": item.expected_output_file,
        "candidate_content_sha256": "",
        "location_quality": "EXACT" if location else "UNRESOLVED",
        "source_provenance_quality": "EXACT",
        "scope_state": "IN_SCOPE",
    }
    candidate["candidate_content_sha256"] = candidate_content_sha256(candidate)
    return candidate


def _current_verifier_launch_binding(
    scratchpad: Path,
    item: QueueWorkItem,
    *,
    plan_digest: str,
) -> tuple[str, str]:
    """Return the provider-observed launch bound to current queue authority.

    A per-output receipt is necessary but insufficient for a destructive report
    disposition: it can be replayed after the verifier roster, methodology, or
    launch changes.  Fresh runs therefore require the current roster, exact work
    unit, launch spec, completed unit receipt, and complete output/gate receipt
    vectors to agree before any finding may leave the report body.
    """
    roster = VerifierWorkRoster.from_json(
        (scratchpad / "verification_runtime_roster.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    if roster.parent_queue_work_plan_digest != plan_digest:
        raise ValueError("verifier roster is stale for current QueueWorkPlan")
    units = [
        unit for unit in roster.work_units
        if item.work_item_id in unit.ordered_work_item_ids
    ]
    if len(units) != 1:
        raise ValueError("verifier work item has no unique current roster owner")
    unit = units[0]
    if unit.parent_queue_work_plan_digest != plan_digest:
        raise ValueError("verifier work unit is stale for current QueueWorkPlan")

    unit_dir = scratchpad / "_verifier_runtime_units" / unit.work_unit_id
    spec = VerifierLaunchSpec.from_json(
        (unit_dir / "launch_spec.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    if (
        spec.work_unit_id != unit.work_unit_id
        or spec.work_unit_resume_digest != unit.resume_digest
        or spec.expected_output_files != unit.expected_output_files
        or item.expected_output_file not in spec.expected_output_files
    ):
        raise ValueError("current verifier launch spec does not bind work unit")

    unit_receipt = VerifierUnitReceipt.from_json(
        (unit_dir / "unit_receipt.json").read_text(
            encoding="utf-8", errors="strict"
        )
    )
    if (
        unit_receipt.status != "COMPLETED"
        or unit_receipt.work_unit_id != unit.work_unit_id
        or unit_receipt.work_unit_resume_digest != unit.resume_digest
        or unit_receipt.launch_spec_digest != spec.digest
    ):
        raise ValueError("current verifier unit lacks completed launch authority")
    output_receipt_digests = tuple(
        _sha((scratchpad / f"verify_{work_id}.receipt.json").read_bytes())
        for work_id in unit.ordered_work_item_ids
    )
    if unit_receipt.output_receipt_digests != output_receipt_digests:
        raise ValueError("verifier unit output receipt vector changed")
    gate_path = unit_dir / "gate_receipt.json"
    if unit_receipt.gate_receipt_digests != (_sha(gate_path.read_bytes()),):
        raise ValueError("verifier unit gate receipt changed")
    return spec.digest, spec.backend


def _validated_verifier(
    scratchpad: Path,
    item: QueueWorkItem,
) -> tuple[str, VerifierOutputReceipt, bytes] | tuple[None, None, None]:
    output_path = scratchpad / item.expected_output_file
    receipt_path = scratchpad / f"verify_{item.work_item_id}.receipt.json"
    proposal_path = scratchpad / f"verify_{item.work_item_id}.severity_proposal.json"
    try:
        output = output_path.read_bytes()
        proposal = proposal_path.read_bytes()
        plan = read_queue_work_plan(scratchpad)
        receipt = VerifierOutputReceipt.from_json(
            receipt_path.read_text(encoding="utf-8", errors="strict")
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        return None, None, None
    identity = receipt.identity
    try:
        launch_digest, verifier_backend = _current_verifier_launch_binding(
            scratchpad,
            item,
            plan_digest=plan.digest,
        )
        receipt.validate_against(
            item,
            plan,
            output,
            severity_proposal=proposal,
            launch_digest=launch_digest,
            verifier_backend=verifier_backend,
        )
    except (OSError, UnicodeError, ValueError, TypeError):
        return None, None, None
    if (
        identity.work_item_id != item.work_item_id
        or identity.queue_record_digest != item.digest
        or identity.expected_output_file != item.expected_output_file
        or identity.expected_output_identity != item.expected_output_identity
        or receipt.output_sha256 != _sha(output)
        or receipt.output_size_bytes != len(output)
        or receipt.severity_proposal_file != proposal_path.name
        or receipt.severity_proposal_sha256 != _sha(proposal)
        or receipt.severity_proposal_size_bytes != len(proposal)
    ):
        return None, None, None
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeError:
        return None, None, None
    return _verifier_status_from_text(text), receipt, output


def _decision(
    candidate: Mapping[str, Any],
    *,
    status: str,
    receipt: VerifierOutputReceipt,
    closure_authority: Any = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    central: dict[str, Any] | None = None
    if status == "CONFIRMED":
        kind = "CONFIRMED"
        reason = "INDEPENDENT_VERIFIER_CONFIRMED"
    elif status in _REFUTED:
        # A provider-observed verifier receipt authenticates who wrote which
        # bytes.  It does not prove exhaustive negative scope or a full-claim
        # refutation.  Preserve the model status as a challenge while keeping
        # the candidate active until the centralized closure provider agrees.
        supporting_negative_resolution(
            requested_effect="REFUTED_FULL",
            evidence_basis="INDEPENDENT_ANALYSIS",
        )
        if closure_authority is not None:
            try:
                central = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        "candidate_id": candidate["candidate_id"],
                        "work_item_id": candidate["candidate_id"],
                        "candidate_content_sha256": candidate[
                            "candidate_content_sha256"
                        ],
                    },
                    requested_effect=REFUTED_FULL,
                )
            except Exception:
                central = None
        if isinstance(central, Mapping) and central.get("status") == "AUTHORIZED":
            kind = "REFUTED"
            reason = "CENTRAL_REPLAYED_EXHAUSTIVE_REFUTATION"
        else:
            central = None
            kind = "AUTHORIZED_DEFERRED"
            reason = "NEGATIVE_PROPOSAL_REQUIRES_TYPED_AUTHORITY"
    elif status in _ZERO_HARM:
        supporting_negative_resolution(
            requested_effect="ZERO_HARM",
            evidence_basis="INDEPENDENT_ANALYSIS",
        )
        if closure_authority is not None:
            try:
                central = resolve_central_negative_closure(
                    closure_authority,
                    work_item={
                        "candidate_id": candidate["candidate_id"],
                        "work_item_id": candidate["candidate_id"],
                        "candidate_content_sha256": candidate[
                            "candidate_content_sha256"
                        ],
                    },
                    requested_effect=ZERO_HARM,
                )
            except Exception:
                central = None
        if isinstance(central, Mapping) and central.get("status") == "AUTHORIZED":
            kind = "AUTHORIZED_ZERO_HARM"
            reason = "CENTRAL_REPLAYED_EXHAUSTIVE_ZERO_HARM"
        else:
            central = None
            kind = "AUTHORIZED_DEFERRED"
            reason = "ZERO_HARM_PROPOSAL_REQUIRES_TYPED_AUTHORITY"
    elif status in _CONTESTED:
        kind = "CONTESTED"
        reason = "INDEPENDENT_VERIFIER_UNRESOLVED_OR_CONTESTED"
    else:
        return None, None
    identity = {
        "candidate_id": candidate["candidate_id"],
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "verifier_receipt_digest": receipt.digest,
        "decision_kind": kind,
    }
    decision = {
        "schema_version": "plamen.finding_lifecycle_decision.v1",
        "run_id": candidate["run_id"],
        "decision_id": f"RDA-{_digest(identity)[:24]}",
        "candidate_id": candidate["candidate_id"],
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "decision_kind": kind,
        "evidence_basis": (
            "CENTRAL_REPLAYED_AUTHORITY" if central else "INDEPENDENT_ANALYSIS"
        ),
        "evidence_sha256": (
            str(central["resolution_digest"]) if central else receipt.digest
        ),
        "proof_scope": (
            "FULL_CLAIM"
            if central
            else "MECHANISM_ONLY"
            if status in (_REFUTED | _ZERO_HARM)
            else "FULL_CLAIM"
        ),
        "discriminator_identity": (
            str(central["provider_id"])
            if central
            else f"independent-verifier-{receipt.verifier_backend}"
        ),
        "discriminator_invocation_id": (
            str(central["provider_completion_sha256"])
            if central
            else receipt.launch_digest
        ),
        "discriminator_phase": "verify",
        "alias_target_candidate_id": None,
        "reason_class": reason,
        "next_action": (
            "complete exact independent re-verification before any non-body disposition"
            if kind == "AUTHORIZED_DEFERRED"
            else None
        ),
        "public_retention_target": (
            "BODY" if kind == "AUTHORIZED_DEFERRED" else None
        ),
        "scope_snapshot_sha256": (
            str(central["subject_digest"]) if central else None
        ),
    }
    return decision, central


def _late_negative_deferred_decision(
    candidate: Mapping[str, Any],
    *,
    status: str,
    late_status: Any,
) -> dict[str, Any]:
    """Turn an authenticated late negative into additive reopen work only."""

    reason = (
        "ZERO_HARM_PROPOSAL_REQUIRES_TYPED_AUTHORITY"
        if status in _ZERO_HARM
        else "NEGATIVE_PROPOSAL_REQUIRES_TYPED_AUTHORITY"
    )
    identity = {
        "candidate_id": candidate["candidate_id"],
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "late_delivery_sha256": late_status.delivery_artifact_sha256,
        "verify_sha256": late_status.verify_sha256,
        "status": status,
    }
    return {
        "schema_version": "plamen.finding_lifecycle_decision.v1",
        "run_id": candidate["run_id"],
        "decision_id": f"RDA-{_digest(identity)[:24]}",
        "candidate_id": candidate["candidate_id"],
        "candidate_content_sha256": candidate["candidate_content_sha256"],
        "decision_kind": "AUTHORIZED_DEFERRED",
        "evidence_basis": "INDEPENDENT_ANALYSIS",
        "evidence_sha256": late_status.verify_sha256,
        "proof_scope": "MECHANISM_ONLY",
        "discriminator_identity": "post-verify-late-status-adapter",
        "discriminator_invocation_id": (
            late_status.delivery_artifact_sha256
        ),
        "discriminator_phase": "post_verify_extract",
        "alias_target_candidate_id": None,
        "reason_class": reason,
        "next_action": (
            "complete exact independent re-verification before any non-body "
            "disposition"
        ),
        "public_retention_target": "BODY",
        "scope_snapshot_sha256": None,
    }


def _assignment_id_map(rows: Iterable[Mapping[str, Any]]) -> dict[str, list[str]]:
    mapping: dict[str, list[str]] = {}
    for row in rows:
        rid = str(row.get("report_id") or "").upper()
        if not _REPORT_ID_RE.fullmatch(rid):
            continue
        raw = str(row.get("finding_id") or "")
        for match in _ID_RE.finditer(raw):
            fid = _norm_id(match.group(1))
            if fid:
                mapping.setdefault(fid, []).append(rid)
    return {key: sorted(set(value)) for key, value in mapping.items()}


def _report_id_map(scratchpad: Path) -> dict[str, list[str]]:
    """Return only IDs materially present in the Master Finding Index.

    ``get_tier_assignments`` deliberately synthesizes/merges queue rows so tier
    writers still receive work when model Markdown is incomplete.  That is a
    routing recovery plan, not evidence that the index or final report retained
    the finding.  Report-disposition accounting therefore consumes the exact
    Master-index parser only.
    """
    return _assignment_id_map(parse_report_index_assignments(scratchpad))


def _planned_report_id_map(scratchpad: Path) -> dict[str, list[str]]:
    rows, _source = get_tier_assignments(scratchpad)
    return _assignment_id_map(rows)


def _source_paths(
    scratchpad: Path,
    items: Iterable[QueueWorkItem],
    *,
    bound_items: Iterable[BoundReportCandidate] = (),
    run_id: str,
) -> list[Path]:
    names = {
        "verification_queue.work_items.json",
        "verification_queue.work_plan.json",
        "verification_runtime_roster.json",
        "verification_queue.md",
        "report_index.md",
    }
    if (scratchpad / "post_verify_candidate_delta.json").is_file():
        names.add("post_verify_candidate_delta.json")
    if (scratchpad / "post_verify_late_delivery.json").is_file():
        names.add("post_verify_late_delivery.json")
    if (
        scratchpad / "post_verify_late_verification_authority.json"
    ).is_file():
        names.add("post_verify_late_verification_authority.json")
        late_authority = load_late_verification_authority(
            scratchpad,
            run_id=run_id,
            repo_root=Path(__file__).resolve().parent.parent,
        )
        for row in late_authority["rows"]:
            for field in (
                "contract_artifact",
                "launch_spec_artifact",
                "execution_artifact",
                "verify_artifact",
                "severity_proposal_artifact",
                "operator_application_artifact",
                "operator_receipt_artifact",
            ):
                if row.get(field):
                    names.add(str(row[field]))
    for bound in bound_items:
        names.add(bound.source_artifact)
    if (scratchpad / "disposition.md").is_file():
        names.add("disposition.md")
    for item in items:
        names.update(
            {
                item.expected_output_file,
                f"verify_{item.work_item_id}.receipt.json",
                f"verify_{item.work_item_id}.severity_proposal.json",
            }
        )
    for name in (PRIMARY_RECEIPT_NAME, SUPPLEMENTAL_RECEIPT_NAME, "findings_inventory.md"):
        if (scratchpad / name).is_file():
            names.add(name)
    if (scratchpad / "negative_closure_broker_authority.json").is_file():
        names.add("negative_closure_broker_authority.json")
    paths = [scratchpad / name for name in sorted(names) if (scratchpad / name).is_file()]
    runtime_root = scratchpad / "_verifier_runtime_units"
    if runtime_root.is_dir():
        for pattern in ("*/launch_spec.json", "*/unit_receipt.json", "*/gate_receipt.json"):
            paths.extend(sorted(runtime_root.glob(pattern)))
    return paths


def build_report_disposition_authority(
    scratchpad: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    root = Path(scratchpad)
    issues: list[str] = []
    try:
        closure_authority = load_central_negative_closure_authority(root)
    except Exception as exc:
        closure_authority = None
        issues.append(
            "central negative-closure authority unavailable; negative report "
            f"proposals remain BODY: {type(exc).__name__}: {exc}"
        )
    try:
        bound_items = _bound_queue_items(root, run_id=run_id)
        items = tuple(row.item for row in bound_items)
    except Exception as exc:
        bound_items = ()
        items = ()
        issues.append(
            "typed base-plus-post-verify candidate universe unavailable: "
            f"{type(exc).__name__}: {exc}"
        )
    proposals = parse_disposition_md(root)
    report_ids = _report_id_map(root)
    planned_report_ids = _planned_report_id_map(root)
    try:
        index_text = (root / "report_index.md").read_text(
            encoding="utf-8", errors="strict"
        )
    except (OSError, UnicodeError):
        index_text = ""
    excluded_index_ids = _first_column_ids(
        _section(index_text, r"Excluded\s+Findings")
    )
    consolidated_index_ids = _first_column_ids(
        _section(
            index_text,
            r"(?:Consolidation\s+Map|Consolidated\s+Findings)",
        )
    )

    candidates: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    closure_decisions: list[dict[str, Any]] = []
    row_facts: dict[str, dict[str, Any]] = {}
    bound_by_id = {
        row.item.work_item_id: row for row in bound_items
    }
    late_bound_ids = {
        row.item.work_item_id
        for row in bound_items
        if row.source_kind != "BASE_VERIFICATION_QUEUE"
    }
    late_statuses: Mapping[str, Any] = {}
    if late_bound_ids:
        try:
            late_statuses = load_post_verify_late_delivery_statuses(
                root, run_id=run_id
            )
        except Exception as exc:
            issues.append(
                "post-verification late-delivery authority unavailable; "
                "all delta candidates remain BODY with visible debt: "
                f"{type(exc).__name__}: {exc}"
            )
    for item in items:
        bound = bound_by_id[item.work_item_id]
        candidate = _candidate(bound, run_id=run_id)
        candidates.append(candidate)
        late_status = late_statuses.get(item.work_item_id)
        if bound.source_kind == "BASE_VERIFICATION_QUEUE":
            status, receipt, output = _validated_verifier(root, item)
        elif late_status is not None:
            status = str(late_status.verifier_status or "UNRESOLVED")
            receipt = None
            output = None
            if late_status.verify_artifact:
                try:
                    output = (
                        root / late_status.verify_artifact
                    ).read_bytes()
                except OSError:
                    output = None
        else:
            status, receipt, output = None, None, None
        receipt_digest = ""
        decision_kind = ""
        closure_decision: dict[str, Any] | None = None
        if receipt is None:
            if bound.source_kind == "BASE_VERIFICATION_QUEUE":
                issues.append(
                    f"{item.work_item_id}: exact verifier output receipt is "
                    "missing/stale/tampered"
                )
                status = "UNRESOLVED"
            elif late_status is None:
                issues.append(
                    f"{item.work_item_id}: exact late-delivery status is "
                    "missing/stale/tampered"
                )
                status = "UNRESOLVED"
            else:
                issues.append(
                    f"{item.work_item_id}: authenticated late verifier status "
                    f"{status or 'UNRESOLVED'} is additive evidence only and "
                    "has no terminal negative authority"
                )
        else:
            receipt_digest = receipt.digest
            decision, closure_decision = _decision(
                candidate,
                status=str(status),
                receipt=receipt,
                closure_authority=closure_authority,
            )
            if decision is not None:
                decisions.append(decision)
                decision_kind = str(decision["decision_kind"])
            if closure_decision is not None:
                closure_decisions.append(closure_decision)
        if (
            bound.source_kind != "BASE_VERIFICATION_QUEUE"
            and late_status is not None
            and str(status) in (_REFUTED | _ZERO_HARM)
        ):
            decision = _late_negative_deferred_decision(
                candidate,
                status=str(status),
                late_status=late_status,
            )
            decisions.append(decision)
            decision_kind = "AUTHORIZED_DEFERRED"
        negative_proposal_status = (
            str(status)
            if str(status) in (_REFUTED | _ZERO_HARM)
            and decision_kind not in {"REFUTED", "AUTHORIZED_ZERO_HARM"}
            else ""
        )
        negative_proposal_reason = (
            "NO_TYPED_NEGATIVE_CLOSURE_AUTHORITY"
            if negative_proposal_status else ""
        )
        if negative_proposal_status:
            issues.append(
                f"{item.work_item_id}: verifier {negative_proposal_status} is "
                "supporting-only; retained in BODY pending typed negative "
                "closure authority"
            )
        rids = report_ids.get(_norm_id(item.work_item_id), [])
        planned_rids = planned_report_ids.get(_norm_id(item.work_item_id), [])
        proposal_rows = [
            {"report_id": rid, "disposition": proposals.get(rid, ("BODY", ""))[0], "reason": proposals.get(rid, ("BODY", ""))[1]}
            for rid in rids
        ]
        proposed_appendix = bool(rids) and all(
            row["disposition"] == "APPENDIX" for row in proposal_rows
        )
        high_medium = _severity(item.severity_proposal.level, item.work_item_id) in {
            "Critical",
            "High",
            "Medium",
        }
        appendix_authorized = (
            decision_kind == "AUTHORIZED_ZERO_HARM"
            and proposed_appendix
            and not high_medium
        )
        target = (
            "EXCLUDED"
            if decision_kind == "REFUTED"
            else "APPENDIX"
            if appendix_authorized
            else "BODY"
        )
        normalized_item_id = _norm_id(item.work_item_id)
        if target == "BODY" and rids:
            accounting_route = "MASTER_INDEX_BODY"
        elif target == "APPENDIX" and rids:
            accounting_route = "MASTER_INDEX_APPENDIX_PENDING_DELIVERY"
        elif (
            target == "EXCLUDED"
            and decision_kind == "REFUTED"
            and normalized_item_id in excluded_index_ids
        ):
            accounting_route = "AUTHORIZED_EXCLUDED_INDEX_ROW"
        else:
            accounting_route = "UNACCOUNTED"
        identity_accounted = accounting_route != "UNACCOUNTED"
        if not identity_accounted:
            issues.append(
                f"{item.work_item_id}: identity is not accounted by its exact "
                f"{target} report route; retained as report debt"
            )
            if planned_rids and target in {"BODY", "APPENDIX"}:
                issues.append(
                    f"{item.work_item_id}: planned fallback report IDs "
                    f"({', '.join(planned_rids)}) are routing proposals only"
                )
        if proposed_appendix and not appendix_authorized:
            issues.append(
                f"{item.work_item_id}: APPENDIX proposal lacks exact independent zero-harm authority; retained in BODY"
            )
        row_facts[item.work_item_id] = {
            "candidate_id": item.work_item_id,
            "report_ids": rids,
            "planned_report_ids": planned_rids,
            "accounting_route": accounting_route,
            "upstream_severity": _severity(item.severity_proposal.level, item.work_item_id),
            "verifier_status": status or "UNRESOLVED",
            "verifier_receipt_digest": receipt_digest,
            "decision_kind": decision_kind,
            "report_proposals": proposal_rows,
            "identity_accounted": identity_accounted,
            "disposition_authorized": bool(
                decision_kind in {"REFUTED", "AUTHORIZED_ZERO_HARM"}
            ),
            "authority_kind": decision_kind or "NONE",
            "negative_proposal_status": negative_proposal_status,
            "negative_proposal_reason": negative_proposal_reason,
            "authority_event_id": (
                next(
                    (row["decision_id"] for row in decisions if row["candidate_id"] == item.work_item_id),
                    "",
                )
            ),
            "public_retention_target": target,
            "visible_debt": (
                bool(negative_proposal_status)
                or not identity_accounted or not receipt_digest or (
                    proposed_appendix and not appendix_authorized
                )
            ),
            "mandatory_reverification": bool(negative_proposal_status),
            "mandatory_reverification_id": "",
            "negative_closure_authority_digest": str(
                (closure_decision or {}).get("resolution_digest") or ""
            ),
            "negative_closure_provider_completion_sha256": str(
                (closure_decision or {}).get("provider_completion_sha256") or ""
            ),
            "negative_closure_provider_publish_sha256": str(
                (closure_decision or {}).get("provider_publish_sha256") or ""
            ),
        }

    lifecycle = build_finding_lifecycle(
        run_id=run_id,
        candidates=candidates,
        decisions=decisions,
        projections=[],
        closure_decisions=closure_decisions,
        authority_identity="plamen-driver-report-disposition",
        authority_invocation_id=_digest(
            {
                "candidate_universe": [
                    {
                        "candidate_id": bound.item.work_item_id,
                        "authority_artifact": bound.authority_artifact,
                        "authority_artifact_sha256": (
                            bound.authority_artifact_sha256
                        ),
                        "authority_record_digest": (
                            bound.authority_record_digest
                        ),
                        "source_artifact": bound.source_artifact,
                        "source_record_digest": bound.source_record_digest,
                        "claim_digest": bound.claim_digest,
                    }
                    for bound in bound_items
                ],
                "run_id": run_id,
                "candidate_ids": sorted(row_facts),
            }
        ),
        closure_authority=closure_authority,
    )
    validate_finding_lifecycle(
        lifecycle, closure_authority=closure_authority
    )

    recovery_obligations: dict[str, list[dict[str, Any]]] = {}
    for obligation in lifecycle["obligations"]:
        if obligation["obligation_kind"] != "RECOVERY_INDEPENDENT_VERIFICATION":
            continue
        recovery_obligations.setdefault(str(obligation["candidate_id"]), []).append(
            obligation
        )
    for candidate_id, row in row_facts.items():
        if not row["mandatory_reverification"]:
            continue
        matches = recovery_obligations.get(candidate_id, [])
        if len(matches) == 1:
            row["mandatory_reverification_id"] = str(matches[0]["obligation_id"])
        else:
            # Cardinality failure is itself visible report debt.  Never invent
            # an obligation identity or relax BODY retention.
            row["public_retention_target"] = "BODY"
            row["disposition_authorized"] = False
            row["visible_debt"] = True
            issues.append(
                f"{candidate_id}: exact mandatory re-verification obligation "
                "is missing or ambiguous"
            )

    aliases: list[dict[str, Any]] = []
    try:
        applied = load_applied_aliases(root)
    except DedupAuthorityError as exc:
        applied = {}
        issues.append(f"applied alias authority invalid: {exc}")
    for member, info in sorted(applied.items()):
        aliases.append(
            {
                "candidate_id": _norm_id(member) or member,
                "alias_target": _norm_id(info["survivor"]) or info["survivor"],
                "authority_kind": "AUTHORIZED_ALIAS",
                "disposition_authorized": True,
                "authority_event_id": _digest(
                    {"member": member, "survivor": info["survivor"], "coupled": info["coupled"]}
                ),
            }
        )

    sources = [
        _source_row(root, path)
        for path in _source_paths(
            root, items, bound_items=bound_items, run_id=run_id
        )
    ]
    rows = [row_facts[key] for key in sorted(row_facts, key=lambda value: (value.casefold(), value))]
    unsigned: dict[str, Any] = {
        "schema_version": AUTHORITY_SCHEMA,
        "run_id": run_id,
        "authority": "DRIVER_DERIVED_FROM_TYPED_INDEPENDENT_DECISIONS",
        "report_writer_authoritative": False,
        "lexical_classifier_authoritative": False,
        "source_artifacts": sources,
        "source_set_sha256": _digest(sources),
        "rows": rows,
        "row_count": len(rows),
        "aliases": aliases,
        "alias_count": len(aliases),
        "finding_lifecycle": lifecycle,
        "issues": sorted(set(issues)),
        "summary": {
            "identity_accounted": sum(bool(row["identity_accounted"]) for row in rows),
            "disposition_authorized": sum(bool(row["disposition_authorized"]) for row in rows),
            "body_retained": sum(row["public_retention_target"] == "BODY" for row in rows),
            "appendix_authorized": sum(row["public_retention_target"] == "APPENDIX" for row in rows),
            "excluded_authorized": sum(row["public_retention_target"] == "EXCLUDED" for row in rows),
            "visible_debt": sum(bool(row["visible_debt"]) for row in rows),
            "planned_only_identity": sum(
                bool(row["planned_report_ids"]) and not bool(row["report_ids"])
                for row in rows
            ),
        },
    }
    return {**unsigned, "receipt_sha256": _digest(unsigned)}


def write_report_disposition_authority(
    scratchpad: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    payload = build_report_disposition_authority(scratchpad, run_id=run_id)
    _atomic_bytes(Path(scratchpad) / AUTHORITY_NAME, _canonical_bytes(payload) + b"\n")
    return payload


def _read_authority(scratchpad: Path, *, run_id: str) -> dict[str, Any]:
    path = Path(scratchpad) / AUTHORITY_NAME
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    if not isinstance(payload, dict) or payload.get("schema_version") != AUTHORITY_SCHEMA:
        raise ValueError("report disposition authority schema mismatch")
    receipt = payload.get("receipt_sha256")
    unsigned = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if receipt != _digest(unsigned):
        raise ValueError("report disposition authority digest mismatch")
    if payload.get("run_id") != run_id:
        raise ValueError("report disposition authority run_id mismatch")
    sources = payload.get("source_artifacts")
    if not isinstance(sources, list) or payload.get("source_set_sha256") != _digest(sources):
        raise ValueError("report disposition authority source-set mismatch")
    root = Path(scratchpad)
    for row in sources:
        source = root / str(row.get("path") or "")
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise ValueError(f"report disposition authority source missing: {source.name}") from exc
        if row.get("sha256") != _sha(raw) or row.get("size_bytes") != len(raw):
            raise ValueError(f"report disposition authority source drift: {source.name}")
    try:
        closure_authority = load_central_negative_closure_authority(root)
    except Exception:
        closure_authority = None
    validate_finding_lifecycle(
        payload.get("finding_lifecycle"),
        closure_authority=closure_authority,
    )
    rebuilt = build_report_disposition_authority(root, run_id=run_id)
    if rebuilt != payload:
        raise ValueError("report disposition authority does not replay from current sources")
    return payload


def authorized_nonbody_internal_ids(
    scratchpad: Path,
    *,
    run_id: str,
) -> dict[str, dict[str, str]]:
    """Return only independently authorized negative/zero-harm/applied aliases."""
    payload = build_report_disposition_authority(Path(scratchpad), run_id=run_id)
    result: dict[str, dict[str, str]] = {}
    for row in payload["rows"]:
        kind = str(row.get("authority_kind") or "")
        target = str(row.get("public_retention_target") or "")
        if not (
            (kind == "REFUTED" and target == "EXCLUDED")
            or (kind == "AUTHORIZED_ZERO_HARM" and target == "APPENDIX")
        ):
            continue
        result[_norm_id(row["candidate_id"])] = {
            "authority_kind": kind,
            "authority_event_id": str(row.get("authority_event_id") or ""),
            "alias_target": "",
            "public_retention_target": target,
        }
    for row in payload["aliases"]:
        result[_norm_id(row["candidate_id"])] = {
            "authority_kind": "AUTHORIZED_ALIAS",
            "authority_event_id": str(row.get("authority_event_id") or ""),
            "alias_target": _norm_id(row.get("alias_target") or ""),
            "public_retention_target": "CONSOLIDATED_ALIAS",
        }
    return result


def _section(text: str, heading: str) -> str:
    match = re.search(rf"(?ims)^##\s+{heading}\b.*?(?=^##\s|\Z)", text or "")
    return match.group(0) if match else ""


def _ids(text: str) -> set[str]:
    return {_norm_id(match.group(1)) for match in _ID_RE.finditer(text or "") if _norm_id(match.group(1))}


def _first_column_ids(section: str) -> set[str]:
    """Extract disposition subjects, never IDs cited in reason/target cells."""
    result: set[str] = set()
    for line in (section or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or all(not cell or set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        result.update(_ids(cells[0]))
    return result


def _dropout_retention_ids(scratchpad: Path) -> set[str]:
    receipt_path = scratchpad / "report_dropout_retention.json"
    projection_path = scratchpad / "report_semantic_report_dropouts.md"
    try:
        payload = json.loads(receipt_path.read_text(encoding="utf-8", errors="strict"))
        projection = projection_path.read_bytes()
    except (OSError, UnicodeError, ValueError, TypeError):
        return set()
    unsigned = dict(payload) if isinstance(payload, dict) else {}
    receipt_sha = unsigned.pop("receipt_sha256", None)
    if (
        payload.get("schema_version") != "plamen.report_dropout_retention.v1"
        or receipt_sha != _digest(unsigned)
        or payload.get("projection_sha256") != _sha(projection)
        or payload.get("row_count") != len(payload.get("rows") or [])
    ):
        return set()
    result: set[str] = set()
    for row in payload.get("rows") or []:
        if not isinstance(row, dict) or row.get("retention_target") != "HUMAN_REVIEW":
            return set()
        source = scratchpad / str(row.get("source_artifact") or "")
        try:
            source_sha = _sha(source.read_bytes())
        except OSError:
            return set()
        if source_sha != row.get("source_sha256"):
            return set()
        result.add(_norm_id(row.get("candidate_id") or ""))
    return result


def validate_index_dispositions(
    scratchpad: Path,
    *,
    run_id: str,
) -> list[str]:
    """Require both identity accounting and authorized non-body disposition."""
    root = Path(scratchpad)
    try:
        index = (root / "report_index.md").read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return ["report disposition authority debt: report_index.md is unavailable"]
    authority = authorized_nonbody_internal_ids(root, run_id=run_id)
    # The canonical tier parser supplies exact master-row identity roles. For
    # negative/consolidation tables only column zero is the disposition subject;
    # target/reason citations must never manufacture another disposition.
    master_ids = set(_report_id_map(root))
    excluded_ids = _first_column_ids(_section(index, r"Excluded\s+Findings"))
    consolidation_ids = _first_column_ids(
        _section(index, r"(?:Consolidation\s+Map|Consolidated\s+Findings)")
    )
    issues: list[str] = []
    for fid in sorted(excluded_ids):
        row = authority.get(fid) or {}
        if row.get("public_retention_target") not in {"EXCLUDED", "APPENDIX"}:
            issues.append(
                f"{fid}: identity is lexically accounted but non-body disposition is unauthorized"
            )
    for fid in sorted(consolidation_ids):
        row = authority.get(fid) or {}
        if row.get("public_retention_target") != "CONSOLIDATED_ALIAS":
            issues.append(
                f"{fid}: consolidation is lexically accounted but alias disposition is unauthorized"
            )
    reference: set[str] = set()
    try:
        reference.update(
            item.work_item_id for item in _queue_items(root, run_id=run_id)
        )
    except Exception:
        # Legacy/migration runs may lack the typed denominator. Raw non-body
        # rows are still rejected above; body rows remain recall-safe and the
        # report-floor authority receipt records the missing queue as debt.
        pass
    seed_path = root / "report_index_coverage_seed.md"
    if seed_path.is_file():
        reference.update(_ids(seed_path.read_text(encoding="utf-8", errors="replace")))
    delivered_human_review = _dropout_retention_ids(root)
    authorized_excluded = {
        fid
        for fid in excluded_ids
        if (authority.get(fid) or {}).get("public_retention_target") == "EXCLUDED"
    }
    authorized_consolidated = {
        fid
        for fid in consolidation_ids
        if (authority.get(fid) or {}).get("public_retention_target")
        == "CONSOLIDATED_ALIAS"
    }
    accounted = (
        master_ids
        | authorized_excluded
        | authorized_consolidated
        | delivered_human_review
    )
    for fid in sorted({_norm_id(value) for value in reference if _norm_id(value)} - accounted):
        issues.append(
            f"{fid}: unresolved report disposition debt; no body, authorized non-body decision, or delivered human-review receipt"
        )
    return sorted(set(issues))


def _report_sections(text: str) -> dict[str, str]:
    matches = list(re.finditer(
        r"(?m)^###\s+(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\][^\n]*\n?",
        text or "",
        re.IGNORECASE,
    ))
    result: dict[str, str] = {}
    appendix = re.search(r"(?im)^##\s+Appendix\b", text or "")
    body_end = appendix.start() if appendix else len(text or "")
    for index, match in enumerate(matches):
        if match.start() >= body_end:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else body_end
        result[match.group(1).upper()] = text[match.start():end]
    return result


def _field(section: str, name: str) -> str:
    match = re.search(
        rf"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?{re.escape(name)}(?:\*\*)?\s*:\s*(.+?)\s*$",
        section or "",
    )
    return re.sub(r"\s+", " ", match.group(1).strip().strip("`* ")) if match else ""


def _section_fields(report_id: str, section: str) -> dict[str, str]:
    heading = section.splitlines()[0] if section.splitlines() else ""
    title = re.sub(
        rf"(?i)^###\s+(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[{re.escape(report_id)}\]\s*",
        "",
        heading,
    ).strip()
    return {
        "report_id": report_id,
        "severity": _severity(_field(section, "Severity"), report_id),
        "title": re.sub(r"\s+", " ", title),
        "location": re.sub(r"\s+", " ", _field(section, "Location")),
        "description_sha256": _sha(_field(section, "Description").encode("utf-8")),
        "impact_sha256": _sha(_field(section, "Impact").encode("utf-8")),
        "recommendation_sha256": _sha(_field(section, "Recommendation").encode("utf-8")),
        "section_body_sha256": _sha(
            "\n".join(section.splitlines()[1:]).strip().encode("utf-8")
        ),
    }


def _appendix_detail_section(report_text: str, report_id: str) -> str:
    match = re.search(
        rf"(?ims)^###\s+Appendix\s+observation\s+\[{re.escape(report_id)}\][^\n]*\n"
        r".*?(?=^#{2,3}\s|\Z)",
        report_text or "",
    )
    return match.group(0) if match else ""


def _appendix_detail_fields(report_id: str, section: str) -> dict[str, str]:
    fields = _section_fields(report_id, section)
    heading = section.splitlines()[0] if section.splitlines() else ""
    fields["title"] = re.sub(
        rf"(?i)^###\s+Appendix\s+observation\s+\[{re.escape(report_id)}\]\s*",
        "",
        heading,
    ).strip()
    return fields


def _projection_fields(row: tuple[str, str, str, str, str]) -> dict[str, str]:
    rid, severity, title, location, _reason = row
    return {
        "report_id": rid,
        "severity": _severity(severity, rid),
        "title": re.sub(r"\s+", " ", title).strip(),
        "location": re.sub(r"\s+", " ", location.replace("`", "")).strip(),
    }


def _body_delivery_rows(
    authority: Mapping[str, Any],
    report_text: str,
) -> list[dict[str, Any]]:
    """Bind every BODY candidate to an actually rendered report identity."""
    rendered = set(_extract_report_ids_from_body(report_text))
    rows: list[dict[str, Any]] = []
    for authority_row in authority.get("rows") or []:
        if authority_row.get("public_retention_target") != "BODY":
            continue
        report_ids = sorted({
            str(value).upper()
            for value in authority_row.get("report_ids") or []
            if _REPORT_ID_RE.fullmatch(str(value).upper())
        })
        rendered_report_ids = [rid for rid in report_ids if rid in rendered]
        rows.append({
            "candidate_id": str(authority_row.get("candidate_id") or ""),
            "report_ids": report_ids,
            "rendered_report_ids": rendered_report_ids,
            "complete": bool(report_ids) and len(rendered_report_ids) == len(report_ids),
        })
    return sorted(rows, key=lambda row: str(row["candidate_id"]).casefold())


def _appendix_payload(
    *,
    authority: Mapping[str, Any],
    pre_report: bytes,
    post_report: bytes,
    sections: Mapping[str, str],
    moved_rows: list[tuple[str, str, str, str, str]],
) -> dict[str, Any]:
    post_text = post_report.decode("utf-8", errors="strict")
    authority_by_rid: dict[str, list[Mapping[str, Any]]] = {}
    for authority_row in authority["rows"]:
        for rid in authority_row.get("report_ids") or []:
            authority_by_rid.setdefault(str(rid), []).append(authority_row)
    rows: list[dict[str, Any]] = []
    for moved in sorted(moved_rows):
        rid = moved[0]
        from plamen_mechanical import _finding_own_block

        original_section = _finding_own_block(sections[rid]).strip()
        raw = original_section.encode("utf-8")
        original = _section_fields(rid, original_section)
        projection = _projection_fields(moved)
        detail_section = _appendix_detail_section(post_text, rid)
        detail = _appendix_detail_fields(rid, detail_section)
        compared = (
            "report_id",
            "severity",
            "title",
            "location",
            "description_sha256",
            "impact_sha256",
            "recommendation_sha256",
            "section_body_sha256",
        )
        differences = {
            field: {"before": original[field], "after": detail[field]}
            for field in compared
            if original[field].casefold() != detail[field].casefold()
        }
        member_authorities = authority_by_rid.get(rid, [])
        candidate_ids = sorted({
            str(item.get("candidate_id") or "")
            for item in member_authorities
            if str(item.get("candidate_id") or "")
        })
        authority_event_ids = sorted({
            str(item.get("authority_event_id") or "")
            for item in member_authorities
            if str(item.get("authority_event_id") or "")
        })
        rows.append(
            {
                "report_id": rid,
                "candidate_ids": candidate_ids,
                "authority_event_ids": authority_event_ids,
                "authority_event_id": _digest(authority_event_ids),
                "full_section_b64": base64.b64encode(raw).decode("ascii"),
                "full_section_sha256": _sha(raw),
                "full_section_size_bytes": len(raw),
                "original_client_fields": original,
                "appendix_projection_fields": projection,
                "appendix_detail_fields": detail,
                "field_preservation": {
                    "compared_fields": list(compared),
                    "differences": differences,
                    "passed": not differences,
                },
            }
        )
    body_delivery_rows = _body_delivery_rows(authority, post_text)
    unsigned: dict[str, Any] = {
        "schema_version": APPENDIX_SCHEMA,
        "authority_receipt_sha256": authority["receipt_sha256"],
        "pre_report_sha256": _sha(pre_report),
        "post_report_sha256": _sha(post_report),
        "row_count": len(rows),
        "rows": rows,
        "body_delivery_row_count": len(body_delivery_rows),
        "body_delivery_debt_count": sum(
            not bool(row["complete"]) for row in body_delivery_rows
        ),
        "body_delivery_rows": body_delivery_rows,
    }
    return {**unsigned, "receipt_sha256": _digest(unsigned)}


def _validate_appendix_sidecar(
    scratchpad: Path,
    project_root: Path,
    authority: Mapping[str, Any],
) -> dict[str, Any]:
    path = scratchpad / APPENDIX_SIDECAR_NAME
    payload = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    unsigned = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    if (
        payload.get("schema_version") != APPENDIX_SCHEMA
        or payload.get("receipt_sha256") != _digest(unsigned)
        or payload.get("authority_receipt_sha256") != authority["receipt_sha256"]
        or payload.get("row_count") != len(payload.get("rows") or [])
        or payload.get("body_delivery_row_count")
        != len(payload.get("body_delivery_rows") or [])
    ):
        raise ValueError("appendix full-content sidecar schema/digest/authority mismatch")
    report = (project_root / "AUDIT_REPORT.md").read_bytes()
    report_text = report.decode("utf-8", errors="strict")
    expected_body_delivery = _body_delivery_rows(authority, report_text)
    if payload.get("body_delivery_rows") != expected_body_delivery:
        raise ValueError("appendix sidecar body-delivery binding mismatch")
    delivery_debt = sum(not bool(row["complete"]) for row in expected_body_delivery)
    if payload.get("body_delivery_debt_count") != delivery_debt:
        raise ValueError("appendix sidecar body-delivery debt count mismatch")
    for row in payload.get("rows") or []:
        try:
            raw = base64.b64decode(row["full_section_b64"], validate=True)
        except Exception as exc:
            raise ValueError("appendix full-content sidecar section encoding invalid") from exc
        if row.get("full_section_sha256") != _sha(raw) or row.get("full_section_size_bytes") != len(raw):
            raise ValueError("appendix full-content sidecar section digest mismatch")
        if not row.get("field_preservation", {}).get("passed"):
            raise ValueError("appendix client-field preservation diff failed")
        rid = str(row.get("report_id") or "")
        if re.search(
            rf"(?m)^###\s+(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[{re.escape(rid)}\]",
            report_text,
        ):
            raise ValueError(f"authorized appendix relocation left body section {rid}")
        projection = row.get("appendix_projection_fields") or {}
        appendix_row = re.search(
            rf"(?m)^\|\s*{re.escape(rid)}\s*\|\s*([^|]+?)\s*\|\s*"
            r"([^|]+?)\s*\|\s*([^|]+?)\s*\|",
            report_text,
        )
        if not appendix_row:
            raise ValueError(f"appendix projection row missing for {rid}")
        actual = {
            "severity": _severity(appendix_row.group(1), rid),
            "title": re.sub(r"\s+", " ", appendix_row.group(2)).strip(),
            "location": re.sub(
                r"\s+", " ", appendix_row.group(3).replace("`", "")
            ).strip(),
        }
        for field in ("severity", "title", "location"):
            if str(actual[field]).casefold() != str(projection.get(field) or "").casefold():
                raise ValueError(
                    f"appendix projection client-field mismatch for {rid}:{field}"
                )
        detail_section = _appendix_detail_section(report_text, rid)
        if not detail_section:
            raise ValueError(f"appendix full-content detail missing for {rid}")
        detail_fields = _appendix_detail_fields(rid, detail_section)
        if detail_fields != row.get("appendix_detail_fields"):
            raise ValueError(f"appendix full-content detail drift for {rid}")
        original_fields = row.get("original_client_fields") or {}
        for field in row.get("field_preservation", {}).get("compared_fields") or []:
            if str(detail_fields.get(field) or "").casefold() != str(
                original_fields.get(field) or ""
            ).casefold():
                raise ValueError(
                    f"appendix full-content client field mismatch for {rid}:{field}"
                )
    if delivery_debt:
        missing = ", ".join(
            str(row.get("candidate_id") or "")
            for row in expected_body_delivery
            if not row.get("complete")
        )
        raise ValueError(f"body delivery incomplete for: {missing}")
    return payload


def validate_report_disposition_authority(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    authority = _read_authority(Path(scratchpad), run_id=run_id)
    sidecar = Path(scratchpad) / APPENDIX_SIDECAR_NAME
    if not sidecar.is_file():
        raise ValueError("appendix full-content sidecar is missing")
    _validate_appendix_sidecar(Path(scratchpad), Path(project_root), authority)
    return authority


def reconcile_report_dispositions(
    scratchpad: Path,
    project_root: Path,
    *,
    run_id: str,
) -> dict[str, Any]:
    """Apply only independently authorized APPENDIX proposals, haltlessly."""
    root = Path(scratchpad)
    project = Path(project_root)
    authority = write_report_disposition_authority(root, run_id=run_id)
    try:
        authority = _read_authority(root, run_id=run_id)
    except ValueError as exc:
        return {"moved": 0, "ids": [], "issues": [str(exc)], "authority": authority}
    report_path = project / "AUDIT_REPORT.md"
    transaction_phase = "report_floor.disposition"
    candidate_relative = "report_floor.disposition.candidate.md"
    try:
        transaction_state = report_mutation_transaction_state(
            scratchpad=root,
            run_id=run_id,
            phase=transaction_phase,
        )
        if transaction_state is not None:
            recovered = recover_report_mutation_transaction(
                scratchpad=root,
                project_root=project,
                run_id=run_id,
                phase=transaction_phase,
                report_candidate_sidecar=candidate_relative,
            )
            if recovered is None:
                raise ReportMutationTransactionError(
                    "report disposition transaction has no recoverable manifest"
                )
            sidecar = _validate_appendix_sidecar(root, project, authority)
            moved_ids = [
                str(row.get("report_id") or "")
                for row in (sidecar.get("rows") or [])
                if str(row.get("report_id") or "")
            ]
            return {
                "moved": len(moved_ids),
                "ids": moved_ids,
                "issues": list(authority["issues"]),
                "authority": authority,
                "sidecar": sidecar,
            }
    except ReportMutationTransactionError as exc:
        return {
            "moved": 0,
            "ids": [],
            "issues": [f"report disposition transaction unavailable: {exc}"],
            "authority": authority,
        }
    try:
        report_bytes = report_path.read_bytes()
        report_text = report_bytes.decode("utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        return {
            "moved": 0,
            "ids": [],
            "issues": [f"report disposition source unavailable: {type(exc).__name__}: {exc}"],
            "authority": authority,
        }

    transaction_inputs = tuple(sorted({
        AUTHORITY_NAME,
        *(
            str(row.get("path") or "")
            for row in (authority.get("source_artifacts") or [])
            if isinstance(row, dict) and str(row.get("path") or "")
        ),
    }))
    try:
        transaction_input_snapshot = capture_report_transaction_inputs(
            root, transaction_inputs
        )
    except ReportMutationTransactionError as exc:
        return {
            "moved": 0,
            "ids": [],
            "issues": [f"report disposition input snapshot failed: {exc}"],
            "authority": authority,
        }

    sidecar_path = root / APPENDIX_SIDECAR_NAME
    if sidecar_path.is_file():
        try:
            sidecar = _validate_appendix_sidecar(root, project, authority)
            return {"moved": 0, "ids": [], "issues": list(authority["issues"]), "authority": authority, "sidecar": sidecar}
        except ValueError as exc:
            try:
                stale = json.loads(sidecar_path.read_text(encoding="utf-8", errors="strict"))
            except Exception:
                stale = {}
            if stale.get("pre_report_sha256") != _sha(report_bytes):
                return {"moved": 0, "ids": [], "issues": [str(exc)], "authority": authority}

    sections = _report_sections(report_text)
    requested: dict[str, tuple[str, str]] = {}
    issues = list(authority["issues"])
    authority_rows_by_rid: dict[str, list[Mapping[str, Any]]] = {}
    for authority_row in authority["rows"]:
        for report_id in authority_row.get("report_ids") or []:
            authority_rows_by_rid.setdefault(str(report_id), []).append(authority_row)
    expected_by_rid: dict[str, set[str]] = {}
    for candidate_id, report_ids in _report_id_map(root).items():
        for report_id in report_ids:
            expected_by_rid.setdefault(report_id, set()).add(candidate_id)
    for row in authority["rows"]:
        if row.get("public_retention_target") != "APPENDIX":
            continue
        for rid in row.get("report_ids") or []:
            section = sections.get(rid)
            if section is None:
                continue
            member_rows = authority_rows_by_rid.get(rid, [])
            represented = {
                _norm_id(str(item.get("candidate_id") or ""))
                for item in member_rows
                if _norm_id(str(item.get("candidate_id") or ""))
            }
            expected = expected_by_rid.get(rid, set())
            blockers = [
                str(item.get("candidate_id") or "")
                for item in member_rows
                if item.get("public_retention_target") != "APPENDIX"
            ]
            missing = sorted(expected - represented)
            if blockers or missing or not expected:
                issues.append(
                    f"{rid}: all exact report-row constituents must authorize APPENDIX; "
                    f"blocking={', '.join(sorted(set(blockers))) or 'none'}; "
                    f"unrepresented={', '.join(missing) or 'none'}"
                )
                continue
            lexical, lexical_reason = classify_body_or_appendix(
                row.get("candidate_id") or rid,
                row.get("upstream_severity") or "",
                section,
                row.get("verifier_status") or "",
            )
            # The classifier is a conservative disagreement alarm, never the
            # source of zero-harm authority.  Its unmatched/default BODY result
            # therefore cannot override an exact independent full-claim
            # decision; an explicit concrete-harm match can and must veto.
            if lexical == "BODY" and not lexical_reason.startswith("default"):
                issues.append(
                    f"{rid}: lexical/section contradiction vetoed authorized zero-harm relocation ({lexical_reason})"
                )
                continue
            proposal = next(
                (item for item in row.get("report_proposals") or [] if item.get("report_id") == rid),
                {},
            )
            requested[rid] = ("APPENDIX", str(proposal.get("reason") or "independent zero-harm decision"))

    from plamen_mechanical import enforce_material_harm_floor

    new_text, moved_rows = enforce_material_harm_floor(report_text, requested)
    moved_ids = {row[0] for row in moved_rows}
    if moved_ids != set(requested):
        missing = sorted(set(requested) - moved_ids)
        if missing:
            issues.append("authorized appendix projection could not preserve/report exact sections: " + ", ".join(missing))
        new_text = report_text
        moved_rows = []
    new_bytes = new_text.encode("utf-8")
    for delivery in _body_delivery_rows(authority, new_text):
        if delivery["complete"]:
            continue
        missing = sorted(
            set(delivery["report_ids"]) - set(delivery["rendered_report_ids"])
        )
        issues.append(
            f"{delivery['candidate_id']}: BODY report identity is not rendered; "
            f"missing={', '.join(missing) or 'no exact Master-index assignment'}"
        )
    sidecar = _appendix_payload(
        authority=authority,
        pre_report=report_bytes,
        post_report=new_bytes,
        sections=sections,
        moved_rows=moved_rows,
    )
    if any(not row["field_preservation"]["passed"] for row in sidecar["rows"]):
        issues.append("appendix client-field preservation diff vetoed relocation")
        new_bytes = report_bytes
        moved_rows = []
        sidecar = _appendix_payload(
            authority=authority,
            pre_report=report_bytes,
            post_report=report_bytes,
            sections=sections,
            moved_rows=[],
        )
    sidecar_bytes = _canonical_bytes(sidecar) + b"\n"
    try:
        apply_report_mutation_transaction(
            scratchpad=root,
            project_root=project,
            run_id=run_id,
            phase=transaction_phase,
            post_report=new_bytes,
            exact_inputs=transaction_inputs,
            expected_inputs=transaction_input_snapshot,
            sidecars={
                APPENDIX_SIDECAR_NAME: sidecar_bytes,
                candidate_relative: new_bytes,
            },
        )
    except ReportMutationTransactionError as exc:
        issues.append(f"report disposition transaction refused: {exc}")
        return {
            "moved": 0,
            "ids": [],
            "issues": sorted(set(issues)),
            "authority": authority,
        }
    try:
        _validate_appendix_sidecar(root, project, authority)
    except ValueError as exc:
        issues.append(str(exc))
    return {
        "moved": len(moved_rows),
        "ids": [row[0] for row in moved_rows],
        "issues": sorted(set(issues)),
        "authority": authority,
        "sidecar": sidecar,
    }


__all__ = [
    "APPENDIX_SIDECAR_NAME",
    "APPENDIX_SCHEMA",
    "AUTHORITY_NAME",
    "AUTHORITY_SCHEMA",
    "authorized_nonbody_internal_ids",
    "build_report_disposition_authority",
    "reconcile_report_dispositions",
    "validate_index_dispositions",
    "validate_report_disposition_authority",
    "write_report_disposition_authority",
]
