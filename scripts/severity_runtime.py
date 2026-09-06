"""Live, backend-neutral shadow wiring for typed severity decisions.

The runtime binds already-validated verifier Markdown and typed proposal
sidecars to driver-owned queue, launch, source-receipt, and evidence context.
It deliberately grants only mechanically observable evidence capabilities and
does not authorize report severity; report cutover is a later governed step.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping

from queue_work_items import VerifierOutputReceipt
from plamen_parsers import (
    _read_typed_queue_work_items,
    read_queue_work_plan,
)
from severity_decision_ledger import (
    LAUNCH_RECEIPT_SCHEMA,
    bind_severity_adjudication,
    bind_severity_proposal,
    load_severity_decision_ledger,
    parse_severity_adjudication_proposal,
    parse_severity_proposal,
    project_report_severity,
    project_retention_severity,
    severity_adjudicator_input_digest,
    severity_assessor_input_digest,
    write_severity_decision_ledger,
)
from trust_evidence_provider import constrain_trust_sensitive_report_projection


SHADOW_LEDGER_NAME = "severity_decision_ledger.shadow.json"
SHADOW_ADJUDICATION_MANIFEST_NAME = (
    "severity_adjudication_manifest.shadow.json"
)
SHADOW_ADJUDICATION_MANIFEST_SCHEMA = (
    "plamen.severity_adjudication_manifest.v1"
)
SHADOW_REPORT_RECEIPT_NAME = "severity_report_shadow_receipt.json"
FINAL_SHADOW_REPORT_RECEIPT_NAME = (
    "severity_final_report_shadow_receipt.json"
)
SHADOW_REPORT_RECEIPT_SCHEMA = "plamen.severity_report_shadow_receipt.v1"


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate severity runtime JSON key {key!r}")
        value[key] = item
    return value


def _strict_json_bytes(value: bytes | str) -> Any:
    text = (
        value.decode("utf-8", errors="strict")
        if isinstance(value, bytes)
        else value
    )
    return json.loads(text, object_pairs_hook=_strict_json_object)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    content = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _load_shadow_state(
    scratchpad: Path, *, run_id: str
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Load the aggregate and per-candidate views as one exact shadow state."""

    ledger_path = _canonical_file(scratchpad, SHADOW_LEDGER_NAME)
    raw = _strict_json_bytes(
        ledger_path.read_text(encoding="utf-8", errors="strict")
    )
    raw_rows = raw.get("decisions") if isinstance(raw, Mapping) else None
    if not isinstance(raw_rows, list):
        raise ValueError("severity shadow ledger decisions are unavailable")
    source_digests = {
        str(row.get("candidate_id") or ""): str(
            row.get("source_receipt_digest") or ""
        )
        for row in raw_rows
        if isinstance(row, Mapping)
    }
    ledger = load_severity_decision_ledger(
        ledger_path,
        expected_run_id=run_id,
        expected_source_receipt_digests=source_digests,
    )
    decisions: dict[str, dict[str, Any]] = {}
    for row in ledger["decisions"]:
        candidate_id = str(row["candidate_id"])
        path = _canonical_file(
            scratchpad, f"verify_{candidate_id}.severity_decision.json"
        )
        persisted = _strict_json_bytes(
            path.read_text(encoding="utf-8", errors="strict")
        )
        if persisted != row:
            raise ValueError(
                f"{candidate_id} severity decision/aggregate ledger mismatch"
            )
        decisions[candidate_id] = dict(row)
    return ledger, decisions


def _refresh_shadow_ledger(scratchpad: Path, *, run_id: str) -> Path:
    decisions: list[dict[str, Any]] = []
    paths: list[Path] = []
    suffix = ".severity_decision.json"
    for path in scratchpad.iterdir():
        name = path.name
        if not path.is_file() or not (
            name.casefold().startswith("verify_")
            and name.casefold().endswith(suffix)
        ):
            continue
        value = _strict_json_bytes(
            path.read_text(encoding="utf-8", errors="strict")
        )
        candidate_id = (
            str(value.get("candidate_id") or "")
            if isinstance(value, Mapping)
            else ""
        )
        expected_name = f"verify_{candidate_id}{suffix}"
        if not candidate_id or name != expected_name:
            raise ValueError(
                "canonical severity artifact ownership mismatch: expected "
                f"{expected_name}, found {name}"
            )
        paths.append(path)
    for path in sorted(paths):
        value = _strict_json_bytes(
            path.read_text(encoding="utf-8", errors="strict")
        )
        if isinstance(value, Mapping) and value.get("run_id") == run_id:
            decisions.append(dict(value))
    _optional_canonical_file(scratchpad, SHADOW_LEDGER_NAME)
    ledger_path = scratchpad / SHADOW_LEDGER_NAME
    write_severity_decision_ledger(ledger_path, run_id, decisions)
    return ledger_path


def _canonical_file(scratchpad: Path, expected_name: str) -> Path:
    variants = sorted(
        path.name
        for path in scratchpad.iterdir()
        if path.is_file() and path.name.casefold() == expected_name.casefold()
    )
    if variants != [expected_name]:
        raise ValueError(
            f"canonical severity artifact ownership mismatch: expected exactly "
            f"{expected_name}, found {variants}"
        )
    return scratchpad / expected_name


def _optional_canonical_file(
    scratchpad: Path, expected_name: str
) -> Path | None:
    variants = sorted(
        path.name
        for path in scratchpad.iterdir()
        if path.is_file() and path.name.casefold() == expected_name.casefold()
    )
    if not variants:
        return None
    if variants != [expected_name]:
        raise ValueError(
            f"canonical severity artifact ownership mismatch: expected exactly "
            f"{expected_name}, found {variants}"
        )
    return scratchpad / expected_name


def _direction(upstream: str, proposed: str) -> str:
    order = ("Critical", "High", "Medium", "Low", "Informational")
    if upstream not in order or proposed not in order:
        return "UNRESOLVED"
    if order.index(proposed) < order.index(upstream):
        return "UP"
    if order.index(proposed) > order.index(upstream):
        return "DOWN"
    return "NONE"


def _poc_attempted(markdown: str) -> bool:
    return bool(
        re.search(
            r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?"
            r"(?:PoC\s+)?Attempted(?:\*\*)?\s*:\s*YES\b",
            markdown or "",
        )
    )


def _proposal_evidence_receipts(
    proposal: Mapping[str, Any],
    *,
    constituents: list[str],
    verify_receipt: VerifierOutputReceipt,
    verify_markdown: str,
    launch_digest: str,
) -> list[dict[str, Any]]:
    references: dict[str, set[str]] = {}
    scopes: dict[str, set[str]] = {}
    for axis_name in ("impact", "likelihood"):
        axis = proposal.get(axis_name) or {}
        premise_id = str(axis.get("premise_id") or "").strip()
        proof_scope = str(axis.get("proof_scope") or "IN_SCOPE_SOURCE").upper()
        for evidence_id in axis.get("evidence_ids") or []:
            references.setdefault(str(evidence_id), set()).add(premise_id)
            scopes.setdefault(str(evidence_id), set()).add(proof_scope)
    adjustment = proposal.get("adjustment") or {}
    for evidence_id in adjustment.get("evidence_ids") or []:
        references.setdefault(str(evidence_id), set()).update(
            str(value) for value in adjustment.get("premise_ids") or []
        )
        scopes.setdefault(str(evidence_id), set()).add(
            str(adjustment.get("proof_scope") or "IN_SCOPE_SOURCE").upper()
        )
    for modifier in proposal.get("modifiers") or []:
        for evidence_id in modifier.get("evidence_ids") or []:
            references.setdefault(str(evidence_id), set())
            scopes.setdefault(str(evidence_id), set()).add(
                str(modifier.get("proof_scope") or "IN_SCOPE_SOURCE").upper()
            )

    receipts: list[dict[str, Any]] = []
    for evidence_id in sorted(references):
        # Verifier prose and an ``Attempted: YES`` label are claims, not an
        # execution receipt.  Until a driver-validated provider supplies
        # command/output/oracle/reachability authority, this projection may
        # bind the source mechanism but must not mint EXECUTION or a stronger
        # proof scope.  The mismatch remains explicit challenge debt.
        proof_scope = "IN_SCOPE_SOURCE"
        capabilities = ["MECHANISM"]
        receipts.append(
            {
                "evidence_id": evidence_id,
                "content_sha256": verify_receipt.output_sha256,
                "premise_ids": sorted(value for value in references[evidence_id] if value),
                "constituent_ids": sorted(constituents),
                "proof_scope": proof_scope,
                "capabilities": sorted(capabilities),
                "issuer_identity": "plamen-driver-evidence-registry",
                "issuer_invocation_id": launch_digest,
            }
        )
    return receipts


def _resolve_shadow_assignment(
    plan,
    phase_name: str,
    assigned_work_item_ids: Iterable[str] | None,
) -> tuple[str, ...]:
    if assigned_work_item_ids is None:
        return tuple(plan.shard(phase_name).ordered_work_item_ids)
    assigned = tuple(assigned_work_item_ids)
    if len(set(assigned)) != len(assigned):
        raise ValueError("dynamic severity assignment contains duplicate IDs")
    known = set(plan.ordered_work_item_ids)
    unknown = [candidate_id for candidate_id in assigned if candidate_id not in known]
    if unknown:
        raise ValueError(
            "dynamic severity assignment contains unknown IDs: "
            + ", ".join(unknown)
        )
    canonical = tuple(
        candidate_id
        for candidate_id in plan.ordered_work_item_ids
        if candidate_id in set(assigned)
    )
    if assigned != canonical:
        raise ValueError("dynamic severity assignment order differs from QueueWorkPlan")
    return assigned


def bind_shadow_severity_for_shard(
    scratchpad: Path,
    phase_name: str,
    *,
    backend: str,
    launch_digest: str,
    run_id: str,
    assigned_work_item_ids: Iterable[str] | None = None,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Bind one completed shard and refresh the non-authoritative shadow ledger."""

    scratchpad = Path(scratchpad)
    try:
        plan = read_queue_work_plan(scratchpad)
        assigned = _resolve_shadow_assignment(
            plan, phase_name, assigned_work_item_ids
        )
        items = {
            item.work_item_id: item
            for item in _read_typed_queue_work_items(
                scratchpad / "verification_queue.md"
            )
        }
    except Exception as exc:
        return (), (
            "severity shadow work-plan authority unavailable or invalid: "
            f"{type(exc).__name__}: {exc}",
        )
    written: list[Path] = []
    issues: list[str] = []
    for work_item_id in assigned:
        try:
            item = items[work_item_id]
            proposal_path = scratchpad / (
                f"verify_{work_item_id}.severity_proposal.json"
            )
            verify_path = scratchpad / item.expected_output_file
            receipt_path = scratchpad / f"verify_{work_item_id}.receipt.json"
            proposal_bytes = proposal_path.read_bytes()
            verify_bytes = verify_path.read_bytes()
            receipt_payload = _strict_json_bytes(receipt_path.read_bytes())
            proposal = parse_severity_proposal(proposal_bytes)
            verify_markdown = verify_bytes.decode("utf-8", errors="strict")
            verify_receipt = VerifierOutputReceipt.from_dict(
                receipt_payload
            )
            verify_receipt.validate_against(
                item,
                plan,
                verify_bytes,
                severity_proposal=proposal_bytes,
                launch_digest=launch_digest,
                verifier_backend=backend,
            )
            constituents = [item.work_item_id, *item.constituents]
            evidence_receipts = _proposal_evidence_receipts(
                proposal,
                constituents=constituents,
                verify_receipt=verify_receipt,
                verify_markdown=verify_markdown,
                launch_digest=launch_digest,
            )
            assessor_identity = f"verifier-{backend}-{phase_name}"
            invocation_id = f"{launch_digest}-{work_item_id}"
            input_sha256 = severity_assessor_input_digest(
                candidate_id=work_item_id,
                constituent_ids=constituents,
                upstream_severity=item.severity_proposal.level,
                run_id=run_id,
                source_receipt_digest=verify_receipt.digest,
                evidence_receipts=evidence_receipts,
            )
            launch_receipt = {
                "schema_version": LAUNCH_RECEIPT_SCHEMA,
                "role": "ASSESSOR",
                "run_id": run_id,
                "candidate_id": work_item_id,
                "constituent_ids": constituents,
                "worker_identity": assessor_identity,
                "invocation_id": invocation_id,
                "backend": backend,
                "launch_manifest_sha256": launch_digest,
                "input_sha256": input_sha256,
                "output_sha256": _digest(proposal),
            }
            decision = bind_severity_proposal(
                proposal,
                candidate_id=work_item_id,
                constituent_ids=constituents,
                upstream_severity=item.severity_proposal.level,
                assessor_identity=assessor_identity,
                assessor_invocation_id=invocation_id,
                run_id=run_id,
                source_receipt_digest=verify_receipt.digest,
                evidence_receipts=evidence_receipts,
                assessor_launch_receipt=launch_receipt,
            )
            decision_path = scratchpad / (
                f"verify_{work_item_id}.severity_decision.json"
            )
            _atomic_json(decision_path, decision)
            written.append(decision_path)
        except Exception as exc:
            issues.append(
                f"{work_item_id} severity shadow binding failed: "
                f"{type(exc).__name__}: {exc}"
            )
    if not issues:
        decisions = []
        for path in sorted(scratchpad.glob("verify_*.severity_decision.json")):
            try:
                value = _strict_json_bytes(
                    path.read_text(encoding="utf-8", errors="strict")
                )
                if isinstance(value, Mapping) and value.get("run_id") == run_id:
                    decisions.append(dict(value))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
        ledger_path = scratchpad / SHADOW_LEDGER_NAME
        write_severity_decision_ledger(ledger_path, run_id, decisions)
        written.append(ledger_path)
    return tuple(written), tuple(issues)


def validate_shadow_severity_for_shard(
    scratchpad: Path,
    phase_name: str,
    *,
    backend: str,
    launch_digest: str,
    run_id: str,
    assigned_work_item_ids: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Side-effect-free completeness/authority check for verifier precommit."""

    scratchpad = Path(scratchpad)
    ledger_path = scratchpad / SHADOW_LEDGER_NAME
    if not ledger_path.is_file():
        return ("severity shadow ledger missing before verifier commit",)
    try:
        plan = read_queue_work_plan(scratchpad)
        assigned = _resolve_shadow_assignment(
            plan, phase_name, assigned_work_item_ids
        )
        items = {
            item.work_item_id: item
            for item in _read_typed_queue_work_items(
                scratchpad / "verification_queue.md"
            )
        }
    except Exception as exc:
        return (
            "severity shadow work-plan authority unavailable or invalid: "
            f"{type(exc).__name__}: {exc}",
        )
    for candidate_id in assigned:
        if not (
            scratchpad / f"verify_{candidate_id}.severity_decision.json"
        ).is_file():
            return (
                f"{candidate_id} severity decision missing before verifier commit",
            )
    try:
        _ledger, decisions = _load_shadow_state(scratchpad, run_id=run_id)
    except Exception as exc:
        return (
            "severity shadow ledger/decision validation failed: "
            f"{type(exc).__name__}: {exc}",
        )
    issues: list[str] = []
    for candidate_id in assigned:
        decision = decisions.get(candidate_id)
        if decision is None:
            issues.append(
                f"{candidate_id} severity decision missing from shadow ledger"
            )
            continue
        item = items[candidate_id]
        expected_constituents = [item.work_item_id, *item.constituents]
        if decision.get("constituent_ids") != expected_constituents:
            issues.append(
                f"{candidate_id} severity decision constituent identity mismatch"
            )
        if decision.get("upstream_severity") != item.severity_proposal.level:
            issues.append(
                f"{candidate_id} severity decision upstream severity mismatch"
            )
        receipt_path = scratchpad / f"verify_{candidate_id}.receipt.json"
        try:
            receipt = VerifierOutputReceipt.from_json(
                receipt_path.read_text(encoding="utf-8", errors="strict")
            )
            if decision.get("source_receipt_digest") != receipt.digest:
                issues.append(
                    f"{candidate_id} severity decision source receipt mismatch"
                )
            producer = (
                (decision.get("assessment") or {})
                .get("producer_authority_binding", {})
                .get("receipt", {})
            )
            if (
                producer.get("backend") != backend
                or producer.get("launch_manifest_sha256") != launch_digest
            ):
                issues.append(
                    f"{candidate_id} severity decision launch/backend mismatch"
                )
        except Exception as exc:
            issues.append(
                f"{candidate_id} severity source receipt unreadable: "
                f"{type(exc).__name__}: {exc}"
            )
    return tuple(issues)


def ensure_shadow_severity_for_shard(
    scratchpad: Path,
    phase_name: str,
    *,
    backend: str,
    launch_digest: str,
    run_id: str,
    assigned_work_item_ids: Iterable[str] | None = None,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Idempotently reconstruct a driver-owned shadow projection once."""

    issues = validate_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend=backend,
        launch_digest=launch_digest,
        run_id=run_id,
        assigned_work_item_ids=assigned_work_item_ids,
    )
    if not issues:
        return (), ()
    # Reconstruction is permitted only from a complete, exact v2 verifier
    # transaction.  Never build shadow authority around stale/tampered bytes.
    try:
        plan = read_queue_work_plan(Path(scratchpad))
        assigned = _resolve_shadow_assignment(
            plan, phase_name, assigned_work_item_ids
        )
        items = {
            item.work_item_id: item
            for item in _read_typed_queue_work_items(
                Path(scratchpad) / "verification_queue.md"
            )
        }
        for candidate_id in assigned:
            item = items[candidate_id]
            output_path = _canonical_file(
                Path(scratchpad), item.expected_output_file
            )
            proposal_path = _canonical_file(
                Path(scratchpad),
                f"verify_{candidate_id}.severity_proposal.json",
            )
            receipt_path = _canonical_file(
                Path(scratchpad), f"verify_{candidate_id}.receipt.json"
            )
            receipt = VerifierOutputReceipt.from_json(
                receipt_path.read_text(encoding="utf-8", errors="strict")
            )
            receipt.validate_against(
                item,
                plan,
                output_path.read_bytes(),
                severity_proposal=proposal_path.read_bytes(),
                launch_digest=launch_digest,
                verifier_backend=backend,
            )
    except Exception as exc:
        return (), (
            "severity shadow deterministic reconstruction source invalid: "
            f"{type(exc).__name__}: {exc}",
        )
    written, bind_issues = bind_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend=backend,
        launch_digest=launch_digest,
        run_id=run_id,
        assigned_work_item_ids=assigned_work_item_ids,
    )
    if bind_issues:
        return written, bind_issues
    return written, validate_shadow_severity_for_shard(
        scratchpad,
        phase_name,
        backend=backend,
        launch_digest=launch_digest,
        run_id=run_id,
        assigned_work_item_ids=assigned_work_item_ids,
    )


def build_shadow_adjudication_manifest(
    scratchpad: Path, *, run_id: str
) -> dict[str, Any]:
    """Enumerate every unresolved severity transaction without tier filtering."""

    scratchpad = Path(scratchpad)
    ledger, decisions = _load_shadow_state(scratchpad, run_id=run_id)
    work_items: list[dict[str, Any]] = []
    for candidate_id in sorted(decisions):
        decision = decisions[candidate_id]
        if decision.get("status") == "RESOLVED":
            continue
        status = {
            "CHALLENGE_REQUIRED": "PENDING",
            "INCOMPLETE": "ASSESSOR_REPAIR_REQUIRED",
            "UNRESOLVED_SEVERITY": "COMPLETED_UNRESOLVED",
        }.get(str(decision.get("status") or ""), "PENDING")
        work_items.append(
            {
                "candidate_id": candidate_id,
                "constituent_ids": list(decision.get("constituent_ids") or []),
                "upstream_severity": decision.get("upstream_severity"),
                "proposed_severity": decision.get("proposed_severity"),
                "direction": _direction(
                    str(decision.get("upstream_severity") or ""),
                    str(decision.get("proposed_severity") or ""),
                ),
                "source_decision_digest": decision["decision_digest"],
                "input_sha256": severity_adjudicator_input_digest(decision),
                "status": status,
                "expected_output_file": (
                    f"verify_{candidate_id}.severity_adjudication_proposal.json"
                ),
            }
        )
    unsigned = {
        "schema_version": SHADOW_ADJUDICATION_MANIFEST_SCHEMA,
        "run_id": run_id,
        "source_ledger_digest": ledger["ledger_digest"],
        "work_item_count": len(work_items),
        "work_items": work_items,
    }
    payload = {**unsigned, "manifest_digest": _digest(unsigned)}
    _atomic_json(
        scratchpad / SHADOW_ADJUDICATION_MANIFEST_NAME,
        payload,
    )
    return payload


def _adjudication_receipt_payload(
    *,
    decision: Mapping[str, Any],
    proposal_path: Path,
    proposal_bytes: bytes,
    launch_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    history = list(decision.get("adjudication_history") or [])
    source_decision_digest = (
        str(history[-1].get("source_decision_digest") or "")
        if history and isinstance(history[-1], Mapping)
        else ""
    )
    unsigned = {
        "schema_version": "plamen.severity_adjudication_receipt.v1",
        "candidate_id": decision["candidate_id"],
        "source_decision_digest": source_decision_digest,
        "adjudicator_input_sha256": launch_receipt["input_sha256"],
        "result_decision_digest": decision["decision_digest"],
        "proposal_file": proposal_path.name,
        "proposal_sha256": hashlib.sha256(proposal_bytes).hexdigest(),
        "proposal_size_bytes": len(proposal_bytes),
        "launch_receipt": dict(launch_receipt),
    }
    return {**unsigned, "receipt_digest": _digest(unsigned)}


def _validate_adjudication_receipt(
    scratchpad: Path,
    decision: Mapping[str, Any],
) -> dict[str, Any] | None:
    history = list(decision.get("adjudication_history") or [])
    if not history:
        return None
    candidate_id = str(decision.get("candidate_id") or "")
    proposal_path = _canonical_file(
        scratchpad,
        f"verify_{candidate_id}.severity_adjudication_proposal.json",
    )
    receipt_path = _canonical_file(
        scratchpad,
        f"verify_{candidate_id}.severity_adjudication_receipt.json",
    )
    proposal_bytes = proposal_path.read_bytes()
    proposal = parse_severity_adjudication_proposal(proposal_bytes)
    receipt = _strict_json_bytes(receipt_path.read_bytes())
    expected_keys = {
        "schema_version",
        "candidate_id",
        "source_decision_digest",
        "adjudicator_input_sha256",
        "result_decision_digest",
        "proposal_file",
        "proposal_sha256",
        "proposal_size_bytes",
        "launch_receipt",
        "receipt_digest",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        raise ValueError("severity adjudication receipt schema mismatch")
    unsigned = {
        key: value for key, value in receipt.items() if key != "receipt_digest"
    }
    if (
        receipt.get("schema_version")
        != "plamen.severity_adjudication_receipt.v1"
        or receipt.get("receipt_digest") != _digest(unsigned)
        or receipt.get("candidate_id") != candidate_id
        or receipt.get("result_decision_digest")
        != decision.get("decision_digest")
        or receipt.get("proposal_file") != proposal_path.name
        or receipt.get("proposal_sha256")
        != hashlib.sha256(proposal_bytes).hexdigest()
        or receipt.get("proposal_size_bytes") != len(proposal_bytes)
    ):
        raise ValueError("severity adjudication receipt binding mismatch")
    event = history[-1]
    if not isinstance(event, Mapping):
        raise ValueError("severity adjudication history event is malformed")
    launch_receipt = (
        (event.get("adjudicator_authority_binding") or {}).get("receipt")
        or {}
    )
    # Report projection must replay the process-owning provider transaction,
    # not merely the model-authored proposal or a caller-authored launch label.
    from severity_adjudication_work import (
        validate_completed_worker_run_for_candidate,
    )

    worker_run = validate_completed_worker_run_for_candidate(
        scratchpad, candidate_id
    )
    if (
        receipt.get("launch_receipt") != launch_receipt
        or receipt.get("source_decision_digest")
        != event.get("source_decision_digest")
        or receipt.get("adjudicator_input_sha256")
        != launch_receipt.get("input_sha256")
        or launch_receipt.get("output_sha256") != _digest(proposal)
        or launch_receipt.get("run_id") != worker_run.get("run_id")
        or launch_receipt.get("worker_identity")
        != worker_run.get("worker_identity")
        or launch_receipt.get("invocation_id")
        != worker_run.get("invocation_id")
        or launch_receipt.get("backend") != worker_run.get("backend")
        or launch_receipt.get("launch_manifest_sha256")
        != worker_run.get("receipt_digest")
    ):
        raise ValueError("severity adjudication authority receipt mismatch")
    return receipt


def _validate_original_verifier_sources(
    scratchpad: Path,
    decisions: Mapping[str, Mapping[str, Any]],
) -> None:
    """Revalidate the immutable AG-1 transaction when its plan is present."""

    queue_path = scratchpad / "verification_queue.md"
    if not queue_path.is_file():
        # Pure-ledger/offline shadow fixtures have no executable queue.  They
        # remain SHADOW_ONLY and cannot be used by the later cutover gate.
        return
    plan = read_queue_work_plan(scratchpad)
    items = {
        item.work_item_id: item
        for item in _read_typed_queue_work_items(queue_path)
    }
    for candidate_id, decision in decisions.items():
        item = items.get(candidate_id)
        if item is None:
            raise ValueError(
                f"{candidate_id} severity decision has no queue authority"
            )
        output_path = _canonical_file(scratchpad, item.expected_output_file)
        proposal_path = _canonical_file(
            scratchpad, f"verify_{candidate_id}.severity_proposal.json"
        )
        receipt_path = _canonical_file(
            scratchpad, f"verify_{candidate_id}.receipt.json"
        )
        output_bytes = output_path.read_bytes()
        proposal_bytes = proposal_path.read_bytes()
        parse_severity_proposal(proposal_bytes)
        receipt = VerifierOutputReceipt.from_dict(
            _strict_json_bytes(receipt_path.read_bytes())
        )
        producer = (
            (decision.get("assessment") or {})
            .get("producer_authority_binding", {})
            .get("receipt", {})
        )
        receipt.validate_against(
            item,
            plan,
            output_bytes,
            severity_proposal=proposal_bytes,
            launch_digest=str(producer.get("launch_manifest_sha256") or ""),
            verifier_backend=str(producer.get("backend") or ""),
        )
        if decision.get("source_receipt_digest") != receipt.digest:
            raise ValueError(
                f"{candidate_id} severity decision source receipt mismatch"
            )


def bind_shadow_adjudication_for_candidate(
    scratchpad: Path,
    candidate_id: str,
    *,
    backend: str,
    launch_digest: str,
    run_id: str,
    worker_identity: str,
    invocation_id: str,
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Bind one independently launched proposal and refresh shadow authority.

    Failures leave the prior decision untouched.  Replaying the exact launch is
    byte-idempotent; a genuinely different second adjudication is retained as
    conflict rather than becoming last-writer-wins authority.
    """

    scratchpad = Path(scratchpad)
    try:
        from severity_adjudication_work import (
            validate_completed_worker_run_for_candidate,
        )

        worker_run = validate_completed_worker_run_for_candidate(
            scratchpad, candidate_id
        )
        expected_authority = {
            "backend": worker_run.get("backend"),
            "launch_digest": worker_run.get("receipt_digest"),
            "run_id": worker_run.get("run_id"),
            "worker_identity": worker_run.get("worker_identity"),
            "invocation_id": worker_run.get("invocation_id"),
        }
        supplied_authority = {
            "backend": backend,
            "launch_digest": launch_digest,
            "run_id": run_id,
            "worker_identity": worker_identity,
            "invocation_id": invocation_id,
        }
        if supplied_authority != expected_authority:
            raise ValueError(
                "caller adjudication authority differs from provider-owned worker receipt"
            )
        # From this point onward only replayed provider fields are used.
        backend = str(worker_run["backend"])
        launch_digest = str(worker_run["receipt_digest"])
        run_id = str(worker_run["run_id"])
        worker_identity = str(worker_run["worker_identity"])
        invocation_id = str(worker_run["invocation_id"])
        try:
            _ledger, decisions = _load_shadow_state(
                scratchpad, run_id=run_id
            )
        except Exception:
            # A candidate decision is the recovery authority because it embeds
            # the exact adjudicator receipt.  Rebuilding the aggregate invokes
            # full semantic replay for every sidecar and therefore cannot bless
            # an arbitrary/tampered partial write.
            _refresh_shadow_ledger(scratchpad, run_id=run_id)
            _ledger, decisions = _load_shadow_state(
                scratchpad, run_id=run_id
            )
        # Adjudication is a new authority-bearing state transition.  Recheck
        # the complete verifier transaction at that boundary rather than
        # trusting that it was valid when the shadow decision was first made.
        _validate_original_verifier_sources(scratchpad, decisions)
        decision = decisions[candidate_id]
        expected_name = (
            f"verify_{candidate_id}.severity_adjudication_proposal.json"
        )
        proposal_path = _canonical_file(scratchpad, expected_name)
        proposal_bytes = proposal_path.read_bytes()
        proposal = parse_severity_adjudication_proposal(proposal_bytes)
        input_sha256 = severity_adjudicator_input_digest(decision)
        output_sha256 = _digest(proposal)
        launch_receipt = {
            "schema_version": LAUNCH_RECEIPT_SCHEMA,
            "role": "ADJUDICATOR",
            "run_id": run_id,
            "candidate_id": candidate_id,
            "constituent_ids": list(decision.get("constituent_ids") or []),
            "worker_identity": worker_identity,
            "invocation_id": invocation_id,
            "backend": backend,
            "launch_manifest_sha256": launch_digest,
            "input_sha256": input_sha256,
            "output_sha256": output_sha256,
        }

        # Exact replay must not create a second adjudication history entry.
        history = list(decision.get("adjudication_history") or [])
        if history:
            prior_binding = history[-1].get("adjudicator_authority_binding") or {}
            prior_receipt = prior_binding.get("receipt") or {}
            replay_fields = (
                "schema_version",
                "role",
                "run_id",
                "candidate_id",
                "constituent_ids",
                "worker_identity",
                "invocation_id",
                "backend",
                "launch_manifest_sha256",
                "output_sha256",
            )
            if all(
                prior_receipt.get(field) == launch_receipt.get(field)
                for field in replay_fields
            ):
                receipt_path = scratchpad / (
                    f"verify_{candidate_id}.severity_adjudication_receipt.json"
                )
                # Exact replay includes exact worker bytes, not merely a
                # semantically equivalent parsed JSON object.  Receipt-first
                # commit ordering makes a missing receipt with committed
                # history an invalid mutation, not a reconstructable crash.
                _validate_adjudication_receipt(scratchpad, decision)
                receipt_payload = _adjudication_receipt_payload(
                    decision=decision,
                    proposal_path=proposal_path,
                    proposal_bytes=proposal_bytes,
                    launch_receipt=prior_receipt,
                )
                _atomic_json(receipt_path, receipt_payload)
                ledger_path = _refresh_shadow_ledger(
                    scratchpad, run_id=run_id
                )
                return (
                    scratchpad / f"verify_{candidate_id}.severity_decision.json",
                    receipt_path,
                    ledger_path,
                ), ()

        updated = bind_severity_adjudication(
            proposal,
            decision=decision,
            adjudicator_launch_receipt=launch_receipt,
        )
        decision_path = scratchpad / (
            f"verify_{candidate_id}.severity_decision.json"
        )
        receipt_path = scratchpad / (
            f"verify_{candidate_id}.severity_adjudication_receipt.json"
        )
        receipt_payload = _adjudication_receipt_payload(
            decision=updated,
            proposal_path=proposal_path,
            proposal_bytes=proposal_bytes,
            launch_receipt=launch_receipt,
        )
        # Persist the raw-byte receipt first.  The decision embeds its launch
        # receipt and is the semantic recovery authority; the standalone
        # receipt supplies the exact-byte authority canonical JSON cannot.
        _atomic_json(receipt_path, receipt_payload)
        _atomic_json(decision_path, updated)
        ledger_path = _refresh_shadow_ledger(scratchpad, run_id=run_id)
        return (decision_path, receipt_path, ledger_path), ()
    except Exception as exc:
        return (), (
            f"{candidate_id} severity adjudication binding failed: "
            f"{type(exc).__name__}: {exc}",
        )


def recover_receipt_pending_decision_commit(
    scratchpad: Path, candidate_id: str
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Commit exactly one already-validated receipt-first transition.

    The caller supplies no process or principal authority.  Reconciliation and
    the provider-owned worker receipt must prove that the persisted raw-output
    receipt is exactly the next transition before this function writes only the
    decision and aggregate ledger.  The receipt itself is never replaced.
    """

    root = Path(scratchpad)
    try:
        from severity_adjudication_work import (
            reconcile_adjudication_work,
            validate_completed_worker_run_for_candidate,
        )

        reconciliation = reconcile_adjudication_work(root)
        if reconciliation.get("states", {}).get(candidate_id) != (
            "RECEIPT_PENDING_DECISION_COMMIT"
        ):
            raise ValueError(
                "candidate is not in the exact receipt-pending commit state"
            )
        worker_run = validate_completed_worker_run_for_candidate(
            root, candidate_id
        )
        decision_path = _canonical_file(
            root, f"verify_{candidate_id}.severity_decision.json"
        )
        proposal_path = _canonical_file(
            root,
            f"verify_{candidate_id}.severity_adjudication_proposal.json",
        )
        receipt_path = _canonical_file(
            root,
            f"verify_{candidate_id}.severity_adjudication_receipt.json",
        )
        decision = _strict_json_bytes(decision_path.read_bytes())
        proposal_bytes = proposal_path.read_bytes()
        proposal = parse_severity_adjudication_proposal(proposal_bytes)
        receipt = _strict_json_bytes(receipt_path.read_bytes())
        if not isinstance(decision, dict) or not isinstance(receipt, dict):
            raise ValueError("receipt-first authority is malformed")
        launch = receipt.get("launch_receipt")
        if not isinstance(launch, dict):
            raise ValueError("receipt-first launch authority is malformed")
        updated = bind_severity_adjudication(
            proposal,
            decision=decision,
            adjudicator_launch_receipt=launch,
        )
        expected_receipt = _adjudication_receipt_payload(
            decision=updated,
            proposal_path=proposal_path,
            proposal_bytes=proposal_bytes,
            launch_receipt=launch,
        )
        if receipt != expected_receipt:
            raise ValueError(
                "persisted receipt does not bind the exact next decision"
            )
        if (
            launch.get("run_id") != worker_run.get("run_id")
            or launch.get("worker_identity")
            != worker_run.get("worker_identity")
            or launch.get("invocation_id") != worker_run.get("invocation_id")
            or launch.get("backend") != worker_run.get("backend")
            or launch.get("launch_manifest_sha256")
            != worker_run.get("receipt_digest")
        ):
            raise ValueError(
                "receipt-first launch authority differs from provider evidence"
            )
        _atomic_json(decision_path, updated)
        ledger_path = _refresh_shadow_ledger(
            root, run_id=str(worker_run["run_id"])
        )
        return (decision_path, receipt_path, ledger_path), ()
    except Exception as exc:
        return (), (
            f"{candidate_id} receipt-first recovery failed: "
            f"{type(exc).__name__}: {exc}",
        )


def _canonical_severity(value: Any) -> str | None:
    text = str(value or "").strip().strip("`*_").title()
    text = {
        "C": "Critical",
        "H": "High",
        "M": "Medium",
        "L": "Low",
        "I": "Informational",
    }.get(text, text)
    if text == "Info":
        text = "Informational"
    return text if text in {
        "Critical", "High", "Medium", "Low", "Informational"
    } else None


def _legacy_report_index_rows(scratchpad: Path) -> list[dict[str, str]]:
    path = _optional_canonical_file(scratchpad, "report_index.md")
    if path is None:
        return []
    normalized: list[dict[str, str]] = []
    headers: list[str] | None = None
    in_master_index = False
    for row_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(),
        start=1,
    ):
        stripped = line.strip()
        if stripped.startswith("## "):
            in_master_index = (
                re.sub(r"\s+", " ", stripped).casefold()
                == "## master finding index"
            )
            headers = None
            continue
        if not in_master_index:
            continue
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        lowered = [re.sub(r"\s+", " ", cell).casefold() for cell in cells]
        if "report id" in lowered and "severity" in lowered:
            headers = lowered
            continue
        if headers is None or all(
            re.fullmatch(r":?-{3,}:?", cell.replace(" ", ""))
            for cell in cells
        ):
            continue
        if len(cells) != len(headers):
            raise ValueError(
                f"report_index row {row_number} column count mismatch"
            )
        values = dict(zip(headers, cells))
        candidate_cell = (
            values.get("source findings")
            or values.get("internal")
            or values.get("finding id")
            or ""
        )
        candidates = re.findall(
            r"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9]*-\d+[A-Za-z0-9]*)"
            r"(?![A-Za-z0-9_-])",
            candidate_cell,
        )
        for candidate in candidates:
            normalized.append(
                {
                    "report_id": values.get("report id", ""),
                    "candidate_id": candidate.upper(),
                    "severity": values.get("severity", ""),
                    "row_number": str(row_number),
                }
            )
    return normalized


def _body_severities(
    scratchpad: Path, report_ids: set[str]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    observed: dict[str, list[dict[str, Any]]] = {}
    digests: dict[str, str] = {}
    for name in (
        "report_critical_high.md",
        "report_medium.md",
        "report_low_info.md",
    ):
        path = _optional_canonical_file(scratchpad, name)
        if path is None:
            continue
        raw = path.read_bytes()
        digests[name] = hashlib.sha256(raw).hexdigest()
        text = raw.decode("utf-8", errors="replace")
        headings = list(
            re.finditer(
                r"(?im)^#{2,4}\s*\[([CHMLI]-\d+)\][^\n]*$", text
            )
        )
        for index, heading in enumerate(headings):
            report_id = heading.group(1).upper()
            if report_id not in report_ids:
                continue
            end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
            block = text[heading.end():end]
            match = re.search(
                r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Severity(?:\*\*)?\s*:\s*"
                r"(Critical|High|Medium|Low|Informational|Info)\b",
                block,
            )
            if match:
                severity = _canonical_severity(match.group(1))
            else:
                severity = None
            observed.setdefault(report_id, []).append(
                {
                    "file": name,
                    "heading_offset": heading.start(),
                    "severity": severity,
                }
            )
    return observed, digests


def _single_report_severities(
    path: Path, report_ids: set[str], *, surface_name: str
) -> tuple[dict[str, list[dict[str, Any]]], str]:
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    observed: dict[str, list[dict[str, Any]]] = {}
    headings = list(
        re.finditer(r"(?im)^#{2,4}\s*\[([CHMLI]-\d+)\][^\n]*$", text)
    )
    for index, heading in enumerate(headings):
        report_id = heading.group(1).upper()
        if report_id not in report_ids:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        block = text[heading.end():end]
        match = re.search(
            r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Severity(?:\*\*)?\s*:\s*"
            r"(Critical|High|Medium|Low|Informational|Info)\b",
            block,
        )
        observed.setdefault(report_id, []).append({
            "file": surface_name,
            "heading_offset": heading.start(),
            "severity": _canonical_severity(match.group(1)) if match else None,
        })
    return observed, hashlib.sha256(raw).hexdigest()


def write_shadow_report_severity_receipt(
    scratchpad: Path,
    *,
    run_id: str,
    projection_stage: str = "PRE_ASSEMBLE",
    project_root: Path | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Plan or record report-tier drift without report mutation authority."""

    scratchpad = Path(scratchpad)
    stage = str(projection_stage or "").strip().upper()
    if stage not in {"PRE_ASSEMBLE", "POST_REPORT_FLOOR"}:
        raise ValueError("unsupported severity report projection stage")
    ledger, decisions = _load_shadow_state(scratchpad, run_id=run_id)
    _validate_original_verifier_sources(scratchpad, decisions)
    for decision in decisions.values():
        _validate_adjudication_receipt(scratchpad, decision)
    index_path = _optional_canonical_file(scratchpad, "report_index.md")
    index_bytes = index_path.read_bytes() if index_path is not None else b""
    index_rows = _legacy_report_index_rows(scratchpad)
    by_candidate: dict[str, list[dict[str, str]]] = {}
    by_report_id: dict[str, list[dict[str, str]]] = {}
    for row in index_rows:
        if row.get("candidate_id"):
            by_candidate.setdefault(row["candidate_id"].upper(), []).append(row)
        if row.get("report_id"):
            by_report_id.setdefault(row["report_id"].upper(), []).append(row)
    report_ids = {
        row.get("report_id", "").upper()
        for row in index_rows
        if row.get("report_id")
    }
    pre_receipt_sha256: str | None = None
    final_report_sha256: str | None = None
    if stage == "PRE_ASSEMBLE":
        body_severities, body_digests = _body_severities(
            scratchpad, report_ids
        )
        body_surface = "REPORT_BODY"
        output_name = SHADOW_REPORT_RECEIPT_NAME
    else:
        if project_root is None:
            raise ValueError("POST_REPORT_FLOOR requires project_root")
        pre_path = _canonical_file(scratchpad, SHADOW_REPORT_RECEIPT_NAME)
        pre_bytes = pre_path.read_bytes()
        pre_receipt = _strict_json_bytes(pre_bytes)
        if not isinstance(pre_receipt, dict):
            raise ValueError("pre-assemble severity projection is malformed")
        pre_unsigned = {
            key: value for key, value in pre_receipt.items()
            if key != "receipt_digest"
        }
        if (
            pre_receipt.get("schema_version") != SHADOW_REPORT_RECEIPT_SCHEMA
            or pre_receipt.get("projection_stage") != "PRE_ASSEMBLE"
            or pre_receipt.get("run_id") != run_id
            or pre_receipt.get("receipt_digest") != _digest(pre_unsigned)
            or pre_receipt.get("severity_ledger_digest")
            != ledger.get("ledger_digest")
        ):
            raise ValueError("pre-assemble severity projection authority is invalid")
        pre_receipt_sha256 = hashlib.sha256(pre_bytes).hexdigest()
        report_path = _canonical_file(Path(project_root), "AUDIT_REPORT.md")
        body_severities, digest = _single_report_severities(
            report_path, report_ids, surface_name="AUDIT_REPORT.md"
        )
        body_digests = {"AUDIT_REPORT.md": digest}
        final_report_sha256 = digest
        body_surface = "FINAL_REPORT"
        output_name = FINAL_SHADOW_REPORT_RECEIPT_NAME
    rows: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    unresolved: list[str] = []
    for candidate_id in sorted(decisions):
        decision = decisions[candidate_id]
        try:
            projection = project_report_severity(decision)
        except Exception:
            projection = project_retention_severity(decision)
        projection = constrain_trust_sensitive_report_projection(
            scratchpad,
            decision=decision,
            projection=projection,
            run_id=run_id,
        )
        authorized = projection["severity"]
        severity_status = projection["severity_status"]
        if severity_status != "RESOLVED":
            unresolved.append(candidate_id)
        candidate_rows = by_candidate.get(candidate_id.upper(), [])
        legacy = candidate_rows[0] if len(candidate_rows) == 1 else None
        legacy_severity = _canonical_severity(
            (legacy or {}).get("severity")
        )
        report_id = str((legacy or {}).get("report_id") or "").upper()
        rows.append(
            {
                "candidate_id": candidate_id,
                "decision_digest": decision["decision_digest"],
                "authorized_severity": authorized,
                "severity_status": severity_status,
                "legacy_report_id": report_id or None,
                "legacy_report_index_severity": legacy_severity,
            }
        )
        if len(candidate_rows) > 1:
            events.append(
                {
                    "candidate_id": candidate_id,
                    "surface": "REPORT_INDEX",
                    "drift_kind": "AMBIGUOUS_LEGACY_MAPPING",
                    "observed_severity": None,
                    "authorized_severity": authorized,
                }
            )
            duplicated_severities = {
                _canonical_severity(row.get("severity"))
                for row in candidate_rows
            }
            if (
                len(duplicated_severities) == 1
                and None not in duplicated_severities
                and next(iter(duplicated_severities)) != authorized
            ):
                events.append(
                    {
                        "candidate_id": candidate_id,
                        "surface": "REPORT_INDEX",
                        "drift_kind": "UNAUTHORIZED_TIER_MUTATION",
                        "observed_severity": next(iter(duplicated_severities)),
                        "authorized_severity": authorized,
                    }
                )
        elif legacy is None:
            events.append(
                {
                    "candidate_id": candidate_id,
                    "surface": "REPORT_INDEX",
                    "drift_kind": "MISSING_LEGACY_PROJECTION",
                    "observed_severity": None,
                    "authorized_severity": authorized,
                }
            )
        else:
            prefix_severity = _canonical_severity(
                report_id.split("-", 1)[0] if report_id else ""
            )
            if prefix_severity != legacy_severity:
                events.append(
                    {
                        "candidate_id": candidate_id,
                        "surface": "REPORT_INDEX",
                        "drift_kind": "AMBIGUOUS_LEGACY_MAPPING",
                        "observed_severity": legacy_severity,
                        "authorized_severity": authorized,
                    }
                )
        if legacy is not None and legacy_severity != authorized:
            events.append(
                {
                    "candidate_id": candidate_id,
                    "surface": "REPORT_INDEX",
                    "drift_kind": "UNAUTHORIZED_TIER_MUTATION",
                    "observed_severity": legacy_severity,
                    "authorized_severity": authorized,
                }
            )
        if report_id and len(by_report_id.get(report_id, [])) > 1:
            if not any(
                event["surface"] == "REPORT_INDEX"
                and event["drift_kind"] == "AMBIGUOUS_LEGACY_MAPPING"
                and event["candidate_id"] == candidate_id
                for event in events
            ):
                events.append(
                    {
                        "candidate_id": candidate_id,
                        "surface": "REPORT_INDEX",
                        "drift_kind": "AMBIGUOUS_LEGACY_MAPPING",
                        "observed_severity": legacy_severity,
                        "authorized_severity": authorized,
                    }
                )
        body_rows = body_severities.get(report_id, [])
        if len(body_rows) > 1:
            events.append(
                {
                    "candidate_id": candidate_id,
                    "surface": body_surface,
                    "drift_kind": "AMBIGUOUS_LEGACY_MAPPING",
                    "observed_severity": None,
                    "authorized_severity": authorized,
                }
            )
            duplicated_body_severities = {
                row.get("severity") for row in body_rows
            }
            if (
                len(duplicated_body_severities) == 1
                and None not in duplicated_body_severities
                and next(iter(duplicated_body_severities)) != authorized
            ):
                events.append(
                    {
                        "candidate_id": candidate_id,
                        "surface": body_surface,
                        "drift_kind": "UNAUTHORIZED_TIER_MUTATION",
                        "observed_severity": next(
                            iter(duplicated_body_severities)
                        ),
                        "authorized_severity": authorized,
                    }
                )
        elif len(body_rows) == 1:
            body_severity = body_rows[0].get("severity")
            if body_severity is None:
                events.append(
                    {
                        "candidate_id": candidate_id,
                        "surface": body_surface,
                        "drift_kind": "MISSING_SEVERITY",
                        "observed_severity": None,
                        "authorized_severity": authorized,
                    }
                )
            elif body_severity != authorized:
                events.append(
                    {
                        "candidate_id": candidate_id,
                        "surface": body_surface,
                        "drift_kind": "UNAUTHORIZED_TIER_MUTATION",
                        "observed_severity": body_severity,
                        "authorized_severity": authorized,
                    }
                )
    unsigned = {
        "schema_version": SHADOW_REPORT_RECEIPT_SCHEMA,
        "run_id": run_id,
        "authority_status": "SHADOW_ONLY",
        "projection_stage": stage,
        "severity_ledger_digest": ledger["ledger_digest"],
        "report_index_sha256": hashlib.sha256(index_bytes).hexdigest(),
        "report_body_sha256": body_digests,
        "legacy_artifact_sha256": {
            "report_index.md": hashlib.sha256(index_bytes).hexdigest(),
            **body_digests,
        },
        "row_count": len(rows),
        "rows": rows,
        "drift_event_count": len(events),
        "drift_events": events,
        "unresolved_candidate_ids": unresolved,
        "pre_projection_receipt_sha256": pre_receipt_sha256,
        "final_report_sha256": final_report_sha256,
    }
    payload = {**unsigned, "receipt_digest": _digest(unsigned)}
    if persist:
        _atomic_json(scratchpad / output_name, payload)
    return payload


__all__ = [
    "SHADOW_ADJUDICATION_MANIFEST_NAME",
    "SHADOW_ADJUDICATION_MANIFEST_SCHEMA",
    "SHADOW_LEDGER_NAME",
    "FINAL_SHADOW_REPORT_RECEIPT_NAME",
    "SHADOW_REPORT_RECEIPT_NAME",
    "SHADOW_REPORT_RECEIPT_SCHEMA",
    "bind_shadow_adjudication_for_candidate",
    "bind_shadow_severity_for_shard",
    "build_shadow_adjudication_manifest",
    "ensure_shadow_severity_for_shard",
    "recover_receipt_pending_decision_commit",
    "validate_shadow_severity_for_shard",
    "write_shadow_report_severity_receipt",
]
