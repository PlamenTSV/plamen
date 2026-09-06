"""Deterministic methodology dispatch/application reconciliation.

The producer's trace is an *attestation*, never semantic proof and never a
finding verdict.  This module binds scheduled methodology bytes, prompt bytes,
worker identity, and output identity, then enumerates missing attestations as
durable obligations.  It can add repair work or human-review debt; it cannot
assert, refute, promote, demote, or delete a finding.

Limits are intentional: a mechanically valid trace proves that a producer
emitted specific, source-resolvable evidence for every scheduled step.  It
does not prove that the reasoning was correct or complete.  Independent
discovery, verification, and benchmark scoring remain responsible for that.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import methodology_application_states as application_states
from methodology_citation import MethodologyCitationResolver


DISPATCH_FILE = "skill_dispatch.json"
TRACE_HEADING = "## Step Execution Trace"
TRACE_JSON_BEGIN = "<!-- PLAMEN_STEP_TRACE_JSON_BEGIN -->"
TRACE_JSON_END = "<!-- PLAMEN_STEP_TRACE_JSON_END -->"
TRACE_COLUMNS = ("skill", "step", "executed", "evidence", "result")
ASSURANCE = "PRODUCER_ATTESTATION_ONLY"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_RE = re.compile(r"(?i)(?:^|\b)(?:explicitly\s+)?safe\s*[:\-\u2013\u2014]")
_GENERIC_RESULT_RE = re.compile(
    r"(?i)^\s*(?:executed|checked|applied|reviewed|done|complete|completed|"
    r"safe|no\s+(?:issue|issues|finding|findings)|not\s+applicable|n/?a|"
    r"method(?:ology)?\s+(?:executed|applied|checked))\s*[.!]?\s*$"
)
_SAFE_OR_NO_FINDING_RE = re.compile(
    r"(?i)(?:\bsafe\b|\bno\s+(?:issue|issues|finding|findings|risk|impact)\b|"
    r"\bnot\s+applicable\b|\bn/?a\b)"
)
_OUTPUT_META_FIELDS = {
    "phase": "PLAMEN_DISPATCH_PHASE",
    "worker": "PLAMEN_DISPATCH_WORKER",
    "output": "PLAMEN_DISPATCH_OUTPUT",
    "contract": "PLAMEN_DISPATCH_CONTRACT_SHA256",
}


def _canonical(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def _canonical_step(value: Any) -> str:
    text = str(value or "").strip().casefold()
    text = re.sub(r"^(?:step|section|check)\s*", "", text)
    match = re.match(
        r"([0-9]+[a-z]?(?:\.[0-9]+[a-z]?)?|whole_method)", text
    )
    if not match:
        return re.sub(r"\s+", "", text)
    token = match.group(1).casefold()
    if token == "whole_method":
        return "whole_method/unenumerated"
    # Keep typed hierarchy separators: Step 1.1 and Step 11 are distinct.
    return token


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_digest(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _atomic_json_if_changed(path: Path, payload: dict[str, Any]) -> None:
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        if path.read_text(encoding="utf-8") == content:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _phase_digest_input(phase_payload: dict[str, Any]) -> dict[str, Any]:
    """Return the exact phase fields protected by ``dispatch_sha256``."""
    return {
        "backend": phase_payload.get("backend"),
        "entries": phase_payload.get("entries"),
    }


def phase_dispatch_sha256(phase_payload: dict[str, Any]) -> str:
    """Recompute a phase dispatch digest without trusting its stored value."""
    return _json_digest(_phase_digest_input(phase_payload))


def _contract_methodologies(entry: dict[str, Any]) -> list[Any]:
    methodologies = entry.get("methodologies")
    if methodologies is None:
        methodologies = entry.get("skill_dispatch")
    return methodologies if isinstance(methodologies, list) else []


def worker_dispatch_contract_sha256(phase: str, entry: dict[str, Any]) -> str:
    """Bind one worker/output to exact methodology descriptors.

    ``prompt_sha256`` is deliberately outside this digest because the digest is
    embedded in the prompt, while the full rendered prompt SHA is stored in the
    phase dispatch and checked against the launcher's on-disk prompt snapshot.
    This avoids a self-referential hash while still binding both layers.
    """
    contract = {
        "schema_version": 1,
        "phase": str(phase),
        "worker_id": str(entry.get("worker_id") or entry.get("agent_id") or ""),
        "output": str(entry.get("output") or ""),
        "methodologies": _contract_methodologies(entry),
    }
    return _json_digest(contract)


def worker_dispatch_markers(
    phase: str, worker_id: str, output: str, contract_sha256: str
) -> str:
    """Canonical output metadata that a producer must echo verbatim."""
    return "\n".join(
        (
            f"<!-- PLAMEN_DISPATCH_PHASE: {phase} -->",
            f"<!-- PLAMEN_DISPATCH_WORKER: {worker_id} -->",
            f"<!-- PLAMEN_DISPATCH_OUTPUT: {output} -->",
            f"<!-- PLAMEN_DISPATCH_CONTRACT_SHA256: {contract_sha256} -->",
        )
    )


def write_phase_dispatch(
    scratchpad: Path,
    *,
    phase: str,
    backend: str,
    entries: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Atomically replace one phase's dispatch without disturbing other phases."""
    path = Path(scratchpad) / DISPATCH_FILE
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            payload = {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        payload = {}
    phases = payload.setdefault("phases", {})
    if not isinstance(phases, dict):
        phases = {}
        payload["phases"] = phases
    normalized_entries = list(entries)
    phase_payload = {
        "backend": str(backend),
        "entries": normalized_entries,
    }
    phase_payload["dispatch_sha256"] = phase_dispatch_sha256(phase_payload)
    phases[str(phase)] = phase_payload
    payload.update(
        {
            "schema_version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    _atomic_json(path, payload)
    return phase_payload


def _trace_rows(text: str) -> list[dict[str, str]]:
    """Parse the authoritative embedded JSON trace.

    Markdown tables are intentionally ignored. Pipes, newlines, and escaping in
    evidence/result fields cannot change row boundaries in this representation.
    """
    if text.count(TRACE_JSON_BEGIN) != 1 or text.count(TRACE_JSON_END) != 1:
        return []
    before, remainder = text.split(TRACE_JSON_BEGIN, 1)
    payload_text, _after = remainder.split(TRACE_JSON_END, 1)
    if before.count(TRACE_HEADING) != 1:
        return []
    try:
        payload = json.loads(payload_text.strip())
    except (json.JSONDecodeError, TypeError):
        return []
    if (
        not isinstance(payload, dict)
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
    ):
        return []
    raw_rows = payload.get("rows")
    if not isinstance(raw_rows, list):
        return []
    rows: list[dict[str, str]] = []
    for raw in raw_rows:
        if not isinstance(raw, dict) or set(raw) != set(TRACE_COLUMNS):
            return []
        if not all(isinstance(raw[key], str) for key in TRACE_COLUMNS):
            return []
        rows.append({key: raw[key] for key in TRACE_COLUMNS})
    return rows


def _output_dispatch_metadata(text: str) -> tuple[dict[str, str], str | None]:
    observed: dict[str, str] = {}
    for field, marker in _OUTPUT_META_FIELDS.items():
        matches = re.findall(
            rf"<!--\s*{re.escape(marker)}\s*:\s*([^>]*?)\s*-->", text
        )
        if len(matches) != 1:
            return {}, f"output dispatch metadata has {len(matches)} {marker} markers"
        observed[field] = matches[0].strip()
    return observed, None


def _output_metadata_issue(
    text: str, *, phase: str, entry: dict[str, Any]
) -> str | None:
    observed, issue = _output_dispatch_metadata(text)
    if issue:
        return issue
    expected = {
        "phase": str(phase),
        "worker": str(entry.get("worker_id") or entry.get("agent_id") or ""),
        "output": str(entry.get("output") or ""),
        "contract": str(entry.get("dispatch_contract_sha256") or ""),
    }
    if observed != expected:
        return "output dispatch metadata does not match exact dispatched worker contract"
    return None


def _evidence_resolves(evidence: str, project_root: Path) -> bool:
    """Compatibility wrapper for application-evidence citation authority."""

    return MethodologyCitationResolver(Path(project_root)).has_resolvable_citation(
        evidence
    )


def _methodology_steps(descriptor: dict[str, Any]) -> list[str]:
    values = descriptor.get("top_level_checklist_step_ids") or []
    steps = [str(value).strip() for value in values if str(value).strip()]
    return steps or ["WHOLE_METHOD/UNENUMERATED"]


def _gap_row(
    phase: str,
    reason: str,
    *,
    entry: dict[str, Any] | None = None,
    skill: str = "[DISPATCH]",
    step: str = "[INTEGRITY]",
) -> dict[str, Any]:
    entry = entry or {}
    return {
        "phase": phase,
        "worker_id": str(entry.get("worker_id") or entry.get("agent_id") or ""),
        "output": str(entry.get("output") or ""),
        "output_sha256": "",
        "skill": skill,
        "methodology_path": "",
        "methodology_sha256": "",
        "step": step,
        "disposition": "GAP",
        "executed": "",
        "evidence": "",
        "result": "",
        "reason": reason,
    }


def _entry_schema_issues(phase: str, entry: Any) -> list[str]:
    if not isinstance(entry, dict):
        return ["dispatch entry is not an object"]
    issues: list[str] = []
    worker = str(entry.get("worker_id") or entry.get("agent_id") or "").strip()
    output = str(entry.get("output") or "").strip()
    prompt_sha = str(entry.get("prompt_sha256") or "").casefold()
    contract_sha = str(entry.get("dispatch_contract_sha256") or "").casefold()
    if not worker:
        issues.append("dispatch entry has no worker identity")
    if (
        not output
        or Path(output).is_absolute()
        or Path(output).name != output
        or "/" in output
        or "\\" in output
        or output in {".", ".."}
    ):
        issues.append("dispatch entry output is empty or not a scratchpad basename")
    if not _SHA256_RE.fullmatch(prompt_sha):
        issues.append("dispatch entry has malformed prompt_sha256")
    if not _SHA256_RE.fullmatch(contract_sha):
        issues.append("dispatch entry has malformed dispatch contract SHA-256")
    elif contract_sha != worker_dispatch_contract_sha256(phase, entry):
        issues.append("dispatch entry contract SHA-256 mismatch")
    methodologies = entry.get("methodologies")
    if methodologies is None:
        methodologies = entry.get("skill_dispatch")
    if not isinstance(methodologies, list):
        issues.append("dispatch methodologies is not a list")
    else:
        for index, descriptor in enumerate(methodologies):
            if not isinstance(descriptor, dict):
                issues.append(f"methodology descriptor {index} is not an object")
                continue
            if not str(descriptor.get("skill") or descriptor.get("methodology") or ""):
                issues.append(f"methodology descriptor {index} has no skill identity")
            if not str(descriptor.get("path") or ""):
                issues.append(f"methodology descriptor {index} has no path")
            if not _SHA256_RE.fullmatch(str(descriptor.get("sha256") or "").casefold()):
                issues.append(f"methodology descriptor {index} has malformed SHA-256")
    return issues


def _prompt_snapshot_matches(scratchpad: Path, entry: dict[str, Any]) -> bool:
    if not entry.get("prompt_snapshot_required"):
        return True
    expected = str(entry.get("prompt_sha256") or "").casefold()
    pattern = str(entry.get("prompt_snapshot_glob") or "_prompt_*.md")
    try:
        candidates = list(Path(scratchpad).glob(pattern))
    except (OSError, ValueError):
        return False
    for path in candidates:
        try:
            if path.is_file() and _sha256_bytes(path.read_bytes()) == expected:
                return True
        except OSError:
            continue
    return False


def _unmeasurable(
    scratchpad: Path, phase: str, reason: str, rows: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    typed_rows = []
    for row in rows or [_gap_row(phase, reason)]:
        typed_rows.append(
            application_states.classify_application_row(
                {
                    **row,
                    "delivery_integrity": "UNKNOWN",
                    "trace_state": "UNKNOWN",
                    "evidence_basis": "NONE",
                }
            )
        )
    result = application_states.build_application_receipt(
        typed_rows,
        phase=phase,
        status="UNMEASURABLE",
        reason=reason,
        assurance=ASSURANCE,
    )
    _write_application_outputs(scratchpad, phase, result)
    return result


def validate_phase_application(
    scratchpad: Path,
    project_root: Path,
    *,
    phase: str,
    trusted_methodology_roots: Iterable[Path] | None = None,
) -> dict[str, Any]:
    """Reconcile exact dispatch bytes against producer attestations.

    ``ATTESTED`` means only that every scheduled step has one digest-current,
    contract-bound row with resolvable source evidence.  It is not a finding
    verdict and not proof that the methodology was correctly applied.
    """
    scratchpad = Path(scratchpad)
    dispatch_path = scratchpad / DISPATCH_FILE
    try:
        dispatch = json.loads(dispatch_path.read_text(encoding="utf-8"))
        phases = dispatch["phases"]
        phase_dispatch = phases[phase]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError):
        return _unmeasurable(
            scratchpad, phase, "missing or invalid skill_dispatch.json phase entry"
        )
    if not isinstance(phase_dispatch, dict):
        return _unmeasurable(scratchpad, phase, "phase dispatch is not an object")
    stored_digest = str(phase_dispatch.get("dispatch_sha256") or "").casefold()
    recomputed_digest = phase_dispatch_sha256(phase_dispatch)
    if not _SHA256_RE.fullmatch(stored_digest) or stored_digest != recomputed_digest:
        return _unmeasurable(
            scratchpad,
            phase,
            "dispatch SHA-256 mismatch; phase entries may be stale or tampered",
        )
    entries = phase_dispatch.get("entries")
    if not isinstance(entries, list) or not entries:
        return _unmeasurable(
            scratchpad,
            phase,
            "phase dispatch contains no worker entries; application cannot be measured",
        )

    schema_rows: list[dict[str, Any]] = []
    valid_entries: list[dict[str, Any]] = []
    for entry in entries:
        issues = _entry_schema_issues(phase, entry)
        if issues:
            schema_rows.append(
                _gap_row(
                    phase,
                    "; ".join(issues),
                    entry=entry if isinstance(entry, dict) else None,
                )
            )
        elif isinstance(entry, dict):
            valid_entries.append(entry)
    if schema_rows:
        return _unmeasurable(
            scratchpad,
            phase,
            "one or more dispatch entries are malformed",
            schema_rows,
        )

    roots = [Path(root).resolve() for root in (trusted_methodology_roots or [])]
    citation_resolver = MethodologyCitationResolver(
        Path(project_root), scratchpad=scratchpad
    )
    reconciled: list[dict[str, Any]] = []
    total_methodologies = 0
    for entry in valid_entries:
        methodologies = _contract_methodologies(entry)
        total_methodologies += len(methodologies)
        output_name = str(entry.get("output") or "").strip()
        output_path = scratchpad / output_name
        try:
            output_bytes = output_path.read_bytes()
            output_text = output_bytes.decode("utf-8", errors="replace")
            trace_rows = _trace_rows(output_text)
            output_sha = _sha256_bytes(output_bytes)
        except OSError:
            output_text = ""
            trace_rows = []
            output_sha = ""
        metadata_issue = _output_metadata_issue(output_text, phase=phase, entry=entry)
        prompt_issue = None
        if not _prompt_snapshot_matches(scratchpad, entry):
            prompt_issue = "no launch prompt snapshot matches dispatched prompt_sha256"
        indexed: dict[tuple[str, str], list[dict[str, str]]] = {}
        for row in trace_rows:
            indexed.setdefault(
                (_canonical(row.get("skill")), _canonical_step(row.get("step"))), []
            ).append(row)

        generic_signatures = Counter(
            (
                re.sub(r"\s+", " ", str(row.get("evidence") or "").strip()).casefold(),
                re.sub(r"\s+", " ", str(row.get("result") or "").strip()).casefold(),
            )
            for row in trace_rows
            if _GENERIC_RESULT_RE.fullmatch(str(row.get("result") or ""))
        )

        for methodology in methodologies:
            skill = str(
                methodology.get("skill") or methodology.get("methodology") or ""
            )
            path = Path(str(methodology.get("path") or ""))
            expected_sha = str(methodology.get("sha256") or "").casefold()
            try:
                resolved_method = path.resolve()
                trusted = bool(roots) and any(
                    resolved_method == root or resolved_method.is_relative_to(root)
                    for root in roots
                )
                current_sha = _sha256_bytes(resolved_method.read_bytes()) if trusted else ""
            except (OSError, ValueError):
                trusted = False
                current_sha = ""
            method_current = bool(trusted and expected_sha and current_sha == expected_sha)
            for step in _methodology_steps(methodology):
                candidates = indexed.get((_canonical(skill), _canonical_step(step)), [])
                reason = "missing trace row"
                evidence = ""
                result_text = ""
                executed = ""
                safe_or_no_finding = False
                generic_result = False
                repeated_generic = False
                evidence_ok = False
                if metadata_issue:
                    reason = metadata_issue
                elif prompt_issue:
                    reason = prompt_issue
                elif not trusted:
                    reason = "methodology path is outside trusted active Plamen roots"
                elif not method_current:
                    reason = "methodology path missing or SHA-256 drifted after dispatch"
                elif len(candidates) != 1:
                    reason = (
                        "missing trace row"
                        if not candidates
                        else "duplicate/conflicting trace rows"
                    )
                else:
                    row = candidates[0]
                    executed = str(row.get("executed") or "").strip().casefold()
                    evidence = str(row.get("evidence") or "").strip()
                    result_text = str(row.get("result") or "").strip()
                    signature = (
                        re.sub(r"\s+", " ", evidence).casefold(),
                        re.sub(r"\s+", " ", result_text).casefold(),
                    )
                    evidence_ok = citation_resolver.has_resolvable_citation(evidence)
                    repeated_generic = (
                        _GENERIC_RESULT_RE.fullmatch(result_text) is not None
                        and generic_signatures[signature] > 1
                    )
                    safe_or_no_finding = (
                        executed in {"safe", "not_applicable", "n/a"}
                        or _SAFE_OR_NO_FINDING_RE.search(result_text) is not None
                    )
                    generic_result = _GENERIC_RESULT_RE.fullmatch(result_text) is not None
                    if safe_or_no_finding:
                        reason = (
                            "producer safe/no-finding attestation requires independent "
                            "skeptic review and cannot close its own obligation"
                        )
                    elif repeated_generic:
                        reason = (
                            "repeated generic producer attestation across multiple "
                            "steps is not evidence of step-specific application"
                        )
                    elif generic_result:
                        reason = (
                            "generic underspecified producer result requires independent "
                            "skeptic review"
                        )
                    elif executed == "yes" and evidence_ok:
                        reason = (
                            "producer attestation is contract/digest current with "
                            "resolvable source evidence; semantic correctness unproven"
                        )
                    elif not evidence_ok and executed in {
                        "yes",
                        "safe",
                        "not_applicable",
                        "n/a",
                    }:
                        reason = (
                            "affirmative/safe attestation lacks resolvable "
                            "source:Lline evidence"
                        )
                    else:
                        reason = f"step reported {executed or 'unknown'}"

                if metadata_issue or prompt_issue or not trusted or not method_current:
                    delivery_integrity = "INVALID"
                else:
                    delivery_integrity = "CURRENT"
                if not candidates:
                    trace_state = "MISSING"
                elif len(candidates) != 1:
                    trace_state = "INVALID"
                elif generic_result or repeated_generic:
                    trace_state = "INVALID"
                elif executed == "yes" and not evidence_ok and not safe_or_no_finding:
                    # A substantive positive without a bound evidence locus is
                    # not mechanically distinguishable from an assertion that
                    # the operator never actually performed.
                    trace_state = "INVALID"
                else:
                    trace_state = "VALID"
                evidence_basis = "IN_SCOPE_SOURCE" if evidence_ok else "NONE"
                source_rows = methodology.get("source_gap_obligations")
                if not isinstance(source_rows, list):
                    source_rows = []
                matching_sources = [
                    source
                    for source in source_rows
                    if isinstance(source, dict)
                    and _canonical_step(source.get("step")) == _canonical_step(step)
                ] or [{}]
                for source in matching_sources:
                    reconciled.append(
                        application_states.classify_application_row(
                            {
                                "phase": phase,
                                "worker_id": str(
                                    entry.get("worker_id")
                                    or entry.get("agent_id")
                                    or ""
                                ),
                                "producer_invocation_id": str(
                                    entry.get("producer_invocation_id")
                                    or entry.get("launch_id")
                                    or entry.get("prompt_sha256")
                                    or ""
                                ),
                                "output": output_name,
                                "output_sha256": output_sha,
                                "prompt_sha256": str(
                                    entry.get("prompt_sha256") or ""
                                ),
                                "dispatch_contract_sha256": str(
                                    entry.get("dispatch_contract_sha256") or ""
                                ),
                                "skill": skill,
                                "methodology_path": path.as_posix(),
                                "methodology_sha256": expected_sha,
                                "step": step,
                                "obligation_id": str(
                                    source.get("obligation_id") or ""
                                ),
                                "executed": executed,
                                "evidence": evidence,
                                "result": result_text,
                                "delivery_integrity": delivery_integrity,
                                "trace_state": trace_state,
                                "evidence_basis": evidence_basis,
                                "reason": reason,
                            }
                        )
                    )

    if total_methodologies == 0:
        result = application_states.build_application_receipt(
            [],
            phase=phase,
            dispatch_sha256=stored_digest,
            status="NOT_APPLICABLE",
            reason="dispatch has workers but no methodology obligations",
            assurance=ASSURANCE,
        )
        _write_application_outputs(scratchpad, phase, result)
        return result

    result = application_states.build_application_receipt(
        reconciled,
        phase=phase,
        dispatch_sha256=stored_digest,
        assurance=ASSURANCE,
    )
    _write_application_outputs(scratchpad, phase, result)
    return result


def _write_application_outputs(
    scratchpad: Path, phase: str, result: dict[str, Any]
) -> None:
    receipt = Path(scratchpad) / f"skill_application_receipt_{phase}.json"
    _atomic_json_if_changed(receipt, result)
    gaps = [
        row
        for row in result.get("rows", [])
        if row.get("application_completeness") in {"MISSING", "INVALID"}
    ]
    review_debt = [
        row
        for row in result.get("rows", [])
        if row.get("application_completeness") == "UNKNOWN"
    ]
    projected_rows = gaps + review_debt
    lines = [
        f"# Skill Execution Gaps - {phase}",
        "",
        f"**Status**: {result.get('status', 'UNMEASURABLE')}",
        f"**Assurance**: {ASSURANCE}",
        "",
        "Producer trace rows are attestations, never semantic proof or finding verdicts.",
        "MISSING/INVALID rows are deterministic repair obligations; UNKNOWN rows are human-review debt.",
        "",
        "| Worker | Output | Skill | Step | Methodology Path | SHA-256 | Reason |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in projected_rows:
        cells = [
            row.get("worker_id", ""),
            row.get("output", ""),
            row.get("skill", ""),
            row.get("step", ""),
            row.get("methodology_path", ""),
            row.get("methodology_sha256", ""),
            row.get("reason", ""),
        ]
        cells = [str(cell).replace("|", "/").replace("\n", " ") for cell in cells]
        lines.append("| " + " | ".join(cells) + " |")
    if not projected_rows:
        lines.append("| (none) | | | | | | no unresolved dispatched obligations |")
    lines.extend(["", "<!-- PLAMEN_STATUS: COMPLETE -->", ""])
    (Path(scratchpad) / f"skill_execution_gaps_{phase}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    application_states.write_application_queues(
        Path(scratchpad), result.get("rows", []), phase=phase
    )


def write_human_review_projection(
    scratchpad: Path,
    *,
    source_phase: str,
    source_result: dict[str, Any],
    repair_result: dict[str, Any] | None = None,
    repair_enabled: bool = False,
    repair_attempted: bool = False,
) -> Path | None:
    """Deliver unresolved application debt through the report appendix.

    A successful repair closes only the *attestation obligation*.  Any finding
    produced by the repair remains in its normal ``analysis_*.md`` path and is
    independently inventoried and verified.
    """
    safe_phase = re.sub(r"[^a-z0-9_]+", "_", source_phase.casefold()).strip("_")
    target = (
        Path(scratchpad)
        / f"report_semantic_methodology_application_{safe_phase or 'unknown'}.md"
    )
    final_result = repair_result if repair_result is not None else source_result
    gaps = [
        row
        for row in final_result.get("rows", [])
        if row.get("disposition") == "GAP"
    ]
    unresolved = final_result.get("status") in {"GAPS", "UNMEASURABLE"} or bool(gaps)
    if not unresolved:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    lines = [
        "# Methodology Application Review",
        "",
        "`METHODOLOGY-APPLICATION-DEBT` remains unresolved.",
        "Producer attestations are not proof that a methodology was correctly applied.",
        f"Source phase: `{source_phase}`; source status: `{source_result.get('status')}`.",
        f"Targeted repair enabled: `{str(repair_enabled).lower()}`; attempted: "
        f"`{str(repair_attempted).lower()}`.",
    ]
    if repair_result is not None:
        lines.append(f"Repair status: `{repair_result.get('status')}`.")
    lines.extend(
        [
            "",
            "These rows require human review; they do not assert or refute a finding:",
            "",
            "| Worker | Skill | Step | Reason |",
            "|---|---|---|---|",
        ]
    )
    for row in gaps or [_gap_row(source_phase, str(final_result.get("reason") or "unmeasurable"))]:
        cells = [
            row.get("worker_id", ""),
            row.get("skill", ""),
            row.get("step", ""),
            row.get("reason", ""),
        ]
        cells = [str(cell).replace("|", "/").replace("\n", " ") for cell in cells]
        lines.append("| " + " | ".join(cells) + " |")
    lines.extend(["", "<!-- PLAMEN_STATUS: COMPLETE -->", ""])
    target.write_text("\n".join(lines), encoding="utf-8")
    return target
