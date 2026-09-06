"""Typed applied authority for final-report identity consolidation.

Report-dedup Markdown and similarity signals are proposals.  This module is
the sole authority for removing a standalone report section: the two report
IDs must resolve to the exact same current source-identity set, the survivor
must remain live, the absorbed section must remain losslessly coupled, every
candidate must receive a disposition, and the immutable receipt must be bound
to the same inputs as the report mutation transaction.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = "plamen.report_dedup_applied_alias_receipt.v1"
RECEIPT_NAME = "report_dedup_applied_alias_receipt.json"
BROKER_PROJECTION_SCHEMA = "plamen.report_dedup_alias_decision_projection.v1"
REQUIRED_EXACT_INPUT_PATHS = (
    "report_dedup_agent_decisions.md",
    "report_dedup_candidate_pairs.md",
    "report_dedup_candidate_pairs.json",
    "report_index.md",
    "finding_mapping.md",
    "semantic_dedup_applied_receipt.json",
    "semantic_dedup_supplemental_applied_receipt.json",
    "findings_inventory.md",
    "verification_queue.md",
)

_REPORT_ID = r"[CHMLI]-\d{1,3}"
_HEADING_RE = re.compile(
    rf"(?im)^#{{2,3}}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*({_REPORT_ID})\s*\][^\n]*\n"
)


class ReportDedupAuthorityError(RuntimeError):
    """A report identity transformation lacks exact applied authority."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_core(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_core(value))


def canonical_receipt_bytes(payload: Mapping[str, Any]) -> bytes:
    return _canonical_core(payload)


def _norm_report_id(value: Any) -> str:
    match = re.fullmatch(_REPORT_ID, str(value or "").strip().upper())
    return match.group(0) if match else ""


def _norm_source_id(value: Any) -> str:
    token = str(value or "").strip().strip("[]").upper()
    return token if re.fullmatch(r"[A-Z][A-Z0-9_-]*-\d+", token) else ""


def standalone_report_ids(text: str) -> set[str]:
    return {match.group(1).upper() for match in _HEADING_RE.finditer(text or "")}


def _quality_observation_ids(text: str) -> set[str]:
    match = re.search(
        r"(?ims)^##\s+Quality\s+Observations[^\n]*\n(.*?)(?=^##\s+|\Z)",
        text or "",
    )
    if not match:
        return set()
    result: set[str] = set()
    for line in match.group(1).splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells:
            continue
        token = re.sub(r"[*`]", "", cells[0]).strip().strip("[]")
        report_id = _norm_report_id(token)
        if report_id:
            result.add(report_id)
    return result


def _validate_exact_input_denominator(
    exact_inputs: Sequence[Mapping[str, Any]],
) -> None:
    paths = [str(row.get("path") or "") for row in exact_inputs]
    if (
        len(paths) != len(set(paths))
        or sorted(paths) != sorted(REQUIRED_EXACT_INPUT_PATHS)
    ):
        raise ReportDedupAuthorityError(
            "receipt exact input denominator is incomplete or duplicated"
        )


def _section_map(text: str) -> dict[str, str]:
    matches = list(_HEADING_RE.finditer(text or ""))
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = len(text)
        next_h2 = re.search(r"(?m)^##\s+", text[match.end() :])
        if next_h2:
            end = min(end, match.end() + next_h2.start())
        if index + 1 < len(matches):
            end = min(end, matches[index + 1].start())
        result[match.group(1).upper()] = text[match.start() : end]
    return result


def _demoted_section(report_id: str, section: str) -> str:
    return re.sub(
        rf"(?im)^#{{2,3}}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*{re.escape(report_id)}\s*\]\s*",
        f"**Absorbed finding {report_id}:** ",
        section.strip(),
        count=1,
    )


def _resolve_source(value: str, aliases: Mapping[str, Mapping[str, str]]) -> str:
    current = _norm_source_id(value)
    seen: set[str] = set()
    while current in aliases:
        if current in seen:
            raise ReportDedupAuthorityError("semantic alias cycle")
        seen.add(current)
        nxt = _norm_source_id(aliases[current].get("survivor", ""))
        if not nxt:
            raise ReportDedupAuthorityError("semantic alias has no live survivor identity")
        current = nxt
    return current


def _resolved_source_ids(
    report_id: str,
    source_ids_by_report_id: Mapping[str, set[str]],
    aliases: Mapping[str, Mapping[str, str]],
) -> list[str]:
    return sorted(
        {
            _resolve_source(item, aliases)
            for item in source_ids_by_report_id.get(report_id, set())
            if _norm_source_id(item)
        }
    )


def source_identity_equivalent(
    survivor: str,
    absorbed: str,
    source_ids_by_report_id: Mapping[str, set[str]],
    *,
    semantic_aliases: Mapping[str, Mapping[str, str]] | None = None,
) -> tuple[bool, str]:
    """Authorize only exact current source identity, never textual similarity."""
    survivor = _norm_report_id(survivor)
    absorbed = _norm_report_id(absorbed)
    if not survivor or not absorbed or survivor == absorbed:
        return False, "INVALID_REPORT_IDENTITY"
    aliases = semantic_aliases or {}
    try:
        left = set(_resolved_source_ids(survivor, source_ids_by_report_id, aliases))
        right = set(_resolved_source_ids(absorbed, source_ids_by_report_id, aliases))
    except ReportDedupAuthorityError:
        return False, "SEMANTIC_ALIAS_AUTHORITY_INVALID"
    if not left or not right:
        return False, "SOURCE_IDENTITY_UNAVAILABLE"
    if left != right:
        return False, "SOURCE_IDENTITY_NOT_EQUIVALENT"
    return True, "EXACT_CURRENT_SOURCE_IDENTITY"


def _candidate_rows(candidates: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in candidates:
        keep = _norm_report_id(item.get("keep"))
        absorb = _norm_report_id(item.get("absorb"))
        if not keep or not absorb or keep == absorb:
            raise ReportDedupAuthorityError("candidate has invalid exact identities")
        pair_key = "~".join(sorted((keep, absorb)))
        if pair_key in seen:
            raise ReportDedupAuthorityError("candidate denominator contains a duplicate pair")
        seen.add(pair_key)
        rows.append(
            {
                "pair_key": pair_key,
                "survivor": keep,
                "absorbed": absorb,
                "signals": sorted({str(v) for v in item.get("signals", [])}),
            }
        )
    return sorted(rows, key=lambda row: row["pair_key"])


def build_receipt(
    *,
    pre_report: str,
    post_report: str,
    exact_inputs: Sequence[Mapping[str, Any]],
    candidates: Sequence[Mapping[str, Any]],
    decisions: Sequence[Mapping[str, Any]],
    source_ids_by_report_id: Mapping[str, set[str]],
    retained_projection_ids: set[str],
    semantic_aliases: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Build and validate the exact receipt staged by the report transaction."""
    candidate_rows = _candidate_rows(candidates)
    by_key = {row["pair_key"]: row for row in candidate_rows}
    disposition: dict[str, Mapping[str, Any]] = {}
    for item in decisions:
        keep = _norm_report_id(item.get("keep"))
        absorb = _norm_report_id(item.get("absorb"))
        if not keep or not absorb:
            raise ReportDedupAuthorityError("decision has invalid exact identities")
        key = "~".join(sorted((keep, absorb)))
        if key not in by_key or key in disposition:
            raise ReportDedupAuthorityError("decision denominator does not match candidates")
        disposition[key] = item
    candidate_loss = sorted(set(by_key) - set(disposition))
    if candidate_loss:
        raise ReportDedupAuthorityError("candidate loss in report dedup disposition")

    pre_ids = standalone_report_ids(pre_report)
    post_ids = standalone_report_ids(post_report)
    retained = {
        rid for rid in (_norm_report_id(item) for item in retained_projection_ids) if rid
    }
    if not retained <= pre_ids or retained & post_ids:
        raise ReportDedupAuthorityError(
            "retained projection identity is stale or still standalone"
        )
    if not retained <= _quality_observation_ids(post_report):
        raise ReportDedupAuthorityError(
            "retained projection identity lacks a Quality Observation row"
        )
    decisions_out: list[dict[str, Any]] = []
    applied: dict[str, str] = {}
    for row in candidate_rows:
        item = disposition[row["pair_key"]]
        requested_merge = str(item.get("decision", "")).upper() == "MERGE"
        keep = _norm_report_id(item.get("keep"))
        absorb = _norm_report_id(item.get("absorb"))
        equivalent, authority_reason = source_identity_equivalent(
            keep,
            absorb,
            source_ids_by_report_id,
            semantic_aliases=semantic_aliases,
        )
        try:
            survivor_sources = _resolved_source_ids(
                keep, source_ids_by_report_id, semantic_aliases or {}
            )
            absorbed_sources = _resolved_source_ids(
                absorb, source_ids_by_report_id, semantic_aliases or {}
            )
        except ReportDedupAuthorityError:
            survivor_sources = []
            absorbed_sources = []
        actually_removed = absorb in pre_ids and absorb not in post_ids and absorb not in retained
        status = "APPLIED" if requested_merge and equivalent and actually_removed else "REJECTED"
        if status == "APPLIED":
            if absorb in applied:
                raise ReportDedupAuthorityError("absorbed identity has multiple survivors")
            applied[absorb] = keep
            reason = authority_reason
        elif requested_merge and not equivalent:
            reason = authority_reason
        elif requested_merge and not actually_removed:
            reason = "PROPOSED_MERGE_NOT_APPLIED"
        else:
            reason = str(item.get("reason") or "KEEP_SEPARATE")
        decisions_out.append(
            {
                "pair_key": row["pair_key"],
                "survivor": keep,
                "absorbed": absorb,
                "status": status,
                "reason": reason,
                "signals": row["signals"],
                "survivor_source_ids": survivor_sources,
                "absorbed_source_ids": absorbed_sources,
            }
        )

    # A directed report alias graph must be acyclic even before checking liveness.
    cycles: list[str] = []
    for start in sorted(applied):
        seen = {start}
        current = applied[start]
        while current in applied:
            if current in seen:
                cycles.append(start)
                break
            seen.add(current)
            current = applied[current]
    if cycles:
        raise ReportDedupAuthorityError("report alias cycle")
    dead = sorted({survivor for survivor in applied.values() if survivor not in post_ids})
    if dead:
        raise ReportDedupAuthorityError("applied alias has no live survivor")

    removed = pre_ids - post_ids - retained
    if removed != set(applied):
        raise ReportDedupAuthorityError(
            "applied aliases do not equal standalone report identity delta"
        )
    pre_sections = _section_map(pre_report)
    post_sections = _section_map(post_report)
    for absorbed in sorted(applied):
        section = pre_sections.get(absorbed, "")
        survivor_section = post_sections.get(applied[absorbed], "")
        if (
            not section
            or not survivor_section
            or _demoted_section(absorbed, section).strip() not in survivor_section
        ):
            raise ReportDedupAuthorityError(
                "absorbed report section lacks exact lossless coupling"
            )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "pre_report": {
            "sha256": _sha(pre_report.encode("utf-8")),
            "size_bytes": len(pre_report.encode("utf-8")),
            "standalone_ids": sorted(pre_ids),
        },
        "post_report": {
            "sha256": _sha(post_report.encode("utf-8")),
            "size_bytes": len(post_report.encode("utf-8")),
            "standalone_ids": sorted(post_ids),
            "retained_projection_ids": sorted(retained),
            "quality_observation_ids": sorted(_quality_observation_ids(post_report)),
        },
        "exact_inputs": [dict(row) for row in exact_inputs],
        "candidate_count": len(candidate_rows),
        "candidates": candidate_rows,
        "decisions": decisions_out,
        "applied_aliases": [
            {"absorbed": absorbed, "survivor": applied[absorbed]}
            for absorbed in sorted(applied)
        ],
        "postconditions": {
            "all_candidates_disposed": len(decisions_out) == len(candidate_rows),
            "all_survivors_live": not dead,
            "applied_equals_standalone_identity_delta": set(applied) == removed,
            "candidate_loss": candidate_loss,
            "cycles": cycles,
        },
    }
    unsigned = dict(payload)
    payload["receipt_sha256"] = _digest(unsigned)
    validate_receipt(
        payload,
        pre_report=pre_report,
        post_report=post_report,
        exact_inputs=exact_inputs,
        source_ids_by_report_id=source_ids_by_report_id,
        semantic_aliases=semantic_aliases or {},
    )
    return payload


def validate_receipt(
    payload: Mapping[str, Any],
    *,
    pre_report: str,
    post_report: str,
    exact_inputs: Sequence[Mapping[str, Any]],
    source_ids_by_report_id: Mapping[str, set[str]] | None = None,
    semantic_aliases: Mapping[str, Mapping[str, str]] | None = None,
) -> None:
    _validate_exact_input_denominator(exact_inputs)
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ReportDedupAuthorityError("receipt schema mismatch")
    unsigned = dict(payload)
    claimed = str(unsigned.pop("receipt_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", claimed) or claimed != _digest(unsigned):
        raise ReportDedupAuthorityError("receipt digest mismatch")
    if payload.get("exact_inputs") != [dict(row) for row in exact_inputs]:
        raise ReportDedupAuthorityError("receipt exact input binding mismatch")
    pre_raw = pre_report.encode("utf-8")
    post_raw = post_report.encode("utf-8")
    if payload.get("pre_report") != {
        "sha256": _sha(pre_raw),
        "size_bytes": len(pre_raw),
        "standalone_ids": sorted(standalone_report_ids(pre_report)),
    }:
        raise ReportDedupAuthorityError("receipt pre-report binding mismatch")
    post_meta = payload.get("post_report", {})
    if (
        post_meta.get("sha256") != _sha(post_raw)
        or post_meta.get("size_bytes") != len(post_raw)
        or post_meta.get("standalone_ids") != sorted(standalone_report_ids(post_report))
        or post_meta.get("quality_observation_ids")
        != sorted(_quality_observation_ids(post_report))
    ):
        raise ReportDedupAuthorityError("receipt post-report binding mismatch")
    candidates = payload.get("candidates", [])
    decisions = payload.get("decisions", [])
    if payload.get("candidate_count") != len(candidates) or len(decisions) != len(candidates):
        raise ReportDedupAuthorityError("receipt candidate loss")
    candidate_keys: list[str] = []
    candidate_identities: dict[str, frozenset[str]] = {}
    for row in candidates:
        survivor = _norm_report_id(row.get("survivor"))
        absorbed = _norm_report_id(row.get("absorbed"))
        pair_key = str(row.get("pair_key", ""))
        expected_key = "~".join(sorted((survivor, absorbed)))
        if (
            not survivor
            or not absorbed
            or survivor == absorbed
            or pair_key != expected_key
        ):
            raise ReportDedupAuthorityError(
                "receipt candidate identity is not coupled to its pair key"
            )
        candidate_keys.append(pair_key)
        candidate_identities[pair_key] = frozenset((survivor, absorbed))
    decision_keys: list[str] = []
    for row in decisions:
        survivor = _norm_report_id(row.get("survivor"))
        absorbed = _norm_report_id(row.get("absorbed"))
        pair_key = str(row.get("pair_key", ""))
        expected_key = "~".join(sorted((survivor, absorbed)))
        if (
            not survivor
            or not absorbed
            or survivor == absorbed
            or pair_key != expected_key
            or candidate_identities.get(pair_key)
            != frozenset((survivor, absorbed))
        ):
            raise ReportDedupAuthorityError(
                "receipt decision identity is not coupled to its candidate"
            )
        decision_keys.append(pair_key)
    if len(set(candidate_keys)) != len(candidate_keys) or sorted(candidate_keys) != sorted(decision_keys):
        raise ReportDedupAuthorityError("receipt candidate disposition mismatch")
    applied: dict[str, str] = {}
    for row in payload.get("applied_aliases", []):
        absorbed = _norm_report_id(row.get("absorbed"))
        survivor = _norm_report_id(row.get("survivor"))
        if not absorbed or not survivor or absorbed == survivor or absorbed in applied:
            raise ReportDedupAuthorityError(
                "receipt applied alias identity is invalid or duplicated"
            )
        applied[absorbed] = survivor
    post_ids = standalone_report_ids(post_report)
    retained = {
        _norm_report_id(item)
        for item in payload.get("post_report", {}).get(
            "retained_projection_ids", []
        )
        if _norm_report_id(item)
    }
    pre_ids = standalone_report_ids(pre_report)
    if not retained <= pre_ids or retained & post_ids:
        raise ReportDedupAuthorityError(
            "receipt retained projection identity is stale or still standalone"
        )
    if not retained <= _quality_observation_ids(post_report):
        raise ReportDedupAuthorityError(
            "receipt retained projection lacks a Quality Observation row"
        )
    removed = pre_ids - post_ids - retained
    if set(applied) != removed:
        raise ReportDedupAuthorityError(
            "receipt applied aliases do not equal report identity delta"
        )
    applied_from_decisions: dict[str, str] = {}
    for row in decisions:
        status = str(row.get("status", ""))
        absorbed = _norm_report_id(row.get("absorbed"))
        survivor = _norm_report_id(row.get("survivor"))
        if status not in {"APPLIED", "REJECTED"}:
            raise ReportDedupAuthorityError("receipt decision status is invalid")
        if status == "APPLIED":
            if (
                not row.get("survivor_source_ids")
                or row.get("survivor_source_ids") != row.get("absorbed_source_ids")
            ):
                raise ReportDedupAuthorityError(
                    "receipt applied decision lacks exact source equivalence"
                )
            if source_ids_by_report_id is None:
                raise ReportDedupAuthorityError(
                    "receipt applied decision lacks live source-authority replay"
                )
            equivalent, _reason = source_identity_equivalent(
                survivor,
                absorbed,
                source_ids_by_report_id,
                semantic_aliases=semantic_aliases or {},
            )
            try:
                expected_survivor_sources = _resolved_source_ids(
                    survivor, source_ids_by_report_id, semantic_aliases or {}
                )
                expected_absorbed_sources = _resolved_source_ids(
                    absorbed, source_ids_by_report_id, semantic_aliases or {}
                )
            except ReportDedupAuthorityError as exc:
                raise ReportDedupAuthorityError(
                    "receipt semantic source-authority replay failed"
                ) from exc
            if (
                not equivalent
                or row.get("survivor_source_ids") != expected_survivor_sources
                or row.get("absorbed_source_ids") != expected_absorbed_sources
            ):
                raise ReportDedupAuthorityError(
                    "receipt applied decision disagrees with live source authority"
                )
            if absorbed in applied_from_decisions:
                raise ReportDedupAuthorityError(
                    "receipt absorbed identity has duplicate applied decisions"
                )
            applied_from_decisions[absorbed] = survivor
    if applied_from_decisions != applied:
        raise ReportDedupAuthorityError(
            "receipt applied decisions do not match applied aliases"
        )
    seen_absorbed: set[str] = set()
    for absorbed, survivor in applied.items():
        if not absorbed or not survivor or absorbed == survivor or absorbed in seen_absorbed:
            raise ReportDedupAuthorityError("receipt applied alias identity is invalid")
        if survivor not in post_ids:
            raise ReportDedupAuthorityError(
                "receipt applied alias immediate survivor is not live"
            )
        seen_absorbed.add(absorbed)
    for start in applied:
        seen = {start}
        current = applied[start]
        while current in applied:
            if current in seen:
                raise ReportDedupAuthorityError("receipt report alias cycle")
            seen.add(current)
            current = applied[current]
        if current not in post_ids:
            raise ReportDedupAuthorityError("receipt applied alias has no live survivor")
    pre_sections = _section_map(pre_report)
    post_sections = _section_map(post_report)
    for absorbed in applied:
        section = pre_sections.get(absorbed, "")
        survivor_section = post_sections.get(applied[absorbed], "")
        if (
            not section
            or not survivor_section
            or _demoted_section(absorbed, section).strip() not in survivor_section
        ):
            raise ReportDedupAuthorityError(
                "receipt absorbed section lacks exact lossless coupling"
            )
    expected_postconditions = {
        "all_candidates_disposed": True,
        "all_survivors_live": True,
        "applied_equals_standalone_identity_delta": True,
        "candidate_loss": [],
        "cycles": [],
    }
    if payload.get("postconditions") != expected_postconditions:
        raise ReportDedupAuthorityError("receipt postconditions failed")


def decision_projection_for_closure_broker(
    payload: Mapping[str, Any],
    *,
    pre_report: str,
    post_report: str,
    exact_inputs: Sequence[Mapping[str, Any]],
    source_ids_by_report_id: Mapping[str, set[str]],
    semantic_aliases: Mapping[str, Mapping[str, str]] | None = None,
) -> dict[str, Any]:
    """Return a deterministic, non-authoritative central-broker projection.

    The current slice does not wire ``closure_broker_v2``.  This projection is
    the future adapter boundary: it can be emitted only after full receipt
    replay succeeds and carries no Markdown-derived fields or independent
    closure decision.
    """
    validate_receipt(
        payload,
        pre_report=pre_report,
        post_report=post_report,
        exact_inputs=exact_inputs,
        source_ids_by_report_id=source_ids_by_report_id,
        semantic_aliases=semantic_aliases or {},
    )
    decisions = [
        {
            "authority_kind": "APPLIED_LOSSLESS_EQUIVALENCE",
            "subject_id": str(row["absorbed"]),
            "survivor_id": str(row["survivor"]),
            "decision": "AUTHORIZED_ALIAS",
        }
        for row in payload.get("applied_aliases", [])
    ]
    return {
        "schema_version": BROKER_PROJECTION_SCHEMA,
        "provider": "report_dedup_applied_alias_authority",
        "source_receipt_sha256": str(payload.get("receipt_sha256", "")),
        "decisions": decisions,
    }


__all__ = [
    "BROKER_PROJECTION_SCHEMA",
    "RECEIPT_NAME",
    "REQUIRED_EXACT_INPUT_PATHS",
    "ReportDedupAuthorityError",
    "SCHEMA_VERSION",
    "build_receipt",
    "canonical_receipt_bytes",
    "decision_projection_for_closure_broker",
    "source_identity_equivalent",
    "standalone_report_ids",
    "validate_receipt",
]
