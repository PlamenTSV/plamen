"""Typed applied-authority boundary for semantic deduplication.

``dedup_decisions.md`` is untrusted proposal material.  This module is the
mechanical authority for the smaller set of transformations that actually
landed.  Its immutable receipt binds proposal identity, exact input/output
bytes, the identity delta, survivor existence, conflicts, and field-complete
preservation of each absorbed finding.

The design is deliberately recall-biased: malformed, ambiguous, conflicting,
row-form, or lossy transformations are rejected and the member stays live.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = "plamen.semantic_dedup_applied_receipt.v1"
PRIMARY_RECEIPT_NAME = "semantic_dedup_applied_receipt.json"
SUPPLEMENTAL_RECEIPT_NAME = "semantic_dedup_supplemental_applied_receipt.json"

__all__ = [
    "DedupAuthorityError",
    "PRIMARY_RECEIPT_NAME",
    "SCHEMA_VERSION",
    "SUPPLEMENTAL_RECEIPT_NAME",
    "assess_field_preservation",
    "canonical_json_bytes",
    "conflicting_merge_members",
    "extract_finding_records",
    "load_applied_aliases",
    "parse_dedup_proposals",
    "preserved_member_card",
    "proposals_from_merge_candidates",
    "write_applied_receipt",
]

_ID = r"(?:INV|F)-\d+"
_ID_RE = re.compile(rf"\b({_ID})\b", re.IGNORECASE)
_SC_HEADING_RE = re.compile(
    rf"(?im)^#{{2,4}}\s+(?:Finding\s+)?\[({_ID})\]:?\s*([^\n]*)\n?"
)
_MERGE_GROUP_RE = re.compile(
    rf"(?im)^\s*MERGE\s*:\s*(\[?{_ID}\]?(?:\s*,\s*\[?{_ID}\]?)+)"
)
_MERGE_HEADING_RE = re.compile(
    rf"(?im)^\s*#{{2,6}}\s+MERGE:\s+\[?({_ID})\]?\s+absorbs\s+\[?({_ID})\]?"
)
_MERGED_ROW_RE = re.compile(
    rf"(?im)^\|\s*\[?({_ID})\]?\s*\|\s*MERGED\s+into\s+\[?({_ID})\]?"
)
_KEEP_LINE_RE = re.compile(rf"(?im)^\s*KEEP\s*:\s*\[?({_ID})\]?\s*$")
_KEEP_HEADING_RE = re.compile(
    rf"(?im)^\s*#{{2,6}}\s+KEEP\s+SEPARATE:\s+\[?({_ID})\]?\s+vs\s+\[?({_ID})\]?"
)
_NONMERGE_ROW_RE = re.compile(
    rf"(?im)^\|\s*\[?({_ID})\]?\s*\|\s*"
    r"(KEEP\s+SEPARATE|KEEP|PASS|PASSTHROUGH|N/A)\b"
)

_CARD_BEGIN_RE = re.compile(
    rf"(?m)^<!-- PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id=({_ID}) "
    r"sha256=([0-9a-f]{64}) bytes=(\d+) -->\s*$"
)

_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "mechanism_root_cause": (
        "root cause", "mechanism", "cause", "invariant broken", "bug mechanism",
    ),
    "description": ("description", "finding summary", "summary", "details"),
    "preconditions": (
        "preconditions", "precondition", "requirements", "assumptions", "trigger",
    ),
    "impact": ("impact", "security impact", "combined impact", "risk"),
    "recommendation": (
        "recommendation", "suggested fix", "fix", "mitigation", "remediation",
    ),
    "external_premises": (
        "external premises", "external premise", "external assumptions",
        "external assumption", "dependency assumptions", "dependency premise",
    ),
    "evidence_scope": (
        "evidence scope", "proof scope", "poc scope", "execution scope",
        "code trace", "evidence narrative",
    ),
    "locations": ("location", "locations", "code location", "primary location", "file"),
    "source_ids": (
        "source ids", "source id", "sources", "constituent findings",
        "internal finding ids", "source identity",
    ),
    "severity": ("severity", "risk level", "level"),
}


class DedupAuthorityError(RuntimeError):
    """The proposed/applied boundary cannot be proven sound."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_core(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return the sole on-disk serialization accepted for a receipt."""
    return _canonical_core(value)


def _canonical_digest(value: Any) -> str:
    return _sha(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    )


def _norm_id(value: str) -> str:
    match = _ID_RE.search(str(value or ""))
    return match.group(1).upper() if match else ""


def _proposal(
    action: str,
    members: Sequence[str],
    requested_survivor: str,
    sources: Sequence[str],
) -> dict[str, Any]:
    normalized: list[str] = []
    for member in members:
        member = _norm_id(member)
        if member and member not in normalized:
            normalized.append(member)
    survivor = _norm_id(requested_survivor)
    identity = {
        "action": action,
        "member_ids": sorted(normalized),
        "requested_survivor": survivor,
    }
    return {
        "proposal_id": "DPROP-" + _canonical_digest(identity)[:20].upper(),
        **identity,
        "sources": sorted(set(str(source) for source in sources if source)),
    }


def parse_dedup_proposals(text: str) -> list[dict[str, Any]]:
    """Parse normalized proposal events without granting application authority.

    Duplicate representations of one decision (group line + heading + status
    row) collapse to one proposal identity.  KEEP/PASS/PASSTHROUGH records are
    retained so a contradictory MERGE can be vetoed deterministically.
    """
    grouped: dict[tuple[str, tuple[str, ...], str], dict[str, Any]] = {}

    def add(action: str, members: Sequence[str], survivor: str, source: str) -> None:
        event = _proposal(action, members, survivor, (source,))
        if action == "MERGE" and len(event["member_ids"]) < 2:
            return
        if action != "MERGE" and not event["member_ids"]:
            return
        key = (
            event["action"],
            tuple(event["member_ids"]),
            event["requested_survivor"],
        )
        prior = grouped.get(key)
        if prior is None:
            grouped[key] = event
        else:
            prior["sources"] = sorted(set(prior["sources"] + event["sources"]))

    for match in _MERGE_GROUP_RE.finditer(text or ""):
        ids = [_norm_id(token) for token in _ID_RE.findall(match.group(1))]
        ids = [item for item in ids if item]
        if len(ids) >= 2:
            add("MERGE", ids, ids[0], "MERGE_GROUP_LINE")
    for match in _MERGE_HEADING_RE.finditer(text or ""):
        add("MERGE", (match.group(1), match.group(2)), match.group(1), "MERGE_HEADING")
    for match in _MERGED_ROW_RE.finditer(text or ""):
        add("MERGE", (match.group(2), match.group(1)), match.group(2), "MERGED_STATUS_ROW")
    for match in _KEEP_LINE_RE.finditer(text or ""):
        add("KEEP", (match.group(1),), match.group(1), "KEEP_LINE")
    for match in _KEEP_HEADING_RE.finditer(text or ""):
        add("KEEP", (match.group(1), match.group(2)), "", "KEEP_SEPARATE_HEADING")
    for match in _NONMERGE_ROW_RE.finditer(text or ""):
        add("KEEP", (match.group(1),), match.group(1), match.group(2).upper())
    return sorted(grouped.values(), key=lambda row: row["proposal_id"])


def conflicting_merge_members(proposals: Sequence[Mapping[str, Any]]) -> set[str]:
    kept: set[str] = set()
    proposed_absorbed: set[str] = set()
    proposed_survivors: dict[str, set[str]] = {}
    for event in proposals:
        members = {_norm_id(item) for item in event.get("member_ids", [])}
        members.discard("")
        if event.get("action") == "MERGE":
            requested = _norm_id(str(event.get("requested_survivor", "")))
            for member in members:
                if member == requested:
                    continue
                proposed_absorbed.add(member)
                proposed_survivors.setdefault(member, set()).add(requested)
        elif event.get("action") == "KEEP":
            kept.update(members)
    # A survivor's PASS/KEEP row is compatible with absorbing another member
    # into it. Conflict exists only when the member proposed for removal also
    # has an explicit independently-live disposition.
    ambiguous = {
        member for member, survivors in proposed_survivors.items()
        if len(survivors) > 1
    }
    return (proposed_absorbed & kept) | ambiguous


def proposals_from_merge_candidates(
    merges: Iterable[tuple[str, str, str]],
    *,
    source: str,
) -> list[dict[str, Any]]:
    """Create typed proposal identities for deterministic merge candidates."""
    events: dict[str, dict[str, Any]] = {}
    for absorbed, survivor, _reason in merges:
        event = _proposal("MERGE", (survivor, absorbed), survivor, (source,))
        events[event["proposal_id"]] = event
    return sorted(events.values(), key=lambda row: row["proposal_id"])


def _normalize_field_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def _markdown_fields(raw: str) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw.splitlines():
        match = re.match(r"^\s*\*\*([^*]+)\*\*\s*:\s*(.*)$", line)
        if match:
            current = _normalize_field_name(match.group(1))
            parsed.setdefault(current, []).append(match.group(2).strip())
            continue
        heading = re.match(r"^\s*#{2,6}\s+(.+?)\s*$", line)
        if heading:
            current = _normalize_field_name(heading.group(1))
            parsed.setdefault(current, [])
            continue
        if current and line.strip():
            parsed[current][-1:] = [
                (parsed[current][-1] + "\n" + line.strip()).strip()
                if parsed[current]
                else line.strip()
            ]
    return parsed


def _semantic_fields(raw: str, title: str, row_values: Mapping[str, str] | None = None) -> dict[str, Any]:
    row_values = row_values or {}
    parsed = _markdown_fields(raw)
    fields: dict[str, Any] = {"title": title.strip()}
    normalized_rows = {_normalize_field_name(k): str(v).strip() for k, v in row_values.items()}
    for canonical, aliases in _FIELD_ALIASES.items():
        values: list[str] = []
        for alias in aliases:
            key = _normalize_field_name(alias)
            values.extend(value for value in parsed.get(key, []) if value.strip())
            if normalized_rows.get(key):
                values.append(normalized_rows[key])
        if canonical == "source_ids":
            tokens: list[str] = []
            for value in values:
                for token in re.findall(r"\b[A-Za-z][A-Za-z0-9_]{0,31}-\d+\b", value):
                    token = token.upper()
                    if token not in tokens:
                        tokens.append(token)
            if tokens:
                fields[canonical] = sorted(tokens)
        elif values:
            fields[canonical] = values
    tags = sorted(
        {
            match.group(0).upper()
            for match in re.finditer(r"\[[A-Z][A-Z0-9_-]{2,63}\]", raw, re.IGNORECASE)
            if not _ID_RE.fullmatch(match.group(0).strip("[]"))
        }
    )
    if tags:
        fields["evidence_tags"] = tags
    return fields


def _record(fid: str, title: str, raw: str, kind: str, row_values: Mapping[str, str] | None = None) -> dict[str, Any]:
    fields = _semantic_fields(raw, title, row_values)
    field_hashes = {
        key: _canonical_digest(value)
        for key, value in sorted(fields.items())
        if value not in ("", [], None)
    }
    return {
        "finding_id": fid,
        "kind": kind,
        "title": title.strip(),
        "raw": raw,
        "raw_sha256": _sha(raw.encode("utf-8")),
        "fields": fields,
        "field_hashes": field_hashes,
    }


def extract_finding_records(text: str) -> dict[str, dict[str, Any]]:
    """Extract top-level SC blocks or typed Markdown queue rows.

    Preserved-member blockquotes are intentionally not top-level identities.
    Duplicate IDs or malformed tables fail closed instead of silently choosing
    one record.
    """
    records: dict[str, dict[str, Any]] = {}
    headings = list(_SC_HEADING_RE.finditer(text or ""))
    for index, match in enumerate(headings):
        start = match.start()
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        fid = _norm_id(match.group(1))
        raw = text[start:end]
        if fid in records:
            raise DedupAuthorityError(f"duplicate top-level finding identity: {fid}")
        records[fid] = _record(fid, match.group(2), raw, "sc")
    if records:
        return records

    header: list[str] | None = None
    for raw_line in (text or "").splitlines(keepends=True):
        stripped = raw_line.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and all(set(cell) <= {"-", ":", " "} for cell in cells if cell):
            continue
        normalized = [_normalize_field_name(cell) for cell in cells]
        if "finding id" in normalized or "finding" in normalized and "severity" in normalized:
            header = normalized
            continue
        if not header:
            continue
        row = dict(zip(header, cells))
        fid = _norm_id(row.get("finding id", row.get("finding", "")))
        if not fid:
            continue
        if fid in records:
            raise DedupAuthorityError(f"duplicate queue finding identity: {fid}")
        title = row.get("title", row.get("finding", fid))
        records[fid] = _record(fid, title, raw_line, "row", row)
    return records


def preserved_member_card(record: Mapping[str, Any]) -> str:
    """Render a visible, exact-byte-recoverable absorbed-member card."""
    fid = _norm_id(str(record.get("finding_id", "")))
    raw = str(record.get("raw", ""))
    digest = _sha(raw.encode("utf-8"))
    encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
    visible_lines: list[str] = []
    for line in raw.splitlines(keepends=True):
        # Escape Markdown headings in the human-readable projection so legacy
        # unanchored finding parsers cannot resurrect the absorbed member as a
        # second top-level identity. Exact original bytes remain in base64.
        heading = re.match(r"^(\s*)(#{1,6})\s+(.+?)(\r?\n)?$", line)
        if heading:
            heading_text = re.sub(
                rf"(?i)^(?:Finding\s+)?\[?({_ID})\]?:?\s*",
                r"member \1 — ",
                heading.group(3),
            )
            visible_line = (
                f"{heading.group(1)}Original heading level {len(heading.group(2))}: "
                f"{heading_text}{heading.group(4) or ''}"
            )
        else:
            visible_line = line
        visible_lines.append(
            "> " + visible_line
            if visible_line.endswith("\n")
            else "> " + visible_line + "\n"
        )
    visible = "".join(visible_lines)
    if not visible:
        visible = "> (empty member)\n"
    return (
        f"\n<!-- PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id={fid} "
        f"sha256={digest} bytes={len(raw.encode('utf-8'))} -->\n"
        f"##### Preserved dedup member {fid}\n"
        f"{visible}"
        f"<!-- PLAMEN_DEDUP_PRESERVED_MEMBER_RAW_BASE64 {encoded} -->\n"
        f"<!-- PLAMEN_DEDUP_PRESERVED_MEMBER_END id={fid} -->\n"
    )


def _extract_preserved_raw(container: str, member_id: str) -> tuple[str | None, list[str]]:
    member_id = _norm_id(member_id)
    issues: list[str] = []
    matches = [m for m in _CARD_BEGIN_RE.finditer(container) if _norm_id(m.group(1)) == member_id]
    if len(matches) != 1:
        return None, ["preserved-member-card-missing" if not matches else "preserved-member-card-ambiguous"]
    begin = matches[0]
    end_re = re.compile(
        rf"(?m)^<!-- PLAMEN_DEDUP_PRESERVED_MEMBER_END id={re.escape(member_id)} -->\s*$"
    )
    end = end_re.search(container, begin.end())
    if end is None:
        return None, ["preserved-member-card-truncated"]
    body = container[begin.end():end.start()]
    raw_match = re.search(
        r"<!-- PLAMEN_DEDUP_PRESERVED_MEMBER_RAW_BASE64 ([A-Za-z0-9+/=]*) -->",
        body,
    )
    if raw_match is None:
        return None, ["preserved-member-raw-missing"]
    try:
        raw_bytes = base64.b64decode(raw_match.group(1), validate=True)
        raw = raw_bytes.decode("utf-8")
    except Exception:
        return None, ["preserved-member-raw-invalid"]
    if len(raw_bytes) != int(begin.group(3)):
        issues.append("preserved-member-byte-count-mismatch")
    if _sha(raw_bytes) != begin.group(2):
        issues.append("preserved-member-hash-mismatch")
    return raw, issues


def assess_field_preservation(
    pre_records: Mapping[str, Mapping[str, Any]],
    post_text: str,
    absorbed_id: str,
    survivor_id: str,
) -> dict[str, Any]:
    """Prove an absorbed member remains field-complete under its survivor."""
    absorbed_id = _norm_id(absorbed_id)
    survivor_id = _norm_id(survivor_id)
    issues: list[str] = []
    absorbed = pre_records.get(absorbed_id)
    if absorbed is None:
        return {
            "passed": False,
            "issues": ["absorbed-member-not-in-input"],
            "preserved_fields": [],
            "missing_fields": [],
        }
    try:
        post_records = extract_finding_records(post_text)
    except DedupAuthorityError as exc:
        return {
            "passed": False,
            "issues": [f"post-parse-error:{exc}"],
            "preserved_fields": [],
            "missing_fields": sorted(absorbed.get("field_hashes", {})),
        }
    survivor = post_records.get(survivor_id)
    if survivor is None:
        issues.append("survivor-not-in-output")
        container = ""
    else:
        container = (
            post_text
            if str(absorbed.get("kind", "")) == "row"
            else str(survivor.get("raw", ""))
        )
    recovered, card_issues = _extract_preserved_raw(container, absorbed_id)
    issues.extend(card_issues)
    preserved: list[str] = []
    missing: list[str] = []
    recovered_hashes: dict[str, str] = {}
    if recovered is not None:
        exact_raw = _sha(recovered.encode("utf-8")) == absorbed.get("raw_sha256")
        if not exact_raw:
            issues.append("absorbed-member-bytes-changed")
        if str(absorbed.get("kind", "")) == "row" and exact_raw:
            # Exact original row bytes preserve every schema column. Re-parsing
            # a detached row without its table header would discard column
            # roles, so byte identity is the stronger proof here.
            recovered_hashes = dict(absorbed.get("field_hashes", {}))
        else:
            try:
                recovered_record = _record(
                    absorbed_id,
                    str(absorbed.get("title", "")),
                    recovered,
                    str(absorbed.get("kind", "sc")),
                )
                recovered_hashes = recovered_record["field_hashes"]
            except Exception:
                issues.append("absorbed-member-field-reparse-failed")
    for field, digest in sorted(dict(absorbed.get("field_hashes", {})).items()):
        if recovered_hashes.get(field) == digest:
            preserved.append(field)
        else:
            missing.append(field)
    if missing:
        issues.append("field-hash-mismatch")
    return {
        "passed": not issues,
        "issues": sorted(set(issues)),
        "preserved_fields": preserved,
        "missing_fields": missing,
        "absorbed_raw_sha256": absorbed.get("raw_sha256", ""),
        "survivor_id": survivor_id,
    }


def _receipt_name(application_kind: str) -> str:
    kind = str(application_kind).upper()
    if kind == "PRIMARY":
        return PRIMARY_RECEIPT_NAME
    if kind == "SUPPLEMENTAL":
        return SUPPLEMENTAL_RECEIPT_NAME
    raise DedupAuthorityError(f"unknown application kind: {application_kind}")


def _with_receipt_digest(payload: dict[str, Any]) -> dict[str, Any]:
    core = dict(payload)
    core.pop("receipt_sha256", None)
    payload = dict(core)
    payload["receipt_sha256"] = _canonical_digest(core)
    return payload


def _validate_payload(payload: Mapping[str, Any]) -> None:
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise DedupAuthorityError("applied receipt schema mismatch")
    core = dict(payload)
    claimed = str(core.pop("receipt_sha256", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", claimed) or claimed != _canonical_digest(core):
        raise DedupAuthorityError("applied receipt digest mismatch")
    if payload.get("application_kind") not in {"PRIMARY", "SUPPLEMENTAL"}:
        raise DedupAuthorityError("applied receipt application kind mismatch")
    if payload.get("phase_name") not in {"sc_semantic_dedup", "semantic_dedup"}:
        raise DedupAuthorityError("applied receipt phase mismatch")
    proposals = payload.get("proposals", [])
    if not isinstance(proposals, list):
        raise DedupAuthorityError("applied receipt proposals are malformed")
    proposal_meta = payload.get("proposal_artifact", {})
    if proposal_meta.get("proposal_count") != len(proposals):
        raise DedupAuthorityError("applied receipt proposal count mismatch")
    if proposal_meta.get("proposal_digest") != _canonical_digest(proposals):
        raise DedupAuthorityError("applied receipt proposal digest mismatch")
    proposal_by_id = {
        str(proposal.get("proposal_id", "")): proposal
        for proposal in proposals
        if isinstance(proposal, Mapping) and proposal.get("proposal_id")
    }
    if len(proposal_by_id) != len(
        [proposal for proposal in proposals if isinstance(proposal, Mapping)]
    ):
        raise DedupAuthorityError("applied receipt proposal identities are not unique")

    def artifact_ids(name: str) -> set[str]:
        values = payload.get(name, {}).get("finding_ids", [])
        if not isinstance(values, list):
            raise DedupAuthorityError(f"{name} identities are malformed")
        normalized = [_norm_id(str(item)) for item in values]
        if any(not item for item in normalized) or len(set(normalized)) != len(normalized):
            raise DedupAuthorityError(f"{name} identities are invalid or duplicated")
        if values != sorted(normalized):
            raise DedupAuthorityError(f"{name} identities are not canonical")
        digest = str(payload.get(name, {}).get("sha256", ""))
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise DedupAuthorityError(f"{name} digest is malformed")
        return set(normalized)

    input_ids = artifact_ids("input_artifact")
    output_ids = artifact_ids("output_artifact")
    computed_removed = sorted(input_ids - output_ids)
    computed_added = sorted(output_ids - input_ids)
    accepted = sorted(str(item) for item in payload.get("accepted_absorbed_ids", []))
    removed = sorted(str(item) for item in payload.get("identity_delta", {}).get("removed_ids", []))
    added = sorted(str(item) for item in payload.get("identity_delta", {}).get("added_ids", []))
    if removed != computed_removed or added != computed_added:
        raise DedupAuthorityError("stored identity delta does not match receipt artifacts")
    if accepted != removed:
        raise DedupAuthorityError("accepted identities do not equal pre/post identity delta")
    accepted_decisions: dict[str, str] = {}
    rejected_input_members: set[str] = set()
    for decision in payload.get("decisions", []):
        status = decision.get("status")
        member = _norm_id(str(decision.get("member_id", "")))
        proposal = proposal_by_id.get(str(decision.get("proposal_id", "")))
        if not member or proposal is None or member not in {
            _norm_id(str(item)) for item in proposal.get("member_ids", [])
        }:
            raise DedupAuthorityError("decision is not bound to its proposal member")
        if status == "REJECTED":
            if decision.get("actual_survivor"):
                raise DedupAuthorityError("rejected decision names an applied survivor")
            if member in input_ids:
                rejected_input_members.add(member)
            continue
        if status != "ACCEPTED":
            raise DedupAuthorityError("applied receipt decision status is invalid")
        survivor = _norm_id(str(decision.get("actual_survivor", "")))
        if member not in input_ids or member in output_ids or not survivor or survivor not in output_ids:
            raise DedupAuthorityError("accepted decision has no live survivor")
        if member in accepted_decisions:
            raise DedupAuthorityError("accepted member has duplicate decisions")
        if not decision.get("field_preservation", {}).get("passed"):
            raise DedupAuthorityError("accepted decision lacks field preservation proof")
        requested = _norm_id(str(decision.get("requested_survivor", "")))
        if bool(decision.get("direction_flipped")) != (survivor != requested):
            raise DedupAuthorityError("accepted direction-flip marker is inconsistent")
        accepted_decisions[member] = survivor
    if sorted(accepted_decisions) != accepted:
        raise DedupAuthorityError("accepted decision set does not match identity delta")
    if added:
        raise DedupAuthorityError("dedup transformation invented top-level identities")
    if not rejected_input_members <= output_ids:
        raise DedupAuthorityError("rejected input member was removed")
    postconditions = payload.get("postconditions", {})
    expected_postconditions = {
        "accepted_equals_identity_delta": True,
        "all_accepted_survivors_live": True,
        "all_rejected_input_members_live": True,
        "field_complete": True,
        "conflicts_applied": [],
    }
    for key, expected in expected_postconditions.items():
        if postconditions.get(key) != expected:
            raise DedupAuthorityError(f"applied receipt postcondition failed: {key}")


def _read_receipt(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise DedupAuthorityError(f"applied receipt is invalid JSON: {exc}") from exc
    if raw != canonical_json_bytes(payload):
        raise DedupAuthorityError("applied receipt is not canonical immutable JSON")
    _validate_payload(payload)
    return payload


def _write_immutable(path: Path, raw: bytes) -> None:
    if path.exists():
        if path.read_bytes() == raw:
            return
        raise DedupAuthorityError(f"immutable applied receipt conflict: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_applied_receipt(
    scratchpad: Path,
    *,
    phase_name: str,
    application_kind: str,
    proposal_text: str,
    proposals: Sequence[Mapping[str, Any]],
    input_text: str,
    output_text: str,
    applied_merges: Iterable[tuple[str, str, str]],
    rejection_reasons: Mapping[str, str] | None = None,
    proposal_path: str | None = None,
) -> dict[str, Any]:
    """Validate and immutably record the exact transformation that landed."""
    scratchpad = Path(scratchpad)
    application_kind = application_kind.upper()
    if phase_name not in {"sc_semantic_dedup", "semantic_dedup"}:
        raise DedupAuthorityError(f"unsupported semantic dedup phase: {phase_name}")
    pre = extract_finding_records(input_text)
    post = extract_finding_records(output_text)
    if application_kind == "SUPPLEMENTAL":
        primary_path = scratchpad / PRIMARY_RECEIPT_NAME
        if not primary_path.is_file():
            raise DedupAuthorityError("supplemental application has no primary predecessor")
        primary = _read_receipt(primary_path)
        if primary.get("phase_name") != phase_name:
            raise DedupAuthorityError("supplemental application changes pipeline phase")
        if primary["output_artifact"]["sha256"] != _sha(input_text.encode("utf-8")):
            raise DedupAuthorityError("supplemental input hash does not match primary output")
        if set(primary["output_artifact"]["finding_ids"]) != set(pre):
            raise DedupAuthorityError("supplemental input identities do not match primary output")
    pre_ids = set(pre)
    post_ids = set(post)
    removed = pre_ids - post_ids
    added = post_ids - pre_ids
    mapping: dict[str, tuple[str, str]] = {}
    for absorbed, survivor, reason in applied_merges:
        absorbed = _norm_id(absorbed)
        survivor = _norm_id(survivor)
        if not absorbed or not survivor or absorbed == survivor:
            raise DedupAuthorityError("invalid applied merge identity")
        if absorbed in mapping and mapping[absorbed][0] != survivor:
            raise DedupAuthorityError("one absorbed identity has multiple applied survivors")
        mapping[absorbed] = (survivor, str(reason))
    if set(mapping) != removed:
        raise DedupAuthorityError(
            "applied merge set does not equal pre/post identity delta: "
            f"applied={sorted(mapping)} removed={sorted(removed)}"
        )
    conflicts = conflicting_merge_members(proposals)
    if conflicts & set(mapping):
        raise DedupAuthorityError("conflicting MERGE/KEEP proposal was applied")

    rejection_reasons = {_norm_id(k): str(v) for k, v in (rejection_reasons or {}).items()}
    decisions: list[dict[str, Any]] = []
    represented_accepted: set[str] = set()
    seen_decision_key: set[tuple[str, str]] = set()
    for proposal in sorted(proposals, key=lambda row: str(row.get("proposal_id", ""))):
        if proposal.get("action") != "MERGE":
            continue
        requested = _norm_id(str(proposal.get("requested_survivor", "")))
        for member in proposal.get("member_ids", []):
            member = _norm_id(str(member))
            if not member or member == requested:
                continue
            key = (str(proposal.get("proposal_id", "")), member)
            if key in seen_decision_key:
                continue
            seen_decision_key.add(key)
            row: dict[str, Any] = {
                "proposal_id": key[0],
                "action": "MERGE",
                "member_id": member,
                "requested_survivor": requested,
            }
            if member in mapping:
                survivor, reason = mapping[member]
                check = assess_field_preservation(pre, output_text, member, survivor)
                if not check.get("passed"):
                    raise DedupAuthorityError(
                        f"field preservation failed for {member}->{survivor}: "
                        + ",".join(check.get("issues", []))
                    )
                row.update(
                    {
                        "status": "ACCEPTED",
                        "reason": reason,
                        "actual_survivor": survivor,
                        "direction_flipped": survivor != requested,
                        "field_preservation": check,
                    }
                )
                represented_accepted.add(member)
            else:
                if member in conflicts:
                    why = "CONFLICTING_PROPOSAL"
                elif member not in pre_ids:
                    why = "MEMBER_NOT_IN_INPUT"
                else:
                    why = rejection_reasons.get(member, "NOT_APPLIED")
                row.update(
                    {
                        "status": "REJECTED",
                        "reason": why,
                        "actual_survivor": "",
                        "direction_flipped": False,
                        "field_preservation": {
                            "passed": False,
                            "issues": ["not-destructively-applied"],
                            "preserved_fields": [],
                            "missing_fields": [],
                        },
                    }
                )
            decisions.append(row)
    # Transitive closure can absorb an event's originally-requested survivor
    # into the final component survivor.  Record that applied member against a
    # proposal that actually contained it instead of losing authority merely
    # because the proposal direction was mechanically flipped downstream.
    for member in sorted(set(mapping) - represented_accepted):
        candidate = next(
            (
                proposal
                for proposal in sorted(
                    proposals, key=lambda row: str(row.get("proposal_id", ""))
                )
                if proposal.get("action") == "MERGE"
                and member in {_norm_id(str(item)) for item in proposal.get("member_ids", [])}
            ),
            None,
        )
        if candidate is None:
            continue
        survivor, reason = mapping[member]
        check = assess_field_preservation(pre, output_text, member, survivor)
        if not check.get("passed"):
            raise DedupAuthorityError(
                f"field preservation failed for {member}->{survivor}: "
                + ",".join(check.get("issues", []))
            )
        decisions.append(
            {
                "proposal_id": str(candidate.get("proposal_id", "")),
                "action": "MERGE",
                "member_id": member,
                "requested_survivor": _norm_id(
                    str(candidate.get("requested_survivor", ""))
                ),
                "status": "ACCEPTED",
                "reason": reason,
                "actual_survivor": survivor,
                "direction_flipped": survivor
                != _norm_id(str(candidate.get("requested_survivor", ""))),
                "field_preservation": check,
            }
        )
        represented_accepted.add(member)
    if represented_accepted != set(mapping):
        raise DedupAuthorityError("an applied identity has no matching proposal event")
    for decision in decisions:
        if decision["status"] == "REJECTED":
            member = decision["member_id"]
            if member in pre_ids and member not in post_ids:
                raise DedupAuthorityError("a rejected proposal member was removed")

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "phase_name": phase_name,
        "application_kind": application_kind,
        "proposal_artifact": {
            "path": proposal_path or (
                "dedup_decisions.md"
                if application_kind == "PRIMARY"
                else "dedup_candidate_pairs_full.md"
            ),
            "sha256": _sha(proposal_text.encode("utf-8")),
            "proposal_count": len(proposals),
            "proposal_digest": _canonical_digest(list(proposals)),
        },
        "input_artifact": {
            "logical_name": "findings_inventory.md",
            "sha256": _sha(input_text.encode("utf-8")),
            "finding_ids": sorted(pre_ids),
        },
        "output_artifact": {
            "logical_name": "findings_inventory.md",
            "sha256": _sha(output_text.encode("utf-8")),
            "finding_ids": sorted(post_ids),
        },
        "proposals": list(proposals),
        "decisions": decisions,
        "accepted_absorbed_ids": sorted(mapping),
        "rejected_member_ids": sorted(
            {
                decision["member_id"]
                for decision in decisions
                if decision["status"] == "REJECTED"
            }
        ),
        "identity_delta": {
            "removed_ids": sorted(removed),
            "added_ids": sorted(added),
        },
        "postconditions": {
            "accepted_equals_identity_delta": sorted(mapping) == sorted(removed),
            "all_accepted_survivors_live": all(survivor in post for survivor, _ in mapping.values()),
            "all_rejected_input_members_live": all(
                decision["member_id"] not in pre_ids or decision["member_id"] in post_ids
                for decision in decisions
                if decision["status"] == "REJECTED"
            ),
            "field_complete": all(
                decision["field_preservation"]["passed"]
                for decision in decisions
                if decision["status"] == "ACCEPTED"
            ),
            "conflicts_applied": sorted(conflicts & set(mapping)),
        },
    }
    payload = _with_receipt_digest(payload)
    _validate_payload(payload)
    raw = canonical_json_bytes(payload)
    path = scratchpad / _receipt_name(application_kind)
    _write_immutable(path, raw)
    return _read_receipt(path)


def load_applied_aliases(
    scratchpad: Path,
    *,
    canonical_text: str | None = None,
) -> dict[str, dict[str, str]]:
    """Return accepted aliases from a valid receipt chain only.

    No receipt means no alias authority.  A corrupt/stale receipt raises so a
    caller can degrade to no propagation while surfacing debt.
    """
    scratchpad = Path(scratchpad)
    paths = [scratchpad / PRIMARY_RECEIPT_NAME, scratchpad / SUPPLEMENTAL_RECEIPT_NAME]
    present = [path for path in paths if path.is_file()]
    if not present:
        return {}
    if present[0].name != PRIMARY_RECEIPT_NAME:
        raise DedupAuthorityError("supplemental receipt has no primary predecessor")
    receipts = [_read_receipt(path) for path in present]
    phase = receipts[0]["phase_name"]
    if any(receipt["phase_name"] != phase for receipt in receipts):
        raise DedupAuthorityError("applied receipt chain changes pipeline phase")
    for left, right in zip(receipts, receipts[1:]):
        if left["output_artifact"]["sha256"] != right["input_artifact"]["sha256"]:
            raise DedupAuthorityError("applied receipt chain input/output hash mismatch")
        if set(left["output_artifact"]["finding_ids"]) != set(right["input_artifact"]["finding_ids"]):
            raise DedupAuthorityError("applied receipt chain identity mismatch")
    if canonical_text is None:
        canonical_path = scratchpad / "findings_inventory.md"
        if not canonical_path.is_file():
            raise DedupAuthorityError("canonical dedup output is missing")
        canonical_text = canonical_path.read_bytes().decode("utf-8", errors="strict")
    if _sha(canonical_text.encode("utf-8")) != receipts[-1]["output_artifact"]["sha256"]:
        raise DedupAuthorityError("canonical output hash does not match applied receipt")
    current_ids = set(extract_finding_records(canonical_text))
    if current_ids != set(receipts[-1]["output_artifact"]["finding_ids"]):
        raise DedupAuthorityError("canonical output identity set does not match applied receipt")
    aliases: dict[str, dict[str, str]] = {}
    for receipt in receipts:
        for decision in receipt["decisions"]:
            if decision["status"] != "ACCEPTED":
                continue
            member = decision["member_id"]
            survivor = decision["actual_survivor"]
            if member in aliases and aliases[member]["survivor"] != survivor:
                raise DedupAuthorityError("applied receipt chain conflicts on alias survivor")
            aliases[member] = {
                "survivor": survivor,
                "coupled": "field-complete-preserved",
            }
    final_ids = set(receipts[-1]["output_artifact"]["finding_ids"])
    for member, info in aliases.items():
        survivor = info["survivor"]
        seen: set[str] = {member}
        while survivor in aliases:
            if survivor in seen:
                raise DedupAuthorityError("applied alias cycle")
            seen.add(survivor)
            survivor = aliases[survivor]["survivor"]
        if survivor not in final_ids:
            raise DedupAuthorityError("applied alias does not resolve to a live survivor")
        info["survivor"] = survivor
    return aliases
