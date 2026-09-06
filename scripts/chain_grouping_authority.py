"""P0-W lossless authority boundary for chain grouping.

Chain-authored Markdown proposes composition/group relations.  It is never
identity or equivalence authority.  This module leaves the semantic Markdown
byte-for-byte intact and emits a driver-owned overlay that either:

* retains a group only when a separately bound typed decision proves all five
  equivalence dimensions; or
* routes every member as an independent verification work item while keeping
  the original group as a composition-only alias card.

The overlay and applied receipt bind the exact source bytes.  A stale,
malformed, ambiguous, or partially proven overlay is ignored by consumers and
cannot collapse work.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


DECISION_SCHEMA = "plamen.chain_equivalence_proposals.v2"
RELATION_SCHEMA = "plamen.chain_grouping_relations.v2"
APPLIED_SCHEMA = "plamen.chain_anti_absorption_applied_receipt.v2"
DECISION_FILE = "chain_equivalence_proposals.json"
RELATION_FILE = "chain_grouping_relations.json"
APPLIED_FILE = "chain_anti_absorption_applied_receipt.json"
DEBT_FILE = "chain_grouping_debt.md"
_DIMENSIONS = ("mechanism", "preconditions", "effect", "impact", "remediation")
_FALLBACK_ID_RE = re.compile(r"^[A-Z][A-Z0-9_-]{1,95}$", re.ASCII)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("receipt_digest", None)
    return _sha256(_canonical_bytes(body))


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.p0w.tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    value["receipt_digest"] = _digest(value)
    _atomic_write(
        path,
        (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
            "utf-8"
        ),
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _read_json(path: Path) -> dict[str, Any]:
    def _reject(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    value = json.loads(
        path.read_text(encoding="utf-8", errors="strict"),
        object_pairs_hook=_strict_object,
        parse_constant=_reject,
    )
    if not isinstance(value, dict):
        raise TypeError(f"{path.name} must contain one object")
    return value


def _validate_digest(value: Mapping[str, Any], label: str) -> None:
    if value.get("receipt_digest") != _digest(value):
        raise ValueError(f"{label} receipt digest mismatch")


def _source_hashes(root: Path) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for name in ("findings_inventory.md", "hypotheses.md", "finding_mapping.md"):
        path = root / name
        try:
            result[name] = _sha256(path.read_bytes())
        except OSError:
            result[name] = None
    return result


def _file_hash(path: Path) -> str | None:
    try:
        return _sha256(path.read_bytes())
    except OSError:
        return None


def _norm_id(value: Any) -> str:
    token = str(value or "").strip().strip("[]`*_ ").upper()
    if not token:
        return ""
    # Finding identities are an extensible, registry-owned contract.  P0-W
    # must not maintain a shorter private prefix grammar: doing so silently
    # removes otherwise valid producer rows (for example nested DA namespaces)
    # from the member denominator before the independent-work projection.
    # The import is deliberately lazy because plamen_parsers invokes this
    # module from its finalized mapping projection.
    try:
        from plamen_parsers import _INTERNAL_FINDING_ID_RE

        return token if _INTERNAL_FINDING_ID_RE.fullmatch(token) else ""
    except (ImportError, AttributeError):
        # Bootstrap-only compatibility for isolated migration tooling.  Live
        # driver paths always have the canonical parser available; the relaxed
        # shape grants no equivalence authority and therefore fails toward
        # independent work rather than identity collapse.
        return token if _FALLBACK_ID_RE.fullmatch(token) else ""


def write_chain_equivalence_proposals(
    scratchpad: Path,
    decisions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Write typed equivalence proposals without granting collapse authority.

    Exact source hashes make a proposal unusable after semantic-source drift,
    but checksums and evidence labels are not proof of independent execution.
    No production consumer may collapse work from this file alone.
    """
    root = Path(scratchpad)
    normalized: list[dict[str, Any]] = []
    for raw in decisions:
        group_id = _norm_id(raw.get("group_id"))
        members = [_norm_id(value) for value in raw.get("members") or []]
        if not group_id or not members or any(not value for value in members):
            raise ValueError("chain equivalence decision identity is invalid")
        if len(members) != len(set(members)):
            raise ValueError("chain equivalence decision members are duplicated")
        dimensions: dict[str, dict[str, Any]] = {}
        raw_dimensions = raw.get("dimensions") or {}
        if not isinstance(raw_dimensions, Mapping):
            raise TypeError("chain equivalence dimensions must be an object")
        for name, value in raw_dimensions.items():
            if name not in _DIMENSIONS or not isinstance(value, Mapping):
                continue
            outcome = str(value.get("outcome") or "").strip().upper()
            evidence_ids = [
                str(item).strip() for item in value.get("evidence_ids") or []
                if str(item).strip()
            ]
            dimensions[name] = {
                "outcome": outcome,
                "evidence_ids": list(dict.fromkeys(evidence_ids)),
            }
        normalized.append({
            "group_id": group_id,
            "members": members,
            "decision": str(raw.get("decision") or "").strip().upper(),
            "dimensions": dimensions,
        })
    payload: dict[str, Any] = {
        "schema": DECISION_SCHEMA,
        "authority": "PROPOSAL_ONLY",
        "source_hashes": _source_hashes(root),
        "decisions": normalized,
    }
    _write_json(root / DECISION_FILE, payload)
    return payload


def _load_decisions(root: Path) -> tuple[dict[str, dict[str, Any]], str | None, list[str]]:
    path = root / DECISION_FILE
    if not path.is_file():
        return {}, None, []
    try:
        value = _read_json(path)
        _validate_digest(value, "chain equivalence decisions")
        if value.get("schema") != DECISION_SCHEMA:
            raise ValueError("unsupported chain equivalence decision schema")
        if value.get("authority") != "PROPOSAL_ONLY":
            raise ValueError("chain equivalence proposal authority mismatch")
        if value.get("source_hashes") != _source_hashes(root):
            raise ValueError("chain equivalence decision source bytes changed")
        by_group: dict[str, dict[str, Any]] = {}
        rows = value.get("decisions")
        if not isinstance(rows, list):
            raise TypeError("chain equivalence decisions must be an array")
        for row in rows:
            if not isinstance(row, dict):
                raise TypeError("chain equivalence decision row must be an object")
            group_id = _norm_id(row.get("group_id"))
            if not group_id or group_id in by_group:
                raise ValueError("chain equivalence decision group identity is ambiguous")
            by_group[group_id] = row
        return by_group, _file_hash(path), []
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        return {}, _file_hash(path), [
            f"typed equivalence decisions invalid: {type(exc).__name__}: {exc}"
        ]


def _line_record_hashes(root: Path, group_ids: Sequence[str]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for name in ("hypotheses.md", "finding_mapping.md"):
        try:
            lines = (root / name).read_bytes().splitlines(keepends=True)
        except OSError:
            lines = []
        per_group: dict[str, str] = {}
        for group_id in group_ids:
            selected = b"".join(
                line for line in lines
                if re.search(
                    rb"(?<![A-Za-z0-9])" + re.escape(group_id.encode("ascii")) + rb"(?![A-Za-z0-9])",
                    line,
                    re.IGNORECASE,
                )
            )
            per_group[group_id] = _sha256(selected)
        result[name] = per_group
    return result


def _proposal_signals(meta_list: Sequence[tuple[str, Mapping[str, str]]]) -> dict[str, Any]:
    loci = [str(meta.get("location") or "").strip() for _cid, meta in meta_list]
    titles = [str(meta.get("title") or "").strip() for _cid, meta in meta_list]
    severities = [str(meta.get("severity") or "").strip() for _cid, meta in meta_list]
    return {
        "loci": loci,
        "titles": titles,
        "severities": severities,
        "authority": "NONE",
        "note": "locus/title/severity/lexical similarity are proposal telemetry only",
    }


def _self_override_present(hypothesis_text: str, group_id: str) -> bool:
    positions = [match.start() for match in re.finditer(re.escape(group_id), hypothesis_text, re.I)]
    return any(
        "anti-absorption override:" in hypothesis_text[pos: pos + 2500].lower()
        for pos in positions
    )


def _classify_decision(
    decision: Mapping[str, Any] | None,
    members: list[str],
) -> tuple[str, str, list[str]]:
    if decision is None:
        return "REJECTED_UNPROVEN", "NONE", ["no independent typed equivalence decision"]
    decision_members = [_norm_id(value) for value in decision.get("members") or []]
    if decision_members != members:
        return "REJECTED_IDENTITY_MISMATCH", "NONE", [
            "typed equivalence decision member denominator/order differs"
        ]
    if str(decision.get("decision") or "").upper() != "EQUIVALENT":
        return "REJECTED_EXPLICIT", "NONE", [
            "proposal did not claim EQUIVALENT"
        ]
    dimensions = decision.get("dimensions")
    if not isinstance(dimensions, Mapping):
        return "REJECTED_INCOMPLETE_PROOF", "NONE", ["dimension proof is absent"]
    missing = [name for name in _DIMENSIONS if name not in dimensions]
    if missing:
        return "REJECTED_INCOMPLETE_PROOF", "NONE", [
            "missing equivalence dimensions: " + ", ".join(missing)
        ]
    mismatched: list[str] = []
    incomplete: list[str] = []
    for name in _DIMENSIONS:
        row = dimensions.get(name)
        if not isinstance(row, Mapping):
            incomplete.append(name)
            continue
        outcome = str(row.get("outcome") or "").upper()
        evidence = [str(value).strip() for value in row.get("evidence_ids") or [] if str(value).strip()]
        if outcome != "SAME":
            mismatched.append(name)
        elif not evidence:
            incomplete.append(name)
    if mismatched:
        return "REJECTED_DIMENSION_MISMATCH", "NONE", [
            "non-equivalent dimensions: " + ", ".join(mismatched)
        ]
    if incomplete:
        return "REJECTED_INCOMPLETE_PROOF", "NONE", [
            "dimensions lack evidence: " + ", ".join(incomplete)
        ]
    return "REJECTED_PROPOSAL_ONLY", "NONE", [
        "equivalence proposal lacks provider-owned independent execution authority"
    ]


def write_chain_grouping_relations(
    scratchpad: Path,
    mapping: Mapping[str, Sequence[str]],
    inventory_meta: Mapping[str, Mapping[str, str]],
    hypothesis_text: str,
) -> int:
    """Write a source-preserving active-relation overlay.

    Returns the number of members newly routed to independent verification.
    A byte-identical, already validated resume returns zero.
    """
    root = Path(scratchpad)
    source_hashes = _source_hashes(root)
    decisions, decision_hash, decision_issues = _load_decisions(root)
    input_core = {
        "source_hashes": source_hashes,
        "proposal_file_sha256": decision_hash,
        "mapping": {
            str(group_id).upper(): [str(member).upper() for member in members]
            for group_id, members in sorted(mapping.items())
        },
    }
    input_digest = _sha256(_canonical_bytes(input_core))
    try:
        existing = load_validated_chain_grouping_relations(root)
        if existing.get("input_digest") == input_digest:
            return 0
    except Exception:
        pass

    candidate_groups: list[tuple[str, list[str]]] = []
    member_occurrences: dict[str, int] = {}
    for raw_group_id, raw_members in sorted(mapping.items()):
        group_id = _norm_id(raw_group_id)
        members = list(dict.fromkeys(
            _norm_id(member) for member in raw_members
            if _norm_id(member)
        ))
        if not group_id or len(members) < 2:
            continue
        candidate_groups.append((group_id, members))
        for member in members:
            member_occurrences[member] = member_occurrences.get(member, 0) + 1

    groups: list[dict[str, Any]] = []
    independent_count = 0
    for group_id, members in candidate_groups:
        status, authority, issues = _classify_decision(decisions.get(group_id), members)
        missing_inventory_members = [
            member for member in members if member not in inventory_meta
        ]
        if missing_inventory_members:
            # The raw mapping is the identity denominator.  Inventory parsing is
            # only proposal telemetry: failure to parse a member cannot shrink a
            # group below the anti-absorption threshold or authorize collapse.
            status = "REJECTED_INCOMPLETE_MEMBER_METADATA"
            authority = "NONE"
            issues.append(
                "inventory metadata missing for mapped members: "
                + ", ".join(missing_inventory_members)
            )
        duplicate_members = [member for member in members if member_occurrences.get(member, 0) > 1]
        if duplicate_members:
            status = "REJECTED_AMBIGUOUS_MEMBERSHIP"
            authority = "NONE"
            issues.append(
                "member participates in multiple active groups: "
                + ", ".join(duplicate_members)
            )
        # v2 cutover invariant: no pre-verification collapse exists.  Even a
        # future classifier regression that returns ACCEPTED cannot silently
        # reactivate grouped work without a new provider-owned arbiter schema.
        if status == "ACCEPTED":
            status = "REJECTED_NO_PROVIDER_AUTHORITY"
            authority = "NONE"
            issues.append("pre-verification equivalence collapse is disabled")
        accepted = False
        member_to_work = {
            member: group_id if accepted else member for member in members
        }
        if not accepted:
            independent_count += len(members)
        meta_list = [
            (member, inventory_meta[member]) for member in members
            if member in inventory_meta
        ]
        groups.append({
            "group_id": group_id,
            "members": members,
            "composition_alias": group_id,
            "missing_inventory_members": missing_inventory_members,
            "active_identity_mode": (
                "EQUIVALENT_GROUP" if accepted else "INDEPENDENT_MEMBERS"
            ),
            "equivalence_status": status,
            "equivalence_authority": authority,
            "equivalence_dimensions": (
                dict((decisions.get(group_id) or {}).get("dimensions") or {})
            ),
            "member_to_work": member_to_work,
            "per_member_evidence_required": True,
            "grouped_proof_replaces_member_proof": False,
            "self_authored_override_present": _self_override_present(
                hypothesis_text, group_id
            ),
            "proposal_signals": _proposal_signals(meta_list),
            "issues": list(dict.fromkeys([*decision_issues, *issues])),
        })

    record_hashes = _line_record_hashes(root, [group_id for group_id, _ in candidate_groups])
    relation: dict[str, Any] = {
        "schema": RELATION_SCHEMA,
        "authority": "DRIVER_APPLIED_RELATION_OVERLAY",
        "input_digest": input_digest,
        "source_hashes": source_hashes,
        "proposal_file_sha256": decision_hash,
        "groups": groups,
        "semantic_source_mutation": "NONE",
        "original_group_cards_retained": True,
    }
    _write_json(root / RELATION_FILE, relation)
    post_hashes = _source_hashes(root)
    if source_hashes != post_hashes:
        raise RuntimeError("P0-W source bytes changed during relation-only repair")

    rejected = [group["group_id"] for group in groups]
    accepted: list[str] = []
    applied: dict[str, Any] = {
        "schema": APPLIED_SCHEMA,
        "state": "APPLIED_RELATION_ONLY" if groups else "NO_GROUP_WORK",
        "input_digest": input_digest,
        "relation_receipt_digest": relation["receipt_digest"],
        "relation_file_sha256": _file_hash(root / RELATION_FILE),
        "proposal_file_sha256": decision_hash,
        "pre_source_hashes": source_hashes,
        "post_source_hashes": post_hashes,
        "accepted_group_decisions": accepted,
        "rejected_group_decisions": rejected,
        "member_to_work": {
            group["group_id"]: group["member_to_work"] for group in groups
        },
        "field_complete_diff": {
            "source_artifacts_compared": ["hypotheses.md", "finding_mapping.md"],
            "affected_record_hashes_pre": record_hashes,
            "affected_record_hashes_post": record_hashes,
            "changed_source_records": [],
            "lost_fields": [],
            "preserved_field_classes": [
                "hypothesis", "narrative", "invariant", "preconditions", "effect",
                "impact", "evidence", "composition", "enabler", "mapping_relation",
            ],
            "all_source_bytes_preserved": True,
        },
        "resume_state": {
            "idempotent_input_digest": input_digest,
            "on_exact_resume": "NO_TRANSFORM_NO_MODEL_WORK",
            "on_drift": "INVALIDATE_OVERLAY_AND_RECOMPUTE",
        },
    }
    _write_json(root / APPLIED_FILE, applied)

    # Keep the historical filename because the chain PhaseIO contract and
    # driver-owned failure markers already bind it.  Ordinary proposal-only
    # relations are telemetry, not client-visible assurance debt.  The later
    # post-report reconciliation is the only layer that can project an exact
    # missing member as a human-review limitation.
    debt_lines = [
        "# Chain Grouping Relation Telemetry (P0-W)", "",
        "Compatibility artifact: original chain group cards remain composition "
        "aliases and every member remains independently addressable. Proposal "
        "status and relation issues below are telemetry only; driver failure "
        "markers may also be appended here. Client-visible assurance limitations "
        "come only from chain_grouping_assurance_reconciliation.json after exact "
        "verifier and report-delivery reconciliation.", "",
        "| Group | Proposal Status | Active Mode | Members | Telemetry |",
        "|---|---|---|---|---|",
    ]
    for group in groups:
        if group["equivalence_status"] == "ACCEPTED":
            continue
        debt_lines.append(
            f"| {group['group_id']} | {group['equivalence_status']} | "
            f"INDEPENDENT_MEMBERS | {', '.join(group['members'])} | "
            f"{'; '.join(group['issues'])} |"
        )
    if len(debt_lines) == 6:
        debt_lines.append("| (none) | CLEAN | NO_GROUP_WORK | - | - |")
    _atomic_write(root / DEBT_FILE, ("\n".join(debt_lines) + "\n").encode("utf-8"))
    return independent_count


def load_validated_chain_grouping_relations(scratchpad: Path) -> dict[str, Any]:
    """Return relation overlay only when receipt, sources, and denominator bind."""
    root = Path(scratchpad)
    relation = _read_json(root / RELATION_FILE)
    _validate_digest(relation, "chain grouping relation")
    if relation.get("schema") != RELATION_SCHEMA:
        raise ValueError("unsupported chain grouping relation schema")
    if relation.get("authority") != "DRIVER_APPLIED_RELATION_OVERLAY":
        raise ValueError("chain grouping relation authority mismatch")
    if relation.get("source_hashes") != _source_hashes(root):
        raise ValueError("chain grouping relation source bytes changed")
    if relation.get("proposal_file_sha256") != _file_hash(root / DECISION_FILE):
        raise ValueError("chain grouping proposal bytes changed")

    groups = relation.get("groups")
    if not isinstance(groups, list):
        raise TypeError("chain grouping relation groups must be an array")
    seen_groups: set[str] = set()
    for group in groups:
        if not isinstance(group, dict):
            raise TypeError("chain grouping relation group must be an object")
        group_id = _norm_id(group.get("group_id"))
        members = [_norm_id(value) for value in group.get("members") or []]
        if not group_id or group_id in seen_groups or len(members) < 2:
            raise ValueError("chain grouping relation group identity is invalid")
        seen_groups.add(group_id)
        if any(not member for member in members) or len(members) != len(set(members)):
            raise ValueError(f"{group_id} relation member denominator is invalid")
        missing_inventory_members = group.get("missing_inventory_members")
        if (
            not isinstance(missing_inventory_members, list)
            or any(member not in members for member in missing_inventory_members)
            or len(missing_inventory_members) != len(set(missing_inventory_members))
        ):
            raise ValueError(f"{group_id} missing-metadata denominator is invalid")
        mode = group.get("active_identity_mode")
        mapping = group.get("member_to_work")
        if not isinstance(mapping, dict) or set(mapping) != set(members):
            raise ValueError(f"{group_id} member-to-work mapping is incomplete")
        if mode == "EQUIVALENT_GROUP":
            raise ValueError(
                f"{group_id} pre-verification equivalence collapse is disabled "
                "until provider-owned independent arbiter authority exists"
            )
        elif mode == "INDEPENDENT_MEMBERS":
            if any(mapping[member] != member for member in members):
                raise ValueError(f"{group_id} independent work mapping drift")
        else:
            raise ValueError(f"{group_id} active identity mode is invalid")
        if group.get("per_member_evidence_required") is not True:
            raise ValueError(f"{group_id} per-member proof requirement missing")
        if group.get("grouped_proof_replaces_member_proof") is not False:
            raise ValueError(f"{group_id} grouped proof gained member authority")

    applied = _read_json(root / APPLIED_FILE)
    _validate_digest(applied, "chain anti-absorption applied")
    if applied.get("schema") != APPLIED_SCHEMA:
        raise ValueError("unsupported chain anti-absorption applied schema")
    if applied.get("relation_receipt_digest") != relation.get("receipt_digest"):
        raise ValueError("chain applied receipt relation binding mismatch")
    if applied.get("relation_file_sha256") != _file_hash(root / RELATION_FILE):
        raise ValueError("chain applied receipt relation bytes changed")
    if applied.get("input_digest") != relation.get("input_digest"):
        raise ValueError("chain applied receipt input binding mismatch")
    if applied.get("pre_source_hashes") != relation.get("source_hashes"):
        raise ValueError("chain applied receipt pre-source mismatch")
    if applied.get("post_source_hashes") != relation.get("source_hashes"):
        raise ValueError("chain applied receipt post-source mismatch")
    diff = applied.get("field_complete_diff")
    if (
        not isinstance(diff, dict)
        or diff.get("lost_fields") != []
        or diff.get("changed_source_records") != []
        or diff.get("all_source_bytes_preserved") is not True
    ):
        raise ValueError("chain applied receipt does not prove lossless repair")
    return relation


def apply_chain_grouping_projection(
    scratchpad: Path,
    mapping: Mapping[str, Sequence[str]],
    *,
    include_group_aliases: bool = False,
    independently_bound_group_ids: Sequence[str] = (),
) -> dict[str, list[str]]:
    """Overlay active work identity without mutating the raw relation files."""
    raw_projected = {
        str(group_id): list(dict.fromkeys(str(member) for member in members))
        for group_id, members in mapping.items()
    }
    # Multi-member Markdown groups are never active by default.  Start from
    # independently addressable singleton relations and add a group back only
    # after a validated typed equivalence decision.  Lookup-only consumers may
    # explicitly request the raw aliases, but queue/dedup consumers cannot.
    independently_bound = {str(value) for value in independently_bound_group_ids}
    projected = {
        group_id: members
        for group_id, members in raw_projected.items()
        if len(members) < 2
        or include_group_aliases
        or group_id in independently_bound
    }
    try:
        relation = load_validated_chain_grouping_relations(scratchpad)
    except Exception:
        return projected
    for group in relation["groups"]:
        group_id = str(group["group_id"])
        members = [str(member) for member in group["members"]]
        if group["active_identity_mode"] == "EQUIVALENT_GROUP":
            projected[group_id] = members
        else:
            projected.pop(group_id, None)
            if include_group_aliases:
                projected[group_id] = members
    return projected
