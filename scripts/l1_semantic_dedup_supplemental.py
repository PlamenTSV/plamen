"""Recall-safe L1 supplemental semantic-dedup derivation and staging.

This module deliberately owns no canonical pipeline paths.  It has two jobs:

* deterministically derive a typed, low-authority proposal artifact from the
  complete candidate-pair denominator; and
* apply the model and supplemental proposal stages inside a caller-supplied
  staging directory, returning exact postimage bytes and projection inputs.

The caller remains responsible for PhaseIO authority and publication.  A
supplemental error degrades to the already-authorized primary result.  Invalid
or tampered proposal authority raises before a staging directory is touched.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import itertools
import json
from pathlib import Path
import re
import shutil
from typing import Any, Iterable, Mapping, Sequence

import plamen_mechanical as _mechanical
import semantic_dedup_authority as _authority


PROPOSAL_SCHEMA = "plamen.semantic_dedup_supplemental_proposals.v1"
PROPOSAL_PATH = "semantic_dedup_supplemental_proposals.json"
SOURCE_PATHS = (
    "findings_inventory.md",
    "dedup_decisions.md",
    "dedup_candidate_pairs.md",
    "dedup_candidate_pairs_full.md",
)
SIGNAL_KIND = "EXACT_LOCATION_SAME_SEVERITY"
ACTIVE = "ACTIVE"
DEGRADED_PRIMARY_ONLY = "DEGRADED_PRIMARY_ONLY"
APPLIED = "APPLIED"

_ID_RE = re.compile(r"\b((?:INV|F)-\d+)\b", re.IGNORECASE)
_LOCATION_SIGNAL_RE = re.compile(
    r"location\s+overlap.*?"
    r"L(\d+)\s*-\s*(\d+)\s+vs\s+L(\d+)\s*-\s*(\d+)",
    re.IGNORECASE,
)
_HEX64_RE = re.compile(r"[0-9a-f]{64}")
_PROPOSAL_ID_RE = re.compile(r"DPROP-[0-9A-F]{20}")
_AGGREGATE_SOURCE_ID_THRESHOLD = 4

# Bind these existing, battle-tested losslessness helpers once.  Keeping the
# aliases local also makes failure/degradation behavior directly injectable in
# focused tests without mutating the shared module.
_parse_finding_info = _mechanical._dedup_parse_finding_info
_resolve_survivor = _mechanical._resolve_dedup_survivor
_apply_merges_to_inventory = _mechanical._apply_merges_to_inventory

__all__ = [
    "ACTIVE",
    "APPLIED",
    "DEGRADED_PRIMARY_ONLY",
    "PROPOSAL_PATH",
    "PROPOSAL_SCHEMA",
    "SIGNAL_KIND",
    "SOURCE_PATHS",
    "apply_supplemental_in_staging",
    "derive_degraded_supplemental_proposals",
    "derive_supplemental_proposals",
    "validate_supplemental_proposals",
]


class SupplementalDedupError(RuntimeError):
    """Supplemental proposal authority is malformed or inconsistent."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return _sha(_canonical_json(value).rstrip(b"\n"))


def _authority_digest(value: Any) -> str:
    return _sha(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _as_bytes(name: str, value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes")
    return bytes(value)


def _strict_text(name: str, raw: bytes) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise SupplementalDedupError(f"{name} is not strict UTF-8") from exc


def _normalize_id(value: str) -> str:
    match = _ID_RE.search(str(value or ""))
    return match.group(1).upper() if match else ""


def _id_order(value: str) -> tuple[str, int, str]:
    normalized = _normalize_id(value)
    match = re.search(r"\d+", normalized)
    prefix = normalized.split("-", 1)[0] if normalized else ""
    return prefix, int(match.group(0)) if match else 0, normalized


def _source_artifacts(
    *,
    inventory_raw: bytes,
    decisions_raw: bytes,
    candidate_pairs_raw: bytes,
    candidate_pairs_full_raw: bytes,
) -> dict[str, dict[str, Any]]:
    rows = {
        "findings_inventory.md": inventory_raw,
        "dedup_decisions.md": decisions_raw,
        "dedup_candidate_pairs.md": candidate_pairs_raw,
        "dedup_candidate_pairs_full.md": candidate_pairs_full_raw,
    }
    return {
        name: {"sha256": _sha(raw), "size_bytes": len(raw)}
        for name, raw in rows.items()
    }


def _finalize_proposal_payload(core: Mapping[str, Any]) -> bytes:
    payload = dict(core)
    payload["artifact_digest"] = _digest(payload)
    return _canonical_json(payload)


def _proposal_id(row: Mapping[str, Any]) -> str:
    identity = {
        "action": row["action"],
        "absorbed_id": row["absorbed_id"],
        "signal_kind": row["signal_kind"],
        "source_pair_digest": row["source_pair_digest"],
        "survivor_id": row["survivor_id"],
    }
    return "DPROP-" + _digest(identity)[:20].upper()


def _pair_rows(raw: bytes, *, source_name: str) -> list[dict[str, Any]]:
    text = _strict_text(source_name, raw)
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 5:
            continue
        id_a = _normalize_id(cells[0])
        id_b = _normalize_id(cells[1])
        if not id_a or not id_b or id_a == id_b:
            continue
        try:
            title_score = Decimal(cells[2])
        except (InvalidOperation, ValueError):
            title_score = Decimal("-1")
        if not title_score.is_finite():
            title_score = Decimal("-1")
        pair_core = {
            "finding_ids": sorted((id_a, id_b), key=_id_order),
            "same_severity_claim": cells[4].strip().casefold(),
            "signal": re.sub(r"\s+", " ", cells[3]).strip(),
            "title_score": format(title_score, "f"),
        }
        rows.append(
            {
                "id_a": id_a,
                "id_b": id_b,
                "line_number": line_number,
                "same_severity": cells[4].strip().casefold() == "yes",
                "signal": cells[3],
                "source_pair_digest": _digest(pair_core),
                "title_score": title_score,
            }
        )
    return rows


def _unordered_pair(a: str, b: str) -> tuple[str, str]:
    return tuple(sorted((_normalize_id(a), _normalize_id(b)), key=_id_order))  # type: ignore[return-value]


def _model_evaluated_pairs(
    decisions_text: str,
) -> set[tuple[str, str]]:
    evaluated: set[tuple[str, str]] = set()
    for event in _authority.parse_dedup_proposals(decisions_text):
        members = sorted(
            {
                _normalize_id(str(member))
                for member in event.get("member_ids", [])
                if _normalize_id(str(member))
            },
            key=_id_order,
        )
        # A one-member KEEP is not a pair disposition.  Pair/group KEEP and all
        # MERGE clusters are model-evaluated relationships.
        if event.get("action") == "MERGE" or len(members) > 1:
            evaluated.update(
                _unordered_pair(left, right)
                for left, right in itertools.combinations(members, 2)
            )
    for match in re.finditer(
        r"(?im)^\s*#{2,6}\s+GROUP:\s+\[?((?:INV|F)-\d+)\]?"
        r"\s+represents\s+(.+?)\s*$",
        decisions_text,
    ):
        members = [_normalize_id(match.group(1))]
        members.extend(_normalize_id(item) for item in _ID_RE.findall(match.group(2)))
        unique = sorted({item for item in members if item}, key=_id_order)
        evaluated.update(
            _unordered_pair(left, right)
            for left, right in itertools.combinations(unique, 2)
        )
    return evaluated


def _exact_location_signal(signal: str) -> bool:
    match = _LOCATION_SIGNAL_RE.search(str(signal or ""))
    if match is None:
        return False
    a0, a1, b0, b1 = match.groups()
    return a0 == b0 and a1 == b1


def _aggregate(record: Mapping[str, Any]) -> bool:
    return len(set(record.get("source_ids") or ())) > _AGGREGATE_SOURCE_ID_THRESHOLD


def derive_supplemental_proposals(
    *,
    inventory_raw: bytes,
    decisions_raw: bytes,
    candidate_pairs_raw: bytes,
    candidate_pairs_full_raw: bytes,
    run_id: str,
) -> bytes:
    """Derive conservative supplemental proposals from exact input bytes.

    Only a full-pair row with exact location endpoints, an affirmative
    same-severity claim, matching parsed severities, title similarity >= 0.5,
    and a mechanically provable survivor superset can become a proposal.
    Every pair already present in the live denominator or explicitly evaluated
    by the model is excluded.
    """

    inventory_raw = _as_bytes("inventory_raw", inventory_raw)
    decisions_raw = _as_bytes("decisions_raw", decisions_raw)
    candidate_pairs_raw = _as_bytes("candidate_pairs_raw", candidate_pairs_raw)
    candidate_pairs_full_raw = _as_bytes(
        "candidate_pairs_full_raw", candidate_pairs_full_raw
    )
    run = str(run_id or "").strip()
    if not run:
        raise SupplementalDedupError("run_id is absent")

    inventory_text = _strict_text("findings_inventory.md", inventory_raw)
    decisions_text = _strict_text("dedup_decisions.md", decisions_raw)
    finfo = {
        _normalize_id(finding_id): dict(record)
        for finding_id, record in _parse_finding_info(inventory_text).items()
        if _normalize_id(finding_id)
    }
    typed_records = _authority.extract_finding_records(inventory_text)
    if not finfo:
        raise SupplementalDedupError("inventory has no parseable finding identities")

    live_pairs = {
        _unordered_pair(row["id_a"], row["id_b"])
        for row in _pair_rows(
            candidate_pairs_raw, source_name="dedup_candidate_pairs.md"
        )
    }
    excluded_pairs = live_pairs | _model_evaluated_pairs(decisions_text)
    candidates: list[dict[str, Any]] = []
    for row in _pair_rows(
        candidate_pairs_full_raw,
        source_name="dedup_candidate_pairs_full.md",
    ):
        id_a = row["id_a"]
        id_b = row["id_b"]
        pair = _unordered_pair(id_a, id_b)
        if pair in excluded_pairs:
            continue
        if (
            not row["same_severity"]
            or row["title_score"] < Decimal("0.5")
            or not _exact_location_signal(row["signal"])
        ):
            continue
        record_a = finfo.get(id_a)
        record_b = finfo.get(id_b)
        typed_a = typed_records.get(id_a)
        typed_b = typed_records.get(id_b)
        if (
            record_a is None
            or record_b is None
            or typed_a is None
            or typed_b is None
        ):
            continue
        explicit_a = typed_a.get("fields", {}).get("severity")
        explicit_b = typed_b.get("fields", {}).get("severity")
        if not explicit_a or not explicit_b:
            continue
        severity_a = str(record_a.get("severity") or "").casefold()
        severity_b = str(record_b.get("severity") or "").casefold()
        if not severity_a or severity_a != severity_b:
            continue
        if _aggregate(record_a) or _aggregate(record_b):
            continue
        # The deterministic direction hint mirrors the old supplemental pass;
        # the superset resolver is authoritative and may flip it.
        ordered = sorted((id_a, id_b), key=_id_order)
        proposed_keep, proposed_absorb = ordered[0], ordered[1]
        resolved = _resolve_survivor(
            id_a,
            id_b,
            proposed_absorb,
            proposed_keep,
            finfo,
        )
        if resolved is None:
            continue
        absorbed, survivor = resolved
        proposal = {
            "action": "MERGE",
            "absorbed_id": absorbed,
            "signal_kind": SIGNAL_KIND,
            "source_pair_digest": row["source_pair_digest"],
            "survivor_id": survivor,
        }
        proposal["proposal_id"] = _proposal_id(proposal)
        candidates.append(proposal)

    candidates.sort(
        key=lambda row: (
            _id_order(str(row["survivor_id"])),
            _id_order(str(row["absorbed_id"])),
            str(row["source_pair_digest"]),
        )
    )
    # Keep the mechanical stage pairwise and order-independent.  Ambiguous
    # components remain independently live for model verification.
    claimed: set[str] = set()
    proposals: list[dict[str, Any]] = []
    for proposal in candidates:
        pair_members = {
            str(proposal["absorbed_id"]),
            str(proposal["survivor_id"]),
        }
        if claimed & pair_members:
            continue
        claimed.update(pair_members)
        proposals.append(proposal)

    core = {
        "schema_version": PROPOSAL_SCHEMA,
        "run_id": run,
        "phase": "semantic_dedup",
        "state": ACTIVE,
        "source_artifacts": _source_artifacts(
            inventory_raw=inventory_raw,
            decisions_raw=decisions_raw,
            candidate_pairs_raw=candidate_pairs_raw,
            candidate_pairs_full_raw=candidate_pairs_full_raw,
        ),
        "proposals": proposals,
        "proposal_set_digest": _digest(proposals),
        "debt": [],
    }
    return _finalize_proposal_payload(core)


def derive_degraded_supplemental_proposals(
    *,
    inventory_raw: bytes,
    decisions_raw: bytes,
    candidate_pairs_raw: bytes,
    candidate_pairs_full_raw: bytes,
    run_id: str,
    debt: str | Mapping[str, Any] | Sequence[Any],
) -> bytes:
    """Build an authenticated empty proposal set for repair-then-degrade."""

    inventory_raw = _as_bytes("inventory_raw", inventory_raw)
    decisions_raw = _as_bytes("decisions_raw", decisions_raw)
    candidate_pairs_raw = _as_bytes("candidate_pairs_raw", candidate_pairs_raw)
    candidate_pairs_full_raw = _as_bytes(
        "candidate_pairs_full_raw", candidate_pairs_full_raw
    )
    run = str(run_id or "").strip()
    if not run:
        raise SupplementalDedupError("run_id is absent")
    if isinstance(debt, Mapping):
        debt_rows: list[Any] = [dict(debt)]
    elif isinstance(debt, str):
        debt_rows = [{"code": "SUPPLEMENTAL_DERIVATION_FAILED", "detail": debt}]
    elif isinstance(debt, Sequence):
        debt_rows = list(debt)
    else:
        debt_rows = [{"code": "SUPPLEMENTAL_DERIVATION_FAILED", "detail": str(debt)}]
    if not debt_rows:
        debt_rows = [{"code": "SUPPLEMENTAL_DERIVATION_FAILED", "detail": "unspecified"}]
    core = {
        "schema_version": PROPOSAL_SCHEMA,
        "run_id": run,
        "phase": "semantic_dedup",
        "state": DEGRADED_PRIMARY_ONLY,
        "source_artifacts": _source_artifacts(
            inventory_raw=inventory_raw,
            decisions_raw=decisions_raw,
            candidate_pairs_raw=candidate_pairs_raw,
            candidate_pairs_full_raw=candidate_pairs_full_raw,
        ),
        "proposals": [],
        "proposal_set_digest": _digest([]),
        "debt": debt_rows,
    }
    return _finalize_proposal_payload(core)


def validate_supplemental_proposals(
    proposal_raw: bytes,
    *,
    inventory_raw: bytes,
    decisions_raw: bytes,
    run_id: str,
) -> dict[str, Any]:
    """Validate exact canonical proposal authority before any staging writes."""

    proposal_raw = _as_bytes("proposal_raw", proposal_raw)
    inventory_raw = _as_bytes("inventory_raw", inventory_raw)
    decisions_raw = _as_bytes("decisions_raw", decisions_raw)
    try:
        payload = json.loads(_strict_text(PROPOSAL_PATH, proposal_raw))
    except json.JSONDecodeError as exc:
        raise SupplementalDedupError("proposal artifact is invalid JSON") from exc
    if not isinstance(payload, dict) or proposal_raw != _canonical_json(payload):
        raise SupplementalDedupError("proposal artifact is not exact canonical JSON")
    expected_keys = {
        "artifact_digest",
        "debt",
        "phase",
        "proposal_set_digest",
        "proposals",
        "run_id",
        "schema_version",
        "source_artifacts",
        "state",
    }
    if set(payload) != expected_keys:
        raise SupplementalDedupError("proposal artifact field set is invalid")
    if payload.get("schema_version") != PROPOSAL_SCHEMA:
        raise SupplementalDedupError("proposal artifact schema mismatch")
    if payload.get("phase") != "semantic_dedup":
        raise SupplementalDedupError("proposal artifact phase mismatch")
    if payload.get("run_id") != str(run_id or "").strip():
        raise SupplementalDedupError("proposal artifact run authority mismatch")
    if payload.get("state") not in {ACTIVE, DEGRADED_PRIMARY_ONLY}:
        raise SupplementalDedupError("proposal artifact state is invalid")
    if not isinstance(payload.get("debt"), list):
        raise SupplementalDedupError("proposal artifact debt is malformed")
    if payload["state"] == DEGRADED_PRIMARY_ONLY and not payload["debt"]:
        raise SupplementalDedupError("degraded proposal artifact has no review debt")
    sources = payload.get("source_artifacts")
    if not isinstance(sources, dict) or set(sources) != set(SOURCE_PATHS):
        raise SupplementalDedupError("proposal source denominator is incomplete")
    for name, row in sources.items():
        if not isinstance(row, dict) or set(row) != {"sha256", "size_bytes"}:
            raise SupplementalDedupError(f"{name}: proposal source binding is malformed")
        if (
            not _HEX64_RE.fullmatch(str(row.get("sha256") or ""))
            or not isinstance(row.get("size_bytes"), int)
            or int(row["size_bytes"]) < 0
        ):
            raise SupplementalDedupError(f"{name}: proposal source binding is invalid")
    for name, raw in (
        ("findings_inventory.md", inventory_raw),
        ("dedup_decisions.md", decisions_raw),
    ):
        if sources[name] != {"sha256": _sha(raw), "size_bytes": len(raw)}:
            raise SupplementalDedupError(f"{name}: proposal source authority drift")
    proposals = payload.get("proposals")
    if not isinstance(proposals, list):
        raise SupplementalDedupError("proposal set is malformed")
    if payload["state"] == DEGRADED_PRIMARY_ONLY and proposals:
        raise SupplementalDedupError("degraded proposal artifact is not empty")
    if payload.get("proposal_set_digest") != _digest(proposals):
        raise SupplementalDedupError("proposal set digest mismatch")
    claimed: set[str] = set()
    proposal_ids: set[str] = set()
    for proposal in proposals:
        if not isinstance(proposal, dict) or set(proposal) != {
            "action",
            "absorbed_id",
            "proposal_id",
            "signal_kind",
            "source_pair_digest",
            "survivor_id",
        }:
            raise SupplementalDedupError("proposal row field set is invalid")
        absorbed = _normalize_id(str(proposal.get("absorbed_id") or ""))
        survivor = _normalize_id(str(proposal.get("survivor_id") or ""))
        if (
            proposal.get("action") != "MERGE"
            or proposal.get("signal_kind") != SIGNAL_KIND
            or not absorbed
            or not survivor
            or absorbed == survivor
            or proposal["absorbed_id"] != absorbed
            or proposal["survivor_id"] != survivor
            or not _HEX64_RE.fullmatch(str(proposal.get("source_pair_digest") or ""))
            or not _PROPOSAL_ID_RE.fullmatch(str(proposal.get("proposal_id") or ""))
            or proposal.get("proposal_id") != _proposal_id(proposal)
        ):
            raise SupplementalDedupError("proposal row is invalid")
        if proposal["proposal_id"] in proposal_ids:
            raise SupplementalDedupError("proposal identities are duplicated")
        proposal_ids.add(proposal["proposal_id"])
        if claimed & {absorbed, survivor}:
            raise SupplementalDedupError("proposal pairs are not disjoint")
        claimed.update((absorbed, survivor))
    core = dict(payload)
    claimed_artifact_digest = str(core.pop("artifact_digest", ""))
    if (
        not _HEX64_RE.fullmatch(claimed_artifact_digest)
        or claimed_artifact_digest != _digest(core)
    ):
        raise SupplementalDedupError("proposal artifact digest mismatch")
    return payload


def _read_authority_receipt(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        payload = json.loads(raw)
    except Exception as exc:
        raise SupplementalDedupError(f"{path.name}: invalid authority receipt") from exc
    if raw != _authority.canonical_json_bytes(payload):
        raise SupplementalDedupError(f"{path.name}: non-canonical authority receipt")
    # This validator is the same gate used by load_applied_aliases.
    _authority._validate_payload(payload)
    return payload


def _ensure_primary(
    work: Path,
    *,
    inventory_text: str,
    decisions_text: str,
) -> tuple[str, dict[str, Any]]:
    inventory_path = work / "findings_inventory.md"
    decisions_path = work / "dedup_decisions.md"
    deduped_path = work / "findings_inventory_deduped.md"
    inventory_path.write_text(inventory_text, encoding="utf-8", newline="")
    decisions_path.write_text(decisions_text, encoding="utf-8", newline="")
    deduped_path.write_text(inventory_text, encoding="utf-8", newline="")
    _mechanical.apply_llm_dedup_decisions(work, "semantic_dedup")
    if not deduped_path.is_file():
        deduped_path.write_text(inventory_text, encoding="utf-8", newline="")
    primary_path = work / _authority.PRIMARY_RECEIPT_NAME
    if not primary_path.is_file():
        # Receipt authority binds exact bytes.  ``Path.read_text`` performs
        # universal-newline translation on Windows and can therefore hash a
        # different string than the file that the primary reducer wrote
        # (GROUP annotation writes historically exposed CRLF/CRCRLF here).
        output_text = deduped_path.read_bytes().decode(
            "utf-8", errors="strict"
        )
        _authority.write_applied_receipt(
            work,
            phase_name="semantic_dedup",
            application_kind="PRIMARY",
            proposal_text=decisions_text,
            proposals=_authority.parse_dedup_proposals(decisions_text),
            input_text=inventory_text,
            output_text=output_text,
            applied_merges=(),
            rejection_reasons={},
        )
    output_text = deduped_path.read_bytes().decode(
        "utf-8", errors="strict"
    )
    _authority.load_applied_aliases(work, canonical_text=output_text)
    return output_text, _read_authority_receipt(primary_path)


def _authority_proposals(
    rows: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "proposal_id": str(row["proposal_id"]),
            "action": "MERGE",
            "member_ids": sorted(
                (str(row["absorbed_id"]), str(row["survivor_id"])),
                key=_id_order,
            ),
            "requested_survivor": str(row["survivor_id"]),
            "sources": ["DRIVER_SUPPLEMENTAL_EXACT_LOCATION"],
        }
        for row in rows
    ]


def _supplemental_stage_degraded(
    *,
    proposal_raw: bytes,
    proposal_payload: Mapping[str, Any],
    primary_receipt: Mapping[str, Any],
    debt: Sequence[Any],
) -> dict[str, Any]:
    input_artifact = dict(primary_receipt["output_artifact"])
    stage = {
        "schema_version": _authority.SCHEMA_VERSION,
        "phase_name": "semantic_dedup",
        "application_kind": "SUPPLEMENTAL",
        "state": DEGRADED_PRIMARY_ONLY,
        "proposal_artifact": {
            "path": PROPOSAL_PATH,
            "sha256": _sha(proposal_raw),
            "proposal_count": 0,
            "proposal_digest": _authority_digest([]),
        },
        "input_artifact": input_artifact,
        "output_artifact": dict(input_artifact),
        "proposals": [],
        "decisions": [],
        "accepted_absorbed_ids": [],
        "rejected_member_ids": [],
        "identity_delta": {"removed_ids": [], "added_ids": []},
        "postconditions": {
            "accepted_equals_identity_delta": True,
            "all_accepted_survivors_live": True,
            "all_rejected_input_members_live": True,
            "field_complete": True,
            "conflicts_applied": [],
        },
        "debt": list(proposal_payload.get("debt") or ()) + list(debt),
    }
    stage["stage_receipt_sha256"] = _authority_digest(stage)
    return stage


def _combined_receipt(
    *,
    decisions_raw: bytes,
    proposal_raw: bytes,
    primary: Mapping[str, Any],
    supplemental: Mapping[str, Any],
) -> dict[str, Any]:
    applied_supplemental = supplemental.get("state") == APPLIED
    stage_receipts = [primary, supplemental]
    proposals: list[dict[str, Any]] = list(primary.get("proposals") or ())
    decisions: list[dict[str, Any]] = list(primary.get("decisions") or ())
    if applied_supplemental:
        proposals.extend(list(supplemental.get("proposals") or ()))
        decisions.extend(list(supplemental.get("decisions") or ()))
    input_artifact = dict(primary["input_artifact"])
    output_artifact = dict(supplemental["output_artifact"])
    input_ids = set(input_artifact["finding_ids"])
    output_ids = set(output_artifact["finding_ids"])
    accepted = sorted(input_ids - output_ids, key=_id_order)
    accepted_set = set(accepted)
    # A member rejected at one stage but accepted at the other is represented
    # by its accepted terminal disposition.  Each full stage remains available
    # under application_stages for provenance.
    decisions = [
        dict(row)
        for row in decisions
        if not (
            row.get("status") == "REJECTED"
            and _normalize_id(str(row.get("member_id") or "")) in accepted_set
        )
    ]
    rejected = sorted(
        {
            _normalize_id(str(row.get("member_id") or ""))
            for row in decisions
            if row.get("status") == "REJECTED"
            and _normalize_id(str(row.get("member_id") or ""))
        },
        key=_id_order,
    )
    framed_proposals = (
        len(decisions_raw).to_bytes(8, "big")
        + decisions_raw
        + len(proposal_raw).to_bytes(8, "big")
        + proposal_raw
    )
    payload: dict[str, Any] = {
        "schema_version": _authority.SCHEMA_VERSION,
        "phase_name": "semantic_dedup",
        "application_kind": "PRIMARY",
        "proposal_artifact": {
            "path": "dedup_decisions.md+" + PROPOSAL_PATH,
            "sha256": _sha(framed_proposals),
            "proposal_count": len(proposals),
            "proposal_digest": _authority_digest(proposals),
        },
        "input_artifact": input_artifact,
        "output_artifact": output_artifact,
        "proposals": proposals,
        "decisions": decisions,
        "accepted_absorbed_ids": accepted,
        "rejected_member_ids": rejected,
        "identity_delta": {
            "removed_ids": accepted,
            "added_ids": sorted(output_ids - input_ids, key=_id_order),
        },
        "postconditions": {
            "accepted_equals_identity_delta": True,
            "all_accepted_survivors_live": all(
                _normalize_id(str(row.get("actual_survivor") or "")) in output_ids
                for row in decisions
                if row.get("status") == "ACCEPTED"
            ),
            "all_rejected_input_members_live": all(
                _normalize_id(str(row.get("member_id") or "")) not in input_ids
                or _normalize_id(str(row.get("member_id") or "")) in output_ids
                for row in decisions
                if row.get("status") == "REJECTED"
            ),
            "field_complete": all(
                bool(row.get("field_preservation", {}).get("passed"))
                for row in decisions
                if row.get("status") == "ACCEPTED"
            ),
            "conflicts_applied": [],
        },
        "application_stages": [
            {**dict(stage_receipts[0]), "state": APPLIED},
            dict(stage_receipts[1]),
        ],
        "supplemental_state": str(supplemental.get("state") or ""),
        "supplemental_debt": list(supplemental.get("debt") or ()),
    }
    core = dict(payload)
    payload["receipt_sha256"] = _authority_digest(core)
    _authority._validate_payload(payload)
    return payload


def _aliases_from_receipt(
    receipt: Mapping[str, Any],
) -> dict[str, dict[str, str]]:
    aliases: dict[str, dict[str, str]] = {}
    for decision in receipt.get("decisions") or ():
        if decision.get("status") != "ACCEPTED":
            continue
        member = _normalize_id(str(decision.get("member_id") or ""))
        survivor = _normalize_id(str(decision.get("actual_survivor") or ""))
        if member and survivor:
            aliases[member] = {
                "survivor": survivor,
                "coupled": "field-complete-preserved",
            }
    return aliases


def apply_supplemental_in_staging(
    *,
    staging_dir: Path,
    inventory_raw: bytes,
    model_decisions_raw: bytes,
    proposal_raw: bytes,
    run_id: str,
) -> dict[str, Any]:
    """Apply primary+supplemental dedup without touching caller-owned files.

    Proposal authority is validated before ``staging_dir`` is created.  The
    returned bytes are publication candidates only; this function never writes
    any canonical pipeline path.
    """

    inventory_raw = _as_bytes("inventory_raw", inventory_raw)
    model_decisions_raw = _as_bytes("model_decisions_raw", model_decisions_raw)
    proposal_raw = _as_bytes("proposal_raw", proposal_raw)
    inventory_text = _strict_text("findings_inventory.md", inventory_raw)
    decisions_text = _strict_text("dedup_decisions.md", model_decisions_raw)
    proposal = validate_supplemental_proposals(
        proposal_raw,
        inventory_raw=inventory_raw,
        decisions_raw=model_decisions_raw,
        run_id=run_id,
    )

    stage_root = Path(staging_dir)
    if stage_root.exists() and (stage_root.is_symlink() or not stage_root.is_dir()):
        raise SupplementalDedupError("staging_dir is not a real directory")
    stage_root.mkdir(parents=True, exist_ok=True)
    generation = _sha(
        inventory_raw
        + len(model_decisions_raw).to_bytes(8, "big")
        + model_decisions_raw
        + len(proposal_raw).to_bytes(8, "big")
        + proposal_raw
    )
    work = stage_root / ("l1_semantic_dedup_" + generation[:24])
    try:
        work.mkdir()
    except FileExistsError as exc:
        raise SupplementalDedupError("staging generation already exists") from exc

    primary_text, primary_receipt = _ensure_primary(
        work,
        inventory_text=inventory_text,
        decisions_text=decisions_text,
    )
    supplemental_state = APPLIED
    supplemental_debt: list[Any] = []
    final_text = primary_text
    supplemental_receipt: dict[str, Any]

    if proposal["state"] == DEGRADED_PRIMARY_ONLY:
        supplemental_state = DEGRADED_PRIMARY_ONLY
        supplemental_receipt = _supplemental_stage_degraded(
            proposal_raw=proposal_raw,
            proposal_payload=proposal,
            primary_receipt=primary_receipt,
            debt=(),
        )
        supplemental_debt = list(supplemental_receipt.get("debt") or ())
    else:
        try:
            finfo = {
                _normalize_id(finding_id): dict(record)
                for finding_id, record in _parse_finding_info(primary_text).items()
                if _normalize_id(finding_id)
            }
            active_ids = set(finfo)
            protected_primary_survivors = {
                _normalize_id(str(row.get("actual_survivor") or ""))
                for row in primary_receipt.get("decisions") or ()
                if row.get("status") == "ACCEPTED"
            }
            accepted_merges: list[tuple[str, str, str]] = []
            rejection_reasons: dict[str, str] = {}
            for row in proposal["proposals"]:
                absorbed = str(row["absorbed_id"])
                survivor = str(row["survivor_id"])
                if absorbed not in active_ids or survivor not in active_ids:
                    rejection_reasons[absorbed] = "MEMBER_NOT_IN_PRIMARY_OUTPUT"
                    continue
                absorb_info = finfo[absorbed]
                survivor_info = finfo[survivor]
                if (
                    str(absorb_info.get("severity") or "").casefold()
                    != str(survivor_info.get("severity") or "").casefold()
                ):
                    rejection_reasons[absorbed] = "SAME_SEVERITY_RECHECK_FAILED"
                    continue
                if _aggregate(absorb_info) or _aggregate(survivor_info):
                    rejection_reasons[absorbed] = "AGGREGATE_GUARD_REJECTED"
                    continue
                resolved = _resolve_survivor(
                    absorbed,
                    survivor,
                    absorbed,
                    survivor,
                    finfo,
                )
                if resolved != (absorbed, survivor):
                    rejection_reasons[absorbed] = "SUPERSET_RECHECK_REJECTED"
                    continue
                if absorbed in protected_primary_survivors:
                    rejection_reasons[absorbed] = "PRIMARY_ALIAS_SURVIVOR_PROTECTED"
                    continue
                accepted_merges.append(
                    (absorbed, survivor, SIGNAL_KIND)
                )

            supplemental_path = work / "findings_inventory_supplemental.md"
            supplemental_path.write_text(primary_text, encoding="utf-8", newline="")
            if accepted_merges:
                _apply_merges_to_inventory(
                    supplemental_path,
                    supplemental_path,
                    accepted_merges,
                    finfo,
                )
            candidate_text = supplemental_path.read_text(
                encoding="utf-8", errors="strict"
            )
            authority_proposals = _authority_proposals(proposal["proposals"])
            _authority.write_applied_receipt(
                work,
                phase_name="semantic_dedup",
                application_kind="SUPPLEMENTAL",
                proposal_text=_strict_text(PROPOSAL_PATH, proposal_raw),
                proposal_path=PROPOSAL_PATH,
                proposals=authority_proposals,
                input_text=primary_text,
                output_text=candidate_text,
                applied_merges=accepted_merges,
                rejection_reasons=rejection_reasons,
            )
            supplemental_receipt = _read_authority_receipt(
                work / _authority.SUPPLEMENTAL_RECEIPT_NAME
            )
            supplemental_receipt = {
                **supplemental_receipt,
                "state": APPLIED,
                "debt": list(proposal.get("debt") or ()),
            }
            final_text = candidate_text
        except Exception as exc:
            supplemental_state = DEGRADED_PRIMARY_ONLY
            supplemental_debt = [
                {
                    "code": "SUPPLEMENTAL_APPLICATION_FAILED",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            ]
            final_text = primary_text
            supplemental_receipt = _supplemental_stage_degraded(
                proposal_raw=proposal_raw,
                proposal_payload=proposal,
                primary_receipt=primary_receipt,
                debt=supplemental_debt,
            )

    if supplemental_state == APPLIED:
        supplemental_debt = list(supplemental_receipt.get("debt") or ())
    combined = _combined_receipt(
        decisions_raw=model_decisions_raw,
        proposal_raw=proposal_raw,
        primary=primary_receipt,
        supplemental=supplemental_receipt,
    )
    combined_raw = _authority.canonical_json_bytes(combined)
    final_raw = final_text.encode("utf-8")
    original_ids = set(_authority.extract_finding_records(inventory_text))
    final_ids = set(_authority.extract_finding_records(final_text))
    absorbed_ids = set(combined["accepted_absorbed_ids"])
    if original_ids != final_ids | absorbed_ids or final_ids & absorbed_ids:
        raise SupplementalDedupError(
            "combined application violates the exact candidate partition"
        )
    aliases = _aliases_from_receipt(combined)
    projection_inputs = {
        "active_finding_ids": sorted(final_ids, key=_id_order),
        "absorbed_finding_ids": sorted(absorbed_ids, key=_id_order),
        "accepted_aliases": [
            {
                "absorbed_id": member,
                "survivor_id": row["survivor"],
                "coupled": row["coupled"],
            }
            for member, row in sorted(aliases.items(), key=lambda item: _id_order(item[0]))
        ],
    }
    return {
        "final_inventory": final_raw,
        "combined_receipt": combined_raw,
        "combined_receipt_payload": combined,
        "aliases": aliases,
        "projection_inputs": projection_inputs,
        "supplemental_state": supplemental_state,
        "supplemental_debt": supplemental_debt,
        "workspace": str(work),
    }
