"""Pure normalization of findings discovered by verifier workers.

The noticing verifier is a proposal producer, not inventory or queue
authority.  This module parses the legacy Markdown projection into exact,
content-bound proposal rows.  It never mutates the canonical inventory, the
T8 queue publication, or any report artifact.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from plamen_types import normalize_severity


SCHEMA = "plamen.post_verify_candidate_proposals.v1"
SOURCE = "post_verify_extract.md"
_BLOCK_RE = re.compile(
    r"(?ms)^#{2,4}\s+Finding\s+\[(VER-\d+)\]\s*:\s*([^\n]+)\n"
    r"(.*?)(?=^#{2,4}\s+Finding\s+\[VER-\d+\]\s*:|\Z)",
    re.IGNORECASE,
)
_FIELD_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?\*{0,2}([^:\n*]+?)\*{0,2}\s*:\s*(.*?)\s*$"
)
_CLEAN_MARKER = re.compile(
    r"(?im)(?:"
    r"\bCLEAN_NO_CANDIDATES\b|"
    r"\bNO_(?:NEW_)?CANDIDATES\b|"
    r"\bno\s+(?:new\s+)?(?:findings|candidates)\b"
    r")"
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fields(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _FIELD_RE.finditer(body):
        key = re.sub(r"\s+", " ", match.group(1)).strip().casefold()
        out.setdefault(key, match.group(2).strip().strip("`"))
    return out


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip().replace("|", "/")


def _derived_identity(
    *,
    source_sha256: str,
    ordinal: int,
    source_candidate_id: str,
    title: str,
    fields: dict[str, str],
) -> str:
    digest = _sha(_canonical({
        "source_sha256": source_sha256,
        "source_record_ordinal": ordinal,
        "source_candidate_id": source_candidate_id,
        "title": title,
        "fields": fields,
    }))
    return "VER-" + str(int(digest[:16], 16))


def parse_post_verify_candidate_proposals(
    scratchpad: Path,
) -> dict[str, Any]:
    """Return an exact proposal/debt denominator from legacy Markdown."""

    root = Path(scratchpad)
    path = root / SOURCE
    if not path.is_file():
        return {
            "schema_version": SCHEMA,
            "source_artifact": SOURCE,
            "source_present": False,
            "source_sha256": "",
            "source_size_bytes": 0,
            "clean_marker": False,
            "source_candidate_count": 1,
            "proposal_count": 0,
            "proposals": [],
            "debt_count": 1,
            "debts": [{
                "source_record_identity": "post-verify-extract:missing",
                "reason_code": "POST_VERIFY_EXTRACT_SOURCE_ABSENT",
                "detail": (
                    "post_verify_extract.md is absent; extraction denominator "
                    "cannot be certified empty"
                ),
            }],
        }
    raw = path.read_bytes()
    source_sha = _sha(raw)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        return {
            "schema_version": SCHEMA,
            "source_artifact": SOURCE,
            "source_present": True,
            "source_sha256": source_sha,
            "source_size_bytes": len(raw),
            "clean_marker": False,
            "source_candidate_count": 1,
            "proposal_count": 0,
            "proposals": [],
            "debt_count": 1,
            "debts": [{
                "source_record_identity": "post-verify-extract:utf8",
                "reason_code": "POST_VERIFY_EXTRACT_INVALID_UTF8",
                "detail": f"source cannot be decoded strictly: {type(exc).__name__}",
            }],
        }

    proposals: list[dict[str, Any]] = []
    debts: list[dict[str, str]] = []
    seen_source_ids: set[str] = set()
    matches = list(_BLOCK_RE.finditer(text))
    for ordinal, match in enumerate(matches, start=1):
        source_id = match.group(1).upper()
        title = _clean(match.group(2)) or source_id
        fields = _fields(match.group(3))
        record_raw = match.group(0).encode("utf-8")
        record_sha = _sha(record_raw)
        if source_id in seen_source_ids:
            debts.append({
                "source_record_identity": f"{source_id}:{ordinal}",
                "reason_code": "POST_VERIFY_EXTRACT_DUPLICATE_SOURCE_ID",
                "detail": (
                    f"{source_id} occurs more than once; each later occurrence "
                    "is retained as explicit parsing debt"
                ),
            })
            continue
        seen_source_ids.add(source_id)
        severity = normalize_severity(
            fields.get("severity") or "Unknown"
        )
        location = _clean(fields.get("location") or "unresolved")
        mechanism = _clean(
            fields.get("root cause")
            or fields.get("description")
            or fields.get("mechanism")
            or "Substantive late-discovery candidate requiring independent review."
        )
        harm = _clean(
            fields.get("impact")
            or fields.get("harm")
            or "Potential security impact requires independent verification."
        )
        source_verify = Path(
            fields.get("source verify file")
            or fields.get("source artifact")
            or ""
        ).name
        source_exists = bool(
            source_verify and (root / source_verify).is_file()
        )
        primary_artifact = source_verify if source_exists else SOURCE
        origin = _clean(
            fields.get("origin assessment") or "NEW_FROM_VERIFY"
        )
        evidence = _clean(
            fields.get("evidence pointer") or primary_artifact
        )
        work_id = _derived_identity(
            source_sha256=source_sha,
            ordinal=ordinal,
            source_candidate_id=source_id,
            title=title,
            fields=fields,
        )
        proposals.append({
            "work_item_id": work_id,
            "source_candidate_id": source_id,
            "source_artifact": SOURCE,
            "source_artifact_sha256": source_sha,
            "source_record_ordinal": ordinal,
            "source_record_sha256": record_sha,
            "source_record_digest": _sha(_canonical({
                "ordinal": ordinal,
                "source_candidate_id": source_id,
                "record_sha256": record_sha,
            })),
            "source_kind": "POST_VERIFY_EXTRACT",
            "severity": severity,
            "title": title,
            "location": location,
            "mechanism": mechanism,
            "harm": harm,
            "evidence": evidence,
            "primary_artifact": primary_artifact,
            "origin_assessment": origin,
            "evidence_debt": (
                "" if source_exists else "source-repair-required"
            ),
        })

    clean = bool(_CLEAN_MARKER.search(text))
    if not matches and not clean:
        debts.append({
            "source_record_identity": "post-verify-extract:unbounded-empty",
            "reason_code": "POST_VERIFY_EXTRACT_EMPTY_WITHOUT_CLEAN_MARKER",
            "detail": (
                "source contains no parseable Finding block and no explicit "
                "clean/no-candidate marker"
            ),
        })
    proposals.sort(
        key=lambda row: (
            int(row["source_record_ordinal"]),
            str(row["work_item_id"]),
        )
    )
    debts.sort(
        key=lambda row: (
            row["source_record_identity"],
            row["reason_code"],
        )
    )
    return {
        "schema_version": SCHEMA,
        "source_artifact": SOURCE,
        "source_present": True,
        "source_sha256": source_sha,
        "source_size_bytes": len(raw),
        "clean_marker": clean,
        "source_candidate_count": len(proposals) + len(debts),
        "proposal_count": len(proposals),
        "proposals": proposals,
        "debt_count": len(debts),
        "debts": debts,
    }


__all__ = [
    "SCHEMA",
    "SOURCE",
    "parse_post_verify_candidate_proposals",
]
