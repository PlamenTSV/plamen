"""Typed finding-local symbol anchors for mechanical enumeration.

This module is deliberately import-light.  It converts an existing reference
graph plus one finding locus into exact anchor facts; it never emits findings,
changes a verdict, or treats function-scope approximation as statement proof.
"""
from __future__ import annotations

import hashlib
import json
import posixpath
import re
from typing import Any, Iterable

ANCHOR_SCHEMA = "plamen.enumeration_symbol_anchor.v1"

_LOCATION_RE = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[A-Za-z0-9_./\\-]+\.(?:sol|vy|rs|go|move|daml))"
    r"(?:(?::[A-Za-z_]\w*)?:L?(?P<line>\d+))?",
    re.IGNORECASE,
)
_EXACT_SITE_CONFIDENCE = frozenset({
    "AST_REFERENCE_SITE",
    "REFERENCE_SITE_NO_POLARITY",
    "SCIP_REFERENCE_SITE",
})
_SITE_FIELDS = ("read_sites", "write_sites", "reference_sites")


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _normalized_path(value: str) -> str:
    normalized = posixpath.normpath(str(value or "").replace("\\", "/").strip())
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.casefold()


def _locations(value: object) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    seen: set[tuple[str, int | None]] = set()
    for match in _LOCATION_RE.finditer(str(value or "")):
        raw_line = match.group("line")
        row = {
            "path": _normalized_path(match.group("path")),
            "line": int(raw_line) if raw_line is not None else None,
            "rendered": (
                f"{match.group('path').replace(chr(92), '/')}:L{int(raw_line)}"
                if raw_line is not None
                else match.group("path").replace("\\", "/")
            ),
        }
        identity = (str(row["path"]), row["line"] if isinstance(row["line"], int) else None)
        if identity not in seen:
            seen.add(identity)
            out.append(row)
    return out


def _exact_symbol_mentions(text: str, aliases: Iterable[str]) -> list[str]:
    found: list[str] = []
    for alias in sorted({str(value).strip() for value in aliases if str(value).strip()}):
        pattern = re.compile(
            r"(?<![A-Za-z0-9_])" + re.escape(alias) + r"(?![A-Za-z0-9_])",
            re.IGNORECASE,
        )
        if pattern.search(text or ""):
            found.append(alias)
    return found


def derive_symbol_anchors(
    *,
    graph: dict[str, Any],
    finding_id: str,
    function_key: str,
    finding_block: str,
    cited_location: str,
    candidate_symbol_identities: Iterable[str],
) -> list[dict[str, Any]]:
    """Return exact anchors in stable identity order.

    A symbol is anchored only when either an exact reference-site fact equals a
    cited statement location, or the finding names an exact normalized symbol
    identity/alias.  Function membership alone is never an anchor.
    """
    citations = [row for row in _locations(cited_location) if row["line"] is not None]
    var_refs = graph.get("var_refs") if isinstance(graph, dict) else {}
    if not isinstance(var_refs, dict):
        return []
    anchors: list[dict[str, Any]] = []
    for symbol_identity in sorted({str(value) for value in candidate_symbol_identities}):
        raw = var_refs.get(symbol_identity)
        if not isinstance(raw, dict):
            continue
        bare = str(raw.get("bare") or symbol_identity.split(".")[-1]).strip()
        aliases = [bare, symbol_identity]
        aliases.extend(
            str(value).strip()
            for value in (raw.get("aliases") or [])
            if isinstance(value, str) and value.strip()
        )
        confidence = str(raw.get("confidence") or "UNKNOWN").strip().upper()
        statement_matches: list[str] = []
        if confidence in _EXACT_SITE_CONFIDENCE:
            sites: list[dict[str, object]] = []
            for field in _SITE_FIELDS:
                values = raw.get(field) or []
                if isinstance(values, list):
                    for value in values:
                        sites.extend(_locations(value))
            for citation in citations:
                for site in sites:
                    if (
                        citation["path"] == site["path"]
                        and citation["line"] == site["line"]
                    ):
                        statement_matches.append(str(site["rendered"]))
        mentions = _exact_symbol_mentions(finding_block, aliases)
        if statement_matches:
            kind = "STATEMENT_REFERENCE"
            evidence = sorted(set(statement_matches))
        elif mentions:
            kind = "FINDING_SYMBOL_IDENTITY"
            evidence = sorted(set(mentions), key=str.casefold)
        else:
            continue
        row = {
            "schema": ANCHOR_SCHEMA,
            "graph_source": str(graph.get("source") or "unknown"),
            "finding_id": str(finding_id),
            "function_identity": str(function_key),
            "symbol_identity": symbol_identity,
            "symbol": bare,
            "aliases": sorted(set(aliases), key=str.casefold),
            "anchor_kind": kind,
            "fidelity": "EXACT",
            "reference_fidelity": (
                "EXACT_SITE" if confidence in _EXACT_SITE_CONFIDENCE else "APPROXIMATE_SCOPE"
            ),
            "cited_locations": [str(row["rendered"]) for row in citations],
            "evidence": evidence,
        }
        row["anchor_id"] = "ESA-" + canonical_digest(row)[:24].upper()
        anchors.append(row)
    return sorted(anchors, key=lambda row: (row["symbol_identity"], row["anchor_id"]))


def unknown_anchor_obligation(
    *, finding_id: str, function_key: str, cited_location: str, graph_source: str
) -> dict[str, Any]:
    row = {
        "schema": "plamen.enumeration_unknown_anchor.v1",
        "finding_id": str(finding_id),
        "function_identity": str(function_key),
        "cited_location": str(cited_location),
        "graph_source": str(graph_source or "unknown"),
        "status": "UNKNOWN",
        "reason": "NO_EXACT_FINDING_LOCAL_ANCHOR",
        "candidate_count": 0,
        "disposition": "ACTIONABLE_HUMAN_REVIEW_DEBT",
    }
    row["obligation_id"] = "EAU-" + canonical_digest(row)[:24].upper()
    return row


__all__ = [
    "ANCHOR_SCHEMA",
    "canonical_digest",
    "derive_symbol_anchors",
    "unknown_anchor_obligation",
]
