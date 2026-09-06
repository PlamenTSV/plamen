"""Typed recon skill-selection and declared-consumer authority.

This module closes three separable recall boundaries without making Markdown an
operational database:

* P1-J: recon merge removes transport/lifecycle markers but preserves the
  ``PLAMEN_SIGNALS`` authority channel byte-for-byte.
* P0-AD: legacy tables and structured signals project into an exact-polarity
  selection catalog.  Prose can create review debt, never flip a table row.
* P0-A: every REQUIRED skill's catalog-declared consumer is either bound to a
  scheduled dispatch or receives a typed, mode-scoped disposition.

The builders are deterministic and timestamp-free.  Their JSON receipts bind
the active ecosystem, pipeline, mode, backend, source bytes, skill index, and
resolved methodology files.  Backend is evidence, not semantic authority;
``semantic_authority_projection`` supports backend-equivalence tests.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SELECTION_SCHEMA = "plamen.skill_selection_catalog.v1"
CONSUMER_SCHEMA = "plamen.skill_consumer_coverage.v1"

_ECOSYSTEM_HEADINGS = {
    "evm": "evm skills",
    "solana": "solana skills",
    "aptos": "aptos skills",
    "sui": "sui skills",
    "soroban": "soroban skills",
    "daml": "daml skills",
}
_NEGATIVE_ALIASES = {
    "NO",
    "N",
    "FALSE",
    "0",
    "N/A",
    "NA",
    "NOT APPLICABLE",
    "NOT SET",
    "UNSET",
    "SKIP",
    "SKIPPED",
    "NOT REQUIRED",
}
_POSITIVE_ALIASES = {"YES", "Y", "TRUE", "1", "REQUIRED", "SELECTED"}
_TRANSPORT_MARKERS = {
    "PLAMEN_STATUS",
    "PLAMEN_PHASE",
    "PLAMEN_OWNER",
    "PLAMEN_ARTIFACT",
    "PLAMEN_FINDINGS_COUNT",
    "PLAMEN_EXPECTED_OUTPUT",
    "PLAMEN_VERSION",
    "RECON_ROLE",
    "EXPECTED_OUTPUT",
}
_STANDARD_DEPTH_ROLES = ("token_flow", "state_trace", "edge_case", "external")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest().upper()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(str(value).encode("utf-8"))


def _file_sha256(path: Path) -> str:
    try:
        return _sha256_bytes(Path(path).read_bytes())
    except OSError:
        return "MISSING"


def _strip_md(value: str) -> str:
    return str(value or "").strip().strip("`*_ ")


def _canonical_skill_id(value: str) -> str:
    value = _strip_md(value).upper().replace("-", " ")
    return re.sub(r"[^A-Z0-9]+", "_", value).strip("_")


def _slug(skill_id: str) -> str:
    return _canonical_skill_id(skill_id).lower().replace("_", "-")


def _header(value: str) -> str:
    value = _strip_md(value).lower().replace("?", "")
    return re.sub(r"[^a-z0-9]+", "_", value).strip("_")


def _cells(line: str) -> list[str]:
    # Skill tables never need escaped-pipe semantics; retaining a small parser
    # here keeps this module independent of the driver's wildcard imports.
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _separator(cells: Sequence[str]) -> bool:
    return bool(cells) and all(re.fullmatch(r"\s*:?-{3,}:?\s*", c or "") for c in cells)


def _iter_section_tables(text: str) -> Iterable[tuple[str, list[str], dict[str, str], int]]:
    """Yield ``(h2, headers, row, line_no)`` for every Markdown table row."""
    h2 = ""
    headers: list[str] = []
    for line_no, raw in enumerate(str(text or "").splitlines(), start=1):
        line = raw.strip()
        heading = re.match(r"^##\s+(.+?)\s*$", line)
        if heading:
            h2 = _strip_md(heading.group(1)).lower()
            headers = []
            continue
        if not (line.startswith("|") and line.endswith("|")):
            headers = []
            continue
        cs = _cells(line)
        if _separator(cs):
            continue
        normalized = [_header(c) for c in cs]
        if any(x in normalized for x in ("skill", "niche_agent")) and any(
            x in normalized
            for x in ("trigger", "trigger_pattern", "protocol_type_trigger", "trigger_flag")
        ):
            headers = normalized
            continue
        if not headers:
            # Selection tables can omit Trigger, so accept Skill+Required too.
            if "skill" in normalized and "required" in normalized:
                headers = normalized
            continue
        yield h2, headers, {
            headers[i]: cs[i] if i < len(cs) else "" for i in range(len(headers))
        }, line_no


def _parse_selection_tables(text: str) -> list[dict[str, Any]]:
    """Parse exact Skill/Required rows without positive-heading inference."""
    rows: list[dict[str, Any]] = []
    headers: list[str] = []
    section = ""
    for line_no, raw in enumerate(str(text or "").splitlines(), start=1):
        line = raw.strip()
        heading = re.match(r"^#{2,6}\s+(.+?)\s*$", line)
        if heading:
            section = _strip_md(heading.group(1))
            headers = []
            continue
        if not (line.startswith("|") and line.endswith("|")):
            headers = []
            continue
        cs = _cells(line)
        if _separator(cs):
            continue
        normalized = [_header(c) for c in cs]
        skill_header = "skill" in normalized or "niche_agent" in normalized
        if skill_header and any(x in normalized for x in ("required", "required_")):
            headers = normalized
            continue
        if not headers:
            continue
        row = {headers[i]: cs[i] if i < len(cs) else "" for i in range(len(headers))}
        skill = row.get("skill") or row.get("niche_agent") or ""
        required = row.get("required") or row.get("required_") or ""
        skill_id = _canonical_skill_id(skill)
        if not skill_id or skill_id in {"SKILL", "NONE_EXTRACTED"}:
            continue
        rows.append(
            {
                "skill_id": skill_id,
                "raw_state": _strip_md(required),
                "rationale": _strip_md(row.get("rationale") or ""),
                "section": section,
                "line": line_no,
            }
        )
    return rows


_SIGNAL_COMMENT_RE = re.compile(
    r"<!--\s*PLAMEN_SIGNALS\s*:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)


def _structured_signal_snapshots(text: str) -> tuple[list[dict[str, Any]], int]:
    snapshots: list[dict[str, Any]] = []
    malformed = 0
    for match in _SIGNAL_COMMENT_RE.finditer(str(text or "")):
        try:
            value = json.loads(match.group(1).strip())
        except (TypeError, ValueError):
            malformed += 1
            continue
        if not isinstance(value, dict):
            malformed += 1
            continue
        if "required_skills" not in value:
            continue
        selected = value.get("required_skills")
        if isinstance(selected, str):
            selected = [selected]
        if not isinstance(selected, list) or any(not isinstance(x, str) for x in selected):
            malformed += 1
            continue
        snapshots.append(
            {
                "selected": sorted({_canonical_skill_id(x) for x in selected if _canonical_skill_id(x)}),
                "offset": match.start(),
            }
        )
    return snapshots, malformed


def strip_recon_transport_markers(text: str) -> tuple[str, dict[str, Any]]:
    """Strip only worker transport markers and prove signal-block parity.

    Unlike the legacy broad ``PLAMEN_*`` regex, this allowlist cannot consume
    current or future structured authority families.  Malformed signal blocks
    are deliberately preserved so validation can surface their debt.
    """
    source = str(text or "")
    before = list(_SIGNAL_COMMENT_RE.finditer(source))
    malformed = _structured_signal_snapshots(source)[1]
    kept: list[str] = []
    removed: list[str] = []
    marker_re = re.compile(r"^\s*<!--\s*([A-Z][A-Z0-9_]*)\s*:.*?-->\s*$")
    for raw in source.splitlines():
        match = marker_re.match(raw)
        if match and match.group(1).upper() in _TRANSPORT_MARKERS:
            removed.append(match.group(1).upper())
            continue
        kept.append(raw)
    result = "\n".join(kept).strip()
    if source.endswith(("\n", "\r")) and result:
        result += "\n"
    after = list(_SIGNAL_COMMENT_RE.finditer(result))
    receipt = {
        "schema": "plamen.recon_signal_transform.v1",
        "input_sha256": _sha256_text(source),
        "output_sha256": _sha256_text(result),
        "removed_transport_markers": sorted(removed),
        "structured_signal_blocks_before": len(before),
        "structured_signal_blocks_after": len(after),
        "malformed_signal_blocks": malformed,
        "authority_loss": [m.group(0) for m in before] != [m.group(0) for m in after],
    }
    return result, receipt


def _normalize_required_cell(raw: str) -> str:
    value = re.sub(r"\s+", " ", _strip_md(raw).upper()).strip()
    value_no_note = re.sub(r"\s*\([^)]*\)\s*$", "", value).strip()
    if value in _POSITIVE_ALIASES or value_no_note in _POSITIVE_ALIASES:
        return "REQUIRED"
    if value in _NEGATIVE_ALIASES or value_no_note in _NEGATIVE_ALIASES:
        return "NOT_REQUIRED"
    return "UNKNOWN"


def normalize_consumer_declaration(value: str) -> tuple[list[str], list[str]]:
    """Map free-form index/SKILL consumer declarations to a closed registry."""
    raw = _strip_md(value).lower().replace("_", "-")
    tokens: set[str] = set()
    if re.search(r"\bbreadth\b", raw):
        if re.search(r"cross[- ]chain|encoding", raw) and (
            re.search(r"owning|focus", raw)
            or re.search(r"\bbreadth\b.*(?:cross[- /]chain|encoding).*\bagent\b", raw)
        ):
            tokens.add("breadth:cross_chain_encoding")
        else:
            tokens.add("breadth:*")
    if re.search(r"core state|economic design", raw):
        tokens.add("breadth:*")
    if re.search(r"\bdepth agents?\b", raw):
        tokens.update(f"depth:{role}" for role in _STANDARD_DEPTH_ROLES)
    depth_aliases = {
        "token-flow": "token_flow",
        "state-trace": "state_trace",
        "edge-case": "edge_case",
        "external": "external",
        "consensus-invariant": "consensus_invariant",
        "network-surface": "network_surface",
    }
    for match in re.findall(r"\bdepth-([a-z][a-z0-9-]*)\b", raw):
        if match in depth_aliases:
            tokens.add(f"depth:{depth_aliases[match]}")
        else:
            tokens.add(f"unknown:depth-{match}")
    if re.search(r"\brecon(?:naissance)?\b", raw):
        tokens.add("recon")
    if re.search(r"verifier|verification", raw):
        tokens.add("verification:*")
    if re.search(r"invariant fuzz", raw):
        tokens.add("invariant_fuzz")
    known_words = (
        "breadth", "depth", "recon", "verif", "invariant fuzz", "core state",
        "economic design", "standalone niche",
    )
    unknown = [] if any(word in raw for word in known_words) else ([raw] if raw else [])
    return sorted(tokens), unknown


def _frontmatter_or_quote_consumers(text: str) -> str:
    match = re.search(
        r"(?im)^\s*>?\s*\*\*Inject Into\*\*\s*:\s*(.+?)\s*$", str(text or "")
    )
    if match:
        return _strip_md(match.group(1))
    match = re.search(r"(?im)^description\s*:\s*[\"']?(.*?Inject Into\s+.+?)[\"']?\s*$", str(text or ""))
    if match:
        tail = re.split(r"Inject Into\s+", match.group(1), maxsplit=1, flags=re.IGNORECASE)
        return tail[-1].strip('"\' ')
    return ""


def _declared_ecosystems(text: str) -> set[str]:
    match = re.search(
        r"(?im)^\s*>?\s*\*\*Languages?\*\*\s*:\s*(.+?)\s*$", str(text or "")
    )
    if not match:
        return set()
    raw = match.group(1).lower()
    return {
        language
        for language in _ECOSYSTEM_HEADINGS
        if re.search(rf"\b{re.escape(language)}\b", raw)
    }


def _catalog_rows(skill_index_text: str, ecosystem: str, pipeline: str) -> list[dict[str, str]]:
    active_headings: set[str]
    if pipeline == "l1":
        active_headings = {"l1 skills"}
    else:
        heading = _ECOSYSTEM_HEADINGS.get(ecosystem)
        active_headings = {x for x in (heading, "injectable skills", "niche agents") if x}
    rows: list[dict[str, str]] = []
    for section, _headers, row, line in _iter_section_tables(skill_index_text):
        normalized_section = re.sub(r"\s*\(.*$", "", section).strip()
        if normalized_section not in active_headings:
            continue
        name = row.get("skill") or row.get("niche_agent") or ""
        skill_id = _canonical_skill_id(name)
        if not skill_id or skill_id in {"SKILL", "NICHE_AGENT", "NONE_EXTRACTED"}:
            continue
        trigger = row.get("trigger_pattern") or row.get("protocol_type_trigger") or row.get("trigger_flag") or ""
        consumers = row.get("used_by") or row.get("inject_into") or ""
        if normalized_section == "niche agents":
            scope = "niche"
            consumers = f"standalone niche {skill_id}"
        elif normalized_section == "injectable skills":
            scope = "injectable"
        elif normalized_section == "l1 skills":
            scope = "injectable/l1"
        else:
            scope = ecosystem
        rows.append(
            {
                "skill_id": skill_id,
                "scope": scope,
                "trigger": _strip_md(trigger),
                "index_consumers_raw": _strip_md(consumers),
                "index_line": str(line),
            }
        )
    # Duplicate catalog identities are themselves ambiguous; retain one row and
    # let the builder emit a debt rather than allowing last-wins behavior.
    return rows


def _all_index_skill_ids(text: str) -> set[str]:
    result: set[str] = set()
    for _section, headers, row, _line in _iter_section_tables(text):
        if "skill" not in headers and "niche_agent" not in headers:
            continue
        skill_id = _canonical_skill_id(row.get("skill") or row.get("niche_agent") or "")
        if skill_id and skill_id not in {"SKILL", "NICHE_AGENT", "NONE_EXTRACTED"}:
            result.add(skill_id)
    return result


def _resolved_skill_path(skill_root: Path, scope: str, skill_id: str) -> Path:
    return Path(skill_root) / Path(scope) / _slug(skill_id) / "SKILL.md"


def _is_always(trigger: str) -> bool:
    # "NOTE: operator X is now ALWAYS-ON elsewhere" inside a conditional
    # trigger must not promote the whole skill.  Catalog-owned always-on state
    # is declared only by a trigger whose leading token is Always.
    return bool(
        re.match(r"^\s*always(?:[- ]on)?\b", str(trigger or ""), re.IGNORECASE)
    )


def applicable_skill_catalog_rows(
    *,
    skill_index_path: Path,
    skill_root: Path,
    ecosystem: str,
    pipeline: str,
) -> list[dict[str, str]]:
    """Return the canonical catalog rows applicable to one audit target.

    This is the single public projection used by both prompt construction and
    selection-authority materialization.  In addition to selecting the active
    skill-index sections, it applies each methodology's declared-ecosystem
    constraint.  Missing methodology files remain catalog rows so the builder
    can surface the existing ``MISSING_METHODOLOGY`` debt instead of silently
    shrinking the allowlist.
    """
    ecosystem_n = str(ecosystem or "").strip().lower()
    pipeline_n = str(pipeline or "sc").strip().lower()
    index_text = Path(skill_index_path).read_text(encoding="utf-8", errors="replace")
    applicable: list[dict[str, str]] = []
    for row in _catalog_rows(index_text, ecosystem_n, pipeline_n):
        path = _resolved_skill_path(Path(skill_root), row["scope"], row["skill_id"])
        try:
            methodology_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            methodology_text = ""
        declared_ecosystems = _declared_ecosystems(methodology_text)
        if declared_ecosystems and ecosystem_n not in declared_ecosystems:
            continue
        applicable.append(dict(row))
    return sorted(applicable, key=lambda row: row["skill_id"])


def bindable_skill_selection_rows(
    *,
    skill_index_path: Path,
    skill_root: Path,
    ecosystem: str,
    pipeline: str,
) -> list[dict[str, str]]:
    """Return the closed vocabulary accepted by ``required_skills``.

    ``required_skills`` is reconciled into the non-niche Required=YES tables in
    the canonical BINDING MANIFEST.  Standalone niche agents deliberately use
    the separate trigger/``required_niches`` authority and therefore must not
    be advertised as selectable on this channel.  Keep the complete catalog
    projection above for selection/consumer authority construction; this
    narrower projection is the producer/validator boundary for recon signals.
    """

    return [
        row
        for row in applicable_skill_catalog_rows(
            skill_index_path=skill_index_path,
            skill_root=skill_root,
            ecosystem=ecosystem,
            pipeline=pipeline,
        )
        if str(row.get("scope") or "") != "niche"
    ]


def selection_signal_issues(
    text: str,
    allowed_rows: Iterable[Mapping[str, Any] | str],
    required: bool = True,
) -> list[dict[str, Any]]:
    """Validate the exact one-line recon ``required_skills`` signal contract.

    IDs are never normalized on this boundary: producers must emit canonical
    IDs exactly as supplied by :func:`applicable_skill_catalog_rows`.  This
    keeps semantic focus labels and wrong-ecosystem skills from being silently
    reinterpreted as methodology selections.
    """
    source = str(text or "")
    marker_count = len(re.findall(r"<!--\s*PLAMEN_SIGNALS\b", source, re.IGNORECASE))
    if marker_count == 0:
        return (
            [{"code": "MISSING_SELECTION_SIGNAL", "detail": "required_skills signal is absent"}]
            if required
            else []
        )
    if marker_count != 1:
        return [
            {
                "code": "DUPLICATE_SELECTION_SIGNAL",
                "count": marker_count,
                "detail": "exactly one PLAMEN_SIGNALS required_skills block is permitted",
            }
        ]

    matches = list(_SIGNAL_COMMENT_RE.finditer(source))
    if len(matches) != 1:
        return [
            {
                "code": "MALFORMED_SELECTION_SIGNAL",
                "detail": "PLAMEN_SIGNALS comment is not a complete JSON block",
            }
        ]
    match = matches[0]
    if "\n" in match.group(0) or "\r" in match.group(0):
        return [
            {
                "code": "MULTILINE_SELECTION_SIGNAL",
                "detail": "PLAMEN_SIGNALS required_skills block must occupy one line",
            }
        ]
    duplicate_keys: list[str] = []

    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                duplicate_keys.append(key)
            value[key] = item
        return value

    try:
        payload = json.loads(match.group(1).strip(), object_pairs_hook=_unique_object)
    except (TypeError, ValueError):
        return [
            {
                "code": "MALFORMED_SELECTION_SIGNAL",
                "detail": "PLAMEN_SIGNALS payload is not valid JSON",
            }
        ]
    if duplicate_keys:
        return [
            {
                "code": "DUPLICATE_SIGNAL_KEY",
                "keys": sorted(set(duplicate_keys)),
                "detail": "PLAMEN_SIGNALS JSON object keys must be unique",
            }
        ]
    if not isinstance(payload, dict):
        return [
            {
                "code": "MALFORMED_SELECTION_SIGNAL",
                "detail": "PLAMEN_SIGNALS payload must be a JSON object",
            }
        ]
    if "required_skills" not in payload:
        return [
            {
                "code": "MISSING_REQUIRED_SKILLS",
                "detail": "PLAMEN_SIGNALS payload must contain required_skills",
            }
        ]
    selected = payload.get("required_skills")
    if not isinstance(selected, list):
        return [
            {
                "code": "REQUIRED_SKILLS_NOT_LIST",
                "detail": "required_skills must be a JSON array",
            }
        ]

    allowed: set[str] = set()
    for row in allowed_rows:
        value = row.get("skill_id") if isinstance(row, Mapping) else row
        skill_id = str(value or "").strip()
        if skill_id and skill_id == _canonical_skill_id(skill_id):
            allowed.add(skill_id)

    issues: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position, value in enumerate(selected):
        if not isinstance(value, str) or not value or value != _canonical_skill_id(value):
            issues.append(
                {
                    "code": "NON_CANONICAL_SKILL_ID",
                    "position": position,
                    "value": value,
                }
            )
            continue
        if value in seen:
            issues.append({"code": "DUPLICATE_SKILL_ID", "skill_id": value})
            continue
        seen.add(value)
        if value not in allowed:
            issues.append({"code": "UNKNOWN_SKILL_ID", "skill_id": value})
    return sorted(issues, key=_canonical_json)


def _source_digest_rows(source_texts: Mapping[str, str]) -> list[dict[str, str]]:
    return [
        {"source": str(name), "sha256": _sha256_text(str(source_texts[name]))}
        for name in sorted(source_texts)
    ]


def build_skill_selection_catalog(
    *,
    skill_index_path: Path,
    skill_root: Path,
    ecosystem: str,
    pipeline: str,
    mode: str,
    backend: str,
    source_texts: Mapping[str, str],
) -> dict[str, Any]:
    """Build the deterministic P0-AD authority catalog."""
    ecosystem = str(ecosystem or "").strip().lower()
    pipeline = str(pipeline or "sc").strip().lower()
    mode = str(mode or "core").strip().lower()
    backend = str(backend or "unknown").strip().lower()
    index_path = Path(skill_index_path)
    index_text = index_path.read_text(encoding="utf-8", errors="replace")
    raw_catalog = applicable_skill_catalog_rows(
        skill_index_path=index_path,
        skill_root=Path(skill_root),
        ecosystem=ecosystem,
        pipeline=pipeline,
    )
    global_ids = _all_index_skill_ids(index_text)
    debts: list[dict[str, Any]] = []
    catalog_by_id: dict[str, dict[str, str]] = {}
    for row in raw_catalog:
        sid = row["skill_id"]
        if sid in catalog_by_id:
            debts.append(
                {
                    "code": "DUPLICATE_CATALOG_ID",
                    "skill_id": sid,
                    "detail": "active skill-index sections define the same canonical ID more than once",
                }
            )
            continue
        catalog_by_id[sid] = row

    records: dict[str, list[dict[str, Any]]] = {sid: [] for sid in catalog_by_id}
    source_semantics: list[dict[str, Any]] = []
    prose_unknown: set[str] = set()
    for source_name in sorted(source_texts):
        text = str(source_texts[source_name] or "")
        table_rows = _parse_selection_tables(text)
        snapshots, malformed = _structured_signal_snapshots(text)
        if malformed:
            debts.append(
                {
                    "code": "MALFORMED_STRUCTURED_SIGNAL",
                    "source": source_name,
                    "count": malformed,
                }
            )
        source_semantics.append(
            {
                "source": source_name,
                "sha256": _sha256_text(text),
                "structured_selection": (
                    "ABSENT"
                    if not snapshots
                    else "EXPLICIT_EMPTY"
                    if all(not snap["selected"] for snap in snapshots)
                    else "EXPLICIT_SET"
                ),
                "structured_snapshots": len(snapshots),
                "table_rows": len(table_rows),
                "malformed_signal_blocks": malformed,
            }
        )
        seen_structured_ids: set[str] = set()
        for snap_no, snap in enumerate(snapshots, start=1):
            selected = set(snap["selected"])
            seen_structured_ids.update(selected)
            for sid in selected:
                if sid not in catalog_by_id:
                    debts.append(
                        {
                            "code": "WRONG_ECOSYSTEM_SKILL" if sid in global_ids else "UNKNOWN_SKILL_ID",
                            "skill_id": sid,
                            "source": source_name,
                            "authority": "PLAMEN_SIGNALS",
                        }
                    )
            # required_skills is a complete selection snapshot by producer
            # contract.  Empty therefore means explicit negative, not absence.
            for sid, cat in catalog_by_id.items():
                if _is_always(cat["trigger"]):
                    continue
                records[sid].append(
                    {
                        "state": "REQUIRED" if sid in selected else "NOT_REQUIRED",
                        "source": source_name,
                        "authority": "PLAMEN_SIGNALS",
                        "record": snap_no,
                    }
                )
        table_ids: set[str] = set()
        for row in table_rows:
            sid = row["skill_id"]
            table_ids.add(sid)
            state = _normalize_required_cell(row["raw_state"])
            if sid not in catalog_by_id:
                debts.append(
                    {
                        "code": "WRONG_ECOSYSTEM_SKILL" if sid in global_ids else "UNKNOWN_SKILL_ID",
                        "skill_id": sid,
                        "source": source_name,
                        "authority": "MARKDOWN_TABLE",
                        "line": row["line"],
                    }
                )
                continue
            # The mechanical pre-pass intentionally seeds every catalog row as
            # NO + [LLM TO ENRICH].  That is schema construction, not a recon
            # negative decision, and must not conflict with the worker's later
            # structured positive selection.
            if state == "NOT_REQUIRED" and "LLM TO ENRICH" in row["rationale"].upper():
                continue
            records[sid].append(
                {
                    "state": state,
                    "source": source_name,
                    "authority": "MARKDOWN_TABLE",
                    "line": row["line"],
                    "raw_state": row["raw_state"],
                }
            )
            if state == "UNKNOWN":
                debts.append(
                    {
                        "code": "UNKNOWN_SELECTION_CELL",
                        "skill_id": sid,
                        "source": source_name,
                        "line": row["line"],
                        "raw_state": row["raw_state"],
                    }
                )
        # Section-scoped prose is review input only.  Exclude table and comment
        # lines so their canonical tokens are not double-counted as prose.
        in_recommendations = False
        for raw in text.splitlines():
            h = re.match(r"^##\s+(.+?)\s*$", raw.strip())
            if h:
                title = _strip_md(h.group(1)).lower()
                in_recommendations = bool(
                    re.search(r"(?:skill|template).*(?:recommend|select)|(?:recommend|select).*(?:skill|template)", title)
                )
                continue
            if not in_recommendations or raw.lstrip().startswith(("|", "<!--")):
                continue
            for sid in catalog_by_id:
                if sid in table_ids or sid in seen_structured_ids:
                    continue
                if re.search(rf"\b{re.escape(sid)}\b", raw.upper()) and re.search(
                    r"\b(?:recommend\w*|requir\w*|select\w*|trigger\w*|appl(?:y|ies|icable))\b",
                    raw,
                    re.IGNORECASE,
                ):
                    prose_unknown.add(sid)
                    debts.append(
                        {
                            "code": "PROSE_ONLY_RECOMMENDATION",
                            "skill_id": sid,
                            "source": source_name,
                        }
                    )

    skills: list[dict[str, Any]] = []
    methodology_digests: list[dict[str, str]] = []
    for sid in sorted(catalog_by_id):
        cat = catalog_by_id[sid]
        path = _resolved_skill_path(Path(skill_root), cat["scope"], sid)
        methodology_sha = _file_sha256(path)
        methodology_digests.append(
            {"skill_id": sid, "path": path.as_posix(), "sha256": methodology_sha}
        )
        index_tokens, index_unknown = normalize_consumer_declaration(cat["index_consumers_raw"])
        if cat["scope"] == "niche":
            index_tokens = [f"niche:{_slug(sid)}"]
            index_unknown = []
        skill_text = ""
        if path.is_file():
            skill_text = path.read_text(encoding="utf-8", errors="replace")
        skill_consumers_raw = _frontmatter_or_quote_consumers(skill_text)
        if cat["scope"] == "niche":
            skill_tokens = [f"niche:{_slug(sid)}"]
            skill_unknown: list[str] = []
        else:
            skill_tokens, skill_unknown = normalize_consumer_declaration(skill_consumers_raw)
        metadata_conflict = (
            methodology_sha == "MISSING"
            or bool(index_unknown)
            or bool(skill_unknown)
            or not index_tokens
            or not skill_tokens
            or set(index_tokens) != set(skill_tokens)
        )
        if metadata_conflict:
            debts.append(
                {
                    "code": "CONSUMER_METADATA_CONFLICT",
                    "skill_id": sid,
                    "index_consumers": index_tokens,
                    "skill_consumers": skill_tokens,
                    "index_unknown": index_unknown,
                    "skill_unknown": skill_unknown,
                    "methodology_sha256": methodology_sha,
                }
            )
        evidence = records[sid]
        states = {r["state"] for r in evidence}
        conflict = len(states) > 1 or "UNKNOWN" in states
        always = _is_always(cat["trigger"])
        if always:
            state = "REQUIRED"
            if "NOT_REQUIRED" in states or "UNKNOWN" in states:
                debts.append(
                    {
                        "code": "ILLEGAL_ALWAYS_ON_DEMOTION",
                        "skill_id": sid,
                        "observed_states": sorted(states),
                    }
                )
        elif conflict:
            state = "UNKNOWN"
            debts.append(
                {
                    "code": "SELECTION_STATE_CONFLICT",
                    "skill_id": sid,
                    "observed_states": sorted(states),
                }
            )
        elif states:
            state = next(iter(states))
        elif sid in prose_unknown:
            state = "UNKNOWN"
        else:
            state = "NOT_REQUIRED"
        skills.append(
            {
                "skill_id": sid,
                "ecosystem": ecosystem,
                "catalog_scope": cat["scope"],
                "trigger": cat["trigger"],
                "state": state,
                "state_origin": "CATALOG_ALWAYS_ON" if always else "RECON_SELECTION",
                "conflict": conflict,
                "selection_evidence": evidence,
                "methodology_path": path.as_posix(),
                "methodology_sha256": methodology_sha,
                "index_consumers_raw": cat["index_consumers_raw"],
                "skill_consumers_raw": skill_consumers_raw,
                "index_consumers": index_tokens,
                "skill_consumers": skill_tokens,
                "consumer_metadata_status": "UNKNOWN" if metadata_conflict else "CURRENT",
            }
        )

    methodology_set_sha = _sha256_text(_canonical_json(methodology_digests))
    artifact: dict[str, Any] = {
        "schema": SELECTION_SCHEMA,
        "authority": {
            "pipeline": pipeline,
            "mode": mode,
            "ecosystem": ecosystem,
            "backend": backend,
            "skill_index_path": index_path.as_posix(),
            "skill_index_sha256": _file_sha256(index_path),
            "methodology_set_sha256": methodology_set_sha,
            "source_digests": _source_digest_rows(source_texts),
        },
        "selection_semantics": {
            "states": ["REQUIRED", "NOT_REQUIRED", "UNKNOWN"],
            "structured_empty_is_explicit_negative": True,
            "prose_cannot_flip_structured_state": True,
            "duplicate_conflict_is_unknown": True,
            "always_on_is_catalog_owned": True,
        },
        "source_semantics": source_semantics,
        "skills": skills,
        "debts": sorted(debts, key=lambda x: _canonical_json(x)),
    }
    artifact["artifact_sha256"] = authority_artifact_digest(artifact)
    return artifact


def _normalized_scheduled_consumer(row: Mapping[str, Any]) -> dict[str, str]:
    kind = str(row.get("kind") or "").strip().lower()
    consumer_id = str(row.get("consumer_id") or "").strip()
    role = str(row.get("role") or "").strip().lower().replace("-", "_")
    focus = str(row.get("focus") or "").strip().lower().replace("-", "_")
    return {"consumer_id": consumer_id, "kind": kind, "role": role, "focus": focus}


def scheduled_consumers_sha256(
    scheduled_consumers: Sequence[Mapping[str, Any]],
) -> str:
    """Digest the canonical scheduled-consumer projection.

    Both producer and freshness validator must normalize role/focus slugs in
    exactly the same way.  In particular, auto-scheduled niche consumers use
    hyphenated Markdown slugs while the coverage authority stores normalized
    underscore slugs.
    """
    normalized = sorted(
        (_normalized_scheduled_consumer(row) for row in scheduled_consumers),
        key=lambda row: row["consumer_id"],
    )
    return _sha256_text(_canonical_json(normalized))


def existing_bindings_sha256(
    existing_bindings: Mapping[str, Sequence[str]],
) -> str:
    normalized = {
        str(consumer_id): sorted(
            {
                _canonical_skill_id(skill)
                for skill in skills
                if _canonical_skill_id(skill)
            }
        )
        for consumer_id, skills in existing_bindings.items()
    }
    return _sha256_text(_canonical_json(normalized))


def _split_skill_cell(value: str) -> list[str]:
    parts = re.split(r"\s*(?:\+|,|;|\band\b)\s*", _strip_md(value), flags=re.IGNORECASE)
    return sorted(
        {
            _canonical_skill_id(re.sub(r"\s*\([^)]*\)\s*$", "", part))
            for part in parts
            if _canonical_skill_id(re.sub(r"\s*\([^)]*\)\s*$", "", part))
        }
    )


_NON_CATALOG_MANIFEST_TEMPLATES = frozenset({
    "GENERAL", "GENERAL_ANALYSIS", "CUSTOM", "CUSTOM_FOCUS",
    "CORE_STATE", "ACCESS_CONTROL",
})


def scheduled_consumers_from_spawn_manifest(
    *,
    manifest_text: str,
    selection_catalog: Mapping[str, Any],
    pipeline: str,
    mode: str,
) -> tuple[list[dict[str, str]], dict[str, list[str]]]:
    """Project scheduled dispatches and existing skill bindings from Markdown.

    Standard SC depth/recon/verification consumers are driver-scheduled roles,
    so they are represented even when instantiate omitted a skill-binding row.
    A REQUIRED niche skill also gets an explicit auto-schedule consumer; this
    makes a missing niche manifest row recoverable rather than misclassified as
    a mode skip.  The caller still must dispatch the effective binding.
    """
    pipeline = str(pipeline or "sc").strip().lower()
    mode = str(mode or "core").strip().lower()
    catalog_skills = {
        str(row.get("skill_id")): row
        for row in selection_catalog.get("skills", [])
        if isinstance(row, Mapping) and row.get("skill_id")
    }
    selected = {
        str(row.get("skill_id")): row
        for row in selection_catalog.get("skills", [])
        if isinstance(row, Mapping) and row.get("state") == "REQUIRED"
    }
    scheduled: dict[str, dict[str, str]] = {}
    existing: dict[str, set[str]] = {}
    agent_focus: dict[str, str] = {}
    tables: list[tuple[str, list[str], dict[str, str]]] = []
    section = ""
    headers: list[str] = []
    for raw in str(manifest_text or "").splitlines():
        line = raw.strip()
        heading = re.match(r"^#{2,6}\s+(.+?)\s*$", line)
        if heading:
            section = _strip_md(heading.group(1)).lower()
            headers = []
            continue
        if not (line.startswith("|") and line.endswith("|")):
            headers = []
            continue
        cs = _cells(line)
        if _separator(cs):
            continue
        normalized = [_header(c) for c in cs]
        if any(
            key in normalized
            for key in ("template", "skill", "niche_agent", "row_type")
        ) and any(
            key in normalized
            for key in ("agent_id", "focus_area", "assigned_to", "inject_into", "required")
        ):
            headers = normalized
            continue
        if not headers:
            continue
        row = {headers[i]: cs[i] if i < len(cs) else "" for i in range(len(headers))}
        tables.append((section, headers, row))
        agent_id = _strip_md(row.get("agent_id") or "").lower()
        focus = _strip_md(row.get("focus_area") or "").lower().replace("-", "_")
        row_type = _strip_md(row.get("row_type") or "AGENT").upper()
        required = _normalize_required_cell(row.get("required") or row.get("required_") or "YES")
        if agent_id and focus and row_type == "AGENT" and required == "REQUIRED":
            cid = f"breadth:{agent_id.upper()}"
            scheduled[cid] = {
                "consumer_id": cid,
                "kind": "breadth",
                "focus": focus,
                "role": "",
            }
            agent_focus[agent_id] = focus
            for skill_id in _split_skill_cell(row.get("template") or row.get("skill") or ""):
                if skill_id not in _NON_CATALOG_MANIFEST_TEMPLATES:
                    existing.setdefault(cid, set()).add(skill_id)

    if pipeline == "sc":
        for role in _STANDARD_DEPTH_ROLES:
            cid = f"depth:{role}"
            scheduled[cid] = {"consumer_id": cid, "kind": "depth", "role": role, "focus": ""}
        scheduled["recon:primary"] = {
            "consumer_id": "recon:primary", "kind": "recon", "role": "primary", "focus": ""
        }
        scheduled["verification:pool"] = {
            "consumer_id": "verification:pool", "kind": "verification", "role": "pool", "focus": ""
        }
        if mode in {"core", "thorough"}:
            scheduled["invariant_fuzz:primary"] = {
                "consumer_id": "invariant_fuzz:primary",
                "kind": "invariant_fuzz",
                "role": "primary",
                "focus": "",
            }

    for _section, _headers, row in tables:
        required = _normalize_required_cell(row.get("required") or row.get("required_") or "YES")
        if required == "NOT_REQUIRED":
            continue
        skills = _split_skill_cell(row.get("skill") or row.get("template") or row.get("niche_agent") or "")
        destination = _strip_md(
            row.get("assigned_to") or row.get("inject_into") or row.get("agent") or ""
        ).lower()
        consumer_ids: list[str] = []
        depth = re.search(r"\bdepth-([a-z][a-z0-9_-]*)\b", destination)
        if depth:
            # Manifest destinations have a hyphenated ``depth-`` prefix.
            # Normalize underscores only inside the complete role token, then
            # close over the standard scheduled-role denominator below.
            role = depth.group(1).replace("-", "_")
            cid = f"depth:{role}"
            if cid in scheduled:
                consumer_ids.append(cid)
        agent = re.search(r"\b(b\d+[a-z]?)\b", destination)
        if agent:
            cid = f"breadth:{agent.group(1).upper()}"
            if cid in scheduled:
                consumer_ids.append(cid)
        focus_match = re.search(r"\(([a-z0-9_-]+)\)", destination)
        if focus_match:
            wanted = focus_match.group(1).replace("-", "_")
            consumer_ids.extend(
                cid for cid, value in scheduled.items()
                if value["kind"] == "breadth" and value["focus"] == wanted
            )
        for cid in consumer_ids:
            for skill_id in skills:
                if skill_id not in _NON_CATALOG_MANIFEST_TEMPLATES:
                    existing.setdefault(cid, set()).add(skill_id)

    # Built-in consumer bindings are explicit authority, not assumed proof of
    # application.  Later application receipts remain independent.
    if "FORK_ANCESTRY" in selected and "recon:primary" in scheduled:
        existing.setdefault("recon:primary", set()).add("FORK_ANCESTRY")
    if "VERIFICATION_PROTOCOL" in selected and "verification:pool" in scheduled:
        existing.setdefault("verification:pool", set()).add("VERIFICATION_PROTOCOL")

    for sid, skill in selected.items():
        if skill.get("catalog_scope") != "niche":
            continue
        slug = _slug(sid)
        cid = f"niche:auto:{slug}"
        scheduled[cid] = {"consumer_id": cid, "kind": "niche", "role": slug, "focus": slug}
        # An explicit matching row proves existing assignment; otherwise the
        # coverage builder classifies this as ADDED_BINDING.
        for section_name, _headers, row in tables:
            if "niche" not in section_name:
                continue
            row_skills = _split_skill_cell(row.get("skill") or row.get("niche_agent") or "")
            required = _normalize_required_cell(row.get("required") or row.get("required_") or "YES")
            if sid in row_skills and required == "REQUIRED":
                existing.setdefault(cid, set()).add(sid)

    return (
        [scheduled[cid] for cid in sorted(scheduled)],
        {cid: sorted(values) for cid, values in sorted(existing.items())},
    )


def _consumer_matches(declared: str, scheduled: Mapping[str, str], skill_id: str) -> bool:
    kind = scheduled["kind"]
    if declared == "breadth:*":
        return kind == "breadth"
    if declared == "breadth:cross_chain_encoding":
        return kind == "breadth" and bool(
            re.search(r"cross|chain|encod|serial", scheduled.get("focus", ""))
        )
    if declared.startswith("depth:"):
        return kind == "depth" and scheduled.get("role") == declared.split(":", 1)[1]
    if declared == "recon":
        return kind == "recon"
    if declared == "verification:*":
        return kind in {"verification", "verifier"}
    if declared == "invariant_fuzz":
        return kind == "invariant_fuzz"
    if declared.startswith("niche:"):
        return kind == "niche" and (
            scheduled.get("role") in {declared.split(":", 1)[1], _slug(skill_id)}
            or _slug(skill_id) in scheduled.get("consumer_id", "").lower()
        )
    return False


def _deterministic_cross_chain_breadth_owner(
    scheduled: Sequence[Mapping[str, str]],
) -> list[Mapping[str, str]]:
    """Choose one real breadth lane when instantiate omitted a named owner.

    ``breadth:cross_chain_encoding`` is a positive delivery obligation, not a
    mode-optional lane.  A manifest can legitimately use generic focus names;
    treating the lack of a regex-matching focus as ``NOT_SCHEDULED_MODE`` made
    a selected methodology disappear.  Prefer the closest semantic focus and
    otherwise choose the stable first breadth consumer ID.
    """
    breadth = [row for row in scheduled if row.get("kind") == "breadth"]
    if not breadth:
        return []
    keywords = ("cross", "chain", "encod", "serial", "message", "external")
    ranked = sorted(
        breadth,
        key=lambda row: (
            0 if any(token in str(row.get("focus") or "") for token in keywords) else 1,
            str(row.get("consumer_id") or ""),
        ),
    )
    return ranked[:1]


def _scheduled_matches_for_declaration(
    declaration: str,
    scheduled: Sequence[Mapping[str, str]],
    skill_id: str,
) -> list[Mapping[str, str]]:
    """Resolve one declaration with the same deterministic fallback everywhere."""

    matches = [
        row for row in scheduled
        if _consumer_matches(declaration, row, skill_id)
    ]
    if declaration == "breadth:cross_chain_encoding" and not matches:
        matches = list(_deterministic_cross_chain_breadth_owner(scheduled))
    return matches


def build_skill_consumer_coverage(
    *,
    selection_catalog: Mapping[str, Any],
    scheduled_consumers: Sequence[Mapping[str, Any]],
    existing_bindings: Mapping[str, Sequence[str]],
) -> dict[str, Any]:
    """Build P0-A all-declared-consumer closure and additive bindings."""
    scheduled = sorted(
        (_normalized_scheduled_consumer(row) for row in scheduled_consumers),
        key=lambda x: x["consumer_id"],
    )
    existing = {
        str(cid): sorted({_canonical_skill_id(x) for x in skills if _canonical_skill_id(x)})
        for cid, skills in existing_bindings.items()
    }
    effective: dict[str, set[str]] = {}
    debts: list[dict[str, Any]] = []
    coverage_skills: list[dict[str, Any]] = []
    catalog_skills = {
        str(skill.get("skill_id") or ""): skill
        for skill in selection_catalog.get("skills", [])
        if isinstance(skill, Mapping) and skill.get("skill_id")
    }
    selected = {
        str(skill.get("skill_id") or ""): skill
        for skill in selection_catalog.get("skills", [])
        if isinstance(skill, Mapping) and skill.get("state") == "REQUIRED"
    }
    scheduled_by_id = {
        str(row.get("consumer_id") or ""): row for row in scheduled
    }

    # The manifest is an explicit producer claim.  It may not assign a
    # selected methodology to a consumer outside the catalog declaration and
    # then rely on the typed projection to erase that claim silently.  Keep
    # the incompatible pair out of effective bindings, but preserve one debt
    # record per pair so the instantiate boundary can reject or degrade it.
    for consumer_id, skill_ids in sorted(existing.items()):
        scheduled_row = scheduled_by_id.get(consumer_id)
        for skill_id in skill_ids:
            # Every explicit binding is a producer claim and must be checked,
            # including optional catalog skills.  Selection state controls
            # additive delivery below; it never licenses an incompatible
            # explicit assignment to disappear from validation.
            skill = catalog_skills.get(skill_id)
            if not skill:
                debts.append(
                    {
                        "code": "UNKNOWN_EXPLICIT_BINDING",
                        "skill_id": skill_id,
                        "consumer_id": consumer_id,
                        "declared_consumers": [],
                    }
                )
                continue
            declared = sorted(set(skill.get("index_consumers") or []))
            compatible_ids = {
                str(match.get("consumer_id") or "")
                for declaration in declared
                for match in _scheduled_matches_for_declaration(
                    declaration, scheduled, skill_id
                )
            }
            if scheduled_row is None or consumer_id not in compatible_ids:
                debts.append(
                    {
                        "code": "INELIGIBLE_EXISTING_BINDING",
                        "skill_id": skill_id,
                        "consumer_id": consumer_id,
                        "declared_consumers": declared,
                    }
                )
    for skill in selection_catalog.get("skills", []):
        sid = str(skill.get("skill_id") or "")
        if skill.get("state") != "REQUIRED":
            continue
        if skill.get("consumer_metadata_status") != "CURRENT":
            debts.append(
                {
                    "code": "CONSUMER_METADATA_CONFLICT",
                    "skill_id": sid,
                    "detail": "selected skill has unresolved index/SKILL consumer declarations",
                }
            )
            coverage_skills.append(
                {
                    "skill_id": sid,
                    "status": "UNKNOWN",
                    "consumers": [],
                    "dispositions": [
                        {
                            "declared_consumer": "UNKNOWN",
                            "status": "UNRESOLVED_METADATA",
                        }
                    ],
                }
            )
            continue
        declared = sorted(set(skill.get("index_consumers") or []))
        consumer_rows: list[dict[str, str]] = []
        dispositions: list[dict[str, str]] = []
        for declaration in declared:
            if declaration.startswith("unknown:"):
                dispositions.append(
                    {"declared_consumer": declaration, "status": "UNRESOLVED_DESTINATION"}
                )
                debts.append(
                    {"code": "UNKNOWN_DECLARED_CONSUMER", "skill_id": sid, "consumer": declaration}
                )
                continue
            matches = _scheduled_matches_for_declaration(
                declaration, scheduled, sid
            )
            if not matches:
                dispositions.append(
                    {"declared_consumer": declaration, "status": "NOT_SCHEDULED_MODE"}
                )
                continue
            for match in matches:
                cid = match["consumer_id"]
                was_bound = sid in existing.get(cid, [])
                effective.setdefault(cid, set()).add(sid)
                consumer_rows.append(
                    {
                        "declared_consumer": declaration,
                        "consumer_id": cid,
                        "status": "DISPATCHED" if was_bound else "ADDED_BINDING",
                    }
                )
        unresolved = any(d["status"] == "UNRESOLVED_DESTINATION" for d in dispositions)
        coverage_skills.append(
            {
                "skill_id": sid,
                "methodology_sha256": skill.get("methodology_sha256"),
                "status": "UNKNOWN" if unresolved else "CURRENT",
                "declared_consumers": declared,
                "consumers": sorted(consumer_rows, key=lambda x: (x["consumer_id"], x["declared_consumer"])),
                "dispositions": sorted(dispositions, key=lambda x: x["declared_consumer"]),
            }
        )

    authority = dict(selection_catalog.get("authority") or {})
    artifact: dict[str, Any] = {
        "schema": CONSUMER_SCHEMA,
        "authority": {
            **authority,
            "selection_catalog_sha256": selection_catalog.get("artifact_sha256"),
            "scheduled_consumers_sha256": scheduled_consumers_sha256(scheduled),
            "existing_bindings_sha256": existing_bindings_sha256(existing),
        },
        "skills": coverage_skills,
        "effective_bindings": {
            cid: sorted(values) for cid, values in sorted(effective.items())
        },
        "debts": sorted(debts, key=lambda x: _canonical_json(x)),
        "status": "UNKNOWN" if debts else "CURRENT",
    }
    artifact["artifact_sha256"] = authority_artifact_digest(artifact)
    return artifact


def authority_artifact_digest(artifact: Mapping[str, Any]) -> str:
    value = dict(artifact)
    value.pop("artifact_sha256", None)
    return _sha256_text(_canonical_json(value))


def write_authority_artifact(path: Path, artifact: Mapping[str, Any]) -> None:
    """Write canonical JSON only when its semantic bytes differ."""
    value = dict(artifact)
    value["artifact_sha256"] = authority_artifact_digest(value)
    body = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file():
        try:
            if target.read_text(encoding="utf-8") == body:
                return
        except OSError:
            pass
    target.write_text(body, encoding="utf-8", newline="\n")


def semantic_authority_projection(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Drop backend/input byte evidence for cross-backend semantic parity."""
    value = json.loads(json.dumps(artifact))
    value.pop("artifact_sha256", None)
    authority = value.get("authority") or {}
    authority.pop("backend", None)
    authority.pop("skill_index_path", None)
    authority.pop("skill_index_sha256", None)
    authority.pop("methodology_set_sha256", None)
    authority.pop("source_digests", None)
    value["authority"] = authority
    # Absolute temporary paths are provenance, not selection semantics.
    for row in value.get("skills", []):
        row.pop("methodology_path", None)
    return value
