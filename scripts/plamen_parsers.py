from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from plamen_types import (
    Phase, Checkpoint, SC_PHASES, L1_PHASES, log,
    L1_VERIFY_SHARD_MANIFESTS, L1_VERIFY_PHASE_NAMES,
    L1_VERIFY_CRITHIGH_PHASE_NAMES,
    SC_VERIFY_SHARD_MANIFESTS, SC_VERIFY_PHASE_NAMES,
    SC_VERIFY_CRITHIGH_PHASE_NAMES,
    _VALID_PIPELINES, _VALID_MODES,
    EVIDENCE_TAGS_PROOF, EVIDENCE_TAG_DEFAULT, EVIDENCE_TAG_NAMES_RE,
    DEPTH_EVIDENCE_TAG_RE, FINDING_BLOCK_HEADING_RE,
    SEVERITY_ORDER, SEVERITY_LETTER, SEVERITY_FROM_LETTER,
    has_mechanical_proof, normalize_severity, severity_letter_from_name,
    severity_rank,
)

__all__ = [
    "DedupSignature",
    "classify_quality_observation",
    "classify_body_or_appendix",
    "parse_disposition_md",
    "_appendix_disposition_report_ids",
    "_DISPOSITION_CLASS_TITLES",
    "_manifest_row_from_cells",
    "_manifest_row_is_spawned_breadth_agent",
    "_normalize_manifest_header",
    "_split_markdown_table_row",
    "_BODY_REPORT_ID_RE",
    "_BODY_SHARD_CAPS",
    "_BRACKETED_ID_RE",
    "_CLASS_LEVEL_TITLES",
    "_CLIENT_BODY_INTERNAL_ID_RE",
    "_COVERED_STATUS_TOKENS",
    "_DEDUP_FIX_VOCAB",
    "_DEDUP_GENERIC_STOP",
    "_DEDUP_VULN_VOCAB",
    "_DEGRADED_SENTINEL_GLOBS",
    "_DEPTH_EVIDENCE_TAG_RE",
    "_DEPTH_PROMOTION_FILES",
    "_FID_BARE_RE",
    "_FID_RANGE_RE",
    "_FINDING_BLOCK_RE",
    "_FINDING_GLOBS_FOR_CITATION",
    "_FINDING_ID_EXTRACT_RE",
    "_ID_ALL_INTERNAL",
    "_ID_ALL_NONHYPO",
    "_ID_DAML_ALTS",
    "_ID_DEPTH_ALTS",
    "_ID_HYPO_ALTS",
    "_ID_NICHE_ALTS",
    "_ID_TOOL_ALTS",
    "HYPOTHESIS_ID_PATTERN",
    "HYPOTHESIS_ID_RE",
    "is_hypothesis_id",
    "extract_hypothesis_ids",
    "normalize_hypothesis_id_token",
    "is_public_report_id",
    "parse_split_parent_hypothesis_id",
    "_parse_skeptic_judge_table",
    "read_judge_decisions_json_sidecar",
    "write_judge_decisions_json_sidecar",
    "_ID_LEDGER_NAME",
    "_ID_LEDGER_SCHEMA_VERSION",
    "_id_ledger_load",
    "_id_ledger_save",
    "_id_prefix_of",
    "_title_hash",
    "_titles_collide",
    "id_ledger_register",
    "id_ledger_next_available",
    "id_ledger_lookup",
    "id_ledger_all_for_prefix",
    "id_ledger_all_records",
    "_HEADING_FINDING_RE",
    "_HTML_ENTITY_MAP",
    "_HTML_ENTITY_RE",
    "_INVENTORY_SOURCE_PATTERNS",
    "_INTERNAL_FINDING_ID_RE",
    "_INTERNAL_ID_RE",
    "_INVENTORY_FINDING_HEADING_RE",
    "_LLM_NORM_TABLE",
    "_LOCATION_RE",
    "_MATRIX_IMPACT_LABELS",
    "_MATRIX_IMPACT_RE",
    "_MATRIX_LIKELIHOOD_LABELS",
    "_MATRIX_LIKELIHOOD_RE",
    "_MATRIX_ONCHAIN_RE",
    "_MATRIX_TRUST_FULLY_RE",
    "_MATRIX_VIEW_FN_RE",
    "_NOTREAD_FINDING_GLOBS",
    "_PATH_CELL_EXTENSIONS",
    "_PROMOTABLE_FEEDER_ID_PATTERN",
    "_QUEUE_HEADER_ALIASES",
    "_REPORT_BULLET_RE",
    "_SCIP_REPO_MAP_FILES",
    "_SCOPE_LEFTOVER_LIB_WHITELIST",
    "_SEVERITY_CODE",
    "_SEVERITY_ORDER",
    "_SEVERITY_RE",
    "_SKEPTIC_DOWNGRADE_RE",
    "_SOURCE_IDS_LINE_RE",
    "_STEP_TRACE_GLOB",
    "_TABLE_FINDING_ID_RE",
    "_TABLE_LOCATION_RE",
    "_TABLE_SOURCE_ID_RE",
    "_TOTAL_FINDINGS_RE",
    "_UNCOVERED_STATUS_TOKENS",
    "_VERIFY_CONFIRMED_VERDICT_RE",
    "_aggregate_step_execution_gaps",
    "_apply_severity_modifiers",
    "_classify_keyword",
    "_compute_matrix_severity",
    "_consolidated_title_for",
    "_count_markdown_table_rows",
    "_dedup_generic_norm",
    "_dedup_queue_by_hypothesis",
    "_dedup_signature_for_finding",
    "_demote_severity_once",
    "_detect_dedup_clusters",
    "_artifact_has_findings",
    "_enforce_severity_matrix",
    "_expected_depth_agent_roles",
    "_extract_artifact_status",
    "_findings_section_has_body",
    "_strip_fenced_code_blocks",
    "_extract_finding_ids_from_text",
    "_extract_finding_signals",
    "_extract_first_tag",
    "_extract_gap_paths_from_markdown",
    "_extract_verifier_severity_with_adjustment",
    "_extract_h2_section",
    "_extract_ids_from_text",
    "_extract_report_ids_from_body",
    "_extract_severity_inputs",
    "_field_anywhere",
    "_negation_governs_keyword",
    "_niche_heading_match",
    "_niche_required_cell_yes",
    "_field_from_markdown",
    "_field_or_section",
    "parse_plamen_signals",
    "_find_report_index_cut_for_active_recovery",
    "_first_heading_title",
    "_inventory_blocks",
    "_is_path_cell",
    "_is_reportable_verdict",
    "_is_separator_row",
    "_is_whitelisted_lib_path",
    "_line_count",
    "_llm_norm",
    "_markdown_section",
    "_match_canonical_header",
    "_merge_inventory_entries",
    "_compute_dedup_candidate_pairs",
    "_compute_dedup_candidate_blocks",
    "_compute_report_dedup_candidate_pairs",
    "_dedup_extract_findings",
    "_dedup_live_pair_cap",
    "_dedup_block_max",
    "_extract_chain_summaries_compact",
    "_chain_iter2_has_no_unexplored_pairs",
    "_enumgap_exploration_has_no_obligations",
    "_line_ranges_overlap",
    "_parse_line_range",
    "_shared_anchor_tokens",
    "_titles_overlap_score",
    "_module_key",
    "_next_report_id_counters",
    "_norm_key",
    "_norm_loc",
    "_normalize_finding_id",
    "_normalize_matrix_label",
    "_normalize_report_id",
    "_normalize_subsystem_scope",
    "_load_scope_file_paths",
    "_path_in_scope_file",
    "_chain_severity_upgrade_justified",
    "_parse_chain_constituents",
    "_parse_chunk_heading_inventory",
    "_parse_chunk_table_inventory",
    "_parse_hypothesis_constituents",
    "_parse_depth_confidence_scores",
    "_parse_depth_finding_blocks",
    "_parse_inventory_chunk",
    "_parse_location_ref",
    "_parse_markdown_table",
    "_parse_notread_files",
    "_parse_report_index_bullets",
    "_parse_report_index_summary_counts",
    "_parse_report_index_table",
    "_report_index_assignment_text",
    "_parse_source_findings_for_ids",
    "_parse_step_trace_rows",
    "_parse_uncovered_from_ledger",
    "_path_in_subsystem_scope",
    "_phase_name_from_sentinel",
    "_project_source_index",
    "_queue_rows_from_inventory",
    "_replace_inventory_location",
    "_report_index_reportable_text",
    "_report_prefix_for_severity",
    "_resolve_inventory_location",
    "_sanitize_client_body",
    "_sanitize_client_title",
    "_sc_contract_module_key",
    "_section_for_report_id",
    "_severity_bucket",
    "_severity_name_from_text",
    "_severity_rank",
    "_split_source_id_tokens",
    "_strip_md",
    "_structural_completeness_ok",
    "_validate_source_token",
    "_verifier_status_from_text",
    "_verify_file_for_id",
    "_write_mechanical_verification_queue_from_inventory",
    "_filter_verification_queue_by_mode",
    "_filter_sc_verification_queue_by_mode",
    "_write_queue_json_sidecar",
    "_read_queue_json_sidecar",
    "_write_queue_excluded_manifest",
    "_write_queue_subset_manifest",
    "_queue_rows_from_inventory_with_exclusions",
    "_read_pipeline_from_config",
    "_matches_l1_nondeterminism_class",
    "compute_report_medium_shards",  # backward compat wrapper
    "compute_report_tier_shards",
    "classify_poc_testability",
    "RESOURCE_EXHAUSTION_PATTERNS",
    "_matches_resource_exhaustion",
    "VERIFY_TARGET_PER_SHARD",
    "compute_sc_verify_shards",
    "compute_verify_shards",
    "derive_tier_assignments_from_verify_queue",
    "ensure_report_medium_shards",  # backward compat wrapper
    "ensure_report_tier_shards",
    "ensure_sc_verify_shard_manifests",
    "ensure_verify_shard_manifests",
    "get_tier_assignments",
    "is_artifact_complete",
    "is_artifact_legacy_unmarked",
    "merge_report_medium_shards",  # backward compat wrapper
    "merge_report_tier_shards",
    "parse_breadth_manifest_agents",
    "parse_breadth_manifest_count",
    "parse_breadth_manifest_outputs",
    "parse_depth_manifest_count",
    "parse_inventory_shard_manifest",
    "parse_report_index_assignments",
    "parse_finding_mapping_rows",
    "parse_report_index_counts",
    "parse_verification_queue_rows",
    # cross-module helpers imported by other modules (must be in __all__ for the
    # star-import + export-invariant test): report-dedup candidate helpers and the
    # PoC keyword predicate now imported by plamen_validators.
    "_parse_report_index_master_rows",
    "_report_index_first_location",
    "_poc_kw_present",
]


# ── Unified internal-ID prefix components (v2.4.3) ──────────────────────────
# Single source of truth for ALL internal finding ID regexes. Each consumer
# combines the subsets it needs. Adding a new agent prefix means ONE edit here.

# Depth agent structural IDs (produced by depth-*, scanners, niche agents)
_ID_DEPTH_ALTS = (
    r"DEPTH-[A-Z]+-\d+|DEPTH-CI-\d+|DEPTH-NS-\d+|DEPTH-ST-\d+|DEPTH-EC-\d+|"
    r"DEPTH-DA[0-9]*-\d+|"
    r"BLIND-\d+|VS-\d+|EN-\d+|SE-\d+|DS-\d+|DE-\d+|DT-\d+|"
    # CI-\d+ = committed-invariant block IDs emitted by the skeptic/depth phases
    # (M1). Cataloged explicitly so completeness gates never silently zero the
    # committed-invariant provenance carried on INVARIANT-sourced candidates.
    r"CI-\d+|"
    r"INV-\d+|DCI-\d+|DEC-\d+|DX-\d+|DN-\d+|DNS-\d+|"
    r"DA-[A-Z0-9_-]+-\d+|DA\d+-[A-Z0-9_-]+-\d+|DCOV\d*-\d+|"
    r"DST-(?:[A-Z0-9_-]+-)?\d+|PERT-\d+|PAIR-\d+|ATT-\d+|"
    r"PANIC(?:-EXPLOIT)?-\d+"
)

# Tool feeder IDs (Slither, fuzzer, scanner, sibling propagation)
_ID_TOOL_ALTS = r"SLITHER-\d+|FUZZ-\d+|MEDUSA-\d+|RSW-\d+|SP-\d+"

# Niche/injectable skill prefixes — 2-4 letter codes
_ID_NICHE_ALTS = (
    r"(?:AA|AB|AC|AL|AR|AV|BLS|BS|CBS|CCT|CFG|CI|CM|CMI|CPI|CR|CS|CT|CU|"
    r"DEP|DEX|ED|EDA|EN|EP|EPA|EVT|EX|FA|FC|FL|GO|GOV|HF|IHR|II|LC|"
    r"LEND|MG|MP|MSS|NFT|NS|OD|OF|OO|OR|P2P|PDA|PSC|PTB|PV|RE|REENT|REF|"
    r"RPC|RS|SA|SAF|SCOUT|SE|SGI|SHIFT|SIG|SL|SLS|SR|SS|SSC|ST|STATIC|STR|"
    r"T22|TF|TPS|TS|TXI|VA|VL|VS|WED|XE|XFER|ZS)-\d+"
)

# Hypothesis/chain/structural IDs (used in report index mapping).
# F1 (hardening from a prior run): the SC chain phase emits grouped-by-severity
# hypothesis IDs `HC-NN` (Critical), `HH-NN` (High), `HM-NN` (Medium),
# `HL-NN` (Low), `HI-NN` (Informational), plus multi-finding-group `GRP-NN`.
# Without these, `_normalize_finding_id` returns "" for every grouped queue
# row, `_validate_verification_queue_inventory_parity` drops them before
# constituent expansion, and 70%+ of inventory IDs appear "missing" at
# sc_verify_queue. See ~/.plamen/rules/phase4c-chain-prompt.md for the
# documented taxonomy.
# R0-2b identity contract. Keep the BODY capture-free because it is embedded
# in larger consumer regexes. `GRP-NN[A-Z]` is the exact identity emitted by
# anti-absorption splits: the suffix is part of the ID, not decoration and not
# an instruction to rewrite the ID back to its parent group.
HYPOTHESIS_ID_PATTERN = (
    r"(?:L1-[CHMLI]-\d+|GRP-\d+[A-Z]?|H[CHMLI]-\d+|"
    r"H-[CHMLI]?\d+|CH-\d+|CC-\d+|F-\d+|[CHMLI]-\d{1,3})"
)

# Backward-compatible embedding name. This is deliberately an alias to the
# canonical grammar rather than a separately maintained expression.
_ID_HYPO_ALTS = HYPOTHESIS_ID_PATTERN

_ASCII_ID_LEFT = r"(?<![A-Za-z0-9_-])"
_ASCII_ID_RIGHT = r"(?![A-Za-z0-9_-])"
HYPOTHESIS_ID_RE = re.compile(
    _ASCII_ID_LEFT + r"(?P<id>" + HYPOTHESIS_ID_PATTERN + r")" + _ASCII_ID_RIGHT,
    re.IGNORECASE | re.ASCII,
)


def is_hypothesis_id(value: str) -> bool:
    """Return whether *value* is exactly one canonical hypothesis ID.

    ASCII identifier boundaries intentionally include hyphen and underscore;
    therefore `GRP-022A-tail` and `GRP-022A_more` cannot be accepted by a
    consumer through prefix matching.
    """
    return bool(HYPOTHESIS_ID_RE.fullmatch((value or "").strip()))


def extract_hypothesis_ids(text: str) -> list[str]:
    """Extract canonical hypothesis IDs in document order, upper-cased."""
    return [m.group("id").upper() for m in HYPOTHESIS_ID_RE.finditer(text or "")]


_LEGACY_GROUP_HYPOTHESIS_ID_RE = re.compile(
    r"GRP-([CHMLI])-(\d{1,3})", re.IGNORECASE | re.ASCII
)


def normalize_hypothesis_id_token(value: str) -> str:
    """Normalize a complete structured hypothesis-ID cell or return ``''``.

    ``GRP-[CHMLI]-NNN`` is a deprecated serialization envelope from historical
    typed tables.  It is accepted only through this structured-cell boundary
    and immediately canonicalized to ``[CHMLI]-NNN``.  It is deliberately not
    part of :data:`HYPOTHESIS_ID_PATTERN`, is never minted into the ledger, and
    is not recognized when embedded in prose or headings.
    """
    token = _strip_md(value or "").strip()
    if len(token) >= 2 and token[0] == "[" and token[-1] == "]":
        token = token[1:-1].strip()
    legacy_group = _LEGACY_GROUP_HYPOTHESIS_ID_RE.fullmatch(token)
    if legacy_group:
        token = f"{legacy_group.group(1)}-{legacy_group.group(2)}"
    return token.upper() if is_hypothesis_id(token) else ""


# Backward-compatible internal name used by older parser call sites.
_normalize_hypothesis_id_token = normalize_hypothesis_id_token


def is_public_report_id(
    value: str,
    *,
    public_report_ids: set[str] | None = None,
    internal_hypothesis_ids: set[str] | None = None,
) -> bool:
    """Return whether a canonical-looking severity ID is client-report shaped.

    C/M/L/I numeric IDs are public report IDs.  H is intentionally narrower:
    only the established two-digit ``H-NN`` shape is public, while ``H-N`` and
    ``H-NNN+`` are internal hypotheses and must remain private. At artifacts
    where namespace membership is known, explicit public membership wins and
    explicit internal membership overrides the ambiguous H-NN shape.
    """
    fid = (value or "").strip().upper()
    match = re.fullmatch(r"([CHMLI])-(\d+)", fid, re.IGNORECASE)
    if not match:
        return False
    if public_report_ids is not None:
        # Once the artifact supplies authoritative report membership, shape is
        # no longer evidence. An undefined H-NN cross-reference remains an
        # internal-looking leak rather than being laundered by two digits.
        return fid in {item.upper() for item in public_report_ids}
    if internal_hypothesis_ids is not None and fid in {
        item.upper() for item in internal_hypothesis_ids
    }:
        return False
    prefix, digits = match.groups()
    return prefix.upper() != "H" or len(digits) == 2


def parse_split_parent_hypothesis_id(status: str) -> str:
    """Return the parent from an explicit ``SPLIT from <ID>`` status clause.

    This is intentionally not an ID search. Status/Notes prose may cite many
    unrelated IDs; only the machine relation creates a parent-union lookup
    alias. The clause may be the complete status or a parenthetical qualifier
    on a disposition, e.g. ``PRIMARY (SPLIT from H-22, anti-absorption)``.
    """
    clause_re = re.compile(
        r"(?<![A-Za-z0-9_-])SPLIT\s+from\s+(?P<id>"
        + HYPOTHESIS_ID_PATTERN
        + r")(?![A-Za-z0-9_-])",
        re.IGNORECASE | re.ASCII,
    )
    parents = {
        match.group("id").upper() for match in clause_re.finditer(status or "")
    }
    if len(parents) != 1:
        return ""
    return next(iter(parents))

# DAML/Canton internal finding-ID prefixes (DML- namespace; collision-free vs
# the report-strip list, the DT/DS/DE/DX depth IDs, and DA=Devil's-Advocate).
# Listed FIRST in the joins so a leftmost finditer match consumes the full
# DML-CC-/DML-CID- token before the bare CC-/niche alts can grab a substring.
_ID_DAML_ALTS = r"DML-(?:AUTH|ASM|CID|SK|BI|PR|IF|AM|CHS|CK|CC|PD|LK|EI)-\d+"

# Convenience: all internal IDs (daml + depth + tool + niche + hypothesis)
_ID_ALL_INTERNAL = "|".join([
    _ID_DAML_ALTS, _ID_DEPTH_ALTS, _ID_TOOL_ALTS, _ID_NICHE_ALTS, _ID_HYPO_ALTS,
])

# All unambiguously-internal IDs for client-body sanitization. Excludes
# bare [CHMLI]-\d{1,3} (report IDs) and H-\d+ / CH-\d+ (overlap with
# report IDs in SC). Only strips IDs that a report reader should never see.
_ID_ALL_NONHYPO = "|".join([
    _ID_DAML_ALTS, _ID_DEPTH_ALTS, _ID_TOOL_ALTS, _ID_NICHE_ALTS,
    # L1-prefixed hypothesis IDs are never client-facing
    r"L1-[CHMLI]-\d+|CC-\d+|F-\d+",
])


_INVENTORY_SOURCE_PATTERNS: tuple[str, ...] = (
    "analysis_*.md",
    "analysis_rescan_*.md",
    "analysis_percontract_*.md",
    # L1 graph-sweep outputs are breadth-equivalent discovery artifacts and
    # run before inventory in thorough mode.
    "graph_sweep*.md",
    "coverage_fill_*.md",
    "panic_audit_*.md",
    "panic_audit_summary.md",
    "symmetric_pair_findings.md",
    "field_validation_matrix.md",
    "primitive_correctness_findings.md",
    "network_amplification_findings.md",
    "lifecycle_replay_findings.md",
)


# Derived allow-list for _extract_finding_ids_from_text (v2.4.9).
# Built from unified source components so a new prefix needs ONE edit above.
_FID_ALLOWED_PREFIXES: frozenset = frozenset({
    "INV", "C", "H", "M", "L", "I", "F", "CC", "CH", "L1",
    "DEPTH", "BLIND", "VS", "EN", "SE",
    "DCI", "DEC", "DX", "DN", "DNS", "DA",
    "DCOV", "DST", "DT", "DS", "DCG", "DPI", "PERT", "PAIR", "ATT", "PANIC",
    "TF", "EC", "ST", "NS", "CI",
    "SLITHER", "FUZZ", "MEDUSA", "RSW", "SP", "SCANNER",
    # M1/M2 Source-ID tags stamped on deriver candidates (the candidates carry
    # INV-NNN finding IDs; these are the `**Source IDs**:` provenance tags).
    # Cataloged so completeness/coverage gates recognize them and never zero
    # INVARIANT/AXISGAP-sourced findings (per the "ID regex must catalog all
    # formats" rule).
    "INVARIANT", "AXISGAP",
}) | frozenset(re.findall(r"[A-Z][A-Z0-9]+", _ID_NICHE_ALTS))

_SEVERITY_RE = re.compile(
    r"(?im)"
    r"(?:"
    # Markdown finding format: `**Severity**: Medium` or `Severity: Medium`
    r"^\s*(?:[*_-]+\s*)?severity(?:[*_]+)?\s*:\s*(critical|high|medium)\b"
    r"|"
    # Table row containing a severity token as its own cell: `| Medium |`
    r"\|\s*(critical|high|medium)\s*\|"
    r")"
)


_SEPARATOR_ROW_RE = re.compile(
    r"^\|[\s:|-]+\|$"
)


def _is_separator_row(s: str) -> bool:
    """Return True if *s* is a markdown table separator row.

    A separator row consists ONLY of pipes, hyphens, colons, and whitespace
    (e.g., `|---|---|---|`). This is stricter than the old heuristic which
    checked `"---" in s` (false-positive on data containing triple hyphens)
    or stripped pipes/colons/hyphens then tested empty (false-positive on
    data cells that happen to be single hyphens like `| - | - |`).
    """
    return bool(_SEPARATOR_ROW_RE.match(s.strip()))


def _breadth_roster_text(text: str) -> str:
    """Ship B: bound breadth-manifest parsing to the `## Breadth Agents`
    section so a later table (e.g. `## Required Template Coverage`, whose header
    also matches the template+required heuristic) cannot bleed into the roster.
    This was an instantiate HALT observed in a prior run (count=16/outputs=None on a VALID
    manifest). Uses section-scoped Markdown AST (plamen_markdown.section_text);
    falls back to the full text when no `## Breadth Agents` heading exists
    (legacy manifests that put the roster table directly under `# Spawn
    Manifest`)."""
    try:
        import plamen_markdown as _mdast
        sect = _mdast.section_text(text, r"\bbreadth\s+agents?\b")
        return sect if sect.strip() else text
    except Exception:
        return text


def parse_breadth_manifest_count(scratchpad: Path) -> Optional[int]:
    """Return the number of breadth agents declared in spawn_manifest.md.

    The manifest is written by the Phase 2 instantiate LLM as a markdown
    table: `| Template | Required? | Agent ID | Focus Area | Status |`.
    Each data row is one agent the orchestrator intends to spawn.

    Returning this count lets the breadth gate use an EXACT quorum
    (equal to the expected-agent count) instead of a fixed floor of 3 —
    closing the residual hole where a Thorough audit spawning 6-9 breadth
    agents could false-pass with only 3 `analysis_*.md` files written.

    Returns None if the manifest is missing, unreadable, or contains no
    data rows — caller falls back to the hardcoded `min_artifacts_count`.
    """
    p = scratchpad / "spawn_manifest.md"
    if not p.exists():
        return None
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    text = _breadth_roster_text(text)  # Ship B: kill cross-section bleed
    count = 0
    in_table = False
    headers: list[str] = []
    seen_agent_ids: set[str] = set()
    for raw in text.splitlines():
        s = raw.strip()
        if not in_table:
            s_lc = s.lower()
            if s.startswith("|") and "template" in s_lc and "required" in s_lc:
                headers = [_normalize_manifest_header(c) for c in _split_markdown_table_row(s)]
                in_table = True
            continue
        if not s.startswith("|"):
            in_table = False
            headers = []
            continue
        if _is_separator_row(s):
            continue
        cells = _split_markdown_table_row(s)
        row = _manifest_row_from_cells(headers, cells)
        req = row.get("required") or row.get("required_") or row.get("required?") or (
            cells[1].strip() if len(cells) > 1 else ""
        )
        if req and re.match(r"(?i)^(?:no|n|false|skip|optional|merged)\b", req):
            continue
        if not _manifest_row_is_spawned_breadth_agent(row, cells):
            continue
        explicit_output = any(str(row.get(k, "")).strip() for k in (
            "output", "output_file", "filename", "file", "artifact",
            "expected_output", "expected_file",
        ))
        agent_key = _strip_md(row.get("agent_id", "") or row.get("agent", "")).lower()
        if agent_key and not explicit_output:
            if agent_key in seen_agent_ids:
                continue
            seen_agent_ids.add(agent_key)
        count += 1
    return count if count > 0 else None


def _split_markdown_table_row(row: str) -> list[str]:
    cells = row.strip().strip("|").split("|")
    return [_strip_md(c).strip() for c in cells]


def _normalize_manifest_header(header: str) -> str:
    header = _strip_md(header).lower()
    return re.sub(r"[^a-z0-9]+", "_", header).strip("_")


def _manifest_row_from_cells(headers: list[str], cells: list[str]) -> dict[str, str]:
    return {
        headers[i]: cells[i].strip()
        for i in range(min(len(headers), len(cells)))
    }


def _manifest_row_is_merged_or_non_output(row: dict[str, str], cells: list[str]) -> bool:
    """Return True for roster rows intentionally covered by another agent."""
    joined = " ".join(cells + list(row.values()))
    joined = re.sub(r"\s+", " ", _strip_md(joined).lower()).strip()
    if re.search(r"\bmerged\s+(?:into|with)\s+[a-z]?\d+\b", joined):
        return True
    if re.search(r"\bcovered\s+by\s+[a-z]?\d+\b", joined):
        return True
    if re.search(r"\babsorbed\s+(?:into|by)\s+[a-z]?\d+\b", joined):
        return True
    row_type = " ".join(
        str(row.get(k, ""))
        for k in (
            "type", "kind", "row_type", "category", "section", "role",
            "agent_type", "spawn_type",
        )
    )
    row_type = re.sub(r"\s+", " ", _strip_md(row_type).lower()).strip()
    if re.search(r"\b(?:skill|injectable|template|methodology|checklist|binding)\b", row_type):
        return True
    status = " ".join(
        str(row.get(k, ""))
        for k in ("status", "spawn_status", "assignment", "agent_id")
    )
    status = re.sub(r"\s+", " ", _strip_md(status).lower()).strip()
    if re.search(
        r"\b(?:inject(?:ed|ion|able)?|attached|append(?:ed)?|inherited|"
        r"methodology|skill(?:\s+only)?|not\s+spawned|no\s+separate\s+agent)\b",
        status,
    ):
        return True
    return False


def _manifest_row_is_spawned_breadth_agent(row: dict[str, str], cells: list[str]) -> bool:
    """Return True for rows that represent a breadth agent with its own output.

    `spawn_manifest.md` has drifted from a pure agent roster into a mixed
    manifest that can include required skills/injectables. Skills are binding
    methodology for a spawned agent, not standalone producers of
    `analysis_*.md`. Treat only explicit agent rows as manifest-exact output
    contracts; otherwise the gate demands files like
    `analysis_oracle_analysis.md` for a skill that was intentionally injected
    into another breadth prompt.
    """
    if _manifest_row_is_merged_or_non_output(row, cells):
        return False
    output_keys = (
        "output", "output_file", "filename", "file", "artifact",
        "expected_output", "expected_file",
    )
    explicit_outputs = [
        Path(_strip_md(str(row.get(k, ""))).strip()).name
        for k in output_keys
        if str(row.get(k, "")).strip()
    ]
    if explicit_outputs:
        return any(_is_breadth_analysis_output(name) for name in explicit_outputs)
    joined = " ".join(cells + list(row.values()))
    joined = re.sub(r"\s+", " ", _strip_md(joined).lower()).strip()
    if re.search(r"\b(?:skill|injectable|template|methodology)\b", joined) and not re.search(
        r"\b(?:agent|analysis[_ -]agent|breadth[_ -]agent|spawn(?:ed)?)\b",
        joined,
    ):
        return False
    agent_id = _strip_md(row.get("agent_id", "") or row.get("agent", "") or "")
    if re.fullmatch(r"(?i)(?:b|ba|breadth|agent)[-_ ]?\d+[a-z]?", agent_id):
        return True
    status = _strip_md(row.get("status", "") or row.get("spawn_status", "") or "").lower()
    if agent_id and re.search(r"\bspawn(?:ed)?\b|\bagent\b|\bpending\b|\bassigned\b", status):
        return True
    return False


def _is_breadth_analysis_output(filename: str) -> bool:
    """True only for files the breadth phase owns."""
    name = Path(_strip_md(filename or "").strip()).name
    reserved_prefixes = (
        "analysis_rescan_",
        "analysis_percontract_",
        "analysis_merged_into_",
        "analysis_report_",
    )
    if any(name.startswith(prefix) for prefix in reserved_prefixes):
        return False
    return bool(re.fullmatch(r"analysis_[A-Za-z0-9][A-Za-z0-9_.-]*\.md", name))


def _manifest_row_is_spawned_depth_agent(row: dict[str, str], cells: list[str]) -> bool:
    """Return True for depth manifest rows that create depth finding files.

    Depth manifests can carry supporting rows for skills, injectables,
    methodology attachments, or merged coverage. Those rows are not producers
    of `depth_*_findings.md` and must not inflate the phase's depth quorum.
    """
    if _manifest_row_is_merged_or_non_output(row, cells):
        return False
    joined = " ".join(cells + list(row.values()))
    joined = re.sub(r"\s+", " ", _strip_md(joined).lower()).strip()
    if re.search(r"\b(?:skill|injectable|template|methodology|checklist|binding)\b", joined) and not re.search(
        r"\b(?:agent|subagent|spawn(?:ed)?|depth[-_ ]agent)\b",
        joined,
    ):
        return False
    status = _strip_md(row.get("status", "") or row.get("spawn_status", "") or "").lower()
    if re.search(
        r"\b(?:inject(?:ed|ion|able)?|attached|append(?:ed)?|inherited|"
        r"methodology|skill(?:\s+only)?|not\s+spawned|no\s+separate\s+agent)\b",
        status,
    ):
        return False
    artifact = (
        row.get("expected_artifact")
        or row.get("output_file")
        or row.get("output")
        or row.get("artifact")
        or row.get("filename")
        or row.get("file")
        or ""
    )
    artifact_name = Path(_strip_md(artifact)).name
    if artifact_name:
        return bool(re.fullmatch(r"depth_[A-Za-z0-9_]+_findings\.md", artifact_name))
    agent_id = _strip_md(
        row.get("agent_id", "")
        or row.get("agent", "")
        or row.get("subagent", "")
        or row.get("role", "")
    ).lower()
    return bool(re.search(r"\bdepth[-_ ](?:token|state|edge|external|consensus|network)", agent_id))


def _slug_to_analysis_filename(value: str) -> Optional[str]:
    value = _strip_md(value).strip()
    if not value:
        return None
    explicit = re.search(r"\b([A-Za-z0-9_.-]+\.md)\b", value)
    if explicit:
        return Path(explicit.group(1)).name
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value.lower()).strip("_")
    slug = re.sub(r"_+", "_", slug)
    if not slug:
        return None
    if slug.startswith("analysis_"):
        return f"{slug}.md"
    return f"analysis_{slug}.md"


def parse_breadth_manifest_outputs(scratchpad: Path) -> Optional[list[str]]:
    """Return manifest-derived breadth output filenames.

    The breadth phase is manifest-exact: the subprocess must produce the
    output file for every required row in `spawn_manifest.md`, not merely any
    N files matching `analysis_*.md`. This parser accepts the documented
    table shape and a small set of explicit output-column aliases.

    Returns None when the manifest is absent or the table cannot be parsed
    completely enough to derive one output per row. Callers may then fall back
    to the older count-based quorum.
    """
    p = scratchpad / "spawn_manifest.md"
    if not p.exists():
        return None
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None
    text = _breadth_roster_text(text)  # Ship B: kill cross-section bleed

    headers: list[str] = []
    outputs: list[str] = []
    seen: set[str] = set()
    in_table = False
    row_count = 0
    seen_agent_ids: set[str] = set()

    for raw in text.splitlines():
        s = raw.strip()
        if not in_table:
            s_lc = s.lower()
            if s.startswith("|") and "template" in s_lc and "required" in s_lc:
                headers = [_normalize_manifest_header(c) for c in _split_markdown_table_row(s)]
                in_table = True
            continue
        if not s.startswith("|"):
            in_table = False
            headers = []
            continue
        if _is_separator_row(s):
            continue
        cells = _split_markdown_table_row(s)
        if not cells:
            continue
        row_count += 1
        row = _manifest_row_from_cells(headers, cells)
        req = row.get("required") or row.get("required_") or row.get("required?")
        if req and re.match(r"(?i)^(?:no|n|false|skip|optional|merged)\b", req.strip()):
            continue
        if not _manifest_row_is_spawned_breadth_agent(row, cells):
            continue

        filename = None
        explicit_output = False
        for key in (
            "output",
            "output_file",
            "filename",
            "file",
            "artifact",
            "expected_output",
            "expected_file",
        ):
            if row.get(key):
                explicit_output = True
                filename = _slug_to_analysis_filename(row[key])
                if filename:
                    break
        agent_key = _strip_md(row.get("agent_id", "") or row.get("agent", "")).lower()
        if agent_key and not explicit_output:
            if agent_key in seen_agent_ids:
                continue
            seen_agent_ids.add(agent_key)
        if not filename:
            for key in ("focus_area", "focus", "agent_id", "template"):
                if row.get(key):
                    filename = _slug_to_analysis_filename(row[key])
                    if filename:
                        break
        if not filename:
            return None
        if not _is_breadth_analysis_output(filename):
            continue
        if filename not in seen:
            seen.add(filename)
            outputs.append(filename)

    if row_count <= 0 or not outputs:
        return None
    return outputs


def parse_breadth_manifest_agents(scratchpad: Path) -> list[dict[str, str]]:
    """Parse spawn_manifest.md and return spawned breadth agent rows
    as ``[{"agent_id", "focus_area"}, ...]``. Empty when the manifest
    is absent or has no spawned-agent rows.

    Ship 7 of the artifact-complete PTY supervision plan. Consumed by
    ``plamen_driver.shard_opengrep_obligations`` to derive per-agent
    obligation shard filenames.

    Walks the same manifest table that ``parse_breadth_manifest_outputs``
    walks (template / skill / merged-into rows are excluded by
    ``_manifest_row_is_spawned_breadth_agent``); extracts the
    ``agent_id`` and ``focus_area`` columns rather than the output
    filename. Deduplicates by case-insensitive agent_id so two manifest
    rows with the same agent never produce a redundant shard.

    Fills in defaults when only one column is present (agent_id only
    -> focus_area = agent_id, or vice versa), so the sharder always
    has both fields to slugify.
    """
    p = scratchpad / "spawn_manifest.md"
    if not p.exists():
        return []
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []

    out: list[dict[str, str]] = []
    headers: list[str] = []
    in_table = False
    seen_agent_ids: set[str] = set()

    for raw in text.splitlines():
        s = raw.strip()
        if not in_table:
            s_lc = s.lower()
            if s.startswith("|") and "template" in s_lc and "required" in s_lc:
                headers = [
                    _normalize_manifest_header(c)
                    for c in _split_markdown_table_row(s)
                ]
                in_table = True
            continue
        if not s.startswith("|"):
            in_table = False
            headers = []
            continue
        if _is_separator_row(s):
            continue
        cells = _split_markdown_table_row(s)
        if not cells:
            continue
        row = _manifest_row_from_cells(headers, cells)
        req = (
            row.get("required")
            or row.get("required_")
            or row.get("required?")
        )
        if req and re.match(
            r"(?i)^(?:no|n|false|skip|optional|merged)\b", req.strip()
        ):
            continue
        if not _manifest_row_is_spawned_breadth_agent(row, cells):
            continue
        agent_id = _strip_md(
            row.get("agent_id", "") or row.get("agent", "")
        ).strip()
        focus_area = _strip_md(
            row.get("focus_area", "") or row.get("focus", "")
        ).strip()
        if not agent_id and not focus_area:
            continue
        if not agent_id:
            agent_id = focus_area
        if not focus_area:
            focus_area = agent_id
        key = agent_id.lower()
        if key in seen_agent_ids:
            continue
        seen_agent_ids.add(key)
        out.append({"agent_id": agent_id, "focus_area": focus_area})
    return out


def _count_markdown_table_rows(text: str,
                               header_predicate,
                               row_skip_predicate=None) -> Optional[int]:
    """Return the number of data rows in the first matching markdown table.

    header_predicate receives the stripped header row and decides whether the
    table is the one we want. Returns None when no matching table is found.
    """
    count = 0
    in_table = False
    saw_matching_header = False
    for raw in text.splitlines():
        s = raw.strip()
        if not in_table:
            if s.startswith("|") and header_predicate(s):
                in_table = True
                saw_matching_header = True
            continue
        if not s.startswith("|"):
            break
        if _is_separator_row(s):
            continue
        cells = _split_markdown_table_row(s)
        if row_skip_predicate and row_skip_predicate(s, cells):
            continue
        count += 1
    if not saw_matching_header:
        return None
    return count if count > 0 else None


def parse_depth_manifest_count(scratchpad: Path) -> Optional[int]:
    """Return the number of declared depth-loop agents, if a manifest exists.

    Preferred source is `phase4b_manifest.md` written by the L1 depth loop.
    As a loose fallback, inspect `spawn_manifest.md` and count rows that look
    depth/post-depth specific. Returns None when no parseable manifest exists.
    """
    candidates = [
        scratchpad / "phase4b_manifest.md",
        scratchpad / "spawn_manifest.md",
    ]
    for p in candidates:
        if not p.exists():
            continue
        try:
            text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if p.name == "phase4b_manifest.md":
            count = 0
            in_table = False
            headers: list[str] = []
            for raw in text.splitlines():
                s = raw.strip()
                if not in_table:
                    s_lc = s.lower()
                    if s.startswith("|") and "agent" in s_lc and (
                        "role" in s_lc or "model" in s_lc or "artifact" in s_lc
                    ):
                        headers = [_normalize_manifest_header(c) for c in _split_markdown_table_row(s)]
                        in_table = True
                    continue
                if not s.startswith("|"):
                    break
                if _is_separator_row(s):
                    continue
                cells = _split_markdown_table_row(s)
                row = _manifest_row_from_cells(headers, cells)
                req = row.get("required") or row.get("required_") or row.get("required?") or row.get("status", "")
                if req and re.match(r"(?i)^(?:no|n|false|skip|optional|merged|covered)\b", req.strip()):
                    continue
                if not _manifest_row_is_spawned_depth_agent(row, cells):
                    continue
                count += 1
            if count > 0:
                return count
            continue

        lowered_lines = text.splitlines()
        count = 0
        in_table = False
        headers: list[str] = []
        for raw in lowered_lines:
            s = raw.strip()
            if not in_table:
                s_lc = s.lower()
                if s.startswith("|") and "template" in s_lc and "required" in s_lc:
                    headers = [_normalize_manifest_header(c) for c in _split_markdown_table_row(s)]
                    in_table = True
                continue
            if not s.startswith("|"):
                break
            if _is_separator_row(s):
                continue
            cells = _split_markdown_table_row(s)
            row = _manifest_row_from_cells(headers, cells)
            req = row.get("required") or row.get("required_") or row.get("required?") or (
                cells[1].strip() if len(cells) > 1 else ""
            )
            if req and re.match(r"(?i)^(?:no|n|false|skip|optional|merged)\b", req):
                continue
            if not _manifest_row_is_spawned_depth_agent(row, cells):
                continue
            count += 1
        if count > 0:
            return count
    return None


def parse_report_index_counts(scratchpad: Path) -> dict[str, int]:
    """Return report-tier counts inferred from report_index.md.

    v2.1.7 — INVERSION FIX of v2.1.6.

    v2.1.6's positive-scoping approach (find `## Master Finding Index`
    section, count IDs only inside it) was over-aggressive: when L1
    `report_index.md` used a different section heading (e.g., `## Promoted
    Findings`) or a multi-section structure (master table + tier-assignment
    subsections), the regex returned partial or zero counts, causing
    `report_medium_a/b` and `report_low_info` to silently write 0-finding
    placeholders. Real bug → silently lost ~25 findings from the L1 run.

    v2.1.7 inverts the strategy: count IDs in the WHOLE FILE except the
    Appendix / Excluded Findings / Internal Audit Traceability section.
    Appendix-cut is more robust than master-section-find because:
    - The appendix has consistent canonical names (Appendix A/B, Excluded
      Findings, Internal Audit Traceability, Hypothesis Traceability).
    - Body content can be in many shapes (single Master table, severity-
      grouped subsections, tier-assignment lists, mixed) — counting all
      first-column IDs in the body is correct regardless of layout.

    The double-count bug (Appendix A internal hypothesis IDs
    leaking into the count) is still fixed because the cut happens BEFORE
    appendix content. Anti-regression test in tests/ would compare both
    layouts.
    """
    counts = {
        "critical_high": 0,
        "medium": 0,
        "low_info": 0,
    }
    # v2.3.3 — single source of truth: derive counts from `get_tier_assignments`.
    # Pre-v2.3.3 this function had its own table-only regex parser that returned
    # 0 when the Index Agent emitted bullet-list narrative (a prior L1 run). The
    # silent-zero contributed to the empty-AUDIT_REPORT failure: tier writers
    # were dispatched with 0 expected findings → emitted placeholders. Reusing
    # `get_tier_assignments` ensures counts and assignments are NEVER out of
    # sync, and inherits the layered fallback (table → bullets → verify-queue
    # mechanical derivation).
    rows, _source = get_tier_assignments(scratchpad)
    for a in rows:
        prefix = a["severity"][:1].upper()
        if prefix in ("C", "H"):
            counts["critical_high"] += 1
        elif prefix == "M":
            counts["medium"] += 1
        elif prefix in ("L", "I"):
            counts["low_info"] += 1
    return counts


def _parse_markdown_table(text: str, required_headers: list[str]) -> tuple[list[str], list[list[str]]]:
    """Return (headers, rows) from the first markdown table matching headers."""
    lines = text.splitlines()
    i = 0
    required = [h.lower() for h in required_headers]
    while i < len(lines):
        header = lines[i].strip()
        if not header.startswith("|"):
            i += 1
            continue
        headers = [c.strip() for c in header.strip("|").split("|")]
        headers_lc = [h.lower() for h in headers]
        if not all(any(req in h for h in headers_lc) for req in required):
            i += 1
            continue
        if i + 1 >= len(lines):
            break
        sep = lines[i + 1].strip()
        if not sep.startswith("|"):
            i += 1
            continue
        rows: list[list[str]] = []
        j = i + 2
        while j < len(lines):
            row = lines[j].strip()
            if not row.startswith("|"):
                break
            if _is_separator_row(row):
                j += 1
                continue
            rows.append([c.strip() for c in row.strip("|").split("|")])
            j += 1
        return headers, rows
    return [], []


def _parse_markdown_tables(text: str, required_headers: list[str]) -> list[tuple[list[str], list[list[str]]]]:
    """Return all markdown tables matching the required header substrings."""
    lines = text.splitlines()
    i = 0
    required = [h.lower() for h in required_headers]
    out: list[tuple[list[str], list[list[str]]]] = []
    while i < len(lines):
        header = lines[i].strip()
        if not header.startswith("|"):
            i += 1
            continue
        headers = [c.strip() for c in header.strip("|").split("|")]
        headers_lc = [h.lower() for h in headers]
        if not all(any(req in h for h in headers_lc) for req in required):
            i += 1
            continue
        if i + 1 >= len(lines) or not lines[i + 1].strip().startswith("|"):
            i += 1
            continue
        rows: list[list[str]] = []
        j = i + 2
        while j < len(lines):
            row = lines[j].strip()
            if not row.startswith("|"):
                break
            if _is_separator_row(row):
                j += 1
                continue
            rows.append([c.strip() for c in row.strip("|").split("|")])
            j += 1
        if rows:
            out.append((headers, rows))
        i = max(j, i + 1)
    return out


# R0-2a: finding_mapping.md is a typed relation, not a bag of IDs.  Header
# aliases are deliberately exact after normalization: substring matching would
# let unrelated tables (for example, a report-status table) masquerade as the
# constituent mapping contract.
_FINDING_MAPPING_HEADER_ROLES: dict[str, dict[str, int]] = {
    "source": {
        "finding_id": 0,
        "source_finding_id": 0,
        "source_id": 0,
        "constituent_finding_id": 0,
        "constituent_id": 0,
        "source_finding": 1,
        "constituent_finding": 1,
        "constituent": 1,
        "finding": 2,
        # Legacy two-column tables use `Source | Hyp`.  This is intentionally
        # weakest so a provenance column named Source cannot beat Finding ID.
        "source": 2,
    },
    "hypothesis": {
        "hypothesis_id": 0,
        "hypothesis_id_s": 0,
        "mapped_hypothesis_id": 0,
        "internal_hypothesis_id": 0,
        "hypothesis": 1,
        "mapped_hypothesis": 1,
        "internal_hypothesis": 1,
        "target_hypothesis": 1,
        "hyp": 2,
    },
    "status": {
        "mapping_status": 0,
        "status": 1,
        "relation": 1,
    },
    "notes": {
        "notes": 0,
        "note": 0,
        "reason": 1,
        "rationale": 1,
        "details": 1,
    },
}


def _finding_mapping_role_index(headers: list[str], role: str) -> int | None:
    aliases = _FINDING_MAPPING_HEADER_ROLES[role]
    candidates = [
        (aliases[header], index)
        for index, header in enumerate(headers)
        if header in aliases
    ]
    if not candidates:
        return None
    return min(candidates)[1]


def _finding_mapping_cell_ids(cell: str, *, hypothesis: bool) -> tuple[str, ...]:
    """Parse only complete ID tokens from a typed mapping cell.

    A cell may contain a bounded list separated by comma/semicolon/plus or
    `and`; any prose makes the entire cell invalid.  This is intentionally
    stricter than searching: status and Notes prose often cites other IDs and
    must never manufacture a relation.
    """
    raw = _strip_md(cell)
    if not raw:
        return ()
    parts = re.split(r"\s*(?:[,;+]|\band\b)\s*", raw, flags=re.IGNORECASE)
    found: list[str] = []
    for part in parts:
        token = part.strip()
        if len(token) >= 2 and token[0] == "[" and token[-1] == "]":
            token = token[1:-1].strip()
        if hypothesis:
            fid = normalize_hypothesis_id_token(token)
            if not fid:
                return ()
        else:
            if not token or not _INTERNAL_FINDING_ID_RE.fullmatch(token):
                return ()
            fid = token.upper()
        if fid not in found:
            found.append(fid)
    return tuple(found)


def parse_finding_mapping_rows(text: str) -> list[dict[str, object]]:
    """Return typed constituent→hypothesis rows from finding_mapping Markdown.

    Only tables with normalized source-ID and hypothesis-ID header roles plus a
    real Markdown separator are eligible.  IDs are read exclusively from those
    two columns; status, Notes, narrative prose, and unrelated tables cannot
    contribute edges.  The result is directional so consumers cannot confuse a
    hypothesis lookup alias with one of its constituent source IDs.
    """
    lines = _llm_norm(text).splitlines()
    parsed: list[dict[str, object]] = []
    i = 0
    while i + 1 < len(lines):
        header_line = lines[i].strip()
        separator_line = lines[i + 1].strip()
        if not header_line.startswith("|") or not _is_separator_row(separator_line):
            i += 1
            continue
        headers = [
            _normalize_manifest_header(cell)
            for cell in _split_markdown_table_row(header_line)
        ]
        source_idx = _finding_mapping_role_index(headers, "source")
        hypothesis_idx = _finding_mapping_role_index(headers, "hypothesis")
        if (
            source_idx is None
            or hypothesis_idx is None
            or source_idx == hypothesis_idx
        ):
            i += 2
            continue
        status_idx = _finding_mapping_role_index(headers, "status")
        notes_idx = _finding_mapping_role_index(headers, "notes")
        j = i + 2
        while j < len(lines):
            row_line = lines[j].strip()
            if not row_line.startswith("|"):
                break
            # A second table can follow without a blank line.  Stop before its
            # header so it is reclassified by its own typed column contract;
            # otherwise the previous table's indices leak into the new rows.
            if (
                j + 1 < len(lines)
                and _is_separator_row(lines[j + 1].strip())
            ):
                break
            if _is_separator_row(row_line):
                j += 1
                continue
            cells = _split_markdown_table_row(row_line)
            if max(source_idx, hypothesis_idx) >= len(cells):
                j += 1
                continue
            source_ids = _finding_mapping_cell_ids(
                cells[source_idx], hypothesis=False
            )
            hypothesis_ids = _finding_mapping_cell_ids(
                cells[hypothesis_idx], hypothesis=True
            )
            if source_ids and hypothesis_ids:
                parsed.append({
                    "source_ids": source_ids,
                    "hypothesis_ids": hypothesis_ids,
                    "status": (
                        _strip_md(cells[status_idx])
                        if status_idx is not None and status_idx < len(cells)
                        else ""
                    ),
                    "notes": (
                        _strip_md(cells[notes_idx])
                        if notes_idx is not None and notes_idx < len(cells)
                        else ""
                    ),
                })
            j += 1
        i = max(j, i + 2)
    return parsed


_QUEUE_HEADER_ALIASES = {
    # canonical -> tuple of substring aliases the LLM might emit. Match is
    # case-insensitive substring against the header cell, so e.g.
    # "Preferred Verification" matches "preferred verification".
    "queue": ("queue", "q#", "queue number", "#"),
    "finding id": ("finding id", "hypothesis id", "finding", "id"),
    "severity": ("severity", "sev"),
    "title": ("title", "description", "summary"),
    "preferred tag": (
        "preferred tag", "preferred verification", "evidence tag",
        "evidence tags", "preferred evidence", "verification tag", "tag",
    ),
    "location": ("location", "path", "file", "loc"),
    "bug class": ("bug class", "category", "class"),
    "primary artifact": ("primary artifact", "artifact", "source artifact"),
    "poc class": ("poc class", "poc_class", "testability", "poc category"),
}


# v2.4.3: derived from unified _ID_* components above.
_FINDING_ID_EXTRACT_RE = re.compile(
    _ASCII_ID_LEFT + r"(" + _ID_ALL_INTERNAL + r")" + _ASCII_ID_RIGHT,
    re.IGNORECASE | re.ASCII,
)


def _normalize_finding_id(raw: str) -> str:
    """Extract a stable finding/issue ID from common markdown/table forms.

    Defensive against LLM output drift via _llm_norm (called inline below
    to avoid forward-reference; mirrors the canonical helper at line ~2318).
    """
    s = (raw or "")
    # Inline mini-norm for forward-reference safety: line endings + curly quotes
    # + em-dash. Full _llm_norm is called downstream; this just keeps ID
    # extraction working when raw heading lines arrive with drift.
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("—", "-").replace("–", "-").replace("−", "-")
    s = s.replace("‘", "'").replace("’", "'")
    s = s.replace("“", '"').replace("”", '"')
    s = s.replace(" ", " ")
    s = s.strip()
    if not s:
        return ""
    link = re.match(r"^\s*\[([^\]]+)\]\([^)]*\)\s*$", s)
    if link:
        s = link.group(1)
    s = s.strip("`*_[]() ")
    verify_wrapper = re.fullmatch(r"verify_(.+?)\.md", s, re.IGNORECASE)
    if verify_wrapper:
        # A verification filename is an explicit serialization envelope, not
        # an identifier token boundary. Unwrap it before canonical matching so
        # strict ASCII boundaries do not suppress its embedded exact ID.
        s = verify_wrapper.group(1)
    legacy_group = re.fullmatch(
        r"GRP-([CHMLI])-(\d{1,3})", s.replace("_", "-"), re.IGNORECASE
    )
    if legacy_group:
        return f"{legacy_group.group(1).upper()}-{legacy_group.group(2)}"
    m = _FINDING_ID_EXTRACT_RE.search(s.replace("_", "-"))
    return m.group(1).upper() if m else ""


def _match_canonical_header(header_lc: str) -> Optional[str]:
    """Return the canonical key whose alias-set best matches a header cell.

    Longest-alias-first to avoid `loc` capturing a `location` cell. Returns
    None if no alias matches — the column is then dropped during parsing.
    Short aliases (<=3 chars) use word-boundary matching to prevent false
    positives like "id" matching "invalid" or "valid".
    """
    best: Optional[tuple[str, int]] = None
    for canonical, aliases in _QUEUE_HEADER_ALIASES.items():
        for alias in aliases:
            if len(alias) <= 3:
                if not re.search(r"(?<!\w)" + re.escape(alias) + r"(?!\w)", header_lc):
                    continue
            else:
                if alias not in header_lc:
                    continue
            if best is None or len(alias) > best[1]:
                best = (canonical, len(alias))
    return best[0] if best else None


def parse_verification_queue_rows(scratchpad: Path) -> list[dict[str, str]]:
    """Parse verification_queue.md into structured rows.

    v2.3.5 P1 — header-alias tolerance. Pre-v2.3.5 required exact substring
    matches for all 6 expected columns; if the LLM wrote `"Preferred
    Verification"` instead of `"Preferred Tag"` (alias documented in v2.2.1
    verifier-schema fix), `_parse_markdown_table` returned `headers=[]` and
    the entire queue parsed empty. Result: every verify shard had zero
    rows → zero `verify_*.md` files → silent halt at verify completion gate.

    Strategy: only require `severity` as the gate header (the most stable
    canonical name) and map every other column to its canonical key via
    `_QUEUE_HEADER_ALIASES`. Downstream consumers continue to read
    `entry.get("finding id")` etc. — the canonical-key contract is
    preserved regardless of the LLM's literal column-name choice.
    """
    p = scratchpad / "verification_queue.md"
    json_rows = _read_queue_json_sidecar(p)
    if json_rows:
        try:
            if not p.exists() or p.with_suffix(".json").stat().st_mtime_ns >= p.stat().st_mtime_ns:
                return json_rows
        except Exception:
            return json_rows
    if not p.exists():
        return json_rows
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return json_rows
    # Anchor on a single highly-stable header. The alias map handles the rest.
    headers, rows = _parse_markdown_table(text, ["severity"])
    if not headers:
        if json_rows:
            log.warning(
                "verification_queue.md has no parseable severity table; "
                "using existing JSON sidecar"
            )
            return json_rows
        return []
    headers_lc = [h.strip().lower() for h in headers]
    # Reject tables that don't even have a finding-id column under any alias.
    if not any(_match_canonical_header(h) == "finding id" for h in headers_lc):
        if json_rows:
            log.warning(
                "verification_queue.md has no finding-id column; using "
                "existing JSON sidecar"
            )
            return json_rows
        return []
    key_map: dict[int, str] = {}
    for idx, h in enumerate(headers_lc):
        canonical = _match_canonical_header(h)
        key_map[idx] = canonical if canonical else f"col_{idx}"
    parsed: list[dict[str, str]] = []
    for row in rows:
        entry: dict[str, str] = {}
        for idx, cell in enumerate(row):
            key = key_map.get(idx, f"col_{idx}")
            entry[key] = cell
        fid = _normalize_finding_id(entry.get("finding id") or "") or (entry.get("finding id") or "").strip()
        entry["finding id"] = fid
        sev = (entry.get("severity") or "").strip()
        if fid and sev:
            parsed.append(entry)
    if not parsed and json_rows:
        log.warning(
            "verification_queue.md parsed empty; using existing JSON sidecar"
        )
        return json_rows
    return parsed


def _severity_bucket(sev: str) -> str:
    n = normalize_severity(sev)
    return "info" if n == "Informational" else n.lower()


# ROOT FIX (verify-shard sizing): every severity tier shards by FINDING COUNT
# at the same small per-shard target so heavy tiers (e.g. 37 Low, 30 Medium)
# spread across enough shards to stay in the High "fast lane" instead of being
# crammed 10-18 findings into one near-timeout shard. The slot pools in
# SC_VERIFY_SHARD_MANIFESTS / L1_VERIFY_SHARD_MANIFESTS must be large enough
# that the `min(len(names), ...)` ceiling never throttles a tier below this
# target; over-provisioned slots are harmless (empty manifests are no-ops).
VERIFY_TARGET_PER_SHARD = 4


def compute_verify_shards(scratchpad: Path) -> dict[str, list[dict[str, str]]]:
    rows = parse_verification_queue_rows(scratchpad)
    crit_high = [r for r in rows if _severity_bucket(r.get("severity", "")) in {"critical", "high"}]
    medium = [r for r in rows if _severity_bucket(r.get("severity", "")) == "medium"]
    # v2.2.2 Fix 4: low_info shard. Pre-v2.2.2 Low and Informational
    # findings were silently dropped from verification — verify_queue
    # produced shards for crithigh/medium only. CLAUDE.md Thorough Mode
    # table mandates "ALL severities (with fuzz)"; pre-v2.2.2 behavior
    # contradicted methodology. Live impact (a prior L1 run):
    # 7 H-L01..H-L07 hypotheses never verified; H-L01 was a confirmed
    # human-GT match (a High-severity finding). Recall lost.
    low_info = [
        r for r in rows
        if _severity_bucket(r.get("severity", "")) in {"low", "info"}
    ]
    def assign_chunks(names: list[str], items: list[dict[str, str]], target: int) -> dict[str, list[dict[str, str]]]:
        out = {name: [] for name in names}
        if not items:
            return out
        chunk_count = min(len(names), max(1, math.ceil(len(items) / max(target, 1))))
        idx = 0
        for i, name in enumerate(names[:chunk_count]):
            remaining_chunks = chunk_count - i
            remaining_items = len(items) - idx
            take = math.ceil(remaining_items / max(remaining_chunks, 1))
            out[name] = items[idx:idx + take]
            idx += take
        if idx < len(items):
            out[names[-1]].extend(items[idx:])
        return out

    shards = {}
    shards.update(assign_chunks(
        list(L1_VERIFY_CRITHIGH_PHASE_NAMES),
        crit_high,
        VERIFY_TARGET_PER_SHARD,
    ))
    shards.update(assign_chunks(
        ["verify_medium_a", "verify_medium_b", "verify_medium_c", "verify_medium_d", "verify_medium_e", "verify_medium_f"],
        medium,
        VERIFY_TARGET_PER_SHARD,
    ))
    shards.update(assign_chunks(
        ["verify_low_a", "verify_low_b", "verify_low_c", "verify_low_d"],
        low_info,
        VERIFY_TARGET_PER_SHARD,
    ))
    return shards


def _queue_sidecar_path(path: Path) -> Path:
    return path.with_suffix(".json")


def _canonical_queue_row(row: dict[str, str]) -> dict[str, str]:
    fid = _normalize_finding_id(row.get("finding id") or "") or str(row.get("finding id", "") or "").strip()
    return {
        "queue #": str(row.get("queue #", "") or ""),
        "finding id": fid,
        "expected output file": str(
            row.get("expected output file")
            or (f"verify_{fid}.md" if fid else "")
        ),
        "severity": normalize_severity(row.get("severity", "") or "Medium"),
        "title": str(row.get("title", "") or ""),
        "bug class": str(row.get("bug class", "") or ""),
        "preferred tag": str(row.get("preferred tag", "") or row.get("evidence tag", "") or ""),
        "location": str(row.get("location", "") or ""),
        "primary artifact": str(row.get("primary artifact", "") or ""),
        "poc class": str(row.get("poc class", "") or "structural"),
        "exclusion reason": str(row.get("exclusion reason", "") or ""),
    }


def _canonical_queue_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Return only queue rows with a real finding identity.

    Queue manifests are machine contracts for later verify phases. A blank or
    malformed ID must be dropped here instead of becoming `verify_.md`, which
    then poisons unrelated phase gates.
    """
    canonical: list[dict[str, str]] = []
    dropped = 0
    for row in rows:
        item = _canonical_queue_row(row)
        if not item.get("finding id"):
            dropped += 1
            continue
        canonical.append(item)
    if dropped:
        log.warning(
            "dropped %s verification queue row(s) with blank finding id before writing manifest",
            dropped,
        )
    return canonical


def _write_queue_json_sidecar(path: Path, rows: list[dict[str, str]], *, kind: str) -> None:
    canonical = _canonical_queue_rows(rows)
    payload = {
        "schema_version": "plamen.verification_queue.v1",
        "kind": kind,
        "source_markdown": path.name,
        "row_count": len(canonical),
        "rows": canonical,
    }
    sidecar = _queue_sidecar_path(path)
    content = json.dumps(payload, indent=2, sort_keys=True)
    if sidecar.exists():
        try:
            if sidecar.read_text(encoding="utf-8", errors="replace") == content:
                return
        except Exception:
            pass
    sidecar.write_text(content + "\n", encoding="utf-8")


# v2.0.5 (P0.1, Codex fix 1): allowed Decision tokens for the skeptic-judge
# table. Any other token in the Decision column means this is NOT a skeptic-
# judge decision row — could be an unrelated 4+ column table elsewhere in
# the same file (Evidence Integrity Notes, etc).
_SKEPTIC_JUDGE_ALLOWED_DECISIONS = frozenset({
    "KEEP", "DOWNGRADE", "UNRESOLVED", "PARTIAL", "DISMISS",
})


def _parse_skeptic_judge_table(text: str) -> list[dict]:
    """v2.0.5 (P0.1): shared parser for the current skeptic_judge_decisions.md
    table format.

    The v2 skeptic prompt at `~/.plamen/prompts/shared/v2/phase5-skeptic.md`
    instructs the LLM to write decisions as a single pipe-delimited table:

        | Finding ID | Original Severity | Final Severity | Decision | Rationale |

    Pre-v2.0.5 the only table consumer was `_collect_judge_downgrade_map`
    (DOWNGRADE rows only). `_collect_judge_unresolved_ids` required
    `Verdict|Decision: UNRESOLVED|PARTIAL` prose, missing the table entirely
    and silently returning an empty set — root cause of the 2026-05-21 halt
    where every legitimate UNRESOLVED stamp failed authenticity.

    Lives in `plamen_parsers` (not `plamen_validators`) to respect the
    parsers→validators dependency direction.

    **Codex fix (P0.1 hardening):** validates BOTH (a) column 1 normalizes
    to a real internal finding ID via `_normalize_finding_id`, AND (b)
    column 4 is in `_SKEPTIC_JUDGE_ALLOWED_DECISIONS`. Without these
    checks, the parser over-matched unrelated 4+ column tables later in
    the file (e.g. an `Evidence Integrity Notes` table can invent
    `finding_id="Category"`, `decision="SUMMARY"`).

    Returns one dict per data row. Header / separator rows and rows that
    fail validation are silently skipped. Returns [] if no validated
    rows are found.
    """
    from plamen_types import normalize_severity
    rows: list[dict] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        # PARSE-1: preserve empty interior cells so positional reads stay
        # aligned to the documented 5-column contract. The prior empty-filter
        # collapsed a blank cell and shifted every later index, silently
        # dropping DOWNGRADE/UNRESOLVED rulings whose Final-Severity (or any
        # interior) cell was blank. Matches the empties-preserving split used by
        # every sibling manifest/table parser.
        cells = [c.strip() for c in s.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        first = cells[0]
        # Skip header row ("| Finding ID | ...") and separator ("|---|---|...")
        if first.startswith("-") or first.lower().startswith("finding"):
            continue
        decision = cells[3].upper().replace("*", "").strip()
        # Codex fix 1a: only accept canonical skeptic-judge decision tokens.
        # Rejects unrelated 4+ column tables whose 4th cell isn't a decision.
        if decision not in _SKEPTIC_JUDGE_ALLOWED_DECISIONS:
            continue
        # Codex fix 1b: column 1 must normalize to a recognized finding ID.
        # Rejects rows where the first cell is prose like "Category" or
        # "code-trace" or any other non-ID token.
        normalized_id = _normalize_finding_id(first)
        if not normalized_id:
            continue
        rows.append({
            "finding_id": first,
            "original_severity": normalize_severity(cells[1]) or cells[1],
            "final_severity": normalize_severity(cells[2]) or cells[2],
            "decision": decision,
            "rationale": cells[4] if len(cells) > 4 else "",
        })
    return rows


# ---------------------------------------------------------------------------
# v2.0.6 (P2): canonical ID ledger
# ---------------------------------------------------------------------------
#
# `_id_ledger.json` records every internal finding ID minted during a single
# audit, with the phase and attempt that produced it. The ledger gives the
# driver three things:
#
# 1. Collision detection across phase retries (chain attempt 1 minted
#    GRP-01 = title-A; attempt 2 tries to mint GRP-01 = title-B → COLLISION).
# 2. Next-available-ID allocation for the chain-prompt directive (so the
#    LLM knows which numbers are taken before it mints).
# 3. Consumer-side validation (sc_verify_queue / report_index should only
#    reference IDs the ledger has recorded — catches stale-markdown drift).
#
# Lives in plamen_parsers (not plamen_validators) so prompts AND validators
# can both consume it without violating the parsers→validators direction.


_ID_LEDGER_NAME = "_id_ledger.json"
_ID_LEDGER_SCHEMA_VERSION = "plamen.id_ledger.v1"


def _id_ledger_path(scratchpad: Path) -> Path:
    return scratchpad / _ID_LEDGER_NAME


# Dash family: em-dash, en-dash, figure-dash, horizontal-bar, minus-sign,
# non-breaking-hyphen, and the small/full-width variants. Cosmetic reword
# (`—` → `-`) across retries must NOT change identity (FIX 2, validated on
# a cross-chain-contract rewording cascade in a prior run).
_DASH_VARIANTS = "‒–—―−‑﹘﹣－"
_DASH_TRANS = {ord(c): "-" for c in _DASH_VARIANTS}


def _title_normalize(title: str) -> str:
    """Canonical normalized form of a finding title for identity comparison.

    Shared by `_title_hash` (exact fast-path) and `_titles_collide` (fuzzy
    same-finding detection). Normalization is intentionally aggressive on
    COSMETIC variation only — dash family, case, whitespace, code-framing
    punctuation, and trailing punctuation — so a phase that re-states the
    SAME finding with a reworded title (em-dash → hyphen, backtick changes,
    expanded abbreviation suffix) collapses to the same/near form, while a
    GENUINELY different finding stays distinct.
    """
    import re as _re
    s = (title or "")
    # Map every dash variant to ASCII hyphen BEFORE other steps so prefix
    # stripping and trailing-punctuation stripping see a uniform character.
    s = s.translate(_DASH_TRANS)
    s = s.strip().lower()
    # Strip leading ID-like prefixes ("GRP-01:", "Finding [HC-02]:")
    s = _re.sub(r"^\s*(?:finding\s+)?\[?[a-z]{1,8}-\d+[a-z0-9-]*\]?\s*[:.]?\s*", "", s)
    # Drop markdown emphasis / code framing characters entirely (not just at
    # the edges) — `withdraw()` vs withdraw() must match.
    s = s.replace("`", "").replace("*", "").replace("_", " ")
    # Collapse all whitespace
    s = _re.sub(r"\s+", " ", s)
    # Strip residual edge punctuation that does not affect meaning.
    s = s.strip(" -:.,;")
    return s


def _title_hash(title: str) -> str:
    """v2.0.6 (P2): canonical content-hash for a finding title.

    Normalizes by lowercasing, collapsing whitespace, mapping every dash
    variant to ASCII hyphen, and stripping common ID/punctuation framing so
    legitimate retry-with-same-content (including cosmetic dash/backtick
    rewordings) produces an identical hash while different-content rewrites
    produce a different hash (collision detection fast-path).
    """
    import hashlib
    s = _title_normalize(title)
    return "sha256:" + hashlib.sha256(s.encode("utf-8")).hexdigest()


def _title_tokens(title: str) -> set[str]:
    """Content-word token set of a normalized title.

    Drops short/stop tokens so that an abbreviation expanded into a full word
    (`gcc` → `crosschainrouter`) and surrounding identical wording compare on
    their shared, meaningful tokens rather than the differing label token.
    """
    import re as _re
    norm = _title_normalize(title)
    raw = [t for t in _re.split(r"[^a-z0-9]+", norm) if t]
    # Tokens of length <= 2 (a, is, of, to) carry no identity signal.
    return {t for t in raw if len(t) > 2}


def _titles_collide(title_a: str, title_b: str) -> bool:
    """Return True only when two titles denote GENUINELY DIFFERENT findings.

    Recall-safe collision predicate (FIX 2). Two titles are treated as the
    SAME finding (NOT a collision) when ANY of:
      1. Normalized forms are identical (exact fast-path, == `_title_hash`).
      2. One normalized form is a prefix of the other (abbreviation expanded,
         trailing detail added: "gcc trusts inbound externalid verbatim" vs
         "crosschainrouter trusts inbound externalid verbatim ...").
      3. Token-set Jaccard similarity >= 0.6 (cosmetic reword / synonym swap
         leaving most meaningful words intact).

    Only when none of these hold is it a real different-finding ID reuse, i.e.
    a collision. This predicate ONLY relaxes false collisions; it never turns a
    same-content reuse into a collision (an identical title is rule 1).
    """
    na = _title_normalize(title_a)
    nb = _title_normalize(title_b)
    if na == nb:
        return False
    if not na or not nb:
        # An empty title carries no identity — never assert a collision on it.
        return False
    # Prefix / containment: one is the other plus added detail.
    shorter, longer = (na, nb) if len(na) <= len(nb) else (nb, na)
    if longer.startswith(shorter):
        return False
    ta, tb = _title_tokens(title_a), _title_tokens(title_b)
    if not ta or not tb:
        return False
    inter = len(ta & tb)
    union = len(ta | tb)
    # High token-set overlap => cosmetic reword / synonym swap / abbreviation
    # expansion (the expanded label inflates the union but the bulk of
    # meaningful words is shared). This threshold deliberately does NOT collapse
    # one-word semantic swaps like "old root cause" vs "new root cause"
    # (Jaccard 0.5), which ARE different findings.
    if union and (inter / union) >= 0.6:
        return False
    return True


def _id_ledger_load(scratchpad: Path) -> dict:
    """Load the ID ledger from disk. Returns the canonical empty shape
    if the file doesn't exist or is malformed (so callers can append
    without needing to special-case first-write).
    """
    path = _id_ledger_path(scratchpad)
    empty = {
        "schema_version": _ID_LEDGER_SCHEMA_VERSION,
        "allocations": [],
    }
    if not path.exists():
        return empty
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return empty
    if not isinstance(payload, dict):
        return empty
    if payload.get("schema_version") != _ID_LEDGER_SCHEMA_VERSION:
        return empty
    allocations = payload.get("allocations")
    if not isinstance(allocations, list):
        return empty
    return {
        "schema_version": _ID_LEDGER_SCHEMA_VERSION,
        "allocations": allocations,
    }


def _id_ledger_save(scratchpad: Path, ledger: dict) -> None:
    """Atomic save via temp-file rename (mirrors `_write_artifact_state`)."""
    path = _id_ledger_path(scratchpad)
    payload = {
        "schema_version": _ID_LEDGER_SCHEMA_VERSION,
        "allocations": ledger.get("allocations", []),
    }
    content = json.dumps(payload, indent=2, sort_keys=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(content + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _id_prefix_of(finding_id: str) -> str:
    """Extract the prefix segment of a finding ID (e.g., GRP-01 → 'GRP-').

    Returns "" for unrecognized formats.
    """
    import re as _re
    m = _re.match(r"^([A-Za-z]{1,8}-)\d+", (finding_id or "").strip().upper())
    return m.group(1) if m else ""


def id_ledger_register(
    scratchpad: Path,
    *,
    finding_id: str,
    owner_phase: str,
    owner_attempt: int,
    owning_artifact: str,
    title: str,
) -> dict:
    """v2.0.6 (P2): register an ID allocation in the ledger.

    Returns a dict with:
      - "status": "REGISTERED" | "REUSED" | "COLLISION"
      - "existing": the prior allocation record if REUSED/COLLISION, else None
      - "current": the input parameters as a record

    Semantics:
      - REGISTERED: ID not previously in ledger → new allocation recorded.
      - REUSED: ID already in ledger with the SAME title_hash → legitimate
        re-allocation (e.g. chain retry with same root cause) — no-op.
      - COLLISION: ID already in ledger with a DIFFERENT title_hash →
        the caller MUST fail the phase.

    The ledger file is written on every REGISTER (atomic). REUSED and
    COLLISION do NOT modify the ledger.
    """
    finding_id = (finding_id or "").strip().upper()
    if not finding_id:
        return {"status": "REGISTERED", "existing": None, "current": None}
    new_hash = _title_hash(title)
    ledger = _id_ledger_load(scratchpad)
    for record in ledger.get("allocations", []):
        if record.get("id", "").upper() == finding_id:
            if record.get("title_hash") == new_hash:
                return {"status": "REUSED", "existing": record, "current": None}
            # Hashes differ — but a cosmetic reword (dash family, abbreviation
            # expansion, backtick changes, added trailing detail) is NOT a
            # collision. Only flag when the titles denote GENUINELY DIFFERENT
            # findings. `title_preview` holds the prior full-ish title (120
            # chars); fall back to it when no separate full title is stored.
            prior_title = record.get("title_preview", "") or ""
            if not _titles_collide(prior_title, title or ""):
                return {"status": "REUSED", "existing": record, "current": None}
            return {"status": "COLLISION", "existing": record, "current": {
                "id": finding_id,
                "owner_phase": owner_phase,
                "owner_attempt": owner_attempt,
                "owning_artifact": owning_artifact,
                "title_preview": (title or "")[:120],
                "title_hash": new_hash,
            }}
    new_record = {
        "id": finding_id,
        "prefix": _id_prefix_of(finding_id),
        "owner_phase": owner_phase,
        "owner_attempt": owner_attempt,
        "owning_artifact": owning_artifact,
        "title_hash": new_hash,
        "title_preview": (title or "")[:120],
        "allocated_at": datetime.now(timezone.utc).isoformat(),
    }
    ledger["allocations"].append(new_record)
    _id_ledger_save(scratchpad, ledger)
    return {"status": "REGISTERED", "existing": None, "current": new_record}


def id_ledger_next_available(scratchpad: Path, prefix: str) -> str:
    """Return the next-available ID for `prefix` (e.g., 'GRP-' → 'GRP-04'
    if GRP-01..GRP-03 are allocated). Caller's responsibility to pass
    the correct prefix shape (must end in '-' and contain only letters
    before the dash).
    """
    import re as _re
    if not prefix or not prefix.endswith("-"):
        return ""
    ledger = _id_ledger_load(scratchpad)
    max_num = 0
    pattern = _re.compile(rf"^{_re.escape(prefix)}(\d+)$", _re.IGNORECASE)
    for record in ledger.get("allocations", []):
        m = pattern.match(record.get("id", ""))
        if m:
            try:
                n = int(m.group(1))
                if n > max_num:
                    max_num = n
            except ValueError:
                pass
    # Pad to 2 digits if the prefix conventionally uses 2-digit numbering,
    # else keep natural width. The chain prompt vocabulary uses 2-digit
    # padding by convention (HC-01, GRP-01, HH-02, etc.).
    return f"{prefix}{max_num + 1:02d}"


def id_ledger_lookup(scratchpad: Path, finding_id: str) -> dict | None:
    """Return the ledger record for `finding_id`, or None if not registered."""
    fid = (finding_id or "").strip().upper()
    if not fid:
        return None
    ledger = _id_ledger_load(scratchpad)
    for record in ledger.get("allocations", []):
        if record.get("id", "").upper() == fid:
            return record
    return None


def id_ledger_all_for_prefix(scratchpad: Path, prefix: str) -> list[dict]:
    """Return all ledger records whose ID has the given prefix."""
    ledger = _id_ledger_load(scratchpad)
    return [r for r in ledger.get("allocations", [])
            if r.get("id", "").upper().startswith(prefix.upper())]


def id_ledger_all_records(scratchpad: Path) -> list[dict]:
    """Return all ledger records (sorted by allocated_at)."""
    ledger = _id_ledger_load(scratchpad)
    records = list(ledger.get("allocations", []))
    records.sort(key=lambda r: r.get("allocated_at", ""))
    return records


def _judge_source_fingerprint(src: Path) -> dict:
    """v2.0.5 (P0.2, Codex fix 2): identity record for the source markdown
    that lets the sidecar reader detect changes within the same mtime
    second.

    Returns `{source_mtime_ns: int, source_sha256: str, source_size: int}`.
    Used by both writer (stored in JSON) and reader (compared to current
    source state). All three fields must match for the sidecar to be
    trusted.
    """
    import hashlib
    try:
        stat = src.stat()
        data = src.read_bytes()
    except OSError:
        return {}
    return {
        "source_mtime_ns": stat.st_mtime_ns,
        "source_sha256": hashlib.sha256(data).hexdigest(),
        "source_size": stat.st_size,
    }


def write_judge_decisions_json_sidecar(scratchpad: Path) -> int:
    """v2.0.5 (P0.2): write `{scratchpad}/judge_decisions.json` from the
    table format of `skeptic_judge_decisions.md`.

    Idempotent: if the JSON sidecar already exists and matches what
    would be written, leaves it alone (preserves mtime). The JSON is
    the canonical machine-readable source — consumers prefer it over
    re-parsing the markdown.

    Codex hardening (P0.2): the sidecar embeds `source_mtime_ns` and
    `source_sha256` so the reader can detect changes within the same
    mtime second (the previous 1-second tolerance silently returned
    stale data when the source was rewritten immediately after the
    sidecar was created).

    Returns the number of decisions written (0 if no source file, no
    valid table rows, or write failed).

    Schema: `plamen.judge_decisions.v1`.
    """
    src = scratchpad / "skeptic_judge_decisions.md"
    if not src.exists():
        return 0
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    rows = _parse_skeptic_judge_table(text)
    if not rows:
        return 0
    decisions = []
    for r in rows:
        decisions.append({
            "finding_id": r["finding_id"],
            "original_severity": r["original_severity"],
            "final_severity": r["final_severity"],
            "decision": r["decision"],
            "rationale": r["rationale"],
        })
    fingerprint = _judge_source_fingerprint(src)
    payload = {
        "schema_version": "plamen.judge_decisions.v1",
        "source_markdown": src.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "row_count": len(decisions),
        "decisions": decisions,
        # Codex fix 2: identity fingerprint of the source markdown.
        "source_mtime_ns": fingerprint.get("source_mtime_ns"),
        "source_sha256": fingerprint.get("source_sha256"),
        "source_size": fingerprint.get("source_size"),
    }
    sidecar = scratchpad / "judge_decisions.json"
    content = json.dumps(payload, indent=2, sort_keys=True)
    if sidecar.exists():
        try:
            existing = sidecar.read_text(encoding="utf-8", errors="replace")
            # Strip the `generated_at` field for content-equality check so
            # idempotent re-writes don't bump mtime needlessly. Also
            # normalize trailing whitespace — the writer appends "\n";
            # the in-memory `content` doesn't have it yet.
            import re as _re
            def _norm(s: str) -> str:
                return _re.sub(
                    r'"generated_at":\s*"[^"]*"',
                    '"generated_at": "<ts>"',
                    s,
                ).rstrip()
            if _norm(existing) == _norm(content):
                return len(decisions)
        except Exception:
            pass
    try:
        sidecar.write_text(content + "\n", encoding="utf-8")
    except OSError:
        return 0
    return len(decisions)


def read_judge_decisions_json_sidecar(scratchpad: Path) -> list[dict]:
    """v2.0.5 (P0.2): read `judge_decisions.json` if present AND the
    embedded source fingerprint matches the current
    `skeptic_judge_decisions.md`. Returns [] otherwise (caller falls
    back to markdown parsing).

    Codex hardening: pre-Codex this function used a 1-second mtime
    tolerance which accepted stale sidecars when the source was
    rewritten immediately after sidecar creation. The new check
    compares (mtime_ns, size, sha256) — accepts only on EXACT match.
    Legacy sidecars without fingerprint fields are rejected (caller
    re-writes them via the writer above).
    """
    sidecar = scratchpad / "judge_decisions.json"
    src = scratchpad / "skeptic_judge_decisions.md"
    if not sidecar.exists():
        return []
    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    if payload.get("schema_version") != "plamen.judge_decisions.v1":
        return []
    # Codex fix 2: require the embedded source fingerprint to match the
    # current source markdown. If any field is missing (legacy sidecar)
    # or differs (source was rewritten), reject the sidecar so the
    # caller falls back to MD parsing.
    if src.exists():
        current = _judge_source_fingerprint(src)
        for k in ("source_mtime_ns", "source_sha256", "source_size"):
            if payload.get(k) != current.get(k):
                return []
    else:
        # Source missing but sidecar exists — accept the sidecar
        # (the gate caller will fall through and handle the missing
        # source separately).
        pass
    decisions = payload.get("decisions")
    if not isinstance(decisions, list):
        return []
    return decisions


def _read_queue_json_sidecar(path: Path) -> list[dict[str, str]]:
    sidecar = _queue_sidecar_path(path)
    if not sidecar.exists():
        return []
    try:
        payload = json.loads(sidecar.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if payload.get("schema_version") != "plamen.verification_queue.v1":
        return []
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return []
    out: list[dict[str, str]] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        row = {str(k): str(v) for k, v in item.items()}
        fid = _normalize_finding_id(row.get("finding id", "")) or row.get("finding id", "").strip()
        if not fid:
            continue
        row["finding id"] = fid
        row["severity"] = normalize_severity(row.get("severity", "") or "Medium")
        out.append(row)
    declared = payload.get("row_count")
    if isinstance(declared, int) and declared != len(out):
        log.warning(
            "%s row_count mismatch in JSON sidecar: declared=%s parsed=%s",
            sidecar.name, declared, len(out),
        )
    return out


def _write_queue_subset_manifest(path: Path, rows: list[dict[str, str]]):
    rows = _canonical_queue_rows(rows)
    header = (
        "# Verification Queue Manifest\n"
        "| Queue # | Finding ID | Expected Output File | Severity | Title | Bug Class | Preferred Tag | Location | Primary Artifact | PoC Class |\n"
        "|---------|------------|----------------------|----------|-------|-----------|---------------|----------|------------------|-----------|\n"
    )
    body = []
    for row in rows:
        fid = row.get("finding id", "")
        body.append(
            "| {queue} | {finding} | verify_{finding}.md | {severity} | {title} | {bug_class} | {tag} | {location} | {artifact} | {poc_class} |".format(
                queue=row.get("queue #", ""),
                finding=fid,
                severity=row.get("severity", ""),
                title=row.get("title", ""),
                bug_class=row.get("bug class", ""),
                tag=row.get("preferred tag", ""),
                location=row.get("location", ""),
                artifact=row.get("primary artifact", ""),
                poc_class=row.get("poc class", "structural"),
            )
        )
    footer = (
        f"\nTotal: {len(rows)} findings | Expected verify_<ID>.md files: {len(rows)}\n"
    )
    content = header + "\n".join(body) + footer
    if path.exists():
        try:
            if path.read_text(encoding="utf-8", errors="replace") == content:
                _write_queue_json_sidecar(path, rows, kind="active")
                return
        except Exception:
            pass
    path.write_text(content, encoding="utf-8")
    _write_queue_json_sidecar(path, rows, kind="active")


def _write_queue_excluded_manifest(path: Path, rows: list[dict[str, str]]):
    """Write the explicit non-active side of the verification route."""
    rows = _canonical_queue_rows(rows)
    header = (
        "# Verification Queue Evidence-Excluded\n"
        "| Finding ID | Severity | Title | Exclusion Reason |\n"
        "|------------|----------|-------|------------------|\n"
    )
    body = []
    for row in rows:
        body.append(
            "| {finding} | {severity} | {title} | {reason} |".format(
                finding=row.get("finding id", ""),
                severity=row.get("severity", ""),
                title=row.get("title", ""),
                reason=row.get("exclusion reason", "Excluded from active verification"),
            )
        )
    footer = f"\nTotal: {len(rows)} excluded finding(s)\n"
    content = header + "\n".join(body) + footer
    if path.exists():
        try:
            if path.read_text(encoding="utf-8", errors="replace") == content:
                _write_queue_json_sidecar(path, rows, kind="excluded")
                return
        except Exception:
            pass
    path.write_text(content, encoding="utf-8")
    _write_queue_json_sidecar(path, rows, kind="excluded")


def ensure_verify_shard_manifests(scratchpad: Path) -> dict[str, list[dict[str, str]]]:
    shards = compute_verify_shards(scratchpad)
    for phase_name, rows in shards.items():
        _write_queue_subset_manifest(scratchpad / L1_VERIFY_SHARD_MANIFESTS[phase_name], rows)
    return shards


def compute_sc_verify_shards(scratchpad: Path) -> dict[str, list[dict[str, str]]]:
    """SC variant of compute_verify_shards with SC-prefixed phase names."""
    rows = parse_verification_queue_rows(scratchpad)
    crit_high = [r for r in rows if _severity_bucket(r.get("severity", "")) in {"critical", "high"}]
    medium = [r for r in rows if _severity_bucket(r.get("severity", "")) == "medium"]
    low_info = [
        r for r in rows
        if _severity_bucket(r.get("severity", "")) in {"low", "info"}
    ]
    def assign_chunks(names: list[str], items: list[dict[str, str]], target: int) -> dict[str, list[dict[str, str]]]:
        out = {name: [] for name in names}
        if not items:
            return out
        chunk_count = min(len(names), max(1, math.ceil(len(items) / max(target, 1))))
        idx = 0
        for i, name in enumerate(names[:chunk_count]):
            remaining_chunks = chunk_count - i
            remaining_items = len(items) - idx
            take = math.ceil(remaining_items / max(remaining_chunks, 1))
            out[name] = items[idx:idx + take]
            idx += take
        if idx < len(items):
            out[names[-1]].extend(items[idx:])
        return out

    shards = {}
    shards.update(assign_chunks(
        list(SC_VERIFY_CRITHIGH_PHASE_NAMES),
        crit_high,
        VERIFY_TARGET_PER_SHARD,
    ))
    sc_medium_names = [k for k in SC_VERIFY_SHARD_MANIFESTS if k.startswith("sc_verify_medium")]
    sc_low_names = [k for k in SC_VERIFY_SHARD_MANIFESTS if k.startswith("sc_verify_low")]
    shards.update(assign_chunks(sc_medium_names, medium, VERIFY_TARGET_PER_SHARD))
    shards.update(assign_chunks(sc_low_names, low_info, VERIFY_TARGET_PER_SHARD))
    return shards


def ensure_sc_verify_shard_manifests(scratchpad: Path) -> dict[str, list[dict[str, str]]]:
    shards = compute_sc_verify_shards(scratchpad)
    for phase_name, rows in shards.items():
        _write_queue_subset_manifest(scratchpad / SC_VERIFY_SHARD_MANIFESTS[phase_name], rows)
    return shards


_POC_KW_BOUNDARY_CACHE: dict[str, re.Pattern] = {}


def _poc_kw_present(pattern: str, *texts: str) -> bool:
    """Word-boundary + negation-aware keyword presence for PoC classification.

    Replaces the legacy bare `pattern in text` substring test (which produced
    two failure modes the plan calls out):

      * NO WORD BOUNDARY — a narrow-unit keyword like `overflow` matched inside
        an unrelated longer word, and broad nouns matched substrings.
      * NO NEGATION AWARENESS — "no overflow check" / "without overflow" hit the
        `overflow` keyword and routed the finding to `narrow_unit`, demanding an
        impossible single-call unit harness for what is actually a MISSING-check
        bug. When the keyword is governed by a negation in its own clause, the
        keyword is NOT asserting the mechanism is present, so it must not drive
        the testable-class routing.

    A keyword that itself contains a space/hyphen (a multi-word phrase, already
    specific) is matched as a tolerant substring (whitespace/hyphen-insensitive)
    — these never over-fired on a single-word boundary. Single bare-word
    keywords are matched with `\\b` boundaries.

    Recall-direction: suppressing a NEGATED narrow-unit/property keyword routes
    the finding toward `structural` (the default), which never demands a
    mandatory unit/property PoC — so this can only RELAX an over-strict PoC
    demand, never drop a finding or add an unwinnable retry.
    """
    rx = _POC_KW_BOUNDARY_CACHE.get(pattern)
    if rx is None:
        has_space = " " in pattern or "-" in pattern
        if has_space:
            # Tolerant phrase match: a space/hyphen in the pattern matches any
            # run of spaces/hyphens in the text, so "off-by-one" matches
            # "off by one" and vice versa. Boundary-anchored at both ends.
            # Build from the RAW pattern (split on space/hyphen, re.escape each
            # word, rejoin with a space/hyphen class) to avoid replacement-string
            # escaping hazards.
            words = [w for w in re.split(r"[\s\-]+", pattern) if w]
            inner = r"[\s\-]+".join(re.escape(w) for w in words)
            rx = re.compile(r"(?<!\w)" + inner + r"(?!\w)", re.IGNORECASE)
        else:
            # Whole-word stem: "overflow" matches "overflow"/"overflows" but not
            # an embedded substring inside an unrelated word.
            rx = re.compile(r"(?<!\w)" + re.escape(pattern) + r"\w*", re.IGNORECASE)
        _POC_KW_BOUNDARY_CACHE[pattern] = rx
    for text in texts:
        if not text:
            continue
        km = rx.search(text)
        if not km:
            continue
        # Negation guard: if the keyword occurrence is governed by a negation in
        # its clause, it is not asserting the mechanism is present.
        if _negation_governs_keyword(text, re.compile(re.escape(km.group(0)), re.IGNORECASE)):
            continue
        return True
    return False


# Resource-exhaustion / executable-harm vocabulary (GENERIC words only — no
# protocol/contract/function names). A finding describing unbounded input, a
# gas bomb / gas griefing, an out-of-gas / unbounded-loop DoS, storage bloat, or
# balance double-counting HAS a concrete executable harm assertion (gas /
# iteration explosion, accounting drift). Such a finding must NOT fall through
# to a structural / CODE-TRACE "no executable harm" no-PoC disposition: that is
# the exact escape that let a deriver-injected gas-bomb finding be refuted with
# no PoC. Matching is negation-aware via `_poc_kw_present` so "no unbounded loop
# exists" does NOT trigger.
RESOURCE_EXHAUSTION_PATTERNS = [
    "unbounded",
    "no length bound", "no size limit", "no length limit",
    "no size or length limit",
    "gas bomb", "gas griefing",
    "out of gas", "oog",
    "unbounded loop", "iterates over",
    "unbounded array", "unbounded string", "unbounded bytes", "unbounded storage",
    "storage bloat",
    "dos via", "denial of service",
    "exhaust gas", "exhaust memory",
    "balance drain", "double-count", "double count",
]


def _matches_resource_exhaustion(*texts: str) -> bool:
    """True iff any *text* asserts a resource-exhaustion / executable-harm
    mechanism from `RESOURCE_EXHAUSTION_PATTERNS`.

    Negation-aware via the shared `_poc_kw_present` guard (so a negated mention
    like "no unbounded loop exists" does NOT match). Recall-direction: a match
    only ever routes a finding TOWARD a testable class / keeps it in the body,
    never drops it.
    """
    return any(_poc_kw_present(p, *texts) for p in RESOURCE_EXHAUSTION_PATTERNS)



# L1-only: bug classes whose harm is a race / non-determinism / Byzantine
# divergence. Per prompts/l1/phase5-verification-prompt.md ("Non-determinism
# findings" section, `[NON-DET-PASS]` via repeated execution) and
# docs/l1-mode/design.md Section 8.2 ("Non-determinism findings -> try
# [NON-DET-PASS] via repeated execution"; "Consensus invariant findings -> try
# [CONFORMANCE-PASS]"), these classes have a MECHANIZED L1 evidence path and
# `[CODE-TRACE]` alone is INSUFFICIENT for High/Critical verdicts on them (that
# prompt's scoring rule caps CODE-TRACE-only evidence at CONTESTED). They must
# NOT fall into the zero-PoC `structural` bucket the way genuinely untestable
# L1 classes (timing/crash-recovery/cross-client/eclipse/network-partition,
# explicitly named as untestable in phase5-verification-prompt.md's
# `poc_class: structural` section) legitimately do. GENERIC bug-class
# vocabulary only — no protocol/chain names.
_L1_NONDETERMINISM_PATTERNS = (
    "race condition", "data race", "non-determinism", "nondeterminism",
    "byzantine",
)


def _matches_l1_nondeterminism_class(*texts: str) -> bool:
    """True iff any *text* names a race/non-determinism/Byzantine bug class."""
    return any(p in t for t in texts for p in _L1_NONDETERMINISM_PATTERNS)


def classify_poc_testability(
    bug_class: str,
    preferred_tag: str,
    title: str,
    severity: str,
    pipeline: str = "",
) -> str:
    """Classify a finding's testability for PoC routing.

    Returns one of: 'unit', 'property', 'integration', 'structural'

    This is MECHANICAL — no LLM needed. Pattern-match on bug class + keywords.

    `pipeline` is an OPTIONAL signal ("l1" for the Go/Rust node-client lane,
    "sc"/"" for everything else). It defaults to "" so every existing caller
    (none of which currently pass it) is byte-identical to prior behavior.
    When pipeline == "l1", race/non-determinism/Byzantine bug classes route to
    `property` instead of `structural` — see `_L1_NONDETERMINISM_PATTERNS`
    above. SC pipelines never take this branch.
    """
    bc = (bug_class or "").lower()
    tag = (preferred_tag or "").lower()
    title_lc = (title or "").lower()
    pipeline_lc = (pipeline or "").lower()

    structural_patterns = [
        "toctou", "crash-recovery", "crash recovery", "timing", "race condition",
        "cross-client", "non-determinism", "nondeterminism", "eclipse",
        "network partition", "byzantine",
        "missing setter", "no admin setter", "has no admin setter",
        "no setter", "missing function", "absent function",
        "event emission missing", "missing event", "no event",
        "event missing", "without emitting events", "without event",
        "emit no event", "emits no event", "no events",
        "no admin setter", "missing admin setter", "without a setter",
    ]
    if any(p in bc or p in title_lc for p in structural_patterns):
        if "map" in title_lc and ("iter" in title_lc or "order" in title_lc):
            return "property"
        try:
            if pipeline_lc == "l1" and _matches_l1_nondeterminism_class(bc, title_lc):
                return "property"
        except Exception:
            pass
        return "structural"

    # VERIF-3: property/accounting/invariant bugs are multi-step and must be
    # property-class, not unit -- mislabeling them 'unit' forces an impossible
    # single-call harness and a false mandatory-PoC demand. Property is defined
    # BEFORE unit so a unit match via a BROAD noun (fee/share/deposit/...) that
    # CO-OCCURS with a strong property signal routes to property. NARROW,
    # unambiguous unit signals (overflow, access control, onlyOwner, ...) always
    # win regardless.
    property_patterns = [
        "state corruption", "invariant", "accumulator", "counter",
        "monotonic", "idempotent", "commutativ",
        "reentrancy", "accounting", "liquidation", "oracle", "price",
        "collateral", "debt", "ltv", "solvency", "interest", "reward",
        "custody", "escrow", "residual", "dust", "share price",
    ]
    narrow_unit_patterns = [
        "panic", "unwrap", "overflow", "underflow", "arithmetic",
        "validation", "bounds check", "off-by-one", "division by zero",
        "index out of", "assertion", "type cast", "truncat",
        "access control", "permission", "onlyowner", "only owner",
        "onlycreator", "unauthorized", "public withdraw", "missing guard",
        "slippage", "minout", "min out", "minreturn", "min return",
    ]
    broad_unit_nouns = [
        "fee", "rounding", "share", "deposit", "withdraw", "approve",
        "allowance", "transferfrom", "transfer from",
    ]
    # Word-boundary + negation-aware matching for the TESTABLE-class keyword
    # scans (narrow-unit / broad-unit / property). A negated mechanism keyword
    # ("no overflow check", "without reentrancy") must NOT route the finding to
    # an impossible unit/property harness — it falls through to structural,
    # which is recall-safe (structural never demands a mandatory PoC). The
    # structural_patterns scan above is INTENTIONALLY left as substring match:
    # several of its patterns ARE negated phrases ("no event", "missing setter")
    # that legitimately describe structural bugs.
    narrow_unit_hit = any(_poc_kw_present(p, bc, title_lc) for p in narrow_unit_patterns)
    broad_unit_hit = any(_poc_kw_present(p, bc, title_lc) for p in broad_unit_nouns)
    property_hit = any(_poc_kw_present(p, bc, title_lc) for p in property_patterns)
    if narrow_unit_hit:
        return "unit"
    if broad_unit_hit:
        # A broad financial noun alone is unit; combined with a property signal
        # (accounting/invariant/reward/...) it is a property-class invariant bug.
        return "property" if property_hit else "unit"

    if "poc-pass" in tag or "poc" in tag:
        return "unit"

    if property_hit:
        return "property"

    # Resource-exhaustion / unbounded-input findings carry a concrete executable
    # harm (gas / iteration explosion, accounting drift) and must be testable as
    # a property — NEVER allowed to fall through to the structural / CODE-TRACE
    # no-PoC default below. Narrow-unit signals already returned above, so this
    # preserves narrow-unit precedence. Negation-aware via the shared guard.
    if _matches_resource_exhaustion(bc, title_lc):
        return "property"

    if "fuzz" in tag or "non-det" in tag:
        return "property"

    integration_patterns = [
        "rpc", "network", "p2p", "multi-component", "integration",
        "handshake", "connection", "endpoint", "api surface",
    ]
    if any(p in bc or p in title_lc for p in integration_patterns):
        return "integration"

    if "lsp" in tag or "code-trace" in tag:
        return "structural"

    return "structural"


def _read_pipeline_from_config(scratchpad: Path) -> str:
    """Read 'pipeline' from {scratchpad}/config.json. Returns '' if absent.

    Mirrors plamen_validators._read_language_from_config. Try/except-safe:
    any I/O/parse failure degrades to '' (== current, pre-existing behavior).
    """
    try:
        import json as _json
        cfg_path = scratchpad / "config.json"
        if cfg_path.exists():
            return _json.loads(
                cfg_path.read_text(encoding="utf-8", errors="replace")
            ).get("pipeline", "") or ""
    except Exception:
        pass
    return ""


def _queue_rows_from_inventory_with_exclusions(
    scratchpad: Path,
    pipeline: str = "",
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Convert inventory blocks into active and evidence-excluded queue rows.

    The verification queue is a routing artifact, not a reasoning task. Letting
    an LLM summarize it caused catastrophic over-cutting: a prior L1 run had
    276 inventory IDs but the queue agent emitted only 20 rows plus a prose
    placeholder. This function makes promotion loss mechanically impossible by
    routing every parsed inventory block to exactly one route.

    `pipeline` is OPTIONAL ("l1" or "sc"/""). When not supplied by the caller
    (every existing caller today), it is auto-detected from
    `{scratchpad}/config.json`'s "pipeline" field via `_read_pipeline_from_config`
    — degrading to "" (== prior behavior, byte-identical for SC) if the file or
    field is absent. This lets `classify_poc_testability` apply the L1-only
    non-determinism/race/Byzantine reroute (see `_matches_l1_nondeterminism_class`)
    without requiring every call site to be touched.
    """
    resolved_pipeline = pipeline or _read_pipeline_from_config(scratchpad)
    inv_path = scratchpad / "findings_inventory.md"
    if not inv_path.exists():
        return [], []
    try:
        blocks = _inventory_blocks(_llm_norm(inv_path.read_text(encoding="utf-8", errors="replace")))
    except Exception:
        return [], []
    rows: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    seen: set[str] = set()
    for block in blocks:
        fid = _normalize_finding_id(block.get("id", ""))
        if not fid or fid in seen:
            continue
        raw = block.get("block", "")
        verdict = _field_from_markdown(raw, ("Verdict", "Final Verdict", "Status"))
        seen.add(fid)
        severity = _severity_name_from_text(raw, {})
        preferred = (
            _field_from_markdown(raw, ("Preferred Tag", "Preferred Evidence", "Evidence Tag"))
            or "CODE-TRACE"
        )
        bug_class = (
            _field_from_markdown(raw, ("Bug Class", "Root Cause", "Class", "Category"))
            or block.get("title", "")
            or "Unclassified"
        )
        source = (
            block.get("source_ids", "")
            or _field_from_markdown(raw, ("Primary Artifact", "Source Artifact", "Artifact"))
            or "findings_inventory.md"
        )
        title_val = block.get("title", "") or fid
        bug_class_val = _strip_md(bug_class)
        preferred_tag_val = _strip_md(preferred).strip("[]") or "CODE-TRACE"
        poc_class = classify_poc_testability(
            bug_class_val, preferred_tag_val, title_val, severity, resolved_pipeline
        )
        rows.append({
            "queue #": str(len(rows) + 1),
            "finding id": fid,
            "severity": severity,
            "title": title_val,
            "bug class": bug_class_val,
            "preferred tag": preferred_tag_val,
            "location": block.get("location", "") or _field_from_markdown(raw, ("Location", "Locations")),
            "primary artifact": _strip_md(source),
            "poc class": poc_class,
        })
        if verdict:
            status = _verifier_status_from_text(f"**Verdict**: {verdict}")
            if not _is_reportable_verdict(status):
                rows[-1]["exclusion reason"] = f"Inventory verdict {status}"
                excluded.append(rows.pop())
    return rows, excluded


def _queue_rows_from_inventory(scratchpad: Path) -> list[dict[str, str]]:
    """Convert reportable inventory blocks into canonical verification rows."""
    rows, _excluded = _queue_rows_from_inventory_with_exclusions(scratchpad)
    return rows


def _write_mechanical_verification_queue_from_inventory(scratchpad: Path) -> int:
    """Write verification_queue.md directly from findings_inventory.md."""
    rows, excluded = _queue_rows_from_inventory_with_exclusions(scratchpad)
    _write_queue_subset_manifest(scratchpad / "verification_queue.md", rows)
    _write_queue_excluded_manifest(
        scratchpad / "verification_queue_evidence_excluded.md",
        excluded,
    )
    return len(rows)


def _filter_verification_queue_by_mode(
    scratchpad: Path,
    mode: str,
    *,
    pipeline_label: str,
) -> int:
    """Remove Low/Info rows from active verification outside Thorough mode.

    Low verifier shards only exist in Thorough mode for both SC and L1. Keeping
    Low/Info rows in the active queue for Light/Core creates an impossible
    contract: no phase owns their `verify_<ID>.md` files, but aggregate parity
    still expects them.
    Preserve traceability by moving them to the explicit evidence-excluded
    sidecar/markdown artifact instead of silently dropping them.
    """
    if mode == "thorough":
        return 0
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return 0
    keep: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    for row in rows:
        bucket = _severity_bucket(row.get("severity", ""))
        if bucket in {"low", "info"}:
            item = dict(row)
            item["exclusion reason"] = (
                f"Excluded from active {pipeline_label} verification in {mode} mode "
                "(Low/Info verify shards run only in Thorough mode)"
            )
            excluded.append(item)
        else:
            keep.append(row)
    if not excluded:
        return 0
    existing_excluded = _read_queue_json_sidecar(
        scratchpad / "verification_queue_evidence_excluded.md"
    )
    seen = {r.get("finding id", "") for r in existing_excluded}
    combined = list(existing_excluded)
    for row in excluded:
        fid = row.get("finding id", "")
        if fid and fid not in seen:
            combined.append(row)
            seen.add(fid)
    _write_queue_subset_manifest(scratchpad / "verification_queue.md", keep)
    _write_queue_excluded_manifest(
        scratchpad / "verification_queue_evidence_excluded.md",
        combined,
    )
    return len(excluded)


def _filter_sc_verification_queue_by_mode(scratchpad: Path, mode: str) -> int:
    """Backward-compatible SC wrapper used by existing tests/imports."""
    return _filter_verification_queue_by_mode(
        scratchpad,
        mode,
        pipeline_label="SC",
    )


# ---------------------------------------------------------------------------
# v2.4.8: Hypothesis-aware verify queue dedup
# ---------------------------------------------------------------------------

_HYPO_HEADING_RE = re.compile(
    r"^\s*#{2,4}\s+"
    r"(?:(?:Chain\s+)?Hypothesis\s+|Finding\s+\[?)?"
    r"(" + HYPOTHESIS_ID_PATTERN + r")" + _ASCII_ID_RIGHT,
    re.MULTILINE | re.IGNORECASE | re.ASCII,
)


def _record_finding_mapping_parse_health(
    scratchpad: Path,
    text: str,
    parsed_rows: list[dict[str, object]],
) -> None:
    """Surface every rejected mapping row without guessing relation edges.

    A table with the typed source/hypothesis header contract is checked row by
    row using the same strict cell grammar as the authoritative parser.  Any
    nonempty row that the parser refuses is loud, including a malformed row
    beside valid relations.  Separately, the narrow legacy/headerless signal is
    preserved for rows whose first two cells are already complete IDs.  This
    function records parse health only; it never returns or manufactures an
    edge.
    """
    sentinel = scratchpad / "finding_mapping_parse.degraded"
    lines = _llm_norm(text).splitlines()
    typed_rejected = 0
    typed_data_lines: set[int] = set()

    i = 0
    while i + 1 < len(lines):
        header_line = lines[i].strip()
        separator_line = lines[i + 1].strip()
        if not header_line.startswith("|") or not _is_separator_row(separator_line):
            i += 1
            continue
        headers = [
            _normalize_manifest_header(cell)
            for cell in _split_markdown_table_row(header_line)
        ]
        source_idx = _finding_mapping_role_index(headers, "source")
        hypothesis_idx = _finding_mapping_role_index(headers, "hypothesis")
        if (
            source_idx is None
            or hypothesis_idx is None
            or source_idx == hypothesis_idx
        ):
            i += 2
            continue

        j = i + 2
        while j < len(lines):
            row_line = lines[j].strip()
            if not row_line.startswith("|"):
                break
            if j + 1 < len(lines) and _is_separator_row(lines[j + 1].strip()):
                break
            if _is_separator_row(row_line):
                j += 1
                continue
            typed_data_lines.add(j)
            cells = _split_markdown_table_row(row_line)
            if not any(_strip_md(cell).strip() for cell in cells):
                j += 1
                continue
            if max(source_idx, hypothesis_idx) >= len(cells):
                typed_rejected += 1
                j += 1
                continue
            source_ids = _finding_mapping_cell_ids(
                cells[source_idx], hypothesis=False
            )
            hypothesis_ids = _finding_mapping_cell_ids(
                cells[hypothesis_idx], hypothesis=True
            )
            if not source_ids or not hypothesis_ids:
                typed_rejected += 1
            j += 1
        i = max(j, i + 2)

    headerless_candidates = 0
    for line_index, line in enumerate(lines):
        if line_index in typed_data_lines:
            continue
        stripped = line.strip()
        if not stripped.startswith("|") or _is_separator_row(stripped):
            continue
        cells = _split_markdown_table_row(stripped)
        if len(cells) < 2:
            continue
        if (
            _finding_mapping_cell_ids(cells[0], hypothesis=False)
            and _finding_mapping_cell_ids(cells[1], hypothesis=True)
        ):
            headerless_candidates += 1

    if typed_rejected or headerless_candidates:
        try:
            sentinel.write_text(
                "Status: DEGRADED_UNTYPED_MAPPING\n"
                f"Accepted typed relation rows: {len(parsed_rows)}\n"
                f"Typed mapping rejected data rows: {typed_rejected}\n"
                f"Headerless candidate relation rows: {headerless_candidates}\n"
                "No relation was inferred from rejected rows. Repair malformed "
                "cells or the Markdown header and separator.\n",
                encoding="utf-8",
            )
        except OSError:
            pass
    elif sentinel.exists():
        try:
            sentinel.unlink()
        except OSError:
            pass


def _parse_hypothesis_constituents(
    scratchpad: Path,
    standalone_severities: dict[str, str] | None = None,
    *,
    include_split_parent_aliases: bool = False,
) -> dict[str, list[str]]:
    """Parse hypothesis → constituent finding ID mapping.

    Tries finding_mapping.md first (table: constituent → hypothesis).
    Falls back to hypotheses.md (section headings + body scan for INV-* IDs).
    Returns {hypothesis_id: [constituent_id, ...]}. By default this contains
    only exact active owners. ``include_split_parent_aliases=True`` adds the
    union under an explicitly declared pre-split parent for lookup consumers
    such as R10; enumeration, repair, coverage, and anti-absorption callers
    must use the default so a retired parent cannot be re-minted.

    ``standalone_severities`` ({finding ID: severity} for findings that appear as
    their own rows) is forwarded to ``_parse_chain_constituents`` so a "justified"
    chain that double-counts standalone constituents (without genuinely elevating
    severity) is still linked for collapse (precision fix #2).
    """
    mapping: dict[str, list[str]] = {}
    split_parent_children: dict[str, list[str]] = {}

    def _finalize_split_identity() -> dict[str, list[str]]:
        """Remove retired parents from active identity; optionally add unions.

        The union is derived only after every exact child source has merged, so
        later typed tables and hypotheses/chain links cannot be omitted. Any
        stale parent section in hypotheses.md is replaced, never extended.
        """
        for parent_id, child_ids in split_parent_children.items():
            mapping.pop(parent_id, None)
            if not include_split_parent_aliases:
                continue
            union: list[str] = []
            for child_id in child_ids:
                for source_id in mapping.get(child_id, []):
                    if source_id not in union:
                        union.append(source_id)
            if union:
                mapping[parent_id] = union
        return mapping

    # --- Source 1: finding_mapping.md (preferred, written by Chain Agent 1)
    fm = scratchpad / "finding_mapping.md"
    if fm.exists():
        try:
            text = _llm_norm(fm.read_text(encoding="utf-8", errors="replace"))
            parsed_mapping_rows = parse_finding_mapping_rows(text)
            _record_finding_mapping_parse_health(
                scratchpad, text, parsed_mapping_rows
            )
            for row in parsed_mapping_rows:
                source_ids = [str(fid).upper() for fid in row["source_ids"]]
                hypothesis_ids = [
                    str(fid).upper() for fid in row["hypothesis_ids"]
                ]
                # Child split IDs own their exact constituents. The original
                # parent remains only a union lookup alias so pre-split R10 and
                # report references still resolve. No arbitrary status/Notes
                # cell scanning is permitted to manufacture that relation.
                for hypothesis_id in hypothesis_ids:
                    existing = mapping.setdefault(hypothesis_id, [])
                    existing.extend(
                        fid for fid in source_ids if fid not in existing
                    )
                parent_id = parse_split_parent_hypothesis_id(
                    str(row.get("status", ""))
                )
                if parent_id:
                    children = split_parent_children.setdefault(parent_id, [])
                    for hypothesis_id in hypothesis_ids:
                        if hypothesis_id != parent_id and hypothesis_id not in children:
                            children.append(hypothesis_id)
        except Exception:
            pass

    # --- Source 3 (chain): ingest chain_hypotheses.md mapping so a chain row
    # collapses with its constituent standalone rows. Run this UNCONDITIONALLY,
    # before any early return, so it applies even when hypotheses.md is absent.
    # Justified compound chains are excluded by _parse_chain_constituents.
    def _merge_chain_links() -> None:
        try:
            chain_links = _parse_chain_constituents(scratchpad, standalone_severities)
        except Exception:
            return
        for chain_id, constituents in chain_links.items():
            if not constituents:
                continue
            existing = mapping.setdefault(chain_id, [])
            for cid in constituents:
                if cid != chain_id and cid not in existing:
                    existing.append(cid)

    # --- Source 2: hypotheses.md (section-based parse)
    hyp = scratchpad / "hypotheses.md"
    if not hyp.exists():
        _merge_chain_links()
        return _finalize_split_identity()
    try:
        text = _llm_norm(hyp.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        _merge_chain_links()
        return _finalize_split_identity()

    # Source 2a: hypotheses.md tables. Chain hypotheses are commonly table
    # rows (`CH-1 | ... | H-10, H-11 | ...`) rather than section headings.
    # Do not skip this just because finding_mapping.md produced H->INV rows.
    try:
        for headers, rows in _parse_markdown_tables(text, ["Hypothesis ID", "Source Findings"]):
            keys = [_norm_key(h) for h in headers]
            h_idx = keys.index("hypothesis id") if "hypothesis id" in keys else -1
            s_idx = keys.index("source findings") if "source findings" in keys else -1
            if h_idx < 0 or s_idx < 0:
                continue
            for row in rows:
                if max(h_idx, s_idx) >= len(row):
                    continue
                hypo_id = _normalize_hypothesis_id_token(row[h_idx])
                if not hypo_id:
                    continue
                constituents: list[str] = []
                for m in _INTERNAL_ID_RE.finditer(row[s_idx]):
                    fid = m.group(1).upper()
                    if fid != hypo_id and fid not in constituents:
                        constituents.append(fid)
                if constituents:
                    existing = mapping.setdefault(hypo_id, [])
                    existing.extend(c for c in constituents if c not in existing)
    except Exception:
        pass

    # Source 2b: split by hypothesis headings
    headings = list(_HYPO_HEADING_RE.finditer(text))
    for i, hm in enumerate(headings):
        hypo_id = hm.group(1).upper()
        start = hm.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        section = text[start:end]
        # Extract all non-hypothesis internal IDs from the section body
        constituents: list[str] = []
        for m in _INTERNAL_ID_RE.finditer(section):
            fid = m.group(1).upper()
            if not is_hypothesis_id(fid) and fid not in constituents:
                constituents.append(fid)
        if constituents:
            mapping.setdefault(hypo_id, []).extend(
                c for c in constituents if c not in mapping.get(hypo_id, [])
            )

    # --- Source 3 (chain): merge chain_hypotheses.md links (see closure above).
    _merge_chain_links()

    return _finalize_split_identity()


# Prose anchors per phase4c-chain-prompt.md "Chain Hypothesis Format":
#   ### Blocked Finding (A)
#   - **ID**: [XX-N], ...
#   ### Enabler Finding (B)
#   - **ID**: [YY-M], ...
# plus the machine-parseable line:
#   Constituents: <A>,<B> | Severity-Upgrade-Justified: YES/NO | Combined-Impact: ...
_CHAIN_HYP_HEADING_RE = re.compile(
    r"^#{1,4}\s*Chain\s+Hypothesis\s+(CH-\d+)\b",
    re.MULTILINE | re.IGNORECASE,
)
_CHAIN_BLOCKED_RE = re.compile(
    r"Blocked\s+Finding\s*\(A\)", re.IGNORECASE
)
_CHAIN_ENABLER_RE = re.compile(
    r"Enabler\s+Finding\s*\(B\)", re.IGNORECASE
)
_CHAIN_ID_FIELD_RE = re.compile(
    r"\*\*ID\*\*\s*:\s*\[?\s*(" + _ID_ALL_INTERNAL + r")\s*\]?",
    re.IGNORECASE,
)
_CHAIN_MACHINE_LINE_RE = re.compile(
    r"Constituents\s*:\s*(?P<ids>[^|]+)\|"
    r"\s*Severity-Upgrade-Justified\s*:\s*(?P<just>YES|NO)\b"
    r"(?:\s*\|\s*Combined-Impact\s*:\s*(?P<impact>.*))?",
    re.IGNORECASE,
)


def _chain_severity_upgrade_justified(section: str) -> bool:
    """True when the chain section carries an explicit, justified upgrade.

    Per the STEP 3 guard, a chain is treated as a GENUINE compound finding
    (and therefore NOT linked to its constituents for collapse) only when the
    machine-parseable line shows `Severity-Upgrade-Justified: YES` AND a
    non-empty `Combined-Impact` (not 'NONE'/blank).
    """
    m = _CHAIN_MACHINE_LINE_RE.search(section)
    if not m:
        return False
    if (m.group("just") or "").strip().upper() != "YES":
        return False
    impact = (m.group("impact") or "").strip()
    if not impact:
        return False
    if impact.strip().lower() in ("none", "n/a", "na", "-", "—"):
        return False
    return True


def _parse_chain_constituents(
    scratchpad: Path, standalone_severities: dict[str, str] | None = None
) -> dict[str, list[str]]:
    """Parse chain_hypotheses.md → {chain_id: [Finding A id, Finding B id]}.

    Uses the 'Blocked Finding (A)' / 'Enabler Finding (B)' prose anchors from
    phase4c-chain-prompt.md "Chain Hypothesis Format". A chain whose
    machine-parseable line shows a justified severity upgrade with a non-empty
    Combined-Impact is normally EXCLUDED from the map (genuine compound finding
    — kept separate, never collapsed into a constituent).

    FIX (precision #2): the `Severity-Upgrade-Justified: YES` flag is
    LLM-self-asserted and syntactic — a chain merely writing YES used to be
    exempted from collapse, letting it double-count its constituents (a CH-*
    chain row emitted beside the SAME constituents that ALSO stand alone as
    their own findings). So when ``standalone_severities`` ({id:
    severity}) is supplied and EVERY constituent of a "justified" chain also
    appears as its own standalone finding AND the chain does NOT genuinely
    elevate severity above its constituents (chain tier ≤ max constituent
    tier), the chain is treated as a double-count and LINKED for collapse
    regardless of the YES flag (research-confirmed Case-1 default: both parts
    valid alone ⇒ note the chaining, don't mint a separate entry). A TRUE
    elevation (chain tier strictly above every constituent) is preserved.
    Recall-safe: when any severity is unknown the chain is kept separate.
    Without ``standalone_severities`` the legacy exempt-on-YES behavior holds.

    Empty/unparseable file → {} (no merge = status quo, which is recall-safe).
    """
    chain_path = scratchpad / "chain_hypotheses.md"
    if not chain_path.exists():
        return {}
    try:
        text = _llm_norm(chain_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}

    out: dict[str, list[str]] = {}
    headings = list(_CHAIN_HYP_HEADING_RE.finditer(text))
    for i, hm in enumerate(headings):
        chain_id = hm.group(1).upper()
        start = hm.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        section = text[start:end]

        # Extract constituents FIRST (needed by the double-count override below).
        constituents: list[str] = []

        # Prefer the explicit Blocked/Enabler anchors (most precise).
        for anchor_re in (_CHAIN_BLOCKED_RE, _CHAIN_ENABLER_RE):
            am = anchor_re.search(section)
            if not am:
                continue
            # The ID field appears on the next bullet after the anchor.
            tail = section[am.end():am.end() + 400]
            idm = _CHAIN_ID_FIELD_RE.search(tail)
            if idm:
                cid = idm.group(1).upper()
                if cid != chain_id and cid not in constituents:
                    constituents.append(cid)

        # Fallback: the machine-parseable Constituents line.
        if not constituents:
            mm = _CHAIN_MACHINE_LINE_RE.search(section)
            if mm:
                for tok in re.split(r"[,\s]+", mm.group("ids") or ""):
                    tok = tok.strip().upper()
                    if tok and re.fullmatch(r"(?:" + _ID_ALL_INTERNAL + r")", tok, re.IGNORECASE):
                        if tok != chain_id and tok not in constituents:
                            constituents.append(tok)

        # Genuine compound finding (justified severity upgrade) → keep separate
        # (do not link) UNLESS it is a pure double-count: every constituent also
        # stands alone AND the chain does NOT actually elevate severity above its
        # constituents (see docstring). A genuine elevation (chain tier strictly
        # above every constituent) is preserved; unknown severities → keep
        # separate (recall-safe).
        if _chain_severity_upgrade_justified(section):
            collapse_double_count = False
            if (standalone_severities and constituents and all(
                    c.upper() in standalone_severities for c in constituents)):
                _sm = re.search(
                    r"Chain\s+Severity\s*:\s*([A-Za-z]+)", section, re.IGNORECASE
                )
                chain_rank = _severity_rank(_sm.group(1)) if _sm else -1
                con_ranks = [
                    _severity_rank(standalone_severities[c.upper()])
                    for c in constituents
                ]
                if (chain_rank >= 0 and all(r >= 0 for r in con_ranks)
                        and chain_rank <= max(con_ranks)):
                    collapse_double_count = True
            if not collapse_double_count:
                continue

        if constituents:
            out[chain_id] = constituents

    return out


_CHAIN_SUMMARY_HEADING_RE = re.compile(
    r"^##\s+Chain\s+Summary\b", re.MULTILINE | re.IGNORECASE
)


def _enumgap_exploration_has_no_obligations(scratchpad: Path) -> bool:
    """Pre-spawn early-exit signal for phase `enumgap_exploration`.

    Returns True when there is nothing to explore — i.e. the enumeration gate
    produced no obligations (the structured `_enumeration_obligations.json` is
    missing or its `obligations` list is empty AND the human-readable
    `enumeration_obligations.md` has no obligation rows). In that case the phase
    is skipped and the pipeline degrades to its prior candidate->verify
    behavior (the gate's ENUMGAP candidates, if any, already sit in the
    inventory).

    Conservative on parse failure: returns False (do NOT skip) so a real
    obligation set is never silently dropped — recall over cost. The phase is
    soft, so a spurious spawn only wastes one sonnet turn.
    """
    try:
        scratchpad = Path(scratchpad)
        jp = scratchpad / "_enumeration_obligations.json"
        if jp.exists():
            try:
                import json as _json
                data = _json.loads(jp.read_text(encoding="utf-8", errors="replace"))
                obl = data.get("obligations") if isinstance(data, dict) else None
                if obl:
                    return False  # have obligations -> run
            except Exception:
                return False  # unparseable -> be safe, run
        md = scratchpad / "enumeration_obligations.md"
        if md.exists():
            try:
                text = md.read_text(encoding="utf-8", errors="replace")
                # an obligation table row is a markdown row that is not the
                # header/separator and names a function in backticks.
                for ln in text.splitlines():
                    s = ln.strip()
                    if (s.startswith("|") and "`" in s
                            and "Function" not in s and "---" not in s):
                        return False
            except Exception:
                return False
        # Neither source shows obligations -> nothing to explore.
        # If NEITHER artifact exists at all, there were no obligations either.
        return True
    except Exception:
        return False


def _chain_iter2_has_no_unexplored_pairs(scratchpad: Path) -> bool:
    """Pre-spawn early-exit signal for phase `chain_iter2`.

    Returns True when there's nothing for iteration 2 to do — i.e. either
    `composition_coverage.md` is missing (chain phase didn't produce it,
    which is itself a soft-degraded state — defer rather than spawn an
    LLM with no input), OR the coverage map's Explored? column shows no
    NO rows that are cross-class AND have at least one Medium+ side.

    Per rules/phase4c-chain-prompt.md ITERATIVE_CHAIN_COMPOSITION:
    "If Agent 2 reported 0 new chains AND 0 unexplored cross-class
    Medium+ pairs → skip iteration 2."

    Conservative on parse failure: returns True (skip) rather than spawn
    an LLM that would then have no work. The soft phase model means a
    false-positive skip is cheap (we lose 0 chains we couldn't find
    anyway); a false-negative spawn wastes ~$1-2 of sonnet time.
    """
    coverage = scratchpad / "composition_coverage.md"
    if not coverage.exists():
        return True
    try:
        text = coverage.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return True
    # Parse the coverage table. Header should include Finding A, Finding B,
    # Explored?, Result, Notes. We look for table rows whose `Explored?`
    # cell is `NO` (case-insensitive) AND at least one severity column on
    # either side mentions Critical/High/Medium. Tolerant of column
    # ordering and exact header wording.
    unexplored_medium_plus = 0
    in_table = False
    header_keys: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("|"):
            in_table = False
            header_keys = []
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and all(set(c) <= {"-", ":", " "} for c in cells):
            # Markdown separator row → previous line was the header.
            continue
        norm = [re.sub(r"[^a-z0-9]+", "", c.lower()) for c in cells]
        if "findinga" in norm or "findingb" in norm or "explored" in norm:
            in_table = True
            header_keys = norm
            continue
        if not in_table or not header_keys:
            continue
        # Look for explored column = NO
        try:
            explored_idx = header_keys.index("explored")
        except ValueError:
            try:
                explored_idx = header_keys.index("exploredq")
            except ValueError:
                continue
        if explored_idx >= len(cells):
            continue
        explored_val = cells[explored_idx].strip().lower()
        if explored_val not in ("no", "n", "false", "pending", "unexplored"):
            continue
        # Severity heuristic: if any cell in the row mentions Critical/High/Medium
        # → count as Medium+ unexplored.
        row_text = " ".join(cells).lower()
        if re.search(r"\b(critical|high|medium)\b", row_text):
            unexplored_medium_plus += 1
            if unexplored_medium_plus > 0:
                return False
    return unexplored_medium_plus == 0


def _extract_chain_summaries_compact(scratchpad: Path) -> int:
    """Extract ## Chain Summary sections from depth/scanner findings into a compact file.

    Writes {scratchpad}/chain_summaries_compact.md. Returns the number of
    source files that contributed at least one section.

    This is the V2 driver's mechanical implementation of the "Pre-Step:
    Chain Summary Extraction" described in phase4c-chain-prompt.md.
    """
    source_globs = [
        "depth_*_findings.md",
        "blind_spot_*_findings.md",
        "scanner_*_findings.md",
        "validation_sweep_findings.md",
        "niche_*_findings.md",
        "design_stress_findings.md",
        "sibling_propagation_findings.md",
        "enumgap_exploration_findings.md",
    ]
    sections: list[str] = []
    contributors = 0
    for glob_pat in source_globs:
        for f in sorted(scratchpad.glob(glob_pat)):
            try:
                text = _llm_norm(f.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
            # Find all ## Chain Summary sections
            matches = list(_CHAIN_SUMMARY_HEADING_RE.finditer(text))
            if not matches:
                continue
            contributors += 1
            for i, m in enumerate(matches):
                start = m.start()
                # Section extends until the next ## heading or EOF
                end_match = re.search(r"^##\s+", text[m.end():], re.MULTILINE)
                end = m.end() + end_match.start() if end_match else len(text)
                section_text = text[start:end].rstrip()
                if section_text:
                    sections.append(f"### Source: {f.name}\n\n{section_text}\n")

    out = scratchpad / "chain_summaries_compact.md"
    if sections:
        out.write_text(
            "# Chain Summaries (extracted by driver)\n\n"
            + "\n---\n\n".join(sections)
            + "\n",
            encoding="utf-8",
        )
    else:
        out.write_text(
            "# Chain Summaries (extracted by driver)\n\n"
            "No ## Chain Summary sections found in depth/scanner artifacts.\n",
            encoding="utf-8",
        )
    return contributors


def _dedup_queue_by_hypothesis(scratchpad: Path) -> int:
    """Collapse verification queue rows that share the same hypothesis.

    For each group of INV-* rows mapping to the same H-N hypothesis,
    keep one representative row (highest severity, hypothesis ID as the
    finding ID). Rewrites verification_queue.md in place.

    Returns the number of rows removed.
    """
    queue_path = scratchpad / "verification_queue.md"
    if not queue_path.exists():
        return 0

    # Read queue rows FIRST so we know which finding IDs stand alone. A
    # "justified" chain whose constituents are ALL standalone rows is a
    # double-count and must still be collapsed (precision fix #2), so the
    # standalone-ID set is threaded into the chain-constituent parse below.
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return 0
    standalone_severities = {
        (row.get("finding id") or "").upper(): (row.get("severity") or "")
        for row in rows
        if (row.get("finding id") or "").strip()
    }

    mapping = _parse_hypothesis_constituents(scratchpad, standalone_severities)
    if not mapping:
        return 0

    # Build a reverse multimap from each constituent to every active hypothesis.
    constituent_to_hypos: dict[str, list[str]] = {}
    for hypo_id, constituents in mapping.items():
        # Map the hypothesis/chain ID to ITSELF so a queue row carrying the
        # hypothesis ID (e.g. a CH-* chain row) joins its own group rather than
        # staying solo — otherwise an unjustified chain's inflated row survives
        # alongside the collapsed constituent representative.
        self_targets = constituent_to_hypos.setdefault(hypo_id.upper(), [])
        if hypo_id not in self_targets:
            self_targets.append(hypo_id)
        for cid in constituents:
            targets = constituent_to_hypos.setdefault(cid, [])
            if hypo_id not in targets:
                targets.append(hypo_id)

    # Group rows by hypothesis (unmapped rows stay solo)
    groups: dict[str, list[dict[str, str]]] = {}
    solo: list[dict[str, str]] = []
    for row in rows:
        fid = (row.get("finding id") or "").upper()
        hypos = constituent_to_hypos.get(fid, [])
        if hypos:
            for hypo in hypos:
                groups.setdefault(hypo, []).append(dict(row))
        else:
            solo.append(row)

    # Collapse each hypothesis group into one representative row
    collapsed: list[dict[str, str]] = []
    for hypo_id, group_rows in sorted(groups.items()):
        if len(group_rows) == 1:
            # Single constituent — keep as-is but relabel to hypothesis ID
            rep = dict(group_rows[0])
            rep["finding id"] = hypo_id
            collapsed.append(rep)
        else:
            # Multiple constituents — pick highest severity, merge context.
            #
            # Chain carve-out: a CH-* hypothesis only reaches this map when it
            # is UNJUSTIFIED (genuine compound chains are excluded upstream in
            # _parse_chain_constituents). For an unjustified chain, the chain
            # tier is an inflated restatement — inherit the constituent
            # severity, NOT the highest (which would be the inflated chain
            # severity). The constituent rows are the non-chain rows in the
            # group; if a chain row is itself present we ignore its severity.
            is_chain = bool(re.fullmatch(r"CH-\d+", hypo_id, re.IGNORECASE))
            if is_chain:
                non_chain_rows = [
                    r for r in group_rows
                    if not re.fullmatch(
                        r"CH-\d+", (r.get("finding id") or "").strip(),
                        re.IGNORECASE,
                    )
                ]
                sev_rows = non_chain_rows or group_rows
                sev_rows.sort(key=lambda r: -_severity_rank(r.get("severity", "")))
                inherited_sev = sev_rows[0].get("severity", "")
                group_rows.sort(key=lambda r: -_severity_rank(r.get("severity", "")))
                rep = dict(sev_rows[0])
                rep["finding id"] = hypo_id
                if inherited_sev:
                    rep["severity"] = inherited_sev
            else:
                group_rows.sort(key=lambda r: -_severity_rank(r.get("severity", "")))
                rep = dict(group_rows[0])
                rep["finding id"] = hypo_id
            # Aggregate title: use the first (highest-sev) constituent's title
            # Aggregate location: list unique locations
            locations = []
            for r in group_rows:
                loc = r.get("location", "").strip()
                if loc and loc not in locations:
                    locations.append(loc)
            if len(locations) > 1:
                rep["location"] = locations[0] + f" (+{len(locations)-1} more)"
            collapsed.append(rep)

    # Combine: collapsed hypothesis rows + solo rows, sorted by severity
    final = collapsed + solo
    final.sort(key=lambda r: -_severity_rank(r.get("severity", "")))
    # Renumber
    for i, row in enumerate(final, 1):
        row["queue #"] = str(i)

    original_count = len(rows)
    _write_queue_subset_manifest(queue_path, final)
    # Multi-target fan-out can make the final queue larger. This return value is
    # a legacy "removed" metric, so never report a negative dedup count.
    return max(0, original_count - len(final))


# v2.4.3: derived from unified _ID_* components. Callers run this on
# report-index table cells (non-zero positions) so [CHMLI]-\d{1,3}
# matches internal hypothesis IDs, not report IDs in column 0.
_INTERNAL_ID_RE = re.compile(
    _ASCII_ID_LEFT + r"(" + _ID_ALL_INTERNAL + r")" + _ASCII_ID_RIGHT,
    re.IGNORECASE | re.ASCII,
)


_REPORT_BULLET_RE = re.compile(
    r"^\s*[-*]\s*([CHMLI]-\d+)\s*[:.]",
    re.MULTILINE,
)


def _parse_report_index_table(text: str) -> list[dict[str, str]]:
    """Format 1: canonical Markdown table form. Returns [] if no rows match."""
    id_re = re.compile(r"^[\*\[`_]*([CHMLI]-\d+)\b")
    out: list[dict[str, str]] = []
    seen: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 2:
            continue
        m = id_re.match(cells[0])
        if not m:
            continue
        report_id = m.group(1)
        finding_id = ""
        for cell in reversed(cells[1:]):
            ids = _INTERNAL_ID_RE.findall(cell)
            if ids:
                finding_id = "+".join(dict.fromkeys(i.upper() for i in ids))
                break
        row = {
            "report_id": report_id,
            "finding_id": finding_id,
            "severity": report_id[0],
        }
        prev = seen.get(report_id)
        sig = (finding_id, report_id[0])
        if prev is not None:
            # Duplicate routing tables in report_index.md must not become
            # duplicate client findings. Keep the first assignment; conflicting
            # duplicates are caught later by report quality/completeness gates.
            continue
        seen[report_id] = sig
        out.append(row)
    return out


def _report_index_assignment_text(text: str) -> str:
    """Return the canonical assignment section of report_index.md.

    The Index Agent may include both:
      - `## Master Finding Index`: semantic report-ID assignments
      - `## Tier Assignments`: writer routing metadata repeating the same IDs

    Only the Master Finding Index is the report-body cardinality contract.
    Parsing the routing tables as assignments doubles every ID and causes
    phantom body-writer shards.
    """
    m = re.search(r"(?im)^\s*#{1,4}\s+Master\s+Finding\s+Index\b[^\n]*$", text)
    if not m:
        return text
    start = m.start()
    next_heading = re.search(r"(?im)^\s*#{1,4}\s+(?!Master\s+Finding\s+Index\b).+$", text[m.end():])
    end = m.end() + next_heading.start() if next_heading else len(text)
    return text[start:end]


def _report_index_reportable_text(text: str) -> str:
    """Return only the reportable-assignment part of report_index.md.

    Excluded / refuted / false-positive sections often still contain report-ID
    looking tokens. Treating those as active assignments caused the assembler
    to restore excluded findings into the client-visible body.
    """
    cut_re = re.compile(
        r"(?im)^\s*#{1,4}\s+.*(?:excluded|false\s*positive|refuted|appendix|"
        r"consolidation map|non-reportable|not reportable|traceability).*$"
    )
    m = cut_re.search(text)
    return text[:m.start()] if m else text


def _parse_report_index_bullets(text: str) -> list[dict[str, str]]:
    """Format 2: bullet form `- C-01: Title (L1-C-01)` / `- C-01: Title (L1-C-01, downgraded ...)`.

    The Index Agent's narrative form observed in a prior L1 run. Recovers
    per-finding mappings where the LLM emitted them; range bullets like
    `- H-01 through H-20: ...` are intentionally NOT parsed (no per-finding
    mapping) and drop to the mechanical fallback.
    """
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        m = _REPORT_BULLET_RE.match(s)
        if not m:
            continue
        report_id = m.group(1)
        if report_id in seen:
            continue
        # Skip range form like `- H-01 through H-20:`
        if re.search(r"\bthrough\s+[CHMLI]-\d+", s, re.IGNORECASE):
            continue
        # Find first internal-ID inside (...) on the line
        finding_id = ""
        paren = re.search(r"\(([^()]*)\)", s)
        if paren:
            mi = _INTERNAL_ID_RE.search(paren.group(1))
            if mi:
                finding_id = mi.group(1)
        seen.add(report_id)
        out.append({
            "report_id": report_id,
            "finding_id": finding_id,
            "severity": report_id[0],
        })
    return out


def parse_report_index_assignments(scratchpad: Path) -> list[dict[str, str]]:
    """Parse report_index.md into report-id/finding-id assignments.

    v2.3.3 — LAYERED FORMAT TOLERANCE.

    Tries two formats in priority order, returning whichever yields rows:
      1. Canonical Markdown table:
         ``| C-01 | Title | Critical | ... | L1-C-01 | ...``
      2. Bullet form (Index Agent narrative observed in a prior L1 run):
         ``- C-01: Title (L1-C-01)`` / ``- C-01: Title (L1-C-01, downgraded ...)``

    Range form (``- H-01 through H-20: ...``) is intentionally NOT parsed —
    it has no per-finding mapping. Empty return triggers the mechanical
    fallback in `get_tier_assignments`, which derives assignments from
    `verification_queue.md` (structured, driver-owned).

    v2.1.9 — Permissive prefix markers in table form.
    v2.3.3 — Bullet-form fallback added after a prior L1 run produced an
    empty AUDIT_REPORT.md when the Index Agent emitted bullet narrative
    instead of the canonical table. The empty deliverable was caused by
    silent-zero assignment dispatch.
    """
    p = scratchpad / "report_index.md"
    if not p.exists():
        return []
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    text = _report_index_reportable_text(text)
    text = _report_index_assignment_text(text)

    rows = _parse_report_index_table(text)
    if rows:
        return rows
    return _parse_report_index_bullets(text)


def _parse_report_index_summary_counts(scratchpad: Path) -> dict[str, int]:
    """Parse the Index Agent's explicit per-severity summary counts.

    This is intentionally independent of ``get_tier_assignments``. The
    assignment merger uses it to decide whether the Index Agent already emitted
    a complete, authoritative reportable set. When it did, mechanical
    verify-queue fallback rows must NOT be appended: the queue still contains
    refuted/excluded/pre-consolidation items that would inflate tier writers.
    """
    p = scratchpad / "report_index.md"
    if not p.exists():
        return {}
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    text = _report_index_reportable_text(text)

    counts = {"C": 0, "H": 0, "M": 0, "L": 0, "I": 0}
    found = False
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip().strip("*") for c in s.strip("|").split("|")]
        if len(cells) < 2:
            continue
        label = cells[0].lower()
        value = cells[1].replace(",", "")
        m = re.search(r"\b(\d+)\b", value)
        if not m:
            continue
        n = int(m.group(1))
        if label.startswith("critical"):
            counts["C"] = n
            found = True
        elif label.startswith("high"):
            counts["H"] = n
            found = True
        elif label.startswith("med"):
            counts["M"] = n
            found = True
        elif label.startswith("low"):
            counts["L"] = n
            found = True
        elif label.startswith("info"):
            counts["I"] = n
            found = True
    return counts if found else {}


_SKEPTIC_DOWNGRADE_RE = re.compile(
    _ASCII_ID_LEFT + r"(" + HYPOTHESIS_ID_PATTERN + r")" + _ASCII_ID_RIGHT
    + r"[^\n→]{0,160}?"
    r"(?:Crit(?:ical)?|High|Med(?:ium)?|Low|Info(?:rmational)?)\s*"
    r"(?:→|->|to)\s*"
    r"(Crit(?:ical)?|High|Med(?:ium)?|Low|Info(?:rmational)?)",
    re.IGNORECASE | re.ASCII,
)


def derive_tier_assignments_from_verify_queue(
    scratchpad: Path,
) -> list[dict[str, str]]:
    """Mechanical fallback for tier assignments. Driver-deterministic.

    Used when `parse_report_index_assignments` returns empty (LLM emitted
    a narrative or range-bullet form the parser cannot decompose into
    per-finding mappings). Derives assignments from structured artifacts
    the driver already trusts:

      - `verification_queue.md` rows (one per finding-id + severity)
      - `skeptic_judge_decisions.md` for severity downgrades, if present

    Output schema matches `parse_report_index_assignments`: list of
    `{report_id, finding_id, severity}` dicts. Report IDs are sequential
    per severity (`C-01`, `C-02`, ..., `H-01`, ...). Skips consolidation
    (one queue row → one report finding) — semantic consolidation is
    LLM work and must not be silently invented.

    Empty return = the fallback also has nothing to work with (no verify
    queue or no rows). Caller should hard-fail rather than dispatch
    placeholder tier writers.
    """
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []

    # Apply skeptic-judge severity downgrades, if any.
    sj = scratchpad / "skeptic_judge_decisions.md"
    downgrades: dict[str, str] = {}
    if sj.exists():
        try:
            sj_text = _llm_norm(sj.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            sj_text = ""
        for m in _SKEPTIC_DOWNGRADE_RE.finditer(sj_text):
            fid = m.group(1)
            new_sev = m.group(2).strip()[:1].upper()
            if new_sev in "CHMLI":
                downgrades[fid] = new_sev

    sev_order = "CHMLI"
    by_sev: dict[str, list[str]] = {s: [] for s in sev_order}
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        vp = _verify_file_for_id(scratchpad, fid)
        try:
            vtxt = _llm_norm(vp.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            vtxt = ""
        if not _is_reportable_verdict(_verifier_status_from_text(vtxt)):
            continue
        # Final severity: skeptic-judge override wins; else queue severity.
        queue_sev = (row.get("severity") or "").strip()
        sev_letter = downgrades.get(fid)
        if not sev_letter:
            sev_letter = queue_sev[:1].upper() if queue_sev else "M"
        if sev_letter not in by_sev:
            sev_letter = "M"
        by_sev[sev_letter].append(fid)

    out: list[dict[str, str]] = []
    for sev_letter in sev_order:
        for idx, fid in enumerate(by_sev[sev_letter], start=1):
            out.append({
                "report_id": f"{sev_letter}-{idx:02d}",
                "finding_id": fid,
                "severity": sev_letter,
            })
    return out


def get_tier_assignments(
    scratchpad: Path,
) -> tuple[list[dict[str, str]], str]:
    """Deterministic tier assignments with layered fallback + merge.

    Returns ``(assignments, source)`` where source is one of:
      * ``"index"``        — Index Agent rows fully cover the verify queue
      * ``"verify-queue"`` — mechanical only (Index Agent produced nothing parseable)
      * ``"merged"``       — Index Agent rows kept + mechanical fills the gap for
                              findings the Index Agent didn't enumerate per-finding
                              (e.g. `H-01 through H-20` range-bullet shorthand)
      * ``"empty"``        — no source produced rows; caller should hard-fail

    **Merge rule** (the architectural fix): the Index Agent's per-finding
    rows (consolidations, severity-adjustments) win where present; mechanical
    rows fill in for verify-queue findings the Index Agent didn't enumerate.
    Both signals contribute, neither alone is load-bearing.

    Pre-v2.3.3 the dispatch read `parse_report_index_assignments` directly.
    On a prior L1 run the parser returned 3 rows (Crit bullets only — the
    Index Agent had collapsed High/Medium/Low to range shorthand). Those 3
    flowed straight to dispatch, the 55 unenumerated findings were silently
    dropped → empty `AUDIT_REPORT.md`. The merge prevents this entire class.
    """
    index_rows = parse_report_index_assignments(scratchpad)
    queue_rows = derive_tier_assignments_from_verify_queue(scratchpad)

    if not index_rows and not queue_rows:
        return [], "empty"
    if not queue_rows:
        return index_rows, "index"
    if not index_rows:
        return queue_rows, "verify-queue"

    # If the Index Agent emitted explicit summary counts and its per-finding
    # rows match those counts, the index is complete and authoritative. Do not
    # append verify-queue rows: the queue is pre-report and may include refuted,
    # excluded, downgraded, or consolidated items that the Index Agent
    # deliberately removed from the reportable body. This exact false merge
    # inflated a prior L1 run's C/H from 61 to 76 and triggered an unnecessary Opus
    # retry after the tier writer had correctly completed all assignments.
    summary_counts = _parse_report_index_summary_counts(scratchpad)
    if summary_counts:
        row_counts = {s: 0 for s in "CHMLI"}
        for a in index_rows:
            sev = (a.get("severity") or "")[:1].upper()
            if sev in row_counts:
                row_counts[sev] += 1
        if all(row_counts[s] == summary_counts.get(s, 0) for s in "CHMLI"):
            return index_rows, "index"

    # If Index Agent rows have no finding-id mappings at all, merge cannot
    # dedupe across sources — adding queue rows would double-count. Fall back
    # to mechanical alone. This protects SC where the Index Agent emits
    # report-IDs without explicit per-row internal IDs (bullet form: `- C-01:
    # Title` with no `(internal-id)` annotation).
    index_with_id = [a for a in index_rows if a.get("finding_id")]
    if not index_with_id:
        return queue_rows, "verify-queue"

    # Both sources have rows. Diff by finding_id. Index Agent is authoritative
    # for findings it enumerated; mechanical fills in for the rest.
    index_finding_ids: set[str] = set()
    for a in index_with_id:
        ids = _INTERNAL_ID_RE.findall(a.get("finding_id", ""))
        if ids:
            index_finding_ids.update(i.upper() for i in ids)
        else:
            index_finding_ids.add(a["finding_id"])
    queue_finding_ids = {a["finding_id"] for a in queue_rows}
    missing_from_index = queue_finding_ids - index_finding_ids
    if not missing_from_index:
        return index_rows, "index"

    # Merge. Continue per-severity numbering past the Index Agent's max.
    merged = list(index_rows)
    seen_report_ids = {a["report_id"] for a in index_rows}
    next_seq: dict[str, int] = {}
    for s in "CHMLI":
        next_seq[s] = max(
            (
                int(a["report_id"].split("-", 1)[1])
                for a in index_rows
                if a["severity"] == s and re.fullmatch(r"\d+", a["report_id"].split("-", 1)[1] if "-" in a["report_id"] else "")
            ),
            default=0,
        )
    for q in queue_rows:
        if q["finding_id"] in index_finding_ids:
            continue
        sev = q["severity"]
        next_seq[sev] = next_seq.get(sev, 0) + 1
        report_id = f"{sev}-{next_seq[sev]:02d}"
        while report_id in seen_report_ids:
            next_seq[sev] += 1
            report_id = f"{sev}-{next_seq[sev]:02d}"
        seen_report_ids.add(report_id)
        merged.append({
            "report_id": report_id,
            "finding_id": q["finding_id"],
            "severity": sev,
        })
    return merged, "merged"


_TIER_SEVERITY_MAP: dict[str, tuple[str, ...]] = {
    "critical_high": ("C", "H"),
    "medium": ("M",),
    "low_info": ("L", "I"),
}

_TIER_EMPTY_HEADER: dict[str, str] = {
    "critical_high": "## Critical Findings\n\n## High Findings\n\n",
    "medium": "## Medium Findings\n\n",
    "low_info": "## Low Findings\n\n## Informational Findings\n\n",
}


def compute_report_tier_shards(
    scratchpad: Path, tier_base: str,
) -> dict[str, list[dict[str, str]]]:
    """Split tier assignments into shards based on _BODY_SHARD_CAPS."""
    sevs = _TIER_SEVERITY_MAP.get(tier_base, ())
    if not sevs:
        return {}
    rows, _source = get_tier_assignments(scratchpad)
    assignments = [a for a in rows if a["severity"] in sevs]
    cap = _BODY_SHARD_CAPS.get(f"report_{tier_base}", 30)
    if len(assignments) <= cap:
        return {f"report_{tier_base}_a": assignments}
    n_shards = (len(assignments) + cap - 1) // cap
    chunk = (len(assignments) + n_shards - 1) // n_shards
    result: dict[str, list[dict[str, str]]] = {}
    for i in range(n_shards):
        suffix = chr(ord("a") + i)
        slice_rows = assignments[i * chunk : (i + 1) * chunk]
        if slice_rows:
            result[f"report_{tier_base}_{suffix}"] = slice_rows
    return result


def compute_report_medium_shards(scratchpad: Path) -> dict[str, list[dict[str, str]]]:
    return compute_report_tier_shards(scratchpad, "medium")


def ensure_report_tier_shards(
    scratchpad: Path, tier_base: str,
) -> dict[str, list[dict[str, str]]]:
    """Compute shards and write per-shard assignment manifests."""
    shards = compute_report_tier_shards(scratchpad, tier_base)
    for phase_name, rows in shards.items():
        manifest = scratchpad / f"{phase_name}_assignments.md"
        lines = [
            f"# {phase_name} assignments",
            "| Report ID | Finding ID |",
            "|-----------|------------|",
        ]
        lines.extend(
            f"| {row['report_id']} | {row['finding_id']} |"
            for row in rows
        )
        content = "\n".join(lines) + "\n"
        if manifest.exists():
            try:
                if manifest.read_text(encoding="utf-8", errors="replace") == content:
                    continue
            except Exception:
                pass
        manifest.write_text(content, encoding="utf-8")
    return shards


def ensure_report_medium_shards(scratchpad: Path) -> dict[str, list[dict[str, str]]]:
    return ensure_report_tier_shards(scratchpad, "medium")


def merge_report_tier_shards(scratchpad: Path, tier_base: str) -> None:
    """Merge report_{tier_base}_[a-z].md shard files into report_{tier_base}.md.

    Safe no-op: if no shard files exist (tier was not split), the base
    file is left untouched to avoid clobbering unsharded body-writer output.
    """
    parts = []
    for p in sorted(scratchpad.glob(f"report_{tier_base}_[a-z].md")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            continue
        if text:
            parts.append(text)
    if not parts:
        return
    merged = "\n\n".join(parts).strip() + "\n"
    (scratchpad / f"report_{tier_base}.md").write_text(merged, encoding="utf-8")


def merge_report_medium_shards(scratchpad: Path) -> None:
    merge_report_tier_shards(scratchpad, "medium")


# v2.3.11: report_assemble is now Python-native (driver owns plumbing).
#
# The prior LLM-driven assemble phase thrashed for 1+ hour on a 225KB
# concatenation job that needed zero semantic reasoning. Per the V2 layer
# doctrine in CLAUDE.md ("Python driver owns runtime policy [...]. V1
# prompts own methodology"), concatenating tier files is plumbing, not
# methodology — should never have been LLM work.
#
# This function reads the tier files + report_index.md, generates the
# Executive Summary + Priority Remediation Order mechanically from the
# Master Finding Index counts and rows, and assembles AUDIT_REPORT.md
# per `~/.claude/rules/report-template.md`. Finishes in <1 second.
#
# The existing post-assemble quality gate (`_run_report_quality_gate`,
# `_check_promotion_symmetry`, etc.) still runs against the Python
# output. Mechanical assembly produces canonicalized output that
# satisfies the gates by construction.
def _extract_h2_section(text: str, header_substr: str) -> str:
    """Return the body of a `## {header_substr}...` section up to next H2.

    Tolerates trailing words in the heading (e.g., "## Summary Counts"
    matches header_substr="Summary"). Empty if no such section.
    Case-insensitive. Accepts H2 or H3 (`##`/`###`) to tolerate LLM
    heading-level drift. H1 is excluded because it is typically a
    document title that contains section names as substrings.
    """
    pattern = re.compile(
        r"^#{2,3}\s+" + re.escape(header_substr) + r"[^\n]*\n((?:.|\n)*?)(?=\n##(?!#)|\Z)",
        re.MULTILINE | re.IGNORECASE,
    )
    m = pattern.search(text)
    return m.group(1).strip() if m else ""


# --------------------------------------------------------------------------
# LLM output normalization layer (defensive, applied at every parser entry).
#
# Rationale: a fresh codebase audit can produce an LLM output format we
# haven't observed before — smart quotes, em-dashes, HTML entities, CRLF,
# zero-width chars, non-breaking spaces. If parsers are written against
# strict ASCII formats, each new format breaks an audit. The structural fix
# is to normalize input ONCE at every parser boundary into a canonical form,
# then parse with strict ASCII-only regexes.
#
# This function is idempotent: normalize(normalize(x)) == normalize(x). It
# only converts encoding-level variants; semantic content is preserved.
# --------------------------------------------------------------------------
_LLM_NORM_TABLE = {
    # Curly quotes -> ASCII
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"', "‟": '"',
    # Dashes -> hyphen
    "–": "-", "—": "-", "―": "-", "−": "-",
    # Ellipsis
    "…": "...",
    # Spaces
    " ": " ", " ": " ", " ": " ", " ": " ", "　": " ",
    # Zero-width / format chars (delete)
    "​": "", "‌": "", "‍": "", "⁠": "", "﻿": "",
    "­": "",
    # Bullet variants -> dash (preserves list semantics)
    "•": "-", "‣": "-", "◦": "-", "⁃": "-",
}


_HTML_ENTITY_RE = re.compile(r"&(?:#x([0-9A-Fa-f]+)|#(\d+)|(amp|lt|gt|quot|apos|nbsp));")


_HTML_ENTITY_MAP = {
    "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": " ",
}


def _llm_norm(text: str) -> str:
    """Idempotent normalization of LLM output for parser robustness.

    Closes the structural failure mode where a new codebase produces an
    LLM-output format variant (smart quote, HTML entity, CRLF) that breaks
    a parser written against ASCII LF. Wired into every parser entry point.
    """
    if not text:
        return text or ""
    s = text
    # Line endings first (so multi-line regexes work uniformly).
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # HTML entity decode (cheap, common LLM artifact). Loop to convergence
    # so double-encoded inputs `&amp;gt;` -> `&gt;` -> `>` are fully decoded.
    def _ent_repl(m: re.Match) -> str:
        if m.group(3):
            return _HTML_ENTITY_MAP.get(m.group(3), m.group(0))
        try:
            if m.group(1):
                cp = int(m.group(1), 16)
            else:
                cp = int(m.group(2))
            if 0 <= cp <= 0x10FFFF:
                return chr(cp)
        except (ValueError, OverflowError):
            pass
        return m.group(0)
    prev = None
    while prev != s:
        prev = s
        s = _HTML_ENTITY_RE.sub(_ent_repl, s)
    # Code-point translation AFTER entity decode so chars produced by entity
    # decoding (e.g. `&#xfeff;` -> `﻿` -> deleted as zero-width BOM)
    # also get normalized. Required for idempotence.
    s = s.translate(str.maketrans(_LLM_NORM_TABLE))
    return s


def _field_from_markdown(text: str, labels: tuple[str, ...]) -> str:
    """Extract a simple `Label: value` field from markdown."""
    text = _llm_norm(text)
    for label in labels:
        m = re.search(
            rf"(?im)^\s*(?:[-*]\s*|#{{1,6}}\s+)?(?:\*\*)?{re.escape(label)}(?:\*\*)?"
            rf"(?:\s*\([^)]*\))?\s*(?::|-|=)\s*(.+)$",
            text,
        )
        if m:
            return m.group(1).strip().strip("`")
    return ""


_OPTIONAL_FINDING_METADATA_LABELS: dict[str, tuple[str, ...]] = {
    "discovery_steer": ("Discovery Steer", "Discovery Steering"),
    "missing_precondition": ("Missing Precondition", "Missing Preconditions"),
    "precondition_type": ("Precondition Type", "Precondition Types"),
    "postconditions_created": (
        "Postconditions Created",
        "Postcondition Created",
        "Postconditions",
        "Postcondition",
    ),
    "postcondition_types": ("Postcondition Types", "Postcondition Type"),
    "semantic_invariant": ("Semantic Invariant", "Semantic Invariants"),
    "branch_preconditions": ("Branch Preconditions", "Branch Precondition"),
    "terminal_mechanism": ("Terminal Mechanism", "Terminal Mechanisms"),
    "composition_candidates": ("Composition Candidates", "Composition Candidate"),
}

_OPTIONAL_FINDING_METADATA_FIELDS: tuple[str, ...] = tuple(
    _OPTIONAL_FINDING_METADATA_LABELS.keys()
)


def _optional_finding_metadata_defaults() -> dict[str, str]:
    return {field: "" for field in _OPTIONAL_FINDING_METADATA_FIELDS}


def _optional_finding_metadata_field_for_label(label: str) -> str:
    key = _norm_key(label)
    for field, labels in _OPTIONAL_FINDING_METADATA_LABELS.items():
        if any(key == _norm_key(alias) for alias in labels):
            return field
    return ""


def _extract_optional_finding_metadata(text: str) -> dict[str, str]:
    out = _optional_finding_metadata_defaults()
    for field, labels in _OPTIONAL_FINDING_METADATA_LABELS.items():
        val = _field_from_markdown(text, labels)
        if val:
            out[field] = _strip_md(val)
    return out


def _first_heading_title(text: str) -> str:
    m = re.search(r"(?m)^#{1,4}\s+(?:Finding\s*)?(?:\[[^\]]+\]\s*)?(.+)$", text)
    return m.group(1).strip() if m else ""


def _sanitize_client_title(title: str) -> str:
    """Remove internal pipeline IDs from client-facing titles/headings."""
    s = title or ""
    internal = _INTERNAL_FINDING_ID_RE.pattern
    # Drop parenthetical/bracketed notes whose only purpose is an internal
    # trace reference, e.g. "(Depth Validation of INV-002)".
    s = re.sub(
        r"\s*[\(\[][^)\]\n]{0,120}?\b(?:" + internal + r")\b[^)\]\n]{0,120}?[\)\]]",
        "",
        s,
        flags=re.IGNORECASE,
    )
    # Titles should retain the client-facing claim, not a generic trace token.
    # Body prose can replace internal IDs with "upstream finding"; headings
    # containing that phrase are placeholders and fail report title quality.
    s = re.sub(r"\b(?:" + internal + r")\b", "", s, flags=re.IGNORECASE)
    s = re.sub(r"(?i)\b(?:and|or|of)\s+(?:and|or|of)\b", " ", s)
    s = re.sub(r"(?i)\bduplicate\s+of\s*(?:/|\band\b|\bor\b)?\s*$", "duplicate", s)
    # Strip a leading agent-finding-ID prefix the mechanical index recovery
    # sometimes leaves on titles, e.g. "/ EXT-001: ..." or "STATE-001 - ...".
    s = re.sub(r"^[\s/]*[A-Z]{2,6}-\d{1,4}\s*[:\-–—]\s*", "", s)
    s = s.lstrip("/ ")
    s = re.sub(r"\s+", " ", s).strip(" -–—:/")
    return s or "Verified finding"


# R0-2b: sanitization uses the canonical internal-token matcher. Ambiguous
# client report IDs are retained by the replacement predicate below, not by a
# second partial hypothesis grammar.
_CLIENT_BODY_INTERNAL_ID_RE = re.compile(
    _ASCII_ID_LEFT
    + r"(?!(?:[CMLI]-\d{1,3}|H-\d{2})" + _ASCII_ID_RIGHT + r")"
    + r"(" + _ID_ALL_INTERNAL + r")" + _ASCII_ID_RIGHT,
    re.IGNORECASE | re.ASCII,
)


def _client_internal_id_replacement(match: re.Match[str]) -> str:
    """Sanitize internal IDs while retaining ambiguous public report IDs."""
    fid = match.group(1).upper()
    if is_public_report_id(fid):
        return match.group(0)
    return "upstream finding"


def _sanitize_client_body(text: str) -> str:
    """Remove internal pipeline IDs from client-facing report prose."""
    clean = re.sub(
        r"\bverify_[A-Za-z0-9_\-\[\].]+\.md\b",
        "verifier artifact",
        text or "",
        flags=re.IGNORECASE,
    )
    clean = _CLIENT_BODY_INTERNAL_ID_RE.sub(_client_internal_id_replacement, clean)
    # Drop internal-status narration the body writer sometimes leaks into prose.
    # The manifest's report_blocked flag is meant to drive a heading tag the
    # assembler strips, NOT client-facing sentences. Remove whole sentences
    # mentioning the internal status so no dangling fragment remains.
    clean = re.sub(
        r"(?is)(?:(?<=[.!?])\s+|^)[^.!?\n]*(?:report[\s-]?blocked|shard\s+inputs?)[^.!?\n]*[.!?]",
        " ",
        clean,
    )
    clean = re.sub(r"[ \t]{2,}", " ", clean)
    return clean.strip()


def _markdown_section(text: str, headings: tuple[str, ...], max_chars: int = 3500) -> str:
    """Extract a markdown H2/H3 section body by heading aliases."""
    if not text:
        return ""
    aliases = [re.escape(h) for h in headings]
    pat = re.compile(
        r"(?ims)^#{2,4}\s+(?:" + "|".join(aliases) + r")\b[^\n]*\n"
        r"(.*?)(?=^#{2,4}\s+\S|\Z)"
    )
    m = pat.search(text)
    if not m:
        return ""
    body = m.group(1).strip()
    if len(body) > max_chars:
        body = body[:max_chars].rstrip() + "\n\n_(Truncated; see verifier artifact for full trace.)_"
    return _sanitize_client_body(body)


def _field_or_section(
    text: str,
    field_labels: tuple[str, ...],
    section_headings: tuple[str, ...],
    fallback: str = "",
    max_chars: int = 3500,
) -> str:
    """Extract a report field from verifier markdown, preferring sections."""
    section = _markdown_section(text, section_headings, max_chars=max_chars)
    if section:
        return section
    field = _field_from_markdown(text, field_labels)
    if field:
        return _sanitize_client_body(field[:max_chars].strip())
    # Many report/verifier artifacts use bold field labels as block headers:
    # `**PoC Result**:\n```...\n````. `_field_from_markdown` intentionally
    # reads only same-line values, so recover the following block here.
    aliases = "|".join(re.escape(label) for label in field_labels)
    block_re = re.compile(
        rf"(?ims)^\s*(?:[-*]\s*)?(?:\*\*)?(?:{aliases})(?:\*\*)?"
        rf"\s*(?::|-|=)\s*\n(.*?)(?=^\s*(?:[-*]\s*)?(?:\*\*)?[A-Z][A-Za-z0-9 /_-]{{1,80}}"
        rf"(?:\*\*)?\s*(?::|-|=)\s*$|^#{1,4}\s+\S|\Z)"
    )
    m = block_re.search(text or "")
    if m:
        return _sanitize_client_body(m.group(1)[:max_chars].strip())
    return fallback


def parse_inventory_shard_manifest(scratchpad: Path, phase_name: str) -> list[str]:
    manifest = scratchpad / f"{phase_name}.manifest.md"
    if not manifest.exists():
        return []
    files: list[str] = []
    try:
        text = _llm_norm(manifest.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return files
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        s_up = s.upper()
        if "FILE" in s_up and ("ROLE" in s_up or "MODEL" in s_up or "STATUS" in s_up):
            continue
        parts = [c.strip() for c in s.strip("|").split("|")]
        if len(parts) >= 2 and parts[0].endswith(".md"):
            files.append(parts[0])
    return files


_SEVERITY_ORDER = {s.lower(): severity_rank(s) for s in SEVERITY_ORDER}
_SEVERITY_ORDER["info"] = 0

_SEVERITY_CODE = {s.lower(): severity_letter_from_name(s) for s in SEVERITY_ORDER}
_SEVERITY_CODE["info"] = "I"


def _strip_md(text: str) -> str:
    s = (text or "").strip()
    s = s.replace("`", "").replace("**", "").replace("*", "")
    return re.sub(r"\s+", " ", s).strip()


def _norm_loc(text: str) -> str:
    return _strip_md(text).replace("\\", "/")


def _norm_key(text: str) -> str:
    s = re.sub(r"\s*\(.*", "", _strip_md(text))
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


# ── L1: PLAMEN_SIGNALS machine-readable channel (regex-fragility plan §4) ────
#
# Extends the proven `<!-- PLAMEN_X: value -->` HTML-comment channel
# (driver `re.finditer(r"<!--\s*PLAMEN_([A-Z_]+):\s*([^>]+?)\s*-->", text)`)
# with a `PLAMEN_SIGNALS` family carrying single-line JSON:
#
#     <!-- PLAMEN_SIGNALS: {"sync_gaps":5,"conditional_writes":2} -->
#
# JSON inside an HTML comment is deterministic by construction; no markdown
# shape variance is possible. This is the L1 authoritative source — when the
# block is present and parseable, the driver trusts it over any L2 prose
# extraction. When it is missing or malformed, the parser returns {} and LOGS
# (never raises, never silently fabricates a signal). Multiple blocks merge
# left-to-right (a later block overrides an earlier key); this matches the
# existing STATUS/ARTIFACT channel's last-wins convention.
_PLAMEN_SIGNALS_BLOCK_RE = re.compile(
    r"<!--\s*PLAMEN_SIGNALS\s*:\s*(\{.*?\})\s*-->",
    re.DOTALL,
)


def parse_plamen_signals(text: str) -> dict:
    """Parse all ``<!-- PLAMEN_SIGNALS: {json} -->`` blocks out of *text*.

    Returns the merged JSON object (later blocks override earlier keys).
    Tolerant of:
      - missing block        -> {} (no log; absence is normal, not an error)
      - malformed/partial JSON inside an otherwise well-formed block
                             -> that block is skipped + a WARNING is logged
                                (zero-harvest-with-evidence tripwire)
      - non-object JSON (list/scalar) inside a block
                             -> skipped + WARNING
      - None / empty text    -> {}

    Never raises. The HTML-comment delimiter is matched format-invariantly
    (whitespace-tolerant, DOTALL so the JSON may legally contain newlines),
    mirroring the driver's existing PLAMEN_X channel parser.
    """
    if not text:
        return {}
    s = _llm_norm(text)
    out: dict = {}
    saw_block = False
    bad_block = False
    for m in _PLAMEN_SIGNALS_BLOCK_RE.finditer(s):
        saw_block = True
        raw = m.group(1).strip()
        try:
            obj = json.loads(raw)
        except (ValueError, TypeError):
            bad_block = True
            continue
        if not isinstance(obj, dict):
            bad_block = True
            continue
        out.update(obj)
    if bad_block and not out:
        # Zero-harvest tripwire: a PLAMEN_SIGNALS block was present (evidence)
        # yet nothing parsed. This is the strictly-worse-than-no-gate signature
        # — surface it instead of silently returning {}.
        log.warning(
            "parse_plamen_signals: PLAMEN_SIGNALS block(s) present but no "
            "valid JSON object harvested (malformed channel) — falling back "
            "to prose extraction"
        )
    elif bad_block and out:
        log.warning(
            "parse_plamen_signals: %d key(s) harvested but at least one "
            "PLAMEN_SIGNALS block was malformed and skipped",
            len(out),
        )
    _ = saw_block  # documented: presence-without-harvest handled above
    return out


# ── L2: one shared tolerant field extractor (regex-fragility plan §4 L2) ─────
#
# Converges the ~15 scattered raw `**Field**:` / `Field:` / table-cell regexes
# onto the existing tolerant toolkit (`_llm_norm`, `_field_from_markdown`,
# `_split_markdown_table_row`, `_is_separator_row`). The single capability it
# ADDS over `_field_from_markdown` is **table-cell key/value extraction**
# (`| Field | value |`, the #1 live miss) plus an opt-in **clause-scoped
# negation guard** (fixing the `_valid_poc_skip` cross-sentence false-fire).
#
# STRICT-SUPERSET CONTRACT (the one rule): for every input the legacy
# extractors accepted, `_field_anywhere` returns a value-identical result.
# It only ever matches MORE shapes, never fewer.

# Negation tokens for the clause-scoped guard. Word-boundary anchored at the
# call site so `id` != `invalid`, `covered` != `uncovered`.
_NEGATION_TOKENS: tuple[str, ...] = (
    "not", "no", "never", "without", "n't", "cannot", "can't",
    "isn't", "wasn't", "aren't", "doesn't", "don't", "didn't",
    "false", "absent", "lacking", "lacks", "missing",
)
_NEGATION_GUARD_RE = re.compile(
    r"(?i)(?<!\w)(?:" + "|".join(re.escape(t) for t in _NEGATION_TOKENS) + r")(?!\w)"
)

# Clause boundary: sentence end, list-item break, table-cell pipe, or a hard
# newline. Used to scope the negation guard to the trigger's own clause rather
# than the failed 80-char DOTALL proximity window.
_CLAUSE_SPLIT_RE = re.compile(r"[.;!?\n]|(?:\s\|\s)")


def _clause_around(text: str, start: int, end: int) -> str:
    """Return the clause (sentence/list-item/table-cell) that spans
    [start, end) within *text*. Boundaries are sentence punctuation, hard
    newlines, or table-cell pipes — NOT a fixed character window."""
    left = 0
    for m in _CLAUSE_SPLIT_RE.finditer(text, 0, start):
        left = m.end()
    right = len(text)
    rm = _CLAUSE_SPLIT_RE.search(text, end)
    if rm is not None:
        right = rm.start()
    return text[left:right]


def _negation_in_clause(text: str, start: int, end: int) -> bool:
    """True if a negation token shares the same clause as the [start,end)
    trigger. Word-boundary matched so `id` does not trip on `invalid`."""
    clause = _clause_around(text, start, end)
    return bool(_NEGATION_GUARD_RE.search(clause))


def _negation_governs_keyword(text: str, keyword_re) -> bool:
    """True iff ANY occurrence of *keyword_re* in *text* shares its clause
    (sentence / list-item / table-cell — NOT a fixed character window) with a
    negation token.

    This is the clause-scoped replacement for the legacy `.{0,80}` DOTALL
    proximity rule used by `_valid_poc_skip`'s mock-feasibility blocker. The old
    rule fired whenever a negation appeared within 80 characters of `mock`,
    even across sentence boundaries (e.g. "...used a Mock harness. The address
    does not exist." wrongly suppressed). Clause scoping suppresses ONLY when
    the negation governs the same clause as the keyword — strictly recall-safe
    for the PoC-skip decision: the old rule OVER-rejected valid skips, so the
    narrower clause guard can only let MORE valid skips through, never drop a
    finding.

    The keyword occurrence itself is blanked inside its clause before the
    negation scan so a keyword that happens to contain or abut a negation
    substring cannot self-trigger.
    """
    if not text:
        return False
    s = _llm_norm(text)
    if isinstance(keyword_re, str):
        keyword_re = re.compile(keyword_re, re.IGNORECASE)
    for km in keyword_re.finditer(s):
        clause = _clause_around(s, km.start(), km.end())
        # Blank the matched keyword span within the clause so the keyword text
        # cannot be misread as a negation source.
        kw_local_start = clause.find(km.group(0))
        if kw_local_start >= 0:
            blanked = (
                clause[:kw_local_start]
                + " " * len(km.group(0))
                + clause[kw_local_start + len(km.group(0)):]
            )
        else:
            blanked = clause
        if _NEGATION_GUARD_RE.search(blanked):
            return True
    return False


def _table_cell_field(
    text: str,
    norm_labels: tuple[str, ...],
    *,
    short_labels: frozenset,
) -> str:
    """Scan markdown tables for a `| label | value |` key/value pair.

    Handles two table renderings the LLM uses interchangeably:
      (a) header/row:   a header row naming the label as a column, with the
                        value in the aligned cell of a following data row
                        (`| Impact | Likelihood |` / `| High | Medium |`).
                        Detected when a separator row (`|---|---|`) immediately
                        follows the candidate header.
      (b) vertical kv:  a 2-(or-more)-column row whose first cell is the label
                        and whose next non-empty cell is the value
                        (`| Severity | High |`). Used when the row is NOT a
                        separator-confirmed header.

    Header/row is tried first (separator-confirmed) so a 2-column matrix header
    like `| Impact | Likelihood |` is not misread as a vertical kv pair. Then
    vertical-kv is tried. Separator rows are never values. Returns "" if no
    match.
    """
    # Parse into (is_sep, cells) keeping document order; non-table lines reset
    # the local table context.
    rows: list[tuple[bool, list[str]]] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s.startswith("|"):
            rows.append((False, []))  # context break sentinel (empty cells)
            continue
        if _is_separator_row(s):
            rows.append((True, []))
            continue
        cells = _split_markdown_table_row(s)
        rows.append((False, cells))

    def _label_columns(cells: list[str]) -> dict[int, str]:
        out: dict[int, str] = {}
        for i, cell in enumerate(cells):
            ck = _norm_key(cell)
            if not ck:
                continue
            for lbl in norm_labels:
                if lbl in short_labels:
                    if re.search(r"(?<!\w)" + re.escape(lbl) + r"(?!\w)", ck):
                        out[i] = lbl
                        break
                elif lbl in ck:
                    out[i] = lbl
                    break
        return out

    # ── Pass (a): separator-confirmed header/row ──
    for idx, (is_sep, cells) in enumerate(rows):
        if is_sep or not cells:
            continue
        # A header is a row whose NEXT non-empty table row is a separator.
        nxt = idx + 1
        if nxt >= len(rows):
            continue
        nxt_sep, nxt_cells = rows[nxt]
        if not nxt_sep:
            continue
        cols = _label_columns(cells)
        if not cols:
            continue
        # Read the aligned value cell from the first data row after the
        # separator.
        for j in range(idx + 2, len(rows)):
            d_sep, d_cells = rows[j]
            if d_sep:
                continue
            if not d_cells:
                break  # context break -> no data row
            for ci in sorted(cols):
                if ci < len(d_cells):
                    v = d_cells[ci].strip()
                    if v:
                        return v
            break

    # ── Pass (b): vertical kv (first cell is the label) ──
    for is_sep, cells in rows:
        if is_sep or not cells:
            continue
        first_key = _norm_key(cells[0])
        if first_key in norm_labels:
            for cell in cells[1:]:
                v = cell.strip()
                if v:
                    return v

    return ""


_FIELD_ANYWHERE_HEADING_RE_CACHE: dict[str, re.Pattern] = {}


def _heading_field(text: str, labels: tuple[str, ...]) -> str:
    """Extract a value rendered as a markdown heading `#{1,6} Label: value`
    or `#{1,6} Label` followed by the next non-blank line's content.

    `_field_from_markdown` already handles the inline `# Label: value` form;
    this adds the `# Label` / next-line-value form used by some agents."""
    for label in labels:
        m = re.search(
            rf"(?im)^\s*#{{1,6}}\s+(?:\*\*)?{re.escape(label)}(?:\*\*)?\s*$",
            text,
        )
        if m:
            tail = text[m.end():].lstrip("\n")
            for ln in tail.splitlines():
                if ln.strip():
                    return ln.strip().strip("`").strip()
    return ""


def _field_anywhere(
    text: str,
    labels,
    *,
    value_pattern: Optional[str] = None,
    table_ok: bool = True,
    negation_guard: bool = False,
    first_match: bool = True,
) -> tuple[str, str]:
    """Single shared tolerant field extractor (regex-fragility plan §4 L2).

    Returns ``(value, shape_tag)`` where ``shape_tag`` is one of
    ``{"kv", "bullet", "bold", "backtick", "table", "heading", "none"}`` —
    callers may ignore the tag. ``value`` is ``""`` when nothing matched.

    Tolerance (strict superset of every legacy single-shape regex):
      - `_llm_norm` normalizes CRLF / smart quotes / HTML entities / zero-width
        BEFORE matching (so a new rendering variant cannot break a parser).
      - kv / bullet / bold(`**Field**:` and `**Field:**`) / backtick label
        forms with `:` / `-` / `=` separators -> delegated to
        `_field_from_markdown` (legacy behavior preserved verbatim).
      - table-cell kv (`| Field | value |`) and header/row tables -> ADDED via
        `_table_cell_field` (the #1 live miss; only matched when table_ok).
      - heading-as-value (`# Field` then next line) -> ADDED.
      - case-insensitive throughout; label aliases longest-first; word-boundary
        match for short (<=3 char) aliases so `id` != `invalid`.
      - ``value_pattern`` (optional): the extracted value must contain a match
        for this regex, else that candidate is rejected and the search
        continues. Lets callers constrain to e.g. a severity enum.
      - ``negation_guard`` (optional): suppress a match when a negation token
        shares the *same clause* as the matched label (NOT an 80-char proximity
        window). Recall-safe narrowing per plan §4.
      - ``first_match`` (default True): return the first accepted value.

    Zero-harvest tripwire: when *text* clearly contains one of the labels yet
    nothing is harvested, a WARNING is logged (the strictly-worse-than-no-gate
    signature). Detection-only — never raises, never drops a candidate.
    """
    if not text:
        return ("", "none")
    if isinstance(labels, str):
        labels = (labels,)
    labels = tuple(l for l in labels if l)
    if not labels:
        return ("", "none")

    s = _llm_norm(text)

    # Longest-first so a long alias wins over a short substring of it
    # (`location` before `loc`), mirroring `_match_canonical_header`.
    ordered = sorted(set(labels), key=len, reverse=True)
    norm_labels = tuple(_norm_key(l) for l in ordered)
    short_labels = frozenset(nl for nl in norm_labels if len(nl) <= 3)

    vpat = re.compile(value_pattern, re.IGNORECASE) if value_pattern else None

    def _accept(value: str) -> bool:
        if not value:
            return False
        if vpat is not None and not vpat.search(value):
            return False
        return True

    # ── Pass 1: inline kv / bullet / bold / backtick (legacy superset) ──
    # `_field_from_markdown` already covers `:`/`-`/`=`, `**bold**`,
    # `**label:**`, backtick, leading bullet, `#{1,6}` heading-inline, and
    # parenthetical-suffix labels. We reproduce its core match here so we can
    # apply the negation guard and value_pattern per-candidate.
    for label in ordered:
        for m in re.finditer(
            # The label group tolerates wrappers on BOTH sides, including the
            # `**label:**` form where the separator colon is INSIDE the closing
            # bold/backtick markers. The closing-wrapper-with-inner-colon branch
            # (`open`) only fires when the label was OPENED with a wrapper, so a
            # bold VALUE like `Severity: **High**` is not mis-consumed.
            rf"(?im)^\s*(?:[-*]\s*|#{{1,6}}\s+)?"
            rf"(?P<lbl>(?P<open>\*\*|`|_|\[)?\s*{re.escape(label)})\s*"
            rf"(?:\s*\([^)]*\))?"
            rf"(?:(?(open)(?::|-|=)?\s*(?:\*\*|`|_|\])\s*(?::|-|=)?|(?!x)x)"
            rf"|\s*(?::|-|=))"
            rf"\s*(?P<val>.+)$",
            s,
        ):
            # Value cleanup mirrors legacy `_field_from_markdown` (strip
            # backticks) plus balanced bold; brackets are MEANINGFUL (e.g.
            # `[POC-PASS]`) and are NOT stripped.
            value = m.group("val").strip()
            if value.startswith("**") and value.endswith("**") and len(value) > 4:
                value = value[2:-2].strip()
            value = value.strip("`").strip()
            if not _accept(value):
                continue
            # Negation guard is scoped to the LABEL clause (the trigger), NOT
            # the whole captured value — fixing the `_valid_poc_skip`
            # cross-sentence false-fire where a negation in a later sentence of
            # the value wrongly suppressed a valid field.
            if negation_guard and _negation_in_clause(
                s, m.start("lbl"), m.end("lbl")
            ):
                continue
            # shape tag: best-effort classification of the matched line
            line = m.group(0)
            lbl_txt = m.group("lbl")
            if line.lstrip().startswith(("-", "*")) and not lbl_txt.lstrip().startswith("*"):
                tag = "bullet"
            elif "**" in lbl_txt:
                tag = "bold"
            elif "`" in lbl_txt:
                tag = "backtick"
            else:
                tag = "kv"
            if first_match:
                return (value, tag)

    # ── Pass 2: table-cell kv / header-row (the ADDED capability) ──
    if table_ok:
        tv = _table_cell_field(s, norm_labels, short_labels=short_labels)
        if _accept(tv):
            ok = True
            if negation_guard:
                idx = s.find(tv)
                if idx >= 0 and _negation_in_clause(s, idx, idx + len(tv)):
                    ok = False
            if ok:
                return (tv, "table")

    # ── Pass 3: heading-as-value (`# Field` then next line) ──
    hv = _heading_field(s, ordered)
    if _accept(hv):
        if not (negation_guard and (lambda i: i >= 0 and _negation_in_clause(s, i, i + len(hv)))(s.find(hv))):
            return (hv, "heading")

    # ── Zero-harvest tripwire ──
    # Evidence = a label clearly appears in the text, yet we harvested nothing.
    label_present = False
    for nl in norm_labels:
        if not nl:
            continue
        if nl in short_labels:
            if re.search(r"(?<!\w)" + re.escape(nl) + r"(?!\w)", _norm_key(s)):
                label_present = True
                break
        elif nl in _norm_key(s):
            label_present = True
            break
    if label_present:
        log.warning(
            "_field_anywhere: label(s) %r present in text but no value "
            "harvested (table_ok=%s, value_pattern=%r, negation_guard=%s) — "
            "possible shape miss, falling back",
            list(labels), table_ok, value_pattern, negation_guard,
        )
    return ("", "none")


# ── Site 2 (regex-fragility plan): niche spawn-manifest tolerance ────────────
#
# Two sibling parsers read the `## Niche Agents` manifest table and decide which
# niche analysis lanes spawn: `_required_niche_worker_jobs` (driver, the
# consumer) and `_niche_tokens_from_required_table` (validators, the producer
# reconciler). A MISSED Required row means a whole analysis lane never spawns —
# a silent recall hole. Both used:
#   * an EXACT `## Niche Agents` heading (`re.match(r"^##+\s+Niche Agents\b")`),
#     missing `# Niche Agents` / synonym renderings; and
#   * a literal `YES` substring in the Required cell, missing `Required` / `Y` /
#     the `✓`/`✔` check glyphs the LLM uses interchangeably.
# These two helpers are the shared, fixture-hardened tolerance both call.

# Heading synonyms for the niche manifest section. The matcher below is
# `#{1,6}` tolerant (strict superset of the old `##+`) and accepts the
# documented synonym renderings.
_NICHE_HEADING_SYNONYMS: tuple[str, ...] = (
    "Niche Agents",
    "Niche Agent Manifest",
    "Niche Analysis Agents",
    "Niche Depth Agents",
)
_NICHE_HEADING_RE = re.compile(
    r"^\s*#{1,6}\s+(?:\*\*|`)?\s*(?:"
    + "|".join(re.escape(s) for s in _NICHE_HEADING_SYNONYMS)
    + r")\b",
    re.IGNORECASE,
)

# Affirmative tokens for a manifest Required cell. Matched with word boundaries
# (so `Y` does not fire on `YET`, `Required` does not fire on `not required`'s
# negation — guarded below). The check glyphs are bare-codepoint matched.
_NICHE_REQUIRED_AFFIRMATIVE: tuple[str, ...] = (
    "yes", "required", "y", "true", "mandatory",
)
_NICHE_REQUIRED_WORD_RE = re.compile(
    r"(?<!\w)(?:" + "|".join(_NICHE_REQUIRED_AFFIRMATIVE) + r")(?!\w)",
    re.IGNORECASE,
)
_NICHE_REQUIRED_GLYPHS: frozenset = frozenset({"✓", "✔", "☑", "✅"})


def _niche_heading_match(line: str) -> bool:
    """True iff `line` is a niche-manifest section heading (any level/synonym)."""
    return bool(_NICHE_HEADING_RE.match(_llm_norm(line)))


def _niche_required_cell_yes(cell: str) -> bool:
    """True iff a manifest Required cell affirmatively marks the row required.

    Strict superset of the legacy `"YES" in cell.upper()`:
      * `YES` (legacy) still matches.
      * `Required` / `Y` / `True` / `Mandatory` newly match (word-boundary, so
        `Y` does not fire on `MAYBE`/`YET`, and a longer word is not partially
        matched).
      * check glyphs `✓ ✔ ☑ ✅` newly match.
    A clause-scoped negation guard suppresses an affirmative governed by a
    negation in the same cell (`not required`, `no` → row is NOT required),
    mirroring the Site 5 recall-safe negation discipline. Recall-direction:
    this only ever marks MORE rows required (more lanes spawn), except the
    negation guard which removes a FALSE affirmative — both are recall-safe for
    the spawn decision (a falsely-required lane wastes a slot; a falsely-skipped
    lane silently drops findings, the worse error this widening prevents).
    """
    if not cell:
        return False
    s = _llm_norm(cell)
    if any(g in s for g in _NICHE_REQUIRED_GLYPHS):
        return True
    m = _NICHE_REQUIRED_WORD_RE.search(s)
    if not m:
        return False
    # Negation guard: if a negation token shares the cell-clause with the
    # affirmative, the cell is asserting the row is NOT required. Blank the
    # affirmative token itself first so e.g. "required" is not read as a
    # negation source; then look for an EXTERNAL negation in the cell-clause.
    clause = _clause_around(s, m.start(), m.end())
    blanked = clause.replace(m.group(0), " " * len(m.group(0)), 1)
    if _NEGATION_GUARD_RE.search(blanked):
        return False
    return True


_SUFFIX_STRIP_RE = re.compile(r"(tion|ing|ness|ment|able|ible|ful|less|ous|ive|ed|er|ly|es|s)$")


def _stem_token(t: str) -> str:
    """Aggressive-enough suffix stripping without a synonym map."""
    if len(t) <= 4:
        return t
    return _SUFFIX_STRIP_RE.sub("", t)


def _title_tokens(text: str) -> set[str]:
    """Tokenize a finding title for overlap scoring."""
    stop = frozenset({
        "the", "a", "an", "in", "on", "at", "to", "for", "of", "via",
        "and", "or", "but", "not", "is", "are", "was", "were", "be",
        "has", "have", "had", "does", "do", "did", "can", "could",
        "may", "might", "will", "would", "shall", "should",
        "all", "any", "each", "every", "some", "no", "none",
        "when", "during", "after", "before", "between", "from",
        "only", "also", "still", "yet", "with", "without", "by",
        "this", "that", "which", "its", "into", "if", "then",
        "using", "uses", "used", "create", "leads", "results",
        "allows", "causes", "triggers", "instead", "about",
    })
    raw = set(re.sub(r"[^a-z0-9_]+", " ", text.lower()).split()) - stop
    return {_stem_token(t) for t in raw if t}


def _titles_overlap_score(a: str, b: str) -> float:
    """Score how likely two finding titles describe the same root cause.

    Uses max-containment ratio with suffix stripping (no synonym map).
    Returns a float in [0.0, 1.0]. Callers pick their own threshold.

    IMPORTANT: This function measures TITLE SIMILARITY, not "same bug".
    Two genuinely different bugs CAN have similar titles (e.g., "panic via
    unwrap in X" vs "panic via unwrap in Y"). Callers MUST combine the
    score with additional context (same file, same function) before making
    merge decisions. Used for CANDIDATE IDENTIFICATION, not final merges.
    """
    ta, tb = _title_tokens(a), _title_tokens(b)
    if not ta or not tb:
        return 0.0
    intersection = ta & tb
    if not intersection:
        return 0.0
    containment = max(len(intersection) / len(ta), len(intersection) / len(tb))
    # Anchor boost: shared specific identifiers (function/struct names
    # containing underscores, or long camelCase >8 chars). A shared
    # specific identifier is a strong signal of the same code area.
    anchor_a = {t for t in ta if "_" in t}
    anchor_b = {t for t in tb if "_" in t}
    if anchor_a & anchor_b:
        containment = min(containment + 0.20, 1.0)
    return containment


def _shared_anchor_tokens(a: str, b: str) -> set[str]:
    """Return specific identifiers (function/struct names) shared by both titles."""
    ta, tb = _title_tokens(a), _title_tokens(b)
    anchor_a = {t for t in ta if "_" in t}
    anchor_b = {t for t in tb if "_" in t}
    return anchor_a & anchor_b


_LINE_RANGE_RE = re.compile(r":L?(\d+)(?:\s*[-–]\s*L?(\d+))?")


def _parse_line_range(location: str) -> tuple[int, int] | None:
    """Extract (start, end) line range from a location string.

    Handles: ``file.rs:L40``, ``file.rs:L40-L65``, ``file.rs:40-65``.
    Returns None if no line info found.  Single-line → (N, N).
    """
    m = _LINE_RANGE_RE.search(location)
    if not m:
        return None
    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else start
    if end < start:
        start, end = end, start
    return (start, end)


def _line_ranges_overlap(a: tuple[int, int], b: tuple[int, int],
                         proximity: int = 15) -> bool:
    """True if two line ranges overlap or are within ``proximity`` lines."""
    return a[0] <= b[1] + proximity and b[0] <= a[1] + proximity


def _extract_ids_from_text(text: str) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for tok in re.findall(r"\b[A-Z][A-Z0-9]{0,6}-\d+\b", text or ""):
        if tok not in seen:
            seen.add(tok)
            ordered.append(tok)
    return ordered


def _extract_first_tag(text: str) -> str:
    m = re.search(r"(\[[A-Z0-9\-]+\])", text or "")
    return m.group(1) if m else ""


def _parse_source_findings_for_ids(path: Path) -> list[dict[str, str]]:
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    findings: list[dict[str, str]] = []
    # Heading tolerance (Tier C): accept `#{2,6} Finding [ID]` instead of the
    # H3-exact `^###` form (strict superset — every old H3 still matches). The
    # per-block Location is harvested with the shared `_field_anywhere`
    # extractor, which accepts bold (`**Location**:`), plain, bullet,
    # `**Location:**`, backtick, `=`-separated, and TABLE-CELL renderings — the
    # old literal `^**Location**:` regex missed all but the bold-colon form.
    heading_re = re.compile(
        r"(?im)^\s*#{2,6}\s+Finding\s+\[([A-Z][A-Z0-9]{0,6}-\d+)\]"
    )
    matches = list(heading_re.finditer(text))
    for i, m in enumerate(matches):
        fid = m.group(1)
        start = m.end()
        # title = the heading line as written (preserve legacy "title" value:
        # the stripped heading line).
        line_end = text.find("\n", m.start())
        title = text[m.start():(line_end if line_end != -1 else len(text))].strip()
        block_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:block_end]
        loc_val, _ = _field_anywhere(block, ("Location", "Locations"), table_ok=True)
        findings.append({
            "id": fid,
            "title": title,
            "location": _norm_loc(loc_val) if loc_val else "",
        })
    return findings


def _parse_chunk_heading_inventory(text: str) -> list[dict[str, object]]:
    lines = text.splitlines()
    entries: list[dict[str, object]] = []
    starts = [
        idx for idx, line in enumerate(lines)
        if re.match(r"^\s*#{2,4}\s+Finding\b", line)
    ]
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(lines)
        block = [x.rstrip() for x in lines[start:end] if x.strip()]
        if not block:
            continue
        heading = block[0].strip()
        title = re.sub(r"^#{2,4}\s+(?:Finding\s+\[[^\]]+\]:\s*)?", "", heading).strip()
        title = re.sub(r"\s*-\s*(Critical|High|Medium|Low|Informational|Info)\s*$", "", title, flags=re.I)
        entry: dict[str, object] = {
            "title": _strip_md(title),
            "severity": "",
            "location": "",
            "source_ids": [],
            "preferred_tag": "",
            "verdict": "",
            "root_cause": "",
            "description": "",
            "impact": "",
            **_optional_finding_metadata_defaults(),
        }
        m = re.match(r"^#{2,4}\s+Finding\s+\[([^\]]+)\]:?", heading)
        if m:
            entry["local_id"] = m.group(1)
        else:
            m = re.match(r"^#{2,4}\s+Finding\s+([A-Z][A-Z0-9-]*-\d+)\b", heading)
            if m:
                entry["local_id"] = m.group(1)
        for row in block[1:]:
            # Format-tolerant field extraction: handles bullets (- / *),
            # bold wrapping (**Label**: / **Label:**), and absence of bold.
            fm = re.match(
                r"^\s*[-*]?\s*(?:\*\*)?([^:*]+?)(?:\*\*)?"
                r"\s*(?:\([^)]*\))?\s*:\s*(.*)",
                row,
            )
            if not fm:
                continue
            label_lc = fm.group(1).strip().lower()
            val_raw = fm.group(2).strip()
            if label_lc == "location":
                entry["location"] = _norm_loc(val_raw)
            elif label_lc == "severity":
                sev_val = _strip_md(val_raw)
                if _non_reportable_marker(sev_val):
                    entry["severity"] = "Informational"
                    if not entry.get("verdict"):
                        entry["verdict"] = "REFUTED"
                elif _ambiguous_na_marker(sev_val):
                    entry["severity"] = "Informational"
                    if not entry.get("verdict"):
                        entry["verdict"] = "UNRESOLVED"
                else:
                    entry["severity"] = sev_val.capitalize()
            elif label_lc == "verdict":
                entry["verdict"] = _strip_md(val_raw)
            elif label_lc in (
                "evidence", "preferred tag", "preferred verification",
                "evidence tag", "evidence tags",
            ):
                entry["preferred_tag"] = _extract_first_tag(val_raw) or _strip_md(val_raw)
            elif label_lc == "root cause":
                entry["root_cause"] = _strip_md(val_raw)
            elif label_lc == "impact":
                entry["impact"] = _strip_md(val_raw)
            elif label_lc == "description":
                entry["description"] = _strip_md(val_raw)
            elif label_lc in ("source ids", "source id"):
                entry["source_ids"] = _extract_ids_from_text(val_raw)
            else:
                opt_field = _optional_finding_metadata_field_for_label(label_lc)
                if opt_field:
                    entry[opt_field] = _strip_md(val_raw)
        if _non_reportable_marker(str(entry.get("severity", ""))) or _non_reportable_marker(str(entry.get("verdict", ""))):
            entry["severity"] = "Informational"
            if not entry.get("verdict"):
                entry["verdict"] = "REFUTED"
        elif _ambiguous_na_marker(str(entry.get("severity", ""))):
            entry["severity"] = "Informational"
            if not entry.get("verdict"):
                entry["verdict"] = "UNRESOLVED"
        entries.append(entry)
    return entries


def _parse_chunk_table_inventory(text: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for headers, rows in _parse_markdown_tables(text, ["title", "severity", "location"]):
        key_map = {idx: _norm_key(h) for idx, h in enumerate(headers)}
        for row in rows:
            entry: dict[str, object] = {
                "title": "",
                "severity": "",
                "location": "",
                "source_ids": [],
                "preferred_tag": "",
                "verdict": "",
                "root_cause": "",
                "description": "",
                "impact": "",
                **_optional_finding_metadata_defaults(),
            }
            for idx, cell in enumerate(row):
                key = key_map.get(idx, "")
                val = _strip_md(cell)
                if "finding id" in key or key == "id":
                    entry["local_id"] = val
                elif "title" in key:
                    entry["title"] = val
                elif "severity" in key:
                    if _non_reportable_marker(val):
                        entry["severity"] = "Informational"
                        if not entry.get("verdict"):
                            entry["verdict"] = "REFUTED"
                    elif _ambiguous_na_marker(val):
                        entry["severity"] = "Informational"
                        if not entry.get("verdict"):
                            entry["verdict"] = "UNRESOLVED"
                    else:
                        entry["severity"] = val.capitalize()
                elif "location" in key:
                    entry["location"] = _norm_loc(val)
                elif "source id" in key or key == "source":
                    entry["source_ids"] = _extract_ids_from_text(val)
                elif "evidence" in key:
                    entry["preferred_tag"] = _extract_first_tag(val) or val
                elif "verdict" in key:
                    entry["verdict"] = val
                elif "root cause" in key:
                    entry["root_cause"] = val
                elif "description" in key:
                    entry["description"] = val
                elif "impact" in key:
                    entry["impact"] = val
                elif "vulnerability class" in key and not entry["root_cause"]:
                    entry["root_cause"] = val
                else:
                    opt_field = _optional_finding_metadata_field_for_label(key)
                    if opt_field:
                        entry[opt_field] = val
            if _non_reportable_marker(str(entry.get("severity", ""))) or _non_reportable_marker(str(entry.get("verdict", ""))):
                entry["severity"] = "Informational"
                if not entry.get("verdict"):
                    entry["verdict"] = "REFUTED"
            elif _ambiguous_na_marker(str(entry.get("severity", ""))):
                entry["severity"] = "Informational"
                if not entry.get("verdict"):
                    entry["verdict"] = "UNRESOLVED"
            if entry["title"] or entry["location"]:
                entries.append(entry)
    return entries


def _parse_inventory_chunk(path: Path) -> list[dict[str, object]]:
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    parsed = _parse_chunk_table_inventory(text) + _parse_chunk_heading_inventory(text)
    merged: dict[tuple[str, str], dict[str, object]] = {}
    order: list[tuple[str, str]] = []
    for entry in parsed:
        local = _normalize_finding_id(str(entry.get("local_id", "")))
        if local:
            key = ("id", local)
        else:
            key = (
                _norm_key(str(entry.get("title", ""))),
                _norm_loc(str(entry.get("location", ""))),
            )
        if not key[0] or key in {("", ""), ("id", "")}:
            continue
        if key not in merged:
            merged[key] = entry
            order.append(key)
            continue
        cur = merged[key]
        for field in (
            "title", "severity", "location", "preferred_tag", "verdict",
            "root_cause", "description", "impact", "local_id",
            *_OPTIONAL_FINDING_METADATA_FIELDS,
        ):
            if not cur.get(field) and entry.get(field):
                cur[field] = entry.get(field)
            elif len(str(entry.get(field, ""))) > len(str(cur.get(field, ""))) and field in {"root_cause", "description", "impact", *_OPTIONAL_FINDING_METADATA_FIELDS}:
                cur[field] = entry.get(field)
        cur_ids = list(cur.get("source_ids", []) or [])
        for sid in list(entry.get("source_ids", []) or []):
            if sid not in cur_ids:
                cur_ids.append(sid)
        cur["source_ids"] = cur_ids
    return [merged[k] for k in order]


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get((sev or "").strip().lower(), -1)


def _merge_inventory_entries(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    merged: dict[tuple[str, str], dict[str, object]] = {}
    order: list[tuple[str, str]] = []
    for entry in entries:
        loc = _norm_loc(str(entry.get("location", "")))
        title_key = _norm_key(str(entry.get("title", "")))
        # Conservative merge: only coalesce exact title+location duplicates.
        # A single location can contain multiple sibling bugs (loop early-exit,
        # >= vs ==, missing field check). Root-cause-only merging overcut those
        # into one row, hiding true positives before verification. Duplicates
        # are cheaper than false drops; later consolidation can merge proven
        # duplicates after verification.
        key = (loc, title_key)
        if not loc or not title_key:
            continue
        if key not in merged:
            source_ids = list(entry.get("source_ids", []))
            local_id = entry.get("local_id")
            if local_id and local_id not in source_ids:
                source_ids.append(local_id)
            merged[key] = {
                "title": entry.get("title", ""),
                "severity": entry.get("severity", ""),
                "location": loc,
                "source_ids": source_ids,
                "preferred_tag": entry.get("preferred_tag", ""),
                "verdict": entry.get("verdict", ""),
                "root_cause": entry.get("root_cause", ""),
                "description": entry.get("description", ""),
                "impact": entry.get("impact", ""),
                **{
                    field: entry.get(field, "")
                    for field in _OPTIONAL_FINDING_METADATA_FIELDS
                },
            }
            order.append(key)
            continue
        cur = merged[key]
        if _severity_rank(str(entry.get("severity", ""))) > _severity_rank(str(cur.get("severity", ""))):
            cur["severity"] = entry.get("severity", "")
        if not cur.get("preferred_tag") and entry.get("preferred_tag"):
            cur["preferred_tag"] = entry.get("preferred_tag", "")
        if not cur.get("verdict") and entry.get("verdict"):
            cur["verdict"] = entry.get("verdict", "")
        for field in (
            "root_cause", "description", "impact", "title",
            *_OPTIONAL_FINDING_METADATA_FIELDS,
        ):
            if len(str(entry.get(field, ""))) > len(str(cur.get(field, ""))):
                cur[field] = entry.get(field, "")
        local_id = entry.get("local_id")
        if local_id and local_id not in cur["source_ids"]:
            cur["source_ids"].append(local_id)
        for fid in entry.get("source_ids", []):
            if fid not in cur["source_ids"]:
                cur["source_ids"].append(fid)
    items = [merged[k] for k in order]
    items.sort(key=lambda e: (-_severity_rank(str(e.get("severity", ""))), _norm_key(str(e.get("title", "")))))
    return items


def _dedup_live_pair_cap() -> int:
    """Resolve the live-pair cap.

    The cap bounds how many candidate pairs are written into the live packet(s)
    handed to the per-pair LLM dedup judge. It is NOT a blind-merge cap — every
    admitted pair is still individually MERGE/KEEP judged by the dedup prompt
    (and gated by the mechanical survivor-superset rule). Raising it only widens
    how many genuine candidates reach the LLM; it never auto-merges.

    Default 250 covers the observed 205-pair L1 case in one pass. Env
    override ``PLAMEN_DEDUP_LIVE_PAIR_CAP`` lets ops dial it down without code
    change if a future inventory is pathologically large.
    """
    raw = os.environ.get("PLAMEN_DEDUP_LIVE_PAIR_CAP", "")
    if raw.strip():
        try:
            val = int(raw.strip())
            if val > 0:
                return val
        except (TypeError, ValueError):
            pass
    return _DEDUP_LIVE_PAIR_CAP_DEFAULT


# Default cap on the number of candidate pairs admitted into the live LLM
# work packet(s). Per-pair LLM judgment is retained for every admitted pair;
# this is a context-budget bound, NOT a blind-merge cap. Overridable via
# PLAMEN_DEDUP_LIVE_PAIR_CAP.
# TURN-SAFE bound. semantic_dedup runs as ONE subprocess in ONE turn, so the
# live cap is the per-turn pair budget. The previous 250 (split into 80-pair
# "rounds") was a regression: the multi-round prompt still asks the SINGLE
# subprocess to evaluate every round, so ~240 pairs of focus-inventory input +
# per-pair decision output blew the 32K output-token cap AND saturated context
# (100% context used) -> 0 decisions, hung. 50 keeps both input (focus
# inventory) and output (decisions) well inside one turn (the long-proven safe
# value was 24; 50 is ~2x that and ~1/5 of the overflow point). Per-round
# SEPARATE subprocesses would let this go higher without overflow (future).
# Overridable via PLAMEN_DEDUP_LIVE_PAIR_CAP for operators on bigger budgets.
_DEDUP_LIVE_PAIR_CAP_DEFAULT = 50

# Keep chunk == cap so len(live_pairs) <= _DEDUP_ROUND_CHUNK is ALWAYS true ->
# exactly ONE round of <= cap pairs reaches the single subprocess, and EVERY
# live pair is per-pair LLM-judged in that one round (no orphaned rounds that
# only the mechanical supplemental fallback would touch). The dedup phase does
# NOT (yet) re-invoke one subprocess PER round, so multi-round-in-one-turn must
# never happen — chunk < cap would strand rounds 2..N unjudged by the LLM.
#
# The real per-turn context pressure was NOT the ~50 focus-inventory bodies; it
# was the SC override forcing the agent to READ the full findings_inventory.md
# AND REWRITE it verbatim into findings_inventory_deduped.md in the same turn.
# That read+rewrite of the whole inventory is now removed: the agent emits
# decisions-only (dedup_decisions.md) and the driver mechanically builds the
# deduped inventory via plamen_mechanical.apply_llm_dedup_decisions. With the
# inventory rewrite gone and only the BOUNDED per-round focus packet read, 50
# per-pair judgements fit comfortably in one turn. Per-round SEPARATE
# subprocesses would let this go higher without overflow (future work).
_DEDUP_ROUND_CHUNK = 50

# Findings whose depth source-ID set exceeds this threshold are treated as
# depth-aggregate / perturbation findings. For such findings the source-ID
# subset and PERT-lineage signals MISFIRE (a single shared source ID makes the
# subset signal fire even though the defects differ), so those two signals are
# SUPPRESSED as candidate-generation hints. The pair may still surface on
# location / title / function-name signals. Heuristic from a prior L1
# post-mortem (two inventory findings carried 15-element source sets).
_DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD = 4

# Back-compat alias. Historically a hard live limit of 24; retained as a name
# so any external reference resolves, but the live cap is now resolved via
# _dedup_live_pair_cap() (env-overridable, default 250).
_DEDUP_LIVE_PAIR_LIMIT = 24

# In-context CLUSTERING block-size range. A signal cluster is normalized into
# blocks of this size before being handed to the dedup judge: clusters > MAX are
# split into near-equal sub-blocks (sharing one [key:] so union-find still links
# cross-sub-block duplicates); clusters < MIN are kept as-is (small blocks are
# cheap; never padded with unrelated findings). The block path's OUTPUT scales
# with n (line-oriented merge groups, a few KB for any n), unlike the legacy
# O(n^2) pair path — so the per-turn block budget can be far larger than the
# legacy 50-pair cap without blowing the output-token ceiling.
_DEDUP_BLOCK_MIN = 4
_DEDUP_BLOCK_MAX = 18


def _dedup_block_max() -> int:
    """Resolve the maximum block size for in-context clustering.

    Mirrors ``_dedup_live_pair_cap``: env override ``PLAMEN_DEDUP_BLOCK_MAX``
    lets ops dial the per-block size without code change; falls back to
    ``_DEDUP_BLOCK_MAX`` (18). A value < ``_DEDUP_BLOCK_MIN`` is clamped up to
    the min so a block is never sized below the floor.
    """
    raw = os.environ.get("PLAMEN_DEDUP_BLOCK_MAX", "")
    if raw.strip():
        try:
            val = int(raw.strip())
            if val > 0:
                return max(val, _DEDUP_BLOCK_MIN)
        except (TypeError, ValueError):
            pass
    return _DEDUP_BLOCK_MAX


def _dedup_extract_findings(inv_text: str) -> list[dict]:
    """Extract the per-finding dedup model from inventory/queue markdown text.

    Single source of truth for BOTH ``_compute_dedup_candidate_pairs`` and
    ``_compute_dedup_candidate_blocks``. Each returned dict carries the exact
    fields the signal predicates and the block/pair writers consume:

      ``id, title, location, severity, file, _lines, _source_ids, _func, _block``

    The extraction logic is verbatim the loop that historically lived inline in
    ``_compute_dedup_candidate_pairs`` (location/severity via the tolerant
    ``_field_anywhere`` extractor, function-name parse, source-ID parse). Keeping
    it in one helper guarantees the pair fallback and the block path see an
    IDENTICAL finding set.
    """
    findings: list[dict] = []
    for m in re.finditer(
        r"#{2,4}\s+(?:Finding\s+)?\[((?:INV|F)-\d+)\]:?\s*(.+?)(?:\n|$)"
        r"((?:.*\n)*?)"
        r"(?=#{2,4}\s+(?:Finding\s+)?\[(?:INV|F)-|\Z)",
        inv_text,
    ):
        inv_id = m.group(1)
        title = m.group(2).strip()
        body = m.group(3)
        # Location / Severity via the shared tolerant extractor: accepts
        # bold (`**Location**:`), plain (`Location:`), bullet, `**Location:**`,
        # backtick, `=`-separated, and TABLE-CELL (`| Location | ... |`)
        # renderings. The old `**Location**:` / `**Severity**:`-exact regexes
        # missed every non-bold form, silently dropping dedup-pair candidates
        # (recall hole). Strict superset — every bold form still matches.
        loc, _ = _field_anywhere(body, ("Location", "Locations"), table_ok=True)
        sev_val, _ = _field_anywhere(body, ("Severity", "Final Severity"), table_ok=True)
        loc = loc.strip()
        # Legacy `**Severity**:\s*(\w+)` captured only the first word token;
        # preserve that value-identity.
        sev = ""
        if sev_val:
            sm = re.match(r"\s*\**\s*(\w+)", sev_val)
            sev = sm.group(1) if sm else sev_val.strip()
        norm = _norm_loc(loc)
        file_part = re.sub(r":L?\d+.*$", "", norm)
        line_range = _parse_line_range(norm)
        # Extract function name from Location field patterns like:
        #   Contract.sol:functionName:L42  or  src/lib.rs:my_func:L10-L20
        #   or  `Contract.sol:functionName` (backtick-wrapped)
        func_name = ""
        func_m = re.search(
            r"[./\w]+\.(?:sol|rs|move|ts|go):"
            r"([a-zA-Z_][a-zA-Z0-9_]*)"
            r"(?::?L?\d|[`\s,|]|$)",
            loc,
        )
        if func_m:
            candidate = func_m.group(1)
            # Filter out line references (L42, Line10) and keywords
            if (
                candidate.lower() not in ("l", "line", "lines")
                and not re.fullmatch(r"[Ll]\d+", candidate)
            ):
                func_name = candidate
        # Extract source IDs (e.g. [D-58,D-59] or [PERT-3]) using the same
        # format-tolerant contract as inventory parity.
        source_ids: set[str] = set()
        for src_line in body.splitlines():
            src_m = _SOURCE_IDS_LINE_RE.match(src_line)
            if src_m:
                source_ids = set(_split_source_id_tokens(src_m.group(1)))
                break
        findings.append({
            "id": inv_id, "title": title, "location": loc,
            "severity": sev, "file": file_part,
            "_lines": line_range, "_source_ids": source_ids,
            "_func": func_name,
            "_block": f"### Finding [{inv_id}]: {title}\n{body}".rstrip(),
        })
    return findings


def _compute_dedup_candidate_pairs(scratchpad: Path) -> int:
    """Identify candidate duplicate pairs in findings_inventory.md.

    Groups findings by file, then pairs by THREE independent signals:
      1. **Location overlap** (primary): same file + line ranges within 15 lines
      2. **Title overlap** (secondary): same file + ≥0.50 token overlap or anchor
      3. **Function-name match** (tertiary): same file + same function name
         extracted from Location field (e.g., ``Contract.sol:functionName:L42``)

    Location overlap catches the hard case: agents describing the same code
    from different angles with completely different vocabulary.  Title overlap
    catches the easy case: near-identical rewordings.  Function-name match
    catches findings targeting the same function but at different line offsets
    (e.g., entry check vs exit path of the same function).

    Aggregate-suppression: for any cross-file candidate where EITHER finding
    carries more than ``_DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD`` depth source IDs
    (depth-aggregate / perturbation findings), the source-ID-subset and
    PERT-lineage signals are SUPPRESSED — they misfire on these large sets and
    are the worst false-merge class. Such pairs may still surface via
    location / title / function-name signals.

    Multi-round: when the live candidate count exceeds ``_DEDUP_ROUND_CHUNK``,
    per-round sub-packets (``dedup_candidate_pairs_round{N}.md`` +
    ``dedup_focus_inventory_round{N}.md``) are written in addition to the
    unified round-1 ``dedup_candidate_pairs.md`` so single-round consumers keep
    working. The driver decides single vs multi-round. Each pair appears in
    exactly one round.

    NEVER merges findings — only identifies candidates for LLM review. The five
    signals are candidate-generation HINTS only; this function performs no
    auto-merge.

    Returns the total number of candidate pairs written (live + deferred).
    """
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return 0
    try:
        inv_text = _llm_norm(inv.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0

    if inv_text and not inv_text.endswith("\n"):
        inv_text += "\n"

    # Extract (inv_id, title, location, severity, source_ids) for each finding
    # via the shared helper so the pair builder and the block builder operate on
    # an IDENTICAL finding model (single source of truth — see
    # _dedup_extract_findings).
    findings: list[dict] = _dedup_extract_findings(inv_text)

    # Group by file (for location/title/anchor signals — same-file only)
    file_groups: dict[str, list[int]] = {}
    for idx, f in enumerate(findings):
        if f["file"] and f["file"] != "unknown":
            file_groups.setdefault(f["file"], []).append(idx)

    # Use a set of sorted (id_a, id_b) tuples to deduplicate —
    # a pair can qualify on MULTIPLE signals.
    seen_pairs: set[tuple[str, str]] = set()
    pairs: list[tuple[dict, dict, float, str]] = []

    # ── Same-file signals: location overlap, title overlap, anchor ──
    for file_part, indices in file_groups.items():
        for i, idx_a in enumerate(indices):
            for idx_b in indices[i + 1:]:
                fa, fb = findings[idx_a], findings[idx_b]
                pair_key = (fa["id"], fb["id"])
                if pair_key in seen_pairs:
                    continue

                reasons: list[str] = []

                # Signal 1: location overlap (primary)
                lr_a, lr_b = fa["_lines"], fb["_lines"]
                if lr_a and lr_b and _line_ranges_overlap(lr_a, lr_b):
                    reasons.append(
                        f"location overlap (L{lr_a[0]}-{lr_a[1]} vs L{lr_b[0]}-{lr_b[1]})"
                    )

                # Signal 2: title overlap (secondary)
                score = _titles_overlap_score(fa["title"], fb["title"])
                anchors = _shared_anchor_tokens(fa["title"], fb["title"])
                if score >= 0.50:
                    reasons.append(f"title overlap {score:.2f}")
                elif anchors:
                    reasons.append(
                        f"shared identifier: {', '.join(sorted(anchors))}"
                    )

                # Signal 5: function-name match (tertiary)
                if fa["_func"] and fb["_func"] and fa["_func"] == fb["_func"]:
                    reasons.append(f"same function: {fa['_func']}")

                if reasons:
                    seen_pairs.add(pair_key)
                    pairs.append((fa, fb, score, " + ".join(reasons)))

    # ── Cross-file signals: source-ID subset, PERT-* lineage ──
    # These fire across ANY pair (same or different file).
    _PERT_RE = re.compile(r"^PERT-\d+$", re.IGNORECASE)
    # Count of pairs for which the subset/PERT signals were suppressed because
    # a side is a large-aggregate finding. Used only for the header note.
    aggregate_suppressed_count = 0
    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            fa, fb = findings[i], findings[j]
            pair_key = (fa["id"], fb["id"])
            if pair_key in seen_pairs:
                continue

            cross_reasons: list[str] = []

            sa, sb = fa["_source_ids"], fb["_source_ids"]

            # Aggregate-suppression: depth-aggregate / perturbation findings
            # carry large source-ID sets, so the subset and PERT-lineage
            # signals MISFIRE (a single shared source ID makes the subset
            # signal fire even though the defects differ). When EITHER side
            # exceeds the threshold, suppress those two false-merge-prone
            # signals for this pair. The pair can still surface on
            # location/title/function-name. This is the worst false-merge
            # class per a prior L1 post-mortem (e.g. two inventory findings
            # carrying 15-element source sets).
            aggregate_suppressed = (
                len(sa) > _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD
                or len(sb) > _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD
            )
            # Track suppression only when the signals WOULD have fired (some
            # shared source ID exists) so the header count reflects real
            # suppressions, not every large-aggregate pair.
            if aggregate_suppressed and sa and sb and (sa & sb):
                aggregate_suppressed_count += 1

            # Signal 3: source-ID subset — if A's source IDs are a
            # non-empty proper subset of B's (or vice versa), A is
            # likely a partial view of the same bug that B covers
            # more completely. (Suppressed for large-aggregate findings.)
            if sa and sb and not aggregate_suppressed:
                if sa < sb:
                    cross_reasons.append(
                        f"source-ID subset ({', '.join(sorted(sa))} ⊂ {', '.join(sorted(sb))})"
                    )
                elif sb < sa:
                    cross_reasons.append(
                        f"source-ID subset ({', '.join(sorted(sb))} ⊂ {', '.join(sorted(sa))})"
                    )
                elif sa & sb and sa != sb:
                    overlap = sa & sb
                    cross_reasons.append(
                        f"source-ID overlap ({', '.join(sorted(overlap))} shared)"
                    )

            # Signal 4: PERT-* lineage — a PERT finding is a documented
            # derivative of a parent depth finding. If A's source IDs
            # contain a PERT-* token and B's source IDs contain the
            # parent of that PERT (or vice versa), they are lineage-linked.
            # Also pair if both source sets reference overlapping depth IDs
            # AND one contains PERT-*. (Suppressed for large-aggregate
            # findings — PERT findings are themselves the aggregate offenders.)
            pert_a = any(_PERT_RE.match(s) for s in sa) if sa else False
            pert_b = any(_PERT_RE.match(s) for s in sb) if sb else False
            if (pert_a or pert_b) and sa & sb and not aggregate_suppressed:
                cross_reasons.append("PERT lineage (shared depth source IDs)")

            if cross_reasons:
                seen_pairs.add(pair_key)
                score = _titles_overlap_score(fa["title"], fb["title"])
                pairs.append((fa, fb, score, " + ".join(cross_reasons)))

    if not pairs:
        (scratchpad / "dedup_candidate_pairs.md").write_text(
            "# Dedup Candidate Pairs\n\nNo candidate duplicate pairs found.\n",
            encoding="utf-8",
        )
        return 0

    # Sort: genuine same-code signals first, bare CC co-occurrence last.
    #
    # The limited live-pair budget must be spent on pairs that are likely to
    # be the SAME code/bug seen twice, not on pairs that merely co-occur in a
    # cross-cutting (CC) breadth sweep. The signals split into two strengths:
    #
    #   STRONG (genuine same-code): location overlap, source-ID subset
    #     (mechanical proof of containment), and PERT lineage (documented
    #     derivative sharing depth source IDs).
    #   WEAK (bare CC co-occurrence): "source-ID overlap" — partial shared
    #     source IDs with NEITHER set a subset of the other. This fires for
    #     unrelated findings that a breadth agent happened to cite together;
    #     it is provenance noise, not a same-code signal.
    #
    # Bare-CC-only pairs are demoted below every genuine same-code pair so the
    # budget is not exhausted by provenance noise (the failure that let the
    # clock-underflow x4 / pull_data x3 clusters escape dedup).
    #
    # NOTE: this only re-RANKS the candidate pairs handed to the dedup LLM. It
    # does NOT decide any merge and CANNOT drop a finding — pairs beyond the
    # live budget are preserved as deferred in dedup_candidate_pairs_full.md.
    def _sort_key(p: tuple) -> tuple:
        reason = p[3]
        has_loc = "location overlap" in reason
        has_subset = "source-ID subset" in reason
        has_pert = "PERT lineage" in reason
        # A pair whose ONLY source-ID signal is the bare partial overlap
        # (and which has no location/subset/PERT genuine signal) is weak CC.
        has_bare_cc = "source-ID overlap" in reason
        is_genuine = has_loc or has_subset or has_pert
        bare_cc_only = has_bare_cc and not is_genuine
        return (
            -int(is_genuine),     # genuine same-code pairs first
            int(bare_cc_only),    # bare-CC-only pairs sink to the bottom
            -int(has_loc),        # within genuine, prefer location overlap
            -int(has_subset),     # then source-ID subset
            -p[2],                # then title score
        )

    sorted_pairs = sorted(pairs, key=_sort_key)

    live_cap = _dedup_live_pair_cap()
    live_pairs = sorted_pairs[:live_cap]
    deferred_pairs = sorted_pairs[live_cap:]

    findings_by_id = {f["id"]: f for f in findings}

    def _pair_row(fa: dict, fb: dict, score: float, reason: str) -> str:
        same_sev = (
            "Yes" if fa["severity"].lower() == fb["severity"].lower() else "No"
        )
        return (
            f"| {fa['id']}: {fa['title'][:50]} | "
            f"{fb['id']}: {fb['title'][:50]} | "
            f"{score:.2f} | {reason} | {same_sev} |"
        )

    def _signal_legend() -> list[str]:
        legend = [
            "Pairs are identified by five independent signals:",
            "- **Source-ID subset**: one finding's depth source IDs are a proper subset of the other's (strongest — mechanical proof of containment)",
            "- **PERT lineage**: perturbation finding shares depth source IDs with parent (strongest — documented derivative)",
            "- **Location overlap**: same file + line ranges within 15 lines (primary for same-file)",
            "- **Title overlap / shared identifiers**: same file + ≥0.50 token overlap (secondary)",
            "- **Function-name match**: same file + same function name from Location field (tertiary)",
        ]
        # Aggregate-suppression note: the subset/PERT hints are unreliable for
        # depth-aggregate / perturbation findings and were suppressed for those
        # pairs (>4 source IDs). The LLM must NOT treat the absence of a
        # subset/PERT signal on such pairs as evidence of distinctness, and
        # must NEVER merge on subset/PERT hints alone.
        legend.append(
            "- **(aggregate-suppressed: >4 source IDs)**: for findings carrying "
            f"more than {_DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD} depth source IDs "
            "(depth-aggregate / perturbation findings), the source-ID-subset and "
            "PERT-lineage hints are SUPPRESSED — they misfire on large source "
            "sets. Such pairs surface (if at all) only via location/title/"
            "function signals; judge them on a confirmed same-root-cause + "
            "same-fix reading of BOTH bodies, never on a subset/PERT hint."
        )
        if aggregate_suppressed_count:
            legend.append(
                f"- NOTE: {aggregate_suppressed_count} pair(s) had subset/PERT "
                "signals suppressed under the aggregate rule."
            )
        return legend

    def _render_pairs_table(
        title_line: str,
        header_count: int,
        note_lines: list[str],
        rows: list[tuple],
    ) -> str:
        out = ["# Dedup Candidate Pairs", "", title_line]
        out.extend(note_lines)
        out.append("")
        out.extend(_signal_legend())
        out.append("")
        out.append("| Finding A | Finding B | Title Score | Signal(s) | Same Sev? |")
        out.append("|-----------|-----------|-------------|-----------|-----------|")
        for fa, fb, score, reason in rows:
            out.append(_pair_row(fa, fb, score, reason))
        out.append("")
        return "\n".join(out)

    def _write_focus_inventory(path: Path, rows: list[tuple], packet_name: str) -> None:
        focus_ids = {item["id"] for fa, fb, _s, _r in rows for item in (fa, fb)}
        if not focus_ids:
            return
        focus_lines = [
            "# Dedup Focus Inventory",
            "",
            "This bounded file contains the full finding bodies for the IDs "
            f"referenced by `{packet_name}`. Use it for semantic review before "
            "falling back to the full inventory. The full bodies carry each "
            "finding's distinct Location(s), Source IDs, attack path, and "
            "impact so both sides of a candidate pair can be coupled on MERGE.",
            "",
        ]
        for f in findings:
            if f["id"] in focus_ids:
                focus_lines.append(str(f.get("_block", "")).rstrip())
                focus_lines.append("")
        path.write_text(
            "\n".join(focus_lines).rstrip() + "\n", encoding="utf-8"
        )

    # ── Determine single vs multi-round layout ──
    # Chunk only the LIVE pairs (the per-pair judged set). Deferred pairs
    # (beyond the cap) are written to dedup_candidate_pairs_full.md for
    # traceability and are never silently discarded.
    if len(live_pairs) <= _DEDUP_ROUND_CHUNK:
        rounds: list[list[tuple]] = [live_pairs] if live_pairs else []
    else:
        rounds = [
            live_pairs[i:i + _DEDUP_ROUND_CHUNK]
            for i in range(0, len(live_pairs), _DEDUP_ROUND_CHUNK)
        ]

    n_rounds = len(rounds)

    # Round 1's packet is ALSO the unified dedup_candidate_pairs.md so that
    # existing single-round consumers (driver, validators) keep working.
    if rounds:
        round1 = rounds[0]
        if n_rounds == 1:
            title_line = (
                f"{len(round1)} candidate pair(s) identified for LLM review."
            )
            note_lines: list[str] = []
            if deferred_pairs:
                note_lines = [
                    "",
                    f"Bounded work packet: showing top {len(live_pairs)} of "
                    f"{len(pairs)} candidate pair(s) (cap={live_cap}).",
                    "The full candidate set is preserved in "
                    "`dedup_candidate_pairs_full.md`.",
                    "Treat omitted pairs as deferred, not silently discarded.",
                ]
        else:
            title_line = (
                f"Round 1 of {n_rounds}: {len(round1)} candidate pair(s) for "
                "LLM review."
            )
            note_lines = [
                "",
                f"Multi-round work packet: {len(live_pairs)} live candidate "
                f"pair(s) (cap={live_cap}) split into {n_rounds} round(s) of "
                f"<= {_DEDUP_ROUND_CHUNK} pairs each.",
                "Evaluate ONLY this round's rows; later rounds are in "
                "`dedup_candidate_pairs_round{N}.md`. Decisions are appended "
                "across rounds and excluded pairs are not re-decided.",
            ]
            if deferred_pairs:
                note_lines.append(
                    "Pairs beyond the cap are preserved in "
                    "`dedup_candidate_pairs_full.md` (deferred, not discarded)."
                )

        unified = _render_pairs_table(
            title_line, len(round1), note_lines, round1
        )
        (scratchpad / "dedup_candidate_pairs.md").write_text(
            unified, encoding="utf-8"
        )
        _write_focus_inventory(
            scratchpad / "dedup_focus_inventory.md",
            round1,
            "dedup_candidate_pairs.md",
        )

        # Per-round sub-packets (only when multi-round).
        if n_rounds > 1:
            for ridx, round_rows in enumerate(rounds, start=1):
                rt_line = (
                    f"Round {ridx} of {n_rounds}: {len(round_rows)} candidate "
                    "pair(s) for LLM review."
                )
                rt_notes = [
                    "",
                    "Evaluate ONLY this round's rows. If the driver supplies an "
                    "`## Already-decided exclusion list`, do NOT re-decide those "
                    "pairs. Append decisions to dedup_decisions.md.",
                ]
                rt_packet = f"dedup_candidate_pairs_round{ridx}.md"
                (scratchpad / rt_packet).write_text(
                    _render_pairs_table(
                        rt_line, len(round_rows), rt_notes, round_rows
                    ),
                    encoding="utf-8",
                )
                _write_focus_inventory(
                    scratchpad / f"dedup_focus_inventory_round{ridx}.md",
                    round_rows,
                    rt_packet,
                )

    # ── Deferred (beyond-cap) traceability file ──
    if deferred_pairs:
        full_lines = [
            "# Dedup Candidate Pairs (Full Set)",
            "",
            f"{len(pairs)} candidate pair(s) identified for LLM review "
            f"({len(live_pairs)} live, {len(deferred_pairs)} deferred beyond "
            f"cap={live_cap}).",
            "Deferred pairs are preserved for traceability and are NOT silently "
            "discarded. Raise PLAMEN_DEDUP_LIVE_PAIR_CAP to admit more into the "
            "live LLM-judged set.",
            "",
            "| Finding A | Finding B | Title Score | Signal(s) | Same Sev? |",
            "|-----------|-----------|-------------|-----------|-----------|",
        ]
        for fa, fb, score, reason in sorted_pairs:
            full_lines.append(_pair_row(fa, fb, score, reason))
        full_lines.append("")
        (scratchpad / "dedup_candidate_pairs_full.md").write_text(
            "\n".join(full_lines), encoding="utf-8"
        )

    # ── Round-count marker (deterministic signal for the driver) ──
    try:
        (scratchpad / "dedup_round_count.txt").write_text(
            f"{n_rounds}\n", encoding="utf-8"
        )
    except Exception:
        pass

    return len(pairs)


# Report-stage cross-tier candidate cap. Mirrors the Fix-4 Hard DO-NOT: never
# raise the 50-pair dedup cap. Cross-tier near-identical pairs over a ~90-finding
# report index never approach this in practice; it is a safety ceiling only.
_REPORT_DEDUP_CANDIDATE_CAP = 50

# Fix-4 location tolerance. The FIRST Location range of two findings must match
# within this many lines on BOTH endpoints (near-identical range) to be a
# candidate. DO NOT loosen beyond ±3 — a wider window explodes to 40-55 false
# pairs on a dense report (per a dense-report precision post-mortem).
_REPORT_DEDUP_LINE_TOLERANCE = 3

# Fix 1 (item C): same-tier title-overlap threshold. Mirrors the threshold
# already used by the sibling inventory-level candidate builder
# (`_compute_dedup_candidate_pairs` Signal 2) for consistency — same-tier
# pairs below this score fall through to the shared-identifier signal instead.
_REPORT_DEDUP_TITLE_SCORE = 0.50


def _report_index_first_location(cell: str) -> tuple[str, tuple[int, int] | None]:
    """Extract (basename, first-line-range) from a Master Finding Index Location cell.

    The Location column can list several sites (``A.sol:10-20; B.sol:30``). This
    returns ONLY the FIRST location's file basename and line range — the "first
    Location range" the Fix-4 candidate list keys on. Returns ("", None) when no
    parseable ``file:Lnnn`` prefix exists (e.g. ``MessageRouter.sol (file)``).
    """
    norm = _norm_loc(cell)
    lr = _parse_line_range(norm)
    if lr is None:
        return "", None
    # Everything before the first `:digit` is the first file reference.
    file_head = re.sub(r":L?\d+.*$", "", norm).strip()
    # Guard against a leading prose token; take the last path-like component.
    fm = re.search(r"([\w./\-]+\.(?:sol|rs|move|ts|go|vy))\s*$", file_head)
    file_part = fm.group(1) if fm else file_head
    base = file_part.rsplit("/", 1)[-1].strip().lower()
    if not base:
        return "", None
    return base, lr


def _parse_report_index_master_rows(text: str) -> list[dict]:
    """Parse the Master Finding Index table into report-ID / title / location rows.

    Header-aware: resolves the Title / Severity / Location column positions from
    the table header so a reordered or extended index still parses. Only the
    ``## Master Finding Index`` section is read (the Tier Assignments / Excluded
    tables repeat report IDs and must NOT be treated as findings).
    """
    section = _report_index_assignment_text(text)
    id_re = re.compile(r"^[\*\[`_]*([CHMLI]-\d+)\b")
    col: dict[str, int] = {}
    rows: list[dict] = []
    for line in section.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        if _is_separator_row(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        # Header row: locate Title / Severity / Location columns by name.
        if not col:
            lowered = [c.lower() for c in cells]
            if any("location" in c for c in lowered) and any(
                "title" in c for c in lowered
            ):
                for idx, name in enumerate(lowered):
                    if "title" in name and "title" not in col:
                        col["title"] = idx
                    elif "severity" in name and "severity" not in col:
                        col["severity"] = idx
                    elif "location" in name and "location" not in col:
                        col["location"] = idx
                continue
        m = id_re.match(cells[0]) if cells else None
        if not m:
            continue
        report_id = m.group(1)
        loc_idx = col.get("location")
        title_idx = col.get("title")
        # Fall back to positional defaults (Report ID | Title | Severity |
        # Location) only if the header never resolved a Location column.
        if loc_idx is None:
            loc_idx = 3
        if title_idx is None:
            title_idx = 1
        location = cells[loc_idx] if loc_idx < len(cells) else ""
        title = cells[title_idx] if title_idx < len(cells) else ""
        rows.append({
            "report_id": report_id,
            "tier": report_id[0],
            "title": title,
            "location": location,
        })
    return rows


def _compute_report_dedup_candidate_pairs(scratchpad: Path) -> int:
    """Emit report_dedup_candidate_pairs.md — same-tier AND cross-tier HINTS.

    Fix 4 (cross-tier): read ``report_index.md``'s Master Finding Index and
    list every CROSS-TIER pair (report-ID prefix differs, e.g. High↔Medium)
    whose FIRST Location range matches within ±3 lines on BOTH endpoints on
    the same file basename. A precision post-mortem showed the mechanical
    report_dedup pass has no candidate list, so the H-01/M-06 identical-
    location twin (a High and a Medium describing the same permissionless
    ``withdraw`` at the same lines) never reached the LLM proposer.

    Fix 1 (item C, same-tier): the near-identical-location signal above now
    fires for SAME-TIER pairs too (the `if fa["tier"] == fb["tier"]: continue`
    skip that previously gated it out is removed). Same-tier pairs ALSO get
    two additional signals the sibling inventory-level candidate builder
    (`_compute_dedup_candidate_pairs`) already uses: title similarity
    (``_titles_overlap_score`` >= 0.50) and a shared specific identifier in
    the title (``_shared_anchor_tokens`` — e.g. a shared function/struct
    name), so two same-tier findings describing the same bug from different
    lines/wording still surface as a candidate. These two signals are scoped
    to SAME-TIER pairs only — cross-tier candidate generation is UNCHANGED
    (location-range only), preserving prior cross-tier behavior exactly.
    Without this, same-tier duplicate merging depended on the LLM doing
    unaided exhaustive pairwise comparison with no candidate scaffolding,
    which does not scale on a dense report (~10 surviving same-tier clusters
    observed on a real report).

    CANDIDATE-ONLY. This helper NEVER merges anything. The report_dedup_agent's
    same-root-cause + same-fix + describable-together test remains the SOLE merge
    authority, and the Python executor's zero-loss embed + data-loss gate is the
    final safety net. Distinct-mechanism findings that happen to sit at the same
    lines, or that merely share a title word/identifier, surface here purely as
    candidates for the LLM to VETO.

    Guards left UNCHANGED per Fix 4 / Fix 1: the report_dedup decision tree's
    anti-transitive / survivor-superset guard, the live-pair cap, and the
    Phase-4e never-cross-tier policy (unaffected — that policy governs a
    different phase's clustering, not this hint list). This helper adds a
    bounded (≤50) candidate list only; it never edits report_index.md or any
    merge/mapping artifact.

    Returns the number of candidate pairs written.
    """
    idx_path = scratchpad / "report_index.md"
    if not idx_path.exists():
        return 0
    try:
        text = _llm_norm(idx_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0

    rows = _parse_report_index_master_rows(text)

    # Attach first-location file basename + range; drop rows with no range.
    findings: list[dict] = []
    for r in rows:
        base, lr = _report_index_first_location(r["location"])
        if not base or lr is None:
            continue
        findings.append({**r, "_file": base, "_lines": lr})

    # Group by file basename; pair findings on the SAME file only.
    by_file: dict[str, list[int]] = {}
    for i, f in enumerate(findings):
        by_file.setdefault(f["_file"], []).append(i)

    tol = _REPORT_DEDUP_LINE_TOLERANCE
    title_thresh = _REPORT_DEDUP_TITLE_SCORE
    pairs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for _file, indices in by_file.items():
        for a in range(len(indices)):
            for b in range(a + 1, len(indices)):
                fa, fb = findings[indices[a]], findings[indices[b]]
                same_tier = fa["tier"] == fb["tier"]
                sa, ea = fa["_lines"]
                sb, eb = fb["_lines"]
                dstart = abs(sa - sb)
                dend = abs(ea - eb)

                signal = ""
                detail = ""
                if dstart <= tol and dend <= tol:
                    # Near-identical location: fires for ANY tier pairing
                    # (Fix 1 — previously cross-tier only).
                    signal = "location"
                    detail = f"±{dstart}/±{dend} lines"
                elif same_tier:
                    # Fix 1: same-tier-only fallback signals when the
                    # locations are NOT near-identical. Cross-tier candidate
                    # generation is unchanged (location-only, see docstring).
                    score = _titles_overlap_score(fa["title"], fb["title"])
                    if score >= title_thresh:
                        signal = "title"
                        detail = f"title overlap {score:.2f}"
                    else:
                        anchors = _shared_anchor_tokens(fa["title"], fb["title"])
                        if anchors:
                            signal = "anchor"
                            detail = f"shared identifier: {', '.join(sorted(anchors))}"

                if not signal:
                    continue

                key = tuple(sorted((fa["report_id"], fb["report_id"])))
                if key in seen:
                    continue
                seen.add(key)
                # Order the row so the higher-severity finding is listed first
                # (survivor hint), matching the agent's survivor-selection rule.
                order = "CHMLI"
                if order.index(fb["tier"]) < order.index(fa["tier"]):
                    fa, fb = fb, fa
                    sa, ea, sb, eb = sb, eb, sa, ea
                pairs.append({
                    "a": fa, "b": fb,
                    "file": _file,
                    "loc_a": (sa, ea), "loc_b": (sb, eb),
                    "dstart": dstart, "dend": dend,
                    "same_tier": same_tier,
                    "signal": signal, "detail": detail,
                })

    # Deterministic ordering: location-signal pairs first (tightest match
    # first), then title/anchor pairs, then report ID — keeps the strongest,
    # most mechanically-certain hints at the top of the bounded live set.
    _signal_rank = {"location": 0, "title": 1, "anchor": 2}
    pairs.sort(key=lambda p: (
        _signal_rank.get(p["signal"], 9),
        p["dstart"] + p["dend"],
        p["a"]["report_id"], p["b"]["report_id"],
    ))

    n_total = len(pairs)
    truncated = n_total > _REPORT_DEDUP_CANDIDATE_CAP
    live = pairs[:_REPORT_DEDUP_CANDIDATE_CAP]

    out = ["# Report Dedup Candidate Pairs", ""]
    if not live:
        out.append(
            "No same-tier or cross-tier candidate pairs found. The "
            "report_dedup_agent still runs its own semantic pass."
        )
        (scratchpad / "report_dedup_candidate_pairs.md").write_text(
            "\n".join(out) + "\n", encoding="utf-8",
        )
        return 0

    out.append(
        f"{len(live)} candidate pair(s): findings on the SAME file that either "
        f"(a) have a FIRST Location range matching within ±{tol} lines on both "
        "endpoints (any tier pairing), or (b) are SAME-TIER with overlapping "
        f"title wording (title overlap >= {title_thresh:.2f}) or a shared "
        "specific identifier (e.g. a function/struct name) in the title."
    )
    out.append("")
    out.append(
        "**CANDIDATE HINTS ONLY.** This list does NOT merge anything. Apply the "
        "consolidation test (same root cause + same fix + describable together) "
        "to BOTH full finding bodies before proposing a MERGE — a matching "
        "location, similar title, or shared identifier is a coincidence signal, "
        "not proof. Two DISTINCT bugs that happen to trip a signal (e.g. two "
        "different bugs in one function, or two findings that merely name the "
        "same function) MUST be kept separate. When in doubt, KEEP SEPARATE."
    )
    if truncated:
        out.append("")
        out.append(
            f"NOTE: {n_total} candidate pair(s) found; showing the strongest "
            f"{_REPORT_DEDUP_CANDIDATE_CAP}. Remaining pairs are deferred (not "
            "discarded) — the agent may still merge them on its own semantic pass."
        )
    out.append("")
    out.append(
        "| Survivor (higher sev) | Absorbed candidate | Tier | File | Loc A | Loc B | Signal |"
    )
    out.append(
        "|-----------------------|--------------------|------|------|-------|-------|--------|"
    )
    for p in live:
        a, b = p["a"], p["b"]
        la, ea = p["loc_a"]
        lb, eb = p["loc_b"]
        tier_label = "same-tier" if p["same_tier"] else "cross-tier"
        out.append(
            f"| {a['report_id']}: {a['title'][:44]} "
            f"| {b['report_id']}: {b['title'][:44]} "
            f"| {tier_label} | {p['file']} | L{la}-{ea} | L{lb}-{eb} "
            f"| {p['signal']} ({p['detail']}) |"
        )
    out.append("")
    (scratchpad / "report_dedup_candidate_pairs.md").write_text(
        "\n".join(out) + "\n", encoding="utf-8",
    )
    return len(live)


def _compute_dedup_candidate_blocks(scratchpad: Path) -> int:
    """Compute size-bounded in-context CLUSTERING blocks for the dedup judge.

    Replaces O(n^2) pair enumeration as the LIVE dedup LLM input. Builds an
    undirected SIGNAL GRAPH over findings (the SAME five signals as the pair
    builder, with the SAME aggregate-suppression), takes connected components as
    raw clusters (singletons excluded), size-normalizes each cluster into the
    [_DEDUP_BLOCK_MIN.._DEDUP_BLOCK_MAX] range, and writes ``dedup_blocks.md``.
    Per block the model returns line-oriented merge GROUPS in ONE call, so output
    scales with n (a few KB for any n); cross-block transitivity is recovered
    deterministically by union-find in ``apply_llm_dedup_decisions``.

    COMPAT SHIM (spec 2c): this also calls ``_compute_dedup_candidate_pairs`` so
    the legacy ``dedup_candidate_pairs.md`` / ``_full.md`` files are still written
    — the mechanical fallback (``_apply_mechanical_dedup_from_pairs``) and the
    supplemental path keep working UNCHANGED on those files.

    Halt-safety: the body is wrapped in try/except; on ANY exception the empty
    ``dedup_blocks.md`` is written and 0 is returned (NEVER raises). The phase
    degrades to passthrough / the mechanical fallback.

    Returns the total finding count placed into blocks (int).
    """
    scratchpad = Path(scratchpad)
    blocks_path = scratchpad / "dedup_blocks.md"

    def _write_empty(reason: str = "") -> None:
        try:
            blocks_path.write_text(
                "# Dedup Candidate Blocks\n\n"
                "No candidate duplicate blocks found.\n",
                encoding="utf-8",
            )
            (scratchpad / "dedup_block_count.txt").write_text(
                "0\n", encoding="utf-8"
            )
        except Exception:
            pass

    # ── COMPAT SHIM: always (re)write the legacy pair files first so the
    #    mechanical fallback + supplemental path keep working unchanged. This
    #    is best-effort; a failure here must not block the block computation. ──
    try:
        _compute_dedup_candidate_pairs(scratchpad)
    except Exception:
        pass

    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        _write_empty("no inventory")
        return 0

    try:
        inv_text = _llm_norm(inv.read_text(encoding="utf-8", errors="replace"))
        if inv_text and not inv_text.endswith("\n"):
            inv_text += "\n"

        findings = _dedup_extract_findings(inv_text)
        n_findings = len(findings)
        if n_findings < 2:
            _write_empty("fewer than 2 findings")
            return 0

        # ── Build the undirected signal graph (adjacency by finding index) ──
        # Edges fire on the SAME predicate logic as the pair builder. Each edge
        # carries a "signal token" used to pick the block key.
        adj: dict[int, set[int]] = {i: set() for i in range(n_findings)}
        # signal_tokens[(i,j)] -> list of human tokens, for [key:] selection.
        edge_tokens: dict[tuple[int, int], list[str]] = {}

        def _add_edge(i: int, j: int, token: str) -> None:
            adj[i].add(j)
            adj[j].add(i)
            key = (i, j) if i < j else (j, i)
            edge_tokens.setdefault(key, []).append(token)

        # Group by file for the same-file signals.
        file_groups: dict[str, list[int]] = {}
        for idx, f in enumerate(findings):
            if f["file"] and f["file"] != "unknown":
                file_groups.setdefault(f["file"], []).append(idx)

        # Same-file signals: location overlap, title overlap / anchor, func match.
        for file_part, indices in file_groups.items():
            for ii, idx_a in enumerate(indices):
                for idx_b in indices[ii + 1:]:
                    fa, fb = findings[idx_a], findings[idx_b]
                    lr_a, lr_b = fa["_lines"], fb["_lines"]
                    if lr_a and lr_b and _line_ranges_overlap(lr_a, lr_b):
                        _add_edge(idx_a, idx_b, f"file:{file_part}")
                    score = _titles_overlap_score(fa["title"], fb["title"])
                    anchors = _shared_anchor_tokens(fa["title"], fb["title"])
                    if score >= 0.50:
                        _add_edge(
                            idx_a, idx_b,
                            f"title:{_norm_key(fa['title'])[:24]}",
                        )
                    elif anchors:
                        _add_edge(
                            idx_a, idx_b,
                            f"title:{sorted(anchors)[0]}",
                        )
                    if fa["_func"] and fb["_func"] and fa["_func"] == fb["_func"]:
                        _add_edge(idx_a, idx_b, f"func:{fa['_func']}")

        # Cross-file signals: source-ID subset, PERT lineage — WITH the SAME
        # aggregate-suppression as the pair builder.
        _PERT_RE = re.compile(r"^PERT-\d+$", re.IGNORECASE)
        for i in range(n_findings):
            for j in range(i + 1, n_findings):
                fa, fb = findings[i], findings[j]
                sa, sb = fa["_source_ids"], fb["_source_ids"]
                aggregate_suppressed = (
                    len(sa) > _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD
                    or len(sb) > _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD
                )
                if aggregate_suppressed:
                    continue
                # Source-ID strict subset (either direction).
                if sa and sb and (sa < sb or sb < sa):
                    sub, sup = (sa, sb) if sa < sb else (sb, sa)
                    _add_edge(
                        i, j,
                        f"src:{sorted(sup)[0]}" if sup else "src",
                    )
                # PERT lineage: shared depth source IDs + a PERT-* token.
                pert_a = any(_PERT_RE.match(s) for s in sa) if sa else False
                pert_b = any(_PERT_RE.match(s) for s in sb) if sb else False
                if (pert_a or pert_b) and (sa & sb):
                    _add_edge(i, j, "src:PERT")

        # ── Connected components (BFS) → raw clusters; singletons excluded. ──
        visited: set[int] = set()
        clusters: list[list[int]] = []
        for start in range(n_findings):
            if start in visited or not adj[start]:
                continue
            comp: list[int] = []
            stack = [start]
            visited.add(start)
            while stack:
                node = stack.pop()
                comp.append(node)
                for nb in adj[node]:
                    if nb not in visited:
                        visited.add(nb)
                        stack.append(nb)
            if len(comp) >= 2:
                clusters.append(comp)

        singletons = n_findings - sum(len(c) for c in clusters)

        if not clusters:
            # No finding shares a signal with another. Empty block file but
            # record the singleton count for traceability.
            try:
                blocks_path.write_text(
                    "# Dedup Candidate Blocks\n\n"
                    "No candidate duplicate blocks found.\n\n"
                    f"## Singletons\nSingletons: {singletons}\n",
                    encoding="utf-8",
                )
                (scratchpad / "dedup_block_count.txt").write_text(
                    "0\n", encoding="utf-8"
                )
            except Exception:
                pass
            return 0

        block_max = _dedup_block_max()

        def _cluster_key(member_idxs: list[int]) -> str:
            """Most-common signal token across the cluster's internal edges."""
            counts: dict[str, int] = {}
            mset = set(member_idxs)
            for (a, b), toks in edge_tokens.items():
                if a in mset and b in mset:
                    for t in toks:
                        counts[t] = counts.get(t, 0) + 1
            if counts:
                # Deterministic: highest count, then lexicographic token.
                return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
            # Fallback: file of the lowest-ID member.
            lead = min(
                member_idxs,
                key=lambda x: _id_num(findings[x]["id"]),
            )
            return f"cluster:{findings[lead]['id']}"

        # ── Size-normalize each cluster into [_DEDUP_BLOCK_MIN..block_max]. ──
        # > block_max: split into ceil(size/block_max) near-equal sub-blocks,
        #   each carrying the SAME [key:] so union-find links cross-sub-block
        #   duplicates. Split is deterministic: sort members by numeric ID,
        #   chunk in order. < MIN: keep as-is (do NOT pad).
        emitted_blocks: list[tuple[str, list[int]]] = []
        for comp in clusters:
            key = _cluster_key(comp)
            ordered = sorted(comp, key=lambda x: _id_num(findings[x]["id"]))
            size = len(ordered)
            if size <= block_max:
                emitted_blocks.append((key, ordered))
                continue
            n_sub = (size + block_max - 1) // block_max  # ceil
            # Near-equal chunk sizes.
            base = size // n_sub
            rem = size % n_sub
            pos = 0
            for s in range(n_sub):
                take = base + (1 if s < rem else 0)
                emitted_blocks.append((key, ordered[pos:pos + take]))
                pos += take

        # ── Write dedup_blocks.md ──
        placed = sum(len(idxs) for _k, idxs in emitted_blocks)
        out: list[str] = ["# Dedup Candidate Blocks", ""]
        out.append(
            f"{placed} finding(s) grouped into {len(emitted_blocks)} block(s) "
            "for in-context clustering review."
        )
        out.append(
            "Each block lists findings that MAY contain duplicates. Return merge "
            "GROUPS per block. IDs only. See output contract."
        )
        out.append("")
        for bn, (key, idxs) in enumerate(emitted_blocks, start=1):
            out.append(f"## Block {bn}  [key: {key}]")
            out.append("| ID | Title | Location | Root Cause | Severity |")
            out.append("|----|-------|----------|------------|----------|")
            for idx in idxs:
                f = findings[idx]
                out.append(
                    "| "
                    + _dedup_block_cell(f["id"], 0)
                    + " | "
                    + _dedup_block_cell(f["title"], 80)
                    + " | "
                    + _dedup_block_cell(f["location"], 0)
                    + " | "
                    + _dedup_block_cell(_dedup_root_cause_for(f), 100)
                    + " | "
                    + _dedup_block_cell(f["severity"], 0)
                    + " |"
                )
            out.append("")
        out.append("## Singletons")
        out.append(f"Singletons: {singletons}")
        out.append("")
        blocks_path.write_text("\n".join(out), encoding="utf-8")

        # Block-count marker (deterministic signal for the driver), analogous to
        # dedup_round_count.txt.
        try:
            (scratchpad / "dedup_block_count.txt").write_text(
                f"{len(emitted_blocks)}\n", encoding="utf-8"
            )
        except Exception:
            pass

        # Focus inventory for the IDs placed in blocks (bounded bodies; reuses
        # the same body model so both sides of any candidate can be coupled).
        try:
            _write_block_focus_inventory(
                scratchpad / "dedup_focus_inventory.md",
                findings,
                {findings[i]["id"] for _k, idxs in emitted_blocks for i in idxs},
            )
        except Exception:
            pass

        return placed
    except Exception:
        _write_empty("exception")
        return 0


def _id_num(fid: str) -> int:
    """Numeric component of a finding ID (e.g. 'INV-7' -> 7). 0 on parse fail."""
    m = re.search(r"\d+", fid or "")
    return int(m.group(0)) if m else 0


def _dedup_block_cell(value: str, truncate: int) -> str:
    """Render a single dedup_blocks.md table cell.

    Pipes inside the value are replaced with ``/`` (so the cell never breaks the
    markdown table), newlines collapsed to spaces, and the result truncated to
    ``truncate`` chars when ``truncate > 0``.
    """
    s = re.sub(r"\s+", " ", str(value or "")).replace("|", "/").strip()
    if truncate and len(s) > truncate:
        s = s[:truncate]
    return s


def _dedup_root_cause_for(f: dict) -> str:
    """Best-effort Root Cause text for a block cell.

    Uses the finding's parsed Root Cause / Description first sentence from its
    body block; empty allowed (the spec permits an empty Root Cause cell).
    """
    body = str(f.get("_block", ""))
    rc, _ = _field_anywhere(body, ("Root Cause", "Description"), table_ok=True)
    rc = rc.strip()
    if not rc:
        return ""
    # First sentence (up to the first period followed by space/end), then the
    # caller truncates to 100 chars.
    m = re.match(r"(.+?\.)(?:\s|$)", rc)
    if m:
        rc = m.group(1)
    return rc


def _write_block_focus_inventory(
    path: Path, findings: list[dict], focus_ids: set[str]
) -> None:
    """Write the bounded focus inventory for the IDs placed into blocks.

    Mirrors the pair builder's ``_write_focus_inventory`` contract so the dedup
    prompt can read full finding bodies (distinct Location / Source IDs / attack
    path / impact) for every block member before deciding a merge.
    """
    if not focus_ids:
        return
    focus_lines = [
        "# Dedup Focus Inventory",
        "",
        "This bounded file contains the full finding bodies for the IDs "
        "referenced by `dedup_blocks.md`. Use it for semantic review before "
        "falling back to the full inventory. The full bodies carry each "
        "finding's distinct Location(s), Source IDs, attack path, and impact so "
        "every member of a candidate block can be coupled on MERGE.",
        "",
    ]
    for f in findings:
        if f["id"] in focus_ids:
            focus_lines.append(str(f.get("_block", "")).rstrip())
            focus_lines.append("")
    path.write_text("\n".join(focus_lines).rstrip() + "\n", encoding="utf-8")


_DEPTH_PROMOTION_FILES = (
    "depth_consensus_invariant_findings.md",
    "depth_state_trace_findings.md",
    "depth_edge_case_findings.md",
    "depth_external_findings.md",
    # v2.8.9: depth_token_flow is a CORE SC depth channel (DT-* ids) but was
    # absent from this list (the list was authored L1-first, where token-flow
    # does not load), so DT-* depth-only findings were never read by the
    # promotion bridge and silently dropped. Added for SC parity.
    "depth_token_flow_findings.md",
    "depth_network_surface_findings.md",
    "depth_iter2_*_findings.md",
    "depth_iter3_*_findings.md",
    "depth_da_*_findings.md",
    "design_stress_findings.md",
    "perturbation_findings.md",
    "attention_repair_findings.md",
    # SC subproducer/feeders. These are written by nested scanner, niche,
    # rescan, per-contract, fuzz, and validation agents; they must receive the
    # same feeder->inventory parity treatment as L1 depth outputs.
    "analysis_rescan_*.md",
    "analysis_percontract_*.md",
    "blind_spot_*_findings.md",
    "scanner_*_findings.md",
    "niche_*_findings.md",
    "validation_sweep_findings.md",
    "scanner_validation_findings.md",
    "sibling_propagation_findings.md",
    "medusa_fuzz_findings.md",
    "trident_fuzz_findings.md",
    "cargo_fuzz_findings.md",
)


_PROMOTABLE_FEEDER_ID_PATTERN = (
    r"(?:"
    # L1/depth/feeders
    r"DCI-\d+|DEC-\d+|DST-\d+|DX-\d+|DN-\d+|"
    r"DNS-\d+|DA-[A-Z0-9_-]+-\d+|DA\d+-[A-Z0-9_-]+-\d+|"
    r"PERT-\d+|ATT-\d+|"
    # SC depth/scanner channels that actually emit DS-/DE-/DT-/BLIND- ids
    # (v2.8.9: these prefixes were ABSENT, so the depth-promotion bridge and its
    # receipt gate parsed 0 findings from depth_state_trace / depth_edge_case /
    # depth_token_flow / blind_spot_* and silently dropped depth-only findings —
    # incl. a CONFIRMED High on a prior run. DST-=design_stress and DEC-/DX- are
    # distinct; DS-/DE-/DT- require a digit so they cannot match inside DST-/DEC-/DX-N.)
    r"DS-\d+|DE-\d+|DT-\d+|BLIND-[A-Z]?-?\d+|"
    # SC scanner/fuzz/tool outputs
    r"SLITHER-\d+|FUZZ-\d+|MEDUSA-\d+|RSW-\d+|SP-\d+|"
    # SC niche/injectable skill prefixes. Deliberately excludes public report
    # IDs C/H/M/L/I-N so client-facing report IDs are not treated as internal
    # feeder IDs by leak/promotion gates.
    r"(?:AA|AB|AC|AL|AR|AV|BLS|BS|CBS|CCT|CFG|CI|CM|CMI|CPI|CR|CS|CT|CU|"
    r"DEP|DEX|ED|EDA|EIP|EN|EP|EPA|EVT|EX|FA|FC|FL|GO|GOV|HF|IHR|II|LC|"
    r"LEND|MG|MP|MSS|NFT|NS|OD|OF|OO|OR|P2P|PDA|PSC|PTB|PV|RE|REENT|REF|"
    r"RPC|RS|SA|SAF|SCOUT|SE|SGI|SHIFT|SIG|SL|SLS|SR|SS|SSC|ST|STATIC|STR|"
    r"T22|TF|TPS|TS|TXI|VA|VL|VS|WED|XE|XFER|ZS)-\d+"
    r")"
)


def _parse_depth_confidence_scores(scratchpad: Path) -> dict[str, float]:
    scores: dict[str, float] = {}
    for p in sorted(scratchpad.glob("confidence_scores*.md")):
        try:
            text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        table_id_idx: int | None = None
        table_composite_idx: int | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("|") and stripped.endswith("|"):
                cells = [c.strip() for c in stripped.strip("|").split("|")]
                if cells and all(set(c) <= {"-", ":"} for c in cells):
                    continue
                norm_headers = [
                    re.sub(r"[^a-z0-9]+", "", c.lower()) for c in cells
                ]
                if "findingid" in norm_headers and "composite" in norm_headers:
                    table_id_idx = norm_headers.index("findingid")
                    table_composite_idx = norm_headers.index("composite")
                    continue
                if (
                    table_id_idx is not None
                    and table_composite_idx is not None
                    and len(cells) > max(table_id_idx, table_composite_idx)
                ):
                    ids = re.findall(
                        r"\b" + _PROMOTABLE_FEEDER_ID_PATTERN + r"\b",
                        cells[table_id_idx],
                    )
                    m = re.search(
                        r"(?<![A-Za-z0-9.\-])(?:0?\.\d+|1\.0+)(?![A-Za-z0-9.])",
                        cells[table_composite_idx],
                    )
                    if ids and m:
                        score = float(m.group(0))
                        for fid in ids:
                            scores[fid] = max(scores.get(fid, 0.0), score)
                        continue
            elif stripped:
                table_id_idx = None
                table_composite_idx = None
            ids = re.findall(r"\b" + _PROMOTABLE_FEEDER_ID_PATTERN + r"\b", line)
            if not ids:
                continue
            # Closes F-PROM-02: require a decimal point so the trailing `1`
            # in `DCI-1` is not parsed as confidence=1.0. A confidence column
            # always uses dotted form (0.85, 1.0). Bare integers are
            # ambiguous with finding-ID suffixes.
            nums = [
                float(x)
                for x in re.findall(
                    r"(?<![A-Za-z0-9.\-])(?:0?\.\d+|1\.0+)(?![A-Za-z0-9.])",
                    line,
                )
            ]
            if nums:
                score = max(nums)
                for fid in ids:
                    scores[fid] = max(scores.get(fid, 0.0), score)
    return scores


def _parse_depth_finding_blocks(path: Path) -> list[dict[str, str]]:
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    lines = text.splitlines()
    starts = []
    heading_re = re.compile(
        r"^\s*#{2,4}\s+(?:Finding\s*)?\[?"
        r"(" + _PROMOTABLE_FEEDER_ID_PATTERN + r")\]?",
        re.IGNORECASE,
    )
    for i, line in enumerate(lines):
        if heading_re.search(line):
            starts.append(i)
    out: list[dict[str, str]] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        block = "\n".join(lines[start:end]).strip()
        m = heading_re.search(lines[start])
        if not m:
            continue
        fid = m.group(1).upper()
        title = re.sub(r"^\s*#{2,4}\s+", "", lines[start]).strip()
        title = re.sub(r"^(?:Finding\s*)?\[?" + re.escape(fid) + r"\]?\s*:?\s*", "", title, flags=re.I).strip()
        title = title or fid
        sev = _field_from_markdown(block, ("Severity", "Final Severity")) or "Medium"
        loc = _field_from_markdown(block, ("Location", "Locations"))
        if not loc:
            lm = re.search(
                r"\b([A-Za-z0-9_./\\-]+\.(?:rs|go|sol|move|py|c|cpp|cc|h|hpp|java|ts|js):L?\d+)\b",
                block,
            )
            loc = lm.group(1) if lm else "unknown"
        tag = _field_from_markdown(
            block, ("Preferred Tag", "Evidence Tag", "Evidence Tags", "Evidence")
        )
        verdict = _field_from_markdown(block, ("Verdict", "Final Verdict", "Status"))
        sev_clean = _strip_md(sev)
        verdict_clean = _strip_md(verdict)
        if _non_reportable_marker(sev_clean) or _non_reportable_marker(verdict_clean):
            sev_clean = "Informational"
            if not verdict_clean:
                verdict_clean = "REFUTED"
        elif _ambiguous_na_marker(sev_clean):
            sev_clean = "Informational"
            if not verdict_clean:
                verdict_clean = "UNRESOLVED"
        desc = _field_from_markdown(block, ("Description", "Root Cause", "Impact"))
        if not desc:
            body_lines = [
                x.strip() for x in block.splitlines()[1:]
                if x.strip() and not x.strip().startswith("|")
            ]
            desc = " ".join(body_lines[:3])[:600] if body_lines else "Depth finding promoted for verification."
        # Extract referenced depth IDs from the block body (excluding self).
        # PERT findings reference their parent (e.g. DCI-3), DA iter2 may
        # reference iter1 IDs.  These become additional Source IDs on promotion
        # so dedup's source-ID-subset / PERT-lineage signals fire correctly.
        _ref_ids = set(
            re.findall(r"\b" + _PROMOTABLE_FEEDER_ID_PATTERN + r"\b", block)
        )
        _ref_ids.discard(fid)
        out.append({
            "id": fid,
            "title": _strip_md(title),
            "severity": sev_clean.capitalize(),
            "location": _norm_loc(loc),
            "preferred_tag": _extract_first_tag(tag) or _strip_md(tag) or "CODE-TRACE",
            "verdict": verdict_clean,
            "description": _strip_md(desc),
            "source_file": path.name,
            "_referenced_ids": sorted(_ref_ids),
            **_extract_optional_finding_metadata(block),
        })

    # ------------------------------------------------------------------
    # F2 (v2.8.x): strictly-additive Chain-Summary table-row fallback.
    #
    # Depth/scanner artifacts sometimes list a finding ONLY as a row in a
    # Chain-Summary / catalog table (e.g. `| DE-1 | file:Lnn | mechanism |
    # verdict | severity |`) and never give it an `## [DE-1]` heading. The
    # heading-only harvest above cannot see those rows, so the finding is lost
    # before inventory. Recover such rows, but ONLY when the ID has ZERO
    # heading coverage anywhere in this file (zero-coverage-only). That makes
    # this a pure recall add: it can never alter a currently-working heading
    # parse, and the row-only candidate is emitted LOW-CONFIDENCE so downstream
    # dedup / promotion consume it exactly like a heading-parsed dict.
    #
    # Detection is header-NAME based (never positional): a table qualifies only
    # when its header row carries at least one location / severity / verdict
    # column, which distinguishes a finding catalog from a step-execution or
    # rules-applied table.
    # ------------------------------------------------------------------
    heading_ids = {d["id"] for d in out}
    row_id_re = re.compile(
        r"^\s*[\*`_ ]*\[?(" + _PROMOTABLE_FEEDER_ID_PATTERN + r")\]?[\*`_ ]*$",
        re.IGNORECASE,
    )

    def _norm_header(cell: str) -> str:
        return re.sub(r"[^a-z0-9]+", "", cell.lower())

    def _sep_row(cells: list[str]) -> bool:
        return bool(cells) and all(c and set(c) <= {"-", ":"} for c in cells)

    seen_row_ids: set[str] = set()
    n = len(lines)
    i = 0
    while i < n - 1:
        header_line = lines[i].strip()
        sep_line = lines[i + 1].strip()
        if not (header_line.startswith("|") and sep_line.startswith("|")):
            i += 1
            continue
        sep_cells = [c.strip() for c in sep_line.strip("|").split("|")]
        if not _sep_row(sep_cells):
            i += 1
            continue
        headers = [c.strip() for c in header_line.strip("|").split("|")]
        norm = [_norm_header(h) for h in headers]

        def _find(*keys: str) -> int | None:
            for idx_h, h in enumerate(norm):
                if any(k in h for k in keys):
                    return idx_h
            return None

        loc_idx = _find("location", "file")
        sev_idx = _find("severity")
        # "status" is accepted for VALUE mapping (some catalogs use it as a
        # verdict synonym) but NOT for qualification: a step-execution ledger
        # commonly has a "Status" column yet is not a finding catalog. Only a
        # proper location / severity / "verdict" column qualifies a table.
        verd_idx = _find("verdict", "status")
        qual_verd_idx = _find("verdict")
        desc_idx = _find(
            "mechanism", "description", "desc", "rootcause", "summary",
            "issue", "impact", "title",
        )
        # Only a Chain-Summary-style finding catalog qualifies.
        if loc_idx is None and sev_idx is None and qual_verd_idx is None:
            i += 1
            continue

        j = i + 2
        while j < n:
            row = lines[j].strip()
            if not row.startswith("|"):
                break
            cells = [c.strip() for c in row.strip("|").split("|")]
            if _sep_row(cells) or not any(cells):
                j += 1
                continue
            m_id = row_id_re.match(cells[0]) if cells else None
            if m_id:
                rid = m_id.group(1).upper()
                if rid not in heading_ids and rid not in seen_row_ids:
                    seen_row_ids.add(rid)

                    def _cell(idx: int | None) -> str:
                        if idx is not None and 0 <= idx < len(cells):
                            return cells[idx].strip()
                        return ""

                    r_loc = _cell(loc_idx)
                    r_sev = _cell(sev_idx) or "Medium"
                    r_verd = _cell(verd_idx)
                    r_desc = _cell(desc_idx)
                    r_sev_clean = _strip_md(r_sev)
                    r_verd_clean = _strip_md(r_verd)
                    if _non_reportable_marker(r_sev_clean) or _non_reportable_marker(r_verd_clean):
                        r_sev_clean = "Informational"
                        if not r_verd_clean:
                            r_verd_clean = "REFUTED"
                    elif _ambiguous_na_marker(r_sev_clean):
                        r_sev_clean = "Informational"
                        if not r_verd_clean:
                            r_verd_clean = "UNRESOLVED"
                    r_title = _strip_md(r_desc) or rid
                    if not r_loc:
                        lm = re.search(
                            r"\b([A-Za-z0-9_./\\-]+\.(?:rs|go|sol|move|py|c|cpp|cc|h|hpp|java|ts|js):L?\d+)\b",
                            row,
                        )
                        r_loc = lm.group(1) if lm else "unknown"
                    r_ref_ids = set(
                        re.findall(r"\b" + _PROMOTABLE_FEEDER_ID_PATTERN + r"\b", row)
                    )
                    r_ref_ids.discard(rid)
                    out.append({
                        "id": rid,
                        "title": r_title[:200] or rid,
                        "severity": r_sev_clean.capitalize(),
                        "location": _norm_loc(r_loc),
                        # Row-only candidate: no execution/analysis section
                        # exists, so it is deliberately LOW-CONFIDENCE.
                        "preferred_tag": "CODE-TRACE",
                        "verdict": r_verd_clean,
                        "description": _strip_md(r_desc) or "Chain-Summary table-row finding recovered for verification.",
                        "source_file": path.name,
                        "_referenced_ids": sorted(r_ref_ids),
                        "_low_confidence_rowonly": "true",
                    })
            j += 1
        i = j if j > i + 1 else i + 1
    return out


# --- v2.3.0 SCIP experiment: coverage gap + path-existence gates -----------
#
# Two driver-side gates exercising the existing SCIP prebake artifacts to
# address two of the three RC buckets identified in the v2.2.2 post-mortem:
#
#   Bucket A — subsystem coverage gaps (~20 misses on a prior L1 run):
#     Recon-flagged in-scope source files received zero depth-agent
#     citations. Driver enumerates source files via the SCIP repo_map,
#     diffs against citation set, surfaces uncited Medium+ files for iter2.
#
#   Bucket C — path hallucination (~3 GT-finding losses on same run):
#     Verify pool had 30% locations corrected (path mismatches) per
#     cross_batch_consistency. Some real bugs killed as FP because the
#     cited path didn't exist. Driver pre-checks every cited path against
#     the SCIP-indexed file set before verify spawns.
#
# Generic across L1 and SC. No protocol-specific knowledge. Reads only
# already-existing prebake artifacts (scip/repo_map.md / repo_map_full.md)
# plus the depth/breadth/scanner finding outputs.
#
# Validation strategy: SOFT in this v2.3.0 round — gates write directive
# files but only emit informational issues (no hard fail). Next post-
# mortem measures whether the directives close any of the residual gap.
# If yes, hard-gate them in v2.3.1.
_SCIP_REPO_MAP_FILES = ("repo_map.md", "repo_map_full.md")


_FINDING_GLOBS_FOR_CITATION = (
    "analysis_*.md",
    "analysis_rescan_*.md",
    "analysis_percontract_*.md",
    "coverage_fill_*.md",
    "panic_audit_*.md",
    "panic_audit_summary.md",
    "symmetric_pair_findings.md",
    "field_validation_matrix.md",
    "primitive_correctness_findings.md",
    "network_amplification_findings.md",
    "lifecycle_replay_findings.md",
    "attention_repair*.md",
    "attention_repair_rows_*.md",
    "findings_inventory*.md",
    "depth_*_findings.md",
    "depth_iter2_*_findings.md",
    "depth_iter3_*_findings.md",
    "depth_da_*_findings.md",
    "attention_repair*.md",
    "attention_repair_rows_*.md",
    "breadth_*_findings.md",
    "blind_spot_*_findings.md",
    "scanner_*_findings.md",
    "niche_*_findings.md",
    "validation_sweep_findings.md",
    "scanner_validation_findings.md",
    "design_stress_findings.md",
    "perturbation_findings.md",
    "verify_*.md",
)


def _extract_gap_paths_from_markdown(text: str) -> list[str]:
    path_re = re.compile(
        r"\b([A-Za-z0-9_./\\-]+\.(?:rs|go|sol|move|py|c|cpp|cc|h|hpp|java|ts|js))\b"
    )
    out: list[str] = []
    seen: set[str] = set()
    for m in path_re.finditer(text):
        p = m.group(1).replace("\\", "/").strip("`")
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


# --- v2.2.0 A.1: skill-step execution trace gate ---------------------------
#
# Failure mode (post-mortem RC-AGENT class, ~22 of 46 misses on a prior L1 run):
# depth agents inherit 6-12 skills and produce 7-15 findings, but the
# findings concentrate on 2-3 skills per agent. Other inherited skills get
# zero attention and entire numbered sections (e.g. RPC_SURFACE_AUDIT §1-6,
# GOSSIP_CACHE_INVARIANCE §1-6) are never executed. The existing
# `skill_execution_gaps.md` is LLM-judged AFTER the fact and unreliable.
#
# A.1 makes execution mechanically traceable:
#   1. Each Thorough depth agent writes `step_execution_trace_{agent}.md`
#      with one pipe-row per (skill, step) it inherited:
#        | Skill | Step | Executed | Evidence | Result |
#      Allowed Executed values: yes / partial / no
#      Evidence MUST be a `file:line` token (or `-` for skip with reason).
#   2. The driver aggregates all traces into
#      `step_execution_gaps_mechanical.md` listing every (skill, step)
#      with Executed != yes — this is the iter2 directive.
#   3. The existing LLM-driven `phase4b-skill-checklist.md` agent now
#      reads the mechanical aggregate first and only synthesizes for
#      what the trace doesn't already cover.
#
# Generic across L1 and SC. The skill section structure (`## N. Title` +
# `Tag: \`[TAG-NAME]\``) is already present in 162 sections / 140 tags
# across L1 skills — no skill rewrites needed. SC skills follow the same
# convention; the gate works there too once SC depth-loop adopts the
# §STEP-TRACE directive.
_STEP_TRACE_GLOB = "step_execution_trace_*.md"


def _parse_step_trace_rows(text: str) -> list[dict[str, str]]:
    """Parse a step-execution-trace markdown file into row dicts.

    Tolerates header variations and case. Recognized columns (in any
    order, identified by header text): Skill, Step, Executed, Evidence,
    Result. Returns rows that contain at least Skill + Step + Executed.
    """
    rows: list[dict[str, str]] = []
    lines = text.splitlines()
    headers: list[str] = []
    for raw in lines:
        s = raw.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells:
            continue
        # Skip pure-separator rows (---|---|---).
        if all(re.fullmatch(r":?-+:?", c) for c in cells if c):
            continue
        if not headers:
            # First non-separator pipe row defines the header set.
            lc = [c.lower() for c in cells]
            if any("skill" in c for c in lc) and any("step" in c for c in lc):
                headers = lc
                continue
            # If no recognizable header yet, ignore the row.
            continue
        row = {}
        for i, cell in enumerate(cells):
            if i < len(headers):
                for known in ("skill", "step", "executed", "evidence", "result"):
                    if known in headers[i]:
                        row[known] = cell
                        break
        if "skill" in row and "step" in row and "executed" in row:
            rows.append(row)
    return rows


def _aggregate_step_execution_gaps(
    scratchpad: Path,
) -> tuple[list[dict[str, str]], list[str]]:
    """Aggregate all step_execution_trace_*.md files into a gap list.

    Returns:
        (gaps, agent_names_with_traces)
        gaps: list of {agent, skill, step, executed, evidence, result}
              dicts where executed != "yes". Includes "no", "partial",
              and any other non-yes value.
        agent_names_with_traces: file-name-derived agent identifiers
              (so the caller can detect missing traces).
    """
    gaps: list[dict[str, str]] = []
    agents: list[str] = []
    for f in sorted(scratchpad.glob(_STEP_TRACE_GLOB)):
        agent = f.name.replace("step_execution_trace_", "").replace(
            ".md", ""
        )
        agents.append(agent)
        try:
            text = _llm_norm(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for row in _parse_step_trace_rows(text):
            if row.get("executed", "").lower() != "yes":
                gaps.append({
                    "agent": agent,
                    "skill": row.get("skill", ""),
                    "step": row.get("step", ""),
                    "executed": row.get("executed", ""),
                    "evidence": row.get("evidence", ""),
                    "result": row.get("result", ""),
                })
    return gaps, agents


def _expected_depth_agent_roles(scratchpad: Path) -> list[str]:
    """Infer which depth agents the run actually used from finding files.

    Strategy: list every `depth_{role}_findings.md` (NOT iter2/iter3/da
    variants) and return the role names. Avoids re-parsing
    template_recommendations.md or hardcoding role lists — generic.

    Exclusion: gap-fill remediation agents (`depth_coverage_*_findings.md`)
    are spawned by the orchestrator in response to the v2.3.0 NOTREAD
    priority coverage gate — they cite uncovered files mechanically rather
    than execute skill methodology, so the §STEP-TRACE directive does not
    apply to them. Including them in the expected-role list creates a
    gate-vs-gate collision (NOTREAD forces them into existence; step-trace
    then punishes them for not having a trace). They are still subject to
    their own telemetry gate (≥2 pre-baked SCIP reads per agent).
    """
    roles: list[str] = []
    for f in sorted(scratchpad.glob("depth_*_findings.md")):
        name = f.name
        # Exclude iteration / Devil's-Advocate variants. Both the abbreviated
        # (`iter2`) and spelled-out (`iteration2`) tokens must be listed —
        # `iteration2` does NOT contain the substring `iter2`, so an
        # un-canonicalized `depth_edge_case_iteration2_findings.md` would
        # otherwise be mis-parsed as a phantom role `edge_case_iteration2`
        # (observed on a prior audit's graph-consumption warning).
        if any(
            tok in name for tok in (
                "iter2", "iter3", "iteration2", "iteration3",
                "_da_", "depth_da",
            )
        ):
            continue
        if name == "depth_findings.md":
            continue
        # depth_{role}_findings.md → role
        role = name[len("depth_"): -len("_findings.md")]
        if not role:
            continue
        # Non-methodology gap-fill agents (see docstring).
        if role.startswith("coverage_"):
            continue
        roles.append(role)
    return roles


# Ship A: single source of truth in plamen_types (was a divergent local copy).
_DEPTH_EVIDENCE_TAG_RE = DEPTH_EVIDENCE_TAG_RE


# --- v2.2.0 A.4: NOTREAD priority coverage gate ----------------------------
#
# Recon's `scope_leftover.md` lists every in-scope source file with one of:
#   READ     — opened and analyzed by recon
#   STUB     — subsystem noted, internals not read
#   NOTREAD  — not opened (these are depth-agent priorities by construction)
#
# Failure mode observed in a prior L1 run: 13 NOTREAD priority files, only ~7
# received any depth coverage. The other 6 silently went unaudited (a class of
# RC-SCOPE misses per post-mortem). v2.2.0 fix: after iter1 depth, identify
# any NOTREAD file with zero citations across all depth/breadth/scanner
# finding outputs and surface as a directive for the next phase to address.
# Generic across L1 and SC (recon writes the same schema for all targets).
_NOTREAD_FINDING_GLOBS = (
    "depth_*_findings.md",
    "depth_iter2_*_findings.md",
    "depth_iter3_*_findings.md",
    "depth_da_*_findings.md",
    "breadth_*_findings.md",
    "blind_spot_*_findings.md",
    "scanner_*_findings.md",
    "niche_*_findings.md",
    "validation_sweep_findings.md",
    "scanner_validation_findings.md",
)


_PATH_CELL_EXTENSIONS = (
    ".rs", ".go", ".sol", ".move", ".py", ".c", ".h", ".cpp", ".cc",
    ".java", ".ts", ".js",
)


_UNCOVERED_STATUS_TOKENS = {"NOTREAD", "NOT_READ", "UNREAD", "UNCOVERED", "MISSED"}


# Coverage status tokens that mean "this file IS covered" (Schema 1 dialect).
# When a row contains any of these, it is NOT uncovered regardless of empty
# Acknowledged column — prevents Schema-2 fallback from misclassifying
# Schema-1 READ/STUB rows.
_COVERED_STATUS_TOKENS = {"READ", "STUB", "CITED", "COVERED", "ANALYZED"}


def _is_path_cell(cell: str) -> str | None:
    """Return a normalized path if `cell` looks like a source file path."""
    stripped = cell.strip("`").strip()
    if not stripped or " " in stripped:
        return None
    stripped = stripped.replace("\\", "/")
    if "/" in stripped or stripped.endswith(_PATH_CELL_EXTENSIONS):
        return stripped
    return None


def _parse_notread_files(scope_leftover_text: str) -> list[str]:
    """Extract paths flagged uncovered by recon's scope_leftover.md.

    Tolerates schema variation observed in production:
      Schema 1 (L1 numbered):    | # | File | Coverage | Notes |   with NOTREAD cell
      Schema 2 (recon template): | File | LOC | Reason | Acknowledged |   no ack = uncovered
      Schema 3 (variants):       NOT_READ / UNREAD / UNCOVERED / MISSED in any cell

    v2.2.3 widening — pre-v2.2.3 only matched literal "NOTREAD" string.
    Live failure mode (a prior L1 run): the recon-prompt template schema
    (Schema 2) doesn't use NOTREAD at all; rows without ACKNOWLEDGED are
    the uncovered ones. Parser missed them entirely.

    Strategy:
      1. If row has any uncovered-status token → uncovered.
      2. ELSE if row matches Schema 2 (path-cell + LOC-cell + ack-cell where
         ack is empty/blank/`-`) → uncovered.
      3. ELSE skip.
    """
    files: list[str] = []
    for line in scope_leftover_text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        if _is_separator_row(s):
            continue
        upper = s.upper()
        # Skip the column-header row of either schema.
        if (
            ("FILE" in upper and "COVERAGE" in upper)
            or ("FILE" in upper and "ACKNOWLEDGED" in upper)
            or ("FILE" in upper and "REASON" in upper and "LOC" in upper)
        ):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 2:
            continue

        # Schema 1 / 3: explicit uncovered-status cell.
        if any(c.upper() in _UNCOVERED_STATUS_TOKENS for c in cells):
            for cell in cells:
                p = _is_path_cell(cell)
                if p:
                    files.append(p)
                    break
            continue

        # Schema 1 dialect short-circuit: if any cell is a covered-status
        # token (READ / STUB / CITED / COVERED / ANALYZED), the row is
        # explicitly covered — do NOT fall through to Schema 2's
        # empty-ack heuristic which would misclassify Schema 1 rows.
        if any(c.upper() in _COVERED_STATUS_TOKENS for c in cells):
            continue

        # Schema 2: | File | LOC | Reason | Acknowledged | with empty ack.
        # Heuristic: path-cell + at least one numeric-LOC cell + last cell
        # is empty / "-" / not starting with ACK-family token.
        path = None
        loc_seen = False
        for cell in cells:
            p = _is_path_cell(cell)
            if p and not path:
                path = p
                continue
            # v2.3.5 P4: tolerate "1,234" (thousands separator), "~500"
            # (approximate), "500 lines"/"500 LOC" (with units). Pre-v2.3.5
            # `re.fullmatch(r"\d{1,7}", cell)` rejected all of these → row
            # fell through schema detection → NOTREAD priority gaps silently
            # under-reported.
            if cell and re.fullmatch(
                r"[~≈]?\s*[\d,]{1,9}(?:\s*(?:lines?|LOC|loc))?", cell.strip()
            ):
                loc_seen = True
        if not path or not loc_seen:
            continue
        last = cells[-1].strip()
        last_lc = last.lower()
        ack_ok = (
            last.upper().startswith("ACKNOWLEDGED")
            or last.upper().startswith("ACK")
            or "leftover-ack" in last_lc
            or "cited" in last_lc
            or "covered" in last_lc
            or "✓" in last
        )
        if ack_ok:
            continue
        # Not acknowledged + has path + has LOC → treat as uncovered.
        files.append(path)
    return files


def _parse_uncovered_from_ledger(ledger_text: str) -> list[str]:
    """Extract paths from `file_coverage_ledger.md`'s `## Uncovered Files` section.

    Schema (per ~/.claude/prompts/l1/phase1-recon-prompt.md):
      ## Uncovered Files (MUST resolve before depth)
      | File | LOC | Top-Level Module | Proposed Action |
      | eth/downloader/skeleton.go | 420 | eth | ADD citation ... |
    """
    files: list[str] = []
    section_re = re.compile(
        r"(?im)^##\s+Uncovered\s+Files.*?(?=^##\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    m = section_re.search(ledger_text)
    if not m:
        return files
    for line in m.group(0).splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        upper = s.upper()
        if "FILE" in upper and ("LOC" in upper or "MODULE" in upper):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        for cell in cells:
            p = _is_path_cell(cell)
            if p:
                files.append(p)
                break
    return files


# --- v2.1.2: end-silent-degradation helpers ---------------------------------
# Foundry / npm library paths that are always out-of-scope by convention.
# scope_leftover entries under these paths are auto-acknowledged without
# requiring a human/LLM-authored ACK string. Prevents the
# false recon degradation class where forge-std / v2-periphery / v3-core entries
# triggered the coverage gate despite being obvious out-of-scope deps.
_SCOPE_LEFTOVER_LIB_WHITELIST = (
    # Generic non-production/test-support paths.
    "test/",
    "tests/",
    "testing/",
    "testdata/",
    "fixtures/",
    "fixture/",
    "examples/",
    "benches/",
    "bench/",
    "crates/testing-",
    "crates/testing_",
    "crates/test-",
    "crates/test_",
    "crates/test-utils/",
    "crates/test_utils/",
    "crates/mock-",
    "crates/mock_",
    "lib/forge-std/",
    "lib/openzeppelin-contracts/",
    "lib/openzeppelin-contracts-upgradeable/",
    "lib/v2-periphery/",
    "lib/v2-core/",
    "lib/v3-periphery/",
    "lib/v3-core/",
    "lib/solmate/",
    "lib/solady/",
    "lib/prb-math/",
    "lib/chainlink/",
    "lib/ccip/",
    "lib/murky/",
    "lib/ds-test/",
    "lib/permit2/",
    "node_modules/",
    "dependencies/",
    "vendor/",
)


def _is_whitelisted_lib_path(file_name: str) -> bool:
    """Return True when `file_name` sits under a known out-of-scope lib dir.

    Path separators are normalized so Windows-style `lib\\forge-std\\...` and
    POSIX `lib/forge-std/...` both match.
    """
    norm = file_name.replace("\\", "/").lstrip("./")
    return any(norm.startswith(p) for p in _SCOPE_LEFTOVER_LIB_WHITELIST)


# --- v2.2.0 A.2: promotion-receipt symmetry gate ---------------------------
#
# Failure mode (post-mortem RC-PIPELINE-DROPOUT class): a verifier emits
# CONFIRMED for a finding, but the report tier writer never produces a body
# section for it AND the index agent never records it as FALSE_POSITIVE in
# Appendix A. The finding is silently lost between Phase 5 and Phase 6.
# v2.1.9's quality gate compares body section counts to summary counts but
# does not assert "every CONFIRMED verifier verdict reaches the report."
#
# A.2 closes this by:
#   1. Mining all verify_*.md files for CONFIRMED verdicts and the finding
#      IDs they cover (regex-extracted, no agent ceremony).
#   2. Diffing that set against (body finding refs ∪ Appendix-A excluded ∪
#      consolidated-into).
#   3. Symmetric difference > 0 → gate fail with a delta-injected retry
#      hint listing the dropped IDs by name (uses the v2.1.6 retry-hint
#      mechanism so the next tier-writer attempt has the missing IDs).
#
# Generic across L1 and SC. Reads only what verifiers and report-writers
# already produce. No new artifacts required from agents.
# v2.3.5 P3: tolerate leading whitespace, bullet markers, and bold wrappers.
# The standard finding-output-format.md prescribes `**Verdict**: CONFIRMED`
# (bold), and tier writers / inventory blocks routinely emit `- Verdict: ...`
# (bullet) or `  Verdict: ...` (indented inside a section). The pre-v2.3.5
# `^Verdict` anchor missed every one of these valid forms, silently dropping
# CONFIRMED IDs from `_collect_verify_promotion_receipts` and any downstream
# consumer that depends on this regex.
_VERIFY_CONFIRMED_VERDICT_RE = re.compile(
    r"^\s*[-*]?\s*(?:\*{1,2})?(?:Verdict|verdict|VERDICT)(?:\*{1,2})?"
    r"\s*[:=]\s*(?:\*{1,2})?\s*(?:`)?CONFIRMED\b",
    re.MULTILINE | re.IGNORECASE,
)


# v2.4.3: derived from unified _ID_ALL_INTERNAL (single source of truth).
_INTERNAL_FINDING_ID_RE = _INTERNAL_ID_RE


def _verifier_status_from_text(text: str) -> str:
    """Best-effort verifier status extraction, with a resource-exhaustion
    safety net layered on top of the raw status resolver.

    SAFETY NET (MODE A, recall-safe): a resource-exhaustion / executable-harm
    finding must not be silently dropped via a STRUCTURAL "no executable harm"
    refutation that produced no PoC. When the raw verdict is a refutation
    (REFUTED / FALSE_POSITIVE) but its ONLY justification is a
    STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION skip (no executed PoC, no
    `[POC-FAIL]`) AND the text asserts a resource-exhaustion mechanism, demote
    the refutation to UNRESOLVED so the finding stays in the report BODY (one
    tier down, flagged for human review) instead of becoming an excluded
    one-liner. This can only KEEP a grounded finding, never drop one. A genuine
    `[POC-FAIL]` (the verifier actually ran a PoC that disproved the harm) is
    NOT touched — that refutation is mechanically backed.
    """
    status = _verifier_status_from_text_impl(text)
    if status in {"REFUTED", "FALSE_POSITIVE"} and _matches_resource_exhaustion(text):
        norm = _llm_norm(text or "")
        has_poc_fail = bool(re.search(r"\[\s*POC-?FAIL\s*\]", norm, re.IGNORECASE))
        structural_skip = bool(
            re.search(r"STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION", norm, re.IGNORECASE)
        )
        if structural_skip and not has_poc_fail:
            return "UNRESOLVED"
    return status


def _verifier_status_from_text_impl(text: str) -> str:
    """Best-effort verifier status extraction for report-index recovery.

    Closes F-VRF-01: an empty/whitespace verifier file used to default to
    `CONFIRMED`, manufacturing a passing verdict from missing data. Empty body
    now returns `UNRESOLVED` so the finding is demoted/flagged for human
    review rather than promoted as evidence.

    Defensive: passes input through `_llm_norm` so smart quotes, em-dashes,
    HTML entities, CRLF, etc. don't break verdict extraction on a fresh
    codebase whose LLM happens to emit a format variant we haven't seen.
    """
    text = _llm_norm(text)
    if not (text and text.strip()):
        return "UNRESOLVED"
    field = _field_from_markdown(text, ("Verdict", "Final Verdict", "Status"))
    if field:
        raw = field.strip().strip("`*_").upper()
        status_re = re.compile(
            r"(?<![A-Z])("
            r"APPENDIX[_\s-]*ONLY|DROP[_\s-]*(?:FALSE[_\s-]*POSITIVE|NON[_\s-]*SECURITY|DESIGN[_\s-]*CONFIRMATION|UNACTIONABLE[_\s-]*SPECULATION)|"
            r"SCHEMA[_\s-]*INVALID|LOCATION[_\s-]*INVALID|"
            r"FALSE[_\s-]*POSITIVE|REFUTED|INFEASIBLE|"
            r"CONTESTED|PARTIAL|UNRESOLVED|DUPLICATE|CONSOLIDATED|"
            r"TRUE[_\s-]*POSITIVE|CONFIRMED|VALID"
            r")(?![A-Z])",
            re.IGNORECASE,
        )
        m_field = status_re.search(raw)
        if m_field:
            tok = m_field.group(1).upper().replace(" ", "_").replace("-", "_")
            tok = re.sub(r"_+", "_", tok)
            if tok in ("TRUE_POSITIVE", "VALID"):
                return "CONFIRMED"
            if tok == "CONSOLIDATED":
                return "DUPLICATE"
            if tok == "PARTIAL":
                return "UNRESOLVED"
            return tok
        return raw.replace(" ", "_").replace("-", "_")
    m = re.search(
        r"(?i)\b(APPENDIX[_\s-]*ONLY|DROP[_\s-]*(?:FALSE[_\s-]*POSITIVE|NON[_\s-]*SECURITY|DESIGN[_\s-]*CONFIRMATION|UNACTIONABLE[_\s-]*SPECULATION)|"
        r"SCHEMA_INVALID|LOCATION_INVALID|FALSE\s*POSITIVE|FALSE_POSITIVE|REFUTED|INFEASIBLE|"
        r"CONTESTED|PARTIAL|UNRESOLVED|DUPLICATE|CONSOLIDATED|"
        r"TRUE\s*POSITIVE|TRUE_POSITIVE|CONFIRMED|VALID)\b",
        text or "",
    )
    if not m:
        # Closes BS.header-only / BS.no-verdict-tokens: a verify file with
        # content but NO verdict token (e.g., a markdown header alone, or
        # only Evidence Tag / Severity fields) used to default to CONFIRMED.
        # That's silent semantic manufacturing — same class as the empty-
        # body bug. Treat absence-of-verdict as UNRESOLVED so downstream
        # demotes the finding and flags it for human review.
        return "UNRESOLVED"
    tok = m.group(1).upper().replace(" ", "_")
    if tok in ("TRUE_POSITIVE", "VALID"):
        return "CONFIRMED"
    if tok == "CONSOLIDATED":
        return "DUPLICATE"
    if tok == "PARTIAL":
        return "UNRESOLVED"
    return tok


def _severity_name_from_text(text: str, queue_row: dict[str, str]) -> str:
    sev = (
        _field_from_markdown(text, ("Severity", "Final Severity"))
        or queue_row.get("severity", "")
        or "Medium"
    ).strip()
    return normalize_severity(sev)


def _report_prefix_for_severity(severity: str) -> str:
    return severity_letter_from_name(severity)


def _verify_file_for_id(scratchpad: Path, finding_id: str) -> Path:
    """Return the existing verifier file for an ID across naming variants."""
    fid = _normalize_finding_id(finding_id) or (finding_id or "").strip()
    if not fid:
        return scratchpad / "__invalid_verify_id__.md"
    for name in (
        f"verify_{fid}.md",
        f"verify_F-{fid}.md",
        f"verify_F_{fid}.md",
        f"verify_[{fid}].md",
    ):
        p = scratchpad / name
        if p.exists():
            return p
    return scratchpad / f"verify_{fid}.md"


def _next_report_id_counters(scratchpad: Path) -> dict[str, int]:
    counters = {"C": 0, "H": 0, "M": 0, "L": 0, "I": 0}
    for row in parse_report_index_assignments(scratchpad):
        rid = (row.get("report_id") or "").strip().upper()
        m = re.match(r"^([CHMLI])-(\d+)$", rid)
        if m:
            counters[m.group(1)] = max(counters[m.group(1)], int(m.group(2)))
    return counters


def _find_report_index_cut_for_active_recovery(text: str) -> int:
    """Insert active recovery rows before excluded/non-reportable sections."""
    cut_re = re.compile(
        r"(?im)^\s*#{1,4}\s+.*(?:excluded|false\s*positive|refuted|appendix|"
        r"consolidation map|non-reportable|not reportable|traceability).*$"
    )
    m = cut_re.search(text)
    return m.start() if m else len(text)


def _is_reportable_verdict(status: str) -> bool:
    status = (status or "").upper()
    if any(tok in status for tok in (
        "APPENDIX_ONLY",
        "DROP_FALSE_POSITIVE",
        "DROP_NON_SECURITY",
        "DROP_DESIGN_CONFIRMATION",
        "DROP_UNACTIONABLE_SPECULATION",
        "FALSE_POSITIVE",
        "REFUTED",
        "INFEASIBLE",
        "SCHEMA_INVALID",
        "LOCATION_INVALID",
    )):
        return False
    if "DUPLICATE" in status or "CONSOLIDATED" in status:
        return False
    return True


def _demote_severity_once(severity: str) -> str:
    """Demote one tier with Low and Informational floors.

    Closes F-SEV-02: pre-fix logic capped index at `len(order) - 2 = 3` which
    inflated `Informational` (idx 4) to `Low` (idx 3). Per report-template.md
    A.3, both Low and Informational are floors — they do not demote further.
    Ordering: Critical > High > Medium > Low; Informational is its own floor.
    """
    order = list(SEVERITY_ORDER)
    sev = normalize_severity(severity)
    try:
        idx = order.index(sev)
    except ValueError:
        return "Medium"
    # Floor: Low and Informational stay where they are.
    if idx >= 3:
        return order[idx]
    return order[idx + 1]


# =============================================================================
# Phase B: Severity Matrix Enforcement (per ~/.claude/rules/report-template.md)
#
# Severity = Impact x Likelihood, then downgrade modifiers stack:
#   1) on-chain-only exploit: -1 tier (only when impact is on-chain confined)
#   2) view-function-only impact: cap at Medium
#   3) fully-trusted actor must act maliciously: -1 tier (floor: Informational)
#
# When a verify_*.md provides Impact + Likelihood, the matrix is authoritative
# and overrides any LLM-emitted Severity. When matrix data is absent, fall back
# to current behaviour (preserve queue/LLM severity) so legacy verify files
# continue to work.
# =============================================================================
_MATRIX_IMPACT_LABELS = {"high", "medium", "low", "informational", "info"}


_MATRIX_LIKELIHOOD_LABELS = {"high", "medium", "low"}


def _normalize_matrix_label(value: str | None, allowed: set[str]) -> str | None:
    if value is None:
        return None
    s = str(value).strip().lower()
    if not s:
        return None
    if s == "info":
        s = "informational"
    if s not in allowed and s.replace("informational", "info") not in allowed:
        return None
    if s.startswith("info"):
        return "Informational"
    if s.startswith("high"):
        return "High"
    if s.startswith("med"):
        return "Medium"
    if s.startswith("low"):
        return "Low"
    return None


def _compute_matrix_severity(impact: str | None, likelihood: str | None) -> str | None:
    """Return matrix severity for given Impact x Likelihood, or None if unparseable.

    Per report-template.md table:
        High x High   -> Critical
        High x Medium -> High
        High x Low    -> Medium
        Medium x High -> High
        Medium x Med  -> Medium
        Medium x Low  -> Medium
        Low x High    -> Medium
        Low x Medium  -> Low
        Low x Low     -> Low
        Informational x * -> Informational
    """
    i = _normalize_matrix_label(impact, _MATRIX_IMPACT_LABELS)
    l = _normalize_matrix_label(likelihood, _MATRIX_LIKELIHOOD_LABELS)
    if i is None or l is None:
        return None
    if i == "Informational":
        return "Informational"
    table = {
        ("High", "High"): "Critical",
        ("High", "Medium"): "High",
        ("High", "Low"): "Medium",
        ("Medium", "High"): "High",
        ("Medium", "Medium"): "Medium",
        ("Medium", "Low"): "Medium",
        ("Low", "High"): "Medium",
        ("Low", "Medium"): "Low",
        ("Low", "Low"): "Low",
    }
    return table.get((i, l))


def _apply_severity_modifiers(severity: str, modifiers: dict[str, bool]) -> str:
    """Apply downgrade modifiers in fixed order: onchain_only, view_function, fully_trusted.

    - onchain_only: -1 tier (Low/Informational are floors)
    - view_function: cap at Medium (do not promote anything below Medium up)
    - fully_trusted: -1 tier with Informational as floor
    """
    sev = severity
    if modifiers.get("onchain_only"):
        sev = _demote_severity_once(sev)
    if modifiers.get("view_function"):
        # Cap at Medium - severities at or below Medium pass through.
        order = list(SEVERITY_ORDER)
        try:
            idx = order.index(sev)
        except ValueError:
            idx = 2  # default to Medium
        if idx < 2:  # Critical or High -> cap at Medium
            sev = "Medium"
    if modifiers.get("fully_trusted"):
        # Per report-template.md, fully-trusted modifier has Informational as
        # the only floor: Low demotes to Informational, Informational stays.
        order = list(SEVERITY_ORDER)
        try:
            idx = order.index(sev)
        except ValueError:
            idx = 2
        if idx < len(order) - 1:
            sev = order[idx + 1]
    return sev


_MATRIX_IMPACT_RE = re.compile(
    r"^\s*(?:[-*+]\s+)?\*{0,2}Impact\*{0,2}\s*:\s*(High|Medium|Low|Informational|Info)\b",
    re.IGNORECASE | re.MULTILINE,
)


_MATRIX_LIKELIHOOD_RE = re.compile(
    r"^\s*(?:[-*+]\s+)?\*{0,2}Likelihood\*{0,2}\s*:\s*(High|Medium|Low)\b",
    re.IGNORECASE | re.MULTILINE,
)


# Fix from a prior audit: the original `fully[-\s]?trusted` pattern matched
# explanatory PROSE that REJECTS applying the modifier (e.g., verifier
# wrote "the severity discount for fully-trusted actors applies only
# when… [we don't apply it here]"). This caused a false-positive -1 tier
# demotion in `_apply_severity_modifiers` → driver expected Medium for
# verify_H-9.md but verifier wrote High → provenance gate halted.
# Fix: require an EXPLICIT structured field marker, not free prose. The
# verifier must affirmatively assert the modifier via a recognized
# line-anchored format. Free mentions of "fully-trusted" in narrative
# discussion are ignored.
_MATRIX_TRUST_FULLY_RE = re.compile(
    # Affirmative explicit forms only — narrative mentions of
    # "fully-trusted" in prose discussion don't match. The verifier
    # must use one of these structured patterns to opt into the
    # -1 tier modifier:
    #   `**Trust**: FULLY_TRUSTED`
    #   `**Modifier**: FULLY_TRUSTED`
    #   `Trust Modifier: fully-trusted`
    #   `Trust Adj.: TRUSTED-ACTOR(...)`
    #   `Severity Modifier: fully-trusted`
    #   `Actor: fully-trusted`
    #   `[TRUSTED-ACTOR]` tag
    #   `applies fully-trusted -1 tier`
    r"(?:^\s*(?:\*\*)?(?:Trust\s*Adj\.?|Trust|Modifier|"
    r"Trust\s*Modifier|Severity\s*Modifier|Actor)(?:\*\*)?\s*:?\s*"
    r"(?:FULLY[_\s-]TRUSTED|fully[-\s]?trusted|TRUSTED-ACTOR))|"
    r"(?:\[TRUSTED-ACTOR\])|"
    r"(?:applies\s+(?:the\s+)?fully[-\s]?trusted)",
    re.IGNORECASE | re.MULTILINE,
)


_MATRIX_VIEW_FN_RE = re.compile(
    r"view[-\s]?function[-\s]?only|view[-\s]?function\s+impact",
    re.IGNORECASE,
)


_MATRIX_ONCHAIN_RE = re.compile(
    r"on[-\s]?chain[-\s]?only|on[-\s]?chain\s+only\s+attack|on[-\s]?chain[-\s]?only\s+exploit",
    re.IGNORECASE,
)


# Severity enum for the matrix axes. Impact may also be "Informational"/"Info"
# (the `_MATRIX_IMPACT_RE` accept set); Likelihood is High/Medium/Low only. The
# leading-word extractor below mirrors the legacy regexes' group(1) — it returns
# the FIRST enum word of a value like `High (direct fund loss)` so the table and
# kv forms yield a value-identical result to the old leading-key regex.
_MATRIX_IMPACT_ENUM = r"\b(?:High|Medium|Low|Informational|Info)\b"
_MATRIX_LIKELIHOOD_ENUM = r"\b(?:High|Medium|Low)\b"
_MATRIX_IMPACT_ENUM_RE = re.compile(_MATRIX_IMPACT_ENUM, re.IGNORECASE)
_MATRIX_LIKELIHOOD_ENUM_RE = re.compile(_MATRIX_LIKELIHOOD_ENUM, re.IGNORECASE)


def _matrix_axis(text: str, labels, enum_re: re.Pattern, enum_pat: str):
    """Extract a severity-matrix axis (Impact / Likelihood) from *text*.

    Routes through the shared `_field_anywhere` tolerant extractor
    (regex-fragility plan Site 3) so the axis is found in EVERY shape:
    leading-key (`Impact: High`), bold/backtick/bullet, AND — the live miss —
    the matrix TABLE forms (`| Impact | Likelihood |` header/row and
    `| Impact | High |` vertical kv). `value_pattern=enum_pat` constrains the
    accepted value to the severity enum (so a `Impact: TBD` line is skipped and
    the search continues, just like the legacy regex would not match it).

    Returns the leading enum WORD (group(1)-equivalent: `High` from
    `High (direct fund loss)`), preserving value-identity with the legacy
    `_MATRIX_*_RE.group(1)`. Returns None when no axis value is present.
    """
    value, _shape = _field_anywhere(
        text, labels, value_pattern=enum_pat, table_ok=True
    )
    if not value:
        return None
    m = enum_re.search(value)
    return m.group(0) if m else None


def _extract_severity_inputs(verify_text: str) -> dict:
    """Parse Impact, Likelihood, and modifier flags from a verify_*.md body.

    Impact/Likelihood are extracted via the shared `_field_anywhere` tolerant
    extractor (Site 3): the legacy leading-key form (`Impact: High`) PLUS the
    previously table-blind matrix renderings (`| Impact | Likelihood |` header
    row + aligned data row, and `| Impact | High |` vertical kv). Modifier flags
    are detected by phrase scan in the body -- these are advisory tags emitted
    by the verifier methodology, not formal fields. Missing data returns
    empty / None values for graceful fallback.
    """
    text = verify_text or ""
    impact = _matrix_axis(
        text, ("Impact",), _MATRIX_IMPACT_ENUM_RE, _MATRIX_IMPACT_ENUM
    )
    likelihood = _matrix_axis(
        text, ("Likelihood",), _MATRIX_LIKELIHOOD_ENUM_RE, _MATRIX_LIKELIHOOD_ENUM
    )
    modifiers = {
        "onchain_only": bool(_MATRIX_ONCHAIN_RE.search(text)),
        "view_function": bool(_MATRIX_VIEW_FN_RE.search(text)),
        "fully_trusted": bool(_MATRIX_TRUST_FULLY_RE.search(text)),
    }
    return {"impact": impact, "likelihood": likelihood, "modifiers": modifiers}


_SEVERITY_ADJUSTMENT_PATTERNS = (
    # `High (adjusted to Medium — reason)` — most common verifier idiom
    re.compile(
        r"^\s*(?:Critical|High|Medium|Low|Informational|Info)\s*"
        r"[\(\[][^)\]]*?\b(?:adjusted|demoted|upgraded|downgraded|capped|"
        r"reduced|raised|moved|now|→|->|=>)\s*(?:to\s+)?"
        r"(Critical|High|Medium|Low|Informational|Info)\b",
        re.IGNORECASE,
    ),
    # `High → Medium` or `High -> Medium` or `High => Medium`
    re.compile(
        r"^\s*(?:Critical|High|Medium|Low|Informational|Info)\s*"
        r"(?:→|->|=>)\s*"
        r"(Critical|High|Medium|Low|Informational|Info)\b",
        re.IGNORECASE,
    ),
)


def _extract_verifier_severity_with_adjustment(raw: str) -> str:
    """Return the FINAL severity the verifier intended, after any inline
    adjustment they documented.

    The verifier prompt allows authored adjustments inline in the
    `Severity:` field (e.g. ``**Severity:** High (adjusted to Medium —
    external precondition required)``). Naive parsing reads "High" (the
    first token) and inflates the expected severity; the provenance
    gate then rejects the LLM's correctly-downgraded report row.

    This helper recognizes the documented adjustment idioms and returns
    the POST-adjustment value. If no adjustment is found, returns the
    field verbatim for downstream `normalize_severity` to handle.

    Added in response to a prior audit halt where
    `verify_H-20.md` wrote `Severity: High (adjusted to Medium —
    external precondition required; see below)` — verifier intent was
    Medium, driver computed High, LLM correctly wrote Medium per the
    intent, provenance gate misclassified as LLM-fault.
    """
    text = (raw or "").strip()
    if not text:
        return text
    # The upstream `_field_from_markdown` extractor can leak markdown
    # decoration (`**`, leading `-`, backticks) when verifiers write
    # `**Severity:** High (...)` — strip those so the adjustment-pattern
    # regex can anchor cleanly on the severity word.
    cleaned = re.sub(r"^[\s*`_\-–—:]+", "", text)
    cleaned = re.sub(r"[\s*`_]+$", "", cleaned)
    for pat in _SEVERITY_ADJUSTMENT_PATTERNS:
        m = pat.search(cleaned)
        if m:
            return m.group(1)
    return text


def _enforce_severity_matrix(verify_text: str, queue_row: dict[str, str]) -> str:
    """Compute expected severity from verify text and queue row.

    Priority (refinement from a prior run, asymmetric and intentional):

    1. Matrix (Impact × Likelihood + modifiers) when both axes are present.
    2. Verifier's explicit `**Severity**:` field when LOWER than the matrix
       computation — the verifier has context (atomic revert, design
       intent) the mechanical matrix cannot capture, AND a verifier
       under-rating is a deliberate authored downgrade that needs no
       Trust Adj. token.
    3. Verifier's inline-adjustment notation (e.g. `Severity: High
       (adjusted to Medium — reason)`) is honored as the verifier's
       intent — the post-adjustment value wins.
    4. Queue-row severity as final fallback with E7 conservative
       downgrade.

    **Why NOT symmetric (verifier wins both directions)?** A prior
    audit's H-9 case looked like a symmetric-rule problem
    (verifier said High, matrix said Medium due to a prose match on
    `fully-trusted`). The real fix was in
    `_MATRIX_TRUST_FULLY_RE` — tightening the trust-modifier detector
    so it requires an explicit structured marker, not free prose.
    With that fix, the verifier explicitly rejecting the modifier in
    narrative no longer false-triggers the demotion. The asymmetric
    contract (matrix corrects LLM over-rating) is preserved, which
    catches the more common failure mode of verifier severity
    inflation seen in a prior grader output (6/7 FOUND verdicts
    over-rated severity vs ground truth).
    """
    inputs = _extract_severity_inputs(verify_text)
    base = _compute_matrix_severity(inputs.get("impact"), inputs.get("likelihood"))
    verifier_sev_raw = _field_from_markdown(
        verify_text or "", ("Severity", "Final Severity"),
    )
    # Apply inline-adjustment recognition before normalizing. The
    # verifier may have written `High (adjusted to Medium — reason)`;
    # honor the post-adjustment value as the verifier's intent.
    verifier_sev_resolved = _extract_verifier_severity_with_adjustment(
        verifier_sev_raw
    )
    verifier_sev = (
        normalize_severity(verifier_sev_resolved) if verifier_sev_resolved else ""
    )
    if base is not None:
        mods = dict(inputs.get("modifiers", {}))
        # CALIBRATION (recover the good-coverage-class Critical): the on-chain-only
        # -1 modifier applies ONLY when impact is CONFINED to on-chain state
        # (report-template.md). Impact:High is defined as "direct fund loss /
        # permanent lock" -- that is NOT confined, so the modifier must not pull a
        # High-impact finding down (later runs lost their Critical to exactly
        # this spurious on-chain demotion of a verified High x High theft). This
        # only PREVENTS a demotion of an already-High-impact finding; it never
        # promotes, so it cannot re-inflate the verifier-over-rating class the
        # asymmetric matrix is designed to correct.
        if _normalize_matrix_label(inputs.get("impact"), _MATRIX_IMPACT_LABELS) == "High":
            mods.pop("onchain_only", None)
        matrix_final = _apply_severity_modifiers(base, mods)
        if verifier_sev and verifier_sev != matrix_final:
            v_rank = severity_rank(verifier_sev)
            m_rank = severity_rank(matrix_final)
            # Verifier wins ONLY when LOWER than the matrix. Higher-than-
            # matrix verifier severity is interpreted as LLM over-rating
            # and the matrix corrects it.
            if v_rank < m_rank and v_rank >= 0:
                return verifier_sev
        return matrix_final
    # No matrix axes — fall back to explicit verifier field or queue row.
    recovered = normalize_severity(
        (verifier_sev or queue_row.get("severity", "") or "Medium").strip()
    )
    if recovered in ("Critical", "High") and not verifier_sev:
        return "Medium"
    return recovered


# =============================================================================
# Phase C: Duplicate / root-cause consolidation gate.
#
# Per report-template.md and phase6 STEP 1.5, findings sharing the same root
# cause must be consolidated. Threshold for an automatic consolidation is 3+
# findings sharing (severity, fix_pattern, vuln_class). The driver performs
# this mechanically so the LLM cannot silently inflate finding counts via
# repeated low-severity issues.
# =============================================================================
class DedupSignature:
    __slots__ = ("severity", "fix_pattern", "vuln_class")

    def __init__(self, severity: str, fix_pattern: str, vuln_class: str):
        self.severity = severity
        self.fix_pattern = fix_pattern
        self.vuln_class = vuln_class

    def key(self) -> tuple[str, str, str]:
        return (
            (self.severity or "").strip().lower(),
            (self.fix_pattern or "").strip().lower(),
            (self.vuln_class or "").strip().lower(),
        )

    def __repr__(self) -> str:
        return f"DedupSignature(sev={self.severity}, fix={self.fix_pattern}, class={self.vuln_class})"


_DEDUP_VULN_VOCAB: list[tuple[str, str]] = [
    ("event emission", "missing_event"),
    ("missing event", "missing_event"),
    ("no event", "missing_event"),
    ("event missing", "missing_event"),
    ("reentrancy", "reentrancy"),
    ("integer overflow", "overflow"),
    ("integer underflow", "overflow"),
    ("overflow", "overflow"),
    ("underflow", "overflow"),
    ("zero-value", "missing_validation"),
    ("zero value", "missing_validation"),
    ("input validation", "missing_validation"),
    ("missing validation", "missing_validation"),
    ("missing check", "missing_validation"),
    ("staleness", "staleness"),
    ("stale data", "staleness"),
    ("stale price", "staleness"),
    ("access control", "access_control"),
    ("missing access", "access_control"),
    ("authorization missing", "access_control"),
    ("centralization", "centralization"),
    ("denial of service", "dos"),
    (" dos ", "dos"),
    ("front-run", "front_run"),
    ("frontrun", "front_run"),
    ("front run", "front_run"),
    ("price manipulation", "price_manipulation"),
    ("oracle manipulation", "oracle_manipulation"),
    ("rounding", "rounding"),
    ("precision loss", "rounding"),
    ("storage collision", "storage_collision"),
    ("storage layout", "storage_collision"),
]


_DEDUP_FIX_VOCAB: list[tuple[str, str]] = [
    ("emit an event", "emit_event"),
    ("emit event", "emit_event"),
    ("emit a", "emit_event"),
    ("event in", "emit_event"),
    ("zero-value validation", "zero_validation"),
    ("zero value validation", "zero_validation"),
    ("zero validation", "zero_validation"),
    ("non-zero check", "zero_validation"),
    ("require(.*!= 0", "zero_validation"),
    ("input validation", "input_validation"),
    ("reentrancyguard", "reentrancy_guard"),
    ("reentrancy guard", "reentrancy_guard"),
    ("nonreentrant", "reentrancy_guard"),
    ("safemath", "checked_arith"),
    ("checked arithmetic", "checked_arith"),
    ("checked math", "checked_arith"),
    ("safe casting", "checked_arith"),
    ("staleness check", "staleness_check"),
    ("max staleness", "staleness_check"),
    ("freshness check", "staleness_check"),
    ("only owner", "access_control_check"),
    ("onlyowner", "access_control_check"),
    ("onlyrole", "access_control_check"),
    ("access control", "access_control_check"),
    ("oracle check", "oracle_check"),
    ("rounding", "rounding_fix"),
    ("validation", "validation"),
    ("require ", "validation"),
]


_CLASS_LEVEL_TITLES: dict[str, str] = {
    "missing_event": "Missing event emission on admin state changes",
    "reentrancy": "Missing reentrancy protection across affected functions",
    "overflow": "Unchecked arithmetic operations",
    "missing_validation": "Admin setters lack input validation",
    "staleness": "External data source freshness not validated",
    "access_control": "Privileged operations lack access control",
    "centralization": "Excessive privileges concentrated in trusted role",
    "dos": "Denial-of-service vectors via unbounded operations",
    "front_run": "Operations exposed to transaction front-running",
    "price_manipulation": "Price feed manipulation vectors",
    "oracle_manipulation": "Oracle manipulation vectors",
    "rounding": "Precision loss from rounding direction",
    "storage_collision": "Storage layout collision risks",
}


# Quality observation vocabulary — unambiguously cosmetic classes that get
# megasection (compact table) treatment in the report.  Anything with
# plausible security impact MUST NOT appear here.
_QUALITY_OBSERVATION_VOCAB: list[tuple[str, str]] = [
    ("dead code", "dead_code"),
    ("unreachable code", "dead_code"),
    ("unused code", "dead_code"),
    ("unused import", "unused_import"),
    ("unused variable", "unused_variable"),
    ("unused parameter", "unused_variable"),
    ("unused return", "unused_variable"),
    ("naming inconsistenc", "naming"),
    ("naming convention", "naming"),
    ("inconsistent naming", "naming"),
    ("variable naming", "naming"),
    ("function naming", "naming"),
    ("typo", "typo"),
    ("spelling", "typo"),
    ("grammar", "typo"),
    ("magic number", "magic_number"),
    ("hardcoded constant", "magic_number"),
    ("hard-coded constant", "magic_number"),
    ("missing natspec", "missing_docs"),
    ("missing documentation", "missing_docs"),
    ("missing comment", "missing_docs"),
    ("undocumented", "missing_docs"),
    ("code style", "code_style"),
    ("formatting", "code_style"),
    ("gas optimization", "gas_optimization"),
    ("gas efficiency", "gas_optimization"),
    ("gas saving", "gas_optimization"),
    ("redundant code", "redundant_code"),
    ("redundant check", "redundant_code"),
    ("unnecessary check", "redundant_code"),
    ("shadow", "shadowing"),
    ("variable shadow", "shadowing"),
]

_QUALITY_CLASS_TITLES: dict[str, str] = {
    "dead_code": "Dead / unreachable code",
    "unused_import": "Unused imports",
    "unused_variable": "Unused variables / parameters",
    "naming": "Naming inconsistencies",
    "typo": "Typos and spelling",
    "magic_number": "Magic numbers / hardcoded constants",
    "missing_docs": "Missing documentation",
    "code_style": "Code style and formatting",
    "gas_optimization": "Gas optimization opportunities",
    "redundant_code": "Redundant code / checks",
    "shadowing": "Variable shadowing",
}


def classify_quality_observation(title: str, severity: str) -> str:
    """Return a quality-observation class if this finding is cosmetic, else ''."""
    if severity.lower() not in ("low", "informational", "info"):
        return ""
    return _classify_keyword(title, _QUALITY_OBSERVATION_VOCAB)


def _classify_keyword(text: str, vocab: list[tuple[str, str]]) -> str:
    if not text:
        return ""
    tl = " " + text.lower() + " "
    # Match longest needle first to avoid early shorter-match short-circuit.
    for needle, canon in sorted(vocab, key=lambda x: -len(x[0])):
        if needle in tl:
            return canon
    return ""


# =========================================================================
# Material-harm body floor (disposition: BODY vs APPENDIX)
# =========================================================================
#
# Policy (recall-safe — see ~/.plamen/rules/report-template.md and
# phase6-report-prompts.md Step 1.25):
#
# A finding is APPENDIX *only* when it has ZERO security consequence — i.e. it
# is pure quality / hardening / observability / style (missing events; missing
# zero-address / range checks with no demonstrated loss; one-step ownership /
# missing two-step / renounceOwnership; defense-in-depth such as "add
# nonReentrant" with no shown reentrancy loss; signature / EIP-712 binding
# hardening with no shown exploit; missing asserts / gates with no consequence;
# UX / allowance friction; naming; typos; error-message wording; magic numbers;
# gas; docs; test-harness quality; interface-vs-impl parity; supportsInterface
# omissions; latent / none-at-present hazards).
#
# Otherwise → BODY, at ANY severity. ANY real security consequence keeps a
# finding in the body even when trusted-actor-gated, self-inflicted, or
# bounded/dust: direct fund loss / extraction, funds locked or frozen,
# privilege escalation, a liveness brick denying a core user action, or
# accounting corruption leading to loss.
#
# Recall-safe default: when in doubt, BODY. Burying a real finding in the
# appendix is the unacceptable error; an extra body finding is cheap. The
# consequence signal therefore wins over the quality signal, and an unmatched
# finding defaults to BODY.
#
# This is a deliberately GENERIC classifier — no protocol / token / contract /
# function names (Plamen Part-0 no-overfit rule).

# Concrete security-consequence vocabulary. A finding whose title or harm text
# matches any of these stays in the BODY regardless of any quality match. Kept
# GENEROUS on purpose: firing here is the recall-safe direction.
_HARM_CONSEQUENCE_RE = re.compile(
    r"(?i)\b("
    # direct value loss / extraction
    r"fund(?:s)?\s+(?:loss|are\s+lost|can\s+be\s+lost)|loss\s+of\s+fund|"
    r"lose\s+(?:funds|their|tokens|assets|value|shares|collateral|deposit)|"
    r"drain\w*|steal\w*|stolen|theft|siphon\w*|exfiltrat\w*|"
    r"extract(?:s|ed|ion)?\s+(?:value|funds|more)|over[-\s]?pay|over[-\s]?charg|"
    r"under[-\s]?pay|mint\s+(?:unlimited|free|extra)|inflat(?:e|ed|ion)\s+|"
    # locked / frozen liveness on value
    r"locked|frozen|freeze|stuck|trapped|"
    r"cannot\s+(?:withdraw|redeem|claim|exit|unstake)|"
    r"unable\s+to\s+(?:withdraw|redeem|claim|exit|unstake)|"
    r"withdraw(?:al)?s?\s+(?:revert|blocked|disabled|fail)|"
    r"permanent(?:ly)?\s+(?:lock|disabl|halt|brick)|"
    # privilege / access
    r"privilege\s+escalat|escalat\w*\s+privilege|"
    r"unauthoriz\w*\s+(?:access|mint|burn|withdraw|transfer|call)|"
    r"takeover|take\s+over|seize\s+control|gain\s+(?:admin|owner|control)|"
    r"bypass\w*\s+(?:access|auth|permission|the\s+(?:check|guard))|"
    r"arbitrary\s+(?:call|external\s+call|code|transfer)|"
    # liveness / DoS on a core action
    r"brick|denial[-\s]?of[-\s]?service|\bdos\b|"
    r"permanently\s+halt|halt\s+(?:block|the\s+protocol|production)|"
    r"deny\w*\s+(?:a\s+core|users?|service)|"
    # accounting / solvency leading to loss
    r"insolven|bad\s+debt|under[-\s]?collateraliz|"
    r"accounting\s+(?:corrupt|error)\w*\s+(?:caus|lead|result)|"
    r"incorrect\s+(?:share|payout|reward|balance|accounting)\s+(?:caus|lead|result|so\s+that|allowing)|"
    r"share\s+(?:inflat|dilut)|first\s+depositor|donation\s+attack|"
    r"price\s+manipulat|oracle\s+manipulat|reentran\w*\s+(?:drain|steal|allow|so)|"
    r"griefing\s+(?:that|to|users)"
    r")\b"
)

# Pure-quality / hardening / observability vocabulary. A finding that matches
# ONLY this set (and NOT the consequence set) is APPENDIX. Kept SPECIFIC on
# purpose so it rarely fires on a real finding.
_PURE_QUALITY_VOCAB: list[tuple[str, str]] = [
    # observability
    ("missing event", "observability"),
    ("no event", "observability"),
    ("does not emit", "observability"),
    ("lacks event", "observability"),
    ("event emission", "observability"),
    ("emit an event", "observability"),
    ("event not emitted", "observability"),
    # input-hardening with no shown loss
    ("missing zero-address check", "input_hardening"),
    ("missing zero address check", "input_hardening"),
    ("zero-address check", "input_hardening"),
    ("zero address validation", "input_hardening"),
    ("address(0) check", "input_hardening"),
    ("missing address(0)", "input_hardening"),
    ("missing range check", "input_hardening"),
    ("missing bounds check", "input_hardening"),
    ("missing sanity check", "input_hardening"),
    ("missing input validation", "input_hardening"),
    ("missing validation", "input_hardening"),
    ("does not validate", "input_hardening"),
    ("lacks validation", "input_hardening"),
    ("no input validation", "input_hardening"),
    ("missing require", "input_hardening"),
    # ownership hygiene
    ("two-step ownership", "ownership_hygiene"),
    ("two step ownership", "ownership_hygiene"),
    ("single-step ownership", "ownership_hygiene"),
    ("one-step ownership", "ownership_hygiene"),
    ("ownable2step", "ownership_hygiene"),
    ("ownable 2 step", "ownership_hygiene"),
    ("renounceownership", "ownership_hygiene"),
    ("renounce ownership", "ownership_hygiene"),
    # defense-in-depth
    ("defense in depth", "defense_in_depth"),
    ("defense-in-depth", "defense_in_depth"),
    ("defence in depth", "defense_in_depth"),
    ("add nonreentrant", "defense_in_depth"),
    ("missing nonreentrant", "defense_in_depth"),
    ("missing reentrancy guard", "defense_in_depth"),
    ("as a precaution", "defense_in_depth"),
    # signature / EIP-712 binding hardening
    ("eip-712", "signature_hardening"),
    ("eip712", "signature_hardening"),
    ("domain separator", "signature_hardening"),
    ("signature binding", "signature_hardening"),
    ("typed data hardening", "signature_hardening"),
    # UX / allowance friction
    ("allowance", "ux_friction"),
    ("approval friction", "ux_friction"),
    ("user experience", "ux_friction"),
    ("ux friction", "ux_friction"),
    ("usability", "ux_friction"),
    # interface parity
    ("interface parity", "interface_parity"),
    ("interface vs impl", "interface_parity"),
    ("interface mismatch with impl", "interface_parity"),
    ("supportsinterface", "interface_parity"),
    ("supports interface", "interface_parity"),
    ("erc165", "interface_parity"),
    ("erc-165", "interface_parity"),
    # latent / no-present-impact
    ("none at present", "latent"),
    ("no current impact", "latent"),
    ("not currently exploitable", "latent"),
    ("no present impact", "latent"),
    ("latent hazard", "latent"),
    ("theoretical only", "latent"),
    # cosmetic (subset of QO vocab, kept so the floor catches them too)
    ("dead code", "cosmetic"),
    ("unused import", "cosmetic"),
    ("unused variable", "cosmetic"),
    ("naming inconsistenc", "cosmetic"),
    ("naming convention", "cosmetic"),
    ("typo", "cosmetic"),
    ("spelling", "cosmetic"),
    ("error message", "cosmetic"),
    ("error-message", "cosmetic"),
    ("revert message", "cosmetic"),
    ("revert string", "cosmetic"),
    ("magic number", "cosmetic"),
    ("hardcoded constant", "cosmetic"),
    ("missing natspec", "cosmetic"),
    ("missing documentation", "cosmetic"),
    ("missing comment", "cosmetic"),
    ("code style", "cosmetic"),
    ("gas optimization", "cosmetic"),
    ("gas efficiency", "cosmetic"),
    ("gas saving", "cosmetic"),
    ("redundant check", "cosmetic"),
    ("shadow", "cosmetic"),
]

_DISPOSITION_CLASS_TITLES: dict[str, str] = {
    "observability": "Observability / missing events",
    "input_hardening": "Input hardening (no demonstrated loss)",
    "ownership_hygiene": "Ownership hygiene",
    "defense_in_depth": "Defense-in-depth (no demonstrated exploit)",
    "signature_hardening": "Signature / EIP-712 hardening",
    "ux_friction": "UX / allowance friction",
    "interface_parity": "Interface parity",
    "latent": "Latent / no present impact",
    "cosmetic": "Code quality / cosmetic",
}


# F5: concrete-harm phrases used ONLY to make an `[EXTERNAL-ASSUMPTION` finding
# load-bearing. An [EXTERNAL-ASSUMPTION] tag marks an in-scope-CONFIRMED
# mechanism whose severity assumes the worst realistic external condition
# (R10) — it is a verification obligation, NOT a severity discount. When such a
# finding ALSO states a concrete harm, a quality keyword (e.g. "defense-in-depth")
# must NOT be allowed to misroute it into the appendix. This list is
# intentionally simpler/broader than _HARM_CONSEQUENCE_RE so it catches harm
# phrasings the main RE does not (e.g. "receive fewer", "less than their fair
# share"). It is gated behind the tag, so over-matching only ever pushes toward
# BODY (recall-safe). GENERIC — no protocol/token/function names.
_F5_CONCRETE_HARM_RE = re.compile(
    r"(?i)\b("
    r"los(?:e|es|ing)|lost|"
    r"short(?:ed|s|fall)?|"
    r"steal\w*|stole|stolen|"
    r"drain\w*|"
    r"lock(?:ed|s|ing)?|frozen|freeze|"
    r"insolven\w*|"
    r"receive\s+fewer|"
    r"less\s+than"
    r")\b"
)

_F5_EXTERNAL_ASSUMPTION_TAG = "[external-assumption"


def classify_body_or_appendix(
    title: str,
    severity: str = "",
    harm_text: str = "",
    verdict: str = "",
) -> tuple[str, str]:
    """Classify a finding as ``"BODY"`` or ``"APPENDIX"`` (recall-safe).

    Returns ``(disposition, reason)``. The consequence signal wins over the
    quality signal, and an unmatched finding defaults to BODY — burying a real
    finding in the appendix is the unacceptable error.

    ``severity`` is accepted for symmetry / future use but does NOT change the
    decision: a Medium / High pure-observability finding still routes to the
    appendix, and a Low / Info finding with a real consequence stays in the
    body. This is exactly the validated policy.
    """
    title = title or ""
    harm_text = harm_text or ""
    blob = f"{title}\n{harm_text}"
    if _HARM_CONSEQUENCE_RE.search(blob):
        return ("BODY", "real security consequence")
    cls = _classify_keyword(blob, _PURE_QUALITY_VOCAB)
    if cls:
        # F5: an [EXTERNAL-ASSUMPTION]-tagged finding that ALSO states a
        # concrete harm is a confirmed mechanism pending external verification
        # (R10), not a hardening note. Override the quality-KEYWORD appendix
        # misroute and keep it in the body. Precedence is explicit: the bare
        # tag WITHOUT a concrete harm falls through to the normal pure-quality
        # APPENDIX path below (prevents hardening-note bloat), so the
        # zero-consequence → appendix floor still wins for pure quality.
        if (
            _F5_EXTERNAL_ASSUMPTION_TAG in blob.lower()
            and _F5_CONCRETE_HARM_RE.search(blob)
        ):
            return ("BODY", "external-assumption with concrete harm (R10)")
        label = _DISPOSITION_CLASS_TITLES.get(cls, cls)
        return ("APPENDIX", f"pure quality/hardening — {label}")
    return ("BODY", "default (recall-safe: no quality-only match)")


_DISPOSITION_ROW_RE = re.compile(
    r"^\|\s*([CHMLI]-\d+)\s*\|\s*(BODY|APPENDIX)\s*\|\s*(.*?)\s*\|?\s*$",
    re.IGNORECASE,
)


def parse_disposition_md(scratchpad: Path) -> dict[str, tuple[str, str]]:
    """Parse ``disposition.md`` into ``{REPORT_ID: (disposition, reason)}``.

    Defensive by construction: a missing or malformed file returns ``{}`` so
    every consumer degrades to current behaviour (everything stays in the
    body). Keys are upper-cased report IDs (``C-01`` …). Disposition is
    normalised to ``BODY`` / ``APPENDIX``; any unrecognised token is treated as
    ``BODY`` (recall-safe).
    """
    p = scratchpad / "disposition.md"
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        m = _DISPOSITION_ROW_RE.match(line.strip())
        if not m:
            continue
        rid = m.group(1).upper()
        disp = m.group(2).upper()
        if disp not in ("BODY", "APPENDIX"):
            disp = "BODY"
        reason = re.sub(r"\s+", " ", m.group(3) or "").strip()
        out[rid] = (disp, reason)
    return out


def _appendix_disposition_report_ids(scratchpad: Path) -> set[str]:
    """Return the set of report IDs dispositioned APPENDIX (upper-cased).

    Empty when ``disposition.md`` is absent/malformed → callers behave exactly
    as before the material-harm floor existed.
    """
    return {
        rid
        for rid, (disp, _reason) in parse_disposition_md(scratchpad).items()
        if disp == "APPENDIX"
    }


_DEDUP_GENERIC_STOP = {
    "the", "a", "an", "in", "on", "at", "to", "for", "of", "and", "or",
    "is", "are", "be", "with", "by", "as", "from", "this", "that",
}


def _dedup_generic_norm(text: str) -> str:
    """Fallback canonical form when no vocabulary token matches."""
    if not text:
        return ""
    tl = re.sub(r"`[^`]*`", " ", text.lower())  # strip code spans
    tl = re.sub(r"\b[a-z][a-zA-Z0-9_]{6,}\b", " ", tl)  # strip long ident-like tokens
    tl = re.sub(r"[^a-z0-9 ]+", " ", tl)
    toks = [t for t in tl.split() if t and t not in _DEDUP_GENERIC_STOP and len(t) > 2]
    return "_".join(toks[:3]) if toks else ""


def _dedup_signature_for_finding(
    text: str,
    severity: str,
    hint_title: str | None = None,
) -> DedupSignature:
    """Compute the dedup signature for a verify_*.md body.

    `hint_title` lets the caller inject the queue-row title when the verify
    file's H1 is just an internal ID like `# INV-001`.
    """
    rec = _field_or_section(
        text,
        ("Recommendation", "Suggested Fix", "Suggested fix", "Fix", "Mitigation"),
        ("Recommendation", "Suggested Fix", "Suggested fix", "Fix", "Mitigation"),
        fallback="",
    )
    title = _first_heading_title(text) or ""
    desc = _field_or_section(
        text,
        ("Description", "Summary", "Root Cause"),
        ("Description", "Summary", "Analysis", "Code Trace", "Root Cause"),
        fallback="",
    )
    parts = [title, desc]
    if hint_title:
        parts.append(hint_title)
    title_blob = " ".join(p for p in parts if p).strip()
    vuln = _classify_keyword(title_blob, _DEDUP_VULN_VOCAB)
    fix = _classify_keyword(rec, _DEDUP_FIX_VOCAB)
    if not vuln:
        vuln = _dedup_generic_norm(title_blob) or "unspecified"
    if not fix:
        fix = _dedup_generic_norm(rec) or "unspecified"
    return DedupSignature(severity=severity, fix_pattern=fix, vuln_class=vuln)


def _detect_dedup_clusters(scratchpad: Path, threshold: int = 3) -> list[dict]:
    """Group active verifications by dedup signature; return clusters >= threshold.

    Returns a list of dicts: {signature: DedupSignature, finding_ids: [...]}.
    Excluded findings (REFUTED / FALSE_POSITIVE) are not clustered.
    """
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []
    by_key: dict[tuple, list[tuple[str, DedupSignature]]] = {}
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        vp = _verify_file_for_id(scratchpad, fid)
        try:
            vtxt = _llm_norm(vp.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            vtxt = ""
        status = _verifier_status_from_text(vtxt)
        if not _is_reportable_verdict(status):
            continue
        severity = _enforce_severity_matrix(vtxt, row)
        unresolved = any(tok in status for tok in ("UNRESOLVED", "PARTIAL"))
        if unresolved:
            severity = _demote_severity_once(severity)
        hint = (row.get("title") or "").strip()
        sig = _dedup_signature_for_finding(vtxt, severity=severity, hint_title=hint)
        by_key.setdefault(sig.key(), []).append((fid, sig))

    clusters: list[dict] = []
    for k, members in by_key.items():
        if len(members) >= threshold:
            clusters.append({
                "signature": members[0][1],
                "finding_ids": [m[0] for m in members],
                "key": k,
            })
    return clusters


def _consolidated_title_for(sig: DedupSignature) -> str:
    """Pick a class-level title for a consolidated finding."""
    return _CLASS_LEVEL_TITLES.get(
        sig.vuln_class.lower(),
        f"{sig.vuln_class.replace('_', ' ').title()} (consolidated)",
    )


# =============================================================================
# Phase D: LLM body writer manifest + post-write validator.
#
# Manifests are emitted per shard from the verified records. They are the
# single source of truth for what the LLM body writer is allowed to produce:
# every report finding has its evidence bound (location, evidence tag, verify
# file, description, recommendation). After the LLM writes its body file the
# driver validates coverage (no missing), no-extras (no hallucinations) and
# evidence integrity (locations match), then halts on any drift.
#
# Findings whose verify file lacks usable Description AND Recommendation are
# tagged `report_blocked` — the body MUST surface a `[REPORT-BLOCKED:` tag in
# the section header so a human reviewer sees the gap instead of placeholder
# prose.
# =============================================================================
_BODY_SHARD_CAPS = {
    "report_critical_high": 15,
    "report_medium": 20,
    "report_low_info": 30,
}


# Body validator -----------------------------------------------------------
# Bracketed report ID like `[M-01]` or `[ m-01 ]` - bounded to prevent
# matching internal IDs like INV-001 or H-1234567.
_BODY_REPORT_ID_RE = re.compile(r"\[\s*([CHMLI])-(\d{1,3})\s*\]", re.IGNORECASE)


def _normalize_report_id(raw: str) -> str:
    m = _BODY_REPORT_ID_RE.fullmatch(f"[{raw.strip()}]")
    if not m:
        return raw.strip().upper()
    return f"{m.group(1).upper()}-{int(m.group(2)):02d}"


def _extract_report_ids_from_body(body: str) -> list[str]:
    """Pull report body IDs from finding headers and Quality rows.

    Header IDs are the normal full-section format. Low/Info cosmetic-only
    findings may also be represented in the prompt-sanctioned
    `## Quality Observations` table, where the first column is the report ID.
    IDs mentioned in prose remain excluded because they are cross-references.
    """
    _HEADER_ID_RE = re.compile(
        r"(?im)^#{1,3}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI])-(\d{1,3})\s*\]"
    )
    found = []
    for m in _HEADER_ID_RE.finditer(body or ""):
        found.append(f"{m.group(1).upper()}-{int(m.group(2)):02d}")
    qo = re.search(r"(?im)^##\s+Quality\s+Observations\b", body or "")
    if qo:
        qo_text = (body or "")[qo.end():]
        end = re.search(r"(?m)^##\s+", qo_text)
        if end:
            qo_text = qo_text[:end.start()]
        for m in re.finditer(r"(?m)^\|\s*([LI])-(\d{1,3})\s*\|", qo_text):
            found.append(f"{m.group(1).upper()}-{int(m.group(2)):02d}")
    return found


def _section_for_report_id(body: str, report_id: str) -> str:
    """Return the slice of body from the report_id heading to the next finding.

    Tolerant to case and whitespace inside the brackets.
    Also tolerates a ``[REPORT-BLOCKED: ...]`` prefix before the report ID
    bracket — the body-writer prompt instructs the LLM to prefix blocked
    findings this way.
    """
    # Match the heading line: `## [REPORT-BLOCKED: ...] [X-NN] ...`
    # or plain `## [X-NN] ...`
    pat = re.compile(
        rf"(?im)^#{{1,3}}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*{re.escape(report_id[0])}-0*{int(report_id.split('-')[1])}\s*\][^\n]*\n",
    )
    m = pat.search(body or "")
    if not m:
        qo = re.search(r"(?im)^##\s+Quality\s+Observations\b", body or "")
        if not qo:
            return ""
        qo_text = (body or "")[qo.end():]
        end = re.search(r"(?m)^##\s+", qo_text)
        if end:
            qo_text = qo_text[:end.start()]
        row_pat = re.compile(
            rf"(?im)^\|\s*{re.escape(report_id[0])}-0*{int(report_id.split('-')[1])}\s*\|[^\n]*$"
        )
        row = row_pat.search(qo_text)
        return row.group(0) if row else ""
    start = m.start()
    # RPT-3: Stop at the next report finding header OR a known STRUCTURAL tier/
    # report heading -- never at an arbitrary `##`. In-finding subheadings like
    # `## Impact` / `## PoC Result` are legitimate (the field extractor supports
    # section-style fields), so terminating on any H2 truncated the finding and
    # produced false "missing substantive Impact/PoC" errors. Cross-finding
    # isolation (X-01 must not borrow X-02's section) is preserved by the
    # next-finding-header branch and the closed structural-heading set.
    end_m = re.search(
        r"(?im)^#{1,2}\s+(?:Critical|High|Medium|Low|Informational|"
        r"Quality\s+Observations|Appendix|Priority\s+Remediation|"
        r"Excluded|Summary)\b"
        r"|^#{3}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*[CHMLI]-\d{1,3}\s*\]",
        (body or "")[m.end():],
    )
    end = m.end() + end_m.start() if end_m else len(body or "")
    return (body or "")[start:end]


_FINDING_BLOCK_RE = re.compile(
    r"^\s*(?:##|###)\s+(?:Finding\s+)?\[?([A-Z][A-Z0-9]{0,6}-\d+)\]?",
    re.MULTILINE,
)


_BRACKETED_ID_RE = re.compile(r"\[([A-Z][A-Z0-9]{0,6}-\d+)\]")


_TABLE_FINDING_ID_RE = re.compile(r"(?im)^\|\s*([A-Z][A-Z0-9]{0,6}-\d+)\s*\|")


_TABLE_SOURCE_ID_RE = re.compile(r"(?im)\b([A-Z][A-Z0-9]{0,6}-\d+)\b")


_TABLE_LOCATION_RE = re.compile(r"([A-Za-z0-9_./\\-]+\.(?:sol|rs|go|move):L?\d+)")


# Site 5 (regex-fragility plan, RECALL-CRITICAL): the non-reportable markers.
# A match forces severity -> Informational and verdict -> REFUTED, so a
# FALSE-fire here silently DEMOTES a real finding. The negation-blind substring
# form wrongly fired on `NOT a duplicate`, `not refuted`, `this is not a false
# positive` — demoting genuine findings. The fix scopes a clause-level negation
# guard to each matched marker: when a negation token (`not`/`no`/`never`/…)
# shares the SAME clause as the marker word, that match is suppressed (it is the
# verifier asserting the finding is NOT non-reportable). Word boundaries already
# prevented `id`!=`invalid`-style false hits; the markers below keep them.
#
# Recall-safety: the guard only ever SUPPRESSES a non-reportable match, i.e. it
# can only KEEP a finding reportable that the old rule would have demoted. It can
# never newly demote a finding the old rule kept. Same direction as the
# `_valid_poc_skip` narrowing — strictly recall-positive.
#
# Each individual marker alternative that itself encodes a negation
# (`not applicable`, `not reportable`, `no finding`) is a TRUE non-reportable
# signal, so its own leading `not`/`no` must NOT trip the guard. We therefore
# strip the marker span before scanning its clause for an OUTSIDE negation.
_NON_REPORTABLE_MARKER_RE = re.compile(
    r"\b(?:refuted|false[_\s-]*positive|infeasible|not\s+applicable|"
    r"absorbed(?:\s+into)?|deduplicated|not\s+reportable|no\s+finding|"
    # Disposition-SENSE only for the two adjective-prone terms. Bare 'duplicate'
    # / 'merged' word-sense (e.g. 'merged-pool', 'duplicate entry') must NOT
    # demote a real finding (recall-safe). Accept: 'duplicate of', 'is/as/marked
    # (a) duplicate', standalone duplicate at field-end/before-ID; 'merged
    # into/with/to/under', 'is/was merged', standalone merged at field-end/before-ID.
    r"duplicate[ds]?\s+of\b|(?:is|as|marked)(?:\s+a)?(?:\s+as)?\s+duplicate\b|"
    r"\bduplicates?\b(?=\s*[.;,)\]]|\s*$|\s+[A-Z]{1,4}-\d)|"
    r"merged\s+(?:in|into|with|to|under)\b|(?:is|was)\s+merged\b|"
    r"\bmerged\b(?=\s*[.;,)\]]|\s*$|\s+[A-Z]{1,4}-\d))",
    re.IGNORECASE,
)


def _non_reportable_marker(text: str) -> bool:
    s = text or ""
    for m in _NON_REPORTABLE_MARKER_RE.finditer(s):
        # Scope the negation check to the marker's own clause, with the marker
        # span itself blanked out so a marker that legitimately contains its own
        # negation (`not applicable`/`not reportable`/`no finding`) is not
        # self-suppressed. Only an EXTERNAL negation governing the marker
        # (e.g. "this is NOT a duplicate") suppresses it.
        clause = _clause_around(s, m.start(), m.end())
        # Blank the marker span inside the clause so a marker that legitimately
        # contains its own negation is not self-suppressed.
        marker_text = m.group(0)
        idx = clause.find(marker_text)
        if idx >= 0:
            masked = clause[:idx] + (" " * len(marker_text)) + clause[idx + len(marker_text):]
        else:
            masked = clause
        if _NEGATION_GUARD_RE.search(masked):
            # An external negation governs this marker -> it is asserting the
            # finding is NOT non-reportable. Suppress this match and keep
            # scanning (another, ungoverned marker may still be present).
            continue
        return True
    return False


def _ambiguous_na_marker(text: str) -> bool:
    return bool(re.fullmatch(
        r"\s*(?:n/?a|not\s+available|unknown)(?:\s*\([^)]*\))?\s*",
        text or "",
        re.IGNORECASE,
    ))


_LOCATION_RE = re.compile(
    r"(?:\*\*)?Location(?:\*\*)?\s*:\s*`?([^\n`]+?)`?\s*$",
    re.MULTILINE | re.IGNORECASE,
)


_SOURCE_IDS_LINE_RE = re.compile(
    r"^\s*[-*]?\s*(?:"
    r"\*\*Source IDs?:\*\*|"
    r"\*\*Source IDs?\*\*\s*:|"
    r"Source IDs?\s*:"
    r")\s*(.+)$",
    re.IGNORECASE,
)


_HEADING_FINDING_RE = re.compile(
    r"^\s*(?:##|###)\s+Finding\b[^\n]*$", re.MULTILINE
)


_INVENTORY_FINDING_HEADING_RE = re.compile(
    r"^\s*###\s+Finding\s+\[[^\]]+\]:", re.MULTILINE
)


_TOTAL_FINDINGS_RE = re.compile(
    r"\*{0,2}Total\s+Findings\*{0,2}\s*:?\*{0,2}\s*[:\|]?\s*(\d+)",
    re.IGNORECASE,
)


def _inventory_blocks(text: str) -> list[dict[str, str]]:
    """Return inventory finding blocks with stable IDs and raw markdown.

    Input is normalized via `_llm_norm` so drift formats (smart quotes,
    em-dash, CRLF, HTML entities, NBSP, zero-width chars) don't fragment
    or hide finding blocks.

    Fence-aware: headings INSIDE triple-backtick or triple-tilde code blocks
    are NOT treated as finding starts. LLM outputs frequently include code
    examples that contain markdown-style headings (e.g., a "before/after"
    sample). Pre-fence-awareness, those got counted as phantom findings.
    """
    text = _llm_norm(text)
    lines = text.splitlines()
    starts: list[tuple[int, str]] = []
    in_fence = False
    fence_marker: str | None = None
    for idx, line in enumerate(lines):
        stripped = line.lstrip()
        # Triple-backtick / triple-tilde fence toggle. Match opening/closing
        # by the same marker char to be permissive about info strings
        # (`'''solidity`, `'''diff`).
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = None
            continue
        if in_fence:
            continue
        if not re.match(r"^\s*#{2,4}\s+", line):
            continue
        fid = _normalize_finding_id(line)
        if fid:
            starts.append((idx, fid))
    out: list[dict[str, str]] = []
    for i, (start, fid) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(lines)
        block = "\n".join(lines[start:end]).strip()
        title = re.sub(r"^\s*#{2,4}\s+", "", lines[start]).strip()
        title = re.sub(r"(?i)^Finding\b\s*", "", title).strip()
        title = re.sub(rf"^\[?\s*{re.escape(fid)}\s*\]?", "", title, flags=re.IGNORECASE).strip()
        title = re.sub(r"^\s*[:=\-–—#]+\s*", "", title).strip()
        out.append({
            "id": fid,
            "title": _strip_md(title),
            "block": block,
            "location": _field_from_markdown(block, ("Location", "Locations")),
            "source_ids": _field_from_markdown(block, ("Source IDs", "Source ID")),
        })
    return out


def _project_source_index(project_root: str) -> dict[str, list[Path]]:
    """Map basename -> source files, excluding build/dependency junk."""
    root = Path(project_root)
    index: dict[str, list[Path]] = {}
    ex_dirs = {
        ".git", "target", "node_modules", ".scratchpad", "artifacts",
        "vendor", "dist", "build", "__pycache__",
    }
    suffixes = {
        ".rs", ".go", ".sol", ".move", ".py", ".c", ".h", ".cpp", ".cc",
        ".hpp", ".ts", ".js", ".jsx", ".tsx",
    }
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in suffixes:
            continue
        rel_parts = set(p.relative_to(root).parts)
        if rel_parts & ex_dirs:
            continue
        index.setdefault(p.name, []).append(p)
    return index


def _is_support_location_path(path: str) -> bool:
    """True for tests/mocks/harnesses that should not be primary locations."""
    p = (path or "").replace("\\", "/").strip().lower()
    if not p:
        return False
    wrapped = f"/{p.lstrip('/')}"
    leaf = p.rsplit("/", 1)[-1]
    markers = (
        "/test/", "/tests/", "/testdata/", "/testing/",
        "/mock/", "/mocks/", "/mocked/",
        "/harness/", "/harnesses/",
        "/fixture/", "/fixtures/",
        "/script/", "/scripts/",
    )
    return (
        any(marker in wrapped for marker in markers)
        or leaf.endswith((".t.sol", ".s.sol", "_test.go", "_tests.rs", ".test.ts", ".spec.ts"))
        or leaf.startswith(("test_", "mock", "stub", "fake"))
        or "harness" in leaf
    )


def _parse_location_ref(location: str) -> tuple[str, int | None]:
    """Extract a path + line from a Location field.

    Closes F-FIELD-01: when multiple paths appear in one Location field
    (e.g., "see foo.rs as background, real bug at bar.rs:L20"), prefer the
    one with an explicit line number — it is almost always the actual
    finding location. Fall back to the first path-only match when no
    annotated path exists.

    Defensive against LLM drift: normalize before parsing.
    """
    location = _llm_norm(location)
    loc = (location or "").strip().strip("`")
    loc = re.sub(r"(?i)\b(?:at|in|file)\s*[:=]\s*", "", loc)
    matches = list(re.finditer(
        r"([A-Za-z0-9_./\\-]+\.(?:cairo|move|hpp|cpp|tsx|jsx|sol|rs|go|py|cc|ts|js|vy|c|h))"
        r"(?![A-Za-z0-9_])(?:\s*(?::L?|#L?|line\s+|L)(\d+))?",
        loc,
        re.IGNORECASE,
    ))
    if not matches:
        return "", None
    production_matches = [
        m for m in matches
        if not _is_support_location_path(m.group(1))
    ]
    search_matches = production_matches or matches
    for m in search_matches:
        if m.group(2):
            return m.group(1).replace("\\", "/"), int(m.group(2))
    m = search_matches[0]
    return m.group(1).replace("\\", "/"), int(m.group(2)) if m.group(2) else None


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return 0


def _resolve_inventory_location(
    project_root: str,
    source_index: dict[str, list[Path]],
    location: str,
) -> tuple[str, str, str]:
    """Return (status, resolved_location, reason)."""
    rel, line = _parse_location_ref(location)
    if not rel:
        return "LOCATION_INVALID", "", "no parseable source path"
    root = Path(project_root)
    cand = root / rel
    if cand.exists() and cand.is_file():
        n = _line_count(cand)
        if line and n and line > n:
            return "LOCATION_INVALID", rel, f"line {line} exceeds file length {n}"
        return "OK", f"{rel}:L{line}" if line else rel, "path exists"
    matches = source_index.get(Path(rel).name, [])
    if len(matches) == 1:
        try:
            new_rel = matches[0].relative_to(root).as_posix()
        except Exception:
            new_rel = str(matches[0]).replace("\\", "/")
        n = _line_count(matches[0])
        if line and n and line > n:
            return "LOCATION_INVALID", new_rel, f"unique basename but line {line} exceeds file length {n}"
        return "RECOVERED_BASENAME", f"{new_rel}:L{line}" if line else new_rel, "unique basename recovery"
    if len(matches) > 1:
        return "LOCATION_AMBIGUOUS", "", f"basename matches {len(matches)} files"
    return "LOCATION_INVALID", "", "file not found"


def _split_source_id_tokens(raw: str) -> list[str]:
    raw = (raw or "").strip()
    raw = raw.strip("[]")
    raw = re.sub(r"(?i)\b(?:Source IDs?|Sources?|Provenance|Origin)\b\s*[:=-]?\s*", "", raw)
    toks = re.split(r",|\n|;|\s+\+\s+|\s+and\s+", raw)
    return [t.strip().strip("`[] ") for t in toks if t.strip().strip("`[] ")]


def _validate_source_token(token: str, scratchpad: Path) -> tuple[str, str]:
    """Validate an inventory Source ID token against scratchpad artifacts."""
    tok = token.strip()
    if not tok:
        return "SOURCE_INVALID", "empty token"
    m = re.match(r"^([A-Za-z0-9_.-]+\.md)(?::|#|::)(.+)$", tok)
    if m:
        p = scratchpad / m.group(1)
        label = m.group(2).strip()
        if not p.exists():
            return "SOURCE_INVALID", f"{m.group(1)} missing"
        try:
            txt = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return "SOURCE_INVALID", f"{m.group(1)} unreadable"
        if label and label in txt:
            return "OK", "file label found"
        # Agents sometimes cite a slug they derived from a finding title
        # rather than a literal anchor. If every slug word appears nearby in
        # the source artifact, treat it as weak but usable provenance.
        words = [
            w.lower() for w in re.split(r"[^A-Za-z0-9]+", label)
            if len(w) >= 4
        ]
        low = txt.lower()
        if words and all(w in low for w in words[:4]):
            return "SOURCE_UNVERIFIED", "slug words found, literal label absent"
        return "SOURCE_INVALID", f"label `{label}` not found in {m.group(1)}"

    # Plain upstream IDs are valid if they occur in any non-inventory artifact.
    norm_id = _normalize_finding_id(tok) or tok
    if re.fullmatch(r"[A-Z][A-Z0-9_-]{0,24}-\d+", norm_id):
        for p in scratchpad.glob("*.md"):
            if p.name.startswith("findings_inventory") or p.name in {
                "verification_queue.md", "report_index.md", "AUDIT_REPORT.md",
            }:
                continue
            try:
                if norm_id in _llm_norm(p.read_text(encoding="utf-8", errors="replace")):
                    return "OK", f"found in {p.name}"
            except Exception:
                continue
        return "SOURCE_UNVERIFIED", "plain ID not found in upstream artifacts"
    # Non-empty free-form provenance should not by itself kill a lead. It is
    # weak evidence, but paired with a real code location it is enough to keep
    # the row in verification.
    return "SOURCE_UNVERIFIED", "free-form source token"


def _replace_inventory_location(text: str, finding_id: str, new_location: str) -> str:
    fid = _normalize_finding_id(finding_id) or finding_id
    lines = text.splitlines()
    starts = [
        i for i, line in enumerate(lines)
        if re.match(r"^\s*#{2,4}\s+", line) and _normalize_finding_id(line) == fid
    ]
    if not starts:
        return text
    start = starts[0]
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if re.match(r"^\s*#{2,4}\s+", lines[i]) and _normalize_finding_id(lines[i]):
            end = i
            break
    loc_re = re.compile(r"^(\s*(?:[-*]\s*)?(?:\*\*)?Location(?:\*\*)?\s*(?::|-|=)\s*)(.*)$", re.IGNORECASE)
    for i in range(start, end):
        m = loc_re.match(lines[i])
        if m:
            lines[i] = m.group(1) + new_location
            return "\n".join(lines) + ("\n" if text.endswith("\n") else "")
    return text


def _extract_finding_signals(text: str) -> tuple[set[str], int]:
    """Return (normalized-ID set, loose-finding-block count).

    Primary signal: explicit bracketed / heading IDs. Secondary signal:
    `## Finding ...` or `### Finding ...` heading blocks with no parseable
    ID attached — still proof that a finding was written. A `**Location**:`
    row is folded into the ID set when no ID regex hit exists for that
    block, so agents that omit the `[XX-N]` prefix still produce a signal.
    """
    ids: set[str] = set()
    for m in _BRACKETED_ID_RE.finditer(text):
        ids.add(m.group(1))
    for m in _FINDING_BLOCK_RE.finditer(text):
        ids.add(m.group(1))
    for line in text.splitlines():
        m = _SOURCE_IDS_LINE_RE.match(line)
        if m:
            for tok in re.findall(r"\b[A-Z][A-Z0-9]{0,6}-\d+\b", m.group(1)):
                ids.add(tok)
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells:
            continue
        if re.fullmatch(r"[A-Z][A-Z0-9]{0,6}-\d+", cells[0]):
            ids.add(cells[0])
        for cell in cells[1:]:
            for m in _TABLE_SOURCE_ID_RE.finditer(cell):
                ids.add(m.group(1))
    blocks = len(_HEADING_FINDING_RE.findall(text)) + len(_TABLE_FINDING_ID_RE.findall(text))
    return ids, blocks


# Phase E14 guardrail: checkpoint-aware sentinel cleanup. Stale `.degraded`
# sentinels from PRIOR aborted runs must not block a fresh start, but
# sentinels for phases the CURRENT checkpoint still marks degraded must be
# preserved — they are the only visible reason the prior process halted.
#
# Decision matrix:
#   sentinel exists,  phase in checkpoint.degraded   -> KEEP (active fault)
#   sentinel exists,  phase in checkpoint.completed  -> CLEAR (stale debris)
#   sentinel exists,  phase in neither               -> CLEAR (orphan from
#                                                       pre-checkpoint abort)
_DEGRADED_SENTINEL_GLOBS = (
    "report_assemble.degraded",
    "report_index.degraded",
    "report_*_body_writer.degraded",
    "*.body_writer.degraded",
    "verify_queue.degraded",
)


def _phase_name_from_sentinel(sentinel_name: str) -> str:
    """Map sentinel filename to the phase name that owns it.

    Examples:
      `report_assemble.degraded` -> `report_assemble`
      `report_critical_high.body_writer.degraded` -> `report_critical_high`
      `verify_queue.degraded` -> `verify_queue`
    """
    name = sentinel_name
    if name.endswith(".degraded"):
        name = name[: -len(".degraded")]
    if name.endswith(".body_writer"):
        name = name[: -len(".body_writer")]
    return name


# Phase E11 follow-up #2: robust finding-ID extraction. Substring search
# false-passes (overlap of unrelated IDs) and false-halts (range syntax,
# markdown-link wrapping). This function returns a normalized set of IDs
# from a free-form text blob, supporting:
#   - Bare IDs:           INV-001
#   - Bracketed IDs:      [INV-001]
#   - Markdown links:     [INV-001](path/to/verify_INV-001.md)
#   - Comma lists:        INV-005, INV-006, INV-007
#   - Range expansion:    INV-001..INV-150  (preserves leading-zero padding)
# Range cap defaults to 10000 to prevent pathological pollution.
_FID_RANGE_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]*)-(\d+)\s*\.\.\s*\1-(\d+)\b",
    re.IGNORECASE,
)


_FID_BARE_RE = re.compile(r"\b([A-Z][A-Z0-9_]*)-(\d+)\b", re.IGNORECASE)


def _extract_finding_ids_from_text(text: str, range_cap: int = 10000) -> set[str]:
    """Extract canonical finding IDs from free-form text.

    Returns a set of `{PREFIX}-{NNNN}` strings using upper-case prefix and
    the original numeric width (preserves leading-zero padding for the
    starting endpoint of a range).
    """
    if not text:
        return set()
    ids: set[str] = set()
    consumed_spans: list[tuple[int, int]] = []
    # Pass 1: range expansion. Consume range-bounded spans so the bare
    # regex on pass 2 doesn't double-count the endpoints.
    for m in _FID_RANGE_RE.finditer(text):
        prefix = m.group(1).upper()
        start = int(m.group(2))
        end = int(m.group(3))
        if end < start:
            start, end = end, start
        # Preserve leading-zero width from the start endpoint.
        width = max(len(m.group(2)), len(m.group(3)))
        n = end - start + 1
        if n > range_cap:
            n = range_cap
            end = start + n - 1
        for i in range(start, end + 1):
            ids.add(f"{prefix}-{i:0{width}d}")
        consumed_spans.append(m.span())

    # Pass 2: bare IDs (skipping consumed range spans).
    for m in _FID_BARE_RE.finditer(text):
        s, e = m.span()
        if any(cs <= s and e <= ce for cs, ce in consumed_spans):
            continue
        prefix = m.group(1).upper()
        # Filter out non-finding patterns: things like `EIP-1234` or
        # `ERC-20` would also match. Use a permissive heuristic: require
        # the prefix to be a typical finding-ID prefix or already seen
        # from a range. Conservative allow-list keeps us close to
        # existing behavior.
        prefix_ok = prefix in _FID_ALLOWED_PREFIXES
        if not prefix_ok:
            continue
        if prefix == "EIP" and len(m.group(2)) > 3:
            continue
        ids.add(f"{prefix}-{m.group(2)}")
    return ids


def _module_key(rel_path: str) -> str:
    """Bucket a repo-relative path into a coverage-module key.

    Uses 2 path segments when the path has 3+ parts (two dirs + file). This
    handles mono-repo layouts where the first segment is a container:

      crates/types/src/lib.rs       -> "crates/types"
      crates/api-client/src/lib.rs  -> "crates/api-client"
      eth/downloader/handler.go     -> "eth/downloader"
      x/staking/keeper/msg.go       -> "x/staking"
      cmd/geth/main.go              -> "cmd/geth"

    Falls back to 1 segment when the path is only 2 parts:

      core/state.go                 -> "core"
      consensus/engine.go           -> "consensus"

    Root-level files bucket as "_root".
    """
    parts = rel_path.split("/")
    if len(parts) >= 3:
        return parts[0] + "/" + parts[1]
    if len(parts) == 2:
        return parts[0]
    return "_root"


def _sc_contract_module_key(rel_path: str) -> str:
    """Bucket SC source paths by contract/program domain."""
    rel = rel_path.replace("\\", "/").lstrip("./")
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return "_root"
    if parts[0] in {"contracts", "src", "sources"}:
        if len(parts) >= 3:
            return parts[0] + "/" + parts[1]
        return parts[0]
    if parts[0] == "programs" and len(parts) >= 2:
        return parts[0] + "/" + parts[1]
    if len(parts) >= 3:
        return parts[0] + "/" + parts[1]
    if len(parts) == 2:
        return parts[0]
    return "_root"


def _normalize_subsystem_scope(scope: str | None) -> str:
    """Normalize a config subsystem scope to a repo-relative POSIX prefix."""
    raw = (scope or "").strip().strip("`\"'")
    if not raw:
        return ""
    raw = raw.replace("\\", "/").lstrip("./")
    return raw.rstrip("/")


def _path_in_subsystem_scope(rel_path: str, scope_prefix: str) -> bool:
    if not scope_prefix:
        return True
    rel = rel_path.replace("\\", "/").lstrip("./").lower()
    pfx = scope_prefix.replace("\\", "/").lstrip("./").lower()
    return rel == pfx or rel.startswith(pfx + "/")


def _load_scope_file_paths(scope_file: str | None) -> set[str]:
    """Parse the wizard's scope file into a set of file identifiers.

    Accepts any of the wizard's documented formats (mirrors the parser in
    `plamen.estimate_cost`):

      - bare paths:        `src/contracts/Vault.sol`
      - markdown tables:   `| MessageRouter.sol | 301 lines |`
      - bullet lists:      `- contracts/Vault.sol`

    Returns a lowercase set containing both each full POSIX-normalised
    relative path AND each bare basename, so coverage gates can match by
    either citation form. Returns an empty set if `scope_file` is empty,
    missing, or unreadable — callers should treat an empty set as
    "no scope file provided, walk everything".

    Used by the recon coverage / subsystem coverage validators to narrow
    the universe of substantial-module-must-be-cited checks when the user
    has explicitly listed audit-scope files. Without this consultation,
    a 200-contract repo with a 5-file scope list still false-trips the
    gate for every uncited bucket.
    """
    if not scope_file:
        return set()
    try:
        if not os.path.isfile(scope_file):
            return set()
    except (OSError, TypeError):
        return set()

    names: set[str] = set()
    try:
        with open(scope_file, "r", encoding="utf-8", errors="ignore") as sf:
            for line in sf:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                for m in re.findall(r"[\w/\\.-]+\.(?:sol|rs|move|go|vy)", line):
                    norm = m.replace("\\", "/").lstrip("./").lower()
                    if norm:
                        names.add(norm)
                        # Also register the bare basename — citations may
                        # appear as `Vault.sol` without a path prefix.
                        bn = norm.rsplit("/", 1)[-1]
                        if bn:
                            names.add(bn)
    except Exception:
        return set()
    return names


def _path_in_scope_file(rel_path: str, scope_names: set[str]) -> bool:
    """Return True when `rel_path` (POSIX, repo-relative) matches a scope
    file entry. Empty `scope_names` means no scope file → match everything."""
    if not scope_names:
        return True
    rel = rel_path.replace("\\", "/").lstrip("./").lower()
    if rel in scope_names:
        return True
    bn = rel.rsplit("/", 1)[-1]
    if bn in scope_names:
        return True
    # Suffix match: scope file says `contracts/Vault.sol`, walker found
    # `src/contracts/Vault.sol`. The reverse (walker found shorter than
    # scope) is also legal — scope `contracts/Vault.sol` should match
    # `contracts/Vault.sol` directly (handled by direct-equality above).
    for n in scope_names:
        if "/" in n and (rel.endswith("/" + n) or n.endswith("/" + rel)):
            return True
    return False


# ===========================================================================
# Artifact marker helpers (Ship 1 of artifact-complete PTY supervision)
# ===========================================================================
#
# Spawned-worker artifacts (analysis_*.md, depth_*_findings.md, niche_*_findings.md,
# verify_*.md, tier writer outputs) carry HTML-comment markers that record the
# write-lifecycle of the file:
#
#   <!-- PLAMEN_ARTIFACT: analysis_access_control.md -->
#   <!-- PLAMEN_OWNER: B3 -->
#   <!-- PLAMEN_STATUS: IN_PROGRESS -->
#   <!-- PLAMEN_PHASE: breadth -->
#   <!-- PLAMEN_VERSION: 1 -->
#   ... body ...
#   <!-- PLAMEN_STATUS: COMPLETE -->
#   <!-- PLAMEN_FINDINGS_COUNT: 7 -->
#
# Helpers in this section are pure (no driver state, no I/O beyond reading the
# given path). Wiring into Phase / gate_passes happens in Ship 3.

# T2-6 (SW15-1): no re.DOTALL. PLAMEN markers are single-line HTML comments;
# with DOTALL a malformed/missing `-->` let the value `(.*?)` swallow the body
# AND the next marker, misclassifying a COMPLETE file as IN_PROGRESS. Bounding
# the value to one line confines the damage of a malformed marker to its line.
_PLAMEN_MARKER_RE = re.compile(
    r"<!--\s*PLAMEN_([A-Z][A-Z0-9_]*)\s*:\s*(.*?)\s*-->",
)


def _strip_fenced_code_blocks(text: str) -> str:
    """Ship 8.18: remove fenced code blocks (``` or ~~~) before PLAMEN-marker
    parsing.

    Prompt/documentation EXAMPLES place marker comments like
    ``<!-- PLAMEN_STATUS: COMPLETE -->`` inside code fences. If an agent echoes
    such an example into its artifact, the marker parser (and legacy-unmarked
    detection) would treat the EXAMPLE as a real status marker -- poisoning the
    last-wins resolution (a fenced COMPLETE could mask a real IN_PROGRESS, or a
    fenced marker could make a genuinely legacy file look fresh-format). Real
    markers an agent writes live in the body, not inside fences, so dropping
    fenced content before parsing is safe and matches intent.
    """
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue  # drop the fence delimiter line itself
        if not in_fence:
            out.append(line)
    return "\n".join(out)

# Site 4 (regex-fragility plan): heading-LEVEL tolerant. The completion gate
# `_structural_completeness_ok` calls `_NO_FINDINGS_HEADING_RE.search` to decide
# whether a complete-marked artifact carries an explicit negative-result
# rationale. The old `^##` H2-exact form false-FAILED a complete artifact that
# rendered the rationale as H1/H3 drift (`# No Findings` / `### No Findings`).
# `#{1,6}` is a strict superset of `##` — every H2 match still matches, and H1
# /H3..H6 drift is newly accepted. Recall-safe: this gate can only now PASS more
# complete artifacts, never fail one it previously passed.
_NO_FINDINGS_HEADING_RE = re.compile(
    r"^#{1,6}\s+.*\b(No\s+Findings|Negative\s+Result)\b",
    re.MULTILINE | re.IGNORECASE,
)

_OBLIGATION_RECEIPTS_HEADING_RE = re.compile(
    r"^##\s+.*\bObligation\s+Receipts\b",
    re.MULTILINE | re.IGNORECASE,
)

# Ship 8.2: an artifact "has findings" if it shows a `## Findings` section
# OR at least one finding block. Finding blocks are `## Finding [ID]`
# (breadth) or `### Finding [ID]` (depth) -- 2 or 3 hashes, then "Finding",
# whitespace, "[". Case-insensitive (review note). The block regex does NOT
# match the `## Findings` section heading ("Findings" has no whitespace+"["
# after "Finding"), so the two regexes are disjoint.
# Ship D: single source of truth in plamen_types (H2/H3, captures the ID).
_FINDING_BLOCK_HEADING_RE = FINDING_BLOCK_HEADING_RE
# Site 4 (regex-fragility plan): heading-LEVEL tolerant `#{1,6}` (strict
# superset of `##`). An agent that renders the findings section as `# Findings`
# or `### Findings` must not false-FAIL the completion gate. `_FINDING_BLOCK_*`
# disjointness is preserved: "Findings\b" still requires the word boundary after
# "Findings", so a `## Finding [ID]` block heading (no trailing 's') never
# collides with this section heading.
_FINDINGS_SECTION_RE = re.compile(
    r"^#{1,6}\s+Findings\b",
    re.MULTILINE | re.IGNORECASE,
)


_FINDINGS_BODY_MIN_CHARS = 15

# Ship D (SW03-1): crash-safety / "to be filled" placeholder bodies that an LLM
# leaves under a `## Findings` heading. Matched substrings are stripped before
# the substance re-check, so they cannot masquerade as completed analysis.
_FINDINGS_PLACEHOLDER_BODY_RE = re.compile(
    r"\(?\s*(?:findings?\s+(?:will\s+be\s+)?appended\b[^)\n]*"
    r"|(?:findings?\s+)?appended\s+below\b[^)\n]*"
    r"|to\s+be\s+(?:filled|added|appended|determined|populated)\b[^)\n]*"
    r"|no\s+findings?\s+(?:yet|recorded\s+yet)\b[^)\n]*"
    r"|placeholder\b[^)\n]*"
    r"|as\s+they\s+are\s+discovered\b[^)\n]*"
    r"|TBD\b|TODO\b)\s*\)?",
    re.IGNORECASE,
)


def _findings_section_has_body(text: str) -> bool:
    """Ship 8.18: True iff a `## Findings` section exists AND has substantive
    body content (>= _FINDINGS_BODY_MIN_CHARS non-whitespace chars between the
    heading and the next `## ` heading / EOF). A BARE `## Findings` shell --
    the heading with nothing under it -- returns False. This closes the hole
    where an empty `## Findings` heading counted as completed work while
    preserving the Ship 8.2 widening (a real `## Findings` section with prose
    still counts, without requiring a `## Finding [` block)."""
    m = _FINDINGS_SECTION_RE.search(text)
    if not m:
        return False
    nl = text.find("\n", m.end())
    if nl == -1:
        return False  # heading is the last line -> no body
    rest = text[nl + 1:]
    nxt = re.search(r"^##\s+\S", rest, re.MULTILINE)
    body = rest[: nxt.start()] if nxt else rest
    if len("".join(body.split())) < _FINDINGS_BODY_MIN_CHARS:
        return False
    # Ship D (SW03-1): reject KNOWN placeholder bodies. The breadth crash-safety
    # stub writes `## Findings\n\n(findings appended below as they are
    # discovered)` (>15 chars), which Ship 8.18's length-only check accepted as
    # real work -> an empty COMPLETE-marked breadth artifact silently passed.
    # Strip placeholder phrases, then re-test substance: a REAL section that
    # merely mentions such a phrase alongside real findings still passes.
    substantive = _FINDINGS_PLACEHOLDER_BODY_RE.sub("", body)
    return len("".join(substantive.split())) >= _FINDINGS_BODY_MIN_CHARS


def _artifact_has_findings(text: str) -> bool:
    """True iff the artifact body shows at least one `## Finding [` /
    `### Finding [` block OR a `## Findings` section WITH substantive body.

    Ship 8.2 findings-present signal (block OR section), tightened by Ship 8.18
    to reject a BARE `## Findings` shell (heading, no body) -- which previously
    counted as completed work."""
    return bool(
        _FINDING_BLOCK_HEADING_RE.search(text)
        or _findings_section_has_body(text)
    )


def _extract_artifact_status(path: Path) -> dict[str, str]:
    """Parse <!-- PLAMEN_* --> comments from `path`.

    Multiple occurrences of the same key collapse to the LAST value
    (final-write-wins semantics: e.g. an IN_PROGRESS line followed by a
    COMPLETE line yields STATUS=COMPLETE).

    Returns an empty dict when the file is missing, unreadable, or contains
    no PLAMEN_* markers. Keys are uppercase without the PLAMEN_ prefix
    (e.g. STATUS, OWNER, FINDINGS_COUNT).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    # Ship 8.18: ignore markers inside fenced code blocks (examples) so a
    # fenced exemplar cannot poison last-wins status resolution.
    text = _strip_fenced_code_blocks(text)
    result: dict[str, str] = {}
    for m in _PLAMEN_MARKER_RE.finditer(text):
        key = m.group(1).strip()
        val = m.group(2).strip()
        # Last occurrence wins because dict overwrite preserves order.
        result[key] = val
    return result


def is_artifact_complete(path: Path, min_bytes: int) -> bool:
    """Return True iff PLAMEN_STATUS == "COMPLETE" AND the file is at
    least `min_bytes` long.

    False when the file is missing, unreadable, below `min_bytes`, lacks a
    PLAMEN_STATUS marker, or has STATUS != COMPLETE. The size guard makes
    COMPLETE necessary but not sufficient — Ship 3 layers structural
    completeness checks on top for the breadth gate.
    """
    try:
        if not path.exists():
            return False
        if path.stat().st_size < min_bytes:
            return False
    except Exception:
        return False
    markers = _extract_artifact_status(path)
    return markers.get("STATUS") == "COMPLETE"


def is_artifact_legacy_unmarked(path: Path) -> bool:
    """Return True iff the file exists with substantive content but
    contains NO ``PLAMEN_*`` comment marker of ANY kind.

    Ship 8.2 (RC2 fix): the prior implementation keyed legacy detection
    off the single ``PLAMEN_ARTIFACT`` marker. That misclassified
    fresh-format files that carry OTHER markers (``PLAMEN_STATUS``,
    ``PLAMEN_FINDINGS_COUNT``, agent-improvised ``PLAMEN_AGENT`` /
    ``PLAMEN_FOCUS``) but happen to omit ``PLAMEN_ARTIFACT`` -- on a
    fresh audit those were wrongly routed to IN_PROGRESS and halted the
    breadth phase (observed in a prior run). A file with any PLAMEN marker is a
    fresh-format file; its completion is judged by status + structure,
    not by legacy detection.

    Uses the canonical ``_PLAMEN_MARKER_RE`` (the same comment-form regex
    ``_extract_artifact_status`` uses) so "has a PLAMEN marker" means the
    same thing across the codebase: a marker the parser cannot see is a
    marker that does not exist. A prose mention of a marker name does NOT
    match -- the regex requires the full ``<!-- PLAMEN_X: ... -->`` comment.

    Legacy/pre-marker artifacts (genuinely no markers) are still detected
    and tolerated on resumed scratchpads with a warning log.
    """
    try:
        if not path.exists() or path.stat().st_size == 0:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    # Ship 8.18: a marker that only appears inside a fenced example does not
    # make a file "fresh-format" -- strip fences before deciding legacy status.
    text = _strip_fenced_code_blocks(text)
    return not bool(_PLAMEN_MARKER_RE.search(text))


def _structural_completeness_ok(
    path: Path,
    *,
    required_headings: tuple[str, ...] | list[str] = (),
    require_findings_count_marker: bool = False,
    placeholder_strings: tuple[str, ...] | list[str] = (),
    require_obligation_receipts_if_shard_exists: Optional[Path] = None,
) -> tuple[bool, list[str]]:
    """Run structural completeness checks against `path` and return
    `(ok, reasons)` where `ok` is True only when every applicable check
    passes. ANY entry in `reasons` hard-fails the artifact -- there is no
    such thing as a "soft warning reason" here.

    Ship 8.2 reduces the contract to its semantic minimum so the gate
    accepts genuinely-complete work without demanding ceremonial marker
    schemas that real agents reproduce inconsistently:

    - required_headings: each entry must appear as a `## ` heading.
      Retained for callers that genuinely need a specific heading;
      breadth/depth now pass `()` and rely on the findings rule below.
    - FINDINGS RULE (replaces the old literal-`## Findings` requirement
      AND the FINDINGS_COUNT==0 branch): the artifact must EITHER show
      findings (`## Findings` section OR >=1 `## Finding [` / `### Finding [`
      block) OR carry an explicit `## No Findings` / `## Negative Result`
      rationale. An artifact with neither is empty/incomplete.
    - placeholder_strings: none of these substrings may remain at COMPLETE
      time (still rejects TODO:/FILL_ME/<placeholder>).

    COMPATIBILITY NO-OPS (Ship 8.2): the following parameters are retained
    ONLY for signature/test stability and have NO effect on the verdict.
    They MUST NOT append any reason (reasons hard-fail):
    - require_findings_count_marker: PLAMEN_FINDINGS_COUNT is now
      informational metadata; the findings decision uses block detection,
      not the count. Passing True changes nothing. (Removing the hard
      requirement eliminates the attempt-1 wasted retry the canonical
      worker files hit when they omitted the count.)
    - require_obligation_receipts_if_shard_exists: receipt coverage is
      owned solely by `_check_opengrep_obligation_coverage` (warning-only,
      non-blocking). A missing `## Obligation Receipts` section MUST NOT
      hard-fail the artifact gate. Passing a shard path changes nothing.

    The return shape `(ok, reasons)` lets the caller surface every failure
    reason in the gate's detail string at once.
    """
    # require_findings_count_marker and require_obligation_receipts_if_shard_exists
    # are intentionally unused (compatibility no-ops -- see docstring).
    _ = (require_findings_count_marker, require_obligation_receipts_if_shard_exists)

    reasons: list[str] = []

    try:
        if not path.exists():
            return False, ["file missing"]
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - I/O failure path
        return False, [f"file unreadable: {exc}"]

    for heading in required_headings:
        pattern = re.compile(
            r"^##\s+" + re.escape(heading) + r"\b",
            re.MULTILINE | re.IGNORECASE,
        )
        if not pattern.search(text):
            reasons.append(f"missing required heading: ## {heading}")

    # Placeholder check distinguishes an LLM-LEFT-BLANK from a CITATION of the
    # audited source. Word-markers like TODO/FIXME/XXX/TBD appear legitimately in
    # real code comments (`// TODO: make configurable`) and in finding prose that
    # quotes or discusses them — that is good analysis, not an unfilled blank.
    # (A multi-hour run stalled because a worker correctly cited a Solidity
    # `// TODO:` source comment as evidence.) So: (1) strip fenced + inline code
    # spans (source citations) before matching, and (2) for word-markers, only
    # flag a LEFT-BLANK shape — the marker at the start of a line or as a field
    # value (`**Field**: TODO`) — never a mid-sentence mention. Unambiguous
    # markers (FILL_ME / <placeholder> / [LLM TO ENRICH]) stay a plain substring.
    _prose = re.sub(r"`[^`\n]*`", " ",
                    re.sub(r"```.*?```", " ", text, flags=re.S))
    _word_markers = {"TODO", "FIXME", "XXX", "TBD"}
    for placeholder in placeholder_strings:
        if not placeholder:
            continue
        norm = placeholder.rstrip(":").strip()
        if norm.upper() in _word_markers:
            hit = bool(re.search(
                r"(?:^|\n)[ \t>*\-]*(?:\*\*[^*\n]+\*\*\s*:?\s*)?"
                + re.escape(norm) + r"\b", _prose, re.IGNORECASE))
        else:
            hit = placeholder in _prose
        if hit:
            reasons.append(f"unresolved placeholder string present: {placeholder!r}")

    # Findings rule: has findings OR an explicit no-findings rationale.
    if not _artifact_has_findings(text) and not _NO_FINDINGS_HEADING_RE.search(text):
        reasons.append(
            "no '## Finding [' / '### Finding [' blocks (and no "
            "'## Findings' section) and no '## No Findings' / "
            "'## Negative Result' rationale -- artifact is empty/incomplete"
        )

    return (len(reasons) == 0, reasons)
