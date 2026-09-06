"""Mechanical extraction of plamen_driver.py into 5 modules.

Reads plamen_driver.py, assigns every top-level definition to a target
module based on a hardcoded mapping, and writes:
  - plamen_parsers.py   (Layer 1: imports plamen_types)
  - plamen_validators.py (Layer 2: imports plamen_types + plamen_parsers)
  - plamen_mechanical.py (Layer 2: imports plamen_types + plamen_parsers)
  - plamen_prompt.py     (Layer 2: imports plamen_types + plamen_parsers)
  - plamen_driver.py     (Layer 3: slim, imports all + re-exports)

Usage: python modularize.py [--dry-run]
"""

import ast
import shutil
import sys
from pathlib import Path

DRIVER = Path(__file__).parent / "plamen_driver.py"
BACKUP = Path(__file__).parent / "plamen_driver_monolith.py"

# ── Module assignment: function/class/const name → target module ──
# "types"      = already extracted (plamen_types.py), skip
# "parsers"    = plamen_parsers.py
# "validators" = plamen_validators.py
# "mechanical" = plamen_mechanical.py
# "prompt"     = plamen_prompt.py
# "driver"     = stays in plamen_driver.py (slim)

ASSIGNMENT = {
    # ═══════════════════════════════════════════════════════════════
    # Layer 0: plamen_types.py (ALREADY EXTRACTED — skip these)
    # ═══════════════════════════════════════════════════════════════
    "_resolve_claude_bin": "types",
    "CLAUDE_BIN": "types",
    "PLAMEN_OPUS_MODEL": "types",
    "_resolve_model_alias": "types",
    "EXIT_SUCCESS": "types",
    "EXIT_ERROR": "types",
    "EXIT_RATE_LIMITED": "types",
    "EXIT_DEGRADED": "types",
    "EXIT_CONFIG_MISSING": "types",
    "EXIT_STARTUP_DECISION": "types",
    "EXIT_HIBERNATING": "types",
    "log": "types",
    "_NEVER_CUT_SKIP_REASONS": "types",
    "L1_NEVER_CUT_ARTIFACT_GROUPS": "types",
    "SC_NEVER_CUT_BASE": "types",
    "SC_NEVER_CUT_CORE_EXTRAS": "types",
    "SC_NEVER_CUT_THOROUGH_EXTRAS": "types",
    "sc_never_cut_groups": "types",
    "L1_VERIFY_SHARD_MANIFESTS": "types",
    "L1_VERIFY_PHASE_NAMES": "types",
    "L1_VERIFY_CRITHIGH_PHASE_NAMES": "types",
    "Phase": "types",
    "phase_model": "types",
    "Checkpoint": "types",
    "_VALID_PIPELINES": "types",
    "_VALID_MODES": "types",
    "_PHASE_NAME_RE": "types",
    "validate_phase_graph": "types",
    "SC_PHASES": "types",
    "L1_PHASES": "types",

    # ═══════════════════════════════════════════════════════════════
    # Layer 1: plamen_parsers.py — pure parsing, no file I/O side effects
    # ═══════════════════════════════════════════════════════════════
    # Severity regex
    "_SEVERITY_RE": "parsers",

    # Breadth/depth/report-index manifest parsing
    "parse_breadth_manifest_count": "parsers",
    "_count_markdown_table_rows": "parsers",
    "parse_depth_manifest_count": "parsers",
    "parse_report_index_counts": "parsers",
    "_parse_markdown_table": "parsers",

    # Verification queue parsing
    "_QUEUE_HEADER_ALIASES": "parsers",
    "_FINDING_ID_EXTRACT_RE": "parsers",
    "_normalize_finding_id": "parsers",
    "_match_canonical_header": "parsers",
    "parse_verification_queue_rows": "parsers",
    "_severity_bucket": "parsers",
    "compute_verify_shards": "parsers",
    "_write_queue_subset_manifest": "parsers",
    "ensure_verify_shard_manifests": "parsers",
    "_queue_rows_from_inventory": "parsers",
    "_write_mechanical_verification_queue_from_inventory": "parsers",

    # Report index parsing
    "_INTERNAL_ID_RE": "parsers",
    "_REPORT_BULLET_RE": "parsers",
    "_parse_report_index_table": "parsers",
    "_report_index_reportable_text": "parsers",
    "_parse_report_index_bullets": "parsers",
    "parse_report_index_assignments": "parsers",
    "_parse_report_index_summary_counts": "parsers",

    # Tier assignments / skeptic downgrade
    "_SKEPTIC_DOWNGRADE_RE": "parsers",
    "derive_tier_assignments_from_verify_queue": "parsers",
    "get_tier_assignments": "parsers",
    "compute_report_medium_shards": "parsers",
    "ensure_report_medium_shards": "parsers",
    "merge_report_medium_shards": "parsers",

    # Text extraction utilities
    "_extract_h2_section": "parsers",
    "_LLM_NORM_TABLE": "parsers",
    "_HTML_ENTITY_RE": "parsers",
    "_HTML_ENTITY_MAP": "parsers",
    "_llm_norm": "parsers",
    "_field_from_markdown": "parsers",
    "_first_heading_title": "parsers",
    "_sanitize_client_title": "parsers",
    "_CLIENT_BODY_INTERNAL_ID_RE": "parsers",
    "_sanitize_client_body": "parsers",
    "_markdown_section": "parsers",
    "_field_or_section": "parsers",

    # Severity/verdict handling
    "_verifier_status_from_text": "parsers",
    "_severity_name_from_text": "parsers",
    "_report_prefix_for_severity": "parsers",
    "_verify_file_for_id": "parsers",
    "_next_report_id_counters": "parsers",
    "_find_report_index_cut_for_active_recovery": "parsers",
    "_is_reportable_verdict": "parsers",
    "_demote_severity_once": "parsers",
    "_MATRIX_IMPACT_LABELS": "parsers",
    "_MATRIX_LIKELIHOOD_LABELS": "parsers",
    "_normalize_matrix_label": "parsers",
    "_compute_matrix_severity": "parsers",
    "_apply_severity_modifiers": "parsers",
    "_MATRIX_IMPACT_RE": "parsers",
    "_MATRIX_LIKELIHOOD_RE": "parsers",
    "_MATRIX_TRUST_FULLY_RE": "parsers",
    "_MATRIX_VIEW_FN_RE": "parsers",
    "_MATRIX_ONCHAIN_RE": "parsers",
    "_extract_severity_inputs": "parsers",
    "_enforce_severity_matrix": "parsers",

    # Dedup signature
    "DedupSignature": "parsers",
    "_classify_keyword": "parsers",
    "_DEDUP_VULN_VOCAB": "parsers",
    "_DEDUP_FIX_VOCAB": "parsers",
    "_CLASS_LEVEL_TITLES": "parsers",
    "_DEDUP_GENERIC_STOP": "parsers",
    "_dedup_generic_norm": "parsers",
    "_dedup_signature_for_finding": "parsers",
    "_detect_dedup_clusters": "parsers",
    "_consolidated_title_for": "parsers",

    # Inventory block parsing
    "_SEVERITY_ORDER": "parsers",
    "_SEVERITY_CODE": "parsers",
    "_strip_md": "parsers",
    "_norm_loc": "parsers",
    "_norm_key": "parsers",
    "_extract_ids_from_text": "parsers",
    "_extract_first_tag": "parsers",
    "_parse_source_findings_for_ids": "parsers",
    "_parse_chunk_heading_inventory": "parsers",
    "_parse_chunk_table_inventory": "parsers",
    "_parse_inventory_chunk": "parsers",
    "_severity_rank": "parsers",
    "_merge_inventory_entries": "parsers",

    # Finding ID extraction
    "_FID_RANGE_RE": "parsers",
    "_FID_BARE_RE": "parsers",
    "_extract_finding_ids_from_text": "parsers",

    # Finding block regexes & parsing for location/evidence
    "_FINDING_BLOCK_RE": "parsers",
    "_BRACKETED_ID_RE": "parsers",
    "_TABLE_FINDING_ID_RE": "parsers",
    "_TABLE_SOURCE_ID_RE": "parsers",
    "_TABLE_LOCATION_RE": "parsers",
    "_LOCATION_RE": "parsers",
    "_SOURCE_IDS_LINE_RE": "parsers",
    "_HEADING_FINDING_RE": "parsers",
    "_INVENTORY_FINDING_HEADING_RE": "parsers",
    "_TOTAL_FINDINGS_RE": "parsers",
    "_inventory_blocks": "parsers",
    "_parse_location_ref": "parsers",
    "_line_count": "parsers",
    "_split_source_id_tokens": "parsers",

    # Body writer parsing
    "_BODY_SHARD_CAPS": "parsers",
    "_BODY_REPORT_ID_RE": "parsers",
    "_normalize_report_id": "parsers",
    "_extract_report_ids_from_body": "parsers",
    "_section_for_report_id": "parsers",

    # Depth file parsing
    "_DEPTH_PROMOTION_FILES": "parsers",
    "_PROMOTABLE_FEEDER_ID_PATTERN": "parsers",
    "_parse_depth_confidence_scores": "parsers",
    "_parse_depth_finding_blocks": "parsers",

    # Verify verdict parsing
    "_VERIFY_CONFIRMED_VERDICT_RE": "parsers",
    "_INTERNAL_FINDING_ID_RE": "parsers",

    # Step trace parsing
    "_STEP_TRACE_GLOB": "parsers",
    "_parse_step_trace_rows": "parsers",
    "_aggregate_step_execution_gaps": "parsers",
    "_expected_depth_agent_roles": "parsers",
    "_DEPTH_EVIDENCE_TAG_RE": "parsers",

    # Notread parsing
    "_NOTREAD_FINDING_GLOBS": "parsers",
    "_PATH_CELL_EXTENSIONS": "parsers",
    "_UNCOVERED_STATUS_TOKENS": "parsers",
    "_COVERED_STATUS_TOKENS": "parsers",
    "_is_path_cell": "parsers",
    "_parse_notread_files": "parsers",
    "_parse_uncovered_from_ledger": "parsers",

    # Degraded sentinel parsing
    "_DEGRADED_SENTINEL_GLOBS": "parsers",
    "_phase_name_from_sentinel": "parsers",

    # Scope/module key parsing
    "_module_key": "parsers",
    "_sc_contract_module_key": "parsers",

    # Scope leftover whitelist
    "_SCOPE_LEFTOVER_LIB_WHITELIST": "parsers",
    "_is_whitelisted_lib_path": "parsers",

    # SCIP/coverage constants
    "_SCIP_REPO_MAP_FILES": "parsers",
    "_FINDING_GLOBS_FOR_CITATION": "parsers",

    # ═══════════════════════════════════════════════════════════════
    # Layer 2: plamen_validators.py — validation functions (read files, return issues)
    # ═══════════════════════════════════════════════════════════════
    "is_verification_queue_empty": "validators",
    "write_empty_verify_placeholders": "validators",
    "gate_passes": "validators",
    "_validate_verification_queue_inventory_parity": "validators",
    "_snapshot_file_state": "validators",
    "_owned_artifact_patterns": "validators",
    "_matches_any_pattern": "validators",
    "_detect_foreign_phase_writes": "validators",
    "_validate_verify_completion": "validators",
    "_promote_depth_findings_to_inventory": "validators",
    "_validate_depth_promotion_receipt": "validators",
    "_validate_report_tier_completeness": "validators",
    "_scan_for_halt_and_gatefail": "validators",
    "_NEVER_CUT_FILENAME_ALIASES": "validators",
    "_normalize_never_cut_filenames": "validators",
    "_assert_never_cut_artifacts": "validators",
    "_match_label_status": "validators",
    "_assert_never_cut_checkpoint": "validators",
    "_validate_depth_iterations": "validators",
    "_validate_depth_coverage": "validators",
    "_collect_scip_indexed_paths": "validators",
    "_collect_cited_paths": "validators",
    "_basenames": "validators",
    "_compute_scip_coverage_sets": "validators",
    "_materialize_sc_slither_flat_files": "validators",
    "_compute_subsystem_coverage_gap": "validators",
    "_parse_subsystem_coverage_gap": "validators",
    "_write_final_subsystem_coverage_summary": "validators",
    "_panic_sites_available": "validators",
    "_scip_text_contains_any": "validators",
    "_primitive_sweep_relevant": "validators",
    "_field_validation_sweep_relevant": "validators",
    "_network_amplification_sweep_relevant": "validators",
    "_lifecycle_replay_sweep_relevant": "validators",
    "_graph_sweeps_needed": "validators",
    "_write_graph_sweeps_skip": "validators",
    "_validate_graph_sweeps": "validators",
    "_validate_attention_repair": "validators",
    "_validate_cited_paths_in_verify": "validators",
    "_synthesize_step_execution_trace": "validators",
    "_step_trace_has_ceremonial_yes": "validators",
    "_ensure_step_execution_traces": "validators",
    "_check_step_execution_traces": "validators",
    "_check_notread_priority_coverage": "validators",
    "_validate_rc_parity": "validators",
    "_canonicalize_summary_table": "validators",
    "_collect_verify_promotion_receipts": "validators",
    "_collect_report_promoted_ids": "validators",
    "_ensure_report_consolidation_map": "validators",
    "_check_promotion_symmetry": "validators",
    "_collect_verify_hypothesis_ids": "validators",
    "_collect_index_acknowledged_ids": "validators",
    "_check_index_completeness": "validators",
    "_repair_report_index_dropouts": "validators",
    "_validate_report_body": "validators",
    "_maybe_skip_empty_body_writer": "validators",
    "_generate_body_writer_retry_hint": "validators",
    "_validate_tier_body_against_manifest": "validators",
    "_collect_judge_unresolved_ids": "validators",
    "_collect_body_unresolved_report_ids": "validators",
    "_check_unresolved_authenticity": "validators",
    "_run_report_quality_gate": "validators",
    "_validate_crossbatch_full_coverage": "validators",
    "_validate_skeptic_full_ch_coverage": "validators",
    "_validate_assemble_not_degraded": "validators",
    "_validate_verify_evidence_tags": "validators",
    "_validate_inventory_structure": "validators",
    "_validate_sc_subsystem_coverage": "validators",
    "_normalize_subsystem_scope": "parsers",
    "_path_in_subsystem_scope": "parsers",
    "_validate_recon_coverage": "validators",
    "_validate_scope_leftover": "validators",
    "_validate_depth_exit": "validators",
    "_validate_inventory_parity": "validators",
    "_verify_file_present_for_id": "validators",
    "_validate_verify_files_for_queue": "validators",
    "_validate_report_index_inputs": "validators",
    "_is_evidence_missing_for_body": "validators",
    "_validate_inventory_evidence": "validators",
    "_parse_inventory_evidence_validation": "validators",
    "_filter_verification_queue_by_evidence": "validators",
    "_validate_crossbatch_quality": "validators",
    "_validate_skeptic_scope": "validators",
    "_validate_verify_content_quality": "validators",

    # Retry hint generators (validators produce these)
    "_RETRY_HINT_SUFFIX": "validators",
    "_write_retry_hint": "validators",
    "_read_retry_hint": "validators",
    "_clear_retry_hint": "validators",
    "_compute_tier_completeness_delta": "validators",
    "_compute_assemble_count_delta": "validators",
    "_generate_tier_retry_hint": "validators",
    "_generate_assemble_retry_hint": "validators",
    "_generate_recon_retry_hint": "validators",
    "_write_promotion_dropout_retry_hint": "validators",
    "_generate_crossbatch_retry_hint": "validators",
    "_generate_verify_aggregate_retry_hint": "validators",
    "_generate_graph_sweeps_retry_hint": "validators",
    "_generate_attention_repair_retry_hint": "validators",
    "_generate_inventory_retry_hint": "validators",
    "_generate_verify_queue_retry_hint": "validators",
    "_generate_depth_retry_hint": "validators",
    "_generate_report_index_retry_hint": "validators",
    "_generate_verify_shard_retry_hint": "validators",
    "_generate_verify_core_if_missing": "validators",
    "_skeptic_expected_findings": "validators",
    "_write_skeptic_manifest": "validators",
    "_generate_skeptic_retry_hint": "validators",
    "_sync_degraded_sentinels_to_checkpoint": "validators",
    "_clear_stale_degraded_sentinels": "validators",
    "_snapshot_report_timestamped": "validators",

    # Quarantine
    "_QUARANTINE_PATTERNS_BY_PHASE": "validators",
    "_RETRY_QUARANTINE_EXTRAS": "validators",
    "_quarantine_phase_overreach": "validators",
    "_quarantine_stale_on_retry": "validators",
    "_restore_quarantined_on_retry_failure": "validators",
    "_cleanup_quarantine_backups": "validators",
    "_quarantine_foreign_phase_writes": "validators",
    "_quarantine_report_without_completed_assemble": "validators",
    "_rewind_completed_after_overflow": "validators",

    # ═══════════════════════════════════════════════════════════════
    # Layer 2: plamen_mechanical.py — file writing, synthesis, assembly
    # ═══════════════════════════════════════════════════════════════
    "_synth_report_section_from_verify": "mechanical",
    "_repair_report_body_from_assignments": "mechanical",
    "_assemble_report_python": "mechanical",
    "_inventory_source_files": "mechanical",
    "_count_inventory_source_signals": "mechanical",
    "ensure_inventory_shard_plan": "mechanical",
    "parse_inventory_shard_manifest": "parsers",
    "write_inventory_chunk_placeholder": "mechanical",
    "_write_mechanical_inventory_from_chunks": "mechanical",
    "_synthesize_components_audited": "mechanical",
    "_normalize_breadth_outputs": "mechanical",
    "_write_mechanical_report_index": "mechanical",
    "_shard_name_for_severity": "mechanical",
    "_build_body_writer_manifests": "mechanical",
    "_write_mechanical_report_tier": "mechanical",
    # Attention repair
    "_ATTENTION_REPAIR_MAX_ITEMS": "mechanical",
    "_path_security_weight": "mechanical",
    "_extract_gap_paths_from_markdown": "parsers",
    "_extract_graph_attention_rows": "mechanical",
    "_build_attention_repair_items": "mechanical",
    "_write_attention_repair_queue": "mechanical",
    "_write_attention_repair_skip": "mechanical",
    "_prepare_attention_repair": "mechanical",
    # Hibernation
    "estimate_rate_limit_wait_seconds": "mechanical",
    "write_hibernation_marker": "mechanical",
    "hibernation_disabled": "mechanical",
    "maybe_resume_hibernation": "mechanical",
    "maybe_hibernate_on_rate_limit": "mechanical",
    "write_report_tier_placeholder": "mechanical",
    # Location/evidence
    "_project_source_index": "parsers",
    "_resolve_inventory_location": "parsers",
    "_validate_source_token": "parsers",
    "_replace_inventory_location": "parsers",
    "_write_location_recovery_skip": "mechanical",
    "_location_recovery_needed": "mechanical",
    "_apply_location_recovery": "mechanical",
    "_extract_finding_signals": "parsers",

    # ═══════════════════════════════════════════════════════════════
    # Layer 2: plamen_prompt.py — prompt building
    # ═══════════════════════════════════════════════════════════════
    "resolve_v1_prompt": "prompt",
    "_SECTION_HEADER_RE": "prompt",
    "extract_phase_sections": "prompt",
    "_prune_l1_verify_shard_prompt": "prompt",
    "count_loc": "prompt",
    "scale_timeout": "prompt",
    "_render_expected_output_block": "prompt",
    "_LEGITIMATE_SUBPRODUCER_PATTERNS": "prompt",
    "_glob_to_regex": "prompt",
    "_check_prompt_name_consistency": "prompt",
    "build_phase_prompt": "prompt",

    # ═══════════════════════════════════════════════════════════════
    # Layer 3: plamen_driver.py (slim) — subprocess, main loop, phase runners
    # ═══════════════════════════════════════════════════════════════
    "_API_RATE_LIMIT_STATUSES": "driver",
    "_STRUCTURED_RATE_LIMIT_RE": "driver",
    "_record_phase_cost": "driver",
    "_extract_json_envelope": "driver",
    "detect_rate_limit": "driver",
    "run_phase": "driver",
    "print_pause_message": "driver",
    "_run_phase_validators": "driver",
    "main": "driver",
}


def get_source_items(source: str):
    """Parse source and return list of (kind, name, start_line, end_line)."""
    tree = ast.parse(source)
    items = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            items.append(("func", node.name, node.lineno, node.end_lineno))
        elif isinstance(node, ast.ClassDef):
            items.append(("class", node.name, node.lineno, node.end_lineno))
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    items.append(("const", t.id, node.lineno, node.end_lineno))
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name):
                items.append(("const", node.target.id, node.lineno, node.end_lineno))
    return items


def extract_block(lines: list[str], start: int, end: int) -> str:
    """Extract lines[start-1:end] (1-indexed)."""
    return "\n".join(lines[start - 1 : end])


def main():
    dry_run = "--dry-run" in sys.argv

    # Always read from monolith backup if it exists (re-runnable)
    read_from = BACKUP if BACKUP.exists() else DRIVER
    source = read_from.read_text(encoding="utf-8")
    lines = source.splitlines()
    items = get_source_items(source)

    # Verify all items are assigned
    unassigned = []
    for kind, name, start, end in items:
        if name not in ASSIGNMENT:
            unassigned.append(f"  {kind:6s} {start:6d}-{end:6d} {name}")
    if unassigned:
        print(f"ERROR: {len(unassigned)} unassigned items:")
        for u in unassigned:
            print(u)
        sys.exit(1)

    # Group items by target module
    modules = {"parsers": [], "validators": [], "mechanical": [], "prompt": [], "driver": []}
    skipped_types = 0
    for kind, name, start, end in items:
        target = ASSIGNMENT[name]
        if target == "types":
            skipped_types += 1
            continue
        modules[target].append((kind, name, start, end))

    print(f"Items: {len(items)} total, {skipped_types} in types (skip), "
          f"{sum(len(v) for v in modules.values())} to extract")
    for mod, mod_items in modules.items():
        total_lines = sum(e - s + 1 for _, _, s, e in mod_items)
        print(f"  {mod:12s}: {len(mod_items):3d} items, ~{total_lines:5d} lines")

    if dry_run:
        print("\n--dry-run: not writing files")
        return

    # ── Extract and write each module ──

    # Shared import header for all modules
    STDLIB_IMPORTS = '''\
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
'''

    # Module-specific import blocks
    MODULE_IMPORTS = {
        "parsers": f"""{STDLIB_IMPORTS}
from plamen_types import (
    Phase, Checkpoint, SC_PHASES, L1_PHASES, log,
    L1_VERIFY_SHARD_MANIFESTS, L1_VERIFY_PHASE_NAMES,
    L1_VERIFY_CRITHIGH_PHASE_NAMES,
    _VALID_PIPELINES, _VALID_MODES,
)
""",
        "validators": f"""{STDLIB_IMPORTS}
from plamen_types import (
    Phase, Checkpoint, SC_PHASES, L1_PHASES, log,
    L1_NEVER_CUT_ARTIFACT_GROUPS,
    SC_NEVER_CUT_BASE, SC_NEVER_CUT_CORE_EXTRAS, SC_NEVER_CUT_THOROUGH_EXTRAS,
    sc_never_cut_groups, _NEVER_CUT_SKIP_REASONS,
    L1_VERIFY_SHARD_MANIFESTS, L1_VERIFY_PHASE_NAMES,
    L1_VERIFY_CRITHIGH_PHASE_NAMES,
    _VALID_PIPELINES, _VALID_MODES,
)
from plamen_parsers import *  # noqa: F403,F401
""",
        "mechanical": f"""{STDLIB_IMPORTS}
from plamen_types import *  # noqa: F403,F401
from plamen_parsers import *  # noqa: F403,F401
from plamen_validators import *  # noqa: F403,F401
""",
        "prompt": f"""{STDLIB_IMPORTS}
from plamen_types import *  # noqa: F403,F401
from plamen_parsers import *  # noqa: F403,F401
from plamen_validators import *  # noqa: F403,F401
""",
    }

    for mod_name, mod_items in modules.items():
        if mod_name == "driver":
            continue  # driver written separately

        mod_items_sorted = sorted(mod_items, key=lambda x: x[2])
        body_parts = []
        for kind, name, start, end in mod_items_sorted:
            block = extract_block(lines, start, end)
            # Grab any comment lines immediately above the definition
            prefix_lines = []
            check_line = start - 2  # 0-indexed
            while check_line >= 0:
                ln = lines[check_line].strip()
                if ln.startswith("#") and not ln.startswith("#!"):
                    prefix_lines.insert(0, lines[check_line])
                    check_line -= 1
                elif ln == "":
                    check_line -= 1
                else:
                    break
            if prefix_lines:
                block = "\n".join(prefix_lines) + "\n" + block
            body_parts.append(block)

        header = MODULE_IMPORTS[mod_name]

        # Build __all__ from the items assigned to this module
        all_names = sorted(set(n for _, n, _, _ in mod_items_sorted))
        all_block = "__all__ = [\n" + "".join(f'    "{n}",\n' for n in all_names) + "]\n"

        content = header + "\n" + all_block + "\n\n" + "\n\n\n".join(body_parts) + "\n"

        out_path = DRIVER.parent / f"plamen_{mod_name}.py"
        out_path.write_text(content, encoding="utf-8")
        print(f"Wrote {out_path.name}: {len(content):,d} bytes")

    # ── Write slim driver ──
    # Backup monolith first
    if not BACKUP.exists():
        shutil.copy2(DRIVER, BACKUP)
        print(f"Backed up monolith to {BACKUP.name}")

    driver_items = sorted(modules["driver"], key=lambda x: x[2])
    driver_body_parts = []
    for kind, name, start, end in driver_items:
        block = extract_block(lines, start, end)
        prefix_lines = []
        check_line = start - 2
        while check_line >= 0:
            ln = lines[check_line].strip()
            if ln.startswith("#") and not ln.startswith("#!"):
                prefix_lines.insert(0, lines[check_line])
                check_line -= 1
            elif ln == "":
                check_line -= 1
            else:
                break
        if prefix_lines:
            block = "\n".join(prefix_lines) + "\n" + block
        driver_body_parts.append(block)

    driver_content = f'''\
"""Plamen V2 driver — slim orchestrator.

Imports all public names from the 4 sub-modules so existing test files
that do `import plamen_driver as D` continue to work unchanged.
"""
{STDLIB_IMPORTS}
from plamen_types import *  # noqa: F403,F401
from plamen_parsers import *  # noqa: F403,F401
from plamen_validators import *  # noqa: F403,F401
from plamen_mechanical import *  # noqa: F403,F401
from plamen_prompt import *  # noqa: F403,F401

''' + "\n\n\n".join(driver_body_parts) + '''


if __name__ == "__main__":
    sys.exit(main())
'''

    DRIVER.write_text(driver_content, encoding="utf-8")
    print(f"Wrote slim {DRIVER.name}: {len(driver_content):,d} bytes")


if __name__ == "__main__":
    main()
