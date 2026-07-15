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
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from plamen_types import (
    Phase, Checkpoint, SC_PHASES, L1_PHASES, log,
    L1_NEVER_CUT_ARTIFACT_GROUPS,
    l1_never_cut_groups,
    SC_NEVER_CUT_BASE, SC_NEVER_CUT_CORE_EXTRAS, SC_NEVER_CUT_THOROUGH_EXTRAS,
    sc_never_cut_groups, _NEVER_CUT_SKIP_REASONS,
    L1_VERIFY_SHARD_MANIFESTS, L1_VERIFY_PHASE_NAMES,
    L1_VERIFY_CRITHIGH_PHASE_NAMES,
    SC_VERIFY_SHARD_MANIFESTS, SC_VERIFY_PHASE_NAMES,
    SC_VERIFY_CRITHIGH_PHASE_NAMES,
    _VALID_PIPELINES, _VALID_MODES,
    EVIDENCE_TAGS_PROOF, EVIDENCE_TAGS_PROD, EVIDENCE_TAG_NAMES_RE,
    has_mechanical_proof,
    has_proof_grade_evidence,
    canonical_verification_status,
    FINDING_BLOCK_HEADING_RE,
    normalize_severity,
    try_normalize_severity,
    plamen_home,
)
from plamen_parsers import *  # noqa: F403,F401
from plamen_parsers import (
    _OPTIONAL_FINDING_METADATA_FIELDS,
    _OPTIONAL_FINDING_METADATA_LABELS,
    _normalize_manifest_header,
    _split_markdown_table_row,
    _manifest_row_from_cells,
    _manifest_row_is_spawned_breadth_agent,
    _poc_kw_present,
)

__all__ = [
    "verify_poc_contract_only_failed_ids",
    "_generate_verify_targeted_repair_hint",
    "verify_targeted_repair_already_done",
    "mark_verify_targeted_repair_done",
    "_NEVER_CUT_FILENAME_ALIASES",
    "_QUARANTINE_PATTERNS_BY_PHASE",
    "_RETRY_HINT_SUFFIX",
    "_ACCUMULATE_ON_RETRY_PHASES",
    "_RETRY_QUARANTINE_EXTRAS",
    "_assert_never_cut_artifacts",
    "_assert_never_cut_checkpoint",
    "_validate_depth_artifact_substance",
    "_depth_artifact_is_stub",
    "_basenames",
    "_canonicalize_summary_table",
    "_check_graph_artifact_consumption",
    "_check_index_completeness",
    "_report_index_dropped_ids",
    "_backfill_report_coverage_dropouts",
    "_check_notread_priority_coverage",
    "_check_opengrep_obligation_coverage",
    "_check_dedup_decision_coverage",
    "_dedup_decision_coverage_detail",
    "_repair_dedup_missing_dispositions",
    "_generate_dedup_decision_retry_hint",
    "_check_function_summary_obligation",
    "_check_pde_section_present",
    "_check_perturbation_block_per_finding",
    "_check_promotion_symmetry",
    "_check_report_index_unresolved_authenticity",
    "validate_report_index_summary_master_parity",
    "_distinct_master_report_ids",
    "_master_tier_counts",
    "_check_speculative_critical_chains",
    "_check_step_execution_traces",
    "_check_unresolved_authenticity",
    "_cleanup_quarantine_backups",
    "_clear_retry_hint",
    "_clear_stale_degraded_sentinels",
    "_collect_body_unresolved_report_ids",
    "_collect_consolidation_absorbed_ids",
    "_collect_cited_paths",
    "_collect_index_acknowledged_ids",
    "_collect_judge_unresolved_ids",
    "_collect_obligation_receipts",
    "_collect_report_coverage_acknowledged_ids",
    "_collect_report_index_seed_ids",
    "_collect_report_promoted_ids",
    "_collect_scip_indexed_paths",
    "_collect_verify_hypothesis_ids",
    "_collect_verify_promotion_receipts",
    "_compute_assemble_count_delta",
    "_compute_scip_coverage_sets",
    "_compute_subsystem_coverage_gap",
    "_compute_tier_completeness_delta",
    "_detect_foreign_phase_writes",
    "_protected_phase_write_patterns",
    "_live_protected_phase_write_patterns",
    "_record_phase_artifact_state",
    "_phase_artifacts_have_active_owner_state",
    "_ensure_report_consolidation_map",
    "_ensure_step_execution_traces",
    "_field_validation_sweep_relevant",
    "_filter_verification_queue_by_evidence",
    "_generate_assemble_retry_hint",
    "_generate_attention_repair_retry_hint",
    "_generate_breadth_retry_hint",
    "_generate_body_writer_retry_hint",
    "_generate_crossbatch_retry_hint",
    "_generate_depth_retry_hint",
    "_generate_depth_repair_hint",
    "_generate_orphan_repair_hint",
    "_depth_core_artifacts_present",
    "_generate_graph_sweeps_retry_hint",
    "_generate_inventory_retry_hint",
    "_generate_recon_retry_hint",
    "_generate_report_index_retry_hint",
    "_generate_skeptic_retry_hint",
    "_generate_tier_retry_hint",
    "_generate_verify_aggregate_retry_hint",
    "_generate_verify_core_if_missing",
    "_generate_verify_queue_retry_hint",
    "_generate_verify_shard_retry_hint",
    "_graph_sweeps_needed",
    "_write_chain_passthrough_outputs",
    "_body_writer_evidence_fields",
    "_expected_report_index_severities",
    "_expected_report_index_statuses",
    "_forced_chain_seed_rows",
    "_is_substantive_body_evidence",
    "_is_spec_support_path",
    "_is_evidence_missing_for_body",
    "_location_present_in_body",
    "_lifecycle_replay_sweep_relevant",
    "_match_label_status",
    "_matches_any_pattern",
    "_materialize_sc_slither_flat_files",
    "_maybe_skip_empty_body_writer",
    "_network_amplification_sweep_relevant",
    "_normalize_never_cut_filenames",
    "_owned_artifact_patterns",
    "_panic_sites_available",
    "_parse_inventory_evidence_validation",
    "_parse_subsystem_coverage_gap",
    "_primitive_sweep_relevant",
    "_promote_depth_findings_to_inventory",
    "_allocate_depth_promotion_inventory_id",
    "_quarantine_foreign_phase_writes",
    "_quarantine_phase_overreach",
    "_quarantine_report_without_completed_assemble",
    "_quarantine_stale_on_retry",
    "_pattern_implicated_by_missing",
    "_parse_rescan_manifest_files",
    "_rescan_manifest_exact_missing",
    "_read_retry_hint",
    "_read_artifact_state",
    "_write_artifact_state",
    "_artifact_record",
    "_report_index_adjustment_reason_present",
    "_repair_report_index_dropouts",
    "_repair_report_index_severity_provenance",
    "_write_severity_override_ledger",
    "_read_severity_override_ledger",
    "_restore_quarantined_on_retry_failure",
    "_rewind_completed_after_overflow",
    "_run_report_quality_gate",
    "_scan_for_halt_and_gatefail",
    "_scip_text_contains_any",
    "_skeptic_expected_findings",
    "_snapshot_file_state",
    "_snapshot_report_timestamped",
    "_step_trace_has_ceremonial_yes",
    "_sync_degraded_sentinels_to_checkpoint",
    "_synthesize_step_execution_trace",
    "_validate_assemble_not_degraded",
    "_validate_attention_repair",
    "_validate_invariants_pass2",
    "_validate_chain_iter2",
    "_validate_exploration_skeptic",
    "_validate_enumgap_exploration",
    "_validate_invariant_commitment",
    "_validate_axis_coverage",
    "_validate_chain_anti_absorption",
    "_declared_depth_findings",
    "_validate_chain_baseline_not_regrouped",
    "_auto_map_unmapped_depth_findings",
    "_generate_chain_baseline_regroup_retry_hint",
    "_validate_chain_self_restatement",
    "_generate_chain_self_restatement_retry_hint",
    "_repair_chain_anti_absorption_splits",
    "_validate_id_ledger_collisions",
    "_validate_consumer_ids_in_ledger",
    "_parse_hypothesis_id_title_pairs",
    "_generate_id_ledger_collision_retry_hint",
    "_generate_anti_absorption_retry_hint",
    "_per_constituent_claim_match",
    "_parse_inventory_finding_meta",
    "_validate_post_verify_extract",
    "_validate_cited_paths_in_verify",
    "_validate_crossbatch_full_coverage",
    "_validate_crossbatch_quality",
    "_parse_confidence_scores_permissive",
    "_validate_confidence_iter2_mandatory",
    "_validate_confidence_scores_quality",
    "_validate_depth_coverage",
    "_validate_percontract_self_exclusion",
    "_validate_depth_self_exclusion",
    "_validate_depth_exit",
    "_validate_depth_iterations",
    "_validate_semantic_gap_niche",
    "_validate_niche_manifest_consistency",
    "_validate_injectable_promotion",
    "_promote_injectable_rows",
    "_flag_derived_required_niches",
    "_detected_flag_present",
    "_detected_protocol_type",
    "_NICHE_FLAG_TO_AGENT",
    "_INJECTABLE_FLAG_TO_SKILL",
    "_INJECTABLE_PROTOCOL_TO_SKILL",
    "_validate_depth_promotion_receipt",
    "_validate_depth_promotion_dedup",
    "_validate_graph_sweeps",
    "_validate_inventory_evidence",
    "_validate_inventory_chunk_structure",
    "_validate_inventory_parity",
    "_validate_inventory_structure",
    "_validate_rc_parity",
    "_validate_recon_content_structure",
    "_validate_recon_coverage",
    "_has_live_placeholder_language",
    "_validate_report_body",
    "_validate_report_index_inputs",
    "_validate_report_index_prewrite_inputs",
    "_validate_report_coverage_semantic_contract",
    "_validate_report_index_severity_provenance",
    "_validate_report_index_triage_safety",
    "_validate_report_tier_completeness",
    "_validate_sc_subsystem_coverage",
    "_validate_scope_leftover",
    "_validate_skeptic_full_ch_coverage",
    "_validate_skeptic_scope",
    "_validate_spawn_manifest_schema",
    "_skill_template_resolves",
    "_manifest_fabricated_templates",
    "_validate_tier_body_against_manifest",
    "_validate_verification_queue_inventory_parity",
    "_compute_unrouted_inventory_ids",
    "_validate_verify_completion",
    "_find_verify_file",
    "_validate_poc_attempt_coverage",
    "_apply_poc_fail_demotions",
    "_apply_independent_severity_caps",
    "_apply_external_assumption_undemotions",
    "_load_independent_severity_caps",
    "_append_crossbatch_coverage_ledger",
    "_validate_report_coverage_accounting",
    "_validate_poc_pass_integrity",
    "_TRIVIAL_ASSERT_STRS",
    "_NONTRIVIAL_ASSERT_RE",
    "_ANY_ASSERT_RE",
    "_build_succeeded",
    "_parse_master_finding_index_rows",
    "_validate_verify_content_quality",
    "_validate_verifier_skip_vocabulary",
    "_validate_verify_evidence_tags",
    "_validate_verify_files_for_queue",
    "_verify_file_present_for_id",
    "_write_final_subsystem_coverage_summary",
    "_write_empty_verification_queue",
    "_write_inventory_base_snapshot",
    "_write_crossbatch_manifest",
    "_write_graph_sweeps_skip",
    "_write_rag_validation_floor",
    "_write_promotion_dropout_retry_hint",
    "_write_retry_hint",
    "_write_semantic_invariants_fallback",
    "_write_semantic_dedup_skip_outputs",
    "_write_skeptic_manifest",
    "_semantic_gap_trigger_counts",
    "_semantic_gap_required",
    "_AUDIT_FRESH_SENTINEL_NAME",
    "validate_breadth_artifact_ownership",
    "validate_depth_artifact_ownership",
    "compute_breadth_row_statuses",
    "compute_depth_row_statuses",
    "compute_verify_row_statuses",
    "compute_phase_row_statuses",
    "gate_passes",
    "scratchpad_is_fresh_audit",
    "is_verification_queue_empty",
    "identify_missing_verify_ids",
    "stub_missing_verify_files",
    "write_empty_verify_placeholders",
    "_collect_judge_downgrade_map",
]


def is_verification_queue_empty(scratchpad: Path, pipeline: str) -> tuple:
    """Return (is_empty, reason).

    A verification queue is empty when there are ZERO Medium+ findings to
    verify. This is a legitimate N/A state (e.g., a clean codebase that
    produced only Low/Info findings) — NOT a pipeline failure. The verify
    phase is `critical=True` with a `verify_*.md` glob that matches 0
    files → gate_passes() would mark the phase degraded and HALT the
    pipeline, which is wrong for an empty queue.

    Sources (order of preference):
    - SC: hypotheses.md (post-chain) + chain_hypotheses.md, fall back to
      findings_inventory.md if neither exists.
    - L1: findings_inventory.md (no chain phase in L1 per design.md §4.2).

    We count occurrences of `Critical`, `High`, `Medium` in severity
    contexts. Zero matches across ALL sources → empty queue.
    Unreadable sources are treated as "not empty" (conservative: let the
    phase run rather than falsely skip).
    """
    q = scratchpad / "verification_queue.md"
    if q.exists():
        try:
            q_text = _llm_norm(q.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            return (False, f"could not read verification_queue.md: {exc}")
        if parse_verification_queue_rows(scratchpad):
            return (False, "verification_queue.md contains reportable rows")
        if re.search(r"\bTotal:\s*0\s+findings\b", q_text, re.IGNORECASE):
            return (True, "verification_queue.md declares Total: 0 findings")
        if q_text.strip():
            return (False, "verification_queue.md exists but is not parseable")

    if pipeline == "l1":
        sources = ["findings_inventory.md"]
    else:
        # Prefer the post-chain hypotheses set; fall back to raw inventory
        # if chain never ran (resume mid-pipeline, Light mode, etc.).
        hyp = scratchpad / "hypotheses.md"
        sources = []
        if hyp.exists():
            sources.append("hypotheses.md")
            if (scratchpad / "chain_hypotheses.md").exists():
                sources.append("chain_hypotheses.md")
        else:
            sources.append("findings_inventory.md")

    total = 0
    any_readable = False
    for name in sources:
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return (False, f"could not read {name}")
        any_readable = True
        total += len(re.findall(r"(?i)\b(Critical|High|Medium)\b", text))

    if not any_readable:
        # No queue source written yet (e.g., resume before inventory ran).
        # Don't short-circuit — let gate_passes handle it.
        return (False, "no queue source files exist yet")
    if total == 0:
        return (True, f"0 reportable finding markers in {', '.join(sources)}")
    return (False, f"{total} reportable finding markers found")


def _write_semantic_dedup_skip_outputs(
    scratchpad: Path,
    phase_name: str,
    reason: str = "no candidate pairs and no LIKELY-DUP tags",
) -> list[str]:
    """Materialize semantic-dedup passthrough outputs before checkpoint completion."""
    scratchpad = Path(scratchpad)
    written: list[str] = []

    decisions = scratchpad / "dedup_decisions.md"
    decisions.write_text(
        "# Semantic Dedup Decisions\n\n"
        "**Status**: PASSTHROUGH\n\n"
        f"**Reason**: {reason}.\n\n"
        "This phase preserves the upstream artifact unchanged unless a bounded "
        "semantic-dedup subprocess later overwrites this passthrough with a "
        "valid deduplicated artifact. The explicit passthrough prevents a "
        "quality-improvement helper from creating missing-file or retry loops.\n",
        encoding="utf-8",
    )
    written.append(decisions.name)

    if phase_name == "semantic_dedup":
        source = scratchpad / "verification_queue.md"
        target = scratchpad / "verification_queue_deduped.md"
        label = "Verification Queue Deduped"
    elif phase_name == "sc_semantic_dedup":
        source = scratchpad / "findings_inventory.md"
        target = scratchpad / "findings_inventory_deduped.md"
        label = "Findings Inventory Deduped"
    else:
        raise ValueError(f"unsupported semantic dedup phase: {phase_name}")

    if source.exists() and source.stat().st_size > 0:
        body = source.read_text(encoding="utf-8", errors="replace")
        if len(body.encode("utf-8", errors="replace")) < 100:
            body += (
                "\n\n<!-- semantic_dedup: no dedup signals; source preserved "
                "unchanged for downstream phases. -->\n"
            )
        target.write_text(body, encoding="utf-8")
    else:
        target.write_text(
            f"# {label}\n\n"
            "**Status**: PASSTHROUGH\n\n"
            f"Source artifact `{source.name}` was unavailable or empty while "
            "semantic dedup needed a deterministic passthrough. Downstream "
            "phases receive this explicit placeholder instead of a missing "
            "file.\n\n"
            "No semantic merge decisions were applied by this fallback.\n",
            encoding="utf-8",
        )
    written.append(target.name)
    return written


def _write_chain_passthrough_outputs(
    scratchpad: Path,
    reason: str = "pre-run scaffold safety net",
) -> list[str]:
    """Write a valid one-finding-per-hypothesis chain baseline.

    Chain Agent 1 is quality-improving, but downstream verification needs the
    three handoff files to exist. This scaffold preserves every inventory
    finding as its own hypothesis until the LLM overwrites it with better
    grouping/enabler analysis.
    """
    scratchpad = Path(scratchpad)
    inv_path = scratchpad / "findings_inventory.md"
    entries = _parse_inventory_chunk(inv_path) if inv_path.exists() else []
    if not entries:
        ids: list[str] = []
        if inv_path.exists():
            try:
                text = inv_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                text = ""
            ids = sorted(_extract_finding_ids_from_text(text))
        entries = [
            {
                "local_id": fid,
                "title": f"Inventory finding {fid}",
                "severity": "Medium",
                "location": "UNKNOWN",
                "source_ids": [fid],
                "root_cause": "",
                "description": "",
            }
            for fid in ids
        ]

    written: list[str] = []
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    hyp_lines = [
        "# Hypotheses",
        "",
        "**Status**: MECHANICAL_BASELINE",
        f"**Reason**: {reason}.",
        f"**Generated At**: {stamp}",
        "",
        "| Hypothesis ID | Severity | Title | Constituent Findings | Location | Notes |",
        "|---------------|----------|-------|----------------------|----------|-------|",
    ]
    map_lines = [
        "# Finding Mapping",
        "",
        "**Status**: MECHANICAL_BASELINE",
        f"**Reason**: {reason}.",
        "",
        "| Finding ID | Hypothesis ID | Mapping Status | Notes |",
        "|------------|---------------|----------------|-------|",
    ]
    for idx, entry in enumerate(entries, start=1):
        def _cell(value: str) -> str:
            return re.sub(r"\s+", " ", str(value or "").replace("|", "/")).strip()

        local = (
            _normalize_finding_id(str(entry.get("local_id", "")))
            or next(iter(entry.get("source_ids", []) or []), "")
            or f"INV-{idx:03d}"
        )
        local = _normalize_finding_id(str(local)) or str(local)
        hid = f"H-{idx}"
        sev = normalize_severity(str(entry.get("severity") or "Medium"))
        title = _cell(str(entry.get("title") or f"Inventory finding {local}"))
        loc = _cell(str(entry.get("location") or "UNKNOWN"))
        source_ids = list(entry.get("source_ids", []) or [])
        if local and local not in source_ids:
            source_ids.insert(0, local)
        sources = ", ".join(str(s) for s in source_ids if str(s).strip()) or local
        note = "Baseline one-to-one mapping; Chain Agent 1 may consolidate if safe."
        hyp_lines.append(
            f"| {hid} | {sev} | {title} | {sources} | {loc} | {note} |"
        )
        map_lines.append(
            f"| {local} | {hid} | BASELINE_ONE_TO_ONE | preserved from inventory |"
        )

    if len(hyp_lines) == 7:
        hyp_lines.append(
            "| H-0 | Informational | No inventory findings parsed | NONE | UNKNOWN | "
            "Placeholder to satisfy downstream handoff; upstream inventory should be checked. |"
        )
        map_lines.append("| NONE | H-0 | EMPTY_INVENTORY | no parsed inventory rows |")

    (scratchpad / "hypotheses.md").write_text("\n".join(hyp_lines) + "\n", encoding="utf-8")
    written.append("hypotheses.md")
    (scratchpad / "finding_mapping.md").write_text("\n".join(map_lines) + "\n", encoding="utf-8")
    written.append("finding_mapping.md")
    enabler = (
        "# Enabler Results\n\n"
        "**Status**: MECHANICAL_BASELINE\n\n"
        f"**Reason**: {reason}.\n\n"
        "No new enabler paths were mechanically introduced by this scaffold. "
        "Chain Agent 1 may overwrite this file with dangerous-state tables and "
        "cross-state interactions. Until then, downstream phases preserve the "
        "one-to-one inventory hypotheses without treating this scaffold as a "
        "claim that no enablers exist.\n"
    )
    (scratchpad / "enabler_results.md").write_text(enabler, encoding="utf-8")
    written.append("enabler_results.md")
    return written


def _write_semantic_invariants_fallback(
    scratchpad: Path,
    reason: str,
) -> list[str]:
    """Write the documented invariant fallback artifact.

    The invariant prompt contract says depth may fall back to
    `state_variables.md` if this enrichment phase times out. The phase gate
    still needs a concrete artifact so resume/checkpoint state remains
    explicit instead of retrying a non-load-bearing helper.
    """
    scratchpad = Path(scratchpad)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    state_path = scratchpad / "state_variables.md"
    variables: list[str] = []
    if state_path.exists():
        try:
            text = state_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("|") or "---" in stripped:
                continue
            cells = [c.strip(" `*") for c in stripped.strip("|").split("|")]
            if cells and cells[0] and cells[0].lower() not in {
                "variable", "state variable", "name",
            }:
                variables.append(cells[0])
        variables = list(dict.fromkeys(variables))[:200]

    if variables:
        variable_cell = ", ".join(variables[:25])
        if len(variables) > 25:
            variable_cell += f", ... (+{len(variables) - 25} more)"
    else:
        variable_cell = "None parsed from state_variables.md"

    body = (
        "# Semantic Invariants\n\n"
        "**Status**: FALLBACK\n\n"
        f"**Reason**: {reason}\n\n"
        f"**Generated**: {stamp}\n\n"
        "The semantic-invariant enrichment pass did not produce a complete "
        "artifact. This file preserves the documented transition contract: "
        "depth agents must read `state_variables.md` directly and derive "
        "invariants locally instead of treating this phase as absent.\n\n"
        "### Main Table\n\n"
        "| Variable | Contract/Module | Semantic Invariant | Write Sites "
        "(with CONDITIONAL annotations) | Value-Changing Functions | "
        "Potential Gaps |\n"
        "|---|---|---|---|---|---|\n"
        f"| {variable_cell} | See state_variables.md | FALLBACK: derive in "
        "depth phase | See state_variables.md and source grep | See "
        "function_list.md | Not precomputed |\n\n"
        "### Mirror Variable Pairs\n\n"
        "| Variable A | Variable B | Same Concept | Functions Writing A Only | "
        "Functions Writing B Only | Sync Gaps |\n"
        "|---|---|---|---|---|---|\n"
        "| FALLBACK | FALLBACK | Not precomputed | Not precomputed | "
        "Not precomputed | Depth must inspect if relevant |\n\n"
        "### Time-Weighted Accumulators\n\n"
        "| Accumulator | Formula Pattern | Controllable Input | Time Source | "
        "Unbounded Delta? | Exposure |\n"
        "|---|---|---|---|---|---|\n"
        "| FALLBACK | Not precomputed | Not precomputed | Not precomputed | "
        "Unknown | Depth must inspect if relevant |\n\n"
        "### Semantic Clusters\n\n"
        "| Cluster Name | Variables | Lifecycle Functions | Full-Write Functions | "
        "Partial-Write Functions |\n"
        "|---|---|---|---|---|\n"
        f"| FALLBACK | {variable_cell} | See function_list.md | Not precomputed | "
        "Not precomputed |\n"
    )
    target = scratchpad / "semantic_invariants.md"
    target.write_text(body, encoding="utf-8")
    return [target.name]


def _write_rag_validation_floor(
    scratchpad: Path,
    reason: str,
) -> list[str]:
    """Write complete RAG floor scores for every inventory finding.

    RAG validation is quality-improving context. Final scoring already
    defines 0.3 as the no-support/tool-failed floor, so the deterministic
    fallback must materialize that floor for every finding rather than
    forcing a retry on a missing `rag_validation.md`.
    """
    scratchpad = Path(scratchpad)
    inv_path = scratchpad / "findings_inventory.md"
    rows: list[tuple[str, str]] = []
    if inv_path.exists():
        try:
            text = _llm_norm(inv_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            text = ""
        for m in re.finditer(
            r"(?im)^\s*#{2,4}\s+Finding\s+\[([A-Z0-9]+(?:-[A-Z0-9]+)*-\d+)\]:\s*(.+)$",
            text,
        ):
            rows.append((m.group(1).strip(), m.group(2).strip()))

    if not rows:
        rows = [("NONE", "No inventory findings parsed")]

    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    lines = [
        "# RAG Validation",
        "",
        "**Status**: FALLBACK_FLOOR",
        "",
        f"**Reason**: {reason}",
        f"**Generated**: {stamp}",
        "",
        "| Finding ID | validate_hypothesis Score | solodit_live Matches | Final RAG Score | Notes |",
        "|---|---|---|---|---|",
    ]
    for fid, title in rows:
        safe_title = title.replace("|", "/")[:120]
        lines.append(
            f"| {fid} | N/A | 0 | 0.3 | [RAG: DRIVER_FLOOR] {safe_title}; {reason} |"
        )
    lines.append("")
    target = scratchpad / "rag_validation.md"
    target.write_text("\n".join(lines), encoding="utf-8")
    return [target.name]


def _write_empty_verification_queue(scratchpad: Path, reason: str) -> list[str]:
    """Write canonical zero-row queue artifacts for an empty verify queue."""
    scratchpad = Path(scratchpad)
    written: list[str] = []
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    body = (
        "# Verification Queue\n\n"
        "| Queue # | Finding ID | Report ID | Severity | Title | Location | "
        "Preferred Tag | Required Evidence | Status |\n"
        "|---|---|---|---|---|---|---|---|---|\n\n"
        "Total: 0 findings\n\n"
        f"Reason: {reason}\n"
        f"Generated: {stamp}\n\n"
        "This is the canonical empty queue artifact. Downstream verify shards, "
        "semantic dedup, cross-batch, and report phases must treat this as a "
        "complete zero-row manifest, not as a missing queue.\n"
    )
    queue = scratchpad / "verification_queue.md"
    queue.write_text(body, encoding="utf-8")
    written.append(queue.name)

    excluded = scratchpad / "verification_queue_evidence_excluded.md"
    excluded.write_text(
        "# Verification Queue Evidence-Excluded\n\n"
        "| Finding ID | Severity | Title | Exclusion Reason |\n"
        "|---|---|---|---|\n\n"
        "Total: 0 findings\n\n"
        f"Reason: {reason}\n"
        f"Generated: {stamp}\n",
        encoding="utf-8",
    )
    written.append(excluded.name)
    return written


def write_empty_verify_placeholders(scratchpad: Path, phase_name: str, reason: str) -> None:
    """Write N/A artifacts so downstream phases (report) have something
    to read. These pass gate_passes() because they are substantial files
    (>= min_artifact_bytes default 50 bytes) even though semantically
    they record the N/A state.
    """
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    if phase_name == "verify":
        marker = scratchpad / "verify_NONE.md"
        marker.write_text(
            f"# Verification Queue: N/A\n\n"
            f"No reportable findings were produced by the breadth/depth/chain "
            f"pipeline, so the verification phase has nothing to exercise.\n\n"
            f"- Reason: {reason}\n"
            f"- Timestamp: {stamp}\n\n"
            f"Report generation proceeds with an empty verified set.\n",
            encoding="utf-8",
        )
    elif phase_name in ("verify_aggregate", "sc_verify_aggregate"):
        marker = scratchpad / "verify_core.md"
        marker.write_text(
            f"# verify_core: N/A\n\n"
            f"No verifier outputs exist for aggregation.\n\n"
            f"- Reason: {reason}\n"
            f"- Timestamp: {stamp}\n",
            encoding="utf-8",
        )
    elif phase_name in SC_VERIFY_PHASE_NAMES:
        marker = scratchpad / f"{phase_name}_NONE.md"
        marker.write_text(
            f"# {phase_name}: N/A\n\n"
            f"No findings assigned to this SC verify shard.\n\n"
            f"- Reason: {reason}\n"
            f"- Timestamp: {stamp}\n",
            encoding="utf-8",
        )
    elif phase_name == "skeptic":
        marker = scratchpad / "skeptic_NONE.md"
        marker.write_text(
            f"# Skeptic-Judge Queue: N/A\n\n"
            f"No Medium+ findings → no High/Critical verdicts to adversarially "
            f"review.\n\n- Reason: {reason}\n- Timestamp: {stamp}\n",
            encoding="utf-8",
        )
    elif phase_name == "crossbatch":
        marker = scratchpad / "cross_batch_consistency.md"
        marker.write_text(
            f"# Cross-Batch Consistency: N/A\n\n"
            f"No verifier batches were produced (empty verification queue). "
            f"There are no severities to cross-compare.\n\n"
            f"- Reason: {reason}\n- Timestamp: {stamp}\n",
            encoding="utf-8",
        )


def identify_missing_verify_ids(
    scratchpad: Path,
    *,
    min_bytes: int = 100,
) -> list[tuple[str, dict]]:
    """Return (finding_id, queue_row) pairs for queue rows without verify files.

    v2.6.8: Extracted from stub_missing_verify_files so the driver can
    first attempt a recovery verification shard before falling back to
    mechanical stubs.
    """
    rows = parse_verification_queue_rows(scratchpad)
    missing: list[tuple[str, dict]] = []
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        if _verify_file_present_for_id(scratchpad, fid, min_bytes=min_bytes):
            continue
        missing.append((fid, row))
    return missing


def stub_missing_verify_files(
    scratchpad: Path,
    pipeline: str,
    *,
    min_bytes: int = 100,
) -> list[str]:
    """Mechanically stub verify files that verify shards failed to produce.

    v2.6.7: When verify shards hit context/time limits they produce partial
    output (e.g. 87/103 files). Without stubs the E1 parity gate
    (_validate_verify_files_for_queue) correctly catches the gap but the
    only recovery is a pipeline halt — there is no fallback to fill the
    gap mechanically.

    v2.6.8: Refactored to use identify_missing_verify_ids(). The driver
    now runs a recovery shard first; this function stubs whatever remains.

    Returns the list of finding IDs that were stubbed.
    """
    missing = identify_missing_verify_ids(scratchpad, min_bytes=min_bytes)
    if not missing:
        return []
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    stubbed: list[str] = []
    for fid, row in missing:
        severity = (row.get("severity") or "Unknown").strip()
        title = (row.get("title") or "").strip()
        location = (row.get("location") or "").strip()
        stub_path = scratchpad / f"verify_{fid}.md"
        stub_path.write_text(
            f"# Verification: {fid}\n\n"
            f"**Finding ID**: {fid}\n"
            f"**Title**: {title}\n"
            f"**Severity**: {severity}\n"
            f"**Location**: {location}\n\n"
            f"**Verdict**: UNVERIFIED\n"
            f"**Evidence Tag**: [CODE-TRACE]\n"
            f"**Preferred Tag**: [CODE-TRACE]\n\n"
            f"## VERIFICATION NOT EXECUTED\n\n"
            f"This finding was not verified by the verification subprocess. "
            f"The verify shard that was assigned this finding either timed "
            f"out or exceeded its context budget before producing a verify "
            f"file for this finding.\n\n"
            f"- Stub reason: verify shard partial output\n"
            f"- Timestamp: {stamp}\n"
            f"- Original severity preserved: {severity}\n\n"
            f"Human reviewer should treat this finding as unverified and "
            f"apply independent judgment on exploitability.\n",
            encoding="utf-8",
        )
        stubbed.append(fid)
    return stubbed


def _verify_shard_gate_missing(scratchpad: Path, phase_name: str, *, min_bytes: int = 100) -> list[str]:
    """Artifact-existence gate for manifest-driven verify shards.

    Verify shard phases intentionally have no static `expected_artifacts`
    because their output set is derived from `verification_queue.md`. Treating
    that as a normal empty-artifact phase creates a misleading vacuous-pass
    warning and hides the real contract from the first gate layer.
    """
    if phase_name in SC_VERIFY_PHASE_NAMES:
        shards = compute_sc_verify_shards(scratchpad)
    else:
        shards = compute_verify_shards(scratchpad)
    queue_path = scratchpad / "verification_queue.md"
    if queue_path.exists():
        try:
            queue_text = _llm_norm(queue_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            queue_text = ""
        if (
            queue_text.strip()
            and not parse_verification_queue_rows(scratchpad)
            and not re.search(r"\bTotal:\s*0\s+findings\b", queue_text, re.IGNORECASE)
        ):
            return [
                "verify queue parse: verification_queue.md exists but no "
                "parseable finding rows were found"
            ]
    expected_rows = shards.get(phase_name, [])
    expected_ids = [row.get("finding id", "") for row in expected_rows]
    expected_ids = [fid for fid in expected_ids if fid]
    if not expected_ids:
        return []

    def _verify_names(fid: str) -> tuple[str, ...]:
        return (
            f"verify_{fid}.md",
            f"verify_F-{fid}.md",
            f"verify_F_{fid}.md",
            f"verify_[{fid}].md",
        )

    def _present(fid: str) -> bool:
        for name in _verify_names(fid):
            p = scratchpad / name
            if p.exists() and p.stat().st_size >= min_bytes:
                return True
        return False

    missing_ids = [fid for fid in expected_ids if not _present(fid)]
    if not missing_ids:
        return []
    sample = sorted(missing_ids)[:5]
    extra = f" (+{len(missing_ids) - len(sample)} more)" if len(missing_ids) > len(sample) else ""
    return [
        f"verify completion: wrote {len(expected_ids) - len(missing_ids)}/"
        f"{len(expected_ids)} verifier files; missing: {sample}{extra}"
    ]


_AUDIT_FRESH_SENTINEL_NAME = "_audit_started_with_markers.json"


def scratchpad_is_fresh_audit(scratchpad: Path) -> bool:
    """Return True iff the scratchpad has a fresh-audit sentinel.

    The sentinel `{scratchpad}/_audit_started_with_markers.json` is written
    by the driver at the start of phase 1 (recon) on fresh audits that run
    under the new artifact-marker contract (Ship 6 wires the write). Its
    presence tells the gate to require PLAMEN markers and structural
    completeness from spawned-worker artifacts.

    Absence means the audit pre-dates marker enforcement (resumed
    scratchpad) and the gate should fall back to legacy size-based
    semantics with a warning log on unmarked / in-progress files.
    """
    try:
        return (scratchpad / _AUDIT_FRESH_SENTINEL_NAME).exists()
    except Exception:
        return False


# Structural-check kwargs are configured per phase. Centralizing here keeps
# Ship 3 phase-aware without introducing a `Phase.structural_checks` field
# (Ship 8 may promote this to a Phase attribute when generalizing to other
# spawned-worker phases). Returning kwargs (rather than (ok, reasons))
# defers the actual file read to _structural_completeness_ok at gate time.
_BREADTH_STRUCTURAL_REQUIRED_HEADINGS: tuple[str, ...] = ("Findings",)
_BREADTH_STRUCTURAL_PLACEHOLDERS: tuple[str, ...] = (
    "TODO:", "FILL_ME", "<placeholder>",
)


# Per-row breadth status taxonomy. Ship 3 surfaced these buckets as
# substrings of the gate's failure message; Ship 6 lifts them into a
# structured per-row datum so the PTY supervision loop can build a
# continuation message that names each incomplete row without
# re-parsing the gate's aggregated string. ``gate_passes`` consumes
# this same helper for the same buckets, so both call sites stay
# byte-equivalent.
_BREADTH_STATUS_MISSING = "missing"
_BREADTH_STATUS_STUB = "stub"
_BREADTH_STATUS_IN_PROGRESS = "in_progress"
_BREADTH_STATUS_STRUCTURAL_FAIL = "structural_fail"
_BREADTH_STATUS_LEGACY_UNMARKED = "legacy_unmarked"
_BREADTH_STATUS_COMPLETE = "complete"

_BREADTH_INCOMPLETE_STATUSES: tuple[str, ...] = (
    _BREADTH_STATUS_MISSING,
    _BREADTH_STATUS_STUB,
    _BREADTH_STATUS_IN_PROGRESS,
    _BREADTH_STATUS_STRUCTURAL_FAIL,
)

# Ship 8 reuses the same status vocabulary for every supervised
# spawned-worker phase (breadth, depth). The string constants above
# are phase-agnostic; only the prefix names keep the historical
# `_BREADTH_` spelling for backward-compat with existing imports.

# Depth structural config. Depth findings use the `### Finding [ID]`
# block format (NOT breadth's `## Findings` heading) and a
# `## Semantic Proof Checks` section, so the depth structural check
# does NOT impose breadth's `## Findings` required heading. It keeps
# the COMPLETE marker + findings-count + zero-findings-rationale +
# no-placeholder contract, which are artifact-type-neutral. Depth has
# no opengrep obligation shard, so the receipts check is not applied.
_DEPTH_STRUCTURAL_PLACEHOLDERS: tuple[str, ...] = (
    "TODO:", "FILL_ME", "<placeholder>",
)

# Canonical depth roles. Pulled from the phase's example_tokens at
# call time (deterministic, independent of what is on disk -- unlike
# the observational _expected_depth_agent_roles, which cannot see a
# role whose file was never written). Falls back to this tuple when a
# phase config carries no example_tokens.
_DEPTH_CANONICAL_ROLES: tuple[str, ...] = (
    "token_flow", "state_trace", "edge_case", "external",
)


def _read_cli_backend_from_config(scratchpad: Path) -> str:
    """Read 'cli_backend' from {scratchpad}/config.json. Default 'claude'.

    Makes worker-completion-marker semantics backend-aware. Only the Claude PTY
    worker pool streams artifacts and writes the `PLAMEN_STATUS: COMPLETE`
    marker, so "unmarked on a fresh audit => a worker is still mid-write =>
    IN_PROGRESS" is a Claude-PTY assumption. A single-subprocess backend
    (codex exec) that has RETURNED has produced FINAL files and never writes the
    marker, so its unmarked-but-substantive artifacts are COMPLETE, not
    in-progress. Defaults to 'claude' (strict) when config is absent/unreadable.
    """
    try:
        import json as _json
        cfg = scratchpad / "config.json"
        if cfg.exists():
            val = _json.loads(
                cfg.read_text(encoding="utf-8", errors="replace")
            ).get("cli_backend")
            return (str(val).strip().lower() or "claude") if val else "claude"
    except Exception:
        pass
    return "claude"


def _config_proven_only(scratchpad: Path) -> bool:
    """Read 'proven_only' from {scratchpad}/config.json. Default False.

    Proven-only mode caps `[CODE-TRACE]`-only findings at Low. The gated
    preservation block in `_expected_report_index_severities` reads this flag
    so the structural-untestable distinction only fires when the user opted
    into proven-only. Defaults False (no cap) when config is absent/unreadable.
    """
    try:
        import json as _json
        cfg = scratchpad / "config.json"
        if cfg.exists():
            val = _json.loads(
                cfg.read_text(encoding="utf-8", errors="replace")
            ).get("proven_only", False)
            return bool(val)
    except Exception:
        pass
    return False


def _classify_artifact_row(
    path: Path,
    *,
    fresh_audit: bool,
    min_bytes: int,
    structural_kwargs: dict,
) -> tuple[str, list[str]]:
    """Classify a single spawned-worker artifact into one of the
    `_BREADTH_STATUS_*` buckets. Shared by every supervised phase's
    per-row status helper (breadth, depth) so the marker semantics
    stay identical across phases.

    ``structural_kwargs`` are forwarded to ``_structural_completeness_ok``
    when the file is COMPLETE on a fresh audit. Pass phase-appropriate
    kwargs (breadth requires the `## Findings` heading + obligation
    receipts; depth does not). Returns ``(status, reasons)``.
    """
    if not path.exists():
        return _BREADTH_STATUS_MISSING, []
    try:
        size_ok = path.stat().st_size >= min_bytes
    except Exception:
        size_ok = False
    if not size_ok:
        return _BREADTH_STATUS_STUB, []

    if is_artifact_legacy_unmarked(path):
        # Codex runs each phase as a single `codex exec` subprocess (NOT a PTY
        # worker pool), so it never writes the PLAMEN_STATUS marker. An unmarked
        # but substantive file from a RETURNED Codex subprocess is COMPLETE, not
        # a worker still mid-write — so do NOT treat it as IN_PROGRESS even on a
        # fresh audit; classify it tolerated-legacy-unmarked (non-blocking).
        # Claude PTY keeps the strict fresh-audit IN_PROGRESS semantics (a live
        # worker may still be writing). `path.parent` is the scratchpad. Stub /
        # missing / explicit-marked-IN_PROGRESS files are handled outside this
        # branch and still block for both backends (silent-incomplete protection).
        if fresh_audit and _read_cli_backend_from_config(path.parent) != "codex":
            return _BREADTH_STATUS_IN_PROGRESS, ["legacy-unmarked on fresh audit"]
        return _BREADTH_STATUS_LEGACY_UNMARKED, []

    if not is_artifact_complete(path, min_bytes):
        return _BREADTH_STATUS_IN_PROGRESS, []

    if fresh_audit:
        ok, reasons = _structural_completeness_ok(path, **structural_kwargs)
        if not ok:
            return _BREADTH_STATUS_STRUCTURAL_FAIL, reasons

    return _BREADTH_STATUS_COMPLETE, []


def validate_breadth_artifact_ownership(
    path: Path,
    *,
    expected_output: str,
    expected_owner: str | None = None,
) -> tuple[bool, list[str]]:
    """Validate marker-level ownership for a fresh breadth row artifact.

    The breadth worker pool launches one top-level Claude PTY per manifest
    row. A row is only complete when the file's markers prove that the
    assigned worker wrote the assigned output, not just any manifest output.
    """
    markers = _extract_artifact_status(path)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw = _strip_fenced_code_blocks(raw)
    except Exception:
        raw = ""

    def _plain_marker(name: str) -> str:
        match = re.search(
            rf"<!--\s*{re.escape(name)}\s*:\s*(.*?)\s*-->",
            raw,
        )
        return match.group(1).strip() if match else ""

    reasons: list[str] = []
    if markers.get("ARTIFACT") != expected_output:
        reasons.append(
            "marker PLAMEN_ARTIFACT does not match expected output "
            f"{expected_output}"
        )
    if markers.get("PHASE") != "breadth":
        reasons.append("marker PLAMEN_PHASE is not breadth")

    expected_marker = _plain_marker("EXPECTED_OUTPUT")
    if expected_marker != expected_output:
        reasons.append(
            "marker EXPECTED_OUTPUT does not match expected output "
            f"{expected_output}"
        )

    if expected_owner:
        owner = markers.get("OWNER")
        agent_row = _plain_marker("AGENT_ROW")
        if owner != expected_owner:
            reasons.append(
                "marker PLAMEN_OWNER does not match manifest row "
                f"{expected_owner}"
            )
        if agent_row != expected_owner:
            reasons.append(
                "marker AGENT_ROW does not match manifest row "
                f"{expected_owner}"
            )
    return not reasons, reasons


def validate_depth_artifact_ownership(
    path: Path,
    *,
    expected_output: str,
    expected_owner: str | None = None,
) -> tuple[bool, list[str]]:
    """Validate marker-level ownership for a fresh depth worker artifact."""
    markers = _extract_artifact_status(path)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        raw = _strip_fenced_code_blocks(raw)
    except Exception:
        raw = ""

    def _plain_marker(name: str) -> str:
        match = re.search(
            rf"<!--\s*{re.escape(name)}\s*:\s*(.*?)\s*-->",
            raw,
        )
        return match.group(1).strip() if match else ""

    reasons: list[str] = []
    if markers.get("ARTIFACT") != expected_output:
        reasons.append(
            "marker PLAMEN_ARTIFACT does not match expected output "
            f"{expected_output}"
        )
    if markers.get("PHASE") != "depth":
        reasons.append("marker PLAMEN_PHASE is not depth")

    expected_marker = _plain_marker("EXPECTED_OUTPUT")
    if expected_marker != expected_output:
        reasons.append(
            "marker EXPECTED_OUTPUT does not match expected output "
            f"{expected_output}"
        )

    if expected_owner:
        owner = markers.get("OWNER")
        agent_row = _plain_marker("AGENT_ROW")
        if owner != expected_owner:
            reasons.append(
                "marker PLAMEN_OWNER does not match depth row "
                f"{expected_owner}"
            )
        if agent_row != expected_owner:
            reasons.append(
                "marker AGENT_ROW does not match depth row "
                f"{expected_owner}"
            )
    return not reasons, reasons


def _read_breadth_worker_pool_contract(scratchpad: Path) -> dict[str, Any]:
    path = scratchpad / "_breadth_worker_pool_contract.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _breadth_worker_pool_contract_active(scratchpad: Path) -> bool:
    return bool(_read_breadth_worker_pool_contract(scratchpad))


def _read_depth_worker_pool_contract(scratchpad: Path) -> dict[str, Any]:
    path = scratchpad / "_depth_worker_pool_contract.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _depth_worker_pool_contract_active(scratchpad: Path) -> bool:
    return bool(_read_depth_worker_pool_contract(scratchpad))


def compute_breadth_row_statuses(
    scratchpad: Path, phase: Phase
) -> list[dict[str, Any]]:
    """Return per-row status for every expected breadth output.

    Each entry is::

        {
          "name": "analysis_<focus_area>.md",
          "status": one of _BREADTH_STATUS_*,
          "reasons": list[str],   # structural_fail reasons; empty otherwise
        }

    Ship 6 of the artifact-complete PTY supervision plan. Used by:

      - ``gate_passes`` (this module) to build its failure-detail
        string; the breadth block delegates to this helper rather
        than inlining the marker-aware checks (kept byte-equivalent
        to the Ship 3 behavior).
      - The PTY supervision loop in ``plamen_driver`` to build a
        continuation message that lists ONLY incomplete rows by name
        and status, so already-COMPLETE rows are never re-run.

    Returns ``[]`` when the manifest is absent or no spawned-agent
    rows can be derived. Callers fall back to the legacy ``analysis_*.md``
    quorum check in that case (gate_passes does this automatically).

    Marker semantics (matching Ship 3):

      - missing:          file does not exist
      - stub:             file exists but size < min_artifact_bytes
      - in_progress:      file has PLAMEN markers but STATUS != COMPLETE,
                          OR file is unmarked on a FRESH-audit scratchpad
                          (sentinel present); fresh audits require markers
                          for new artifacts.
      - structural_fail:  file is COMPLETE on a fresh audit but fails a
                          structural completeness check (missing required
                          heading, zero-findings-no-rationale, residual
                          placeholder strings, missing obligation receipts
                          section). Returns the same ``reasons`` the gate
                          surfaces today.
      - legacy_unmarked:  file exists with substantive content but no
                          PLAMEN_ARTIFACT marker, on a LEGACY/resumed
                          scratchpad. Treated as pass (with warning) by
                          ``gate_passes``; the supervision loop ignores
                          these rows (they are not incomplete).
      - complete:         file is COMPLETE and (on fresh audits) passes
                          structural checks.
    """
    expected_outputs = parse_breadth_manifest_outputs(scratchpad)
    contract = _read_breadth_worker_pool_contract(scratchpad)
    if not expected_outputs and contract.get("phase") == "breadth":
        outputs = contract.get("outputs")
        if isinstance(outputs, list):
            expected_outputs = [
                str(name).strip()
                for name in outputs
                if str(name).strip().endswith(".md")
            ]
    if not expected_outputs:
        return []

    fresh_audit = scratchpad_is_fresh_audit(scratchpad)
    # Ship 8.2 semantic-minimum contract: no required literal heading
    # (findings are detected via `## Finding [` / `### Finding [` blocks or
    # a `## Findings` section), and the obligation-receipts section is NOT a
    # hard structural gate (receipt coverage is warning-only, owned by
    # `_check_opengrep_obligation_coverage`). FINDINGS_COUNT is informational.
    # The remaining hard checks: fresh marker present, last STATUS COMPLETE,
    # findings-or-rationale, no residual placeholders.
    structural_kwargs = dict(
        required_headings=(),
        placeholder_strings=_BREADTH_STRUCTURAL_PLACEHOLDERS,
    )

    agents = parse_breadth_manifest_agents(scratchpad) or []
    expected_owner_by_output: dict[str, str] = {}
    for idx, name in enumerate(expected_outputs):
        if idx < len(agents):
            owner = str(agents[idx].get("agent_id") or "").strip()
            if owner:
                expected_owner_by_output[name] = owner
    contract_jobs = contract.get("jobs")
    if isinstance(contract_jobs, list):
        for job in contract_jobs:
            if not isinstance(job, dict):
                continue
            output = str(job.get("output") or "").strip()
            owner = str(job.get("agent_id") or "").strip()
            if output and owner:
                expected_owner_by_output[output] = owner

    statuses: list[dict[str, Any]] = []
    for name in expected_outputs:
        status, reasons = _classify_artifact_row(
            scratchpad / name,
            fresh_audit=fresh_audit,
            min_bytes=phase.min_artifact_bytes,
            structural_kwargs=structural_kwargs,
        )
        if (
            status == _BREADTH_STATUS_COMPLETE
            and fresh_audit
            and _breadth_worker_pool_contract_active(scratchpad)
        ):
            ok, marker_reasons = validate_breadth_artifact_ownership(
                scratchpad / name,
                expected_output=name,
                expected_owner=expected_owner_by_output.get(name),
            )
            if not ok:
                status = _BREADTH_STATUS_STRUCTURAL_FAIL
                reasons = list(reasons) + marker_reasons
        statuses.append({"name": name, "status": status, "reasons": reasons})
    return statuses


def _depth_expected_outputs(phase: Phase) -> list[str]:
    """Return the canonical depth output filenames for the phase.

    Uses ``phase.example_tokens`` (the 4 standard depth roles --
    token_flow, state_trace, edge_case, external) when present, else
    the ``_DEPTH_CANONICAL_ROLES`` fallback. This is deterministic and
    independent of disk state, so a role whose file was never written
    is still expected (and therefore flagged MISSING) -- exactly the
    failure mode (observed in a prior run) the supervision loop must catch.
    """
    roles = list(getattr(phase, "example_tokens", None) or _DEPTH_CANONICAL_ROLES)
    return [f"depth_{role}_findings.md" for role in roles if role]


def compute_depth_row_statuses(
    scratchpad: Path, phase: Phase
) -> list[dict[str, Any]]:
    """Depth analog of ``compute_breadth_row_statuses`` (Ship 8).

    Returns per-row status for the canonical depth output files
    (``depth_<role>_findings.md`` for each role in the phase's
    ``example_tokens``). Same status vocabulary and marker semantics
    as breadth, via the shared ``_classify_artifact_row`` helper, but
    with DEPTH-appropriate structural kwargs:

      - NO ``## Findings`` required heading (depth uses ``### Finding
        [ID]`` blocks and a ``## Semantic Proof Checks`` section).
      - require COMPLETE marker + FINDINGS_COUNT + zero-findings
        rationale + no residual placeholders.
      - NO opengrep obligation-receipts requirement (depth agents do
        not own opengrep shards).

    Returns ``[]`` when no canonical roles can be derived (caller
    falls back to the legacy glob+quorum gate).
    """
    expected = _depth_expected_outputs(phase)
    contract = _read_depth_worker_pool_contract(scratchpad)
    expected_owner_by_output: dict[str, str] = {}
    if contract.get("phase") == "depth":
        contract_jobs = contract.get("jobs")
        if isinstance(contract_jobs, list):
            for job in contract_jobs:
                if not isinstance(job, dict):
                    continue
                output = str(job.get("output") or "").strip()
                owner = str(job.get("agent_id") or "").strip()
                if output and owner:
                    expected_owner_by_output[output] = owner
        outputs = contract.get("canonical_outputs")
        if isinstance(outputs, list):
            contract_expected = [
                str(name).strip()
                for name in outputs
                if str(name).strip().startswith("depth_")
                and str(name).strip().endswith("_findings.md")
            ]
            if contract_expected:
                expected = contract_expected
    if not expected:
        return []
    fresh_audit = scratchpad_is_fresh_audit(scratchpad)
    # Ship 8.2 semantic-minimum contract (same as breadth): findings are
    # detected via `### Finding [` / `## Finding [` blocks or a `## Findings`
    # section; FINDINGS_COUNT and obligation-receipts are no longer hard
    # gates. No required literal heading (depth uses `### Finding [ID]`).
    structural_kwargs = dict(
        required_headings=(),
        placeholder_strings=_DEPTH_STRUCTURAL_PLACEHOLDERS,
    )
    statuses: list[dict[str, Any]] = []
    for name in expected:
        status, reasons = _classify_artifact_row(
            scratchpad / name,
            fresh_audit=fresh_audit,
            min_bytes=phase.min_artifact_bytes,
            structural_kwargs=structural_kwargs,
        )
        if (
            status == _BREADTH_STATUS_COMPLETE
            and fresh_audit
            and _depth_worker_pool_contract_active(scratchpad)
        ):
            ok, marker_reasons = validate_depth_artifact_ownership(
                scratchpad / name,
                expected_output=name,
                expected_owner=expected_owner_by_output.get(name),
            )
            if not ok:
                status = _BREADTH_STATUS_STRUCTURAL_FAIL
                reasons = list(reasons) + marker_reasons
        if (
            status == _BREADTH_STATUS_COMPLETE
            and fresh_audit
            and name in {
                "depth_token_flow_findings.md",
                "depth_state_trace_findings.md",
            }
        ):
            try:
                text = (scratchpad / name).read_text(
                    encoding="utf-8", errors="replace"
                )
            except Exception:
                text = ""
            missing_perturbation = _missing_perturbation_block_ids(text)
            if missing_perturbation:
                status = _BREADTH_STATUS_STRUCTURAL_FAIL
                reasons = list(reasons) + [
                    "missing perturbation block(s) for Medium+ CONFIRMED "
                    f"finding(s): {', '.join(missing_perturbation[:5])}"
                ]
        statuses.append({"name": name, "status": status, "reasons": reasons})
    return statuses


def compute_verify_row_statuses(
    scratchpad: Path,
    phase_name: str,
    *,
    min_bytes: int = 100,
) -> list[dict[str, Any]]:
    """Return per-finding status for a manifest-driven verify shard.

    Verify shard outputs are dynamic (`verify_<finding_id>.md`) and derive
    from the queue shard manifest, not from `Phase.expected_artifacts`. This
    helper gives the PTY supervision loop the same row-level visibility breadth
    and depth already have, so a partial verifier shard can recover only the
    missing files instead of re-running the whole shard.
    """
    if phase_name in SC_VERIFY_PHASE_NAMES:
        shards = compute_sc_verify_shards(scratchpad)
    elif phase_name in L1_VERIFY_PHASE_NAMES:
        shards = compute_verify_shards(scratchpad)
    else:
        return []
    rows = shards.get(phase_name, [])
    statuses: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        fid = str(row.get("finding id") or "").strip()
        if not fid:
            continue
        name = f"verify_{fid}.md"
        present = _verify_file_present_for_id(
            scratchpad,
            fid,
            min_bytes=min_bytes,
        )
        statuses.append({
            "name": name,
            "finding_id": fid,
            "status": (
                _BREADTH_STATUS_COMPLETE
                if present
                else _BREADTH_STATUS_MISSING
            ),
            "reasons": [] if present else ["missing verifier file"],
            "row": row,
        })
    return statuses


def compute_phase_row_statuses(
    scratchpad: Path, phase: Phase
) -> list[dict[str, Any]]:
    """Dispatch to the per-phase row-status helper for a supervised
    spawned-worker phase. Returns ``[]`` for any phase that is not
    supervised (the supervision loop and gate then fall back to their
    legacy paths). Ship 8 dispatcher: breadth -> breadth helper,
    depth -> depth helper.
    """
    if phase.name == "breadth":
        return compute_breadth_row_statuses(scratchpad, phase)
    if phase.name == "depth":
        return compute_depth_row_statuses(scratchpad, phase)
    if phase.name in L1_VERIFY_PHASE_NAMES or phase.name in SC_VERIFY_PHASE_NAMES:
        return compute_verify_row_statuses(
            scratchpad,
            phase.name,
            min_bytes=max(100, getattr(phase, "min_artifact_bytes", 0) or 0),
        )
    return []


def _aggregate_supervised_row_statuses(
    phase: Phase,
    row_statuses: list[dict[str, Any]],
    scratchpad: Path,
    artifact_label: str,
) -> Optional[str]:
    """Aggregate per-row statuses into a single gate failure-detail
    string, or ``None`` when every row passes.

    Shared by the breadth and depth gate branches (Ship 8). Emits the
    ``legacy-unmarked-artifact`` and ``in-progress-tolerated-legacy``
    warning logs as a side effect, exactly as the Ship 3/6 breadth
    block did. ``artifact_label`` is the glob shown in the failure
    message (e.g. ``analysis_*.md`` or ``depth_*_findings.md``).

    Legacy/resumed scratchpads (no fresh-audit sentinel) never block on
    in_progress rows -- they are downgraded to tolerated warnings, so
    resumed audits keep forward progress.
    """
    fresh_audit = scratchpad_is_fresh_audit(scratchpad)
    missing_expected: list[str] = []
    stub_expected: list[str] = []
    in_progress_expected: list[str] = []
    structural_fail_expected: list[tuple[str, list[str]]] = []
    legacy_unmarked_expected: list[str] = []
    for row in row_statuses:
        s = row.get("status")
        n = row.get("name", "")
        if s == _BREADTH_STATUS_MISSING:
            missing_expected.append(n)
        elif s == _BREADTH_STATUS_STUB:
            stub_expected.append(n)
        elif s == _BREADTH_STATUS_IN_PROGRESS:
            in_progress_expected.append(n)
            if "legacy-unmarked on fresh audit" in (row.get("reasons") or []):
                legacy_unmarked_expected.append(n)
        elif s == _BREADTH_STATUS_STRUCTURAL_FAIL:
            structural_fail_expected.append((n, row.get("reasons") or []))
        elif s == _BREADTH_STATUS_LEGACY_UNMARKED:
            legacy_unmarked_expected.append(n)
        # _BREADTH_STATUS_COMPLETE -> no action

    if legacy_unmarked_expected:
        # Split by whether the unmarked file ACTUALLY blocks. A file is only in
        # in_progress_expected when it was classified IN_PROGRESS (a live Claude
        # PTY worker on a fresh audit may still be mid-write -> blocks). A file
        # classified LEGACY_UNMARKED is NON-blocking: either a resumed scratchpad
        # (marker lost to compaction) OR a codex single-subprocess run (codex
        # never writes the PLAMEN marker; a RETURNED subprocess produced a final
        # file). Do NOT alarm the operator with "treated as IN_PROGRESS" text for
        # the non-blocking case — that misread looked like a failure.
        _in_prog_set = set(in_progress_expected)
        tolerated_unmarked = [n for n in legacy_unmarked_expected if n not in _in_prog_set]
        blocking_unmarked = [n for n in legacy_unmarked_expected if n in _in_prog_set]
        if tolerated_unmarked:
            sample = ", ".join(tolerated_unmarked[:12])
            if len(tolerated_unmarked) > 12:
                sample += f", ... (+{len(tolerated_unmarked) - 12} more)"
            log.info(
                f"[gate_passes] {phase.name}: legacy-unmarked-artifact "
                f"(tolerated, non-blocking -- no PLAMEN marker; codex "
                f"single-subprocess or resumed scratchpad): {sample}"
            )
        if blocking_unmarked:
            sample = ", ".join(blocking_unmarked[:12])
            if len(blocking_unmarked) > 12:
                sample += f", ... (+{len(blocking_unmarked) - 12} more)"
            log.warning(
                f"[gate_passes] {phase.name}: legacy-unmarked-artifact "
                f"(fresh-audit scratchpad; treated as IN_PROGRESS for "
                f"continuation): {sample}"
            )

    # Ship 8.18: explicit IN_PROGRESS (a file carrying PLAMEN markers but not
    # COMPLETE) must NEVER pass -- not even on a resumed/legacy scratchpad. An
    # actively-incomplete file means work was started and not finished; resume
    # must finish it, not skip it. (Previously ALL in_progress rows were
    # downgraded to a tolerated warning on non-fresh audits, letting incomplete
    # work pass the gate.) legacy-UNMARKED files (no markers at all) remain
    # tolerated on resume: they are classified _BREADTH_STATUS_LEGACY_UNMARKED
    # (never in_progress here) and are non-blocking via the warning above.
    if not fresh_audit and in_progress_expected:
        log.warning(
            f"[gate_passes] {phase.name}: explicit IN_PROGRESS artifact(s) on "
            f"a resumed scratchpad now BLOCK (Ship 8.18): "
            f"{', '.join(in_progress_expected[:12])}"
        )

    if not (
        missing_expected
        or stub_expected
        or in_progress_expected
        or structural_fail_expected
    ):
        return None

    detail = []
    if missing_expected:
        sample = ", ".join(missing_expected[:12])
        if len(missing_expected) > 12:
            sample += f", ... (+{len(missing_expected) - 12} more)"
        detail.append(f"missing: {sample}")
    if stub_expected:
        sample = ", ".join(stub_expected[:12])
        if len(stub_expected) > 12:
            sample += f", ... (+{len(stub_expected) - 12} more)"
        detail.append(f"stub: {sample}")
    if in_progress_expected:
        sample = ", ".join(in_progress_expected[:12])
        if len(in_progress_expected) > 12:
            sample += f", ... (+{len(in_progress_expected) - 12} more)"
        detail.append(f"in_progress: {sample}")
    if structural_fail_expected:
        samples = []
        for n, reasons in structural_fail_expected[:6]:
            first_reason = reasons[0] if reasons else "structural fail"
            samples.append(f"{n} ({first_reason})")
        sample = "; ".join(samples)
        if len(structural_fail_expected) > 6:
            sample += f"; ... (+{len(structural_fail_expected) - 6} more)"
        detail.append(f"structural_fail: {sample}")
    return (
        f"{artifact_label} manifest-exact incomplete "
        f"({len(row_statuses)} expected; {'; '.join(detail)})"
    )


# Ship C (fixes SW04-4): accept hyphen and dot in the slug
# (analysis_percontract_core-vault.md, analysis_percontract_v1.2.md). The old
# `[A-Za-z0-9_]+` silently dropped such declared filenames from the exact gate,
# and when ALL declared names were non-matching the gate fell back to the
# permissive glob -- defeating the Ship 8.17 exact gate. Mirrors the
# plamen_contracts._RESCAN_OUTPUT_RE character class.
_RESCAN_MANIFEST_FILE_RE = re.compile(
    r"\b(analysis_(?:rescan|percontract)_[A-Za-z0-9][A-Za-z0-9_.\-]*\.md)\b"
)


def _parse_rescan_manifest_files(text: str) -> list[str]:
    """Extract the concrete output filenames a rescan coordinator declared in
    rescan_manifest.md. Matches the two rescan output families with a literal
    suffix (analysis_rescan_<id>.md, analysis_percontract_<id>.md, including
    analysis_percontract_scope_review.md). Glob exemplars like
    `analysis_rescan_*.md` are intentionally NOT matched (the `*` is not a
    word char), so a manifest that only shows the glob form declares nothing
    and the caller falls back to the legacy glob gate.
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in _RESCAN_MANIFEST_FILE_RE.findall(text or ""):
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _rescan_manifest_exact_missing(
    scratchpad: Path, phase: Phase
) -> Optional[list[str]]:
    """Ship 8.17 (Option A): bounded exact rescan completion gate.

    When ``rescan_manifest.md`` exists and declares concrete output files, this
    is the AUTHORITATIVE rescan gate: return the declared files that are
    missing or not substantive (``< phase.min_artifact_bytes``). An empty list
    means every declared file is present and substantive.

    Returns ``None`` when ``rescan_manifest.md`` is ABSENT or declares no
    parseable files -- the caller then falls back to the legacy glob/quorum
    gate, so old or in-flight runs (no manifest) never false-fail. This ship
    deliberately does NOT require PLAMEN markers for rescan (presence + size
    only); supervised missing-only continuation is a later Option B.
    """
    manifest = scratchpad / "rescan_manifest.md"
    fresh_audit = scratchpad_is_fresh_audit(scratchpad)
    if not manifest.exists():
        return None
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    declared = _parse_rescan_manifest_files(text)
    if not declared:
        return None
    min_bytes = max(phase.min_artifact_bytes, 1000) if fresh_audit else phase.min_artifact_bytes
    missing: list[str] = []
    if fresh_audit and not any(
        name.startswith("analysis_percontract_") for name in declared
    ):
        missing.append(
            "rescan_manifest.md declares no concrete analysis_percontract_*.md file"
        )
    for name in declared:
        p = scratchpad / name
        try:
            if not p.exists() or p.stat().st_size < min_bytes:
                missing.append(name)
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
            markers = {
                m.group(1).strip().upper(): m.group(2).strip().upper()
                for m in re.finditer(
                    r"<!--\s*PLAMEN_([A-Z_]+):\s*([^>]+?)\s*-->",
                    text,
                )
            }
            # An EXPLICIT non-COMPLETE STATUS marker (e.g. IN_PROGRESS) is a
            # deliberate "worker not done" signal — shipping it as complete
            # would risk delivering partial rescan output (a silent-incomplete
            # recall loss). This is intentional protection, NOT a timing race:
            # the genuine mid-flush race is when NO STATUS marker is present yet
            # (the `markers and ...` guard already skips that case, deferring to
            # presence+size+structural). So a present non-COMPLETE STATUS keeps
            # blocking. See test_ship_8_17_rescan_exact_gate.py.
            if markers and markers.get("STATUS") != "COMPLETE":
                missing.append(f"{name} has PLAMEN_STATUS != COMPLETE")
                continue
            if fresh_audit or markers:
                ok, reasons = _structural_completeness_ok(
                    p,
                    required_headings=(),
                    placeholder_strings=("TODO", "FILL_ME", "<placeholder>"),
                )
                if not ok:
                    missing.append(f"{name} structural_fail: {'; '.join(reasons[:3])}")
        except OSError:
            missing.append(name)
    return missing


def gate_passes(scratchpad: Path, project_root: str, phase: Phase) -> tuple:
    """Return (passed, missing). Two-mode gate:
    - Explicit filename (no glob wildcards): THAT file must exist and be
      >= min_artifact_bytes. A stub fails the pattern.
    - Glob pattern (contains `*` or `?`): at least `min_artifacts_count`
      matching files must be >= min_artifact_bytes. Default count is 1
      (any substantial match passes — permissive). Critical phases set
      count >= 3 to catch silent degradations where one solo agent writes
      while the other N-1 are never spawned (manifest-aware quorum).
    """
    missing = []
    if not phase.expected_artifacts and not getattr(phase, "any_of", None):
        if phase.name in L1_VERIFY_PHASE_NAMES or phase.name in SC_VERIFY_PHASE_NAMES:
            missing.extend(_verify_shard_gate_missing(scratchpad, phase.name, min_bytes=phase.min_artifact_bytes))
        else:
            log.warning(
                f"[gate_passes] {phase.name}: no expected_artifacts and no any_of — "
                f"vacuous pass (phase may be misconfigured)"
            )
    # Ship 8.17 (Option A): when the rescan coordinator declared its planned
    # outputs in rescan_manifest.md, that manifest is the AUTHORITATIVE gate --
    # every declared file must exist and be substantive. This closes the weak
    # glob/quorum hole where a partial rescan (coordinator intended N files,
    # only some landed) passed on >=1 matching file. When the manifest is
    # absent/empty, fall through to the legacy glob loop (no false-fail on
    # old/in-flight runs). PLAMEN markers are intentionally NOT required here.
    if phase.name == "rescan":
        rescan_missing = _rescan_manifest_exact_missing(scratchpad, phase)
        if rescan_missing is not None:
            return (len(rescan_missing) == 0), rescan_missing
        if scratchpad_is_fresh_audit(scratchpad):
            return False, [
                "rescan_manifest.md missing or declares no concrete "
                "analysis_rescan_*.md / analysis_percontract_*.md files"
            ]
    for pattern in phase.expected_artifacts:
        if pattern == "AUDIT_REPORT.md":
            p = Path(project_root) / "AUDIT_REPORT.md"
            if not p.exists() or p.stat().st_size < phase.min_artifact_bytes:
                missing.append(pattern)
            continue
        if phase.name == "breadth" and pattern == "analysis_*.md":
            row_statuses = compute_breadth_row_statuses(scratchpad, phase)
            if row_statuses:
                # The manifest is the authoritative breadth contract.
                # Aggregate per-row statuses (Ship 6 helper, byte-equivalent
                # to the Ship 3 inline logic) instead of the legacy
                # min_artifacts_count quorum.
                detail = _aggregate_supervised_row_statuses(
                    phase, row_statuses, scratchpad, "analysis_*.md"
                )
                if detail:
                    missing.append(detail)
                continue
        if phase.name == "depth" and pattern == "depth_*_findings.md":
            # Ship 8: marker-aware depth gate on FRESH audits only. The
            # canonical 4 depth role files (from phase.example_tokens)
            # must each be COMPLETE + structurally sound. Legacy/resumed
            # depth audits fall through to the existing glob+quorum
            # below (no behavior change for in-flight audits, and no
            # canonical-role tightening that the old quorum did not
            # enforce).
            if scratchpad_is_fresh_audit(scratchpad):
                row_statuses = compute_depth_row_statuses(scratchpad, phase)
                if row_statuses:
                    detail = _aggregate_supervised_row_statuses(
                        phase, row_statuses, scratchpad, "depth_*_findings.md"
                    )
                    if detail:
                        missing.append(detail)
                    continue
            # Legacy audit OR no canonical roles -> fall through to the
            # generic glob+quorum path (min_artifacts_count).
        is_glob = any(ch in pattern for ch in "*?[")
        matches = list(scratchpad.glob(pattern))
        if phase.name == "breadth" and pattern == "analysis_*.md":
            matches = [
                m for m in matches
                if not (
                    m.name.startswith("analysis_rescan_")
                    or m.name.startswith("analysis_percontract_")
                )
            ]
        if not matches:
            missing.append(pattern)
            continue
        if is_glob:
            substantial = [m for m in matches
                           if m.stat().st_size >= phase.min_artifact_bytes]
            needed = max(1, phase.min_artifacts_count)
            if len(substantial) < needed:
                missing.append(
                    f"{pattern} (quorum: {len(substantial)}/{needed} substantial)"
                )
        else:
            # location_recovery.md may be a legitimate N/A skip-summary. When
            # `_location_recovery_needed` is false, the driver writes a ~75-byte
            # `_write_location_recovery_skip` output ("SKIPPED: all inventory
            # locations resolve mechanically"). That is BELOW min_artifact_bytes
            # but is a valid terminal artifact — treating it as "(stub only)"
            # makes every resume rewind location_recovery (and the downstream
            # invariants/invariants_p2 it gates). Recognize the skip-summary
            # exactly the way the empty-verify short-circuit recognizes valid
            # terminal states. Genuinely missing/empty/other-broken files still
            # fail below (no "SKIPPED ... resolve mechanically" marker present).
            if phase.name == "location_recovery" and pattern == "location_recovery.md":
                try:
                    _lr_text = matches[0].read_text(
                        encoding="utf-8", errors="replace"
                    ).lower()
                except Exception:
                    _lr_text = ""
                if "skipped" in _lr_text and "resolve mechanically" in _lr_text:
                    # Valid N/A skip-summary — passing terminal artifact.
                    continue
            # Strict: single explicit filename — it must be substantial
            if matches[0].stat().st_size < phase.min_artifact_bytes:
                missing.append(pattern + " (stub only)")

    # any_of: ALL outer groups must be satisfied; within an outer group,
    # AT LEAST ONE pattern must have a substantial match. This decouples
    # the gate from naming-convention flux (e.g. verify_F_*.md vs
    # verify_F-*.md — either shape alone means the LLM wrote verifiers).
    for group_idx, or_group in enumerate(getattr(phase, "any_of", []) or []):
        group_satisfied = False
        for pattern in or_group:
            matches = list(scratchpad.glob(pattern))
            if not matches:
                continue
            substantial = [m for m in matches
                           if m.stat().st_size >= phase.min_artifact_bytes]
            if substantial:
                group_satisfied = True
                break
        if not group_satisfied:
            missing.append(
                f"any_of[{group_idx}]: none of {or_group} matched substantially"
            )
    return (not missing, missing)


def _codebase_is_complex(scratchpad: Path) -> bool:
    """Complex tier per phase2-instantiate Step 2a: >10 in-scope contracts OR
    >5000 total lines, computed from contract_inventory.md.

    Conservative: if the inventory is absent/unparseable, return False — do NOT
    enforce the breadth floor on missing data (avoids a false instantiate halt).
    Total-lines is the primary, reliable signal; contract count (excluding clear
    interface/mock/test-dir files) is secondary. v2.8.14.
    """
    inv = scratchpad / "contract_inventory.md"
    if not inv.exists():
        return False
    try:
        text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    lines_idx: Optional[int] = None
    total_lines = 0
    contracts = 0
    for ln in text.splitlines():
        s = ln.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells or all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        low = [c.lower() for c in cells]
        if lines_idx is None:
            if "lines" in low:
                lines_idx = low.index("lines")
            continue  # header row consumed
        name = cells[0]
        path = (cells[1].lower() if len(cells) > 1 else "")
        lv: Optional[int] = None
        if lines_idx < len(cells) and re.fullmatch(r"[\d,]+", cells[lines_idx]):
            lv = int(cells[lines_idx].replace(",", ""))
        if lv is None:
            for c in cells:
                if re.fullmatch(r"[\d,]+", c):
                    lv = int(c.replace(",", ""))
                    break
        if lv is None:
            continue
        total_lines += lv
        is_aux = (
            "interface" in path or "/mock" in path or "mock/" in path
            or "/test/" in path or "/tests/" in path
            or re.match(r"I[A-Z]", name) is not None  # IFoo.sol interface convention
        )
        if not is_aux:
            contracts += 1
    return total_lines > 5000 or contracts > 10


# v2.8.17: non-skill Template tokens that are valid in an AGENT row but have
# no SKILL.md BY DESIGN — the GENERAL floor-fill sentinel (phase2-instantiate
# Step 2a.3) and the always-required baseline focus areas. Mirrors the driver's
# _SC_SKILL_INJECT_EXCLUDE so the fabricated-template gate and the injector
# agree on what is "not a real skill but not an error".
_NON_SKILL_TEMPLATE_TOKENS = frozenset({
    "GENERAL", "GENERAL_ANALYSIS", "CUSTOM", "CUSTOM_FOCUS",
    "CORE_STATE", "ACCESS_CONTROL",
    "FORK_ANCESTRY", "VERIFICATION_PROTOCOL", "MOVE_SAFETY_CORE_DIRECTIVES",
})


def _skill_template_resolves(token: str) -> bool:
    """True if an UPPER_SNAKE skill-template name has a SKILL.md in ANY SC
    skill tree (language/injectable/niche). Mirrors driver's
    _sc_skill_path_for_name existence check (searched across all trees, since
    a shared skill resolves regardless of which language dir it lives in)."""
    slug = str(token or "").strip().strip("`").lower().replace("_", "-")
    if not slug:
        return False
    base = plamen_home() / "agents" / "skills"
    for sub in ("evm", "solana", "aptos", "sui", "soroban",
                "injectable", "niche", "injectable/l1"):
        if (base / sub / slug / "SKILL.md").exists():
            return True
    return False


def _manifest_fabricated_templates(scratchpad: Path) -> list[str]:
    """Return `agent_id:TOKEN` for each spawned breadth AGENT row whose
    Template column names a skill-like token (UPPER_SNAKE) that resolves to NO
    SKILL.md and is not a recognized non-skill sentinel/baseline.

    This catches `instantiate` inventing skill names to satisfy the breadth
    floor (phase2-instantiate Step 2a.3) — e.g. REWARD_ACCOUNTING /
    GAME_LOGIC_CORRECTNESS — which silently drop methodology. Combined cells
    ("A + B") are split. Fails soft to [] on any parse problem.
    """
    p = scratchpad / "spawn_manifest.md"
    if not p.exists():
        return []
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    fabricated: list[str] = []
    headers: list[str] = []
    in_table = False
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
        req = (row.get("required") or row.get("required_")
               or row.get("required?") or "")
        if req and re.match(r"(?i)^(?:no|n|false|skip|optional|merged)\b",
                            req.strip()):
            continue
        if not _manifest_row_is_spawned_breadth_agent(row, cells):
            continue
        template = _strip_md(row.get("template", "") or "").strip()
        agent_id = _strip_md(row.get("agent_id", "")
                             or row.get("agent", "")).strip() or "?"
        for tok in re.split(r"\s*(?:\+|,|;|/|\band\b)\s*", template,
                            flags=re.IGNORECASE):
            t = re.sub(r"\s*\([^)]*\)\s*$", "", tok).strip().strip("`")
            T = t.upper().replace(" ", "_")
            if not re.match(r"^[A-Z][A-Z0-9_]+$", T):
                continue
            if T in _NON_SKILL_TEMPLATE_TOKENS:
                continue
            if _skill_template_resolves(T):
                continue
            fabricated.append(f"{agent_id}:{T}")
    return fabricated


def _validate_spawn_manifest_schema(scratchpad: Path, mode: str = "core") -> list[str]:
    """Validate the Phase 2 manifest at the producer boundary.

    `spawn_manifest.md` is the contract consumed by breadth. Letting
    `instantiate` complete with a table-ish but unparseable manifest shifts
    a producer bug into the next phase and creates misleading breadth retry
    loops. This validator uses the same canonical parser as the breadth gate
    so the schema is accepted or rejected exactly once, at the artifact owner.
    """
    path = scratchpad / "spawn_manifest.md"
    if not path.exists():
        return ["spawn_manifest.md missing"]
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return [f"spawn_manifest.md unreadable: {exc}"]
    if path.stat().st_size < 50:
        return ["spawn_manifest.md is a stub (<50 bytes)"]

    # Scope the forbidden-filename scan to PIPE-DELIMITED ROWS of a
    # markdown table only. Pre-fix, this regex ran against the entire
    # file body — including bullet-list prose where the LLM helpfully
    # explained "do NOT include these artifacts" with the filenames as
    # examples. A prior audit halted on this exact false
    # positive: spawn_manifest.md had a `## Phase 3b/3c Artifacts (NOT
    # breadth AGENT rows)` section that explicitly clarified the rules,
    # and the prose `- analysis_rescan_*.md → Phase 3b ...` lines made
    # the validator fail.
    #
    # The actual contract violation we care about is: a forbidden
    # filename appearing in a markdown TABLE ROW (i.e. inside `| ... |`
    # cells), which is how the LLM would actually try to schedule a
    # non-breadth artifact. Prose mentions, bullet points, and code
    # fences are all fine.
    forbidden_pattern = re.compile(
        r"\b(?:verify_[A-Za-z0-9_.-]*|analysis_rescan_[A-Za-z0-9_.-]+|"
        r"analysis_percontract_[A-Za-z0-9_.-]+|analysis_merged_into_[A-Za-z0-9_.-]+)\.md\b"
    )
    forbidden_set: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        # A row of a markdown table: leading `|` AND at least one more
        # `|` separating cells. This excludes prose bullets (`-`),
        # numbered lists (`1.`), and free paragraphs.
        if not (stripped.startswith("|") and stripped.count("|") >= 2):
            continue
        # Also skip markdown table separators (`|---|---|...`)
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and all(set(c) <= {"-", ":", " "} for c in cells):
            continue
        for m in forbidden_pattern.finditer(stripped):
            forbidden_set.add(m.group(0))
    forbidden = sorted(forbidden_set)
    outputs = parse_breadth_manifest_outputs(scratchpad)
    count = parse_breadth_manifest_count(scratchpad)
    if outputs and count:
        issues: list[str] = []
        if forbidden:
            issues.append(
                "spawn_manifest.md contains non-breadth artifact row(s): "
                + ", ".join(forbidden[:8])
            )
        if len(outputs) != count:
            issues.append(
                "spawn_manifest.md maps spawned breadth agents to "
                f"{len(outputs)} unique output file(s) for {count} spawned "
                "agent row(s); each spawned agent needs a distinct "
                "analysis_*.md output"
            )
        # v2.8.14: enforce the Complex-tier breadth FLOOR. The merge hierarchy
        # (300-line cap) can otherwise collapse breadth below the tier floor —
        # on PulsechainGameWards a Complex codebase got 5 breadth agents instead
        # of the documented 7-9, merging away whole lenses (NFT/economic/
        # centralization). Distinct lenses are a recall-protection on big audits.
        is_complex = _codebase_is_complex(scratchpad)
        # The Complex-tier breadth floor (>=7) is a Core/Thorough recall
        # protection. LIGHT mode deliberately runs 3-4 breadth agents per the
        # AUDIT MODES table, so enforcing the floor there would false-fail a
        # correctly-sized Light manifest. Gate the floor to Core/Thorough only;
        # any non-core/thorough mode (light, and unknown modes) skips it.
        if count < 7 and is_complex and mode in ("core", "thorough"):
            issues.append(
                f"breadth tier floor: codebase is Complex (>10 in-scope "
                f"contracts or >5000 total lines per contract_inventory.md) but "
                f"spawn_manifest declares only {count} breadth AGENT row(s); the "
                f"Complex tier requires >=7 (phase2-instantiate Step 2a). Reach "
                f">=7 per Step 2a.3 floor-fill: split a real skill's scope across "
                f"agents, bind the closest real skill, or use Template `GENERAL` "
                f"— do NOT invent skill names and do NOT merge below the floor."
            )
        # v2.8.17: reject FABRICATED skill templates on COMPLEX codebases — the
        # breadth-floor-fill scenario where instantiate invents names (e.g.
        # REWARD_ACCOUNTING) to reach >=7 agents, silently dropping methodology.
        # Scoped to Complex so it never false-fires on simple/test manifests that
        # use placeholder template names; non-complex fabrication is still
        # surfaced by the driver's binding-loss warning. Soft/retry-driven;
        # GENERAL is the valid escape, so there is no halt loop.
        fabricated = _manifest_fabricated_templates(scratchpad) if is_complex else []
        if fabricated:
            issues.append(
                "spawn_manifest.md binds fabricated skill template(s) "
                + ", ".join(sorted(set(fabricated))[:8])
                + " — these resolve to no SKILL.md (phase2-instantiate Step "
                "2a.3). Bind the closest REAL skill from skill-index.md / "
                "template_recommendations.md (split scope or closest-fit) or use "
                "Template `GENERAL` for a skill-less focus agent; never invent a "
                "template name."
            )
        if not issues:
            return []
        return issues

    has_table = any(
        line.strip().startswith("|")
        and "template" in line.lower()
        and "required" in line.lower()
        for line in text.splitlines()
    )
    if not has_table:
        log.warning(
            "[_validate_spawn_manifest_schema] spawn_manifest.md lacks "
            "recognizable table header with Template and Required columns "
            "— LLM prose check (soft)"
        )

    suffix = ""
    if forbidden:
        suffix = "; non-breadth artifact rows present: " + ", ".join(forbidden[:8])
    return [
        "spawn_manifest.md schema invalid: no parseable spawned breadth-agent "
        "rows. Required rows must identify spawned agents and derive or name "
        "first-pass analysis_*.md outputs" + suffix
    ]


def _verification_queue_parity_sets(
    scratchpad: Path,
) -> tuple[set[str], set[str], set[str], set[str]]:
    """Compute the ID sets used by verification-queue<->inventory parity.

    Returns (inventory_ids, active_ids, mapped_hypos, acknowledged) using the
    SAME hypothesis-expansion + evidence-excluded + semantic-dedup
    acknowledgement logic the parity validator relies on. Side-effect-free.

    Raises on inventory parse failure so callers can surface a parse-error
    issue distinct from a clean empty inventory.
    """
    inv_path = scratchpad / "findings_inventory.md"
    inventory_ids = {
        _normalize_finding_id(b.get("id", ""))
        for b in _inventory_blocks(inv_path.read_text(encoding="utf-8", errors="replace"))
    }
    inventory_ids.discard("")

    active_ids = {
        _normalize_finding_id(r.get("finding id", ""))
        for r in parse_verification_queue_rows(scratchpad)
    }
    active_ids.discard("")

    # v2.4.9: hypothesis-aware expansion.  _dedup_queue_by_hypothesis collapses
    # INV-NNN rows into H-N representative rows.  Expand H-N/CH-N back to their
    # constituent INV-NNN IDs so the parity check works across ID namespaces.
    hypo_map = _parse_hypothesis_constituents(scratchpad)
    expanded_ids: set[str] = set(active_ids)
    mapped_hypos: set[str] = set()
    for aid in active_ids:
        constituents = hypo_map.get(aid, [])
        if constituents:
            mapped_hypos.add(aid)
            for cid in constituents:
                norm = _normalize_finding_id(cid) or cid.upper()
                if norm:
                    expanded_ids.add(norm)

    excluded_ids: set[str] = set()
    excluded_path = scratchpad / "verification_queue_evidence_excluded.md"
    if excluded_path.exists():
        try:
            text = excluded_path.read_text(encoding="utf-8", errors="replace")
            headers, rows = _parse_markdown_table(text, ["severity"])
            if headers:
                headers_lc = [h.strip().lower() for h in headers]
                fid_idx = next(
                    (
                        i for i, h in enumerate(headers_lc)
                        if _match_canonical_header(h) == "finding id"
                    ),
                    -1,
                )
                if fid_idx >= 0:
                    for row in rows:
                        if fid_idx < len(row):
                            excluded_ids.add(_normalize_finding_id(row[fid_idx]))
        except Exception:
            pass
    excluded_ids.discard("")
    expanded_excluded_ids: set[str] = set(excluded_ids)
    for eid in excluded_ids:
        constituents = hypo_map.get(eid, [])
        for cid in constituents:
            norm = _normalize_finding_id(cid) or cid.upper()
            if norm:
                expanded_excluded_ids.add(norm)

    dedup_acknowledged_ids = _collect_semantic_dedup_acknowledged_ids(scratchpad)
    acknowledged = expanded_ids | expanded_excluded_ids | dedup_acknowledged_ids
    return inventory_ids, active_ids, mapped_hypos, acknowledged


def _compute_unrouted_inventory_ids(scratchpad: Path) -> list[str]:
    """Return sorted normalized inventory IDs not routed/excluded/deduped.

    Side-effect-free. This is the exact "missing" set
    `_validate_verification_queue_inventory_parity` reports as a dropout, so
    a mechanical backfill of these IDs makes parity hold deterministically.

    Returns [] if findings_inventory.md is missing or unparseable (those are
    distinct failures owned by the parity validator's issue strings).
    """
    inv_path = scratchpad / "findings_inventory.md"
    if not inv_path.exists():
        return []
    try:
        inventory_ids, _active, _mapped, acknowledged = _verification_queue_parity_sets(
            scratchpad
        )
    except Exception:
        return []
    if not inventory_ids:
        return []
    return sorted(inventory_ids - acknowledged)


def _resolve_inventory_floor_builder():
    """Opportunistically resolve the B1 inventory floor builder WITHOUT
    creating a validators -> mechanical import dependency.

    The dependency-direction invariant (test_modularization.DIRECTION) forbids
    `plamen_validators` from importing the mechanical module — mechanical sits
    ABOVE validators and imports validators at module load, so a static or
    function-local reverse import of mechanical would be a layering violation
    (and a load-time cycle). The floor builder nonetheless lives in mechanical
    (it composes mechanical-owned rendering with parser-owned merging).

    Resolution rule: look the builder up in `sys.modules` ONLY. At driver
    runtime mechanical is always already imported (it imports us), so the
    builder is present and the B2 fallback works. In an isolated unit test that
    loaded the mechanical module (as the B1/B2 controls do) it is likewise
    present. If mechanical is genuinely not loaded, this returns
    None and the caller surfaces the honest "missing inventory" error rather
    than silently skipping — it never fabricates a dependency.

    Returns the `ensure_findings_inventory_floor` callable, or None.
    """
    import sys as _sys

    mech = _sys.modules.get("plamen_mechanical")
    builder = getattr(mech, "ensure_findings_inventory_floor", None)
    return builder if callable(builder) else None


def _validate_verification_queue_inventory_parity(
    scratchpad: Path, floor_builder=None
) -> list[str]:
    """Ensure every inventory ID is routed to verify or explicitly excluded.

    Evidence filtering is allowed to suppress rows only by writing
    verification_queue_evidence_excluded.md. Anything else is a promotion
    dropout and must halt before verification.

    `floor_builder` (B2): an optional `ensure_findings_inventory_floor`-shaped
    callable injected by the driver (which legitimately imports mechanical). When
    omitted, the builder is resolved opportunistically from `sys.modules` via
    `_resolve_inventory_floor_builder` so this layer never statically depends on
    mechanical.
    """
    inv_path = scratchpad / "findings_inventory.md"

    # B2 verify graceful fallback (ROOT, validator-level): a missing OR
    # present-but-empty findings_inventory.md must NOT be a terminal hard-fail
    # whenever real findings still exist on disk in the completed breadth/depth/
    # chunk artifacts. Reconstruct honestly via the B1 inventory floor BEFORE
    # returning the "missing" error, so verification proceeds on the real
    # findings instead of silently skipping them. The floor:
    #   * is a NO-OP when a usable inventory already exists (no clobber),
    #   * NEVER fabricates a finding (only carries forward findings that
    #     actually appear in a source artifact), and
    #   * writes a structurally valid EMPTY inventory for a genuinely empty
    #     audit (0 findings anywhere) -> clean empty path, not a crash.
    # Only if the floor itself cannot put a usable file on disk AND the audit is
    # genuinely empty do we treat it as the valid empty path (return []). A hard
    # terminal "missing" is returned only when reconstruction was attempted and
    # still left no inventory file at all (an unexpected failure worth halting
    # on, not a silent skip).
    def _inventory_usable() -> bool:
        if not inv_path.exists():
            return False
        try:
            txt = inv_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return False
        try:
            return len(_inventory_blocks(txt)) > 0
        except Exception:
            return False

    if not _inventory_usable():
        # B2: reconstruct via the injected (or opportunistically-resolved) B1
        # floor builder. No static reverse import of the mechanical module here
        # — that would violate the validators -> mechanical dependency-direction
        # invariant and reintroduce the module-load cycle.
        floor_n = 0
        floor_src = 0
        builder = floor_builder or _resolve_inventory_floor_builder()
        if builder is None:
            # Mechanical not loaded and no builder injected: we cannot honestly
            # reconstruct. Surface the missing-inventory error rather than
            # silently skipping — recall-safe (never fabricate, never hide).
            return ["verification queue parity: findings_inventory.md missing"]
        try:
            floor_n, floor_src = builder(scratchpad)
        except Exception as exc:
            log.error(
                "[verify_queue parity] inventory floor reconstruction raised: "
                f"{exc!r}"
            )
        if floor_n > 0:
            log.warning(
                "[verify_queue parity] findings_inventory.md was missing/empty; "
                f"B1 floor reconstructed {floor_n} finding(s) from {floor_src} "
                "source artifact(s) -- proceeding on the honest reconstructed "
                "inventory (DEGRADED, not terminal)"
            )
        elif inv_path.exists():
            # Floor ran and wrote a valid (empty) inventory: genuinely empty
            # audit. Clean empty path -- no IDs to route, no dropout.
            log.warning(
                "[verify_queue parity] findings_inventory.md was missing/empty "
                f"and {floor_src} source artifact(s) yielded 0 findings "
                "(genuinely empty audit); valid empty inventory on disk -- "
                "clean empty path"
            )
            return []
        else:
            # Reconstruction could not even place a file on disk: surface a hard
            # error so the unexpected failure is visible, never silently skipped.
            return ["verification queue parity: findings_inventory.md missing"]

    try:
        inventory_ids, active_ids, mapped_hypos, acknowledged = (
            _verification_queue_parity_sets(scratchpad)
        )
    except Exception as exc:
        return [f"verification queue parity: inventory parse failed: {exc}"]
    if not inventory_ids:
        return []

    missing = sorted(inventory_ids - acknowledged)
    extra = sorted((active_ids - mapped_hypos) - inventory_ids)
    issues: list[str] = []
    if missing:
        sample = ", ".join(missing[:10])
        more = f" (+{len(missing) - 10} more)" if len(missing) > 10 else ""
        issues.append(
            f"verification queue dropout: {len(missing)} inventory ID(s) "
            "absent from active queue, evidence-excluded queue, and semantic "
            f"dedup receipt: {sample}{more}"
        )
    if len(acknowledged) < len(inventory_ids):
        issues.append(
            f"verification queue coverage: acknowledged {len(acknowledged)}/"
            f"{len(inventory_ids)} inventory IDs"
        )
    if extra:
        sample = ", ".join(extra[:10])
        more = f" (+{len(extra) - 10} more)" if len(extra) > 10 else ""
        issues.append(
            f"verification queue has {len(extra)} ID(s) not present in inventory: "
            f"{sample}{more}"
        )
    return issues


def _collect_semantic_dedup_acknowledged_ids(scratchpad: Path) -> set[str]:
    """Return inventory IDs explicitly absorbed/grouped by semantic dedup.

    After `semantic_dedup`, the active verification queue may intentionally
    omit absorbed duplicate rows. Startup reconciliation must not treat those
    IDs as lost, but it also must not excuse plain PASS rows that vanished.
    """
    path = scratchpad / "dedup_decisions.md"
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()

    acknowledged: set[str] = set()

    # Heading form:
    #   ### MERGE: INV-011 absorbs INV-010
    #   ### GROUP: INV-001 represents INV-002, INV-003
    for line in text.splitlines():
        m = re.match(
            r"(?i)^\s*#{2,6}\s+MERGE:\s+"
            r"([A-Z]+-\d+)\s+absorbs\s+(.+?)\s*$",
            line,
        )
        if m:
            for fid in re.findall(r"\b[A-Z]+-\d+\b", m.group(2)):
                norm = _normalize_finding_id(fid)
                if norm:
                    acknowledged.add(norm)
            continue
        m = re.match(
            r"(?i)^\s*#{2,6}\s+GROUP:\s+"
            r"([A-Z]+-\d+)\s+represents\s+(.+?)\s*$",
            line,
        )
        if m:
            representative = _normalize_finding_id(m.group(1))
            for fid in re.findall(r"\b[A-Z]+-\d+\b", m.group(2)):
                norm = _normalize_finding_id(fid)
                if norm and norm != representative:
                    acknowledged.add(norm)
            continue

        # Status-table form:
        # | INV-010 | MERGED into INV-011 | ... |
        # | INV-002 | GROUPED under INV-001 | ... |
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        fid = _normalize_finding_id(cells[0])
        status = cells[1].lower()
        if fid and (
            status.startswith("merged")
            or status.startswith("absorbed")
            or status.startswith("grouped")
            or "merged into" in status
            or "inherits verification" in status
        ):
            acknowledged.add(fid)

    acknowledged.discard("")
    return acknowledged


def _snapshot_file_state(scratchpad: Path, project_root: str) -> dict[str, tuple[int, int]]:
    """Return path -> (mtime_ns, size) for current run-relevant artifacts."""
    state: dict[str, tuple[int, int]] = {}
    excluded_dirs = {
        "_overflow",
        "_retry_quarantine",
        ".pytest_cache",
        "__pycache__",
    }
    for p in scratchpad.rglob("*"):
        if not p.is_file():
            continue
        rel_parts = p.relative_to(scratchpad).parts
        if rel_parts and rel_parts[0] in excluded_dirs:
            continue
        try:
            stat = p.stat()
        except Exception:
            continue
        state[p.relative_to(scratchpad).as_posix()] = (stat.st_mtime_ns, stat.st_size)
    report = Path(project_root) / "AUDIT_REPORT.md"
    if report.exists():
        try:
            stat = report.stat()
            state["../AUDIT_REPORT.md"] = (stat.st_mtime_ns, stat.st_size)
        except Exception:
            pass
    return state


_PROTECTED_WRITE_PATTERNS_BY_PHASE: dict[str, tuple[str, ...]] = {
    "depth": (
        "rag_validation.md",
        "chain_summaries_compact.md",
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
        "chain_hypotheses.md",
        "composition_coverage.md",
        "synthesis_full.md",
        "verification_queue*.md",
        "verify_*.md",
        "verify_H*.md",
        "verify_CH*.md",
        "verify_F*.md",
        "verify_core.md",
        "cross_batch_consistency*.md",
        "skeptic_*.md",
        "judge_*.md",
        "report_index.md",
        "report_coverage.md",
        "report_quality.md",
        "report_*.md",
        "../AUDIT_REPORT.md",
    ),
    "breadth": (
        "analysis_rescan_*.md",
        "analysis_percontract_*.md",
        "analysis_merged_into_*.md",
        "findings_inventory*.md",
        "semantic_invariants.md",
        "depth_*",
        "rag_validation.md",
        "hypotheses.md",
        "finding_mapping.md",
        "enabler_results.md",
        "chain_hypotheses.md",
        "verification_queue*.md",
        "verify_*.md",
        "report_*.md",
        "../AUDIT_REPORT.md",
    ),
}


def _protected_phase_write_patterns(phase_name: str) -> tuple[str, ...]:
    return _PROTECTED_WRITE_PATTERNS_BY_PHASE.get(phase_name, ())


def _future_phase_write_patterns(
    scratchpad: Path,
    pipeline: str,
    phase_name: str,
    phase_names: list[str],
) -> list[str]:
    """Return artifact patterns owned by phases after ``phase_name``.

    This is the shared source of truth for both live subprocess containment
    and post-run containment. Keeping the pattern derivation in one place
    prevents the bug class where post-run detects a phase leak only after the
    model has already spent a full turn writing later-phase artifacts.
    """
    owned = _owned_artifact_patterns(pipeline, scratchpad)
    try:
        idx = phase_names.index(phase_name)
    except ValueError:
        return list(_protected_phase_write_patterns(phase_name))

    future_patterns: list[str] = []
    for later_name in phase_names[idx + 1:]:
        future_patterns.extend(owned.get(later_name, []))
    future_patterns.extend(_protected_phase_write_patterns(phase_name))

    current_owned = set(owned.get(phase_name, []))
    if current_owned:
        future_patterns = [p for p in future_patterns if p not in current_owned]

    if phase_name.startswith("report_body_writer_"):
        future_patterns = [
            p for p in future_patterns
            if not re.fullmatch(
                r"report_(?:critical_high|medium|low_info)(?:_[a-z])?\.md",
                p,
            )
        ]

    return sorted(set(future_patterns))


def _live_protected_phase_write_patterns(
    scratchpad: Path,
    pipeline: str,
    phase_name: str,
    active_phase_names: list[str] | tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Return downstream artifact patterns for live PTY/headless aborts."""
    if active_phase_names:
        phase_names = [str(name) for name in active_phase_names]
    else:
        phases = L1_PHASES if pipeline == "l1" else SC_PHASES
        phase_names = [p.name for p in phases]
    patterns = _future_phase_write_patterns(
        scratchpad,
        pipeline,
        phase_name,
        phase_names,
    )
    blocking: list[str] = []
    for pattern in patterns:
        if not _live_foreign_pattern_is_benign(phase_name, pattern):
            blocking.append(pattern)
    return tuple(sorted(set(blocking)))


def _live_foreign_pattern_is_benign(phase_name: str, pattern: str) -> bool:
    """Pattern-level mirror of the driver's benign quarantine policy."""
    from fnmatch import fnmatch

    if phase_name == "report_index":
        return (
            fnmatch(pattern, "report_critical_high*.md")
            or fnmatch(pattern, "report_medium*.md")
            or fnmatch(pattern, "report_low_info*.md")
        )
    if phase_name == "depth":
        benign = (
            "hypotheses.md",
            "finding_mapping.md",
            "enabler_results.md",
            "chain_*.md",
            "synthesis_*.md",
            "composition_coverage.md",
        )
        return any(fnmatch(pattern, p) for p in benign)
    if phase_name.startswith("inventory_chunk_"):
        benign = (
            "findings_inventory_chunk_*.md",
            "findings_inventory.md",
            "semantic_invariants.md",
        )
        return any(fnmatch(pattern, p) for p in benign)
    if phase_name == "breadth":
        benign = ("analysis_rescan_*.md", "analysis_percontract_*.md")
        return any(fnmatch(pattern, p) for p in benign)
    return False


_ARTIFACT_STATE_NAME = "_artifact_state.json"
_BREADTH_WORKER_POOL_CONTRACT_NAME = "_breadth_worker_pool_contract.json"


def _artifact_state_path(scratchpad: Path) -> Path:
    return scratchpad / _ARTIFACT_STATE_NAME


def _read_artifact_state(scratchpad: Path) -> dict[str, Any]:
    """Read durable artifact ownership metadata.

    The ledger is intentionally best-effort: corrupted or missing metadata must
    not crash the pipeline, but callers should then treat provenance as unknown
    instead of silently inferring ownership from file presence.
    """
    path = _artifact_state_path(scratchpad)
    if not path.exists():
        return {"version": 1, "artifacts": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("[artifact-state] ignoring unreadable artifact ledger: %s", exc)
        return {"version": 1, "artifacts": {}}
    if not isinstance(data, dict):
        return {"version": 1, "artifacts": {}}
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, dict):
        data["artifacts"] = {}
    data.setdefault("version", 1)
    return data


def _write_artifact_state(scratchpad: Path, state: dict[str, Any]) -> None:
    path = _artifact_state_path(scratchpad)
    payload = json.dumps(state, indent=2, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), delete=False,
        prefix=f".{path.name}.", suffix=".tmp",
    ) as tmp:
        tmp.write(payload)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def _artifact_path_for_name(scratchpad: Path, project_root: str, name: str) -> Path:
    if name == "../AUDIT_REPORT.md":
        return Path(project_root) / "AUDIT_REPORT.md"
    if name.startswith("../"):
        return Path(project_root) / name[3:]
    return scratchpad / name


def _artifact_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _artifact_record(
    scratchpad: Path,
    project_root: str,
    name: str,
    *,
    owner_phase: str,
    status: str,
) -> dict[str, Any] | None:
    path = _artifact_path_for_name(scratchpad, project_root, name)
    if not path.exists() or not path.is_file():
        return None
    try:
        stat = path.stat()
        sha256 = _artifact_sha256(path)
    except Exception as exc:
        log.debug("[artifact-state] could not stat/hash %s: %s", name, exc)
        return None
    return {
        "path": name,
        "owner_phase": owner_phase,
        "status": status,
        "mtime_ns": stat.st_mtime_ns,
        "size": stat.st_size,
        "sha256": sha256,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _materialized_artifact_names(
    scratchpad: Path,
    project_root: str,
    patterns: list[str],
) -> list[str]:
    names: list[str] = []
    for pattern in patterns:
        if pattern == "AUDIT_REPORT.md":
            pattern = "../AUDIT_REPORT.md"
        if pattern == "../AUDIT_REPORT.md" or pattern.startswith("../"):
            if _artifact_path_for_name(scratchpad, project_root, pattern).exists():
                names.append(pattern)
            continue
        if any(ch in pattern for ch in "*?["):
            names.extend(sorted(p.name for p in scratchpad.glob(pattern) if p.is_file()))
        else:
            p = scratchpad / pattern
            if p.exists() and p.is_file():
                names.append(pattern)
    return sorted(set(names))


def _record_phase_artifact_state(
    scratchpad: Path,
    project_root: str,
    phases: list[Phase],
    phase_name: str,
    pipeline: str,
    *,
    status: str = "ACTIVE",
) -> list[str]:
    """Record durable ownership for artifacts materialized by a phase.

    This is the runtime source of truth that separates a real containment
    violation from stale downstream artifacts left by a prior run. File
    presence alone is not provenance.
    """
    del phases  # ownership is keyed by pipeline/phase, not active mode order.
    owned = _owned_artifact_patterns(pipeline, scratchpad).get(phase_name, [])
    names = _materialized_artifact_names(scratchpad, project_root, owned)
    if not names:
        return []
    state = _read_artifact_state(scratchpad)
    artifacts = state.setdefault("artifacts", {})
    for name in names:
        record = _artifact_record(
            scratchpad, project_root, name,
            owner_phase=phase_name, status=status,
        )
        if record:
            artifacts[name] = record
    _write_artifact_state(scratchpad, state)
    return names


def _phase_artifacts_have_active_owner_state(
    scratchpad: Path,
    project_root: str,
    phase_name: str,
    pipeline: str,
) -> tuple[bool, list[str]]:
    """Return whether current phase artifacts have matching owner metadata.

    Artifact recovery must not infer phase completion from file presence on a
    dirty scratchpad. Only artifacts previously recorded by the same phase with
    matching content hashes are eligible for auto-complete.
    """
    owned = _owned_artifact_patterns(pipeline, scratchpad).get(phase_name, [])
    names = _materialized_artifact_names(scratchpad, project_root, owned)
    if not names:
        return False, ["no owned artifacts materialized"]
    state = _read_artifact_state(scratchpad)
    artifacts = state.get("artifacts", {})
    issues: list[str] = []
    for name in names:
        rec = artifacts.get(name) if isinstance(artifacts, dict) else None
        if not isinstance(rec, dict):
            issues.append(f"{name}: no owner record")
            continue
        if rec.get("owner_phase") != phase_name or rec.get("status") != "ACTIVE":
            issues.append(
                f"{name}: owner={rec.get('owner_phase')} status={rec.get('status')}"
            )
            continue
        path = _artifact_path_for_name(scratchpad, project_root, name)
        try:
            current_hash = _artifact_sha256(path)
        except Exception as exc:
            issues.append(f"{name}: unreadable for hash ({exc})")
            continue
        if rec.get("sha256") != current_hash:
            issues.append(f"{name}: content hash changed since owner record")
    return not issues, issues


def _mark_artifacts_quarantined(
    scratchpad: Path,
    project_root: str,
    phase_name: str,
    names: list[str],
) -> None:
    if not names:
        return
    state = _read_artifact_state(scratchpad)
    artifacts = state.setdefault("artifacts", {})
    now = datetime.now(timezone.utc).isoformat()
    for name in names:
        prior = artifacts.get(name) if isinstance(artifacts.get(name), dict) else {}
        artifacts[name] = {
            **prior,
            "path": name,
            "owner_phase": prior.get("owner_phase") or phase_name,
            "quarantined_by_phase": phase_name,
            "status": "QUARANTINED",
            "updated_at": now,
        }
    _write_artifact_state(scratchpad, state)


def _owned_artifact_patterns(pipeline: str, scratchpad: Optional[Path] = None) -> dict[str, list[str]]:
    """Return per-phase artifact ownership patterns for phase-containment checks."""
    common_report = ["../AUDIT_REPORT.md"]
    def _verify_output_names(rows: list[dict[str, str]]) -> list[str]:
        names: list[str] = []
        for row in rows:
            fid = (row.get("finding id") or "").strip()
            if not fid:
                continue
            names.append(f"verify_{fid}.md")
        return names

    if pipeline == "l1":
        verify_shards = compute_verify_shards(scratchpad) if scratchpad else {
            name: [] for name in L1_VERIFY_PHASE_NAMES
        }
        verify_names = {
            phase_name: _verify_output_names(rows)
            for phase_name, rows in verify_shards.items()
        }
        owned = {
            "bake": ["primitive_status.md", "bake_validation.md"],
            "recon": [
                "recon_summary.md", "threat_model.md", "subsystem_map.md",
                "attack_surface.md", "trust_boundaries.md",
                "template_recommendations.md", "scope_leftover.md",
                "file_coverage_ledger.md", "integration_points.md",
            ],
            "breadth": ["analysis_*.md"],
            "graph_sweeps": [
                "graph_sweep_summary.md", "coverage_fill_*.md",
                "panic_audit_*.md", "panic_audit_summary.md",
                "symmetric_pair_findings.md",
                "field_validation_matrix.md",
                "primitive_correctness_findings.md",
                "network_amplification_findings.md",
                "lifecycle_replay_findings.md",
            ],
            "inventory_prepare": [
                "inventory_shard_plan.md", "inventory_chunk_a.manifest.md",
                "inventory_chunk_b.manifest.md", "inventory_chunk_c.manifest.md",
            ],
            "inventory_chunk_a": ["findings_inventory_chunk_a.md"],
            "inventory_chunk_b": ["findings_inventory_chunk_b.md"],
            "inventory_chunk_c": ["findings_inventory_chunk_c.md"],
            "inventory": [
                "findings_inventory.md", "inventory_evidence_validation.md",
                "inventory_merge_receipt.md",
            ],
            "location_recovery": ["location_recovery.md"],
            "invariants": ["semantic_invariants.md"],
            # v2.8.8: Pass 2 appends to Pass 1's file (semantic_invariants.md).
            # Shared ownership is intentional — Pass 2 strictly appends a
            # `## Pass 2:` section, never rewrites Pass 1 content.
            "invariants_p2": ["semantic_invariants.md"],
            "post_verify_extract": ["post_verify_extract.md"],
            "depth": [
                "depth_*_findings.md", "depth_iter2_*_findings.md",
                "blind_spot_*_findings.md", "scanner_*_findings.md",
                "da_*_findings.md", "confidence_scores.md",
                "design_stress_findings.md", "perturbation_findings.md",
                "skill_execution_gaps.md", "skill_execution_checklist.md",
                "never_cut_checkpoint.md", "depth_exit.md",
            ],
            "rag_sweep": ["rag_validation.md"],
            "chain": ["hypotheses.md", "finding_mapping.md", "enabler_results.md"],
            "chain_agent2": ["chain_hypotheses.md", "composition_coverage.md", "synthesis_full.md"],
            "semantic_dedup": [
                "dedup_decisions.md", "verification_queue_deduped.md",
            ],
            "attention_repair": ["attention_repair_summary.md", "attention_repair_findings.md"],
            "enumgap_exploration": ["enumgap_exploration_findings.md"],
            "verify_queue": [
                "verification_queue.md", "verification_queue_evidence_excluded.md",
            ],
            "verify_aggregate": ["verify_core.md"],
            "mechanical_verify": ["mechanical_verify_manifest.md"],
            "crossbatch": ["cross_batch_consistency.md"],
            "skeptic": ["skeptic_findings.md", "skeptic_judge_decisions.md"],
            "report_index": [
                "report_index.md", "report_coverage.md", "report_records.json",
            ],
            "report_body_writer_critical_high": ["report_critical_high.md"],
            "report_body_writer_medium": ["report_medium.md"],
            "report_body_writer_low_info": ["report_low_info.md"],
            "report_critical_high": ["report_critical_high.md"],
            "report_critical_high_merge": ["report_critical_high.md"],
            "report_medium": ["report_medium.md"],
            "report_medium_merge": ["report_medium.md"],
            "report_low_info": ["report_low_info.md"],
            "report_low_info_merge": ["report_low_info.md"],
            "report_assemble": common_report,
            # Cross-tier dedup (Python-native). Owns its decisions mapping and
            # the snapshot side artifacts; MAY rewrite the delivered report when
            # the data-loss gate passes (hence common_report ownership too).
            "report_dedup": [
                "report_dedup_mapping.md",
                "AUDIT_REPORT.pre-dedup.md",
                "AUDIT_REPORT.deduped.md",
                *common_report,
            ],
            # Material-harm disposition (LLM) writes the BODY/APPENDIX ledger.
            "report_disposition": ["disposition.md"],
            # Material-harm floor (Python-native, FINAL mutation) owns its marker
            # and may rewrite the delivered report (relocation + summary update).
            "report_floor": ["material_harm_floor.md", "disposition.md", *common_report],
        }
        # Dynamic tier shard entries based on actual manifests
        if scratchpad:
            manifest_dir = scratchpad / "body_manifests"
            if manifest_dir.is_dir():
                from plamen_types import _EXPANDABLE_TIERS, _valid_report_shard_suffix
                for tier in _EXPANDABLE_TIERS:
                    for f in sorted(manifest_dir.glob(f"report_{tier}_*.json")):
                        suffix = f.stem[len(f"report_{tier}_"):]
                        if _valid_report_shard_suffix(suffix):
                            bw = f"report_body_writer_{tier}_{suffix}"
                            owned[bw] = [f"report_{tier}_{suffix}.md"]
                            owned[f"report_{tier}_{suffix}"] = [
                                f"report_{tier}_{suffix}.md",
                                f"report_{tier}_{suffix}_assignments.md",
                            ]
                    if not any(k.startswith(f"report_body_writer_{tier}") for k in owned):
                        owned[f"report_body_writer_{tier}"] = [f"report_{tier}.md"]
                        owned[f"report_{tier}"] = [f"report_{tier}.md"]
        for phase_name, manifest in L1_VERIFY_SHARD_MANIFESTS.items():
            owned[phase_name] = [manifest, *verify_names.get(phase_name, [])]
        return owned
    sc_verify_shards = compute_sc_verify_shards(scratchpad) if scratchpad else {
        name: [] for name in SC_VERIFY_PHASE_NAMES
    }
    sc_verify_names = {
        phase_name: _verify_output_names(rows)
        for phase_name, rows in sc_verify_shards.items()
    }
    owned = {
        "recon": [
            "recon_summary.md", "design_context.md", "attack_surface.md",
            "state_variables.md", "function_list.md", "contract_inventory.md",
            "template_recommendations.md", "detected_patterns.md",
            "setter_list.md", "emit_list.md", "build_status.md",
        ],
        "instantiate": ["spawn_manifest.md"],
        "breadth": ["analysis_*.md"],
        "rescan_prepare": ["rescan_manifest.md"],
        "rescan": ["analysis_rescan_*.md", "analysis_percontract_*.md"],
        "inventory_prepare": [
            "inventory_shard_plan.md", "inventory_chunk_a.manifest.md",
            "inventory_chunk_b.manifest.md", "inventory_chunk_c.manifest.md",
        ],
        "inventory_chunk_a": ["findings_inventory_chunk_a.md"],
        "inventory_chunk_b": ["findings_inventory_chunk_b.md"],
        "inventory_chunk_c": ["findings_inventory_chunk_c.md"],
        "inventory": [
            "findings_inventory.md", "inventory_evidence_validation.md",
            "inventory_merge_receipt.md",
        ],
        "invariants": ["semantic_invariants.md"],
        # v2.8.8: Pass 2 appends to Pass 1's file. Shared ownership intentional.
        "invariants_p2": ["semantic_invariants.md"],
        "post_verify_extract": ["post_verify_extract.md"],
        "depth": [
            "depth_*_findings.md", "depth_iter2_*_findings.md",
            "blind_spot_*_findings.md", "scanner_*_findings.md",
            "da_*_findings.md", "confidence_scores.md",
            "design_stress_findings.md", "perturbation_findings.md",
            "skill_execution_gaps.md", "skill_execution_checklist.md",
            "never_cut_checkpoint.md", "depth_exit.md",
        ],
        "rag_sweep": ["rag_validation.md"],
        # Phase 4b.6: independent exploration-completeness verifier. Writes its
        # own additive findings + coverage-record artifact; never edits prior
        # artifacts, so ownership is exclusive to this one file.
        "exploration_skeptic": ["exploration_skeptic_findings.md"],
        # Phase 4b.7: depth-exploration of enumeration obligations. Writes its
        # own additive findings artifact; the driver promotes those into the
        # inventory in the post-hook (mirroring the enumeration gate's own
        # inventory append, which depth already performs).
        "enumgap_exploration": ["enumgap_exploration_findings.md"],
        # Phase 4b.8 (M2): multi-axis coverage meta-pass. Writes its additive
        # findings artifact plus the driver-owned hot-function/axis matrix; the
        # driver promotes gap findings into the inventory in the post-hook
        # (mirroring enumgap_exploration).
        "axis_coverage": [
            "axis_coverage_findings.md", "hot_function_axes.md",
            "_hot_function_axes.json", "axis_coverage_promotion_receipt.md",
        ],
        "sc_semantic_dedup": ["dedup_decisions.md", "findings_inventory_deduped.md"],
        "attention_repair": ["attention_repair_summary.md", "attention_repair_findings.md"],
        "chain": ["hypotheses.md", "finding_mapping.md", "enabler_results.md"],
        "chain_agent2": ["chain_hypotheses.md", "composition_coverage.md", "synthesis_full.md"],
        # v2.8.8: iteration 2 appends new chains to chain_hypotheses.md
        # AND writes new artifact chain_iteration2.md. Shared ownership
        # on chain_hypotheses.md/composition_coverage.md intentional —
        # both append-only.
        "chain_iter2": [
            "chain_iteration2.md",
            "chain_hypotheses.md",
            "composition_coverage.md",
        ],
        "sc_verify_queue": [
            "verification_queue.md", "verification_queue_evidence_excluded.md",
        ],
        "sc_verify_aggregate": ["verify_core.md"],
        "sc_mechanical_verify": ["mechanical_verify_manifest.md"],
        "skeptic": ["skeptic_findings.md", "skeptic_judge_decisions.md"],
        "crossbatch": ["cross_batch_consistency.md"],
        "report_index": ["report_index.md", "report_coverage.md"],
        "report_body_writer_critical_high": ["report_critical_high.md"],
        "report_body_writer_medium": ["report_medium.md"],
        "report_body_writer_low_info": ["report_low_info.md"],
        "report_critical_high": ["report_critical_high.md"],
        "report_critical_high_merge": ["report_critical_high.md"],
        "report_medium": ["report_medium.md"],
        "report_medium_merge": ["report_medium.md"],
        "report_low_info": ["report_low_info.md"],
        "report_low_info_merge": ["report_low_info.md"],
        "report_assemble": common_report,
        # Phase 6d LLM consolidation proposer. Writes ONLY its decisions file —
        # it never edits AUDIT_REPORT.md (the Python report_dedup phase below is
        # the sole executor), so ownership is exclusive to this one artifact.
        "report_dedup_agent": ["report_dedup_agent_decisions.md"],
        # Cross-tier dedup (Python-native). Owns its decisions mapping and the
        # snapshot side artifacts; MAY rewrite the delivered report when the
        # data-loss gate passes (hence common_report ownership too).
        "report_dedup": [
            "report_dedup_mapping.md",
            "AUDIT_REPORT.pre-dedup.md",
            "AUDIT_REPORT.deduped.md",
            *common_report,
        ],
        # Material-harm disposition (LLM) writes the BODY/APPENDIX ledger.
        "report_disposition": ["disposition.md"],
        # Material-harm floor (Python-native, FINAL mutation) owns its marker and
        # may rewrite the delivered report (relocation + summary update).
        "report_floor": ["material_harm_floor.md", "disposition.md", *common_report],
    }
    if scratchpad:
        manifest_dir = scratchpad / "body_manifests"
        if manifest_dir.is_dir():
            from plamen_types import _EXPANDABLE_TIERS, _valid_report_shard_suffix
            for tier in _EXPANDABLE_TIERS:
                for f in sorted(manifest_dir.glob(f"report_{tier}_*.json")):
                    suffix = f.stem[len(f"report_{tier}_"):]
                    if _valid_report_shard_suffix(suffix):
                        owned[f"report_body_writer_{tier}_{suffix}"] = [
                            f"report_{tier}_{suffix}.md"
                        ]
                        owned[f"report_{tier}_{suffix}"] = [
                            f"report_{tier}_{suffix}.md",
                            f"report_{tier}_{suffix}_assignments.md",
                        ]
    for phase_name, manifest in SC_VERIFY_SHARD_MANIFESTS.items():
        owned[phase_name] = [manifest, *sc_verify_names.get(phase_name, [])]
    return owned


def _matches_any_pattern(name: str, patterns: list[str]) -> bool:
    from fnmatch import fnmatch
    return any(fnmatch(name, pat) for pat in patterns)


def _detect_foreign_phase_writes(scratchpad: Path, project_root: str,
                                 phases: list[Phase], phase_name: str,
                                 pipeline: str,
                                 before_state: dict[str, tuple[int, int]]) -> list[str]:
    """Return later-phase artifacts created/modified by the current phase attempt."""
    phase_names = [p.name for p in phases]
    future_patterns = _future_phase_write_patterns(
        scratchpad, pipeline, phase_name, phase_names
    )
    if not future_patterns:
        return []

    after_state = _snapshot_file_state(scratchpad, project_root)
    offenders: list[str] = []
    allowed_verify_overreach = set()
    # v2.1.8: STRICT PHASE ISOLATION (revised v2.1.6 #1).
    #
    # The v2.1.6 blanket allowlist let verify produce skeptic/crossbatch/
    # verify_core inline. This saved cost but degraded adversarial
    # divergence for skeptic (per AD-2: same-context skeptic <50% divergence
    # vs >99% for fresh-context). User explicitly chose "each phase
    # isolated and seamless" over the cost optimization.
    #
    # New policy: only `verify_core.md` is permitted inline (it's a pure
    # mechanical aggregate with no adversarial reasoning; fresh context
    # adds nothing). All other inline-overreach files are quarantined to
    # `{scratchpad}/_overflow/{phase}/` by `_quarantine_phase_overreach`,
    # which runs BEFORE this foreign-write check. Quarantined files no
    # longer satisfy the dedicated phase's gate, so skeptic and crossbatch
    # phases run as separate subprocesses with fresh context.
    if phase_name in {"verify", *L1_VERIFY_PHASE_NAMES, *SC_VERIFY_PHASE_NAMES}:
        allowed_verify_overreach = {
            "verify_core.md",  # mechanical aggregate; same-context is fine
        }
    for name, meta in after_state.items():
        prev = before_state.get(name)
        changed = prev is None or prev != meta
        if not changed:
            continue
        # v2.1.6: glob-aware allowlist match (was set membership only).
        if _matches_any_pattern(name, allowed_verify_overreach):
            continue
        if _matches_any_pattern(name, future_patterns):
            offenders.append(name)
    offenders.sort()
    return offenders


# v2.8.8: the Medium+ project-mock PoC override (T1b) is a NEW hard gate on a
# `critical` verify phase. To prevent a genuinely-unmockable finding from
# hard-halting the pipeline (the re-audit's only latent halt-class), the
# override is bounded: it hard-fails for at most `_VERIFY_OVERRIDE_RETRY_CAP`
# shard attempts, then degrades to a WARN (recorded) so the phase can complete.
# The pre-existing mandatory-PoC enforcement is NOT bounded — it is satisfiable
# and load-bearing. Mirrors the body-content Bucket-3 retry-then-WARN pattern.
_VERIFY_OVERRIDE_RETRY_CAP = 2
_OVERRIDE_ISSUE_MARK = "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip invalid"


def _verify_override_retry_path(scratchpad: Path, phase_name: str) -> Path:
    return scratchpad / f".{phase_name}.mock_override_retry"


def _verify_override_exhausted(scratchpad: Path, phase_name: str) -> bool:
    try:
        return int(
            _verify_override_retry_path(scratchpad, phase_name).read_text(encoding="utf-8")
        ) >= _VERIFY_OVERRIDE_RETRY_CAP
    except Exception:
        return False


def _bump_verify_override(scratchpad: Path, phase_name: str) -> None:
    p = _verify_override_retry_path(scratchpad, phase_name)
    try:
        n = int(p.read_text(encoding="utf-8"))
    except Exception:
        n = 0
    try:
        p.write_text(str(n + 1), encoding="utf-8")
    except Exception:
        pass


def _record_verify_override_degraded(
    scratchpad: Path, phase_name: str, override_issues: list[str]
) -> None:
    """Bounded-retry exhausted: degrade the Medium+ mock override to WARN.

    Written so the operator sees that a Medium+ finding shipped without the
    forced PoC after the retry budget was spent (not silently dropped).
    """
    try:
        path = scratchpad / "verify_override_degraded.md"
        prior = path.read_text(encoding="utf-8", errors="replace") if path.exists() else (
            "# Medium+ Mock-Override Degraded to WARN (v2.8.8)\n\n"
            "Each row is a Medium+ unit/property finding whose "
            "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip was flagged invalid "
            "(project mocks the dependency) but the verifier did not produce a "
            "PoC within the bounded retry budget. Shipped as WARN to avoid a "
            "critical-phase halt; worth human review.\n\n"
            "| Phase | Finding/Issue |\n|---|---|\n"
        )
        rows = "".join(f"| {phase_name} | {i} |\n" for i in override_issues)
        path.write_text(prior + rows, encoding="utf-8")
    except Exception:
        pass


def _validate_verify_completion(
    scratchpad: Path,
    phase_name: str,
    *,
    min_bytes: int = 100,
    mode: str = "core",
) -> list[str]:
    """Ensure a verify shard produced the expected verifier file set.

    Accepts both `verify_{id}.md` and `verify_F-{id}.md` — the LLM prompt
    uses the F- prefix convention in most places, but legacy callers may
    emit the un-prefixed form. Either is considered valid.
    """
    if phase_name in SC_VERIFY_PHASE_NAMES:
        shards = compute_sc_verify_shards(scratchpad)
    else:
        shards = compute_verify_shards(scratchpad)
    expected_rows = shards.get(phase_name, [])
    # For each finding id, accept either shape as present.
    expected_ids = [row['finding id'] for row in expected_rows]
    if not expected_ids:
        return []

    def _verify_names(fid: str) -> tuple[str, ...]:
        return (
            f"verify_{fid}.md",
            f"verify_F-{fid}.md",
            f"verify_F_{fid}.md",
            f"verify_[{fid}].md",
        )

    def _present(fid: str) -> bool:
        for name in _verify_names(fid):
            p = scratchpad / name
            if p.exists() and p.stat().st_size >= min_bytes:
                return True
        return False

    present_ids = [fid for fid in expected_ids if _present(fid)]
    actual = len(present_ids)
    # Keep `expected_files` variable for downstream logging/schema checks
    expected_files = set()
    for fid in expected_ids:
        for name in _verify_names(fid):
            if (scratchpad / name).exists():
                expected_files.add(name)
    if actual < len(expected_ids):
        missing_ids = [fid for fid in expected_ids if not _present(fid)]
        sample = sorted(missing_ids)[:5]
        extra = f" (+{len(missing_ids) - len(sample)} more)" if len(missing_ids) > len(sample) else ""
        return [
            f"verify completion: wrote {actual}/{len(expected_ids)} verifier files; "
            f"missing: {sample}{extra}"
        ]

    row_by_file: dict[str, dict[str, str]] = {}
    for row in expected_rows:
        fid = row.get("finding id", "")
        for name in _verify_names(fid):
            row_by_file[name] = row

    schema_issues = []
    # v2.2.1 Fix 1: accept aliases observed in practice. Verifier prompts
    # in the wild emit any of:
    #   **Preferred Tag**:           (canonical, what the prompt asks for)
    #   **Preferred Verification**:  (verifier-side paraphrase observed in a prior L1 run)
    #   **Evidence Tag**:            (verifier-side paraphrase observed in a prior L1 run)
    #   **Evidence Tags**:           (plural variant)
    # Pre-v2.2.1 the strict-substring gate ("Preferred Tag" not in txt) failed
    # twice on the same content → degraded → halted. Required manual recovery.
    # The gate now accepts any of the four; the prompt-side hardening to emit
    # the literal "Preferred Tag" form ships separately (rules/phase5*.md).
    accepted_field_names = (
        "Preferred Tag",
        "Preferred Verification",
        "Evidence Tag",
        "Evidence Tags",
    )
    for name in sorted(expected_files):
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        evidence = _field_from_markdown(txt, ("Evidence Tag", "Evidence Tags", "Evidence"))
        preferred = _field_from_markdown(
            txt, ("Preferred Tag", "Preferred Verification", "Preferred Evidence")
        )
        if evidence and not preferred:
            txt = txt.rstrip() + f"\n\n**Preferred Tag**: {evidence}\n"
            p.write_text(txt, encoding="utf-8")
        missing_fields: list[str] = []
        if not _field_from_markdown(txt, accepted_field_names):
            missing_fields.append("Preferred Tag/Evidence Tag")
        verdict = _field_from_markdown(txt, ("Verdict", "Final Verdict", "Status"))
        if (
            not verdict
            or _verifier_status_from_text(f"**Verdict**: {verdict}")
            == "SCHEMA_INVALID"
        ):
            missing_fields.append("Verdict")
        row = row_by_file.get(name, {})
        if (
            not _field_from_markdown(txt, ("Severity", "Final Severity"))
            and not row.get("severity")
        ):
            missing_fields.append("Severity")
        if missing_fields:
            schema_issues.append(f"{name} ({', '.join(missing_fields)})")
    if schema_issues:
        return [
            "verify schema: missing required verifier fields in "
            + ", ".join(schema_issues[:8])
        ]
    poc_issues = _validate_poc_contract_for_rows(scratchpad, expected_rows, mode)
    if poc_issues:
        # Split the bounded Medium+ mock override (v2.8.8) from the unbounded
        # mandatory-PoC enforcement. The override hard-fails for a bounded
        # number of shard attempts, then degrades to WARN so a genuinely
        # unmockable Medium+ finding cannot hard-halt this critical phase.
        override_issues = [i for i in poc_issues if _OVERRIDE_ISSUE_MARK in i]
        hard_issues = [i for i in poc_issues if _OVERRIDE_ISSUE_MARK not in i]
        if override_issues:
            if _verify_override_exhausted(scratchpad, phase_name):
                _record_verify_override_degraded(
                    scratchpad, phase_name, override_issues
                )
            else:
                _bump_verify_override(scratchpad, phase_name)
                hard_issues.extend(override_issues)
        if hard_issues:
            return [
                "verify PoC contract: " + "; ".join(hard_issues)
            ]
    return []


def _promote_depth_findings_to_inventory(scratchpad: Path, min_confidence: float = 0.70) -> list[str]:
    """Append high-confidence depth-only findings to findings_inventory.md.

    L1 inventory runs before depth. Without this bridge, DCI/DEC/DX/DN findings
    can be real, scored, and then invisible to verify_queue/report_index. This
    function is deterministic plumbing: it preserves depth IDs as Source IDs
    and only appends IDs not already acknowledged by inventory.
    """
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return []
    try:
        inv_text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    existing_ids = set(re.findall(r"\b" + _PROMOTABLE_FEEDER_ID_PATTERN + r"\b", inv_text))
    next_n = max(
        (int(x) for x in re.findall(r"###\s+Finding\s+\[INV-(\d+)\]", inv_text)),
        default=0,
    ) + 1
    scores = _parse_depth_confidence_scores(scratchpad)

    # Build location index from existing inventory for conservative dedup.
    # Fires on EITHER high title overlap (≥0.80) OR location overlap
    # (same file + line ranges within 15 lines).  Location overlap is the
    # stronger signal — catches duplicates with completely different titles.
    _existing_by_file: dict[str, list[tuple[str, tuple[int, int] | None]]] = {}
    for _em in re.finditer(
        r"###\s+Finding\s+\[INV-\d+\]:\s*(.+?)(?:\n|$)"
        r"(?:.*\n)*?\*\*Location\*\*:\s*(\S+)",
        inv_text, re.IGNORECASE,
    ):
        _etitle = _em.group(1).strip()
        _eloc = _norm_loc(_em.group(2).strip())
        _efile = re.sub(r":L?\d+.*$", "", _eloc)
        _elines = _parse_line_range(_eloc)
        if _efile:
            _existing_by_file.setdefault(_efile, []).append((_etitle, _elines))

    candidates: list[dict[str, str]] = []
    dedup_skipped: list[tuple[str, str, str, float]] = []
    for pat in _DEPTH_PROMOTION_FILES:
        for p in sorted(scratchpad.glob(pat)):
            for item in _parse_depth_finding_blocks(p):
                fid = item["id"]
                if fid in existing_ids:
                    continue
                score = scores.get(fid)
                status = _verifier_status_from_text(f"**Verdict**: {item.get('verdict', '')}") if item.get("verdict") else ""
                if status and not _is_reportable_verdict(status):
                    continue
                if status != "CONFIRMED" and score is not None and score < min_confidence:
                    continue
                # Tag likely duplicates: same file + (high title overlap OR
                # location overlap).  Never blocks promotion — tags the
                # finding so the LLM can make the semantic merge decision.
                cand_loc = _norm_loc(item.get("location", ""))
                cand_file = re.sub(r":L?\d+.*$", "", cand_loc)
                cand_lines = _parse_line_range(cand_loc)
                # v2.4.8: high-confidence duplicates are BLOCKED from promotion.
                # Block when title overlap >= 0.90 (near-identical titles), OR
                # when title overlap >= 0.50 AND location overlaps (same bug,
                # slightly different phrasing). Low-title-overlap + location-overlap
                # is tagged but promoted (different bug at same site).
                # 0.80-0.89 title overlap without location match is tagged only.
                _blocked = False
                if cand_file and cand_file in _existing_by_file:
                    for _et, _elines in _existing_by_file[cand_file]:
                        _overlap = _titles_overlap_score(item["title"], _et)
                        _loc_match = (
                            cand_lines is not None
                            and _elines is not None
                            and _line_ranges_overlap(cand_lines, _elines)
                        )
                        if _overlap >= 0.90 or (_loc_match and _overlap >= 0.50):
                            _reason = "location overlap" if _loc_match else f"score={_overlap:.2f}"
                            item["_dup_tag"] = f"[LIKELY-DUP of \"{_et[:60]}\" {_reason}]"
                            dedup_skipped.append((fid, item["title"], _et, _overlap))
                            _blocked = True
                            break
                        if _overlap >= 0.80 or _loc_match:
                            _reason = "location overlap" if _loc_match else f"score={_overlap:.2f}"
                            item["_dup_tag"] = f"[LIKELY-DUP of \"{_et[:60]}\" {_reason}]"
                            dedup_skipped.append((fid, item["title"], _et, _overlap))
                            break
                if _blocked:
                    existing_ids.add(fid)
                    continue
                item["confidence"] = f"{score:.2f}" if score is not None else "n/a"
                candidates.append(item)
                existing_ids.add(fid)
                # Register this candidate so later candidates dedup against it too
                if cand_file:
                    _existing_by_file.setdefault(cand_file, []).append(
                        (item["title"], cand_lines)
                    )
    if not candidates and not dedup_skipped:
        return []

    promoted_ids: list[str] = []
    if candidates:
        additions = [
            "",
            "## Depth Promotion Supplement",
            "",
            "These findings were produced after the initial inventory phase and "
            "promoted mechanically so verification/reporting cannot drop depth-channel outputs.",
            "",
        ]
        for item in candidates:
            inv_id, next_n = _allocate_depth_promotion_inventory_id(
                scratchpad,
                preferred_n=next_n,
                title=item["title"],
            )
            promoted_ids.append(item["id"])
            dup_line = f"**Dedup Signal**: {item['_dup_tag']}\n" if item.get("_dup_tag") else ""
            optional_lines: list[str] = []
            for field in _OPTIONAL_FINDING_METADATA_FIELDS:
                val = _strip_md(str(item.get(field, ""))).strip()
                if not val:
                    continue
                label = _OPTIONAL_FINDING_METADATA_LABELS[field][0]
                optional_lines.append(f"**{label}**: {val}")
            additions.extend([
                f"### Finding [{inv_id}]: {item['title']}",
                f"**Source IDs**: [{', '.join([item['id']] + item.get('_referenced_ids', []))}]",
                f"**Severity**: {item['severity']}",
                f"**Location**: {item['location']}",
                f"**Preferred Tag**: {item['preferred_tag']}",
                f"**Confidence**: {item['confidence']}",
                f"**Primary Artifact**: {item['source_file']}",
            ])
            if dup_line:
                additions.append(dup_line.rstrip())
            additions.extend([
                "",
                f"**Description**: {item['description']}",
                *optional_lines,
                "",
            ])
        inv.write_text(inv_text.rstrip() + "\n" + "\n".join(additions), encoding="utf-8")

    # Always write receipt so the validator can see blocked/tagged IDs
    # even when no candidates survive dedup (fixes all-blocked-no-receipt halt).
    receipt_lines = [
        "# Depth Promotion Receipt\n",
        f"Promoted {len(promoted_ids)} depth finding(s) into findings_inventory.md.\n",
    ]
    if promoted_ids:
        receipt_lines.append("## Promoted\n")
        receipt_lines.extend(f"- `{fid}`\n" for fid in promoted_ids)
    if dedup_skipped:
        receipt_lines.append("\n## Likely Duplicates\n")
        for _dfid, _dtitle, _matched, _dscore in dedup_skipped:
            receipt_lines.append(
                f"- `{_dfid}` — \"{_dtitle[:60]}\" matched existing "
                f"\"{_matched[:60]}\" (score={_dscore:.2f})\n"
            )
    (scratchpad / "depth_promotion_receipt.md").write_text(
        "\n".join(receipt_lines), encoding="utf-8",
    )
    return promoted_ids


def _allocate_depth_promotion_inventory_id(
    scratchpad: Path,
    *,
    preferred_n: int,
    title: str,
) -> tuple[str, int]:
    """Allocate/register an INV id for a depth-promoted inventory row.

    Depth promotion appends driver-owned inventory rows after the inventory
    phase. Those rows are first-class consumer IDs, so they must be ledger
    registered at the same time they are written.
    """
    n = max(1, int(preferred_n or 1))
    for _ in range(1000):
        candidate = f"INV-{n:03d}"
        try:
            result = id_ledger_register(
                scratchpad,
                finding_id=candidate,
                owner_phase="depth_promotion",
                owner_attempt=1,
                owning_artifact="findings_inventory.md",
                title=title,
            )
        except Exception as exc:
            log.debug(f"[depth_promotion] ledger register skipped for {candidate}: {exc}")
            return candidate, n + 1
        if result.get("status") != "COLLISION":
            return candidate, n + 1
        try:
            ledger_nums = [
                int(m.group(1))
                for rec in id_ledger_all_records(scratchpad)
                for m in [re.match(r"^INV-(\d+)$", str(rec.get("id", "")).upper())]
                if m
            ]
            n = max([n] + ledger_nums) + 1
        except Exception:
            n += 1
    return f"INV-{n:03d}", n + 1


def _backfill_inventory_ids_into_ledger(scratchpad: Path) -> int:
    """Register existing `findings_inventory.md` INV headings if absent.

    This is a conservative repair path for resumed/fresh audits where a
    deterministic inventory mutation wrote valid rows but missed ledger
    registration. It never invents IDs: it only records headings already on
    disk so consumer phases stop treating real inventory rows as hallucinated
    references.
    """
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return 0
    try:
        text = inv.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    try:
        ledger_ids = {
            str(rec.get("id", "")).upper()
            for rec in id_ledger_all_records(scratchpad)
            if rec.get("id")
        }
    except Exception:
        ledger_ids = set()
    registered = 0
    matches = list(FINDING_BLOCK_HEADING_RE.finditer(text))
    for idx, match in enumerate(matches):
        raw_id = (match.group(1) or "").strip().upper()
        if not re.match(r"^INV-\d+$", raw_id) or raw_id in ledger_ids:
            continue
        line_end = text.find("\n", match.start())
        if line_end < 0:
            line_end = len(text)
        heading = text[match.start():line_end]
        title_m = re.search(r"\]\s*[:\-–—]?\s*(.+)$", heading)
        title = _strip_md(title_m.group(1)).strip() if title_m else raw_id
        try:
            result = id_ledger_register(
                scratchpad,
                finding_id=raw_id,
                owner_phase="inventory_backfill",
                owner_attempt=1,
                owning_artifact="findings_inventory.md",
                title=title or raw_id,
            )
        except Exception as exc:
            log.debug(f"[id-ledger] inventory backfill skipped for {raw_id}: {exc}")
            continue
        if result.get("status") in {"REGISTERED", "REUSED"}:
            ledger_ids.add(raw_id)
            registered += 1
    return registered


# Accept BOTH `flag: N` (the form agents actually write, verified against real
# agent output) AND `flag = N`. The prior `=`-only regex silently
# returned 0 counts for every run that used the colon form, so
# `_semantic_gap_required` evaluated False even when conditional_writes=4 /
# cluster_gaps=2 etc. were present — the niche then fired only by recon-
# recommendation luck, not the designed trigger. Optional bold/backtick
# wrappers tolerated; matches inside ``` fences too (MULTILINE, line-anchored).
_SEMANTIC_GAP_COUNTER_RE = re.compile(
    r"^\s*[-*]?\s*[`*]*\s*"
    r"(sync_gaps|accumulation_exposures|conditional_writes|cluster_gaps)"
    r"[`*]*\s*[:=]\s*[`*]*\s*(\d+)\b",
    re.IGNORECASE | re.MULTILINE,
)


def _semantic_gap_trigger_counts(scratchpad: Path) -> dict[str, int]:
    """Return Phase 4a.5 semantic-gap trigger counts from semantic_invariants.md.

    The semantic-gap niche agent is different from recon-time niche agents:
    its trigger is produced by the invariants phase, after
    template_recommendations.md has already been written.  This helper is the
    mechanical bridge between that late signal and the depth phase contract.
    """
    p = scratchpad / "semantic_invariants.md"
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    counts = {
        "sync_gaps": 0,
        "accumulation_exposures": 0,
        "conditional_writes": 0,
        "cluster_gaps": 0,
    }
    for key, value in _SEMANTIC_GAP_COUNTER_RE.findall(text):
        counts[key.lower()] = max(counts.get(key.lower(), 0), int(value))
    # Table-cell rendering (`| sync_gaps | 5 |` or a header/row matrix) is a
    # shape the line-anchored counter regex above is blind to. Harvest it via
    # the shared tolerant extractor, constrained to a numeric value. Strict
    # superset: the `:`/`=` forms are already captured above; this only ADDS
    # the pipe-as-separator form (recall up, no value-identity regression).
    for key in list(counts.keys()):
        cell_val, _shape = _field_anywhere(
            text, (key,), value_pattern=r"\d+", table_ok=True
        )
        if cell_val:
            m_num = re.search(r"\d+", cell_val)
            if m_num:
                counts[key] = max(counts.get(key, 0), int(m_num.group(0)))
    # Some invariant artifacts mention the flags without the summary footer.
    # Treat explicit CONFIRMED flag occurrences as a conservative trigger.
    fallback_flags = {
        "sync_gaps": r"\bSYNC_GAP\b",
        "accumulation_exposures": r"\bACCUMULATION_EXPOSURE\b",
        "conditional_writes": r"\bCONDITIONAL(?:_WRITE)?\b",
        "cluster_gaps": r"\b(?:CLUSTER_GAP|LIFECYCLE_GAP)\b",
    }
    for key, pat in fallback_flags.items():
        if counts.get(key, 0) == 0 and re.search(pat, text, re.IGNORECASE):
            counts[key] = 1
    return counts


def _semantic_gap_required(scratchpad: Path) -> bool:
    counts = _semantic_gap_trigger_counts(scratchpad)
    return any(counts.get(k, 0) > 0 for k in (
        "sync_gaps",
        "accumulation_exposures",
        "conditional_writes",
        "cluster_gaps",
    ))


def _validate_semantic_gap_niche(scratchpad: Path, mode: str) -> list[str]:
    """Require semantic-gap niche output when Phase 4a.5 produced gap triggers."""
    if mode not in ("core", "thorough"):
        return []
    if not _semantic_gap_required(scratchpad):
        return []
    out = scratchpad / "niche_semantic_gap_findings.md"
    if out.exists() and out.stat().st_size >= 500:
        return []
    counts = _semantic_gap_trigger_counts(scratchpad)
    counter_text = ", ".join(
        f"{k}={v}" for k, v in counts.items() if v > 0
    ) or "semantic gap flag present"
    return [
        "semantic-gap niche missing: semantic_invariants.md triggered "
        f"SEMANTIC_GAP_INVESTIGATOR ({counter_text}); expected "
        "niche_semantic_gap_findings.md"
    ]


# ---------------------------------------------------------------------------
# Niche manifest consistency (Gate 1) + injectable promotion (Gate 2)
# ---------------------------------------------------------------------------
#
# Single source of truth for the recon Binding Rules flag -> niche mapping
# (phase1-recon-prompt.md "Niche Agent Binding Rules"). This is GENERIC: it
# maps documented detected_patterns.md FLAG TOKENS to documented niche agent
# names. No protocol-specific or bug-specific names appear here — only the
# flag/niche vocabulary that the recon prompt itself documents. Keeping this
# as a module-level table means the flag-derived recall fallback (Gate 1) and
# any future trigger derivation share one definition.
_NICHE_FLAG_TO_AGENT: dict[str, str] = {
    "MISSING_EVENT": "EVENT_COMPLETENESS",
    "HAS_SIGNATURES": "SIGNATURE_VERIFICATION_AUDIT",
    "HAS_MULTI_CONTRACT": "SEMANTIC_CONSISTENCY_AUDIT",
    "MULTI_STEP_OPS": "MULTI_STEP_OPERATION_SAFETY",
    "OUTCOME_CALLBACK": "CALLBACK_RECEIVER_SAFETY",
    "HAS_DOCS": "SPEC_COMPLIANCE_AUDIT",
    "MIXED_DECIMALS": "DIMENSIONAL_ANALYSIS",
}

# Single source of truth for the documented Injectable Skills trigger context
# (phase1-recon-prompt.md "Injectable Skills" + skill-index.md). Maps a
# detected_patterns.md / classification FLAG TOKEN to the injectable skill
# name. Used by Gate 2 to detect Required=NO-while-trigger-present GENERICALLY
# from flags rather than substring-matching skill names in the recommendation
# file (which DOCUMENTS the trigger vocabulary verbatim — the false-fire
# source the CROSS_VM language-gate fix guards against).
_INJECTABLE_FLAG_TO_SKILL: dict[str, str] = {
    "NON_EVM_TARGET": "CROSS_VM_SERIALIZATION_CONFORMANCE",
    "NAMED_EXTERNAL_PROTOCOL": "INTEGRATION_HAZARD_RESEARCH",
}

# protocol_type classification -> injectable skill (phase1-recon-prompt.md
# "Injectable Skills"). protocol_type lives in detected_patterns.md /
# recon classification as `protocol_type = <value>`.
_INJECTABLE_PROTOCOL_TO_SKILL: dict[str, str] = {
    "vault": "VAULT_ACCOUNTING",
    "lending": "LENDING_PROTOCOL_SECURITY",
    "dex_integration": "DEX_INTEGRATION_SECURITY",
    "governance": "GOVERNANCE_ATTACK_VECTORS",
    "nft": "NFT_PROTOCOL_SECURITY",
    "account_abstraction": "ACCOUNT_ABSTRACTION_SECURITY",
    "outcome_determinism": "OUTCOME_DETERMINISM",
}

_INJECTABLE_PLACEHOLDER_RE = re.compile(
    r"\[\s*LLM\s+TO\s+ENRICH\s*\]|\bTODO\b|\bTBD\b|\bFIXME\b|\bXXX\b",
    re.IGNORECASE,
)


def _detected_flag_present(scratchpad: Path, flag: str) -> bool:
    """Return True when detected_patterns.md records FLAG as present.

    GENERIC flag detection mirroring `_has_non_evm_target_evidence` in the
    driver: an explicit `FLAG = YES/TRUE` (or `: YES`) is authoritative-True,
    an explicit NO/FALSE is authoritative-False, and a bare `FLAG detected`
    occurrence (the prose form the recon prompt uses) counts as present. We
    read ONLY detected_patterns.md — never template_recommendations.md, which
    documents the flag vocabulary verbatim and would false-fire.
    """
    dp = scratchpad / "detected_patterns.md"
    if not dp.exists():
        return False
    try:
        text = dp.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    m = re.search(
        rf"\b{re.escape(flag)}\b\s*(?:=|:)\s*(YES|NO|TRUE|FALSE)",
        text,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).upper() in ("YES", "TRUE")
    # No explicit assignment: treat an affirmative prose mention as present.
    return bool(
        re.search(
            rf"\b{re.escape(flag)}\b\s+(?:flag\s+)?(?:detected|present|found|"
            r"triggered|set)\b",
            text,
            re.IGNORECASE,
        )
    )


def _detected_protocol_type(scratchpad: Path) -> str:
    """Return the recon-classified protocol_type, lowercased, or ''."""
    for name in ("detected_patterns.md", "recon_summary.md", "design_context.md"):
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        m = re.search(
            r"protocol[_\s]*type\s*(?:=|:)\s*['\"`]?([A-Za-z_]+)",
            text,
            re.IGNORECASE,
        )
        if m:
            return m.group(1).strip().lower()
    return ""


def _flag_derived_required_niches(scratchpad: Path) -> set[str]:
    """Recall fallback: niches whose detected_patterns.md flag is present.

    Independent of template_recommendations.md so a fully-degraded
    recommendation file cannot zero-out the required-niche set. Mirrors
    `_semantic_gap_required` deriving the niche purely from triggers.
    """
    out: set[str] = set()
    for flag, agent in _NICHE_FLAG_TO_AGENT.items():
        if _detected_flag_present(scratchpad, flag):
            out.add(agent)
    return out


def _signal_declared_required_niches(scratchpad: Path) -> set[str]:
    """Site 2 L1 authoritative source (regex-fragility plan §4 L1): niches the
    recon phase declared via a deterministic
    `<!-- PLAMEN_SIGNALS: {"required_niches": ["EVENT_COMPLETENESS", ...]} -->`
    block in template_recommendations.md (or detected_patterns.md).

    The HTML-comment JSON channel has no markdown shape variance, so a niche
    listed here is shape-independent and cannot be lost to a table/heading
    rendering drift. This set is UNIONED into the required-niche reconciliation
    (recall-safe: it can only ADD niches, mirroring the always-superset repair
    in `_validate_niche_manifest_consistency`). Only canonical uppercase tokens
    are accepted; anything else is ignored.
    """
    out: set[str] = set()
    for fname in ("template_recommendations.md", "detected_patterns.md"):
        p = scratchpad / fname
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        signals = parse_plamen_signals(text)
        raw = signals.get("required_niches")
        if isinstance(raw, str):
            raw = [raw]
        if isinstance(raw, (list, tuple)):
            for tok in raw:
                if isinstance(tok, str) and re.fullmatch(r"[A-Z][A-Z0-9_]+", tok.strip()):
                    out.add(tok.strip())
    return out


def _niche_tokens_from_required_table(text: str) -> set[str]:
    """Parse uppercase niche tokens from a `## Niche Agents` table.

    Returns the niche names whose Required cell contains YES. Mirrors the
    consumer parse in `_required_niche_worker_jobs` (plamen_driver.py) so the
    producer and consumer agree on which rows count.
    """
    tokens: set[str] = set()
    in_niche = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        # Site 2 (regex-fragility plan): `#{1,6}` + heading-synonym tolerant,
        # kept in lockstep with the consumer `_required_niche_worker_jobs`
        # (sibling-sweep) so producer and consumer agree on which rows count.
        if _niche_heading_match(line):
            in_niche = True
            continue
        if in_niche and re.match(r"^#{1,6}\s+", line):
            break
        if not in_niche or not line.startswith("|") or _is_separator_row(line):
            continue
        cells = [c.strip().strip("`*") for c in line.strip("|").split("|")]
        if len(cells) < 3 or cells[0].lower().startswith("niche agent"):
            continue
        name = cells[0].strip()
        # Only accept canonical uppercase-token niche names.
        if not re.fullmatch(r"[A-Z][A-Z0-9_]+", name):
            continue
        # Site 2: Required-cell alias table (YES/Required/Y/True/✓...) + clause
        # negation guard, replacing the literal `"YES" in cell.upper()`.
        if len(cells) <= 2 or not _niche_required_cell_yes(cells[2]):
            continue
        tokens.add(name)
    return tokens


def _niche_tokens_from_binding_rules(text: str) -> set[str]:
    """Parse the recon Addendum niche prose list (Niche Agent Binding Rules).

    The recon prompt records each required niche a SECOND time as prose lines
    of the form `<FLAG> ... -> <NICHE_AGENT> niche agent REQUIRED`. This is the
    independent niche representation (B in the plan) we reconcile against the
    BINDING MANIFEST table (A) and spawn_manifest table (C).
    """
    tokens: set[str] = set()
    known = set(_NICHE_FLAG_TO_AGENT.values()) | {
        "SPEC_COMPLIANCE_AUDIT",
        "SIGNATURE_VERIFICATION_AUDIT",
        "SEMANTIC_CONSISTENCY_AUDIT",
        "MULTI_STEP_OPERATION_SAFETY",
        "CALLBACK_RECEIVER_SAFETY",
        "EVENT_COMPLETENESS",
        "DIMENSIONAL_ANALYSIS",
    }
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if "REQUIRED" not in line.upper():
            continue
        if "niche agent" not in line.lower():
            continue
        for tok in re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b", line):
            if tok in known:
                tokens.add(tok)
    return tokens


def _rewrite_niche_required_table(text: str, required: set[str]) -> str:
    """Rewrite (or append) a `## Niche Agents` table so its Required=YES rows
    equal exactly `required`. Recall-safe: only the union superset is ever
    passed in by the caller. Returns the rewritten file text.
    """
    rows = sorted(required)
    header = (
        "## Niche Agents\n"
        "\n"
        "| Niche Agent | Trigger | Required? | Agent ID | Expected Output |\n"
        "|-------------|---------|-----------|----------|-----------------|\n"
    )
    body_lines = []
    for name in rows:
        slug = name.lower().replace("_", "-")
        out = f"niche_{name.lower()}_findings.md"
        body_lines.append(
            f"| {name} | flag-derived (consistency repair) | YES | "
            f"niche-{slug} | {out} |"
        )
    table = header + "\n".join(body_lines) + "\n"

    lines = text.splitlines()
    start = None
    end = len(lines)
    for i, raw in enumerate(lines):
        if re.match(r"^##+\s+Niche Agents\b", raw.strip(), re.IGNORECASE):
            start = i
            for j in range(i + 1, len(lines)):
                if re.match(r"^##+\s+", lines[j].strip()):
                    end = j
                    break
            break
    if start is None:
        # No existing section: append.
        return text.rstrip() + "\n\n" + table
    new_lines = lines[:start] + table.rstrip("\n").splitlines() + lines[end:]
    return "\n".join(new_lines) + ("\n" if text.endswith("\n") else "")


def _validate_niche_manifest_consistency(
    scratchpad: Path, mode: str
) -> list[str]:
    """Gate 1: reconcile the three niche representations and repair to the
    recall-safe union; fail-loud only when repair is impossible.

    A = required-niche tokens in template_recommendations.md `## Niche Agents`
        BINDING MANIFEST table (Required=YES rows).
    B = required-niche tokens in template_recommendations.md Niche Agent
        Binding Rules prose (the recon Addendum niche list).
    C = niche tokens in spawn_manifest.md `## Niche Agents` table.
    flag = niches whose detected_patterns.md trigger flag is present.
    signal = niches the recon phase declared via the deterministic
        `<!-- PLAMEN_SIGNALS: {"required_niches": [...]} -->` L1 channel.

    Contract: spawn_manifest niche set MUST equal union(A, B, flag, signal).
    If not,
    REPAIR spawn_manifest + the BINDING MANIFEST table to the union (always the
    superset — only ADD, never drop). If repair cannot be applied, return a
    hard issue rather than dispatch an inconsistent/empty table.

    Scoped to core/thorough like `_validate_semantic_gap_niche` so Light is
    unaffected.
    """
    if mode not in ("core", "thorough"):
        return []

    tr_path = scratchpad / "template_recommendations.md"
    sm_path = scratchpad / "spawn_manifest.md"

    tr_text = ""
    if tr_path.exists():
        try:
            tr_text = tr_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            tr_text = ""
    sm_text = ""
    if sm_path.exists():
        try:
            sm_text = sm_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            sm_text = ""

    set_a = _niche_tokens_from_required_table(tr_text)
    set_b = _niche_tokens_from_binding_rules(tr_text)
    set_flag = _flag_derived_required_niches(scratchpad)
    set_signal = _signal_declared_required_niches(scratchpad)  # Site 2 L1
    set_c = _niche_tokens_from_required_table(sm_text)

    union = set_a | set_b | set_flag | set_signal
    if not union:
        # Nothing is required by any source: a niche-free audit is valid.
        return []
    if set_c == union:
        return []

    dropped = union - set_c
    issues: list[str] = []
    repaired_any = False

    # Repair spawn_manifest (the consumer contract) to the union.
    if sm_path.exists() or sm_text:
        try:
            new_sm = _rewrite_niche_required_table(sm_text, union)
            sm_path.write_text(new_sm, encoding="utf-8")
            repaired_any = True
        except Exception as exc:
            issues.append(
                "niche manifest consistency: spawn_manifest.md niche table "
                f"disagrees with union {sorted(union)} and could not be "
                f"repaired ({exc})"
            )
    else:
        # No spawn_manifest yet (resume before instantiate produced it):
        # cannot repair the consumer contract; surface as hard so the
        # producer boundary rebuilds it rather than dispatching nothing.
        issues.append(
            "niche manifest consistency: spawn_manifest.md missing while "
            f"niche union {sorted(union)} is required"
        )

    # Repair the BINDING MANIFEST table so downstream re-reads are consistent.
    if tr_path.exists():
        try:
            new_tr = _rewrite_niche_required_table(tr_text, union)
            if new_tr != tr_text:
                tr_path.write_text(new_tr, encoding="utf-8")
        except Exception as exc:
            log.warning(
                "[niche manifest consistency] could not repair BINDING "
                "MANIFEST niche table in template_recommendations.md: %s", exc
            )

    if repaired_any:
        log.warning(
            "[niche manifest consistency] repaired niche manifest to "
            "recall-safe union %s (added: %s) — spawn_manifest niche table "
            "had %s",
            sorted(union), sorted(dropped), sorted(set_c),
        )
        # Repair succeeded: do NOT block. The consumer now reads the union.
        return []
    return issues


def _injectable_rows(text: str) -> list[tuple[str, str]]:
    """Parse the `### Injectable Skills` section into (row_text, joined_cells).

    Returns one entry per content line of the section (table row or bullet),
    preserving the raw line so the promotion repair can rewrite it. The recon
    prompt documents injectables as a bullet list, but instantiate / repaired
    files may use a table; handle both.
    """
    rows: list[tuple[str, str]] = []
    in_sec = False
    for raw in text.splitlines():
        line = raw.strip()
        if re.match(r"^#{2,}\s+Injectable Skills\b", line, re.IGNORECASE):
            in_sec = True
            continue
        if in_sec and re.match(r"^#{2,}\s+", line):
            break
        if not in_sec or not line:
            continue
        if line.startswith("|"):
            if _is_separator_row(line):
                continue
            cells = [c.strip().strip("`*") for c in line.strip("|").split("|")]
            if cells and cells[0].lower() in ("skill", "injectable", "injectable skill"):
                continue
            rows.append((raw, " | ".join(cells)))
        elif line.startswith("-") or line.startswith("*"):
            rows.append((raw, line.lstrip("-* ").strip()))
    return rows


def _validate_injectable_promotion(
    scratchpad: Path, language: str = ""
) -> list[str]:
    """Gate 2: flag un-enriched or un-promoted injectable recommendations.

    For each row of the `### Injectable Skills` section of
    template_recommendations.md:
      (a) un-resolved placeholder rationale ('[LLM TO ENRICH]', TODO, TBD,
          empty) -> recon failure (the LLM left a stub);
      (b) Required=NO while the injectable's trigger context IS present in
          detected_patterns.md (derived GENERICALLY from the documented
          flag/protocol-type trigger tables, never by substring-matching skill
          names in the recommendation file) -> recon failure.

    Language-gated exactly like the CROSS_VM driver fix: the NON_EVM_TARGET
    trigger only counts when language is a non-EVM/foreign-VM target, so a
    pure-EVM audit does not false-fire on the documented CROSS_VM vocabulary.
    """
    tr_path = scratchpad / "template_recommendations.md"
    if not tr_path.exists():
        return []
    try:
        text = tr_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rows = _injectable_rows(text)
    if not rows:
        return []

    lang = (language or "").strip().lower()
    issues: list[str] = []

    # Build skill -> required? + rationale-empty? view from the rows.
    for raw, joined in rows:
        joined_low = joined.lower()
        # Identify which injectable skill this row references (if any).
        skill_name = ""
        for name in list(_INJECTABLE_FLAG_TO_SKILL.values()) + list(
            _INJECTABLE_PROTOCOL_TO_SKILL.values()
        ):
            if name.lower() in joined_low:
                skill_name = name
                break
        if not skill_name:
            continue

        # Determine Required state from the row (table cell or prose).
        required_no = bool(
            re.search(r"required\??\s*(?:=|:)?\s*\|?\s*no\b", joined_low)
            or re.search(r"\|\s*no\s*\|", joined_low)
        )
        required_yes = bool(
            re.search(r"required\??\s*(?:=|:)?\s*\|?\s*yes\b", joined_low)
            or re.search(r"\|\s*yes\s*\|", joined_low)
        )
        has_placeholder = bool(_INJECTABLE_PLACEHOLDER_RE.search(raw))

        # (a) A *selected* injectable (Required=YES) must carry a real
        # rationale. A placeholder on an UNSELECTED catalog row (Required=NO or
        # unset) is the NORMAL "not applicable" state of the injectable MENU —
        # the recon template lists ALL injectables and leaves [LLM TO ENRICH]
        # on the ones it did not select. Flagging every placeholder fired on
        # the whole 9-row catalog and mass-promoted every injectable; scope (a)
        # to Required=YES rows only.
        if required_yes:
            if has_placeholder:
                issues.append(
                    f"injectable '{skill_name}' is Required=YES but has an "
                    "un-enriched placeholder rationale "
                    "([LLM TO ENRICH]/TODO/TBD); recon must fill it"
                )
            continue

        # (b) trigger-present-but-not-required (only meaningful if we can
        # find a NO, or if the row simply recommends without promoting).
        trigger_present = False
        # flag-derived trigger.
        for flag, name in _INJECTABLE_FLAG_TO_SKILL.items():
            if name != skill_name:
                continue
            if flag == "NON_EVM_TARGET" and lang != "evm":
                # CROSS_VM is an EVM-side (outbound-serialization) skill: it
                # triggers only on an EXPLICIT EVM audit that targets a non-EVM
                # VM, NOT on native non-EVM (solana/aptos/sui/soroban) or
                # legacy/unknown audits. Skip the flag for any non-EVM language.
                continue
            if _detected_flag_present(scratchpad, flag):
                trigger_present = True
        # protocol-type-derived trigger.
        for ptype, name in _INJECTABLE_PROTOCOL_TO_SKILL.items():
            if name == skill_name and _detected_protocol_type(scratchpad) == ptype:
                trigger_present = True

        if trigger_present and (required_no or not required_yes):
            issues.append(
                f"injectable '{skill_name}' trigger context is present in "
                "detected_patterns.md but the row is not Required=YES; recon "
                "must promote it"
            )

    return issues


def _promote_injectable_rows(scratchpad: Path, language: str = "") -> int:
    """Mechanically promote un-resolved/un-promoted injectable rows to
    Required=YES with a derived rationale (recall-safe second-failure repair).

    Returns the number of rows changed. Mirrors the recall-safe posture of
    the niche union repair: never drop, only promote.
    """
    tr_path = scratchpad / "template_recommendations.md"
    if not tr_path.exists():
        return 0
    try:
        text = tr_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    if not _validate_injectable_promotion(scratchpad, language):
        return 0

    lang = (language or "").strip().lower()
    out_lines: list[str] = []
    in_sec = False
    changed = 0
    for raw in text.splitlines():
        line = raw.strip()
        if re.match(r"^#{2,}\s+Injectable Skills\b", line, re.IGNORECASE):
            in_sec = True
            out_lines.append(raw)
            continue
        if in_sec and re.match(r"^#{2,}\s+", line):
            in_sec = False
            out_lines.append(raw)
            continue
        if not in_sec or not line.startswith("|") or _is_separator_row(line):
            out_lines.append(raw)
            continue
        cells = [c.strip() for c in raw.strip().strip("|").split("|")]
        if cells and cells[0].strip().strip("`*").lower() in (
            "skill", "injectable", "injectable skill"
        ):
            out_lines.append(raw)
            continue
        joined_low = raw.lower()
        skill_name = ""
        for name in list(_INJECTABLE_FLAG_TO_SKILL.values()) + list(
            _INJECTABLE_PROTOCOL_TO_SKILL.values()
        ):
            if name.lower() in joined_low:
                skill_name = name
                break
        if not skill_name:
            out_lines.append(raw)
            continue
        # Only touch a row that the validator would genuinely flag: a row whose
        # trigger IS present in detected_patterns.md (promote NO->YES + fill
        # rationale) or a Required=YES row left with a placeholder (fill
        # rationale only). An UNSELECTED catalog row (Required=NO, trigger
        # absent) is left exactly as-is — never mass-promoted.
        required_yes = bool(
            re.search(r"required\??\s*(?:=|:)?\s*\|?\s*yes\b", joined_low)
            or re.search(r"\|\s*yes\s*\|", joined_low)
        )
        trigger_present = False
        for flag, name in _INJECTABLE_FLAG_TO_SKILL.items():
            if name != skill_name:
                continue
            if flag == "NON_EVM_TARGET" and lang != "evm":
                # EVM-side skill: only an explicit EVM audit serializes on the
                # EVM side; skip the flag for any non-EVM language (see driver gate).
                continue
            if _detected_flag_present(scratchpad, flag):
                trigger_present = True
        if (not trigger_present) and _detected_protocol_type(scratchpad):
            for ptype, name in _INJECTABLE_PROTOCOL_TO_SKILL.items():
                if name == skill_name and _detected_protocol_type(scratchpad) == ptype:
                    trigger_present = True
        promote_to_yes = trigger_present and not required_yes
        fill_rationale = promote_to_yes or required_yes
        if not promote_to_yes and not fill_rationale:
            out_lines.append(raw)
            continue
        new_cells = list(cells)
        row_changed = False
        for i, c in enumerate(new_cells):
            cl = c.strip().lower()
            if promote_to_yes and cl in ("no",):
                new_cells[i] = "YES"
                row_changed = True
            elif fill_rationale and (
                _INJECTABLE_PLACEHOLDER_RE.fullmatch(c.strip())
                or _INJECTABLE_PLACEHOLDER_RE.search(c)
            ):
                new_cells[i] = (
                    "trigger present in detected_patterns.md "
                    "(mechanically promoted)"
                )
                row_changed = True
        if row_changed:
            changed += 1
            out_lines.append("| " + " | ".join(new_cells) + " |")
        else:
            out_lines.append(raw)
    if changed:
        try:
            tr_path.write_text("\n".join(out_lines) + ("\n" if text.endswith("\n") else ""), encoding="utf-8")
        except Exception as exc:
            log.warning("[injectable promotion] write failed: %s", exc)
            return 0
    return changed


def _validate_depth_promotion_receipt(scratchpad: Path, min_confidence: float = 0.70) -> list[str]:
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return []
    inv_text = inv.read_text(encoding="utf-8", errors="replace")
    scores = _parse_depth_confidence_scores(scratchpad)

    # v2.4.9: read the promotion receipt to identify findings intentionally
    # blocked as high-confidence duplicates. These should not be flagged as
    # missing — the promoter already decided they overlap an existing entry.
    blocked_ids: set[str] = set()
    receipt = scratchpad / "depth_promotion_receipt.md"
    if receipt.exists():
        try:
            receipt_text = receipt.read_text(encoding="utf-8", errors="replace")
            # Extract only the "Likely Duplicates" section — these were
            # intentionally blocked or tagged. Promoted IDs are NOT included
            # (they should be in inventory; if removed later that's a real gap).
            dup_sec = receipt_text.split("## Likely Duplicates")
            if len(dup_sec) > 1:
                dup_body = dup_sec[1].split("\n## ")[0]
                for m in re.finditer(
                    r"- `(" + _PROMOTABLE_FEEDER_ID_PATTERN + r")`", dup_body
                ):
                    blocked_ids.add(m.group(1))
        except Exception:
            pass

    missing: list[str] = []
    for pat in _DEPTH_PROMOTION_FILES:
        for p in sorted(scratchpad.glob(pat)):
            for item in _parse_depth_finding_blocks(p):
                fid = item["id"]
                if fid in blocked_ids:
                    continue
                score = scores.get(fid)
                status = _verifier_status_from_text(f"**Verdict**: {item.get('verdict', '')}") if item.get("verdict") else ""
                if status and not _is_reportable_verdict(status):
                    continue
                if status != "CONFIRMED" and score is not None and score < min_confidence:
                    continue
                # Closes F-PROM-01: word-boundary match. Plain substring
                # match false-passed `DCI-1` whenever `DCI-12` was already
                # present in inventory, hiding genuinely-missing promotions.
                if not re.search(rf"\b{re.escape(fid)}\b", inv_text):
                    missing.append(fid)
    if missing:
        return [
            "depth promotion receipt: high-confidence depth findings missing "
            "from findings_inventory.md: " + ", ".join(sorted(set(missing))[:12])
        ]
    return []


def _validate_depth_promotion_dedup(scratchpad: Path) -> list[str]:
    """Advisory validator: flags suspiciously high promotion inflation.

    Warns (does NOT block) when depth promotion added >40% more findings
    relative to the pre-promotion inventory AND the promoted findings
    cover fewer than 3 distinct files. High inflation over few files
    suggests duplicate clusters that the promotion gate's 0.80 threshold
    did not catch.
    """
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return []
    inv_text = inv.read_text(encoding="utf-8", errors="replace")
    pre_count = len(re.findall(
        r"###\s+Finding\s+\[INV-\d+\]",
        inv_text.split("## Depth Promotion Supplement")[0]
        if "## Depth Promotion Supplement" in inv_text else inv_text,
    ))
    post_count = len(re.findall(r"###\s+Finding\s+\[INV-\d+\]", inv_text))
    promoted_count = post_count - pre_count
    if pre_count == 0 or promoted_count <= 0:
        return []
    ratio = promoted_count / pre_count
    supplement = inv_text.split("## Depth Promotion Supplement")[1] if "## Depth Promotion Supplement" in inv_text else ""
    promoted_files = set()
    for loc_m in re.finditer(r"\*\*Location\*\*:\s*(\S+)", supplement, re.IGNORECASE):
        f = re.sub(r":L?\d+.*$", "", _norm_loc(loc_m.group(1)))
        if f:
            promoted_files.add(f)
    issues: list[str] = []
    if ratio > 0.40 and len(promoted_files) < 3:
        issues.append(
            f"inflation advisory: depth promotion added {promoted_count} findings "
            f"({ratio:.0%} of {pre_count} pre-existing) across only "
            f"{len(promoted_files)} file(s). Review dedup_candidate_pairs.md "
            f"for potential duplicates."
        )
    return issues


def _validate_report_tier_completeness(scratchpad: Path, phase_name: str) -> list[str]:
    """Ensure a report tier writer produced one ### section per assigned finding.

    Complements the §6b.1 bash gate in commands/plamen-l1.md: that gate only
    fires inside the LLM subprocess, and is bypassed when the Python driver
    short-circuits to a placeholder write (count == 0 branch). This helper is
    a Python-side backstop run against every tier phase after gate_passes()
    succeeds — if the tier file exists but has fewer findings than the index
    assigned, the assembler will invent placeholder rows like
    "[Unverified Medium finding N]" in the final report.
    """
    _tier_m = re.match(r"^report_(critical_high|medium|low_info)(?:_[a-z])?$", phase_name)
    if not _tier_m:
        return []
    filename = f"{phase_name}.md"
    tier_base = _tier_m.group(1)

    _shard_m = re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase_name)
    if _shard_m:
        shards = ensure_report_tier_shards(scratchpad, tier_base)
        expected = len(shards.get(phase_name, []))
    else:
        key = tier_base
        counts = parse_report_index_counts(scratchpad)
        if not counts or sum(counts.values()) == 0:
            idx_path = scratchpad / "report_index.md"
            if idx_path.exists() and idx_path.stat().st_size > 200:
                return [
                    f"tier completeness: parse_report_index_counts returned "
                    f"all zeros despite report_index.md existing ({idx_path.stat().st_size}B) — "
                    f"possible parse failure"
                ]
            return []
        expected = counts.get(key, 0)

    if expected == 0:
        return []

    tier_file = scratchpad / filename
    if not tier_file.exists():
        return [f"tier completeness: {filename} missing (expected {expected} findings)"]

    try:
        text = tier_file.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [f"tier completeness: cannot read {filename}"]

    actual = len(re.findall(r"(?m)^#{2,3}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[[CHMLI]-\d+\]", text))
    # Quality Observations megasection: findings as table rows (| I-03 | ... |)
    qo_match = re.search(r"(?mi)^##\s+Quality\s+Observations", text)
    if qo_match:
        qo_text = text[qo_match.end():]
        qo_end = re.search(r"(?m)^##\s+", qo_text)
        if qo_end:
            qo_text = qo_text[:qo_end.start()]
        actual += len(re.findall(r"(?m)^\|\s*[CHMLI]-\d+\s*\|", qo_text))
    if actual < expected:
        return [
            f"tier completeness: {filename} has {actual} findings "
            f"but index assigns {expected}"
        ]
    return []


def _scan_for_halt_and_gatefail(scratchpad: Path,
                                violations_offset: int = 0) -> list[str]:
    """Return depth-agent identifiers implicated by hard-stop policy signals.

    Signals:
    - A depth artifact whose first line starts with `[HALT]`
    - New `violations.md` entries matching `[GATE FAIL] ... pre-baked reads`

    violations_offset lets callers scan only the lines appended during the
    current phase attempt, so stale violations from earlier attempts do not
    poison retries.
    """
    offenders = set()

    for p in scratchpad.glob("depth*_findings.md"):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                first = f.readline().strip()
        except Exception:
            continue
        if first.startswith("[HALT]"):
            offenders.add(p.stem.replace("_findings", ""))

    vp = scratchpad / "violations.md"
    if vp.exists():
        try:
            with vp.open("r", encoding="utf-8", errors="replace") as f:
                if violations_offset > 0:
                    f.seek(violations_offset)
                text = f.read()
        except Exception:
            text = ""
        gatefail_re = re.compile(
            r"(?im)^\[GATE FAIL\]\s+([^:\n]+):.*pre-baked reads"
        )
        for m in gatefail_re.finditer(text):
            offenders.add(m.group(1).strip())

    return sorted(offenders)


_NEVER_CUT_FILENAME_ALIASES = (
    # (canonical, alias) — alias is the `depth_`-prefixed form some
    # orchestrators emit when grouping iter1 supplementary outputs under
    # the depth-findings naming convention. Auto-renamed to canonical so
    # downstream consumers (chain analysis, report tier writers) find the
    # file at the path methodology documents.
    ("perturbation_findings.md", "depth_perturbation_findings.md"),
    ("design_stress_findings.md", "depth_design_stress_findings.md"),
)


def _normalize_never_cut_filenames(scratchpad: Path) -> list[str]:
    """Rename `depth_`-prefixed never-cut aliases to canonical names.

    v2.3.4 — gate tolerance was insufficient: the orchestrator's choice of
    `depth_perturbation_findings.md` over `perturbation_findings.md` halted
    the L1 audit at the never-cut gate. Even with alternation accepted at
    the gate, downstream consumers (~33 files reference the canonical name)
    would still miss the artifact. Auto-rename canonicalizes once at gate
    time so the rest of the pipeline sees the methodology-documented name.

    No-op if canonical already exists OR alias doesn't exist. Same approach
    as v2.1.2 A.5's `findings_breadth_*` -> `analysis_*` shim.
    """
    renamed: list[str] = []
    for canonical, alias in _NEVER_CUT_FILENAME_ALIASES:
        canon_p = scratchpad / canonical
        alias_p = scratchpad / alias
        if canon_p.exists() or not alias_p.exists():
            continue
        try:
            alias_p.rename(canon_p)
            renamed.append(f"{alias} -> {canonical}")
        except Exception:
            # Don't break the gate on rename failure; the alternation in
            # NEVER_CUT_GROUPS still accepts the alias form as a fallback.
            pass
    if renamed:
        try:
            vp = scratchpad / "violations.md"
            with vp.open("a", encoding="utf-8") as f:
                f.write("\n## Never-cut filename normalization (v2.3.4)\n")
                for r in renamed:
                    f.write(f"- {r}\n")
        except Exception:
            pass
    return renamed


def _assert_never_cut_artifacts(
    scratchpad: Path,
    groups: Optional[list] = None,
) -> list[str]:
    """Return missing never-cut artifact groups for the depth phase.

    When `groups` is None, defaults to L1_NEVER_CUT_ARTIFACT_GROUPS for
    backwards compatibility. SC callers pass sc_never_cut_groups(mode).

    v2.3.4: canonicalizes `depth_`-prefixed aliases first so downstream
    consumers see the methodology-documented filename.
    """
    _normalize_never_cut_filenames(scratchpad)
    if groups is None:
        groups = L1_NEVER_CUT_ARTIFACT_GROUPS
    missing = []
    for group in groups:
        if not any((scratchpad / name).exists() for name in group):
            missing.append(" or ".join(group))
    return missing


def _depth_artifact_is_stub(path: Path) -> Optional[str]:
    """Return a stub reason for a depth never-cut artifact, or None if substantive.

    Conservative on purpose (S1.1): flags only unambiguous stubs — header-only
    WRITE-THEN-VERIFY reservations, driver-synthesized placeholders, uniform
    confidence tables — so a genuine clean agent result is never false-rejected
    (false rejection would be a new halt, which this work explicitly forbids).
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    name = path.name
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        text = ""
    low = text.lower()

    # WRITE-THEN-VERIFY header reservation that was never populated.
    if "writing in progress" in low:
        return f"{name} (stub — WRITE-THEN-VERIFY reservation not populated)"

    # v2.0.5 (B2): the PLAMEN-STUB sentinel comment is an unambiguous
    # stub marker injected by `_render_reservation_header` (the source-
    # of-truth helper in plamen_prompt.py). Any file containing this
    # sentinel is a stub regardless of size — newer audits opt into
    # this contract; legacy audits without it fall back to existing
    # size/shape heuristics below.
    if "plamen-stub:" in low:
        return f"{name} (stub — PLAMEN-STUB sentinel present, content to follow)"

    if name in ("perturbation_findings.md", "depth_perturbation_findings.md"):
        # A real perturbation file carries block tables; 79-byte reservations
        # (the observed failure) are well under 1KB.
        if size < 1024:
            return f"{name} (stub — {size} bytes, perturbation blocks absent)"
        return None

    if name == "confidence_scores.md":
        if re.search(r"(?im)^\s*>?\s*\**status\**\s*:\s*\**\s*synthesized\b", text):
            return f"{name} (stub — driver-synthesized placeholder)"
        scores = _parse_confidence_scores_permissive(path.parent)
        if len(scores) >= 4 and len(set(scores.values())) == 1:
            val = next(iter(set(scores.values())))
            return (
                f"{name} (stub — {len(scores)} findings all composite "
                f"{val}, formulaic)"
            )
        # Alignment with the depth GATE (_validate_confidence_scores_quality):
        # it degrades depth when a thorough run has <=2 distinct composites
        # across >=8 findings (the Codex 0.74/0.81-for-everything signature).
        # Previously this synthesis check only caught the all-identical case
        # (==1), so a 2-distinct formulaic stub PASSED here (never recomputed)
        # yet FAILED the gate -> guaranteed degrade with no recovery. Use the
        # SAME definition so the lifecycle synth mechanically recomputes real
        # per-finding scores before the gate runs. Conservative: only the
        # narrow low-cardinality-on-many-findings shape, never a genuinely
        # differentiated table.
        uniq = set(scores.values())
        if len(scores) >= 8 and len(uniq) <= 2:
            return (
                f"{name} (stub — {len(scores)} findings with only "
                f"{len(uniq)} distinct composite value(s) "
                f"({', '.join(f'{v:.3f}' for v in sorted(uniq))}), formulaic)"
            )
        # F2.b: DRIVER-COMPUTED `(no findings produced)` placeholder is a
        # stub ONLY when real depth findings exist on disk — a legitimate
        # clean-codebase audit can produce zero findings and that is NOT
        # a stub. Catches the attempt-1 placeholder that survived past
        # attempt-2 producing real findings.
        is_driver_no_rows = (
            re.search(r"\bdriver-computed\b", text, re.IGNORECASE)
            and (
                re.search(r"\(no\s+findings\s+produced\)", text, re.IGNORECASE)
                or len(scores) == 0
            )
        )
        if is_driver_no_rows:
            scratchpad = path.parent
            finding_globs = (
                "depth_*_findings.md",
                "blind_spot_*_findings.md",
                "niche_*_findings.md",
                "validation_sweep_findings.md",
                "scanner_*_findings.md",
                "design_stress_findings.md",
                "perturbation_findings.md",
            )
            has_real_findings = False
            for pat in finding_globs:
                for p in scratchpad.glob(pat):
                    try:
                        body = p.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        continue
                    # Ship D (SW07-1): accept H2 AND H3 finding blocks (depth
                    # uses `### Finding [ID]`); the old H2-only check matched
                    # the driver's old H2-only blindness.
                    if FINDING_BLOCK_HEADING_RE.search(body):
                        has_real_findings = True
                        break
                if has_real_findings:
                    break
            if has_real_findings:
                return (
                    f"{name} (stub — DRIVER-COMPUTED placeholder, "
                    f"no real rows despite findings on disk)"
                )
        return None

    if name in ("skill_execution_gaps.md", "skill_execution_checklist.md"):
        if size < 200:
            return f"{name} (stub — {size} bytes, header-only)"
        return None

    # Generic depth / scanner / niche findings files.
    if size < 200:
        return f"{name} (stub — {size} bytes)"
    return None


def _validate_depth_artifact_substance(
    scratchpad: Path, mode: str, pipeline: str = "sc"
) -> list[str]:
    """S1.1: reject stub never-cut artifacts that pass the existence-only gate.

    `_assert_never_cut_artifacts` checks `.exists()` only — a 79-byte
    WRITE-THEN-VERIFY reservation or a driver-synthesized confidence stub
    slips straight through. This walks the same never-cut groups and reports
    any group whose ONLY present members are stubs, so the depth gate can
    treat that group as unsatisfied.
    """
    if pipeline == "l1":
        groups = l1_never_cut_groups(mode)
    else:
        groups = sc_never_cut_groups(mode)
    stubs: list[str] = []
    for group in groups:
        present = [scratchpad / n for n in group if (scratchpad / n).exists()]
        if not present:
            continue  # missing entirely — _assert_never_cut_artifacts owns it
        reasons = [_depth_artifact_is_stub(p) for p in present]
        # Group is satisfied if ANY present member is substantive.
        if all(r is not None for r in reasons):
            reason_str = "; ".join(r for r in reasons if r)
            # Core/Light: a present, substantive-but-UNIFORM confidence table is
            # advisory only (2-axis scoring; Core/Light have NO iter2/iter3
            # adaptive routing that depends on differentiated scores) and the
            # mechanical scorer (_compute_depth_confidence) cannot differentiate
            # findings that carry no evidence/depth-evidence tags -> every row
            # lands on the same composite. Mirror the L1 depth gate, which treats
            # confidence uniformity as a NON-blocking warning outside Thorough.
            # Genuine stubs (empty / driver-synthesized placeholder / no rows)
            # still block here; only the "formulaic" uniformity reason is
            # downgraded. Thorough keeps it blocking (iter2 enforcement depends
            # on differentiated scores).
            if (
                (mode or "core").lower() != "thorough"
                and len(group) == 1
                and group[0] == "confidence_scores.md"
                and "formulaic" in reason_str
            ):
                continue
            stubs.append(reason_str)
    return stubs


def _match_label_status(text: str, label: str):
    """Match `label: STATUS rest` in either bullet/plain OR markdown-table form.

    Accepts any of:
      * `depth-state-trace: SPAWNED path/to/file.md`
      * `- depth-state-trace: SPAWNED path/to/file.md`
      * `| depth-state-trace | SPAWNED | path/to/file.md |`

    The driver can't force models to emit one specific shape; the
    methodology prompt asks for plain `label: STATUS`, but models sometimes
    normalize the block into a markdown table ("it looks like structured
    metadata, so it belongs in a table"). Accepting both prevents a
    false-positive gate failure on a semantically-correct artifact. Returns
    (status, rest_of_line) or None.
    """
    _NC_STATUSES = r"SPAWNED|SKIPPED|COMPLETED|DONE|RAN|YES"
    bullet = re.search(
        rf"(?im)^\s*[-*]?\s*{re.escape(label)}\s*:\s*({_NC_STATUSES})\b\s*(.*)$",
        text,
    )
    if bullet:
        raw = bullet.group(1).upper()
        status = "SPAWNED" if raw in ("COMPLETED", "DONE", "RAN", "YES") else raw
        return status, (bullet.group(2) or "").strip()
    table = re.search(
        rf"(?im)^\s*\|\s*{re.escape(label)}\s*\|\s*({_NC_STATUSES})\b\s*\|?\s*([^|\n]*)\|?",
        text,
    )
    if table:
        raw = table.group(1).upper()
        status = "SPAWNED" if raw in ("COMPLETED", "DONE", "RAN", "YES") else raw
        return status, (table.group(2) or "").strip()
    return None


def _assert_never_cut_checkpoint(
    scratchpad: Path, mode: str = "thorough"
) -> list[str]:
    """Validate never_cut_checkpoint.md emitted by the depth loop.

    v2.6.3: mode-aware — design-stress, perturbation, and skill-execution-
    checklist labels are only required in Thorough mode.
    """
    p = scratchpad / "never_cut_checkpoint.md"
    if not p.exists():
        return ["never_cut_checkpoint.md missing"]
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["never_cut_checkpoint.md unreadable"]

    issues = []
    base_labels = [
        "depth-consensus-invariant",
        "depth-network-surface",
        "depth-state-trace",
        "depth-external",
        "depth-edge-case",
        "confidence-scoring",
    ]
    thorough_only_labels = [
        "design-stress",
        "perturbation",
        "skill-execution-checklist",
    ]
    labels = list(base_labels)
    if mode == "thorough":
        labels = labels + thorough_only_labels
    for label in labels:
        result = _match_label_status(text, label)
        if result is None:
            issues.append(f"{label}: missing entry")
            continue
        status, rest = result
        if status == "SKIPPED":
            reason_match = re.search(r"\b([A-Z_]+)\b", rest)
            reason = reason_match.group(1) if reason_match else ""
            if not reason:
                issues.append(f"{label}: SKIPPED without any reason")
            elif reason not in _NEVER_CUT_SKIP_REASONS:
                log.warning(
                    "[_assert_never_cut_checkpoint] %s: SKIPPED with "
                    "non-allowlisted reason %r (soft — structured skip "
                    "intent accepted)", label, reason,
                )
    return issues


def _validate_depth_iterations(scratchpad: Path, mode: str) -> list[str]:
    """Soft validator for the depth iteration counter in adaptive_loop_log.md.

    plamen.md line 899 already writes this artifact; line 946 already asserts
    `iter >= 2 when uncertain Medium+ findings exist after iter 1`. The LLM
    orchestrator frequently forgets self-assertions (the motivating failure
    mode for V2), so we re-run a driver-side version of the same check.

    Design choice — SOFT on missing file:
    - Absent file returns []. Methodology owns file-existence enforcement;
      duplicating it here would false-positive against Light mode (where the
      loop may be skipped) and against in-flight audits from older driver
      versions.
    - Present-but-unparseable file returns []. LLM emission format is not
      fixed; we never break the pipeline on our own parse failure.
    - The hard check is thorough-mode-specific: iter 1 uncertain Medium+ > 0
      AND total iterations < 2 → issue string.
    """
    p = scratchpad / "adaptive_loop_log.md"
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    # Total iterations — accept "iterations: 3", "Total iterations: 3",
    # "| iterations | 3 |", "Iteration count: 3", or fall back to counting
    # distinct "## Iteration N" / "### Iteration N" headers.
    iter_count = None
    for pattern in (
        r"(?im)^\s*[-*]?\s*(?:total\s+)?iterations?\s*(?:count)?\s*:\s*(\d+)\b",
        r"(?im)^\s*\|\s*(?:total\s+)?iterations?\s*(?:count)?\s*\|\s*(\d+)\b",
        r"(?im)^\s*iteration\s+count\s*:\s*(\d+)\b",
    ):
        m = re.search(pattern, text)
        if m:
            iter_count = int(m.group(1))
            break
    if iter_count is None:
        headers = re.findall(r"(?im)^\s*#{2,4}\s*iteration\s+(\d+)\b", text)
        if headers:
            iter_count = max(int(h) for h in headers)
    if iter_count is None:
        return []  # format not recognized — stay soft

    if mode != "thorough":
        return []

    # Iter 1 uncertain Medium+ count. Accept several phrasings.
    uncertain_medium_plus = None
    for pattern in (
        r"(?im)iter(?:ation)?\s*1[^\n]*?uncertain\s+medium\+?\s*:?\s*(\d+)\b",
        r"(?im)uncertain\s+medium\+?\s+after\s+iter(?:ation)?\s*1\s*:?\s*(\d+)\b",
        r"(?im)^\s*[-*]?\s*iter1_uncertain_medium_plus\s*:\s*(\d+)\b",
        r"(?im)^\s*\|\s*iter1_uncertain_medium_plus\s*\|\s*(\d+)\b",
    ):
        m = re.search(pattern, text)
        if m:
            uncertain_medium_plus = int(m.group(1))
            break
    if uncertain_medium_plus is None:
        return []  # can't apply the conditional assertion without this signal

    if uncertain_medium_plus > 0 and iter_count < 2:
        return [
            f"adaptive_loop shows {iter_count} iteration(s) but iter 1 left "
            f"{uncertain_medium_plus} uncertain Medium+ finding(s) — thorough "
            f"mode requires iter >= 2 (plamen.md line 946)"
        ]

    # Fallback: if adaptive_loop_log didn't have parseable uncertain counts,
    # try mechanical detection from confidence_scores.md + inventory severities.
    if uncertain_medium_plus is None:
        issues = _validate_confidence_iter2_mandatory(scratchpad)
        if issues:
            return issues

    return []


def _parse_confidence_scores_permissive(
    scratchpad: Path,
) -> dict[str, float]:
    """Parse confidence_scores.md accepting ANY finding ID format.

    Unlike _parse_depth_confidence_scores (which uses _PROMOTABLE_FEEDER_ID_PATTERN
    and misses verbose LLM IDs like DEPTH-CONSENSUS-INVARIANT-1), this parser
    accepts any non-empty text in the Finding ID column. Used by quality
    validators where we care about score distribution, not ID format.
    """
    p = scratchpad / "confidence_scores.md"
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}

    scores: dict[str, float] = {}
    id_idx: int | None = None
    composite_idx: int | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("|") and stripped.endswith("|")):
            if stripped:
                id_idx = composite_idx = None
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and all(set(c) <= {"-", ":"} for c in cells):
            continue
        norm = [re.sub(r"[^a-z0-9]+", "", c.lower()) for c in cells]
        if "findingid" in norm and "composite" in norm:
            id_idx = norm.index("findingid")
            composite_idx = norm.index("composite")
            continue
        if (
            id_idx is not None
            and composite_idx is not None
            and len(cells) > max(id_idx, composite_idx)
        ):
            fid = cells[id_idx].strip()
            if not fid or fid.startswith("-"):
                continue
            m = re.search(
                r"(?<![A-Za-z0-9.\-])(?:0?\.\d+|1\.0+)(?![A-Za-z0-9.])",
                cells[composite_idx],
            )
            if m:
                scores[fid] = float(m.group(0))
    return scores


def _validate_confidence_scores_quality(scratchpad: Path, mode: str) -> list[str]:
    """Detect formulaic stub confidence scores (all identical composites).

    When a Codex/LLM subprocess stamps every finding with the same score,
    it treated confidence scoring as a checkbox rather than doing per-finding
    analysis. This prevents proper iteration 2 routing.

    Returns issues only in thorough mode and only when > 3 findings all share
    the same composite score.
    """
    if mode != "thorough":
        return []
    scores = _parse_confidence_scores_permissive(scratchpad)
    if len(scores) < 4:
        return []
    unique_values = set(scores.values())
    if len(unique_values) == 1:
        val = next(iter(unique_values))
        return [
            f"confidence_scores.md has {len(scores)} findings all with "
            f"identical composite {val} — formulaic stub, not per-finding "
            f"analysis. Iteration 2 routing is unreliable."
        ]
    if len(unique_values) <= 2 and len(scores) >= 8:
        return [
            f"confidence_scores.md has {len(scores)} findings with only "
            f"{len(unique_values)} distinct composite value(s) "
            f"({', '.join(f'{v:.3f}' for v in sorted(unique_values))}) — "
            f"likely formulaic stub."
        ]
    return []


def _validate_confidence_iter2_mandatory(scratchpad: Path) -> list[str]:
    """Mechanical check: UNCERTAIN Medium+ findings exist but no iter2 artifacts.

    Fallback for _validate_depth_iterations when adaptive_loop_log.md doesn't
    contain parseable uncertain-medium-plus counts. Uses confidence_scores.md
    and findings_inventory.md directly. Only fires in thorough mode (caller
    in _validate_depth_iterations already gates on mode == "thorough").
    """
    scores = _parse_confidence_scores_permissive(scratchpad)
    if not scores:
        return []

    uncertain_ids = {fid for fid, s in scores.items() if s < 0.7}
    if not uncertain_ids:
        return []

    # Severity resolution does NOT live in confidence_scores.md (it has no
    # Severity column — only Finding ID | Evidence | Consensus | Quality | RAG
    # | Composite | Classification). Resolving severity by ID-joining against
    # findings_inventory.md is FAIL-OPEN: when the inventory uses a different
    # finding-ID namespace than the scoring file (a routine condition on the
    # Claude PTY worker-pool path), every search misses, medium_plus stays 0,
    # and the mandated Devil's-Advocate iteration is silently skipped. Resolve
    # severity from the depth findings files (same agent-finding ID namespace
    # as the uncertain IDs) first, fall back to the inventory window, and FAIL
    # CLOSED (treat as Medium+) when severity is unresolvable for an uncertain
    # ID — recall safety. Worst case is one unnecessary DA worker; never again
    # a silent skip of a mandated iteration.

    # (1) Build id -> severity from the depth findings files (no ID-join).
    sev_by_id: dict[str, str] = {}
    for pattern in _DEPTH_PROMOTION_FILES:
        for path in scratchpad.glob(pattern):
            for blk in _parse_depth_finding_blocks(path):
                bid = (blk.get("id") or "").strip().upper()
                if not bid:
                    continue
                sev = (blk.get("severity") or "").strip()
                if not sev:
                    continue
                # Keep the highest-rank severity seen for an ID.
                if bid not in sev_by_id or _severity_rank(sev) > _severity_rank(sev_by_id[bid]):
                    sev_by_id[bid] = sev

    # (2) Inventory window fallback (still correct when namespaces align, and
    #     covers breadth/scanner-only findings absent from depth files).
    inv = scratchpad / "findings_inventory.md"
    inv_text = ""
    if inv.exists():
        try:
            inv_text = inv.read_text(encoding="utf-8", errors="replace")
        except Exception:
            inv_text = ""

    def _severity_from_inventory(fid: str) -> str | None:
        if not inv_text:
            return None
        m = re.search(re.escape(fid), inv_text)
        if not m:
            return None
        window = inv_text[m.start():m.start() + 500]
        wm = re.search(
            r"(?i)(?:\*\*)?Severity(?:\*\*)?\s*:?\s*"
            r"(Critical|High|Medium|Low|Informational|Info)",
            window,
        )
        return wm.group(1) if wm else None

    medium_plus_uncertain = 0
    below_medium = 0
    unresolved = 0
    for fid in uncertain_ids:
        sev = sev_by_id.get(fid.strip().upper())
        if not sev:
            sev = _severity_from_inventory(fid)
        if not sev:
            # FAIL CLOSED: unresolvable severity counts as Medium+ so the
            # mandated DA iteration still fires (recall safety).
            unresolved += 1
            continue
        if _severity_rank(sev) >= 2:  # Medium=2, High=3, Critical=4
            medium_plus_uncertain += 1
        else:
            below_medium += 1

    # Only skip iter-2 when EVERY uncertain finding resolved to a below-Medium
    # severity (the sole case where skipping is correct per
    # phase4-confidence-scoring.md Rule 3a).
    if medium_plus_uncertain == 0 and unresolved == 0:
        return []

    # Tolerate filename drift. The driver's manifest instructs the LLM to
    # write `depth_iter2_*_findings.md`, but the orchestrator routinely
    # drops the `_findings` segment and writes `depth_iter2_state_trace.md`,
    # `depth_iter2_edge_case.md`, etc. A strict glob falsely concludes
    # "no iter2 artifacts exist" and re-runs the entire opus depth phase
    # (~$15-30 waste). Same class as the v2.3.4 perturbation_findings
    # canonicalization. iter3 outputs also imply iter2 completed, so they
    # satisfy this gate too.
    # The driver's _canonicalize_depth_iter_filenames normally rewrites every
    # iteration-token variant to the canonical `depth_iter{N}_{role}_findings.md`
    # form BEFORE this gate runs. These globs are the defense-in-depth path
    # for when canonicalization hit an OSError. They cover both the
    # abbreviated (`iter2`) and spelled-out (`iteration2`) tokens in any
    # filename position — `iteration2` does NOT contain the substring
    # `iter2`, so both families need their own glob.
    da_files = (
        list(scratchpad.glob("depth_da_*_findings.md"))
        + list(scratchpad.glob("depth_iter2_*_findings.md"))
        + list(scratchpad.glob("depth_iter2_*.md"))
        + list(scratchpad.glob("depth_iter3_*.md"))
        + list(scratchpad.glob("depth_*iter2*.md"))
        + list(scratchpad.glob("depth_*iter3*.md"))
        + list(scratchpad.glob("depth_*iteration2*.md"))
        + list(scratchpad.glob("depth_*iteration3*.md"))
        + list(scratchpad.glob("da_iter2_*.md"))
        + list(scratchpad.glob("da_iter3_*.md"))
        + list(scratchpad.glob("da-iter2-*.md"))
        + list(scratchpad.glob("da-iter3-*.md"))
    )
    if da_files:
        return []

    suffix = ""
    if unresolved:
        suffix = (
            f" (+{unresolved} with unresolvable severity, treated as "
            f"Medium+ for recall safety)"
        )
    return [
        f"confidence_scores.md shows {medium_plus_uncertain} uncertain "
        f"Medium+ finding(s) (composite < 0.7){suffix} but no iter2/DA "
        f"artifacts exist — thorough mode requires iteration 2"
    ]


def _validate_depth_coverage(scratchpad: Path, mode: str) -> list[str]:
    """Soft validator for iter2 coverage of mechanical iter1 gaps.

    AD-1 'Prior Path' is agent-written prose and can claim comprehensive iter1
    coverage while iter1 actually produced zero Depth Evidence tags for many
    in-scope locations. phase4b-da-iter2.md Pre-step 4 writes
    `iter1_coverage_gap.md` as the set-based mechanical complement. This
    validator catches the specific failure mode where iter2 re-states iter1
    in different words ('ceremonial rewrite') without producing new Depth
    Evidence tags for the mechanically-identified gap.

    Design choice — SOFT on every failure mode (mirrors _validate_depth_iterations):
    - Missing iter1_coverage_gap.md → []. Methodology owns that artifact;
      we false-positive against Core mode and non-thorough configs otherwise.
    - Empty gap file → []. Nothing to cover means nothing to violate.
    - Missing depth_da_*_findings.md → []. DA iter2 was either skipped
      (no Medium+ uncertain findings) or the methodology chose to pass.
    - Files present but unparseable → []. Never break on own parse failure.

    Hard check (thorough only): iter1_coverage_gap.md is non-empty AND at
    least one depth_da_*_findings.md exists AND across ALL DA iter2 outputs
    the combined Depth Evidence tag count is zero. This is the ceremonial-
    rewrite signature.
    """
    if mode != "thorough":
        return []
    gap = scratchpad / "iter1_coverage_gap.md"
    if not gap.exists():
        return []
    try:
        gap_text = gap.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    gap_lines = [
        ln for ln in gap_text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not gap_lines:
        return []

    da_files = list(scratchpad.glob("depth_da_*_findings.md"))
    if not da_files:
        return []

    from plamen_parsers import _DEPTH_EVIDENCE_TAG_RE
    tag_pattern = _DEPTH_EVIDENCE_TAG_RE
    total_tags = 0
    for f in da_files:
        try:
            t = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        total_tags += len(tag_pattern.findall(t))

    if total_tags == 0:
        return [
            f"iter2 DA agents produced 0 Depth Evidence tags across "
            f"{len(da_files)} output file(s) while iter1_coverage_gap.md "
            f"lists ~{len(gap_lines)} uncovered location(s) — probable "
            f"ceremonial rewrite of iter1 rather than new analysis "
            f"(phase4b-da-iter2.md AD-5: new-evidence-only re-scoring)"
        ]
    return []


_PERCONTRACT_EXCLUSION_HEADING_RE = re.compile(
    r"(?im)^\s{0,3}#{1,6}\s+.*"
    r"(?:exclusion|already[ _-]found|already[ _-]known|not[ _-]duplicat)"
    r".*$"
)


def _build_percontract_referent_universe(
    scratchpad: Path,
) -> tuple[set[str], set[str]]:
    """Return ``(finding_ids, locations)`` that legitimately existed in the
    orchestrator-provided exclusion universe for Phase 3c per-contract agents.

    The universe is the union of:
    - first-pass breadth outputs (``analysis_*.md``), EXCLUDING this phase's own
      ``analysis_rescan_*`` and ``analysis_percontract_*`` outputs, and
    - the additional re-scan outputs (``analysis_rescan_*.md``).

    Finding IDs are normalized upper-case (e.g. ``B1-2``); locations are
    normalized lower-case with whitespace stripped so a cited
    ``Vault.sol:L88`` matches the universe regardless of case.
    All parse failures degrade to empty contributions — never raise.
    """
    finding_ids: set[str] = set()
    locations: set[str] = set()

    sources: list[Path] = []
    for p in sorted(scratchpad.glob("analysis_*.md")):
        name = p.name
        if name.startswith("analysis_rescan_") or name.startswith(
            "analysis_percontract_"
        ):
            continue
        sources.append(p)
    sources.extend(sorted(scratchpad.glob("analysis_rescan_*.md")))

    for p in sources:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in _FINDING_BLOCK_RE.finditer(text):
            finding_ids.add(m.group(1).strip().upper())
        for m in _BRACKETED_ID_RE.finditer(text):
            finding_ids.add(m.group(1).strip().upper())
        for m in _TABLE_LOCATION_RE.finditer(text):
            locations.add(_norm_referent_location(m.group(1)))
        for m in _LOCATION_RE.finditer(text):
            for loc in _TABLE_LOCATION_RE.findall(m.group(1)):
                locations.add(_norm_referent_location(loc))
    return finding_ids, locations


def _norm_referent_location(loc: str) -> str:
    """Normalize a ``file:line`` location for set-membership comparison:
    lower-case, drop a leading ``L`` on the line number, strip whitespace and
    directory components so ``a/b/Foo.sol:L88`` and ``Foo.sol:88`` compare equal.
    """
    loc = (loc or "").strip().lower().replace("\\", "/")
    # Keep only the final path component (basename) + line number.
    m = re.match(r"^(.*?)([A-Za-z0-9_.\-]+\.(?:sol|rs|go|move)):l?(\d+)$", loc)
    if m:
        return f"{m.group(2)}:{m.group(3)}"
    return re.sub(r":l(\d+)$", r":\1", loc)


# Mechanism / harm vocabulary used to decide whether a re-emitted self-excluded
# candidate carries its OWN content (concrete enough to dedup against an existing
# finding OR resolve into a concrete finding) versus being a content-less stub
# (bare "already known" assertion with no location and no harm). A content-less
# stub must NOT be promoted to a Medium body finding — it routes to a
# LOW-confidence appendix disposition instead. This is a ROOT FIX for the latent
# recall hazard where a self-excluded UNIQUE bug re-emits as an unverifiable
# Medium body stub. Recall-safe: content-less stubs are KEPT (appendix), never
# dropped; content-bearing ones flow through normal dedup/resolution.
_PERCONTRACT_HARM_RE = re.compile(
    r"\b(?:"
    r"loss|lose|lost|steal|stol|drain|lock(?:ed|s|ing)?|frozen|freeze|"
    r"overflow|underflow|insolven|brick|dos|denial|revert|griefing|"
    r"mint|inflat|deflat|manipulat|bypass|escalat|unauthor|"
    r"reentran|front[-\s]*run|sandwich|double[-\s]*(?:spend|count)|"
    r"corrupt|mismatch|stale|incorrect|wrong|drift|desync|"
    r"fund|asset|collateral|debt|reward|fee|share|balance|"
    r"attacker|exploit|profit|extract|skim"
    r")\b",
    re.IGNORECASE,
)


def _percontract_candidate_is_content_bearing(
    title: str, location: str, line_text: str
) -> bool:
    """Return True when a re-emitted self-excluded candidate carries its OWN
    content — enough to dedup against an existing finding OR resolve into a
    concrete finding.

    A candidate is content-bearing when it has BOTH:
      1. a concrete location (a real ``file:line`` token), AND
      2. a mechanism/harm signal (vocabulary indicating WHAT goes wrong).

    A bare "already known" / "duplicate" assertion with no location and no harm
    is content-LESS: an unfalsifiable stub. Such stubs are still recovered (so
    the suppressed candidate is never dropped) but the driver re-emits them at
    Informational severity with a ``[CONTENT-LESS]`` marker so report_index
    routes them to a LOW-confidence appendix disposition rather than promoting
    them to a Medium body finding (root fix from a prior run).

    Recall-safe: this only DOWNGRADES a content-less stub's body-promotion; it
    never removes the candidate from the re-emit set.
    """
    haystack = " ".join((title or "", line_text or ""))
    # Concrete location: a real file:line token (the validator already extracts
    # ``location`` from _TABLE_LOCATION_RE, so a non-empty location is concrete).
    has_location = bool((location or "").strip()) or bool(
        _TABLE_LOCATION_RE.search(haystack)
    )
    has_harm = bool(_PERCONTRACT_HARM_RE.search(haystack))
    return has_location and has_harm


def _validate_percontract_self_exclusion(
    scratchpad: Path,
) -> tuple[list[str], list[dict]]:
    """Soft validator for Phase 3c belief-based self-exclusion (BUG 2 / M-04).

    A per-contract agent is GIVEN an orchestrator-built exclusion list (finding
    IDs + locations from ``analysis_*.md`` + ``analysis_rescan_*.md``) and told
    "do not re-report exclusion-list findings". Nothing constrains the PROVENANCE
    of an exclusion, so an agent can self-generate an "## Exclusion List (Already
    Found)" section asserting a real bug is already known when NO provided finding
    contained it — silently dropping a true positive.

    This validator builds the REFERENT UNIVERSE (real provided IDs + locations),
    scans every ``analysis_percontract_*.md`` for exclusion/already-found
    sections, and flags any excluded entry whose cited referent is EMPTY or
    matches nothing in the universe. Each flagged entry is captured for
    re-emission downstream so the suppressed bug cannot vanish.

    Returns ``(warnings, recovered)`` where ``recovered`` is a list of dicts
    with ``title``/``location``/``severity``/``source``/``line_text`` for the
    driver side effect to re-emit.

    Recall-safe by construction:
    - No per-contract files / no exclusion section → ``([], [])``.
    - An exclusion citing a real provided ID or location → not flagged.
    - Parse failures / unreadable files → contribute nothing, never raise.
    The validator ONLY ever adds candidates; it never removes/refutes findings.
    """
    pc_files = sorted(scratchpad.glob("analysis_percontract_*.md"))
    # Never re-scan the driver-owned re-emit artifact.
    pc_files = [p for p in pc_files if p.name != "analysis_percontract_reemit.md"]
    if not pc_files:
        return [], []

    from plamen_parsers import _SEPARATOR_ROW_RE

    finding_ids, locations = _build_percontract_referent_universe(scratchpad)

    warnings: list[str] = []
    recovered: list[dict] = []

    for p in pc_files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        lines = text.splitlines()
        # Identify exclusion-intent section spans: from a matching heading until
        # the next heading of the same-or-shallower depth (or EOF).
        section_spans: list[tuple[int, int]] = []
        for idx, ln in enumerate(lines):
            if not _PERCONTRACT_EXCLUSION_HEADING_RE.match(ln):
                continue
            hm = re.match(r"^\s*(#{1,6})\s", ln)
            depth = len(hm.group(1)) if hm else 6
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                jm = re.match(r"^\s*(#{1,6})\s", lines[j])
                if jm and len(jm.group(1)) <= depth:
                    end = j
                    break
            section_spans.append((idx + 1, end))
        if not section_spans:
            continue

        for (start, end) in section_spans:
            for j in range(start, end):
                entry = lines[j]
                stripped = entry.strip()
                if not stripped:
                    continue
                # Only consider entry-like lines (list items, table rows, or
                # lines that explicitly say EXCLUDED/duplicate). Skip plain
                # prose / separator rows.
                is_entry = bool(
                    re.match(r"^\s*(?:[-*+]|\|)", entry)
                    or re.search(
                        r"\b(?:excluded|duplicate|already\s+(?:found|known)|"
                        r"not\s+duplicat)\b",
                        entry,
                        re.IGNORECASE,
                    )
                )
                if not is_entry:
                    continue
                if _SEPARATOR_ROW_RE.match(stripped):
                    continue
                # Header rows of a markdown table aren't findings.
                if re.match(r"^\s*\|", entry) and re.search(
                    r"\b(referent|title|location|severity|finding)\b",
                    entry,
                    re.IGNORECASE,
                ) and "EXCLUDED" not in entry.upper():
                    # likely the table header — only skip if it has no real ref
                    pass

                cited_ids = {
                    m.group(1).strip().upper()
                    for m in _BRACKETED_ID_RE.finditer(entry)
                }
                cited_locs = {
                    _norm_referent_location(loc)
                    for loc in _TABLE_LOCATION_RE.findall(entry)
                }
                # The entry's OWN [PCn-k] id is the excluded candidate, not a
                # referent — drop ids matching the per-contract prefix from the
                # referent set so it is not treated as a citation.
                referent_ids = {
                    i for i in cited_ids if not re.match(r"^PC\d", i)
                }
                has_real_referent = bool(
                    (referent_ids & finding_ids)
                    or (cited_locs & locations)
                )
                if has_real_referent:
                    continue

                # Referent-less exclusion → suppressed real bug. Capture it.
                own_id = next(
                    (i for i in cited_ids if re.match(r"^PC\d", i)),
                    None,
                )
                loc = ""
                if cited_locs:
                    loc = sorted(cited_locs)[0]
                title = re.sub(
                    r"^\s*(?:[-*+]\s*|\|\s*)", "", stripped
                ).strip().strip("|").strip()
                sev_m = _SEVERITY_RE.search(entry)
                severity = ""
                if sev_m:
                    severity = (sev_m.group(1) or sev_m.group(2) or "").title()
                content_bearing = _percontract_candidate_is_content_bearing(
                    title, loc, stripped
                )
                recovered.append(
                    {
                        "title": title or "(untitled self-excluded candidate)",
                        "location": loc,
                        "severity": severity,
                        "source": p.name,
                        "own_id": own_id or "",
                        "line_text": stripped,
                        "content_bearing": content_bearing,
                    }
                )

    if recovered:
        content_less = sum(
            1 for c in recovered if not c.get("content_bearing")
        )
        warnings.append(
            f"{len(recovered)} per-contract exclusion entry(ies) across "
            f"{len(pc_files)} file(s) cite no referent present in the provided "
            f"exclusion universe ({len(finding_ids)} IDs, {len(locations)} "
            f"locations) — belief-based self-exclusion; re-emitting candidates "
            f"({content_less} content-less → appendix disposition, "
            f"{len(recovered) - content_less} content-bearing → dedup/resolve) "
            f"(phase3b-rescan-prompt.md EXCLUSION SOURCE RULE)"
        )
    return warnings, recovered


# Heading vocabulary for depth-agent self-exclusion sections. Depth agents
# frequently park confirmed-mechanism candidates under a "Non-Reportable /
# Absorbed Candidates" (or "self-dropped") heading and justify the drop
# WITHOUT citing an in-scope refutation — the depth analogue of the Phase 3c
# belief-based self-exclusion hazard. Mirrors _PERCONTRACT_EXCLUSION_HEADING_RE.
_DEPTH_SELF_EXCLUSION_HEADING_RE = re.compile(
    r"(?im)^\s{0,3}#{1,6}\s+.*"
    r"(?:non[ _-]?reportable|absorbed|self[ _-]?drop|self[ _-]?exclu)"
    r".*$"
)

# Vocabulary that marks a drop as resting on an UNVERIFIED EXTERNAL assumption
# rather than an in-scope, verifiable refutation. A candidate dropped on any of
# these premises is a candidate for re-emission even when it cites a location,
# because the justification is not an in-scope proof. Kept narrow on purpose:
# "reverts on" (behavioral premise) is matched, but "reverts at Foo.sol:L120"
# (a concrete in-scope refutation) is NOT — that is a legitimate refutation.
_DEPTH_EXTERNAL_ASSUMPTION_RE = re.compile(
    r"(?i)(?:"
    r"reverts?\s+on\b|"
    r"\batomic\b|"
    r"not\s+demonstrab|"
    r"out[-\s]?of[-\s]?scope|"
    r"\bassum(?:e|es|ed|ing|ption)\b|"
    r"guaranteed\s+by\b"
    r")"
)

# A bare Markdown horizontal rule (``---`` / ``***`` / ``___``, 3+ identical
# chars, nothing else on the line). Such a line is a visual SEPARATOR, not a
# list bullet — but the entry-detection regex ``^\s*(?:[-*+]|\|)`` would match
# its leading ``-``/``*`` and mint a spurious content-less entry. ``_SEPARATOR_
# ROW_RE`` only covers ``|---|`` table separators, so bare HRs need their own
# skip (blemish 1). Kept strict (whole-line) so it never eats a real bullet.
_BARE_HR_RE = re.compile(r"^\s*([-*_])\1{2,}\s*$")


def _validate_depth_self_exclusion(
    scratchpad: Path,
) -> tuple[list[str], list[dict]]:
    """Soft validator for depth-agent belief-based self-exclusion (F3).

    Depth agents self-drop confirmed-mechanism candidates in
    "Non-Reportable / Absorbed Candidates" (or "self-dropped") sections of
    ``depth_*_findings.md``. Unlike a verifier-refuted finding, these drops are
    frequently justified WITHOUT an in-scope refutation — either citing no
    referent at all, or resting on an UNVERIFIED EXTERNAL assumption ("reverts
    on insufficiency", "atomic", "out of scope", "assume ...", "guaranteed by
    ..."). Nothing constrains the provenance of such a drop, so a true positive
    can silently vanish. This is the depth analogue of
    ``_validate_percontract_self_exclusion``.

    The validator builds the SAME referent universe (real provided finding IDs +
    ``analysis_*.md`` / ``analysis_rescan_*.md`` locations), scans every
    ``depth_*_findings.md`` self-exclusion section, and flags any absorbed
    candidate that EITHER:
      (a) cites NO concrete provided referent — no upstream finding ID present in
          the universe AND no concrete ``file:Lnnn`` location of any kind, OR
      (b) rests on an unverified EXTERNAL assumption (``_DEPTH_EXTERNAL_
          ASSUMPTION_RE``) to justify the drop.

    Counterplan narrowing: a candidate whose drop cites a concrete in-scope
    refutation (a real ``file:Lnnn``) AND does NOT rest on an external
    assumption is NOT flagged — a legitimately-refuted candidate is left alone.

    Returns ``(warnings, recovered)`` with the same dict shape as the
    per-contract validator so the driver side effect can re-emit uniformly.

    Recall-safe by construction: no depth files / no self-exclusion section →
    ``([], [])``; parse failures degrade to empty contributions, never raise;
    the validator ONLY ever adds candidates, never removes/refutes findings.
    Idempotent: entries already tagged ``[RE-EMITTED`` are skipped so a re-run
    does not re-flag driver-minted re-emits.
    """
    depth_files = sorted(scratchpad.glob("depth_*_findings.md"))
    # Never re-scan the driver-owned re-emit artifact.
    depth_files = [
        p for p in depth_files
        if p.name != "depth_selfexcl_reemit_findings.md"
    ]
    if not depth_files:
        return [], []

    from plamen_parsers import _SEPARATOR_ROW_RE

    finding_ids, locations = _build_percontract_referent_universe(scratchpad)

    warnings: list[str] = []
    recovered: list[dict] = []

    for p in depth_files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        lines = text.splitlines()
        # Identify self-exclusion section spans: from a matching heading until
        # the next heading of the same-or-shallower depth (or EOF).
        section_spans: list[tuple[int, int]] = []
        for idx, ln in enumerate(lines):
            if not _DEPTH_SELF_EXCLUSION_HEADING_RE.match(ln):
                continue
            hm = re.match(r"^\s*(#{1,6})\s", ln)
            depth = len(hm.group(1)) if hm else 6
            end = len(lines)
            for j in range(idx + 1, len(lines)):
                jm = re.match(r"^\s*(#{1,6})\s", lines[j])
                if jm and len(jm.group(1)) <= depth:
                    end = j
                    break
            section_spans.append((idx + 1, end))
        if not section_spans:
            continue

        for (start, end) in section_spans:
            # Group each entry with its CONTINUATION lines into ONE logical
            # entry (blemish 2): an absorbed candidate is often a bullet whose
            # concrete ``file:Lnnn`` / harm spills onto following lines. A
            # continuation line is a non-empty line that is NOT itself a new
            # bullet, heading, bare horizontal rule, or table row. Referent /
            # content-bearing detection then runs over the FULL joined text, so
            # a location or harm sitting on line 2+ is correctly seen. Bare HRs
            # (``---``/``***``/``___``) are separators, never entries (blemish 1).
            logical_entries: list[tuple[int, list[str]]] = []
            current = None
            for j in range(start, end):
                entry = lines[j]
                stripped = entry.strip()
                if not stripped:
                    current = None
                    continue
                if _BARE_HR_RE.match(stripped) or _SEPARATOR_ROW_RE.match(stripped):
                    # Horizontal rule / table separator: boundary, not an entry.
                    current = None
                    continue
                if re.match(r"^\s*#", entry):  # nested heading: boundary
                    current = None
                    continue
                # A real Markdown bullet requires whitespace AFTER the marker,
                # so a ``**bold**`` continuation line is not mistaken for one.
                is_new_bullet = bool(re.match(r"^\s*[-*+]\s", entry))
                is_table_row = bool(re.match(r"^\s*\|", entry))
                if is_new_bullet or is_table_row:
                    current = [entry]
                    logical_entries.append((j, current))
                    continue
                if current is not None:
                    current.append(entry)  # continuation of entry in progress
                    continue
                # Not currently in an entry: a plain prose line only STARTS a
                # new logical entry when it carries absorbed/dropped vocabulary.
                if re.search(
                    r"\b(?:absorbed|self[ _-]?drop|dropped|excluded|"
                    r"duplicate|not\s+report|already\s+(?:found|known))\b",
                    entry,
                    re.IGNORECASE,
                ):
                    current = [entry]
                    logical_entries.append((j, current))

            for (j, entry_lines) in logical_entries:
                first = entry_lines[0]
                # Detection text keeps newlines so ``^``-anchored regexes
                # (severity) still match on continuation lines; stored line_text
                # is space-joined so the driver evidence stays single-line.
                detect_text = "\n".join(entry_lines)
                line_text = " ".join(
                    s for s in (ln.strip() for ln in entry_lines) if s
                )
                # Idempotency: never re-flag a driver-minted re-emit entry.
                if "[RE-EMITTED" in detect_text.upper():
                    continue

                cited_ids = {
                    m.group(1).strip().upper()
                    for m in _BRACKETED_ID_RE.finditer(detect_text)
                }
                cited_locs = {
                    _norm_referent_location(loc)
                    for loc in _TABLE_LOCATION_RE.findall(detect_text)
                }
                # The candidate's OWN depth id (e.g. [TF-3], [DE-2]) is not a
                # referent — but we cannot know the prefix set for depth, so we
                # only treat IDs that appear in the provided universe as
                # referents (see has_universe_id below).
                has_universe_id = bool(cited_ids & finding_ids)
                # A concrete in-scope refutation is ANY cited file:Lnnn (per the
                # counterplan) OR a real upstream finding ID.
                has_concrete_referent = bool(has_universe_id or cited_locs)
                has_external_assumption = bool(
                    _DEPTH_EXTERNAL_ASSUMPTION_RE.search(detect_text)
                )
                # Trigger: referent-less OR unverified-external-assumption.
                if has_concrete_referent and not has_external_assumption:
                    continue  # legitimately-refuted; leave alone

                own_id = next(iter(cited_ids), None) if cited_ids else None
                loc = ""
                if cited_locs:
                    loc = sorted(cited_locs)[0]
                title = re.sub(
                    r"^\s*(?:[-*+]\s*|\|\s*)", "", first.strip()
                ).strip().strip("|").strip()
                sev_m = _SEVERITY_RE.search(detect_text)
                severity = ""
                if sev_m:
                    severity = (sev_m.group(1) or sev_m.group(2) or "").title()
                # Content-bearing detection runs over the FULL joined entry so a
                # concrete location / harm on a CONTINUATION line is seen.
                content_bearing = _percontract_candidate_is_content_bearing(
                    title, loc, line_text
                )
                recovered.append(
                    {
                        "title": title or "(untitled self-excluded candidate)",
                        "location": loc,
                        "severity": severity,
                        "source": p.name,
                        "own_id": own_id or "",
                        "line_text": line_text,
                        "content_bearing": content_bearing,
                        "external_assumption": has_external_assumption,
                    }
                )

    if recovered:
        content_less = sum(
            1 for c in recovered if not c.get("content_bearing")
        )
        ext = sum(1 for c in recovered if c.get("external_assumption"))
        warnings.append(
            f"{len(recovered)} depth self-exclusion entry(ies) across "
            f"{len(depth_files)} file(s) cite no in-scope referent OR rest on "
            f"an unverified external assumption ({ext} external-assumption) — "
            f"belief-based self-exclusion; re-emitting candidates "
            f"({content_less} content-less → appendix disposition, "
            f"{len(recovered) - content_less} content-bearing → dedup/resolve) "
            f"(finding-output-format.md R10 UNRESEARCHED-EXTERNAL burden)"
        )
    return warnings, recovered


def _collect_scip_indexed_paths(scratchpad: Path) -> set[str]:
    """Return the set of source paths the SCIP prebake recorded.

    Reads `scratchpad/scip/repo_map.md` (or `repo_map_full.md` if present
    and larger) — the prebake's deterministic per-file inventory. Each
    `## <relative_path>` H2 header is a real indexed file.

    If no SCIP prebake artifact exists, falls back to SC recon/inventory
    artifacts (`contract_inventory.md`, `function_list.md`, `file_coverage.md`,
    `file_coverage_ledger.md`). This gives SC the same coverage/attention
    accounting as L1 without requiring a separate graph bake.
    """
    paths: set[str] = set()
    scip_dir = scratchpad / "scip"
    candidates: list[Path] = []
    if scip_dir.is_dir():
        full = scip_dir / "repo_map_full.md"
        short = scip_dir / "repo_map.md"
        if full.exists():
            candidates.append(full)
        if short.exists():
            candidates.append(short)
    fallback_candidates = (
        scratchpad / "contract_inventory.md",
        scratchpad / "function_list.md",
        scratchpad / "file_coverage.md",
        scratchpad / "file_coverage_ledger.md",
    )
    if not candidates:
        candidates.extend(p for p in fallback_candidates if p.exists())
    for f in candidates:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        found_in_file = 0
        for m in re.finditer(r"^##\s+([^\n]+?)\s*$", text, re.MULTILINE):
            p = m.group(1).strip().strip("`")
            # repo_map_full.md uses absolute paths (Windows: C:/...). Strip
            # leading drive prefix and project_root if present so we can
            # match against relative cited paths.
            if re.match(r"^[A-Za-z]:[/\\]", p):
                # Take the substring after the first known crate-style
                # prefix marker. Tolerant: accept "C:/Users/.../crates/..."
                # → "crates/..."
                m2 = re.search(
                    r"(?:crates/|src/|cmd/|pkg/|core/|eth/|consensus/|p2p/|"
                    r"actors/|types/|api-server/|storage/|reth-|"
                    r"contracts/|test/|tests/|scripts/|programs/)",
                    p,
                )
                if m2:
                    p = p[m2.start():]
            if not p:
                continue
            # v2.3.3: filter SCIP non-file tokens. Some SCIP indexers emit
            # synthetic tokens like ``Crate Structure``, ``Module Tree``,
            # ``Workspace`` as `## ...` headers in repo_map.md. These pollute
            # the coverage-gap signal because they trivially never get cited
            # (no file extension, no real path). Reject anything that looks
            # like a synthetic label rather than a relative path.
            if " " in p:
                continue  # paths don't contain spaces
            if "." not in p.rsplit("/", 1)[-1]:
                continue  # leaf must look like a filename with extension
            paths.add(p.rstrip("/"))
            found_in_file += 1
        # Some prebake repo maps are table/bullet based rather than H2 based.
        # Fall back to harvesting source-path tokens from the whole file.
        if found_in_file == 0:
            path_re = re.compile(
                r"\b([A-Za-z0-9_./\\-]+\.(?:rs|go|sol|move|py|c|cpp|cc|h|hpp|java|ts|js))\b"
            )
            for m in path_re.finditer(text):
                p = m.group(1).replace("\\", "/").strip("`")
                if re.match(r"^[A-Za-z]:/", p):
                    m2 = re.search(
                        r"(?:crates/|src/|cmd/|pkg/|core/|eth/|consensus/|p2p/|"
                        r"actors/|types/|api-server/|storage/|reth-|"
                        r"contracts/|test/|tests/|scripts/|programs/)",
                        p,
                    )
                    if m2:
                        p = p[m2.start():]
                if " " in p or "." not in p.rsplit("/", 1)[-1]:
                    continue
                paths.add(p.rstrip("/"))
    return paths


def _collect_cited_paths(scratchpad: Path) -> set[str]:
    """Return the set of source paths cited by depth/breadth/scanner/verify.

    Harvests `path/to/file.ext:Lnn` and `path/to/file.ext` tokens from
    every finding-class output. Used by both the coverage gap helper
    (Bucket A) and the path-existence gate (Bucket C).
    """
    paths: set[str] = set()
    citation_re = re.compile(
        r"\b([a-zA-Z][a-zA-Z0-9_./\-]*?\."
        r"(?:rs|go|sol|move|py|c|cpp|cc|h|hpp|java|ts|js))\b"
    )
    for pattern in _FINDING_GLOBS_FOR_CITATION:
        for f in scratchpad.glob(pattern):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for m in citation_re.finditer(text):
                paths.add(m.group(1))
    return paths


def _basenames(paths: set[str]) -> dict[str, set[str]]:
    """Group full paths by their basename for coarse-match resolution."""
    out: dict[str, set[str]] = {}
    for p in paths:
        bn = p.rsplit("/", 1)[-1]
        out.setdefault(bn, set()).add(p)
    return out


def _is_spec_support_path(path: str) -> bool:
    """True for tests/mocks/harnesses that are spec evidence, not prod surface."""
    p = (path or "").replace("\\", "/").strip().lower()
    if not p:
        return False
    wrapped = f"/{p.lstrip('/')}"
    leaf = p.rsplit("/", 1)[-1]
    support_markers = (
        "/test/", "/tests/", "/testdata/",
        "/mock/", "/mocks/", "/mocked/",
        "/harness/", "/harnesses/",
        "/fixture/", "/fixtures/",
        "/example/", "/examples/",
        "/script/", "/scripts/",
        "/benches/", "/bench/",
        "/vendor/", "/third_party/", "/node_modules/",
    )
    if any(marker in wrapped for marker in support_markers):
        return True
    if leaf.endswith((".t.sol", ".s.sol", "_test.go", "_tests.rs", ".test.ts", ".spec.ts")):
        return True
    if leaf.startswith(("mock", "stub", "fake")):
        return True
    if "harness" in leaf:
        return True
    # Interface declarations carry no executable production surface, so depth
    # agents legitimately never cite them. Recognize the `/interfaces/`
    # directory marker and the Solidity `I<UpperCamel>.sol` convention
    # (leaf already lowercased above).
    if "/interface/" in wrapped or "/interfaces/" in wrapped:
        return True
    if re.match(r"^i[a-z0-9][a-z0-9_]*\.(?:sol|vy)$", leaf):
        return True
    # Mock/stub/fake declared via SUFFIX (ERC20Mock.sol, BridgeRouterMock.sol)
    # are test-support doubles, not production surface.
    stem = leaf.rsplit(".", 1)[0]
    if stem.endswith(("mock", "stub", "fake", "mockup", "harness")):
        return True
    return False


def _first_production_location_for_validator(text: str, *fallbacks: str) -> str:
    """Pick a production source location, never a PoC/test primary location.

    Verifier artifacts often mention both vulnerable production files and test
    files that prove them. Downstream manifests must use the production file as
    the finding location; test/mock/harness paths are supporting evidence only.
    """
    candidates: list[str] = []
    field = _field_from_markdown(
        text or "",
        ("Location", "Location(s)", "Primary Location", "Affected Location", "Affected Locations"),
    )
    for cand in (*fallbacks, field):
        if cand and cand not in candidates:
            candidates.append(cand)
    for pattern in (
        r"\b(?:src|contracts|programs|sources|move|crates|packages|modules)"
        r"/[A-Za-z0-9_./-]+\.(?:cairo|move|hpp|cpp|tsx|jsx|sol|rs|go|py|cc|ts|js|vy|c|h)"
        r"(?![A-Za-z0-9_])(?::L?\d+(?:[-:]\d+)?)?",
        r"\b[A-Za-z0-9_./-]+\.(?:cairo|move|hpp|cpp|tsx|jsx|sol|rs|go|py|cc|ts|js|vy|c|h)"
        r"(?![A-Za-z0-9_])(?::L?\d+(?:[-:]\d+)?)?",
    ):
        for m in re.finditer(pattern, text or "", re.IGNORECASE):
            cand = m.group(0).strip("`")
            if cand not in candidates:
                candidates.append(cand)
    for cand in candidates:
        rel, _line = _parse_location_ref(cand)
        path = rel or cand
        if path and not _is_spec_support_path(path):
            return cand.strip()
    for cand in candidates:
        if cand:
            return cand.strip()
    return ""


def _compute_scip_coverage_sets(
    scratchpad: Path, scope_file: str | None = None
) -> dict[str, object]:
    indexed = _collect_scip_indexed_paths(scratchpad)
    cited = _collect_cited_paths(scratchpad)
    cited_basenames = _basenames(cited)

    spec_support_indexed = {p for p in indexed if _is_spec_support_path(p)}
    prod_indexed = {
        p for p in indexed
        if p not in spec_support_indexed
    }
    # Narrow the required (prod) universe to in-scope files only when the
    # wizard supplied a scope file, so out-of-scope vendored libraries are not
    # reported as coverage gaps. Empty scope → require everything (unchanged).
    scope_names = _load_scope_file_paths(scope_file)
    if scope_names:
        prod_indexed = {
            p for p in prod_indexed if _path_in_scope_file(p, scope_names)
        }
    indexed_basenames = _basenames(prod_indexed)

    uncited: list[str] = []
    covered: set[str] = set()
    for p in sorted(prod_indexed):
        bn = p.rsplit("/", 1)[-1]
        if p in cited:
            covered.add(p)
            continue
        if (
            bn in cited_basenames
            and len(cited_basenames.get(bn, set())) == 1
            and len(indexed_basenames.get(bn, set())) == 1
        ):
            covered.add(p)
            continue
        uncited.append(p)

    coverage_pct = 100.0 * len(covered) / max(1, len(prod_indexed))
    return {
        "indexed": indexed,
        "prod_indexed": prod_indexed,
        "spec_support_indexed": spec_support_indexed,
        "cited": cited,
        "covered": covered,
        "uncited": uncited,
        "coverage_pct": coverage_pct,
    }


def _materialize_sc_slither_flat_files(scratchpad: Path) -> list[str]:
    """Create `scratchpad/slither/*` orientation files from recon artifacts.

    EVM breadth/depth prompts already know how to consume
    `{SCRATCHPAD}/slither/{call_graph,function_summary,...}.md` when
    `primitive_status.md` contains `SLITHER_PREBAKE_COMPLETE: true`. Recon
    often writes equivalent root-level artifacts; this adapter makes the
    contract explicit and deterministic so agents grep flat files instead of
    re-querying MCP or silently missing structural context.
    """
    mappings = {
        "call_graph.md": ["call_graph.md", "caller_map.md", "callee_map.md"],
        "function_summary.md": ["function_summary.md", "function_list.md"],
        "state_write_map.md": ["state_write_map.md", "state_variables.md"],
        "inheritance_tree.md": ["inheritance_tree.md", "contract_inventory.md"],
        "access_control_map.md": ["access_control_map.md", "modifiers.md", "setter_list.md"],
        "detector_findings.md": ["detector_findings.md", "static_analysis.md"],
    }
    slither_dir = scratchpad / "slither"
    slither_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    for target, sources in mappings.items():
        chunks: list[str] = [
            f"# {target.replace('_', ' ').replace('.md', '').title()} (SC Flat Artifact)",
            "",
            "> Deterministically materialized from recon artifacts. Verify against source before treating as ground truth.",
            "",
        ]
        for src in sources:
            p = scratchpad / src
            if not p.exists() or p.stat().st_size < 20:
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace").strip()
            except Exception:
                continue
            if not text:
                continue
            chunks.extend([f"## Source: `{src}`", "", text[:200000], ""])
        if len(chunks) <= 4:
            continue
        out = slither_dir / target
        out.write_text("\n".join(chunks).rstrip() + "\n", encoding="utf-8")
        generated.append(target)

    if generated:
        status = slither_dir / "primitive_status.md"
        existing = ""
        if status.exists():
            try:
                existing = status.read_text(encoding="utf-8", errors="replace")
            except Exception:
                existing = ""
        lines = existing.rstrip().splitlines() if existing.strip() else [
            "# SC Slither Flat Artifact Status", ""
        ]
        if not any("SLITHER_PREBAKE_COMPLETE" in line for line in lines):
            lines.append("- SLITHER_PREBAKE_COMPLETE: true")
        if not any("SLITHER_FLAT_FILES" in line for line in lines):
            lines.append("- SLITHER_FLAT_FILES: " + ", ".join(generated))
        status.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return generated


def _compute_subsystem_coverage_gap(
    scratchpad: Path, mode: str, scope_file: str | None = None
) -> list[str]:
    """SCIP-driven generic coverage gap. Soft validator.

    Generic mechanism (no per-codebase tuning):
      1. Enumerate SCIP-indexed source files (`repo_map.md`).
      2. Enumerate paths cited across depth/breadth/scanner/verify outputs.
      3. Diff: indexed - cited = uncited.
      4. Filter to "production code" (heuristic — skip test/, tests/,
         testdata/, examples/, benches/, fixtures/, vendor/).
      5. Write `subsystem_coverage_gap.md` listing uncited files for
         iter2 / DA / next-phase consumption.

    Mode-gated: thorough only. Light/Core skip.

    Returns informational issue list on first round (v2.3.0 SOFT). Empty
    issue list = either gap file written OR mode skip. Hard-gate is a
    v2.3.1 decision contingent on next post-mortem.
    """
    gap_path = scratchpad / "subsystem_coverage_gap.md"

    def _write_skip(reason: str) -> None:
        try:
            gap_path.write_text(
                "# Subsystem Coverage Gap (v2.3.0 SCIP experiment)\n\n"
                f"**Status**: SKIPPED — {reason}\n",
                encoding="utf-8",
            )
        except Exception:
            pass

    if mode != "thorough":
        _write_skip(f"mode={mode!r} (gate runs in thorough only)")
        return []

    indexed = _collect_scip_indexed_paths(scratchpad)
    if not indexed:
        _write_skip(
            "no SCIP repo_map.md found in scratchpad/scip/ — bake phase "
            "may have skipped (SC mode, or rust-analyzer/scip-go missing). "
            "Coverage gap analysis requires the SCIP prebake."
        )
        return []

    cov = _compute_scip_coverage_sets(scratchpad, scope_file=scope_file)
    prod_indexed = cov["prod_indexed"]
    uncited = cov["uncited"]
    coverage_pct = cov["coverage_pct"]

    try:
        if uncited:
            lines = [
                "# Subsystem Coverage Gap (v2.3.0 SCIP experiment)",
                "",
                f"**Indexed prod files**: {len(prod_indexed)} | "
                f"**Cited**: {len(prod_indexed) - len(uncited)} | "
                f"**Uncited**: {len(uncited)} | "
                f"**Coverage**: {coverage_pct:.1f}%",
                "",
                "Files below are recon-indexed via SCIP but received zero "
                "citations across depth, breadth, scanner, niche, validation, "
                "and verify outputs. iter2 / DA / next-phase agents SHOULD "
                "read this file and route attention to uncited entries.",
                "",
                "| # | File |",
                "|---|------|",
            ]
            for i, p in enumerate(uncited, 1):
                lines.append(f"| {i} | `{p}` |")
            gap_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:
            gap_path.write_text(
                "# Subsystem Coverage Gap (v2.3.0 SCIP experiment)\n\n"
                f"**Coverage**: 100.0% ({len(prod_indexed)} indexed = "
                f"cited). No subsystem skip.\n",
                encoding="utf-8",
            )
    except Exception:
        pass

    # SOFT: report informational only. Hard-gating decision deferred to
    # v2.3.1 post-measurement.
    if uncited:
        sample = ", ".join(uncited[:3])
        more = f" (+{len(uncited)-3} more)" if len(uncited) > 3 else ""
        return [
            f"subsystem coverage: {len(uncited)} indexed prod file(s) "
            f"uncited ({coverage_pct:.0f}% coverage). Sample: "
            f"{sample}{more}. See subsystem_coverage_gap.md."
        ]
    return []


def _parse_subsystem_coverage_gap(scratchpad: Path) -> dict[str, float]:
    """Read subsystem_coverage_gap.md stats written by coverage helper."""
    p = scratchpad / "subsystem_coverage_gap.md"
    stats = {"indexed": 0.0, "cited": 0.0, "uncited": 0.0, "coverage": 100.0}
    if not p.exists():
        return stats
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return stats
    m = re.search(
        r"Indexed prod files\*\*:\s*(\d+).*?"
        r"Cited\*\*:\s*(\d+).*?"
        r"Uncited\*\*:\s*(\d+).*?"
        r"Coverage\*\*:\s*([0-9.]+)%",
        text,
        re.DOTALL,
    )
    if not m:
        return stats
    return {
        "indexed": float(m.group(1)),
        "cited": float(m.group(2)),
        "uncited": float(m.group(3)),
        "coverage": float(m.group(4)),
    }


def _write_final_subsystem_coverage_summary(scratchpad: Path) -> None:
    """Write final strict citation coverage after all phase outputs exist."""
    if not _collect_scip_indexed_paths(scratchpad):
        return
    cov = _compute_scip_coverage_sets(scratchpad)
    prod_indexed = cov["prod_indexed"]
    cited = cov["cited"]
    covered = cov["covered"]
    uncited = cov["uncited"]
    coverage_pct = cov["coverage_pct"]
    coverage_fill_files = [
        p for p in sorted(scratchpad.glob("coverage_fill_*.md"))
        if p.stat().st_size >= 100
    ]
    lines = [
        "# Final Subsystem Coverage (strict SCIP citation)",
        "",
        f"**Indexed prod files**: {len(prod_indexed)} | "
        f"**Covered by source citation**: {len(covered)} | "
        f"**Uncovered**: {len(uncited)} | "
        f"**Coverage**: {coverage_pct:.1f}%",
        "",
        f"**Distinct cited source paths observed**: {len(cited)}",
        f"**Coverage-fill shard files**: {len(coverage_fill_files)}",
        "",
        "This is the final strict source-citation metric after breadth, graph "
        "sweeps, depth, verification, and report artifacts exist. It is not "
        "the same as `file_coverage_ledger.md`, which may count acknowledged "
        "or heuristic coverage.",
    ]
    if uncited:
        lines.extend([
            "",
            "## Uncovered Production Files",
            "",
            "| # | File |",
            "|---|------|",
        ])
        for i, p in enumerate(uncited, 1):
            lines.append(f"| {i} | `{p}` |")
    else:
        lines.extend(["", "No uncovered production files under strict SCIP citation."])
    try:
        (scratchpad / "subsystem_coverage_final.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    except Exception:
        pass


def _panic_sites_available(scratchpad: Path) -> bool:
    """Return True when the L1 bake produced a non-empty panic work queue."""
    p = scratchpad / "scip" / "panic_sites.md"
    if not p.exists():
        return False
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    meaningful = [
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return len(meaningful) > 0


def _scip_text_contains_any(scratchpad: Path, needles: tuple[str, ...]) -> bool:
    """Return True when prebaked SCIP/context files mention any trigger token."""
    scip_dir = scratchpad / "scip"
    if not scip_dir.is_dir():
        return False
    files = (
        "repo_map.md",
        "repo_map_full.md",
        "xref_map.md",
        "type_hierarchy.md",
        "call_graph_consensus.md",
        "call_graph_p2p.md",
        "call_graph_execution.md",
        "concurrency_inventory.md",
    )
    lowered = tuple(n.lower() for n in needles)
    for name in files:
        p = scip_dir / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:
            continue
        if any(n in text for n in lowered):
            return True
    return False


def _primitive_sweep_relevant(scratchpad: Path) -> bool:
    return _scip_text_contains_any(
        scratchpad,
        (
            "merkle", "proof", "validate_path", "validate_chunk",
            "from_compact", "to_compact", "serialize", "deserialize",
            "codec", "encoding", "decoding", "difficulty", "ema",
            "log10", "pow", "round", "nonce", "replay", "signature",
            "hash", "commitment",
        ),
    )


def _field_validation_sweep_relevant(scratchpad: Path) -> bool:
    return _scip_text_contains_any(
        scratchpad,
        (
            "header", "block", "transaction", "tx", "commitment",
            "signature", "signed", "verify", "validate", "nonce",
            "height", "timestamp", "prev_", "parent", "hash",
            "sidecar", "extension", "witness", "blob", "mweb",
        ),
    )


def _network_amplification_sweep_relevant(scratchpad: Path) -> bool:
    return _scip_text_contains_any(
        scratchpad,
        (
            "gossip", "broadcast", "peer", "p2p", "network",
            "handshake", "request", "response", "timeout",
            "seen", "cache", "mempool", "chunk",
        ),
    )


def _lifecycle_replay_sweep_relevant(scratchpad: Path) -> bool:
    return _scip_text_contains_any(
        scratchpad,
        (
            "cache", "seen", "pending", "pool", "mempool", "orphan",
            "expiry", "expire", "ttl", "evict", "delete", "remove",
            "nonce", "sequence", "replay", "signature", "txid",
            "tx_hash", "peer_score", "reputation", "score",
            "sidecar", "extension", "witness", "blob", "mutated",
        ),
    )


def _graph_sweeps_needed(scratchpad: Path, mode: str) -> tuple[bool, str]:
    """Decide whether the graph-sweep phase has real work.

    Thorough L1 audits should convert baked graph artifacts into work queues
    when either coverage is weak (<60%) or panic sites exist. This keeps the
    phase cost bounded on small/well-covered projects while making the
    class of 50%+ uncited code mechanically impossible to ignore.
    """
    if mode != "thorough":
        return False, f"mode={mode}; graph sweeps run in thorough only"
    repo_indexed = bool(_collect_scip_indexed_paths(scratchpad))
    if not repo_indexed and not _panic_sites_available(scratchpad):
        return False, "no SCIP repo map or panic-site queue found"
    stats = _parse_subsystem_coverage_gap(scratchpad)
    low_coverage = stats["uncited"] > 0 and stats["coverage"] < 60.0
    panic_sites = _panic_sites_available(scratchpad)
    reasons: list[str] = []
    if low_coverage:
        reasons.append(
            f"coverage={stats['coverage']:.1f}% with {int(stats['uncited'])} uncited files"
        )
    if panic_sites:
        reasons.append("panic_sites.md non-empty")
    if _field_validation_sweep_relevant(scratchpad):
        reasons.append("field-validation surface detected")
    if _primitive_sweep_relevant(scratchpad):
        reasons.append("primitive/serialization surface detected")
    if _network_amplification_sweep_relevant(scratchpad):
        reasons.append("network-amplification surface detected")
    if _lifecycle_replay_sweep_relevant(scratchpad):
        reasons.append("lifecycle/replay surface detected")
    if reasons:
        return True, "; ".join(reasons)
    return False, (
        f"coverage={stats['coverage']:.1f}% and no panic-site queue requiring sweep"
    )


def _write_graph_sweeps_skip(scratchpad: Path, reason: str) -> None:
    (scratchpad / "graph_sweep_summary.md").write_text(
        "# Graph-Sharded Audit Sweeps\n\n"
        f"**Status**: SKIPPED\n\nReason: {reason}\n",
        encoding="utf-8",
    )


def _validate_graph_sweeps(
    scratchpad: Path, mode: str, *, min_bytes: int = 100,
) -> tuple[list[str], list[str]]:
    """Gate for graph-sweep phase when graph queues are present.

    Returns ``(hard, soft)`` — hard issues block the phase (file existence,
    byte size); soft issues are keyword-content checks on LLM prose (logged
    as warnings, never block).

    *min_bytes* is the caller-resolved artifact threshold (already halved for
    Codex by ``_run_validators_and_enrichments``). Every size check in this
    function uses it instead of a hardcoded constant.
    """
    needed, reason = _graph_sweeps_needed(scratchpad, mode)
    if not needed:
        return [], []
    hard: list[str] = []
    soft: list[str] = []
    summary = scratchpad / "graph_sweep_summary.md"
    if not summary.exists() or summary.stat().st_size < min_bytes:
        hard.append("graph_sweep_summary.md missing or stub")

    stats = _parse_subsystem_coverage_gap(scratchpad)
    if stats["uncited"] > 0 and stats["coverage"] < 60.0:
        coverage_files = [
            p for p in scratchpad.glob("coverage_fill_*.md")
            if p.stat().st_size >= min_bytes
        ]
        if not coverage_files:
            hard.append(
                "coverage_fill_*.md missing despite low subsystem coverage "
                f"({reason})"
            )

    if _panic_sites_available(scratchpad):
        panic_files = [
            p for p in scratchpad.glob("panic_audit_*.md")
            if p.stat().st_size >= min_bytes
        ]
        panic_summary = scratchpad / "panic_audit_summary.md"
        if not panic_files and (
            not panic_summary.exists() or panic_summary.stat().st_size < min_bytes
        ):
            hard.append("panic audit output missing despite non-empty panic_sites.md")
    if _field_validation_sweep_relevant(scratchpad):
        p = scratchpad / "field_validation_matrix.md"
        if not p.exists() or p.stat().st_size < min_bytes:
            hard.append("field_validation_matrix.md missing despite validation surface")
    if _primitive_sweep_relevant(scratchpad):
        p = scratchpad / "primitive_correctness_findings.md"
        if not p.exists() or p.stat().st_size < min_bytes:
            hard.append(
                "primitive_correctness_findings.md missing despite primitive/serialization surface"
            )
    if _network_amplification_sweep_relevant(scratchpad):
        p = scratchpad / "network_amplification_findings.md"
        if not p.exists() or p.stat().st_size < min_bytes:
            hard.append(
                "network_amplification_findings.md missing despite network surface"
            )
        else:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            required_groups = (
                ("ingress", "entry", "endpoint"),
                ("dedup", "seen", "cache"),
                ("validation", "validate"),
                ("egress", "fanout", "loop", "broadcast", "multiplier"),
                ("verdict",),
                ("evidence",),
            )
            if not all(any(token in text for token in group) for group in required_groups):
                soft.append(
                    "network_amplification_findings.md lacks required ingress/dedup/"
                    "validation/egress/verdict/evidence coverage"
                )
    if _lifecycle_replay_sweep_relevant(scratchpad):
        p = scratchpad / "lifecycle_replay_findings.md"
        if not p.exists() or p.stat().st_size < min_bytes:
            hard.append(
                "lifecycle_replay_findings.md missing despite cache/replay lifecycle surface"
            )
        else:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
            required_groups = (
                ("insert",),
                ("consume", "use"),
                ("evict", "delete", "remove", "expire"),
                ("replay", "nonce", "sequence", "identity"),
                ("verdict",),
                ("evidence",),
            )
            if not all(any(token in text for token in group) for group in required_groups):
                soft.append(
                    "lifecycle_replay_findings.md lacks required insert/consume/"
                    "evict/replay/verdict/evidence coverage"
                )
    return hard, soft


def _validate_post_verify_extract(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for Phase 5.5 (Post-Verification Finding Extraction).

    No hard issues. The common case is that verify_*.md files contain
    zero [VER-NEW-*] observations and the agent returns immediately. We
    only care that the summary artifact `post_verify_extract.md` was
    written (acknowledgement that the phase ran, even if it found
    nothing). Missing → log warning + sentinel.
    """
    if mode != "thorough":
        return []
    summary = scratchpad / "post_verify_extract.md"
    if summary.exists() and summary.stat().st_size > 20:
        return []
    try:
        (scratchpad / "post_verify_extract.degraded").write_text(
            "[POST_VERIFY_EXTRACT_DEGRADED] post_verify_extract.md missing "
            "or empty. Pipeline continues; any [VER-NEW-*] observations "
            "in verify_*.md were NOT promoted to hypotheses.md.\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    import logging as _logging
    _logging.getLogger("plamen.validators").warning(
        "[post_verify_extract] summary artifact missing/empty — sentinel "
        "written, pipeline continues"
    )
    return []


def _validate_chain_iter2(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for Phase 4c Iteration 2 (chain composition re-evaluation).

    Like Pass 2, never returns hard issues. Confirms the iteration-2
    artifact exists (either real LLM output or the deterministic
    early-exit note written by the driver pre-skip), logs warning + writes
    sentinel on missing/empty output. Pipeline always proceeds.
    """
    if mode != "thorough":
        return []
    iter2_path = scratchpad / "chain_iteration2.md"
    if iter2_path.exists() and iter2_path.stat().st_size > 30:
        return []
    # Missing or near-empty output. Write sentinel; don't halt.
    try:
        (scratchpad / "chain_iter2.degraded").write_text(
            "[CHAIN_ITER2_DEGRADED] chain_iteration2.md missing or "
            "<30 bytes. Pipeline continues; iteration 1 chain hypotheses "
            "are still in chain_hypotheses.md.\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    import logging as _logging
    _logging.getLogger("plamen.validators").warning(
        "[chain_iter2] chain_iteration2.md missing/empty — sentinel "
        "written, pipeline continues"
    )
    return []


# Wording that asserts an axis was TOUCHED rather than naming + locating the
# specific instance that was verified. A NO-GAP whose evidence cell is only
# such wording is the coarse rubber-stamp this gate exists to catch: it clears
# the whole axis on the strength of "something adjacent was explored" without
# resolving THIS instance to a finding or a concrete safe-locus.
_EXPLORATION_RUBBERSTAMP_WORDING_RE = re.compile(
    r"\b(?:explored|covered|touched|examined|considered|reviewed|"
    r"checked|looked\s+at|analy[sz]ed|addressed\s+elsewhere|"
    r"same\s+pattern|similar)\b",
    re.IGNORECASE,
)


def _exploration_evidence_has_concrete_locus(evidence: str) -> bool:
    """Return True when *evidence* names a concrete verification locus.

    A concrete locus is either a file:line / function reference (the place the
    instance was found safe) or a prior finding ID (the finding that already
    captures the instance). This is the bar a NO-GAP / ASSESSED row must clear
    so the instance is provably resolved, not merely "explored somewhere".
    """
    if not evidence:
        return False
    text = _llm_norm(evidence).strip()
    if not text:
        return False
    # file:line (e.g. Foo.sol:L120, src/foo.rs:88, foo.move:12-30)
    if re.search(r"[A-Za-z0-9_./\\-]+\.(?:sol|move|rs|go|cairo|fc|tact)\b", text, re.IGNORECASE):
        return True
    # bare line reference (Lnn / line nn) or a function-call locus name(
    if re.search(r"\bL\d+\b|\bline\s+\d+\b", text, re.IGNORECASE):
        return True
    if re.search(r"\b[a-zA-Z_][a-zA-Z0-9_]*\s*\(", text):
        return True
    # prior finding ID reference (B1-2, RS3-1, PC2-4, EN-5, H-03, M-1, ...)
    try:
        if _INTERNAL_FINDING_ID_RE.search(text):
            return True
    except Exception:
        pass
    if re.search(r"\b[A-Z]{1,5}-?\d+(?:-\d+)?\b", text):
        return True
    return False


def _scan_exploration_instance_gaps(text: str) -> list[dict[str, str]]:
    """Parse the per-instance coverage record and return the rows whose
    disposition CLEARS an instance (NO-GAP / ASSESSED) without naming the
    specific instance + a concrete evidence locus.

    These are the rubber-stamp rows: an axis declared covered without the
    instance being resolved to a finding or a concrete safe-locus. Each
    returned dict carries {finding, axis, instance, disposition, evidence}
    for observability. This is a READ-ONLY scan — it never mutates findings;
    the caller treats every hit as recall-positive (an instance that should be
    re-surfaced as an ADD, never a drop).
    """
    norm = _llm_norm(text)
    # Locate the coverage-record header row to map columns by name. Fall back
    # to positional columns (Finding|Axis|Instance|Disposition|Evidence) when
    # no recognizable header is present.
    col_idx: dict[str, int] | None = None
    hits: list[dict[str, str]] = []
    clearing = {"no-gap", "nogap", "no gap", "assessed"}
    for raw in norm.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        if _is_separator_row(line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells:
            continue
        lowered = [c.lower() for c in cells]
        # Header detection: a row that names the schema columns.
        if col_idx is None and "disposition" in lowered:
            col_idx = {}
            for want in ("finding", "axis", "instance", "disposition", "evidence"):
                for i, c in enumerate(lowered):
                    if want in c:
                        col_idx[want] = i
                        break
            continue
        # Resolve column positions.
        if col_idx is not None and "disposition" in col_idx:
            def _get(name: str) -> str:
                i = col_idx.get(name, -1)
                return cells[i] if 0 <= i < len(cells) else ""
            finding = _get("finding")
            axis = _get("axis")
            instance = _get("instance")
            disposition = _get("disposition")
            evidence = _get("evidence")
        elif len(cells) >= 5:
            # Positional fallback: Finding|Axis|Instance|Disposition|Evidence
            finding, axis, instance, disposition, evidence = cells[:5]
        else:
            continue
        disp = disposition.lower().strip()
        # Tolerate dispositions wrapped in backticks/bold/parentheses.
        disp_core = re.sub(r"[`*()_]", "", disp).strip()
        if disp_core not in clearing:
            continue
        # A clearing row is a rubber-stamp when the instance is unnamed OR the
        # evidence is missing/only touch-wording without a concrete locus.
        inst_named = bool(instance.strip()) and instance.strip().lower() not in (
            "direction", "similar-mechanism", "neighbour", "neighbor", "n/a", "-", "—",
        )
        ev_concrete = _exploration_evidence_has_concrete_locus(evidence)
        ev_only_wording = bool(
            evidence.strip()
            and not ev_concrete
            and _EXPLORATION_RUBBERSTAMP_WORDING_RE.search(evidence)
        )
        if (not inst_named) or (not ev_concrete) or ev_only_wording:
            hits.append({
                "finding": finding,
                "axis": axis,
                "instance": instance,
                "disposition": disposition,
                "evidence": evidence,
            })
    return hits


def _validate_exploration_skeptic(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for Phase 4b.6 (exploration-completeness verifier).

    Recall-positive / additive phase. Like chain_iter2, this validator NEVER
    returns hard issues — it returns [] in every branch, so it can never set
    passed=False and can never halt the pipeline. Confirms the additive
    findings/coverage-record artifact exists and is substantial; on
    missing/empty output it logs a warning and writes a sentinel, then lets the
    pipeline proceed (the phase only ADDS findings, so its absence loses no
    prior finding).

    Additionally (root fix for the axis-level rubber-stamp), it scans the
    per-instance coverage record for `NO-GAP` / `ASSESSED` rows that CLEAR an
    instance without naming the specific instance + a concrete evidence locus.
    Those are the coarse "axis was touched somewhere" passes that falsely close
    an unexamined neighbour/direction/sub-mechanism. Each such row is WARNING-
    only and recall-positive: it is written to an `.instance_gap` sentinel so a
    human / downstream pass can re-surface it as an ADD. It NEVER halts and
    NEVER drops or downgrades a finding.
    """
    if mode != "thorough":
        return []
    out_path = scratchpad / "exploration_skeptic_findings.md"
    if not (out_path.exists() and out_path.stat().st_size > 30):
        # Missing or near-empty output. Write sentinel; don't halt.
        try:
            (scratchpad / "exploration_skeptic.degraded").write_text(
                "[EXPLORATION_SKEPTIC_DEGRADED] exploration_skeptic_findings.md "
                "missing or <30 bytes. Pipeline continues; this phase is "
                "additive-only, so no prior finding is lost by its absence.\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        import logging as _logging
        _logging.getLogger("plamen.validators").warning(
            "[exploration_skeptic] exploration_skeptic_findings.md missing/empty "
            "— sentinel written, pipeline continues"
        )
        return []

    # Artifact present. Scan the coverage record for instance-level
    # rubber-stamps (axis cleared without a named instance + concrete locus).
    try:
        body = out_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        body = ""
    try:
        gap_rows = _scan_exploration_instance_gaps(body)
    except Exception:
        gap_rows = []
    if gap_rows:
        import logging as _logging
        _logging.getLogger("plamen.validators").warning(
            "[exploration_skeptic] %d coverage-record row(s) clear an instance "
            "(NO-GAP/ASSESSED) without a named instance + concrete evidence "
            "locus — each is recall-positive and should be re-surfaced as an "
            "ADD, not treated as resolved. Sentinel written, pipeline continues.",
            len(gap_rows),
        )
        lines = [
            "[EXPLORATION_SKEPTIC_INSTANCE_GAP] The following coverage-record",
            "rows cleared an instance (NO-GAP/ASSESSED) without naming the",
            "specific instance and citing a concrete evidence locus (file:line,",
            "function, or prior finding ID). Per the NO-GAP Evidence Rule these",
            "are unexplored instances, NOT resolved ones. This is WARNING-only",
            "and recall-positive: nothing is dropped or downgraded; each row",
            "below should be re-surfaced as an ADD by a human or later pass.",
            "",
        ]
        for r in gap_rows:
            lines.append(
                f"- finding={r['finding']!r} axis={r['axis']!r} "
                f"instance={r['instance']!r} disposition={r['disposition']!r} "
                f"evidence={r['evidence']!r}"
            )
        try:
            (scratchpad / "exploration_skeptic.instance_gap").write_text(
                "\n".join(lines) + "\n", encoding="utf-8"
            )
        except OSError:
            pass
    return []


def _validate_enumgap_exploration(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for Phase 4b.7 (enumeration-obligation exploration).

    Recall-positive / additive phase. Like exploration_skeptic / chain_iter2,
    this validator NEVER returns hard issues — it returns [] in every branch, so
    it can never set passed=False and can never halt. The phase only ADDS
    depth-traced findings (and reasoned clears); its absence loses no prior
    finding because the pre-existing ENUMGAP candidates already appended by the
    enumeration gate remain as the haltless candidate->verify fallback.

    On missing/near-empty output it writes a degraded sentinel and continues.
    """
    try:
        scratchpad = Path(scratchpad)
        out_path = scratchpad / "enumgap_exploration_findings.md"
        if not (out_path.exists() and out_path.stat().st_size > 30):
            try:
                (scratchpad / "enumgap_exploration.degraded").write_text(
                    "[ENUMGAP_EXPLORATION_DEGRADED] enumgap_exploration_findings.md "
                    "missing or <30 bytes. Pipeline continues; this phase is "
                    "additive-only — the enumeration gate's pre-existing ENUMGAP "
                    "candidates remain as the candidate->verify fallback, so no "
                    "obligation is lost by its absence.\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
            import logging as _logging
            _logging.getLogger("plamen.validators").warning(
                "[enumgap_exploration] enumgap_exploration_findings.md missing/empty "
                "— sentinel written, pipeline continues (obligations fall back to "
                "the verify candidates)"
            )
    except Exception:
        pass
    return []


# M1 committed-invariant commitment ------------------------------------------
#
# The skeptic phases (4b.6 exploration-skeptic, 5.1 skeptic) are told that every
# time they clear a value-bearing instance as NO-GAP or DOWNGRADE a value-bearing
# finding, they must ALSO emit a `committed-invariant [CI-n]` block encoding the
# tacit local guard as a falsifiable assertion. This SOFT validator confirms the
# habit: it counts NO-GAP/DOWNGRADE signals in the skeptic artifacts and the
# `[CI-n]` blocks present, and if there are value-bearing clears but zero
# committed invariants it writes a `.ci_gap` sentinel + warning for visibility.
# WARNING-only: never returns a hard issue, never sets passed=False, never halts.
# The habit is recall-positive (more falsifiable candidates); its absence loses
# no prior finding, so a gap is advisory, not fatal.

_CI_BLOCK_PRESENCE_RE = re.compile(r"committed-invariant\s*\[\s*CI(?:-[A-Za-z0-9]+)+\s*\]", re.IGNORECASE)
_CI_CLEAR_SIGNAL_RE = re.compile(r"\bNO-?GAP\b|\bDOWNGRADE\b", re.IGNORECASE)
# Format-agnostic committed-invariant header counter. Any `committed-invariant
# [<anything>]` header, regardless of ID shape. Compared against the harvestable
# _CI_BLOCK_PRESENCE_RE count to detect ID-format drift (a block the deriver's
# _CI_BLOCK_RE cannot parse = a silently-dropped committed invariant).
_CI_BLOCK_ANY_RE = re.compile(r"committed-invariant\s*\[\s*[^\]\n]+\]", re.IGNORECASE)


def _validate_invariant_commitment(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for M1 committed-invariant emission (skeptic phases).

    Recall-positive / additive. Like _validate_exploration_skeptic, it returns []
    in every branch — it can never set passed=False and can never halt. When a
    skeptic artifact records value-bearing clears (NO-GAP / DOWNGRADE) but carries
    NO `committed-invariant [CI-n]` block, it writes a `.ci_gap` sentinel and a
    warning so the missing falsifiable assertions are visible. Never raises.
    """
    if mode != "thorough":
        return []
    try:
        scratchpad = Path(scratchpad)
    except Exception:
        return []
    arts = []
    for name in ("exploration_skeptic_findings.md", "skeptic_findings.md"):
        try:
            p = scratchpad / name
            if p.exists() and p.stat().st_size > 30:
                arts.append(p)
        except OSError:
            continue
    if not arts:
        return []
    clears = 0
    ci_blocks = 0
    ci_blocks_any = 0
    for p in arts:
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        clears += len(_CI_CLEAR_SIGNAL_RE.findall(body))
        ci_blocks += len(_CI_BLOCK_PRESENCE_RE.findall(body))
        ci_blocks_any += len(_CI_BLOCK_ANY_RE.findall(body))
    # Harvest-vs-emit reconciliation (durable guard against ID-format drift):
    # committed-invariant blocks the harvester regex can't parse are silently
    # dropped — the CI-A1-vs-`CI-\d+` class that dark-dropped 12 skeptic
    # invariants pre-fix. If the artifacts carry more CI headers than the
    # harvestable pattern matches, surface it LOUDLY (sentinel + warning) rather
    # than letting the deriver harvest 0 with no signal. Never raises.
    if ci_blocks_any > ci_blocks:
        import logging as _logging
        _logging.getLogger("plamen.validators").warning(
            "[invariant_commitment] CI ID-FORMAT DRIFT: %d committed-invariant "
            "block(s) present but only %d match the harvestable pattern — %d "
            "would be silently dropped by the deriver. Investigate _CI_BLOCK_RE "
            "/ _CI_BLOCK_PRESENCE_RE ID shape.",
            ci_blocks_any, ci_blocks, ci_blocks_any - ci_blocks,
        )
        try:
            (scratchpad / "invariant_commitment.ci_format_gap").write_text(
                f"[INVARIANT_COMMITMENT_CI_FORMAT_GAP] {ci_blocks_any} "
                f"committed-invariant block(s) present but only {ci_blocks} are "
                f"harvestable ({ci_blocks_any - ci_blocks} dropped by ID-format "
                "mismatch). The deriver's _CI_BLOCK_RE cannot parse these IDs; "
                "broaden it to match the emitted ID shape.\n",
                encoding="utf-8",
            )
        except OSError:
            pass
    if clears > 0 and ci_blocks == 0:
        import logging as _logging
        _logging.getLogger("plamen.validators").warning(
            "[invariant_commitment] %d NO-GAP/DOWNGRADE clear(s) recorded across "
            "skeptic artifacts but 0 committed-invariant [CI-n] blocks emitted — "
            "each value-bearing clear should commit its tacit local guard as a "
            "falsifiable assertion. WARNING-only; sentinel written, pipeline "
            "continues (no prior finding is lost).",
            clears,
        )
        try:
            (scratchpad / "invariant_commitment.ci_gap").write_text(
                "[INVARIANT_COMMITMENT_CI_GAP] The skeptic artifacts recorded "
                f"{clears} value-bearing clear(s) (NO-GAP/DOWNGRADE) but emitted "
                "0 committed-invariant [CI-n] block(s). Per M1, each value-bearing "
                "clear should commit its tacit local guard as a falsifiable "
                "assertion for the falsifier. This is WARNING-only and "
                "recall-positive: nothing is dropped or downgraded; the missing "
                "assertions should be surfaced as committed invariants.\n",
                encoding="utf-8",
            )
        except OSError:
            pass
    return []


def _validate_axis_coverage(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for Phase 4b.8 (M2 multi-axis coverage meta-pass).

    Recall-positive / additive phase. Like _validate_enumgap_exploration /
    _validate_exploration_skeptic, it returns [] in EVERY branch — it can never
    set passed=False and can never halt. The phase only ADDS axis-coverage
    findings (or reasoned clears over GAP cells); its absence loses no prior
    finding because the mechanical matrix (hot_function_axes.md) is always
    persisted and the phase is skipped-when-clean.

    On missing/near-empty output it writes an `.axis_gap` degraded sentinel and
    a warning, then lets the pipeline proceed. Never raises.
    """
    if mode != "thorough":
        return []
    try:
        scratchpad = Path(scratchpad)
        out_path = scratchpad / "axis_coverage_findings.md"
        if not (out_path.exists() and out_path.stat().st_size > 30):
            try:
                (scratchpad / "axis_coverage.degraded").write_text(
                    "[AXIS_COVERAGE_DEGRADED] axis_coverage_findings.md missing or "
                    "<30 bytes. Pipeline continues; this phase is additive-only — "
                    "the mechanical hot-function × axis matrix (hot_function_axes.md) "
                    "is persisted regardless, so no prior finding is lost by its "
                    "absence.\n",
                    encoding="utf-8",
                )
            except OSError:
                pass
            import logging as _logging
            _logging.getLogger("plamen.validators").warning(
                "[axis_coverage] axis_coverage_findings.md missing/empty — sentinel "
                "written, pipeline continues (the mechanical axis matrix remains "
                "available for human review)"
            )
    except Exception:
        pass
    return []


# v2.x Fix 2: Anti-Absorption Hard Gate ---------------------------------------
#
# Chain Agent 1 groups raw findings into hypotheses (GRP-* IDs). The prompt's
# anti-absorption rule (phase4c-chain-prompt.md rule 6) tells the agent to
# split groups whose constituents need different fixes, span different
# functions, or differ in severity by >1 tier. In practice the LLM ignores
# this rule and produces "super-groups" — e.g., absorbing 4 distinct
# same-file bugs into one Medium hypothesis. When the verifier picks the
# weakest constituent's PoC and it fails, the entire group is dropped via
# poc_demotions.md, taking N true positives with it.
#
# This validator runs after Chain Agent 1 completes. It mechanically enforces
# the anti-absorption rule using the constituent locations / severities /
# root-cause text from findings_inventory.md. On violation it emits a
# retry-hint file that the build_phase_prompt function injects into the
# attempt-2 Chain Agent 1 prompt. Hard cap at 1 retry — after that the gate
# downgrades to warning and the pipeline proceeds.

_NICHE_AGENT_AAB_KEYWORD_GUARD = (
    "anti-absorption override",
    "anti absorption override",
)


def _extract_function_name(location_text: str) -> str:
    """Extract the function name token from a Location field string.

    Locations from finding-output-format are typically `Contract.sol:Lnn-Lmm
    function_name()` or `Contract.sol:Lnn` plus a function reference in the
    description. We extract the leftmost `name(` token. Returns "" when no
    function is identifiable (e.g., the finding is at constant declaration).
    """
    if not location_text:
        return ""
    text = location_text.strip()
    m = re.search(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", text)
    return m.group(1) if m else ""


def _extract_file_name(location_text: str) -> str:
    """Extract the source filename (without path) from a Location string."""
    if not location_text:
        return ""
    text = location_text.strip()
    m = re.search(
        r"([A-Za-z0-9_\-./\\]+\.(?:sol|move|rs|go|cairo|fc|tact))",
        text,
        re.IGNORECASE,
    )
    if not m:
        return ""
    return m.group(1).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


_SEVERITY_RANK = {
    "informational": 0, "info": 0,
    "low": 1,
    "medium": 2, "med": 2,
    "high": 3,
    "critical": 4, "crit": 4,
}


def _severity_tier(text: str) -> int:
    return _SEVERITY_RANK.get((text or "").strip().lower(), -1)


def _jaccard_token_similarity(a: str, b: str) -> float:
    """Token-set Jaccard similarity over alpha-only tokens length>=3.

    Used to compare root-cause / title strings to decide whether two
    constituents describe the same mechanism.
    """
    def tokens(s: str) -> set[str]:
        return {t for t in re.findall(r"[a-zA-Z]{3,}", (s or "").lower())}
    ta, tb = tokens(a), tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _parse_inventory_finding_meta_blocks(
    text: str, *, prefix_min: int = 2
) -> dict[str, dict[str, str]]:
    """Shared block-meta extractor for findings_inventory.md.

    Builds ``{finding_id: {title, severity, location, root_cause}}`` from
    `#{2,4} Finding [ID]: Title` blocks. *prefix_min* sets the minimum ID prefix
    length (2 for the base parser, 1 for the report-ID-tolerant twin).

    Per-block fields are harvested through the shared `_field_anywhere` tolerant
    extractor so the severity / location / root-cause values are recognized in
    bold (`**Severity**: High`), plain (`Severity: High`), bullet
    (`- Severity: High`), `=`-separated, and TABLE-CELL (`| Severity | High |`)
    renderings — a strict superset of the legacy `**Field**:`-exact regexes,
    which silently lost every field a uniform-tabular inventory rendered.
    """
    meta: dict[str, dict[str, str]] = {}
    matches = list(re.finditer(
        r"^#{2,4}\s*Finding\s*\[\s*([A-Z]{" + str(prefix_min)
        + r",6}-\d+)\s*\]\s*:\s*(.+?)\s*$",
        text,
        re.MULTILINE,
    ))
    for i, m in enumerate(matches):
        fid = m.group(1).strip().upper()
        title = m.group(2).strip()
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        sev_val, _ = _field_anywhere(block, ("Severity", "Final Severity"), table_ok=True)
        # Legacy severity regex captured only the first alpha word; preserve that
        # value-identity (e.g. "High (direct loss)" -> "High").
        sev_word = ""
        if sev_val:
            sm = re.match(r"\s*\**\s*([A-Za-z]+)", sev_val)
            sev_word = sm.group(1).strip() if sm else sev_val.strip()
        loc_val, _ = _field_anywhere(block, ("Location", "Locations"), table_ok=True)
        rc_val, _ = _field_anywhere(block, ("Root Cause", "Root-Cause"), table_ok=True)
        meta[fid] = {
            "title": title,
            "severity": sev_word,
            "location": loc_val.strip(),
            "root_cause": (rc_val.strip() if rc_val else title),
        }
    return meta


def _parse_inventory_finding_meta(scratchpad: Path) -> dict[str, dict[str, str]]:
    """Build {finding_id: {title, severity, location, root_cause}} from
    findings_inventory.md. Used by anti-absorption gate.
    """
    inventory_path = scratchpad / "findings_inventory.md"
    if not inventory_path.exists():
        return {}
    try:
        text = inventory_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    return _parse_inventory_finding_meta_blocks(text, prefix_min=2)


def _parse_hypothesis_id_title_pairs(text: str) -> list[tuple[str, str]]:
    """v2.0.6 (P2.4): extract `(finding_id, title)` pairs from an LLM-written
    hypotheses-style markdown file (hypotheses.md, chain_hypotheses.md).

    Recognizes lines like:
      `### GRP-01 — Title here`
      `### Hypothesis HC-02: Title here`
      `## Chain Hypothesis CH-01 — Title`
      `### Finding [HM-03]: Title`

    Returns pairs in document order. Duplicate IDs are returned multiple
    times (the caller handles dedup via the ledger).
    """
    from plamen_parsers import _HYPO_HEADING_RE
    pairs: list[tuple[str, str]] = []
    table_id_re = re.compile(
        r"^(H-[CHMLI]?\d+|CH-\d+|L1-[CHMLI]-\d+|GRP-\d+|H[CHMLI]-\d+)$",
        re.IGNORECASE,
    )
    for line in text.splitlines():
        m = _HYPO_HEADING_RE.match(line)
        if not m:
            stripped = line.strip()
            if not stripped.startswith("|") or stripped.count("|") < 2:
                continue
            if re.fullmatch(
                r"\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?",
                stripped,
            ):
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not cells:
                continue
            tm = table_id_re.fullmatch(cells[0])
            if not tm:
                continue
            title = ""
            for cell in cells[1:]:
                if re.fullmatch(
                    r"(?i)(critical|high|medium|low|informational|info|severity|title)",
                    cell or "",
                ):
                    continue
                title = cell
                break
            pairs.append((tm.group(1).upper(), title))
            continue
        fid = m.group(1).upper()
        # Everything after the matched ID on the heading is the title;
        # strip common separators (`:`, `—`, `-`, `]`) and whitespace.
        rest = line[m.end():].strip()
        rest = rest.lstrip("]")  # `### Finding [GRP-01]: title`
        rest = rest.lstrip(":–—-").strip()
        pairs.append((fid, rest))
    return pairs


def _parse_chain_agent2_id_title_pairs(text: str) -> list[tuple[str, str]]:
    """Extract only chain-agent2-local `CH-*` mints with stable content keys.

    `chain_hypotheses.md` is a composition artifact. It necessarily references
    upstream `H-*` findings, but those are consumers, not new allocations. The
    generic hypotheses parser sees detail lines such as `**ID**: H-01` and can
    falsely try to re-mint upstream IDs under `chain_agent2`.

    For `CH-*` rows, natural-language titles drift across retries
    ("H-09 (fee)" vs "H-09: full title"). The stable identity is the ordered
    source-ID tuple in the row/block, so use that as the ledger title.
    """
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    ch_re = re.compile(r"^CH-\d+$", re.IGNORECASE)
    source_re = re.compile(r"\bH-\d+\b", re.IGNORECASE)
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|") and stripped.count("|") >= 2:
            if re.fullmatch(
                r"\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?",
                stripped,
            ):
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not cells or not ch_re.fullmatch(cells[0]):
                continue
            fid = cells[0].upper()
            if fid in seen:
                continue
            source_ids: list[str] = []
            for cell in cells[1:]:
                for m in source_re.finditer(cell):
                    sid = m.group(0).upper()
                    if sid not in source_ids:
                        source_ids.append(sid)
            title = " + ".join(source_ids) if source_ids else " | ".join(cells[1:4])
            pairs.append((fid, title))
            seen.add(fid)
            continue
        m = re.match(
            r"^#{2,4}\s*(?:Chain\s+Hypothesis\s+)?(CH-\d+)\b\s*:?\s*(.*)$",
            stripped,
            re.IGNORECASE,
        )
        if not m:
            continue
        fid = m.group(1).upper()
        if fid in seen:
            continue
        title = m.group(2).strip() or fid
        pairs.append((fid, title))
        seen.add(fid)
    return pairs


def _validate_id_ledger_collisions(
    scratchpad: Path, phase_name: str, attempt: int = 1
) -> list[str]:
    """v2.0.6 (P2.4): BLOCKING gate — register each ID the phase emitted
    and detect collisions against prior attempts.

    Per the plan, this gate is hard-fail for chain / chain_agent2 — a
    prior GRP-01 collision (chain attempt 1 minted GRP-01 for
    Critical public-withdraw; attempt 2 re-minted for Medium reinitializer)
    is the canonical case. Returns issue strings describing each collision;
    empty list means no collisions (and IDs have been registered).

    Phase-specific source map:
      - chain: hypotheses.md (HC/HH/HM/HL/HI/GRP/H prefixes)
      - chain_agent2: chain_hypotheses.md (CH prefix)

    Other phases (inventory_*, niche_promotion) register inline at minting
    time via `plamen_mechanical.py`; they do not run this gate.
    """
    artifact_map = {
        "chain": "hypotheses.md",
        "chain_agent2": "chain_hypotheses.md",
    }
    artifact_name = artifact_map.get(phase_name)
    if not artifact_name:
        return []
    artifact_path = scratchpad / artifact_name
    if not artifact_path.exists():
        return []
    try:
        text = artifact_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if phase_name == "chain_agent2":
        pairs = _parse_chain_agent2_id_title_pairs(text)
    else:
        pairs = _parse_hypothesis_id_title_pairs(text)
    if not pairs:
        return []
    from plamen_parsers import _id_ledger_load, _id_ledger_save, id_ledger_register

    # Failed retries are quarantined and are not downstream truth. Do not let
    # their same-phase allocations poison the next attempt.
    #
    # `chain_agent2` mints CH-* whose stable identity is the ordered source-ID
    # tuple in the row; natural-language detail around that tuple drifts freely
    # across retries, so for chain_agent2 we PURGE its own prior-attempt
    # allocations entirely (a re-mint is a replacement). Cross-phase collisions
    # remain blocking.
    #
    # `chain` (Agent 1) owns GRP/HH/HM/... whose identity IS the title. We do
    # NOT blind-purge those on retry — that would lose the genuine
    # collision (GRP-01 Critical-A on attempt 1 vs different Medium-B on
    # attempt 2). Instead, retry-awareness for `chain` is content-based: the
    # ledger's `_titles_collide` predicate treats a phase re-minting its own ID
    # with the SAME finding (cosmetic reword: em-dash -> hyphen, abbreviation
    # expanded, added detail) as REUSED, and only a genuinely DIFFERENT finding
    # as COLLISION. This was a prior false-collision root cause: 36
    # cosmetic chain rewordings tripped the strict title-hash equality check.
    if attempt > 1 and phase_name == "chain_agent2":
        try:
            ledger = _id_ledger_load(scratchpad)
            before = len(ledger.get("allocations", []))
            ledger["allocations"] = [
                r for r in ledger.get("allocations", [])
                if not (
                    str(r.get("owner_phase", "")) == phase_name
                    and str(r.get("owning_artifact", "")) == artifact_name
                )
            ]
            if len(ledger.get("allocations", [])) != before:
                _id_ledger_save(scratchpad, ledger)
        except Exception:
            pass

    collisions: list[str] = []
    seen_in_this_phase: set[str] = set()
    for fid, title in pairs:
        # Within the same artifact, the FIRST occurrence of an ID is the
        # one that "owns" the title; later occurrences are usually
        # cross-references (e.g. in finding_mapping section). Register
        # only on first sight per phase invocation.
        if fid in seen_in_this_phase:
            continue
        seen_in_this_phase.add(fid)
        result = id_ledger_register(
            scratchpad,
            finding_id=fid,
            owner_phase=phase_name,
            owner_attempt=attempt,
            owning_artifact=artifact_name,
            title=title,
        )
        if result["status"] == "COLLISION":
            existing = result.get("existing") or {}
            current = result.get("current") or {}
            collisions.append(
                f"ID `{fid}` was previously allocated by "
                f"{existing.get('owner_phase','?')}/attempt "
                f"{existing.get('owner_attempt','?')} to title "
                f"{existing.get('title_preview','?')[:60]!r}; this attempt "
                f"tried to re-allocate it to "
                f"{current.get('title_preview','?')[:60]!r}"
            )
    return collisions


def _validate_consumer_ids_in_ledger(
    scratchpad: Path, phase_name: str
) -> list[str]:
    """v2.0.6 (P2.5): backstop gate — every internal finding ID a
    consumer phase references MUST exist in the ID ledger.

    Pure consumer phases (sc_verify_queue, sc_verify_aggregate, skeptic,
    crossbatch, report_index) never mint IDs — they only consume IDs that
    upstream minting phases (inventory_*, chain, chain_agent2) allocated.
    A reference to an unregistered ID is a contamination signal: either
    the LLM hallucinated, the consumer is reading stale markdown from a
    previous audit, OR an upstream phase failed silently.

    WARNING-only at first ship to avoid false halts while the ledger
    pattern matures across pipelines. Promotion to halt-class follows
    the documented two-cycle pattern (warning → halt) per the plan's
    promotion-path policy.

    Returns issue strings; empty list means the consumer's IDs all
    trace back to the ledger.
    """
    # Phase → (artifact, prefix glob for IDs that SHOULD be in the
    # ledger). Consumers may also reference non-finding tokens (file
    # names, report IDs M-NN/L-NN/etc.) — those are NOT checked here.
    consumer_artifacts = {
        "sc_verify_queue": "verification_queue.md",
        "sc_verify_aggregate": "verify_core.md",
        "skeptic": "skeptic_findings.md",
        "crossbatch": "cross_batch_consistency.md",
        "report_index": "report_index.md",
    }
    artifact_name = consumer_artifacts.get(phase_name)
    if not artifact_name:
        return []
    artifact_path = scratchpad / artifact_name
    if not artifact_path.exists():
        return []
    _backfill_inventory_ids_into_ledger(scratchpad)
    # Import lazily to keep modularization clean.
    from plamen_parsers import (
        _INTERNAL_FINDING_ID_RE, id_ledger_all_records,
    )
    ledger_ids = {
        r.get("id", "").upper() for r in id_ledger_all_records(scratchpad)
        if r.get("id")
    }
    if not ledger_ids:
        # Ledger empty — could be a legacy audit (pre-v2.0.6). Silent skip.
        return []
    if phase_name == "skeptic":
        referenced = _skeptic_structural_id_references(scratchpad)
    else:
        try:
            text = artifact_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        referenced = {
            m.group(1).upper() for m in _INTERNAL_FINDING_ID_RE.finditer(text)
        }
    # Filter out internal/report-tier IDs that this gate doesn't validate:
    # - M-NN, L-NN, C-NN, H-NN, I-NN (report tier IDs, minted at report_index)
    # - CH-NN (chain hypothesis IDs from chain_agent2)
    # The ledger SHOULD know about CH-* but report-tier IDs are post-mapping
    # and not part of the same namespace.
    import re as _re
    report_tier_re = _re.compile(r"^[CHMLI]-\d+$")
    auxiliary_scope_re = _re.compile(r"^AB-\d+$")
    fresh_audit = scratchpad_is_fresh_audit(scratchpad)
    finding_refs = {
        r for r in referenced
        if (
            not report_tier_re.match(r)
            and not auxiliary_scope_re.match(r)
            and (fresh_audit or not r.startswith("INV-"))
        )
    }
    # INV-* remains legacy-tolerant only on pre-marker audits. Fresh audits
    # must have driver-registered INV allocations so stale retry collisions
    # cannot silently reuse an inventory ID for different content.
    synthetic_traces: dict[str, dict[str, str]] = {}
    unregistered: set[str] = set()
    for ref in sorted(finding_refs - ledger_ids):
        trace = _trace_synthetic_consumer_id(scratchpad, ref)
        if trace:
            synthetic_traces[ref] = trace
            continue
        # Prefix-AGNOSTIC produced-artifact backstop: an ID-shaped token that is
        # not in the minted ledger AND not traced through the (prefix-keyed)
        # synthetic path above is NOT contamination if it demonstrably APPEARS
        # in a produced upstream artifact (findings_inventory / analysis_* /
        # chain_* / depth_* / verify_* / hypotheses / etc.). Legitimate
        # agent-source / chain namespaces (CMI-, CC-, CCT-, CR-, DEX-, TF-, ...)
        # are minted by breadth/depth/recon workers that the ledger does not
        # track, so requiring a ledger entry mis-reads them as contamination.
        # We do NOT enumerate prefixes — presence in a real artifact is the
        # signal. RECALL-SAFE: a hallucinated / stale-cross-run ID present in NO
        # produced artifact (and not in the ledger) is still flagged.
        present = _id_present_in_produced_artifact(scratchpad, ref, artifact_name)
        if present:
            synthetic_traces[ref] = {
                "id": ref,
                "source_artifact": present,
                "source_kind": "produced-artifact-presence",
            }
            continue
        unregistered.add(ref)
    if synthetic_traces:
        _write_id_ledger_synthetic_map(
            scratchpad,
            phase_name=phase_name,
            consumer_artifact=artifact_name,
            traces=synthetic_traces,
        )
    if not unregistered:
        return []
    # WARNING-only signal. Format names a sample.
    sample = sorted(unregistered)[:8]
    extra = f" (+{len(unregistered) - 8} more)" if len(unregistered) > 8 else ""
    return [
        f"id-ledger consumer-backstop: {phase_name} references "
        f"{len(unregistered)} unregistered ID(s): "
        f"{', '.join(sample)}{extra}"
    ]


def _skeptic_structural_id_references(scratchpad: Path) -> set[str]:
    """Return IDs used as skeptic section/table keys, not prose examples.

    Skeptic reasoning often mentions local concern labels from upstream
    artifacts (e.g. OR-2, EX-1, CC-09) while discussing why a manifest finding
    is overstated. Those prose mentions are not identity bindings. The ledger
    backstop should only inspect the structural places where skeptic binds a
    decision to a finding: section headings and judge-table first cells.
    """
    from plamen_parsers import _INTERNAL_FINDING_ID_RE

    refs: set[str] = set()
    findings_path = scratchpad / "skeptic_findings.md"
    if findings_path.exists():
        try:
            text = findings_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for line in text.splitlines():
            if not re.match(r"^\s*#{2,6}\s+", line):
                continue
            m = _INTERNAL_FINDING_ID_RE.search(line)
            if m:
                refs.add(m.group(1).upper())

    decisions_path = scratchpad / "skeptic_judge_decisions.md"
    if decisions_path.exists():
        try:
            text = decisions_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("|"):
                continue
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not cells:
                continue
            first = cells[0]
            if not first or set(first) <= {"-", ":"}:
                continue
            if first.lower() in {"finding id", "id", "finding"}:
                continue
            m = _INTERNAL_FINDING_ID_RE.search(first)
            if m:
                refs.add(m.group(1).upper())
    return refs


def _trace_synthetic_consumer_id(
    scratchpad: Path, ref: str
) -> dict[str, str] | None:
    """Trace non-ledger internal IDs to a durable upstream artifact.

    Some methodology-owned artifacts mint local IDs that are not part of the
    chain/inventory ledger namespace: depth concern IDs (DCI/DST/DA/etc.),
    cross-batch IDs (CBS), skill-gap IDs (SGI), and chain-composition IDs
    (CC). Ledger-owned chain IDs (GRP/HH/HM/HL/HI/CH) are deliberately not
    accepted through this synthetic path.
    """
    ref = (ref or "").upper()
    exact: list[str] = []
    globs: list[str] = []
    if re.match(r"^(?:DCI|DEC|DX|DN|DNS)-", ref) or ref.startswith("DA-"):
        globs.extend([
            "depth_*_findings.md",
            "blind_spot_*_findings.md",
            "niche_*_findings.md",
        ])
        exact.extend([
            "validation_sweep_findings.md",
            "consensus_map.md",
            "confidence_scores.md",
        ])
    elif ref.startswith("DST-"):
        exact.extend(["design_stress_findings.md", "depth_design_stress_findings.md"])
        globs.extend(["depth_*_findings.md", "niche_*_findings.md"])
    elif ref.startswith("PERT-"):
        exact.extend(["perturbation_findings.md", "depth_perturbation_findings.md"])
        globs.extend(["depth_*_findings.md", "niche_*_findings.md"])
    elif ref.startswith("SGI-"):
        exact.extend([
            "skill_execution_gaps.md",
            "skill_execution_checklist.md",
            "niche_semantic_gap_findings.md",
            "niche_semantic_consistency_findings.md",
        ])
    elif ref.startswith("CBS-"):
        exact.extend(["cross_batch_consistency.md"])
    elif ref.startswith("CC-"):
        exact.extend([
            "chain_hypotheses.md",
            "hypotheses.md",
            "chain_summaries_compact.md",
            "chain_topology.md",
        ])
    elif ref.startswith("EN-"):
        exact.extend(["enabler_results.md", "chain_hypotheses.md"])
    elif ref.startswith("ST-"):
        exact.extend(["design_stress_findings.md"])
    elif ref.startswith("VS-"):
        exact.extend(["validation_sweep_findings.md"])
    else:
        return None

    candidates: list[Path] = []
    for name in exact:
        p = scratchpad / name
        if p.exists() and p.is_file():
            candidates.append(p)
    for pattern in globs:
        candidates.extend(sorted(p for p in scratchpad.glob(pattern) if p.is_file()))

    token_re = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(ref)}(?![A-Za-z0-9_-])")
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if token_re.search(text):
            return {
                "id": ref,
                "source_artifact": path.name,
                "source_kind": "synthetic-local-id",
            }
    return None


# Produced-artifact families a consumer-referenced ID may legitimately have been
# minted into by an upstream breadth/depth/recon/chain worker. Prefix-agnostic:
# membership is decided by token PRESENCE, not by the ID's prefix. The consumer's
# own artifact is excluded by the caller so an ID does not "register itself".
_PRODUCED_ARTIFACT_GLOBS: tuple[str, ...] = (
    "findings_inventory*.md",
    "analysis_*.md",
    "chain_*.md",
    "chain_hypotheses.md",
    "hypotheses.md",
    "depth_*.md",
    "blind_spot_*.md",
    "niche_*.md",
    "validation_sweep_findings.md",
    "design_stress_findings.md",
    "perturbation_findings.md",
    "verify_*.md",
    "verify_core.md",
    "verification_queue.md",
    "enabler_results.md",
)


# Ledger-OWNED minting namespaces: hypothesis / severity-group / chain / driver
# inventory IDs. Their identity is the MINT (chain Agent 1 / inventory), so they
# MUST trace to `_id_ledger.json` — artifact presence alone does NOT register
# them (a stale `hypotheses.md` HM-NN from a prior attempt would otherwise
# launder a collision). Everything else (agent-source / breadth-worker
# namespaces like CMI-/CC-/CCT-/CR-/DEX-/TF-/...) is minted by workers the ledger
# does not track, so artifact presence is the legitimate registration signal.
_LEDGER_OWNED_ID_RE = re.compile(
    r"^(?:H-\d+|H[CHMLI]-\d+|GRP-\d+|CH-\d+|INV-\d+)$",
    re.IGNORECASE,
)


def _id_present_in_produced_artifact(
    scratchpad: Path, ref: str, exclude_artifact: str | None = None
) -> str | None:
    """Return the name of a produced artifact that contains *ref*, or None.

    Prefix-agnostic backstop for the id-ledger consumer gate: an ID-shaped
    token that ACTUALLY APPEARS (as a whole token) in a real upstream artifact
    is a legitimate agent-source/chain ID, not contamination — regardless of its
    prefix. The consumer's own output (`exclude_artifact`) is skipped so a
    self-reference cannot launder a hallucinated ID. Ledger-OWNED minting
    namespaces (`_LEDGER_OWNED_ID_RE`) are NOT accepted via this path — they must
    trace to the ledger so a stale artifact cannot launder a mint collision.
    """
    ref = (ref or "").strip().upper()
    if not ref:
        return None
    if _LEDGER_OWNED_ID_RE.match(ref):
        return None
    token_re = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(ref)}(?![A-Za-z0-9_-])")
    seen: set[str] = set()
    for pattern in _PRODUCED_ARTIFACT_GLOBS:
        for path in sorted(scratchpad.glob(pattern)):
            if not path.is_file():
                continue
            if exclude_artifact and path.name == exclude_artifact:
                continue
            if path.name in seen:
                continue
            seen.add(path.name)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if token_re.search(text):
                return path.name
    return None


def _write_id_ledger_synthetic_map(
    scratchpad: Path,
    *,
    phase_name: str,
    consumer_artifact: str,
    traces: dict[str, dict[str, str]],
) -> None:
    """Best-effort audit trail for non-ledger IDs accepted by traceability."""
    path = scratchpad / "_id_ledger_synthetic_map.json"
    try:
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
        else:
            payload = {"schema_version": 1, "traces": []}
    except Exception:
        payload = {"schema_version": 1, "traces": []}
    existing = {
        (
            str(t.get("id") or "").upper(),
            str(t.get("consumer_phase") or ""),
            str(t.get("consumer_artifact") or ""),
            str(t.get("source_artifact") or ""),
        )
        for t in payload.get("traces", [])
        if isinstance(t, dict)
    }
    for ref, trace in sorted(traces.items()):
        key = (
            ref.upper(),
            phase_name,
            consumer_artifact,
            str(trace.get("source_artifact", "")),
        )
        if key in existing:
            continue
        payload.setdefault("traces", []).append({
            "id": ref.upper(),
            "consumer_phase": phase_name,
            "consumer_artifact": consumer_artifact,
            "source_artifact": trace.get("source_artifact", ""),
            "source_kind": trace.get("source_kind", "synthetic-local-id"),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        })
    try:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError:
        return


def _generate_id_ledger_collision_retry_hint(
    collisions: list[str], phase_name: str
) -> str:
    """Render a retry hint when the collision gate fails."""
    lines = [
        "## RETRY HINT — ID ledger collision (v2.0.6)",
        "",
        f"Your previous attempt at `{phase_name}` re-minted an ID that a "
        "PRIOR attempt already allocated to DIFFERENT content. This is the "
        "root cause of a prior halt class: when the same ID "
        "(e.g., GRP-01) means two different findings in different artifact "
        "files, downstream phases get incoherent data and either silently "
        "produce wrong reports OR halt at the authenticity gate.",
        "",
        "Collisions detected:",
    ]
    for c in collisions[:8]:
        lines.append(f"- {c}")
    if len(collisions) > 8:
        lines.append(f"- ... (+{len(collisions) - 8} more)")
    lines.extend([
        "",
        "REPAIR:",
        "1. For each collision: if your new grouping has the SAME root "
        "cause as the prior allocation, REUSE the prior ID (write the "
        "same title/scope).",
        "2. If your new grouping has a DIFFERENT root cause, allocate a "
        "NEW ID using the next-available number for the prefix. The "
        "ledger directive at the top of your prompt lists which numbers "
        "are taken.",
        "3. NEVER reuse an existing ID for different content — the "
        "driver's post-phase ledger gate will fail every attempt that "
        "does so.",
    ])
    return "\n".join(lines) + "\n"


def _validate_chain_anti_absorption(scratchpad: Path, mode: str) -> list[str]:
    """HARD-with-retry gate enforcing anti-absorption (phase4c-chain rule 6).

    For each multi-constituent GRP-* hypothesis, flag a violation when any of:
      (a) Constituents span ≥2 distinct (file, function) tuples
      (b) max(severity) − min(severity) > 1 tier
      (c) Pairwise root-cause Jaccard similarity < 0.30
    UNLESS the hypothesis body (in hypotheses.md) explicitly contains
    "Anti-absorption override:" with a reason.

    Returns issue strings. Caller may emit a retry hint and re-spawn chain
    Agent 1 on attempt 2; if violations persist on attempt 2, caller should
    log warning and proceed (do not halt the pipeline).
    """
    # Lazy import to avoid circular dependency at module load
    try:
        from plamen_parsers import _parse_hypothesis_constituents
    except Exception:
        return []

    if mode not in ("core", "thorough"):
        return []
    inventory = _parse_inventory_finding_meta(scratchpad)
    if not inventory:
        return []
    mapping = _parse_hypothesis_constituents(scratchpad)
    if not mapping:
        return []
    hyp_text = ""
    hyp_path = scratchpad / "hypotheses.md"
    if hyp_path.exists():
        try:
            hyp_text = hyp_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            hyp_text = ""

    issues: list[str] = []
    for hyp_id, constituents in mapping.items():
        # Resolve constituent metadata; skip those not in inventory (could be
        # chain hypothesis IDs CH-*, niche IDs not yet promoted, etc.).
        meta_list = [
            (cid, inventory[cid]) for cid in constituents if cid in inventory
        ]
        if len(meta_list) < 2:
            continue
        # Look for explicit override anywhere in the hypothesis's section
        override_present = False
        if hyp_text:
            # Find the hypothesis block and look for the override sentinel
            block_pat = re.compile(
                rf"(?:^|\n)[^\n]*\b{re.escape(hyp_id)}\b[^\n]*\n",
                re.IGNORECASE,
            )
            for match in block_pat.finditer(hyp_text):
                start = match.start()
                end = min(start + 2000, len(hyp_text))
                snippet = hyp_text[start:end].lower()
                if any(kw in snippet for kw in _NICHE_AGENT_AAB_KEYWORD_GUARD):
                    override_present = True
                    break
        if override_present:
            continue

        # (a) distinct (file, function)
        file_func_pairs = set()
        for cid, m in meta_list:
            f = _extract_file_name(m["location"])
            fn = _extract_function_name(m["location"]) or _extract_function_name(m["root_cause"])
            file_func_pairs.add((f.lower(), fn.lower()))
        # Remove the no-information pair if any constituent had no file/func
        file_func_pairs.discard(("", ""))
        distinct_functions = len(file_func_pairs) >= 2

        # (b) severity tier span > 1
        sev_ranks = [
            _severity_tier(m["severity"]) for _, m in meta_list
        ]
        sev_ranks = [r for r in sev_ranks if r >= 0]
        sev_span = (max(sev_ranks) - min(sev_ranks)) if sev_ranks else 0
        severity_violation = sev_span > 1

        # (c) Root-cause similarity (pairwise minimum)
        rc_min_sim = 1.0
        rcs = [m["root_cause"] or m["title"] for _, m in meta_list]
        for i in range(len(rcs)):
            for j in range(i + 1, len(rcs)):
                sim = _jaccard_token_similarity(rcs[i], rcs[j])
                if sim < rc_min_sim:
                    rc_min_sim = sim
        rc_low_similarity = rc_min_sim < 0.30

        violations: list[str] = []
        # Fix 6: distinct (file, function) is DEMOTED to a soft retry-hint note.
        # It is NEVER, by itself, a hard violation and must never drive
        # mechanical atomization or a standalone retry — same-fix mirror-contract
        # clusters legitimately span functions/files. It is surfaced only as
        # advisory context WHEN a real (severity/Jaccard) violation already
        # forces a retry.
        if severity_violation:
            sev_strs = sorted({m["severity"] for _, m in meta_list if m["severity"]})
            violations.append(f"severity span > 1 tier ({', '.join(sev_strs)})")
        if rc_low_similarity:
            violations.append(f"root-cause Jaccard {rc_min_sim:.2f} < 0.30")
        if not violations:
            # Distinct functions alone -> preserve the LLM's grouping; no issue.
            continue
        soft_note = ""
        if distinct_functions:
            funcs_str = ", ".join(
                f"{ff[0] or '?'}:{ff[1] or '?'}" for ff in sorted(file_func_pairs)
            )
            soft_note = (
                f" [soft note: constituents span distinct functions ({funcs_str}) "
                "— advisory only, not itself a split trigger]"
            )
        constituent_ids = ", ".join(cid for cid, _ in meta_list)
        issues.append(
            f"{hyp_id} absorbs {len(meta_list)} constituents ({constituent_ids}) "
            f"with anti-absorption violations: {'; '.join(violations)}{soft_note}"
        )
    return issues


_MECHANICAL_BASELINE_STAMP = "**Status**: MECHANICAL_BASELINE"


def _declared_depth_findings(
    depth_path: Path,
) -> list[tuple[str, str, str, str, str]]:
    """Parse `### Finding [ID]:` blocks from a depth_*_findings.md file.

    Returns a list of (finding_id, title, severity, location, verdict) tuples,
    one per declared finding. Used by BOTH the baseline-regroup gate (CHECK 2,
    verdict filter) and the inline auto-map repair helper, so detection and
    repair stay symmetric.

    Uses the permissive `_INVENTORY_FINDING_HEADING_RE` + `_extract_finding_ids_from_text`
    for ID detection (matches bare DA-N / DX-N / etc. shapes), then derives the
    title/severity/location/verdict from the block body via `_field_from_markdown`.
    This deliberately does NOT rely on `_parse_depth_finding_blocks`, whose
    feeder-ID heading pattern rejects bare `DA-N`-shaped IDs.
    """
    try:
        from plamen_parsers import (
            _INVENTORY_FINDING_HEADING_RE,
            _extract_finding_ids_from_text,
            _field_from_markdown,
            _normalize_finding_id,
            _strip_md,
        )
    except Exception:
        return []

    try:
        text = depth_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    matches = list(_INVENTORY_FINDING_HEADING_RE.finditer(text))
    if not matches:
        return []

    out: list[tuple[str, str, str, str, str]] = []
    seen: set[str] = set()
    for idx, m in enumerate(matches):
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        block = text[start:end]
        heading_line = next(
            (ln for ln in block.splitlines() if ln.strip()), ""
        )
        declared = _extract_finding_ids_from_text(heading_line)
        if not declared:
            continue
        for did in sorted(declared):
            norm = _normalize_finding_id(str(did)) or str(did).strip().upper()
            if not norm or norm in seen:
                continue
            seen.add(norm)
            # Title: strip the `### Finding [ID]:` prefix from the heading.
            title = re.sub(r"^\s*###\s+Finding\s+\[[^\]]+\]:\s*", "", heading_line).strip()
            title = _strip_md(title) or norm
            sev = _strip_md(
                _field_from_markdown(block, ("Severity", "Final Severity"))
            ) or "Medium"
            loc = _strip_md(
                _field_from_markdown(block, ("Location", "Locations"))
            ) or "UNKNOWN"
            verdict = _strip_md(
                _field_from_markdown(block, ("Verdict", "Final Verdict", "Status"))
            )
            out.append((norm, title, sev, loc, verdict))
    return out


def _validate_chain_baseline_not_regrouped(scratchpad: Path, mode: str) -> list[str]:
    """HARD-with-retry gate: Chain Agent 1 must overwrite the driver scaffold.

    The driver writes a one-finding-per-hypothesis MECHANICAL_BASELINE scaffold
    (hypotheses.md / finding_mapping.md / enabler_results.md) BEFORE Chain Agent
    1 runs (see `_write_chain_passthrough_outputs`). If the agent obeys the
    generic RESUMPTION PROTOCOL (any >=200-byte file = complete prior work), it
    skips PHASE 1 grouping and leaves the scaffold in place. Post-inventory
    depth findings (Devil's-Advocate DA-*, etc.) that were not present at
    scaffold time then never get mapped into hypotheses.md / finding_mapping.md
    and are silently dropped from the report.

    This gate fires on exactly the two observable signatures of the no-op:
      CHECK 1 (stamp): hypotheses.md OR finding_mapping.md still carries the
        literal `**Status**: MECHANICAL_BASELINE` stamp — only the driver
        scaffold writes this, so its survival proves grouping was skipped.
      CHECK 2 (unmapped depth IDs): a finding ID DECLARED via `### Finding
        [ID]:` in any depth_*_findings.md that is ABSENT from
        finding_mapping.md's constituent set — in a healthy grouped run every
        declared depth finding is grouped, so this set difference is empty.

    Returns issue strings. Caller emits a retry hint and re-spawns Chain Agent 1
    on attempt 2; if violations persist, caller logs a warning and proceeds
    (never halts).
    """
    if mode not in ("core", "thorough"):
        return []

    issues: list[str] = []

    # --- CHECK 1: MECHANICAL_BASELINE stamp survived (scaffold not overwritten)
    for fname in ("hypotheses.md", "finding_mapping.md"):
        fpath = scratchpad / fname
        if not fpath.exists():
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if _MECHANICAL_BASELINE_STAMP in text:
            issues.append(
                f"{fname} still carries MECHANICAL_BASELINE stamp — Chain Agent 1 "
                "skipped PHASE 1 grouping (scaffold not overwritten)"
            )

    # --- CHECK 2: every declared depth finding ID is mapped as a constituent
    try:
        from plamen_parsers import (
            _extract_finding_ids_from_text,
            _normalize_finding_id,
            _parse_hypothesis_constituents,
        )
    except Exception:
        return issues

    def _norm(raw: str) -> str:
        return _normalize_finding_id(str(raw)) or str(raw).strip().upper()

    # Build the set of constituent IDs declared anywhere in the mapping. Source
    # both from the structured parser AND from a raw ID sweep of
    # finding_mapping.md / hypotheses.md, using the SAME extractor as the
    # declared-depth-ID side. This keeps the two sides symmetric so the gate
    # cannot false-fire on ID shapes the structured constituent parser does not
    # recognize (e.g. bare DA-3) but that are genuinely present in the mapping.
    mapped_ids: set[str] = set()
    try:
        mapping = _parse_hypothesis_constituents(scratchpad)
    except Exception:
        mapping = {}
    for constituents in (mapping or {}).values():
        for cid in constituents:
            norm = _norm(cid)
            if norm:
                mapped_ids.add(norm)
    for fname in ("finding_mapping.md", "hypotheses.md"):
        fpath = scratchpad / fname
        if not fpath.exists():
            continue
        try:
            ftext = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for mid in _extract_finding_ids_from_text(ftext):
            norm = _norm(mid)
            if norm:
                mapped_ids.add(norm)

    # Collect declared depth finding IDs ONLY from `### Finding [ID]:` headings
    # in depth_*_findings.md (not from free-text cross-references), so the gate
    # cannot false-fire on mentioned-but-not-declared IDs. Only NON-REFUTED
    # findings (CONFIRMED/PARTIAL/CONTESTED, per _is_reportable_verdict) are
    # required to be mapped — REFUTED/FALSE_POSITIVE/DUPLICATE depth findings
    # are legitimately excluded from grouping, so flagging them would false-fire
    # and (post inline auto-map) leave a non-repairable residual. The same
    # heading/ID/verdict extraction (`_declared_depth_findings`) is reused by the
    # inline auto-map repair helper, keeping detection and repair symmetric.
    for depth_path in sorted(scratchpad.glob("depth_*_findings.md")):
        for did, _title, _sev, _loc, verdict in _declared_depth_findings(depth_path):
            if not _is_reportable_verdict(verdict):
                continue
            norm = _norm(did)
            if not norm:
                continue
            if norm not in mapped_ids:
                issues.append(
                    f"depth finding {norm} declared in {depth_path.name} is absent "
                    "from finding_mapping.md constituents — depth findings dropped "
                    "from grouping"
                )

    return issues


def _auto_map_unmapped_depth_findings(scratchpad: Path) -> list[str]:
    """Inline mechanical repair for the chain baseline-regroup gate.

    When `_validate_chain_baseline_not_regrouped` detects unmapped non-refuted
    depth findings (and/or the surviving MECHANICAL_BASELINE stamp), the driver
    repairs the condition deterministically instead of retrying Chain Agent 1
    (which both costs a 42-min re-run AND re-mints cosmetically-reworded IDs that
    trip `_validate_id_ledger_collisions`). This mirrors the existing inline
    repair pattern used for anti-absorption (`_repair_chain_anti_absorption_splits`):
    repair-then-recheck, never retry.

    For each `depth_*_findings.md` finding whose verdict is reportable
    (CONFIRMED/PARTIAL/CONTESTED — REFUTED/FALSE_POSITIVE/DUPLICATE skipped via
    `_is_reportable_verdict`) and whose ID is NOT already mapped, append a solo
    hypothesis row to BOTH `hypotheses.md` and `finding_mapping.md` using the
    same scaffold row format as `_write_chain_passthrough_outputs`, preserving
    the finding's ID, title, and severity verbatim from the depth block. Also
    strips the `**Status**: MECHANICAL_BASELINE` stamp from both files so the
    gate's CHECK 1 clears after repair (full-skip self-heal).

    RECALL-SAFE: only ADDS rows, never removes any. Returns the list of finding
    IDs it appended (empty if nothing to repair).
    """
    scratchpad = Path(scratchpad)
    try:
        from plamen_parsers import (
            _extract_finding_ids_from_text,
            _normalize_finding_id,
            _parse_hypothesis_constituents,
        )
    except Exception:
        return []

    def _norm(raw: str) -> str:
        return _normalize_finding_id(str(raw)) or str(raw).strip().upper()

    def _cell(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "").replace("|", "/")).strip()

    hyp_path = scratchpad / "hypotheses.md"
    map_path = scratchpad / "finding_mapping.md"

    # Rebuild the mapped-ID set using the SAME symmetric logic the gate uses
    # (structured constituent parser + raw ID sweep of both files), so the
    # helper repairs exactly what the gate flags.
    mapped_ids: set[str] = set()
    try:
        mapping = _parse_hypothesis_constituents(scratchpad)
    except Exception:
        mapping = {}
    for constituents in (mapping or {}).values():
        for cid in constituents:
            norm = _norm(cid)
            if norm:
                mapped_ids.add(norm)
    for fpath in (map_path, hyp_path):
        if not fpath.exists():
            continue
        try:
            ftext = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for mid in _extract_finding_ids_from_text(ftext):
            norm = _norm(mid)
            if norm:
                mapped_ids.add(norm)

    # Collect unmapped non-refuted depth findings (id, title, severity, location).
    to_append: list[dict[str, str]] = []
    seen_new: set[str] = set()
    for depth_path in sorted(scratchpad.glob("depth_*_findings.md")):
        for did, title, sev, loc, verdict in _declared_depth_findings(depth_path):
            if not _is_reportable_verdict(verdict):
                continue
            norm = _norm(did)
            if not norm or norm in mapped_ids or norm in seen_new:
                continue
            seen_new.add(norm)
            to_append.append({
                "id": norm,
                "title": _cell(title or norm),
                "severity": normalize_severity(sev or "Medium"),
                "location": _cell(loc or "UNKNOWN"),
            })

    # Strip the MECHANICAL_BASELINE stamp even when there is nothing to append,
    # so the full-skip-with-no-unmapped-depth edge case still self-heals CHECK 1.
    def _strip_stamp(text: str) -> str:
        out_lines = [
            ln for ln in text.splitlines()
            if ln.strip() != _MECHANICAL_BASELINE_STAMP
        ]
        return "\n".join(out_lines)

    if not to_append:
        # Nothing to map, but still clear any surviving stamp.
        for fpath in (hyp_path, map_path):
            if not fpath.exists():
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if _MECHANICAL_BASELINE_STAMP in text:
                fpath.write_text(_strip_stamp(text).rstrip("\n") + "\n", encoding="utf-8")
        return []

    # Allocate fresh H-N hypothesis IDs continuing the existing sequence.
    max_h = 0
    for fpath in (hyp_path, map_path):
        if not fpath.exists():
            continue
        try:
            ftext = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in re.finditer(r"\bH-(\d+)\b", ftext):
            try:
                max_h = max(max_h, int(m.group(1)))
            except ValueError:
                continue

    note = "Mechanically appended unmapped depth finding; chain composition runs downstream."
    new_hyp_rows: list[str] = []
    new_map_rows: list[str] = []
    next_h = max_h
    for entry in to_append:
        next_h += 1
        hid = f"H-{next_h}"
        new_hyp_rows.append(
            f"| {hid} | {entry['severity']} | {entry['title']} | "
            f"{entry['id']} | {entry['location']} | {note} |"
        )
        new_map_rows.append(
            f"| {entry['id']} | {hid} | AUTO_MAPPED_DEPTH | {note} |"
        )

    def _append_rows(fpath: Path, rows: list[str]) -> None:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace") if fpath.exists() else ""
        except Exception:
            text = ""
        text = _strip_stamp(text)
        body = text.rstrip("\n")
        if body:
            body += "\n"
        body += "\n".join(rows) + "\n"
        fpath.write_text(body, encoding="utf-8")

    _append_rows(hyp_path, new_hyp_rows)
    _append_rows(map_path, new_map_rows)

    return [entry["id"] for entry in to_append]


def _generate_chain_baseline_regroup_retry_hint(issues: list[str]) -> str:
    """Produce a chain-phase retry hint when grouping was skipped.

    DEPRECATED for the chain phase: the baseline-regroup gate now repairs inline
    via `_auto_map_unmapped_depth_findings` instead of retrying Chain Agent 1, so
    this hint is no longer written on the chain phase. Retained because existing
    tests reference it and to keep the retry-hint contract intact for any future
    caller.

    Read at attempt 2 by build_phase_prompt and prepended to the Chain Agent 1
    prompt so it re-runs PHASE 1 grouping + PHASE 0 enabler enumeration.
    """
    if not issues:
        return ""
    lines = [
        "## ATTEMPT 2 RETRY — CHAIN GROUPING WAS SKIPPED",
        "",
        "You exited the chain phase while the driver scaffold was still in "
        "place. The MECHANICAL_BASELINE files are NOT completed work. You MUST:",
        "",
        "1. Read chain_summaries_compact.md and every depth_*_findings.md.",
        "2. Perform PHASE 1 grouping + PHASE 0 enabler enumeration.",
        "3. OVERWRITE hypotheses.md, finding_mapping.md, enabler_results.md "
        "removing the `**Status**: MECHANICAL_BASELINE` stamp.",
        "4. Ensure EVERY depth finding ID below appears as a constituent in "
        "finding_mapping.md.",
        "",
        "Violations detected on attempt 1:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.append("")
    return "\n".join(lines)


def _highest_constituent_severity(meta_list: list[tuple[str, dict[str, str]]]) -> str:
    rank_to_sev = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}
    ranks = [_severity_tier(m.get("severity", "")) for _, m in meta_list]
    ranks = [r for r in ranks if r >= 0]
    if not ranks:
        return "Medium"
    return rank_to_sev.get(max(ranks), "Medium")


def _chain_hyp_prefix_for_severity(severity: str) -> str:
    sev = normalize_severity(severity)
    return {
        "Critical": "HC",
        "High": "HH",
        "Medium": "HM",
        "Low": "HL",
        "Informational": "HI",
    }.get(sev, "HM")


def _next_chain_hyp_id(prefix: str, used: set[str], counters: dict[str, int]) -> str:
    n = counters.get(prefix, 0) + 1
    while f"{prefix}-{n:02d}" in used:
        n += 1
    counters[prefix] = n
    hid = f"{prefix}-{n:02d}"
    used.add(hid)
    return hid


def _chain_group_violates_anti_absorption(
    meta_list: list[tuple[str, dict[str, str]]],
) -> bool:
    # A group is a mechanical anti-absorption VIOLATION (-> split) ONLY when it
    # bundles constituents at genuinely DIFFERENT locations that are also
    # different bugs. Distinctness is judged on LOCATION, never on lexical
    # overlap: same-location constituents -- paraphrase duplicates with divergent
    # prose, and the same bug labeled at adjacent severities -- are ONE finding
    # and must never be split. (The prior prose-Jaccard trigger fired on
    # same-location paraphrases generated fresh each run and shattered single
    # root bugs into many findings: 53 chain hypotheses -> 140, 2 -> 6 Criticals.)
    if len(meta_list) < 2:
        return False
    loc_keys = [
        (
            _extract_file_name(m.get("location", "")).lower(),
            _normalize_locus_function(m.get("location", "")),
        )
        for _, m in meta_list
    ]
    if len({k for k in loc_keys if k[0] or k[1]}) <= 1:
        return False  # a single locus -> one bug -> never split
    # >= 2 distinct loci: a distinctness signal counts ONLY between constituents
    # at DIFFERENT loci (never between same-locus prose paraphrases).
    #   (b) a severity span > 1 tier across distinct loci (obscures a real gap);
    #   (c) unrelated root cause across distinct loci (token Jaccard < 0.30).
    for i in range(len(meta_list)):
        ki = loc_keys[i]
        if not (ki[0] or ki[1]):
            continue
        ti = _severity_tier(meta_list[i][1].get("severity", ""))
        rci = meta_list[i][1].get("root_cause") or meta_list[i][1].get("title", "")
        for j in range(i + 1, len(meta_list)):
            kj = loc_keys[j]
            if ki == kj or not (kj[0] or kj[1]):
                continue  # same locus (or unknown) -> not a distinctness signal
            tj = _severity_tier(meta_list[j][1].get("severity", ""))
            if ti >= 0 and tj >= 0 and abs(ti - tj) > 1:
                return True
            rcj = meta_list[j][1].get("root_cause") or meta_list[j][1].get("title", "")
            if _jaccard_token_similarity(rci, rcj) < 0.30:
                return True
    return False


def _hypothesis_override_present(hyp_text: str, hyp_id: str) -> bool:
    if not hyp_text:
        return False
    block_pat = re.compile(
        rf"(?:^|\n)[^\n]*\b{re.escape(hyp_id)}\b[^\n]*\n",
        re.IGNORECASE,
    )
    for match in block_pat.finditer(hyp_text):
        start = match.start()
        end = min(start + 2000, len(hyp_text))
        snippet = hyp_text[start:end].lower()
        if any(kw in snippet for kw in _NICHE_AGENT_AAB_KEYWORD_GUARD):
            return True
    return False


_LINE_REF_TOKEN_RE = re.compile(r"^[Ll]?\d+$")


def _normalize_locus_function(location: str) -> str:
    """Best-effort function token for exact-locus sub-cluster keying.

    Reuses `_extract_function_name` on the STRUCTURED Location field ONLY, then
    discards line-reference-shaped tokens (`L671`, `671`) that the extractor can
    mistake for a function name — a line ref is never a function and would
    otherwise fragment an exact locus. The root-cause / description prose is
    deliberately NOT consulted: free text routinely places a common word before
    a parenthesis (`... non-20-byte wallets (Solana ...)`, `... reordered L20
    (delete)`), which `_extract_function_name` would return as a bogus function
    and shatter same-fix mirror-contract clusters into singletons. Returns ""
    when no real function token is identifiable — findings at the same
    file + severity tier then correctly cluster together.
    """
    fn = _extract_function_name(location or "")
    if fn and _LINE_REF_TOKEN_RE.match(fn):
        fn = ""
    return fn.lower()


def _partition_into_subclusters(
    meta_list: list[tuple[str, dict[str, str]]],
) -> list[list[tuple[str, dict[str, str]]]]:
    """Partition constituents into MAXIMAL sub-clusters (Fix 5).

    Key = EXACT normalized (file, function) — tier is NOT keyed. This is a strict
    equality partition — NEVER fuzzy union-find — so it cannot transitively
    over-merge: two constituents merge only when they share the identical locus.
    Constituents at the same exact fix site stay ONE hypothesis regardless of the
    severity each was labeled with (same fix = one finding, per report-template's
    "same fix, not same file" consolidation rule; severity inherited as the
    highest); genuinely-unshared loci fall out as singletons. Order-preserving
    (first-seen key order) for deterministic IDs.
    """
    # Key = EXACT normalized (file, function). Severity tier is deliberately NOT
    # in the key: the SAME bug labeled at two tiers (e.g. a public function
    # reported once High, once Medium) must merge into ONE hypothesis (severity
    # inherited as the highest), not fragment across tier boundaries.
    buckets: dict[tuple[str, str], list[tuple[str, dict[str, str]]]] = {}
    order: list[tuple[str, str]] = []
    for cid, m in meta_list:
        key = (
            _extract_file_name(m.get("location", "")).lower(),
            _normalize_locus_function(m.get("location", "")),
        )
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append((cid, m))
    return [buckets[k] for k in order]


def _build_merged_group(
    hyp_id: str,
    sub: list[tuple[str, dict[str, str]]],
    reason: str,
) -> dict[str, object]:
    """Assemble ONE hypothesis row for a sub-cluster, retaining every source_id.

    The primary member's title heads the row; every other member's title is
    carried as a merged-angle description bullet (mirrors the C-01 "distinct
    angles preserved" pattern) so no constituent framing is lost. If members
    carry differing downstream verdicts (verdict field is absent at chain time,
    so this is inert here but correct if ever populated), the merged row keeps
    them together and surfaces the contested members as an `[UNRESOLVED]`
    sub-note rather than splitting one bug into diverging verify passes.
    """
    sev = _highest_constituent_severity(sub)
    titles = [(m.get("title") or cid).replace("|", "/") for cid, m in sub]
    title = titles[0] if titles else hyp_id
    extra = [t for t in titles[1:] if t]
    if extra:
        title = f"{title} [+ merged angles: {'; '.join(extra)}]"
    verdicts = {(m.get("verdict") or "").strip().upper() for _, m in sub}
    verdicts.discard("")
    if len(verdicts) > 1:
        contested = [cid for cid, m in sub if (m.get("verdict") or "").strip()]
        title = f"{title} [UNRESOLVED: contested members {', '.join(contested)}]"
    return {
        "id": hyp_id,
        "severity": sev,
        "title": title,
        "source_ids": [cid for cid, _ in sub],
        "reason": reason,
    }


def _repair_chain_anti_absorption_splits(scratchpad: Path) -> int:
    """Mechanically resolve over-absorbed chain hypotheses via sub-clustering.

    The safe repair for an anti-absorption failure is never another merge and
    never a per-constituent explosion. When a multi-constituent hypothesis
    violates the (post-Fix-6) rule and lacks an explicit override, partition it
    into maximal sub-clusters keyed on EXACT (file, function) + severity tier
    (Fix 5): emit ONE hypothesis per sub-cluster carrying ALL of its source_ids,
    with singletons only for truly-unshared loci. This resolves a severity-span
    violation by tier and keeps same-locus clusters intact instead of atomizing
    them, preserving every source finding without spending a retry.
    """
    try:
        from plamen_parsers import _parse_hypothesis_constituents
    except Exception:
        return 0

    inventory = _parse_inventory_finding_meta(scratchpad)
    if not inventory:
        return 0
    mapping = _parse_hypothesis_constituents(scratchpad)
    if not mapping:
        return 0
    hyp_path = scratchpad / "hypotheses.md"
    try:
        hyp_text = hyp_path.read_text(encoding="utf-8", errors="replace") if hyp_path.exists() else ""
    except Exception:
        hyp_text = ""

    used: set[str] = set(mapping)
    counters: dict[str, int] = {}
    for hid in used:
        m = re.match(r"^([A-Z]+)-(\d+)$", hid)
        if m:
            counters[m.group(1)] = max(counters.get(m.group(1), 0), int(m.group(2)))

    repaired_rows: list[dict[str, str]] = []
    final_groups: list[dict[str, object]] = []
    split_count = 0

    for hyp_id in sorted(mapping):
        constituent_ids = list(dict.fromkeys(cid for cid in mapping[hyp_id] if cid in inventory))
        meta_list = [(cid, inventory[cid]) for cid in constituent_ids]
        violates = (
            len(meta_list) >= 2
            and not _hypothesis_override_present(hyp_text, hyp_id)
            and _chain_group_violates_anti_absorption(meta_list)
        )
        if violates:
            subclusters = _partition_into_subclusters(meta_list)
            if len(subclusters) <= 1:
                # All constituents share one exact locus + tier -> same fix
                # site -> keep merged under the original id; nothing to split.
                final_groups.append(_build_merged_group(
                    hyp_id, meta_list, "preserved same-locus cluster"
                ))
                continue
            split_count += 1
            # Retire the over-absorbed id; every sub-cluster is emitted as a
            # freshly-minted, correctly-scoped hypothesis carrying ALL of its
            # own source_ids (never a per-constituent singleton unless the
            # constituent is truly unshared).
            used.discard(hyp_id)
            for sub in subclusters:
                sev0 = _highest_constituent_severity(sub)
                prefix = _chain_hyp_prefix_for_severity(sev0)
                target_id = _next_chain_hyp_id(prefix, used, counters)
                for cid, _ in sub:
                    repaired_rows.append({
                        "old": hyp_id,
                        "new": target_id,
                        "source": cid,
                        "reason": "distinct exact locus (file+function+severity tier)",
                    })
                final_groups.append(_build_merged_group(
                    target_id, sub, "MECHANICAL_ANTI_ABSORPTION_SUBCLUSTER"
                ))
            continue
        if meta_list:
            final_groups.append(_build_merged_group(
                hyp_id, meta_list, "preserved original chain grouping"
            ))

    if not repaired_rows:
        return 0

    hyp_lines = [
        "# Hypotheses",
        "",
        "Driver-repaired chain hypotheses. Over-absorbed groups that violated "
        "anti-absorption were split mechanically to preserve every source "
        "finding and avoid retry-cost loops.",
        "",
        "| Hypothesis ID | Severity | Title | Source Findings | Reason |",
        "|---------------|----------|-------|-----------------|--------|",
    ]
    map_lines = [
        "# Finding Mapping",
        "",
        "| Finding ID | Hypothesis ID | Mapping Status |",
        "|------------|---------------|----------------|",
    ]
    for group in final_groups:
        hid = str(group["id"])
        sources = [str(x) for x in group.get("source_ids", [])]
        hyp_lines.append(
            f"| {hid} | {group['severity']} | {group['title']} | "
            f"{', '.join(sources)} | {group['reason']} |"
        )
        for cid in sources:
            map_lines.append(f"| {cid} | {hid} | {group['reason']} |")
    hyp_lines.append("")
    map_lines.append("")

    try:
        (scratchpad / "hypotheses.md").write_text("\n".join(hyp_lines), encoding="utf-8")
        (scratchpad / "finding_mapping.md").write_text("\n".join(map_lines), encoding="utf-8")
        receipt_lines = [
            "# Anti-Absorption Mechanical Repair",
            "",
            f"**Split groups**: {split_count}",
            f"**Reassigned findings**: {len(repaired_rows)}",
            "",
            "| Old Hypothesis | New Hypothesis | Source Finding | Reason |",
            "|----------------|----------------|----------------|--------|",
        ]
        for row in repaired_rows:
            receipt_lines.append(
                f"| {row['old']} | {row['new']} | {row['source']} | {row['reason']} |"
            )
        receipt_lines.append("")
        (scratchpad / "anti_absorption_repair.md").write_text(
            "\n".join(receipt_lines), encoding="utf-8"
        )
        try:
            from plamen_parsers import id_ledger_register
            titles_by_id = {
                str(group["id"]): str(group.get("title") or group["id"])
                for group in final_groups
                if str(group.get("reason") or "")
                == "MECHANICAL_ANTI_ABSORPTION_SUBCLUSTER"
            }
            for row in repaired_rows:
                new_id = str(row.get("new") or "").strip()
                if not new_id:
                    continue
                id_ledger_register(
                    scratchpad,
                    finding_id=new_id,
                    owner_phase="chain",
                    owner_attempt=1,
                    owning_artifact="hypotheses.md",
                    title=titles_by_id.get(new_id, new_id),
                )
        except Exception:
            pass
    except OSError:
        return 0
    return len(repaired_rows)


def _generate_anti_absorption_retry_hint(issues: list[str]) -> str:
    """Produce a chain-phase retry hint text describing each violation.

    Read at attempt 2 by build_phase_prompt and prepended to the Chain
    Agent 1 prompt so the agent can split the offending groups.
    """
    if not issues:
        return ""
    lines = [
        "## ATTEMPT 2 RETRY — ANTI-ABSORPTION VIOLATIONS",
        "",
        "Chain Agent 1 attempt 1 grouped findings into hypotheses that violate "
        "the anti-absorption rule (`phase4c-chain-prompt.md` PHASE 1 rule 6). "
        "You MUST split the offending hypotheses below into separate "
        "hypotheses, one per distinct root cause / fix.",
        "",
        "Anti-absorption rule recap:",
        "- Constituents in the same hypothesis must share file AND function",
        "- Severity tier span must be <= 1 (a Medium and a High cannot share a "
        "Medium hypothesis)",
        "- Pairwise root-cause token Jaccard similarity must be >= 0.30 "
        "(metric: `|A ∩ B| / |A ∪ B|` on lowercased word tokens). "
        "Any pair below 0.30 -> SPLIT into separate hypotheses.",
        "",
        "If you believe a violation is intentional (e.g., two findings are "
        "redundant detections of the same single bug by different agents and "
        "TRULY require the same fix), add the following line in the "
        "hypothesis body to override:",
        "",
        "    Anti-absorption override: <one-sentence reason>",
        "",
        "Without an explicit override, the violations below MUST be resolved "
        "by splitting:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "When splitting: keep the constituent IDs intact, produce N "
        "separate GRP-* IDs with the same severity inheritance rule "
        "(group inherits highest constituent severity).",
        "",
    ])
    return "\n".join(lines)


def _parse_inventory_finding_meta_tolerant(
    scratchpad: Path,
) -> dict[str, dict[str, str]]:
    """Like _parse_inventory_finding_meta but accepts single-letter report IDs.

    Chain constituents are referenced with both internal (INV-*) and
    report-style (M-07/H-08) IDs. The base parser only matches 2-6 letter
    prefixes; this variant matches 1-6 letter prefixes so the chain
    self-restatement gate can resolve M-/H-/L- constituents in fixtures and
    in post-promotion inventories.
    """
    inventory_path = scratchpad / "findings_inventory.md"
    if not inventory_path.exists():
        return {}
    try:
        text = inventory_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    # Collapsed onto the shared block-meta extractor (prefix_min=1 accepts the
    # single-letter report IDs M-/H-/L-). The previous near-duplicate body is
    # gone — one extractor path, table-cell tolerant.
    return _parse_inventory_finding_meta_blocks(text, prefix_min=1)


def _validate_chain_self_restatement(scratchpad: Path, mode: str) -> list[str]:
    """HARD-with-retry gate against UNDER-merging (chain self-restatement).

    The mirror of `_validate_chain_anti_absorption` (which guards OVER-merging).
    A chain hypothesis is a self-restatement — an inflated duplicate of a single
    constituent re-emitted at a higher tier — when it:

      (a) resolves to exactly ONE distinct constituent; OR
      (b) has two constituents A and B that share file AND function AND have
          root-cause Jaccard similarity >= 0.50 (same-bug restatement);

      AND the chain's machine-parseable line lacks a justified severity upgrade
      (`Severity-Upgrade-Justified: NO`, or the line is absent, or
      `Combined-Impact` is empty/NONE).

    A chain that carries `Severity-Upgrade-Justified: YES` with a non-empty
    concrete `Combined-Impact` is a GENUINE compound finding and is NEVER
    flagged (recall-safety: a real distinct compound finding is preserved).

    Returns issue strings. Caller emits a retry hint (hard cap 1 retry) then
    proceeds — STEP 3 collapse + STEP 4 report carve-out are the safety nets.
    """
    try:
        from plamen_parsers import (
            _parse_chain_constituents,
            _chain_severity_upgrade_justified,
            _CHAIN_HYP_HEADING_RE,
        )
        from plamen_parsers import _llm_norm as _pp_llm_norm
    except Exception:
        return []

    if mode not in ("core", "thorough"):
        return []
    # Tolerant inventory meta: chain constituents are referenced with both
    # internal (INV-*) and report-style (M-07/H-08) IDs. The shared
    # _parse_inventory_finding_meta only recognizes 2-6 letter prefixes, so we
    # parse with a prefix-tolerant regex here (single-letter report IDs too).
    inventory = _parse_inventory_finding_meta_tolerant(scratchpad)
    # Note: do NOT early-return on empty inventory — case (a) (single
    # constituent) only needs the chain parser, not inventory metadata.

    chain_path = scratchpad / "chain_hypotheses.md"
    if not chain_path.exists():
        return []
    try:
        text = _pp_llm_norm(chain_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []

    # Build {chain_id: section_text} for justification lookup.
    sections: dict[str, str] = {}
    headings = list(_CHAIN_HYP_HEADING_RE.finditer(text))
    for i, hm in enumerate(headings):
        cid = hm.group(1).upper()
        start = hm.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        sections[cid] = text[start:end]

    # _parse_chain_constituents already EXCLUDES justified chains; to catch a
    # 1-constituent restatement that an over-eager agent marked YES *without*
    # an impact, we re-parse anchors directly here for completeness.
    issues: list[str] = []
    for chain_id, section in sections.items():
        # Skip genuine compound findings (justified + concrete impact).
        if _chain_severity_upgrade_justified(section):
            continue

        # Resolve constituent IDs from this chain's anchors/machine line.
        single = _parse_chain_constituents(scratchpad).get(chain_id, [])
        # _parse_chain_constituents drops justified chains; for unjustified
        # ones it returns the constituent list. Resolve metadata.
        meta_list = [
            (cid, inventory[cid]) for cid in single if cid in inventory
        ]

        if not single:
            # Could not resolve any constituent — nothing to assert.
            continue

        # (a) exactly one distinct constituent → restatement
        distinct_ids = {cid for cid in single}
        if len(distinct_ids) == 1:
            issues.append(
                f"{chain_id} has a single constituent "
                f"({next(iter(distinct_ids))}) and no Combined-Impact "
                f"justification — chain restates one finding at a higher tier"
            )
            continue

        # (b) two constituents, same file+function, high root-cause overlap
        if len(meta_list) >= 2:
            file_func_pairs = set()
            rcs = []
            for cid, m in meta_list:
                f = _extract_file_name(m.get("location", ""))
                fn = (
                    _extract_function_name(m.get("location", ""))
                    or _extract_function_name(m.get("root_cause", ""))
                )
                file_func_pairs.add((f.lower(), fn.lower()))
                rcs.append(m.get("root_cause") or m.get("title", ""))
            file_func_pairs.discard(("", ""))
            same_func = len(file_func_pairs) == 1
            rc_max_sim = 0.0
            for i in range(len(rcs)):
                for j in range(i + 1, len(rcs)):
                    sim = _jaccard_token_similarity(rcs[i], rcs[j])
                    if sim > rc_max_sim:
                        rc_max_sim = sim
            if same_func and rc_max_sim >= 0.50:
                ff = next(iter(file_func_pairs))
                issues.append(
                    f"{chain_id} constituents "
                    f"({', '.join(cid for cid, _ in meta_list)}) share "
                    f"{ff[0] or '?'}:{ff[1] or '?'} with root-cause Jaccard "
                    f"{rc_max_sim:.2f} >= 0.50 and no Combined-Impact "
                    f"justification — chain restates a single bug"
                )
    return issues


def _generate_chain_self_restatement_retry_hint(issues: list[str]) -> str:
    """Retry hint for chain self-restatement (under-merge) violations.

    Read at attempt 2 and prepended to the Chain Agent 2 prompt.
    """
    if not issues:
        return ""
    lines = [
        "## ATTEMPT 2 RETRY — CHAIN SELF-RESTATEMENT VIOLATIONS",
        "",
        "Chain Agent 2 attempt 1 emitted chain hypotheses that merely RESTATE "
        "a single constituent finding at a higher severity tier "
        "(`phase4c-chain-prompt.md` Chain Self-Containment Guard). A chain is "
        "NOT a new finding when it is satisfiable by one constituent alone, or "
        "when both constituents resolve to the same bug (same file+function, "
        "high root-cause overlap).",
        "",
        "For EACH violation below you MUST do ONE of:",
        "1. DROP the chain hypothesis and record it in "
        "`composition_coverage.md` as `Result=SELF-CONTAINED`, leaving the "
        "constituent at its original severity; OR",
        "2. Supply an explicit Combined-Impact Justification — a concrete "
        "loss/privilege/liveness consequence that NEITHER constituent produces "
        "alone, quantified per Rule 10 — and set the machine-parseable line to "
        "`Severity-Upgrade-Justified: YES | Combined-Impact: <concrete one-line>`.",
        "",
        "Violations:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.append("")
    return "\n".join(lines)


def _validate_invariants_pass2(scratchpad: Path, mode: str) -> list[str]:
    """SOFT validator for Phase 4a.5 Pass 2 (Recursive Semantic Gap Trace).

    Pass 2 appends a `## Pass 2: Recursive Trace Results` section to the
    existing `semantic_invariants.md` (written by Pass 1). This validator
    confirms the append happened. It NEVER returns hard issues — Pass 2 is
    an enrichment phase. Missing output → log warning, mark degraded
    sentinel, RETURN EMPTY LIST so the pipeline proceeds.

    Phase mode-gating: scheduler only spawns this in Thorough. Defensive
    early-exit handles Core/Light callers gracefully.
    """
    if mode != "thorough":
        return []
    inv_path = scratchpad / "semantic_invariants.md"
    if not inv_path.exists():
        # Pass 1 itself didn't produce output — separate failure mode, not
        # ours to flag. Return empty.
        return []
    try:
        text = inv_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    # Pass 2 header — tolerant of shape (## vs ### vs ####, bold, leading ws,
    # trailing qualifiers). The agent never writes this identically twice.
    _PASS2_HEADER = r"(?im)^\s{0,3}(?:#{1,4}\s*)?\*{0,3}\s*pass\s*2\b"
    if re.search(_PASS2_HEADER, text):
        # Single source of truth (FIX): gate the advisory on the REAL depth
        # trigger, not a local stricter parser. The prior `_FLAG_TOKEN` regex
        # (`flag [:=] -?\d`, needs >=2) DIFFERED from the actual niche trigger
        # `_semantic_gap_required` — which also counts CONFIRMED gap TOKENS
        # (SYNC_GAP / ACCUMULATION_EXPOSURE / CONDITIONAL(_WRITE) / CLUSTER_GAP)
        # and table cells. That mismatch produced false alarms ("1/4, may not
        # fire") on runs where the niche actually fired 4/4. `_semantic_gap_
        # required` reads the same post-Pass-2 semantic_invariants.md the depth
        # phase evaluates, so the advisory can never disagree with whether
        # SEMANTIC_GAP_INVESTIGATOR fires. Warn ONLY when it genuinely won't.
        if not _semantic_gap_required(scratchpad):
            import logging as _logging
            _logging.getLogger("plamen.validators").warning(
                "[invariants_p2] Pass 2 section present but no semantic-gap "
                "flags/tokens in semantic_invariants.md; "
                "SEMANTIC_GAP_INVESTIGATOR will not fire. Continuing — Pass 1 "
                "data alone is sufficient for depth."
            )
        return []
    # Pass 2 didn't append a section. Soft-degrade sentinel; don't halt.
    try:
        (scratchpad / "invariants_p2.degraded").write_text(
            "[INVARIANTS_P2_DEGRADED] No `## Pass 2:` section appended "
            "to semantic_invariants.md. Pipeline continues with Pass 1 "
            "data only; depth agents will not have CONFIRMED_GAP / "
            "BRANCH_ASYMMETRY / DIRECTIONAL_PAIRING_GAP flags.\n",
            encoding="utf-8",
        )
    except OSError:
        pass
    import logging as _logging
    _logging.getLogger("plamen.validators").warning(
        "[invariants_p2] no Pass 2 section appended — sentinel written, "
        "pipeline continues"
    )
    return []


def _validate_attention_repair(
    scratchpad: Path, mode: str,
) -> tuple[list[str], list[str]]:
    """Returns ``(hard, soft)`` — hard issues block; soft are warnings."""
    if mode != "thorough":
        return [], []
    queue = scratchpad / "attention_repair_queue.md"
    if not queue.exists():
        return [], []
    try:
        qtext = queue.read_text(encoding="utf-8", errors="replace")
    except Exception:
        qtext = ""
    queued_rows = [ln for ln in qtext.splitlines() if re.match(r"^\|\s*\d+\s*\|", ln)]
    if not queued_rows:
        return [], []
    summary = scratchpad / "attention_repair_summary.md"
    if not summary.exists() or summary.stat().st_size < 100:
        return ["attention_repair_summary.md missing or stub despite queued repair items"], []
    summary_outputs: list[str] = []
    rowshard_outputs: list[str] = []
    for name in ("attention_repair_summary.md", "attention_repair_findings.md"):
        p = scratchpad / name
        if p.exists():
            try:
                summary_outputs.append(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
    for p in sorted(scratchpad.glob("attention_repair_rows_*.md")):
        try:
            rowshard_outputs.append(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    blob = "\n".join(summary_outputs + rowshard_outputs)
    summary_blob = "\n".join(summary_outputs)
    rowshard_blob = "\n".join(rowshard_outputs)
    soft: list[str] = []
    verdict_words = (
        r"SAFE|COVERED|ALREADY_COVERED|REVIEWED|CLOSED|MERGED|DUPLICATE|"
        r"CONFIRMED|FINDING|EXPLOITABLE|FALSE_POSITIVE|NO_FINDING|NO_ISSUE|"
        r"NOT_EXPLOITABLE|NEEDS_HUMAN|UNREACHABLE|NOT_APPLICABLE|UNRESOLVED"
    )
    if not re.search(r"(?i)\bverdict\b", blob) or not re.search(rf"\b({verdict_words})\b", blob, re.I):
        soft.append("attention repair output lacks per-item verdicts")
    allowed_verdict_re = re.compile(
        rf"\b({verdict_words})\b",
        re.IGNORECASE,
    )

    def _parse_attention_row_no(raw: str) -> int | None:
        m = re.search(r"\b(?:queue\s*)?(?:row\s*)?#?\s*(\d+)\b", str(raw or ""), re.IGNORECASE)
        if not m:
            return None
        try:
            return int(m.group(1))
        except ValueError:
            return None

    summary_receipts: set[int] = set()
    receipt_context: dict[int, str] = {}
    for line in summary_blob.splitlines():
        s = line.strip()
        # Table row: | N | VERDICT | ... |, also accepts | Row 1 | / | #1 |.
        if s.startswith("|"):
            cells = [c.strip().strip("`") for c in s.strip("|").split("|")]
            row_no = _parse_attention_row_no(cells[0] if cells else "")
            if row_no is not None and len(cells) >= 2 and any(allowed_verdict_re.search(c) for c in cells[1:]):
                summary_receipts.add(row_no)
                receipt_context[row_no] = " | ".join(cells[3:] if len(cells) >= 4 else cells[1:])
            continue
        # Bullet fallback: - N: VERDICT ..., * Row N. VERDICT ..., - #N VERDICT ...
        bm = re.match(r"^[-*]\s*((?:queue\s*)?(?:row\s*)?#?\s*\d+)\s*[:.)-]?\s*(.+)$", s, re.I)
        if bm and allowed_verdict_re.search(bm.group(2)):
            row_no = _parse_attention_row_no(bm.group(1))
            if row_no is not None:
                summary_receipts.add(row_no)
                receipt_context[row_no] = bm.group(2)
    queue_numbers: list[int] = []
    queued_paths: list[str] = []
    for line in qtext.splitlines():
        s = line.strip()
        if not re.match(r"^\|\s*\d+\s*\|", s):
            continue
        cells = [c.strip().strip("`") for c in s.strip("|").split("|")]
        if len(cells) < 3:
            continue
        row_no: int | None = None
        try:
            row_no = int(cells[0])
            queue_numbers.append(row_no)
        except ValueError:
            pass
        kind = cells[1].lower()
        if any(token in kind for token in ("uncited", "notread", "file", "path")):
            for cell in (cells[2], cells[-1]):
                for p in _extract_gap_paths_from_markdown(cell):
                    if p not in queued_paths:
                        queued_paths.append(p)
    missing_receipts = [n for n in queue_numbers if n not in summary_receipts]
    if missing_receipts:
        return [
            "attention repair summary missing queue receipt row(s): "
            + ", ".join(str(n) for n in missing_receipts[:12])
        ], soft

    def _attention_path_cited(path: str) -> bool:
        norm_path = _norm_loc(path)
        norm_full = _norm_loc(blob)
        norm_rowshard = _norm_loc(rowshard_blob)
        if norm_path and norm_path in norm_full:
            return True
        # Queue rows can contain host/user prefixes while agent outputs cite
        # repo-relative paths. Match on the security-relevant suffix, not on
        # the absolute prefix.
        for marker in ("/crates/", "/src/", "/contracts/", "/programs/"):
            if marker in norm_path:
                suffix = norm_path[norm_path.index(marker) + 1:]
                if suffix and suffix in norm_full:
                    return True
        basename = Path(norm_path).name
        if not basename:
            return False
        # Closes F-INV-04 (laundering): when the queued path is multi-segment
        # AND the basename appears ONLY in summary/findings (not in a
        # structured row-shard table), require at least a 2-segment match.
        # Row-shard files (`attention_repair_rows_*.md`) are tabular per-row
        # review and are allowed lenient basename match by design (A3 test).
        if "/" in norm_path and basename in norm_rowshard:
            return True  # row-shard lenient
        if "/" in norm_path:
            parent = norm_path.rsplit("/", 1)[0].rsplit("/", 1)[-1]
            two_seg = f"{parent}/{basename}" if parent else basename
            return bool(two_seg and two_seg in norm_full)
        return basename in norm_full

    missing_paths = [p for p in queued_paths if not _attention_path_cited(p)]
    if missing_paths:
        return [
            "attention repair did not cite queued path(s): "
            + ", ".join(missing_paths[:8])
        ], soft

    return [], soft


def _validate_cited_paths_in_verify(
    scratchpad: Path,
    project_root: str | None = None,
) -> list[str]:
    """Path-existence gate. Bucket C of v2.2.2 post-mortem.

    For each verify_*.md file, harvest the **Location**: cited path and
    check whether it resolves against:
      (a) the SCIP-indexed file set (preferred), OR
      (b) basename-only match against indexed files (lenient fallback), OR
      (c) filesystem existence under the project/repo root.

    SCIP coverage is frequently incomplete (e.g. rust-analyzer scip may
    skip some crates), so a path absent from the SCIP map is NOT proof of
    hallucination. A cited path that resolves to a real file on disk is
    treated as RESOLVED. Only paths absent from BOTH the SCIP map AND the
    filesystem are genuine hallucinations and stay flagged.

    Findings whose path resolves to NEITHER are flagged for the report
    pipeline as `[PATH-UNRESOLVED]`. Soft v2.3.0 — informational only.

    Returns a list of issue strings. Empty = all paths resolve OR no
    SCIP index exists to validate against.
    """
    indexed = _collect_scip_indexed_paths(scratchpad)
    if not indexed:
        return []  # No SCIP → can't validate
    indexed_basenames = _basenames(indexed)

    # Candidate roots for filesystem-existence fallback. Cited paths are
    # repo-relative (e.g. "crates/p2p/src/gossip_service.rs"), so resolve
    # against the project_root the SCIP index was built from, plus a couple
    # of adjacent roots in case the build root differs from project_root.
    fs_roots: list[Path] = []
    if project_root:
        try:
            pr = Path(project_root)
            fs_roots.append(pr)
            fs_roots.append(pr.parent)
        except Exception:
            pass

    def _exists_on_disk(rel_path: str) -> bool:
        if not fs_roots:
            return False
        rel = rel_path.lstrip("/")
        for root in fs_roots:
            try:
                if (root / rel).exists():
                    return True
            except Exception:
                continue
        return False

    location_re = re.compile(
        r"^\s*(?:-\s+)?\*\*Location\*\*\s*:?\s*`?([^\n`]+?)`?\s*$",
        re.MULTILINE | re.IGNORECASE,
    )
    path_with_line_re = re.compile(
        r"^([a-zA-Z0-9_./\-]+\."
        r"(?:rs|go|sol|move|py|c|cpp|cc|h|hpp|java|ts|js))"
        r"(?::L?\d+(?:[-:]\d+)?)?$"
    )

    unresolved: list[tuple[str, str]] = []  # (verify_file, cited_path)
    checked = 0
    for f in sorted(scratchpad.glob("verify_*.md")):
        if f.name in {"verify_core.md", "verify_core_full.md"}:
            continue
        if "skeptic" in f.name or "judge" in f.name:
            continue
        if f.name.endswith(_RETRY_HINT_SUFFIX):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in location_re.finditer(text):
            cell = m.group(1).strip()
            # Strip line-number suffix for path-only check.
            pm = path_with_line_re.match(cell)
            if not pm:
                continue
            path = pm.group(1)
            # Verifier outputs may cite generated PoC/test/harness files in
            # Execution Result or Error Trace sections. Those paths are
            # evidence artifacts, not audited production locations, and they
            # are often absent from SCIP repo_map because they were created
            # during verification. Do not let them halt a verifier shard.
            if _is_spec_support_path(path):
                continue
            checked += 1
            bn = path.rsplit("/", 1)[-1]
            if path in indexed or bn in indexed_basenames:
                continue
            # SCIP miss is not proof of hallucination — SCIP coverage is
            # often partial. Fall back to filesystem existence under the
            # project/repo root before flagging as unresolved.
            if _exists_on_disk(path):
                continue
            unresolved.append((f.name, path))

    if not unresolved:
        try:
            (scratchpad / "path_unresolved.md").unlink(missing_ok=True)
        except Exception:
            pass
        return []
    sample = "; ".join(
        f"{vf}->{p}" for vf, p in unresolved[:3]
    )
    more = f" (+{len(unresolved)-3} more)" if len(unresolved) > 3 else ""
    # Persist for downstream consumption (Index Agent / report pipeline).
    out = scratchpad / "path_unresolved.md"
    try:
        lines = [
            "# Path-Unresolved Findings (v2.3.0 SCIP experiment)",
            "",
            f"Verifier files cite paths that do NOT resolve against the "
            f"SCIP-indexed file set ({len(unresolved)} of {checked} cited "
            f"paths checked). Likely causes: path hallucination by "
            f"recon/depth/breadth, or path drift between recon-time and "
            f"verify-time. Index Agent SHOULD treat these as candidates "
            f"for FALSE_POSITIVE / DUPLICATE / location-correction-needed "
            f"rather than promoting unverified.",
            "",
            "| Verify File | Cited Path |",
            "|-------------|------------|",
        ]
        for vf, p in unresolved:
            lines.append(f"| {vf} | `{p}` |")
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass

    return [
        f"path unresolved: {len(unresolved)} verify file(s) cite paths "
        f"absent from SCIP repo_map: {sample}{more}. See path_unresolved.md."
    ]


def _synthesize_step_execution_trace(
    scratchpad: Path, role: str
) -> bool:
    """Build a deterministic step_execution_trace_{role}.md from depth findings.

    v2.3.3 — Replaces the LLM-emit-or-fail dependency with a driver-side
    projection. Reads ``depth_{role}_findings.md`` and counts evidence-tag
    occurrences. Each tag class becomes one (skill, step) row with
    ``Executed=yes`` if ≥1 tag of that class appears. The first occurrence's
    ``file:line`` (if any) goes into the Evidence cell so the ceremonial-yes
    check still passes.

    Returns True iff the role has a non-empty findings file (synthesis ran).
    """
    findings_path = scratchpad / f"depth_{role}_findings.md"
    if not findings_path.exists():
        return False
    try:
        text = findings_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    if not text.strip():
        return False

    # Count tag classes; sample one file:line per class for the Evidence cell.
    tag_counts: dict[str, int] = {}
    tag_samples: dict[str, str] = {}
    file_line_re = re.compile(
        r"([A-Za-z0-9_./\-]+\.(?:rs|go|sol|move|py|c|cpp|h|hpp|java|ts|js))"
        r":L?(\d+)"
    )
    first_file_line = None
    first_file_line_match = file_line_re.search(text)
    if first_file_line_match:
        first_file_line = (
            f"{first_file_line_match.group(1)}:L{first_file_line_match.group(2)}"
        )
    for m in _DEPTH_EVIDENCE_TAG_RE.finditer(text):
        tag = m.group(1).upper()
        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        if tag not in tag_samples:
            window = text[max(0, m.start() - 500):m.start() + 500]
            fm = file_line_re.search(window)
            if fm:
                tag_samples[tag] = f"{fm.group(1)}:L{fm.group(2)}"
            elif first_file_line:
                tag_samples[tag] = first_file_line
    finding_count = len(re.findall(r"^###\s*(?:Finding\s*)?\[", text, re.MULTILINE))

    out_path = scratchpad / f"step_execution_trace_{role}.md"
    lines = [
        f"# Step Execution Trace: {role}",
        "",
        f"> **Source**: synthesized from `depth_{role}_findings.md` "
        f"({finding_count} finding(s)) by the driver. Driver-deterministic "
        f"projection — does not depend on agent compliance with the "
        f"§STEP-TRACE directive.",
        "",
        "| Skill | Step | Executed | Evidence | Result |",
        "|-------|------|----------|----------|--------|",
    ]
    if not tag_counts:
        lines.append(
            "| (general) | depth analysis | no | - | "
            "no evidence tags in findings |"
        )
    else:
        # One row per tag class. Sorted for stable output.
        for tag in sorted(tag_counts.keys()):
            count = tag_counts[tag]
            evidence = tag_samples.get(tag) or "-"
            lines.append(
                f"| (general) | `[{tag}:*]` | yes | {evidence} | "
                f"{count} occurrence(s) |"
            )
    lines.append("")
    try:
        out_path.write_text("\n".join(lines), encoding="utf-8")
        return True
    except Exception:
        return False


def _step_trace_evidence_has_citation(ev: str) -> bool:
    """Shared step-trace evidence citation contract (sibling-sweep aligned).

    A step-trace Evidence cell satisfies the file:line contract when it carries
    ANY of the citation forms the depth agents emit across backends. This is the
    single source of truth for BOTH `_step_trace_has_ceremonial_yes` (which
    previously accepted ONLY the strict `file:L42` form and so wrongly rejected
    `file lines 42` / `file L42` / `[TRACE: ...]` traces, forcing needless
    synthesis) and the validator twin in `_ensure_step_execution_traces`. The
    accepted set is the UNION of both twins (strict superset of the old strict
    form):
      * `file.ext:L42` / `file.ext:42`            (strict colon form)
      * `file.ext, lines 42` / `file.ext lines 42`(prose "line N" form)
      * `file.ext L42`                            (space before L)
      * `<has a .ext token> AND <has a digit>`     (lenient file+line co-mention)
      * a depth/PoC evidence tag `[TRACE: ...]` etc.
      * the explicit `(general)` no-file-applicable marker
    """
    ev = (ev or "").strip()
    if not ev or ev == "-":
        return False
    return bool(
        re.search(r"[A-Za-z0-9_./\-]+\.[a-z]+:L?\d+", ev)
        or re.search(r"[A-Za-z0-9_./\-]+\.[a-z]+,?\s*lines?\s*\d+", ev, re.IGNORECASE)
        or re.search(r"[A-Za-z0-9_./\-]+\.[a-z]+\s+L\d+", ev)
        or (re.search(r"\.[a-z]+\b", ev) and re.search(r"\d+", ev))
        or re.search(
            r"\[(BOUNDARY|VARIATION|TRACE|CROSS-DOMAIN-DEP|REGRESS|"
            r"PERTURBATION|MEDUSA-PASS|POC-PASS|POC-FAIL)[:\]]",
            ev,
        )
        or ev.startswith("(general)")
    )


def _step_trace_has_ceremonial_yes(trace_path: Path) -> bool:
    """Return True when a step trace claims Executed=yes without file:line.

    Existing agent-emitted traces can be verbose and still fail the mechanical
    contract by using finding IDs (for example `DCI-7`) as evidence. In that
    case the deterministic synthesized trace is safer than preserving the
    malformed trace, because it projects file:line evidence from the actual
    depth finding body.

    Sibling-sweep (Tier C): now uses the SHARED
    `_step_trace_evidence_has_citation` contract — previously it accepted only
    the strict `file:L42` form, so a richer agent-emitted trace using
    `file lines 42` / `file L42` / `[TRACE: ...]` was wrongly judged ceremonial
    and needlessly re-synthesized (an internal inconsistency with the twin in
    `_ensure_step_execution_traces`).
    """
    try:
        text = trace_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return True
    rows = _parse_step_trace_rows(text)
    if not rows:
        return True
    for row in rows:
        if row.get("executed", "").strip().lower() != "yes":
            continue
        if not _step_trace_evidence_has_citation(row.get("evidence", "")):
            return True
    return False


def _ensure_step_execution_traces(scratchpad: Path) -> int:
    """Synthesize traces for any depth role that has findings but no
    non-trivial agent-emitted trace. Preserves richer agent-emitted traces
    only when they satisfy the non-ceremonial file:line evidence contract.

    Returns count of traces synthesized (informational only).
    """
    synthesized = 0
    for role in _expected_depth_agent_roles(scratchpad):
        trace_path = scratchpad / f"step_execution_trace_{role}.md"
        try:
            ok = (
                trace_path.exists()
                and trace_path.stat().st_size > 200
                and not _step_trace_has_ceremonial_yes(trace_path)
            )
        except Exception:
            ok = False
        if ok:
            continue
        if _synthesize_step_execution_trace(scratchpad, role):
            synthesized += 1
    return synthesized


def _check_step_execution_traces(
    scratchpad: Path, mode: str
) -> list[str]:
    """Validator: every Thorough depth agent has a step trace + non-ceremonial rows.

    v2.3.3 — Auto-synthesizes traces from depth findings BEFORE running
    checks, eliminating the agent-compliance dependency. A prior L1
    post-mortem found that agents were not emitting traces at runtime;
    the orchestrator was post-hoc reconstructing them inside the depth
    subprocess to satisfy the gate. Moving that reconstruction into the
    driver makes it deterministic and idempotent.

    Checks (Thorough only):
      1. Every depth_{role}_findings.md has a step_execution_trace_{role}.md
         (auto-synthesized if missing).
      2. Each trace contains at least one row with Executed=yes.
      3. Each "yes" row has a non-empty Evidence cell.

    Side effect: writes ``step_execution_gaps_mechanical.md`` for iter2.
    """
    if mode != "thorough":
        return []
    expected_roles = _expected_depth_agent_roles(scratchpad)
    if not expected_roles:
        return []
    # v2.3.3: synthesize-first. Eliminates LLM-emit-or-fail risk.
    _ensure_step_execution_traces(scratchpad)
    gaps, agents_with_traces = _aggregate_step_execution_gaps(scratchpad)
    issues: list[str] = []

    # Check 1: trace presence
    missing_traces = sorted(set(expected_roles) - set(agents_with_traces))
    if missing_traces:
        issues.append(
            f"step trace missing: {len(missing_traces)} depth agent(s) "
            f"emitted findings but no step_execution_trace_*.md file: "
            f"{', '.join(missing_traces[:5])}"
        )

    # Check 2: ceremonial-yes detection — yes rows without evidence
    cere_count = 0
    cere_samples: list[str] = []
    for f in sorted(scratchpad.glob(_STEP_TRACE_GLOB)):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for row in _parse_step_trace_rows(text):
            if row.get("executed", "").lower() == "yes":
                # Shared citation contract (sibling-sweep aligned with
                # _step_trace_has_ceremonial_yes): accepts strict `file:L42`,
                # comma/"line N", space-L, lenient file+digit, depth-tag, and
                # `(general)` forms. GPT and Claude cite evidence differently.
                has_citation = _step_trace_evidence_has_citation(
                    row.get("evidence", "")
                )
                if not has_citation:
                    cere_count += 1
                    if len(cere_samples) < 3:
                        cere_samples.append(
                            f"{f.name.replace('step_execution_trace_','').replace('.md','')}:"
                            f" {row.get('skill','?')}/{row.get('step','?')}"
                        )
    if cere_count:
        issues.append(
            f"step trace ceremonial: {cere_count} row(s) marked Executed=yes "
            f"without `file:line` Evidence: {'; '.join(cere_samples)}"
        )

    # Always write the mechanical gap aggregate (even when empty — clears
    # stale data between runs).
    gap_path = scratchpad / "step_execution_gaps_mechanical.md"
    try:
        if gaps:
            lines = [
                "# Step Execution Gaps (Mechanical Aggregate, v2.2.0 A.1)",
                "",
                f"Aggregated from {len(agents_with_traces)} depth-agent "
                f"step_execution_trace_*.md file(s). Each row below is a "
                f"(skill, step) where the agent reported Executed != yes.",
                "",
                "| Agent | Skill | Step | Executed | Evidence | Result |",
                "|-------|-------|------|----------|----------|--------|",
            ]
            for g in gaps:
                lines.append(
                    f"| {g['agent']} | {g['skill']} | {g['step']} | "
                    f"{g['executed']} | {g['evidence']} | {g['result']} |"
                )
            lines.append("")
            lines.append(
                "**iter2 / DA / skill-checklist directive**: Each row above "
                "is a mandatory investigation target. An agent addressing "
                "this list must EXECUTE the named step, cite `file:line` "
                "evidence, and produce one finding OR an explicit "
                "`<safe: justification>` per gap."
            )
            gap_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:
            gap_path.write_text(
                "# Step Execution Gaps (Mechanical Aggregate, v2.2.0 A.1)\n\n"
                f"All {len(agents_with_traces)} depth-agent traces report "
                f"Executed=yes for every inherited (skill, step). No gaps.\n",
                encoding="utf-8",
            )
    except Exception:
        pass

    # IMPORTANT: do NOT return an issue for "gaps present." Gaps are the
    # expected output of iter1 — iter2 consumes the gap file and closes
    # them. A hard-fail on gaps-existing would loop iter1 forever, since
    # the same agents would produce the same gaps. Only trace-missing
    # and trace-ceremonial are gate-failure conditions; trace-with-gaps
    # is the directive to the next phase.

    return issues


# --- Graph-artifact consumption gate (v2.5.0 P0) --------------------------

_GRAPH_ARTIFACT_NAMES = frozenset({
    "caller_map.md",
    "callee_map.md",
    "state_write_map.md",
    "function_summary.md",
})

# Patterns that prove the agent consumed a graph artifact — either by reading
# the file or acknowledging its unavailability.
_GRAPH_REF_PATTERNS: dict[str, re.Pattern[str]] = {
    name: re.compile(
        # Match: "caller_map.md", "Read: caller_map", "[GRAPH-ARTIFACT: UNAVAILABLE:caller_map.md]"
        rf"(?:caller_map|callee_map|state_write_map|function_summary)\.md"
        if name.startswith("caller") else
        rf"(?:caller_map|callee_map|state_write_map|function_summary)\.md",
        re.IGNORECASE,
    )
    for name in _GRAPH_ARTIFACT_NAMES
}

# Single compiled regex matching any of the 4 artifact basenames.
_GRAPH_ANY_REF_RE = re.compile(
    r"(?:caller_map|callee_map|state_write_map|function_summary)(?:\.md)?",
    re.IGNORECASE,
)

# Matches the UNAVAILABLE tag emitted per the depth template directive.
_GRAPH_UNAVAILABLE_TAG_RE = re.compile(
    r"\[GRAPH-ARTIFACT:\s*UNAVAILABLE[:\s]+"
    r"(caller_map|callee_map|state_write_map|function_summary)",
    re.IGNORECASE,
)

# Per-artifact reference regex (exact basename).
_GRAPH_PER_ARTIFACT_RE: dict[str, re.Pattern[str]] = {
    name: re.compile(
        rf"{re.escape(name.replace('.md', ''))}(?:\.md)?",
        re.IGNORECASE,
    )
    for name in _GRAPH_ARTIFACT_NAMES
}

_GRAPH_STUB_SIZE_THRESHOLD = 200  # bytes — below this the file is a stub


def _check_graph_artifact_consumption(
    scratchpad: Path, mode: str
) -> list[str]:
    """Validator: every Thorough-mode depth agent demonstrates graph-artifact reads.

    v2.5.0 P0 — Depth templates across all 5 languages contain a MANDATORY
    graph-artifact read directive. This gate mechanically verifies compliance.

    For each depth_{role}_findings.md that is substantial (>200 bytes):
      - Count distinct graph artifacts referenced (by filename mention or
        [GRAPH-ARTIFACT: UNAVAILABLE:...] tag).
      - If any produced graph artifact is not referenced → issue.

    Precondition: at least one graph artifact file must exist in the scratchpad.
    If recon did not produce any (e.g. no Slither, no grep fallback), the gate
    is vacuously satisfied — you can't consume what doesn't exist.

    Same exclusions as _check_step_execution_traces: coverage_* agents,
    iter2/iter3/da variants are exempt.
    """
    if mode != "thorough":
        return []

    # Check if any graph artifacts were produced by recon.
    graph_files_present = [
        name for name in _GRAPH_ARTIFACT_NAMES
        if (scratchpad / name).exists()
    ]
    if not graph_files_present:
        return []

    expected_roles = _expected_depth_agent_roles(scratchpad)
    if not expected_roles:
        return []

    issues: list[str] = []
    for role in expected_roles:
        findings_path = scratchpad / f"depth_{role}_findings.md"
        if not findings_path.exists():
            continue
        try:
            size = findings_path.stat().st_size
        except OSError:
            continue
        if size < _GRAPH_STUB_SIZE_THRESHOLD:
            continue

        try:
            text = findings_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Count distinct artifacts referenced.
        refs_found: set[str] = set()
        for artifact_name, pat in _GRAPH_PER_ARTIFACT_RE.items():
            if pat.search(text):
                refs_found.add(artifact_name)
        # Also check UNAVAILABLE tags.
        for m in _GRAPH_UNAVAILABLE_TAG_RE.finditer(text):
            refs_found.add(m.group(1) + ".md")

        missing_refs = sorted(set(graph_files_present) - refs_found)
        if missing_refs:
            present_str = ", ".join(sorted(refs_found)) if refs_found else "none"
            issues.append(
                f"graph-artifact consumption: depth_{role} references only "
                f"{len(refs_found)}/{len(graph_files_present)} graph artifacts "
                f"(found: {present_str}; missing: {', '.join(missing_refs)}). "
                f"MANDATORY directive requires reading every produced graph "
                f"artifact or emitting [GRAPH-ARTIFACT: UNAVAILABLE:...] tags."
            )

    return issues


# ---------------------------------------------------------------------------
# Obligation-receipt gates (Steps 5-8 of recall-recovery plan)
#
# Each mechanical artifact recon produces is treated as an obligation set.
# Every row must produce a receipt in the owning consumer phase's output
# (REPORTED / DISMISSED / CARRIED). The gates count receipts vs rows; gaps
# trigger a WARNING (first ship) — to be promoted to FAIL after one observed
# audit cycle.
# ---------------------------------------------------------------------------

_VALID_DISMISSAL_REASONS = frozenset({
    "out_of_scope", "false_positive", "informational_style",
    "environmental", "retry_budget_exhausted",
})
_VALID_DISMISSAL_PREFIXES = ("duplicate_of:", "superseded_by:")


# Receipt line:
#   [OBLIG:<artifact>:<row_id>] STATUS:<R|D|C|REPORTED|DISMISSED|CARRIED>
#   KEY:<text> -> <finding_id | reason | next_phase>
# Accepts both short (R/D/C) and long forms for STATUS.
_OBLIG_RECEIPT_RE = re.compile(
    r"\[OBLIG:(?P<artifact>[A-Za-z0-9_.\-]+):(?P<row>[^\]\s]+)\]\s+"
    r"STATUS:(?P<status>REPORTED|DISMISSED|CARRIED|R|D|C)\b"
    r"(?:[^\n]*?(?:KEY|key)[:\s]+(?P<key>[^\n→\-]*?(?=\s+(?:→|->|—|\-|$))))?"
    r"(?:[^\n]*?(?:→|->|—)\s*(?P<dest>[^\n]+))?",
    re.IGNORECASE,
)


def _parse_opengrep_row_count(scratchpad: Path) -> int:
    """Count data rows in opengrep_findings.md.

    Returns 0 if the file is missing or empty (gate vacuously satisfied).
    Data rows are markdown table rows matching `| <int> | ...` excluding
    header / separator rows.
    """
    path = scratchpad / "opengrep_findings.md"
    if not path.exists():
        return 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    # Rows look like: `| 17 | <rule> | warning | <location> | <message> |`
    rows = 0
    for line in text.splitlines():
        m = re.match(r"^\|\s*(\d+)\s*\|", line)
        if m:
            rows += 1
    return rows


# F4: also accept table-form receipts under a section heading matching
# `## ... Obligation Receipts ... opengrep ...`. The breadth LLM consistently
# emits markdown tables (`| row | rule | location | finding | notes |`)
# instead of the strict `[OBLIG:...:row] STATUS:R|D|C` line form — the
# strict regex misses every table row, so the validator logged 0 receipts
# across multiple audits despite each analysis file carrying real
# receipts in table form. F4 closes that gap conservatively:
#   - section-bounded (only headings that name the artifact)
#   - numeric first cell required (unrelated tables NOT absorbed)
#   - empty / "N/A" / "-" addressed_by cells are NOT acknowledgments

_OBLIG_TABLE_HEADING_RE = re.compile(
    r"(?im)^#{2,4}\s+[^\n]*Obligation\s+Receipts[^\n]*$"
)
_OBLIG_NEXT_HEADING_RE = re.compile(r"(?m)^#{1,6}\s+")
_OBLIG_TABLE_ROW_RE = re.compile(r"^\s*\|\s*(\d+)\s*\|(.+)\|\s*$")
_OBLIG_TABLE_SEP_RE = re.compile(r"^\s*\|[\s\-:|]+\|\s*$")
_OBLIG_DISMISS_KEYS = re.compile(
    r"\b(?:style|gas|stylistic|non[-_ ]security|not\s+security|"
    r"false\s*positive|FP|by\s*design|informational)\b",
    re.IGNORECASE,
)
_OBLIG_CARRY_KEYS = re.compile(
    r"\b(?:carry|carried|defer|deferred|later\s+phase|next\s+phase)\b",
    re.IGNORECASE,
)
_OBLIG_NONE_CELLS = frozenset({
    "", "n/a", "na", "none", "-", "—", "(none)", "(n/a)",
})


def _parse_obligation_table_receipts(text: str, artifact: str) -> dict[str, str]:
    """F4: parse table-form Obligation Receipts sections targeting `artifact`.

    Section-bounded: only scans tables under a heading whose text mentions
    `Obligation Receipts` AND the artifact name. Requires a numeric first
    cell so unrelated finding-summary tables are NOT absorbed as fake
    receipts. Conservative status inference.
    """
    receipts: dict[str, str] = {}
    artifact_lc = artifact.lower()
    # Drop extension when matching against heading prose ("opengrep_findings.md"
    # vs "opengrep" — the heading typically uses the bare keyword).
    artifact_root = artifact_lc.split(".")[0].split("_")[0]
    for hm in _OBLIG_TABLE_HEADING_RE.finditer(text):
        heading_lc = hm.group(0).lower()
        if artifact_lc not in heading_lc and artifact_root not in heading_lc:
            continue
        section_start = hm.end()
        rest = text[section_start:]
        nxt = _OBLIG_NEXT_HEADING_RE.search(rest)
        section = rest[: nxt.start()] if nxt else rest
        for line in section.splitlines():
            s = line.rstrip()
            if not s or _OBLIG_TABLE_SEP_RE.match(s):
                continue
            m = _OBLIG_TABLE_ROW_RE.match(s)
            if not m:
                continue
            row = m.group(1).strip()
            rest_cells = [c.strip() for c in m.group(2).split("|")]
            cells_lc = [c.lower() for c in rest_cells]
            non_empty = [
                c for c in rest_cells if c.lower() not in _OBLIG_NONE_CELLS
            ]
            # Conservative: a row with EVERY non-first cell empty/N/A is
            # not a real acknowledgment (likely a placeholder / template).
            if not non_empty:
                continue
            joined = " | ".join(rest_cells)
            if _OBLIG_DISMISS_KEYS.search(joined):
                status = "DISMISSED"
            elif _OBLIG_CARRY_KEYS.search(joined):
                status = "CARRIED"
            else:
                status = "REPORTED"
            receipts.setdefault(row, status)
    return receipts


def _collect_obligation_receipts(scratchpad: Path, artifact: str,
                                  output_globs: tuple[str, ...]) -> dict[str, str]:
    """Scan owning phase outputs for receipts targeting `artifact`.

    Accepts BOTH the canonical strict line form (preferred) and the
    table form under an `Obligation Receipts ... <artifact>` heading
    (F4 — relaxation, because LLMs consistently emit tables and the
    strict regex used to log 0 receipts despite real acknowledgments).
    Returns dict[row_id -> status]. Strict-line wins on conflict.
    """
    receipts: dict[str, str] = {}
    for pattern in output_globs:
        for f in scratchpad.glob(pattern):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # 1) Strict line form (the canonical, unambiguous shape).
            for m in _OBLIG_RECEIPT_RE.finditer(text):
                if m.group("artifact").lower() != artifact.lower():
                    continue
                row = m.group("row").strip()
                status = m.group("status").upper()
                if status in ("R",):
                    status = "REPORTED"
                elif status in ("D",):
                    status = "DISMISSED"
                elif status in ("C",):
                    status = "CARRIED"
                receipts[row] = status
            # 2) F4: section-bounded table form. Additive, deduped by row.
            for row, status in _parse_obligation_table_receipts(text, artifact).items():
                receipts.setdefault(row, status)
    return receipts


def _dedup_decision_coverage_detail(scratchpad: Path) -> dict[str, Any]:
    """Return structured candidate/disposition coverage for semantic dedup."""
    pairs_path = scratchpad / "dedup_candidate_pairs.md"
    decisions_path = scratchpad / "dedup_decisions.md"
    empty = {"pair_count": 0, "accounted": 0, "missing_count": 0, "missing_rows": []}
    if not pairs_path.exists() or not decisions_path.exists():
        return empty
    try:
        pairs_text = pairs_path.read_text(encoding="utf-8", errors="replace")
        decisions_text = decisions_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return empty
    pair_rows: list[str] = []
    for line in pairs_text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.split("|") if c.strip()]
        if len(cells) < 2:
            continue
        if cells[0].startswith("-") or cells[0].lower() in ("finding a", "pair", "id"):
            continue
        pair_rows.append(s)
    if not pair_rows:
        return empty
    accounted = 0
    allowed_re = re.compile(
        r"\b(MERGE|GROUP|KEEP[\s_-]?SEPARATE|N[/\s]?A|PASSTHROUGH)\b",
        re.IGNORECASE,
    )
    for line in decisions_text.splitlines():
        s = line.strip()
        if s.startswith("|") and allowed_re.search(s):
            accounted += 1
    missing_count = max(0, len(pair_rows) - accounted)
    return {
        "pair_count": len(pair_rows),
        "accounted": accounted,
        "missing_count": missing_count,
        "missing_rows": pair_rows[accounted:],
    }


def _check_dedup_decision_coverage(scratchpad: Path) -> list[str]:
    """v2.0.10 (P5): coverage gate for sc_semantic_dedup.

    Every row in `dedup_candidate_pairs.md` MUST have a corresponding row
    in `dedup_decisions.md` with one of {MERGE, GROUP, KEEP SEPARATE, N/A}.
    Returns WARNING-class issue strings; caller treats as non-blocking.
    The v2.7.0 mechanical-dedup fallback already covers the worst case
    (PASSTHROUGH not overwritten); this gate adds telemetry on the
    LLM's compliance with the explicit-disposition contract.
    """
    pairs_path = scratchpad / "dedup_candidate_pairs.md"
    decisions_path = scratchpad / "dedup_decisions.md"
    if not pairs_path.exists() or not decisions_path.exists():
        return []
    try:
        pairs_text = pairs_path.read_text(encoding="utf-8", errors="replace")
        decisions_text = decisions_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    # Count live candidate pair rows (skip headers/separators)
    import re as _re
    pair_count = 0
    for line in pairs_text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.split("|") if c.strip()]
        if len(cells) < 2:
            continue
        if cells[0].startswith("-") or cells[0].lower() in ("finding a", "pair", "id"):
            continue
        pair_count += 1
    if pair_count == 0:
        return []
    # Count disposition rows in decisions: any row whose disposition cell
    # matches the allowed set is "accounted".
    accounted = 0
    allowed_re = _re.compile(
        r"\b(MERGE|GROUP|KEEP[\s_-]?SEPARATE|N[/\s]?A|PASSTHROUGH)\b",
        _re.IGNORECASE,
    )
    for line in decisions_text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        if allowed_re.search(s):
            accounted += 1
    if accounted >= pair_count:
        return []
    return [
        f"dedup decision coverage: {accounted}/{pair_count} candidate pair(s) "
        f"have a disposition row in dedup_decisions.md — "
        f"{pair_count - accounted} unaccounted"
    ]


def _repair_dedup_missing_dispositions(
    scratchpad: Path, phase_name: str
) -> int:
    """Append deterministic PASSTHROUGH rows for missing dedup dispositions."""
    detail = _dedup_decision_coverage_detail(scratchpad)
    missing_rows = [str(x) for x in (detail.get("missing_rows") or [])]
    if not missing_rows:
        return 0
    path = scratchpad / "dedup_decisions.md"
    try:
        existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    except OSError:
        existing = ""

    def _cell(value: str) -> str:
        return re.sub(r"\s+", " ", value.replace("|", "/")).strip()

    lines: list[str] = []
    if existing and not existing.endswith("\n"):
        lines.append("")
    lines.extend([
        "",
        "## Mechanical Missing Disposition Repair",
        "",
        f"**Phase**: `{phase_name}`",
        "",
        "Rows below were candidate pairs that lacked explicit semantic-dedup "
        "dispositions. They are marked PASSTHROUGH to preserve upstream "
        "findings rather than silently dropping or merging them.",
        "",
        "| Repair Row | Candidate Pair | Disposition | Reason |",
        "|---|---|---|---|",
    ])
    for idx, row in enumerate(missing_rows, start=1):
        lines.append(
            f"| {idx} | {_cell(row)} | PASSTHROUGH | missing explicit LLM disposition |"
        )
    try:
        path.write_text(existing + "\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        return 0
    return len(missing_rows)


def _generate_dedup_decision_retry_hint(
    scratchpad: Path, phase_name: str, limit: int = 40
) -> str:
    detail = _dedup_decision_coverage_detail(scratchpad)
    missing_rows = [str(x) for x in (detail.get("missing_rows") or [])]
    missing_count = int(detail.get("missing_count") or 0)
    pair_count = int(detail.get("pair_count") or 0)
    accounted = int(detail.get("accounted") or 0)
    lines = [
        "## RETRY HINT - semantic dedup missing dispositions",
        "",
        f"`{phase_name}` left {missing_count}/{pair_count} candidate pair(s) "
        f"without explicit disposition rows in `dedup_decisions.md`.",
        "",
        "Repair only the missing dispositions. Preserve existing MERGE/GROUP/"
        "KEEP SEPARATE/N/A/PASSTHROUGH rows and preserve the existing deduped "
        "output unless a listed missing pair requires a narrowly scoped update.",
        "",
        f"Accounted rows before retry: {accounted}/{pair_count}.",
        "",
        "Missing candidate pair rows:",
    ]
    for row in missing_rows[:limit]:
        lines.append(f"- `{row}`")
    if len(missing_rows) > limit:
        lines.append(f"- ... (+{len(missing_rows) - limit} more)")
    lines.extend([
        "",
        "Completion contract:",
        "- Every candidate row in `dedup_candidate_pairs.md` must have a "
        "matching disposition row in `dedup_decisions.md`.",
        "- Do not introduce new finding IDs or change unrelated phase outputs.",
    ])
    return "\n".join(lines) + "\n"


def _check_opengrep_obligation_coverage(
    scratchpad: Path, mode: str
) -> list[str]:
    """COVERAGE TELEMETRY (warning-only, NOT enforced): reports how many
    opengrep_findings.md rows have a breadth-emitted receipt.

    Ship 8.6-lite: this is telemetry, not a completeness contract. It emits
    issue strings for the driver to log and writes `opengrep_obligation_gap.md`
    for observation, but its issues NEVER contribute to the artifact gate's
    `missing` list (`gate_passes`). A missing `## Obligation Receipts` section
    does not fail breadth -- that hard-coupling was removed in Ship 8.2 (it was
    internally inconsistent with this check already being warning-only).
    Vacuous-pass when opengrep_findings.md is absent or has 0 rows.

    Receipts remain warning-only by design: real agents do not reliably emit
    them, and forcing them would create a noisy halt class. A future,
    explicitly-scoped change could derive receipts mechanically from shard
    disposition (keyed by DEDUP_KEY) -- but that stays warning-only for >=1
    clean run before any promotion is even considered.
    """
    rows = _parse_opengrep_row_count(scratchpad)
    if rows == 0:
        return []

    # Breadth output: analysis_*.md plus per-contract + rescan outputs.
    # Receipts may live in any of these files. analysis_b*.md are bucket-named
    # by the breadth orchestrator; analysis_<role>.md are role-named.
    receipts = _collect_obligation_receipts(
        scratchpad, "opengrep_findings.md",
        ("analysis_*.md", "analysis_b*.md", "analysis_percontract_*.md",
         "analysis_rescan_*.md"),
    )

    if not receipts:
        try:
            (scratchpad / "opengrep_obligation_gap.md").write_text(
                "# OpenGrep Obligation Gap\n\n"
                f"**Total opengrep rows**: {rows}\n"
                f"**Receipts emitted**: 0\n"
                f"**Unaccounted rows**: {rows}\n\n"
                "No `[OBLIG:opengrep_findings.md:<row>]` lines were found in "
                "any `analysis_*.md` file. Breadth phase should append a "
                "receipts section addressing every row in opengrep_findings.md.\n",
                encoding="utf-8",
            )
        except Exception:
            pass
        return [
            f"opengrep coverage telemetry (not enforced): {rows} row(s) in "
            "opengrep_findings.md, 0 receipts in breadth output. Receipts are "
            "warning-only and never fail the artifact gate; emitting a "
            "`## Obligation Receipts — opengrep_findings.md` section improves "
            "the coverage number."
        ]

    accounted = set(receipts.keys())
    # Convert row indices we extract to a comparable form (string of int).
    # Receipts may use "1" or "01" etc.; normalize both sides.
    accounted_norm = {r.lstrip("0") or "0" for r in accounted}
    all_rows_norm = {str(i) for i in range(1, rows + 1)}
    unaccounted = sorted(all_rows_norm - accounted_norm, key=lambda x: int(x))

    issues: list[str] = []
    if unaccounted:
        # Snapshot the gap so post-mortem can inspect it.
        try:
            gap_path = scratchpad / "opengrep_obligation_gap.md"
            gap_path.write_text(
                "# OpenGrep Obligation Gap\n\n"
                f"**Total opengrep rows**: {rows}\n"
                f"**Receipts emitted**: {len(accounted_norm)}\n"
                f"**Unaccounted rows**: {len(unaccounted)}\n\n"
                "## Unaccounted Row Indices\n"
                "Each row below has no `[OBLIG:opengrep_findings.md:<row>]` "
                "receipt in any analysis_*.md file. Future audits should "
                "address them in breadth output as REPORTED/DISMISSED/CARRIED.\n\n"
                + "\n".join(f"- row {r}" for r in unaccounted[:200]),
                encoding="utf-8",
            )
        except Exception:
            pass
        issues.append(
            f"opengrep coverage telemetry (not enforced): "
            f"{len(unaccounted)}/{rows} row(s) in opengrep_findings.md have "
            "no breadth receipt (see opengrep_obligation_gap.md). Warning-only; "
            "does not fail the artifact gate."
        )

    # Validate dismissal vocabulary on emitted DISMISSED receipts (lenient —
    # unknown reasons are logged but do not count toward the gate today).
    return issues


def _parse_function_summary_rows(scratchpad: Path) -> list[dict[str, str]]:
    """Parse function_summary.md into per-function rows.

    Each row dict carries: contract, function, state_writes, external_calls.
    Returns [] when the artifact is absent.
    """
    path = scratchpad / "function_summary.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rows: list[dict[str, str]] = []
    current_contract = ""
    in_table = False
    header_cols: list[str] = []
    for line in text.splitlines():
        m = re.match(r"^##\s+(\S+\.(sol|rs|move|go))\s*$", line)
        if m:
            current_contract = m.group(1)
            in_table = False
            header_cols = []
            continue
        if line.strip().startswith("| Function") or line.strip().startswith("|Function"):
            header_cols = [c.strip().lower() for c in line.split("|")[1:-1]]
            in_table = True
            continue
        if in_table and re.match(r"^\|[\s\-:]+\|", line):
            continue  # separator
        if in_table and line.startswith("|"):
            cells = [c.strip() for c in line.split("|")[1:-1]]
            if len(cells) < len(header_cols):
                continue
            row: dict[str, str] = {"contract": current_contract}
            for i, col in enumerate(header_cols):
                if i < len(cells):
                    row[col.replace(" ", "_")] = cells[i]
            # Normalize
            row["function"] = row.get("function", "")
            row["state_writes"] = row.get("state_writes", "")
            row["external_calls"] = row.get("external_calls", "")
            rows.append(row)
        elif in_table and not line.strip():
            in_table = False
    return rows


def _check_function_summary_obligation(
    scratchpad: Path, mode: str
) -> list[str]:
    """WARNING-class: every function_summary.md row with state-writes or
    external-calls needs a receipt in the owning depth role's output.

    Row partitioning:
      - State Writes non-empty → depth-state-trace must dispose.
      - External Calls non-empty → depth-token-flow must dispose.
      - Both → either role's receipt counts.

    Vacuous-pass when function_summary.md is absent (no obligation set).
    """
    rows = _parse_function_summary_rows(scratchpad)
    if not rows:
        return []

    def _is_meaningful(cell: str) -> bool:
        return bool(cell) and cell.strip() not in ("-", "—", "N/A", "(none)", "")

    # Build per-row id `<contract>.<function>` and required-role lookup.
    required_state: set[str] = set()
    required_extcall: set[str] = set()
    for row in rows:
        contract_short = (row.get("contract", "") or "").split(".")[0]
        func = (row.get("function", "") or "").strip("`")
        if not func:
            continue
        row_id = f"{contract_short}.{func}" if contract_short else func
        if _is_meaningful(row.get("state_writes", "")):
            required_state.add(row_id)
        if _is_meaningful(row.get("external_calls", "")):
            required_extcall.add(row_id)

    if not required_state and not required_extcall:
        return []

    state_receipts = _collect_obligation_receipts(
        scratchpad, "function_summary.md",
        ("depth_state_trace_findings.md",
         "depth_da_state_trace_findings.md",
         "depth_da3_state_trace_findings.md"),
    )
    tokenflow_receipts = _collect_obligation_receipts(
        scratchpad, "function_summary.md",
        ("depth_token_flow_findings.md",
         "depth_da_token_flow_findings.md",
         "depth_da3_token_flow_findings.md"),
    )
    all_receipts = set(state_receipts.keys()) | set(tokenflow_receipts.keys())

    # Normalize: receipts may quote backticks, full path, etc. — strip backticks.
    all_receipts_norm = {r.strip("`") for r in all_receipts}

    missing_state = sorted(required_state - all_receipts_norm)
    missing_extcall = sorted(required_extcall - all_receipts_norm)

    issues: list[str] = []
    if missing_state:
        issues.append(
            f"function_summary obligation: depth-state-trace missing "
            f"{len(missing_state)}/{len(required_state)} receipts "
            f"(first 5: {', '.join(missing_state[:5])})"
        )
    if missing_extcall:
        issues.append(
            f"function_summary obligation: depth-token-flow missing "
            f"{len(missing_extcall)}/{len(required_extcall)} receipts "
            f"(first 5: {', '.join(missing_extcall[:5])})"
        )

    if issues:
        # Snapshot for post-mortem.
        try:
            (scratchpad / "function_summary_obligation_gap.md").write_text(
                "# function_summary Obligation Gap\n\n"
                f"**State-trace required**: {len(required_state)}\n"
                f"**State-trace receipts emitted**: "
                f"{len(required_state) - len(missing_state)}\n"
                f"**Token-flow required**: {len(required_extcall)}\n"
                f"**Token-flow receipts emitted**: "
                f"{len(required_extcall) - len(missing_extcall)}\n\n"
                "## Missing state-trace rows\n"
                + "\n".join(f"- {r}" for r in missing_state[:200])
                + "\n\n## Missing token-flow rows\n"
                + "\n".join(f"- {r}" for r in missing_extcall[:200]),
                encoding="utf-8",
            )
        except Exception:
            pass

    return issues


def _check_pde_section_present(scratchpad: Path) -> list[str]:
    """WARNING-class: niche_semantic_consistency_findings.md must contain a
    Pre-Commit Dimension Enumeration section.

    Vacuous-pass when the niche output is absent (niche agent didn't run).
    """
    path = scratchpad / "niche_semantic_consistency_findings.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    if not re.search(r"^##\s+Pre-Commit\s+Dimension\s+Enumeration",
                     text, re.IGNORECASE | re.MULTILINE):
        return [
            "PDE missing: niche_semantic_consistency_findings.md has no "
            "`## Pre-Commit Dimension Enumeration` section. The niche agent "
            "should enumerate sibling/decoded-field/mirror/actor dimensions "
            "BEFORE writing findings so cross-sibling self-refutation is "
            "structurally prevented."
        ]
    # Optional: count populated table rows
    pde_section = re.split(r"^##\s+(?!#)", text, flags=re.MULTILINE)
    # Confirm at least one table row appears within ~3 KB of the heading.
    return []


_PERTURBATION_BLOCK_RE = re.compile(
    r"""
    ^\s*(?:
        \#{2,6}\s+
        (?:adversarial\s+)?perturbation
        (?:\s+(?:block|matrix|analysis|checks?))?
        \b
      |
        [*_]{1,3}\s*
        (?:adversarial\s+)?perturbation
        (?:\s+(?:block|matrix|analysis|checks?))?
        \s*[*_]{1,3}\s*:?\s*$
      |
        (?:adversarial\s+)?perturbation
        (?:\s+(?:block|matrix|analysis|checks?))?
        \s*:?\s*$
    )
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)


def _missing_perturbation_block_ids(text: str) -> list[str]:
    """Return Medium+ CONFIRMED finding IDs missing an inline perturbation block."""
    findings: list[tuple[int, str]] = []
    for m in re.finditer(
        r"#{2,6}\s+Finding\s+\[(?P<id>[A-Z]{1,8}-\d+[A-Z\d-]*)\]",
        text,
    ):
        findings.append((m.start(), m.group("id")))
    missing_blocks: list[str] = []
    for i, (start, fid) in enumerate(findings):
        end = findings[i + 1][0] if i + 1 < len(findings) else len(text)
        block = text[start:end]
        # Verdict / Severity via the shared tolerant extractor so the bullet,
        # plain-colon, `**label:**`, and table-cell renderings are seen — the
        # literal `**Verdict**:` / `**Severity**:` regexes UNDER-warned (they
        # skipped any finding rendered differently, silently passing it). This
        # is a soft (WARNING-class) gate; catching more findings only raises
        # coverage, never halts.
        verdict_val, _ = _field_anywhere(
            block, ("Verdict", "Final Verdict", "Status"), table_ok=True
        )
        sev_val, _ = _field_anywhere(
            block, ("Severity", "Final Severity"), table_ok=True
        )
        verdict_word = re.match(r"\s*\**\s*(\w+)", verdict_val or "")
        sev_word = re.match(r"\s*\**\s*(\w+)", sev_val or "")
        if not verdict_word or not sev_word:
            continue
        if verdict_word.group(1).upper() != "CONFIRMED":
            continue
        if sev_word.group(1).capitalize() not in ("Critical", "High", "Medium"):
            continue
        if not _PERTURBATION_BLOCK_RE.search(block):
            missing_blocks.append(fid)
    return missing_blocks


def _check_perturbation_block_per_finding(scratchpad: Path) -> list[str]:
    """WARNING-class: every Medium+ CONFIRMED finding in depth-state-trace
    and depth-token-flow output must carry an inline Perturbation Block.

    Vacuous-pass when the depth output is absent.
    """
    issues: list[str] = []
    for role_file in (
        "depth_state_trace_findings.md",
        "depth_token_flow_findings.md",
    ):
        path = scratchpad / role_file
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        missing_blocks = _missing_perturbation_block_ids(text)
        if missing_blocks:
            issues.append(
                f"perturbation block: {role_file} has "
                f"{len(missing_blocks)} Medium+ CONFIRMED finding(s) without "
                f"`### Perturbation Block` table (first 5: "
                f"{', '.join(missing_blocks[:5])})"
            )
    return issues


def _check_notread_priority_coverage(
    scratchpad: Path, mode: str
) -> list[str]:
    """Soft validator: NOTREAD files with zero citations in any finding output.

    Mode-gated: runs in core/thorough only. Light skips (smaller budget,
    smaller scope, less leverage from the gate).

    Side effect: writes `{scratchpad}/notread_priority_gaps.md` listing the
    uncovered files. The next phase's prompt SHOULD reference this file so
    iter2/DA agents target it; this is a soft directive — no hard halt.
    """
    # v2.2.1 Fix 4: write a status note unconditionally on skip so the
    # absence of `notread_priority_gaps.md` is unambiguous after a run.
    # Pre-v2.2.1 the early-returns left no trace, making it impossible
    # to tell from the scratchpad whether the gate ran-and-passed or
    # never-ran. Now: file always exists when the function executes.
    gap_path = scratchpad / "notread_priority_gaps.md"

    def _write_skip(reason: str) -> None:
        try:
            gap_path.write_text(
                "# NOTREAD priority coverage gaps (v2.2.0 A.4)\n\n"
                f"**Status**: SKIPPED — {reason}\n",
                encoding="utf-8",
            )
        except Exception:
            pass

    if mode not in ("core", "thorough"):
        _write_skip(
            f"mode={mode!r} (gate runs in core/thorough only)"
        )
        return []
    # v2.2.3 widening: try BOTH scope_leftover.md AND file_coverage_ledger.md.
    # Recon writes both; uncovered files may live in either depending on
    # which schema the agent chose. Union the two sets.
    sl = scratchpad / "scope_leftover.md"
    fl = scratchpad / "file_coverage_ledger.md"
    notread: list[str] = []
    if sl.exists():
        try:
            notread.extend(_parse_notread_files(
                _llm_norm(sl.read_text(encoding="utf-8", errors="replace"))
            ))
        except Exception:
            pass
    if fl.exists():
        try:
            notread.extend(_parse_uncovered_from_ledger(
                _llm_norm(fl.read_text(encoding="utf-8", errors="replace"))
            ))
        except Exception:
            pass
    # Dedup while preserving order.
    seen = set()
    notread = [p for p in notread if not (p in seen or seen.add(p))]

    if not sl.exists() and not fl.exists():
        _write_skip(
            "neither scope_leftover.md nor file_coverage_ledger.md exists "
            "(recon may not have produced them; check recon agent L1-2 / "
            "TASK 5a output)"
        )
        return []
    if not notread:
        _write_skip(
            f"scope_leftover.md present={sl.exists()} / "
            f"file_coverage_ledger.md present={fl.exists()} but parser "
            f"found 0 uncovered rows (accepted schemas: scope_leftover "
            f"NOTREAD/UNREAD/UNCOVERED status cell, scope_leftover empty "
            f"Acknowledged column, file_coverage_ledger ## Uncovered Files "
            f"section)"
        )
        return []

    # Concatenate all finding outputs once for cheap citation check.
    finding_text_parts: list[str] = []
    for pattern in _NOTREAD_FINDING_GLOBS:
        for f in scratchpad.glob(pattern):
            try:
                finding_text_parts.append(
                    f.read_text(encoding="utf-8", errors="replace")
                )
            except Exception:
                continue
    finding_blob = "\n".join(finding_text_parts)

    basename_counts: dict[str, int] = {}
    for path in notread:
        basename = path.replace("\\", "/").rsplit("/", 1)[-1]
        if basename:
            basename_counts[basename] = basename_counts.get(basename, 0) + 1

    uncovered: list[str] = []
    for path in notread:
        # Citation = bare filename or full relative path appears anywhere in
        # any finding output. Use basename only when unique in the NOTREAD set;
        # otherwise basename collisions (`metadata.rs`, `lib.rs`, etc.) create
        # false coverage and suppress required depth gap-fill.
        norm_path = path.replace("\\", "/").strip("`")
        basename = norm_path.rsplit("/", 1)[-1]
        if norm_path in finding_blob:
            continue
        if basename and basename_counts.get(basename, 0) == 1 and basename in finding_blob:
            continue
        uncovered.append(path)

    # Persist the gap list for iter2 phase to consume.
    try:
        gap_path = scratchpad / "notread_priority_gaps.md"
        if uncovered:
            lines = [
                "# NOTREAD priority coverage gaps (v2.2.0 A.4)",
                "",
                "These files were flagged NOTREAD by recon and received zero",
                "citations across depth, breadth, scanner, and niche finding",
                "outputs after iter 1. The next iter MUST target each file.",
                "",
                "| # | File |",
                "|---|------|",
            ]
            for i, p in enumerate(uncovered, 1):
                lines.append(f"| {i} | `{p}` |")
            gap_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        else:
            # Clear stale gap files between runs.
            if gap_path.exists():
                gap_path.write_text(
                    "# NOTREAD priority coverage gaps (v2.2.0 A.4)\n\n"
                    "All NOTREAD priority files received depth coverage.\n",
                    encoding="utf-8",
                )
    except Exception:
        pass

    if uncovered:
        sample = ", ".join(uncovered[:3])
        more = f" (+{len(uncovered)-3} more)" if len(uncovered) > 3 else ""
        return [
            f"NOTREAD priority gap: {len(uncovered)} file(s) flagged NOTREAD "
            f"by recon received zero citations after iter 1: {sample}{more}. "
            f"See notread_priority_gaps.md."
        ]
    return []


def _validate_rc_parity(
    phase: Phase, scratchpad: Path, rc: int, backend: str = "claude",
) -> list[str]:
    """Parity check for rc=-2 (timeout-killed) phases (A3).

    Before v2.1.2, the driver's gate check was pure file-existence: if the
    subprocess died via SIGKILL mid-write but the file existed with >= 100
    bytes, the phase was marked complete. A prior postmortem surfaced
    three consecutive silent acceptances (inventory, verify, report) that
    each had correct-looking output but incomplete content.

    This helper runs ONLY when `rc != 0` and applies phase-specific content
    parity heuristics. On clean rc=0 exits it is a no-op. SOFT: unknown
    phase names or unparseable files return [] — we don't false-alarm on
    phases that don't have an obvious content signature.
    """
    if rc == 0:
        return []
    # rc is nonzero; rc=-2 is the timeout sentinel, other values are
    # claude -p internal errors. Both warrant parity.
    issues: list[str] = []
    name = phase.name
    try:
        if name == "inventory":
            p = scratchpad / "findings_inventory.md"
            if p.exists():
                text = p.read_text(encoding="utf-8", errors="replace")
                # Expect at least N inventory ID rows. 79 was a prior
                # count; a real small audit still produces >= 10 rows in
                # core mode. <5 rows with rc!=0 is almost certainly
                # truncation.
                id_rows = len(re.findall(
                    r"^\s*\|\s*\[[A-Z]{2,4}-\d+\]",
                    text, re.MULTILINE,
                ))
                if id_rows < 5:
                    issues.append(
                        f"findings_inventory.md has only {id_rows} ID row(s) "
                        f"with rc={rc} — likely truncated mid-write"
                    )
        elif name == "recon":
            summary = scratchpad / "recon_summary.md"
            build = scratchpad / "build_status.md"
            min_summary_bytes = 200 if backend == "codex" else 512
            min_build_bytes = 30 if backend == "codex" else 80
            if not summary.exists():
                issues.append("recon_summary.md missing after nonzero rc")
            else:
                text = summary.read_text(encoding="utf-8", errors="replace")
                if summary.stat().st_size < min_summary_bytes:
                    issues.append(
                        "recon_summary.md is too small after nonzero rc "
                        f"({summary.stat().st_size} bytes, min={min_summary_bytes})"
                    )
                if not re.search(
                    r"(?im)^(?:#+\s+|\*\*).*(?:recon|summary|protocol|contract|"
                    r"component|attack|risk|template|skill|overview|finding|scope)",
                    text,
                ):
                    log.warning(
                        "[_validate_rc_parity] recon_summary.md lacks "
                        "recognizable heading keywords — LLM prose check (soft)"
                    )
            if not build.exists():
                issues.append("build_status.md missing after nonzero rc")
            else:
                text = build.read_text(encoding="utf-8", errors="replace")
                if build.stat().st_size < min_build_bytes:
                    issues.append(
                        "build_status.md is too small after nonzero rc "
                        f"({build.stat().st_size} bytes, min={min_build_bytes})"
                    )
                elif not re.search(
                    r"(?i)\b(?:build|compile|forge|hardhat|foundry|slither|"
                    r"aderyn|opengrep|success|failed|unavailable|skipped|"
                    r"status|compiled|ok|error|passed)\b",
                    text,
                ):
                    log.warning(
                        "[_validate_rc_parity] build_status.md lacks "
                        "recognizable build keywords — LLM prose check (soft)"
                    )
        elif name.startswith("verify") or name in SC_VERIFY_PHASE_NAMES:
            shard_issues = _validate_verify_completion(scratchpad, name)
            if shard_issues:
                issues.extend(shard_issues)
            # Every hypothesis ID in hypotheses.md must have >=1
            # verify_*.md file referencing it. Missing IDs after rc!=0
            # suggest mid-phase termination.
            #
            # v2.3.5 P2: use the canonical `_INTERNAL_FINDING_ID_RE` (covers
            # SC bare H-1, L1 prefixed L1-H-12, L1 tiered H-C01/H-M27/H-L07,
            # CC-NN, F-NN). Pre-v2.3.5 used a hardcoded `\b(H-\d+|CH-\d+)\b`
            # that missed every L1 ID format → the parity gate passed
            # vacuously on every L1 timeout. False clean.
            hp = scratchpad / "hypotheses.md"
            is_verify_shard = name in L1_VERIFY_PHASE_NAMES or name in SC_VERIFY_PHASE_NAMES
            if hp.exists() and not is_verify_shard:
                hyp_text = hp.read_text(encoding="utf-8", errors="replace")
                hyp_ids = set(_INTERNAL_FINDING_ID_RE.findall(hyp_text))
                if hyp_ids:
                    verified = set()
                    for vf in scratchpad.glob("verify_*.md"):
                        try:
                            vt = vf.read_text(encoding="utf-8", errors="replace")
                        except Exception:
                            continue
                        verified.update(_INTERNAL_FINDING_ID_RE.findall(vt))
                    missing = sorted(hyp_ids - verified)
                    if missing:
                        issues.append(
                            f"verify rc={rc}: {len(missing)} hypothesis ID(s) "
                            f"unreferenced in any verify_*.md "
                            f"(e.g. {', '.join(missing[:3])}...)"
                        )
        elif name in ("report", "report_assemble"):
            # The monolithic or sharded assembler finished phase — check
            # AUDIT_REPORT.md has body sections, not just a header stub.
            pr = scratchpad.parent / "AUDIT_REPORT.md"
            if pr.exists():
                try:
                    rtxt = pr.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    rtxt = ""
                section_count = len(re.findall(
                    r"^###\s*\[[CHMLI]-\d+\]", rtxt, re.MULTILINE
                ))
                if section_count < 3 and len(rtxt) < 5000:
                    issues.append(
                        f"AUDIT_REPORT.md has {section_count} finding "
                        f"section(s) with rc={rc} — probable assembler stub"
                    )
    except Exception as exc:
        log.warning(
            f"[_validate_rc_parity] {phase.name}: internal error during "
            f"parity check (soft-pass): {exc}"
        )
        return []
    return issues


def _canonicalize_summary_table(text: str, tier_counts: dict[str, int]) -> tuple[str, list[tuple[str, str]]]:
    """Rewrite the `## Summary` count table inside a markdown report so
    each `| Severity | N |` row reflects ``tier_counts``.

    Returns ``(new_text, deltas)`` where ``deltas`` is a list of
    ``(severity_name, "old->new")`` tuples for any row that was updated
    (empty list = file already canonical).

    v2.1.9 — body section counts are the authoritative source. The
    Summary table is metadata derived from the body. Mismatches are
    self-healed in place rather than treated as report failures.
    """
    deltas: list[tuple[str, str]] = []
    new_text = text
    for char, name in (
        ("C", "Critical"), ("H", "High"), ("M", "Medium"),
        ("L", "Low"), ("I", "Informational"),
    ):
        target = tier_counts.get(char, 0)
        pattern = re.compile(
            rf"^(\s*\|\s*{name}\s*\|\s*)(\d+)(\s*\|.*)$",
            re.MULTILINE,
        )
        def _sub(m: re.Match, _t=target, _n=name) -> str:
            current = int(m.group(2))
            if current != _t:
                deltas.append((_n, f"{current}->{_t}"))
            return f"{m.group(1)}{_t}{m.group(3)}"
        new_text = pattern.sub(_sub, new_text, count=1)
    total_target = sum(tier_counts.get(c, 0) for c in "CHMLI")
    total_pattern = re.compile(
        r"^(\s*\|\s*(?:\*\*)?Total(?:\*\*)?\s*\|\s*(?:\*\*)?)(\d+)"
        r"((?:\*\*)?\s*\|.*)$",
        re.MULTILINE,
    )
    def _sub_total(m: re.Match) -> str:
        current = int(m.group(2))
        if current != total_target:
            deltas.append(("Total", f"{current}->{total_target}"))
        return f"{m.group(1)}{total_target}{m.group(3)}"
    new_text = total_pattern.sub(_sub_total, new_text, count=1)
    return new_text, deltas


def _canonical_internal_id_key(raw: str) -> str:
    """Canonical comparison key for internal finding IDs."""
    fid = _normalize_finding_id(raw) or (raw or "").strip().upper()
    if not fid:
        return ""
    return re.sub(r"-0+(\d)", r"-\1", fid)


def _verify_filename_finding_id(path: Path) -> str:
    m = re.match(r"verify_(?:F-)?([A-Z][A-Z0-9\-]*\d+)\.md$", path.name, re.IGNORECASE)
    if not m:
        return ""
    return _normalize_finding_id(m.group(1)) or m.group(1).upper()


def _collect_verify_promotion_receipts(scratchpad: Path) -> set[str]:
    """Mine verify_*.md files for finding IDs that received CONFIRMED.

    Strategy: per file, if `Verdict: CONFIRMED` appears anywhere, extract
    every internal-finding-id token in the file. Conservative — false
    positives in this set just mean we expect the finding in the report,
    which is what we want.

    Skip patterns whose files are non-finding (skeptic_judge_summary,
    skeptic_findings — these reference IDs but don't author verdicts).
    """
    receipts: set[str] = set()
    for f in scratchpad.glob("verify_*.md"):
        # v2.3.2 F2: align filter with the other 3 verify_*.md globs
        # (_collect_verify_hypothesis_ids, _validate_cited_paths_in_verify,
        # _generate_verify_core_if_missing). Skipping the aggregate and
        # retry-hint files prevents future double-count regressions if the
        # CONFIRMED verdict regex is ever loosened to match table cells.
        if f.name in {"verify_core.md", "verify_core_full.md"}:
            continue
        if f.name.endswith(_RETRY_HINT_SUFFIX):
            continue
        if "skeptic" in f.name or "judge" in f.name:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if _verifier_status_from_text(text) != "CONFIRMED":
            continue
        fid = _verify_filename_finding_id(f)
        if fid:
            receipts.add(fid)
            continue
        # Legacy fallback for malformed verifier filenames: accept only an
        # explicit ID field, never arbitrary body references. Confirmed
        # verifier prose often cites related source IDs (`DX-1`, `VS-7`) or
        # standards (`EIP-20`); those are not independent promotion receipts.
        for line in text[:2048].splitlines():
            if re.match(r"^\s*(?:[*_`]*\s*)?(?:Finding|Hypothesis)\s+ID\s*[:|]", line, re.IGNORECASE):
                fid = _normalize_finding_id(line)
                if fid:
                    receipts.add(fid)
                    break
    return receipts


def _collect_report_promoted_ids(
    audit_report_text: str, report_index_text: str
) -> set[str]:
    """Return the set of internal IDs that the report acknowledges.

    Acknowledged = referenced in any of:
      - AUDIT_REPORT.md body (any internal ID mention — usually in
        Description/Evidence cross-refs or Internal-Hypothesis col)
      - AUDIT_REPORT.md Appendix A (Internal Hypothesis column)
      - report_index.md Master Finding Index (Internal Hypothesis column)
      - report_index.md Excluded Findings table (Internal ID column)
      - report_index.md Consolidation Map (Consolidated From column)
    """
    promoted: set[str] = set()
    for txt in (audit_report_text, report_index_text):
        if not txt:
            continue
        for m in _INTERNAL_FINDING_ID_RE.finditer(txt):
            promoted.add(m.group(1))
    return promoted


_REPORT_COVERAGE_ACK_STATUSES = {
    "PROMOTED",
    "MERGED",
    "MERGE_INTO",
    "DUPLICATE",
    "APPENDIX_ONLY",
    "DROP_FALSE_POSITIVE",
    "DROP_NON_SECURITY",
    "DROP_DESIGN_CONFIRMATION",
    "DROP_UNACTIONABLE_SPECULATION",
    "FALSE_POSITIVE",
    "DEFERRED",
    "EXCLUDED",
}


def _collect_report_coverage_acknowledged_ids(scratchpad: Path) -> set[str]:
    """Return candidate IDs explicitly accounted for by report_coverage.md.

    `report_coverage.md` is an internal ledger emitted by report_index. It is
    allowed to acknowledge source IDs that should not become standalone client
    body sections because they were merged, duplicated, demoted to appendix, or
    explicitly dropped. Do not treat header rows or UNACCOUNTED rows as a pass.
    """
    path = scratchpad / "report_coverage.md"
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()
    acknowledged: set[str] = set()
    id_col: int | None = None
    status_cols: list[int] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|") or re.fullmatch(r"\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        lower_cells = [c.lower() for c in cells]
        # A header row's ID cell is a SHORT header LABEL (e.g. "Candidate ID /
        # Label", "Finding ID"), NOT prose that merely contains the word
        # "candidate". Data rows whose Reason text says e.g. "auto-mapped depth
        # candidate" must NOT be misdetected as headers — that flips id_col to
        # the reason column and corrupts ID extraction for every following row.
        def _is_id_header_cell(cell: str) -> bool:
            return bool(re.match(
                r"^(?:raw\s+)?(?:candidate(?:\s+id)?(?:\s*/\s*label)?"
                r"|finding\s+id|internal\s+id|hyp(?:othesis)?\s+id)\s*$",
                cell.strip(),
            ))
        if any(_is_id_header_cell(c) for c in lower_cells):
            for i, c in enumerate(lower_cells):
                if _is_id_header_cell(c):
                    id_col = i
                if any(kw in c for kw in ("status", "disposition", "report id", "reason", "refutation")):
                    status_cols.append(i)
            continue
        if id_col is None:
            if len(cells) >= 5:
                id_cell = cells[1]
                status_text = f"{cells[3]} {cells[4]}".upper()
            elif len(cells) >= 3:
                id_cell = cells[1]
                status_text = cells[2].upper()
            else:
                continue
        else:
            if id_col >= len(cells):
                continue
            id_cell = cells[id_col]
            if status_cols:
                status_text = " ".join(cells[i] for i in status_cols if i < len(cells)).upper()
            elif len(cells) >= 5:
                status_text = f"{cells[3]} {cells[4]}".upper()
            elif len(cells) >= 3:
                status_text = cells[2].upper()
            else:
                continue
        if re.search(r"\b(?:CANDIDATE|FINDING|INTERNAL)\s+ID\b", id_cell, re.IGNORECASE):
            continue
        if "UNACCOUNTED" in status_text or "AUTO_EXCLUDED" in status_text:
            continue
        if not any(status in status_text for status in _REPORT_COVERAGE_ACK_STATUSES):
            continue
        for m in _INTERNAL_FINDING_ID_RE.finditer(id_cell):
            acknowledged.add(m.group(1))
    return acknowledged


def _collect_report_index_seed_ids(scratchpad: Path) -> set[str]:
    """Return every Finding/Hyp ID enumerated in report_index_coverage_seed.md.

    This is the AUTHORITATIVE completeness superset for the report_index phase:
    it unions every ID from the bounded ledgers (verification queue, severity
    binding, finding_mapping, dedup absorbed->survivor). The reconciliation gate
    requires each of these IDs to receive exactly one disposition in the merged
    report_index.md, so a sharded index can never let a finding fall between
    shards. Empty when the seed is absent (gate then falls back to verify IDs).
    """
    scratchpad = Path(scratchpad)
    seed = scratchpad / "report_index_coverage_seed.md"
    if not seed.is_file():
        return set()
    try:
        text = seed.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()
    ids: set[str] = set()
    in_table = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            in_table = False
            continue
        lowered = line.lower()
        if "finding/hyp id" in lowered and "expected severity" in lowered:
            in_table = True
            continue
        if not in_table:
            continue
        if re.fullmatch(r"\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?", line):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not cells:
            continue
        first = cells[0]
        if not first or first.lower() in {"(none)", "finding/hyp id"}:
            continue
        m = (
            _INTERNAL_FINDING_ID_RE.fullmatch(first)
            or _INTERNAL_FINDING_ID_RE.search(first)
        )
        if m:
            ids.add(m.group(1).upper())
    return ids


def _ensure_report_consolidation_map(
    scratchpad: Path, project_root: str
) -> int:
    """Write/update the internal source-ID consolidation map.

    Verifier files often cite source IDs from depth/DA/graph passes inside a
    consolidated `INV-*` finding. Those source IDs should not become duplicate
    report body sections, but they must be traceable internally so promotion
    symmetry can distinguish "consolidated" from "dropped". The client report
    must not carry this map because it contains internal pipeline IDs.
    """
    records_path = scratchpad / "report_records.json"
    records: dict[str, Any] = {}
    if not records_path.exists():
        records = {"active": []}
    else:
        try:
            records = json.loads(records_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            records = {"active": []}
    active_records = records.get("active", [])
    active_titles = {
        str(rec.get("report_id") or "").strip(): str(rec.get("title") or "").replace("|", "/").strip()
        for rec in active_records
        if str(rec.get("report_id") or "").strip()
    }
    try:
        active_report_ids = set(active_titles)
    except Exception:
        active_report_ids = set()
    rows: list[tuple[str, str, str]] = []
    for rec in active_records:
        fid = (rec.get("finding_id") or "").strip()
        rid = (rec.get("report_id") or "").strip()
        title = (rec.get("title") or "").replace("|", "/").strip()
        if not fid or not rid:
            continue
        vp = _verify_file_for_id(scratchpad, fid)
        try:
            vtxt = vp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if not _is_reportable_verdict(_verifier_status_from_text(vtxt)):
            continue
        for sid in sorted(set(_INTERNAL_FINDING_ID_RE.findall(vtxt))):
            if sid == fid or sid.startswith("INV-"):
                continue
            rows.append((sid, rid, title))

    coverage_path = scratchpad / "report_coverage.md"
    if coverage_path.exists():
        try:
            coverage_text = coverage_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            coverage_text = ""
        for raw in coverage_text.splitlines():
            line = raw.strip()
            if not line.startswith("|") or re.fullmatch(r"\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?", line):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 5:
                id_cell = cells[1]
                status_text = f"{cells[3]} {cells[4]}".upper()
                reason = cells[4]
            elif len(cells) >= 3:
                id_cell = cells[1]
                status_text = cells[2].upper()
                reason = cells[2]
            else:
                continue
            if "UNACCOUNTED" in status_text:
                continue
            if not any(status in status_text for status in _REPORT_COVERAGE_ACK_STATUSES):
                continue
            source_ids = [m.group(1) for m in _INTERNAL_FINDING_ID_RE.finditer(id_cell)]
            if not source_ids:
                continue
            report_ids = []
            for rm in re.finditer(r"\b([CHMLI]-\d{1,3})\b", reason, re.IGNORECASE):
                rid = _normalize_report_id(rm.group(1)) or rm.group(1).upper()
                if not active_report_ids or rid in active_report_ids:
                    report_ids.append(rid)
            if not report_ids:
                continue
            for sid in source_ids:
                for rid in report_ids:
                    rows.append((sid, rid, active_titles.get(rid, "coverage-accounted finding")))
    if not rows:
        return 0
    # Deduplicate while preserving stable order.
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str, str]] = []
    for sid, rid, title in rows:
        key = (sid, rid)
        if key in seen:
            continue
        seen.add(key)
        unique.append((sid, rid, title))

    section_lines = [
        "# Internal Consolidation Map",
        "",
        "This file is pipeline-internal and must not be copied into AUDIT_REPORT.md.",
        "",
        "## Consolidation Map",
        "",
        "| Source ID | Report ID | Report Title |",
        "|-----------|-----------|--------------|",
    ]
    section_lines.extend(
        f"| {sid} | {rid} | {title} |" for sid, rid, title in unique
    )
    section = "\n".join(section_lines) + "\n"
    try:
        (scratchpad / "report_consolidation_internal.md").write_text(
            section, encoding="utf-8"
        )
    except Exception:
        return 0
    return len(unique)


def _load_report_reference_aliases(
    scratchpad: Path,
    defined_report_ids: set[str],
) -> dict[str, str]:
    """Map internal source IDs to delivered report IDs for public prose.

    Public report IDs reuse the H-* namespace, so only undefined references
    are rewritten. `report_traceability_internal.md` is authoritative because
    it records the report-index assignment before verifier prose can introduce
    incidental cross-references.
    """
    aliases: dict[str, str] = {}
    trace = scratchpad / "report_traceability_internal.md"
    if not trace.exists():
        return aliases
    try:
        text = trace.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return aliases
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("|") or re.fullmatch(
            r"\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?",
            line,
        ):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2 or cells[0].lower() == "report id":
            continue
        report_id = _normalize_report_id(cells[0]) or cells[0].upper()
        if report_id not in defined_report_ids:
            continue
        for src in _INTERNAL_FINDING_ID_RE.findall(cells[1]):
            src_u = src.upper()
            if src_u not in defined_report_ids:
                aliases.setdefault(src_u, report_id)
    return aliases


def _rewrite_public_report_references(
    text: str,
    aliases: dict[str, str],
    defined_report_ids: set[str],
) -> tuple[str, int]:
    """Rewrite mapped internal IDs in prose references to public report IDs."""
    if not aliases:
        return text, 0
    changed = 0
    ref_re = re.compile(
        r"(?i)\b(?:see|related to|duplicate of|duplicates|same as|"
        r"cross-reference|cross reference|absorbed by|absorbs)\b"
        r"(?P<mid>[^\n]{0,120}?)(?P<id>H-\d{1,3}|CH-\d{1,3}|"
        r"HM-\d{1,3}|HL-\d{1,3}|HI-\d{1,3})"
    )

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        old = match.group("id").upper()
        norm = _normalize_report_id(old) or old
        if norm in defined_report_ids:
            return match.group(0)
        new = aliases.get(old) or aliases.get(norm)
        if not new or new == old:
            return match.group(0)
        changed += 1
        return match.group(0)[:match.start("id") - match.start()] + new

    return ref_re.sub(repl, text), changed


def _check_promotion_symmetry(
    scratchpad: Path, project_root: str
) -> list[str]:
    """Diff verify-receipts against report-acknowledged IDs.

    Returns a list of FAIL messages. Empty = all CONFIRMED verifier
    findings reached the report (body, appendix, or consolidated).
    """
    pr = Path(project_root) / "AUDIT_REPORT.md"
    ri = scratchpad / "report_index.md"
    receipts = _collect_verify_promotion_receipts(scratchpad)
    if not receipts:
        return []
    rtxt = ""
    itxt = ""
    if pr.exists():
        try:
            rtxt = pr.read_text(encoding="utf-8", errors="replace")
        except Exception:
            rtxt = ""
    if ri.exists():
        try:
            itxt = ri.read_text(encoding="utf-8", errors="replace")
        except Exception:
            itxt = ""
    promoted = _collect_report_promoted_ids(rtxt, itxt)
    internal_ack_text = ""
    for internal_path in (
        scratchpad / "report_consolidation_internal.md",
        scratchpad / "report_traceability_internal.md",
    ):
        if internal_path.exists():
            try:
                internal_ack_text += "\n" + internal_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except Exception:
                pass
    if internal_ack_text:
        promoted.update(_collect_report_promoted_ids("", internal_ack_text))
    promoted.update(_collect_report_coverage_acknowledged_ids(scratchpad))
    records_path = scratchpad / "report_records.json"
    if records_path.exists():
        try:
            records = json.loads(records_path.read_text(encoding="utf-8", errors="replace"))
            for rec in records.get("active", []):
                for fid in (rec.get("absorbed_finding_ids") or [rec.get("finding_id")]):
                    if fid:
                        promoted.add(str(fid))
            for rec in records.get("excluded", []):
                fid = rec.get("finding_id")
                if fid:
                    promoted.add(str(fid))
        except Exception:
            pass

    # Stronger body-retention check: if an internal ID has a report-ID mapping,
    # the corresponding `### [X-NN]` body section must exist unless the ID is
    # explicitly excluded/consolidated. Merely appearing in report_index.md is
    # not enough; that was the DCI-14 / graph-queue dropout class.
    assignments, _source = get_tier_assignments(scratchpad)
    promoted_keys = {_canonical_internal_id_key(p) for p in promoted}
    internal_to_report = {
        _canonical_internal_id_key(a["finding_id"]): a["report_id"]
        for a in assignments
        if a.get("finding_id") and a.get("report_id")
    }
    body_report_ids = set(re.findall(
        r"^#{1,3}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\]", rtxt, re.MULTILINE
    ))
    explicitly_non_body: set[str] = set()
    ri_text = itxt or ""
    for section_name in (
        r"Excluded\s+Findings",
        r"Consolidation\s+Map",
        r"Consolidated\s+Findings",
    ):
        m = re.search(
            rf"(?im)^##\s+{section_name}.*?(?=^##\s|\Z)",
            ri_text,
            re.MULTILINE | re.DOTALL,
        )
        if m:
            explicitly_non_body.update(
                _canonical_internal_id_key(x.group(1))
                for x in _INTERNAL_FINDING_ID_RE.finditer(m.group(0))
            )

    # Material-harm body floor: a CONFIRMED finding dispositioned APPENDIX is
    # relocated to Appendix C (a row, not a `### [X-NN]` body section). That is
    # NOT a dropout — acknowledge it via its mapped internal id(s) so the
    # symmetry check does not flag the deliberate relocation.
    appendix_rids = _appendix_disposition_report_ids(scratchpad)
    if appendix_rids:
        for a in assignments:
            if (a.get("report_id") or "").upper() not in appendix_rids:
                continue
            fid_val = a.get("finding_id") or ""
            if not fid_val:
                continue
            explicitly_non_body.add(_canonical_internal_id_key(fid_val))
            for piece in re.split(r"[+,\s]+", fid_val):
                piece = piece.strip()
                if piece:
                    explicitly_non_body.add(_canonical_internal_id_key(piece))

    dropped: list[str] = []
    for fid in sorted(receipts):
        key = _canonical_internal_id_key(fid)
        rid = internal_to_report.get(key)
        if rid:
            if rid not in body_report_ids and key not in explicitly_non_body:
                dropped.append(fid)
            continue
        if key not in promoted_keys:
            dropped.append(fid)
    if not dropped:
        return []
    sample = ", ".join(dropped[:5])
    more = f" (+{len(dropped)-5} more)" if len(dropped) > 5 else ""
    return [
        f"promotion dropout: {len(dropped)} CONFIRMED verifier finding(s) "
        f"missing from report body / internal traceability / consolidation map: "
        f"{sample}{more}"
    ]


# --- v2.2.2 Fix 2 + Fix 5: post-Index completeness + Excluded honesty -----
#
# Failure mode (a prior L1 run, RC-PIPELINE-DROPOUT — silent):
# the Index Agent consumed only the crit/high verify shard and wrote
# report_index.md with 33 entries while 31 verified Medium-shard
# findings + 7 Low-tier hypotheses were silently dropped. The Excluded
# Findings table read "None — all findings indexed." The v2.2.0 A.2
# promotion-receipt gate failed to catch this because its regex
# (`H-\d+`) didn't match L1 hypothesis IDs (`H-{S}\d+`) — fixed in
# v2.2.2 Fix 1, but defense-in-depth requires a gate that fires
# EARLIEST, post-Index and pre-tier-writer.
#
# A post-Index gate catches dropout BEFORE expensive tier writers run.
# It also enforces the Excluded Findings table is honest: every
# verify_*.md hypothesis ID must appear in either the Master Finding
# Index Internal Hypothesis column OR the Excluded Findings table.
# Generic across L1 and SC; reads only what already exists.
def _collect_verify_hypothesis_ids(scratchpad: Path) -> set[str]:
    """Return the set of hypothesis IDs from filesystem verify_*.md files.

    Source of truth: filesystem glob, NOT verify_core.md. The whole
    point of the post-Index gate is to detect when verify_core.md or
    the Index Agent missed shards. Excludes verify_core / skeptic /
    judge / retry-hint files.

    Hypothesis ID is extracted from filename: `verify_H-C01.md` →
    `H-C01`. Tolerates the `verify_F-{id}.md` legacy naming
    (`verify_F-H-M27.md` → `H-M27`).
    """
    ids: set[str] = set()
    for f in scratchpad.glob("verify_*.md"):
        if f.name in {"verify_core.md", "verify_core_full.md"}:
            continue
        if f.name.endswith(_RETRY_HINT_SUFFIX):
            continue
        if "skeptic" in f.name or "judge" in f.name:
            continue
        # `verify_H-C01.md` or `verify_F-H-C01.md` or `verify_L1-H-12.md`
        # Permissive: capture everything between `verify_(F-)?` and `.md`
        # then accept if it ends in a digit (drops malformed names but
        # tolerates SC `H-1` and L1 `H-C01` / `H-M27` / `H-L07` shapes).
        m = re.match(
            r"verify_(?:F-)?([A-Z][A-Z0-9\-]*\d+)\.md$",
            f.name,
        )
        if m:
            ids.add(m.group(1))
    return ids


def _collect_index_acknowledged_ids(
    scratchpad: Path,
) -> tuple[set[str], set[str], list[str]]:
    """Return (master_ids, excluded_ids, master_id_list) from report_index.md.

    master_ids: SET of internal-hypothesis-ID tokens in the Master Finding
    Index section.
    excluded_ids: SET of same in the Excluded Findings table.
    master_id_list: LIST (with duplicates preserved) of every internal ID
    occurrence in Master, for v2.2.3 uniqueness checking. The L1-H-08
    duplicate-binding bug observed in v2.2.2 (one internal ID mapped to
    TWO different report findings) requires checking occurrence count,
    not just presence.

    We harvest from the whole section by regex rather than column-positional
    parsing because Index Agent column order varies (SC vs L1 schemas).
    """
    master: set[str] = set()
    excluded: set[str] = set()
    master_list: list[str] = []
    p = scratchpad / "report_index.md"
    if not p.exists():
        return master, excluded, master_list
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return master, excluded, master_list

    def _sections(name_re: str) -> str:
        return "\n\n".join(
            m.group(0)
            for m in re.finditer(
                rf"(?im)^##\s+{name_re}.*?(?=^##\s|\Z)",
                text,
                re.MULTILINE | re.DOTALL,
            )
        )

    master_sec = _sections(r"(?:Master\s+Finding\s+Index|Promoted\s+Findings)")
    excluded_sec = _sections(r"Excluded\s+Findings")

    # For Master, walk row-by-row so each row contributes ONE internal-ID
    # occurrence even if the row mentions cross-references. This is the
    # uniqueness check substrate.
    #
    # ID-position heuristic: in both SC and L1 schemas, the Master Finding
    # Index has the Report ID at column 0 (e.g., `H-06`) and the Internal
    # Hypothesis ID late in the row (e.g., column N-2: `L1-H-08`). Taking
    # the FIRST regex match would harvest the Report ID instead of the
    # Internal Hypothesis ID — they share the `H-NN` shape after v2.2.2
    # widening. Use the LAST match per row, which biases toward the
    # Internal Hypothesis column.
    for line in master_sec.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        # Skip header / separator rows.
        upper = s.upper()
        if _is_separator_row(s) or (
            "REPORT ID" in upper and "TITLE" in upper
        ):
            continue
        # v2.5.0: strip parenthetical content before ID extraction.
        # LLM violation of Rule 3/4 writes "CH-3 (H-2, H-27)" — the
        # parenthetical constituents cause false duplicate-binding when
        # H-27 also has its own standalone row. Stripping parens keeps
        # the last-match heuristic clean: only CH-3 survives.
        s_clean = re.sub(r"\([^)]*\)", "", s)
        cells = [c.strip() for c in s_clean.strip("|").split("|")]
        candidate_cells = list(reversed(cells[1:])) if len(cells) > 1 else [s_clean]
        row_ids: list[str] = []
        for cell in candidate_cells:
            row_ids = [
                m.group(1).upper()
                for m in _INTERNAL_FINDING_ID_RE.finditer(cell)
            ]
            if row_ids:
                break
        if not row_ids:
            continue
        # v2.8.10/v2.8.13: a MULTI-CONSTITUENT row (a chain tagged
        # CHAIN-UPGRADE/CHAIN-DOWNGRADE, OR any `+`-joined compound/consolidation
        # row with >1 internal ID) lists CONSTITUENTS that legitimately also have
        # their own single-ID rows — compound findings reference standalone
        # findings (see the Cross-Reference Map design and the prompt's allowed
        # `H-2+H-13` form). Counting those constituents toward the uniqueness
        # substrate falsely flags every compound row as a duplicate binding —
        # the dominant report_index HALT class (PulsechainGameWards: ~31 dups,
        # of which only ~9 were chain-tagged; the rest were non-chain compound).
        # v2.8.13 extends the v2.8.10 chain-only exemption to ALL multi-ID rows:
        # index every constituent for completeness (`master` set) but EXCLUDE
        # multi-constituent rows from `master_list` so the duplicate-binding
        # check only counts rows whose SOLE binding is a single internal ID.
        # Genuine double-binds (same id sole-bound in two single-ID rows) still
        # fire. (Over-consolidation quality is a separate, non-halt concern.)
        unique_ids = list(dict.fromkeys(row_ids))
        is_multi_constituent = (
            len(unique_ids) > 1
            or bool(re.search(r"CHAIN-(?:UP|DOWN)GRADE", s, re.IGNORECASE))
        )
        for tok in unique_ids:
            master.add(tok)
            if not is_multi_constituent:
                master_list.append(tok)

    for m in _INTERNAL_FINDING_ID_RE.finditer(excluded_sec):
        excluded.add(m.group(1))
    return master, excluded, master_list


def _collect_consolidation_absorbed_ids(scratchpad: Path) -> set[str]:
    """Return internal IDs explicitly absorbed by report_index Consolidation Map.

    Consolidated findings should not be repaired back into the Master Finding
    Index as duplicates. The Master row owns one canonical internal ID; the map
    owns the absorbed siblings.
    """
    p = scratchpad / "report_index.md"
    if not p.exists():
        return set()
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()
    m = re.search(
        r"(?ims)^##\s+Consolidation\s+Map\b.*?(?=^##\s|\Z)",
        text,
    )
    if not m:
        return set()
    section = m.group(0)
    lines = [ln.strip() for ln in section.splitlines() if ln.strip().startswith("|")]
    if not lines:
        return set()
    header_cells: list[str] = []
    absorbed_cols: set[int] = set()
    ids: set[str] = set()
    for line in lines:
        if _is_separator_row(line):
            continue
        cells = [c.strip().lower() for c in line.strip("|").split("|")]
        if not header_cells:
            header_cells = cells
            for idx, cell in enumerate(cells):
                if any(token in cell for token in (
                    "absorbed", "consolidated from", "source", "source ids",
                    "source findings",
                )) and not any(token in cell for token in (
                    "report id", "canonical", "representative", "title", "reason",
                )):
                    absorbed_cols.add(idx)
            continue
        if not absorbed_cols:
            return set()
        raw_cells = [c.strip() for c in line.strip("|").split("|")]
        for idx in absorbed_cols:
            if idx < len(raw_cells):
                ids.update(m.group(1) for m in _INTERNAL_FINDING_ID_RE.finditer(raw_cells[idx]))
    return ids


def _report_index_dropped_ids(scratchpad: Path) -> list[str]:
    """Return the reference IDs the report index has NOT accounted for.

    This is the EXACT reference/indexed computation used by
    _check_index_completeness, factored out so the dropout-recovery backfill
    consumes the identical set with zero divergence. reference = verify IDs
    union coverage-seed superset; indexed = master|excluded|absorbed|coverage.
    """
    verify_ids = _collect_verify_hypothesis_ids(scratchpad)
    seed_ids = _collect_report_index_seed_ids(scratchpad)
    reference_ids = set(verify_ids) | set(seed_ids)
    if not reference_ids:
        return []
    master_ids, excluded_ids, _master_list = _collect_index_acknowledged_ids(scratchpad)
    absorbed_ids = _collect_consolidation_absorbed_ids(scratchpad)
    coverage_ids = _collect_report_coverage_acknowledged_ids(scratchpad)

    def _zn(s: str) -> str:
        return re.sub(r"-0+(\d)", r"-\1", s)

    norm_ref = {_zn(v): v for v in reference_ids}
    norm_indexed = {
        _zn(i) for i in (master_ids | excluded_ids | absorbed_ids | coverage_ids)
    }
    dropped_norm = sorted(set(norm_ref) - norm_indexed)
    return [norm_ref[n] for n in dropped_norm]


def _backfill_report_coverage_dropouts(scratchpad: Path) -> int:
    """Recall-safe completeness guarantee: append every still-dropped reference
    ID to report_coverage.md's Raw Candidate Ledger as a DEFERRED disposition so
    the completeness gate passes deterministically instead of halting a finished
    audit at the last mile.

    This is the residual net behind the mechanical report-index builder: any
    reference ID that has no verify file (e.g. a depth auto-find with only a
    coverage-seed entry) and therefore is not enumerated into the body still
    gets an explicit, non-UNACCOUNTED ledger row. Findings are NEVER silently
    dropped — they are mechanically accounted with a human-promotion note.
    Returns the number of IDs backfilled.
    """
    dropped = _report_index_dropped_ids(scratchpad)
    if not dropped:
        return 0
    path = scratchpad / "report_coverage.md"
    try:
        existing = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    except Exception:
        existing = ""

    rows = [
        f"| mechanical-dropout-backfill | {fid} | unknown | DEFERRED | "
        f"report_index dropout — mechanically backfilled for completeness; "
        f"see verify_{fid}.md / coverage seed; pending human promotion to body |"
        for fid in dropped
    ]

    # CRITICAL: the coverage parser (_collect_report_coverage_acknowledged_ids /
    # _validate_report_coverage_accounting) reads rows ONLY between a ledger
    # header and the NEXT `## ` heading. If a ledger section already exists
    # mid-file (the LLM-written coverage case, with later sections after it),
    # appending rows at EOF puts them OUTSIDE that section → invisible to the
    # parser. So insert INTO the existing ledger section (right before the next
    # `## ` heading); only create a new section when none exists.
    ledger_re = re.compile(
        r"(?im)^##\s+(?:Raw\s+)?(?:Candidate|Coverage|Promotion)\s+Ledger\b.*$"
    )
    m = ledger_re.search(existing)
    if m:
        rest = existing[m.end():]
        nxt = re.search(r"(?m)^##\s+", rest)
        sec_end = m.end() + (nxt.start() if nxt else len(rest))
        head = existing[:sec_end].rstrip("\n")
        tail = existing[sec_end:]
        new_text = head + "\n" + "\n".join(rows) + "\n"
        if tail.strip():
            new_text += "\n" + tail.lstrip("\n")
    else:
        prefix = existing
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        new_text = (
            prefix
            + "\n## Raw Candidate Ledger\n"
            + "| Source File | Candidate ID / Label | Severity Signal | Status | "
            "Report ID / Refutation / Reason |\n"
            + "|-------------|----------------------|-----------------|--------|"
            "---------------------------------|\n"
            + "\n".join(rows) + "\n"
        )
    try:
        path.write_text(new_text, encoding="utf-8")
    except Exception as exc:  # pragma: no cover - filesystem failure
        logging.getLogger("plamen.validators").warning(
            f"[report_index] coverage dropout backfill write failed: {exc!r}"
        )
        return 0
    return len(dropped)


def _check_index_completeness(
    scratchpad: Path, project_root: str | None = None, write_retry_hint: bool = True
) -> list[str]:
    """Post-Index gate: every verify hypothesis ID must be indexed or excluded.

    Generic across L1 and SC. Returns issue list; empty = pass.

    On failure, writes a delta retry hint that names the missing IDs,
    so the Index Agent retry sees an explicit checklist rather than
    re-doing the same enumeration that just failed.
    """
    verify_ids = _collect_verify_hypothesis_ids(scratchpad)
    # TASK C reconciliation backbone: the driver-written coverage seed is the
    # AUTHORITATIVE completeness superset (it unions verify IDs + finding_mapping
    # + dedup + severity-binding IDs). When the report_index is sharded by tier,
    # this is what guarantees no finding falls BETWEEN shards: every seed ID must
    # receive exactly one disposition in the merged report_index.md. The seed is
    # a strict superset of verify_ids, so reconciling against (verify ∪ seed)
    # only ever ADDS coverage requirements — it can never hide a real dropout.
    seed_ids = _collect_report_index_seed_ids(scratchpad)
    reference_ids = set(verify_ids) | set(seed_ids)
    if not reference_ids:
        return []  # No verify outputs / no seed = nothing to validate against
    master_ids, excluded_ids, master_list = _collect_index_acknowledged_ids(
        scratchpad
    )
    absorbed_ids = _collect_consolidation_absorbed_ids(scratchpad)
    if not master_ids and not excluded_ids:
        ri = scratchpad / "report_index.md"
        if ri.exists():
            try:
                ri_size = ri.stat().st_size
            except Exception:
                ri_size = 0
            if ri_size > 200:
                return [
                    "index completeness: report_index.md exists "
                    f"({ri_size} bytes) but parsed 0 master/excluded IDs — "
                    "possible parse failure in _collect_index_acknowledged_ids"
                ]
        return []

    issues: list[str] = []

    # v2.2.3: dedup check. Each internal hypothesis ID must appear EXACTLY
    # ONCE in the Master Finding Index. Live failure mode (a prior L1 run):
    # L1-H-08 was bound to two different report findings (H-06 + H-24);
    # count-based gate satisfied because the ID appeared at least once,
    # but the row-level binding was duplicated. Mechanical detection:
    # any ID that appears 2+ times in the row-by-row master list is bound
    # to multiple report findings.
    from collections import Counter
    master_counts = Counter(master_list)
    duplicates = sorted(
        i for i, c in master_counts.items() if c > 1
    )
    if duplicates:
        sample = ", ".join(duplicates[:5])
        more = f" (+{len(duplicates)-5} more)" if len(duplicates) > 5 else ""
        issues.append(
            f"index duplicate binding: {len(duplicates)} internal ID(s) "
            f"appear in multiple Master Finding Index rows: {sample}{more}. "
            "Each internal hypothesis ID MUST bind to exactly one report ID."
        )

    # Normalize leading zeros so H-1 matches H-01, INV-2 matches INV-002.
    # LLM verifiers name files and Index Agent writes table rows independently;
    # zero-padding mismatch is the #1 false-alarm class in completeness gates.
    def _zn(s: str) -> str:
        return re.sub(r"-0+(\d)", r"-\1", s)

    # TASK C: reconcile against the union of verify IDs and the coverage-seed
    # superset. The seed enumerates every finding/hypothesis the report MUST
    # account for across tier shards; reconciling against it (not just verify
    # IDs) is what mechanically guarantees a sharded index drops nothing
    # between shards.
    norm_ref = {_zn(v): v for v in reference_ids}
    coverage_ids = _collect_report_coverage_acknowledged_ids(scratchpad)
    norm_indexed = {_zn(i) for i in (master_ids | excluded_ids | absorbed_ids | coverage_ids)}
    dropped_norm = sorted(set(norm_ref) - norm_indexed)
    dropped = [norm_ref[n] for n in dropped_norm]
    if not dropped:
        return issues
    src_label = (
        "verify_*.md / coverage-seed" if seed_ids else "verify_*.md"
    )
    if not write_retry_hint:
        sample = ", ".join(dropped[:5])
        more = f" (+{len(dropped)-5} more)" if len(dropped) > 5 else ""
        issues.append(
            f"index dropout: {len(dropped)} {src_label} finding ID(s) "
            f"absent from Master Finding Index, Excluded Findings, Consolidation Map, and report_coverage.md: "
            f"{sample}{more}. See report_index{_RETRY_HINT_SUFFIX}."
        )
        return issues

    # Write delta retry hint for the Index Agent.
    try:
        hint_path = scratchpad / f"report_index{_RETRY_HINT_SUFFIX}"
        body = (
            "## v2.2.2 — Index completeness retry hint\n\n"
            f"The previous report_index attempt indexed {len(norm_indexed)} "
            "hypothesis IDs but the bounded ledgers (verify_*.md files + "
            f"report_index_coverage_seed.md) enumerate {len(reference_ids)} "
            f"finding/hypothesis ID(s). Specifically, these "
            f"{len(dropped)} ID(s) are present in the coverage seed / appear "
            "on disk as `verify_<ID>.md` but are NEITHER in the Master Finding "
            "Index, Excluded Findings table, Consolidation Map, nor report_coverage.md:\n\n"
            + "\n".join(f"- `{i}`" for i in dropped)
            + "\n\n"
            "Read each missing finding (`verify_<ID>.md` when present, else the "
            "coverage-seed row) and either (a) assign it a report ID in the "
            "Master Finding Index, or (b) place it in the Excluded Findings "
            "table with a stated reason (FALSE_POSITIVE / DUPLICATE OF X-NN / "
            "CONSOLIDATED INTO X-NN). Silent omission is a workflow violation.\n"
        )
        hint_path.write_text(body, encoding="utf-8")
    except Exception:
        pass

    sample = ", ".join(dropped[:5])
    more = f" (+{len(dropped)-5} more)" if len(dropped) > 5 else ""
    issues.append(
        f"index dropout: {len(dropped)} {src_label} finding ID(s) "
            f"absent from Master Finding Index, Excluded Findings, Consolidation Map, and report_coverage.md: "
        f"{sample}{more}. See report_index{_RETRY_HINT_SUFFIX}."
    )
    return issues


def _repair_report_index_dropouts(scratchpad: Path) -> list[str]:
    """Mechanically index dropped verify IDs instead of degrading silently.

    The recovery is deliberately conservative: it never invents analysis and
    never blanket-marks missing IDs as false positives. It reads each existing
    `verify_<ID>.md`; verifier-excluded IDs go to Excluded Findings, while
    reportable verifier statuses receive deterministic report IDs in a
    separate Master Finding Index recovery table.
    """
    idx_path = scratchpad / "report_index.md"
    if not idx_path.exists():
        return []
    verify_ids = _collect_verify_hypothesis_ids(scratchpad)
    master_ids, excluded_ids, _ = _collect_index_acknowledged_ids(scratchpad)
    absorbed_ids = _collect_consolidation_absorbed_ids(scratchpad)
    # v2.4.8: normalize leading zeros (same as _check_index_completeness)
    # so repair doesn't inject duplicates when H-01 == H-1.
    def _zn(s: str) -> str:
        return re.sub(r"-0+(\d)", r"-\1", s)
    coverage_ids = _collect_report_coverage_acknowledged_ids(scratchpad)
    norm_indexed = {_zn(i) for i in (master_ids | excluded_ids | absorbed_ids | coverage_ids)}
    dropped = sorted(v for v in verify_ids if _zn(v) not in norm_indexed)
    if not dropped:
        return []

    queue_rows = {
        (r.get("finding id") or "").strip(): r
        for r in parse_verification_queue_rows(scratchpad)
        if (r.get("finding id") or "").strip()
    }
    counters = _next_report_id_counters(scratchpad)
    active_rows: list[str] = []
    excluded_rows: list[str] = []
    repaired: list[str] = []

    for fid in dropped:
        verify_path = _verify_file_for_id(scratchpad, fid)
        try:
            verify_text = verify_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            verify_text = ""
        row = queue_rows.get(fid, {})
        status = _verifier_status_from_text(verify_text)
        title = (
            row.get("title", "").strip()
            or _first_heading_title(verify_text)
            or "Recovered verified finding"
        )
        title = re.sub(r"\s+", " ", title).replace("|", "/").strip()
        severity = _severity_name_from_text(verify_text, row)
        location = (
            _first_production_location_for_validator(
                verify_text,
                row.get("location", "").strip(),
            )
            or f"verify_{fid}.md"
        ).replace("|", "/")
        evidence = (
            _field_from_markdown(verify_text, ("Evidence Tag", "Evidence Tags", "Evidence"))
            or _field_from_markdown(verify_text, ("Preferred Tag", "Preferred Evidence"))
            or row.get("preferred tag", "")
            or "CODE-TRACE"
        ).replace("|", "/")

        if any(tok in status for tok in (
            "APPENDIX_ONLY",
            "DROP_FALSE_POSITIVE",
            "DROP_NON_SECURITY",
            "DROP_DESIGN_CONFIRMATION",
            "DROP_UNACTIONABLE_SPECULATION",
            "FALSE_POSITIVE",
            "REFUTED",
            "INFEASIBLE",
        )):
            excluded_rows.append(
                f"| {fid} | {status} | Recovered from verify_{fid}.md; verifier marked non-reportable. |"
            )
            repaired.append(fid)
            continue
        if "DUPLICATE" in status or "CONSOLIDATED" in status:
            excluded_rows.append(
                f"| {fid} | {status} | Recovered from verify_{fid}.md; verifier marked duplicate/consolidated. |"
            )
            repaired.append(fid)
            continue

        prefix = _report_prefix_for_severity(severity)
        counters[prefix] += 1
        rid = f"{prefix}-{counters[prefix]:02d}"
        active_rows.append(
            f"| {rid} | {title} | {severity} | {location} | {evidence} | "
            f"Mechanical index recovery from verify_{fid}.md |  | {fid} |"
        )
        repaired.append(fid)

    if not repaired:
        return []

    try:
        text = idx_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    def _insert_rows_into_table(
        source: str,
        heading_re: str,
        rows_to_insert: list[str],
        fallback_section: str,
    ) -> str:
        if not rows_to_insert:
            return source
        heading = re.search(
            rf"(?im)^##\s+{heading_re}\b[^\n]*$",
            source,
        )
        if not heading:
            cut = _find_report_index_cut_for_active_recovery(source)
            return source[:cut].rstrip() + "\n\n" + fallback_section + "\n\n" + source[cut:]
        section_start = heading.end()
        next_heading = re.search(r"(?im)^##\s+", source[section_start:])
        section_end = section_start + next_heading.start() if next_heading else len(source)
        section = source[section_start:section_end]
        table_lines = list(re.finditer(r"(?m)^\|.*\|\s*$", section))
        if len(table_lines) < 2:
            return (
                source[:section_end].rstrip()
                + "\n\n"
                + fallback_section.split("\n", 1)[1].lstrip()
                + "\n"
                + source[section_end:]
            )
        insert_at = section_start + table_lines[-1].end()
        return source[:insert_at].rstrip() + "\n" + "\n".join(rows_to_insert) + source[insert_at:]

    if active_rows:
        fallback_active = "\n".join([
            "## Master Finding Index",
            "| Report ID | Title | Severity | Location | Evidence Tag | Recovery Note | Trust Adj. | Internal Hypothesis ID |",
            "|-----------|-------|----------|----------|--------------|---------------|------------|------------------------|",
            *active_rows,
        ])
        text = _insert_rows_into_table(
            text,
            r"Master\s+Finding\s+Index",
            active_rows,
            fallback_active,
        )

    if excluded_rows:
        fallback_excluded = "\n".join([
            "## Excluded Findings",
            "| Internal ID | Verdict | Reason |",
            "|-------------|---------|--------|",
            *excluded_rows,
        ])
        text = _insert_rows_into_table(
            text,
            r"Excluded\s+Findings",
            excluded_rows,
            fallback_excluded,
        )

    idx_path.write_text(text, encoding="utf-8")
    return repaired


def _is_substantive_body_evidence(value: str) -> bool:
    """Return True when a verifier field/section can seed a body section."""
    text = _llm_norm(value or "")
    text = re.sub(r"(?s)```.*?```", " ", text)
    text = re.sub(r"[*_`>#|\[\]()-]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return False
    lowered = text.lower().strip(" .:;")
    if lowered in {
        "n/a", "na", "none", "nil", "null", "unknown", "todo", "tbd",
        "missing", "not provided", "not available", "not applicable",
        "omitted", "no description", "no recommendation", "see above",
        "see verification artifact",
    }:
        return False
    if re.fullmatch(
        r"(?:no|none|missing|not\s+provided|not\s+available)\s+"
        r"(?:description|summary|recommendation|fix|mitigation|narrative)s?",
        lowered,
    ):
        return False
    return bool(re.search(r"[A-Za-z0-9]", text))


def _body_writer_evidence_fields(verify_text: str) -> tuple[str, str]:
    """Extract verifier narrative fields for report body manifests.

    Verifier outputs use both inline fields (`**Description**: ...`) and
    section-headed markdown (`## Description\n...`). Body-writer gating must
    treat those formats identically; otherwise real verifier narratives are
    marked REPORT-BLOCKED and downstream writers receive empty seeds.
    """
    text = verify_text or ""
    desc = _field_or_section(
        text,
        ("Description", "Finding Summary", "Summary", "Root Cause"),
        ("Description", "Finding Summary", "Summary", "Analysis", "Code Trace", "Root Cause"),
        fallback="",
        max_chars=5000,
    ).strip()
    rec = _field_or_section(
        text,
        ("Recommendation", "Suggested Fix", "Suggested fix", "Fix", "Mitigation"),
        ("Recommendation", "Suggested Fix", "Suggested fix", "Fix", "Mitigation"),
        fallback="",
        max_chars=5000,
    ).strip()
    return desc, rec


def _is_evidence_missing_for_body(verify_text: str) -> bool:
    """REPORT-BLOCKED triggers when a verify_*.md has no usable narrative.

    Conservative test: both Description and Recommendation must be absent or
    non-substantive. A single substantive field/section is enough for a body
    writer to produce a section, while empty headings and N/A boilerplate stay
    blocked.
    """
    desc, rec = _body_writer_evidence_fields(verify_text or "")
    return not (
        _is_substantive_body_evidence(desc)
        or _is_substantive_body_evidence(rec)
    )


# RPT-2: single source of truth for the PoC-evidence field/section names a body
# section may use. Both the per-shard gate (_validate_report_body) and the
# post-assembly gate (_run_report_quality_gate) read from these so their
# acceptance sets can never drift (the prior drift hard-halted Evidence-Tag-only
# UNVERIFIED/CODE-TRACE sections). Includes Evidence Tag/Evidence per v2.7.5.
_BODY_POC_FIELDS = (
    "PoC Result", "Execution Result", "Execution Output",
    "Test Output", "Proof", "PoC Attempt", "PoC Execution",
    "Evidence Tag", "Evidence",
)
_BODY_POC_SECTIONS = (
    "PoC Result", "Execution Result", "Execution Output",
    "Test Output", "Proof", "Reproduction", "PoC Attempt",
    "PoC Execution", "Evidence Tag", "Evidence",
)


def _validate_report_body(body: str, manifest: dict) -> dict:
    """Validate an LLM-written body file against its shard manifest.

    Returns {"ok": bool, "missing": [...], "extras": [...], "integrity": [...],
             "blocked_violations": [...], "unexpected_blocked": [...],
             "duplicates": [...]}.
    """
    findings = manifest.get("findings", []) or []
    expected_list = [f["report_id"].upper() for f in findings if f.get("report_id")]
    body_id_list = _extract_report_ids_from_body(body)
    expected_ids = set(expected_list)
    body_ids = set(body_id_list)

    missing = sorted(expected_ids - body_ids)
    extras = sorted(body_ids - expected_ids)
    from collections import Counter
    duplicates = sorted(
        rid for rid, n in Counter(body_id_list).items() if n > 1
    )

    integrity_errors: list[str] = []
    blocked_violations: list[str] = []
    content_errors: list[str] = []
    for f in findings:
        rid = f.get("report_id", "").upper()
        if rid in missing:
            continue
        section = _section_for_report_id(body, rid)
        # Location integrity: the manifest location must appear somewhere in
        # the section (case-insensitive substring match - tolerates LLM
        # rewording around it).
        # v2.5.0: multi-range locations like "file.sol:L361-366,L381-386"
        # may be split by the LLM into separate lines or table rows. Check
        # the full string first; if that fails, check the base file path
        # (before ':') as a relaxed match. The file path is the strongest
        # identity signal — line ranges vary with LLM formatting.
        loc = f.get("location", "").strip()
        if loc and not _location_present_in_body(loc, section):
            integrity_errors.append(
                f"{rid}: location {loc!r} not present in body section"
            )
        if f.get("report_blocked"):
            section_upper = section.upper()
            severity = normalize_severity(str(f.get("severity", "") or "Medium"))
            if (
                severity in {"Critical", "High", "Medium"}
                and
                "[REPORT-BLOCKED" not in section_upper
                and "VERIFICATION NOT EXECUTED" not in section_upper
                and "[UNVERIFIED]" not in section_upper
            ):
                blocked_violations.append(
                    f"{rid}: report_blocked but no [REPORT-BLOCKED tag in body"
                )
        elif "[REPORT-BLOCKED" in section.upper():
            blocked_violations.append(
                f"{rid}: body has [REPORT-BLOCKED] but manifest has verified evidence"
            )
        severity = normalize_severity(str(f.get("severity", "") or "Medium"))
        if (
            severity in {"Critical", "High", "Medium"}
            and not f.get("report_blocked")
            and "VERIFICATION NOT EXECUTED" not in section.upper()
        ):
            if not _is_substantive_body_evidence(_field_or_section(
                section,
                ("Impact", "Security Impact", "Risk"),
                ("Impact", "Security Impact", "Risk"),
                fallback="",
                max_chars=2500,
            )):
                content_errors.append(f"{rid}: missing substantive Impact")
            # RPT-4: a self-declared [UNVERIFIED] finding by definition has no
            # PoC to report; requiring a substantive PoC Result for it just
            # forces boilerplate. Keep the Impact requirement; skip PoC Result
            # for UNVERIFIED. RPT-2: accept the Evidence Tag/Evidence field as a
            # valid PoC-evidence surface (parity with the post-assembly gate).
            # Fix 1: a [CONFIRMED] finding is verdict-confirmed on [CODE-TRACE]
            # with NO executed PoC — same no-PoC-to-report basis as [UNVERIFIED],
            # so it is exempt from the substantive-PoC-Result requirement too.
            # Fix 2: a [UNPROVEN-EXTERNAL] finding likewise has NO executed PoC
            # (its external leg could not be fork-verified for want of a
            # reachable RPC) — same no-PoC-to-report basis, so it is exempt too.
            _section_upper = section.upper()
            if "[UNVERIFIED]" not in _section_upper \
                    and "[CONFIRMED]" not in _section_upper \
                    and "[UNPROVEN-EXTERNAL]" not in _section_upper \
                    and not _is_substantive_body_evidence(_field_or_section(
                section,
                _BODY_POC_FIELDS,
                _BODY_POC_SECTIONS,
                fallback="",
                max_chars=2500,
            )):
                content_errors.append(f"{rid}: missing substantive PoC Result")

    # GATE-2: substantive-Impact/PoC adequacy is a prose/LLM-quality judgment,
    # not a mechanical guarantee. Per the WARN-not-halt doctrine it must NOT
    # flip `ok` (which gates the critical report_body_writer phase). It is kept
    # in the returned dict under "content" for telemetry; the consumer logs it
    # as a WARNING. Mechanical guarantees (missing/extra/duplicate IDs,
    # location integrity, report-blocked tag) stay hard.
    ok = not (
        missing or extras or duplicates or integrity_errors
        or blocked_violations
    )
    return {
        "ok": ok,
        "missing": missing,
        "extras": extras,
        "duplicates": duplicates,
        "integrity": integrity_errors,
        "blocked_violations": blocked_violations,
        "content": content_errors,
    }


_SOURCE_FILE_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])([A-Za-z0-9_./-]+\.(?:sol|rs|move|cairo|vy|py|js|ts|tsx|jsx|toml|yaml|yml|json|md))(?![A-Za-z0-9_./-])",
    re.IGNORECASE,
)
_FUNCTION_TOKEN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _location_present_in_body(expected_location: str, section: str) -> bool:
    """Return True when a report body preserves the expected source location.

    Body-writer manifests sometimes carry compact, human-authored locations
    such as ``A.sol, B.sol:admin setters``. Requiring that exact phrase in the
    body turns harmless wording differences into retries. The durable contract
    is source identity: concrete source files and named functions/selectors
    must survive the phase boundary.

    Keep this strict for generic/non-source locations. A phrase like
    ``Critical, [CODE-TRACE]`` contains no source token and must still be
    copied exactly or fail.
    """
    loc = (expected_location or "").strip()
    sec = section or ""
    if not loc:
        return True
    loc_l = loc.lower()
    sec_l = sec.lower()
    if loc_l in sec_l:
        return True

    source_files = {
        m.group(1).replace("\\", "/").split("/")[-1].lower()
        for m in _SOURCE_FILE_TOKEN_RE.finditer(loc)
    }
    if source_files:
        body_sources = {
            m.group(1).replace("\\", "/").split("/")[-1].lower()
            for m in _SOURCE_FILE_TOKEN_RE.finditer(sec)
        }
        functions = {
            m.group(1).lower()
            for m in _FUNCTION_TOKEN_RE.finditer(loc)
            if len(m.group(1)) > 1
        }
        body_functions = {
            m.group(1).lower()
            for m in _FUNCTION_TOKEN_RE.finditer(sec)
            if len(m.group(1)) > 1
        }

        # One concrete file token is enough for multi-file shorthand. If the
        # body names source files but none match the manifest, fail even if a
        # function token appears in the title; otherwise stale titles can mask
        # a section copied from a different verified finding.
        if source_files & body_sources:
            return True
        if body_sources:
            return False
        if functions and (functions & body_functions):
            return True
        return False

    base_file = loc.split(":")[0].strip() if ":" in loc else ""
    return bool(base_file and base_file.lower() in sec_l)


def _maybe_skip_empty_body_writer(scratchpad: Path, phase_name: str) -> bool:
    """Phase E11 follow-up #1: deterministic skip for empty-shard body writers.

    When `_build_body_writer_manifests` produces no manifest for a shard
    (because the tier has 0 findings after dedup + verdict filtering), the
    body-writer phase has nothing to author. Calling the LLM is wasteful
    and risks the LLM producing empty/stub output that fails the legacy
    tier confirmation handler.

    This helper:
      - Returns False (don't skip) when a manifest exists for the shard.
      - Returns True (do skip) and writes an authentic empty-tier note to
        the tier file when the manifest is absent. The caller is expected
        to mark the phase complete and continue.
    """
    if not phase_name.startswith("report_body_writer_"):
        return False
    shard_key = phase_name.replace("report_body_writer_", "report_")
    manifests_dir = scratchpad / "body_manifests"
    manifest_path = manifests_dir / f"{shard_key}.json"
    if manifest_path.exists():
        # Manifest emitted for this shard - LLM body writer must run.
        return False
    # Find any sharded variant (e.g. report_critical_high_a.json) that may
    # have been emitted instead. If any exists, do NOT skip.
    for cand in (scratchpad / "body_manifests").glob(f"{shard_key}_*.json"):
        if cand.exists():
            return False
    expected_count = _expected_tier_assignment_count(scratchpad, shard_key)
    if expected_count is None or expected_count != 0:
        return False
    # No manifest: emit an authentic empty-tier note so the legacy
    # confirmation handler accepts the tier file as substantive.
    out_name = f"{shard_key}.md"
    pretty = shard_key.replace("report_", "").replace("_", " ").title()
    note = (
        f"# {pretty} Findings\n\n"
        f"_No findings of this severity tier were produced by the "
        "verification stage in this run. This is an authentic empty tier; "
        "it is not a placeholder for a missing finding. The driver "
        "deterministically skipped the body writer phase because the "
        f"per-shard manifest at `body_manifests/{shard_key}.json` was "
        "absent (zero reportable findings after Phase 5 / E1-E8 gates).\n\n"
        f"## Provenance\n\n"
        f"Phase: {phase_name} (skipped via empty-shard handler)\n"
        f"Manifest: absent\n"
        "Validator: soft-pass (no findings to validate)\n"
        "Empty-Tier-Auth: PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER\n"
    )
    (scratchpad / out_name).write_text(note, encoding="utf-8")
    # Sidecar write is best-effort; the body file's PLAMEN-DRIVER-
    # AUTHENTIC-EMPTY-TIER marker is the authoritative provenance signal
    # (see `_empty_tier_sidecar_valid` fallback). However we still log
    # any failure so future audits don't hit a silent path —
    # previously this `except Exception: pass` swallowed the sidecar
    # write error and halted the audit at the legacy tier validator
    # because the validator strictly required the sidecar. Live data
    # from a prior audit confirmed the sidecar was missing.
    try:
        manifests_dir.mkdir(parents=True, exist_ok=True)
        (manifests_dir / f"{shard_key}.empty.json").write_text(
            json.dumps(
                {
                    "auth": "PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER",
                    "phase": phase_name,
                    "shard": shard_key,
                    "assigned_count": 0,
                    "output": out_name,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception as exc:
        import logging as _logging
        _logging.getLogger("plamen.validators").warning(
            f"[empty-shard] sidecar write failed for {shard_key} "
            f"({exc!r}) — relying on body-file marker fallback"
        )
    return True


def _expected_tier_assignment_count(scratchpad: Path, shard_key: str) -> int | None:
    """Return current report-index assignment count for a tier/shard key."""
    m = re.match(r"^report_(critical_high|medium|low_info)(?:_[a-z])?$", shard_key)
    if not m:
        return None
    tier = m.group(1)
    try:
        if re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", shard_key):
            return len(compute_report_tier_shards(scratchpad, tier).get(shard_key, []))
        rows, source = get_tier_assignments(scratchpad)
        if source == "empty":
            return 0
        sevs = {
            "critical_high": ("C", "H"),
            "medium": ("M",),
            "low_info": ("L", "I"),
        }.get(tier, ())
        return sum(1 for row in rows if (row.get("severity") or "") in sevs)
    except Exception:
        return None


def _empty_tier_sidecar_valid(scratchpad: Path, shard_key: str, body_name: str) -> bool:
    """Accept an empty-tier body file when the driver-written sidecar OR
    the body file's own provenance marker confirm authenticity.

    Background: `_maybe_skip_empty_body_writer` writes BOTH a body file
    (containing the `PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER` marker in its
    Provenance section) AND a JSON sidecar at
    `body_manifests/<shard>.empty.json`. If the sidecar write fails (FS
    error, permission issue, race with a parallel sweep) the body file
    is still on disk and is still authentic — the marker is the source
    of truth. Pre-fix, the missing sidecar caused a hard "manifest
    missing" halt at the legacy tier confirmation handler, even though
    the body file was unambiguously a driver-authored empty tier.
    Post-fix, EITHER source of provenance is accepted.

    Caller must still verify the body file has no report IDs (done
    upstream at line 5624). The expected_count == 0 cross-check
    prevents impostors: a manifest could be wrong, but if the queue
    truly has a non-zero count for this tier, we refuse the empty-tier
    pass.
    """
    expected_count = _expected_tier_assignment_count(scratchpad, shard_key)
    if expected_count is None or expected_count != 0:
        return False
    sidecar = scratchpad / "body_manifests" / f"{shard_key}.empty.json"
    if sidecar.exists():
        try:
            data = json.loads(sidecar.read_text(encoding="utf-8"))
            if (
                data.get("auth") == "PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER"
                and data.get("shard") == shard_key
                and data.get("assigned_count") == 0
                and data.get("output") == body_name
            ):
                return True
        except Exception:
            pass
    # Sidecar missing / unreadable / mismatched — fall back to the body
    # file's own provenance marker. The marker is hard-coded by the
    # driver in `_maybe_skip_empty_body_writer` and cannot be produced
    # by an LLM agent or third-party tool.
    body_path = scratchpad / body_name
    if not body_path.exists():
        return False
    try:
        body_text = body_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    return "PLAMEN-DRIVER-AUTHENTIC-EMPTY-TIER" in body_text


def _generate_body_writer_retry_hint(scratchpad: Path, phase_name: str) -> str:
    """Phase E11 follow-up #3: build a delta-aware retry hint for body writer.

    When `_validate_tier_body_against_manifest` reports issues on attempt 1,
    the retry must be specific. Generic prompts re-yield the same
    hallucination/dropout pattern. This builds a hint enumerating:
      - Missing report IDs (must add)
      - Extra report IDs (must remove — likely hallucinations)
      - Integrity errors (location drift)
      - Report-blocked tag misses (must surface the [REPORT-BLOCKED: ...] tag)
    """
    shard_key = phase_name.replace("report_body_writer_", "report_")
    body_path = scratchpad / f"{shard_key}.md"
    if not body_path.exists():
        return f"Body file `{shard_key}.md` is missing entirely. Re-author it."
    manifests_dir = scratchpad / "body_manifests"
    manifest_path = manifests_dir / f"{shard_key}.json"
    if not manifest_path.exists():
        for cand in manifests_dir.glob(f"{shard_key}_*.json"):
            manifest_path = cand
            break
    if not manifest_path.exists():
        return ""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        body = body_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    result = _validate_report_body(body, manifest)
    if result.get("ok"):
        return ""
    parts = ["## RETRY HINT — body writer attempt 1 failed validator"]
    if result.get("missing"):
        parts.append(
            "\n### Missing report IDs (re-author from manifest)\n"
            + "\n".join(f"- {rid}" for rid in result["missing"])
        )
    if result.get("extras"):
        parts.append(
            "\n### Extra / hallucinated report IDs (REMOVE — not in manifest)\n"
            + "\n".join(f"- {rid}" for rid in result["extras"])
        )
    if result.get("integrity"):
        parts.append(
            "\n### Location / integrity violations (use the manifest's exact location string)\n"
            + "\n".join(f"- {s}" for s in result["integrity"])
        )
    if result.get("blocked_violations"):
        parts.append(
            "\n### Report-blocked tag violations\n"
            "- If the manifest row has `report_blocked: true`, prefix that heading with `[REPORT-BLOCKED: insufficient evidence]`.\n"
            "- If the manifest row has verified evidence, REMOVE any stale `[REPORT-BLOCKED: ...]` prefix.\n"
            + "\n".join(f"- {s}" for s in result["blocked_violations"])
        )
    if result.get("content"):
        parts.append(
            "\n### Required C/H/M body fields\n"
            "- Critical, High, and Medium sections must include substantive `Impact` and `PoC Result` fields.\n"
            "- Use manifest `poc_result` first; otherwise read the referenced `verify_files` and summarize the verifier's PoC/Execution Result or explicit not-executed reason.\n"
            + "\n".join(f"- {s}" for s in result["content"])
        )
    parts.append(
        "\n### Self-check before next attempt\n"
        f"- The manifest at `body_manifests/{manifest_path.name}` is the "
        "single source of truth.\n"
        "- Every entry there must appear in your output, no more, no less.\n"
        "- Include `**PoC Result**:` for each Critical/High/Medium report section.\n"
        "- Use the manifest's `location` verbatim — do not paraphrase paths.\n"
    )
    return "\n".join(parts) + "\n"


def _validate_tier_body_against_manifest(
    scratchpad: Path, phase_name: str, collect_content: "list[str] | None" = None
) -> list[str]:
    """Phase E5 wiring: validate the tier file against its body-writer manifest.

    `collect_content` (optional out-param): when a list is passed, substantive
    Impact/PoC content shortfalls are appended to it (Bucket 3 bounded-retry).
    They are NEVER added to the returned hard-issue list.

    Tier-phase names are mapped to manifest keys:
        report_critical_high  -> body_manifests/report_critical_high.json
        report_medium / _a / _b -> body_manifests/report_medium*.json
        report_low_info       -> body_manifests/report_low_info.json

    Returns issue strings if the body file fails coverage / no-extras /
    location-integrity / report-blocked-tag checks. Fails closed for V2
    report phases when the manifest is absent but a tier body exists.
    """
    _tier_m = re.match(
        r"^report_(critical_high|medium|low_info)(?:_[a-z])?$", phase_name
    )
    if not _tier_m:
        return []
    body_files = [f"{phase_name}.md"]
    manifest_keys = [phase_name]

    manifests_dir = scratchpad / "body_manifests"
    if not manifests_dir.exists():
        body_path = scratchpad / f"{phase_name}.md"
        if body_path.exists():
            try:
                existing_body = body_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                existing_body = ""
            if (
                not _extract_report_ids_from_body(existing_body)
                and _empty_tier_sidecar_valid(scratchpad, phase_name, f"{phase_name}.md")
            ):
                return []
            return [f"body validator: body_manifests missing for {phase_name}"]
        expected = _expected_tier_assignment_count(scratchpad, phase_name)
        if expected is not None and expected == 0:
            return []
        return [f"body validator: neither body_manifests dir nor {phase_name}.md exist"]
    issues: list[str] = []
    for body_name, mkey in zip(body_files, manifest_keys):
        manifest_path = manifests_dir / f"{mkey}.json"
        # When tier was sharded (e.g. report_critical_high split into _a/_b),
        # find any matching shard manifest.
        if not manifest_path.exists():
            for cand in manifests_dir.glob(f"{mkey}_*.json"):
                manifest_path = cand
                break
        if not manifest_path.exists():
            body_path = scratchpad / body_name
            if body_path.exists():
                try:
                    existing_body = body_path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    existing_body = ""
                if (
                    not _extract_report_ids_from_body(existing_body)
                    and _empty_tier_sidecar_valid(scratchpad, mkey, body_name)
                ):
                    continue
                issues.append(f"body validator: manifest {mkey}.json missing for {body_name}")
            continue
        body_path = scratchpad / body_name
        if not body_path.exists():
            issues.append(f"body validator: {body_name} missing")
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            body = body_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            issues.append(f"body validator: {body_name} unreadable ({exc})")
            continue
        result = _validate_report_body(body, manifest)
        # GATE-2: substantive-Impact/PoC adequacy is prose quality -> WARN only,
        # never a hard issue (it no longer flips result["ok"]). Surface it for
        # telemetry but do not gate the critical report_body_writer phase on it.
        if result.get("content"):
            log.warning(
                "[body validator %s] content (soft): %s",
                body_name, "; ".join(result["content"][:5]),
            )
            # Bucket 3: expose the content shortfall to callers that drive a
            # bounded PRODUCTIVE retry of the body-writer (then WARN-ship). This
            # never enters `issues`, so it cannot hard-halt; it only feeds the
            # retry trigger in _run_phase_validators.
            if collect_content is not None:
                collect_content.extend(result["content"])
        if not result.get("ok"):
            parts = []
            if result.get("missing"):
                parts.append(f"missing {len(result['missing'])} report ID(s): "
                             + ", ".join(result["missing"][:5]))
            if result.get("extras"):
                parts.append(f"extra {len(result['extras'])} hallucinated ID(s): "
                             + ", ".join(result["extras"][:5]))
            if result.get("duplicates"):
                parts.append(f"duplicate {len(result['duplicates'])} report section(s): "
                             + ", ".join(result["duplicates"][:5]))
            if result.get("integrity"):
                parts.append("integrity: " + "; ".join(result["integrity"][:3]))
            if result.get("blocked_violations"):
                parts.append("report-blocked tag missing: "
                             + "; ".join(result["blocked_violations"][:3]))
            issues.append(f"body validator [{body_name}] " + " | ".join(parts))
    return issues


# --- v2.2.1 Fix 2: UNRESOLVED authenticity cross-check -------------------
#
# Failure mode (a prior L1 run): C-02's report body was tagged
# `[UNRESOLVED — needs human review]` even though the Skeptic-Judge had
# ruled it SKEPTIC CORRECT (not UNRESOLVED). Tier writer or assembler
# widened the UNRESOLVED bucket — every body [UNRESOLVED] section MUST
# correspond to a Judge UNRESOLVED entry. Driver-side cross-check.
#
# Generic across L1 and SC. Reads only Phase 5.1 outputs (skeptic_judge*
# decisions) and the assembled report; no protocol-specific knowledge.
# v2.0.5 (P0.1): `_parse_skeptic_judge_table` was moved to plamen_parsers
# to respect the parsers→validators dependency direction. Validators import
# it as needed via the standard `from plamen_parsers import ...` pattern.

def _collect_judge_unresolved_ids(scratchpad: Path) -> set[str]:
    """Return finding IDs that the Skeptic-Judge ruled UNRESOLVED (or PARTIAL).

    Reads `skeptic_judge_decisions.md` (or any `judge_*.md` if the
    aggregate doesn't exist). Parsing strategy (in order):
    1. v2.0.5 (P0.2): `judge_decisions.json` sidecar if present AND fresh —
       the canonical machine-readable source written by the driver.
    2. v2.0.5 (P0.1): table-format parser via `_parse_skeptic_judge_table` —
       the current v2 skeptic prompt produces a single pipe-table.
    3. Legacy H2-section parser (per-finding `## {ID}` blocks with
       `Verdict|Decision: UNRESOLVED|PARTIAL` prose).
    4. Whole-file regex fallback for files with no H2 sections at all.

    PARTIAL is treated as UNRESOLVED-equivalent (both carry identical
    downstream semantics: demote 1 tier, retain in body, flag for review).
    """
    ids: set[str] = set()
    # v2.0.5 (P0.2): prefer the JSON sidecar when fresh.
    try:
        from plamen_parsers import read_judge_decisions_json_sidecar
        sidecar_rows = read_judge_decisions_json_sidecar(scratchpad)
    except ImportError:
        sidecar_rows = []
    if sidecar_rows:
        for row in sidecar_rows:
            if str(row.get("decision", "")).upper() in ("UNRESOLVED", "PARTIAL"):
                fid = row.get("finding_id")
                if fid:
                    ids.add(fid)
        if ids:
            return ids
        # Sidecar exists but had no UNRESOLVED rows — still return early
        # rather than fall through to potentially-stale markdown parse.
        return ids
    candidates: list[Path] = []
    primary = scratchpad / "skeptic_judge_decisions.md"
    if primary.exists():
        candidates.append(primary)
    else:
        candidates.extend(scratchpad.glob("judge_*.md"))
    if not candidates:
        return ids
    verdict_re = re.compile(
        r"(?:Verdict|Judge[ _]?Decision|Decision|Ruling)"
        r"\*{0,2}\s*[:=]\s*\*{0,2}\s*[`]?"
        r"(?:UNRESOLVED|PARTIAL)\b",
        re.IGNORECASE,
    )
    section_split_re = re.compile(r"(?m)^##\s+", re.MULTILINE)
    for f in candidates:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # v2.0.5 (P0.1): try table parse first. If the file has table rows,
        # they are authoritative.
        from plamen_parsers import _parse_skeptic_judge_table as _pt
        table_rows = _pt(text)
        if table_rows:
            for row in table_rows:
                if row["decision"] in ("UNRESOLVED", "PARTIAL"):
                    ids.add(row["finding_id"])
            continue  # this file's decisions captured from the table
        # Legacy fallback: H2 section / whole-file regex parse.
        parts = section_split_re.split(text)
        if len(parts) <= 1:
            if verdict_re.search(text):
                for m in _INTERNAL_FINDING_ID_RE.finditer(text):
                    ids.add(m.group(1))
            continue
        for chunk in parts:
            if not chunk.strip():
                continue
            if not verdict_re.search(chunk):
                continue
            for m in _INTERNAL_FINDING_ID_RE.finditer(chunk):
                ids.add(m.group(1))
    return ids


def _collect_judge_downgrade_map(scratchpad: Path) -> dict[str, str]:
    """Return {finding_id: target_severity} for DOWNGRADE rulings.

    v2.0.5 (P0.1+P0.2): refactored to share `_parse_skeptic_judge_table`
    with `_collect_judge_unresolved_ids`, and prefer the
    `judge_decisions.json` sidecar when fresh.
    """
    result: dict[str, str] = {}
    # v2.0.5 (P0.2): prefer the JSON sidecar.
    try:
        from plamen_parsers import read_judge_decisions_json_sidecar
        sidecar_rows = read_judge_decisions_json_sidecar(scratchpad)
    except ImportError:
        sidecar_rows = []
    if sidecar_rows:
        for row in sidecar_rows:
            if str(row.get("decision", "")).upper() != "DOWNGRADE":
                continue
            fid = row.get("finding_id")
            final_sev = row.get("final_severity")
            if fid and final_sev:
                result[fid] = final_sev
        return result
    # Fallback: parse markdown table directly.
    primary = scratchpad / "skeptic_judge_decisions.md"
    if not primary.exists():
        return result
    try:
        text = primary.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return result
    from plamen_parsers import _parse_skeptic_judge_table as _pt
    for row in _pt(text):
        if row["decision"] != "DOWNGRADE":
            continue
        fid = row["finding_id"]
        final_sev = row["final_severity"]
        if final_sev and fid:
            result[fid] = final_sev
    return result


def _collect_body_unresolved_report_ids(audit_report_text: str) -> set[str]:
    """Return report IDs of body sections tagged [UNRESOLVED ...].

    Matches `### [X-NN] Title [UNRESOLVED ...]` headers across all
    severity tiers (C/H/M/L/I).
    """
    ids: set[str] = set()
    pattern = re.compile(
        r"^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\][^\n]*\[UNRESOLVED",
        re.MULTILINE,
    )
    for m in pattern.finditer(audit_report_text):
        ids.add(m.group(1))
    return ids


def _check_unresolved_authenticity(
    scratchpad: Path, project_root: str
) -> list[str]:
    """Cross-check body [UNRESOLVED] sections against Judge UNRESOLVED rulings.

    Two failure modes:
      (a) Body has [UNRESOLVED] for a finding the Judge did NOT rule
          UNRESOLVED → tier-writer or assembler widened the bucket.
      (b) Judge ruled UNRESOLVED for a finding but the body has no
          [UNRESOLVED] section → demote-keep-in-body rule was skipped.

    Returns issues for both cases. Returns [] if Judge file is absent
    (Skeptic-Judge phase didn't run — common for Light/Core modes).
    """
    pr = Path(project_root) / "AUDIT_REPORT.md"
    if not pr.exists():
        return []
    try:
        rtxt = pr.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    # Skip-clean if Skeptic-Judge phase didn't run (no judge artifacts).
    # Light/Core modes don't run Skeptic-Judge; we have no ground truth
    # to validate body [UNRESOLVED] tags against, so don't flag.
    has_judge_artifacts = (
        (scratchpad / "skeptic_judge_decisions.md").exists()
        or any(scratchpad.glob("judge_*.md"))
    )
    if not has_judge_artifacts:
        return []

    judge_unresolved = _collect_judge_unresolved_ids(scratchpad)
    body_unresolved = _collect_body_unresolved_report_ids(rtxt)

    if not judge_unresolved and not body_unresolved:
        return []

    # Index Agent's report_index.md maps internal IDs → report IDs.
    # Build that map so we can check (a) against the right axis.
    ri = scratchpad / "report_index.md"
    internal_to_report: dict[str, str] = {}
    if ri.exists():
        try:
            itxt = ri.read_text(encoding="utf-8", errors="replace")
        except Exception:
            itxt = ""
        # Each Master Finding Index row contains a report ID in col 0
        # and an internal ID somewhere later in the row. Reuse the
        # tolerant assignment parser that already handles this.
        assignments, _source = get_tier_assignments(scratchpad)
        for a in assignments:
            rid = a.get("report_id")
            raw_fid = a.get("finding_id") or ""
            if not rid or not raw_fid:
                continue
            internal_to_report[raw_fid] = rid
            for m in _INTERNAL_FINDING_ID_RE.finditer(raw_fid):
                internal_to_report[m.group(1)] = rid

    issues: list[str] = []

    # Case (a): body [UNRESOLVED] without Judge UNRESOLVED ruling
    judge_promoted_to_report = {
        internal_to_report.get(i) for i in judge_unresolved
    }
    judge_promoted_to_report.discard(None)
    phantom = body_unresolved - judge_promoted_to_report
    if phantom:
        sample = ", ".join(sorted(phantom)[:5])
        issues.append(
            f"unresolved phantom: {len(phantom)} body section(s) tagged "
            f"[UNRESOLVED] without a corresponding Judge UNRESOLVED "
            f"ruling: {sample}. Tier-writer / assembler widened the "
            f"bucket; verify against skeptic_judge_decisions.md."
        )

    # Case (b): Judge UNRESOLVED but body lacks [UNRESOLVED] tag
    if internal_to_report and judge_unresolved:
        missing_in_body = judge_promoted_to_report - body_unresolved
        # Filter out IDs that are absent from the body entirely (those
        # are caught by the promotion-receipt gate, not this one).
        present_ids = set(re.findall(
            r"^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\]", rtxt, re.MULTILINE
        ))
        missing_tag = missing_in_body & present_ids
        if missing_tag:
            sample = ", ".join(sorted(missing_tag)[:5])
            issues.append(
                f"unresolved untagged: {len(missing_tag)} report ID(s) "
                f"with Judge UNRESOLVED ruling appear in body without "
                f"[UNRESOLVED] flag: {sample}. v2.2.0 A.3 "
                f"demote-keep-in-body rule skipped."
            )

    return issues


_MFI_HEADER_RE = re.compile(r"(?im)^##\s+Master Finding Index\b")


def _parse_master_finding_index_rows(scratchpad: Path) -> list[dict[str, str]]:
    """Parse report_index.md `## Master Finding Index` into row dicts.

    Header-aware column resolution (column order is not assumed). Returns
    rows with keys: report_id, severity, verification, trust_adj, internal.
    Empty list if the file/section is absent or has no header row.
    """
    ri = scratchpad / "report_index.md"
    if not ri.exists():
        return []
    try:
        text = ri.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    m = _MFI_HEADER_RE.search(text)
    if not m:
        return []
    section = text[m.end():]
    nxt = re.search(r"(?m)^##\s+", section)
    if nxt:
        section = section[: nxt.start()]

    rows: list[dict[str, str]] = []
    col_idx: dict[str, int] = {}
    for line in section.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        cells_lc = [c.lower() for c in cells]
        if not col_idx:
            if not any("report" in c and "id" in c for c in cells_lc):
                continue  # data before a recognizable header — skip
            for i, c in enumerate(cells_lc):
                if "report" in c and "id" in c:
                    col_idx["report_id"] = i
                elif "severity" in c:
                    col_idx["severity"] = i
                elif "verification" in c:
                    col_idx["verification"] = i
                elif "trust" in c:
                    col_idx["trust_adj"] = i
                elif "internal" in c or "hypothesis" in c:
                    col_idx["internal"] = i
            continue

        def _cell(key: str) -> str:
            i = col_idx.get(key, -1)
            return cells[i] if 0 <= i < len(cells) else ""

        rid = _cell("report_id")
        if not re.match(r"^\[?[CHMLI]-\d", rid, re.IGNORECASE):
            continue
        rows.append({
            "report_id": rid,
            "severity": _cell("severity"),
            "verification": _cell("verification"),
            "trust_adj": _cell("trust_adj"),
            "internal": _cell("internal"),
        })
    return rows


def _distinct_master_report_ids(scratchpad: Path) -> set[str]:
    """Distinct, normalized report-ID set from the Master Finding Index.

    The Master Finding Index is the report-body cardinality contract: one row
    per reportable finding, keyed by a clean severity-prefixed report ID
    (C-/H-/M-/L-/I-NN). Consolidation-Map-absorbed IDs are INTERNAL hypothesis
    IDs, not report IDs, so they never appear as Master rows — the distinct
    report-ID set already excludes them by construction.
    """
    ids: set[str] = set()
    for r in _parse_master_finding_index_rows(scratchpad):
        rid = (r.get("report_id") or "").strip().strip("[]").upper()
        m = re.match(r"([CHMLI])-0*(\d+)", rid)
        if m:
            ids.add(f"{m.group(1)}-{int(m.group(2))}")
    return ids


def _master_tier_counts(scratchpad: Path) -> dict[str, int]:
    """Per-tier counts derived from the distinct Master report-ID set."""
    counts = {"C": 0, "H": 0, "M": 0, "L": 0, "I": 0}
    for rid in _distinct_master_report_ids(scratchpad):
        tier = rid[:1]
        if tier in counts:
            counts[tier] += 1
    return counts


def validate_report_index_summary_master_parity(scratchpad: Path) -> list[str]:
    """A2: reconcile the Index Agent `## Summary` counts with the Master Finding
    Index distinct report-ID set, and REPAIR the Summary in place when they
    drift.

    A prior failure shape: the `## Summary` count table claimed 45 findings
    while the Master Finding Index actually listed 74 distinct report IDs. Tier
    writers dispatched against that inconsistent index then hallucinated IDs to
    "fill" the gap between the summary count and the body, producing ghost
    findings with no backing section.

    This is the UPSTREAM root fix (at report_index, before tier writers
    dispatch). The Master Finding Index is authoritative for cardinality — every
    distinct report ID is one reportable finding. When the LLM's Summary table
    disagrees, this gate rewrites the Summary table to match the Master via the
    existing ``_canonicalize_summary_table`` helper so tier writers receive a
    consistent index. It NEVER changes the Master rows themselves (no findings
    are added or dropped — only the summary metadata is corrected), and it is a
    NO-OP when the Summary already matches the Master (no false flag).

    Returns a list of human-readable repair notes (empty = already consistent).
    These are informational; the caller treats them as a self-heal, not a halt —
    a corrected summary is strictly better than an inconsistent one, and
    blocking the pipeline on a metadata mismatch the gate just fixed would be a
    recall-negative false halt.
    """
    ri = scratchpad / "report_index.md"
    if not ri.exists():
        return []
    master_counts = _master_tier_counts(scratchpad)
    # No Master rows parsed → nothing to reconcile against (don't touch the
    # Summary; a different gate handles a genuinely empty/malformed Master).
    if sum(master_counts.values()) == 0:
        return []

    summary_counts = _parse_report_index_summary_counts(scratchpad)
    if not summary_counts:
        # Master rows exist but no Summary table found: do not fabricate one
        # here (a separate structural gate owns Summary presence). No false flag.
        return []

    # Compare LLM Summary vs Master cardinality per tier.
    drift = {
        char: (summary_counts.get(char, 0), master_counts.get(char, 0))
        for char in ("C", "H", "M", "L", "I")
        if summary_counts.get(char, 0) != master_counts.get(char, 0)
    }
    if not drift:
        return []  # consistent — NO false flag

    try:
        text = ri.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [
            "report_index Summary/Master parity: could not read report_index.md "
            f"to repair drift {drift}: {exc}"
        ]
    new_text, deltas = _canonicalize_summary_table(text, master_counts)
    notes: list[str] = []
    if deltas:
        try:
            ri.write_text(new_text, encoding="utf-8")
            notes.append(
                "report_index Summary/Master parity: rewrote `## Summary` to "
                "match Master Finding Index cardinality "
                f"(Master total={sum(master_counts.values())}); "
                "deltas: " + ", ".join(f"{n} {d}" for n, d in deltas)
            )
        except Exception as exc:
            notes.append(
                "report_index Summary/Master parity: Summary disagrees with "
                f"Master {drift} but in-place repair failed: {exc}"
            )
    else:
        # Drift detected by tier-count comparison but the canonicalizer found no
        # `| Severity | N |` rows to rewrite (Summary table in a non-canonical
        # shape). Surface as a note so the inconsistency is visible, not silent.
        notes.append(
            "report_index Summary/Master parity: Summary counts disagree with "
            f"Master Finding Index {drift} but the `## Summary` table is not in "
            "the canonical `| Severity | N |` shape — could not auto-repair; "
            "Master remains authoritative for tier-writer dispatch"
        )
    return notes


def _check_report_index_unresolved_authenticity(scratchpad: Path) -> list[str]:
    """T1-b: every `UNRESOLVED(...)` Trust Adj. stamp must be backed by a
    real Skeptic-Judge UNRESOLVED/PARTIAL ruling, AND every
    `SEVERITY_OVERRIDE(...)` stamp must be backed by an entry in
    `_severity_override_ledger.json`.

    v2.0.7 (P1.4, Codex Point 2/3): split into two distinct provenance
    classes so the driver no longer self-contradicts:
      - UNRESOLVED(...) — Skeptic-Judge UNRESOLVED/PARTIAL ruling required.
      - SEVERITY_OVERRIDE(...) — driver auto-repair via
        `_repair_report_index_severity_provenance`; matching entry in
        `_severity_override_ledger.json` required.

    On a prior run the Index Agent stamped verifier-`CONTESTED` findings
    as Judge-`UNRESOLVED` AND the driver auto-repair function wrote more
    `UNRESOLVED(...)` stamps without Judge backing. This gate halted on
    both. P1 separates the two semantic surfaces.
    """
    rows = _parse_master_finding_index_rows(scratchpad)
    if not rows:
        return []
    issues: list[str] = []

    # ─── UNRESOLVED(...) — Skeptic-Judge backing required ───
    unresolved_rows = [
        r for r in rows
        if re.search(r"UNRESOLVED\s*\(", r.get("trust_adj", ""), re.IGNORECASE)
    ]
    if unresolved_rows:
        has_judge = (
            (scratchpad / "skeptic_judge_decisions.md").exists()
            or any(scratchpad.glob("judge_*.md"))
            or any(scratchpad.glob("skeptic_*.md"))
        )
        if not has_judge:
            ids = ", ".join(r["report_id"] for r in unresolved_rows[:8])
            issues.append(
                f"report_index unresolved authenticity: {len(unresolved_rows)} "
                "row(s) carry an UNRESOLVED(...) Trust Adj. stamp but NO "
                "Skeptic-Judge artifact exists in the scratchpad. UNRESOLVED is "
                "valid ONLY from a Skeptic-Judge ruling — a verifier CONTESTED "
                f"verdict is NOT UNRESOLVED. Affected rows: {ids}"
            )
        else:
            judge_unresolved = {
                re.sub(r"[^A-Z0-9]+", "", x.upper())
                for x in _collect_judge_unresolved_ids(scratchpad)
            }
            phantom: list[str] = []
            for r in unresolved_rows:
                internal = r.get("internal", "")
                toks = {
                    re.sub(r"[^A-Z0-9]+", "", t.upper())
                    for t in re.findall(r"[A-Za-z]+-\d+", internal)
                }
                if not (toks & judge_unresolved):
                    phantom.append(f"{r['report_id']} (internal {internal or '?'})")
            if phantom:
                issues.append(
                    f"report_index unresolved authenticity: {len(phantom)} row(s) "
                    "stamped UNRESOLVED(...) have no matching Skeptic-Judge "
                    "UNRESOLVED/PARTIAL ruling — likely a verifier CONTESTED verdict "
                    f"mislabeled as UNRESOLVED: {'; '.join(phantom[:8])}"
                )

    # ─── SEVERITY_OVERRIDE(...) — driver-ledger backing required ───
    override_rows = [
        r for r in rows
        if re.search(r"SEVERITY_OVERRIDE\s*\(", r.get("trust_adj", ""),
                     re.IGNORECASE)
    ]
    if override_rows:
        ledger = _read_severity_override_ledger(scratchpad)
        ledger_by_rid = {
            (rec.get("report_id") or "").upper(): rec for rec in ledger
        }
        unbacked: list[str] = []
        for r in override_rows:
            rid = (r.get("report_id") or "").upper()
            if rid not in ledger_by_rid:
                unbacked.append(f"{rid} (no ledger entry)")
        if unbacked:
            issues.append(
                f"report_index severity-override authenticity: "
                f"{len(unbacked)} row(s) carry a SEVERITY_OVERRIDE(...) "
                "Trust Adj. stamp without a matching entry in "
                "_severity_override_ledger.json. This token is "
                "driver-only — the Index Agent must NOT emit it manually. "
                f"Affected rows: {'; '.join(unbacked[:8])}"
            )
    return issues


def _chain_constituents_verified(scratchpad: Path, report_id: str) -> bool:
    """True when a chain/compound report row's constituents are ALL backed by a
    mechanically-proven verifier file (rule 8 constituent-verification exception).

    Reads the report_index `Verification Files` map: the row whose first cell is
    `report_id` and which names `verify_<ID>.md` file(s) is treated as the
    constituent set, and EVERY named file must show mechanical proof
    (`[POC-PASS]`/`[MEDUSA-PASS]`). Used to suppress the speculative-Critical
    flag for a chain whose Critical is inherited from a verified constituent
    (e.g. a chain over a standalone verified-Critical bug). Conservative: returns
    False when the map is absent or any constituent lacks mechanical proof.
    """
    idx = scratchpad / "report_index.md"
    if not idx.exists():
        return False
    try:
        text = idx.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    rid = report_id.strip().upper()
    if not rid:
        return False
    names: list[str] = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells or cells[0].upper() != rid:
            continue
        for c in cells[1:]:
            names.extend(re.findall(r"verify_[A-Za-z0-9_.+\-]+?\.md", c))
    names = list(dict.fromkeys(names))
    if not names:
        return False
    for name in names:
        vp = scratchpad / name
        if not vp.exists():
            return False
        try:
            vc = vp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return False
        if not has_mechanical_proof(vc):
            return False
    return True


def _check_speculative_critical_chains(scratchpad: Path) -> list[str]:
    """T2-c (WARNING-class): flag Critical chain rows that lack verification.

    A `Critical` assigned to a chain / compound hypothesis (`CH-*` internal
    ID, or `+`-joined constituents) with a non-VERIFIED disposition is
    speculative; STEP 1 rule 8 of the report-index prompt caps these at
    High. This is the observability backstop — it never blocks the gate.

    Exception (rule 8): a chain whose constituents are EACH independently
    verified ([POC-PASS]/[MEDUSA-PASS]) is NOT speculative — its Critical is
    inherited from a verified constituent — so it is not flagged even if the
    Index Agent left the row's own Verification column as UNVERIFIED.
    """
    rows = _parse_master_finding_index_rows(scratchpad)
    if not rows:
        return []
    flagged: list[str] = []
    for r in rows:
        if "critical" not in (r.get("severity") or "").strip().lower():
            continue
        internal = r.get("internal", "")
        is_chain = ("CH-" in internal.upper()) or ("+" in internal)
        if not is_chain:
            continue
        verif = (r.get("verification") or "").strip().upper()
        if "VERIFIED" in verif and "UNVERIFIED" not in verif:
            continue  # genuinely verifier-confirmed
        # Fix 1 (atomic migration): the canonical Verification column now uses
        # CONFIRMED for a verdict-confirmed / [CODE-TRACE]-only finding (distinct
        # from UNVERIFIED = refuted/none). STEP 1 rule 8 treats CONFIRMED as
        # non-speculative just like VERIFIED — otherwise the ~54 CONFIRMED
        # findings would each read as an unverified Critical chain and get
        # falsely flagged/capped on a label change alone.
        if "CONFIRMED" in verif:
            continue  # verdict-confirmed (CODE-TRACE) is non-speculative
        if _chain_constituents_verified(scratchpad, r.get("report_id", "")):
            continue  # Critical inherited from verified constituent(s) (rule 8)
        flagged.append(
            f"{r['report_id']} (internal {internal or '?'}, "
            f"verification {verif or '?'})"
        )
    if flagged:
        return [
            f"speculative critical: {len(flagged)} Critical chain finding(s) "
            "without verifier confirmation — STEP 1 rule 8 caps these at "
            f"High: {'; '.join(flagged[:8])}"
        ]
    return []


def _write_promotion_dropout_retry_hint(
    scratchpad: Path, dropped_ids: list[str]
) -> Path | None:
    """Write a retry hint for report_assemble naming the missing IDs.

    Pairs with the v2.1.6 retry-hint mechanism — the next attempt's
    prompt sees this file and is told exactly which IDs to add.
    """
    if not dropped_ids:
        return None
    hint_path = scratchpad / f"report_assemble{_RETRY_HINT_SUFFIX}"
    try:
        body = (
            "## v2.2.0 A.2 — promotion dropout retry hint\n\n"
            f"The previous report_assemble attempt dropped {len(dropped_ids)} "
            "CONFIRMED verifier finding(s) from the body, Appendix A, and "
            "the Consolidation Map. Add a body section OR an Appendix A row "
            "(FALSE_POSITIVE/DUPLICATE) OR a Consolidation Map entry for "
            "each of:\n\n"
            + "\n".join(f"- `{i}`" for i in dropped_ids)
            + "\n"
        )
        hint_path.write_text(body, encoding="utf-8")
        return hint_path
    except Exception:
        return None


def _run_report_quality_gate(
    scratchpad: Path, project_root: str
) -> list[str]:
    """Mechanical post-assembly quality gate (A4).

    Runs after `report_assemble` completes. Replaces the LLM-written
    quality check that a prior monolithic assembler was supposed to
    produce but timed out before emitting. Pure Python, sub-second.

    Writes `{SCRATCHPAD}/report_quality.md` with PASS/FAIL per check and
    returns the list of FAIL messages (empty = all pass).

    v2.1.9 — Summary table self-heal:
    Body section counts are canonical. The `## Summary` tables in both
    `AUDIT_REPORT.md` and `report_index.md` are rewritten in place to
    match `tier_counts` before the count check runs. This eliminates the
    Q83 false-alarm class observed in a prior L1 run, where
    body and summary disagreed on Medium count by 1 and the gate
    trip-wired despite the body being correct.

    v2.2.0 A.2 — promotion-receipt symmetry:
    After self-heal, diff the set of CONFIRMED verifier verdicts against
    the set of IDs acknowledged by the report (body + Appendix A +
    Consolidation Map). Any dropouts → gate fail with a delta retry
    hint pinning the missing IDs.
    """
    pr = Path(project_root) / "AUDIT_REPORT.md"
    ri = scratchpad / "report_index.md"
    if not pr.exists():
        return ["AUDIT_REPORT.md missing"]
    try:
        rtxt = pr.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["AUDIT_REPORT.md unreadable"]

    issues: list[str] = []
    checks: list[tuple[str, str, str]] = []  # (check, status, detail)

    # Check 1: finding section count per severity tier. Use the body parser as
    # the single source of truth for section IDs; private header regexes have
    # repeatedly drifted from the validator contract.
    body_end_for_counts = rtxt.find("## Appendix A")
    report_body_for_counts = rtxt[:body_end_for_counts] if body_end_for_counts > 0 else rtxt
    body_report_ids_for_counts = _extract_report_ids_from_body(report_body_for_counts)
    from collections import Counter
    body_report_id_counter = Counter(body_report_ids_for_counts)
    tier_counts = {
        tier_char: sum(
            1 for rid in body_report_ids_for_counts
            if rid.startswith(tier_char + "-")
        )
        for tier_char in ("C", "H", "M", "L", "I")
    }
    total_sections = sum(tier_counts.values())

    # v2.1.9 self-heal: canonicalize the AUDIT_REPORT.md Summary table from
    # body counts before checking. Body is authoritative.
    rtxt_new, report_deltas = _canonicalize_summary_table(rtxt, tier_counts)
    if report_deltas:
        try:
            pr.write_text(rtxt_new, encoding="utf-8")
            rtxt = rtxt_new
            checks.append((
                "summary_selfheal_report",
                "INFO",
                "rewrote AUDIT_REPORT.md Summary: " + ", ".join(
                    f"{name} {delta}" for name, delta in report_deltas
                ),
            ))
        except Exception as e:
            checks.append((
                "summary_selfheal_report", "WARN",
                f"rewrite failed: {e}",
            ))
    else:
        checks.append((
            "summary_selfheal_report", "PASS", "summary already canonical",
        ))

    assignments, assignment_source = get_tier_assignments(scratchpad)
    # Material-harm body floor: APPENDIX-dispositioned findings are RELOCATED to
    # Appendix C by report_assemble, so they legitimately leave the body. Drop
    # them from the expected body-assignment set BEFORE the count / exact-id
    # checks so the floor does not trip a false shortfall / missing-ID failure.
    # No-op when disposition.md is absent (degrade to pre-floor behaviour).
    _appendix_rids = _appendix_disposition_report_ids(scratchpad)
    if _appendix_rids and assignments:
        assignments = [
            a for a in assignments
            if (a.get("report_id") or "").upper() not in _appendix_rids
        ]
    if assignments and total_sections != len(assignments):
        if total_sections > len(assignments):
            # v2.5.4: Body has MORE sections than assignments — extra
            # coverage from promotion recovery (_repair_promotion_dropouts)
            # or assembler self-heal. Body is authoritative (v2.1.9
            # principle). WARN, not FAIL — missing sections (body < index)
            # is the real error class.
            checks.append((
                "body_assignment_count", "WARN",
                f"body sections={total_sections} > assignments="
                f"{len(assignments)} from {assignment_source} "
                f"(+{total_sections - len(assignments)} via "
                f"promotion recovery, body is authoritative)",
            ))
        else:
            detail = (
                f"body sections={total_sections}, expected assignments="
                f"{len(assignments)} from {assignment_source}"
            )
            shortfall = len(assignments) - total_sections
            if shortfall > max(2, int(len(assignments) * 0.20)):
                checks.append(("body_assignment_count", "FAIL", detail))
                issues.append("report body count mismatch: " + detail)
            else:
                checks.append(("body_assignment_count", "WARN",
                                detail + f" (shortfall={shortfall}, within tolerance)"))
                log.warning(
                    "[_run_report_quality_gate] body_assignment_count: %s "
                    "(shortfall=%d, within tolerance — soft check)",
                    detail, shortfall,
                )
    else:
        checks.append((
            "body_assignment_count", "PASS",
            f"body sections={total_sections}, assignments={len(assignments)} "
            f"source={assignment_source}",
        ))

    # Also canonicalize report_index.md Summary Counts so downstream
    # consumers see consistent metadata.
    if ri.exists():
        try:
            itxt = ri.read_text(encoding="utf-8", errors="replace")
        except Exception:
            itxt = ""
        if itxt:
            itxt_new, idx_deltas = _canonicalize_summary_table(itxt, tier_counts)
            if idx_deltas:
                try:
                    ri.write_text(itxt_new, encoding="utf-8")
                    checks.append((
                        "summary_selfheal_index",
                        "INFO",
                        "rewrote report_index.md Summary: " + ", ".join(
                            f"{name} {delta}" for name, delta in idx_deltas
                        ),
                    ))
                except Exception as e:
                    checks.append((
                        "summary_selfheal_index", "WARN",
                        f"rewrite failed: {e}",
                    ))
            else:
                checks.append((
                    "summary_selfheal_index", "PASS",
                    "index summary already canonical",
                ))

    # The legacy "tier_count_C/H/M/L/I" check now trivially PASSes because
    # both files were rewritten from body counts. Recorded for forensics.
    for char, name in (
        ("C", "Critical"), ("H", "High"), ("M", "Medium"),
        ("L", "Low"), ("I", "Informational"),
    ):
        actual = tier_counts.get(char, 0)
        checks.append((
            f"tier_count_{char}", "PASS",
            f"body sections={actual} (canonical)",
        ))

    mapped = _ensure_report_consolidation_map(scratchpad, project_root)
    if mapped:
        try:
            rtxt = pr.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
        checks.append((
            "consolidation_map_selfheal", "INFO",
            f"wrote {mapped} source-ID consolidation row(s)",
        ))

    aliases = _load_report_reference_aliases(
        scratchpad,
        {rid.upper() for rid in body_report_ids_for_counts},
    )
    rtxt_new, alias_rewrites = _rewrite_public_report_references(
        rtxt,
        aliases,
        {rid.upper() for rid in body_report_ids_for_counts},
    )
    if alias_rewrites:
        try:
            pr.write_text(rtxt_new, encoding="utf-8")
            rtxt = rtxt_new
            checks.append((
                "public_reference_alias_selfheal",
                "INFO",
                f"rewrote {alias_rewrites} internal prose reference(s) "
                "to public report IDs",
            ))
        except Exception as e:
            checks.append((
                "public_reference_alias_selfheal",
                "WARN",
                f"rewrite failed: {e}",
            ))

    # Check 2: no internal IDs leaked into AUDIT_REPORT.md.
    # `_ID_ALL_NONHYPO` excludes H/CH because H-01 is also a report ID. Add
    # explicit privacy patterns for chain IDs and non-report-shaped hypothesis
    # IDs while preserving valid C/H/M/L/I-NN report section IDs.
    from plamen_parsers import _ID_ALL_NONHYPO
    internal_id_patterns = [
        rf"\b(?:{_ID_ALL_NONHYPO})\b",
        r"\bCH-\d+\b",
        r"\bH-[CHMLI]\d+\b",
        r"\bH-(?:[1-9]|\d{3,})\b",
        r"\bverify_[A-Za-z0-9_\-\[\].]+\.md\b",
    ]
    # Body-only checks still exclude Appendix A for finding-section accounting.
    # Internal-ID privacy is stricter: the delivered report must not contain
    # pipeline trace IDs anywhere. Internal traceability belongs in
    # report_index.md/report_coverage.md.
    body_end = rtxt.find("## Appendix A")
    body = rtxt[:body_end] if body_end > 0 else rtxt
    body_report_ids = _extract_report_ids_from_body(body)
    duplicate_report_ids = sorted(
        rid for rid, n in body_report_id_counter.items() if n > 1
    )
    if duplicate_report_ids:
        checks.append((
            "duplicate_report_sections", "FAIL",
            f"duplicate body section IDs: {duplicate_report_ids[:10]}",
        ))
        issues.append(
            "duplicate report body sections: " + ", ".join(duplicate_report_ids[:10])
        )
    else:
        checks.append(("duplicate_report_sections", "PASS", "none"))

    if assignments:
        expected_report_ids = {
            (a.get("report_id") or "").upper()
            for a in assignments
            if a.get("report_id")
        }
        actual_report_ids = {rid.upper() for rid in body_report_ids}
        missing_report_ids = sorted(expected_report_ids - actual_report_ids)
        extra_report_ids = sorted(actual_report_ids - expected_report_ids)
        if missing_report_ids:
            checks.append((
                "body_assignment_exact_ids", "FAIL",
                f"missing={missing_report_ids[:10]} extra={extra_report_ids[:10]}",
            ))
            issues.append(
                "report body ID set mismatch: "
                f"missing={missing_report_ids[:10]} extra={extra_report_ids[:10]}"
            )
        elif extra_report_ids:
            checks.append((
                "body_assignment_exact_ids", "WARN",
                f"extra={extra_report_ids[:10]} (promotion recovery)",
            ))
        else:
            checks.append(("body_assignment_exact_ids", "PASS", "exact set"))

    leaked = []
    valid_report_ids = {rid.upper() for rid in body_report_ids}
    for pat in internal_id_patterns:
        hits = re.findall(pat, rtxt, flags=re.IGNORECASE)
        if hits:
            leaked.extend(h for h in set(hits) if h.upper() not in valid_report_ids)
    if leaked:
        leaked = sorted(set(leaked))[:10]
        checks.append(("internal_id_leak", "FAIL", f"found {len(leaked)}: {leaked}"))
        issues.append(f"internal IDs leaked into AUDIT_REPORT.md: {leaked}")
    else:
        checks.append(("internal_id_leak", "PASS", "none"))

    excluded_body_hits = sorted(set(re.findall(
        r"(?m)^\s*\*{0,2}(?:Verdict|Status|Exclusion)\*{0,2}\s*:\s*.*(FALSE_POSITIVE|REFUTED|INFEASIBLE)",
        body,
        flags=re.IGNORECASE,
    )))
    if excluded_body_hits:
        checks.append((
            "excluded_verdict_body_leak", "FAIL",
            f"active body contains excluded verdict tokens: {excluded_body_hits}",
        ))
        issues.append(
            "active body contains FALSE_POSITIVE/REFUTED/INFEASIBLE markers"
        )
    else:
        checks.append(("excluded_verdict_body_leak", "PASS", "none"))

    # Check 3: basic stub-guard
    if total_sections == 0:
        checks.append(("stub_guard", "FAIL", "0 finding sections in body"))
        issues.append("AUDIT_REPORT.md is a stub (0 finding sections)")
    else:
        checks.append(("stub_guard", "PASS", f"{total_sections} sections"))

    if total_sections > 0:
        # v2.5.2: preserve tier prefix per section so PoC Result is only
        # required for C/H/M (report-template.md: optional for L/I).
        _section_header_re = re.compile(
            r"^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI])-\d+\]",
            re.MULTILINE,
        )
        section_pairs: list[tuple[str, str]] = []  # (tier_char, section_body)
        headers = list(_section_header_re.finditer(body))
        for i, hm in enumerate(headers):
            start = hm.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
            section_pairs.append((hm.group(1), body[start:end]))
        sections = [(t, s) for t, s in section_pairs if s.strip()]
        heading_titles: dict[str, str] = {}
        for hm in re.finditer(
            r"(?im)^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\]\s*([^\n]*)",
            body,
        ):
            rid = hm.group(1).upper()
            title = re.sub(r"\[[A-Z][^\]]*\]", " ", hm.group(2) or "")
            title = re.sub(r"\s+", " ", title).strip(" -:|")
            heading_titles[rid] = title
        placeholder_title_ids: list[str] = []
        for rid, title in heading_titles.items():
            title_l = title.lower()
            if not title_l:
                placeholder_title_ids.append(rid)
                continue
            if "upstream finding" in title_l:
                placeholder_title_ids.append(rid)
                continue
            if re.search(
                r"\b(?:unverified|verified)\b.*\b(?:severity|finding)\b.*"
                r"(?:CH|H|INV|VS|BLIND|SE|EN|SLITHER|[A-Z]{2,})-\d+\b",
                title,
                re.IGNORECASE,
            ):
                placeholder_title_ids.append(rid)
                continue
        bad_location_ids: list[str] = []
        title_location_pairs: dict[tuple[str, str], list[str]] = {}
        for idx, (_tier, section) in enumerate(sections):
            rid = body_report_ids[idx] if idx < len(body_report_ids) else f"section-{idx + 1}"
            loc = _field_from_markdown(section, ("Location", "Locations")) or ""
            loc_rel, _loc_line = _parse_location_ref(loc)
            if loc and not loc_rel and re.search(
                r"\b(?:Critical|High|Medium|Low|Informational|Info)\b"
                r".*\[(?:POC|CODE|MEDUSA|PROD|TRACE|CONFIRMED)",
                loc,
                re.IGNORECASE,
            ):
                bad_location_ids.append(rid)
            title_key = re.sub(r"[^a-z0-9]+", " ", heading_titles.get(rid, "").lower()).strip()
            loc_key = re.sub(r"\s+", " ", (loc or "").strip().lower())
            if title_key and loc_key:
                title_location_pairs.setdefault((title_key, loc_key), []).append(rid)
        duplicate_title_location = [
            ids for ids in title_location_pairs.values() if len(ids) > 1
        ]
        thin_sections = [
            body_report_ids[i] if i < len(body_report_ids) else f"section-{i + 1}"
            for i, (_, s) in enumerate(sections)
            if len(s.strip()) < 400
        ]
        boilerplate = sum(
            1 for _, s in sections
            if (
                "tier writer omitted the assigned body section" in s
                or "Python assembler restored the assigned section" in s
                or "Review the cited location and apply the mitigation" in s
                or "Impact was not separately summarized by the verifier" in s
            )
        )
        blocked_ids: list[str] = []
        for hm in re.finditer(r"(?im)^###[^\n]*\[REPORT-BLOCKED[^\]]*\][^\n]*$", body):
            rid_m = re.search(r"\[([CHMLI]-\d+)\]", hm.group(0), re.IGNORECASE)
            if rid_m:
                blocked_ids.append(rid_m.group(1).upper())
        stub_recovered_ids = re.findall(
            r"(?im)^###[^\n]*\[([CHMLI]-\d+)\][^\n]*\[STUB-RECOVERED\]",
            body,
        )
        blocked_ch = [rid for rid in blocked_ids if rid[:1].upper() in ("C", "H")]
        stub_ch = [rid for rid in stub_recovered_ids if rid[:1].upper() in ("C", "H")]
        blocked_limit = max(3, math.ceil(total_sections * 0.20))
        stub_limit = max(2, math.ceil(total_sections * 0.10))
        # GATE-3: an upstream evidence gap (REPORT-BLOCKED/STUB-RECOVERED C/H
        # section, or too many blocked/stub sections) is a quality/recall
        # judgment the MECHANICAL assembler cannot fix -- it cannot synthesize
        # evidence it does not have. Per the WARN-not-halt doctrine these are
        # SOFT. What stays HARD is mechanical: internal markers must not leak
        # into the client report, and there must not be duplicate structural
        # headings. (The upstream verify gate -- still hard -- is the correct
        # place to catch missing evidence.)
        evidence_quality_soft: list[str] = []
        evidence_quality_hard: list[str] = []
        if blocked_ch:
            evidence_quality_soft.append(
                f"{len(blocked_ch)} Critical/High REPORT-BLOCKED section(s): {blocked_ch[:10]}"
            )
        if len(blocked_ids) >= blocked_limit:
            evidence_quality_soft.append(
                f"{len(blocked_ids)}/{total_sections} REPORT-BLOCKED section(s)"
            )
        if stub_ch:
            evidence_quality_soft.append(
                f"{len(stub_ch)} Critical/High STUB-RECOVERED section(s): {stub_ch[:10]}"
            )
        if len(stub_recovered_ids) >= stub_limit:
            evidence_quality_soft.append(
                f"{len(stub_recovered_ids)}/{total_sections} STUB-RECOVERED section(s)"
            )
        internal_marker_leaks = re.findall(
            r"\[(?:REPORT-BLOCKED|STUB-RECOVERED)[^\]]*\]",
            body,
            flags=re.IGNORECASE,
        )
        if internal_marker_leaks:
            evidence_quality_hard.append(
                f"{len(internal_marker_leaks)} internal report marker(s) leaked into client report"
            )
        quality_heading_count = len(
            re.findall(r"(?im)^##\s+Quality\s+Observations\s*$", body)
        )
        if quality_heading_count > 1:
            evidence_quality_hard.append(
                f"{quality_heading_count} duplicate Quality Observations sections"
            )
        if evidence_quality_soft:
            soft_detail = "; ".join(evidence_quality_soft)
            checks.append(("evidence_quality", "WARN", soft_detail))
            log.warning(
                "[_run_report_quality_gate] evidence_quality (soft): %s", soft_detail
            )
        if evidence_quality_hard:
            detail = "; ".join(evidence_quality_hard)
            checks.append(("evidence_quality", "FAIL", detail))
            issues.append("report body evidence quality blocked: " + detail)
        if not evidence_quality_soft and not evidence_quality_hard:
            checks.append((
                "evidence_quality",
                "PASS",
                f"REPORT-BLOCKED={len(blocked_ids)}, STUB-RECOVERED={len(stub_recovered_ids)}",
            ))
        if placeholder_title_ids:
            checks.append((
                "title_quality",
                "WARN",
                "placeholder/generated titles: " + ", ".join(placeholder_title_ids[:10]),
            ))
            log.warning(
                "[_run_report_quality_gate] title_quality: placeholder titles %s",
                placeholder_title_ids[:10],
            )
        else:
            checks.append(("title_quality", "PASS", "finding headings are specific"))
        if bad_location_ids:
            checks.append((
                "location_quality",
                "FAIL",
                "metadata used as source location: " + ", ".join(bad_location_ids[:10]),
            ))
            issues.append(
                "report body contains severity/evidence metadata as Location: "
                + ", ".join(bad_location_ids[:10])
            )
        else:
            checks.append(("location_quality", "PASS", "no metadata-as-location fields"))
        if duplicate_title_location:
            detail = "; ".join(", ".join(ids) for ids in duplicate_title_location[:5])
            checks.append((
                "duplicate_title_location",
                "WARN",
                detail,
            ))
            log.warning(
                "[_run_report_quality_gate] duplicate_title_location: %s",
                detail,
            )
        else:
            checks.append(("duplicate_title_location", "PASS", "none"))
        def _section_field_substantive(
            section: str,
            field_labels: tuple[str, ...],
            section_labels: tuple[str, ...],
        ) -> bool:
            value = _field_or_section(
                section,
                field_labels,
                section_labels,
                fallback="",
                max_chars=2500,
            )
            return _is_substantive_body_evidence(value)

        # T2-d: split missing-Impact by tier. A C/H/M finding shipped with
        # no substantive `## Impact` section is a hard quality failure (the
        # a prior run shipped M-07/M-13/M-16 this way) — it must block the gate
        # and trigger a retry, not just WARN. L/I missing Impact stays soft.
        missing_impact_chm: list[str] = []
        missing_impact_li: list[str] = []
        for i, (t, s) in enumerate(sections):
            rid = (
                body_report_ids[i] if i < len(body_report_ids)
                else f"section-{i + 1}"
            )
            if _section_field_substantive(
                s,
                ("Impact", "Security Impact", "Risk"),
                ("Impact", "Security Impact", "Risk"),
            ):
                continue
            if t in ("C", "H", "M"):
                missing_impact_chm.append(rid)
            else:
                missing_impact_li.append(rid)
        missing_impact_ids = missing_impact_chm + missing_impact_li
        # PoC Result is required for C/H/M only; optional for L/I per
        # report-template.md ("PoC Result field optional for Informational",
        # "Recommendation field optional for Low").
        missing_poc_ids = [
            body_report_ids[i] if i < len(body_report_ids) else f"section-{i + 1}"
            for i, (t, s) in enumerate(sections)
            if t in ("C", "H", "M")
            and "VERIFICATION NOT EXECUTED" not in s.upper()
            and "[UNVERIFIED]" not in s.upper()
            # Fix 1: [CONFIRMED] (verdict-confirmed on [CODE-TRACE], no executed
            # PoC) is exempt from the substantive-PoC-Result requirement, same
            # basis as [UNVERIFIED].
            and "[CONFIRMED]" not in s.upper()
            and not _section_field_substantive(
                s,
                _BODY_POC_FIELDS,
                _BODY_POC_SECTIONS,
            )
        ]
        if boilerplate > max(0, int(total_sections * 0.05)):
            # Literal report-stub boilerplate phrase match is MECHANICAL -> hard.
            checks.append((
                "content_authenticity", "FAIL",
                f"{boilerplate}/{total_sections} sections contain report-stub boilerplate",
            ))
            issues.append("report body is dominated by boilerplate/stub sections")
        elif missing_impact_chm or missing_poc_ids:
            # GATE-1: "is this Impact/PoC paragraph substantive" is a prose/
            # LLM-quality judgment (via _is_substantive_body_evidence), NOT a
            # mechanical guarantee. Per the WARN-not-halt doctrine it must NOT
            # be appended to `issues` (which hard-halts the critical
            # report_assemble phase and survives the FC4 content rescue). It is
            # recorded as a WARN for telemetry; the mechanical checks (ID set,
            # duplicates, marker leak, stub_guard==0) remain hard.
            checks.append((
                "content_authenticity", "WARN",
                "C/H/M sections with non-substantive Impact: "
                f"{missing_impact_chm[:10]}, PoC Result: {missing_poc_ids[:10]}",
            ))
            log.warning(
                "[_run_report_quality_gate] content_authenticity (soft): C/H/M "
                "Impact %s / PoC Result %s non-substantive",
                missing_impact_chm[:10], missing_poc_ids[:10],
            )
        elif missing_impact_li:
            checks.append((
                "content_authenticity", "WARN",
                f"missing/non-substantive Impact in L/I sections "
                f"{missing_impact_li[:10]}",
            ))
            log.warning(
                "[_run_report_quality_gate] content_authenticity: missing Impact "
                "in L/I sections %s (soft check)",
                missing_impact_li[:10],
            )
        elif thin_sections and len(thin_sections) > max(1, int(total_sections * 0.15)):
            checks.append((
                "content_authenticity", "WARN",
                f"{len(thin_sections)}/{total_sections} sections below 400 chars: "
                f"{thin_sections[:10]}",
            ))
            log.warning(
                "[_run_report_quality_gate] %d/%d sections below 400 chars "
                "— LLM output quality check (soft): %s",
                len(thin_sections), total_sections, thin_sections[:10],
            )
        else:
            checks.append((
                "content_authenticity", "PASS",
                "sections include Impact and PoC Result (C/H/M) without stub boilerplate",
            ))

        defined_report_ids = set(body_report_ids)
        referenced_ids = set()
        reference_re = re.compile(
            r"(?i)\b(?:see|related to|duplicate of|duplicates|same as|"
            r"cross-reference|cross reference|absorbed by|absorbs)\b"
            r"[^\n]{0,120}?(?:\[\s*)?([CHMLI]-\d{1,3})(?:\s*\])?"
        )
        for m in reference_re.finditer(body):
            referenced_ids.add(_normalize_report_id(m.group(1)))
        dangling_refs = sorted(referenced_ids - defined_report_ids)
        if dangling_refs:
            checks.append((
                "report_cross_references", "WARN",
                f"undefined report ID references: {dangling_refs[:10]}",
            ))
            log.warning(
                "[_run_report_quality_gate] dangling cross-references: %s",
                dangling_refs[:10],
            )
        else:
            checks.append(("report_cross_references", "PASS", "none"))

    # v2.5.2: Components Audited is best-effort — WARN when absent
    # (upstream data may not exist), only FAIL when it was available
    # but not included.
    if total_sections > 0 and "### Components Audited" not in rtxt:
        checks.append(("components_audited", "WARN", "missing Components Audited block"))
    else:
        checks.append(("components_audited", "PASS", "present or no finding sections"))

    # Check 4: runtime metadata sanity — Codex/Claude branding not leaked.
    # Only flag clear branding strings, not generic words.
    forbidden = [
        "claude.ai", "anthropic", "Claude Code", "Claude Opus",
        "Claude Sonnet", "Claude Haiku",
    ]
    meta_leaks = [s for s in forbidden if s.lower() in body.lower()]
    if meta_leaks:
        checks.append(("metadata_leak", "FAIL", f"{meta_leaks}"))
        issues.append(f"runtime-metadata branding leaked: {meta_leaks}")
    else:
        checks.append(("metadata_leak", "PASS", "clean"))

    # Check 6 (v2.2.1 Fix 2): UNRESOLVED authenticity. Body [UNRESOLVED]
    # sections must correspond to Judge UNRESOLVED rulings. Catches the
    # prior-L1-run C-02 phantom-flag class (tier writer or assembler
    # widened the bucket).
    unresolved_issues = _check_unresolved_authenticity(
        scratchpad, project_root
    )
    if unresolved_issues:
        for u in unresolved_issues:
            checks.append(("unresolved_authenticity", "FAIL", u))
        issues.extend(unresolved_issues)
    else:
        checks.append((
            "unresolved_authenticity", "PASS",
            "body [UNRESOLVED] sections match Judge UNRESOLVED rulings",
        ))

    # Check 5 (v2.2.0 A.2): promotion-receipt symmetry. Every CONFIRMED
    # verifier verdict must reach the report (body, Appendix A, or
    # consolidation map). Dropouts trigger a delta retry hint so the
    # next attempt knows exactly what to add.
    promotion_issues = _check_promotion_symmetry(scratchpad, project_root)
    if promotion_issues:
        # Extract dropped IDs from the issue message for the retry hint.
        dropped_match = re.search(
            r"missing from report .*?: (.*?)(?:\s*\(\+|$)",
            promotion_issues[0],
        )
        if dropped_match:
            dropped_ids = [
                s.strip() for s in dropped_match.group(1).split(",")
                if s.strip()
            ]
            _write_promotion_dropout_retry_hint(scratchpad, dropped_ids)
        checks.append(("promotion_receipt", "FAIL", promotion_issues[0]))
        issues.extend(promotion_issues)
    else:
        checks.append(("promotion_receipt", "PASS",
                        "all CONFIRMED verifier IDs reached report"))

    # Write report_quality.md
    qp = scratchpad / "report_quality.md"
    try:
        lines = [
            "# Report Quality Gate (v2.1.2 mechanical)",
            "",
            f"- Total sections: {total_sections} "
            f"(C={tier_counts.get('C',0)}, H={tier_counts.get('H',0)}, "
            f"M={tier_counts.get('M',0)}, L={tier_counts.get('L',0)}, "
            f"I={tier_counts.get('I',0)})",
            "",
            "| Check | Status | Detail |",
            "|-------|--------|--------|",
        ]
        for name, status, detail in checks:
            lines.append(f"| {name} | {status} | {detail} |")
        lines.append("")
        lines.append(
            "Overall: " + ("PASS" if not issues else f"FAIL ({len(issues)})")
        )
        qp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass

    return issues


def _snapshot_report_timestamped(project_root: str) -> str | None:
    """Write a timestamped `AUDIT_REPORT-YYYYMMDD-HHMM.md` copy on success.

    Returns the snapshot path on success, None on failure. SOFT: never
    raises; logs warning on failure.
    """
    import shutil
    from datetime import datetime
    src = Path(project_root) / "AUDIT_REPORT.md"
    if not src.exists():
        return None
    try:
        stamp = datetime.now().strftime("%Y%m%d-%H%M")
        dst = Path(project_root) / f"AUDIT_REPORT-{stamp}.md"
        shutil.copy2(src, dst)
        return str(dst)
    except Exception as e:
        log.warning(f"timestamped report snapshot failed: {e}")
        return None


# --- end v2.1.2 helpers ------------------------------------------------------
# --- v2.1.6: deterministic-retry + checkpoint-integrity helpers -------------
#
# Problem observed in prior SC and L1 runs: when a completeness gate
# fails (tier writer short, assembler count mismatch), the driver re-spawns
# the same prompt without telling the LLM WHICH specific items were missing.
# LLMs routinely re-produce identical wrong output on hollow retries, burning
# $5–$40 per retry. Research-backed fix: inject delta-specific retry hints.
# (Wei et al. 2023 on recency + action-grounding: per-call instructions with
# concrete deltas drive ~99% adherence; re-asking generically drives <50%.)
_RETRY_HINT_SUFFIX = "_retry_hint.md"


def _compute_tier_completeness_delta(
    scratchpad: Path, phase_name: str
) -> tuple[list[str], list[str]]:
    """Return (expected_ids, produced_ids) for a report tier phase.

    expected_ids: IDs the Index Agent assigned to this tier per
    `report_index.md` Master Finding Index.
    produced_ids: IDs actually present as `### [X-NN]` sections in the
    corresponding tier file on disk.

    Returns ([], []) on any parse failure (SOFT — caller decides).
    """
    # Map phase to tier filename and acceptable ID prefixes.
    _TIER_PREFIXES: dict[str, set[str]] = {
        "critical_high": {"C", "H"},
        "medium": {"M"},
        "low_info": {"L", "I"},
    }
    tier_map: dict[str, tuple[str, set[str]]] = {
        "report_critical_high": ("report_critical_high.md", {"C", "H"}),
        "report_medium": ("report_medium.md", {"M"}),
        "report_low_info": ("report_low_info.md", {"L", "I"}),
    }
    _shard_m = re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase_name)
    if _shard_m:
        tier_map[phase_name] = (f"{phase_name}.md", _TIER_PREFIXES[_shard_m.group(1)])
    if phase_name not in tier_map:
        return [], []
    tier_file, prefixes = tier_map[phase_name]

    tier = scratchpad / tier_file
    if not tier.exists():
        return [], []
    try:
        tier_text = tier.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], []

    # v2.3.3: derive expected IDs from `get_tier_assignments` (single source of
    # truth) instead of a private table-only regex over `report_index.md`.
    # Pre-v2.3.3 this function had its own strict regex, which silently returned
    # 0 expected IDs when the Index Agent emitted bullet-list narrative — the
    # same bug class that produced the 42-byte AUDIT_REPORT.md in a prior L1 run.
    rows, _source = get_tier_assignments(scratchpad)
    expected = [
        a["report_id"] for a in rows
        if a["report_id"][:1].upper() in prefixes
    ]

    # Produced = report-ID section headers in the tier file. Use the same
    # parser as the body validator instead of a private `###`-only regex;
    # otherwise a body that passes `_validate_report_body` can fail retry-hint
    # accounting solely because it used `## [X-NN]`.
    produced = [
        fid for fid in _extract_report_ids_from_body(tier_text)
        if fid[:1].upper() in prefixes
    ]

    return expected, produced


def _compute_assemble_count_delta(
    scratchpad: Path, project_root: str
) -> dict[str, tuple[int, int]]:
    """Return per-tier (summary_count, body_count) from AUDIT_REPORT.md.

    Used by the report_assemble quality gate's delta-aware retry hint so
    the retry prompt can say "summary says 22 Medium, body has 25, fix one
    side" instead of re-asking generically.
    """
    pr = Path(project_root) / "AUDIT_REPORT.md"
    if not pr.exists():
        return {}
    try:
        text = pr.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    summary = {}
    for char, name in (
        ("C", "Critical"), ("H", "High"), ("M", "Medium"),
        ("L", "Low"), ("I", "Informational"),
    ):
        m = re.search(
            rf"^\s*\|\s*{name}\s*\|\s*(\d+)\s*\|",
            text, re.MULTILINE,
        )
        summary[char] = int(m.group(1)) if m else 0

    body = {}
    body_end = text.find("## Appendix A")
    body_text = text[:body_end] if body_end > 0 else text
    body_ids = _extract_report_ids_from_body(body_text)
    for char in ("C", "H", "M", "L", "I"):
        body[char] = sum(1 for rid in body_ids if rid.startswith(char + "-"))

    return {c: (summary.get(c, 0), body.get(c, 0)) for c in "CHMLI"}


def _write_retry_hint(
    scratchpad: Path, phase_name: str, hint: str
) -> None:
    """Write a retry-hint file consumed by `build_phase_prompt` on attempt 2.

    The hint file is deleted after attempt 2 to prevent stale hints from
    affecting unrelated future runs.
    """
    try:
        p = scratchpad / f"{phase_name}{_RETRY_HINT_SUFFIX}"
        p.write_text(hint, encoding="utf-8")
    except Exception as e:
        log.warning(f"[{phase_name}] retry hint write failed: {e}")


def _read_retry_hint(scratchpad: Path, phase_name: str) -> str:
    """Return retry-hint text for this phase, or '' if none."""
    p = scratchpad / f"{phase_name}{_RETRY_HINT_SUFFIX}"
    if not p.exists():
        return ""
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        # v2.6.x: depth confidence scoring is an in-scope never-cut artifact.
        # Older halted runs may still have a retry hint that told attempt 3
        # not to execute "scoring", making the repair prompt self-contradictory.
        if phase_name == "depth" and "verification, scoring, or report work" in text:
            text = text.replace(
                "Phase 4b.5/RAG, chain analysis, verification, scoring, or report work",
                "Phase 4b.5/RAG, final_scoring, chain analysis, verification, or report work",
            )
            if "Initial confidence scoring is part of the depth phase" not in text:
                patched = text.replace(
                    "- Do NOT write rag_validation.md or any later-phase artifact.\n",
                    "- Do NOT write rag_validation.md or any later-phase artifact.\n"
                    "- Initial confidence scoring is part of the depth phase in Core/Thorough. "
                    "If confidence_scores.md is missing or too small, spawn the Phase 4b "
                    "Confidence Scoring Agent and write confidence_scores.md before returning.\n",
                )
                if patched == text:
                    patched = (
                        text.rstrip()
                        + "\n- Initial confidence scoring is part of the depth phase in Core/Thorough. "
                        "If confidence_scores.md is missing or too small, spawn the Phase 4b "
                        "Confidence Scoring Agent and write confidence_scores.md before returning.\n"
                    )
                text = patched
        return text
    except Exception:
        return ""


def _clear_retry_hint(scratchpad: Path, phase_name: str) -> None:
    """Remove the retry-hint file for this phase (post-retry cleanup)."""
    p = scratchpad / f"{phase_name}{_RETRY_HINT_SUFFIX}"
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass


def _generate_tier_retry_hint(
    scratchpad: Path, phase_name: str
) -> str | None:
    """Compute a delta-aware retry hint for a report tier phase.

    Returns a human-readable multi-line prompt suffix listing the SPECIFIC
    missing IDs, or None if no delta exists / helper cannot determine one.
    """
    expected, produced = _compute_tier_completeness_delta(scratchpad, phase_name)
    if not expected:
        return None
    missing = [fid for fid in expected if fid not in set(produced)]
    if not missing:
        return None
    sample = ", ".join(f"`{fid}`" for fid in missing[:20])
    return (
        "## RETRY HINT — delta-aware (v2.1.6)\n"
        "\n"
        "Your previous attempt produced an incomplete tier file. The Index "
        "Agent assigned "
        f"{len(expected)} finding(s) to this tier, but your tier file "
        f"contains only {len(produced)}. The following "
        f"{len(missing)} finding(s) are MISSING from your output and "
        "MUST be written in this attempt:\n"
        "\n"
        f"  {sample}\n"
        "\n"
        "Treat the existing tier file as baseline — APPEND the missing "
        "findings at the correct severity position, do NOT rewrite the "
        "findings that are already present. Use `report_index.md` as the "
        "authoritative source for each missing finding's title, location, "
        "severity, and internal-hypothesis cross-reference.\n"
    )


def _generate_assemble_retry_hint(
    scratchpad: Path, project_root: str
) -> str | None:
    """Compute a delta-aware retry hint for report_assemble quality gate.

    Returns a prompt suffix listing per-tier (summary_count, body_count)
    mismatches, or None if counts reconcile.
    """
    deltas = _compute_assemble_count_delta(scratchpad, project_root)
    mismatches = [
        (c, s, b) for c, (s, b) in deltas.items() if s != b
    ]
    if not mismatches:
        return None
    lines = [
        "## RETRY HINT — assembler count reconciliation (v2.1.6)",
        "",
        "Your previous assembled AUDIT_REPORT.md has a mismatch between "
        "the Summary table counts and the actual `### [X-NN]` body "
        "sections. Per-tier deltas:",
        "",
        "| Tier | Summary says | Body has |",
        "|------|--------------|----------|",
    ]
    name_map = {"C": "Critical", "H": "High", "M": "Medium",
                "L": "Low", "I": "Informational"}
    for c, s, b in mismatches:
        lines.append(f"| {name_map[c]} | {s} | {b} |")
    lines.extend([
        "",
        "Resolution: the body is the source of truth (each section is "
        "authored by a tier writer). Update the Summary table to match "
        "the body count. Do NOT add or remove body sections — those came "
        "from the tier writers and are canonical.",
        "",
    ])
    return "\n".join(lines)


def _generate_recon_retry_hint(missing: list[str]) -> str:
    """Build a targeted retry hint for recon gate failures.

    Handles two failure classes:
    1. Stub-only/missing artifacts — specific files need content written.
    2. Coverage failures — substantial modules uncited in recon output.
    """
    if not missing:
        return ""
    text = "\n".join(str(x) for x in missing)

    # --- Class 1: stub-only or missing artifacts ---
    stub_artifacts: list[str] = []
    for item in missing:
        m = re.match(r"^(\S+\.md)\s*\(stub only\)$", str(item))
        if m:
            stub_artifacts.append(m.group(1))
        elif str(item).endswith(".md") and "coverage" not in str(item).lower() and "content" not in str(item).lower():
            stub_artifacts.append(str(item).split()[0])

    if stub_artifacts:
        lines = [
            "## RETRY HINT - recon artifacts missing or empty",
            "",
            "The previous attempt wrote some recon files but left these "
            "empty or too small. The other recon artifacts are complete — "
            "do NOT rewrite them.",
            "",
            "ONLY produce these files (read existing complete artifacts "
            "for context, do NOT modify them):",
        ]
        for name in stub_artifacts:
            lines.append(f"- {name}")
        lines.extend([
            "",
            "IMPORTANT: Work sequentially on each file. Do NOT spawn "
            "parallel sub-agents — process one file at a time to avoid "
            "capacity issues.",
        ])
        # If there are also coverage failures, append them
        coverage_items = [
            item for item in missing
            if "coverage" in str(item).lower()
        ]
        if coverage_items:
            lines.extend(["", "Additionally fix these coverage gaps:"])
            for item in coverage_items:
                lines.append(f"- {item}")
        return "\n".join(lines) + "\n"

    # --- Class 2: coverage failures only ---
    modules: list[str] = []
    m = re.search(
        r"recon missed substantial modules .*?:\s*(.+)$",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if m:
        modules = [
            x.strip()
            for x in re.split(r",\s*", m.group(1))
            if x.strip()
        ][:12]
    lines = [
        "## RETRY HINT - recon coverage gate failed",
        "",
        "The previous recon attempt produced artifacts but failed the "
        "mechanical coverage gate. Do not treat existing recon files as "
        "complete until this delta is fixed.",
        "",
        "Required action:",
        "1. For each missed substantial module below, cite at least one "
        "real in-scope source file path from that module in a recon artifact.",
        "2. If a module is intentionally out of scope, add rows to "
        "scope_leftover.md with ACKNOWLEDGED status for the skipped files.",
        "3. Keep existing recon content; append the missing coverage rather "
        "than rewriting everything.",
        "",
        "Gate failure:",
    ]
    for item in missing:
        lines.append(f"- {item}")
    if modules:
        lines.extend(["", "Missed modules to cover or ACKNOWLEDGE:"])
        for mod in modules:
            lines.append(f"- {mod}")
    return "\n".join(lines) + "\n"


def _generate_breadth_retry_hint(scratchpad: Path, missing: list[str]) -> str:
    expected = parse_breadth_manifest_outputs(scratchpad) or []
    open_outputs: list[str] = []
    min_bytes = 200
    for name in expected:
        p = scratchpad / name
        if not p.exists() or p.stat().st_size < min_bytes:
            open_outputs.append(name)
    if not open_outputs and not missing:
        return ""
    lines = [
        "## RETRY HINT - breadth manifest completion failed",
        "",
        "The previous breadth attempt returned before all manifest-derived "
        "`analysis_<focus_area>.md` outputs were substantial. Do not proceed "
        "to later phases, and do not count non-manifest analysis files.",
        "",
        "Required completion loop:",
        "1. Read `spawn_manifest.md` and derive the expected breadth outputs.",
        "2. Re-list those expected files in the scratchpad. File existence/size "
        "is authoritative; ignore stale COMPLETE/PENDING text in the manifest "
        "Status column.",
        f"3. Spawn ONLY rows whose output is missing or below {min_bytes} bytes.",
        "4. Use batches of at most 6 parallel Task calls.",
        "5. After each batch returns, repeat steps 2-4.",
        "6. Exit only when no expected output is missing or stub.",
        "",
    ]
    if open_outputs:
        lines.append("Open manifest outputs:")
        for name in open_outputs[:30]:
            lines.append(f"- {name}")
        if len(open_outputs) > 30:
            lines.append(f"- ... (+{len(open_outputs) - 30} more)")
        lines.append("")
    if missing:
        lines.append("Gate failure:")
        for item in missing:
            lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def _sync_degraded_sentinels_to_checkpoint(
    scratchpad: Path, checkpoint: "Checkpoint"
) -> list[str]:
    """Scan scratchpad for `*.degraded` sentinels and append to checkpoint.

    Fixes a prior L1 observation: `_v2_checkpoint.json.degraded == []`
    disagrees with 3 `.degraded` files on disk. Readers of the checkpoint
    JSON get a falsely-clean picture. This helper reconciles — called at
    pipeline shutdown.

    Returns the list of sentinel phase names added.
    """
    added: list[str] = []
    for p in sorted(scratchpad.glob("*.degraded")):
        # RESUME-4: use the canonical sentinel->phase mapper (handles compound
        # suffixes like `.body_writer.degraded`) so a phantom phase name is
        # never injected into checkpoint.degraded (which would force a false
        # EXIT_DEGRADED final state) and stale compound sentinels for completed
        # phases are correctly cleaned. The naive `.degraded` strip diverged
        # from _clear_stale_degraded_sentinels' mapping.
        phase_name = _phase_name_from_sentinel(p.name)
        if phase_name in checkpoint.completed:
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
            continue
        if phase_name and phase_name not in checkpoint.degraded:
            checkpoint.degraded.append(phase_name)
            added.append(phase_name)
    return added


def _generate_verify_core_if_missing(scratchpad: Path) -> bool:
    """Mechanical aggregation of verify_*.md into verify_core.md.

    v2.2.2 Fix 3 — ALWAYS rebuild. Pre-v2.2.2 this helper was a
    "if missing or <100 bytes" fallback. Live failure mode (a prior
    L1 run): the LLM-written verify_core.md existed and was >100 bytes
    but contained ONLY the crit/high shard — the medium shard's 31
    verifier rows were missing. The fallback didn't fire, the Index
    Agent read the incomplete aggregate, and 31 verified findings were
    silently dropped from the report (analytical baseline of 18/74
    recall regressed to 7/74 visible).

    The fix: always rebuild from filesystem `verify_*.md` glob. The
    LLM doesn't add semantic value to a one-row-per-finding aggregate;
    the per-finding semantics live in the individual verify files. The
    aggregate is a deterministic projection — own it deterministically.

    Returns True if the file was written here, False if no verify_*.md
    files exist to aggregate.
    """
    target = scratchpad / "verify_core.md"
    verify_files = sorted(
        f for f in scratchpad.glob("verify_*.md")
        if f.name != "verify_core.md"
        and not f.name.endswith(_RETRY_HINT_SUFFIX)
        # Skeptic / judge files are NOT verifier outputs.
        and "skeptic" not in f.name
        and "judge" not in f.name
    )
    if not verify_files:
        if not target.exists():
            target.write_text(
                "# Verification Core (Auto-Generated)\n\n"
                "No `verify_*.md` files found. "
                "All verification shards may have been skipped.\n\n"
                "| Finding | Verdict | Evidence | Severity |\n"
                "|---------|---------|----------|----------|\n",
                encoding="utf-8",
            )
        return False

    rows: list[tuple[str, str, str, str]] = []
    for vf in verify_files:
        try:
            t = vf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Extract finding ID from filename: verify_H-03.md, verify_F-L1-C-01.md,
        # verify_H-C01.md (L1 tiered), verify_H-M27.md, verify_H-L07.md.
        # v2.3.2 F1: align with _collect_verify_hypothesis_ids' permissive
        # regex. The prior `-\d+` trailing requirement rejected L1 tiered
        # IDs (H-C01 / H-M27 / H-L07) — same bug class as v2.2.2 Fix 1, just
        # in a different gate. Falling back to vf.stem produced garbage
        # `verify_H-C01` rows in the verify_core.md aggregate.
        fid_match = re.search(
            r"verify_(?:F-)?([A-Z][A-Z0-9\-]*\d+)", vf.stem
        )
        fid = fid_match.group(1) if fid_match else vf.stem
        verdict_field = _field_from_markdown(
            t, ("Verdict", "Final Verdict", "Status")
        )
        verdict = (
            _verifier_status_from_text(f"Verdict: {verdict_field}")
            if verdict_field else ""
        ) or "-"
        tag_field = _field_from_markdown(
            t, ("Evidence Tag", "Evidence Tags", "Evidence")
        )
        tag_match = re.search(
            r"\[(" + EVIDENCE_TAG_NAMES_RE + r")\b",
            tag_field or t,
        )
        tag = f"[{tag_match.group(1)}]" if tag_match else (tag_field or "-")
        loc_field = _field_from_markdown(t, ("Location", "Location(s)"))
        loc = (loc_field.strip(" *`") if loc_field else "-")[:80]
        rows.append((fid, verdict, tag, loc))

    rows.sort(key=lambda r: r[0])
    lines = [
        "# verify_core.md (mechanical aggregate — v2.2.2)",
        "",
        f"> Aggregated from {len(rows)} `verify_*.md` file(s) by the "
        "driver. v2.2.2 always rebuilds (was: fallback if missing or "
        "<100 bytes) — the prior conditional logic let an LLM-written "
        "incomplete aggregate slip past the threshold and silently "
        "dropped a whole verify shard. See individual `verify_*.md` "
        "files for full per-finding verification detail.",
        "",
        "| Finding ID | Verdict | Evidence Tag | Location |",
        "|------------|---------|--------------|----------|",
    ]
    for fid, verdict, tag, loc in rows:
        lines.append(f"| {fid} | {verdict} | {tag} | {loc} |")
    lines.append("")
    try:
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True
    except Exception as e:
        log.warning(f"verify_core mechanical fallback write failed: {e}")
        return False


def _validate_verify_content_quality(
    scratchpad: Path, max_thin_ratio: float = 0.40
) -> list[str]:
    """Detect when too many verify_*.md files are content-thin.

    GATE-4 / SOFT-WARN ONLY -- this is a PROSE/LLM-quality judgment (counting
    "substantive sections"), NOT a mechanical guarantee. It is currently UNWIRED.
    If it is ever wired, its result MUST be logged as a WARNING and MUST NOT be
    appended to any phase's hard-issue list (doing so would reintroduce the
    prose-gate false-halt class on the critical verify_aggregate path -- see
    GATE-1/GATE-2). Mechanical verify guarantees live in mechanical_verify.py.

    Closes Codex gap #5: a verify file that has only `**Verdict**: CONFIRMED`
    with no Description / Impact / Recommendation cannot produce a useful
    report section. The renderer falls back to thin boilerplate. If too many
    verify files are thin, the report is silently shallow even though every
    queue ID is "verified."

    Threshold: >40% of verify files thin -> flag. Configurable via
    `max_thin_ratio` for stricter modes.

    A verify file is considered "thin" if it lacks at least 2 of the 4 key
    sections: Description, Impact, PoC Result, Recommendation. Skips
    skeptic/judge/aggregate files.
    """
    verify_files = sorted(
        f for f in scratchpad.glob("verify_*.md")
        if f.name not in {"verify_core.md", "verify_core_full.md"}
        and not f.name.endswith(_RETRY_HINT_SUFFIX)
        and "skeptic" not in f.name and "judge" not in f.name
    )
    if not verify_files:
        return []
    thin: list[str] = []
    section_re = re.compile(
        r"(?im)^#{2,4}\s+(?:Description|Impact|PoC Result|Recommendation|"
        r"Finding Summary|Analysis|Code Trace|Mitigation|Fix|"
        r"Assessment|Consequences|Testing|Suggested\s+Changes?|Proof|"
        r"Exploit|Severity|Root\s+Cause|Vulnerability|Overview|"
        r"Evidence|Details|Summary)\b",
    )
    for vf in verify_files:
        try:
            text = _llm_norm(vf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            text = ""
        # Count distinct section headings present (label only, no `###` prefix).
        sections = set()
        for m in section_re.finditer(text):
            label_only = re.sub(r"^#+\s+", "", m.group(0)).lower()
            sections.add(label_only)
        # Also accept inline `**Field**:` form for non-shard verifiers.
        for label in ("Description", "Impact", "PoC Result", "Recommendation",
                       "Assessment", "Consequences", "Severity", "Evidence",
                       "Root Cause", "Fix", "Mitigation", "Analysis"):
            if _field_from_markdown(text, (label,)):
                sections.add(label.lower())
        if len(sections) < 2:
            thin.append(vf.name)
    if not thin:
        return []
    ratio = len(thin) / len(verify_files)
    if ratio < max_thin_ratio:
        return []
    sample = ", ".join(thin[:5])
    more = f" (+{len(thin) - 5} more)" if len(thin) > 5 else ""
    return [
        f"verify content quality: {len(thin)}/{len(verify_files)} ({ratio:.0%}) "
        f"verify_*.md files are content-thin (<2 of Description/Impact/PoC/"
        f"Recommendation sections); the report will be shallow. Files: "
        f"{sample}{more}"
    ]


def _validate_crossbatch_quality(scratchpad: Path) -> list[str]:
    """Promote crossbatch warnings into gate signal (v2.1.6).

    A prior L1 run exposed that `cross_batch_consistency.md` frequently
    reports "Overall: ISSUES FOUND" with 21 findings missing evidence
    tags etc., but the driver did not halt. Those issues mean downstream
    verdicts lack mechanical proof tags — a substance problem.

    This helper returns gate issues when the crossbatch file reports
    missing-evidence above a threshold. SOFT: returns [] when file
    missing or unparseable.
    """
    p = scratchpad / "cross_batch_consistency.md"
    if not p.exists():
        return []
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    # Look for explicit counts. Pattern: "21 findings missing evidence tags"
    issues: list[str] = []
    m = re.search(
        r"(\d+)\s+findings?\s+missing\s+evidence\s+tags?",
        text, re.IGNORECASE,
    )
    if m:
        n = int(m.group(1))
        # 20+ missing evidence tags is suspicious; 5+ in a small audit is too.
        # Use percentage-of-total when we can find the "Files checked: N" line.
        total_m = re.search(
            r"Files?\s+checked\s*:?\s*(\d+)", text, re.IGNORECASE,
        )
        total = int(total_m.group(1)) if total_m else None
        if total and total > 0:
            pct = (n / total) * 100
            if pct >= 30:
                issues.append(
                    f"crossbatch: {n}/{total} ({pct:.0f}%) findings missing "
                    "evidence tags — verify shards should re-attach"
                )
        elif n >= 20:
            issues.append(
                f"crossbatch: {n} findings missing evidence tags — "
                "verify shards should re-attach"
            )
    _fail_signal_patterns = (
        r"overall\b[^:]*:\s*(?:fail|issues)",
        r"status\b[^:]*:\s*fail",
        r"schema\s+violations?",
        r"severity\s+mismatches?",
        r"missing\s+severity\s+field",
        r"evidence[- ]?tag\s+mismatches?",
    )
    lowered = text.lower()
    expected_ids = _collect_verify_hypothesis_ids(scratchpad)
    checked_total = None
    checked_patterns = (
        r"Verifiers?\s+Checked\s*:?\s*(\d+)",
        r"Verify\s+Files\s+Checked\s*:?\s*(\d+)",
        r"Files?\s+checked\s*:?\s*(\d+)",
        r"Checked\s*:?\s*(\d+)\s*/\s*(\d+)",
    )
    for pat in checked_patterns:
        cm = re.search(pat, text, re.IGNORECASE)
        if not cm:
            continue
        checked_total = int(cm.group(1))
        if len(cm.groups()) >= 2 and cm.group(2):
            declared_total = int(cm.group(2))
            if expected_ids and declared_total < len(expected_ids):
                issues.append(
                    f"crossbatch: declared scope {declared_total} below "
                    f"{len(expected_ids)} verify file(s)"
                )
        break
    # ID coverage is checked separately by _validate_crossbatch_full_coverage
    # (which accepts affirmation phrases, range patterns, and enumeration).
    # This quality gate focuses on substance: evidence-tag rates + fail signals.
    # The prior redundant coverage check here used a stricter format requirement
    # than the full-coverage gate, causing false failures when haiku wrote
    # honest summaries without literal `Checked: N/M` patterns.
    if any(re.search(pat, lowered) for pat in _fail_signal_patterns):
        issues.append(
            "crossbatch: consistency/schema issues reported; see "
            "cross_batch_consistency.md"
        )
    return issues


def _crossbatch_verify_file_ids(scratchpad: Path) -> list[tuple[str, str]]:
    """Return `(finding_id, filename)` rows for real verifier artifacts."""
    rows: list[tuple[str, str]] = []
    for p in sorted(scratchpad.glob("verify_*.md")):
        if p.name.endswith(_RETRY_HINT_SUFFIX):
            continue
        stem = p.stem
        if stem.startswith("verify_F-"):
            fid = stem[len("verify_F-"):]
        elif stem.startswith("verify_F_"):
            fid = stem[len("verify_F_"):]
        elif stem.startswith("verify_"):
            tok = stem[len("verify_"):]
            if tok in {"core", "queue", "aggregate", "NONE"}:
                continue
            fid = tok.strip("[]")
        else:
            continue
        if fid:
            rows.append((fid, p.name))
    return rows


def _crossbatch_manifest_rows(scratchpad: Path) -> list[dict[str, str]]:
    """Return the canonical crossbatch scope rows."""
    queue_by_id = {
        (row.get("finding id") or "").strip(): row
        for row in parse_verification_queue_rows(scratchpad)
        if (row.get("finding id") or "").strip()
    }
    rows: list[dict[str, str]] = []
    for fid, filename in _crossbatch_verify_file_ids(scratchpad):
        p = scratchpad / filename
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        qrow = queue_by_id.get(fid, {})
        verdict = _verifier_status_from_text(text) or "-"
        severity = _severity_name_from_text(text, qrow) if text else (
            qrow.get("severity") or "-"
        )
        evidence = (
            _field_from_markdown(text, ("Evidence Tag", "Evidence Tags", "Evidence"))
            or qrow.get("preferred tag")
            or "-"
        )
        title = (
            _field_from_markdown(text, ("Title", "Finding", "Finding Title"))
            or qrow.get("title")
            or "-"
        )
        rows.append({
            "finding_id": fid,
            "verify_file": filename,
            "verdict": verdict,
            "severity": severity,
            "evidence_tag": evidence,
            "title": title,
        })
    return rows


def _write_crossbatch_manifest(scratchpad: Path) -> list[dict[str, str]]:
    """Write the manifest that makes crossbatch scope explicit."""
    rows = _crossbatch_manifest_rows(scratchpad)
    payload = {
        "phase": "crossbatch",
        "required_count": len(rows),
        "findings": rows,
    }
    target = scratchpad / "crossbatch_manifest.json"
    content = json.dumps(payload, indent=2)
    try:
        if target.exists() and target.read_text(encoding="utf-8") == content:
            return rows
    except Exception:
        pass
    target.write_text(content, encoding="utf-8")
    return rows


def _crossbatch_expected_rows(scratchpad: Path) -> list[tuple[str, str]]:
    """Return expected `(finding_id, verify_file)` rows for crossbatch."""
    current_rows = _crossbatch_verify_file_ids(scratchpad)
    if current_rows:
        return current_rows
    manifest = scratchpad / "crossbatch_manifest.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        rows = []
        for item in data.get("findings", []) or []:
            fid = str(item.get("finding_id") or "").strip()
            filename = str(item.get("verify_file") or "").strip()
            if fid:
                rows.append((fid, filename))
        return rows
    return []


def _append_crossbatch_coverage_ledger(scratchpad: Path) -> list[str]:
    """Append missing verify IDs to the crossbatch coverage ledger.

    The crossbatch LLM owns contradiction analysis. The driver owns the
    transition invariant that every verifier artifact is explicitly accounted
    for. If the LLM writes valid consistency prose but omits some IDs, append
    a truthful coverage-only ledger so downstream gates do not force a retry
    for an ID-list omission.
    """
    cb = scratchpad / "cross_batch_consistency.md"
    if not cb.exists():
        return []
    try:
        cb_text = cb.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    verify_rows = _crossbatch_expected_rows(scratchpad)
    if not verify_rows:
        return []
    cb_ids = _extract_finding_ids_from_text(cb_text)
    missing_rows = [
        (fid, filename)
        for fid, filename in verify_rows
        if fid not in cb_ids and fid not in cb_text
    ]
    if not missing_rows:
        return []

    lines = [
        "",
        "## Verify Coverage Ledger (Driver Completion)",
        "",
        "The crossbatch agent did not explicitly list every manifest verifier ID. "
        "The driver appended this coverage-only ledger to preserve the phase "
        "transition contract. Rows below mean the verifier file exists and no "
        "cross-batch contradiction was reported for that ID by the agent.",
        "",
        "| Finding ID | Verify Artifact | Cross-Batch Status | Notes |",
        "|------------|-----------------|--------------------|-------|",
    ]
    for fid, filename in missing_rows:
        lines.append(
            f"| {fid} | {filename} | NO_CONTRADICTION_REPORTED_BY_AGENT | "
            "DRIVER_COVERAGE_COMPLETION; verifier artifact present. |"
        )
    lines.append("")
    try:
        cb.write_text(cb_text.rstrip() + "\n" + "\n".join(lines), encoding="utf-8")
    except Exception:
        return []
    return [fid for fid, _filename in missing_rows]


def _skeptic_manifest_ids(scratchpad: Path) -> list[str]:
    """Return current skeptic scope IDs, falling back to old manifests only.

    Stale `skeptic_manifest.json` files caused critical/high verifier outputs
    created after queue regeneration to escape skeptic coverage. The current
    verifier/queue state is the contract; the manifest is just a prompt aid.
    """
    current = [r["finding_id"] for r in _skeptic_expected_findings(scratchpad)]
    if current:
        return list(dict.fromkeys(current))
    path = scratchpad / "skeptic_manifest.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    out: list[str] = []
    for item in payload.get("findings", []):
        if not isinstance(item, dict):
            continue
        fid = str(item.get("finding_id") or "").strip()
        if fid:
            out.append(fid)
    return out


def _validate_skeptic_scope(scratchpad: Path) -> list[str]:
    """Ensure the dedicated skeptic phase covers every Critical/High finding."""
    manifest_ids = _skeptic_manifest_ids(scratchpad)
    if manifest_ids:
        expected = set(manifest_ids)
    else:
        expected: set[str] = set()
        queue_rows = parse_verification_queue_rows(scratchpad)
        for row in queue_rows:
            fid = (row.get("finding id") or "").strip()
            if not fid:
                continue
            if _severity_bucket(row.get("severity", "")) not in {"critical", "high"}:
                continue
            vp = _verify_file_for_id(scratchpad, fid)
            try:
                vtxt = vp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                vtxt = ""
            if _is_reportable_verdict(_verifier_status_from_text(vtxt)):
                expected.add(fid)
    if not expected:
        return []

    texts: list[str] = []
    for name in ("skeptic_findings.md", "skeptic_judge_decisions.md"):
        p = scratchpad / name
        if p.exists():
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                pass
    for p in sorted(scratchpad.glob("judge_*.md")):
        try:
            texts.append(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    if not texts:
        return [f"skeptic scope: missing skeptic/judge artifacts for {len(expected)} C/H finding(s)"]
    combined = "\n".join(texts)
    covered = set(_INTERNAL_FINDING_ID_RE.findall(combined))

    # Closes Codex gap #3: skeptic files often reference report IDs (C-01,
    # H-03) instead of internal finding IDs (INV-001). Resolve via the
    # Master Finding Index mapping so a legitimately-thorough skeptic
    # review using only report IDs doesn't false-flag.
    internal_to_report: dict[str, str] = {}
    report_to_internal: dict[str, str] = {}
    try:
        for a in get_tier_assignments(scratchpad)[0]:
            fid = a.get("finding_id", "")
            rid = a.get("report_id", "")
            if fid and rid:
                internal_to_report[fid] = rid
                report_to_internal[rid] = fid
    except Exception:
        pass
    if internal_to_report:
        # Treat report IDs in skeptic text as covering their mapped internal IDs.
        for rid in list(covered):
            mapped = report_to_internal.get(rid)
            if mapped:
                covered.add(mapped)
    missing = sorted(expected - covered)
    if missing:
        sample = ", ".join(missing[:8])
        more = f" (+{len(missing)-8} more)" if len(missing) > 8 else ""
        return [
            f"skeptic scope: reviewed {len(expected)-len(missing)}/{len(expected)} "
            f"Critical/High finding(s); missing {sample}{more}"
        ]
    return []


# --- end v2.1.6 helpers -----------------------------------------------------
# --- v2.1.8: strict phase-isolation via quarantine --------------------------
#
# Some phases' subagents produce later-phase artifacts inline as an
# optimization. v2.1.6 accepted these via an allowlist. v2.1.8 refines:
# adversarial-class artifacts (skeptic, judge, crossbatch) MUST be produced
# in their dedicated phases with fresh context per AD-2 (rules/phase4-
# confidence-scoring.md), so we quarantine them out of the way and let the
# dedicated phases run. Mechanical-aggregate artifacts (verify_core.md)
# remain allowed inline.
# Files that must be produced ONLY by their dedicated phase. If they appear
# during a different phase's subprocess, we move them aside rather than
# halt — keeps the pipeline seamless while preserving phase isolation.
_QUARANTINE_PATTERNS_BY_PHASE: dict[str, tuple[str, ...]] = {
    # Verify phases must NOT produce skeptic/crossbatch artifacts inline.
    # Same-context production loses adversarial divergence (skeptic) and
    # cross-shard independence (crossbatch). verify_core.md is exempt — it's
    # mechanical aggregation, no adversarial reasoning.
    "verify": (
        "skeptic_*.md", "judge_*.md",
        "cross_batch_consistency*.md", "scanner_validation_*.md",
    ),
    "verify_crithigh": (
        "skeptic_*.md", "judge_*.md",
        "cross_batch_consistency*.md",
    ),
    "verify_medium_a": (
        "skeptic_*.md", "judge_*.md",
        "cross_batch_consistency*.md",
    ),
    "verify_medium_b": (
        "skeptic_*.md", "judge_*.md",
        "cross_batch_consistency*.md",
    ),
}
for _verify_phase_name in L1_VERIFY_PHASE_NAMES:
    _QUARANTINE_PATTERNS_BY_PHASE.setdefault(_verify_phase_name, (
        "skeptic_*.md", "judge_*.md", "cross_batch_consistency*.md",
    ))
for _verify_phase_name in SC_VERIFY_PHASE_NAMES:
    _QUARANTINE_PATTERNS_BY_PHASE.setdefault(_verify_phase_name, (
        "skeptic_*.md", "judge_*.md", "cross_batch_consistency*.md",
    ))


def _quarantine_phase_overreach(
    scratchpad: Path, phase_name: str, file_state_before: dict
) -> list[str]:
    """Move later-phase artifacts written by this phase into `_overflow/`.

    Strict phase isolation, seamless mode: the dedicated downstream phase
    will produce its canonical output with fresh context. The quarantined
    file is preserved for forensics — operator can inspect after run.

    Returns the list of (relative) filenames moved.
    """
    patterns = _QUARANTINE_PATTERNS_BY_PHASE.get(phase_name)
    if not patterns:
        return []
    overflow_dir = scratchpad / "_overflow" / phase_name
    moved: list[str] = []
    for pat in patterns:
        for src in scratchpad.glob(pat):
            # Only quarantine files that this phase actually produced or
            # modified — i.e., not present in `file_state_before` snapshot
            # OR mtime/size differs.
            try:
                st = src.stat()
                cur_meta = (st.st_mtime_ns, st.st_size)
            except Exception:
                continue
            prev_meta = file_state_before.get(src.name)
            changed = prev_meta is None or prev_meta != cur_meta
            if not changed:
                continue
            try:
                overflow_dir.mkdir(parents=True, exist_ok=True)
                dst = overflow_dir / src.name
                # If dst already exists from a prior run, append a suffix.
                if dst.exists():
                    import time as _t
                    dst = overflow_dir / f"{src.stem}.{int(_t.time())}{src.suffix}"
                src.rename(dst)
                moved.append(src.name)
            except Exception as e:
                log.warning(
                    f"[{phase_name}] quarantine of {src.name} failed: {e}"
                )
    if moved:
        # Log to violations.md so the operator sees this in post-run.
        try:
            vp = scratchpad / "violations.md"
            with vp.open("a", encoding="utf-8") as f:
                f.write(
                    f"\n## v2.1.8 phase-isolation quarantine "
                    f"({phase_name})\n"
                )
                f.write(
                    "Inline production of dedicated-phase artifacts. Moved "
                    "to `_overflow/` so the dedicated phase can run with "
                    "fresh context (AD-2 adversarial divergence).\n"
                )
                for name in moved:
                    f.write(f"- {name} -> _overflow/{phase_name}/\n")
        except Exception:
            pass
    return moved


# --- v2.3.14: stale artifact quarantine before retry ----------------------------
# Phase-specific dynamic artifact patterns that should be quarantined on retry
# but are NOT in the phase's expected_artifacts (they're produced dynamically).
_RETRY_QUARANTINE_EXTRAS: dict[str, list[str]] = {
    "crossbatch": ["cross_batch_consistency.md"],
    "verify_aggregate": ["verify_core.md"],
    "graph_sweeps": ["graph_*.md"],
    "report_index": ["report_index.md", "report_coverage.md"],
    "skeptic": ["skeptic_findings.md", "skeptic_judge_decisions.md", "judge_*.md"],
}


_ACCUMULATE_ON_RETRY_PHASES: frozenset[str] = frozenset({
    "breadth", "rescan", "depth",
})
"""Phases where substantial attempt-1 artifacts should be KEPT on retry.

For these phases, the gate failure is a quorum shortfall (not enough files),
not a content problem. Existing substantial files are correct work products.
The RESUMPTION PROTOCOL sees them and only spawns agents for the missing
outputs — accumulating results across attempts instead of restarting from
scratch.
"""


def _retry_quarantine_dir(scratchpad: Path, phase_name: str) -> Path:
    return scratchpad / "_retry_quarantine" / phase_name


def _pattern_implicated_by_missing(pattern: str, missing: list[str]) -> bool:
    """Ship 8.15: True iff an artifact `pattern` is named in any gate-failure
    message in `missing`. For concrete filenames, substring match. For glob
    patterns (e.g. `graph_*.md`), match on the literal prefix before the first
    wildcard so a message naming `graph_foo.md` implicates `graph_*.md`.
    """
    if not missing:
        return False
    if any(ch in pattern for ch in "*?["):
        prefix = re.split(r"[*?\[]", pattern, 1)[0]
        return bool(prefix) and any(prefix in m for m in missing)
    return any(pattern in m for m in missing)


def _quarantine_stale_on_retry(
    scratchpad: Path, phase: Phase, missing: list[str]
) -> list[str]:
    """Rename stale phase outputs so the RESUMPTION PROTOCOL won't skip them.

    On retry after a gate failure, artifacts exist on disk but have wrong
    content. The RESUMPTION PROTOCOL sees >=500 bytes and tells the LLM
    "already done, skip." This function moves them under
    `_retry_quarantine/{phase}/` so the retry LLM cannot accidentally read and
    copy the known-bad output as source material.

    Only quarantines the phase's OWN outputs (expected_artifacts + dynamic
    extras). Never touches earlier-phase inputs.

    v2.4.5: phases in _ACCUMULATE_ON_RETRY_PHASES skip quarantine entirely.
    Their substantial files are correct partial work; the RESUMPTION PROTOCOL
    accumulates them across retry attempts.

    Returns list of renamed filenames (for logging).
    """
    if phase.name in _ACCUMULATE_ON_RETRY_PHASES:
        return []

    renamed: list[str] = []

    # Collect all patterns to quarantine: expected_artifacts + dynamic extras
    patterns: list[str] = list(phase.expected_artifacts or [])
    extras = _RETRY_QUARANTINE_EXTRAS.get(phase.name, [])
    patterns.extend(extras)

    # Ship 8.15: TARGETED REPAIR. Quarantine ONLY the artifacts implicated by
    # the gate-failure messages, not every expected artifact. Observed: a 443-byte
    # recon_summary.md failure broadly quarantined 5 VALID drafts
    # (design_context, contract_inventory, state_variables, function_list,
    # template_recommendations), forcing a full re-run + recompaction. The
    # `missing` messages name the failing file(s); use them so the retry
    # repairs only what failed and the RESUMPTION PROTOCOL keeps valid work.
    # Fallback: if NO expected artifact is named in any message (a global /
    # structural failure that doesn't cite a file), keep the old broad
    # behavior so the retry is not left blind with all-present artifacts.
    implicated = [p for p in patterns if _pattern_implicated_by_missing(p, missing)]
    if implicated:
        patterns = implicated

    # For skeptic, exclude skeptic_judge_decisions.md (it's a downstream
    # artifact consumed by report_index, not a skeptic-phase own output
    # in the same sense).
    exclude = set()
    if phase.name == "skeptic":
        exclude.add("skeptic_judge_decisions.md")

    for pattern in patterns:
        if pattern == "AUDIT_REPORT.md":
            # AUDIT_REPORT.md lives in project_root, not scratchpad
            continue
        is_glob = any(ch in pattern for ch in "*?[")
        if is_glob:
            matches = list(scratchpad.glob(pattern))
        else:
            p = scratchpad / pattern
            matches = [p] if p.exists() else []

        for src in matches:
            if src.name in exclude:
                continue
            try:
                if src.stat().st_size < 500:
                    continue  # stub, not stale — leave for RESUMPTION
                qdir = _retry_quarantine_dir(scratchpad, phase.name)
                qdir.mkdir(parents=True, exist_ok=True)
                dst = qdir / src.name
                # Don't overwrite a prior backup from the same phase.
                if dst.exists():
                    continue
                src.rename(dst)
                renamed.append(src.name)
            except Exception as e:
                log.debug(
                    f"[{phase.name}] quarantine-on-retry of "
                    f"{src.name} failed: {e}"
                )
    return renamed


def _restore_quarantined_on_retry_failure(
    scratchpad: Path, phase: Phase
) -> None:
    """Restore retry-quarantine backups when retry also fails (degraded).

    The stale content is better than nothing for downstream phases.
    """
    patterns: list[str] = list(phase.expected_artifacts or [])
    patterns.extend(_RETRY_QUARANTINE_EXTRAS.get(phase.name, []))

    for pattern in patterns:
        if pattern == "AUDIT_REPORT.md":
            continue
        is_glob = any(ch in pattern for ch in "*?[")
        backups: list[Path] = []
        qdir = _retry_quarantine_dir(scratchpad, phase.name)
        if is_glob:
            if qdir.exists():
                backups.extend(qdir.glob(pattern))
            backups.extend(scratchpad.glob(pattern + ".attempt1"))
        else:
            bp = qdir / pattern
            if bp.exists():
                backups.append(bp)
            legacy_bp = scratchpad / (pattern + ".attempt1")
            if legacy_bp.exists():
                backups.append(legacy_bp)

        for backup in backups:
            original = scratchpad / backup.name
            if backup.parent == scratchpad and backup.name.endswith(".attempt1"):
                original = scratchpad / backup.name.removesuffix(".attempt1")
            # Only restore if the retry didn't produce a replacement
            if not original.exists() or original.stat().st_size < 100:
                try:
                    backup.rename(original)
                except Exception:
                    pass
            else:
                # Retry produced its own version; discard backup
                try:
                    backup.unlink()
                except Exception:
                    pass


def _cleanup_quarantine_backups(
    scratchpad: Path, phase: Phase
) -> None:
    """Delete retry-quarantine backups after a successful retry.

    The retry produced valid replacements; the backups are no longer needed.
    """
    patterns: list[str] = list(phase.expected_artifacts or [])
    patterns.extend(_RETRY_QUARANTINE_EXTRAS.get(phase.name, []))

    for pattern in patterns:
        if pattern == "AUDIT_REPORT.md":
            continue
        is_glob = any(ch in pattern for ch in "*?[")
        backups: list[Path] = []
        qdir = _retry_quarantine_dir(scratchpad, phase.name)
        if is_glob:
            if qdir.exists():
                backups.extend(qdir.glob(pattern))
            backups.extend(scratchpad.glob(pattern + ".attempt1"))
        else:
            bp = qdir / pattern
            if bp.exists():
                backups.append(bp)
            legacy_bp = scratchpad / (pattern + ".attempt1")
            if legacy_bp.exists():
                backups.append(legacy_bp)

        for backup in backups:
            try:
                backup.unlink()
            except Exception:
                pass
    qdir = _retry_quarantine_dir(scratchpad, phase.name)
    try:
        if qdir.exists() and not any(qdir.iterdir()):
            qdir.rmdir()
            parent = qdir.parent
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
    except Exception:
        pass


# --- end v2.3.14 quarantine helpers -------------------------------------------
def _quarantine_foreign_phase_writes(
    scratchpad: Path,
    project_root: str,
    phase_name: str,
    offenders: list[str],
) -> tuple[list[str], list[str]]:
    """Move foreign later-phase artifacts aside after containment detection.

    `_quarantine_phase_overreach` handles a narrow allowlist before the
    containment check. This helper handles the general case, including
    `../AUDIT_REPORT.md` in the project root. Leaving a rogue project-root
    report in place made an earlier verifier-authored report look published
    even though the real report phases never ran.

    Returns ``(moved, failed)``. ``failed`` names any rogue later-phase artifact
    that could NOT be moved and is STILL at its root path — a live containment
    hole (a downstream consumer could read it, and neither the resume
    overflow-rewind — no ``_overflow`` entry is created — nor the reconcile —
    which checks EXPECTED artifacts, not ROGUE ones — would catch it). The caller
    MUST fail/re-run the phase when ``failed`` is non-empty rather than mark it
    complete with a live foreign file in place. The move itself is hardened:
    ``rename`` first, then a ``shutil.move`` copy+delete fallback for a transient
    lock / cross-device case, so a genuine ``failed`` means the file is truly
    stuck (e.g. held open elsewhere) and only a phase re-run can clear it.
    """
    if not offenders:
        return [], []
    import shutil
    overflow_dir = scratchpad / "_overflow" / phase_name
    moved: list[str] = []
    failed: list[str] = []
    for name in offenders:
        if name == "../AUDIT_REPORT.md":
            src = Path(project_root) / "AUDIT_REPORT.md"
        elif name.startswith("../"):
            src = Path(project_root) / name[3:]
        else:
            src = scratchpad / name
        if not src.exists() or not src.is_file():
            continue
        moved_ok = False
        try:
            overflow_dir.mkdir(parents=True, exist_ok=True)
            dst = overflow_dir / src.name
            if dst.exists():
                import time as _t
                dst = overflow_dir / f"{src.stem}.{int(_t.time())}{src.suffix}"
            try:
                src.rename(dst)
            except OSError:
                # transient lock / cross-device: fall back to copy+delete.
                shutil.move(str(src), str(dst))
            moved.append(name)
            moved_ok = True
        except Exception as e:
            log.warning(
                f"[{phase_name}] quarantine of foreign artifact {name} "
                f"failed: {e}"
            )
        if not moved_ok and src.exists():
            # Could not move it AND it is still live at root -> containment hole.
            failed.append(name)
    if moved:
        _mark_artifacts_quarantined(scratchpad, project_root, phase_name, moved)
        try:
            vp = scratchpad / "violations.md"
            with vp.open("a", encoding="utf-8") as f:
                f.write(
                    f"\n## phase-containment foreign-artifact quarantine "
                    f"({phase_name})\n"
                )
                for name in moved:
                    f.write(f"- {name} -> _overflow/{phase_name}/\n")
        except Exception:
            pass
    return moved, failed


def _quarantine_report_without_completed_assemble(
    scratchpad: Path,
    project_root: str,
    checkpoint: "Checkpoint",
) -> Optional[Path]:
    """Quarantine project-root AUDIT_REPORT.md unless assemble completed.

    A report is authoritative only if `report_assemble` completed in the
    checkpoint. This startup guard catches reports left behind by older driver
    versions or interrupted rogue phases before a resume can treat them as
    published output.
    """
    report = Path(project_root) / "AUDIT_REPORT.md"
    if not report.exists() or "report_assemble" in checkpoint.completed:
        return None
    overflow = scratchpad / "_overflow" / "startup_report_guard"
    try:
        overflow.mkdir(parents=True, exist_ok=True)
        dst = overflow / report.name
        if dst.exists():
            import time as _t
            dst = overflow / f"{report.stem}.{int(_t.time())}{report.suffix}"
        report.rename(dst)
        try:
            with (scratchpad / "violations.md").open("a", encoding="utf-8") as f:
                f.write(
                    "\n## startup report quarantine\n"
                    "Moved project-root AUDIT_REPORT.md because "
                    "`report_assemble` is not completed in _v2_checkpoint.json.\n"
                    f"- ../AUDIT_REPORT.md -> {dst.relative_to(scratchpad)}\n"
                )
        except Exception:
            pass
        return dst
    except Exception as e:
        log.warning(
            "[startup] failed to quarantine AUDIT_REPORT.md without completed "
            f"report_assemble: {e}"
        )
        return None


def _rewind_completed_after_overflow(
    scratchpad: Path,
    checkpoint: "Checkpoint",
    phases: list[Phase],
) -> list[str]:
    """Rewind checkpoint when a completed phase has UNRECONCILED overflow.

    `_overflow/<phase>/` means that phase once wrote artifacts owned by later
    phases (a phase-containment leak that was quarantined out of its scope).

    HEAL-AWARE DEFAULT — do NOT rewind. A non-empty `_overflow/<phase>/` from an
    already-reconciled run (the phase re-ran and completed cleanly with the
    foreign files quarantined OUT of its active scope, and downstream phases
    completed consuming the clean output) is a HISTORICAL record, not a live
    contamination. Rewinding it discards a substantively-complete audit — the
    exact failure this default prevents (a stale inventory-leak quarantine
    should never nuke ~50 completed downstream phases on resume). The per-phase
    artifact-gate reconcile (`_reconcile_completed_checkpoint_artifacts`) remains
    the real, precise safety net: it independently rewinds any completed phase
    whose artifact gate genuinely fails, plus its downstream. So trusting the
    healed state here loses no correctness. The stale record is archived to
    `_healed_<ts>` (preserved, inert) so it doesn't re-trigger detection/logging.

    OPT-IN RERUN — for the narrow developer case "I landed a phase-containment
    FIX and want the affected completed phases rerun under it," set
    `PLAMEN_REWIND_ON_OVERFLOW=1`: this reruns the contaminated phase and every
    completed downstream phase (the prior always-on behavior).
    """
    overflow = scratchpad / "_overflow"
    if not overflow.exists():
        return []
    phase_order = [p.name for p in phases]
    completed = list(checkpoint.completed or [])
    contaminated: list[str] = [
        name for name in completed
        if (overflow / name).exists() and any((overflow / name).iterdir())
    ]
    if not contaminated:
        return []

    opt_in = os.environ.get("PLAMEN_REWIND_ON_OVERFLOW", "").strip().lower() in (
        "1", "true", "yes", "on"
    )

    def _archive(name: str, tag: str) -> None:
        phase_dir = overflow / name
        if not phase_dir.exists():
            return
        archive = overflow / f"{name}_{tag}_{int(time.time())}"
        try:
            phase_dir.rename(archive)
        except OSError:
            import shutil
            shutil.move(str(phase_dir), str(archive))

    if not opt_in:
        # Heal-aware default: trust the reconciled run; archive the stale record
        # so it stays inert and does not re-trigger detection on later resumes.
        for name in contaminated:
            _archive(name, "healed")
        log.info(
            "[resume] heal-aware: completed phase(s) %s have stale (already-"
            "reconciled) overflow; archived to _healed_ WITHOUT rewinding (the "
            "artifact-gate reconcile still validates each phase). Set "
            "PLAMEN_REWIND_ON_OVERFLOW=1 to rerun them after a containment fix.",
            ", ".join(contaminated),
        )
        return []

    # Opt-in rerun-after-fix path (prior behavior): rerun the contaminated phase
    # and every completed downstream phase.
    indices = [phase_order.index(name) for name in contaminated if name in phase_order]
    if not indices:
        return []
    first_idx = min(indices)
    removed = [
        name for name in completed
        if name in phase_order and phase_order.index(name) >= first_idx
    ]
    if removed:
        checkpoint.completed = [
            name for name in completed
            if name not in removed
        ]
        checkpoint.degraded = [
            name for name in (checkpoint.degraded or [])
            if name not in removed
        ]
    # Archive consumed overflow dirs so the next resume doesn't re-detect
    # them and rewind again (infinite loop).
    for name in contaminated:
        _archive(name, "rewound")
    return removed


def _skeptic_expected_findings(scratchpad: Path) -> list[dict[str, str]]:
    """Return reportable Critical/High findings the skeptic must cover."""
    queue_rows = parse_verification_queue_rows(scratchpad)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in queue_rows:
        fid = (row.get("finding id") or "").strip()
        if not fid or fid in seen:
            continue
        vp = _verify_file_for_id(scratchpad, fid)
        try:
            vtxt = vp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            vtxt = ""
        status = _verifier_status_from_text(vtxt)
        if not _is_reportable_verdict(status):
            continue
        severity = _severity_name_from_text(vtxt, row)
        if _severity_bucket(severity) not in {"critical", "high"}:
            continue
        seen.add(fid)
        title = (
            _field_from_markdown(vtxt, ("Title", "Finding", "Finding Title"))
            or row.get("title")
            or ""
        )
        location = _first_production_location_for_validator(
            vtxt,
            row.get("location") or "",
        ).strip(" *`")
        evidence = _field_from_markdown(
            vtxt, ("Evidence Tag", "Evidence Tags", "Evidence")
        )
        out.append({
            "finding_id": fid,
            "title": title,
            "severity": severity,
            "location": location,
            "verify_file": vp.name,
            "evidence_tag": evidence,
        })
    return out


def _write_skeptic_manifest(scratchpad: Path) -> list[dict[str, str]]:
    """Write the manifest that makes skeptic scope explicit and retryable."""
    rows = _skeptic_expected_findings(scratchpad)
    path = scratchpad / "skeptic_manifest.json"
    payload = {
        "phase": "skeptic",
        "required_count": len(rows),
        "findings": rows,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return rows


def _generate_skeptic_retry_hint(scratchpad: Path) -> str:
    rows = _skeptic_expected_findings(scratchpad)
    required = {r["finding_id"] for r in rows}
    texts: list[str] = []
    for p in sorted(scratchpad.glob("skeptic_*.md")) + sorted(scratchpad.glob("judge_*.md")):
        try:
            texts.append(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass
    covered = _extract_finding_ids_from_text("\n".join(texts))
    missing = sorted(required - covered)
    if not missing:
        return ""
    lines = [
        "## RETRY HINT - skeptic coverage gate failed",
        "",
        f"The skeptic phase must cover every ID in `skeptic_manifest.json` "
        f"({len(required)} total). The previous attempt missed:",
        "",
    ]
    lines.extend(f"- {fid}" for fid in missing)
    lines.extend([
        "",
        "Required action: rewrite `skeptic_findings.md` and "
        "`skeptic_judge_decisions.md` so every missing ID appears explicitly.",
        "Do not use range wording unless the range covers every manifest ID.",
    ])
    return "\n".join(lines) + "\n"


# --- end v2.1.8 helpers -----------------------------------------------------
# --- v2.3.14: retry hint generators for all validator-gated phases -----------
def _generate_crossbatch_retry_hint(scratchpad: Path) -> str:
    """Build retry hint for crossbatch coverage failures."""
    cb = scratchpad / "cross_batch_consistency.md"
    verify_ids: list[str] = []
    for p in sorted(scratchpad.glob("verify_*.md")):
        stem = p.stem
        if stem.startswith("verify_F-"):
            verify_ids.append(stem[len("verify_F-"):])
        elif stem.startswith("verify_F_"):
            verify_ids.append(stem[len("verify_F_"):])
        elif stem.startswith("verify_"):
            tok = stem[len("verify_"):]
            if tok in {"core", "queue", "aggregate", "NONE"}:
                continue
            verify_ids.append(tok.strip("[]"))
    if not verify_ids:
        return ""
    lines = [
        "## RETRY HINT — crossbatch coverage gate (v2.3.14)",
        "",
        "Your `cross_batch_consistency.md` must explicitly mention EVERY "
        f"verify finding ID ({len(verify_ids)} total). The previous "
        "attempt missed some. Each ID must appear literally in the file.",
        "",
        "Required IDs:",
    ]
    for fid in verify_ids:
        lines.append(f"- {fid}")
    lines.append("")
    lines.append(
        "For each ID use a format like: "
        "'`{ID}`: consistent across batches / discrepancy noted'. "
        "Do NOT assume prior output files are correct — "
        "they have been quarantined."
    )
    return "\n".join(lines) + "\n"


def _generate_verify_aggregate_retry_hint(issues: list[str]) -> str:
    """Build retry hint for verify_aggregate evidence tag failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT ? verify_aggregate quality gate (v2.3.14)",
        "",
        "Your previous attempt failed these verification quality checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Each verify file MUST contain an evidence tag in one of these "
        "formats: `[POC-PASS]`, `[POC-FAIL]`, `[CODE-TRACE]`, "
        "`[MEDUSA-PASS]`, or a Preferred Tag / Evidence Tag field.",
        "",
        "Do NOT assume prior output files are correct ? "
        "they have been quarantined.",
    ])
    return "\n".join(lines) + "\n"

def _generate_graph_sweeps_retry_hint(issues: list[str]) -> str:
    """Build retry hint for graph_sweeps validation failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT — graph_sweeps quality gate (v2.3.14)",
        "",
        "Your previous attempt failed these graph sweep quality checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Produce output that satisfies ALL of the above. "
        "Do NOT assume prior output files are correct — "
        "they have been quarantined.",
    ])
    return "\n".join(lines) + "\n"


def _generate_attention_repair_retry_hint(issues: list[str]) -> str:
    """Build retry hint for attention_repair validation failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT — attention_repair quality gate (v2.3.14)",
        "",
        "Your previous attempt failed these attention repair checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Ensure every uncited path from the NOTREAD priority list is "
        "either cited in a depth/scanner artifact or explicitly "
        "acknowledged. Rewrite attention_repair_summary.md as a receipt "
        "table with one row per attention_repair_queue.md row. Copy Queue #, "
        "Kind, and Target exactly from the queue. For path targets, include "
        "the full relative path in Target and cite the same path again in "
        "Evidence with file:line support. Use a clear Verdict such as SAFE, "
        "COVERED, CONFIRMED, FINDING, FALSE_POSITIVE, NO_FINDING, or "
        "NEEDS_HUMAN if the source is unavailable. Do NOT assume prior output "
        "files are correct; they have been quarantined.",
    ])
    return "\n".join(lines) + "\n"


def _generate_inventory_retry_hint(issues: list[str]) -> str:
    """Build retry hint for inventory parity/structure failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT — inventory quality gate (v2.3.14)",
        "",
        "Your previous attempt failed these inventory quality checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Ensure findings_inventory.md covers ALL findings from breadth "
        "analysis files and follows the required table structure. "
        "Do NOT assume prior output files are correct — "
        "they have been quarantined.",
    ])
    return "\n".join(lines) + "\n"


def _read_inventory_merge_receipt(scratchpad: Path) -> dict[str, int]:
    receipt = scratchpad / "inventory_merge_receipt.md"
    if not receipt.exists():
        return {}
    try:
        text = receipt.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    out: dict[str, int] = {}
    for key, pattern in {
        "chunks": r"Chunk files\s*:\s*(\d+)",
        "parsed": r"Parsed chunk findings\s*:\s*(\d+)",
        "merged": r"Merged inventory findings\s*:\s*(\d+)",
    }.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            out[key] = int(m.group(1))
    return out


def _inventory_parity_artifact(scratchpad: Path) -> Path:
    """Return the immutable inventory artifact that the merge receipt covers."""
    for name in (
        "findings_inventory_base.md",
        "findings_inventory_pre_dedup.md",
        "findings_inventory.md",
    ):
        path = scratchpad / name
        if path.exists():
            return path
    return scratchpad / "findings_inventory.md"


def _write_inventory_base_snapshot(scratchpad: Path) -> bool:
    """Snapshot the original inventory merge output before downstream mutation."""
    current = scratchpad / "findings_inventory.md"
    if not current.exists():
        return False
    base = scratchpad / "findings_inventory_base.md"
    try:
        shutil.copy2(current, base)
        return True
    except Exception as exc:
        log.warning("[inventory] failed to write base inventory snapshot: %s", exc)
        return False


def _read_depth_promotion_receipt_count(scratchpad: Path) -> int:
    receipt = scratchpad / "depth_promotion_receipt.md"
    if not receipt.exists():
        return 0
    try:
        text = receipt.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    m = re.search(r"Promoted\s+(\d+)\s+depth finding", text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    promoted_section = re.search(
        r"(?is)^##\s+Promoted\b(.*?)(?=^##\s+|\Z)", text, re.MULTILINE,
    )
    if not promoted_section:
        return 0
    return len(re.findall(r"(?m)^\s*[-*]\s*`?([A-Z0-9_-]+-\d+)`?", promoted_section.group(1)))


def _count_depth_promotion_inventory_blocks(inv_text: str) -> int:
    section = re.search(
        r"(?is)^##\s+Depth Promotion Supplement\b(.*?)(?=^##\s+|\Z)",
        _llm_norm(inv_text),
        re.MULTILINE,
    )
    if not section:
        return 0
    return len(_inventory_blocks(section.group(1)))


def _count_niche_promotion_inventory_blocks(inv_text: str) -> int:
    """Count inventory blocks under the disjoint niche-promoted section.

    Niche-agent promotions are written to a separate `## Niche-Promoted
    Findings` section (promotion skips IDs already present in inventory, so
    this section is disjoint from the depth-promotion supplement and from the
    base inventory). The depth-promotion receipt does NOT account for these,
    so a clean merge can self-fail parity unless they are counted separately.
    """
    section = re.search(
        r"(?is)^##\s+Niche[- ]Promoted Findings\b(.*?)(?=^##\s+|\Z)",
        _llm_norm(inv_text),
        re.MULTILINE,
    )
    if not section:
        return 0
    return len(_inventory_blocks(section.group(1)))


def _generate_verify_queue_retry_hint(issues: list[str]) -> str:
    """Build retry hint for verify_queue parity failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT — verify_queue parity gate (v2.3.14)",
        "",
        "Your previous attempt failed these verification queue checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "The verification_queue.md must include every finding from "
        "findings_inventory.md. Do NOT assume prior output files are "
        "correct — they have been quarantined.",
    ])
    return "\n".join(lines) + "\n"


_PLAMEN_ORPHAN_REPAIR_HINT_CLAUDE = """\
## RETRY HINT — orphaned background agents detected (v2.0.3)

Your previous attempt invoked the Task tool with `run_in_background: true`
on {n} agents and ended its turn before agents could return. The following
files contain ONLY reservation headers and must be re-derived:
{file_list}

REPAIR:
1. Delete or overwrite the stub files listed above — their content is
   meaningless (header-only WRITE-THEN-VERIFY reservation).
2. Re-spawn each agent as a FOREGROUND Task call. Do NOT pass
   `run_in_background: true`. Spawn all in a single message.
3. Do NOT end_turn until every Task call has returned with a result.
4. The PLAMEN V2 EXECUTION CONTRACT at the top of this prompt is the
   binding directive — re-read it before spawning.
"""

_PLAMEN_ORPHAN_REPAIR_HINT_CODEX = """\
## RETRY HINT — orphaned spawn_agent calls detected (v2.0.3)

Your previous attempt called `spawn_agent` on {n} agents and exec exited
before calling `wait_agent` on all of them. The following files contain
ONLY reservation headers and must be re-derived:
{file_list}

REPAIR:
1. Delete or overwrite the stub files listed above.
2. For each agent, call `spawn_agent` then `wait_agent` BEFORE exec exits.
3. The PLAMEN V2 EXECUTION CONTRACT at the top of this prompt is the
   binding directive.
"""


def _generate_orphan_repair_hint(
    diag: dict, *, backend: str = "claude"
) -> str:
    """v2.0.3 (A4): targeted retry hint when the orphan-background signature
    was detected by `detect_background_orphan` (driver-side, post-subprocess).

    Reads the diagnostic dict written by A2 to `_diagnostic_orphan_{phase}.json`.
    Backend-aware: Claude variant cites Task/run_in_background; Codex variant
    cites spawn_agent/wait_agent. Per Codex Round-2 Claim 6, detection lives
    in the driver and writes the diagnostic; the validator-side hint generator
    is consumption-only and has no detection logic of its own.
    """
    stubs = diag.get("stub_files") or []
    n = diag.get("task_count_background") or diag.get("stub_count") or len(stubs)
    file_list = "\n".join(f"  - {s}" for s in stubs) if stubs else "  - (no stub files listed)"
    template = (
        _PLAMEN_ORPHAN_REPAIR_HINT_CODEX if backend == "codex"
        else _PLAMEN_ORPHAN_REPAIR_HINT_CLAUDE
    )
    return template.format(n=n, file_list=file_list)


def _generate_depth_retry_hint(
    issues: list[str], *,
    backend: str = "claude",
    scratchpad: Optional[Path] = None,
) -> str:
    """Build retry hint for depth execution-boundary and quality failures.

    v2.0.3 (A4): if the driver wrote `_diagnostic_orphan_depth.json` via
    `detect_background_orphan`, return the orphan-specific repair hint
    instead of the generic quality-gate text. The orphan path is a
    different failure class (LLM exited before agents returned vs. quality
    gate fired on substantive output) and needs a different repair plan.
    """
    # v2.0.3 (A4): orphan-background dispatch. Read the diagnostic written
    # by detect_background_orphan (driver-side). If present, the orphan
    # repair hint replaces the generic quality-gate text.
    if scratchpad is not None:
        diag_path = scratchpad / "_diagnostic_orphan_depth.json"
        if diag_path.exists():
            try:
                diag = json.loads(diag_path.read_text(encoding="utf-8"))
                return _generate_orphan_repair_hint(diag, backend=backend)
            except (OSError, json.JSONDecodeError):
                pass  # fall through to existing dispatch
    if not issues:
        return ""
    lines = [
        "## RETRY HINT — depth quality gate (v2.3.14)",
        "",
        "Your previous attempt failed these depth quality checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Repair rules:",
        "- Stay inside the depth phase only. Do NOT execute Phase 4b.5/RAG, final_scoring, chain analysis, verification, or report work.",
        "- Do NOT write rag_validation.md or any later-phase artifact.",
        "- Initial confidence scoring is part of the depth phase in Core/Thorough. If confidence_scores.md is missing or too small, spawn the Phase 4b Confidence Scoring Agent and write confidence_scores.md before returning.",
        "- If semantic_invariants.md triggered SEMANTIC_GAP_INVESTIGATOR, spawn that niche agent now and write niche_semantic_gap_findings.md. Do not collapse missing-write/lifecycle-gap signals into generic snapshot prose.",
        "- For every graph-artifact issue, update the named depth output so it references every produced graph artifact, or add an explicit [GRAPH-ARTIFACT: UNAVAILABLE:<file>] tag for unavailable artifacts.",
        "- For every SC subsystem coverage issue, read and cite the exact missing files named above, or add explicit [SCOPE-COVERED: <file>] tags after reviewing them.",
        "- If confidence_scores.md has all identical composite values, REDO scoring: read each finding's depth output and assign per-finding Evidence/Consensus/Quality scores based on actual depth evidence tags ([BOUNDARY], [VARIATION], [TRACE]) present.",
        "- If iter2 is flagged as missing: after fixing confidence_scores.md, check if any Medium+ findings are UNCERTAIN (composite < 0.7). If yes, spawn a DA iteration 2 agent for those findings and write depth_da_*_findings.md or depth_iter2_*_findings.md.",
        "",
        "Ensure ALL never-cut artifacts are produced and all depth "
        "agents include step execution traces. Prior output files "
        "are still on disk — re-read and fix quality issues in place. "
        "Only re-spawn agents whose output is missing or too small.",
    ])
    if backend == "codex":
        # Extract specific missing artifact filenames from never-cut issues
        missing_files = []
        for issue in issues:
            if "never-cut" in issue.lower():
                for part in issue.split(","):
                    part = part.strip()
                    if part.endswith(".md"):
                        # Extract just the filename
                        fname = part.split("/")[-1].split(" or ")[0].strip()
                        missing_files.append(fname)
        lines.extend([
            "",
            "## Codex spawn_agent repair plan",
            "",
            "For each missing artifact below, use spawn_agent to create it.",
            "Each spawn_agent call should include the file's full methodology",
            "from the V1 prompt section. Use wait_agent after each spawn.",
            "",
        ])
        if missing_files:
            for fname in missing_files:
                lines.append(f"- MISSING: `{fname}` → spawn_agent with targeted prompt")
        else:
            lines.append("- Check the MANDATORY DEPTH ARTIFACT CHECKLIST above for the full spawn plan.")
        lines.extend([
            "",
            "Do NOT return until every artifact in the checklist exists and",
            "is ≥200 bytes. The gate checks file existence mechanically.",
        ])
    return "\n".join(lines) + "\n"


# S1.6 — depth core-artifact set. These are the deliverables chain analysis
# consumes; if all are present and substantive, a missing tail artifact
# (perturbation, design_stress) must NOT halt the pipeline.
_DEPTH_CORE_ARTIFACTS = (
    "depth_token_flow_findings.md",
    "depth_state_trace_findings.md",
    "depth_edge_case_findings.md",
    "depth_external_findings.md",
    "blind_spot_a_findings.md",
    "blind_spot_b_findings.md",
    "blind_spot_c_findings.md",
)


def _depth_core_artifacts_present(
    scratchpad: Path,
    pipeline: str = "sc",
    mode: str = "core",
) -> bool:
    """S1.6: True when depth's CORE deliverables are all present + substantive.

    SC core = the 4 depth-role findings files + the 3 blind-spot scanners.
    L1 core = the five L1 depth role findings files.
    When this holds, depth has produced usable input for chain analysis and
    a remaining tail-artifact gap must degrade-and-continue, not halt.
    """
    if (pipeline or "sc") == "l1":
        core = tuple(group[0] for group in l1_never_cut_groups(mode)[:5])
    else:
        core = _DEPTH_CORE_ARTIFACTS
    for name in core:
        p = scratchpad / name
        if not p.exists() or _depth_artifact_is_stub(p) is not None:
            return False
    return True


def _generate_depth_repair_hint(
    missing: list, pipeline: str = "sc", mode: str = "core"
) -> str:
    """S1.5: targeted repair hint — produce ONLY the missing/stub artifacts.

    The core depth findings are already complete; this steers the one
    auto-granted repair attempt at the tail gaps without a full re-run and
    without overrunning the phase boundary.

    v2.8.16: pipeline-aware. The L1 depth phase has 5 role findings (no
    blind_spot scanners, no chain phase), so an SC-worded hint would
    misdescribe the L1 repair target. The SC branch is the verbatim original
    (reached on the default ``pipeline="sc"``), so SC output is byte-identical.
    """
    if (pipeline or "sc") == "l1":
        lines = [
            "## RETRY HINT — depth targeted repair (L1)",
            "",
            "The CORE depth findings are already complete and on disk: the five "
            "L1 depth role files — `depth_consensus_invariant_findings.md`, "
            "`depth_network_surface_findings.md`, `depth_state_trace_findings.md`, "
            "`depth_external_findings.md`, `depth_edge_case_findings.md` — are "
            "present and substantive. DO NOT regenerate them — reuse them as-is. "
            "L1 has NO `blind_spot_*` scanners and NO chain phase.",
            "",
            "Produce ONLY the missing / stub artifacts below, then STOP:",
        ]
        lines.extend(f"- {m}" for m in (missing or []))
        lines.extend([
            "",
            "- If `confidence_scores.md` is missing or a stub, write it for the "
            "L1 depth findings.",
            "- In Thorough mode only: write a substantive "
            "`perturbation_findings.md` and `design_stress_findings.md` if "
            "missing or stubs, and `skill_execution_gaps.md` if applicable.",
            "- Do NOT write `verification_queue.md`, any `verify_*.md`, or any "
            "report artifact — those belong to later phases. Writing them "
            "wastes the attempt.",
            "- Return `DONE: depth repair complete` when finished.",
        ])
        return "\n".join(lines) + "\n"
    lines = [
        "## RETRY HINT — depth targeted repair",
        "",
        "The CORE depth findings are already complete and on disk: the four "
        "`depth_*_findings.md` role files and the three "
        "`blind_spot_*_findings.md` scanners are present and substantive. "
        "DO NOT regenerate them — reuse them as-is.",
        "",
        "Produce ONLY the missing / stub artifacts below, then STOP:",
    ]
    lines.extend(f"- {m}" for m in (missing or []))
    lines.extend([
        "",
        "- Write a substantive `perturbation_findings.md` if it is missing "
        "or a stub (one `### Perturbation Block` table per Medium+ finding).",
        "- If `confidence_scores.md` shows Medium+ findings in the UNCERTAIN "
        "band, run depth iteration 2 (Devil's-Advocate) for those findings "
        "and write `depth_da_*_findings.md`.",
        "- Do NOT write `hypotheses.md`, `finding_mapping.md`, or any chain / "
        "synthesis / verification / report artifact — those belong to later "
        "phases. Writing them wastes the attempt.",
        "- Return `DONE: depth repair complete` when finished.",
    ])
    return "\n".join(lines) + "\n"


def _generate_report_index_retry_hint(issues: list[str]) -> str:
    """Build retry hint for report_index completeness failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT — report_index completeness gate (v2.5.0)",
        "",
        "Your previous attempt failed these report index checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Every hypothesis in hypotheses.md must map to a report ID in "
        "the Master Finding Index, be listed in the Excluded Findings "
        "table, or be consolidated into another report finding. "
        "Do NOT assume prior output files are correct — "
        "they have been quarantined.",
        "",
        "### Common failure: duplicate binding",
        "If an internal ID appears in multiple rows, the most common cause is:",
        "- A chain hypothesis row (CH-N) lists constituent IDs in "
        "parentheses. Use the "
        "chain ID when `verify_CH-3.md` exists, or `H-2+H-27` when only "
        "constituent verifier files exist.",
        "- A finding that was consolidated into another report finding still "
        "has its own standalone row. Remove the standalone row and record the "
        "consolidation in the Consolidation Map.",
        "Each Internal Hypothesis cell MUST contain one parseable ID token "
        "or a plus-joined consolidated list such as `H-2+H-27`.",
    ])
    if any("severity provenance" in issue.lower() for issue in issues):
        lines.extend([
            "",
            "### Common failure: silent severity change",
            "For every Master Finding Index row, compare the row's final "
            "Severity / Report ID tier against the severity in the mapped "
            "`verify_<ID>.md` file and `verification_queue.md` row.",
            "",
            "If the final report severity differs, you MUST do one of:",
            "- Restore the row to the upstream verifier/queue severity and "
            "move it to the matching report tier; OR",
            "- Keep the changed severity ONLY when a canonical adjustment "
            "applies, and write the reason in `Trust Adj.` / `Severity Trail`.",
            "",
            "Accepted canonical adjustment reasons:",
            "- `TRUSTED-ACTOR(original_sev)`",
            "- `UNRESOLVED(original_sev)` or `PARTIAL(original_sev)`",
            "- `POC-FAIL(original_sev)`",
            "- `PROVEN(original_sev)` only when PROVEN_ONLY=true",
            "- `CHAIN-UPGRADE(original_sev)` / `CHAIN-DOWNGRADE(original_sev)` "
            "with the chain ID and enabling relation.",
            "",
            "Do NOT silently place a Medium verified finding in a Low row, "
            "and do NOT silently upgrade an Informational finding to Low. "
            "A bare `-` / `—` Trust Adj. is valid only when final severity "
            "equals upstream severity.",
        ])
    return "\n".join(lines) + "\n"


def _generate_verify_shard_retry_hint(issues: list[str]) -> str:
    """Build retry hint for verify shard completion failures."""
    if not issues:
        return ""
    lines = [
        "## RETRY HINT ? verify shard completion gate (v2.3.14)",
        "",
        "Your previous attempt failed these verify shard checks:",
        "",
    ]
    for issue in issues:
        lines.append(f"- {issue}")
    lines.extend([
        "",
        "Each finding assigned to your shard must have a corresponding "
        "verify_{id}.md file with verdict and evidence tag. "
        "Do NOT assume prior output files are correct. On verify-shard "
        "retries, inspect and repair every assigned `verify_<ID>.md` in "
        "place; the prior failure list may not be exhaustive if an older "
        "driver truncated gate output.",
        "",
        "PoC ledger contract for every mandatory unit/property/property-like finding:",
        "- If you attempted a PoC, write `Attempted: YES` AND concrete "
        "`Test File:` and `Command:` fields. Do not use N/A/NONE for either.",
        "- If you did not attempt a PoC, write `Attempted: NO` AND "
        "`PoC Not Attempted Because: <VALID_BLOCKER>` using exactly one of:",
        "  `NO_BUILD_ENVIRONMENT`, `EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS`, "
        "`DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL`, `PURE_SPEC_OR_DOCS_ONLY`, "
        "`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`, `CROSS_VM_ENCODING_NO_RUNTIME`.",
        "- For `unit` or `property` rows, weak reasons like missing mocks, "
        "complex setup, time, or 'not necessary' are not valid blockers by "
        "themselves. Build a minimal harness/mock when feasible.",
        "- Before returning, make one final pass over ALL rows in this shard "
        "manifest, not only the IDs named above.",
    ])
    return "\n".join(lines) + "\n"


# --- MVP verify targeted PoC-contract repair (additive, haltless) -----------
#
# Class scope: the ONLY failure this MVP targets is the per-finding PoC-contract
# gate emitting "{fid} says Attempted:YES but lacks concrete Test File/Command"
# (plamen_validators._validate_poc_contract_for_rows). Those sub-issues are
# wrapped by _validate_verify_completion into a single combined entry of the
# shape "verify PoC contract: <sub>; <sub>; ...". The targeted repair fires at
# most ONCE per phase, scoped to ONLY the named IDs via a sharpened hint, and
# only when the WHOLE gate failure is this class. Any other issue type (schema,
# missing files, mandatory-not-attempted, location recovery, EXTERNAL_DEPENDENCY
# mock-override, base gate issues, ...) means we do NOT fire and the existing
# verify-shard degrade-and-continue runs unchanged.
_VERIFY_POC_CONTRACT_PREFIX = "verify PoC contract: "
_VERIFY_ATTEMPTED_YES_NO_TESTFILE = "says Attempted:YES but lacks concrete Test File/Command"
# Codex-direction sub-class (parity with the Claude-direction Attempted:YES
# shape above). _validate_poc_contract_for_rows emits this when a row that is
# locally PoC-required declared `Attempted: NO` without a valid blocker (or
# omitted the ledger value entirely): "{fid} mandatory {poc_class} PoC not
# attempted with valid blocker". The cheap one-shot targeted repair hint asks
# the verifier to EITHER attempt the PoC (supply Test File/Command) OR
# non-silently re-justify with a valid blocker — exactly the remediation this
# sub-class needs — so it is repairable by the same scoped hint. This match is
# backend-gated to codex only (see verify_poc_contract_only_failed_ids).
_VERIFY_MANDATORY_NOT_ATTEMPTED = "PoC not attempted with valid blocker"
_VERIFY_TARGETED_REPAIR_FLAG_SUFFIX = "_verify_targeted_repair_done"


def verify_poc_contract_only_failed_ids(
    missing: list[str], scratchpad: Path | None = None
) -> list[str]:
    """Return failed finding IDs IFF the gate failure is PoC-contract-only.

    PoC-contract-only means: every entry in ``missing`` is a combined
    ``"verify PoC contract: ..."`` entry AND every sub-issue inside it belongs
    to a targeted-repairable class. Two repairable classes, BACKEND-AGNOSTIC:
    ``"says Attempted:YES but lacks concrete Test File/Command"`` and
    ``"mandatory {class} PoC not attempted with valid blocker"``. Both are
    repaired by the same scoped one-shot hint (attempt the PoC or non-silently
    re-justify). If the failure mixes in any other issue type, return ``[]`` so
    the caller skips the targeted attempt and degrades as now.

    The mandatory-not-attempted class was originally Codex-only. It is now
    eligible on ALL backends: a prior Claude run degraded shards because the
    verifier non-silently reclassified findings (exactly as the prompt asks)
    and got only generic whole-shard retries — no precise per-finding hint — so
    it could never converge. The repair EXECUTION path (``_write_retry_hint`` +
    ``run_phase`` + re-validate) is backend-agnostic, so there is no reason to
    withhold the convergence hint on Claude.

    NOTE: this only changes WHICH ids are eligible for the cheap one-shot repair
    path; the underlying ``_validate_poc_contract_for_rows`` gate is UNTOUCHED
    and stays exactly as hard (anti-fabrication preserved). A repaired file is
    re-validated by the same gate on the next attempt.

    The returned IDs are de-duplicated, order-preserved. An empty list is the
    "do not fire" signal for ALL non-matching inputs (empty/mixed/other-class).
    """
    if not missing:
        return []
    fids: list[str] = []
    seen: set[str] = set()
    for entry in missing:
        if not isinstance(entry, str):
            return []
        if not entry.startswith(_VERIFY_POC_CONTRACT_PREFIX):
            # Any non-PoC-contract issue (schema, missing files, location
            # recovery, base gate, ...) -> not PoC-contract-only -> bail.
            return []
        body = entry[len(_VERIFY_POC_CONTRACT_PREFIX):]
        # _validate_verify_completion joins sub-issues with "; ".
        for sub in body.split(";"):
            sub = sub.strip()
            if not sub:
                continue
            if _VERIFY_ATTEMPTED_YES_NO_TESTFILE in sub:
                m = re.match(r"^([A-Za-z0-9_.\[\]\-]+)\s+says\s+Attempted:YES", sub)
            elif _VERIFY_MANDATORY_NOT_ATTEMPTED in sub:
                # "{fid} mandatory {poc_class} PoC not attempted with valid
                # blocker" (all backends). Isolate the leading id.
                m = re.match(r"^([A-Za-z0-9_.\[\]\-]+)\s+mandatory\b", sub)
            else:
                # A different PoC-contract sub-class (missing ledger,
                # EXTERNAL_DEPENDENCY mock-override, ...) -> the targeted hint
                # would not fully repair the gate -> bail.
                return []
            if not m:
                # Could not isolate the id from a matching-class sub-issue ->
                # ambiguous -> bail (degrade as now).
                return []
            fid = m.group(1).strip().strip("[]")
            if fid and fid not in seen:
                seen.add(fid)
                fids.append(fid)
    return fids


def _generate_verify_targeted_repair_hint(fids: list[str]) -> str:
    """Sharpened, scoped retry hint naming ONLY the failed IDs.

    Tells the verifier to repair ONLY these verify_<ID>.md files and to leave
    every other verify_*.md file untouched (the good findings' files are already
    on disk and are preserved by the partial-results accumulation logic).
    """
    if not fids:
        return ""
    lines = [
        "## RETRY HINT — targeted PoC-contract repair (MVP, one-shot)",
        "",
        "The verify-shard PoC contract gate failed for ONLY these findings; "
        "each declared `Attempted: YES` but did NOT supply a concrete "
        "`Test File:` AND `Command:`. This is your final targeted attempt for "
        "this shard — repair ONLY the IDs listed below:",
        "",
    ]
    for fid in fids:
        lines.append(
            f"- `verify_{fid}.md`: either (a) keep `Attempted: YES` and add a "
            f"concrete `Test File:` AND `Command:` (no N/A / NONE), OR "
            f"(b) change to `Attempted: NO` and add "
            f"`PoC Not Attempted Because: <VALID_BLOCKER>` using exactly one of "
            f"`NO_BUILD_ENVIRONMENT`, `EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS`, "
            f"`DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL`, `PURE_SPEC_OR_DOCS_ONLY`, "
            f"`STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION`, "
            f"`CROSS_VM_ENCODING_NO_RUNTIME`."
        )
    lines.extend([
        "",
        "Repair ONLY the verify_*.md files named above. Do NOT touch, rewrite, "
        "delete, or re-verify any other verify_*.md file in this shard — all "
        "other findings are already complete and must be preserved verbatim.",
    ])
    return "\n".join(lines) + "\n"


def verify_targeted_repair_already_done(scratchpad: Path, phase_name: str) -> bool:
    """Fire-once guard: True if the targeted repair already ran for this phase.

    Disk-marker based so it survives resume (the marker is written to the
    scratchpad before the targeted attempt is spawned).
    """
    flag = scratchpad / f"{phase_name}{_VERIFY_TARGETED_REPAIR_FLAG_SUFFIX}.flag"
    return flag.exists()


def mark_verify_targeted_repair_done(scratchpad: Path, phase_name: str) -> None:
    """Set the fire-once marker for this phase (before spawning the attempt)."""
    flag = scratchpad / f"{phase_name}{_VERIFY_TARGETED_REPAIR_FLAG_SUFFIX}.flag"
    try:
        flag.write_text(
            f"targeted PoC-contract repair attempted for {phase_name} at "
            f"{time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
            encoding="utf-8",
        )
    except Exception:
        pass


# --- end v2.3.14 retry hint generators --------------------------------------
def _validate_depth_exit(scratchpad: Path) -> list[str]:
    """Validate structured depth-exit metadata emitted by the depth loop.

    Accepts YAML-style, bullet list, OR markdown-table emission. See
    `_match_label_status` for the reasoning behind format tolerance.
    """
    p = scratchpad / "depth_exit.md"
    if not p.exists():
        return ["depth_exit.md missing"]
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["depth_exit.md unreadable"]

    issues = []

    # criterion: YAML/bullet form `criterion: 1` OR table row `| criterion | 1 |`
    crit_m = re.search(r"(?im)^\s*[-*]?\s*criterion\s*:\s*([1-4])\b", text)
    if not crit_m:
        crit_m = re.search(
            r"(?im)^\s*\|\s*criterion\s*\|\s*([1-4])\b", text
        )
    criterion = int(crit_m.group(1)) if crit_m else None
    if criterion is None:
        issues.append("criterion missing/invalid")

    # rationale: YAML/bullet form OR table row
    rationale_m = re.search(r"(?im)^\s*[-*]?\s*rationale\s*:\s*(.+?)\s*$", text)
    if not rationale_m:
        rationale_m = re.search(
            r"(?im)^\s*\|\s*rationale\s*\|\s*([^|\n]+?)\s*\|", text
        )
    if not rationale_m or not rationale_m.group(1).strip():
        issues.append("rationale missing")

    # explored_paths: list bullets `- path one` OR table rows under the
    # explored_paths header `| explored | path one |`. Strip the YAML header
    # line itself so `- explored_paths:` isn't counted as a path.
    _DEPTH_EXIT_META_PREFIXES = (
        "explored_paths", "criterion", "rationale", "phase",
        "iteration", "confidence", "findings", "reason",
    )
    explored = [
        m.group(1).strip()
        for m in re.finditer(r"(?im)^\s*-\s+(.+?)\s*$", text)
        if not any(
            m.group(1).strip().lower().startswith(p)
            for p in _DEPTH_EXIT_META_PREFIXES
        )
    ]
    if not explored:
        # Legacy table form: `| explored | path one |` (column 1 literal).
        explored = re.findall(
            r"(?im)^\s*\|\s*(?:explored(?:_path)?s?)?\s*\|\s*([^|\n]+?)\s*\|",
            text,
        )
        explored = [e.strip() for e in explored if e.strip()]
    if not explored:
        # Section-scoped table form: under `## explored_paths`, scan any
        # 2-column rows until the next `##` header. This accepts arbitrary
        # column-1 content (path names), not just the literal "explored*".
        sec_m = re.search(
            r"(?im)^\s*##\s*explored(?:_paths?)?\s*$", text
        )
        if sec_m:
            after = text[sec_m.end():]
            next_hdr = re.search(r"(?im)^\s*##\s", after)
            section = after[: next_hdr.start()] if next_hdr else after
            for row in re.finditer(
                r"(?m)^\s*\|\s*([^|\n]+?)\s*\|\s*[^|\n]+?\s*\|",
                section,
            ):
                col1 = row.group(1).strip()
                if not col1:
                    continue
                if col1.lower() in ("path", "paths", "field", "name"):
                    continue
                if set(col1) <= set("-: "):
                    continue
                explored.append(col1)
    if not explored:
        issues.append("explored_paths missing")
    elif criterion == 4 and len(explored) < 3:
        issues.append("criterion 4 requires >=3 explored_paths")

    return issues


# Non-production path classifier for finding LOCATIONS. CONSERVATIVE by design:
# this routes a finding OUT of the report body, so it must only fire on
# UNAMBIGUOUS test/fuzz/harness signals — a non-production DIRECTORY component or
# an unambiguous test-file SUFFIX. It deliberately does NOT match bare name
# components (mock/stub/fake/test inside a filename): a PRODUCTION contract can
# legitimately be named `Stub.sol`, `MockableVault.sol`, etc., and matching those
# would wrongly DROP real findings. Recall-safe: a genuine test helper sitting in
# a production dir with a test-y name is KEPT (a false-negative on filtering),
# never a dropped real finding.
_NONPROD_PATH_PARTS = {
    "test", "tests", "fuzz", "fuzzing", "script", "scripts", "fixture",
    "fixtures", "mock", "mocks", "spec", "specs", "benchmark", "benchmarks",
    "medusa", "echidna", "halmos", ".medusa-tests", "_fuzzproj",
}
_NONPROD_FILE_SUFFIXES = (
    ".t.sol", ".s.sol", "_test.go", "_test.rs", ".test.ts", ".spec.ts",
    ".test.js", ".spec.js", "_test.py",
)


def _is_nonproduction_location(rel_path: str) -> bool:
    """True only on an UNAMBIGUOUS test/fuzz/harness signal: a non-production
    directory component, or a test-file suffix. `rel_path` is project-root-
    relative, optionally with a `:Lnnn` suffix (stripped here)."""
    rel = (rel_path or "").strip().split(":")[0].strip().replace("\\", "/")
    if not rel:
        return False
    parts = [p.lower() for p in rel.split("/")]
    if any(p in _NONPROD_PATH_PARTS for p in parts[:-1]):  # directory parts only
        return True
    return parts[-1].endswith(_NONPROD_FILE_SUFFIXES)


# A finding whose LOCATION is PROSE naming a test/fuzz/invariant HARNESS (no real
# source file) is about non-audited test code, not the production protocol. Tight
# + generic: requires "harness" next to a test/fuzz/invariant qualifier (or a
# bare "test harness") and NO real-looking file token — so a production finding
# that merely mentions "test" is not swept up.
_HARNESS_PROSE_RE = re.compile(
    r"(?i)(?:\b(?:fuzz|invariant|medusa|echidna|halmos)\b[^.\n]{0,24}\bharness\b"
    r"|\bharness\b[^.\n]{0,24}\b(?:fuzz|invariant|test)\b"
    r"|\b(?:fuzz|invariant)\s+(?:test\s+)?harness\b"
    r"|\btest\s+harness\b)"
)


def _is_harness_location_prose(location: str) -> bool:
    loc = (location or "").strip()
    if not loc:
        return False
    if re.search(r"\.(?:sol|rs|go|move|vy|cairo)\b", loc, re.IGNORECASE):
        return False  # a real-ish file token -> leave it to the path-based logic
    return bool(_HARNESS_PROSE_RE.search(loc))


# Gate 3 — identifier-existence hallucination catch. A finding may cite a
# CONCRETE code identifier (a function/method name) that simply does not exist
# anywhere in the codebase — a stronger anti-hallucination signal than the
# path-based location gates above, which only check the *file*, not the
# *symbol* inside it. Deliberately narrow extraction: only patterns that are
# "clearly a function" trigger (backtick-quoted `foo()` / `Contract.method`,
# a `function fooBar` prose token, or a bare `fooBar()` call token). Plain
# prose ("the setter", "withdraw path") and bare variable names in backticks
# (no dot, no parens) never match, by design -> treated as NO concrete
# identifier, per the recall-safe skip requirement.
_IDENTIFIER_PATTERNS = (
    re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)\(\)`"),
    re.compile(r"`([A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*)\(?\)?`"),
    re.compile(r"(?i)\bfunction\s+([A-Za-z_][A-Za-z0-9_]{2,})\b"),
    re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\(\)"),
)


def _extract_concrete_identifier(title: str, location: str = "") -> str | None:
    """Extract a single, unambiguous concrete function/method identifier cited
    in a finding's title/location. Returns the bare symbol name (dotted
    `Contract.method` forms are reduced to `method`), or None when zero or
    2+ distinct identifiers are cited (ambiguous -> skip, recall-safe)."""
    text = f"{title or ''} {location or ''}"
    candidates: list[str] = []
    for pat in _IDENTIFIER_PATTERNS:
        for m in pat.finditer(text):
            ident = m.group(1)
            candidates.append(ident.rsplit(".", 1)[-1])
    if not candidates:
        return None
    uniq = sorted(set(candidates))
    if len(uniq) != 1:
        return None
    return uniq[0]


def _identifier_exists_in_project(identifier: str, source_index: dict[str, list]) -> bool:
    """Whole-scope check: does `identifier` occur (word-boundary) in ANY file
    of the project source index? Deliberately ignores which file the finding
    resolved to -> inheritance/imports/wrong-file resolution never trip this."""
    if not identifier:
        return False
    pattern = re.compile(r"\b" + re.escape(identifier) + r"\b")
    seen: set = set()
    for paths in source_index.values():
        for p in paths:
            if p in seen:
                continue
            seen.add(p)
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if pattern.search(content):
                return True
    return False


def _validate_inventory_evidence(
    scratchpad: Path,
    project_root: str,
    apply_safe_recovery: bool = True,
) -> dict[str, dict[str, str]]:
    """Validate inventory locations/provenance and write a triage ledger.

    This is a cheap pre-verification guard. It does not refute findings; it
    identifies evidence defects and safely rewrites only unique-basename
    location recoveries.
    """
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return {}
    try:
        text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    source_index = _project_source_index(project_root)
    records: dict[str, dict[str, str]] = {}
    recovered: dict[str, str] = {}

    for item in _inventory_blocks(text):
        fid = item["id"]
        loc_status, resolved, loc_reason = _resolve_inventory_location(
            project_root, source_index, item.get("location", "")
        )
        # Gate 2 — non-production scope filter: a finding resolved to a real file
        # that lives in a test/fuzz/mock/harness tree is about non-audited code,
        # not the production protocol -> route out of the body (appendix).
        if loc_status in ("OK", "RECOVERED_BASENAME") and _is_nonproduction_location(resolved):
            loc_status = "LOCATION_NONPRODUCTION"
            loc_reason = "resolved to a non-production (test/fuzz/mock/harness) path"
        elif loc_status not in ("OK", "RECOVERED_BASENAME") and _is_harness_location_prose(item.get("location", "")):
            # Location is prose naming a test/fuzz/invariant harness (no real file)
            # -> the finding is about non-audited test code, not production.
            loc_status = "LOCATION_NONPRODUCTION"
            loc_reason = "finding is about the test/fuzz/invariant harness, not production code"
        # Gate 3 — identifier-existence hallucination catch: a finding citing a
        # CONCRETE function/method identifier that is absent from the ENTIRE
        # project source index (not merely the resolved file — inheritance,
        # imports, and wrong-file resolution never trip this) is very likely a
        # hallucinated reference. RECALL-SAFE: only Low/Informational findings
        # are appendix-routed; Medium/High/Critical are flagged for human
        # review only and stay exactly where they were (never appendix-routed,
        # never dropped). Never raises: any parse error leaves loc_status as-is.
        try:
            ident = _extract_concrete_identifier(item.get("title", ""), item.get("location", ""))
            if ident and not _identifier_exists_in_project(ident, source_index):
                severity = normalize_severity(
                    _field_from_markdown(item.get("block", ""), ("Severity", "Final Severity"))
                )
                if severity in ("Low", "Informational"):
                    if loc_status in ("OK", "RECOVERED_BASENAME"):
                        loc_status = "IDENTIFIER_UNVERIFIED"
                        loc_reason = (
                            f"cited identifier `{ident}` not found anywhere in the "
                            "project source index (likely hallucinated)"
                        )
                else:
                    # Medium/High/Critical: flag only, never appendix-route.
                    flag = (
                        f"[IDENTIFIER-UNVERIFIED — human review: `{ident}` not "
                        "found anywhere in the project source index]"
                    )
                    loc_reason = f"{loc_reason} {flag}".strip() if loc_reason else flag
        except Exception:
            pass
        source_tokens = _split_source_id_tokens(item.get("source_ids", ""))
        source_statuses = []
        source_reasons = []
        for tok in source_tokens:
            st, reason = _validate_source_token(tok, scratchpad)
            source_statuses.append(st)
            if st != "OK":
                source_reasons.append(f"{tok}: {reason}")
        if not source_tokens:
            source_statuses.append("SOURCE_MISSING")
            source_reasons.append("no Source IDs field")
        if all(s == "OK" for s in source_statuses):
            source_status = "OK"
        elif any(s in ("OK", "SOURCE_UNVERIFIED") for s in source_statuses):
            source_status = "SOURCE_UNVERIFIED"
        else:
            source_status = "SOURCE_INVALID"
        if loc_status == "RECOVERED_BASENAME" and resolved:
            recovered[fid] = resolved
        records[fid] = {
            "id": fid,
            "title": item.get("title", ""),
            "location_status": loc_status,
            "resolved_location": resolved,
            "location_reason": loc_reason,
            "source_status": source_status,
            "source_reason": "; ".join(source_reasons[:4]) or "all source tokens resolved",
        }

    if apply_safe_recovery and recovered:
        new_text = text
        for fid, loc in recovered.items():
            new_text = _replace_inventory_location(new_text, fid, loc)
        if new_text != text:
            inv.write_text(new_text, encoding="utf-8")

    lines = [
        "# Inventory Evidence Validation",
        "",
        "| Finding ID | Location Status | Resolved Location | Location Reason | Source Status | Source Reason |",
        "|------------|-----------------|-------------------|-----------------|---------------|---------------|",
    ]
    for fid in sorted(records, key=lambda x: [int(n) if n.isdigit() else n for n in re.split(r"(\d+)", x)]):
        r = records[fid]
        lines.append(
            f"| {fid} | {r['location_status']} | {r['resolved_location']} | "
            f"{r['location_reason'].replace('|', '/')} | {r['source_status']} | "
            f"{r['source_reason'].replace('|', '/')} |"
        )
    invalid = [
        fid for fid, r in records.items()
        if r["location_status"] not in ("OK", "RECOVERED_BASENAME")
        or r["source_status"] != "OK"
    ]
    lines.extend([
        "",
        f"Summary: {len(records)} checked, {len(recovered)} basename-recovered, {len(invalid)} with unresolved evidence.",
        "",
    ])
    (scratchpad / "inventory_evidence_validation.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )
    return records


def _parse_inventory_evidence_validation(scratchpad: Path) -> dict[str, dict[str, str]]:
    p = scratchpad / "inventory_evidence_validation.md"
    if not p.exists():
        return {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {}
    headers, rows = _parse_markdown_table(text, ["finding id", "location status", "source status"])
    if not headers:
        return {}
    keys = [_norm_key(h) for h in headers]
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
        fid = _normalize_finding_id(d.get("finding id", "")) or d.get("finding id", "")
        if fid:
            out[fid] = d
    return out


def _filter_verification_queue_by_evidence(scratchpad: Path) -> list[str]:
    """Remove out-of-scope / hallucinated-location rows before expensive verify.

    Two drop policies:
      - HARD (location ground truth, drop on its own): the cited file genuinely
        does not exist, the cited line exceeds the file length, the location
        resolved to a non-production (test/fuzz/mock/harness) path, or (Low/
        Informational only — Gate 3) the finding cites a concrete function/
        method identifier absent from the ENTIRE project source index. These
        are mechanical facts, not judgment — a finding citing absent/non-
        production/hallucinated code is not an in-scope production
        vulnerability. Medium+ findings are NEVER hard-dropped by Gate 3 (see
        `_validate_inventory_evidence` — they are flagged, not appendix-routed).
      - CONSERVATIVE (both-bad): only suppress when BOTH location and provenance
        are unresolved/invalid. A merely unparseable/prose location with a usable
        Source ID still proceeds to verifier/location recovery.
    All removals are written to verification_queue_evidence_excluded.md (ledger,
    not a silent drop — this is an appendix routing, not a body deletion).
    """
    records = _parse_inventory_evidence_validation(scratchpad)
    if not records:
        return []
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []
    kept: list[dict[str, str]] = []
    removed: list[dict[str, str]] = []
    for row in rows:
        fid = _normalize_finding_id(row.get("finding id") or "") or (row.get("finding id") or "").strip()
        rec = records.get(fid)
        if not rec:
            kept.append(row)
            continue
        loc_status_val = rec.get("location status")
        loc_reason_val = (rec.get("location reason") or "").lower()
        loc_bad = loc_status_val not in ("OK", "RECOVERED_BASENAME")
        src_bad = rec.get("source status") in ("SOURCE_INVALID", "SOURCE_MISSING")
        # HARD ground-truth drop (on its own): the inventory location resolved to
        # a real file that lives in a test/fuzz/mock/harness tree — out of audit
        # scope regardless of provenance.
        #
        # NOTE: we deliberately do NOT hard-drop a file-not-found location even on
        # its own. At the INVENTORY stage a not-found path with a GOOD Source ID is
        # a real finding whose location field is wrong-but-recoverable from its
        # provenance (the lenient policy the COMP/F-INV tests pin). The genuinely
        # hallucinated-location case observed in practice is a DOWNSTREAM (report
        # tier-writer) corruption that overwrites the validated report_index
        # location — that is caught at report-assembly, not here.
        loc_hard_invalid = loc_status_val in ("LOCATION_NONPRODUCTION", "IDENTIFIER_UNVERIFIED")
        if loc_hard_invalid or (loc_bad and src_bad):
            row = dict(row)
            if loc_status_val == "IDENTIFIER_UNVERIFIED":
                row["exclusion reason"] = (
                    "Unverified identifier (appendix, not dropped): "
                    f"{rec.get('location reason') or 'cited identifier not found anywhere in the project source index'}"
                )
            elif loc_hard_invalid:
                row["exclusion reason"] = (
                    f"Out-of-scope location ({loc_status_val}): "
                    f"{rec.get('location reason') or 'cited code is not an in-scope production file'}"
                )
            else:
                row["exclusion reason"] = (
                    f"Evidence invalid: location_status={loc_status_val}; "
                    f"source_status={rec.get('source status')}"
                )
            removed.append(row)
        else:
            kept.append(row)
    if not removed:
        return []
    existing_removed: list[dict[str, str]] = []
    excluded_path = scratchpad / "verification_queue_evidence_excluded.md"
    if excluded_path.exists():
        try:
            text = excluded_path.read_text(encoding="utf-8", errors="replace")
            headers, existing_rows = _parse_markdown_table(text, ["severity"])
            keys = [_norm_key(h) for h in headers]
            for raw_row in existing_rows:
                d = {
                    keys[i]: raw_row[i].strip()
                    for i in range(min(len(keys), len(raw_row)))
                }
                fid_existing = (
                    _normalize_finding_id(d.get("finding id", ""))
                    or d.get("finding id", "")
                )
                if fid_existing:
                    existing_removed.append({
                        "finding id": fid_existing,
                        "severity": d.get("severity", ""),
                        "title": d.get("title", ""),
                        "exclusion reason": (
                            d.get("exclusion reason", "")
                            or "Previously excluded from active verification"
                        ),
                    })
        except Exception:
            existing_removed = []
    merged_removed: dict[str, dict[str, str]] = {}
    for row in existing_removed + removed:
        fid = _normalize_finding_id(row.get("finding id", "")) or row.get("finding id", "")
        if fid:
            row = dict(row)
            row["finding id"] = fid
            merged_removed[fid] = row
    for idx, row in enumerate(kept, start=1):
        row["queue #"] = str(idx)
    _write_queue_subset_manifest(scratchpad / "verification_queue.md", kept)
    _write_queue_excluded_manifest(excluded_path, list(merged_removed.values()))
    return [(r.get("finding id") or "").strip() for r in removed if r.get("finding id")]


def _validate_inventory_parity(scratchpad: Path) -> list[str]:
    """Detect findings_inventory.md that is truncated relative to source.

    Hook: defends against the SIGKILL-at-timeout failure mode where the
    inventory agent is killed mid-write. The partial file can still satisfy
    the byte-size gate (it was growing when cut), but has been observed to
    contain only 5-20% of the findings that the breadth/scanner/niche agents
    actually produced. Downstream depth/chain/verify then cascade on the
    truncated set and the final report silently drops most findings.

    Signal: set-difference on finding signals parsed from source agent
    outputs vs. the inventory. Primary signal is bracketed finding IDs;
    fallback is heading-derived IDs and Location-line tags so that breadth
    agents that skip the `[XX-N]` prefix still produce evidence. If both
    the inventory file exists AND every upstream source artifact is empty
    of signals, the gate FAILS loudly rather than passing vacuously —
    that state is itself evidence that upstream phases did not produce
    the expected artifacts.
    """
    inv_path = _inventory_parity_artifact(scratchpad)
    if not inv_path.exists():
        return ["findings_inventory.md missing"]
    try:
        inv_text = inv_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["findings_inventory.md unreadable"]

    # In sharded inventory mode, final `findings_inventory.md` is a merge of
    # `findings_inventory_chunk_*.md`, not a fresh merge over raw breadth and
    # graph artifacts. The parity source must match the phase contract,
    # otherwise legitimate deduplication looks like truncation.
    chunk_sources = sorted(scratchpad.glob("findings_inventory_chunk_*.md"))
    if chunk_sources:
        source_files = chunk_sources
        source_label = "inventory chunks"
    else:
        source_files = []
        for pat in _INVENTORY_SOURCE_PATTERNS:
            source_files.extend(sorted(scratchpad.glob(pat)))
        source_label = "upstream artifacts"
    source_ids: set[str] = set()
    source_blocks = 0
    parsed_chunk_entries = 0
    observed_chunk_blocks = 0
    source_files_seen = 0
    for p in source_files:
        if p.name in {"findings_inventory.md", "hypotheses.md",
                      "chain_hypotheses.md"}:
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        source_files_seen += 1
        if chunk_sources:
            # In chunk mode, the parser used by the mechanical merge is the
            # authoritative contract. The loose signal regex is diagnostic only:
            # using it for hard parity recreates the parser/gate mismatch that
            # caused permanent inventory retry loops.
            entries = _parse_inventory_chunk(p)
            parsed_chunk_entries += len(entries)
            _, loose_blocks = _extract_finding_signals(txt)
            observed_chunk_blocks += loose_blocks
            for entry in entries:
                local_id = _normalize_finding_id(str(entry.get("local_id", "")))
                if local_id:
                    source_ids.add(local_id)
                for sid in entry.get("source_ids", []) or []:
                    norm = _normalize_finding_id(str(sid))
                    if norm:
                        source_ids.add(norm)
            source_blocks = parsed_chunk_entries
        else:
            ids, blocks = _extract_finding_signals(txt)
            source_ids |= ids
            source_blocks += blocks

    if chunk_sources and not source_ids and source_blocks == 0 and observed_chunk_blocks == 0:
        # Some tests/light paths create chunk placeholders with no findings.
        # Empty chunk files are not authoritative; fall back to raw artifacts.
        source_files = []
        for pat in _INVENTORY_SOURCE_PATTERNS:
            source_files.extend(sorted(scratchpad.glob(pat)))
        source_label = "upstream artifacts"
        source_ids = set()
        source_blocks = 0
        source_files_seen = 0
        for p in source_files:
            if p.name in {"findings_inventory.md", "hypotheses.md",
                          "chain_hypotheses.md"}:
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            source_files_seen += 1
            ids, blocks = _extract_finding_signals(txt)
            source_ids |= ids
            source_blocks += blocks

    inv_ids, loose_inv_blocks = _extract_finding_signals(inv_text)
    # For the inventory artifact itself, the block count contract is the
    # canonical finding-section parser. `_extract_finding_signals()` also
    # counts table ID rows as loose blocks, which is useful for upstream
    # breadth/chunk diagnostics but wrong for the final inventory: source-ID
    # traceability tables can contain many IDs without being additional
    # inventory findings. Comparing the merge receipt against that loose count
    # caused permanent retry loops such as `receipt merged=79` vs
    # `inventory blocks=111`.
    canonical_inv_blocks = len(_inventory_blocks(inv_text))
    inv_blocks = canonical_inv_blocks or loose_inv_blocks

    issues: list[str] = []

    # Gate path A: zero source signal + inventory body indicates a problem.
    # A non-trivial inventory cannot be satisfied by zero upstream findings.
    inv_body_len = len(inv_text.strip())
    if not source_ids and source_blocks == 0:
        if source_files_seen == 0 and inv_body_len < 512:
            # No upstream artifacts AND inventory is essentially empty
            # (e.g., Light mode with zero findings). Treat as vacuous OK.
            return []
        issues.append(
            "inventory parity: zero finding signals in upstream artifacts "
            f"({source_files_seen} {source_label} scanned) but inventory has "
            f"{len(inv_ids)} IDs / {inv_blocks} heading blocks — upstream "
            "breadth/scanner outputs may be missing or empty; cannot "
            "validate parity"
        )
        return issues

    # Gate path B: set-difference on IDs.
    coverage = 1.0
    if source_ids:
        covered = source_ids & inv_ids
        missing = source_ids - inv_ids
        coverage = len(covered) / len(source_ids)
        if coverage < 0.45:
            sample = sorted(missing)[:8]
            issues.append(
                f"inventory parity: coverage {coverage:.0%} "
                f"({len(covered)}/{len(source_ids)} source IDs from {source_label}); "
                f"truncation suspected; missing sample: {sample}"
            )

    receipt = _read_inventory_merge_receipt(scratchpad)
    promoted_inventory_blocks = _count_depth_promotion_inventory_blocks(inv_text)
    promoted_receipt_count = _read_depth_promotion_receipt_count(scratchpad)
    niche_inventory_blocks = _count_niche_promotion_inventory_blocks(inv_text)
    accounted_promotions = (
        max(promoted_inventory_blocks, promoted_receipt_count) + niche_inventory_blocks
    )
    expected_inventory_blocks = (
        receipt.get("merged", 0) + accounted_promotions
        if receipt else 0
    )
    receipt_accounts_for_merge = bool(
        chunk_sources
        and receipt.get("parsed") == parsed_chunk_entries
        and receipt.get("merged", -1) > 0
        and (
            receipt.get("merged") == inv_blocks
            or (
                accounted_promotions > 0
                and expected_inventory_blocks == inv_blocks
            )
        )
    )
    if chunk_sources and receipt and not receipt_accounts_for_merge:
        issues.append(
            "inventory parity: mechanical merge receipt mismatch "
            f"(receipt parsed={receipt.get('parsed')}, merged={receipt.get('merged')}; "
            f"parsed chunk entries={parsed_chunk_entries}, "
            f"observed loose source blocks={observed_chunk_blocks or source_blocks}, "
            f"promoted inventory blocks={promoted_inventory_blocks}, "
            f"promotion receipt count={promoted_receipt_count}, "
            f"niche inventory blocks={niche_inventory_blocks}, "
            f"inventory blocks={inv_blocks})"
        )

    # Gate path C: block count sanity. If source had N heading blocks but
    # inventory collapses them into far fewer blocks, flag even when ID text
    # still appears somewhere in the inventory. A list of absorbed IDs is not
    # a substitute for retained finding bodies.
    block_retention = inv_blocks / max(source_blocks, 1)
    chunk_exact_merge_accounted = bool(
        chunk_sources and (
            (source_ids and coverage >= 0.95 and inv_blocks > 0)
            or receipt_accounts_for_merge
        )
    )
    if (
        source_blocks >= 5
        and block_retention < 0.45
        and not chunk_exact_merge_accounted
    ):
        issues.append(
            f"inventory parity: inventory contains {inv_blocks} finding "
            f"blocks vs {source_blocks} in {source_label} "
            f"({block_retention:.0%} retention); "
            "truncation suspected"
        )

    return issues


def _validate_inventory_chunk_structure(scratchpad: Path, phase_name: str) -> list[str]:
    """Validate an inventory shard artifact as a chunk, not just a file.

    Inventory chunks are direct synthesis phases. A table-only artifact is not
    enough: the mechanical inventory merge and later report provenance need
    per-finding detail blocks that preserve source IDs, locations, verdicts,
    descriptions, and impacts. This catches the old prompt contradiction where
    the subprocess wrote a Master Table, then spun until timeout without
    writing detail blocks.
    """
    out = scratchpad / f"findings_{phase_name}.md"
    if not out.exists():
        return [f"{out.name} missing"]
    try:
        text = out.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [f"{out.name} unreadable: {exc}"]

    issues: list[str] = []

    def has_field(block: str, group: tuple[str, ...]) -> bool:
        # Route through the shared tolerant extractor (_llm_norm + table /
        # heading / `**Label:**` / bold tolerance) instead of a raw two-shape
        # regex, so a field present in a non-canonical shape is NOT miscounted
        # as missing. The whole alias group is passed at once.
        val, _shape = _field_anywhere(block, group, table_ok=True)
        return bool(val.strip())

    detail_matches = list(re.finditer(
        r"(?m)^###\s+(?:Finding\s+)?\[(CC-\d+)\]\s*:?\s*(.+?)\s*$",
        text,
    ))
    parsed_entries = _parse_inventory_chunk(out)
    if parsed_entries and not detail_matches:
        issues.append(
            f"inventory chunk has {len(parsed_entries)} parsed table row(s) "
            "but 0 per-finding detail block(s)"
        )
    if detail_matches and len(parsed_entries) < len(detail_matches):
        issues.append(
            f"inventory chunk parser retained {len(parsed_entries)} finding(s) "
            f"but artifact has {len(detail_matches)} detail heading(s)"
        )

    _has_detail_section = bool(re.search(
        r"(?im)^##\s+(?:Per[- ]Finding\s+)?Detail",
        text,
    ))
    if not _has_detail_section and detail_matches:
        issues.append("inventory chunk detail headings exist without `## Per-Finding Detail` section")
    elif parsed_entries and not _has_detail_section:
        issues.append("inventory chunk missing `## Per-Finding Detail` section")

    required_field_groups: list[tuple[str, ...]] = [
        ("Source IDs", "Source ID", "Sources", "Agent Sources"),
        ("Severity", "Risk Level", "Level"),
        ("Location", "Code Location", "File", "Where"),
        ("Preferred Tag", "Evidence Tag", "Evidence Tags",
         "Preferred Verification", "Evidence", "Verification Method"),
        ("Verdict", "Final Verdict", "Status"),
        # v2.x: Description and Root Cause are semantically equivalent in
        # practice — LLMs frequently consolidate them, especially on short
        # Low/Info findings where the "why" and the "what" are the same
        # sentence. Treat them as alternates rather than as two required
        # fields. The mechanical inventory merger uses whichever is present
        # as the description for downstream consumers.
        ("Description", "Root Cause", "Cause", "Summary", "Mechanism"),
        ("Impact", "Security Impact", "Risk", "Consequence", "Effect"),
    ]
    # Per-field miss counters. Soft-log up to 8 individual findings (to
    # avoid log spam on huge chunks), but always count toward the global
    # tally so we can promote pervasive field drift to a retry-hint.
    field_miss_counts: dict[str, int] = {}
    for idx, match in enumerate(detail_matches):
        start = match.end()
        end = detail_matches[idx + 1].start() if idx + 1 < len(detail_matches) else len(text)
        block = text[start:end]
        missing = [
            group[0] for group in required_field_groups
            if not has_field(block, group)
        ]
        for field in missing:
            field_miss_counts[field] = field_miss_counts.get(field, 0) + 1
        # NOTE: per-finding misses are NOT logged here. A sub-threshold miss
        # (e.g. a few findings folding Impact into Description prose) is normal
        # LLM variance — it was emitting cosmetic [WARNING] lines without ever
        # triggering a retry (false-positive noise). Only PERVASIVE drift
        # (>=30%, computed below) is surfaced, so the log aligns exactly with
        # the gate's actual decision.

    # Mechanical-default pass: a tiny set of fields have an unambiguous
    # pre-verify default, so a chunk that merely omitted them should be
    # auto-filled IN PLACE rather than burning a whole-chunk retry. Only
    # `Preferred Tag` qualifies: a not-yet-verified inventory finding is
    # `[CODE-TRACE]` by definition (the value verify assigns absent a PoC).
    # Content fields (Source IDs, Severity, Location, Description, Impact) have
    # NO safe default and still trigger a retry below. Recall-safe: this only
    # ADDS a labeled field that was already implied; it never edits content.
    _DEFAULTABLE = {"Preferred Tag": "[CODE-TRACE]"}
    inserts_at: list[tuple[int, str]] = []
    for idx, match in enumerate(detail_matches):
        start = match.end()
        end = detail_matches[idx + 1].start() if idx + 1 < len(detail_matches) else len(text)
        block = text[start:end]
        lines = []
        for field, default in _DEFAULTABLE.items():
            group = next((g for g in required_field_groups if g[0] == field), None)
            if group and not has_field(block, group):
                lines.append(f"**{field}**: {default}")
        if lines:
            inserts_at.append((end, "\n" + "\n".join(lines) + "\n"))
    if inserts_at:
        new_text = text
        for pos, snippet in sorted(inserts_at, key=lambda p: p[0], reverse=True):
            new_text = new_text[:pos] + snippet + new_text[pos:]
        try:
            out.write_text(new_text, encoding="utf-8")
            for field in _DEFAULTABLE:
                field_miss_counts.pop(field, None)
            log.info(
                "[_validate_inventory_chunk_structure] mechanically defaulted "
                "%d block(s) missing %s to its pre-verify value — no retry needed",
                len(inserts_at), "/".join(_DEFAULTABLE),
            )
        except OSError as exc:
            # Could not rewrite; fall through to the normal pervasive check so
            # the field is not silently lost (it will retry instead).
            log.warning(
                "[_validate_inventory_chunk_structure] could not write "
                "defaulted chunk (%s); leaving to pervasive-drift retry", exc,
            )

    # Pervasive-drift promotion: if ANY required field is missing from
    # >= 30% of detail blocks, promote to a hard retry-hint. The LLM's
    # next attempt will see the explicit instruction to emit the field
    # rather than silently collapsing it into Root Cause prose.
    #
    # Threshold rationale: 1-2 findings drifting in a 30-finding chunk is
    # normal LLM variance — re-running burns budget for a cosmetic gain.
    # 10+ findings dropping the same field is a prompt-template miss,
    # and a targeted retry-hint typically converges in 1 attempt.
    total = len(detail_matches)
    if total >= 5:  # below 5 detail blocks, percentage is noise
        pervasive: list[str] = []
        for field, count in field_miss_counts.items():
            if count / total >= 0.30:
                pervasive.append(f"{field} ({count}/{total} findings)")
        if pervasive:
            # Pervasive drift IS actionable (it triggers a retry-hint), so it
            # IS logged — exactly the misses that matter, never the cosmetic
            # sub-threshold ones.
            log.warning(
                "[_validate_inventory_chunk_structure] pervasive field drift "
                "in %s: %s", phase_name, ", ".join(sorted(pervasive)),
            )
            issues.append(
                "pervasive per-finding field drift: "
                + ", ".join(sorted(pervasive))
                + ". The Per-Finding Detail block for each ### [<ID>] heading "
                + "MUST emit `**<Field>**: ...` lines for every required "
                + "field (Source IDs, Severity, Location, Preferred Tag, "
                + "Verdict, Root Cause, Description, Impact). Do NOT collapse "
                + "Description into Root Cause prose; keep them as separate "
                + "labeled fields so downstream report writers can find both."
            )

    return issues


# =============================================================================
# Phase E1-E4 / E6: live pipeline enforcement gates.
#
# Each helper returns a list of issues; an empty list means PASS. The driver's
# gate runner promotes a non-empty issue list into a hard halt (critical=True
# for the phase that calls the gate, or via a missing-artifact path).
# =============================================================================
def _verify_file_present_for_id(scratchpad: Path, fid: str, *, min_bytes: int = 100) -> bool:
    """Return True when a usable verify file exists for the finding id."""
    candidates = (
        f"verify_{fid}.md",
        f"verify_F-{fid}.md",
        f"verify_F_{fid}.md",
        f"verify_[{fid}].md",
    )
    for name in candidates:
        p = scratchpad / name
        if p.exists() and p.stat().st_size >= min_bytes:
            return True
    return False


def _verification_queue_schema_issue(scratchpad: Path) -> str | None:
    """Return a fail-closed issue when verification_queue.md exists but parses empty.

    A genuinely empty queue is represented by driver-owned N/A artifacts such as
    verify_NONE.md, or by the canonical queue footer `Total: 0 findings`.
    Anything else means the queue parser and downstream validators checked zero
    items because the markdown contract drifted.
    """
    q = scratchpad / "verification_queue.md"
    if not q.exists():
        return None
    try:
        text = q.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"verification_queue.md unreadable ({exc})"
    if parse_verification_queue_rows(scratchpad):
        return None
    normalized = _llm_norm(text)
    if re.search(r"\bTotal:\s*0\s+findings\b", normalized, re.IGNORECASE):
        return None
    if not normalized.strip():
        return "verification_queue.md exists but is empty"
    return "verification_queue.md schema invalid: no parseable finding rows"


def _validate_verify_files_for_queue(scratchpad: Path, *, min_bytes: int = 100) -> list[str]:
    """E1: aggregate-level queue<->verify parity.

    For every active row in `verification_queue.md`, ensure a verify file
    exists. Per-shard gates already cover their own slices; this gate catches
    the "queue had 206, verify had 131" pattern at the aggregate boundary —
    the point where crossbatch / report_index / report_assemble would
    otherwise read from an incomplete set.
    """
    schema_issue = _verification_queue_schema_issue(scratchpad)
    if schema_issue:
        return [schema_issue]
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []
    expected_ids: list[str] = []
    for r in rows:
        fid = (r.get("finding id") or "").strip()
        if fid:
            expected_ids.append(fid)
    missing = [fid for fid in expected_ids if not _verify_file_present_for_id(scratchpad, fid, min_bytes=min_bytes)]
    if not missing:
        return []
    sample = ", ".join(missing[:8])
    msg = (
        f"verify-output parity: queue has {len(expected_ids)} active row(s), "
        f"only {len(expected_ids) - len(missing)} verify file(s) on disk; "
        f"{len(missing)} missing — sample: {sample}"
    )
    return [msg]


def _validate_report_index_inputs(scratchpad: Path) -> list[str]:
    """E2: report_index must reject unverified queue rows.

    Same set-difference as E1 but framed for the report_index gate so the halt
    message is specific to the index phase. Belt-and-suspenders with E1.
    """
    issues = _validate_verify_files_for_queue(scratchpad)
    if issues:
        return ["report_index: " + issues[0] + " — refuse to write report_index.md"]
    out = _validate_report_index_severity_provenance(scratchpad)
    triage = _validate_report_index_triage_safety(scratchpad)
    if triage:
        import logging as _logging
        _logging.getLogger("plamen.validators").warning(
            "[report_index] triage safety (WARNING, non-blocking): %s",
            "; ".join(triage),
        )
    return out


def _validate_report_index_prewrite_inputs(scratchpad: Path) -> list[str]:
    """Validate inputs before a deterministic report_index rewrite.

    This intentionally does not inspect an existing `report_index.md`; on
    resume that file can be stale or known-bad from a prior attempt. Content
    validators run only after the current phase has written the new index.
    """
    issues = _validate_verify_files_for_queue(scratchpad)
    if issues:
        return ["report_index: " + issues[0] + " - refuse to write report_index.md"]
    if issues:
        return ["report_index: " + issues[0] + " — refuse to write report_index.md"]
    return []


def _severity_from_report_cell(value: str, fallback_letter: str = "") -> str:
    text = _llm_norm(value or "")
    m = re.search(
        r"\b(Critical|High|Medium|Low|Informational|Info)\b",
        text,
        re.IGNORECASE,
    )
    if m:
        return normalize_severity(m.group(1))
    letter = (fallback_letter or "")[:1].upper()
    return {
        "C": "Critical", "H": "High", "M": "Medium",
        "L": "Low", "I": "Informational",
    }.get(letter, "")


def _chain_justified_upgrade_ids(scratchpad: Path) -> set[str]:
    """Return the set of chain IDs in chain_hypotheses.md that are GENUINE
    compound findings (machine line `Severity-Upgrade-Justified: YES` with a
    concrete non-empty `Combined-Impact`).

    These chains are NEVER eligible for CHAIN-RESTATEMENT exemption: dropping
    one without a body home is a genuinely-lost compound finding and must stay
    flagged. NO-upgrade / absorbed chains are not in this set and may be
    exempted (they are absorbed into their body constituents).

    Reuses the canonical `_chain_severity_upgrade_justified` /
    `_CHAIN_HYP_HEADING_RE` helpers so the YES/NO semantics match the chain
    self-restatement and anti-absorption gates exactly. Missing/unparseable
    file → empty set (no chain is treated as justified, the recall-safe
    default for this gate's exemption path).
    """
    try:
        from plamen_parsers import (
            _chain_severity_upgrade_justified,
            _CHAIN_HYP_HEADING_RE,
        )
        from plamen_parsers import _llm_norm as _pp_llm_norm
    except Exception:
        return set()
    chain_path = scratchpad / "chain_hypotheses.md"
    if not chain_path.exists():
        return set()
    try:
        text = _pp_llm_norm(chain_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()
    justified: set[str] = set()
    headings = list(_CHAIN_HYP_HEADING_RE.finditer(text))
    for i, hm in enumerate(headings):
        cid = hm.group(1).upper()
        start = hm.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        section = text[start:end]
        if _chain_severity_upgrade_justified(section):
            justified.add(cid)
    return justified


def _chain_section_severity(section: str, full_text: str, cid: str) -> str:
    """Robustly extract a chain's declared severity. Real `chain_hypotheses.md`
    files express it three different ways and we accept all three — a missed
    severity silently drops a justified High from the coverage seed (the bug
    this guards against). Order: most-specific first.
      1. a bare ``Chain Severity: <tier>`` line in the section, then
      2. a ``Chain Severity Matrix: ... -> <tier>`` conclusion line (the
         upgraded tier sits AFTER the arrow), then
      3. the summary-table row for the chain id (Chain Severity is its trailing
         column; last tier token on the row wins).
    """
    m = re.search(
        r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Chain\s+Severity(?:\*\*)?\s*:\s*"
        r"\**\s*(Critical|High|Medium|Low|Informational)\b",
        section,
    )
    if m:
        return normalize_severity(m.group(1))
    m = re.search(
        r"(?is)Chain\s+Severity\s+Matrix\b.*?(?:->|→|=>)\s*\**\s*"
        r"(Critical|High|Medium|Low|Informational)\b",
        section,
    )
    if m:
        return normalize_severity(m.group(1))
    for line in full_text.splitlines():
        if not line.lstrip().startswith("|") or cid.lower() not in line.lower():
            continue
        tiers = re.findall(
            r"\b(Critical|High|Medium|Low|Informational)\b", line, re.IGNORECASE
        )
        if tiers:
            return normalize_severity(tiers[-1])
    return ""


def _forced_chain_seed_rows(scratchpad: Path) -> dict[str, dict[str, object]]:
    """Force-include justified High/Critical chains into the coverage seed.

    A chain that `chain_hypotheses.md` upgraded to High/Critical with a justified
    Combined-Impact (machine line `Severity-Upgrade-Justified: YES`) is a genuine
    compound finding whose severity is ABOVE its constituents — yet without this
    helper it is never force-promoted to the verify queue / coverage seed in any
    mode, so a PARTIAL/Low→High chain silently never reaches the body.

    Returns ``{chain_id: {"severity": <High|Critical>, "constituents": [ids]}}``.
    Purely additive — the caller only ADDS these IDs (chain + constituents) to
    the seed superset, never demotes or drops anything. Severity-regression-safe.

    Reuses the canonical `_chain_justified_upgrade_ids` (YES + concrete impact)
    and `_parse_chain_constituents` semantics. Mode-agnostic by design: the
    force-include must hold regardless of light/core/thorough.
    """
    justified = _chain_justified_upgrade_ids(scratchpad)
    if not justified:
        return {}
    chain_path = scratchpad / "chain_hypotheses.md"
    if not chain_path.exists():
        return {}
    try:
        from plamen_parsers import _CHAIN_HYP_HEADING_RE, _CHAIN_MACHINE_LINE_RE
        from plamen_parsers import _llm_norm as _pp_llm_norm
    except Exception:
        return {}
    try:
        text = _pp_llm_norm(chain_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    out: dict[str, dict[str, object]] = {}
    headings = list(_CHAIN_HYP_HEADING_RE.finditer(text))
    for i, hm in enumerate(headings):
        cid = hm.group(1).upper()
        if cid not in justified:
            continue
        start = hm.end()
        end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
        section = text[start:end]
        # Extract the declared Chain Severity from the section prose. Only
        # force-include when it is High or Critical (the upgraded tiers that
        # otherwise never reach the body).
        sev = _chain_section_severity(section, text, cid)
        if sev not in {"Critical", "High"}:
            continue
        # Constituent IDs from the machine line (authoritative, bounded).
        constituents: list[str] = []
        ml = _CHAIN_MACHINE_LINE_RE.search(section)
        if ml:
            for raw in re.split(r"[,\s]+", (ml.group("ids") or "").strip()):
                rid = (_normalize_finding_id(raw) or raw).strip().upper()
                if rid and rid != cid:
                    constituents.append(rid)
        out[cid] = {"severity": sev, "constituents": constituents}
    return out


def _reason_is_chain_restatement(reason: str) -> bool:
    """True when an Excluded Findings reason cites CHAIN-RESTATEMENT.

    Per report-template / phase6a-report-index rules, a NO-upgrade chain that
    is absorbed into a body constituent is recorded with `CHAIN-RESTATEMENT`
    (Consolidation Reason) and/or `CHAIN-DOWNGRADE` (Trust Adj.). Both are
    legitimate non-body dispositions equivalent to CONSOLIDATED. We also accept
    the prose form `absorbed into <body finding>` when it co-occurs with a
    chain marker, so a human-phrased reason is not falsely flagged.
    """
    reason_norm = re.sub(r"[\s\-]+", "_", (reason or "").upper())
    if "CHAIN_RESTATEMENT" in reason_norm or "CHAIN_DOWNGRADE" in reason_norm:
        return True
    text = _llm_norm(reason or "").lower()
    if not text:
        return False
    # Prose form: an absorbed/merged chain restatement. Require BOTH a chain
    # marker and an absorption verb so generic "absorbed" prose for a
    # non-chain row does not slip through (those are handled by CONSOLIDATED /
    # MERGE_INTO / DUPLICATE in the main allowed set).
    has_chain = bool(re.search(r"\bchain\b", text)) or bool(re.search(r"\bch-\d+\b", text))
    has_absorb = bool(re.search(r"\b(?:absorb(?:ed)?|restat\w*|merg(?:ed|e)\s+into)\b", text))
    return has_chain and has_absorb


def _validate_report_index_triage_safety(scratchpad: Path) -> list[str]:
    """Reject unsafe client-worthiness triage for Medium+ findings."""
    idx_path = scratchpad / "report_index.md"
    if not idx_path.exists():
        return []
    try:
        text = _llm_norm(idx_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    m = re.search(r"(?ims)^##\s+Excluded\s+Findings\b.*?(?=^##\s|\Z)", text)
    if not m:
        return []
    headers, rows = _parse_markdown_table(m.group(0), [])
    if not headers:
        return []
    keys = [_norm_key(h) for h in headers]

    def _cell(row: list[str], *names: str) -> str:
        for name in names:
            if name in keys:
                i = keys.index(name)
                if i < len(row):
                    return row[i].strip()
        return ""

    allowed_medium_plus = (
        "DROP_FALSE_POSITIVE",
        "FALSE_POSITIVE",
        "REFUTED",
        "INFEASIBLE",
        "UNRESOLVED_EVIDENCE",
        "EVIDENCE_UNRESOLVED",
        "INSUFFICIENT_EVIDENCE",
        "NEAR_ZERO_EVIDENCE",
        "ZERO_EVIDENCE",
        "NO_REPRODUCIBLE_PATH",
        "NO_REPRODUCIBLE_CODE_PATH",
        "NO_REACHABLE_PATH",
        "NO_TRACE",
        "CONTESTED",
        "LOW_CONFIDENCE",
        "DROP_NON_SECURITY",
        "DROP_DESIGN_CONFIRMATION",
        "DROP_UNACTIONABLE_SPECULATION",
        "MERGE_INTO",
        "MERGED",
        "DUPLICATE",
        "CONSOLIDATED",
        "APPENDIX_ONLY",
        "AUTO_EXCLUDED",
        # Driver re-emit marker for a content-LESS self-excluded stub (no
        # concrete location or harm). An unfalsifiable stub routed to appendix
        # is a legitimate non-body disposition (it is KEPT, not dropped). A
        # content-BEARING re-emit does NOT carry this marker, so it still
        # requires a real evidence/dedup reason to leave the body (negative
        # control preserved). Root fix from a prior run.
        "CONTENT_LESS",
        "CONTENTLESS",
    )

    def _medium_plus_exclusion_allowed(reason: str) -> bool:
        reason_norm = re.sub(r"[\s\-]+", "_", (reason or "").upper())
        if any(tok in reason_norm for tok in allowed_medium_plus):
            return True
        text = _llm_norm(reason or "").lower()
        if not text:
            return False
        # Structural evidence/refutation basis. This deliberately avoids a
        # finite list of report-index prose variants: any Medium+ exclusion is
        # allowed only when the reason is clearly about failure to establish a
        # reachable, reproducible, evidenced issue, not merely "not client
        # worthy" or "appendix only".
        evidence_failure = bool(re.search(
            r"(?:"
            r"(?:insufficient|weak|missing|minimal|near[-\s]*zero|zero|no)\s+"
            r"(?:evidence|support|proof|trace|code\s+trace)"
            r"|(?:evidence|support|proof|trace|code\s+trace)\s+"
            r"(?:unresolved|insufficient|weak|missing|absent)"
            r"|no\s+(?:reproducible\s+)?(?:code\s+)?path"
            r"|no\s+(?:reachable\s+)?(?:entry|route|path|trace)"
            r"|cannot\s+(?:reproduce|reach|trace)"
            r"|unresolved\s+after\s+\w+"
            r"|confidence\s+0\.\d+"
            r"|low\s+confidence"
            r"|contested"
            r")",
            text,
        ))
        return evidence_failure

    justified_chains = _chain_justified_upgrade_ids(scratchpad)

    unsafe: list[str] = []
    for row in rows:
        sev = normalize_severity(_cell(row, "severity"))
        if sev not in ("Critical", "High", "Medium"):
            continue
        raw_id = _cell(row, "internal id", "internal hypothesis id", "finding id", "id")
        fid = _normalize_finding_id(raw_id) or raw_id or "unknown"
        reason = _cell(row, "exclusion reason", "reason", "verdict", "status")
        if _medium_plus_exclusion_allowed(reason):
            continue
        # CHAIN-RESTATEMENT carve-out: a NO-upgrade chain absorbed into its
        # body constituent is a legitimate non-body disposition (equivalent to
        # CONSOLIDATED). BUT a chain that chain_hypotheses.md marks as a
        # justified-upgrade compound (Severity-Upgrade-Justified: YES +
        # concrete Combined-Impact) is a genuine distinct finding — excluding
        # it without a body home is a dropped compound finding and STAYS
        # flagged. So we exempt only when the cited chain is NOT a justified
        # upgrade (or no such chain exists in the chain file).
        if _reason_is_chain_restatement(reason):
            chain_ids = {m.group(0).upper() for m in re.finditer(r"\bCH-\d+\b", (raw_id or "") + " " + (reason or ""), re.IGNORECASE)}
            # Restatement is only credible for a NON-justified chain. If ANY
            # referenced chain ID is a justified-upgrade compound, do not
            # exempt (negative control). If no chain ID parses, fall back to
            # "no justified chain matches" → exempt, since the reason itself
            # is an explicit NO-upgrade restatement disposition.
            if not (chain_ids & justified_chains):
                continue
        unsafe.append(f"{fid}:{sev}:{reason or 'missing reason'}")
    if not unsafe:
        return []
    sample = "; ".join(unsafe[:5])
    more = f"; ... (+{len(unsafe)-5} more)" if len(unsafe) > 5 else ""
    return [
        "report_index triage safety: Medium+ excluded finding(s) lack an "
        "allowed non-body reason (DROP_FALSE_POSITIVE / DROP_NON_SECURITY / "
        "INFEASIBLE / UNRESOLVED_EVIDENCE / MERGE_INTO / DUPLICATE / "
        f"CONSOLIDATED): {sample}{more}"
    ]


def _report_index_adjustment_reason_present(*values: str) -> bool:
    text = _llm_norm(" ".join(v or "" for v in values)).strip()
    if not text:
        return False
    stripped = re.sub(r"[\s`*_|\-–—:;,.]+", "", text).lower()
    if stripped in {"", "none", "na", "n/a", "no", "notapplicable"}:
        return False
    return bool(re.search(
        r"trust|actor|assumption|proven|poc|fail|cap|unresolved|partial|"
        r"chain|upgrade|downgrade|demot|human|contest|was|from|->|=>|"
        # v2.0.7 (P1.1): SEVERITY_OVERRIDE is the new driver-emitted token
        # for severity-provenance auto-repair. Recognize it as a canonical
        # reason so the provenance gate doesn't re-flag rows the repair
        # function just patched.
        r"override|"
        # STRUCTURAL-UNTESTABLE(sev): proven-only structural carve-out audit
        # trail. A preserved (uncapped) severity carrying this note records
        # that the verifier blessed a genuine structural-untestability blocker
        # for the finding's PoC class, so the provenance gate must accept it.
        # NOTE (Fix 3): the EXTERNAL-ASSUMPTION-CAP(sev) token is already
        # accepted here via the `assumption` and `cap` alternatives above — no
        # new alternative is needed. A canonical Verification word (CONFIRMED /
        # VERIFIED / UNVERIFIED) is deliberately NOT added: it is a STATUS, not a
        # severity-change REASON, and must never excuse a silent severity delta.
        r"structural|untestable|"
        # M4: INDEPENDENT-MIN(<claimed>) is the Trust Adj. token for the
        # blind-first independent-severity cap (mirrors EXTERNAL-ASSUMPTION-
        # CAP's registration above). The token itself does not contain "cap"
        # as a substring, so "independent" must be its own alternative.
        r"independent",
        text,
        re.IGNORECASE,
    ))


def _poc_demotion_caps_for_validator(scratchpad: Path) -> dict[str, str]:
    path = scratchpad / "poc_demotions.md"
    if not path.exists():
        return {}
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    caps: dict[str, str] = {}
    headers, rows = _parse_markdown_table(text, ["finding id", "capped at"])
    if not headers:
        return caps
    keys = [_norm_key(h) for h in headers]
    for row in rows:
        d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
        fid = _normalize_finding_id(d.get("finding id", "")) or d.get("finding id", "")
        cap = normalize_severity(d.get("capped at", ""))
        if fid and cap:
            caps[fid] = cap
    return caps


def _cap_report_index_severity(severity: str, cap: str) -> str:
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev = normalize_severity(severity)
    capped = normalize_severity(cap)
    if order.index(sev) < order.index(capped):
        return capped
    return sev


def _structurally_untestable(scratchpad: Path, vtxt: str, poc_class: str) -> bool:
    """Is this finding GENUINELY structurally untestable (preserve severity)?

    True only when the verifier's PoC ledger names a real structural-untestability
    blocker that is valid for the finding's PoC class. This is the verifier-blessed
    case the proven-only blanket cap conflates with weak/lazy `[CODE-TRACE]`.

    Reuses the already-shipped `_valid_poc_skip` distinction (which rejects
    STRUCTURAL_* for unit/property class and unmockable EXTERNAL_* skips), then
    adds two additional REJECTIONS so weak skips keep the cap:
      * NO_BUILD_ENVIRONMENT cited while build_status.md reports SUCCESS (the
        harness exists — not structurally untestable).
      * PURE_SPEC_OR_DOCS_ONLY (a spec/docs-only finding is NOT a CONFIRMED
        structural harm that merely lacks an executable harness).
    Recall-safe: this can ONLY mark FEWER findings as untestable than
    `_valid_poc_skip` alone, so it never preserves a weak finding.
    """
    skip = _poc_skip_code(vtxt)
    if not skip:
        return False
    if not _valid_poc_skip(vtxt, poc_class):
        return False
    if "NO_BUILD_ENVIRONMENT" in skip and _build_succeeded(scratchpad) is True:
        return False
    if "PURE_SPEC_OR_DOCS_ONLY" in skip:
        return False
    return True


# ── Fix 3: narrow always-on brake for unproven external-assumption Highs ───
# A precision post-mortem found Highs promoted purely on R10 worst-case-external
# assumption: a finding whose in-scope-proven fact is only the ABSENCE of a
# balance-delta check, and whose fund-loss HARM materializes solely when an
# untrusted EXTERNAL contract's return value diverges from reality (over-report
# / return-inflation / misrouted output). No PoC was (or could be, without a
# fork) executed. Such a finding stays IN THE BODY (it is a real hardening gap)
# but its severity must not ride at High on an assumed worst-case external
# behavior — it is capped to Medium (floor Medium, never Low) and stamped
# EXTERNAL-ASSUMPTION-CAP(<orig>). Three CONJUNCTIVE guards keep this narrow so
# it never touches an in-scope-proven or PoC-executed finding.

_EXTERNAL_ASSUMPTION_BLOCKERS: frozenset[str] = frozenset({
    "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS",
    "DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL",
    "STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION",
})


def _poc_not_attempted(content: str) -> bool:
    """Guard 2: the PoC ledger says `Attempted: NO` with one of the
    external/deployment/structural no-fork blockers.

    This is the exact class the fork-PoC mandate (Fix 2) would target once an
    RPC egress exists; until then Fix 3 caps it deterministically."""
    if _poc_attempted_value(content) != "NO":
        return False
    return _poc_skip_code(content) in _EXTERNAL_ASSUMPTION_BLOCKERS


def _poc_attempted_and_passed(content: str) -> bool:
    """Load-bearing carve-out: the ledger shows `Attempted: YES` AND the
    Execution Result recorded a passing run.

    Protects findings whose author actually built and ran a harness that PASSED
    (even if the tag was integrity-downgraded to [CODE-TRACE] because the PoC
    lacked an assertion) — those are NOT unproven external-assumption Highs.
    Redundant with guard 2 (Attempted:YES ⇒ _poc_not_attempted is False) but
    stated explicitly so a format drift in the skip fields cannot re-expose a
    genuinely-executed finding to the cap."""
    if _poc_attempted_value(content) != "YES":
        return False
    m = re.search(
        r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Result(?:\*\*)?\s*:\s*\**\s*(PASS)\b",
        content or "",
    )
    return bool(m)


def _external_assumption_promoted(content: str) -> bool:
    """Guard 3: the finding's harm is anchored to an UNTRUSTED-EXTERNAL-
    RETURN-VALUE mechanism and its severity is promoted on that assumption.

    Requires BOTH:
      (a) an external call whose RETURN VALUE is trusted verbatim (no re-derived
          balance-delta) — the specific in-scope-proven structural fact; AND
      (b) a promotion signal that the HARM rides on assumed worst-case external
          behavior — a literal `[EXTERNAL-ASSUMPTION:]` tag, R10 worst-case
          language, or explicit external-dependency conditioning co-located with
          the return-trust.

    The mechanism requirement (a) is what makes this NOT a bare-R10 match: an
    R10 mention alone (or any finding without external-return-value trust) never
    fires. Anchored to a mechanism, not a protocol name (no-overfit)."""
    low = _llm_norm(content or "").lower()
    return_trust = bool(re.search(
        r"return\s+value|returned?\s+(?:by|value|figure|amount)|"
        r"reported\s+(?:figure|amount|value|output)|raw\s+\w*\s*return|"
        r"consumed\s+verbatim|trusted\s+verbatim|ground\s+truth",
        low,
    ))
    balance_delta = bool(re.search(
        r"balance[- ]?delta|balanceof\s*delta|no\s+balance|"
        r"without\s+[^.]*balance|delta\s+(?:check|verification|measure|bracket)|"
        r"over[- ]?(?:pay|report)|under[- ]?deliver|"
        r"return[- ]?inflation|inflat\w*",
        low,
    ))
    if not (return_trust and balance_delta):
        return False
    promoted = bool(re.search(
        r"\[\s*external-assumption\s*:|worst[- ]?(?:realistic|case)|\br10\b|"
        r"external(?:ly)?[,\s][^.]{0,60}"
        r"(?:dependency|contract|router|integration|system\s+contract)|"
        r"trusted[- ]by[- ]integration|misbehav|malicious",
        low,
    ))
    return promoted


def _external_assumption_cap_applies(vtxt: str) -> bool:
    """Whole three-guard conjunction + carve-out for the external-assumption
    severity brake. Kept as one predicate so the severity map and the status
    map read from the identical decision."""
    if _poc_attempted_and_passed(vtxt):
        return False  # carve-out: a real passing run is not unproven
    return (
        not has_proof_grade_evidence(vtxt)   # guard 1: no proof-grade evidence
        and _poc_not_attempted(vtxt)          # guard 2: Attempted:NO + ext blocker
        and _external_assumption_promoted(vtxt)  # guard 3: ext-return-value promo
    )


# ── R10 demotion-side gate: external-best-case un-demotion veto ─────────────
# MIRROR of the assert-side `_external_assumption_cap_applies` above. That brake
# caps a finding whose HARM rides on an assumed worst-case external condition;
# this gate handles the INVERSE demotion — a finding CONFIRMED-in-scope at DEPTH
# that a verifier DEMOTED (verdict CONTESTED / harm dismissed) purely on an
# UNCITED best-case external assumption. The disposition (not a severity number)
# is what was silently lost; the driver-side compute hook
# `_apply_external_assumption_undemotions` re-emits + stamps + re-queues, and
# `external_assumption_undemotions.md` is the read-back ledger these two helpers
# serve. Recall-safe: an absent/unparseable ledger is a strict no-op.

def _floor_report_index_severity(severity: str, floor: str) -> str:
    """Inverse of `_cap_report_index_severity`: never LOWERS; raises `severity`
    up to `floor` when `floor` is MORE severe. (Local: `_higher_severity` lives
    in plamen_mechanical and is not imported here.)"""
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev = normalize_severity(severity)
    fl = normalize_severity(floor)
    return fl if order.index(fl) < order.index(sev) else sev


def _load_external_assumption_undemotions(scratchpad: Path) -> dict[str, str]:
    """Read the driver-computed ledger `external_assumption_undemotions.md`.

    Mirrors `_load_independent_severity_caps` / `_poc_demotion_caps_for_validator`.
    Returns {finding_id: restored_floor_severity}. Recall-safe {} on absent /
    unparseable ledger.
    """
    path = scratchpad / "external_assumption_undemotions.md"
    if not path.exists():
        return {}
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    out: dict[str, str] = {}
    headers, rows = _parse_markdown_table(text, ["finding id", "restored floor"])
    if not headers:
        return out
    keys = [_norm_key(h) for h in headers]
    for row in rows:
        d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
        fid = _normalize_finding_id(d.get("finding id", "")) or d.get("finding id", "")
        floor = normalize_severity(d.get("restored floor", ""))
        if fid and floor:
            out[fid] = floor
    return out


# Supplementary external-best-case-demotion cue: a verifier that DISMISSES the
# harm because a value is assumed STABLE / INVARIANT WITHIN A WINDOW (per
# ledger / timestamp / block) — the stale-cache-vs-fresh-read demotion shape the
# return-trust + balance-delta `_external_assumption_promoted` regex does not
# cover. Anchored to the within-window-stability MECHANISM, never a protocol
# name (no-overfit). Only consulted when the finding is already DEMOTED
# (CONTESTED/PARTIAL/UNRESOLVED) in the caller, so a finding whose BUG is
# non-stability (which verifies CONFIRMED) is filtered out upstream.
_EXTERNAL_STABILITY_DEMOTION_RE = re.compile(
    r"time[- ]?invariant"
    r"|(?:stable|constant|unchanged|fixed|does\s+not\s+change|doesn't\s+change)"
    r"\s+(?:within|per|across|for)\s+(?:a\s+)?"
    r"(?:ledger|timestamp|block|window|epoch|round|tx|transaction)"
    r"|invariant\s+within\s+(?:a\s+)?(?:ledger|timestamp|block|window)"
    r"|fresh[- ]per[- ](?:timestamp|ledger|block)"
    r"|fresh\s+per\s+(?:timestamp|ledger|block)",
    re.IGNORECASE,
)


def _external_bestcase_stability_demotion(content: str) -> bool:
    """Supplementary external-best-case demotion cue (generic). True when the
    verifier prose dismisses the harm on an assumed WITHIN-WINDOW STABILITY of a
    value (per-ledger/timestamp/block time-invariance) — the stale-cache demotion
    shape `_external_assumption_promoted` (return-trust + balance-delta) misses.
    ANDed with `demoted` in the caller, so it is a strict recall-direction widen
    of the external-best-case-demotion detection, never a standalone trigger."""
    return bool(_EXTERNAL_STABILITY_DEMOTION_RE.search(_llm_norm(content or "")))


def _external_dependency_research_surfaces_local(
    scratchpad: Path,
) -> list[tuple[str, str]]:
    """Local re-parse of `external_dependency_research.md`'s Integration Surface
    column (avoids a driver->validators->driver import cycle; the driver owns the
    canonical `_external_dependency_research_surfaces`). Returns (dependency,
    file:line) pairs. Never raises; [] on absent/unparseable ledger."""
    path = scratchpad / "external_dependency_research.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    row_re = re.compile(r"^\|\s*`?([^|`]+?)`?\s*\|\s*([^|]+?)\s*\|", re.MULTILINE)
    loc_re = re.compile(r"[\w./\\-]+\.[A-Za-z]+:L?\d+")
    out: list[tuple[str, str]] = []
    for m in row_re.finditer(text):
        dep = m.group(1).strip()
        if not dep or dep.lower() in (
            "dependency", "---", "name/namespace", "-", ""
        ):
            continue
        for loc in loc_re.findall(m.group(2)):
            out.append((dep, loc))
    return out


# ── Fix 2: severity-aware fork-PoC mandate (INERT-SAFE without RPC egress) ──
# A Medium+ external-integration fund-drain/misrouting finding whose harm rides
# on an untrusted external contract at a KNOWN deployed address is exactly the
# class a `forge test --fork-url --fork-block-number` PoC can PROVE — instead of
# being refused with a self-declared `structural` PoC class and no attempt. Two
# pieces:
#   (1) `_effective_poc_class` floors such a finding to `integration` so a
#       verifier cannot zero the PoC requirement by self-declaring `structural`.
#   (2) `_valid_poc_skip` rejects an EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip
#       for a Medium+ CONFIRMED finding ONLY when an RPC egress-reachability
#       probe SUCCEEDS *and* the verifier prose names a concrete address — i.e.
#       a fork PoC is actually runnable here.
#
# The entire mandate is GATED on the egress-reachability probe. With NO reachable
# RPC (this environment) the probe returns False, the skip STAYS valid, and the
# finding is stamped `[UNPROVEN-EXTERNAL]` — the mandate is a strict NO-OP versus
# the pre-Fix-2 disposition. Anchored to GENERIC mechanisms (no protocol names).

# Client-facing evidence-honesty stamp for a Medium+ external-integration
# finding whose fork PoC could NOT be attempted because no RPC egress was
# reachable. It co-exists with `[CODE-TRACE]` (it is NOT a proof/trace tag and
# is deliberately NOT in EVIDENCE_TAGS_PROOF — it must never upgrade a finding to
# proof-grade). It records "the harm mechanism is in-scope-proven but its
# external leg is unverified for want of a fork" so R10 can block promotion
# ABOVE the proven-mechanism severity (never below).
_UNPROVEN_EXTERNAL_STAMP = "[UNPROVEN-EXTERNAL]"

# GENERIC fund-drain / misrouting harm vocabulary (no protocol/contract/function
# names). A finding asserting funds are drained, mis-routed to a wrong
# recipient/chain, over-paid, or lost across an EXTERNAL integration carries a
# concrete fund-flow harm — the kind a fork PoC proves. Matching is
# negation-aware via `_poc_kw_present`.
_EXTERNAL_INTEGRATION_HARM_PATTERNS = (
    "fund drain", "funds drained", "drain funds", "drains funds",
    "fund loss", "funds lost", "loss of funds", "steal funds",
    "misroute", "misrouted", "mis-routed", "mis-route",
    "wrong recipient", "wrong destination", "wrong chain",
    "routed to the wrong", "sent to the wrong",
    "over-pay", "over-payment", "overpay", "overpayment",
    "under-deliver", "misdirected", "siphon",
)


def _matches_external_integration_harm(*texts: str) -> bool:
    """True iff any *text* asserts a GENERIC external-integration fund-drain /
    misrouting harm. Negation-aware (a negated mention does not match).

    Recall-direction: a match only ever routes a finding TOWARD a testable
    (`integration`) class / keeps it in the body, never drops it."""
    return any(
        _poc_kw_present(p, *texts) for p in _EXTERNAL_INTEGRATION_HARM_PATTERNS
    )


# A concrete deployed address the verifier prose names — a RESOLVABLE target a
# `--fork-url` PoC can pin against. This requires an actual address TOKEN, not
# just the words "deployed address": a bare phrase like "no deployed address is
# known" describes the ABSENCE of a target and must NOT satisfy the guard. We
# accept a 0x-hex EVM address, an explicit "deployed/mainnet at 0x…" phrase, or a
# base58 program-id (32–44 chars) co-located with an address/program-id cue.
_DEPLOYED_ADDRESS_RE = re.compile(
    r"0x[0-9a-fA-F]{40}\b"
    r"|(?:deployed|mainnet|live|on[- ]?chain|pinned|canonical|forked?)\s+"
    r"(?:contract\s+|program\s+)?(?:at\s+)?"
    r"(?:0x[0-9a-fA-F]{40}\b|[1-9A-HJ-NP-Za-km-z]{32,44}\b)"
    r"|(?:address|program\s*id)\s+(?:is\s+)?"
    r"(?:0x[0-9a-fA-F]{40}\b|[1-9A-HJ-NP-Za-km-z]{32,44}\b)",
    re.IGNORECASE,
)


def _names_resolvable_deployed_address(content: str) -> bool:
    """Guard: the verifier prose names a concrete deployed/on-chain address
    TOKEN (0x-hex or base58 program-id) so a `--fork-url` PoC has a pinned target
    to fork against. A bare mention of the words "deployed address" WITHOUT an
    actual address token does NOT satisfy this — that describes the absence of a
    fork target, not a resolvable one."""
    return bool(_DEPLOYED_ADDRESS_RE.search(content or ""))


def _fork_rpc_url(scratchpad: Path) -> str:
    """Resolve a fork RPC URL from config.json or the environment. Empty when
    none is configured — in which case the fork-PoC mandate is inert."""
    for env_key in ("PLAMEN_FORK_RPC_URL", "FORK_RPC_URL", "ETH_RPC_URL"):
        val = os.environ.get(env_key, "").strip()
        if val:
            return val
    try:
        cfg = scratchpad / "config.json"
        if cfg.exists():
            data = json.loads(cfg.read_text(encoding="utf-8", errors="replace"))
            for key in ("fork_rpc_url", "rpc_url", "fork_url"):
                val = str(data.get(key, "") or "").strip()
                if val:
                    return val
    except Exception:
        pass
    return ""


def _unproven_external_stamped(vtxt: str) -> bool:
    """True when the verifier body carries the `[UNPROVEN-EXTERNAL]` stamp: an
    external-integration finding whose fund-flow harm is in-scope-proven but
    whose external leg could NOT be fork-verified (no reachable RPC). R10 uses
    this to hold the report severity at the proven-mechanism floor (never above),
    never below. Legacy verify files never carry the stamp, so this is a strict
    no-op on pre-Fix-2 data."""
    return _UNPROVEN_EXTERNAL_STAMP.upper() in (vtxt or "").upper()


def _egress_rpc_reachable(scratchpad: Path) -> bool:
    """Egress-reachability probe for the fork-PoC mandate (Fix 2).

    Returns True ONLY when a fork RPC endpoint is BOTH configured AND reachable
    via a short, bounded TCP connect. With no configured URL, no network egress,
    or any failure, returns False — so the whole mandate is a strict no-op in an
    RPC-less environment (this one). This is the SINGLE interlock the plan
    requires; tests monkeypatch it to simulate a reachable RPC without real
    network access.
    """
    url = _fork_rpc_url(scratchpad)
    if not url:
        return False
    try:
        import socket
        from urllib.parse import urlparse

        parsed = urlparse(url if "://" in url else "//" + url, scheme="https")
        host = parsed.hostname
        if not host:
            return False
        port = parsed.port or (443 if (parsed.scheme or "https") == "https" else 80)
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except Exception:
        return False


def _expected_report_index_severities(scratchpad: Path) -> dict[str, str]:
    caps = _poc_demotion_caps_for_validator(scratchpad)
    independent_caps = _load_independent_severity_caps(scratchpad)
    undemotions = _load_external_assumption_undemotions(scratchpad)
    proven_only = _config_proven_only(scratchpad)
    out: dict[str, str] = {}
    for row in parse_verification_queue_rows(scratchpad):
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        vf = _verify_file_for_id(scratchpad, fid)
        try:
            vtxt = _llm_norm(vf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            vtxt = ""
        sev = _enforce_severity_matrix(vtxt, row)
        status = _verifier_status_from_text(vtxt)
        # PARTIAL/UNRESOLVED auto-demotion: only fires when the verifier
        # did NOT explicitly assign a Severity field. If the verifier
        # wrote `**Severity**: Medium` AND `**Verdict**: PARTIAL`, they
        # already considered the partial-evidence context when picking
        # Medium — demoting here second-guesses the verifier.
        # Observed INV-128 case: explicit Severity: Medium + Verdict: PARTIAL
        # → pre-suppression driver demoted to Low → LLM correctly wrote
        # Medium per the explicit field → provenance gate halted.
        verifier_assigned_severity = bool(
            _field_from_markdown(vtxt, ("Severity", "Final Severity"))
        )
        if (
            not verifier_assigned_severity
            and any(tok in status for tok in ("UNRESOLVED", "PARTIAL"))
        ):
            sev = _demote_severity_once(sev)
        if fid in caps:
            sev = _cap_report_index_severity(sev, caps[fid])
        # M4: blind-first independent severity cap (anti-inflation). Only
        # ever lowers (never raises, never drops) — see
        # `_apply_independent_severity_caps` for the full derivation.
        if fid in independent_caps:
            sev = _cap_report_index_severity(sev, independent_caps[fid])
        # R10 demotion-side gate (MIRROR of the assert-side external-assumption
        # CAP below). A finding CONFIRMED-in-scope at DEPTH that was DEMOTED
        # (verdict CONTESTED / harm dismissed) by the verifier purely on an
        # UNCITED best-case external assumption must not silently lose its
        # disposition. FLOOR its report severity to the depth-CLAIMED (queue)
        # severity and `continue` so the proven-only Low-cap cannot push it
        # below. The ledger is written by the driver post-verify hook
        # `_apply_external_assumption_undemotions` (which also stamps
        # [UNPROVEN-EXTERNAL] + re-queues). Recall-safe: empty ledger => no-op.
        # Placed BEFORE the CAP/UNPROVEN blocks so a general-case veto floors to
        # FULL claimed severity (may exceed Medium), superseding their Medium
        # floor; on a Low-claimed finding it is inert numerically but still
        # `continue`s past the proven-only Low-cap.
        if fid in undemotions:
            sev = _floor_report_index_severity(sev, undemotions[fid])
            out[fid] = sev
            continue
        # Fix 3: NARROW always-on external-assumption severity brake. Fires
        # (regardless of proven_only) ONLY on the three-guard conjunction —
        # CODE-TRACE-only + Attempted:NO-with-external-blocker + external-
        # return-value-promotion — and NOT on a finding with a passing run.
        # Caps to Medium (floor Medium, never Low, in-body). `continue` so the
        # proven_only Low-cap below can never push this class below Medium.
        if _external_assumption_cap_applies(vtxt):
            sev = _cap_report_index_severity(sev, "Medium")
            out[fid] = sev
            continue
        # Fix 2 R10: a finding stamped `[UNPROVEN-EXTERNAL]` (external-integration
        # fund-drain/misrouting harm whose external leg was NOT fork-verified for
        # want of a reachable RPC) must NOT be promoted ABOVE its proven-mechanism
        # severity on the assumed external behavior. Cap to Medium (floor Medium,
        # in-body, never below) and `continue` so the proven_only Low-cap cannot
        # push it lower. Gated on the LITERAL stamp + Attempted:NO + no
        # proof-grade evidence, so it is a strict no-op on any legacy/proven
        # finding (the stamp is absent) — this is the R10 promotion brake the
        # INERT mandate relies on.
        if (
            _unproven_external_stamped(vtxt)
            and not has_proof_grade_evidence(vtxt)
            and _poc_attempted_value(vtxt) == "NO"
        ):
            sev = _cap_report_index_severity(sev, "Medium")
            out[fid] = sev
            continue
        # Proven-only cap for [CODE-TRACE]-only findings, WITH a structural-
        # untestability carve-out. The blanket "cap [CODE-TRACE] at Low" rule
        # conflates (1) weak/lazy traces (a harness exists but no PoC was
        # written) with (2) genuinely structurally-untestable CONFIRMED findings
        # whose verifier explicitly declined to downgrade. Only (1) keeps the
        # Low cap; (2) preserves the verifier-stated severity. Reuses the shipped
        # `_valid_poc_skip` distinction — no new heuristic. Gated behind
        # proven_only + best-tag-is-CODE-TRACE-only, so it is a no-op for
        # non-proven-only runs and for any POC-PASS/MEDUSA-PASS/PROD-* finding
        # (those carry a proof-grade tag). Conservative + additive: relative to
        # the current blanket cap this can only RAISE severity (case 2), never
        # lower it.
        if proven_only and not has_proof_grade_evidence(vtxt):
            poc_class = _effective_poc_class(row.get("poc class") or "", vtxt)
            if not _structurally_untestable(scratchpad, vtxt, poc_class):
                sev = _cap_report_index_severity(sev, "Low")
            # else: verifier-blessed structural untestability → preserve sev
        out[fid] = sev
    return out


# A tag-downgrade audit annotation the driver writes into a verify file when it
# demotes a prose proof tag: e.g. `[CODE-TRACE] (was [POC-PASS], integrity
# downgrade: ...)` or `[CODE-TRACE] (was [POC-PASS], mechanical integrity=...)`.
# The RESIDUAL `[POC-PASS]` inside that parenthetical is NOT current evidence —
# scanning raw text would mis-read the finding as proof-grade (the exact bug
# that inflated index-VERIFIED to 71). Strip these before reading the tag.
_TAG_DOWNGRADE_ANNOTATION_RE = re.compile(
    r"\(\s*(?:was|previously|formerly)\s*\[[^\]]+\][^)]*\)",
    re.IGNORECASE,
)


_UNEXECUTED_PROOF_FLAGS = frozenset({
    "[MECHANICAL-UNAVAILABLE]",
    "[POC-UNVERIFIED-HARNESS]",
})


def _effective_tag_is_proof_grade(
    tag_text: str, integrity_context: str = "",
) -> bool:
    """Interpret an effective evidence tag for report-label purposes only.

    Production evidence remains proof-grade independently of the local harness.
    A mechanical proof tag preserved beside an explicit non-execution flag does
    not make the report label VERIFIED; it remains useful provenance, but the
    mechanical run did not establish it.
    """
    upper = (tag_text or "").upper()
    if any(tag in upper for tag in EVIDENCE_TAGS_PROD):
        return True
    context_upper = (integrity_context or "").upper()
    if any(
        flag in upper or flag in context_upper
        for flag in _UNEXECUTED_PROOF_FLAGS
    ):
        return False
    return has_proof_grade_evidence(upper)


def _effective_proof_grade_from_manifest_row(row: object) -> Optional[bool]:
    """Return the structured manifest's report-label proof grade.

    ``None`` means the row is unusable and the caller should use the legacy
    verify-file fallback. This helper deliberately affects only the canonical
    CONFIRMED/VERIFIED label; proof routing and severity retain their existing
    evidence helpers.
    """
    if not isinstance(row, dict):
        return None
    effective_tag = str(row.get("effective_tag") or "")
    mechanical_status = str(row.get("mechanical_status") or "").upper()
    integrity_state = str(row.get("integrity_state") or "").upper()
    if not (effective_tag or mechanical_status or integrity_state):
        return None

    effective_upper = effective_tag.upper()
    if any(tag in effective_upper for tag in EVIDENCE_TAGS_PROD):
        return True
    if mechanical_status == "PASS" and integrity_state in {"", "CONSISTENT"}:
        return True
    if (
        mechanical_status and mechanical_status != "PASS"
        and has_mechanical_proof(effective_upper)
    ):
        return False
    if integrity_state in {"MECHANICAL_UNAVAILABLE", "POC_UNVERIFIED_HARNESS"}:
        return False
    return _effective_tag_is_proof_grade(effective_tag)


def _effective_proof_grade_from_verify(vtxt: str) -> bool:
    """Is the finding's EFFECTIVE (post-integrity-downgrade) best evidence
    proof-grade?

    Reads the verify file's current evidence-tag field (the leading bracketed
    token, after stripping any `(was [X], downgrade …)` audit annotation) and
    tests it against the proof-grade vocabulary. Self-contained (one source:
    the verify file the driver already rewrites on integrity downgrade), so a
    finding whose `[POC-PASS]` was demoted to `[CODE-TRACE]` reads CONFIRMED,
    not VERIFIED — restoring evidence honesty to the status label."""
    stripped = _TAG_DOWNGRADE_ANNOTATION_RE.sub(" ", vtxt or "")
    field = _field_from_markdown(
        stripped,
        ("Evidence Tag", "Preferred Tag", "Mechanical-Tag", "Evidence"),
    )
    m = re.search(r"\[([A-Za-z0-9\-]+)\]", field or "")
    if m:
        return _effective_tag_is_proof_grade(field, stripped)
    # No evidence-tag field at all: fall back to a proof-grade scan of the
    # annotation-stripped body (still honest — the residual proof tags removed).
    return _effective_tag_is_proof_grade(stripped)


def _expected_report_index_statuses(scratchpad: Path) -> dict[str, str]:
    """Fix 1: driver-compute ONE canonical verification-status token per
    finding — the single source of truth for BOTH the report_index Verification
    column and the body finding-header tag.

    Derived from (verifier verdict, EFFECTIVE best-evidence proof-grade) via the
    pure `canonical_verification_status` helper. Keyed on finding ID (same key
    space as `_expected_report_index_severities`). Emitted to `status_binding.md`
    by the driver so the Index Agent stops re-deriving the label from raw prose
    (which produced the 71-index / 12-body / 17-PoC collision)."""
    out: dict[str, str] = {}
    manifest_by_id: dict[str, dict] = {}
    try:
        from mechanical_verify import read_verdict_manifest
        for manifest_row in read_verdict_manifest(scratchpad):
            if not isinstance(manifest_row, dict):
                continue
            manifest_id = str(manifest_row.get("finding_id") or "").strip()
            if manifest_id:
                manifest_by_id[manifest_id.upper()] = manifest_row
    except Exception:
        # Legacy/malformed resumes retain the verify-file derivation.
        manifest_by_id = {}
    for row in parse_verification_queue_rows(scratchpad):
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        vf = _verify_file_for_id(scratchpad, fid)
        try:
            vtxt = _llm_norm(vf.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            vtxt = ""
        status = _verifier_status_from_text(vtxt)
        manifest_grade = _effective_proof_grade_from_manifest_row(
            manifest_by_id.get(fid.upper())
        )
        out[fid] = canonical_verification_status(
            status,
            manifest_grade if manifest_grade is not None
            else _effective_proof_grade_from_verify(vtxt),
        )
    return out


def _report_index_rows_for_severity_audit(scratchpad: Path) -> list[dict[str, str]]:
    idx = scratchpad / "report_index.md"
    if not idx.exists():
        return []
    try:
        text = _llm_norm(idx.read_text(encoding="utf-8", errors="replace"))
        text = _report_index_reportable_text(text)
        text = _report_index_assignment_text(text)
    except Exception:
        return []
    headers, rows = _parse_markdown_table(text, ["report id"])
    if not headers:
        return []
    keys = [_norm_key(h) for h in headers]
    out: list[dict[str, str]] = []
    for row in rows:
        d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
        rid = _normalize_report_id(d.get("report id", "")) or d.get("report id", "")
        if not re.fullmatch(r"[CHMLI]-\d+", rid or "", re.IGNORECASE):
            continue
        internal = (
            d.get("internal hypothesis")
            or d.get("internal hypothesis id")
            or d.get("hypothesis")
            or d.get("finding id")
            or d.get("internal id")
            or ""
        )
        trust = (
            d.get("trust adj")
            or d.get("trust adjustment")
            or d.get("severity trail")
            or d.get("sev trail")
            or d.get("adjustment")
            or d.get("reason")
            or ""
        )
        out.append({
            "report_id": rid.upper(),
            "severity": d.get("severity", ""),
            "verification": d.get("verification", ""),
            "trust_adj": trust,
            "internal": internal,
        })
    return out


def _validate_report_index_severity_provenance(scratchpad: Path) -> list[str]:
    """Reject silent severity changes in LLM-authored report_index.md."""
    expected_by_id = _expected_report_index_severities(scratchpad)
    if not expected_by_id:
        return []
    rows = _report_index_rows_for_severity_audit(scratchpad)
    if not rows:
        return []
    issues: list[str] = []
    rank = {s: i for i, s in enumerate(["Critical", "High", "Medium", "Low", "Informational"])}
    for row in rows:
        rid = row["report_id"]
        final = _severity_from_report_cell(row.get("severity", ""), rid[:1])
        tier = _severity_from_report_cell("", rid[:1])
        if final and tier and final != tier:
            issues.append(
                f"report_index severity/tier mismatch: {rid} table severity "
                f"{final} conflicts with report ID tier {tier}"
            )
            continue
        ids = [
            _normalize_finding_id(fid) or fid
            for fid in _INTERNAL_FINDING_ID_RE.findall(row.get("internal", ""))
        ]
        expected = [expected_by_id[fid] for fid in ids if fid in expected_by_id]
        if not expected:
            continue
        source = min(expected, key=lambda sev: rank.get(sev, 99))
        if final == source:
            continue
        if _report_index_adjustment_reason_present(
            row.get("trust_adj", ""),
            row.get("verification", ""),
            row.get("severity", ""),
        ):
            continue
        issues.append(
            f"report_index severity provenance: {rid} maps {', '.join(ids)} "
            f"from {source} to {final} with no Trust Adj./Severity Trail reason"
        )
    if not issues:
        return []
    sample = "; ".join(issues[:5])
    return [sample + ("; ..." if len(issues) > 5 else "")]


def _repair_report_index_severity_provenance(scratchpad: Path) -> list[dict[str, str]]:
    """Mechanically resolve severity-provenance violations without halting.

    Background: the provenance validator catches silent LLM severity changes
    in `report_index.md`. Pre-fix, retry exhaustion halted the entire audit
    over typically 1-3 misclassified rows out of 70+, wasting $30+ in
    retried opus subprocesses.

    Strategy: when a row's LLM severity is BELOW the upstream expected
    value AND the LLM left Trust Adj. empty, mark the row as
    `SEVERITY_OVERRIDE(upstream=<sev>, llm=<sev>, reason=llm-downgrade-no-judge)`.

    v2.0.7 (P1, Codex Point 2/3): the previous implementation wrote
    `UNRESOLVED(<upstream>)` here, overloading the Skeptic-Judge-reserved
    token. The authenticity gate then rejected every UNRESOLVED stamp
    that lacked a Skeptic-Judge ruling, INCLUDING the ones this function
    had just written. A prior halt traced to this driver
    self-contradiction. The fix: a distinct token `SEVERITY_OVERRIDE(...)`
    that is driver-only, backed by `_severity_override_ledger.json`, and
    accepted by the authenticity gate ONLY when the ledger contains a
    matching entry.

    Severity INFLATION (LLM put HIGHER than upstream) is NOT auto-
    corrected — that direction has different risk and stays a hard fail.

    Returns a list of dicts:
      {"report_id": "L-01", "internal": "H-44",
       "llm_severity": "Low", "upstream_severity": "Medium",
       "action": "applied SEVERITY_OVERRIDE(upstream=Medium, llm=Low, ...)"}

    The ledger artifact at `{scratchpad}/_severity_override_ledger.json`
    is the machine-readable companion. `severity_overrides.md` is
    regenerated from it as a human-readable view.
    """
    idx_path = scratchpad / "report_index.md"
    if not idx_path.exists():
        return []
    expected_by_id = _expected_report_index_severities(scratchpad)
    if not expected_by_id:
        return []
    try:
        text = idx_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    rows = _report_index_rows_for_severity_audit(scratchpad)
    if not rows:
        return []
    rank = {s: i for i, s in enumerate(
        ["Critical", "High", "Medium", "Low", "Informational"]
    )}
    repairs: list[dict[str, str]] = []
    fixed_text = text
    for row in rows:
        rid = row["report_id"]
        final = _severity_from_report_cell(row.get("severity", ""), rid[:1])
        ids = [
            _normalize_finding_id(fid) or fid
            for fid in _INTERNAL_FINDING_ID_RE.findall(row.get("internal", ""))
        ]
        expected = [expected_by_id[fid] for fid in ids if fid in expected_by_id]
        if not expected:
            continue
        source = min(expected, key=lambda sev: rank.get(sev, 99))
        if final == source:
            continue
        # Skip if the row already has a canonical reason.
        if _report_index_adjustment_reason_present(
            row.get("trust_adj", ""),
            row.get("verification", ""),
            row.get("severity", ""),
        ):
            continue
        # Only auto-repair DOWNGRADES (LLM put lower than upstream).
        # Inflation is risky and stays a hard fail.
        if rank.get(final, 99) <= rank.get(source, 99):
            continue
        # Locate the row line and patch the Trust Adj. cell.
        # Master Finding Index format:
        #   | Report ID | Title | Severity | Location | Verification | Trust Adj. | Internal |
        # We rewrite the Trust Adj. cell from `-` (or empty) to
        # `UNRESOLVED(<source>)`.
        rid_escaped = re.escape(rid)
        line_pat = re.compile(
            rf"^(\|\s*{rid_escaped}\s*\|.+?\|)([^|]*)(\|[^|]*\|\s*$)",
            re.MULTILINE,
        )
        m = line_pat.search(fixed_text)
        if not m:
            # Try a more permissive match: row line for this Report ID.
            simple_pat = re.compile(
                rf"^(\|\s*{rid_escaped}\s*\|.*)$", re.MULTILINE
            )
            sm = simple_pat.search(fixed_text)
            if not sm:
                repairs.append({
                    "report_id": rid,
                    "internal": ", ".join(ids),
                    "llm_severity": final or "(unknown)",
                    "upstream_severity": source,
                    "action": "could not locate row to patch — skipped",
                })
                continue
            # Permissive path: replace `| - |` cell near end with
            # `| SEVERITY_OVERRIDE(...) |`. Conservative: only touch a
            # cell that is literally "-" or empty.
            # v2.0.7 (P1.1): token renamed from UNRESOLVED to
            # SEVERITY_OVERRIDE — UNRESOLVED is reserved for Skeptic-Judge.
            override_token = (
                f"SEVERITY_OVERRIDE(upstream={source}, llm={final or 'unknown'}, "
                f"reason=llm-downgrade-no-judge)"
            )
            line = sm.group(1)
            patched = re.sub(
                r"\|\s*(?:-|—|–|\s)\s*(?=\|[^|]*\|\s*$)",
                f"| {override_token} ",
                line,
                count=1,
            )
            if patched == line:
                repairs.append({
                    "report_id": rid,
                    "internal": ", ".join(ids),
                    "llm_severity": final or "(unknown)",
                    "upstream_severity": source,
                    "action": "Trust Adj. cell not empty — skipped",
                })
                continue
            fixed_text = fixed_text.replace(line, patched, 1)
            repairs.append({
                "report_id": rid,
                "internal": ", ".join(ids),
                "llm_severity": final or "(unknown)",
                "upstream_severity": source,
                "action": f"applied {override_token}",
            })
            continue
        # Strict match path: rebuild the row with new Trust Adj. cell.
        # m.group(1) = everything through Verification cell trailing `|`
        # m.group(2) = current Trust Adj. content (often `-` or empty)
        # m.group(3) = trailing `| Internal |`
        # v2.0.7 (P1.1): SEVERITY_OVERRIDE token (driver-only) replaces
        # UNRESOLVED (Skeptic-Judge-only) for severity-provenance repairs.
        override_token = (
            f"SEVERITY_OVERRIDE(upstream={source}, llm={final or 'unknown'}, "
            f"reason=llm-downgrade-no-judge)"
        )
        new_line = (
            m.group(1)
            + f" {override_token} "
            + m.group(3)
        )
        fixed_text = fixed_text[:m.start()] + new_line + fixed_text[m.end():]
        repairs.append({
            "report_id": rid,
            "internal": ", ".join(ids),
            "llm_severity": final or "(unknown)",
            "upstream_severity": source,
            "action": f"applied {override_token}",
        })
    if fixed_text != text:
        try:
            idx_path.write_text(fixed_text, encoding="utf-8")
        except Exception as exc:
            # Failure to write is best-effort: log and let the validator
            # re-fail on this artifact (visible halt, not silent corruption).
            return [{
                "report_id": "*",
                "internal": "(write error)",
                "llm_severity": "",
                "upstream_severity": "",
                "action": f"could not write patched report_index.md: {exc}",
            }]
    # v2.0.7 (P1.2): persist the override ledger as JSON (canonical
    # machine-readable source) + markdown (derived human view). The
    # authenticity gate consults the JSON to validate each
    # SEVERITY_OVERRIDE token in report_index.md.
    if repairs:
        _write_severity_override_ledger(scratchpad, repairs)
    return repairs


def _write_severity_override_ledger(
    scratchpad: Path, repairs: list[dict[str, str]]
) -> None:
    """v2.0.7 (P1.2): write `_severity_override_ledger.json` (canonical
    machine-readable record) and `severity_overrides.md` (derived view).

    The JSON ledger is consulted by `_check_report_index_unresolved_authenticity`
    to validate each SEVERITY_OVERRIDE token in `report_index.md`.
    Schema: `plamen.severity_overrides.v1`.
    """
    if not repairs:
        return
    overrides = []
    for r in repairs:
        overrides.append({
            "report_id": r.get("report_id", ""),
            "internal_id": r.get("internal", ""),
            "llm_severity": r.get("llm_severity", ""),
            "upstream_severity": r.get("upstream_severity", ""),
            "reason": "llm-downgrade-no-judge",
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "action": r.get("action", ""),
        })
    payload = {
        "schema_version": "plamen.severity_overrides.v1",
        "row_count": len(overrides),
        "overrides": overrides,
    }
    # Atomic JSON write
    try:
        json_path = scratchpad / "_severity_override_ledger.json"
        tmp = json_path.with_suffix(json_path.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tmp.replace(json_path)
    except OSError:
        pass
    # Derived markdown view (human-readable)
    try:
        ledger = scratchpad / "severity_overrides.md"
        lines = [
            "# Severity Overrides (Auto-Correction Ledger)",
            "",
            "Rows where the LLM-written report_index.md disagreed with the",
            "upstream verifier-computed severity. The driver applied the",
            "canonical `SEVERITY_OVERRIDE(...)` Trust Adj. token so the",
            "audit could complete; these rows should be reviewed by a human",
            "before the report is delivered.",
            "",
            "The machine-readable source of truth is "
            "`_severity_override_ledger.json`. This markdown is a derived",
            "view kept for human review.",
            "",
            "| Report ID | Internal | LLM proposed | Upstream | Action |",
            "|-----------|----------|--------------|----------|--------|",
        ]
        for r in repairs:
            lines.append(
                f"| {r['report_id']} | {r['internal']} | "
                f"{r['llm_severity']} | {r['upstream_severity']} | "
                f"{r['action']} |"
            )
        ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass


def _read_severity_override_ledger(scratchpad: Path) -> list[dict]:
    """v2.0.7 (P1.4): read `_severity_override_ledger.json` for the
    authenticity gate to confirm each `SEVERITY_OVERRIDE(...)` token in
    `report_index.md` has driver backing.

    Returns the `overrides` list (or [] on absent / malformed file).
    Caller normally indexes by `report_id` for O(1) lookup.
    """
    path = scratchpad / "_severity_override_ledger.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    if payload.get("schema_version") != "plamen.severity_overrides.v1":
        return []
    overrides = payload.get("overrides")
    if not isinstance(overrides, list):
        return []
    return overrides


def _scratchpad_audit_mode(scratchpad: Path) -> str:
    cfg = scratchpad / "config.json"
    if not cfg.exists():
        return ""
    try:
        data = json.loads(cfg.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return ""
    return str(data.get("mode") or "").strip().lower()


def _load_candidate_semantic_facets_for_validator(
    scratchpad: Path,
) -> dict[str, dict[str, object]]:
    path = scratchpad / "candidate_semantic_facets.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    candidates = payload.get("candidates") if isinstance(payload, dict) else None
    if not isinstance(candidates, list):
        return {}
    out: dict[str, dict[str, object]] = {}
    for item in candidates:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("id") or "").strip().upper()
        if not fid:
            continue
        out[fid] = item
    return out


def _parse_report_coverage_rows_for_contract(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    active_headers: list[str] = []
    coverage_header_markers = (
        "candidate id", "candidate id / label", "internal finding id",
        "canonical id",
    )
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        lower = [_norm_key(c) for c in cells]
        if any(k in lower for k in coverage_header_markers) or (
            "status" in lower and any("reason" in k or "refutation" in k for k in lower)
        ):
            active_headers = lower
            continue
        if any(k in lower for k in ("status", "covered by", "field binding", "obligation id")):
            active_headers = []
            continue
        if not active_headers:
            continue
        d = {
            active_headers[i]: cells[i].strip()
            for i in range(min(len(active_headers), len(cells)))
        }
        rows.append(d)
    return rows


def _coverage_row_value(row: dict[str, str], *keys: str) -> str:
    for key in keys:
        norm = _norm_key(key)
        if norm in row:
            return row[norm]
    return ""


def _load_obligation_ledger_rows(scratchpad: Path) -> list[dict[str, Any]]:
    path = scratchpad / "obligation_ledger.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    rows = payload.get("obligations") if isinstance(payload, dict) else []
    return [r for r in rows if isinstance(r, dict)]


def _retention_claim_units(text: str) -> list[str]:
    units: list[str] = []
    for line in str(text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if "|" in s:
            units.append(s[:1800])
            continue
        for part in re.split(r"(?<=[.;:!?])\s+", s):
            part = part.strip()
            if part:
                units.append(part[:1800])
    return units


def _validate_obligation_ledger_retention(scratchpad: Path, coverage_text: str) -> list[str]:
    """Hard-gate only stable Medium+ typed obligations.

    This intentionally avoids broad prose semantics. It checks active
    machine-readable obligations and requires either exact pair preservation,
    an absorbing report ID, or an explicit refutation token in report_index /
    report_coverage.
    """
    rows = _load_obligation_ledger_rows(scratchpad)
    if not rows:
        return []
    issues: list[str] = []
    for row in rows:
        if str(row.get("status") or "").lower() != "active":
            continue
        sev = normalize_severity(str(row.get("severity_signal") or ""))
        if sev not in {"Critical", "High", "Medium"}:
            continue
        cls = str(row.get("class") or "")
        if cls not in {"chain_upgrade_retention"}:
            continue
        oid = str(row.get("id") or row.get("source_id") or "unknown")
        source_id = str(row.get("source_id") or "")
        relevant = "\n".join(
            unit for unit in _retention_claim_units(coverage_text)
            if (
                (oid and oid.lower() in unit.lower())
                or (source_id and source_id.lower() in unit.lower())
            )
        )
        if relevant and (
            re.search(r"\b[CHMLI]-\d{1,4}\b", relevant, re.IGNORECASE)
            or re.search(
                # Refutation / merge tokens AND non-silent deferral tokens.
                # DEFERRED and APPENDIX_ONLY are legitimate, tracked, reasoned
                # dispositions in report_coverage.md (see
                # _REPORT_COVERAGE_ACK_STATUSES). An obligation the ledger
                # explicitly carries as DEFERRED/APPENDIX_ONLY (with a reason)
                # is accounted for, not silently dropped. DROP_* statuses are
                # accepted only when accompanied by a reason on the same unit so
                # a bare DROP token cannot launder a genuinely unmentioned
                # obligation.
                r"\b(FALSE_POSITIVE|REFUTED|INFEASIBLE|NO_REACHABLE|NO_TRACE|"
                r"MERGE_INTO|MERGED|DUPLICATE OF|CONSOLIDATED INTO|"
                r"DEFERRED|APPENDIX_ONLY)\b",
                relevant,
                re.IGNORECASE,
            )
            or re.search(
                # DROP_<X> disposition followed by some reason text on the unit.
                r"\bDROP_[A-Z_]+\b.*\S",
                relevant,
                re.IGNORECASE,
            )
        ):
            continue
        # Human-readable, per-row distinct issue text: name the source_id +
        # severity + a one-line target excerpt so deduplicated obligation rows
        # never read as identical clones.
        target_excerpt = re.sub(r"\s+", " ", str(row.get("target") or "")).strip()[:160]
        issues.append(
            f"obligation retention: active {cls} {oid} "
            f"(chain {source_id or 'unknown'}, {sev}"
            + (f", \"{target_excerpt}\"" if target_excerpt else "")
            + ") not preserved by exact report coverage, absorbing report ID, "
            "explicit refutation, or a tracked deferral/appendix disposition"
        )
    return issues[:10]


def _validate_report_coverage_semantic_contract(scratchpad: Path) -> list[str]:
    """Report-index recall contract.

    Hard-fail only on low-ambiguity loss classes. Broader semantic hints are
    written to `report_semantic_retention_risks.md` for human/post-run review
    so this does not become a noisy halt source.
    """
    coverage_path = scratchpad / "report_coverage.md"
    if not coverage_path.exists():
        return []
    try:
        text = _llm_norm(coverage_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []

    mode = _scratchpad_audit_mode(scratchpad)
    facets = _load_candidate_semantic_facets_for_validator(scratchpad)
    rows = _parse_report_coverage_rows_for_contract(text)
    issues: list[str] = []
    risk_rows: list[str] = []

    for row in rows:
        raw_id = _coverage_row_value(
            row, "candidate id", "candidate id / label",
            "internal finding id", "canonical id", "finding id",
        )
        ids = [m.group(1).upper() for m in _INTERNAL_FINDING_ID_RE.finditer(raw_id)]
        if not ids:
            continue
        status = _coverage_row_value(row, "status", "disposition", "action").upper()
        reason = _coverage_row_value(
            row, "report id / refutation / reason", "reason", "notes",
            "exclusion reason", "verdict / reason",
        )
        sev = normalize_severity(
            _coverage_row_value(row, "severity", "severity signal")
        )
        candidate_facet_text = ""
        for fid in ids:
            item = facets.get(fid)
            if not item:
                continue
            f = item.get("facets") if isinstance(item, dict) else {}
            if isinstance(f, dict):
                candidate_facet_text += " " + " ".join(
                    ", ".join(str(x) for x in f.get(k, []) if x)
                    for k in ("mechanisms", "branch_conditions", "decoded_fields", "entrypoints")
                )

        combined = f"{status} {reason}".upper()
        # Fix A — structured mode-limit detection (NOT a prose substring scan
        # over merged status+reason, which is the negation-blind fragility class
        # docs/design/regex-fragility-remediation-plan.md forbids). A genuine
        # Thorough mode-limit is a DEFERRED disposition whose QUALIFIER is the
        # canonical `mode-limited` token, in one of the two renderings phase6
        # HARD RULE 3/6 mandates: the status column is `DEFERRED: mode-limited`
        # (merged), OR the reason column LEADS with `mode-limited:` (split). An
        # honest `DEFERRED` whose reason LEADS with UNRESOLVED_EVIDENCE /
        # NEEDS_VERIFICATION and only mentions `mode-limited` inside a negation
        # ("Not `mode-limited`", carried for human review) is NOT a mode-limit —
        # mode-limited is not its disposition qualifier — so it is excluded
        # structurally, with no negation-lookahead. (`status` is already
        # uppercased above; the reason lead is normalized the same way. Keying on
        # the qualifier POSITION is what distinguishes the two, since the real
        # false-positive row carries a bare `DEFERRED` status with the honest
        # disposition token living in its reason column.)
        lead_disposition = re.split(r"[:\s]", status.strip().strip("`*_ "), 1)[0].upper()
        reason_lead = re.split(r"[:\s]", reason.strip().strip("`*_ "), 1)[0].upper()
        row_mode_limited = bool(
            re.search(r"\bMODE[-_ ]?LIMITED\b", status)
        ) or reason_lead in {"MODE-LIMITED", "MODE_LIMITED", "MODELIMITED"}
        if (
            mode == "thorough"
            and sev in {"Critical", "High", "Medium"}
            and lead_disposition == "DEFERRED"
            and row_mode_limited
        ):
            # Fix B — haltless parity. A genuine Thorough mode-limit is a fact
            # about what actually ran; retrying the LLM cannot repair it, so a
            # hard-halt just burns retries and blocks a substantively-complete
            # audit (contradicting the CLAUDE.md repair-then-degrade contract).
            # Degrade to a flagged human-review row instead. Append
            # UNCONDITIONALLY (mirroring the obligation-ledger retention below) —
            # NOT via the facet-gated risk_rows block, because a mode-limited
            # lane has no extracted facets and a fallthrough there would drop it
            # silently.
            risk_rows.append(
                f"| {raw_id or '(unknown)'} | {sev} | THOROUGH-MODE-LIMITED | "
                f"{reason.replace('|', '/') or '(missing reason)'} | "
                "mode-limited deferral in Thorough mode "
                "(flagged for human review, not halted) |"
            )
            continue

        # Non-blocking retention risk: a Medium+ merge/drop with extracted
        # facets but no target report ID or concrete refutation vocabulary.
        if (
            sev in {"Critical", "High", "Medium"}
            and candidate_facet_text.strip()
            and re.search(r"\b(MERGED|MERGE_INTO|DUPLICATE|APPENDIX_ONLY|DROP_|DEFERRED)\b", combined)
            and not re.search(r"\b[CHMLI]-\d{1,3}\b", reason, re.IGNORECASE)
            and not re.search(
                r"\b(FALSE_POSITIVE|REFUTED|INFEASIBLE|NO_REACHABLE|NO_TRACE|"
                r"INSUFFICIENT|UNRESOLVED|CONTESTED|DUPLICATE OF|MERGE_INTO)\b",
                combined,
                re.IGNORECASE,
            )
        ):
            risk_rows.append(
                f"| {raw_id or '(unknown)'} | {sev} | {status or '(none)'} | "
                f"{reason.replace('|', '/') or '(missing reason)'} | "
                f"{candidate_facet_text.replace('|', '/').strip()} |"
            )

    combined_report_text = text
    idx_path = scratchpad / "report_index.md"
    if idx_path.exists():
        try:
            combined_report_text += "\n" + idx_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Obligation-ledger retention is a recall/coverage-completeness check that
    # depends on prose preservation of typed obligations. It must NOT discard a
    # finished audit: per the v2.8.0 gate audit philosophy, prose-dependent
    # recall gates degrade to a flagged human-review artifact rather than a hard
    # halt. A still-unaccounted obligation is appended to
    # report_semantic_retention_risks.md (so it is never silently dropped) but
    # is NOT added to the hard-fail set returned to the report_index driver
    # gate. The silent-drop protection is preserved: the obligation remains
    # visible for human review.
    obligation_issues = _validate_obligation_ledger_retention(
        scratchpad, combined_report_text
    )
    for msg in obligation_issues:
        risk_rows.append(
            f"| (obligation) | Medium+ | UNACCOUNTED-OBLIGATION | "
            f"{msg.replace('|', '/')} | obligation_ledger.json |"
        )

    if risk_rows:
        try:
            (scratchpad / "report_semantic_retention_risks.md").write_text(
                "# Report Semantic Retention Risks\n\n"
                "Non-blocking retention telemetry (human review). Rows below "
                "have Medium+ semantic facets or typed obligations with a "
                "non-body disposition whose reason does not name an absorbing "
                "report ID, a concrete refutation token, or a tracked "
                "deferral/appendix disposition. These are flagged, not "
                "silently dropped, and do NOT halt the pipeline.\n\n"
                "| Candidate | Severity | Status | Reason | Extracted Facets |\n"
                "|-----------|----------|--------|--------|------------------|\n"
                + "\n".join(risk_rows)
                + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass

    # This contract is now fully haltless (repair-then-degrade, per CLAUDE.md):
    # both retention classes it detects — Thorough mode-limited Medium+ deferrals
    # (Fix B, above) and unaccounted obligations — are written to
    # report_semantic_retention_risks.md as flagged human-review rows, never
    # added to the returned hard-fail `issues` list. `issues` therefore stays
    # empty; it is retained as the return type for the report_index driver gate,
    # which now finds no blocking coverage issue from this check and proceeds.
    return issues[:10]


def _validate_report_coverage_accounting(scratchpad: Path) -> list[str]:
    """Fail report_index when any raw candidate ID is left unaccounted.

    `report_coverage.md` is the mechanical receipt that maps every raw
    candidate ID to one of: promoted, excluded, or consolidated. An
    `UNACCOUNTED` disposition means the report index silently lost a candidate
    after verification/indexing, so downstream report writers must not proceed.
    """
    coverage_path = scratchpad / "report_coverage.md"
    if not coverage_path.exists():
        return ["report_index: missing report_coverage.md accounting ledger"]
    try:
        text = coverage_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [f"report_index: cannot read report_coverage.md: {exc}"]

    unaccounted: list[tuple[str, str]] = []
    in_ledger = False
    disposition_idx: int | None = None
    source_idx = 0
    candidate_idx = 1
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"(?i)^##\s+(?:Raw\s+)?(?:Candidate|Coverage|Promotion)\s+Ledger\b", stripped):
            in_ledger = True
            disposition_idx = None
            continue
        if in_ledger and re.match(r"^##\s+", stripped):
            break
        if not in_ledger or not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3:
            continue
        if set(cells[0]) <= {"-"}:
            continue
        lower_cells = [c.lower() for c in cells]
        _disp_idx = next(
            (i for i, c in enumerate(lower_cells)
             if "status" in c or "disposition" in c),
            None,
        )
        if _disp_idx is not None:
            source_idx = 0
            candidate_idx = 1
            disposition_idx = _disp_idx
            continue
        idx = disposition_idx if disposition_idx is not None else 2
        if idx >= len(cells):
            continue
        if cells[idx].upper() == "UNACCOUNTED":
            source = cells[source_idx] if source_idx < len(cells) else cells[0]
            candidate = cells[candidate_idx] if candidate_idx < len(cells) else "n/a"
            unaccounted.append((candidate, source))

    if not unaccounted:
        return _validate_report_coverage_semantic_contract(scratchpad)
    sample = ", ".join(
        f"{fid} from {source}" for fid, source in unaccounted[:8]
    )
    more = f" (+{len(unaccounted) - 8} more)" if len(unaccounted) > 8 else ""
    issues = [
        "report_index: raw candidate ledger has "
        f"{len(unaccounted)} UNACCOUNTED candidate(s): {sample}{more}"
    ]
    issues.extend(_validate_report_coverage_semantic_contract(scratchpad))
    return issues


def _clear_stale_degraded_sentinels(scratchpad: Path) -> list[str]:
    """Checkpoint-aware sentinel cleanup. Returns cleared paths only.

    Sentinels whose phase still appears in `checkpoint.degraded` are
    PRESERVED so the operator sees the prior halt reason on resume.
    Stale (phase completed) and orphan (no checkpoint mention) sentinels
    are removed.
    """
    cleared: list[str] = []
    if not scratchpad.exists():
        return cleared
    checkpoint = Checkpoint.load(scratchpad)
    degraded_phases = set(checkpoint.degraded or [])
    seen: set[Path] = set()
    for pattern in _DEGRADED_SENTINEL_GLOBS:
        for p in scratchpad.glob(pattern):
            if p in seen:
                continue
            seen.add(p)
            phase_name = _phase_name_from_sentinel(p.name)
            if phase_name in degraded_phases:
                # Live signal — preserve so operator can read it.
                continue
            try:
                p.unlink()
                cleared.append(str(p.name))
            except Exception as e:
                log.warning(f"failed to clear stale sentinel {p}: {e}")
    return cleared


def _validate_crossbatch_full_coverage(scratchpad: Path) -> list[str]:
    """E3: crossbatch must list every verify finding ID.

    Reads `cross_batch_consistency.md` and confirms every existing verify file
    is referenced. If the file is missing OR partial, return issues. Soft pass
    only when there are zero verify files (vacuous).
    """
    cb = scratchpad / "cross_batch_consistency.md"
    if not cb.exists():
        return []
    try:
        cb_text = cb.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    verify_ids = {fid for fid, _filename in _crossbatch_expected_rows(scratchpad)}
    if not verify_ids:
        # Phase E14 guardrail: empty expected set IS the only soft-pass
        # branch. An "Overall: PASS" affirmation alone never substitutes
        # for ID coverage when verify files exist on disk. (Old failure
        # mode "checked 41 of 203 but said PASS" closed.)
        return []
    # Phase E11 follow-up #2: robust ID extraction from crossbatch text
    # (handles ranges, markdown links, brackets, comma lists). Falls back
    # to substring search if a verify ID has an unusual prefix the
    # extractor doesn't classify as a finding ID.
    cb_ids = _extract_finding_ids_from_text(cb_text)
    missing = [
        fid for fid in sorted(verify_ids)
        if fid not in cb_ids and fid not in cb_text
    ]
    if not missing:
        return []
    sample = ", ".join(missing[:5])
    return [
        f"crossbatch coverage: {len(missing)}/{len(verify_ids)} verify file(s) "
        f"absent from cross_batch_consistency.md — sample: {sample}"
    ]


def _validate_skeptic_full_ch_coverage(scratchpad: Path) -> list[str]:
    """E3: skeptic must cover every Critical/High reportable verify file.

    Reads verify files, filters to CONFIRMED + (Critical|High), and confirms
    each ID appears in both aggregate skeptic artifacts.
    """
    ch_ids: list[str] = list(dict.fromkeys(_skeptic_manifest_ids(scratchpad)))
    if not ch_ids:
        skeptic_files = list(scratchpad.glob("skeptic_*.md"))
        if not skeptic_files:
            # Skeptic is Thorough-only; absence is allowed when phase did not run.
            return []
        for p in scratchpad.glob("verify_*.md"):
            stem = p.stem
            if stem in ("verify_core", "verify_queue", "verify_aggregate"):
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            status = _verifier_status_from_text(txt)
            if not _is_reportable_verdict(status):
                continue
            sev = _severity_name_from_text(txt, {})
            if sev not in ("Critical", "High"):
                continue
            # Recover finding id from filename.
            if stem.startswith("verify_F-"):
                fid = stem[len("verify_F-"):]
            elif stem.startswith("verify_F_"):
                fid = stem[len("verify_F_"):]
            else:
                fid = stem[len("verify_"):]
            ch_ids.append(fid.strip("[]"))
    if not ch_ids:
        # Phase E14 guardrail: empty expected C/H set is the only
        # soft-pass branch. AGREE phrase alone is not enough when C/H
        # findings exist on disk.
        return []
    issues: list[str] = []
    for name in ("skeptic_findings.md", "skeptic_judge_decisions.md"):
        p = scratchpad / name
        if not p.exists():
            issues.append(f"{name} missing for {len(ch_ids)} Critical/High finding(s)")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        file_ids = _extract_finding_ids_from_text(text)
        file_missing = [fid for fid in ch_ids if fid not in file_ids and fid not in text]
        if file_missing:
            sample = ", ".join(file_missing[:5])
            issues.append(
                f"{name} missing {len(file_missing)}/{len(ch_ids)} Critical/High "
                f"finding(s) — sample: {sample}"
            )
    if not issues:
        return []
    return ["skeptic coverage: " + "; ".join(issues)]


def _validate_assemble_not_degraded(scratchpad: Path) -> list[str]:
    """E4: a `report_assemble.degraded` sentinel must halt the pipeline.

    The driver previously emitted the sentinel and continued; the report then
    shipped with stubs / FP leakage / missing severity sections. This gate
    promotes the sentinel into a hard halt so the user sees the failure
    instead of a degraded-but-shipped report.
    """
    sentinel = scratchpad / "report_assemble.degraded"
    if not sentinel.exists():
        return []
    try:
        body = sentinel.read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        body = ""
    msg = "report_assemble: degraded sentinel present — halt instead of ship"
    if body:
        msg += f"; reasons: {body[:300]}"
    return [msg]


def _validate_verify_evidence_tags(scratchpad: Path, *, min_bytes: int = 100) -> list[str]:
    """E6: each verify file must carry a Preferred Tag / Evidence Tag.

    Missing tag is a schema failure. Per-shard gates may have allowed the
    file through with size >= 100B but the substance gate must catch a
    tagless body before report_index reads it.
    """
    schema_issue = _verification_queue_schema_issue(scratchpad)
    if schema_issue:
        return [schema_issue]
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []
    missing: list[str] = []
    for r in rows:
        fid = (r.get("finding id") or "").strip()
        if not fid:
            continue
        if not _verify_file_present_for_id(scratchpad, fid, min_bytes=min_bytes):
            continue
        # Find the actual file.
        for name in (
            f"verify_{fid}.md",
            f"verify_F-{fid}.md",
            f"verify_F_{fid}.md",
            f"verify_[{fid}].md",
        ):
            p = scratchpad / name
            if p.exists():
                try:
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    txt = ""
                tag = (
                    _field_from_markdown(
                        txt,
                        ("Preferred Tag", "Preferred Verification",
                         "Preferred Evidence", "Evidence Tag", "Evidence Tags",
                         "Evidence"),
                    )
                    or ""
                ).strip()
                if not tag:
                    missing.append(fid)
                break
    if not missing:
        return []
    sample = ", ".join(missing[:8])
    return [
        f"verify evidence tags: {len(missing)} verify file(s) missing "
        f"Preferred/Evidence Tag — sample: {sample}"
    ]


def _validate_inventory_structure(scratchpad: Path) -> list[str]:
    inv_path = scratchpad / "findings_inventory.md"
    if not inv_path.exists():
        return ["findings_inventory.md missing"]
    try:
        text = inv_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["findings_inventory.md unreadable"]

    issues: list[str] = []
    blocks = _inventory_blocks(text)
    block_count = len(blocks)

    claimed_total = None
    m = _TOTAL_FINDINGS_RE.search(text)
    if m:
        try:
            claimed_total = int(m.group(1))
        except Exception:
            claimed_total = None

    if claimed_total and block_count < max(5, int(claimed_total * 0.70)):
        issues.append(
            f"inventory structure: file claims {claimed_total} findings but only "
            f"{block_count} parseable finding blocks were written"
        )

    if not blocks:
        if claimed_total:
            issues.append("inventory structure: no parseable finding blocks found")
        return issues

    def _has_field(block: str, *labels: str) -> bool:
        """True iff `block` carries any of `labels` as a real field.

        Site 1 (regex-fragility plan): routed through the shared
        `_field_anywhere(table_ok=True)` extractor so a UNIFORM-TABULAR
        inventory (`| Severity | High |`, header/row tables) — which the old
        `label*:` colon-only regex could not see — is recognized as having the
        field. Previously a fully-valid tabular inventory tripped the >40%
        missing-fields HARD issue and HALTED the run.

        Strict superset: every colon-form the old regex accepted
        (`Severity:`, `**Severity**:`) is a kv/bold shape `_field_anywhere`
        also accepts, plus `=`, backtick, bullet, and the table forms. This is
        a presence check, so a non-empty harvested VALUE means the field is
        present. Detection-only: this helper only relaxes a gate (more fields
        seen -> fewer false HALTs), never tightens it.
        """
        value, _shape = _field_anywhere(block, list(labels), table_ok=True)
        return bool(value)

    missing_fields = 0
    # Preserve the legacy smoke/resume tolerance for titleless stub findings
    # such as `### Finding F-01`; those are enough to route severity-only
    # empty-verify paths but are not the canonical inventory body contract.
    # Detailed titled blocks, including `## Finding [INV-001]: title`, still
    # get the required-field check through the shared inventory parser.
    field_checked_blocks = [item for item in blocks if item.get("title")]
    for item in field_checked_blocks:
        block = item.get("block", "")
        has_source_ids = _has_field(block, "Source IDs", "Source ID", "Sources", "Agent Sources")
        has_severity = _has_field(block, "Severity", "Risk Level", "Level")
        has_location = _has_field(block, "Location", "Code Location", "File", "Where")
        has_tag = _has_field(
            block, "Preferred Tag", "Evidence Tags", "Evidence Tag",
            "Preferred Verification", "Evidence", "Verification Method",
        )
        if not (has_source_ids and has_severity and has_location and has_tag):
            missing_fields += 1

    # Site 1 L1 authoritative source (regex-fragility plan §4 L1): if the
    # inventory phase emitted a `<!-- PLAMEN_SIGNALS: {...} -->` block asserting
    # field-presence completeness, that deterministic machine signal OVERRIDES
    # the prose-derived `missing_fields` count. JSON-in-HTML-comment has no
    # shape variance, so when the producer affirms completeness we trust it over
    # any prose extraction (the L1>L2 precedence the plan mandates). Recognized
    # keys (any one present-and-true suffices):
    #   "inventory_fields_complete": true
    #   "inventory_missing_fields": 0
    signals = parse_plamen_signals(text)
    l1_complete = False
    if signals:
        if signals.get("inventory_fields_complete") is True:
            l1_complete = True
        mf = signals.get("inventory_missing_fields")
        if isinstance(mf, (int, float)) and int(mf) == 0:
            l1_complete = True

    checked_count = len(field_checked_blocks)
    if l1_complete:
        # L1 says complete: never hard-fail on the prose count. Surface a soft
        # note if prose disagrees so a producer bug is still visible.
        if checked_count and missing_fields > max(2, int(checked_count * 0.40)):
            log.warning(
                "[_validate_inventory_structure] PLAMEN_SIGNALS asserts inventory "
                "fields complete, but prose extraction flagged %d/%d blocks "
                "missing fields — trusting L1 signal (no HALT)",
                missing_fields, checked_count,
            )
    elif checked_count and missing_fields > max(2, int(checked_count * 0.40)):
        issues.append(
            f"inventory structure: {missing_fields}/{checked_count} finding blocks "
            "are missing one or more required fields (Source IDs / Severity / "
            "Location / Preferred Tag)"
        )
    elif checked_count and missing_fields > max(1, int(checked_count * 0.20)):
        log.warning(
            "[_validate_inventory_structure] %d/%d finding blocks missing "
            "required fields — LLM prose format check (soft)",
            missing_fields, checked_count,
        )

    return issues


# FIX (#3): type-only-file detection for the SC subsystem-coverage gate.
# A file with no executable body (pure struct/enum/constant/type-alias/abstract
# type-holder / interface) has no logic for depth to analyze — flagging a bucket
# made entirely of such files as "uncovered" is a false positive. Detection is
# structural and generic (no protocol-specific tokens).
_EXEC_BODY_RE = re.compile(
    r"\b(?:function|constructor|modifier|receive|fallback)\b[^;{]*\{"
)
# Chain/network qualifiers used to detect cross-chain type "twins" (struct files
# that must agree across deployments or signatures replay / assets mis-route).
_CHAIN_NET_TOKENS = (
    "ethereum", "polygon", "arbitrum", "optimism", "base", "bsc", "avalanche",
    "avax", "gnosis", "mainnet", "testnet", "sepolia", "l1", "l2",
)
_TYPEHASH_TOKENS = ("typehash", "domain", "eip712", "permit", "separator")


def _resolve_indexed_path(indexed: str, project_root: str | None) -> Path | None:
    """Best-effort resolve a recon-indexed path to an on-disk file under
    project_root. Returns None when unresolvable — callers treat None as
    'has a body' (conservative: never drop a real logic file on a miss)."""
    if not project_root or not indexed:
        return None
    rel = indexed.replace("\\", "/").lstrip("./")
    root = Path(project_root)
    cand = root / rel
    try:
        if cand.exists():
            return cand
        p = Path(indexed)
        if p.is_absolute() and p.exists():
            return p
        # Last resort (only reached on a would-be-flagged bucket — rare path):
        # match by basename under project_root.
        base = rel.split("/")[-1]
        for m in root.rglob(base):
            return m
    except Exception:
        return None
    return None


def _sol_has_executable_body(path_abs: Path | None) -> bool:
    """True if the .sol file defines at least one function/constructor/modifier/
    receive/fallback WITH a body. Pure type/interface/constant files return
    False. Unresolved path or read failure → True (conservative: keep required)."""
    if path_abs is None:
        return True
    try:
        txt = path_abs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return True
    return bool(_EXEC_BODY_RE.search(txt))


def _strip_chain_tokens(name: str) -> str:
    out = name
    for t in _CHAIN_NET_TOKENS:
        out = out.replace(t, "")
    return out


def _cross_type_consistency_leads(files: list[str]) -> list[str]:
    """Emit `[CONSISTENCY-CHECK: A vs B]` leads for paired type files a single
    logic flow may never compare: (a) cross-chain/network type twins (identical
    base name modulo a chain token); (b) a struct file paired with its
    typehash/domain constant sharing a stem. Generic structural matching only;
    bounded (small type-only buckets, rare path); capped output."""
    leads: list[str] = []
    bases = [f.replace("\\", "/").split("/")[-1].lower() for f in files]
    n = len(files)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = bases[i], bases[j]
            if a == b:
                continue
            twin = (
                _strip_chain_tokens(a) == _strip_chain_tokens(b)
                and any(t in a or t in b for t in _CHAIN_NET_TOKENS)
            )
            ha = any(t in a for t in _TYPEHASH_TOKENS)
            hb = any(t in b for t in _TYPEHASH_TOKENS)
            stem_a = re.sub(r"\.(sol|move|rs)$", "", a)
            stem_b = re.sub(r"\.(sol|move|rs)$", "", b)
            pair = (ha != hb) and (stem_a[:5] == stem_b[:5]) and len(stem_a) >= 5
            if twin or pair:
                leads.append(f"[CONSISTENCY-CHECK: {files[i]} vs {files[j]}]")
                if len(leads) >= 12:
                    return leads
    return leads


def _validate_sc_subsystem_coverage(
    scratchpad: Path, mode: str, min_bucket_files: int = 4,
    scope_file: str | None = None, project_root: str | None = None,
) -> list[str]:
    """Hard SC coverage gate from contract inventory / Slither flat files.

    This is the SC equivalent of the L1 subsystem coverage guard: if a
    substantial contract/program bucket is indexed by recon but never cited by
    breadth/depth/scanner/verify outputs and not explicitly ACKNOWLEDGED, the
    pipeline must not treat the run as coverage-complete.

    When the wizard supplied a `scope_file` listing the explicit audit-scope
    files, the required-coverage universe is narrowed to those files only —
    a properly-scoped audit must never be failed for not covering out-of-scope
    vendored libraries (e.g. uniswap math libs). This mirrors how
    `_validate_recon_coverage` consults the scope file. The filter is applied
    to the REQUIRED (`prod`) set, never the cited set, so out-of-scope files
    are simply not demanded. `_path_in_scope_file` is permissive when scope is
    empty, so the no-scope-file behaviour is unchanged.
    """
    if mode != "thorough":
        return []
    indexed = {
        p for p in _collect_scip_indexed_paths(scratchpad)
        if p.endswith((".sol", ".move", ".rs"))
    }
    if not indexed:
        return []

    test_markers = (
        "/test/", "/tests/", "/script/", "/scripts/", "/mock", "/mocks/",
        "/fixture/", "/fixtures/", ".t.sol", ".s.sol", "_test.rs",
        "/interface/", "/interfaces/",
    )
    # Also match paths that START with these non-auditable prefixes
    # (indexed paths may lack a leading slash).
    non_auditable_prefixes = (
        "test/", "tests/", "script/", "scripts/", "mock/", "mocks/",
        "fixture/", "fixtures/", "interface/", "interfaces/",
    )
    prod = {
        p for p in indexed
        if not any(t in p.lower() for t in test_markers)
        and not any(p.lower().startswith(pfx) for pfx in non_auditable_prefixes)
    }
    # Narrow the required-coverage universe to in-scope files only. Out-of-scope
    # vendored libraries must never be demanded by this gate. Empty scope means
    # no scope file → require everything (behaviour unchanged).
    scope_names = _load_scope_file_paths(scope_file)
    if scope_names:
        prod = {p for p in prod if _path_in_scope_file(p, scope_names)}
    if not prod:
        return []

    cited = _collect_cited_paths(scratchpad)
    ack_paths: set[str] = set()
    for name in ("scope_leftover.md", "subsystem_coverage_gap.md", "sc_subsystem_coverage.md"):
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for line in text.splitlines():
            if "ACKNOWLEDGED" not in line.upper():
                continue
            for m in re.finditer(
                r"\b([A-Za-z0-9_./\\-]+\.(?:sol|move|rs))\b", line
            ):
                ack_paths.add(m.group(1).replace("\\", "/").lstrip("./"))
            for m in re.finditer(
                r"\b([A-Za-z0-9_][A-Za-z0-9_./\\-]*[A-Za-z0-9_])\b", line
            ):
                seg = m.group(1).replace("\\", "/").lstrip("./")
                if "/" in seg and not seg.endswith((".sol", ".move", ".rs")):
                    ack_paths.add(seg)

    def covered(path: str) -> bool:
        if path in cited or path in ack_paths:
            return True
        for c in cited:
            c = c.replace("\\", "/").lstrip("./")
            if path.endswith("/" + c) or c.endswith("/" + path):
                return True
        for a in ack_paths:
            if path.endswith("/" + a) or a.endswith("/" + path):
                return True
            if path.startswith(a + "/") or ("/" + a + "/") in path:
                return True
        return False

    buckets: dict[str, set[str]] = {}
    for p in prod:
        buckets.setdefault(_sc_contract_module_key(p), set()).add(p)

    uncovered: list[str] = []
    uncovered_details: dict[str, list[str]] = {}
    type_only_accounted: list[str] = []   # [SCOPE-TYPE-ONLY: ...] rows
    consistency_leads: list[str] = []     # [CONSISTENCY-CHECK: A vs B] rows
    for key, files in sorted(buckets.items()):
        if len(files) < min_bucket_files:
            continue
        if not any(covered(f) for f in files):
            file_list = sorted(files)
            # FIX (#3): a bucket whose .sol files ALL lack an executable body is
            # non-auditable-for-depth (same rationale as the interface
            # exclusion) — there is no logic to cite, so it must not be a
            # required-coverage FAIL. Bounded: the file reads run only for
            # buckets that would OTHERWISE be flagged (rare path). Conservative:
            # an unresolved/unreadable file is treated as having a body, so a
            # genuine logic file is never dropped from coverage. .move/.rs
            # buckets fall through to the original behaviour (type-only Move/Rust
            # modules are rarer — injectable-first, extend only if a run shows
            # the same FP).
            all_sol = bool(file_list) and all(
                f.lower().endswith(".sol") for f in file_list
            )
            if all_sol and all(
                not _sol_has_executable_body(
                    _resolve_indexed_path(f, project_root)
                )
                for f in file_list
            ):
                # No silent drop: account each file + route paired type files to
                # the consistency lane. A type-rooted bug shows at the
                # consumption site (in depth scope) or via cross-type comparison
                # — never as a missing standalone depth bucket here.
                for f in file_list:
                    type_only_accounted.append(
                        f"[SCOPE-TYPE-ONLY: {f} — no executable body; "
                        "covered-by-consumption]"
                    )
                consistency_leads.extend(
                    _cross_type_consistency_leads(file_list)
                )
                continue
            uncovered.append(f"{key} ({len(file_list)} files)")
            uncovered_details[key] = file_list

    out = scratchpad / "sc_subsystem_coverage.md"
    lines = [
        "# SC Subsystem Coverage",
        "",
        f"**Indexed prod files**: {len(prod)}",
        f"**Buckets**: {len(buckets)}",
        f"**Uncovered substantial buckets**: {len(uncovered)}",
        "",
    ]
    if uncovered:
        lines += ["| Bucket | Missing Files |", "|--------|---------------|"]
        for key, files in uncovered_details.items():
            lines.append(f"| {key} ({len(files)} files) | {', '.join(files)} |")
    else:
        lines += ["All substantial SC source buckets have at least one citation or ACKNOWLEDGED row."]
    if type_only_accounted:
        lines += [
            "",
            "## Type-only buckets (excluded from required coverage — "
            "no executable body; covered at consumption sites)",
            "",
        ]
        lines += type_only_accounted
    if consistency_leads:
        lines += [
            "",
            "## Cross-type consistency leads "
            "(route to SEMANTIC_CONSISTENCY_AUDIT / CROSS_CHAIN_MESSAGE_INTEGRITY)",
            "",
        ]
        lines += consistency_leads
    try:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass
    # Route paired type files to the consistency lane by raising a flag the
    # SEMANTIC_CONSISTENCY_AUDIT niche reads — converts the exclusion from
    # "ignore" to "compare these explicitly". Append-only, dedup'd.
    if consistency_leads:
        try:
            dp = scratchpad / "detected_patterns.md"
            existing = dp.read_text(encoding="utf-8", errors="replace") if dp.exists() else ""
            if "CROSS_TYPE_CONSISTENCY" not in existing:
                with dp.open("a", encoding="utf-8") as fh:
                    if existing and not existing.endswith("\n"):
                        fh.write("\n")
                    fh.write(
                        "\nCROSS_TYPE_CONSISTENCY=true  "
                        "# type-only files paired across chain/network or "
                        "struct<->typehash; compare for divergence\n"
                    )
        except Exception:
            pass

    if uncovered:
        exact_files = [
            f for key in sorted(uncovered_details) for f in uncovered_details[key]
        ]
        sample = ", ".join(exact_files[:24])
        suffix = " ..." if len(exact_files) > 24 else ""
        return [
            "SC subsystem coverage missed substantial buckets: "
            + ", ".join(uncovered[:8])
            + f"; missing files: {sample}{suffix}"
        ]
    if not cited:
        return ["SC subsystem coverage: zero source citations across finding artifacts"]
    return []


# Test / fuzz / verification directory markers. A path segment is out-of-scope
# when ANY of its delimiter-split sub-words is one of these — so `.medusa-tests`
# (-> {medusa, tests}), `fuzz-tests`, `invariant-tests`, `verify_helpers` are all
# excluded, while a one-word segment like `latest` or `attestation` is NOT. This
# mirrors the dirs the recon prompt already tells recon to skip; the plain
# exact-segment `skip_tokens` check missed dotted/hyphenated variants.
_RECON_TEST_FUZZ_MARKERS = frozenset({
    "test", "tests", "testing",
    "fuzz", "fuzzing", "medusa", "echidna", "halmos",
    "invariant", "invariants", "symbolic",
    "verification", "verify",
    "certora", "coverage", "mock", "mocks", "fixture", "fixtures",
})


def _recon_segment_is_test_fuzz(seg: str) -> bool:
    """True when a path segment names a test/fuzz/verification dir, including
    dotted/hyphenated variants the exact-segment skip list misses
    (`.medusa-tests`, `fuzz-tests`). Split on . _ - and match delimited
    sub-words only, so `latest`/`attestation` (single words) are NOT excluded."""
    words = [w for w in re.split(r"[._-]+", (seg or "").lower()) if w]
    return any(w in _RECON_TEST_FUZZ_MARKERS for w in words)


def _validate_recon_coverage(scratchpad: Path, project_root: str,
                             language: str,
                             subsystem_scope: str | None = None,
                             backend: str = "claude",
                             scope_file: str | None = None) -> list[str]:
    """Post-recon: assert every substantial module is cited.

    The failure mode this catches (Heimdallr arxiv 2601.17833, named as a
    core LLM-audit failure): recon produces an `attack_surface.md` that
    feels thorough but only covers the most obvious entry points; whole
    subsystems go uncited; downstream breadth/depth agents analyze only
    what recon flagged; the report silently omits the uncovered subsystems.

    Signal: group in-scope source files by 2-segment module key (see
    `_module_key`). For each module with >=10 files, require at least one
    file from that module to appear as a full relative-path citation
    somewhere in recon artifacts. Modules explicitly ACKNOWLEDGED in
    `scope_leftover.md` are exempt. Modules with <10 files are exempt
    (recon can legitimately skip small helpers). Path matching is by
    suffix-match on relative paths, never by basename — duplicate
    basenames across modules no longer false-cover each other.
    """
    lang_key = (language or "").lower()
    exts = {
        "evm": [".sol"], "solana": [".rs"], "soroban": [".rs"],
        "aptos": [".move"], "sui": [".move"],
        "go": [".go"], "rust": [".rs"],
        "l1": [".go", ".rs"], "mixed": [".go", ".rs"],
    }.get(lang_key, [".sol", ".rs", ".move", ".go"])
    # Build-system / IDE noise + universally out-of-scope audit conventions.
    # Without the audit-convention tokens (interfaces, test, mock, script,
    # fixture) every SC repo with external-protocol interface stubs or a
    # tests directory false-tripped this gate — even though the parallel
    # _validate_sc_subsystem_coverage already excludes the same patterns.
    # Comparison is case-insensitive: matches `Test/`, `Tests/`, `Mocks/`
    # etc. that don't follow the lowercase convention.
    skip_tokens = (
        # Build / vendoring / IDE
        "vendor", "target", "node_modules", ".git", "out",
        "build", "dist", ".idea", ".vscode",
        # Out-of-scope by audit convention (matches the SC subsystem
        # coverage gate's `test_markers` + `non_auditable_prefixes`)
        "interfaces", "interface",
        "mock", "mocks",
        "test", "tests",
        "script", "scripts",
        "fixture", "fixtures",
    )
    root = Path(project_root)
    scope_prefix = _normalize_subsystem_scope(subsystem_scope)
    if not root.exists():
        return []

    # v2.4.x: scope-narrowed walk. When subsystem_scope is set we only
    # need to enumerate files under the scope prefix — files outside the
    # prefix are auto-exempt by `_path_in_subsystem_scope` further down,
    # so walking them is wasted I/O on huge repos. Falls back to full
    # rglob from project root when no scope is set.
    walk_roots: list[Path] = []
    if scope_prefix:
        scope_root = root / scope_prefix
        if scope_root.exists() and scope_root.is_dir():
            walk_roots.append(scope_root)
        else:
            # Configured scope path doesn't exist on disk -> fall back to
            # full walk so the validator can still flag the situation.
            walk_roots.append(root)
    else:
        walk_roots.append(root)

    # modules: key -> set of relative paths (POSIX form)
    modules: dict[str, set[str]] = {}
    for ext in exts:
        for walk_root in walk_roots:
            for p in walk_root.rglob(f"*{ext}"):
                try:
                    rel = p.relative_to(root).as_posix()
                except Exception:
                    continue
                parts_lower = [seg.lower() for seg in rel.split("/")]
                if any(tok in parts_lower for tok in skip_tokens):
                    continue
                # Catch dotted/hyphenated test/fuzz/verification dirs that the
                # exact-segment skip list misses (`.medusa-tests`, `fuzz-tests`,
                # `invariant-tests`) — recon is explicitly told to skip these, so
                # the coverage gate must not penalize their omission.
                if any(_recon_segment_is_test_fuzz(seg) for seg in parts_lower):
                    continue
                if scope_prefix and not _path_in_subsystem_scope(rel, scope_prefix):
                    # Belt-and-suspenders: scope walk guarantees this is
                    # already true, but a broken symlink or fallback path
                    # could violate it.
                    continue
                key = _module_key(rel)
                modules.setdefault(key, set()).add(rel)

    if not modules:
        return []

    # When the wizard passed an explicit scope file, restrict the
    # universe of "must-be-cited" files to those listed in it. A
    # 200-contract repo with a 5-file scope list should not trip the
    # gate for the 195 contracts the user already declared out-of-scope.
    # `_path_in_scope_file` is permissive when `scope_names` is empty.
    scope_names = _load_scope_file_paths(scope_file)
    if scope_names:
        filtered: dict[str, set[str]] = {}
        for key, files in modules.items():
            kept = {f for f in files if _path_in_scope_file(f, scope_names)}
            if kept:
                filtered[key] = kept
        modules = filtered
        if not modules:
            # User's scope file matches nothing under the walked roots.
            # That's a configuration error worth a warning, but not a
            # blocking gate failure — recon may have other artifacts.
            return []

    recon_files = [
        "recon_summary.md", "subsystem_map.md", "attack_surface.md",
        "integration_points.md", "opengrep_hits_ranked.md",
        "file_coverage_ledger.md", "detected_patterns.md",
        "function_list.md", "state_variables.md", "contract_inventory.md",
        "threat_model.md", "trust_boundaries.md",
    ]
    # Match anything that looks like a file reference. Don't require a
    # trailing `:` or whitespace — citations sometimes appear at end of
    # line, inside backticks, or inside bullet lists.
    cite_re = re.compile(
        r"([A-Za-z0-9_][A-Za-z0-9_/.\\-]*?\.(?:sol|rs|move|go))"
    )
    cited_paths: set[str] = set()
    for name in recon_files:
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in cite_re.finditer(txt):
            raw = m.group(1).replace("\\", "/").lstrip("./")
            if raw:
                cited_paths.add(raw)

    # ACKNOWLEDGED rows in scope_leftover.md — track full file paths.
    ack_paths: set[str] = set()
    lp = scratchpad / "scope_leftover.md"
    if lp.exists():
        try:
            lt = lp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            lt = ""
        for line in lt.splitlines():
            s = line.strip()
            if not s.startswith("|") or _is_separator_row(s):
                continue
            s_up = s.upper()
            if "FILE" in s_up and ("STATUS" in s_up or "PATH" in s_up or "SCOPE" in s_up):
                continue
            parts = [x.strip() for x in s.strip("|").split("|")]
            if len(parts) >= 2 and any(p.upper().startswith("ACKNOWLEDGED") for p in parts[1:]):
                raw = parts[0].replace("\\", "/").lstrip("./")
                if raw:
                    ack_paths.add(raw)

    def _is_covered(rel_path: str) -> bool:
        # Direct match, or suffix match (citation can be abbreviated to a
        # shorter path as long as the source path ends with it).
        if rel_path in cited_paths or rel_path in ack_paths:
            return True
        for c in cited_paths:
            if rel_path.endswith("/" + c) or c.endswith("/" + rel_path):
                return True
        for a in ack_paths:
            if rel_path.startswith(a + "/") or rel_path == a:
                return True
            if rel_path.endswith("/" + a) or a.endswith("/" + rel_path):
                return True
        return False

    uncovered = []
    for mod, files in modules.items():
        if len(files) < 10:
            continue
        if not any(_is_covered(f) for f in files):
            uncovered.append(f"{mod} ({len(files)} files)")

    issues = []
    if uncovered:
        # Stable order, cap the reported list.
        uncovered.sort()
        issues.append(
            "recon missed substantial modules (no file cited; not "
            "ACKNOWLEDGED in scope_leftover): " + ", ".join(uncovered[:8])
        )
    if not cited_paths:
        if backend == "codex":
            log.warning(
                "recon emitted zero file-path citations across all artifacts "
                "(Codex backend — GPT models may cite by function/module name "
                "instead of file path; treating as soft warning)"
            )
        else:
            issues.append(
                "recon emitted zero file-path citations across all artifacts"
            )
    return issues


_RECON_PLACEHOLDER_RE = re.compile(
    r"(?:\(\s*stub\s*\)|\bstub\s+(?:artifact|only|content|"
    r"placeholder|summary|file)\b|\b(?:placeholder|tbd|todo|"
    r"llm to|fill later|deferred during enrichment)\b)",
    re.IGNORECASE,
)


def _has_live_placeholder_language(text: str) -> str | None:
    """Return the offending line if live placeholder/stub content is found.

    Returns None when no live placeholder content is detected.
    Recon summaries often include gate-status statements such as
    "No placeholder markers remain."  The old whole-file regex treated those
    negated cleanup statements as actual placeholders and forced pointless
    retries after a valid recon.  Evaluate line-by-line and ignore explicit
    absence/replacement statements while still catching real TODO/stub bodies.
    """
    for raw in _llm_norm(text).splitlines():
        line = raw.strip().lower()
        if not line or not _RECON_PLACEHOLDER_RE.search(line):
            continue
        # Negation: explicit cleanup / absence statements
        if re.search(
            r"\b(no|without|not|never|absent|removed|removes|free of|"
            r"clean of|replaces|replaced|overwrites|overwrote|enriched)\b"
            r".{0,80}\b(stub|placeholder|todo|tbd|llm to|fill later)\b",
            line,
        ):
            continue
        if re.search(
            r"\b(stub|placeholder|todo|tbd|llm to|fill later)\b"
            r".{0,80}\b(absent|removed|remain|remaining|free of|"
            r"replaced|overwritten)\b",
            line,
        ):
            continue
        # Negation: security analysis context — the target code contains
        # placeholders/stubs, the recon is describing them (not being one)
        if re.search(
            r"\b(uses?|contains?|has|implement|call|address|value|"
            r"function|contract|module|variable|parameter|argument|"
            r"code|codebase|protocol|program)\b"
            r".{0,40}\b(stub|placeholder|todo|tbd)\b",
            line,
        ):
            continue
        # Negation: code-reference context — line cites source file paths,
        # line numbers, or backticked code near the matched word, indicating
        # recon is describing target-code TODOs/stubs (not being a placeholder
        # itself).  v2.1.7: fixes false recon degradation on L1 codebases
        # where recon quotes source-code TODO comments verbatim.
        if re.search(
            r"(?:"
            # file-extension patterns (.rs: .go: .sol: .ts:)
            r"\.\w{1,4}[:`\s,)]"
            # crate / source directory paths
            r"|(?:crates|src|cmd|pkg|internal|contracts)/"
            # "at line N" / "line 146" / "L120"
            r"|(?:at\s+)?line\s+\d+\b|\bL\d+\b"
            # recon structural prefixes
            r"|code\s+path\s*:|bug\s+class\s*:"
            # backticked code within 60 chars of the matched term
            r"|`[^`]+`.{0,60}\b(?:stub|todo|tbd)\b"
            r"|\b(?:stub|todo|tbd)\b.{0,60}`[^`]+`"
            r")",
            line,
        ):
            continue
        # Negation: "the/that TODO" followed by a descriptor word —
        # recon is referencing a code-level artifact ("the TODO about
        # staked address check"), not being a placeholder itself.
        # Requires a follow-on word (about/for/in/regarding/...) to
        # distinguish "the TODO about X" from "TODO: fill later".
        # v2.7.1: fixes false recon retry on a prior L1 run where
        # trust_boundaries wrote "the TODO about staked address check".
        if re.search(
            r"\b(?:the|that|said|above|aforementioned|existing"
            r"|incomplete|missing|unimplemented|remaining|open)\s+"
            r"(?:stub|placeholder|todo|tbd)\s+"
            r"(?:about|for|in|at|from|on|regarding|concerning|related"
            r"|around|check|comment|item|note|marker|issue|task|block"
            r"|where|which|that|mentioned|listed|described|identified)\b",
            line,
        ):
            continue
        # Negation: parenthesized status annotation in table rows —
        # recon tables use "(todo)" or "(tbd)" as status markers on
        # findings/entry-points, not as placeholder content.
        # v2.7.3: fixes false recon retry on a prior L1 run's attack_surface.md
        # where table cells contained "(todo)" as issue status.
        if re.search(r"^\s*\|", raw.strip()) and re.search(
            r"\(\s*(?:todo|tbd|stub)\s*\)", line
        ):
            continue
        return line
    return None


def _validate_recon_content_structure(
    scratchpad: Path, backend: str = "claude",
) -> tuple[list[str], list[str]]:
    """Check that critical recon artifacts have required structural sections.

    Returns (hard_issues, soft_issues).
    hard_issues: design_context Operational Implications / Key Invariants,
        recon_summary byte minimum — downstream agents depend on these.
    soft_issues: heading format checks for attack_surface, recon_summary,
        build_status — format-dependent, non-blocking warnings.
    """
    hard: list[str] = []
    soft: list[str] = []
    prepass_marker = (
        "<!-- plamen-prepass v1: mechanical pre-pass output; "
        "safe to overwrite while marker is present -->"
    )
    def _read_artifact(name: str) -> tuple[str, str]:
        path = scratchpad / name
        if not path.exists():
            return "", ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        return text, _llm_norm(text).lower()

    def _mech_artifact_complete(name: str) -> bool:
        """A canonical mechanical inventory file is 'complete' when it exists,
        is no longer pre-pass-marker-stamped, and carries a substantive
        enumeration body (a real table row or per-entity line) — NOT merely
        non-empty bytes. Mirrors the placeholder-refusal logic in
        ``plamen_mechanical.strip_codex_prepass_markers``.
        """
        path = scratchpad / name
        if not path.exists():
            return False
        text, _ = _read_artifact(name)
        lines = text.splitlines()
        # (b) line 1 must not be the pre-pass overwrite marker
        if lines[:1] == [prepass_marker]:
            return False
        # body = everything after a leading marker line (none here), used to
        # reject pure placeholder content the way the codex stripper does
        body = text if lines[:1] != [prepass_marker] else "\n".join(lines[1:])
        if not body.strip() or "[LLM TO ENRICH]" in body:
            return False
        # (c) substantive enumeration: at least one markdown table data row
        # (a non-separator `| ... |` line) OR a per-entity bullet/numbered line.
        for raw in body.splitlines():
            s = raw.strip()
            if (
                s.startswith("|")
                and s.endswith("|")
                and not _is_separator_row(s)
                and any(ch.isalnum() for ch in s.strip("|"))
            ):
                return True
            if re.match(r"^(?:[-*+]\s+|\d+[.)]\s+)\S", s):
                return True
        return False

    mech_complete = all(
        _mech_artifact_complete(name)
        for name in ("function_list.md", "state_variables.md", "contract_inventory.md")
    )
    mech_soft_suffix = " (soft: mechanical inventory complete)"

    for name in (
        "design_context.md",
        "attack_surface.md",
        "state_variables.md",
        "function_list.md",
        "contract_inventory.md",
        "template_recommendations.md",
        "detected_patterns.md",
        "setter_list.md",
        "emit_list.md",
        "build_status.md",
    ):
        text, _ = _read_artifact(name)
        if text.splitlines()[:1] == [prepass_marker]:
            hard.append(
                f"{name} still has pre-pass overwrite marker; recon merge "
                "did not produce a durable canonical handoff"
            )

    # design_context.md: must contain Operational Implications (Rule 14)
    dc = scratchpad / "design_context.md"
    if dc.exists():
        txt, _ = _read_artifact("design_context.md")
        if not re.search(
            r"(?im)^#+\s+.*(?:operational\s+implications|implications.*(?:operational|design|system)"
            r"|practical\s+implications|operational\s+impact|how.*invariants.*(?:affect|impact)"
            r"|implications\b)",
            txt,
        ):
            msg = (
                "design_context.md missing '## Operational Implications' section "
                "(Rule 14 — breadth/depth agents need it)"
            )
            (soft if mech_complete else hard).append(
                msg + mech_soft_suffix if mech_complete else msg
            )
        if not re.search(
            r"(?im)^#+\s+.*(?:(?:key|protocol|core|safety|system|critical)\s+)?invariant",
            txt,
        ):
            msg = (
                "design_context.md missing Key Invariants section "
                "(downstream agents derive analysis from invariant formulas)"
            )
            (soft if mech_complete else hard).append(
                msg + mech_soft_suffix if mech_complete else msg
            )

    # attack_surface.md: heading format (non-blocking)
    atk = scratchpad / "attack_surface.md"
    if atk.exists():
        txt, _ = _read_artifact("attack_surface.md")
        if not re.search(
            r"(?im)^#+\s+.*(?:entry|external|public|attack|surface|function"
            r"|interface|method|endpoint|vector|risk|threat|accessible|exposed)",
            txt,
        ):
            soft.append(
                "attack_surface.md has no recognizable section headers "
                "(expected entry-point or attack-surface headings)"
            )

    summary = scratchpad / "recon_summary.md"
    if summary.exists():
        txt, norm = _read_artifact("recon_summary.md")
        min_summary_bytes = 200 if backend == "codex" else 512
        if summary.stat().st_size < min_summary_bytes:
            msg = (
                "recon_summary.md is too small to be a clean handoff "
                f"({summary.stat().st_size} bytes, min={min_summary_bytes})"
            )
            (soft if mech_complete else hard).append(
                msg + mech_soft_suffix if mech_complete else msg
            )
        if not re.search(
            r"(?im)^(?:#+\s+|\*\*).*(?:recon|summary|protocol|contract|component|"
            r"attack|risk|template|skill|overview|finding|scope)",
            txt,
        ):
            soft.append(
                "recon_summary.md lacks recognizable recon summary sections"
            )
    build = scratchpad / "build_status.md"
    if build.exists():
        try:
            txt = build.read_text(encoding="utf-8", errors="replace")
        except Exception:
            txt = ""
        min_build_bytes = 30 if backend == "codex" else 80
        if build.stat().st_size < min_build_bytes or not re.search(
            r"(?i)\b(?:build|compile|forge|hardhat|foundry|cargo|move|sui|"
            r"stellar|slither|aderyn|opengrep|success|failed|unavailable|"
            r"skipped|status|compiled|ok|error|passed)\b",
            txt,
        ):
            soft.append(
                "build_status.md is not a substantive build/static status "
                "artifact"
            )

    return hard, soft


def _validate_scope_leftover(
    scratchpad: Path,
    subsystem_scope: str | None = None,
    backend: str = "claude",
) -> list[str]:
    """Return uncovered large-file rows from scope_leftover.md."""
    p = scratchpad / "scope_leftover.md"
    if not p.exists():
        if backend == "codex":
            try:
                p.write_text(
                    "# Scope Leftover\n\nAll modules covered.\n",
                    encoding="utf-8",
                )
                log.info(
                    "[scope_leftover] auto-generated for Codex backend "
                    "(GPT models may not produce this Claude-convention file)"
                )
            except OSError:
                pass
            return []
        return ["scope_leftover.md missing"]
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ["scope_leftover.md unreadable"]

    issues = []
    scope_prefix = _normalize_subsystem_scope(subsystem_scope)

    # Detect column positions from header row rather than assuming fixed order.
    col_file = 0
    col_loc = 1
    col_reason = 2
    col_ack = 3
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("|") and not _is_separator_row(s):
            hdr_cells = [c.strip().lower() for c in s.strip("|").split("|")]
            if any("file" in c or "path" in c or "component" in c for c in hdr_cells):
                for idx, c in enumerate(hdr_cells):
                    if "file" in c or "path" in c or "component" in c:
                        col_file = idx
                    elif "loc" in c or "line" in c or "size" in c:
                        col_loc = idx
                    elif "reason" in c or "why" in c:
                        col_reason = idx
                    elif "ack" in c or "status" in c or "cover" in c:
                        col_ack = idx
                break

    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        parts = [x.strip() for x in s.strip("|").split("|")]
        # Skip header rows (contain column-label keywords).
        parts_lc = " ".join(parts).lower()
        if "file" in parts_lc and ("status" in parts_lc or "loc" in parts_lc or "ack" in parts_lc):
            continue
        if len(parts) < 3:
            continue
        file_name = parts[col_file] if col_file < len(parts) else ""
        loc_s = parts[col_loc] if col_loc < len(parts) else "0"
        reason = parts[col_reason] if col_reason < len(parts) else ""
        ack = parts[col_ack] if col_ack < len(parts) else ""
        if scope_prefix and not _path_in_subsystem_scope(file_name, scope_prefix):
            continue
        # v2.1.7: only extract LOC when the cell looks numeric ("420",
        # "1.8k", "500 LOC").  Previously, description text like "First
        # 420 lines read" was parsed as LOC=420 because digits were
        # extracted from natural language.  This caused IN_SCOPE_PARTIAL
        # rows (which have no LOC column) to be spuriously flagged.
        if re.match(r"^\s*[\d,.]+\s*(?:[kKmM]?\s*(?:LOC|loc|lines?)?)?\s*$", loc_s):
            try:
                loc = int(re.sub(r"[^\d]", "", loc_s) or "0")
            except Exception:
                loc = 0
        else:
            loc = 0
        ack_lc = ack.lower()
        ack_ok = (
            ack.upper().startswith("ACKNOWLEDGED:")
            or "cited" in ack_lc
            or (
                "covered" in ack_lc
                and "not covered" not in ack_lc
                and "uncovered" not in ack_lc
            )
            or "✓" in ack
            or "[x]" in ack_lc
            or "check" in ack_lc
            # v2.1.6: honor `LEFTOVER-ACK:` convention used by L1 recon.
            # Observed prior L1 run: recon correctly acknowledged
            # crates/macros/src/lib.rs as a proc-macro leftover via
            # `LEFTOVER-ACK: proc-macro / no runtime surface` but the
            # gate ignored it. Prefix-match on any ACK-family token.
            or "leftover-ack" in ack_lc
            or ack_lc.strip().startswith("ack:")
            or ack_lc.strip().startswith("ack ")
        )
        # v2.1.7: treat coverage-description language as implicit ack.
        # Scope leftover tables (especially IN_SCOPE_PARTIAL) may describe
        # analysis already performed ("full file read", "N lines read")
        # without an explicit ACK column.  When the ack column is empty
        # or missing, scan all columns for evidence the file was analyzed.
        if not ack_ok:
            all_cols_lc = " ".join(parts).lower()
            if re.search(
                r"\bfull(?:y)?\s+(?:file\s+)?read\b"
                r"|\bfully\s+analyzed\b"
                r"|\bno\s+additional\s+(?:partial\s+)?read\s+needed\b"
                r"|\b\d+\s+lines?\s+read\b"
                r"|\bfully\s+(?:covered|examined|reviewed)\b",
                all_cols_lc,
            ):
                ack_ok = True
        # v2.1.2: auto-acknowledge files under known out-of-scope library
        # directories (Foundry / npm / vendored deps). Prevents the
        # false recon degradation class where forge-std / v2-periphery / v3-core
        # tripped the gate despite being conventionally out of scope.
        if not ack_ok and _is_whitelisted_lib_path(file_name):
            ack_ok = True
        if loc > 200 and not ack_ok:
            issues.append(f"{file_name} ({loc} LOC, reason={reason})")
    return issues


# ---------------------------------------------------------------------------
# v2.4.0: PoC classification gates (post-verify, pre-report)
# ---------------------------------------------------------------------------

def _find_verify_file(scratchpad: Path, fid: str) -> Optional[Path]:
    """Find the verify_*.md file for a given finding ID."""
    def _canon_id(value: str) -> str:
        return re.sub(r"[^A-Z0-9]+", "", value.upper())

    fid = (fid or "").strip()
    if not fid:
        return None
    normalized = fid.replace(" ", "_").replace("-", "_")
    candidates = [
        scratchpad / f"verify_{fid}.md",
        scratchpad / f"verify_{normalized}.md",
        scratchpad / f"verify_F_{fid}.md",
        scratchpad / f"verify_F-{fid}.md",
    ]
    for c in candidates:
        if c.exists():
            return c

    # Do not use broad glob substring matching here: F-1 must not resolve to
    # verify_F-10.md. The fallback accepts only a unique canonical ID match.
    target = _canon_id(fid)
    matches: list[Path] = []
    for p in sorted(scratchpad.glob("verify_*.md"), key=lambda x: x.name.lower()):
        raw = p.stem[len("verify_"):]
        raw = raw.strip("[]")
        if _canon_id(raw) == target:
            matches.append(p)
    return matches[0] if len(matches) == 1 else None


_POC_SKIP_CODES_RE = (
    r"NO_BUILD_ENVIRONMENT|EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS|"
    r"DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL|PURE_SPEC_OR_DOCS_ONLY|"
    r"STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION|"
    r"CROSS_VM_ENCODING_NO_RUNTIME"
)


# Section-label detection for the PoC testability ledger. The verifier emits
# the per-finding ledger as MARKDOWN HEADINGS ("### PoC Attempt" /
# "### Execution Result") in the common case, but format drift across backends
# (Claude vs Codex) and prompt revisions also produces:
#   - bold-field forms:           **PoC Attempt** / **Execution Result**
#   - a single combined heading:  ### PoC Attempt & Execution Result
# All three are semantically a present ledger. The gate must accept any of them
# (mirroring _field_from_markdown's existing heading/bold tolerance) while still
# FAILING when there is genuinely no PoC accounting in any form. The "& combined"
# heading satisfies BOTH the attempt and execution requirements at once.
_POC_ATTEMPT_SECTION_RE = re.compile(
    r"(?im)^\s*(?:#{2,4}\s+|(?:[-*]\s*)?\*\*)\s*"
    r"PoC\s+Attempt(?:\s*(?:&|and|/|\+)\s*(?:Execution\s+Result|"
    r"PoC\s+Result|PoC\s+Execution|Result))?\b"
)
_POC_EXEC_SECTION_RE = re.compile(
    r"(?im)^\s*(?:#{2,4}\s+|(?:[-*]\s*)?\*\*)\s*"
    r"(?:Execution\s+Result|PoC\s+Result|PoC\s+Execution)\b"
)
# A single combined heading "PoC Attempt & Execution Result" provides the
# execution-section requirement too, even though the exec label is the second
# half of the same line (so _POC_EXEC_SECTION_RE's line-anchored match misses).
_POC_COMBINED_SECTION_RE = re.compile(
    r"(?im)^\s*(?:#{2,4}\s+|(?:[-*]\s*)?\*\*)\s*"
    r"PoC\s+Attempt\s*(?:&|and|/|\+)\s*"
    r"(?:Execution\s+Result|PoC\s+Result|PoC\s+Execution|Result)\b"
)


def _has_poc_ledger_sections(content: str) -> tuple[bool, bool]:
    """Detect the PoC Attempt and Execution Result ledger sections.

    Accepts markdown-heading, bold-field, and combined-heading forms. Returns
    (has_attempt_section, has_exec_section).
    """
    combined = bool(_POC_COMBINED_SECTION_RE.search(content))
    has_attempt = combined or bool(_POC_ATTEMPT_SECTION_RE.search(content))
    has_exec = combined or bool(_POC_EXEC_SECTION_RE.search(content))
    return has_attempt, has_exec


def _poc_attempted_value(content: str) -> str:
    field = _field_from_markdown(content, ("Attempted", "PoC Attempted"))
    if field:
        m = re.match(r"\s*(YES|NO)\b", field, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    m = re.search(
        r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Attempted(?:\*\*)?\s*:\s*(YES|NO)\b",
        content,
    )
    return m.group(1).upper() if m else ""


def _poc_skip_reason_value(content: str) -> str:
    field = _field_from_markdown(content, (
        "PoC Not Attempted Because",
        "Not Attempted Because",
        "PoC Skip Reason",
        "Skip Reason",
        "PoC not attempted",
    ))
    if field:
        return field
    m = re.search(
        r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?"
        r"(?:PoC\s+Not\s+Attempted\s+Because"
        r"|Not\s+Attempted\s+Because"
        r"|PoC\s+[Ss]kip(?:\s+[Rr]eason)?"
        r"|[Ss]kip\s+[Rr]eason"
        r"|PoC\s+not\s+attempted)"
        r"(?:\*\*)?\s*:\s*(.+)$",
        content,
    )
    return m.group(1).strip().strip("`") if m else ""


def _poc_skip_code(content: str) -> str:
    reason = _poc_skip_reason_value(content)
    if not reason:
        return ""
    m = re.match(r"\s*\**\s*(" + _POC_SKIP_CODES_RE + r")\b", reason, re.IGNORECASE)
    return m.group(1).upper() if m else ""


def _valid_poc_skip(
    content: str,
    poc_class: str,
    scratchpad: Optional[Path] = None,
    severity: str = "",
) -> bool:
    skip_code = _poc_skip_code(content)
    if not skip_code:
        return False
    if poc_class in {"unit", "property"} and skip_code == "STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION":
        return False
    if poc_class == "unit" and skip_code == "DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL":
        return False
    # Fix 2: severity-aware fork-PoC mandate. An
    # EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip becomes INVALID for a Medium+
    # finding ONLY when a fork PoC is actually runnable here — the egress-
    # reachability probe SUCCEEDS *and* the verifier prose names a concrete
    # deployed address to fork against. In an RPC-less environment the probe
    # returns False, so this branch never fires and the skip stays valid (the
    # finding then rides `[UNPROVEN-EXTERNAL]`). This is INERT-SAFE: it can only
    # ADD an obligation when a real fork endpoint exists, never in this env.
    if (
        skip_code == "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS"
        and scratchpad is not None
        and normalize_severity(severity) in {"Critical", "High", "Medium"}
        and _names_resolvable_deployed_address(content)
        and _egress_rpc_reachable(scratchpad)
    ):
        return False
    # Mock-feasibility blocker (THE intentional recall-safe narrowing): an
    # EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip is invalid when the verifier's
    # OWN prose says the dependency could not be mocked. The legacy rule fired
    # whenever a negation token appeared within 80 chars (DOTALL) of `mock` —
    # which crossed sentence boundaries and made the gate UNWINNABLE for valid
    # skips ("...used a Mock harness. The on-chain address does not exist."). We
    # now scope the negation to the SAME CLAUSE as the `mock` keyword via the
    # shared `_negation_governs_keyword` helper. This suppresses FEWER valid
    # skips than the old rule, so it is strictly recall-safe (it can only let
    # MORE valid skips through, never drop a finding).
    if skip_code == "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS" and re.search(
        r"\bmock\w*\b", content, re.IGNORECASE
    ) and _negation_governs_keyword(content, re.compile(r"\bmock\w*\b", re.IGNORECASE)):
        return False
    if skip_code == "CROSS_VM_ENCODING_NO_RUNTIME":
        return bool(re.search(
            r"\b(?:solana|svm|bitcoin|btc|move|aptos|sui|cosmos|ibc|"
            r"wormhole|layerzero|near|stellar|substrate|tron|"
            r"encoding|serialization|serializ\w*|wire\s*format|"
            r"calldata\s*layout|payload\s*format|message\s*format|"
            r"abi\s*layout)\b",
            content,
            re.IGNORECASE,
        ))
    return True


# ── Force-by-default PoC gate: closed taxonomy of code-grounded skip blockers ──
# ROOT CAUSE: `_poc_contract_required` keyed the mandatory-PoC decision off the
# finding's PoC CLASS (queue estimate or verifier self-declaration), and that
# class is PROVEN-UNRELIABLE — the mechanical seed `classify_poc_testability`
# defaults hard-to-classify findings to `structural`, and empirically EVERY
# sampled lazy skip (a concrete testable harm self-declared structural with NO
# real blocker) rode that default straight past the gate. The fix flips the
# default: a finding whose verify content asserts a CONCRETE material harm is
# FORCED into a testable PoC class UNLESS a real, CLOSED, code-grounded
# blocker excuses it. GENERIC vocabulary only (no protocol/contract names),
# negation-aware via the shared `_poc_kw_present` guard.

_MATERIAL_HARM_PATTERNS = (
    "drain", "drained", "draining",
    "lock", "locked", "locking", "lockout",
    "freeze", "frozen", "freezing",
    "brick", "bricked", "bricking",
    "mint", "minted", "minting",
    "steal", "stolen", "stealing",
    "insolven",
    "mis-account", "misaccount", "mis-accounted", "misaccounted",
    "privilege escalation", "escalate privilege", "escalates privilege",
    "over-withdraw", "overwithdraw", "over withdraw",
    "double-spend", "double spend",
    "lose funds", "loses funds", "losing funds", "lost funds",
    "fund loss", "funds lost", "loss of funds",
    "permanently halt", "permanently disabled", "permanently locked",
    "denial of service", "griefing",
    "unauthorized mint", "unauthorized transfer", "unrecoverable",
    "halts block production", "liveness brick", "archiv",
)


def _has_concrete_material_harm(content: str) -> bool:
    """Generic, negation-aware matcher (mirrors `_matches_external_integration_harm`):
    does the verify content assert a CONCRETE fund/state/privilege/liveness/
    accounting delta (drain / lock / mint / mis-account / brick / freeze /
    escalate / steal / insolvency / ...) per the Material Harm field mandated
    by `~/.plamen/rules/finding-output-format.md`?

    Scoped to the Material Harm / Impact field when present (the field the
    methodology mandates for exactly this assertion); falls back to the full
    body when neither field is present so an unusual ledger shape still gets
    scanned. Force-by-default direction: ambiguity (no field found) routes
    TOWARD scanning the whole body, never straight to "no harm"."""
    if not content:
        return False
    # RECALL-SAFE direction (load-bearing): this matcher gates the
    # SPEC_DOCS_NO_STATE_DELTA blocker (a skip is excused only when NO material
    # harm is asserted). UNDER-matching wrongly excuses a real finding — the
    # exact H-01 regression: the verifier's PoC-ledger phrase "No fund-drain
    # assertion ..." made the shared NEGATION-AWARE `_poc_kw_present` guard
    # suppress the many POSITIVE "drain of custodied IBT is achievable" mentions,
    # so a flagship fund-drain read as "no harm" and skipped the force floor.
    # OVER-matching only ever forces an (at worst wasted) PoC attempt and can
    # never drop a finding, so scan the FULL body with a PLAIN leading-boundary
    # keyword search (matches inflections: drain/drains/draining/drainable) and
    # do NOT apply the negation guard here.
    hay = content.lower()
    return any(
        re.search(r"\b" + re.escape(p.lower()), hay) for p in _MATERIAL_HARM_PATTERNS
    )


# FULLY_TRUSTED_DESIGN blocker: the harm actor is a FULLY-TRUSTED authority
# (governance/DAO/timelock/multisig/upgrade authority) acting WITHIN its
# granted powers, with no runtime defect a non-trusted actor could trigger —
# e.g. a PoC would only re-demonstrate that an upgrade authority can upgrade.
# A SEMI-trusted role (admin/operator/keeper/oracle/harvester/relayer/...) is
# explicitly NOT this blocker — semi-trusted-role abuse is a real, testable
# harm and must still be forced.
_FULLY_TRUSTED_AUTHORITY_ROLE_PATTERNS = (
    "governance", "dao", "timelock", "multisig", "multi-sig",
    "upgrade authority", "upgrade admin", "protocol owner",
)
_FULLY_TRUSTED_ABSENCE_OF_CONTROL_PATTERNS = (
    "no timelock", "without a timelock", "absence of timelock",
    "no m-of-n", "without m-of-n", "absence of m-of-n",
    "as designed", "works as designed", "re-demonstrates",
    "within its powers", "within powers", "acting within its authority",
)


def _has_fully_trusted_actor_blocker(content: str) -> bool:
    """FULLY_TRUSTED_DESIGN blocker: reuses the structured `[TRUSTED-ACTOR]` /
    `Trust Adj.` tagging (`_MATRIX_TRUST_FULLY_RE`) OR free-form fully-trusted-
    authority language — an explicit `fully-trusted` marker CO-LOCATED with a
    governance/DAO/timelock/multisig/upgrade-authority actor AND
    absence-of-control language (no timelock, no M-of-N, "as designed"). An
    explicit `semi-trusted` marker ALWAYS overrides to False — a semi-trusted
    role is never this blocker."""
    if not content:
        return False
    if re.search(r"\bsemi[-\s]trusted\b", content, re.IGNORECASE):
        return False
    if _MATRIX_TRUST_FULLY_RE.search(content):
        return True
    has_marker = bool(re.search(r"\bfully[-\s_]trusted\b", content, re.IGNORECASE))
    has_authority = any(
        _poc_kw_present(p, content) for p in _FULLY_TRUSTED_AUTHORITY_ROLE_PATTERNS
    )
    has_absence = any(
        _poc_kw_present(p, content) for p in _FULLY_TRUSTED_ABSENCE_OF_CONTROL_PATTERNS
    )
    return has_marker and has_authority and has_absence


# DEPLOY_OR_TX_ORDERING blocker: harm is a deploy-time / initialize-time
# ordering race (front-running the constructor/initializer), not a runtime
# defect a PoC harness can reproduce deterministically post-deployment.
_DEPLOY_FN_RE = re.compile(
    r"\b(?:initialize|__constructor|constructor|deploy(?:ment)?)\b",
    re.IGNORECASE,
)
_DEPLOY_ORDERING_RACE_RE = re.compile(
    r"\bfront[-\s]?run\w*\b"
    r"|\bgap\s+between\s+deploy(?:ment)?\b"
    r"|\b(?:tx|transaction)\s+order(?:ing)?\b"
    r"|\bdeploy(?:ment|-time)?\s+(?:front[-\s]?run|race)\b",
    re.IGNORECASE,
)


def _has_deploy_ordering_blocker(content: str) -> bool:
    """DEPLOY_OR_TX_ORDERING blocker: the cited function is
    initialize/__constructor/deploy AND the harm is an ordering race
    (front-running the deploy/initialize step, transaction ordering)."""
    if not content:
        return False
    return bool(_DEPLOY_FN_RE.search(content)) and bool(
        _DEPLOY_ORDERING_RACE_RE.search(content)
    )


# LIVE_ARTIFACT_REQUIRED blocker: the harm needs a SEPARATELY-compiled
# malicious artifact (a second contract/program deployed by the attacker) that
# a single-harness unit/property PoC cannot self-contain.
_LIVE_ARTIFACT_PATTERNS = (
    "malicious contract", "malicious artifact", "attacker contract",
    "attacker-controlled contract", "second contract", "second deployment",
    "separately compiled", "separately-compiled",
    "deploy a malicious", "requires deploying", "requires a separate deploy",
    "custom contract must be deployed",
)


def _has_live_artifact_blocker(content: str) -> bool:
    """LIVE_ARTIFACT_REQUIRED blocker: harm requires a separately-compiled
    malicious artifact / second-contract deploy the PoC cannot self-contain."""
    if not content:
        return False
    return any(_poc_kw_present(p, content) for p in _LIVE_ARTIFACT_PATTERNS)


def _has_refuted_verdict(content: str) -> bool:
    """REFUTED blocker: the verifier's own verdict is REFUTED — no positive
    harm is left to test."""
    if not content:
        return False
    verdict = _field_from_markdown(content, ("Verdict", "Final Verdict", "Status"))
    return bool(re.search(r"\bREFUTED\b", verdict or "", re.IGNORECASE))


def _has_valid_skip_blocker(
    content: str,
    severity: str = "",
    scratchpad: Optional[Path] = None,
) -> bool:
    """Closed, code-grounded taxonomy of blockers that legitimately excuse a
    concrete-material-harm finding from the force-by-default PoC floor.

    Recall-safe by construction: this is a CLOSED allowlist, not a catch-all.
    A finding with a concrete material harm that does NOT match one of these
    six blockers is forced into a testable PoC class regardless of its
    self-declared/queue class label.
    """
    if not content:
        return False
    if _has_refuted_verdict(content):
        return True
    if _has_fully_trusted_actor_blocker(content):
        return True
    if _has_deploy_ordering_blocker(content):
        return True
    if _has_live_artifact_blocker(content):
        return True
    # EXTERNAL_DEP_NO_FORK: mirrors the fork-PoC mandate invalidation logic in
    # `_valid_poc_skip` exactly — an external-integration fund-drain/misrouting
    # harm is a valid blocker UNLESS a fork PoC is actually runnable here
    # (Medium+ severity + a named resolvable deployed address + reachable RPC
    # egress). With no reachable RPC (the common case) the blocker stays valid.
    if _matches_external_integration_harm(content):
        fork_actually_runnable = (
            scratchpad is not None
            and normalize_severity(severity) in {"Critical", "High", "Medium"}
            and _names_resolvable_deployed_address(content)
            and _egress_rpc_reachable(scratchpad)
        )
        if not fork_actually_runnable:
            return True
    # SPEC_DOCS_NO_STATE_DELTA: no concrete material harm asserted at all — a
    # pure doc/naming/spec mismatch with no state delta to test.
    if not _has_concrete_material_harm(content):
        return True
    return False


def _effective_poc_class(
    queue_class: str,
    content: Optional[str] = None,
    severity: str = "",
    scratchpad: Optional[Path] = None,
) -> str:
    """Resolve the effective PoC class, honoring a verifier reclassification.

    The queue `poc class` is an LLM estimate derived from the finding TITLE
    before the code was read. Per `~/.plamen/rules/phase5-poc-execution.md` the
    verifier MAY non-silently reclassify the finding and DECLARE the corrected
    class as a `PoC Class:` ledger field in its own `verify_<id>.md` output.

    When the verifier reclassified AWAY from a locally-testable class
    (to `structural`/`integration`/`spec`/`docs`), that declared class is
    authoritative — otherwise the queue's stale unit/property estimate forces a
    PoC the verifier already (correctly) showed is the wrong test class.

    Recall-safe / anti-gaming: a ledger that leaves the declared class at
    unit/property (or omits it) NEVER relaxes below the queue estimate — a
    silent leave-testable still requires the PoC. This helper can ONLY move a
    testable queue class to a non-testable declared class, never the reverse.

    Read via the shared `_field_anywhere` tolerant extractor (table-cell / bold
    / bullet / colon forms) with a LEADING-TOKEN match so the justification text
    the prompt asks for (`PoC Class: structural  (queue said property; ...)`) is
    honored.
    """
    poc_class = (queue_class or "structural").strip().lower()
    if not content:
        return poc_class
    # STICKY FLOOR (MODE A, load-bearing): a finding whose verify content
    # asserts a resource-exhaustion / executable-harm mechanism (unbounded
    # input, gas griefing, storage bloat, balance double-count) HAS an
    # executable harm assertion. Do NOT honor a verifier's
    # structural/integration/spec/docs self-declaration for it — that is the
    # exact escape that let a real gas-bomb finding be refused with no PoC.
    # Floor the effective class at a TESTABLE class so the mandatory-PoC
    # contract re-queues a real attempt before any refutation is accepted.
    # (A queue estimate that is already unit/property is left as-is.)
    if _matches_resource_exhaustion(content):
        return poc_class if poc_class in {"unit", "property"} else "property"
    # STICKY FLOOR (Fix 2, mirror of the resource-exhaustion floor above): a
    # finding whose harm is an external-integration fund-drain / misrouting AND
    # whose verifier prose names a concrete deployed address HAS a fork-testable
    # harm. Do NOT honor a verifier self-declaring `structural`/`spec`/`docs` to
    # zero the PoC requirement — floor the effective class at `integration` so
    # the fork-PoC mandate re-queues a real attempt (when RPC egress exists).
    # A queue estimate already at unit/property/integration is left as-is (only
    # a non-testable self-declaration is blocked). GENERIC — no protocol names.
    if _matches_external_integration_harm(content) and \
            _names_resolvable_deployed_address(content):
        return poc_class if poc_class in {"unit", "property", "integration"} \
            else "integration"
    # STICKY FLOOR 3 (force-by-default, load-bearing): a finding whose verify
    # content asserts a CONCRETE material harm (fund/state/privilege/liveness/
    # accounting delta) is FORCED into a testable class UNLESS a closed,
    # code-grounded blocker (`_has_valid_skip_blocker`) excuses it —
    # fully-trusted-design, deploy/tx-ordering race, external-dep-no-fork,
    # live-artifact-required, spec/docs-no-state-delta, or a REFUTED verdict.
    # This is the DEFAULT-FORCE floor: the queue/declared class (`structural`
    # in particular) is proven-unreliable (`classify_poc_testability` defaults
    # hard-to-classify findings to structural, and every sampled lazy skip
    # rode that default) so it is NOT honored as a reason to skip a concrete
    # harm. Label-independent — never honors ANY declared class (structural/
    # integration/spec/docs) for a concrete-harm/no-blocker finding.
    if _has_concrete_material_harm(content) and not _has_valid_skip_blocker(
        content, severity, scratchpad
    ):
        return poc_class if poc_class in {"unit", "property"} else "property"
    declared_raw, _shape = _field_anywhere(
        content, ("PoC Class", "Poc Class"), table_ok=True
    )
    m_decl = re.match(r"\s*([A-Za-z_]+)", declared_raw or "")
    if m_decl:
        declared = m_decl.group(1).lower()
        if declared in {"structural", "integration", "spec", "docs"}:
            return declared
    return poc_class


def _poc_contract_required(
    row: dict[str, str],
    mode: str,
    content: Optional[str] = None,
    scratchpad: Optional[Path] = None,
) -> bool:
    """Whether a mandatory unit/property PoC is contractually required for *row*.

    The queue `poc class` is an LLM estimate derived from the finding TITLE
    before the code was read. The verify prompt instructs the verifier to
    CHALLENGE a wrong queue class and DECLARE the corrected class as a
    `PoC Class:` ledger field in its own output. When the verifier has
    non-silently reclassified the finding to a non-testable class
    (`structural`/`integration`/`spec`/`docs`), the contract requirement is
    driven by THAT declared class, not the stale queue estimate — otherwise the
    gate demands a unit/property PoC the verifier already (correctly) showed is
    not the right test class, which is an unwinnable retry.

    The reclassification is read via the shared `_field_anywhere` tolerant
    extractor (table-cell / bold / bullet / colon forms), with a LEADING-TOKEN
    match so the justification text the prompt asks for
    (`PoC Class: structural  (queue said property; ...)`) is honored. A ledger
    that leaves the declared class at unit/property does NOT downgrade the
    requirement (anti-gaming floor preserved — silently leaving it testable
    still requires the PoC).
    """
    # Effective class honors a verifier's non-silent reclassification AWAY from
    # a locally-testable class (recall-safe: never relaxes below queue estimate
    # for a declared unit/property/omitted ledger). Shared with the aggregate
    # skip-vocabulary audit so both gates agree on the authoritative class.
    # Also carries the force-by-default sticky floor (STICKY FLOOR 3): a
    # concrete-material-harm finding with no valid code-grounded blocker is
    # forced into a testable class regardless of the declared/queue label.
    poc_class = _effective_poc_class(
        row.get("poc class") or "", content, row.get("severity", ""), scratchpad
    )
    if poc_class not in {"unit", "property"}:
        return False
    mode_l = (mode or "core").lower()
    if mode_l == "light":
        return False
    sev = normalize_severity(row.get("severity", ""))
    # Mandatory unit/property PoC enforcement caps at Medium in ALL modes.
    # A Low/Info finding shipping `Attempted: NO` (no fork PoC, or a property
    # skip) is NORMAL — Low/Info findings rarely warrant a property PoC — yet
    # under Thorough the old `return True` made the mandatory-PoC contract apply
    # to every severity, so each all-Low/Info verify shard tripped this gate,
    # fired a FUTILE one-shot targeted repair (which a retry can never satisfy
    # for a Low CODE-TRACE finding), and degraded anyway — paying a full
    # re-spawn per low shard for no possible outcome change. Capping at Medium
    # lets the Low/Info finding ship as the verifier's verdict (e.g. CODE-TRACE)
    # with NO spurious UNPROVEN and NO wasted retry. Critical/High/Medium
    # enforcement (and their fixable retries) is UNCHANGED in every mode — a
    # real fork-PoC still matters there and a retry can fix a fixable gap.
    return sev in {"Critical", "High", "Medium"}


def _validate_poc_contract_for_rows(
    scratchpad: Path,
    rows: list[dict[str, str]],
    mode: str,
) -> list[str]:
    """Hard verifier-shard contract for mandatory PoC attempts.

    A failing/compiling PoC is still an attempt; this gate only prevents
    ledgerless or unjustified skips for rows already classified as locally
    testable. Proof strength is handled by evidence tags and demotion logic.
    """
    issues: list[str] = []
    # Project-wide mock feasibility (shared with the aggregate skip audit).
    # Computed once per shard-gate invocation; sees whatever verify files exist
    # on disk at gate time, which includes this shard's own outputs.
    mock_feasible, mock_example = _project_mock_feasible(scratchpad)
    for row in rows:
        # First-pass cheap gate on MODE/SEVERITY only (no I/O, no class check):
        # the queue `poc class` is a pre-code-read estimate that defaults
        # hard-to-classify findings to `structural`, and the force-by-default
        # sticky floor (STICKY FLOOR 3 in `_effective_poc_class`) can ONLY be
        # evaluated against the verify CONTENT — so a class-only pre-filter
        # here would silently exempt every lazy structural-seeded skip from
        # ever having its content read. Mode/severity are class-independent
        # and cost no I/O, so they remain a valid cheap pre-filter.
        mode_l = (mode or "core").lower()
        if mode_l == "light":
            continue
        if normalize_severity(row.get("severity", "")) not in {"Critical", "High", "Medium"}:
            continue
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        path = _find_verify_file(scratchpad, fid)
        if not path:
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Authoritative gate using the verifier's DECLARED PoC Class ledger
        # field AND the force-by-default concrete-material-harm floor — both
        # resolved against CONTENT (never the unreliable queue-only class).
        # If the verifier non-silently reclassified this finding to a
        # non-testable class (structural/integration/spec/docs) WITH a valid
        # blocker, the mandatory unit/property contract no longer applies —
        # demanding the PoC anyway is an unwinnable retry. The anti-gaming
        # floor is preserved inside `_poc_contract_required` (a declared
        # unit/property does NOT relax; a concrete-harm/no-blocker finding is
        # forced regardless of the declared label).
        if not _poc_contract_required(row, mode, content, scratchpad):
            continue
        has_poc_section, has_exec_section = _has_poc_ledger_sections(content)
        if not has_poc_section or not has_exec_section:
            # Write-completion race: the worker returns "DONE" and the driver
            # invokes this gate the instant the file appears, but the OS write
            # buffer for the ledger sections may not be flushed yet. The file
            # passes the size check (partial body) while the "PoC Attempt" /
            # "Execution Result" sections are still in-flight. A bounded
            # re-read after a short filesystem-sync delay resolves the partial
            # state without a full shard retry — mirroring the driver-level
            # bounded retry but at I/O granularity. Only fail if the sections
            # are STILL absent after the resync (a genuine omission).
            for _delay in (0.25, 0.5):
                time.sleep(_delay)
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    break
                has_poc_section, has_exec_section = _has_poc_ledger_sections(content)
                if has_poc_section and has_exec_section:
                    break
            if not has_poc_section or not has_exec_section:
                issues.append(f"{fid} missing PoC Attempt/Execution Result ledger")
                continue
        attempted = _poc_attempted_value(content)
        attempted_yes = attempted == "YES"
        attempted_no = attempted == "NO"
        raw_poc_class = (row.get("poc class") or "structural").strip().lower()
        # Effective class subsumes ALL sticky floors (resource-exhaustion,
        # external-integration fund-drain, and the force-by-default
        # concrete-material-harm floor) so the `_valid_poc_skip` call below
        # correctly rejects an inappropriate self-declared-non-testable skip
        # for a row `_poc_contract_required` already determined is
        # force-required — using the raw queue class here would silently
        # re-open the exact escape hatch the force floors exist to close.
        poc_class = _effective_poc_class(
            raw_poc_class, content, row.get("severity", ""), scratchpad
        )
        # MODE A floor: a resource-exhaustion / executable-harm finding is
        # testable regardless of a structural self-declaration. Retained
        # (unchanged from the original resource-exhaustion-only computation)
        # to gate the reclassification-softening branch below alongside the
        # new `force_floored` flag.
        forced_executable = _matches_resource_exhaustion(
            content, row.get("title", ""), row.get("bug class", "")
        )
        # Force-by-default (STICKY FLOOR 2/3): the effective class differs from
        # the raw/queue class — i.e. a sticky floor (external-integration or
        # concrete-material-harm) actually MOVED the class. Like
        # `forced_executable`, this must ALSO suppress the reclassification-
        # softening branch below — a declared structural/integration/spec/docs
        # label must not let a concrete, unblocked harm dodge the mandatory
        # PoC ("label-independent" force).
        force_floored = poc_class != raw_poc_class
        if attempted_yes:
            command = _field_from_markdown(content, ("Command",))
            test_file = _field_from_markdown(content, ("Test File",))
            if (
                not command or re.fullmatch(r"`?(?:N/?A|NONE|NOT_APPLICABLE)`?", command.strip(), re.I)
                or not test_file or re.fullmatch(r"`?(?:N/?A|NONE|NOT_APPLICABLE)`?", test_file.strip(), re.I)
            ):
                issues.append(f"{fid} says Attempted:YES but lacks concrete Test File/Command")
            continue
        if attempted_no and _valid_poc_skip(
            content, poc_class, scratchpad, row.get("severity", "")
        ):
            # Medium+ project-mock override (parity with the aggregate
            # skip-vocabulary audit, scoped to Critical/High/Medium to avoid
            # Low/Info retry churn): an EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS
            # skip is NOT a valid blocker when the project demonstrably mocks
            # the dependency (a passing sibling test used a *Mock/*Stub). The
            # verifier can build the same minimal harness, or non-silently
            # reclassify to structural/integration (handled below) — so this
            # stays satisfiable and rides bounded-retry-then-WARN, never a halt.
            sev = normalize_severity(row.get("severity", ""))
            if (
                sev in {"Critical", "High", "Medium"}
                and _poc_skip_code(content) == "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS"
                and mock_feasible
                and re.search(r"\bmock\b", content, re.IGNORECASE)
            ):
                issues.append(
                    f"{fid} EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip invalid "
                    f"for {sev} {poc_class} finding: mocking is demonstrably "
                    f"feasible here (a passing test used `{mock_example}`) — "
                    "build the minimal mock/harness and run the PoC, or "
                    "non-silently reclassify the PoC Class with justification"
                )
            continue
        # Verifier-challenge softening: the queue PoC Class is an LLM estimate
        # from the finding title; the verifier analyzed the actual code at the
        # cited Location. The verify prompt explicitly tells the verifier to
        # CHALLENGE (not silently bypass) a wrong queue class. When the verifier
        # does so non-silently — declares `PoC Class: structural`/`integration`
        # in its OWN ledger AND records a skip that is valid FOR THAT DECLARED
        # CLASS — honor that informed reclassification instead of hard-degrading.
        # This is an LLM-classification disagreement, which must WARN, not FAIL:
        # the soft gate `_validate_poc_attempt_coverage` still records it as a
        # violations.md warning.
        #
        # Two fixes vs the old exact-match-on-STRUCTURAL-skip-only check (both
        # caused legitimate Claude reclassifications to degrade their shard):
        #   #1 LEADING-TOKEN match tolerates the justification text the prompt
        #      asks for: `PoC Class: structural  (queue said property; ...)`.
        #      The old `declared in {"structural","integration"}` exact-match
        #      was defeated by the trailing parenthetical -> false FAIL.
        #   #2 Evaluate `_valid_poc_skip` against the DECLARED class, not only
        #      the structural skip code, so a reclassify-to-`integration` +
        #      DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL (valid for integration) is
        #      honored — previously only the STRUCTURAL skip code was softened.
        # Anti-gaming floor PRESERVED: a ledger that leaves PoC Class as
        # unit/property (leading token unit/property) is a SILENT bypass and
        # still fails — the verifier must DECLARE the reclassification — and
        # `_valid_poc_skip` still enforces mock-feasibility / class rules for
        # the declared class, so this opens no new bypass vector.
        if attempted_no and not forced_executable and not force_floored:
            declared_raw = (
                _field_from_markdown(content, ("PoC Class", "Poc Class", "PoC class")) or ""
            ).strip().lower()
            m_decl = re.match(r"(structural|integration)\b", declared_raw)
            if m_decl and _valid_poc_skip(content, m_decl.group(1)):
                continue
        issues.append(f"{fid} mandatory {poc_class} PoC not attempted with valid blocker")
    return issues


def _validate_poc_attempt_coverage(scratchpad: Path, mode: str) -> list[str]:
    """Post-verification soft gate: check verifiers attempted PoCs for testable findings.

    Returns list of warning strings (soft — logged to violations.md, not halt).
    """
    if mode == "light":
        return []

    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []

    warnings: list[str] = []
    for row in rows:
        queue_class = row.get("poc class", "structural").strip().lower()
        severity = (row.get("severity") or "").strip().lower()
        fid = row.get("finding id", "")

        # Fix 2 (fork-PoC mandate, INERT-SAFE): an external-integration
        # fund-drain / misrouting finding whose harm rides on an untrusted
        # external contract at a known deployed address is fork-testable — even
        # when the queue/verifier class is `integration`/`structural` (so the
        # unit/property gate below `continue`s past it). Handle that class HERE.
        #   * Mandate ACTIVE (RPC egress reachable + verifier names a concrete
        #     address): an EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip is INVALID
        #     — log POC_ATTEMPT_SKIPPED for Medium+ so a fork PoC is demanded.
        #   * Mandate INERT (no reachable RPC — this env): the skip STAYS valid;
        #     stamp `[UNPROVEN-EXTERNAL]` and record an informational note. This
        #     is a strict no-op versus pre-Fix-2 (no new violation).
        # Only fires when the finding is NOT already caught by the unit/property
        # path below (queue_class not unit/property), so no double-processing.
        if (
            queue_class not in ("unit", "property")
            and severity in ("critical", "high", "medium")
        ):
            fpath = _find_verify_file(scratchpad, fid)
            if fpath:
                try:
                    fcontent = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    fcontent = ""
                eff_class = _effective_poc_class(queue_class, fcontent)
                if (
                    eff_class == "integration"
                    and _matches_external_integration_harm(fcontent)
                    and _names_resolvable_deployed_address(fcontent)
                    and not has_mechanical_proof(fcontent)
                    and _poc_attempted_value(fcontent) == "NO"
                    and _poc_skip_code(fcontent)
                    == "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS"
                ):
                    if _egress_rpc_reachable(scratchpad):
                        # Mandate ACTIVE: a fork PoC is runnable — demand it.
                        warnings.append(
                            f"POC_ATTEMPT_SKIPPED: {fid} (poc_class={eff_class}, "
                            f"severity={severity}) — external-integration "
                            "fund-drain/misrouting harm at a named deployed "
                            "address with a reachable fork RPC: run "
                            "`forge test --fork-url <rpc> --fork-block-number "
                            "<pinned>` against the pinned address, or "
                            "non-silently reclassify with justification"
                        )
                    else:
                        # Mandate INERT (no RPC egress): NO-OP. Record the
                        # evidence-honesty stamp so downstream R10 keeps the
                        # finding at its proven-mechanism severity (never above).
                        warnings.append(
                            f"POC_UNPROVEN_EXTERNAL: {fid} (poc_class={eff_class}, "
                            f"severity={severity}) — {_UNPROVEN_EXTERNAL_STAMP} "
                            "external leg unverified (no reachable fork RPC); "
                            "skip valid, severity held at proven-mechanism floor"
                        )
            continue

        # First-pass cheap gate on the QUEUE class (no I/O): if not even the
        # queue estimate makes this testable, skip without reading the file.
        if queue_class not in ("unit", "property"):
            continue
        if mode == "core" and severity not in ("critical", "high", "medium"):
            continue

        verify_path = _find_verify_file(scratchpad, fid)
        if not verify_path:
            continue

        try:
            content = verify_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # Second-pass gate using the verifier's DECLARED `PoC Class:` ledger
        # field. When the verifier non-silently reclassified this finding to a
        # non-testable class (structural/integration/spec/docs), the
        # unit/property attempt expectation no longer applies — flagging it
        # "Attempted: NO without structural justification" is a FALSE warning
        # (the verifier DID justify, via the reclassification). Parity with the
        # hard `_poc_contract_required` gate; shared `_effective_poc_class`
        # keeps both gates' class resolution identical. Anti-gaming floor
        # preserved: a ledger left at unit/property (or omitted) does NOT relax,
        # so a genuine unit/property finding with no reclassification + invalid
        # skip STILL warns below.
        poc_class = _effective_poc_class(queue_class, content)
        if poc_class not in ("unit", "property"):
            continue

        _attempt_sec, _exec_sec = _has_poc_ledger_sections(content)
        has_poc_section = _attempt_sec or _exec_sec
        has_poc_pass = has_mechanical_proof(content)
        attempted_no = _poc_attempted_value(content) == "NO"
        compiled_na = bool(re.search(
            r"Compiled\s*:\s*(?:N/?A|NOT_APPLICABLE|NO)\b", content, re.IGNORECASE
        ))
        not_executed = bool(re.search(
            r"Result\s*:\s*(?:NOT_EXECUTED|N/?A|NOT_APPLICABLE)\b", content, re.IGNORECASE
        ))
        no_test_written = bool(re.search(
            r"(?:no\s+(?:foundry|hardhat|cargo|move|unit|integration)?\s*test\s+written|"
            r"no\s+test\s+(?:was\s+)?written|"
            r"not\s+attempted|"
            r"skipped\s+(?:po?c|test|execution))",
            content,
            re.IGNORECASE,
        ))
        allowed_skip = _valid_poc_skip(content, poc_class)
        # v2.x Fix 5: CROSS_VM_ENCODING_NO_RUNTIME requires evidence of a
        # cross-VM context to prevent abuse as a generic escape hatch.
        # Require either (a) a target-VM keyword (Solana/Bitcoin/Move/etc.)
        # OR (b) a wire-format keyword (encoding/serialization/calldata/etc.)
        # in the finding body. Without one of these, treat the skip as
        # unjustified and revoke `allowed_skip`.
        if allowed_skip and _poc_skip_code(content) == "CROSS_VM_ENCODING_NO_RUNTIME":
            cross_vm_keyword_present = bool(re.search(
                r"\b(?:solana|svm|bitcoin|btc|move|aptos|sui|cosmos|ibc|"
                r"wormhole|layerzero|near|stellar|substrate|tron|"
                r"encoding|serialization|serializ\w*|wire\s*format|"
                r"calldata\s*layout|payload\s*format|message\s*format|"
                r"abi\s*layout)\b",
                content,
                re.IGNORECASE,
            ))
            if not cross_vm_keyword_present:
                allowed_skip = False

        if has_poc_pass:
            continue

        if not has_poc_section:
            warnings.append(
                f"POC_ATTEMPT_MISSING: {fid} (poc_class={poc_class}, severity={severity}) "
                f"— no ### PoC Attempt section in verify file"
            )
        else:
            if attempted_no or compiled_na or not_executed or no_test_written:
                if not allowed_skip:
                    warnings.append(
                        f"POC_ATTEMPT_SKIPPED: {fid} (poc_class={poc_class}, severity={severity}) "
                        f"— Attempted: NO without structural justification"
                    )

    return warnings


def _per_constituent_claim_match(
    verify_content: str,
    constituent_metas: list[tuple[str, dict[str, str]]],
    abs_threshold: float = 0.25,
    margin: float = 0.10,
) -> tuple[str, list[tuple[str, float]]]:
    """For a multi-constituent hypothesis, detect which constituent's claim
    the verifier tested by Jaccard-matching the verify file's Finding Summary
    against each constituent's title and root cause.

    Decision rule combines an absolute threshold with a winner-by-margin
    check (Jaccard scores are inherently low; relative ranking is more
    discriminating than an absolute cutoff):

      - "single_winner" — exactly one constituent above abs_threshold,
        AND its score exceeds the runner-up by at least `margin`
      - "shared_claim" — multiple constituents above abs_threshold, all
        within `margin` of each other (verifier tested a shared property)
      - "ambiguous" — no constituent above abs_threshold (verifier tested
        a claim that doesn't match any constituent title — falls back to
        cap-all behavior for safety)

    scores is a list of (constituent_id, similarity) for ALL constituents.
    """
    # Extract verifier's claim text — Finding Summary preferred, else first 1000 chars
    summary_match = re.search(
        r"#{2,3}\s*Finding\s*Summary(.*?)(?=\n#{2,3}\s|\Z)",
        verify_content,
        re.DOTALL | re.IGNORECASE,
    )
    claim_text = (
        summary_match.group(1) if summary_match else verify_content[:1500]
    )
    # Strip code blocks to focus on prose
    claim_text = re.sub(r"```.*?```", "", claim_text, flags=re.DOTALL)

    scores: list[tuple[str, float]] = []
    for cid, meta in constituent_metas:
        comp = (meta.get("title", "") or "") + " " + (meta.get("root_cause", "") or "")
        sim = _jaccard_token_similarity(claim_text, comp)
        scores.append((cid, sim))

    above_threshold = [(c, s) for c, s in scores if s >= abs_threshold]
    if not above_threshold:
        return "ambiguous", scores

    sorted_scores = sorted(scores, key=lambda x: -x[1])
    top = sorted_scores[0]
    runner_up = sorted_scores[1] if len(sorted_scores) >= 2 else (None, 0.0)

    if top[1] - runner_up[1] >= margin:
        # Top clearly outranks runner-up: single winner regardless of how
        # many cleared the abs_threshold (others are coincidental overlap)
        return "single_winner", scores
    if len(above_threshold) >= 2:
        # Multiple within margin → shared claim
        return "shared_claim", scores
    # One above threshold but margin to next is small → treat as
    # single winner (the threshold cleared anyway)
    return "single_winner", scores


def _poc_fail_asserts_harm(content: str, poc_section: str) -> bool:
    """Impact-Premise gate for POC-FAIL demotion (force-by-default Edit 5).

    A demotion is a NEW severity reduction and must be evidence-backed by a
    test that actually engaged the claimed harm, not merely a mechanism (per
    `~/.plamen/rules/phase5-poc-execution.md` Impact Premise Verification).

    Returns False (no-demote; the finding falls back to CODE-TRACE at its
    pre-force disposition) ONLY when the ledger EXPLICITLY records
    `Attempted: NO` (a genuine, structurally-declared skip — nothing was ever
    run against the claimed harm) or an explicit no-executable-harm-assertion
    disposition. A bare `[POC-FAIL]` tag on a declared-NO-attempt ledger
    cannot be trusted to disprove that harm — this is exactly the "forced
    attempt that cannot assert the harm" case Edit 5 targets.

    Returns True (demotion allowed) in every other case, including the
    common already-shipped shape where the `Attempted` field is absent but a
    narrative execution outcome is present (legacy ledgers predate the
    formal `Attempted:` field). Recall-safe: this can only SUPPRESS a
    demotion for a declared-NO-attempt row, never sink a finding further and
    never suppress a demotion for a genuine executed result.
    """
    scoped = poc_section or content
    if re.search(r"no\s+executable\s+harm\s+assertion", scoped, re.IGNORECASE):
        return False
    if _poc_attempted_value(content) == "NO":
        return False
    return True


def _apply_poc_fail_demotions(scratchpad: Path, mode: str) -> list[dict[str, str]]:
    """Demote findings where PoC mechanically disproved the claimed harm.

    For poc_class=unit findings with [POC-FAIL]: cap at Informational.
    For poc_class=property findings with [POC-FAIL]: cap at Low.

    v2.x Fix 4 (per-constituent safety net): when the failed hypothesis
    absorbed multiple constituents (per finding_mapping.md) AND the
    verifier's Finding Summary matches exactly ONE constituent's title
    well (Jaccard >= 0.40), skip the hypothesis-level demotion. The
    un-tested constituents survive at their original severity, and the
    tested constituent gets a per-constituent demotion entry. This
    prevents one weak constituent's PoC failure from sinking N true
    positives in the same group.

    Returns list of demotion records.
    """
    if mode == "light":
        return []

    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []

    # Lazy-load hypothesis constituent mapping + inventory meta (Fix 4)
    try:
        from plamen_parsers import _parse_hypothesis_constituents
        hyp_constituents = _parse_hypothesis_constituents(scratchpad)
    except Exception:
        hyp_constituents = {}
    try:
        inventory_meta = _parse_inventory_finding_meta(scratchpad)
    except Exception:
        inventory_meta = {}

    demotions: list[dict[str, str]] = []
    carveout_skips: list[dict[str, str]] = []
    for row in rows:
        poc_class = row.get("poc class", "structural")
        # VERIF-4: include 'integration' (capped at Low like property) but ONLY
        # on a genuine EXECUTED mechanical FAIL (checked below), never on a bare
        # prose [POC-FAIL] without execution. 'structural' stays untouched
        # (often no harness exists, so a FAIL is not harm-disproof).
        if poc_class not in ("unit", "property", "integration"):
            continue

        fid = row.get("finding id", "")
        severity = (row.get("severity") or "").strip()

        verify_path = _find_verify_file(scratchpad, fid)
        if not verify_path:
            continue

        try:
            content = verify_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        poc_section_match = re.search(
            r"#{2,3}\s*(?:PoC Attempt|Execution Result)(.*?)(?=\n#{2,3}\s|\Z)", content, re.DOTALL
        )
        poc_section = poc_section_match.group(1) if poc_section_match else ""
        if "[POC-FAIL]" not in poc_section:
            evidence_line = re.search(r"Evidence\s*Tag\s*:\s*\[POC-FAIL\]", content, re.IGNORECASE)
            if not evidence_line:
                continue

        if has_mechanical_proof(content):
            continue

        # Force-by-default Edit 5 (no-demote floor): a [POC-FAIL] whose ledger
        # shows NO harm-asserting test (Impact-Premise unmet) is treated as
        # CODE-TRACE and the finding falls back to its pre-force disposition
        # — NEVER demoted below baseline. Only a harm-asserting PoC that ran
        # and failed demotes.
        if not _poc_fail_asserts_harm(content, poc_section):
            continue

        if poc_class == "integration":
            # VERIF-4: integration findings demote ONLY on a real executed FAIL
            # (mechanical-verify annotation), not a bare prose [POC-FAIL] -- an
            # integration finding that merely lacked a harness must not be sunk.
            if not re.search(
                r"Mechanical[- ]?(?:Verified\s+)?(?:Status|Tag)\s*:\s*\[?FAIL",
                content, re.IGNORECASE,
            ):
                continue
            new_sev = "Low"
            reason = "POC-FAIL on integration finding — executed harness disproved the claimed harm"
        elif poc_class == "unit":
            new_sev = "Informational"
            reason = "POC-FAIL on unit-testable finding — claimed harm mechanically disproved"
        else:
            new_sev = "Low"
            reason = "POC-FAIL on property-testable finding — invariant violation not reproduced"

        # v2.x Fix 4: per-constituent demotion. If this hypothesis absorbed
        # multiple constituents, check whether the verifier tested only one
        # constituent's claim. If so, spare the others.
        constituent_ids = [
            cid for cid in hyp_constituents.get(fid.upper(), [])
            if cid in inventory_meta
        ]
        if len(constituent_ids) >= 2:
            constituent_metas = [(cid, inventory_meta[cid]) for cid in constituent_ids]
            match_kind, scores = _per_constituent_claim_match(content, constituent_metas)
            if match_kind == "single_winner":
                winner = max(scores, key=lambda x: x[1])
                spared = [c for c, _ in scores if c != winner[0]]
                # Demote the hypothesis (Index Agent caps the report row),
                # but emit a carveout record so the Index Agent's STEP 1.5
                # consolidation knows to split out the spared constituents
                # as separate report rows at their original severity.
                demotions.append({
                    "finding_id": fid,
                    "original_severity": severity,
                    "new_severity": new_sev,
                    "poc_class": poc_class,
                    "reason": reason + f" (verifier tested constituent {winner[0]} "
                                       f"with Jaccard {winner[1]:.2f}; "
                                       f"{len(spared)} other constituent(s) spared)",
                })
                carveout_skips.append({
                    "hypothesis_id": fid,
                    "tested_constituent": winner[0],
                    "tested_jaccard": f"{winner[1]:.2f}",
                    "spared_constituents": ",".join(spared),
                })
                continue
            elif match_kind == "ambiguous":
                # Verifier's claim doesn't match any constituent — keep
                # current cap-all behavior (safe fallback). Annotate the
                # reason so the report writer understands.
                top_score = max((s for _, s in scores), default=0.0)
                reason = (
                    reason +
                    f" (verifier claim-ambiguous: best constituent match Jaccard "
                    f"{top_score:.2f} < 0.40 threshold; cap-all applied)"
                )
            # shared_claim → fall through to cap-all (verifier tested
            # a property all constituents share, so demoting all is correct)

        demotions.append({
            "finding_id": fid,
            "original_severity": severity,
            "new_severity": new_sev,
            "poc_class": poc_class,
            "reason": reason,
        })

    if demotions:
        lines = [
            "# PoC Fail Demotions\n\n",
            "Findings mechanically disproved by executed PoCs. Index Agent MUST respect these severity caps.\n\n",
            "| Finding ID | Original Severity | Capped At | PoC Class | Reason |\n",
            "|-----------|-------------------|-----------|-----------|--------|\n",
        ]
        for d in demotions:
            lines.append(
                f"| {d['finding_id']} | {d['original_severity']} | {d['new_severity']} "
                f"| {d['poc_class']} | {d['reason']} |\n"
            )
        (scratchpad / "poc_demotions.md").write_text("".join(lines), encoding="utf-8")

    if carveout_skips:
        clines = [
            "# PoC Demotion Constituent Carveouts (Fix 4)\n\n",
            "When a multi-constituent hypothesis received [POC-FAIL] but the "
            "verifier's Finding Summary only matched ONE constituent's claim "
            "well, the un-tested constituents are spared from the cap. The "
            "Index Agent STEP 1.5 consolidation should split the spared "
            "constituents into SEPARATE report rows at their original "
            "severity, leaving only the tested constituent under the demotion.\n\n",
            "| Hypothesis ID | Tested Constituent | Tested Jaccard | Spared Constituents |\n",
            "|---------------|--------------------|-----------------|---------------------|\n",
        ]
        for c in carveout_skips:
            clines.append(
                f"| {c['hypothesis_id']} | {c['tested_constituent']} "
                f"| {c['tested_jaccard']} | {c['spared_constituents']} |\n"
            )
        (scratchpad / "poc_demotion_carveouts.md").write_text(
            "".join(clines), encoding="utf-8"
        )

    return demotions


# ── M4: blind-first independent severity cap (anti-inflation) ─────────────
# Mirrors the `poc_demotions.md` mechanical-cap precedent end-to-end. The
# verifier prompt (phase5-verification-prompt.md) requires a MANDATORY
# `Independent Severity` field, assessed from code+evidence ALONE, filled
# BEFORE reconciling with the pre-assigned/claimed severity from the
# verification queue. This function reads that field back and mechanically
# caps `final = min(independent, claimed)` — i.e. it can ONLY LOWER severity,
# it NEVER raises it, and it NEVER drops a finding:
#   - Independent >= claimed (same or MORE severe)   -> no cap
#   - Independent missing / unparseable / "N/A"      -> no cap (recall-safe;
#     falls back to claimed)
#   - Verdict REFUTED / FALSE_POSITIVE / duplicate    -> no cap (N/A class,
#     the finding isn't in the body at all)
_INDEPENDENT_SEVERITY_RANK: dict[str, int] = {
    "Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4,
}

_INDEPENDENT_SEVERITY_SKIP_VERDICTS = frozenset({
    "REFUTED", "FALSE_POSITIVE", "DROP_FALSE_POSITIVE", "INFEASIBLE",
    "DUPLICATE", "CONSOLIDATED",
})


def _apply_independent_severity_caps(scratchpad: Path, mode: str) -> list[dict[str, str]]:
    """M4: cap severity to min(independent, claimed) via the verifier's
    blind-first Independent Severity assessment.

    Returns a list of cap records and writes `independent_severity_caps.md`
    (Finding ID | Claimed | Independent | Final) when any cap fires.
    """
    if mode == "light":
        return []

    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []

    caps: list[dict[str, str]] = []
    for row in rows:
        fid = row.get("finding id", "")
        claimed_raw = (row.get("severity") or "").strip()
        if not fid or not claimed_raw:
            continue
        claimed = normalize_severity(claimed_raw)
        if claimed not in _INDEPENDENT_SEVERITY_RANK:
            continue

        verify_path = _find_verify_file(scratchpad, fid)
        if not verify_path:
            continue
        try:
            content = verify_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        status = _verifier_status_from_text(content)
        if status in _INDEPENDENT_SEVERITY_SKIP_VERDICTS:
            continue

        field = _field_from_markdown(content, ("Independent Severity",))
        if not field:
            # Missing field entirely -> no cap (recall-safe fallback to claimed).
            continue
        field_clean = field.strip().strip("`*_")
        if re.fullmatch(r"(?i)\s*n/?a\s*", field_clean):
            continue
        independent = try_normalize_severity(field_clean)
        if not independent or independent not in _INDEPENDENT_SEVERITY_RANK:
            # Unparseable -> no cap (recall-safe fallback to claimed).
            continue

        if _INDEPENDENT_SEVERITY_RANK[independent] <= _INDEPENDENT_SEVERITY_RANK[claimed]:
            # Independent is the same or MORE severe than claimed -> never
            # raise severity; no cap.
            continue

        caps.append({
            "finding_id": fid,
            "claimed_severity": claimed,
            "independent_severity": independent,
            "final_severity": independent,
        })

    if caps:
        lines = [
            "# Independent Severity Caps\n\n",
            "Findings where the verifier's blind-first Independent Severity "
            "assessment (assessed from code+evidence alone, before seeing the "
            "pre-assigned severity) is LOWER than the claimed/queue severity. "
            "Index Agent MUST respect these severity caps — final = "
            "min(independent, claimed), stamped Trust Adj. "
            "INDEPENDENT-MIN(<claimed>).\n\n",
            "| Finding ID | Claimed | Independent | Final |\n",
            "|-----------|---------|-------------|-------|\n",
        ]
        for c in caps:
            lines.append(
                f"| {c['finding_id']} | {c['claimed_severity']} "
                f"| {c['independent_severity']} | {c['final_severity']} |\n"
            )
        (scratchpad / "independent_severity_caps.md").write_text(
            "".join(lines), encoding="utf-8"
        )

    return caps


def _load_independent_severity_caps(scratchpad: Path) -> dict[str, str]:
    """Return finding-ID severity caps from independent_severity_caps.md.

    Mirrors `_poc_demotion_caps_for_validator` — read back the mechanically
    computed ledger so `_expected_report_index_severities` (and the
    report_index provenance gate) can apply the same min(independent,
    claimed) cap the Index Agent is instructed to apply.
    """
    path = scratchpad / "independent_severity_caps.md"
    if not path.exists():
        return {}
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    caps: dict[str, str] = {}
    headers, rows = _parse_markdown_table(text, ["finding id", "final"])
    if not headers:
        return caps
    keys = [_norm_key(h) for h in headers]
    for row in rows:
        d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
        fid = _normalize_finding_id(d.get("finding id", "")) or d.get("finding id", "")
        final = normalize_severity(d.get("final", ""))
        if fid and final:
            caps[fid] = final
    return caps


def _stamp_unproven_external(vf: Path, vtxt: str) -> None:
    """Idempotently append [EXTERNAL-ASSUMPTION] + [UNPROVEN-EXTERNAL] markers to
    a verify file so the existing consume block (`_unproven_external_stamped`)
    keeps the finding in body at its proven-mechanism floor even if the ledger is
    later absent (defense in depth)."""
    if _UNPROVEN_EXTERNAL_STAMP.upper() in (vtxt or "").upper():
        return
    try:
        with open(vf, "a", encoding="utf-8") as f:
            f.write("\n\n<!-- R10 demotion-side gate -->\n"
                    "[EXTERNAL-ASSUMPTION: verifier demotion rests on an uncited "
                    "best-case external condition; worst-case external behavior "
                    "assumed per R10] [UNPROVEN-EXTERNAL]\n")
    except Exception:
        pass


def _aggregate_depth_verdict(
    fid: str,
    inv_verdicts: dict[str, str],
    hyp_constituents: dict[str, list[str]],
) -> str:
    """Depth verdict for a queue finding-id (condition 1 / G4).

    Returns the DIRECT inventory verdict when the queue id IS an inventory id.
    Otherwise the queue id is a hypothesis id (`H-NN`, incl. anti-absorption
    `GRP-NNx` splits) whose CONSTITUENT inventory findings carry the depth
    verdicts. Aggregate them recall-safely:
      * CONFIRMED  if ANY constituent is CONFIRMED/PARTIAL (mechanism real in at
        least one split),
      * REFUTED    only when EVERY resolvable constituent was REFUTED in-scope
        (G4 blocks the un-demotion),
      * ''         when no constituent verdict is resolvable — falls through to
        the verifier-side gates, preserving the prior recall-safe behavior.
    """
    direct = inv_verdicts.get(fid, "") or inv_verdicts.get(
        _normalize_finding_id(fid) or fid, ""
    )
    if direct:
        return direct
    consts = hyp_constituents.get(fid) or hyp_constituents.get(fid.upper()) or []
    verdicts: list[str] = []
    for c in consts:
        v = inv_verdicts.get(c, "") or inv_verdicts.get(
            _normalize_finding_id(str(c)) or str(c), ""
        )
        if v:
            verdicts.append(v)
    if not verdicts:
        return ""
    if any("CONFIRM" in v or "PARTIAL" in v for v in verdicts):
        return "CONFIRMED"
    if all("REFUTED" in v for v in verdicts):
        return "REFUTED"
    return ""


def _apply_external_assumption_undemotions(scratchpad: Path, mode: str) -> list[dict[str, str]]:
    """R10 demotion-side gate. For each queue finding that is CONFIRMED/PARTIAL
    (not REFUTED) at DEPTH yet DEMOTED by the verifier purely on an UNCITED
    best-case external assumption: (1) write a row to
    `external_assumption_undemotions.md` (Finding ID | Depth Verdict | Verifier
    Sev | Restored Floor | Basis), (2) STAMP [EXTERNAL-ASSUMPTION] +
    [UNPROVEN-EXTERNAL] into the verify file (idempotent) so the existing
    consume block keeps the finding IN BODY at proven severity, flagged for
    human review of the external leg. Structural MIRROR of the assert-side
    `_external_assumption_cap_applies`. Recall-safe: [] on absent/unparseable
    input.
    """
    if mode == "light":
        return []
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []

    # Condition-1 source: depth Verdict per finding, read from inventory (queue
    # rows carry NO verdict column). inv id == queue finding id (queue is built
    # from inventory).
    inv_verdicts: dict[str, str] = {}
    inv_blocks_by_id: dict[str, str] = {}
    inv_path = scratchpad / "findings_inventory.md"
    if inv_path.exists():
        try:
            for b in _inventory_blocks(
                inv_path.read_text(encoding="utf-8", errors="replace")
            ):
                bid = _normalize_finding_id(b.get("id", "")) or b.get("id", "")
                if bid:
                    inv_verdicts[bid] = (
                        _field_from_markdown(b.get("block", ""), ("Verdict",)) or ""
                    ).upper()
                    inv_blocks_by_id[bid] = b.get("block", "")
        except Exception:
            pass

    # Bridge queue finding-id (a hypothesis id, e.g. H-22) -> its constituent
    # inventory ids (INV-041, ... — incl. anti-absorption GRP split sources) so
    # condition-1 / G4 actually engage on real Thorough runs where the queue id
    # is a hypothesis id and inventory uses INV-NNN. {} on absent mapping =>
    # _aggregate_depth_verdict falls through to the verifier-side gates.
    try:
        hyp_constituents = _parse_hypothesis_constituents(scratchpad)
    except Exception:
        hyp_constituents = {}

    # Condition-3 source: EXT-CITED grounding. Stub/empty ledger => [] => no
    # grounding. Local re-parse avoids a driver import cycle.
    try:
        surfaces = _external_dependency_research_surfaces_local(scratchpad)
    except Exception:
        surfaces = []

    fired: list[dict[str, str]] = []
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        claimed = normalize_severity((row.get("severity") or "").strip())
        if not fid or not claimed:
            continue
        vf = _find_verify_file(scratchpad, fid)
        if not vf:
            continue
        try:
            vtxt = vf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        # ---- Condition 1: depth-CONFIRMED / not-REFUTED (G4) ----
        # Direct inventory lookup, else aggregate over the hypothesis's
        # constituent inventory findings (queue id H-NN -> INV-NNN, incl. GRP
        # anti-absorption splits). '' => unresolved mapping => fall through to
        # the verifier-side gates (recall-safe, prior behavior preserved).
        depth_verdict = _aggregate_depth_verdict(fid, inv_verdicts, hyp_constituents)
        if depth_verdict == "REFUTED":            # every constituent refuted in-scope
            continue
        if depth_verdict and "CONFIRM" not in depth_verdict and "PARTIAL" not in depth_verdict:
            continue                               # only CONFIRMED/PARTIAL qualify
        # (empty depth_verdict => fall through; verifier-side signals still gate)

        # ---- Guard G3 / in-scope-executed: Attempted:YES ⇒ never veto ----
        if _poc_attempted_and_passed(vtxt):        # explicit carve-out (H-14)
            continue
        if not _poc_not_attempted(vtxt):           # Attempted:NO + ext/structural
            continue                               # blocker (blocks H-14 & H-5)

        # ---- Guard: proof-grade evidence ⇒ never veto ----
        if has_proof_grade_evidence(vtxt):
            continue

        # ---- Condition 2: verifier disposition rests on external best-case ----
        status = _verifier_status_from_text(vtxt)
        demoted = any(t in status for t in ("CONTESTED", "PARTIAL", "UNRESOLVED"))
        block = inv_blocks_by_id.get(fid, "")
        has_ext_tag = (
            "[EXTERNAL-ASSUMPTION" in vtxt or "NEEDS_DEPENDENCY_RESEARCH" in vtxt
            or "[EXTERNAL-ASSUMPTION" in block or "NEEDS_DEPENDENCY_RESEARCH" in block
        )
        ext_cue = (
            _external_assumption_promoted(vtxt)          # return-trust+external
            or _external_bestcase_stability_demotion(vtxt)  # within-window stability
        )
        if not (demoted and (has_ext_tag or ext_cue)):
            continue                                # G2: in-scope-grounded => skip

        # ---- Condition 3: no EXT-CITED grounding (G1) ----
        if "[EXT-CITED" in vtxt or "[EXT-CITED" in block:
            # only exempt when a matching surface row actually exists
            loc = _field_from_markdown(vtxt, ("Location",)) or ""
            if any(surf and surf in loc for _dep, surf in surfaces):
                continue

        # ---- FIRE ----
        restored = claimed                          # floor-to-claimed (recall-safe)
        fired.append({
            "finding_id": fid,
            "depth_verdict": depth_verdict or "(inv-absent)",
            "verifier_sev": normalize_severity(
                _field_from_markdown(vtxt, ("Severity", "Final Severity")) or claimed
            ),
            "restored_floor": restored,
            "basis": "external best-case demotion, uncited (stub/absent research ledger)",
        })
        _stamp_unproven_external(vf, vtxt)          # idempotent

    if fired:
        lines = [
            "# External-Assumption Un-Demotions (R10 demotion-side gate)\n\n",
            "Findings CONFIRMED/PARTIAL in-scope at depth but DEMOTED by the "
            "verifier purely on an UNCITED best-case external assumption. Report "
            "severity is FLOORED to the depth-claimed (queue) severity, the "
            "finding is kept IN BODY, stamped [EXTERNAL-ASSUMPTION] + "
            "[UNPROVEN-EXTERNAL], and flagged for human review of the unproven "
            "external leg. Mirror of the assert-side EXTERNAL-ASSUMPTION-CAP "
            "brake.\n\n",
            "| Finding ID | Depth Verdict | Verifier Sev | Restored Floor | Basis |\n",
            "|-----------|---------------|--------------|----------------|-------|\n",
        ]
        for c in fired:
            lines.append(
                f"| {c['finding_id']} | {c['depth_verdict']} | {c['verifier_sev']} "
                f"| {c['restored_floor']} | {c['basis']} |\n"
            )
        (scratchpad / "external_assumption_undemotions.md").write_text(
            "".join(lines), encoding="utf-8"
        )
        # NOTE: the in-body keep + human-review obligation is carried by the
        # [UNPROVEN-EXTERNAL] verify-file stamp (read by the existing
        # `_unproven_external_stamped` consume block, which floors the finding
        # in-body at proven severity) plus this ledger. report_index runs AFTER
        # verify, so an explicit verification_queue re-emit here could not
        # re-verify same-run anyway; on a rerun the gate simply re-fires and
        # re-flags. A canonical `_write_queue_subset_manifest` re-emit (never
        # `route_promotion_orphans`, whose schema/dispositions are for
        # promotion→report routing, not queue re-emit) is a possible future
        # enhancement, tracked separately with its own fixture.
    return fired


# Per-ecosystem assertion vocabulary. Each ecosystem's "any" / "nontrivial" /
# "trivial_strs" cover the canonical test-runner output the verifier writes:
#   evm        — Foundry (Solidity) `assertEq/assertTrue/vm.expectRevert/...`
#                + Hardhat (chai) `expect(...).to.equal/revert/emit/...`
#   solana     — Rust `assert!`/`assert_eq!`/`#[should_panic]`/`.unwrap_err()`
#   aptos      — Move `assert!(cond, abort_code)` (two-arg)
#   sui        — Move `assert!(cond)` (single-arg)
#   soroban    — Rust (same family as solana)
#   l1_go      — Go `t.Fatal/t.Error/...` + testify `assert.*` / `require.*`
#   l1_rust    — Rust (same family as solana)
# The legacy globals below are kept as the union fallback for callers that
# don't dispatch by language (back-compat).

_EVM_ANY_RE = re.compile(
    r"assertEq|assertNotEq|assertTrue|assertFalse|"
    r"assertGt|assertGe|assertLt|assertLe|"
    r"assertApproxEq(?:Abs|Rel)|"
    r"vm\.expectRevert|vm\.expectEmit|vm\.expectCall|"
    r"expect\([^)]+\)\.to\.(?:be|equal|revert|emit|have|deep|include)",
    re.IGNORECASE,
)
_EVM_NONTRIVIAL_RE = re.compile(
    # assertEq(IDENT, ...) where IDENT is not a bare bool/number literal,
    # so `assertEq(1, 1)` / `assertEq(true, true)` fall through to the trivial check.
    r"assert(?:Eq|NotEq|Gt|Ge|Lt|Le|ApproxEqAbs|ApproxEqRel)\s*\(\s*(?!(?:true|false)\s*[,)])[A-Za-z_][A-Za-z_0-9.\[\]()]*\s*,|"
    r"assertTrue\s*\(\s*(?!true\s*[,)])[A-Za-z_][A-Za-z_0-9.\[\]()]*|"
    r"assertFalse\s*\(\s*(?!false\s*[,)])[A-Za-z_][A-Za-z_0-9.\[\]()]*|"
    r"vm\.expectRevert\s*\(\s*[A-Za-z\d_]|"
    r"vm\.expectEmit|"
    r"expect\([^)]+\)\.to\.(?:revert|emit|equal|deep|have|include)",
    re.IGNORECASE,
)
_EVM_TRIVIAL_STRS = [
    "assertEq(1, 1)", "assertEq(0, 0)",
    "assertEq(true, true)", "assertEq(false, false)",
    "assertTrue(true)", "assertFalse(false)",
    "vm.expectRevert();",
]

_RUST_ANY_RE = re.compile(
    r"assert(?:_eq|_ne|_matches)?!\s*\(|"
    r"#\[should_panic|"
    r"\.unwrap_err\(\)|"
    r"\.is_err\(\)|"
    r"\.is_none\(\)",
    re.IGNORECASE,
)
_RUST_NONTRIVIAL_RE = re.compile(
    r"#\[should_panic|"
    r"\.unwrap_err\(\)|"
    r"\.is_err\(\)|"
    r"\.is_none\(\)|"
    r"assert(?:_eq|_ne|_matches)?!\s*\([^)]*(?:result|output|value|balance|state|err|len|count|sum|got|exp|act|amount|owner|address|received|sent|delta)",
    re.IGNORECASE,
)
_RUST_TRIVIAL_STRS = [
    "assert!(true)", "assert_eq!(1, 1)", "assert_eq!(true, true)",
    "assert!(1 == 1)", "assert!(1==1)",
]

# Move (Aptos): assert!(cond, abort_code) — two-arg form
_APTOS_MOVE_ANY_RE = re.compile(
    r"assert!\s*\(",
)
_APTOS_MOVE_NONTRIVIAL_RE = re.compile(
    r"assert!\s*\([^,)]*(?:result|output|value|balance|state|got|exp|act|len|count|sum|amount|owner|received|sent|delta|==|!=|>=|<=|>|<)[^,)]*,\s*\w+\s*\)",
    re.IGNORECASE,
)
_APTOS_MOVE_TRIVIAL_STRS = [
    "assert!(true,",
    "assert!(true)",
]

# Move (Sui): assert!(cond) — single-arg form (abort code optional)
_SUI_MOVE_ANY_RE = re.compile(
    r"assert!\s*\(|"
    r"abort\s+\d+",
)
_SUI_MOVE_NONTRIVIAL_RE = re.compile(
    r"assert!\s*\([^)]*(?:result|output|value|balance|state|got|exp|act|len|count|sum|amount|owner|received|sent|delta|==|!=|>=|<=|>|<)",
    re.IGNORECASE,
)
_SUI_MOVE_TRIVIAL_STRS = [
    "assert!(true)",
    "assert!(1 == 1)",
]

# Go testing + testify
_GO_ANY_RE = re.compile(
    r"t\.Fatal|t\.Error|t\.FailNow|t\.Fatalf|t\.Errorf|"
    r"assert\.\w+\(|require\.\w+\(",
    re.IGNORECASE,
)
_GO_NONTRIVIAL_RE = re.compile(
    r"t\.Fatalf?\s*\(\s*\"[^\"]+\"\s*,|"
    r"t\.Errorf?\s*\(\s*\"[^\"]+\"\s*,|"
    r"(?:assert|require)\.(?:Equal|NotEqual|True|False|Nil|NotNil|Contains|Greater|Less|GreaterOrEqual|LessOrEqual|ErrorIs|NoError|Panics|Empty|Len)",
    re.IGNORECASE,
)
_GO_TRIVIAL_STRS = [
    't.Fatal("")', 't.Error("")', 'assert.True(t, true)', 'require.True(t, true)',
    'assert.Equal(t, 1, 1)',
]

_ECOSYSTEM_ASSERT_DISPATCH: dict[str, dict[str, object]] = {
    "evm":     {"any": _EVM_ANY_RE,        "nontrivial": _EVM_NONTRIVIAL_RE,        "trivial": _EVM_TRIVIAL_STRS},
    "solana":  {"any": _RUST_ANY_RE,       "nontrivial": _RUST_NONTRIVIAL_RE,       "trivial": _RUST_TRIVIAL_STRS},
    "soroban": {"any": _RUST_ANY_RE,       "nontrivial": _RUST_NONTRIVIAL_RE,       "trivial": _RUST_TRIVIAL_STRS},
    "aptos":   {"any": _APTOS_MOVE_ANY_RE, "nontrivial": _APTOS_MOVE_NONTRIVIAL_RE, "trivial": _APTOS_MOVE_TRIVIAL_STRS},
    "sui":     {"any": _SUI_MOVE_ANY_RE,   "nontrivial": _SUI_MOVE_NONTRIVIAL_RE,   "trivial": _SUI_MOVE_TRIVIAL_STRS},
    "l1_go":   {"any": _GO_ANY_RE,         "nontrivial": _GO_NONTRIVIAL_RE,         "trivial": _GO_TRIVIAL_STRS},
    "l1_rust": {"any": _RUST_ANY_RE,       "nontrivial": _RUST_NONTRIVIAL_RE,       "trivial": _RUST_TRIVIAL_STRS},
}


def _read_language_from_config(scratchpad: Path) -> str:
    """Read 'language' from {scratchpad}/config.json. Returns '' if not present."""
    try:
        import json as _json
        cfg_path = scratchpad / "config.json"
        if cfg_path.exists():
            return _json.loads(cfg_path.read_text(encoding="utf-8", errors="replace")).get("language", "") or ""
    except Exception:
        pass
    return ""


def _resolve_assert_dispatch(language: str) -> dict:
    """Return per-ecosystem assertion regex bundle. Falls back to union if unknown.

    The fallback is the union of all known ecosystem regexes — broader than any
    single ecosystem. This preserves the legacy 'any caller without language
    info gets the lenient detection' behavior while still catching Solidity
    Foundry assertions that the v1 regex missed entirely.
    """
    lang = (language or "").lower().strip()
    if lang in _ECOSYSTEM_ASSERT_DISPATCH:
        return _ECOSYSTEM_ASSERT_DISPATCH[lang]
    return {
        "any": _ANY_ASSERT_RE,
        "nontrivial": _NONTRIVIAL_ASSERT_RE,
        "trivial": _TRIVIAL_ASSERT_STRS,
    }


# Legacy globals (back-compat). UNION across all ecosystems so any caller that
# bypasses _resolve_assert_dispatch() still benefits from Foundry/Move/Go
# vocabulary additions. Direct imports of these names remain valid.
_TRIVIAL_ASSERT_STRS = list({
    *_EVM_TRIVIAL_STRS, *_RUST_TRIVIAL_STRS,
    *_APTOS_MOVE_TRIVIAL_STRS, *_SUI_MOVE_TRIVIAL_STRS, *_GO_TRIVIAL_STRS,
})

_NONTRIVIAL_ASSERT_RE = re.compile(
    # Rust
    r"#\[should_panic|"
    r"\.unwrap_err\(\)|"
    r"\.is_err\(\)|"
    r"\.is_none\(\)|"
    r"assert(?:_eq|_ne|_matches)?!\s*\([^)]*(?:result|output|value|balance|state|err|len|count|sum|got|exp|act|amount|owner|address|received|sent|delta)|"
    # Foundry / Solidity
    r"assert(?:Eq|NotEq|Gt|Ge|Lt|Le|ApproxEqAbs|ApproxEqRel)\s*\([^,)]+,[^)]+\)|"
    r"assertTrue\s*\([^)]*(?:result|output|value|balance|state|err|len|count|sum|got|exp|act|amount|owner|address|gas|fee|received|sent|delta)|"
    r"vm\.expectRevert\s*\(\s*[A-Za-z\d_]|"
    r"vm\.expectEmit|"
    # Hardhat (chai)
    r"expect\([^)]+\)\.to\.(?:revert|emit|equal|deep|have|include)|"
    # Python unittest (legacy)
    r"assert\s*\.\s*(?:True|False|Equal|NotEqual)|"
    # Go
    r"t\.Fatalf?|t\.Errorf?|"
    r"(?:assert|require)\.(?:Equal|NotEqual|True|False|Nil|NotNil|Contains|Greater|Less|ErrorIs|NoError|Panics|Empty|Len)",
    re.IGNORECASE,
)

_ANY_ASSERT_RE = re.compile(
    # Rust
    r"assert(?:_eq|_ne|_matches)?!\s*\(|"
    r"#\[should_panic|"
    r"\.unwrap_err\(\)|"
    r"\.is_err\(\)|"
    r"\.is_none\(\)|"
    # Foundry / Solidity
    r"assertEq|assertNotEq|assertTrue|assertFalse|"
    r"assertGt|assertGe|assertLt|assertLe|"
    r"assertApproxEq(?:Abs|Rel)|"
    r"vm\.expectRevert|vm\.expectEmit|vm\.expectCall|"
    # Hardhat (chai)
    r"expect\([^)]+\)\.to\.(?:be|equal|revert|emit|have|deep|include)|"
    # Python unittest (legacy)
    r"assert\s*\.\s*(?:True|False|Equal|NotEqual)|"
    # Go
    r"t\.Fatal|t\.Error|t\.FailNow|t\.Fatalf|t\.Errorf|"
    r"assert\.\w+\(|require\.\w+\(",
    re.IGNORECASE,
)


_MECHANICAL_PASS_RE = re.compile(
    r"(?im)^\s*\**Mechanical-Verified\**\s*:\s*YES\b[^\n]*\bStatus\s*:\s*PASS\b"
)


def _mechanical_manifest_pass_ids(scratchpad: Path) -> set[str]:
    """Return finding IDs with Phase 5b PASS in mechanical manifest JSON."""
    path = scratchpad / "mechanical_verify_manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()
    out: set[str] = set()
    for item in data.get("results", []) or []:
        if str(item.get("status", "")).upper() == "PASS":
            fid = str(item.get("finding_id", "")).strip()
            if fid:
                out.add(fid)
    return out


def _validate_poc_pass_integrity(scratchpad: Path) -> list[dict[str, str]]:
    """Sanity-check [POC-PASS] claims for basic validity.

    Catches trivial assertions (assert!(true)) and missing assertions.
    Returns list of findings to downgrade from [POC-PASS] -> [CODE-TRACE].

    Per-ecosystem dispatch: reads `language` from `{scratchpad}/config.json`
    and selects the matching assertion vocabulary. Falls back to union regex
    if language is unset or unknown (back-compat).

    T1-a: when the Phase 5b `mechanical_verify` phase actually compiled and
    ran the finding's test file and stamped `Mechanical-Verified: YES —
    Status: PASS`, that execution is ground truth. The .md code-block scan
    below only sees the snippet pasted into the verify file, which routinely
    omits the assertion living in the real `.t.sol` — so it false-downgrades
    mechanically-proven passes. Mechanical PASS therefore overrides the scan.
    """
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []

    language = _read_language_from_config(scratchpad)
    dispatch = _resolve_assert_dispatch(language)
    any_re = dispatch["any"]
    nontrivial_re = dispatch["nontrivial"]
    trivial_strs = dispatch["trivial"]

    manifest_pass_ids = _mechanical_manifest_pass_ids(scratchpad)
    downgrades: list[dict[str, str]] = []
    for row in rows:
        fid = row.get("finding id", "")
        poc_class = row.get("poc class", "structural")
        if fid in manifest_pass_ids:
            continue

        verify_path = _find_verify_file(scratchpad, fid)
        if not verify_path:
            continue
        try:
            content = verify_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        has_mechanical_tag = has_mechanical_proof(content)
        if not has_mechanical_tag:
            continue

        # T1-a: a mechanical PASS (Phase 5b ran the real test file) is
        # authoritative — never downgrade it from a .md snippet scan.
        if _MECHANICAL_PASS_RE.search(content):
            continue

        code_blocks = re.findall(r"```(?:rust|go|python|solidity|javascript|typescript|move|toml)?\s*\n(.*?)```", content, re.DOTALL)
        if not code_blocks:
            continue

        all_code = "\n".join(code_blocks)

        has_any_assert = bool(any_re.search(all_code))

        if not has_any_assert:
            if "#[should_panic]" not in all_code and "should_panic" not in all_code:
                downgrades.append({
                    "finding_id": fid,
                    "reason": "No assertion found in PoC code — downgrade to [CODE-TRACE]",
                    "poc_class": poc_class,
                })
            continue

        has_nontrivial = bool(nontrivial_re.search(all_code))
        if not has_nontrivial:
            code_normalized = re.sub(r"\s+", "", all_code.lower())
            is_trivial = any(
                t.replace(" ", "").lower() in code_normalized for t in trivial_strs
            )
            if is_trivial:
                downgrades.append({
                    "finding_id": fid,
                    "reason": "Trivial assertion only (assert!(true) or equivalent) — downgrade to [CODE-TRACE]",
                    "poc_class": poc_class,
                })

    return downgrades


# ---------------------------------------------------------------------------
# T2-a: verifier skip-vocabulary audit (WARNING-class)
# ---------------------------------------------------------------------------

_MOCK_IDENT_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]*(?:Mock|Stub|Fake|Harness)\b")
_VERIFY_CODE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def _build_succeeded(scratchpad: Path) -> Optional[bool]:
    """Read build_status.md and report whether the project build succeeded.

    Returns True/False when the status is determinable, None otherwise.
    """
    bs = scratchpad / "build_status.md"
    if not bs.exists():
        return None
    try:
        text = bs.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    m = re.search(
        r"(?im)^\s*\**(?:build\s+)?status\**\s*:\s*\**\s*([A-Za-z_ ]+)", text
    )
    if m:
        v = m.group(1).strip().lower()
        if v.startswith(("success", "ok", "pass", "compiled")):
            return True
        if "fail" in v or "error" in v:
            return False
    tl = text.lower()
    if "compiled successfully" in tl or "build: success" in tl:
        return True
    if "build failed" in tl or "compilation failed" in tl:
        return False
    return None


def _project_mock_feasible(
    scratchpad: Path, verify_cache: Optional[dict] = None
) -> tuple[bool, str]:
    """Is mocking demonstrably feasible in this project?

    True when any *passing* verify file's code blocks reference a
    `*Mock`/`*Stub`/`*Fake`/`*Harness` identifier. Single source of the
    feasibility signal, shared by the per-shard PoC contract (hard gate,
    Medium+) and the aggregate skip-vocabulary audit (WARN-class). When
    `verify_cache` is supplied it is populated with every read verify file so
    the caller can reuse the content without re-reading.
    """
    try:
        rows = parse_verification_queue_rows(scratchpad)
    except Exception:
        return (False, "")
    feasible = False
    example = ""
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        vp = _find_verify_file(scratchpad, fid)
        if not vp:
            continue
        try:
            content = vp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if verify_cache is not None:
            verify_cache[fid] = content
        if not feasible and has_mechanical_proof(content):
            code = "\n".join(_VERIFY_CODE_BLOCK_RE.findall(content))
            mm = _MOCK_IDENT_RE.search(code)
            if mm:
                feasible = True
                example = mm.group(0)
    return (feasible, example)


def _validate_verifier_skip_vocabulary(scratchpad: Path) -> list[str]:
    """T2-a (WARNING-class): catch invalid PoC-skip reasons in verify files.

    Four mechanical checks. Emits warnings and writes verifier_skip_audit.md;
    NEVER blocks the gate. The recall lever is the strengthened verification
    prompt preconditions — this is the observability safety net.

      Check 1 — mock-consistency: a verify file that skips with
        EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS citing a missing mock, while
        another passing test in the same project demonstrably used a mock.
      Check 2 — NO_BUILD_ENVIRONMENT cited while build_status.md = SUCCESS.
      Check 3 — DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL on a unit-class
        finding (unit-class is harness-testable by definition).
      Check 4 — empty / N/A skip reason on a unit-class finding.
    """
    rows = parse_verification_queue_rows(scratchpad)
    if not rows:
        return []
    build_ok = _build_succeeded(scratchpad)

    # Pass 1: is mocking demonstrably feasible in this project? Shared signal,
    # populates verify_cache for the per-row checks below (single source).
    verify_cache: dict[str, str] = {}
    mock_feasible, mock_example = _project_mock_feasible(scratchpad, verify_cache)

    warnings: list[str] = []
    audit_rows: list[str] = []
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        content = verify_cache.get(fid)
        if not content:
            continue
        poc_class = (row.get("poc class") or "structural").strip().lower()
        attempted_no = _poc_attempted_value(content) == "NO"
        skip_code = _poc_skip_code(content)
        if not attempted_no and not skip_code:
            continue  # PoC was attempted — nothing to audit

        invalid: Optional[str] = None
        if "NO_BUILD_ENVIRONMENT" in skip_code and build_ok is True:
            invalid = (
                "NO_BUILD_ENVIRONMENT cited but build_status.md reports a "
                "SUCCESSFUL build — the harness exists"
            )
        elif (
            "DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL" in skip_code
            and poc_class == "unit"
        ):
            invalid = (
                "DEPLOYMENT_ONLY_REQUIRES_LIVE_EXTERNAL cited on a unit-class "
                "finding — unit-class is harness-testable by definition"
            )
        elif (
            poc_class == "unit"
            and attempted_no
            and skip_code in ("", "N/A", "NA", "NONE")
        ):
            invalid = (
                "unit-class finding skipped with an empty / N/A reason — no "
                "real environmental blocker named"
            )
        elif (
            "EXTERNAL_DEPENDENCY_NO_FORK" in skip_code
            and mock_feasible
            and re.search(r"\bmock\b", content, re.IGNORECASE)
        ):
            invalid = (
                "EXTERNAL_DEPENDENCY_NO_FORK_OR_ADDRESS skip cites a missing "
                f"mock, but mocking is demonstrably feasible here (a passing "
                f"test used `{mock_example}`)"
            )

        if invalid:
            warnings.append(f"{fid}: {invalid}")
            audit_rows.append(
                f"| {fid} | {poc_class} | {skip_code or 'N/A'} | {invalid} |"
            )

    if audit_rows:
        try:
            (scratchpad / "verifier_skip_audit.md").write_text(
                "# Verifier Skip-Reason Audit (T2-a)\n\n"
                "WARNING-class. Each row is a PoC skip whose reason fails a "
                "mechanical validity check — the PoC should have been "
                "attempted.\n\n"
                "| Finding | PoC Class | Skip Code | Why Invalid |\n"
                "|---|---|---|---|\n" + "\n".join(audit_rows) + "\n",
                encoding="utf-8",
            )
        except Exception:
            pass
    return warnings
