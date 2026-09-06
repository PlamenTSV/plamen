from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from collections import Counter
import hashlib
import json
import logging
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from bounded_artifact_io import (
    BoundedNamespaceCaptureError,
    read_bounded_regular_bytes,
    retain_bounded_regular_namespace,
)
from artifact_ledger import (
    ArtifactLedgerError,
    authorize_deterministic_work_unit_reexecution,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_input_prebind_producer_authority_issues,
    stored_committed_work_unit_authority_issues,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract

from coverage_shortfalls import (
    coverage_shortfalls_projection,
    replace_producer_shortfalls,
    shortfall,
    unknown_shortfall,
)
from finding_producer_registry import (
    ProducerResolutionError,
    classify_producer_id as _classify_producer_id,
    producer_for_artifact as _registered_producer_for_artifact,
    producer_numeric_id_pattern as _registered_numeric_id_pattern,
    producer_read_id_pattern as _registered_producer_read_id_pattern,
    producer_patterns as _registered_producer_patterns,
    read_registered_enumeration_obligations as _read_registered_enumeration_obligations,
    read_registered_typed_actions as _read_registered_typed_actions,
    render_delivery_human_review_projection as _render_delivery_human_review_projection,
    resolve_effective_scopes as _resolve_effective_scopes,
)
from skill_selection_authority import strip_recon_transport_markers
from security_obligation_authority import (
    read_queueable_security_obligations as _read_queueable_security_obligations,
    write_security_obligation_authority as _write_security_obligation_authority,
)
from report_evidence_authority import (
    ReportEvidenceError as _ReportEvidenceError,
    materialize_report_evidence_runtime as _materialize_report_evidence_runtime,
    project_report_evidence_markdown as _project_report_evidence_markdown,
    validate_report_evidence_bundle as _validate_report_evidence_bundle,
)
from report_mutation_transaction import (
    ReportMutationTransactionError as _ReportMutationTransactionError,
    apply_report_mutation_transaction as _apply_report_mutation_transaction,
    capture_report_transaction_inputs as _capture_report_transaction_inputs,
    recover_report_mutation_transaction as _recover_report_mutation_transaction,
    report_mutation_transaction_state as _report_mutation_transaction_state,
)
from preverify_inventory_successor import (
    DELIVERY_RECEIPT_NAME as PREVERIFY_DELIVERY_SUCCESSOR_NAME,
    FINAL_RECEIPT_NAME as PREVERIFY_INVENTORY_SUCCESSOR_NAME,
    validate_preverify_successor_payloads,
)
from preverify_projection_authority import (
    resolve_active_preverify_projection,
    PreverifyProjectionAuthorityError,
    successor_projection_present,
)
from niche_lifecycle_authority import (
    NicheLifecycleAuthorityError as _NicheLifecycleAuthorityError,
    action_denominator_records as _niche_lifecycle_action_records,
    commit_niche_lifecycle_generation as _commit_niche_lifecycle_generation,
    load_current_niche_lifecycle as _load_current_niche_lifecycle,
    niche_lifecycle_context as _niche_lifecycle_context,
    _discard_niche_inventory_publication_capability,
    _publish_niche_inventory_with_capability as _issue_niche_inventory_publication_capability,
    projection_binding as _niche_lifecycle_projection_binding,
    validate_projection_binding as _validate_niche_lifecycle_projection,
)
from operational_markdown import operational_markdown_view
from plamen_markdown import mapped_headings

from plamen_types import *  # noqa: F403,F401
import plamen_parsers as _parsers
from plamen_parsers import *  # noqa: F403,F401
from plamen_parsers import (
    FINDING_ARTIFACT_MAX_BYTES as _SHARED_FINDING_ARTIFACT_MAX_BYTES,
    FindingArtifactLimitError as _FindingArtifactLimitError,
    _EXPLICIT_FINDING_HEADING_RE,
    _canonical_finding_blocks,
    _OPTIONAL_FINDING_METADATA_FIELDS,
    _OPTIONAL_FINDING_METADATA_LABELS,
    _QUALITY_CLASS_TITLES,
    _queue_rows_from_inventory_with_exclusions,
    _read_finding_artifact_bytes,
    _write_queue_subset_manifest,
    classify_quality_observation,
)
from plamen_validators import *  # noqa: F403,F401
from plamen_validators import (  # explicit private helpers used by SC index repair
    _collect_judge_unresolved_ids,
    _expected_report_index_severities,
    _inventory_structural_source_referents,
    _promote_injectable_rows,
    _reconcile_skill_manifest_sources,
    _report_index_adjustment_reason_present,
    _verifier_output_has_completion_authority,
    _verification_runtime_debt_coverage,
)

__all__ = [
    "CanonicalMergeAuthorityError",
    "_ATTENTION_REPAIR_MAX_ITEMS",
    "_records_from_inventory_text",
    "enforce_material_harm_floor",
    "_apply_location_recovery",
    "_apply_mechanical_dedup_from_pairs",
    "_apply_merges_to_inventory",
    "_extract_dedup_absorbed_ids",
    "apply_llm_dedup_decisions",
    "_apply_llm_group_decisions",
    "_parse_dedup_group_lines",
    "_DEDUP_GROUP_LINE_RE",
    "_DEDUP_ID_TOKEN_RE",
    "_stamp_dedup_group_note",
    "_dedup_parse_finding_info",
    "_dedup_survivor_superset_ok",
    "_resolve_dedup_survivor",
    "_provenance_class_tokens",
    "write_mechanism_attribution_ledger",
    "backfill_unrouted_inventory_into_queue",
    "_assemble_report_python",
    "_dedup_report_python",
    "_dedup_report_sections",
    "_dedup_report_candidate_pairs",
    "build_dedup_cluster_map",
    "_detect_dedup_report_clusters",
    "_dedup_data_loss_gate",
    "_reclassify_cosmetic_low_info_to_qo",
    "_finding_own_block",
    "_qo_one_line_desc",
    "_append_quality_observation_rows",
    "_dedup_title_jaccard",
    "_defined_report_section_ids",
    "_build_human_review_appendix",
    "_build_attention_repair_items",
    "_build_body_writer_manifests",
    "_build_sc_body_writer_manifests",
    "_collect_raw_candidate_ledger_rows",
    "_extract_source_ids_from_inventory",
    "_finalize_report_tier_section",
    "_count_inventory_source_signals",
    "_extract_graph_attention_rows",
    "_inventory_location_map",
    "_inventory_source_files",
    "_location_recovery_needed",
    "_normalize_breadth_outputs",
    "_merge_recon_worker_shards",
    "validate_recon_direct_retry_launch_authority",
    "_patch_report_index_with_recovered",
    "_path_security_weight",
    "_prepare_attention_repair",
    "_repair_promotion_dropouts",
    "_repair_report_body_from_assignments",
    "_repair_report_body_from_manifest",
    "_repair_sc_report_index_from_prior",
    "_tag_report_index_unresolved_sections",
    "_shard_name_for_severity",
    "_synth_report_section_from_verify",
    "_synthesize_components_audited",
    "_write_attention_repair_queue",
    "_write_obligation_ledger",
    "_allocate_inventory_ledger_id",
    "_write_canonical_finding_identity_map",
    "_write_candidate_semantic_facets",
    "_write_finding_records_from_inventory",
    "_write_attention_repair_skip",
    "_write_security_obligations",
    "_write_spec_expectations",
    "_write_location_recovery_skip",
    "_write_mechanical_inventory_from_chunks",
    "_render_inventory_from_merged_entries",
    "ensure_findings_inventory_floor",
    "_write_mechanical_report_index",
    "read_niche_identity_debt_sidecar",
    "promote_niche_to_inventory",
    "promote_blind_spot_to_inventory",
    "strip_codex_prepass_markers",
    "_write_mechanical_report_tier",
    "ensure_inventory_shard_plan",
    "ensure_rescan_manifest",
    "estimate_rate_limit_wait_seconds",
    "hibernation_disabled",
    "maybe_hibernate_on_rate_limit",
    "maybe_resume_hibernation",
    "write_hibernation_marker",
    "write_inventory_chunk_placeholder",
    "write_report_tier_placeholder",
    "compute_promotion_orphans",
    "promotion_reconciled_subjects",
    "route_promotion_orphans",
]


_RECON_CANONICAL_OUTPUTS = (
    "recon_summary.md",
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
)

_L1_RECON_CANONICAL_OUTPUTS = (
    "recon_summary.md",
    "threat_model.md",
    "subsystem_map.md",
    "attack_surface.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "scope_leftover.md",
)

_PREPASS_MARKER = "<!-- plamen-prepass v1: mechanical pre-pass output; safe to overwrite while marker is present -->"


def _strip_recon_worker_markers(text: str) -> str:
    """Remove worker transport comments while preserving typed authority.

    P1-J: ``PLAMEN_SIGNALS`` is not lifecycle decoration.  The prior broad
    ``PLAMEN_*`` regex deleted the only exact-polarity skill-selection channel
    during canonical merge.  The shared helper uses a closed transport-marker
    allowlist and retains even malformed signals for loud downstream debt.
    """
    stripped, _receipt = strip_recon_transport_markers(text)
    return stripped.strip()


def _strip_prepass_marker(text: str) -> str:
    """Remove pre-pass overwrite provenance from merged canonical handoffs."""
    if not text:
        return ""
    lines = text.splitlines()
    if lines and lines[0].strip() == _PREPASS_MARKER:
        return "\n".join(lines[1:]).lstrip()
    return text


def strip_codex_prepass_markers(scratchpad: Path) -> list[str]:
    """Codex-only: drop the line-1 pre-pass marker from recon artifacts whose
    body holds durable content.

    The recon content gate treats a surviving line-1 ``_PREPASS_MARKER`` as
    proof that recon never produced a durable canonical handoff. That proxy is
    valid under Claude's whole-file ``Write`` (which always replaces line 1),
    but Codex's ``apply_patch`` makes targeted body edits that leave line 1
    untouched -- so a legitimately-enriched file keeps the marker and
    false-fails the gate, costing a full recon retry on every Codex run. The
    marker's real purpose is pre-pass resume idempotency, which is fully served
    once the recon phase has run.

    Recall-safe: only the line-1 comment is removed, never content. A file whose
    body is still a pure ``[LLM TO ENRICH]`` placeholder (pre-pass populated
    nothing real and recon did not enrich it) or is empty KEEPS its marker, so
    the gate still fails and forces a retry. Mechanically-populated files (real
    regex-extracted tables) and LLM-enriched files both have real bodies and get
    the marker stripped.

    Returns the list of artifact names whose marker was stripped.
    """
    stripped: list[str] = []
    for name in _RECON_CANONICAL_OUTPUTS:
        path = scratchpad / name
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        lines = text.splitlines()
        if lines[:1] != [_PREPASS_MARKER]:
            continue  # already enriched (marker gone) or no marker present
        body = "\n".join(lines[1:])
        if not body.strip() or "[LLM TO ENRICH]" in body:
            continue  # placeholder/empty -- keep marker so the gate still fails
        try:
            path.write_text(body.lstrip("\n").rstrip() + "\n", encoding="utf-8")
            stripped.append(name)
        except Exception:
            continue
    return stripped


def _render_l1_recon_worker_shards(
    scratchpad: Path,
    config: dict,
) -> list[str]:
    """Project isolated L1 recon leaves into the stable L1 handoff schema."""
    mode = str(config.get("mode") or "core").lower()
    jobs = (
        (
            ("l1_threat_fork", "recon_l1_threat_fork.md"),
            ("l1_subsystem_attack_trust", "recon_l1_subsystem_attack_trust.md"),
            ("l1_build_templates", "recon_l1_build_templates.md"),
        )
        if mode == "light"
        else (
            ("l1_threat_fork", "recon_l1_threat_fork.md"),
            ("l1_subsystem_scope", "recon_l1_subsystem_scope.md"),
            ("l1_attack_trust", "recon_l1_attack_trust.md"),
            ("l1_build_static", "recon_l1_build_static.md"),
            ("l1_templates_patterns", "recon_l1_templates_patterns.md"),
        )
    )
    shards: dict[str, str] = {}
    transforms: list[dict[str, Any]] = []
    for role, name in jobs:
        path = scratchpad / name
        raw = ""
        if path.is_file():
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                raw = ""
        stripped, transform = strip_recon_transport_markers(raw)
        shards[role] = stripped.strip()
        transforms.append({"source": name, "role": role, **transform})

    transform_receipt = {
        "schema": "plamen.recon_signal_transform_set.v1",
        "pipeline": "l1",
        "mode": mode,
        "ecosystem": str(config.get("language") or "unknown"),
        "transforms": sorted(transforms, key=lambda row: row["source"]),
    }
    transform_receipt["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            transform_receipt,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest().upper()
    (scratchpad / "recon_signal_transform_receipt.json").write_text(
        json.dumps(
            transform_receipt,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    def _join(*roles: str) -> str:
        parts = [shards.get(role, "").strip() for role in roles]
        return "\n\n".join(part for part in parts if part)

    threat = _join("l1_threat_fork")
    subsystem = _join("l1_subsystem_scope", "l1_subsystem_attack_trust")
    attack_trust = _join("l1_attack_trust", "l1_subsystem_attack_trust")
    build = _join("l1_build_static", "l1_build_templates")
    templates = _join("l1_templates_patterns", "l1_build_templates")

    def _body_or_debt(body: str, label: str) -> str:
        if body.strip():
            return body.strip()
        return (
            f"No {label} shard evidence was committed. This is explicit recon "
            "debt and must not be interpreted as evidence of safety or coverage."
        )

    def _write(name: str, title: str, sections: list[tuple[str, str]]) -> None:
        chunks = [f"# {title}", ""]
        for section_title, body in sections:
            chunks.extend(
                [
                    f"## {section_title}",
                    "",
                    _body_or_debt(body, section_title.lower()),
                    "",
                ]
            )
        text = "\n".join(chunks).rstrip() + "\n"
        if len(text.encode("utf-8", errors="ignore")) < 120:
            text += (
                "\n## Handoff Status\n\n"
                "This deterministic projection preserves the available L1 recon "
                "evidence and exposes missing worker evidence as explicit debt.\n"
            )
        (scratchpad / name).write_text(text, encoding="utf-8", newline="\n")

    _write(
        "threat_model.md",
        "L1 Threat Model",
        [
            ("Consensus, Fork, Safety, and Liveness Evidence", threat),
            (
                "Unresolved Assumption Policy",
                "Every externally defined or unconfirmed premise remains "
                "unresolved until a later evidence-producing phase confirms it.",
            ),
        ],
    )
    _write(
        "subsystem_map.md",
        "L1 Subsystem Map",
        [
            ("Subsystem and Source Denominator", subsystem),
            (
                "Composition Boundary",
                "Downstream analysis must trace state and control across every "
                "cited subsystem seam rather than treating modules in isolation.",
            ),
        ],
    )
    _write(
        "attack_surface.md",
        "L1 Attack Surface",
        [("Externally Reachable and Composed Surfaces", attack_trust)],
    )
    _write(
        "trust_boundaries.md",
        "L1 Trust Boundaries",
        [
            ("Privilege, Peer, Input, and Persistence Boundaries", attack_trust),
            (
                "Threat-Model Cross-Reference",
                threat,
            ),
        ],
    )
    _write(
        "template_recommendations.md",
        "L1 Template Recommendations",
        [
            ("Risk-Pattern and Skill Signals", templates),
            ("Build and Static Capability Context", build),
        ],
    )
    _write(
        "scope_leftover.md",
        "Scope Leftover",
        [
            ("Worker Scope Evidence", subsystem),
            (
                "Mechanical Leftover Roster",
                "| File | LOC | Reason | Acknowledged |\n"
                "|---|---:|---|---|\n"
                "\n"
                "No leftover row is fabricated by the merge. Coverage gates may "
                "append mechanically enumerated uncited files for human review.",
            ),
        ],
    )

    summary = [
        "# L1 Recon Summary",
        "",
        "## Run Context",
        "",
        "- Pipeline: l1",
        f"- Mode: {mode}",
        f"- Language: {config.get('language', 'unknown')}",
        f"- Project root: `{config.get('project_root') or ''}`",
        "",
        "## Transactional Worker Coverage",
        "",
    ]
    for role, name in jobs:
        path = scratchpad / name
        size = 0
        if path.is_file():
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
        state = f"present ({size} bytes)" if size else "missing (explicit debt)"
        summary.append(f"- `{role}` -> `{name}`: {state}")
    summary.extend(
        [
            "",
            "## Canonical Handoff",
            "",
            "The Python driver deterministically projected isolated, "
            "single-writer recon leaves into the seven L1 canonical artifacts. "
            "Transport markers were removed, machine-readable selection signals "
            "were preserved, and absent evidence was surfaced as debt rather than "
            "converted into a safety conclusion.",
            "",
            "## Build and Primitive Capability Evidence",
            "",
            _body_or_debt(build, "build/static capability"),
            "",
            "## Threat and Fork-Safety Evidence",
            "",
            _body_or_debt(threat, "threat/fork"),
            "",
            "## Subsystem, Attack, and Trust Evidence",
            "",
            _body_or_debt(
                "\n\n".join(part for part in (subsystem, attack_trust) if part),
                "subsystem/attack/trust",
            ),
            "",
            "## Template and Pattern Evidence",
            "",
            _body_or_debt(templates, "template/pattern"),
            "",
        ]
    )
    (scratchpad / "recon_summary.md").write_text(
        "\n".join(summary).rstrip() + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return list(_L1_RECON_CANONICAL_OUTPUTS)


def _render_recon_worker_shards(scratchpad: Path, config: dict) -> list[str]:
    """Merge driver-owned recon worker shards into canonical recon artifacts.

    The worker-pool architecture deliberately forbids recon workers from
    writing canonical phase outputs or later-phase files. This merge is the
    single deterministic bridge back to the existing pipeline contract: all
    downstream phases still see the same recon file names and formats, while
    recon itself gets the documented multi-role coverage without a coordinator
    session that can leak into instantiate/breadth/depth.

    Existing deterministic prepass artifacts are preserved and enriched rather
    than replaced. That keeps Slither/OpenGrep/parser-derived inventories as the
    authority when present and uses the LLM shards as contextual analysis.
    """
    if str(config.get("pipeline") or "sc").lower() == "l1":
        return _render_l1_recon_worker_shards(scratchpad, config)

    shard_names = (
        "recon_build_static.md",
        "recon_design_context.md",
        "recon_inventory_surface.md",
        "recon_templates_patterns.md",
    )
    shards: dict[str, str] = {}
    signal_transforms: list[dict[str, Any]] = []
    for name in shard_names:
        path = scratchpad / name
        if not path.exists():
            continue
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
            stripped, transform = strip_recon_transport_markers(raw)
            shards[name] = stripped.strip()
            signal_transforms.append({"source": name, **transform})
        except Exception:
            shards[name] = ""

    # Durable, timestamp-free transform proof.  A future signal family cannot
    # be silently stripped because each shard records exact before/after block
    # parity.  Missing mode-specific shards are absence, not invented empties.
    transform_receipt = {
        "schema": "plamen.recon_signal_transform_set.v1",
        "pipeline": str(config.get("pipeline") or "sc"),
        "mode": str(config.get("mode") or "core"),
        "ecosystem": str(config.get("language") or "unknown"),
        "transforms": sorted(signal_transforms, key=lambda row: row["source"]),
    }
    transform_receipt["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            transform_receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest().upper()
    (scratchpad / "recon_signal_transform_receipt.json").write_text(
        json.dumps(transform_receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Light mode has two merged roles. Map them into the four conceptual
    # buckets so the canonical synthesis below is mode-independent.
    build = shards.get("recon_build_static.md", "")
    design = shards.get("recon_design_context.md", "") or build
    inventory = shards.get("recon_inventory_surface.md", "")
    templates = shards.get("recon_templates_patterns.md", "") or inventory

    def _read_existing(name: str) -> str:
        path = scratchpad / name
        if not path.exists():
            return ""
        try:
            return _strip_prepass_marker(
                path.read_text(encoding="utf-8", errors="replace")
            ).strip()
        except Exception:
            return ""

    def _section(title: str, body: str) -> str:
        body = (body or "").strip()
        if not body:
            body = "No additional worker evidence was produced for this section."
        return f"## {title}\n\n{body}\n"

    def _existing_or_fallback(name: str, fallback_title: str, fallback_body: str) -> str:
        existing = _read_existing(name)
        if existing and len(existing.encode("utf-8", errors="ignore")) >= 100:
            return (
                existing.rstrip()
                + "\n\n"
                + _section("Recon Worker Addendum", fallback_body)
            ).strip()
        return (
            f"# {fallback_title}\n\n"
            + _section("Recon Worker Evidence", fallback_body)
        ).strip()

    def _write(name: str, text: str) -> None:
        text = text.strip() + "\n"
        if len(text.encode("utf-8", errors="ignore")) < 120:
            text += (
                "\n## Merge Note\n\n"
                "This file was generated by the deterministic recon worker "
                "merge. Downstream phases should treat it as a scoped recon "
                "handoff and inspect source files directly for confirmation.\n"
            )
        (scratchpad / name).write_text(text, encoding="utf-8")

    mode = str(config.get("mode") or "core")
    language = str(config.get("language") or "evm")
    project_root = str(config.get("project_root") or "")

    _write(
        "build_status.md",
        _existing_or_fallback(
            "build_status.md",
            "Build and Static Analysis Status",
            build,
        ),
    )

    design_text = _existing_or_fallback(
        "design_context.md",
        "Design Context",
        design,
    )
    if not re.search(r"(?im)^#+\s+.*operational\s+implications", design_text):
        design_text += (
            "\n\n## Operational Implications\n\n"
            "Recon workers did not isolate a separate operational implications "
            "section. Downstream agents must derive operational impact from the "
            "design, inventory, dependency, and attack-surface evidence above.\n"
        )
    if not re.search(r"(?im)^#+\s+.*invariant", design_text):
        design_text += (
            "\n\n## Key Invariants\n\n"
            "Recon workers did not isolate a separate invariant list. Breadth "
            "and depth agents must derive protocol invariants from entry points, "
            "state transitions, accounting flows, permissions, and external "
            "dependencies in the recon artifacts.\n"
        )
    _write("design_context.md", design_text)

    _write(
        "attack_surface.md",
        _existing_or_fallback(
            "attack_surface.md",
            "Attack Surface",
            inventory,
        ),
    )
    _write(
        "contract_inventory.md",
        _existing_or_fallback(
            "contract_inventory.md",
            "Contract Inventory",
            inventory,
        ),
    )
    _write(
        "function_list.md",
        _existing_or_fallback(
            "function_list.md",
            "Function List",
            inventory,
        ),
    )
    _write(
        "state_variables.md",
        _existing_or_fallback(
            "state_variables.md",
            "State Variables",
            inventory,
        ),
    )
    _write(
        "setter_list.md",
        _existing_or_fallback(
            "setter_list.md",
            "Setter List",
            inventory,
        ),
    )
    _write(
        "emit_list.md",
        _existing_or_fallback(
            "emit_list.md",
            "Event Emission List",
            inventory,
        ),
    )
    _write(
        "detected_patterns.md",
        _existing_or_fallback(
            "detected_patterns.md",
            "Detected Patterns",
            templates or inventory,
        ),
    )
    _write(
        "template_recommendations.md",
        _existing_or_fallback(
            "template_recommendations.md",
            "Template Recommendations",
            templates or inventory,
        ),
    )

    summary_parts = [
        "# Recon Summary",
        "",
        "## Run Context",
        "",
        f"- Pipeline: {config.get('pipeline', 'sc')}",
        f"- Mode: {mode}",
        f"- Language: {language}",
        f"- Project root: `{project_root}`",
        "",
        "## Worker Coverage",
        "",
    ]
    for name in shard_names:
        path = scratchpad / name
        if path.exists():
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            summary_parts.append(f"- `{name}`: present ({size} bytes)")
        else:
            summary_parts.append(f"- `{name}`: not present in this mode")
    summary_parts.extend([
        "",
        "## Canonical Handoff",
        "",
        "The Python driver merged isolated recon worker shards into the canonical "
        "recon artifacts consumed by instantiate, breadth, depth, verification, "
        "and report phases. Recon workers did not write later-phase artifacts.",
        "",
        "## Key Evidence Pointers",
        "",
        "Breadth and depth agents should read `design_context.md`, "
        "`attack_surface.md`, `contract_inventory.md`, `function_list.md`, "
        "`state_variables.md`, `detected_patterns.md`, and "
        "`template_recommendations.md` before deriving analysis scope.",
        "",
        _section("Build/Static Worker Summary", build)[:5000],
        "",
        _section("Design Worker Summary", design)[:5000],
        "",
        _section("Inventory Worker Summary", inventory)[:5000],
        "",
        _section("Template/Pattern Worker Summary", templates)[:5000],
    ])
    _write("recon_summary.md", "\n".join(summary_parts))
    return list(_RECON_CANONICAL_OUTPUTS)


_RECON_TRANSFORM_RECEIPT = "recon_signal_transform_receipt.json"
_CANONICAL_MERGE_TIMEOUT_SECONDS = 30
_CANONICAL_RETRY_ROOT = "_canonical_retry_generation/recon"


class CanonicalMergeAuthorityError(RuntimeError):
    """The deterministic recon merge could not establish typed authority."""


def _canonical_merge_stable_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _canonical_merge_dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    mode = str(config.get("mode") or "core").strip().lower()
    language = str(config.get("language") or "unknown").strip().lower()
    ecosystem = {"solidity": "evm", "ethereum": "evm"}.get(language, language)
    backend = str(config.get("cli_backend") or "claude").strip().lower()
    return pipeline, mode, ecosystem, backend


def _canonical_merge_input_names(pipeline: str, mode: str) -> tuple[str, ...]:
    if pipeline == "l1":
        return (
            (
                "recon_l1_threat_fork.md",
                "recon_l1_subsystem_attack_trust.md",
                "recon_l1_build_templates.md",
            )
            if mode == "light"
            else (
                "recon_l1_threat_fork.md",
                "recon_l1_subsystem_scope.md",
                "recon_l1_attack_trust.md",
                "recon_l1_build_static.md",
                "recon_l1_templates_patterns.md",
            )
        )
    return (
        (
            "recon_build_static.md",
            "recon_inventory_surface.md",
        )
        if mode == "light"
        else (
            "recon_build_static.md",
            "recon_design_context.md",
            "recon_inventory_surface.md",
            "recon_templates_patterns.md",
        )
    )


def _canonical_merge_output_names(pipeline: str) -> tuple[str, ...]:
    canonical = (
        _L1_RECON_CANONICAL_OUTPUTS
        if pipeline == "l1"
        else _RECON_CANONICAL_OUTPUTS
    )
    return (*canonical, _RECON_TRANSFORM_RECEIPT)


def _canonical_merge_capture(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    input_names: tuple[str, ...],
) -> dict[str, Any]:
    worker_inputs: dict[str, str] = {}
    for name in input_names:
        path = scratchpad / name
        if not path.is_file() or path.is_symlink():
            raise CanonicalMergeAuthorityError(
                f"canonical merge input is absent or unsafe: {name}"
            )
        raw = path.read_bytes()
        if not raw:
            raise CanonicalMergeAuthorityError(
                f"canonical merge input is empty: {name}"
            )
        worker_inputs[name] = hashlib.sha256(raw).hexdigest()
    source_root = project_root / "src"
    source_records = {
        path.relative_to(source_root).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in sorted(source_root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    } if source_root.is_dir() else {}
    source_capture_digest = _canonical_merge_stable_digest(source_records)
    config_digest = _canonical_merge_stable_digest(dict(config))
    input_set_digest = _canonical_merge_stable_digest({
        "worker_inputs": worker_inputs,
        "source_capture_digest": source_capture_digest,
        "config_digest": config_digest,
    })
    return {
        "worker_inputs": worker_inputs,
        "source_capture_digest": source_capture_digest,
        "config_digest": config_digest,
        "input_set_digest": input_set_digest,
    }


def _canonical_merge_receipt_capture(scratchpad: Path) -> Mapping[str, Any] | None:
    path = scratchpad / _RECON_TRANSFORM_RECEIPT
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, TypeError, ValueError):
        return None
    capture = payload.get("authority_capture") if isinstance(payload, Mapping) else None
    return capture if isinstance(capture, Mapping) else None


def _canonical_merge_published_records(
    scratchpad: Path,
    output_names: tuple[str, ...],
    capture: Mapping[str, Any],
) -> dict[str, dict[str, Any]] | None:
    """Authenticate an all-new post-publish/pre-commit generation."""

    receipt_path = scratchpad / _RECON_TRANSFORM_RECEIPT
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, TypeError, ValueError):
        return None
    if not isinstance(receipt, dict) or receipt.get("authority_capture") != capture:
        return None
    stored_receipt_digest = receipt.get("artifact_sha256")
    unsigned = dict(receipt)
    unsigned.pop("artifact_sha256", None)
    expected_receipt_digest = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest().upper()
    if stored_receipt_digest != expected_receipt_digest:
        return None
    output_hashes = receipt.get("canonical_output_sha256")
    canonical_names = output_names[:-1]
    if not isinstance(output_hashes, dict) or set(output_hashes) != set(canonical_names):
        return None
    records: dict[str, dict[str, Any]] = {}
    for name in output_names:
        path = scratchpad / name
        if not path.is_file() or path.is_symlink():
            return None
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if name != _RECON_TRANSFORM_RECEIPT and output_hashes.get(name) != digest:
            return None
        records[f"scratchpad:{name}"] = {
            "sha256": digest,
            "size": len(raw),
        }
    return records


def _canonical_merge_bound_generation_state(
    scratchpad: Path,
    prior: Mapping[str, Any],
    output_names: tuple[str, ...],
) -> str:
    """Classify a bound generation as all-old, all-new, or mixed."""

    prestates = prior.get("output_prestates")
    if not isinstance(prestates, Mapping):
        return "mixed"
    old = 0
    new = 0
    for name in output_names:
        identity = f"scratchpad:{name}"
        prestate = prestates.get(identity)
        if not isinstance(prestate, Mapping):
            return "mixed"
        path = scratchpad / name
        exists = path.is_file() and not path.is_symlink()
        existed = prestate.get("existed") is True
        if not exists and not existed:
            old += 1
            continue
        if exists and existed:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest == prestate.get("sha256"):
                old += 1
                continue
        new += 1
    if old == len(output_names):
        return "all_old"
    if new == len(output_names):
        return "all_new"
    return "mixed"


def _canonical_retry_regular_bytes(path: Path, *, label: str) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise CanonicalMergeAuthorityError(
            f"canonical retry {label} is absent or unsafe"
        )
    raw = path.read_bytes()
    if not raw or len(raw) > 16 * 1024 * 1024:
        raise CanonicalMergeAuthorityError(
            f"canonical retry {label} is empty or unbounded"
        )
    return raw


def _canonical_retry_plan(
    scratchpad: Path,
    *,
    run_id: str,
    output_names: tuple[str, ...],
) -> tuple[dict[str, Any], bytes] | None:
    path = scratchpad / "recon_retry_plan.json"
    if not path.exists():
        return None
    raw = _canonical_retry_regular_bytes(path, label="plan")
    try:
        plan = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalMergeAuthorityError(
            f"canonical retry plan is not JSON: {exc}"
        ) from exc
    required = plan.get("required_output_schema") if isinstance(plan, dict) else None
    failures = plan.get("failed_predicates") if isinstance(plan, dict) else None
    required_names = {
        str(row.get("pattern") or "")
        for row in required
        if isinstance(row, Mapping)
    } if isinstance(required, list) else set()
    canonical_names = set(output_names[:-1])
    if (
        not isinstance(plan, dict)
        or plan.get("schema") != "plamen.retry-plan/v1"
        or plan.get("run_id") != run_id
        or plan.get("phase_name") != "recon"
        or plan.get("work_unit_id") != "phase"
        or plan.get("attempt") != 2
        or plan.get("semantic_retry") is not True
        or required_names != canonical_names
        or not isinstance(failures, list)
        or not failures
        or any(
            not isinstance(row, Mapping)
            or not str(row.get("gate_id") or "").startswith("recon.")
            or row.get("contract_digest") != plan.get("contract_digest")
            for row in failures
        )
    ):
        raise CanonicalMergeAuthorityError(
            "canonical retry plan does not authorize this exact recon generation"
        )
    return plan, raw


def _canonical_retry_bundle_records(
    bundle: Path,
    manifest: Mapping[str, Any],
    *,
    output_names: tuple[str, ...],
) -> tuple[tuple[str, ...], dict[str, bytes]]:
    expected_candidates = set(output_names[:-1])
    expected_predecessors = set(output_names)
    candidates = manifest.get("candidate_records")
    predecessors = manifest.get("predecessor_records")
    if (
        not isinstance(candidates, Mapping)
        or set(candidates) != expected_candidates
        or not isinstance(predecessors, Mapping)
        or set(predecessors) != expected_predecessors
    ):
        raise CanonicalMergeAuthorityError(
            "canonical retry bundle output denominator is malformed"
        )
    candidate_bytes: dict[str, bytes] = {}
    for directory, rows in (("candidate", candidates), ("predecessor", predecessors)):
        for name, record in rows.items():
            raw = _canonical_retry_regular_bytes(
                bundle / directory / str(name),
                label=f"bundle {directory}/{name}",
            )
            if (
                not isinstance(record, Mapping)
                or record.get("sha256") != hashlib.sha256(raw).hexdigest()
                or record.get("size") != len(raw)
            ):
                raise CanonicalMergeAuthorityError(
                    f"canonical retry bundle bytes changed: {directory}/{name}"
                )
            if directory == "candidate":
                candidate_bytes[str(name)] = raw
    plan_raw = _canonical_retry_regular_bytes(
        bundle / "retry_plan.json", label="bundled plan"
    )
    if manifest.get("retry_plan_sha256") != hashlib.sha256(plan_raw).hexdigest():
        raise CanonicalMergeAuthorityError("canonical retry bundled plan changed")
    prompt_raw = _canonical_retry_regular_bytes(
        bundle / "prompt.md", label="bundled prompt"
    )
    transcript_raw = _canonical_retry_regular_bytes(
        bundle / "transcript.log", label="bundled transcript"
    )
    if (
        manifest.get("prompt_sha256") != hashlib.sha256(prompt_raw).hexdigest()
        or manifest.get("transcript_sha256")
        != hashlib.sha256(transcript_raw).hexdigest()
    ):
        raise CanonicalMergeAuthorityError(
            "canonical retry supervised-attempt evidence changed"
        )
    manifest_name = bundle.relative_to(bundle.parents[2]).as_posix()
    input_names = tuple(manifest.get("input_names") or ())
    expected_inputs = tuple(
        [
            *(f"{manifest_name}/candidate/{name}" for name in output_names[:-1]),
            *(f"{manifest_name}/predecessor/{name}" for name in output_names),
            f"{manifest_name}/retry_plan.json",
            f"{manifest_name}/prompt.md",
            f"{manifest_name}/transcript.log",
            f"{manifest_name}/manifest.json",
        ]
    )
    if input_names != expected_inputs:
        raise CanonicalMergeAuthorityError(
            "canonical retry bundle input denominator changed"
        )
    return input_names, candidate_bytes


def _canonical_retry_generation(
    *,
    scratchpad: Path,
    ledger: Mapping[str, Any],
    prior: Mapping[str, Any],
    contract: Any,
    run_id: str,
    output_names: tuple[str, ...],
    supervised_attempt: int | None = None,
) -> dict[str, Any] | None:
    """Return a sealed retry projection, or a pending quarantine sentinel."""

    plan_result = _canonical_retry_plan(
        scratchpad, run_id=run_id, output_names=output_names
    )
    if plan_result is None:
        return None
    plan, plan_raw = plan_result
    evidence_attempt = (
        supervised_attempt
        if type(supervised_attempt) is int
        else plan.get("attempt")
    )
    if type(evidence_attempt) is not int or evidence_attempt < 2:
        raise CanonicalMergeAuthorityError(
            "canonical retry supervised attempt ordinal is invalid"
        )
    expected_identities = tuple(f"scratchpad:{name}" for name in output_names)
    historical_issues = stored_committed_work_unit_authority_issues(
        ledger,
        work_unit_key=contract.key,
        run_id=run_id,
        expected_artifact_identities=expected_identities,
    )
    if historical_issues:
        raise CanonicalMergeAuthorityError(
            "canonical retry predecessor authority does not replay: "
            + "; ".join(historical_issues)
        )
    commit = prior.get("commit_authority")
    prior_attempt = commit.get("attempt_ordinal") if isinstance(commit, Mapping) else None
    if type(prior_attempt) is not int or prior_attempt < 1:
        raise CanonicalMergeAuthorityError(
            "canonical retry predecessor attempt is invalid"
        )
    attempt = prior_attempt + 1
    bundle_relative = f"{_CANONICAL_RETRY_ROOT}/attempt-{attempt}"
    bundle = scratchpad / bundle_relative
    manifest_path = bundle / "manifest.json"
    if manifest_path.exists():
        raw = _canonical_retry_regular_bytes(manifest_path, label="bundle manifest")
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise CanonicalMergeAuthorityError(
                f"canonical retry bundle manifest is not JSON: {exc}"
            ) from exc
        unsigned = dict(manifest) if isinstance(manifest, dict) else {}
        claimed = unsigned.pop("manifest_sha256", None)
        if (
            claimed != _canonical_merge_stable_digest(unsigned)
            or manifest.get("schema") != "plamen.canonical-retry-generation.v1"
            or manifest.get("run_id") != run_id
            or manifest.get("attempt_ordinal") != attempt
            or manifest.get("supervised_attempt_ordinal") != evidence_attempt
            or manifest.get("predecessor_work_unit_key") != contract.key
            or manifest.get("predecessor_receipt_digest")
            != (commit.get("receipt_digest") if isinstance(commit, Mapping) else None)
        ):
            raise CanonicalMergeAuthorityError(
                "canonical retry bundle manifest authority is invalid"
            )
        inputs, candidate_bytes = _canonical_retry_bundle_records(
            bundle, manifest, output_names=output_names
        )
        return {
            "state": "ready",
            "attempt": attempt,
            "bundle": bundle,
            "bundle_relative": bundle_relative,
            "manifest": manifest,
            "input_names": inputs,
            "candidate_bytes": candidate_bytes,
        }

    prior_records = prior.get("artifacts")
    if not isinstance(prior_records, Mapping):
        raise CanonicalMergeAuthorityError(
            "canonical retry predecessor records are absent"
        )
    quarantine = scratchpad / "_retry_quarantine" / "recon"
    predecessor_sources: dict[str, Path] = {}
    for name in output_names:
        source = (
            scratchpad / name
            if name == _RECON_TRANSFORM_RECEIPT
            else quarantine / name
        )
        raw = _canonical_retry_regular_bytes(
            source, label=f"predecessor {name}"
        )
        record = prior_records.get(f"scratchpad:{name}")
        if (
            not isinstance(record, Mapping)
            or record.get("sha256") != hashlib.sha256(raw).hexdigest()
            or record.get("size") != len(raw)
        ):
            raise CanonicalMergeAuthorityError(
                f"canonical retry predecessor bytes changed: {name}"
            )
        predecessor_sources[name] = source

    present = {
        name: (scratchpad / name).is_file() and not (scratchpad / name).is_symlink()
        for name in output_names[:-1]
    }
    if not any(present.values()):
        return {"state": "pending"}
    if not all(present.values()):
        raise CanonicalMergeAuthorityError(
            "canonical retry candidate generation is partial"
        )
    prompt_path = scratchpad / f"_prompt_recon.attempt{evidence_attempt}.md"
    transcript_path = scratchpad / f"_stdio_recon.attempt{evidence_attempt}.log"
    prompt_raw = _canonical_retry_regular_bytes(
        prompt_path, label="supervised attempt prompt"
    )
    transcript_raw = _canonical_retry_regular_bytes(
        transcript_path, label="supervised attempt transcript"
    )
    prompt_text = prompt_raw.decode("utf-8", errors="replace")
    transcript_text = transcript_raw.decode("utf-8", errors="replace")
    transcript_paths = {
        str(scratchpad),
        str(scratchpad).replace("\\", "\\\\"),
        scratchpad.as_posix(),
    }
    if (
        "# RETRY ATTEMPT (driver-detected gate failure on previous attempt)"
        not in prompt_text
        or str(scratchpad) not in prompt_text
        or not any(path in transcript_text for path in transcript_paths)
        or len(transcript_raw) < 500
        or any(name not in transcript_text for name in output_names[:-1])
        or not any(
            marker in transcript_text
            for marker in (
                '\"stop_reason\":\"end_turn\"',
                '\"type\":\"turn.completed\"',
                "DONE: Recon retry",
            )
        )
    ):
        raise CanonicalMergeAuthorityError(
            "canonical retry lacks a completed supervised direct-attempt transcript"
        )
    candidate_bytes = {
        name: _canonical_retry_regular_bytes(
            scratchpad / name, label=f"candidate {name}"
        )
        for name in output_names[:-1]
    }
    if all(
        hashlib.sha256(raw).hexdigest()
        == prior_records[f"scratchpad:{name}"].get("sha256")
        for name, raw in candidate_bytes.items()
    ):
        raise CanonicalMergeAuthorityError(
            "canonical retry candidate did not produce a new generation"
        )

    parent = bundle.parent
    parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".attempt-{attempt}-", dir=parent))
    try:
        (stage / "candidate").mkdir()
        (stage / "predecessor").mkdir()
        candidate_records: dict[str, dict[str, Any]] = {}
        predecessor_records: dict[str, dict[str, Any]] = {}
        for name, raw in candidate_bytes.items():
            (stage / "candidate" / name).write_bytes(raw)
            candidate_records[name] = {
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)
            }
        for name, source in predecessor_sources.items():
            raw = source.read_bytes()
            (stage / "predecessor" / name).write_bytes(raw)
            predecessor_records[name] = {
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)
            }
        (stage / "retry_plan.json").write_bytes(plan_raw)
        (stage / "prompt.md").write_bytes(prompt_raw)
        (stage / "transcript.log").write_bytes(transcript_raw)
        input_names = tuple(
            [
                *(f"{bundle_relative}/candidate/{name}" for name in output_names[:-1]),
                *(f"{bundle_relative}/predecessor/{name}" for name in output_names),
                f"{bundle_relative}/retry_plan.json",
                f"{bundle_relative}/prompt.md",
                f"{bundle_relative}/transcript.log",
                f"{bundle_relative}/manifest.json",
            ]
        )
        unsigned = {
            "schema": "plamen.canonical-retry-generation.v1",
            "run_id": run_id,
            "attempt_ordinal": attempt,
            "supervised_attempt_ordinal": evidence_attempt,
            "predecessor_work_unit_key": contract.key,
            "predecessor_receipt_digest": commit.get("receipt_digest"),
            "retry_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
            "prompt_sha256": hashlib.sha256(prompt_raw).hexdigest(),
            "transcript_sha256": hashlib.sha256(transcript_raw).hexdigest(),
            "retry_plan_contract_digest": plan.get("contract_digest"),
            "candidate_records": candidate_records,
            "predecessor_records": predecessor_records,
            "input_names": list(input_names),
        }
        manifest = {
            **unsigned,
            "manifest_sha256": _canonical_merge_stable_digest(unsigned),
        }
        (stage / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(stage, bundle)
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=False)
    inputs, sealed_candidates = _canonical_retry_bundle_records(
        bundle, manifest, output_names=output_names
    )
    return {
        "state": "ready",
        "attempt": attempt,
        "bundle": bundle,
        "bundle_relative": bundle_relative,
        "manifest": manifest,
        "input_names": inputs,
        "candidate_bytes": sealed_candidates,
    }


def _restore_canonical_retry_predecessor(
    scratchpad: Path,
    retry: Mapping[str, Any],
    output_names: tuple[str, ...],
) -> None:
    bundle = Path(retry["bundle"])
    quarantine = scratchpad / "_retry_quarantine" / "recon"
    for name in output_names:
        expected = retry["manifest"]["predecessor_records"][name]
        destination = scratchpad / name
        if (
            destination.is_file()
            and not destination.is_symlink()
            and destination.stat().st_size == expected["size"]
            and hashlib.sha256(destination.read_bytes()).hexdigest()
            == expected["sha256"]
        ):
            continue
        quarantined = quarantine / name
        if quarantined.is_file() and not quarantined.is_symlink():
            os.replace(quarantined, destination)
            continue
        raw = _canonical_retry_regular_bytes(
            bundle / "predecessor" / name,
            label=f"restored predecessor {name}",
        )
        temporary = destination.with_name(f".{destination.name}.retry-predecessor")
        temporary.write_bytes(raw)
        os.replace(temporary, destination)
        if (
            destination.stat().st_size != expected["size"]
            or hashlib.sha256(destination.read_bytes()).hexdigest()
            != expected["sha256"]
        ):
            raise CanonicalMergeAuthorityError(
                f"canonical retry predecessor restore changed bytes: {name}"
            )


def _committed_canonical_retry_generation(
    scratchpad: Path,
    prior: Mapping[str, Any],
    output_names: tuple[str, ...],
) -> dict[str, Any] | None:
    manifest = prior.get("contract_manifest")
    immutable = manifest.get("immutable_inputs") if isinstance(manifest, Mapping) else None
    candidates = [
        str(identity).removeprefix("scratchpad:")
        for identity in immutable or ()
        if str(identity).startswith(f"scratchpad:{_CANONICAL_RETRY_ROOT}/")
        and str(identity).endswith("/manifest.json")
    ]
    if not candidates:
        return None
    if len(candidates) != 1:
        raise CanonicalMergeAuthorityError(
            "committed canonical retry bundle denominator is ambiguous"
        )
    bundle = scratchpad / Path(candidates[0]).parent
    raw = _canonical_retry_regular_bytes(
        bundle / "manifest.json", label="committed bundle manifest"
    )
    try:
        retry_manifest = json.loads(raw.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalMergeAuthorityError(
            f"committed canonical retry manifest is not JSON: {exc}"
        ) from exc
    unsigned = dict(retry_manifest) if isinstance(retry_manifest, dict) else {}
    claimed = unsigned.pop("manifest_sha256", None)
    if (
        claimed != _canonical_merge_stable_digest(unsigned)
        or retry_manifest.get("schema")
        != "plamen.canonical-retry-generation.v1"
    ):
        raise CanonicalMergeAuthorityError(
            "committed canonical retry manifest integrity failed"
        )
    extra_inputs, candidate_bytes = _canonical_retry_bundle_records(
        bundle, retry_manifest, output_names=output_names
    )
    stored_names = tuple(str(value).removeprefix("scratchpad:") for value in immutable)
    if not set(extra_inputs).issubset(set(stored_names)):
        raise CanonicalMergeAuthorityError(
            "committed canonical retry contract omitted sealed inputs"
        )
    return {
        "state": "ready",
        "attempt": retry_manifest.get("attempt_ordinal"),
        "bundle": bundle,
        "bundle_relative": bundle.relative_to(scratchpad).as_posix(),
        "manifest": retry_manifest,
        "input_names": extra_inputs,
        "candidate_bytes": candidate_bytes,
        "contract_input_names": stored_names,
    }


def _record_canonical_merge_drift_debt(
    *,
    scratchpad: Path,
    contract: Any,
    capture: Mapping[str, Any],
) -> None:
    ledger = read_artifact_ledger(scratchpad)
    old = ledger.get("work_units", {}).get(contract.key)
    if not isinstance(old, dict):
        raise CanonicalMergeAuthorityError(
            "canonical merge drift has no committed predecessor"
        )
    commit = old.get("commit_authority")
    old_attempt = commit.get("attempt_ordinal") if isinstance(commit, Mapping) else None
    if type(old_attempt) is not int or old_attempt < 1:
        raise CanonicalMergeAuthorityError(
            "canonical merge predecessor attempt authority is invalid"
        )
    attempt_ordinal = old_attempt + 1
    attempt_identity = f"{contract.key}/attempt-{attempt_ordinal}"
    binding = {
        "producer_attempt_identity": attempt_identity,
        "attempt_ordinal": attempt_ordinal,
        "input_set_digest": capture["input_set_digest"],
        "config_digest": capture["config_digest"],
        "source_capture_digest": capture["source_capture_digest"],
    }
    binding["attempted_authority_digest"] = _canonical_merge_stable_digest(binding)
    disposition = {
        **binding,
        "schema": "plamen.recon-mutation-disposition.v1",
        "state": "FAILED",
        "reason_codes": ["CANONICAL_INPUT_AUTHORITY_CHANGED"],
    }
    old["semantic_status"] = "INVALID"
    old["execution_state"] = "FAILED"
    ledger["work_units"][attempt_identity] = {
        **binding,
        "work_unit_key": attempt_identity,
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
        "durable_disposition": disposition,
    }
    write_artifact_ledger(scratchpad, ledger)


def validate_recon_direct_retry_launch_authority(
    scratchpad: Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate that a direct recon fallback is an armed retry, not drift."""

    root = Path(scratchpad)
    project_root = Path(str(config.get("project_root") or ""))
    run_id = str(config.get("_run_id") or config.get("run_id") or "").strip()
    if not run_id or not project_root.is_dir():
        raise CanonicalMergeAuthorityError(
            "direct recon retry requires current run and project authority"
        )
    pipeline, mode, ecosystem, backend = _canonical_merge_dimensions(config)
    input_names = _canonical_merge_input_names(pipeline, mode)
    output_names = _canonical_merge_output_names(pipeline)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id="canonical_merge",
        exact_inputs=input_names,
        exact_outputs=output_names,
        exact_writer="DRIVER",
    )
    plan_result = _canonical_retry_plan(
        root, run_id=run_id, output_names=output_names
    )
    if plan_result is None:
        raise CanonicalMergeAuthorityError(
            "direct recon fallback is not armed by a retry plan"
        )
    plan, plan_raw = plan_result
    ledger = read_artifact_ledger(root)
    prior = ledger.get("work_units", {}).get(contract.key)
    if (
        not isinstance(prior, Mapping)
        or prior.get("semantic_status") != "ACTIVE"
        or prior.get("execution_state") != "OUTPUT_COMMITTED"
    ):
        raise CanonicalMergeAuthorityError(
            "direct recon retry has no active committed predecessor"
        )
    commit = prior.get("commit_authority")
    prior_attempt = (
        commit.get("attempt_ordinal") if isinstance(commit, Mapping) else None
    )
    if (
        type(prior_attempt) is not int
        or plan.get("attempt") != prior_attempt + 1
    ):
        raise CanonicalMergeAuthorityError(
            "direct recon retry plan ordinal does not follow its predecessor"
        )
    receipt_path = root / _RECON_TRANSFORM_RECEIPT
    receipt_raw = _canonical_retry_regular_bytes(
        receipt_path, label="predecessor receipt"
    )
    try:
        receipt = json.loads(receipt_raw.decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalMergeAuthorityError(
            "direct recon retry predecessor receipt is malformed"
        ) from exc
    if (
        not isinstance(receipt, Mapping)
        or isinstance(receipt.get("retry_generation"), Mapping)
        or (
            isinstance(receipt.get("authority_capture"), Mapping)
            and isinstance(
                receipt["authority_capture"].get("retry_generation"), Mapping
            )
        )
    ):
        raise CanonicalMergeAuthorityError(
            "direct recon retry cannot supersede an already committed retry"
        )
    prior_records = prior.get("artifacts")
    if not isinstance(prior_records, Mapping):
        raise CanonicalMergeAuthorityError(
            "direct recon retry predecessor records are absent"
        )
    quarantine = root / "_retry_quarantine" / "recon"
    authenticated_predecessors: dict[str, dict[str, Any]] = {}
    for name in output_names:
        source = (
            receipt_path
            if name == _RECON_TRANSFORM_RECEIPT
            else quarantine / name
        )
        raw = _canonical_retry_regular_bytes(
            source, label=f"launch predecessor {name}"
        )
        record = prior_records.get(f"scratchpad:{name}")
        observed = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
        if (
            not isinstance(record, Mapping)
            or record.get("sha256") != observed["sha256"]
            or record.get("size") != observed["size"]
        ):
            raise CanonicalMergeAuthorityError(
                f"direct recon retry predecessor bytes changed: {name}"
            )
        authenticated_predecessors[name] = observed
    return {
        "semantic_attempt": int(plan["attempt"]),
        "predecessor_attempt": prior_attempt,
        "predecessor_receipt_digest": (
            commit.get("receipt_digest") if isinstance(commit, Mapping) else None
        ),
        "retry_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "predecessor_set_digest": _canonical_merge_stable_digest(
            authenticated_predecessors
        ),
    }


def _merge_recon_worker_shards(
    scratchpad: Path,
    config: dict,
    *,
    failure_injector: Callable[..., None] | None = None,
    supervised_attempt: int | None = None,
) -> list[str]:
    """Atomically publish the registered canonical DRIVER merge denominator."""

    scratchpad = Path(scratchpad)
    project_root = Path(str(config.get("project_root") or ""))
    run_id = str(config.get("_run_id") or config.get("run_id") or "").strip()
    if not run_id or not project_root.is_dir():
        raise CanonicalMergeAuthorityError(
            "canonical merge requires current run_id and project_root"
        )
    pipeline, mode, ecosystem, backend = _canonical_merge_dimensions(config)
    input_names = _canonical_merge_input_names(pipeline, mode)
    output_names = _canonical_merge_output_names(pipeline)
    contract = resolve_phase_io_contract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase="recon",
        work_unit_id="canonical_merge",
        exact_inputs=input_names,
        exact_outputs=output_names,
        exact_writer="DRIVER",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_CANONICAL_MERGE_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=(),
    )
    ledger = read_artifact_ledger(scratchpad)
    prior = ledger.get("work_units", {}).get(contract.key)
    retry_generation = (
        _committed_canonical_retry_generation(scratchpad, prior, output_names)
        if isinstance(prior, Mapping)
        else None
    )
    if retry_generation is not None:
        input_names = tuple(retry_generation["contract_input_names"])
        contract = resolve_phase_io_contract(
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            backend=backend,
            phase="recon",
            work_unit_id="canonical_merge",
            exact_inputs=input_names,
            exact_outputs=output_names,
            exact_writer="DRIVER",
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=_CANONICAL_MERGE_TIMEOUT_SECONDS,
            exec_mode="python",
            tool_policy=(),
        )
    capture = _canonical_merge_capture(
        scratchpad, project_root, config, input_names
    )
    if retry_generation is not None:
        capture["retry_generation"] = {
            "attempt_ordinal": retry_generation["attempt"],
            "manifest_sha256": retry_generation["manifest"]["manifest_sha256"],
            "candidate_records": retry_generation["manifest"]["candidate_records"],
        }
        capture["input_set_digest"] = _canonical_merge_stable_digest(capture)
    if failure_injector is not None:
        failure_injector("after_capture")
    if (
        isinstance(prior, Mapping)
        and prior.get("semantic_status") == "ACTIVE"
        and prior.get("execution_state") == "OUTPUT_COMMITTED"
    ):
        input_issues = validate_work_unit_inputs(
            scratchpad, project_root, contract, launch, run_id=run_id
        )
        output_issues = validate_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
        stored_capture = _canonical_merge_receipt_capture(scratchpad)
        if not input_issues and not output_issues and stored_capture == capture:
            return list(output_names[:-1])
        retry_generation = _canonical_retry_generation(
            scratchpad=scratchpad,
            ledger=ledger,
            prior=prior,
            contract=contract,
            run_id=run_id,
            output_names=output_names,
            supervised_attempt=supervised_attempt,
        )
        if retry_generation is None:
            _record_canonical_merge_drift_debt(
                scratchpad=scratchpad,
                contract=contract,
                capture=capture,
            )
            return []
        if retry_generation.get("state") == "pending":
            # The driver has quarantined the exact committed generation and
            # armed a supervised retry, but that retry has not returned a full
            # candidate denominator yet. Preserve the old owner and let the
            # direct attempt execute; absence is not input-authority drift.
            return []
        _restore_canonical_retry_predecessor(
            scratchpad, retry_generation, output_names
        )
        base_issues = validate_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
        if base_issues:
            raise CanonicalMergeAuthorityError(
                "canonical retry could not restore its committed predecessor: "
                + "; ".join(base_issues)
            )
        input_names = (*input_names, *tuple(retry_generation["input_names"]))
        contract = resolve_phase_io_contract(
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            backend=backend,
            phase="recon",
            work_unit_id="canonical_merge",
            exact_inputs=input_names,
            exact_outputs=output_names,
            exact_writer="DRIVER",
        )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=_CANONICAL_MERGE_TIMEOUT_SECONDS,
            exec_mode="python",
            tool_policy=(),
        )
        try:
            authorization = authorize_deterministic_work_unit_reexecution(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
            )
        except ArtifactLedgerError as exc:
            raise CanonicalMergeAuthorityError(
                f"canonical retry reexecution authorization failed: {exc}"
            ) from exc
        if not isinstance(authorization, Mapping):
            raise CanonicalMergeAuthorityError(
                "canonical retry did not establish input-driven reexecution authority"
            )
        capture = _canonical_merge_capture(
            scratchpad, project_root, config, input_names
        )
        capture["retry_generation"] = {
            "attempt_ordinal": retry_generation["attempt"],
            "manifest_sha256": retry_generation["manifest"]["manifest_sha256"],
            "candidate_records": retry_generation["manifest"]["candidate_records"],
        }
        capture["input_set_digest"] = _canonical_merge_stable_digest(capture)
        ledger = read_artifact_ledger(scratchpad)
        prior = ledger.get("work_units", {}).get(contract.key)

    resuming_bound = bool(
        isinstance(prior, Mapping)
        and prior.get("semantic_status") == "INPUTS_BOUND"
        and prior.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    )
    if resuming_bound:
        input_issues = validate_work_unit_inputs(
            scratchpad, project_root, contract, launch, run_id=run_id
        )
        if input_issues:
            raise CanonicalMergeAuthorityError(
                "canonical merge bound input replay failed: "
                + "; ".join(input_issues)
            )
        armed = prior
    else:
        try:
            armed = record_work_unit_inputs(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
            )
        except ArtifactLedgerError as exc:
            raise CanonicalMergeAuthorityError(
                f"canonical merge input arm failed: {exc}"
            ) from exc
    if (
        armed.get("semantic_status") != "INPUTS_BOUND"
        or armed.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
    ):
        raise CanonicalMergeAuthorityError(
            "canonical merge did not establish a clean preexecution arm"
        )
    if failure_injector is not None:
        failure_injector("after_arm")

    bound_state = _canonical_merge_bound_generation_state(
        scratchpad, armed, output_names
    )
    if bound_state == "mixed":
        raise CanonicalMergeAuthorityError(
            "canonical merge recovery observed a mixed output generation"
        )
    recovered_records = (
        _canonical_merge_published_records(
            scratchpad, output_names, capture
        )
        if bound_state == "all_new"
        else None
    )
    if bound_state == "all_new" and recovered_records is None:
        raise CanonicalMergeAuthorityError(
            "canonical merge recovery could not authenticate published outputs"
        )

    if recovered_records is not None:
        try:
            committed = record_work_unit_artifacts(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
                actor="DRIVER",
                expected_output_records=recovered_records,
            )
        except ArtifactLedgerError as exc:
            raise CanonicalMergeAuthorityError(
                f"canonical merge recovery commit failed: {exc}"
            ) from exc
        if (
            committed.get("semantic_status") != "ACTIVE"
            or committed.get("execution_state") != "OUTPUT_COMMITTED"
        ):
            raise CanonicalMergeAuthorityError(
                "canonical merge recovery was not ACTIVE/OUTPUT_COMMITTED"
            )
        return list(output_names[:-1])

    # Keep the private transaction basename deliberately short.  The retry
    # contract stages nested paths such as
    # ``_canonical_retry_generation/recon/attempt-2/candidate/``; with a
    # perfectly valid 150+ character audit root, the former descriptive
    # prefix pushed the longest candidate to exactly 260 characters on
    # Windows.  ``Path.write_bytes`` then failed with ENOENT before canonical
    # adoption even though every candidate existed.  The random suffix still
    # provides transaction isolation, while the compact prefix preserves the
    # same-volume atomic publication boundary below legacy MAX_PATH.
    stage = Path(tempfile.mkdtemp(prefix=".cm-", dir=scratchpad))
    try:
        for name in (*input_names, *output_names[:-1]):
            source = scratchpad / name
            if source.is_file() and not source.is_symlink():
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes())
        if retry_generation is not None:
            rendered = list(output_names[:-1])
            for name, raw in retry_generation["candidate_bytes"].items():
                (stage / name).write_bytes(raw)
            # Produce the registered transform receipt shape first; candidate
            # markdown bytes replace only its canonical postimages below.
            if pipeline == "l1":
                _render_l1_recon_worker_shards(stage, config)
            else:
                _render_recon_worker_shards(stage, config)
            for name, raw in retry_generation["candidate_bytes"].items():
                (stage / name).write_bytes(raw)
        elif pipeline == "l1":
            rendered = _render_l1_recon_worker_shards(stage, config)
        else:
            rendered = _render_recon_worker_shards(stage, config)
        if tuple(rendered) != output_names[:-1]:
            raise CanonicalMergeAuthorityError(
                "canonical renderer output denominator/order drift"
            )
        # These additive, deterministic transforms are part of the canonical
        # renderer, not validation side effects.  Running them against the
        # private stage before hashing/publication keeps the artifact ledger,
        # transform receipt, retry quarantine, and root bytes on one exact
        # generation.  The validator calls remain idempotent read checks.
        canonical_normalization = {
            "skill_manifest_promotions": _reconcile_skill_manifest_sources(stage),
            "injectable_promotions": _promote_injectable_rows(stage, ecosystem),
        }
        receipt_path = stage / _RECON_TRANSFORM_RECEIPT
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if retry_generation is not None:
            receipt["retry_generation"] = {
                "attempt_ordinal": retry_generation["attempt"],
                "manifest_sha256": retry_generation["manifest"]["manifest_sha256"],
            }
        receipt["authority_capture"] = dict(capture)
        receipt["canonical_normalization"] = canonical_normalization
        receipt["canonical_output_sha256"] = {
            name: hashlib.sha256((stage / name).read_bytes()).hexdigest()
            for name in output_names[:-1]
        }
        receipt.pop("artifact_sha256", None)
        receipt["artifact_sha256"] = hashlib.sha256(
            json.dumps(
                receipt,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest().upper()
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        staged_bytes = {
            name: (stage / name).read_bytes() for name in output_names
        }
        if any(not raw for raw in staged_bytes.values()):
            raise CanonicalMergeAuthorityError(
                "canonical renderer produced an empty output"
            )
        if failure_injector is not None:
            failure_injector("after_stage")
        for name in output_names:
            os.replace(stage / name, scratchpad / name)
        if failure_injector is not None:
            failure_injector("after_publish")
        if failure_injector is not None:
            failure_injector("before_commit")
        expected_records = {
            f"scratchpad:{name}": {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
            for name, raw in staged_bytes.items()
        }
        committed = record_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=expected_records,
        )
        if (
            committed.get("semantic_status") != "ACTIVE"
            or committed.get("execution_state") != "OUTPUT_COMMITTED"
        ):
            raise CanonicalMergeAuthorityError(
                "canonical merge commit was not ACTIVE/OUTPUT_COMMITTED"
            )
        issues = validate_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
        )
        if issues:
            raise CanonicalMergeAuthorityError(
                "canonical merge committed replay failed: "
                + "; ".join(issues)
            )
    except ArtifactLedgerError as exc:
        raise CanonicalMergeAuthorityError(
            f"canonical merge transaction failed: {exc}"
        ) from exc
    finally:
        shutil.rmtree(stage, ignore_errors=False)
    return list(output_names[:-1])


def _synthesize_components_audited(scratchpad: Path) -> str:
    """Build a conservative Components Audited table from mechanical ledgers.

    Report quality should not depend on an LLM Index Agent remembering to emit
    a Components Audited section. Prefer `file_coverage_ledger.md` because it
    carries per-file status; fall back to headings from `subsystem_map.md`, then
    to file entries in `contract_inventory.md` for small SC projects.
    """
    ledger = scratchpad / "file_coverage_ledger.md"
    rows: dict[str, dict[str, int]] = {}
    if ledger.exists():
        try:
            text = _llm_norm(ledger.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            text = ""
        for line in text.splitlines():
            s = line.strip()
            if not s.startswith("|") or _is_separator_row(s):
                continue
            upper = s.upper()
            if re.search(r"\bFILE\b", upper) and (
                re.search(r"\bSTATUS\b", upper) or re.search(r"\bCOVERAGE\b", upper)
            ):
                continue
            cells = [c.strip(" `") for c in s.strip("|").split("|")]
            path = None
            status = "Catalogued"
            for cell in cells:
                p = _is_path_cell(cell)
                if p and not path:
                    path = p
                c = cell.upper()
                if c in {"COVERED", "READ", "CITED", "ACKNOWLEDGED", "LEFTOVER", "NOTREAD", "UNREAD", "UNCOVERED"}:
                    status = c.title()
            if not path:
                continue
            component = _module_key(path)
            bucket = rows.setdefault(
                component,
                {"files": 0, "covered": 0, "ack": 0, "leftover": 0},
            )
            bucket["files"] += 1
            if status.upper() in {"COVERED", "READ", "CITED"}:
                bucket["covered"] += 1
            elif status.upper() == "ACKNOWLEDGED":
                bucket["ack"] += 1
            elif status.upper() in {"LEFTOVER", "NOTREAD", "UNREAD", "UNCOVERED"}:
                bucket["leftover"] += 1
        if rows:
            lines = [
                "| Component | Files Catalogued | Covered | Acknowledged | Leftover |",
                "|-----------|------------------|---------|--------------|----------|",
            ]
            for component in sorted(rows):
                r = rows[component]
                lines.append(
                    f"| `{component}` | {r['files']} | {r['covered']} | "
                    f"{r['ack']} | {r['leftover']} |"
                )
            return "\n".join(lines)

    subsystem = scratchpad / "subsystem_map.md"
    if subsystem.exists():
        try:
            text = _llm_norm(subsystem.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            text = ""
        headings = []
        for m in re.finditer(r"(?m)^#{2,4}\s+(.+)$", text):
            h = m.group(1).strip()
            if h and len(h) < 120:
                headings.append(h)
        if headings:
            # D6 fix: compute Covered counts by matching inventory finding
            # locations to component (heading) prefixes. Pre-fix the table
            # had only Component + Source columns and no count — producing
            # the all-zero Covered column observed in a prior report.
            covered_per_component: dict[str, int] = {h: 0 for h in headings}
            inv = scratchpad / "findings_inventory.md"
            if inv.exists():
                try:
                    inv_text = _llm_norm(inv.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    inv_text = ""
                # FIX #7: prose subsystem headings (e.g. "Rate Limiting
                # (mempool)") never matched path tokens (e.g.
                # "mempool/rate_limiting.rs"), yielding the all-zero Covered
                # column. Pre-normalize each heading to a path token form:
                # strip parentheticals, lowercase, collapse spaces/hyphens to
                # underscores. Then match the normalized token against the
                # lowercased path so prose-style headings attribute correctly.
                # Presentation-only: this changes no finding, only counts.
                def _heading_path_token(h: str) -> str:
                    base = h.replace("\\", "/").lstrip("./").strip("`")
                    base = re.sub(r"\([^)]*\)", " ", base)  # drop parentheticals
                    base = base.lower().strip()
                    base = re.sub(r"[\s\-]+", "_", base)
                    return base.strip("_")

                heading_tokens = {h: _heading_path_token(h) for h in headings}
                for block in _inventory_blocks(inv_text):
                    loc = block.get("location", "") or ""
                    rel, _line = _parse_location_ref(loc)
                    if not rel:
                        continue
                    rel_norm = rel.replace("\\", "/").lstrip("./")
                    rel_lower = rel_norm.lower()
                    # Component matches if heading is a prefix of the path,
                    # OR if heading contains a path-segment that matches,
                    # OR if the normalized heading token appears in the path.
                    for h in headings:
                        h_norm = h.replace("\\", "/").lstrip("./").strip("`")
                        h_token = heading_tokens.get(h, "")
                        if (
                            rel_norm.startswith(h_norm + "/")
                            or rel_norm == h_norm
                            or h_norm in rel_norm
                            or (h_token and h_token in rel_lower)
                        ):
                            covered_per_component[h] += 1
                            break  # Each finding counts once.
            lines = [
                "| Component | Covered (findings) | Coverage Source |",
                "|-----------|--------------------|-----------------|",
            ]
            for h in headings[:40]:
                lines.append(
                    f"| `{h}` | {covered_per_component.get(h, 0)} | subsystem_map.md |"
                )
            return "\n".join(lines)

    inventory = scratchpad / "contract_inventory.md"
    if inventory.exists():
        try:
            text = _llm_norm(inventory.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            text = ""
        cut = re.search(r"(?im)^##\s+Out[- ]of[- ]Scope\b", text)
        scoped_text = text[: cut.start()] if cut else text
        paths: list[str] = []
        for m in re.finditer(r"`([^`]+\.(?:sol|rs|go|move|cairo|vy|ts|js|py))`", scoped_text, re.IGNORECASE):
            path = m.group(1).replace("\\", "/").strip()
            if path and path not in paths:
                paths.append(path)
        if paths:
            lines = [
                "| Component | Source | Status |",
                "|-----------|--------|--------|",
            ]
            for path in paths[:60]:
                lines.append(f"| `{Path(path).name}` | `{path}` | In scope |")
            return "\n".join(lines)

    return ""


def _looks_like_code_location(value: str) -> bool:
    """Return True for source-code locations suitable for client findings."""
    v = (value or "").strip().strip("`")
    if not v:
        return False
    rel, _line = _parse_location_ref(v)
    if rel:
        return True
    if re.search(
        r"\.(?:cairo|move|hpp|cpp|tsx|jsx|sol|rs|go|py|cc|ts|js|vy|c|h)"
        r"(?::|#|$)",
        v,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\b(?:src|contracts|programs|sources|move|crates|packages|modules)/",
        v,
        re.IGNORECASE,
    ):
        return True
    return False


def _is_test_or_mock_location(value: str) -> bool:
    """Return True for PoC/test/harness paths that are not primary locations."""
    v = (value or "").replace("\\", "/").lower()
    name = Path(v.split(":", 1)[0]).name.lower()
    return (
        "/test/" in f"/{v}"
        or "/tests/" in f"/{v}"
        or "/mock" in f"/{v}"
        or "/mocks/" in f"/{v}"
        or name.startswith("test_")
        or name.endswith(".t.sol")
        or name.startswith("mock")
    )


def _extract_code_location_from_text(text: str) -> str:
    """Extract the first source-code location from verifier/report prose.

    Priority:
      1. An explicit `Location:` field whose value is a non-test source path.
      2. The first regex-matched source path in the prose that is NOT a
         test/mock file.
      3. The explicit `Location:` field even if not strictly a "looks like
         code" match — sometimes verifiers write `Location: src/Foo.sol`
         in narrative prose without the strict pattern.

    Returns empty string when the only candidates are test/mock paths.
    Pre-fix (observed in a prior audit), the function fell through to
    `candidates[0]` UNFILTERED when all candidates were test/mock — a
    STRUCTURAL_NO_EXECUTABLE_HARM_ASSERTION verify file that mentioned
    only the test harness produced `Location: VerifyCritHigh.t.sol` in
    the manifest, which then leaked into the body writer's output, the
    final report, and a useless client-facing "location" pointing at a
    test file rather than the source bug site. Downstream builders have
    an inventory/index fallback for empty locations; returning a
    known-bad test path actively defeats that fallback.
    """
    loc = (
        _field_from_markdown(
            text,
            ("Location", "Primary Location", "Affected Location", "Affected Locations"),
        )
        or ""
    ).strip()
    if loc and _looks_like_code_location(loc) and not _is_test_or_mock_location(loc):
        return loc
    candidates: list[str] = []
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
        if not _is_test_or_mock_location(cand):
            return cand
    if loc and _looks_like_code_location(loc) and not _is_test_or_mock_location(loc):
        return loc
    # All remaining candidates are test/mock paths. Return empty so the
    # downstream builder can consult the inventory / report_index row
    # for the actual source location instead of writing a test file path
    # into the finding's Location field.
    return ""


def _verified_claim_title(verify_text: str) -> str:
    """Extract the client-facing claim title from a verifier artifact heading."""
    for m in re.finditer(r"(?m)^#{1,4}\s+(.+)$", verify_text or ""):
        title = m.group(1).strip()
        title = re.sub(
            r"(?i)^verification\s*:\s*(?:[A-Z]+-\d+\s*(?:[-:\u2013\u2014]\s*)?)?",
            "",
            title,
        ).strip(" -:\u2013\u2014")
        title = _sanitize_client_title(title)
        if title.lower() in {
            "description", "finding summary", "summary", "root cause",
            "analysis", "code trace", "impact", "recommendation",
            "suggested fix", "poc attempt", "execution result",
        }:
            continue
        if title and not _is_placeholder_report_title(title):
            return title
    return ""


def _title_tokens_for_conflict(title: str) -> set[str]:
    stop = {
        "the", "and", "for", "with", "from", "into", "that", "this", "called",
        "missing", "incorrect", "allows", "causes", "leads", "verified",
        "finding", "contract", "function",
    }
    return {
        tok
        for tok in re.findall(r"[a-z0-9]{3,}", (title or "").lower())
        if tok not in stop
    }


def _titles_conflict(index_title: str, verify_title: str) -> bool:
    """Detect when report_index title and verifier title describe different bugs."""
    a = _title_tokens_for_conflict(index_title)
    b = _title_tokens_for_conflict(verify_title)
    if not a or not b:
        return False
    overlap = len(a & b)
    return overlap / max(1, min(len(a), len(b))) < 0.25


def _inventory_location_map(scratchpad: Path) -> dict[str, str]:
    """Map inventory IDs and source IDs to original inventory locations."""
    records_by_id, records_by_source = _load_finding_record_maps(scratchpad)
    out: dict[str, str] = {}
    for mapping in (records_by_id, records_by_source):
        for key, rec in mapping.items():
            loc = (rec.get("location") or "").strip()
            if (
                loc
                and _looks_like_code_location(loc)
                and not _is_test_or_mock_location(loc)
                and key not in out
            ):
                out[key] = loc

    if successor_projection_present(scratchpad):
        # The immutable records projection is already the exact structured
        # representation of the frozen inventory.  Never enrich it from a
        # later mutable canonical file.
        return out

    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return out
    try:
        text = _llm_norm(inv.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    for block in _inventory_blocks(text):
        loc = (block.get("location") or "").strip()
        if not _looks_like_code_location(loc) or _is_test_or_mock_location(loc):
            continue
        keys: list[str] = []
        fid = _normalize_finding_id(block.get("id", "")) or block.get("id", "")
        if fid:
            keys.append(fid)
        for sid in sorted(
            _extract_finding_ids_from_text(block.get("source_ids", "")),
            key=lambda value: (value.casefold(), value),
        ):
            keys.append(sid)
        for key in keys:
            norm = _normalize_finding_id(key) or key
            if norm and norm not in out:
                out[norm] = loc
    return out


def _records_from_inventory_text(text: str) -> list[dict[str, object]]:
    """Return structured finding records from `findings_inventory.md`.

    This is the immutable identity ledger for downstream phases. Markdown stays
    the human-readable artifact, but report/queue plumbing should not have to
    re-derive identity fields from prose at every phase boundary.
    """
    records: list[dict[str, object]] = []
    seen: set[str] = set()
    for block in _inventory_blocks(text):
        fid = _normalize_finding_id(block.get("id", "")) or block.get("id", "")
        if not fid or fid in seen:
            continue
        raw = block.get("block", "")
        source_ids = []
        for sid in sorted(
            _extract_finding_ids_from_text(block.get("source_ids", "")),
            key=lambda value: (value.casefold(), value),
        ):
            # The extractor already returns canonical upper-case tokens from
            # the registry grammar.  Generic finding normalization rewrites
            # underscores to hyphens and would corrupt content-addressed or
            # role-bearing producer identities (for example DXRE-* lineage).
            norm = sid.upper()
            if norm and norm not in source_ids:
                source_ids.append(norm)
        severity = _severity_name_from_text(raw, {})
        preferred = (
            _field_from_markdown(raw, ("Preferred Tag", "Preferred Evidence", "Evidence Tag"))
            or EVIDENCE_TAG_DEFAULT
        )
        root_cause = _field_or_section(
            raw,
            ("Root Cause", "Vulnerability Class", "Bug Class", "Class"),
            ("Root Cause", "Vulnerability Class", "Bug Class", "Class"),
            fallback="",
            max_chars=3000,
        )
        description = _field_or_section(
            raw,
            ("Description", "Details", "Summary"),
            ("Description", "Details", "Summary", "Analysis"),
            fallback="",
            max_chars=5000,
        )
        impact = _field_or_section(
            raw,
            ("Impact", "Risk"),
            ("Impact", "Risk", "Security Impact"),
            fallback="",
            max_chars=3000,
        )
        primary_artifact = _field_from_markdown(
            raw, ("Primary Artifact", "Source Artifact", "Artifact")
        )
        producer = None
        scope_debt: list[str] = []
        if primary_artifact:
            try:
                producer = _registered_producer_for_artifact(
                    Path(primary_artifact).name,
                    consumer="pre_dedup_promotion",
                )
            except ProducerResolutionError as exc:
                scope_debt.append(str(exc))
        scopes = _resolve_effective_scopes(
            producer=producer,
            evidence_scope=(
                _field_from_markdown(raw, ("Evidence Scope",))
                or _field_from_markdown(raw, ("Effective Evidence Scope",))
            ),
            proof_scope=(
                _field_from_markdown(raw, ("Proof Scope",))
                or _field_from_markdown(raw, ("Effective Proof Scope",))
            ),
            harm_scope=(
                _field_from_markdown(raw, ("Harm Scope",))
                or _field_from_markdown(raw, ("Effective Harm Scope",))
            ),
        )
        scope_debt.extend(str(value) for value in scopes["scope_debt"])
        records.append({
            "inventory_id": fid,
            "source_ids": source_ids,
            "title": block.get("title", "") or fid,
            "severity": severity,
            "location": block.get("location", "") or _field_from_markdown(raw, ("Location", "Locations")),
            "preferred_tag": _extract_first_tag(preferred) or _strip_md(preferred) or EVIDENCE_TAG_DEFAULT,
            "verdict": _field_from_markdown(raw, ("Verdict", "Final Verdict", "Status")),
            "root_cause": root_cause,
            "description": description,
            "impact": impact,
            "primary_artifact": primary_artifact,
            "effective_evidence_scope": scopes["effective_evidence_scope"],
            "effective_proof_scope": scopes["effective_proof_scope"],
            "effective_harm_scope": scopes["effective_harm_scope"],
            "scope_debt": scope_debt,
            "raw_block_len": len(raw),
        })
        seen.add(fid)
    return records


def _write_finding_records_from_inventory(scratchpad: Path) -> int:
    """Write `finding_records.json` from the current inventory markdown."""
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return 0
    try:
        inventory_raw = read_bounded_regular_bytes(inv, 64 * 1024 * 1024)
        text = _llm_norm(inventory_raw.decode("utf-8", errors="replace"))
    except Exception:
        return 0
    records = _records_from_inventory_text(text)
    if not records:
        return 0
    payload = {
        "schema_version": "plamen.finding_records.v2",
        "source": "findings_inventory.md",
        "source_sha256": hashlib.sha256(inventory_raw).hexdigest(),
        "records": records,
    }
    try:
        target = scratchpad / "finding_records.json"
        encoded = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=scratchpad,
            prefix=".finding_records.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    except Exception:
        return 0
    return len(records)


_CANONICAL_FINDING_ID_MAP_NAME = "_canonical_finding_ids.json"
_CANONICAL_FINDING_ID_SCHEMA = "plamen.canonical_finding_ids.v1"
_UNMAPPED_ID_TOKENS_NAME = "_unmapped_id_tokens.json"
_UNMAPPED_ID_SCHEMA = "plamen.unmapped_id_tokens.v1"

_CANONICAL_ID_PRODUCER_PATTERNS: tuple[str, ...] = (
    "analysis_*.md",
    "analysis_rescan_*.md",
    "analysis_percontract_*.md",
    "graph_sweep*.md",
    "coverage_fill_*.md",
    "panic_audit_*.md",
    "panic_audit_summary.md",
    "symmetric_pair_findings.md",
    "field_validation_matrix.md",
    "primitive_correctness_findings.md",
    "network_amplification_findings.md",
    "lifecycle_replay_findings.md",
    "findings_inventory.md",
    "findings_inventory_chunk_*.md",
    "depth_*_findings.md",
    "blind_spot_*_findings.md",
    "validation_sweep_findings.md",
    "niche_*_findings.md",
    "medusa_fuzz_findings.md",
    "invariant_fuzz_results.md",
    "design_stress_findings.md",
    "depth_design_stress_findings.md",
    "perturbation_findings.md",
    "depth_perturbation_findings.md",
    "attention_repair_summary.md",
    "rag_validation.md",
    "hypotheses.md",
    "chain_hypotheses.md",
    "chain_iteration2.md",
    "post_verify_new_observations.md",
    "skeptic_findings.md",
    "cross_batch_consistency.md",
    "report_index.md",
)
_CANONICAL_ID_PRODUCER_PATTERNS = tuple(dict.fromkeys(
    _CANONICAL_ID_PRODUCER_PATTERNS
    + _registered_producer_patterns("canonical_identity")
))

_CANONICAL_ID_SKIP_PREFIXES: tuple[str, ...] = (
    "_prompt_", "_stdio_", "_continuation_", "_retry_", "_canonical_",
)

_GENERIC_ID_TOKEN_RE = re.compile(
    r"\b[A-Z]{2,12}[A-Z0-9]*(?:-[A-Z0-9_]+)*-\d+\b"
)
_COMMON_NON_FINDING_ID_RE = re.compile(
    r"^(?:ERC|EIP|BIP|RFC|CAIP|SLIP|CVE|CWE|PR|IP|HTTP|TLS)-\d+",
    re.IGNORECASE,
)


def _canonical_id_norm(value: str) -> str:
    return re.sub(r"\s+", " ", _strip_md(value or "")).strip().lower()


def _canonical_finding_hash(parts: dict[str, str]) -> str:
    immutable = {
        "artifact": parts.get("artifact", ""),
        "local_id": _canonical_id_norm(parts.get("local_id", "")),
        "title": _canonical_id_norm(parts.get("title", "")),
        "location": _canonical_id_norm(parts.get("location", "")),
        "root_cause": _canonical_id_norm(parts.get("root_cause", "")),
        "source_ids": _canonical_id_norm(parts.get("source_ids", "")),
    }
    blob = json.dumps(immutable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _iter_finding_blocks_with_meta(text: str) -> list[dict[str, Any]]:
    matches = list(FINDING_BLOCK_HEADING_RE.finditer(text or ""))
    out: list[dict[str, Any]] = []
    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        block = text[start:end].strip()
        line_end = text.find("\n", match.start(), end)
        if line_end < 0:
            line_end = end
        heading = text[match.start():line_end]
        title = ""
        m_title = re.search(r"\]\s*[:\-–—]?\s*(.+)$", heading)
        if m_title:
            title = _strip_md(m_title.group(1)).strip()
        out.append({
            "local_id": match.group(1).strip(),
            "title": title,
            "block": block,
            "offset": start,
        })
    return out


def _producer_artifact_paths_for_identity(scratchpad: Path) -> list[Path]:
    seen: set[str] = set()
    paths: list[Path] = []
    for pattern in _CANONICAL_ID_PRODUCER_PATTERNS:
        for p in sorted(scratchpad.glob(pattern)):
            if not p.is_file():
                continue
            if p.name in seen or p.name.startswith(_CANONICAL_ID_SKIP_PREFIXES):
                continue
            if p.name.startswith("analysis_merged_into_"):
                continue
            seen.add(p.name)
            paths.append(p)
    return paths


def _canonical_identity_records_from_artifact(path: Path) -> list[dict[str, Any]]:
    try:
        producer = _registered_producer_for_artifact(
            path.name, consumer="canonical_identity"
        )
    except ProducerResolutionError:
        producer = None
    if producer is not None and getattr(
        producer, "artifact_format", "MARKDOWN_FINDINGS"
    ) != "MARKDOWN_FINDINGS":
        try:
            actions = _read_registered_typed_actions(
                path, consumer="canonical_identity"
            )
        except Exception:
            # Exact delivery reconciliation owns the typed parse debt.  Do not
            # invent a partial canonical identity from malformed JSON.
            return []
        typed_records: list[dict[str, Any]] = []
        for action in actions:
            title = f"Exploration additive action {action.action_id}"
            parts = {
                "artifact": path.name,
                "local_id": action.action_id,
                "action_identity": action.action_identity,
                "obligation_id": action.obligation_id,
                "source_finding": action.source_finding,
                "axis": action.axis,
                "instance": action.instance,
                "evidence_sha256": hashlib.sha256(
                    action.evidence.encode("utf-8")
                ).hexdigest(),
                "rationale_sha256": hashlib.sha256(
                    action.rationale.encode("utf-8")
                ).hexdigest(),
            }
            digest = _canonical_finding_hash(parts)
            referenced = sorted({
                match.group(1).upper()
                for value in (action.source_finding, action.evidence, action.rationale)
                for match in _INTERNAL_FINDING_ID_RE.finditer(value)
                if match.group(1).upper() != action.action_id.upper()
            })
            typed_records.append({
                "canonical_id": "CID-" + digest[:16].upper(),
                "fingerprint": "sha256:" + digest,
                "artifact": path.name,
                "offset": action.lineage_source_line,
                "local_id": action.action_id,
                "local_id_raw": action.action_id,
                "action_identity": action.action_identity,
                "source_identity": (
                    f"{path.name}:{action.action_identity}"
                ),
                "title": title,
                "severity": "Unknown",
                "location": "",
                "root_cause": "",
                "source_ids_text": (
                    f"{action.source_finding}, {action.obligation_id}"
                ),
                "referenced_ids": referenced,
                "raw_block_len": (
                    len(action.evidence.encode("utf-8"))
                    + len(action.rationale.encode("utf-8"))
                ),
                "proof_scope": action.proof_scope,
                "requires_independent_consumer": True,
            })
        return typed_records
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    records: list[dict[str, Any]] = []
    for item in _iter_finding_blocks_with_meta(text):
        block = str(item.get("block") or "")
        local_id_raw = str(item.get("local_id") or "").strip()
        local_id = _normalize_finding_id(local_id_raw) or local_id_raw
        title = str(item.get("title") or "").strip()
        if not title:
            title = _field_from_markdown(block, ("Title", "Finding", "Issue")) or local_id
        severity = normalize_severity(_field_from_markdown(block, ("Severity", "Risk Level", "Level")))
        location = _field_from_markdown(block, ("Location", "Locations", "Code Location", "File"))
        root_cause = _field_from_markdown(block, ("Root Cause", "Cause", "Invariant Broken"))
        source_ids = _field_from_markdown(
            block,
            (
                "Source IDs", "Source ID", "Sources", "Constituent Findings",
                "Internal Finding IDs", "Source Identity", "Proposal ID",
                "Source Obligation ID", "Source Work Item ID",
            ),
        )
        parts = {
            "artifact": path.name,
            "local_id": local_id,
            "title": title,
            "location": location,
            "root_cause": root_cause,
            "source_ids": source_ids,
        }
        digest = _canonical_finding_hash(parts)
        referenced = sorted({
            m.group(1).upper()
            for m in _INTERNAL_FINDING_ID_RE.finditer(block)
            if m.group(1).upper() != local_id.upper()
        })
        records.append({
            "canonical_id": "CID-" + digest[:16].upper(),
            "fingerprint": "sha256:" + digest,
            "artifact": path.name,
            "offset": int(item.get("offset") or 0),
            "local_id": local_id,
            "local_id_raw": local_id_raw,
            "title": title,
            "severity": severity,
            "location": location,
            "root_cause": root_cause,
            "source_ids_text": source_ids,
            "referenced_ids": referenced,
            "raw_block_len": len(block),
        })
    return records


def _collect_unmapped_id_tokens(scratchpad: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for p in sorted(scratchpad.glob("*.md")):
        if not p.is_file() or p.name.startswith(_CANONICAL_ID_SKIP_PREFIXES):
            continue
        try:
            text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for match in _GENERIC_ID_TOKEN_RE.finditer(text):
            token = match.group(0).upper()
            if _COMMON_NON_FINDING_ID_RE.match(token):
                continue
            if _INTERNAL_FINDING_ID_RE.fullmatch(token):
                continue
            key = (p.name, token)
            if key in seen:
                continue
            seen.add(key)
            start = max(0, match.start() - 80)
            end = min(len(text), match.end() + 80)
            context = re.sub(r"\s+", " ", text[start:end]).strip()
            rows.append({
                "artifact": p.name,
                "token": token,
                "context": context[:240],
            })
    return rows


def _write_canonical_finding_identity_map(
    scratchpad: Path,
    *,
    phase_name: str = "",
    pipeline: str = "",
    mode: str = "",
) -> int:
    """Write deterministic finding-identity sidecars without mutating artifacts.

    This is the first step toward Python-owned final IDs: producers may still
    emit local IDs, but the driver records a stable content fingerprint and
    CID alias for every parseable finding block. Nothing is dropped or merged.
    """
    records: list[dict[str, Any]] = []
    for path in _producer_artifact_paths_for_identity(scratchpad):
        records.extend(_canonical_identity_records_from_artifact(path))
    records.sort(key=lambda r: (str(r.get("artifact")), int(r.get("offset") or 0), str(r.get("local_id"))))
    payload = {
        "schema_version": _CANONICAL_FINDING_ID_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "last_phase": phase_name,
        "pipeline": pipeline,
        "mode": mode,
        "record_count": len(records),
        "records": records,
    }
    try:
        (scratchpad / _CANONICAL_FINDING_ID_MAP_NAME).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except Exception:
        return 0

    unmapped = _collect_unmapped_id_tokens(scratchpad)
    try:
        (scratchpad / _UNMAPPED_ID_TOKENS_NAME).write_text(
            json.dumps(
                {
                    "schema_version": _UNMAPPED_ID_SCHEMA,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "last_phase": phase_name,
                    "token_count": len(unmapped),
                    "tokens": unmapped,
                },
                indent=2,
                sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
    except Exception:
        pass
    return len(records)


def _load_finding_record_maps(
    scratchpad: Path,
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    """Return maps keyed by inventory ID and original source IDs."""
    if successor_projection_present(scratchpad):
        try:
            payload = resolve_active_preverify_projection(
                scratchpad
            )["records_payload"]
        except (PreverifyProjectionAuthorityError, KeyError, TypeError) as exc:
            logging.getLogger(__name__).warning(
                "authenticated frozen finding records unavailable: %s",
                exc,
            )
            raise PreverifyProjectionAuthorityError(
                "authenticated frozen finding-record denominator is "
                f"unavailable: {exc}"
            ) from exc
    else:
        path = scratchpad / "finding_records.json"
        inv = scratchpad / "findings_inventory.md"
        if inv.exists() and (
            not path.exists() or path.stat().st_mtime < inv.stat().st_mtime
        ):
            _write_finding_records_from_inventory(scratchpad)
        if not path.exists():
            return {}, {}
        try:
            payload = json.loads(
                path.read_text(encoding="utf-8", errors="replace")
            )
        except Exception:
            return {}, {}
    records = payload.get("records", [])
    if not isinstance(records, list):
        return {}, {}
    by_id: dict[str, dict[str, object]] = {}
    by_source: dict[str, dict[str, object]] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        fid = _normalize_finding_id(str(rec.get("inventory_id", ""))) or str(rec.get("inventory_id", "")).strip()
        if fid and fid not in by_id:
            by_id[fid] = rec
        for sid in rec.get("source_ids", []) or []:
            norm = _normalize_finding_id(str(sid)) or str(sid).strip()
            if norm and norm not in by_source:
                by_source[norm] = rec
    return by_id, by_source


def _finding_record_for_ids(
    scratchpad: Path,
    finding_ids: list[str],
    maps: tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]] | None = None,
) -> dict[str, object]:
    by_id, by_source = maps if maps is not None else _load_finding_record_maps(scratchpad)
    for fid in finding_ids:
        norm = _normalize_finding_id(fid) or fid
        if norm in by_id:
            return by_id[norm]
        if norm in by_source:
            return by_source[norm]
    return {}


def _is_placeholder_report_title(title: str) -> bool:
    """Return True for generated titles that should inherit source identity."""
    t = re.sub(r"\s+", " ", (title or "").strip()).lower()
    if not t:
        return True
    if t in {"verified finding", "upstream finding", "excluded finding"}:
        return True
    return bool(re.fullmatch(
        r"(?:unverified|verified)?\s*(?:critical|high|medium|low|informational)"
        r"(?:-|\s)+severity finding(?:\s*-\s*[A-Z][A-Z0-9-]*\d+)?",
        t,
        re.IGNORECASE,
    ))


def _record_title(record: dict[str, object]) -> str:
    title = _sanitize_client_title(str(record.get("title", "") or "").strip())
    return "" if _is_placeholder_report_title(title) else title


def _inventory_location_for_ids(
    scratchpad: Path,
    finding_ids: list[str],
    location_by_id: dict[str, str] | None = None,
) -> str:
    """Recover original inventory location for report/verify IDs."""
    loc_map = location_by_id if location_by_id is not None else _inventory_location_map(scratchpad)
    if not loc_map:
        return ""
    candidates: list[str] = []
    for fid in finding_ids:
        norm = _normalize_finding_id(fid) or fid
        if norm:
            candidates.append(norm)
    try:
        hyp_map = _parse_hypothesis_constituents(scratchpad)
    except Exception:
        hyp_map = {}
    for fid in list(candidates):
        for child in hyp_map.get(fid, []) or []:
            norm = _normalize_finding_id(child) or child
            if norm and norm not in candidates:
                candidates.append(norm)
    for fid in candidates:
        loc = loc_map.get(fid, "")
        if _looks_like_code_location(loc) and not _is_test_or_mock_location(loc):
            return loc
    return ""


def _build_internal_traceability_from_records(scratchpad: Path) -> str:
    """Build internal traceability from deterministic report_records.json."""
    records_path = scratchpad / "report_records.json"
    if not records_path.exists():
        return ""
    try:
        data = json.loads(records_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    active = data.get("active") or []
    excluded = data.get("excluded") or []
    lines = [
        "# Internal Report Traceability",
        "",
        "| Report ID | Internal Hypothesis | Chain | Verification | Agent Sources |",
        "|-----------|---------------------|-------|--------------|---------------|",
    ]
    for rec in active:
        rid = str(rec.get("report_id") or "").strip()
        if not rid:
            continue
        ids = rec.get("absorbed_finding_ids") or [rec.get("finding_id")]
        ids = _clean_finding_id_list(ids)
        verify_refs = ", ".join(f"verify_{i}.md" for i in ids) or "n/a"
        source_refs = ", ".join(ids) or "n/a"
        chain_refs = ", ".join(i for i in ids if i.upper().startswith("CH-")) or "n/a"
        lines.append(
            f"| {rid} | {', '.join(ids).replace('|', '/')} | "
            f"{chain_refs.replace('|', '/')} | "
            f"{verify_refs.replace('|', '/')} | {source_refs.replace('|', '/')} |"
        )
    lines.extend([
        "",
        "### Excluded Findings",
        "",
        "| Internal ID | Severity | Title | Exclusion Reason |",
        "|-------------|----------|-------|------------------|",
    ])
    for rec in excluded:
        lines.append(
            f"| {str(rec.get('finding_id', '')).replace('|', '/')} | "
            f"{str(rec.get('severity', '')).replace('|', '/')} | "
            f"{str(rec.get('title', '')).replace('|', '/')} | "
            f"{str(rec.get('reason', rec.get('verdict', ''))).replace('|', '/')} |"
        )
    return "\n".join(lines).strip()


def _build_client_excluded_appendix_from_records(scratchpad: Path) -> str:
    """Build client-facing excluded findings without internal IDs."""
    records_path = scratchpad / "report_records.json"
    if not records_path.exists():
        return ""
    try:
        data = json.loads(records_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    excluded = data.get("excluded") or []
    if not excluded:
        return ""
    lines = [
        "| Severity | Title | Exclusion Reason |",
        "|----------|-------|------------------|",
    ]
    for rec in excluded:
        title = _sanitize_client_title(str(rec.get("title", "") or "Excluded finding"))
        reason = _sanitize_client_body(str(rec.get("reason", rec.get("verdict", "")) or ""))
        lines.append(
            f"| {str(rec.get('severity', '')).replace('|', '/')} | "
            f"{title.replace('|', '/')} | "
            f"{reason.replace('|', '/')} |"
        )
    return "\n".join(lines).strip()


def _synth_report_section_from_verify(
    scratchpad: Path,
    report_id: str,
    finding_id: str,
    queue_row: dict[str, str],
    unresolved: bool,
) -> str:
    """Build a body section from verified artifacts when a tier writer omits it.

    This is deterministic report repair, not new audit analysis: it only
    promotes a finding already present in the verification queue and, when
    available, its verifier output.
    """
    verify_path = _verify_file_for_id(scratchpad, finding_id)
    try:
        verify_text = _llm_norm(verify_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        verify_text = ""
    record = _finding_record_for_ids(scratchpad, [finding_id])

    # Closes F-RPT-01: detect when verify file is missing/empty so the
    # synthesized section is tagged STUB-RECOVERED rather than silently
    # manufacturing CONFIRMED/CODE-TRACE semantics from absent evidence.
    stub_recovered = not (verify_text and verify_text.strip())

    title = (
        (queue_row.get("title") or "").strip()
        or str(record.get("title", "") if record else "").strip()
        or _verified_claim_title(verify_text)
        or _first_heading_title(verify_text)
        or "Verified finding"
    )
    title = _sanitize_client_title(re.sub(r"\s+", " ", title).strip())
    if record and _is_placeholder_report_title(title):
        title = _record_title(record) or title
    severity = SEVERITY_FROM_LETTER.get(report_id[:1], normalize_severity(queue_row.get("severity", "Medium")))
    raw_verdict = _field_from_markdown(verify_text, ("Verdict",))
    verdict = _sanitize_client_body(raw_verdict) if raw_verdict else (
        "UNRESOLVED" if stub_recovered else "CONFIRMED"
    )
    preferred_tag = (
        _field_from_markdown(verify_text, ("Preferred Tag", "Preferred Evidence"))
        or queue_row.get("preferred tag", "")
        or EVIDENCE_TAG_DEFAULT
    )
    evidence_tag = (
        _field_from_markdown(verify_text, ("Evidence Tag", "Evidence"))
        or preferred_tag
    )
    location_candidates = [
        _extract_code_location_from_text(verify_text) if verify_text else "",
        queue_row.get("location", "").strip(),
        str(record.get("location", "") if record else "").strip(),
        _field_from_markdown(verify_text, ("Location", "Primary Location")),
    ]
    location = ""
    for cand in location_candidates:
        cand = (cand or "").strip()
        if cand and _looks_like_code_location(cand) and not _is_test_or_mock_location(cand):
            location = cand
            break
    if not location:
        for cand in location_candidates:
            cand = (cand or "").strip()
            if cand:
                location = cand
                break
    location = _sanitize_client_body(location or "See verification artifact")
    bug_class = _sanitize_client_body(queue_row.get("bug class", "").strip()) or "verified issue"
    suffixes: list[str] = []
    if stub_recovered:
        suffixes.append("[STUB-RECOVERED]")
    if unresolved:
        suffixes.append("[UNRESOLVED - needs human review]")
    header_suffix = (" " + " ".join(suffixes)) if suffixes else ""
    unresolved_note = (
        "\n**Human review**: a verifier or skeptic proposed a negative/unresolved disposition; "
        "severity was retained pending independent closure authority and the finding remains "
        "in the body.\n"
        if unresolved else ""
    )
    description = _field_or_section(
        verify_text,
        ("Description", "Finding Summary", "Summary", "Root Cause"),
        ("Finding Summary", "Analysis", "Code Trace", "Description", "Root Cause"),
        fallback=(
            queue_row.get("description", "").strip()
            or str(record.get("description", "") if record else "").strip()
            or str(record.get("root_cause", "") if record else "").strip()
            or queue_row.get("root cause", "").strip()
            or "Verifier artifact did not include a narrative description."
        ),
    )
    impact = _field_or_section(
        verify_text,
        ("Impact", "Combined Impact", "Risk"),
        ("Combined Impact", "Impact", "Risk", "Security Impact"),
        fallback=(
            queue_row.get("impact", "").strip()
            or str(record.get("impact", "") if record else "").strip()
            or (
                "Impact remains unverified because the assigned verifier work "
                "did not complete; preserve the proposed severity for human review."
                if stub_recovered
                else "Verifier evidence ties the cited code path to the assigned severity; review the code trace and severity rationale for exploitability details."
            )
        ),
        max_chars=2500,
    )
    poc_result = _field_or_section(
        verify_text,
        ("PoC Result", "Execution Output", "Test Output", "Proof"),
        ("PoC Result", "Execution Output", "Test Output", "Proof", "Reproduction"),
        fallback=(
            "Verification was not executed or did not produce an authenticated result."
            if stub_recovered
            else "No executable PoC was recorded; verifier relied on code trace evidence."
        ),
        max_chars=2500,
    )
    recommendation = _field_or_section(
        verify_text,
        ("Recommendation", "Suggested Fix", "Fix", "Mitigation"),
        ("Suggested Fix", "Recommendation", "Mitigation", "Fix"),
        fallback=(
            "Human review is required before prescribing a fix; first validate the retained mechanism and its affected path."
            if stub_recovered
            else "Apply the verifier-recommended mitigation and add a regression test for the cited path."
        ),
        max_chars=3000,
    )
    severity_rationale = _field_or_section(
        verify_text,
        ("Severity Rationale", "Severity rationale"),
        ("Severity Rationale", "Exploitability", "Precondition", "Preconditions"),
        fallback=(
            f"Provisional `{bug_class}` severity retained pending verification."
            if stub_recovered
            else f"Verified `{bug_class}` finding with {evidence_tag} evidence."
        ),
        max_chars=1800,
    )
    description = _sanitize_client_body(description)
    impact = _sanitize_client_body(impact)
    poc_result = _sanitize_client_body(poc_result)
    recommendation = _sanitize_client_body(recommendation)
    generic_fallback_markers = (
        "Verifier artifact did not include",
        "Impact was not separately summarized",
        "Verifier evidence ties the cited code path",
        "No executable PoC was recorded; verifier relied on code trace evidence",
        "Apply the verifier-recommended mitigation",
        "Apply the verifier-recommended mitigation and add a regression test",
    )
    insufficient_body_evidence = (
        stub_recovered
        or any(marker in description for marker in generic_fallback_markers)
        or any(marker in impact for marker in generic_fallback_markers)
        or any(marker in poc_result for marker in generic_fallback_markers)
        or any(marker in recommendation for marker in generic_fallback_markers)
        or not _is_substantive_body_evidence(description)
        or not _is_substantive_body_evidence(impact)
        or (
            report_id[:1].upper() in {"C", "H", "M"}
            and not _is_substantive_body_evidence(poc_result)
        )
    )
    heading_prefix = (
        "[REPORT-BLOCKED: insufficient verifier evidence] "
        if insufficient_body_evidence else ""
    )

    confidence_parts = []
    if not stub_recovered and evidence_tag and evidence_tag not in ("N/A", "unknown"):
        confidence_parts.append(f"PoC: {_sanitize_client_body(evidence_tag)}")
    confidence_level = (
        "UNVERIFIED"
        if stub_recovered
        else "HIGH" if has_mechanical_proof(evidence_tag or "") else "MEDIUM"
    )
    confidence_line = f"**Confidence**: {confidence_level}"
    if confidence_parts:
        confidence_line += f" ({', '.join(confidence_parts)})"

    return "\n".join([
        f"### {heading_prefix}[{report_id}] {title}{header_suffix}",
        "",
        f"**Severity**: {severity}",
        f"**Verdict**: {verdict}",
        f"**Location**: {location}",
        confidence_line,
        unresolved_note.rstrip(),
        "",
        "**Description**:",
        description,
        "",
        "**Impact**:",
        impact,
        "",
        "**PoC Result**:",
        poc_result,
        "",
        "**Recommendation**:",
        recommendation,
        "",
    ]).replace("\n\n\n", "\n\n").strip()


def _report_candidate_universe_rows(
    scratchpad: Path,
) -> list[dict[str, Any]]:
    """Return the exact report-time candidate denominator.

    The typed work-item sidecar is the cutover boundary.  Once it exists,
    report consumers must authenticate and enumerate the immutable base plus
    post-verification delta universe; a malformed or missing delta is an error,
    never permission to fall back to lossy Markdown.  Runs predating the typed
    sidecar retain their legacy queue projection.

    This helper is intentionally report-only.  Pre-verification and
    verification producers must continue to consume the frozen base queue.
    The import stays local to avoid coupling the large mechanical module to the
    post-verification authority during pre-report module initialization.
    """
    from post_verify_candidate_delta import (
        current_report_candidate_universe_legacy_rows,
        report_candidate_universe_requires_typed_authority,
    )

    if report_candidate_universe_requires_typed_authority(Path(scratchpad)):
        return current_report_candidate_universe_legacy_rows(
            Path(scratchpad)
        )
    return parse_verification_queue_rows(Path(scratchpad))


def _repair_report_body_from_assignments(body: str, scratchpad: Path) -> str:
    """Append missing assigned report sections and apply UNRESOLVED flags."""
    assignments, _source = get_tier_assignments(scratchpad)
    if not assignments:
        return body

    queue_rows = {
        (r.get("finding id") or "").strip(): r
        for r in _report_candidate_universe_rows(scratchpad)
        if (r.get("finding id") or "").strip()
    }
    unresolved_ids = _collect_judge_unresolved_ids(scratchpad)

    # First, tag existing assigned body sections that correspond to unresolved
    # internal IDs but lack the required body marker.
    unresolved_report_ids = {
        a.get("report_id", "")
        for a in assignments
        if a.get("finding_id", "") in unresolved_ids
    }
    fixed_lines: list[str] = []
    header_re = re.compile(r"^(###\s*\[([CHMLI]-\d+)\].*)$")
    for line in body.splitlines():
        m = header_re.match(line)
        if m and m.group(2) in unresolved_report_ids and "[UNRESOLVED" not in line:
            line = line + " [UNRESOLVED - needs human review]"
        fixed_lines.append(line)
    body = "\n".join(fixed_lines)

    present = set(re.findall(r"^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\]", body, re.MULTILINE))
    missing_sections: list[str] = []
    for a in assignments:
        rid = a.get("report_id", "")
        fid = a.get("finding_id", "")
        if not rid or not fid or rid in present:
            continue
        missing_sections.append(
            _synth_report_section_from_verify(
                scratchpad,
                rid,
                fid,
                queue_rows.get(fid, {}),
                fid in unresolved_ids,
            )
        )
        present.add(rid)
    if not missing_sections:
        return body

    insertion = (
        "\n\n".join(missing_sections)
        + "\n\n---\n\n"
    )
    marker = "\n## Priority Remediation Order"
    if marker in body:
        return body.replace(marker, "\n" + insertion + "## Priority Remediation Order", 1)
    return body.rstrip() + "\n\n---\n\n" + insertion


def _synth_report_section_from_manifest_row(scratchpad: Path, row: dict[str, object]) -> str:
    report_id = str(row.get("report_id", "") or "").strip().upper()
    title = _sanitize_client_title(str(row.get("title", "") or "Verified finding"))
    severity = normalize_severity(str(row.get("severity", "") or report_id[:1]))
    location = _sanitize_client_body(str(row.get("location", "") or "See verification artifacts"))
    evidence = _sanitize_client_body(str(row.get("evidence_tag", "") or EVIDENCE_TAG_DEFAULT))
    verify_files = [str(v) for v in (row.get("verify_files") or []) if str(v).strip()]

    desc_parts: list[str] = []
    impact_parts: list[str] = []
    poc_parts: list[str] = []
    rec_parts: list[str] = []
    verdicts: list[str] = []
    for vf in verify_files:
        p = scratchpad / vf
        if not p.exists():
            continue
        try:
            txt = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            txt = ""
        if not txt:
            continue
        verdict = _verifier_status_from_text(txt)
        if verdict:
            verdicts.append(verdict)
        desc = _field_or_section(
            txt,
            ("Description", "Finding Summary", "Summary", "Root Cause"),
            ("Finding Summary", "Analysis", "Code Trace", "Description", "Root Cause"),
            fallback="",
            max_chars=1800,
        )
        impact = _field_or_section(
            txt,
            ("Impact", "Combined Impact", "Risk"),
            ("Combined Impact", "Impact", "Risk", "Security Impact"),
            fallback="",
            max_chars=1200,
        )
        poc = _field_or_section(
            txt,
            ("PoC Result", "Execution Output", "Test Output", "Proof"),
            ("PoC Result", "Execution Output", "Test Output", "Proof", "Reproduction"),
            fallback="",
            max_chars=1200,
        )
        rec = _field_or_section(
            txt,
            ("Recommendation", "Suggested Fix", "Fix", "Mitigation"),
            ("Suggested Fix", "Recommendation", "Mitigation", "Fix"),
            fallback="",
            max_chars=1400,
        )
        label = vf.replace("|", "/")
        if _is_substantive_body_evidence(desc):
            desc_parts.append(f"From `{label}`:\n{_sanitize_client_body(desc)}")
        if _is_substantive_body_evidence(impact):
            impact_parts.append(f"From `{label}`:\n{_sanitize_client_body(impact)}")
        if _is_substantive_body_evidence(poc):
            poc_parts.append(f"From `{label}`:\n{_sanitize_client_body(poc)}")
        if _is_substantive_body_evidence(rec):
            rec_parts.append(f"From `{label}`:\n{_sanitize_client_body(rec)}")

    desc = "\n\n".join(desc_parts) or _sanitize_client_body(str(row.get("description", "") or "Verified evidence is listed in the shard manifest."))
    impact = "\n\n".join(impact_parts) or "Impact follows from the verified constituent evidence and report-index severity assignment."
    poc = "\n\n".join(poc_parts) or "No executable PoC output was recorded; verifier relied on code trace evidence."
    rec = "\n\n".join(rec_parts) or _sanitize_client_body(str(row.get("recommendation", "") or "Apply the mitigation described by the verifier artifacts and add regression coverage."))
    verdict = " / ".join(dict.fromkeys(verdicts)) or "CONFIRMED"
    confidence = "HIGH" if has_mechanical_proof(evidence) or any("POC-PASS" in p for p in poc_parts) else "MEDIUM"

    return "\n".join([
        f"### [{report_id}] {title}",
        "",
        f"**Severity**: {severity}",
        f"**Verdict**: {verdict}",
        f"**Location**: {location}",
        f"**Confidence**: {confidence} ({evidence})",
        "",
        "**Description**:",
        desc,
        "",
        "**Impact**:",
        impact,
        "",
        "**PoC Result**:",
        poc,
        "",
        "**Recommendation**:",
        rec,
        "",
    ]).replace("\n\n\n", "\n\n").strip()


def _replace_report_section(body: str, report_id: str, replacement: str) -> str:
    section = _section_for_report_id(body, report_id)
    if not section:
        return body.rstrip() + "\n\n" + replacement.strip() + "\n"
    start = body.find(section)
    if start < 0:
        return body
    end = start + len(section)
    return body[:start].rstrip() + "\n\n" + replacement.strip() + "\n\n" + body[end:].lstrip()


def _sanitize_undefined_report_references(body: str) -> str:
    """Remove report-like IDs from prose when no matching body section exists."""
    defined = {
        m.group(1).upper()
        for m in re.finditer(
            r"(?im)^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\]",
            body or "",
        )
    }

    def repl(match: re.Match[str]) -> str:
        prefix = match.group(1)
        rid = _normalize_report_id(match.group(2))
        if rid in defined:
            return match.group(0)
        return f"{prefix} the related finding"

    return re.sub(
        r"(?i)\b(duplicate of|duplicates|same as|absorbed by|absorbs|related to|"
        r"cross-reference(?:d)? to)\s+(?:\[\s*)?([CHMLI]-\d{1,3})(?:\s*\])?",
        repl,
        body or "",
    )


def _section_has_substantive_report_body(section: str) -> bool:
    text = re.sub(r"(?im)^###\s+.*$", "", section or "")
    if len(text.strip()) < 350:
        return False
    if not _is_substantive_body_evidence(text):
        return False
    return bool(re.search(
        r"(?im)^\*\*(?:Description|Impact|Recommendation|PoC Result|Evidence Tag)\*\*\s*:",
        section or "",
    ))


def _normalize_report_blocked_markers(body: str) -> tuple[str, int]:
    """Downgrade stale REPORT-BLOCKED headings to ordinary UNVERIFIED prose.

    `REPORT-BLOCKED` is a pipeline failure marker, not a synonym for "no
    executable verifier file." If a section already has client-usable body
    text, location, impact, and recommendation, keep it in the report as
    low-confidence/unverified rather than poisoning final report quality.
    """
    out: list[str] = []
    last = 0
    changed = 0
    pat = re.compile(
        r"(?im)^###\s+(?P<head>[^\n]*\[REPORT-BLOCKED[^\]]*\][^\n]*)\n"
    )
    matches = list(pat.finditer(body or ""))
    for i, m in enumerate(matches):
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(body or "")
        section = (body or "")[m.start():section_end]
        out.append((body or "")[last:m.start()])
        heading = m.group("head")
        if (
            re.search(r"\[[CHMLI]-\d+\]", heading, re.IGNORECASE)
            and _section_has_substantive_report_body(section)
        ):
            clean_heading = re.sub(
                r"\s*\[REPORT-BLOCKED[^\]]*\]\s*",
                " ",
                heading,
                flags=re.IGNORECASE,
            )
            clean_heading = re.sub(r"\s+", " ", clean_heading).strip()
            out.append("### " + clean_heading + "\n")
            changed += 1
        else:
            out.append(m.group(0))
        last = m.end()
    out.append((body or "")[last:])
    return "".join(out), changed


def _repair_report_body_from_manifest(scratchpad: Path, phase_name: str) -> int:
    if not phase_name.startswith("report_body_writer_"):
        return 0
    shard_key = phase_name.replace("report_body_writer_", "report_")
    manifest_path = scratchpad / "body_manifests" / f"{shard_key}.json"
    body_path = scratchpad / f"{shard_key}.md"
    if not manifest_path.exists() or not body_path.exists():
        return 0
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        body = body_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0

    repaired = 0
    for row in manifest.get("findings", []) or []:
        rid = str(row.get("report_id", "") or "").upper()
        if not rid or row.get("report_blocked"):
            continue
        section = _section_for_report_id(body, rid)
        loc = str(row.get("location", "") or "").strip()
        needs_location_repair = bool(
            loc and section and not _location_present_in_body(loc, section)
        )
        if "[REPORT-BLOCKED" not in section.upper() and not needs_location_repair:
            continue
        body = _replace_report_section(
            body,
            rid,
            _synth_report_section_from_manifest_row(scratchpad, row),
        )
        repaired += 1
    evidence_bundle_path = scratchpad / "report_evidence_records.json"
    if evidence_bundle_path.exists():
        try:
            evidence_bundle = _validate_report_evidence_bundle(
                json.loads(evidence_bundle_path.read_text(encoding="utf-8"))
            )
            projected = _project_report_evidence_markdown(body, evidence_bundle)
            if projected != body:
                body = projected
                repaired += 1
        except (OSError, UnicodeError, json.JSONDecodeError, _ReportEvidenceError) as exc:
            debt_path = scratchpad / "report_evidence_runtime_debt.md"
            debt_path.write_text(
                "# Report Evidence Runtime Debt\n\n"
                "The typed evidence projection could not be applied before report "
                "assembly. The finding body remains present, but evidence assurance "
                "requires human review.\n\n"
                f"- Failure class: `{type(exc).__name__}`\n",
                encoding="utf-8",
            )
    if repaired:
        body_path.write_text(body.rstrip() + "\n", encoding="utf-8")
    return repaired


def _normalize_tier_report_blocked_markers(scratchpad: Path, filenames: list[str]) -> int:
    total = 0
    for name in filenames:
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        new_text, changed = _normalize_report_blocked_markers(text)
        if changed:
            p.write_text(new_text.rstrip() + "\n", encoding="utf-8")
            total += changed
    return total


def _patch_report_index_with_recovered(
    scratchpad: Path,
    recovered: list[tuple[str, str, str, str]],
) -> int:
    """Append promotion-recovered finding rows to report_index.md.

    v2.5.4: Without this, _repair_promotion_dropouts adds body sections
    that get_tier_assignments() doesn't know about → body_assignment_count
    FAIL (61 vs 58) and _check_promotion_symmetry can't find the internal
    IDs → promotion_receipt FAIL. Both create an infinite degraded loop.

    Each tuple is ``(finding_id, report_id, title, severity)``.
    Returns number of rows actually appended (skips duplicates).
    """
    if not recovered:
        return 0
    ri = scratchpad / "report_index.md"
    if not ri.exists():
        return 0
    try:
        text = ri.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0

    new = [
        (fid, rid, title, sev)
        for fid, rid, title, sev in recovered
        if not re.search(rf"(?<!\w){re.escape(fid)}(?!\w)", text)
    ]
    if not new:
        return 0

    rows = []
    for fid, rid, title, sev in new:
        title_clean = title.replace("|", "/").strip()[:80]
        rows.append(
            f"| {rid} | {title_clean} | {sev} | - | [CODE-TRACE] | "
            f"CONFIRMED | RECOVERED | {fid} |"
        )

    block = "\n".join(rows) + "\n"

    cut_re = re.compile(
        r"(?m)^\s*#{1,4}\s+(?:Excluded|Tier\s+Assignment|Consolidation\s+Map|"
        r"Cross-Reference|Appendix|Promotion\s+Failure|Report\s+Coverage)",
        re.IGNORECASE,
    )
    m = cut_re.search(text)
    if m:
        text = text[: m.start()] + "\n" + block + "\n" + text[m.start() :]
    else:
        text = text.rstrip() + "\n\n" + block

    try:
        ri.write_text(text, encoding="utf-8")
    except Exception:
        return 0
    return len(new)


def _repair_promotion_dropouts(body: str, scratchpad: Path) -> str:
    """Synthesize sections for CONFIRMED verify findings not in the report.

    v2.5.2: Catches the VS-*/EN-* dropout class where the Index Agent
    omitted a CONFIRMED finding from the Master Finding Index, causing
    _repair_report_body_from_assignments to miss it (no tier assignment).
    This pass uses verify receipts directly — if a finding was CONFIRMED
    in a verify file and doesn't appear in the body, synthesize a section.

    v2.5.4: Also patches report_index.md with recovered mappings so that
    get_tier_assignments() and _check_promotion_symmetry() see them.
    Without this, body sections=61 vs assignments=58 → infinite FAIL loop.
    """
    receipts = _collect_verify_promotion_receipts(scratchpad)
    if not receipts:
        return body

    assignments, _ = get_tier_assignments(scratchpad)
    assigned_internal = {
        a.get("finding_id", "") for a in assignments if a.get("finding_id")
    }

    from plamen_parsers import _INTERNAL_FINDING_ID_RE
    appendix_cut = body.find("## Appendix A")
    body_pre_appendix = body[:appendix_cut] if appendix_cut > 0 else body
    present_internal = set(_INTERNAL_FINDING_ID_RE.findall(body_pre_appendix))

    present_report = set(re.findall(
        r"^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[([CHMLI]-\d+)\]",
        body, re.MULTILINE,
    ))

    queue_rows = {
        (r.get("finding id") or "").strip(): r
        for r in parse_verification_queue_rows(scratchpad)
        if (r.get("finding id") or "").strip()
    }

    dropped: list[str] = []
    for fid in sorted(receipts):
        if fid in assigned_internal:
            continue
        if fid in present_internal:
            continue
        dropped.append(fid)

    if not dropped:
        return body

    next_ids: dict[str, int] = {}
    for rid in present_report:
        prefix = rid[0]
        num = int(rid.split("-")[1])
        next_ids[prefix] = max(next_ids.get(prefix, 0), num + 1)
    index_counters = _next_report_id_counters(scratchpad)
    for prefix, max_num in index_counters.items():
        next_ids[prefix] = max(next_ids.get(prefix, 0), max_num + 1)

    unresolved_ids = _collect_judge_unresolved_ids(scratchpad)
    missing_sections: list[str] = []
    recovered_mappings: list[tuple[str, str, str, str]] = []
    for fid in dropped:
        qrow = queue_rows.get(fid, {})
        verify_path = _verify_file_for_id(scratchpad, fid)
        try:
            verify_text = verify_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            verify_text = ""
        sev = _severity_name_from_text(verify_text, qrow)
        prefix = severity_letter_from_name(sev)
        num = next_ids.get(prefix, 1)
        next_ids[prefix] = num + 1
        report_id = f"{prefix}-{num:02d}"
        section = _synth_report_section_from_verify(
            scratchpad, report_id, fid, qrow, fid in unresolved_ids,
        )
        missing_sections.append(section)
        present_report.add(report_id)
        title = _sanitize_client_title(
            (qrow.get("title") or "Verified finding").strip()
        )
        recovered_mappings.append((fid, report_id, title, sev))
        log.info(f"[report_assemble] promotion self-heal: {fid} → [{report_id}]")

    n_patched = _patch_report_index_with_recovered(scratchpad, recovered_mappings)
    if n_patched:
        log.info(
            f"[report_assemble] patched report_index.md with "
            f"{n_patched} recovered mapping(s)"
        )

    insertion = (
        "\n\n".join(missing_sections)
        + "\n\n---\n\n"
    )
    marker = "\n## Priority Remediation Order"
    if marker in body:
        return body.replace(marker, "\n" + insertion + "## Priority Remediation Order", 1)
    return body.rstrip() + "\n\n---\n\n" + insertion


_REPORT_SECTION_HEADING_RE = re.compile(
    r"(?im)^#{2,3}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI]-\d+)\s*\]"
)


def _defined_report_section_ids(*tier_texts: str) -> set[str]:
    """Return the set of report IDs that have a real `## [X-NN]` / `### [X-NN]`
    finding section across the given tier texts.

    Used to prevent the Priority Remediation Order / Executive Summary from
    citing a report ID that the Master Finding Index lists but that has no
    corresponding finding section in the assembled body (the "ghost reference"
    class). Matches the heading shapes the assembler actually emits (H2 or H3,
    optional REPORT-BLOCKED prefix, optional inner whitespace).
    """
    ids: set[str] = set()
    for text in tier_texts:
        if not text:
            continue
        for m in _REPORT_SECTION_HEADING_RE.finditer(text):
            ids.add(m.group(1).upper())
    return ids


def _finalize_report_tier_section(section: str, id_to_title: dict) -> str:
    """Rewrite generic/broken finding headings from the canonical index title
    and strip internal-status prose. Preserves a trailing verification-status
    tag ([VERIFIED]/[CONFIRMED]/[UNVERIFIED]/[CONTESTED]); drops a
    [REPORT-BLOCKED ...] tag."""
    if not section:
        return section
    head_re = re.compile(
        r"^(#{2,3})\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI]-\d+)\s*\]\s*(.*?)\s*$"
    )
    status_re = re.compile(
        r"(?i)(\[(?:VERIFIED|CONFIRMED|UNVERIFIED|CONTESTED|VERIFICATION NOT EXECUTED|REPORT-BLOCKED[^\]]*)\])\s*$"
    )
    out = []
    for ln in section.split("\n"):
        m = head_re.match(ln)
        if not m:
            out.append(ln)
            continue
        level, rid, rest = m.group(1), m.group(2), m.group(3)
        status = ""
        sm = status_re.search(rest)
        title_part = rest
        if sm:
            tag = sm.group(1)
            if not re.match(r"(?i)\[REPORT-BLOCKED", tag):
                status = " " + tag
            title_part = rest[:sm.start()].strip()
        title_clean = _sanitize_client_title(title_part)
        if (not title_clean
                or title_clean.lower() in {"verification", "untitled", "finding", "verified finding"}
                or len(title_clean) < 8):
            title_clean = id_to_title.get(rid) or title_clean or "Verified finding"
        out.append(f"{level} [{rid}] {title_clean}{status}".rstrip())
    return _sanitize_client_body("\n".join(out))


_HUMAN_REVIEW_SOURCES: tuple[tuple[str, str], ...] = (
    ("report_semantic_retention_risks.md", "Retention / obligation coverage"),
    ("report_semantic_severity_repairs.md", "Severity-provenance adjustments"),
    ("chain_composition_coverage_gaps.md", "Chain-composition coverage gaps"),
    (
        "depth_finalization_human_review.md",
        "Depth recall-postprocessor finalization",
    ),
)


def _delivered_lifecycle_work_ids(scratchpad: Path) -> set[str]:
    """Return internal IDs with both active records and a material body."""

    try:
        payload = json.loads(
            (scratchpad / "report_records.json").read_text(
                encoding="utf-8", errors="strict"
            )
        )
    except Exception:
        return set()
    body = ""
    for name in (
        "report_critical_high.md", "report_medium.md", "report_medium_a.md",
        "report_medium_b.md", "report_low_info.md", "report_low_info_a.md",
        "report_low_info_b.md",
    ):
        path = scratchpad / name
        if path.is_file():
            try:
                body += "\n" + path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    delivered: set[str] = set()
    for row in payload.get("active") or [] if isinstance(payload, dict) else []:
        if not isinstance(row, dict) or row.get("report_blocked") is True:
            continue
        report_id = str(row.get("report_id") or "").strip().upper()
        if not report_id or re.search(
            rf"(?im)^\s*#{{2,6}}\s+\[?{re.escape(report_id)}\]?\b", body
        ) is None:
            continue
        values = [
            row.get("finding_id"),
            *(row.get("candidate_ids") or []),
            *(row.get("absorbed_finding_ids") or []),
        ]
        for value in values:
            for match in _INTERNAL_ID_RE.finditer(str(value or "")):
                delivered.add(match.group(1).upper())
    return delivered


def _security_obligation_appendix_projection(scratchpad: Path) -> str:
    """Render client-safe retention from typed JSON and its PhaseIO receipt.

    The Markdown sidecar is a cache only. Deletion or tampering is reported,
    then the authoritative JSON is projected deterministically so retention
    cannot silently disappear or leak exact internal SOT aliases.
    """

    trace_names = (
        "security_obligation_lifecycle.json",
        "security_obligation_authority.json",
        "mandatory_reverification_denominator.json",
        "mandatory_reverification_assignment.json",
        "mandatory_reverification_completion.json",
    )
    if not any((scratchpad / name).exists() for name in trace_names):
        # Repositories/runs that predate or never armed P1-C do not acquire a
        # synthetic warning merely because another report appendix is built.
        return ""
    try:
        import security_obligation_lifecycle as lifecycle
        from artifact_ledger import read_artifact_ledger

        ledger = read_artifact_ledger(scratchpad)
        units = [
            row
            for row in ledger.get("work_units", {}).values()
            if isinstance(row, dict)
            and str(row.get("work_unit_key") or "").endswith(
                "/report_index/security_obligation_lifecycle.final"
            )
            and row.get("semantic_status") == "ACTIVE"
        ]
        if len(units) != 1:
            raise ValueError("exact lifecycle PhaseIO transaction is unavailable")
        unit = units[0]
        authority_path = scratchpad / lifecycle.AUTHORITY_FILE
        authority_identity = f"scratchpad:{lifecycle.AUTHORITY_FILE}"
        binding = ledger.get("artifact_bindings", {}).get(authority_identity)
        artifact = (unit.get("artifacts") or {}).get(authority_identity)
        raw = authority_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if (
            not isinstance(binding, dict)
            or not isinstance(artifact, dict)
            or binding.get("owner_key") != unit.get("work_unit_key")
            or artifact.get("owner_key") != unit.get("work_unit_key")
            or binding.get("status") != "ACTIVE"
            or binding.get("sha256") != digest
            or artifact.get("sha256") != digest
        ):
            raise ValueError("lifecycle JSON lacks current PhaseIO ownership")
        expected = {
            str(identity).split(":", 1)[1]: str(row.get("sha256") or "")
            for identity, row in (unit.get("input_bindings") or {}).items()
            if str(identity).startswith("scratchpad:")
            and isinstance(row, dict)
            and re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256") or ""))
        }
        recorded = json.loads(raw.decode("utf-8", errors="strict"))
        lifecycle._validate_payload(recorded)
        rebuilt = lifecycle.build_security_obligation_lifecycle(
            scratchpad, expected_input_sha256=expected
        )
        if recorded != rebuilt or recorded.get("run_id") != unit.get("run_id"):
            raise ValueError("lifecycle JSON is stale for current exact inputs")

        cache_warning = ""
        cache_path = scratchpad / lifecycle.REPORT_RETENTION_FILE
        cache_identity = f"scratchpad:{lifecycle.REPORT_RETENTION_FILE}"
        cache_binding = ledger.get("artifact_bindings", {}).get(cache_identity)
        try:
            cache_sha = hashlib.sha256(cache_path.read_bytes()).hexdigest()
        except OSError:
            cache_sha = ""
        if (
            not isinstance(cache_binding, dict)
            or cache_binding.get("owner_key") != unit.get("work_unit_key")
            or cache_binding.get("sha256") != cache_sha
        ):
            cache_warning = (
                "\n\n**Projection cache status**: STALE_OR_MISSING; regenerated "
                "from authoritative lifecycle JSON."
            )

        delivered = _delivered_lifecycle_work_ids(scratchpad)
        identity_counts: Counter[str] = Counter()
        for row in recorded.get("rows") or []:
            if not isinstance(row, dict):
                continue
            for value in {
                str(row.get("assigned_work_item_id") or "").upper(),
                str(row.get("candidate_id") or "").upper(),
            } - {""}:
                identity_counts[value] += 1
        retained = []
        for row in recorded.get("rows") or []:
            if not isinstance(row, dict) or row.get("state") == lifecycle.AUTHORIZED_NEGATIVE:
                continue
            work_ids = {
                str(row.get("assigned_work_item_id") or "").upper(),
                str(row.get("candidate_id") or "").upper(),
            } - {""}
            if (
                row.get("state")
                in {lifecycle.VERIFIED_CONFIRMED, lifecycle.VERIFIED_CONTESTED}
                and work_ids
                and work_ids & delivered
                and all(identity_counts[value] == 1 for value in work_ids)
            ):
                continue
            retained.append(row)
        authority_issues = [str(issue) for issue in recorded.get("issues") or []]
        if (
            not retained
            and not cache_warning
            and recorded.get("status") == "COMPLETE"
            and not authority_issues
        ):
            return ""
        lines = [
            "### Security obligation lifecycle retention",
            "",
            "This methodology-coverage surface is not a finding, severity, proof, or negative decision.",
            "",
            f"**Lifecycle status**: {recorded.get('status', 'UNKNOWN')}",
            f"**Retained coverage obligations**: {len(retained)}",
        ]
        if retained:
            lines.extend((
                "",
                "| Coverage reference | State | Scope | Required action | Debt |",
                "|---|---|---|---|---|",
            ))
            for row in retained:
                alias = str(row.get("alias_id") or "")
                opaque = hashlib.sha256(alias.encode("utf-8")).hexdigest()[:12].upper()
                state = str(row.get("state") or "UNKNOWN").replace("|", "/")
                symbol = str(row.get("symbol") or "").replace("|", "/")
                scope = (
                    f"methodology coverage for `{symbol}`"
                    if symbol else "methodology coverage"
                )
                debt = ", ".join(str(item) for item in row.get("debt_reasons") or [])
                debt = debt.replace("|", "/") or "none"
                lines.append(
                    f"| coverage-ref-{opaque} | {state} | {scope} | "
                    f"HUMAN_REVIEW_OR_VERIFIED_BODY | {debt} |"
                )
        if authority_issues or recorded.get("status") != "COMPLETE":
            lines.extend(("", "**Lifecycle authority debt**:", ""))
            if authority_issues:
                for ordinal, issue in enumerate(authority_issues, 1):
                    safe = re.sub(
                        r"\bSOT-[0-9A-Fa-f]{24}\b",
                        lambda match: "coverage-ref-" + hashlib.sha256(
                            match.group(0).encode("utf-8")
                        ).hexdigest()[:12].upper(),
                        issue,
                    )
                    safe = _render_actionable_coverage_references(
                        safe, scratchpad
                    ).replace("\n", " ").replace("|", "/")
                    lines.append(f"- debt-{ordinal:03d}: {safe}")
            else:
                lines.append(
                    "- lifecycle status is degraded without a row-local closure; "
                    "bounded human review is required."
                )
        return "\n".join(lines) + cache_warning
    except Exception as exc:
        return (
            "### Security obligation lifecycle retention\n\n"
            "**Status**: UNKNOWN — authoritative lifecycle/PhaseIO replay "
            f"failed ({type(exc).__name__}). Human review is required."
        )


def _coverage_report_reference_map(scratchpad: Path) -> dict[str, str]:
    """Map typed Master-Index identities to public report labels.

    Status, location, trust-adjustment, and title prose can cite ID-shaped
    tokens.  They are not lineage columns and must not manufacture a mapping.
    Prefer the canonical header roles; use the existing assignment parser only
    as a format-tolerance fallback when no typed Master table is available.
    """
    path = Path(scratchpad) / "report_index.md"
    if not path.exists():
        return {}
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    mapping: dict[str, str] = {}
    scope = _extract_h2_section(text, "Master Finding Index") or text
    headers: dict[str, int] = {}
    saw_typed_master_table = False
    lineage_header_aliases = {
        "internal id", "internal ids", "internal finding id",
        "internal finding ids", "internal hypothesis",
        "internal hypothesis id", "internal hypothesis ids",
        "hypothesis id", "hypothesis ids", "source id", "source ids",
    }
    for line in scope.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or _is_separator_row(stripped):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        normalized = [re.sub(r"[^a-z0-9]+", " ", cell.lower()).strip() for cell in cells]
        if not headers:
            report_cols = [i for i, name in enumerate(normalized) if name == "report id"]
            title_cols = [i for i, name in enumerate(normalized) if name == "title"]
            internal_cols = [
                i for i, name in enumerate(normalized)
                if name in lineage_header_aliases
            ]
            if report_cols and title_cols:
                saw_typed_master_table = True
            if report_cols and title_cols and internal_cols:
                headers = {
                    "report": report_cols[0],
                    "title": title_cols[0],
                    "internal": internal_cols[0],
                }
            continue
        if max(headers.values()) >= len(cells):
            continue
        public = re.fullmatch(
            r"[\s`*_\[]*([CHMLI]-\d{1,3})[\s`*_\]]*",
            cells[headers["report"]],
            re.IGNORECASE,
        )
        if not public:
            continue
        report_id = public.group(1).upper()
        title = re.sub(r"[`*_\[\]]", "", cells[headers["title"]])
        title = re.sub(r"\s+", " ", title).strip(" :-")[:120]
        label = f"{report_id} ({title})" if title else report_id
        for match in _INTERNAL_ID_RE.finditer(cells[headers["internal"]]):
            fid = match.group(1).upper()
            if fid != report_id:
                mapping.setdefault(fid, label)
    if mapping or headers or saw_typed_master_table:
        return mapping

    title_map = _report_id_title_map(scratchpad)
    try:
        assignments = parse_report_index_assignments(scratchpad)
    except Exception:
        assignments = []
    for row in assignments:
        report_id = str(row.get("report_id") or "").strip().upper()
        if not report_id:
            continue
        title = title_map.get(report_id, "")
        label = f"{report_id} ({title})" if title else report_id
        for match in _INTERNAL_ID_RE.finditer(str(row.get("finding_id") or "")):
            fid = match.group(1).upper()
            if fid != report_id:
                mapping.setdefault(fid, label)
    return mapping


def _render_actionable_coverage_references(text: str, scratchpad: Path) -> str:
    """Resolve coverage scopes before generic client-ID sanitization.

    If an internal identity has no public report assignment, retain a stable
    opaque source reference derived from that identity. The stable receipt ID,
    producer, and scope remain sufficient to reconcile the row without leaking
    an internal pipeline identifier into client prose.
    """
    public_refs = _coverage_report_reference_map(scratchpad)

    def replace(match: re.Match[str]) -> str:
        fid = match.group(1).upper()
        if fid in public_refs:
            return public_refs[fid]
        # Coverage receipts are an internal control-plane artifact. If a typed
        # Master lineage column did not establish a public identity, preserve
        # actionability via an opaque stable reference even for ambiguous H-NN
        # shapes; shape alone is not public lineage evidence.
        digest = hashlib.sha256(fid.encode("utf-8")).hexdigest()[:12].upper()
        return f"source-ref-{digest}"

    return _INTERNAL_ID_RE.sub(replace, text or "")


def _build_human_review_appendix(scratchpad: Path) -> str:
    """Fold degrade-with-flag items (report_semantic_*.md) into a DELIVERED
    appendix.

    The late-stage gates that now degrade-with-flag instead of halting
    (obligation/retention retention, severity-provenance) write their deferred
    items to report_semantic_*.md "for human review". Those files live in the
    scratchpad, which is cleaned on success and is never read by the client — so
    the human-review flag never reached the human. This folds them into
    AUDIT_REPORT.md so the flag is actually delivered (and survives cleanup).

    Returns "" when there is nothing to flag.
    """
    blocks: list[str] = []
    ordered: list[tuple[str, str]] = list(_HUMAN_REVIEW_SOURCES)
    known = {n for n, _ in ordered}
    lifecycle_projection = _security_obligation_appendix_projection(scratchpad).strip()
    if lifecycle_projection:
        blocks.append(lifecycle_projection)
    # The JSON/PhaseIO projection above is authoritative; never consume the
    # mutable Markdown cache through the generic source loop.
    known.add("security_obligation_report_retention.md")
    # Registered producer delivery is a typed JSON authority. Its Markdown
    # file is only a cache: deleting/staling that cache must not erase DXRE or
    # other producer review obligations from the delivered appendix.
    delivery_projection_name = "report_semantic_finding_delivery.md"
    known.add(delivery_projection_name)
    delivery_receipt = scratchpad / "finding_delivery_receipt.json"
    delivery_successor = scratchpad / PREVERIFY_DELIVERY_SUCCESSOR_NAME
    final_successor = scratchpad / PREVERIFY_INVENTORY_SUCCESSOR_NAME
    if delivery_successor.exists() or final_successor.exists():
        try:
            final_payload = json.loads(
                final_successor.read_text(encoding="utf-8", errors="strict")
            )
            successor_payload = json.loads(
                delivery_successor.read_text(
                    encoding="utf-8", errors="strict"
                )
            )
            validate_preverify_successor_payloads(
                scratchpad,
                final_payload=final_payload,
                delivery_payload=successor_payload,
                run_id=str(final_payload.get("run_id") or ""),
            )
            delivery_payload = successor_payload["delivery_payload"]
            delivery_text = _render_delivery_human_review_projection(
                delivery_payload
            ).strip()
            if delivery_text:
                delivery_text = re.sub(
                    r"(?m)\A#\s+[^\n]*\n+", "", delivery_text
                ).strip()
                blocks.append(
                    "### Registered Finding Delivery Debt\n\n" + delivery_text
                )
        except Exception as exc:
            blocks.append(
                "### Registered Finding Delivery Debt\n\n"
                "**Status**: UNKNOWN — authoritative receipt could not be "
                f"projected ({type(exc).__name__})."
            )
    elif delivery_receipt.exists():
        try:
            delivery_payload = json.loads(
                delivery_receipt.read_text(encoding="utf-8", errors="strict")
            )
            delivery_text = _render_delivery_human_review_projection(
                delivery_payload
            ).strip()
            if delivery_text:
                delivery_text = re.sub(
                    r"(?m)\A#\s+[^\n]*\n+", "", delivery_text
                ).strip()
                blocks.append(
                    "### Registered Finding Delivery Debt\n\n" + delivery_text
                )
        except Exception as exc:
            blocks.append(
                "### Registered Finding Delivery Debt\n\n"
                "**Status**: UNKNOWN - authoritative receipt could not be "
                f"projected ({type(exc).__name__})."
            )
    # The JSON journal, not its Markdown projection, is authoritative. A
    # missing/deleted projection must not erase a postprocessor failure from
    # the delivered report appendix.
    finalization_receipt = scratchpad / "depth_finalization_receipt.json"
    if finalization_receipt.exists():
        try:
            payload = json.loads(
                finalization_receipt.read_text(encoding="utf-8", errors="replace")
            )
            processors = payload.get("processors", {}) if isinstance(payload, dict) else {}
            failed = [
                (name, row)
                for name, row in processors.items()
                if not isinstance(row, dict) or row.get("status") != "COMPLETE"
            ] if isinstance(processors, dict) else [("journal", {"error": "invalid processors"})]
            if failed or payload.get("status") == "DEGRADED_HUMAN_REVIEW":
                lines = [
                    "### Depth recall-postprocessor finalization",
                    "",
                    f"**Status**: {payload.get('status', 'UNKNOWN')}",
                    "",
                    "| Processor | State | Error |",
                    "|---|---|---|",
                ]
                for name, row in failed:
                    state = str(row.get("status", "UNKNOWN")).replace("|", "/")
                    error = str(row.get("error", "outcome incomplete")).replace("|", "/")
                    lines.append(f"| {name} | {state} | {error} |")
                blocks.append("\n".join(lines))
        except Exception as exc:
            blocks.append(
                "### Depth recall-postprocessor finalization\n\n"
                "**Status**: UNKNOWN — authoritative receipt could not be "
                f"parsed ({type(exc).__name__})."
            )
    # The structured JSON ledger is authoritative. Consume its in-memory
    # projection directly so a failed/stale Markdown cache cannot hide debt.
    coverage_name = "report_semantic_coverage_shortfalls.md"
    known.add(coverage_name)
    try:
        coverage_text = _render_actionable_coverage_references(
            coverage_shortfalls_projection(scratchpad), scratchpad
        ).strip()
    except Exception as exc:
        coverage_text = (
            "# Coverage Shortfalls\n\n"
            "`COVERAGE-SHORTFALL` projection failed; bounded mechanical "
            f"coverage is UNKNOWN. Detail: {exc!r}"
        )
    if coverage_text:
        coverage_text = re.sub(
            r"(?m)\A#\s+[^\n]*\n+", "", coverage_text
        ).strip()
        blocks.append(f"### Coverage Shortfalls\n\n{coverage_text}")
    try:
        for p in sorted(scratchpad.glob("report_semantic_*.md")):
            if p.name not in known:
                label = (
                    p.stem.replace("report_semantic_", "").replace("_", " ").strip().title()
                    or p.name
                )
                ordered.append((p.name, label))
                known.add(p.name)
    except Exception:
        pass
    for name, label in ordered:
        if (
            name == "depth_finalization_human_review.md"
            and finalization_receipt.exists()
        ):
            continue
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace").strip()
        except Exception:
            continue
        if (
            name == "chain_composition_coverage_gaps.md"
            and re.search(r"(?im)^\*\*Status\*\*:\s*COMPLETE\s*$", text)
        ):
            continue
        # Drop a leading H1 the source carries; keep the substantive body.
        text = re.sub(r"(?m)\A#\s+[^\n]*\n+", "", text).strip()
        if len(text) < 20:
            continue
        blocks.append(f"### {label}\n\n{text}")
    return "\n\n".join(blocks)


_TIER_LOC_FILE_RE = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./\\-]*\.(?:sol|rs|go|move|vy|cairo))"
)


def _recover_tier_locations(
    section: str, id_to_location: dict[str, str], project_root: str
) -> tuple[str, int]:
    """Repair tier-writer LOCATION corruption against the authoritative index.

    Observed failure mode: a report tier writer overwrites a finding's
    `**Location**` with a non-existent file (e.g. a path cribbed from a recon
    "REMOVED files" table) — corrupting a REAL, verified finding's location. The
    validated `report_index.md` Master Finding Index still holds the correct
    location. For each `### [X-NN]` section whose `**Location**` cites ONLY files
    that do not exist in the source tree, replace it with the index location
    (when THAT one resolves). This RECOVERS the real finding — it never drops it.
    Returns (patched_section, n_recovered)."""
    if not id_to_location or not section:
        return section, 0
    try:
        from plamen_parsers import _project_source_index
    except Exception:
        return section, 0
    try:
        src_index = _project_source_index(project_root)
    except Exception:
        return section, 0
    root = Path(project_root)

    def _all_files_missing(loc: str) -> bool:
        files = _TIER_LOC_FILE_RE.findall(loc or "")
        if not files:
            return False  # no parseable file token -> not a recoverable corruption
        for f in files:
            f = f.strip().replace("\\", "/").lstrip("./")
            if (root / f).is_file() or src_index.get(Path(f).name):
                return False  # at least one cited file is real -> not corrupted
        return True

    n = 0
    sec_re = re.compile(
        r"(^###\s+\[([CHMLI]-\d+)\][^\n]*\n)(.*?)(?=^###\s+\[|\Z)", re.S | re.M
    )

    def _patch(m: "re.Match") -> str:
        nonlocal n
        head, rid, body = m.group(1), m.group(2), m.group(3)
        idx_loc = id_to_location.get(rid)
        if not idx_loc:
            return m.group(0)
        lm = re.search(r"(?im)^(\*\*Location\*\*:\s*)(.+)$", body)
        if not lm:
            return m.group(0)
        body_loc = lm.group(2)
        if _all_files_missing(body_loc) and not _all_files_missing(idx_loc):
            new_body = body[: lm.start(2)] + idx_loc.strip() + body[lm.end(2):]
            n += 1
            return head + new_body
        return m.group(0)

    return sec_re.sub(_patch, section), n


_BODY_STATUS_TOKENS = ("VERIFIED", "CONFIRMED", "CONTESTED", "UNRESOLVED", "UNVERIFIED")
_BODY_HEADER_STATUS_RE = re.compile(
    r"(?m)^(###\s+\[([CHMLI]-\d+)\]\s+.+?)"
    r"(?:\s+\[(?:" + "|".join(_BODY_STATUS_TOKENS) + r")[^\]\n]*\])?\s*$"
)


def _index_status_map(idx_text: str) -> dict[str, str]:
    """Map report_id -> canonical verification status from the report_index
    Master Finding Index 'Verification' column.

    The Verification column is driver-computed from `status_binding.md`
    (verifier verdict + best evidence tag), so it is the single source of truth
    for the body header tag. This lets the assembler stamp the body header
    MECHANICALLY instead of trusting the tier-writer LLM's own [STATUS] token,
    which historically disagreed with the index (index CONFIRMED vs body
    UNVERIFIED). Returns {} when no Verification column is present.
    """
    out: dict[str, str] = {}
    try:
        section = _extract_h2_section(idx_text, "Master Finding Index")
    except Exception:
        section = ""
    if not section:
        return out
    id_re = re.compile(r"^[\*\[`_]*([CHMLI]-\d+)\b")
    vcol: int | None = None
    for line in section.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if vcol is None:
            low = [c.lower() for c in cells]
            if any("verification" in c for c in low):
                vcol = next(i for i, c in enumerate(low) if "verification" in c)
            continue
        m = id_re.match(cells[0]) if cells else None
        if not m or vcol >= len(cells):
            continue
        raw = cells[vcol].upper()
        for tok in _BODY_STATUS_TOKENS:
            if tok in raw:
                out[m.group(1)] = tok
                break
    return out


def _stamp_body_header_status(tier_text: str, status_map: dict[str, str]) -> str:
    """Overwrite each `### [X-NN] Title [STATUS]` header's status token with the
    canonical index status. Findings absent from the map keep their existing tag;
    only a KNOWN trailing status token is replaced (a title's own `[...]` is left
    alone). Mechanical — no LLM."""
    if not status_map:
        return tier_text

    def _repl(m: "re.Match[str]") -> str:
        canon = status_map.get(m.group(2))
        if not canon:
            return m.group(0)
        return f"{m.group(1).rstrip()} [{canon}]"

    return _BODY_HEADER_STATUS_RE.sub(_repl, tier_text)


def _assemble_report_python(
    scratchpad: Path, project_root: str
) -> bool:
    """Mechanical AUDIT_REPORT.md assembly. No LLM call.

    Reads tier files + report_index.md from `scratchpad`. Generates
    Executive Summary + Priority Remediation Order from `report_index.md`'s
    Summary counts and Master Finding Index rows. Writes AUDIT_REPORT.md
    at `project_root` and `report_quality.md` in scratchpad.

    Returns True on success. Hard-fails (returns False) if no tier files
    exist — that's a real upstream problem, not something this layer
    should silently paper over.
    """
    idx_path = scratchpad / "report_index.md"
    crit_high_path = scratchpad / "report_critical_high.md"
    medium_path = scratchpad / "report_medium.md"
    low_info_path = scratchpad / "report_low_info.md"
    audit_report_path = Path(project_root) / "AUDIT_REPORT.md"

    def _read(p: Path) -> str:
        try:
            return _llm_norm(p.read_text(encoding="utf-8", errors="replace")) if p.exists() else ""
        except Exception:
            return ""

    idx_text = _read(idx_path)
    if idx_text and not (scratchpad / "report_records.json").exists():
        try:
            _build_sc_body_writer_manifests(scratchpad)
        except Exception as exc:
            log.warning(f"[report_assemble] report_records recovery failed: {exc!r}")
    crit_high_text = _read(crit_high_path)
    medium_text = _read(medium_path)
    low_info_text = _read(low_info_path)
    _normalize_tier_report_blocked_markers(
        scratchpad,
        [
            "report_critical_high.md",
            "report_medium.md",
            "report_medium_a.md",
            "report_medium_b.md",
            "report_low_info.md",
            "report_low_info_a.md",
            "report_low_info_b.md",
        ],
    )
    crit_high_text = _read(crit_high_path)
    medium_text = _read(medium_path)
    low_info_text = _read(low_info_path)

    # Fix 1 (mechanical body-label binding): stamp every body header's
    # verification status from the canonical report_index Verification column so
    # the body can never disagree with the index. The tier-writer LLM's own
    # [STATUS] token is overridden — it historically wrote [UNVERIFIED] for
    # findings the index (correctly) marked CONFIRMED.
    _status_map = _index_status_map(idx_text)
    if _status_map:
        crit_high_text = _stamp_body_header_status(crit_high_text, _status_map)
        medium_text = _stamp_body_header_status(medium_text, _status_map)
        low_info_text = _stamp_body_header_status(low_info_text, _status_map)

    if not (crit_high_text or medium_text or low_info_text):
        log.error(
            "[report_assemble] no tier files found in scratchpad — "
            "cannot assemble AUDIT_REPORT.md"
        )
        return False

    project_name = Path(project_root).name
    today = datetime.now().strftime("%Y-%m-%d")

    # --- Parse Report Header Info from report_index.md -----------------------
    # The LLM Index Agent writes a richer header block (Language/Version, Build
    # Status, Static Analysis Status, Scope, Auditor).  Extract these so the
    # assembled report includes them on separate lines rather than the minimal
    # fallback.  Keys are matched case-insensitively; values are stripped of
    # leading/trailing markdown bold markers.
    header_info: dict[str, str] = {}
    header_section = _extract_h2_section(idx_text, "Report Header Info")
    for hm in re.finditer(
        r"[-*]\s*\*?\*?([^:*]+?)\*?\*?\s*:\s*(.+)", header_section
    ):
        key = hm.group(1).strip()
        val = re.sub(r"^\*\*|\*\*$", "", hm.group(2).strip()).strip()
        if val:
            header_info[key.lower()] = val
    if "project name" in header_info:
        project_name = header_info["project name"]

    # --- Parse counts from report_index.md ## Summary section ---------------
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    summary_body = _extract_h2_section(idx_text, "Summary")
    for sev_label in counts:
        m = re.search(
            rf"\*{{0,2}}{sev_label}\*{{0,2}}\s*[:\|]\s*(\d+)",
            summary_body, re.IGNORECASE,
        )
        if m:
            counts[sev_label] = int(m.group(1))
    total_count = sum(counts.values())

    # --- Parse Master Finding Index rows for Priority Remediation Order ---
    # Tolerant to either `| C-01 | Title | Severity | ...` (canonical table)
    # or `- C-01: Title (severity)` (bullet form, fallback).
    finding_rows: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    index_scope = _extract_h2_section(idx_text, "Master Finding Index")
    if not index_scope:
        # Fallback for older/freeform index files: never let excluded rows feed
        # client-facing remediation order.
        index_scope = re.split(
            r"(?im)^##\s+Excluded Findings\b", idx_text, maxsplit=1
        )[0]
    for m in re.finditer(
        r"^\|\s*\[?\*?\*?([CHMLI]-\d+)\*?\*?\]?\s*\|\s*([^|]+?)\s*\|",
        index_scope, re.MULTILINE,
    ):
        rid = m.group(1)
        if rid in seen_ids:
            continue
        seen_ids.add(rid)
        finding_rows.append({"id": rid, "title": _sanitize_client_title(m.group(2).strip())})
    # Severity-prefix sort (C, H, M, L, I) for the priority order.
    sev_priority = {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}
    finding_rows.sort(
        key=lambda r: (
            sev_priority.get(r["id"][0], 9),
            int(re.findall(r"\d+", r["id"])[0]) if re.findall(r"\d+", r["id"]) else 0,
        )
    )
    # Canonical report-ID -> title map used to repair generic/broken tier
    # headings during section finalization. Built from ALL index rows BEFORE the
    # ghost-reference filter below, so a tier heading can still be repaired from
    # its canonical title even if the remediation order will not cite it.
    id_to_title = {r["id"]: r["title"] for r in finding_rows}

    # Canonical report-ID -> LOCATION map from the Master Finding Index, used to
    # recover tier-writer location corruption (a real finding whose body
    # `**Location**` was overwritten with a non-existent path). Column-drift
    # tolerant: pick the first index cell that looks like a source location.
    id_to_location: dict[str, str] = {}
    for _line in index_scope.splitlines():
        if not _line.strip().startswith("|"):
            continue
        _cells = [c.strip() for c in _line.strip().strip("|").split("|")]
        if not _cells:
            continue
        _idm = re.match(r"\[?\*?\*?([CHMLI]-\d+)\*?\*?\]?$", _cells[0])
        if not _idm:
            continue
        for _c in _cells[1:]:
            if re.search(r"\.(?:sol|rs|go|move|vy|cairo)\b|:L\d", _c):
                id_to_location[_idm.group(1)] = _c
                break

    # --- Ghost-reference guard (assembler bug fix) ---------------------------
    # The Master Finding Index can list a report ID (e.g. M-18) that has NO
    # corresponding `### [X-NN]` finding section in any tier file — a stale
    # internal/index ID that never produced a body section. Citing it in the
    # Priority Remediation Order or Executive Summary creates a dangling
    # reference the reader cannot resolve. Derive the set of report IDs that
    # ACTUALLY have a finding section from the tier texts, and restrict
    # finding_rows to those. IDs with a real section but absent from the index
    # are also recovered so they are not silently dropped from remediation.
    defined_section_ids = _defined_report_section_ids(
        crit_high_text, medium_text, low_info_text
    )
    if defined_section_ids:
        kept_rows = [r for r in finding_rows if r["id"] in defined_section_ids]
        dropped = [r["id"] for r in finding_rows if r["id"] not in defined_section_ids]
        if dropped:
            log.warning(
                "[report_assemble] dropped %d dangling remediation ID(s) with "
                "no finding section: %s",
                len(dropped), ", ".join(sorted(dropped)),
            )
        present_ids = {r["id"] for r in kept_rows}
        for rid in sorted(
            defined_section_ids - present_ids,
            key=lambda x: (
                {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}.get(x[0], 9),
                int(re.findall(r"\d+", x)[0]) if re.findall(r"\d+", x) else 0,
            ),
        ):
            kept_rows.append({"id": rid, "title": id_to_title.get(rid, "Finding")})
            log.warning(
                "[report_assemble] recovered remediation ID %s present as a "
                "finding section but missing from Master Finding Index", rid,
            )
        kept_rows.sort(
            key=lambda r: (
                {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}.get(r["id"][0], 9),
                int(re.findall(r"\d+", r["id"])[0]) if re.findall(r"\d+", r["id"]) else 0,
            )
        )
        finding_rows = kept_rows

    # --- Generate Executive Summary mechanically -----------------------------
    top_crits = [r for r in finding_rows if r["id"].startswith("C-")][:5]
    if top_crits:
        crit_bullets = "\n".join(
            f"- **{r['id']}** — {r['title']}" for r in top_crits
        )
    else:
        crit_bullets = "_No Critical findings._"

    exec_summary = (
        f"This security audit examined `{project_name}`. The audit "
        f"identified **{total_count} findings**: "
        f"{counts['Critical']} Critical, {counts['High']} High, "
        f"{counts['Medium']} Medium, {counts['Low']} Low, "
        f"{counts['Informational']} Informational.\n\n"
        f"The most severe issues:\n\n{crit_bullets}\n\n"
        f"Findings should be addressed in the **Priority Remediation Order** "
        f"at the end of this report. Critical and High findings warrant "
        f"immediate attention before any further deployment activity."
    )

    # --- Generate Priority Remediation Order ---------------------------------
    sev_urgency = {
        "C": "Immediate", "H": "Before launch",
        "M": "Before launch", "L": "Recommended", "I": "Recommended",
    }
    if finding_rows:
        remediation = "\n".join(
            f"{i}. **{r['id']}** — {r['title']} *({sev_urgency.get(r['id'][0], 'Recommended')})*"
            for i, r in enumerate(finding_rows, 1)
        )
    else:
        remediation = "_No findings to remediate._"

    # --- Summary table -------------------------------------------------------
    summary_table = (
        "| Severity | Count |\n"
        "|----------|-------|\n"
        + "\n".join(f"| {sev} | {n} |" for sev, n in counts.items())
        + f"\n| **Total** | **{total_count}** |"
    )

    # --- Optional sections from report_index.md ------------------------------
    components_block = (
        _extract_h2_section(idx_text, "Components Audited")
        or _synthesize_components_audited(scratchpad)
    )
    appendix_block = _build_client_excluded_appendix_from_records(scratchpad)
    internal_traceability = _build_internal_traceability_from_records(scratchpad)
    if internal_traceability:
        try:
            (scratchpad / "report_traceability_internal.md").write_text(
                internal_traceability + "\n", encoding="utf-8"
            )
        except Exception as exc:
            log.warning(f"[report_assemble] internal traceability write failed: {exc}")

    # --- Split tier files into per-severity sections -------------------------
    def _sections_by_prefix(text: str, prefixes: set[str]) -> str:
        # Ship D (SW14-2/3/4): accept H2 AND H3 report-ID headings, and inner
        # whitespace `[ C-01 ]`. The old `###`-only / no-whitespace form dropped
        # a `## [C-01]` (or `### [ C-01 ]`) finding from assembly while the
        # count gate still counted it -> finding silently vanished.
        headers = list(re.finditer(
            r"(?im)^(?:#{2,3}\s*(?:[^\n]*\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI])-\d+\s*\][^\n]*|##\s+\S[^\n]*)",
            text or "",
        ))
        parts: list[str] = []
        for i, hm in enumerate(headers):
            end = headers[i + 1].start() if i + 1 < len(headers) else len(text or "")
            if hm.group(1) and hm.group(1).upper() in prefixes:
                parts.append((text or "")[hm.start():end].strip())
        return "\n\n".join(parts).strip()

    crit_section = _sections_by_prefix(crit_high_text, {"C"})
    high_section = _sections_by_prefix(crit_high_text, {"H"})
    low_section = _sections_by_prefix(low_info_text, {"L"})
    info_section = _sections_by_prefix(low_info_text, {"I"})
    # Medium tier file may have multiple H1/H2 headers because
    # `merge_report_medium_shards` naively concatenates shard files
    # (each with its own `# Medium Findings` H1, and shard B sometimes
    # has its own `## Medium Findings` H2). Strip ALL of these so we
    # own the section structure exactly once.
    medium_clean = re.sub(
        r"^#\s+(?:Medium\s+Findings|Medium)[^\n]*\n+", "",
        medium_text.strip(), flags=re.MULTILINE,
    )
    medium_clean = re.sub(
        r"^##\s+Medium\s+Findings[^\n]*\n+", "",
        medium_clean, flags=re.MULTILINE,
    ).strip()

    # Rewrite generic/broken finding headings from the canonical index title
    # and strip internal-status prose leaked into bodies.
    crit_section = _finalize_report_tier_section(crit_section, id_to_title)
    high_section = _finalize_report_tier_section(high_section, id_to_title)
    medium_clean = _finalize_report_tier_section(medium_clean, id_to_title)
    low_section = _finalize_report_tier_section(low_section, id_to_title)
    info_section = _finalize_report_tier_section(info_section, id_to_title)

    # Recover tier-writer LOCATION corruption against the validated index (a real
    # finding whose body location was overwritten with a non-existent path).
    crit_section, _n1 = _recover_tier_locations(crit_section, id_to_location, project_root)
    high_section, _n2 = _recover_tier_locations(high_section, id_to_location, project_root)
    medium_clean, _n3 = _recover_tier_locations(medium_clean, id_to_location, project_root)
    low_section, _n4 = _recover_tier_locations(low_section, id_to_location, project_root)
    info_section, _n5 = _recover_tier_locations(info_section, id_to_location, project_root)
    _loc_recovered = _n1 + _n2 + _n3 + _n4 + _n5
    if _loc_recovered:
        log.warning(
            "[report_assemble] recovered %d body location(s) corrupted by the tier "
            "writer — replaced with the validated report_index location",
            _loc_recovered,
        )

    # --- Assemble per ~/.claude/rules/report-template.md ---------------------
    auditor = header_info.get("auditor", "Automated Security Analysis (Plamen V2)")
    scope = header_info.get("scope", project_root)
    header_fields = [
        f"**Date**: {header_info.get('date', today)}",
        f"**Auditor**: {auditor}",
        f"**Scope**: {scope}",
    ]
    for extra_key, label in (
        ("language/version", "Language/Version"),
        ("language", "Language"),
        ("build status", "Build Status"),
        ("static analysis status", "Static Analysis Status"),
    ):
        if extra_key in header_info:
            header_fields.append(f"**{label}**: {header_info[extra_key]}")

    parts: list[str] = [
        f"# Security Audit Report — {project_name}",
        "",
        *header_fields,
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        exec_summary,
        "",
        "## Summary",
        "",
        summary_table,
    ]
    if components_block:
        parts.extend(["", "### Components Audited", "", components_block])
    parts.extend(["", "---", ""])
    if crit_section:
        parts.extend(["## Critical Findings", "", crit_section, ""])
    if high_section:
        parts.extend(["## High Findings", "", high_section, ""])
    if crit_section or high_section:
        parts.extend(["---", ""])
    if medium_clean:
        # Medium tier file already has its own `## Medium Findings` heading
        # in most cases; only add one if it's missing.
        if not re.match(r"^##\s+Medium\s+Findings", medium_clean):
            parts.append("## Medium Findings")
            parts.append("")
        parts.extend([medium_clean, "", "---", ""])
    quality_section = _extract_h2_section(low_info_text, "Quality Observations")
    if low_section:
        parts.extend(["## Low Findings", "", low_section, ""])
    if info_section:
        parts.extend(["## Informational Findings", "", info_section, ""])
    if quality_section:
        parts.extend(["## Quality Observations", "", quality_section, ""])
    if low_section or info_section or quality_section:
        parts.extend(["---", ""])
    parts.extend(["## Priority Remediation Order", "", remediation, ""])
    if appendix_block:
        parts.extend(["", "---", "", "## Appendix A: Excluded Findings", ""])
        parts.extend([appendix_block, ""])
    # Appendix B: items the late-stage gates DEFERRED with a flag instead of
    # halting (obligation/retention, severity-provenance). They are written to
    # report_semantic_*.md in the scratchpad, which is cleaned on success — so
    # without folding them here the "flagged for human review" promise never
    # reaches the human. Deliver them in the report so they survive cleanup.
    human_review = _build_human_review_appendix(scratchpad)
    if human_review:
        parts.extend([
            "", "---", "", "## Appendix B: Flagged for Human Review", "",
            "_The pipeline deferred the items below with a flag rather than "
            "halting the audit. They are retained here for reviewer attention "
            "and were not silently dropped._", "",
            human_review, "",
        ])

    body = "\n".join(parts)
    body = _tag_report_index_unresolved_sections(body, idx_text, scratchpad)
    # Do not synthesize client-facing body sections during assembly. Missing
    # assigned sections, promotion dropouts, or low-evidence verifier outputs
    # are quality failures that must be fixed upstream by the index/body-writer
    # phases. Auto-writing body prose here hides omissions and creates bloated
    # reports on small scopes.
    body = _sanitize_client_body(body)
    body = _sanitize_undefined_report_references(body)

    # --- Mechanical sanitization (canonical-by-construction) -----------------
    # Strip control characters per `~/.claude/rules/phase6-report-prompts.md`
    # quality-gate spec: form-feed, ANSI escapes, null bytes, etc.
    body = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", body)
    # Strip ANSI escape sequences if any leaked through.
    body = re.sub(r"\x1b\[[0-9;]*[mGKH]", "", body)
    # Internal report-blocked markers are useful for tier/body gates, but must
    # never leak into the client-facing report. Keep UNVERIFIED/CONTESTED prose.
    body = re.sub(r"\s*\[REPORT-BLOCKED[^\]]*\]\s*", " ", body, flags=re.IGNORECASE)
    body = re.sub(r"[ \t]{2,}", " ", body)

    # --- Material-harm body floor: DELIBERATELY NOT APPLIED HERE -------------
    # The floor must run AFTER the LLM `report_disposition` phase produces its
    # (richer, recall-safe) disposition.md, executed by the Python `report_floor`
    # phase. Previously this assembler called write_disposition_md() (the keyword
    # classifier) + enforce_material_harm_floor() inline, which:
    #   (1) pre-created disposition.md with the WEAK keyword classification
    #       BEFORE the LLM phase ran, and
    #   (2) physically relocated body sections at assemble time.
    # Consequence: the LLM report_disposition phase's gate artifact already
    # existed (>=100 bytes) so its gate passed even when the LLM produced
    # nothing, the keyword floor's relocations were already applied, and the
    # later report_floor pass was an idempotent no-op — so the keyword classifier
    # won EVERY run and the LLM disposition was structurally dead. We now leave
    # the assembled body un-floored; report_disposition (LLM) writes the
    # disposition, then report_floor (Python) applies it. Recall-safe + haltless
    # is preserved by report_floor's keyword fallback when the LLM phase is
    # absent/empty.

    # Reconcile the Executive Summary prose count to the `## Summary` table
    # (idempotent no-op here since both derive from the same counts, but keeps
    # the two in sync if any body pass above ever perturbs the table).
    body = _reconcile_exec_summary_count(body)

    # --- Write outputs -------------------------------------------------------
    try:
        audit_report_path.write_text(body, encoding="utf-8")
    except Exception as e:
        log.error(f"[report_assemble] AUDIT_REPORT.md write failed: {e}")
        return False

    finding_section_count = len(
        re.findall(r"^###\s*\[[CHMLI]-\d+\]", body, re.MULTILINE)
    )
    # Count megasection rows (Quality Observations table)
    appendix_start = body.find("## Appendix")
    quality_body = body[:appendix_start] if appendix_start >= 0 else body
    quality_row_count = len(
        re.findall(r"^\|\s*[CHMLI]-\d+\s*\|", quality_body, re.MULTILINE)
    )
    total_findings_in_report = finding_section_count + quality_row_count
    quality = [
        "# Report Quality Check (Python-assembled, v2.4.2)",
        "",
        f"- Source: tier files concatenated mechanically; no LLM round-trip.",
        f"- Body bytes: {len(body):,}",
        f"- Finding sections (### [X-NN]): {finding_section_count}",
        f"- Quality observation rows: {quality_row_count}",
        f"- Total findings in report: {total_findings_in_report}",
        f"- Summary total: {total_count}",
        f"- Section presence: "
        f"crit={'YES' if crit_section else 'NO'} | "
        f"high={'YES' if high_section else 'NO'} | "
        f"medium={'YES' if medium_clean else 'NO'} | "
        f"low={'YES' if low_section else 'NO'} | "
        f"info={'YES' if info_section else 'NO'} | "
        f"quality_obs={'YES' if quality_section else 'NO'}",
        f"- Components Audited block: {'YES' if components_block else 'NO'}",
        f"- Appendix A traceability: {'YES' if appendix_block else 'NO'}",
        f"- Excluded Findings: {'YES' if '### Excluded Findings' in appendix_block else 'NO'}",
    ]
    try:
        (scratchpad / "report_quality.md").write_text(
            "\n".join(quality) + "\n", encoding="utf-8"
        )
    except Exception:
        pass
    log.info(
        f"[report_assemble] python-assembled {audit_report_path.name} "
        f"({len(body):,} bytes, {finding_section_count} finding sections, "
        f"no LLM round-trip)"
    )
    return True


# ── report_dedup phase (cross-tier same-bug consolidation) ──────────────────
#
# report_index STEP-1.5 forbids merging hypotheses across severity tiers, so a
# single bug that surfaced at two severities (e.g. C-01 + H-12) is never a
# consolidation candidate before the report exists. This phase runs AFTER
# severities are final (post report_assemble) and looks for cross-tier
# duplicates in the assembled AUDIT_REPORT.md.
#
# SAFETY (invariant #1, non-negotiable): this phase NEVER loses report content.
# It ALWAYS snapshots the untouched original (AUDIT_REPORT.pre-dedup.md), writes
# the candidate deduped report to AUDIT_REPORT.deduped.md, and only promotes the
# deduped output to AUDIT_REPORT.md if a MECHANICAL DATA-LOSS GATE confirms every
# original Location string, Impact bullet, PoC test-id, and report-ID mapping
# still appears. On ANY detected loss it KEEPS the original as the delivered
# report and leaves the deduped file as a side artifact for human review.

_DEDUP_LOCATION_TOKEN_RE = re.compile(
    r"`?[\w./\\-]+\.\w+:L?\d+(?:-L?\d+)?`?", re.IGNORECASE
)
_DEDUP_POC_FN_RE = re.compile(r"\b(test[A-Za-z0-9_]+|test_[A-Za-z0-9_]+)\b")
_DEDUP_IMPACT_BULLET_RE = re.compile(r"(?m)^\s*[-*]\s+(.+\S)\s*$")
_DEDUP_TITLE_STOPWORDS = frozenset({
    "the", "a", "an", "in", "on", "of", "to", "and", "or", "is", "are", "for",
    "with", "via", "by", "when", "due", "can", "be", "not", "no", "missing",
})

# Fix-text similarity vocabulary. Recommendation/fix prose is stop-worded down
# to its content terms (verbs + nouns describing the CODE CHANGE), then the two
# survivors' fix term sets are Jaccard-compared. A high overlap means "the same
# code change fixes both" — the load-bearing same-fix signal that distinguishes
# a true cross-tier duplicate (a) from a related-but-distinct pair (b).
_DEDUP_FIX_STOPWORDS = frozenset({
    "the", "a", "an", "in", "on", "of", "to", "and", "or", "is", "are", "for",
    "with", "via", "by", "when", "due", "can", "be", "not", "no", "should",
    "must", "this", "that", "it", "as", "at", "if", "then", "use", "using",
    "add", "ensure", "consider", "recommend", "recommended", "fix", "apply",
    "function", "value", "values", "code", "call", "calls", "called", "before",
    "after", "which", "will", "would", "also", "from", "into", "all", "any",
})
# Code identifiers used as merge anchors: camelCase/snake_case names with >=4
# chars, plus dotted member paths. These tie a title like "Reward accounting in
# claim()" to the same function across two findings even when titles diverge.
_DEDUP_ANCHOR_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b")
# Antonym pairs that signal OPPOSITE fixes (e.g. inflow vs outflow accounting).
# When the two fix texts each contain a different member of the same pair, the
# same-fix gate is BLOCKED even at high lexical overlap — they touch the same
# topic but require divergent code changes (e.g. a missing-accumulator-update case).
_DEDUP_FIX_ANTONYMS = (
    frozenset({"inflow", "outflow"}),
    frozenset({"deposit", "withdraw"}),
    frozenset({"deposit", "withdrawal"}),
    frozenset({"increment", "decrement"}),
    frozenset({"increase", "decrease"}),
    frozenset({"mint", "burn"}),
    frozenset({"add", "subtract"}),
    frozenset({"credit", "debit"}),
    frozenset({"lock", "unlock"}),
    frozenset({"stake", "unstake"}),
    frozenset({"enter", "exit"}),
    frozenset({"buy", "sell"}),
    frozenset({"lower", "upper"}),
    frozenset({"min", "max"}),
    frozenset({"floor", "ceil"}),
    frozenset({"send", "receive"}),
)


def _dedup_fix_terms(text: str) -> set[str]:
    """Content-term set of a Recommendation/fix paragraph (for fix similarity)."""
    return {
        w for w in re.findall(r"[a-z0-9]+", (text or "").lower())
        if w not in _DEDUP_FIX_STOPWORDS and len(w) > 2
    }


def _dedup_fix_jaccard(a: str, b: str) -> float:
    ta, tb = _dedup_fix_terms(a), _dedup_fix_terms(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _dedup_fix_antonym_conflict(a: str, b: str) -> bool:
    """True iff the two fix texts pick OPPOSITE members of an antonym pair.

    A related-but-distinct pair (same variable, opposite direction → different
    fix) is blocked from merging even when its surrounding prose overlaps. We
    require each side to contain a DIFFERENT member of the same pair and NOT the
    other's member, so a fix that mentions both ('handle deposit and withdraw')
    is not falsely flagged.
    """
    ta = _dedup_fix_terms(a)
    tb = _dedup_fix_terms(b)
    for pair in _DEDUP_FIX_ANTONYMS:
        members = tuple(pair)
        x, y = members[0], members[1]
        a_has_x, a_has_y = x in ta, y in ta
        b_has_x, b_has_y = x in tb, y in tb
        # A leans to one member exclusively, B leans to the other exclusively.
        a_only_x = a_has_x and not a_has_y
        a_only_y = a_has_y and not a_has_x
        b_only_x = b_has_x and not b_has_y
        b_only_y = b_has_y and not b_has_x
        if (a_only_x and b_only_y) or (a_only_y and b_only_x):
            return True
    return False


def _dedup_report_sections(body: str) -> list[dict]:
    """Split an assembled report body into per-finding records.

    Each record carries: id, severity prefix, heading line, full section text,
    location-token set, impact-bullet set, and PoC test-fn set. Only
    `### [X-NN]` / `## [X-NN]` finding sections are records (not H2 tier
    headers like `## Critical Findings`).
    """
    headers = list(re.finditer(
        r"(?im)^(#{2,3})\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI]-\d+)\s*\][^\n]*$",
        body or "",
    ))
    records: list[dict] = []
    for i, hm in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body or "")
        # A severity/tier H2 belongs to document structure, not to the finding
        # immediately above it.  Including it in the survivor section causes
        # consolidation content to be appended *after* the next tier heading,
        # so the receipt says "absorbed into H-xx" while Markdown presents it
        # under Medium/Low.  Stop at the first intervening non-finding H2.
        next_h2 = re.search(r"(?m)^##\s+(?!\s*\[)", (body or "")[hm.end() : end])
        if next_h2:
            end = hm.end() + next_h2.start()
        section = (body or "")[hm.start():end]
        rid = _normalize_report_id(hm.group(2))
        locs = {m.group(0).strip("`") for m in _DEDUP_LOCATION_TOKEN_RE.finditer(section)}
        # Source files named in the **Location** field (with OR without :Lnn),
        # normalized to basename — the same-site signal for the title/root-cause
        # merge path. Scoped to the Location field (not the whole section) so a
        # contract merely referenced in passing in the Description does not
        # create a spurious same-file link.
        loc_field_m = re.search(
            r"(?is)\*\*Location\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", section
        )
        files = _dedup_location_files(loc_field_m.group(1) if loc_field_m else "")
        pocs = set(_DEDUP_POC_FN_RE.findall(section))
        impacts = set()
        impact_block = re.search(
            r"(?is)\*\*Impact\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", section
        )
        if impact_block:
            for bm in _DEDUP_IMPACT_BULLET_RE.finditer(impact_block.group(1)):
                impacts.add(bm.group(1).strip())
        title = hm.group(0)
        title = re.sub(r"(?i)^#{2,3}\s*\[\s*[CHMLI]-\d+\s*\]\s*", "", title)
        title = re.sub(r"(?i)\s*\[(?:VERIFIED|CONFIRMED|UNVERIFIED|CONTESTED|UNRESOLVED[^\]]*|VERIFICATION NOT EXECUTED)\]\s*$", "", title).strip()
        # Recommendation/fix prose: the load-bearing same-fix discriminator.
        fix_text = ""
        fix_block = re.search(
            r"(?is)\*\*Recommendation\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", section
        )
        if fix_block:
            fix_text = fix_block.group(1).strip()
        # Description prose (fallback context for the same-fix gate).
        desc_text = ""
        desc_block = re.search(
            r"(?is)\*\*Description\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", section
        )
        if desc_block:
            desc_text = desc_block.group(1).strip()
        # Anchor identifiers from the title (function/variable names tie two
        # findings to the same code site even when titles otherwise diverge).
        anchors = {
            m.group(1).lower()
            for m in _DEDUP_ANCHOR_RE.finditer(title)
            if m.group(1).lower() not in _DEDUP_TITLE_STOPWORDS
        }
        records.append({
            "id": rid,
            "prefix": rid[0],
            "heading": hm.group(0),
            "section": section,
            "title": title,
            "locations": locs,
            "files": files,
            "pocs": pocs,
            "impacts": impacts,
            "fix_text": fix_text,
            "desc_text": desc_text,
            "anchors": anchors,
        })
    return records


def _dedup_title_jaccard(a: str, b: str) -> float:
    def _toks(s: str) -> set[str]:
        return {
            w for w in re.findall(r"[a-z0-9]+", (s or "").lower())
            if w not in _DEDUP_TITLE_STOPWORDS and len(w) > 2
        }
    ta, tb = _toks(a), _toks(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


_DEDUP_AGGREGATE_SUPPRESS_THRESHOLD = 6
# Same-fix recall layer thresholds. A weak-signal cross-tier pair (shared
# location OR shared anchor, but no source-ID subset) is PROMOTED to a mergeable
# candidate only when the two Recommendation texts overlap at/above this Jaccard
# AND no antonym (opposite-direction) conflict is present. Tuned conservatively:
# precision (no false merge that HIDES a finding) dominates recall.
_DEDUP_SAME_FIX_JACCARD = 0.5
_DEDUP_SAME_FIX_MIN_TERMS = 3

# Same-ROOT-CAUSE recall layer (the load-bearing fix for the real-report inert
# bug). Two agents finding the SAME bug at the SAME code site write SUBSTANTIVE
# but DIFFERENTLY-WORDED Recommendations, so Recommendation-text Jaccard is the
# WRONG discriminator (it vetoes true dupes). The reliable "same bug" signal at
# a shared site is the TITLE / root-cause text.
#
# A same-site pair MERGES (antonym-gated) when BOTH hold:
#   1. it shares >= MIN_ANCHORS meaningful title identifiers (necessary — a
#      single shared anchor, e.g. just the function name in "access control in
#      pause()" vs "missing event in pause()", is two DIFFERENT bugs in one
#      function and must stay separate), AND
#   2. it carries a STRONG, fully-generic same-root-cause signal: a shared
#      FUNCTION / method identifier in both titles (two findings naming the same
#      function are almost always about the same bug).
#
# Why a function anchor and NOT a title-similarity threshold: real reports reuse
# domain vocabulary heavily ("virtual", "tokens", "market", "creation"), so two
# DIFFERENT bugs routinely share 2-3 generic topic anchors at the same site.
# Requiring a shared FUNCTION identifier separates the true duplicate halves
# (which name the same function) from those coincidental topic-word collisions.
# The shared identifier must be a FUNCTION/method (camelCase lowerFirst,
# underscore-bearing, or the method part of a dotted `Contract.method`) — NOT a
# bare PascalCase CONTRACT name, because one contract hosts many distinct bugs
# (two different findings naming the same contract is NOT a duplicate).
#
# NO-OVERFIT (Plamen Part-0): there is deliberately NO numeric title-Jaccard
# fallback. Any such cut-off would have to be calibrated to a particular report's
# pair overlaps (sit between that report's highest false-pair overlap and lowest
# true-pair overlap) — i.e. fit to one codebase's findings, not a general method.
# The function-anchor signal is a pure code-shape property with no tuned
# constant. Same-site pairs that share no function anchor stay UNMERGED here
# (recall-safe — never dropped); a lower-severity pure-quality / hardening twin
# is relocated to the appendix by the material-harm body floor, so the body still
# avoids duplicates without a fitted threshold.
_DEDUP_SAME_ROOTCAUSE_MIN_ANCHORS = 2
# Identifier tokens in a finding TITLE (>= 4 chars).
_DEDUP_CODE_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b")
# Dotted member access `Identifier.method` in a title — the `method` part is a
# function anchor even when it is plain-lowercase (e.g. `Hook.validate`).
_DEDUP_DOTTED_METHOD_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\.([A-Za-z_][A-Za-z0-9_]{2,})\b")
# Source files referenced by a finding (with OR without a :Lnn suffix, so a
# Location like "Foo.sol (constructor)" still yields a file). Matched against the
# Location field only, normalized to basename, so two findings at the same file
# are recognized even when their line ranges differ or one omits line numbers.
_DEDUP_FILE_MENTION_RE = re.compile(
    r"[\w./\\-]*\b\w+\.(?:sol|rs|move|go|vy|cairo|fc|tact|sw|huff)\b", re.I
)


def _dedup_location_files(field_text: str) -> set[str]:
    """Basenames of source files named in a finding's Location field.

    Tolerant of line-number-free mentions (``Foo.sol (constructor)``) so the
    same-file site signal survives a Location written without ``:Lnn``.
    """
    out: set[str] = set()
    for m in _DEDUP_FILE_MENTION_RE.finditer(field_text or ""):
        base = re.split(r"[\\/]", m.group(0))[-1].strip().lower()
        if base:
            out.add(base)
    return out


def _dedup_parse_loc_ranges(locs: set[str]) -> dict[str, list[tuple[int, int]]]:
    """Map basename -> list of (start,end) line ranges from location tokens.

    Tokens look like ``core/Foo.sol:120-145`` or ``Foo.sol:L88``. A single-line
    token yields ``(n, n)``. Unparseable tokens are skipped.
    """
    out: dict[str, list[tuple[int, int]]] = {}
    for loc in locs or set():
        m = re.search(r"([\w./\\-]+\.\w+):L?(\d+)(?:-L?(\d+))?", loc or "", re.I)
        if not m:
            continue
        base = re.split(r"[\\/]", m.group(1))[-1].strip().lower()
        start = int(m.group(2))
        end = int(m.group(3)) if m.group(3) else start
        if end < start:
            start, end = end, start
        out.setdefault(base, []).append((start, end))
    return out


def _dedup_locations_overlap(a_locs: set[str], b_locs: set[str]) -> bool:
    """True iff any A range and any B range cover the SAME file and intersect.

    Detects same-site duplicates whose line ranges OVERLAP but are not identical
    (e.g. ``Foo.sol:100-120`` vs ``Foo.sol:100-133``) — the common shape when two
    agents bound the same defect slightly differently.
    """
    ar = _dedup_parse_loc_ranges(a_locs)
    br = _dedup_parse_loc_ranges(b_locs)
    for base, a_ranges in ar.items():
        for b_start, b_end in br.get(base, []):
            for a_start, a_end in a_ranges:
                if a_start <= b_end and b_start <= a_end:
                    return True
    return False


def _dedup_same_site(a: dict, b: dict) -> bool:
    """True when two finding records point at the SAME code site.

    Same site = overlapping line ranges in a shared file, OR a shared source
    file named in either Location field. This is the precondition for the
    title/root-cause MERGE path so a cross-file pair that merely shares title
    words is NOT merged (which could HIDE a distinct finding).
    """
    if _dedup_locations_overlap(a.get("locations", set()), b.get("locations", set())):
        return True
    a_files = a.get("files") or set()
    b_files = b.get("files") or set()
    if a_files & b_files:
        return True
    # Fall back to the location-token file parts (covers records built without a
    # precomputed `files` set).
    a_fp = {f for f in (_dedup_file_part(l) for l in a.get("locations", set())) if f}
    b_fp = {f for f in (_dedup_file_part(l) for l in b.get("locations", set())) if f}
    a_base = {re.split(r"[\\/]", f)[-1] for f in a_fp}
    b_base = {re.split(r"[\\/]", f)[-1] for f in b_fp}
    return bool(a_base & b_base)


def _dedup_function_anchors(title: str) -> set[str]:
    """FUNCTION / method identifiers named in a title.

    A function anchor is a lowerFirst-camelCase or underscore-bearing identifier
    (e.g. ``collectProtocolFees``, ``_getAmountIn``) OR the ``method`` part of a
    dotted ``Contract.method`` access (e.g. ``validate`` in ``Hook.validate``).
    A bare PascalCase CONTRACT/type name (e.g. ``ReclaimValidationHook``) is
    DELIBERATELY excluded: one contract hosts many distinct bugs, so two findings
    that merely both name the same contract are NOT a duplicate. Two findings
    naming the same FUNCTION almost always describe the same defect.
    """
    out: set[str] = set()
    for m in _DEDUP_CODE_IDENT_RE.finditer(title or ""):
        w = m.group(1)
        first_ok = w[0].islower() or w[0] == "_"   # NOT PascalCase
        shaped = bool(re.search(r"[a-z][A-Z]", w)) or "_" in w  # camelCase/snake
        if first_ok and shaped:
            out.add(w.lower())
    for m in _DEDUP_DOTTED_METHOD_RE.finditer(title or ""):
        out.add(m.group(1).lower())
    return out


def _dedup_same_root_cause_ok(a: dict, b: dict) -> tuple[bool, str]:
    """Title/root-cause same-bug signal for SAME-SITE pairs (antonym-gated upstream).

    Returns (ok, reason). True ONLY when the two findings sit at the same site
    AND their titles indicate the SAME root cause under BOTH:
      1. >= MIN_ANCHORS shared meaningful title anchors (necessary — one shared
         anchor is just a co-located function name, i.e. a different bug), AND
      2. a STRONG, fully-generic signal: a shared FUNCTION / method identifier
         in both titles (two findings naming the same function are almost always
         the same defect). PascalCase contract/type names are excluded — one
         contract hosts many distinct bugs.

    The shared-function signal is a code-shape property, not a constant tuned to
    any one codebase. There is no numeric title-similarity threshold: a tuned
    title-Jaccard cut-off would be fit to a specific report's pair overlaps
    (Plamen Part-0 no-overfit). Same-site pairs that share NO function anchor are
    left UNMERGED here; they are kept separate (recall-safe — never dropped), and
    a lower-severity pure-quality / hardening twin is relocated to the appendix by
    the material-harm body floor, so the body still avoids duplicates without a
    fitted constant.
    """
    if not _dedup_same_site(a, b):
        return (False, "not-same-site")
    shared_anchors = a.get("anchors", set()) & b.get("anchors", set())
    if len(shared_anchors) < _DEDUP_SAME_ROOTCAUSE_MIN_ANCHORS:
        return (False, f"weak-title (shared-anchors={len(shared_anchors)}<{_DEDUP_SAME_ROOTCAUSE_MIN_ANCHORS})")
    shared_fn = _dedup_function_anchors(a.get("title", "")) & _dedup_function_anchors(b.get("title", ""))
    if shared_fn:
        return (True, f"same-root-cause (shared function={sorted(shared_fn)})")
    return (False, f"weak-title (anchors={len(shared_anchors)}, no-shared-function)")


def _dedup_same_fix_ok(a: dict, b: dict) -> tuple[bool, str]:
    """Precision gate: do these two findings describe the SAME bug / same fix?

    Returns (ok, reason). True when a same-site pair carries a same-root-cause
    title signal OR a strongly-overlapping Recommendation, and carries NO
    antonym (opposite-direction) conflict. A false positive here HIDES a finding
    (worse than a duplicate), so the gate defaults to NOT-OK on ambiguity.

    Ordering of acceptance paths (all under the hoisted antonym veto):
      1. **Same-root-cause via TITLE** (`_dedup_same_root_cause_ok`) — the
         load-bearing path for genuine duplicate halves found by two DIFFERENT
         agents. Such halves write SUBSTANTIVE but DIFFERENTLY-WORDED
         Recommendations, so Recommendation Jaccard < floor vetoes them; the
         reliable signal is a shared FUNCTION identifier at a shared code site.
         Requires same-site + >= MIN_ANCHORS shared title anchors + a shared
         function/method name in both titles (a generic code-shape signal, no
         tuned constant); a single shared anchor (just a function name) is NOT
         enough, so two different bugs in one function stay separate.
      2. **Identical-location + thin Recommendation** (legacy) — exact location
         token overlap with a too-thin fix text to discriminate.
      3. **Recommendation-text Jaccard** (legacy) — both fixes substantive and
         lexically overlapping at/above the same-fix Jaccard.
    """
    fa, fb = a.get("fix_text", ""), b.get("fix_text", "")
    # Hoisted antonym (opposite-direction) veto — applies to EVERY acceptance
    # path. Falls back to Description prose when a fix text is absent so a
    # same-site opposite-direction pair (e.g. increment-inflow vs
    # decrement-outflow) is rejected before any same-bug path can fire.
    ax = fa or a.get("desc_text", "")
    bx = fb or b.get("desc_text", "")
    if _dedup_fix_antonym_conflict(ax, bx):
        return (False, "antonym-conflict (opposite-direction fix)")

    # Path 1: same-root-cause via title at a shared code site. This is the fix
    # for the real-report inert bug — true duplicate halves carry substantive
    # but divergent Recommendation text, so the Recommendation-Jaccard gate below
    # would (wrongly) veto them. Reading the root cause from the title + shared
    # anchors recovers the merge while keeping different-bug pairs separate.
    rc_ok, rc_reason = _dedup_same_root_cause_ok(a, b)
    if rc_ok:
        return (True, rc_reason)

    # Path 2 (legacy): exact-location overlap with a thin/absent Recommendation,
    # where the location overlap is itself the authoritative same-root-cause
    # signal. (Substantive recs do NOT short-circuit here — they fall to Path 3.)
    if a.get("locations") and b.get("locations") and (a["locations"] & b["locations"]):
        ta0, tb0 = _dedup_fix_terms(fa), _dedup_fix_terms(fb)
        thin = (len(ta0) < _DEDUP_SAME_FIX_MIN_TERMS
                or len(tb0) < _DEDUP_SAME_FIX_MIN_TERMS)
        if thin:
            return (True, "same-fix (identical-location cross-tier)")

    # Path 3 (legacy): Recommendation-text Jaccard.
    if not fa or not fb:
        return (False, "no-recommendation-text")
    ta, tb = _dedup_fix_terms(fa), _dedup_fix_terms(fb)
    if len(ta) < _DEDUP_SAME_FIX_MIN_TERMS or len(tb) < _DEDUP_SAME_FIX_MIN_TERMS:
        return (False, "fix-text-too-thin")
    jac = _dedup_fix_jaccard(fa, fb)
    if jac < _DEDUP_SAME_FIX_JACCARD:
        return (False, f"fix-jaccard={jac:.2f}<{_DEDUP_SAME_FIX_JACCARD}")
    return (True, f"same-fix (fix-jaccard={jac:.2f})")


# ── Fix 4: transitive-closure clustering (post pairwise dedup) ──────────────
# Pairwise semantic dedup is LOCAL: it merges duplicate PAIRS but leaves N
# co-referent survivors (e.g. three "public withdraw" halves each merged with a
# different twin) as separate report findings — the ~2.5-3:1 fragmentation
# source. This step builds an undirected graph over the SURVIVING findings where
# an edge = (same file+function AND same root-cause/fix-pattern AND same tier),
# then collapses each connected component to ONE finding (highest severity,
# union of member locations as a location table). The edge predicate is the
# EXISTING pairwise consolidation test `_dedup_same_fix_ok` (same-site + shared
# function root cause + antonym veto) gated by same-tier equality — so it NEVER
# merges across tiers (no severity blur) and NEVER across mechanisms. The key is
# structural (file+function+fix-pattern); no protocol content leaks in.

def _cluster_severity_tier(rec: dict) -> str:
    """Normalized severity tier for a clustering record (default Medium)."""
    return normalize_severity(rec.get("severity", "") or "Medium")


def _cluster_primary_location(rec: dict) -> str:
    """Best single location string for a member row in the location table."""
    loc = (rec.get("location") or "").strip()
    if loc:
        return loc
    locs = rec.get("locations") or set()
    return sorted(locs)[0] if locs else ""


def _cluster_union_locations(members: list[dict]) -> list[str]:
    """Ordered, de-duplicated union of member primary locations."""
    out: list[str] = []
    seen: set[str] = set()
    for r in members:
        loc = _cluster_primary_location(r)
        key = _norm_loc(loc).lower()
        if loc and key not in seen:
            seen.add(key)
            out.append(loc)
    return out


def _cluster_location_table(members: list[dict]) -> str:
    """Render the consolidated Location table (one row per cluster member).

    Mirrors the report-template Root-Cause-Consolidation location table so the
    report writer can paste it verbatim into the single consolidated finding.
    """
    lines = [
        "| Internal ID | Location | Severity |",
        "|-------------|----------|----------|",
    ]
    for r in members:
        lines.append(
            f"| {r.get('id', '')} | {_cluster_primary_location(r) or '(unspecified)'} "
            f"| {_cluster_severity_tier(r)} |"
        )
    return "\n".join(lines)


# Fix 4: max members in a merged report cluster. Mirrors report-template's
# 'max 6 locations per finding' consolidation rule; larger cliques are left
# unmerged (a giant cluster is more likely over-broad than one real bug).
_MAX_CLUSTER_MEMBERS = 6

# Fix 4 hardening: opposite-direction cues checked over TITLE+DESC for clustering
# edges only (a distinct-bug pair in one function can share fix wording). Generic
# input-handling antonyms — no protocol content. Kept separate from the global
# _DEDUP_FIX_ANTONYMS so pairwise dedup behavior is unchanged.
_CLUSTER_EXTRA_ANTONYMS = (
    ("accept", "revert"),
    ("accept", "reject"),
    ("underflow", "overflow"),
    ("too small", "too large"),
    ("below", "above"),
)


def _detect_dedup_report_clusters(records: list[dict]) -> list[dict]:
    """Transitive-closure clustering over surviving findings (Fix 4).

    Runs AFTER pairwise semantic dedup. Builds an undirected graph over the
    surviving finding records where an edge exists iff two findings share the
    SAME code site (file + function), the SAME root-cause / fix-pattern, AND the
    SAME severity tier. Each connected component of size >= 2 collapses to ONE
    finding whose severity is the shared tier and whose Location is the UNION of
    member locations rendered as a location table.

    Edge predicate = the EXISTING pairwise consolidation test
    ``_dedup_same_fix_ok`` (same-site + shared-function root cause + antonym /
    opposite-direction veto) gated by same-tier equality. Recall-safe: NEVER
    merges across tiers (no severity blur) and NEVER across mechanisms.

    ``records`` is a list of finding dicts carrying at minimum ``id``, ``title``,
    ``severity`` (or a normalizable tier), and the same-fix schema fields
    ``locations`` / ``files`` / ``anchors`` / ``fix_text`` / ``desc_text`` that
    ``_dedup_report_sections`` (report body) and the inventory adapter produce.
    Returns cluster dicts, largest first:
    ``{survivor, members(sorted), severity, locations, location_table}``.
    """
    n = len(records)
    if n < 2:
        return []
    parent = list(range(n))

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(x: int, y: int) -> None:
        rx, ry = _find(x), _find(y)
        if rx != ry:
            parent[max(rx, ry)] = min(rx, ry)

    # Chain-proofing (Fix 4 hardening): clustering has NO LLM confirmation of
    # each merge (unlike pairwise dedup), and transitive closure over a
    # location-tolerant predicate CHAINS unrelated bugs (A-B share a site, B-C
    # share a site, ... => A..Z collapse even though A and Z are distinct). Two
    # guards, both recall-safe (a false merge HIDES a finding, worse than a dup):
    #   (1) EDGES use the STRICT same-root-cause signal only
    #       (`_dedup_same_root_cause_ok`: same-site + shared FUNCTION + >=
    #       MIN_ANCHORS shared title anchors + antonym veto) — NOT the looser
    #       `_dedup_same_fix_ok` location/Jaccard legacy paths that chain.
    #   (2) A component merges ONLY if it is a CLIQUE (every pair matches), not
    #       merely connected — this kills transitive chaining outright — and is
    #       capped at _MAX_CLUSTER_MEMBERS (report-template's max-locations rule).
    #       Non-clique / oversized components fall back to singletons (no merge).
    tiers = [_cluster_severity_tier(r) for r in records]

    def _strict_edge(i: int, j: int) -> bool:
        if tiers[i] != tiers[j]:
            return False  # NEVER cross-tier (no severity blur)
        ok, reason = _dedup_same_fix_ok(records[i], records[j])
        if not ok:
            return False
        # Exclude the ONE chaining path: "identical-location + thin fix" links
        # ANY two findings sharing a location token regardless of bug, so under
        # transitive closure it collapses every finding in a busy file into one
        # component. Keep the discriminating signals — same-root-cause via title
        # (path 1) and substantive identical-fix Jaccard (path 3, the genuine
        # H-05==H-09 duplicate-halves case) — drop only the location-alone path.
        if "identical-location" in reason:
            return False
        a, b = records[i], records[j]
        # SAME-FUNCTION guard: a clustering edge requires a shared code-identifier
        # anchor in BOTH findings. Blocks fix-Jaccard (path 3) from merging
        # DIFFERENT functions that happen to share fix wording (e.g. `deposit`
        # reconciliation vs `redeem` reconciliation). Genuine duplicate halves
        # (same function, differently-worded titles) still share the function
        # anchor, so the H-05==H-09 case is preserved.
        if not (a.get("anchors") and b.get("anchors")
                and (a["anchors"] & b["anchors"])):
            return False
        # OPPOSITE-DIRECTION guard over TITLE+DESC (not just fix): two distinct
        # bugs in the SAME function can carry near-identical fixes ("validate
        # to_ray input") while being opposite-direction (`accepts negative` vs
        # `reverts on overflow`). The fix-only antonym veto misses this because
        # the opposition lives in the title/description. Scoped to clustering
        # (stricter than pairwise dedup by design); does not touch global dedup.
        at = (a.get("title", "") + " " + a.get("desc_text", "")).lower()
        bt = (b.get("title", "") + " " + b.get("desc_text", "")).lower()
        if _dedup_fix_antonym_conflict(at, bt):
            return False
        for x, y in _CLUSTER_EXTRA_ANTONYMS:
            ax_, ay_ = x in at, y in at
            bx_, by_ = x in bt, y in bt
            if (ax_ and not ay_ and by_ and not bx_) or \
               (ay_ and not ax_ and bx_ and not by_):
                return False
        return True

    edge: dict = {}
    for i in range(n):
        for j in range(i + 1, n):
            if _strict_edge(i, j):
                edge[(i, j)] = True
                _union(i, j)

    comps: dict[int, list[int]] = {}
    for i in range(n):
        comps.setdefault(_find(i), []).append(i)

    clusters: list[dict] = []
    for _root, idxs in comps.items():
        if len(idxs) < 2:
            continue
        # CLIQUE guard: every pair in the component must carry a strict edge.
        # A connected-but-not-complete component is an ambiguous chain -> do NOT
        # merge it (leave members as separate findings). Oversized cliques
        # (> _MAX_CLUSTER_MEMBERS) are also not merged (likely over-broad).
        if len(idxs) > _MAX_CLUSTER_MEMBERS:
            continue
        is_clique = all(
            edge.get((min(a, b), max(a, b)), False)
            for k, a in enumerate(idxs) for b in idxs[k + 1:]
        )
        if not is_clique:
            continue
        members = [records[i] for i in idxs]
        # Survivor = highest severity, then lowest ID number (deterministic).
        # Within a cluster the tier is invariant, so this reduces to lowest ID.
        members_sorted = sorted(
            members,
            key=lambda r: (
                _SEVERITY_ORDER.index(_cluster_severity_tier(r)),
                _dedup_id_num(r.get("id", "")),
            ),
        )
        survivor = members_sorted[0]
        member_ids = sorted(
            (r.get("id", "") for r in members), key=_dedup_id_num
        )
        clusters.append({
            "survivor": survivor.get("id", ""),
            "members": member_ids,
            "severity": _cluster_severity_tier(survivor),
            "locations": _cluster_union_locations(members_sorted),
            "location_table": _cluster_location_table(members_sorted),
        })
    clusters.sort(key=lambda c: (-len(c["members"]), _dedup_id_num(c["survivor"])))
    return clusters


def _inventory_records_for_clustering(text: str) -> list[dict]:
    """Adapt findings_inventory.md blocks into clustering records.

    Reuses ``_dedup_parse_finding_info`` for id/title/location/severity/block,
    and enriches each SC block with the ``locations`` / ``files`` / ``anchors`` /
    ``fix_text`` / ``desc_text`` fields the ``_dedup_same_fix_ok`` consolidation
    predicate reads (same schema as ``_dedup_report_sections``).
    """
    base = _dedup_parse_finding_info(text)
    records: list[dict] = []
    for fid, info in base.items():
        if info.get("kind") != "sc":
            continue
        block = info.get("block", "")
        title = info.get("title", "")
        loc = info.get("location", "")
        locations = {
            m.group(0).strip("`") for m in _DEDUP_LOCATION_TOKEN_RE.finditer(loc)
        }
        if not locations and loc:
            locations = {loc}
        files = {info["file"]} if info.get("file") else set()
        anchors = {
            m.group(1).lower()
            for m in _DEDUP_ANCHOR_RE.finditer(title)
            if m.group(1).lower() not in _DEDUP_TITLE_STOPWORDS
        }
        fix_text = ""
        fix_block = re.search(
            r"(?is)\*\*Recommendation\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", block
        )
        if fix_block:
            fix_text = fix_block.group(1).strip()
        desc_text = ""
        desc_block = re.search(
            r"(?is)\*\*Description\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", block
        )
        if desc_block:
            desc_text = desc_block.group(1).strip()
        records.append({
            "id": fid,
            "title": title,
            "severity": info.get("severity", "Medium"),
            "location": loc,
            "locations": locations,
            "files": files,
            "anchors": anchors,
            "fix_text": fix_text,
            "desc_text": desc_text,
        })
    return records


def build_dedup_cluster_map(scratchpad: Path) -> int:
    """Fix 4: write the transitive-closure cluster map for report-index STEP-1.5.

    Reads the (post-pairwise-dedup) ``findings_inventory.md``, clusters
    co-referent survivors, and writes ``dedup_cluster_map.md`` — a consolidation
    HINT the report-index STEP-1.5 reads so the writer emits ONE finding with a
    location table per cluster (report-template Root-Cause-Consolidation rule).
    Purely additive: writes only the hint artifact; the inventory is NOT
    collapsed here (recall-safe — coverage accounting stays with the pairwise /
    LLM merge path). Returns the number of clusters (>= 2 members).
    """
    inv = scratchpad / "findings_inventory.md"
    if not inv.exists():
        return 0
    try:
        text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    records = _inventory_records_for_clustering(text)
    clusters = _detect_dedup_report_clusters(records)
    lines = [
        "# Dedup Cluster Map",
        "",
        "> Fix 4: transitive-closure clusters over post-pairwise-dedup findings.",
        "> Each cluster is ONE report finding — report-index STEP-1.5 consolidates",
        "> the members into a single finding with the location table below (per the",
        "> report-template Root-Cause-Consolidation rule). Recall-safe: same",
        "> file+function+fix-pattern AND same tier only; never cross-tier /",
        "> cross-mechanism. These are consolidation HINTS, not mandates.",
        "",
        f"**Clusters**: {len(clusters)}",
        "",
    ]
    if not clusters:
        lines.append("_No co-referent clusters detected._")
    for i, cl in enumerate(clusters, 1):
        lines.extend([
            f"## Cluster CL-{i}",
            "",
            f"CLUSTER: {', '.join(cl['members'])}",
            "",
            f"**Survivor**: {cl['survivor']}",
            f"**Severity**: {cl['severity']}",
            f"**Members**: {', '.join(cl['members'])}",
            "",
            "**Consolidated Location table**:",
            "",
            cl["location_table"],
            "",
        ])
    (scratchpad / "dedup_cluster_map.md").write_text(
        "\n".join(lines).rstrip("\n") + "\n", encoding="utf-8",
    )
    return len(clusters)


def _dedup_report_candidate_pairs(
    records: list[dict], src_by_id: dict[str, set[str]]
) -> list[dict]:
    """Detect same-root-cause candidate pairs (NEVER auto-merge — candidates only).

    Signals, ranked: (1) source-ID subset [primary], (2) shared location token,
    (3) shared PoC test-fn, (4) title Jaccard >= 0.5, (5) same-fix (shared
    location/anchor + same Recommendation). Aggregate-source-ID suppression: a
    finding with a large source-ID set is excluded from the subset signal
    (avoids class-D false merges).

    Candidate GENERATION spans BOTH same-tier and cross-tier pairs (F2): the LLM
    report_index STEP-1.5 only catches a subset of same-tier root-cause dupes,
    so report_dedup is the deterministic backstop within AND across tiers. Only
    candidate generation widens here — the merge DECISION downstream is gated by
    the unchanged `_dedup_same_fix_ok` and superset (`_resolve_dedup_survivor`)
    guards, so a false merge that HIDES a finding remains precluded.
    """
    pairs: list[dict] = []
    n = len(records)
    for i in range(n):
        for j in range(i + 1, n):
            a, b = records[i], records[j]
            a_src = src_by_id.get(a["id"], set())
            b_src = src_by_id.get(b["id"], set())
            signals: list[str] = []
            rank = 99
            agg = (len(a_src) > _DEDUP_AGGREGATE_SUPPRESS_THRESHOLD
                   or len(b_src) > _DEDUP_AGGREGATE_SUPPRESS_THRESHOLD)
            if a_src and b_src and not agg and (
                a_src.issubset(b_src) or b_src.issubset(a_src)
            ):
                signals.append("source-id-subset")
                rank = min(rank, 0)
            shared_loc = bool(a["locations"] & b["locations"])
            if shared_loc:
                signals.append("shared-location")
                rank = min(rank, 1)
            if a["pocs"] & b["pocs"]:
                signals.append("shared-poc")
                rank = min(rank, 2)
            jac = _dedup_title_jaccard(a["title"], b["title"])
            if jac >= 0.5:
                signals.append(f"title-jaccard={jac:.2f}")
                rank = min(rank, 3)
            # Same-fix recall layer: a pair tied to the same code site (shared
            # location OR shared anchor identifier) whose Recommendations agree
            # is a true cross-tier duplicate that the subset signal misses
            # (different agents → different source IDs). The same-fix gate runs
            # here so the candidate carries an authoritative MERGE-eligible flag;
            # the antonym/thin-fix vetoes keep precision intact.
            shared_anchor = bool(a.get("anchors") and b.get("anchors")
                                 and (a["anchors"] & b["anchors"]))
            # Candidate broadening (recall-safe): also adjudicate pairs in the
            # SAME SOURCE FILE even when the exact location token / anchor
            # differs. Different agents express the same site at different
            # granularity (e.g. "Foo.sol:L120" vs "Foo.onCall()"), so
            # exact-token matching misses true same-root-cause dupes. ONLY the
            # candidate set widens here — the merge DECISION stays gated by the
            # UNCHANGED strict `_dedup_same_fix_ok` (Recommendation Jaccard +
            # antonym/thin-fix vetoes) and the superset survivor guard, so a
            # false merge that HIDES a finding remains precluded.
            a_files = {f for f in (_dedup_file_part(l) for l in a["locations"]) if f}
            b_files = {f for f in (_dedup_file_part(l) for l in b["locations"]) if f}
            same_file = bool(a_files & b_files)
            if ((shared_loc or shared_anchor or same_file)
                    and "source-id-subset" not in signals
                    and not agg):
                ok, reason = _dedup_same_fix_ok(a, b)
                if ok:
                    site = ("loc" if shared_loc
                            else "anchor" if shared_anchor else "file")
                    signals.append(f"same-fix-cross-tier[{site}]:{reason}")
                    rank = min(rank, 1)
            if not signals:
                continue
            # survivor = higher severity (lower prefix priority number)
            pri = {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}
            if pri.get(a["prefix"], 9) <= pri.get(b["prefix"], 9):
                keep, absorb = a, b
            else:
                keep, absorb = b, a
            pairs.append({
                "keep": keep["id"], "absorb": absorb["id"],
                "signals": signals, "rank": rank,
            })
    pairs.sort(key=lambda p: p["rank"])
    return pairs


def _impact_block_text(text: str) -> str:
    """Concatenate just the `**Impact**` blocks of a report (the Impact line plus
    its bullets, up to the next bold field / heading / horizontal rule). Used to
    scope the data-loss bullet check to IMPACT bullets only — the bullets that
    actually carry severity-relevant signal — when the candidate transform (the
    QO retabulation) intentionally compacts a cosmetic finding's verbose
    Recommendation/Evidence/Description bullets into a one-line table row."""
    out: list[str] = []
    capturing = False
    for ln in text.splitlines():
        if re.match(r"\s*\*\*Impact\*\*", ln, re.I):
            capturing = True
            out.append(ln)
            continue
        if capturing:
            # stop at the next bold field, heading, or horizontal rule
            if re.match(r"\s*(?:\*\*[A-Za-z][^*]*\*\*\s*:|#{1,6}\s|---)", ln):
                capturing = False
                continue
            out.append(ln)
    return "\n".join(out)


def _dedup_data_loss_gate(original: str, deduped: str,
                          impact_only: bool = False) -> list[str]:
    """Mechanical zero-data-loss gate. Returns a list of LOST items (empty=ok).

    Every Location token, PoC test-id, and bullet in the ORIGINAL must still
    appear somewhere in the DEDUPED output. Merged findings renumber survivors,
    so we do NOT require the absorbed ID heading to survive — only its CONTENT
    (locations/impacts/pocs). The report-ID dimension is checked via the dedup
    mapping separately by the caller.

    `impact_only=True` scopes the BULLET check to `**Impact**`-block bullets
    only. The merge path couples ALL absorbed bullets into the survivor (no
    legitimate loss), so it keeps the strict whole-document bullet check. The QO
    retabulation, by design, drops a cosmetic finding's Recommendation/Evidence
    prose into a one-line row — those bullets are not severity-bearing and must
    not be counted as data loss (the security-signal guard, not this gate,
    protects real Low findings from being retabulated).
    """
    lost: list[str] = []
    orig_locs = {m.group(0).strip("`") for m in _DEDUP_LOCATION_TOKEN_RE.finditer(original)}
    ded_locs = {m.group(0).strip("`") for m in _DEDUP_LOCATION_TOKEN_RE.finditer(deduped)}
    for loc in orig_locs:
        if loc not in ded_locs:
            lost.append(f"location:{loc}")
    orig_pocs = set(_DEDUP_POC_FN_RE.findall(original))
    ded_pocs = set(_DEDUP_POC_FN_RE.findall(deduped))
    for poc in orig_pocs:
        if poc not in ded_pocs:
            lost.append(f"poc:{poc}")
    # Bullet presence: normalize whitespace + the retab's pipe-escape (`|`->`/`,
    # applied identically to both sides so a literal `|` in an original bullet is
    # not a phantom loss) before the containment check.
    def _norm(s: str) -> str:
        return re.sub(r"\s+", " ", s).strip().lower().replace("|", "/")

    bullet_src = _impact_block_text(original) if impact_only else original
    orig_b = {_norm(m.group(1)) for m in _DEDUP_IMPACT_BULLET_RE.finditer(bullet_src)}
    ded_normalized = _norm(deduped)
    for bullet in orig_b:
        if bullet and bullet not in ded_normalized:
            lost.append(f"impact:{bullet[:60]}")
    return lost


# Security-impact signal vocabulary. A Low/Info finding whose body mentions any
# of these is NOT cosmetic — it keeps its full `### [X-NN]` section even if its
# title matches a quality-observation class. Generic vulnerability vocabulary
# only (no protocol-specific tokens): the retabulation must never demote a real
# (even low-severity) security observation to a single QO table row.
_QO_SECURITY_IMPACT_SIGNAL_RE = re.compile(
    r"(?i)\b("
    r"missing\s+validation|input\s+validation|sanitiz|"
    r"missing\s+event|event\s+emission|emit\b|"
    r"access\s+control|authoriz|unauthoriz|permission|privileg|"
    r"\bauth\b|authenticat|onlyowner|onlyadmin|role[-\s]?based|"
    r"fund(?:s)?\s+loss|loss\s+of\s+funds|drain|steal|theft|"
    r"reentran|re-entran|"
    r"overflow|underflow|"
    r"front[-\s]?run|"
    r"oracle|price\s+manipulat|"
    r"centraliz"
    r")\b"
)


def _finding_own_block(section: str) -> str:
    """Trim a parsed finding `section` to the finding's OWN content.

    `_dedup_report_sections` extends a finding section to the NEXT finding
    heading (or EOF), which can swallow a trailing non-finding section such as
    a pre-existing `## Quality Observations` table, `## Priority Remediation
    Order`, or an appendix when the finding is the last one before that
    section. For QO retabulation we must operate on (and remove) ONLY the
    finding's own block — bounded by the first subsequent `##`/`###` heading
    after the finding's own heading line. Returns the trimmed block (always a
    leading substring of `section`).
    """
    if not section:
        return section
    # Skip the finding's own heading line, then find the next H2/H3 heading.
    nl = section.find("\n")
    if nl < 0:
        return section
    rest = section[nl + 1:]
    m = re.search(r"(?m)^#{2,3}\s", rest)
    if not m:
        return section
    return section[: nl + 1 + m.start()]


def _reclassify_cosmetic_low_info_to_qo(
    audit_text: str,
    extra_qo_ids: set[str] | None = None,
) -> tuple[str, list[tuple[str, str, str, str, str, str]]]:
    """F1 — Quality-Observations retabulation (RETABULATION, never a drop).

    For each `### [L-NN]` / `### [I-NN]` finding section: if
    ``classify_quality_observation(title, severity)`` returns a non-empty
    cosmetic class OR the report ID is in ``extra_qo_ids`` (Phase 6d agent
    proposals) — AND the section body carries NO security-impact signal — move
    the finding into a single row under a `## Quality Observations` megasection
    table and remove the standalone `###` section. Otherwise the section is
    kept verbatim.

    ``extra_qo_ids`` lets the LLM proposer flag cosmetic Low/Info findings the
    vocab classifier misses. The security-impact-signal guard still applies to
    agent-flagged IDs (an agent CANNOT bury a finding whose body shows a
    security signal), and retabulation remains provably zero-loss (every removed
    section re-appears as exactly one QO row preserving its locations / impacts /
    PoC fns), so the downstream data-loss gate re-confirms no loss.

    This is pure retabulation: every report ID that leaves a `###` section
    re-appears as exactly one QO table row, so NO finding ID is ever dropped
    (the downstream `_dedup_data_loss_gate` re-confirms zero location/impact/PoC
    loss).

    Returns ``(new_text, log_rows)`` where each log row is
    ``(report_id, title, severity, location, class, one_line_desc)``. When no
    section qualifies, returns the input unchanged with an empty log.
    """
    if not audit_text:
        return audit_text, []

    records = _dedup_report_sections(audit_text)
    pri_to_sev = {"L": "Low", "I": "Informational"}
    extra = {x.upper() for x in (extra_qo_ids or set())}

    qo_rows: list[tuple[str, str, str, str, str, str]] = []
    blocks_to_remove: list[str] = []
    for rec in records:
        prefix = rec["prefix"]
        if prefix not in pri_to_sev:
            continue  # only Low / Info are QO-eligible
        sev_word = pri_to_sev[prefix]
        cls = classify_quality_observation(rec["title"], sev_word)
        if not cls and rec["id"].upper() in extra:
            # Agent flagged this Low/Info as cosmetic but the vocab classifier
            # did not name a class — record it under a generic class so the
            # retabulation still fires (the security-impact guard below still
            # protects against burying a real finding).
            cls = "observation"
        if not cls:
            continue  # not a cosmetic class → keep the full section
        # Operate on the finding's OWN block only — never the trailing
        # non-finding section a parsed record may have swallowed.
        own = _finding_own_block(rec["section"])
        if _QO_SECURITY_IMPACT_SIGNAL_RE.search(own):
            continue  # carries a security-impact signal → keep the full section
        # Build the QO row. The Location cell lists ALL location tokens and the
        # Description cell carries any impact bullets / PoC test-fns inline, so
        # the downstream mechanical data-loss gate (which checks every original
        # location / impact bullet / PoC fn still appears SOMEWHERE) passes —
        # retabulation is provably zero-loss, not merely "usually" cosmetic.
        own_locs = {
            m.group(0).strip("`") for m in _DEDUP_LOCATION_TOKEN_RE.finditer(own)
        }
        own_pocs = set(_DEDUP_POC_FN_RE.findall(own))
        own_impacts: set[str] = set()
        imp_block = re.search(
            r"(?is)\*\*Impact\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", own
        )
        if imp_block:
            for bm in _DEDUP_IMPACT_BULLET_RE.finditer(imp_block.group(1)):
                own_impacts.add(bm.group(1).strip())
        locs_sorted = sorted(own_locs)
        loc_cell = ", ".join(f"`{l}`" for l in locs_sorted) if locs_sorted else ""
        desc = _qo_one_line_desc(own)
        extra_bits: list[str] = []
        for imp in sorted(own_impacts):
            imp_clean = re.sub(r"\s+", " ", imp).replace("|", "/").strip()
            if imp_clean and imp_clean.lower() not in desc.lower():
                extra_bits.append(imp_clean)
        for poc in sorted(own_pocs):
            extra_bits.append(poc)
        if extra_bits:
            desc = (desc + " " if desc else "") + "(" + "; ".join(extra_bits) + ")"
        class_title = _QUALITY_CLASS_TITLES.get(cls, cls)
        qo_rows.append(
            (rec["id"], rec["title"], sev_word, loc_cell, class_title, desc)
        )
        blocks_to_remove.append(own)

    if not qo_rows:
        return audit_text, []

    # --- remove the absorbed `###` blocks (longest-first to keep indices
    #     stable; every block text is unique because IDs are unique) ----------
    new_text = audit_text
    for own in sorted(blocks_to_remove, key=lambda s: -len(s)):
        idx = new_text.find(own)
        if idx < 0:
            continue
        new_text = new_text[:idx] + new_text[idx + len(own):]

    # --- append (or extend) the `## Quality Observations` table --------------
    new_text = _append_quality_observation_rows(new_text, qo_rows)
    new_text = re.sub(r"\n{4,}", "\n\n\n", new_text)
    return new_text, qo_rows


def _qo_one_line_desc(section: str) -> str:
    """Extract a one-sentence description for a QO row from a finding section.

    Prefers the first non-empty line of the `**Description**` field; falls back
    to the first non-heading, non-metadata prose line. Always single-line.
    """
    desc_block = re.search(
        r"(?is)\*\*Description\*\*\s*:?(.*?)(?:\n\*\*[A-Z]|\Z)", section
    )
    raw = desc_block.group(1) if desc_block else ""
    if not raw.strip():
        # Fall back to the first prose line that is not a heading / metadata.
        for ln in section.splitlines():
            s = ln.strip()
            if not s or s.startswith("#") or s.startswith("**") or s.startswith("|"):
                continue
            raw = s
            break
    text = re.sub(r"\s+", " ", raw).strip()
    text = text.replace("|", "/")  # never break the markdown table
    # First sentence, capped.
    m = re.match(r"(.{0,200}?[.!?])\s", text + " ")
    one = m.group(1).strip() if m else text[:200].strip()
    return one


def _append_quality_observation_rows(
    text: str, rows: list[tuple[str, str, str, str, str, str]]
) -> str:
    """Append QO rows into a `## Quality Observations` table.

    If the section already exists, append rows to its table; otherwise create
    the section (with header row) at the end of the document. Idempotent header.
    """
    header = (
        "| ID | Title | Severity | Location | Class | Description |\n"
        "|----|-------|----------|----------|-------|-------------|\n"
    )

    def _fmt(r: tuple[str, str, str, str, str, str]) -> str:
        rid, title, sev, loc, cls, desc = r
        title = re.sub(r"\s+", " ", title).replace("|", "/").strip()
        loc = (loc or "").replace("|", "/").strip()
        return f"| {rid} | {title} | {sev} | {loc} | {cls} | {desc} |"

    body_rows = "\n".join(_fmt(r) for r in rows) + "\n"

    existing = _extract_h2_section(text, "Quality Observations")
    if existing:
        # Append rows to the end of the existing section's table.
        pattern = re.compile(
            r"(^#{2,3}\s+Quality Observations[^\n]*\n(?:.|\n)*?)(?=\n##(?!#)|\Z)",
            re.MULTILINE | re.IGNORECASE,
        )
        m = pattern.search(text)
        if m:
            sect = m.group(1).rstrip("\n")
            # Ensure a header exists in the section; if not, inject one.
            if "| ID | Title |" not in sect and "|----" not in sect:
                sect = sect + "\n\n" + header.rstrip("\n")
            new_sect = sect + "\n" + body_rows.rstrip("\n") + "\n"
            return text[: m.start()] + new_sect + text[m.end():]

    # No existing section — create it at the end of the document.
    section = (
        "\n\n## Quality Observations\n\n"
        + header
        + body_rows.rstrip("\n")
        + "\n"
    )
    return text.rstrip("\n") + section + "\n"


# =========================================================================
# Material-harm body floor — mechanical enforcement (the load-bearing part)
# =========================================================================
#
# Policy + recall-safety contract live in plamen_parsers.classify_body_or_appendix
# and ~/.plamen/rules/{report-template.md,phase6-report-prompts.md}. Here we:
#   1. WRITE `disposition.md` (report-ID keyed) deterministically from the
#      bounded ledgers report-index already uses.
#   2. ENFORCE it on the assembled report: any APPENDIX id that still has a
#      `### [X-NN]` body section is RELOCATED to an Appendix table row — never
#      dropped. A missing/empty disposition is a no-op (degrade to body).
#
# Prior soft LLM rules were ignored, so the enforcement is driver-mechanical.

_FLOOR_SEV_WORD = {
    "C": "Critical", "H": "High", "M": "Medium", "L": "Low", "I": "Informational",
}

_FLOOR_APPENDIX_HEADING = "## Appendix C: Quality & Hardening Observations"


def _report_id_title_map(scratchpad: Path) -> dict[str, str]:
    """Map report-ID -> client title from report_index.md Master Finding Index."""
    p = scratchpad / "report_index.md"
    if not p.exists():
        return {}
    try:
        txt = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}
    scope = _extract_h2_section(txt, "Master Finding Index") or txt
    out: dict[str, str] = {}
    for m in re.finditer(
        r"^\|\s*\[?\*?\*?([CHMLI]-\d+)\*?\*?\]?\s*\|\s*([^|]+?)\s*\|",
        scope, re.MULTILINE,
    ):
        rid = m.group(1).upper()
        if rid not in out:
            out[rid] = _sanitize_client_title(m.group(2).strip())
    return out


def write_disposition_md(scratchpad: Path) -> int:
    """Write `disposition.md` (report-ID keyed BODY/APPENDIX classification).

    ALWAYS-RUN classification. Sources the ID set from the same bounded
    ledgers report-index uses (report_index.md assignments, which are derived
    from verification_queue.md / verify_*.md / finding_mapping.md), and the
    per-finding harm/verdict from the mapped verify_*.md file(s). Each row:

        | REPORT_ID | BODY|APPENDIX | <one-line reason> |

    Returns the number of rows written. Defensive: returns 0 (and writes
    nothing) when there are no report-ID assignments yet, so the caller
    degrades to current behaviour. Never raises.
    """
    try:
        assignments = parse_report_index_assignments(scratchpad)
    except Exception:
        assignments = []
    if not assignments:
        return 0
    title_map = _report_id_title_map(scratchpad)
    rows_out: list[tuple[str, str, str]] = []
    seen: set[str] = set()
    for a in assignments:
        rid = (a.get("report_id") or "").strip().upper()
        if not rid or rid in seen:
            continue
        seen.add(rid)
        internal = a.get("finding_id") or ""
        vtxt = ""
        for piece in re.split(r"[+,\s]+", internal):
            piece = piece.strip()
            if not piece:
                continue
            try:
                vp = _verify_file_for_id(scratchpad, piece)
                if vp.exists():
                    vtxt += "\n" + _llm_norm(
                        vp.read_text(encoding="utf-8", errors="replace")
                    )
            except Exception:
                pass
        title = title_map.get(rid) or _first_heading_title(vtxt) or "Finding"
        harm = _field_from_markdown(
            vtxt, ("Material Harm", "Impact", "Description")
        ) or ""
        try:
            status = _verifier_status_from_text(vtxt)
        except Exception:
            status = ""
        sev = _FLOOR_SEV_WORD.get(rid[0], "")
        try:
            disp, reason = classify_body_or_appendix(title, sev, harm, status)
        except Exception:
            disp, reason = ("BODY", "default (classifier error — recall-safe)")
        rows_out.append((rid, disp, reason))

    def _sort_key(r: tuple[str, str, str]) -> tuple[int, int]:
        rid = r[0]
        prio = {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}.get(rid[0], 9)
        num = re.findall(r"\d+", rid)
        return (prio, int(num[0]) if num else 0)

    rows_out.sort(key=_sort_key)
    n_appendix = sum(1 for _r, d, _x in rows_out if d == "APPENDIX")
    lines = [
        "# Finding Disposition (BODY / APPENDIX)",
        "",
        "Driver-computed material-harm body floor. APPENDIX = ZERO security "
        "consequence (pure quality / hardening / observability / style). BODY = "
        "any real security consequence, at any severity. Recall-safe default: "
        "BODY. This is mechanically enforced on the assembled report.",
        "",
        f"- Total: {len(rows_out)} | BODY: {len(rows_out) - n_appendix} | "
        f"APPENDIX: {n_appendix}",
        "",
        "| Report ID | Disposition | Reason |",
        "|-----------|-------------|--------|",
    ]
    for rid, disp, reason in rows_out:
        reason_cell = re.sub(r"\s+", " ", reason).replace("|", "/").strip()
        lines.append(f"| {rid} | {disp} | {reason_cell} |")
    try:
        (scratchpad / "disposition.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        log.warning(f"[disposition] write failed: {exc!r}")
        return 0
    log.info(
        f"[disposition] wrote disposition.md ({len(rows_out)} finding(s), "
        f"{n_appendix} APPENDIX)"
    )
    return len(rows_out)


def _strip_floor_id_references(text: str, moved_ids: set[str]) -> str:
    """Remove dangling references to relocated IDs from summary-style sections.

    Drops Executive-Summary bullet lines (`- **X-NN** — …`) and Priority
    Remediation Order numbered lines (`N. **X-NN** — …`) that cite a relocated
    finding, then renumbers the remediation list. Leaves everything else intact.
    """
    if not moved_ids:
        return text
    out_lines: list[str] = []
    rem_counter = 0
    in_remediation = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("## "):
            in_remediation = bool(
                re.match(r"##\s+Priority Remediation Order", s, re.IGNORECASE)
            )
        # Executive-summary / generic bullet citing a moved id.
        bm = re.match(r"^\s*[-*]\s+\*\*([CHMLI]-\d+)\*\*", line)
        if bm and bm.group(1).upper() in moved_ids:
            continue
        # Priority Remediation Order numbered line citing a moved id.
        nm = re.match(r"^\s*\d+\.\s+\*\*([CHMLI]-\d+)\*\*\s*(.*)$", line)
        if in_remediation and nm:
            if nm.group(1).upper() in moved_ids:
                continue
            rem_counter += 1
            out_lines.append(f"{rem_counter}. **{nm.group(1)}** {nm.group(2)}".rstrip())
            continue
        out_lines.append(line)
    return "\n".join(out_lines)


def _decrement_summary_counts(text: str, moved_by_sev: dict[str, int]) -> str:
    """Decrement the report's `## Summary` counts table for relocated findings.

    `moved_by_sev` maps a severity word (``Critical`` / ``High`` / ``Medium`` /
    ``Low`` / ``Informational``) to the number of findings relocated out of the
    body at that severity. Each matching `| Severity | N |` row in the FIRST
    `## Summary` table has its count reduced by that many (floored at 0). The
    delivered report's Summary then matches its remaining body sections.

    Recall-safe + idempotent: a second floor pass relocates nothing, so
    `moved_by_sev` is empty and this is a no-op. Never raises — on any anomaly it
    returns the input unchanged.
    """
    if not moved_by_sev:
        return text
    try:
        norm = {
            re.sub(r"[^a-z]", "", k.lower()): v
            for k, v in moved_by_sev.items()
            if v
        }
        if not norm:
            return text

        # The `Total` row is decremented by the SUM of all per-severity moves so
        # the table stays internally consistent (its parts keep summing to the
        # total). Without this the per-severity rows drop but `**Total**` stays
        # stale, producing a self-contradictory Summary in the delivered report.
        total_dec = sum(norm.values())

        # Tolerate optional markdown emphasis (`**Total**`, `**92**`) around both
        # the label and the count cell so the Total/bolded rows are matched too.
        row_re = re.compile(
            r"^(\s*\|\s*)(\**)([A-Za-z]+)(\**)(\s*\|\s*)(\**)(\d+)(\**)(\s*\|.*)$"
        )
        out: list[str] = []
        in_summary = False
        for line in text.splitlines():
            s = line.strip()
            if re.match(r"^##+\s+Summary\b", s, re.IGNORECASE):
                in_summary = True
                out.append(line)
                continue
            if in_summary and s.startswith("## "):
                in_summary = False  # left the Summary section
            if in_summary:
                m = row_re.match(line)
                if m:
                    key = re.sub(r"[^a-z]", "", m.group(3).lower())
                    dec = total_dec if key == "total" else norm.get(key, 0)
                    if dec:
                        newcount = max(0, int(m.group(7)) - dec)
                        line = (
                            f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(4)}"
                            f"{m.group(5)}{m.group(6)}{newcount}{m.group(8)}"
                            f"{m.group(9)}"
                        )
            out.append(line)
        return "\n".join(out)
    except Exception:
        return text


def _reconcile_exec_summary_count(text: str) -> str:
    """Rewrite the Executive Summary's prose finding count to match the delivered
    ``## Summary`` counts table.

    The mechanical ``## Summary`` table is the authoritative delivered count (its
    per-tier rows equal the body ``### [X-NN]`` sections). The Executive Summary
    prose count (``identified **N findings**: A Critical, B High, C Medium,
    D Low, E Informational.``) is generated ONCE at assembly time from the
    (pre-floor) report_index counts and is never revised. The material-harm
    floor then relocates pure-quality body findings into Appendix C and
    decrements the ``## Summary`` table (see ``_decrement_summary_counts``),
    leaving the prose count stale and contradicting the delivered table.

    This reconciles the prose count to the current ``## Summary`` table so the
    two agree. It does NOT touch the (mechanically-correct) ``## Summary`` table.

    Deterministic, idempotent (a second pass finds matching numbers and is a
    no-op), and unparseable-safe: if the ``## Summary`` table or the
    exec-summary count line cannot be fully parsed, the text is returned
    unchanged.
    """
    if not text:
        return text
    try:
        # 1. Locate the FIRST `## Summary` (or `## Summary Counts`) table. The
        #    `\bSummary` anchor deliberately does NOT match `## Executive
        #    Summary` (word after `## ` there is `Executive`).
        sm = re.search(r"(?im)^##+[ \t]+Summary(?:[ \t]+Counts)?\b", text)
        if not sm:
            return text
        after = sm.end()
        nxt = re.search(r"(?m)^##[ \t]+", text[after:])
        summary_region = text[after: after + nxt.start()] if nxt else text[after:]

        counts: dict[str, int] = {}
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            rm = re.search(
                rf"(?im)^\s*\|\s*\**{sev}\**\s*\|\s*\**(\d+)\**\s*\|",
                summary_region,
            )
            if rm:
                counts[sev] = int(rm.group(1))
        if len(counts) < 5:
            # Incomplete table — do not risk a partial rewrite.
            return text
        total = sum(counts.values())

        # 2. Rewrite the exec-summary count line. Matches the assembler-generated
        #    prose exactly, tolerating optional bold markers and singular
        #    "finding".
        pat = re.compile(
            r"(identified\s+\**)(\d+)(\s+findings?\**\s*:\s*)"
            r"(\d+)(\s+Critical\s*,\s*)"
            r"(\d+)(\s+High\s*,\s*)"
            r"(\d+)(\s+Medium\s*,\s*)"
            r"(\d+)(\s+Low\s*,\s*)"
            r"(\d+)(\s+Informational)",
            re.IGNORECASE,
        )

        def _sub(m: "re.Match[str]") -> str:
            return (
                f"{m.group(1)}{total}{m.group(3)}"
                f"{counts['Critical']}{m.group(5)}"
                f"{counts['High']}{m.group(7)}"
                f"{counts['Medium']}{m.group(9)}"
                f"{counts['Low']}{m.group(11)}"
                f"{counts['Informational']}{m.group(13)}"
            )

        new_text, n = pat.subn(_sub, text, count=1)
        return new_text if n else text
    except Exception:
        return text


def enforce_material_harm_floor(
    audit_text: str, disposition: dict[str, tuple[str, str]]
) -> tuple[str, list[tuple[str, str, str, str, str]]]:
    """Relocate APPENDIX-dispositioned body sections to a lossless Appendix.

    The load-bearing backstop. For every report ID dispositioned APPENDIX that
    STILL has a `### [X-NN]` (or `## [X-NN]`) finding section in the report
    BODY (the region before the first `## Appendix` heading):
      - remove the standalone section, and
      - add one row to `## Appendix C: Quality & Hardening Observations`, and
      - retain the complete original finding content under an Appendix-detail
        heading that is not counted as a BODY finding.

    GUARANTEES (recall-safe):
      (a) after the move the body contains ONLY BODY ids;
      (b) every APPENDIX id with a body section appears as exactly one Appendix
          table row — never dropped;
      (c) a body section for an APPENDIX id is moved (stripped from body, added
          as a row).

    Degrades to a no-op (returns the input unchanged) when `audit_text` is
    empty, `disposition` is empty, or no APPENDIX id has a body section.
    Idempotent: a second pass finds no APPENDIX `###` sections and is a no-op.

    Returns ``(new_text, moved_rows)`` where each moved row is
    ``(report_id, severity, title, location, reason)``.
    """
    if not audit_text or not disposition:
        return audit_text, []
    appendix = {
        rid: reason
        for rid, (disp, reason) in disposition.items()
        if disp == "APPENDIX"
    }
    if not appendix:
        return audit_text, []

    # Operate only on the BODY region (before the first appendix heading) so we
    # never touch existing appendix tables (A/B/C) or their rows.
    am = re.search(r"(?im)^##\s+Appendix\b", audit_text)
    if am:
        head, tail = audit_text[: am.start()], audit_text[am.start():]
    else:
        head, tail = audit_text, ""

    records = _dedup_report_sections(head)
    moved_rows: list[tuple[str, str, str, str, str]] = []
    moved_details: list[str] = []
    blocks_to_remove: list[str] = []
    moved_ids: set[str] = set()
    for rec in records:
        rid = (rec["id"] or "").upper()
        if rid not in appendix:
            continue
        own = _finding_own_block(rec["section"])
        sev = _field_from_markdown(own, ("Severity",)) or _FLOOR_SEV_WORD.get(
            rid[0], ""
        )
        sev = re.sub(r"[^A-Za-z].*$", "", sev.strip()) or _FLOOR_SEV_WORD.get(
            rid[0], ""
        )
        title = re.sub(r"\s+", " ", rec.get("title") or "Finding").strip()
        locs = sorted(rec.get("locations") or [])
        loc_cell = ", ".join(f"`{l}`" for l in locs) if locs else ""
        reason = appendix.get(rid) or "pure quality/hardening (no demonstrated harm)"
        moved_rows.append((rid, sev, title, loc_cell, reason))
        moved_details.append(
            re.sub(
                rf"(?im)^#{{2,3}}\s+\[{re.escape(rid)}\]\s*",
                f"### Appendix observation [{rid}] ",
                own,
                count=1,
            ).strip()
        )
        blocks_to_remove.append(own)
        moved_ids.add(rid)

    if not moved_rows:
        return audit_text, []

    for own in sorted(blocks_to_remove, key=lambda s: -len(s)):
        idx = head.find(own)
        if idx < 0:
            continue
        head = head[:idx] + head[idx + len(own):]

    head = _strip_floor_id_references(head, moved_ids)
    # Decrement the `## Summary` counts table so the delivered report's summary
    # matches its remaining body sections (recall-safe: moved findings are still
    # accounted for in Appendix C below; idempotent on re-run).
    moved_by_sev: dict[str, int] = {}
    for _rid, _sev, _t, _l, _r in moved_rows:
        key = (_sev or "").strip() or _FLOOR_SEV_WORD.get(_rid[0], "")
        if key:
            moved_by_sev[key] = moved_by_sev.get(key, 0) + 1
    head = _decrement_summary_counts(head, moved_by_sev)
    head = re.sub(r"\n{4,}", "\n\n\n", head).rstrip("\n")

    # Build / extend the Appendix C table.
    appendix_header = (
        "| ID | Severity | Title | Location | Reason |\n"
        "|----|----------|-------|----------|--------|\n"
    )

    def _fmt(r: tuple[str, str, str, str, str]) -> str:
        rid, sev, title, loc, reason = r
        title = re.sub(r"\s+", " ", title).replace("|", "/").strip()
        reason = re.sub(r"\s+", " ", reason).replace("|", "/").strip()
        loc = (loc or "").replace("|", "/").strip()
        return f"| {rid} | {sev} | {title} | {loc} | {reason} |"

    body_rows = "\n".join(_fmt(r) for r in moved_rows)
    detail_blocks = "\n\n".join(moved_details)
    intro = (
        "_The items below are quality / hardening / observability observations "
        "with no demonstrated security consequence. They were routed out of the "
        "client body to keep it focused on findings with material harm; none was "
        "dropped._"
    )

    if _FLOOR_APPENDIX_HEADING.split(":", 1)[0] in tail or "Quality & Hardening Observations" in tail:
        # Extend an existing Appendix C table (idempotent re-runs / merges).
        pattern = re.compile(
            r"(?ims)^##\s+Appendix C:[^\n]*\n(?:.*?)(?=^##\s|\Z)"
        )
        m = pattern.search(tail)
        if m:
            sect = m.group(0).rstrip("\n")
            if "| ID | Severity |" not in sect:
                sect = sect + "\n\n" + appendix_header.rstrip("\n")
            sect = sect + "\n" + body_rows + "\n\n" + detail_blocks + "\n"
            tail = tail[: m.start()] + sect + tail[m.end():]
        else:
            tail = tail.rstrip("\n") + "\n\n" + _FLOOR_APPENDIX_HEADING + "\n\n" + intro + "\n\n" + appendix_header + body_rows + "\n\n" + detail_blocks + "\n"
    else:
        tail = tail.rstrip("\n") + "\n\n---\n\n" + _FLOOR_APPENDIX_HEADING + "\n\n" + intro + "\n\n" + appendix_header + body_rows + "\n\n" + detail_blocks + "\n"

    new_text = head.rstrip("\n") + "\n\n" + tail.lstrip("\n")
    new_text = re.sub(r"\n{4,}", "\n\n\n", new_text)
    # Sync the Executive Summary prose count to the just-decremented `## Summary`
    # table so the delivered report's headline finding count matches its body.
    new_text = _reconcile_exec_summary_count(new_text)
    if not new_text.endswith("\n"):
        new_text += "\n"
    return new_text, moved_rows


def apply_material_harm_floor(scratchpad: Path, project_root: str) -> dict:
    """Read disposition.md + AUDIT_REPORT.md, enforce the floor, rewrite report.

    Thin file-IO wrapper around `enforce_material_harm_floor`. Haltless: any
    missing file or parse failure is a no-op. Returns
    ``{"moved": N, "ids": [...]}``.
    """
    pr = Path(project_root) / "AUDIT_REPORT.md"
    if not pr.exists():
        return {"moved": 0, "ids": []}
    try:
        disposition = parse_disposition_md(scratchpad)
    except Exception:
        disposition = {}
    if not disposition:
        return {"moved": 0, "ids": []}
    try:
        text = pr.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"moved": 0, "ids": []}
    new_text, moved = enforce_material_harm_floor(text, disposition)
    if not moved:
        return {"moved": 0, "ids": []}
    try:
        pr.write_text(new_text, encoding="utf-8")
    except Exception as exc:
        log.warning(f"[material-harm-floor] rewrite failed: {exc!r}")
        return {"moved": 0, "ids": []}
    ids = [r[0] for r in moved]
    log.info(
        f"[material-harm-floor] relocated {len(moved)} pure-quality finding(s) "
        f"to {_FLOOR_APPENDIX_HEADING.split(':',1)[0]}: {', '.join(ids[:10])}"
    )
    return {"moved": len(moved), "ids": ids}


# =========================================================================
# Gate P — content-shaped Promotion Completeness (Class C pipeline-loss)
# =========================================================================
#
# Replaces the v2.8.9 ID-pattern feeder harvest (86% net-noise: promoted on
# bare ID-token presence with no harm signal) with a CONTENT-SHAPED harvest:
# a candidate only counts when it carries a real (file:Lnnn location +
# mechanism cue + enough descriptive text) — bare "[XX-5]"-shaped noise with
# no location/mechanism never becomes a candidate at all. Destination (BODY /
# Appendix C / Appendix A) is decided by the EXISTING material-harm classifier
# (`classify_body_or_appendix`, the same primitive `write_disposition_md` /
# `enforce_material_harm_floor` already use), never by the harvester itself —
# this is the one routing choice that fixes v2.8.9's noise (promotion signal
# = Material-Harm classifier, destination = disposition router).
#
# Recall-safe: a harvested candidate is never dropped — it lands in exactly
# one of BODY-candidate / Appendix-C staging / Appendix-A staging.
# Precision-safe: BODY candidates are appended to findings_inventory.md as
# NEEDS_VERIFICATION (never body-at-severity directly) — the existing
# verify-the-positives pipeline adjudicates before anything can reach the
# report body.
# Idempotent + append-only + bounded: mirrors enumeration_gate.py's receipt
# discipline and per-run caps so a flood of shallow candidates cannot inflate
# the body.
# No-overfit: pure shape/content mechanics (a location pattern + generic,
# HOW-shaped mechanism vocabulary); no protocol/token/contract name in logic
# or fixtures.
#
# `compute_promotion_orphans` / `route_promotion_orphans` are pure, driver-
# wireable callables — this module never calls itself from a phase hook; the
# driver owner wires the call sites (mirrors enumeration_gate.py's contract).

_PROMO_MAX_FILES = 60           # bound files scanned per run (recall-safe cap)
_PROMO_MAX_PER_FILE = 12        # bound candidates harvested per feeder file
_PROMO_MAX_PER_RUN = 30         # global bound on emitted candidates per run
# Historical location-proximity helpers retain this window only for diagnostic
# duplicate nomination. Neither proximity nor equal location/shape suppresses
# a subject; only the full cryptographic subject establishes exact identity.
_PROMO_LOC_WINDOW = 30
_PROMO_LOC_RE = re.compile(
    r"([A-Za-z0-9_][A-Za-z0-9_./\-]*\.(?:rs|sol|move|go|py|cairo)):L?(\d+)(?:\s*-\s*L?(\d+))?",
    re.I,
)
_PROMO_MIN_TEXT_LEN = 30        # minimum descriptive-text length to count as "shaped"

_PROMO_FEEDER_GLOBS: tuple = (
    "depth_*.md",
    "blind_spot_*.md",
    "analysis_*.md",
    "analysis_percontract_*.md",
    "analysis_rescan_*.md",
    "scanner_*.md",
    "niche_*.md",
    "*_percontract_*.md",
    "validation_sweep*.md",
    "design_stress_findings.md",
    "sibling_propagation_findings.md",
    "skill_execution_gaps.md",
    "checklist*.md",
)
_PROMO_FEEDER_GLOBS = tuple(dict.fromkeys(
    _PROMO_FEEDER_GLOBS + _registered_producer_patterns("late_harvest")
))

# Artifacts Gate P must never re-harvest: its own output (prevents a
# harvest-loop on the ledgers/receipts it writes) plus report/inventory
# artifacts the normal pipeline already owns.
_PROMO_EXCLUDE_NAMES: frozenset = frozenset({
    "findings_inventory.md",
    "report_index_coverage_seed.md",
    "promotion_orphans.md",
    "promotion_routing.md",
    "promotion_orphans_appendix_c.md",
    "promotion_orphans_appendix_a.md",
    "promotion_gate_receipt.md",
})

_PROMO_LOCATION_RE = re.compile(
    r"\b[\w][\w./\\-]*\.(?:sol|rs|move|go|py|ts|js|jsx|tsx)\s*:\s*L?\d+"
    r"(?:\s*[-–]\s*L?\d+)?\b",
    re.IGNORECASE,
)

# Generic, HOW-shaped defect-mechanism vocabulary (no protocol/function names)
# — mirrors the style of the pipeline's existing `_GUARD_ABSENCE_CUE` /
# `_HARM_CONSEQUENCE_RE` cue lists. This is the harvest-side precision gate:
# bare ID-token text with no mechanism wording never becomes a candidate.
_PROMO_MECHANISM_CUE_RE = re.compile(
    r"(?i)\b(?:missing|lacks?|no\s+(?:check|guard|validation)|"
    r"does\s+not\s+(?:check|validate|verify|update|emit|revert|reset)|"
    r"fails?\s+to\s+(?:check|validate|update|emit|revert|reset)|"
    r"unchecked|un-?gated|not\s+gated|"
    r"incorrect(?:ly)?|allows?\s+|permits?\s+|"
    r"overflow|underflow|reentran\w*|"
    r"can\s+be\s+(?:bypassed|manipulated|drained|exploited)|"
    r"race\s+condition|stale\b|out[-\s]of[-\s]date|"
    r"never\s+(?:checked|validated|updated|reset)|"
    r"truncat\w*|mismatch\w*|misrout\w*|drain\w*|corrupt\w*|"
    r"desync\w*|inconsistent\w*|bypass\w*|manipulat\w*"
    r")\b"
)

_PROMO_REFUTED_RE = re.compile(
    r"(?i)\b(?:REFUTED|FALSE[_\s-]?POSITIVE|DROP_FALSE_POSITIVE|"
    r"not\s+exploitable|not\s+a\s+(?:bug|vulnerability|real\s+issue)|"
    r"safe\s+by\s+design|working\s+as\s+intended|intended\s+behavior|"
    r"design\s+confirmation)\b"
)

# A heading that is a METHODOLOGY / meta / bookkeeping section, never a finding.
# A real finding block is titled with a bug ("Finding [X]: ...", or a defect
# description) — never one of these process artifacts. Applied to the block's own
# heading line only, so it cannot suppress a finding that merely MENTIONS these words
# in its body. Deliberately EXCLUDES "CHECK N" (real blind-spot findings title as
# "CHECK 5 - <bug>: CONFIRMED"); the negative-disposition filter below handles the
# "CHECK N - no finding / rationale" case instead.
_PROMO_META_HEADING_RE = re.compile(
    r"(?i)(semantic\s+proof\s+check|obligation\s+receipt|exclusion\s+list|"
    r"pre-?condition\s+analysis|post-?condition\s+analysis|step\s+execution\s+checklist|"
    r"chain\s+summary|rules?\s+applied|depth\s+evidence|file\s+coverage|"
    r"coverage\s+checkpoint|self[-\s]?check|scope\s+containment|"
    r"analysis\s+methodology|methodology\b)"
)

# A NEGATIVE / no-finding / correct-usage disposition — the block itself concludes
# there is NO issue, so it is not a pipeline-loss candidate. Applied to the whole
# block. Kept specific so it does not match a real finding that says "does X correctly
# but fails Y" (only "correct <noun> usage", not a bare "correctly").
_PROMO_NEG_DISPOSITION_RE = re.compile(
    r"(?i)(no\s+additional\s+finding|no\s+finding\b|not\s+a\s+finding|"
    r"\bDONE\b\s*[-–—:]?\s*CORRECT|correct\s+\w*\s*usage|"
    r"no\s+(?:issue|bug|vulnerabilit)\w*|\bis\s+safe\b)"
)

# "dup of X-NN" / "duplicate of X-NN" — a cited referent means the EXCLUDED
# stub is a legitimate dedup, not pipeline-loss; only REFERENT-LESS stubs are
# candidates (exactly where a suppressed real bug hides per orchestrator-
# rules.md's own EXCLUSION SOURCE RULE).
_PROMO_DUP_REFERENT_RE = re.compile(r"(?i)\bdup(?:licate)?\s+of\b")
_PROMO_DUP_REFERENT_ID_RE = re.compile(
    r"(?i)\bdup(?:licate)?\s+of\s+\[?([A-Za-z][A-Za-z0-9_-]*-\d+)\]?"
)

_PROMO_EXCLUDED_STUB_RE = re.compile(
    r"(?im)^\s*EXCLUDED\s*\[([A-Za-z0-9_\-]+)\]\s*(.*)$"
)

_PROMO_ID_TOKEN_RE = re.compile(r"^\[?([A-Za-z]{1,10}-?\d+)\]?")

_PROMO_SUBJECT_SCHEMA = "plamen.gate_p.subject.v1"
_PROMO_SUBJECT_FIELD_RE = re.compile(
    r"(?im)^\s*\*\*Promotion Subject SHA256\*\*:\s*([0-9a-f]{64})\s*$"
)
_PROMO_RECEIPT_SUBJECT_RE = re.compile(
    r"(?im)^\s*PROMOGAP-SUBJECT-SHA256:\s*([0-9a-f]{64})\s*$"
)


def _promo_atomic_write_text(path: Path, text: str) -> None:
    """Publish one Gate-P text artifact atomically within its directory."""

    target = Path(path)
    encoded = text.encode("utf-8")
    with tempfile.NamedTemporaryFile(
        mode="wb",
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _promo_canonical_location(value: object) -> str:
    location = re.sub(r"\s+", " ", str(value or "").strip())
    return location.strip("`").replace("\\", "/")


def _promo_subject_from_components(
    *,
    producer_key: str,
    source_artifact: str,
    source_artifact_sha256: str,
    record_sha256: str,
    location: str,
    shape: str,
) -> str:
    payload = {
        "location": _promo_canonical_location(location),
        "producer_key": str(producer_key or "UNREGISTERED_MARKDOWN"),
        "record_sha256": str(record_sha256).lower(),
        "schema": _PROMO_SUBJECT_SCHEMA,
        "shape": str(shape or ""),
        "source_artifact": str(source_artifact or ""),
        "source_artifact_sha256": str(source_artifact_sha256).lower(),
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _promo_bind_subject_identity(
    cand: dict,
    *,
    source_artifact_sha256: str,
    producer_key: str,
) -> str:
    """Bind a harvested record to one stable, replayable Gate-P subject.

    Neither a producer-local ID nor a location/shape tuple is an identity.
    The subject includes the producing contract, the exact source artifact
    bytes, the exact extracted record bytes, the canonical location, and the
    record shape.  The full SHA-256 is retained; no prefix is authoritative.
    """

    record_bytes = cand.pop("_record_bytes", None)
    if not isinstance(record_bytes, bytes):
        record_bytes = str(cand.get("text", "") or "").encode(
            "utf-8", errors="surrogatepass"
        )
    record_sha256 = hashlib.sha256(record_bytes).hexdigest()
    location = _promo_canonical_location(cand.get("location", ""))
    cand["location"] = location
    producer_identity = str(producer_key or "UNREGISTERED_MARKDOWN")
    subject = _promo_subject_from_components(
        producer_key=producer_identity,
        source_artifact=str(cand.get("source_file", "") or ""),
        source_artifact_sha256=source_artifact_sha256,
        record_sha256=record_sha256,
        location=location,
        shape=str(cand.get("shape", "") or ""),
    )
    cand.update({
        "producer_key": producer_identity,
        "source_artifact_sha256": str(source_artifact_sha256).lower(),
        "record_sha256": record_sha256,
        "subject_sha256": subject,
    })
    return subject


def promotion_reconciled_subjects(scratchpad: Path) -> set[str]:
    """Return exact source subjects already retained one-to-one in inventory.

    The inventory reconciliation receipt is accepted only when its deterministic
    validator reproduces it from current bytes.  Only ``RETAINED`` rows qualify;
    merge/refutation/debt proposals never suppress Gate P.  This keeps ordinary
    delivered findings from consuming the orphan cap without falling back to a
    producer-local ID or location similarity.
    """

    root = Path(scratchpad)
    receipt_path = root / "inventory_reconciliation.json"
    if not receipt_path.is_file():
        return set()
    try:
        from inventory_reconciliation import validate_inventory_reconciliation

        if validate_inventory_reconciliation(root):
            return set()
        payload = json.loads(
            read_bounded_regular_bytes(
                receipt_path, 64 * 1024 * 1024
            ).decode("utf-8")
        )
    except Exception:
        return set()
    if not isinstance(payload, dict):
        return set()
    subjects: set[str] = set()
    for row in payload.get("candidates") or ():
        if not isinstance(row, dict):
            continue
        if (
            row.get("disposition") != "RETAINED"
            or not row.get("target_inventory_id")
        ):
            continue
        source_sha256 = str(row.get("source_sha256") or "").lower()
        record_sha256 = str(row.get("source_block_sha256") or "").lower()
        if not (
            re.fullmatch(r"[0-9a-f]{64}", source_sha256)
            and re.fullmatch(r"[0-9a-f]{64}", record_sha256)
        ):
            continue
        producer_key = str(row.get("producer_key") or "")
        if producer_key.startswith("UNREGISTERED_"):
            producer_key = "UNREGISTERED_MARKDOWN"
        subjects.add(_promo_subject_from_components(
            producer_key=producer_key,
            source_artifact=str(row.get("source_artifact") or ""),
            source_artifact_sha256=source_sha256,
            record_sha256=record_sha256,
            location=str(row.get("source_location") or ""),
            shape="finding_block",
        ))
    return subjects


def _promo_seed_ids(scratchpad: Path) -> tuple[set[str], dict[str, str]]:
    """Parse the preverify promotion seed (or legacy report seed fallback).

    The caller treats a MISSING seed file as the no-op advisory condition
    (mirrors `enumeration_gate._load_graph` returning ``None``): Gate P has no
    reconciliation ledger to check orphans against, so it does not harvest.
    """
    root = Path(scratchpad)
    p = root / "promotion_coverage_seed.md"
    if not p.is_file():
        p = root / "report_index_coverage_seed.md"
    if not p.exists():
        return set(), {}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise OSError(f"promotion coverage seed is unreadable: {exc}") from exc
    ids: set[str] = set()
    verdicts: dict[str, str] = {}
    for line in text.splitlines():
        m = re.match(r"^\|\s*([A-Za-z0-9_\-]+)\s*\|\s*([^|]*)\|\s*([^|]*)\|", line)
        if not m:
            continue
        fid = m.group(1).strip().upper()
        if not fid or not re.search(r"[A-Za-z]", fid) or fid == "FINDING/HYP ID":
            continue
        if re.fullmatch(r"[0-9A-F]{64}", fid):
            continue  # subject table, never a producer-local finding ID
        ids.add(fid)
        verdicts[fid] = m.group(3).strip()
    return ids, verdicts


def _promo_seed_subjects(scratchpad: Path) -> set[str]:
    root = Path(scratchpad)
    path = root / "promotion_coverage_seed.md"
    if not path.is_file():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    return {
        value.lower()
        for value in re.findall(
            r"(?im)^\s*\|\s*([0-9a-f]{64})\s*\|\s*DELIVERED\s*\|\s*$",
            text,
        )
    }


def _promo_covered_locations(scratchpad: Path) -> dict[str, list[tuple[int, int]]]:
    """Parse every ``file:line[-line]`` in ``findings_inventory.md`` ->
    ``{normalized_path: [(lo, hi), ...]}``.

    findings_inventory.md is the CONSOLIDATED promoted set: every reported finding
    traces to an inventory entry carrying a ``**Location**`` field. A harvested feeder
    block whose location overlaps one of these was consolidated under a report ID and
    is therefore NOT a pipeline-loss. This is the location-based reconciliation the
    coverage seed cannot provide (the seed carries hypothesis/report IDs only, no
    locations, and never the raw depth-agent IDs the feeders use). A missing inventory
    is an ordinary empty baseline; an unreadable one raises so the caller can surface
    UNKNOWN instead of producing silent duplicate-orphan noise.
    """
    out: dict[str, list[tuple[int, int]]] = {}
    p = Path(scratchpad) / "findings_inventory.md"
    if not p.exists():
        return out
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise OSError(f"promotion inventory locations are unreadable: {exc}") from exc
    for m in _PROMO_LOC_RE.finditer(text):
        f = m.group(1).strip().strip("`").lower()
        lo = int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        if hi < lo:
            lo, hi = hi, lo
        out.setdefault(f, []).append((lo, hi))
    return out


def _promo_location_is_covered(cand: dict, covered: dict) -> bool:
    """Diagnostic-only location-overlap nomination.

    This helper is not suppression authority. Only a full Gate-P subject may
    establish exact record identity; semantic equivalence belongs downstream.
    """
    if not covered:
        return False
    hay = "\n".join(
        str(cand.get(k, "") or "") for k in ("location", "title", "text")
    )
    for m in _PROMO_LOC_RE.finditer(hay):
        f = m.group(1).strip().strip("`").lower()
        ranges = covered.get(f)
        if not ranges:
            continue
        lo = int(m.group(2))
        hi = int(m.group(3)) if m.group(3) else lo
        if hi < lo:
            lo, hi = hi, lo
        for (clo, chi) in ranges:
            if lo <= chi + _PROMO_LOC_WINDOW and hi >= clo - _PROMO_LOC_WINDOW:
                return True
    return False


def _promo_shape_ok(text: str) -> tuple[bool, str]:
    """Content-shape test: a real location + a mechanism cue + enough text.

    This is the precision gate that keeps bare ID-pattern noise (the v2.8.9
    class of "noise") from ever becoming a harvested candidate — the harvest
    signal is CONTENT shape, not ID-token presence.
    """
    if not text or len(text.strip()) < _PROMO_MIN_TEXT_LEN:
        return False, ""
    # reject methodology / meta / bookkeeping section headers (never a finding)
    first_line = next((ln for ln in text.splitlines() if ln.strip()), "")
    heading_text = re.sub(r"^\s*#{1,6}\s*", "", first_line).strip()
    if _PROMO_META_HEADING_RE.fullmatch(heading_text):
        return False, ""
    # reject blocks that conclude NO issue (no-finding / correct-usage). REFUTED
    # blocks are NOT rejected here — they are real findings that were disproven, and
    # _promo_disposition routes them to Appendix A (excluded), preserving the trail.
    loc_m = _PROMO_LOCATION_RE.search(text)
    if not loc_m:
        return False, ""
    # A producer-authored no-finding/safe statement is a proposal to review,
    # not authority for the found-then-lost recovery gate to suppress it.
    if not _PROMO_MECHANISM_CUE_RE.search(text) and not (
        _PROMO_NEG_DISPOSITION_RE.search(text)
        or _PROMO_REFUTED_RE.search(text)
    ):
        return False, ""
    return True, loc_m.group(0).strip()


_PROMO_HEADING_RE = re.compile(r"^\s*#{2,4}\s+(.*)$")

# Broad, generic bracketed-ID token — deliberately independent of the strict
# internal-ID catalog (`_ID_DEPTH_ALTS` et al. in plamen_parsers.py). That
# catalog is missing several real internal prefixes report-template.md itself
# names as internal (bare `DE-`, `DS-`, `DT-`), so a heading like
# ``## Finding [DE-11]: ...`` silently produces ZERO blocks from
# `_inventory_blocks()` — exactly the "coverage exists but the mechanism
# cannot detect its own non-fulfillment" pipeline-loss class Gate P exists to
# catch. Gate P's harvest is CONTENT-shaped, not ID-pattern-shaped, so its own
# block splitter must not depend on that catalog being complete.
_PROMO_BLOCK_ID_RE = re.compile(r"\[([A-Za-z]{1,10}\d*-\d+)\]")


def _promo_split_heading_blocks(text: str) -> list[dict]:
    """Fence-aware split on level-2/3/4 markdown headings.

    Mirrors `_inventory_blocks`'s fence-awareness (code blocks containing
    markdown-style headings are not treated as finding starts) but extracts
    the heading's bracketed ID token with a broad generic regex instead of
    the strict internal-ID catalog, so it never silently drops a
    finding-shaped block over an unrecognized ID prefix.
    """
    # Keep line endings while slicing. The record is the exact heading block
    # with only outer delimiter whitespace removed; the independent whole-
    # artifact digest still binds line-ending and surrounding-byte changes.
    lines = text.splitlines(keepends=True)
    starts: list[tuple[int, str]] = []
    in_fence = False
    fence_marker: str | None = None
    for idx, exact_line in enumerate(lines):
        line = exact_line.rstrip("\r\n")
        stripped = line.lstrip()
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
        if _PROMO_HEADING_RE.match(line):
            starts.append((idx, line))
    out: list[dict] = []
    for i, (start, heading_line) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(lines)
        record_text = "".join(lines[start:end])
        block = record_text.strip()
        hm = _PROMO_HEADING_RE.match(heading_line.rstrip("\r\n"))
        raw_title = hm.group(1) if hm else heading_line
        idm = _PROMO_BLOCK_ID_RE.search(raw_title)
        orig_id = idm.group(1).strip().upper() if idm else ""
        title = re.sub(r"(?i)^Finding\b\s*", "", raw_title).strip()
        if idm:
            title = title.replace(idm.group(0), "").strip()
        title = re.sub(r"^\s*[:=\-–—#]+\s*", "", title).strip()
        out.append({
            "id": orig_id,
            "title": title,
            "block": block,
        })
    return out


def _promo_harvest_finding_blocks(path: Path, text: str) -> list[dict]:
    """Hiding spot 1: full ``## Finding [ID]: Title`` blocks (depth_* /
    blind_spot_* / analysis_* / *_percontract_* / niche_* etc.) that never
    received a report ID — the "unpromoted feeder block" class."""
    out: list[dict] = []
    try:
        blocks = _promo_split_heading_blocks(text)
    except Exception:
        return out
    for b in blocks:
        block_text = b.get("block", "") or ""
        ok, loc = _promo_shape_ok(block_text)
        if not ok:
            orig_id = (b.get("id") or "").strip().upper()
            first_line = next(
                (line for line in block_text.splitlines() if line.strip()), ""
            )
            heading_text = re.sub(r"^\s*#{1,6}\s*", "", first_line).strip()
            if (
                orig_id
                and len(block_text.strip()) >= _PROMO_MIN_TEXT_LEN
                and not _PROMO_META_HEADING_RE.fullmatch(heading_text)
            ):
                out.append({
                    "source_file": path.name,
                    "shape": "finding_shape_debt",
                    "orig_id": orig_id,
                    "title": b.get("title") or "Unparsed finding candidate",
                    "location": "UNKNOWN",
                    "text": block_text,
                    "shape_debt": True,
                    "proof_scope": "NONE",
                    "requires_independent_consumer": True,
                    "_record_bytes": block_text.encode(
                        "utf-8", errors="surrogatepass"
                    ),
                })
            continue
        location = ""
        try:
            location = (_field_from_markdown(block_text, ("Location", "Locations")) or "").strip()
        except Exception:
            location = ""
        location = location or loc
        out.append({
            "source_file": path.name,
            "shape": "finding_block",
            "orig_id": (b.get("id") or "").strip().upper(),
            "title": b.get("title") or "Untitled finding",
            "location": location,
            "text": block_text,
            "_record_bytes": block_text.encode(
                "utf-8", errors="surrogatepass"
            ),
        })
    return out


def _promo_harvest_table_rows(path: Path, text: str) -> list[dict]:
    """Hiding spot 2: markdown pipe-table rows (checklist cells, summary-table
    rows) that describe a defect inline without their own finding heading."""
    out: list[dict] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        stripped_chars = set(s.replace("|", "").strip())
        if not stripped_chars or stripped_chars <= {"-", ":", " "}:
            continue  # table separator row
        ok, loc = _promo_shape_ok(s)
        if not ok:
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        orig_id = ""
        if cells:
            idm = _PROMO_ID_TOKEN_RE.match(cells[0])
            if idm:
                orig_id = idm.group(1).strip().upper()
        # Title: prefer the cell carrying the mechanism/harm prose (not the
        # bare ID cell or the location cell, so Location doesn't get echoed
        # into Title AND Description on emission). Falls back to the whole
        # row if no cell independently matches the mechanism cue.
        title_cell = ""
        for c in cells:
            if _PROMO_LOCATION_RE.fullmatch(c.strip()):
                continue  # skip a cell that IS just the location
            if _PROMO_MECHANISM_CUE_RE.search(c):
                title_cell = c
                break
        if not title_cell:
            candidates = [c for c in cells if not _PROMO_LOCATION_RE.fullmatch(c.strip())]
            title_cell = max(candidates, key=len) if candidates else s
        out.append({
            "source_file": path.name,
            "shape": "table_row",
            "orig_id": orig_id,
            "title": _strip_md(title_cell)[:120],
            "location": loc,
            "text": s,
            # `desc`: the mechanism/harm cell alone, WITHOUT the location
            # cell — used for the emitted Description so the harvested
            # location is not echoed twice (once in **Location**, again
            # inside a raw-row **Description**). `text` (the full row) is
            # kept for classification/hashing, which benefit from full
            # context.
            "desc": title_cell,
            "_record_bytes": line.encode("utf-8", errors="surrogatepass"),
        })
    return out


def _promo_harvest_excluded_stubs(path: Path, text: str) -> list[dict]:
    """Hiding spot 3: referent-less ``EXCLUDED [ID] ...`` exclusion stubs
    (the orchestrator-rules.md per-cluster exclusion format). A stub citing a
    real "dup of X-NN" referent is a legitimate dedup — skipped. Only
    REFERENT-LESS stubs are candidates: content-bearing ones (own location +
    mechanism/harm) are harvested normally; content-less ones ("already
    known" with no location) are still harvested (never dropped) but flagged
    so the router sends them to human review, not the body."""
    out: list[dict] = []
    for m in _PROMO_EXCLUDED_STUB_RE.finditer(text):
        stub_id = m.group(1).strip()
        rest = (m.group(2) or "").strip()
        alias_match = _PROMO_DUP_REFERENT_ID_RE.search(rest)
        ok, loc = _promo_shape_ok(rest)
        out.append({
            "source_file": path.name,
            "shape": "excluded_stub",
            "orig_id": stub_id.strip().upper(),
            "title": (rest[:120] if rest else f"Referent-less exclusion {stub_id}"),
            "location": loc,
            "text": rest,
            "content_bearing": ok,
            "alias_proposal": bool(alias_match),
            "alias_target": alias_match.group(1).upper() if alias_match else "",
            "_record_bytes": m.group(0).encode(
                "utf-8", errors="surrogatepass"
            ),
        })
    return out


def _promo_harvest_registered_typed_actions(path: Path) -> list[dict]:
    """Adapt typed generator actions directly; never round-trip through Markdown."""

    out: list[dict] = []
    producer = _registered_producer_for_artifact(
        path.name, consumer="late_harvest"
    )
    if producer is not None and getattr(producer, "action_contract", "") == (
        "ENUMERATION_OBLIGATION"
    ):
        for obligation in _read_registered_enumeration_obligations(
            path, consumer="late_harvest"
        ):
            candidate = {
                "source_file": path.name,
                "shape": "typed_enumeration_obligation",
                "orig_id": obligation.action_id,
                "action_identity": obligation.action_identity,
                "source_identity": f"{path.name}:{obligation.action_identity}",
                "title": f"Unresolved exploration obligation {obligation.action_id}",
                "location": "",
                "text": "",
                "desc": "",
                "proof_scope": "NONE",
                "requires_independent_consumer": True,
            }
            candidate["_record_bytes"] = json.dumps(
                asdict(obligation),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            out.append(candidate)
        return out
    for action in _read_registered_typed_actions(path, consumer="late_harvest"):
        text = "\n".join(
            value for value in (action.evidence, action.rationale) if value
        )
        location_match = _PROMO_LOCATION_RE.search(text)
        candidate = {
            "source_file": path.name,
            "shape": "typed_generator_action",
            "orig_id": action.action_id,
            "action_identity": action.action_identity,
            "source_identity": f"{path.name}:{action.action_identity}",
            "title": (
                f"Exploration additive action: {action.instance}"
                if action.instance
                else f"Exploration additive action {action.action_id}"
            ),
            "location": location_match.group(0).strip() if location_match else "",
            "text": text,
            "desc": text,
            "proof_scope": action.proof_scope,
            "requires_independent_consumer": True,
        }
        candidate["_record_bytes"] = json.dumps(
            asdict(action),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        out.append(candidate)
    return out


def _promo_disposition(cand: dict) -> tuple[str, str]:
    """Return BODY plus the retention reason for one harvested candidate.

    Material-harm and producer-negative classifications are proposal evidence
    only: without replayable terminal authority, every active path is reopened
    for independent verification rather than routed to an appendix.
    """
    text = cand.get("text", "") or ""
    title = cand.get("title", "") or ""
    if cand.get("shape") == "typed_generator_action":
        return (
            "BODY",
            "typed unverified generator output routed to independent verification",
        )
    if cand.get("shape") == "typed_enumeration_obligation":
        return (
            "BODY",
            "unresolved enumeration work lacks completion authority; retained "
            "for independent review",
        )
    if cand.get("alias_proposal"):
        return (
            "BODY",
            "textual alias proposal lacks applied lossless-equivalence authority; "
            "retained for verification",
        )
    if cand.get("shape") == "excluded_stub" and not cand.get("content_bearing", True):
        cand["shape_debt"] = True
        return (
            "BODY",
            "content-less exclusion lacks terminal authority; retained as "
            "verification and human-review debt",
        )
    if cand.get("shape_debt"):
        return (
            "BODY",
            "candidate identity failed heuristic shape parsing; retained as "
            "location/methodology repair debt",
        )
    negative_text = f"{title}\n{text}"
    if (
        _PROMO_REFUTED_RE.search(negative_text)
        or _PROMO_NEG_DISPOSITION_RE.search(negative_text)
    ):
        cand["negative_proposal"] = True
        cand["negative_proposal_kind"] = "REFUTATION_PROPOSAL"
        return (
            "BODY",
            "producer negative proposal lacks replayable terminal authority; "
            "reopened for independent verification",
        )
    verdict = ""
    try:
        verdict = _field_from_markdown(text, ("Verdict", "Final Verdict", "Status"))
    except Exception:
        verdict = ""
    if verdict and re.search(r"(?i)refut|false.?positive", verdict):
        cand["negative_proposal"] = True
        cand["negative_proposal_kind"] = "REFUTATION_PROPOSAL"
        return (
            "BODY",
            "structured negative proposal lacks replayable terminal authority; "
            "reopened for independent verification",
        )
    try:
        disp, reason = classify_body_or_appendix(title, "", text, verdict)
    except Exception:
        disp, reason = ("BODY", "default (classifier error — recall-safe)")
    if disp == "APPENDIX":
        cand["zero_harm_proposal"] = True
        return (
            "BODY",
            "zero-harm classifier proposal lacks typed terminal authority; "
            f"retained for verification ({reason})",
        )
    return ("BODY", reason)


def _write_promotion_orphans_md(
    scratchpad: Path, orphans: list[dict], already_tracked: int, files_scanned: int
) -> None:
    lines = [
        "# Promotion Orphans (Gate P harvest)",
        "",
        "Content-shaped harvest of finding-SHAPED blocks (location + mechanism "
        "+ harm) across feeder artifacts that never received a report ID. Each "
        "row is routed through the existing material-harm classifier, never "
        "promoted to body-at-severity directly. Recall-safe: nothing harvested "
        "here is dropped.",
        "",
        f"- Files scanned: {files_scanned} | Exact delivered/repeated subjects "
        f"excluded: {already_tracked} | Orphans: "
        f"{len(orphans)}",
        "",
        "| Candidate | Subject SHA256 | Source | Shape | Orig ID | Location | Disposition | Reason |",
        "|-----------|----------------|--------|-------|---------|----------|--------------|--------|",
    ]
    for c in orphans:
        title = re.sub(r"\s+", " ", c.get("title", "")).replace("|", "/").strip()[:80]
        reason = re.sub(r"\s+", " ", c.get("reason", "")).replace("|", "/").strip()
        loc = (c.get("location") or "-").replace("|", "/")
        lines.append(
            f"| {c['candidate_id']} | `{c.get('subject_sha256', '')}` | "
            f"{c['source_file']} | {c['shape']} | "
            f"{c.get('orig_id', '') or '-'} | `{loc}` | "
            f"{c.get('disposition', '')} | {title} — {reason} |"
        )
    if not orphans:
        lines.append("| (none) | | | | | | | no orphans found |")
    try:
        (scratchpad / "promotion_orphans.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        log.warning(f"[promotion-gate] write promotion_orphans.md failed: {exc!r}")


def compute_promotion_orphans(scratchpad: Path) -> list[dict]:
    """Gate P harvest + reconcile (content-shaped, NOT ID-pattern).

    Scans every feeder artifact (`depth_*`, `blind_spot_*`, `analysis_*`,
    `*_percontract_*`, checklists, exclusion stubs) for finding-SHAPED
    content — a real `file:Lnnn` location + a generic defect-mechanism cue +
    enough descriptive text. Each extracted record receives a full SHA-256
    subject bound to producer, source-artifact bytes, record bytes, location,
    and shape. Producer-local IDs and location/shape similarity are never
    suppression authority. Exact repeated subjects alone are collapsed;
    every other candidate is classified BODY / APPENDIX_C / APPENDIX_A and
    written to `promotion_orphans.md`.

    No-op advisory when `report_index_coverage_seed.md` is absent (mirrors
    `enumeration_gate.py`'s graph-absent no-op) — recall-safe: nothing is
    silently dropped, the gate simply has not run yet. Bounded (per-file and
    per-run caps) so it can never flood. Never raises.
    """
    scratchpad = Path(scratchpad)
    seed_path = scratchpad / "promotion_coverage_seed.md"
    if not seed_path.exists():
        seed_path = scratchpad / "report_index_coverage_seed.md"
    if not seed_path.exists():
        try:
            replace_producer_shortfalls(
                scratchpad,
                "promotion_gate",
                [unknown_shortfall(
                    producer="promotion_gate",
                    scope="promotion-provider",
                    kind="PROVIDER_UNAVAILABLE",
                    detail=(
                        "promotion completeness cannot reconcile without "
                        "promotion_coverage_seed.md or report_index_coverage_seed.md"
                    ),
                )],
            )
        except Exception:
            pass
        return []
    cap_rows: list[dict] = []
    try:
        # The seed proves phase readiness, not record identity.  Its local IDs
        # are deliberately never used as suppression authority.
        _seed_ids, _seed_verdicts = _promo_seed_ids(scratchpad)
        # The seed contains prior Gate-P delivery subjects.  Ordinary raw
        # discoveries that the exact inventory reconciliation already proves
        # were retained one-to-one must join the same denominator; otherwise
        # Gate P re-harvests already-delivered findings and can spend its
        # bounded orphan budget on duplicates.  Only a currently replayable
        # RETAINED row contributes here.
        delivered_subjects = (
            _promo_seed_subjects(scratchpad)
            | promotion_reconciled_subjects(scratchpad)
        )
    except Exception as exc:
        try:
            replace_producer_shortfalls(
                scratchpad,
                "promotion_gate",
                [unknown_shortfall(
                    producer="promotion_gate",
                    scope="promotion-seed",
                    kind="PROVIDER_FAILED",
                    detail=(
                        "promotion completeness could not read its reconciliation "
                        f"seed ({type(exc).__name__})"
                    ),
                    samples=[seed_path.name],
                )],
            )
        except Exception:
            pass
        return []
    # Read inventory locations only as non-authoritative diagnostic telemetry.
    # Location overlap never suppresses a candidate; semantic dedup downstream
    # decides equivalence after Gate P has delivered the stable subject.
    try:
        covered_locs = _promo_covered_locations(scratchpad)
    except Exception as exc:
        covered_locs = {}
        cap_rows.append(unknown_shortfall(
            producer="promotion_gate",
            scope="inventory-location-reconciliation",
            kind="PROVIDER_FAILED",
            detail=(
                "promoted-location reconciliation could not read inventory; "
                f"orphan harvest continued recall-safely ({type(exc).__name__})"
            ),
            samples=["findings_inventory.md"],
        ))

    files: list[Path] = []
    seen_paths: set[Path] = set()
    for pat in _PROMO_FEEDER_GLOBS:
        try:
            for p in sorted(scratchpad.glob(pat)):
                if p.name in _PROMO_EXCLUDE_NAMES or p in seen_paths or not p.is_file():
                    continue
                seen_paths.add(p)
                files.append(p)
        except Exception as exc:
            cap_rows.append(unknown_shortfall(
                producer="promotion_gate",
                scope=f"feeder-discovery:{pat}",
                kind="PROVIDER_FAILED",
                detail=(
                    "promotion feeder discovery failed for one configured pattern "
                    f"({type(exc).__name__})"
                ),
            ))
            continue
    # Glob declaration order and filesystem enumeration order are not part of
    # the result. Canonicalize before bounded caps and candidate numbering.
    all_files = sorted(
        seen_paths,
        key=lambda item: (item.name.casefold(), item.name),
    )
    files = all_files[:_PROMO_MAX_FILES]
    if len(all_files) > _PROMO_MAX_FILES:
        cap_rows.append(shortfall(
            producer="promotion_gate",
            scope="feeder-files",
            cap="PROMO_MAX_FILES",
            limit=_PROMO_MAX_FILES,
            observed=len(all_files),
            retained=len(files),
            exact=True,
            samples=[p.name for p in all_files[_PROMO_MAX_FILES:]],
            detail="promotion-gate feeder artifacts were not scanned",
        ))

    orphans: list[dict] = []
    already_tracked = 0
    seen_subjects: set[str] = set()  # exact-subject dedup across harvesters
    run_cap_seen = False
    for p in files:
        try:
            registered = _registered_producer_for_artifact(
                p.name, consumer="late_harvest"
            )
        except ProducerResolutionError:
            registered = None
        try:
            source_bytes = read_bounded_regular_bytes(p, 64 * 1024 * 1024)
        except Exception as exc:
            cap_rows.append(unknown_shortfall(
                producer="promotion_gate",
                scope=f"feeder:{p.name}",
                kind="PROVIDER_FAILED",
                detail=(
                    "promotion feeder exact bytes could not be read and were not "
                    f"harvested ({type(exc).__name__})"
                ),
                samples=[p.name],
            ))
            continue
        source_artifact_sha256 = hashlib.sha256(source_bytes).hexdigest()
        producer_key = str(
            getattr(registered, "key", "") or "UNREGISTERED_MARKDOWN"
        )
        if registered is not None and getattr(
            registered, "artifact_format", "MARKDOWN_FINDINGS"
        ) != "MARKDOWN_FINDINGS":
            try:
                harvested = _promo_harvest_registered_typed_actions(p)
            except Exception as exc:
                cap_rows.append(unknown_shortfall(
                    producer="promotion_gate",
                    scope=f"feeder:{p.name}:typed-adapter",
                    kind="PROVIDER_FAILED",
                    detail=(
                        "typed promotion feeder could not be validated "
                        f"({type(exc).__name__})"
                    ),
                    samples=[p.name],
                ))
                continue
            text = ""
        else:
            harvested = []
        try:
            if registered is None or getattr(
                registered, "artifact_format", "MARKDOWN_FINDINGS"
            ) == "MARKDOWN_FINDINGS":
                text = source_bytes.decode("utf-8", errors="replace")
        except Exception as exc:
            cap_rows.append(unknown_shortfall(
                producer="promotion_gate",
                scope=f"feeder:{p.name}",
                kind="PROVIDER_FAILED",
                detail=(
                    "promotion feeder could not be read and was not harvested "
                    f"({type(exc).__name__})"
                ),
                samples=[p.name],
            ))
            continue
        harvest_failed = False
        if registered is None or getattr(
            registered, "artifact_format", "MARKDOWN_FINDINGS"
        ) == "MARKDOWN_FINDINGS":
            try:
                harvested.extend(_promo_harvest_finding_blocks(p, text))
            except Exception:
                harvest_failed = True
            try:
                harvested.extend(_promo_harvest_table_rows(p, text))
            except Exception:
                harvest_failed = True
            try:
                harvested.extend(_promo_harvest_excluded_stubs(p, text))
            except Exception:
                harvest_failed = True
        if harvest_failed:
            cap_rows.append(unknown_shortfall(
                producer="promotion_gate",
                scope=f"feeder:{p.name}:harvest",
                kind="PROVIDER_FAILED",
                detail="one or more promotion feeder harvesters failed",
                samples=[p.name],
            ))
        for cand in harvested:
            _promo_bind_subject_identity(
                cand,
                source_artifact_sha256=source_artifact_sha256,
                producer_key=producer_key,
            )
        harvested.sort(key=lambda cand: cand["subject_sha256"])

        per_file = 0
        for cand_idx, cand in enumerate(harvested):
            subject = cand["subject_sha256"]
            if subject in delivered_subjects:
                already_tracked += 1
                continue
            if subject in seen_subjects:
                already_tracked += 1
                continue
            # Only an ELIGIBLE, untracked, uncovered, non-duplicate orphan can
            # prove the orphan budget overflowed. Raw candidate-shaped rows do
            # not inflate the omission denominator.
            if per_file >= _PROMO_MAX_PER_FILE:
                cap_rows.append(shortfall(
                    producer="promotion_gate",
                    scope=f"feeder:{p.name}",
                    cap="PROMO_MAX_PER_FILE",
                    limit=_PROMO_MAX_PER_FILE,
                    observed=per_file + 1,
                    retained=per_file,
                    exact=False,
                    samples=[cand.get("orig_id") or cand.get("title") or ""],
                    detail=("eligible promotion orphans exceeded the per-file budget; "
                            "additional eligible orphans may exist"),
                ))
                break
            if len(orphans) >= _PROMO_MAX_PER_RUN:
                if not run_cap_seen:
                    cap_rows.append(shortfall(
                        producer="promotion_gate",
                        scope="orphan-harvest",
                        cap="PROMO_MAX_PER_RUN",
                        limit=_PROMO_MAX_PER_RUN,
                        observed=len(orphans) + 1,
                        retained=len(orphans),
                        exact=False,
                        samples=[cand.get("orig_id") or cand.get("title") or ""],
                        detail=("eligible promotion orphans exceeded the global budget; "
                                "additional eligible orphans may exist"),
                    ))
                    run_cap_seen = True
                break
            seen_subjects.add(subject)
            try:
                disp, reason = _promo_disposition(cand)
            except Exception:
                disp, reason = ("BODY", "default (routing error — recall-safe)")
            cand["disposition"] = disp
            cand["reason"] = reason
            orphans.append(cand)
            per_file += 1
        if run_cap_seen:
            break

    try:
        replace_producer_shortfalls(scratchpad, "promotion_gate", cap_rows)
    except Exception:
        # Gate P remains haltless; failure to write telemetry cannot suppress
        # the bounded harvest itself.
        pass

    for i, cand in enumerate(orphans, start=1):
        cand["candidate_id"] = f"PROMO-{i:03d}"

    try:
        _write_promotion_orphans_md(scratchpad, orphans, already_tracked, len(files))
    except Exception as exc:
        log.warning(f"[promotion-gate] harvest ledger write failed: {exc!r}")
    return orphans


def _write_promotion_routing_md(
    scratchpad: Path, body_cands: list[dict], appc_rows: list[dict], appa_rows: list[dict]
) -> None:
    lines = [
        "# Promotion Routing (Gate P)",
        "",
        "Accounting receipt for how each harvested orphan was routed. BODY -> "
        "appended to findings_inventory.md as a NEEDS_VERIFICATION candidate "
        "(never body-at-severity directly). APPENDIX_C -> quality/hardening "
        "staging (zero security consequence). APPENDIX_A -> verifier-refuted "
        "or referent-less/content-less staging (human review, never dropped).",
        "",
        f"- BODY candidates: {len(body_cands)} | Appendix C: {len(appc_rows)} "
        f"| Appendix A: {len(appa_rows)}",
        "",
        "| Candidate | Source | Shape | Destination | Reason |",
        "|-----------|--------|-------|-------------|--------|",
    ]
    for label, rows in (
        ("BODY -> findings_inventory.md (NEEDS_VERIFICATION)", body_cands),
        ("APPENDIX_C -> promotion_orphans_appendix_c.md", appc_rows),
        ("APPENDIX_A -> promotion_orphans_appendix_a.md", appa_rows),
    ):
        for c in rows:
            reason = re.sub(r"\s+", " ", c.get("reason", "")).replace("|", "/").strip()
            lines.append(
                f"| {c['candidate_id']} | {c['source_file']} | {c['shape']} | "
                f"{label} | {reason} |"
            )
    if not (body_cands or appc_rows or appa_rows):
        lines.append("| (none) | | | | no candidates routed |")
    try:
        (scratchpad / "promotion_routing.md").write_text(
            "\n".join(lines) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        log.warning(f"[promotion-gate] write promotion_routing.md failed: {exc!r}")


def _write_promotion_appendix_staging(
    scratchpad: Path, appc_rows: list[dict], appa_rows: list[dict]
) -> None:
    def _fmt_rows(rows: list[dict]) -> list[str]:
        out = []
        for c in rows:
            title = re.sub(r"\s+", " ", c.get("title", "")).replace("|", "/").strip()[:100]
            reason = re.sub(r"\s+", " ", c.get("reason", "")).replace("|", "/").strip()
            loc = (c.get("location") or "-").replace("|", "/")
            out.append(f"| {c['candidate_id']} | {title} | `{loc}` | {reason} |")
        return out

    c_lines = [
        "# Promotion Gate — Appendix C Staging (Quality & Hardening)",
        "",
        "Content-shaped orphans classified as zero-security-consequence (pure "
        "quality / hardening / observability). Staged here for the "
        "driver-owned report assembly to merge into Appendix C — never a "
        "body finding.",
        "",
        "| Candidate | Title | Location | Reason |",
        "|-----------|-------|----------|--------|",
    ]
    c_lines.extend(_fmt_rows(appc_rows) or ["| (none) | | | no candidates |"])

    a_lines = [
        "# Promotion Gate — Appendix A Staging (Excluded / Human Review)",
        "",
        "Content-shaped orphans that are either verifier-refuted or "
        "referent-less exclusion stubs with no recoverable content. Staged "
        "here for the driver-owned report assembly to merge into Appendix A "
        "— never dropped, flagged for human review when content-less.",
        "",
        "| Candidate | Title | Location | Reason |",
        "|-----------|-------|----------|--------|",
    ]
    a_lines.extend(_fmt_rows(appa_rows) or ["| (none) | | | no candidates |"])

    try:
        (scratchpad / "promotion_orphans_appendix_c.md").write_text(
            "\n".join(c_lines) + "\n", encoding="utf-8"
        )
        (scratchpad / "promotion_orphans_appendix_a.md").write_text(
            "\n".join(a_lines) + "\n", encoding="utf-8"
        )
    except Exception as exc:
        log.warning(f"[promotion-gate] appendix staging write failed: {exc!r}")


def _append_inventory_blocks(inv_text: str, header: str, lines: list[str]) -> str:
    """Pure text-append primitive for `findings_inventory.md`.

    Appends an optional section `header` (only non-empty on the FIRST call
    that introduces the PROMOGAP section — the caller already checks whether
    the header text is present) followed by the given finding-block `lines`
    (already flattened: one list entry per markdown line, each candidate's
    lines ending with a blank-line separator).

    This function performs NO dedup of its own — the caller
    (`route_promotion_orphans`) is responsible for excluding already-emitted
    candidates via the receipt before building `lines`, so calling this twice
    with an empty `lines` list is a safe no-op-shaped append (idempotency is
    enforced upstream, not here).
    """
    text = inv_text or ""
    if header:
        text += (
            header
            if header.startswith("\n")
            else ("\n\n" + header.lstrip("\n"))
        )
    else:
        text += "\n\n"
    body = "\n".join(lines).rstrip("\n")
    if body:
        text += body
    return text if text.endswith("\n") else text + "\n"


def route_promotion_orphans(scratchpad: Path, orphans: "list[dict] | None" = None) -> dict:
    """Gate P routing: disposition-router for harvested promotion orphans.

    BODY-disposed orphans are appended to `findings_inventory.md` as
    NEEDS_VERIFICATION candidates (never body-at-severity directly — the
    existing verify-the-positives pipeline adjudicates before anything can
    reach the report body). APPENDIX_C / APPENDIX_A orphans are staged into
    dedicated ledgers (`promotion_orphans_appendix_c.md` /
    `promotion_orphans_appendix_a.md`) for the driver-owned report assembly
    to merge — this function never writes AUDIT_REPORT.md itself.

    Idempotent: the `findings_inventory.md` append is gated by a dedicated
    receipt (`promotion_gate_receipt.md`) keyed on a content hash of each
    candidate, so a second call on unchanged feeder artifacts appends
    nothing new. The staging ledgers are deterministic snapshots of the
    current harvest, so they are naturally idempotent (same input -> same
    output) without a receipt. Never raises; a failure at any step degrades
    to the next step running with what succeeded.
    """
    scratchpad = Path(scratchpad)
    if orphans is None:
        try:
            orphans = compute_promotion_orphans(scratchpad)
        except Exception:
            orphans = []
    orphans = orphans or []
    result = {
        "harvested": len(orphans),
        "body_candidates": 0,
        "appendix_c": 0,
        "appendix_a": 0,
        "emitted_to_inventory": 0,
    }
    if not orphans:
        try:
            _write_promotion_routing_md(scratchpad, [], [], [])
            _write_promotion_appendix_staging(scratchpad, [], [])
        except Exception:
            pass
        return result

    receipt_path = scratchpad / "promotion_gate_receipt.md"
    seen: set[str] = set()
    if receipt_path.exists():
        try:
            seen.update(_PROMO_RECEIPT_SUBJECT_RE.findall(
                receipt_path.read_text(encoding="utf-8", errors="replace"),
            ))
        except Exception:
            pass
    # Crash recovery does not depend on receipt publication: the canonical
    # inventory carries the same subject.  If the process dies after the
    # atomic inventory replace but before receipt replace, resume still sees
    # the completed append and cannot duplicate it.
    inventory_path = scratchpad / "findings_inventory.md"
    if inventory_path.exists():
        try:
            seen.update(_PROMO_SUBJECT_FIELD_RE.findall(
                inventory_path.read_bytes().decode(
                    "utf-8", errors="replace"
                )
            ))
        except Exception:
            pass

    body_cands: list[dict] = []
    all_body: list[dict] = []
    pending_body_subjects: set[str] = set()
    appc_rows: list[dict] = []
    appa_rows: list[dict] = []
    for cand in orphans:
        disp = cand.get("disposition", "BODY")
        subject = str(cand.get("subject_sha256", "") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", subject):
            # Caller-supplied candidates still receive the same canonical
            # identity contract; an absent source digest remains explicit.
            subject = _promo_bind_subject_identity(
                cand,
                source_artifact_sha256=str(
                    cand.get("source_artifact_sha256", "")
                    or hashlib.sha256(b"").hexdigest()
                ),
                producer_key=str(
                    cand.get("producer_key", "") or "UNREGISTERED_MARKDOWN"
                ),
            )
        cand["_promo_key"] = subject
        if disp == "BODY":
            all_body.append(cand)
            if (
                cand["_promo_key"] not in seen
                and cand["_promo_key"] not in pending_body_subjects
            ):
                body_cands.append(cand)
                pending_body_subjects.add(cand["_promo_key"])
        elif disp == "APPENDIX_C":
            appc_rows.append(cand)
        else:
            appa_rows.append(cand)
    result["body_candidates"] = len(all_body)
    result["appendix_c"] = len(appc_rows)
    result["appendix_a"] = len(appa_rows)

    if body_cands:
        inv_path = inventory_path
        if inv_path.exists():
            try:
                inv_text = inv_path.read_bytes().decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                inv_text = None
            if inv_text is not None:
                max_inv = 0
                for m in re.finditer(r"\bINV-(\d+)\b", inv_text):
                    try:
                        max_inv = max(max_inv, int(m.group(1)))
                    except ValueError:
                        pass
                appended_lines: list[str] = []
                new_keys: list[str] = []
                for idx, cand in enumerate(body_cands, start=1):
                    inv_n = max_inv + idx
                    title = cand.get("title") or "Untitled promotion-gap finding"
                    try:
                        inv_id = _allocate_inventory_ledger_id(
                            scratchpad, preferred_id=f"INV-{inv_n:03d}",
                            owner_phase="promotion_gate",
                            owning_artifact="findings_inventory.md", title=title,
                        )
                    except Exception:
                        inv_id = f"INV-{inv_n:03d}"
                    try:
                        sev = _severity_name_from_text(cand.get("text", ""), {})
                    except Exception:
                        sev = "Medium"
                    loc = cand.get("location") or "UNKNOWN"
                    if cand.get("shape") == "typed_generator_action":
                        source_lines = [
                            f"**Source IDs**: [{cand.get('orig_id', '')}]",
                            f"**Primary Artifact**: {cand.get('source_file', '')}",
                            f"**Source Identity**: {cand.get('source_identity', '')}",
                            "**Proof Scope**: UNVERIFIED_GENERATOR_OUTPUT",
                            "**Effective Proof Scope**: ANALYTICAL",
                            "**Effective Harm Scope**: UNPROVEN",
                        ]
                    else:
                        source_lines = [
                            f"**Source IDs**: PROMOGAP ({cand.get('shape','')} orphan "
                            f"from {cand.get('source_file','')}; content-shaped "
                            "promotion-completeness gap — mechanically harvested, "
                            "verifier to confirm or refute)"
                        ]
                    if cand.get("negative_proposal"):
                        source_lines.extend([
                            "**Negative Proposal**: REFUTATION_PROPOSAL "
                            "(non-authoritative producer assessment)",
                            "**Mandatory Verification**: true",
                        ])
                    if cand.get("zero_harm_proposal"):
                        source_lines.extend([
                            "**Zero-Harm Proposal**: NONTERMINAL_CLASSIFIER_PROPOSAL",
                            "**Mandatory Verification**: true",
                        ])
                    if cand.get("alias_proposal"):
                        source_lines.extend([
                            f"**Alias Proposal**: {cand.get('alias_target') or 'UNRESOLVED'} "
                            "(no applied equivalence authority)",
                            "**Mandatory Verification**: true",
                        ])
                    if cand.get("shape_debt"):
                        source_lines.extend([
                            "**Promotion Shape Debt**: unresolved location or "
                            "mechanism encoding",
                            "**Mandatory Verification**: true",
                        ])
                    appended_lines.extend([
                        f"### Finding [{inv_id}]: {title}",
                        f"**Severity**: {sev}",
                        f"**Location**: `{loc}`",
                        f"**Promotion Subject SHA256**: {cand['subject_sha256']}",
                        f"**Promotion Source Artifact SHA256**: "
                        f"{cand['source_artifact_sha256']}",
                        f"**Promotion Record SHA256**: {cand['record_sha256']}",
                        f"**Promotion Producer**: {cand['producer_key']}",
                        "**Preferred Tag**: [CODE-TRACE]",
                        *source_lines,
                        "**Verdict**: NEEDS_VERIFICATION",
                        f"**Root Cause**: {cand.get('reason', '')}",
                        f"**Description**: {_strip_md(cand.get('desc') or cand.get('text', ''))[:1200]}",
                        "**Impact**: Potential unpromoted finding recovered from "
                        "a feeder artifact (verifier to confirm the concrete harm).",
                        "",
                    ])
                    new_keys.append(cand["_promo_key"])
                if appended_lines:
                    header = (
                        "\n\n## Promotion-Completeness Candidates (PROMOGAP)\n\n"
                        "Mechanically-harvested finding-shaped content (checklist "
                        "cells, summary-table rows, referent-less exclusion "
                        "stubs, unpromoted feeder findings) that never received "
                        "a report ID. Low-confidence by construction — the "
                        "verify phase confirms or refutes each. Recall-safe: "
                        "append-only.\n\n"
                    )
                    hdr = (
                        "" if "Promotion-Completeness Candidates (PROMOGAP)" in inv_text
                        else header
                    )
                    try:
                        _promo_atomic_write_text(
                            inv_path,
                            _append_inventory_blocks(inv_text, hdr, appended_lines),
                        )
                        result["emitted_to_inventory"] = len(new_keys)
                        seen.update(new_keys)
                    except Exception as exc:
                        log.warning(f"[promotion-gate] inventory append failed: {exc!r}")
                    try:
                        _write_finding_records_from_inventory(scratchpad)
                    except Exception:
                        pass

    if seen:
        try:
            rlines = [
                "# Promotion Gate Receipt",
                "",
                "**Schema**: plamen.gate_p.receipt.v2",
                "",
            ]
            rlines += [
                f"PROMOGAP-SUBJECT-SHA256: {subject}"
                for subject in sorted(seen)
            ]
            _promo_atomic_write_text(receipt_path, "\n".join(rlines) + "\n")
        except Exception as exc:
            # Inventory subjects are the crash-safe authority; the receipt is
            # a deterministic projection and may be reconstructed on resume.
            log.warning(f"[promotion-gate] receipt write failed: {exc!r}")

    try:
        _write_promotion_routing_md(scratchpad, all_body, appc_rows, appa_rows)
        _write_promotion_appendix_staging(scratchpad, appc_rows, appa_rows)
    except Exception as exc:
        log.warning(f"[promotion-gate] ledger write failed: {exc!r}")

    return result


_REPORT_DEDUP_AGENT_ID_RE = re.compile(r"\b([CHMLI]-\d{1,3})\b")


def _parse_report_dedup_agent_decisions(
    scratchpad: Path,
) -> tuple[list[tuple[str, str]], set[str]]:
    """Parse the report_dedup_agent proposal file into machine inputs.

    Returns ``(merge_pairs, qo_ids)``:
      - ``merge_pairs``: list of (survivor_report_id, absorbed_report_id) from
        the `## MERGE Decisions` table (rows whose `Same Root Cause` cell is YES;
        defaults to accepting a row when that column is absent).
      - ``qo_ids``: set of report IDs from the `## Quality Observation
        Reclassifications` table.

    Defensive by construction: any read/parse failure returns empties so the
    caller falls back to a mechanical-only pass (report_dedup is critical=False;
    the agent proposal is advisory, never load-bearing). Self-merges and
    duplicate absorbed IDs are dropped here so the downstream merge loop never
    sees a contradictory proposal.
    """
    path = scratchpad / "report_dedup_agent_decisions.md"
    if not path.exists():
        return [], set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        log.warning(f"[report_dedup] agent decisions read failed: {exc!r}")
        return [], set()

    def _section(key: str) -> str:
        # Body of the FIRST H2 whose title CONTAINS `key` (case-insensitive,
        # format-tolerant), up to the next H2. The LLM phrases headers loosely
        # ("Quality Observation Reclassification Decisions" vs ".Reclassifications")
        # and adds sub-tables; matching on a substring of the H2 title — not an
        # exact name — stops the whole agent proposal from being silently dropped.
        m = re.search(
            r"(?ims)^##\s+[^\n]*" + re.escape(key) + r"[^\n]*\n(.*?)(?=^##\s+|\Z)", text
        )
        return m.group(1) if m else ""

    def _row_ids(line: str) -> list[str]:
        # Report IDs in the row, in order, de-duplicated. COLUMN-AGNOSTIC: the
        # agent's table layout varies ("Survivor ID | Survivor Title | Absorbed
        # IDs | ..." vs "Survivor | Absorbed | ..."), so we never assume a
        # column index — first ID = survivor, every later ID = an absorbed.
        out: list[str] = []
        seen: set[str] = set()
        for mm in _REPORT_DEDUP_AGENT_ID_RE.finditer(line):
            v = mm.group(1).upper()
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    merge_pairs: list[tuple[str, str]] = []
    seen_absorbed: set[str] = set()
    seen_survivor: set[str] = set()
    for line in _section("MERGE").splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        # A standalone "NO" cell (Same Root Cause = NO) vetoes the row.
        if any(re.fullmatch(r"(?i)no", c or "") for c in cells):
            continue
        ids = _row_ids(s)
        if len(ids) < 2:   # header rows / prose carry < 2 report IDs
            continue
        survivor = ids[0]
        for absorbed in ids[1:]:
            if absorbed == survivor:
                continue
            # one absorbed -> one survivor; an absorbed can't also be a survivor
            if absorbed in seen_absorbed or absorbed in seen_survivor:
                continue
            if survivor in seen_absorbed:
                continue
            seen_absorbed.add(absorbed)
            seen_survivor.add(survivor)
            merge_pairs.append((survivor, absorbed))

    qo_ids: set[str] = set()
    merged = seen_absorbed | seen_survivor
    for line in _section("Quality Observation").splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        # QO id is the FIRST cell of a table row (not any ID mentioned in prose/
        # justification) — first-cell-only avoids pulling cross-referenced IDs.
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells:
            continue
        m = _REPORT_DEDUP_AGENT_ID_RE.search(cells[0])
        if m and m.group(1).upper() not in merged:  # never QO an already-merged id
            qo_ids.add(m.group(1).upper())

    return merge_pairs, qo_ids


def _report_dedup_candidate_pairs_from_hint(scratchpad: Path) -> list[tuple[str, str]]:
    """Extract the (report_id_A, report_id_B) pairs from the driver-computed
    ``report_dedup_candidate_pairs.md`` HINT file (C Fix 1 output). The first two
    cells of each data row are ``<ID>: <title>`` — pull the leading report ID of
    each. Returns [] on any absence/parse failure (advisory only)."""
    path = scratchpad / "report_dedup_candidate_pairs.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    pairs: list[tuple[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 2:
            continue
        ma = _REPORT_DEDUP_AGENT_ID_RE.search(cells[0])
        mb = _REPORT_DEDUP_AGENT_ID_RE.search(cells[1])
        if not ma or not mb:
            continue  # header/prose rows carry no leading IDs in the first 2 cells
        a, b = ma.group(1).upper(), mb.group(1).upper()
        if a != b:
            pairs.append(tuple(sorted((a, b))))  # type: ignore[arg-type]
    # de-dup while preserving order
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for p in pairs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _report_dedup_coverage_gaps(scratchpad: Path) -> list[tuple[str, str]]:
    """C Fix 2 (coverage receipt): return the driver-computed candidate pairs
    that the report_dedup_agent did NOT explicitly dispose.

    A candidate pair (X, Y) is COVERED when BOTH IDs appear somewhere in
    ``report_dedup_agent_decisions.md`` (any table: MERGE, Quality Observation,
    or Reviewed — Kept Separate) — i.e. the agent looked at both findings and
    recorded a verdict. An UNCOVERED pair is one the agent silently skipped: the
    C-Fix-1 hint surfaced it but no KEEP/MERGE disposition exists.

    VISIBILITY ONLY — this never merges, never drops, never changes severity. It
    exists so a silently-skipped duplicate is logged for the operator instead of
    vanishing (recall/precision honesty; recall-safe by construction). Returns []
    when either file is absent (advisory)."""
    try:
        from plamen_validators import _report_dedup_exact_pair_coverage_detail

        detail = _report_dedup_exact_pair_coverage_detail(scratchpad)
        if not detail.get("ledger_issues"):
            gaps: list[tuple[str, str]] = []
            for pair_key in detail.get("missing_pair_keys", []):
                parts = str(pair_key).split("~", 1)
                if len(parts) == 2:
                    gaps.append((parts[0], parts[1]))
            return gaps
    except Exception as exc:
        log.warning(
            "[report_dedup] typed exact-pair coverage unavailable; "
            "using legacy Markdown projection fallback: %r",
            exc,
        )

    candidates = _report_dedup_candidate_pairs_from_hint(scratchpad)
    if not candidates:
        return []
    decisions_path = scratchpad / "report_dedup_agent_decisions.md"
    if not decisions_path.exists():
        return list(candidates)  # nothing disposed → every candidate is a gap
    try:
        dtext = decisions_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    disposed_ids = {m.group(1).upper() for m in _REPORT_DEDUP_AGENT_ID_RE.finditer(dtext)}
    return [
        (a, b) for (a, b) in candidates
        if a not in disposed_ids or b not in disposed_ids
    ]


def _dedup_report_python(
    scratchpad: Path,
    project_root: str,
    *,
    run_id: str = "test-unbound",
) -> bool:
    """Cross-tier report dedup. Python-native, NEVER loses content.

    Idempotent: a report with no cross-tier candidate pairs is a no-op (the
    delivered AUDIT_REPORT.md is left untouched, mapping records identity).
    `critical=False` — a crash/timeout/veto here MUST NOT halt the run or
    corrupt the delivered report.
    """
    audit_path = Path(project_root) / "AUDIT_REPORT.md"
    mapping_path = scratchpad / "report_dedup_mapping.md"
    candidate_relative = "report_dedup.canonical_candidate.md"
    exact_inputs = (
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
    input_snapshot = _capture_report_transaction_inputs(
        scratchpad, exact_inputs
    )

    def _write_mapping(lines: list[str]) -> None:
        try:
            mapping_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception as exc:
            log.warning(f"[report_dedup] mapping write failed: {exc!r}")

    # A crash after the canonical atomic replace must recover from the armed
    # payload, not re-run dedup against its own postimage.  Pre-ARM orphans have
    # no manifest and fall through to deterministic recomputation; their exact
    # preimage/payload files are create-once and therefore cannot be clobbered.
    transaction_phase = "report_dedup"
    try:
        _report_mutation_transaction_state(
            scratchpad=scratchpad,
            run_id=str(run_id or "test-unbound"),
            phase=transaction_phase,
        )
        recovered = _recover_report_mutation_transaction(
            scratchpad=scratchpad,
            project_root=Path(project_root),
            run_id=str(run_id or "test-unbound"),
            phase=transaction_phase,
            report_candidate_sidecar=candidate_relative,
        )
    except _ReportMutationTransactionError as exc:
        log.warning(f"[report_dedup] transaction recovery refused: {exc}")
        return False
    if recovered is not None:
        log.info("[report_dedup] recovered exact armed report transaction")
        return True

    if not audit_path.exists():
        _write_mapping([
            "# Report Dedup Mapping", "",
            "_AUDIT_REPORT.md not present — transaction unavailable; retained as debt._",
        ])
        log.warning("[report_dedup] AUDIT_REPORT.md missing — transaction debt")
        return False

    try:
        original = audit_path.read_text(encoding="utf-8", errors="strict")
    except Exception as exc:
        _write_mapping(["# Report Dedup Mapping", "", f"_read failed: {exc!r}_"])
        log.warning(f"[report_dedup] read failed: {exc!r}")
        return False

    def _commit_dedup(
        candidate: str,
        mapping_lines: list[str],
        *,
        evaluated_candidate: str | None = None,
        authority_candidates: list[dict] | None = None,
        authority_decisions: list[dict] | None = None,
        retained_projection_ids: set[str] | None = None,
        authority_source_ids: dict[str, set[str]] | None = None,
        semantic_aliases: dict[str, dict[str, str]] | None = None,
    ) -> bool:
        """Arm applied authority + sidecars, then replace the report."""
        try:
            import report_dedup_authority as report_alias_authority

            receipt_payload = report_alias_authority.build_receipt(
                pre_report=original,
                post_report=candidate,
                exact_inputs=input_snapshot,
                candidates=authority_candidates or [],
                decisions=authority_decisions or [],
                source_ids_by_report_id=authority_source_ids or {},
                retained_projection_ids=retained_projection_ids or set(),
                semantic_aliases=semantic_aliases or {},
            )
            receipt_bytes = report_alias_authority.canonical_receipt_bytes(
                receipt_payload
            )
        except Exception as exc:
            # Repair-then-degrade: no authority defect may strand the report or
            # partially hide an identity.  Retain the exact original and issue
            # a no-op receipt which disposes every proposal as KEEP_SEPARATE.
            log.warning(
                "[report_dedup] applied alias authority vetoed candidate; "
                "retaining original report: %r",
                exc,
            )
            candidate = original
            fallback_decisions = [
                {
                    "keep": str(row.get("keep", "")),
                    "absorb": str(row.get("absorb", "")),
                    "signals": list(row.get("signals", [])),
                    "decision": "KEEP_SEPARATE",
                    "reason": "applied-alias-authority-veto",
                }
                for row in (authority_candidates or [])
            ]
            mapping_lines = list(mapping_lines) + [
                "",
                "## APPLIED ALIAS AUTHORITY: VETO",
                "_Candidate report retained unchanged; every consolidation "
                "proposal remains KEEP_SEPARATE._",
            ]
            try:
                receipt_payload = report_alias_authority.build_receipt(
                    pre_report=original,
                    post_report=original,
                    exact_inputs=input_snapshot,
                    candidates=authority_candidates or [],
                    decisions=fallback_decisions,
                    source_ids_by_report_id=authority_source_ids or {},
                    retained_projection_ids=set(),
                    semantic_aliases=semantic_aliases or {},
                )
                receipt_bytes = report_alias_authority.canonical_receipt_bytes(
                    receipt_payload
                )
            except Exception as fallback_exc:
                log.warning(
                    "[report_dedup] no-op alias receipt could not be built; "
                    "canonical report remains untouched: %r",
                    fallback_exc,
                )
                return False
        mapping = ("\n".join(mapping_lines).rstrip("\n") + "\n").encode("utf-8")
        candidate_bytes = candidate.encode("utf-8")
        try:
            _apply_report_mutation_transaction(
                scratchpad=scratchpad,
                project_root=Path(project_root),
                run_id=str(run_id or "test-unbound"),
                phase=transaction_phase,
                post_report=candidate_bytes,
                exact_inputs=exact_inputs,
                expected_inputs=input_snapshot,
                sidecars={
                    "AUDIT_REPORT.pre-dedup.md": original.encode("utf-8"),
                    candidate_relative: candidate_bytes,
                    "AUDIT_REPORT.deduped.md": (
                        evaluated_candidate.encode("utf-8")
                        if evaluated_candidate is not None
                        else candidate_bytes
                    ),
                    "report_dedup_mapping.md": mapping,
                    "report_dedup_applied_alias_receipt.json": receipt_bytes,
                },
            )
        except (OSError, UnicodeError, _ReportMutationTransactionError) as exc:
            log.warning(
                f"[report_dedup] durable transaction refused ({exc!r}); "
                "canonical report retained/recoverable"
            )
            return False
        return True

    # --- F1: Quality-Observations retabulation (RETABULATION, never a drop) ---
    # Move unambiguously cosmetic Low/Info `###` sections into a single
    # `## Quality Observations` table BEFORE the cross-tier pair pass. Wrapped so
    # any internal error degrades gracefully (report_dedup is critical=False).
    # --- agent proposals (Phase 6d LLM proposer) ----------------------------
    # The report_dedup_agent reads the assembled report and proposes the
    # cross-tier / no-location MERGES and QO reclassifications that the
    # mechanical signals below cannot pair (missing/coarse locations, different
    # provenance). Advisory only: a missing/garbage file degrades to mechanical-
    # only. Agent MERGE rows are proposals: zero-loss embedding alone does not
    # prove semantic equivalence and cannot remove a standalone report identity.
    agent_merge_pairs: list[tuple[str, str]] = []
    agent_qo_ids: set[str] = set()
    try:
        agent_merge_pairs, agent_qo_ids = _parse_report_dedup_agent_decisions(
            scratchpad
        )
    except Exception as exc:
        log.warning(f"[report_dedup] agent decisions parse failed: {exc!r} — ignored")
        agent_merge_pairs, agent_qo_ids = [], set()

    # C Fix 2 (coverage receipt): surface any driver-computed candidate pair the
    # agent did not explicitly dispose. VISIBILITY ONLY — never merges/drops; a
    # silently-skipped duplicate is logged instead of vanishing (recall-safe).
    try:
        _cov_gaps = _report_dedup_coverage_gaps(scratchpad)
        if _cov_gaps:
            log.warning(
                f"[report_dedup] {len(_cov_gaps)} candidate pair(s) had no "
                f"explicit MERGE/Kept-Separate disposition (left un-merged): "
                + ", ".join(f"{a}~{b}" for a, b in _cov_gaps[:20])
            )
    except Exception as exc:
        log.warning(f"[report_dedup] coverage-gap check failed: {exc!r} — ignored")

    qo_rows: list[tuple[str, str, str, str, str, str]] = []
    working = original
    try:
        retab, qo_rows = _reclassify_cosmetic_low_info_to_qo(
            original, extra_qo_ids=agent_qo_ids
        )
        if qo_rows:
            # Gate QO retabulation INDEPENDENTLY from the merges. The whole-report
            # gate at the end is all-or-nothing, so a single lossy QO retab (e.g. a
            # finding whose impact sub-bullets don't fit the compact QO row) would
            # otherwise VETO every good merge too. Decouple: if the QO retab loses
            # data, drop QO and keep the original as the merge base — merges still land.
            # impact_only: the QO retab intentionally compacts cosmetic
            # Recommendation/Evidence/Description bullets into a one-line row.
            # Only IMPACT bullets (+ locations/PoCs, always checked) are
            # severity-bearing and must survive; the security-signal guard in
            # _reclassify_cosmetic_low_info_to_qo already protects real findings.
            lost_qo = _dedup_data_loss_gate(original, retab, impact_only=True)
            if lost_qo:
                log.warning(
                    f"[report_dedup] QO retabulation is lossy ({len(lost_qo)} item(s)) — "
                    f"dropping QO retab, proceeding with merges on the original "
                    f"(prevents one lossy QO from vetoing all merges)"
                )
                working = original
                qo_rows = []
            else:
                working = retab
    except Exception as exc:
        log.warning(f"[report_dedup] QO retabulation failed: {exc!r} — skipped")
        working = original
        qo_rows = []

    records = _dedup_report_sections(working)
    src_by_id = _parsers._dedup_source_ids_by_report_id(scratchpad)
    pairs = _dedup_report_candidate_pairs(records, src_by_id)

    # Append agent-proposed MERGE pairs as candidates. Only pairs whose BOTH
    # endpoints survive as parseable report sections (a QO-retabulated finding
    # is no longer a `###` section and cannot be merged) are admitted. The
    # "agent-semantic" signal authorizes a MERGE in the decision tree below,
    # gated end-to-end by the zero-loss embed + data-loss gate.
    _present_ids = {r["id"] for r in records}
    _existing_pair_keys = {
        frozenset((p["keep"], p["absorb"])) for p in pairs
    }
    for survivor, absorbed in agent_merge_pairs:
        if survivor not in _present_ids or absorbed not in _present_ids:
            continue
        key = frozenset((survivor, absorbed))
        if key in _existing_pair_keys:
            # Already a mechanical candidate — add the agent signal so the
            # decision tree treats it as MERGE-eligible even if the mechanical
            # gate would have left it KEEP_SEPARATE.
            for p in pairs:
                if frozenset((p["keep"], p["absorb"])) == key:
                    if "agent-semantic" not in p["signals"]:
                        p["signals"].append("agent-semantic")
                    p["keep"], p["absorb"] = survivor, absorbed
                    p["rank"] = min(p.get("rank", 99), 0)
                    break
            continue
        _existing_pair_keys.add(key)
        pairs.append({
            "keep": survivor, "absorb": absorbed,
            "signals": ["agent-semantic"], "rank": 0,
        })
    pairs.sort(key=lambda p: p.get("rank", 99))

    rec_by_id = {r["id"]: r for r in records}
    decisions: list[dict] = []
    # Resolve merge direction with the reusable superset gate; default
    # KEEP_SEPARATE (a duplicate is cosmetic, a dropped finding is recall loss).
    absorbed_into: dict[str, str] = {}
    for p in pairs:
        keep_id, absorb_id = p["keep"], p["absorb"]
        if absorb_id in absorbed_into or keep_id in absorbed_into:
            # avoid transitive double-merge; conservative skip
            decisions.append({**p, "decision": "KEEP_SEPARATE",
                              "reason": "transitive-merge-avoided"})
            continue
        finfo = {
            keep_id: {"source_ids": src_by_id.get(keep_id, set()),
                      "line_range": None, "file": ""},
            absorb_id: {"source_ids": src_by_id.get(absorb_id, set()),
                        "line_range": None, "file": ""},
        }
        # Agent-proposed semantic merge (Phase 6d proposer). The LLM read both
        # full sections and judged them the same root cause / same fix — the
        # cross-tier / no-location relationship the mechanical signals cannot
        # pair. Authorize the MERGE here; safety is NOT taken on faith: the
        # merge builder embeds the absorbed section verbatim under the survivor
        # (zero-loss) and the whole-report `_dedup_data_loss_gate` VETOes the
        # entire promotion (retaining the original report) if ANY location /
        # impact / PoC token is lost. So the worst case of a wrong agent merge
        # is a cosmetic regrouping, never a dropped finding.
        if "agent-semantic" in p["signals"]:
            decisions.append({
                "keep": keep_id, "absorb": absorb_id,
                "signals": p["signals"], "decision": "MERGE",
                "reason": "agent-proposed semantic cross-tier merge",
            })
            absorbed_into[absorb_id] = keep_id
            continue
        # Two signals authorize a mechanical cross-tier merge:
        #   (1) source-id-subset — same internal provenance (primary), and
        #   (2) same-fix-cross-tier — same code site + same Recommendation,
        #       re-confirmed below by the same-fix precision gate.
        # All OTHER weak signals (bare location/poc/title) remain
        # candidates-only and default KEEP_SEPARATE.
        same_fix_signal = any(
            s.startswith("same-fix-cross-tier") for s in p["signals"]
        )
        if same_fix_signal and "source-id-subset" not in p["signals"]:
            keep_rec_p = rec_by_id.get(keep_id)
            absorb_rec_p = rec_by_id.get(absorb_id)
            # Re-confirm the same-fix gate at decision time (defense in depth):
            # the candidate flag was set on the SAME two records, so this is a
            # deterministic re-check that also makes the merge auditable.
            sf_ok, sf_reason = (False, "missing-record")
            if keep_rec_p is not None and absorb_rec_p is not None:
                sf_ok, sf_reason = _dedup_same_fix_ok(keep_rec_p, absorb_rec_p)
            if sf_ok:
                # Survivor = higher severity (already chosen as `keep`). No
                # source-ID superset exists (different agents), so the merge
                # rests entirely on the same-fix gate + the data-loss gate.
                decisions.append({
                    "keep": keep_id, "absorb": absorb_id,
                    "signals": p["signals"], "decision": "MERGE",
                    "reason": f"same-fix cross-tier ({sf_reason})",
                })
                absorbed_into[absorb_id] = keep_id
                continue
            decisions.append({**p, "decision": "KEEP_SEPARATE",
                              "reason": f"same-fix gate vetoed ({sf_reason})"})
            continue
        if "source-id-subset" in p["signals"]:
            keep_src = src_by_id.get(keep_id, set())
            absorb_src = src_by_id.get(absorb_id, set())
            merge_ok = False
            reason = ""
            if keep_src and absorb_src and keep_src == absorb_src:
                # Identical internal-hypothesis provenance → unambiguously the
                # same bug surfaced at two severities. Survivor = higher sev
                # (already chosen as `keep`).
                merge_ok = True
                reason = "identical source-id set (same hypothesis, cross-tier)"
            else:
                # Proper subset → use the reusable superset gate to pick the
                # survivor (and FLIP if the proposed survivor is the smaller).
                resolved = _resolve_dedup_survivor(
                    absorb_id, keep_id, absorb_id, keep_id, finfo
                )
                if resolved is not None:
                    absorb_id, keep_id = resolved
                    merge_ok = True
                    reason = "source-id subset (cross-tier, superset survivor)"
            if merge_ok:
                decisions.append({
                    "keep": keep_id, "absorb": absorb_id,
                    "signals": p["signals"], "decision": "MERGE",
                    "reason": reason,
                })
                absorbed_into[absorb_id] = keep_id
                continue
        decisions.append({**p, "decision": "KEEP_SEPARATE",
                          "reason": "weak-signal-only (" + ",".join(p["signals"]) + ")"})

    # P0-AC: all LLM/similarity/subset outputs above are proposals.  Removing a
    # standalone report identity additionally requires exact current source
    # identity, normalized only through the immutable semantic applied-receipt
    # chain.  Zero-loss text embedding by itself is not equivalence authority.
    semantic_aliases: dict[str, dict[str, str]] = {}
    semantic_authority_valid = True
    try:
        import semantic_dedup_authority as semantic_authority

        receipt_present = any(
            (scratchpad / name).is_file()
            for name in (
                semantic_authority.PRIMARY_RECEIPT_NAME,
                semantic_authority.SUPPLEMENTAL_RECEIPT_NAME,
            )
        )
        if receipt_present:
            semantic_aliases = semantic_authority.load_applied_aliases(scratchpad)
    except Exception as exc:
        semantic_authority_valid = False
        semantic_aliases = {}
        log.warning(
            "[report_dedup] semantic applied-alias chain is invalid; all "
            "consolidation proposals remain KEEP_SEPARATE: %r",
            exc,
        )

    try:
        import report_dedup_authority as report_alias_authority

        for decision in decisions:
            if decision.get("decision") != "MERGE":
                continue
            if semantic_authority_valid:
                allowed, authority_reason = (
                    report_alias_authority.source_identity_equivalent(
                        str(decision.get("keep", "")),
                        str(decision.get("absorb", "")),
                        src_by_id,
                        semantic_aliases=semantic_aliases,
                    )
                )
            else:
                allowed, authority_reason = (
                    False,
                    "SEMANTIC_ALIAS_AUTHORITY_INVALID",
                )
            if allowed:
                decision["reason"] = authority_reason
            else:
                decision["decision"] = "KEEP_SEPARATE"
                decision["reason"] = authority_reason
    except Exception as exc:
        log.warning(
            "[report_dedup] report alias authority unavailable; all proposals "
            "remain KEEP_SEPARATE: %r",
            exc,
        )
        for decision in decisions:
            if decision.get("decision") == "MERGE":
                decision["decision"] = "KEEP_SEPARATE"
                decision["reason"] = "REPORT_ALIAS_AUTHORITY_UNAVAILABLE"

    merges = [d for d in decisions if d["decision"] == "MERGE"]

    # --- write decisions-only mapping ---------------------------------------
    map_lines = ["# Report Dedup Mapping", ""]
    map_lines.append(f"- Quality-Observation retabulations: {len(qo_rows)}")
    map_lines.append(f"- Candidate pairs evaluated: {len(pairs)}")
    map_lines.append(f"- Merges proposed: {len(merges)}")
    map_lines.append("")
    if qo_rows:
        map_lines.append("## Quality-Observation Retabulations (section -> QO table row)")
        map_lines.append("")
        map_lines.append("| Report ID | Severity | Class | Title |")
        map_lines.append("|-----------|----------|-------|-------|")
        for rid, title, sev_word, _loc, class_title, _desc in qo_rows:
            t = re.sub(r"\s+", " ", title).replace("|", "/").strip()
            map_lines.append(f"| {rid} | {sev_word} | {class_title} | {t} |")
        map_lines.append("")
    map_lines.append("| Survivor | Absorbed | Decision | Signals | Reason |")
    map_lines.append("|----------|----------|----------|---------|--------|")
    for d in decisions:
        map_lines.append(
            f"| {d['keep']} | {d['absorb']} | {d['decision']} | "
            f"{';'.join(d['signals'])} | {d['reason']} |"
        )

    def _commit_authorized(
        candidate: str,
        mapping_lines: list[str],
        *,
        evaluated_candidate: str | None = None,
    ) -> bool:
        return _commit_dedup(
            candidate,
            mapping_lines,
            evaluated_candidate=evaluated_candidate,
            authority_candidates=pairs,
            authority_decisions=decisions,
            retained_projection_ids={row[0] for row in qo_rows},
            authority_source_ids=src_by_id,
            semantic_aliases=semantic_aliases,
        )

    if not merges:
        if not qo_rows:
            # Idempotent no-op: leave AUDIT_REPORT.md untouched.
            ok = _commit_authorized(
                original,
                map_lines + [
                    "",
                    "_No cross-tier merges, no QO retabulation — report unchanged (identity)._",
                ],
            )
            log.info(
                f"[report_dedup] no cross-tier merges "
                f"({len(pairs)} candidates) — report unchanged"
            )
            return ok
        # QO-only change: promote `working` after the data-loss gate confirms
        # the retabulation lost nothing relative to the true original.
        lost_qo = _dedup_data_loss_gate(original, working)
        if lost_qo:
            ok = _commit_authorized(
                original,
                map_lines + [
                    "", f"## DATA-LOSS GATE: VETO ({len(lost_qo)} item(s) lost)",
                    "_QO retabulation dropped content — original report retained as delivered._",
                    "",
                    *[f"- LOST {item}" for item in lost_qo[:50]],
                ],
                evaluated_candidate=working,
            )
            log.warning(
                f"[report_dedup] QO-only data-loss gate VETO "
                f"({len(lost_qo)} lost item(s)) — original retained"
            )
            return ok
        ok = _commit_authorized(
            working,
            map_lines + [
                "", "## DATA-LOSS GATE: PASS",
                f"_Promoted QO-retabulated report ({len(qo_rows)} cosmetic Low/Info "
                f"finding(s) moved to Quality Observations; no cross-tier merges). "
                f"Original snapshot at AUDIT_REPORT.pre-dedup.md. On an exact "
                f"resume the committed postimage is reused and the report unchanged._",
            ],
        )
        log.info(
            f"[report_dedup] promoted QO-retabulated report: "
            f"{len(qo_rows)} retabulation(s), data-loss gate passed"
        )
        return ok

    # --- build deduped body: append absorbed content into survivor, drop
    #     absorbed section. Survivor keeps highest severity (it already is the
    #     keep). Renumbering is intentionally NOT done here to keep the merge
    #     strictly additive and the data-loss gate exact on locations/impacts. --
    deduped = working  # base includes the F1 QO retabulation, if any
    for d in merges:
        keep_rec = rec_by_id.get(d["keep"])
        absorb_rec = rec_by_id.get(d["absorb"])
        if not keep_rec or not absorb_rec:
            continue
        # Build a coupling block of the absorbed finding's distinct content.
        extra_locs = sorted(absorb_rec["locations"] - keep_rec["locations"])
        extra_impacts = sorted(absorb_rec["impacts"] - keep_rec["impacts"])
        extra_pocs = sorted(absorb_rec["pocs"] - keep_rec["pocs"])
        couple_parts = [
            f"\n\n**Consolidated from {d['absorb']}** "
            f"(same root cause, surfaced at a different severity tier):\n"
        ]
        if extra_locs:
            couple_parts.append(
                "- Additional locations: " + ", ".join(f"`{l}`" for l in extra_locs)
            )
        for imp in extra_impacts:
            couple_parts.append(f"- {imp}")
        if extra_pocs:
            couple_parts.append("- PoC references: " + ", ".join(extra_pocs))
        # If the absorbed section has unique location/impact/poc content not
        # captured by tokens above, append its full section text verbatim so the
        # data-loss gate is guaranteed to pass (zero-loss superset).
        #
        # IDEMPOTENCY: demote the absorbed `### [X-NN]` heading inside the
        # embedded block to a non-heading bold line. Otherwise the embedded
        # heading re-materializes the absorbed finding as a parseable section on
        # a subsequent run, and the phase would merge it AGAIN (non-idempotent).
        # The data-loss gate checks locations/impacts/pocs — never headings — so
        # demoting the heading preserves zero-loss while making re-runs a no-op.
        absorbed_body = re.sub(
            r"(?im)^#{2,3}\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI]-\d+)\s*\]\s*",
            r"**Absorbed finding \1:** ",
            absorb_rec["section"].strip(),
        )
        couple_block = "\n".join(couple_parts) + "\n\n" + absorbed_body + "\n"
        # Insert coupling at end of the survivor section.
        keep_section = keep_rec["section"]
        idx = deduped.find(keep_section)
        if idx < 0:
            continue
        new_keep = keep_section.rstrip() + "\n" + couple_block
        deduped = deduped[:idx] + new_keep + deduped[idx + len(keep_section):]
        # Remove the absorbed standalone section.
        ab_section = absorb_rec["section"]
        ab_idx = deduped.find(ab_section)
        if ab_idx >= 0:
            deduped = deduped[:ab_idx] + deduped[ab_idx + len(ab_section):]
        # Refresh rec_by_id survivor section pointer for chained merges.
        refreshed = _dedup_report_sections(deduped)
        rec_by_id = {r["id"]: r for r in refreshed}

    deduped = re.sub(r"\n{4,}", "\n\n\n", deduped)

    # --- MECHANICAL DATA-LOSS GATE ------------------------------------------
    lost = _dedup_data_loss_gate(original, deduped)
    if lost:
        # VETO: keep the original AUDIT_REPORT.md as delivered, leave deduped
        # as a side artifact, log a warning. NEVER auto-degrade the real report.
        ok = _commit_authorized(
            original,
            map_lines + [
                "", f"## DATA-LOSS GATE: VETO ({len(lost)} item(s) lost)",
                "_Deduped output dropped content — original report retained as delivered._",
                "",
                *[f"- LOST {item}" for item in lost[:50]],
            ],
            evaluated_candidate=deduped,
        )
        log.warning(
            f"[report_dedup] data-loss gate VETO ({len(lost)} lost item(s)) — "
            f"original AUDIT_REPORT.md retained, deduped kept as side artifact"
        )
        return ok

    # --- gate passed → promote deduped to delivered report -------------------
    ok = _commit_authorized(
        deduped,
        map_lines + [
            "", "## DATA-LOSS GATE: PASS",
            f"_Promoted deduped report ({len(merges)} cross-tier merge(s), "
            f"{len(qo_rows)} QO retabulation(s)). "
            f"Original snapshot at AUDIT_REPORT.pre-dedup.md. On an exact "
            f"resume the committed postimage is reused and the report unchanged._",
        ],
    )
    log.info(
        f"[report_dedup] promoted deduped report: {len(merges)} cross-tier "
        f"merge(s), {len(qo_rows)} QO retabulation(s), data-loss gate passed"
    )
    return ok


def _report_index_unresolved_report_ids(
    index_text: str,
    scratchpad: Path | None = None,
) -> set[str]:
    """Return report IDs whose report-index Trust Adj. requires UNRESOLVED.

    Prefer the Skeptic-Judge decision files as the source of truth. The report
    index is a routing table, and some rows can carry advisory `PARTIAL(...)`
    trust text for reasons other than a Judge UNRESOLVED/PARTIAL ruling. When
    judge artifacts are available, only tag rows whose internal IDs intersect a
    real Judge UNRESOLVED/PARTIAL decision.
    """
    ids: set[str] = set()
    judge_unresolved: set[str] = set()
    if scratchpad is not None:
        try:
            judge_unresolved = {x.upper() for x in _collect_judge_unresolved_ids(scratchpad)}
        except Exception:
            judge_unresolved = set()
    section = _extract_h2_section(index_text or "", "Master Finding Index")
    if not section:
        return ids
    col_idx: dict[str, int] = {}
    for line in section.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        lower = [c.lower() for c in cells]
        if "report id" in lower or "trust adj." in lower or "trust adj" in lower:
            for i, name in enumerate(lower):
                if "report" in name and "id" in name:
                    col_idx["report_id"] = i
                elif "trust" in name and "adj" in name:
                    col_idx["trust_adj"] = i
                elif "internal" in name and ("hypothesis" in name or "id" in name):
                    col_idx["internal"] = i
            continue
        if not col_idx:
            continue
        rid_i = col_idx.get("report_id", 0)
        trust_i = col_idx.get("trust_adj")
        if trust_i is None or rid_i >= len(cells) or trust_i >= len(cells):
            continue
        rid_m = re.search(r"\b([CHMLI]-\d{1,3})\b", cells[rid_i], re.IGNORECASE)
        if not rid_m:
            continue
        trust = cells[trust_i]
        if re.search(r"\b(?:UNRESOLVED|PARTIAL)\s*\(", trust, re.IGNORECASE):
            internal_i = col_idx.get("internal")
            internal = cells[internal_i] if internal_i is not None and internal_i < len(cells) else ""
            internal_ids = {m.group(1).upper() for m in _INTERNAL_FINDING_ID_RE.finditer(internal)}
            if judge_unresolved and internal_ids and not (internal_ids & judge_unresolved):
                continue
            ids.add(rid_m.group(1).upper())
    return ids


def _tag_report_index_unresolved_sections(
    body: str,
    index_text: str,
    scratchpad: Path | None = None,
) -> str:
    """Add `[UNRESOLVED]` to assigned body headings that require it."""
    unresolved_ids = _report_index_unresolved_report_ids(index_text, scratchpad)
    if not unresolved_ids:
        return body

    def repl(match: re.Match[str]) -> str:
        line = match.group(0)
        rid = match.group(1).upper()
        if rid not in unresolved_ids or re.search(r"\[UNRESOLVED\b", line, re.IGNORECASE):
            return line
        return line.rstrip() + " [UNRESOLVED]"

    pattern = re.compile(
        r"(?im)^###\s*(?:\[REPORT-BLOCKED[^\]]*\]\s*)?\[\s*([CHMLI]-\d{1,3})\s*\][^\n]*$"
    )
    return pattern.sub(repl, body or "")


def _inventory_source_files(scratchpad: Path) -> list[Path]:
    seen: set[str] = set()
    files: list[Path] = []
    for pattern in _INVENTORY_SOURCE_PATTERNS:
        for p in sorted(scratchpad.glob(pattern)):
            if p.name in seen:
                continue
            seen.add(p.name)
            files.append(p)
    return files


def _count_inventory_source_signals(path: Path) -> int:
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return 0
    ids, blocks = _extract_finding_signals(text)
    return max(blocks, len(ids), 1 if text.strip() else 0)


def ensure_inventory_shard_plan(scratchpad: Path, target_per_shard: int = 70,
                                max_shards: int = 3) -> dict[str, list[dict[str, object]]]:
    """Create inventory shard manifests from breadth analysis files."""
    source_files = _inventory_source_files(scratchpad)
    weighted = []
    total = 0
    for p in source_files:
        signals = _count_inventory_source_signals(p)
        weighted.append({"path": p.name, "signals": signals})
        total += signals

    if not weighted:
        num_shards = 1
    else:
        num_shards = max(1, min(max_shards, math.ceil(total / max(target_per_shard, 1))))

    shard_names = [f"inventory_chunk_{c}" for c in ("a", "b", "c")[:num_shards]]
    shard_entries = {name: [] for name in ("inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c")}
    shard_totals = {name: 0 for name in shard_entries}

    for item in sorted(weighted, key=lambda x: (-int(x["signals"]), str(x["path"]))):
        active = sorted(shard_names, key=lambda name: (shard_totals[name], name))
        chosen = active[0]
        shard_entries[chosen].append(item)
        shard_totals[chosen] += int(item["signals"])

    plan_lines = [
        "# Inventory Shard Plan",
        "",
        f"- Total breadth analysis files: {len(weighted)}",
        f"- Total source finding signals: {total}",
        f"- Target signals per shard: {target_per_shard}",
        f"- Active shard count: {num_shards}",
        "",
    ]
    for shard_name in ("inventory_chunk_a", "inventory_chunk_b", "inventory_chunk_c"):
        manifest = scratchpad / f"{shard_name}.manifest.md"
        rows = shard_entries[shard_name]
        lines = [
            f"# {shard_name} manifest",
            "",
            f"- Output: findings_{shard_name}.md",
            f"- Assigned files: {len(rows)}",
            f"- Estimated signals: {shard_totals[shard_name]}",
            "",
            "| File | Estimated signals |",
            "|------|-------------------|",
        ]
        lines.extend(
            f"| {row['path']} | {row['signals']} |"
            for row in rows
        )
        lines.append("")
        content = "\n".join(lines)
        if not manifest.exists() or manifest.read_text(encoding="utf-8", errors="replace") != content:
            manifest.write_text(content, encoding="utf-8")
        plan_lines.append(
            f"- {shard_name}: {len(rows)} files / {shard_totals[shard_name]} signals"
        )

    plan_text = "\n".join(plan_lines) + "\n"
    plan_path = scratchpad / "inventory_shard_plan.md"
    if not plan_path.exists() or plan_path.read_text(encoding="utf-8", errors="replace") != plan_text:
        plan_path.write_text(plan_text, encoding="utf-8")
    return shard_entries


def _rescan_manifest_slug(value: str) -> str:
    """Sanitize a contract/file label into a rescan-manifest filename slug.

    The slug must round-trip through `plamen_validators._RESCAN_MANIFEST_FILE_RE`
    (`[A-Za-z0-9][A-Za-z0-9_.\\-]*`): non-conforming characters collapse to `_`
    and a non-alphanumeric leading char is stripped. Returns "" if nothing
    usable remains so the caller can fall back to the scope-review slug.
    """
    base = (value or "").replace("\\", "/").strip().strip("`")
    base = Path(base).name  # drop directories; keep the leaf
    base = re.sub(r"\.(?:sol|rs|go|move|cairo|vy|ts|js|py)$", "", base, flags=re.IGNORECASE)
    slug = re.sub(r"[^A-Za-z0-9_.\-]", "_", base).strip("_")
    slug = re.sub(r"_{2,}", "_", slug)
    # Leading char must be alphanumeric per the validator regex.
    slug = re.sub(r"^[^A-Za-z0-9]+", "", slug)
    return slug


def _rescan_percontract_clusters(scratchpad: Path, max_clusters: int = 6) -> list[str]:
    """Derive per-contract cluster slugs from `contract_inventory.md`.

    Reuses the same scoped-source extraction as `_synthesize_components_audited`
    (in-scope `\\`...\\`` code-file paths above any `## Out of Scope` cut). Returns
    a bounded, de-duplicated list of filename-safe slugs. Empty when the
    inventory is absent or sparse — the caller then falls back to a single
    `analysis_percontract_scope_review.md` row.
    """
    inventory = scratchpad / "contract_inventory.md"
    if not inventory.exists():
        return []
    try:
        text = _llm_norm(inventory.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    cut = re.search(r"(?im)^##\s+Out[- ]of[- ]Scope\b", text)
    scoped_text = text[: cut.start()] if cut else text
    slugs: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(
        r"`([^`]+\.(?:sol|rs|go|move|cairo|vy|ts|js|py))`", scoped_text, re.IGNORECASE
    ):
        slug = _rescan_manifest_slug(m.group(1))
        if slug and slug.lower() not in seen:
            seen.add(slug.lower())
            slugs.append(slug)
        if len(slugs) >= max_clusters:
            break
    return slugs


def ensure_rescan_manifest(scratchpad: Path, config: dict) -> Path:
    """Mechanically write `rescan_manifest.md` (Phase 3b prepare step).

    Mirrors `ensure_inventory_shard_plan`: a cheap deterministic planning step
    that emits the concrete output filenames the rescan worker pool will fill,
    so the pure executor (`rescan` phase) never has to plan-and-execute in one
    overloaded coordinator on large codebases.

    Emits:
      - 2-3 concrete ``analysis_rescan_<n>.md`` rows (broad re-scan agents), and
      - >=1 concrete ``analysis_percontract_<cluster>.md`` row derived from
        ``contract_inventory.md`` clusters; falls back to a single
        ``analysis_percontract_scope_review.md`` row when the inventory is
        sparse/empty.

    All filenames are CONCRETE (never glob form) so the manifest round-trips
    through ``plamen_validators._parse_rescan_manifest_files`` and satisfies the
    authoritative ``_rescan_manifest_exact_missing`` gate. Idempotent:
    compare-then-write, so a re-run on an unchanged scratchpad is a no-op.
    """
    n_rescan = max(2, min(3, int(config.get("rescan_agent_count", 3) or 3)))
    rescan_files = [f"analysis_rescan_{n}.md" for n in range(1, n_rescan + 1)]

    clusters = _rescan_percontract_clusters(scratchpad)
    if clusters:
        percontract_files = [f"analysis_percontract_{slug}.md" for slug in clusters]
    else:
        percontract_files = ["analysis_percontract_scope_review.md"]

    lines = [
        "# Rescan Manifest",
        "",
        "Mechanically derived plan for the Phase 3b breadth re-scan worker pool.",
        "Each row below is a CONCRETE output file the rescan executor must fill.",
        "Per-worker methodology is unchanged (see phase3b-rescan.md / the",
        "EXCLUSION SOURCE RULE) — this file only enumerates the output families.",
        "",
        "## Re-Scan Agents",
        "",
        "| Output |",
        "|--------|",
    ]
    lines.extend(f"| {name} |" for name in rescan_files)
    lines += [
        "",
        "## Per-Contract Agents",
        "",
        "| Output |",
        "|--------|",
    ]
    lines.extend(f"| {name} |" for name in percontract_files)
    lines.append("")
    content = "\n".join(lines)

    manifest = scratchpad / "rescan_manifest.md"
    if (
        not manifest.exists()
        or manifest.read_text(encoding="utf-8", errors="replace") != content
    ):
        manifest.write_text(content, encoding="utf-8")
    return manifest


def write_inventory_chunk_placeholder(scratchpad: Path, phase_name: str, reason: str):
    out_name = f"findings_{phase_name}.md"
    p = scratchpad / out_name
    p.write_text(
        f"# {phase_name}: N/A\n\n"
        f"No analysis files were assigned to this shard.\n\n"
        f"- Reason: {reason}\n"
        f"- Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
        encoding="utf-8",
    )


def _allocate_inventory_ledger_id(
    scratchpad: Path,
    *,
    preferred_id: str,
    owner_phase: str,
    owning_artifact: str,
    title: str,
) -> str:
    """Register an INV id, allocating a fresh one if a stale retry collided."""
    candidate = preferred_id
    for _ in range(1000):
        try:
            result = id_ledger_register(
                scratchpad,
                finding_id=candidate,
                owner_phase=owner_phase,
                owner_attempt=1,
                owning_artifact=owning_artifact,
                title=title,
            )
        except Exception as e:
            log.debug(f"[{owner_phase}] ledger register skipped for {candidate}: {e}")
            return candidate
        if result.get("status") != "COLLISION":
            return candidate
        try:
            nums = [
                int(m.group(1))
                for rec in id_ledger_all_records(scratchpad)
                for m in [re.match(r"^INV-(\d+)$", str(rec.get("id", "")).upper())]
                if m
            ]
            candidate = f"INV-{(max(nums) if nums else 0) + 1:03d}"
        except Exception:
            m = re.search(r"(\d+)$", candidate)
            n = int(m.group(1)) + 1 if m else 1
            candidate = f"INV-{n:03d}"
    return candidate


def _write_mechanical_inventory_from_chunks(scratchpad: Path) -> tuple[int, int]:
    """Write final findings_inventory.md from completed inventory chunks.

    L1 runs can produce hundreds of chunk findings. A fourth LLM merge pass has
    repeatedly timed out or short-circuited on a partial file. This deterministic
    merge preserves every parsed chunk source ID and performs only safe
    root-cause deduplication by normalized location + root-cause/title.
    """
    chunk_paths = sorted(scratchpad.glob("findings_inventory_chunk_*.md"))
    entries: list[dict[str, object]] = []
    for p in chunk_paths:
        entries.extend(_parse_inventory_chunk(p))
    merged = _merge_inventory_entries(entries)
    if not merged:
        return 0, 0

    _n_parsed_entries, _n_merged = _render_inventory_from_merged_entries(
        scratchpad, merged
    )
    receipt = [
        "# Mechanical Inventory Merge Receipt",
        "",
        f"Chunk files: {len(chunk_paths)}",
        f"Parsed chunk findings: {len(entries)}",
        f"Merged inventory findings: {_n_merged}",
        "",
    ]
    (scratchpad / "inventory_merge_receipt.md").write_text(
        "\n".join(receipt), encoding="utf-8"
    )
    return len(entries), _n_merged


def _render_inventory_from_merged_entries(
    scratchpad: Path, merged: list[dict[str, object]]
) -> tuple[int, int]:
    """Render `findings_inventory.md` from already-merged inventory entries.

    Shared emission body extracted from `_write_mechanical_inventory_from_chunks`
    so the floor builder (`ensure_findings_inventory_floor`) produces a
    byte-structurally identical inventory: the same `# Finding Inventory` header,
    `## Summary` table, and `### Finding [INV-NNN]:` blocks the downstream
    verify-queue / parity validators expect.

    `merged` MUST already be the conservative-merge output of
    `_merge_inventory_entries` (it never fabricates a finding). Returns
    (input_entry_count, rendered_finding_count). Writes nothing and returns
    (0, 0) when `merged` is empty.
    """
    if not merged:
        return 0, 0

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for item in merged:
        sev = _severity_name_from_text("", {"severity": str(item.get("severity", ""))})
        counts[sev] = counts.get(sev, 0) + 1

    lines = [
        "# Finding Inventory",
        "",
        "Generated mechanically from `findings_inventory_chunk_*.md` to avoid",
        "LLM merge truncation. Source IDs are preserved for parity checks.",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.extend([
        f"| Total | {len(merged)} |",
        "",
        "## Findings",
        "",
    ])

    for i, item in enumerate(merged, start=1):
        sev = _severity_name_from_text("", {"severity": str(item.get("severity", ""))})
        title = _strip_md(str(item.get("title", ""))) or "Untitled finding"
        loc = _norm_loc(str(item.get("location", ""))) or "UNKNOWN"
        tag = (
            _extract_first_tag(str(item.get("preferred_tag", "")))
            or _strip_md(str(item.get("preferred_tag", "")))
            or EVIDENCE_TAG_DEFAULT
        )
        source_ids = []
        for sid in item.get("source_ids", []) or []:
            norm = _normalize_finding_id(str(sid)) or _strip_md(str(sid))
            if norm and norm not in source_ids:
                source_ids.append(norm)
        if item.get("local_id"):
            local = _normalize_finding_id(str(item.get("local_id"))) or _strip_md(str(item.get("local_id")))
            if local and local not in source_ids:
                source_ids.append(local)
        source_text = ", ".join(source_ids) if source_ids else "SOURCE_UNVERIFIED"
        root = _strip_md(str(item.get("root_cause", ""))) or title
        desc = _strip_md(str(item.get("description", ""))) or root
        impact = _strip_md(str(item.get("impact", ""))) or "Impact requires verifier confirmation."
        verdict = _strip_md(str(item.get("verdict", ""))) or "NEEDS_VERIFICATION"
        optional_lines: list[str] = []
        for field in _OPTIONAL_FINDING_METADATA_FIELDS:
            val = _strip_md(str(item.get(field, ""))).strip()
            if not val:
                continue
            label = _OPTIONAL_FINDING_METADATA_LABELS[field][0]
            optional_lines.append(f"**{label}**: {val}")
        inv_id = _allocate_inventory_ledger_id(
            scratchpad,
            preferred_id=f"INV-{i:03d}",
            owner_phase="inventory",
            owning_artifact="findings_inventory.md",
            title=title,
        )
        # v2.0.6 (P2.2): register the INV allocation in the ID ledger.
        # Inventory consolidation is mechanical / driver-owned, so true
        # collisions cannot happen here — but the registration makes
        # the IDs visible to the consumer backstop gate (P2.5) and to
        # downstream phases that allocate from the same namespace.
        try:
            from plamen_parsers import id_ledger_register
            id_ledger_register(
                scratchpad,
                finding_id=inv_id,
                owner_phase="inventory",
                owner_attempt=1,
                owning_artifact="findings_inventory.md",
                title=title,
            )
        except Exception as e:
            log.debug(f"[inventory] ledger register skipped for {inv_id}: {e}")
        lines.extend([
            f"### Finding [{inv_id}]: {title}",
            f"**Severity**: {sev}",
            f"**Location**: {loc}",
            f"**Preferred Tag**: {tag}",
            f"**Source IDs**: {source_text}",
            f"**Verdict**: {verdict}",
            f"**Root Cause**: {root}",
            f"**Description**: {desc}",
            f"**Impact**: {impact}",
            *optional_lines,
            "",
        ])

    (scratchpad / "findings_inventory.md").write_text("\n".join(lines), encoding="utf-8")
    _write_finding_records_from_inventory(scratchpad)
    return len(merged), len(merged)


def ensure_findings_inventory_floor(scratchpad: Path) -> tuple[int, int]:
    """Guarantee `findings_inventory.md` exists, reconstructed honestly.

    B1 inventory floor. When the inventory phase degrades (a chunk failed, the
    LLM merge truncated, the file was never written or is empty), downstream
    verification has nothing to work on and the run terminally halts even though
    real findings exist on disk in the breadth/depth/chunk artifacts. This floor
    reconstructs `findings_inventory.md` from whatever completed:

      * `findings_inventory_chunk_*.md` (already-structured inventory chunks),
      * `analysis_*.md` (breadth pass findings, incl. rescan/percontract),
      * `depth_*_findings.md` (depth agent findings).

    It REUSES the existing parse + conservative-merge helpers
    (`_parse_inventory_chunk`, `_parse_depth_finding_blocks`,
    `_merge_inventory_entries`) and the shared renderer, so it can NEVER
    fabricate a finding — every emitted INV-* entry traces to a real finding in
    a source artifact. `_merge_inventory_entries` only coalesces exact
    title+location duplicates, so no real finding is silently dropped either.

    Idempotent w.r.t. an already-good inventory: it is a NO-OP (returns the
    current block count, 0 sources scanned) when `findings_inventory.md` already
    holds usable finding blocks — it never overwrites a real inventory.

    Returns (n_findings, n_source_artifacts). When NO source artifact yields ANY
    finding (a genuinely empty audit), it writes a structurally valid EMPTY
    inventory and returns (0, n_source_artifacts) — a valid empty path, never a
    crash.
    """
    inv_path = scratchpad / "findings_inventory.md"
    # NO-OP guard: never clobber an inventory that already has real findings.
    if inv_path.exists():
        try:
            existing = inv_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            existing = ""
        try:
            existing_blocks = len(_inventory_blocks(existing))
        except Exception:
            existing_blocks = 0
        if existing_blocks > 0:
            return existing_blocks, 0

    entries: list[dict[str, object]] = []
    n_sources = 0

    # (1) Structured inventory chunks — richest source, parse first.
    for p in sorted(scratchpad.glob("findings_inventory_chunk_*.md")):
        n_sources += 1
        for entry in _parse_inventory_chunk(p):
            identity_values = [
                entry.get("local_id"),
                *(entry.get("source_ids", []) or []),
                entry.get("source_action_id"),
            ]
            if any(
                str(value or "").strip()
                and not _normalize_finding_id(str(value or "").strip())
                for value in identity_values
            ):
                continue
            entries.append(entry)

    # (2) Breadth analysis passes (analysis_*.md, incl. rescan/percontract),
    # (3) depth agent findings (depth_*_findings.md), and (4) blind-spot scanner +
    # niche findings (blind_spot_*_findings.md / niche_*_findings.md) — these last
    # two were absent from the floor feeders, so a degraded inventory could not
    # recover a blind-spot/niche finding (the BLIND-B3 recall leak). All use the
    # standard `### Finding [ID]: Title` heading parsed by _parse_depth_finding_blocks.
    feeder_globs = (
        "analysis_*.md", "depth_*_findings.md",
        "blind_spot_*_findings.md", "niche_*_findings.md",
    )
    for pattern in feeder_globs:
        for p in sorted(scratchpad.glob(pattern)):
            n_sources += 1
            for blk in _parse_depth_finding_blocks(p):
                # The recall floor is not an identity-resolution boundary.
                # Parser debt/quarantine and content-less methodology rows stay
                # in their source/debt artifacts; they cannot mint inventory
                # Source IDs or Action IDs merely because inventory is empty.
                if str(blk.get("_content_bearing", "")).lower() != "true":
                    continue
                if str(blk.get("_identity_debt", "")).strip():
                    continue
                if str(blk.get("_identity_quarantine", "")).lower() == "true":
                    continue
                if str(blk.get("_identity_status", "REGISTERED")).upper() in {
                    "UNKNOWN_WELL_FORMED",
                    "MALFORMED",
                    "PRODUCER_LOCAL_ID_MISMATCH",
                }:
                    continue
                if str(blk.get("_local_id_valid", "true")).lower() == "false":
                    continue
                # _parse_depth_finding_blocks emits `id`; the merge helper keys
                # provenance off `local_id` / `source_ids`. Adapt without losing
                # the originating finding ID.
                src_id = str(blk.get("id", "")).strip()
                entries.append({
                    "title": blk.get("title", ""),
                    "severity": blk.get("severity", ""),
                    "location": blk.get("location", ""),
                    "preferred_tag": blk.get("preferred_tag", ""),
                    "verdict": blk.get("verdict", ""),
                    "root_cause": blk.get("root_cause", "") or blk.get("description", ""),
                    "description": blk.get("description", ""),
                    "impact": blk.get("impact", ""),
                    "local_id": src_id,
                    "source_ids": [src_id] if src_id else [],
                    **{
                        f: blk.get(f, "")
                        for f in _OPTIONAL_FINDING_METADATA_FIELDS
                        if blk.get(f)
                    },
                })

    merged = _merge_inventory_entries(entries)
    if not merged:
        # Genuinely empty audit (no findings anywhere) OR no source artifacts.
        # Either way write a structurally valid empty inventory — a clean empty
        # path, never a crash. Downstream parity treats an empty inventory as
        # zero IDs to route (no dropout).
        empty_lines = [
            "# Finding Inventory",
            "",
            "Reconstructed mechanically by the inventory floor "
            "(`ensure_findings_inventory_floor`). No findings were recoverable "
            "from any completed breadth/depth/chunk artifact.",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            "| Critical | 0 |",
            "| High | 0 |",
            "| Medium | 0 |",
            "| Low | 0 |",
            "| Informational | 0 |",
            "| Total | 0 |",
            "",
            "## Findings",
            "",
            "_No findings._",
            "",
        ]
        inv_path.write_text("\n".join(empty_lines), encoding="utf-8")
        try:
            _write_finding_records_from_inventory(scratchpad)
        except Exception:
            pass
        return 0, n_sources

    n_parsed, n_rendered = _render_inventory_from_merged_entries(scratchpad, merged)
    receipt = [
        "# Inventory Floor Reconstruction Receipt",
        "",
        "findings_inventory.md was missing/empty after the inventory phase; "
        "reconstructed honestly from completed artifacts (no fabrication).",
        "",
        f"Source artifacts scanned: {n_sources}",
        f"Parsed source findings: {len(entries)}",
        f"Reconstructed inventory findings: {n_rendered}",
        "",
    ]
    (scratchpad / "inventory_floor_receipt.md").write_text(
        "\n".join(receipt), encoding="utf-8"
    )
    return n_rendered, n_sources


# Canonical unresolved-debt artifact consumed by the depth postprocessor gate.
_NICHE_IDENTITY_DEBT_NAME = "niche_identity_debt.json"
_NICHE_IDENTITY_DEBT_SCHEMA = "plamen.niche_identity_debt.v2"
_NICHE_FINDING_ARTIFACT_MAX_BYTES = _SHARED_FINDING_ARTIFACT_MAX_BYTES
_NICHE_SOURCE_NAMESPACE_MAX_BYTES = 64 * 1024 * 1024
_NICHE_IDENTITY_DEBT_EXACT_BLOCK_MAX_BYTES = 64 * 1024
_NICHE_IDENTITY_DEBT_SEMANTIC_FIELD_MAX_BYTES = 16 * 1024
_NICHE_IDENTITY_DEBT_SIDECAR_MAX_BYTES = 8 * 1024 * 1024
_NICHE_SOURCE_NAME_RE = re.compile(
    r"niche_[A-Za-z0-9_.-]+_findings\.md"
)
_NICHE_CURRENT_INPUT_NAME_RE = re.compile(
    r"(?:niche_[A-Za-z0-9_.-]+_findings\.md|findings_inventory\.md)"
)
_WINDOWS_REPARSE_POINT = 0x400


def _niche_name_sort_key(value: str) -> tuple[str, str]:
    return value.casefold(), value

# Public compatibility alias for the explicit subset of the shared canonical
# block grammar. Niche parsing itself consumes ``_canonical_finding_blocks`` so
# unadorned registered IDs and normalized HTML headings share one denominator.
_NICHE_FINDING_HEADING_RE = _EXPLICIT_FINDING_HEADING_RE


def _enumerate_niche_source_paths(scratchpad: Path) -> list[Path]:
    """Enumerate the complete, root-bound canonical niche source namespace."""

    root = Path(scratchpad)
    root_stat = root.lstat()
    root_attributes = int(
        getattr(root_stat, "st_file_attributes", 0) or 0
    )
    if (
        stat.S_ISLNK(root_stat.st_mode)
        or root_attributes & _WINDOWS_REPARSE_POINT
        or not stat.S_ISDIR(root_stat.st_mode)
    ):
        raise ValueError("niche source root must be a real directory")
    root_resolved = root.resolve(strict=True)
    paths: list[Path] = []
    seen_casefold: set[str] = set()
    for candidate in root.iterdir():
        name = candidate.name
        if not _NICHE_SOURCE_NAME_RE.fullmatch(name):
            continue
        try:
            name.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("niche source name must be ASCII") from exc
        folded = name.casefold()
        if folded in seen_casefold:
            raise ValueError(f"niche source casefold alias: {name}")
        seen_casefold.add(folded)
        source_stat = candidate.lstat()
        attributes = int(
            getattr(source_stat, "st_file_attributes", 0) or 0
        )
        if (
            Path(name).name != name
            or stat.S_ISLNK(source_stat.st_mode)
            or attributes & _WINDOWS_REPARSE_POINT
            or not stat.S_ISREG(source_stat.st_mode)
        ):
            raise ValueError(f"niche source must be a regular non-link: {name}")
        if int(getattr(source_stat, "st_nlink", 0) or 0) != 1:
            raise ValueError(
                f"niche source link alias rejected (nlink != 1): {name}"
            )
        if (
            candidate.parent.resolve(strict=True) != root_resolved
            or candidate.resolve(strict=True).parent != root_resolved
        ):
            raise ValueError(f"niche source escaped root: {name}")
        paths.append(candidate)
    return sorted(paths, key=lambda value: _niche_name_sort_key(value.name))


def _read_niche_source_bytes(path: Path) -> bytes:
    return read_bounded_regular_bytes(
        path,
        _NICHE_FINDING_ARTIFACT_MAX_BYTES,
        require_single_link=True,
    )


def _niche_source_snapshot(path: Path) -> dict[str, Any]:
    raw = _read_niche_source_bytes(path)
    return {
        "source_file": path.name,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "source_size_bytes": len(raw),
    }


def _parse_niche_findings(
    scratchpad: Path,
    *,
    _retained_capture: Any = None,
) -> list[dict[str, Any]]:
    """Parse all niche_*_findings.md files into structured finding entries.

    Each niche agent writes findings in the standard finding-output-format.md
    template (## Finding [NSC-N]: Title + **Severity** / **Location** / etc).
    Every heading accepted by the shared producer grammar is retained in the
    action denominator. Registered candidates missing substantive fields become
    typed schema debt; only complete, registered actions may be promoted.

    Returns a list of dicts with source metadata, normalized identity status,
    typed identity debt/quarantine fields, and the parsed finding body.
    """
    if _retained_capture is None:
        with retain_bounded_regular_namespace(
            Path(scratchpad),
            _NICHE_SOURCE_NAME_RE,
            per_file_limit=_NICHE_FINDING_ARTIFACT_MAX_BYTES,
            total_limit=_NICHE_SOURCE_NAMESPACE_MAX_BYTES,
            max_members=128,
            require_single_link=True,
        ) as retained:
            return _parse_niche_findings(
                scratchpad, _retained_capture=retained
            )
    retained = _retained_capture
    entries: list[dict[str, Any]] = []
    for source_name in retained.namespace:
        niche_path = Path(scratchpad) / source_name
        try:
            raw_source = retained.files[source_name].raw
            general_actions = _parsers._parse_depth_finding_blocks(
                niche_path,
                _captured_bytes=raw_source,
            )
        except _FindingArtifactLimitError:
            raise
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(
                f"NICHE_SOURCE_UNREADABLE: {niche_path.name}"
            ) from exc
        registered_producer = _registered_producer_for_artifact(
            niche_path.name,
            consumer="pre_dedup_promotion",
        )
        source_sha256 = hashlib.sha256(raw_source).hexdigest()
        for general_action in general_actions:
            source_byte_start = int(
                general_action.get("_source_byte_start", -1)
            )
            source_byte_end = int(
                general_action.get("_source_byte_end", -1)
            )
            if not 0 <= source_byte_start < source_byte_end <= len(raw_source):
                raise RuntimeError(
                    "NICHE_ACTION_RAW_RANGE_INVALID: general parser action "
                    f"{niche_path.name}:{general_action.get('id', '')} has "
                    "no exact nonempty physical-byte range"
                )
            raw_block_bytes = raw_source[source_byte_start:source_byte_end]
            source_block_sha256 = hashlib.sha256(raw_block_bytes).hexdigest()
            if (
                general_action.get("_source_size_bytes") != len(raw_source)
                or general_action.get("_source_sha256") != source_sha256
                or general_action.get("_source_block_size_bytes")
                != len(raw_block_bytes)
                or general_action.get("_source_block_sha256")
                != source_block_sha256
            ):
                raise RuntimeError(
                    "NICHE_ACTION_RAW_RANGE_INVALID: general parser source "
                    f"binding drift for {niche_path.name}"
                )
            raw_id = str(
                general_action.get("_raw_id")
                or general_action.get("id")
                or ""
            ).strip()
            identity = _classify_producer_id(
                raw_id,
                producer=registered_producer,
            )
            fid = str(general_action.get("id") or "").strip().upper()
            fid = fid or identity.normalized_id or raw_id.upper()
            if not fid:
                continue
            identity_status = str(
                general_action.get("_identity_status") or identity.status
            )
            identity_debt = str(
                general_action.get("_identity_debt") or identity.identity_debt
            )
            local_id_valid = str(
                general_action.get("_local_id_valid") or ""
            ).lower() == "true"
            if registered_producer is not None and local_id_valid:
                identity_status = "REGISTERED"
                identity_debt = ""
            elif registered_producer is not None and not local_id_valid:
                identity_status = (
                    identity_status or "PRODUCER_LOCAL_ID_MISMATCH"
                )
                identity_debt = (
                    identity_debt or "PRODUCER_LOCAL_ID_MISMATCH"
                )
            title = str(general_action.get("title") or "").strip() or fid
            severity = str(general_action.get("severity") or "").strip()
            location = str(general_action.get("location") or "").strip()
            preferred_tag = str(
                general_action.get("preferred_tag") or ""
            ).strip()
            if preferred_tag and not preferred_tag.startswith("["):
                preferred_tag = f"[{preferred_tag.strip('[]')}]"
            description_full = str(
                general_action.get("description") or ""
            ).strip()
            impact_full = str(general_action.get("_impact") or "").strip()
            missing_required_fields = sorted(
                str(field_name)
                for field_name in general_action.get(
                    "_missing_required_fields", []
                )
                if str(field_name)
            )
            if missing_required_fields and not identity_debt:
                identity_status = "FINDING_BLOCK_SCHEMA_DEBT"
                identity_debt = "MISSING_REQUIRED_FINDING_FIELDS"
            description_full = description_full or title
            impact_full = (
                impact_full or "Impact requires verifier confirmation."
            )
            block = str(
                general_action.get("_normalized_source_block")
                or raw_block_bytes.decode("utf-8", errors="replace")
            ).strip()
            source_action_identity = _niche_source_action_identity(
                source_file=niche_path.name,
                source_sha256=source_sha256,
                normalized_local_id=fid,
                source_byte_start=source_byte_start,
                source_byte_end=source_byte_end,
                source_block_sha256=source_block_sha256,
            )
            entries.append({
                "source_file": niche_path.name,
                "source_sha256": source_sha256,
                "source_size_bytes": len(raw_source),
                "source_byte_start": source_byte_start,
                "source_byte_end": source_byte_end,
                "source_block_sha256": source_block_sha256,
                "source_block_size_bytes": len(raw_block_bytes),
                "exact_block_capture": (
                    "FULL"
                    if len(raw_block_bytes) <= _NICHE_IDENTITY_DEBT_EXACT_BLOCK_MAX_BYTES
                    else "OMITTED_OVERSIZE"
                ),
                "exact_block_bytes_b64": (
                    base64.b64encode(raw_block_bytes).decode("ascii")
                    if len(raw_block_bytes) <= _NICHE_IDENTITY_DEBT_EXACT_BLOCK_MAX_BYTES
                    else ""
                ),
                "raw_id": raw_id,
                "normalized_id": identity.normalized_id,
                "normalized_local_id": fid,
                "source_id": fid,
                "source_action_identity": source_action_identity,
                "identity_status": identity_status,
                "identity_debt": identity_debt,
                "missing_required_fields": missing_required_fields,
                "identity_authority": "false",
                "identity_quarantine": "true" if identity_debt else "false",
                "title": title,
                "severity": severity or "Medium",
                "location": _norm_loc(location) if location else "UNKNOWN",
                "preferred_tag": preferred_tag or "[CODE-TRACE]",
                "description": (
                    description_full[:1500]
                ),
                "description_full": description_full,
                "impact": (
                    impact_full[:800]
                ),
                "impact_full": impact_full,
                "raw_block": block,
                "action_shape": str(
                    general_action.get("_action_shape") or "UNKNOWN"
                ),
            })
    retained.revalidate()
    return entries


def _niche_identity_debt_digest(payload: dict[str, Any]) -> str:
    """Return the deterministic digest for a record or artifact body."""

    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _niche_source_action_identity(
    *,
    source_file: str,
    source_sha256: str,
    normalized_local_id: str,
    source_byte_start: int,
    source_byte_end: int,
    source_block_sha256: str,
) -> str:
    payload = {
        "schema_version": "plamen.niche_source_action.v1",
        "source_file": source_file,
        "source_sha256": source_sha256,
        "normalized_local_id": normalized_local_id,
        "source_byte_start": source_byte_start,
        "source_byte_end": source_byte_end,
        "source_block_sha256": source_block_sha256,
    }
    return "NACT-" + _niche_identity_debt_digest(payload)[:24].upper()


def _niche_action_record(entry: dict[str, Any]) -> dict[str, Any]:
    """Project every parsed niche action into the complete denominator."""

    record: dict[str, Any] = {
        "source_file": str(entry.get("source_file") or ""),
        "source_sha256": str(entry.get("source_sha256") or "").lower(),
        "source_size_bytes": int(entry.get("source_size_bytes") or 0),
        "normalized_local_id": str(
            entry.get("normalized_local_id") or entry.get("source_id") or ""
        ),
        "raw_id": str(entry.get("raw_id") or ""),
        "source_byte_start": int(entry.get("source_byte_start") or 0),
        "source_byte_end": int(entry.get("source_byte_end") or 0),
        "source_block_sha256": str(
            entry.get("source_block_sha256") or ""
        ).lower(),
        "source_block_size_bytes": int(
            entry.get("source_block_size_bytes") or 0
        ),
        "exact_block_capture": str(entry.get("exact_block_capture") or ""),
        "exact_block_bytes_b64": str(
            entry.get("exact_block_bytes_b64") or ""
        ),
        "source_action_identity": str(
            entry.get("source_action_identity") or ""
        ),
        "identity_status": str(entry.get("identity_status") or ""),
        "identity_debt": str(entry.get("identity_debt") or ""),
        "missing_required_fields": sorted(
            str(value)
            for value in entry.get("missing_required_fields", [])
            if str(value)
        ),
        "supersedes_source_action_identities": sorted(
            str(value)
            for value in entry.get("supersedes_source_action_identities", [])
            if str(value)
        ),
        "action_status": "DEBT" if entry.get("identity_debt") else "CLEAN",
        "quarantine": bool(entry.get("identity_debt")),
    }
    record["action_record_sha256"] = _niche_identity_debt_digest(record)
    return record


def _niche_action_set_digest(actions: list[dict[str, Any]]) -> str:
    return _niche_identity_debt_digest({"actions": actions})


_NICHE_ACTION_BINDING_FIELDS = (
    "source_file",
    "source_sha256",
    "source_size_bytes",
    "normalized_local_id",
    "raw_id",
    "source_byte_start",
    "source_byte_end",
    "source_block_sha256",
    "source_block_size_bytes",
    "source_action_identity",
)


def _niche_action_bindings(
    actions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Project the immutable occurrence binding for exact multiset parity."""

    return sorted(
        (
            {field: action.get(field) for field in _NICHE_ACTION_BINDING_FIELDS}
            for action in actions
        ),
        key=lambda record: (
            str(record.get("source_file") or ""),
            int(record.get("source_byte_start") or 0),
            int(record.get("source_byte_end") or 0),
            str(record.get("normalized_local_id") or ""),
            str(record.get("source_action_identity") or ""),
        ),
    )


def _niche_live_action_denominator_digest(
    actions: list[dict[str, Any]],
) -> str:
    return _niche_identity_debt_digest(
        {"bindings": _niche_action_bindings(actions)}
    )


def _niche_source_namespace_digest(names: list[str]) -> str:
    return _niche_identity_debt_digest({"source_namespace": names})


def _niche_lifecycle_set_digest(records: list[dict[str, Any]]) -> str:
    return _niche_identity_debt_digest({"lifecycle_records": records})


def _niche_removed_action_records(
    source_errors: list[dict[str, Any]],
    lifecycle_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return sorted(
        [
            dict(record)
            for record in (*source_errors, *lifecycle_records)
            if record.get("status")
            in {"SOURCE_ACTION_REMOVED", "DELIVERED_ACTION_REMOVED"}
        ],
        key=lambda record: (
            str(record.get("source_action_identity") or ""),
            str(record.get("status") or ""),
            str(record.get("record_sha256") or ""),
        ),
    )


def _niche_removed_action_set_digest(
    source_errors: list[dict[str, Any]],
    lifecycle_records: list[dict[str, Any]],
) -> str:
    return _niche_identity_debt_digest({
        "removed_actions": _niche_removed_action_records(
            source_errors, lifecycle_records
        )
    })


def _reconcile_niche_action_drift(
    scratchpad: Path,
    entries: list[dict[str, Any]],
    *,
    prior: Optional[dict[str, Any]] = None,
) -> list[dict[str, Any]]:
    """Turn same-source/local-ID byte drift into persistent typed debt."""

    if prior is None:
        prior = read_niche_identity_debt_sidecar(
            scratchpad,
            _validate_live_sources=False,
        )
    prior_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in (prior or {}).get("actions", []):
        key = (
            str(record.get("source_file") or ""),
            str(record.get("normalized_local_id") or "").upper(),
        )
        prior_by_key.setdefault(key, []).append(dict(record))
    inventory_path = Path(scratchpad) / "findings_inventory.md"
    if inventory_path.exists():
        try:
            inventory_text = read_bounded_regular_bytes(
                inventory_path,
                _NICHE_FINDING_ARTIFACT_MAX_BYTES,
                require_single_link=True,
            ).decode("utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            raise RuntimeError(
                "NICHE_INVENTORY_CAPTURE_UNSAFE: findings_inventory.md"
            ) from exc
        for record in _inventory_niche_action_bindings(inventory_text):
            key = (
                str(record["source_file"]),
                str(record["normalized_local_id"]).upper(),
            )
            if all(
                prior_record.get("source_action_identity")
                != record["source_action_identity"]
                for prior_record in prior_by_key.get(key, [])
            ):
                prior_by_key.setdefault(key, []).append(record)

    reconciled: list[dict[str, Any]] = []
    for original in entries:
        entry = dict(original)
        key = (
            str(entry.get("source_file") or ""),
            str(entry.get("normalized_local_id") or "").upper(),
        )
        prior_rows = prior_by_key.get(key, [])
        current_identity = str(entry.get("source_action_identity") or "")
        exact_prior = next(
            (
                row for row in prior_rows
                if row.get("source_action_identity") == current_identity
            ),
            None,
        )
        if exact_prior and exact_prior.get("supersedes_source_action_identities"):
            entry["supersedes_source_action_identities"] = sorted(
                {
                    str(value)
                    for value in exact_prior.get(
                        "supersedes_source_action_identities", []
                    )
                    if str(value)
                }
            )
        prior_drift = bool(
            exact_prior
            and exact_prior.get("identity_debt")
            == "SOURCE_ACTION_CONTENT_DRIFT"
        )
        changed_from_prior = bool(
            prior_rows
            and all(
                row.get("source_action_identity") != current_identity
                for row in prior_rows
            )
        )
        if prior_drift or changed_from_prior:
            entry["supersedes_source_action_identities"] = sorted(
                {
                    str(row.get("source_action_identity") or "")
                    for row in prior_rows
                    if row.get("source_action_identity") != current_identity
                }
            )
            if not entry.get("identity_debt"):
                entry["identity_status"] = "SOURCE_ACTION_CONTENT_DRIFT"
                entry["identity_debt"] = "SOURCE_ACTION_CONTENT_DRIFT"
                entry["identity_quarantine"] = "true"
        reconciled.append(entry)
    return reconciled


def _bounded_niche_semantic(value: object) -> tuple[str, dict[str, Any]]:
    """Bound one UTF-8 semantic field while retaining recovery identity."""

    text = str(value or "")
    raw = text.encode("utf-8", errors="replace")
    truncated = len(raw) > _NICHE_IDENTITY_DEBT_SEMANTIC_FIELD_MAX_BYTES
    bounded = raw[:_NICHE_IDENTITY_DEBT_SEMANTIC_FIELD_MAX_BYTES]
    if truncated:
        text = bounded.decode("utf-8", errors="ignore")
    return text, {
        "truncated": truncated,
        "utf8_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _niche_identity_debt_record(entry: dict[str, Any]) -> dict[str, Any]:
    """Project one quarantined parser row into the canonical debt schema."""

    bounded_semantics: dict[str, str] = {}
    semantic_metadata: dict[str, Any] = {}
    for field_name, value in (
        ("title", entry.get("title")),
        ("severity", entry.get("severity")),
        ("location", entry.get("location")),
        ("description", entry.get("description_full")),
        ("impact", entry.get("impact_full")),
    ):
        bounded, metadata = _bounded_niche_semantic(value)
        bounded_semantics[field_name] = bounded
        semantic_metadata[f"{field_name}_truncated"] = metadata["truncated"]
        semantic_metadata[f"{field_name}_utf8_bytes"] = metadata["utf8_bytes"]
        semantic_metadata[f"{field_name}_sha256"] = metadata["sha256"]
    record: dict[str, Any] = {
        "source_file": str(entry.get("source_file") or ""),
        "source_sha256": str(entry.get("source_sha256") or "").lower(),
        "source_size_bytes": int(entry.get("source_size_bytes") or 0),
        "source_byte_start": int(entry.get("source_byte_start") or 0),
        "source_byte_end": int(entry.get("source_byte_end") or 0),
        "source_block_sha256": str(
            entry.get("source_block_sha256") or ""
        ).lower(),
        "source_block_size_bytes": int(
            entry.get("source_block_size_bytes") or 0
        ),
        "exact_block_capture": str(entry.get("exact_block_capture") or ""),
        "exact_block_bytes_b64": str(
            entry.get("exact_block_bytes_b64") or ""
        ),
        "raw_id": str(entry.get("raw_id") or ""),
        "normalized_id": str(entry.get("normalized_id") or ""),
        "normalized_local_id": str(
            entry.get("normalized_local_id") or entry.get("source_id") or ""
        ),
        "source_action_identity": str(
            entry.get("source_action_identity") or ""
        ),
        "supersedes_source_action_identities": sorted(
            str(value)
            for value in entry.get("supersedes_source_action_identities", [])
            if str(value)
        ),
        **bounded_semantics,
        **semantic_metadata,
        "identity_status": str(entry.get("identity_status") or ""),
        "identity_debt": str(entry.get("identity_debt") or ""),
        "missing_required_fields": sorted(
            str(value)
            for value in entry.get("missing_required_fields", [])
            if str(value)
        ),
        "resolution_status": "UNRESOLVED",
        "required_action": (
            "RECONCILE_SOURCE_ACTION_DRIFT"
            if entry.get("identity_debt") == "SOURCE_ACTION_CONTENT_DRIFT"
            else (
                "REPAIR_FINDING_BLOCK_SCHEMA"
                if entry.get("identity_debt") == "MISSING_REQUIRED_FINDING_FIELDS"
                else "RECONCILE_PRODUCER_IDENTITY"
            )
        ),
        "identity_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
        "quarantine": True,
    }
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["debt_id"] = f"NID-{record_sha256[:24].upper()}"
    return record


def _niche_identity_source_error(path: Path) -> dict[str, Any]:
    """Create bounded typed debt for a source that cannot be safely read."""

    try:
        stat_result = path.lstat()
        source_size = int(stat_result.st_size)
        stat_identity = {
            "source_file": path.name,
            "source_size_bytes": source_size,
            "source_mtime_ns": int(stat_result.st_mtime_ns),
        }
    except OSError:
        source_size = -1
        stat_identity = {
            "source_file": path.name,
            "source_size_bytes": source_size,
            "source_mtime_ns": 0,
        }
    record: dict[str, Any] = {
        **stat_identity,
        "source_limit_bytes": _NICHE_FINDING_ARTIFACT_MAX_BYTES,
        "source_sha256": "",
        "source_hash_status": "UNAVAILABLE_OVER_LIMIT",
        "status": "SOURCE_OVER_LIMIT",
        "identity_debt": "SOURCE_ARTIFACT_OVER_LIMIT",
        "required_action": "REDUCE_AND_REVIEW_SOURCE_ARTIFACT",
        "resolution_status": "UNRESOLVED",
        "identity_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
        "quarantine": True,
    }
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["debt_id"] = f"NIDSRC-{record_sha256[:24].upper()}"
    return record


def _niche_capture_corruption_error(detail: object) -> dict[str, Any]:
    """Create blocking haltless debt when no safe source snapshot can commit."""

    bounded, metadata = _bounded_niche_semantic(detail)
    record: dict[str, Any] = {
        "source_file": "<niche-source-namespace>",
        "source_size_bytes": 0,
        "source_mtime_ns": 0,
        "source_limit_bytes": _NICHE_FINDING_ARTIFACT_MAX_BYTES,
        "source_sha256": "",
        "source_hash_status": "UNAVAILABLE_UNSAFE_CAPTURE",
        "status": "SOURCE_CAPTURE_CORRUPTION",
        "identity_debt": "SOURCE_CAPTURE_CORRUPTION",
        "required_action": "RECAPTURE_AND_RECONCILE_SOURCE_NAMESPACE",
        "resolution_status": "UNRESOLVED",
        "identity_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
        "quarantine": True,
        "detail": bounded,
        "detail_truncated": metadata["truncated"],
        "detail_utf8_bytes": metadata["utf8_bytes"],
        "detail_sha256": metadata["sha256"],
    }
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["debt_id"] = f"NIDSRC-{record_sha256[:24].upper()}"
    return record


def _niche_undelivered_clean_action_error(
    action: dict[str, Any],
) -> dict[str, Any]:
    """Project a clean-but-not-inventory-delivered action as blocking debt."""

    record: dict[str, Any] = {
        field: action.get(field) for field in _NICHE_ACTION_BINDING_FIELDS
    }
    record.update({
        "exact_block_capture": str(
            action.get("exact_block_capture") or "LEGACY_UNAVAILABLE"
        ),
        "exact_block_bytes_b64": str(
            action.get("exact_block_bytes_b64") or ""
        ),
        "prior_action_record_sha256": str(
            action.get("action_record_sha256") or ""
        ),
        "status": "UNDELIVERED_CLEAN_ACTION",
        "identity_debt": "UNDELIVERED_CLEAN_ACTION",
        "required_action": "DELIVER_ACTION_TO_INVENTORY_OR_HUMAN_REVIEW",
        "resolution_status": "UNRESOLVED",
        "identity_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
        "quarantine": True,
    })
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["debt_id"] = f"NIDSRC-{record_sha256[:24].upper()}"
    return record


def _niche_identity_missing_source_error(
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Persist a prior live source that disappeared or was renamed."""

    record: dict[str, Any] = {
        "source_file": str(snapshot.get("source_file") or ""),
        "source_size_bytes": int(snapshot.get("source_size_bytes") or 0),
        "source_sha256": str(snapshot.get("source_sha256") or "").lower(),
        "status": "SOURCE_MISSING",
        "identity_debt": "SOURCE_ARTIFACT_MISSING_OR_RENAMED",
        "required_action": "RESTORE_OR_RECONCILE_SOURCE_ARTIFACT",
        "resolution_status": "UNRESOLVED",
        "identity_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
        "quarantine": True,
    }
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["debt_id"] = f"NIDSRC-{record_sha256[:24].upper()}"
    return record


def _niche_removed_action_source_error(
    action: dict[str, Any],
) -> dict[str, Any]:
    """Persist an undelivered prior action that vanished from live parsing."""

    record: dict[str, Any] = {
        field: action.get(field) for field in _NICHE_ACTION_BINDING_FIELDS
    }
    record.update({
        "exact_block_capture": str(
            action.get("exact_block_capture") or "LEGACY_UNAVAILABLE"
        ),
        "exact_block_bytes_b64": str(
            action.get("exact_block_bytes_b64") or ""
        ),
        "prior_action_record_sha256": str(
            action.get("action_record_sha256")
            or action.get("prior_action_record_sha256")
            or ""
        ),
        "status": "SOURCE_ACTION_REMOVED",
        "identity_debt": "SOURCE_ACTION_REMOVED",
        "required_action": "RESTORE_OR_RECONCILE_SOURCE_ACTION",
        "resolution_status": "UNRESOLVED",
        "identity_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
        "quarantine": True,
    })
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["debt_id"] = f"NIDSRC-{record_sha256[:24].upper()}"
    return record


def _niche_delivered_action_lifecycle_record(
    action: dict[str, Any],
    inventory_referents: set[str],
) -> dict[str, Any]:
    """Retain a nonblocking audit trail for a delivered vanished action."""

    record: dict[str, Any] = {
        field: action.get(field) for field in _NICHE_ACTION_BINDING_FIELDS
    }
    record.update({
        "exact_block_capture": str(
            action.get("exact_block_capture") or "LEGACY_UNAVAILABLE"
        ),
        "exact_block_bytes_b64": str(
            action.get("exact_block_bytes_b64") or ""
        ),
        "prior_action_record_sha256": str(
            action.get("action_record_sha256")
            or action.get("prior_action_record_sha256")
            or ""
        ),
        "status": "DELIVERED_ACTION_REMOVED",
        "blocking": False,
        "inventory_referents": sorted(inventory_referents),
        "proof_authority": "NONE",
        "drop_authority": False,
        "clean_authority": False,
    })
    record_sha256 = _niche_identity_debt_digest(record)
    record["record_sha256"] = record_sha256
    record["lifecycle_id"] = f"NIDLIFE-{record_sha256[:24].upper()}"
    return record


def _reconcile_niche_removed_actions(
    scratchpad: Path,
    entries: list[dict[str, Any]],
    prior: Optional[dict[str, Any]],
    *,
    delivered: Optional[dict[str, set[str]]] = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Reconcile the prior action multiset without granting disappearance authority."""

    current_identities = {
        str(entry.get("source_action_identity") or "") for entry in entries
    }
    # A producer-authored supersession is evidence, never lifecycle authority.
    # Only the independent typed disposition channel may resolve a committed
    # historical action.  Until that producer exists, disappearance remains a
    # tombstone even when a replacement action names the old identity.
    retained_identities = current_identities
    delivered = dict(delivered or {})
    blocking: dict[str, dict[str, Any]] = {}
    lifecycle: dict[str, dict[str, Any]] = {}

    for prior_error in (prior or {}).get("source_errors", []):
        if prior_error.get("status") != "SOURCE_ACTION_REMOVED":
            continue
        identity = str(prior_error.get("source_action_identity") or "")
        if identity and identity not in retained_identities:
            if identity in delivered:
                row = _niche_delivered_action_lifecycle_record(
                    prior_error, delivered[identity]
                )
                lifecycle[identity] = row
            else:
                blocking[identity] = dict(prior_error)
    for prior_row in (prior or {}).get("lifecycle_records", []):
        identity = str(prior_row.get("source_action_identity") or "")
        if identity and identity not in retained_identities:
            if identity in delivered:
                lifecycle[identity] = _niche_delivered_action_lifecycle_record(
                    prior_row, delivered[identity]
                )
            else:
                blocking[identity] = _niche_removed_action_source_error(
                    prior_row
                )
    for prior_action in (prior or {}).get("actions", []):
        identity = str(prior_action.get("source_action_identity") or "")
        if not identity or identity in retained_identities:
            continue
        if identity in delivered:
            lifecycle[identity] = _niche_delivered_action_lifecycle_record(
                prior_action, delivered[identity]
            )
            blocking.pop(identity, None)
        elif identity not in lifecycle:
            blocking[identity] = _niche_removed_action_source_error(prior_action)
    return list(blocking.values()), list(lifecycle.values())


def _niche_removed_action_binding_valid(record: dict[str, Any]) -> bool:
    source_file = str(record.get("source_file") or "")
    source_sha256 = str(record.get("source_sha256") or "")
    block_sha256 = str(record.get("source_block_sha256") or "")
    local_id = str(record.get("normalized_local_id") or "")
    start = record.get("source_byte_start")
    end = record.get("source_byte_end")
    source_size = record.get("source_size_bytes")
    block_size = record.get("source_block_size_bytes")
    if (
        Path(source_file).name != source_file
        or not _NICHE_SOURCE_NAME_RE.fullmatch(source_file)
        or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
        or not re.fullmatch(r"[0-9a-f]{64}", block_sha256)
        or not local_id
        or not isinstance(start, int)
        or not isinstance(end, int)
        or not isinstance(source_size, int)
        or not isinstance(block_size, int)
        or start < 0
        or end <= start
        or end > source_size
        or block_size != end - start
        or record.get("source_action_identity")
        != _niche_source_action_identity(
            source_file=source_file,
            source_sha256=source_sha256,
            normalized_local_id=local_id,
            source_byte_start=start,
            source_byte_end=end,
            source_block_sha256=block_sha256,
        )
        or not re.fullmatch(
            r"[0-9a-f]{64}",
            str(record.get("prior_action_record_sha256") or ""),
        )
    ):
        return False
    capture = str(record.get("exact_block_capture") or "")
    encoded = str(record.get("exact_block_bytes_b64") or "")
    if capture == "FULL":
        try:
            captured = base64.b64decode(encoded, validate=True)
        except Exception:
            return False
        return (
            len(captured) == block_size
            and hashlib.sha256(captured).hexdigest() == block_sha256
        )
    if capture == "OMITTED_OVERSIZE":
        return not encoded and block_size > _NICHE_IDENTITY_DEBT_EXACT_BLOCK_MAX_BYTES
    return capture == "LEGACY_UNAVAILABLE" and not encoded


def read_niche_identity_debt_sidecar(
    scratchpad: Path,
    *,
    _validate_live_sources: bool = True,
) -> Optional[dict[str, Any]]:
    """Read and validate the canonical unresolved niche identity-debt artifact.

    A caller must treat any validation error or positive
    ``blocking_debt_count`` as non-clean postprocessor state.  The artifact and
    its records deliberately carry no proof, drop, or clean authority. Public
    replay also authenticates every source snapshot and raw block against the
    current scratchpad. The private structural-only mode exists solely so a
    rerun can convert stale clean actions into explicit current drift debt.
    """

    lifecycle_current: Optional[dict[str, Any]] = None
    path = Path(scratchpad) / _NICHE_IDENTITY_DEBT_NAME
    if not path.exists():
        return None
    try:
        projection_bytes = read_bounded_regular_bytes(
            path,
            _NICHE_IDENTITY_DEBT_SIDECAR_MAX_BYTES,
            require_single_link=True,
        )
    except Exception as exc:
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: unsafe or unreadable "
            f"projection: {exc}"
        ) from exc
    try:
        payload = json.loads(projection_bytes.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: unreadable JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: non-object")
    if payload.get("schema_version") != _NICHE_IDENTITY_DEBT_SCHEMA:
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: schema")
    artifact_sha256 = str(payload.get("artifact_sha256") or "").lower()
    unsigned_payload = {
        key: value for key, value in payload.items() if key != "artifact_sha256"
    }
    if artifact_sha256 != _niche_identity_debt_digest(unsigned_payload):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: artifact hash")
    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: candidates")
    actions = payload.get("actions")
    if not isinstance(actions, list):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: actions")
    source_errors = payload.get("source_errors")
    if not isinstance(source_errors, list):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source errors")
    lifecycle_records = payload.get("lifecycle_records")
    if lifecycle_records is None and not _validate_live_sources:
        lifecycle_records = []
    if not isinstance(lifecycle_records, list):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: lifecycle records"
        )
    if payload.get("denominator_complete") is not True:
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: incomplete denominator"
        )
    if payload.get("action_count") != len(actions):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action count")
    if payload.get("action_set_sha256") != _niche_action_set_digest(actions):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action set hash")
    if payload.get("candidate_count") != len(candidates):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: count")
    if payload.get("source_error_count", 0) != len(source_errors):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source error count")
    if payload.get("blocking_debt_count") != len(candidates) + len(source_errors):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: debt count")
    lifecycle_count = payload.get("lifecycle_count")
    if lifecycle_count is None and not _validate_live_sources:
        lifecycle_count = len(lifecycle_records)
    if lifecycle_count != len(lifecycle_records):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: lifecycle count")
    lifecycle_set_sha256 = payload.get("lifecycle_set_sha256")
    if lifecycle_set_sha256 is None and not _validate_live_sources:
        lifecycle_set_sha256 = _niche_lifecycle_set_digest(lifecycle_records)
    if lifecycle_set_sha256 != _niche_lifecycle_set_digest(lifecycle_records):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: lifecycle set hash"
        )
    removed_action_records = _niche_removed_action_records(
        source_errors, lifecycle_records
    )
    removed_action_count = payload.get("removed_action_count")
    if removed_action_count is None and not _validate_live_sources:
        removed_action_count = len(removed_action_records)
    if removed_action_count != len(removed_action_records):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: removed action count"
        )
    removed_action_set_sha256 = payload.get("removed_action_set_sha256")
    if removed_action_set_sha256 is None and not _validate_live_sources:
        removed_action_set_sha256 = _niche_removed_action_set_digest(
            source_errors, lifecycle_records
        )
    if removed_action_set_sha256 != _niche_removed_action_set_digest(
        source_errors, lifecycle_records
    ):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: removed action set hash"
        )
    if (
        payload.get("clean_authority") is not False
        or payload.get("drop_authority") is not False
        or payload.get("proof_authority") != "NONE"
    ):
        raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: authority")
    seen_action_identities: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action")
        action_record_sha256 = str(
            action.get("action_record_sha256") or ""
        ).lower()
        unsigned_action = {
            key: value
            for key, value in action.items()
            if key != "action_record_sha256"
        }
        if action_record_sha256 != _niche_identity_debt_digest(unsigned_action):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action record hash"
            )
        source_action_identity = str(
            action.get("source_action_identity") or ""
        )
        if (
            not re.fullmatch(r"NACT-[0-9A-F]{24}", source_action_identity)
            or source_action_identity in seen_action_identities
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action identity"
            )
        seen_action_identities.add(source_action_identity)
        start = action.get("source_byte_start")
        end = action.get("source_byte_end")
        block_size = action.get("source_block_size_bytes")
        source_size = action.get("source_size_bytes")
        normalized_local_id = str(
            action.get("normalized_local_id") or ""
        )
        source_file = str(action.get("source_file") or "")
        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or not isinstance(block_size, int)
            or not isinstance(source_size, int)
            or start < 0
            or end <= start
            or end > source_size
            or block_size != end - start
            or not normalized_local_id
            or Path(source_file).name != source_file
            or not re.fullmatch(r"niche_[A-Za-z0-9_.-]+_findings\.md", source_file)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(action.get("source_sha256") or "")
            )
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(action.get("source_block_sha256") or ""),
            )
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action byte range binding"
            )
        expected_identity = _niche_source_action_identity(
            source_file=source_file,
            source_sha256=str(action.get("source_sha256") or ""),
            normalized_local_id=normalized_local_id,
            source_byte_start=start,
            source_byte_end=end,
            source_block_sha256=str(
                action.get("source_block_sha256") or ""
            ),
        )
        if expected_identity != source_action_identity:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action identity binding"
            )
        has_debt = bool(action.get("identity_debt"))
        if (
            action.get("action_status") != ("DEBT" if has_debt else "CLEAN")
            or action.get("quarantine") is not has_debt
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action status"
            )
    # Range disjointness is a structural property of the projection itself,
    # so reject it before immutable-CAS comparison.  This preserves precise
    # diagnostics and prevents two action identities from claiming the same
    # producer bytes even when every per-record digest was recomputed.
    prior_end_by_source: dict[str, int] = {}
    for action in sorted(
        actions,
        key=lambda item: (
            str(item.get("source_file") or ""),
            int(item.get("source_byte_start", -1)),
            int(item.get("source_byte_end", -1)),
        ),
    ):
        source_file = str(action.get("source_file") or "")
        start = int(action.get("source_byte_start", -1))
        prior_end = prior_end_by_source.get(source_file)
        if prior_end is not None and start < prior_end:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: action range overlap"
            )
        prior_end_by_source[source_file] = int(
            action.get("source_byte_end", -1)
        )
    for record in candidates:
        if not isinstance(record, dict):
            raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: record")
        record_sha256 = str(record.get("record_sha256") or "").lower()
        unsigned_record = {
            key: value
            for key, value in record.items()
            if key not in {"record_sha256", "debt_id"}
        }
        if record_sha256 != _niche_identity_debt_digest(unsigned_record):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: record hash"
            )
        if record.get("debt_id") != f"NID-{record_sha256[:24].upper()}":
            raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: debt id")
        if (
            record.get("identity_authority") is not False
            or record.get("clean_authority") is not False
            or record.get("drop_authority") is not False
            or record.get("proof_authority") != "NONE"
            or record.get("resolution_status") != "UNRESOLVED"
            or record.get("required_action") not in {
                "RECONCILE_PRODUCER_IDENTITY",
                "RECONCILE_SOURCE_ACTION_DRIFT",
                "REPAIR_FINDING_BLOCK_SCHEMA",
            }
            or not record.get("identity_debt")
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: record authority"
            )
        start = record.get("source_byte_start")
        end = record.get("source_byte_end")
        size = record.get("source_block_size_bytes")
        source_size = record.get("source_size_bytes")
        source_file = str(record.get("source_file") or "")
        if (
            not isinstance(start, int)
            or not isinstance(end, int)
            or not isinstance(size, int)
            or not isinstance(source_size, int)
            or start < 0
            or end <= start
            or end > source_size
            or size != end - start
            or Path(source_file).name != source_file
            or not re.fullmatch(r"niche_[A-Za-z0-9_.-]+_findings\.md", source_file)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(record.get("source_sha256") or "")
            )
            or not re.fullmatch(
                r"[0-9a-f]{64}",
                str(record.get("source_block_sha256") or ""),
            )
        ):
            raise RuntimeError(f"invalid {_NICHE_IDENTITY_DEBT_NAME}: byte range")
        if record.get("source_action_identity") != _niche_source_action_identity(
            source_file=source_file,
            source_sha256=str(record.get("source_sha256") or ""),
            normalized_local_id=str(
                record.get("normalized_local_id") or ""
            ),
            source_byte_start=start,
            source_byte_end=end,
            source_block_sha256=str(
                record.get("source_block_sha256") or ""
            ),
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: debt action binding"
            )
        if record.get("exact_block_capture") == "FULL":
            try:
                captured = base64.b64decode(
                    str(record.get("exact_block_bytes_b64") or ""),
                    validate=True,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: block encoding"
                ) from exc
            if (
                len(captured) != size
                or hashlib.sha256(captured).hexdigest()
                != record.get("source_block_sha256")
            ):
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: block identity"
                )
        elif (
            record.get("exact_block_capture") != "OMITTED_OVERSIZE"
            or record.get("exact_block_bytes_b64")
            or size <= _NICHE_IDENTITY_DEBT_EXACT_BLOCK_MAX_BYTES
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: block capture status"
            )
        for field_name in (
            "title", "severity", "location", "description", "impact"
        ):
            field_bytes = str(record.get(field_name) or "").encode("utf-8")
            original_bytes = record.get(f"{field_name}_utf8_bytes")
            original_sha256 = str(
                record.get(f"{field_name}_sha256") or ""
            )
            truncated = record.get(f"{field_name}_truncated")
            if (
                len(field_bytes) > _NICHE_IDENTITY_DEBT_SEMANTIC_FIELD_MAX_BYTES
                or not isinstance(original_bytes, int)
                or original_bytes < len(field_bytes)
                or not re.fullmatch(
                    r"[0-9a-f]{64}",
                    original_sha256,
                )
                or not isinstance(truncated, bool)
                or (
                    not truncated
                    and (
                        original_bytes != len(field_bytes)
                        or original_sha256
                        != hashlib.sha256(field_bytes).hexdigest()
                    )
                )
                or (truncated and original_bytes <= len(field_bytes))
            ):
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: semantic bound"
                )
    for lifecycle_record in lifecycle_records:
        if not isinstance(lifecycle_record, dict):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: lifecycle record"
            )
        record_sha256 = str(
            lifecycle_record.get("record_sha256") or ""
        ).lower()
        unsigned_lifecycle = {
            key: value
            for key, value in lifecycle_record.items()
            if key not in {"record_sha256", "lifecycle_id"}
        }
        identity = str(
            lifecycle_record.get("source_action_identity") or ""
        )
        inventory_referents = lifecycle_record.get("inventory_referents")
        if (
            record_sha256 != _niche_identity_debt_digest(unsigned_lifecycle)
            or lifecycle_record.get("lifecycle_id")
            != f"NIDLIFE-{record_sha256[:24].upper()}"
            or lifecycle_record.get("status") != "DELIVERED_ACTION_REMOVED"
            or lifecycle_record.get("blocking") is not False
            or lifecycle_record.get("clean_authority") is not False
            or lifecycle_record.get("drop_authority") is not False
            or lifecycle_record.get("proof_authority") != "NONE"
            or not re.fullmatch(r"NACT-[0-9A-F]{24}", identity)
            or not _niche_removed_action_binding_valid(lifecycle_record)
            or not isinstance(inventory_referents, list)
            or inventory_referents
            != sorted({str(value) for value in inventory_referents})
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: lifecycle authority"
            )
    for source_error in source_errors:
        if not isinstance(source_error, dict):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source error"
            )
        record_sha256 = str(source_error.get("record_sha256") or "").lower()
        unsigned_error = {
            key: value
            for key, value in source_error.items()
            if key not in {"record_sha256", "debt_id"}
        }
        status = str(source_error.get("status") or "")
        if status == "SOURCE_OVER_LIMIT":
            status_valid = (
                source_error.get("required_action")
                == "REDUCE_AND_REVIEW_SOURCE_ARTIFACT"
                and source_error.get("identity_debt")
                == "SOURCE_ARTIFACT_OVER_LIMIT"
            )
        elif status == "SOURCE_MISSING":
            status_valid = (
                source_error.get("required_action")
                == "RESTORE_OR_RECONCILE_SOURCE_ARTIFACT"
                and source_error.get("identity_debt")
                == "SOURCE_ARTIFACT_MISSING_OR_RENAMED"
                and Path(str(source_error.get("source_file") or "")).name
                == str(source_error.get("source_file") or "")
                and bool(
                    re.fullmatch(
                        r"niche_[A-Za-z0-9_.-]+_findings\.md",
                        str(source_error.get("source_file") or ""),
                    )
                )
                and isinstance(source_error.get("source_size_bytes"), int)
                and int(source_error.get("source_size_bytes")) >= 0
                and bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}",
                        str(source_error.get("source_sha256") or ""),
                    )
                )
            )
        elif status == "SOURCE_ACTION_REMOVED":
            source_file = str(source_error.get("source_file") or "")
            normalized_local_id = str(
                source_error.get("normalized_local_id") or ""
            )
            start = source_error.get("source_byte_start")
            end = source_error.get("source_byte_end")
            status_valid = (
                source_error.get("required_action")
                == "RESTORE_OR_RECONCILE_SOURCE_ACTION"
                and source_error.get("identity_debt")
                == "SOURCE_ACTION_REMOVED"
                and Path(source_file).name == source_file
                and bool(_NICHE_SOURCE_NAME_RE.fullmatch(source_file))
                and isinstance(start, int)
                and isinstance(end, int)
                and start >= 0
                and end > start
                and isinstance(source_error.get("source_size_bytes"), int)
                and end <= int(source_error.get("source_size_bytes") or 0)
                and bool(normalized_local_id)
                and source_error.get("source_action_identity")
                == _niche_source_action_identity(
                    source_file=source_file,
                    source_sha256=str(
                        source_error.get("source_sha256") or ""
                    ),
                    normalized_local_id=normalized_local_id,
                    source_byte_start=start,
                    source_byte_end=end,
                    source_block_sha256=str(
                        source_error.get("source_block_sha256") or ""
                    ),
                )
                and _niche_removed_action_binding_valid(source_error)
            )
        elif status == "UNDELIVERED_CLEAN_ACTION":
            status_valid = (
                source_error.get("required_action")
                == "DELIVER_ACTION_TO_INVENTORY_OR_HUMAN_REVIEW"
                and source_error.get("identity_debt")
                == "UNDELIVERED_CLEAN_ACTION"
                and _niche_removed_action_binding_valid(source_error)
            )
        elif status == "SOURCE_CAPTURE_CORRUPTION":
            detail = str(source_error.get("detail") or "")
            detail_raw = detail.encode("utf-8")
            original_size = source_error.get("detail_utf8_bytes")
            detail_sha = str(source_error.get("detail_sha256") or "")
            truncated = source_error.get("detail_truncated")
            status_valid = (
                source_error.get("required_action")
                == "RECAPTURE_AND_RECONCILE_SOURCE_NAMESPACE"
                and source_error.get("identity_debt")
                == "SOURCE_CAPTURE_CORRUPTION"
                and source_error.get("source_file")
                == "<niche-source-namespace>"
                and isinstance(original_size, int)
                and original_size >= len(detail_raw)
                and isinstance(truncated, bool)
                and bool(re.fullmatch(r"[0-9a-f]{64}", detail_sha))
                and (
                    truncated
                    or (
                        original_size == len(detail_raw)
                        and detail_sha == hashlib.sha256(detail_raw).hexdigest()
                    )
                )
            )
        else:
            status_valid = False
        if (
            record_sha256 != _niche_identity_debt_digest(unsigned_error)
            or source_error.get("debt_id")
            != f"NIDSRC-{record_sha256[:24].upper()}"
            or not status_valid
            or source_error.get("clean_authority") is not False
            or source_error.get("drop_authority") is not False
            or source_error.get("proof_authority") != "NONE"
            or source_error.get("resolution_status") != "UNRESOLVED"
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source error authority"
            )
    expected_snapshots = payload.get("source_snapshots")
    if not isinstance(expected_snapshots, list):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source snapshots"
        )
    snapshot_names: set[str] = set()
    for snapshot in expected_snapshots:
        if not isinstance(snapshot, dict):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source snapshots"
            )
        source_file = str(snapshot.get("source_file") or "")
        if (
            source_file in snapshot_names
            or Path(source_file).name != source_file
            or not _NICHE_SOURCE_NAME_RE.fullmatch(source_file)
            or not re.fullmatch(
                r"[0-9a-f]{64}", str(snapshot.get("source_sha256") or "")
            )
            or not isinstance(snapshot.get("source_size_bytes"), int)
            or int(snapshot.get("source_size_bytes") or 0) < 0
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source snapshots"
            )
        snapshot_names.add(source_file)
    if expected_snapshots != sorted(
        expected_snapshots,
        key=lambda record: _niche_name_sort_key(str(record["source_file"])),
    ):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source snapshots"
        )

    source_namespace = payload.get("source_namespace")
    if source_namespace is None and not _validate_live_sources:
        source_namespace = sorted(snapshot_names, key=_niche_name_sort_key)
    if (
        not isinstance(source_namespace, list)
        or source_namespace != sorted(
            source_namespace, key=_niche_name_sort_key
        )
        or len(source_namespace) != len(set(source_namespace))
        or len(source_namespace)
        != len({str(name).casefold() for name in source_namespace})
        or any(
            not isinstance(name, str)
            or Path(name).name != name
            or not _NICHE_SOURCE_NAME_RE.fullmatch(name)
            for name in source_namespace
        )
    ):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source namespace"
        )
    source_namespace_sha256 = payload.get("source_namespace_sha256")
    if source_namespace_sha256 is None and not _validate_live_sources:
        source_namespace_sha256 = _niche_source_namespace_digest(
            source_namespace
        )
    if source_namespace_sha256 != _niche_source_namespace_digest(
        source_namespace
    ):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source namespace hash"
        )
    if not snapshot_names.issubset(set(source_namespace)):
        raise RuntimeError(
            f"invalid {_NICHE_IDENTITY_DEBT_NAME}: source snapshot namespace"
        )
    # Authenticate the mutable compatibility projection against the immutable
    # lifecycle CAS before consulting the live producer namespace.  Otherwise
    # a coordinated sidecar/source rewrite can be diagnosed merely as source
    # drift and obscure the stronger fact that it does not match committed
    # history.  Structural validation above still bounds every field supplied
    # to the lifecycle validator.
    if payload.get("lifecycle_authority_schema"):
        try:
            lifecycle_current = _validate_niche_lifecycle_projection(
                Path(scratchpad),
                payload,
                project_root=Path(scratchpad).parent,
            )
        except _NicheLifecycleAuthorityError as exc:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: identity-debt binding "
                f"changed; live source/lifecycle authority projection: {exc}"
            ) from exc
    if _validate_live_sources:
        root = Path(scratchpad)
        try:
            live_paths = _enumerate_niche_source_paths(root)
        except Exception as exc:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live source root"
            ) from exc
        live_namespace = [path.name for path in live_paths]
        if live_namespace != source_namespace:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live source namespace drift"
            )
        live_sources: dict[str, bytes] = {}
        live_snapshots: list[dict[str, Any]] = []
        oversized_names: set[str] = set()
        for source_path in live_paths:
            try:
                if source_path.lstat().st_size > _NICHE_FINDING_ARTIFACT_MAX_BYTES:
                    oversized_names.add(source_path.name)
                    continue
                source_bytes = _read_niche_source_bytes(source_path)
            except Exception as exc:
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live source "
                    f"missing or unreadable: {source_path.name}"
                ) from exc
            live_snapshots.append({
                "source_file": source_path.name,
                "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
                "source_size_bytes": len(source_bytes),
            })
            live_sources[source_path.name] = source_bytes
        if live_snapshots != expected_snapshots:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live source size/hash drift"
            )
        recorded_overlimit_names = {
            str(record.get("source_file") or "")
            for record in source_errors
            if record.get("status") == "SOURCE_OVER_LIMIT"
        }
        if oversized_names != recorded_overlimit_names:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live source over-limit drift"
            )
        if oversized_names and actions:
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live action denominator "
                "cannot be complete with an over-limit source"
            )
        inventory_path = root / "findings_inventory.md"
        try:
            inventory_text = read_bounded_regular_bytes(
                inventory_path,
                _NICHE_FINDING_ARTIFACT_MAX_BYTES,
                require_single_link=True,
            ).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            inventory_text = ""
        historical_actions = (
            [row["action_payload"] for row in lifecycle_current["action_history"]]
            if lifecycle_current is not None
            else actions
        )
        live_delivery_records = _validated_niche_delivery_records(
            inventory_text,
            historical_actions,
            authority_records=(
                lifecycle_current.get("delivery_records", [])
                if lifecycle_current is not None
                else ()
            ),
        )
        live_inventory_referents = _inventory_niche_action_referents(
            live_delivery_records
        )
        if (
            lifecycle_current is not None
            and live_delivery_records
            != list(lifecycle_current.get("delivery_records", []))
        ):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live typed delivery binding"
            )
        for lifecycle_record in lifecycle_records:
            identity = str(
                lifecycle_record.get("source_action_identity") or ""
            )
            if sorted(live_inventory_referents.get(identity, set())) != list(
                lifecycle_record.get("inventory_referents") or []
            ) or not live_inventory_referents.get(identity):
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live lifecycle delivery binding"
                )

        action_by_identity = {
            str(action["source_action_identity"]): action
            for action in actions
        }
        for record in (*actions, *candidates):
            source_file = str(record.get("source_file") or "")
            source_bytes = live_sources.get(source_file)
            start = int(record.get("source_byte_start", -1))
            end = int(record.get("source_byte_end", -1))
            if source_bytes is None or not 0 <= start < end <= len(source_bytes):
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live raw block range"
                )
            raw_block = source_bytes[start:end]
            if (
                len(raw_block) != record.get("source_block_size_bytes")
                or hashlib.sha256(raw_block).hexdigest()
                != record.get("source_block_sha256")
            ):
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live raw block "
                    "slice/hash drift"
                )
            if record in candidates:
                action = action_by_identity.get(
                    str(record.get("source_action_identity") or "")
                )
                if action is None or any(
                    action.get(field) != record.get(field)
                    for field in (
                        "source_file",
                        "source_sha256",
                        "source_size_bytes",
                        "source_byte_start",
                        "source_byte_end",
                        "source_block_sha256",
                        "source_block_size_bytes",
                        "normalized_local_id",
                    )
                ):
                    raise RuntimeError(
                        f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live debt/action binding"
                    )

        prior_end_by_source: dict[str, int] = {}
        for action in sorted(
            actions,
            key=lambda item: (
                str(item.get("source_file") or ""),
                int(item.get("source_byte_start", -1)),
                int(item.get("source_byte_end", -1)),
            ),
        ):
            source_file = str(action.get("source_file") or "")
            start = int(action.get("source_byte_start", -1))
            prior_end = prior_end_by_source.get(source_file)
            if prior_end is not None and start < prior_end:
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live action range overlap"
                )
            prior_end_by_source[source_file] = int(
                action.get("source_byte_end", -1)
            )
        if not oversized_names:
            try:
                live_entries = _parse_niche_findings(root)
            except Exception as exc:
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live action denominator parse"
                ) from exc
            live_action_records = [
                _niche_action_record(entry) for entry in live_entries
            ]
            if _niche_action_bindings(live_action_records) != _niche_action_bindings(
                actions
            ):
                raise RuntimeError(
                    f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live action denominator mismatch"
                )
        stored_live_digest = payload.get("live_action_denominator_sha256")
        if stored_live_digest != _niche_live_action_denominator_digest(actions):
            raise RuntimeError(
                f"invalid {_NICHE_IDENTITY_DEBT_NAME}: live action denominator hash"
            )
    return payload


def _write_niche_identity_debt_sidecar(
    scratchpad: Path,
    identity_debts: list[dict[str, Any]],
    source_errors: Optional[list[dict[str, Any]]] = None,
    *,
    actions: Optional[list[dict[str, Any]]] = None,
    source_namespace: Optional[list[str]] = None,
    source_snapshots: Optional[list[dict[str, Any]]] = None,
    lifecycle_records: Optional[list[dict[str, Any]]] = None,
    lifecycle_authority: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Publish the complete current action denominator plus unresolved debt."""

    by_debt_id: dict[str, dict[str, Any]] = {}
    for entry in identity_debts:
        record = _niche_identity_debt_record(entry)
        by_debt_id[record["debt_id"]] = record
    by_source_error_id: dict[str, dict[str, Any]] = {}
    for record in source_errors or []:
        by_source_error_id[str(record["debt_id"])] = dict(record)
    candidates = sorted(
        by_debt_id.values(),
        key=lambda record: (
            str(record["source_file"]),
            str(record["source_sha256"]),
            int(record["source_byte_start"]),
            int(record["source_byte_end"]),
            str(record["debt_id"]),
        ),
    )
    merged_source_errors = sorted(
        by_source_error_id.values(),
        key=lambda record: (
            str(record["source_file"]),
            int(record["source_size_bytes"]),
            str(record["debt_id"]),
        ),
    )
    action_records = sorted(
        (_niche_action_record(entry) for entry in (actions or [])),
        key=lambda record: (
            str(record["source_file"]),
            int(record["source_byte_start"]),
            str(record["normalized_local_id"]),
            str(record["source_action_identity"]),
        ),
    )
    if source_namespace is None or source_snapshots is None:
        source_paths = _enumerate_niche_source_paths(Path(scratchpad))
        if source_namespace is None:
            source_namespace = [path.name for path in source_paths]
        if source_snapshots is None:
            source_snapshots = []
            for source_path in source_paths:
                try:
                    source_snapshots.append(_niche_source_snapshot(source_path))
                except ValueError:
                    if source_path.lstat().st_size <= _NICHE_FINDING_ARTIFACT_MAX_BYTES:
                        raise
    namespace = sorted(
        (str(value) for value in (source_namespace or [])),
        key=_niche_name_sort_key,
    )
    snapshots = sorted(
        (
            {
                "source_file": str(record.get("source_file") or ""),
                "source_sha256": str(record.get("source_sha256") or ""),
                "source_size_bytes": int(record.get("source_size_bytes") or 0),
            }
            for record in (source_snapshots or [])
        ),
        key=lambda record: _niche_name_sort_key(str(record["source_file"])),
    )
    lifecycle_rows = sorted(
        (dict(record) for record in (lifecycle_records or [])),
        key=lambda record: (
            str(record.get("source_file") or ""),
            str(record.get("source_action_identity") or ""),
            str(record.get("lifecycle_id") or ""),
        ),
    )
    payload: dict[str, Any] = {
        "schema_version": _NICHE_IDENTITY_DEBT_SCHEMA,
        "artifact_role": "CANONICAL_UNRESOLVED_IDENTITY_DEBT",
        "required_consumer": "DEPTH_POSTPROCESSOR_IDENTITY_DEBT_GATE",
        "required_action": "CONSUME_AND_RECONCILE_ALL_CANDIDATES",
        "denominator_complete": True,
        "action_count": len(action_records),
        "action_set_sha256": _niche_action_set_digest(action_records),
        "live_action_denominator_sha256": (
            _niche_live_action_denominator_digest(action_records)
        ),
        "candidate_count": len(candidates),
        "source_error_count": len(merged_source_errors),
        "blocking_debt_count": len(candidates) + len(merged_source_errors),
        "lifecycle_count": len(lifecycle_rows),
        "lifecycle_set_sha256": _niche_lifecycle_set_digest(lifecycle_rows),
        "removed_action_count": len(
            _niche_removed_action_records(
                merged_source_errors, lifecycle_rows
            )
        ),
        "removed_action_set_sha256": _niche_removed_action_set_digest(
            merged_source_errors, lifecycle_rows
        ),
        "clean_authority": False,
        "proof_authority": "NONE",
        "drop_authority": False,
        "source_namespace": namespace,
        "source_namespace_sha256": _niche_source_namespace_digest(namespace),
        "source_snapshots": snapshots,
        "actions": action_records,
        "candidates": candidates,
        "source_errors": merged_source_errors,
        "lifecycle_records": lifecycle_rows,
    }
    if lifecycle_authority is not None:
        payload.update(
            _niche_lifecycle_projection_binding(lifecycle_authority)
        )
    payload["artifact_sha256"] = _niche_identity_debt_digest(payload)
    rendered = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    if len(rendered.encode("utf-8")) > _NICHE_IDENTITY_DEBT_SIDECAR_MAX_BYTES:
        raise RuntimeError(
            "NICHE_IDENTITY_DEBT_SIDECAR_OVER_LIMIT: unresolved debt exceeds "
            f"{_NICHE_IDENTITY_DEBT_SIDECAR_MAX_BYTES} bytes"
        )
    _promo_atomic_write_text(
        Path(scratchpad) / _NICHE_IDENTITY_DEBT_NAME,
        rendered,
    )
    return payload


_INVENTORY_FINDING_HEADING_CONTENT_RE = re.compile(
    r"^(?:Finding\s*)?\[\s*(INV-[0-9]+)\s*\](?:\s*[:\-].*)?$",
    re.IGNORECASE,
)


def _operational_inventory_finding_blocks(
    text: str,
) -> list[tuple[str, str]]:
    """Return real CommonMark inventory headings and their same-level blocks."""

    source = str(text or "")
    operational = operational_markdown_view(source)
    headings = mapped_headings(source)
    out: list[tuple[str, str]] = []
    for index, heading in enumerate(headings):
        match = _INVENTORY_FINDING_HEADING_CONTENT_RE.match(
            str(heading["content"]).strip()
        )
        if match is None:
            continue
        end = len(source)
        for later in headings[index + 1:]:
            if int(later["level"]) <= int(heading["level"]):
                end = int(later["start"])
                break
        out.append((
            match.group(1).upper(),
            operational[int(heading["start"]):end],
        ))
    return out


def _operational_inventory_finding_records(
    text: str,
) -> list[dict[str, str]]:
    """Return operational fields plus the exact authored block digest."""

    source = str(text or "")
    operational = operational_markdown_view(source)
    headings = mapped_headings(source)
    out: list[dict[str, str]] = []
    for index, heading in enumerate(headings):
        match = _INVENTORY_FINDING_HEADING_CONTENT_RE.match(
            str(heading["content"]).strip()
        )
        if match is None:
            continue
        start = int(heading["start"])
        end = len(source)
        for later in headings[index + 1:]:
            if int(later["level"]) <= int(heading["level"]):
                end = int(later["start"])
                break
        exact = source[start:end].rstrip() + "\n"
        out.append({
            "inventory_id": match.group(1).upper(),
            "operational_block": operational[start:end],
            "inventory_block_sha256": hashlib.sha256(
                exact.encode("utf-8", errors="strict")
            ).hexdigest(),
        })
    return out


def _operational_inventory_field(
    block: str,
    labels: tuple[str, ...],
) -> str:
    """Read one real, line-level bold field from an operational block."""

    for label in labels:
        match = re.search(
            rf"(?im)^\s*(?:[-*]\s*)?\*\*{re.escape(label)}\*\*"
            rf"\s*:\s*([^\r\n]+?)\s*$",
            block,
        )
        if match is not None:
            return match.group(1).strip().strip("`")
    return ""


def _niche_delivery_record(
    action: Mapping[str, Any],
    *,
    inventory_id: str,
    inventory_block_sha256: str,
) -> dict[str, Any]:
    record = {
        "source_action_identity": str(action["source_action_identity"]),
        "source_file": str(action["source_file"]),
        "normalized_local_id": str(
            action.get("normalized_local_id") or action.get("source_id") or ""
        ),
        "source_sha256": str(action["source_sha256"]),
        "source_byte_start": int(action["source_byte_start"]),
        "source_byte_end": int(action["source_byte_end"]),
        "source_block_sha256": str(action["source_block_sha256"]),
        "inventory_id": str(inventory_id).upper(),
        "inventory_block_sha256": str(inventory_block_sha256),
    }
    record["delivery_record_sha256"] = _niche_identity_debt_digest(record)
    return record


def _validated_niche_delivery_records(
    text: str,
    actions: Sequence[Mapping[str, Any]],
    *,
    authority_records: Sequence[Mapping[str, Any]] = (),
    newly_written_inventory_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Validate exact one-to-one delivery under typed producer authority.

    Markdown is evidence only.  An otherwise exact block is delivery authority
    only when its record was already committed in the lifecycle CAS or its
    inventory ID was written by this invocation before the next CAS commit.
    """

    blocks = _operational_inventory_finding_records(text)
    occurrences: dict[str, list[dict[str, str]]] = {}
    for row in blocks:
        identity = _operational_inventory_field(
            row["operational_block"], ("Source Action Identity",)
        ).strip().upper()
        if re.fullmatch(r"NACT-[0-9A-F]{24}", identity):
            occurrences.setdefault(identity, []).append(row)
    prior = {
        str(row.get("source_action_identity") or ""): dict(row)
        for row in authority_records
        if isinstance(row, Mapping)
    }
    new_ids = {str(value).upper() for value in newly_written_inventory_ids}
    accepted: list[dict[str, Any]] = []
    used_inventory: set[str] = set()
    for action in actions:
        identity = str(action.get("source_action_identity") or "")
        candidates = occurrences.get(identity, [])
        if len(candidates) != 1:
            continue
        row = candidates[0]
        block = row["operational_block"]
        artifact = Path(_operational_inventory_field(
            block, ("Primary Artifact", "Source Artifact")
        )).name
        source_ids = _operational_inventory_field(
            block, ("Source IDs", "Source ID")
        )
        local_ids = {
            token.upper()
            for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]*-[0-9]+", source_ids)
        }
        source_hash = _operational_inventory_field(
            block, ("Source Artifact Hash",)
        ).lower()
        if source_hash.startswith("sha256:"):
            source_hash = source_hash[7:]
        range_text = _operational_inventory_field(block, ("Source Byte Range",))
        range_match = re.fullmatch(r"([0-9]+)-([0-9]+)", range_text)
        block_hash = _operational_inventory_field(
            block, ("Source Block SHA256",)
        ).lower()
        expected_local = str(
            action.get("normalized_local_id") or action.get("source_id") or ""
        ).upper()
        if (
            artifact != str(action.get("source_file") or "")
            or expected_local not in local_ids
            or source_hash != str(action.get("source_sha256") or "").lower()
            or range_match is None
            or int(range_match.group(1)) != int(action.get("source_byte_start", -1))
            or int(range_match.group(2)) != int(action.get("source_byte_end", -1))
            or block_hash != str(action.get("source_block_sha256") or "").lower()
        ):
            continue
        candidate = _niche_delivery_record(
            action,
            inventory_id=row["inventory_id"],
            inventory_block_sha256=row["inventory_block_sha256"],
        )
        old = prior.get(identity)
        authorized = row["inventory_id"] in new_ids or old == candidate
        if not authorized or row["inventory_id"] in used_inventory:
            continue
        used_inventory.add(row["inventory_id"])
        accepted.append(candidate)
    return sorted(
        accepted,
        key=lambda row: (row["source_action_identity"], row["inventory_id"]),
    )


def _inventory_niche_action_referents(
    delivery_records: Sequence[Mapping[str, Any]],
) -> dict[str, set[str]]:
    """Project only typed, PhaseIO-committed delivery records."""

    if isinstance(delivery_records, (str, bytes, bytearray)):
        return {}
    return {
        str(row["source_action_identity"]): {str(row["inventory_id"]).upper()}
        for row in delivery_records
    }


def _inventory_niche_action_bindings(text: str) -> list[dict[str, str]]:
    """Recover exact niche action keys from structurally typed inventory rows."""

    bindings: list[dict[str, str]] = []
    for inventory_id, block in _operational_inventory_finding_blocks(text):
        artifact = Path(
            _operational_inventory_field(
                block, ("Primary Artifact", "Source Artifact")
            )
        ).name
        action_identity = _operational_inventory_field(
            block, ("Source Action Identity",)
        ).strip().upper()
        source_ids = _operational_inventory_field(
            block, ("Source IDs", "Source ID")
        )
        if (
            not artifact.startswith("niche_")
            or not re.fullmatch(r"NACT-[0-9A-F]{24}", action_identity)
        ):
            continue
        producer = _registered_producer_for_artifact(
            artifact,
            consumer="pre_dedup_promotion",
        )
        source_pattern = (
            _registered_producer_read_id_pattern(producer)
            if producer is not None
            else _PROMOTABLE_FEEDER_ID_PATTERN
        )
        local_ids = re.findall(
            r"\b" + source_pattern + r"\b",
            source_ids,
            re.IGNORECASE,
        )
        if not local_ids:
            continue
        bindings.append(
            {
                "source_file": artifact,
                "normalized_local_id": local_ids[0].upper(),
                "source_action_identity": action_identity,
                "inventory_id": inventory_id,
            }
        )
    return bindings


def _niche_current_run_id(scratchpad: Path, explicit: str = "") -> str:
    run = str(explicit or "").strip()
    if run:
        return run
    checkpoint = Path(scratchpad) / "_v2_checkpoint.json"
    try:
        value = json.loads(
            read_bounded_regular_bytes(
                checkpoint, 4 * 1024 * 1024, require_single_link=True
            ).decode("utf-8", errors="strict")
        )
        if isinstance(value, dict):
            run = str(value.get("run_id") or "").strip()
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        run = ""
    if run:
        return run
    # Direct unit tests and legacy library callers do not own a driver
    # checkpoint. Keep that compatibility path isolated to this scratchpad;
    # production passes the canonical UUID explicitly at the driver boundary.
    identity = os.path.normcase(
        os.path.normpath(os.fspath(Path(scratchpad).resolve()))
    )
    return "standalone-" + hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()[:32]


def _finalize_niche_lifecycle_authority(
    scratchpad: Path,
    *,
    retained_capture: Any,
    parsed_all: list[dict[str, Any]],
    lifecycle_source_errors: list[dict[str, Any]],
    lifecycle_records: list[dict[str, Any]],
    project_root: Path,
    run_id: str,
    dimensions: dict[str, str],
    delivery_records: Sequence[Mapping[str, Any]],
    inventory_publication_capability: object | None = None,
) -> dict[str, Any]:
    """Commit the typed lifecycle, then publish its legacy projection."""

    action_records = [
        _niche_action_record(entry) for entry in parsed_all
    ]
    # The immutable lifecycle generation must be derived from one retained
    # current-input view.  The long-lived source capture protects parsing and
    # inventory mutation; this post-mutation capture then retains both that
    # exact source namespace and the resulting inventory through PhaseIO/CAS
    # publication.  A same-byte pathname replacement therefore cannot acquire
    # idempotent authority merely because its content digest is unchanged.
    with retain_bounded_regular_namespace(
        Path(scratchpad),
        _NICHE_CURRENT_INPUT_NAME_RE,
        per_file_limit=_NICHE_FINDING_ARTIFACT_MAX_BYTES,
        total_limit=(
            _NICHE_SOURCE_NAMESPACE_MAX_BYTES
            + _NICHE_FINDING_ARTIFACT_MAX_BYTES
        ),
        max_members=129,
        require_single_link=True,
    ) as current_inputs:
        current_source_names = tuple(
            name for name in current_inputs.namespace
            if _NICHE_SOURCE_NAME_RE.fullmatch(name)
        )
        if current_source_names != tuple(retained_capture.namespace):
            raise BoundedNamespaceCaptureError(
                "source namespace changed before lifecycle current-input capture"
            )
        for name in current_source_names:
            previous = retained_capture.files[name]
            current = current_inputs.files[name]
            if (
                previous.raw != current.raw
                or previous.sha256 != current.sha256
                or previous.size != current.size
                or previous.physical_identity != current.physical_identity
            ):
                raise BoundedNamespaceCaptureError(
                    "source member changed before lifecycle current-input capture: "
                    + name
                )
        inventory_file = current_inputs.files.get("findings_inventory.md")
        inventory_bytes = (
            inventory_file.raw if inventory_file is not None else None
        )
        current_inputs.revalidate()
        authority = _commit_niche_lifecycle_generation(
            Path(scratchpad),
            project_root=Path(project_root),
            run_id=run_id,
            dimensions=dimensions,
            retained_capture=current_inputs,
            actions=action_records,
            inventory_bytes=inventory_bytes,
            delivery_records=delivery_records,
            inventory_publication_capability=inventory_publication_capability,
        )
    action_history = {
        row["source_action_identity"]: row["action_payload"]
        for row in authority["action_history"]
    }
    source_errors_by_key = {
        (
            str(row.get("status") or ""),
            str(row.get("source_action_identity") or row.get("debt_id") or ""),
        ): dict(row)
        for row in lifecycle_source_errors
    }
    lifecycle_by_identity = {
        str(row.get("source_action_identity") or ""): dict(row)
        for row in lifecycle_records
    }
    for transition in authority["transitions"]:
        identity = transition["source_action_identity"]
        payload = action_history.get(identity)
        if payload is None:
            raise RuntimeError(
                "NICHE_LIFECYCLE_ACTION_HISTORY_MISSING: " + identity
            )
        if transition["state"] == "UNDELIVERED_CLEAN_ACTION":
            row = _niche_undelivered_clean_action_error(payload)
            source_errors_by_key[(row["status"], identity)] = row
        elif transition["state"] == "SOURCE_ACTION_REMOVED":
            row = _niche_removed_action_source_error(payload)
            source_errors_by_key[(row["status"], identity)] = row
            lifecycle_by_identity.pop(identity, None)
        elif transition["state"] == "DELIVERED_ACTION_REMOVED":
            row = _niche_delivered_action_lifecycle_record(
                payload,
                set(transition["inventory_referents"]),
            )
            lifecycle_by_identity[identity] = row
            source_errors_by_key.pop(("SOURCE_ACTION_REMOVED", identity), None)
        elif transition["state"] == "DELIVERED_CLEAN_ACTION":
            source_errors_by_key.pop(
                ("UNDELIVERED_CLEAN_ACTION", identity), None
            )
    source_namespace = list(retained_capture.namespace)
    source_snapshots = [
        {
            "source_file": name,
            "source_sha256": retained_capture.files[name].sha256,
            "source_size_bytes": retained_capture.files[name].size,
        }
        for name in source_namespace
    ]
    identity_debts = [
        entry for entry in parsed_all if entry.get("identity_debt")
    ]
    payload = _write_niche_identity_debt_sidecar(
        Path(scratchpad),
        identity_debts,
        list(source_errors_by_key.values()),
        actions=parsed_all,
        source_namespace=source_namespace,
        source_snapshots=source_snapshots,
        lifecycle_records=list(lifecycle_by_identity.values()),
        lifecycle_authority=authority,
    )
    try:
        _validate_niche_lifecycle_projection(
            Path(scratchpad), payload, project_root=Path(project_root)
        )
    except _NicheLifecycleAuthorityError as exc:
        raise RuntimeError(
            "NICHE_LIFECYCLE_PROJECTION_INVALID: " + str(exc)
        ) from exc
    return authority


def _publish_niche_capture_blocking_projection(
    scratchpad: Path,
    detail: object,
) -> None:
    """Best-effort haltless debt when immutable lifecycle commit is impossible."""

    try:
        payload = _write_niche_identity_debt_sidecar(
            Path(scratchpad),
            [],
            [_niche_capture_corruption_error(detail)],
            actions=[],
            source_namespace=[],
            source_snapshots=[],
            lifecycle_records=[],
        )
        payload["lifecycle_authority_status"] = "BLOCKED"
        payload["artifact_sha256"] = _niche_identity_debt_digest({
            key: value for key, value in payload.items()
            if key != "artifact_sha256"
        })
        _promo_atomic_write_text(
            Path(scratchpad) / _NICHE_IDENTITY_DEBT_NAME,
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            ) + "\n",
        )
    except Exception:
        # The original capture error remains the authoritative failure. This
        # best-effort projection must never hide or replace it.
        return


def _publish_niche_overlimit_blocking_projection(scratchpad: Path) -> bool:
    """Publish typed legacy debt when namespace capture fails only on size.

    Oversized producer artifacts cannot enter the immutable lifecycle CAS
    because their bytes were never captured.  They can still be represented
    precisely as blocking compatibility debt, including an exact namespace and
    bounded snapshots for every other member.  The projection carries no clean,
    drop, or proof authority and is replaced only after a safe full recapture.
    """

    try:
        root = Path(scratchpad)
        source_paths = _enumerate_niche_source_paths(root)
        overlimit = [
            path for path in source_paths
            if int(path.lstat().st_size) > _NICHE_FINDING_ARTIFACT_MAX_BYTES
        ]
        if not overlimit:
            return False
        snapshots: list[dict[str, Any]] = []
        for path in source_paths:
            if path in overlimit:
                continue
            raw = _read_niche_source_bytes(path)
            snapshots.append({
                "source_file": path.name,
                "source_sha256": hashlib.sha256(raw).hexdigest(),
                "source_size_bytes": len(raw),
            })
        payload = _write_niche_identity_debt_sidecar(
            root,
            [],
            [_niche_identity_source_error(path) for path in overlimit],
            actions=[],
            source_namespace=[path.name for path in source_paths],
            source_snapshots=snapshots,
            lifecycle_records=[],
        )
        payload["lifecycle_authority_status"] = "BLOCKED"
        payload["artifact_sha256"] = _niche_identity_debt_digest({
            key: value for key, value in payload.items()
            if key != "artifact_sha256"
        })
        _promo_atomic_write_text(
            root / _NICHE_IDENTITY_DEBT_NAME,
            json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            ) + "\n",
        )
        return True
    except Exception:
        return False


def promote_niche_to_inventory(
    scratchpad: Path,
    *,
    project_root: Optional[Path] = None,
    run_id: str = "",
    pipeline: str = "sc",
    mode: str = "thorough",
    ecosystem: str = "evm",
    backend: str = "claude",
    _retained_capture: Any = None,
) -> tuple[int, int]:
    """Promote niche agent findings into findings_inventory.md as INV-* entries.

    Niche agents (semantic consistency, dimensional analysis, event
    completeness, semantic gap investigator) write to niche_*_findings.md
    during depth phase iteration 1. These files reach chain analysis via
    chain_summaries_compact.md but do NOT enter findings_inventory.md, which
    is the source of truth for verification_queue.md. Result: niche findings
    are never verified or reported.

    This function appends niche findings to findings_inventory.md, continuing
    the INV-NNN numbering. Idempotence comes only from typed delivery records
    in the immutable lifecycle CAS; the Markdown receipt is diagnostic and
    cannot certify a colliding/stale local ID or source-action identity.

    Call site: post-depth phase completion in plamen_driver.py, after
    _canonicalize_depth_iter_filenames but before sc_semantic_dedup runs.

    Returns (parsed_count, appended_count).
    """
    root = Path(scratchpad)
    project = Path(project_root) if project_root is not None else root.parent
    current_run = _niche_current_run_id(root, run_id)
    dimensions = {
        "pipeline": str(pipeline or "sc").strip().lower(),
        "mode": str(mode or "thorough").strip().lower(),
        "ecosystem": str(ecosystem or "evm").strip().lower(),
        "backend": str(backend or "claude").strip().lower(),
        "phase": "depth",
        "producer": "niche_promotion",
    }
    expected_context = _niche_lifecycle_context(
        project_root=project,
        run_id=current_run,
        dimensions=dimensions,
    )
    if _retained_capture is None:
        try:
            # Reject a stale/cross-run chain before mutating inventory or any
            # compatibility projection.
            _load_current_niche_lifecycle(
                root,
                project_root=project,
                expected_run_id=current_run,
                expected_context=expected_context,
            )
            with retain_bounded_regular_namespace(
                root,
                _NICHE_SOURCE_NAME_RE,
                per_file_limit=_NICHE_FINDING_ARTIFACT_MAX_BYTES,
                total_limit=_NICHE_SOURCE_NAMESPACE_MAX_BYTES,
                max_members=128,
                require_single_link=True,
            ) as retained:
                return promote_niche_to_inventory(
                    root,
                    project_root=project,
                    run_id=current_run,
                    pipeline=dimensions["pipeline"],
                    mode=dimensions["mode"],
                    ecosystem=dimensions["ecosystem"],
                    backend=dimensions["backend"],
                    _retained_capture=retained,
                )
        except (
            BoundedNamespaceCaptureError,
            _NicheLifecycleAuthorityError,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            if (
                isinstance(exc, BoundedNamespaceCaptureError)
                and "namespace member exceeds" in str(exc)
                and _publish_niche_overlimit_blocking_projection(root)
            ):
                raise RuntimeError("SOURCE_OVER_LIMIT: " + str(exc)) from exc
            _publish_niche_capture_blocking_projection(root, exc)
            if "CROSS_RUN_REPLAY" in str(exc):
                raise RuntimeError("CROSS_RUN_REPLAY") from exc
            raise RuntimeError(
                "NICHE_SOURCE_CAPTURE_OR_LIFECYCLE_CHANGED: " + str(exc)
            ) from exc
    retained_capture = _retained_capture
    prior_authority = _load_current_niche_lifecycle(
        root,
        project_root=project,
        expected_run_id=current_run,
        expected_context=expected_context,
    )
    prior = read_niche_identity_debt_sidecar(
        scratchpad,
        _validate_live_sources=False,
    )
    if prior is None:
        if prior_authority is not None:
            # Reconstruct the historical inputs solely from the immutable CAS;
            # the mutable sidecar is never needed to preserve a tombstone.
            prior_actions = [
                dict(row["action_payload"])
                for row in prior_authority["action_history"]
            ]
            prior_source_errors: list[dict[str, Any]] = []
            prior_lifecycle: list[dict[str, Any]] = []
            by_identity = {
                row["source_action_identity"]: row
                for row in prior_authority["action_history"]
            }
            for transition in prior_authority["transitions"]:
                payload = by_identity[transition["source_action_identity"]][
                    "action_payload"
                ]
                if transition["state"] == "SOURCE_ACTION_REMOVED":
                    prior_source_errors.append(
                        _niche_removed_action_source_error(payload)
                    )
                elif transition["state"] == "UNDELIVERED_CLEAN_ACTION":
                    prior_source_errors.append(
                        _niche_undelivered_clean_action_error(payload)
                    )
                elif transition["state"] == "DELIVERED_ACTION_REMOVED":
                    prior_lifecycle.append(
                        _niche_delivered_action_lifecycle_record(
                            payload,
                            set(transition["inventory_referents"]),
                        )
                    )
            prior = {
                "actions": prior_actions,
                "source_errors": prior_source_errors,
                "lifecycle_records": prior_lifecycle,
                "source_snapshots": prior_authority[
                    "source_capture"
                ]["source_snapshots"],
            }
    source_paths = [root / name for name in retained_capture.namespace]
    source_namespace = [path.name for path in source_paths]
    current_source_names = {path.name for path in source_paths}
    lifecycle_source_errors = [
        _niche_identity_missing_source_error(snapshot)
        for snapshot in (prior or {}).get("source_snapshots", [])
        if str(snapshot.get("source_file") or "") not in current_source_names
    ]
    for prior_error in (prior or {}).get("source_errors", []):
        if (
            prior_error.get("status") == "SOURCE_MISSING"
            and str(prior_error.get("source_file") or "")
            not in current_source_names
        ):
            lifecycle_source_errors.append(dict(prior_error))
    source_snapshots: list[dict[str, Any]] = [
        {
            "source_file": name,
            "source_sha256": retained_capture.files[name].sha256,
            "source_size_bytes": retained_capture.files[name].size,
        }
        for name in source_namespace
    ]
    parsed_all = _reconcile_niche_action_drift(
        scratchpad,
        _parse_niche_findings(
            scratchpad, _retained_capture=retained_capture
        ),
        prior=prior,
    )
    parsed_count = len(parsed_all)
    identity_debts = [
        entry for entry in parsed_all if entry.get("identity_debt")
    ]
    # Shape alone is never promotion authority. Registered, debt-free IDs may
    # enter inventory; every other explicit finding stays quarantined below.
    parsed = [
        entry for entry in parsed_all
        if entry.get("identity_status") == "REGISTERED"
        and not entry.get("identity_debt")
    ]

    inventory_path = scratchpad / "findings_inventory.md"
    if not inventory_path.exists():
        removed_action_errors, lifecycle_records = _reconcile_niche_removed_actions(
            scratchpad, parsed_all, prior, delivered={}
        )
        lifecycle_source_errors.extend(removed_action_errors)
        _finalize_niche_lifecycle_authority(
            root,
            retained_capture=retained_capture,
            parsed_all=parsed_all,
            lifecycle_source_errors=lifecycle_source_errors,
            lifecycle_records=lifecycle_records,
            project_root=project,
            run_id=current_run,
            dimensions=dimensions,
            delivery_records=[],
        )
        return parsed_count, 0
    try:
        inventory_pre_bytes = read_bounded_regular_bytes(
            inventory_path,
            _NICHE_FINDING_ARTIFACT_MAX_BYTES,
            require_single_link=True,
        )
        inv_text = inventory_pre_bytes.decode("utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "NICHE_INVENTORY_CAPTURE_UNSAFE: findings_inventory.md"
        ) from exc
    historical_action_payloads = (
        [row["action_payload"] for row in prior_authority["action_history"]]
        if prior_authority is not None
        else list((prior or {}).get("actions", []))
    )
    prior_delivery_records = _validated_niche_delivery_records(
        inv_text,
        historical_action_payloads,
        authority_records=(
            prior_authority.get("delivery_records", [])
            if prior_authority is not None
            else ()
        ),
    )
    structural_referents = _inventory_niche_action_referents(
        prior_delivery_records
    )
    removed_action_errors, lifecycle_records = _reconcile_niche_removed_actions(
        scratchpad, parsed_all, prior, delivered=structural_referents
    )
    lifecycle_source_errors.extend(removed_action_errors)
    receipt_path = scratchpad / "niche_promotion_receipt.md"
    already_promoted: set[str] = set(structural_referents)

    def _identity_debt_receipt_lines() -> list[str]:
        if not identity_debts:
            return []
        lines = ["", "## Identity Reconciliation Debt", ""]
        lines.extend(
            f"- {entry['source_action_identity']} | {entry['source_id']} | "
            f"status={entry['identity_status']} | "
            f"debt={entry['identity_debt']} | source={entry['source_file']} | "
            "authority=false | quarantine=true"
            for entry in identity_debts
        )
        return lines

    # Only immutable typed delivery records are idempotence authority. Raw
    # inventory structure and the Markdown receipt remain evidence, so a bare
    # or mismatched Source Action Identity cannot suppress real promotion.
    new_entries = [
        entry for entry in parsed
        if entry["source_action_identity"] not in already_promoted
    ]
    if not new_entries:
        # Rebuild the human-readable projection from the authenticated typed
        # delivery records. The receipt itself never enters this decision.
        recovered = [
            (
                entry["source_action_identity"],
                entry["source_id"],
                sorted(
                    structural_referents.get(
                        entry["source_action_identity"], set()
                    )
                )[0],
            )
            for entry in parsed
            if structural_referents.get(entry["source_action_identity"])
        ]
        if recovered or identity_debts:
            receipt_lines = [
                "# Niche Promotion Receipt",
                "",
                f"Parsed niche findings: {parsed_count}",
                f"Already promoted (structural recovery): {len(recovered)}",
                "Newly appended this run: 0",
                "",
                "## Source-to-Inventory ID Mapping",
                "",
            ]
            receipt_lines.extend(
                f"- {action_identity} | {source_id} -> {inventory_id} "
                "(recovered from exact Source Action Identity)"
                for action_identity, source_id, inventory_id in recovered
            )
            receipt_lines.extend(_identity_debt_receipt_lines())
            rendered = "\n".join(receipt_lines) + "\n"
            if receipt_path.exists():
                try:
                    prior_text = receipt_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                    receipt_path.write_text(
                        prior_text.rstrip() + "\n\n## Re-Run\n\n" + rendered,
                        encoding="utf-8",
                    )
                except Exception:
                    receipt_path.write_text(rendered, encoding="utf-8")
            else:
                receipt_path.write_text(rendered, encoding="utf-8")
        _finalize_niche_lifecycle_authority(
            root,
            retained_capture=retained_capture,
            parsed_all=parsed_all,
            lifecycle_source_errors=lifecycle_source_errors,
            lifecycle_records=lifecycle_records,
            project_root=project,
            run_id=current_run,
            dimensions=dimensions,
            delivery_records=prior_delivery_records,
        )
        return parsed_count, 0

    # Find highest existing INV-NNN to continue numbering
    max_inv = 0
    for m in re.finditer(r"\bINV-(\d+)\b", inv_text):
        try:
            max_inv = max(max_inv, int(m.group(1)))
        except ValueError:
            continue

    # Build appended entries
    appended_lines: list[str] = []
    mapping_lines: list[str] = []
    new_inventory_ids: set[str] = set()
    for idx, entry in enumerate(new_entries, start=1):
        inv_n = max_inv + idx
        title = entry["title"] or "Untitled niche finding"
        inv_id = _allocate_inventory_ledger_id(
            scratchpad,
            preferred_id=f"INV-{inv_n:03d}",
            owner_phase="niche_promotion",
            owning_artifact="findings_inventory.md",
            title=title,
        )
        # v2.0.6 (P2.2): register the niche-promoted INV in the ledger.
        try:
            from plamen_parsers import id_ledger_register
            id_ledger_register(
                scratchpad,
                finding_id=inv_id,
                owner_phase="niche_promotion",
                owner_attempt=1,
                owning_artifact="findings_inventory.md",
                title=title,
            )
        except Exception as e:
            log.debug(f"[niche] ledger register skipped for {inv_id}: {e}")
        sev = _severity_name_from_text("", {"severity": entry["severity"]})
        loc = entry["location"]
        tag = entry["preferred_tag"]
        desc = entry["description"] or title
        impact = entry["impact"]
        appended_lines.extend([
            f"### Finding [{inv_id}]: {title}",
            f"**Severity**: {sev}",
            f"**Location**: {loc}",
            f"**Preferred Tag**: {tag}",
            f"**Source IDs**: {entry['source_id']} (niche-promoted from {entry['source_file']})",
            f"**Primary Artifact**: {entry['source_file']}",
            f"**Source Artifact Hash**: sha256:{entry['source_sha256']}",
            f"**Source Byte Range**: {entry['source_byte_start']}-{entry['source_byte_end']}",
            f"**Source Block SHA256**: {entry['source_block_sha256']}",
            f"**Source Action Identity**: {entry['source_action_identity']}",
            f"**Verdict**: NEEDS_VERIFICATION",
            f"**Root Cause**: {title}",
            f"**Description**: {desc}",
            f"**Impact**: {impact}",
            "",
        ])
        mapping_lines.append(
            f"- {entry['source_action_identity']} | {entry['source_id']} -> {inv_id} "
            f"({entry['source_file']}: {title[:80]})"
        )
        new_inventory_ids.add(inv_id.upper())

    # Append to inventory (preserve trailing newline behavior)
    section_header = (
        "\n\n## Niche-Promoted Findings\n\n"
        "Findings discovered by niche agents (semantic consistency, "
        "dimensional analysis, event completeness, semantic gap investigator) "
        "during depth phase iteration 1. Promoted post-depth so they reach "
        "the verification queue and chain analysis with the same first-class "
        "status as breadth/depth findings.\n\n"
    )
    existing = inv_text.rstrip()
    new_text = existing + section_header + "\n".join(appended_lines) + "\n"
    if len(new_text.encode("utf-8")) > _NICHE_FINDING_ARTIFACT_MAX_BYTES:
        raise RuntimeError(
            "NICHE_INVENTORY_PUBLICATION_OVER_LIMIT: findings_inventory.md"
        )
    try:
        current_inventory = read_bounded_regular_bytes(
            inventory_path,
            _NICHE_FINDING_ARTIFACT_MAX_BYTES,
            require_single_link=True,
        ).decode("utf-8", errors="replace")
    except (OSError, ValueError) as exc:
        raise RuntimeError(
            "NICHE_INVENTORY_CAPTURE_UNSAFE: findings_inventory.md"
        ) from exc
    if current_inventory != inv_text:
        raise RuntimeError(
            "NICHE_INVENTORY_CAPTURE_CHANGED_BEFORE_PUBLICATION"
        )
    combined_action_payloads = {
        str(row.get("source_action_identity") or ""): row
        for row in historical_action_payloads
    }
    combined_action_payloads.update({
        str(row.get("source_action_identity") or ""): row for row in parsed_all
    })
    delivery_records = _validated_niche_delivery_records(
        new_text,
        list(combined_action_payloads.values()),
        authority_records=prior_delivery_records,
        newly_written_inventory_ids=new_inventory_ids,
    )

    # Receipt for idempotency
    receipt_lines = [
        "# Niche Promotion Receipt",
        "",
        f"Parsed niche findings: {parsed_count}",
        f"Already promoted (prior attempt): {len(already_promoted)}",
        f"Newly appended this run: {len(new_entries)}",
        "",
        "## Source-to-Inventory ID Mapping",
        "",
    ]
    receipt_lines.extend(mapping_lines)
    receipt_lines.extend(_identity_debt_receipt_lines())
    receipt_lines.append("")
    # Preserve prior mappings across retries
    if receipt_path.exists():
        try:
            prior_text = receipt_path.read_text(encoding="utf-8", errors="replace")
            # Append rather than overwrite to preserve prior-run history
            receipt_path.write_text(
                prior_text.rstrip() + "\n\n## Re-Run\n\n" + "\n".join(receipt_lines),
                encoding="utf-8",
            )
        except Exception:
            receipt_path.write_text("\n".join(receipt_lines), encoding="utf-8")
    else:
        receipt_path.write_text("\n".join(receipt_lines), encoding="utf-8")

    inventory_publication_capability: object | None = None
    try:
        inventory_publication_capability = (
            _issue_niche_inventory_publication_capability(
                root,
                project_root=project,
                run_id=current_run,
                dimensions=dimensions,
                expected_pre_bytes=inventory_pre_bytes,
                expected_post_bytes=new_text.encode("utf-8"),
                max_bytes=_NICHE_FINDING_ARTIFACT_MAX_BYTES,
            )
        )
        _finalize_niche_lifecycle_authority(
            root,
            retained_capture=retained_capture,
            parsed_all=parsed_all,
            lifecycle_source_errors=lifecycle_source_errors,
            lifecycle_records=lifecycle_records,
            project_root=project,
            run_id=current_run,
            dimensions=dimensions,
            delivery_records=delivery_records,
            inventory_publication_capability=inventory_publication_capability,
        )
    finally:
        if inventory_publication_capability is not None:
            _discard_niche_inventory_publication_capability(
                inventory_publication_capability
            )

    # Re-write finding records only after the immutable delivery authority is
    # current.  This mutable sidecar cannot certify the publication.
    try:
        _write_finding_records_from_inventory(scratchpad)
    except Exception:
        pass
    return parsed_count, len(new_entries)


# Blind-spot scanner finding IDs: BLIND-A1, BLIND-B3, BLIND-C5 (per-scanner
# letter + running number), or BLIND-1. NOTE: the niche regex requires
# digits-immediately-after-dash and would MISS the letter+digit suffix form.
_BLIND_SPOT_HEADING_RE = re.compile(
    r"^#{2,4}\s*Finding\s*\[\s*(?P<id>BLIND-[A-Z]?\d+)\s*\]\s*:\s*(?P<title>.+?)\s*$",
    re.MULTILINE,
)
_BLIND_SPOT_REQUIRED_FIELDS = (
    "Severity",
    "Location",
    "Description",
    "Impact",
)


def _parse_blind_spot_findings(scratchpad: Path) -> list[dict[str, str]]:
    """Parse blind_spot_*_findings.md into structured finding entries. Mirrors
    `_parse_niche_findings` (same required-field guard + field extraction) but
    matches the BLIND-* id form. Conservative: requires the standard fields near
    the heading so methodology preambles are not mistaken for findings."""
    entries: list[dict[str, str]] = []
    for p in sorted(scratchpad.glob("blind_spot_*_findings.md")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        matches = list(_BLIND_SPOT_HEADING_RE.finditer(text))
        for i, m in enumerate(matches):
            start = m.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            block = text[start:end]
            if not all(
                f"**{field}**" in block
                for field in _BLIND_SPOT_REQUIRED_FIELDS
            ):
                continue
            fid = m.group("id").strip()
            title = m.group("title").strip()
            sev_match = re.search(r"\*\*Severity\*\*\s*:\s*([A-Za-z]+)", block, re.IGNORECASE)
            loc_match = re.search(
                r"\*\*Location\*\*\s*:\s*(.+?)(?=\n\*\*|\n\n|$)", block,
                re.IGNORECASE | re.DOTALL)
            tag_match = re.search(
                r"\*\*Preferred\s*Tag\*\*\s*:\s*(\[[A-Z\-]+\])", block, re.IGNORECASE)
            desc_match = re.search(
                r"\*\*Description\*\*\s*:\s*(.+?)(?=\n\*\*[A-Z]|\n##|\Z)", block,
                re.IGNORECASE | re.DOTALL)
            impact_match = re.search(
                r"\*\*Impact\*\*\s*:\s*(.+?)(?=\n\*\*[A-Z]|\n##|\Z)", block,
                re.IGNORECASE | re.DOTALL)
            entries.append({
                "source_file": p.name,
                "source_id": fid,
                "title": title,
                "severity": (sev_match.group(1).strip() if sev_match else "Medium"),
                "location": (_norm_loc(loc_match.group(1).strip()) if loc_match else "UNKNOWN"),
                "preferred_tag": (tag_match.group(1).strip() if tag_match else "[CODE-TRACE]"),
                "description": (_strip_md(desc_match.group(1).strip())[:1500] if desc_match else title),
                "impact": (_strip_md(impact_match.group(1).strip())[:800]
                           if impact_match else "Impact requires verifier confirmation."),
                "raw_block": block,
            })
    return entries


def promote_blind_spot_to_inventory(scratchpad: Path) -> tuple[int, int]:
    """Recover LEAKED blind-spot scanner findings into findings_inventory.md.

    Unlike niche findings (which never reach the inventory by design), blind-spot
    findings (BLIND-*) normally DO reach it via the LLM inventory merge. But that
    merge has been observed to SILENTLY DROP a scored blind-spot finding whose
    siblings were promoted (e.g. BLIND-B3 scored 0.47, siblings B1/B2 promoted,
    B3 vanished) — so it never reached verify/report. This is a recall leak.

    This promotes ONLY the leaked ones: any BLIND-* id that is ABSENT from
    findings_inventory.md is appended as an INV-* entry (present ones are left
    untouched — no duplication). Idempotent via a receipt. Recall-safe:
    append-only, never drops, never overwrites a present finding.

    Call site: post-depth, alongside `promote_niche_to_inventory`.
    Returns (parsed_count, recovered_count).
    """
    inventory_path = scratchpad / "findings_inventory.md"
    if not inventory_path.exists():
        return 0, 0
    try:
        inv_text = inventory_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0, 0

    parsed = _parse_blind_spot_findings(scratchpad)
    if not parsed:
        return 0, 0

    receipt_path = scratchpad / "blind_spot_promotion_receipt.md"
    structural_sources = set(_inventory_structural_source_referents(inv_text))
    already_promoted: set[str] = set()
    if receipt_path.exists():
        try:
            for line in receipt_path.read_text(encoding="utf-8", errors="replace").splitlines():
                mm = re.search(r"\b(BLIND-[A-Z]?\d+)\s*->\s*INV-\d+", line)
                if mm and mm.group(1).upper() in structural_sources:
                    already_promoted.add(mm.group(1))
        except Exception:
            pass

    def _already_in_inventory(bid: str) -> bool:
        return bid.upper() in structural_sources

    # LEAKED = a parsed BLIND id that is NOT already accounted in the inventory
    # (as a Source ID / heading) AND not already recovered on a prior attempt.
    missing = [
        e for e in parsed
        if not _already_in_inventory(e["source_id"])
        and e["source_id"] not in already_promoted
    ]
    if not missing:
        return len(parsed), 0

    max_inv = 0
    for m in re.finditer(r"\bINV-(\d+)\b", inv_text):
        try:
            max_inv = max(max_inv, int(m.group(1)))
        except ValueError:
            continue

    appended_lines: list[str] = []
    mapping_lines: list[str] = []
    for idx, entry in enumerate(missing, start=1):
        inv_n = max_inv + idx
        title = entry["title"] or "Untitled blind-spot finding"
        inv_id = _allocate_inventory_ledger_id(
            scratchpad, preferred_id=f"INV-{inv_n:03d}",
            owner_phase="blind_spot_promotion",
            owning_artifact="findings_inventory.md", title=title)
        try:
            from plamen_parsers import id_ledger_register
            id_ledger_register(
                scratchpad, finding_id=inv_id, owner_phase="blind_spot_promotion",
                owner_attempt=1, owning_artifact="findings_inventory.md", title=title)
        except Exception as e:
            log.debug(f"[blind_spot] ledger register skipped for {inv_id}: {e}")
        sev = _severity_name_from_text("", {"severity": entry["severity"]})
        appended_lines.extend([
            f"### Finding [{inv_id}]: {title}",
            f"**Severity**: {sev}",
            f"**Location**: {entry['location']}",
            f"**Preferred Tag**: {entry['preferred_tag']}",
            f"**Source IDs**: {entry['source_id']} "
            f"(blind-spot-recovered; LEAKED from {entry['source_file']} — "
            "scored but dropped by the inventory merge)",
            "**Verdict**: NEEDS_VERIFICATION",
            f"**Root Cause**: {title}",
            f"**Description**: {entry['description'] or title}",
            f"**Impact**: {entry['impact']}",
            "",
        ])
        mapping_lines.append(
            f"- {entry['source_id']} -> {inv_id} ({entry['source_file']}: {title[:80]})")

    section_header = (
        "\n\n## Blind-Spot-Recovered Findings\n\n"
        "Blind-spot scanner findings that were SCORED but silently dropped by the "
        "inventory merge (a recall leak). Mechanically recovered so they reach the "
        "verification queue with first-class status. Recall-safe: append-only.\n\n"
    )
    inventory_path.write_text(
        inv_text.rstrip() + section_header + "\n".join(appended_lines) + "\n",
        encoding="utf-8")

    receipt_lines = [
        "# Blind-Spot Promotion Receipt", "",
        f"Parsed blind-spot findings: {len(parsed)}",
        f"Already recovered (prior attempt): {len(already_promoted)}",
        f"Newly recovered this run (LEAKED): {len(missing)}", "",
        "## Source-to-Inventory ID Mapping", "",
    ]
    receipt_lines.extend(mapping_lines)
    receipt_lines.append("")
    if receipt_path.exists():
        try:
            prior = receipt_path.read_text(encoding="utf-8", errors="replace")
            receipt_path.write_text(
                prior.rstrip() + "\n\n## Re-Run\n\n" + "\n".join(receipt_lines),
                encoding="utf-8")
        except Exception:
            receipt_path.write_text("\n".join(receipt_lines), encoding="utf-8")
    else:
        receipt_path.write_text("\n".join(receipt_lines), encoding="utf-8")

    try:
        _write_finding_records_from_inventory(scratchpad)
    except Exception:
        pass
    return len(parsed), len(missing)


_ATTENTION_REPAIR_MAX_ITEMS = 32
_ATTENTION_EXACT_SCOPE_MAX_FILES = 512


_FACET_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("asset-binding-mismatch", r"\b(?:mismatch|not\s+match|does\s+not\s+match|diverge|different)\b.*\b(?:asset|token|coin|amount|target|recipient|params|decoded|input|output)\b|\b(?:asset|token|coin|amount|target|recipient|params|decoded|input|output)\b.*\b(?:mismatch|not\s+match|does\s+not\s+match|diverge|different)\b"),
    ("swap-skip-or-divergence", r"\b(?:skip|empty|bypass|not\s+execute|without\s+swap|swapData|swap)\b"),
    ("refund-provenance", r"\b(?:refund|revert|rollback|failed)\b.*\b(?:recipient|sender|source|address|provenance)\b"),
    ("source-authentication", r"\b(?:source\s+sender|sender|origin|source\s+chain|chainid|authenticat|verify)\b"),
    ("native-token-branch", r"\b(?:native|wrapped|wrap|unwrap|msg\.value|payable|sentinel|WETH|W[A-Z0-9_]+)\b"),
    ("approval-execution-amount", r"\b(?:approve|allowance)\b.*\b(?:amount|fee|deduct|full|original|mismatch)\b|\b(?:fee|deduct)\b.*\b(?:approve|swap|amount)\b"),
    ("slippage-minout", r"\b(?:slippage|min(?:imum)?(?:Amount)?Out|minReturn|amountOutMin|sandwich|MEV)\b"),
    ("pool-or-route-trust", r"\b(?:pool|pair|router|route|reserve|oracle|quote)\b.*\b(?:exist|select|trust|manipulat|check)\b"),
    ("access-control", r"\b(?:public|external|onlyOwner|role|access\s+control|permission|admin|owner|withdraw|sweep)\b"),
    ("encoding-width-or-layout", r"\b(?:bytes\d*|length|cast|decode|encode|deserialize|layout|struct|writable|signer|permission)\b"),
)


def _write_security_obligations(
    scratchpad: Path,
    mode: str = "core",
    *,
    ecosystem: str = "",
    run_id: str = "",
    source_snapshot_digest: str = "",
    stage: str = "post_depth",
) -> int:
    """Write the typed P1-C authority and its Markdown projection.

    The return value counts rule-owned security obligations, excluding the
    additive SO-000 substrate/authority debt row.  Queue construction reads
    the JSON authority through ``_parse_security_obligation_items`` below.
    """
    payload = _write_security_obligation_authority(
        Path(scratchpad),
        mode=str(mode or "core"),
        ecosystem=str(ecosystem or ""),
        run_id=str(run_id or ""),
        source_snapshot_digest=str(source_snapshot_digest or ""),
        stage=str(stage or "post_depth"),
    )
    return sum(
        1
        for row in payload.get("obligations", [])
        if isinstance(row, dict) and row.get("display_id") != "SO-000"
    )


def _parse_security_obligation_items(scratchpad: Path) -> list[dict[str, str]]:
    """Read only current, non-accounted rows from typed P1-C authority.

    A corrupt/missing authority returns one SO-000 review row; it never falls
    back to reconstructing methodology decisions from the Markdown view.
    """
    return _read_queueable_security_obligations(Path(scratchpad))


def _composition_obligation_rows(scratchpad: Path) -> list[dict[str, object]]:
    path = scratchpad / "composition_coverage.md"
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    # Dedup by distinct chain id (source_id). A single chain referenced across
    # ~10 lines of composition_coverage.md previously minted ~10 near-identical
    # active rows → 10 identical UNACCOUNTED-OBLIGATION Appendix-B clones. We
    # accumulate into a dict keyed on the chain id, keep the HIGHEST severity
    # signal, union the evidence/target lines, and OR the `declined` flag
    # CONSERVATIVELY (a chain is active if ANY contributing line is non-declined,
    # i.e. covered/declined only when EVERY line declined). Pure aggregation —
    # no severity-logic change, regression-safe.
    _SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    by_chain: dict[str, dict[str, object]] = {}
    order: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not re.search(r"\bCH-\d{1,4}\b", line, re.IGNORECASE):
            continue
        if not re.search(
            r"\b(?:UPGRADE|COMPOSED|CHAIN[-_ ]?UPGRADE|cross[-_ ]?user|"
            r"fund\s+loss|theft|drain|strand(?:s|ed|ing)?|freez(?:e|es|ing)|lock(?:s|ed|ing)?)\b",
            line,
            re.IGNORECASE,
        ):
            continue
        ids = sorted(set(m.group(0).upper() for m in re.finditer(r"\bCH-\d{1,4}\b", line, re.I)))
        rid = ids[0] if ids else f"CH-L{line_no}"
        sev = "High" if re.search(r"\b(?:critical|high|theft|drain|fund\s+loss)\b", line, re.I) else "Medium"
        # A composition row where the chain agent EXPLICITLY declined to promote a
        # formal CH ID ("CH-13 would be ... noting but not assigning formal CH ID")
        # must not mint an *active* retention obligation: there is no chain to
        # preserve, and the report-index retention gate would otherwise demand
        # coverage by an obligation token that names a hypothetical. Mint it as a
        # pre-closed row so the ledger still records it without forcing a retry.
        # Anchored decline detection (v2.8.8 hardening): the non-promotion
        # phrase MUST be tied to a chain/CH referent, so a real fund-loss chain
        # line that merely contains "declining"/"not assigning blame"/etc. is
        # NOT silently marked covered. Bare `declin\w*` was dropped for this
        # reason (re-audit flagged it as a recall-regression over-match).
        declined = bool(re.search(
            r"(?:noting\s+but\s+not\s+assign\w*|"
            r"not\s+assign\w*\s+(?:a\s+)?(?:formal\s+)?(?:ch\b|chain\b|ch[-\s]?id\b)|"
            r"no\s+formal\s+ch[-\s]?id\b|"
            r"not\s+(?:a\s+)?(?:formal\s+|standalone\s+)?(?:formal\s+)?chain\b|"
            r"not\s+promot\w*\s+(?:to\s+)?(?:a\s+)?(?:formal\s+)?(?:ch\b|chain\b))",
            line,
            re.IGNORECASE,
        ))
        existing = by_chain.get(rid)
        if existing is None:
            by_chain[rid] = {
                "id": f"OBL-CHAIN-{rid}",
                "class": "chain_upgrade_retention",
                "source_id": rid,
                # active if ANY line is non-declined (covered only if ALL declined)
                "_any_active": not declined,
                "severity_signal": sev,
                "source": "composition_coverage.md",
                "evidence": f"composition_coverage.md:L{line_no}",
                "target": line.strip()[:800],
                "absorbing_id": "",
            }
            order.append(rid)
        else:
            # keep highest severity
            if _SEV_RANK.get(sev, 99) < _SEV_RANK.get(
                str(existing["severity_signal"]), 99
            ):
                existing["severity_signal"] = sev
            # active if ANY contributing line is non-declined
            existing["_any_active"] = bool(existing["_any_active"]) or (not declined)
            # union evidence line refs and target excerpts (bounded)
            ev = str(existing["evidence"])
            existing["evidence"] = (ev + f"; L{line_no}")[:800]
            tgt = str(existing["target"])
            extra = line.strip()
            if extra and extra not in tgt:
                existing["target"] = (tgt + " | " + extra)[:800]

    rows: list[dict[str, object]] = []
    for rid in order:
        agg = by_chain[rid]
        active = bool(agg.pop("_any_active"))
        agg["status"] = "active" if active else "covered"
        agg["closure_reason"] = (
            ""
            if active
            else (
                "chain agent explicitly declined to promote a formal CH ID "
                "(hypothetical/non-chain composition)"
            )
        )
        rows.append(agg)
    return rows


def _deferred_chain_notes_projection(
    scratchpad: Path,
) -> tuple[set[str], bytes | None]:
    """Compute ONE clean deferred-High note per un-queue-able justified chain.

    A chain that `chain_hypotheses.md` upgraded to High/Critical with a
    justified Combined-Impact is a genuine compound finding. When it is
    genuinely un-queue-able IN-MODE (neither the chain id NOR any constituent
    reaches the verification queue — e.g. constituent body missing / PoC infra
    absent), leaving its obligation `active` would surface a noisy
    `UNACCOUNTED-OBLIGATION`. Instead we emit exactly ONE human-readable
    deferred note (e.g.
    `Deferred finding (chain-derived, estimated High) — needs verification:
    CH-01 = H-01 ⊕ H-23`) sourced from chain_hypotheses.md, written to a
    `report_semantic_chain_deferred.md` file that `_build_human_review_appendix`
    folds into AUDIT_REPORT.md so the human actually sees it.

    Returns the set of chain IDs that were rendered as deferred notes, so the
    caller can mark the matching obligation rows `covered`.

    Purely additive — never demotes/drops a finding; a chain that DOES reach the
    queue is left untouched (it goes to the body via the verify path).
    """
    try:
        forced = _forced_chain_seed_rows(scratchpad)
    except Exception:
        forced = {}
    if not forced:
        return set(), None
    # Verify-queue ID set: the chains that already have a body/verification home.
    queue_ids: set[str] = set()
    try:
        for r in parse_verification_queue_rows(scratchpad):
            fid = (r.get("finding id") or "").strip().upper()
            if fid:
                queue_ids.add(fid)
    except Exception:
        queue_ids = set()

    deferred: dict[str, dict[str, object]] = {}
    for cid, info in forced.items():
        constituents = [c.upper() for c in (info or {}).get("constituents", []) or []]
        # Queue-able when the chain id OR any constituent is in the queue.
        if cid in queue_ids or any(c in queue_ids for c in constituents):
            continue
        deferred[cid] = {
            "severity": str((info or {}).get("severity", "High")) or "High",
            "constituents": constituents,
        }
    if not deferred:
        return set(), None

    lines = ["# Report Semantic Chain Deferred", ""]
    lines.append(
        "Chain-derived compound findings that were upgraded to High/Critical "
        "with a justified Combined-Impact but could not be queued for "
        "verification in this mode (constituent body missing or PoC "
        "infrastructure absent). Flagged for human review — NOT silently "
        "dropped."
    )
    lines.append("")
    for cid in sorted(deferred):
        info = deferred[cid]
        sev = str(info.get("severity") or "High")
        cons = info.get("constituents") or []
        joined = " ⊕ ".join(cons) if cons else "(constituents unresolved)"
        lines.append(
            f"- Deferred finding (chain-derived, estimated {sev}) "
            f"— needs verification: {cid} = {joined}"
        )
    lines.append("")
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    return set(deferred.keys()), raw


def _render_deferred_chain_notes(scratchpad: Path) -> set[str]:
    """Legacy standalone projection writer retained for direct callers/tests."""

    deferred, raw = _deferred_chain_notes_projection(Path(scratchpad))
    if raw is not None:
        try:
            (Path(scratchpad) / "report_semantic_chain_deferred.md").write_bytes(raw)
        except Exception:
            pass
    return deferred


def _write_obligation_ledger(
    scratchpad: Path,
    mode: str,
    *,
    emit_deferred_report: bool = True,
) -> int:
    """Write a typed, protocol-neutral obligation ledger.

    The ledger is a deterministic retention contract, not a detector. Classes
    appear only when the audit artifacts trigger them, so protocols without
    chain compositions can legitimately have zero rows. The sole feeder is
    `_composition_obligation_rows` (CH-* chain-upgrade retention from
    composition_coverage.md), which carries no protocol-specific vocabulary.
    """
    obligations: list[dict[str, object]] = []
    obligations.extend(_composition_obligation_rows(scratchpad))

    # Render un-queue-able justified chains as ONE clean deferred-High note
    # each, then mark the matching obligation rows `covered` so the retention
    # gate is satisfied and no `UNACCOUNTED-OBLIGATION` clone is produced.
    try:
        deferred_chain_ids, _deferred_report_bytes = (
            _deferred_chain_notes_projection(scratchpad)
        )
        if emit_deferred_report and _deferred_report_bytes is not None:
            (Path(scratchpad) / "report_semantic_chain_deferred.md").write_bytes(
                _deferred_report_bytes
            )
    except Exception:
        deferred_chain_ids = set()
    if deferred_chain_ids:
        for row in obligations:
            if str(row.get("source_id") or "").upper() in deferred_chain_ids:
                row["status"] = "covered"
                row["closure_reason"] = "rendered as deferred chain note"

    payload = {
        "schema_version": "plamen.obligation_ledger.v1",
        "mode": mode,
        "row_count": len(obligations),
        "active_count": sum(1 for r in obligations if r.get("status") == "active"),
        "obligations": obligations,
    }
    (scratchpad / "obligation_ledger.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# Obligation Ledger",
        "",
        "Driver-generated typed retention obligations. These rows are "
        "questions/receipts, not expected findings. Empty class sets are valid "
        "when the protocol shape does not trigger them.",
        "",
        "| ID | Class | Status | Severity Signal | Target | Source |",
        "|----|-------|--------|-----------------|--------|--------|",
    ]
    if obligations:
        for row in obligations:
            target = str(row.get("target") or "").replace("|", "/")
            lines.append(
                f"| {row.get('id')} | {row.get('class')} | {row.get('status')} | "
                f"{row.get('severity_signal')} | `{target}` | {row.get('evidence')} |"
            )
    else:
        lines.append("| n/a | n/a | none | n/a | No obligations triggered. | n/a |")
    (scratchpad / "obligation_ledger.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return len(obligations)


def _extract_skill_execution_repair_items(scratchpad: Path, limit: int = 8) -> list[dict[str, str]]:
    path = scratchpad / "skill_execution_checklist.md"
    if not path.exists():
        return []
    try:
        text = _llm_norm(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    items: list[dict[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|") or _is_separator_row(s):
            continue
        cells = [c.strip().strip("`") for c in s.strip("|").split("|")]
        if len(cells) < 5 or cells[0].lower() == "skill":
            continue
        status = cells[2].upper()
        if "PARTIAL" not in status and "NOT_EXECUTED" not in status:
            continue
        skill = cells[0]
        agent = cells[1]
        gap = cells[4]
        items.append({
            "kind": "skill-execution-gap",
            "target": skill,
            "reason": f"{status}: required methodology gap for {agent}: {gap}",
            "source": "skill_execution_checklist.md",
            "evidence": f"{skill} row in skill_execution_checklist.md",
        })
        if len(items) >= limit:
            break
    return items


def _extract_candidate_facets(text: str) -> dict[str, list[str]]:
    norm = _llm_norm(text or "")
    mechanisms: list[str] = []
    for name, pattern in _FACET_KEYWORDS:
        if re.search(pattern, norm, re.IGNORECASE | re.DOTALL):
            mechanisms.append(name)
    functions = sorted({
        m.group(1)
        for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", norm)
        if m.group(1) not in {"if", "require", "assert", "revert", "return"}
    })[:12]
    fields = sorted({
        m.group(1)
        for m in re.finditer(r"\b(?:params|decoded|message|payload|data)\.([A-Za-z_][A-Za-z0-9_]*)\b", norm)
    })[:16]
    branch_terms = sorted({
        token
        for token in (
            "empty-input", "zero-value", "unauthenticated-source",
            "mismatched-parameter", "skipped-execution", "native-branch",
            "unbounded-decoding",
        )
        if (
            (token == "empty-input" and re.search(r"\bempty|length\s*==\s*0|\.length\s*==\s*0\b", norm, re.IGNORECASE))
            or (token == "zero-value" and re.search(r"\bzero|0\s*(?:amount|address|value)\b", norm, re.IGNORECASE))
            or (token == "unauthenticated-source" and re.search(r"\bunauth|missing\s+(?:sender|source).*validat|source\s+sender\b", norm, re.IGNORECASE))
            or (token == "mismatched-parameter" and re.search(r"\bmismatch|not\s+match|different\b", norm, re.IGNORECASE))
            or (token == "skipped-execution" and re.search(r"\bskip|bypass|not\s+execute|without\b", norm, re.IGNORECASE))
            or (token == "native-branch" and re.search(r"\bnative|wrapped|msg\.value|payable|sentinel\b", norm, re.IGNORECASE))
            or (token == "unbounded-decoding" and re.search(r"\bdecode|bytes|length|cast|deserialize\b", norm, re.IGNORECASE))
        )
    })
    return {
        "mechanisms": mechanisms,
        "entrypoints": functions,
        "decoded_fields": fields,
        "branch_conditions": branch_terms,
    }


def _write_candidate_semantic_facets(scratchpad: Path) -> int:
    rows = _report_candidate_universe_rows(scratchpad)
    finding_record_maps = _load_finding_record_maps(scratchpad)
    records: list[dict[str, object]] = []
    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        record = _finding_record_for_ids(scratchpad, [fid], finding_record_maps)
        parts = [
            fid,
            row.get("severity", ""),
            row.get("title", ""),
            row.get("location", ""),
            row.get("claim premise", ""),
            row.get("claim harm", ""),
            row.get("claim evidence", ""),
        ]
        if record:
            for key in ("title", "root_cause", "description", "impact", "location"):
                val = record.get(key)
                if val:
                    parts.append(str(val))
        vp = _verify_file_for_id(scratchpad, fid)
        if vp.exists():
            try:
                parts.append(vp.read_text(encoding="utf-8", errors="replace")[:80_000])
            except Exception:
                pass
        facets = _extract_candidate_facets("\n".join(parts))
        records.append({
            "id": fid,
            "severity": normalize_severity(row.get("severity", "")),
            "title": row.get("title", ""),
            "location": row.get("location", ""),
            "facets": facets,
        })
    payload = {
        "schema_version": "plamen.candidate_semantic_facets.v1",
        "candidate_count": len(records),
        "candidates": records,
    }
    (scratchpad / "candidate_semantic_facets.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# Candidate Semantic Facets",
        "",
        "Driver-extracted semantic hints for preservation checks. These facets "
        "are not findings; they are compact reminders of mechanism, branch, "
        "field, and entrypoint details that must survive merge/dedup/reporting.",
        "",
        "| Candidate ID | Severity | Mechanisms | Branch Conditions | Decoded Fields | Entrypoints |",
        "|--------------|----------|------------|-------------------|----------------|-------------|",
    ]
    for rec in records:
        facets = rec["facets"]
        assert isinstance(facets, dict)
        lines.append(
            f"| {rec['id']} | {rec['severity']} | "
            f"{', '.join(facets.get('mechanisms', [])) or '-'} | "
            f"{', '.join(facets.get('branch_conditions', [])) or '-'} | "
            f"{', '.join(facets.get('decoded_fields', [])) or '-'} | "
            f"{', '.join(facets.get('entrypoints', [])) or '-'} |"
        )
    if not records:
        lines.extend(("", "0 candidates; explicit empty denominator."))
    (scratchpad / "candidate_semantic_facets.md").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return len(records)


def _path_security_weight(path: str) -> int:
    """Rank uncovered files so repair stays bounded and security-relevant."""
    p = path.lower().replace("\\", "/")
    weights = (
        ("consensus", 9), ("validation", 9), ("block", 8), ("header", 8),
        ("transaction", 8), ("tx", 7), ("mempool", 7), ("p2p", 7),
        ("peer", 7), ("gossip", 7), ("network", 6), ("rpc", 6),
        ("api", 5), ("merkle", 8), ("proof", 8), ("vdf", 8),
        ("difficulty", 7), ("epoch", 6), ("fork", 6), ("cache", 5),
        ("storage", 5), ("database", 4), ("config", 2), ("test", -8),
    )
    return sum(w for token, w in weights if token in p)


def _spec_support_role(path: str) -> str:
    p = (path or "").replace("\\", "/").lower()
    leaf = p.rsplit("/", 1)[-1]
    if "harness" in leaf or "/harness" in p:
        return "harness invariant / fuzz expectation"
    if "/mock" in p or leaf.startswith(("mock", "fake", "stub")):
        return "mocked external dependency assumption"
    if leaf.endswith((".t.sol", ".test.ts", ".spec.ts", "_test.go", "_tests.rs")) or "/test" in p:
        return "test expectation / intended behavior"
    if "/script" in p or leaf.endswith(".s.sol"):
        return "deployment/script assumption"
    return "support/spec evidence"


def _write_spec_expectations(scratchpad: Path, support_paths: list[str] | set[str]) -> None:
    """Materialize support files as expectation evidence, not coverage debt.

    Attention repair should not spend audit budget proving mocks, tests, and
    harnesses safe. They are still valuable inputs: downstream agents can use
    them as claims to prove or break against production code.
    """
    paths = sorted({str(p).replace("\\", "/") for p in support_paths if str(p).strip()})
    out = scratchpad / "spec_expectations.md"
    if not paths:
        try:
            out.write_text(
                "# Spec Expectations\n\n"
                "**Status**: SKIPPED - no test/mock/harness support files were indexed.\n",
                encoding="utf-8",
            )
        except Exception:
            pass
        return
    lines = [
        "# Spec Expectations",
        "",
        "These files are excluded from production coverage-obligation queues "
        "such as attention_repair. Use them as specification evidence only: "
        "tests describe intended behavior, mocks describe assumed external "
        "behavior, and harnesses describe invariants to prove or break against "
        "production code. Do not report findings against these files unless "
        "they affect deployment, verification validity, or hide a production "
        "false negative.",
        "",
        "| # | File | Role | How downstream agents should use it |",
        "|---|------|------|--------------------------------------|",
    ]
    for i, path in enumerate(paths, 1):
        role = _spec_support_role(path)
        lines.append(
            f"| {i} | `{path}` | {role} | Derive expectations, then test "
            "production code against those expectations. |"
        )
    try:
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:
        pass


def _extract_graph_attention_rows(scratchpad: Path) -> list[dict[str, str]]:
    """Harvest all uncertain graph rows; the caller owns the loud queue cap."""
    rows: list[dict[str, str]] = []
    files = (
        "field_validation_matrix.md",
        "primitive_correctness_findings.md",
        "network_amplification_findings.md",
        "lifecycle_replay_findings.md",
        "panic_audit_summary.md",
    )
    signal_re = re.compile(
        r"\b(NEEDS_REVIEW|UNKNOWN|PARTIAL\s+GAP|PARTIAL|WEAK|GAP|MISSING|"
        r"Missing\?\s*\|\s*(?:YES|TRUE)|EXPLOITABLE)\b",
        re.IGNORECASE,
    )
    for name in files:
        p = scratchpad / name
        if not p.exists():
            continue
        try:
            text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("|") or _is_separator_row(stripped):
                continue
            if not signal_re.search(stripped):
                continue
            evidence = ", ".join(_extract_gap_paths_from_markdown(stripped)[:3])
            rows.append({
                "kind": "graph-row",
                "target": stripped[:500],
                "reason": f"uncertain or unsafe verdict in {name}",
                "source": name,
                "evidence": evidence or "row-level evidence required",
            })
    return rows


def _build_attention_repair_items(
    scratchpad: Path,
    mode: str,
    *,
    scope_file: str | None = None,
    scope_match_mode: str = "legacy",
    pipeline: str = "l1",
    language: str = "",
) -> list[dict[str, str]]:
    exact_scope_authority = (
        normalize_scope_match_mode(scope_match_mode) == "exact"
    )
    items: list[dict[str, str]] = []
    seen_targets: set[str] = set()
    cap_rows: list[dict] = []
    producer = "attention_repair"

    def add(kind: str, target: str, reason: str, source: str, evidence: str = "") -> None:
        key = f"{kind}:{target}"
        if target and key not in seen_targets:
            items.append({
                "kind": kind,
                "target": target,
                "reason": reason,
                "source": source,
                "evidence": evidence or target,
            })
            seen_targets.add(key)

    # P1-C cutover: attention repair is a read-only consumer of the bound
    # post-depth authority.  Re-deriving here would silently transfer semantic
    # ownership away from the two driver PhaseIO transactions and could account
    # receipts against a different input snapshot.
    if mode == "thorough":
        obligations = _parse_security_obligation_items(scratchpad)
        # Exact security aliases are mandatory application work, not optional
        # prioritization hints. Never drop alias 11+ from the repair queue.
        for obligation in obligations:
            exact_target = obligation.get("alias_id") or obligation["id"]
            relation_context = "; ".join(
                part
                for part in (
                    f"parent={obligation['id']}",
                    (
                        f"symbol={obligation.get('symbol')}"
                        if obligation.get("symbol")
                        else ""
                    ),
                    (
                        f"object={obligation.get('object_id')}"
                        if obligation.get("object_id")
                        else ""
                    ),
                )
                if part
            )
            add(
                "security-obligation",
                exact_target,
                (
                    f"{obligation['class']}: {obligation['question']}"
                    + (f" ({relation_context})" if relation_context else "")
                ),
                "security_obligations.md",
                obligation.get("signals", ""),
            )
        try:
            skill_items = _extract_skill_execution_repair_items(scratchpad)
            if len(skill_items) > 8:
                cap_rows.append(shortfall(
                    producer=producer,
                    scope="skill-execution-repairs",
                    cap="ATTENTION_SKILL_REPAIRS",
                    limit=8,
                    observed=len(skill_items),
                    retained=8,
                    exact=True,
                    samples=[row.get("target", "") for row in skill_items[8:]],
                    detail="skill-application repair obligations were omitted from the queue",
                ))
            for item in skill_items[:8]:
                add(
                    item["kind"],
                    item["target"],
                    item["reason"],
                    item["source"],
                    item.get("evidence", ""),
                )
        except Exception:
            pass
        try:
            for issue in _check_perturbation_block_per_finding(scratchpad):
                add(
                    "missing-perturbation-block",
                    issue[:240],
                    "depth finding lacks required sibling/field/direction/actor perturbation table",
                    "depth perturbation validator",
                    issue,
                )
        except Exception:
            pass

    if mode != "thorough":
        try:
            replace_producer_shortfalls(scratchpad, producer, [])
        except Exception:
            pass
        return items[:_ATTENTION_REPAIR_MAX_ITEMS]

    gap_file = scratchpad / "notread_priority_gaps.md"
    if gap_file.exists():
        try:
            text = _llm_norm(gap_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            text = ""
        if "All NOTREAD priority files received" not in text and "Status**: SKIPPED" not in text:
            for p in _extract_gap_paths_from_markdown(text):
                add("notread-file", p, "recon marked file NOTREAD and depth cited no evidence", gap_file.name)

    cov = _compute_scip_coverage_sets(
        scratchpad,
        scope_file=scope_file,
        scope_match_mode=scope_match_mode,
        pipeline=pipeline,
        language=language,
    )
    _write_spec_expectations(
        scratchpad,
        cov.get("spec_support_indexed", set()) if isinstance(cov, dict) else set(),
    )
    uncited = list(cov.get("uncited", []))
    if uncited:
        ranked = sorted(
            uncited,
            key=lambda p: (-_path_security_weight(str(p)), str(p)),
        )
        if exact_scope_authority:
            ranked_window = ranked[:_ATTENTION_EXACT_SCOPE_MAX_FILES]
            if len(ranked) > _ATTENTION_EXACT_SCOPE_MAX_FILES:
                cap_rows.append(shortfall(
                    producer=producer,
                    scope="exact-scope-uncited-files",
                    cap="ATTENTION_EXACT_SCOPE_MAX_FILES",
                    limit=_ATTENTION_EXACT_SCOPE_MAX_FILES,
                    observed=len(ranked),
                    retained=len(ranked_window),
                    exact=True,
                    samples=[
                        str(path)
                        for path in ranked[_ATTENTION_EXACT_SCOPE_MAX_FILES:]
                    ],
                    detail=(
                        "authorized exact-scope files exceeded the global "
                        "safety ceiling; omitted rows remain explicit final "
                        "coverage debt and cannot be reported COMPLETE"
                    ),
                ))
        else:
            ranked_window = ranked[:16]
        if not exact_scope_authority and len(ranked) > 16:
            cap_rows.append(shortfall(
                producer=producer,
                scope="uncited-security-files",
                cap="ATTENTION_UNCITED_FILES",
                limit=16,
                observed=len(ranked),
                retained=16,
                exact=True,
                samples=[str(path) for path in ranked[16:]],
                detail="uncited production files were omitted from attention repair",
            ))
        for ranked_idx, p in enumerate(ranked_window):
            if (
                not exact_scope_authority
                and _path_security_weight(str(p)) <= 0
                and len(items) >= 8
            ):
                cap_rows.append(shortfall(
                    producer=producer,
                    scope="uncited-low-weight-policy",
                    cap="ATTENTION_LOW_WEIGHT_QUEUE_FLOOR",
                    limit=ranked_idx,
                    observed=len(ranked_window),
                    retained=ranked_idx,
                    exact=True,
                    samples=[str(path) for path in ranked_window[ranked_idx:]],
                    detail="low-weight uncited files were not queued after the repair queue reached eight items",
                    kind="POLICY_SKIP",
                ))
                break
            add(
                "uncited-security-file",
                str(p),
                (
                    "exact scope citation coverage did not touch this "
                    "authorized file"
                    if exact_scope_authority
                    else "strict SCIP citation coverage did not touch this "
                    "security-relevant file"
                ),
                (
                    Path(scope_file).name
                    if exact_scope_authority and scope_file
                    else "scip/repo_map.md"
                ),
            )

    graph_rows = _extract_graph_attention_rows(scratchpad)
    if len(graph_rows) > 12:
        cap_rows.append(shortfall(
            producer=producer,
            scope="uncertain-graph-rows",
            cap="ATTENTION_GRAPH_ROWS",
            limit=12,
            observed=len(graph_rows),
            retained=12,
            exact=True,
            samples=[row.get("source", "") for row in graph_rows[12:]],
            detail="uncertain graph-analysis rows were omitted from attention repair",
        ))
    for row in graph_rows[:12]:
        add(row["kind"], row["target"], row["reason"], row["source"], row["evidence"])

    security_items = [
        row for row in items if row.get("kind") == "security-obligation"
    ]
    exact_scope_items = [
        row for row in items
        if exact_scope_authority
        and row.get("kind") == "uncited-security-file"
    ]
    optional_items = [
        row for row in items
        if row.get("kind") != "security-obligation"
        and row not in exact_scope_items
    ]
    optional_budget = max(
        0,
        _ATTENTION_REPAIR_MAX_ITEMS
        - len(security_items)
        - len(exact_scope_items),
    )
    retained_optional = optional_items[:optional_budget]
    retained_items = security_items + exact_scope_items + retained_optional
    if len(retained_optional) < len(optional_items):
        cap_rows.append(shortfall(
            producer=producer,
            scope="final-optional-repair-queue",
            cap="ATTENTION_OPTIONAL_REPAIR_MAX_ITEMS",
            limit=optional_budget,
            observed=len(optional_items),
            retained=len(retained_optional),
            exact=True,
            samples=[
                row.get("target", "")
                for row in optional_items[optional_budget:]
            ],
            detail=(
                "optional attention-repair rows exceeded the remaining worker "
                "queue budget; exact security obligations were retained"
            ),
        ))
    try:
        replace_producer_shortfalls(scratchpad, producer, cap_rows)
    except Exception:
        pass
    return retained_items


def _write_attention_repair_queue(scratchpad: Path, items: list[dict[str, str]]) -> None:
    binding_payload = [
        {
            "row": index,
            "kind": str(item["kind"]),
            "target": str(item["target"]),
            "reason": str(item["reason"]),
            "source": str(item["source"]),
            "evidence": str(item.get("evidence", "")),
        }
        for index, item in enumerate(items, 1)
    ]
    queue_binding = attention_queue_binding_sha256(binding_payload)
    lines = [
        "# Attention Repair Queue",
        "",
        f"QUEUE_BINDING_SHA256: {queue_binding}",
        "",
        "This is a deterministic, bounded repair queue. It is not a second",
        "breadth/depth pass. Audit only these rows, preserve SAFE verdicts,",
        "and emit findings only with file:line evidence.",
        "",
        "MANDATORY RECEIPT CONTRACT: attention_repair_summary.md must contain",
        "one table row per queue row. The Queue #, Kind, and Target cells must",
        "copy this queue exactly. For path targets, copy the full relative path",
        "instead of a basename or folder summary. The Evidence cell must cite",
        "the same target path again with file:line evidence, or mark the row",
        "NEEDS_HUMAN if the source file is unavailable.",
        "",
        "| # | Kind | Target | Reason | Source | Evidence hint |",
        "|---|------|--------|--------|--------|---------------|",
    ]
    for i, item in enumerate(items, 1):
        target = str(item["target"]).replace("|", "\\|")
        reason = str(item["reason"]).replace("|", "\\|")
        source = str(item["source"]).replace("|", "\\|")
        evidence = str(item.get("evidence", "")).replace("|", "\\|")
        lines.append(f"| {i} | {item['kind']} | `{target}` | {reason} | `{source}` | `{evidence}` |")
    (scratchpad / "attention_repair_queue.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def _write_attention_repair_skip(scratchpad: Path, reason: str) -> None:
    (scratchpad / "attention_repair_summary.md").write_text(
        "# Attention Repair\n\n"
        "**Status**: SKIPPED\n\n"
        f"Reason: {reason}\n",
        encoding="utf-8",
    )


def _prepare_attention_repair(
    scratchpad: Path,
    mode: str,
    *,
    scope_file: str | None = None,
    scope_match_mode: str = "legacy",
    pipeline: str = "l1",
    language: str = "",
) -> tuple[bool, str]:
    # The model is never authoritative for application receipts. A retry or a
    # newly-derived queue invalidates any prior deterministic gate receipt.
    (scratchpad / "attention_repair_application_receipt.json").unlink(
        missing_ok=True
    )
    items = _build_attention_repair_items(
        scratchpad,
        mode,
        scope_file=scope_file,
        scope_match_mode=scope_match_mode,
        pipeline=pipeline,
        language=language,
    )
    if not items:
        return False, f"mode={mode}; no NOTREAD, strict-coverage, or graph-row repair queue"
    _write_attention_repair_queue(scratchpad, items)
    return True, f"{len(items)} bounded repair item(s)"


def _normalize_breadth_outputs(scratchpad: Path) -> list[str]:
    """Breadth output compatibility shim (A5).

    Rename `findings_breadth_*.md` → `analysis_*.md` when the agent produced
    the older name convention. The v1.2.1 Track B fix (`_render_expected_output_block`)
    emits a HARD CONTRACT directive telling the LLM to use `analysis_*.md`, but
    LLMs occasionally drift anyway. Rather than falsely halt a run where the
    work was completed correctly, auto-rename before the gate globs.

    Logs the rename to `violations.md` so it is still tracked as a
    contract-drift event worth noticing in post-mortems. Returns the list of
    (old, new) pairs that were renamed.
    """
    renamed: list[str] = []
    fb_files = sorted(scratchpad.glob("findings_breadth_*.md"))
    if not fb_files:
        return renamed
    existing_analysis = {p.name for p in scratchpad.glob("analysis_*.md")}
    for fb in fb_files:
        # Derive target name by replacing the prefix.
        new_name = fb.name.replace("findings_breadth_", "analysis_", 1)
        if new_name in existing_analysis:
            # Both names exist — don't clobber; the gate will accept the
            # analysis_*.md one and the findings_breadth_*.md one becomes
            # orphan content. Log but don't move.
            renamed.append(f"{fb.name} -> SKIPPED (target {new_name} exists)")
            continue
        target = scratchpad / new_name
        try:
            fb.rename(target)
            renamed.append(f"{fb.name} -> {new_name}")
        except Exception as e:
            renamed.append(f"{fb.name} -> FAILED ({e})")
    if renamed:
        try:
            vp = scratchpad / "violations.md"
            with vp.open("a", encoding="utf-8") as f:
                f.write("\n## Breadth filename drift (A5 shim)\n")
                for r in renamed:
                    f.write(f"- {r}\n")
        except Exception:
            pass
    return renamed


_SOURCE_IDS_RE = re.compile(
    r"\*\*Source\s+IDs?\*\*\s*:\s*(.+)", re.IGNORECASE
)


def _extract_dedup_absorbed_ids(scratchpad: Path) -> set[str]:
    """Extract receipt-accepted semantic/mechanical dedup absorptions.

    Raw ``dedup_decisions.md`` rows are proposals and are never consumed here.

    These IDs are no longer standalone candidates — they are accounted for via
    the absorbing survivor.
    """
    try:
        from semantic_dedup_authority import load_applied_aliases

        return set(load_applied_aliases(Path(scratchpad)))
    except Exception as exc:
        log.warning(
            "[dedup-authority] coverage cannot trust raw absorbed proposals: %r",
            exc,
        )
        return set()

    # Legacy parser retained below for archaeology only; applied authority
    # returns above and never consumes raw proposal prose.
    absorbed: set[str] = set()
    for name in ("dedup_decisions.md",):
        path = scratchpad / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        # Format 1: LLM semantic dedup — | absorbed_id | MERGED into survivor |
        for m in re.finditer(
            r"^\|\s*(\S+)\s*\|\s*MERGED\s+into\b",
            text,
            re.MULTILINE | re.IGNORECASE,
        ):
            token = m.group(1).strip().strip("[]")
            if token and _INTERNAL_ID_RE.fullmatch(token):
                absorbed.add(token.upper())
        # Format 2: mechanical — | MECHANICAL_MERGE/SUPPLEMENT | absorbed_id | keep |
        for m in re.finditer(
            r"^\|\s*MECHANICAL_(?:MERGE|SUPPLEMENT)\s*\|\s*(\S+)\s*\|",
            text,
            re.MULTILINE | re.IGNORECASE,
        ):
            token = m.group(1).strip().strip("[]")
            if token and _INTERNAL_ID_RE.fullmatch(token):
                absorbed.add(token.upper())
    return absorbed


def _extract_source_ids_from_inventory(scratchpad: Path) -> set[str]:
    """Extract all Source IDs referenced by inventory findings.

    Inventory entries have ``**Source IDs**: CC-01, GC-4, DE-3`` lines.
    These are upstream breadth-level IDs already consolidated INTO INV-XXX
    findings — provenance metadata, not standalone candidates.
    """
    source_ids: set[str] = set()
    for name in ("findings_inventory.md", "findings_inventory_deduped.md"):
        path = scratchpad / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in _SOURCE_IDS_RE.finditer(text):
            for token in re.split(r"[,;\s]+", m.group(1).strip()):
                token = token.strip().strip("[]")
                if token and _INTERNAL_ID_RE.fullmatch(token):
                    source_ids.add(token.upper())
    return source_ids


def _collect_raw_candidate_ledger_rows(
    scratchpad: Path, promoted_ids: set[str], excluded_ids: set[str]
) -> list[str]:
    """Build report_coverage candidate trace rows from authoritative feeders.

    This ledger is a hard gate, so it must not scan broad prose artifacts.
    Depth/breadth/scanner files contain examples, cross-references, historical
    IDs, standards identifiers, and intentionally unqueued leads. Treat those
    as advisory analysis context, not report-index candidates. The reportable
    candidate set begins at inventory/queue/verification mapping boundaries.
    """
    # Source IDs in inventory entries are provenance metadata for promoted
    # findings — they are implicitly accounted, not standalone candidates.
    implicit_ids = _extract_source_ids_from_inventory(scratchpad)
    effective_promoted = promoted_ids | implicit_ids
    # Dedup-absorbed IDs were merged into surviving findings by the semantic
    # or mechanical dedup phase — they are accounted, not standalone.
    dedup_absorbed = _extract_dedup_absorbed_ids(scratchpad)

    # Only scan authoritative candidate sources — inventory and verification
    # files.  Chain analysis artifacts (hypotheses, chain_hypotheses,
    # finding_mapping) are structural groupings of inventory IDs, not candidate
    # sources.  Backup/evidence-excluded queues are pre-dedup snapshots whose
    # IDs are accounted via the dedup pipeline.
    source_globs = [
        "findings_inventory.md",
        "findings_inventory_deduped.md",
        "verification_queue*.md",
        "verify_core.md",
    ]
    _SKIP_SUFFIXES = ("_evidence_excluded.md", "_pre_dedup.md")
    seen: set[tuple[str, str]] = set()
    rows: list[str] = []
    for pattern in source_globs:
        for path in sorted(scratchpad.glob(pattern), key=lambda p: p.name.lower()):
            if not path.is_file():
                continue
            if any(path.name.endswith(sfx) for sfx in _SKIP_SUFFIXES):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            ids = sorted({m.group(1).upper() for m in _INTERNAL_ID_RE.finditer(text)})
            for fid in ids:
                key = (path.name, fid)
                if key in seen:
                    continue
                seen.add(key)
                if fid in effective_promoted:
                    disposition = "PROMOTED"
                elif fid in excluded_ids:
                    disposition = "EXCLUDED"
                elif fid in dedup_absorbed:
                    disposition = "MERGED"
                else:
                    disposition = "AUTO_EXCLUDED"
                rows.append(
                    f"| {path.name.replace('|', '/')} | {fid} | {disposition} |"
                )
    return rows


def _load_poc_demotion_caps(scratchpad: Path) -> dict[str, dict[str, str]]:
    """Return live typed PoC-negative severity caps.

    No such authority is cut over.  The former Markdown table represented an
    execution-scope proposal and is intentionally inert, including on resume
    from a scratchpad that still contains ``poc_demotions.md``.
    """
    _ = scratchpad
    return {}


# ── ZERO-DATA-LOSS mechanical dedup support (v2.9 dedup throughput upgrade) ──
#
# The mechanical dedup paths (fallback when the LLM dedup fails twice, and the
# supplemental pass on deferred candidate pairs) are the only places where a
# merge can be applied WITHOUT a per-pair LLM judgment. The DEDUP_AUDIT.md
# post-mortem proved that the worst false-merge class is the source-ID-subset /
# PERT-lineage signal misfiring on LARGE-AGGREGATE findings (perturbation /
# depth-aggregate findings carrying >4 depth source IDs): a single shared source
# ID makes the subset signal fire even though the defects differ. Blind merge on
# that signal would destroy 13+ true-positives.
#
# Two mechanical protections are added here and shared by BOTH paths:
#   1. Aggregate guard  — never act on a source-ID-subset / PERT-lineage signal
#      when EITHER finding has > _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD source IDs.
#   2. Survivor-superset gate — before committing a merge, the survivor's
#      source-ID set must be a SUPERSET of the absorbed set AND its location
#      range must subsume the absorbed location. If the proposed survivor is not
#      the superset but the other side is, FLIP. If neither subsumes the other,
#      KEEP SEPARATE (skip the pair). This makes the INV-013/014 outbound-path
#      loss and INV-031/044 POC-PASS loss mechanically impossible.
#
# And, on every accepted merge, the survivor's TEXT/ROW is COUPLED first (the
# absorbed finding's distinct Location(s), Impact, Recommendation, union Source
# IDs, higher severity, strongest evidence tag are carried into the survivor)
# BEFORE the absorbed block/row is removed — so no distinct attack path / route
# / impact / evidence is ever dropped.

# Findings with more source IDs than this are depth-aggregate / perturbation
# findings; the source-ID-subset and PERT-lineage signals are unreliable for
# them (a single shared source ID fires the subset test on unrelated defects).
_DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD = 4

_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Informational")


def _higher_severity(a: str, b: str) -> str:
    """Return the MORE severe (higher-tier) of two severity strings."""
    na, nb = normalize_severity(a), normalize_severity(b)
    try:
        ia, ib = _SEVERITY_ORDER.index(na), _SEVERITY_ORDER.index(nb)
    except ValueError:
        return na
    return na if ia <= ib else nb


def _absorbed_severity_higher(absorbed_sev: str, survivor_sev: str) -> bool:
    """True iff the absorbed finding's tier is STRICTLY more severe than the
    survivor's.

    Used by the dedup same-severity guard: removing a strictly-more-severe
    absorbed finding would drop the higher severity (the zero-loss coupling
    raises the survivor only up to the higher of the two, but the SURVIVING block
    is the lower-severity one in that direction, so the merge is unsafe). Returns
    False when severities are equal, the absorbed is less severe, or either tier
    is unparseable (fail-open to merge, matching historical trust of the
    LLM-chosen direction).
    """
    try:
        ia = _SEVERITY_ORDER.index(normalize_severity(absorbed_sev))
        ik = _SEVERITY_ORDER.index(normalize_severity(survivor_sev))
    except ValueError:
        return False
    return ia < ik  # lower index == more severe


def _strongest_evidence(a: str, b: str) -> str:
    """Return the strongest of two evidence tags (mechanical proof wins)."""
    a = (a or "").strip()
    b = (b or "").strip()
    if has_mechanical_proof(a) and not has_mechanical_proof(b):
        return a
    if has_mechanical_proof(b) and not has_mechanical_proof(a):
        return b
    return a or b


def _dedup_file_part(location: str) -> str:
    """Return the normalized file path component of a location string.

    Strips the ``:Lnn`` / ``:funcName:Lnn`` suffix so two findings can be tested
    for same-file membership. Empty for artifact-only / unparseable locations.
    """
    norm = _norm_loc(location or "")
    return re.sub(r":L?\d+.*$", "", re.sub(r":[A-Za-z_][\w]*(?=:L?\d)", "", norm)).strip()


def _dedup_parse_finding_info(text: str) -> dict[str, dict]:
    """Parse per-finding info from a target dedup file (SC inventory or L1 queue).

    Returns ``{ID: {source_ids, location, line_range, severity, evidence,
    title, kind, block | row}}`` covering BOTH formats:

    - SC inventory: ``### Finding [INV-N]: Title`` blocks with ``**Location**``,
      ``**Severity**``, ``**Source IDs**``, evidence-tag, ``**Impact**``,
      ``**Recommendation**`` markdown lines.
    - L1 queue: pipe-delimited ``| ... |`` rows whose columns carry finding id,
      severity, location, preferred/evidence tag (header-alias tolerant).

    Used by the survivor-superset gate and the coupling helpers. Findings with
    malformed / absent Source IDs or Location parse to empty sets — the superset
    gate then conservatively falls back to KEEP SEPARATE.
    """
    info: dict[str, dict] = {}

    # --- SC inventory blocks ---
    for m in re.finditer(
        r"#{2,4}\s+(?:Finding\s+)?\[((?:INV|F)-\d+)\]:?\s*(.+?)(?:\n|$)"
        r"((?:.*\n)*?)"
        r"(?=#{2,4}\s+(?:Finding\s+)?\[(?:INV|F)-|\Z)",
        text,
    ):
        fid = m.group(1)
        title = m.group(2).strip()
        body = m.group(3)
        loc_m = re.search(r"\*\*Location\*\*:\s*(.+)", body, re.IGNORECASE)
        sev_m = re.search(r"\*\*Severity\*\*:\s*([^\n]+)", body, re.IGNORECASE)
        loc = loc_m.group(1).strip() if loc_m else ""
        sev = normalize_severity(sev_m.group(1)) if sev_m else "Medium"
        source_ids: set[str] = set()
        for src_line in body.splitlines():
            src_m = _SOURCE_IDS_LINE_RE.match(src_line)
            if src_m:
                source_ids = {t.upper() for t in _split_source_id_tokens(src_m.group(1))}
                break
        evidence = ""
        ev_m = re.search(
            r"\[(" + EVIDENCE_TAG_NAMES_RE + r")\]", body
        )
        if ev_m:
            evidence = ev_m.group(0)
        info[fid] = {
            "source_ids": source_ids,
            "location": loc,
            "file": _dedup_file_part(loc),
            "line_range": _parse_line_range(_norm_loc(loc)),
            "severity": sev,
            "evidence": evidence,
            "title": title,
            "kind": "sc",
            # Preserve the exact source bytes.  P0-Q's field-complete applied
            # receipt hashes the original block and requires the absorbed
            # member card to reconstruct those bytes exactly.
            "block": m.group(0),
        }

    # --- L1 queue rows ---
    # Preserve exact row terminators for the field-complete member card.
    lines = text.splitlines(keepends=True)
    header_keys: dict[int, str] | None = None
    for raw in lines:
        line = raw.strip()
        if not line.startswith("|"):
            header_keys = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not cells:
            continue
        if all(set(c) <= {"-", ":", " "} for c in cells if c):
            continue  # separator row
        low = [c.lower() for c in cells]
        if header_keys is None and any(
            _match_canonical_header(h) == "finding id" for h in low
        ):
            header_keys = {}
            for idx, h in enumerate(low):
                canonical = _match_canonical_header(h)
                if canonical:
                    header_keys[idx] = canonical
            continue
        # data row
        fid = ""
        fid_m = re.search(r"\b((?:INV|F)-\d+)\b", line)
        if fid_m:
            fid = fid_m.group(1)
        if not fid or fid in info:
            continue
        row_vals: dict[str, str] = {}
        if header_keys:
            for idx, cell in enumerate(cells):
                key = header_keys.get(idx)
                if key:
                    row_vals[key] = cell
        loc = row_vals.get("location", "")
        sev = normalize_severity(row_vals.get("severity", "")) if row_vals.get("severity") else "Medium"
        evidence = row_vals.get("preferred tag", "")
        title = row_vals.get("title", "")
        # Source IDs are not a standard queue column; scan the row for any
        # bracketed source-id tokens as a best effort.
        info[fid] = {
            "source_ids": set(),
            "location": loc,
            "file": _dedup_file_part(loc),
            "line_range": _parse_line_range(_norm_loc(loc)),
            "severity": sev,
            "evidence": evidence,
            "title": title,
            "kind": "l1",
            "row": raw,
            "row_values": dict(row_vals),
            "header_keys": dict(header_keys or {}),
        }
    return info


def _dedup_l1_delivery_compatible(absorb: dict, keep: dict) -> bool:
    """True when every canonical L1 row field can reach the survivor shard.

    Verify workers consume the bounded shard row, not the preserved-member
    card that lives outside the queue table.  Title and evidence-debt cells are
    explicitly coupled by ``_couple_absorbed_into_survivor_row``; location,
    severity, and preferred evidence have their own mechanical union rules.
    Every other canonical executable field (notably Primary Artifact, bug
    class, and PoC class) must already agree or the merge is vetoed so both
    findings retain independent verification jobs.
    """
    a_values = dict(absorb.get("row_values") or {})
    k_values = dict(keep.get("row_values") or {})
    mechanically_coupled = {
        "finding id", "queue", "title", "location", "severity",
        "preferred tag", "evidence debt",
    }
    for key, raw_value in a_values.items():
        if key in mechanically_coupled:
            continue
        value = str(raw_value or "").strip()
        if not value:
            continue
        if value != str(k_values.get(key, "") or "").strip():
            return False
    return True


def _dedup_survivor_superset_ok(absorb: dict, keep: dict) -> bool:
    """True iff *keep* is a safe superset survivor of *absorb*.

    The survivor must subsume the absorbed finding's content along whatever
    dimension proves the duplicate relationship:

    - **Strict source-ID superset** (keep.source_ids ⊋ absorb.source_ids): the
      survivor was discovered by every agent that found the absorbed finding,
      plus more. This is dispositive REGARDLESS of file (a genuine cross-file
      stub/full subset pair — e.g. the v2.6.9 backstop case — has different
      locations but a proven source-ID superset). The absorbed finding's
      distinct location is then COUPLED into the survivor by the caller.

    - **Same-file location subsumption** (when source IDs are equal or absent):
      the survivor's line range must contain the absorbed's, and they must be in
      the same file. This is the same-site stub/full case and the INV-013/014
      guard (the wider-range survivor must be chosen so the outbound path is not
      dropped).

    Returns False (→ KEEP SEPARATE) when neither relationship holds, e.g. two
    co-located but distinct defects whose source IDs neither contain the other.
    """
    a_src = absorb.get("source_ids") or set()
    k_src = keep.get("source_ids") or set()

    if absorb.get("kind") == "l1" and keep.get("kind") == "l1":
        if not _dedup_l1_delivery_compatible(absorb, keep):
            return False

    # Dimension 1: strict source-ID superset is dispositive across files.
    if a_src and k_src:
        if not a_src.issubset(k_src):
            return False
        if a_src != k_src:
            return True  # proper superset — survivor covers strictly more
        # Equal sets fall through to the location test (same-site stub/full).

    # Dimension 2: same-file location subsumption.
    a_lr = absorb.get("line_range")
    k_lr = keep.get("line_range")
    a_file = absorb.get("file") or ""
    k_file = keep.get("file") or ""
    if a_lr is not None and k_lr is not None:
        # If both carry a file part, they must match (different files cannot be
        # subsumed by a line range alone).
        if a_file and k_file and a_file != k_file:
            return False
        return k_lr[0] <= a_lr[0] and k_lr[1] >= a_lr[1]

    # No dimension established subsumption → conservative KEEP SEPARATE.
    return False


def _dedup_info_insufficient(rec: dict | None) -> bool:
    """True when a finding record carries neither source IDs nor a line range.

    When BOTH sides of a pair are info-insufficient, the survivor-superset gate
    cannot decide direction from finding bodies — the merge direction then rests
    on the candidate-pair signal that already passed its own gate (aggregate
    guard for subset/PERT; EXACT-endpoint location for the supplemental path).
    Note: large-aggregate findings (the dangerous false-merge class) ALWAYS
    carry many source IDs, so they are never info-insufficient — the superset
    gate and aggregate guard always apply to them.
    """
    if rec is None:
        return True
    return not (rec.get("source_ids")) and rec.get("line_range") is None


def _resolve_dedup_survivor(
    id_a: str, id_b: str, proposed_absorb: str, proposed_keep: str,
    finfo: dict[str, dict],
) -> tuple[str, str] | None:
    """Resolve absorb/keep so the survivor is the source-ID/location superset.

    Returns (absorb, keep) if a safe merge direction exists, else None
    (KEEP SEPARATE). If the proposed survivor is not the superset but the other
    side is, FLIP. If neither subsumes the other, return None.

    Graceful fallback: when BOTH findings are info-insufficient (no source IDs
    AND no parseable location in their bodies — e.g. a verification queue with
    no Location column), the gate cannot establish subsumption. In that case the
    proposed direction is honored as-is, because the candidate-pair signal that
    produced the pair already enforced its own gate upstream (aggregate guard +
    EXACT-endpoint location). This preserves legitimate same-defect merges
    without weakening the protection for the dangerous large-aggregate class,
    which is never info-insufficient.
    """
    a = finfo.get(proposed_absorb)
    k = finfo.get(proposed_keep)
    if a is None or k is None:
        # One side missing entirely — honor the proposed direction (the pair
        # signal already gated it). This matches pre-gate behavior for findings
        # that are not present in the parsed body (rare; defensive).
        return (proposed_absorb, proposed_keep)
    if _dedup_info_insufficient(a) and _dedup_info_insufficient(k):
        # Neither side has source IDs or a line range — defer to the signal's
        # proposed direction (upstream gate already applied).
        return (proposed_absorb, proposed_keep)
    if _dedup_survivor_superset_ok(a, k):
        return (proposed_absorb, proposed_keep)
    # Try the flip: keep <- absorb (the other side may be the superset).
    if _dedup_survivor_superset_ok(k, a):
        return (proposed_keep, proposed_absorb)
    return None


# Clean, greppable generator class tokens stamped by the M1/M2 meta-passes:
# `AXISGAP:<id>` (multi-axis coverage, M2) and `INVARIANT:<id>` (committed
# invariant, M1). Pure provenance bookkeeping — no protocol content.
_PROVENANCE_CLASS_RE = re.compile(r"\b(AXISGAP|INVARIANT):([A-Za-z0-9_.-]+)")


def _provenance_class_tokens(text: str) -> list[str]:
    """Extract clean generator-provenance class tokens (``AXISGAP:<id>``,
    ``INVARIANT:<id>``) from a Source IDs value or a whole finding block.

    These tokens mark a finding as (also) discovered by the multi-axis (M2) or
    committed-invariant (M1) meta-pass. They must never be dropped on a dedup
    merge — losing one makes a co-found GT item read as 100% normal-sourced and
    breaks attribution. Order-preserving, de-duplicated. Never raises."""
    out: list[str] = []
    for m in _PROVENANCE_CLASS_RE.finditer(text or ""):
        tok = f"{m.group(1).upper()}:{m.group(2)}"
        if tok not in out:
            out.append(tok)
    return out


def _attribution_tokens(source_text: str) -> tuple[list[str], list[str]]:
    """Split a `**Source IDs**:` value into (normal_upstream_ids, class_tokens).

    ``class_tokens`` are the clean generator tokens (``AXISGAP:<id>``,
    ``INVARIANT:<id>``); ``normal_upstream_ids`` are the remaining ID-shaped
    tokens with the class tokens' embedded IDs removed so they are not
    double-counted. Order-preserving; never raises."""
    cls = _provenance_class_tokens(source_text)
    stripped = source_text or ""
    for c in cls:
        # Remove the exact class-token text (case-insensitive) so its embedded
        # id (AXIS-101 / CI-3) is not re-counted as a normal upstream token.
        stripped = re.sub(re.escape(c), " ", stripped, flags=re.IGNORECASE)
    normal: list[str] = []
    for m in re.finditer(r"\b([A-Za-z][A-Za-z0-9_]{0,24}-\d+)\b", stripped):
        tok = m.group(1).upper()
        if tok not in normal:
            normal.append(tok)
    return normal, cls


def write_mechanism_attribution_ledger(scratchpad: Path) -> dict:
    """Driver post-dedup hook. Write ``mechanism_attribution.md`` mapping each
    surviving inventory finding to the Source provenance tokens that contributed
    to it (normal upstream IDs + generator class tokens ``AXISGAP:``/
    ``INVARIANT:``).

    This makes "did the multi-axis (M2) or committed-invariant (M1) meta-pass
    co-find this?" a mechanical grep instead of an LLM guess — the prerequisite
    for measuring M1/M2 contribution. Pure provenance bookkeeping; no protocol
    content. Never raises, never halts. Returns
    ``{"rows": N, "axisgap": n, "invariant": n}``."""
    scratchpad = Path(scratchpad)
    try:
        inv = scratchpad / "findings_inventory.md"
        if not inv.exists():
            return {"rows": 0, "axisgap": 0, "invariant": 0}
        text = inv.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"rows": 0, "axisgap": 0, "invariant": 0}

    rows: list[tuple[str, str, str, str]] = []
    n_axis = 0
    n_inv = 0
    for m in re.finditer(
        r"#{2,4}\s+(?:Finding\s+)?\[((?:INV|F)-\d+)\]:?\s*(.+?)(?:\n|$)"
        r"((?:.*\n)*?)"
        r"(?=#{2,4}\s+(?:Finding\s+)?\[(?:INV|F)-|\Z)",
        text,
    ):
        fid = m.group(1)
        title = (m.group(2) or "").strip()
        body = m.group(3) or ""
        src_line = ""
        for ln in body.splitlines():
            sm = _SOURCE_IDS_LINE_RE.match(ln)
            if sm:
                src_line = sm.group(1)
                break
        normal, cls = _attribution_tokens(src_line)
        classes = sorted({c.split(":", 1)[0].upper() for c in cls})
        if "AXISGAP" in classes:
            n_axis += 1
        if "INVARIANT" in classes:
            n_inv += 1
        all_tokens = normal + cls
        rows.append((
            fid,
            title.replace("|", "/"),
            ", ".join(all_tokens) if all_tokens else "-",
            ", ".join(classes) if classes else "-",
        ))

    lines = [
        "# Mechanism Attribution Ledger",
        "",
        "Maps each surviving inventory finding to the Source provenance tokens "
        "that contributed to it — normal upstream IDs plus generator class "
        "tokens `AXISGAP:` (multi-axis coverage, M2) and `INVARIANT:` "
        "(committed invariant, M1). Mechanical grep target for measuring "
        "whether the M1/M2 meta-passes co-found a finding. Provenance-only; "
        "regenerated post-dedup so merged findings retain absorbed provenance.",
        "",
        "| Finding ID | Title | Source Tokens | Generator Provenance |",
        "|------------|-------|---------------|----------------------|",
    ]
    for fid, title, toks, classes in rows:
        lines.append(f"| {fid} | {title} | {toks} | {classes} |")
    lines.append("")
    try:
        (scratchpad / "mechanism_attribution.md").write_text(
            "\n".join(lines), encoding="utf-8"
        )
    except Exception:
        return {"rows": len(rows), "axisgap": n_axis, "invariant": n_inv}
    return {"rows": len(rows), "axisgap": n_axis, "invariant": n_inv}


def _couple_absorbed_into_survivor_block(
    block: str, absorb_id: str, absorb_info: dict, keep_info: dict,
) -> str:
    """Rewrite an SC survivor inventory block to ABSORB the absorbed finding's
    distinct content BEFORE the absorbed block is removed (ZERO DATA LOSS).

    Couples: absorbed Location (expanded Location list), distinct Impact /
    Recommendation as a coupled paragraph, union Source IDs, higher Severity,
    strongest evidence tag. Idempotent on the ``Coupled from {id}`` marker.

    Provenance-preserving merge: any generator class token (``AXISGAP:`` /
    ``INVARIANT:``) carried by the ABSORBED finding is appended to the
    survivor's Source IDs when the survivor lacks it, so an M1/M2 co-discovery
    is never dropped by the merge.
    """
    if f"Coupled from {absorb_id}" in block:
        return block
    lines = block.splitlines()
    out: list[str] = []
    a_loc = (absorb_info.get("location") or "").strip()
    # Provenance-preserving merge: carry EVERY generator class token
    # (AXISGAP:/INVARIANT:) from BOTH sides into the survivor. The absorbed
    # finding's tokens must never be dropped — losing one makes an M1/M2
    # co-discovery read as 100% normal-sourced.
    _prov_tokens: list[str] = []
    for _blk in (block, keep_info.get("block", ""), absorb_info.get("block", "")):
        for _pt in _provenance_class_tokens(_blk):
            if _pt not in _prov_tokens:
                _prov_tokens.append(_pt)
    _prov_upper = {t.upper() for t in _prov_tokens}
    # Drop any (possibly garbled) class-prefixed token from the parsed sets;
    # the clean forms are re-appended below so the output grep-resolves.
    union_src = sorted(
        t for t in (
            (keep_info.get("source_ids") or set())
            | (absorb_info.get("source_ids") or set())
        )
        if not t.upper().startswith(("AXISGAP:", "INVARIANT:"))
    )
    for _pt in _prov_tokens:
        if _pt not in union_src:
            union_src.append(_pt)
    new_sev = _higher_severity(keep_info.get("severity", ""), absorb_info.get("severity", ""))
    new_ev = _strongest_evidence(keep_info.get("evidence", ""), absorb_info.get("evidence", ""))
    saw_location = False
    saw_source = False
    saw_severity = False
    for line in lines:
        # Expand the Location line to include the absorbed location.
        loc_m = re.match(r"(\s*\*\*Location\*\*:\s*)(.+)", line, re.IGNORECASE)
        if loc_m and a_loc and a_loc.lower() not in loc_m.group(2).lower():
            out.append(f"{loc_m.group(1)}{loc_m.group(2).rstrip()} ; {a_loc}")
            saw_location = True
            continue
        # Replace Severity with the higher of the two.
        sev_m = re.match(r"(\s*\*\*Severity\*\*:\s*)(.+)", line, re.IGNORECASE)
        if sev_m:
            out.append(f"{sev_m.group(1)}{new_sev}")
            saw_severity = True
            continue
        # Set Source IDs to the union.
        src_m = _SOURCE_IDS_LINE_RE.match(line)
        if src_m and union_src:
            out.append(f"**Source IDs**: {', '.join(union_src)}")
            saw_source = True
            continue
        out.append(line)
    # Append a coupled paragraph carrying the absorbed finding's distinct
    # attack path / route / impact (so both paths survive in one finding).
    coupled = [
        "",
        f"**Coupled from {absorb_id}: {absorb_info.get('title', '').strip()}**",
    ]
    if a_loc:
        coupled.append(
            f"Additionally affects the distinct path at {a_loc} "
            f"(absorbed from {absorb_id}); this route must be fixed together with "
            "the surviving finding's path."
        )
    if new_ev and new_ev not in "\n".join(out):
        coupled.append(f"Evidence carried from absorbed finding: {new_ev}.")
    out.extend(coupled)
    # If the block had no explicit Location / Severity / Source IDs line, ensure
    # the coupled content still records them.
    if a_loc and not saw_location:
        out.append(f"**Coupled Location**: {a_loc}")
    if union_src and not saw_source:
        out.append(f"**Source IDs**: {', '.join(union_src)}")
    if not saw_severity:
        out.append(f"**Severity**: {new_sev}")

    # P0-Q: the short coupling paragraph above is useful to readers but is not
    # a losslessness proof.  Preserve the absorbed member's exact source block
    # in a visible, byte-recoverable group card.  The applied-authority receipt
    # reparses this card and compares every typed field hash before permitting
    # physical removal or downstream alias propagation.
    try:
        from semantic_dedup_authority import preserved_member_card

        card = preserved_member_card({
            "finding_id": absorb_id,
            "raw": str(absorb_info.get("block", "")),
        })
        out.extend(card.strip("\n").splitlines())
    except Exception:
        # The post-transform field gate will veto this merge.  Do not claim
        # losslessness merely because the best-effort card renderer failed.
        pass
    return "\n".join(out).rstrip()


def _couple_absorbed_into_survivor_row(
    row: str, absorb_id: str, absorb_info: dict, keep_info: dict,
) -> str:
    """Rewrite an L1 survivor queue row to ABSORB the absorbed row's distinct
    Location / evidence / severity BEFORE the absorbed row is removed.

    Unions location, inherits higher severity and strongest evidence. Operates
    on pipe-delimited cells without assuming fixed column order: it rewrites the
    cell that currently holds the survivor's location/severity/evidence values.
    """
    if f"+{absorb_id}" in row:
        return row
    a_loc = (absorb_info.get("location") or "").strip()
    k_loc = (keep_info.get("location") or "").strip()
    new_sev = _higher_severity(keep_info.get("severity", ""), absorb_info.get("severity", ""))
    new_ev = _strongest_evidence(keep_info.get("evidence", ""), absorb_info.get("evidence", ""))
    # Is the absorbed finding's location DISTINCT from the survivor's? Only then
    # is there a route to couple. When the absorbed location is already subsumed
    # by the survivor's range (or identical), there is no distinct attack path —
    # provenance lives in dedup_decisions.md (the MERGED-into row + Coupled-
    # content column), not smeared into the queue row.
    a_lr = absorb_info.get("line_range")
    k_lr = keep_info.get("line_range")
    loc_subsumed = bool(
        a_lr and k_lr and k_lr[0] <= a_lr[0] and k_lr[1] >= a_lr[1]
        and _norm_loc(a_loc).split(":", 1)[0] == _norm_loc(k_loc).split(":", 1)[0]
    )
    # A distinct location is only meaningful if it is a real CODE site (has a
    # parseable line range). Artifact references (verify_*.md, primary-artifact
    # filenames) and bare paths are not code routes — coupling them would just
    # leak the absorbed ID without preserving any attack path.
    loc_distinct = (
        bool(a_loc) and a_lr is not None and a_loc != k_loc and not loc_subsumed
    )
    # Split into cells preserving the leading/trailing pipe structure.
    cells = row.split("|")
    a_values = dict(absorb_info.get("row_values") or {})
    k_values = dict(keep_info.get("row_values") or {})
    header_keys = dict(keep_info.get("header_keys") or {})
    # These are canonical fields whose distinct absorbed values have no other
    # row-level union rule. Keep them directly in the surviving executable row
    # because L1 verifier shards do not read the out-of-table preservation card.
    for header_index, key in sorted(header_keys.items()):
        if key not in {"title", "evidence debt"}:
            continue
        absorbed_value = str(a_values.get(key, "") or "").strip()
        kept_value = str(k_values.get(key, "") or "").strip()
        if not absorbed_value or absorbed_value.casefold() in kept_value.casefold():
            continue
        cell_index = int(header_index) + 1  # leading pipe creates cells[0] == ""
        if cell_index >= len(cells):
            continue
        current = cells[cell_index].strip()
        coupled = (
            f"{current} / coupled {absorb_id}: {absorbed_value}"
            if current else f"coupled {absorb_id}: {absorbed_value}"
        )
        cells[cell_index] = cells[cell_index].replace(current, coupled)
    coupled_loc = False
    for i, cell in enumerate(cells):
        cstr = cell.strip()
        if not cstr:
            continue
        # Location cell: union a DISTINCT absorbed location.
        if loc_distinct and k_loc and cstr == k_loc and a_loc not in cstr:
            cells[i] = cell.replace(cstr, f"{k_loc} ; {a_loc} (+{absorb_id})")
            coupled_loc = True
            continue
        # Severity cell: bump to the higher tier.
        if normalize_severity(cstr) == normalize_severity(keep_info.get("severity", "")) and \
                cstr.lower() in {s.lower() for s in _SEVERITY_ORDER}:
            if new_sev.lower() != cstr.lower():
                cells[i] = cell.replace(cstr, new_sev)
            continue
        # Evidence cell: carry the strongest evidence tag.
        if keep_info.get("evidence") and cstr == keep_info.get("evidence", "").strip():
            if new_ev and new_ev != cstr:
                cells[i] = cell.replace(cstr, new_ev)
            continue
    new_row = "|".join(cells)
    # If a DISTINCT location could not be unioned onto a dedicated location cell
    # (no matching location cell present), guarantee no loss by appending a
    # coupled-location annotation. Only fires for genuinely distinct routes.
    if loc_distinct and not coupled_loc and f"+{absorb_id}" not in new_row:
        ncells = new_row.split("|")
        for j in range(len(ncells) - 1, -1, -1):
            if ncells[j].strip():
                ncells[j] = ncells[j].rstrip() + f" [coupled {absorb_id}: {a_loc}]"
                break
        new_row = "|".join(ncells)
    return new_row


def _apply_mechanical_dedup_from_pairs(
    scratchpad: Path,
    phase_name: str,
    *,
    supplemental: bool = False,
) -> int:
    """Mechanical dedup from pre-computed candidate pairs.

    When ``supplemental=False`` (default): fallback when LLM dedup fails twice.
    Reads ``dedup_candidate_pairs.md``, merges ONLY source-ID subset / PERT
    lineage + same-severity pairs, writes ``*_deduped.md`` for later swap.

    When ``supplemental=True``: runs AFTER successful LLM dedup + artifact swap.
    Reads ``dedup_candidate_pairs_full.md`` (the complete candidate set),
    accepts ONLY location-overlap + title >= 1.00 + same-severity pairs
    (source-ID/PERT are too noisy for deferred pairs — they share agent provenance,
    not root cause), skips LLM-evaluated live pairs and already-absorbed IDs,
    modifies the swapped file in-place, and appends to ``dedup_decisions.md``.

    Returns the number of merges applied.
    """
    # --- file selection ---
    pending_path: Path | None = None
    if supplemental:
        pairs_file = scratchpad / "dedup_candidate_pairs_full.md"
        if not pairs_file.exists():
            pairs_file = scratchpad / "dedup_candidate_pairs.md"
    else:
        pairs_file = scratchpad / "dedup_candidate_pairs.md"
    if not pairs_file.exists():
        return 0
    try:
        text = pairs_file.read_bytes().decode("utf-8", errors="replace")
    except Exception:
        return 0

    # --- parse per-finding info for the aggregate guard + survivor-superset
    #     gate + content coupling. For both fallback and supplemental the
    #     finding bodies live in the canonical inventory for both pipelines.
    #     Semantic dedup precedes queue publication and may not edit a queue.
    if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
        _finfo_path = scratchpad / "findings_inventory.md"
    else:
        _finfo_path = None
    finfo: dict[str, dict] = {}
    if _finfo_path is not None and _finfo_path.exists():
        try:
            finfo = _dedup_parse_finding_info(
                _finfo_path.read_bytes().decode("utf-8", errors="replace")
            )
        except Exception:
            finfo = {}

    def _is_aggregate(_fid: str) -> bool:
        rec = finfo.get(_fid)
        if not rec:
            return False
        return len(rec.get("source_ids") or set()) > _DEDUP_AGGREGATE_SOURCE_ID_THRESHOLD

    # --- supplemental: load IDs currently present in the target file ---
    present_ids: set[str] | None = None
    live_pairs: set[frozenset[str]] | None = None
    if supplemental:
        if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
            _target = scratchpad / "findings_inventory.md"
        else:
            return 0
        if not _target.exists():
            return 0
        pending_path = _target.with_name(
            _target.name + ".semantic_dedup.pending"
        )
        # Crash recovery for the receipt-before-commit window.  The canonical
        # queue/inventory is never edited until the immutable receipt exists.
        # If a prior attempt wrote the receipt and durable staged output but
        # crashed before os.replace, validate that exact output through the
        # normal receipt chain and finish the atomic commit.  If canonical is
        # already the receipted output, return the accepted count so the driver
        # refreshes typed queue/shard projections after a crash between commit
        # and sidecar regeneration.
        try:
            import semantic_dedup_authority as dedup_authority

            supp_receipt = (
                scratchpad
                / dedup_authority.SUPPLEMENTAL_RECEIPT_NAME
            )
            if supp_receipt.is_file():
                payload = json.loads(supp_receipt.read_text(encoding="utf-8"))
                accepted_count = len(payload.get("accepted_absorbed_ids") or [])
                for candidate, staged in (
                    (_target, False),
                    (pending_path, True),
                ):
                    if not candidate.is_file():
                        continue
                    try:
                        candidate_text = candidate.read_bytes().decode(
                            "utf-8", errors="strict"
                        )
                        dedup_authority.load_applied_aliases(
                            scratchpad, canonical_text=candidate_text
                        )
                    except Exception:
                        continue
                    if staged:
                        os.replace(candidate, _target)
                    elif pending_path.exists():
                        pending_path.unlink()
                    return accepted_count
        except Exception as exc:
            log.warning(
                "[dedup-authority] supplemental commit recovery deferred; "
                "will recompute conservatively: %r",
                exc,
            )
        _target_text = _target.read_bytes().decode("utf-8", errors="replace")
        # Top-level identities only. Field-complete absorbed-member cards retain
        # lineage IDs inside survivor bodies and must not resurrect those IDs as
        # independently present supplemental-dedup candidates.
        present_ids = set(_dedup_parse_finding_info(_target_text))
        # Build exclusion set from the live pairs file (LLM already evaluated)
        _live_file = scratchpad / "dedup_candidate_pairs.md"
        if _live_file.exists():
            live_pairs = set()
            for _ll in _live_file.read_text(encoding="utf-8", errors="replace").splitlines():
                _ll = _ll.strip()
                if not _ll.startswith("|"):
                    continue
                _lc = [c.strip() for c in _ll.split("|")]
                _lc = [c for c in _lc if c]
                if len(_lc) < 2 or _lc[0].startswith("-") or _lc[0].lower().startswith("finding"):
                    continue
                _la = re.match(r"((?:INV|F)-\d+)", _lc[0])
                _lb = re.match(r"((?:INV|F)-\d+)", _lc[1])
                if _la and _lb:
                    live_pairs.add(frozenset([_la.group(1), _lb.group(1)]))

    # Parse table rows: | id_a: title | id_b: title | score | signal | same? |
    merge_pairs: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.split("|")]
        cells = [c for c in cells if c]
        if len(cells) < 5:
            continue
        if cells[0].startswith("-") or cells[0].lower().startswith("finding"):
            continue
        signal = cells[3].lower()
        same_sev = cells[4].strip().lower()
        if same_sev != "yes":
            continue
        if supplemental:
            title_score = 0.0
            try:
                title_score = float(cells[2])
            except (ValueError, IndexError):
                pass
            has_strong = "location overlap" in signal and title_score >= 1.0
            # FIX #5: narrow relax — allow a merge when the two findings share
            # an EXACT file:line location (identical line range, same file is
            # already guaranteed by the same-file pair grouping) AND the same
            # severity tier (already enforced by same_sev above), at a lower
            # title-similarity threshold (>= 0.5). Adjacent-but-different lines
            # produce different ranges and MUST NOT merge — equality of both
            # endpoints is required. Do NOT broaden beyond exact-location +
            # same-tier.
            if not has_strong and "location overlap" in signal and title_score >= 0.5:
                _ranges = re.findall(
                    r"l(\d+)\s*-\s*(\d+)\s+vs\s+l(\d+)\s*-\s*(\d+)",
                    signal,
                    re.IGNORECASE,
                )
                if _ranges:
                    _a0, _a1, _b0, _b1 = _ranges[0]
                    if _a0 == _b0 and _a1 == _b1:
                        has_strong = True
        else:
            has_strong = "source-id subset" in signal or "pert lineage" in signal
        if not has_strong:
            continue
        id_a_m = re.match(r"((?:INV|F)-\d+)", cells[0])
        id_b_m = re.match(r"((?:INV|F)-\d+)", cells[1])
        if not id_a_m or not id_b_m:
            continue
        id_a = id_a_m.group(1)
        id_b = id_b_m.group(1)
        # Skip pairs where either ID was already removed by prior dedup
        if present_ids is not None:
            if id_a not in present_ids or id_b not in present_ids:
                continue
        # Skip pairs already evaluated by LLM dedup (live set)
        if live_pairs is not None and frozenset([id_a, id_b]) in live_pairs:
            continue
        # AGGREGATE GUARD: never act on a source-ID-subset / PERT-lineage signal
        # when EITHER finding is a large-aggregate finding (> threshold source
        # IDs). These signals misfire on perturbation / depth-aggregate findings
        # (DEDUP_AUDIT.md class D). This mirrors the parser-side suppression so
        # even a stale candidate file carrying the hint cannot drive a merge.
        if ("subset" in signal or "pert lineage" in signal) and (
            _is_aggregate(id_a) or _is_aggregate(id_b)
        ):
            continue
        # Proposed absorb direction (a HINT only — refined by the superset gate):
        # - source-ID subset with ⊂: absorb A (the subset side) into B
        # - PERT lineage: absorb B (the PERT-sourced variant)
        # - location overlap (supplemental): absorb higher INV# into lower
        if "subset" in signal and "⊂" in signal:
            prop_absorb, prop_keep = id_a, id_b
        elif supplemental and "location overlap" in signal:
            num_a = int(re.search(r"\d+", id_a).group())
            num_b = int(re.search(r"\d+", id_b).group())
            if num_a > num_b:
                prop_absorb, prop_keep = id_a, id_b
            else:
                prop_absorb, prop_keep = id_b, id_a
        else:
            prop_absorb, prop_keep = id_b, id_a
        # SURVIVOR-SUPERSET GATE: the survivor MUST be the source-ID / location
        # superset. If the proposed survivor is not the superset but the other
        # side is, FLIP. If neither subsumes the other, KEEP SEPARATE (skip).
        # This makes the INV-013/014 outbound-path loss and INV-031/044
        # POC-PASS loss mechanically impossible. When finding info is missing
        # (malformed bodies), _resolve_dedup_survivor returns None → skip.
        resolved = _resolve_dedup_survivor(id_a, id_b, prop_absorb, prop_keep, finfo)
        if resolved is None:
            continue
        absorb, keep = resolved
        merge_pairs.append((absorb, keep, signal))

    if not merge_pairs:
        return 0

    # Deduplicate: if a finding is absorbed into multiple keepers, pick first
    absorbed_set: set[str] = set()
    final_merges: list[tuple[str, str, str]] = []
    for absorb, keep, sig in merge_pairs:
        if absorb in absorbed_set or keep in absorbed_set or absorb == keep:
            continue
        absorbed_set.add(absorb)
        final_merges.append((absorb, keep, sig))

    # --- compute coupled-content notes (auditable record of what was carried
    #     into each survivor) ---
    coupled_notes: dict[str, str] = {}
    for absorb, keep, _sig in final_merges:
        a = finfo.get(absorb, {})
        k = finfo.get(keep, {})
        bits: list[str] = []
        a_loc = (a.get("location") or "").strip()
        if a_loc:
            bits.append(f"loc {a_loc}")
        union_src = sorted((k.get("source_ids") or set()) | (a.get("source_ids") or set()))
        if union_src:
            bits.append(f"src {{{','.join(union_src)}}}")
        merged_sev = _higher_severity(k.get("severity", ""), a.get("severity", ""))
        bits.append(f"sev {merged_sev}")
        merged_ev = _strongest_evidence(k.get("evidence", ""), a.get("evidence", ""))
        if merged_ev:
            bits.append(f"ev {merged_ev}")
        coupled_notes[absorb] = "; ".join(bits) if bits else "(no distinct content)"

    # --- write / append dedup decisions ---
    if supplemental:
        dec_path = scratchpad / "dedup_decisions.md"
        existing = ""
        if dec_path.exists():
            existing = dec_path.read_text(encoding="utf-8", errors="replace")
        supp_lines = [
            "",
            "---",
            "",
            "## Supplemental Mechanical Dedup",
            "",
            "**Status**: MECHANICAL_SUPPLEMENT",
            "",
            f"Applied {len(final_merges)} supplemental merge(s) from full "
            "candidate pair set (survivor-superset gate + aggregate guard "
            "enforced; absorbed content coupled into survivor).",
            "",
            "| Action | Absorbed | Into | Signal | Coupled-content |",
            "|--------|----------|------|--------|-----------------|",
        ]
        for absorb, keep, sig in final_merges:
            supp_lines.append(
                f"| MECHANICAL_SUPPLEMENT | {absorb} | {keep} | {sig} "
                f"| {coupled_notes.get(absorb, '')} |"
            )
        # Also emit the canonical MERGED-into form so _extract_dedup_absorbed_ids
        # and the report coverage ledger account each absorbed ID.
        supp_lines.append("")
        for absorb, keep, _sig in final_merges:
            supp_lines.append(f"| {absorb} | MERGED into {keep} |")
        supp_lines.append("")
        dec_path.write_text(
            existing.rstrip("\n") + "\n" + "\n".join(supp_lines),
            encoding="utf-8",
        )
    else:
        dec_lines = [
            "# Semantic Dedup Decisions",
            "",
            "**Status**: MECHANICAL_FALLBACK",
            "",
            f"LLM dedup failed twice. Applied {len(final_merges)} conservative "
            "mechanical merge(s) from pre-computed candidate pairs "
            "(survivor-superset gate + aggregate guard enforced; absorbed "
            "content coupled into survivor).",
            "",
            "## Decisions",
            "",
            "| Action | Absorbed | Into | Signal | Coupled-content |",
            "|--------|----------|------|--------|-----------------|",
        ]
        for absorb, keep, sig in final_merges:
            dec_lines.append(
                f"| MECHANICAL_MERGE | {absorb} | {keep} | {sig} "
                f"| {coupled_notes.get(absorb, '')} |"
            )
        dec_lines.append("")
        for absorb, keep, _sig in final_merges:
            dec_lines.append(f"| {absorb} | MERGED into {keep} |")
        dec_lines.append("")
        (scratchpad / "dedup_decisions.md").write_text(
            "\n".join(dec_lines), encoding="utf-8",
        )

    # --- remove absorbed finding rows from the target file ---
    if supplemental:
        # In-place: modify the already-swapped file
        if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
            target = scratchpad / "findings_inventory.md"
        else:
            return len(final_merges)
    else:
        # Fallback: copy source to deduped target
        if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
            source = scratchpad / "findings_inventory.md"
            target = scratchpad / "findings_inventory_deduped.md"
        else:
            return len(final_merges)
        if not source.exists():
            return len(final_merges)

    read_path = target if supplemental else source
    if not read_path.exists():
        return len(final_merges)
    input_text = read_path.read_bytes().decode("utf-8", errors="replace")
    apply_target = target
    if supplemental:
        assert pending_path is not None
        shutil.copy2(read_path, pending_path)
        apply_target = pending_path
        _apply_merges_to_inventory(
            apply_target, apply_target, final_merges, finfo
        )
    else:
        _apply_merges_to_inventory(
            read_path, apply_target, final_merges, finfo
        )

    # P0-Q/P0-S: deterministic fallback/supplemental transforms cross the same
    # field-complete applied-authority boundary as LLM proposals.  A receipt
    # failure restores the exact pre-transform bytes, leaving proposal prose
    # visible but incapable of feeding aliases downstream.
    receipt_written = False
    try:
        import semantic_dedup_authority as dedup_authority

        mechanical_proposals = dedup_authority.proposals_from_merge_candidates(
            final_merges,
            source=(
                "MECHANICAL_SUPPLEMENT"
                if supplemental
                else "MECHANICAL_FALLBACK"
            ),
        )
        receipt_kind = (
            "SUPPLEMENTAL"
            if supplemental
            and (scratchpad / dedup_authority.PRIMARY_RECEIPT_NAME).is_file()
            else "PRIMARY"
        )
        dedup_authority.write_applied_receipt(
            scratchpad,
            phase_name=phase_name,
            application_kind=receipt_kind,
            proposal_text=text,
            proposal_path=pairs_file.name,
            proposals=mechanical_proposals,
            input_text=input_text,
            output_text=apply_target.read_bytes().decode(
                "utf-8", errors="replace"
            ),
            applied_merges=final_merges,
        )
        receipt_written = True
        if supplemental:
            # Receipt-first atomic commit. A crash before this line leaves the
            # canonical candidate set untouched; a crash after receipt but
            # before replacement is completed by the recovery block above.
            os.replace(apply_target, target)
    except Exception as exc:
        log.warning(
            "[dedup-authority] mechanical application receipt veto; "
            "restoring all members: %r",
            exc,
        )
        if supplemental:
            # Retain a receipted stage for deterministic resume; discard any
            # unreceipted partial output. Canonical bytes were never changed.
            if not receipt_written and pending_path is not None:
                try:
                    pending_path.unlink(missing_ok=True)
                except Exception:
                    pass
        else:
            try:
                target.write_bytes(input_text.encode("utf-8"))
            except Exception:
                pass
        return 0

    return len(final_merges)


def _apply_merges_to_inventory(
    read_path: Path,
    target: Path,
    final_merges: list[tuple[str, str, str]],
    finfo: dict[str, dict],
) -> int:
    """Apply MERGE decisions to a findings inventory / verification queue.

    Shared ZERO-DATA-LOSS coupling+removal engine used by BOTH the mechanical
    fallback path (``_apply_mechanical_dedup_from_pairs``) and the faithful
    LLM-decisions path (``apply_llm_dedup_decisions``). For each merge:

      1. COUPLE the absorbed finding's distinct Location / Impact /
         Recommendation / union Source IDs / higher Severity / strongest
         evidence into the SURVIVOR (block for SC, row for L1).
      2. THEN remove the absorbed block / row.

    ``read_path`` is the source inventory/queue to start from; the result is
    written to ``target`` (they may be the same file for in-place edits).
    ``final_merges`` is a list of ``(absorbed_id, survivor_id, signal)`` tuples;
    the survivor-superset gate is the caller's responsibility (the mechanical
    path runs ``_resolve_dedup_survivor`` first, the LLM path trusts the
    agent's flipped direction recorded in ``dedup_decisions.md``). Returns the
    number of merges applied.
    """
    if not read_path.exists():
        return 0
    body = read_path.read_bytes().decode("utf-8", errors="replace")
    absorbed_to_keep = {absorb: keep for absorb, keep, _ in final_merges}
    absorbed_ids = set(absorbed_to_keep.keys())

    # --- Step 1: couple absorbed content into survivors ---
    # SC inventory survivors (block-form). Rewrite each survivor block.
    keep_blocks_sc = {
        keep for keep in absorbed_to_keep.values()
        if finfo.get(keep, {}).get("kind") == "sc"
    }
    if keep_blocks_sc:
        def _couple_sc(match: re.Match) -> str:
            block = match.group(0)
            kid = match.group(1)
            if kid not in keep_blocks_sc:
                return block
            new_block = block.rstrip()
            for absorb, keep in absorbed_to_keep.items():
                if keep != kid:
                    continue
                new_block = _couple_absorbed_into_survivor_block(
                    new_block, absorb, finfo.get(absorb, {}), finfo.get(kid, {}),
                )
            # Preserve trailing newline structure of the original match.
            trailing = block[len(block.rstrip()):]
            return new_block + trailing
        body = re.sub(
            r"#{2,4}\s+(?:Finding\s+)?\[((?:INV|F)-\d+)\]:?[^\n]*\n"
            r"(?:(?!#{2,4}\s+(?:Finding\s+)?\[(?:INV|F)-).*\n?)*",
            _couple_sc,
            body,
        )

    # L1 queue survivors (row-form). Rewrite each survivor row in place.
    keep_rows_l1 = {
        keep for keep in absorbed_to_keep.values()
        if finfo.get(keep, {}).get("kind") == "l1"
    }
    if keep_rows_l1:
        new_body_lines: list[str] = []
        for line in body.splitlines():
            if line.strip().startswith("|"):
                rid_m = re.search(r"\b((?:INV|F)-\d+)\b", line)
                if rid_m and rid_m.group(1) in keep_rows_l1:
                    kid = rid_m.group(1)
                    for absorb, keep in absorbed_to_keep.items():
                        if keep == kid:
                            line = _couple_absorbed_into_survivor_row(
                                line, absorb, finfo.get(absorb, {}), finfo.get(kid, {}),
                            )
            new_body_lines.append(line)
        body = "\n".join(new_body_lines)

    # --- Step 2: remove absorbed blocks (SC) / rows (L1) ---
    # SC blocks: drop the absorbed `### Finding [ID]:` block entirely.
    absorbed_sc = {
        a for a in absorbed_ids if finfo.get(a, {}).get("kind") == "sc"
    }
    if absorbed_sc:
        def _drop_sc(match: re.Match) -> str:
            fid = match.group(1)
            return "" if fid in absorbed_sc else match.group(0)
        body = re.sub(
            r"#{2,4}\s+(?:Finding\s+)?\[((?:INV|F)-\d+)\]:?[^\n]*\n"
            r"(?:(?!#{2,4}\s+(?:Finding\s+)?\[(?:INV|F)-).*\n?)*",
            _drop_sc,
            body,
        )

    # L1 / generic pipe rows: drop absorbed rows by primary Finding ID.
    out_lines: list[str] = []
    for line in body.splitlines():
        skip = False
        if line.strip().startswith("|"):
            row_id_m = re.search(r"\b((?:INV|F)-\d+)\b", line)
            if row_id_m and row_id_m.group(1) in absorbed_ids:
                # Only drop rows for absorbed findings that are NOT block-form
                # (block-form absorbed are already removed above; a stray pipe
                # mention of an absorbed ID inside a survivor block must NOT be
                # dropped — but block bodies are not pipe rows, so this is safe).
                if finfo.get(row_id_m.group(1), {}).get("kind") != "sc":
                    skip = True
        if not skip:
            out_lines.append(line)
    deduped = "\n".join(out_lines)
    # Row-form queues have no safe column in which to inline arbitrary
    # narrative fields. Append exact, visible absorbed-member cards outside the
    # table; queue parsers ignore them, while the P0-Q field gate proves every
    # original column byte remains recoverable before authorizing removal.
    try:
        from semantic_dedup_authority import preserved_member_card

        row_cards: list[str] = []
        for absorbed, _survivor in sorted(absorbed_to_keep.items()):
            record = finfo.get(absorbed, {})
            if record.get("kind") != "l1":
                continue
            marker = f"PLAMEN_DEDUP_PRESERVED_MEMBER_BEGIN id={absorbed} "
            if marker in deduped:
                continue
            row_cards.append(
                preserved_member_card({
                    "finding_id": absorbed,
                    "raw": str(record.get("row", "")),
                }).strip("\n")
            )
        if row_cards:
            deduped = deduped.rstrip("\n") + "\n\n## Preserved Dedup Members\n\n" + "\n\n".join(row_cards)
    except Exception:
        # Receipt validation will veto and restore the input if a card cannot
        # be rendered exactly.
        pass
    if not deduped.endswith("\n"):
        deduped += "\n"
    target.write_bytes(deduped.encode("utf-8"))
    return len(final_merges)


# ── GROUP-note stamping for the LLM-decisions apply path ──
_DEDUP_GROUP_NOTE_RE = re.compile(r"\*\*Dedup Group\*\*:", re.IGNORECASE)


def _stamp_dedup_group_note(
    inv_path: Path, representative_id: str, member_ids: list[str]
) -> int:
    """Stamp a ``**Dedup Group**:`` note onto non-representative member blocks.

    GROUP keeps every member block visible (no removal); the non-representative
    members inherit verification/reporting from the representative. Idempotent:
    a member already carrying a Dedup Group note is left unchanged. Returns the
    number of member blocks stamped.
    """
    if not inv_path.exists() or not member_ids:
        return 0
    body = inv_path.read_text(encoding="utf-8", errors="replace")
    members = {m for m in member_ids if m and m != representative_id}
    if not members:
        return 0
    stamped = 0

    def _stamp(match: re.Match) -> str:
        nonlocal stamped
        block = match.group(0)
        fid = match.group(1)
        if fid not in members:
            return block
        if _DEDUP_GROUP_NOTE_RE.search(block):
            return block
        note = (
            f"\n**Dedup Group**: inherits verification from "
            f"{representative_id}\n"
        )
        trailing = block[len(block.rstrip()):]
        stamped += 1
        return block.rstrip() + note + trailing

    body = re.sub(
        r"#{2,4}\s+(?:Finding\s+)?\[((?:INV|F)-\d+)\]:?[^\n]*\n"
        r"(?:(?!#{2,4}\s+(?:Finding\s+)?\[(?:INV|F)-).*\n?)*",
        _stamp,
        body,
    )
    if stamped:
        if not body.endswith("\n"):
            body += "\n"
        inv_path.write_text(body, encoding="utf-8")
    return stamped


# ── Group-line decision parsing (NEW in-context clustering output form) ──
# A MERGE line lists the survivor first, then >=1 absorbed IDs:
#   MERGE: INV-3, INV-7, INV-12\tsame-root-cause reentrancy
# requires >= 2 IDs (the (?:...)+ after the first). KEEP: lines are advisory
# (coverage-gate only) and ignored for apply.
_DEDUP_GROUP_LINE_RE = re.compile(
    r"(?im)^\s*MERGE\s*:\s*(\[?(?:INV|F)-\d+\]?(?:\s*,\s*\[?(?:INV|F)-\d+\]?)+)"
)
_DEDUP_ID_TOKEN_RE = re.compile(r"(?:INV|F)-\d+", re.IGNORECASE)


def _parse_dedup_group_lines(text: str) -> list[list[str]]:
    """Parse ``MERGE: A, B, C`` group-lines into ID clusters (>=2 IDs each).

    Tolerant: any line not matching ``_DEDUP_GROUP_LINE_RE`` is silently skipped
    (no raise). A MERGE line with only one parseable ID is skipped. IDs are
    upper-cased and stripped of brackets. Order is PRESERVED (first ID = the
    survivor the agent intended; union-find re-derives the actual survivor via
    the superset gate, but order is kept for determinism).
    """
    clusters: list[list[str]] = []
    for m in _DEDUP_GROUP_LINE_RE.finditer(text):
        ids: list[str] = []
        for tok in _DEDUP_ID_TOKEN_RE.findall(m.group(1)):
            cid = tok.upper().strip("[]")
            if cid not in ids:
                ids.append(cid)
        if len(ids) >= 2:
            clusters.append(ids)
    return clusters


def _apply_llm_group_decisions(scratchpad: Path, phase_name: str) -> int:
    """Union-find transitive-closure reduce over ALL LLM MERGE decision forms.

    The NEW group reducer (spec 2b). Parses every MERGE form recorded in
    ``dedup_decisions.md`` — the in-context group-lines (``MERGE: A, B, C``), the
    legacy ``### MERGE: {survivor} absorbs {absorbed}`` headings, and the
    ``| {absorbed} | MERGED into {survivor} |`` status rows — into ID clusters,
    UNIONs them so cross-block transitivity is recovered (Block1 ``MERGE A,B`` +
    Block2 ``MERGE B,C`` -> one component {A,B,C}), then for each component picks
    a provisional survivor by folding the EXISTING ``_resolve_dedup_survivor``
    gate pairwise (a member the gate rejects is DROPPED and KEPT SEPARATE — never
    a forced merge), applies the EXISTING same-severity guard, and hands the
    resulting ``(absorbed, survivor, "llm-group")`` list to the EXISTING
    ``_apply_merges_to_inventory`` (zero-loss coupling + removal).

    Returns the number of merges applied. Returns 0 (no-op, leaves any prewritten
    passthrough copy in place) when no real MERGE rows exist. NEVER raises out of
    a dedup decision: a parse/apply failure degrades to 0.
    """
    scratchpad = Path(scratchpad)
    dec_path = scratchpad / "dedup_decisions.md"
    if not dec_path.is_file():
        return 0
    try:
        text = dec_path.read_bytes().decode("utf-8", errors="replace")
    except Exception:
        return 0
    try:
        import semantic_dedup_authority as dedup_authority

        proposals = dedup_authority.parse_dedup_proposals(text)
        conflicting_members = dedup_authority.conflicting_merge_members(proposals)
    except Exception as exc:
        log.warning(
            "[dedup-authority] proposal parse failed; keeping all members: %r",
            exc,
        )
        return 0

    if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
        source = scratchpad / "findings_inventory.md"
        target = scratchpad / "findings_inventory_deduped.md"
    else:
        return 0
    if not source.exists():
        return 0

    finfo: dict[str, dict] = {}
    try:
        finfo = _dedup_parse_finding_info(
            source.read_bytes().decode("utf-8", errors="replace")
        )
    except Exception:
        finfo = {}
    finfo = {k.upper(): v for k, v in finfo.items()}

    # ── Step 1: collect ID-clusters from ALL three MERGE forms. ──
    clusters: list[list[str]] = [
        list(event["member_ids"])
        for event in proposals
        if event.get("action") == "MERGE"
    ]

    if not clusters:
        # KEEP/GROUP/empty proposal sets still receive an applied receipt. This
        # prevents "no destructive delta" from silently falling back to raw
        # proposal authority on resume.
        try:
            shutil.copy2(source, target)
            if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
                for group_match in re.finditer(
                    r"(?im)^\s*#{2,6}\s+GROUP:\s+\[?([A-Za-z]+-\d+)\]?\s+represents\s+(.+?)\s*$",
                    text,
                ):
                    representative = group_match.group(1).strip().upper()
                    group_members = [
                        token.strip().upper().strip("[]")
                        for token in re.split(r"[,;\s]+", group_match.group(2))
                        if re.fullmatch(r"\[?[A-Za-z]+-\d+\]?", token.strip())
                    ]
                    _stamp_dedup_group_note(target, representative, group_members)
            dedup_authority.write_applied_receipt(
                scratchpad,
                phase_name=phase_name,
                application_kind="PRIMARY",
                proposal_text=text,
                proposals=proposals,
                input_text=source.read_bytes().decode("utf-8", errors="replace"),
                output_text=target.read_bytes().decode("utf-8", errors="replace"),
                applied_merges=[],
            )
        except Exception as exc:
            log.warning(
                "[dedup-authority] no-merge receipt failed; keeping passthrough: %r",
                exc,
            )
            try:
                shutil.copy2(source, target)
            except Exception:
                pass
        return 0

    # ── Step 2: UNION-FIND over all clusters → connected components. ──
    parent: dict[str, str] = {}

    def _find(x: str) -> str:
        parent.setdefault(x, x)
        root = x
        while parent[root] != root:
            root = parent[root]
        # Path compression.
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def _union(a: str, b: str) -> None:
        ra, rb = _find(a), _find(b)
        if ra != rb:
            parent[rb] = ra

    # Track first-seen order of IDs for deterministic component iteration.
    order: list[str] = []
    seen_order: set[str] = set()
    for cl in clusters:
        first = cl[0]
        for cid in cl:
            if cid not in seen_order:
                seen_order.add(cid)
                order.append(cid)
            _union(first, cid)

    components: dict[str, list[str]] = {}
    for cid in order:
        components.setdefault(_find(cid), []).append(cid)

    # ── Step 3+4+5: per component, fold-left _resolve_dedup_survivor to choose
    #    a survivor, drop gate-rejected members, apply same-severity guard. ──
    final_merges: list[tuple[str, str, str]] = []
    rejection_reasons: dict[str, str] = {}
    for root, members in components.items():
        if len(members) < 2:
            continue
        if any(member in conflicting_members for member in members):
            for member in members:
                if member in conflicting_members:
                    rejection_reasons[member] = "CONFLICTING_PROPOSAL"
            continue
        missing_members = [member for member in members if member not in finfo]
        if missing_members:
            for member in missing_members:
                rejection_reasons[member] = "MEMBER_NOT_IN_INPUT"
            continue
        # Deterministic processing order: ID-numeric ascending so the fold is
        # reproducible regardless of decision-line ordering.
        ordered = sorted(members, key=lambda x: (_dedup_id_num(x), x))
        survivor = ordered[0]
        component_absorbed: list[str] = []
        for nxt in ordered[1:]:
            resolved = _resolve_dedup_survivor(survivor, nxt, nxt, survivor, finfo)
            if resolved is None:
                rejection_reasons[nxt] = "SUPERSET_GATE_REJECTED"
                # Gate rejects this pair → KEEP SEPARATE (drop from the merge).
                continue
            absorb, keep = resolved
            # The running survivor is whichever side the gate kept.
            survivor = keep
            # The dropped side is the absorbed one (could be the prior survivor
            # if the gate flipped direction).
            component_absorbed.append(absorb)
        # Re-point every absorbed at the FINAL survivor and apply the
        # same-severity guard (spec 2b step 5). The existing zero-loss coupling
        # ALWAYS raises the survivor to the higher of the two severities, so the
        # ONLY case where a merge would lose a higher severity is when the
        # ABSORBED tier is strictly higher than the survivor's. In that case the
        # higher-severity finding would be the one removed — skip it (keep
        # separate). When absorbed severity <= survivor severity, the survivor's
        # tier is preserved (or coupled up), so the merge is safe — mirroring the
        # historical behavior where the LLM-chosen survivor-superset direction is
        # honored and the higher severity is retained by coupling.
        for absorb in component_absorbed:
            if absorb == survivor:
                continue
            a = finfo.get(absorb)
            k = finfo.get(survivor)
            if a is not None and k is not None:
                sa = a.get("severity")
                sk = k.get("severity")
                if sa and sk and _absorbed_severity_higher(sa, sk):
                    rejection_reasons[absorb] = "HIGHER_SEVERITY_MEMBER_VETO"
                    # Absorbed tier strictly higher than survivor → removing it
                    # would drop a higher-severity finding. Keep separate.
                    log.debug(
                        "[dedup] same-severity guard skip %s->%s "
                        "(absorbed %s > survivor %s)",
                        absorb, survivor, sa, sk,
                    )
                    continue
            final_merges.append((absorb, survivor, "llm-group"))

    # De-dup absorbed (a finding absorbed into multiple components → first only)
    # and drop any merge whose survivor is itself absorbed elsewhere.
    all_survivors = {s for _a, s, _ in final_merges}
    deduped_merges: list[tuple[str, str, str]] = []
    seen_absorbed: set[str] = set()
    for absorb, survivor, sig in final_merges:
        if absorb in all_survivors:
            continue
        if absorb in seen_absorbed or absorb == survivor:
            continue
        seen_absorbed.add(absorb)
        deduped_merges.append((absorb, survivor, sig))

    # Zero accepted merges is still an applied-authority event: the receipt
    # records explicit rejections and the output remains an exact passthrough.

    # ── Step 6: build the deduped artifact via the EXISTING zero-loss engine. ──
    try:
        shutil.copy2(source, target)
    except Exception:
        try:
            target.write_text(
                source.read_bytes().decode("utf-8", errors="replace"),
                encoding="utf-8",
            )
        except Exception:
            return 0
    if deduped_merges:
        try:
            _apply_merges_to_inventory(target, target, deduped_merges, finfo)
        except Exception as exc:
            log.warning(
                "[dedup-authority] transform failed; restoring passthrough: %r",
                exc,
            )
            shutil.copy2(source, target)
            deduped_merges = []
    # GROUP is non-destructive, but it still changes output bytes. Stamp its
    # notes before the immutable receipt hashes the applied artifact.
    if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
        for group_match in re.finditer(
            r"(?im)^\s*#{2,6}\s+GROUP:\s+\[?([A-Za-z]+-\d+)\]?\s+represents\s+(.+?)\s*$",
            text,
        ):
            representative = group_match.group(1).strip().upper()
            group_members = [
                token.strip().upper().strip("[]")
                for token in re.split(r"[,;\s]+", group_match.group(2))
                if re.fullmatch(r"\[?[A-Za-z]+-\d+\]?", token.strip())
            ]
            _stamp_dedup_group_note(target, representative, group_members)
    try:
        source_text = source.read_bytes().decode("utf-8", errors="replace")
        output_text = target.read_bytes().decode("utf-8", errors="replace")
        dedup_authority.write_applied_receipt(
            scratchpad,
            phase_name=phase_name,
            application_kind="PRIMARY",
            proposal_text=text,
            proposals=proposals,
            input_text=source_text,
            output_text=output_text,
            applied_merges=deduped_merges,
            rejection_reasons=rejection_reasons,
        )
    except Exception as exc:
        log.warning(
            "[dedup-authority] applied receipt veto; restoring passthrough: %r",
            exc,
        )
        try:
            shutil.copy2(source, target)
        except Exception:
            pass
        return 0
    return len(deduped_merges)


def _dedup_id_num(fid: str) -> int:
    """Numeric component of a finding ID for deterministic ordering."""
    m = re.search(r"\d+", fid or "")
    return int(m.group(0)) if m else 0


def apply_llm_dedup_decisions(scratchpad: Path, phase_name: str) -> int:
    """Build the deduped inventory from LLM-authored dedup decisions.

    Faithful (non-fallback) path: the dedup agent emits ONLY ``dedup_decisions.md``
    (decisions-as-delta); the driver mechanically produces the deduped artifact
    so the survivor-superset coupling + aggregate guard + zero-data-loss
    coupling are enforced on the LLM's own MERGE choices — identically to the
    mechanical fallback. The LLM never rewrites the whole inventory verbatim.

    Parses ``dedup_decisions.md`` for:
      - ``| {absorbed} | MERGED into {survivor} | ... |`` status rows AND/OR
        ``### MERGE: {survivor} absorbs {absorbed}`` headings (MERGE pairs).
      - ``### GROUP: {representative} represents {member_ids}`` headings, which
        keep both blocks and stamp a ``**Dedup Group**:`` note.

    The survivor direction is taken from the LLM decision as authored (the agent
    already applied the survivor-superset gate / flip per the prompt). The
    coupling+removal is applied by the shared ``_apply_merges_to_inventory``
    engine so no distinct content is lost. Returns the number of MERGE
    decisions applied. Does nothing (returns 0) when no real MERGE/GROUP rows
    exist (e.g. a passthrough stub), leaving any prewritten passthrough copy in
    place as the recall-safe floor.
    """
    scratchpad = Path(scratchpad)
    dec_path = scratchpad / "dedup_decisions.md"
    if not dec_path.is_file():
        return 0
    try:
        text = dec_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0

    # Source + target artifacts per pipeline.
    if phase_name in {"semantic_dedup", "sc_semantic_dedup"}:
        source = scratchpad / "findings_inventory.md"
        target = scratchpad / "findings_inventory_deduped.md"
    else:
        return 0
    if not source.exists():
        return 0

    # --- MERGE decisions: route ALL three MERGE forms (new group-lines, legacy
    #     `### MERGE: … absorbs …` headings, `| … | MERGED into … |` rows)
    #     through the union-find transitive-closure reduce. The reducer parses
    #     every form, unions cross-block transitivity, picks survivors via the
    #     EXISTING superset gate (dropping gate-rejected members), applies the
    #     same-severity guard, and writes the deduped artifact via the EXISTING
    #     zero-loss `_apply_merges_to_inventory`. ---
    merges_applied = _apply_llm_group_decisions(scratchpad, phase_name)

    # The union-find reducer also owns GROUP-only and KEEP/no-delta paths.  It
    # stamps every GROUP annotation before hashing the immutable applied
    # receipt.  A second stamp here used to mutate the output after receipt
    # publication, making the canonical bytes fail their own authority check.
    return merges_applied


def _cap_severity_at(severity: str, capped_at: str) -> str:
    """Apply a maximum severity cap without upgrading lower severities."""
    order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev = normalize_severity(severity)
    cap = normalize_severity(capped_at)
    if order.index(sev) < order.index(cap):
        return cap
    return sev


def _write_mechanical_report_index(
    scratchpad: Path,
    *,
    prepare_body: bool = True,
    materialize_facets: bool = True,
) -> int:
    """Build a recall-safe report index from verifier artifacts.

    Verifier status and signature clusters are proposals, not destructive
    authority.  Every queue identity remains active unless an applied typed
    lifecycle/alias boundary has already removed it upstream.  Later report
    disposition machinery may consume genuine authority; this builder never
    invents it from prose.
    """
    if materialize_facets:
        try:
            _write_candidate_semantic_facets(scratchpad)
        except Exception as exc:
            log.warning(
                f"[report_index] candidate semantic facets skipped: {exc!r}"
            )
    rows = _report_candidate_universe_rows(scratchpad)
    if not rows:
        return 0
    counters = {"C": 0, "H": 0, "M": 0, "L": 0, "I": 0}
    raw_active: list[dict[str, str]] = []
    excluded: list[dict[str, str]] = []
    poc_caps = _load_poc_demotion_caps(scratchpad)
    finding_record_maps = _load_finding_record_maps(scratchpad)
    # P0-V: skeptic UNRESOLVED is a challenge/evidence state, not severity
    # authority.  Pull the IDs only to retain a visible Trust-Adj/body flag.
    try:
        judge_unresolved_ids = {
            x.upper() for x in _collect_judge_unresolved_ids(scratchpad)
        }
    except Exception:
        judge_unresolved_ids = set()
    late_statuses: Mapping[str, Any] = {}
    if (
        Path(scratchpad)
        / "post_verify_late_verification_authority.json"
    ).is_file():
        from post_verify_candidate_delta import (
            load_post_verify_late_delivery_statuses,
        )

        late_statuses = load_post_verify_late_delivery_statuses(scratchpad)

    for row in rows:
        fid = (row.get("finding id") or "").strip()
        if not fid:
            continue
        record = _finding_record_for_ids(scratchpad, [fid], finding_record_maps)
        vp = _verify_file_for_id(scratchpad, fid)
        late_status = late_statuses.get(fid)
        verifier_complete = (
            bool(late_status)
            and late_status.delivery_state
            == "INDEPENDENT_VERIFICATION_RECORDED"
            and bool(late_status.verify_artifact)
        ) or (
            row.get("source kind") in {
                None, "", "BASE_VERIFICATION_QUEUE"
            }
            and _verifier_output_has_completion_authority(scratchpad, fid)
        )
        untrusted_claim_text = ""
        if verifier_complete:
            try:
                vtxt = _llm_norm(
                    vp.read_text(encoding="utf-8", errors="replace")
                )
            except Exception:
                vtxt = ""
        else:
            # Unreceipted/partial bytes are not a report-index input.  Keep
            # queue/record facts and route the candidate as visibly pending.
            # A bounded read may preserve a claimed negative verdict as an
            # explicitly non-authoritative challenge; none of these bytes may
            # supply severity, evidence, title, location, or report removal.
            vtxt = ""
            try:
                untrusted_claim_text = _llm_norm(
                    read_bounded_regular_bytes(vp, 4 * 1024 * 1024).decode(
                        "utf-8", errors="replace"
                    )
                )
            except (OSError, RuntimeError, UnicodeError, ValueError):
                untrusted_claim_text = ""
        status = (
            _verifier_status_from_text(vtxt)
            if verifier_complete
            else "UNRESOLVED"
        )
        claimed_status = (
            status
            if verifier_complete
            else _verifier_status_from_text(untrusted_claim_text)
        )
        # Phase B: matrix is authoritative when Impact + Likelihood are present.
        # Falls back to LLM/queue severity otherwise (back-compat).
        severity = (
            _enforce_severity_matrix(vtxt, row)
            if verifier_complete
            else normalize_severity(row.get("severity", "") or "Medium")
        )
        # P0-V: unresolved is driven by verifier text OR a skeptic proposal,
        # but it never changes the tier without typed independent authority.
        unresolved = any(tok in status for tok in ("UNRESOLVED", "PARTIAL")) or (
            fid.upper() in judge_unresolved_ids
        )
        adjustments: list[str] = []
        if unresolved:
            original_severity = severity
            adjustments.append(f"UNRESOLVED({original_severity})")
        poc_cap = poc_caps.get(fid)
        if poc_cap:
            capped = _cap_severity_at(severity, poc_cap["capped_at"])
            if capped != severity:
                adjustments.append(f"POC_FAIL_CAP:{poc_cap['capped_at']}")
            severity = capped
        title = (
            row.get("title", "").strip()
            or str(record.get("title", "") if record else "").strip()
            or _first_heading_title(vtxt)
            or "Verified finding"
        )
        title = _sanitize_client_title(re.sub(r"\s+", " ", title).replace("|", "/").strip())
        if record and _is_placeholder_report_title(title):
            title = _record_title(record) or title
        location = (
            row.get("location", "").strip()
            or str(record.get("location", "") if record else "").strip()
            or _field_from_markdown(vtxt, ("Location", "Primary Location"))
            or f"verify_{fid}.md"
        ).replace("|", "/")
        evidence = (
            _field_from_markdown(vtxt, ("Evidence Tag", "Evidence Tags", "Evidence"))
            or _field_from_markdown(vtxt, ("Preferred Tag", "Preferred Evidence"))
            or row.get("preferred tag", "")
            or (EVIDENCE_TAG_DEFAULT if verifier_complete else "UNVERIFIED")
        ).replace("|", "/")

        proposed_negative_status = (
            claimed_status
            if not _is_reportable_verdict(claimed_status)
            else ""
        )
        if proposed_negative_status:
            excluded.append({
                "finding_id": fid,
                "severity": severity,
                "title": title,
                "verdict": proposed_negative_status,
                "reason": (
                    f"{proposed_negative_status} claimed in verify_{fid}.md; "
                    "terminal authority not established"
                ),
            })
            # A verifier-authored negative is a challenge that requires typed
            # closure authority.  Keep the exact candidate active and preserve
            # the proposal for later adjudication.
            unresolved = True
            adjustments.append(
                f"UNPROVEN_NEGATIVE({proposed_negative_status})"
            )
        # Phase C: pre-compute dedup signature from verify body for clustering.
        sig = _dedup_signature_for_finding(vtxt, severity=severity, hint_title=title)
        raw_active.append({
            "finding_id": fid,
            "severity": severity,
            "title": title,
            "location": location,
            "evidence": evidence,
            "verdict": status,
            "unresolved": bool(unresolved),
            "severity_adjustments": adjustments,
            "report_blocked": not verifier_complete,
            "_sig_key": sig.key(),
            "_sig_vuln": sig.vuln_class,
            "_sig_fix": sig.fix_pattern,
        })

    # ----- Phase C: nominate signature clusters, never apply them here -----
    consolidation_map: list[dict] = []
    by_key: dict[tuple, list[dict]] = {}
    for r in raw_active:
        by_key.setdefault(r["_sig_key"], []).append(r)
    consolidated: list[dict] = []
    consumed_ids: set[str] = set()
    for key, members in by_key.items():
        if len(members) >= 3:
            sig = DedupSignature(
                severity=members[0]["severity"],
                fix_pattern=members[0]["_sig_fix"],
                vuln_class=members[0]["_sig_vuln"],
            )
            absorbed = [m["finding_id"] for m in members]
            class_title = _consolidated_title_for(sig)
            locations = " ; ".join(sorted({m["location"] for m in members}))
            # Use strongest evidence (mechanical proof > trace > default)
            best_evidence = members[0]["evidence"]
            for m in members[1:]:
                if has_mechanical_proof(m["evidence"]):
                    best_evidence = m["evidence"]
                    break
            # Use most conservative verdict (CONFIRMED > PARTIAL > rest)
            _VERDICT_RANK = {"CONFIRMED": 3, "PARTIAL": 2, "CONTESTED": 1}
            best_verdict = max(
                members, key=lambda m: _VERDICT_RANK.get(m["verdict"], 0)
            )["verdict"]
            # Preserve unresolved if ANY member is unresolved.
            any_unresolved = any(bool(m.get("unresolved")) for m in members)
            consolidation_map.append({
                "title": class_title,
                "severity": members[0]["severity"],
                "vuln_class": sig.vuln_class,
                "fix_pattern": sig.fix_pattern,
                "absorbed_finding_ids": absorbed,
                "authority_state": "PROPOSAL_ONLY",
            })

    active: list[dict[str, str]] = []
    # Keep all non-clustered raw rows + the consolidated rows, preserving order.
    for r in raw_active:
        if r["finding_id"] in consumed_ids:
            continue
        active.append({
            "finding_id": r["finding_id"],
            "severity": r["severity"],
            "title": r["title"],
            "location": r["location"],
            "evidence": r["evidence"],
            "verdict": r["verdict"],
            "unresolved": r["unresolved"],
            "severity_adjustments": r.get("severity_adjustments", []),
            "absorbed_finding_ids": [],
            "report_blocked": bool(r.get("report_blocked")),
        })
    # `consolidated`/`consumed_ids` intentionally remain empty.  An applied
    # lossless-equivalence receipt upstream is the only identity-removal path.

    # Re-sort by severity rank then by original verdict order (stable).
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    active.sort(key=lambda r: sev_rank.get(r["severity"], 99))

    # Assign report IDs after consolidation.
    for r in active:
        prefix = _report_prefix_for_severity(r["severity"])
        counters[prefix] += 1
        r["report_id"] = f"{prefix}-{counters[prefix]:02d}"

    lines = [
        "# Report Index",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {counters['C']} |",
        f"| High | {counters['H']} |",
        f"| Medium | {counters['M']} |",
        f"| Low | {counters['L']} |",
        f"| Informational | {counters['I']} |",
        f"| Total | {sum(counters.values())} |",
        "",
        "## Master Finding Index",
        "",
        "| Report ID | Title | Severity | Location | Evidence Tag | Verdict | Trust Adj. | Internal Hypothesis ID |",
        "|-----------|-------|----------|----------|--------------|---------|------------|------------------------|",
    ]
    for r in active:
        adj = ", ".join(r.get("severity_adjustments") or [])
        lines.append(
            f"| {r['report_id']} | {r['title']} | {r['severity']} | {r['location']} | "
            f"{r['evidence']} | {r['verdict']} | {adj} | {r['finding_id']} |"
        )
    if consolidation_map:
        lines.extend([
            "",
            "## Proposed Consolidation Map (Non-authoritative)",
            "",
            "| Report ID | Title | Severity | Absorbed Findings | Reason |",
            "|-----------|-------|----------|-------------------|--------|",
        ])
        for cm in consolidation_map:
            report_id = "PROPOSAL"
            lines.append(
                f"| {report_id} | {cm['title']} | {cm['severity']} | "
                f"{', '.join(cm['absorbed_finding_ids'])} | "
                f"Same fix pattern ({cm['fix_pattern']}) and severity |"
            )
    lines.extend([
        "",
        "## Proposed Negative Dispositions (Non-authoritative)",
        "",
        "| Internal ID | Severity | Title | Exclusion Reason |",
        "|-------------|----------|-------|------------------|",
    ])
    for r in excluded:
        lines.append(
            f"| {r['finding_id']} | {r['severity']} | {r['title']} | {r['reason'].replace('|', '/')} |"
        )
    lines.append("")
    (scratchpad / "report_index.md").write_text("\n".join(lines), encoding="utf-8")
    (scratchpad / "report_records.json").write_text(
        json.dumps(
            {
                "active": active,
                "excluded": [],
                "negative_disposition_proposals": excluded,
                "consolidation_map": consolidation_map,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    coverage_lines = [
        "# Report Coverage",
        "",
        "Deterministic report-index coverage emitted by `_write_mechanical_report_index`.",
        "",
        "## Counts",
        "",
        f"- Verification queue rows parsed: {len(rows)}",
        f"- Active report rows: {len(active)}",
        "- Excluded rows: 0",
        f"- Negative disposition proposals: {len(excluded)}",
        f"- Consolidation proposals: {len(consolidation_map)}",
        "",
        "## Active Trace",
        "",
        "| Report ID | Internal Finding IDs | Severity | Verdict | Evidence Tag |",
        "|-----------|----------------------|----------|---------|--------------|",
    ]
    for r in active:
        ids = r.get("absorbed_finding_ids") or [r["finding_id"]]
        coverage_lines.append(
            f"| {r['report_id']} | {', '.join(ids).replace('|', '/')} | "
            f"{r['severity']} | {r['verdict']} | {r['evidence']} |"
        )
    coverage_lines.extend([
        "",
        "## Proposed Negative Disposition Trace",
        "",
        "| Internal Finding ID | Severity | Verdict / Reason |",
        "|---------------------|----------|------------------|",
    ])
    for r in excluded:
        coverage_lines.append(
            f"| {r['finding_id']} | {r['severity']} | {r['reason'].replace('|', '/')} |"
        )
    promoted_ids = {
        fid.upper()
        for r in active
        for fid in (r.get("absorbed_finding_ids") or [r["finding_id"]])
    }
    excluded_ids: set[str] = set()
    raw_rows = _collect_raw_candidate_ledger_rows(
        scratchpad, promoted_ids, excluded_ids
    )
    coverage_lines.extend([
        "",
        "## Raw Candidate Ledger",
        "",
        "| Source Artifact | Candidate ID | Disposition |",
        "|-----------------|--------------|-------------|",
    ])
    if raw_rows:
        coverage_lines.extend(raw_rows)
    else:
        coverage_lines.append("| _No raw candidate IDs found_ | n/a | n/a |")
    coverage_lines.append("")
    (scratchpad / "report_coverage.md").write_text(
        "\n".join(coverage_lines),
        encoding="utf-8",
    )
    if prepare_body:
        for _tier in ("critical_high", "medium", "low_info"):
            ensure_report_tier_shards(scratchpad, _tier)
        # Phase E5 prerequisite: emit body-writer manifests so the next phase
        # (tier writer, mechanical or LLM) has a verified-evidence anchor. The
        # manifest dir doubles as the validator's source of truth.
        try:
            _build_body_writer_manifests(scratchpad)
        except Exception as exc:
            log.warning(
                f"[report_index] body-writer manifest emission failed: {exc!r}"
            )
    return len(active)


def _latest_report_index_backup(scratchpad: Path, filename: str) -> Path | None:
    """Return only an authenticated live root; retry backups are control data."""

    direct = scratchpad / filename
    if not direct.is_file():
        return None
    try:
        raw = direct.read_bytes()
        if not raw:
            return None
        ledger = read_artifact_ledger(Path(scratchpad))
        identity = f"scratchpad:{filename}"
        binding = ledger.get("artifact_bindings", {}).get(identity)
        if not isinstance(binding, dict):
            return None
        run_id = str(binding.get("run_id") or "").strip()
        if not run_id:
            return None
        if semantic_input_prebind_producer_authority_issues(
            scratchpad,
            scratchpad.parent,
            (identity,),
            run_id=run_id,
        ):
            return None
    except (OSError, TypeError, ValueError):
        return None
    return direct


def _split_markdown_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _join_markdown_row(cells: list[str]) -> str:
    return "| " + " | ".join((c or "").replace("|", "/").strip() for c in cells) + " |"


def _report_id_replace_once(text: str, rid_map: dict[str, str]) -> str:
    if not rid_map:
        return text
    old_ids = sorted((re.escape(k) for k in rid_map), key=len, reverse=True)
    pat = re.compile(r"(?<![A-Z0-9-])(" + "|".join(old_ids) + r")(?![A-Z0-9-])")
    return pat.sub(lambda m: rid_map.get(m.group(1), m.group(1)), text)


def _replace_or_insert_summary_counts(text: str, counts: dict[str, int]) -> str:
    total = sum(counts.values())
    summary = "\n".join([
        "## Summary Counts",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {counts.get('Critical', 0)} |",
        f"| High | {counts.get('High', 0)} |",
        f"| Medium | {counts.get('Medium', 0)} |",
        f"| Low | {counts.get('Low', 0)} |",
        f"| Informational | {counts.get('Informational', 0)} |",
        f"| **Total** | **{total}** |",
    ])
    m = re.search(
        r"(?ms)^##\s+Summary(?:\s+Counts)?\b.*?(?=^---\s*$\n\n^##|\n\n^##\s+Master\s+Finding\s+Index\b)",
        text,
    )
    if m:
        return text[:m.start()] + summary + "\n\n" + text[m.end():].lstrip()
    anchor = re.search(r"(?m)^##\s+Master\s+Finding\s+Index\b", text)
    if anchor:
        return text[:anchor.start()] + summary + "\n\n---\n\n" + text[anchor.start():]
    return summary + "\n\n---\n\n" + text


def _build_tier_assignments_from_index_rows(rows: list[dict[str, object]]) -> str:
    def verify_files_for(internal: str) -> str:
        ids = [
            _normalize_finding_id(fid) or fid
            for fid in _INTERNAL_FINDING_ID_RE.findall(internal or "")
        ]
        paths = [f".scratchpad/verify_{fid}.md" for fid in ids if not fid.startswith("CH-")]
        return ", ".join(paths) if paths else "(see constituent verification files)"

    groups = [
        ("Critical+High Tier (for Opus writer)", {"Critical", "High"}),
        ("Medium Tier (for Sonnet writer)", {"Medium"}),
        ("Low+Info Tier (for Sonnet writer)", {"Low", "Informational"}),
    ]
    out = ["## Tier Assignments", ""]
    for title, severities in groups:
        out.extend([
            f"### {title}",
            "",
            "| Report ID | Internal Hypothesis | Verify File(s) | Notes |",
            "|-----------|---------------------|----------------|-------|",
        ])
        for row in rows:
            if str(row["severity"]) not in severities:
                continue
            internal = str(row.get("internal", "")).strip()
            notes = str(row.get("verification", "") or row.get("trust_adj", "") or "Mapped from Master Finding Index")
            out.append(
                f"| {row['report_id']} | {internal} | {verify_files_for(internal)} | {notes.replace('|', '/')} |"
            )
        out.append("")
    return "\n".join(out).rstrip()


def _replace_section(text: str, heading_re: str, replacement: str) -> str:
    m = re.search(heading_re, text, re.IGNORECASE | re.MULTILINE)
    if not m:
        return text.rstrip() + "\n\n---\n\n" + replacement.strip() + "\n"
    next_heading = re.search(r"(?m)^##\s+", text[m.end():])
    end = m.end() + next_heading.start() if next_heading else len(text)
    return text[:m.start()] + replacement.strip() + "\n" + text[end:]


def _replace_completeness_assertion(text: str, rows: list[dict[str, object]]) -> str:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for row in rows:
        sev = str(row.get("severity", ""))
        if sev in counts:
            counts[sev] += 1
    receipt = "\n".join([
        "## Completeness Assertion",
        "",
        "```",
        "REPORT_INDEX_REPAIRED_BY_PYTHON: true",
        f"Reportable rows: {sum(counts.values())}",
        f"Critical: {counts['Critical']}",
        f"High: {counts['High']}",
        f"Medium: {counts['Medium']}",
        f"Low: {counts['Low']}",
        f"Informational: {counts['Informational']}",
        "Coverage accounting remains in report_coverage.md.",
        "```",
    ])
    return _replace_section(text, r"(?m)^##\s+Completeness\s+Assertion\b.*$", receipt)


def _repair_sc_report_index_from_prior(
    scratchpad: Path,
    *,
    prepare_body: bool = True,
) -> int:
    """Repair an SC LLM report index when only mechanical contracts failed.

    SC report indexing is a semantic consolidation step, so replacing it with
    the L1 deterministic index can discard useful titles and grouping. Preserve
    the LLM index, then mechanically repair contract violations whose source of
    truth is already known to Python: report-ID tier, final severity, summary
    counts, and writer routing.
    """
    source = _latest_report_index_backup(scratchpad, "report_index.md")
    if source is None:
        return 0
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    lines = text.splitlines()
    header_idx = -1
    for i, line in enumerate(lines):
        lowered = line.lower()
        if line.lstrip().startswith("|") and "report id" in lowered and "severity" in lowered:
            header_idx = i
            break
    if header_idx < 0 or header_idx + 1 >= len(lines):
        return 0
    end_idx = header_idx + 2
    while end_idx < len(lines) and lines[end_idx].lstrip().startswith("|"):
        end_idx += 1

    headers = _split_markdown_row(lines[header_idx])
    keys = [_norm_key(h) for h in headers]
    try:
        rid_i = keys.index("report id")
    except ValueError:
        return 0
    sev_i = keys.index("severity") if "severity" in keys else -1
    verification_i = keys.index("verification") if "verification" in keys else -1
    trust_i = next(
        (i for i, k in enumerate(keys) if k in {"trust adj", "trust adjustment", "severity trail", "sev trail", "adjustment"}),
        -1,
    )
    internal_i = next(
        (i for i, k in enumerate(keys) if k in {"internal hypothesis", "internal hypothesis id", "internal id", "finding id", "hypothesis"}),
        -1,
    )
    if sev_i < 0 or internal_i < 0:
        return 0

    expected_by_id = _expected_report_index_severities(scratchpad)
    severity_rank_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    # P0-V (SC parity): skeptic UNRESOLVED proposals are visible status only;
    # they do not demote the preserved tier.
    try:
        judge_unresolved_ids = {
            x.upper() for x in _collect_judge_unresolved_ids(scratchpad)
        }
    except Exception:
        judge_unresolved_ids = set()
    rows: list[dict[str, object]] = []
    changed = False
    for original_order, line in enumerate(lines[header_idx + 2:end_idx]):
        cells = _split_markdown_row(line)
        if len(cells) < len(headers):
            cells.extend([""] * (len(headers) - len(cells)))
        rid = (_normalize_report_id(cells[rid_i]) or cells[rid_i]).upper()
        if not re.fullmatch(r"[CHMLI]-\d+", rid or "", re.IGNORECASE):
            continue
        internal = cells[internal_i]
        ids = [
            _normalize_finding_id(fid) or fid
            for fid in _INTERNAL_FINDING_ID_RE.findall(internal)
        ]
        current_sev = normalize_severity(cells[sev_i])
        expected = [expected_by_id[fid] for fid in ids if fid in expected_by_id]
        target_sev = current_sev
        if expected:
            source_sev = min(expected, key=lambda sev: severity_rank_map.get(sev, 99))
            reason_values = [
                cells[trust_i] if trust_i >= 0 and trust_i < len(cells) else "",
                cells[verification_i] if verification_i >= 0 and verification_i < len(cells) else "",
                cells[sev_i],
            ]
            if current_sev != source_sev and not _report_index_adjustment_reason_present(*reason_values):
                target_sev = source_sev
                cells[sev_i] = source_sev
                changed = True
        # P0-V (SC parity): stamp disagreement without a tier mutation.
        row_ids_upper = {fid.upper() for fid in ids}
        existing_trust = cells[trust_i] if 0 <= trust_i < len(cells) else ""
        if (
            judge_unresolved_ids
            and (row_ids_upper & judge_unresolved_ids)
            and not re.search(r"\bUNRESOLVED\s*\(", existing_trust, re.IGNORECASE)
        ):
            pre_demote = target_sev
            if sev_i >= 0 and sev_i < len(cells):
                cells[sev_i] = target_sev
            token = f"UNRESOLVED({pre_demote})"
            if trust_i >= 0 and trust_i < len(cells):
                cells[trust_i] = (
                    f"{existing_trust.strip()}, {token}".lstrip(", ").strip()
                    if existing_trust.strip()
                    else token
                )
            changed = True
        rows.append({
            "old_report_id": rid,
            "report_id": rid,
            "severity": target_sev,
            "cells": cells,
            "order": original_order,
            "internal": internal,
            "verification": cells[verification_i] if verification_i >= 0 and verification_i < len(cells) else "",
            "trust_adj": cells[trust_i] if trust_i >= 0 and trust_i < len(cells) else "",
        })

    if not rows:
        return 0

    counters = {sev: 0 for sev in SEVERITY_ORDER}
    ordered: list[dict[str, object]] = []
    for sev in SEVERITY_ORDER:
        sev_rows = [r for r in rows if r["severity"] == sev]
        sev_rows.sort(key=lambda r: int(r["order"]))
        for row in sev_rows:
            counters[sev] += 1
            new_rid = f"{SEVERITY_LETTER[sev]}-{counters[sev]:02d}"
            if row["old_report_id"] != new_rid:
                changed = True
            row["report_id"] = new_rid
            cells = list(row["cells"])
            cells[rid_i] = new_rid
            cells[sev_i] = sev
            row["cells"] = cells
            ordered.append(row)

    table_lines = [
        _join_markdown_row(headers),
        lines[header_idx + 1],
        *[_join_markdown_row(list(row["cells"])) for row in ordered],
    ]
    rid_map = {
        str(row["old_report_id"]): str(row["report_id"])
        for row in ordered
        if row["old_report_id"] != row["report_id"]
    }
    table_text = "\n".join(table_lines)
    before_table = _report_id_replace_once("\n".join(lines[:header_idx]), rid_map)
    after_table = _report_id_replace_once("\n".join(lines[end_idx:]), rid_map)
    repaired = before_table.rstrip() + "\n\n" + table_text + "\n\n" + after_table.lstrip()
    repaired = _replace_or_insert_summary_counts(repaired, counters)
    repaired = _replace_section(
        repaired,
        r"(?m)^##\s+Tier\s+Assignments\b.*$",
        _build_tier_assignments_from_index_rows(ordered),
    )
    repaired = _replace_completeness_assertion(repaired, ordered)
    if changed:
        repaired += "\n## Mechanical Repair Receipt\n\n"
        repaired += "- Repaired report IDs and severity tiers from verifier/queue authority.\n"
        repaired += "- Rebuilt summary counts and tier assignments from Master Finding Index.\n"
        if rid_map:
            repaired += "- Report ID remap: " + ", ".join(f"{k}->{v}" for k, v in rid_map.items()) + "\n"

    (scratchpad / "report_index.md").write_text(repaired, encoding="utf-8")

    coverage_source = _latest_report_index_backup(scratchpad, "report_coverage.md")
    if coverage_source is not None:
        try:
            cov = coverage_source.read_text(encoding="utf-8", errors="replace")
            cov = _report_id_replace_once(cov, rid_map)
            (scratchpad / "report_coverage.md").write_text(cov, encoding="utf-8")
        except Exception:
            pass
    elif not (scratchpad / "report_coverage.md").exists():
        (scratchpad / "report_coverage.md").write_text(
            "# Report Coverage\n\nMechanical SC report-index repair had no prior coverage ledger.\n",
            encoding="utf-8",
        )

    if prepare_body:
        try:
            _build_sc_body_writer_manifests(scratchpad)
        except Exception as exc:
            log.warning(
                f"[report_index] SC body manifest rebuild after repair failed: {exc!r}"
            )
    return len(ordered)


def _shard_name_for_severity(severity: str) -> str:
    sev = normalize_severity(severity)
    if sev in ("Critical", "High"):
        return "report_critical_high"
    if sev == "Medium":
        return "report_medium"
    return "report_low_info"


def _parse_report_index_excluded_records(scratchpad: Path) -> list[dict[str, str]]:
    """Parse client-safe excluded records from an LLM-authored report index."""
    idx = scratchpad / "report_index.md"
    if not idx.exists():
        return []
    try:
        text = _llm_norm(idx.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    m = re.search(r"(?ims)^##\s+Excluded\s+Findings\b.*?(?=^##\s|\Z)", text)
    if not m:
        return []
    section = m.group(0)
    records: list[dict[str, str]] = []
    headers, rows = _parse_markdown_table(section, [])
    if headers:
        keys = [_norm_key(h) for h in headers]
        for row in rows:
            d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
            raw_id = (
                d.get("internal id")
                or d.get("internal hypothesis id")
                or d.get("internal hypothesis")
                or d.get("finding id")
                or d.get("id")
                or ""
            )
            fid = _normalize_finding_id(raw_id) or raw_id.strip()
            title = _sanitize_client_title(d.get("title", "") or "Excluded finding")
            reason = _sanitize_client_body(
                d.get("exclusion reason")
                or d.get("reason")
                or d.get("verdict")
                or d.get("status")
                or "Excluded by report index"
            )
            severity = normalize_severity(d.get("severity", "") or "Informational")
            if fid or title:
                records.append({
                    "finding_id": fid,
                    "severity": severity,
                    "title": title,
                    "reason": reason,
                    "verdict": reason,
                })
    if records:
        return records
    seen: set[str] = set()
    for match in _INTERNAL_FINDING_ID_RE.finditer(section):
        fid = _normalize_finding_id(match.group(1)) or match.group(1)
        if fid in seen:
            continue
        seen.add(fid)
        records.append({
            "finding_id": fid,
            "severity": "Informational",
            "title": "Excluded finding",
            "reason": "Excluded by report index",
            "verdict": "Excluded by report index",
        })
    return records


def _clean_finding_id_list(values: list[str] | tuple[str, ...] | None) -> list[str]:
    """Normalize and drop blank finding IDs before deriving artifact names."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        fid = _normalize_finding_id(str(raw or "")) or str(raw or "").strip()
        if not fid or fid in seen:
            continue
        seen.add(fid)
        out.append(fid)
    return out


def _body_writer_poc_result_field(verify_text: str) -> str:
    """Extract verifier PoC/result text for report body manifests."""
    return _field_or_section(
        verify_text or "",
        (
            "PoC Result",
            "Execution Result",
            "Execution Output",
            "Test Output",
            "Proof",
        ),
        (
            "PoC Result",
            "Execution Result",
            "Execution Output",
            "Test Output",
            "Proof",
            "Reproduction",
            "PoC Attempt",
            "PoC Execution",
        ),
        fallback="",
        max_chars=2500,
    ).strip()


def _materialize_report_evidence_or_debt(scratchpad: Path) -> bool:
    """Build the P1-K boundary haltlessly and make any failure durable."""

    try:
        _materialize_report_evidence_runtime(scratchpad)
    except (OSError, UnicodeError, json.JSONDecodeError, _ReportEvidenceError, ValueError) as exc:
        (scratchpad / "report_evidence_runtime_debt.md").write_text(
            "# Report Evidence Runtime Debt\n\n"
            "Typed report evidence could not be reconciled before body rendering. "
            "All report assignments remain retained, but evidence presentation is "
            "degraded and requires human review.\n\n"
            f"- Failure class: `{type(exc).__name__}`\n"
            f"- Detail: `{str(exc).replace('`', "'")[:800]}`\n",
            encoding="utf-8",
        )
        return False
    (scratchpad / "report_evidence_runtime_debt.md").unlink(missing_ok=True)
    return True


def _verification_runtime_debt_binding(
    scratchpad: Path, candidate_ids: list[str]
) -> dict[str, Any] | None:
    """Return an exact, proof-free retention source for missing verifier files.

    The binding is emitted only when the central denominator validator replays
    the current queue/work-plan bytes and covers every requested identity.
    It is provenance for an explicitly UNRESOLVED report row; it never stands
    in for verifier evidence or execution.
    """

    missing = [
        candidate_id
        for candidate_id in dict.fromkeys(candidate_ids)
        if candidate_id
        and not _verifier_output_has_completion_authority(
            scratchpad, candidate_id
        )
    ]
    if not missing:
        return None
    covered, issues = _verification_runtime_debt_coverage(scratchpad, missing)
    if issues or any(candidate_id not in covered for candidate_id in missing):
        return None
    path = scratchpad / "verification_runtime_debt.json"
    if not path.is_file():
        return None
    return {
        "artifact": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "covered_candidate_ids": missing,
        "authority": "RETENTION_ONLY",
        "verifier_status": "UNRESOLVED",
        "proof_authority": "NONE",
    }


def _build_body_writer_manifests(
    scratchpad: Path,
    *,
    persist: bool = True,
    materialize_evidence: bool = True,
) -> dict[str, dict]:
    """Emit per-shard manifests anchored to verified evidence.

    Splits shards when their finding count exceeds the per-tier cap. Cap names
    follow the convention `report_xxx_a`, `report_xxx_b`, etc.
    """
    records_path = scratchpad / "report_records.json"
    if not records_path.exists():
        return {}
    try:
        records = json.loads(records_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    active = records.get("active", [])
    inventory_location_by_id = _inventory_location_map(scratchpad)
    finding_record_maps = _load_finding_record_maps(scratchpad)
    # Group rows by tier shard.
    grouped: dict[str, list[dict]] = {
        "report_critical_high": [],
        "report_medium": [],
        "report_low_info": [],
    }
    for row in active:
        sev = row.get("severity", "")
        shard = _shard_name_for_severity(sev)
        verify_files = []
        absorbed = _clean_finding_id_list(row.get("absorbed_finding_ids") or [])
        row_finding_ids = _clean_finding_id_list([row.get("finding_id", "")])
        row_finding_id = row_finding_ids[0] if row_finding_ids else ""
        if absorbed:
            verify_files = [f"verify_{fid}.md" for fid in absorbed]
        else:
            if row_finding_id:
                verify_files = [f"verify_{row_finding_id}.md"]
        evidence_ids = absorbed or ([row_finding_id] if row_finding_id else [])
        record = _finding_record_for_ids(
            scratchpad,
            absorbed or ([row_finding_id] if row_finding_id else []),
            finding_record_maps,
        )
        # Pull narrative seed from the primary verify file, but evaluate
        # evidence completeness across every absorbed verifier file.
        primary_verify_path = (
            (scratchpad / verify_files[0]) if verify_files else None
        )
        verify_text = ""
        primary_complete = bool(evidence_ids) and (
            _verifier_output_has_completion_authority(
                scratchpad, evidence_ids[0]
            )
        )
        if primary_verify_path and primary_verify_path.exists() and primary_complete:
            try:
                verify_text = _llm_norm(primary_verify_path.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                verify_text = ""
        desc, rec = _body_writer_evidence_fields(verify_text)
        poc_result = _body_writer_poc_result_field(verify_text)
        if (not desc or not _is_substantive_body_evidence(desc)) and record:
            desc = str(
                record.get("description")
                or record.get("root_cause")
                or record.get("impact")
                or ""
            )
        location = (row.get("location", "") or "").strip()
        if not _looks_like_code_location(location) or _is_test_or_mock_location(location):
            location = ""
        if not location:
            for index, vf in enumerate(verify_files):
                p = scratchpad / vf
                candidate_id = (
                    evidence_ids[index] if index < len(evidence_ids) else ""
                )
                if (
                    not p.exists()
                    or not candidate_id
                    or not _verifier_output_has_completion_authority(
                        scratchpad, candidate_id
                    )
                ):
                    continue
                try:
                    txt = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    txt = ""
                location = _extract_code_location_from_text(txt)
                if location and not _is_test_or_mock_location(location):
                    break
                location = ""
        if not location:
            location = _inventory_location_for_ids(
                scratchpad,
                absorbed or ([row_finding_id] if row_finding_id else []),
                inventory_location_by_id,
            )
        verify_statuses = []
        report_blocked = not bool(verify_files)
        for index, vf in enumerate(verify_files):
            p = scratchpad / vf
            txt = ""
            candidate_id = evidence_ids[index] if index < len(evidence_ids) else ""
            complete = bool(candidate_id) and _verifier_output_has_completion_authority(
                scratchpad, candidate_id
            )
            if p.exists() and complete:
                try:
                    txt = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    txt = ""
            missing = (
                not complete
                or (not p.exists())
                or _is_evidence_missing_for_body(txt)
            )
            verify_statuses.append({"file": vf, "exists": p.exists(), "evidence_missing": bool(missing)})
            if missing:
                report_blocked = True
        runtime_debt = _verification_runtime_debt_binding(
            scratchpad,
            absorbed or ([row_finding_id] if row_finding_id else []),
        )
        grouped[shard].append({
            "report_id": row.get("report_id", ""),
            "finding_id": row_finding_id,
            "severity": row.get("severity", ""),
            "title": (
                _record_title(record)
                if record and _is_placeholder_report_title(str(row.get("title", "")))
                else row.get("title", "")
            ) or str(record.get("title", "") if record else ""),
            "location": location,
            "evidence_tag": row.get("evidence", EVIDENCE_TAG_DEFAULT),
            "verify_file": verify_files[0] if verify_files else "",
            "verify_files": verify_files,
            "verify_statuses": verify_statuses,
            "description": desc,
            "poc_result": poc_result,
            "recommendation": rec,
            "report_blocked": bool(report_blocked),
            "verification_runtime_debt": runtime_debt,
        })

    manifests: dict[str, dict] = {}
    for shard, rows in grouped.items():
        if not rows:
            continue
        cap = _BODY_SHARD_CAPS.get(shard, 30)
        if len(rows) <= cap:
            manifests[shard] = {"shard": shard, "findings": rows}
        else:
            # Split into _a/_b/_c ... shards balanced by cap.
            n = len(rows)
            n_shards = (n + cap - 1) // cap
            chunk = (n + n_shards - 1) // n_shards
            for i in range(n_shards):
                suffix = chr(ord("a") + i)
                slice_rows = rows[i * chunk : (i + 1) * chunk]
                if not slice_rows:
                    continue
                name = f"{shard}_{suffix}"
                manifests[name] = {"shard": name, "findings": slice_rows}

    if not manifests:
        manifests["report_empty"] = {
            "schema_version": "plamen.empty_report_denominator.v1",
            "shard": "report_empty",
            "denominator_state": "EMPTY",
            "findings": [],
        }

    if not persist:
        return manifests

    # Persist manifests so subsequent phases can read them deterministically.
    out_dir = scratchpad / "body_manifests"
    try:
        out_dir.mkdir(exist_ok=True)
        for old in out_dir.glob("report_*.json"):
            if old.stem not in manifests:
                try:
                    old.unlink()
                except Exception:
                    pass
                for stale in (
                    scratchpad / f"{old.stem}.md",
                    scratchpad / f"{old.stem}_assignments.md",
                ):
                    try:
                        stale.unlink(missing_ok=True)
                    except Exception:
                        pass
        for name, m in manifests.items():
            (out_dir / f"{name}.json").write_text(
                json.dumps(m, indent=2),
                encoding="utf-8",
            )
    except Exception:
        pass
    if (
        materialize_evidence
        and manifests
        and (scratchpad / "report_records.json").exists()
    ):
        _materialize_report_evidence_or_debt(scratchpad)
    return manifests


def _build_sc_body_writer_manifests(
    scratchpad: Path,
    *,
    persist: bool = True,
    materialize_evidence: bool = True,
) -> dict[str, dict]:
    """Build body-writer manifests for SC pipelines from LLM-written report_index.md.

    L1 uses _write_mechanical_report_index -> _build_body_writer_manifests.
    SC receives an LLM-authored report_index.md, so this function bridges the
    gap: it parses report_index.md via get_tier_assignments, enriches each row
    with title/location/evidence from structured finding records and verifier
    files, then writes both body_manifests/*.json and report_records.json for
    downstream assembly/traceability.
    """
    assignments, source = get_tier_assignments(scratchpad)

    # --- Enrich from report_index.md table cells (title, location) ---
    idx_path = scratchpad / "report_index.md"
    title_map: dict[str, str] = {}
    location_map: dict[str, str] = {}
    verification_map: dict[str, str] = {}
    if idx_path.exists():
        try:
            idx_text = _llm_norm(idx_path.read_text(encoding="utf-8", errors="replace"))
            idx_text = _report_index_reportable_text(idx_text)
            idx_text = _report_index_assignment_text(idx_text)
        except Exception:
            idx_text = ""
        id_re = re.compile(r"^[\*\[`_]*([CHMLI]-\d+)\b")
        header_map: dict[str, int] = {}
        for line in idx_text.splitlines():
            s = line.strip()
            if not s.startswith("|"):
                continue
            cells = [c.strip() for c in s.strip("|").split("|")]
            if len(cells) < 2:
                continue
            lowered = [re.sub(r"\s+", " ", c.strip().lower()) for c in cells]
            if "report id" in lowered:
                header_map = {name: idx for idx, name in enumerate(lowered)}
                continue
            m = id_re.match(cells[0])
            if not m:
                continue
            rid = m.group(1)
            title_idx = header_map.get("title", 1)
            location_idx = (
                header_map.get("location")
                if header_map
                else 3
            )
            title_map[rid] = (
                cells[title_idx].strip() if title_idx < len(cells) else ""
            )
            location_map[rid] = (
                cells[location_idx].strip()
                if location_idx is not None and location_idx < len(cells)
                else ""
            )
            verification_idx = (
                header_map.get("verification")
                if header_map
                else None
            )
            if verification_idx is not None and verification_idx < len(cells):
                verification_map[rid] = cells[verification_idx].strip()

    def _extract_internal_ids(value: str) -> list[str]:
        ids = [
            _normalize_finding_id(m.group(1)) or m.group(1)
            for m in _INTERNAL_FINDING_ID_RE.finditer(value or "")
        ]
        if ids:
            return list(dict.fromkeys(ids))
        out: list[str] = []
        for tok in re.split(r"[,;+]\s*", value or ""):
            fid = _normalize_finding_id(tok)
            if fid:
                out.append(fid)
        return list(dict.fromkeys(out))

    try:
        # Additive evidence lookup may inspect proposal-only composition aliases
        # so it can locate every constituent verifier. This does not grant the
        # group deletion, demotion, coverage, or completion authority; each
        # constituent is still checked independently below.
        hypothesis_constituents = _parse_hypothesis_constituents(
            scratchpad,
            include_composition_aliases=True,
        )
    except Exception:
        hypothesis_constituents = {}

    def _verification_cell_verify_ids(report_id: str) -> list[str]:
        """Return concrete verifier IDs explicitly named by the index row."""
        ids: list[str] = []
        for fid in _extract_internal_ids(verification_map.get(report_id, "")):
            if fid.startswith("CH-"):
                continue
            if _verify_file_for_id(scratchpad, fid).exists():
                ids.append(fid)
        return list(dict.fromkeys(ids))

    def _constituent_verify_ids(report_id: str, finding_ids: list[str]) -> list[str]:
        """Resolve report-level chain IDs to the verifier files that prove them.

        Report IDs like H-01 may map to CH-1, but there is no `verify_CH-1.md`.
        The canonical evidence lives in constituent verifier files referenced by
        the report-index Verification cell, e.g. `H-3+H-9`. Treat those as the
        body writer evidence source instead of marking the report blocked.
        """
        explicit_verified = _verification_cell_verify_ids(report_id)
        if explicit_verified:
            return explicit_verified
        expanded = list(finding_ids)
        for fid in list(finding_ids):
            if not fid.startswith("CH-"):
                continue
            constituents: list[str] = []
            for cid in _extract_internal_ids(verification_map.get(report_id, "")):
                if cid.startswith("CH-") or cid in expanded:
                    continue
                if _verify_file_for_id(scratchpad, cid).exists():
                    constituents.append(cid)
            for cid in hypothesis_constituents.get(fid, []) or []:
                if cid.startswith("CH-") or cid in expanded or cid in constituents:
                    continue
                if _verify_file_for_id(scratchpad, cid).exists():
                    constituents.append(cid)
            if constituents:
                return list(dict.fromkeys([
                    cid for cid in expanded if not cid.startswith("CH-")
                ] + constituents))
        return expanded

    queue_location_by_id: dict[str, str] = {}
    inventory_location_by_id = _inventory_location_map(scratchpad)
    finding_record_maps = _load_finding_record_maps(scratchpad)
    try:
        for qrow in _report_candidate_universe_rows(scratchpad):
            qfid = (
                qrow.get("finding id")
                or qrow.get("hypothesis id")
                or qrow.get("id")
                or ""
            ).strip()
            qloc = (
                qrow.get("location")
                or qrow.get("primary location")
                or qrow.get("source location")
                or ""
            ).strip()
            norm = _normalize_finding_id(qfid) or qfid
            if (
                norm
                and qloc
                and _looks_like_code_location(qloc)
                and not _is_test_or_mock_location(qloc)
            ):
                queue_location_by_id[norm] = qloc
    except Exception:
        queue_location_by_id = {}

    # --- Build per-finding records ---
    grouped: dict[str, list[dict]] = {
        "report_critical_high": [],
        "report_medium": [],
        "report_low_info": [],
    }
    active_records: list[dict[str, object]] = []
    _SEV_EXPAND = {
        "C": "Critical", "H": "High", "M": "Medium",
        "L": "Low", "I": "Informational",
    }
    for row in assignments:
        report_id = row.get("report_id", "")
        if not re.fullmatch(r"[CHMLI]-\d+", report_id or "", re.IGNORECASE):
            continue
        report_id = report_id.upper()
        finding_id = row.get("finding_id", "")
        finding_ids = _extract_internal_ids(finding_id)
        is_chain_report = any(fid.startswith("CH-") for fid in finding_ids)
        verify_ids = _constituent_verify_ids(report_id, finding_ids)
        sev_letter = row.get("severity", "")
        sev_full = _SEV_EXPAND.get(sev_letter, sev_letter)
        shard = _shard_name_for_severity(sev_full)

        title = title_map.get(report_id, "")
        location = location_map.get(report_id, "")
        record = _finding_record_for_ids(scratchpad, verify_ids, finding_record_maps)

        verify_text = ""
        primary_fid = verify_ids[0] if verify_ids else ""
        primary_complete = bool(primary_fid) and (
            _verifier_output_has_completion_authority(
                scratchpad, primary_fid
            )
        )
        if primary_fid and primary_complete:
            vf = _verify_file_for_id(scratchpad, primary_fid)
            if vf.exists():
                try:
                    verify_text = _llm_norm(vf.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    pass

        verify_title = _verified_claim_title(verify_text) if verify_text else ""
        if (
            verify_title
            and len(verify_ids) == 1
            and not is_chain_report
            and (not title or _titles_conflict(title, verify_title))
        ):
            title = verify_title
        elif not title and verify_title:
            title = verify_title
        if record and _is_placeholder_report_title(title):
            title = _record_title(record) or title
        desc, rec = _body_writer_evidence_fields(verify_text)
        poc_result = _body_writer_poc_result_field(verify_text)
        if (not desc or not _is_substantive_body_evidence(desc)) and record:
            desc = str(
                record.get("description")
                or record.get("root_cause")
                or record.get("impact")
                or ""
            )
        evidence_tag = (
            _field_from_markdown(verify_text, ("Evidence Tag", "Evidence", "Preferred Tag", "Preferred Evidence"))
            or str(record.get("preferred_tag", "") if record else "")
            or (EVIDENCE_TAG_DEFAULT if primary_complete else "UNVERIFIED")
        ).strip()
        if location and (not _looks_like_code_location(location) or _is_test_or_mock_location(location)):
            location = ""
        verify_location = _extract_code_location_from_text(verify_text) if verify_text else ""
        verify_location_authoritative = bool(verify_location and verify_text)
        if not verify_location:
            for fid in finding_ids:
                vf = _verify_file_for_id(scratchpad, fid)
                if (
                    not vf.exists()
                    or not _verifier_output_has_completion_authority(
                        scratchpad, fid
                    )
                ):
                    continue
                try:
                    candidate_text = _llm_norm(vf.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    candidate_text = ""
                verify_location = _extract_code_location_from_text(candidate_text)
                if verify_location:
                    verify_location_authoritative = True
                    break
        if not verify_location:
            for fid in verify_ids:
                norm = _normalize_finding_id(fid) or fid
                verify_location = queue_location_by_id.get(norm, "")
                if verify_location:
                    break
        if not verify_location and record:
            candidate = str(record.get("location", "") or "")
            if _looks_like_code_location(candidate) and not _is_test_or_mock_location(candidate):
                verify_location = candidate
        if not verify_location:
            verify_location = _inventory_location_for_ids(
                scratchpad,
                verify_ids,
                inventory_location_by_id,
            )
        if verify_location and len(verify_ids) == 1 and verify_location_authoritative and not is_chain_report:
            if not location:
                location = verify_location
            else:
                loc_files = {
                    Path(m.group(0).split(":", 1)[0].replace("\\", "/")).name.lower()
                    for m in re.finditer(
                        r"[A-Za-z0-9_./-]+\.(?:cairo|move|hpp|cpp|tsx|jsx|sol|rs|go|py|cc|ts|js|vy|c|h)",
                        location,
                        re.IGNORECASE,
                    )
                }
                verify_files_seen = {
                    Path(m.group(0).split(":", 1)[0].replace("\\", "/")).name.lower()
                    for m in re.finditer(
                        r"[A-Za-z0-9_./-]+\.(?:cairo|move|hpp|cpp|tsx|jsx|sol|rs|go|py|cc|ts|js|vy|c|h)",
                        verify_location,
                        re.IGNORECASE,
                    )
                }
                if verify_files_seen and loc_files and not (verify_files_seen & loc_files):
                    location = verify_location
                elif (
                    verify_files_seen
                    and (verify_files_seen & loc_files)
                    and re.search(r":L?\d", verify_location)
                    and not re.search(r":L?\d", location)
                ):
                    location = verify_location
        if not location and verify_location:
            location = verify_location
        verify_files = []
        for fid in verify_ids:
            vf = _verify_file_for_id(scratchpad, fid)
            verify_files.append(vf.name if vf.exists() else f"verify_{fid}.md")
        verify_statuses = []
        report_blocked = not bool(verify_files)
        verdict = ""
        for fid in verify_ids:
            vf = _verify_file_for_id(scratchpad, fid)
            txt = ""
            complete = _verifier_output_has_completion_authority(
                scratchpad, fid
            )
            if vf.exists() and complete:
                try:
                    txt = _llm_norm(vf.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    txt = ""
            if not verdict and txt:
                verdict = _verifier_status_from_text(txt)
            missing = (
                not complete
                or (not vf.exists())
                or _is_evidence_missing_for_body(txt)
            )
            verify_statuses.append({"file": f"verify_{fid}.md", "exists": vf.exists(), "evidence_missing": bool(missing)})
            if missing:
                report_blocked = True
        runtime_debt = _verification_runtime_debt_binding(
            scratchpad, list(verify_ids)
        )
        runtime_debt_unresolved = bool(runtime_debt)

        manifest_row = {
            "report_id": report_id,
            "finding_id": finding_id,
            "severity": sev_full,
            "title": title,
            "location": location,
            "evidence_tag": evidence_tag,
            "verify_file": verify_files[0] if verify_files else "",
            "verify_files": verify_files,
            "verify_statuses": verify_statuses,
            "description": desc,
            "poc_result": poc_result,
            "recommendation": rec,
            "report_blocked": bool(report_blocked),
            "verification_runtime_debt": runtime_debt,
        }
        grouped[shard].append(manifest_row)
        active_records.append({
            "report_id": report_id,
            "finding_id": primary_fid or finding_id,
            "severity": sev_full,
            "title": title,
            "location": location,
            "evidence": evidence_tag,
            "verdict": (
                "UNRESOLVED"
                if runtime_debt_unresolved
                else verdict or "CONFIRMED"
            ),
            "unresolved": bool(
                runtime_debt_unresolved
                or (verdict or "").upper() in {"UNRESOLVED", "PARTIAL"}
            ),
            "severity_adjustments": [],
            "absorbed_finding_ids": finding_ids if len(finding_ids) > 1 else [],
            "report_blocked": bool(report_blocked),
        })

    # --- Write manifests (same format as L1 _build_body_writer_manifests) ---
    manifests: dict[str, dict] = {}
    for shard, rows in grouped.items():
        if not rows:
            continue
        cap = _BODY_SHARD_CAPS.get(shard, 30)
        if len(rows) <= cap:
            manifests[shard] = {"shard": shard, "findings": rows}
        else:
            n = len(rows)
            n_shards = (n + cap - 1) // cap
            chunk = (n + n_shards - 1) // n_shards
            for i in range(n_shards):
                suffix = chr(ord("a") + i)
                slice_rows = rows[i * chunk : (i + 1) * chunk]
                if not slice_rows:
                    continue
                name = f"{shard}_{suffix}"
                manifests[name] = {"shard": name, "findings": slice_rows}

    if not manifests:
        manifests["report_empty"] = {
            "schema_version": "plamen.empty_report_denominator.v1",
            "shard": "report_empty",
            "denominator_state": "EMPTY",
            "findings": [],
        }

    if not persist:
        return manifests

    out_dir = scratchpad / "body_manifests"
    try:
        out_dir.mkdir(exist_ok=True)
        for old in out_dir.glob("report_*.json"):
            if old.stem not in manifests:
                try:
                    old.unlink()
                except Exception:
                    pass
                for stale in (
                    scratchpad / f"{old.stem}.md",
                    scratchpad / f"{old.stem}_assignments.md",
                ):
                    try:
                        stale.unlink(missing_ok=True)
                    except Exception:
                        pass
        for name, m in manifests.items():
            (out_dir / f"{name}.json").write_text(
                json.dumps(m, indent=2),
                encoding="utf-8",
            )
        excluded = _parse_report_index_excluded_records(scratchpad)
        (scratchpad / "report_records.json").write_text(
            json.dumps(
                {
                    "schema_version": "plamen.report_records.v1",
                    "source": "report_index.md",
                    "active": active_records,
                    "excluded": excluded,
                    "consolidation_map": [],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception as exc:
        log = logging.getLogger("plamen.mechanical")
        log.warning("_build_sc_body_writer_manifests: manifest/records write failed: %s", exc)
    if (
        materialize_evidence
        and manifests
        and (scratchpad / "report_records.json").exists()
    ):
        _materialize_report_evidence_or_debt(scratchpad)
    return manifests


def _write_mechanical_report_tier(scratchpad: Path, phase_name: str) -> int:
    """Write tier markdown from verified records; no LLM report writer needed.

    Phase A D1/D2 fix: emit per-severity `## {Severity} Findings` H2 headers
    inside the tier file so `_extract_h2_section` in the assembler routes
    each finding to the correct section. Pre-fix, the tier file had only an
    H1 title and the assembler couldn't split — every C/H finding ended up
    pulled under the Medium section.
    """
    assignments, _source = get_tier_assignments(scratchpad)
    records_by_report_id: dict[str, dict] = {}
    records_path = scratchpad / "report_records.json"
    if records_path.exists():
        try:
            records = json.loads(records_path.read_text(encoding="utf-8"))
            for row in records.get("active", []):
                rid = row.get("report_id")
                if rid:
                    records_by_report_id[rid] = row
        except Exception:
            records_by_report_id = {}
    if records_by_report_id:
        assignments = [
            {
                "report_id": rid,
                "finding_id": row.get("finding_id", ""),
                "severity": severity_letter_from_name(row.get("severity", "")),
                "absorbed_finding_ids": row.get("absorbed_finding_ids") or [],
                "title": row.get("title", ""),
                "evidence": row.get("evidence", ""),
                # A verifier-authored negative is still an unresolved proposal
                # until independent typed closure exists. Preserve the record
                # state through tier dispatch instead of recomputing it only
                # from prose and accidentally presenting it as ordinary body.
                "unresolved": bool(row.get("unresolved")),
                "verdict": row.get("verdict", ""),
                "severity_adjustments": row.get("severity_adjustments") or [],
            }
            for rid, row in sorted(
                records_by_report_id.items(),
                key=lambda item: (
                    {"C": 0, "H": 1, "M": 2, "L": 3, "I": 4}.get(item[0][0], 99),
                    item[0],
                ),
            )
        ]
    if not assignments:
        return 0
    queue_rows = {
        (r.get("finding id") or "").strip(): r
        for r in _report_candidate_universe_rows(scratchpad)
        if (r.get("finding id") or "").strip()
    }
    if phase_name == "report_critical_high":
        selected = [a for a in assignments if a["severity"] in ("C", "H")]
        filename = "report_critical_high.md"
        title = "# Critical and High Findings"
        per_sev_headers = (("C", "Critical Findings"), ("H", "High Findings"))
    elif (_shard_m := re.match(r"^report_(critical_high|medium|low_info)_[a-z]$", phase_name)):
        _shard_tier = _shard_m.group(1)
        shards = ensure_report_tier_shards(scratchpad, _shard_tier)
        selected = shards.get(phase_name, [])
        filename = f"{phase_name}.md"
        _titles_map = {
            "critical_high": ("# Critical and High Findings", (("C", "Critical Findings"), ("H", "High Findings"))),
            "medium": ("# Medium Findings", (("M", "Medium Findings"),)),
            "low_info": ("# Low and Informational Findings", (("L", "Low Findings"), ("I", "Informational Findings"))),
        }
        title, per_sev_headers = _titles_map[_shard_tier]
    elif phase_name == "report_medium":  # SC unsharded medium tier
        selected = [a for a in assignments if a["severity"] == "M"]
        filename = "report_medium.md"
        title = "# Medium Findings"
        per_sev_headers = (("M", "Medium Findings"),)
    elif phase_name == "report_low_info":
        selected = [a for a in assignments if a["severity"] in ("L", "I")]
        filename = "report_low_info.md"
        title = "# Low and Informational Findings"
        per_sev_headers = (("L", "Low Findings"), ("I", "Informational Findings"))
    else:
        return 0

    parts = [title, ""]
    unresolved_ids = _collect_judge_unresolved_ids(scratchpad)

    for sev_letter, header_text in per_sev_headers:
        bucket = [a for a in selected if a["severity"] == sev_letter]
        if not bucket:
            continue
        parts.extend([f"## {header_text}", ""])
        for a in bucket:
            fid = a.get("finding_id", "")
            source_ids = a.get("absorbed_finding_ids") or []
            if isinstance(source_ids, str):
                source_ids = [s.strip() for s in source_ids.split(",") if s.strip()]
            if not source_ids:
                source_ids = [fid] if fid else []
            primary_source = source_ids[0] if source_ids else fid
            target_evidence = str(a.get("evidence") or "").strip()
            if len(source_ids) > 1 and target_evidence:
                for source_id in source_ids:
                    try:
                        src_txt = _llm_norm(
                            _verify_file_for_id(scratchpad, source_id).read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                    except Exception:
                        src_txt = ""
                    src_evidence = (
                        _field_from_markdown(src_txt, ("Evidence Tag", "Evidence Tags", "Evidence"))
                        or _field_from_markdown(src_txt, ("Preferred Tag", "Preferred Evidence"))
                        or ""
                    ).strip()
                    if src_evidence == target_evidence:
                        primary_source = source_id
                        break
            # D7 fix: also flag UNRESOLVED when the verifier verdict itself
            # is UNRESOLVED (not only when skeptic-judge ruled UNRESOLVED).
            # Body tag is a triage signal regardless of UNRESOLVED origin.
            verdicts: list[str] = []
            for source_id in source_ids:
                verify_path = _verify_file_for_id(scratchpad, source_id)
                try:
                    vtxt = _llm_norm(verify_path.read_text(encoding="utf-8", errors="replace"))
                except Exception:
                    vtxt = ""
                verdicts.append(_verifier_status_from_text(vtxt))
            is_unresolved = bool(a.get("unresolved")) or any(
                source_id in unresolved_ids for source_id in source_ids
            ) or any(v == "UNRESOLVED" for v in verdicts)
            section = _synth_report_section_from_verify(
                scratchpad,
                a.get("report_id", ""),
                primary_source,
                queue_rows.get(fid, {"finding id": fid, "severity": sev_letter}),
                is_unresolved,
            )
            if len(source_ids) > 1:
                evidence_lines = ["", "**Consolidated Evidence Sources**:"]
                for source_id in source_ids:
                    evidence_lines.append(f"- verify_{source_id}.md")
                section = section.rstrip() + "\n" + "\n".join(evidence_lines) + "\n"
            parts.append(section)
            parts.append("")

    if not selected:
        write_report_tier_placeholder(scratchpad, filename, "0 findings assigned in report_index.md")
    else:
        (scratchpad / filename).write_text("\n".join(parts).strip() + "\n", encoding="utf-8")
    return len(selected)


def estimate_rate_limit_wait_seconds(stdio_log: Path) -> Optional[int]:
    """Best-effort parse of a provider-advised retry/reset window."""
    if not stdio_log.exists():
        return None
    try:
        with stdio_log.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 65536))
            tail = f.read().decode("utf-8", errors="replace")
    except Exception:
        return None

    # Bind every parsed delay to provider control-plane evidence.  The stdio
    # stream also contains arbitrary assistant/project text.  Short relative
    # delays may use a conventional raw HTTP/API error line, but absolute reset
    # times (which can pause for days) require a fully framed provider event:
    # Claude's direct 429/rate_limit metadata, or Codex's matched stream-json
    # error/turn.failed sequence.  Never combine fields across records.
    parsed_records: list[tuple[str, dict[str, Any]]] = []
    raw_records: list[str] = []
    for raw_line in tail.splitlines():
        try:
            envelope = json.loads(raw_line)
        except Exception:
            envelope = None
        if isinstance(envelope, dict):
            parsed_records.append((raw_line, envelope))
            continue
        raw_records.append(raw_line)

    def _message_is_rate_limit(message: str) -> bool:
        return bool(re.search(
            r"(?i)(?:hit|reached|exceeded).{0,24}"
            r"(?:usage|rate|weekly|daily).{0,12}limit|"
            r"(?:usage|rate|weekly|daily).{0,12}limit.{0,24}"
            r"(?:hit|reached|exceeded)|purchase more credits",
            message,
        ))

    # Authenticate Codex errors with an ordered, single-turn state machine.
    # Global presence checks are insufficient because stale/replayed events can
    # be reordered or crossed between turns in a concatenated log.
    codex_framed_error_indices: set[int] = set()
    active_thread: Optional[str] = None
    turn_active = False
    pending_error: Optional[tuple[int, str]] = None
    for record_index, (_, envelope) in enumerate(parsed_records):
        record_type = str(envelope.get("type", "")).strip().lower()
        if record_type == "thread.started":
            # Every observed thread boundary invalidates prior turn state,
            # including malformed boundaries.  Only a nonempty string ID may
            # establish the replacement thread.
            active_thread = None
            turn_active = False
            pending_error = None
            thread_id = envelope.get("thread_id")
            if isinstance(thread_id, str) and thread_id.strip():
                active_thread = thread_id
        elif record_type == "turn.started":
            if active_thread is not None:
                turn_active = True
                pending_error = None
        elif record_type == "error" and active_thread is not None and turn_active:
            message = envelope.get("message")
            if isinstance(message, str) and _message_is_rate_limit(message):
                pending_error = (record_index, message)
        elif record_type == "turn.failed":
            failure = envelope.get("error")
            failed_message = (
                failure.get("message") if isinstance(failure, dict) else None
            )
            if (
                turn_active
                and pending_error is not None
                and isinstance(failed_message, str)
                and failed_message == pending_error[1]
            ):
                codex_framed_error_indices.add(pending_error[0])
            turn_active = False
            pending_error = None
        elif record_type in {"turn.completed", "thread.ended", "thread.completed"}:
            turn_active = False
            pending_error = None
            if record_type.startswith("thread."):
                active_thread = None

    relative_lines: list[tuple[str, bool]] = []
    absolute_lines: list[str] = []
    absolute_envelopes: list[dict[str, Any]] = []
    for record_index, (raw_line, envelope) in enumerate(parsed_records):
        api_status = envelope.get(
            "apiErrorStatus", envelope.get("api_error_status")
        )
        error_kind = str(envelope.get("error", "")).strip().lower()
        record_type = str(envelope.get("type", "")).strip().lower()
        message = envelope.get("message")
        message_text = message if isinstance(message, str) else ""
        quota = envelope.get("quotaLimits")
        if not isinstance(quota, dict):
            quota = envelope.get("quota_limits")
        claude_framed = (
            api_status in {429, 529, "429", "529"}
            and error_kind in {"rate_limit", "rate_limited", "usage_limit"}
            and isinstance(quota, dict)
            and bool(envelope.get("requestId") or envelope.get("request_id"))
            and bool(envelope.get("session_id") or envelope.get("sessionId"))
        )
        codex_framed = (
            record_type == "error"
            and record_index in codex_framed_error_indices
        )
        if claude_framed or codex_framed:
            relative_lines.append((raw_line, True))
            absolute_lines.append(raw_line)
            absolute_envelopes.append(envelope)

    for raw_line in raw_records:
        if re.search(
            r"(?i)^\s*(?:HTTP(?:\s+status)?|API(?:\s+error)?|Error)"
            r"\s*[:= ]\s*"
            r"(?:429|529)\b",
            raw_line,
        ):
            relative_lines.append((raw_line, False))

    if not relative_lines and not absolute_lines:
        return None

    def _local_wall_clock_delta(
        month: int,
        day: int,
        hour: int,
        minute: int,
        *,
        year: Optional[int] = None,
    ) -> Optional[int]:
        """Resolve a future local wall time through the OS timezone rules."""
        now_epoch = time.time()
        current_year = time.localtime(now_epoch).tm_year
        years = [year] if year is not None else range(current_year, current_year + 9)
        for candidate_year in years:
            try:
                target_epoch = time.mktime((
                    int(candidate_year), month, day, hour, minute, 0,
                    -1, -1, -1,
                ))
                # mktime normalizes invalid dates (for example Feb 29 in a
                # non-leap year).  Accept only an exact local-time round trip.
                resolved = time.localtime(target_epoch)
                if (
                    resolved.tm_year, resolved.tm_mon, resolved.tm_mday,
                    resolved.tm_hour, resolved.tm_min,
                ) != (int(candidate_year), month, day, hour, minute):
                    continue
                delta = int(target_epoch - now_epoch)
                if delta > 0:
                    return delta
            except (OverflowError, OSError, ValueError):
                continue
        return None

    patterns = [
        (re.compile(r"(?i)retry[-_ ]after[=:\s]+(\d+)\s*(seconds?|secs?|s)\b"), 1),
        (re.compile(r"(?i)retry[-_ ]after[=:\s]+(\d+)\s*(minutes?|mins?|m)\b"), 60),
        (re.compile(r"(?i)try again in\s+(\d+)\s*(seconds?|secs?|s)\b"), 1),
        (re.compile(r"(?i)try again in\s+(\d+)\s*(minutes?|mins?|m)\b"), 60),
        (re.compile(r"(?i)wait\s+(\d+)\s*(seconds?|secs?|s)\b"), 1),
        (re.compile(r"(?i)wait\s+(\d+)\s*(minutes?|mins?|m)\b"), 60),
    ]
    _RAW_RELATIVE_WAIT_CEILING_S = 900
    for line, provider_framed in relative_lines:
        for rx, mult in patterns:
            m = rx.search(line)
            if m:
                try:
                    candidate = int(m.group(1)) * mult
                    if (
                        not provider_framed
                        and candidate > _RAW_RELATIVE_WAIT_CEILING_S
                    ):
                        continue
                    return candidate
                except Exception:
                    pass

    # Claude Code emits quota exhaustion as JSONL with an authoritative Unix
    # reset timestamp, for example:
    #   {"error":"rate_limit","apiErrorStatus":429,
    #    "quotaLimits":{"status":"rejected","resetsAt":1788314400}}
    # Prefer that machine-readable timestamp over natural-language parsing.  A
    # bare ``resetsAt`` token is not enough: model output and project files can
    # contain arbitrary JSON, so require rate-limit evidence in the same
    # envelope before trusting it as provider control-plane data.
    for envelope in reversed(absolute_envelopes):
        quota = envelope.get("quotaLimits")
        if not isinstance(quota, dict):
            quota = envelope.get("quota_limits")
        if not isinstance(quota, dict):
            continue
        reset_raw = quota.get("resetsAt", quota.get("resets_at"))
        try:
            reset_epoch = float(reset_raw)
            # Be tolerant of providers serializing Unix milliseconds.
            if reset_epoch > 10_000_000_000:
                reset_epoch /= 1000.0
            now_utc = datetime.now(timezone.utc)
            target_utc = datetime.fromtimestamp(reset_epoch, timezone.utc)
            delta = int((target_utc - now_utc).total_seconds())
            if delta > 0:
                return delta
        except Exception:
            continue

    # Absolute reset timestamp WITH a date. Codex/ChatGPT daily usage caps phrase
    # the reset as an absolute wall-clock time hours out, e.g.
    #   "... or try again at Jul 11th, 2026 2:46 AM."
    # This is neither a "retry-after N" delta nor the "resets HH:MM am/pm" form,
    # so without this branch the estimator returned None and the caller fell back
    # to a pointless 5-minute spin-wait before a retry that re-hits the same cap.
    _MONTHS = {
        "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
        "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
    }
    date_with_year_rx = re.compile(
        r"(?i)(?:try again|reset[s]?|available again)\s+(?:at|on)\s+"
        r"([a-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})[,\s]+"
        r"(\d{1,2}):(\d{2})\s*(am|pm)\b"
    )
    m = next(
        (match for line in absolute_lines if (match := date_with_year_rx.search(line))),
        None,
    )
    if m:
        try:
            mon = _MONTHS.get(m.group(1)[:3].lower())
            if mon:
                day = int(m.group(2))
                year = int(m.group(3))
                hour = int(m.group(4))
                minute = int(m.group(5))
                if hour == 12:
                    hour = 0
                if m.group(6).lower() == "pm":
                    hour += 12
                delta = _local_wall_clock_delta(
                    mon, day, hour, minute, year=year
                )
                if delta is not None:
                    return delta
        except Exception:
            pass

    # Claude's human-readable weekly-cap fallback omits the year and often the
    # minutes: "resets Sep 2, 5am".  Resolve it to the next occurrence of that
    # local wall-clock date, rolling into the next year only when needed.
    yearless_date_rx = re.compile(
        r"(?i)(?:try again|reset[s]?|available again)(?:\s+(?:at|on))?\s+"
        r"([a-z]{3,9})\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+"
        r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b"
    )
    m = next(
        (match for line in absolute_lines if (match := yearless_date_rx.search(line))),
        None,
    )
    if m:
        try:
            mon = _MONTHS.get(m.group(1)[:3].lower())
            if mon:
                day = int(m.group(2))
                hour = int(m.group(3))
                minute = int(m.group(4) or 0)
                if hour == 12:
                    hour = 0
                if m.group(5).lower() == "pm":
                    hour += 12
                delta = _local_wall_clock_delta(mon, day, hour, minute)
                if delta is not None:
                    return delta
        except Exception:
            pass

    # Absolute reset time WITHOUT a date: "resets 5:46 PM", "resets at 5:46 PM",
    # or the Codex time-only variant "try again at 5:46 PM".
    time_only_rx = re.compile(
        r"(?i)(?:try again\s+at|resets?(?:\s+at)?|available again\s+at)\s+"
        r"(\d{1,2})(?::(\d{2}))?\s*(am|pm)\b"
    )
    m = next(
        (match for line in absolute_lines if (match := time_only_rx.search(line))),
        None,
    )
    if m:
        try:
            hour = int(m.group(1))
            minute = int(m.group(2) or 0)
            ampm = m.group(3).lower()
            if hour == 12:
                hour = 0
            if ampm == "pm":
                hour += 12
            now = time.localtime()
            today_epoch = time.mktime((
                now.tm_year, now.tm_mon, now.tm_mday,
                hour, minute, 0, -1, -1, -1,
            ))
            if today_epoch <= time.time():
                tomorrow = datetime.fromtimestamp(time.time()) + timedelta(days=1)
                return _local_wall_clock_delta(
                    tomorrow.month, tomorrow.day, hour, minute,
                    year=tomorrow.year,
                )
            return int(today_epoch - time.time())
        except Exception:
            return None

    return None


def write_hibernation_marker(scratchpad: Path, phase_name: str,
                             wake_at_utc: datetime, attempt: int) -> None:
    marker = scratchpad / ".hibernating"
    marker.write_text(json.dumps({
        "wake_at_utc": wake_at_utc.astimezone(timezone.utc).isoformat(),
        "last_phase": phase_name,
        "attempt_count": attempt,
    }, indent=2), encoding="utf-8")


def hibernation_disabled() -> bool:
    """Return whether rate-limit auto-sleep is disabled.

    Default is disabled. A pipeline should return control to the operator on
    rate limit instead of planting `.hibernating` and fighting manual resumes.
    Opt in explicitly with `PLAMEN_HIBERNATE=1`.
    """
    if os.environ.get("PLAMEN_NO_HIBERNATE", "").lower() in {
        "1", "true", "yes", "on"
    }:
        return True
    return os.environ.get("PLAMEN_HIBERNATE", "").lower() not in {
        "1", "true", "yes", "on"
    }


def maybe_resume_hibernation(scratchpad: Path) -> Optional[int]:
    """Handle an existing hibernation marker before any phase work starts."""
    if hibernation_disabled():
        marker = scratchpad / ".hibernating"
        if marker.exists():
            marker.unlink(missing_ok=True)
            print("[no-sleep] cleared .hibernating marker", file=sys.stderr)
        return None

    marker = scratchpad / ".hibernating"
    if not marker.exists():
        return None
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        wake_at = datetime.fromisoformat(data["wake_at_utc"])
        if wake_at.tzinfo is None:
            wake_at = wake_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
    except Exception:
        marker.unlink(missing_ok=True)
        return None

    if wake_at > now:
        remaining = int((wake_at - now).total_seconds())
        mins = max(1, remaining // 60)
        print("\n" + "=" * 60, file=sys.stderr)
        print("Pipeline HIBERNATING -- waiting for provider reset window.",
              file=sys.stderr)
        print(f"  Wait ~{mins} minute(s), then re-run the same command.",
              file=sys.stderr)
        print("  To skip the wait:  add --force to the command",
              file=sys.stderr)
        print("  All progress is saved -- resumes from last completed phase.",
              file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        return EXIT_HIBERNATING

    marker.unlink(missing_ok=True)
    return None


def maybe_hibernate_on_rate_limit(scratchpad: Path, phase_name: str,
                                  attempt: int) -> Optional[int]:
    if hibernation_disabled():
        return None

    stdio = scratchpad / f"_stdio_{phase_name}.log"
    wait_s = estimate_rate_limit_wait_seconds(stdio)
    if wait_s is not None and wait_s > 300:
        wake_at = datetime.now(timezone.utc) + timedelta(seconds=wait_s)
        write_hibernation_marker(scratchpad, phase_name, wake_at, attempt)
        print("\n" + "=" * 60, file=sys.stderr)
        print("Pipeline HIBERNATING -- long rate-limit/reset window detected.",
              file=sys.stderr)
        print(f"  Wake-at UTC: {wake_at.isoformat()}", file=sys.stderr)
        print("  To skip the wait:  re-run with --force", file=sys.stderr)
        print("  All progress is saved -- resumes from last completed phase.",
              file=sys.stderr)
        print("=" * 60 + "\n", file=sys.stderr)
        return EXIT_HIBERNATING
    return None


def write_report_tier_placeholder(scratchpad: Path, tier_filename: str,
                                  reason: str) -> None:
    p = scratchpad / tier_filename
    p.write_text(
        f"# Report Tier: N/A\n\n"
        f"No findings were assigned to this tier.\n\n"
        f"- Reason: {reason}\n"
        f"- Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%S')}\n",
        encoding="utf-8",
    )


def _write_location_recovery_skip(scratchpad: Path, reason: str) -> None:
    (scratchpad / "location_recovery.md").write_text(
        "# Location Recovery\n\n"
        f"SKIPPED: {reason}\n",
        encoding="utf-8",
    )


def _location_recovery_needed(scratchpad: Path, project_root: str) -> tuple[bool, str]:
    records = _validate_inventory_evidence(scratchpad, project_root)
    bad = [
        fid for fid, r in records.items()
        if r.get("location_status") not in ("OK", "RECOVERED_BASENAME")
    ]
    if not bad:
        return False, "all inventory locations resolve mechanically"
    return True, f"{len(bad)} unresolved inventory location(s)"


def _apply_location_recovery(scratchpad: Path, project_root: str) -> list[str]:
    """Apply `location_recovery.md` rows with verdict RECOVERED."""
    p = scratchpad / "location_recovery.md"
    inv = scratchpad / "findings_inventory.md"
    if not p.exists() or not inv.exists():
        return []
    try:
        text = _llm_norm(p.read_text(encoding="utf-8", errors="replace"))
        inv_text = _llm_norm(inv.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    headers, rows = _parse_markdown_table(text, ["finding id", "verdict", "new location"])
    if not headers:
        return []
    keys = [_norm_key(h) for h in headers]
    source_index = _project_source_index(project_root)
    applied: list[str] = []
    new_text = inv_text
    for row in rows:
        d = {keys[i]: row[i].strip() for i in range(min(len(keys), len(row)))}
        fid = _normalize_finding_id(d.get("finding id", "")) or d.get("finding id", "")
        verdict = d.get("verdict", "").upper()
        loc = d.get("new location", "")
        if not fid or "RECOVERED" not in verdict or not loc:
            continue
        st, resolved, _reason = _resolve_inventory_location(project_root, source_index, loc)
        if st not in ("OK", "RECOVERED_BASENAME"):
            continue
        new_text = _replace_inventory_location(new_text, fid, resolved or loc)
        applied.append(fid)
    if applied and new_text != inv_text:
        inv.write_text(new_text, encoding="utf-8")
        _validate_inventory_evidence(scratchpad, project_root)
    return applied


def backfill_unrouted_inventory_into_queue(
    scratchpad: Path,
    route: str = "active",
    *,
    authenticated_inventory_text: str | None = None,
) -> list[str]:
    """Route every queue-generation dropout to ACTIVE verification work.

    Deterministic + idempotent. Returns the backfilled finding IDs.  This
    helper is an identity/work repair, never a producer verdict or exclusion
    authority.  In particular a resume-detected identity remains verifier work;
    callers that already completed ordinary shards must use the driver's
    bounded recovery-verification path and targeted descendant invalidation.

    ``route`` remains in the signature only to fail old callers loudly.  The
    former ``route="excluded"`` behavior converted a persisted candidate into
    a lexical DEFERRED acknowledgement without independent verification and is
    therefore forbidden.

    The persistence is via the CANONICAL writer `_write_queue_subset_manifest`,
    which rewrites BOTH `verification_queue.md` (canonical 10-column manifest)
    AND its JSON sidecar `verification_queue.json`. We never raw-append markdown
    text and never hand-roll a partial-column row: the previous implementation
    appended 6-column rows AFTER the manifest footer line, which the markdown
    table parser stops at, and left the JSON sidecar stale -> parity never
    closed and resume rewound ~15 phases on every attempt.

    Each backfilled row reuses the EXACT field extraction from
    `_queue_rows_from_inventory_with_exclusions` (the queue builder), so the
    row dict carries the same queue/severity/title/bug-class/preferred-tag/
    location/primary-artifact/poc-class fields any normal active row has.
    """
    from plamen_validators import _compute_unrouted_inventory_ids
    from plamen_parsers import (
        _read_queue_json_sidecar,
        _write_queue_excluded_manifest,
    )

    if route != "active":
        raise ValueError(
            "queue backfill may only create active verification work; "
            "producer/excluded disposition is forbidden"
        )

    # Migrate the exact legacy P0-N anti-pattern.  Older runs may already have
    # converted a resume dropout into an excluded DEFERRED row, so the parity
    # set no longer calls it "unrouted".  That lexical acknowledgement has no
    # disposition authority: route it active and remove only this exact legacy
    # reason.  Legitimate mode/scope/evidence exclusions remain untouched.
    excluded_path = scratchpad / "verification_queue_evidence_excluded.md"
    existing_excluded = _read_queue_json_sidecar(excluded_path)
    legacy_prefix = "deferred on resume: queue-generation dropout"
    legacy_deferred_ids: set[str] = set()
    retained_excluded: list[dict[str, str]] = []
    for row in existing_excluded:
        reason = str(row.get("exclusion reason") or "").strip().lower()
        fid = _normalize_finding_id(row.get("finding id", "")) or str(
            row.get("finding id", "") or ""
        ).strip()
        if fid and reason.startswith(legacy_prefix):
            legacy_deferred_ids.add(fid)
        else:
            retained_excluded.append(row)

    unrouted = sorted(
        set(
            _compute_unrouted_inventory_ids(
                scratchpad,
                authenticated_inventory_text=authenticated_inventory_text,
            )
        )
        | legacy_deferred_ids
    )
    if not unrouted:
        return []

    queue_path = scratchpad / "verification_queue.md"
    if not queue_path.exists():
        # A missing queue is a different failure owned by the existing gate.
        return []

    # Existing ACTIVE rows (authoritative via JSON sidecar when present, with
    # markdown fallback handled inside parse_verification_queue_rows). These are
    # preserved verbatim; we only ADD the unrouted IDs.
    existing_rows = parse_verification_queue_rows(scratchpad)
    present_ids: set[str] = set()
    for row in existing_rows:
        fid = _normalize_finding_id(row.get("finding id", "")) or (
            row.get("finding id", "") or ""
        ).strip()
        if fid:
            present_ids.add(fid)

    # Build canonical row dicts for every inventory block, using the SAME
    # builder the queue phase uses. Index the builder's ACTIVE rows by
    # normalized finding ID so each backfilled row is byte-for-byte the kind of
    # row the builder would have emitted had it not been dropped. Fall back to
    # excluded rows (a dropout can also originate from an inventory block the
    # builder placed nowhere) and finally to a minimal canonical dict.
    builder_active, builder_excluded = _queue_rows_from_inventory_with_exclusions(
        scratchpad
    )
    builder_by_id: dict[str, dict[str, str]] = {}
    for src in (builder_excluded, builder_active):
        # active last so it wins on collision (active is the preferred route)
        for row in src:
            bid = _normalize_finding_id(row.get("finding id", "")) or (
                row.get("finding id", "") or ""
            ).strip()
            if bid:
                builder_by_id[bid] = row

    appended: list[str] = []

    new_rows: list[dict[str, str]] = []
    for fid in unrouted:
        if fid in present_ids:
            # Idempotency: never duplicate an ID already in the active queue.
            # If it is simultaneously carrying the exact legacy resume-
            # deferred row, still return it as recovered work after removing
            # that stale exclusion. This closes the crash window between the
            # active manifest write and exclusion cleanup.
            if fid in legacy_deferred_ids:
                appended.append(fid)
            continue
        src = builder_by_id.get(fid)
        if src is not None:
            row = dict(src)
            # Drop any exclusion reason so this routes ACTIVE, and annotate the
            # backfill provenance via the bug class without losing the real one.
            row.pop("exclusion reason", None)
            if not row.get("bug class"):
                row["bug class"] = "Unrouted by queue generation (mechanical backfill)"
        else:
            row = {
                "finding id": fid,
                "severity": "Medium",
                "title": fid,
                "bug class": "Unrouted by queue generation (mechanical backfill)",
                "preferred tag": "CODE-TRACE",
                "location": "",
                "primary artifact": "findings_inventory.md",
                "poc class": "structural",
            }
        new_rows.append(row)
        present_ids.add(fid)
        appended.append(fid)

    if not new_rows:
        if legacy_deferred_ids and len(retained_excluded) != len(existing_excluded):
            _write_queue_excluded_manifest(excluded_path, retained_excluded)
        return appended

    # Persist via the canonical writer: it writes the 10-column manifest AND
    # the JSON sidecar, so parse_verification_queue_rows (and therefore
    # _compute_unrouted_inventory_ids) immediately sees the rows. Assign a
    # monotonic Queue # across the combined set so numbering stays well-formed.
    combined = existing_rows + new_rows
    for idx, row in enumerate(combined, start=1):
        row["queue #"] = str(idx)
    _write_queue_subset_manifest(queue_path, combined)
    if legacy_deferred_ids and len(retained_excluded) != len(existing_excluded):
        _write_queue_excluded_manifest(excluded_path, retained_excluded)
    return appended
