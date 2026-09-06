"""Closed work-unit capability and producer-authority registry.

Markdown remains methodology/presentation.  This registry is the typed control
plane for who may research externally, which producer outcomes are legal, how
artifacts are interpreted, and which independent lifecycle owns a negative.
"""
from __future__ import annotations

from dataclasses import dataclass
import fnmatch
from typing import Iterable


GENERATOR_OUTCOMES = frozenset(
    {
        "CANDIDATE",
        "REFUTATION_PROPOSAL",
        "NOT_APPLICABLE_PROPOSAL",
        "UNRESOLVED",
    }
)
CAMPAIGN_OUTCOMES = frozenset(
    {
        "VIOLATION_CANDIDATE",
        "NO_VIOLATIONS",
        "TOOL_UNAVAILABLE",
        "COMPILATION_FAILED",
        "TIMEOUT",
        "UNRESOLVED",
    }
)
ALL_MODES = frozenset({"light", "core", "thorough"})


class CapabilityResolutionError(ValueError):
    """No exact unambiguous work-unit capability exists."""


@dataclass(frozen=True)
class WorkUnitCapability:
    key: str
    pipelines: frozenset[str]
    modes: frozenset[str]
    owner_phase: str
    work_categories: tuple[str, ...]
    artifact_patterns: tuple[str, ...]
    actor: str
    authority_class: str
    entity_kind: str
    parser_profile: str
    allowed_outcomes: frozenset[str]
    harvest_policy: str
    methodology_binding: str
    lifecycle_owner: str
    discriminator_barrier: str
    terminal_negative_authority: bool = False
    external_research: bool = False
    shell_network: bool = False
    section_selector: str = ""


def _generator(
    key: str,
    *,
    pipelines: Iterable[str],
    phase: str,
    categories: tuple[str, ...],
    patterns: tuple[str, ...],
    entity: str = "FINDING",
    parser: str = "STRUCTURED_FINDING",
    methodology: str = "DISPATCH_VECTOR",
    lifecycle: str = "candidate_negative_skeptic",
    barrier: str = "discovery_negative",
    modes: frozenset[str] = ALL_MODES,
    section: str = "",
) -> WorkUnitCapability:
    return WorkUnitCapability(
        key=key,
        pipelines=frozenset(pipelines),
        modes=modes,
        owner_phase=phase,
        work_categories=categories,
        artifact_patterns=patterns,
        actor="MODEL",
        authority_class="GENERATOR",
        entity_kind=entity,
        parser_profile=parser,
        allowed_outcomes=GENERATOR_OUTCOMES,
        harvest_policy="STRUCTURED_ENTITY_PROPOSALS",
        methodology_binding=methodology,
        lifecycle_owner=lifecycle,
        discriminator_barrier=barrier,
        section_selector=section,
    )


_CAPABILITIES = (
    _generator(
        "sc_breadth", pipelines=("sc",), phase="breadth",
        categories=("standard", "*"), patterns=("analysis_*.md",),
        methodology="BREADTH_DISPATCH_VECTOR",
    ),
    _generator(
        "l1_breadth", pipelines=("l1",), phase="breadth",
        categories=("standard", "*"), patterns=("analysis_*.md",),
        methodology="L1_BREADTH_DISPATCH_VECTOR",
    ),
    _generator(
        "sc_rescan", pipelines=("sc",), phase="rescan",
        categories=("rescan", "standard", "*"),
        patterns=("analysis_rescan_*.md",),
        methodology="RESCAN_DISPATCH_VECTOR",
        modes=frozenset({"thorough"}),
    ),
    _generator(
        "sc_per_contract", pipelines=("sc",), phase="rescan",
        categories=("per_contract",), patterns=("analysis_percontract_*.md",),
        entity="COVERAGE", parser="PER_CONTRACT_ENTITY",
        methodology="PER_CONTRACT_DISPATCH_VECTOR",
        modes=frozenset({"thorough"}),
    ),
    _generator(
        "semantic_invariants_p1", pipelines=("sc", "l1"), phase="invariants",
        categories=("*",), patterns=("semantic_invariants.md",),
        entity="GAP", parser="INVARIANT_PASS1",
        methodology="INVARIANT_PASS1_SECTION",
        lifecycle="semantic_invariant_authority",
        section="PASS1_ONLY",
        modes=frozenset({"core", "thorough"}),
    ),
    _generator(
        "semantic_invariants_p2", pipelines=("sc", "l1"), phase="invariants_p2",
        categories=("*",), patterns=("semantic_invariants.md",),
        entity="GAP", parser="INVARIANT_PASS2",
        methodology="INVARIANT_PASS2_SECTION",
        section="PASS2_ONLY",
        modes=frozenset({"thorough"}),
    ),
    _generator(
        "sc_depth_standard", pipelines=("sc",), phase="depth",
        categories=("standard", "da"),
        patterns=("depth_*_findings.md", "depth_da_iter2_findings.md"),
        methodology="DEPTH_DISPATCH_VECTOR",
    ),
    _generator(
        "l1_depth_standard", pipelines=("l1",), phase="depth",
        categories=("standard", "da"),
        patterns=("depth_*_findings.md", "depth_da_iter2_findings.md"),
        methodology="L1_DEPTH_DISPATCH_VECTOR",
    ),
    _generator(
        "depth_scanner", pipelines=("sc", "l1"), phase="depth",
        categories=("scanner",),
        patterns=("blind_spot_*_findings.md", "validation_sweep_findings.md", "scanner_*_findings.md"),
        methodology="SCANNER_DISPATCH_VECTOR",
    ),
    _generator(
        "sibling_propagation", pipelines=("sc", "l1"), phase="depth",
        categories=("sibling",), patterns=("sibling_propagation_findings.md",),
        entity="COVERAGE", parser="SIBLING_DENOMINATOR",
        methodology="SIBLING_DISPATCH_VECTOR",
    ),
    _generator(
        "depth_niche", pipelines=("sc", "l1"), phase="depth",
        categories=("niche",), patterns=("niche_*_findings.md",),
        methodology="NICHE_SKILL_VECTOR",
    ),
    _generator(
        "depth_sidecar", pipelines=("sc", "l1"), phase="depth",
        categories=("sidecar",),
        patterns=("design_stress_findings.md", "perturbation_findings.md", "*_sidecar_findings.md"),
        methodology="SIDECAR_DISPATCH_VECTOR",
    ),
    _generator(
        "attention_repair", pipelines=("sc", "l1"), phase="attention_repair",
        categories=("*",),
        patterns=("attention_repair_summary.md", "attention_repair_findings.md"),
        entity="COVERAGE", parser="ATTENTION_WORKLIST",
        methodology="ATTENTION_REPAIR_SECTION",
    ),
    _generator(
        "axis_coverage", pipelines=("sc",), phase="axis_coverage",
        categories=("*",), patterns=("axis_coverage_findings.md",),
        entity="CELL", parser="AXIS_CELL",
        methodology="AXIS_COVERAGE_SECTION",
        modes=frozenset({"thorough"}),
    ),
    _generator(
        "l1_graph_sweep", pipelines=("l1",), phase="graph_sweeps",
        categories=("*",),
        patterns=(
            "graph_sweep*.md", "coverage_fill_*.md", "panic_audit_*.md",
            "panic_audit_summary.md", "symmetric_pair_findings.md",
            "field_validation_matrix.md", "primitive_correctness_findings.md",
            "network_amplification_findings.md", "lifecycle_replay_findings.md",
        ),
        entity="GRAPH_ROW", parser="L1_GRAPH_ROW",
        methodology="L1_GRAPH_SWEEP_SECTION",
        modes=frozenset({"thorough"}),
    ),
    _generator(
        "chain_agent1", pipelines=("sc",), phase="chain",
        categories=("*",),
        patterns=("hypotheses.md", "finding_mapping.md", "enabler_results.md"),
        entity="PAIR", parser="CHAIN_REACHABILITY",
        methodology="CHAIN_AGENT1_SECTION", barrier="post_chain_negative",
    ),
    _generator(
        "chain_agent2", pipelines=("sc",), phase="chain_agent2",
        categories=("*",),
        patterns=("chain_hypotheses.md", "composition_coverage.md", "synthesis_full.md"),
        entity="PAIR", parser="CHAIN_PAIR",
        methodology="CHAIN_AGENT2_SECTION", barrier="post_chain_negative",
    ),
    _generator(
        "chain_iter2", pipelines=("sc",), phase="chain_iter2",
        categories=("*",), patterns=("chain_iteration2.md",),
        entity="PAIR", parser="CHAIN_PAIR",
        methodology="CHAIN_ITER2_SECTION", barrier="post_chain_negative",
        modes=frozenset({"thorough"}),
    ),
    WorkUnitCapability(
        key="sc_fuzz_campaign", pipelines=frozenset({"sc"}),
        modes=frozenset({"thorough"}), owner_phase="depth",
        work_categories=("fuzz",),
        artifact_patterns=("invariant_fuzz_results.md", "medusa_fuzz_findings.md"),
        actor="MODEL", authority_class="CAMPAIGN", entity_kind="CAMPAIGN",
        parser_profile="FUZZ_CAMPAIGN", allowed_outcomes=CAMPAIGN_OUTCOMES,
        harvest_policy="CAMPAIGN_EVIDENCE_ONLY",
        methodology_binding="FUZZ_DISPATCH_VECTOR",
        lifecycle_owner="fuzz_workspace_authority", discriminator_barrier="none",
    ),
    WorkUnitCapability(
        key="application_skeptic_discriminator", pipelines=frozenset({"sc", "l1"}),
        modes=ALL_MODES, owner_phase="application_skeptic",
        work_categories=("*",), artifact_patterns=("*_skeptic_assessments_*.json",),
        actor="MODEL", authority_class="DISCRIMINATOR", entity_kind="DECISION",
        parser_profile="TYPED_JSON", allowed_outcomes=frozenset(
            {"NEGATIVE_AGREEMENT", "REGISTRY_CANDIDATE_PROPOSED", "UNRESOLVED_DEBT"}
        ), harvest_policy="TYPED_RECEIPT_ONLY",
        methodology_binding="APPLICATION_SKEPTIC_PACKET",
        lifecycle_owner="application_skeptic", discriminator_barrier="self",
        terminal_negative_authority=True,
    ),
    WorkUnitCapability(
        key="recon_external_research", pipelines=frozenset({"sc", "l1"}),
        modes=ALL_MODES, owner_phase="recon",
        work_categories=("external_dependency_research",), artifact_patterns=("external_dependency_research.md",),
        actor="MODEL", authority_class="RESEARCH", entity_kind="EVIDENCE",
        parser_profile="RESEARCH_LEDGER", allowed_outcomes=frozenset({"EVIDENCE", "UNAVAILABLE"}),
        harvest_policy="EVIDENCE_ONLY", methodology_binding="RECON_RESEARCH_PACKET",
        lifecycle_owner="research_authority", discriminator_barrier="none",
        external_research=True,
    ),
    WorkUnitCapability(
        key="precedent_research", pipelines=frozenset({"sc", "l1"}),
        modes=frozenset({"thorough"}), owner_phase="rag_sweep",
        work_categories=("*",), artifact_patterns=("precedent_*.json", "rag_validation.md"),
        actor="MODEL", authority_class="RESEARCH", entity_kind="EVIDENCE",
        parser_profile="PRECEDENT", allowed_outcomes=frozenset({"EVIDENCE", "UNAVAILABLE"}),
        harvest_policy="EVIDENCE_ONLY", methodology_binding="PRECEDENT_PACKET",
        lifecycle_owner="precedent_evidence_authority", discriminator_barrier="none",
        external_research=True,
    ),
)


def all_capabilities() -> tuple[WorkUnitCapability, ...]:
    return tuple(sorted(_CAPABILITIES, key=lambda row: row.key))


def capability_by_key(key: str) -> WorkUnitCapability:
    matches = [row for row in _CAPABILITIES if row.key == str(key).strip()]
    if len(matches) != 1:
        raise CapabilityResolutionError(f"unknown/ambiguous capability {key!r}")
    return matches[0]


def _category_matches(capability: WorkUnitCapability, category: str) -> bool:
    category_n = str(category or "*").strip().casefold() or "*"
    return category_n in capability.work_categories or "*" in capability.work_categories


def resolve_capability(
    *, pipeline: str, mode: str, phase: str, category: str = "*"
) -> WorkUnitCapability:
    pipeline_n = str(pipeline).strip().casefold()
    mode_n = str(mode).strip().casefold()
    phase_n = str(phase).strip().casefold()
    matches = [
        row for row in _CAPABILITIES
        if pipeline_n in row.pipelines
        and mode_n in row.modes
        and row.owner_phase == phase_n
        and _category_matches(row, category)
    ]
    exact = [row for row in matches if str(category).casefold() in row.work_categories]
    if len(exact) == 1:
        return exact[0]
    if len(matches) != 1:
        raise CapabilityResolutionError(
            f"capability resolution is not exact for {pipeline_n}/{mode_n}/{phase_n}/{category}: "
            + ",".join(sorted(row.key for row in matches))
        )
    return matches[0]


def classify_artifact_capability(
    *,
    pipeline: str,
    mode: str,
    phase: str,
    artifact: str,
    category: str = "*",
    actor: str = "MODEL",
) -> WorkUnitCapability | None:
    try:
        capability = resolve_capability(
            pipeline=pipeline, mode=mode, phase=phase, category=category
        )
    except CapabilityResolutionError:
        return None
    if capability.actor != str(actor).strip().upper():
        return None
    name = str(artifact).replace("\\", "/")
    if not any(fnmatch.fnmatchcase(name, pattern) for pattern in capability.artifact_patterns):
        return None
    return capability


def render_capability_block(capability: WorkUnitCapability) -> str:
    outcomes = (
        "CANDIDATE | REFUTATION_PROPOSAL | NOT_APPLICABLE_PROPOSAL | UNRESOLVED"
        if capability.authority_class == "GENERATOR"
        else " | ".join(sorted(capability.allowed_outcomes))
    )
    lines = [
        "\n## DRIVER-COMPILED WORK-UNIT CAPABILITY (FINAL AUTHORITY)\n",
        f"Capability ID: {capability.key}\n",
        f"Authority Class: {capability.authority_class}\n",
        f"Allowed Outcomes: {outcomes}\n",
    ]
    if capability.authority_class == "GENERATOR":
        lines.append(
            "Inherited SAFE/CLEAR/REFUTED/DISMISSED/NO_FINDING and equivalent "
            "terminal-negative labels are translated to proposals; they never "
            "authorize deletion, downgrade, or exclusion.\n"
        )
    if capability.external_research:
        lines.append("External research: ALLOWED only for this exact work unit.\n")
    else:
        lines.append("External research: DENIED. Use only bound local evidence.\n")
    lines.append(f"Lifecycle owner: {capability.lifecycle_owner}\n")
    return "".join(lines)


def compile_work_unit_capability_contract(
    prompt: str, capability: WorkUnitCapability
) -> str:
    return str(prompt).rstrip() + "\n" + render_capability_block(capability)


def validate_registry() -> None:
    capabilities = all_capabilities()
    keys = [row.key for row in capabilities]
    if keys != sorted(set(keys)):
        raise ValueError("work-unit capability keys are not unique/sorted")
    for row in capabilities:
        if row.authority_class == "GENERATOR":
            if row.allowed_outcomes != GENERATOR_OUTCOMES or row.terminal_negative_authority:
                raise ValueError(f"generator {row.key} has terminal-negative authority")
        if row.authority_class == "CAMPAIGN" and row.harvest_policy != "CAMPAIGN_EVIDENCE_ONLY":
            raise ValueError(f"campaign {row.key} is not evidence-scoped")
        if row.external_research and row.authority_class != "RESEARCH":
            raise ValueError(f"non-research capability {row.key} has research authority")
        if not row.pipelines or not row.modes or not row.work_categories:
            raise ValueError(f"capability {row.key} is incomplete")


validate_registry()


__all__ = [
    "ALL_MODES",
    "CAMPAIGN_OUTCOMES",
    "CapabilityResolutionError",
    "GENERATOR_OUTCOMES",
    "WorkUnitCapability",
    "all_capabilities",
    "capability_by_key",
    "classify_artifact_capability",
    "compile_work_unit_capability_contract",
    "render_capability_block",
    "resolve_capability",
    "validate_registry",
]
