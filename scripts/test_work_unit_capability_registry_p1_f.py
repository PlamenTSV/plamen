from __future__ import annotations

import pytest

import work_unit_capabilities as C
import plamen_driver as D
import plamen_prompt as P
from plamen_types import SC_PHASES, plamen_home


EXPECTED_PRODUCER_KEYS = {
    "sc_breadth",
    "l1_breadth",
    "sc_rescan",
    "sc_per_contract",
    "semantic_invariants_p1",
    "semantic_invariants_p2",
    "sc_depth_standard",
    "l1_depth_standard",
    "depth_scanner",
    "sibling_propagation",
    "depth_niche",
    "depth_sidecar",
    "attention_repair",
    "axis_coverage",
    "l1_graph_sweep",
    "chain_agent1",
    "chain_agent2",
    "chain_iter2",
    "sc_fuzz_campaign",
}


def test_registry_is_closed_unique_and_covers_active_producer_classes() -> None:
    capabilities = C.all_capabilities()
    keys = [capability.key for capability in capabilities]
    assert keys == sorted(set(keys))
    assert EXPECTED_PRODUCER_KEYS <= set(keys)
    C.validate_registry()


def test_generator_outcomes_are_nonterminal_and_campaign_is_separate() -> None:
    for capability in C.all_capabilities():
        if capability.authority_class == "GENERATOR":
            assert capability.allowed_outcomes == C.GENERATOR_OUTCOMES
            assert capability.terminal_negative_authority is False
        if capability.authority_class == "CAMPAIGN":
            assert capability.harvest_policy == "CAMPAIGN_EVIDENCE_ONLY"
            assert "NO_VIOLATIONS" in capability.allowed_outcomes
            assert "REFUTED" not in capability.allowed_outcomes


def test_exact_resolution_distinguishes_depth_categories_and_backends() -> None:
    standard = C.resolve_capability(
        pipeline="sc", mode="thorough", phase="depth", category="standard"
    )
    scanner = C.resolve_capability(
        pipeline="sc", mode="thorough", phase="depth", category="scanner"
    )
    fuzz = C.resolve_capability(
        pipeline="sc", mode="thorough", phase="depth", category="fuzz"
    )
    assert standard.key == "sc_depth_standard"
    assert scanner.key == "depth_scanner"
    assert fuzz.key == "sc_fuzz_campaign"
    with pytest.raises(C.CapabilityResolutionError):
        C.resolve_capability(
            pipeline="l1", mode="thorough", phase="depth", category="fuzz"
        )


def test_generator_contract_is_last_authority_and_translates_legacy_negatives() -> None:
    capability = C.capability_by_key("sc_breadth")
    rendered = C.compile_work_unit_capability_contract(
        "Earlier inherited text.\nAllowed Verdicts: CONFIRMED | REFUTED\n",
        capability,
    )
    assert rendered.endswith(C.render_capability_block(capability))
    assert "Authority Class: GENERATOR" in rendered
    assert (
        "CANDIDATE | REFUTATION_PROPOSAL | NOT_APPLICABLE_PROPOSAL | UNRESOLVED"
        in rendered
    )
    assert "translated to proposals" in rendered


def test_discriminator_retains_terminal_negative_authority() -> None:
    capability = C.capability_by_key("application_skeptic_discriminator")
    block = C.render_capability_block(capability)
    assert capability.terminal_negative_authority is True
    assert "NEGATIVE_AGREEMENT" in block
    assert "REFUTATION_PROPOSAL" not in block


def test_only_explicit_research_capabilities_allow_external_research() -> None:
    research = {
        capability.key
        for capability in C.all_capabilities()
        if capability.external_research
    }
    assert research == {"recon_external_research", "precedent_research"}
    for capability in C.all_capabilities():
        block = C.render_capability_block(capability)
        if not capability.external_research:
            assert "WebSearch" not in block
            assert "WebFetch" not in block


def test_artifact_classification_excludes_driver_reemits_and_campaign_status() -> None:
    assert C.classify_artifact_capability(
        pipeline="sc",
        mode="thorough",
        phase="depth",
        artifact="depth_state_trace_findings.md",
        category="standard",
        actor="MODEL",
    ).key == "sc_depth_standard"
    assert C.classify_artifact_capability(
        pipeline="sc",
        mode="thorough",
        phase="depth",
        artifact="depth_percontract_reemit_findings.md",
        category="standard",
        actor="DRIVER",
    ) is None
    assert C.classify_artifact_capability(
        pipeline="sc",
        mode="thorough",
        phase="depth",
        artifact="invariant_fuzz_results.md",
        category="fuzz",
        actor="MODEL",
    ).authority_class == "CAMPAIGN"


def test_typed_worker_render_seam_appends_capability_after_phaseio() -> None:
    rendered = D._compile_typed_worker_prompt(
        "Allowed Verdicts: CONFIRMED | REFUTED\n",
        config={
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "claude",
        },
        phase_name="depth",
        agent_id="depth-state",
        output="depth_state_trace_findings.md",
        work_category="standard",
    )
    assert rendered.rfind("DRIVER-COMPILED WORK-UNIT CAPABILITY") > rendered.rfind(
        "PLAMEN PHASE I/O CONTRACT"
    )
    assert rendered.rstrip().endswith("Lifecycle owner: candidate_negative_skeptic")


def test_generic_render_seam_appends_axis_generator_capability(tmp_path) -> None:
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    phase = next(row for row in SC_PHASES if row.name == "axis_coverage")
    rendered = P.build_phase_prompt(
        plamen_home() / "commands" / "plamen.md",
        phase,
        {
            "project_root": str(tmp_path),
            "scratchpad": str(scratch),
            "language": "evm",
            "mode": "thorough",
            "pipeline": "sc",
            "cli_backend": "claude",
            "subsystem_scope": "",
            "scope_file": "",
            "scope_notes": "",
            "_run_id": "00000000-0000-4000-8000-000000000001",
        },
    )
    assert "Capability ID: axis_coverage" in rendered
    assert rendered.rstrip().endswith("Lifecycle owner: candidate_negative_skeptic")
