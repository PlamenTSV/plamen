"""P1 regression: SC breadth/depth worker prompts mechanically inject the
recon-selected skills bound in spawn_manifest.md (the L1 v2.6.4 fix, ported to
SC). The misapplication audit proved this wiring was the dominant recall miss:
skills were bound per agent but never reached the worker prompt.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import plamen_driver as D


_MANIFEST = """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|----------|-----------|----------|------------|-----------------|--------|
| AGENT | TOKEN_FLOW_TRACING | YES | B1 | core_token_flow | analysis_core_token_flow.md | QUEUED |
| AGENT | CROSS_CHAIN_MESSAGE_INTEGRITY | YES | B3 | cross_chain_integrity | analysis_cross_chain_integrity.md | QUEUED |

## Skill-to-Agent Assignment

| Template | Required? | Assigned To | Method |
|----------|-----------|-------------|--------|
| TOKEN_FLOW_TRACING | YES | B1 | Primary |
| CROSS_CHAIN_MESSAGE_INTEGRITY | YES | B3 | Primary |
| CROSS_CHAIN_TIMING | YES | B3 | Merged (secondary) |
| INTEGRATION_HAZARD_RESEARCH | YES | depth-external | Depth Phase 4b injection |
| DEX_INTEGRATION_SECURITY | YES | depth-edge-case | Depth Phase 4b injection |
| FORK_ANCESTRY | YES | Recon TASK 0 | Already executed |
| VERIFICATION_PROTOCOL | YES | Verifiers | Phase 5 only |
"""

_REALISTIC_INJECT_INTO_MANIFEST = """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|----------|----------|-----------|----------|------------|-----------------|--------|
| AGENT | CROSS_CHAIN_MESSAGE_INTEGRITY + CROSS_CHAIN_TIMING | YES | B1 | cross_chain_message_integrity | analysis_cross_chain_message_integrity.md | QUEUED |
| AGENT | TOKEN_FLOW_TRACING | YES | B2 | token_flow_dex | analysis_token_flow_dex.md | QUEUED |
| AGENT | ECONOMIC_DESIGN_AUDIT + EXTERNAL_PRECONDITION_AUDIT | YES | B3 | economic_temporal_external | analysis_economic_temporal_external.md | QUEUED |

## Skill Bindings

| Skill | Type | Inject Into | Delivery Mode |
|-------|------|-------------|---------------|
| CROSS_CHAIN_TIMING | Secondary (standard) | B1 | Full SKILL.md |
| TEMPORAL_PARAMETER_STALENESS | Secondary (standard) | B3 | Full SKILL.md |
| EXTERNAL_PRECONDITION_AUDIT | Secondary (standard) | B3 | Full SKILL.md |
| DEX_INTEGRATION_SECURITY | Injectable | B2 | Full SKILL.md |
| INTEGRATION_HAZARD_RESEARCH | Injectable | depth-external | Full SKILL.md |
"""


def _mkscratch() -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_scskill_"))
    (sp / "spawn_manifest.md").write_text(_MANIFEST, encoding="utf-8")
    return sp


def _mkscratch_realistic() -> Path:
    sp = Path(tempfile.mkdtemp(prefix="plamen_scskill_real_"))
    (sp / "spawn_manifest.md").write_text(_REALISTIC_INJECT_INTO_MANIFEST, encoding="utf-8")
    return sp


def test_parse_binds_breadth_focus_and_depth_role():
    sp = _mkscratch()
    breadth, depth = D._parse_sc_skill_bindings(sp)
    assert "CROSS_CHAIN_MESSAGE_INTEGRITY" in breadth.get("cross_chain_integrity", [])
    assert "CROSS_CHAIN_TIMING" in breadth.get("cross_chain_integrity", [])
    assert "TOKEN_FLOW_TRACING" in breadth.get("core_token_flow", [])
    # depth injectables keyed by role
    assert "INTEGRATION_HAZARD_RESEARCH" in depth.get("external", [])
    assert "DEX_INTEGRATION_SECURITY" in depth.get("edge_case", [])


def test_parse_realistic_inject_into_bindings():
    sp = _mkscratch_realistic()
    breadth, depth = D._parse_sc_skill_bindings(sp)
    assert "CROSS_CHAIN_MESSAGE_INTEGRITY" in breadth.get("cross_chain_message_integrity", [])
    assert "CROSS_CHAIN_TIMING" in breadth.get("cross_chain_message_integrity", [])
    assert "DEX_INTEGRATION_SECURITY" in breadth.get("token_flow_dex", [])
    assert "ECONOMIC_DESIGN_AUDIT" in breadth.get("economic_temporal_external", [])
    assert "TEMPORAL_PARAMETER_STALENESS" in breadth.get("economic_temporal_external", [])
    assert "EXTERNAL_PRECONDITION_AUDIT" in breadth.get("economic_temporal_external", [])
    assert "INTEGRATION_HAZARD_RESEARCH" in depth.get("external", [])


def test_non_evm_target_evidence_mechanically_recovers_cross_vm_binding():
    sp = _mkscratch_realistic()
    (sp / "recon_summary.md").write_text(
        "Gateway withdrawAndCall targets Solana and Bitcoin. "
        "PayloadCodec serializes Solana pubkey/account bytes for a destination chain.",
        encoding="utf-8",
    )
    # CROSS_VM is an EVM-SIDE skill: recovery fires on an EXPLICIT EVM audit that
    # serializes outbound for a non-EVM VM (e.g. an PayloadCodec). Native
    # non-EVM (solana/aptos/sui/soroban) and legacy/unknown ('') runs must NOT recover.
    breadth, depth = D._parse_sc_skill_bindings(sp, "evm")
    assert "CROSS_VM_SERIALIZATION_CONFORMANCE" in breadth.get(
        "cross_chain_message_integrity", []
    )
    assert "CROSS_VM_SERIALIZATION_CONFORMANCE" in depth.get("external", [])


# --- Recall re-validation: the generic cross-chain detector must fire across
# bridge families (not just one protocol's literal contract names). Each fixture
# uses only GENERIC bridge vocabulary + non-EVM (Solana/Borsh) evidence. ---

def _binds_cross_vm(tmp_summary: str) -> bool:
    sp = _mkscratch_realistic()
    (sp / "recon_summary.md").write_text(tmp_summary, encoding="utf-8")
    breadth, depth = D._parse_sc_skill_bindings(sp, "evm")
    return "CROSS_VM_SERIALIZATION_CONFORMANCE" in breadth.get(
        "cross_chain_message_integrity", [])


def test_cross_vm_recovers_on_layerzero_shaped():
    # LayerZero-style: no literal method in the regex; caught via generic bridge vocab
    assert _binds_cross_vm(
        "lzReceive handler forwards a cross-chain bridge payload; "
        "serializes Solana pubkey/account bytes with Borsh for the destination chain.")


def test_cross_vm_recovers_on_wormhole_shaped():
    assert _binds_cross_vm(
        "receiveWormholeMessages parses the payload and relays it; "
        "encodes a Solana account address (base58/Borsh) for the destination chain.")


def test_cross_vm_recovers_on_ccip_axelar_shaped():
    assert _binds_cross_vm(
        "ccipReceive on the destination chain via the relay/bridge; "
        "packs a Solana Pubkey (Borsh) for the source chain.")


def test_cross_vm_no_recover_evm_only_bridge_negative_control():
    # bridge/message/payload vocabulary but NO non-EVM (Solana/Bitcoin/Borsh)
    # evidence -> the positive AND cross_chain gate must NOT fire (no over-firing).
    assert not _binds_cross_vm(
        "A generic EVM bridge relays a cross-chain message payload between two "
        "EVM chains; no non-EVM serialization involved.")


def test_recon_and_verifier_skills_excluded():
    sp = _mkscratch()
    breadth, depth = D._parse_sc_skill_bindings(sp)
    allskills = {s for v in breadth.values() for s in v} | {s for v in depth.values() for s in v}
    assert "FORK_ANCESTRY" not in allskills
    assert "VERIFICATION_PROTOCOL" not in allskills


def test_skill_path_resolves_evm_skill():
    # CROSS_CHAIN_MESSAGE_INTEGRITY lives under agents/skills/evm/
    p = D._sc_skill_path_for_name("CROSS_CHAIN_MESSAGE_INTEGRITY", "evm")
    assert p is not None and p.name == "SKILL.md" and "cross-chain-message-integrity" in p.as_posix()


def test_injection_block_is_mandatory_and_lists_skills():
    blk = D._sc_skill_injection_block(
        ["CROSS_CHAIN_MESSAGE_INTEGRITY"], agent_kind="breadth", language="evm"
    )
    assert "MANDATORY" in blk
    assert "Step Execution Checklist" in blk
    assert "cross-chain-message-integrity/SKILL.md" in blk
    # empty for an unbound / unresolvable skill set
    assert D._sc_skill_injection_block([], agent_kind="breadth", language="evm") == ""
    assert D._sc_skill_injection_block(
        ["NONEXISTENT_SKILL_XYZ"], agent_kind="breadth", language="evm"
    ) == ""


def test_breadth_worker_prompt_injects_bound_skill():
    sp = _mkscratch()
    job = {"agent_id": "B3", "focus_area": "cross_chain_integrity",
           "output": "analysis_cross_chain_integrity.md"}
    prompt = D._build_breadth_worker_prompt(
        job=job, scratchpad=sp, project_root=str(sp),
        config={"pipeline": "sc", "language": "evm", "mode": "thorough"}, attempt=1,
    )
    assert "ASSIGNED SKILL METHODOLOGY (MANDATORY" in prompt
    assert "cross-chain-message-integrity/SKILL.md" in prompt


def test_breadth_worker_prompt_injects_realistic_secondary_and_injectable_skills():
    sp = _mkscratch_realistic()
    job = {"agent_id": "B2", "focus_area": "token_flow_dex",
           "output": "analysis_token_flow_dex.md"}
    prompt = D._build_breadth_worker_prompt(
        job=job, scratchpad=sp, project_root=str(sp),
        config={"pipeline": "sc", "language": "evm", "mode": "thorough"}, attempt=1,
    )
    assert "token-flow-tracing/SKILL.md" in prompt
    assert "dex-integration-security/SKILL.md" in prompt


def test_depth_worker_prompt_injects_injectable_depth_skill():
    sp = _mkscratch()
    job = {"agent_id": "depth-external", "role": "external",
           "output": "depth_external_findings.md", "category": "standard"}
    prompt = D._build_depth_worker_prompt(
        job=job, scratchpad=sp, project_root=str(sp),
        config={"pipeline": "sc", "language": "evm", "mode": "thorough"}, attempt=1,
    )
    assert "ASSIGNED SKILL METHODOLOGY (MANDATORY" in prompt
    assert ("integration-hazard-research/SKILL.md" in prompt
            or "dex-integration-security/SKILL.md" in prompt)


def test_breadth_prompt_unchanged_when_no_manifest():
    # No spawn_manifest -> no skill block, prompt still builds.
    sp = Path(tempfile.mkdtemp(prefix="plamen_noman_"))
    job = {"agent_id": "B1", "focus_area": "core_token_flow", "output": "analysis_x.md"}
    prompt = D._build_breadth_worker_prompt(
        job=job, scratchpad=sp, project_root=str(sp),
        config={"pipeline": "sc", "language": "evm", "mode": "core"}, attempt=1,
    )
    assert "ASSIGNED SKILL METHODOLOGY" not in prompt
    assert "BREADTH ROW WORKER" in prompt
