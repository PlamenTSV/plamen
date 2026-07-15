"""R0-1: every smart-contract breadth backend receives one semantic floor.

The kernel is deliberately a single versioned Markdown source.  These tests
guard against the two failure modes this change is meant to remove: an empty
recon skill selection leaving no security reasoning floor, and Claude/Codex
backend drift creating different floors.
"""
from __future__ import annotations

import re
from pathlib import Path

import codex_adapter as C
import plamen_driver as D


REPO = Path(__file__).resolve().parent.parent
KERNEL = REPO / "prompts" / "shared" / "v2" / "breadth-semantic-operator-kernel.md"
SC_LANGUAGES = ("evm", "solana", "aptos", "sui", "soroban")
MODES = ("light", "core", "thorough")


def _prompt(tmp_path: Path, *, pipeline: str = "sc", language: str = "evm", mode: str = "core") -> str:
    return D._build_breadth_worker_prompt(
        job={
            "agent_id": "B1" if pipeline == "sc" else "L1B1",
            "focus_area": "state_transitions",
            "output": "analysis_state_transitions.md",
            "layers": "execution",
            "skills": "state-safety",
            "difficulty": "HIGH",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path.parent),
        config={"pipeline": pipeline, "language": language, "mode": mode},
        attempt=1,
    )


def _kernel_source() -> str:
    return KERNEL.read_text(encoding="utf-8").strip()


def test_empty_skill_selection_still_gets_complete_versioned_kernel(tmp_path: Path):
    prompt = _prompt(tmp_path)
    kernel = _kernel_source()

    assert kernel in prompt
    assert "ASSIGNED SKILL METHODOLOGY" not in prompt
    assert "PLAMEN_BREADTH_SEMANTIC_KERNEL: BEGIN v1.0.0" in prompt
    assert len(re.findall(r"(?m)^\d+\. \*\*", kernel)) == 12


def test_recon_selected_skill_is_additive_to_kernel(tmp_path: Path):
    (tmp_path / "spawn_manifest.md").write_text(
        """# Spawn Manifest

## Breadth Agents

| Row Type | Template | Required? | Agent ID | Focus Area | Expected Output | Status |
|---|---|---|---|---|---|---|
| AGENT | CROSS_CHAIN_MESSAGE_INTEGRITY | YES | B1 | state_transitions | analysis_state_transitions.md | QUEUED |

## Skill Bindings

| Skill | Type | Inject Into | Delivery Mode |
|---|---|---|---|
| CROSS_CHAIN_MESSAGE_INTEGRITY | Primary | B1 | Full SKILL.md |
""",
        encoding="utf-8",
    )

    prompt = _prompt(tmp_path)
    assert _kernel_source() in prompt
    assert "ASSIGNED SKILL METHODOLOGY (MANDATORY" in prompt
    assert "cross-chain-message-integrity/SKILL.md" in prompt


def test_all_sc_languages_and_modes_receive_byte_identical_kernel(tmp_path: Path):
    kernel = _kernel_source()
    for language in SC_LANGUAGES:
        for mode in MODES:
            prompt = _prompt(tmp_path, language=language, mode=mode)
            assert prompt.count(kernel) == 1, (language, mode)


def test_codex_role_and_generated_toml_embed_the_same_kernel(tmp_path: Path, monkeypatch):
    kernel = _kernel_source()
    role = next(role for role in C.AGENT_ROLES if role["name"] == "breadth")
    assert role["instructions"].count(kernel) == 1

    out = tmp_path / "adapter"
    # The generator's progress message intentionally renders paths relative to
    # its installation root; make the isolated output that root for this test.
    monkeypatch.setattr(C, "PLAMEN_HOME", tmp_path)
    C.generate_agent_tomls(out)
    generated = (out / "agents" / "breadth.toml").read_text(encoding="utf-8")
    checked_in = (REPO / "codex-adapter" / "agents" / "breadth.toml").read_text(
        encoding="utf-8"
    )
    assert generated.count(kernel) == 1
    assert checked_in.count(kernel) == 1


def test_l1_does_not_receive_smart_contract_kernel(tmp_path: Path):
    prompt = _prompt(tmp_path, pipeline="l1", language="go")
    assert "PLAMEN_BREADTH_SEMANTIC_KERNEL" not in prompt


def test_missing_kernel_degrades_loudly_instead_of_claiming_coverage(
    tmp_path: Path, monkeypatch
):
    missing_home = tmp_path / "missing-install"
    monkeypatch.setattr(D, "plamen_home", lambda: missing_home)

    prompt = _prompt(tmp_path)
    assert "[BREADTH-KERNEL-UNAVAILABLE]" in prompt
    assert "Do not treat this worker as complete security-method coverage" in prompt


def test_existing_r13_directive_remains_separate_and_unchanged(tmp_path: Path):
    prompt = _prompt(tmp_path)
    assert prompt.count(D._BREADTH_ANTI_NORMALIZATION_DIRECTIVE) == 1
    assert D._BREADTH_ANTI_NORMALIZATION_DIRECTIVE not in _kernel_source()


def test_kernel_is_compact_and_part0_clean():
    kernel = _kernel_source()
    # The floor should remain small enough to be applied; ecosystem skills add
    # detail underneath it.  Concrete brand/ecosystem names do not belong here.
    assert len(kernel.split()) <= 650
    assert kernel.count("\n") <= 60
    forbidden_names = (
        "uniswap", "aave", "compound", "spectra", "solodit", "ethereum",
        "solana", "aptos", "sui", "soroban", "bitcoin", "wormhole",
        "layerzero",
    )
    assert not any(name in kernel.lower() for name in forbidden_names)


def test_coordinator_document_and_worker_prompt_do_not_claim_coverage(tmp_path: Path):
    coordinator = (
        REPO / "prompts" / "shared" / "v2" / "phase3-breadth.md"
    ).read_text(encoding="utf-8")
    prompt = _prompt(tmp_path)
    assert "execution procedure, not vulnerability coverage" in coordinator
    assert "breadth audit methodology and vulnerability coverage" not in prompt
