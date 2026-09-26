"""The actual bound leaf projection must carry evidence-led depth guidance."""

from __future__ import annotations

from pathlib import Path

import plamen_driver as driver
import pytest


ROOT = Path(__file__).resolve().parents[1]


def test_every_sc_depth_projection_preserves_harm_and_uncertainty(tmp_path: Path) -> None:
    for language in ("evm", "solana", "aptos", "sui", "soroban", "daml"):
        projection = driver._standard_depth_template_projection(
            ROOT / "prompts" / language / "phase4b-depth-templates.md",
            role="token_flow",
            scratchpad=tmp_path,
            output="depth_token_flow_findings.md",
        )
        if language == "daml":
            assert "party action → ACS change" in projection
            assert "financial or non-financial harm" in projection
        else:
            assert "attacker action → reachable state transition → concrete harm" in projection, language
            assert "governance, authorization, integrity, or liveness" in projection, language
        assert "unproven defense alone does not prove the attack" in projection
        assert "[EXTERNAL-ASSUMPTION: ...]" in projection
        assert "NEEDS_DEPENDENCY_RESEARCH" in projection
        assert "profit/loss in dollar terms" not in projection, language
        assert "If you cannot construct a trace showing the defense" not in projection
        assert "## Output" not in projection


def test_depth_role_files_are_method_only() -> None:
    for role in (
        "edge-case", "external", "state-trace", "token-flow",
        "consensus-invariant", "network-surface",
    ):
        body = (ROOT / "agents" / f"depth-{role}.md").read_text(
            encoding="utf-8"
        )
        assert "## Output Format" not in body, role
        assert "## Finding ID Format" not in body, role
        assert "## Return Protocol" not in body, role
        assert "DONE:" not in body, role
        assert not any(
            word in body for word in ("CONFIRMED", "REFUTED", "CONTESTED")
        ), role


@pytest.mark.parametrize("backend", ["codex", "claude", "claude-headless"])
def test_standard_depth_worker_keeps_one_contract_across_backends(
    tmp_path: Path, backend: str
) -> None:
    prompt = driver._build_depth_worker_prompt(
        job={
            "agent_id": "depth-external",
            "role": "external",
            "output": "depth_external_findings.md",
            "category": "standard",
            "focus": "external integrations",
        },
        scratchpad=tmp_path,
        project_root=str(tmp_path),
        config={
            "pipeline": "sc", "mode": "light", "language": "evm",
            "cli_backend": backend, "project_root": str(tmp_path),
            "scratchpad": str(tmp_path),
        },
        attempt=1,
    )
    assert "## Intent and Harm Check" in prompt
    assert "name each challenged invariant, the read-site" in prompt
    assert "A comment or test alone does not establish" in prompt
    assert "[EXTERNAL-ASSUMPTION: ...]" in prompt
    assert "NEEDS_DEPENDENCY_RESEARCH" in prompt
    assert "`DONE: depth_external_findings.md complete`" in prompt
    assert "DONE: {N} depth findings" not in prompt
