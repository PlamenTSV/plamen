"""Backend-neutral phase wrappers keep the driver as the sole sequencer."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from plamen_prompt import build_phase_prompt
from plamen_types import SC_PHASES


@pytest.mark.parametrize("backend", ["codex", "claude-headless"])
def test_direct_phase_scope_has_no_obsolete_backend_or_output_probe(
    tmp_path: Path, backend: str
) -> None:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    legacy = tmp_path / "legacy.md"
    legacy.write_text(
        "## Phase 2: Orchestrator Instantiation\n\n"
        "Apply the selected phase methodology.\n",
        encoding="utf-8",
    )
    phase = replace(
        next(item for item in SC_PHASES if item.name == "instantiate"),
        expected_artifacts=["spawn_manifest_proposal.md"],
        any_of=[],
        min_artifacts_count=1,
    )
    config = {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "proven_only": False,
        "cli_backend": backend,
    }
    prompt = build_phase_prompt(legacy, phase, config)
    assert "## DRIVER-OWNED PHASE SCOPE" in prompt
    assert "## DRIVER-OWNED RESUMPTION PROTOCOL" in prompt
    assert "phase-scoped claude -p subprocess" not in prompt
    assert "## MCP POLICY" not in prompt
    assert "check whether your assigned output already exists" not in prompt.lower()
