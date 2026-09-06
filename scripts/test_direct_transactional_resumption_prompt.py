"""Regression tests for driver-owned direct-worker resumption."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import claude_worker_prompt_consistency as prompt_consistency
import plamen_prompt
import plamen_validators
from plamen_types import SC_PHASES


_UNSAFE_RESUMPTION_PHRASES = (
    "check the scratchpad for prior-attempt",
    "check against `{scratchpad}` glob",
    "any matching file >= 200 bytes",
)


def _instantiate_prompt(tmp_path: Path, *, retry: bool = False) -> tuple[str, Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    v1_prompt = tmp_path / "plamen.md"
    v1_prompt.write_text(
        "## Phase 2: Orchestrator Instantiation\n\n"
        "Use the phase-scoped instantiate methodology.\n",
        encoding="utf-8",
    )
    if retry:
        plamen_validators._write_retry_hint(  # pylint: disable=protected-access
            scratchpad,
            "instantiate",
            "Prior provider result contained a denied canonical output probe.",
        )
        (scratchpad / "instantiate_retry_plan.json").write_text(
            json.dumps(
                {
                    "schema": "plamen.retry-plan/v1",
                    "phase_name": "instantiate",
                    "semantic_retry": True,
                    "failed_predicates": ["provider result permission denial"],
                }
            ),
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
        "cli_backend": "claude",
    }
    return plamen_prompt.build_phase_prompt(v1_prompt, phase, config), project, scratchpad


def _assert_driver_owned_resumption(prompt: str) -> None:
    lowered = prompt.lower()
    assert "## driver-owned resumption protocol (hard)" in lowered
    assert "do not inspect the canonical scratchpad" in lowered
    assert "do not use read, glob, grep" in lowered
    assert "final runtime output routing" in lowered
    for unsafe in _UNSAFE_RESUMPTION_PHRASES:
        assert unsafe not in lowered


def test_instantiate_attempt1_does_not_probe_canonical_expected_output(tmp_path: Path):
    prompt, _project, scratchpad = _instantiate_prompt(tmp_path)
    _assert_driver_owned_resumption(prompt)
    assert f"check against `{scratchpad}` glob".lower() not in prompt.lower()


def test_instantiate_retry_does_not_probe_canonical_expected_output(tmp_path: Path):
    prompt, _project, scratchpad = _instantiate_prompt(tmp_path, retry=True)
    assert prompt.startswith("# RETRY ATTEMPT")
    _assert_driver_owned_resumption(prompt)
    assert prompt.lower().count("## driver-owned resumption protocol (hard)") == 1
    assert f"check against `{scratchpad}` glob".lower() not in prompt.lower()


def test_direct_resumption_block_is_restricted_claude_consistent(tmp_path: Path):
    prompt, project, scratchpad = _instantiate_prompt(tmp_path)
    match = re.search(
        r"(?ms)^## DRIVER-OWNED RESUMPTION PROTOCOL \(HARD\)\n.*?(?=^## |\Z)",
        prompt,
    )
    assert match is not None
    issues = prompt_consistency.validate_claude_worker_prompt_consistency(
        match.group(0),
        phase_io_inputs=(),
        phase_io_outputs=(scratchpad / "spawn_manifest_proposal.md",),
        policy_tools=("Read", "Glob", "Grep", "Write"),
        safe_search_roots=(),
        project_root=project,
        scratchpad_root=scratchpad,
    )
    assert issues == ()
