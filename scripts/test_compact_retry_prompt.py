"""Tests for the Pattern 2 compact retry prompt refactor.

When a phase fails its gate, `_write_retry_hint` is called and the next
attempt's prompt is built via `build_phase_prompt`. Retry prompts are
compact and error-primary for every phase. Accumulate phases
(breadth/rescan/depth) still preserve complete artifacts on disk, but no
longer replay the full original prompt by default.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
import re

import pytest

import claude_worker_prompt_consistency as prompt_consistency
import headless_worker_runtime as headless_runtime
import plamen_driver as driver
import plamen_prompt as p
import plamen_validators as v
from plamen_types import SC_PHASES


# --- Fixtures ---------------------------------------------------------------


@pytest.fixture
def scratch_and_project():
    scratch = Path(tempfile.mkdtemp(prefix="plamen_compret_"))
    project = Path(tempfile.mkdtemp(prefix="plamen_compret_proj_"))
    v1 = scratch / "v1.md"
    # Use realistic section markers so the V1 body extraction has something
    # to find for accumulate phase tests.
    v1.write_text(
        "## Phase 3: Parallel Breadth Analysis\n\n"
        "Spawn agents in parallel.\n\n"
        + ("LOTS_OF_ORIGINAL_PROMPT_BODY " * 200)
        + "\n",
        encoding="utf-8",
    )
    yield scratch, project, v1
    shutil.rmtree(scratch, ignore_errors=True)
    shutil.rmtree(project, ignore_errors=True)


def _config(scratch: Path, project: Path) -> dict:
    return {
        "project_root": str(project),
        "scratchpad": str(scratch),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "proven_only": False,
        "cli_backend": "claude",
    }


# --- Non-accumulate phases: compact retry mode ------------------------------


class TestCompactRetryNonAccumulate:
    def test_retry_hint_triggers_compact_replacement(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "sc_semantic_dedup", "Test hint: missing X, Y, Z.")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert prompt.startswith("# RETRY ATTEMPT")
        # Compact prompt should be SUBSTANTIALLY smaller than the full prompt
        # (original full prompts are 5-15 KB; compact should be < 5 KB).
        assert len(prompt) < 6000, f"compact prompt too large: {len(prompt)} bytes"

    def test_hint_appears_in_primary_position(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        unique_hint = "UNIQUE_SENTINEL_ERROR_PHRASE_42"
        v._write_retry_hint(scratch, "sc_semantic_dedup", f"Test: {unique_hint}")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        # Error context must appear in the first 1500 chars (primary attention zone)
        idx = prompt.find(unique_hint)
        assert idx >= 0, "unique sentinel not found in compact prompt"
        assert idx < 1500, f"sentinel buried at position {idx} (should be < 1500)"

    def test_snapshot_path_is_referenced(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "sc_semantic_dedup", "hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert "_prompt_sc_semantic_dedup.attempt1.md" in prompt

    def test_quarantine_path_is_referenced(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "sc_semantic_dedup", "hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert "_retry_quarantine/sc_semantic_dedup" in prompt

    def test_compact_includes_expected_output_section(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "sc_semantic_dedup", "hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        # phase has expected_artifacts → block should render
        assert "EXPECTED OUTPUT FILES" in prompt

    def test_compact_includes_critical_scope_directive(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "sc_semantic_dedup", "hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert "Critical phase scope" in prompt
        assert "single phase subprocess" in prompt

    def test_compact_omits_full_v1_body(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "sc_semantic_dedup", "hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        # The huge LOTS_OF_ORIGINAL_PROMPT_BODY filler should NOT appear in
        # the compact prompt — that's the whole point.
        assert "LOTS_OF_ORIGINAL_PROMPT_BODY" not in prompt


# --- Accumulate phases: compact repair mode, preserve artifacts -------------


class TestAccumulatePhasesUnchanged:
    def test_breadth_retry_uses_compact_repair_not_prepend(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "breadth", "breadth hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "breadth")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert prompt.startswith("# RETRY ATTEMPT")
        assert "RETRY HINT (injected by driver" not in prompt
        assert "preserve" in prompt.lower()
        assert "Do NOT overwrite completed rows/files" in prompt

    def test_depth_retry_uses_compact_repair_not_prepend(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "depth", "depth hint")
        phase = next(ph for ph in SC_PHASES if ph.name == "depth")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert prompt.startswith("# RETRY ATTEMPT")
        assert "RETRY HINT (injected by driver" not in prompt
        assert "Repair ONLY" in prompt

    def test_rescan_retry_uses_compact_repair_not_prepend(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        v._write_retry_hint(scratch, "rescan", "rescan hint")
        try:
            phase = next(ph for ph in SC_PHASES if ph.name == "rescan")
        except StopIteration:
            pytest.skip("rescan phase not in SC_PHASES")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert prompt.startswith("# RETRY ATTEMPT")
        assert "RETRY HINT (injected by driver" not in prompt
        assert "Repair ONLY" in prompt


# --- Attempt 1 unchanged (no retry hint -> no special branch) ---------------


class TestAttempt1Unchanged:
    def test_attempt1_no_retry_hint_no_compact_path(self, scratch_and_project):
        scratch, project, v1 = scratch_and_project
        # NO retry hint written → attempt-1-style prompt
        phase = next(ph for ph in SC_PHASES if ph.name == "sc_semantic_dedup")
        prompt = p.build_phase_prompt(v1, phase, _config(scratch, project))
        assert not prompt.startswith("# RETRY ATTEMPT")
        assert "RETRY HINT (injected by driver" not in prompt


@pytest.mark.parametrize("retry", (False, True))
def test_instantiate_render_is_restricted_claude_phaseio_consistent(
    scratch_and_project,
    retry: bool,
):
    scratch, project, v1 = scratch_and_project
    (project / "contracts").mkdir()
    exact_inputs = (
        "attack_surface.md",
        "contract_inventory.md",
        "design_context.md",
        "detected_patterns.md",
        "external_dependency_research.md",
        "function_list.md",
        "recon_signal_transform_receipt.json",
        "recon_summary.md",
        "skill_selection_catalog.json",
        "state_variables.md",
        "template_recommendations.md",
    )
    for name in exact_inputs:
        (scratch / name).write_text(f"# {name}\n", encoding="utf-8")
    if retry:
        v._write_retry_hint(
            scratch,
            "instantiate",
            "spawn_manifest_proposal.md is missing",
        )
    phase = next(ph for ph in SC_PHASES if ph.name == "instantiate")
    rendered = driver._compile_instantiate_model_prompt(
        p.build_phase_prompt(v1, phase, _config(scratch, project))
    )
    attempt_name = "attempt-retry-private" if retry else "attempt-1-private"
    private_output = (
        Path(".scratchpad")
        / ".worker_transactions"
        / "instantiate"
        / "instantiate-orchestrator"
        / "attempts"
        / attempt_name
        / "output"
    )
    provider_prompt = headless_runtime._route_prompt(
        rendered,
        output_directory=private_output,
        output_paths=("spawn_manifest_proposal.md",),
    ).decode("utf-8")
    private_destination = (
        private_output / "spawn_manifest_proposal.md"
    ).as_posix()

    assert "{template-name}/SKILL.md" not in rendered
    assert "Use the Task tool only" not in rendered
    assert "**Write spawn manifest** to" not in provider_prompt
    assert "Write only `spawn_manifest_proposal.md`" not in provider_prompt
    canonical_proposal = scratch / "spawn_manifest_proposal.md"
    assert canonical_proposal.as_posix() not in provider_prompt
    assert str(canonical_proposal) not in provider_prompt
    assert provider_prompt.count("## Runtime output routing") == 1
    assert (
        f"`spawn_manifest_proposal.md` -> `{private_destination}`"
        in provider_prompt
    )
    assert "Write it only to the exact attempt-owned destination" in provider_prompt
    if not retry:
        assert re.search(
            r"(?i)before the final Write, confirm in memory",
            rendered,
        )
    assert not re.search(
        r"(?i)(?:re-?read|read again).{0,100}(?:manifest|spawn_manifest)",
        rendered,
    )
    prompt_consistency.require_claude_worker_prompt_consistency(
        provider_prompt,
        phase_io_inputs=tuple(scratch / name for name in exact_inputs),
        phase_io_outputs=(scratch / "spawn_manifest_proposal.md",),
        policy_tools=("Read", "Write", "Edit", "Glob", "Grep"),
        safe_search_roots=(project / "contracts",),
        project_root=str(project),
        scratchpad_root=str(scratch),
    )


# --- Accumulate phases set integrity check ----------------------------------


class TestAccumulateSetIntegrity:
    def test_accumulate_set_contains_expected_phases(self):
        assert "breadth" in v._ACCUMULATE_ON_RETRY_PHASES
        assert "depth" in v._ACCUMULATE_ON_RETRY_PHASES
        assert "rescan" in v._ACCUMULATE_ON_RETRY_PHASES
