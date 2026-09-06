"""Codex secondary-artifact pre-creation completeness tests.

Codex's apply_patch cannot create new files — only modify existing ones. The
driver seeds empty target files via `_precreate_codex_artifacts` so the model
has valid apply_patch targets. Historically this seeded ONLY the phase's
`expected_artifacts` glob (the 4 core depth findings), leaving the never-cut
secondary artifacts (blind-spot scanners, validation sweep, confidence scores)
and triggered niche outputs with no target — so the never-cut gate degraded
the depth phase. Recon had the same gap for its `*_worker.md` shards.

These tests pin the codex-scoped, non-halting fix:
  1. depth seeds blind_spot_a/b/c + validation_sweep + the manifest's
     TRIGGERED niche files, but not driver-owned confidence artifacts.
  2. recon seeds the *_worker.md shards.
  3. NON-HALTING: an EMPTY seeded blind_spot_a still FAILS the never-cut/stub
     gate (flagged stub, NOT passed) → degrade-and-continue intact.
  4. CODEX-ONLY: the Claude path never calls _precreate (seeds nothing).
  5. expected_artifacts for SC depth is UNCHANGED (still ['depth_*_findings.md']).
  6. alternation seeds exactly ONE representative.
  7. only TRIGGERED niches are seeded (not all possible).
"""

from __future__ import annotations

from pathlib import Path

import plamen_driver as D
import plamen_types as T


def _depth_phase() -> T.Phase:
    return T.Phase(
        name="depth",
        section_markers=["## Step 1"],
        expected_artifacts=["depth_*_findings.md"],
        base_timeout_s=600,
        example_tokens=["token_flow", "state_trace", "edge_case", "external"],
    )


def _recon_phase() -> T.Phase:
    return T.Phase(
        name="recon",
        section_markers=["## Step 1"],
        expected_artifacts=["recon_summary.md"],
        base_timeout_s=600,
    )


def _write_manifest_with_niche(scratchpad: Path, *, triggered: bool) -> None:
    required_cell = "YES" if triggered else "NO"
    scratchpad.joinpath("spawn_manifest.md").write_text(
        "# Spawn Manifest\n\n"
        "## Niche Agents\n\n"
        "| Niche Agent | Trigger | Required | Agent ID | Output |\n"
        "|---|---|---|---|---|\n"
        f"| EVENT_COMPLETENESS | MISSING_EVENT | {required_cell} | niche-evt | "
        "niche_event_completeness_findings.md |\n"
        "| SIGNATURE_VERIFICATION_AUDIT | HAS_SIGNATURES | NO | niche-sig | "
        "niche_signature_verification_audit_findings.md |\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1. depth seeds the secondary never-cut artifacts + triggered niche files
# ---------------------------------------------------------------------------

def test_depth_seeds_model_secondaries_but_not_driver_confidence(tmp_path):
    scratchpad = tmp_path
    _write_manifest_with_niche(scratchpad, triggered=True)

    D._precreate_codex_artifacts(
        _depth_phase(), scratchpad, {"mode": "core", "pipeline": "sc"}
    )

    # Core depth glob seeds the 4 example_tokens.
    for token in ("token_flow", "state_trace", "edge_case", "external"):
        assert (scratchpad / f"depth_{token}_findings.md").exists()

    # Secondary never-cut artifacts now seeded.
    for name in (
        "blind_spot_a_findings.md",
        "blind_spot_b_findings.md",
        "blind_spot_c_findings.md",
        "validation_sweep_findings.md",
    ):
        seeded = scratchpad / name
        assert seeded.exists(), f"{name} should be pre-seeded"
        assert seeded.read_text(encoding="utf-8") == "", f"{name} seeded empty"
    assert not (scratchpad / "confidence_scores.md").exists()
    assert not (scratchpad / "confidence_consensus_authority.json").exists()
    assert not (scratchpad / "consensus_map.md").exists()

    # Triggered niche output seeded; untriggered one NOT seeded.
    assert (scratchpad / "niche_event_completeness_findings.md").exists()
    assert not (
        scratchpad / "niche_signature_verification_audit_findings.md"
    ).exists()


# ---------------------------------------------------------------------------
# 2. recon seeds the *_worker.md shards
# ---------------------------------------------------------------------------

def test_recon_seeds_worker_shards(tmp_path):
    scratchpad = tmp_path
    D._precreate_codex_artifacts(
        _recon_phase(), scratchpad, {"mode": "core", "pipeline": "sc"}
    )
    for shard in (
        "recon_build_static.md",
        "recon_design_context.md",
        "recon_inventory_surface.md",
        "recon_templates_patterns.md",
    ):
        assert (scratchpad / shard).exists(), f"{shard} should be pre-seeded"

    # Light mode seeds only the two broader shards.
    light_scratch = tmp_path / "light"
    light_scratch.mkdir()
    D._precreate_codex_artifacts(
        _recon_phase(), light_scratch, {"mode": "light", "pipeline": "sc"}
    )
    assert (light_scratch / "recon_build_static.md").exists()
    assert (light_scratch / "recon_inventory_surface.md").exists()
    assert not (light_scratch / "recon_design_context.md").exists()


# ---------------------------------------------------------------------------
# 3. NON-HALTING: an empty seeded blind_spot_a still fails the never-cut gate
# ---------------------------------------------------------------------------

def test_empty_seeded_blindspot_still_fails_stub_gate(tmp_path):
    import plamen_validators as V

    scratchpad = tmp_path
    _write_manifest_with_niche(scratchpad, triggered=False)
    D._precreate_codex_artifacts(
        _depth_phase(), scratchpad, {"mode": "core", "pipeline": "sc"}
    )

    # The empty blind_spot_a seed exists...
    assert (scratchpad / "blind_spot_a_findings.md").exists()

    # ...but the substance validator still reports it as a stub, so the
    # never-cut gate treats the group as unsatisfied (degrade-and-continue).
    stubs = V._validate_depth_artifact_substance(scratchpad, "core", pipeline="sc")
    joined = "; ".join(stubs)
    # The load-bearing guarantee: the blind-spot scanner groups (and the core
    # depth findings + validation sweep) are flagged when only an empty seed is
    # present, so the never-cut gate treats them as unsatisfied → degrade, not
    # a false pass.
    for required in (
        "blind_spot_a_findings.md",
        "blind_spot_b_findings.md",
        "blind_spot_c_findings.md",
        "validation_sweep_findings.md",
    ):
        assert required in joined, (
            f"empty {required} must be flagged as stub (no false-pass), got: {stubs}"
        )

    # _depth_artifact_is_stub flags the 0-byte scanner seed directly.
    reason = V._depth_artifact_is_stub(scratchpad / "blind_spot_a_findings.md")
    assert reason is not None, "0-byte seed must be a stub, never a false-pass"

    # And the existence-only never-cut assert still treats the group as present
    # (so the existing two-stage gate, not this fix, owns the stub rejection).
    # The substance validator above is what blocks the false-pass.


# ---------------------------------------------------------------------------
# 4. CODEX-ONLY: Claude path never invokes precreate
# ---------------------------------------------------------------------------

def test_precreate_call_is_codex_only(tmp_path):
    """The only call site for _precreate_codex_artifacts is inside the codex
    backend branch. The Claude worker-pool path creates its own files."""
    src = Path(__file__).resolve().parent.joinpath("plamen_driver.py").read_text(
        encoding="utf-8"
    )
    # Exactly one call site (the definition + the call; grep the call form).
    call_count = src.count("_precreate_codex_artifacts(phase, scratchpad")
    assert call_count == 1, f"expected exactly one call site, found {call_count}"

    # That call must live after the `if backend == \"codex\":` guard and before
    # the claude PTY branch. After the codex depth fan-out refactor the codex
    # branch returns early (delegating execution to _run_one_codex_exec), so
    # the following claude branch marker is `if is_claude_pty:` (was `elif`).
    # The precreate call must still sit inside the codex branch only.
    codex_guard = src.index('if backend == "codex":')
    call_idx = src.index("_precreate_codex_artifacts(phase, scratchpad")
    if_claude = src.index("if is_claude_pty:", codex_guard)
    assert codex_guard < call_idx < if_claude, (
        "precreate call must be inside the codex backend branch only"
    )


# ---------------------------------------------------------------------------
# 5. expected_artifacts for SC depth is UNCHANGED
# ---------------------------------------------------------------------------

def test_sc_depth_expected_artifacts_unchanged():
    # The shared never-cut gate keys off Phase.expected_artifacts for BOTH
    # backends — the fix must NOT touch it. SC depth must stay the core glob.
    depth = next(p for p in T.SC_PHASES if p.name == "depth")
    assert depth.expected_artifacts == ["depth_*_findings.md"], (
        f"SC depth expected_artifacts changed: {depth.expected_artifacts}"
    )
    assert depth.example_tokens == [
        "token_flow", "state_trace", "edge_case", "external",
    ], "SC depth example_tokens must not be mutated by the fix"


# ---------------------------------------------------------------------------
# 6. alternation seeds exactly ONE representative
# ---------------------------------------------------------------------------

def test_alternation_seeds_one_representative(tmp_path):
    scratchpad = tmp_path
    D._precreate_codex_artifacts(
        _depth_phase(), scratchpad, {"mode": "core", "pipeline": "sc"}
    )
    # The validation-sweep group is ['validation_sweep_findings.md',
    # 'scanner_validation_findings.md']; only the first representative is seeded.
    assert (scratchpad / "validation_sweep_findings.md").exists()
    assert not (scratchpad / "scanner_validation_findings.md").exists(), (
        "alternation must seed exactly one representative (the first)"
    )


def test_thorough_alternation_seeds_first_only(tmp_path):
    scratchpad = tmp_path
    D._precreate_codex_artifacts(
        _depth_phase(), scratchpad, {"mode": "thorough", "pipeline": "sc"}
    )
    # Thorough adds [design_stress|depth_design_stress], etc. — first only.
    assert (scratchpad / "design_stress_findings.md").exists()
    assert not (scratchpad / "depth_design_stress_findings.md").exists()
    assert (scratchpad / "perturbation_findings.md").exists()
    assert not (scratchpad / "depth_perturbation_findings.md").exists()


# ---------------------------------------------------------------------------
# 7. only TRIGGERED niches seeded (not all possible)
# ---------------------------------------------------------------------------

def test_only_triggered_niches_seeded(tmp_path):
    scratchpad = tmp_path
    _write_manifest_with_niche(scratchpad, triggered=False)
    D._precreate_codex_artifacts(
        _depth_phase(), scratchpad, {"mode": "core", "pipeline": "sc"}
    )
    # Neither niche is required → neither seeded.
    assert not (scratchpad / "niche_event_completeness_findings.md").exists()
    assert not (
        scratchpad / "niche_signature_verification_audit_findings.md"
    ).exists()


def test_no_manifest_seeds_no_niches(tmp_path):
    scratchpad = tmp_path  # no spawn_manifest.md present
    D._precreate_codex_artifacts(
        _depth_phase(), scratchpad, {"mode": "core", "pipeline": "sc"}
    )
    # Core never-cut secondaries still seeded; no niche files created.
    assert (scratchpad / "blind_spot_a_findings.md").exists()
    assert not list(scratchpad.glob("niche_*_findings.md"))


# ---------------------------------------------------------------------------
# Directive (part B) parity: the fill directive names the same files
# ---------------------------------------------------------------------------

def test_fill_directive_lists_seeded_files(tmp_path):
    scratchpad = tmp_path
    _write_manifest_with_niche(scratchpad, triggered=True)
    directive = D._codex_precreated_fill_directive("depth", "sc", "core", scratchpad)
    assert "PRE-CREATED SECONDARY ARTIFACTS" in directive
    for name in (
        "blind_spot_a_findings.md",
        "validation_sweep_findings.md",
        "niche_event_completeness_findings.md",
    ):
        assert name in directive, f"directive must name {name}"
    # First-representative alternation only.
    assert "scanner_validation_findings.md" not in directive
    assert "confidence_scores.md" not in directive
    assert "confidence_consensus_authority.json" not in directive
    assert "consensus_map.md" not in directive


def test_fill_directive_recon_lists_shards():
    directive = D._codex_precreated_fill_directive("recon", "sc", "core", None)
    for shard in (
        "recon_build_static.md",
        "recon_design_context.md",
        "recon_inventory_surface.md",
        "recon_templates_patterns.md",
    ):
        assert shard in directive

    # Non-depth/recon phase yields no directive.
    assert D._codex_precreated_fill_directive("verify", "sc", "core", None) == ""


def test_l1_depth_seeds_l1_never_cut(tmp_path):
    scratchpad = tmp_path
    phase = T.Phase(
        name="depth",
        section_markers=["## Step 1"],
        expected_artifacts=["depth_*_findings.md"],
        base_timeout_s=600,
        example_tokens=["consensus_invariant", "network_surface"],
    )
    D._precreate_codex_artifacts(
        phase, scratchpad, {"mode": "core", "pipeline": "l1"}
    )
    # L1 base set + core extra.
    assert (scratchpad / "depth_consensus_invariant_findings.md").exists()
    assert (scratchpad / "depth_network_surface_findings.md").exists()
    assert not (scratchpad / "confidence_scores.md").exists()
    # L1-4: L1 now has its own scanner floor (mirrors SC's blind-spot A/B/C +
    # validation sweep) as of the L1 rigor buildout, so these ARE seeded under
    # L1 core too -- Codex needs a target file to apply_patch into.
    assert (scratchpad / "blind_spot_a_findings.md").exists()
    assert (scratchpad / "blind_spot_b_findings.md").exists()
    assert (scratchpad / "blind_spot_c_findings.md").exists()
    assert (scratchpad / "validation_sweep_findings.md").exists()
