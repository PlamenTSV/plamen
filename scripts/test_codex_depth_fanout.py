"""Codex depth fan-out parity tests.

Context (a live SC Thorough Codex run): for backend==codex the depth
phase ran as ONE `codex exec` that had to produce ~15 artifacts. Codex's
single turn under-fanned-out — it produced the 4 core role findings +
blind_spot_a, then ran out and left blind_spot_b/c, validation_sweep,
design_stress, perturbation, skill_execution_checklist as 0-byte STUBS and the
semantic-gap niche MISSING. The depth never-cut gate correctly HALTED (those
scanners caught 6/7 misses in the v1.1.5 post-mortem — NOT optional).

The fix: when backend=="codex" AND phase.name=="depth", run ONE `codex exec`
per depth JOB (the same deterministic plan the proven Claude PTY worker pool
fans into), so every never-cut artifact actually gets produced. ADDITIVE — the
Claude PTY worker-pool path and the Claude / Codex single-subprocess paths must
be behavior-unchanged.

These tests pin:
  (a) _should_use_depth_codex_fanout gating;
  (b) _run_depth_codex_fanout iterates ALL _depth_worker_jobs (reproducing-then-
      fixing the halt: every never-cut artifact incl. blind_spot_b/c,
      validation_sweep, design_stress, perturbation, skill_execution_checklist,
      and the triggered niche is produced non-stub);
  (c) resume-safe (already-complete jobs are skipped);
  (d) source-grep that the is_claude_pty depth worker-pool branch + the
      single-subprocess codex path remain intact (additive, behavior-preserved).
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


def _base_config(scratchpad: Path, *, backend: str, mode: str,
                 pipeline: str = "sc") -> dict:
    # The production phase loop materializes these immutable upstream inputs
    # before dispatching the lower-level fan-out helper.  This unit test calls
    # that helper directly, so its fixture must represent the same boundary.
    scratchpad.joinpath("findings_inventory.md").write_text(
        "# Findings Inventory\n\nNo prior candidates.\n", encoding="utf-8"
    )
    scratchpad.joinpath("semantic_invariants.md").write_text(
        "# Semantic Invariants\n\nNo invariant candidates.\n", encoding="utf-8"
    )
    scratchpad.joinpath("security_feature_facts.json").write_text(
        '{"schema":"fixture.security-feature-facts.v1","facts":[]}\n',
        encoding="utf-8",
    )
    scratchpad.joinpath("security_obligation_authority.json").write_text(
        '{"schema":"fixture.security-obligations.v1","obligations":[]}\n',
        encoding="utf-8",
    )
    scratchpad.joinpath("security_obligations.md").write_text(
        "# Security Obligations\n\nNo obligations.\n", encoding="utf-8"
    )
    if mode == "thorough":
        scratchpad.joinpath(
            "semantic_invariant_final_byte_authority.json"
        ).write_text(
            '{"schema":"fixture.semantic-final-byte.v1"}\n',
            encoding="utf-8",
        )
    return {
        "cli_backend": backend,
        "mode": mode,
        "pipeline": pipeline,
        "language": "evm",
        "scratchpad": str(scratchpad),
        "project_root": str(scratchpad),
        "_run_id": "RUN-CODEX-FANOUT-TEST",
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }


def _write_manifest_with_triggered_niche(scratchpad: Path) -> None:
    """Manifest with one TRIGGERED niche so _depth_worker_jobs yields it."""
    scratchpad.joinpath("spawn_manifest.md").write_text(
        "# Spawn Manifest\n\n"
        "## Niche Agents\n\n"
        "| Niche Agent | Trigger | Required | Agent ID | Output |\n"
        "|---|---|---|---|---|\n"
        "| EVENT_COMPLETENESS | MISSING_EVENT | YES | niche-evt | "
        "niche_event_completeness_findings.md |\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# (a) gating
# ---------------------------------------------------------------------------

def test_gating_codex_depth_thorough_true(tmp_path):
    cfg = _base_config(tmp_path, backend="codex", mode="thorough")
    # Thorough SC depth always yields >1 job.
    assert D._should_use_depth_codex_fanout(cfg, tmp_path) is True


def test_gating_codex_depth_core_true(tmp_path):
    cfg = _base_config(tmp_path, backend="codex", mode="core")
    # Core SC depth = 4 standard + 4 side jobs => >1 job.
    assert D._should_use_depth_codex_fanout(cfg, tmp_path) is True


def test_gating_claude_headless_backend_true(tmp_path):
    cfg = _base_config(tmp_path, backend="claude", mode="thorough")
    assert D._should_use_depth_codex_fanout(cfg, tmp_path) is True


def test_gating_claude_pty_backend_false(tmp_path):
    cfg = _base_config(tmp_path, backend="claude", mode="thorough")
    cfg["claude_exec_mode"] = "pty"
    assert D._should_use_depth_codex_fanout(cfg, tmp_path) is False


def test_gating_codex_l1_thorough_true(tmp_path):
    cfg = _base_config(tmp_path, backend="codex", mode="thorough", pipeline="l1")
    assert D._should_use_depth_codex_fanout(cfg, tmp_path) is True


# Non-depth is gated at the call-site (run_phase checks phase.name == "depth"
# before invoking _should_use_depth_codex_fanout). The helper itself only
# decides codex + real-fan-out; we assert the call-site guard via source-grep
# below in test_source_wiring_is_additive.


# ---------------------------------------------------------------------------
# (b) _run_depth_codex_fanout iterates ALL jobs -> every never-cut artifact
#     is produced non-stub. This reproduces-then-fixes the halt.
# ---------------------------------------------------------------------------

_SUBSTANTIVE = (
    "<!-- PLAMEN_STATUS: COMPLETE -->\n\n"
    "## Finding [X-1]: placeholder\n\n"
    + ("Detailed analysis body. " * 60)
    + "\n"
)


def _install_fanout_fakes(monkeypatch, *, produced: list[str],
                          fail_outputs: set[str] | None = None,
                          stub_once: set[str] | None = None):
    """Monkeypatch the fan-out collaborators.

    - _build_depth_worker_prompt / _translate_prompt_for_codex: cheap stubs.
    - _run_one_codex_exec: writes substantive content into each job output
      (the real driver lets the codex subprocess do this).
    - _depth_worker_output_complete: simple size-based check so the test does
      not depend on the standard-job status machinery.
    - _synthesize_depth_lifecycle_artifacts: no-op (records that it ran once).
    """
    fail_outputs = fail_outputs or set()
    stub_once = dict.fromkeys(stub_once or set(), True)
    synth_calls = {"n": 0}

    monkeypatch.setattr(
        D, "_build_depth_worker_prompt",
        lambda **kw: f"PROMPT::{kw['job']['output']}",
    )
    monkeypatch.setattr(
        D, "_translate_prompt_for_codex",
        lambda prompt, **kw: prompt,
    )

    def _fake_exec(*, prompt, phase, config, scratchpad, attempt, label,
                   expected_outputs, timeout, effective_model, **_runtime):
        produced.append(label)
        for out in expected_outputs:
            if out in fail_outputs:
                return D.EXIT_ERROR
            # First attempt leaves a stub for stub_once outputs; the per-job
            # retry then fills it.
            if stub_once.get(out):
                stub_once[out] = False
                (scratchpad / out).write_text("", encoding="utf-8")
                continue
            (scratchpad / out).write_text(_SUBSTANTIVE, encoding="utf-8")
        return 0

    monkeypatch.setattr(D, "_run_one_codex_exec", _fake_exec)

    def _complete(scratchpad, phase, job, **kw):
        p = scratchpad / job["output"]
        try:
            return p.stat().st_size >= 500
        except OSError:
            return False

    monkeypatch.setattr(D, "_depth_worker_output_complete", _complete)
    # This unit isolates fan-out/retry scheduling. PhaseIO input/output
    # authority is exercised by the dedicated adversarial prelaunch suite.
    monkeypatch.setattr(
        D, "_bind_typed_model_worker_inputs", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_record_typed_model_worker_artifact", lambda **_kwargs: []
    )

    def _synth(
        scratchpad, pipeline, *, force=False, mode="core", config=None,
        phase=None,
    ):
        synth_calls["n"] += 1
        return []

    monkeypatch.setattr(D, "_synthesize_depth_lifecycle_artifacts", _synth)
    return synth_calls


def test_fanout_produces_every_nevercut_artifact_thorough(tmp_path, monkeypatch):
    _write_manifest_with_triggered_niche(tmp_path)
    cfg = _base_config(tmp_path, backend="codex", mode="thorough")
    phase = _depth_phase()

    produced: list[str] = []
    synth_calls = _install_fanout_fakes(monkeypatch, produced=produced)

    rc = D._run_depth_codex_fanout(
        phase=phase, config=cfg, scratchpad=tmp_path, attempt=1,
    )
    assert rc == 0

    jobs = D._depth_worker_jobs(tmp_path, cfg)
    expected_outputs = {str(j["output"]) for j in jobs}

    # The exact never-cut + thorough side artifacts that Codex's single mega-
    # turn dropped in the halt MUST all be present and non-stub now.
    must_exist = {
        "depth_token_flow_findings.md",
        "depth_state_trace_findings.md",
        "depth_edge_case_findings.md",
        "depth_external_findings.md",
        "blind_spot_a_findings.md",
        "blind_spot_b_findings.md",
        "blind_spot_c_findings.md",
        "validation_sweep_findings.md",
        "design_stress_findings.md",
        "perturbation_findings.md",
        "skill_execution_checklist.md",
        "niche_event_completeness_findings.md",
    }
    assert must_exist <= expected_outputs, (
        f"job plan missing expected artifacts: {must_exist - expected_outputs}"
    )
    for name in must_exist:
        p = tmp_path / name
        assert p.exists(), f"{name} should be produced by the fan-out"
        assert p.stat().st_size >= 500, f"{name} should be non-stub"

    # One `codex exec` per job — the prior failure was ONE exec for all.
    assert len(produced) == len(jobs)
    # Lifecycle synthesis runs exactly once after all jobs (mirrors PTY pool).
    assert synth_calls["n"] == 1

    # Observability contract written, same shape as the PTY pool.
    contract = tmp_path / "_depth_worker_pool_contract.json"
    assert contract.exists()
    import json
    data = json.loads(contract.read_text(encoding="utf-8"))
    assert data["phase"] == "depth"
    assert set(data["outputs"]) == expected_outputs


def test_fanout_retries_a_stub_job_once(tmp_path, monkeypatch):
    cfg = _base_config(tmp_path, backend="codex", mode="core")
    phase = _depth_phase()
    produced: list[str] = []
    # blind_spot_b is a stub on first attempt; the per-job retry fills it.
    _install_fanout_fakes(
        monkeypatch, produced=produced,
        stub_once={"blind_spot_b_findings.md"},
    )

    rc = D._run_depth_codex_fanout(
        phase=phase, config=cfg, scratchpad=tmp_path, attempt=1,
    )
    assert rc == 0
    p = tmp_path / "blind_spot_b_findings.md"
    assert p.exists() and p.stat().st_size >= 500
    # blind_spot_b's label appears twice (attempt + one retry).
    bsb_label = "depth_worker_blind-spot-b"
    assert produced.count(bsb_label) == 2


def test_fanout_hard_failure_propagates(tmp_path, monkeypatch):
    cfg = _base_config(tmp_path, backend="codex", mode="core")
    phase = _depth_phase()
    produced: list[str] = []
    _install_fanout_fakes(
        monkeypatch, produced=produced,
        fail_outputs={"depth_token_flow_findings.md"},
    )
    rc = D._run_depth_codex_fanout(
        phase=phase, config=cfg, scratchpad=tmp_path, attempt=1,
    )
    assert rc == D.EXIT_ERROR


# ---------------------------------------------------------------------------
# (c) resume-safe: already-complete jobs are skipped (no codex exec spent).
# ---------------------------------------------------------------------------

def test_fanout_skips_already_complete_jobs(tmp_path, monkeypatch):
    cfg = _base_config(tmp_path, backend="codex", mode="core")
    phase = _depth_phase()

    # Pre-seed two outputs as already substantive (a prior run / resume).
    pre_done = ["depth_token_flow_findings.md", "blind_spot_a_findings.md"]
    for name in pre_done:
        (tmp_path / name).write_text(_SUBSTANTIVE, encoding="utf-8")

    produced: list[str] = []
    _install_fanout_fakes(monkeypatch, produced=produced)

    rc = D._run_depth_codex_fanout(
        phase=phase, config=cfg, scratchpad=tmp_path, attempt=1,
    )
    assert rc == 0

    jobs = D._depth_worker_jobs(tmp_path, cfg)
    # The two pre-done jobs were skipped: their labels never ran.
    assert "depth_worker_depth-token-flow" not in produced
    assert "depth_worker_blind-spot-a" not in produced
    # Everything else still ran exactly once.
    assert len(produced) == len(jobs) - len(pre_done)


# ---------------------------------------------------------------------------
# (d) source-grep: additive — the Claude PTY depth worker-pool branch and the
#     single-subprocess codex path remain intact / behavior-preserved.
# ---------------------------------------------------------------------------

def _driver_source() -> str:
    return (Path(D.__file__)).read_text(encoding="utf-8")


def test_source_claude_pty_depth_branch_intact():
    src = _driver_source()
    # The is_claude_pty depth worker-pool branch must still be present.
    assert "_should_use_depth_worker_pool(config, scratchpad)" in src
    assert "_run_depth_worker_pool_pty(" in src


def test_source_single_subprocess_codex_path_intact():
    src = _driver_source()
    # The single-subprocess codex path delegates to the factored helper.
    assert "def _run_one_codex_exec(" in src
    assert "label=phase.name," in src
    # Both codex command builders remain in use (skip-model fallback intact).
    assert "_build_codex_cmd(" in src
    assert "_build_codex_cmd_no_model(" in src


def test_source_wiring_is_additive():
    src = _driver_source()
    # The new fan-out branch is gated on backend==codex AND phase==depth AND
    # the helper — wired BEFORE the single-subprocess codex translate.
    assert 'phase.name == "depth"' in src
    assert "_should_use_depth_codex_fanout(config, scratchpad)" in src
    assert "_run_depth_codex_fanout(" in src
    # The fan-out wiring precedes the single-subprocess codex translate call.
    fanout_idx = src.index("return _run_depth_codex_fanout(")
    translate_idx = src.index(
        "prompt = _translate_prompt_for_codex(\n            prompt, phase_name=phase.name,"
    )
    assert fanout_idx < translate_idx


# ── Codex robustness fixes (context-window / spawn_agent / no perma-fail) ──

def test_codex_robustness_overrides_present():
    ov = D._codex_robustness_overrides()
    s = " ".join(ov)
    assert "model_auto_compact_token_limit=220000" in s
    assert 'service_tier="flex"' in s
    # The #16068 trigger must NEVER be set (causes bogus context-exceeded).
    assert "model_context_window" not in s


def test_build_codex_cmd_includes_robustness_overrides():
    cmd = D._build_codex_cmd("gpt-5.4")
    j = " ".join(cmd)
    assert "model_auto_compact_token_limit=220000" in j
    assert 'service_tier="flex"' in j
    assert "model_context_window" not in j


def test_build_codex_cmd_no_model_includes_robustness_overrides():
    cmd = D._build_codex_cmd_no_model()
    j = " ".join(cmd)
    assert "model_auto_compact_token_limit=220000" in j
    assert 'service_tier="flex"' in j


def test_codex_config_generator_no_context_window_landmine():
    import inspect
    import codex_adapter
    src = inspect.getsource(codex_adapter.generate_config_toml)
    # The #16068 landmine assignment is gone; replaced by auto-compact + flex tier.
    assert "model_context_window = 272000" not in src
    assert 'model = "gpt-5.3-codex"' not in src   # ChatGPT-auth-rejected default removed
    assert "model_auto_compact_token_limit" in src
    assert 'service_tier = "flex"' in src
    assert 'model = "gpt-5.6-terra"' in src


def test_codex_context_exceeded_degrades_not_perma_fail():
    """The codex context-window handler must DEGRADE the phase and continue
    (no perma-fail), not sys.exit(EXIT_ERROR)."""
    import inspect
    src = inspect.getsource(D.run_pipeline) if hasattr(D, "run_pipeline") else inspect.getsource(D)
    assert "CODEX-CONTEXT-EXCEEDED" in src
    assert "no perma-fail" in src
