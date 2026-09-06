"""Ship 8.17 (Option A) -- bounded rescan exact gating.

Rescan is a critical multi-agent phase whose completion was gated by a weak
glob/quorum (`analysis_rescan_*.md` >= 1). A partial rescan (coordinator
intended N files, only some landed) passed. Option A: the coordinator declares
its planned outputs in `rescan_manifest.md` (FIRST ACTION); when present, that
manifest is the AUTHORITATIVE exact gate. When absent, the legacy glob is
preserved so old/in-flight runs never false-fail.

Deliberately NOT in this ship: PLAMEN marker requirements, and adding rescan to
PTY_SUPERVISED_PHASES (missing-only continuation). On exact-gate failure the
existing whole-phase retry is used.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
from plamen_validators import (  # noqa: E402
    gate_passes,
    _parse_rescan_manifest_files,
    _rescan_manifest_exact_missing,
)

RESCAN = next(p for p in D.SC_PHASES if p.name == "rescan")
SUB = "# Rescan\n\n## No Findings\n\n" + ("Checked declared scope. " * 20)
FRESH_SUB = "# Rescan\n\n## No Findings\n\n" + ("Checked declared scope. " * 90)
TINY = "x" * 10


def _manifest(sp: Path, files: list[str]):
    body = "# Rescan Manifest\n" + "".join(f"- {f}\n" for f in files)
    (sp / "rescan_manifest.md").write_text(body, encoding="utf-8")


# --------------------------------------------------------------------------
# parser unit
# --------------------------------------------------------------------------

def test_parser_extracts_concrete_filenames_ignores_glob():
    text = (
        "# Rescan Manifest\n"
        "- analysis_rescan_1.md\n"
        "- analysis_rescan_2.md\n"
        "- analysis_percontract_core.md\n"
        "- analysis_percontract_scope_review.md\n"
        "(glob form analysis_rescan_*.md must NOT be matched)\n"
    )
    files = _parse_rescan_manifest_files(text)
    assert files == [
        "analysis_rescan_1.md", "analysis_rescan_2.md",
        "analysis_percontract_core.md", "analysis_percontract_scope_review.md",
    ]
    assert "analysis_rescan_*.md" not in files


# --------------------------------------------------------------------------
# exact gate cases (codex requirements)
# --------------------------------------------------------------------------

def test_manifest_present_one_declared_missing_fails(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    declared = ["analysis_rescan_1.md", "analysis_rescan_2.md",
                "analysis_percontract_core.md"]
    _manifest(sp, declared)
    (sp / "analysis_rescan_1.md").write_text(SUB, encoding="utf-8")
    (sp / "analysis_percontract_core.md").write_text(SUB, encoding="utf-8")
    # analysis_rescan_2.md NOT written
    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is False
    assert "analysis_rescan_2.md" in missing


def test_manifest_present_all_substantive_passes(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    declared = ["analysis_rescan_1.md", "analysis_rescan_2.md",
                "analysis_percontract_core.md"]
    _manifest(sp, declared)
    for f in declared:
        (sp / f).write_text(SUB, encoding="utf-8")
    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is True, missing
    assert missing == []


def test_manifest_absent_glob_fallback_preserved(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    # No rescan_manifest.md. Legacy glob: >=1 substantial file in each family.
    (sp / "analysis_rescan_1.md").write_text(SUB, encoding="utf-8")
    (sp / "analysis_percontract_core.md").write_text(SUB, encoding="utf-8")
    assert _rescan_manifest_exact_missing(sp, RESCAN) is None  # signals fallback
    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is True, missing


def test_scope_review_passes_only_when_substantive(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    declared = ["analysis_rescan_1.md", "analysis_rescan_2.md",
                "analysis_percontract_scope_review.md"]
    _manifest(sp, declared)
    (sp / "analysis_rescan_1.md").write_text(SUB, encoding="utf-8")
    (sp / "analysis_rescan_2.md").write_text(SUB, encoding="utf-8")
    # tiny scope-review -> not substantive -> fail
    (sp / "analysis_percontract_scope_review.md").write_text(TINY, encoding="utf-8")
    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is False
    assert "analysis_percontract_scope_review.md" in missing
    # now make it substantive -> pass
    (sp / "analysis_percontract_scope_review.md").write_text(SUB, encoding="utf-8")
    passed2, _ = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed2 is True


def test_partial_cannot_pass_when_manifest_exists(tmp_path):
    """Manifest declares 3; only 1 on disk. The legacy glob/quorum (>=1) would
    have passed, but the exact gate must FAIL."""
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    _manifest(sp, ["analysis_rescan_1.md", "analysis_rescan_2.md",
                   "analysis_percontract_core.md"])
    (sp / "analysis_rescan_1.md").write_text(SUB, encoding="utf-8")
    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is False
    assert "analysis_rescan_2.md" in missing
    assert "analysis_percontract_core.md" in missing


def test_unparseable_manifest_falls_back_to_glob(tmp_path):
    """A manifest that declares no concrete filenames (e.g. only the glob form)
    must NOT block -- fall back to legacy glob so it can't false-fail."""
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n- analysis_rescan_*.md\n", encoding="utf-8")
    (sp / "analysis_rescan_1.md").write_text(SUB, encoding="utf-8")
    (sp / "analysis_percontract_core.md").write_text(SUB, encoding="utf-8")
    assert _rescan_manifest_exact_missing(sp, RESCAN) is None
    passed, _ = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is True


def test_fresh_rescan_requires_parseable_manifest(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    (sp / "analysis_rescan_1.md").write_text(FRESH_SUB, encoding="utf-8")
    (sp / "analysis_percontract_core.md").write_text(FRESH_SUB, encoding="utf-8")

    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)

    assert passed is False
    assert any("rescan_manifest.md" in item for item in missing)


def test_fresh_rescan_requires_percontract_and_1kb_outputs(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _manifest(sp, ["analysis_rescan_1.md"])
    (sp / "analysis_rescan_1.md").write_text(FRESH_SUB, encoding="utf-8")

    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)

    assert passed is False
    assert any("analysis_percontract" in item for item in missing)

    _manifest(sp, ["analysis_rescan_1.md", "analysis_percontract_core.md"])
    (sp / "analysis_percontract_core.md").write_text(SUB, encoding="utf-8")
    passed2, missing2 = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed2 is False
    assert "analysis_percontract_core.md" in missing2

    (sp / "analysis_percontract_core.md").write_text(FRESH_SUB, encoding="utf-8")
    passed3, missing3 = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed3 is True, missing3


def test_rescan_declared_in_progress_marker_fails_even_above_size(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    declared = ["analysis_rescan_1.md", "analysis_percontract_core.md"]
    _manifest(sp, declared)
    body = (
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n\n"
        "## Finding [RSW-1]: substantive rescan issue\n\n"
        "**Severity**: Medium\n\n"
        + ("real analysis " * 150)
    )
    for name in declared:
        (sp / name).write_text(body, encoding="utf-8")

    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)

    assert passed is False
    assert any("PLAMEN_STATUS" in str(item) for item in missing)


def test_rescan_worker_pool_declines_invalid_manifest_shape(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    _manifest(sp, ["analysis_rescan_1.md"])

    assert D._should_use_rescan_worker_pool({"cli_backend": "claude"}, sp) is False


def test_rescan_retry_prompt_binds_retry_work_unit_identity(tmp_path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    job = {
        "agent_id": "R1",
        "focus_area": "generic fixture scope",
        "output": "analysis_rescan_1.md",
        "methodology_steps": ["STEP-1"],
    }
    prompt = D._build_rescan_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "codex",
        },
        attempt=2,
    )

    assert "/rescan/worker.r1.attempt-0002" in prompt
    assert "/rescan/worker.r1\"" not in prompt
    assert "MUST use `[RS1-<N>]`" in prompt


def test_per_contract_worker_uses_registered_pc_identity_namespace(tmp_path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "rescan_manifest.md").write_text(
        "# Rescan Manifest\n\n## Per-Contract Agents\n\n"
        "| Output |\n|---|\n| analysis_percontract_Vault.md |\n",
        encoding="utf-8",
    )
    job = {
        "agent_id": "PC4",
        "focus_area": "generic contract fixture",
        "output": "analysis_percontract_Vault.md",
        "category": "per_contract",
        "methodology_steps": ["RS-PC"],
    }
    prompt = D._build_rescan_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": "codex",
        },
        attempt=1,
    )

    assert "MUST use `[PC4-<N>]`" in prompt


@pytest.mark.parametrize(
    ("backend", "worker_name"),
    (
        ("codex", "_run_one_codex_exec"),
        ("claude-headless", "_run_one_claude_headless_breadth_worker"),
    ),
)
def test_headless_rescan_fanout_executes_every_manifest_row_transactionally(
    tmp_path,
    monkeypatch,
    backend,
    worker_name,
):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    declared = [
        "analysis_rescan_1.md",
        "analysis_percontract_core.md",
    ]
    _manifest(sp, declared)
    calls = []

    monkeypatch.setattr(
        D, "_prepare_typed_model_worker_launch", lambda **_kwargs: []
    )
    monkeypatch.setattr(
        D, "_record_typed_model_worker_artifact", lambda **_kwargs: []
    )

    def worker(**kwargs):
        output = (
            kwargs["expected_outputs"][0]
            if worker_name == "_run_one_codex_exec"
            else kwargs["job"]["output"]
        )
        calls.append(output)
        (sp / output).write_text(FRESH_SUB, encoding="utf-8")
        return 0

    monkeypatch.setattr(D, worker_name, worker)
    rc = D._run_rescan_backend_fanout(
        backend=backend,
        phase=RESCAN,
        config={
            "pipeline": "sc",
            "mode": "thorough",
            "language": "evm",
            "cli_backend": (
                "codex" if backend == "codex" else "claude"
            ),
            "project_root": str(tmp_path),
            "_run_id": "fixture-run",
        },
        scratchpad=sp,
        attempt=1,
        timeout=30,
        effective_model="fixture-model",
    )

    assert rc == 0
    assert calls == declared


def test_rescan_worker_pool_repairs_only_manifest_open_rows(tmp_path, monkeypatch):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "_audit_started_with_markers.json").write_text("{}", encoding="utf-8")
    declared = ["analysis_rescan_1.md", "analysis_rescan_2.md",
                "analysis_percontract_core.md"]
    _manifest(sp, declared)
    (sp / "analysis_rescan_1.md").write_text(FRESH_SUB, encoding="utf-8")
    calls: list[str] = []

    def _fake_worker(**kwargs):
        job = kwargs["job"]
        calls.append(job["output"])
        (sp / job["output"]).write_text(FRESH_SUB, encoding="utf-8")
        return {"output": job["output"], "rc": 0, "status": "complete"}

    monkeypatch.setattr(D, "_run_single_rescan_worker_pty", _fake_worker)

    rc = D._run_rescan_worker_pool_pty(
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"mode": "core", "language": "evm", "pipeline": "sc"},
        phase=RESCAN,
        base_cmd=["claude", "--session-id", "base"],
        env={},
        timeout=1.0,
        quiescence_s=0.0,
        attempt=2,
    )

    assert rc == 0
    assert calls == ["analysis_rescan_2.md", "analysis_percontract_core.md"]


def test_rescan_worker_prompt_is_one_artifact_allowlist(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    job = {
        "agent_id": "R1",
        "focus_area": "fresh rescan",
        "output": "analysis_rescan_1.md",
    }

    prompt = D._build_rescan_worker_prompt(
        job=job,
        scratchpad=sp,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "core", "pipeline": "sc"},
        attempt=2,
    )

    assert "EXPECTED_OUTPUT: analysis_rescan_1.md" in prompt
    assert "PLAMEN_PHASE: rescan" in prompt
    assert "phase3b-rescan.md" in prompt
    assert "do not spawn" in prompt.lower()
    assert "The sole logical output is `analysis_rescan_1.md`" in prompt
    assert "Do not write the canonical scratchpad" in prompt
    assert "final\n`Runtime output routing" in prompt
    assert "Do not proceed outside this assigned worker contract" in prompt


# --------------------------------------------------------------------------
# Item 4 (Design A): rescan_prepare writes the manifest mechanically; the
# rescan phase below stays the pure worker-pool executor. The mechanical
# manifest must satisfy this AUTHORITATIVE exact gate once workers fill it.
# --------------------------------------------------------------------------

import plamen_mechanical as M  # noqa: E402


def test_mechanical_prepare_manifest_satisfies_exact_gate(tmp_path):
    sp = tmp_path / ".scratchpad"; sp.mkdir()
    (sp / "contract_inventory.md").write_text(
        "# Contract Inventory\n\n| C | `src/ExampleVault.sol` |\n",
        encoding="utf-8",
    )
    declared = _parse_rescan_manifest_files(
        M.ensure_rescan_manifest(sp, {}).read_text(encoding="utf-8")
    )
    assert declared, "mechanical manifest must declare concrete files"
    assert any(n.startswith("analysis_percontract_") for n in declared)
    # Before workers run, every declared file is missing → gate must NOT pass.
    assert _rescan_manifest_exact_missing(sp, RESCAN) == declared
    # After the worker pool fills each declared output substantively → pass.
    for name in declared:
        (sp / name).write_text(FRESH_SUB, encoding="utf-8")
    assert _rescan_manifest_exact_missing(sp, RESCAN) == []
    passed, missing = gate_passes(sp, str(tmp_path), RESCAN)
    assert passed is True, missing


def test_rescan_phase_contract_unchanged_by_split():
    """The rescan phase stays the pure worker-pool executor; rescan_prepare is
    a separate mechanical phase. Recall: the rescan output families are intact."""
    assert RESCAN.expected_artifacts == [
        "analysis_rescan_*.md", "analysis_percontract_*.md"
    ]
    prep = next(p for p in D.SC_PHASES if p.name == "rescan_prepare")
    assert prep.expected_artifacts == ["rescan_manifest.md"]
