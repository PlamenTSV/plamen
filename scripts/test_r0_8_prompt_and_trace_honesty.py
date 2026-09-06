"""R0-8a/8b: closed methodology bindings and honest embedded traces."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

import plamen_driver as D
import plamen_validators as V


def _sidecar_job(role: str) -> dict[str, str]:
    return next(
        dict(job) for job in D._DEPTH_THOROUGH_SIDE_JOBS
        if job["role"] == role
    )


def _prompt(
    tmp_path: Path,
    role: str,
    *,
    pipeline: str = "sc",
    language: str = "evm",
) -> str:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(exist_ok=True)
    return D._build_depth_worker_prompt(
        job=_sidecar_job(role),
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config={
            "language": language,
            "mode": "thorough",
            "pipeline": pipeline,
        },
        attempt=1,
    )


def test_sc_design_stress_sidecar_binds_language_dedicated_methodology(tmp_path):
    prompt = _prompt(tmp_path, "design_stress")

    assert "prompts/evm/phase4b-depth-driver.md" in prompt.replace("\\", "/")
    assert "### Design Stress Testing Agent (Thorough only)" in prompt
    assert "EXPECTED_OUTPUT: design_stress_findings.md" in prompt
    assert "Write exactly this file and no other scratchpad artifact" in prompt


def test_l1_design_stress_sidecar_binds_l1_dedicated_methodology(tmp_path):
    prompt = _prompt(
        tmp_path, "design_stress", pipeline="l1", language="rust"
    )

    assert "prompts/l1/phase4b-scanner-templates.md" in prompt.replace("\\", "/")
    assert "## Scanner: Design Stress" in prompt
    assert "EXPECTED_OUTPUT: design_stress_findings.md" in prompt


@pytest.mark.parametrize(
    ("role", "methodology_name", "output"),
    (
        (
            "perturbation",
            "prompts/shared/v2/phase4b-perturbation.md",
            "perturbation_findings.md",
        ),
        (
            "skill_execution_checklist",
            "prompts/shared/v2/phase4b-skill-checklist.md",
            "skill_execution_checklist.md",
        ),
    ),
)
def test_shared_sidecars_bind_their_dedicated_methodologies(
    tmp_path, role, methodology_name, output
):
    prompt = _prompt(tmp_path, role)

    assert methodology_name in prompt.replace("\\", "/")
    assert f"EXPECTED_OUTPUT: {output}" in prompt


def test_unknown_sidecar_role_is_rejected_instead_of_generic_fallback(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    unknown = {
        "agent_id": "unknown-sidecar",
        "role": "unknown_sidecar",
        "output": "unknown_sidecar_findings.md",
        "category": "sidecar",
        "focus": "unregistered",
    }

    with pytest.raises(ValueError, match="unregistered depth sidecar role"):
        D._build_depth_worker_prompt(
            job=unknown,
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
            attempt=1,
        )


@pytest.mark.parametrize("category", (None, "standard", "scanner", "niche"))
def test_registered_sidecar_role_forces_exact_category(tmp_path, category):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    job = _sidecar_job("perturbation")
    if category is None:
        job.pop("category")
    else:
        job["category"] = category

    with pytest.raises(ValueError, match="category mismatch"):
        D._build_depth_worker_prompt(
            job=job,
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
            attempt=1,
        )


def test_registered_sidecar_output_forces_exact_role_and_category(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    job = {
        "agent_id": "impostor",
        "role": "not_perturbation",
        "output": "perturbation_findings.md",
        "category": "standard",
        "focus": "try to evade the sidecar contract",
    }

    with pytest.raises(ValueError, match="role/output mismatch"):
        D._build_depth_worker_prompt(
            job=job,
            scratchpad=scratchpad,
            project_root=str(tmp_path),
            config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
            attempt=1,
        )


@pytest.mark.parametrize(
    ("pipeline", "language"),
    (
        ("../l1", "rust"),
        ("sc", "../evm"),
        ("smart-contract", "evm"),
        ("l1", "evm"),
        ("sc", "rust"),
    ),
)
def test_sidecar_binding_rejects_noncanonical_pipeline_language(
    tmp_path, pipeline, language
):
    with pytest.raises(ValueError, match="unsupported depth binding"):
        _prompt(
            tmp_path,
            "design_stress",
            pipeline=pipeline,
            language=language,
        )


@pytest.mark.parametrize(
    ("pipeline", "language", "anchor"),
    (
        (" SC ", " EVM ", "### Design Stress Testing Agent (Thorough only)"),
        ("sc", "solana", "### Design Stress Testing Agent (Thorough only)"),
        ("sc", "aptos", "### Design Stress Testing Agent (Thorough only)"),
        ("sc", "sui", "### Design Stress Testing Agent (Thorough only)"),
        ("sc", "soroban", "### Design Stress Testing Agent (Thorough only)"),
        ("sc", "daml", "### Design Stress Testing Agent (Thorough only)"),
        (" L1 ", " RUST ", "## Scanner: Design Stress"),
        ("l1", "go", "## Scanner: Design Stress"),
    ),
)
def test_every_supported_design_stress_binding_has_exact_existing_anchor(
    tmp_path, pipeline, language, anchor
):
    prompt = _prompt(
        tmp_path,
        "design_stress",
        pipeline=pipeline,
        language=language,
    )
    assert anchor in prompt


def test_sidecar_binding_rejects_resolved_path_outside_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("# Phase 4b Finding Perturbation Agent\n", encoding="utf-8")
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setitem(
        D._DEPTH_SIDECAR_CONTRACTS,
        "perturbation",
        {
            "output": "perturbation_findings.md",
            "methodology": "../outside.md",
            "anchor": "# Phase 4b Finding Perturbation Agent",
        },
    )

    with pytest.raises(ValueError, match="escapes Plamen home"):
        D._depth_sidecar_methodology_binding(
            _sidecar_job("perturbation"),
            {"pipeline": "sc", "language": "evm"},
        )


def test_sidecar_binding_rejects_missing_exact_heading_anchor(tmp_path, monkeypatch):
    home = tmp_path / "home"
    methodology = home / "prompts/shared/v2/phase4b-perturbation.md"
    methodology.parent.mkdir(parents=True)
    methodology.write_text(
        "# Phase 4b Finding Perturbation Agent (renamed)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(D, "plamen_home", lambda: home)

    with pytest.raises(ValueError, match="exact heading anchor"):
        D._depth_sidecar_methodology_binding(
            _sidecar_job("perturbation"),
            {"pipeline": "sc", "language": "evm"},
        )


def test_sidecar_binding_rejects_missing_methodology_file(tmp_path, monkeypatch):
    home = tmp_path / "empty-home"
    home.mkdir()
    monkeypatch.setattr(D, "plamen_home", lambda: home)

    with pytest.raises(ValueError, match="not a file"):
        D._depth_sidecar_methodology_binding(
            _sidecar_job("skill_execution_checklist"),
            {"pipeline": "sc", "language": "evm"},
        )


def test_producer_barrier_holds_perturbation_and_checklist(monkeypatch, tmp_path):
    phase = next(p for p in D.SC_PHASES if p.name == "depth")
    jobs = [
        dict(D._SC_DEPTH_STANDARD_JOBS[0]),
        dict(D._SC_DEPTH_CORE_SIDE_JOBS[0]),
        {
            "agent_id": "niche-demo",
            "role": "demo",
            "output": "niche_demo_findings.md",
            "category": "niche",
            "focus": "demo",
        },
        *_sidecar_jobs(),
    ]
    completed: set[str] = set()
    monkeypatch.setattr(
        D,
        "_depth_worker_output_complete",
        lambda _sp, _phase, job, **_kwargs: job["output"] in completed,
    )

    ready = D._depth_jobs_ready_after_producer_barrier(tmp_path, phase, jobs, jobs)
    roles = {job["role"] for job in ready}
    assert "design_stress" in roles
    assert "perturbation" not in roles
    assert "skill_execution_checklist" not in roles

    completed.update(
        job["output"]
        for job in jobs
        if job["category"] in {"standard", "scanner", "niche"}
    )
    ready = D._depth_jobs_ready_after_producer_barrier(tmp_path, phase, jobs, jobs)
    roles = {job["role"] for job in ready}
    assert {"perturbation", "skill_execution_checklist"} <= roles


def _sidecar_jobs() -> list[dict[str, str]]:
    return [dict(job) for job in D._DEPTH_THOROUGH_SIDE_JOBS]


def _write_findings(scratchpad: Path) -> None:
    source = scratchpad / "src" / "State.sol"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("\n".join(f"line {n}" for n in range(1, 81)) + "\n")
    (scratchpad / "depth_state_trace_findings.md").write_text(
        "### Finding [DST-1]: example\n"
        "**Location**: src/State.sol:L42\n"
        "[BOUNDARY:limit] checked at src/State.sol:L42\n",
        encoding="utf-8",
    )


def test_missing_agent_trace_becomes_unknown_gap_not_application_evidence(tmp_path):
    _write_findings(tmp_path)

    issues = V._check_step_execution_traces(tmp_path, "thorough")
    trace = (tmp_path / "step_execution_trace_state_trace.md").read_text(
        encoding="utf-8"
    )
    gaps = (tmp_path / "step_execution_gaps_mechanical.md").read_text(
        encoding="utf-8"
    )

    assert issues == []
    assert "| unknown |" in trace.lower()
    assert "| yes |" not in trace.lower()
    assert "BOUNDARY" not in trace
    assert "state_trace" in gaps and "unknown" in gaps.lower()


def test_invalid_agent_trace_becomes_unknown_instead_of_tag_derived_yes(tmp_path):
    _write_findings(tmp_path)
    (tmp_path / "step_execution_trace_state_trace.md").write_text(
        "| Skill | Step | Executed | Evidence | Result |\n"
        "|---|---|---|---|---|\n"
        "| state | boundary | yes | DST-1 | finding ID only |\n",
        encoding="utf-8",
    )

    V._check_step_execution_traces(tmp_path, "thorough")
    trace = (tmp_path / "step_execution_trace_state_trace.md").read_text(
        encoding="utf-8"
    )

    assert "| unknown |" in trace.lower()
    assert "| yes |" not in trace.lower()
    assert "src/State.sol:L42" not in trace


def test_embedded_trace_is_extracted_verbatim_and_digest_bound(tmp_path):
    _write_findings(tmp_path)
    findings_path = tmp_path / "depth_state_trace_findings.md"
    embedded = (
        "\n## Step Execution Trace\n\n"
        "| Skill | Step | Executed | Evidence | Result |\n"
        "|---|---|---|---|---|\n"
        "| state | boundary | yes | src/State.sol:L42 | checked |\n"
    )
    findings_path.write_text(
        findings_path.read_text(encoding="utf-8") + embedded,
        encoding="utf-8",
    )
    expected_digest = hashlib.sha256(findings_path.read_bytes()).hexdigest()

    assert V._ensure_step_execution_traces(tmp_path) == 1
    trace = (tmp_path / "step_execution_trace_state_trace.md").read_text(
        encoding="utf-8"
    )
    assert f"PLAMEN_STEP_TRACE_SOURCE_SHA256: {expected_digest}" in trace
    assert "| state | boundary | yes | src/State.sol:L42 | checked |" in trace


def test_standalone_trace_without_source_digest_becomes_unknown(tmp_path):
    _write_findings(tmp_path)
    trace_path = tmp_path / "step_execution_trace_state_trace.md"
    trace_path.write_text(
        "| Skill | Step | Executed | Evidence | Result |\n"
        "|---|---|---|---|---|\n"
        "| state | boundary | yes | src/State.sol:L42 | checked |\n",
        encoding="utf-8",
    )

    V._ensure_step_execution_traces(tmp_path)
    trace = trace_path.read_text(encoding="utf-8")
    assert "| agent-trace |" in trace
    assert "| unknown |" in trace.lower()
    assert "| yes |" not in trace.lower()
    assert "missing source digest" in trace.lower()


def test_stale_trace_digest_becomes_unknown_instead_of_rebinding(tmp_path):
    _write_findings(tmp_path)
    findings_path = tmp_path / "depth_state_trace_findings.md"
    findings_path.write_text(
        findings_path.read_text(encoding="utf-8")
        + "\n## Step Execution Trace\n\n"
        + "| Skill | Step | Executed | Evidence | Result |\n"
        + "|---|---|---|---|---|\n"
        + "| state | boundary | yes | src/State.sol:L42 | checked |\n",
        encoding="utf-8",
    )
    V._ensure_step_execution_traces(tmp_path)
    findings_path.write_text(
        findings_path.read_text(encoding="utf-8") + "\npost-trace mutation\n",
        encoding="utf-8",
    )

    V._ensure_step_execution_traces(tmp_path)
    trace = (tmp_path / "step_execution_trace_state_trace.md").read_text(
        encoding="utf-8"
    )
    assert "stale source digest" in trace.lower()
    assert "| unknown |" in trace.lower()
    assert "| yes |" not in trace.lower()


def test_forged_digest_bound_sidecar_without_embedded_table_is_unknown(tmp_path):
    _write_findings(tmp_path)
    findings_path = tmp_path / "depth_state_trace_findings.md"
    digest = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    trace_path = tmp_path / "step_execution_trace_state_trace.md"
    trace_path.write_text(
        "# Step Execution Trace: state_trace\n"
        "<!-- PLAMEN_STEP_TRACE_SOURCE_ARTIFACT: depth_state_trace_findings.md -->\n"
        f"<!-- PLAMEN_STEP_TRACE_SOURCE_SHA256: {digest} -->\n\n"
        "| Skill | Step | Executed | Evidence | Result |\n"
        "|---|---|---|---|---|\n"
        "| state | boundary | yes | src/State.sol:L42 | forged |\n",
        encoding="utf-8",
    )

    V._ensure_step_execution_traces(tmp_path)
    trace = trace_path.read_text(encoding="utf-8")
    assert "missing or malformed embedded trace" in trace
    assert "| unknown |" in trace.lower()
    assert "| yes |" not in trace.lower()


def test_digest_bound_sidecar_rows_must_match_embedded_rows_verbatim(tmp_path):
    _write_findings(tmp_path)
    findings_path = tmp_path / "depth_state_trace_findings.md"
    findings_path.write_text(
        findings_path.read_text(encoding="utf-8")
        + "\n## Step Execution Trace\n\n"
        + "| Skill | Step | Executed | Evidence | Result |\n"
        + "|---|---|---|---|---|\n"
        + "| state | boundary | no | - | not checked |\n",
        encoding="utf-8",
    )
    digest = hashlib.sha256(findings_path.read_bytes()).hexdigest()
    trace_path = tmp_path / "step_execution_trace_state_trace.md"
    trace_path.write_text(
        "# Step Execution Trace: state_trace\n"
        "<!-- PLAMEN_STEP_TRACE_SOURCE_ARTIFACT: depth_state_trace_findings.md -->\n"
        f"<!-- PLAMEN_STEP_TRACE_SOURCE_SHA256: {digest} -->\n\n"
        "| Skill | Step | Executed | Evidence | Result |\n"
        "|---|---|---|---|---|\n"
        "| state | boundary | yes | src/State.sol:L42 | changed |\n",
        encoding="utf-8",
    )

    V._ensure_step_execution_traces(tmp_path)
    trace = trace_path.read_text(encoding="utf-8")
    assert "sidecar rows differ from embedded trace" in trace
    assert "| unknown |" in trace.lower()
    assert "| yes |" not in trace.lower()


@pytest.mark.parametrize(
    "evidence",
    (
        "src/State.sol, line 42",
        "src/State.sol L42",
        "[TRACE: reached revert at L42]",
        "(general) no file applies",
        "src/Missing.sol:L42",
        "src/State.sol:L999",
    ),
)
def test_yes_evidence_rejects_non_strict_or_unresolvable_forms(tmp_path, evidence):
    _write_findings(tmp_path)
    assert not V._step_trace_evidence_has_citation(evidence, tmp_path)


def test_tag_is_accepted_only_when_it_embeds_resolvable_file_lline(tmp_path):
    _write_findings(tmp_path)
    assert V._step_trace_evidence_has_citation(
        "[TRACE: src/State.sol:L42 reached revert]", tmp_path
    )
    assert V._step_trace_evidence_has_citation(
        "[TRACE: src/State.sol:42 reached revert]", tmp_path
    )


def test_invalid_embedded_yes_is_routed_as_actionable_unknown(tmp_path):
    _write_findings(tmp_path)
    findings_path = tmp_path / "depth_state_trace_findings.md"
    findings_path.write_text(
        findings_path.read_text(encoding="utf-8")
        + "\n## Step Execution Trace\n\n"
        + "| Skill | Step | Executed | Evidence | Result |\n"
        + "|---|---|---|---|---|\n"
        + "| state | boundary | yes | [TRACE: reached L42] | checked |\n",
        encoding="utf-8",
    )

    assert V._check_step_execution_traces(tmp_path, "thorough") == []
    gaps = (tmp_path / "step_execution_gaps_mechanical.md").read_text(
        encoding="utf-8"
    )
    assert "| state_trace | state | boundary | unknown |" in gaps
    assert "rerun the original assigned methodology step" in gaps


def test_worker_prompt_requires_embedded_trace_and_one_output(tmp_path):
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    prompt = D._build_depth_worker_prompt(
        job=dict(D._SC_DEPTH_STANDARD_JOBS[1]),
        scratchpad=scratchpad,
        project_root=str(tmp_path),
        config={"language": "evm", "mode": "thorough", "pipeline": "sc"},
        attempt=1,
    )
    assert "## Step Execution Trace" in prompt
    assert "inside `depth_state_trace_findings.md`" in prompt
    assert "Do NOT write a separate `step_execution_trace_" in prompt
    assert "exact `relative/source.ext:L42`" in prompt


def test_missing_trace_gap_orders_original_methodology_rerun(tmp_path):
    _write_findings(tmp_path)
    V._check_step_execution_traces(tmp_path, "thorough")
    gaps = (tmp_path / "step_execution_gaps_mechanical.md").read_text(
        encoding="utf-8"
    )
    assert "agent-trace" in gaps
    assert "rerun the original assigned role methodology" in gaps
