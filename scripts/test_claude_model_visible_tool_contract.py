from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import claude_phase_tool_policy as P
import headless_worker_runtime as H
import plamen_driver as D
from phase_contract_compiler import extract_compiled_phase_io
from test_headless_driver_cutover_p0_am import (
    _armed_inventory_model,
    _install_offline_driver_provider,
)


def _policy_fixture(tmp_path: Path):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "src"
    methodology = tmp_path / "methodology"
    receipts = scratchpad / "private-receipts"
    for path in (scratchpad, source, methodology, receipts):
        path.mkdir(parents=True, exist_ok=True)
    phase_input = scratchpad / "phase_input.md"
    phase_input.write_text("bound input\n", encoding="utf-8")
    prompt_snapshot = scratchpad / "_prompt_private.md"
    prompt_snapshot.write_text("private prompt\n", encoding="utf-8")
    forbidden = scratchpad / "forbidden.md"
    forbidden.write_text("private forbidden\n", encoding="utf-8")
    policy = P.build_policy_manifest(
        run_id="private-run-id",
        phase="recon",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(methodology,),
        exact_read_files=(phase_input, prompt_snapshot),
        exact_write_files=(scratchpad / "output.md",),
        forbidden_read_files=(forbidden,),
        receipt_directory=receipts,
    )
    return project, scratchpad, source, phase_input, prompt_snapshot, policy


def test_projection_is_deterministic_relative_and_private(tmp_path: Path):
    project, _scratchpad, _source, phase_input, snapshot, policy = (
        _policy_fixture(tmp_path)
    )
    first = P.build_model_visible_projection(
        policy,
        phase_io_input_paths=(phase_input,),
        private_exact_read_paths=(snapshot,),
    )
    second = P.build_model_visible_projection(
        policy,
        phase_io_input_paths=(phase_input,),
        private_exact_read_paths=(snapshot,),
    )
    assert first == second == {
        "schema_version": P.MODEL_VISIBLE_PROJECTION_SCHEMA,
        "safe_search_roots": ["src"],
        "exact_input_paths": [".scratchpad/phase_input.md"],
    }
    rendered = P.render_model_visible_supervisor_block(first)
    assert rendered == P.render_model_visible_supervisor_block(second)
    assert project.as_posix() not in rendered
    assert snapshot.name not in rendered
    assert policy["policy_id"] not in rendered
    assert policy["manifest_digest"] not in rendered
    assert "private-receipts" not in rendered
    assert "methodology" not in rendered
    assert "forbidden.md" not in rendered
    assert "Every Glob or Grep call MUST set `path` explicitly" in rendered
    assert "one exact PhaseIO input file listed above" in rendered
    assert "revalidates\n  its bound byte length and SHA-256" in rendered
    assert "Never call Glob/Grep with `path: \".\"`" in rendered
    assert "`foundry.toml` is not permission to probe" in rendered
    assert "Never use Read for existence" in rendered
    assert "Any tool-policy DENY invalidates this attempt" in rendered
    assert "Restricted Claude exposes no shell/execution tool" in rendered


def test_projection_requires_exact_written_read_denominator(tmp_path: Path):
    _project, _scratchpad, _source, phase_input, _snapshot, policy = (
        _policy_fixture(tmp_path)
    )
    with pytest.raises(P.ClaudePhaseToolPolicyError, match="denominator"):
        P.build_model_visible_projection(
            policy,
            phase_io_input_paths=(phase_input,),
        )


def test_projection_accepts_ordinary_unicode_and_spaces(tmp_path: Path):
    project = tmp_path / "project"
    source = project / "src résumé Δ"
    scratchpad = project / ".scratchpad"
    receipts = scratchpad / "receipts"
    methodology = tmp_path / "methodology"
    for path in (source, receipts, methodology):
        path.mkdir(parents=True, exist_ok=True)
    exact_input = scratchpad / "résumé Δ input.md"
    exact_input.write_text("input\n", encoding="utf-8")
    policy = P.build_policy_manifest(
        run_id="unicode-positive",
        phase="recon",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(methodology,),
        exact_read_files=(exact_input,),
        exact_write_files=(scratchpad / "output.md",),
        forbidden_read_files=(),
        receipt_directory=receipts,
    )
    projection = P.build_model_visible_projection(
        policy,
        phase_io_input_paths=(exact_input,),
    )
    assert projection["safe_search_roots"] == ["src résumé Δ"]
    assert projection["exact_input_paths"] == [
        ".scratchpad/résumé Δ input.md"
    ]


@pytest.mark.parametrize(
    "character",
    ("\u0085", "\u2028", "\u2029", "\u202e", "\u2066", "\udcff"),
)
@pytest.mark.parametrize("field", ("safe_search_roots", "exact_input_paths"))
def test_projection_rejects_unicode_control_separator_and_bidi_in_every_path_field(
    character: str,
    field: str,
):
    payload = {
        "schema_version": P.MODEL_VISIBLE_PROJECTION_SCHEMA,
        "safe_search_roots": ["src"],
        "exact_input_paths": [".scratchpad/input.md"],
    }
    payload[field] = [f"ordinary name{character}injected"]
    with pytest.raises(P.ClaudePhaseToolPolicyError, match="invalid path text"):
        P.validate_model_visible_projection(payload)


@pytest.mark.parametrize("invalid", ([1], [{"unhashable": True}]))
def test_projection_rejects_non_string_rows_without_raw_type_error(invalid):
    payload = {
        "schema_version": P.MODEL_VISIBLE_PROJECTION_SCHEMA,
        "safe_search_roots": invalid,
        "exact_input_paths": [".scratchpad/input.md"],
    }
    with pytest.raises(P.ClaudePhaseToolPolicyError, match="not canonical"):
        P.validate_model_visible_projection(payload)


def test_filesystem_root_admission_accepts_spaces_and_ordinary_unicode(
    tmp_path: Path,
):
    project = tmp_path / "project résumé Δ"
    D._admit_model_prompt_filesystem_roots({
        "project_root": str(project),
        "scratchpad": str(project / ".scratchpad with space"),
    })


@pytest.mark.parametrize("pipeline", ("sc", "l1"))
@pytest.mark.parametrize("character", ("`", "\u2028", "\udcff"))
def test_recon_prompt_rejects_hostile_project_root_before_compilation(
    tmp_path: Path,
    pipeline: str,
    character: str,
):
    safe_project = tmp_path / "project"
    config = {
        "pipeline": pipeline,
        "mode": "thorough",
        "language": "rust" if pipeline == "l1" else "evm",
        "cli_backend": "claude",
        "project_root": f"{safe_project}{character}injected",
        "scratchpad": str(safe_project / ".scratchpad"),
        "_run_id": "hostile-root",
    }
    job = {
        "agent_id": "R1",
        "role": "l1_threat_fork" if pipeline == "l1" else "build_static",
        "output": "recon_hostile.md",
        "focus": "bounded evidence",
    }
    with pytest.raises(ValueError, match="prompt-unsafe path component"):
        D._build_recon_worker_prompt(
            job=job,
            scratchpad=Path(config["scratchpad"]),
            project_root=str(config["project_root"]),
            config=config,
            attempt=1,
        )


@pytest.mark.parametrize("character", ("`", "\u2028", "\udcff"))
def test_route_prompt_rejects_hostile_attempt_relative_path(character: str):
    with pytest.raises(H.HeadlessWorkerRuntimeError, match="safely renderable"):
        H._route_prompt(
            "bounded prompt",
            output_directory=(
                Path(".scratchpad")
                / ".worker_transactions"
                / f"attempt{character}injected"
            ),
            output_paths=("recon.md",),
        )


def test_route_prompt_renders_exact_read_only_input_routes():
    rendered = H._route_prompt(
        "bounded prompt",
        output_directory=Path(".scratchpad/.worker_transactions/attempt/output"),
        output_paths=("recon.md",),
        input_routes=(
            (
                "scratchpad:external_dependency_obligations.json",
                Path(".scratchpad/external_dependency_obligations.json"),
            ),
            ("project:contracts/Unit.sol", Path("contracts/Unit.sol")),
        ),
    ).decode("utf-8")

    assert rendered.count("## Runtime input routing") == 1
    assert "frozen, read-only inputs" in rendered
    assert (
        "`scratchpad:external_dependency_obligations.json` -> "
        "`.scratchpad/external_dependency_obligations.json`"
    ) in rendered
    assert (
        "`project:contracts/Unit.sol` -> `contracts/Unit.sol`"
    ) in rendered
    assert rendered.index("## Runtime input routing") < rendered.index(
        "## Runtime output routing"
    )


def test_route_prompt_renders_authenticated_inline_input_before_output_route():
    payload = b'{"obligations":[{"id":"EXT-1","behavior":"```"}]}\n'
    rendered = H._route_prompt(
        "bounded prompt",
        output_directory=Path(".scratchpad/.worker_transactions/attempt/output"),
        output_paths=("research.md",),
        input_routes=((
            "scratchpad:external_dependency_obligations.json",
            Path(".scratchpad/external_dependency_obligations.json"),
        ),),
        inline_inputs=((
            "scratchpad:external_dependency_obligations.json",
            payload,
        ),),
    ).decode("utf-8")

    assert rendered.count("## Runtime inlined PhaseIO inputs") == 1
    assert "exact authenticated input bytes" in rendered
    assert "do not claim that a read tool is unavailable" in rendered
    assert payload.decode("utf-8").strip() in rendered
    assert "````text" in rendered
    assert rendered.index("## Runtime inlined PhaseIO inputs") < rendered.index(
        "## Runtime output routing"
    )


def _make_directory_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except OSError as exc:
        if os.name != "nt":
            pytest.skip(f"directory symlink unavailable: {exc}")
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        pytest.skip(f"directory junction unavailable: {completed.stderr}")


def test_safe_search_roots_exclude_symlink_or_junction_escape(tmp_path: Path):
    project, _scratchpad, source, phase_input, snapshot, policy = (
        _policy_fixture(tmp_path)
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    link = project / "escaped"
    _make_directory_link(link, outside)
    try:
        rebuilt = P.build_policy_manifest(
            run_id="escape-test",
            phase="recon",
            attempt=1,
            expected_cwd=project,
            project_root=project,
            scratchpad_root=project / ".scratchpad",
            methodology_read_roots=(tmp_path / "methodology",),
            exact_read_files=(phase_input, snapshot),
            exact_write_files=(project / ".scratchpad" / "output.md",),
            forbidden_read_files=(),
            receipt_directory=project / ".scratchpad" / "private-receipts",
        )
        assert rebuilt["safe_search_roots"] == [source.resolve().as_posix()]
        assert outside.resolve().as_posix() not in rebuilt["safe_search_roots"]
        projection = P.build_model_visible_projection(
            rebuilt,
            phase_io_input_paths=(phase_input,),
            private_exact_read_paths=(snapshot,),
        )
        assert projection["safe_search_roots"] == ["src"]
    finally:
        if link.exists():
            if os.name == "nt" and getattr(link, "is_junction", lambda: False)():
                link.rmdir()
            else:
                link.unlink()


def test_project_root_and_omitted_search_stay_denied_with_external_scratchpad(
    tmp_path: Path,
):
    project = tmp_path / "project"
    source = project / "src"
    scratchpad = tmp_path / "external-scratchpad"
    receipts = scratchpad / "receipts"
    methodology = tmp_path / "methodology"
    for path in (source, receipts, methodology):
        path.mkdir(parents=True, exist_ok=True)
    exact_input = scratchpad / "input.md"
    exact_input.write_text("input\n", encoding="utf-8")
    policy = P.build_policy_manifest(
        run_id="external-scratch",
        phase="recon",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(methodology,),
        exact_read_files=(exact_input,),
        exact_write_files=(scratchpad / "output.md",),
        forbidden_read_files=(),
        receipt_directory=receipts,
    )
    assert policy["safe_search_roots"] == [source.resolve().as_posix()]
    root_search = P.evaluate_tool_call(
        tool_name="Glob",
        tool_input={"path": str(project), "pattern": "**/*"},
        cwd=project,
        policy=policy,
    )
    omitted_search = P.evaluate_tool_call(
        tool_name="Grep",
        tool_input={"pattern": "contract"},
        cwd=project,
        policy=policy,
    )
    assert root_search["reason_code"] == "UNSAFE_SEARCH_ROOT"
    assert omitted_search["reason_code"] == "PATH_TEXT_INVALID"


def test_live_foundry_root_glob_shape_stays_denied_and_is_prompt_forbidden(
    tmp_path: Path,
):
    project, _scratchpad, _source, phase_input, snapshot, policy = (
        _policy_fixture(tmp_path)
    )
    decision = P.evaluate_tool_call(
        tool_name="Glob",
        tool_input={"pattern": "foundry.toml", "path": "."},
        cwd=project,
        policy=policy,
    )
    assert decision == {
        "decision": "DENY",
        "reason_code": "UNSAFE_SEARCH_ROOT",
        "target": project.resolve().as_posix(),
    }

    projection = P.build_model_visible_projection(
        policy,
        phase_io_input_paths=(phase_input,),
        private_exact_read_paths=(snapshot,),
    )
    rendered = P.render_model_visible_supervisor_block(projection)
    assert "`foundry.toml` is not permission to probe" in rendered
    assert "Never call Glob/Grep with `path: \".\"`" in rendered
    assert "one exact attempt-owned output path" in rendered
    assert "an exact attempt-owned output\n  after writing it" in rendered
    assert "a denial makes" in rendered and "the whole attempt unusable" in rendered


def test_recon_prompt_has_no_stale_optional_reads_or_unconditional_shell(
    tmp_path: Path,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = {
        "pipeline": "sc",
        "mode": "thorough",
        "language": "evm",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "recon-prompt-test",
    }
    prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R1",
            "role": "build_static",
            "output": "recon_build_static.md",
            "focus": "build evidence",
        },
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
    )
    assert "Driver-provided recon inputs you may read when present" not in prompt
    assert "/build_status.md`" not in prompt
    assert "/_recon_static_probe.md`" not in prompt
    assert "Use commands only when the runtime exposes an execution tool" in prompt
    assert "Restricted Claude exposes no shell/execution tool" in prompt
    assert "report `NOT_ATTEMPTED`" in prompt
    assert "Build-root discovery is driver-owned in restricted Claude" in prompt
    assert "guessed root-level manifest such as `foundry.toml`" in prompt
    assert "searching `.` or a parent with Glob/Grep/Read" in prompt
    assert "you may move one or two parents" not in prompt
    templates_prompt = D._build_recon_worker_prompt(
        job={
            "agent_id": "R4",
            "role": "templates_patterns",
            "output": "recon_templates_patterns.md",
            "focus": "risk patterns",
        },
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
    )
    assert "inventory_surface attack-surface narrative when present" not in (
        templates_prompt
    )
    assert "recon_inventory_surface.md` when present" not in templates_prompt
    assert "do not read a sibling recon shard merely because it is present" in (
        templates_prompt
    )


@pytest.mark.parametrize(
    ("role", "output"),
    (
        ("l1_build_static", "recon_l1_build_static.md"),
        ("l1_build_templates", "recon_l1_build_templates.md"),
    ),
)
def test_l1_primitive_status_read_is_positive_phaseio_bound_authority(
    tmp_path: Path,
    role: str,
    output: str,
):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    config = {
        "pipeline": "l1",
        "mode": "light" if role == "l1_build_templates" else "thorough",
        "language": "rust",
        "cli_backend": "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": "l1-positive-bound-input",
    }
    prompt = D._build_l1_recon_worker_prompt(
        job={
            "agent_id": "R3" if role == "l1_build_templates" else "R4",
            "role": role,
            "output": output,
            "focus": "build/static capability evidence",
        },
        scratchpad=scratchpad,
        project_root=str(project),
        config=config,
        attempt=1,
    )
    compiled = extract_compiled_phase_io(prompt)
    assert "Read `primitive_status.md`" in prompt or (
        "read `primitive_status.md`" in prompt
    )
    assert compiled["immutable_inputs"] == [
        "scratchpad:primitive_status.md"
    ]


def test_headless_provider_gets_supervisor_suffix_but_snapshot_stays_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _install_offline_driver_provider(monkeypatch)
    _inventory, config, contract, launch = _armed_inventory_model(
        tmp_path,
        backend="claude",
    )
    config["claude_auth_route"] = "OAUTH_TOKEN"
    phase = D.Phase(
        name="report_index",
        section_markers=["## Report Index"],
        expected_artifacts=["report_index.md"],
        base_timeout_s=30,
        model="sonnet",
        min_artifact_bytes=1,
    )
    captured: dict[str, object] = {}

    def capture(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(stdout=b"", stderr=b"")

    monkeypatch.setattr(D, "execute_headless_worker", capture)
    monkeypatch.setattr(D, "_record_phase_cost", lambda *_a, **_k: None)
    monkeypatch.setattr(D, "detect_background_orphan", lambda *_a, **_k: None)
    original = "original compiled methodology prompt\n"
    assert D._run_transactional_headless_leaf(
        backend="claude",
        prompt=original,
        phase=phase,
        config=config,
        scratchpad=tmp_path,
        attempt=1,
        label="model-visible-contract",
        expected_outputs=["report_index.md"],
        timeout=30,
        effective_model=launch.model,
        contract=contract,
        launch=launch,
        working_directory=str(tmp_path),
        analysis_directories=(str(tmp_path),),
    ) == 0
    effective = str(captured["prompt"])
    assert effective.startswith(original.rstrip() + "\n\n")
    assert "## Restricted Claude Supervisor Tool Contract" in effective
    assert captured["methodology_digests"] == (
        hashlib.sha256(original.encode("utf-8")).hexdigest(),
    )
    snapshot = tmp_path / "_prompt_model-visible-contract.attempt1.md"
    assert snapshot.read_bytes() == original.encode("utf-8")
    boundary = config["_claude_phase_tool_boundaries"][phase.name]
    for private_value in (
        boundary["policy_path"],
        boundary["settings_path"],
        boundary["receipt_directory"],
        boundary["manifest_digest"],
    ):
        assert str(private_value) not in effective
