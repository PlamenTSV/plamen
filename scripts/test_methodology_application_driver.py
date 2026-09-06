from __future__ import annotations

import hashlib
import json
from pathlib import Path

import methodology_application as A
import plamen_driver as D
import finding_producer_registry as R


def _phase() -> D.Phase:
    return D.Phase(
        name="breadth",
        section_markers=["Phase 3"],
        expected_artifacts=["analysis_*.md"],
        base_timeout_s=60,
        min_artifact_bytes=100,
    )


def _setup(tmp_path: Path, *, missing_step: bool):
    home = tmp_path / "plamen-home"
    skill = home / "agents" / "skills" / "evm" / "oracle" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# Oracle\n\n## Step 1: inventory\n## Step 2: trace\n", encoding="utf-8")
    project = tmp_path / "project"
    source = project / "src" / "Oracle.sol"
    source.parent.mkdir(parents=True)
    source.write_text("line one\nline two\n", encoding="utf-8")
    sp = project / ".scratchpad"
    sp.mkdir()
    descriptor = {
        "skill": "ORACLE_ANALYSIS",
        "path": skill.as_posix(),
        "sha256": hashlib.sha256(skill.read_bytes()).hexdigest(),
        "top_level_checklist_step_ids": ["1", "2"],
    }
    entry = {
        "worker_id": "B1",
        "output": "analysis_oracle.md",
        "prompt_sha256": "a" * 64,
        "prompt_snapshot_required": False,
        "methodologies": [descriptor],
    }
    entry["dispatch_contract_sha256"] = A.worker_dispatch_contract_sha256(
        "breadth", entry
    )
    A.write_phase_dispatch(sp, phase="breadth", backend="claude-pty", entries=[entry])
    rows = [
        {
            "skill": "ORACLE_ANALYSIS",
            "step": "1",
            "executed": "yes",
            "evidence": "src/Oracle.sol:L1",
            "result": "enumerated the concrete read path",
        }
    ]
    if not missing_step:
        rows.append(
            {
                "skill": "ORACLE_ANALYSIS",
                "step": "2",
                "executed": "yes",
                "evidence": "src/Oracle.sol:L2",
                "result": "traced the concrete state dependency",
            }
        )
    markers = A.worker_dispatch_markers(
        "breadth", "B1", "analysis_oracle.md", entry["dispatch_contract_sha256"]
    )
    (sp / "analysis_oracle.md").write_text(
        markers
        + "\n\n# Analysis\n\n## Step Execution Trace\n\n"
        + A.TRACE_JSON_BEGIN
        + "\n"
        + json.dumps({"schema_version": 1, "rows": rows})
        + "\n"
        + A.TRACE_JSON_END
        + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    config = {
        "project_root": project.as_posix(),
        "scratchpad": sp.as_posix(),
        "pipeline": "sc",
        "language": "evm",
        "mode": "light",
        "cli_backend": "claude",
        "methodology_application_mode": "repair",
    }
    return home, project, sp, config


def test_no_gap_does_not_spawn_repair(tmp_path: Path, monkeypatch):
    home, _project, sp, config = _setup(tmp_path, missing_step=False)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(
        D,
        "_run_methodology_repair_producer",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not spawn")),
    )

    result = D._run_methodology_application_boundary(_phase(), config, sp)

    assert result["status"] == "ATTESTED"
    assert not (sp / D._METHODOLOGY_REPAIR_ATTEMPT).exists()
    assert not (sp / "report_semantic_methodology_application_breadth.md").exists()


def test_gap_spawns_one_exact_targeted_repair_and_reuses_normal_finding_path(
    tmp_path: Path, monkeypatch,
):
    home, _project, sp, config = _setup(tmp_path, missing_step=True)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    calls = []

    def fake_runner(*, plan, **_kwargs):
        calls.append(plan["prompt"])
        assert "step `2`" in plan["prompt"]
        exact_section = plan["prompt"].split("## Exact GAP obligations", 1)[1].split(
            "Read only", 1
        )[0]
        assert "step `1`" not in exact_section
        entry = plan["entry"]
        (sp / "_prompt_breadth_repair_worker_METHODOLOGY_APPLICATION_REPAIR_BREADTH.attempt1.md").write_text(
            plan["prompt"], encoding="utf-8", newline="\n"
        )
        markers = A.worker_dispatch_markers(
            "breadth_repair",
            entry["worker_id"],
            entry["output"],
            entry["dispatch_contract_sha256"],
        )
        row = {
            "skill": "ORACLE_ANALYSIS",
            "step": "2",
            "executed": "yes",
            "evidence": "src/Oracle.sol:L2",
            "result": "traced the exact state dependency and its consumers",
        }
        (sp / D._METHODOLOGY_REPAIR_OUTPUT).write_text(
            markers
            + "\n\n# Repair\n\n## Finding [REPAIR-1]: Candidate for normal verification\n\n"
            "Specific candidate remains subject to inventory and verify.\n\n"
            "## Step Execution Trace\n\n"
            + A.TRACE_JSON_BEGIN
            + "\n"
            + json.dumps({"schema_version": 1, "rows": [row]})
            + "\n"
            + A.TRACE_JSON_END
            + "\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
            encoding="utf-8",
        )
        return 0

    monkeypatch.setattr(D, "_run_methodology_repair_producer", fake_runner)

    first = D._run_methodology_application_boundary(_phase(), config, sp)
    second = D._run_methodology_application_boundary(_phase(), config, sp)

    assert first["status"] == second["status"] == "ATTESTED"
    assert len(calls) == 1
    assert "## Finding [REPAIR-1]" in (sp / D._METHODOLOGY_REPAIR_OUTPUT).read_text()
    source_receipt = json.loads(
        (sp / "skill_application_receipt_breadth.json").read_text()
    )
    repair_receipt = json.loads(
        (sp / "skill_application_receipt_breadth_repair.json").read_text()
    )
    source_step = next(row for row in source_receipt["rows"] if row["step"] == "2")
    assert repair_receipt["rows"][0]["obligation_id"] == source_step["obligation_id"]
    assert not (sp / "report_semantic_methodology_application_breadth.md").exists()
    attempt = json.loads((sp / D._METHODOLOGY_REPAIR_ATTEMPT).read_text())
    assert attempt["state"] == "FINISHED" and attempt["return_code"] == 0


def test_failed_repair_is_haltless_and_report_visible(tmp_path: Path, monkeypatch):
    home, _project, sp, config = _setup(tmp_path, missing_step=True)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    monkeypatch.setattr(D, "_run_methodology_repair_producer", lambda **_kwargs: -2)

    result = D._run_methodology_application_boundary(_phase(), config, sp)

    assert result["status"] == "GAPS"
    review = (sp / "report_semantic_methodology_application_breadth.md").read_text()
    assert "METHODOLOGY-APPLICATION-DEBT" in review
    assert "attempted: `true`" in review
    attempt = json.loads((sp / D._METHODOLOGY_REPAIR_ATTEMPT).read_text())
    assert attempt["return_code"] == -2


def test_repair_methodology_is_byte_identical_but_runtime_contract_is_backend_bound(
    tmp_path: Path, monkeypatch
):
    home, _project, sp, config = _setup(tmp_path, missing_step=True)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    source = A.validate_phase_application(
        sp,
        Path(config["project_root"]),
        phase="breadth",
        trusted_methodology_roots=[home],
    )
    prompts = []
    for backend in ("claude", "claude-headless", "codex"):
        plan = D._build_methodology_repair_plan(
            scratchpad=sp,
            project_root=config["project_root"],
            config={**config, "cli_backend": backend},
            source_result=source,
        )
        prompts.append(plan["prompt"])
    marker = "<!-- PLAMEN_PHASE_IO_CONTRACT_BEGIN -->"
    methodology_bodies = [prompt.split(marker, 1)[0] for prompt in prompts]
    assert methodology_bodies[0] == methodology_bodies[1] == methodology_bodies[2]
    assert "<PLAMEN_METHOD_BYTES" in methodology_bodies[0]
    assert "## Step 2: trace" in methodology_bodies[0]
    missing_row = next(
        row
        for row in source["rows"]
        if row["application_completeness"] == "MISSING"
    )
    assert missing_row["obligation_id"] in methodology_bodies[0]
    from phase_contract_compiler import extract_compiled_phase_io
    contracts = [extract_compiled_phase_io(prompt) for prompt in prompts]
    assert [item["work_unit_key"].split("/")[3] for item in contracts] == [
        "claude", "claude-headless", "codex"
    ]
    assert all(
        item["allowed_outputs"]
        == ["scratchpad:analysis_methodology_repair_breadth.md"]
        for item in contracts
    )


def test_depth_repair_plan_binds_depth_snapshot_and_phase_language(
    tmp_path: Path, monkeypatch,
):
    home, _project, sp, config = _setup(tmp_path, missing_step=True)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    source = A.validate_phase_application(
        sp,
        Path(config["project_root"]),
        phase="breadth",
        trusted_methodology_roots=[home],
    )

    plan = D._build_methodology_repair_plan(
        scratchpad=sp,
        project_root=config["project_root"],
        config=config,
        source_result=source,
        source_phase="depth",
    )

    assert plan is not None
    assert plan["entry"]["prompt_snapshot_glob"] == (
        "_prompt_depth_repair_worker_"
        "METHODOLOGY_APPLICATION_REPAIR_DEPTH.attempt*.md"
    )
    assert "accepted depth producer barrier" in plan["prompt"]
    assert "Do not rerun depth" in plan["prompt"]
    assert "<!-- PLAMEN_PHASE: depth_repair -->" in plan["prompt"]


def test_repair_runner_uses_source_phase_label_on_both_backends(
    tmp_path: Path, monkeypatch,
):
    _home, _project, sp, config = _setup(tmp_path, missing_step=True)
    phase = D.Phase(
        name="depth",
        section_markers=["Phase 4"],
        expected_artifacts=["depth_*.md"],
        base_timeout_s=60,
        min_artifact_bytes=100,
    )
    plan = {
        "job": {
            "agent_id": "METHODOLOGY_APPLICATION_REPAIR_DEPTH",
            "output": "depth_methodology_repair_findings.md",
        },
        "prompt": "depth repair",
        "entry": {"source_phase": "depth"},
    }
    seen: list[tuple[str, str]] = []

    def fake_claude(**kwargs):
        seen.append(("claude", kwargs["label_prefix"]))
        return 0

    def fake_codex(**kwargs):
        seen.append(("codex", kwargs["label"]))
        return 0

    monkeypatch.setattr(D, "_run_one_claude_headless_breadth_worker", fake_claude)
    monkeypatch.setattr(D, "_run_one_codex_exec", fake_codex)

    assert D._run_methodology_repair_producer(
        plan=plan, phase=phase, config=config, scratchpad=sp
    ) == 0
    assert D._run_methodology_repair_producer(
        plan=plan,
        phase=phase,
        config={**config, "cli_backend": "codex"},
        scratchpad=sp,
    ) == 0
    assert seen == [
        ("claude", "depth_repair_worker"),
        ("codex", "depth_repair_worker_METHODOLOGY_APPLICATION_REPAIR_DEPTH"),
    ]


def test_depth_repair_uses_a_preverify_promotable_typed_feeder(
    tmp_path: Path, monkeypatch,
):
    home, _project, sp, config = _setup(tmp_path, missing_step=True)
    monkeypatch.setattr(D, "plamen_home", lambda: home)
    source = A.validate_phase_application(
        sp,
        Path(config["project_root"]),
        phase="breadth",
        trusted_methodology_roots=[home],
    )

    plan = D._build_methodology_repair_plan(
        scratchpad=sp,
        project_root=config["project_root"],
        config=config,
        source_result=source,
        source_phase="depth",
    )

    assert plan is not None
    assert plan["job"]["output"] == "depth_methodology_repair_findings.md"
    assert "Finding IDs MUST use `MAD-<N>`" in plan["prompt"]
    assert "depth_methodology_repair_findings.md" in D._DEPTH_PROMOTION_FILES


def test_rescan_repair_is_registered_and_harvested_as_a_first_class_producer(
    tmp_path: Path,
) -> None:
    name = "analysis_methodology_repair_rescan.md"
    producer = R.producer_for_artifact(name, consumer="pre_dedup_promotion")
    assert producer is not None
    assert producer.owner_phase == "rescan"
    assert R.producer_accepts_local_id(producer, "MAR-1")

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / name).write_text(
        "## Finding [MAR-1]: Repair candidate\n\n"
        "**Verdict**: REFUTATION_PROPOSAL\n"
        "**Location**: src/Example.sol:L7\n",
        encoding="utf-8",
    )
    phase = D.Phase(
        name="rescan",
        section_markers=["Phase 4"],
        expected_artifacts=["analysis_rescan_*.md"],
        base_timeout_s=60,
        min_artifact_bytes=100,
    )
    artifacts = D._candidate_negative_phase_artifacts(
        phase, scratchpad, {"_run_id": "RUN-1"}
    )
    assert [row.relative_path for row in artifacts] == [name]


def test_depth_repair_candidate_is_promoted_before_verify(tmp_path: Path):
    sp = tmp_path / ".scratchpad"
    sp.mkdir()
    (sp / "findings_inventory.md").write_text(
        "# Findings Inventory\n\n## Findings\n",
        encoding="utf-8",
    )
    (sp / "depth_methodology_repair_findings.md").write_text(
        "## Finding [MAD-1]: Repair-discovered lifecycle gap\n\n"
        "**Severity**: Medium\n\n"
        "**Location**: src/Example.sol:L7\n\n"
        "**Root Cause**: A reachable state transition omits its paired update.\n\n"
        "**Impact**: The stored accounting basis diverges from the value used later.\n",
        encoding="utf-8",
    )

    promoted = D._promote_depth_findings_to_inventory(sp)

    assert "MAD-1" in promoted
    inventory = (sp / "findings_inventory.md").read_text(encoding="utf-8")
    assert "MAD-1" in inventory
    assert "## Depth Promotion Supplement" in inventory
    assert "### Finding [INV-001]" in inventory


def test_methodology_repair_ids_are_canonical_internal_identities():
    for finding_id in ("MAB-1", "MAR-2", "MAD-3"):
        assert D._normalize_finding_id(finding_id) == finding_id


def test_off_boundary_mode_skips_post_acceptance_validation_and_repair(
    tmp_path: Path, monkeypatch,
):
    _home, _project, sp, config = _setup(tmp_path, missing_step=True)
    config["methodology_application_mode"] = "off"
    monkeypatch.setattr(
        D,
        "validate_phase_application",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("disabled")),
    )
    assert D._run_methodology_application_boundary(_phase(), config, sp) is None
    assert not (sp / D._METHODOLOGY_REPAIR_ATTEMPT).exists()


def test_explicit_boundary_mode_name_takes_precedence(tmp_path: Path):
    _home, _project, sp, config = _setup(tmp_path, missing_step=True)
    config["methodology_application_mode"] = "off"  # legacy alias
    config["methodology_application_boundary_mode"] = "observe"

    result = D._run_methodology_application_boundary(_phase(), config, sp)

    assert result is not None
    assert result["status"] == "GAPS"
    assert (sp / "report_semantic_methodology_application_breadth.md").exists()
