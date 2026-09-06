"""Focused regression coverage for authenticated recon retry generations."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import pytest

import artifact_ledger as ledger
import claude_phase_tool_policy as claude_policy
import claude_worker_prompt_consistency as prompt_consistency
import headless_worker_runtime as headless_runtime
import plamen_driver as driver
import plamen_mechanical as mechanical
import test_recon_canonical_prepass_handoff as prepass_fixture
from phase_io_contracts import recon_direct_retry_output_paths
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
)
from test_recon_canonical_prepass_handoff import RUN_ID, _workspace


def _retry_plan(scratchpad: Path, *, run_id: str = RUN_ID) -> None:
    digest = "a" * 64
    payload = {
        "schema": "plamen.retry-plan/v1",
        "run_id": run_id,
        "phase_name": "recon",
        "work_unit_id": "phase",
        "attempt": 2,
        "semantic_retry": True,
        "contract_digest": digest,
        "launch_digest": "b" * 64,
        "required_output_schema": [
            {"pattern": name, "minimum_bytes": 100, "minimum_count": 1}
            for name in mechanical._RECON_CANONICAL_OUTPUTS
        ],
        "failed_predicates": [
            {
                "gate_id": "recon.methodology_selection.binding_manifest",
                "contract_digest": digest,
            }
        ],
    }
    (scratchpad / "recon_retry_plan.json").write_text(
        json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
    )


def _supervised_attempt_evidence(scratchpad: Path, attempt: int = 2) -> None:
    (scratchpad / f"_prompt_recon.attempt{attempt}.md").write_text(
        "# RETRY ATTEMPT (driver-detected gate failure on previous attempt)\n"
        f"SCRATCHPAD: {scratchpad}\n",
        encoding="utf-8",
    )
    (scratchpad / f"_stdio_recon.attempt{attempt}.log").write_text(
        ("supervised retry event\n" * 30)
        + f"cwd={scratchpad}\n"
        + "outputs=" + ",".join(mechanical._RECON_CANONICAL_OUTPUTS) + "\n"
        + '{"stop_reason":"end_turn","type":"assistant"}\n',
        encoding="utf-8",
    )


def _quarantine_committed_generation(scratchpad: Path) -> None:
    quarantine = scratchpad / "_retry_quarantine" / "recon"
    quarantine.mkdir(parents=True)
    for name in mechanical._RECON_CANONICAL_OUTPUTS:
        (scratchpad / name).rename(quarantine / name)


def _write_candidates(scratchpad: Path, *, only: int | None = None) -> None:
    names = mechanical._RECON_CANONICAL_OUTPUTS
    if only is not None:
        names = names[:only]
    for name in names:
        (scratchpad / name).write_text(
            f"# Authenticated retry {name}\n\n" + ("candidate evidence\n" * 20),
            encoding="utf-8",
        )


def _prepared_retry(tmp_path: Path) -> tuple[Path, Path, dict]:
    project, scratchpad, config = _workspace(tmp_path)
    # These legacy fixtures exercise the PTY candidate lane.  Typed headless
    # retry coverage below uses a real private MODEL transaction.
    config["claude_exec_mode"] = "pty"
    mechanical._merge_recon_worker_shards(scratchpad, config)
    _quarantine_committed_generation(scratchpad)
    _retry_plan(scratchpad, run_id=str(config["_run_id"]))
    _supervised_attempt_evidence(scratchpad)
    return project, scratchpad, config


def _commit_private_retry(
    tmp_path: Path,
    *,
    attempt: int = 2,
) -> tuple[Path, Path, dict]:
    prior_backend = prepass_fixture.DIMENSIONS["backend"]
    prior_run_id = prepass_fixture.RUN_ID
    prepass_fixture.DIMENSIONS["backend"] = "codex"
    prepass_fixture.RUN_ID = FIXTURE_RUN_ID
    try:
        project, scratchpad, config = _workspace(tmp_path)
    finally:
        prepass_fixture.DIMENSIONS["backend"] = prior_backend
        prepass_fixture.RUN_ID = prior_run_id
    config["cli_backend"] = "codex"
    mechanical._merge_recon_worker_shards(scratchpad, config)
    _quarantine_committed_generation(scratchpad)
    _retry_plan(scratchpad, run_id=str(config["_run_id"]))
    _supervised_attempt_evidence(scratchpad, attempt)
    config.setdefault("_active_model_attempts", {})["recon"] = attempt
    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    contract, launch = driver._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert contract is not None and launch is not None
    ledger.record_work_unit_inputs(
        scratchpad,
        project,
        contract,
        launch,
        run_id=str(config["_run_id"]),
    )
    expected = recon_direct_retry_output_paths("sc", attempt)

    def command_builder(output_directory: Path):
        script = (
            "from pathlib import Path; import json,sys; "
            "sys.stdin.buffer.read(); root=Path(sys.argv[1]); "
            "names=json.loads(sys.argv[2]); "
            "[(root/name).parent.mkdir(parents=True,exist_ok=True) for name in names]; "
            "[(root/name).write_text('# Authenticated retry '+Path(name).name+'\\n\\n'"
            "+'candidate evidence\\n'*20,encoding='utf-8') for name in names]"
        )
        return (
            r"C:\p27rt\python.exe" if os.name == "nt" else sys.executable,
            "-I",
            "-c",
            script,
            str(output_directory),
            json.dumps(expected),
        )

    headless_runtime.execute_headless_worker(
        scratchpad=scratchpad,
        project_root=project,
        run_id=str(config["_run_id"]),
        phase_io_contract=contract,
        phase_io_launch=launch,
        prompt="Analyze recon and write every routed output artifact.",
        command_builder=command_builder,
        cwd=project,
        environment={},
        environment_allowlist=(),
        source_snapshot_digest="a" * 64,
        methodology_digests=("b" * 64,),
        startup_authority_binding=durable_startup_permit(scratchpad),
        attempt_id="attempt-" + str(attempt) * 24,
    )
    return project, scratchpad, config


def _skill_promotion_fixture() -> bytes:
    return (
        "# Template Recommendations\n\n"
        "## Binding Manifest\n\n"
        "| Skill | Required | Rationale |\n"
        "|---|---|---|\n"
        "| CROSS_CHAIN_MESSAGE_INTEGRITY | NO | Not selected |\n\n"
        "## Template / Skill Recommendations\n\n"
        "CROSS_CHAIN_MESSAGE_INTEGRITY is recommended and required because messages "
        "cross a trust boundary.\n"
    ).encode("utf-8")


def test_typed_direct_retry_routes_to_bounded_consistent_prompt(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _prepared_retry(tmp_path)
    config["claude_exec_mode"] = "headless"
    config.setdefault("_active_model_attempts", {})["recon"] = 2
    legacy = (
        "Search scratchpad recursively, run shell commands, and write "
        "recon_summary.md.\n"
    )

    prompt = driver._route_recon_direct_retry_prompt(
        legacy,
        phase_name="recon",
        scratchpad=scratchpad,
        config=config,
        attempt=2,
    )
    expected = recon_direct_retry_output_paths("sc", 2)

    assert prompt != legacy
    assert len(expected) == 11
    assert "scratchpad:recon_retry_plan.json" in prompt
    assert "Search scratchpad recursively" not in prompt
    assert "## Output files to write" in prompt
    for output in expected:
        assert f"scratchpad:{output}" in prompt
    prompt_consistency.require_claude_worker_prompt_consistency(
        prompt,
        phase_io_inputs=(scratchpad / "recon_retry_plan.json",),
        phase_io_outputs=tuple(scratchpad / output for output in expected),
        policy_tools=("Read", "Write", "Glob", "Grep"),
        safe_search_roots=(project,),
        project_root=str(project),
        scratchpad_root=str(scratchpad),
    )
    assert driver._route_recon_direct_retry_prompt(
        legacy,
        phase_name="breadth",
        scratchpad=scratchpad,
        config=config,
        attempt=2,
    ) == legacy


def test_typed_direct_retry_passes_supervisor_augmented_consistency(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _prepared_retry(tmp_path)
    config.update({
        "claude_exec_mode": "headless",
    })
    config.setdefault("_active_model_attempts", {})["recon"] = 2
    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    assert driver._bind_typed_model_phase_inputs(
        phase, scratchpad, config
    ) == []
    contract, launch = driver._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )
    assert contract is not None and launch is not None
    prompt = driver._route_recon_direct_retry_prompt(
        "legacy coordinator prompt",
        phase_name="recon",
        scratchpad=scratchpad,
        config=config,
        attempt=2,
    )
    snapshot = scratchpad / "_prompt_recon-direct-retry-test.attempt2.md"
    snapshot.write_text(prompt, encoding="utf-8")
    transaction_output = scratchpad / "_transaction-test-output"
    transaction_output.mkdir()
    boundary = driver._prepare_claude_phase_tool_boundary(
        phase=phase,
        scratchpad=scratchpad,
        config=config,
        attempt=2,
        prompt_snapshot=snapshot,
        transaction_output_directory=transaction_output,
        expected_cwd=project,
        contract=contract,
        launch=launch,
    )
    assert boundary is not None
    policy = claude_policy.load_policy(Path(boundary["policy_path"]))
    input_paths = (scratchpad / "recon_retry_plan.json",)
    projection = claude_policy.build_model_visible_projection(
        policy,
        phase_io_input_paths=input_paths,
        private_exact_read_paths=(snapshot,),
    )
    effective = (
        prompt.rstrip()
        + "\n\n"
        + claude_policy.render_model_visible_supervisor_block(projection)
    )
    prompt_consistency.require_claude_worker_prompt_consistency(
        effective,
        phase_io_inputs=input_paths,
        phase_io_outputs=tuple(
            scratchpad / output
            for output in recon_direct_retry_output_paths("sc", 2)
        ),
        policy_tools=claude_policy.provider_builtin_tools(policy),
        safe_search_roots=tuple(policy["safe_search_roots"]),
        project_root=str(project),
        scratchpad_root=str(scratchpad),
    )
    assert "## Restricted Claude Supervisor Tool Contract" in effective


def _injectable_promotion_fixture() -> bytes:
    return (
        "# Detected Patterns and Templates\n\n"
        "NAMED_EXTERNAL_PROTOCOL = YES\n\n"
        "## Injectable Skills\n\n"
        "| Skill | Required | Rationale |\n"
        "|---|---|---|\n"
        "| INTEGRATION_HAZARD_RESEARCH | NO | [LLM TO ENRICH] |\n"
    ).encode("utf-8")


def test_canonical_skill_promotion_is_committed_before_retry_quarantine(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, template_shard=_skill_promotion_fixture()
    )

    mechanical._merge_recon_worker_shards(scratchpad, config)
    final_bytes = (scratchpad / "template_recommendations.md").read_bytes()
    assert b"| CROSS_CHAIN_MESSAGE_INTEGRITY | YES |" in final_bytes

    state = ledger.read_artifact_ledger(scratchpad)
    key = next(key for key in state["work_units"] if key.endswith("/canonical_merge"))
    record = state["work_units"][key]["artifacts"][
        "scratchpad:template_recommendations.md"
    ]
    import hashlib

    assert record["sha256"] == hashlib.sha256(final_bytes).hexdigest()
    assert record["size"] == len(final_bytes)
    receipt = json.loads(
        (scratchpad / mechanical._RECON_TRANSFORM_RECEIPT).read_text(encoding="utf-8")
    )
    assert receipt["canonical_output_sha256"]["template_recommendations.md"] == (
        hashlib.sha256(final_bytes).hexdigest()
    )
    assert receipt["canonical_normalization"]["skill_manifest_promotions"] == 1

    _quarantine_committed_generation(scratchpad)
    _retry_plan(scratchpad)
    # Before a supervised direct retry returns candidates, exact committed
    # predecessor bytes are accepted as pending rather than reported as drift.
    assert mechanical._merge_recon_worker_shards(scratchpad, config) == []


def test_postcommit_skill_template_tamper_still_fails_closed(tmp_path: Path) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, template_shard=_skill_promotion_fixture()
    )
    mechanical._merge_recon_worker_shards(scratchpad, config)
    template = scratchpad / "template_recommendations.md"
    template.write_bytes(template.read_bytes() + b"\npost-commit tamper\n")
    _quarantine_committed_generation(scratchpad)
    _retry_plan(scratchpad)
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="canonical retry predecessor bytes changed: template_recommendations.md",
    ):
        mechanical._merge_recon_worker_shards(scratchpad, config)


def test_canonical_injectable_promotion_is_hashed_and_gate_idempotent(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, template_shard=_injectable_promotion_fixture()
    )
    mechanical._merge_recon_worker_shards(scratchpad, config)
    template = scratchpad / "template_recommendations.md"
    before = template.read_bytes()
    assert b"| INTEGRATION_HAZARD_RESEARCH | YES |" in before
    receipt = json.loads(
        (scratchpad / mechanical._RECON_TRANSFORM_RECEIPT).read_text(encoding="utf-8")
    )
    assert receipt["canonical_normalization"]["injectable_promotions"] == 1
    assert mechanical._reconcile_skill_manifest_sources(scratchpad) == 0
    assert mechanical._promote_injectable_rows(scratchpad, "evm") == 0
    assert template.read_bytes() == before


def test_supervised_direct_retry_becomes_same_owner_committed_generation(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    before = ledger.read_artifact_ledger(scratchpad)
    key = next(key for key in before["work_units"] if key.endswith("/canonical_merge"))

    # Before the supervised direct attempt returns, quarantine is pending and
    # must not invalidate the committed owner.
    (scratchpad / "_stdio_recon.attempt2.log").unlink()
    assert mechanical._merge_recon_worker_shards(scratchpad, config) == []
    assert ledger.read_artifact_ledger(scratchpad)["work_units"][key][
        "semantic_status"
    ] == "ACTIVE"

    _supervised_attempt_evidence(scratchpad)
    _write_candidates(scratchpad)
    assert mechanical._merge_recon_worker_shards(scratchpad, config) == list(
        mechanical._RECON_CANONICAL_OUTPUTS
    )
    after = ledger.read_artifact_ledger(scratchpad)
    unit = after["work_units"][key]
    assert (unit["semantic_status"], unit["execution_state"]) == (
        "ACTIVE",
        "OUTPUT_COMMITTED",
    )
    assert unit["commit_authority"]["attempt_ordinal"] == 2
    assert any(
        value.endswith("/transcript.log")
        for value in unit["contract_manifest"]["immutable_inputs"]
    )
    assert mechanical._merge_recon_worker_shards(scratchpad, config) == list(
        mechanical._RECON_CANONICAL_OUTPUTS
    )


def test_direct_fallback_return_hook_commits_authenticated_retry(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    _write_candidates(scratchpad)
    launch_authority = (
        mechanical.validate_recon_direct_retry_launch_authority(
            scratchpad, config
        )
    )

    outputs = driver._finalize_recon_direct_fallback(
        scratchpad,
        config,
        require_retry_authority=True,
        semantic_attempt=2,
        supervised_attempt=2,
        launch_authority=launch_authority,
    )

    assert outputs == list(mechanical._RECON_CANONICAL_OUTPUTS)
    receipt = json.loads(
        (scratchpad / mechanical._RECON_TRANSFORM_RECEIPT).read_text(
            encoding="utf-8"
        )
    )
    assert receipt["retry_generation"]["attempt_ordinal"] == 2
    assert receipt["retry_generation"] == {
        "attempt_ordinal": receipt["authority_capture"]["retry_generation"][
            "attempt_ordinal"
        ],
        "manifest_sha256": receipt["authority_capture"]["retry_generation"][
            "manifest_sha256"
        ],
    }


def test_active_canonical_retry_bypasses_leaf_pool_and_adopts_direct_generation(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(tmp_path)
    config["claude_exec_mode"] = "pty"
    mechanical._merge_recon_worker_shards(scratchpad, config)
    kind, issues = driver._recon_retry_predecessor_kind(scratchpad, config)
    assert (kind, issues) == ("canonical_merge", [])

    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    moved = driver._quarantine_stale_on_retry(
        scratchpad,
        phase,
        ["recon.full_validator: canonical generation needs semantic repair"],
        include_recon_canonical=True,
    )
    assert set(mechanical._RECON_CANONICAL_OUTPUTS).issubset(set(moved))
    _retry_plan(scratchpad)
    authority = mechanical.validate_recon_direct_retry_launch_authority(
        scratchpad, config
    )
    config["_recon_force_direct_retry"] = True
    assert not driver._should_use_recon_worker_pool(config, scratchpad)

    # Simulate the isolated direct model returning its full root candidate
    # denominator and supervised transcript.  Adoption below is the real
    # canonical PhaseIO retry-generation transaction.
    _supervised_attempt_evidence(scratchpad)
    _write_candidates(scratchpad)
    outputs = driver._finalize_recon_direct_fallback(
        scratchpad,
        config,
        require_retry_authority=True,
        semantic_attempt=2,
        supervised_attempt=2,
        launch_authority=authority,
    )
    config.pop("_recon_force_direct_retry", None)
    assert outputs == list(mechanical._RECON_CANONICAL_OUTPUTS)
    assert not (scratchpad / "_retry_quarantine" / "recon" / "recon_summary.md").exists()


def test_active_canonical_retry_resolves_exact_model_transaction(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    config.setdefault("_active_model_attempts", {})["recon"] = 2

    contract, launch = driver._typed_model_phase_contract_and_launch(
        phase, scratchpad, config
    )

    assert contract is not None and launch is not None
    assert contract.model_invoked is True
    assert contract.key.endswith("/recon/direct_retry.attempt-0002")
    assert contract.immutable_inputs == (
        "scratchpad:recon_retry_plan.json",
    )
    assert {
        spec.identity.removeprefix("scratchpad:")
        for spec in contract.outputs
    } == set(recon_direct_retry_output_paths("sc", 2))
    assert not {
        spec.identity.removeprefix("scratchpad:")
        for spec in contract.outputs
    } & set(mechanical._RECON_CANONICAL_OUTPUTS)
    assert all(spec.writer == "MODEL" for spec in contract.outputs)
    assert all(spec.write_mode == "REPLACE" for spec in contract.outputs)


@pytest.mark.parametrize("attempt", (2, 3))
def test_private_model_commit_projects_then_canonical_merge_remains_root_owner(
    tmp_path: Path,
    attempt: int,
) -> None:
    _project, scratchpad, config = _commit_private_retry(
        tmp_path, attempt=attempt
    )
    private_paths = recon_direct_retry_output_paths("sc", attempt)
    state = ledger.read_artifact_ledger(scratchpad)
    private_key = next(
        key
        for key in state["work_units"]
        if key.endswith(f"/direct_retry.attempt-{attempt:04d}")
    )
    assert state["work_units"][private_key]["execution_state"] == (
        "OUTPUT_COMMITTED"
    )
    assert not any(
        identity == f"scratchpad:{name}"
        for identity in state["work_units"][private_key]["artifacts"]
        for name in mechanical._RECON_CANONICAL_OUTPUTS
    )
    authority = mechanical.validate_recon_direct_retry_launch_authority(
        scratchpad, config
    )
    outputs = driver._finalize_recon_direct_fallback(
        scratchpad,
        config,
        require_retry_authority=True,
        semantic_attempt=2,
        supervised_attempt=attempt,
        launch_authority=authority,
    )
    assert outputs == list(mechanical._RECON_CANONICAL_OUTPUTS)
    after = ledger.read_artifact_ledger(scratchpad)
    canonical_key = next(
        key
        for key in after["work_units"]
        if key.endswith("/recon/canonical_merge")
    )
    for name, private_path in zip(
        mechanical._RECON_CANONICAL_OUTPUTS, private_paths
    ):
        assert (scratchpad / private_path).is_file()
        owners = [
            key
            for key, unit in after["work_units"].items()
            if f"scratchpad:{name}" in unit.get("artifacts", {})
        ]
        assert canonical_key in owners
        assert private_key not in owners


def test_run_phase_recovers_committed_private_retry_without_provider_rerun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, config = _commit_private_retry(tmp_path, attempt=2)
    config.pop("_active_model_attempts", None)
    launched = False

    def forbidden(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return 0

    monkeypatch.setattr(driver, "_run_phase_once", forbidden)
    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    assert driver.run_phase(phase, config, attempt=2) == 0
    assert launched is False
    assert all(
        (scratchpad / name).is_file()
        for name in mechanical._RECON_CANONICAL_OUTPUTS
    )


def test_private_retry_tamper_and_wrong_attempt_fail_closed(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _commit_private_retry(tmp_path, attempt=2)
    private = scratchpad / recon_direct_retry_output_paths("sc", 2)[0]
    private.write_bytes(private.read_bytes() + b"tamper\n")
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="private MODEL commit is invalid|private artifact changed",
    ):
        driver._validated_committed_recon_direct_retry_bytes(
            scratchpad, config, supervised_attempt=2
        )
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="disagrees with active attempt",
    ):
        driver._validated_committed_recon_direct_retry_bytes(
            scratchpad, config, supervised_attempt=3
        )


@pytest.mark.parametrize(
    ("resume_state", "expected_attempt"),
    (
        ("pre_spawn", 2),
        ("attempt2_rate_limit", 3),
        ("attempt3_rate_limit", 3),
    ),
)
def test_durable_direct_retry_resume_never_reenters_leaf_pool(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resume_state: str,
    expected_attempt: int,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    for ordinal in (2, 3):
        (scratchpad / f"_prompt_recon.attempt{ordinal}.md").unlink(
            missing_ok=True
        )
        (scratchpad / f"_stdio_recon.attempt{ordinal}.log").unlink(
            missing_ok=True
        )
    if resume_state in {"attempt2_rate_limit", "attempt3_rate_limit"}:
        (scratchpad / "_stdio_recon.attempt2.log").write_text(
            "PLAMEN_RATE_LIMIT_DETECTED=1 api_error_status=429 "
            "type=rate_limit_error phase=recon source=test\n",
            encoding="utf-8",
        )
    if resume_state == "attempt3_rate_limit":
        (scratchpad / "_stdio_recon.attempt3.log").write_text(
            "PLAMEN_RATE_LIMIT_DETECTED=1 api_error_status=429 "
            "type=rate_limit_error phase=recon source=test\n",
            encoding="utf-8",
        )

    # No ephemeral selector survives this simulated process restart.
    config.pop("_recon_force_direct_retry", None)
    assert driver._pending_recon_direct_retry_authority(
        scratchpad, config
    ) is not None
    assert not driver._should_use_recon_worker_pool(config, scratchpad)
    seen: list[int] = []

    def fake_direct(_phase, _config, attempt):
        seen.append(attempt)
        (scratchpad / f"_prompt_recon.attempt{attempt}.md").write_text(
            "# RETRY ATTEMPT (driver-detected gate failure on previous attempt)\n"
            + f"SCRATCHPAD: {scratchpad}\n",
            encoding="utf-8",
        )
        (scratchpad / f"_stdio_recon.attempt{attempt}.log").write_text(
            ("durable resumed supervised retry\n" * 30)
            + f"cwd={scratchpad}\n"
            + "outputs="
            + ",".join(mechanical._RECON_CANONICAL_OUTPUTS)
            + "\n"
            + '{"stop_reason":"end_turn","type":"assistant"}\n',
            encoding="utf-8",
        )
        _write_candidates(scratchpad)
        return 0

    monkeypatch.setattr(driver, "_run_phase_once", fake_direct)
    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    assert driver.run_phase(phase, config, attempt=1) == 0
    assert seen == [expected_attempt]
    receipt = json.loads(
        (scratchpad / mechanical._RECON_TRANSFORM_RECEIPT).read_text(
            encoding="utf-8"
        )
    )
    assert receipt["retry_generation"]["attempt_ordinal"] == 2


def test_tampered_durable_direct_retry_fails_before_any_model_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    quarantined = (
        scratchpad / "_retry_quarantine" / "recon" / "recon_summary.md"
    )
    quarantined.write_bytes(quarantined.read_bytes() + b"tampered\n")
    state, authority, issue = driver._recon_direct_retry_durable_state(
        scratchpad, config
    )
    assert state == "INVALID"
    assert authority is None
    assert "predecessor bytes changed" in issue
    assert not driver._should_use_recon_worker_pool(config, scratchpad)

    launched = False

    def forbidden(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return 0

    monkeypatch.setattr(driver, "_run_phase_once", forbidden)
    phase = next(row for row in driver.SC_PHASES if row.name == "recon")
    assert driver.run_phase(phase, config, attempt=1) == driver.EXIT_ERROR
    assert not launched


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH regression")
def test_direct_retry_stage_stays_below_legacy_max_path(
    tmp_path: Path,
) -> None:
    # Reproduce the real DODO E2E geometry: a 152-character scratch root made
    # the old `.canonical-merge-<random>` candidate spelling exactly 260
    # characters, so pathlib reported ENOENT for template_recommendations.md.
    fixed_tail = len(str(Path("project") / ".scratchpad")) + 1
    padding = max(1, 152 - len(str(tmp_path)) - fixed_tail - 1)
    long_root = tmp_path / ("x" * padding)
    _project, scratchpad, config = _prepared_retry(long_root)
    _write_candidates(scratchpad)
    launch_authority = mechanical.validate_recon_direct_retry_launch_authority(
        scratchpad, config
    )
    old_probe = (
        scratchpad
        / ".canonical-merge-12345678"
        / "_canonical_retry_generation"
        / "recon"
        / "attempt-2"
        / "candidate"
        / "template_recommendations.md"
    )
    compact_probe = (
        scratchpad
        / ".cm-12345678"
        / "_canonical_retry_generation"
        / "recon"
        / "attempt-2"
        / "candidate"
        / "template_recommendations.md"
    )
    assert len(str(old_probe)) >= 260
    assert len(str(compact_probe)) < 260

    outputs = driver._finalize_recon_direct_fallback(
        scratchpad,
        config,
        require_retry_authority=True,
        semantic_attempt=2,
        supervised_attempt=2,
        launch_authority=launch_authority,
    )
    assert outputs == list(mechanical._RECON_CANONICAL_OUTPUTS)


def test_direct_fallback_return_hook_rejects_missing_retry_authority(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(tmp_path)
    mechanical._merge_recon_worker_shards(scratchpad, config)

    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="no retained prelaunch authority",
    ):
        driver._finalize_recon_direct_fallback(
            scratchpad,
            config,
            require_retry_authority=True,
            semantic_attempt=2,
            supervised_attempt=2,
        )


def test_unarmed_direct_fallback_is_rejected_without_poisoning_owner(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(tmp_path)
    mechanical._merge_recon_worker_shards(scratchpad, config)
    before = ledger.read_artifact_ledger(scratchpad)

    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="not armed by a retry plan",
    ):
        mechanical.validate_recon_direct_retry_launch_authority(
            scratchpad, config
        )

    assert ledger.read_artifact_ledger(scratchpad) == before


def test_direct_retry_binds_actual_supervised_transport_attempt(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    prompt2 = scratchpad / "_prompt_recon.attempt2.md"
    log2 = scratchpad / "_stdio_recon.attempt2.log"
    (scratchpad / "_prompt_recon.attempt3.md").write_bytes(prompt2.read_bytes())
    (scratchpad / "_stdio_recon.attempt3.log").write_bytes(log2.read_bytes())
    _write_candidates(scratchpad)

    authority = mechanical.validate_recon_direct_retry_launch_authority(
        scratchpad, config
    )
    assert authority["semantic_attempt"] == 2
    driver._finalize_recon_direct_fallback(
        scratchpad,
        config,
        require_retry_authority=True,
        semantic_attempt=2,
        supervised_attempt=3,
        launch_authority=authority,
    )
    manifest = json.loads(
        (
            scratchpad
            / "_canonical_retry_generation/recon/attempt-2/manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["attempt_ordinal"] == 2
    assert manifest["supervised_attempt_ordinal"] == 3


def test_tampered_quarantine_is_rejected_before_direct_launch(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    before = ledger.read_artifact_ledger(scratchpad)
    template = (
        scratchpad
        / "_retry_quarantine"
        / "recon"
        / "template_recommendations.md"
    )
    template.write_bytes(template.read_bytes() + b"tampered before launch\n")

    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="predecessor bytes changed: template_recommendations.md",
    ):
        mechanical.validate_recon_direct_retry_launch_authority(
            scratchpad, config
        )

    assert ledger.read_artifact_ledger(scratchpad) == before


def test_arbitrary_unbound_root_candidates_without_direct_attempt_fail_closed(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    (scratchpad / "_stdio_recon.attempt2.log").unlink()
    _write_candidates(scratchpad)
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="supervised attempt transcript",
    ):
        mechanical._merge_recon_worker_shards(scratchpad, config)


def test_partial_candidate_denominator_cannot_be_adopted(tmp_path: Path) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    _write_candidates(scratchpad, only=1)
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="candidate generation is partial",
    ):
        mechanical._merge_recon_worker_shards(scratchpad, config)


def test_committed_retry_bundle_tamper_fails_closed(tmp_path: Path) -> None:
    _project, scratchpad, config = _prepared_retry(tmp_path)
    _write_candidates(scratchpad)
    mechanical._merge_recon_worker_shards(scratchpad, config)
    transcript = next(
        (scratchpad / "_canonical_retry_generation").rglob("transcript.log")
    )
    transcript.write_bytes(transcript.read_bytes() + b"tampered\n")
    with pytest.raises(
        mechanical.CanonicalMergeAuthorityError,
        match="supervised-attempt evidence changed",
    ):
        mechanical._merge_recon_worker_shards(scratchpad, config)
