from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import fuzz_workspace_authority as fwa


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "test" / "invariant").mkdir(parents=True)
    (root / ".medusa-tests").mkdir(parents=True)
    (root / "src" / "Counter.sol").write_text(
        "pragma solidity ^0.8.20; contract Counter {}\n", encoding="utf-8"
    )
    (root / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\n", encoding="utf-8"
    )
    (root / "test" / "invariant" / "Existing.t.sol").write_text(
        "contract ExistingTest {}\n", encoding="utf-8"
    )
    (root / ".medusa-tests" / "ExistingHarness.sol").write_text(
        "contract ExistingHarness {}\n", encoding="utf-8"
    )
    (root / "medusa.json").write_text("{}\n", encoding="utf-8")
    return root


def _materialize(tmp_path: Path, **kwargs: object) -> dict[str, object]:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    return fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-1",
        source_snapshot_digest="a" * 64,
        allowed_tools=(Path(sys.executable).name,),
        **kwargs,
    )


def _load(path: str | Path) -> dict[str, object]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def test_evm_workspace_binds_only_remapped_solidity_node_dependencies(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    dependency = root / "node_modules" / "@example" / "contracts"
    unrelated = root / "node_modules" / "unrelated"
    nested = dependency / "node_modules" / "nested"
    dependency.mkdir(parents=True)
    unrelated.mkdir(parents=True)
    nested.mkdir(parents=True)
    (dependency / "Library.sol").write_text(
        "library Library {}\n", encoding="utf-8"
    )
    (dependency / "package.json").write_text("{}\n", encoding="utf-8")
    (unrelated / "Ignored.sol").write_text(
        "library Ignored {}\n", encoding="utf-8"
    )
    (nested / "IgnoredNested.sol").write_text(
        "library IgnoredNested {}\n", encoding="utf-8"
    )
    (root / "remappings.txt").write_text(
        "@example/=node_modules/@example/\n", encoding="utf-8"
    )
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-NODE-DEPS",
        source_snapshot_digest="b" * 64,
        allowed_tools=(Path(sys.executable).name,),
    )

    active = Path(str(receipt["active_root"]))
    assert receipt["status"] == "READY"
    assert (
        active / "node_modules" / "@example" / "contracts" / "Library.sol"
    ).is_file()
    assert not (active / "node_modules" / "unrelated").exists()
    assert not (
        active / "node_modules" / "@example" / "contracts"
        / "node_modules" / "nested"
    ).exists()


def test_materialization_excludes_all_sibling_plamen_scratchpads(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad-p7"
    scratchpad.mkdir()
    for generated in (
        ".scratchpad-p4",
        ".scratchpad-rerun-codex-isolated-home-v3-20260905",
        ".plamen-stale-snapshots-old",
    ):
        directory = root / generated
        directory.mkdir()
        (directory / "RecursiveCopy.sol").write_text(
            "contract MustNeverEnterFuzzWorkspace {}\n", encoding="utf-8"
        )

    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-NO-RECURSION",
        source_snapshot_digest="c" * 64,
    )

    assert receipt["status"] == "READY"
    active = Path(str(receipt["active_root"]))
    assert (active / "src" / "Counter.sol").is_file()
    assert not any(active.glob(".scratchpad*"))
    assert not any(active.glob(".plamen-stale-snapshots*"))
    assert not any(
        row["relative_path"].endswith("RecursiveCopy.sol")
        for row in receipt["inputs"]
    )


def test_driver_indexes_reconcile_exact_unscored_denominator_compare_only(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    scratchpad = Path(str(receipt["scratchpad_root"]))
    output = scratchpad / "invariant_fuzz_results.md"
    output.write_text(
        "## Finding [FUZZ-1]\n\n**Evidence Tag**: [FUZZ-PASS]\n",
        encoding="utf-8",
    )
    jobs = [{
        "agent_id": "invariant-fuzz",
        "role": "invariant_fuzz",
        "output": output.name,
        "category": "fuzz",
        "fuzz_authority_path": str(receipt["authority_path"]),
    }]
    launch_index = fwa.write_fuzz_workspace_index(
        scratchpad,
        jobs,
        run_id="RUN-1",
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
    )
    assert launch_index["row_count"] == 1
    assert fwa.validate_fuzz_workspace_index(
        scratchpad / fwa.WORKSPACE_INDEX_FILE
    ) == []
    row = fwa.resolve_fuzz_workspace_index_row(
        scratchpad / fwa.WORKSPACE_INDEX_FILE,
        job_id="invariant-fuzz",
        output=output.name,
    )
    assert row["status"] == "READY"

    result = fwa.finalize_fuzz_workspace(Path(str(receipt["authority_path"])))
    assert result["status"] == "UNSCORED"
    result_index = fwa.write_fuzz_workspace_result_index(
        scratchpad / fwa.WORKSPACE_INDEX_FILE
    )
    assert result_index["row_count"] == 1
    assert result_index["rows"][0]["status"] == "UNSCORED"
    assert result_index["rows"][0]["output_sha256"] == hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    assert fwa.validate_fuzz_workspace_result_index(
        scratchpad / fwa.RESULT_INDEX_FILE
    ) == []

    assert fwa.write_fuzz_workspace_index(
        scratchpad,
        jobs,
        run_id="RUN-1",
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
    ) == launch_index
    assert fwa.write_fuzz_workspace_result_index(
        scratchpad / fwa.WORKSPACE_INDEX_FILE
    ) == result_index


def test_workspace_index_tamper_is_never_reblessed(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    scratchpad = Path(str(receipt["scratchpad_root"]))
    jobs = [{
        "agent_id": "invariant-fuzz",
        "role": "invariant_fuzz",
        "output": "invariant_fuzz_results.md",
        "category": "fuzz",
        "fuzz_authority_path": str(receipt["authority_path"]),
    }]
    fwa.write_fuzz_workspace_index(
        scratchpad,
        jobs,
        run_id="RUN-1",
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
    )
    index_path = scratchpad / fwa.WORKSPACE_INDEX_FILE
    tampered = _load(index_path)
    tampered["rows"][0]["status"] = "UNSCORED"
    index_path.write_text(json.dumps(tampered), encoding="utf-8")
    assert fwa.validate_fuzz_workspace_index(index_path)
    with pytest.raises(fwa.FuzzWorkspaceError, match="WORKSPACE_INDEX_DRIFT"):
        fwa.write_fuzz_workspace_index(
            scratchpad,
            jobs,
            run_id="RUN-1",
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
        )


def test_unscored_fuzz_tag_retains_candidate_without_proof_authority(
    tmp_path: Path,
) -> None:
    import plamen_parsers as parsers

    path = tmp_path / "medusa_fuzz_findings.md"
    path.write_text(
        "## Finding [MEDUSA-1]: invariant counterexample proposal\n\n"
        "**Severity**: High\n\n"
        "**Location**: src/Counter.sol:1\n\n"
        "**Description**: A generated sequence appears to violate the encoded "
        "state relation and requires independent verification.\n\n"
        "**Evidence Tag**: [MEDUSA-PASS]\n",
        encoding="utf-8",
    )
    findings = parsers._parse_depth_finding_blocks(path)
    assert len(findings) == 1
    assert findings[0]["id"] == "MEDUSA-1"
    assert findings[0]["preferred_tag"] == "CODE-TRACE"
    assert findings[0]["fuzz_execution_status"] == "UNSCORED"
    assert findings[0]["fuzz_original_tag"] == "MEDUSA-PASS"


def test_materialization_quarantines_user_tests_and_fuzzer_harnesses(
    tmp_path: Path,
) -> None:
    source = _project(tmp_path)
    scratchpad = source / ".scratchpad"
    scratchpad.mkdir()
    before = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file()
    }

    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=source,
        project_root=source,
        job_id="medusa-fuzz",
        language="evm",
        role="medusa_fuzz",
        run_id="RUN-1",
        source_snapshot_digest="b" * 64,
    )

    assert receipt["status"] == "READY"
    active = Path(str(receipt["active_root"]))
    quarantine = Path(str(receipt["quarantine_root"]))
    assert (active / "src" / "Counter.sol").is_file()
    assert (active / "foundry.toml").is_file()
    assert not (active / "test" / "invariant" / "Existing.t.sol").exists()
    assert not (active / ".medusa-tests" / "ExistingHarness.sol").exists()
    assert not (active / "medusa.json").exists()
    assert (quarantine / "test" / "invariant" / "Existing.t.sol").is_file()
    assert (quarantine / ".medusa-tests" / "ExistingHarness.sol").is_file()
    assert (quarantine / "medusa.json").is_file()
    assert receipt["denominators"]["test"]["count"] == 3
    after = {
        path.relative_to(source).as_posix(): path.read_bytes()
        for path in source.rglob("*")
        if path.is_file() and ".scratchpad" not in path.parts
    }
    assert after == before


def test_exact_denominators_are_sorted_digest_bound_and_collision_safe(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    records = receipt["inputs"]
    assert [row["relative_path"] for row in records] == sorted(
        row["relative_path"] for row in records
    )
    assert len({row["relative_path"] for row in records}) == len(records)
    assert fwa.validate_fuzz_workspace_authority(
        Path(str(receipt["authority_path"])), check_source=True
    ) == []
    payload = _load(str(receipt["authority_path"]))
    assert payload["payload_digest"] == fwa.payload_digest(payload)
    for category in ("source", "configuration", "test", "dependency"):
        denominator = payload["denominators"][category]
        assert denominator["set_digest"] == fwa.record_set_digest(
            [row for row in payload["inputs"] if row["category"] == category]
        )


def test_resume_is_idempotent_but_dirty_or_tampered_workspace_is_unscored(
    tmp_path: Path,
) -> None:
    first = _materialize(tmp_path)
    authority = Path(str(first["authority_path"]))
    original_bytes = authority.read_bytes()
    second = fwa.materialize_fuzz_workspace(
        scratchpad=Path(str(first["scratchpad_root"])),
        build_root=Path(str(first["source_root"])),
        project_root=Path(str(first["project_root"])),
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-1",
        source_snapshot_digest="a" * 64,
        allowed_tools=(Path(sys.executable).name,),
    )
    assert second["status"] == "READY"
    assert authority.read_bytes() == original_bytes

    active_source = Path(str(first["active_root"])) / "src" / "Counter.sol"
    active_source.chmod(0o644)
    active_source.write_text("mutated\n", encoding="utf-8")
    issues = fwa.validate_fuzz_workspace_authority(authority, check_source=True)
    assert any("WORKSPACE_INPUT_DRIFT" in issue for issue in issues)
    dirty = fwa.materialize_fuzz_workspace(
        scratchpad=Path(str(first["scratchpad_root"])),
        build_root=Path(str(first["source_root"])),
        project_root=Path(str(first["project_root"])),
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-1",
        source_snapshot_digest="a" * 64,
        allowed_tools=(Path(sys.executable).name,),
    )
    assert dirty["status"] == "UNSCORED"
    assert Path(str(dirty["debt_path"])).is_file()
    assert "WORKSPACE_INPUT_DRIFT" in json.dumps(_load(str(dirty["debt_path"])))


@pytest.mark.parametrize(
    ("limit_name", "limit_value", "debt_code"),
    [
        ("max_files", 1, "INPUT_FILE_COUNT_LIMIT"),
        ("max_total_bytes", 8, "INPUT_BYTE_LIMIT"),
    ],
)
def test_bounded_materialization_is_atomic_and_visible_debt(
    tmp_path: Path,
    limit_name: str,
    limit_value: int,
    debt_code: str,
) -> None:
    receipt = _materialize(tmp_path, **{limit_name: limit_value})
    assert receipt["status"] == "UNSCORED"
    assert not Path(str(receipt["active_root"])).exists()
    debt = _load(str(receipt["debt_path"]))
    assert debt["status"] == "UNSCORED"
    assert any(item["code"] == debt_code for item in debt["issues"])


def test_links_and_reparse_points_fail_closed_without_path_escape(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    outside = tmp_path / "outside.sol"
    outside.write_text("contract Outside {}\n", encoding="utf-8")
    link = root / "src" / "escape.sol"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation unavailable on this host")
    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-1",
        source_snapshot_digest="c" * 64,
    )
    assert receipt["status"] == "UNSCORED"
    debt = _load(str(receipt["debt_path"]))
    assert any(item["code"] == "UNSAFE_LINK_OR_REPARSE" for item in debt["issues"])
    assert outside.read_text(encoding="utf-8") == "contract Outside {}\n"


def test_source_toctou_fails_without_publishing_partial_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = fwa._stable_read
    calls = {"count": 0}

    def unstable(path: Path, *args: object, **kwargs: object) -> bytes:
        if path.name == "Counter.sol":
            calls["count"] += 1
            raise fwa.FuzzWorkspaceError("SOURCE_TOCTOU", "changed during read")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(fwa, "_stable_read", unstable)
    receipt = _materialize(tmp_path)
    assert receipt["status"] == "UNSCORED"
    assert calls["count"] == 1
    assert not Path(str(receipt["active_root"])).exists()
    assert "SOURCE_TOCTOU" in json.dumps(_load(str(receipt["debt_path"])))


def test_recorded_runner_binds_tool_command_version_logs_and_result(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    generated = Path(str(receipt["generated_root"]))
    generated.mkdir(parents=True, exist_ok=True)
    harness = generated / "Harness.txt"
    harness.write_text("generated harness\n", encoding="utf-8")
    harness_bytes = harness.read_bytes()

    rc = fwa.run_recorded_command(
        authority,
        [sys.executable, "-c", "print('campaign-result')"],
        timeout_seconds=30,
    )
    assert rc == 0
    result = fwa.finalize_fuzz_workspace(authority)
    # A probe/build command is exact execution evidence, but it is not evidence
    # that the assigned fuzz campaign ran.
    assert result["status"] == "UNSCORED"
    assert result["campaign_command_count"] == 0
    assert result["campaign_execution_status"] == "NOT_EXECUTED"
    assert any(
        row["code"] == "NO_RECORDED_CAMPAIGN_COMMAND"
        for row in result["issues"]
    )
    assert result["generated_harnesses"] == [
        {
            "relative_path": ".plamen-generated/Harness.txt",
            "size": len(harness_bytes),
            "sha256": hashlib.sha256(harness_bytes).hexdigest(),
        }
    ]
    assert len(result["commands"]) == 1
    command = result["commands"][0]
    assert command["argv"] == [sys.executable, "-c", "print('campaign-result')"]
    assert command["returncode"] == 0
    assert command["tool_version"]["argv"]
    assert command["tool_version"]["output_sha256"]
    stdout_path = Path(str(receipt["workspace_root"])) / command["stdout"]["path"]
    assert stdout_path.is_file()
    assert command["stdout"]["sha256"] == hashlib.sha256(
        stdout_path.read_bytes()
    ).hexdigest()
    assert fwa.validate_fuzz_workspace_result(authority) == []


def test_missing_command_or_unapproved_write_never_becomes_execution_authority(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    active = Path(str(receipt["active_root"]))
    (active / "unexpected.txt").write_text("not in generated lane\n", encoding="utf-8")
    result = fwa.finalize_fuzz_workspace(authority)
    assert result["status"] == "UNSCORED"
    codes = {row["code"] for row in result["issues"]}
    assert "NO_RECORDED_COMMAND" in codes
    assert "WRITE_OUTSIDE_GENERATED_LANE" in codes


def test_runner_rejects_unbound_tool_path_traversal_and_source_drift(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(authority, ["definitely-not-allowed"], 5) == 125
    assert fwa.run_recorded_command(
        authority, [sys.executable, "../escape.py"], 5
    ) == 125
    source = Path(str(receipt["source_root"])) / "src" / "Counter.sol"
    source.write_text("changed after snapshot\n", encoding="utf-8")
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('must-not-run')"], 5
    ) == 125
    debt = _load(str(receipt["debt_path"]))
    assert debt["status"] == "UNSCORED"
    assert any(item["code"] == "SOURCE_DENOMINATOR_DRIFT" for item in debt["issues"])


def test_generated_lane_collision_never_overwrites_quarantined_user_test(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    quarantine = (
        Path(str(receipt["quarantine_root"]))
        / "test" / "invariant" / "Existing.t.sol"
    )
    original = quarantine.read_bytes()
    active_generated = (
        Path(str(receipt["active_root"]))
        / "test" / "invariant" / "Existing.t.sol"
    )
    active_generated.parent.mkdir(parents=True, exist_ok=True)
    active_generated.write_text("driver-owned replacement name\n", encoding="utf-8")
    result = fwa.finalize_fuzz_workspace(Path(str(receipt["authority_path"])))
    assert quarantine.read_bytes() == original
    assert result["status"] == "UNSCORED"  # no recorded command
    assert any(
        row["relative_path"] == "test/invariant/Existing.t.sol"
        for row in result["generated_harnesses"]
    )


def test_cli_runner_is_cross_platform_and_does_not_use_a_shell(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    module = Path(fwa.__file__).resolve()
    completed = subprocess.run(
        [
            sys.executable,
            str(module),
            "run",
            "--authority",
            str(receipt["authority_path"]),
            "--timeout",
            "30",
            "--",
            sys.executable,
            "-c",
            "print('ok')",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    final = subprocess.run(
        [
            sys.executable,
            str(module),
            "finalize",
            "--authority",
            str(receipt["authority_path"]),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert final.returncode == 2, final.stderr
    assert _load(str(receipt["result_path"]))["status"] == "UNSCORED"


def test_recorded_runner_allows_only_generated_subproject_cwd(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    generated_subproject = Path(str(receipt["active_root"])) / "test" / "invariant"
    generated_subproject.mkdir(parents=True, exist_ok=True)
    rc = fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        30,
        cwd_relative="test/invariant",
    )
    assert rc == 0
    result = fwa.finalize_fuzz_workspace(Path(str(receipt["authority_path"])))
    assert result["status"] == "UNSCORED"
    assert Path(result["commands"][0]["cwd"]) == generated_subproject.resolve()
    assert fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", "print('no')"],
        30,
        cwd_relative="src",
    ) == 125
    assert fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", "print('no')"],
        30,
        cwd_relative="../project",
    ) == 125


def test_driver_prepares_distinct_workspace_per_fuzz_leaf_and_finalizes_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import plamen_driver as driver

    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "project_root": str(root),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "claude",
        "_run_id": "RUN-DRIVER",
        "_audit_snapshot": {"snapshot_digest": "d" * 64},
    }
    jobs = driver._depth_fuzz_jobs_if_required(scratchpad, config)
    prepared = driver._prepare_depth_fuzz_workspaces(
        jobs, scratchpad=scratchpad, project_root=str(root), config=config
    )
    assert len(prepared) == 2
    assert {job["fuzz_workspace_status"] for job in prepared} == {"READY"}
    assert len({job["fuzz_workspace_root"] for job in prepared}) == 2
    assert all(Path(job["fuzz_authority_path"]).is_file() for job in prepared)
    assert (root / "test" / "invariant" / "Existing.t.sol").is_file()

    job = prepared[0]
    output = scratchpad / job["output"]
    output.write_text(
        "# Fuzz\n\n## Result Status: RAN\n\n<!-- PLAMEN_STATUS: COMPLETE -->\n",
        encoding="utf-8",
    )
    before = output.read_bytes()
    assert fwa.run_recorded_command(
        Path(job["fuzz_authority_path"]),
        [sys.executable, "-c", "print('driver-bound')"],
        30,
    ) == 125  # production authority does not allow the test-only Python tool
    result = driver._finalize_depth_fuzz_workspace(scratchpad, job)
    assert result["status"] == "UNSCORED"
    assert output.read_bytes() == before
    assert Path(job["fuzz_result_path"]).is_file()


def test_driver_missing_audit_snapshot_is_haltless_but_never_execution_ready(
    tmp_path: Path,
) -> None:
    import plamen_driver as driver

    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "project_root": str(root),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "claude",
        "_run_id": "RUN-UNBOUND",
    }
    jobs = driver._prepare_depth_fuzz_workspaces(
        driver._depth_fuzz_jobs_if_required(scratchpad, config),
        scratchpad=scratchpad,
        project_root=str(root),
        config=config,
    )
    assert jobs and {job["fuzz_workspace_status"] for job in jobs} == {"UNSCORED"}
    for job in jobs:
        debt = _load(job["fuzz_debt_path"])
        assert debt["status"] == "UNSCORED"
        assert any(row["code"] == "SOURCE_SNAPSHOT_UNBOUND" for row in debt["issues"])


def test_driver_aggregate_result_index_has_one_phaseio_owner(
    tmp_path: Path,
) -> None:
    import plamen_driver as driver

    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    config = {
        "project_root": str(root),
        "pipeline": "sc",
        "language": "evm",
        "mode": "thorough",
        "cli_backend": "claude",
        "_run_id": "RUN-AGGREGATE",
        "_audit_snapshot": {"snapshot_digest": "e" * 64},
    }
    jobs = driver._prepare_depth_fuzz_workspaces(
        driver._depth_fuzz_jobs_if_required(scratchpad, config),
        scratchpad=scratchpad,
        project_root=str(root),
        config=config,
    )
    for job in jobs:
        (scratchpad / job["output"]).write_text(
            f"## Finding [{ 'FUZZ-1' if job['role'] == 'invariant_fuzz' else 'MEDUSA-1' }]\n\n"
            "**Evidence Tag**: [FUZZ-PASS]\n",
            encoding="utf-8",
        )
    assert driver._record_depth_fuzz_result_index(
        scratchpad=scratchpad, jobs=jobs, config=config
    ) == []
    result_path = scratchpad / fwa.RESULT_INDEX_FILE
    assert fwa.validate_fuzz_workspace_result_index(result_path) == []
    ledger = _load(scratchpad / "_artifact_state.json")
    owner = (
        "sc/thorough/evm/claude/depth/fuzz_workspace.finalize.all"
    )
    artifact = ledger["artifact_bindings"][
        "scratchpad:fuzz_workspace_result_index.json"
    ]
    assert artifact["owner_key"] == owner


def test_missing_fuzz_index_is_launch_fatal_while_other_missing_inputs_degrade() -> None:
    import plamen_driver as driver

    issue = (
        "semantic input missing at binding: "
        "scratchpad:fuzz_workspace_index.json"
    )
    assert driver._typed_worker_input_issue_is_fatal(
        "invariant_fuzz_results.md", issue
    )
    assert driver._typed_worker_input_issue_is_fatal(
        "medusa_fuzz_findings.md", issue
    )
    assert not driver._typed_worker_input_issue_is_fatal(
        "depth_state_trace_findings.md", issue
    )


def test_direct_dispatch_caller_cannot_retain_unindexed_ready_status(
    tmp_path: Path,
) -> None:
    import plamen_driver as driver

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    job = {
        "agent_id": "invariant-fuzz",
        "role": "invariant_fuzz",
        "output": "invariant_fuzz_results.md",
        "category": "fuzz",
        "fuzz_workspace_status": "READY",
        "fuzz_authority_path": str(tmp_path / "forged-authority.json"),
        "fuzz_authority_digest": "f" * 64,
    }
    issues = driver._bind_depth_fuzz_job_to_index(
        scratchpad=scratchpad, job=job
    )
    assert issues
    assert job["fuzz_workspace_status"] == "UNSCORED"


def test_all_live_fuzz_prompts_forbid_unrecorded_or_quarantined_execution() -> None:
    root = Path(__file__).parents[1]
    prompts = [
        root / "prompts/evm/v2/phase4b-invariant-fuzz.md",
        root / "prompts/evm/v2/phase4b-medusa-fuzz.md",
        root / "prompts/solana/v2/phase4b-invariant-fuzz.md",
        root / "prompts/soroban/v2/phase4b-invariant-fuzz.md",
        root / "prompts/sui/v2/phase4b-invariant-fuzz.md",
    ]
    for path in prompts:
        text = path.read_text(encoding="utf-8")
        assert "P2-A execution boundary" in text, path
        assert "recorded runner" in text, path
        assert "quarantined" in text, path
        assert "original" in text and "root" in text, path
    medusa = prompts[1].read_text(encoding="utf-8")
    assert "USE IT" not in medusa
    assert "go install" not in medusa
    assert "cannot be installed" not in medusa
    assert "npx hardhat" not in medusa
    assert "medusa unavailable AND copied build root NOT Foundry-usable" not in medusa
    solana = prompts[2].read_text(encoding="utf-8")
    soroban = prompts[3].read_text(encoding="utf-8")
    assert "Read `trident_available`" not in solana
    assert "trident --version" in solana
    assert "cargo test" in solana
    assert "Read `cargo_fuzz_available`" not in soroban
    assert "cargo --version" in soroban


def test_phase_io_binds_fuzz_authority_and_driver_result_as_typed_artifacts() -> None:
    from phase_io_contracts import resolve_phase_io_contract

    contract = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="worker.invariant-fuzz",
        exact_outputs=("invariant_fuzz_results.md",),
    )
    immutable = set(contract.immutable_inputs)
    assert "scratchpad:fuzz_workspace_index.json" in immutable
    finalization = resolve_phase_io_contract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="depth",
        work_unit_id="fuzz_workspace.finalize.all",
        exact_inputs=(
            "fuzz_workspace_index.json",
            "invariant_fuzz_results.md",
        ),
        exact_outputs=("fuzz_workspace_result_index.json",),
        exact_writer="DRIVER",
    )
    assert finalization.model_invoked is False
    assert {spec.identity for spec in finalization.outputs} == {
        "scratchpad:fuzz_workspace_result_index.json"
    }


def test_legacy_claude_depth_prompt_uses_only_workspace_for_fuzz_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import plamen_driver as driver

    receipt = _materialize(tmp_path)
    scratchpad = Path(str(receipt["scratchpad_root"]))
    job = {
        "agent_id": "invariant-fuzz",
        "role": "invariant_fuzz",
        "output": "invariant_fuzz_results.md",
        "category": "fuzz",
        "focus": "bounded invariant campaign",
        "fuzz_workspace_status": "READY",
        "fuzz_workspace_root": str(receipt["workspace_root"]),
        "fuzz_active_root": str(receipt["active_root"]),
        "fuzz_generated_root": str(receipt["generated_root"]),
        "fuzz_quarantine_root": str(receipt["quarantine_root"]),
        "fuzz_authority_path": str(receipt["authority_path"]),
        "fuzz_runner_path": str(Path(fwa.__file__).resolve()),
    }
    monkeypatch.setattr(driver, "plamen_home", lambda: Path(__file__).parents[1])
    prompt = driver._build_depth_worker_prompt(
        job=job,
        scratchpad=scratchpad,
        project_root=str(receipt["project_root"]),
        config={
            "pipeline": "sc",
            "language": "evm",
            "mode": "thorough",
            "cli_backend": "claude",
        },
        attempt=1,
    )
    assert str(receipt["active_root"]).replace("\\", "/") in prompt
    assert str(receipt["authority_path"]).replace("\\", "/") in prompt
    assert "fuzz_workspace_authority.py" in prompt
    assert "run --authority" in prompt
    assert Path(sys.executable).resolve().as_posix() in prompt
    assert "Do not execute any pre-existing quarantined test" in prompt
    assert "do not write to the original project/build root" in prompt.lower()


@pytest.mark.parametrize(
    ("language", "role", "argv", "expected"),
    [
        ("evm", "invariant_fuzz", ["forge", "build"], ""),
        (
            "evm",
            "invariant_fuzz",
            ["forge", "test", "--match-contract", "GeneratedInvariant"],
            "FOUNDRY_INVARIANT",
        ),
        ("evm", "medusa_fuzz", ["medusa", "--version"], ""),
        ("evm", "medusa_fuzz", ["medusa", "fuzz", "--timeout", "600"], "MEDUSA_FUZZ"),
        ("solana", "invariant_fuzz", ["trident", "fuzz", "run"], "TRIDENT_FUZZ"),
        ("solana", "invariant_fuzz", ["cargo", "test"], "CARGO_TEST_FALLBACK"),
        ("soroban", "invariant_fuzz", ["cargo", "+nightly", "fuzz", "run", "target"], "CARGO_FUZZ"),
        ("soroban", "invariant_fuzz", ["cargo", "test"], "CARGO_TEST_FALLBACK"),
        ("sui", "invariant_fuzz", ["sui", "move", "build"], ""),
        ("sui", "invariant_fuzz", ["sui", "move", "test"], "SUI_MOVE_TEST"),
    ],
)
def test_campaign_command_classification_is_role_specific(
    language: str,
    role: str,
    argv: list[str],
    expected: str,
) -> None:
    assert fwa._campaign_command_kind(language, role, argv) == expected


def test_timeout_terminates_descendant_process_tree(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    marker = Path(str(receipt["generated_root"])) / "escaped-child.txt"
    child_code = (
        "import pathlib,sys,time; time.sleep(1.5); "
        "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}, sys.argv[1]]); "
        "time.sleep(30)"
    )
    rc = fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", parent_code, str(marker)],
        timeout_seconds=0.3,
    )
    assert rc == 124
    time.sleep(2.0)
    assert not marker.exists(), "timed-out tool left an executable child alive"
    command = fwa._command_receipts(receipt)[0][0]
    assert command["timed_out"] is True
    assert command["process_tree_policy"] in {
        "WINDOWS_JOB_OBJECT_KILL_ON_CLOSE",
        "POSIX_CONTAINMENT_UNAVAILABLE",
    }


def test_receipt_hashes_semantic_inherited_environment_without_disclosing_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FOUNDRY_PROFILE", "secret-profile-value")
    receipt = _materialize(tmp_path)
    assert fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        [sys.executable, "-c", "print('env-bound')"],
        30,
    ) == 0
    command = fwa._command_receipts(receipt)[0][0]
    inherited = command["inherited_environment_fingerprint"]
    row = next(item for item in inherited["variables"] if item["name"] == "FOUNDRY_PROFILE")
    assert row["sha256"] == hashlib.sha256(b"secret-profile-value").hexdigest()
    assert "secret-profile-value" not in json.dumps(command)
    assert inherited["set_digest"] == fwa.record_set_digest(inherited["variables"])


def test_symlink_to_excluded_scratchpad_is_rejected_not_silently_skipped(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "hidden.sol").write_text("contract Hidden {}\n", encoding="utf-8")
    alias = root / "scratchpad-alias"
    try:
        alias.symlink_to(scratchpad, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation unavailable on this host")
    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-LINK",
        source_snapshot_digest="f" * 64,
    )
    assert receipt["status"] == "UNSCORED"
    assert "UNSAFE_LINK_OR_REPARSE" in json.dumps(_load(str(receipt["debt_path"])))


def test_tool_output_lanes_cover_ecosystem_runtime_products(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    assert {".anchor", ".trident", "test-ledger", "Move.lock"}.issubset(
        set(receipt["tool_output_roots"])
    )

    source = tmp_path / "solana-project"
    (source / "programs" / "program" / "src").mkdir(parents=True)
    (source / "programs" / "program" / "src" / "lib.rs").write_text(
        "pub fn entry() {}\n", encoding="utf-8"
    )
    (source / "Anchor.toml").write_text("[programs.localnet]\n", encoding="utf-8")
    solana_scratchpad = source / ".scratchpad"
    solana_scratchpad.mkdir()
    solana = fwa.materialize_fuzz_workspace(
        scratchpad=solana_scratchpad,
        build_root=source,
        project_root=source,
        job_id="invariant-fuzz",
        language="solana",
        role="invariant_fuzz",
        run_id="RUN-SOLANA",
        source_snapshot_digest="e" * 64,
    )
    assert {"Trident.toml", "trident-tests"}.issubset(
        set(solana["generated_write_roots"])
    )


def test_result_and_raw_command_log_tampering_are_detected(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('bound-output')"], 30
    ) == 0
    result = fwa.finalize_fuzz_workspace(authority)
    result_path = Path(str(receipt["result_path"]))
    result_path.write_text(result_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    # Whitespace does not alter parsed JSON; alter a bound semantic field too.
    mutated = _load(result_path)
    mutated["command_count"] = 999
    result_path.write_text(json.dumps(mutated), encoding="utf-8")
    assert any("RESULT_DIGEST_INVALID" in row for row in fwa.validate_fuzz_workspace_result(authority))

    command = result["commands"][0]
    stdout = Path(str(receipt["workspace_root"])) / command["stdout"]["path"]
    stdout.write_bytes(stdout.read_bytes() + b"tamper")
    issues = fwa.validate_fuzz_workspace_result(authority)
    assert any("COMMAND_RECEIPT_INVALID" in row for row in issues)


def test_interrupted_running_receipt_remains_visible_unscored_debt(tmp_path: Path) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('started')"], 30
    ) == 0
    command_path = next(
        (Path(str(receipt["runtime_root"])) / "commands").glob("*-command.json")
    )
    command = _load(command_path)
    command["status"] = "RUNNING"
    command["payload_digest"] = fwa.payload_digest(command)
    command_path.chmod(0o644)
    command_path.write_text(json.dumps(command), encoding="utf-8")
    result = fwa.finalize_fuzz_workspace(authority)
    assert result["status"] == "UNSCORED"
    assert {row["code"] for row in result["issues"]} >= {
        "COMMAND_RECEIPT_INVALID",
        "NO_RECORDED_COMMAND",
        "NO_RECORDED_CAMPAIGN_COMMAND",
    }


def test_rejected_boundary_attempt_survives_finalization_as_integrity_debt(
    tmp_path: Path,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(authority, ["not-approved"], 5) == 125
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('later-valid-probe')"], 30
    ) == 0
    result = fwa.finalize_fuzz_workspace(authority)
    assert result["status"] == "UNSCORED"
    assert "UNAPPROVED_TOOL" in {row["code"] for row in result["issues"]}


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        ([], "NOT_EXECUTED"),
        ([{"returncode": 1, "timed_out": False}], "EXECUTED_FAILED"),
        ([{"returncode": 124, "timed_out": True}], "TIMEOUT"),
        ([{"returncode": 1, "timed_out": False}, {"returncode": 0, "timed_out": False}], "EXECUTED_SUCCESS"),
    ],
)
def test_campaign_execution_status_is_deterministic(
    rows: list[dict[str, object]], expected: str
) -> None:
    assert fwa._campaign_execution_status(rows) == expected


def test_campaign_requires_a_generated_harness_that_matches_executed_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    monkeypatch.setattr(
        fwa, "_campaign_command_kind", lambda language, role, argv: "FIXTURE_CAMPAIGN"
    )
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "print('empty-campaign')"], 30
    ) == 0
    empty = fwa.finalize_fuzz_workspace(authority)
    assert empty["status"] == "UNSCORED"
    assert "CAMPAIGN_WITHOUT_GENERATED_HARNESS" in {
        row["code"] for row in empty["issues"]
    }

    second_root = tmp_path / "second"
    second_root.mkdir()
    bound = _materialize(second_root)
    bound_authority = Path(str(bound["authority_path"]))
    harness = Path(str(bound["generated_root"])) / "Harness.sol"
    harness.write_text("contract Harness {}\n", encoding="utf-8")
    assert fwa.run_recorded_command(
        bound_authority, [sys.executable, "-c", "print('real-campaign')"], 30
    ) == 0
    measured = fwa.finalize_fuzz_workspace(bound_authority)
    assert measured["status"] == "MEASURED"
    assert measured["campaign_execution_status"] == "EXECUTED_SUCCESS"
    assert measured["proof_authority"] == "EXECUTION_SCOPE_REQUIRES_CONSUMER"

    harness.write_text("contract Harness { uint changed; }\n", encoding="utf-8")
    drifted = fwa.finalize_fuzz_workspace(bound_authority)
    assert drifted["status"] == "UNSCORED"
    assert "GENERATED_HARNESS_NOT_EXECUTED" in {
        row["code"] for row in drifted["issues"]
    }


def test_generated_harness_denominator_excludes_mutable_fuzzer_corpus(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="medusa-fuzz",
        language="evm",
        role="medusa_fuzz",
        run_id="RUN-CORPUS",
        source_snapshot_digest="9" * 64,
    )
    generated = Path(str(receipt["active_root"])) / ".medusa-tests"
    (generated / "corpus").mkdir(parents=True)
    (generated / ".fuzz-artifacts").mkdir()
    (generated / "Harness.sol").write_text("contract Harness {}\n", encoding="utf-8")
    (generated / "medusa.json").write_text("{}\n", encoding="utf-8")
    (generated / "corpus" / "seed-1").write_bytes(b"mutable seed")
    (generated / ".fuzz-artifacts" / "trace").write_bytes(b"runtime trace")
    rows = fwa._generated_harness_rows(receipt)
    assert [row["relative_path"] for row in rows] == [
        ".medusa-tests/Harness.sol",
        ".medusa-tests/medusa.json",
    ]


def test_campaign_parser_binds_selector_and_explicit_case_budget() -> None:
    spec = fwa._campaign_command_spec(
        "evm", "invariant_fuzz",
        [
            "forge", "test", "--match-contract", "GeneratedInvariant",
            "--match-test", "invariant_balance", "--invariant-runs", "256",
            "--invariant-depth=25",
        ],
    )
    assert spec == {
        "kind": "FOUNDRY_INVARIANT",
        "tool_family": "forge",
        "selector": {
            "contract": "GeneratedInvariant", "test": "invariant_balance",
        },
        "requested_cases": {"invariant_depth": 25, "invariant_runs": 256},
    }
    assert fwa._campaign_command_spec(
        "evm", "invariant_fuzz",
        ["forge", "test", "--match-contract", "GeneratedInvariant", "--list"],
    ) is None
    assert fwa._campaign_command_spec(
        "soroban", "invariant_fuzz",
        ["cargo", "+nightly", "fuzz", "run", "target", "--", "-runs=10000"],
    )["requested_cases"] == {"runs": 10000}


def test_prepared_campaign_is_backend_neutral_but_not_self_certifying(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    scratchpad = root / ".scratchpad"
    scratchpad.mkdir()
    receipt = fwa.materialize_fuzz_workspace(
        scratchpad=scratchpad,
        build_root=root,
        project_root=root,
        job_id="invariant-fuzz",
        language="evm",
        role="invariant_fuzz",
        run_id="RUN-PREPARED",
        source_snapshot_digest="8" * 64,
        allowed_tools=("forge",),
    )
    harness = Path(str(receipt["generated_root"])) / "GeneratedInvariant.t.sol"
    harness.write_text("contract GeneratedInvariant {}\n", encoding="utf-8")
    contract = fwa.prepare_fuzz_campaign_contract(
        Path(str(receipt["authority_path"])),
        argv=[
            "forge", "test", "--match-contract", "GeneratedInvariant",
            "--invariant-runs", "256",
        ],
        timeout_seconds=600,
        cwd_relative=".",
        selected_harnesses=[".plamen-generated/GeneratedInvariant.t.sol"],
        assertion_ids=["INV-001"],
        expected_case_count=256,
    )
    assert contract["status"] == "UNSCORED"
    assert contract["command_spec"]["kind"] == "FOUNDRY_INVARIANT"
    assert contract["selected_harnesses"][0]["sha256"] == hashlib.sha256(
        harness.read_bytes()
    ).hexdigest()
    assert {row["code"] for row in contract["issues"]} >= {
        "FILESYSTEM_CONTAINMENT_UNAVAILABLE",
    }
    stored = _load(str(contract["contract_path"]))
    assert stored["payload_digest"] == fwa.payload_digest(stored)

    assert fwa.run_recorded_command(
        Path(str(receipt["authority_path"])),
        ["forge", "test", "--match-contract", "GeneratedInvariant"],
        30,
    ) == 125
    debt = _load(str(receipt["debt_path"]))
    assert "COMMAND_PROVENANCE_UNAUTHENTICATED" in {
        row["code"] for row in debt["issues"]
    }


def test_failed_campaign_classification_cannot_be_measured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _materialize(tmp_path)
    authority = Path(str(receipt["authority_path"]))
    assert fwa.run_recorded_command(
        authority, [sys.executable, "-c", "raise SystemExit(3)"], 30
    ) == 3
    monkeypatch.setattr(
        fwa, "_campaign_command_kind", lambda language, role, argv: "FIXTURE_CAMPAIGN"
    )
    result = fwa.finalize_fuzz_workspace(authority)
    assert result["status"] == "UNSCORED"
    assert "CAMPAIGN_EXECUTION_FAILED" in {
        row["code"] for row in result["issues"]
    }
