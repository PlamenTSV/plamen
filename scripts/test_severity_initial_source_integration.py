"""Same-run verifier-to-initial-severity source transaction integration.

This is a transaction/lineage test using the existing deterministic Low
verifier child.  Low is selected in the initial Thorough policy; it is not a
Core acceptance, production PoC-authority, provider-quality, or report proof.
Nonempty typed planning is exercised directly, not through the live handler.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
IMPLEMENTATION_ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(IMPLEMENTATION_ROOT))

from artifact_ledger import LEDGER_NAME, read_artifact_ledger  # noqa: E402
import plamen_driver as driver  # noqa: E402
import severity_initial_source as source  # noqa: E402
import severity_source_aggregate as aggregate  # noqa: E402
import severity_planning as planning  # noqa: E402
import severity_adjudication_work as severity_work  # noqa: E402
from worker_execution_receipts import environment_allowlist_sha256  # noqa: E402
import test_live_verify_queue_main_boundary_a0 as QUEUE  # noqa: E402
import test_verification_report_tail_same_run_integration as TAIL  # noqa: E402
from verify_queue_transaction import (  # noqa: E402
    validate_live_verify_queue_publication,
)


class _InjectedSourceCrash(RuntimeError):
    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _native_tool(env_name: str, candidates: tuple[Path, ...]) -> Path:
    configured = os.environ.get(env_name)
    if configured is not None:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute() or not candidate.is_file():
            pytest.fail(f"{env_name} must name an existing absolute file")
        selected = candidate.resolve(strict=True)
    else:
        selected = next(
            (
                candidate.resolve(strict=True)
                for candidate in candidates
                if candidate.is_file()
            ),
            None,
        )
        if selected is None:
            pytest.skip(f"no explicit native tool is available for {env_name}")
    assert selected.is_file()
    assert os.access(selected, os.X_OK)
    return selected


def _tool_identity(path: Path, version: subprocess.CompletedProcess[bytes]) -> dict[str, Any]:
    observed = path.stat()
    assert version.returncode == 0, version.stderr.decode("utf-8", errors="replace")
    assert version.stdout.strip() or version.stderr.strip()
    return {
        "path": str(path),
        "sha256": _sha256_file(path),
        "size": observed.st_size,
        "device": observed.st_dev,
        "inode": observed.st_ino,
        "mode": observed.st_mode,
        "version_stdout": version.stdout.decode("utf-8", errors="strict"),
        "version_stderr": version.stderr.decode("utf-8", errors="strict"),
    }


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def _run_real_forge_attempts(
    tmp_path: Path, project: Path,
) -> dict[str, Mapping[str, Any]]:
    """Run exact dependency-free selectors and retain local-only evidence."""

    user_root = Path.home()
    forge = _native_tool(
        "PLAMEN_TEST_FORGE",
        (user_root / ".foundry" / "bin" / "forge",),
    )
    solc_candidates = (
        user_root / "Library" / "Application Support" / "svm" / "0.8.26"
        / "solc-0.8.26",
        user_root / ".svm" / "0.8.26" / "solc-0.8.26",
    )
    solc = _native_tool("PLAMEN_TEST_SOLC", solc_candidates)

    isolated_home = tmp_path / "forge-home"
    isolated_tmp = tmp_path / "forge-tmp"
    evidence_root = tmp_path / "forge-attempt-evidence"
    build_root = tmp_path / "forge-build"
    for directory in (isolated_home, isolated_tmp, evidence_root, build_root):
        directory.mkdir()
    process_env = {
        "HOME": str(isolated_home),
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(isolated_tmp),
        "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1",
        "NO_COLOR": "1",
    }
    forge_version = subprocess.run(
        (str(forge), "--version"), cwd=project, env=process_env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        check=False,
    )
    solc_version = subprocess.run(
        (str(solc), "--version"), cwd=project, env=process_env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        check=False,
    )
    forge_identity = _tool_identity(forge, forge_version)
    solc_identity = _tool_identity(solc, solc_version)
    assert "forge Version: 1.5.1-" in (
        forge_identity["version_stdout"] + forge_identity["version_stderr"]
    )
    assert "Version: 0.8.26+" in (
        solc_identity["version_stdout"] + solc_identity["version_stderr"]
    )

    test_path = project / "test" / "Unit.t.sol"
    test_sha256 = _sha256_file(test_path)
    attempts: dict[str, Mapping[str, Any]] = {}
    for number in (1, 2, 3):
        candidate_id = f"INV-{number}"
        function_name = f"test_INV_{number}"
        output_root = build_root / f"out-{number}"
        cache_root = build_root / f"cache-{number}"
        argv = (
            str(forge), "test", "--root", str(project),
            "--match-path", "test/Unit.t.sol",
            "--match-contract", "UnitPoCTest",
            "--match-test", function_name,
            "--json", "--offline", "--use", str(solc),
            "--out", str(output_root), "--cache-path", str(cache_root),
        )
        completed = subprocess.run(
            argv, cwd=project, env=process_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, check=False,
        )
        stdout_path = evidence_root / f"{candidate_id}.stdout"
        stderr_path = evidence_root / f"{candidate_id}.stderr"
        stdout_path.write_bytes(completed.stdout)
        stderr_path.write_bytes(completed.stderr)
        assert completed.returncode == 0, completed.stderr.decode(
            "utf-8", errors="replace"
        )
        result = json.loads(completed.stdout.decode("utf-8", errors="strict"))
        assert isinstance(result, dict)
        observed_rows: list[tuple[str, str, Mapping[str, Any]]] = []
        for suite_name, suite in result.items():
            if not isinstance(suite, Mapping):
                continue
            rows = suite.get("test_results")
            if not isinstance(rows, Mapping):
                continue
            for observed_name, row in rows.items():
                assert isinstance(row, Mapping)
                observed_rows.append((str(suite_name), str(observed_name), row))
        assert len(observed_rows) == 1, observed_rows
        suite_name, observed_name, selected_row = observed_rows[0]
        assert suite_name == "test/Unit.t.sol:UnitPoCTest"
        assert observed_name == f"{function_name}()"
        assert selected_row.get("status") == "Success"
        receipt_core = {
            "schema": "plamen.test.real-forge-selection.v1",
            "candidate_id": candidate_id,
            "command": list(argv),
            "command_text": shlex.join(argv),
            "returncode": completed.returncode,
            "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
            "forge": forge_identity,
            "solc": solc_identity,
            "test_file": "test/Unit.t.sol",
            "test_file_sha256": test_sha256,
            "selected_suite": suite_name,
            "selected_test": observed_name,
            "selected_result": dict(selected_row),
        }
        receipt = {
            **receipt_core,
            "receipt_sha256": hashlib.sha256(_canonical(receipt_core)).hexdigest(),
        }
        (evidence_root / f"{candidate_id}.selection.json").write_bytes(
            _canonical(receipt) + b"\n"
        )
        attempts[candidate_id] = receipt

    assert evidence_root.parent == project.parent
    assert evidence_root != project and project not in evidence_root.parents
    return attempts


def _attempted_verifier_bytes(
    work_id: str, attempts: Mapping[str, Mapping[str, Any]],
) -> bytes:
    receipt = attempts[work_id]
    return (
        f"# Verification: {work_id}\n\n"
        f"**Finding ID**: {work_id}\n\n"
        "**Severity**: Low\n\n"
        "**Verdict**: CONTESTED\n\n"
        "**Location**: `src/Unit.sol:L1`\n\n"
        "**Evidence Tag**: [CODE-TRACE] [POC-PASS]\n\n"
        "The bounded local harness executed the exact selected setter test. "
        "This establishes transaction-fixture evidence only and does not "
        "establish production candidate execution authority. The candidate's "
        "external premise remains unproven. "
        "[EXTERNAL-ASSUMPTION: fixture condition]\n\n"
        "**PoC Class**: unit\n\n"
        "### PoC Attempt\n"
        "- PoC Required: YES\n"
        "- Attempted: YES\n"
        "- Test File: `test/Unit.t.sol`\n"
        f"- Command: `{receipt['command_text']}`\n\n"
        "### Execution Result\n"
        "- Result: PASS\n"
        f"- Local Fixture Receipt SHA-256: `{receipt['receipt_sha256']}`\n"
    ).encode("utf-8")


def _unit_by_suffix(
    ledger: Mapping[str, Any], suffix: str,
) -> tuple[str, Mapping[str, Any]]:
    matches = [
        (key, row)
        for key, row in ledger["work_units"].items()
        if key.endswith(suffix)
    ]
    assert len(matches) == 1, (suffix, matches)
    return matches[0]


def _assert_nonempty_planning_recovery(
    root: Path, project: Path, config: Mapping[str, Any],
    candidate_ids: tuple[str, ...], monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Explicit initial fixture capacity for complete repository methodology
    # plus candidate evidence. This does not change production defaults or
    # retry an overflow with a larger budget. Two items force multiple shards.
    args = {
        "backend": "codex", "transport": "posix-v2-compat",
        "effective_model": "gpt-5.6-sol",
        "working_directory": str(project), "source_root": str(project),
        "tool_policy": ["read-bound-inputs-and-source", "write-assigned-staging-only"],
        "environment_allowlist_digest": environment_allowlist_sha256(()),
        "adjudicator_identity": "independent-severity-adjudicator",
        "invocation_prefix": "same-run-severity-planning",
        "timeout_seconds_per_worker": 30,
        "max_items_per_worker": 2, "max_weight_per_worker": 32,
        "max_context_bytes_per_worker": 262_144,
    }
    kwargs = dict(
        scratchpad=root, project_root=project,
        implementation_root=IMPLEMENTATION_ROOT, config=config,
        planning_args=args,
    )
    source_bytes = (root / aggregate.INITIAL_SNAPSHOT_NAME).read_bytes()
    initial_rows = json.loads(source_bytes)["decisions"]
    assert {row["status"] for row in initial_rows} == {"CHALLENGE_REQUIRED"}
    assert {row["candidate_id"] for row in initial_rows} == set(candidate_ids)

    def planning_fault(point: str) -> None:
        if point == "after_output_3":
            raise _InjectedSourceCrash("nonempty planning after_output_3")

    with pytest.raises(_InjectedSourceCrash, match="nonempty planning after_output_3"):
        planning.run_severity_planning(**kwargs, fault_hook=planning_fault)
    interrupted = read_artifact_ledger(root)
    key, row = _unit_by_suffix(interrupted, "/severity_adjudication_shadow/planning")
    assert row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    assert row["artifacts"] == {}
    names = row["preexecution_authority"]["output_names"]
    prefix = {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in names if (root / name).exists()
    }
    assert list(prefix) == names[:3]
    assert all(f"scratchpad:{name}" not in interrupted["artifact_bindings"] for name in names)
    plan = planning.run_severity_planning(**kwargs)
    assert plan["denominator_count"] == len(candidate_ids)
    assert set(plan["denominator_ids"]) == set(candidate_ids)
    assert plan["debt_items"] == []
    assert plan["launch_count"] >= 2
    scheduled = [item for shard in plan["shards"] for item in shard["candidate_ids"]]
    assert sorted(scheduled) == sorted(candidate_ids)
    assert len(scheduled) == len(set(scheduled))
    assert severity_work.validate_prepared_work(root) == []
    assert {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in prefix
    } == prefix
    committed = read_artifact_ledger(root)
    assert committed["work_units"][key]["execution_state"] == "OUTPUT_COMMITTED"
    assert set(committed["work_units"][key]["artifacts"]) == {
        f"scratchpad:{name}" for name in names
    }
    assert all(committed["artifact_bindings"][f"scratchpad:{name}"]["owner_key"] == key for name in names)
    frozen = {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in names
    }
    frozen_ledger = (root / LEDGER_NAME).read_bytes()

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("committed nonempty planning must not rederive")

    with monkeypatch.context() as replay_patch:
        replay_patch.setattr(planning, "derive_adjudication_work", forbidden)
        assert planning.run_severity_planning(**kwargs) == plan
    assert (root / LEDGER_NAME).read_bytes() == frozen_ledger
    assert {
        name: ((root / name).read_bytes(), (root / name).stat().st_mtime_ns)
        for name in names
    } == frozen
    assert (root / aggregate.INITIAL_SNAPSHOT_NAME).read_bytes() == source_bytes
    assert (root / aggregate.OUTPUT_NAME).read_bytes() == source_bytes


@pytest.mark.posix_only
def test_same_run_low_verifier_source_publication_recovers_without_relaunch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resume only the DRIVER source transaction after MODEL/control commit."""

    if os.name != "posix":
        pytest.skip("deterministic verifier child requires the POSIX runtime")

    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "test").mkdir()
    (project / "src" / "Unit.sol").write_text(
        "pragma solidity 0.8.26;\n"
        "contract Unit { uint256 public value; "
        "function setValue(uint256 next) external { value = next; } }\n",
        encoding="utf-8",
    )
    (project / "test" / "Unit.t.sol").write_text(
        "pragma solidity 0.8.26;\n"
        "import {Unit} from '../src/Unit.sol';\n"
        "contract UnitPoCTest {\n"
        " function test_INV_1() public { _check(1); }\n"
        " function test_INV_2() public { _check(2); }\n"
        " function test_INV_3() public { _check(3); }\n"
        " function _check(uint256 next) internal {\n"
        "  Unit target = new Unit(); target.setValue(next);\n"
        "  require(target.value() == next, 'setter mismatch');\n"
        " }\n"
        "}\n",
        encoding="utf-8",
    )
    (project / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\n",
        encoding="utf-8",
    )
    attempts = _run_real_forge_attempts(tmp_path, project)
    assert set(attempts) == {"INV-1", "INV-2", "INV-3"}
    TAIL._install_supported_queue_seed(
        monkeypatch, severity="Low", mode="thorough",
    )
    root, config, run_id = QUEUE._seed(
        project, pipeline="sc", backend="codex",
        preseed_adapter_successors=False,
    )
    # Production recon closes the external-dependency denominator before the
    # verification queue exists.  This composed fixture starts at the queue
    # boundary, so explicitly run that same deterministic DRIVER producer
    # here.  With no unvendored dependency obligations this publishes the
    # authenticated zero-research projection; it does not launch a provider
    # and does not fabricate an R-EXT MODEL result.
    dependency = driver._ensure_recon_dependency_parity(
        root, str(project), config,
    )
    assert dependency["expected_ids"] == []
    assert dependency["researched"] == dependency["unresolved"] == 0
    dependency_ledger = read_artifact_ledger(root)
    dependency_binding = dependency_ledger["artifact_bindings"][
        "scratchpad:external_dependency_research.md"
    ]
    assert dependency_binding["owner_key"].endswith(
        "/recon/dependency_reconcile"
    )
    assert dependency_binding["run_id"] == run_id
    assert dependency_binding["status"] == "ACTIVE"
    assert not (root / "recon_external_dependency_research.md").exists()

    # Production SC semantic dedup precedes verify-queue publication.  This
    # fixture has no candidate dedup signal, so publish the genuine typed
    # preserve-all DRIVER transaction used by the Core zero-entry path.  It
    # does not claim MODEL review or absence of duplicates, and the source
    # inventory remains byte-for-byte under its original producer.
    inventory_path = root / "findings_inventory.md"
    inventory_before = inventory_path.read_bytes()
    inventory_binding_before = dict(
        dependency_ledger["artifact_bindings"][
            "scratchpad:findings_inventory.md"
        ]
    )
    assert driver._run_sc_semantic_dedup_noop(
        root, config, "fixture conservative preserve-all"
    ) == ["dedup_decisions.md", "findings_inventory_deduped.md"]
    assert inventory_path.read_bytes() == inventory_before
    assert (root / "findings_inventory_deduped.md").read_bytes() == (
        inventory_before
    )
    dedup_ledger = read_artifact_ledger(root)
    assert dedup_ledger["artifact_bindings"][
        "scratchpad:findings_inventory.md"
    ] == inventory_binding_before
    dedup_owner = dedup_ledger["artifact_bindings"][
        "scratchpad:dedup_decisions.md"
    ]["owner_key"]
    assert dedup_owner.endswith(
        "/sc_semantic_dedup/noop_passthrough"
    )
    for relative in (
        "dedup_decisions.md",
        "findings_inventory_deduped.md",
    ):
        binding = dedup_ledger["artifact_bindings"][f"scratchpad:{relative}"]
        assert binding["owner_key"] == dedup_owner
        assert binding["run_id"] == run_id
        assert binding["status"] == "ACTIVE"
    queue_phase, phases = QUEUE._phase_and_graph("sc")
    checkpoint = QUEUE._checkpoint(root, config, run_id)
    queue_outcome = QUEUE._invoke(
        boundary=QUEUE._boundary(), phase=queue_phase,
        checkpoint=checkpoint, root=root, config=config, phases=phases,
    )
    assert queue_outcome["state"] == "COMMITTED", queue_outcome
    assert validate_live_verify_queue_publication(
        scratchpad=root,
        project_root=project,
        plan=queue_outcome["cutover_result"]["plan"],
        run_id=run_id,
    )["safe_to_consume"] is True

    verifier_phase = next(
        phase for phase in phases
        if phase.name == driver._dynamic_verifier_coordinator_map(config)["low_info"]
    )
    roster_outcome = driver._prepare_dynamic_verifier_roster(
        root, config,
        next(phase for phase in phases if phase.name == "sc_verify_crithigh"),
    )
    assert roster_outcome.debts == ()
    assert roster_outcome.roster is not None
    assert len(roster_outcome.roster.work_units) == 1
    verifier_unit = roster_outcome.roster.work_units[0]
    assert verifier_unit.tier_pool == "low_info"
    assert verifier_unit.ordered_work_item_ids

    child_launches = 0
    real_child = driver._run_one_codex_exec

    def counted_child(*args: Any, **kwargs: Any) -> Any:
        nonlocal child_launches
        contract = kwargs.get("phase_io_contract")
        phase = kwargs.get("phase")
        if (
            getattr(phase, "name", "") == verifier_phase.name
            and str(getattr(contract, "key", "")).endswith(
                f"/method_model.{verifier_unit.work_unit_id}"
            )
        ):
            child_launches += 1
        return real_child(*args, **kwargs)

    real_publish = source.publish_source_decisions
    source_calls = 0

    def crash_once_after_output(**kwargs: Any) -> tuple[Path, ...]:
        nonlocal source_calls
        source_calls += 1
        if source_calls != 1:
            return real_publish(**kwargs)

        def fault(point: str) -> None:
            if point == "after_output_1":
                raise _InjectedSourceCrash(point)

        return real_publish(**kwargs, fault_hook=fault)

    monkeypatch.setattr(driver, "_run_one_codex_exec", counted_child)
    monkeypatch.setattr(source, "publish_source_decisions", crash_once_after_output)
    monkeypatch.setattr(
        TAIL, "_low_verifier_bytes",
        lambda work_id: _attempted_verifier_bytes(work_id, attempts),
    )
    resumed = False

    def assert_crash_and_resume_inside_live_session() -> None:
        nonlocal resumed
        assert child_launches == 1
        assert source_calls == 1
        failed_phase = checkpoint.phase_commits[verifier_phase.name]
        assert failed_phase.state == "INCOMPLETE_WITH_DEBT"
        assert verifier_phase.name not in checkpoint.completed
        failed_gates = {failure.gate_id for failure in failed_phase.unresolved_failures}
        assert failed_gates

        ledger_after_crash = read_artifact_ledger(root)
        control_key, control_row = _unit_by_suffix(
            ledger_after_crash,
            f"/{verifier_phase.name}/method_receipt."
            f"{verifier_unit.work_unit_id}",
        )
        assert control_row["execution_state"] == "OUTPUT_COMMITTED"
        assert control_row["model_invoked"] is False
        source_key, source_row = _unit_by_suffix(
            ledger_after_crash,
            "/severity_adjudication_shadow/"
            f"source_decisions.{verifier_unit.work_unit_id}",
        )
        assert source_row["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert source_row["artifacts"] == {}

        receipt_bytes = {
            work_id: (root / f"verify_{work_id}.receipt.json").read_bytes()
            for work_id in verifier_unit.ordered_work_item_ids
        }
        control_row_bytes = json.dumps(
            control_row, sort_keys=True, separators=(",", ":"),
        )
        for index, work_id in enumerate(verifier_unit.ordered_work_item_ids):
            binding = ledger_after_crash["artifact_bindings"][
                f"scratchpad:verify_{work_id}.receipt.json"
            ]
            assert binding["owner_key"] == control_key
            decision = root / f"verify_{work_id}.severity_decision.json"
            assert decision.is_file() is (index == 0)
            if index == 0:
                assert f"scratchpad:{decision.name}" not in ledger_after_crash[
                    "artifact_bindings"
                ]

        # The coordinator observes a committed verifier control receipt and
        # must replay it, resume only the armed source transaction, and never
        # relaunch the already committed deterministic child.
        assert driver._handle_dynamic_verifier_phase(
            verifier_phase, checkpoint, root, config, phases,
            phase_idx=phases.index(verifier_phase), total_active=len(phases),
        ) is True
        assert child_launches == 1
        assert source_calls == 2

        committed = read_artifact_ledger(root)
        recovered_phase = checkpoint.phase_commits[verifier_phase.name]
        assert recovered_phase.state == "CLEAN"
        assert recovered_phase.unresolved_failures == ()
        assert {event.gate_id for event in recovered_phase.clearance_events} == failed_gates
        assert all(event.gate_id == event.clearing_gate_id for event in recovered_phase.clearance_events)
        assert json.dumps(
            committed["work_units"][control_key],
            sort_keys=True,
            separators=(",", ":"),
        ) == control_row_bytes
        _source_key, committed_source = _unit_by_suffix(
            committed,
            "/severity_adjudication_shadow/"
            f"source_decisions.{verifier_unit.work_unit_id}",
        )
        assert _source_key == source_key
        assert committed_source["execution_state"] == "OUTPUT_COMMITTED"
        assert committed_source["model_invoked"] is False
        for work_id, raw in receipt_bytes.items():
            assert (root / f"verify_{work_id}.receipt.json").read_bytes() == raw
            assert committed["artifact_bindings"][
                f"scratchpad:verify_{work_id}.receipt.json"
            ]["owner_key"] == control_key
            assert committed["artifact_bindings"][
                f"scratchpad:verify_{work_id}.severity_decision.json"
            ]["owner_key"] == source_key

        assert driver._dynamic_verifier_unit_gate_issues(
            root, verifier_phase.name, roster_outcome.roster,
            verifier_unit, config,
        ) == []
        committed_source_bytes = {
            work_id: (
                root / f"verify_{work_id}.severity_decision.json"
            ).read_bytes()
            for work_id in verifier_unit.ordered_work_item_ids
        }
        committed_source_row = json.dumps(
            committed["work_units"][source_key],
            sort_keys=True, separators=(",", ":"),
        )
        assert driver._handle_dynamic_verifier_phase(
            verifier_phase, checkpoint, root, config, phases,
            phase_idx=phases.index(verifier_phase), total_active=len(phases),
        ) is True
        replayed = read_artifact_ledger(root)
        assert child_launches == 1
        assert source_calls == 2
        assert json.dumps(
            replayed["work_units"][source_key],
            sort_keys=True, separators=(",", ":"),
        ) == committed_source_row
        assert {
            work_id: (
                root / f"verify_{work_id}.severity_decision.json"
            ).read_bytes()
            for work_id in verifier_unit.ordered_work_item_ids
        } == committed_source_bytes
        assert not (root / aggregate.OUTPUT_NAME).exists()
        assert not (root / aggregate.INITIAL_SNAPSHOT_NAME).exists()

        def aggregate_fault(point: str) -> None:
            if point == "after_output_1":
                raise _InjectedSourceCrash("aggregate after_output_1")

        aggregate_args = dict(scratchpad=root, project_root=project, config=config)
        with pytest.raises(_InjectedSourceCrash, match="aggregate after_output_1"):
            aggregate.run_severity_source_aggregate(
                **aggregate_args, fault_hook=aggregate_fault,
            )
        partial_aggregate = read_artifact_ledger(root)
        aggregate_key, aggregate_record = _unit_by_suffix(
            partial_aggregate, "/severity_adjudication_shadow/source_aggregate",
        )
        assert aggregate_record["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
        assert aggregate_record["artifacts"] == {}
        aggregate_identity = f"scratchpad:{aggregate.OUTPUT_NAME}"
        snapshot_identity = f"scratchpad:{aggregate.INITIAL_SNAPSHOT_NAME}"
        assert aggregate_identity not in partial_aggregate["artifact_bindings"]
        assert snapshot_identity not in partial_aggregate["artifact_bindings"]
        assert not (root / aggregate.INITIAL_SNAPSHOT_NAME).exists()
        aggregate_bytes = (root / aggregate.OUTPUT_NAME).read_bytes()
        assert aggregate.run_severity_source_aggregate(**aggregate_args) is True
        assert aggregate.validate_severity_source_aggregate(**aggregate_args) == ()
        committed_aggregate = read_artifact_ledger(root)
        assert committed_aggregate["work_units"][aggregate_key]["execution_state"] == "OUTPUT_COMMITTED"
        assert committed_aggregate["artifact_bindings"][aggregate_identity]["owner_key"] == aggregate_key
        assert committed_aggregate["artifact_bindings"][snapshot_identity]["owner_key"] == aggregate_key
        assert set(committed_aggregate["work_units"][aggregate_key]["artifacts"]) == {
            aggregate_identity, snapshot_identity,
        }
        assert (root / aggregate.INITIAL_SNAPSHOT_NAME).read_bytes() == aggregate_bytes
        assert (root / aggregate.OUTPUT_NAME).read_bytes() == aggregate_bytes
        assert {row["candidate_id"] for row in json.loads(aggregate_bytes)["decisions"]} == set(
            verifier_unit.ordered_work_item_ids
        )
        assert aggregate.run_severity_source_aggregate(**aggregate_args) is True
        assert read_artifact_ledger(root)["work_units"][aggregate_key] == committed_aggregate["work_units"][aggregate_key]
        _assert_nonempty_planning_recovery(
            root, project, config, verifier_unit.ordered_work_item_ids, monkeypatch,
        )
        assert child_launches == 1
        assert source_calls == 2
        resumed = True

    TAIL._run_same_run_harmless_verifier(
        root=root, config=config, checkpoint=checkpoint, phases=phases,
        monkeypatch=monkeypatch,
        after_run=assert_crash_and_resume_inside_live_session,
        expected_incomplete_phase=verifier_phase.name,
    )
    assert resumed is True
    assert child_launches == 1
    assert source_calls == 2
    assert (root / aggregate.OUTPUT_NAME).is_file()
