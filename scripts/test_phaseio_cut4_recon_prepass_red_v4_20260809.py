"""V4 RED denominator for the live Cut-4 recon prepass boundary.

Unlike V1/V2, this module enters through the current production functions.  It
does not import a proposed application module, accept a status string as proof,
or replace any ArtifactLedger/transaction helper.  Provider execution may be
made unavailable, but the real prepass, driver startup, ledger reader, and
resume/degrade branch remain in the path.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
from types import SimpleNamespace
from typing import Any, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402
import test_driver_smoke as DRIVER_SMOKE  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


RUN_ID = "cut4-recon-v4"
V1_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_20260730.py":
        "50be6f719bde3c0910b9766fdf682824d5a3d4d4ec26cec86cedc48c4a224f2a",
    "test_phaseio_cut4_recon_dependency_merge_red_20260730.py":
        "7abf2efb49123bdcf93732a909ccd0f98f9371688c4bee7a69a5675b970e1bb1",
}
V2_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v2_20260809.py":
        "103f4c38b3d2f293b70dee127ac81e3c1a0d5fb5f36927873ce2033fe3689f4a",
    "test_phaseio_cut4_recon_dependency_merge_red_v2_20260809.py":
        "0de4ff1d7492416035721ac629cd21258feb0d17987f6b6c7a9ebdf62bd3a57a",
}
V3_HASHES = {
    "test_phaseio_cut4_recon_prepass_red_v3_20260809.py":
        "95046fbd0bb7c05da23b1a668dd6c5baf7d44d9e00bad3bdc9177bc6eff74a77",
    "test_phaseio_cut4_recon_dependency_merge_red_v3_20260809.py":
        "a4ab164ff922781a39bacfa4bc03384f8569980ec5c09e0ba3ecf0a44869210a",
}

SC_PREPASS = (
    "contract_inventory.md",
    "state_variables.md",
    "function_list.md",
    "build_status.md",
    "design_context.md",
    "attack_surface.md",
    "detected_patterns.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)
L1_PREPASS = (
    "subsystem_map.md",
    "trust_boundaries.md",
    "attack_surface.md",
    "threat_model.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _workspace(
    tmp_path: Path,
    *,
    pipeline: str,
    mode: str,
    route: str,
) -> tuple[Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = project / "src"
    source.mkdir(parents=True)
    scratchpad.mkdir()
    if pipeline == "l1":
        (source / "node.rs").write_text(
            "pub fn process_block(height: u64) -> bool { height > 0 }\n",
            encoding="utf-8",
        )
        language = "rust"
    else:
        (source / "Protocol.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract Protocol { uint256 public value; "
            "function set(uint256 x) external { value = x; } }\n",
            encoding="utf-8",
        )
        language = "evm"
    backend = "codex" if route == "codex" else "claude"
    config = {
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "cli_backend": backend,
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
        "run_id": RUN_ID,
        "prepass_external_scanners": False,
    }
    return project, scratchpad, config


def _assert_nonempty(root: Path, names: tuple[str, ...]) -> None:
    missing = [name for name in names if not (root / name).is_file()]
    empty = [name for name in names if (root / name).is_file() and not (root / name).read_bytes()]
    assert not missing, f"real prepass omitted files: {missing}"
    assert not empty, f"real prepass emitted zero-byte files: {empty}"


def _disable_external_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make only OS/provider execution unavailable; keep prepass logic real."""
    monkeypatch.setattr(RP.shutil, "which", lambda _name: None)
    monkeypatch.setattr(RP, "gate_supply_chain", lambda _root: None)
    monkeypatch.setattr(
        RP,
        "run_owned_process",
        lambda _args, **_kwargs: SimpleNamespace(
            returncode=127, stdout="", stderr="fixture unavailable"
        ),
    )


def _active_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    ledger = AL.read_artifact_ledger(root)
    matches = [
        row for key, row in ledger.get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(matches) == 1, f"expected one committed unit *{suffix}, got {len(matches)}"
    return matches[0]


def _assert_committed_outputs(root: Path, unit: Mapping[str, Any], names: tuple[str, ...]) -> None:
    ledger = AL.read_artifact_ledger(root)
    identities = {f"scratchpad:{name}" for name in names}
    assert identities.issubset(set(unit.get("artifacts", {})))
    for identity in identities:
        row = ledger.get("artifact_bindings", {}).get(identity)
        assert isinstance(row, Mapping), f"missing committed binding {identity}"
        assert row.get("status") == "ACTIVE"
        assert row.get("owner_key") == unit.get("work_unit_key")
        record = unit["artifacts"][identity]
        assert int(record.get("size") or 0) > 0


def _publication_rows(ledger: Mapping[str, Any], suffix: str) -> dict[str, Mapping[str, Any]]:
    return {
        str(key): row
        for key, row in ledger.get("work_units", {}).items()
        if isinstance(row, Mapping)
        and (
            str(key).endswith(suffix)
            or f"{suffix}.attempt-" in str(key)
            or f"{suffix}/attempt-" in str(key)
        )
    }


def _assert_changed_authority_transition(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    suffix: str,
    mutation: str,
) -> None:
    """Reject the V3 false-green: a changed authority cannot be a no-op."""
    before_rows = _publication_rows(before, suffix)
    after_rows = _publication_rows(after, suffix)
    active_before = [
        (key, row) for key, row in before_rows.items()
        if row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(active_before) == 1, "mutation control lacks a genuine first commit"
    old_key, old = active_before[0]
    assert json.dumps(after, sort_keys=True) != json.dumps(before, sort_keys=True), (
        f"{mutation}: second call was a complete ledger no-op"
    )

    current_old = after_rows.get(old_key, {})
    invalidated = (
        current_old.get("semantic_status") != "ACTIVE"
        or current_old.get("execution_state") != "OUTPUT_COMMITTED"
    )
    successors = [
        row for key, row in after_rows.items()
        if key != old_key
        or row.get("publication_generation") != old.get("publication_generation")
    ]
    attempted = [
        row for row in successors
        if any(
            row.get(field) and row.get(field) != old.get(field)
            for field in (
                "input_set_digest",
                "contract_digest",
                "namespace_digest",
                "source_capture_digest",
                "attempted_authority_digest",
            )
        )
    ]
    durable_debt = [
        row for row in attempted
        if row.get("semantic_status") in {"QUARANTINED", "DEBT", "REJECTED"}
        or row.get("execution_state") in {
            "OUTPUT_QUARANTINED",
            "INPUT_REJECTED",
            "PUBLICATION_REJECTED",
        }
        or (row.get("commit_authority") or {}).get("reason_codes")
    ]
    committed_successor = [
        row for row in attempted
        if row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert invalidated or durable_debt or committed_successor, (
        f"{mutation}: first ACTIVE generation survived changed authority with "
        "no bound successor or durable rejection/debt"
    )


def _commit_fixture_prepass(root: Path, project: Path) -> None:
    """Create the genuine first generation used only by false-green controls."""
    key = canonical_work_unit_key("sc", "core", "evm", "codex", "recon", "prepass")
    contract = PhaseIOContract(
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="codex",
        phase="recon",
        work_unit_id="prepass",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="V4_FALSE_GREEN_CONTROL",
            )
            for name in SC_PREPASS
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="core",
        ecosystem="evm",
        backend="codex",
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    AL.record_work_unit_inputs(root, project, contract, launch, run_id=RUN_ID)
    for name in SC_PREPASS:
        (root / name).write_text(
            f"# {name}\n\nfirst committed V4 control generation\n" + "x" * 160 + "\n",
            encoding="utf-8",
        )
    AL.record_work_unit_artifacts(
        root, project, contract, launch, run_id=RUN_ID, actor="DRIVER"
    )
    _active_unit(root, "/recon/prepass")


def test_v1_v2_v3_fixture_preimages_remain_byte_frozen() -> None:
    for name, expected in {**V1_HASHES, **V2_HASHES, **V3_HASHES}.items():
        path = SCRIPTS / name
        assert path.is_file(), name
        assert _sha(path) == expected


@pytest.mark.parametrize(
    ("pipeline", "mode", "route"),
    (
        ("sc", "light", "codex"),
        ("sc", "core", "claude-headless"),
        ("sc", "thorough", "pty"),
        ("l1", "light", "pty"),
        ("l1", "core", "codex"),
        ("l1", "thorough", "claude-headless"),
    ),
)
def test_live_prepass_matrix_requires_one_committed_selected_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    mode: str,
    route: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline=pipeline, mode=mode, route=route
    )

    # This is the current entry point.  Tool discovery/build failure is a real
    # provider outcome; it must not erase the deterministic prepass bytes.
    result = RP.run_recon_prepass(config)
    expected = L1_PREPASS if pipeline == "l1" else SC_PREPASS
    _assert_nonempty(scratchpad, expected)
    assert isinstance(result, dict) and result

    unit = _active_unit(scratchpad, "/recon/prepass")
    assert unit.get("run_id") == RUN_ID
    _assert_committed_outputs(scratchpad, unit, expected)


@pytest.mark.parametrize(
    "failpoint",
    (
        "after_capture",
        "after_arm",
        "after_stage",
        "after_publish",
        "before_commit",
    ),
)
def test_live_prepass_executes_named_crash_and_recovers_same_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    before = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in SC_PREPASS
    }
    hits: list[str] = []

    class InjectedCrash(RuntimeError):
        pass

    def injector(point: str, *_args: Any, **_kwargs: Any) -> None:
        hits.append(str(point))
        if str(point) == failpoint:
            raise InjectedCrash(failpoint)

    try:
        RP.run_recon_prepass(config, failure_injector=injector)
    except InjectedCrash:
        pass
    except TypeError as exc:
        pytest.fail(
            f"real run_recon_prepass cannot execute named injector {failpoint}: {exc}",
            pytrace=False,
        )
    assert failpoint in hits, f"publisher accepted but never executed {failpoint}"

    # Resume through the same current public entry, never a fixture journal.
    RP.run_recon_prepass(config)
    final = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in SC_PREPASS
    }
    all_old = final == before
    all_new = all(isinstance(raw, bytes) and raw for raw in final.values())
    assert all_old or all_new, "crash recovery exposed a mixed semantic postimage"
    if all_new:
        unit = _active_unit(scratchpad, "/recon/prepass")
        _assert_committed_outputs(scratchpad, unit, SC_PREPASS)
    else:
        rows = _publication_rows(
            AL.read_artifact_ledger(scratchpad), "/recon/prepass"
        )
        assert any(
            row.get("semantic_status") in {"QUARANTINED", "DEBT", "REJECTED"}
            for row in rows.values()
        )


@pytest.mark.parametrize("mutation", ("source_edit", "config_edit", "unexpected_output"))
def test_live_prepass_drift_never_rebinds_the_armed_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    _disable_external_providers(monkeypatch)
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    first = {name: _sha(scratchpad / name) for name in SC_PREPASS}
    _active_unit(scratchpad, "/recon/prepass")
    before_ledger = AL.read_artifact_ledger(scratchpad)

    if mutation == "source_edit":
        (project / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract Changed { function x() external {} }\n",
            encoding="utf-8",
        )
    elif mutation == "config_edit":
        config["language"] = "solana"
    else:
        (scratchpad / "recon_unplanned_semantic.md").write_text(
            "# Unplanned\n\nnonempty semantic output\n", encoding="utf-8"
        )

    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    after_ledger = AL.read_artifact_ledger(scratchpad)
    _assert_changed_authority_transition(
        before_ledger,
        after_ledger,
        suffix="/recon/prepass",
        mutation=mutation,
    )
    # The assertion is intentionally unconditional: unchanged bytes are not
    # permission to preserve the old generation after authority drift.
    assert first or after_ledger


@pytest.mark.parametrize("mutation", ("source_edit", "config_edit", "unexpected_output"))
def test_v4_rejects_v3_prepass_second_call_noop_counterexample(
    tmp_path: Path,
    mutation: str,
) -> None:
    project, scratchpad, _config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _commit_fixture_prepass(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    # Fileless mutation model: a broken second publisher returns without any
    # ledger write. V3 accepted this whenever public output hashes were stable.
    after = AL.read_artifact_ledger(scratchpad)
    with pytest.raises(AssertionError, match="complete ledger no-op"):
        _assert_changed_authority_transition(
            before,
            after,
            suffix="/recon/prepass",
            mutation=mutation,
        )


def test_exact_prepass_noop_reuses_same_generation_without_semantic_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    RP.run_recon_prepass(config)
    unit_before = dict(_active_unit(scratchpad, "/recon/prepass"))
    files_before = {
        name: (_sha(scratchpad / name), (scratchpad / name).stat().st_mtime_ns)
        for name in SC_PREPASS
    }
    ledger_before = AL.read_artifact_ledger(scratchpad)
    RP.run_recon_prepass(config)
    unit_after = _active_unit(scratchpad, "/recon/prepass")
    files_after = {
        name: (_sha(scratchpad / name), (scratchpad / name).stat().st_mtime_ns)
        for name in SC_PREPASS
    }
    assert files_after == files_before, "exact retry performed a semantic write"
    assert unit_after.get("publication_generation") == unit_before.get("publication_generation")
    assert AL.read_artifact_ledger(scratchpad) == ledger_before


def _resume_shard(job: Mapping[str, str]) -> str:
    return (
        f"<!-- PLAMEN_ARTIFACT: {job['output']} -->\n"
        f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- RECON_ROLE: {job['role']} -->\n"
        f"<!-- EXPECTED_OUTPUT: {job['output']} -->\n\n"
        f"# Resume worker {job['role']}\n\n"
        "## Evidence\n\nThe completed-recon resume branch replays this "
        "nonempty bounded shard without launching a provider. Source, state, "
        "entry-point, trust, build, and downstream implications are recorded.\n\n"
        "## Canonical Merge Hints\n\n- Preserve bounded evidence.\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


@pytest.mark.integration
@pytest.mark.parametrize("resume_branch", ("marker_strip", "shard_remerge"))
def test_real_second_driver_invocation_uses_completed_recon_resume_branch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    resume_branch: str,
) -> None:
    trace = tmp_path / f"resume_{resume_branch}.jsonl"
    old = '''_stub_mod = types.ModuleType("recon_prepass")\n_stub_mod.run_recon_prepass = lambda cfg: "stub-prepass"'''
    new = f'''import recon_prepass as _real_recon_prepass\n_real_run_recon_prepass = _real_recon_prepass.run_recon_prepass\ndef _observed_real_prepass(cfg):\n    result = _real_run_recon_prepass(cfg)\n    with Path(r"{trace}").open("a", encoding="utf-8") as fh:\n        fh.write(json.dumps({{"event": "prepass", "nonempty": bool(result)}}, sort_keys=True) + "\\n")\n    return result\n_real_recon_prepass.run_recon_prepass = _observed_real_prepass\n_stub_mod = _real_recon_prepass'''
    template = DRIVER_SMOKE.RUNNER_TEMPLATE.replace(old, new)
    template = template.replace('sys.modules["recon_prepass"] = _stub_mod', '')
    anchor = "import plamen_driver as pd\n"
    instrumentation = f'''import plamen_driver as pd\n_resume_trace = Path(r"{trace}")\ndef _record_resume_event(event, payload):\n    with _resume_trace.open("a", encoding="utf-8") as fh:\n        fh.write(json.dumps({{"event": event, "payload": payload}}, sort_keys=True, default=str) + "\\n")\ndef _is_completed_recon_resume(root):\n    checkpoint = Path(root) / "_v2_checkpoint.json"\n    if not checkpoint.is_file():\n        return False\n    try:\n        data = json.loads(checkpoint.read_text(encoding="utf-8"))\n    except Exception:\n        return False\n    return "recon" in set(data.get("completed") or [])\ndef _canonical_snapshot(root):\n    root = Path(root)\n    names = ("recon_summary.md", "design_context.md", "attack_surface.md", "state_variables.md", "function_list.md", "contract_inventory.md", "template_recommendations.md")\n    return {{\n        name: hashlib.sha256((root / name).read_bytes()).hexdigest()\n        for name in names\n        if (root / name).is_file()\n    }}\ndef _has_registered_resume_successor(root, suffix):\n    from artifact_ledger import read_artifact_ledger\n    rows = read_artifact_ledger(Path(root)).get("work_units", {{}})\n    return any(\n        str(key).endswith(suffix)\n        and isinstance(row, dict)\n        and row.get("semantic_status") == "ACTIVE"\n        and row.get("execution_state") == "OUTPUT_COMMITTED"\n        for key, row in rows.items()\n    )\n_real_strip_resume = pd.strip_codex_prepass_markers\ndef _observed_strip_resume(*args, **kwargs):\n    before = _canonical_snapshot(args[0])\n    result = _real_strip_resume(*args, **kwargs)\n    after = _canonical_snapshot(args[0])\n    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))\n    resumed = _is_completed_recon_resume(args[0])\n    _record_resume_event("marker_strip", {{"result": list(result or []), "completed_resume": resumed, "changed": changed}})\n    if resumed and not changed:\n        raise SystemExit(93)\n    if resumed and not _has_registered_resume_successor(args[0], "/recon/resume_marker_strip"):\n        raise SystemExit(91)\n    return result\npd.strip_codex_prepass_markers = _observed_strip_resume\n_real_merge_resume = pd._merge_recon_worker_shards\ndef _observed_merge_resume(*args, **kwargs):\n    before = _canonical_snapshot(args[0])\n    result = _real_merge_resume(*args, **kwargs)\n    after = _canonical_snapshot(args[0])\n    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))\n    resumed = _is_completed_recon_resume(args[0])\n    _record_resume_event("shard_remerge", {{"result": list(result or []), "completed_resume": resumed, "changed": changed}})\n    if resumed and not changed:\n        raise SystemExit(94)\n    if resumed and not _has_registered_resume_successor(args[0], "/recon/canonical_merge"):\n        raise SystemExit(92)\n    return result\npd._merge_recon_worker_shards = _observed_merge_resume\n'''
    instrumentation = instrumentation.replace(
        "if resumed and not changed:\n"
        "        raise SystemExit(93)\n"
        "    if resumed and not _has_registered_resume_successor("
        "args[0], \"/recon/resume_marker_strip\"):\n",
        "if resumed and result and not changed:\n"
        "        raise SystemExit(93)\n"
        "    if resumed and result and not _has_registered_resume_successor("
        "args[0], \"/recon/resume_marker_strip\"):\n",
    )
    template = template.replace(anchor, instrumentation, 1)
    monkeypatch.setattr(DRIVER_SMOKE, "RUNNER_TEMPLATE", template)

    run_root, _project, scratchpad, config_path, call_log = DRIVER_SMOKE._make_project(
        f"cut4_v4_resume_{resume_branch}_", mode="light", pipeline="sc",
        extra_config={"cli_backend": "codex"},
    )
    try:
        first_rc = DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        first_capture = capsys.readouterr()
        first_output = first_capture.out + first_capture.err
        assert first_rc == D.EXIT_DEGRADED, first_output
        checkpoint_before = json.loads(
            (scratchpad / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        assert "recon" in checkpoint_before.get("completed", []), first_output
        assert checkpoint_before.get("run_id")
        calls_before = call_log.read_text(encoding="utf-8").splitlines()
        recon_calls_before = sum(
            line.startswith("recon:") for line in calls_before
        )
        assert recon_calls_before == 1

        design = scratchpad / "design_context.md"
        if resume_branch == "marker_strip":
            design.write_text(
                RP._PREPASS_MARKER + "\n" + design.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        else:
            # Add the remerge sources through the real MODEL preparation and
            # commit boundary.  Direct post-run file writes are intentionally
            # rejected by startup drift authority before resume dispatch.
            cfg = json.loads(config_path.read_text(encoding="utf-8"))
            cfg["_run_id"] = checkpoint_before["run_id"]
            cfg["run_id"] = checkpoint_before["run_id"]
            phase = next(row for row in D.SC_PHASES if row.name == "recon")
            for job in D._recon_worker_jobs(cfg):
                assert D._prepare_typed_model_worker_launch(
                    phase=phase,
                    config=cfg,
                    scratchpad=scratchpad,
                    project_root=str(_project),
                    agent_id=job["agent_id"],
                    output=job["output"],
                    timeout_s=30,
                ) == []
                (scratchpad / job["output"]).write_text(
                    _resume_shard(job), encoding="utf-8"
                )
                assert D._record_typed_model_worker_artifact(
                    phase=phase,
                    config=cfg,
                    scratchpad=scratchpad,
                    project_root=str(_project),
                    agent_id=job["agent_id"],
                    output=job["output"],
                    timeout_s=30,
                ) == []
                shard_unit = _active_unit(
                    scratchpad,
                    f"/recon/worker.{job['agent_id'].lower()}",
                )
                _assert_committed_outputs(
                    scratchpad, shard_unit, (job["output"],)
                )
            design.write_text(
                RP._PREPASS_MARKER
                + "\n# Design Context\n\n[LLM TO ENRICH] Pre-pass stub.\n",
                encoding="utf-8",
            )

        second_rc = DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        captured = capsys.readouterr()
        # INFO-level startup branch evidence is intentionally written only to
        # the driver's durable file log; the smoke subprocess exposes WARNING+
        # on stderr.  Inspect both transports rather than requiring an INFO
        # message on the terminal transport.
        driver_log = scratchpad / "_plamen.log"
        second_output = captured.out + captured.err + (
            driver_log.read_text(encoding="utf-8", errors="replace")
            if driver_log.is_file()
            else ""
        )
        expected_missing_successor_rc = 91 if resume_branch == "marker_strip" else 92
        assert second_rc in {0, D.EXIT_DEGRADED, expected_missing_successor_rc}, (
            second_output
        )
        assert "[pre-pass] skipped because recon is already completed" in second_output
        checkpoint_after = json.loads(
            (scratchpad / "_v2_checkpoint.json").read_text(encoding="utf-8")
        )
        assert "recon" in checkpoint_after.get("completed", [])
        assert checkpoint_after.get("run_id") == checkpoint_before.get("run_id")
        calls_after = call_log.read_text(encoding="utf-8").splitlines()
        assert sum(line.startswith("recon:") for line in calls_after) == recon_calls_before

        events = [
            json.loads(line)
            for line in trace.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert sum(row.get("event") == "prepass" for row in events) == 1
        resumed_marker = next(
            (
                row for row in events
                if row.get("event") == "marker_strip"
                and (row.get("payload") or {}).get("completed_resume") is True
            ),
            None,
        )
        assert resumed_marker is not None
        if resume_branch == "shard_remerge":
            assert (resumed_marker.get("payload") or {}).get("result") == []
            assert (resumed_marker.get("payload") or {}).get("changed") == []
            assert any(
                row.get("event") == "shard_remerge"
                and (row.get("payload") or {}).get("completed_resume") is True
                and (row.get("payload") or {}).get("changed")
                for row in events
            )
            assert "re-merging recon worker shards" in second_output
            suffix = "/recon/canonical_merge"
        else:
            assert (resumed_marker.get("payload") or {}).get("changed")
            assert not any(
                row.get("event") == "shard_remerge"
                and (row.get("payload") or {}).get("completed_resume") is True
                for row in events
            )
            if second_rc != expected_missing_successor_rc:
                assert "stripped pre-pass marker" in second_output
            suffix = "/recon/resume_marker_strip"
        assert design.read_bytes()
        _active_unit(scratchpad, suffix)
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


@pytest.mark.integration
def test_actual_phase_loop_marker_degrade_requires_canonical_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trace = tmp_path / "phase_loop_marker_degrade.json"
    template = DRIVER_SMOKE.RUNNER_TEMPLATE
    anchor = "import plamen_driver as pd\n"
    instrumentation = f'''import plamen_driver as pd\n_marker_degrade_trace = Path(r"{trace}")\n_real_marker_strip = pd.strip_codex_prepass_markers\ndef _blocked_early_marker_strip(*_args, **_kwargs):\n    return []\npd.strip_codex_prepass_markers = _blocked_early_marker_strip\n_real_phase_loop_degrade = pd._try_recon_prepass_marker_degrade\ndef _degrade_snapshot(root):\n    root = Path(root)\n    names = ("recon_summary.md", "design_context.md", "attack_surface.md", "state_variables.md", "function_list.md", "contract_inventory.md", "template_recommendations.md")\n    return {{name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in names if (root / name).is_file()}}\ndef _has_degrade_successor(root):\n    from artifact_ledger import read_artifact_ledger\n    return any(\n        str(key).endswith("/recon/prepass_degrade")\n        and isinstance(row, dict)\n        and row.get("semantic_status") == "ACTIVE"\n        and row.get("execution_state") == "OUTPUT_COMMITTED"\n        for key, row in read_artifact_ledger(Path(root)).get("work_units", {{}}).items()\n    )\ndef _observed_phase_loop_degrade(root, config, missing):\n    before = _degrade_snapshot(root)\n    pd.strip_codex_prepass_markers = _real_marker_strip\n    try:\n        result = _real_phase_loop_degrade(root, config, missing)\n    finally:\n        pd.strip_codex_prepass_markers = _blocked_early_marker_strip\n    after = _degrade_snapshot(root)\n    changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))\n    attempts = sum(line.startswith("recon:") for line in CALL_LOG.read_text(encoding="utf-8").splitlines())\n    marker_only = bool(missing) and all("pre-pass overwrite marker" in str(item) for item in missing)\n    payload = {{"degraded": bool(result[0]), "changed": changed, "attempts": attempts, "marker_only": marker_only}}\n    _marker_degrade_trace.write_text(json.dumps(payload, sort_keys=True) + "\\n", encoding="utf-8")\n    if result[0] and changed and attempts >= 2 and marker_only and not _has_degrade_successor(root):\n        raise SystemExit(95)\n    return result\npd._try_recon_prepass_marker_degrade = _observed_phase_loop_degrade\n'''
    template = template.replace(anchor, instrumentation, 1)
    assignment = "pd.run_phase = stub_run_phase"
    marker_writer = f'''_unmarked_stub_run_phase = stub_run_phase\ndef _marker_preserving_stub_run_phase(phase, config, attempt):\n    rc = _unmarked_stub_run_phase(phase, config, attempt)\n    if phase.name == "recon":\n        marker = {RP._PREPASS_MARKER!r}\n        for name in _RECON_ARTIFACTS:\n            path = Path(config["scratchpad"]) / name\n            if path.is_file():\n                body = path.read_text(encoding="utf-8")\n                if not body.startswith(marker):\n                    path.write_text(marker + "\\n" + body, encoding="utf-8")\n    return rc\npd.run_phase = _marker_preserving_stub_run_phase'''
    template = template.replace(assignment, marker_writer, 1)
    monkeypatch.setattr(DRIVER_SMOKE, "RUNNER_TEMPLATE", template)

    run_root, _project, scratchpad, config_path, call_log = DRIVER_SMOKE._make_project(
        "cut4_v4_phase_loop_degrade_",
        mode="light",
        pipeline="sc",
        extra_config={"cli_backend": "codex"},
    )
    try:
        rc = DRIVER_SMOKE._run_driver(run_root, config_path, call_log, "A")
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert rc in {D.EXIT_DEGRADED, 95}, output
        assert trace.is_file(), "real phase-loop degrade caller was not reached"
        event = json.loads(trace.read_text(encoding="utf-8"))
        assert event == {
            "attempts": event["attempts"],
            "changed": event["changed"],
            "degraded": True,
            "marker_only": True,
        }
        assert event["attempts"] >= 2
        assert event["changed"]
        changed_names = tuple(str(name) for name in event["changed"])
        _assert_nonempty(scratchpad, changed_names)
        # RED target: the real phase-loop caller changed the canonical bytes,
        # but no exact DRIVER successor owns that promotion yet.
        unit = _active_unit(scratchpad, "/recon/prepass_degrade")
        _assert_committed_outputs(scratchpad, unit, changed_names)
    finally:
        shutil.rmtree(run_root, ignore_errors=True)


def test_zero_byte_output_cannot_be_clean_prepass_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_external_providers(monkeypatch)
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="claude-headless"
    )
    RP.run_recon_prepass(config)
    _assert_nonempty(scratchpad, SC_PREPASS)
    (scratchpad / "function_list.md").write_bytes(b"")

    RP.run_recon_prepass(config)
    ledger = AL.read_artifact_ledger(scratchpad)
    binding = ledger.get("artifact_bindings", {}).get("scratchpad:function_list.md")
    assert isinstance(binding, Mapping)
    assert binding.get("status") != "ACTIVE", (
        "zero-byte semantic output retained ACTIVE producer authority"
    )
    assert not any(
        str(key).endswith("/recon/prepass")
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
        for key, row in ledger.get("work_units", {}).items()
    )
