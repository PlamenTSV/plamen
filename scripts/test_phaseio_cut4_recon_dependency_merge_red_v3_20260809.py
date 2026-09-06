"""V3 live-entry RED denominator for recon fanout, dependency, and merge.

Every semantic route below calls the current production symbol.  Only the
external model/PTY process is replaced.  ArtifactLedger preparation, commit,
validation, deterministic dependency enumeration, merge rendering, and
consumer binding are never mocked.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import sys
import threading
from types import SimpleNamespace
from typing import Any, Mapping

import pytest


SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

import artifact_ledger as AL  # noqa: E402
import plamen_driver as D  # noqa: E402
import plamen_mechanical as M  # noqa: E402
import rooted_path_io as RIO  # noqa: E402
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)


RUN_ID = "cut4-recon-v3"
SC_CANONICAL = (
    "recon_summary.md",
    "design_context.md",
    "attack_surface.md",
    "state_variables.md",
    "function_list.md",
    "contract_inventory.md",
    "template_recommendations.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "build_status.md",
)
EXACT_RECON_CONSUMER_EIGHT = (
    "template_recommendations.md",
    "detected_patterns.md",
    "design_context.md",
    "attack_surface.md",
    "contract_inventory.md",
    "function_list.md",
    "state_variables.md",
    "recon_summary.md",
)
L1_CANONICAL = (
    "recon_summary.md",
    "threat_model.md",
    "subsystem_map.md",
    "attack_surface.md",
    "trust_boundaries.md",
    "template_recommendations.md",
    "scope_leftover.md",
)


def _driver_vector_descriptors(scratchpad: Path) -> tuple[Path, ...]:
    vector_root = scratchpad / "_driver_vector_transactions"
    if not RIO.lexists(vector_root):
        return ()
    descriptors: list[Path] = []
    with RIO.scandir(vector_root) as parents:
        parent_names = sorted(entry.name for entry in parents)
    for parent_name in parent_names:
        parent = vector_root / parent_name
        with RIO.scandir(parent) as stages:
            stage_names = sorted(entry.name for entry in stages)
        for stage_name in stage_names:
            descriptor = parent / stage_name / "descriptor.json"
            if RIO.is_file(descriptor):
                descriptors.append(descriptor)
    return tuple(descriptors)


def _driver_vector_candidate(descriptor: Path) -> Path:
    with RIO.scandir(descriptor.parent) as entries:
        names = sorted(entry.name for entry in entries)
    return next(
        descriptor.parent / name
        for name in names
        if name != "descriptor.json" and RIO.is_file(descriptor.parent / name)
    )


def _workspace(
    tmp_path: Path,
    *,
    pipeline: str = "sc",
    mode: str = "thorough",
    route: str = "codex",
    dependency: bool = True,
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
        import_line = 'import "@vendor/protocol/Oracle.sol";\n' if dependency else ""
        (source / "Protocol.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
            + import_line
            + "contract Protocol { function ready() external pure returns (bool) { return true; } }\n",
            encoding="utf-8",
        )
        language = "evm"
    config = {
        "pipeline": pipeline,
        "mode": mode,
        "language": language,
        "cli_backend": "codex" if route == "codex" else "claude",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "_run_id": RUN_ID,
        "run_id": RUN_ID,
    }
    return project, scratchpad, config


def _phase(config: Mapping[str, Any], name: str = "recon") -> Any:
    phases = D.L1_PHASES if config["pipeline"] == "l1" else D.SC_PHASES
    return next(row for row in phases if row.name == name)


def _shard(job: Mapping[str, str]) -> str:
    return (
        f"<!-- PLAMEN_ARTIFACT: {job['output']} -->\n"
        f"<!-- PLAMEN_OWNER: {job['agent_id']} -->\n"
        "<!-- PLAMEN_STATUS: IN_PROGRESS -->\n"
        "<!-- PLAMEN_PHASE: recon -->\n"
        "<!-- PLAMEN_VERSION: 1 -->\n"
        f"<!-- RECON_ROLE: {job['role']} -->\n"
        f"<!-- EXPECTED_OUTPUT: {job['output']} -->\n\n"
        f"# Recon worker {job['role']}\n\n"
        "## Evidence\n\n"
        "- `src/Protocol.sol:L1` is the concrete production source denominator.\n"
        "- Entry points, state, trust boundaries, build capability, dependency "
        "questions, and downstream implications were enumerated without a "
        "safety conclusion. This body is intentionally nonempty and exceeds "
        "the current worker content threshold.\n\n"
        "## Canonical Merge Hints\n\n"
        f"- Merge the bounded {job['role']} evidence without inventing facts.\n\n"
        "<!-- PLAMEN_STATUS: COMPLETE -->\n"
    )


def _write_worker_output(kwargs: Mapping[str, Any], config: Mapping[str, Any]) -> int:
    jobs = D._recon_worker_jobs(dict(config))
    job = kwargs.get("job")
    if not isinstance(job, Mapping):
        output = str((kwargs.get("expected_outputs") or [""])[0])
        job = next(
            (row for row in jobs if row["output"] == output),
            {
                "agent_id": "R-EXT",
                "role": "external_dependency_research",
                "output": output,
            },
        )
    root = Path(str(config["scratchpad"]))
    (root / str(job["output"])).write_text(_shard(job), encoding="utf-8")
    return 0


_REAL_RUN_SINGLE_RECON_WORKER_PTY = D._run_single_recon_worker_pty


class _PtyLifecycleInstallation:
    """Fresh synchronization and bounded diagnostics for one fake PTY install."""

    def __init__(self, *, acquire_timeout_s: float = 5.0) -> None:
        self.lifecycle_mutex = threading.Lock()
        self.diagnostic_lock = threading.Lock()
        self.acquire_timeout_s = acquire_timeout_s
        self.results: list[dict[str, Any]] = []
        self.events: list[tuple[str, str]] = []
        self.active_owners = 0
        self.max_active_owners = 0
        self.write_failures: set[str] = set()
        self.poll_failures: set[str] = set()

    def event(self, name: str, output: str) -> None:
        with self.diagnostic_lock:
            self.events.append((name, output))

    def owner_entered(self, output: str) -> None:
        with self.diagnostic_lock:
            self.active_owners += 1
            self.max_active_owners = max(self.max_active_owners, self.active_owners)
            self.events.append(("acquired", output))

    def owner_left(self, output: str) -> None:
        with self.diagnostic_lock:
            assert self.active_owners > 0
            self.active_owners -= 1
            self.lifecycle_mutex.release()
            self.events.append(("released", output))

    def observe(self, result: Mapping[str, Any], *, attempt: int) -> None:
        bounded = {
            "output": str(result.get("output") or ""),
            "attempt": attempt,
            "rc": result.get("rc"),
            "status": str(result.get("status") or ""),
            "reasons": tuple(str(item) for item in (result.get("reasons") or [])),
        }
        with self.diagnostic_lock:
            self.results.append(bounded)


class _FakePtySession:
    """External PTY-only replacement; all surrounding transaction code is real."""

    jobs: list[dict[str, str]] = []
    scratchpad: Path
    installation: _PtyLifecycleInstallation

    def __init__(self, _cmd: Any, **kwargs: Any) -> None:
        self.prompt_path = Path(kwargs["prompt_path"])
        self.transcript_path = self.prompt_path.with_suffix(".transcript.absent")
        self._owns_lifecycle_mutex = False
        self.acquire_started = threading.Event()
        self._job = next(
            (
                job for job in self.jobs
                if Path(job["output"]).stem in self.prompt_path.name
            ),
            {
                "agent_id": "R-EXT",
                "role": "external_dependency_research",
                "output": "recon_external_dependency_research.md",
            },
        )

    def spawn(self) -> None:
        output = self._job["output"]
        self.installation.event("acquire_started", output)
        self.acquire_started.set()
        if not self.installation.lifecycle_mutex.acquire(
            timeout=self.installation.acquire_timeout_s
        ):
            self.installation.event("acquire_timeout", output)
            raise RuntimeError("fixture PTY lifecycle acquire timeout")
        self._owns_lifecycle_mutex = True
        self.installation.owner_entered(output)
        if output in self.installation.write_failures:
            self.installation.event("write_failed", output)
            raise RuntimeError("fixture PTY output write failure")
        (self.scratchpad / self._job["output"]).write_text(
            _shard(self._job), encoding="utf-8"
        )
        self.installation.event("wrote", output)

    def send_bootstrap(self) -> None:
        return None

    def wait_for_turn_complete(self, _timeout: float, **kwargs: Any) -> Any:
        output = self._job["output"]
        if output in self.installation.poll_failures:
            self.installation.event("poll_failed", output)
            raise RuntimeError("fixture PTY poll failure")
        on_poll = kwargs.get("on_poll")
        state = SimpleNamespace(rate_limited=False, overloaded=False)
        if on_poll is not None:
            on_poll(0.0, state)
        self.installation.event("polled", output)
        return state

    def terminate(self, **_kwargs: Any) -> None:
        if not self._owns_lifecycle_mutex:
            return None
        self._owns_lifecycle_mutex = False
        output = self._job["output"]
        self.installation.owner_left(output)
        return None


def _installed_fake_pty_session(
    installation: _PtyLifecycleInstallation,
    *,
    jobs: list[dict[str, str]],
    scratchpad: Path,
) -> type[_FakePtySession]:
    return type(
        "_InstalledFakePtySession",
        (_FakePtySession,),
        {
            "installation": installation,
            "jobs": json.loads(json.dumps(jobs)),
            "scratchpad": scratchpad,
        },
    )


def _install_external_boundary(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
    route: str,
    *,
    pty_installation: _PtyLifecycleInstallation | None = None,
) -> _PtyLifecycleInstallation | None:
    if route == "codex":
        monkeypatch.setattr(
            D, "_run_one_codex_exec",
            lambda **kwargs: _write_worker_output(kwargs, config),
        )
    elif route == "claude-headless":
        monkeypatch.setattr(
            D, "_run_one_claude_headless_breadth_worker",
            lambda **kwargs: _write_worker_output(kwargs, config),
        )
    else:
        installation = pty_installation or _PtyLifecycleInstallation()
        installed_session = _installed_fake_pty_session(
            installation,
            jobs=D._recon_worker_jobs(config),
            scratchpad=Path(config["scratchpad"]),
        )

        def observed_worker(**kwargs: Any) -> dict[str, Any]:
            result = _REAL_RUN_SINGLE_RECON_WORKER_PTY(**kwargs)
            installation.observe(result, attempt=int(kwargs.get("attempt") or 0))
            return result

        monkeypatch.setattr(D, "ClaudePtySession", installed_session)
        monkeypatch.setattr(D, "_run_single_recon_worker_pty", observed_worker)
        return installation
    return None


def _active_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    ledger = AL.read_artifact_ledger(root)
    rows = [
        row for key, row in ledger.get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(rows) == 1, f"expected one committed work unit *{suffix}; got {len(rows)}"
    return rows[0]


def _bound_unit(root: Path, suffix: str) -> Mapping[str, Any]:
    rows = [
        row for key, row in AL.read_artifact_ledger(root).get("work_units", {}).items()
        if str(key).endswith(suffix)
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "INPUTS_BOUND"
        and row.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    ]
    assert len(rows) == 1, f"expected one prelaunch-bound unit *{suffix}; got {len(rows)}"
    return rows[0]


def _assert_active_artifact(root: Path, name: str, owner: Mapping[str, Any]) -> None:
    raw = (root / name).read_bytes()
    assert raw, f"{name} is zero bytes"
    identity = f"scratchpad:{name}"
    record = owner.get("artifacts", {}).get(identity)
    assert isinstance(record, Mapping), f"{identity} absent from committed work unit"
    assert record.get("sha256") == hashlib.sha256(raw).hexdigest()
    assert int(record.get("size") or 0) == len(raw)
    binding = AL.read_artifact_ledger(root).get("artifact_bindings", {}).get(identity)
    assert isinstance(binding, Mapping) and binding.get("status") == "ACTIVE"
    assert binding.get("owner_key") == owner.get("work_unit_key")


def _prepare_l1_bake(
    monkeypatch: pytest.MonkeyPatch,
    scratchpad: Path,
    config: dict[str, Any],
) -> None:
    monkeypatch.setattr(D.shutil, "which", lambda _name, *_args, **_kwargs: None)
    issues = D._run_l1_bake_capability_transaction(scratchpad, config)
    assert issues == []
    unit = _active_unit(scratchpad, "/bake/capability_status")
    _assert_active_artifact(scratchpad, "primitive_status.md", unit)


def _prepare_sc_prepass_inputs(scratchpad: Path, config: dict[str, Any]) -> None:
    names = (
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "meta_buffer.md",
    )
    for name in names:
        (scratchpad / name).write_text(
            f"# {name}\n\ncommitted deterministic prepass input\n" + "p" * 180 + "\n",
            encoding="utf-8",
        )
    unit = _commit_fixture_driver_outputs(
        scratchpad,
        Path(config["project_root"]),
        work_unit_id="prepass_fixture_prerequisite",
        names=names,
    )
    for name in names:
        _assert_active_artifact(scratchpad, name, unit)


def _run_fanout(
    monkeypatch: pytest.MonkeyPatch,
    config: dict[str, Any],
    route: str,
    *,
    pty_installation: _PtyLifecycleInstallation | None = None,
) -> int:
    scratchpad = Path(config["scratchpad"])
    phase = _phase(config)
    _install_external_boundary(
        monkeypatch,
        config,
        route,
        pty_installation=pty_installation,
    )
    if config["pipeline"] == "l1":
        _prepare_l1_bake(monkeypatch, scratchpad, config)
    else:
        _prepare_sc_prepass_inputs(scratchpad, config)
    if route == "pty":
        return D._run_recon_worker_pool_pty(
            scratchpad=scratchpad,
            project_root=config["project_root"],
            config=config,
            phase=phase,
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )
    return D._run_recon_backend_fanout(
        backend=route,
        phase=phase,
        config=config,
        scratchpad=scratchpad,
        attempt=1,
        timeout=30,
        effective_model="fixture-model",
    )


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
def test_live_fanout_matrix_commits_shards_before_canonical_driver_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pipeline: str,
    mode: str,
    route: str,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline=pipeline, mode=mode, route=route
    )
    installation = _PtyLifecycleInstallation() if route == "pty" else None
    result = _run_fanout(
        monkeypatch,
        config,
        route,
        pty_installation=installation,
    )
    diagnostic = None if installation is None else {
        "results": installation.results,
        "events": installation.events,
    }
    assert result == 0, diagnostic

    # Positive control: every model row is a real current PhaseIO/ledger commit.
    jobs = D._recon_worker_jobs(config)
    if installation is not None:
        observed_by_output = {
            str(row["output"]): row for row in installation.results
            if str(row["output"]) in {str(job["output"]) for job in jobs}
        }
        expected_outputs = [str(job["output"]) for job in jobs]
        assert set(observed_by_output) == set(expected_outputs), diagnostic
        observed = [observed_by_output[output] for output in expected_outputs]
        assert len(observed_by_output) == len(expected_outputs), diagnostic
        assert sum(
            str(row["output"]) in set(expected_outputs)
            for row in installation.results
        ) == len(expected_outputs), diagnostic
        assert all(
            row["attempt"] == 1
            and row["rc"] == 0
            and row["status"] == "complete"
            and row["reasons"] == ()
            for row in observed
        ), diagnostic
        assert installation.active_owners == 0, diagnostic
        assert installation.max_active_owners == 1, diagnostic
    for job in jobs:
        unit = _active_unit(scratchpad, f"/recon/worker.{job['agent_id'].lower()}")
        _assert_active_artifact(scratchpad, job["output"], unit)

    canonical = L1_CANONICAL if pipeline == "l1" else SC_CANONICAL
    for name in canonical:
        assert (scratchpad / name).read_bytes(), name
    assert (scratchpad / "recon_signal_transform_receipt.json").read_bytes()

    # RED target: the current mechanical merge writes bytes but has no DRIVER
    # publication work unit or artifact bindings.
    unit = _active_unit(scratchpad, "/recon/canonical_merge")
    for name in (*canonical, "recon_signal_transform_receipt.json"):
        _assert_active_artifact(scratchpad, name, unit)


@pytest.mark.parametrize("route", ("codex", "claude-headless", "pty"))
def test_live_dependency_wave_commits_rext_before_driver_reconcile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route=route, dependency=True
    )
    phase = _phase(config)
    _install_external_boundary(monkeypatch, config, route)
    _prepare_sc_prepass_inputs(scratchpad, config)
    if route == "pty":
        result = D._run_recon_dependency_research_wave(
            scratchpad=scratchpad,
            project_root=config["project_root"],
            config=config,
            phase=phase,
            base_cmd=["claude"],
            env={},
            timeout=30,
            quiescence_s=0.01,
            attempt=1,
        )
    else:
        result = D._run_recon_dependency_research_headless(
            backend=route,
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            attempt=1,
            timeout=30,
            effective_model="fixture-model",
        )

    assert result.get("observed", result.get("total", 0)) or result.get("unresolved", 0)
    for name in (
        "external_dependency_obligations.json",
        "recon_external_dependency_research.md",
        "external_dependency_research.md",
    ):
        assert (scratchpad / name).read_bytes(), name
    rext = _active_unit(scratchpad, "/recon/worker.r-ext")
    _assert_active_artifact(scratchpad, "recon_external_dependency_research.md", rext)

    D._ensure_recon_dependency_parity(scratchpad, config["project_root"], config)
    reconciler = _active_unit(scratchpad, "/recon/dependency_reconcile")
    _assert_active_artifact(scratchpad, "external_dependency_research.md", reconciler)


def test_dependency_wave_refreshes_explicit_absence_capture_after_rext_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="pty", dependency=True
    )
    phase = _phase(config)
    _install_external_boundary(monkeypatch, config, "pty")
    _prepare_sc_prepass_inputs(scratchpad, config)

    baseline = D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )
    assert baseline["unresolved"] > 0
    before = json.loads(
        (scratchpad / "dependency_reconcile_preexecution_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert before["research"]["state"] == "EXPLICIT_ABSENCE"

    result = D._run_recon_dependency_research_wave(
        scratchpad=scratchpad,
        project_root=config["project_root"],
        config=config,
        phase=phase,
        base_cmd=["claude"],
        env={},
        timeout=30,
        quiescence_s=0.01,
        attempt=1,
    )
    after = json.loads(
        (scratchpad / "dependency_reconcile_preexecution_authority.json").read_text(
            encoding="utf-8"
        )
    )
    assert after["research"]["state"] == "ACTIVE"
    assert after["authority_sha256"] != before["authority_sha256"]
    assert result["expected_ids"]
    reconciler = _active_unit(
        scratchpad, "/recon/dependency_reconcile.active_research"
    )
    _assert_active_artifact(
        scratchpad, "external_dependency_research.md", reconciler
    )


def test_dependency_zero_is_nonempty_typed_zero_not_zero_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="light", route="codex", dependency=False
    )
    source = project / "src" / "Protocol.sol"
    source_before = source.read_bytes()

    def drift_after_arm(event: str) -> None:
        if event == "after_descriptor":
            source.write_bytes(source_before + b"\n// post-arm drift\n")

    with pytest.raises(D.ArtifactLedgerError, match="capture drifted"):
        D._publish_dependency_obligations(
            scratchpad,
            project,
            config,
            failure_injector=drift_after_arm,
        )
    assert not (scratchpad / "external_dependency_obligations.json").exists()
    capture_path = scratchpad / "dependency_obligations_preexecution_authority.json"
    assert not capture_path.exists()
    capture_unit = next(
        row
        for key, row in AL.read_artifact_ledger(scratchpad)["work_units"].items()
        if key.endswith("/recon/dependency_obligations.source_capture")
    )
    assert capture_unit["semantic_status"] == "INPUTS_BOUND"
    assert capture_unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    descriptor = next(iter(_driver_vector_descriptors(scratchpad)))
    candidate = _driver_vector_candidate(descriptor)
    retained = {
        "ledger": (scratchpad / "_artifact_state.json").read_bytes(),
        "descriptor": RIO.read_bytes(descriptor),
        "candidate": RIO.read_bytes(candidate),
    }
    with pytest.raises(D.ArtifactLedgerError, match="vector recovery failed"):
        D._publish_dependency_obligations(scratchpad, project, config)
    assert (scratchpad / "_artifact_state.json").read_bytes() == retained["ledger"]
    assert RIO.read_bytes(descriptor) == retained["descriptor"]
    assert RIO.read_bytes(candidate) == retained["candidate"]
    source.write_bytes(source_before)

    result = D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )
    assert result.get("unresolved") == 0
    assert (scratchpad / "external_dependency_obligations.json").read_bytes()
    assert (scratchpad / "external_dependency_research.md").read_bytes()

    obligations = _active_unit(scratchpad, "/recon/dependency_obligations")
    reconcile = _active_unit(scratchpad, "/recon/dependency_reconcile")
    _assert_active_artifact(
        scratchpad, "external_dependency_obligations.json", obligations
    )
    _assert_active_artifact(scratchpad, "external_dependency_research.md", reconcile)

    capture_path = scratchpad / "dependency_obligations_preexecution_authority.json"
    foreign = json.loads(capture_path.read_text(encoding="utf-8"))
    foreign["run_id"] = "foreign-run"
    foreign_unsigned = dict(foreign)
    foreign_unsigned.pop("authority_sha256")
    foreign["authority_sha256"] = D._stable_payload_digest(foreign_unsigned)
    ledger_before_foreign = AL.read_artifact_ledger(scratchpad)
    capture_before_foreign = capture_path.read_bytes()
    with pytest.raises(D.ArtifactLedgerError, match="current run authority"):
        D._publish_dependency_capture(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            payload=foreign,
            expected_current_authority=foreign,
        )
    assert AL.read_artifact_ledger(scratchpad) == ledger_before_foreign
    assert capture_path.read_bytes() == capture_before_foreign

    before = {
        name: (scratchpad / name).read_bytes()
        for name in (
            "_artifact_state.json",
            "dependency_obligations_preexecution_authority.json",
            "external_dependency_obligations.json",
            "dependency_reconcile_preexecution_authority.json",
            "external_dependency_research.md",
        )
    }

    def _bomb(*_args, **_kwargs):
        raise AssertionError("exact dependency replay reached a forbidden action")

    for name in (
        "enumerate_dependency_obligations",
        "render_dependency_obligations",
        "reconcile_dependency_research_ledger",
        "_recoverable_driver_output_vector",
        "_arm_dependency_phase_io",
    ):
        monkeypatch.setattr(D, name, _bomb)
    replay = D._ensure_recon_dependency_parity(
        scratchpad, config["project_root"], config
    )
    assert replay.get("unresolved") == 0
    assert {
        name: (scratchpad / name).read_bytes()
        for name in before
    } == before


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH regression")
def test_dependency_vector_recovery_uses_rooted_io_beyond_max_path(
    tmp_path: Path,
) -> None:
    long_root = tmp_path / ("driver-vector-long-root-" + "x" * 56)
    project, scratchpad, config = _workspace(
        long_root,
        pipeline="sc",
        mode="light",
        route="codex",
        dependency=False,
    )
    source = project / "src" / "Protocol.sol"
    source_before = source.read_bytes()

    def drift_after_descriptor(event: str) -> None:
        if event == "after_descriptor":
            source.write_bytes(source_before + b"\n// retained long-path vector\n")

    with pytest.raises(D.ArtifactLedgerError, match="capture drifted"):
        D._publish_dependency_obligations(
            scratchpad,
            project,
            config,
            failure_injector=drift_after_descriptor,
        )

    descriptor = next(iter(_driver_vector_descriptors(scratchpad)))
    candidate = _driver_vector_candidate(descriptor)
    assert len(str(descriptor.parent)) > 260
    assert len(str(descriptor)) > 260
    assert len(str(candidate)) > 260
    retained_descriptor = RIO.read_bytes(
        descriptor,
        label="retained long-path vector descriptor",
        require_single_link=True,
    )
    retained_candidate = RIO.read_bytes(
        candidate,
        label="retained long-path vector candidate",
        require_single_link=True,
    )

    source.write_bytes(source_before)
    result = D._ensure_recon_dependency_parity(
        scratchpad,
        config["project_root"],
        config,
    )
    assert result.get("unresolved") == 0
    assert retained_descriptor
    assert retained_candidate
    assert (scratchpad / "external_dependency_obligations.json").read_bytes()
    assert (scratchpad / "external_dependency_research.md").read_bytes()
    assert not RIO.lexists(scratchpad / "_driver_vector_transactions")


def test_dependency_vector_recovery_rejects_multilink_stage_fail_closed(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path,
        pipeline="sc",
        mode="light",
        route="codex",
        dependency=False,
    )
    source = project / "src" / "Protocol.sol"
    source_before = source.read_bytes()

    def drift_after_descriptor(event: str) -> None:
        if event == "after_descriptor":
            source.write_bytes(source_before + b"\n// retain for alias attack\n")

    with pytest.raises(D.ArtifactLedgerError, match="capture drifted"):
        D._publish_dependency_obligations(
            scratchpad,
            project,
            config,
            failure_injector=drift_after_descriptor,
        )
    descriptor = next(iter(_driver_vector_descriptors(scratchpad)))
    alias = descriptor.parent / "descriptor-hardlink-alias.json"
    os.link(RIO.native_path(descriptor), RIO.native_path(alias))
    assert RIO.lstat(descriptor).st_nlink == 2
    ledger_before = (scratchpad / "_artifact_state.json").read_bytes()
    descriptor_before = RIO.read_bytes(descriptor)
    source.write_bytes(source_before)

    with pytest.raises(D.ArtifactLedgerError, match="vector recovery failed"):
        D._publish_dependency_obligations(scratchpad, project, config)

    assert (scratchpad / "_artifact_state.json").read_bytes() == ledger_before
    assert RIO.read_bytes(descriptor) == descriptor_before
    assert RIO.lexists(alias)
    assert not (
        scratchpad / "dependency_obligations_preexecution_authority.json"
    ).exists()


def test_dependency_reconcile_capture_revalidates_after_arm_and_recovers_exactly(
    tmp_path: Path,
) -> None:
    alias_project, alias_scratchpad, alias_config = _workspace(
        tmp_path / "caller-alias",
        pipeline="sc",
        mode="light",
        route="codex",
        dependency=False,
    )
    D._publish_dependency_obligations(
        alias_scratchpad, alias_project, alias_config
    )
    alias_authority = D._current_dependency_authority_payload(
        config=alias_config, kind="RECONCILE"
    )
    captured_raw = (
        json.dumps(alias_authority, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")

    def mutate_caller_alias(event: str) -> None:
        if event == "after_descriptor":
            alias_authority["backend"] = "mutated-caller-alias"

    D._publish_dependency_capture(
        scratchpad=alias_scratchpad,
        project_root=alias_project,
        config=alias_config,
        payload=alias_authority,
        expected_current_authority=alias_authority,
        failure_injector=mutate_caller_alias,
    )
    assert (
        alias_scratchpad / "dependency_reconcile_preexecution_authority.json"
    ).read_bytes() == captured_raw

    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="light", route="codex", dependency=False
    )
    obligations = D._publish_dependency_obligations(scratchpad, project, config)
    source = project / "src" / "Protocol.sol"
    source_before = source.read_bytes()

    expected = D._current_dependency_authority_payload(
        config=config, kind="RECONCILE"
    )
    foreign = json.loads(json.dumps(expected))
    foreign["backend"] = "foreign-backend"
    unsigned = dict(foreign)
    unsigned.pop("authority_sha256")
    foreign["authority_sha256"] = D._stable_payload_digest(unsigned)
    before = (scratchpad / "_artifact_state.json").read_bytes()
    with pytest.raises(D.ArtifactLedgerError, match="explicit expected authority"):
        D._publish_dependency_capture(
            scratchpad=scratchpad,
            project_root=project,
            config=config,
            payload=foreign,
            expected_current_authority=expected,
        )
    assert (scratchpad / "_artifact_state.json").read_bytes() == before
    assert not (scratchpad / "dependency_reconcile_preexecution_authority.json").exists()

    def drift_after_descriptor(event: str) -> None:
        if event == "after_descriptor":
            source.write_bytes(source_before + b"\n// reconcile capture drift\n")

    with pytest.raises(D.ArtifactLedgerError, match="capture drifted"):
        D._publish_dependency_reconcile(
            scratchpad,
            project,
            config,
            obligations,
            worker_text="",
            failure_injector=drift_after_descriptor,
        )
    assert not (scratchpad / "dependency_reconcile_preexecution_authority.json").exists()
    assert not (scratchpad / "external_dependency_research.md").exists()
    unit = next(
        row
        for key, row in AL.read_artifact_ledger(scratchpad)["work_units"].items()
        if key.endswith("/recon/dependency_reconcile.source_capture")
    )
    assert unit["semantic_status"] == "INPUTS_BOUND"
    assert unit["execution_state"] == "INPUTS_BOUND_PREEXECUTION"
    descriptor = next(
        path
        for path in (scratchpad / "_driver_vector_transactions").rglob("descriptor.json")
        if "dependency_reconcile.source_capture" in json.loads(
            path.read_text(encoding="utf-8")
        )["work_unit_key"]
    )
    retained = {
        "ledger": (scratchpad / "_artifact_state.json").read_bytes(),
        "descriptor": descriptor.read_bytes(),
    }
    with pytest.raises(D.ArtifactLedgerError, match="vector recovery failed"):
        D._publish_dependency_reconcile(
            scratchpad,
            project,
            config,
            obligations,
            worker_text="",
        )
    assert (scratchpad / "_artifact_state.json").read_bytes() == retained["ledger"]
    assert descriptor.read_bytes() == retained["descriptor"]

    source.write_bytes(source_before)
    recovered = D._publish_dependency_reconcile(
        scratchpad,
        project,
        config,
        obligations,
        worker_text="",
    )
    assert recovered["unresolved"] == 0
    assert (scratchpad / "dependency_reconcile_preexecution_authority.json").is_file()
    assert (scratchpad / "external_dependency_research.md").is_file()
    assert not (scratchpad / "_driver_vector_transactions").exists()


def _commit_fixture_driver_outputs(
    root: Path,
    project: Path,
    *,
    work_unit_id: str,
    names: tuple[str, ...],
) -> Mapping[str, Any]:
    payloads = {name: (root / name).read_bytes() for name in names}
    key = canonical_work_unit_key(
        "sc", "thorough", "evm", "claude", "recon", work_unit_id
    )
    contract = PhaseIOContract(
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        phase="recon",
        work_unit_id=work_unit_id,
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=name,
                owner_key=key,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                minimum_gate="FIXTURE_PREREQUISITE",
            )
            for name in names
        ),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=key,
        pipeline="sc",
        mode="thorough",
        ecosystem="evm",
        backend="claude",
        model="driver",
        timeout_s=30,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    # Arm against true absence, then publish the already-derived fixture bytes.
    # This uses the real ledger transaction and therefore exercises output
    # prestates instead of blessing files that predated the receipt.
    for name in names:
        (root / name).unlink()
    AL.record_work_unit_inputs(root, project, contract, launch, run_id=RUN_ID)
    for name, raw in payloads.items():
        (root / name).write_bytes(raw)
    AL.record_work_unit_artifacts(
        root, project, contract, launch, run_id=RUN_ID, actor="DRIVER"
    )
    return _active_unit(root, f"/recon/{work_unit_id}")


def test_instantiate_binds_exact_eight_recon_consumers_and_separate_skill_row(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="pty"
    )
    # This setup is a real ArtifactLedger control, not a transaction mock: it
    # isolates the downstream current consumer from the missing merge producer.
    for name in EXACT_RECON_CONSUMER_EIGHT:
        (scratchpad / name).write_text(
            f"# {name}\n\ncommitted canonical fixture bytes\n" + "x" * 180 + "\n",
            encoding="utf-8",
        )
    producer = _commit_fixture_driver_outputs(
        scratchpad,
        project,
        work_unit_id="canonical_fixture_prerequisite",
        names=EXACT_RECON_CONSUMER_EIGHT,
    )
    for name in EXACT_RECON_CONSUMER_EIGHT:
        _assert_active_artifact(scratchpad, name, producer)

    selection_issues = D._materialize_live_skill_selection_boundary(
        scratchpad, config
    )
    assert selection_issues == []
    selection = _active_unit(scratchpad, "/recon/skill_selection_authority")
    _assert_active_artifact(scratchpad, "skill_selection_catalog.json", selection)

    instantiate = _phase(config, "instantiate")
    exact = D._instantiate_exact_inputs(scratchpad)
    assert set(EXACT_RECON_CONSUMER_EIGHT).issubset(exact)
    assert "skill_selection_catalog.json" in exact
    assert len([name for name in exact if name in EXACT_RECON_CONSUMER_EIGHT]) == 8
    issues = D._bind_typed_model_phase_inputs(instantiate, scratchpad, config)
    assert issues == []
    unit = _bound_unit(scratchpad, "/instantiate/model")
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in (*EXACT_RECON_CONSUMER_EIGHT, "skill_selection_catalog.json")
    }


def test_breadth_real_binding_rejects_uncommitted_mechanical_merge(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    jobs = D._recon_worker_jobs(config)
    phase = _phase(config)
    _prepare_sc_prepass_inputs(scratchpad, config)
    for job in jobs:
        assert D._prepare_typed_model_worker_launch(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(project),
            agent_id=job["agent_id"],
            output=job["output"],
            timeout_s=30,
        ) == []
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
        assert D._record_typed_model_worker_artifact(
            phase=phase,
            config=config,
            scratchpad=scratchpad,
            project_root=str(project),
            agent_id=job["agent_id"],
            output=job["output"],
            timeout_s=30,
        ) == []
    M._merge_recon_worker_shards(scratchpad, config)
    for job in jobs:
        _assert_active_artifact(
            scratchpad,
            job["output"],
            _active_unit(scratchpad, f"/recon/worker.{job['agent_id'].lower()}"),
        )

    canonical_names = (
        "recon_summary.md",
        "attack_surface.md",
        "contract_inventory.md",
        "function_list.md",
        "state_variables.md",
        "template_recommendations.md",
    )
    producer = _active_unit(scratchpad, "/recon/canonical_merge")
    assert producer.get("semantic_status") == "ACTIVE"
    assert producer.get("execution_state") == "OUTPUT_COMMITTED"
    assert set(producer.get("artifacts", {})) == {
        f"scratchpad:{name}"
        for name in (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    }

    breadth = _phase(config, "breadth")
    output = "analysis_fixture.md"
    issues = D._prepare_typed_model_worker_launch(
        phase=breadth,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="B1",
        output=output,
        timeout_s=30,
    )
    assert issues == [], "real breadth binding accepted no clean recon producer authority"
    unit = _bound_unit(scratchpad, "/breadth/worker.b1")
    assert unit.get("semantic_status") == "INPUTS_BOUND"
    assert unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    assert unit.get("artifacts") == {}
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in canonical_names
    }
    receipt_digest = producer["commit_authority"]["receipt_digest"]
    for name in canonical_names:
        binding = unit["input_bindings"][f"scratchpad:{name}"]
        raw = (scratchpad / name).read_bytes()
        assert binding.get("status") == "ACTIVE"
        assert binding.get("producer_run_id") == RUN_ID
        assert binding.get("producer_work_unit_key") == producer.get("work_unit_key")
        assert binding.get("producer_contract_digest") == producer.get("contract_digest")
        assert binding.get("producer_launch_digest") == producer.get("launch_digest")
        assert binding.get("producer_commit_receipt_digest") == receipt_digest
        assert binding.get("sha256") == hashlib.sha256(raw).hexdigest()
        assert binding.get("size") == len(raw)


def test_transform_receipt_is_a_real_canonical_contract_output(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    jobs = D._recon_worker_jobs(config)
    for job in jobs:
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
    M._merge_recon_worker_shards(scratchpad, config)
    receipt = scratchpad / "recon_signal_transform_receipt.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload.get("schema") == "plamen.recon_signal_transform_set.v1"
    assert payload.get("transforms")

    try:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="thorough",
            ecosystem="evm",
            backend="claude",
            phase="recon",
            work_unit_id="canonical_merge",
            exact_inputs=tuple(job["output"] for job in jobs),
            exact_outputs=(*SC_CANONICAL, "recon_signal_transform_receipt.json"),
            exact_writer="DRIVER",
        )
    except (KeyError, TypeError, ValueError) as exc:
        pytest.fail(f"canonical merge contract/receipt output is absent: {exc}", pytrace=False)
    assert "scratchpad:recon_signal_transform_receipt.json" in {
        row.identity for row in contract.outputs
    }


@pytest.mark.parametrize("failpoint", ("after_capture", "after_arm", "before_commit"))
def test_canonical_merge_has_named_transactional_recovery_seam(
    tmp_path: Path,
    failpoint: str,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    for job in D._recon_worker_jobs(config):
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
    M._merge_recon_worker_shards(scratchpad, config)
    assert all((scratchpad / name).read_bytes() for name in SC_CANONICAL)
    assert (scratchpad / "recon_signal_transform_receipt.json").read_bytes()

    signature = inspect.signature(M._merge_recon_worker_shards)
    assert "failure_injector" in signature.parameters, (
        f"real merge has no named transactional recovery seam for {failpoint}"
    )


@pytest.mark.parametrize("drift", ("shard_bytes", "source_bytes", "no_op"))
def test_canonical_replay_never_accepts_drift_or_zero_ledger(
    tmp_path: Path,
    drift: str,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    jobs = D._recon_worker_jobs(config)
    for job in jobs:
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
    M._merge_recon_worker_shards(scratchpad, config)
    before = AL.read_artifact_ledger(scratchpad)
    canonical_names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    first = {name: (scratchpad / name).read_bytes() for name in canonical_names}
    first_mtimes = {name: (scratchpad / name).stat().st_mtime_ns for name in canonical_names}
    old_key, old = next(
        (str(key), row)
        for key, row in before.get("work_units", {}).items()
        if str(key).endswith("/recon/canonical_merge")
        and isinstance(row, Mapping)
        and row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    )
    old_input_digest = old.get("input_set_digest")
    assert set(old.get("artifacts", {})) == {
        f"scratchpad:{name}" for name in canonical_names
    }
    expected_attempt = old["commit_authority"]["attempt_ordinal"] + 1
    if drift == "shard_bytes":
        (scratchpad / jobs[0]["output"]).write_text(
            _shard(jobs[0]) + "\nchanged source shard\n", encoding="utf-8"
        )
    elif drift == "source_bytes":
        (Path(config["project_root"]) / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract Drift {}\n", encoding="utf-8"
        )
    M._merge_recon_worker_shards(scratchpad, config)
    after = AL.read_artifact_ledger(scratchpad)
    assert all((scratchpad / name).read_bytes() == first[name] for name in canonical_names)
    if drift == "no_op":
        assert after == before
        assert {
            name: (scratchpad / name).stat().st_mtime_ns for name in canonical_names
        } == first_mtimes
        return

    rows = {
        str(key): row
        for key, row in after.get("work_units", {}).items()
        if str(key).endswith("/recon/canonical_merge")
        or "/recon/canonical_merge/attempt-" in str(key)
    }
    assert after != before
    old_after = rows[old_key]
    assert old_after.get("semantic_status") != "ACTIVE"
    assert old_after.get("execution_state") != "OUTPUT_COMMITTED"
    successors = [
        row
        for key, row in rows.items()
        if key != old_key
        and row.get("attempt_ordinal") == expected_attempt
        and row.get("semantic_status") in {"DEBT", "QUARANTINED", "REJECTED"}
        and row.get("execution_state") in {"FAILED", "OUTPUT_QUARANTINED"}
    ]
    assert len(successors) == 1
    successor = successors[0]
    disposition = successor.get("durable_disposition")
    assert isinstance(disposition, Mapping)
    assert disposition.get("reason_codes") == ["CANONICAL_INPUT_AUTHORITY_CHANGED"]
    assert successor.get("input_set_digest")
    assert successor.get("input_set_digest") != old_input_digest
    assert not successor.get("artifacts")
    successor_key = successor.get("work_unit_key")
    assert successor_key == f"{old_key}/attempt-{expected_attempt}"
    assert all(
        binding.get("owner_key") != successor_key
        for binding in after.get("artifact_bindings", {}).values()
        if isinstance(binding, Mapping)
    )


def test_supplementary_fallback_is_an_explicit_missing_production_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The current inline validator fallback is not called through a fake future
    # route.  Its missing typed contract is the precise RED condition.
    try:
        contract = resolve_phase_io_contract(
            pipeline="sc",
            mode="core",
            ecosystem="evm",
            backend="codex",
            phase="recon",
            work_unit_id="supplementary_disposition",
            exact_inputs=(
                "recon_summary.md",
                "recon_supplementary_disposition_input_authority.json",
            ),
            exact_outputs=(
                "recon_supplementary_disposition.json",
                "recon_supplementary_disposition_receipt.json",
            ),
            exact_writer="DRIVER",
        )
    except (KeyError, TypeError, ValueError) as exc:
        pytest.fail(
            f"supplementary fallback has no registered production publication seam: {exc}",
            pytrace=False,
        )
    assert contract.model_invoked is False
    assert all(row.writer == "DRIVER" for row in contract.outputs)
    assert tuple(row.path for row in contract.outputs) == (
        "recon_supplementary_disposition.json",
        "recon_supplementary_disposition_receipt.json",
    )

    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _prepare_sc_prepass_inputs(scratchpad, config)
    for job in D._recon_worker_jobs(config):
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
    M._merge_recon_worker_shards(scratchpad, config)

    attack_path = scratchpad / "attack_surface.md"
    attack_before = attack_path.read_bytes()

    def drift_after_stage(event: str) -> None:
        if event == "after_descriptor":
            attack_path.write_bytes(attack_before + b"\nforeign post-arm drift\n")

    drifted, drift_issues = D._write_and_record_recon_supplementary_disposition(
        scratchpad=scratchpad,
        config=config,
        effective_min_bytes=1,
        failure_injector=drift_after_stage,
    )
    assert drifted is None
    assert any("capture drifted" in issue for issue in drift_issues)
    assert not (scratchpad / "recon_supplementary_disposition.json").exists()
    assert not (scratchpad / "recon_supplementary_disposition_receipt.json").exists()
    attack_path.write_bytes(attack_before)

    def fail_second_replace(event: str) -> None:
        if event == "after_replace:recon_supplementary_disposition.json":
            raise OSError("fixture second-replacement interruption")

    failed, issues = D._write_and_record_recon_supplementary_disposition(
        scratchpad=scratchpad,
        config=config,
        effective_min_bytes=1,
        failure_injector=fail_second_replace,
    )
    assert failed is None and issues
    assert (scratchpad / "recon_supplementary_disposition.json").is_file()
    assert not (scratchpad / "recon_supplementary_disposition_receipt.json").exists()
    assert any(
        path.name == "descriptor.json"
        for path in (scratchpad / "_driver_vector_transactions").rglob("*")
    )

    payload, issues = D._write_and_record_recon_supplementary_disposition(
        scratchpad=scratchpad,
        config=config,
        effective_min_bytes=1,
    )
    assert issues == []
    assert payload is not None
    assert [row["identity"] for row in payload["rows"]] == [
        f"scratchpad:{name}" for name in (
            "attack_surface.md",
            "detected_patterns.md",
            "setter_list.md",
            "emit_list.md",
        )
    ]
    assert all(row["state"] == "DRIVER_FALLBACK" for row in payload["rows"])
    capture = _active_unit(scratchpad, "/recon/supplementary_disposition.source_capture")
    disposition = _active_unit(scratchpad, "/recon/supplementary_disposition")
    _assert_active_artifact(
        scratchpad,
        "recon_supplementary_disposition_input_authority.json",
        capture,
    )
    for name in (
        "recon_supplementary_disposition.json",
        "recon_supplementary_disposition_receipt.json",
    ):
        _assert_active_artifact(scratchpad, name, disposition)
    before = AL.read_artifact_ledger(scratchpad)
    before_bytes = {
        name: (scratchpad / name).read_bytes()
        for name in (
            "recon_supplementary_disposition_input_authority.json",
            "recon_supplementary_disposition.json",
            "recon_supplementary_disposition_receipt.json",
        )
    }
    replay, replay_issues = D._write_and_record_recon_supplementary_disposition(
        scratchpad=scratchpad,
        config=config,
        effective_min_bytes=1,
        failure_injector=lambda event: pytest.fail(
            f"exact replay reached publication: {event}", pytrace=False
        ),
    )
    assert replay_issues == [] and replay == payload
    assert AL.read_artifact_ledger(scratchpad) == before
    assert all((scratchpad / name).read_bytes() == raw for name, raw in before_bytes.items())

    forged = json.loads(json.dumps(before))
    forged["artifact_bindings"]["scratchpad:attack_surface.md"]["run_id"] = "foreign-run"
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: forged)
    rejected = D._recon_supplementary_disposition_payload(
        scratchpad,
        config,
        effective_min_bytes=1,
    )
    attack = next(
        row for row in rejected["rows"]
        if row["identity"] == "scratchpad:attack_surface.md"
    )
    assert attack["state"] == "DEBT"
    assert "producer_work_unit_key" not in attack

    forged_worker = json.loads(json.dumps(before))
    canonical_key = forged_worker["artifact_bindings"][
        "scratchpad:attack_surface.md"
    ]["owner_key"]
    evil_key = canonical_key.rsplit("/", 1)[0] + "/worker.evil"
    evil_owner = forged_worker["work_units"].pop(canonical_key)
    evil_owner["work_unit_key"] = evil_key
    evil_owner["artifacts"]["scratchpad:attack_surface.md"]["writer"] = "MODEL"
    forged_worker["work_units"][evil_key] = evil_owner
    forged_worker["artifact_bindings"]["scratchpad:attack_surface.md"][
        "owner_key"
    ] = evil_key
    forged_worker["artifact_bindings"]["scratchpad:attack_surface.md"][
        "writer"
    ] = "MODEL"
    monkeypatch.setattr(D, "read_artifact_ledger", lambda _root: forged_worker)
    rejected_worker = D._recon_supplementary_disposition_payload(
        scratchpad,
        config,
        effective_min_bytes=1,
    )
    attack = next(
        row for row in rejected_worker["rows"]
        if row["identity"] == "scratchpad:attack_surface.md"
    )
    assert attack["state"] == "DEBT"
    assert "producer_work_unit_key" not in attack


def test_output_vector_recovery_rejects_attacker_consistent_descriptor_mutation_free(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _prepare_sc_prepass_inputs(scratchpad, config)
    for job in D._recon_worker_jobs(config):
        (scratchpad / job["output"]).write_text(_shard(job), encoding="utf-8")
    M._merge_recon_worker_shards(scratchpad, config)

    def interrupt_after_first_replace(event: str) -> None:
        if event == "after_replace:recon_supplementary_disposition.json":
            raise OSError("leave one genuine recovery descriptor")

    payload, issues = D._write_and_record_recon_supplementary_disposition(
        scratchpad=scratchpad,
        config=config,
        effective_min_bytes=1,
        failure_injector=interrupt_after_first_replace,
    )
    assert payload is None and issues
    descriptor_path = next(
        (scratchpad / "_driver_vector_transactions").rglob("descriptor.json")
    )
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    attacker = b"attacker-selected prior bytes\n"
    descriptor["contract_digest"] = "a" * 64
    descriptor["rows"][0].update({
        "old_state": "PRESENT",
        "old_sha256": hashlib.sha256(attacker).hexdigest(),
        "old_size": len(attacker),
        "old_b64": base64.b64encode(attacker).decode("ascii"),
    })
    unsigned = dict(descriptor)
    unsigned.pop("descriptor_sha256")
    descriptor["descriptor_sha256"] = D._stable_payload_digest(unsigned)
    descriptor_path.write_text(
        json.dumps(descriptor, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    protected_paths = [
        scratchpad / "_artifact_state.json",
        scratchpad / "recon_supplementary_disposition.json",
        descriptor_path,
    ]
    before = {path: path.read_bytes() for path in protected_paths}
    rejected, rejected_issues = D._write_and_record_recon_supplementary_disposition(
        scratchpad=scratchpad,
        config=config,
        effective_min_bytes=1,
    )
    assert rejected is None
    assert any("vector recovery failed" in issue for issue in rejected_issues), rejected_issues
    assert {path: path.read_bytes() for path in protected_paths} == before
    assert not (scratchpad / "recon_supplementary_disposition_receipt.json").exists()
