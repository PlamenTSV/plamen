"""V4 live-entry RED denominator for recon fanout, dependency, and merge.

Every semantic route below calls the current production symbol.  Only the
external model/PTY process is replaced.  ArtifactLedger preparation, commit,
validation, deterministic dependency enumeration, merge rendering, and
consumer binding are never mocked.
"""
from __future__ import annotations

import hashlib
import json
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
from phase_io_contracts import (  # noqa: E402
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
    resolve_phase_io_contract,
)


RUN_ID = "cut4-recon-v4"
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
BREADTH_RECON_SIX = (
    "recon_summary.md",
    "attack_surface.md",
    "contract_inventory.md",
    "function_list.md",
    "state_variables.md",
    "template_recommendations.md",
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


def _publication_rows(root: Path, suffix: str) -> list[Mapping[str, Any]]:
    return [
        row for key, row in AL.read_artifact_ledger(root).get("work_units", {}).items()
        if str(key).endswith(suffix) or f"{suffix}/attempt-" in str(key)
        if isinstance(row, Mapping)
    ]


def _assert_changed_authority_transition(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    suffix: str,
    mutation: str,
) -> None:
    before_rows = [
        row for key, row in before.get("work_units", {}).items()
        if (str(key).endswith(suffix) or f"{suffix}/attempt-" in str(key))
        and isinstance(row, Mapping)
    ]
    after_rows = [
        row for key, row in after.get("work_units", {}).items()
        if (str(key).endswith(suffix) or f"{suffix}/attempt-" in str(key))
        and isinstance(row, Mapping)
    ]
    first_active = [
        row for row in before_rows
        if row.get("semantic_status") == "ACTIVE"
        and row.get("execution_state") == "OUTPUT_COMMITTED"
    ]
    assert len(first_active) == 1, "control lacks one genuine first ACTIVE generation"
    assert after != before, (
        f"complete ledger no-op after canonical {mutation} drift preserves stale authority"
    )

    old_key = first_active[0].get("work_unit_key")
    old_after = next(
        (row for row in after_rows if row.get("work_unit_key") == old_key), None
    )
    invalidated_old = isinstance(old_after, Mapping) and (
        old_after.get("semantic_status") != "ACTIVE"
        or old_after.get("execution_state") != "OUTPUT_COMMITTED"
    )
    successor = next(
        (row for row in after_rows if row.get("work_unit_key") != old_key), None
    )
    durable_successor = isinstance(successor, Mapping) and (
        successor.get("semantic_status") in {"ACTIVE", "INVALID", "DEBT"}
        or successor.get("execution_state") in {
            "INPUTS_BOUND_PREEXECUTION",
            "OUTPUT_ARMED",
            "OUTPUT_COMMITTED",
            "FAILED",
        }
    )
    assert invalidated_old or durable_successor, (
        f"canonical {mutation} drift left the first ACTIVE generation authoritative"
    )
    changed_bindings = {
        field
        for field in (
            "input_set_digest",
            "contract_digest",
            "namespace_digest",
            "source_capture_digest",
            "attempted_authority_digest",
        )
        if isinstance(successor, Mapping)
        and successor.get(field) != first_active[0].get(field)
    }
    assert changed_bindings, (
        f"canonical {mutation} transition recorded no changed authority binding"
    )


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
    monkeypatch.setattr(
        D.shutil,
        "which",
        lambda _name, *_args, **_kwargs: None,
    )
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


def test_dependency_zero_is_nonempty_typed_zero_not_zero_ledger(
    tmp_path: Path,
) -> None:
    _project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="light", route="codex", dependency=False
    )
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


def _prepare_real_sc_worker_shards(
    scratchpad: Path,
    project: Path,
    config: dict[str, Any],
) -> tuple[dict[str, str], ...]:
    phase = _phase(config)
    _prepare_sc_prepass_inputs(scratchpad, config)
    jobs = tuple(D._recon_worker_jobs(config))
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
        _assert_active_artifact(
            scratchpad,
            job["output"],
            _active_unit(scratchpad, f"/recon/worker.{job['agent_id'].lower()}"),
        )
    return jobs


def _commit_fixture_canonical_generation(
    scratchpad: Path,
    project: Path,
) -> Mapping[str, Any]:
    names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    for name in SC_CANONICAL:
        (scratchpad / name).write_text(
            f"# {name}\n\nmanual first canonical generation\n" + "c" * 180 + "\n",
            encoding="utf-8",
        )
    (scratchpad / "recon_signal_transform_receipt.json").write_text(
        json.dumps(
            {
                "schema": "plamen.recon_signal_transform_set.v1",
                "transforms": [{"kind": "fixture", "source": "committed"}],
            },
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )
    return _commit_fixture_driver_outputs(
        scratchpad,
        project,
        work_unit_id="canonical_merge",
        names=names,
    )


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

    producer = _active_unit(scratchpad, "/recon/canonical_merge")
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
    assert issues == []
    unit = _bound_unit(scratchpad, "/breadth/worker.b1")
    assert unit.get("artifacts") == {}
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in BREADTH_RECON_SIX
    }
    receipt_digest = producer["commit_authority"]["receipt_digest"]
    for name in BREADTH_RECON_SIX:
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


def test_breadth_prelaunch_binds_six_active_recon_inputs_before_output_commit(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="claude-headless"
    )
    for name in BREADTH_RECON_SIX:
        (scratchpad / name).write_text(
            f"# {name}\n\ncommitted canonical prerequisite\n" + "b" * 180 + "\n",
            encoding="utf-8",
        )
    producer = _commit_fixture_driver_outputs(
        scratchpad,
        project,
        work_unit_id="canonical_merge",
        names=BREADTH_RECON_SIX,
    )
    for name in BREADTH_RECON_SIX:
        _assert_active_artifact(scratchpad, name, producer)

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
    assert issues == []
    unit = _bound_unit(scratchpad, "/breadth/worker.b1")
    assert unit.get("semantic_status") == "INPUTS_BOUND"
    assert unit.get("execution_state") == "INPUTS_BOUND_PREEXECUTION"
    assert unit.get("artifacts") == {}
    assert set(unit.get("input_bindings", {})) == {
        f"scratchpad:{name}" for name in BREADTH_RECON_SIX
    }
    assert all(
        binding.get("status") == "ACTIVE"
        for binding in unit["input_bindings"].values()
    )

    (scratchpad / output).write_text(
        "# Breadth fixture\n\nexternal model output\n" + "o" * 220 + "\n",
        encoding="utf-8",
    )
    assert D._record_typed_model_worker_artifact(
        phase=breadth,
        config=config,
        scratchpad=scratchpad,
        project_root=str(project),
        agent_id="B1",
        output=output,
        timeout_s=30,
    ) == []
    committed = _active_unit(scratchpad, "/breadth/worker.b1")
    _assert_active_artifact(scratchpad, output, committed)


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
def test_live_canonical_merge_executes_named_crash_and_recovers_same_publisher(
    tmp_path: Path,
    failpoint: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="core", route="codex"
    )
    _prepare_real_sc_worker_shards(scratchpad, project, config)
    names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    before = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in names
    }
    hits: list[str] = []

    class InjectedCrash(RuntimeError):
        pass

    def injector(point: str, *_args: Any, **_kwargs: Any) -> None:
        hits.append(str(point))
        if str(point) == failpoint:
            raise InjectedCrash(failpoint)

    try:
        M._merge_recon_worker_shards(
            scratchpad,
            config,
            failure_injector=injector,
        )
    except InjectedCrash:
        pass
    except TypeError as exc:
        pytest.fail(
            f"real canonical merge cannot execute named injector {failpoint}: {exc}",
            pytrace=False,
        )
    assert failpoint in hits, f"publisher accepted but never executed {failpoint}"

    # Resume through the same production merge entry point.
    M._merge_recon_worker_shards(scratchpad, config)
    final = {
        name: ((scratchpad / name).read_bytes() if (scratchpad / name).is_file() else None)
        for name in names
    }
    all_old = final == before
    all_new = all(isinstance(raw, bytes) and raw for raw in final.values())
    assert all_old or all_new, "canonical crash recovery exposed a mixed postimage"
    if all_new:
        unit = _active_unit(scratchpad, "/recon/canonical_merge")
        for name in names:
            _assert_active_artifact(scratchpad, name, unit)
    else:
        assert any(
            row.get("semantic_status") in {"QUARANTINED", "DEBT", "REJECTED"}
            for row in _publication_rows(scratchpad, "/recon/canonical_merge")
        )


@pytest.mark.parametrize("drift", ("shard_bytes", "source_bytes"))
def test_live_canonical_drift_never_leaves_first_generation_active(
    tmp_path: Path,
    drift: str,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    jobs = _prepare_real_sc_worker_shards(scratchpad, project, config)
    M._merge_recon_worker_shards(scratchpad, config)
    _active_unit(scratchpad, "/recon/canonical_merge")
    before_ledger = AL.read_artifact_ledger(scratchpad)
    if drift == "shard_bytes":
        (scratchpad / jobs[0]["output"]).write_text(
            _shard(jobs[0]) + "\nchanged source shard\n", encoding="utf-8"
        )
    elif drift == "source_bytes":
        (Path(config["project_root"]) / "src" / "Protocol.sol").write_text(
            "pragma solidity ^0.8.20; contract Drift {}\n", encoding="utf-8"
        )
    M._merge_recon_worker_shards(scratchpad, config)
    after_ledger = AL.read_artifact_ledger(scratchpad)
    _assert_changed_authority_transition(
        before_ledger,
        after_ledger,
        suffix="/recon/canonical_merge",
        mutation=drift,
    )


@pytest.mark.parametrize("drift", ("shard_bytes", "source_bytes"))
def test_v4_rejects_v3_canonical_second_call_noop_counterexample(
    tmp_path: Path,
    drift: str,
) -> None:
    project, scratchpad, _config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="pty"
    )
    _commit_fixture_canonical_generation(scratchpad, project)
    before = AL.read_artifact_ledger(scratchpad)
    # Fileless counterexample: model the V3 false green, where a drifted retry
    # simply returns and leaves the complete first ledger generation untouched.
    after = AL.read_artifact_ledger(scratchpad)
    with pytest.raises(AssertionError, match="complete ledger no-op"):
        _assert_changed_authority_transition(
            before,
            after,
            suffix="/recon/canonical_merge",
            mutation=drift,
        )


def test_exact_canonical_noop_reuses_generation_without_semantic_write(
    tmp_path: Path,
) -> None:
    project, scratchpad, config = _workspace(
        tmp_path, pipeline="sc", mode="thorough", route="codex"
    )
    _prepare_real_sc_worker_shards(scratchpad, project, config)
    M._merge_recon_worker_shards(scratchpad, config)
    unit_before = dict(_active_unit(scratchpad, "/recon/canonical_merge"))
    names = (*SC_CANONICAL, "recon_signal_transform_receipt.json")
    files_before = {
        name: (
            hashlib.sha256((scratchpad / name).read_bytes()).hexdigest(),
            (scratchpad / name).stat().st_mtime_ns,
        )
        for name in names
    }
    ledger_before = AL.read_artifact_ledger(scratchpad)
    M._merge_recon_worker_shards(scratchpad, config)
    unit_after = _active_unit(scratchpad, "/recon/canonical_merge")
    files_after = {
        name: (
            hashlib.sha256((scratchpad / name).read_bytes()).hexdigest(),
            (scratchpad / name).stat().st_mtime_ns,
        )
        for name in names
    }
    assert files_after == files_before, "exact canonical retry performed a semantic write"
    assert unit_after.get("publication_generation") == unit_before.get(
        "publication_generation"
    )
    assert AL.read_artifact_ledger(scratchpad) == ledger_before


def test_supplementary_fallback_is_an_explicit_missing_production_seam() -> None:
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
