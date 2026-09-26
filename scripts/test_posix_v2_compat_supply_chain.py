"""Focused tests for the explicit post-session POSIX supply-chain lane."""
from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest

import plamen_driver as D
import posix_v2_compat_runtime as compat_runtime
import recon_prepass as R
import supply_chain_gate as S


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-only route")


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    scratchpad.mkdir(parents=True)
    return project.resolve(), scratchpad.resolve()


def _session(project: Path, scratchpad: Path):
    return compat_runtime.issue_posix_v2_compat_session_for_installed_front(
        run_id="compat-supply-chain-test",
        project_root=project,
        scratchpad=scratchpad,
    )


def _osv_clean_payload() -> dict:
    return {"results": []}


def test_pre_snapshot_compat_defers_every_target_subprocess(
    tmp_path, monkeypatch,
):
    project, scratchpad = _roots(tmp_path)
    (project / "package.json").write_text("{}\n", encoding="utf-8")
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        R,
        "gate_supply_chain",
        lambda *_args, **_kwargs: pytest.fail("pre-session scanner executed"),
    )
    monkeypatch.setattr(
        R,
        "_run_cmd",
        lambda *_args, **_kwargs: pytest.fail("target command executed"),
    )
    config = {
        "pipeline": "sc",
        "language": "evm",
        "project_root": str(project),
        "scratchpad": str(scratchpad),
    }

    receipt = R.prepare_snapshot_bound_inputs(
        config, posix_compat_v2=True
    )

    assert receipt["status"] == "DEGRADED"
    assert "PRE_SNAPSHOT_MATERIALIZATION_DEFERRED" in receipt["reason"]
    assert "no target subprocess" in receipt["reason"]
    assert config["_snapshot_input_preparation"] == receipt


def test_driver_threads_pre_snapshot_defer_only_from_process_marker(
    monkeypatch,
):
    calls: list[dict] = []

    def prepare(config, **kwargs):
        calls.append(dict(kwargs))
        return {"status": "DEGRADED", "reason": "test"}

    monkeypatch.setattr(R, "prepare_snapshot_bound_inputs", prepare)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_PROCESS_MARKER", None)
    D._prepare_snapshot_bound_inputs({})
    monkeypatch.setattr(
        D,
        "_POSIX_COMPAT_V2_PROCESS_MARKER",
        D._POSIX_COMPAT_V2_MARKER_TOKEN,
    )
    D._prepare_snapshot_bound_inputs({})

    assert calls == [{}, {"posix_compat_v2": True}]


def test_driver_threads_opaque_runtime_only_for_native_guest(monkeypatch):
    calls: list[dict] = []
    native = object()

    def prepare(config, **kwargs):
        calls.append(dict(kwargs))
        return {"status": "PREPARED", "reason": "native"}

    config = D._DriverConfig({}, native_guest_runtime_authorities=native)
    monkeypatch.setattr(R, "prepare_snapshot_bound_inputs", prepare)
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_PROCESS_MARKER", None)
    monkeypatch.setattr(
        D, "_native_guest_runtime_authorities_for_launch", lambda value: (
            native if value is config else pytest.fail("foreign config")
        )
    )

    D._prepare_snapshot_bound_inputs(config)

    assert calls == [{"native_runtime_authority": native}]


def test_exact_opaque_session_is_required_and_roots_are_bound(tmp_path):
    project, scratchpad = _roots(tmp_path)
    authority = _session(project, scratchpad)
    try:
        admitted = S._validated_posix_v2_compat_session(
            authority, scan_root=project
        )
        assert admitted.project_root == project
        assert admitted.scratchpad == scratchpad
        with pytest.raises(S.SupplyChainAbortError, match="exact POSIX V2"):
            S._validated_posix_v2_compat_session(
                object(), scan_root=project
            )
        outside = tmp_path / "outside"
        outside.mkdir()
        with pytest.raises(S.SupplyChainAbortError, match="boundary"):
            S._validated_posix_v2_compat_session(
                authority, scan_root=outside
            )
    finally:
        authority.close()


def test_osv_transport_uses_exact_offline_flags_and_typed_json(
    tmp_path, monkeypatch,
):
    project, scratchpad = _roots(tmp_path)
    lockfile = project / "package-lock.json"
    lockfile.write_text("{}\n", encoding="utf-8")
    authority = _session(project, scratchpad)
    popen_calls: list[tuple[list[str], dict]] = []
    raw_payload = json.dumps(_osv_clean_payload()).encode("utf-8")

    class FakePopen:
        pid = 424242

        def __init__(self, argv, **kwargs):
            popen_calls.append((list(argv), dict(kwargs)))
            kwargs["stdout"].write(raw_payload)

        def wait(self, timeout):
            assert timeout == 120
            return 0

    monkeypatch.setattr(S.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(
        S,
        "run_owned_process",
        lambda *_args, **_kwargs: pytest.fail("native runner was reached"),
    )
    binary = S._AuthorizedScanner("osv-scanner", str(sys.executable))
    try:
        result = S._call_offline_scanner(
            binary, lockfile, posix_compat_session=authority
        )
    finally:
        authority.close()

    assert result.state is S.OfflineScanState.SUCCEEDED
    assert json.loads(result.output) == _osv_clean_payload()
    assert len(popen_calls) == 1
    execution_argv, kwargs = popen_calls[0]
    scan_index = execution_argv.index("scan")
    transient = Path(kwargs["cwd"])
    assert execution_argv[scan_index:] == [
        "scan",
        "--offline",
        "--offline-vulnerabilities",
        "-L",
        str(lockfile),
        "--format",
        "json",
        "--config",
        str(transient / "osv-scanner.toml"),
    ]
    assert kwargs["shell"] is False
    assert kwargs["start_new_session"] is True
    assert transient.parent == scratchpad
    for key in ("TMPDIR", "XDG_CACHE_HOME"):
        assert Path(kwargs["env"][key]).is_relative_to(transient)
    assert not transient.exists()
    receipts = list(
        (scratchpad / S._POSIX_COMPAT_RECEIPT_DIR).glob("*.json")
    )
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
    properties = receipt["security_properties"]
    assert properties["population_zero_proven"] is False
    assert properties["native_owned_process_runner"] is False
    assert receipt["writable_roots"][0].startswith(str(scratchpad) + os.sep)
    assert receipt["read_only_intent_roots"] == [str(project)]
    if sys.platform == "darwin":
        assert properties["write_confinement"] == "DARWIN_SEATBELT"


def test_timeout_kills_the_new_process_group_and_fails_closed(
    tmp_path, monkeypatch,
):
    project, scratchpad = _roots(tmp_path)
    lockfile = project / "package-lock.json"
    lockfile.write_text("{}\n", encoding="utf-8")
    authority = _session(project, scratchpad)
    kills: list[tuple[int, int]] = []

    class TimeoutPopen:
        pid = 818181

        def __init__(self, _argv, **_kwargs):
            self.waits = 0

        def wait(self, timeout):
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired(["osv-scanner"], timeout)
            return -signal.SIGTERM

        def kill(self):
            pytest.fail("direct child kill used before process-group kill")

    monkeypatch.setattr(S.subprocess, "Popen", TimeoutPopen)
    monkeypatch.setattr(
        S.os, "killpg", lambda pid, sig: kills.append((pid, sig))
    )
    binary = S._AuthorizedScanner("osv-scanner", str(sys.executable))
    try:
        result = S._call_offline_scanner(
            binary, lockfile, posix_compat_session=authority
        )
    finally:
        authority.close()

    assert result.state is S.OfflineScanState.FAILED
    assert result.returncode == 124
    assert "timed out" in result.reason
    assert kills == [(818181, signal.SIGTERM)]


def test_normal_transport_remains_owned_runner_with_offline_osv_argv(
    tmp_path, monkeypatch,
):
    project, _scratchpad = _roots(tmp_path)
    lockfile = project / "package-lock.json"
    lockfile.write_text("{}\n", encoding="utf-8")
    calls = []

    def run_owned(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        return type(
            "Result",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(_osv_clean_payload()),
                "stderr": "",
            },
        )()

    monkeypatch.setattr(S, "run_owned_process", run_owned)
    monkeypatch.setattr(
        S.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("compat Popen was reached"),
    )
    result = S._call_offline_scanner(
        S._AuthorizedScanner("osv-scanner", str(sys.executable)), lockfile
    )

    assert result.state is S.OfflineScanState.SUCCEEDED
    command, kwargs = calls[0]
    assert command == [
        str(sys.executable),
        "scan",
        "--offline",
        "--offline-vulnerabilities",
        "-L",
        str(lockfile),
        "--format",
        "json",
        "--config",
        str(Path(kwargs["cwd"]) / "osv-scanner.toml"),
    ]


def test_dual_lock_denominator_runs_two_osv_scans_under_same_session(
    tmp_path, monkeypatch,
):
    project, scratchpad = _roots(tmp_path)
    (project / "package-lock.json").write_text("{}\n", encoding="utf-8")
    (project / "yarn.lock").write_text("fixture\n", encoding="utf-8")
    authority = _session(project, scratchpad)
    scanner_bin = tmp_path / "scanner-bin"
    scanner_bin.mkdir()
    osv = scanner_bin / "osv-scanner"
    osv.write_text(
        "#!/bin/sh\nprintf '%s\\n' '{\"results\":[]}'\n",
        encoding="utf-8",
    )
    osv.chmod(0o755)
    monkeypatch.setenv("PATH", str(scanner_bin))
    try:
        admission = S.gate_supply_chain(
            project, denylist=[], posix_compat_session=authority
        )
        view = S.project_supply_chain_admission(
            admission, posix_compat_session=authority,
        )
    finally:
        authority.close()

    assert [(row["scanner_id"], Path(row["lockfile"]).name) for row in view["scanner_evidence"]] == [
        ("osv-scanner", "package-lock.json"),
        ("osv-scanner", "yarn.lock"),
    ]


def test_osv_compat_command_preserves_offline_neutral_config_flags(tmp_path):
    project, scratchpad = _roots(tmp_path)
    lockfile = project / "yarn.lock"
    lockfile.write_text("fixture\n", encoding="utf-8")
    transient = scratchpad / "transient"
    transient.mkdir()

    command = S._compat_scanner_command(
        "osv-scanner", "/trusted/osv-scanner", lockfile, transient
    )

    assert not isinstance(command, S.OfflineScanResult)
    argv, cwd = command
    assert argv == [
        "/trusted/osv-scanner",
        "scan",
        "--offline",
        "--offline-vulnerabilities",
        "-L",
        str(lockfile),
        "--format",
        "json",
        "--config",
        str(transient / "osv-scanner.toml"),
    ]
    assert cwd == transient


def test_main_orders_strict_gate_immediately_after_session_issue():
    source = inspect.getsource(D.main)
    issue = source.index("_issue_posix_v2_compat_session(")
    gate = source.index("_run_posix_v2_compat_supply_chain_gate(config)", issue)
    debt = source.index("_record_posix_v2_compat_runtime_debt(", gate)
    assert issue < gate < debt


def test_compat_gate_rejects_ambient_skip_and_driver_passes_exact_session(
    tmp_path, monkeypatch,
):
    project, scratchpad = _roots(tmp_path)
    authority = _session(project, scratchpad)
    monkeypatch.setenv("PLAMEN_SKIP_SUPPLY_CHAIN_GATE", "1")
    try:
        with pytest.raises(S.SupplyChainAbortError, match="cannot bypass"):
            S.gate_supply_chain(
                project, posix_compat_session=authority
            )
    finally:
        authority.close()

    calls = []
    monkeypatch.delenv("PLAMEN_SKIP_SUPPLY_CHAIN_GATE")
    monkeypatch.setattr(
        D,
        "_POSIX_COMPAT_V2_PROCESS_MARKER",
        D._POSIX_COMPAT_V2_MARKER_TOKEN,
    )
    exact_session = object()
    monkeypatch.setattr(D, "_POSIX_COMPAT_V2_SESSION_AUTHORITY", exact_session)
    monkeypatch.setattr(
        S,
        "gate_supply_chain",
        lambda root, *, posix_compat_session: calls.append(
            (Path(root), posix_compat_session)
        ),
    )

    D._run_posix_v2_compat_supply_chain_gate(
        {"project_root": str(project)}
    )

    assert calls == [(project, exact_session)]
