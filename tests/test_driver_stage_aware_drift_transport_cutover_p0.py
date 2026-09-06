"""Focused P0 coverage for driver drift decisions and headless cutover."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import plamen_driver as DRIVER  # noqa: E402


RUN_ID = "12345678-1234-5678-9234-567812345678"
KEY = bytes(range(32))
RUNTIME_CHANGE = {
    "component": "toolchain",
    "identity": "@runtime/tool/scip-go",
    "stored": {"sha256": "1" * 64, "byte_count": 123},
    "current": {"sha256": "2" * 64, "byte_count": 124},
}


def _drift(stage: str) -> DRIVER.AuditInputDriftError:
    return DRIVER.AuditInputDriftError(
        "drift",
        run_id=RUN_ID,
        phase="recon",
        detection_stage=stage,
        snapshot_verdict="MISMATCH",
        changed_components=("toolchain",),
        runtime_entry_changes=(RUNTIME_CHANGE,),
        stored_snapshot_digest="3" * 64,
        current_snapshot_digest="4" * 64,
    )


def _arm(tmp_path: Path, key: bytearray, *, protected: bool = False) -> Path:
    project = tmp_path / "project"
    scratch = project / ".scratchpad"
    scratch.mkdir(parents=True)
    receipt = (
        scratch / "forbidden.json"
        if protected
        else tmp_path / "external" / "decision.json"
    )
    DRIVER._PENDING_AUDIT_INPUT_DRIFT_MAC_KEY = key
    DRIVER._arm_audit_input_drift_decision_channel(
        requested_path=receipt,
        launch_intent=DRIVER.STARTUP_RESUME_EXISTING,
        project_root=project,
        scratchpad=scratch,
    )
    return receipt


def _verify_mac(value: dict) -> None:
    supplied = value["receipt_mac"]
    unsigned = {key: item for key, item in value.items() if key != "receipt_mac"}
    expected = hmac.new(
        KEY,
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert supplied == expected


@pytest.mark.parametrize(
    "stage,phase_state,generation_state",
    (
        (
            "PRE_PHASE_EXECUTION",
            "NOT_ENTERED_IN_THIS_INVOCATION",
            "NO_CURRENT_PHASE_GENERATION_LAUNCHED_IN_THIS_INVOCATION",
        ),
        (
            "POST_PHASE_EXECUTION",
            "EXECUTION_OR_RECOVERY_PATH_ENTERED",
            "UNKNOWN_MAY_HAVE_LAUNCHED",
        ),
    ),
)
def test_pre_and_post_drift_emit_exact_authenticated_exit5(
    stage, phase_state, generation_state, monkeypatch, tmp_path,
):
    key = bytearray(KEY)
    receipt = _arm(tmp_path, key)
    monkeypatch.setattr(DRIVER, "main", lambda: (_ for _ in ()).throw(_drift(stage)))

    assert DRIVER._run_main_entrypoint() == 5
    value = json.loads(receipt.read_text(encoding="utf-8"))
    assert set(value) == {
        "schema", "decision_kind", "run_id", "launch_intent", "exit_status",
        "phase", "detection_stage", "snapshot_verdict", "changed_components",
        "runtime_entry_changes", "stored_snapshot_digest",
        "current_snapshot_digest", "phase_execution_state",
        "audit_model_generation_state", "prior_phase_or_run_model_state",
        "drift_evidence_relative_path", "existing_evidence_deletion_performed",
        "driver_continued_after_detection", "required_action", "allowed_actions",
        "receipt_authentication_scope", "same_user_process_compromise_out_of_scope",
        "decision_id", "receipt_mac",
    }
    assert value["exit_status"] == 5
    assert value["detection_stage"] == stage
    assert value["phase_execution_state"] == phase_state
    assert value["audit_model_generation_state"] == generation_state
    assert value["runtime_entry_changes"] == [RUNTIME_CHANGE]
    unsigned = {
        key: item for key, item in value.items()
        if key not in {"decision_id", "receipt_mac"}
    }
    assert value["decision_id"] == hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    _verify_mac(value)
    assert key == bytearray(32)
    assert DRIVER._AUDIT_INPUT_DRIFT_DECISION_CHANNEL is None


def test_external_receipt_write_failure_is_conservative_exit5(
    monkeypatch, tmp_path, capsys,
):
    key = bytearray(KEY)
    receipt = _arm(tmp_path, key, protected=True)
    monkeypatch.setattr(
        DRIVER, "main",
        lambda: (_ for _ in ()).throw(_drift("PRE_PHASE_EXECUTION")),
    )

    assert DRIVER._run_main_entrypoint() == 5
    assert not receipt.exists()
    output = capsys.readouterr().err
    assert "WRITE_FAILED" in output
    assert "No current-phase audit-model generation" not in output
    assert key == bytearray(32)


def test_typed_internal_drift_retains_runtime_entry_changes(tmp_path):
    scratch = tmp_path / ".scratchpad"
    scratch.mkdir()
    config = {"_run_id": RUN_ID}
    with pytest.raises(DRIVER.AuditInputDriftError) as raised:
        DRIVER._raise_typed_audit_input_drift(
            config=config,
            scratchpad=scratch,
            phase_label="recon:post-execution",
            snapshot_verdict="MISMATCH",
            changed_components=("toolchain",),
            runtime_entry_changes=(RUNTIME_CHANGE,),
            stored_snapshot_digest="3" * 64,
            current_snapshot_digest="4" * 64,
        )
    assert raised.value.detection_stage == "POST_PHASE_EXECUTION"
    internal = json.loads(
        (scratch / "audit_input_drift.json").read_text(encoding="utf-8")
    )
    assert internal["runtime_entry_changes"] == [RUNTIME_CHANGE]
    assert internal["detection_stage"] == "POST_PHASE_EXECUTION"


def _config(tmp_path: Path, **updates) -> dict:
    value = {
        "project_root": str(tmp_path / "project"),
        "scratchpad": str(tmp_path / "project" / ".scratchpad"),
        "pipeline": "sc",
        "mode": "thorough",
        "cli_backend": "claude",
    }
    value.update(updates)
    return value


@pytest.mark.parametrize("source", ("config", "environment"))
def test_explicit_or_ambient_pty_is_rejected_without_mutation(
    source, monkeypatch, tmp_path,
):
    config = _config(tmp_path)
    if source == "config":
        config["claude_exec_mode"] = "pty"
        monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
    else:
        monkeypatch.setenv("PLAMEN_CLAUDE_EXEC_MODE", "pty")
    before = dict(config)
    with pytest.raises(ValueError, match="PTY transport"):
        DRIVER._admit_driver_transport_cutover(
            config, config_path=tmp_path / "config.json",
        )
    assert config == before
    assert not Path(config["scratchpad"]).exists()


def test_missing_mode_fresh_sc_thorough_derives_headless_without_home_write(
    monkeypatch, tmp_path,
):
    home = tmp_path / "home"
    home.mkdir()
    sentinel = home / ".claude.json"
    sentinel.write_bytes(b"USER-SENTINEL\n")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
    config = _config(tmp_path)

    DRIVER._admit_driver_transport_cutover(
        config, config_path=tmp_path / "config.json",
    )
    assert config["claude_exec_mode"] == "headless"
    assert sentinel.read_bytes() == b"USER-SENTINEL\n"
    assert sorted(path.name for path in home.iterdir()) == [".claude.json"]


def test_missing_mode_legacy_checkpoint_stops_and_preserves_bytes(
    monkeypatch, tmp_path,
):
    monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
    config = _config(tmp_path)
    scratch = Path(config["scratchpad"])
    scratch.mkdir(parents=True)
    checkpoint = scratch / "_v2_checkpoint.json"
    original = b'{"legacy":"pty"}\n'
    checkpoint.write_bytes(original)

    with pytest.raises(ValueError, match="legacy checkpoint"):
        DRIVER._admit_driver_transport_cutover(
            config, config_path=tmp_path / "config.json",
        )
    assert checkpoint.read_bytes() == original
    assert "claude_exec_mode" not in config


def test_codex_primary_with_claude_override_enters_same_headless_cutover(
    monkeypatch, tmp_path,
):
    monkeypatch.delenv("PLAMEN_CLAUDE_EXEC_MODE", raising=False)
    config = _config(
        tmp_path,
        cli_backend="codex",
        phase_backend_overrides={"skeptic": "claude"},
    )
    assert DRIVER._configured_audit_uses_claude(config) is True
    DRIVER._admit_driver_transport_cutover(
        config, config_path=tmp_path / "config.json",
    )
    assert config["claude_exec_mode"] == "headless"


@pytest.mark.parametrize(
    "updates", ({"mode": "core"}, {"pipeline": "l1"}),
)
def test_claude_cutover_is_limited_to_current_sc_thorough(updates, tmp_path):
    config = _config(tmp_path, claude_exec_mode="headless", **updates)
    with pytest.raises(ValueError, match="only for SC Thorough"):
        DRIVER._admit_driver_transport_cutover(
            config, config_path=tmp_path / "config.json",
        )


def test_main_no_longer_invokes_user_folder_trust_writer():
    import inspect

    source = inspect.getsource(DRIVER.main)
    assert "_ensure_claude_folder_trusted(" not in source
