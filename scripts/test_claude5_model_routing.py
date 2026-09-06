"""Claude 5 routing admission and wizard-summary regressions."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import plamen_types as types
import plamen_driver as driver


def _phase(phases, name):
    return next(phase for phase in phases if phase.name == name)


def _load_front():
    spec = importlib.util.spec_from_file_location(
        "plamen_claude5_front", ROOT / "plamen.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    saved = sys.argv
    sys.argv = ["plamen.py"]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.argv = saved
    return module


@pytest.mark.parametrize("phases,pipeline", ((types.SC_PHASES, "sc"), (types.L1_PHASES, "l1")))
def test_light_routes_every_active_phase_to_sonnet5(phases, pipeline):
    config = {
        "pipeline": pipeline,
        "cli_backend": "claude",
        "breadth_model_override": "claude-opus-5",
    }
    active = [phase for phase in phases if "light" in phase.modes]
    assert active
    assert {
        types.phase_model(phase, "light", config) for phase in active
    } == {"claude-sonnet-5"}


def test_core_and_thorough_admit_only_current_opus_sonnet_ids():
    for phases, pipeline in ((types.SC_PHASES, "sc"), (types.L1_PHASES, "l1")):
        for mode in ("core", "thorough"):
            config = {"pipeline": pipeline, "cli_backend": "claude"}
            models = {
                types.phase_model(phase, mode, config)
                for phase in phases
                if mode in phase.modes
            }
            assert models <= {
                "claude-opus-5",
                "claude-sonnet-5",
            }
            assert "claude-opus-5" in models
            assert "claude-sonnet-5" in models


@pytest.mark.parametrize(
    "override",
    (
        "claude-opus-4-8",
        "claude-sonnet-4-5",
        "opus",
        "sonnet",
        "claude-opus-5 ",
        "gpt-5.6-sol",
        5,
    ),
)
@pytest.mark.parametrize("mode", ("light", "core", "thorough"))
def test_breadth_override_rejects_nonexact_or_stale_ids(override, mode):
    breadth = _phase(types.SC_PHASES, "breadth")
    with pytest.raises(ValueError, match="breadth model override"):
        types.phase_model(
            breadth,
            mode,
            {
                "pipeline": "sc",
                "cli_backend": "claude",
                "breadth_model_override": override,
                "allow_model_fallback": True,
            },
        )


@pytest.mark.parametrize(
    "override,expected",
    (
        ("claude-opus-5", "claude-opus-5"),
        ("claude-sonnet-5", "claude-sonnet-5"),
    ),
)
def test_valid_breadth_override_is_exact_but_light_stays_sonnet5(
    override, expected
):
    breadth = _phase(types.SC_PHASES, "breadth")
    config = {
        "pipeline": "sc",
        "cli_backend": "claude",
        "breadth_model_override": override,
    }
    assert types.phase_model(breadth, "core", config) == expected
    assert types.phase_model(breadth, "light", config) == "claude-sonnet-5"


@pytest.mark.parametrize(
    "name,value",
    (
        ("PLAMEN_OPUS_MODEL", "claude-opus-4-8"),
        ("PLAMEN_SONNET_MODEL", "claude-sonnet-4-5"),
        ("PLAMEN_HAIKU_MODEL", "claude-opus-4-8"),
        ("PLAMEN_HAIKU_MODEL", "claude-haiku-4-5-20251001"),
        ("PLAMEN_THOROUGH_OPUS_MODEL", "claude-opus-4-7"),
    ),
)
def test_stale_environment_model_is_rejected_at_import(name, value):
    env = dict(os.environ)
    for key in (
        "PLAMEN_OPUS_MODEL",
        "PLAMEN_SONNET_MODEL",
        "PLAMEN_HAIKU_MODEL",
        "PLAMEN_THOROUGH_OPUS_MODEL",
    ):
        env.pop(key, None)
    env[name] = value
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.path.insert(0, 'scripts'); import plamen_types",
        ],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert "admitted current ID" in result.stderr


def test_wizard_summary_reports_exact_current_ids(monkeypatch):
    front = _load_front()
    for key in ("PLAMEN_OPUS_MODEL", "PLAMEN_SONNET_MODEL"):
        monkeypatch.delenv(key, raising=False)
    assert front._wizard_model_summary("claude", "light") == (
        "Claude Code / claude-sonnet-5"
    )
    summary = front._wizard_model_summary("claude", "thorough")
    assert "claude-opus-5" in summary
    assert "claude-sonnet-5" in summary


def test_noninteractive_thorough_plan_is_provider_free_and_path_native(
    tmp_path, monkeypatch
):
    front = _load_front()
    project = tmp_path / "unicode project δ" / "contracts"
    project.mkdir(parents=True)
    (project / "Token.sol").write_text(
        "pragma solidity ^0.8.20; contract Token {}\n", encoding="utf-8"
    )
    monkeypatch.setattr(front, "_detect_cli_backends", lambda: ["claude"])
    monkeypatch.setattr(
        front, "_claude_headless_transport_capability",
        lambda: {
            "available": True, "platform": "TEST", "reason": "",
            "write_authority": "EXHAUSTIVE",
        },
    )
    plan = front._public_plan(
        "thorough", [str(project), "--claude", "--json"]
    )
    assert plan["provider_invocations"] == 0
    assert plan["target"] == os.path.abspath(project)
    assert plan["config_path"] == os.path.join(
        os.path.abspath(project), ".scratchpad", "config.json"
    )
    assert {row["model"] for row in plan["routes"]} == {
        "claude-opus-5", "claude-sonnet-5",
    }
    assert not (project / ".scratchpad").exists()


@pytest.mark.parametrize(
    "name,value,mode",
    (
        ("PLAMEN_OPUS_MODEL", "claude-opus-4-8", "core"),
        ("PLAMEN_SONNET_MODEL", "claude-sonnet-4-5", "light"),
        ("PLAMEN_HAIKU_MODEL", "claude-opus-4-8", "core"),
        ("PLAMEN_HAIKU_MODEL", "claude-haiku-4-5-20251001", "thorough"),
        ("PLAMEN_THOROUGH_OPUS_MODEL", "claude-opus-4-8", "light"),
    ),
)
def test_wizard_summary_rejects_stale_environment_models(
    monkeypatch, name, value, mode
):
    front = _load_front()
    monkeypatch.setenv(name, value)
    with pytest.raises(RuntimeError, match="admitted current ID"):
        front._wizard_model_summary("claude", mode)


def test_noninteractive_config_rejects_stale_claude_environment(monkeypatch):
    front = _load_front()
    monkeypatch.setattr(
        front, "_claude_headless_transport_capability",
        lambda: {
            "available": True, "platform": "TEST", "reason": "",
            "write_authority": "EXHAUSTIVE",
        },
    )
    monkeypatch.setenv("PLAMEN_THOROUGH_OPUS_MODEL", "claude-opus-4-8")
    with pytest.raises(RuntimeError, match="admitted current ID"):
        front._launch_v2_config_value(
            "sc", "thorough", ".", "evm", cli_backend="claude"
        )


@pytest.mark.parametrize(
    "configured,expected",
    (
        ("opus", "claude-opus-5"),
        ("sonnet", "claude-sonnet-5"),
        ("claude-opus-5", "claude-opus-5"),
        ("claude-sonnet-5", "claude-sonnet-5"),
    ),
)
def test_verification_recovery_accepts_only_current_exact_routes(
    configured, expected
):
    assert driver._verify_recovery_model(
        {
            "cli_backend": "claude",
            "mode": "core",
            "_verification_recovery_model": configured,
        }
    ) == expected


@pytest.mark.parametrize(
    "configured",
    (
        "claude-opus-4-8",
        "claude-sonnet-4-5",
        "claude-opus-5 ",
        " Opus",
        "gpt-5.6-sol",
        "haiku",
        "claude-haiku-4-5-20251001",
        5,
        False,
    ),
)
def test_verification_recovery_rejects_stale_arbitrary_and_noncanonical_routes(
    configured,
):
    with pytest.raises(ValueError, match="verification recovery model"):
        driver._verify_recovery_model(
            {
                "cli_backend": "claude",
                "mode": "core",
                "allow_model_fallback": True,
                "_verification_recovery_model": configured,
            }
        )


@pytest.mark.parametrize(
    "config_update,environment_update",
    (
        ({"breadth_model_override": "claude-opus-4-8"}, {}),
        ({"_verification_recovery_model": "claude-sonnet-4-5"}, {}),
        (
            {"breadth_model_override": "claude-sonnet-5"},
            {"PLAMEN_BREADTH_MODEL_OVERRIDE": "claude-sonnet-4-5"},
        ),
    ),
)
def test_driver_startup_rejects_every_model_route_before_mutation_or_provider(
    tmp_path, monkeypatch, config_update, environment_update
):
    project = tmp_path / "project"
    project.mkdir()
    sentinel = project / "sentinel.sol"
    sentinel.write_bytes(b"contract Sentinel {}\n")
    scratchpad = project / ".scratchpad-never-created"
    config = {
        "project_root": os.fspath(project),
        "scratchpad": os.fspath(scratchpad),
        "language": "evm",
        "mode": "core",
        "pipeline": "sc",
        "cli_backend": "claude",
        **config_update,
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    before_project = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file()
    }
    before_config = config_path.read_bytes()
    for name, value in environment_update.items():
        monkeypatch.setenv(name, value)

    calls = []

    def forbidden(name):
        def stop(*_args, **_kwargs):
            calls.append(name)
            raise AssertionError(f"{name} ran before model admission")

        return stop

    monkeypatch.setattr(driver.display, "install_detached_output_guards", lambda: None)
    monkeypatch.setattr(driver, "_admit_direct_driver_projection", forbidden("projection"))
    monkeypatch.setattr(driver, "run_phase", forbidden("provider"))
    monkeypatch.setattr(driver.subprocess, "Popen", forbidden("subprocess"))
    monkeypatch.setattr(
        driver.sys, "argv", [os.fspath(Path(driver.__file__)), os.fspath(config_path)]
    )

    with pytest.raises(SystemExit) as stopped:
        driver.main()

    assert stopped.value.code == driver.EXIT_CONFIG_MISSING
    assert calls == []
    assert not scratchpad.exists()
    assert config_path.read_bytes() == before_config
    assert {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in project.rglob("*")
        if path.is_file()
    } == before_project


def test_model_summary_does_not_swallow_invalid_route():
    with pytest.raises(ValueError, match="breadth model override"):
        driver._format_ai_model_summary(
            {
                "cli_backend": "claude",
                "pipeline": "sc",
                "breadth_model_override": "claude-opus-4-8",
            },
            [_phase(types.SC_PHASES, "breadth")],
            "core",
        )


@pytest.mark.parametrize(
    "phases,pipeline",
    ((types.SC_PHASES, "sc"), (types.L1_PHASES, "l1")),
)
@pytest.mark.parametrize("mode", ("light", "core", "thorough"))
def test_complete_active_claude_roster_has_no_haiku_or_stale_route(
    phases, pipeline, mode
):
    models = {
        types.phase_model(
            phase,
            mode,
            {"pipeline": pipeline, "cli_backend": "claude"},
        )
        for phase in phases
        if mode in phase.modes
    }
    expected = (
        {"claude-sonnet-5"}
        if mode == "light"
        else {"claude-opus-5", "claude-sonnet-5"}
    )
    assert models <= expected
    assert models


def test_nested_claude_haiku_alias_is_bound_to_sonnet5():
    assert types.PLAMEN_HAIKU_MODEL == "claude-sonnet-5"
