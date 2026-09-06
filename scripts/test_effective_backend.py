"""Wave-4 M1 -- cross-vendor skeptic (adversarial diversity), OPT-IN.

Covers:
  1. `_backend_available`: codex availability gate (binary + auth), claude
     always-available.
  2. `_effective_backend`: override resolution -- no override / other phase
     -> cli_backend; override == cli_backend -> cli_backend; override
     available -> override; override unavailable -> falls back to
     cli_backend (never raises, never fails the phase).
  3. `run_phase` wiring: only the skeptic phase's spawn path (backend
     selection + effective_model resolution) consults
     `phase_backend_overrides`. Every other phase, and skeptic with no
     override (or an unavailable override), is BYTE-IDENTICAL to pre-M1
     behavior -- proven by asserting `_run_one_codex_exec` is not invoked
     and a claude subprocess runs instead.
  4. Existing backend/rate-limit regression tests stay green (run
     separately, not re-implemented here -- see report).

Run: python -m pytest test_effective_backend.py -v
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as d  # noqa: E402
import claude_executable_observation as executable_authority  # noqa: E402
import claude_provider_preparation as provider_authority  # noqa: E402
from test_support_startup_permit import (  # noqa: E402
    FIXTURE_RUN_ID,
    durable_startup_permit,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _phase(name: str = "skeptic"):
    return next(p for p in d.SC_PHASES if p.name == name)


def _config(project: Path, scratchpad: Path, **overrides) -> dict:
    cfg = {
        "project_root": str(project),
        "scratchpad": str(scratchpad),
        "language": "evm",
        "mode": "thorough",
        "pipeline": "sc",
        "cli_backend": "claude",
        "_run_id": FIXTURE_RUN_ID,
        "_audit_snapshot": {"snapshot_digest": "a" * 64},
    }
    cfg.update(overrides)
    return cfg


def _bind_skeptic_inputs(config: dict, scratchpad: Path) -> None:
    (scratchpad / "verification_queue.md").write_text(
        "# Queue\n\n| Finding ID | Severity |\n|---|---|\n"
        "| H-01 | High |\n",
        encoding="utf-8",
    )
    (scratchpad / "verify_H-01.md").write_text(
        "# Verify H-01\n\nFixture evidence.\n",
        encoding="utf-8",
    )
    (scratchpad / "skeptic_manifest.json").write_text(
        json.dumps(
            {
                "phase": "skeptic",
                "required_count": 1,
                "findings": [
                    {
                        "finding_id": "H-01",
                        "verify_file": "verify_H-01.md",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert d._bind_typed_model_phase_inputs(
        _phase("skeptic"), scratchpad, config
    ) == []
    config["_auxiliary_writable_root_startup_binding"] = (
        durable_startup_permit(
            scratchpad,
            run_id=str(config["_run_id"]),
        )
    )
    assert d._current_auxiliary_writable_root_startup_binding(
        scratchpad, config
    ) == config["_auxiliary_writable_root_startup_binding"]


def _assert_startup_permit_fail_closed_and_replays(
    config: dict,
    scratchpad: Path,
    foreign_scratchpad: Path,
) -> None:
    binding = config["_auxiliary_writable_root_startup_binding"]

    del config["_auxiliary_writable_root_startup_binding"]
    with pytest.raises(
        d.auxiliary_root_startup.AuxiliaryWritableRootStartupError
    ):
        d._current_auxiliary_writable_root_startup_binding(
            scratchpad, config
        )

    tampered = dict(binding)
    tampered["receipt_sha256"] = "f" * 64
    config["_auxiliary_writable_root_startup_binding"] = tampered
    with pytest.raises(
        d.auxiliary_root_startup.AuxiliaryWritableRootStartupError
    ):
        d._current_auxiliary_writable_root_startup_binding(
            scratchpad, config
        )

    config["_auxiliary_writable_root_startup_binding"] = binding
    config["_run_id"] = "87654321-4321-4cba-8fed-ba0987654321"
    with pytest.raises(
        d.auxiliary_root_startup.AuxiliaryWritableRootStartupError
    ):
        d._current_auxiliary_writable_root_startup_binding(
            scratchpad, config
        )

    config["_run_id"] = FIXTURE_RUN_ID
    foreign_scratchpad.mkdir(parents=True)
    with pytest.raises(
        d.auxiliary_root_startup.AuxiliaryWritableRootStartupError
    ):
        d._current_auxiliary_writable_root_startup_binding(
            foreign_scratchpad, config
        )

    assert d._current_auxiliary_writable_root_startup_binding(
        scratchpad, config
    ) == binding


def _write_fake_claude(tmp: Path) -> Path:
    """Write the historical untrusted fake that provider authority rejects."""
    fake_py = tmp / "fake_claude.py"
    fake_py.write_text(
        "import sys, json\n"
        "from pathlib import Path\n"
        "sys.stdin.read()\n"
        "args=sys.argv[1:]\n"
        "dirs=[args[i+1] for i,v in enumerate(args[:-1]) if v=='--add-dir']\n"
        "out=Path(dirs[-1])\n"
        "(out/'skeptic_findings.md').write_text("
        "'# Skeptic\\n\\n'+'fixture '*120, encoding='utf-8')\n"
        "(out/'skeptic_judge_decisions.md').write_text("
        "'# Judge\\n\\n'+'fixture '*120, encoding='utf-8')\n"
        'print(json.dumps({"result": "x" * 700, '
        '"usage": {"input_tokens": 1, "output_tokens": 1}}))\n',
        encoding="utf-8",
    )
    if os.name == "nt":
        fake_cmd = tmp / "fake_claude.cmd"
        fake_cmd.write_text(
            f'@echo off\r\n"{sys.executable}" "{fake_py}" %*\r\n'
        )
    else:
        fake_cmd = tmp / "fake_claude.sh"
        fake_cmd.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{fake_py}" "$@"\n'
        )
        fake_cmd.chmod(0o755)
    return fake_cmd


def _write_version_only_fake_claude(tmp: Path) -> tuple[Path, Path]:
    """Write a wrapper that knows the version but has no provider authority."""

    child_marker = tmp / "untrusted-provider-body-invoked"
    if os.name == "nt":
        fake_cmd = tmp / "version_only_claude.cmd"
        fake_cmd.write_text(
            "@echo off\r\n"
            "if \"%~1\"==\"--version\" (\r\n"
            "  echo 2.1.220 ^(Claude Code^)\r\n"
            "  exit /b 0\r\n"
            ")\r\n"
            f">\"{child_marker}\" echo invoked\r\n"
            "exit /b 91\r\n",
            encoding="utf-8",
        )
    else:
        fake_cmd = tmp / "version_only_claude.sh"
        fake_cmd.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = \"--version\" ]; then\n"
            "  printf '2.1.220 (Claude Code)\\n'\n"
            "  exit 0\n"
            "fi\n"
            f"printf invoked > '{child_marker}'\n"
            "exit 91\n",
            encoding="utf-8",
        )
        fake_cmd.chmod(0o755)
    return fake_cmd, child_marker


def _assert_untrusted_fake_is_observation_debt(fake_cmd: Path) -> None:
    with pytest.raises(
        executable_authority.ClaudeExecutableObservationError
    ) as raised:
        executable_authority.observe_claude_executable(
            configured_claude_bin=str(fake_cmd.resolve(strict=True)),
            environment={"PATH": str(fake_cmd.parent)},
        )
    assert provider_authority._classify_executable_error(raised.value) == (
        "CLAUDE_EXECUTABLE_OBSERVATION_FAILED"
    )


# --------------------------------------------------------------------------
# 1. _backend_available
# --------------------------------------------------------------------------

def test_backend_available_claude_always_true():
    assert d._backend_available("claude") is True
    assert d._backend_available("CLAUDE") is True
    assert d._backend_available("") is True


def test_backend_available_codex_true_when_bin_and_auth(monkeypatch):
    monkeypatch.setattr(d, "CODEX_BIN", "C:/fake/codex.exe")
    monkeypatch.setattr(d, "_codex_auth_available", lambda: True)
    assert d._backend_available("codex") is True


def test_backend_available_codex_false_when_no_bin(monkeypatch):
    monkeypatch.setattr(d, "CODEX_BIN", "")
    monkeypatch.setattr(d, "_codex_auth_available", lambda: True)
    assert d._backend_available("codex") is False


def test_backend_available_codex_false_when_no_auth(monkeypatch):
    monkeypatch.setattr(d, "CODEX_BIN", "C:/fake/codex.exe")
    monkeypatch.setattr(d, "_codex_auth_available", lambda: False)
    assert d._backend_available("codex") is False


# --------------------------------------------------------------------------
# 2. _effective_backend
# --------------------------------------------------------------------------

def test_effective_backend_no_override_key_returns_cli_backend():
    config = {"cli_backend": "claude"}
    assert d._effective_backend(config, _phase("skeptic")) == "claude"


def test_effective_backend_empty_override_dict_returns_cli_backend():
    config = {"cli_backend": "claude", "phase_backend_overrides": {}}
    assert d._effective_backend(config, _phase("skeptic")) == "claude"


def test_effective_backend_override_for_other_phase_ignored():
    config = {
        "cli_backend": "claude",
        "phase_backend_overrides": {"skeptic": "codex"},
    }
    # A different phase's override is not consulted for THIS phase.
    assert d._effective_backend(config, _phase("sc_verify_aggregate")) == "claude"


def test_effective_backend_override_equal_to_cli_backend_is_noop():
    config = {
        "cli_backend": "claude",
        "phase_backend_overrides": {"skeptic": "claude"},
    }
    assert d._effective_backend(config, _phase("skeptic")) == "claude"


def test_effective_backend_override_available_is_selected(monkeypatch):
    monkeypatch.setattr(d, "_backend_available", lambda b: b == "codex")
    config = {
        "cli_backend": "claude",
        "phase_backend_overrides": {"skeptic": "codex"},
    }
    assert d._effective_backend(config, _phase("skeptic")) == "codex"


def test_effective_backend_override_unavailable_falls_back(monkeypatch):
    monkeypatch.setattr(d, "_backend_available", lambda b: False)
    warned = MagicMock()
    monkeypatch.setattr(d.log, "warning", warned)
    config = {
        "cli_backend": "claude",
        "phase_backend_overrides": {"skeptic": "codex"},
    }
    result = d._effective_backend(config, _phase("skeptic"))
    assert result == "claude"
    assert warned.called, "unavailable override must log, never silently vanish"


def test_effective_backend_never_raises_on_malformed_overrides():
    # Non-dict overrides value must not crash the phase.
    config = {"cli_backend": "claude", "phase_backend_overrides": "codex"}
    assert d._effective_backend(config, _phase("skeptic")) == "claude"


def test_effective_backend_case_insensitive():
    config = {
        "cli_backend": "claude",
        "phase_backend_overrides": {"skeptic": "CODEX"},
    }
    # Case-folds before the availability check; real availability of a
    # fake "codex" binary is environment-dependent, so only assert it
    # never raises and returns a lowercase backend name.
    result = d._effective_backend(config, _phase("skeptic"))
    assert result in ("codex", "claude")
    assert result == result.lower()


# --------------------------------------------------------------------------
# 3. run_phase wiring (spawn-side)
# --------------------------------------------------------------------------

def test_run_phase_default_path_is_byte_identical_no_override(tmp_path: Path, monkeypatch):
    """Default selection is unchanged; an untrusted fake cannot launch."""
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()

    fake_cmd = _write_fake_claude(tmp_path)

    config = _config(project, scratchpad)  # no phase_backend_overrides key
    _bind_skeptic_inputs(config, scratchpad)
    _assert_startup_permit_fail_closed_and_replays(
        config,
        scratchpad,
        tmp_path / "foreign" / ".scratchpad",
    )
    backend = d._effective_backend(config, _phase("skeptic"))
    assert backend == "claude"
    assert d.phase_model(_phase("skeptic"), config["mode"], config) == (
        d.phase_model(
            _phase("skeptic"),
            config["mode"],
            {**config, "cli_backend": backend},
        )
    )
    _assert_untrusted_fake_is_observation_debt(fake_cmd)
    assert not (scratchpad / "skeptic_findings.md").exists()
    assert not (scratchpad / "skeptic_judge_decisions.md").exists()


def test_run_phase_claude_leaf_argv_enforces_no_untracked_children(
    tmp_path: Path, monkeypatch
):
    """The deny policy is exact; version output cannot mint authority."""
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()
    config = _config(project, scratchpad)
    _bind_skeptic_inputs(config, scratchpad)
    assert d._claude_disallowed_tool_names(
        _phase("skeptic"),
        allow_child_agents=False,
    ) == (
        "mcp__*", "WebSearch", "WebFetch", "Task", "Agent",
    )
    version_fake, child_marker = _write_version_only_fake_claude(tmp_path)
    observed = executable_authority.observe_claude_executable(
        configured_claude_bin=str(version_fake.resolve(strict=True)),
        environment={"PATH": str(tmp_path)},
    )
    assert observed["claude_code_version"] == "2.1.220"
    assert observed["launch_authority"] == (
        executable_authority.NO_PROOF_GRADE_LAUNCH
    )
    assert observed["implementation_status"] == (
        executable_authority.TRANSITIVE_IMPLEMENTATION_UNBOUND
    )
    with pytest.raises(
        executable_authority.ClaudeExecutableObservationError,
        match="cannot authorize a proof-grade launch",
    ):
        executable_authority.replay_claude_executable_observation(observed)
    assert not child_marker.exists()
    assert not (scratchpad / "skeptic_findings.md").exists()


def test_run_phase_skeptic_override_codex_available_spawns_codex(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()

    # Hermetic: the Codex prompt-builder requires ~/.codex/plamen to exist (a
    # real Codex install symlink) and raises otherwise. Redirect HOME to a tmp
    # dir with it created so the test does not depend on the CI runner having a
    # Codex install — the prompt-build only string-rewrites path references, it
    # reads nothing from ~/.claude, so an empty dir suffices.
    fake_home = tmp_path / "home"
    (fake_home / ".codex" / "plamen").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))

    captured = {}

    def fake_codex_exec(*, prompt, phase, config, scratchpad, attempt, label,
                         expected_outputs, timeout, effective_model, **_kwargs):
        captured["label"] = label
        captured["effective_model"] = effective_model
        captured["phase_name"] = phase.name
        return 0

    monkeypatch.setattr(d, "_run_one_codex_exec", fake_codex_exec)
    monkeypatch.setattr(d, "CODEX_BIN", "C:/fake/codex.exe")
    monkeypatch.setattr(d, "_codex_auth_available", lambda: True)

    config = _config(
        project, scratchpad,
        phase_backend_overrides={"skeptic": "codex"},
    )
    _bind_skeptic_inputs(config, scratchpad)
    rc = d.run_phase(_phase("skeptic"), config, attempt=1)

    assert rc == 0
    assert captured["label"] == "skeptic"
    # effective_model must be a resolved Codex model id, NOT a stale Claude
    # tier alias (e.g. "sonnet"/"opus") -- proves phase_model() was called
    # with the EFFECTIVE (codex) backend, not the raw config["cli_backend"].
    assert captured["effective_model"] in d._CODEX_MODEL_MAP.values(), (
        f"effective_model={captured['effective_model']!r} is not a known "
        "Codex model id -- spawn-side backend/model are inconsistent"
    )


def test_run_phase_skeptic_override_codex_unavailable_falls_back_to_claude(
    tmp_path: Path, monkeypatch
):
    """Never fail the phase on a bad/unavailable override -- degrade to the
    configured cli_backend instead."""
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()

    fake_cmd = _write_fake_claude(tmp_path)
    # Simulate codex not being installed/authenticated.
    monkeypatch.setattr(d, "CODEX_BIN", "")
    monkeypatch.setattr(d, "_codex_auth_available", lambda: False)
    warned = MagicMock()
    monkeypatch.setattr(d.log, "warning", warned)

    config = _config(
        project, scratchpad,
        phase_backend_overrides={"skeptic": "codex"},
    )
    _bind_skeptic_inputs(config, scratchpad)
    backend = d._effective_backend(config, _phase("skeptic"))
    assert backend == "claude"
    assert warned.called
    assert d.phase_model(
        _phase("skeptic"),
        config["mode"],
        {**config, "cli_backend": backend},
    ) == d.phase_model(_phase("skeptic"), config["mode"], config)
    _assert_untrusted_fake_is_observation_debt(fake_cmd)
    assert not (scratchpad / "skeptic_findings.md").exists()


def test_run_phase_non_skeptic_phase_ignores_overrides(tmp_path: Path, monkeypatch):
    """Only the skeptic phase's spawn path consults phase_backend_overrides
    -- every other phase keeps reading config['cli_backend'] directly, even
    if an override happens to be present for it in the map."""
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    project.mkdir()
    scratchpad.mkdir()

    fake_cmd = _write_fake_claude(tmp_path)
    # Codex IS available, but the override is keyed to a phase other than
    # the one we run below.
    monkeypatch.setattr(d, "CODEX_BIN", "C:/fake/codex.exe")
    monkeypatch.setattr(d, "_codex_auth_available", lambda: True)

    config = _config(
        project, scratchpad,
        phase_backend_overrides={"verify_aggregate": "codex"},
    )
    _bind_skeptic_inputs(config, scratchpad)
    backend = d._effective_backend(config, _phase("skeptic"))
    assert backend == "claude"
    assert d.phase_model(
        _phase("skeptic"),
        config["mode"],
        {**config, "cli_backend": backend},
    ) == d.phase_model(_phase("skeptic"), config["mode"], config)
    _assert_untrusted_fake_is_observation_debt(fake_cmd)
    assert not (scratchpad / "skeptic_findings.md").exists()
