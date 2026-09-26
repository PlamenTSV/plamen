"""The Claude Code builtin `agents-md` plugin must be disabled deterministically.

DODO run44 (2026-09-19, generation 3b99eee1) halted at `instantiate`: the
Claude CLI had auto-updated 2.1.273 -> 2.1.278 between run43 and run44, and the
new CLI ships a BUILTIN plugin `agents-md@builtin` ("AGENTS.md as project
instructions: by default loaded where the project has no CLAUDE.md").  Two of
eight recon-era workers and both instantiate attempts reported it in their
`system/init` event; the fail-closed init-applicability gate expects
`plugins == []` and rejected them (`INIT_APPLICABILITY_MISMATCH`), so the phase
degraded after two attempts and the run stopped.

The gate is right: an audited repository's AGENTS.md is an instruction-
injection surface the driver never armed.  The fix is on the CONTROL side --
the per-worker settings overlay disables the builtin -- and the value has ONE
owner (`pty_exec.CLAUDE_SETTINGS_ENABLED_PLUGINS`) that every writer and
validator imports, so the writers and the gate cannot drift apart again.

Measured on 2.1.278 with the driver's flags: `enabledPlugins: {}` loaded the
plugin 6/6 launches; `{"agents-md@builtin": false}` loaded it 0/6, with the
PreToolUse hook still firing and the granted tool still usable on BOTH 2.1.273
and 2.1.278.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import pty_exec  # noqa: E402
import claude_phase_tool_policy as policy  # noqa: E402

EXPECTED = {"agents-md@builtin": False}


def test_single_owner_value_is_exactly_the_builtin_disable() -> None:
    assert pty_exec.CLAUDE_SETTINGS_ENABLED_PLUGINS == EXPECTED
    assert all(value is False for value in pty_exec.CLAUDE_SETTINGS_ENABLED_PLUGINS.values()), (
        "the plugin map may only DISABLE; a True value would grant a plugin"
    )


def test_isolation_payload_carries_the_same_value() -> None:
    payload = json.loads(pty_exec.SUBPROCESS_ISOLATION_PAYLOAD)
    assert payload["enabledPlugins"] == EXPECTED
    assert payload["hooks"] == {} and payload["mcpServers"] == {}
    assert payload["skipDangerousModePermissionPrompt"] is True


def _real_overlay(tmp_path: Path) -> dict:
    """A settings overlay produced by the product writer, not hand-built, so the
    validator's unrelated denominators (allow rules, hooks) are satisfied."""
    from test_claude_phase_tool_policy_p1_f import _fixture

    fx = _fixture(tmp_path)
    policy_path = fx["scratchpad"] / "policy.json"
    policy_path.write_bytes(policy.canonical_json_bytes(fx["policy"]))
    return policy.build_settings_overlay(
        policy=fx["policy"], policy_path=policy_path, hook_script=Path(policy.__file__),
    )


def test_grant_nothing_predicate_is_the_property() -> None:
    ok = pty_exec.settings_enabled_plugins_grant_nothing
    assert ok(dict(EXPECTED))
    assert ok({}), "an empty map grants nothing (governance-pinned fixtures still write it)"
    assert ok({"other@builtin": False, "agents-md@builtin": False})
    for granting in (
        {"agents-md@builtin": True},
        {"x": 1}, {"x": 0}, {"x": None}, {"x": "false"},
        {"": False},
        [], None, "{}",
    ):
        assert not ok(granting), granting


def test_writer_emits_the_disable_and_validator_gates_on_the_property(
    tmp_path: Path,
) -> None:
    overlay = _real_overlay(tmp_path)
    assert overlay["enabledPlugins"] == EXPECTED
    policy.validate_settings_overlay(overlay, restricted_analysis=True)
    for accepted in ({}, {"other@builtin": False}):
        policy.validate_settings_overlay(
            {**overlay, "enabledPlugins": accepted}, restricted_analysis=True,
        )
    for granting in ({"agents-md@builtin": True}, {"x": 1}, None, []):
        with pytest.raises(policy.ClaudePhaseToolPolicyError):
            policy.validate_settings_overlay(
                {**overlay, "enabledPlugins": granting}, restricted_analysis=True,
            )


def test_every_writer_imports_the_single_owner() -> None:
    """No module may spell the value itself; drift between a writer and the
    gate is exactly what halted run44.

    `claude_attempt_profile.py` keeps an empty map in the profile's BASE
    settings.json on purpose: its test file is hash-pinned by the fast-lane
    skip governance roster (`fast_lane_skip_governance_r10.json`), and the base
    file is shadowed by the per-worker `--settings` overlay -- measured: base
    `{}` + overlay disable -> init plugins `[]` even with setting sources on.
    """
    for name in (
        "claude_phase_tool_policy.py",
        "worker_execution_receipts.py",
        "plamen_driver.py",
    ):
        source = (_SCRIPTS / name).read_text("utf-8")
        assert (
            "CLAUDE_SETTINGS_ENABLED_PLUGINS" in source
            or "settings_enabled_plugins_grant_nothing" in source
        ), name
        assert '"enabledPlugins": {}' not in source, f"{name} still writes an empty plugin map"
        assert 'get("enabledPlugins") != {}' not in source, f"{name} still gates on one spelling"


def test_expected_init_contract_still_requires_no_loaded_plugins() -> None:
    """The control moved; the gate did not loosen."""
    source = (_SCRIPTS / "posix_v2_compat_claude.py").read_text("utf-8")
    assert '"plugins": [],' in source
