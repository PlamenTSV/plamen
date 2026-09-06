"""Reviewed compatibility contract for the locked Claude Code 2.1.252 CLI."""

from __future__ import annotations

import pytest

import claude_attempt_profile as A
import claude_auth_route as R
import claude_child_environment as C
import claude_executable_observation as E
import claude_headless_profile as H


VERSION = "2.1.252"


def test_locked_cli_capability_row_matches_probed_2_1_252_surface() -> None:
    row = E._REVIEWED_COMPATIBILITY_ROWS[VERSION]
    assert row["compatibility_id"] == "claude-code-2.1.252"
    assert set(row["supported_capabilities"]) >= {
        "-p",
        "--dangerously-skip-permissions",
        "--disable-slash-commands",
        "--mcp-config",
        "--no-chrome",
        "--no-session-persistence",
        "--output-format=stream-json",
        "--permission-mode=dontAsk",
        "--prompt-suggestions=false",
        "--safe-mode",
        "--session-id",
        "--setting-sources=",
        "--strict-mcp-config",
        "--tools",
        "--verbose",
        "init-security-v2",
    }
    assert E._REVIEWED_TYPED_PROFILE_CAPABILITIES_BY_VERSION[VERSION] == {
        "--restricted",
        "--settings",
    }
    assert H.parse_claude_code_version(
        "2.1.252 (Claude Code)\n"
    ) == VERSION
    assert H._runtime_authority_flags(
        customization_mode="BOUND_SETTINGS",
        claude_code_version=VERSION,
    ) == ["--mcp-config", "--settings", "--strict-mcp-config"]


def test_2_1_252_functional_controls_and_oauth_init_are_exact() -> None:
    controls = {
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "CLAUDE_CODE_SKIP_PROMPT_HISTORY": "1",
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    }
    assert C.normalize_claude_functional_controls(
        controls, claude_code_version=VERSION
    ) == dict(sorted(controls.items()))
    assert R.expected_init_api_key_sources(
        claude_code_version=VERSION,
        desired_route="OAUTH_TOKEN",
    ) == ("none",)
    assert R.expected_init_api_key_sources(
        claude_code_version=VERSION,
        desired_route="STORED_SUBSCRIPTION_OAUTH",
    ) == ("none",)
    with pytest.raises(R.ClaudeAuthRouteError):
        R.expected_init_api_key_sources(
            claude_code_version="2.1.253",
            desired_route="OAUTH_TOKEN",
        )


def test_2_1_252_state_projection_tracks_observed_migration_delta() -> None:
    assert A._CLAUDE_STATE_VERSION == VERSION
    assert A._CLAUDE_STATE_MIGRATION_VERSION == 13
    assert {
        "hasResetAutoModeOptInForDefaultOffer",
        "opusProMigrationComplete",
        "sonnet1m45MigrationComplete",
    }.issubset(A._STATE_BOOLEAN_FIELDS)
