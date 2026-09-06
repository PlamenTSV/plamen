from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import shutil
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import claude_phase_tool_policy as POLICY  # noqa: E402
import claude_headless_profile as PROFILE  # noqa: E402
import claude_runtime_materialization as RUNTIME  # noqa: E402
import worker_execution_receipts as WER  # noqa: E402


def _restricted_overlay(tmp_path: Path) -> tuple[dict[str, object], Path]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    methodology = tmp_path / "methodology"
    receipts = scratchpad / "receipts"
    output = scratchpad / "attempt-1" / "recon.md"
    for directory in (
        project / "src",
        scratchpad,
        methodology,
        receipts,
        output.parent,
    ):
        directory.mkdir(parents=True, exist_ok=True)
    policy = POLICY.build_policy_manifest(
        run_id="restricted-settings-schema-p0",
        phase="recon",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(methodology,),
        exact_read_files=(),
        exact_write_files=(output,),
        forbidden_read_files=(),
        receipt_directory=receipts,
    )
    policy_path = scratchpad / "policy.json"
    policy_path.write_bytes(POLICY.canonical_json_bytes(policy))
    settings = POLICY.build_settings_overlay(
        policy=policy,
        policy_path=policy_path,
        hook_script=Path(POLICY.__file__),
    )
    return settings, policy_path


def _runtime_policy(
    settings_raw: bytes,
    mcp_raw: bytes,
    *,
    restricted_analysis: bool,
    restricted_web_analysis: bool = False,
) -> dict[str, object]:
    return {
        "settings_authority": {
            "mode": "BOUND_SETTINGS",
            "settings_sha256": hashlib.sha256(settings_raw).hexdigest(),
        },
        "mcp_authority": {
            "selected_config_sha256": hashlib.sha256(mcp_raw).hexdigest(),
            "server_names": [],
            "runtime_selection": None,
        },
        "headless_profile": {
            "expected_init_contract": {
                "required_capabilities": (
                    [
                        capability
                        for capability, required in (
                            (
                                "vendor-restricted-analysis",
                                restricted_analysis,
                            ),
                            (
                                "vendor-restricted-web-analysis",
                                restricted_web_analysis,
                            ),
                        )
                        if required
                    ]
                ),
            },
        },
    }


def _runtime_validate(
    settings: dict[str, object],
    *,
    restricted_analysis: bool,
    restricted_web_analysis: bool = False,
) -> tuple[bytes | None, bytes | None, tuple[str, ...]]:
    settings_raw = POLICY.canonical_json_bytes(settings)
    mcp_raw = POLICY.canonical_json_bytes({"mcpServers": {}})
    return RUNTIME._validated_bound_runtime_sources(
        policy=_runtime_policy(
            settings_raw,
            mcp_raw,
            restricted_analysis=restricted_analysis,
            restricted_web_analysis=restricted_web_analysis,
        ),
        bound_settings_bytes=settings_raw,
        selected_mcp_config_bytes=mcp_raw,
    )


def test_runtime_accepts_exact_bounded_web_schema_and_rejects_lane_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_python = tmp_path / "python.exe"
    shutil.copy2(sys.executable, private_python)
    monkeypatch.setattr(POLICY.sys, "executable", str(private_python))
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    receipts = scratchpad / "receipts"
    output = scratchpad / "attempt-1" / "recon_external_dependency_research.md"
    exact_input = scratchpad / "external_dependency_obligations.json"
    for directory in (project / "src", receipts, output.parent):
        directory.mkdir(parents=True, exist_ok=True)
    exact_input.write_text("{}\n", encoding="utf-8")
    network_authority = POLICY.build_dependency_research_network_authority([{
        "obligation_id": "DEP-98C0701965F5",
        "dependency": "@openzeppelin/contracts",
        "kind": "source-import",
        "source_location": "src/Vault.sol:L7",
        "declaration_evidence": (
            'import "@openzeppelin/contracts/token/ERC20.sol";'
        ),
        "research_question": (
            "Determine the externally defined semantics, temporal guarantees, "
            "failure behavior, and integration assumptions relied on at this locus."
        ),
    }])
    policy = POLICY.build_policy_manifest(
        run_id="restricted-web-settings-schema-p0",
        phase="recon_external_dependency_research",
        attempt=1,
        expected_cwd=project,
        project_root=project,
        scratchpad_root=scratchpad,
        methodology_read_roots=(),
        exact_read_files=(exact_input,),
        exact_write_files=(output,),
        forbidden_read_files=(),
        receipt_directory=receipts,
        network_authority=network_authority,
    )
    policy_path = scratchpad / "policy.json"
    policy_path.write_bytes(POLICY.canonical_json_bytes(policy))
    settings = POLICY.build_settings_overlay(
        policy=policy,
        policy_path=policy_path,
        hook_script=Path(POLICY.__file__),
    )
    settings_path = scratchpad / "settings.json"
    settings_path.write_bytes(POLICY.canonical_json_bytes(settings))
    mcp_path = scratchpad / "mcp.json"
    mcp_path.write_bytes(POLICY.canonical_json_bytes({"mcpServers": {}}))

    settings_raw = POLICY.canonical_json_bytes(settings)
    exact_settings, exact_mcp, servers = _runtime_validate(
        settings,
        restricted_analysis=False,
        restricted_web_analysis=True,
    )
    assert exact_settings == settings_raw
    assert exact_mcp == POLICY.canonical_json_bytes({"mcpServers": {}})
    assert servers == ()
    assert set(settings["hooks"]) == {
        "PreToolUse", "PostToolUse", "PostToolUseFailure",
    }

    profile = PROFILE.compile_claude_headless_profile(
        claude_code_version="2.1.252",
        cwd=str(project.resolve()),
        accepted_models=("claude-sonnet-5",),
        permission_mode="default",
        builtin_tools=tuple(WER._RESTRICTED_CLAUDE_WEB_TOOLS),
        required_tools=("Read", "Write"),
        forbidden_tools=tuple(sorted(WER._RESTRICTED_CLAUDE_WEB_FORBIDDEN_TOOLS)),
        mcp_server_names=(),
        customization_mode="BOUND_SETTINGS",
        accepted_api_key_sources=("none",),
        required_capabilities=("vendor-restricted-web-analysis",),
    )
    script = tmp_path / "provider.py"
    script.write_text("pass\n", encoding="utf-8")
    session_id = "11111111-2222-4333-8444-555555555555"
    argv = [
        sys.executable,
        str(script),
        "-p",
        "--model",
        "claude-sonnet-5",
        "--output-format",
        "stream-json",
        "--verbose",
        "--session-id",
        session_id,
        "--no-session-persistence",
        *profile["cli_flags"],
        "--settings",
        str(settings_path),
        "--strict-mcp-config",
        "--mcp-config",
        str(mcp_path),
    ]
    stream_binding = WER._claude_stream_stdout_binding(
        {
            "schema": WER.CLAUDE_STREAM_STDOUT_CONFIGURATION_SCHEMA,
            "expected_session_id": session_id,
            "expected_init_contract": profile["expected_init_contract"],
            "max_line_bytes": 2 * 1024 * 1024,
            "max_stream_bytes": WER.DEFAULT_STDOUT_LIMIT_BYTES,
        },
        argv=argv,
        stdout_limit_bytes=WER.DEFAULT_STDOUT_LIMIT_BYTES,
        cwd=project.resolve(),
        effective_model="claude-sonnet-5",
    )
    assert stream_binding["command_contract"]["headless_profile"][
        "permission_mode"
    ] == "default"
    assert profile["cli_flags"].count("--allowedTools") == 1
    allowed_index = profile["cli_flags"].index("--allowedTools")
    assert profile["cli_flags"][allowed_index + 1].split(",") == list(
        WER._RESTRICTED_CLAUDE_WEB_ALLOWED_TOOLS
    )
    for replacement in (
        None,
        "Grep,Glob,Read",
        "Glob,Grep,Read,Read",
        "Edit,Glob,Grep,Read,WebFetch,WebSearch,Write",
        "WebFetch,WebSearch",
        "Edit,Glob,Grep,Read",
        "Glob,Grep,Read,Write",
    ):
        broken_profile = copy.deepcopy(profile)
        broken_flags = broken_profile["cli_flags"]
        broken_index = broken_flags.index("--allowedTools")
        if replacement is None:
            del broken_flags[broken_index:broken_index + 2]
        else:
            broken_flags[broken_index + 1] = replacement
        unsigned = dict(broken_profile)
        unsigned.pop("profile_sha256")
        broken_profile["profile_sha256"] = PROFILE._digest(unsigned)
        with pytest.raises(
            PROFILE.ClaudeHeadlessProfileError,
            match="CLI flags disagree",
        ):
            PROFILE.replay_claude_headless_profile(broken_profile)

    class BoundRuntime:
        def replay_bound_settings_bytes(self) -> bytes:
            return settings_raw

    process_capability = {"platform": "WINDOWS", "fixture": "job-only"}
    monkeypatch.setattr(
        WER, "process_tree_termination_capability", lambda: process_capability,
    )
    monkeypatch.setattr(
        WER, "_windows_job_only_capability", lambda: process_capability,
    )
    stage = WER._restricted_claude_stage_binding(
        {
            "policy": {
                "headless_profile": profile,
                "settings_authority": {
                    "mode": "BOUND_SETTINGS",
                    "settings_sha256": hashlib.sha256(settings_raw).hexdigest(),
                },
            },
        },
        BoundRuntime(),  # type: ignore[arg-type]
        output_scope=output.parent,
        output_contract=({"relative_path": output.name},),
    )
    assert stage is not None
    assert stage["permission_rules"] == sorted({
        "Glob",
        "Grep",
        "Read",
        *POLICY.exact_edit_permission_rules((output,)),
    })
    assert "WebFetch" not in stage["permission_rules"]
    assert "WebSearch" not in stage["permission_rules"]

    with pytest.raises(
        RUNTIME.ClaudeRuntimeMaterializationError,
        match="bound settings capability denominator is malformed",
    ):
        _runtime_validate(settings, restricted_analysis=False)

    broken = copy.deepcopy(settings)
    broken["hooks"].pop("PostToolUseFailure")  # type: ignore[union-attr]
    with pytest.raises(
        RUNTIME.ClaudeRuntimeMaterializationError,
        match="bound settings capability denominator is malformed",
    ):
        _runtime_validate(
            broken,
            restricted_analysis=False,
            restricted_web_analysis=True,
        )

    for capabilities in (
        ["vendor-restricted-analysis", "vendor-restricted-web-analysis"],
        ["vendor-restricted-unknown", "vendor-restricted-web-analysis"],
    ):
        with pytest.raises(
            WER.WorkerExecutionError,
            match="restricted Claude capability denominator is unsupported",
        ):
            WER._restricted_claude_capability_lane({
                "required_capabilities": sorted(capabilities),
            })


def test_producer_materializer_and_worker_accept_exact_restricted_schema(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_python = tmp_path / "python.exe"
    shutil.copy2(sys.executable, private_python)
    monkeypatch.setattr(POLICY.sys, "executable", str(private_python))
    settings, _ = _restricted_overlay(tmp_path)
    settings_raw = POLICY.canonical_json_bytes(settings)
    settings_path = tmp_path / "settings.json"
    settings_path.write_bytes(settings_raw)

    exact_settings, exact_mcp, servers = _runtime_validate(
        settings,
        restricted_analysis=True,
    )
    binding = WER._claude_bound_settings_binding(
        settings_path,
        restricted_analysis=True,
    )

    assert exact_settings == settings_raw
    assert exact_mcp == POLICY.canonical_json_bytes({"mcpServers": {}})
    assert servers == ()
    assert binding["sha256"] == hashlib.sha256(settings_raw).hexdigest()
    assert set(binding["hook_authority"]) == {
        "hook_executable", "hook_script", "hook_policy",
    }


def _extra_key(settings: dict[str, object]) -> None:
    settings["unexpected"] = True


def _missing_key(settings: dict[str, object]) -> None:
    settings.pop("enabledPlugins")


def _bad_default(settings: dict[str, object]) -> None:
    settings["permissions"]["defaultMode"] = "acceptEdits"  # type: ignore[index]


def _noncanonical_allow(settings: dict[str, object]) -> None:
    permissions = settings["permissions"]  # type: ignore[assignment]
    permissions["allow"] = ["Edit(/z)", "Edit(/a)", "Edit(/a)"]


def _missing_hook(settings: dict[str, object]) -> None:
    settings["hooks"] = {}


def _malformed_hook(settings: dict[str, object]) -> None:
    settings["hooks"] = {"PreToolUse": []}


@pytest.mark.parametrize(
    "mutate",
    (
        _extra_key,
        _missing_key,
        _bad_default,
        _noncanonical_allow,
        _missing_hook,
        _malformed_hook,
    ),
)
def test_restricted_schema_negatives_fail_before_provider_materialization(
    tmp_path: Path,
    mutate: object,
) -> None:
    settings, _ = _restricted_overlay(tmp_path)
    broken = copy.deepcopy(settings)
    mutate(broken)  # type: ignore[operator]
    settings_path = tmp_path / f"broken-{mutate.__name__}.json"  # type: ignore[attr-defined]
    settings_path.write_bytes(POLICY.canonical_json_bytes(broken))

    with pytest.raises(POLICY.ClaudePhaseToolPolicyError):
        POLICY.validate_settings_overlay(broken, restricted_analysis=True)
    with pytest.raises(
        RUNTIME.ClaudeRuntimeMaterializationError,
        match="bound settings capability denominator is malformed",
    ):
        _runtime_validate(broken, restricted_analysis=True)
    with pytest.raises(
        WER.WorkerExecutionError,
        match="settings capability denominator is malformed",
    ):
        WER._claude_bound_settings_binding(
            settings_path,
            restricted_analysis=True,
        )


def test_legacy_and_restricted_bound_settings_are_lane_discriminated(
    tmp_path: Path,
) -> None:
    restricted, _ = _restricted_overlay(tmp_path)
    legacy = {
        "enabledPlugins": {},
        "hooks": {},
        "mcpServers": {},
        "permissions": {"deny": ["WebFetch", "WebSearch"]},
    }
    legacy_path = tmp_path / "legacy-settings.json"
    legacy_path.write_bytes(POLICY.canonical_json_bytes(legacy))

    assert _runtime_validate(legacy, restricted_analysis=False)[2] == ()
    assert WER._claude_bound_settings_binding(
        legacy_path,
        restricted_analysis=False,
    )["hook_authority"] is None

    legacy_raw = POLICY.canonical_json_bytes(legacy)
    mcp_raw = POLICY.canonical_json_bytes({"mcpServers": {}})
    minimal_legacy_policy = _runtime_policy(
        legacy_raw,
        mcp_raw,
        restricted_analysis=False,
    )
    minimal_legacy_policy.pop("headless_profile")
    assert RUNTIME._validated_bound_runtime_sources(
        policy=minimal_legacy_policy,
        bound_settings_bytes=legacy_raw,
        selected_mcp_config_bytes=mcp_raw,
    ) == (legacy_raw, mcp_raw, ())

    with pytest.raises(POLICY.ClaudePhaseToolPolicyError):
        POLICY.validate_settings_overlay(legacy, restricted_analysis=True)
    with pytest.raises(POLICY.ClaudePhaseToolPolicyError):
        POLICY.validate_settings_overlay(restricted, restricted_analysis=False)
    with pytest.raises(RUNTIME.ClaudeRuntimeMaterializationError):
        _runtime_validate(restricted, restricted_analysis=False)


def test_present_malformed_headless_authority_cannot_downgrade_to_legacy(
    tmp_path: Path,
) -> None:
    legacy = {
        "enabledPlugins": {},
        "hooks": {},
        "mcpServers": {},
        "permissions": {"deny": []},
    }
    legacy_raw = POLICY.canonical_json_bytes(legacy)
    mcp_raw = POLICY.canonical_json_bytes({"mcpServers": {}})
    policy = _runtime_policy(
        legacy_raw,
        mcp_raw,
        restricted_analysis=False,
    )
    policy["headless_profile"] = {"expected_init_contract": {}}

    with pytest.raises(
        RUNTIME.ClaudeRuntimeMaterializationError,
        match="launch capability authority is malformed",
    ):
        RUNTIME._validated_bound_runtime_sources(
            policy=policy,
            bound_settings_bytes=legacy_raw,
            selected_mcp_config_bytes=mcp_raw,
        )
