from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import claude_headless_profile as HEADLESS  # noqa: E402
import claude_phase_tool_policy as POLICY  # noqa: E402
import plamen_driver as DRIVER  # noqa: E402
import test_wer_claude_runtime_lifecycle_p0_am as RUNTIME_FIXTURES  # noqa: E402
import windows_low_integrity_lease as LOW_INTEGRITY  # noqa: E402
import worker_execution_receipts as WER  # noqa: E402


PINNED_CLAUDE_VERSION = "2.1.252"
ANALYSIS_TOOLS = ("Edit", "Glob", "Grep", "Read", "Write")
FORBIDDEN_EXECUTION_TOOLS = (
    "Agent",
    "Bash",
    "PowerShell",
    "Task",
    "WebFetch",
    "WebSearch",
    "mcp__server__tool",
)


def _phase() -> DRIVER.Phase:
    return DRIVER.Phase(
        name="recon",
        section_markers=[],
        expected_artifacts=["recon.md"],
        base_timeout_s=60,
    )


def _launch(*, tool_policy: tuple[str, ...]) -> DRIVER.LaunchSpec:
    return DRIVER.LaunchSpec(
        work_unit_key="smart-contract/core/evm/claude/recon/recon",
        pipeline="smart-contract",
        mode="core",
        ecosystem="evm",
        backend="claude",
        model="claude-opus-5-20260801",
        timeout_s=60,
        exec_mode="headless",
        tool_policy=tool_policy,
    )


def _policy_fixture(tmp_path: Path) -> dict[str, object]:
    project = tmp_path / "project"
    source = project / "src"
    scratchpad = project / ".scratchpad"
    methodology = tmp_path / "methodology"
    receipts = scratchpad / "receipts"
    for directory in (source, scratchpad, methodology, receipts):
        directory.mkdir(parents=True, exist_ok=True)
    output = scratchpad / "attempt-1" / "recon.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    policy = POLICY.build_policy_manifest(
        run_id="restricted-analysis-p0",
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
    return {
        "project": project,
        "scratchpad": scratchpad,
        "output": output,
        "policy": policy,
        "policy_path": policy_path,
    }


class _BoundSettingsRuntime:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def replay_bound_settings_bytes(self) -> bytes:
        return self._raw


def _restricted_stage_fixture(tmp_path: Path) -> dict[str, object]:
    output_scope = (tmp_path / "attempt-output").resolve(strict=False)
    output_scope.mkdir(parents=True)
    output_contract = [{"relative_path": "recon.md"}]
    exact_rules = sorted(
        {
            "Glob",
            "Grep",
            "Read",
            *POLICY.exact_edit_permission_rules(
                (output_scope / "recon.md",)
            ),
        }
    )
    settings = {
        "enabledPlugins": {},
        "mcpServers": {},
        "permissions": {
            "allow": exact_rules,
            "deny": [],
            "defaultMode": "default",
        },
        "hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{}]}]},
    }
    raw = json.dumps(
        settings,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    expected = {
        "claude_code_version": PINNED_CLAUDE_VERSION,
        "permission_mode": "default",
        "required_capabilities": ["vendor-restricted-analysis"],
        "allowed_tools": list(ANALYSIS_TOOLS),
        "forbidden_tools": sorted(
            WER._RESTRICTED_CLAUDE_FORBIDDEN_TOOLS
        ),
        "allowed_mcp_servers": [],
        "required_mcp_servers": [],
        "allowed_tool_prefixes": [],
    }
    profile = {
        "claude_code_version": PINNED_CLAUDE_VERSION,
        "expected_init_contract": expected,
        "cli_flags": [
            "--restricted",
            "--permission-mode",
            "default",
            "--tools",
            ",".join(ANALYSIS_TOOLS),
        ],
    }
    request = {
        "policy": {
            "headless_profile": profile,
            "settings_authority": {
                "mode": "BOUND_SETTINGS",
                "settings_sha256": hashlib.sha256(raw).hexdigest(),
            },
        }
    }
    return {
        "output_scope": output_scope,
        "output_contract": output_contract,
        "raw": raw,
        "request": request,
    }


def _synthetic_restricted_binding(
    *,
    output_scope: Path,
    output_contract: list[dict[str, object]],
) -> dict[str, object]:
    core = {
        "protocol": "CLAUDE_CODE_RESTRICTED_ANALYSIS_STAGE_V1",
        "claude_code_version": PINNED_CLAUDE_VERSION,
        "settings_sha256": "a" * 64,
        "permission_rules": sorted(
            {
                "Glob",
                "Grep",
                "Read",
                *POLICY.exact_edit_permission_rules(
                    output_scope / str(row["relative_path"])
                    for row in output_contract
                ),
            }
        ),
        "output_scope": str(output_scope),
        "os_write_confinement": "NOT_PROVIDED",
        "process_tree": "WINDOWS_JOB_OBJECT",
        "limitation": "VENDOR_RESTRICTED_FILE_TOOLS_PLUS_EXACT_STAGE_RULES",
    }
    return {**core, "binding_sha256": WER._digest_json(core)}


def _install_runtime_fixture_authorities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        RUNTIME_FIXTURES.A,
        "_default_runtime_namespace",
        lambda: RUNTIME_FIXTURES._fixture_runtime_namespace(tmp_path),
    )
    RUNTIME_FIXTURES.provider_fixtures._install_observers(
        monkeypatch,
        Path(sys.executable).resolve(strict=True),
    )
    # This test exercises WER's process-scope dispatch, not the independently
    # covered executable-alias guard.  The Windows Store/Python installer may
    # expose python.exe through a hardlink, which is intentionally rejected by
    # the production Claude executable replay.
    monkeypatch.setattr(
        WER,
        "_recheck_claude_executable_before_launch",
        lambda *_args, **_kwargs: None,
    )


def test_pinned_default_profile_is_restricted_without_bypass() -> None:
    flags = HEADLESS._profile_cli_flags(
        customization_mode="BOUND_SETTINGS",
        claude_code_version=PINNED_CLAUDE_VERSION,
        permission_mode="default",
        builtin_tools=ANALYSIS_TOOLS,
        restricted_analysis=True,
    )

    assert flags.count("--restricted") == 1
    assert flags.count("--permission-mode") == 1
    assert flags[flags.index("--permission-mode") + 1] == "default"
    assert "--dangerously-skip-permissions" not in flags
    assert flags[flags.index("--tools") + 1] == ",".join(ANALYSIS_TOOLS)


def test_only_filesystem_analysis_workload_selects_restricted_lane() -> None:
    assert DRIVER._claude_restricted_analysis_launch(
        _phase(), _launch(tool_policy=("filesystem",))
    )


@pytest.mark.parametrize(
    "tool_policy",
    (
        ("filesystem", "command"),
        ("filesystem", "mcp"),
        ("filesystem", "network"),
        ("command",),
    ),
)
def test_command_or_external_capability_workload_cannot_select_restricted_lane(
    tool_policy: tuple[str, ...],
) -> None:
    assert not DRIVER._claude_restricted_analysis_launch(
        _phase(), _launch(tool_policy=tool_policy)
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job-only authority")
def test_restricted_stage_binding_authenticates_exact_vendor_and_write_contract(
    tmp_path: Path,
) -> None:
    fixture = _restricted_stage_fixture(tmp_path)
    binding = WER._restricted_claude_stage_binding(
        fixture["request"],
        _BoundSettingsRuntime(fixture["raw"]),
        output_scope=fixture["output_scope"],
        output_contract=fixture["output_contract"],
    )

    assert binding is not None
    assert binding["claude_code_version"] == PINNED_CLAUDE_VERSION
    assert binding["process_tree"] == "WINDOWS_JOB_OBJECT"
    assert binding["os_write_confinement"] == "NOT_PROVIDED"
    assert binding["permission_rules"] == sorted(
        {
            "Glob",
            "Grep",
            "Read",
            *POLICY.exact_edit_permission_rules(
                (fixture["output_scope"] / "recon.md",)
            ),
        }
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job-only authority")
@pytest.mark.parametrize(
    "mutation",
    (
        "unpinned_version",
        "missing_restricted",
        "bypass",
        "wrong_permission_mode",
        "bash_allowed",
        "mcp_prefix",
        "extra_edit_scope",
        "settings_substitution",
    ),
)
def test_restricted_stage_binding_fails_closed_on_authority_drift(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _restricted_stage_fixture(tmp_path)
    request = copy.deepcopy(fixture["request"])
    runtime_raw = fixture["raw"]
    profile = request["policy"]["headless_profile"]
    expected = profile["expected_init_contract"]
    if mutation == "unpinned_version":
        profile["claude_code_version"] = "2.1.253"
    elif mutation == "missing_restricted":
        profile["cli_flags"].remove("--restricted")
    elif mutation == "bypass":
        profile["cli_flags"].append("--dangerously-skip-permissions")
    elif mutation == "wrong_permission_mode":
        expected["permission_mode"] = "dontAsk"
    elif mutation == "bash_allowed":
        expected["allowed_tools"] = [*ANALYSIS_TOOLS, "Bash"]
    elif mutation == "mcp_prefix":
        expected["allowed_tool_prefixes"] = ["mcp__"]
    elif mutation == "extra_edit_scope":
        settings = json.loads(runtime_raw)
        settings["permissions"]["allow"].append(
            POLICY._claude_absolute_edit_rule(
                (fixture["output_scope"].parent / "sibling.md").as_posix()
            )
        )
        runtime_raw = json.dumps(
            settings,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        request["policy"]["settings_authority"]["settings_sha256"] = (
            hashlib.sha256(runtime_raw).hexdigest()
        )
    elif mutation == "settings_substitution":
        runtime_raw = runtime_raw + b" "

    assert WER._restricted_claude_stage_binding(
        request,
        _BoundSettingsRuntime(runtime_raw),
        output_scope=fixture["output_scope"],
        output_contract=fixture["output_contract"],
    ) is None


@pytest.mark.skipif(os.name != "nt", reason="Windows Job-only authority")
def test_authenticated_restricted_worker_uses_job_only_and_reaches_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_runtime_fixture_authorities(tmp_path, monkeypatch)
    case = RUNTIME_FIXTURES._case(tmp_path, label="restricted-job-only")
    provider_calls = RUNTIME_FIXTURES._install_fake_cli(
        monkeypatch,
        (case,),
    )
    real_scope = WER._OwnedProcessTree
    scope_calls: list[dict[str, object]] = []

    class RefusingLowIntegrityLease:
        def __init__(self, **_kwargs: object) -> None:
            raise PermissionError(5, "WRITE_OWNER denied on inherited Modify ACL")

    monkeypatch.setitem(
        sys.modules,
        "windows_low_integrity_lease",
        types.SimpleNamespace(
            WindowsLowIntegrityExecutionLease=RefusingLowIntegrityLease,
            _set_windows_integrity_label=(
                LOW_INTEGRITY._set_windows_integrity_label
            ),
        ),
    )

    def authenticate(
        _request: object,
        _runtime: object,
        *,
        output_scope: Path,
        output_contract: list[dict[str, object]],
    ) -> dict[str, object]:
        return _synthetic_restricted_binding(
            output_scope=output_scope,
            output_contract=output_contract,
        )

    def scope_factory(**kwargs: object) -> object:
        scope_calls.append(dict(kwargs))
        return real_scope(**kwargs)

    monkeypatch.setattr(WER, "_restricted_claude_stage_binding", authenticate)
    monkeypatch.setattr(WER, "_OwnedProcessTree", scope_factory)
    completed = WER.run_observed_worker(**case.wer_kwargs())

    assert completed.receipt_path.is_file()
    assert len(provider_calls) == 1
    assert scope_calls == [
        {
            "persistent_identity": f"scope-{case.label}",
            "windows_job_only": True,
        }
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job-only authority")
def test_windows_job_creation_failure_blocks_before_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_runtime_fixture_authorities(tmp_path, monkeypatch)
    case = RUNTIME_FIXTURES._case(tmp_path, label="restricted-job-failure")
    provider_calls = RUNTIME_FIXTURES._install_fake_cli(
        monkeypatch,
        (case,),
    )

    def authenticate(
        _request: object,
        _runtime: object,
        *,
        output_scope: Path,
        output_contract: list[dict[str, object]],
    ) -> dict[str, object]:
        return _synthetic_restricted_binding(
            output_scope=output_scope,
            output_contract=output_contract,
        )

    def refuse_job(**kwargs: object) -> object:
        assert kwargs["windows_job_only"] is True
        raise RuntimeError("synthetic Windows Job creation failure")

    monkeypatch.setattr(WER, "_restricted_claude_stage_binding", authenticate)
    monkeypatch.setattr(WER, "_OwnedProcessTree", refuse_job)
    with pytest.raises(
        WER.WorkerExecutionIncomplete,
        match="process-scope construction failed",
    ):
        WER.run_observed_worker(**case.wer_kwargs())

    assert provider_calls == []


def test_exact_edit_permission_and_hook_deny_sibling_and_project_write(
    tmp_path: Path,
) -> None:
    fixture = _policy_fixture(tmp_path)
    policy = fixture["policy"]
    output = fixture["output"]
    project = fixture["project"]
    settings = POLICY.build_settings_overlay(
        policy=policy,
        policy_path=fixture["policy_path"],
        hook_script=Path(POLICY.__file__),
    )

    assert settings["permissions"]["defaultMode"] == "default"
    assert settings["permissions"]["allow"] == sorted(
        {
            "Glob",
            "Grep",
            "Read",
            POLICY._claude_absolute_edit_rule(
                output.resolve(strict=False).as_posix()
            ),
        }
    )
    for denied in (
        output.with_name("sibling.md"),
        project / "src" / "Contract.sol",
    ):
        for tool in ("Edit", "Write"):
            decision = POLICY.evaluate_tool_call(
                tool_name=tool,
                tool_input={"file_path": str(denied)},
                cwd=project,
                policy=policy,
            )
            assert decision["decision"] == "DENY"
            assert decision["reason_code"] == "UNREGISTERED_WRITE"


@pytest.mark.parametrize("tool", FORBIDDEN_EXECUTION_TOOLS)
def test_analysis_policy_denies_command_network_mcp_and_subagent_tools(
    tmp_path: Path,
    tool: str,
) -> None:
    fixture = _policy_fixture(tmp_path)
    decision = POLICY.evaluate_tool_call(
        tool_name=tool,
        tool_input={},
        cwd=fixture["project"],
        policy=fixture["policy"],
    )

    assert decision["decision"] == "DENY"
    assert decision["reason_code"] in {"TOOL_DENIED", "UNKNOWN_TOOL"}
