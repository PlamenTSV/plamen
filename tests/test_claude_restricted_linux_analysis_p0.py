from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import claude_phase_tool_policy as POLICY  # noqa: E402
import worker_execution_receipts as WER  # noqa: E402


PINNED_CLAUDE_VERSION = "2.1.252"
FILE_TOOLS = ["Edit", "Glob", "Grep", "Read", "Write"]
FORBIDDEN_TOOLS = sorted(WER._RESTRICTED_CLAUDE_FORBIDDEN_TOOLS)


def _linux_capability(**updates: object) -> dict[str, object]:
    capability: dict[str, object] = {
        "platform": "LINUX",
        "strategy": (
            "TRUSTED_PREEXEC_CGROUP_V2_ASSIGN_ACK_"
            "CGROUP_KILL_POPULATED_ZERO"
        ),
        "provider_owns_tree": True,
        "descendant_termination_required": True,
        "pre_execution_assignment": True,
        "termination_scope": "CGROUP_V2_SUBTREE",
        "population_zero_proof": "CGROUP_EVENTS_POPULATED_ZERO",
        "exhaustive_descendant_termination_authority": True,
        "exhaustive_write_confinement_authority": True,
        "write_confinement": "LANDLOCK_ABI_3_PATH_BENEATH",
        "delegated_root": "/sys/fs/cgroup/plamen-test",
        "helper_path": "/opt/plamen/linux_cgroup_exec.py",
        "helper_sha256": "a" * 64,
        "interpreter_path": "/usr/bin/python3",
        "interpreter_sha256": "b" * 64,
    }
    capability.update(updates)
    return capability


def _fixture(
    tmp_path: Path,
    *,
    tools: list[str],
    source_mode: str,
    output_count: int = 1,
) -> dict[str, object]:
    output_scope = (tmp_path / "attempt-output").resolve(strict=False)
    output_scope.mkdir(parents=True)
    output_contract = [
        {"relative_path": f"result-{index}.md"}
        for index in range(output_count)
    ]
    exact_rules = (
        sorted(
            {
                "Glob",
                "Grep",
                "Read",
                *POLICY.exact_edit_permission_rules(
                    output_scope / str(row["relative_path"])
                    for row in output_contract
                ),
            }
        )
        if source_mode == WER.WORKER_FILE_OUTPUTS
        else []
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
        "allowed_tools": tools,
        "forbidden_tools": FORBIDDEN_TOOLS,
        "allowed_mcp_servers": [],
        "required_mcp_servers": [],
        "allowed_tool_prefixes": [],
    }
    request = {
        "policy": {
            "headless_profile": {
                "claude_code_version": PINNED_CLAUDE_VERSION,
                "expected_init_contract": expected,
                "cli_flags": [
                    "--restricted",
                    "--permission-mode",
                    "default",
                    "--tools",
                    ",".join(tools),
                ],
            },
            "settings_authority": {
                "mode": "BOUND_SETTINGS",
                "settings_sha256": hashlib.sha256(raw).hexdigest(),
            },
        }
    }
    return {
        "output_scope": output_scope,
        "output_contract": output_contract,
        "source_mode": source_mode,
        "runtime": SimpleNamespace(
            replay_bound_settings_bytes=lambda: raw,
        ),
        "request": request,
    }


def _bind(fixture: dict[str, object]) -> dict[str, object] | None:
    return WER._restricted_claude_stage_binding(
        fixture["request"],
        fixture["runtime"],
        output_scope=fixture["output_scope"],
        output_contract=fixture["output_contract"],
        output_source_mode=fixture["source_mode"],
    )


@pytest.mark.parametrize(
    "tools,source_mode,expected_rules",
    (
        (FILE_TOOLS, WER.WORKER_FILE_OUTPUTS, "nonempty"),
        ([], WER.STDOUT_ASSIGNED_OUTPUT, "empty"),
    ),
)
def test_linux_restricted_profiles_bind_exhaustive_native_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tools: list[str],
    source_mode: str,
    expected_rules: str,
) -> None:
    capability = _linux_capability()
    monkeypatch.setattr(
        WER,
        "process_tree_termination_capability",
        lambda: copy.deepcopy(capability),
    )
    monkeypatch.setattr(
        WER,
        "_windows_job_only_capability",
        lambda: (_ for _ in ()).throw(
            AssertionError("Linux restricted lane must not select Job-only")
        ),
    )
    fixture = _fixture(
        tmp_path,
        tools=tools,
        source_mode=source_mode,
    )

    binding = _bind(fixture)

    assert binding is not None
    assert binding["process_tree"] == "LINUX_CGROUP_V2_SUBTREE"
    assert binding["os_write_confinement"] == "LANDLOCK_ABI_3_PATH_BENEATH"
    assert binding["native_capability_sha256"] == WER._digest_json(capability)
    assert bool(binding["permission_rules"]) is (expected_rules == "nonempty")
    if source_mode == WER.STDOUT_ASSIGNED_OUTPUT:
        assert binding["output_source_mode"] == WER.STDOUT_ASSIGNED_OUTPUT
    else:
        assert "output_source_mode" not in binding
    assert WER._restricted_claude_process_capability(binding) == capability
    assert WER._active_write_confinement_binding(
        WER._RESTRICTED_CLAUDE_STAGE_AUTHORITY,
        binding,
        capability=capability,
        process_scope_identity="scope-linux-test",
        require_current_process=False,
    ) == binding


@pytest.mark.parametrize(
    "updates",
    (
        {"provider_owns_tree": False},
        {"pre_execution_assignment": False},
        {"exhaustive_descendant_termination_authority": False},
        {"exhaustive_write_confinement_authority": False},
        {"termination_scope": "PROCESS_GROUP_ONLY"},
        {"population_zero_proof": "UNAVAILABLE"},
        {"write_confinement": "UNAVAILABLE"},
        {"platform": "MACOS"},
    ),
)
def test_linux_restricted_binding_rejects_missing_native_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    updates: dict[str, object],
) -> None:
    monkeypatch.setattr(
        WER,
        "process_tree_termination_capability",
        lambda: _linux_capability(**updates),
    )
    fixture = _fixture(
        tmp_path,
        tools=FILE_TOOLS,
        source_mode=WER.WORKER_FILE_OUTPUTS,
    )

    assert _bind(fixture) is None


def test_linux_restricted_replay_rejects_capability_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = _linux_capability()
    current = copy.deepcopy(capability)
    monkeypatch.setattr(
        WER,
        "process_tree_termination_capability",
        lambda: copy.deepcopy(current),
    )
    fixture = _fixture(
        tmp_path,
        tools=FILE_TOOLS,
        source_mode=WER.WORKER_FILE_OUTPUTS,
    )
    binding = _bind(fixture)
    assert binding is not None

    current["delegated_root"] = "/sys/fs/cgroup/substituted"

    with pytest.raises(
        WER.WorkerExecutionError,
        match="differs from the arm",
    ):
        WER._restricted_claude_process_capability(binding)


def test_linux_restricted_binding_fails_closed_when_capability_probe_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        WER,
        "process_tree_termination_capability",
        lambda: (_ for _ in ()).throw(OSError("cgroup probe failed")),
    )
    fixture = _fixture(
        tmp_path,
        tools=FILE_TOOLS,
        source_mode=WER.WORKER_FILE_OUTPUTS,
    )

    assert _bind(fixture) is None


@pytest.mark.parametrize(
    "tools,source_mode,output_count",
    (
        (FILE_TOOLS, WER.STDOUT_ASSIGNED_OUTPUT, 1),
        ([], WER.WORKER_FILE_OUTPUTS, 1),
        (FILE_TOOLS, WER.WORKER_FILE_OUTPUTS, 0),
        ([], WER.STDOUT_ASSIGNED_OUTPUT, 2),
    ),
)
def test_restricted_profile_output_source_hybrids_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tools: list[str],
    source_mode: str,
    output_count: int,
) -> None:
    monkeypatch.setattr(
        WER,
        "process_tree_termination_capability",
        lambda: _linux_capability(),
    )
    fixture = _fixture(
        tmp_path,
        tools=tools,
        source_mode=source_mode,
        output_count=output_count,
    )

    assert _bind(fixture) is None


def test_empty_tools_cli_value_is_admitted_only_by_explicit_caller() -> None:
    argv = ["claude", "--tools", ""]

    assert WER._single_cli_option_value(
        argv,
        "--tools",
        allow_empty=True,
    ) == ""
    with pytest.raises(WER.WorkerExecutionError, match="value is invalid"):
        WER._single_cli_option_value(argv, "--tools")
