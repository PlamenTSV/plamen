from __future__ import annotations

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import shutil
from types import SimpleNamespace

import pytest

import claude_executable_observation as O


VERSION = "2.1.220"
CANONICAL_VERSION_OUTPUT = f"{VERSION} (Claude Code)\n"


@pytest.fixture(autouse=True)
def _reviewed_windows_native_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep legacy native fixtures focused on observation mechanics.

    The dedicated magic-prefix fixture remains unsigned because its tiny
    payload cannot satisfy this test-only neutral metadata observer.
    """

    def query(path: Path, *, environment):
        del environment
        if path.stat().st_size < 1024:
            return None
        return {
            "signature_status": "Valid",
            "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
            "publisher_name": "Anthropic PBC",
            "product_name": "Claude Code",
            "file_version": f"{VERSION}.0",
        }

    monkeypatch.setattr(O, "_query_windows_native_metadata", query)


def _copy_native(path: Path) -> Path:
    shutil.copyfile(O.sys.executable, path)
    path.chmod(0o700)
    return path.resolve(strict=True)


def _successful_runner(
    calls: list[dict[str, object]],
    *,
    stdout: str = CANONICAL_VERSION_OUTPUT,
    stderr: str = "",
    returncode: int = 0,
    after_call=None,
):
    def run(command, **kwargs):
        calls.append({"command": tuple(command), **kwargs})
        if after_call is not None:
            after_call()
        return SimpleNamespace(
            args=tuple(command),
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            duration_s=0.01,
            process_tree_terminated=True,
            containment_capability={
                "pre_execution_assignment": True,
                "exhaustive_descendant_termination_authority": True,
            },
        )

    return run


def _observe_native(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    stdout: str = CANONICAL_VERSION_OUTPUT,
) -> tuple[Path, dict[str, object], list[dict[str, object]]]:
    executable = _copy_native(tmp_path / ("claude.exe" if os.name == "nt" else "claude"))
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        O,
        "run_owned_process",
        _successful_runner(calls, stdout=stdout),
    )
    observation = O.observe_claude_executable(
        configured_claude_bin=str(executable),
        environment={"PATH": str(tmp_path)},
    )
    return executable, observation, calls


def test_configured_exact_binary_not_path_claude_is_observed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_candidate = _copy_native(
        tmp_path / ("claude-path.exe" if os.name == "nt" else "claude-path")
    )
    configured = _copy_native(
        tmp_path / ("claude-configured.exe" if os.name == "nt" else "claude-configured")
    )
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(O, "run_owned_process", _successful_runner(calls))

    observed = O.observe_claude_executable(
        configured_claude_bin=str(configured),
        environment={"PATH": str(path_candidate.parent)},
    )

    assert calls[0]["command"] == (str(configured), "--version")
    assert observed["configured_claude_bin"] == str(configured)
    assert observed["resolved_executable"] == str(configured)
    assert observed["claude_code_version"] == VERSION
    assert observed["implementation_status"] == O.DIRECT_IMPLEMENTATION_BOUND
    assert observed["implementation_kind"] == "NATIVE_EXECUTABLE_IMAGE"
    assert observed["launch_authority"] == O.PROOF_GRADE
    assert observed["compatibility"]["compatibility_id"] == "claude-code-2.1.220"
    assert calls[0]["timeout"] == O.DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS
    assert O.DEFAULT_VERSION_PROBE_TIMEOUT_SECONDS == 3.0
    assert O.GENERATION_VERSION_PROBE_TIMEOUT_SECONDS == 120.0
    assert calls[0]["output_limit_bytes"] == O.VERSION_PROBE_OUTPUT_LIMIT_BYTES


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -float("inf")])
def test_direct_probe_rejects_nonfinite_timeout_before_spawn(
    timeout: float, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        O,
        "run_owned_process",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    with pytest.raises(O.ClaudeExecutableObservationError):
        O.observe_claude_executable(
            configured_claude_bin="must-not-be-resolved",
            timeout_seconds=timeout,
        )
    assert calls == []


def test_reviewed_2_1_250_native_binary_is_proof_grade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    version = "2.1.250"

    def metadata(path: Path, *, environment):
        del path, environment
        return {
            "signature_status": "Valid",
            "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
            "publisher_name": "Anthropic PBC",
            "product_name": "Claude Code",
            "file_version": f"{version}.0",
        }

    monkeypatch.setattr(O, "_query_windows_native_metadata", metadata)
    _, observed, _ = _observe_native(
        monkeypatch,
        tmp_path,
        stdout=f"{version} (Claude Code)\n",
    )

    assert observed["claude_code_version"] == version
    assert observed["launch_authority"] == O.PROOF_GRADE
    assert (
        observed["compatibility"]["compatibility_id"]
        == "claude-code-2.1.250"
    )
    assert "--settings" in O._REVIEWED_TYPED_PROFILE_CAPABILITIES_BY_VERSION[
        version
    ]


@pytest.mark.parametrize(
    "stdout",
    (
        "2.1.220",
        "2.1.220 (Claude Code)\nextra\n",
        "02.1.220 (Claude Code)\n",
        " 2.1.220 (Claude Code)\n",
        "2.1.220 (Claude Code) \n",
        "garbage\n",
    ),
)
def test_malformed_or_noncanonical_version_output_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    with pytest.raises(O.ClaudeExecutableObservationError, match="version|canonical"):
        _observe_native(monkeypatch, tmp_path, stdout=stdout)


@pytest.mark.parametrize(
    "stdout",
    (
        "2.1.219 (Claude Code)\n",
        "2.1.221 (Claude Code)\n",
        "2.1.251 (Claude Code)\n",
        "2.2.0 (Claude Code)\n",
        "3.0.0 (Claude Code)\n",
    ),
)
def test_old_and_unknown_future_versions_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stdout: str,
) -> None:
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="reviewed compatibility|unsupported",
    ):
        _observe_native(monkeypatch, tmp_path, stdout=stdout)


def test_nonzero_stderr_or_unclosed_owned_probe_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _copy_native(tmp_path / ("claude.exe" if os.name == "nt" else "claude"))
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        O,
        "run_owned_process",
        _successful_runner(calls, stderr="warning\n"),
    )
    with pytest.raises(O.ClaudeExecutableObservationError, match="stderr"):
        O.observe_claude_executable(
            configured_claude_bin=str(executable),
            environment={"PATH": str(tmp_path)},
        )

    def unclosed(command, **kwargs):
        return SimpleNamespace(
            args=tuple(command),
            returncode=0,
            stdout=CANONICAL_VERSION_OUTPUT,
            stderr="",
            process_tree_terminated=False,
            containment_capability={},
        )

    monkeypatch.setattr(O, "run_owned_process", unclosed)
    with pytest.raises(O.ClaudeExecutableObservationError, match="owned|terminated"):
        O.observe_claude_executable(
            configured_claude_bin=str(executable),
            environment={"PATH": str(tmp_path)},
        )


def test_executable_change_during_probe_and_before_launch_rejects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _copy_native(tmp_path / ("claude.exe" if os.name == "nt" else "claude"))
    original = executable.read_bytes()
    calls: list[dict[str, object]] = []

    def mutate() -> None:
        executable.write_bytes(original + b"drift")

    monkeypatch.setattr(
        O,
        "run_owned_process",
        _successful_runner(calls, after_call=mutate),
    )
    with pytest.raises(O.ClaudeExecutableObservationError, match="changed|drift"):
        O.observe_claude_executable(
            configured_claude_bin=str(executable),
            environment={"PATH": str(tmp_path)},
        )

    executable.write_bytes(original)
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    observed = O.observe_claude_executable(
        configured_claude_bin=str(executable),
        environment={"PATH": str(tmp_path)},
    )
    executable.write_bytes(original + b"prelaunch-drift")
    with pytest.raises(O.ClaudeExecutableObservationError, match="changed|drift"):
        O.recheck_claude_executable_before_launch(
            observed,
            launch_executable=str(executable),
        )


def test_replay_is_digest_bound_and_prelaunch_requires_same_exact_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable, observed, _ = _observe_native(monkeypatch, tmp_path)
    assert O.replay_claude_executable_observation(observed) == observed
    assert (
        O.recheck_claude_executable_before_launch(
            observed,
            launch_executable=str(executable),
        )
        == observed
    )

    tampered = deepcopy(observed)
    tampered["claude_code_version"] = "2.1.219"
    with pytest.raises(O.ClaudeExecutableObservationError, match="digest|compatibility"):
        O.replay_claude_executable_observation(tampered)

    other = _copy_native(tmp_path / ("other.exe" if os.name == "nt" else "other"))
    with pytest.raises(O.ClaudeExecutableObservationError, match="launch executable"):
        O.recheck_claude_executable_before_launch(
            observed,
            launch_executable=str(other),
        )


def test_replay_rejects_version_stdout_that_was_rehashed_but_does_not_match(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, observed, _ = _observe_native(monkeypatch, tmp_path)
    tampered = deepcopy(observed)
    replacement = "2.1.219 (Claude Code)\n"
    tampered["version_probe"]["stdout_utf8"] = replacement
    tampered["version_probe"]["stdout_bytes"] = len(replacement.encode("utf-8"))
    tampered["version_probe"]["stdout_sha256"] = hashlib.sha256(
        replacement.encode("utf-8")
    ).hexdigest()
    core = dict(tampered)
    core.pop("observation_sha256")
    tampered["observation_sha256"] = O._digest(core)

    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="bind the observed version",
    ):
        O.replay_claude_executable_observation(tampered)


def test_relative_dotdot_symlink_and_hardlink_aliases_reject(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _copy_native(tmp_path / ("claude.exe" if os.name == "nt" else "claude"))
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    with pytest.raises(O.ClaudeExecutableObservationError, match="absolute|canonical"):
        O.observe_claude_executable(
            configured_claude_bin=executable.name,
            environment={"PATH": str(tmp_path)},
        )
    with pytest.raises(O.ClaudeExecutableObservationError, match="canonical|alias"):
        O.observe_claude_executable(
            configured_claude_bin=str(tmp_path / "sub" / ".." / executable.name),
            environment={"PATH": str(tmp_path)},
        )

    hardlink = tmp_path / ("hardlink.exe" if os.name == "nt" else "hardlink")
    os.link(executable, hardlink)
    with pytest.raises(O.ClaudeExecutableObservationError, match="hardlink|alias"):
        O.observe_claude_executable(
            configured_claude_bin=str(hardlink.resolve()),
            environment={"PATH": str(tmp_path)},
        )

    executable.unlink()
    hardlink.unlink()
    executable = _copy_native(tmp_path / ("claude2.exe" if os.name == "nt" else "claude2"))
    alias = tmp_path / ("alias.exe" if os.name == "nt" else "alias")
    try:
        alias.symlink_to(executable)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(O.ClaudeExecutableObservationError, match="symlink|reparse|alias"):
        O.observe_claude_executable(
            configured_claude_bin=str(alias.absolute()),
            environment={"PATH": str(tmp_path)},
        )


def _write_npm_wrapper(root: Path) -> tuple[Path, Path, Path]:
    wrapper = root / "claude.cmd"
    runtime = _copy_native(root / "node.exe")
    entrypoint = root / "node_modules" / "@anthropic-ai" / "claude-code" / "cli.js"
    entrypoint.parent.mkdir(parents=True)
    (entrypoint.parent / "package.json").write_text(
        '{"name":"@anthropic-ai/claude-code","version":"2.1.220",'
        '"dependencies":{}}\n',
        encoding="utf-8",
    )
    (entrypoint.parent / "lib").mkdir()
    (entrypoint.parent / "lib" / "runtime.js").write_text(
        "module.exports = 'closure';\n",
        encoding="utf-8",
    )
    entrypoint.write_text(
        "#!/usr/bin/env node\nrequire('./lib/runtime.js');\n"
        "console.log('fake');\n",
        encoding="utf-8",
    )
    wrapper.write_text(
        '@ECHO off\r\n'
        '"%~dp0node.exe" "%~dp0node_modules\\@anthropic-ai\\claude-code\\cli.js" %*\r\n',
        encoding="utf-8",
        newline="",
    )
    return wrapper.resolve(strict=True), runtime, entrypoint.resolve(strict=True)


def test_reviewed_npm_cmd_wrapper_records_unclosed_resolution_denominator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, runtime, entrypoint = _write_npm_wrapper(tmp_path)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(O, "run_owned_process", _successful_runner(calls))

    observed = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )

    assert observed["implementation_status"] == O.TRANSITIVE_IMPLEMENTATION_UNBOUND
    assert observed["implementation_debt"] == O.NPM_RESOLUTION_DENOMINATOR_UNBOUND
    assert observed["launch_authority"] == O.NO_PROOF_GRADE_LAUNCH
    rows = {row["role"]: row for row in observed["implementation_files"]}
    assert set(rows) == {"CONFIGURED_WRAPPER"}
    assert observed["implementation_closure_roots"] == []
    assert rows["CONFIGURED_WRAPPER"]["path"] == str(wrapper)
    assert calls[0]["command"] == (str(wrapper), "--version")
    assert O.replay_claude_executable_observation(
        observed,
        require_proof_grade=False,
    ) == observed
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="proof-grade",
    ):
        O.replay_claude_executable_observation(observed)


def test_unclosed_npm_denominator_is_rejected_before_entrypoint_change_matters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, _, entrypoint = _write_npm_wrapper(tmp_path)
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    observed = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )
    entrypoint.write_text("console.log('changed');\n", encoding="utf-8")
    with pytest.raises(O.ClaudeExecutableObservationError, match="proof-grade"):
        O.recheck_claude_executable_before_launch(
            observed,
            launch_executable=str(wrapper),
        )


def test_unclosed_npm_denominator_cannot_be_promoted_by_declared_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, _, entrypoint = _write_npm_wrapper(tmp_path)
    dependency = entrypoint.parent / "lib" / "runtime.js"
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    observed = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )

    assert str(dependency) not in {
        row["path"] for row in observed["implementation_files"]
    }
    dependency.write_text("module.exports = 'changed';\n", encoding="utf-8")
    with pytest.raises(O.ClaudeExecutableObservationError, match="proof-grade"):
        O.recheck_claude_executable_before_launch(
            observed,
            launch_executable=str(wrapper),
        )


def test_unknown_wrapper_records_explicit_unbound_debt_and_cannot_authorize_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper = tmp_path / "claude.cmd"
    wrapper.write_text("@echo off\r\necho opaque\r\n", encoding="utf-8", newline="")
    wrapper = wrapper.resolve(strict=True)
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))

    observed = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )
    assert observed["implementation_status"] == O.TRANSITIVE_IMPLEMENTATION_UNBOUND
    assert observed["launch_authority"] == O.NO_PROOF_GRADE_LAUNCH
    assert observed["implementation_debt"] == O.TRANSITIVE_IMPLEMENTATION_UNBOUND
    assert O.replay_claude_executable_observation(
        observed,
        require_proof_grade=False,
    ) == observed
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="TRANSITIVE_IMPLEMENTATION_UNBOUND|proof-grade",
    ):
        O.replay_claude_executable_observation(observed)
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="TRANSITIVE_IMPLEMENTATION_UNBOUND|proof-grade",
    ):
        O.recheck_claude_executable_before_launch(
            observed,
            launch_executable=str(wrapper),
        )


def test_npm_tokens_in_comments_cannot_mint_transitive_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, _, _ = _write_npm_wrapper(tmp_path)
    wrapper.write_text(
        "@echo off\r\n"
        'rem "%~dp0node.exe" "%~dp0node_modules\\@anthropic-ai\\claude-code\\cli.js" %*\r\n'
        "echo attacker-controlled-command\r\n",
        encoding="utf-8",
        newline="",
    )
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    observed = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )
    assert observed["implementation_status"] == O.TRANSITIVE_IMPLEMENTATION_UNBOUND
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="TRANSITIVE_IMPLEMENTATION_UNBOUND",
    ):
        O.replay_claude_executable_observation(observed)


def test_required_capability_must_exist_in_exact_reviewed_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _copy_native(tmp_path / ("claude.exe" if os.name == "nt" else "claude"))
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    with pytest.raises(O.ClaudeExecutableObservationError, match="capability"):
        O.observe_claude_executable(
            configured_claude_bin=str(executable),
            environment={"PATH": str(tmp_path)},
            required_capabilities=("imaginary-future-flag",),
        )


def test_real_required_flag_capabilities_are_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _copy_native(tmp_path / ("claude.exe" if os.name == "nt" else "claude"))
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))

    observed = O.observe_claude_executable(
        configured_claude_bin=str(executable),
        environment={"PATH": str(tmp_path)},
        required_capabilities=(
            "-p",
            "--output-format=stream-json",
            "--safe-mode",
            "init-security-v2",
        ),
    )

    assert observed["launch_authority"] == O.PROOF_GRADE


def test_observation_is_deterministic_and_binds_all_file_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper, _, entrypoint = _write_npm_wrapper(tmp_path)
    monkeypatch.setattr(O, "run_owned_process", _successful_runner([]))
    first = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )
    second = O.observe_claude_executable(
        configured_claude_bin=str(wrapper),
        environment={"PATH": str(tmp_path)},
    )
    assert first == second
    expected = hashlib.sha256(entrypoint.read_bytes()).hexdigest()
    assert expected not in {
        row["sha256"] for row in first["implementation_files"]
    }
    assert first["implementation_debt"] == O.NPM_RESOLUTION_DENOMINATOR_UNBOUND


def test_typed_reference_binds_reviewed_version_capabilities_and_observation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _, observed, _ = _observe_native(monkeypatch, tmp_path)
    reference = O.compile_claude_executable_observation_reference(
        observed,
        required_capabilities=(
            "--tools",
            "--safe-mode",
            "init-security-v2",
        ),
    )

    assert reference["schema"] == (
        "plamen.claude_executable_observation_reference.v1"
    )
    assert reference["observation_sha256"] == observed["observation_sha256"]
    assert reference["compatibility_sha256"] == (
        observed["compatibility"]["compatibility_sha256"]
    )
    assert reference["required_capabilities"] == [
        "--safe-mode",
        "--tools",
        "init-security-v2",
    ]
    assert O.replay_claude_executable_observation_reference(reference) == (
        reference
    )

    changed = deepcopy(reference)
    changed["required_capabilities"].append("--unknown-future-flag")
    core = dict(changed)
    core.pop("reference_sha256")
    changed["reference_sha256"] = O._digest(core)
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="capabilit",
    ):
        O.replay_claude_executable_observation_reference(changed)


def test_magic_prefix_alone_cannot_mint_native_proof_grade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = tmp_path / ("claude.exe" if os.name == "nt" else "claude")
    executable.write_bytes(b"MZthis-is-not-a-signed-claude-executable")
    executable.chmod(0o700)
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(O, "run_owned_process", _successful_runner(calls))

    observed = O.observe_claude_executable(
        configured_claude_bin=str(executable.resolve(strict=True)),
        environment={"PATH": str(tmp_path)},
    )

    assert observed["implementation_status"] == (
        O.TRANSITIVE_IMPLEMENTATION_UNBOUND
    )
    assert observed["implementation_debt"] == O.NATIVE_IMPLEMENTATION_UNBOUND
    assert observed["launch_authority"] == O.NO_PROOF_GRADE_LAUNCH
    with pytest.raises(
        O.ClaudeExecutableObservationError,
        match="cannot authorize a proof-grade launch",
    ):
        O.replay_claude_executable_observation(observed)
