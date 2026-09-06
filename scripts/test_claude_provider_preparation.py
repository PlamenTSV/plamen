from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import claude_auth_route as A
import claude_provider_preparation as P
import claude_runtime_materialization as M
from claude_executable_observation import (
    ClaudeExecutableObservationError,
)
from claude_stored_subscription_source import (
    ClaudeStoredSubscriptionSourceError,
)
from test_support_startup_permit import durable_startup_permit


VERSION = "2.1.220"
MODEL = "claude-opus-5"
RUN_ID = "12345678-1234-4abc-8def-1234567890ab"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _hex(number: int) -> str:
    return format(number, "064x")


def _stored_evidence(*, available: bool = True) -> dict[str, object]:
    core: dict[str, object] = {
        "schema": "plamen.claude_stored_subscription_source.v1",
        "store_class": "FILE_BACKED",
        "source_identity": "fixture-profile",
        "source_size": 211 if available else 0,
        "available": available,
        "observation_authority_sha256": "b" * 64,
        "credential_values_recorded": False,
        "credential_content_hashes_recorded": False,
    }
    return {**core, "receipt_sha256": _digest(core)}


def _executable_observation(path: Path) -> dict[str, object]:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    executable_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
    capabilities = sorted(
        (
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
        )
    )
    compatibility_core = {
        "compatibility_id": "claude-code-2.1.220",
        "claude_code_version": VERSION,
        "supported_capabilities": capabilities,
    }
    stdout = f"{VERSION} (Claude Code)\n"
    native_core = {
        "schema": "plamen.claude_native_platform_authority.v1",
        "platform": "WINDOWS_AUTHENTICODE",
        "publisher_policy_id": "anthropic-claude-code-windows-v1",
        "publisher_name": "Anthropic PBC",
        "signer_subject": "CN=Anthropic PBC, O=Anthropic PBC",
        "product_name": "Claude Code",
        "file_version": f"{VERSION}.0",
        "claude_code_version": VERSION,
        "executable_path": str(resolved),
        "executable_sha256": executable_sha256,
        "executable_size": info.st_size,
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    core = {
        "schema": "plamen.claude_executable_observation.v1",
        "configured_claude_bin": str(resolved),
        "resolved_executable": str(resolved),
        "claude_code_version": VERSION,
        "compatibility": {
            **compatibility_core,
            "compatibility_sha256": _digest(compatibility_core),
        },
        "implementation_kind": "NATIVE_EXECUTABLE_IMAGE",
        "implementation_status": "DIRECT_IMPLEMENTATION_BOUND",
        "implementation_debt": None,
        "implementation_files": [
            {
                "role": "CONFIGURED_EXECUTABLE",
                "path": str(resolved),
                "sha256": executable_sha256,
                "size": info.st_size,
                "device": info.st_dev,
                "inode": info.st_ino,
                "mode": info.st_mode,
                "link_count": 1,
            }
        ],
        "implementation_closure_roots": [],
        "native_platform_authority": {
            **native_core,
            "authority_sha256": _digest(native_core),
        },
        "version_probe": {
            "argv": [str(resolved), "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(stdout.encode("utf-8")),
            "stdout_sha256": hashlib.sha256(
                stdout.encode("utf-8")
            ).hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": "PROOF_GRADE",
    }
    return {**core, "observation_sha256": _digest(core)}


def _unbound_wrapper_observation(path: Path) -> dict[str, object]:
    observed = _executable_observation(path)
    core = {
        key: value
        for key, value in observed.items()
        if key != "observation_sha256"
    }
    core["implementation_kind"] = "UNREVIEWED_WRAPPER"
    core["implementation_status"] = "TRANSITIVE_IMPLEMENTATION_UNBOUND"
    core["implementation_debt"] = "TRANSITIVE_IMPLEMENTATION_UNBOUND"
    core["implementation_files"][0]["role"] = "CONFIGURED_WRAPPER"
    core["native_platform_authority"] = None
    core["launch_authority"] = "NO_PROOF_GRADE_LAUNCH"
    return {**core, "observation_sha256": _digest(core)}


def _install_observers(
    monkeypatch: pytest.MonkeyPatch,
    executable: Path,
    *,
    stored_available: bool = True,
    observation: dict[str, object] | None = None,
) -> None:
    observed = observation or _executable_observation(executable)
    monkeypatch.setattr(
        P,
        "observe_claude_executable",
        lambda **_kwargs: observed,
    )
    evidence = _stored_evidence(available=stored_available)
    def observed_source_authority(**_kwargs: object) -> object:
        if not stored_available:
            return evidence
        return A._promote_stored_subscription_source_evidence(
            evidence,
            provider_authority_sha256=(
                evidence["observation_authority_sha256"]
            ),
        )

    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        observed_source_authority,
    )
    monkeypatch.setattr(
        P,
        "replay_stored_subscription_source_observation",
        lambda value: dict(value),
    )
    monkeypatch.setattr(
        P,
        "replay_startup_permit_binding",
        lambda **kwargs: {"binding": dict(kwargs["binding"])},
    )


def _inputs(
    tmp_path: Path,
    *,
    backend: str = "claude",
    route: str = "STORED_SUBSCRIPTION_OAUTH",
    settings_mode: str = "SAFE_MODE",
    mcp_servers: tuple[str, ...] = (),
    ambient_secret: str = "sk-ant-api-red",
) -> dict[str, object]:
    project = tmp_path / "project"
    scratchpad = project / ".scratchpad"
    source = tmp_path / "source-profile"
    project.mkdir(parents=True, exist_ok=True)
    scratchpad.mkdir(exist_ok=True)
    source.mkdir(exist_ok=True)
    executable = tmp_path / "claude-fixture.exe"
    executable.write_bytes(b"fixture native image")
    phase = "breadth"
    intent = P.compile_claude_provider_semantic_intent(
        run_id=RUN_ID,
        phase=phase,
        backend=backend,
        launch_model=MODEL,
        accepted_models=(MODEL,),
        cwd=str(project),
        session_id="d63d4072-5b15-5f0d-8cb6-d6e2ff4bfde3",
        max_line_bytes=2 * 1024 * 1024,
        max_stream_bytes=8 * 1024 * 1024,
        desired_auth_route=route,
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=("base", "git", "rust"),
        functional_controls={
            "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_UPDATES": "1",
            "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        },
    )
    tool_policy = P.compile_claude_phase_tool_policy(
        phase=phase,
        permission_mode="dontAsk",
        builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        required_tools=("Read", "Write"),
        forbidden_tools=("Bash", "WebFetch", "WebSearch"),
    )
    bound_settings_bytes = (
        None
        if settings_mode == "SAFE_MODE"
        else _canonical(
            {
                "enabledPlugins": {},
                "hooks": {},
                "mcpServers": {},
                "permissions": {"deny": []},
            }
        )
        + b"\n"
    )
    selected_mcp_config_bytes = (
        None
        if settings_mode == "SAFE_MODE"
        else _canonical(
            {
                "mcpServers": {
                    name: {
                        "command": "fixture-mcp",
                        "args": [],
                    }
                    for name in mcp_servers
                }
            }
        )
        + b"\n"
    )
    settings = P.compile_claude_settings_policy(
        mode=settings_mode,
        settings_sha256=(
            None
            if bound_settings_bytes is None
            else hashlib.sha256(bound_settings_bytes).hexdigest()
        ),
        external_policy_sha256=(
            None if settings_mode == "SAFE_MODE" else _hex(32)
        ),
    )
    mcp = P.compile_claude_mcp_policy(
        settings_mode=settings_mode,
        server_names=mcp_servers,
        source_manifest_sha256=(
            _hex(33) if mcp_servers else None
        ),
        selected_config_sha256=(
            None
            if selected_mcp_config_bytes is None
            else hashlib.sha256(
                selected_mcp_config_bytes
            ).hexdigest()
        ),
    )
    ambient = {
        "PATH": str(tmp_path),
        "HOME": str(tmp_path / "home"),
        "USERPROFILE": str(tmp_path / "home"),
        "ANTHROPIC_API_KEY": ambient_secret,
    }
    if route == "OAUTH_TOKEN":
        ambient["CLAUDE_CODE_OAUTH_TOKEN"] = "oauth-private-value"
    return {
        "semantic_intent": intent,
        "phase_tool_policy": tool_policy,
        "settings_policy": settings,
        "mcp_policy": mcp,
        "configured_claude_bin": str(executable),
        "ambient_environment": ambient,
        "settings_evidence": {},
        "stored_subscription_source_path": (
            source / ".credentials.json"
        ),
        "source_config_dir": (
            None if route == "OAUTH_TOKEN" else source
        ),
        "project_root": project,
        "trusted_cwds": (project,),
        "startup_authority_binding": {
            "schema": "fixture.startup-binding.v1",
            "run_id": RUN_ID,
            "startup_epoch": "epoch-1",
        },
        "startup_scratchpad": scratchpad,
        "source_snapshot_sha256": _hex(41),
        "_bound_settings_bytes": bound_settings_bytes,
        "_selected_mcp_config_bytes": selected_mcp_config_bytes,
    }


def _public_inputs(values: dict[str, object]) -> dict[str, object]:
    return {
        key: value
        for key, value in values.items()
        if not key.startswith("_")
    }


def _attach(
    package: P.ClaudeProviderPreparation,
    values: dict[str, object],
) -> P.BoundClaudeProviderRuntime:
    return P.attach_claude_provider_runtime(
        package,
        ambient_environment=values["ambient_environment"],
        source_config_dir=values["source_config_dir"],
        project_root=values["project_root"],
        trusted_cwds=values["trusted_cwds"],
        bound_settings_bytes=values["_bound_settings_bytes"],
        selected_mcp_config_bytes=values[
            "_selected_mcp_config_bytes"
        ],
    )


def _prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    **overrides: object,
) -> P.ClaudeProviderPreparation:
    values = _inputs(tmp_path)
    values.update(overrides)
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    return P.prepare_claude_provider(**_public_inputs(values))


def _rehash_outer(payload: dict[str, object]) -> bytes:
    core = {
        key: value
        for key, value in payload.items()
        if key != "preparation_sha256"
    }
    payload["preparation_sha256"] = _digest(core)
    return _canonical(payload) + b"\n"


def _replay(package: P.ClaudeProviderPreparation):
    record = package.record
    return P.replay_claude_provider_preparation(
        package.to_bytes(),
        expected_backend="claude",
        expected_startup_authority_sha256=record[
            "startup_authority_sha256"
        ],
        expected_source_snapshot_sha256=record[
            "source_snapshot_sha256"
        ],
    )


def test_package_is_immutable_replayable_and_exact_consumer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package = _prepare(monkeypatch, tmp_path)
    assert package.eligible
    assert package.debts == ()
    assert _replay(package).to_bytes() == package.to_bytes()
    with pytest.raises((AttributeError, TypeError)):
        package._record_bytes = b""  # type: ignore[misc]

    public = package.public_headless_arguments()
    assert public["environment"] == {}
    assert public["claude_launch_security"] == package.record[
        "launch_security"
    ]
    assert public["claude_launch_security_request"] == package.record[
        "launch_security_request"
    ]
    assert public["provider_stdout_evidence_configuration"] == (
        package.record["stream_configuration"]
    )
    assert tuple(public["environment_allowlist"]) == tuple(
        package.record["planned_child_environment_names"]
    )
    assert public["claude_provider_preparation_sha256"] == (
        package.preparation_sha256
    )
    assert public["claude_runtime_host_policy_sha256"] == (
        package.record["runtime_host_policy"]["policy_sha256"]
    )
    argv = package.command_for_bound_stdin()
    assert argv[0] == str(
        Path(package.record["executable_observation"][
            "resolved_executable"
        ])
    )
    assert argv[1:3] == ("-p", "--model")
    assert "fixture prompt" not in argv
    assert "--model" in argv
    assert MODEL in argv
    assert tuple(package.record["headless_profile"]["cli_flags"]) == (
        argv[-len(package.record["headless_profile"]["cli_flags"]):]
    )
    values = _inputs(tmp_path / "attached")
    _install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    attached_package = P.prepare_claude_provider(
        **_public_inputs(values)
    )
    opaque = _attach(attached_package, values)
    assert type(opaque).__name__ == "BoundClaudeProviderRuntime"
    assert opaque.preparation_sha256 == attached_package.preparation_sha256
    assert opaque.runtime_host_policy_sha256 == attached_package.record[
        "runtime_host_policy"
    ]["policy_sha256"]
    with pytest.raises(TypeError):
        opaque.__reduce__()


def test_ambient_api_key_is_observed_but_stored_route_is_single_planned_route(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package = _prepare(monkeypatch, tmp_path)
    record = package.record
    assert record["auth_route_observation"]["selected_route"] == "API_KEY"
    assert "STORED_SUBSCRIPTION_OAUTH" in record[
        "auth_route_observation"
    ]["present_routes"]
    assert record["auth_route_policy"]["desired_route"] == (
        "STORED_SUBSCRIPTION_OAUTH"
    )
    assert "ANTHROPIC_API_KEY" not in record[
        "planned_child_environment_names"
    ]
    assert record["headless_profile"]["expected_init_contract"][
        "accepted_api_key_sources"
    ] == ["none"]


def test_no_mcp_safe_mode_and_selected_mcp_are_distinct_authorities(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    safe = _prepare(monkeypatch, tmp_path / "safe")
    assert safe.record["headless_profile"]["customization_mode"] == (
        "SAFE_MODE"
    )
    assert safe.record["mcp_authority"]["server_names"] == []
    assert "--safe-mode" in safe.record["headless_profile"]["cli_flags"]

    selected_inputs = _inputs(
        tmp_path / "mcp",
        settings_mode="BOUND_SETTINGS",
        mcp_servers=("unified-vuln-db",),
    )
    executable = Path(str(selected_inputs["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    selected = P.prepare_claude_provider(
        **_public_inputs(selected_inputs)
    )
    assert selected.eligible
    assert selected.record["headless_profile"]["customization_mode"] == (
        "BOUND_SETTINGS"
    )
    assert selected.record["mcp_authority"]["server_names"] == [
        "unified-vuln-db"
    ]
    assert selected.record["headless_profile"][
        "required_runtime_authority_flags"
    ] == ["--mcp-config", "--settings", "--strict-mcp-config"]
    assert "--safe-mode" not in selected.record[
        "headless_profile"
    ]["cli_flags"]


def test_bound_exact_consumer_with_empty_mcp_is_not_safe_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(tmp_path, settings_mode="BOUND_SETTINGS")
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    package = P.prepare_claude_provider(**_public_inputs(values))
    assert package.eligible
    assert package.record["settings_authority"]["mode"] == "BOUND_SETTINGS"
    assert package.record["mcp_authority"]["server_names"] == []
    assert package.record["mcp_authority"][
        "selected_config_sha256"
    ] == hashlib.sha256(
        values["_selected_mcp_config_bytes"]
    ).hexdigest()


def test_model_session_and_stream_mismatches_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    with pytest.raises(P.ClaudeProviderPreparationError, match="model"):
        P.compile_claude_provider_semantic_intent(
            run_id=RUN_ID,
            phase="breadth",
            backend="claude",
            launch_model=MODEL,
            accepted_models=("claude-sonnet-5",),
            cwd=str(tmp_path),
            session_id="d63d4072-5b15-5f0d-8cb6-d6e2ff4bfde3",
            max_line_bytes=1024,
            max_stream_bytes=1024,
            desired_auth_route="STORED_SUBSCRIPTION_OAUTH",
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
            phase_environment_policies=("base",),
            functional_controls={
                "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
            },
        )
    package = _prepare(monkeypatch, tmp_path / "package")
    for mutate in ("session", "stream", "model"):
        payload = package.record
        if mutate == "session":
            payload["stream_configuration"]["expected_session_id"] = (
                "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
            )
        elif mutate == "stream":
            payload["stream_configuration"]["max_stream_bytes"] -= 1
        else:
            payload["headless_profile"]["expected_init_contract"][
                "accepted_models"
            ] = ["claude-sonnet-5"]
        with pytest.raises(P.ClaudeProviderPreparationError):
            P.replay_claude_provider_preparation(
                _rehash_outer(payload),
                expected_backend="claude",
                expected_startup_authority_sha256=package.record[
                    "startup_authority_sha256"
                ],
                expected_source_snapshot_sha256=package.record[
                    "source_snapshot_sha256"
                ],
            )


def test_unknown_version_and_unbound_wrapper_become_typed_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(tmp_path / "version")
    _install_observers(
        monkeypatch,
        Path(str(values["configured_claude_bin"])),
    )
    monkeypatch.setattr(
        P,
        "observe_claude_executable",
        lambda **_kwargs: (_ for _ in ()).throw(
            ClaudeExecutableObservationError(
                "Claude Code version 99.0.0 has no reviewed compatibility row"
            )
        ),
    )
    version = P.prepare_claude_provider(**_public_inputs(values))
    assert not version.eligible
    assert version.debts[0]["code"] == "CLAUDE_VERSION_UNSUPPORTED"

    wrapper_values = _inputs(tmp_path / "wrapper")
    executable = Path(str(wrapper_values["configured_claude_bin"]))
    _install_observers(
        monkeypatch,
        executable,
        observation=_unbound_wrapper_observation(executable),
    )
    wrapper = P.prepare_claude_provider(
        **_public_inputs(wrapper_values)
    )
    assert not wrapper.eligible
    assert wrapper.debts[0]["code"] == (
        "CLAUDE_IMPLEMENTATION_CLOSURE_UNBOUND"
    )


def test_absent_store_host_and_executable_are_explicit_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    absent_values = _inputs(tmp_path / "absent")
    _install_observers(
        monkeypatch,
        Path(str(absent_values["configured_claude_bin"])),
    )
    monkeypatch.setattr(
        P,
        "observe_claude_executable",
        lambda **_kwargs: (_ for _ in ()).throw(
            ClaudeExecutableObservationError(
                "owned Claude version probe failed: FileNotFoundError"
            )
        ),
    )
    absent = P.prepare_claude_provider(
        **_public_inputs(absent_values)
    )
    assert absent.debts[0]["code"] == "CLAUDE_EXECUTABLE_UNAVAILABLE"

    store_values = _inputs(tmp_path / "store")
    executable = Path(str(store_values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        lambda **_kwargs: (_ for _ in ()).throw(
            ClaudeStoredSubscriptionSourceError(
                "stored subscription observation is unsupported host"
            )
        ),
    )
    store = P.prepare_claude_provider(**_public_inputs(store_values))
    assert store.debts[0]["code"] == "CLAUDE_STORED_SOURCE_UNSUPPORTED"

    host_values = _inputs(tmp_path / "host")
    executable = Path(str(host_values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    monkeypatch.setattr(P, "_detect_host_family", lambda: "unsupported")
    host = P.prepare_claude_provider(**_public_inputs(host_values))
    assert host.debts[0]["code"] == "CLAUDE_HOST_UNSUPPORTED"


def test_unsupported_host_fails_before_provider_observation_and_compilation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(tmp_path / "unsupported-host")
    monkeypatch.setattr(P, "_detect_host_family", lambda: "unsupported")
    monkeypatch.setattr(
        P,
        "replay_startup_permit_binding",
        lambda **kwargs: {"binding": dict(kwargs["binding"])},
    )
    calls: list[str] = []

    def unexpected(name: str):
        def fail(*_args: object, **_kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(
                f"{name} ran after the host was classified unsupported"
            )

        return fail

    for name in (
        "observe_claude_executable",
        "observe_stored_subscription_source_authority",
        "compile_claude_settings_authority",
        "compile_claude_mcp_authority",
        "observe_claude_auth_sources",
        "classify_claude_auth_route",
        "compile_claude_auth_route_policy",
        "compile_claude_headless_profile_from_authorities",
    ):
        monkeypatch.setattr(P, name, unexpected(name))

    package = P.prepare_claude_provider(**_public_inputs(values))

    assert not package.eligible
    assert package.debts[0]["code"] == "CLAUDE_HOST_UNSUPPORTED"
    assert calls == []


@pytest.mark.parametrize(
    ("release", "expected_family"),
    (
        ("6.8.0-generic", "linux"),
        ("4.4.0-19041-Microsoft", "wsl2"),
        ("5.15.153.1-MICROSOFT-standard-WSL2", "wsl2"),
        ("6.8.0-newsletter", "linux"),
        ("6.8.0-microsoftish", "linux"),
        ("6.8.0-notwsl", "linux"),
        ("6.8.0-custom-native-linux", "linux"),
        ("6.8.0-prewsl2", "linux"),
        ("6.8.0-wsl2post", "linux"),
        ("6.8.0-WSL3-custom", "linux"),
    ),
)
def test_kernel_marker_boundaries_reach_the_exact_durable_host_family(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    release: str,
    expected_family: str,
) -> None:
    with monkeypatch.context() as host_context:
        host_context.setattr(P.os, "name", "posix")
        host_context.setattr(P.sys, "platform", "linux")
        host_context.setattr(
            P.os,
            "uname",
            lambda: SimpleNamespace(release=release),
            raising=False,
        )
        detected_family = P._detect_host_family()
    assert detected_family == expected_family

    values = _inputs(tmp_path / release)
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    monkeypatch.setattr(
        P,
        "_detect_host_family",
        lambda: detected_family,
    )

    package = P.prepare_claude_provider(**_public_inputs(values))

    assert package.eligible
    assert package.record["runtime_host_policy"]["host_family"] == (
        expected_family
    )


def test_raw_available_store_receipt_is_explicit_authority_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(tmp_path)
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    raw = _stored_evidence(available=True)
    monkeypatch.setattr(
        P,
        "observe_stored_subscription_source_authority",
        lambda **_kwargs: raw,
    )

    package = P.prepare_claude_provider(**_public_inputs(values))

    assert not package.eligible
    assert package.debts[0]["code"] == (
        "CLAUDE_STORED_SOURCE_AUTHORITY_UNAVAILABLE"
    )
    assert package.record["auth_source_observation"] is None


def test_privacy_record_is_not_an_offline_secret_or_path_oracle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    red_values = _inputs(tmp_path, ambient_secret="sk-ant-api-red")
    executable = Path(str(red_values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    red = P.prepare_claude_provider(**_public_inputs(red_values))

    blue_values = dict(red_values)
    blue_values["ambient_environment"] = {
        **red_values["ambient_environment"],
        "ANTHROPIC_API_KEY": "sk-ant-api-blue",
    }
    blue = P.prepare_claude_provider(**_public_inputs(blue_values))
    red_again = P.prepare_claude_provider(
        **_public_inputs(red_values)
    )
    assert red.to_bytes() == blue.to_bytes() == red_again.to_bytes()
    for package in (red, blue, red_again):
        durable = package.to_bytes()
        for secret in (
            b"sk-ant-api-red",
            b"sk-ant-api-blue",
            str(red_values["source_config_dir"]).encode("utf-8"),
        ):
            assert secret not in durable
            assert (
                hashlib.sha256(secret).hexdigest().encode("ascii")
                not in durable
            )
        assert b"credential_values_recorded\" : true" not in durable
    assert red.record["runtime_host_policy"][
        "host_paths_recorded"
    ] is False


@pytest.mark.parametrize("family", ("windows", "linux", "wsl2", "macos"))
def test_windows_and_posix_host_capability_is_observed_not_asserted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    family: str,
) -> None:
    values = _inputs(tmp_path / family)
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    monkeypatch.setattr(P, "_detect_host_family", lambda: family)
    package = P.prepare_claude_provider(**_public_inputs(values))
    assert package.eligible
    assert package.record["runtime_host_policy"][
        "host_family"
    ] == family


def test_retry_and_restart_reuse_policy_but_get_fresh_bound_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(tmp_path)
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    package = P.prepare_claude_provider(**_public_inputs(values))
    replayed = _replay(package)
    assert replayed.to_bytes() == package.to_bytes()

    first = _attach(package, values)
    second = _attach(package, values)
    restarted = _attach(replayed, values)
    assert len(
        {
            first.attachment_sha256,
            second.attachment_sha256,
            restarted.attachment_sha256,
        }
    ) == 3
    assert {
        first.preparation_sha256,
        second.preparation_sha256,
        restarted.preparation_sha256,
    } == {package.preparation_sha256}
    claimed = P.claim_bound_claude_provider_runtime(
        first,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=first.attachment_sha256,
    )
    assert type(claimed.host_inputs).__name__ == "ClaudeRuntimeHostInputs"
    assert claimed.bound_settings_bytes is None
    assert claimed.selected_mcp_config_bytes is None
    with pytest.raises(P.ClaudeProviderPreparationError, match="claimed"):
        P.claim_bound_claude_provider_runtime(
            first,
            provider_preparation=package,
            expected_preparation_sha256=package.preparation_sha256,
            expected_runtime_host_policy_sha256=package.record[
                "runtime_host_policy"
            ]["policy_sha256"],
            expected_attachment_sha256=first.attachment_sha256,
        )


def test_bound_settings_and_mcp_bytes_are_transient_exact_and_mutation_safe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(
        tmp_path,
        settings_mode="BOUND_SETTINGS",
        mcp_servers=("unified-vuln-db",),
    )
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    package = P.prepare_claude_provider(**_public_inputs(values))
    attachment = _attach(package, values)
    claimed = P.claim_bound_claude_provider_runtime(
        attachment,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=attachment.attachment_sha256,
    )
    assert claimed.bound_settings_bytes == values[
        "_bound_settings_bytes"
    ]
    assert claimed.selected_mcp_config_bytes == values[
        "_selected_mcp_config_bytes"
    ]
    assert values["_bound_settings_bytes"] not in package.to_bytes()
    assert values["_selected_mcp_config_bytes"] not in package.to_bytes()

    with pytest.raises(P.ClaudeProviderPreparationError) as captured:
        P.attach_claude_provider_runtime(
            package,
            ambient_environment=values["ambient_environment"],
            source_config_dir=values["source_config_dir"],
            project_root=values["project_root"],
            trusted_cwds=values["trusted_cwds"],
            bound_settings_bytes=b'{"changed":true}\n',
            selected_mcp_config_bytes=values[
                "_selected_mcp_config_bytes"
            ],
        )
    assert captured.value.debt["code"] == "CLAUDE_BOUND_SETTINGS_DRIFT"


def test_bound_provider_sources_materialize_only_under_attempt_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(
        tmp_path,
        route="OAUTH_TOKEN",
        settings_mode="BOUND_SETTINGS",
        mcp_servers=("unified-vuln-db",),
    )
    scratchpad = Path(values["startup_scratchpad"])
    values["startup_authority_binding"] = durable_startup_permit(
        scratchpad,
        run_id=RUN_ID,
    )
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(
        monkeypatch,
        executable,
        stored_available=False,
    )
    package = P.prepare_claude_provider(**_public_inputs(values))
    attachment = _attach(package, values)
    claimed = P.claim_bound_claude_provider_runtime(
        attachment,
        provider_preparation=package,
        expected_preparation_sha256=package.preparation_sha256,
        expected_runtime_host_policy_sha256=package.record[
            "runtime_host_policy"
        ]["policy_sha256"],
        expected_attachment_sha256=attachment.attachment_sha256,
    )
    profile_flags = tuple(
        package.record["headless_profile"]["cli_flags"]
    )
    command = package.command_for_bound_stdin()
    base_argv = command[:-len(profile_flags)]
    request = M.compile_claude_runtime_materialization_request(
        launch_security_request=package.record[
            "launch_security_request"
        ],
        provider_runtime=claimed,
        base_argv=base_argv,
        scratchpad=scratchpad,
        startup_permit_binding=values[
            "startup_authority_binding"
        ],
        run_id=RUN_ID,
        outer_attempt_arm_sha256=_hex(51),
        work_plan_sha256=_hex(52),
        attempt_id="attempt-bound-provider",
        process_scope_identity="scope-bound-provider",
    )
    runtime = M.materialize_claude_runtime(request)
    try:
        argv = runtime.final_argv
        settings_path = Path(
            argv[argv.index("--settings") + 1]
        )
        mcp_path = Path(
            argv[argv.index("--mcp-config") + 1]
        )
        assert settings_path.is_absolute()
        assert mcp_path.is_absolute()
        assert runtime.process_writable_root in settings_path.parents
        assert runtime.process_writable_root in mcp_path.parents
        assert settings_path.read_bytes() == values[
            "_bound_settings_bytes"
        ]
        assert mcp_path.read_bytes() == values[
            "_selected_mcp_config_bytes"
        ]
        assert M.replay_claude_runtime_materialization(runtime)[
            "valid"
        ] is True

        original = settings_path.read_bytes()
        settings_path.write_bytes(original + b" ")
        with pytest.raises(
            M.ClaudeRuntimeMaterializationError,
            match="changed after materialization",
        ):
            M.replay_claude_runtime_materialization(runtime)
        settings_path.write_bytes(original)
    finally:
        runtime.abort_before_process_scope(
            "TEST_BOUND_RUNTIME_SOURCE_ABORT"
        )


def test_secret_bearing_selected_mcp_config_is_explicitly_unsupported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    values = _inputs(
        tmp_path,
        settings_mode="BOUND_SETTINGS",
        mcp_servers=("unified-vuln-db",),
    )
    secret_config = (
        _canonical(
            {
                "mcpServers": {
                    "unified-vuln-db": {
                        "command": "fixture-mcp",
                        "env": {"SOLIDIT_API_KEY": "private-secret"},
                    }
                }
            }
        )
        + b"\n"
    )
    values["_selected_mcp_config_bytes"] = secret_config
    values["mcp_policy"] = P.compile_claude_mcp_policy(
        settings_mode="BOUND_SETTINGS",
        server_names=("unified-vuln-db",),
        source_manifest_sha256=_hex(33),
        selected_config_sha256=hashlib.sha256(
            secret_config
        ).hexdigest(),
    )
    executable = Path(str(values["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    package = P.prepare_claude_provider(**_public_inputs(values))
    with pytest.raises(P.ClaudeProviderPreparationError) as captured:
        _attach(package, values)
    assert captured.value.debt["code"] == (
        "CLAUDE_BOUND_SOURCE_SECRET_UNSUPPORTED"
    )
    assert b"private-secret" not in package.to_bytes()


def test_codex_rejects_claude_package_and_parent_or_code_drift_rejects_replay(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    codex = _inputs(tmp_path / "codex", backend="codex")
    executable = Path(str(codex["configured_claude_bin"]))
    _install_observers(monkeypatch, executable)
    with pytest.raises(P.ClaudeProviderPreparationError, match="Codex|backend"):
        P.prepare_claude_provider(**_public_inputs(codex))

    package = _prepare(monkeypatch, tmp_path / "claude")
    with pytest.raises(P.ClaudeProviderPreparationError, match="Codex|backend"):
        package.validate_for_backend("codex")
    with pytest.raises(P.ClaudeProviderPreparationError, match="startup"):
        P.replay_claude_provider_preparation(
            package.to_bytes(),
            expected_backend="claude",
            expected_startup_authority_sha256=_hex(999),
            expected_source_snapshot_sha256=package.record[
                "source_snapshot_sha256"
            ],
        )

    mutated = package.record
    mutated["implementation_closure"][0]["sha256"] = _hex(998)
    with pytest.raises(
        P.ClaudeProviderPreparationError,
        match="implementation closure",
    ):
        P.replay_claude_provider_preparation(
            _rehash_outer(mutated),
            expected_backend="claude",
            expected_startup_authority_sha256=package.record[
                "startup_authority_sha256"
            ],
            expected_source_snapshot_sha256=package.record[
                "source_snapshot_sha256"
            ],
        )
