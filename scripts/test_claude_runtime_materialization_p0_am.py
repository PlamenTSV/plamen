from __future__ import annotations

from copy import deepcopy
import hashlib
import inspect
import json
import os
from pathlib import Path
import pickle
import subprocess
from types import MappingProxyType
from concurrent.futures import ThreadPoolExecutor

import pytest

import auxiliary_writable_root_lease as A
from claude_child_environment import (
    planned_claude_child_environment_key_set_sha256,
)
from claude_headless_profile import (
    compile_claude_headless_profile_from_authorities,
)
import claude_launch_security as L
import claude_provider_preparation as P
import claude_runtime_materialization as M
from provider_command_authority import argv_authority_sha256
from review_fixtures import claude_runtime_test_support as test_support
import test_claude_provider_preparation as provider_fixtures
from test_support_startup_permit import (
    FIXTURE_RUN_ID,
    durable_startup_permit,
    rotate_startup_permit,
)


VERSION = "2.1.220"
SESSION_ID = "12345678-1234-4234-8234-123456789abc"


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _install_windows_private_acl(path: Path) -> None:
    if os.name != "nt":
        return
    import claude_stored_subscription_source as stored

    sid = stored._current_windows_user_sid_string()
    for target, grant in (
        (path.parent, f"*{sid}:(OI)(CI)(F)"),
        (path, f"*{sid}:(F)"),
    ):
        completed = subprocess.run(
            [
                "icacls",
                str(target),
                "/inheritance:r",
                "/grant:r",
                grant,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if completed.returncode != 0:
            raise AssertionError("private credential fixture ACL failed")


@pytest.fixture(autouse=True)
def _isolated_auxiliary_namespace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    namespace = tmp_path / "runtime-authority"
    monkeypatch.setattr(A, "_default_runtime_namespace", lambda: namespace)


def _sources(
    tmp_path: Path,
    *,
    secret: str = "offline-high-entropy-subscription-secret",
    credentials: bool = True,
) -> tuple[Path, Path, str]:
    config = tmp_path / "source-config"
    config.mkdir(exist_ok=True)
    if credentials:
        credentials_path = config / ".credentials.json"
        credentials_path.write_text(
            json.dumps(
                {
                    "claudeAiOauth": {
                        "accessToken": secret,
                        "refreshToken": "offline-refresh-secret",
                        "expiresAt": 4102444800000,
                    }
                }
            ),
            encoding="utf-8",
        )
        try:
            credentials_path.chmod(0o600)
        except OSError:
            pass
        _install_windows_private_acl(credentials_path)
    (config / "settings.json").write_text("{}", encoding="utf-8")
    state = tmp_path / "source-state.json"
    state.write_text("{}", encoding="utf-8")
    return config, state, secret


def _executable_observation(tmp_path: Path) -> dict[str, object]:
    executable = str((tmp_path / "fake-claude.exe").resolve())
    file_row = {
        "role": "CONFIGURED_EXECUTABLE",
        "path": executable,
        "sha256": "2" * 64,
        "size": 10,
        "device": 1,
        "inode": 2,
        "mode": 33279,
        "link_count": 1,
    }
    compatibility_core = {
        "compatibility_id": f"claude-code-{VERSION}",
        "claude_code_version": VERSION,
        "supported_capabilities": sorted(
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
        ),
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
        "executable_path": executable,
        "executable_sha256": file_row["sha256"],
        "executable_size": file_row["size"],
        "signature_status": "Valid",
        "implementation_closure": (
            "SIGNED_NATIVE_PRODUCT_IMAGE_WITH_EXTERNAL_OS_AUTHORITY"
        ),
    }
    core = {
        "schema": "plamen.claude_executable_observation.v1",
        "configured_claude_bin": executable,
        "resolved_executable": executable,
        "claude_code_version": VERSION,
        "compatibility": {
            **compatibility_core,
            "compatibility_sha256": _digest(compatibility_core),
        },
        "implementation_kind": "NATIVE_EXECUTABLE_IMAGE",
        "implementation_status": "DIRECT_IMPLEMENTATION_BOUND",
        "implementation_debt": None,
        "implementation_files": [file_row],
        "implementation_closure_roots": [],
        "native_platform_authority": {
            **native_core,
            "authority_sha256": _digest(native_core),
        },
        "version_probe": {
            "argv": [executable, "--version"],
            "returncode": 0,
            "stdout_utf8": stdout,
            "stdout_bytes": len(stdout.encode()),
            "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
            "stderr_bytes": 0,
            "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            "owned_process_scope_closed": True,
        },
        "launch_authority": "PROOF_GRADE",
    }
    return {**core, "observation_sha256": _digest(core)}


def _launch_request(
    *,
    tmp_path: Path,
    project: Path,
    ambient: dict[str, str],
    route: str = "STORED_SUBSCRIPTION_OAUTH",
    mode: str = "SAFE_MODE",
    servers: tuple[str, ...] = (),
    expected_key_set_sha256: str | None = None,
) -> dict[str, object]:
    auth = L.compile_claude_auth_route_policy(
        claude_code_version=VERSION,
        desired_route=route,
    )
    settings = L.compile_claude_settings_authority(
        mode=mode,
        settings_sha256=None if mode == "SAFE_MODE" else "3" * 64,
        external_policy_sha256=(
            None if mode == "SAFE_MODE" else "4" * 64
        ),
    )
    mcp = L.compile_claude_mcp_authority(
        settings_mode=mode,
        server_names=servers,
        source_manifest_sha256="5" * 64 if servers else None,
        selected_config_sha256=(
            None if mode == "SAFE_MODE" else "6" * 64
        ),
    )
    executable = _executable_observation(tmp_path)
    profile = compile_claude_headless_profile_from_authorities(
        executable_observation=executable,
        auth_route_policy=auth,
        settings_authority=settings,
        mcp_authority=mcp,
        cwd=str(project.resolve()),
        accepted_models=("claude-opus-5",),
        permission_mode="dontAsk",
        builtin_tools=("Edit", "Glob", "Grep", "Read", "Write"),
        required_tools=("Read",),
        forbidden_tools=("Bash",),
    )
    policies = ("base", "git", "rust")
    controls = {
        "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_UPDATES": "1",
        "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
    }
    expected = expected_key_set_sha256
    if expected is None:
        expected = planned_claude_child_environment_key_set_sha256(
            ambient=ambient,
            selected_route=route,
            endpoint_environment_names=(),
            phase_environment_policies=policies,
            functional_control_names=tuple(controls),
            home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        )
    policy = L.compile_claude_launch_security(
        headless_profile=profile,
        auth_route_policy=auth,
        executable_observation=executable,
        settings_authority=settings,
        mcp_authority=mcp,
        home_variable_policy="PRESERVE_TOOLCHAIN_HOME",
        phase_environment_policies=policies,
        functional_controls=controls,
        expected_child_environment_key_set_sha256=expected,
    )
    return L.compile_claude_launch_security_request(
        policy=policy,
        executable_observation=executable,
    )


def _ambient() -> dict[str, str]:
    return {
        "PATH": "C:\\toolchain",
        "HOME": "C:\\Users\\fixture",
        "USERPROFILE": "C:\\Users\\fixture",
        "GIT_CONFIG_GLOBAL": "C:\\Users\\fixture\\.gitconfig",
        "CARGO_HOME": "C:\\Users\\fixture\\.cargo",
        "ANTHROPIC_API_KEY": "must-be-removed-api-key",
        "CLAUDE_CODE_SESSION_ID": "parent-session",
        "CLAUDE_SECURESTORAGE_CONFIG_DIR": (
            "C:\\attacker-controlled-credential-store"
        ),
        "GITHUB_TOKEN": "unrelated-secret",
    }


def _base_argv(tmp_path: Path) -> tuple[str, ...]:
    return (
        str((tmp_path / "fake-claude.exe").resolve()),
        "-p",
        "--model",
        "claude-opus-5",
        "--output-format",
        "stream-json",
        "--verbose",
        "--session-id",
        SESSION_ID,
        "--no-session-persistence",
    )


def _kwargs(
    *,
    tmp_path: Path,
    attempt_id: str,
    request: dict[str, object] | None = None,
    source_config: Path | None = None,
    ambient: dict[str, str] | None = None,
    route: str = "STORED_SUBSCRIPTION_OAUTH",
    reservation: A.AuxiliaryWritableRootReservation | None = None,
) -> dict[str, object]:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir(exist_ok=True)
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    ambient = dict(_ambient() if ambient is None else ambient)
    if route == "OAUTH_TOKEN":
        ambient.setdefault(
            "CLAUDE_CODE_OAUTH_TOKEN",
            "offline-setup-token-value",
        )
    if source_config is None and route != "OAUTH_TOKEN":
        source_config, _, _ = _sources(
            tmp_path,
            credentials=(route != "OAUTH_TOKEN"),
        )
    launch_request = request or _launch_request(
        tmp_path=tmp_path,
        project=project,
        ambient=ambient,
        route=route,
    )
    return {
        "launch_security_request": launch_request,
        "host_inputs": M.compile_claude_runtime_host_inputs(
            auth_route=route,
            ambient_environment=ambient,
            source_config_dir=source_config,
            project_root=project,
            trusted_cwds=(project,),
        ),
        "base_argv": _base_argv(tmp_path),
        "scratchpad": scratchpad,
        "startup_permit_binding": durable_startup_permit(scratchpad),
        "run_id": FIXTURE_RUN_ID,
        "outer_attempt_arm_sha256": _digest(
            {"outer-attempt-arm": attempt_id}
        ),
        "work_plan_sha256": _digest({"work-plan": "shared"}),
        "attempt_id": attempt_id,
        "process_scope_identity": f"scope-{attempt_id}",
        "auxiliary_reservation": reservation,
    }


def _request(
    kwargs: dict[str, object],
) -> M.ClaudeRuntimeMaterializationRequest:
    # Deliberately bypass the production compiler to exercise the lower-level
    # materializer in isolation.  Requests created here are never admissible
    # to ``materialize_claude_runtime`` because they lack a provider parent.
    return test_support.compile_unbound_request(**kwargs)


def _materialize_request(
    request: M.ClaudeRuntimeMaterializationRequest,
) -> M.ClaudeRuntimeMaterialization:
    """Test-only lower-level sink for legacy materializer unit coverage."""

    return test_support.materialize_unbound_request(request)


def _materialize(
    kwargs: dict[str, object],
) -> M.ClaudeRuntimeMaterialization:
    return _materialize_request(_request(kwargs))


def test_safe_subscription_runtime_materializes_and_replays(
    tmp_path: Path,
) -> None:
    config, _, secret = _sources(tmp_path)
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-happy",
        source_config=config,
    )
    result = _materialize(kwargs)

    assert isinstance(result, M.ClaudeRuntimeMaterialization)
    assert result.receipt["refresh_continuity_authority"] == (
        "UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
    )
    assert result.receipt["completion_capable"] is False
    assert result._profile.config_dir.joinpath(
        ".credentials.json"
    ).is_file()
    assert secret in result._profile.config_dir.joinpath(
        ".credentials.json"
    ).read_text(encoding="utf-8")
    assert result.process_writable_root.exists()
    child = result.compiled_child_environment.environment
    assert child["HOME"] == _ambient()["HOME"]
    assert child["USERPROFILE"] == _ambient()["USERPROFILE"]
    assert child["CARGO_HOME"] == _ambient()["CARGO_HOME"]
    assert "CLAUDE_SECURESTORAGE_CONFIG_DIR" not in child
    assert child["CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"] == "1"
    assert result.receipt["precedence_environment_denials"] == [
        "CLAUDE_SECURESTORAGE_CONFIG_DIR"
    ]
    assert result._profile.state_path.parent == result._profile.config_dir
    assert M.replay_claude_runtime_materialization(result)[
        "valid"
    ] is True
    assert (
        result.compiled_child_environment.receipt[
            "final_environment_key_set_sha256"
        ]
        == result.receipt["expected_child_environment_key_set_sha256"]
    )

    cleanup = result.abort_before_process_scope("TEST_HANDOFF_ABORT")
    assert cleanup["closure_mode"] == "PRELAUNCH_ABORT"
    assert cleanup["profile_first_cleanup"] is True
    assert cleanup["completion_authority"] is False
    assert not result.process_writable_root.exists()


def test_oauth_setup_token_is_no_copy_completion_capable_lane(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "offline-one-year-setup-token"
    ambient = {**_ambient(), "CLAUDE_CODE_OAUTH_TOKEN": token}
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-oauth-production",
        ambient=ambient,
        route="OAUTH_TOKEN",
    )

    def forbidden_source_acquisition(**_kwargs):
        raise AssertionError("OAuth token lane read stored credentials")

    monkeypatch.setattr(
        M._stored,
        "acquire_stored_subscription_materialization",
        forbidden_source_acquisition,
    )
    result = _materialize(kwargs)

    assert result.receipt["selected_auth_route"] == "OAUTH_TOKEN"
    assert result.receipt["credential_materialization_mode"] == (
        "ENVIRONMENT_OAUTH_TOKEN"
    )
    assert result.receipt["refresh_continuity_authority"] == (
        "ENVIRONMENT_OAUTH_TOKEN_NO_WRITEBACK"
    )
    assert result.receipt["completion_capable"] is True
    assert (
        result.compiled_child_environment.environment[
            "CLAUDE_CODE_OAUTH_TOKEN"
        ]
        == token
    )
    assert "ANTHROPIC_API_KEY" not in (
        result.compiled_child_environment.environment
    )
    assert not (
        result._profile.config_dir / ".credentials.json"
    ).exists()
    public = json.dumps(
        {
            "receipt": result.receipt,
            "redacted": result.redacted_receipts,
            "representation": repr(result),
        },
        sort_keys=True,
    )
    assert token not in public
    assert hashlib.sha256(token.encode()).hexdigest() not in public
    result.abort_before_process_scope("TEST_OAUTH_PRODUCTION_ABORT")


def test_missing_oauth_setup_token_is_clear_prearm_failure(
    tmp_path: Path,
) -> None:
    project = tmp_path / "missing-token-project"
    project.mkdir()
    ambient_with_token = {
        **_ambient(),
        "CLAUDE_CODE_OAUTH_TOKEN": "planning-token",
    }
    request = _launch_request(
        tmp_path=tmp_path,
        project=project,
        ambient=ambient_with_token,
        route="OAUTH_TOKEN",
    )
    ambient_missing_token = {
        **_ambient(),
        "CLAUDE_CODE_OAUTH_TOKEN": "",
    }
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="attempt-oauth-setup-required",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-oauth-setup-required",
        request=request,
        reservation=reservation,
        ambient=ambient_missing_token,
        route="OAUTH_TOKEN",
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="setup-token",
    ) as failure:
        _materialize(kwargs)
    assert failure.value.reason_code == "OAUTH_SETUP_TOKEN_REQUIRED"
    assert reservation._armed is False


def test_oauth_attempts_are_parallel_disjoint_and_secret_free(
    tmp_path: Path,
) -> None:
    token = "offline-shared-setup-token"
    ambient = {**_ambient(), "CLAUDE_CODE_OAUTH_TOKEN": token}
    prepared = [
        _kwargs(
            tmp_path=tmp_path,
            attempt_id=f"oauth-parallel-{index:02d}",
            ambient=ambient,
            route="OAUTH_TOKEN",
        )
        for index in range(40)
    ]
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(_materialize, prepared))
    try:
        assert len({item._profile.root for item in results}) == 40
        assert len({item._profile.state_path for item in results}) == 40
        assert all(
            item.compiled_child_environment.environment[
                "CLAUDE_CODE_OAUTH_TOKEN"
            ]
            == token
            for item in results
        )
        assert all(
            not (
                item._profile.config_dir / ".credentials.json"
            ).exists()
            for item in results
        )
        durable = json.dumps(
            [
                {
                    "receipt": item.receipt,
                    "redacted": item.redacted_receipts,
                }
                for item in results
            ],
            sort_keys=True,
        )
        assert token not in durable
        assert hashlib.sha256(token.encode()).hexdigest() not in durable
    finally:
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(
                executor.map(
                    lambda item: item.abort_before_process_scope(
                        "TEST_PARALLEL_OAUTH_ABORT"
                    ),
                    results,
                )
            )


def test_launch_request_substitution_is_preallocation(
    tmp_path: Path,
) -> None:
    kwargs = _kwargs(tmp_path=tmp_path, attempt_id="attempt-substitute")
    request = deepcopy(kwargs["launch_security_request"])
    assert isinstance(request, dict)
    request["request_sha256"] = "0" * 64
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="attempt-substitute",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs["launch_security_request"] = request
    kwargs["auxiliary_reservation"] = reservation

    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="launch-security",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


@pytest.mark.parametrize(
    ("route", "mode", "servers"),
    (
        ("API_KEY", "SAFE_MODE", ()),
    ),
)
def test_nonfirst_lane_policy_is_rejected_before_reservation(
    tmp_path: Path,
    route: str,
    mode: str,
    servers: tuple[str, ...],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    ambient = _ambient()
    if route == "API_KEY":
        ambient["ANTHROPIC_API_KEY"] = "selected-api-key"
    request = _launch_request(
        tmp_path=tmp_path,
        project=project,
        ambient=ambient,
        route=route,
        mode=mode,
        servers=servers,
    )
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id=f"reject-{route.lower()}-{mode.lower()}",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id=f"reject-{route.lower()}-{mode.lower()}",
        request=request,
        reservation=reservation,
        ambient=ambient,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="reviewed runtime lanes",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


@pytest.mark.parametrize("servers", ((), ("unified-vuln-db",)))
def test_bound_lane_without_provider_source_bytes_rejects_before_reservation(
    tmp_path: Path,
    servers: tuple[str, ...],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    ambient = _ambient()
    request = _launch_request(
        tmp_path=tmp_path,
        project=project,
        ambient=ambient,
        mode="BOUND_SETTINGS",
        servers=servers,
    )
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id=f"reject-bound-{len(servers)}",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id=f"reject-bound-{len(servers)}",
        request=request,
        reservation=reservation,
        ambient=ambient,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="exact bounded source bytes",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


def test_unavailable_stored_source_fails_before_reservation(
    tmp_path: Path,
) -> None:
    config, _, _ = _sources(tmp_path, credentials=False)
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="attempt-unavailable",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-unavailable",
        source_config=config,
        reservation=reservation,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="stored subscription source",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


def test_source_substitution_before_exact_consume_aborts_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config, _, _ = _sources(tmp_path)
    captured: list[object] = []
    original = M.materialize_claude_attempt_profile

    def mutate_before_consume(**kwargs):
        captured.append(kwargs["leased_parent"])
        (config / ".credentials.json").write_text(
            json.dumps(
                {
                    "claudeAiOauth": {
                        "accessToken": "substituted",
                        "refreshToken": "substituted-refresh",
                        "expiresAt": 4102444800000,
                    }
                }
            ),
            encoding="utf-8",
        )
        return original(**kwargs)

    monkeypatch.setattr(
        M,
        "materialize_claude_attempt_profile",
        mutate_before_consume,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-source-substitution",
        source_config=config,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="attempt profile materialization",
    ):
        _materialize(kwargs)
    assert captured
    lease = captured[0]
    assert not lease.root.exists()


def test_key_denominator_failure_is_preallocation(
    tmp_path: Path,
) -> None:
    config, _, _ = _sources(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    ambient = _ambient()
    request = _launch_request(
        tmp_path=tmp_path,
        project=project,
        ambient=ambient,
        expected_key_set_sha256="f" * 64,
    )
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="attempt-key-denominator-failure",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-key-denominator-failure",
        request=request,
        source_config=config,
        reservation=reservation,
        ambient=ambient,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="key denominator",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


def test_public_receipts_and_repr_have_no_secret_hash_or_path(
    tmp_path: Path,
) -> None:
    config, _, secret = _sources(tmp_path)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-privacy",
            source_config=config,
        )
    )
    public = json.dumps(
        {
            "receipt": result.receipt,
            "redacted": result.redacted_receipts,
        },
        sort_keys=True,
    )
    secret_hash = hashlib.sha256(secret.encode()).hexdigest()
    for forbidden in (
        secret,
        secret_hash,
        str(config),
        ".credentials.json",
        str(result._profile.root),
        str(result._lease.root),
    ):
        assert forbidden not in public
        assert forbidden not in repr(result)
    with pytest.raises(TypeError):
        json.dumps(result)
    result.abort_before_process_scope("TEST_PRIVACY_ABORT")


def test_prelaunch_abort_revokes_enclosing_lease_exactly_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-single-abort",
        )
    )
    original = result._lease.abort_before_process_scope
    calls = 0

    def counted_abort(**kwargs):
        nonlocal calls
        calls += 1
        return original(**kwargs)

    monkeypatch.setattr(
        result._lease,
        "abort_before_process_scope",
        counted_abort,
    )
    receipt = result.abort_before_process_scope(
        "TEST_SINGLE_ABORT"
    )
    assert calls == 1
    assert receipt["closure_mode"] == "PRELAUNCH_ABORT"
    assert not result.process_writable_root.exists()


def test_retry_reuses_policy_but_has_disjoint_profile_and_lease(
    tmp_path: Path,
) -> None:
    config, _, _ = _sources(tmp_path)
    first_kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-retry-one",
        source_config=config,
    )
    second_kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-retry-two",
        request=first_kwargs["launch_security_request"],
        source_config=config,
    )
    first = _materialize(first_kwargs)
    second = _materialize(second_kwargs)

    assert (
        first.receipt["launch_security_policy_sha256"]
        == second.receipt["launch_security_policy_sha256"]
    )
    assert first._profile.root != second._profile.root
    assert first._lease.root != second._lease.root
    assert (
        first._profile.binding["credential_copy"]["materialization_id"]
        != second._profile.binding["credential_copy"]["materialization_id"]
    )
    assert first.receipt["receipt_sha256"] != second.receipt["receipt_sha256"]
    first.abort_before_process_scope("TEST_RETRY_ONE_ABORT")
    second.abort_before_process_scope("TEST_RETRY_TWO_ABORT")


def test_stale_startup_permit_rejects_before_reservation(
    tmp_path: Path,
) -> None:
    kwargs = _kwargs(tmp_path=tmp_path, attempt_id="attempt-stale-startup")
    scratchpad = kwargs["scratchpad"]
    assert isinstance(scratchpad, Path)
    rotate_startup_permit(scratchpad)
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="attempt-stale-startup",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs["auxiliary_reservation"] = reservation
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="startup permit",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


def test_reservation_attempt_substitution_is_prearm(
    tmp_path: Path,
) -> None:
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="different-attempt",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="expected-attempt",
        reservation=reservation,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="reservation",
    ):
        _materialize(kwargs)
    assert reservation._armed is False


def test_opaque_request_is_one_shot_and_redacted(
    tmp_path: Path,
) -> None:
    config, _, secret = _sources(tmp_path)
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-opaque-request",
        source_config=config,
    )
    request = _request(kwargs)

    assert secret not in repr(request)
    assert str(config) not in repr(request)
    with pytest.raises(TypeError):
        json.dumps(request)

    result = _materialize_request(request)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="already claimed",
    ):
        _materialize_request(request)
    result.abort_before_process_scope("TEST_OPAQUE_REQUEST_ABORT")


def test_host_inputs_are_opaque_one_shot_and_erased(
    tmp_path: Path,
) -> None:
    config, _, secret = _sources(tmp_path)
    project = tmp_path / "host-project"
    project.mkdir()
    ambient = _ambient()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="STORED_SUBSCRIPTION_OAUTH",
        ambient_environment=ambient,
        source_config_dir=config,
        project_root=project,
        trusted_cwds=(project,),
    )
    for forbidden in (secret, ambient["GITHUB_TOKEN"], str(config)):
        assert forbidden not in repr(host)
    with pytest.raises(TypeError):
        pickle.dumps(host)
    with pytest.raises(TypeError):
        deepcopy(host)
    with pytest.raises(TypeError):
        json.dumps(host)

    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-host-one-shot",
        source_config=config,
    )
    kwargs["host_inputs"] = host
    request = _request(kwargs)
    assert getattr(
        host,
        "_ClaudeRuntimeHostInputs__ambient_environment",
    ) == {}
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="already claimed",
    ):
        test_support.compile_unbound_request(**kwargs)

    result = _materialize_request(request)
    assert getattr(
        request,
        "_ClaudeRuntimeMaterializationRequest__ambient_environment",
    ) == {}
    assert getattr(
        request,
        "_ClaudeRuntimeMaterializationRequest__source_config_dir",
    ) is None
    result.abort_before_process_scope("TEST_HOST_INPUT_ERASURE")


def test_unused_request_discard_is_terminal_idempotent_and_secret_free(
    tmp_path: Path,
) -> None:
    secret = "unrelated-secret"
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-request-discard",
    )
    request = _request(kwargs)

    receipt = request.discard()

    assert receipt["discarded"] is True
    assert receipt["credential_values_recorded"] is False
    assert receipt["credential_content_hashes_recorded"] is False
    assert receipt["host_paths_recorded"] is False
    assert request.discard() == receipt
    assert (
        M.replay_claude_runtime_request_discard_receipt(receipt)
        == receipt
    )
    assert secret not in repr(request)
    assert secret not in json.dumps(receipt, sort_keys=True)
    assert getattr(
        request,
        "_ClaudeRuntimeMaterializationRequest__ambient_environment",
    ) == {}
    assert getattr(
        request,
        "_ClaudeRuntimeMaterializationRequest__source_config_dir",
    ) is None
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="already claimed",
    ):
        _materialize_request(request)


def test_materialized_request_cannot_be_relabeled_discarded(
    tmp_path: Path,
) -> None:
    request = _request(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-request-discard-claimed",
        )
    )
    claimed = _materialize_request(request)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="cannot be relabeled discarded",
    ):
        request.discard()
    claimed.abort_before_process_scope("TEST_REQUEST_DISCARD_CLAIMED")


def test_request_api_cannot_accept_raw_ambient_or_private_paths() -> None:
    parameters = inspect.signature(
        M.compile_claude_runtime_materialization_request
    ).parameters
    assert "host_inputs" in parameters
    assert "ambient_environment" not in parameters
    assert "source_config_dir" not in parameters
    assert "project_root" not in parameters
    assert "trusted_cwds" not in parameters


def test_host_input_auth_route_is_exact_and_source_config_is_conditional(
    tmp_path: Path,
) -> None:
    project = tmp_path / "route-bound-project"
    project.mkdir()
    config, _, _ = _sources(tmp_path)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="forbid source config",
    ):
        M.compile_claude_runtime_host_inputs(
            auth_route="OAUTH_TOKEN",
            ambient_environment={
                **_ambient(),
                "CLAUDE_CODE_OAUTH_TOKEN": "offline-token",
            },
            source_config_dir=config,
            project_root=project,
            trusted_cwds=(project,),
        )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="require source config",
    ):
        M.compile_claude_runtime_host_inputs(
            auth_route="STORED_SUBSCRIPTION_OAUTH",
            ambient_environment=_ambient(),
            source_config_dir=None,
            project_root=project,
            trusted_cwds=(project,),
        )


def test_request_authorities_are_unique_and_bind_private_inputs(
    tmp_path: Path,
) -> None:
    first_kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-input-authority",
    )
    second_kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-input-authority",
        request=first_kwargs["launch_security_request"],
    )
    first = _request(first_kwargs)
    second = _request(second_kwargs)
    assert first.request_sha256 != second.request_sha256

    host = second_kwargs["host_inputs"]
    assert isinstance(host, M.ClaudeRuntimeHostInputs)
    # The second host authority was consumed into its request; neither object
    # retains ambient values after its one permitted claim.
    assert getattr(
        host,
        "_ClaudeRuntimeHostInputs__ambient_environment",
    ) == {}
    first_result = _materialize_request(first)
    second_result = _materialize_request(second)
    first_result.abort_before_process_scope("TEST_INPUT_AUTHORITY_ONE")
    second_result.abort_before_process_scope("TEST_INPUT_AUTHORITY_TWO")


def test_host_input_private_field_substitution_is_rejected(
    tmp_path: Path,
) -> None:
    config, _, _ = _sources(tmp_path)
    project = tmp_path / "substitution-project"
    project.mkdir()
    host = M.compile_claude_runtime_host_inputs(
        auth_route="STORED_SUBSCRIPTION_OAUTH",
        ambient_environment=_ambient(),
        source_config_dir=config,
        project_root=project,
        trusted_cwds=(project,),
    )
    object.__setattr__(
        host,
        "_ClaudeRuntimeHostInputs__ambient_environment",
        MappingProxyType({**_ambient(), "GITHUB_TOKEN": "substituted"}),
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-host-substitution",
        source_config=config,
    )
    kwargs["host_inputs"] = host
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="authority drifted",
    ):
        _request(kwargs)


def test_final_argv_is_exact_base_plus_replayed_profile_flags(
    tmp_path: Path,
) -> None:
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-final-argv",
    )
    launch = kwargs["launch_security_request"]
    assert isinstance(launch, dict)
    expected = (
        *kwargs["base_argv"],
        *launch["policy"]["headless_profile"]["cli_flags"],
    )

    result = _materialize(kwargs)

    assert result.final_argv == expected
    assert "--safe-mode" in result.final_argv
    assert "--disallowedTools" not in result.final_argv
    assert result.receipt["final_argv_count"] == len(expected)
    result.abort_before_process_scope("TEST_FINAL_ARGV_ABORT")


def test_argv_authority_uses_shared_unicode_safe_provider_digest() -> None:
    argv = (
        "C:\\Program Files\\Claude π\\claude.exe",
        "-p",
        "inspect seam α",
    )
    assert M.claude_runtime_argv_sha256(argv) == (
        argv_authority_sha256(argv)
    )


def test_persisted_aggregate_replays_without_live_paths(
    tmp_path: Path,
) -> None:
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-persisted-replay",
        )
    )
    replay = M.reconcile_claude_runtime_persisted_authority(
        result.receipt,
        result.redacted_receipts,
        base_argv=result._base_argv,
        final_argv=result.final_argv,
        environment_names=tuple(
            result.compiled_child_environment.environment
        ),
    )
    assert replay["valid"] is True
    tampered = result.redacted_receipts
    tampered["child_environment"]["receipt_sha256"] = "0" * 64
    with pytest.raises(M.ClaudeRuntimeMaterializationError):
        M.reconcile_claude_runtime_persisted_authority(
            result.receipt,
            tampered,
            base_argv=result._base_argv,
            final_argv=result.final_argv,
            environment_names=tuple(
                result.compiled_child_environment.environment
            ),
        )
    result.abort_before_process_scope("TEST_PERSISTED_REPLAY_ABORT")


def test_runtime_result_construction_requires_private_capability(
    tmp_path: Path,
) -> None:
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-result-opacity",
        )
    )
    fields = {
        name: getattr(result, name)
        for name in (
            "_profile",
            "_lease",
                "_compiled_child_environment",
                "_child_environment_names",
            "_base_argv",
            "_headless_profile_cli_flags",
            "_runtime_authority_cli_flags",
            "_bound_settings_file",
            "_selected_mcp_config_file",
            "_expected_mcp_servers",
            "_final_argv",
            "_receipt",
            "_redacted_receipts",
            "_outer_attempt_arm_sha256",
            "_process_scope_identity",
        )
    }
    with pytest.raises(TypeError, match="opaque"):
        M.ClaudeRuntimeMaterialization(
            _construction_capability=object(),
            **fields,
        )
    result.abort_before_process_scope("TEST_RESULT_OPACITY_ABORT")


@pytest.mark.parametrize(
    "extra",
    (
        ("--safe-mode",),
        ("--tools", "Read"),
        ("--disallowedTools", "Bash"),
        ("--output-format=stream-json",),
        ("--resume", SESSION_ID),
    ),
)
def test_base_argv_alias_or_second_denominator_is_preallocation(
    tmp_path: Path,
    extra: tuple[str, ...],
) -> None:
    reservation = A.reserve_auxiliary_writable_root(
        attempt_id="attempt-argv-reject",
        purpose=M.AUXILIARY_PURPOSE,
    )
    kwargs = _kwargs(
        tmp_path=tmp_path,
        attempt_id="attempt-argv-reject",
        reservation=reservation,
    )
    kwargs["base_argv"] = (*kwargs["base_argv"], *extra)

    with pytest.raises(M.ClaudeRuntimeMaterializationError):
        _request(kwargs)
    assert reservation._armed is False


class _FakeOwnedProcessScope:
    def __init__(
        self,
        identity: str,
        *,
        closed: bool,
        emergency: bool,
        attached: bool = True,
        terminated: bool = False,
        pre_release_process_identity: object | None = None,
        process_creation_state: str | None = None,
        created_process_termination_proven: bool = False,
        population_zero_proven: bool | None = None,
        emergency_zero_proven: bool = True,
        emergency_failure: bool = False,
    ) -> None:
        self.persistent_identity = identity
        self.closed = closed
        self.population_zero_proven = (
            closed
            if population_zero_proven is None
            else population_zero_proven
        )
        self.emergency_closed = emergency
        self.attached = attached
        self.terminated = terminated
        self.pre_release_process_identity = pre_release_process_identity
        self.created_process_termination_proven = (
            created_process_termination_proven
        )
        self.process_creation_state = (
            process_creation_state
            or (
                "ATTACHED"
                if attached
                else "CREATION_FAILED_WITHOUT_PROCESS_OBJECT"
            )
        )
        self.process_creation_evidence = {
            "state": self.process_creation_state,
            "creation_attempted": (
                self.process_creation_state
                != "NOT_ATTEMPTED"
            ),
            "process_object_returned": (
                self.process_creation_state
                in {"PROCESS_CREATED", "ATTACHED"}
            ),
            "attached": attached,
            "created_process_termination_proven": (
                created_process_termination_proven
            ),
        }
        self.emergency_zero_proven = emergency_zero_proven
        self.emergency_failure = emergency_failure
        self.emergency_calls = 0

    def emergency_close(self) -> None:
        self.emergency_calls += 1
        if self.emergency_failure:
            raise RuntimeError("injected emergency failure")
        self.closed = True
        self.population_zero_proven = self.emergency_zero_proven
        self.emergency_closed = True


def _trust_fake_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        A,
        "_owned_process_scope_type",
        lambda: _FakeOwnedProcessScope,
    )
    monkeypatch.setattr(
        M._profile,
        "_owned_process_scope_type",
        lambda: _FakeOwnedProcessScope,
    )


def _materialize_bound_provider_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> M.ClaudeRuntimeMaterialization:
    values = provider_fixtures._inputs(
        tmp_path / "bound-provider",
        route="OAUTH_TOKEN",
        settings_mode="BOUND_SETTINGS",
        mcp_servers=(),
    )
    scratchpad = Path(values["startup_scratchpad"])
    values["startup_authority_binding"] = durable_startup_permit(
        scratchpad,
        run_id=provider_fixtures.RUN_ID,
    )
    executable = Path(str(values["configured_claude_bin"]))
    provider_fixtures._install_observers(
        monkeypatch,
        executable,
        stored_available=False,
    )
    package = P.prepare_claude_provider(
        **provider_fixtures._public_inputs(values)
    )
    attachment = provider_fixtures._attach(package, values)
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
    request = M.compile_claude_runtime_materialization_request(
        launch_security_request=package.record[
            "launch_security_request"
        ],
        provider_runtime=claimed,
        base_argv=command[:-len(profile_flags)],
        scratchpad=scratchpad,
        startup_permit_binding=values[
            "startup_authority_binding"
        ],
        run_id=provider_fixtures.RUN_ID,
        outer_attempt_arm_sha256="a" * 64,
        work_plan_sha256="b" * 64,
        attempt_id="attempt-bound-postclose",
        process_scope_identity="scope-attempt-bound-postclose",
    )
    return M.materialize_claude_runtime(request)


def _simulate_provider_state_update(
    result: M.ClaudeRuntimeMaterialization,
) -> None:
    """Model Claude 2.1.220's one supported post-process state delta."""

    state = json.loads(
        result._profile.state_path.read_text(encoding="utf-8")
    )
    state["numStartups"] = 2
    result._profile.state_path.write_text(
        json.dumps(
            state,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    result._profile.state_path.chmod(0o600)


def test_bound_settings_bytes_replay_again_after_scope_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize_bound_provider_runtime(
        tmp_path,
        monkeypatch,
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-bound-postclose",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    settings_path = Path(
        result.final_argv[
            result.final_argv.index("--settings") + 1
        ]
    )
    original = settings_path.read_bytes()
    settings_path.write_bytes(original + b" ")
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="post-process replay failed",
    ):
        M.reconcile_claude_runtime_after_scope_close(result, scope)
    settings_path.write_bytes(original)
    postprocess = M.reconcile_claude_runtime_after_scope_close(
        result,
        scope,
    )
    assert postprocess["process_closed"] is True
    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["completion_authority"] is True
    assert not result.process_writable_root.exists()


def test_normal_scope_cleanup_is_profile_first_and_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(tmp_path=tmp_path, attempt_id="attempt-normal-close")
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-normal-close",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    postprocess = M.reconcile_claude_runtime_after_scope_close(
        result,
        scope,
    )
    assert postprocess["selected_auth_route"] == (
        "STORED_SUBSCRIPTION_OAUTH"
    )
    assert postprocess["worker_credential_refresh_authority"] == (
        "NONE_UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
    )
    assert postprocess["current_attempt_credential_copy_status"] == (
        "ORIGINAL_PRIVATE_COPY_UNCHANGED"
    )

    receipt = result.revoke_after_normal_scope_close(scope)

    assert receipt["closure_mode"] == "NORMAL_COMPLETION"
    assert receipt["profile_first_cleanup"] is True
    assert receipt["completion_authority"] is True
    assert not result._profile.root.exists()
    assert not result.process_writable_root.exists()
    assert result.compiled_child_environment.active is False
    assert result.revoke_after_normal_scope_close(scope) == receipt


def test_oauth_scope_cleanup_can_mint_normal_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-oauth-normal-close",
            route="OAUTH_TOKEN",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-oauth-normal-close",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    postprocess = M.reconcile_claude_runtime_after_scope_close(
        result,
        scope,
    )
    assert postprocess["selected_auth_route"] == "OAUTH_TOKEN"
    assert postprocess["worker_credential_refresh_authority"] == (
        "NONE_ACCESS_ONLY_ENVIRONMENT_TOKEN"
    )
    assert postprocess["current_attempt_credential_copy_status"] == (
        "NOT_APPLICABLE_ENVIRONMENT_TOKEN"
    )

    receipt = result.revoke_after_normal_scope_close(scope)

    assert receipt["closure_mode"] == "NORMAL_COMPLETION"
    assert receipt["completion_authority"] is True
    assert not result.process_writable_root.exists()


def test_oauth_failed_scope_cleanup_withholds_completion_and_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-oauth-failed-close",
            route="OAUTH_TOKEN",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-oauth-failed-close",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    failure_sha256 = _digest(
        {"reason_code": "NONZERO_EXIT", "returncode": 7}
    )

    receipt = result.revoke_after_failed_scope_close(
        scope,
        "NONZERO_EXIT",
        primary_failure_evidence_sha256=failure_sha256,
    )

    assert receipt["closure_mode"] == "NORMAL_SCOPE_FAILURE_CLEANUP"
    assert receipt["reason_code"] == "NONZERO_EXIT"
    assert receipt["primary_failure_evidence_sha256"] == failure_sha256
    assert receipt["profile_first_cleanup"] is True
    assert receipt["completion_authority"] is False
    assert receipt["emergency_zero_population"] is False
    assert result.postprocess_receipt is None
    assert not result._profile.root.exists()
    assert not result.process_writable_root.exists()
    assert M.replay_claude_runtime_lifecycle_receipt(receipt) == receipt
    assert (
        result.revoke_after_failed_scope_close(
            scope,
            "NONZERO_EXIT",
            primary_failure_evidence_sha256=failure_sha256,
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("closed", "population_zero", "emergency"),
    (
        (False, False, False),
        (True, False, False),
        (True, True, True),
    ),
)
def test_failed_scope_cleanup_requires_exact_normal_zero_population_ordering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closed: bool,
    population_zero: bool,
    emergency: bool,
) -> None:
    _trust_fake_scope(monkeypatch)
    attempt = (
        f"attempt-failed-order-{int(closed)}-"
        f"{int(population_zero)}-{int(emergency)}"
    )
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id=attempt,
            route="OAUTH_TOKEN",
        )
    )
    scope = _FakeOwnedProcessScope(
        f"scope-{attempt}",
        closed=closed,
        emergency=emergency,
        population_zero_proven=population_zero,
    )
    result.bind_process_scope(scope)

    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="failure cleanup|zero-population|scope authority",
    ):
        result.revoke_after_failed_scope_close(
            scope,
            "NONZERO_EXIT",
            primary_failure_evidence_sha256="7" * 64,
        )

    assert result._profile.root.exists()
    assert result.process_writable_root.exists()
    if not closed:
        _simulate_provider_state_update(result)
        result.emergency_close_to_quarantine_debt(scope)


def test_failed_scope_cleanup_fault_never_mints_completion_and_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-failed-cleanup-retry",
            route="OAUTH_TOKEN",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-failed-cleanup-retry",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    original = result._lease.revoke
    calls = 0

    def fail_once(token):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise A.AuxiliaryWritableRootLeaseError(
                "injected failure cleanup fault"
            )
        return original(token)

    monkeypatch.setattr(result._lease, "revoke", fail_once)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="failure cleanup|profile-first revocation",
    ):
        result.revoke_after_failed_scope_close(
            scope,
            "NONZERO_EXIT",
            primary_failure_evidence_sha256="8" * 64,
        )
    assert result.lifecycle_receipt is None
    assert not result._profile.root.exists()
    assert result.process_writable_root.exists()

    receipt = result.revoke_after_failed_scope_close(
        scope,
        "NONZERO_EXIT",
        primary_failure_evidence_sha256="8" * 64,
    )
    assert receipt["closure_mode"] == "NORMAL_SCOPE_FAILURE_CLEANUP"
    assert receipt["completion_authority"] is False
    assert not result.process_writable_root.exists()


@pytest.mark.parametrize(
    "forgery",
    (
        "missing-summary",
        "completion-authority",
        "receipt-binding",
    ),
)
def test_failed_scope_cleanup_rejects_forged_profile_replay_and_retries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    forgery: str,
) -> None:
    _trust_fake_scope(monkeypatch)
    attempt = f"attempt-failed-profile-replay-{forgery}"
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id=attempt,
            route="OAUTH_TOKEN",
        )
    )
    scope = _FakeOwnedProcessScope(
        f"scope-{attempt}",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    real_replay = M.replay_claude_attempt_profile_revocation
    calls = 0

    def forged_once(profile, receipt):
        nonlocal calls
        calls += 1
        replay = real_replay(profile, receipt)
        if calls != 1:
            return replay
        if forgery == "missing-summary":
            return {}
        forged = dict(replay)
        if forgery == "completion-authority":
            forged["completion_authority"] = True
        else:
            forged["receipt_sha256"] = "0" * 64
        return forged

    monkeypatch.setattr(
        M,
        "replay_claude_attempt_profile_revocation",
        forged_once,
    )
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="profile revocation authority is invalid",
    ):
        result.revoke_after_failed_scope_close(
            scope,
            "NONZERO_EXIT",
            primary_failure_evidence_sha256="9" * 64,
        )

    assert result.lifecycle_receipt is None
    assert not result._profile.root.exists()
    assert result.process_writable_root.exists()
    receipt = result.revoke_after_failed_scope_close(
        scope,
        "NONZERO_EXIT",
        primary_failure_evidence_sha256="9" * 64,
    )
    assert receipt["closure_mode"] == "NORMAL_SCOPE_FAILURE_CLEANUP"
    assert receipt["completion_authority"] is False
    assert not result.process_writable_root.exists()


def test_postprocess_receipt_cannot_claim_worker_refresh_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-oauth-no-worker-refresh",
            route="OAUTH_TOKEN",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-oauth-no-worker-refresh",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    postprocess = M.reconcile_claude_runtime_after_scope_close(
        result,
        scope,
    )
    changed = dict(postprocess)
    changed["worker_credential_refresh_authority"] = "ALLOWED"
    core = dict(changed)
    core.pop("receipt_sha256")
    changed["receipt_sha256"] = _digest(core)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="does not replay",
    ):
        M.replay_claude_runtime_postprocess_receipt(changed)
    result.revoke_after_normal_scope_close(scope)


def test_oauth_child_environment_is_invalidated_immediately_after_attach(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    token = "offline-short-lived-parent-copy"
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-oauth-post-attach",
            ambient={
                **_ambient(),
                "CLAUDE_CODE_OAUTH_TOKEN": token,
            },
            route="OAUTH_TOKEN",
        )
    )
    temporary_popen_environment = dict(
        result.compiled_child_environment.environment
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-oauth-post-attach",
        closed=False,
        emergency=False,
        attached=True,
    )
    result.bind_process_scope(scope)

    result.invalidate_child_environment_after_process_attach(scope)
    temporary_popen_environment.clear()

    assert result.compiled_child_environment.active is False
    assert token not in repr(result)
    assert token not in json.dumps(result.receipt, sort_keys=True)
    with pytest.raises(RuntimeError, match="invalidated"):
        _ = result.compiled_child_environment.environment
    scope.closed = True
    scope.population_zero_proven = True
    _simulate_provider_state_update(result)
    M.reconcile_claude_runtime_after_scope_close(result, scope)
    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["completion_authority"] is True


def test_bound_scope_popen_failure_aborts_without_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-popen-failure",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-popen-failure",
        closed=True,
        emergency=False,
        attached=False,
    )
    result.bind_process_scope(scope)

    receipt = result.abort_bound_scope_before_process_attach(
        scope,
        "POPEN_FAILED",
    )

    assert receipt["closure_mode"] == (
        "BOUND_SCOPE_PRELAUNCH_ABORT"
    )
    assert receipt["reason_code"] == "POPEN_FAILED"
    assert receipt["completion_authority"] is False
    assert not result._profile.root.exists()
    assert not result.process_writable_root.exists()
    assert result.compiled_child_environment.active is False
    assert (
        result.abort_bound_scope_before_process_attach(
            scope,
            "POPEN_FAILED",
        )
        == receipt
    )


def test_created_process_attach_failure_closes_without_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-attach-failure",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-attach-failure",
        closed=True,
        emergency=False,
        attached=False,
        process_creation_state="PROCESS_CREATED",
        created_process_termination_proven=True,
        population_zero_proven=True,
    )
    result.bind_process_scope(scope)

    receipt = result.close_after_process_attach_failure(
        scope,
        "ATTACH_FAILED",
    )

    assert receipt["closure_mode"] == (
        "PROCESS_ATTACH_FAILURE_CLEANUP"
    )
    assert receipt["reason_code"] == "ATTACH_FAILED"
    assert receipt["completion_authority"] is False
    assert receipt["profile_first_cleanup"] is True
    assert result.compiled_child_environment.active is False
    assert not result._profile.root.exists()
    assert not result.process_writable_root.exists()
    assert (
        result.close_after_process_attach_failure(
            scope,
            "ATTACH_FAILED",
        )
        == receipt
    )


@pytest.mark.parametrize(
    (
        "termination_proven",
        "closed",
        "population_zero_proven",
    ),
    (
        (False, True, True),
        (True, False, False),
        (True, True, False),
    ),
)
def test_created_process_attach_failure_without_complete_proof_is_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    termination_proven: bool,
    closed: bool,
    population_zero_proven: bool,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id=(
                "attempt-attach-debt-"
                f"{int(termination_proven)}-{int(closed)}-"
                f"{int(population_zero_proven)}"
            ),
        )
    )
    scope = _FakeOwnedProcessScope(
        (
            "scope-attempt-attach-debt-"
            f"{int(termination_proven)}-{int(closed)}-"
            f"{int(population_zero_proven)}"
        ),
        closed=closed,
        emergency=False,
        attached=False,
        process_creation_state="PROCESS_CREATED",
        created_process_termination_proven=termination_proven,
        population_zero_proven=population_zero_proven,
    )
    result.bind_process_scope(scope)

    receipt = result.close_after_process_attach_failure(
        scope,
        "ATTACH_FAILED_UNPROVEN",
    )

    assert receipt["closure_mode"] == (
        "PROCESS_ATTACH_FAILURE_UNPROVEN_DEBT"
    )
    assert receipt["completion_authority"] is False
    assert receipt["recovery_required"] is True
    assert receipt["profile_retained"] is True
    assert receipt["auxiliary_root_retained"] is True
    assert receipt["process_zero_proven"] is population_zero_proven
    assert receipt["created_process_termination_proven"] is (
        termination_proven
    )
    assert result._profile.root.exists()
    assert result.process_writable_root.exists()
    assert result.compiled_child_environment.active is False
    assert M.replay_claude_runtime_lifecycle_receipt(receipt) == (
        receipt
    )


def test_never_created_abort_rejects_process_created_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-created-not-prelaunch",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-created-not-prelaunch",
        closed=True,
        emergency=False,
        attached=False,
        process_creation_state="PROCESS_CREATED",
        created_process_termination_proven=True,
    )
    result.bind_process_scope(scope)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="bound-prelaunch abort failed",
    ):
        result.abort_bound_scope_before_process_attach(
            scope,
            "WRONG_CLOSURE_API",
        )
    receipt = result.close_after_process_attach_failure(
        scope,
        "ATTACH_FAILED",
    )
    assert receipt["completion_authority"] is False


def test_bound_scope_abort_rejects_any_attached_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-popen-overclaim",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-popen-overclaim",
        closed=True,
        emergency=False,
        attached=True,
    )
    result.bind_process_scope(scope)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="scope authority",
    ):
        result.abort_bound_scope_before_process_attach(
            scope,
            "POPEN_FAILED",
        )
    _simulate_provider_state_update(result)
    M.reconcile_claude_runtime_after_scope_close(result, scope)
    result.revoke_after_normal_scope_close(scope)


def test_postbind_credential_refresh_completes_without_writeback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(tmp_path=tmp_path, attempt_id="attempt-refresh-close")
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-refresh-close",
        closed=False,
        emergency=False,
    )
    result.bind_process_scope(scope)
    credential = result._profile.config_dir / ".credentials.json"
    source_credential = tmp_path / "source-config" / ".credentials.json"
    source_before = source_credential.read_bytes()
    credential.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "refreshed-private-access",
                    "refreshToken": "refreshed-private-refresh",
                    "expiresAt": 4102444801000,
                }
            }
        ),
        encoding="utf-8",
    )
    scope.closed = True
    scope.population_zero_proven = True
    _simulate_provider_state_update(result)

    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="only valid before",
    ):
        M.replay_claude_runtime_materialization(result)
    postprocess = M.reconcile_claude_runtime_after_scope_close(result, scope)
    assert postprocess["current_attempt_credential_copy_status"] == (
        "UNTRUSTED_PRIVATE_COPY_CHANGED_OR_REPLACED_DISCARD_ONLY"
    )
    assert postprocess["worker_credential_refresh_authority"] == (
        "NONE_UNPROVEN_PRIVATE_COPY_NO_WRITEBACK"
    )
    assert source_credential.read_bytes() == source_before
    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["completion_authority"] is True
    assert receipt["closure_mode"] == "NORMAL_COMPLETION"
    assert source_credential.read_bytes() == source_before
    assert not result.process_writable_root.exists()
    public_receipts = json.dumps(
        {"postprocess": postprocess, "lifecycle": receipt},
        sort_keys=True,
    )
    for private_value in (
        "refreshed-private-access",
        "refreshed-private-refresh",
    ):
        assert private_value not in public_receipts
        assert (
            hashlib.sha256(private_value.encode("utf-8")).hexdigest()
            not in public_receipts
        )


def test_atomic_credential_replacement_after_reconciliation_is_resealed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-stale-unchanged-copy",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-stale-unchanged-copy",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    postprocess = M.reconcile_claude_runtime_after_scope_close(
        result,
        scope,
    )
    assert postprocess["current_attempt_credential_copy_status"] == (
        "ORIGINAL_PRIVATE_COPY_UNCHANGED"
    )

    credential = result._profile.config_dir / ".credentials.json"
    replacement = result._profile.config_dir / "replacement"
    replacement.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "replacement-private-access",
                    "refreshToken": "replacement-private-refresh",
                    "expiresAt": 4102444802000,
                }
            }
        ),
        encoding="utf-8",
    )
    replacement.chmod(0o600)
    os.replace(replacement, credential)

    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["closure_mode"] == "NORMAL_COMPLETION"
    assert receipt["completion_authority"] is True
    assert not result.process_writable_root.exists()


def test_invalid_credential_replacement_after_reconciliation_cannot_complete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-invalid-credential-after-reconcile",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-invalid-credential-after-reconcile",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    M.reconcile_claude_runtime_after_scope_close(result, scope)

    credential = result._profile.config_dir / ".credentials.json"
    credential.write_bytes(b'{"unsupported":"credential-shape"}')
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="profile-first revocation failed",
    ):
        result.revoke_after_normal_scope_close(scope)
    assert result._profile.root.exists()
    assert result.process_writable_root.exists()

    credential.write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "recovered-private-access",
                    "refreshToken": "recovered-private-refresh",
                    "expiresAt": 4102444803000,
                }
            }
        ),
        encoding="utf-8",
    )
    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["closure_mode"] == "NORMAL_COMPLETION"
    assert receipt["completion_authority"] is True
    assert not result.process_writable_root.exists()


def test_emergency_zero_calls_scope_then_withholds_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(tmp_path=tmp_path, attempt_id="attempt-emergency-close")
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-emergency-close",
        closed=False,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)

    receipt = result.emergency_zero_and_revoke(scope)

    assert scope.emergency_calls == 1
    assert receipt["closure_mode"] == (
        "EMERGENCY_ZERO_POPULATION_CLEANUP"
    )
    assert receipt["completion_authority"] is False
    assert receipt["emergency_zero_population"] is True
    assert not result.process_writable_root.exists()


def test_emergency_without_zero_proof_retains_roots_and_emits_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-emergency-debt",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-emergency-debt",
        closed=False,
        emergency=False,
        emergency_zero_proven=False,
    )
    result.bind_process_scope(scope)

    receipt = result.emergency_close_to_quarantine_debt(scope)

    assert receipt["closure_mode"] == (
        "EMERGENCY_ZERO_UNPROVEN_DEBT"
    )
    assert receipt["completion_authority"] is False
    assert receipt["recovery_required"] is True
    assert receipt["process_zero_proven"] is False
    assert receipt["profile_retained"] is True
    assert receipt["auxiliary_root_retained"] is True
    assert result._profile.root.exists()
    assert result.process_writable_root.exists()
    assert M.replay_claude_runtime_lifecycle_receipt(receipt) == receipt
    assert result.emergency_close_to_quarantine_debt(scope) == receipt


def test_emergency_close_failure_retains_roots_and_emits_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(
            tmp_path=tmp_path,
            attempt_id="attempt-emergency-failure",
        )
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-emergency-failure",
        closed=False,
        emergency=False,
        emergency_failure=True,
    )
    result.bind_process_scope(scope)

    receipt = result.emergency_close_to_quarantine_debt(scope)

    assert receipt["closure_mode"] == "EMERGENCY_CLOSE_FAILED_DEBT"
    assert receipt["emergency_close_observed"] is False
    assert receipt["completion_authority"] is False
    assert result._profile.root.exists()
    assert result.process_writable_root.exists()


def test_retry_after_failure_between_profile_and_auxiliary_revoke(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(tmp_path=tmp_path, attempt_id="attempt-close-retry")
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-close-retry",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    M.reconcile_claude_runtime_after_scope_close(result, scope)
    original = result._lease.revoke
    calls = 0

    def fail_once(token):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise A.AuxiliaryWritableRootLeaseError(
                "injected before auxiliary revoke"
            )
        return original(token)

    monkeypatch.setattr(result._lease, "revoke", fail_once)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="profile-first revocation",
    ):
        result.revoke_after_normal_scope_close(scope)
    assert not result._profile.root.exists()
    assert result.process_writable_root.exists()

    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["completion_authority"] is True
    assert not result.process_writable_root.exists()


def test_retry_after_auxiliary_revoke_before_aggregate_finalize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _trust_fake_scope(monkeypatch)
    result = _materialize(
        _kwargs(tmp_path=tmp_path, attempt_id="attempt-finalize-retry")
    )
    scope = _FakeOwnedProcessScope(
        "scope-attempt-finalize-retry",
        closed=True,
        emergency=False,
    )
    result.bind_process_scope(scope)
    _simulate_provider_state_update(result)
    M.reconcile_claude_runtime_after_scope_close(result, scope)
    original = result._lease.revoke
    calls = 0

    def revoke_then_fail(token):
        nonlocal calls
        calls += 1
        receipt = original(token)
        if calls == 1:
            raise A.AuxiliaryWritableRootLeaseError(
                "injected after auxiliary revoke"
            )
        return receipt

    monkeypatch.setattr(result._lease, "revoke", revoke_then_fail)
    with pytest.raises(
        M.ClaudeRuntimeMaterializationError,
        match="profile-first revocation",
    ):
        result.revoke_after_normal_scope_close(scope)
    assert not result.process_writable_root.exists()

    receipt = result.revoke_after_normal_scope_close(scope)
    assert receipt["completion_authority"] is True
    assert result.revoke_after_normal_scope_close(scope) == receipt
